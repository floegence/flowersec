package rawquic

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	quic "github.com/quic-go/quic-go"
)

// OwnedListenerConfig supplies the shared UDP/TLS admission root and exact
// preauth accounts. The route/TLS certificate policy is installed by the trusted
// listener assembly. Each connection is admitted before QUIC creates its TLS
// state, including connections that fail their handshake or never reach Accept.
type OwnedListenerConfig struct {
	Root                        *resourcev4.Root
	Owner                       resourcev4.OwnerKey
	Accounts                    []resourcev4.Account
	TLS                         *tls.Config
	Address                     netip.AddrPort
	Connection                  OwnedOptions
	Connections                 uint16
	RuntimeBytes, ProviderBytes uint64
	ProviderTasks               uint32
}

type OwnedListener struct {
	mu                  sync.Mutex
	c                   OwnedListenerConfig
	listener            *quic.Listener
	transport           *quic.Transport
	packet              *net.UDPConn
	address             netip.AddrPort
	reservation, shared resourcev4.Reference
	environment         resourcev4.Reference
	connectionCharge    resourcev4.Vector
	accounts            [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	slots               []ownedListenerSlot
	serial              uint64
	accepting, closed   bool
	closing, cleaned    bool
	closeErr            error
	done                chan struct{}
}

type ownedListenerSlot struct {
	owner        *ownedConnection
	used, handed bool
	observing    bool
}

type ownedListenerKey struct{}
type ownedListenerIdentity struct {
	listener *OwnedListener
	owner    *ownedConnection
	slot     uint16
}

func OwnedListenerCharge(c OwnedListenerConfig) (resourcev4.Vector, error) {
	if c.Root == nil || !c.Address.IsValid() || c.Address.Addr().Zone() != "" ||
		c.Connections == 0 || c.Connections > 1024 || c.RuntimeBytes == 0 || c.ProviderBytes == 0 ||
		c.ProviderTasks == 0 || c.ProviderTasks > 256 || len(c.Accounts) == 0 || len(c.Accounts) > resourcev4.MaxAccountsPerCharge ||
		c.TLS == nil || c.TLS.GetCertificate != nil || c.TLS.GetConfigForClient != nil ||
		c.TLS.VerifyPeerCertificate != nil || c.TLS.VerifyConnection != nil || c.TLS.GetClientCertificate != nil ||
		c.TLS.ClientAuth != tls.NoClientCert || len(c.TLS.Certificates) != 1 || len(c.TLS.NextProtos) != 1 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if _, err := OwnedCharge(c.Connection); err != nil {
		return resourcev4.Vector{}, err
	}
	if _, err := prepareTLS(c.TLS, true); err != nil {
		return resourcev4.Vector{}, err
	}
	certificate := c.TLS.Certificates[0]
	if len(certificate.Certificate) == 0 || len(certificate.Certificate) > 16 || len(certificate.OCSPStaple) != 0 ||
		len(certificate.SignedCertificateTimestamps) != 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	bytes := uint64(unsafe.Sizeof(OwnedListener{})) + uint64(c.Connections)*(uint64(unsafe.Sizeof(ownedListenerSlot{}))+uint64(unsafe.Sizeof(ownedListenerIdentity{})))
	for _, der := range certificate.Certificate {
		if len(der) == 0 || len(der) > 65536 {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		bytes += uint64(len(der))
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: bytes, resourcev4.ProviderBytes: c.ProviderBytes,
		resourcev4.Items: uint64(c.Connections) + 1, resourcev4.WorkSlots: uint64(c.Connections) + 1,
		resourcev4.Tasks: uint64(c.ProviderTasks) + uint64(c.Connections), resourcev4.NativeHandles: 1}).
		Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func ListenOwned(c OwnedListenerConfig, reservation, environment resourcev4.Reference) (_ *OwnedListener, err error) {
	charge, err := OwnedListenerCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	if reservation == environment {
		return nil, resourcev4.ErrOwner
	}
	if err = reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	shared, err := environment.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	l := &OwnedListener{c: c, reservation: owned, shared: shared, environment: environment, slots: make([]ownedListenerSlot, c.Connections), done: make(chan struct{})}
	copy(l.accounts[:], c.Accounts)
	l.c.Accounts = l.accounts[:len(c.Accounts)]
	l.c.TLS, err = prepareTLS(c.TLS, true)
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	cert := c.TLS.Certificates[0]
	cert.Leaf = nil
	cert.Certificate = make([][]byte, len(c.TLS.Certificates[0].Certificate))
	for i, der := range c.TLS.Certificates[0].Certificate {
		cert.Certificate[i] = append([]byte(nil), der...)
	}
	l.c.TLS.Certificates = []tls.Certificate{cert}
	l.c.TLS.NextProtos = append([]string(nil), c.TLS.NextProtos...)
	defer func() {
		if err != nil {
			_ = l.Close()
			_ = l.WaitCleanup(context.Background())
		}
	}()
	l.connectionCharge, err = OwnedCharge(c.Connection)
	if err != nil {
		return nil, err
	}
	config, err := newConfig(c.Connection.Limits)
	if err != nil {
		return nil, err
	}
	l.packet, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(c.Address))
	if err != nil {
		return nil, err
	}
	l.address = l.packet.LocalAddr().(*net.UDPAddr).AddrPort()
	l.transport = &quic.Transport{Conn: stabilizePacketConn(l.packet), ConnectionIDLength: connectionIDLength, ConnContext: l.admit}
	l.listener, err = l.transport.Listen(l.c.TLS, config)
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (l *OwnedListener) admit(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.serial == math.MaxUint64 {
		return nil, resourcev4.ErrClosed
	}
	if err := l.shared.Check(); err != nil {
		return nil, err
	}
	index := -1
	for i := range l.slots {
		if !l.slots[i].used {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, resourcev4.ErrCapacity
	}
	l.serial++
	var seed [32]byte
	copy(seed[:16], l.c.Owner.Backing[:])
	copy(seed[16:24], "quic-v4/")
	binary.BigEndian.PutUint64(seed[24:], l.serial)
	digest := sha256.Sum256(seed[:])
	owner := l.c.Owner
	copy(owner.Backing[:], digest[:16])
	ref, err := l.c.Root.Reserve(owner, l.connectionCharge, l.c.Accounts...)
	if err != nil {
		return nil, err
	}
	defer ref.Release()
	p, err := newOwned(l.c.Connection, ref, l.environment)
	if err != nil {
		return nil, err
	}
	p.listener, p.listenerSlot = l, uint16(index)
	l.slots[index] = ownedListenerSlot{owner: p.ownedConnection, used: true, observing: true}
	id := ownedListenerIdentity{l, p.ownedConnection, uint16(index)}
	// One precharged observer belongs to this original native connection. It
	// reclaims failed TLS/unaccepted connections only after quic-go ends them;
	// accepted owners retain their own actual method and stream retirement.
	go l.observe(ctx, id)
	return context.WithValue(ctx, ownedListenerKey{}, id), nil
}

func (l *OwnedListener) observe(ctx context.Context, id ownedListenerIdentity) {
	<-ctx.Done()
	l.mu.Lock()
	slot := &l.slots[id.slot]
	slot.observing = false
	unaccepted := !slot.handed
	if unaccepted {
		slot.handed = true
	}
	if slot.owner == nil {
		*slot = ownedListenerSlot{}
	}
	l.cleanupLocked()
	l.mu.Unlock()
	if unaccepted {
		p := &OwnedConnection{id.owner}
		_ = p.Close()
		_ = p.WaitCleanup(context.Background())
		_ = p.Retire()
	}
}

// Accept transfers an original pre-TLS reservation, never creates a second
// connection owner from a peer identifier or from a native termination signal.
func (l *OwnedListener) Accept(ctx context.Context) (*OwnedConnection, error) {
	if l == nil || ctx == nil {
		return nil, resourcev4.ErrConfiguration
	}
	l.mu.Lock()
	if l.closed || l.accepting {
		l.mu.Unlock()
		return nil, resourcev4.ErrCapacity
	}
	l.accepting = true
	listener := l.listener
	l.mu.Unlock()
	defer func() { l.mu.Lock(); l.accepting = false; l.cleanupLocked(); l.mu.Unlock() }()
	conn, err := listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	id, ok := conn.Context().Value(ownedListenerKey{}).(ownedListenerIdentity)
	if !ok || id.listener != l {
		_ = conn.CloseWithError(closeCode, "invalid admission owner")
		return nil, resourcev4.ErrOwner
	}
	l.mu.Lock()
	slot := &l.slots[id.slot]
	if l.closed || !slot.used || slot.owner != id.owner || slot.handed || conn.Context().Err() != nil || ctx.Err() != nil {
		l.mu.Unlock()
		_ = conn.CloseWithError(closeCode, "admission closed")
		return nil, resourcev4.ErrClosed
	}
	slot.handed = true
	l.mu.Unlock()
	p := &OwnedConnection{id.owner}
	session, err := newSession(conn, nil, nil, uint16(l.c.Connection.Limits.MaxInboundStreams))
	if err != nil {
		_ = conn.CloseWithError(closeCode, "invalid negotiated transport")
		_ = p.Close()
		_ = p.WaitCleanup(context.Background())
		_ = p.Retire()
		return nil, err
	}
	session.owned = true
	p.mu.Lock()
	p.session = session
	p.mu.Unlock()
	return p, nil
}

func (l *OwnedListener) release(index uint16, owner *ownedConnection) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if int(index) >= len(l.slots) {
		return
	}
	slot := &l.slots[index]
	if slot.owner != owner {
		return
	}
	slot.owner = nil
	if !slot.observing {
		*slot = ownedListenerSlot{}
	}
	l.cleanupLocked()
}

func (l *OwnedListener) Addr() netip.AddrPort { return l.address }

func (l *OwnedListener) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	if l.closed {
		err := l.closeErr
		l.mu.Unlock()
		return err
	}
	l.closed, l.closing = true, true
	listener, transport, packet := l.listener, l.transport, l.packet
	l.mu.Unlock()
	var err error
	if listener != nil {
		err = listener.Close()
	}
	if transport != nil {
		err = errors.Join(err, transport.Close())
	}
	if packet != nil {
		err = errors.Join(err, packet.Close())
	}
	l.mu.Lock()
	l.closeErr, l.closing = err, false
	l.cleanupLocked()
	l.mu.Unlock()
	return err
}

func (l *OwnedListener) cleanupLocked() {
	if !l.closed || l.closing || l.accepting || l.cleaned {
		return
	}
	for _, slot := range l.slots {
		if slot.used {
			return
		}
	}
	l.cleaned = true
	l.listener, l.transport, l.packet, l.slots = nil, nil, nil, nil
	l.c.TLS, l.c.Accounts, l.c.Root = nil, nil, nil
	clear(l.accounts[:])
	l.reservation.Release()
	l.shared.Release()
	l.environment = resourcev4.Reference{}
	close(l.done)
}

func (l *OwnedListener) WaitCleanup(ctx context.Context) error {
	if l == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-l.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
