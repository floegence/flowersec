package webtransport

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
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
	CheckOrigin                 func(*http.Request) bool
	CheckRequest                func(*http.Request) bool
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
	server              *Server
	ready               chan *OwnedConnection
	failures            chan error
	serving             bool
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
	stop                chan struct{}
}

type ownedListenerSlot struct {
	owner                 *ownedConnection
	used, handed, claimed bool
	observing             bool
	failureReported       bool
}

type ownedListenerKey struct{}
type ownedListenerIdentity struct {
	listener *OwnedListener
	owner    *ownedConnection
	slot     uint16
}

func OwnedListenerCharge(c OwnedListenerConfig) (resourcev4.Vector, error) {
	if c.CheckOrigin == nil || c.CheckRequest == nil || c.Root == nil || !c.Address.IsValid() || c.Address.Addr().Zone() != "" ||
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
	bytes := uint64(unsafe.Sizeof(OwnedListener{})) + uint64(c.Connections)*(uint64(unsafe.Sizeof(ownedListenerSlot{}))+uint64(unsafe.Sizeof(ownedListenerIdentity{}))+uint64(unsafe.Sizeof(error(nil))))
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
	l := &OwnedListener{c: c, reservation: owned, shared: shared, environment: environment, slots: make([]ownedListenerSlot, c.Connections), done: make(chan struct{}), stop: make(chan struct{}), ready: make(chan *OwnedConnection, c.Connections), failures: make(chan error, c.Connections)}
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
	config, err := newServerQUICConfig(c.Connection.Limits)
	if err != nil {
		return nil, err
	}
	l.packet, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(c.Address))
	if err != nil {
		return nil, err
	}
	l.address = l.packet.LocalAddr().(*net.UDPAddr).AddrPort()
	l.transport = &quic.Transport{Conn: &packetConnWithoutGSO{l.packet}, ConnContext: l.admit}
	l.listener, err = l.transport.Listen(l.c.TLS, config)
	if err != nil {
		return nil, err
	}
	l.server, err = NewServer(l.c.TLS, c.Connection.Limits, c.CheckOrigin)
	if err != nil {
		return nil, err
	}
	l.server.SetHandler(http.HandlerFunc(l.upgrade))
	l.serving = true
	go l.serve()
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
	copy(seed[16:24], "wt-v4///")
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

// serve starts one precharged H3 task only after the original TLS connection
// has a resource owner. A stalled CONNECT retains that original finite slot.
func (l *OwnedListener) serve() {
	defer func() { l.mu.Lock(); l.serving = false; l.cleanupLocked(); l.mu.Unlock() }()
	for {
		conn, err := l.listener.Accept(context.Background())
		if err != nil {
			return
		}
		id, ok := conn.Context().Value(ownedListenerKey{}).(ownedListenerIdentity)
		if !ok || id.listener != l {
			_ = conn.CloseWithError(0, "invalid owner")
			continue
		}
		l.mu.Lock()
		slot := &l.slots[id.slot]
		if l.closed || slot.owner != id.owner || slot.handed || conn.Context().Err() != nil {
			l.mu.Unlock()
			_ = conn.CloseWithError(0, "closed")
			continue
		}
		p := id.owner
		nativeSession := newOwnedNativeSession(conn, l.c.Connection, false)
		p.mu.Lock()
		p.conn, p.session, p.nativeDone = conn, nativeSession, false
		p.mu.Unlock()
		l.mu.Unlock()
		h3, err := l.server.inner.H3.NewRawServerConn(conn)
		if err != nil {
			_ = conn.CloseWithError(0, "")
			p.mu.Lock()
			p.nativeDone = true
			p.cleanupLocked()
			p.mu.Unlock()
			close(nativeSession.done)
			continue
		}
		nativeSession.start(h3.HandleUnidirectionalStream, h3.HandleRequestStream)
		go func() { <-nativeSession.done; p.mu.Lock(); p.nativeDone = true; p.cleanupLocked(); p.mu.Unlock() }()
	}
}

func (l *OwnedListener) upgrade(w http.ResponseWriter, r *http.Request) {
	guard, ok := r.Context().Value(connectionKey{}).(*connectionGuard)
	if !ok || guard.conn == nil {
		http.Error(w, "invalid endpoint", http.StatusForbidden)
		return
	}
	id, ok := guard.conn.Context().Value(ownedListenerKey{}).(ownedListenerIdentity)
	if !ok || id.listener != l {
		http.Error(w, "invalid owner", http.StatusForbidden)
		return
	}
	if !l.c.CheckRequest(r) {
		l.reportUpgradeFailure(id, ErrInvalidURL)
		http.Error(w, "invalid endpoint", http.StatusForbidden)
		_ = guard.conn.CloseWithError(0, "invalid endpoint")
		return
	}
	if err := l.server.checkNativeTuple(w, r); err != nil {
		l.reportUpgradeFailure(id, err)
		_ = guard.conn.CloseWithError(0, "upgrade rejected")
		return
	}
	if !l.c.CheckOrigin(r) {
		l.reportUpgradeFailure(id, ErrOriginPolicyRequired)
		_ = guard.conn.CloseWithError(0, "upgrade rejected")
		return
	}
	endpoint, err := acceptedEndpoint(guard.conn, r)
	if err != nil {
		l.reportUpgradeFailure(id, err)
		_ = guard.conn.CloseWithError(0, "invalid endpoint")
		return
	}
	stream, ok := w.(http3.HTTPStreamer)
	if !ok {
		l.reportUpgradeFailure(id, ErrNativeTuple)
		_ = guard.conn.CloseWithError(0, "invalid HTTP stream")
		return
	}
	request := stream.HTTPStream()
	// The same actual CONNECT stream supplies both reliable association and
	// RFC HTTP/3 datagram context; no guessed Session ID is installed.
	// The native provider adds/removes the standard 0x41 + CONNECT-ID
	// association prefix for both browsers and Go. JavaScript sees only
	// application bytes; the original CONNECT still owns each QUIC stream.
	if err = id.owner.session.install(request); err != nil {
		l.reportUpgradeFailure(id, err)
		_ = guard.conn.CloseWithError(0, "invalid association")
		return
	}
	w.WriteHeader(http.StatusOK)
	if err = http.NewResponseController(w).Flush(); err != nil {
		l.reportUpgradeFailure(id, err)
		_ = guard.conn.CloseWithError(0, "response failed")
		return
	}

	l.mu.Lock()
	slot := &l.slots[id.slot]
	if l.closed || slot.owner != id.owner || slot.handed || guard.conn.Context().Err() != nil {
		l.mu.Unlock()
		_ = guard.conn.CloseWithError(0, "closed")
		return
	}
	p := id.owner
	p.mu.Lock()
	p.endpoint = endpoint
	p.mu.Unlock()
	slot.handed = true
	l.ready <- &OwnedConnection{p}
	l.mu.Unlock()
}

// One original native connection may report at most one pre-admission
// failure. The finite queue wakes Accept with the actual upgrade cause without
// selecting or completing any installed Flowersec material.
func (l *OwnedListener) reportUpgradeFailure(id ownedListenerIdentity, err error) {
	if err == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || id.listener != l || int(id.slot) >= len(l.slots) {
		return
	}
	slot := &l.slots[id.slot]
	if slot.owner != id.owner || slot.handed || slot.failureReported {
		return
	}
	slot.failureReported = true
	select {
	case l.failures <- err:
	default:
	}
}

// Accept transfers the once-only native owner installed before TLS. A queued
// or cancelled connection cannot become a replacement Session continuation.
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
	l.mu.Unlock()
	defer func() { l.mu.Lock(); l.accepting = false; l.cleanupLocked(); l.mu.Unlock() }()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.listenerContext():
		return nil, resourcev4.ErrClosed
	case err := <-l.failures:
		return nil, err
	case p := <-l.ready:
		l.mu.Lock()
		slot := &l.slots[p.listenerSlot]
		if l.closed || slot.owner != p.ownedConnection || slot.claimed {
			l.mu.Unlock()
			return nil, resourcev4.ErrClosed
		}
		slot.claimed = true
		l.mu.Unlock()
		if err := ctx.Err(); err != nil {
			_ = p.Close()
			_ = p.WaitCleanup(context.Background())
			_ = p.Retire()
			return nil, err
		}
		return p, nil
	}
}

func (l *OwnedListener) listenerContext() <-chan struct{} { return l.stop }

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
	close(l.stop)
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
	if l.server != nil {
		err = errors.Join(err, l.server.Close())
	}
	// Closing queued entrances is owned here; transferred entrances retain the
	// actual Session retirement responsibility.
	for index := range l.slots {
		l.mu.Lock()
		slot := &l.slots[index]
		var pending *OwnedConnection
		if slot.used && slot.handed && !slot.claimed {
			slot.claimed = true
			pending = &OwnedConnection{slot.owner}
		}
		l.mu.Unlock()
		if pending != nil {
			_ = pending.Close()
			_ = pending.WaitCleanup(context.Background())
			_ = pending.Retire()
		}
	}
	l.mu.Lock()
	l.closeErr, l.closing = err, false
	l.cleanupLocked()
	l.mu.Unlock()
	return err
}

func (l *OwnedListener) cleanupLocked() {
	if !l.closed || l.closing || l.accepting || l.serving || l.cleaned {
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

type packetConnWithoutGSO struct{ tunablePacketConn }
