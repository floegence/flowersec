package rawquic

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/internal/quicfailure"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	quic "github.com/quic-go/quic-go"
)

// OwnedOptions fixes the native connection's complete stream table and local
// provider allowance before UDP/TLS work. ProviderBytes includes the qualified
// QUIC runtime, packet queues and stream/connection flow-control backing. A
// declared allowance is not itself evidence of runtime service qualification.
type OwnedOptions struct {
	Limits                      quicbase.Limits
	StreamSlots                 uint16
	RuntimeBytes, ProviderBytes uint64
	ProviderTasks               uint32
}

func OwnedCharge(o OwnedOptions) (resourcev4.Vector, error) {
	if o.Limits.ValidateV4() != nil || o.StreamSlots < 2 || o.StreamSlots > 4096 ||
		o.RuntimeBytes == 0 || o.ProviderBytes == 0 || o.ProviderTasks == 0 || o.ProviderTasks > 256 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	// Each peer can create at most the original admitted number of incoming
	// streams. The table also includes the local maintenance/data directions.
	if int64(o.StreamSlots) < o.Limits.MaxInboundStreams || o.ProviderBytes < o.Limits.MaxConnectionReceiveWindow {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	fixed := uint64(unsafe.Sizeof(OwnedConnection{})) + uint64(unsafe.Sizeof(ownedConnection{})) +
		uint64(o.StreamSlots)*(uint64(unsafe.Sizeof(ownedStreamSlot{}))+uint64(unsafe.Sizeof(OwnedStream{}))+uint64(unsafe.Sizeof(nativeStreamProtection{}))) +
		uint64(unsafe.Sizeof(preparePacketConn{}))
	return (resourcev4.Vector{resourcev4.SDKBytes: fixed, resourcev4.ProviderBytes: o.ProviderBytes,
		resourcev4.Items: uint64(o.StreamSlots)*2 + 1, resourcev4.WorkSlots: uint64(o.StreamSlots)*4 + 4,
		resourcev4.Tasks: uint64(o.ProviderTasks), resourcev4.Timers: 2,
		resourcev4.Connections: 1, resourcev4.NativeHandles: uint64(o.StreamSlots) + 1,
		resourcev4.TLSHandshakes: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: o.RuntimeBytes})
}

// OwnedConnection contains one canonical native owner. It exposes no raw
// socket, QUIC connection or migration hook. Every stream method pins the same
// original connection backing through actual return, including after Close.
// There is no success/READY capability and no connection-guarantee assertion
// here: the Session assembly separately proves its full transport graph.
type OwnedConnection struct{ *ownedConnection }

type ownedConnection struct {
	environmentBorrow                *native.EnvironmentBorrow
	mu                               sync.Mutex
	session                          *Session
	reservation, environment         resourcev4.Reference
	options                          OwnedOptions
	slots                            []ownedStreamSlot
	serial                           uint64
	calls                            uint32
	opening, accepting, datagramRead bool
	datagramWrite, client            bool
	closed, closing, complete        bool
	retired, maintenanceOpened       bool
	sessionClaimed                   bool
	closeErr                         error
	datagramMaximum                  int
	done                             chan struct{}
	streamWake                       chan struct{}
	listener                         *OwnedListener
	listenerSlot                     uint16
	maintenanceAccept                sync.Once
	maintenanceAcceptErr             error
}

type ownedStreamSlot struct {
	protection                           *nativeStreamProtection
	native                               carrier.Stream
	generation                           uint64
	calls                                uint8
	used, opening, closed, closeReturned bool
	reading, writing, halfClosing        bool
	stopping, resetting                  bool
	cleanup                              chan struct{}
	cleanupComplete                      bool
}

type OwnedStream struct {
	owner      *ownedConnection
	slot       uint16
	generation uint64
}

// DialOwned admits metadata, native capacity and Environment ownership before
// creating its dedicated socket. Remote is an already resolved numeric address;
// there is no DNS, resumption, 0-RTT, proxy or secondary address attempt. Only
// TLS is sent before return. Byte/work caps apply to the actual UDP preparation.
func DialOwned(ctx context.Context, remote netip.AddrPort, config *tls.Config, o OwnedOptions,
	prepareBytes, prepareWork uint64, reservation, environment resourcev4.Reference, admitted ...*native.EnvironmentBorrow,
) (_ *OwnedConnection, err error) {
	if ctx == nil || !remote.IsValid() || remote.Port() == 0 || remote.Addr().Zone() != "" ||
		prepareBytes == 0 || prepareBytes > 262144 || prepareWork == 0 || prepareWork > math.MaxInt64 ||
		config == nil || len(config.Certificates) != 0 || config.GetClientCertificate != nil {
		return nil, resourcev4.ErrConfiguration
	}
	prepared, err := prepareTLS(config, false)
	if err != nil {
		return nil, err
	}
	qconfig, err := newConfig(o.Limits)
	if err != nil {
		return nil, err
	}
	p, err := newOwned(o, reservation, environment, admitted...)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = p.Close()
			_ = p.WaitCleanup(context.Background())
			_ = p.Retire()
		}
	}()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	network := "udp6"
	local := &net.UDPAddr{IP: net.IPv6unspecified}
	if remote.Addr().Is4() {
		network, local.IP = "udp4", net.IPv4zero
	}
	socket, err := net.ListenUDP(network, local)
	if err != nil {
		return nil, err
	}
	packet := &preparePacketConn{tunablePacketConn: socket}
	packet.bytes.Store(int64(prepareBytes))
	packet.work.Store(int64(prepareWork))
	packet.preparing.Store(true)
	if prepared.ServerName == "" {
		prepared.ServerName = remote.Addr().String()
	}
	p.session, err = dialPacketConn(ctx, net.UDPAddrFromAddrPort(remote), prepared, qconfig, uint16(o.Limits.MaxInboundStreams), packet)
	if err != nil {
		return nil, quicfailure.Connection(err)
	}
	packet.preparing.Store(false)
	p.session.owned = true
	p.client = true
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return p, nil
}

// AcceptOwned transfers one original accepted native Session. It cannot adopt
// an arbitrary transport implementation. The listener retains its separate
// UDP/listener charge until all of its accepted connection users have retired.
// Failure leaves the native Session with the caller.
func AcceptOwned(session *Session, o OwnedOptions, reservation, environment resourcev4.Reference) (*OwnedConnection, error) {
	if session == nil || session.conn == nil || session.transport != nil || session.packetConn != nil ||
		session.capacity != uint16(o.Limits.MaxInboundStreams) {
		return nil, resourcev4.ErrConfiguration
	}
	if err := session.conn.Context().Err(); err != nil {
		return nil, err
	}
	// Exclusive adoption is fenced on the actual native object, not a wrapper
	// address or caller-populated generation. It also excludes later migration.
	session.migrationMu.Lock()
	defer session.migrationMu.Unlock()
	if session.owned || session.rawUsed || session.migration != nil || len(session.migrationTransports) != 0 {
		return nil, resourcev4.ErrOwner
	}
	p, err := newOwned(o, reservation, environment)
	if err != nil {
		return nil, err
	}
	session.owned = true
	p.session = session
	return p, nil
}

func newOwned(o OwnedOptions, reservation, environment resourcev4.Reference, admitted ...*native.EnvironmentBorrow) (*OwnedConnection, error) {
	charge, err := OwnedCharge(o)
	if err != nil {
		return nil, err
	}
	if reservation == environment {
		return nil, resourcev4.ErrOwner
	}
	if err = reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	shared, original, err := native.TakeEnvironmentBorrow(environment, admitted...)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		native.ReleaseEnvironmentBorrow(shared, original)
		return nil, err
	}
	return &OwnedConnection{&ownedConnection{options: o, reservation: owned, environment: shared, environmentBorrow: original,
		slots: make([]ownedStreamSlot, o.StreamSlots), done: make(chan struct{}), datagramMaximum: carrier.MaxUnreliableWireBytes}}, nil
}

func (p *OwnedConnection) CheckEnvironment(environment resourcev4.Reference) error {
	if p == nil || p.ownedConnection == nil {
		return resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return resourcev4.ErrClosed
	}
	return p.reservation.CheckSameEnvironment(environment)
}

// ClaimSession is the once-only transfer into one original Session graph.
func (p *OwnedConnection) ClaimSession(environment resourcev4.Reference) error {
	if p == nil || p.ownedConnection == nil {
		return resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(); err != nil {
		return err
	}
	if err := p.reservation.CheckSameEnvironment(environment); err != nil {
		return err
	}
	if p.sessionClaimed || !p.maintenanceOpened {
		return resourcev4.ErrOwner
	}
	p.sessionClaimed = true
	return nil
}

// CheckStreamCapacity validates actual provider positions before Session claim.
func (p *OwnedConnection) CheckStreamCapacity(required uint32) error {
	if p == nil || p.ownedConnection == nil {
		return resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(); err != nil {
		return err
	}
	if required > uint32(p.options.StreamSlots) || int64(required) > p.options.Limits.MaxInboundStreams {
		return resourcev4.ErrCapacity
	}
	return nil
}

func (p *ownedConnection) checkLocked() error {
	if p.closed || p.retired || p.session == nil {
		return resourcev4.ErrClosed
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	if err := p.environment.Check(); err != nil {
		return err
	}
	return p.session.conn.Context().Err()
}

// TLSState reads the exact original negotiated connection after TLS Finished.
// Its certificate pointers are immutable borrowed provider state; callers must
// not retain them beyond this owner's cleanup or use them as activation proof.
func (p *OwnedConnection) TLSState() (tls.ConnectionState, error) {
	if p == nil || p.ownedConnection == nil {
		return tls.ConnectionState{}, resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(); err != nil {
		return tls.ConnectionState{}, err
	}
	state := p.session.conn.ConnectionState()
	if !state.TLS.HandshakeComplete || state.TLS.Version != tls.VersionTLS13 || state.Used0RTT || state.TLS.DidResume || !validALPN(state.TLS.NegotiatedProtocol) {
		return tls.ConnectionState{}, ErrInvalidTLS
	}
	return state.TLS, nil
}

// OpenMaintenance is once-only, even when its original operation fails. The
// native stream may remain empty until original durable consumption permits
// the initial Flowersec flight. Incoming and outgoing DATA use separate slots.
func (p *OwnedConnection) OpenMaintenance(ctx context.Context) (*OwnedStream, error) {
	return p.open(ctx, false, true)
}

func (p *OwnedConnection) AcceptMaintenance(ctx context.Context) (*OwnedStream, error) {
	return p.open(ctx, true, true)
}

// PrepareMaintenance reserves the original incoming maintenance position
// without waiting for a remotely visible STREAM frame. The first I/O accepts
// that same stream once; closing it before acceptance closes the connection.
// This lets a physical listener finish native preparation before the original
// authorization permits its peer to publish the first Flowersec byte.
func (p *OwnedConnection) PrepareMaintenance(ctx context.Context) (*OwnedStream, error) {
	return p.openOriginal(ctx, true, true, nil, true)
}

func (p *OwnedConnection) OpenStream(ctx context.Context) (*OwnedStream, error) {
	return p.open(ctx, false, false)
}

func (p *OwnedConnection) AcceptStream(ctx context.Context) (*OwnedStream, error) {
	return p.open(ctx, true, false)
}

func (p *OwnedConnection) open(ctx context.Context, accept, maintenance bool) (*OwnedStream, error) {
	return p.openProtected(ctx, accept, maintenance, nil)
}

func (p *OwnedConnection) openProtected(ctx context.Context, accept, maintenance bool, protection *nativeStreamProtection) (*OwnedStream, error) {
	return p.openOriginal(ctx, accept, maintenance, protection, false)
}

func (p *OwnedConnection) openOriginal(ctx context.Context, accept, maintenance bool, protection *nativeStreamProtection, deferAccept bool) (*OwnedStream, error) {
	if p == nil || p.ownedConnection == nil || ctx == nil {
		return nil, resourcev4.ErrConfiguration
	}
	p.mu.Lock()
	if err := p.checkLocked(); err != nil {
		p.mu.Unlock()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		p.mu.Unlock()
		return nil, err
	}
	if maintenance && (accept == p.client || p.maintenanceOpened) || !maintenance && !p.maintenanceOpened {
		p.mu.Unlock()
		return nil, resourcev4.ErrOwner
	}
	if accept && p.accepting || !accept && protection == nil && p.opening || p.serial == math.MaxUint64 {
		p.mu.Unlock()
		return nil, resourcev4.ErrCapacity
	}
	index := -1
	if protection != nil {
		if protection.owner != p.ownedConnection || accept || maintenance {
			p.mu.Unlock()
			return nil, resourcev4.ErrOwner
		}
		if err := protection.availableLocked(); err != nil {
			p.mu.Unlock()
			return nil, err
		}
		index = int(protection.index)
	} else {
		for i := range p.slots {
			if !p.slots[i].used && p.slots[i].protection == nil {
				index = i
				break
			}
		}
	}
	if index < 0 && accept && !maintenance {
		var err error
		index, err = p.waitStreamSlotLocked(ctx)
		if err != nil {
			p.mu.Unlock()
			return nil, err
		}
	}
	if index < 0 {
		p.mu.Unlock()
		return nil, resourcev4.ErrCapacity
	}
	p.serial++
	generation := p.serial
	p.slots[index] = ownedStreamSlot{protection: protection, used: true, opening: !deferAccept, generation: generation, cleanup: make(chan struct{})}
	if maintenance {
		p.maintenanceOpened = true
	}
	if deferAccept {
		// Reserve native acceptance as well as the prepaid stream slot. A
		// DATA accept cannot consume stream zero before maintenance I/O starts.
		p.accepting = true
		p.mu.Unlock()
		return &OwnedStream{owner: p.ownedConnection, slot: uint16(index), generation: generation}, nil
	}
	if accept {
		p.accepting = true
	} else if protection == nil {
		p.opening = true
	}
	p.calls++
	session := p.session
	p.mu.Unlock()
	var native carrier.Stream
	var err error
	if accept {
		native, err = session.acceptStream(ctx)
	} else {
		native, err = session.openStream(ctx)
	}
	err = quicfailure.Connection(err)
	p.mu.Lock()
	if err == nil {
		err = p.checkLocked()
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && maintenance {
		stream, ok := native.(*Stream)
		if !ok || stream.NativeStreamID() != 0 {
			err = resourcev4.ErrOwner
		}
	}
	if err != nil && native != nil {
		p.mu.Unlock()
		_ = native.Close()
		p.mu.Lock()
	}
	p.calls--
	if accept {
		p.accepting = false
	} else if protection == nil {
		p.opening = false
	}
	if err != nil {
		p.resetStreamLocked(&p.slots[index])
	} else {
		p.slots[index].native, p.slots[index].opening = native, false
	}
	p.cleanupLocked()
	p.mu.Unlock()
	if err != nil {
		if maintenance {
			_ = p.Close()
		}
		return nil, err
	}
	return &OwnedStream{owner: p.ownedConnection, slot: uint16(index), generation: generation}, nil
}

// Datagram methods own one position per direction and expose only caller-owned
// receive storage. QUIC's queued datagram and packet backing stays inside the
// original provider charge; a caller never retains the provider's receive slice.
// MaxDatagramBytes is the provider's local Flowersec submission cap. QUIC's
// actual path check may still reject a submission if the native limit shrinks.
// A smaller observed limit is retained for subsequent local admission; the
// owner never probes or retransmits the consumed application datagram.
func (p *OwnedConnection) MaxDatagramBytes() int {
	if p == nil || p.ownedConnection == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.checkLocked() != nil {
		return 0
	}
	return p.datagramMaximum
}

func (p *OwnedConnection) SendDatagram(src []byte) error {
	if len(src) == 0 || len(src) > carrier.MaxUnreliableWireBytes {
		return carrier.ErrUnreliableTooLarge
	}
	session, err := p.beginDatagram(false)
	if err != nil {
		return err
	}
	defer p.endDatagram(false)
	err = session.conn.SendDatagram(src)
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		p.mu.Lock()
		p.datagramMaximum = min(p.datagramMaximum, max(0, int(tooLarge.MaxDatagramPayloadSize)))
		p.mu.Unlock()
		return carrier.ErrUnreliableTooLarge
	}
	return quicfailure.Connection(err)
}

func (p *OwnedConnection) ReceiveDatagram(ctx context.Context, dst []byte) (int, error) {
	if ctx == nil || len(dst) < carrier.MaxUnreliableWireBytes {
		return 0, resourcev4.ErrConfiguration
	}
	session, err := p.beginDatagram(true)
	if err != nil {
		return 0, err
	}
	defer p.endDatagram(true)
	packet, err := session.receiveUnreliable(ctx)
	if err != nil {
		return 0, quicfailure.Connection(err)
	}
	if len(packet) == 0 || len(packet) > carrier.MaxUnreliableWireBytes {
		return 0, carrier.ErrUnreliableTooLarge
	}
	return copy(dst, packet), nil
}

func (p *OwnedConnection) beginDatagram(read bool) (*Session, error) {
	if p == nil || p.ownedConnection == nil {
		return nil, resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(); err != nil {
		return nil, err
	}
	if !p.maintenanceOpened {
		return nil, resourcev4.ErrOwner
	}
	if read && p.datagramRead || !read && p.datagramWrite {
		return nil, resourcev4.ErrCapacity
	}
	if read {
		p.datagramRead = true
	} else {
		p.datagramWrite = true
	}
	p.calls++
	return p.session, nil
}

func (p *OwnedConnection) endDatagram(read bool) {
	p.mu.Lock()
	if read {
		p.datagramRead = false
	} else {
		p.datagramWrite = false
	}
	p.calls--
	p.cleanupLocked()
	p.mu.Unlock()
}

func (p *OwnedConnection) Close() error {
	if p == nil || p.ownedConnection == nil {
		return nil
	}
	p.mu.Lock()
	if p.closed {
		err := p.closeErr
		p.mu.Unlock()
		return err
	}
	p.closed, p.closing = true, true
	p.closeStreamProtectionsLocked()
	p.reservation.Seal()
	session := p.session
	p.mu.Unlock()
	var err error
	if session != nil {
		err = session.closeWithErrorContext(context.Background(), carrier.ApplicationError{Code: uint64(closeCode)})
	}
	p.mu.Lock()
	p.closeErr, p.closing = err, false
	p.cleanupLocked()
	p.mu.Unlock()
	return err
}

func (p *ownedConnection) cleanupLocked() {

	for i := range p.slots {
		slot := &p.slots[i]
		if slot.used && !slot.cleanupComplete && slot.closed && slot.closeReturned && slot.calls == 0 {
			slot.cleanupComplete = true
			close(slot.cleanup)
		}
	}
	if p.closed && !p.closing && p.calls == 0 && !p.complete {
		p.complete = true
		close(p.done)
	}
}

func (p *OwnedConnection) WaitCleanup(ctx context.Context) error {
	if p == nil || p.ownedConnection == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Retire requires actual connection closure and method exits plus retirement
// of every delivered stream. Aliases cannot read a recycled table slot.
func (p *OwnedConnection) Retire() error {
	if p == nil || p.ownedConnection == nil {
		return nil
	}
	p.mu.Lock()
	var listener *OwnedListener
	defer func() {
		p.mu.Unlock()
		if listener != nil {
			listener.release(p.listenerSlot, p.ownedConnection)
		}
	}()
	if p.retired {
		return nil
	}
	if !p.complete {
		return resourcev4.ErrOwner
	}
	for _, slot := range p.slots {
		if slot.used {
			return resourcev4.ErrOwner
		}
	}
	p.retired = true
	p.session, p.slots = nil, nil
	p.reservation.Release()
	native.ReleaseEnvironmentBorrow(p.environment, p.environmentBorrow)
	p.environmentBorrow = nil
	p.environment = resourcev4.Reference{}
	listener, p.listener = p.listener, nil
	return nil
}

func (s *OwnedStream) slotLocked() (*ownedStreamSlot, error) {
	if int(s.slot) >= len(s.owner.slots) {
		return nil, resourcev4.ErrOwner
	}
	slot := &s.owner.slots[s.slot]
	if !slot.used || slot.generation != s.generation || slot.opening {
		return nil, resourcev4.ErrOwner
	}
	return slot, nil
}

const (
	ownedRead = iota
	ownedWrite
	ownedHalfClose
	ownedStop
	ownedReset
)

func slotOperation(slot *ownedStreamSlot, op int) *bool {
	switch op {
	case ownedRead:
		return &slot.reading
	case ownedWrite:
		return &slot.writing
	case ownedHalfClose:
		return &slot.halfClosing
	case ownedStop:
		return &slot.stopping
	default:
		return &slot.resetting
	}
}

func (s *OwnedStream) begin(op int) (carrier.Stream, error) {
	if s == nil || s.owner == nil {
		return nil, resourcev4.ErrOwner
	}
	p := s.owner
	p.mu.Lock()
	if err := p.checkLocked(); err != nil {
		p.mu.Unlock()
		return nil, err
	}
	slot, err := s.slotLocked()
	if err != nil {
		p.mu.Unlock()
		return nil, err
	}
	if slot.closed {
		p.mu.Unlock()
		return nil, resourcev4.ErrClosed
	}
	if slot.native == nil && op != ownedRead && op != ownedWrite {
		p.mu.Unlock()
		return nil, resourcev4.ErrOwner
	}
	busy := slotOperation(slot, op)
	if *busy || op == ownedWrite && slot.halfClosing || op == ownedHalfClose && slot.writing {
		p.mu.Unlock()
		return nil, resourcev4.ErrCapacity
	}
	*busy = true
	slot.calls++
	p.calls++
	native := slot.native
	p.mu.Unlock()
	if native != nil {
		return native, nil
	}
	native, err = s.acceptMaintenance()
	if err != nil {
		s.end(op)
	}
	return native, err
}

func (s *OwnedStream) acceptMaintenance() (carrier.Stream, error) {
	p := s.owner
	// Concurrent read/write observers retain their existing method positions
	// while the same original connection owns exactly one native acceptance.
	p.maintenanceAccept.Do(func() {
		p.mu.Lock()
		slot, err := s.slotLocked()
		if err == nil {
			err = p.checkLocked()
		}
		if err == nil && (slot.closed || !p.accepting) {
			err = resourcev4.ErrClosed
		}
		if err != nil {
			p.accepting = false
			p.maintenanceAcceptErr = err
			p.mu.Unlock()
			return
		}
		session := p.session
		p.mu.Unlock()
		native, err := session.acceptStream(session.conn.Context())
		err = quicfailure.Connection(err)
		if err == nil {
			stream, ok := native.(*Stream)
			if !ok || stream.NativeStreamID() != 0 {
				err = resourcev4.ErrOwner
			}
		}
		p.mu.Lock()
		if err == nil {
			err = p.checkLocked()
		}
		if err == nil && slot.closed {
			err = resourcev4.ErrClosed
		}
		if err == nil {
			slot.native = native
		}
		p.accepting = false
		p.maintenanceAcceptErr = err
		p.mu.Unlock()
		if err != nil && native != nil {
			_ = native.Close()
		}
	})
	if err := p.maintenanceAcceptErr; err != nil {
		_ = (&OwnedConnection{p}).Close()
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	slot, err := s.slotLocked()
	if err != nil {
		return nil, err
	}
	if err = p.checkLocked(); err != nil {
		return nil, err
	}
	if slot.closed || slot.native == nil {
		return nil, resourcev4.ErrClosed
	}
	return slot.native, nil
}

func (s *OwnedStream) end(op int) {
	p := s.owner
	p.mu.Lock()
	slot, err := s.slotLocked()
	if err == nil {
		*slotOperation(slot, op) = false
		slot.calls--
		p.calls--
	}
	p.cleanupLocked()
	p.mu.Unlock()
}

func (s *OwnedStream) Read(dst []byte) (int, error) {
	native, err := s.begin(ownedRead)
	if err != nil {
		return 0, err
	}
	defer s.end(ownedRead)
	n, err := native.Read(dst)
	return n, streamDirectionFailure(err)
}

func (s *OwnedStream) Write(src []byte) (int, error) {
	native, err := s.begin(ownedWrite)
	if err != nil {
		return 0, err
	}
	defer s.end(ownedWrite)
	n, err := native.Write(src)
	return n, streamDirectionFailure(err)
}

func (s *OwnedStream) CloseWrite() error {
	native, err := s.begin(ownedHalfClose)
	if err != nil {
		return err
	}
	defer s.end(ownedHalfClose)
	return native.CloseWrite()
}

func (s *OwnedStream) StopSending() error {
	native, err := s.begin(ownedStop)
	if err != nil {
		return err
	}
	defer s.end(ownedStop)
	return native.StopSending()
}

// ResetWrite cancels only the original send direction. It unblocks a pending
// Write without canceling the reverse Read or manufacturing an E2EE terminal.
func (s *OwnedStream) ResetWrite() error {
	native, err := s.begin(ownedReset)
	if err != nil {
		return err
	}
	defer s.end(ownedReset)
	stream := native.(*Stream)
	stream.stream.CancelWrite(streamResetCode)
	stream.lifecycle.CloseWriteResult(nil)
	return nil
}

// WaitCleanup observes actual provider method exits after Close. It neither
// closes the peer direction nor substitutes native FIN for authenticated proof.
func (s *OwnedStream) WaitCleanup(ctx context.Context) error {
	if s == nil || s.owner == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	p := s.owner
	p.mu.Lock()
	slot, err := s.slotLocked()
	if err != nil {
		p.mu.Unlock()
		return err
	}
	cleanup := slot.cleanup
	p.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-cleanup:
		return nil
	case <-p.done:
		return nil
	}
}

func (s *OwnedStream) Reset() error { return s.Close() }

func (s *OwnedStream) Close() error {
	if s == nil || s.owner == nil {
		return resourcev4.ErrOwner
	}
	p := s.owner
	p.mu.Lock()
	slot, err := s.slotLocked()
	if err != nil {
		p.mu.Unlock()
		return err
	}
	if slot.closed {
		p.mu.Unlock()
		return nil
	}
	slot.closed = true
	slot.calls++
	p.calls++
	native := slot.native
	p.mu.Unlock()
	if native == nil {
		// There is no stream handle to cancel yet. Closing the same connection
		// interrupts its original accept and all observers join through calls.
		err = (&OwnedConnection{p}).Close()
	} else {
		err = native.Close()
	}
	p.mu.Lock()
	slot.closeReturned = true
	slot.calls--
	p.calls--
	p.cleanupLocked()
	p.mu.Unlock()
	return err
}

func (s *OwnedStream) Retire() error {
	if s == nil || s.owner == nil {
		return resourcev4.ErrOwner
	}
	p := s.owner
	p.mu.Lock()
	defer p.mu.Unlock()
	slot, err := s.slotLocked()
	if err != nil {
		return err
	}
	if slot.calls != 0 || !p.complete && (!slot.closed || !slot.closeReturned) {
		return resourcev4.ErrOwner
	}
	p.resetStreamLocked(slot)
	return nil
}

func (s *OwnedStream) Context() context.Context {
	if s == nil || s.owner == nil {
		return deadStreamContext
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	slot, err := s.slotLocked()
	if err != nil || slot.closed || s.owner.closed {
		return deadStreamContext
	}
	if slot.native == nil {
		return s.owner.session.conn.Context()
	}
	return slot.native.Context()
}

var deadStreamContext = func() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}()

var ErrPrepareBudget = errors.New("rawquic: original preparation budget exhausted")

// The wrapper deliberately preserves numeric UDP controls while omitting GSO,
// just like the original raw QUIC socket. Limits count actual original packet
// work. An exhausted budget never becomes a new address/connection attempt.
type preparePacketConn struct {
	tunablePacketConn
	preparing   atomic.Bool
	bytes, work atomic.Int64
}

func (c *preparePacketConn) charge(n int) error {
	if c.preparing.Load() && (c.work.Add(-1) < 0 || c.bytes.Add(-int64(n)) < 0) {
		return ErrPrepareBudget
	}
	return nil
}

func (c *preparePacketConn) ReadFrom(dst []byte) (int, net.Addr, error) {
	n, address, err := c.tunablePacketConn.ReadFrom(dst)
	if n != 0 {
		if budgetErr := c.charge(n); budgetErr != nil {
			return 0, nil, budgetErr
		}
	}
	return n, address, err
}

func (c *preparePacketConn) WriteTo(src []byte, address net.Addr) (int, error) {
	if err := c.charge(len(src)); err != nil {
		return 0, err
	}
	return c.tunablePacketConn.WriteTo(src, address)
}

var _ io.ReadWriteCloser = (*OwnedStream)(nil)
