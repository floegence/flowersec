package sessionv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

var (
	ErrCredit     = errors.New("sessionv4: receive credit exhausted")
	ErrStreamData = errors.New("sessionv4: invalid authenticated Stream data")
	ErrTerminal   = errors.New("sessionv4: conflicting terminal frontier")
	ErrAbandoned  = errors.New("sessionv4: receive direction abandoned")
	ErrFlowClosed = errors.New("sessionv4: receive owner closed")
)

// TerminalTuple always describes an application direction's original frontier,
// even when a later maintenance record carries its terminal proof.
type TerminalTuple struct {
	Epoch                uint32
	NextSequence, Offset uint64
}

// ReceivePool accounts one Session traffic direction's aggregate promises.
// Streams share this gate so two simultaneous expansions cannot oversubscribe
// signed.max_credit or the actual reserved local backing pool.
type ReceivePool struct {
	mu                    sync.Mutex
	limit, used           uint64
	capacity, backingUsed uint64
	maxFlows, flows       uint32
	reservation           resourcev4.Reference
	protections           *ReceiveProtection
	closed                bool
	done                  chan struct{}
}

// ReceivePoolCharge includes the complete local ring capacity and a finite
// number of direction owners. Root reference/slab metadata is charged by the
// actual shared root. Each direction includes one bounded read/wait position.
// The selected profile adds channel, stack and allocator overhead to this
// minimum before reserving; this size is not a runtime/RSS qualification.
func ReceivePoolCharge(localCapacity uint64, maxFlows uint32) (resourcev4.Vector, error) {
	if localCapacity > math.MaxInt64 || maxFlows == 0 {
		return resourcev4.Vector{}, ErrCredit
	}
	metadata := uint64(unsafe.Sizeof(ReceivePool{})) + uint64(maxFlows)*(uint64(unsafe.Sizeof(ReceiveFlow{}))+uint64(unsafe.Sizeof(ReceiveProtection{})))
	if localCapacity > math.MaxUint64-metadata {
		return resourcev4.Vector{}, ErrCredit
	}
	return resourcev4.Vector{resourcev4.SDKBytes: localCapacity + metadata, resourcev4.Items: 2 * uint64(maxFlows), resourcev4.WorkSlots: uint64(maxFlows), resourcev4.Tasks: uint64(maxFlows)}, nil
}

func NewReceivePool(signedMaxCredit, localCapacity uint64, maxFlows uint32, reservation resourcev4.Reference) (*ReceivePool, error) {
	if signedMaxCredit > math.MaxInt64 {
		return nil, ErrCredit
	}
	charge, err := ReceivePoolCharge(localCapacity, maxFlows)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	return &ReceivePool{limit: min(signedMaxCredit, localCapacity), capacity: localCapacity, maxFlows: maxFlows, reservation: owned, done: make(chan struct{})}, nil
}
func (p *ReceivePool) Outstanding() uint64 { p.mu.Lock(); defer p.mu.Unlock(); return p.used }
func (p *ReceivePool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		for g := p.protections; g != nil; {
			next := g.next
			g.closeLocked()
			g = next
		}
		close(p.done)
		p.reservation.Seal()
		p.reservation.Release()
	}
}

// ReceiveFlow allocates its own ring only after reserving physical capacity
// from the pool. Zero credit does not make a ring free. It retains a real root
// reference until Cleanup, independently of consumed/revoked credit. Creation
// does not authorize OPEN: a bootstrap or accepted Stream owner installs it.
type ReceiveFlow struct {
	pool                                   *ReceivePool
	protection                             *ReceiveProtection
	engine                                 *cryptov4.Engine
	scope                                  uint64
	direction                              protocolv4.Direction
	storage                                []byte
	reservation                            resourcev4.Reference
	head, size                             int
	limit, released                        uint64
	minimumPromise, creditAck, creditLimit uint64
	delivered                              uint64
	observed                               TerminalTuple
	// Last authenticated DATA/OPEN frontier, retained across installed epochs
	// with no records. Together with observed it describes that finite interval
	// without allocating history per rekey.
	lastObserved                                      TerminalTuple
	terminal                                          TerminalTuple
	hasTerminal, graceful, abandoned, fenced, cleaned bool
	readPending                                       bool
	messageAdmissionPaused                            bool
	rawUsed                                           bool
	readOwner                                         *StreamOwnership
	sharedInputFailed                                 bool
	readTails                                         uint32
	readWake, cleanupWake                             chan struct{}
	assembly                                          *NativeDataAssembly
	termination                                       directionTermination
}

func NewReceiveFlow(pool *ReceivePool, scope uint64, direction protocolv4.Direction, initialLimit uint64, frontier TerminalTuple, capacity uint64) (*ReceiveFlow, error) {
	if pool == nil || scope == 0 || scope > math.MaxInt64 || direction > protocolv4.ServerToClient || frontier.Offset != 0 || capacity > uint64(math.MaxInt) || initialLimit > capacity {
		return nil, ErrCredit
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.closed {
		return nil, ErrFlowClosed
	}
	credit, backing, slots := pool.availableLocked(nil)
	if initialLimit > credit {
		return nil, ErrCredit
	}
	if slots == 0 || capacity > backing {
		return nil, resourcev4.ErrCapacity
	}
	ref, err := pool.reservation.Borrow()
	if err != nil {
		return nil, err
	}
	pool.used += initialLimit
	pool.backingUsed += capacity
	pool.flows++
	return newReceiveFlow(pool, scope, direction, initialLimit, frontier, capacity, ref), nil
}

func newReceiveFlow(pool *ReceivePool, scope uint64, direction protocolv4.Direction, initialLimit uint64, frontier TerminalTuple, capacity uint64, ref resourcev4.Reference) *ReceiveFlow {
	return &ReceiveFlow{pool: pool, scope: scope, direction: direction, storage: make([]byte, int(capacity)), reservation: ref, limit: initialLimit, observed: frontier, lastObserved: frontier, readWake: make(chan struct{}, 1), cleanupWake: make(chan struct{}, 1)}
}

// Grant returns an absolute limit for a credit ACK after reserving its delta.
// It never retracts an already granted promise, including after local Reset.
func (f *ReceiveFlow) Grant(newLimit uint64) error {
	p := f.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || f.cleaned {
		return ErrFlowClosed
	}
	if err := f.reservation.Check(); err != nil {
		return err
	}
	if f.abandoned || f.hasTerminal {
		return ErrAbandoned
	}
	if newLimit < f.limit || newLimit < f.released {
		return ErrCredit
	}
	if f.messageAdmissionPaused && newLimit > f.limit {
		return ErrCredit
	}
	delta := newLimit - f.limit
	credit, _, _ := p.availableLocked(f.protection)
	if newLimit-f.released > uint64(len(f.storage)) || delta > credit {
		return ErrCredit
	}
	p.used += delta
	f.limit = newLimit
	return nil
}

// ApplyData consumes an already authenticated frame synchronously, under the
// same gate as queue ownership and credit. Callers release ReceivedRecord after
// this call, so pending application reads do not retain the crypto workspace.
func (f *ReceiveFlow) ApplyData(frame *protocolv4.Frame) error {
	return f.applyData(frame, nil)
}

func (f *ReceiveFlow) applyData(frame *protocolv4.Frame, assembly *NativeDataAssembly) error {
	return f.applyDataMode(frame, assembly, true)
}

func (f *ReceiveFlow) applyDataMode(frame *protocolv4.Frame, assembly *NativeDataAssembly, commit bool) error {
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	return f.applyDataLocked(frame, assembly, commit, false)
}

func (f *ReceiveFlow) applyDataLocked(frame *protocolv4.Frame, assembly *NativeDataAssembly, commit, shared bool) error {
	if frame == nil || frame.Type != protocolv4.FrameStreamData || frame.Header.Scope != f.scope {
		return ErrStreamData
	}
	data, ok := frame.Field("data").ByteString()
	if !ok {
		return ErrStreamData
	}
	offset, ok := frame.Field("offset").Uint()
	if !ok {
		return ErrStreamData
	}
	direction, ok := frame.Field("direction").Uint()
	if !ok || direction != uint64(f.direction) {
		return ErrStreamData
	}
	fin, ok := frame.Field("fin").Bool()
	if !ok {
		return ErrStreamData
	}
	p := f.pool
	if p.closed || f.cleaned || f.fenced && !(shared && f.abandoned && !f.sharedInputFailed) {
		return ErrFlowClosed
	}
	if assembly != nil && assembly.closed {
		return ErrFlowClosed
	}
	if f.assembly != nil && f.assembly.phase != nativeDataPrepared && (f.assembly != assembly || f.assembly.phase != nativeDataAuthenticating) {
		return cryptov4.ErrCapacity
	}
	if err := f.reservation.Check(); err != nil {
		return err
	}
	if frame.Header.Epoch != f.observed.Epoch || frame.Header.Sequence != f.observed.NextSequence || frame.Header.Sequence == math.MaxUint64 || offset != f.observed.Offset {
		return ErrStreamData
	}
	if uint64(len(data)) > math.MaxUint64-offset {
		return ErrStreamData
	}
	end := offset + uint64(len(data))
	if end > f.limit {
		return ErrCredit
	}
	next := TerminalTuple{Epoch: frame.Header.Epoch, NextSequence: frame.Header.Sequence + 1, Offset: end}
	if f.hasTerminal {
		if next.Epoch != f.terminal.Epoch || next.NextSequence > f.terminal.NextSequence || end > f.terminal.Offset {
			return ErrTerminal
		}
		if next.NextSequence == f.terminal.NextSequence && end != f.terminal.Offset {
			return ErrTerminal
		}
	}
	if fin && f.hasTerminal && next != f.terminal {
		return ErrTerminal
	}
	if !f.abandoned && len(data) > len(f.storage)-f.size {
		return ErrCredit
	}
	if !commit {
		return nil
	}
	// A FIN closes the future promise but preserves already queued data.
	if fin && !f.hasTerminal {
		f.termination.start(false, nil)
		f.terminal = next
		f.hasTerminal = true
		f.graceful = !f.abandoned
		p.used -= f.limit - end
		f.limit = end
	}
	f.observed = next
	f.lastObserved = next
	if f.abandoned {
		f.released = end
		p.used -= uint64(len(data))
		if f.termination.service != nil {
			f.termination.service.notify()
		}
		return nil
	}
	if len(data) > 0 {
		tail := (f.head + f.size) % len(f.storage)
		n := copy(f.storage[tail:], data)
		copy(f.storage, data[n:])
		f.size += len(data)
	}
	f.signalReadLocked()
	if f.hasTerminal && f.termination.service != nil {
		f.termination.service.notify()
	}
	return nil
}

// TryRead reports only currently available data. Empty output is open until a
// graceful FIN has been observed AND every queued byte has been delivered.
// Waiting/cancellation belongs to the caller's bounded read owner.
func (f *ReceiveFlow) TryRead(dst []byte) (int, protocolv4.V4ReadTerminal, error) {
	return f.tryReadOwned(dst, nil)
}

func (f *ReceiveFlow) tryReadOwned(dst []byte, owner *StreamOwnership) (int, protocolv4.V4ReadTerminal, error) {
	if len(dst) == 0 {
		return 0, protocolv4.V4ReadTerminalUnknown, ErrReadInput
	}
	p := f.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := f.readOwnershipLocked(owner); err != nil {
		return 0, protocolv4.V4ReadTerminalUnknown, err
	}
	if f.readPending {
		return 0, protocolv4.V4ReadTerminalUnknown, ErrReadInProgress
	}
	terminal, err := f.readStatusLocked()
	if terminal != protocolv4.V4ReadTerminalOpen || err != nil {
		return 0, terminal, err
	}
	return f.readCopyLocked(dst)
}

// The caller owns the original pool/read gate. This check never consumes data.
func (f *ReceiveFlow) readStatusLocked() (protocolv4.V4ReadTerminal, error) {
	p := f.pool
	if f.abandoned {
		if cause := f.termination.firstCause(); cause != nil {
			return protocolv4.V4ReadTerminalAbandoned, cause
		}
		return protocolv4.V4ReadTerminalAbandoned, ErrAbandoned
	}
	if f.graceful && f.hasTerminal && f.size == 0 && f.released == f.terminal.Offset {
		return protocolv4.V4ReadTerminalEof, nil
	}
	if p.closed || f.cleaned {
		return protocolv4.V4ReadTerminalUnknown, ErrFlowClosed
	}
	if err := f.reservation.Check(); err != nil {
		return protocolv4.V4ReadTerminalUnknown, err
	}
	if f.engine != nil {
		if err := f.engine.ApplicationInputReady(f.observed.Epoch); err != nil {
			return protocolv4.V4ReadTerminalUnknown, err
		}
	}
	return protocolv4.V4ReadTerminalOpen, nil
}

func (f *ReceiveFlow) readCopyLocked(dst []byte) (int, protocolv4.V4ReadTerminal, error) {
	n := min(len(dst), f.size)
	if n > 0 {
		first := copy(dst[:n], f.storage[f.head:min(len(f.storage), f.head+n)])
		copy(dst[first:n], f.storage[:n-first])
		clear(f.storage[f.head:min(len(f.storage), f.head+n)])
		clear(f.storage[:n-first])
		f.head = (f.head + n) % len(f.storage)
		f.size -= n
		f.released += uint64(n)
		f.delivered += uint64(n)
		f.pool.used -= uint64(n)
		if err := f.replenishCreditLocked(); err != nil {
			return n, protocolv4.V4ReadTerminalUnknown, err
		}
	}
	if f.graceful && f.hasTerminal && f.size == 0 && f.released == f.terminal.Offset {
		return n, protocolv4.V4ReadTerminalEof, nil
	}
	return n, protocolv4.V4ReadTerminalOpen, nil
}

// Abandon seals application delivery immediately. It frees only already
// received bytes; outstanding network promises await authenticated evidence.
func (f *ReceiveFlow) Abandon() {
	p := f.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if f.cleaned {
		return
	}
	f.abandon()
}
func (f *ReceiveFlow) abandon() {
	// Already established EOF is a fact, including after Session idle close.
	// Only a still-open/unread direction can be converted to abandoned.
	if f.abandoned || f.graceful && f.hasTerminal && f.size == 0 && f.released == f.terminal.Offset {
		return
	}
	f.abandoned = true
	f.termination.start(false, ErrAbandoned)
	f.graceful = false
	// A native provider may still be filling the disjoint, unverified assembly
	// region. Only authenticated queued bytes are abandoned here; the original
	// assembly clears its own backing after its actual I/O/authentication exits.
	if f.size != 0 {
		first := min(f.size, len(f.storage)-f.head)
		clear(f.storage[f.head : f.head+first])
		clear(f.storage[:f.size-first])
	}
	f.pool.used -= uint64(f.size)
	f.released += uint64(f.size)
	f.size = 0
	f.head = 0
	f.signalReadLocked()
}

func (f *ReceiveFlow) ApplyStopped(terminal TerminalTuple) error {
	p := f.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrFlowClosed
	}
	if f.hasTerminal {
		if f.terminal != terminal {
			return ErrTerminal
		}
		return nil
	}
	if f.cleaned {
		return ErrFlowClosed
	}
	observed := f.observed
	if terminal.Epoch != observed.Epoch {
		if terminal.Epoch < f.lastObserved.Epoch || terminal.Epoch > observed.Epoch {
			return ErrTerminal
		}
		// An old terminal can arrive under a newer maintenance key. Every
		// intervening epoch was really installed by AdvanceEpoch, and none
		// carried another authenticated record. Select the original frontier;
		// a completed old barrier cannot leave an unseen byte/sequence gap.
		observed = f.lastObserved
		if terminal.Epoch > observed.Epoch {
			observed.Epoch, observed.NextSequence = terminal.Epoch, 0
		}
		if terminal != observed {
			return ErrTerminal
		}
	}
	if terminal.NextSequence < observed.NextSequence || terminal.Offset < observed.Offset || terminal.Offset > f.limit {
		return ErrTerminal
	}
	if terminal.NextSequence == observed.NextSequence && terminal.Offset != observed.Offset {
		return ErrTerminal
	}
	f.observed = observed
	f.abandon()
	f.terminal = terminal
	f.hasTerminal = true
	f.termination.start(false, nil)
	if f.termination.service != nil {
		f.termination.service.notify()
	}
	p.used -= f.limit - terminal.Offset
	f.limit = terminal.Offset
	return nil
}

// AdvanceEpoch is called only at the Session's proven rekey barrier. A saved
// terminal tuple never changes epoch, even if the other direction stays live.
func (f *ReceiveFlow) AdvanceEpoch(epoch uint32) error {
	p := f.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || f.cleaned {
		return ErrFlowClosed
	}
	if f.hasTerminal {
		return nil
	}
	if f.observed.Epoch == math.MaxUint32 || epoch != f.observed.Epoch+1 {
		return ErrTerminal
	}
	f.observed.Epoch = epoch
	f.observed.NextSequence = 0
	return nil
}

// Fence marks the original logical direction incapable of accepting any more
// data. It is a local owner fact, not a claim that native I/O has exited.
func (f *ReceiveFlow) Fence() {
	p := f.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	f.fenceLocked()
}

func (f *ReceiveFlow) fenceLocked() {
	if !f.cleaned {
		if !f.hasTerminal || f.observed != f.terminal {
			f.termination.start(true, nil)
		}
		f.abandon()
		f.fenced = true
	}
}

type DrainProof struct {
	Terminal, Observed TerminalTuple
	Aborted            bool
}

func (f *ReceiveFlow) DrainProof() (DrainProof, bool) {
	p := f.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if !f.hasTerminal || f.cleaned {
		return DrainProof{}, false
	}
	if f.observed == f.terminal {
		return DrainProof{Terminal: f.terminal, Observed: f.observed}, true
	}
	if !f.abandoned || !f.fenced || f.observed.Epoch != f.terminal.Epoch {
		return DrainProof{}, false
	}
	// The permanent local gate plus authenticated terminal proof permits
	// revoking bytes which can never again be delivered. No ACK is advanced.
	p.used -= f.limit - f.released
	f.limit = f.released
	return DrainProof{Terminal: f.terminal, Observed: f.observed, Aborted: true}, true
}

// Cleanup runs only after real native/crypto/read aliases have exited. It frees
// the final backing responsibility separately from wire drained and EOF facts.
func (f *ReceiveFlow) Cleanup() error {
	p := f.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if f.cleaned {
		return nil
	}
	if f.readPending || f.readTails != 0 || f.assembly != nil {
		return ErrReadInProgress
	}
	if !p.closed && (!f.hasTerminal || f.observed != f.terminal && !f.fenced) {
		return ErrTerminal
	}
	if !f.abandoned && f.size != 0 {
		return ErrCredit
	}
	p.used -= f.limit - f.released
	f.releaseBackingLocked()
	return nil
}

func (f *ReceiveFlow) releaseBackingLocked() {
	f.pool.backingUsed -= uint64(len(f.storage))
	f.pool.flows--
	clear(f.storage)
	f.storage = nil
	f.cleaned = true
	if f.protection != nil {
		f.protection.returnLocked(f)
	} else {
		f.reservation.Release()
	}
	f.reservation = resourcev4.Reference{}
	f.termination.retire()
}

func (f *ReceiveFlow) Snapshot() (observed TerminalTuple, receiveLimit, releasedOffset uint64, readTerminal protocolv4.V4ReadTerminal) {
	p := f.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	terminal := protocolv4.V4ReadTerminalOpen
	if f.abandoned {
		terminal = protocolv4.V4ReadTerminalAbandoned
	} else if f.graceful && f.size == 0 && f.released == f.terminal.Offset {
		terminal = protocolv4.V4ReadTerminalEof
	} else if p.closed {
		terminal = protocolv4.V4ReadTerminalUnknown
	}
	return f.observed, f.limit, f.released, terminal
}

// The original Session cleanup coordinator observes real read/cursor exits.
// Waiting neither starts a task nor steals the application's read notification.
func (f *ReceiveFlow) waitCleanup(ctx context.Context) error {
	for {
		err := f.Cleanup()
		if !errors.Is(err, ErrReadInProgress) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-f.cleanupWake:
		}
	}
}

func (f *ReceiveFlow) notifyCleanupLocked() {
	select {
	case f.cleanupWake <- struct{}{}:
	default:
	}
}
