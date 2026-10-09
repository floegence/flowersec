package sessionv4

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// nativeStreamTransport joins the original QUIC associations to authenticated
// OPEN and DATA owners. Only the actual connection owner can supply a stream.
// A finite unbound reader set is separate from DATA authentication workers and
// maintenance. No shared crypto worker waits for an unbound or partial stream.
type nativeStreamTransport struct {
	mu                                                    sync.Mutex
	admission                                             *OpenAdmission
	connection                                            native.Connection
	reservation                                           resourcev4.Reference
	slots                                                 []nativeStreamSlot
	readers                                               []nativeOpenReader
	context                                               context.Context
	cancel                                                context.CancelFunc
	wake, done                                            chan struct{}
	closeWake                                             chan struct{}
	timeout                                               uint64
	started, running, accepting, closed, closing, cleaned bool
	opening                                               uint32
	generation                                            uint64
}

type nativeOpenReader struct {
	receiver *RecordReceiver
	used     bool
}
type nativeStreamSlot struct {
	protection                                                           *nativeStreamProtection
	association                                                          CarrierAssociation
	stream                                                               native.Stream
	deadline                                                             *timev4.Deadline
	ready                                                                chan struct{}
	retry                                                                chan struct{}
	readDone                                                             chan struct{}
	reader                                                               int
	generation                                                           uint64
	pins                                                                 uint32
	used, preparing, caller, reading, readyClosed, retiring, carrierDone bool
	writeStopped, writeFinished, readStopped                             bool
}

func nativeStreamTransportCharge(c SessionCoreConfig) (resourcev4.Vector, error) {
	count := uint64(c.Open.Terminal) + uint64(c.Open.IngressItems)
	if !c.Native || c.Open.Active == 0 || c.Open.IngressItems == 0 || c.Open.IngressItems > 128 || count > 4096+128 || c.DispatchTimeoutMS == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(nativeStreamTransport{})) + count*(uint64(unsafe.Sizeof(nativeStreamSlot{}))+uint64(unsafe.Sizeof(nativeStreamProtection{}))) + uint64(c.Open.IngressItems)*uint64(unsafe.Sizeof(nativeOpenReader{})),
		resourcev4.Items: 2*count + 1, resourcev4.Tasks: count + 3, resourcev4.WorkSlots: count + 3, resourcev4.Timers: 2}, nil
}

func newNativeStreamTransport(a *OpenAdmission, connection native.Connection, c SessionCoreConfig, reservation resourcev4.Reference, receivers []resourcev4.Reference) (_ *nativeStreamTransport, err error) {
	if a == nil || connection == nil || len(receivers) != int(c.Open.IngressItems) {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := nativeStreamTransportCharge(c)
	if err != nil {
		return nil, err
	}
	if err = connection.CheckEnvironment(reservation); err != nil {
		return nil, err
	}
	if err = connection.CheckStreamCapacity(c.Open.Active + c.Open.IngressItems + 1); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(a.reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := &nativeStreamTransport{admission: a, connection: connection, reservation: owned, timeout: c.DispatchTimeoutMS,
		slots: make([]nativeStreamSlot, int(c.Open.Terminal+c.Open.IngressItems)), readers: make([]nativeOpenReader, len(receivers)), context: ctx, cancel: cancel, wake: make(chan struct{}, 1), done: make(chan struct{}), closeWake: make(chan struct{})}
	defer func() {
		if err != nil {
			for _, r := range n.readers {
				if r.receiver != nil {
					r.receiver.Close()
					_ = r.receiver.retire()
				}
			}
			cancel()
			owned.Release()
		}
	}()
	for i, ref := range receivers {
		if err = ref.CheckSameEnvironment(owned); err != nil {
			return nil, err
		}
		n.readers[i].receiver, err = NewRecordReceiver(a.engine, 1-a.direction, a.engine.MaxFrame(), c.DecoderNodes, c.decode(), ref)
		if err != nil {
			return nil, err
		}
	}
	go n.closeWorker()
	return n, nil
}

func (n *nativeStreamTransport) notify() {
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

// BindNativeConnection joins the original provider to this preadmitted graph.
// It must precede claim/Noise/READY. It cannot adopt arbitrary native callbacks,
// supply missing resources, or assert provider qualification.
func (p *SessionCorePlan) BindNativeConnection(connection native.Connection) error {
	if p == nil || !originalNativeConnection(connection) {
		return cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.claimed || p.busy || p.nativeConnection != nil || !p.config.Native || p.config.Streams == (SessionStreamConfig{}) {
		return cryptov4.ErrTransition
	}
	if err := connection.CheckStreamCapacity(p.config.Open.Active + p.config.Open.IngressItems + 1); err != nil {
		return err
	}
	if err := connection.ClaimSession(p.environment); err != nil {
		return err
	}
	p.nativeConnection = connection
	return nil
}

// The slot remains original through its physical method tails and authenticated
// proof retirement. Reusing a QUIC stream ID cannot replace an old association.
func (n *nativeStreamTransport) claim(incoming bool) (*nativeStreamSlot, error) {
	return n.claimProtected(incoming, nil)
}

func (n *nativeStreamTransport) claimProtected(incoming bool, protection *nativeStreamProtection) (*nativeStreamSlot, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, cryptov4.ErrClosed
	}
	if err := n.reservation.Check(); err != nil {
		return nil, err
	}
	if n.generation == ^uint64(0) {
		return nil, cryptov4.ErrCapacity
	}
	reader := -1
	if incoming {
		for i := range n.readers {
			if !n.readers[i].used {
				reader = i
				break
			}
		}
		if reader < 0 {
			return nil, cryptov4.ErrCapacity
		}
	} else if !n.openingAvailableLocked(protection) {
		return nil, cryptov4.ErrCapacity
	}
	if protection != nil {
		if incoming || protection.transport != n {
			return nil, cryptov4.ErrConfiguration
		}
		if err := protection.availableLocked(); err != nil {
			return nil, err
		}
	}
	for i := range n.slots {
		s := &n.slots[i]
		if s.used || s.protection != protection || protection != nil && protection.index != i {
			continue
		}
		n.generation++
		*s = nativeStreamSlot{protection: protection, used: true, preparing: true, caller: !incoming, reader: reader, generation: n.generation, ready: make(chan struct{}), retry: make(chan struct{}, 1), readDone: make(chan struct{})}
		if incoming {
			n.readers[reader].used = true
		} else {
			n.opening++
		}
		return s, nil
	}
	return nil, cryptov4.ErrCapacity
}

func (n *nativeStreamTransport) attach(s *nativeStreamSlot, stream native.Stream) error {
	deadline, err := timev4.NewAge(n.admission.engine.Clock(), n.timeout, n.admission.engine.SessionParameters().SessionNotAfterMS)
	n.mu.Lock()
	if err == nil && n.closed {
		err = cryptov4.ErrClosed
	}
	s.stream, s.preparing, s.deadline = stream, false, deadline
	if err == nil {
		s.association.native = stream
		s.reading = true
		go n.read(s)
	}
	n.mu.Unlock()
	return err
}

func (n *nativeStreamTransport) open(ctx context.Context) (*nativeStreamSlot, error) {
	return n.openProtected(ctx, nil)
}

func (n *nativeStreamTransport) openProtected(ctx context.Context, protection *nativeStreamProtection) (*nativeStreamSlot, error) {
	return n.openProtectedObserved(ctx, protection, nil)
}

// The original initializer can retain a scalar observation of the physical
// slot before provider creation. Observation does not pin retirement or grant
// another caller authority over that slot.
func (n *nativeStreamTransport) openProtectedObserved(ctx context.Context, protection *nativeStreamProtection, observe func(*nativeStreamSlot, uint64)) (*nativeStreamSlot, error) {
	if ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	s, err := n.claimProtected(false, protection)
	if err != nil {
		return nil, err
	}
	if observe != nil {
		observe(s, s.generation)
	}
	var stream native.Stream
	if protection != nil {
		stream, err = protection.provider.Open(ctx)
	} else {
		stream, err = n.connection.OpenNativeStream(ctx)
	}
	if err != nil {
		n.mu.Lock()
		s.preparing = false
		n.mu.Unlock()
		n.finishOpen(s)
		return nil, err
	}
	if err = n.attach(s, stream); err != nil {
		n.finishOpen(s)
		return nil, err
	}
	return s, nil
}

func (n *nativeStreamTransport) slotRetired(s *nativeStreamSlot, generation uint64) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return !s.used || s.generation != generation
}

func (n *nativeStreamTransport) finishOpen(s *nativeStreamSlot) {
	n.mu.Lock()
	// The original caller pins this generation until all of its cleanup work
	// returns. Releasing it before Close/Read completion would permit slot ABA.
	generation := s.generation
	s.association.mu.Lock()
	scope := s.association.scope
	s.association.mu.Unlock()
	unbound := scope == 0
	if !unbound {
		// A local pre-ticket failure burns its ordinal and removes the
		// logical preparation. Its native reader must not keep waiting for
		// an outcome for an OPEN that was never published.
		n.admission.mu.Lock()
		logical, err := n.admission.slot(OpenHandle{n.admission, scope})
		unbound = err != nil || logical.carrier != &s.association
		n.admission.mu.Unlock()
	}
	closed := n.closed
	if (closed || unbound) && !s.readyClosed {
		close(s.ready)
		s.readyClosed = true
	}
	stream, reading, done := s.stream, s.reading, s.readDone
	n.mu.Unlock()
	if closed || unbound {
		if stream != nil {
			_ = stream.Close()
		}
		if reading {
			<-done
		}
	}
	n.mu.Lock()
	if s.caller {
		s.caller = false
		n.opening--
	}
	n.mu.Unlock()
	if closed || unbound {
		n.dispose(s, generation)
	}
	n.notify()
}

func (n *nativeStreamTransport) accept() {
	defer func() { n.mu.Lock(); n.accepting = false; n.finishLocked(); n.mu.Unlock(); n.notify() }()
	for {
		s, err := n.claim(true)
		if errors.Is(err, cryptov4.ErrCapacity) {
			select {
			case <-n.context.Done():
				return
			case <-n.wake:
				continue
			}
		}
		if err != nil {
			return
		}
		generation := s.generation // preparing keeps this original slot pinned.
		stream, err := n.connection.AcceptNativeStream(n.context)
		if err != nil {
			n.mu.Lock()
			s.preparing = false
			n.mu.Unlock()
			n.dispose(s, generation)
			if n.context.Err() == nil {
				n.admission.closeWithTransportCause(err)
			}
			return
		}
		if err = n.attach(s, stream); err != nil {
			n.dispose(s, generation)
			if n.context.Err() == nil {
				n.admission.closeWithCause(err)
			}
			return
		}
	}
}

func (n *nativeStreamTransport) read(s *nativeStreamSlot) {
	defer func() { n.mu.Lock(); s.reading = false; close(s.readDone); n.mu.Unlock(); n.notify() }()
	n.mu.Lock()
	reader := s.reader
	n.mu.Unlock()
	if reader >= 0 {
		record, err := n.readOpen(s, n.readers[reader].receiver)
		if err == nil {
			body, bodyErr := record.Body()
			err = bodyErr
			if err == nil {
				bootstrap := n.admission.bootstrap // Immutable before Run/accept.
				if bootstrap != nil && body.Type == protocolv4.FrameOpenStream && body.Header.Scope == bootstrap.spec.Scope {
					err = bootstrap.BindPeerPrefix(record, &s.association, s.stream)
				} else {
					_, err = n.admission.Hold(record, &s.association, s.deadline)
				}
			}
			record.Release()
		}
		if err != nil {
			n.mu.Lock()
			n.readers[reader].used = false
			s.reader = -1
			n.mu.Unlock()
			n.notify()
			if n.context.Err() == nil {
				n.admission.closeWithCause(err)
			}
			return
		}
	}
	select {
	case <-n.context.Done():
		return
	case <-s.ready:
	}
	if reader >= 0 {
		n.mu.Lock()
		n.readers[reader].used = false
		s.reader = -1
		n.mu.Unlock()
		n.notify()
	}
	n.admission.mu.Lock()
	s.association.mu.Lock()
	scope := s.association.scope
	s.association.mu.Unlock()
	h := OpenHandle{n.admission, scope}
	slot, err := n.admission.slot(h)
	accepted := err == nil && slot.accepted && slot.phase == openLive && !n.admission.closed
	n.admission.mu.Unlock()
	if !accepted {
		return
	}
	_ = n.admission.ReadNativeData(n.context, h, &s.association, s.stream)
}

// Only a no-attempt capacity/epoch refusal may retry the same complete OPEN.
// The service tick supplies bounded progress without stealing maintenance or
// DATA workers' wakeups; no replacement Read or scope owner is created.
func (n *nativeStreamTransport) readOpen(s *nativeStreamSlot, r *RecordReceiver) (_ *ReceivedRecord, err error) {
	if err = r.begin(n.context); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			r.finish()
		}
	}()
	prefix, err := ReadRecordPrefix(s.stream, r.maxFrame)
	if err != nil {
		return nil, err
	}
	r.storageUsed = prefix.RequiredBytes()
	wire, err := prefix.ReadBody(s.stream, r.storage)
	if err != nil {
		return nil, err
	}
	for {
		var record *ReceivedRecord
		record, err = r.authenticateMode(wire, true)
		if !errors.Is(err, cryptov4.ErrCapacity) && !errors.Is(err, cryptov4.ErrInputPending) {
			return record, err
		}
		select {
		case <-n.context.Done():
			return nil, n.context.Err()
		case <-s.retry:
		}
	}
}

// progress performs only original, bounded native cancellation/FIN operations.
// QUIC's FIN is sent after the E2EE FIN publication has actually returned; STOP
// cancels one send direction, and receive fencing cancels only its native Read.
func (n *nativeStreamTransport) progress(s *nativeStreamSlot) {
	n.mu.Lock()
	if n.closed || !s.used || s.preparing || s.retiring {
		n.mu.Unlock()
		return
	}
	s.pins++
	generation := s.generation
	dispose := false
	defer func() {
		n.mu.Lock()
		s.pins--
		n.mu.Unlock()
		if dispose {
			n.dispose(s, generation)
		}
		n.notify()
	}()
	stream, deadline, closed := s.stream, s.deadline, n.closed
	select {
	case s.retry <- struct{}{}:
	default:
	}
	s.association.mu.Lock()
	scope := s.association.scope
	s.association.mu.Unlock()
	caller := s.caller
	if stream == nil {
		n.mu.Unlock()
		dispose = !caller
		return
	}
	a := n.admission
	a.mu.Lock()
	slot, lookup := a.slot(OpenHandle{a, scope})
	bound := scope != 0 && lookup == nil && slot.carrier == &s.association
	accepted := bound && slot.accepted
	decided := bound && (slot.local && slot.submitted || !slot.local && slot.outcomeComplete || slot.bootstrap) && (slot.phase == openLive || slot.phase == openRecent || slot.phase == openHeld)
	if bound && slot.bootstrap {
		decided = decided && a.bootstrap.complete && a.bootstrap.materialized && !slot.deciding
	}
	if decided {
		// Admission completed for this original native generation. Its logical
		// proof can later compact or retire before this physical slot is released;
		// that must not reactivate the already completed OPEN deadline. Stream
		// termination and provider cleanup retain their independent owners.
		s.deadline = nil
	}
	if decided && !s.readyClosed {
		close(s.ready)
		s.readyClosed = true
	}
	normalRejected := bound && decided && !accepted
	closeStream := closed || normalRejected || !bound && !caller && !s.reading
	resetWrite, closeWrite, stopRead := false, normalRejected, normalRejected
	normalRead := normalRejected
	gracefulClose := normalRejected
	if accepted && slot.flow != nil {
		f := slot.flow
		f.send.mu.Lock()
		resetWrite = f.send.stopping && !f.send.finTerminal
		f.send.writer.mu.Lock()
		resetWrite = resetWrite || f.send.active && f.send.writer.closed
		f.send.writer.mu.Unlock()
		closeWrite = f.send.finTerminal && !f.send.active
		sendDone := f.send.sendDrained && !f.send.active
		f.send.mu.Unlock()
		f.receive.pool.mu.Lock()
		normalRead = slot.drainComplete && f.receive.hasTerminal && f.receive.observed == f.receive.terminal
		stopRead = f.receive.fenced || normalRead
		receiveDone := f.receive.hasTerminal && (f.receive.fenced || f.receive.observed == f.receive.terminal)
		f.receive.pool.mu.Unlock()
		gracefulClose = sendDone && normalRead
		closeStream = closeStream || sendDone && receiveDone && !s.reading
	}
	a.mu.Unlock()
	expired := !decided && deadline != nil && deadline.Check() != nil
	if expired {
		closeStream = true
	}
	doReset := resetWrite && !s.writeStopped
	doFIN := closeWrite && !s.writeFinished && !doReset
	doStop := stopRead && !s.readStopped
	if doReset {
		s.writeStopped = true
	}
	if doFIN {
		s.writeFinished = true
	}
	if doStop {
		s.readStopped = true
	}
	reading := s.reading
	carrierDone := s.carrierDone
	n.mu.Unlock()
	if expired && !closed {
		a.closeWithCause(timev4.ErrExpired)
	}
	if doReset {
		_ = stream.ResetWrite()
	}
	if doFIN {
		_ = stream.CloseWrite()
	}
	if doStop {
		if normalRead {
			if actual, ok := stream.(native.DirectionalStream); ok {
				_ = actual.StopSendingDrained()
			} else {
				_ = stream.StopSending()
			}
		} else {
			_ = stream.StopSending()
		}
	}
	if closeStream && !carrierDone {
		if actual, ok := stream.(native.DirectionalStream); ok && gracefulClose && !closed && !expired {
			// Do not RESET a queued FIN. Keep the original slot while native I/O
			// tails are returning, and let the same progress owner try cleanup again.
			if err := actual.CloseDirections(); err != nil {
				return
			}
		} else {
			_ = stream.Close()
		}
		if !reading && !caller {
			dispose = true
		}
	} else if carrierDone && (!bound || closed) && !caller {
		dispose = true
	}
}

// dispose retains association metadata until its proof no longer refers to it.
// Physical retirement, not reset submission, reports CarrierClosed.
func (n *nativeStreamTransport) dispose(s *nativeStreamSlot, generation uint64) {
	n.mu.Lock()
	if !s.used || s.generation != generation || s.preparing || s.reading || s.caller || s.retiring || s.pins != 0 {
		n.mu.Unlock()
		return
	}
	s.retiring = true
	stream, already := s.stream, s.carrierDone
	s.association.mu.Lock()
	scope := s.association.scope
	s.association.mu.Unlock()
	n.mu.Unlock()
	if stream != nil && !already {
		closeNativeStream(stream)
		if err := stream.Retire(); err != nil {
			n.mu.Lock()
			s.retiring = false
			n.mu.Unlock()
			return
		}
		if scope != 0 {
			_ = n.admission.CarrierClosed(OpenHandle{n.admission, scope})
		}
	}
	n.mu.Lock()
	n.admission.mu.Lock()
	slot, err := n.admission.slot(OpenHandle{n.admission, scope})
	retained := scope != 0 && err == nil && slot.carrier == &s.association && !n.admission.closed
	if err == nil && slot.carrier == &s.association && (!retained || n.closed) {
		// Admission cleanup readers use this alias after native Close too.
		// Detach it under their lock before clearing the original slot.
		slot.carrier = nil
	}
	s.carrierDone = true
	s.retiring = false
	if !retained || n.closed {
		if s.reader >= 0 {
			n.readers[s.reader].used = false
		}
		protection := s.protection
		if protection != nil && (protection.closed || n.closed) {
			protection = nil
		}
		*s = nativeStreamSlot{protection: protection}
	}
	n.admission.mu.Unlock()
	n.finishLocked()
	n.mu.Unlock()
	n.notify()
}

func (n *nativeStreamTransport) Run(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	n.mu.Lock()
	if n.closed || n.started {
		n.mu.Unlock()
		return cryptov4.ErrClosed
	}
	n.started, n.running, n.accepting = true, true, true
	go n.accept()
	n.mu.Unlock()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	defer func() {
		n.Close()
		n.mu.Lock()
		n.running = false
		n.finishLocked()
		n.mu.Unlock()
		n.notify()
	}()
	for {
		for i := range n.slots {
			n.progress(&n.slots[i])
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-n.context.Done():
			return cryptov4.ErrClosed
		case <-n.admission.engine.Done():
			return cryptov4.ErrClosed
		case <-ticker.C:
		}
	}
}

// Close seals new work promptly. A single preadmitted cleanup task owns all
// actual native close calls and remains charged through their physical exits.
func (n *nativeStreamTransport) Close() {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	n.closed, n.closing = true, true
	for i := range n.slots {
		if protection := n.slots[i].protection; protection != nil {
			protection.closeLocked()
		}
	}
	n.reservation.Seal()
	n.cancel()
	close(n.closeWake)
	n.mu.Unlock()
}

func (n *nativeStreamTransport) closeWorker() {
	<-n.closeWake
	_ = n.connection.Close()
	for i := range n.readers {
		n.readers[i].receiver.Close()
	}
	// A failed Retire means an original method tail is still present. Keep the
	// one admitted cleanup task alive until every original slot really retires,
	// including streams attached after Close while an Open/Accept was returning.
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		for i := range n.slots {
			s := &n.slots[i]
			n.mu.Lock()
			generation := s.generation
			n.mu.Unlock()
			n.dispose(s, generation)
		}
		n.mu.Lock()
		quiescent := !n.running && !n.accepting && n.opening == 0
		for i := range n.slots {
			quiescent = quiescent && !n.slots[i].used
		}
		n.mu.Unlock()
		if quiescent {
			break
		}
		select {
		case <-n.wake:
		case <-ticker.C:
		}
	}
	_ = n.connection.WaitCleanup(context.Background())
	n.mu.Lock()
	n.closing = false
	n.finishLocked()
	n.mu.Unlock()
}

func (n *nativeStreamTransport) finishLocked() {
	if !n.closed || n.closing || n.running || n.accepting || n.opening != 0 || n.cleaned {
		return
	}
	for i := range n.slots {
		if n.slots[i].used {
			return
		}
	}
	n.cleaned = true
	close(n.done)
}

func (n *nativeStreamTransport) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-n.done:
		return nil
	}
}

func (n *nativeStreamTransport) Retire() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.cleaned {
		return cryptov4.ErrCapacity
	}
	for _, r := range n.readers {
		if err := r.receiver.retire(); err != nil {
			return err
		}
	}
	n.slots, n.readers = nil, nil
	n.reservation.Release()
	return nil
}

var _ io.Writer = native.Stream(nil)
