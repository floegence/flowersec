package sessionv4

import (
	"context"
	"io"
	"math"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

// BootstrapReservation supplies the original fixed channel's actual backing
// before READY. Native create/accept capacity remains the provider admission
// owner's responsibility; a logical writer is bound only to its real result.
type BootstrapReservation struct {
	StreamReservation
	Receiver *RecordReceiver
}

type bootstrapWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *bootstrapWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	provider := w.writer
	w.mu.Unlock()
	if provider == nil {
		return 0, ErrOpenPending
	}
	return provider.Write(p)
}

// Bootstrap is the same preaccepted scope owner through READY, its one real
// prefix, every rekey, terminal proof and retirement. No dynamic OPEN outcome
// or second receive queue is created for it.
type Bootstrap struct {
	admission              *OpenAdmission
	spec                   protocolv4.BootstrapSpec
	handle                 OpenHandle
	reader                 *RecordReceiver
	provider               *bootstrapWriter
	prefixMax              int
	creation               cryptov4.BootstrapCreation
	complete, materialized bool
	shared                 *SharedIngress
	output                 io.Writer
	carrier                CarrierAssociation
}

func (b *Bootstrap) Handle() OpenHandle { return b.handle }

func (a *OpenAdmission) PrepareBootstrap(reservation BootstrapReservation) (*Bootstrap, error) {
	return a.prepareBootstrap(reservation, nil, nil)
}

// PrepareSharedBootstrap uses the original shared reader and carrier output.
// The fixed scope owns only a logical association: no additional native reader,
// provider handle or authentication workspace is created or retired for it.
// The caller must include the flow, queue and bootstrap metadata in admission.
func (g *SharedIngress) PrepareBootstrap(reservation StreamReservation, output io.Writer) (*Bootstrap, error) {
	if g == nil || output == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return g.admission.prepareBootstrap(BootstrapReservation{StreamReservation: reservation, Receiver: g.receiver}, g, output)
}

func (a *OpenAdmission) prepareBootstrap(reservation BootstrapReservation, shared *SharedIngress, output io.Writer) (*Bootstrap, error) {
	spec, enabled := a.engine.BootstrapSpec()
	if !enabled || reservation.Receiver == nil || reservation.Receiver.engine != a.engine || reservation.Receiver.direction != 1-a.direction ||
		reservation.InitialReceiveLimit != spec.ReceiveLimit || reservation.SendCapacity == 0 || reservation.ReceiveCapacity < spec.ReceiveLimit || reservation.SendQueue != nil && reservation.SendQueue.Capacity < spec.ReceiveLimit {
		return nil, cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if shared != nil && (a.sharedIngress != shared || shared.admission != a || shared.receiver != reservation.Receiver) {
		return nil, cryptov4.ErrConfiguration
	}
	if a.closed || a.bootstrap != nil || a.nextOrdinal != 1 || !a.positiveAvailable(spec.Opener, InternalStream) {
		return nil, cryptov4.ErrCapacity
	}
	i := a.freeSlot(false, false)
	if i < 0 {
		return nil, cryptov4.ErrCapacity
	}
	header := protocolv4.RecordHeader{Scope: spec.Scope, Epoch: ^uint32(0)}
	wire, _, err := protocolv4.EncodeOpen(reservation.OpenStorage, header, spec.Opener, spec.Kind, nil, spec.ReceiveLimit)
	if err != nil {
		return nil, err
	}
	provider := &bootstrapWriter{}
	reservation.Writer = provider
	flow, err := a.newFlow(spec.Scope, spec.ReceiveLimit, InternalStream, reservation.StreamReservation)
	if err != nil {
		return nil, err
	}
	if err = a.engine.BindBootstrapResources(); err != nil {
		flow.send.Stop()
		_ = flow.send.retire()
		_ = flow.receive.releaseUnpublished(true)
		return nil, err
	}
	b := &Bootstrap{admission: a, spec: spec, handle: OpenHandle{a, spec.Scope}, reader: reservation.Receiver, provider: provider, prefixMax: len(wire), shared: shared, output: output, carrier: CarrierAssociation{shared: shared}}
	if shared != nil {
		b.reader = nil // The shared ingress retains its sole reader ownership.
	}
	clear(wire)
	a.slots[i] = openSlot{scope: spec.Scope, phase: openReserved, class: InternalStream, local: a.direction == spec.Opener, accepted: true, activeCharged: true,
		bootstrap: true, localLimit: spec.ReceiveLimit, peerLimit: spec.ReceiveLimit, flow: flow}
	a.insert(spec.Scope, i)
	a.active++
	a.positiveProofs++
	a.byOpener[spec.Opener][InternalStream]++
	a.lifetime[spec.Opener][InternalStream]++
	if a.direction == spec.Opener {
		a.nextOrdinal++
	}
	a.bootstrap = b
	return b, nil
}

// Complete is called by the private Session initializer immediately after its
// actual dual-READY transition, before publication or application dispatch.
func (b *Bootstrap) Complete() error {
	a := b.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return cryptov4.ErrClosed
	}
	if b.complete {
		return nil
	}
	s, err := a.slot(b.handle)
	if err != nil || !s.bootstrap || s.phase != openReserved {
		return ErrOpenAssociation
	}
	creation, err := a.engine.BootstrapCreation()
	if err != nil {
		return err
	}
	b.creation, b.complete = creation, true
	s.phase = openLive
	a.highestAccepted[b.spec.Opener] = max(a.highestAccepted[b.spec.Opener], s.scope)
	notifyOpenWait(a.outcomeWake[a.find(s.scope)])
	return nil
}

// MaterializeShared publishes the one real client prefix after dual READY.
// Pressure before a ticket is obtained permits another attempt on this same
// object; a submitted prefix is never sent again. The server binds only from
// its original authenticated shared-ingress dispatch.
func (b *Bootstrap) MaterializeShared(ctx context.Context) (RecordWriteResult, error) {
	if b == nil || ctx == nil || b.shared == nil || b.admission.direction != b.spec.Opener {
		return RecordWriteResult{}, ErrOpenAssociation
	}
	a := b.admission
	a.mu.Lock()
	s, err := a.slot(b.handle)
	if err == nil && s.carrier == nil {
		if a.closed || a.draining || !b.complete || s.cancelled || s.phase != openLive {
			err = ErrOpenAssociation
		} else {
			err = b.bind(s, &b.carrier, b.output)
		}
	}
	a.mu.Unlock()
	if err != nil {
		return RecordWriteResult{}, err
	}
	return b.PublishPrefix(ctx)
}

// WaitMaterialized observes the original fixed scope, without an OPEN outcome
// or another initializer. Its one observer uses the caller's admitted task and
// deadline. Cancellation ends observation only and preserves the real prefix.
func (b *Bootstrap) WaitMaterialized(ctx context.Context) error {
	if b == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	a := b.admission
	a.mu.Lock()
	s, err := a.slot(b.handle)
	if err != nil || a.closed {
		a.mu.Unlock()
		return cryptov4.ErrClosed
	}
	if s.outcomeWaiting {
		a.mu.Unlock()
		return ErrOpenWaitBusy
	}
	if s.retirementReferences == math.MaxUint32 || !a.beginTailLocked() {
		a.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	s.outcomeWaiting = true
	s.retirementReferences++
	wake := a.outcomeWake[a.find(s.scope)]
	a.mu.Unlock()
	defer a.finishOutcomeWait(b.handle)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		a.mu.Lock()
		s, err := a.slot(b.handle)
		if err == nil {
			switch {
			case a.closed:
				err = cryptov4.ErrClosed
			case s.cancelled || s.phase != openReserved && s.phase != openLive:
				err = ErrAbandoned
			case b.complete && b.materialized && s.submitted && !s.deciding && s.carrier != nil:
				err = nil
			default:
				err = ErrOpenPending
			}
		}
		a.mu.Unlock()
		if err != ErrOpenPending {
			return err
		}
		select {
		case <-wake:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (b *Bootstrap) Creation() (cryptov4.BootstrapCreation, error) {
	a := b.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	if !b.complete {
		return cryptov4.BootstrapCreation{}, cryptov4.ErrNotReady
	}
	return b.creation, nil
}

// BindLocalCarrier consumes the single client initializer's actual provider
// result. A late result cannot attach to a stopped, draining or retired scope.
func (b *Bootstrap) BindLocalCarrier(carrier *CarrierAssociation, writer io.Writer) error {
	a := b.admission
	if carrier == nil || writer == nil || a.direction != b.spec.Opener || b.shared != nil {
		return ErrOpenAssociation
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(b.handle)
	if err != nil {
		return err
	}
	if a.closed || a.draining || !b.complete || s.cancelled || s.phase != openLive || s.carrier != nil {
		return ErrOpenAssociation
	}
	s.flow.send.mu.Lock()
	defer s.flow.send.mu.Unlock()
	if s.flow.send.stopping {
		return ErrAbandoned
	}
	return b.bind(s, carrier, writer)
}

// bind runs under the original admission gate; the provider call itself never
// runs under that gate or the association/provider mutexes.
func (b *Bootstrap) bind(s *openSlot, carrier *CarrierAssociation, writer io.Writer) error {
	carrier.mu.Lock()
	defer carrier.mu.Unlock()
	if carrier.bound != nil {
		return ErrOpenAssociation
	}
	carrier.bound, carrier.scope = b.admission, b.spec.Scope
	s.carrier = carrier
	b.provider.mu.Lock()
	b.provider.writer = writer
	b.provider.mu.Unlock()
	return nil
}

// PublishPrefix uses the same record publisher as later DATA. Freeze or work
// pressure leaves the original native binding intact for its eventual retry.
func (b *Bootstrap) PublishPrefix(ctx context.Context) (result RecordWriteResult, err error) {
	a := b.admission
	a.mu.Lock()
	s, err := a.slot(b.handle)
	if err != nil {
		a.mu.Unlock()
		return result, err
	}
	if a.closed || a.draining || !b.complete || a.direction != b.spec.Opener || s.phase != openLive || s.carrier == nil || s.submitted || s.deciding {
		a.mu.Unlock()
		return result, ErrOpenAssociation
	}
	flow := s.flow
	flow.send.mu.Lock()
	if flow.send.stopping || flow.send.active {
		flow.send.mu.Unlock()
		a.mu.Unlock()
		return result, ErrAbandoned
	}
	if !a.beginTailLocked() {
		flow.send.mu.Unlock()
		a.mu.Unlock()
		return result, cryptov4.ErrClosed
	}
	defer a.endTail()
	flow.send.active, s.deciding = true, true
	flow.send.mu.Unlock()
	a.mu.Unlock()
	result, err = flow.send.writer.WriteBuildGuard(ctx, protocolv4.FrameOpenStream, b.prefixMax, func(header protocolv4.RecordHeader, dst []byte) (int, error) {
		a.mu.Lock()
		defer a.mu.Unlock()
		s, err := a.slot(b.handle)
		if err != nil {
			return 0, err
		}
		s.header, s.submitted = header, true
		flow.send.mu.Lock()
		defer func() { flow.send.encoding = false; flow.send.mu.Unlock() }()
		if header.Epoch != flow.send.frontier.Epoch || header.Sequence != 0 || flow.send.frontier.NextSequence != 0 || flow.send.frontier.Offset != 0 {
			return 0, ErrStreamData
		}
		flow.send.frontier.NextSequence = header.Sequence + 1
		wire, digest, err := protocolv4.EncodeOpen(dst, header, b.spec.Opener, b.spec.Kind, nil, b.spec.ReceiveLimit)
		s.digest = digest
		return len(wire), err
	}, nil, sendTicket{flow: flow.send})
	a.mu.Lock()
	if s, lookupErr := a.slot(b.handle); lookupErr == nil {
		s.deciding = false
		b.materialized = err == nil && result.Complete
		notifyOpenWait(a.outcomeWake[a.find(s.scope)])
	}
	flow.send.mu.Lock()
	flow.send.active = false
	flow.send.ticketed, flow.send.encoding = false, false
	if err != nil && result.Submitted {
		flow.send.stopping = true
	}
	if flow.send.stopping && !flow.send.hasTerminal {
		flow.send.terminal, flow.send.hasTerminal = flow.send.frontier, true
	}
	flow.send.signalCleanupLocked()
	flow.send.mu.Unlock()
	a.mu.Unlock()
	if err != nil && result.Submitted {
		a.closeWithCause(err)
	}
	return result, err
}

// BindPeerPrefix authenticates a real carrier association for the existing
// private/live scope. Prefix arrival grants no new credit or OPEN outcome.
func (b *Bootstrap) BindPeerPrefix(record *ReceivedRecord, carrier *CarrierAssociation, writer io.Writer) (err error) {
	a := b.admission
	if record == nil || record.receiver.engine != a.engine || record.incoming != nil || carrier == nil || writer == nil || a.direction == b.spec.Opener {
		return ErrOpenAssociation
	}
	if b.shared != nil {
		if record.receiver != b.shared.receiver || carrier != &b.carrier {
			return ErrOpenAssociation
		}
		writer = b.output
	}
	defer record.acceptOnSuccess(&err)
	f, err := record.Body()
	if err != nil {
		return err
	}
	if !b.spec.ValidatePrefix(f) {
		return ErrOpenAssociation
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(b.handle)
	if err != nil {
		return err
	}
	if a.closed || s.cancelled || s.carrier != nil || s.submitted || s.phase != openLive && s.phase != openReserved {
		return ErrOpenAssociation
	}
	flow := s.flow.receive
	flow.pool.mu.Lock()
	defer flow.pool.mu.Unlock()
	if flow.observed.Epoch != f.Header.Epoch || flow.observed.NextSequence != 0 || flow.observed.Offset != 0 || flow.hasTerminal || flow.fenced {
		return ErrOpenAssociation
	}
	if err = b.bind(s, carrier, writer); err != nil {
		return err
	}
	flow.observed.NextSequence = f.Header.Sequence + 1
	flow.lastObserved = flow.observed
	s.header, s.submitted = f.Header, true
	b.materialized = true
	notifyOpenWait(a.outcomeWake[a.find(s.scope)])
	return nil
}
