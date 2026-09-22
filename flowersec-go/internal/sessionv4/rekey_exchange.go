package sessionv4

import (
	"context"
	"errors"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// RekeyExchange executes the four flights for an already admitted round. The
// outer Session cause/authorization owner supplies its fixed hard deadline. Requests,
// authorization and public operation waiters do not create another exchange.
// Progress never waits for a peer barrier while occupying a publisher slot.
type RekeyExchange struct {
	mu           sync.Mutex
	admission    *OpenAdmission
	barriers     *Barriers
	writer       *RecordWriter
	round        *cryptov4.RekeyRound
	charge       *RekeyCharge
	timing       *rekeyTiming
	intent       *RekeyIntent
	freeze       *cryptov4.ApplicationFreeze
	local        []protocolv4.RecordHeader
	phase        []byte
	phaseSize    int
	state        uint8
	busy, closed bool
	armed        bool
	cancelled    bool
	initPrepared bool
}

func NewRekeyExchange(a *OpenAdmission, b *Barriers, w *RecordWriter, deadlineMS uint64, budgets RekeyPhaseBudgets) (*RekeyExchange, error) {
	if a == nil || b == nil || b.admission != a || w == nil || w.engine != a.engine || w.scope != 0 {
		return nil, cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	if a.closed || a.exchange != nil {
		a.mu.Unlock()
		return nil, cryptov4.ErrTransition
	}
	if !a.beginTailLocked() {
		a.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	defer a.endTail()
	x := &RekeyExchange{admission: a, barriers: b, writer: w}
	a.exchange = x
	a.liveness.pauseExchange(x)
	credit := a.rekeyCredit
	a.mu.Unlock()
	installed := false
	defer func() {
		if !installed {
			x.releaseOwner()
		}
	}()
	if credit == nil {
		return nil, cryptov4.ErrConfiguration
	}
	timing, err := newRekeyTiming(credit, budgets)
	if err != nil {
		return nil, err
	}
	scopes, err := protocolv4.FieldItemLimit("REKEY_INIT", "client_barrier")
	if err != nil {
		return nil, err
	}
	scopes = min(scopes, int(a.engine.SignedScopeLimit()))
	frontier, err := a.engine.ScopeFrontier(0, a.direction)
	if err != nil {
		return nil, err
	}
	charge, err := credit.Prepare(frontier.Epoch)
	if err != nil {
		return nil, err
	}
	r, err := a.engine.BeginRekey(deadlineMS)
	if err != nil {
		_ = charge.Cancel()
		return nil, err
	}
	x.round, x.charge, x.timing = r, charge, timing
	x.local = make([]protocolv4.RecordHeader, scopes)
	x.phase = make([]byte, a.engine.MaxFrame())
	if err = r.BindMarkerAccounting(x.markerReceived); err != nil {
		r.Close()
		_ = charge.Cancel()
		return nil, err
	}
	a.mu.Lock()
	if a.termination != nil {
		timing.wake = a.termination.wake
		a.termination.rekeyTiming, a.termination.rekeyRound = timing, r
		a.termination.notify()
	}
	a.mu.Unlock()
	installed = true
	return x, nil
}

// releaseOwner cannot reopen ordinary probes for a newer rekey owner. The
// old original crypto/freeze gates must already be complete or safely closed.
func (x *RekeyExchange) releaseOwner() { x.releaseOwnerResult(false) }

func (x *RekeyExchange) releaseOwnerResult(completed bool) {
	a := x.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.exchange == x {
		a.exchange = nil
		if a.termination != nil && a.termination.rekeyTiming == x.timing {
			a.termination.rekeyTiming, a.termination.rekeyRound = nil, nil
			a.termination.notify()
		}
		a.liveness.releaseExchange(x, completed)
	}
}

func (x *RekeyExchange) initTicket() error {
	if err := x.timing.Init(); err != nil {
		return err
	}
	return x.charge.Init()
}
func (x *RekeyExchange) markerReceived() error {
	if x.admission.direction == protocolv4.ServerToClient {
		return x.timing.Commit()
	}
	if err := x.timing.Ack(); err != nil {
		return err
	}
	return x.charge.Ack()
}
func (x *RekeyExchange) markerTicket() error {
	if x.admission.direction == protocolv4.ClientToServer {
		return x.timing.Commit()
	}
	if err := x.timing.Ack(); err != nil {
		return err
	}
	return x.charge.Ack()
}

func (x *RekeyExchange) begin() (err error) {
	// Admission precedes the exchange gate, as it does for maintenance
	// scheduling. A completed exchange can still have a returning publisher.
	if !x.admission.beginTail() {
		return cryptov4.ErrClosed
	}
	defer func() {
		if err != nil {
			x.admission.endTail()
		}
	}()
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.cancelled {
		return ErrRekeyCancelled
	}
	if x.closed {
		return cryptov4.ErrClosed
	}
	if x.busy {
		return cryptov4.ErrCapacity
	}
	x.busy = true
	return nil
}

func (x *RekeyExchange) end(err error) error {
	defer x.admission.endTail()
	if err != nil {
		x.cancelExpiredManual(err)
	}
	x.mu.Lock()
	cancelled := x.cancelled || x.intent != nil && x.intent.isCancelled()
	x.cancelled = cancelled
	if cancelled {
		err = ErrRekeyCancelled
	}
	if x.closed && err == nil {
		err = cryptov4.ErrClosed
	}
	x.busy = false
	failed := err != nil || x.closed
	freeze := x.freeze
	if failed {
		x.closed = true
		clear(x.phase)
		clear(x.local)
	}
	x.mu.Unlock()
	if cancelled {
		x.round.Close()
		_ = x.charge.Cancel()
		// A late prepare/freeze owns its original references until this exit.
		_ = x.barriers.cancelOwned(freeze)
		x.releaseOwner()
		return err
	}
	if failed {
		x.admission.closeWithCause(err)
		_ = x.charge.Cancel()
		x.round.Close()
		x.writer.Close()
	}
	return err
}

// cancelBeforeInit is invoked only after the original cause gate has revoked
// publication. Real crypto work keeps its owner until exit; the Session remains
// usable and the original maintenance sequence has not been consumed.
func (x *RekeyExchange) cancelBeforeInit() {
	if !x.admission.beginTail() {
		return
	}
	defer x.admission.endTail()
	x.mu.Lock()
	x.cancelled = true
	x.closed = true
	busy := x.busy
	freeze := x.freeze
	if !busy {
		clear(x.phase)
		clear(x.local)
	}
	x.mu.Unlock()
	x.round.Close()
	_ = x.charge.Cancel()
	_ = x.barriers.cancelOwned(freeze)
	x.releaseOwner()
}

func (x *RekeyExchange) Close() {
	if !x.admission.beginTail() {
		return
	}
	defer x.admission.endTail()
	x.mu.Lock()
	x.closed = true
	if !x.busy {
		clear(x.phase)
		clear(x.local)
	}
	x.mu.Unlock()
	x.round.Close()
	_ = x.charge.Cancel()
	x.admission.Close()
	x.writer.Close()
}

// Start freezes and publishes the client's actual INIT. The ticket callback
// makes the freeze irreversible before crypto or provider work can finish.
func (x *RekeyExchange) Start(ctx context.Context) (result RecordWriteResult, err error) {
	if err = x.begin(); err != nil {
		return result, err
	}
	publisherBusy := false
	defer func() {
		if publisherBusy {
			if endErr := x.end(nil); endErr != nil {
				err = endErr
			}
		} else {
			err = x.end(err)
		}
	}()
	if x.admission.direction != protocolv4.ClientToServer || x.state != 0 {
		return result, cryptov4.ErrRekey
	}
	if err = x.timing.Check(); err != nil {
		return result, err
	}
	if !x.initPrepared {
		if err = x.round.PrepareInit(); err != nil {
			return result, err
		}
		if err = x.timing.Check(); err != nil {
			return result, err
		}
		freeze, err := x.barriers.freezeOwned()
		if err != nil {
			return result, err
		}
		x.mu.Lock()
		x.freeze = freeze
		cancelled := x.cancelled
		x.mu.Unlock()
		if cancelled {
			return result, ErrRekeyCancelled
		}
		n, err := x.barriers.CopyLocal(x.local)
		if err != nil {
			return result, err
		}
		body, err := x.round.BuildInit(x.phase, x.local[:n])
		if err != nil {
			return result, err
		}
		x.phaseSize = len(body)
	}
	if err = x.round.Check(); err != nil {
		return result, err
	}
	if err = x.timing.Check(); err != nil {
		return result, err
	}
	// Publish preparation only after the last round/clock check has exited.
	// A cancelled owner's delayed publisher then holds no crypto job that a
	// later intent could accidentally mistake for an available round slot.
	x.mu.Lock()
	x.initPrepared = true
	x.mu.Unlock()
	var guard cryptov4.TicketGuard
	if x.intent != nil {
		guard = x.intent
	}
	result, err = x.writer.WriteBuildGuard(ctx, protocolv4.FrameRekey, x.phaseSize, func(_ protocolv4.RecordHeader, dst []byte) (int, error) {
		if err := x.barriers.Published(); err != nil {
			return 0, err
		}
		return copy(dst, x.phase[:x.phaseSize]), nil
	}, x.initTicket, guard)
	if !result.Submitted && errors.Is(err, cryptov4.ErrCapacity) {
		publisherBusy = true
		return result, err
	}
	if err == nil {
		x.state = 1
		clear(x.phase)
	}
	return result, err
}

// Handle consumes an actual record from this Session's original maintenance
// reader. The record remains caller-owned. Marker MAC verification has already
// run inside that reader before its irreversible receive-frontier update.
func (x *RekeyExchange) Handle(record *ReceivedRecord) (err error) {
	if err = x.begin(); err != nil {
		return err
	}
	defer func() { err = x.end(err) }()
	if record == nil || record.receiver.engine != x.admission.engine {
		return cryptov4.ErrRekey
	}
	defer record.acceptOnSuccess(&err)
	f, err := record.Body()
	if err != nil {
		return err
	}
	if x.admission.direction == protocolv4.ServerToClient {
		switch x.state {
		case 0:
			if err = x.round.AcceptInitTicket(f, x.initTicket); err != nil {
				return err
			}
			if err = x.barriers.RegisterPeer(record); err != nil {
				return err
			}
			if err = record.accepted(); err != nil {
				return err
			}
			n, err := x.barriers.CopyLocal(x.local)
			if err != nil {
				return err
			}
			body, err := x.round.BuildReply(x.phase, x.local[:n])
			if err != nil {
				return err
			}
			x.phaseSize = len(body)
			if err = x.round.InstallCandidate(); err != nil {
				return err
			}
			x.state = 1
		case 2:
			if f.Schema != "REKEY_COMMIT" {
				return cryptov4.ErrRekey
			}
			x.state = 3
		default:
			return cryptov4.ErrRekey
		}
	} else {
		switch x.state {
		case 1:
			if err = x.round.AcceptReply(f); err != nil {
				return err
			}
			if err = x.barriers.RegisterPeer(record); err != nil {
				return err
			}
			if err = record.accepted(); err != nil {
				return err
			}
			if err = x.round.InstallCandidate(); err != nil {
				return err
			}
			x.state = 2
		case 3:
			if f.Schema != "REKEY_ACK" {
				return cryptov4.ErrRekey
			}
			if err = x.complete(); err != nil {
				return err
			}
			x.state = 4
		default:
			return cryptov4.ErrRekey
		}
	}
	return nil
}

// Progress emits at most one flight when the original peer frontier is proven.
// A false ready result consumes no maintenance sequence/output reservation.
func (x *RekeyExchange) Progress(ctx context.Context) (result RecordWriteResult, ready bool, err error) {
	if err = x.begin(); err != nil {
		return result, false, err
	}
	defer func() { err = x.end(err) }()
	if x.state == 4 {
		return result, true, nil
	}
	if err = x.round.Check(); err != nil {
		return result, false, err
	}
	if err = x.timing.Check(); err != nil {
		return result, false, err
	}
	server := x.admission.direction == protocolv4.ServerToClient
	if server && x.state != 1 && x.state != 3 || !server && x.state != 2 {
		return result, false, cryptov4.ErrRekey
	}
	ready, err = x.barriers.Satisfied()
	if err != nil || !ready {
		return result, ready, err
	}
	if !x.writer.isIdle() {
		return result, false, nil
	}
	if server && x.state == 1 {
		result, err = x.writer.WriteBuild(ctx, protocolv4.FrameRekey, x.phaseSize, func(_ protocolv4.RecordHeader, dst []byte) (int, error) {
			if err := x.round.ArmMarker(); err != nil {
				return 0, err
			}
			if err := x.barriers.Published(); err != nil {
				return 0, err
			}
			return copy(dst, x.phase[:x.phaseSize]), nil
		})
		if !result.Submitted && errors.Is(err, cryptov4.ErrCapacity) {
			return result, false, nil
		}
		if err == nil {
			x.state = 2
			clear(x.phase)
		}
		return result, true, err
	}
	if !server && !x.armed {
		if err = x.round.ArmMarker(); err != nil {
			return result, false, err
		}
		x.armed = true
	}
	var ticketed func() error
	if server {
		ticketed = x.complete
	}
	result, err = x.writer.WriteRekeyMarker(ctx, x.round, x.markerTicket, ticketed)
	if !result.Submitted && errors.Is(err, cryptov4.ErrCapacity) {
		return result, false, nil
	}
	if err == nil {
		if server {
			x.state = 4
		} else {
			x.state = 3
		}
	}
	return result, true, err
}

func (x *RekeyExchange) complete() error {
	if err := x.round.Complete(); err != nil {
		return err
	}
	frontier, err := x.admission.engine.ScopeFrontier(0, x.admission.direction)
	if err != nil {
		return err
	}
	if err = x.admission.AdvanceEpoch(frontier.Epoch); err != nil {
		return err
	}
	if err := x.barriers.Complete(); err != nil {
		return err
	}
	if x.intent != nil {
		x.intent.complete()
	}
	x.releaseOwnerResult(true)
	return nil
}

// cancelExpiredManual revokes only a purely manual, unticketed local prepare.
// The original cause mutex also orders peer/safety acquisition and INIT tickets;
// those obligations can never be erased by this local-work timeout.
func (x *RekeyExchange) cancelExpiredManual(cause error) bool {
	if !x.admission.beginTail() {
		return false
	}
	defer x.admission.endTail()
	if x.intent == nil {
		return false
	}
	if _, err := x.admission.engine.AuthorizationRemainingMS(); err != nil {
		return false
	}
	i := x.intent
	c := i.causes
	c.mu.Lock()
	cancelled := i.cancelled
	c.mu.Unlock()
	// A watchdog can retain the old exchange across a worker's cancellation
	// or the last manual release. That original local outcome is idempotent.
	if cancelled {
		return true
	}
	if !errors.Is(cause, cryptov4.ErrExpired) {
		return false
	}
	x.timing.mu.Lock()
	localExpired := x.timing.stage == 0 && x.timing.local != nil && errors.Is(x.timing.local.Check(), timev4.ErrExpired)
	x.timing.mu.Unlock()
	if !localExpired {
		return false
	}
	c.mu.Lock()
	if i.cancelled {
		c.mu.Unlock()
		return true
	}
	if c.closed || c.current != i || i.peer || i.securityDeadline != 0 || i.submitted || i.completed {
		c.mu.Unlock()
		return false
	}
	i.cancelled = true
	i.failure = cause
	c.current = nil
	c.liveness.releaseIntent(i)
	c.mu.Unlock()
	x.cancelBeforeInit()
	return true
}
