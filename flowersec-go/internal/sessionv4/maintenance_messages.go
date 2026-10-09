package sessionv4

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

var ErrMaintenanceRate = errors.New("sessionv4: ordinary maintenance rate exhausted")

var errMaintenanceDiscarded = errors.New("sessionv4: authenticated ordinary maintenance record locally refused")
var errPongQueueFull = fmt.Errorf("sessionv4: pong reply queue full: %w", cryptov4.ErrCapacity)

// MaintenanceMessagePolicy fixes finite ingress work and original reply work
// windows before admission. Refill uses cumulative proven elapsed time and
// constant work, with no retained credit beyond the admitted finite burst.
type MaintenanceMessagePolicy struct {
	IngressBurst                    uint32
	IngressRefillMS, ReplyTimeoutMS uint64
}

// PongSlot is caller-reserved ordinary maintenance backing, including a real
// publication tail. It never borrows a rekey marker or confirmation reservation.
type PongSlot struct {
	nonce      [16]byte
	window     *timev4.Window
	publishing bool
}

// MaintenanceMessages dispatches authenticated PING/PONG and publishes at most
// one queued PONG per scheduler quantum. Session scheduling gives marker and
// urgent work priority before calling Progress; a blocked reply owns no lock.
type MaintenanceMessages struct {
	reservation                           resourcev4.Reference
	mu                                    sync.Mutex
	liveness                              *Liveness
	policy                                MaintenanceMessagePolicy
	slots                                 []PongSlot
	head, count                           int
	closed, active                        bool
	tokens                                uint32
	refill                                maintenanceRefill
	wake, stop, done                      chan struct{}
	started, coordinator, worker, cleaned bool
}

func NewMaintenanceMessages(p *Liveness, slots []PongSlot, policy MaintenanceMessagePolicy, reservation resourcev4.Reference) (*MaintenanceMessages, error) {
	if p == nil || len(slots) == 0 || uint64(len(slots)) > uint64(policy.IngressBurst) || policy.IngressRefillMS == 0 || policy.ReplyTimeoutMS == 0 {
		return nil, cryptov4.ErrConfiguration
	}
	for _, slot := range slots {
		if slot != (PongSlot{}) {
			return nil, cryptov4.ErrConfiguration
		}
	}
	if _, err := timev4.NewDelay(p.admission.engine.Clock(), policy.IngressRefillMS); err != nil {
		return nil, err
	}
	if _, err := timev4.NewWindow(p.admission.engine.Clock(), policy.ReplyTimeoutMS); err != nil {
		return nil, err
	}
	a := p.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.runtime != nil || a.liveness != p || a.maintenanceMessages != nil {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := MaintenanceMessagesCharge(len(slots))
	if err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(p.reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	q := &MaintenanceMessages{reservation: owned, liveness: p, slots: slots, policy: policy, tokens: policy.IngressBurst, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	a.maintenanceMessages = q
	return q, nil
}

func (q *MaintenanceMessages) consume(now timev4.Mark, rate timev4.Rate) error {
	if err := q.reservation.Check(); err != nil {
		return err
	}
	return q.refill.consume(now, rate, q.policy.IngressRefillMS, q.policy.IngressBurst, &q.tokens)
}

func (a *OpenAdmission) invalidateAutomaticSample() {
	if a == nil {
		return
	}
	a.mu.Lock()
	p := a.liveness
	a.mu.Unlock()
	if p != nil {
		p.invalidateAutomaticSample()
	}
}

// Handle copies only the fixed opaque nonce; it never retains the decoder or
// peer bytes. Rate/queue refusal is local resource failure, not path failure.
// PONG still passes the original same-session/epoch/direction matcher.
func (q *MaintenanceMessages) Handle(record *ReceivedRecord) (matched bool, err error) {
	if record == nil || q.liveness == nil || record.receiver.engine != q.liveness.admission.engine || record.receiver.direction != 1-q.liveness.admission.direction {
		return false, ErrProbeOwner
	}
	f, err := record.Body()
	if err != nil {
		return false, err
	}
	return q.handleFrame(record, f)
}

func (q *MaintenanceMessages) handleFrame(record *ReceivedRecord, f *protocolv4.Frame) (matched bool, err error) {
	nonce, ping, err := validateMaintenanceFrame(record, q.liveness.admission, f)
	if err != nil {
		return false, err
	}
	if err := record.acceptMaintenanceFrame(f); err != nil {
		return false, err
	}
	p := q.liveness
	clock := p.admission.engine.Clock()
	now, err := clock.Monotonic()
	if err != nil {
		return false, err
	}
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return false, cryptov4.ErrClosed
	}
	if err = q.consume(now, clock.Profile().Rate); err != nil {
		q.mu.Unlock()
		if !ping && errors.Is(err, ErrMaintenanceRate) {
			p.invalidateAutomaticSample()
		}
		return false, err
	}
	if !ping {
		q.mu.Unlock()
		return p.handlePongFrame(f)
	}
	if q.count == len(q.slots) {
		q.mu.Unlock()
		return false, errPongQueueFull
	}
	window, err := timev4.NewWindow(p.admission.engine.Clock(), q.policy.ReplyTimeoutMS)
	if err == nil {
		i := (q.head + q.count) % len(q.slots)
		q.slots[i] = PongSlot{nonce: nonce, window: window}
		q.count++
		q.notify()
	}
	q.mu.Unlock()
	return false, err
}

func validateMaintenanceFrame(record *ReceivedRecord, admission *OpenAdmission, f *protocolv4.Frame) ([16]byte, bool, error) {
	if record == nil || admission == nil || record.receiver.engine != admission.engine || record.receiver.direction != 1-admission.direction || f == nil {
		return [16]byte{}, false, ErrProbeOwner
	}
	if f.Header.Scope != 0 || f.Schema != "PING" && f.Schema != "PONG" {
		return [16]byte{}, false, ErrProbeOwner
	}
	value, ok := f.Field("nonce").ByteString()
	if !ok || len(value) != 16 {
		return [16]byte{}, false, ErrProbeOwner
	}
	return [16]byte(value), f.Schema == "PING", nil
}

type pongTicket struct {
	queue *MaintenanceMessages
	slot  *PongSlot
	ctx   context.Context
}

func (g pongTicket) LockTicket() error {
	g.queue.mu.Lock()
	err := g.ctx.Err()
	if err == nil && g.queue.closed {
		err = cryptov4.ErrClosed
	}
	if err == nil {
		err = g.queue.reservation.Check()
	}
	if err == nil {
		err = g.slot.window.Check()
	}
	if err != nil {
		g.queue.mu.Unlock()
	}
	return err
}
func (g pongTicket) UnlockTicket(bool) { g.queue.mu.Unlock() }

// Progress never waits for a marker, another publisher, credit or application
// work. Before-ticket contention keeps the same finite original queue entry.
// After-ticket failure ends the Session; no response receives a second ticket.
func (q *MaintenanceMessages) Progress(ctx context.Context) (result RecordWriteResult, ready bool, err error) {
	if ctx == nil {
		return result, false, cryptov4.ErrConfiguration
	}
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return result, false, cryptov4.ErrClosed
	}
	if err := q.reservation.Check(); err != nil {
		q.mu.Unlock()
		return result, false, err
	}
	if q.active || q.count == 0 {
		q.mu.Unlock()
		return result, false, nil
	}
	slot := &q.slots[q.head]
	if err = slot.window.Check(); err != nil {
		q.mu.Unlock()
		q.liveness.admission.closeWithCause(err)
		return result, false, err
	}
	q.active, slot.publishing = true, true
	nonce := slot.nonce
	q.mu.Unlock()
	result, err = q.liveness.writer.WriteBuildGuard(ctx, protocolv4.FramePong, 32, func(_ protocolv4.RecordHeader, dst []byte) (int, error) {
		body, err := protocolv4.EncodeMap(dst, "PONG", []protocolv4.Field{{Name: "nonce", Kind: protocolv4.ByteString, Bytes: nonce[:]}})
		return len(body), err
	}, nil, pongTicket{q, slot, ctx})
	retry := !result.Submitted && (errors.Is(err, cryptov4.ErrCapacity) || errors.Is(err, cryptov4.ErrTransition) || errors.Is(err, cryptov4.ErrNotReady))
	q.mu.Lock()
	q.active, slot.publishing = false, false
	if !retry || q.closed {
		*slot = PongSlot{}
		q.head = (q.head + 1) % len(q.slots)
		q.count--
	}
	q.cleanupLocked()
	q.mu.Unlock()
	if retry {
		return result, false, nil
	}
	if err != nil {
		q.liveness.admission.closeWithCause(err)
	}
	return result, true, err
}

func (q *MaintenanceMessages) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		q.closed = true
		q.reservation.Seal()
		close(q.stop)
	}
	q.count = 0
	for i := range q.slots {
		if q.slots[i].publishing {
			q.count++
		} else {
			q.slots[i] = PongSlot{}
		}
	}
	q.cleanupLocked()
}

func (q *MaintenanceMessages) notify() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *MaintenanceMessages) cleanupLocked() {
	if q.closed && !q.cleaned && !q.active && !q.coordinator && !q.worker {
		q.cleaned = true
		close(q.done)
	}
}

// Run uses this owner's two reserved ordinary-maintenance tasks. One
// writer publishes finite replies; the coordinator checks the original window
// even while the provider holds that writer. No per-PING task is created.
func (q *MaintenanceMessages) Run(ctx context.Context) (err error) {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	q.mu.Lock()
	if q.started || q.closed {
		q.mu.Unlock()
		return cryptov4.ErrClosed
	}
	if err := q.reservation.Check(); err != nil {
		q.mu.Unlock()
		return err
	}
	q.started, q.coordinator, q.worker = true, true, true
	q.mu.Unlock()
	type completion struct {
		ready bool
		err   error
	}
	jobs, completed := make(chan struct{}), make(chan completion, 1)
	go func() {
		defer func() { q.mu.Lock(); q.worker = false; q.cleanupLocked(); q.mu.Unlock() }()
		for range jobs {
			_, ready, err := q.Progress(ctx)
			completed <- completion{ready, err}
		}
	}()
	defer close(jobs)
	defer func() {
		q.liveness.admission.closeWithCause(err)
		q.mu.Lock()
		q.coordinator = false
		q.cleanupLocked()
		q.mu.Unlock()
	}()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	busy, retry := false, false
	for {
		q.mu.Lock()
		if q.closed {
			q.mu.Unlock()
			return cryptov4.ErrClosed
		}
		var remaining uint64
		var submit chan<- struct{}
		if q.count != 0 {
			remaining, err = q.slots[q.head].window.RemainingMS()
			if !busy && !retry {
				submit = jobs
			}
		}
		q.mu.Unlock()
		if err != nil {
			return err
		}
		if retry {
			remaining = min(remaining, uint64(10))
		}
		var tick <-chan time.Time
		if remaining != 0 {
			timer.Reset(idleTimerChunk(remaining))
			tick = timer.C
		}
		select {
		case submit <- struct{}{}:
			busy = true
		case c := <-completed:
			busy, retry = false, !c.ready
			if c.err != nil {
				return c.err
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-q.stop:
			return cryptov4.ErrClosed
		case <-q.liveness.admission.engine.Done():
			return cryptov4.ErrClosed
		case <-q.wake:
		case <-tick:
			retry = false
		}
		timer.Stop()
	}
}

func (q *MaintenanceMessages) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-q.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func MaintenanceMessagesCharge(slots int) (resourcev4.Vector, error) {
	if slots <= 0 || uint64(slots) > uint64(^uint32(0)) {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return resourcev4.Vector{
		resourcev4.SDKBytes: uint64(unsafe.Sizeof(MaintenanceMessages{})) + uint64(slots)*(uint64(unsafe.Sizeof(PongSlot{}))+uint64(unsafe.Sizeof(timev4.Window{}))),
		resourcev4.Items:    2 + 2*uint64(slots), resourcev4.Tasks: 2, resourcev4.WorkSlots: 2, resourcev4.Timers: 1,
	}, nil
}
func (q *MaintenanceMessages) retire() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.cleaned {
		return cryptov4.ErrCapacity
	}
	q.refill = maintenanceRefill{}
	q.reservation.Release()
	return nil
}
