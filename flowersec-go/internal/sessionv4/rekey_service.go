package sessionv4

import (
	"context"
	"errors"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// RekeyService owns one bounded coordinator and one publication worker. Peer
// causes join the original round; a provider tail never creates a replacement
// exchange or blocks the independent deadline checks.
type RekeyService struct {
	active                                        *RekeyExchange
	mu                                            sync.Mutex
	admission                                     *OpenAdmission
	causes                                        *RekeyCauses
	barriers                                      *Barriers
	writer                                        *RecordWriter
	budgets                                       RekeyPhaseBudgets
	reservation                                   resourcev4.Reference
	wake, stop, done                              chan struct{}
	started, closed, coordinator, worker, cleaned bool
}

// RekeyServiceCharge includes the service, one original exchange and its fixed
// phase/barrier backing. Runtime/allocator and provider overhead is admitted by
// the complete profile in addition to this checked minimum.
func RekeyServiceCharge(maxFrame, maxScopes uint32) resourcev4.Vector {
	return resourcev4.Vector{
		resourcev4.SDKBytes: uint64(unsafe.Sizeof(RekeyService{})) + uint64(unsafe.Sizeof(RekeyExchange{})) + uint64(unsafe.Sizeof(Barriers{})) + uint64(maxFrame) + uint64(maxScopes)*(3*uint64(unsafe.Sizeof(protocolv4.RecordHeader{}))+1),
		resourcev4.Items:    3, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2, resourcev4.Timers: 2,
	}
}

func NewRekeyService(a *OpenAdmission, writer *RecordWriter, budgets RekeyPhaseBudgets, reservation resourcev4.Reference) (*RekeyService, error) {
	if a == nil || writer == nil || writer.engine != a.engine || writer.scope != 0 {
		return nil, cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.runtime != nil || a.rekeyService != nil || a.rekeyCauses == nil || a.barriers == nil || a.exchange != nil {
		return nil, cryptov4.ErrConfiguration
	}
	if _, err := newRekeyTiming(a.rekeyCredit, budgets); err != nil {
		return nil, err
	}
	scopes, err := protocolv4.FieldItemLimit("REKEY_INIT", "client_barrier")
	if err != nil {
		return nil, err
	}
	scopes = min(scopes, int(a.engine.SignedScopeLimit()))
	owned, err := reservation.Take(RekeyServiceCharge(a.engine.MaxFrame(), uint32(scopes)))
	if err != nil {
		return nil, err
	}
	p := &RekeyService{admission: a, causes: a.rekeyCauses, barriers: a.barriers, writer: writer, budgets: budgets, reservation: owned, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	p.causes.mu.Lock()
	p.causes.wake = p.wake
	p.causes.mu.Unlock()
	a.rekeyService = p
	return p, nil
}

func (p *RekeyService) notify() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *RekeyService) prepare(i *RekeyIntent) (*RekeyExchange, error) {
	return p.causes.Prepare(i, p.barriers, p.writer, p.causes.credit.authorization.Cap(), p.budgets)
}

// Handle runs in the one original maintenance reader. A flight arriving while
// its preceding publication is still exiting retains this exact input. It
// never re-authenticates the candidate, consumes a new cause or changes its cap.
func (p *RekeyService) Handle(ctx context.Context, record *ReceivedRecord) error {
	if ctx == nil || record == nil {
		return cryptov4.ErrConfiguration
	}
	f, err := record.Body()
	if err != nil {
		return err
	}
	if f.Schema == "REKEY_REQUEST" || f.Schema == "REKEY_INIT" {
		i, err := p.causes.Peer(record)
		if err != nil {
			return err
		}
		p.notify()
		if f.Schema == "REKEY_REQUEST" {
			return nil
		}
		_ = i
	}
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		p.causes.mu.Lock()
		i := p.causes.current
		var x *RekeyExchange
		if i != nil {
			x = i.exchange
		}
		p.causes.mu.Unlock()
		if i == nil {
			return cryptov4.ErrRekey
		}
		if x != nil {
			err = x.Handle(record)
			if !errors.Is(err, cryptov4.ErrCapacity) {
				p.notify()
				return err
			}
			if err := x.timing.Check(); err != nil {
				return err
			}
			if _, err := x.round.DeadlineRemainingMS(); err != nil {
				return err
			}
		}
		// One bounded reader wait. The coordinator also wakes on real worker
		// completion; this finite quantum prevents shared hint consumers from
		// losing the original deadline check.
		timer.Reset(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-p.stop:
			timer.Stop()
			return cryptov4.ErrClosed
		case <-timer.C:
		}
	}
}

func (p *RekeyService) step(ctx context.Context) error {
	c := p.causes
	c.mu.Lock()
	i := c.current
	c.mu.Unlock()
	if i == nil {
		return nil
	}
	x, err := p.prepare(i)
	if errors.Is(err, ErrRekeyCredit) || errors.Is(err, ErrRekeyCancelled) {
		return nil
	}
	if err != nil {
		c.mu.Lock()
		gone := c.current != i || i.cancelled || i.completed
		c.mu.Unlock()
		if gone {
			return nil
		}
		return err
	}
	p.mu.Lock()
	p.active = x
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.active = nil; p.mu.Unlock() }()
	x.mu.Lock()
	if x.busy {
		x.mu.Unlock()
		return nil
	}
	state := x.state
	x.mu.Unlock()
	if p.admission.direction == protocolv4.ClientToServer && state == 0 {
		_, err = x.Start(ctx)
	} else if p.admission.direction == protocolv4.ServerToClient && state == 0 {
		c.mu.Lock()
		submitted, peer := i.submitted, i.peer
		c.mu.Unlock()
		if !submitted && !peer {
			_, err = c.SendRequest(ctx, i, p.writer)
		}
	} else if p.admission.direction == protocolv4.ClientToServer && state == 2 || p.admission.direction == protocolv4.ServerToClient && (state == 1 || state == 3) {
		_, _, err = x.Progress(ctx)
	}
	if errors.Is(err, cryptov4.ErrCapacity) || errors.Is(err, ErrRekeyCancelled) {
		return nil
	}
	return err
}

func (p *RekeyService) check() (bool, error) {
	p.mu.Lock()
	active := p.active
	p.mu.Unlock()
	if active != nil {
		active.timing.mu.Lock()
		var err error
		if active.timing.phase != nil {
			err = active.timing.phase.Check()
		}
		active.timing.mu.Unlock()
		if err != nil {
			return false, rekeyTimeError(err)
		}
	}
	p.causes.mu.Lock()
	i := p.causes.current
	var x *RekeyExchange
	var err error
	if i != nil {
		x = i.exchange
		if i.securityGate != nil {
			err = i.securityGate.Check()
		}
	}
	p.causes.mu.Unlock()
	if err != nil {
		return false, err
	}
	if x != nil {
		if err := p.checkExchange(x); err != nil {
			return false, err
		}
	}
	return i != nil || active != nil, nil
}

// checkExchange reconciles a snapshot with the cause owner after checking its
// original timing. Cancellation or completion can win while the check runs.
func (p *RekeyService) checkExchange(x *RekeyExchange) error {
	err := x.timing.Check()
	if err == nil {
		_, err = x.round.DeadlineRemainingMS()
	}
	if err == nil || x.cancelExpiredManual(err) {
		return nil
	}
	p.causes.mu.Lock()
	completed := x.intent != nil && x.intent.completed
	p.causes.mu.Unlock()
	if completed {
		_, err = p.admission.engine.AuthorizationRemainingMS()
	}
	return err
}

func (p *RekeyService) Run(ctx context.Context) (err error) {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	if p.started || p.closed {
		p.mu.Unlock()
		return cryptov4.ErrClosed
	}
	if err := p.reservation.Check(); err != nil {
		p.mu.Unlock()
		return err
	}
	p.started, p.coordinator, p.worker = true, true, true
	p.mu.Unlock()
	jobs, results := make(chan struct{}), make(chan error, 1)
	go func() {
		defer func() { p.mu.Lock(); p.worker = false; p.cleanupLocked(); p.mu.Unlock() }()
		for range jobs {
			results <- p.step(ctx)
		}
	}()
	defer close(jobs)
	defer func() {
		p.admission.closeWithCause(err)
		p.mu.Lock()
		p.coordinator = false
		p.cleanupLocked()
		p.mu.Unlock()
	}()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	busy, retry := false, false
	for {
		pending, err := p.check()
		if err != nil {
			return err
		}
		var submit chan<- struct{}
		var tick <-chan time.Time
		if pending {
			timer.Reset(10 * time.Millisecond)
			tick = timer.C
			if !busy && !retry {
				submit = jobs
			}
		}
		select {
		case submit <- struct{}{}:
			busy = true
		case err := <-results:
			busy, retry = false, true
			if err != nil {
				return err
			}
		case <-p.wake:
			retry = false
		case <-tick:
			retry = false
		case <-ctx.Done():
			return ctx.Err()
		case <-p.stop:
			return cryptov4.ErrClosed
		case <-p.admission.engine.Done():
			return cryptov4.ErrClosed
		}
		timer.Stop()
	}
}

func (p *RekeyService) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		close(p.stop)
	}
	p.cleanupLocked()
}
func (p *RekeyService) cleanupLocked() {
	if p.closed && !p.cleaned && !p.worker && !p.coordinator {
		p.cleaned = true
		close(p.done)
	}
}
func (p *RekeyService) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *RekeyService) retire() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.cleaned {
		return cryptov4.ErrCapacity
	}
	p.reservation.Release()
	return nil
}
