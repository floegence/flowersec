package sessionv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// ServeConfig reserves the original aggregate, its coordinator and live child
// links. The concrete route adapter must hold its exclusive ingress token for
// this owner's entire lifetime. The borrowed Environment is never closed here.
type ServeConfig struct {
	Positions                    uint32
	RuntimeBytes, DrainTimeoutMS uint64
	Clock                        *timev4.Clock
}

type serveChild struct {
	session                                                 *EnvironmentSession
	drain                                                   *DrainOperation
	generation                                              uint64
	active, callback, attached, published, reported, driven bool
}

type ServeGroup struct {
	lifetime                                   context.Context
	position                                   int
	abortResult                                DrainResult
	mu                                         sync.Mutex
	config                                     ServeConfig
	environment                                *Environment
	reservation, shared                        resourcev4.Reference
	children                                   []serveChild
	cursor                                     int
	generation                                 uint64
	active, pendingResults                     uint32
	failed, expired                            bool
	firstCause                                 error
	closed, forced, draining, cleaned, retired bool
	deadline                                   *timev4.Deadline
	operation                                  *DrainOperation
	wake, done                                 chan struct{}
}

// ServeIngress is an original preauth/HTTP callback responsibility. It is
// registered before provider work and transferred to the same child at READY.
// Release means the actual ingress callback has returned, not that its Session
// has cleaned up. A copied stale token cannot touch a reused child position.
type ServeIngress struct {
	group      *ServeGroup
	index      int
	generation uint64
}

func ServeCharge(c ServeConfig) (resourcev4.Vector, error) {
	if c.Positions == 0 || c.Positions > 65536 || c.RuntimeBytes == 0 || c.DrainTimeoutMS == 0 || c.Clock == nil {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ServeGroup{})) + uint64(unsafe.Sizeof(DrainOperation{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + uint64(c.Positions)*uint64(unsafe.Sizeof(serveChild{})), resourcev4.Items: 4 + uint64(c.Positions), resourcev4.Tasks: 1 + uint64(c.Positions), resourcev4.WorkSlots: 1 + uint64(c.Positions), resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func (e *Environment) NewServeGroup(ctx context.Context, c ServeConfig, reservation resourcev4.Reference) (*ServeGroup, error) {
	if e == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := ServeCharge(c)
	if err != nil {
		return nil, err
	}
	if _, err = timev4.NewAge(c.Clock, c.DrainTimeoutMS, math.MaxUint64); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, cryptov4.ErrClosed
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(e.reservation); err != nil {
		return nil, err
	}
	position := -1
	for i, g := range e.groups {
		if g == nil {
			position = i
			break
		}
	}
	if position < 0 {
		return nil, cryptov4.ErrCapacity
	}
	shared, err := e.reservation.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	g := &ServeGroup{lifetime: ctx, config: c, environment: e, reservation: owned, shared: shared, children: make([]serveChild, c.Positions), operation: &DrainOperation{done: make(chan struct{})}, wake: make(chan struct{}, 1), done: make(chan struct{})}
	g.position = position
	e.groups[position] = g
	e.groupsActive++
	go g.run(ctx)
	return g, nil
}

func (g *ServeGroup) BeginIngress() (ServeIngress, error) {
	if g == nil {
		return ServeIngress{}, cryptov4.ErrConfiguration
	}
	if err := g.reservation.Check(); err != nil {
		return ServeIngress{}, err
	}
	if err := g.shared.Check(); err != nil {
		return ServeIngress{}, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return ServeIngress{}, cryptov4.ErrClosed
	}
	if err := g.lifetime.Err(); err != nil {
		return ServeIngress{}, err
	}
	if g.generation == math.MaxUint64 {
		return ServeIngress{}, cryptov4.ErrCapacity
	}
	for i := range g.children {
		c := &g.children[i]
		if !c.active {
			g.generation++
			*c = serveChild{active: true, callback: true, generation: g.generation}
			g.active++
			return ServeIngress{g, i, c.generation}, nil
		}
	}
	return ServeIngress{}, cryptov4.ErrCapacity
}

func (i ServeIngress) childLocked() *serveChild {
	if i.group == nil || i.index < 0 || i.index >= len(i.group.children) {
		return nil
	}
	c := &i.group.children[i.index]
	if !c.active || c.generation != i.generation {
		return nil
	}
	return c
}

func (i ServeIngress) Accept(ctx context.Context, c AcceptedIngressConfig) (*EnvironmentSession, error) {
	if i.group == nil || c.Intake.Input.Config.Core.Clock != i.group.config.Clock {
		return nil, cryptov4.ErrConfiguration
	}
	return i.group.environment.acceptIngress(ctx, c, i)
}

// AcceptOwned additionally reports the local graph transfer. This is only
// cleanup ownership, never a claim about durable spend, admission or READY.
func (i ServeIngress) AcceptOwned(ctx context.Context, c AcceptedIngressConfig) (*EnvironmentSession, bool, error) {
	if i.group == nil || c.Intake.Input.Config.Core.Clock != i.group.config.Clock {
		return nil, false, cryptov4.ErrConfiguration
	}
	owned := false
	s, err := i.group.environment.acceptIngressOwned(ctx, c, i, &owned)
	return s, owned, err
}

func (i ServeIngress) attach(s *EnvironmentSession) (bool, error) {
	g := i.group
	g.mu.Lock()
	defer g.mu.Unlock()
	c := i.childLocked()
	if c == nil || !c.callback || c.attached {
		return false, cryptov4.ErrTransition
	}
	c.attached, c.session = true, s
	if g.closed {
		return true, cryptov4.ErrClosed
	}
	return true, nil
}

// Called with only the original Session gate held. The group gate takes no
// Session, provider, store or application locks and invokes no callbacks.
func (i ServeIngress) publish() error {
	g := i.group
	g.mu.Lock()
	defer g.mu.Unlock()
	c := i.childLocked()
	if c == nil || !c.attached || c.published || g.closed || g.lifetime.Err() != nil {
		return cryptov4.ErrClosed
	}
	c.published = true
	g.pendingResults++
	notifyOpenWait(g.wake)
	return nil
}

func (g *ServeGroup) reportLocked(c *serveChild, result DrainResult) {
	if !c.published || c.reported || result.Outcome == DrainPending {
		return
	}
	c.reported = true
	g.pendingResults--
	if result.Outcome != Drained {
		g.failed = true
		g.expired = g.expired || result.Outcome == DrainDeadlineAborted
		if g.firstCause == nil {
			g.firstCause = result.Cause
		}
	}
}

func (g *ServeGroup) freeLocked(c *serveChild) {
	if !c.callback && c.session == nil {
		*c = serveChild{}
		g.active--
	}
}

func (i ServeIngress) Release() {
	if i.group == nil {
		return
	}
	g := i.group
	g.mu.Lock()
	if c := i.childLocked(); c != nil && c.callback {
		c.callback = false
		g.freeLocked(c)
	}
	notifyOpenWait(g.wake)
	g.mu.Unlock()
}

func (i ServeIngress) finish(result DrainResult) {
	g := i.group
	g.mu.Lock()
	if c := i.childLocked(); c != nil {
		g.reportLocked(c, result)
		c.session = nil
		g.freeLocked(c)
	}
	notifyOpenWait(g.wake)
	g.mu.Unlock()
}

func (g *ServeGroup) Drain(timeoutMS, absoluteCap uint64) (*DrainOperation, error) {
	if g == nil {
		return nil, cryptov4.ErrConfiguration
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.draining {
		return g.operation, nil
	}
	if g.closed {
		return nil, cryptov4.ErrClosed
	}
	if timeoutMS == 0 {
		timeoutMS = g.config.DrainTimeoutMS
	}
	if absoluteCap == 0 {
		absoluteCap = math.MaxUint64
	}
	deadline, err := timev4.NewAge(g.config.Clock, min(timeoutMS, g.config.DrainTimeoutMS), absoluteCap)
	if err != nil {
		return nil, err
	}
	g.closed, g.draining, g.deadline = true, true, deadline
	notifyOpenWait(g.wake)
	return g.operation, nil
}

func (g *ServeGroup) Close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.closed, g.forced = true, true
	if g.abortResult.Outcome == DrainPending {
		g.abortResult = DrainResult{DrainFailed, cryptov4.ErrClosed}
	}
	if g.draining {
		g.operation.finish(DrainFailed, cryptov4.ErrClosed)
	}
	notifyOpenWait(g.wake)
	g.mu.Unlock()
}

// One original cursor drives all children without awaiting any child. A slow
// provider, handler or callback keeps its link but cannot block sibling Drain.
func (g *ServeGroup) run(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	parent := ctx.Done()
	for {
		g.environment.mu.Lock()
		environmentClosed := g.environment.closed
		g.environment.mu.Unlock()
		if environmentClosed {
			g.Close()
		}
		g.mu.Lock()
		if g.draining && !g.forced {
			if err := g.deadline.Check(); err != nil && !errors.Is(err, timev4.ErrUnavailable) {
				g.forced = true
				outcome := DrainFailed
				if errors.Is(err, timev4.ErrExpired) {
					outcome, err = DrainDeadlineAborted, ErrDrainDeadline
				}
				g.abortResult = DrainResult{outcome, err}
			}
		}
		if g.draining && g.pendingResults == 0 {
			outcome := Drained
			if g.failed {
				outcome = DrainFailed
			}
			if g.expired {
				outcome = DrainDeadlineAborted
			}
			g.operation.finish(outcome, g.firstCause)
		}
		if g.closed && g.active == 0 {
			g.mu.Unlock()
			timer.Stop()
			e := g.environment
			e.mu.Lock()
			g.mu.Lock()
			g.cleaned = true
			g.lifetime = nil
			close(g.done)
			e.groups[g.position] = nil
			e.groupsActive--
			e.completeLocked()
			g.mu.Unlock()
			e.mu.Unlock()
			return
		}
		closed, forced, abortResult := g.closed, g.forced, g.abortResult
		var cap uint64
		if g.deadline != nil {
			cap = g.deadline.Cap()
		}
		count := len(g.children)
		g.mu.Unlock()
		if closed {
			for range count {
				g.mu.Lock()
				index := g.cursor
				g.cursor = (g.cursor + 1) % count
				c := &g.children[index]
				s, op, published, driven, generation := c.session, c.drain, c.published, c.driven, c.generation
				g.mu.Unlock()
				if s == nil {
					continue
				}
				if forced || !published {
					result := s.abortFromGroup(abortResult)
					g.mu.Lock()
					c = &g.children[index]
					if c.generation == generation && c.active {
						g.reportLocked(c, result)
					}
					g.mu.Unlock()
				} else if !driven {
					var err error
					op, err = s.drainForGroup(cap)
					g.mu.Lock()
					c = &g.children[index]
					if c.generation == generation && c.active {
						c.driven, c.drain = true, op
						if err != nil {
							outcome := DrainFailed
							if errors.Is(err, timev4.ErrExpired) {
								outcome, err = DrainDeadlineAborted, ErrDrainDeadline
							}
							g.reportLocked(c, DrainResult{outcome, err})
						}
					}
					g.mu.Unlock()
				}
				if op != nil {
					result := op.Result()
					g.mu.Lock()
					c = &g.children[index]
					if c.generation == generation && c.active {
						g.reportLocked(c, result)
					}
					g.mu.Unlock()
				}
			}
		}
		timer.Reset(10 * time.Millisecond)
		select {
		case <-parent:
			g.Close()
			parent = nil
		case <-g.wake:
		case <-timer.C:
		}
		timer.Stop()
	}
}

func (g *ServeGroup) CleanupStatus() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cleaned
}
func (g *ServeGroup) WaitCleanup(ctx context.Context) error {
	if g == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-g.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (g *ServeGroup) Retire() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.cleaned {
		return cryptov4.ErrCapacity
	}
	if !g.retired {
		g.retired = true
		g.children = nil
		g.shared.Release()
		g.reservation.Release()
	}
	return nil
}
