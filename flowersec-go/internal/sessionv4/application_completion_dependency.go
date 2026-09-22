package sessionv4

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrCompletionDependency = errors.New("sessionv4: completion_dependency_unavailable")

const maxCompletionDependencyWaitMS = 30000

// This is a future service claim in the existing Completion reservation. It
// consumes no running worker. Its owner remains charged after conversion to a
// real permit; expiration only detaches the explicit dependency wait.
type completionDependency struct {
	mu       sync.Mutex
	executor atomic.Pointer[ApplicationExecutor]
	index    int
	states   [maxApplicationAncestors]*applicationContextState
	count    int
	window   *timev4.Window
	deadline time.Time
	expired  chan struct{}
	once     sync.Once
}

func completionDependencyBytes() uint64 {
	return uint64(unsafe.Sizeof(completionDependency{})) + uint64(unsafe.Sizeof(timev4.Window{}))
}

func (p *CompletionReservation) claimDependency(dependencies *applicationDependencies, clock *timev4.Clock) (*completionDependency, error) {
	if p == nil || dependencies == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e := p.executor.Load()
	if e == nil {
		return nil, cryptov4.ErrClosed
	}
	if !dependencies.hasCompletion(e) {
		return nil, nil
	}
	// Rejoining cannot reopen an expired first window while the coordinator is
	// between visits. Clock sampling stays outside the executor's dispatch gate.
	e.mu.Lock()
	var original *completionDependency
	if p.executor.Load() == e && p.index < len(e.completions) && e.completions[p.index].reservation == p {
		original = e.completions[p.index].dependency
	}
	e.mu.Unlock()
	original.advance()
	window, err := timev4.NewWindow(clock, maxCompletionDependencyWaitMS)
	if err != nil {
		return nil, err
	}
	d := &completionDependency{index: p.index, states: dependencies.states, count: dependencies.count, window: window, expired: make(chan struct{})}
	for j := 0; j < d.count; j++ {
		s := d.states[j]
		s.mu.Lock()
		deadline := s.deadline
		s.mu.Unlock()
		if !deadline.IsZero() && (d.deadline.IsZero() || deadline.Before(d.deadline)) {
			d.deadline = deadline
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if p.executor.Load() != e || p.index >= len(e.completions) || e.completions[p.index].reservation != p {
		return nil, cryptov4.ErrClosed
	}
	s := &e.completions[p.index]
	if !s.running && !s.claimed && e.completionRunning+e.completionClaims >= e.config.CompletionRunning {
		return nil, ErrCompletionDependency
	}
	if original := s.dependency; original != nil {
		original.mu.Lock()
		defer original.mu.Unlock()
		select {
		case <-original.expired:
			return nil, ErrCompletionDependency
		default:
		}
		if !original.deadline.IsZero() && !time.Now().Before(original.deadline) {
			return nil, ErrCompletionDependency
		}
		// Preflight the finite union; rejected joins cannot mutate an existing promise.
		states, count := original.states, original.count
		for j := 0; j < dependencies.count; j++ {
			state, found := dependencies.states[j], false
			for k := 0; k < count; k++ {
				found = found || states[k] == state
			}
			if !found {
				if count == maxApplicationAncestors {
					return nil, ErrCompletionDependency
				}
				states[count] = state
				count++
			}
		}
		original.states, original.count = states, count
		if !d.deadline.IsZero() && (original.deadline.IsZero() || d.deadline.Before(original.deadline)) {
			original.deadline = d.deadline
		}
		d = original
	}
	if s.running || s.claimed {
		return d, nil
	}
	if e.completionRunning+e.completionClaims >= e.config.CompletionRunning {
		return nil, ErrCompletionDependency
	}
	d.executor.Store(e)
	s.dependency, s.claimed = d, true
	e.completionClaims++
	e.dispatchCompletionsLocked()
	return d, nil
}

// The original Session coordinator calls advance. There is no per-result
// polling task or timer, and repeated waits cannot extend this first deadline.
func (d *completionDependency) advance() {
	if d == nil {
		return
	}
	d.mu.Lock()
	states, count, deadline := d.states, d.count, d.deadline
	d.mu.Unlock()
	expired := d.window.Check() != nil || !deadline.IsZero() && !time.Now().Before(deadline)
	e := d.executor.Load()
	live := false
	if e != nil {
		for j := 0; j < count; j++ {
			s := states[j]
			s.mu.Lock()
			live = live || s.live && s.executor == e && s.lane == completionApplicationLane
			s.mu.Unlock()
		}
	}
	if expired {
		d.once.Do(func() { close(d.expired) })
	}
	if e == nil || live && !expired {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if d.executor.Load() != e || d.index >= len(e.completions) {
		return
	}
	s := &e.completions[d.index]
	if s.dependency == d && s.claimed {
		s.claimed = false
		e.completionClaims--
	}
	d.executor.Store(nil)
	e.dispatchCompletionsLocked()
}

func completionContext(ctx interface{ Value(any) any }, executor *ApplicationExecutor) bool {
	c, _ := ctx.Value(applicationContextKey{}).(*applicationContext)
	if c == nil || executor == nil {
		return false
	}
	for j := 0; j <= c.count; j++ {
		s := c.state
		if j < c.count {
			s = c.ancestors[j]
		}
		s.mu.Lock()
		live := s.live && s.executor == executor && s.lane == completionApplicationLane
		s.mu.Unlock()
		if live {
			return true
		}
	}
	return false
}

// Detaching the last typed consumer withdraws only an unconsumed promise. The
// original dependency window stays fixed, while real callbacks retain permits.
func (p *CompletionReservation) releaseDependencyClaim() {
	if p == nil {
		return
	}
	e := p.executor.Load()
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if p.executor.Load() != e || p.index >= len(e.completions) {
		return
	}
	s := &e.completions[p.index]
	if s.reservation != p || !s.claimed {
		return
	}
	s.claimed = false
	e.completionClaims--
	if s.dependency != nil {
		s.dependency.executor.Store(nil)
	}
	e.dispatchCompletionsLocked()
}

func (d *completionDependency) limitDeadline(ctx context.Context) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return
	}
	d.mu.Lock()
	if d.deadline.IsZero() || deadline.Before(d.deadline) {
		d.deadline = deadline
	}
	d.mu.Unlock()
}
