package sessionv4

import (
	"context"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
)

func (s *applicationContextState) currentSerialLocked(serial uint64) bool {
	if s.depth == 0 {
		return serial == 0
	}
	return serial == s.serial[s.depth-1]
}

// ordinarySynchronousOrigin selects only the actual current ordinary owner.
// Completion ancestry is preserved by the original context and dependencies.
// This is a local capability check, never a goroutine identity inference.
func ordinarySynchronousOrigin(ctx context.Context, executor *ApplicationExecutor) (*applicationContext, ApplicationWorkClass, error) {
	if _, err := checkApplicationContext(ctx); err != nil {
		return nil, 0, err
	}
	c, _ := ctx.Value(applicationContextKey{}).(*applicationContext)
	if c == nil {
		return nil, 0, nil
	}
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.live || !s.currentSerialLocked(c.serial) {
		return nil, 0, ErrApplicationDependency
	}
	if s.lane != ordinaryApplicationLane || s.executor != executor {
		return nil, 0, nil
	}
	return c, s.class, nil
}

// enterSynchronousStage is a direct call within an existing ordinary callback.
// The caller has already acquired every entry/input/output/scratch resource.
// Each child receives a distinct serial token; the suspended parent's token and
// an exited child's token cannot create detectable concurrent or stale work.
// An application must not escape this context into its own concurrent work.
func enterSynchronousStage(ctx context.Context, executor *ApplicationExecutor) (context.Context, func(), error) {
	c, _, err := ordinarySynchronousOrigin(ctx, executor)
	if err != nil {
		return nil, nil, err
	}
	if c == nil {
		return nil, nil, cryptov4.ErrConfiguration
	}
	s := c.state
	s.mu.Lock()
	if !s.live || !s.currentSerialLocked(c.serial) || s.depth == len(s.serial) || s.sequence == math.MaxUint64 {
		s.mu.Unlock()
		return nil, nil, ErrApplicationDependency
	}
	if err := s.backing.Check(); err != nil {
		s.mu.Unlock()
		return nil, nil, err
	}
	s.sequence++
	token := s.sequence
	s.serial[s.depth] = token
	s.depth++
	s.mu.Unlock()
	child := &applicationContext{Context: ctx, state: s, ancestors: c.ancestors, count: c.count, serial: token}
	return child, func() {
		s.mu.Lock()
		if s.depth != 0 && s.serial[s.depth-1] == token {
			s.depth--
			s.serial[s.depth] = 0
		}
		s.mu.Unlock()
	}, nil
}

// runInline consumes an actual ordinary permit without creating an SDK task.
// External and Completion callers need this new permit; a live synchronous
// ordinary stage instead continues under its original owner. Both retain their
// real slot and backing until the callback and all of its defers have exited.
func (p *ApplicationPermit) runInline(work func()) error {
	if p == nil || work == nil {
		return cryptov4.ErrConfiguration
	}
	e := p.executor.Load()
	if e == nil {
		return cryptov4.ErrClosed
	}
	e.mu.Lock()
	result, err := e.startLocked(p)
	e.mu.Unlock()
	if err != nil {
		return err
	}
	e.run(p.index, work, result)
	return nil
}
