package sessionv4

import (
	"context"
	"errors"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

var ErrApplicationDependency = errors.New("sessionv4: dependency_unavailable")

// The SDK carries at most eight explicit application ancestors. These are
// local, original owners; no peer field, goroutine identity or ambient global
// context can manufacture an invocation or remove a Completion ancestor.
const maxApplicationAncestors = 8

type applicationLane uint8

const (
	ordinaryApplicationLane applicationLane = iota
	completionApplicationLane
)

type applicationContextKey struct{}
type cleanupOnlyContextKey struct{}

// Cleanup inherits only its original finite cancellation/deadline. The SDK
// gives the callback no context that can authorize new business descendants.
type ordinaryCleanupContext struct{ context.Context }

func (c ordinaryCleanupContext) Value(key any) any {
	if _, ok := key.(cleanupOnlyContextKey); ok {
		return true
	}
	if _, ok := key.(applicationContextKey); ok {
		return nil
	}
	return c.Context.Value(key)
}

type applicationContext struct {
	context.Context
	state     *applicationContextState
	ancestors [maxApplicationAncestors]*applicationContextState
	count     int
	serial    uint64
}

func (c *applicationContext) Value(key any) any {
	if _, ok := key.(applicationContextKey); ok {
		return c
	}
	return c.Context.Value(key)
}

// State is separate from its invocation so an escaped application context
// cannot retain an old Session, input or executor after actual callback exit.
// A known SDK child pins the original metadata with a real reference below.
type applicationContextState struct {
	mu            sync.Mutex
	executor      *ApplicationExecutor
	result        *UnaryCall
	streamResult  *StreamMessages
	messageResult *typedMessageDecode
	backing       resourcev4.Reference
	lane          applicationLane
	class         ApplicationWorkClass
	live          bool
	deadline      time.Time
	serial        [maxApplicationAncestors]uint64
	depth         int
	sequence      uint64
}

type applicationDependencies struct {
	states [maxApplicationAncestors]*applicationContextState
	refs   [maxApplicationAncestors]resourcev4.Reference
	count  int
}

func applicationContextBytes() uint64 {
	return uint64(unsafe.Sizeof(applicationContext{})) + uint64(unsafe.Sizeof(applicationContextState{}))
}

// enterApplicationContext is used only by an already running SDK application
// trampoline. The original metadata includes this bounded context and state.
// The returned exit must run after all application defers, including Goexit.
func enterApplicationContext(parent context.Context, executor *ApplicationExecutor, lane applicationLane, class ApplicationWorkClass, backing resourcev4.Reference, dependencies *applicationDependencies) (context.Context, func(), error) {
	return enterApplicationContextState(parent, executor, lane, class, backing, dependencies, false)
}

// Only the already admitted lease-release trampoline uses this entry. Closing
// a budget domain cannot erase that original cleanup obligation. Descendant
// work still needs a fresh Borrow and therefore cannot reopen the closed domain.
func enterCleanupApplicationContext(executor *ApplicationExecutor, backing resourcev4.Reference) (context.Context, func(), error) {
	return enterApplicationContextState(context.Background(), executor, completionApplicationLane, ApplicationShort, backing, nil, true)
}

func enterApplicationContextState(parent context.Context, executor *ApplicationExecutor, lane applicationLane, class ApplicationWorkClass, backing resourcev4.Reference, dependencies *applicationDependencies, retained bool) (context.Context, func(), error) {
	if parent == nil || executor == nil || lane > completionApplicationLane || class > ApplicationResident {
		return nil, nil, cryptov4.ErrConfiguration
	}
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	check := backing.Check
	if retained {
		check = backing.CheckRetained
	}
	if err := check(); err != nil {
		return nil, nil, err
	}
	deadline, _ := parent.Deadline()
	s := &applicationContextState{deadline: deadline, executor: executor, backing: backing, lane: lane, class: class, live: true}
	c := &applicationContext{Context: parent, state: s}
	if dependencies != nil {
		c.ancestors, c.count = dependencies.states, dependencies.count
	}
	return c, func() {
		s.mu.Lock()
		s.live = false
		s.executor = nil
		s.result = nil
		s.streamResult = nil
		s.messageResult = nil
		s.backing = resourcev4.Reference{}
		s.mu.Unlock()
	}, nil
}

// captureApplicationDependencies precedes new work, never waits for a parent,
// and pins only real original references. An exited parent cannot be used to
// create work. Already accepted children retain their own independent rights.
func captureApplicationDependencies(ctx context.Context) (d applicationDependencies, err error) {
	if ctx == nil {
		return d, cryptov4.ErrConfiguration
	}
	if err = ctx.Err(); err != nil {
		return d, err
	}
	if ctx.Value(cleanupOnlyContextKey{}) != nil {
		return d, ErrApplicationDependency
	}
	c, _ := ctx.Value(applicationContextKey{}).(*applicationContext)
	if c == nil {
		return d, nil
	}
	if c.count >= maxApplicationAncestors {
		return d, ErrApplicationDependency
	}
	defer func() {
		if err != nil {
			d.release()
		}
	}()
	for j := 0; j <= c.count; j++ {
		s := c.state
		if j < c.count {
			s = c.ancestors[j]
		}
		s.mu.Lock()
		if !s.live || j == c.count && !s.currentSerialLocked(c.serial) {
			s.mu.Unlock()
			if j == c.count {
				return d, ErrApplicationDependency
			}
			continue
		}
		ref, e := s.backing.Borrow()
		s.mu.Unlock()
		if e != nil {
			return d, e
		}
		d.states[d.count], d.refs[d.count] = s, ref
		d.count++
	}
	return d, nil
}

func (d *applicationDependencies) release() {
	for j := 0; j < d.count; j++ {
		d.refs[j].Release()
	}
	*d = applicationDependencies{}
}

func (d *applicationDependencies) merge(source *applicationDependencies) error {
	if source == nil {
		return nil
	}
	for j := 0; j < source.count; j++ {
		s := source.states[j]
		found := false
		for k := 0; k < d.count; k++ {
			found = found || d.states[k] == s
		}
		if found {
			continue
		}
		s.mu.Lock()
		if !s.live {
			s.mu.Unlock()
			continue
		}
		if d.count == maxApplicationAncestors {
			s.mu.Unlock()
			return ErrApplicationDependency
		}
		ref, err := s.backing.Borrow()
		s.mu.Unlock()
		if err != nil {
			return err
		}
		d.states[d.count], d.refs[d.count] = s, ref
		d.count++
	}
	return nil
}

func (d *applicationDependencies) checkOrigin() error {
	if d.count == 0 {
		return nil
	}
	s := d.states[d.count-1]
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.live {
		return ErrApplicationDependency
	}
	return nil
}

func (d *applicationDependencies) hasCompletion(executor *ApplicationExecutor) bool {
	for j := 0; j < d.count; j++ {
		s := d.states[j]
		s.mu.Lock()
		live := s.live && s.executor == executor && s.lane == completionApplicationLane
		s.mu.Unlock()
		if live {
			return true
		}
	}
	return false
}

func checkApplicationContext(ctx context.Context) (bool, error) {
	if ctx == nil {
		return false, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if ctx.Value(cleanupOnlyContextKey{}) != nil {
		return true, ErrApplicationDependency
	}
	c, _ := ctx.Value(applicationContextKey{}).(*applicationContext)
	if c == nil {
		return false, nil
	}
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	if !c.state.live || !c.state.currentSerialLocked(c.serial) {
		return true, ErrApplicationDependency
	}
	return true, nil
}

// The original decoder cannot wait for its own output or cleanup. The bounded
// explicit ancestor list also catches a known SDK child that depends on it.
func (c *UnaryCall) checkResultDependency(ctx context.Context) error {
	if _, err := checkApplicationContext(ctx); err != nil {
		return err
	}
	parent, _ := ctx.Value(applicationContextKey{}).(*applicationContext)
	if parent == nil {
		return nil
	}
	for j := 0; j <= parent.count; j++ {
		s := parent.state
		if j < parent.count {
			s = parent.ancestors[j]
		}
		s.mu.Lock()
		self := s.live && s.result == c
		s.mu.Unlock()
		if self {
			return ErrCompletionDependency
		}
	}
	return nil
}

func (d *applicationDependencies) pruneExited() {
	n := 0
	for j := 0; j < d.count; j++ {
		s := d.states[j]
		s.mu.Lock()
		live := s.live
		s.mu.Unlock()
		if live {
			d.states[n], d.refs[n] = s, d.refs[j]
			n++
		} else {
			d.refs[j].Release()
		}
	}
	clear(d.states[n:])
	clear(d.refs[n:])
	d.count = n
}
