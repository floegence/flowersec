package sessionv4

import (
	"context"
	"sync"
	"time"
)

// initialParentContext supplies exactly one standard-library cancellation
// registration. Its private Done prevents attachment to the caller's hidden
// cancelCtx; its AfterFunc lets the original exchange tasks propagate parent
// cancellation without a standard-library observer goroutine. Providers still
// receive a normal derived context with the original Err/Cause semantics.
// This separately charged object never points back to InitialExchange. A
// provider retaining its context cannot retain handshake buffers through it.
type initialParentContext struct {
	mu          sync.Mutex
	parent      context.Context
	done        chan struct{}
	deadline    time.Time
	hasDeadline bool
	err         error
	callback    func()
	registered  bool
}

func (p *initialParentContext) Done() <-chan struct{} { return p.done }
func (p *initialParentContext) Deadline() (time.Time, bool) {
	return p.deadline, p.hasDeadline
}

func (p *initialParentContext) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *initialParentContext) Value(key any) any {
	return p.parent.Value(key)
}

func (p *initialParentContext) AfterFunc(callback func()) func() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.registered {
		panic("sessionv4: duplicate initial cancellation registration")
	}
	p.registered = true
	p.callback = callback
	// Go holds the child's cancellation mutex here. Only register; neither
	// inspect the original parent nor call back until construction returns.
	return p.stop
}

func (p *initialParentContext) stop() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.callback == nil {
		return false
	}
	p.callback = nil
	return true
}

// observe runs only in the original watchdog or under InitialExchange.mu.
// Those tasks and gates already participate in the actual cleanup boundary.
func (p *initialParentContext) observe() {
	p.mu.Lock()
	if p.err != nil {
		p.mu.Unlock()
		return
	}
	err := p.parent.Err()
	if err == nil {
		p.mu.Unlock()
		return
	}
	p.err = err
	close(p.done)
	callback := p.callback
	p.callback = nil
	p.mu.Unlock()
	if callback != nil {
		callback()
	}
}
