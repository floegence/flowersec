package controlv4

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
	"unsafe"
)

var ErrControlTaskExit = errors.New("controlv4: original control task exited unexpectedly")

// The original transport reserves one context and observer for the complete
// call, including source verification, Completion and result decoding.
// No context is derived from an opaque parent with an implicit forwarding task.
const controlCallContextBytes = uint64(unsafe.Sizeof(controlCallContext{})) + 1024

type controlCallContext struct {
	base         context.Context
	cancel       context.CancelCauseFunc
	parent       context.Context
	parentDone   <-chan struct{}
	deadline     time.Time
	provider     *HTTPSBootstrapProvider
	interrupt    func()
	beforeWrite  func() error
	stop, exited chan struct{}
	started      bool
}

// Construction invokes only SDK operations. Publish cancel under the owner's
// gate before start inspects any application-supplied context methods.
func newControlCallContext(timeout time.Duration) *controlCallContext {
	base, cancel := context.WithCancelCause(context.Background())
	return &controlCallContext{base: base, cancel: cancel,
		deadline: time.Now().Add(timeout),
		stop:     make(chan struct{}), exited: make(chan struct{})}
}

func newHTTPSCallContext(provider *HTTPSBootstrapProvider) *controlCallContext {
	call := newControlCallContext(provider.config.Timeout)
	call.provider = provider
	return call
}

// start runs on the original caller, after its unconditional cleanup defer is
// installed. A context callback that blocks or exits still owns that position.
func (c *controlCallContext) bindParent(parent context.Context) error {
	c.parent = parent
	if end, ok := parent.Deadline(); ok && end.Before(c.deadline) {
		c.deadline = end
	}
	c.parentDone = parent.Done()
	if err := parent.Err(); err != nil {
		if err != context.DeadlineExceeded {
			err = context.Canceled
		}
		c.cancel(err)
	}
	return c.Err()
}

func (c *controlCallContext) startObserver() {
	c.started = true
	go c.observe()
}

func (c *controlCallContext) start(parent context.Context) error {
	if err := c.bindParent(parent); err != nil {
		return err
	}
	c.startObserver()
	return nil
}

// The handler's one observer also owns the actual host interruption callbacks.
// Install absolute I/O deadlines before it starts, so a late setup call cannot
// overwrite an already delivered cancellation with a later deadline.
func (c *controlCallContext) startHTTP(parent context.Context, w http.ResponseWriter) error {
	return c.startHTTPDirections(parent, w, true)
}

func (c *controlCallContext) startHTTPDirections(parent context.Context, w http.ResponseWriter, read bool) error {
	if err := c.bindParent(parent); err != nil {
		return err
	}
	controller := http.NewResponseController(w)
	if read {
		if err := controller.SetReadDeadline(c.deadline); err != nil {
			return err
		}
	}
	if err := controller.SetWriteDeadline(c.deadline); err != nil {
		return err
	}
	c.interrupt = func() {
		now := time.Now()
		// Each original direction gets its cleanup even if the other host
		// callback panics or terminates this observer goroutine.
		defer controller.SetWriteDeadline(now)
		if read {
			_ = controller.SetReadDeadline(now)
		}
	}
	if err := c.Err(); err != nil {
		return err
	}
	c.startObserver()
	return nil
}

func (c *controlCallContext) Deadline() (time.Time, bool) { return c.deadline, true }
func (c *controlCallContext) Done() <-chan struct{}       { return c.base.Done() }
func (c *controlCallContext) Value(key any) any {
	if value := c.base.Value(key); value != nil {
		return value
	}
	return c.parent.Value(key)
}

// Err reads only SDK state, the captured parent signal and the original fixed
// deadline. Parent methods run once in start, outside every ownership gate.
// The context contract keeps its two public error values; fixed internal causes
// remain available to the original cleanup/publication owner.
func (c *controlCallContext) Err() error {
	if cause := c.cause(); cause != nil {
		c.cancel(cause)
		if cause == context.DeadlineExceeded {
			return context.DeadlineExceeded
		}
		return context.Canceled
	}
	return nil
}

// cause is callback-free, including before start has finished. It is safe at
// the final publication gate and during panic/Goexit cleanup.
func (c *controlCallContext) cause() error {
	if cause := context.Cause(c.base); cause != nil {
		return cause
	}
	if !time.Now().Before(c.deadline) {
		return context.DeadlineExceeded
	}
	select {
	case <-c.parentDone:
		return context.Canceled
	default:
		return nil
	}
}

func (c *controlCallContext) stopCall() { c.cancel(context.Canceled) }

func (c *controlCallContext) observe() {
	returned := false
	defer close(c.exited)
	defer func() {
		if recovered := recover(); recovered != nil || !returned {
			c.cancel(ErrControlTaskExit)
			c.closeActive()
		}
	}()
	var providerStop <-chan struct{}
	if c.provider != nil {
		providerStop = c.provider.stop
	}
	timer := time.NewTimer(time.Until(c.deadline))
	defer timer.Stop()
	select {
	case <-c.stop:
		returned = true
		return
	case <-c.base.Done():
	case <-c.parentDone:
		cause := c.cause()
		if cause == nil {
			cause = context.Canceled
		}
		c.cancel(cause)
	case <-timer.C:
		c.cancel(context.DeadlineExceeded)
	case <-providerStop:
		c.cancel(net.ErrClosed)
	}
	c.closeActive()
	if c.interrupt != nil {
		c.interrupt()
	}
	returned = true
}

// finish joins the actual observer before its owner releases any capacity.
// It does not call the parent or manufacture cancellation of a successful call.
func (c *controlCallContext) finish() {
	if c.started {
		close(c.stop)
		<-c.exited
	}
}

func (c *controlCallContext) closeActive() {
	p := c.provider
	if p == nil {
		return
	}
	p.mu.Lock()
	conn := p.active
	p.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}
