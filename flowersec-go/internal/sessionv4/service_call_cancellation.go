package sessionv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

var errServiceCallContext = errors.New("sessionv4: caller context failed")

// One preadmitted call position owns this cancellation observer. The exposed
// child is a standard context, but its parent registration touches only SDK
// state. No opaque parent starts a second standard-library relay. A blocked
// original Err/Cause read retains this owner until its actual task exits.
type serviceCallCancellation struct {
	parent      serviceCallParentContext
	context     context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	environment *Environment
}

// The separate Done prevents registration against the Cause context's hidden
// cancellation tree. AfterFunc admits exactly the one SDK child, whose callback
// uses only this cached Err and SDK-owned Cause. Application Value lookups
// still reach the original caller after the standard child handles its keys.
type serviceCallParentContext struct {
	mu          sync.Mutex
	input       context.Context
	cause       context.Context
	setCause    context.CancelCauseFunc
	done        chan struct{}
	deadline    time.Time
	hasDeadline bool
	err         error
	callback    func()
	registered  bool
	application *applicationContext
	cleanupOnly bool
}

func (p *serviceCallParentContext) Done() <-chan struct{} { return p.done }
func (p *serviceCallParentContext) Deadline() (time.Time, bool) {
	return p.deadline, p.hasDeadline
}
func (p *serviceCallParentContext) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}
func (p *serviceCallParentContext) Value(key any) any {
	switch key.(type) {
	case applicationContextKey:
		return p.application
	case cleanupOnlyContextKey:
		if p.cleanupOnly {
			return true
		}
		return nil
	}
	if value := p.cause.Value(key); value != nil {
		return value
	}
	return p.input.Value(key)
}
func (p *serviceCallParentContext) AfterFunc(callback func()) func() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.registered {
		panic("sessionv4: duplicate call cancellation registration")
	}
	p.registered, p.callback = true, callback
	return p.stop
}
func (p *serviceCallParentContext) stop() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.callback == nil {
		return false
	}
	p.callback = nil
	return true
}

func (p *serviceCallParentContext) finish(err, cause error) {
	p.mu.Lock()
	if p.err != nil {
		p.mu.Unlock()
		return
	}
	if err != context.Canceled && err != context.DeadlineExceeded {
		err = context.Canceled
	}
	if cause == nil {
		cause = err
	}
	p.setCause(cause)
	p.err = err
	close(p.done)
	callback := p.callback
	p.callback = nil
	p.mu.Unlock()
	if callback != nil {
		callback()
	}
}

func newServiceCallCancellation(input context.Context, environment *Environment) *serviceCallCancellation {
	o := &serviceCallCancellation{done: make(chan struct{}), environment: environment}
	o.parent.input, o.parent.done = input, make(chan struct{})
	o.parent.cause, o.parent.setCause = context.WithCancelCause(context.Background())
	o.context, o.cancel = context.WithCancel(&o.parent)
	return o
}

// setup belongs to the already retained caller stack. It either closes done
// itself, including on abnormal setup exit, or hands it to the one admitted
// observer. No setup callback executes under the client or parent gate.
func (o *serviceCallCancellation) setup() (err error) {
	return o.setupUntil(nil)
}

// Contract refresh adds its original trusted deadline to this same observer.
// A timer channel wakes the admitted task; no timer callback or opaque-parent
// context.WithTimeout creates another task or cleanup responsibility.
func (o *serviceCallCancellation) setupUntil(deadline *timev4.Deadline) (err error) {
	watching, returned := false, false
	defer func() {
		if !returned {
			o.parent.finish(context.Canceled, errServiceCallContext)
		}
		if !watching {
			close(o.done)
		}
	}()
	if err = o.context.Err(); err != nil {
		returned = true
		return err
	}
	input := o.parent.input
	inputDone := input.Done()
	o.parent.deadline, o.parent.hasDeadline = input.Deadline()
	if err = input.Err(); err != nil {
		o.parent.finish(err, context.Cause(input))
		returned = true
		return err
	}
	o.parent.application, _ = input.Value(applicationContextKey{}).(*applicationContext)
	o.parent.cleanupOnly = input.Value(cleanupOnlyContextKey{}) != nil
	if deadline != nil {
		remaining, sampleErr := deadline.RemainingMS()
		if sampleErr != nil {
			o.finishDeadline(sampleErr)
			returned = true
			return sampleErr
		}
		end := time.Now().Add(serviceCallWakeDuration(remaining))
		if !o.parent.hasDeadline || end.Before(o.parent.deadline) {
			o.parent.deadline, o.parent.hasDeadline = end, true
		}
	}
	if err = o.context.Err(); err != nil {
		returned = true
		return err
	}
	if inputDone != nil || deadline != nil {
		watching = true
		go o.observe(inputDone, deadline)
	}
	returned = true
	return nil
}

func serviceCallWakeDuration(remaining uint64) time.Duration {
	return time.Duration(min(remaining, uint64(math.MaxInt64/int64(time.Millisecond)))) * time.Millisecond
}

func (o *serviceCallCancellation) finishDeadline(err error) {
	standard := context.Canceled
	if err == timev4.ErrExpired {
		standard = context.DeadlineExceeded
	}
	o.parent.finish(standard, err)
}

func (o *serviceCallCancellation) observe(inputDone <-chan struct{}, deadline *timev4.Deadline) {
	returned := false
	defer func() {
		if recover() != nil || !returned {
			o.parent.finish(context.Canceled, errServiceCallContext)
		}
		if o.environment != nil {
			o.environment.signalMaterials()
		}
		close(o.done)
	}()
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		if o.context.Err() != nil {
			break
		}
		var wake <-chan time.Time
		if deadline != nil {
			remaining, err := deadline.RemainingMS()
			if err != nil {
				o.finishDeadline(err)
				break
			}
			if timer == nil {
				timer = time.NewTimer(serviceCallWakeDuration(remaining))
			} else {
				timer.Reset(serviceCallWakeDuration(remaining))
			}
			wake = timer.C
		}
		select {
		case <-o.context.Done():
		case <-inputDone:
			input := o.parent.input
			err := input.Err()
			if err == nil {
				err = context.Canceled
			}
			o.parent.finish(err, context.Cause(input))
		case <-wake:
			continue
		}
		break
	}
	returned = true
}

func (o *serviceCallCancellation) complete() bool {
	if o == nil {
		return true
	}
	select {
	case <-o.done:
		return true
	default:
		return false
	}
}

// The original call slot is running throughout setup. Both ordinary and
// initializer entries use this same cancellation owner and cleanup boundary.
func (c *UnaryServiceClient) setupCallContext(slot *serviceClientCall, input context.Context) (context.Context, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	o := newServiceCallCancellation(input, c.environment)
	slot.cancellation, slot.cancel = o, o.cancel
	c.mu.Unlock()
	if err := o.setup(); err != nil {
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return nil, cryptov4.ErrClosed
		}
		return nil, err
	}
	return o.context, nil
}
