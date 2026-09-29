package ledgerv4

import (
	"context"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// This context never asks an opaque parent to register a child. Parent methods
// run once on the admitted constructor; all ownership gates read SDK state and
// the captured signal. The original task owns and joins its one observer.
type ledgerTaskContext struct {
	base           context.Context
	cancel         context.CancelCauseFunc
	parent         context.Context
	owner          *ledgerTaskContext
	parentDone     <-chan struct{}
	parentDeadline time.Time
	hasDeadline    bool
	stop, exited   chan struct{}
}

const ledgerTaskContextBytes = uint64(unsafe.Sizeof(ledgerTaskContext{})) + uint64(unsafe.Sizeof(time.Timer{})) + 1024

func newLedgerTaskContext(parent context.Context) *ledgerTaskContext {
	base, cancel := context.WithCancelCause(context.Background())
	c := &ledgerTaskContext{base: base, cancel: cancel, parent: parent,
		stop: make(chan struct{}), exited: make(chan struct{})}
	returned := false
	defer func() {
		if !returned {
			cancel(ErrOwner)
		}
	}()
	c.parentDeadline, c.hasDeadline = parent.Deadline()
	c.parentDone = parent.Done()
	if err := parent.Err(); err != nil {
		if err != context.DeadlineExceeded {
			err = context.Canceled
		}
		cancel(err)
	}
	returned = true
	return c
}

func (c *ledgerTaskContext) Deadline() (time.Time, bool) { return c.parentDeadline, c.hasDeadline }
func (c *ledgerTaskContext) Done() <-chan struct{}       { return c.base.Done() }
func (c *ledgerTaskContext) Value(key any) any {
	if value := c.base.Value(key); value != nil {
		return value
	}
	return c.parent.Value(key)
}

func (c *ledgerTaskContext) Err() error {
	if c.owner != nil && c.owner.Err() != nil {
		c.cancel(context.Cause(c.owner.base))
	}
	if c.hasDeadline && !time.Now().Before(c.parentDeadline) {
		c.cancel(context.DeadlineExceeded)
	}
	select {
	case <-c.parentDone:
		c.cancel(context.Canceled)
	default:
	}
	if cause := context.Cause(c.base); cause != nil {
		if cause == context.DeadlineExceeded || cause == timev4.ErrExpired {
			return context.DeadlineExceeded
		}
		return context.Canceled
	}
	return nil
}

func (c *ledgerTaskContext) observe(window *timev4.Window, deadline *timev4.Deadline, origin timev4.Mark) {
	returned := false
	defer close(c.exited)
	defer func() {
		if recovered := recover(); recovered != nil || !returned {
			c.cancel(ErrOwner)
		}
	}()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	var ownerDone, ownerParent <-chan struct{}
	if c.owner != nil {
		ownerDone, ownerParent = c.owner.base.Done(), c.owner.parentDone
	}
	for {
		select {
		case <-c.stop:
			returned = true
			return
		default:
		}
		if c.Err() != nil {
			returned = true
			return
		}
		remaining := uint64(100)
		var err error
		if window != nil {
			remaining, err = window.RemainingMS()
		}
		var cap uint64
		if err == nil && deadline != nil {
			var now timev4.Sample
			now, err = deadline.Sample()
			if err == nil && origin != (timev4.Mark{}) && !now.Mark.SameEra(origin) {
				err = timev4.ErrContinuity
			}
			if err == nil {
				cap, err = deadline.RemainingMSAt(now)
			}
		} else if deadline == nil {
			cap = remaining
		}
		if err != nil {
			c.cancel(err)
			returned = true
			return
		}
		// One merged wakeup observes the original bounds, including a changed
		// time era or tightened deadline. Rechecking never restarts the window.
		wait := time.Duration(max(uint64(1), min(remaining, cap, uint64(100)))) * time.Millisecond
		if c.hasDeadline {
			wait = min(wait, max(time.Nanosecond, time.Until(c.parentDeadline)))
		}
		timer.Reset(wait)
		select {
		case <-c.stop:
			returned = true
			return
		case <-c.base.Done():
			returned = true
			return
		case <-c.parentDone:
			_ = c.Err()
			returned = true
			return
		case <-ownerDone:
			_ = c.Err()
			returned = true
			return
		case <-ownerParent:
			_ = c.Err()
			returned = true
			return
		case <-timer.C:
		}
	}
}
