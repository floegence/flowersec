package sessionv4

import (
	"context"
	"time"
)

// Static installation calls no application code. Its retained synchronous
// visit captures only the context facts used by the SDK handoff gate, outside
// all owner locks. It needs no observer, timer, or derived cancellation task.
type staticContractContext struct {
	done        <-chan struct{}
	deadline    time.Time
	hasDeadline bool
	application *applicationContext
	cleanupOnly bool
	err         error
}

func captureStaticContractContext(input context.Context) (*staticContractContext, error) {
	c := &staticContractContext{done: input.Done()}
	c.deadline, c.hasDeadline = input.Deadline()
	c.application, _ = input.Value(applicationContextKey{}).(*applicationContext)
	c.cleanupOnly = input.Value(cleanupOnlyContextKey{}) != nil
	c.err = input.Err()
	return c, c.Err()
}

func (c *staticContractContext) Done() <-chan struct{} { return c.done }
func (c *staticContractContext) Deadline() (time.Time, bool) {
	return c.deadline, c.hasDeadline
}
func (c *staticContractContext) Err() error {
	if c.err != nil {
		return c.err
	}
	select {
	case <-c.done:
		return context.Canceled
	default:
		return nil
	}
}
func (c *staticContractContext) Value(key any) any {
	switch key.(type) {
	case applicationContextKey:
		return c.application
	case cleanupOnlyContextKey:
		if c.cleanupOnly {
			return true
		}
	}
	return nil
}
