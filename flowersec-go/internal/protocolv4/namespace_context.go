package protocolv4

import (
	"context"
	"time"
)

// The provider gets the original caller's values and deadline, while
// cancellation belongs to the admitted SDK task. The original watchdog
// observes parent cancellation; no opaque parent registers a separate relay.
// SDK gates use only the local cancellation methods. Value finds the local
// cancellation owner before consulting the caller, including for Cause and
// children created with WithCancelCause.
type namespaceTaskContext struct {
	context.Context
	parent context.Context
}

func (c *namespaceTaskContext) Value(key any) any {
	if value := c.Context.Value(key); value != nil {
		return value
	}
	return c.parent.Value(key)
}

func (c *namespaceTaskContext) Deadline() (time.Time, bool) { return c.parent.Deadline() }
