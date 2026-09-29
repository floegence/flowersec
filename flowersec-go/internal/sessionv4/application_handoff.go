package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

// withApplicationHandoff orders a bounded SDK-only ownership transfer against
// actual callback/stage exit. A prior liveness check alone cannot protect a
// later installation. The action must not invoke application code, reenter
// the origin, sample clocks, wait for work, or perform external I/O.
func withApplicationHandoff(ctx context.Context, action func() error) error {
	if ctx == nil || action == nil {
		return cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if ctx.Value(cleanupOnlyContextKey{}) != nil {
		return ErrApplicationDependency
	}
	c, _ := ctx.Value(applicationContextKey{}).(*applicationContext)
	if c == nil {
		return action()
	}
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.live || !s.currentSerialLocked(c.serial) || s.services != nil && s.services.sealed.Load() {
		return ErrApplicationDependency
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return action()
}
