package contextutil

import (
	"context"
	"time"
)

// WithTimeout returns the parent context if d<=0; otherwise wraps it with a timeout.
func WithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, d)
}
