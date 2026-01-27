package contextutil

import (
	"context"
	"time"
)

// WithTimeout returns parent if d<=0; otherwise wraps it with a timeout.
//
// A nil parent is treated as context.Background() to avoid panics in downstream code.
func WithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if d <= 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, d)
}
