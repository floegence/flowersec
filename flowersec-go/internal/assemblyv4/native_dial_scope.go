package assemblyv4

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// NativeDialScope is a trusted host operation that runs the supplied dial on
// its calling OS thread, for example inside an explicitly selected netns. It
// must invoke dial synchronously exactly once and restore its original scope
// before returning. It adds no retry, provider, worker or protocol authority.
// Errors after dial still leave native cleanup with the original factory.
type NativeDialScope func(context.Context, func() error) error

// RunNativeDial validates the one synchronous host operation. The caller must
// retain and retire any returned native owner even when the scope returns an error.
func RunNativeDial(ctx context.Context, scope NativeDialScope, dial func() error) error {
	if ctx == nil || dial == nil {
		return resourcev4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if scope == nil {
		return dial()
	}
	var state atomic.Uint32
	var repeated atomic.Bool
	var dialErr error
	finished := make(chan struct{})
	err := scope(ctx, func() error {
		if !state.CompareAndSwap(0, 1) {
			repeated.Store(true)
			return resourcev4.ErrConfiguration
		}
		defer func() { state.Store(2); close(finished) }()
		dialErr = dial()
		return dialErr
	})
	original := state.Swap(3)
	if original == 1 || original == 2 {
		<-finished
	}
	if original != 2 || repeated.Load() {
		return errors.Join(err, dialErr, resourcev4.ErrConfiguration)
	}
	return errors.Join(err, dialErr)
}
