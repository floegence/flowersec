package assemblyv4

import (
	"context"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// The original preparation observer owns parent cancellation. Deriving a
// standard cancel context from an opaque parent would create another task
// whose exit cannot be joined before the candidate slot is reused.
type carrierPreparationContext struct {
	context.Context
	lifetime context.Context
	cancel   context.CancelCauseFunc
	once     sync.Once
	err      error
}

func newCarrierPreparationContext(parent context.Context) (context.Context, context.CancelCauseFunc) {
	lifetime, cancel := context.WithCancelCause(context.Background())
	c := &carrierPreparationContext{Context: parent, lifetime: lifetime, cancel: cancel}
	return c, func(cause error) { c.cancelWithError(context.Canceled, cause) }
}

func (c *carrierPreparationContext) Done() <-chan struct{} { return c.lifetime.Done() }
func (c *carrierPreparationContext) Err() error {
	if c.lifetime.Err() == nil {
		return nil
	}
	return c.err
}
func (c *carrierPreparationContext) cancelWithError(err, cause error) {
	c.once.Do(func() {
		c.err = err
		c.cancel(cause)
	})
}
func cancelPreparationParent(parent, ctx context.Context, cancel context.CancelCauseFunc) {
	if original, ok := ctx.(*carrierPreparationContext); ok {
		original.cancelWithError(parent.Err(), context.Cause(parent))
	} else {
		cancel(context.Cause(parent))
	}
}
func (c *carrierPreparationContext) Value(key any) any {
	if value := c.lifetime.Value(key); value != nil {
		return value
	}
	return c.Context.Value(key)
}

// A nil trusted deadline is used by WebSocket preparation, whose original
// provider enforces its bounded handshake deadline on the owned socket.
func watchCarrierPreparation(parent, ctx context.Context, cancel context.CancelCauseFunc, deadline *timev4.Deadline, stop <-chan struct{}, stopped chan<- struct{}) {
	returned := false
	defer close(stopped)
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
		if recovered := recover(); recovered != nil || !returned {
			cancel(sessionv4.ErrEnvironmentTaskExit)
		}
	}()
	parentDone := parent.Done()
	for {
		if err := parent.Err(); err != nil {
			cancelPreparationParent(parent, ctx, cancel)
			returned = true
			return
		}
		var wake <-chan time.Time
		if deadline != nil {
			remaining, err := deadline.RemainingMS()
			if err != nil {
				cancel(err)
				returned = true
				return
			}
			// Chunking avoids uint64-to-duration overflow on distant caps.
			delay := time.Duration(min(remaining, uint64(time.Minute/time.Millisecond))) * time.Millisecond
			if timer == nil {
				timer = time.NewTimer(delay)
			} else {
				timer.Reset(delay)
			}
			wake = timer.C
		}
		select {
		case <-stop:
			if err := parent.Err(); err != nil {
				cancelPreparationParent(parent, ctx, cancel)
			}
			returned = true
			return
		case <-ctx.Done():
			returned = true
			return
		case <-parentDone:
			cancelPreparationParent(parent, ctx, cancel)
			returned = true
			return
		case <-wake:
		}
	}
}
