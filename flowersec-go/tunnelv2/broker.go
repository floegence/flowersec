// Package tunnelv2 bridges opaque Flowersec v2 carrier streams without
// terminating endpoint-to-endpoint encryption.
package tunnelv2

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/carrier"
)

var (
	ErrInvalidLimits = errors.New("invalid Flowersec v2 tunnel bridge limits")
	ErrControlClosed = errors.New("Flowersec v2 tunnel control stream closed")
)

const defaultCleanupTimeout = 2 * time.Second

type Limits struct {
	MaxConcurrentStreams int
	CopyBufferBytes      int
	CleanupTimeout       time.Duration
}

func DefaultLimits() Limits {
	return Limits{MaxConcurrentStreams: 128, CopyBufferBytes: 32 << 10, CleanupTimeout: defaultCleanupTimeout}
}

func (limits Limits) normalized() Limits {
	if limits.CleanupTimeout == 0 {
		limits.CleanupTimeout = defaultCleanupTimeout
	}
	return limits
}

func (limits Limits) validate() error {
	if limits.MaxConcurrentStreams < 1 || limits.MaxConcurrentStreams > 128 ||
		limits.CopyBufferBytes < 1 || limits.CopyBufferBytes > 64<<10 ||
		limits.CleanupTimeout < time.Millisecond || limits.CleanupTimeout > time.Minute {
		return ErrInvalidLimits
	}
	return nil
}

// Bridge mirrors the client-opened control stream first, then maps every
// accepted data stream to one newly opened stream on the opposite leg. Stream
// bytes remain opaque; half-close and reset stay scoped to the mapped pair.
func Bridge(ctx context.Context, clientLeg, serverLeg carrier.Session, limits Limits) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if clientLeg == nil || serverLeg == nil {
		return io.ErrClosedPipe
	}
	limits = limits.normalized()
	if err := limits.validate(); err != nil {
		return err
	}
	bridgeContext, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled)

	clientControl, err := clientLeg.AcceptStream(bridgeContext)
	if err != nil {
		return errors.Join(preferContextCause(bridgeContext, err), closeBridgeSessions(limits.CleanupTimeout, clientLeg, serverLeg))
	}
	serverControl, err := serverLeg.OpenStream(bridgeContext)
	if err != nil {
		return errors.Join(preferContextCause(bridgeContext, err), closeBridgeSessions(limits.CleanupTimeout, clientLeg, serverLeg))
	}

	semaphore := make(chan struct{}, limits.MaxConcurrentStreams)
	tasks := newTaskGroup()
	tasks.Add(1)
	go func() {
		defer tasks.Done()
		if err := spliceStreamPair(bridgeContext, clientControl, serverControl, limits.CopyBufferBytes, true); err != nil {
			cancel(errors.Join(ErrControlClosed, err))
			return
		}
		cancel(ErrControlClosed)
	}()

	tasks.Add(2)
	go acceptLoop(bridgeContext, cancel, tasks, semaphore, clientLeg, serverLeg, limits.CopyBufferBytes)
	go acceptLoop(bridgeContext, cancel, tasks, semaphore, serverLeg, clientLeg, limits.CopyBufferBytes)

	<-bridgeContext.Done()
	cause := context.Cause(bridgeContext)
	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), limits.CleanupTimeout)
	defer cancelCleanup()
	closeCtx, cancelClose := context.WithTimeout(context.Background(), limits.CleanupTimeout/2)
	closeError := errors.Join(
		clientLeg.CloseWithErrorContext(closeCtx, carrier.ApplicationError{Reason: "tunnel bridge closed"}),
		serverLeg.CloseWithErrorContext(closeCtx, carrier.ApplicationError{Reason: "tunnel bridge closed"}),
	)
	cancelClose()
	waitError := tasks.Wait(cleanupCtx)
	return errors.Join(cause, closeError, waitError)
}

func acceptLoop(
	ctx context.Context,
	cancel context.CancelCauseFunc,
	tasks *taskGroup,
	semaphore chan struct{},
	source, target carrier.Session,
	bufferBytes int,
) {
	defer tasks.Done()
	for {
		incoming, err := source.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() == nil {
				cancel(err)
			}
			return
		}
		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			_ = incoming.Reset()
			return
		}
		outgoing, err := target.OpenStream(ctx)
		if err != nil {
			<-semaphore
			_ = incoming.Reset()
			if ctx.Err() != nil {
				return
			}
			continue
		}
		tasks.Add(1)
		go func() {
			defer tasks.Done()
			defer func() { <-semaphore }()
			_ = spliceStreamPair(ctx, incoming, outgoing, bufferBytes, false)
		}()
	}
}

type taskGroup struct {
	mu    sync.Mutex
	count int
	done  chan struct{}
}

func newTaskGroup() *taskGroup { return &taskGroup{done: make(chan struct{})} }

func (group *taskGroup) Add(count int) {
	group.mu.Lock()
	group.count += count
	group.mu.Unlock()
}

func (group *taskGroup) Done() {
	group.mu.Lock()
	group.count--
	if group.count == 0 {
		close(group.done)
	}
	group.mu.Unlock()
}

func (group *taskGroup) Wait(ctx context.Context) error {
	select {
	case <-group.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func closeBridgeSessions(timeout time.Duration, sessions ...carrier.Session) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var closeErrors []error
	for _, session := range sessions {
		closeErrors = append(closeErrors, session.CloseWithErrorContext(ctx, carrier.ApplicationError{Reason: "tunnel bridge closed"}))
	}
	return errors.Join(closeErrors...)
}

func spliceStreamPair(ctx context.Context, left, right carrier.Stream, bufferBytes int, closeOnHalfClose bool) error {
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = left.Reset()
		_ = right.Reset()
	})
	defer func() { _ = stopCancellation() }()

	results := make(chan error, 2)
	copyDirection := func(destination, source carrier.Stream) {
		buffer := make([]byte, bufferBytes)
		_, copyErr := io.CopyBuffer(destination, source, buffer)
		if copyErr != nil {
			_ = destination.Reset()
			results <- copyErr
			return
		}
		closeErr := destination.CloseWrite()
		results <- closeErr
	}
	go copyDirection(right, left)
	go copyDirection(left, right)
	first := <-results
	if first != nil || closeOnHalfClose {
		_ = left.Reset()
		_ = right.Reset()
	}
	second := <-results
	return errors.Join(first, second)
}

func preferContextCause(ctx context.Context, fallback error) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return fallback
}
