// Package tunnelv3 bridges opaque Flowersec v3 carrier streams without
// terminating endpoint-to-endpoint encryption.
package tunnelv3

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
)

var (
	ErrInvalidLimits     = errors.New("invalid Flowersec v3 tunnel bridge limits")
	ErrControlClosed     = errors.New("Flowersec v3 tunnel control stream closed")
	ErrActivationTimeout = errors.New("Flowersec v3 tunnel activation timed out")
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
func Bridge(ctx context.Context, clientLeg, serverLeg carrier.Session, limits Limits, activationTimeout time.Duration) error {
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
	if activationTimeout < time.Millisecond || activationTimeout > time.Minute {
		return ErrInvalidLimits
	}
	bridgeContext, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled)

	activationContext, cancelActivation := context.WithTimeoutCause(bridgeContext, activationTimeout, ErrActivationTimeout)
	clientControl, err := acceptControlStream(activationContext, clientLeg)
	if err != nil {
		cancelActivation()
		return errors.Join(preferContextCause(bridgeContext, err), closeBridgeSessions(limits.CleanupTimeout, clientLeg, serverLeg))
	}
	serverControl, err := openControlStream(activationContext, serverLeg)
	cancelActivation()
	if err != nil {
		_ = clientControl.Reset()
		return errors.Join(preferContextCause(bridgeContext, err), closeBridgeSessions(limits.CleanupTimeout, clientLeg, serverLeg))
	}

	semaphore := make(chan struct{}, limits.MaxConcurrentStreams)
	clientUnreliable, clientSupportsUnreliable := clientLeg.(carrier.UnreliableTransport)
	serverUnreliable, serverSupportsUnreliable := serverLeg.(carrier.UnreliableTransport)
	bridgeUnreliable := clientSupportsUnreliable && serverSupportsUnreliable &&
		clientUnreliable.UnreliableAvailable() && serverUnreliable.UnreliableAvailable()
	baseTasks := 3
	if bridgeUnreliable {
		baseTasks += 2
	}
	tasks := newTaskGroup(baseTasks)
	go func() {
		defer tasks.Done()
		if err := spliceStreamPair(bridgeContext, clientControl, serverControl, limits.CopyBufferBytes, limits.CleanupTimeout); err != nil {
			cancel(errors.Join(ErrControlClosed, err))
			return
		}
		cancel(ErrControlClosed)
	}()

	go acceptLoop(bridgeContext, tasks, semaphore, clientLeg, serverLeg, limits.CopyBufferBytes)
	go acceptLoop(bridgeContext, tasks, semaphore, serverLeg, clientLeg, limits.CopyBufferBytes)
	if bridgeUnreliable {
		go unreliableLoop(bridgeContext, tasks, clientUnreliable, serverUnreliable)
		go unreliableLoop(bridgeContext, tasks, serverUnreliable, clientUnreliable)
	}

	<-bridgeContext.Done()
	cause := context.Cause(bridgeContext)
	applicationError := carrier.ApplicationError{Reason: "tunnel bridge closed"}
	if errors.Is(cause, ErrControlClosed) {
		applicationError = carrier.ApplicationError{Code: 1, Reason: "session closed"}
	}
	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), limits.CleanupTimeout)
	defer cancelCleanup()
	closeCtx, cancelClose := context.WithTimeout(context.Background(), limits.CleanupTimeout/2)
	closeError := errors.Join(
		clientLeg.CloseWithErrorContext(closeCtx, applicationError),
		serverLeg.CloseWithErrorContext(closeCtx, applicationError),
	)
	cancelClose()
	waitError := tasks.Wait(cleanupCtx)
	return errors.Join(cause, closeError, waitError)
}

type controlStreamResult struct {
	stream carrier.Stream
	err    error
}

func acceptControlStream(ctx context.Context, session carrier.Session) (carrier.Stream, error) {
	return boundedControlStream(ctx, func() (carrier.Stream, error) { return session.AcceptStream(ctx) })
}

func openControlStream(ctx context.Context, session carrier.Session) (carrier.Stream, error) {
	return boundedControlStream(ctx, func() (carrier.Stream, error) { return session.OpenStream(ctx) })
}

func boundedControlStream(ctx context.Context, operation func() (carrier.Stream, error)) (carrier.Stream, error) {
	result := make(chan controlStreamResult, 1)
	go func() {
		stream, err := operation()
		if ctx.Err() != nil && stream != nil {
			_ = stream.Reset()
			stream = nil
		}
		result <- controlStreamResult{stream: stream, err: err}
	}()
	select {
	case completed := <-result:
		return completed.stream, completed.err
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

func unreliableLoop(
	ctx context.Context,
	tasks *taskGroup,
	source, target carrier.UnreliableTransport,
) {
	defer tasks.Done()
	for {
		payload, err := source.ReceiveUnreliable(ctx)
		if err != nil {
			return
		}
		if err := target.SendUnreliable(payload); err != nil {
			return
		}
	}
}

func acceptLoop(
	ctx context.Context,
	tasks *taskGroup,
	semaphore chan struct{},
	source, target carrier.Session,
	bufferBytes int,
) {
	defer tasks.Done()
	for {
		incoming, err := source.AcceptStream(ctx)
		if err != nil {
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
			_ = spliceStreamPair(ctx, incoming, outgoing, bufferBytes, 0)
		}()
	}
}

type taskGroup struct {
	mu    sync.Mutex
	count int
	done  chan struct{}
}

func newTaskGroup(initial int) *taskGroup {
	return &taskGroup{count: initial, done: make(chan struct{})}
}

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

func spliceStreamPair(ctx context.Context, left, right carrier.Stream, bufferBytes int, halfCloseGrace time.Duration) error {
	if halfCloseGrace > 0 {
		return spliceControlStreamPair(ctx, left, right, bufferBytes, halfCloseGrace)
	}
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
	if first != nil {
		_ = left.Reset()
		_ = right.Reset()
		return errors.Join(first, <-results)
	}
	return <-results
}

type controlCopyEvent struct {
	direction int
	eof       bool
	err       error
}

func spliceControlStreamPair(ctx context.Context, left, right carrier.Stream, bufferBytes int, halfCloseGrace time.Duration) error {
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = left.Reset()
		_ = right.Reset()
	})
	defer func() { _ = stopCancellation() }()

	events := make(chan controlCopyEvent, 4)
	copyDirection := func(direction int, destination, source carrier.Stream) {
		buffer := make([]byte, bufferBytes)
		_, copyErr := io.CopyBuffer(destination, source, buffer)
		if copyErr != nil {
			events <- controlCopyEvent{direction: direction, err: copyErr}
			return
		}
		events <- controlCopyEvent{direction: direction, eof: true}
		events <- controlCopyEvent{direction: direction, err: destination.CloseWrite()}
	}
	go copyDirection(0, right, left)
	go copyDirection(1, left, right)

	done := [2]bool{}
	var timer *time.Timer
	var timerChannel <-chan time.Time
	for !done[0] || !done[1] {
		select {
		case event := <-events:
			if event.eof {
				if timer == nil {
					timer = time.NewTimer(halfCloseGrace)
					timerChannel = timer.C
				}
				continue
			}
			done[event.direction] = true
			if event.err != nil {
				_ = left.Reset()
				_ = right.Reset()
				if timer != nil {
					timer.Stop()
				}
				return event.err
			}
		case <-timerChannel:
			_ = left.Reset()
			_ = right.Reset()
			return context.DeadlineExceeded
		case <-ctx.Done():
			_ = left.Reset()
			_ = right.Reset()
			if timer != nil {
				timer.Stop()
			}
			return context.Cause(ctx)
		}
	}
	if timer != nil {
		timer.Stop()
	}
	return nil
}

func preferContextCause(ctx context.Context, fallback error) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return fallback
}
