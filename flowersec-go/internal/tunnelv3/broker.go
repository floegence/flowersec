// Package tunnelv3 bridges opaque flowersec v5 carrier streams without
// terminating endpoint-to-endpoint encryption.
package tunnelv3

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/carrier"
)

var (
	ErrInvalidLimits     = errors.New("invalid flowersec v5 tunnel bridge limits")
	ErrControlClosed     = errors.New("flowersec v5 tunnel control stream closed")
	errControlForwarding = errors.New("tunnel control forwarding failed")
	ErrActivationTimeout = errors.New("flowersec v5 tunnel activation timed out")
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
	return bridge(ctx, clientLeg, serverLeg, limits, activationTimeout, new(sync.WaitGroup))
}

func bridge(ctx context.Context, clientLeg, serverLeg carrier.Session, limits Limits, activationTimeout time.Duration, workers *sync.WaitGroup) error {
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
	clientControl, err := boundedControlStream(activationContext, workers, clientLeg.AcceptStream)
	if err != nil {
		cancelActivation()
		return errors.Join(preferContextCause(bridgeContext, err), closeBridgeSessions(limits.CleanupTimeout, clientLeg, serverLeg))
	}
	serverControl, err := boundedControlStream(activationContext, workers, serverLeg.OpenStream)
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
	controlEvents := startControlCopies(clientControl, serverControl, limits.CopyBufferBytes, workers)
	workers.Go(func() { acceptLoop(bridgeContext, workers, semaphore, clientLeg, serverLeg, limits.CopyBufferBytes) })
	workers.Go(func() { acceptLoop(bridgeContext, workers, semaphore, serverLeg, clientLeg, limits.CopyBufferBytes) })
	if bridgeUnreliable {
		workers.Go(func() { unreliableLoop(bridgeContext, clientUnreliable, serverUnreliable) })
		workers.Go(func() { unreliableLoop(bridgeContext, serverUnreliable, clientUnreliable) })
	}

	firstFIN, err := waitControlCopies(bridgeContext, controlEvents, limits.CleanupTimeout)
	var clientReleased bool
	var releaseErr error
	if err != nil {
		resetDone := make(chan struct{})
		workers.Go(func() {
			defer close(resetDone)
			_ = clientControl.Reset()
			_ = serverControl.Reset()
		})
		select {
		case <-resetDone:
		case <-bridgeContext.Done():
		}
	} else if firstFIN == 1 || (clientLeg.Kind() == serverLeg.Kind() && nativeTunnelSession(clientLeg)) {
		drain, stop := context.WithTimeout(bridgeContext, limits.CleanupTimeout)
		legs := []carrier.Session{clientLeg, serverLeg}
		if firstFIN == 1 {
			// The client sends its FIN only after verifying the server's
			// record and FIN. Its own input is now fully copied to the server.
			if bridgeContext.Err() == nil {
				clientReleased = true
				releaseErr = clientLeg.CloseWithErrorContext(drain, closeApplicationError(ErrControlClosed))
			}
			legs = legs[1:]
		} else if clientLeg.Kind() == carrier.KindWebTransport {
			legs = legs[:1]
		}
		for _, leg := range legs {
			select {
			case <-leg.Termination():
			case <-drain.Done():
				err = context.Cause(drain)
			}
			if err != nil {
				break
			}
		}
		stop()
	} else if clientLeg.Kind() == carrier.KindWebSocket && serverLeg.Kind() == carrier.KindWebSocket {
		// A client-first opaque exchange has no later client FIN to prove the
		// reply FIN reached its mux. Keep WebSocket CLOSE behind that frame.
		if flusher, ok := clientControl.(interface{ Flush(context.Context) error }); ok {
			drain, stop := context.WithTimeout(bridgeContext, limits.CleanupTimeout)
			err = flusher.Flush(drain)
			stop()
		}
	}
	if err != nil {
		cancel(errors.Join(errControlForwarding, err))
	} else {
		cancel(ErrControlClosed)
	}
	cause := context.Cause(bridgeContext)
	applicationError := closeApplicationError(cause)
	// Parent cancellation keeps the carrier's existing wire close reason while
	// Bridge returns the caller's cause. A copy failure uses its own reason.
	if !errors.Is(cause, ErrControlClosed) && !errors.Is(cause, errControlForwarding) {
		applicationError = carrier.ApplicationError{Reason: "tunnel bridge closed"}
		if err != nil && clientLeg.Kind() == carrier.KindWebTransport && serverLeg.Kind() == carrier.KindWebTransport {
			applicationError = closeApplicationError(errControlForwarding)
		}
	}
	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), limits.CleanupTimeout)
	defer cancelCleanup()
	closeCtx, cancelClose := context.WithTimeout(context.Background(), limits.CleanupTimeout/2)
	closeError := releaseErr
	if !clientReleased {
		closeError = clientLeg.CloseWithErrorContext(closeCtx, applicationError)
	}
	closeError = errors.Join(closeError, serverLeg.CloseWithErrorContext(closeCtx, applicationError))
	cancelClose()
	done := make(chan struct{})
	go func() {
		workers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return errors.Join(cause, closeError)
	case <-cleanupCtx.Done():
		return errors.Join(cause, closeError, cleanupCtx.Err())
	}
}

type controlStreamResult struct {
	stream carrier.Stream
	err    error
}

func boundedControlStream(ctx context.Context, workers *sync.WaitGroup, operation func(context.Context) (carrier.Stream, error)) (carrier.Stream, error) {
	result := make(chan controlStreamResult)
	workers.Go(func() {
		stream, err := operation(ctx)
		select {
		case result <- controlStreamResult{stream: stream, err: err}:
		case <-ctx.Done():
			if stream != nil {
				_ = stream.Reset()
			}
		}
	})
	select {
	case completed := <-result:
		if cause := context.Cause(ctx); cause != nil {
			if completed.stream != nil {
				_ = completed.stream.Reset()
			}
			return nil, cause
		}
		return completed.stream, completed.err
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

func unreliableLoop(
	ctx context.Context,
	source, target carrier.UnreliableTransport,
) {
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
	workers *sync.WaitGroup,
	semaphore chan struct{},
	source, target carrier.Session,
	bufferBytes int,
) {
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
		workers.Go(func() {
			defer func() { <-semaphore }()
			_ = spliceStreamPair(ctx, incoming, outgoing, bufferBytes, 0)
		})
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
		_, err := waitControlCopies(ctx, startControlCopies(left, right, bufferBytes, new(sync.WaitGroup)), halfCloseGrace)
		if err != nil {
			_ = left.Reset()
			_ = right.Reset()
		}
		return err
	}
	reset := sync.OnceFunc(func() {
		_ = left.Reset()
		_ = right.Reset()
	})
	resetDone := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		defer close(resetDone)
		reset()
	})
	defer func() {
		if !stopCancellation() {
			<-resetDone
		}
	}()

	var first sync.Once
	var firstDirection int
	var results [2]error
	copyDirection := func(direction int, destination, source carrier.Stream) {
		err := copyStreamBytes(destination, source, bufferBytes)
		if err == nil {
			err = destination.CloseWrite()
		} else {
			_ = destination.Reset()
		}
		results[direction] = err
		first.Do(func() {
			firstDirection = direction
			if err != nil {
				reset()
			}
		})
	}
	var peer sync.WaitGroup
	peer.Go(func() { copyDirection(0, right, left) })
	copyDirection(1, left, right)
	peer.Wait()
	if results[firstDirection] != nil {
		return errors.Join(results[firstDirection], results[1-firstDirection])
	}
	return results[1-firstDirection]
}

type controlCopyEvent struct {
	direction int
	eof       bool
	err       error
}

// Small control messages need not keep a full bulk buffer while waiting for
// the next read. A busy direction grows once, to the configured copy size.
func copyStreamBytes(dst io.Writer, src io.Reader, bufferBytes int) error {
	if writer, ok := src.(io.WriterTo); ok {
		_, err := writer.WriteTo(dst)
		return err
	}
	if reader, ok := dst.(io.ReaderFrom); ok {
		_, err := reader.ReadFrom(src)
		return err
	}
	buf := make([]byte, min(1024, bufferBytes))
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			written, err := dst.Write(buf[:n])
			if err != nil {
				return err
			}
			if written != n {
				return io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
		if n == len(buf) && len(buf) < bufferBytes {
			buf = make([]byte, bufferBytes)
		}
	}
}

func startControlCopies(left, right carrier.Stream, bufferBytes int, workers *sync.WaitGroup) <-chan controlCopyEvent {
	events := make(chan controlCopyEvent, 4)
	copyDirection := func(direction int, destination, source carrier.Stream) {
		copyErr := copyStreamBytes(destination, source, bufferBytes)
		if copyErr != nil {
			events <- controlCopyEvent{direction: direction, err: copyErr}
			return
		}
		events <- controlCopyEvent{direction: direction, eof: true}
		events <- controlCopyEvent{direction: direction, err: destination.CloseWrite()}
	}
	workers.Go(func() { copyDirection(0, right, left) })
	workers.Go(func() { copyDirection(1, left, right) })
	return events
}

func waitControlCopies(ctx context.Context, events <-chan controlCopyEvent, halfCloseGrace time.Duration) (int, error) {
	done := [2]bool{}
	firstFIN := -1
	var timer *time.Timer
	var timerChannel <-chan time.Time
	for !done[0] || !done[1] {
		select {
		case event := <-events:
			if event.eof {
				if timer == nil {
					firstFIN = event.direction
					timer = time.NewTimer(halfCloseGrace)
					timerChannel = timer.C
				}
				continue
			}
			done[event.direction] = true
			if event.err != nil {
				if timer != nil {
					timer.Stop()
				}
				return firstFIN, event.err
			}
		case <-timerChannel:
			return firstFIN, context.DeadlineExceeded
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return firstFIN, context.Cause(ctx)
		}
	}
	if timer != nil {
		timer.Stop()
	}
	return firstFIN, nil
}

func preferContextCause(ctx context.Context, fallback error) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return fallback
}
