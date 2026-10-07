package interopharness

import (
	"context"
	"time"
)

// The original listener owns the loop and every actual acceptance callback.
// Closing it cancels a blocked recipe and native Accept, seals new dispatch,
// and joins all admitted callbacks before the listener reservation retires.
func (s *Server) startNativeAcceptLoop(reporter *Reporter, accept func(context.Context, *Server, *httpCallbackGate) error, closeNative func()) {
	ctx, cancel := context.WithCancel(s.context)
	callbacks := newHTTPCallbackGate()
	done := make(chan struct{})
	s.acceptReady = make(chan struct{})
	go func() {
		defer close(done)
		initial := true
		for {
			position := s
			if s.nextAccepted != nil {
				var err error
				position, err = s.nextAccepted(ctx, s)
				if err != nil {
					return
				}
			}
			if initial {
				close(s.acceptReady)
				initial = false
			}
			if err := accept(ctx, position, callbacks); err != nil {
				if ctx.Err() != nil {
					position.retireUnused()
					return
				}
				if s.onTransportError != nil {
					s.onTransportError("upgrade", err)
				}
				select {
				case position.results <- SessionResult{Err: err}:
				default:
				}
				position.retireUnused()
			}
			if s.nextAccepted == nil {
				return
			}
		}
	}()
	s.transportJoin = func(ctx context.Context) error {
		cancel()
		callbacks.seal()
		closeNative()
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case <-callbacks.drained:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	reporter.Cleanup(func() {
		timeout, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelWait()
		reporter.ErrorIf(s.transportJoin(timeout))
	})
}

// WaitAcceptReady includes the first native acceptance position in the
// listener's initial resource baseline. HTTP positions remain request-owned.
func (s *Server) WaitAcceptReady(ctx context.Context) error {
	if s.acceptReady == nil {
		return nil
	}
	select {
	case <-s.acceptReady:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
