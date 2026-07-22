package weaknet

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultConnReadBuffer   = 32 * 1024
	defaultPacketReadBuffer = 64 * 1024
	minimumPacketReadBuffer = 64 * 1024
	maxPumpReadBuffer       = 4 * 1024 * 1024
	defaultPumpQueueUnits   = 1024
)

// PumpClock makes scheduler deadlines testable without weakening the real
// net.Conn and net.PacketConn data paths.
type PumpClock interface {
	Now() time.Time
	WaitUntil(context.Context, time.Time) error
}

type PumpOptions struct {
	Clock           PumpClock
	ReadBufferBytes int
	// PacketTargetResolver binds each datagram to a destination before it enters
	// the scheduler, so reordering cannot redirect it to a later peer address.
	PacketTargetResolver func(net.Addr) (net.Addr, error)
	// OnBackpressure runs synchronously when the byte pump first blocks on each
	// full-capacity episode. The callback must not block.
	OnBackpressure func()
}

type realPumpClock struct{}

func (realPumpClock) Now() time.Time { return time.Now() }

func (realPumpClock) WaitUntil(ctx context.Context, deadline time.Time) error {
	wait := time.Until(deadline)
	if wait <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type pumpCore struct {
	source      io.Closer
	destination io.Closer
	started     atomic.Bool
	explicit    atomic.Bool
	closeOnce   sync.Once
	closeErr    error
	cancelMu    sync.Mutex
	cancel      context.CancelFunc
}

func newPumpCore(source, destination io.Closer) *pumpCore {
	return &pumpCore{source: source, destination: destination}
}

func (core *pumpCore) start() error {
	if core.explicit.Load() {
		return ErrPumpClosed
	}
	if !core.started.CompareAndSwap(false, true) {
		return ErrPumpAlreadyRun
	}
	return nil
}

func (core *pumpCore) bindCancel(cancel context.CancelFunc) {
	core.cancelMu.Lock()
	core.cancel = cancel
	closed := core.explicit.Load()
	core.cancelMu.Unlock()
	if closed {
		cancel()
	}
}

func (core *pumpCore) cancelRun() {
	core.cancelMu.Lock()
	cancel := core.cancel
	core.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (core *pumpCore) closeConnections() error {
	core.closeOnce.Do(func() {
		core.closeErr = errors.Join(core.source.Close(), core.destination.Close())
	})
	return core.closeErr
}

func (core *pumpCore) closeExplicitly() error {
	core.explicit.Store(true)
	core.cancelRun()
	return core.closeConnections()
}

func (core *pumpCore) classify(parent context.Context, fallback error) error {
	if err := parent.Err(); err != nil {
		return err
	}
	if core.explicit.Load() {
		return ErrPumpClosed
	}
	return fallback
}

func normalizePumpOptions(options PumpOptions, defaultReadBuffer int) (PumpOptions, error) {
	if options.ReadBufferBytes < 0 || options.ReadBufferBytes > maxPumpReadBuffer {
		return PumpOptions{}, ErrInvalidPump
	}
	if options.ReadBufferBytes == 0 {
		options.ReadBufferBytes = defaultReadBuffer
	}
	if options.Clock == nil {
		options.Clock = realPumpClock{}
	}
	return options, nil
}

func elapsedSince(clock PumpClock, start time.Time) (time.Duration, error) {
	elapsed := clock.Now().Sub(start)
	if elapsed < 0 {
		return 0, ErrInvalidPump
	}
	return elapsed, nil
}

func writeFull(writer io.Writer, payload []byte) (int, error) {
	total := 0
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if written < 0 || written > len(payload) {
			return total, io.ErrShortWrite
		}
		total += written
		payload = payload[written:]
		if err != nil {
			return total, err
		}
		if written == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
