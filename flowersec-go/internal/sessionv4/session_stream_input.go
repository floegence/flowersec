package sessionv4

import (
	"context"
	"io"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// sessionStreamInput carries the same original provider across READY. Its one
// preadmitted close worker lets cancellation seal I/O promptly even when the
// provider's actual Close blocks. Read, Write and Close retain their original
// buffer/provider responsibilities until their real calls have returned.
type sessionStreamInput struct {
	mu                         sync.Mutex
	provider                   io.ReadWriteCloser
	reservation                resourcev4.Reference
	writeGate                  chan struct{}
	stop, cleanup              chan struct{}
	writeSlots, writers        uint32
	reading, closed, closeDone bool
	cleaned, retired           bool
}

func sessionStreamInputCharge(writeSlots uint32) (resourcev4.Vector, error) {
	if writeSlots == 0 || writeSlots > 130 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	// Writers use their original Initial/record tasks and buffers. Runtime
	// channel/allocator/stack overhead belongs to the complete core allowance.
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(sessionStreamInput{})), resourcev4.Items: 1, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1}, nil
}

func newSessionStreamInput(provider io.ReadWriteCloser, writeSlots uint32, reservation resourcev4.Reference) (*sessionStreamInput, error) {
	charge, err := sessionStreamInputCharge(writeSlots)
	if err != nil || provider == nil {
		return nil, cryptov4.ErrConfiguration
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	s := &sessionStreamInput{provider: provider, reservation: owned, writeSlots: writeSlots,
		writeGate: make(chan struct{}, 1), stop: make(chan struct{}), cleanup: make(chan struct{})}
	s.writeGate <- struct{}{}
	go s.closeProvider()
	return s, nil
}

func (s *sessionStreamInput) closeProvider() {
	<-s.stop
	_ = s.provider.Close()
	s.mu.Lock()
	s.closeDone = true
	s.finishLocked()
	s.mu.Unlock()
}

func (s *sessionStreamInput) finishLocked() {
	if !s.cleaned && s.closeDone && !s.reading && s.writers == 0 {
		s.cleaned = true
		s.provider = nil
		close(s.cleanup)
	}
}

func (s *sessionStreamInput) Read(dst []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	if s.reading {
		s.mu.Unlock()
		return 0, cryptov4.ErrCapacity
	}
	s.reading = true
	provider := s.provider
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.reading = false
		s.finishLocked()
		s.mu.Unlock()
	}()
	return provider.Read(dst)
}

// Every scope holds this same gate for its complete encrypted envelope,
// including short provider writes. Waiting writers retain their original
// charged record positions and wake promptly when this carrier is sealed.
func (s *sessionStreamInput) Write(p []byte) (written int, err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	if s.writers == s.writeSlots {
		s.mu.Unlock()
		return 0, cryptov4.ErrCapacity
	}
	s.writers++
	provider := s.provider
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.writers--
		s.finishLocked()
		s.mu.Unlock()
	}()
	select {
	case <-s.stop:
		return 0, io.ErrClosedPipe
	case <-s.writeGate:
	}
	defer func() { s.writeGate <- struct{}{} }()
	for written < len(p) {
		select {
		case <-s.stop:
			return written, io.ErrClosedPipe
		default:
		}
		n, err := provider.Write(p[written:])
		if n < 0 || n > len(p)-written {
			return written, io.ErrShortWrite
		}
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func (s *sessionStreamInput) InterruptRead() { _ = s.Close() }

// Close requests physical shutdown. WaitCleanup separately joins the actual
// provider result; request completion never claims that the socket has exited.
func (s *sessionStreamInput) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.reservation.Seal()
		close(s.stop)
	}
	return nil
}

func (s *sessionStreamInput) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-s.cleanup:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *sessionStreamInput) Retire() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retired {
		return nil
	}
	if !s.cleaned {
		return cryptov4.ErrCapacity
	}
	s.retired = true
	s.reservation.Release()
	s.reservation = resourcev4.Reference{}
	return nil
}
