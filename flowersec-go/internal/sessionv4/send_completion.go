package sessionv4

import "sync"

// SendStatus is a compact observation of the original sending direction. It
// retains no payload, keys, provider, Stream or Session references. Local
// acceptance, FIN submission and peer authentication are independent facts.
type SendStatus struct {
	AcceptedBytes          uint64
	PeerAuthenticatedBytes uint64
	FINSubmitted           bool
	SendDrained            bool
	FirstError             error
}

type sendCompletion struct {
	mu                       sync.Mutex
	status                   SendStatus
	finDone, drainDone       chan struct{}
	finSettled, drainSettled bool
	finError, drainError     error
}

func newSendCompletion() *sendCompletion {
	return &sendCompletion{finDone: make(chan struct{}), drainDone: make(chan struct{})}
}

func (s *sendCompletion) accepted(offset uint64) {
	s.mu.Lock()
	s.status.AcceptedBytes = max(s.status.AcceptedBytes, offset)
	s.mu.Unlock()
}

func (s *sendCompletion) authenticated(offset uint64) {
	s.mu.Lock()
	s.status.PeerAuthenticatedBytes = max(s.status.PeerAuthenticatedBytes, offset)
	s.mu.Unlock()
}

func (s *sendCompletion) submittedFIN() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.FINSubmitted = true
	if !s.finSettled {
		s.finSettled = true
		close(s.finDone)
	}
}

func (s *sendCompletion) drained(offset uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.PeerAuthenticatedBytes = max(s.status.PeerAuthenticatedBytes, offset)
	s.status.SendDrained = true
	if !s.drainSettled {
		s.drainSettled = true
		close(s.drainDone)
	}
}

func (s *sendCompletion) fail(cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failLocked(cause)
}

// stop is local termination/cleanup, which cannot invent a failure in an
// already drained direction. Real later provider failures still use fail and
// preserve their error without retracting either established wait result.
func (s *sendCompletion) stop(cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.status.SendDrained {
		s.failLocked(cause)
	}
}

func (s *sendCompletion) failLocked(cause error) {
	if cause == nil {
		cause = ErrAbandoned
	}
	if s.status.FirstError == nil {
		s.status.FirstError = cause
	}
	if !s.finSettled {
		s.finSettled, s.finError = true, cause
		close(s.finDone)
	}
	if !s.drainSettled {
		s.drainSettled, s.drainError = true, cause
		close(s.drainDone)
	}
}

func (s *sendCompletion) result(drain bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if drain {
		return s.drainSettled, s.drainError
	}
	return s.finSettled, s.finError
}

func (s *sendCompletion) snapshot() SendStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}
