package rpcv4

import (
	"context"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// OutputInterest is a read-only observation of one original invocation's
// response path. It has no channel, ticket, execution key or cancellation API.
// A copied view never follows a reused ReplySlot or another execution join.
type OutputInterest struct{ state *outputInterestState }

// OutputObservation is retained by the SDK invocation until actual application
// exit. Ending that invocation closes future waits, without inventing a STOP or
// making the response path uninterested merely because the handler returned.
type OutputObservation struct{ state *outputInterestState }
type outputInterestState struct {
	mu                       sync.Mutex
	reservation              resourcev4.Reference
	invocationDone           <-chan struct{}
	invocationEnded          chan struct{}
	lost                     chan struct{}
	reason                   string
	waiting                  uint32
	attached, ended, cleaned bool
}

type OutputInterestProgress struct {
	Interested bool
	Reason     string
}

func OutputObservationCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	n := uint64(unsafe.Sizeof(outputInterestState{})) + uint64(unsafe.Sizeof(OutputObservation{})) + uint64(unsafe.Sizeof(OutputInterest{}))
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 3}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}
func (n *Network) NewOutputObservation(t Ticket, ctx context.Context, reservation resourcev4.Reference, runtimeBytes uint64) (*OutputObservation, error) {
	if n == nil || ctx == nil {
		return nil, ErrConfiguration
	}
	// Even a nonstandard context cannot execute code under an RPC owner gate.
	done := ctx.Done()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	charge, err := OutputObservationCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	s, err := n.slotLocked(t)
	if err != nil {
		return nil, err
	}
	live := false
	for _, publisher := range n.publishers {
		if publisher != nil && publisher.channel == s.path.Channel && publisher.liveLocked() == nil {
			live = true
			break
		}
	}
	if !live {
		return nil, ErrClosed
	}
	if t.direction != incoming || s.inputState != InputComplete || s.observation != nil || s.message.sdk {
		return nil, ErrOwner
	}
	kind := s.header.Kind()
	if kind != "execution_unary_request" && kind != "transient_unary_request" {
		return nil, ErrMethod
	}
	if err := reservation.CheckSameEnvironment(n.reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	state := &outputInterestState{reservation: owned, invocationDone: done, invocationEnded: make(chan struct{}), lost: make(chan struct{}), attached: true}
	if s.message.stop || s.message.abort {
		state.reason = "response_output_stopped"
		close(state.lost)
	}
	o := &OutputObservation{state: state}
	s.observation = state
	return o, nil
}
func (o *OutputObservation) View() OutputInterest {
	if o == nil {
		return OutputInterest{}
	}
	return OutputInterest{o.state}
}
func (v OutputInterest) Progress() OutputInterestProgress {
	if v.state == nil {
		return OutputInterestProgress{Reason: "owner_unavailable"}
	}
	s := v.state
	s.mu.Lock()
	defer s.mu.Unlock()
	return OutputInterestProgress{s.reason == "", s.reason}
}
func (v OutputInterest) Interested() bool { return v.Progress().Interested }

// WaitLost occupies the one finite invocation waiter position. It creates no
// task or polling timer and does not release the application's execution permit.
// Canceling this wait changes neither output interest nor business execution.
func (v OutputInterest) WaitLost(ctx context.Context) (OutputInterestProgress, error) {
	if v.state == nil || ctx == nil {
		return OutputInterestProgress{}, ErrOwner
	}
	waitDone := ctx.Done()
	if err := ctx.Err(); err != nil {
		return v.Progress(), err
	}
	s := v.state
	s.mu.Lock()
	if s.ended || s.cleaned {
		s.mu.Unlock()
		return v.Progress(), ErrOwner
	}
	select {
	case <-s.invocationDone:
		s.mu.Unlock()
		return v.Progress(), ErrOwner
	default:
	}
	if s.reason != "" {
		result := OutputInterestProgress{Reason: s.reason}
		s.mu.Unlock()
		return result, nil
	}
	if s.waiting != 0 {
		s.mu.Unlock()
		return v.Progress(), ErrCapacity
	}
	if err := s.reservation.Check(); err != nil {
		s.mu.Unlock()
		return v.Progress(), err
	}
	s.waiting++
	lost, ended, invocationDone := s.lost, s.invocationEnded, s.invocationDone
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.waiting--; s.cleanupLocked(); s.mu.Unlock() }()
	select {
	case <-lost:
		return v.Progress(), nil
	case <-ended:
		return v.Progress(), ErrOwner
	case <-invocationDone:
		return v.Progress(), ErrOwner
	case <-waitDone:
		return v.Progress(), ctx.Err()
	}
}
func (s *outputInterestState) lose(reason string, detach bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reason == "" {
		s.reason = reason
		close(s.lost)
	}
	if detach {
		s.attached = false
	}
	s.cleanupLocked()
}
func (o *OutputObservation) EndInvocation() {
	if o == nil || o.state == nil {
		return
	}
	s := o.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ended {
		s.ended = true
		s.invocationDone = nil
		close(s.invocationEnded)
	}
	s.cleanupLocked()
}
func (s *outputInterestState) cleanupLocked() {
	if s.cleaned || s.attached || !s.ended || s.waiting != 0 {
		return
	}
	s.reservation.Release()
	s.reservation = resourcev4.Reference{}
	s.invocationDone = nil
	s.cleaned = true
}
func (o *OutputObservation) CleanupComplete() bool {
	if o == nil || o.state == nil {
		return true
	}
	s := o.state
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleaned
}

func (OutputInterest) String() string                   { return "Flowersec.OutputInterest" }
func (OutputInterest) GoString() string                 { return "Flowersec.OutputInterest" }
func (OutputInterest) MarshalJSON() ([]byte, error)     { return []byte("{}"), nil }
func (*OutputObservation) String() string               { return "Flowersec.OutputObservation" }
func (*OutputObservation) GoString() string             { return "Flowersec.OutputObservation" }
func (*OutputObservation) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
