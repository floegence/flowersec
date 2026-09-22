package rpcv4

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// DurableExecutionJoin is one original response obligation. Refresh is provider
// work on an already admitted task; Observe and CopyResult are finite SDK work.
// The join never starts a task or creates dispatch rights from a stored record.
type DurableExecutionJoin struct{ *durableExecutionJoin }
type durableExecutionJoin struct {
	admission                    *DurableExecutionAdmission
	mu                           sync.Mutex
	history                      *DurableExecutions
	work                         *DurableExecutionWork
	target                       ExecutionTarget
	access                       ExecutionAccess
	reservation, authority       resourcev4.Reference
	deadline                     *timev4.Deadline
	payload                      []byte
	observation                  ExecutionObservation
	failure                      error
	busy, ready, closed, cleaned bool
}

func DurableExecutionJoinCharge(limit uint32, runtimeBytes uint64) (resourcev4.Vector, error) {
	if limit > 1048576 || runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	n := uint64(unsafe.Sizeof(DurableExecutionJoin{})) + uint64(unsafe.Sizeof(durableExecutionJoin{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + uint64(limit) + 128
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func (s *DurableExecutions) AdmitJoined(ctx context.Context, routes *ContractRoutes, input *VerifiedInput, caller ExecutionPrincipal, access ExecutionAccess, metadata resourcev4.Reference, runtimeBytes uint64, reserve func(resourcev4.Reference, resourcev4.Reference) error) (ExecutionObservation, *DurableExecutionWork, *DurableExecutionJoin, error) {
	return s.admitJoined(ctx, routes, input, caller, access, metadata, runtimeBytes, reserve, nil)
}

func (s *DurableExecutions) admitJoined(ctx context.Context, routes *ContractRoutes, input *VerifiedInput, caller ExecutionPrincipal, access ExecutionAccess, metadata resourcev4.Reference, runtimeBytes uint64, reserve func(resourcev4.Reference, resourcev4.Reference) error, admission *DurableExecutionAdmission) (observation ExecutionObservation, work *DurableExecutionWork, join *DurableExecutionJoin, err error) {
	if s == nil || s.durableExecutions == nil || input == nil || access == nil {
		return observation, nil, nil, ErrOwner
	}
	input.mu.Lock()
	h, deadline := input.header, input.deadline
	input.mu.Unlock()
	if deadline == nil {
		return observation, nil, nil, ErrOwner
	}
	charge, err := DurableExecutionJoinCharge(h.Fields().ResponseLimitBytes, runtimeBytes)
	if err != nil {
		return observation, nil, nil, err
	}
	owned, err := metadata.Take(charge)
	if err != nil {
		return observation, nil, nil, err
	}
	j := &DurableExecutionJoin{&durableExecutionJoin{reservation: owned, access: access}}
	j.target = ExecutionTarget{Service: s.config.Service, Caller: caller, Operation: h.Fields().OperationID, RequestDigest: h.Fields().RequestDigest, ContractDigest: h.Fields().ServiceContractDigest}
	j.target.Caller.Subject = strings.Clone(caller.Subject)
	j.deadline, err = deadline.Fork(h.Fields().DeadlineAtMS)
	if err == nil {
		err = access.WithExecutionAccess(j.target, func(authority resourcev4.Reference) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.closed {
				return ErrClosed
			}
			if s.joins == math.MaxUint32 {
				return ErrCapacity
			}
			if err := owned.CheckSameEnvironment(s.reservation); err != nil {
				return err
			}
			if err := owned.CheckSameEnvironment(authority); err != nil {
				return err
			}
			var err error
			if admission == nil {
				j.authority, err = authority.Borrow()
			} else {
				if authority != admission.authority {
					return ErrOwner
				}
				j.authority = admission.joinAuthority
				err = j.authority.Check()
				if err == nil {
					j.admission = admission
					admission.tails.Add(1)
				}
			}
			if err != nil {
				return err
			}
			j.history = s
			s.joins++
			return nil
		})
	}
	if err != nil {
		j.Close()
		return observation, nil, nil, err
	}
	j.payload = make([]byte, h.Fields().ResponseLimitBytes)
	observation, work, err = s.admit(ctx, routes, input, caller, access, reserve, admission)
	if err != nil {
		j.Close()
		return observation, work, nil, durableExecutionError(err)
	}
	j.observation = observation
	// Only a still-live original task can lend its ephemeral result. Admission
	// and exit share the finite owner table; no provider operation occurs here.
	s.mu.Lock()
	for _, candidate := range s.works {
		if candidate == nil {
			continue
		}
		candidate.mu.Lock()
		if !candidate.exited && candidate.target == j.target && candidate.resultReaders < math.MaxUint32 {
			candidate.resultReaders++
			j.work = candidate
		}
		candidate.mu.Unlock()
		if j.work != nil {
			break
		}
	}
	s.mu.Unlock()
	return observation, work, j, nil
}

// Refresh completes at most one query and one full, admitted result read. It
// holds no join/Session gate across either call. Closing keeps its backing and
// authority pinned until the actual provider call returns.
func (j *DurableExecutionJoin) Refresh(ctx context.Context) error {
	if j == nil || j.durableExecutionJoin == nil || ctx == nil {
		return ErrOwner
	}
	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		return ErrClosed
	}
	if j.busy {
		j.mu.Unlock()
		return ErrCapacity
	}
	if j.work != nil || j.ready || j.failure != nil {
		j.mu.Unlock()
		return nil
	}
	j.busy = true
	s, target, access, deadline := j.history, j.target, j.access, j.deadline
	j.mu.Unlock()
	var o ExecutionObservation
	ready := false
	err := deadline.Check()
	if err == nil {
		o, err = s.Query(ctx, target, access)
	}
	if err == nil && o.ResultAvailable {
		var n int
		o, n, err = s.ReadResult(ctx, target, access, j.payload)
		ready = err == nil && uint32(n) == o.ResultBytes
	}
	if err == nil {
		err = deadline.Check()
	}
	j.mu.Lock()
	j.busy = false
	if !j.closed {
		j.observation, j.ready = o, ready && err == nil
		// Capacity and uncertain trusted time are retryable only on this owner.
		if err != nil && !errors.Is(err, ledgerv4.ErrCapacity) && !errors.Is(err, ErrCapacity) && !errors.Is(err, timev4.ErrPending) && !errors.Is(err, timev4.ErrUnavailable) {
			j.failure = durableExecutionError(err)
		}
	}
	j.cleanupLocked()
	j.mu.Unlock()
	return durableExecutionError(err)
}

func (j *DurableExecutionJoin) viewLocked() (ExecutionObservation, bool, error) {
	if j.closed {
		return ExecutionObservation{}, false, ErrClosed
	}
	if j.busy {
		return ExecutionObservation{}, false, ErrCapacity
	}
	if err := j.deadline.Check(); err != nil {
		return ExecutionObservation{}, false, err
	}
	if err := j.history.checkAccess(j.target, j.access); err != nil {
		return ExecutionObservation{}, false, err
	}
	o, ready := j.observation, j.ready
	if j.work != nil {
		w := j.work
		w.mu.Lock()
		if w.io {
			w.mu.Unlock()
			return ExecutionObservation{}, false, ErrCapacity
		}
		o, ready = w.final, w.resultCommitted
		w.mu.Unlock()
	}
	if ready && o.ResultNotAfterMS != 0 {
		now, err := j.history.config.Clock.Sample()
		if err != nil {
			return o, false, err
		}
		if !now.ValidBefore(o.ResultNotAfterMS) {
			return o, false, ErrResultExpired
		}
	}
	o.ResultAvailable = ready
	return o, ready, j.failure
}

func (j *DurableExecutionJoin) Observe() (ExecutionObservation, bool, error) {
	if j == nil || j.durableExecutionJoin == nil {
		return ExecutionObservation{}, false, ErrOwner
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.viewLocked()
}

func (j *DurableExecutionJoin) CopyResult(dst []byte, offset uint32) (int, error) {
	if j == nil || j.durableExecutionJoin == nil || len(dst) > 4096 {
		return 0, ErrConfiguration
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	o, ready, err := j.viewLocked()
	if err != nil {
		return 0, err
	}
	if !ready {
		return 0, ErrCapacity
	}
	if offset > o.ResultBytes {
		return 0, ErrResponseLimit
	}
	if j.work == nil {
		return copy(dst, j.payload[offset:o.ResultBytes]), nil
	}
	w := j.work
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.io {
		return 0, ErrCapacity
	}
	return copy(dst, w.output[offset:o.ResultBytes]), nil
}

func (j *DurableExecutionJoin) Close() {
	if j == nil || j.durableExecutionJoin == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.closed = true
	j.cleanupLocked()
}
func (j *DurableExecutionJoin) cleanupLocked() {
	if !j.closed || j.busy || j.cleaned {
		return
	}
	j.cleaned = true
	if w := j.work; w != nil {
		w.mu.Lock()
		w.resultReaders--
		admission := w.releaseResultLocked()
		w.mu.Unlock()
		if admission != nil {
			admission.releaseTail()
		}
	}
	clear(j.payload)
	j.payload = nil
	if j.admission == nil {
		j.authority.Release()
	} else {
		j.admission.releaseTail()
		j.admission = nil
	}
	j.reservation.Release()
	if s := j.history; s != nil {
		s.mu.Lock()
		s.joins--
		s.cleanupLocked()
		s.mu.Unlock()
	}
	j.history, j.work, j.access, j.deadline = nil, nil, nil, nil
	j.target = ExecutionTarget{}
	j.authority, j.reservation = resourcev4.Reference{}, resourcev4.Reference{}
}
func (j *DurableExecutionJoin) CleanupComplete() bool {
	if j == nil || j.durableExecutionJoin == nil {
		return true
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cleaned
}
