package rpcv4

import (
	"context"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// ExecutionJoin is one charged original response obligation for a verified
// duplicate or first request. It never acquires a task, dispatches application
// code or makes another network request. Session coordination polls this fixed
// owner without a callback list, waiter task or store query loop.
type ExecutionJoin struct {
	mu                     sync.Mutex
	history                *VolatileExecutions
	admission              *ExecutionAdmission
	index                  int
	generation             uint64
	result                 *executionResult
	target                 ExecutionTarget
	access                 ExecutionAccess
	reservation, authority resourcev4.Reference
	closed                 bool
}

func ExecutionJoinCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ExecutionJoin{})) + 128, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

// AdmitJoined obtains the original response pin, task resources and actual
// executor position before committing a new record. Duplicate lookup attaches
// only this response pin. There is no intervening unpinned result/GC window.
func (s *VolatileExecutions) AdmitJoined(ctx context.Context, routes *ContractRoutes, input *VerifiedInput, caller ExecutionPrincipal, access ExecutionAccess, metadata resourcev4.Reference, runtimeBytes uint64, reserve func(resourcev4.Reference, resourcev4.Reference) error) (observation ExecutionObservation, work *ExecutionWork, join *ExecutionJoin, err error) {
	return s.admitJoined(ctx, routes, input, caller, access, metadata, runtimeBytes, reserve, nil)
}

func (s *VolatileExecutions) admitJoined(ctx context.Context, routes *ContractRoutes, input *VerifiedInput, caller ExecutionPrincipal, access ExecutionAccess, metadata resourcev4.Reference, runtimeBytes uint64, reserve func(resourcev4.Reference, resourcev4.Reference) error, admission *ExecutionAdmission) (observation ExecutionObservation, work *ExecutionWork, join *ExecutionJoin, err error) {
	if reserve == nil {
		return observation, nil, nil, ErrConfiguration
	}
	charge, err := ExecutionJoinCharge(runtimeBytes)
	if err != nil {
		return observation, nil, nil, err
	}
	owned, err := metadata.Take(charge)
	if err != nil {
		return observation, nil, nil, err
	}
	j := &ExecutionJoin{reservation: owned}
	observation, work, err = s.admit(ctx, routes, input, caller, access, reserve, j, admission)
	if err != nil {
		releaseExecutionAuthority(j.authority, j.admission)
		j.reservation.Release()
		return observation, work, nil, err
	}
	return observation, work, j, nil
}
func (j *ExecutionJoin) prepareLocked(s *VolatileExecutions, authority resourcev4.Reference, admission *ExecutionAdmission) error {
	if err := j.reservation.CheckSameEnvironment(s.reservation); err != nil {
		return err
	}
	if err := j.reservation.CheckSameEnvironment(authority); err != nil {
		return err
	}
	var pin resourcev4.Reference
	var err error
	if admission == nil {
		pin, err = authority.Borrow()
	} else {
		pin = admission.joinAuthority
		if admission.reusable {
			j.admission = admission
		} else {
			admission.joinAuthority = resourcev4.Reference{}
		}
		err = pin.Check()
	}
	if err != nil {
		releaseExecutionAuthority(pin, admission)
		return err
	}
	j.authority = pin
	return nil
}
func (j *ExecutionJoin) attachLocked(s *VolatileExecutions, index int, target ExecutionTarget, access ExecutionAccess) {
	r := &s.records[index]
	target.Service = s.service
	target.Caller.Subject = strings.Clone(target.Caller.Subject)
	j.history, j.index, j.generation = s, index, r.generation
	j.target, j.access = target, access
	if j.admission != nil {
		j.admission.tails.Add(1)
	}
	// An ephemeral response is available only to joins admitted before the
	// actual task exit. Later duplicates cannot extend its absent retention.
	if r.result != nil && !(r.result.retentionMS == 0 && r.result.expired) {
		j.result = r.result
		r.result.readers++
	}
	r.joins++
}
func (j *ExecutionJoin) recordLocked() (*executionRecord, error) {
	if j.closed || j.history == nil {
		return nil, ErrClosed
	}
	r := &j.history.records[j.index]
	if !r.used || r.generation != j.generation || r.request != j.target.RequestDigest || r.contract != j.target.ContractDigest {
		return nil, ErrOwner
	}
	return r, nil
}
func (j *ExecutionJoin) readyLocked(r *executionRecord) (bool, error) {
	b := j.result
	if b == nil || r.result != b || !b.formed {
		if r.resultDeleted || r.resultFormed && r.result != nil && r.result.expired {
			return false, ErrResultExpired
		}
		return false, nil
	}
	if b.retentionMS == 0 {
		return true, nil
	}
	now, err := j.history.clock.Sample()
	if err != nil {
		return false, err
	}
	if b.expired || !now.ValidBefore(b.expires) {
		return false, ErrResultExpired
	}
	return true, nil
}
func (j *ExecutionJoin) Observe() (observation ExecutionObservation, ready bool, err error) {
	if j == nil {
		return observation, false, ErrOwner
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return observation, false, ErrClosed
	}
	err = j.access.WithExecutionAccess(j.target, func(resourcev4.Reference) error {
		s := j.history
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return ErrClosed
		}
		r, err := j.recordLocked()
		if err != nil {
			return err
		}
		observation = s.snapshotLocked(r)
		ready, err = j.readyLocked(r)
		return err
	})
	return
}
func (j *ExecutionJoin) CopyResult(dst []byte, offset uint32) (n int, err error) {
	if j == nil || len(dst) > 4096 {
		return 0, ErrConfiguration
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return 0, ErrClosed
	}
	err = j.access.WithExecutionAccess(j.target, func(resourcev4.Reference) error {
		s := j.history
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return ErrClosed
		}
		r, err := j.recordLocked()
		if err != nil {
			return err
		}
		ready, err := j.readyLocked(r)
		if err != nil {
			return err
		}
		if !ready {
			return ErrExecutionUnsupported
		}
		if offset > j.result.length {
			return ErrResponseLimit
		}
		n = copy(dst, j.result.payload[offset:j.result.length])
		return nil
	})
	return
}
func (j *ExecutionJoin) Close() {
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return
	}
	s := j.history
	s.mu.Lock()
	r, err := j.recordLocked()
	if err == nil {
		r.joins--
		if j.result != nil && r.result == j.result {
			j.result.readers--
			s.cleanupResultLocked(r)
		}
		if s.closed && r.work == nil && r.result == nil && r.joins == 0 {
			s.removeLocked(j.index)
		}
	}
	s.cleanupLocked()
	s.mu.Unlock()
	if j.admission != nil {
		j.admission.releaseTail()
		j.admission = nil
	} else {
		j.authority.Release()
	}
	j.reservation.Release()
	j.authority, j.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	j.history, j.result, j.access = nil, nil, nil
	j.target = ExecutionTarget{}
	j.closed = true
}
