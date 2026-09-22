package rpcv4

import (
	"context"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// ExecutionAdmission protects one original unary execution opportunity before
// a Session's irreversible admission. It owns real history and active capacity,
// complete work/result backing, the executor's future backing reference and
// both original authorization references. It grants no dispatch permission:
// the ordinary verified-input, current authority, Offer and deadline gates
// still decide whether to create a record. Copies do not create another owner.
type ExecutionAdmission struct {
	mu                           sync.Mutex
	self                         *ExecutionAdmission
	history                      *VolatileExecutions
	metadata, historyPin         resourcev4.Reference
	authority                    resourcev4.Reference
	workAuthority, joinAuthority resourcev4.Reference
	work                         *resourcev4.ProtectedReservation
	task, result                 resourcev4.Reference
	maxResponse                  uint32
	claimed                      atomic.Bool
	tails                        atomic.Uint32
	using                        atomic.Bool
	reusable, closed, cleaned    bool
	floorIndex                   int
	floors                       [3]*resourcev4.ProtectedReservation
	held                         [3]resourcev4.Reference
}

func (*ExecutionAdmission) String() string               { return "Flowersec.ExecutionAdmission" }
func (*ExecutionAdmission) GoString() string             { return "Flowersec.ExecutionAdmission" }
func (*ExecutionAdmission) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// ExecutionAdmissionCharges uses the same work/result geometry as ordinary
// execution. The caller includes these four vectors in its original aggregate
// allocation; no private budget or fresh root is introduced here.
func (s *VolatileExecutions) ExecutionAdmissionCharges(maxResponse uint32, runtimeBytes uint64) (charges [4]resourcev4.Vector, err error) {
	return s.executionAdmissionCharges(maxResponse, runtimeBytes, false)
}

// ShortAdmissionCharges protects the same actual task and retained result
// between uses. It includes no second history, executor, or result budget.
func (s *VolatileExecutions) ShortAdmissionCharges(maxResponse uint32, runtimeBytes uint64) (charges [4]resourcev4.Vector, err error) {
	return s.executionAdmissionCharges(maxResponse, runtimeBytes, true)
}

func (s *VolatileExecutions) executionAdmissionCharges(maxResponse uint32, runtimeBytes uint64, reusable bool) (charges [4]resourcev4.Vector, err error) {
	if s == nil || maxResponse > 1048576 || runtimeBytes == 0 {
		return charges, ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return charges, ErrClosed
	}
	charges[0], err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ExecutionAdmission{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
	if err != nil {
		return
	}
	work, err := s.workChargesLocked(maxResponse, true)
	if err != nil {
		return charges, err
	}
	charges[1], err = resourcev4.ProtectedCharge(work[0])
	charges[2], charges[3] = work[1], work[2]
	if reusable && err == nil {
		charges[2], err = resourcev4.ProtectedCharge(work[1])
		if err == nil {
			charges[3], err = resourcev4.ProtectedCharge(work[2])
		}
	}
	return
}

// ReserveAdmission consumes the original four references only after validating
// every scope. Failed construction unwinds only its own accepted references.
// authority is the exact SDK authority owner later returned by ExecutionAccess.
func (s *VolatileExecutions) ReserveAdmission(maxResponse uint32, runtimeBytes uint64, authority resourcev4.Reference, refs [4]resourcev4.Reference) (*ExecutionAdmission, error) {
	return s.reserveAdmission(maxResponse, runtimeBytes, authority, refs, false)
}

func (s *VolatileExecutions) ReserveShortAdmission(maxResponse uint32, runtimeBytes uint64, authority resourcev4.Reference, refs [4]resourcev4.Reference) (*ExecutionAdmission, error) {
	return s.reserveAdmission(maxResponse, runtimeBytes, authority, refs, true)
}

func (s *VolatileExecutions) reserveAdmission(maxResponse uint32, runtimeBytes uint64, authority resourcev4.Reference, refs [4]resourcev4.Reference, reusable bool) (*ExecutionAdmission, error) {
	charges, err := s.executionAdmissionCharges(maxResponse, runtimeBytes, reusable)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	s.refreshAdmissionFloorsLocked()
	if s.used+s.reserved == uint32(len(s.records)) || s.active+s.reserved == s.maxActive {
		return nil, ErrCapacity
	}
	for i, ref := range refs {
		if err := ref.CheckAllocationScope(s.root, s.owner, s.accounts[:s.accountCount]); err != nil {
			return nil, err
		}
		if err := ref.CheckSameEnvironment(authority); err != nil {
			return nil, err
		}
		if ref == authority || ref == s.reservation {
			return nil, ErrOwner
		}
		for _, previous := range refs[:i] {
			if previous == ref {
				return nil, ErrOwner
			}
		}
	}
	index := -1
	if reusable {
		for i, floor := range s.floors {
			if floor == nil {
				index = i
				break
			}
		}
		if index < 0 {
			return nil, ErrCapacity
		}
	}
	a := &ExecutionAdmission{history: s, authority: authority, maxResponse: maxResponse, reusable: reusable, floorIndex: index}
	a.self = a
	success := false
	var owned [4]resourcev4.Reference
	defer func() {
		if !success {
			for _, ref := range owned {
				ref.Release()
			}
			a.work.CloseAfterUse()
			for _, floor := range a.floors {
				floor.CloseAfterUse()
			}
			a.historyPin.Release()
			a.workAuthority.Release()
			a.joinAuthority.Release()
		}
	}()
	for i, ref := range refs {
		owned[i], err = ref.Take(charges[i])
		if err != nil {
			return nil, err
		}
	}
	a.historyPin, err = s.reservation.Borrow()
	if err != nil {
		return nil, err
	}
	a.workAuthority, err = authority.Borrow()
	if err != nil {
		return nil, err
	}
	a.joinAuthority, err = authority.Borrow()
	if err != nil {
		return nil, err
	}
	borrow, err := owned[1].Borrow()
	if err != nil {
		return nil, err
	}
	work, _ := s.workChargesLocked(maxResponse, true)
	a.work, err = resourcev4.NewProtectedReservation(owned[1], work[0], borrow)
	if err != nil {
		borrow.Release()
		return nil, err
	}
	a.metadata, a.task, a.result = owned[0], owned[2], owned[3]
	if reusable {
		a.floors[0] = a.work
		for i := 1; i < len(a.floors); i++ {
			a.floors[i], err = resourcev4.NewProtectedReservation(owned[i+1], work[i])
			if err != nil {
				return nil, err
			}
		}
		a.task, a.result = resourcev4.Reference{}, resourcev4.Reference{}
		s.floors[index] = a
		s.floorCount++
	}
	a.claimed.Store(true)
	s.reserved++
	success = true
	return a, nil
}

// AdmitReservedJoined uses the original response pin for duplicate lookup.
// One-use admissions release unused capacity after the attempt. Reusable
// short admissions restore their original promise only after actual tails
// return; a failed attempt cannot create a record or dispatch application work.
func (s *VolatileExecutions) AdmitReservedJoined(ctx context.Context, routes *ContractRoutes, input *VerifiedInput, caller ExecutionPrincipal, access ExecutionAccess, metadata resourcev4.Reference, runtimeBytes uint64, admission *ExecutionAdmission, reserve func(resourcev4.Reference, resourcev4.Reference) error) (ExecutionObservation, *ExecutionWork, *ExecutionJoin, error) {
	if admission == nil || admission.self != admission {
		return ExecutionObservation{}, nil, nil, ErrOwner
	}
	admission.mu.Lock()
	defer admission.mu.Unlock()
	if admission.closed || admission.history != s {
		return ExecutionObservation{}, nil, nil, ErrOwner
	}
	if admission.reusable {
		if err := admission.prepareReuseLocked(); err != nil {
			return ExecutionObservation{}, nil, nil, err
		}
		defer admission.finishReuseLocked()
	} else {
		if !admission.claimed.Load() {
			return ExecutionObservation{}, nil, nil, ErrOwner
		}
		defer admission.closeLocked()
	}
	return s.admitJoined(ctx, routes, input, caller, access, metadata, runtimeBytes, reserve, admission)
}

func (a *ExecutionAdmission) takeWorkLocked(s *VolatileExecutions, response uint32) (refs [3]resourcev4.Reference, err error) {
	if a.history != s || !a.claimed.Load() || a.closed || response > a.maxResponse {
		return refs, ErrOwner
	}
	if a.reusable {
		refs, a.held = a.held, [3]resourcev4.Reference{}
		return refs, nil
	}
	refs[0], err = a.work.Checkout()
	if err != nil {
		return refs, err
	}
	refs[1], refs[2] = a.task, a.result
	a.task, a.result = resourcev4.Reference{}, resourcev4.Reference{}
	return refs, nil
}

func (a *ExecutionAdmission) consumeLocked(s *VolatileExecutions) {
	s.reserved--
	a.claimed.Store(false)
}

func (a *ExecutionAdmission) Close() {
	if a == nil || a.self != a {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closeLocked()
}

func (a *ExecutionAdmission) closeLocked() {
	if a.closed {
		return
	}
	s := a.history
	s.mu.Lock()
	if a.claimed.Load() {
		a.consumeLocked(s)
	}
	if a.reusable && a.floorIndex >= 0 && s.floors[a.floorIndex] == a {
		s.floors[a.floorIndex] = nil
		s.floorCount--
	}
	s.cleanupLocked()
	s.mu.Unlock()
	a.closed = true
	a.work.CloseAfterUse()
	for _, floor := range a.floors {
		floor.CloseAfterUse()
	}
	a.cleanupLocked()
}

func (a *ExecutionAdmission) cleanupLocked() {
	if !a.closed || a.cleaned || a.tails.Load() != 0 {
		return
	}
	a.metadata.Release()
	a.historyPin.Release()
	a.workAuthority.Release()
	a.joinAuthority.Release()
	a.task.Release()
	a.result.Release()
	a.history, a.work = nil, nil
	a.floors = [3]*resourcev4.ProtectedReservation{}
	a.metadata, a.historyPin, a.authority = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	a.workAuthority, a.joinAuthority, a.task, a.result = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	a.cleaned = true
}

func (a *ExecutionAdmission) prepareReuseLocked() error {
	if err := a.checkReadyLocked(); err != nil {
		return err
	}
	if err := resourcev4.CheckoutProtectedBatch(a.floors[:], a.held[:]); err != nil {
		return err
	}
	a.using.Store(true)
	return nil
}

// CheckReady is only a local scheduling observation. Actual admission repeats
// the original transfer; neither this observation nor a floor grants authority.
func (a *ExecutionAdmission) CheckReady() error {
	if a == nil || a.self != a {
		return ErrOwner
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.checkReadyLocked()
}

func (a *ExecutionAdmission) checkReadyLocked() error {
	if a.closed || !a.reusable {
		return ErrClosed
	}
	if a.tails.Load() != 0 {
		return ErrCapacity
	}
	s := a.history
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	s.refreshAdmissionFloorsLocked()
	claimed := a.claimed.Load()
	s.mu.Unlock()
	if !claimed {
		return ErrCapacity
	}
	for _, floor := range a.floors {
		if err := floor.CheckAvailable(); err != nil {
			return err
		}
	}
	return nil
}

// AdmissionAccounts captures the history's original shared budget scope for
// an enclosing atomic batch. The caller provides bounded scratch, and adoption
// repeats the exact scope check before creating any history responsibility.
func (s *VolatileExecutions) AdmissionAccounts(root *resourcev4.Root, owner resourcev4.OwnerKey, accounts *[resourcev4.MaxAccountsPerCharge]resourcev4.Account) (int, error) {
	if s == nil || accounts == nil {
		return 0, ErrOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrClosed
	}
	if err := s.reservation.CheckAllocationScope(root, owner, s.accounts[:s.accountCount]); err != nil {
		return 0, err
	}
	*accounts = s.accounts
	return s.accountCount, nil
}

func (a *ExecutionAdmission) finishReuseLocked() {
	for _, ref := range a.held {
		ref.Release()
	}
	a.held = [3]resourcev4.Reference{}
	a.using.Store(false)
	s := a.history
	s.mu.Lock()
	s.refreshAdmissionFloorsLocked()
	s.mu.Unlock()
}

// Work and response tails call this only after releasing the history gate.
// Closing a Session can release its authority pins as soon as those actual
// tails exit; retained history/result bytes do not pin obsolete Session I/O.
func (a *ExecutionAdmission) releaseTail() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tails.Add(^uint32(0))
	a.cleanupLocked()
}

// This original finite table is already charged to the service history.
// Replenishment runs before ordinary admission and after collection, so a
// returned short floor cannot lose its future position to a racing new call.
func (s *VolatileExecutions) refreshAdmissionFloorsLocked() {
	if s.closed || s.floorCount == 0 {
		return
	}
	for range len(s.floors) {
		index := s.floorCursor
		s.floorCursor = (index + 1) % len(s.floors)
		a := s.floors[index]
		if a == nil || a.claimed.Load() || a.using.Load() || a.tails.Load() != 0 {
			continue
		}
		if s.used+s.reserved == uint32(len(s.records)) || s.active+s.reserved == s.maxActive {
			return
		}
		ready := true
		for _, floor := range a.floors {
			ready = ready && floor.CheckAvailable() == nil
		}
		if ready {
			a.claimed.Store(true)
			s.reserved++
		}
	}
}

func releaseExecutionAuthority(ref resourcev4.Reference, admission *ExecutionAdmission) {
	if admission == nil || !admission.reusable {
		ref.Release()
	}
}
