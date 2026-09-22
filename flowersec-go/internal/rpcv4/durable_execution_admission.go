package rpcv4

import (
	"context"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type DurableExecutionAdmission struct{ *durableExecutionAdmission }
type durableExecutionAdmission struct {
	mu                                                  sync.Mutex
	history                                             *DurableExecutions
	capacity                                            *ledgerv4.SQLiteExecutionCapacity
	authority, workAuthority, joinAuthority, historyPin resourcev4.Reference
	floors                                              [3]*resourcev4.ProtectedReservation
	held                                                [3]resourcev4.Reference
	maxResponse                                         uint32
	index                                               int
	claimed, using, closed                              atomic.Bool
	tails                                               atomic.Uint32
	cleaned                                             bool
}

func (s *DurableExecutions) ShortAdmissionCharges(maxResponse uint32, runtimeBytes uint64) (charges [4]resourcev4.Vector, err error) {
	if s == nil || s.durableExecutions == nil || maxResponse > 1048576 || runtimeBytes == 0 {
		return charges, ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return charges, ErrClosed
	}
	charges[0], err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(DurableExecutionAdmission{})) + uint64(unsafe.Sizeof(durableExecutionAdmission{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
	if err == nil {
		charges[0], err = charges[0].Add(ledgerv4.SQLiteExecutionCapacityCharge())
	}
	if err != nil {
		return
	}
	work, err := s.workCharges(maxResponse)
	if err != nil {
		return charges, err
	}
	for i, v := range work {
		charges[i+1], err = resourcev4.ProtectedCharge(v)
		if err != nil {
			return charges, err
		}
	}
	return
}

func (s *DurableExecutions) AdmissionAccounts(root *resourcev4.Root, owner resourcev4.OwnerKey, accounts *[resourcev4.MaxAccountsPerCharge]resourcev4.Account) (int, error) {
	if s == nil || s.durableExecutions == nil || accounts == nil {
		return 0, ErrOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrClosed
	}
	if err := s.reservation.CheckAllocationScope(root, owner, s.config.Accounts); err != nil {
		return 0, err
	}
	clear(accounts[:])
	copy(accounts[:], s.config.Accounts)
	return len(s.config.Accounts), nil
}

// ReserveShortAdmission uses only finite cached capacity and original resource
// transfers. It performs no provider I/O while Session construction holds gates.
func (s *DurableExecutions) ReserveShortAdmission(maxResponse uint32, runtimeBytes uint64, authority resourcev4.Reference, refs [4]resourcev4.Reference) (*DurableExecutionAdmission, error) {
	charges, err := s.ShortAdmissionCharges(maxResponse, runtimeBytes)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	s.refreshAdmissionFloorsLocked()
	if s.active+s.reserved >= uint32(len(s.works)) {
		return nil, ErrCapacity
	}
	index := -1
	for i, floor := range s.floors {
		if floor == nil {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, ErrCapacity
	}
	for i, ref := range refs {
		if err := ref.CheckAllocationScope(s.config.Root, s.config.Owner, s.config.Accounts); err != nil {
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
	a := &DurableExecutionAdmission{&durableExecutionAdmission{history: s, authority: authority, maxResponse: maxResponse, index: index}}
	var owned [4]resourcev4.Reference
	success := false
	defer func() {
		if !success {
			for _, ref := range owned {
				ref.Release()
			}
			for _, floor := range a.floors {
				floor.CloseAfterUse()
			}
			a.historyPin.Release()
			a.workAuthority.Release()
			a.joinAuthority.Release()
			a.capacity.Close()
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
	work, err := s.workCharges(maxResponse)
	if err != nil {
		return nil, err
	}
	borrow, err := owned[1].Borrow()
	if err != nil {
		return nil, err
	}
	a.floors[0], err = resourcev4.NewProtectedReservation(owned[1], work[0], borrow)
	if err != nil {
		borrow.Release()
		return nil, err
	}
	for i := 1; i < 3; i++ {
		a.floors[i], err = resourcev4.NewProtectedReservation(owned[i+1], work[i])
		if err != nil {
			return nil, err
		}
	}
	a.capacity, err = s.config.Store.ReserveCapacity(owned[0])
	if err != nil {
		return nil, err
	}
	a.claimed.Store(true)
	s.reserved++
	s.floors[index] = a
	s.floorCount++
	success = true
	return a, nil
}

func (s *DurableExecutions) workCharges(response uint32) (charges [3]resourcev4.Vector, err error) {
	charges[0], err = durableExecutionWorkCharge(response, s.config.WorkRuntimeBytes)
	if err != nil {
		return
	}
	charges[1] = s.config.TaskCharge
	charges[2], err = s.config.Store.WorkCharge()
	return
}

func (a *DurableExecutionAdmission) CheckReady() error {
	if a == nil || a.durableExecutionAdmission == nil {
		return ErrOwner
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.checkReadyLocked()
}
func (a *DurableExecutionAdmission) checkReadyLocked() error {
	if a.closed.Load() {
		return ErrClosed
	}
	if a.using.Load() || a.tails.Load() != 0 {
		return ErrCapacity
	}
	s := a.history
	s.mu.Lock()
	s.refreshAdmissionFloorsLocked()
	live := !s.closed && a.claimed.Load()
	s.mu.Unlock()
	if !live {
		return ErrCapacity
	}
	for _, floor := range a.floors {
		if err := floor.CheckAvailable(); err != nil {
			return err
		}
	}
	return nil
}
func (s *DurableExecutions) refreshAdmissionFloorsLocked() {
	if s.closed || s.floorCount == 0 {
		return
	}
	for range len(s.floors) {
		i := s.floorCursor
		s.floorCursor = (i + 1) % len(s.floors)
		a := s.floors[i]
		if a == nil || a.closed.Load() || a.claimed.Load() || a.using.Load() || a.tails.Load() != 0 {
			continue
		}
		if s.active+s.reserved >= uint32(len(s.works)) {
			return
		}
		ready := true
		for _, floor := range a.floors {
			ready = ready && floor.CheckAvailable() == nil
		}
		if ready && a.capacity.CheckReady() == nil {
			a.claimed.Store(true)
			s.reserved++
		}
	}
}
func (a *DurableExecutionAdmission) begin(s *DurableExecutions) error {
	if a == nil || a.durableExecutionAdmission == nil {
		return ErrOwner
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.history != s {
		return ErrOwner
	}
	if err := a.checkReadyLocked(); err != nil {
		return err
	}
	if err := resourcev4.CheckoutProtectedBatch(a.floors[:], a.held[:]); err != nil {
		return err
	}
	a.using.Store(true)
	return nil
}
func (a *DurableExecutionAdmission) finish() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, ref := range a.held {
		ref.Release()
	}
	a.held = [3]resourcev4.Reference{}
	a.using.Store(false)
	if a.closed.Load() {
		a.cleanupLocked()
		return
	}
	s := a.history
	s.mu.Lock()
	s.refreshAdmissionFloorsLocked()
	s.mu.Unlock()
}

// The original admission attempt exclusively owns held while using is true.
// Close only marks closure during that interval; no gate spans provider I/O.
func (a *DurableExecutionAdmission) takeWork(s *DurableExecutions, response uint32, authority resourcev4.Reference) (refs [3]resourcev4.Reference, err error) {
	if a.history != s || !a.using.Load() || a.closed.Load() || !a.claimed.Load() || response > a.maxResponse || authority != a.authority {
		return refs, ErrOwner
	}
	refs, a.held = a.held, [3]resourcev4.Reference{}
	return refs, nil
}
func (a *DurableExecutionAdmission) consumeLocked(s *DurableExecutions) {
	a.claimed.Store(false)
	s.reserved--
}

func (s *DurableExecutions) AdmitReservedJoined(ctx context.Context, routes *ContractRoutes, input *VerifiedInput, caller ExecutionPrincipal, access ExecutionAccess, metadata resourcev4.Reference, runtimeBytes uint64, admission *DurableExecutionAdmission, reserve func(resourcev4.Reference, resourcev4.Reference) error) (ExecutionObservation, *DurableExecutionWork, *DurableExecutionJoin, error) {
	if err := admission.begin(s); err != nil {
		return ExecutionObservation{}, nil, nil, err
	}
	defer admission.finish()
	return s.admitJoined(ctx, routes, input, caller, access, metadata, runtimeBytes, reserve, admission)
}

func (a *DurableExecutionAdmission) Close() {
	if a == nil || a.durableExecutionAdmission == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed.Swap(true) {
		return
	}
	s := a.history
	s.mu.Lock()
	if a.claimed.Swap(false) {
		s.reserved--
	}
	if s.floors[a.index] == a {
		s.floors[a.index] = nil
		s.floorCount--
	}
	s.cleanupLocked()
	s.mu.Unlock()
	a.cleanupLocked()
}
func (a *DurableExecutionAdmission) cleanupLocked() {
	if !a.closed.Load() || a.cleaned || a.using.Load() {
		return
	}
	for _, floor := range a.floors {
		floor.CloseAfterUse()
	}
	if a.tails.Load() != 0 {
		return
	}
	a.cleaned = true
	a.workAuthority.Release()
	a.joinAuthority.Release()
	a.historyPin.Release()
	a.capacity.Close()
	a.history = nil
	a.floors = [3]*resourcev4.ProtectedReservation{}
	a.authority, a.workAuthority, a.joinAuthority, a.historyPin = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
}
func (a *DurableExecutionAdmission) releaseTail() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tails.Add(^uint32(0))
	a.cleanupLocked()
}
