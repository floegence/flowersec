package assemblyv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// These fields extend the factory's original finite method table. They do not
// create another provider pool, worker, queue or ownership coordinator.
type carrierFactorySlot struct {
	active, inUse, admitted, closing bool
	externalPreparation              bool
	serial                           uint64
	cancel                           context.CancelFunc
	floor                            *resourcev4.ProtectedReservation
	providerEnvironment              *native.EnvironmentBorrow
	policy, environment              resourcev4.Reference
	scope                            sessionv4.SessionResourceScope
}

type carrierPreparationOwner interface {
	prepareCarrier(context.Context, sessionv4.CarrierPreparationRequest, *factoryPreparation) (*sessionv4.PreparedCarrier, error)
	checkPreparation(int, uint64) error
	closePreparation(int, uint64)
}

// A copied token keeps its original generation. Factory slot reuse cannot turn
// an earlier token into authority over a later preparation or connection.
type factoryPreparation struct {
	owner  carrierPreparationOwner
	index  int
	serial uint64
}

func (p *factoryPreparation) Matches(factory sessionv4.ConsumerCarrierFactory) bool {
	owner, ok := factory.(carrierPreparationOwner)
	return p != nil && ok && owner == p.owner
}
func (p *factoryPreparation) Check() error {
	if p == nil || p.owner == nil {
		return resourcev4.ErrOwner
	}
	return p.owner.checkPreparation(p.index, p.serial)
}
func (p *factoryPreparation) Close() {
	if p != nil && p.owner != nil {
		p.owner.closePreparation(p.index, p.serial)
	}
}
func (p *factoryPreparation) PrepareCarrier(ctx context.Context, request sessionv4.CarrierPreparationRequest) (*sessionv4.PreparedCarrier, error) {
	if p == nil || p.owner == nil {
		return nil, resourcev4.ErrOwner
	}
	return p.owner.prepareCarrier(ctx, request, p)
}

// Called under the factory's local gate. All operations below are bounded local
// resource operations; there is no clock callback, provider call or native I/O.
func admitFactoryPreparation(factory carrierPreparationOwner, slots []carrierFactorySlot, serial *uint64, root *resourcev4.Root, owner resourcev4.OwnerKey, policy, environment resourcev4.Reference, minimum resourcev4.Vector, request sessionv4.CarrierPreparationAdmissionRequest) (_ *factoryPreparation, err error) {
	if *serial == math.MaxUint64 {
		return nil, resourcev4.ErrCapacity
	}
	if err = request.Environment.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	accounts := [2]resourcev4.Account{request.Scope.Tenant, request.Scope.Session}
	if err = request.Reservation.CheckAllocationScope(root, owner, accounts[:]); err != nil {
		return nil, err
	}
	if err = request.Reservation.CheckSameEnvironment(policy); err != nil {
		return nil, err
	}
	index := -1
	for i := range slots {
		if !slots[i].active {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, resourcev4.ErrCapacity
	}
	charge, err := resourcev4.ProtectedCharge(minimum)
	if err != nil {
		return nil, err
	}
	*serial = *serial + 1
	var seed [48]byte
	copy(seed[:16], owner.Backing[:])
	copy(seed[16:40], "provider-admission-v4")
	binary.BigEndian.PutUint64(seed[40:], *serial)
	digest := sha256.Sum256(seed[:])
	copy(owner.Backing[:], digest[:16])
	ref, err := root.Reserve(owner, charge, accounts[:]...)
	if err != nil {
		return nil, err
	}
	defer ref.Release()
	borrow, err := policy.Borrow()
	if err != nil {
		return nil, err
	}
	providerEnvironment, err := native.NewEnvironmentBorrow(request.Environment)
	if err != nil {
		borrow.Release()
		return nil, err
	}
	floor, err := resourcev4.NewProtectedReservation(ref, minimum)
	if err != nil {
		providerEnvironment.Close()
		borrow.Release()
		return nil, err
	}
	slots[index] = carrierFactorySlot{active: true, admitted: true, serial: *serial, floor: floor, providerEnvironment: providerEnvironment,
		policy: borrow, environment: request.Environment, scope: request.Scope}
	return &factoryPreparation{owner: factory, index: index, serial: *serial}, nil
}

func originalFactorySlot(slots []carrierFactorySlot, index int, serial uint64) (*carrierFactorySlot, error) {
	if index < 0 || index >= len(slots) || !slots[index].active || !slots[index].admitted || slots[index].serial != serial {
		return nil, resourcev4.ErrOwner
	}
	return &slots[index], nil
}

func claimFactorySlot(factory carrierPreparationOwner, slots []carrierFactorySlot, serial *uint64, preparation *factoryPreparation, request sessionv4.CarrierPreparationRequest) (int, uint64, *resourcev4.ProtectedReservation, error) {
	if preparation != nil {
		if preparation.owner != factory {
			return 0, 0, nil, resourcev4.ErrOwner
		}
		slot, err := originalFactorySlot(slots, preparation.index, preparation.serial)
		if err != nil {
			return 0, 0, nil, err
		}
		if slot.closing {
			return 0, 0, nil, resourcev4.ErrClosed
		}
		if slot.environment != request.Config.Environment || slot.scope != request.Scope {
			return 0, 0, nil, resourcev4.ErrOwner
		}
		if slot.inUse {
			return 0, 0, nil, resourcev4.ErrCapacity
		}
		if err = slot.policy.Check(); err != nil {
			return 0, 0, nil, err
		}
		if err = slot.floor.CheckAvailable(); err != nil {
			return 0, 0, nil, err
		}
		if err = slot.providerEnvironment.Check(slot.environment); err != nil {
			return 0, 0, nil, err
		}
		slot.inUse = true
		return preparation.index, preparation.serial, slot.floor, nil
	}
	if *serial == math.MaxUint64 {
		return 0, 0, nil, resourcev4.ErrCapacity
	}
	for i := range slots {
		if !slots[i].active {
			*serial = *serial + 1
			slots[i] = carrierFactorySlot{active: true, inUse: true, serial: *serial}
			return i, *serial, nil, nil
		}
	}
	return 0, 0, nil, resourcev4.ErrCapacity
}

func (s *carrierFactorySlot) release(serial uint64) {
	if !s.active || s.serial != serial {
		return
	}
	s.inUse, s.cancel = false, nil
	if s.admitted && !s.closing {
		if s.externalPreparation {
			s.floor, s.providerEnvironment = nil, nil
		}
		return
	}
	if !s.externalPreparation {
		s.floor.CloseAfterUse()
		s.providerEnvironment.Close()
	}
	s.policy.Release()
	*s = carrierFactorySlot{}
}

func (s *carrierFactorySlot) closeAdmission() {
	if !s.admitted {
		return
	}
	s.closing = true
	if !s.externalPreparation {
		s.floor.CloseAfterUse()
		s.providerEnvironment.Close()
	}
	if !s.inUse {
		s.release(s.serial)
	}
}
