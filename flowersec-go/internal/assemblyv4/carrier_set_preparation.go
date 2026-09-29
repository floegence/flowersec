package assemblyv4

import (
	"bytes"
	"context"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// One source reserves a real method position in every eligible route factory.
// Its at most two concurrent attempts share the componentwise maximum provider geometry;
// unused routes retain policy/metadata only, never another socket/TLS allowance.
// All transitions use the set gate followed by the relevant child factory gate.
type carrierSetPreparation struct {
	active   bool
	count    uint8
	lanes    [2]carrierFactorySlot
	running  [2]bool
	selected [2]int
	routes   [16]factoryPreparation
}

func (s *CarrierSet) PreparationParallelism() uint8 {
	if s == nil {
		return 0
	}
	return s.parallel
}

func (s *CarrierSet) AdmitPreparations(request sessionv4.CarrierPreparationAdmissionRequest, output []sessionv4.CarrierPreparation) (err error) {
	if s == nil || len(output) == 0 || len(output) > int(s.parallel) {
		return resourcev4.ErrConfiguration
	}
	for _, preparation := range output {
		if preparation != nil {
			return resourcev4.ErrOwner
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return resourcev4.ErrClosed
	}
	if request.Clock != s.clock {
		return resourcev4.ErrOwner
	}
	s.cleanupPreparationsLocked()
	index := -1
	for i := range s.preparations {
		if !s.preparations[i].active {
			index = i
			break
		}
	}
	if index < 0 {
		return resourcev4.ErrCapacity
	}
	p := &s.preparations[index]
	*p = carrierSetPreparation{active: true, count: uint8(len(output)), selected: [2]int{-1, -1}}
	defer func() {
		if err != nil {
			s.closePreparationGroupLocked(p)
			s.cleanupPreparationsLocked()
		}
	}()
	for lane := range output {
		preparation, admissionErr := admitFactoryPreparation(s, p.lanes[:p.count], &s.serial, s.root, s.owner,
			s.reservation, s.environment, s.providerCharge, request)
		if admissionErr != nil {
			return admissionErr
		}
		preparation.index = index*2 + lane
		output[lane] = preparation
	}
	// Every route has its own original policy and method slot. These are
	// alternatives within this source, so each is reserved once, not per lane.
	for route, factory := range s.factories {
		p.routes[route], err = factory.admitSetRoute(request)
		if err != nil {
			return err
		}
	}
	return nil
}

func (factory carrierSetFactory) admitSetRoute(request sessionv4.CarrierPreparationAdmissionRequest) (factoryPreparation, error) {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if *factory.closed {
		return factoryPreparation{}, resourcev4.ErrClosed
	}
	if *factory.serial == math.MaxUint64 {
		return factoryPreparation{}, resourcev4.ErrCapacity
	}
	if request.Clock != factory.clock || request.Environment != factory.environment {
		return factoryPreparation{}, resourcev4.ErrOwner
	}
	for i := range *factory.slots {
		if (*factory.slots)[i].active {
			continue
		}
		policy, err := factory.reservation.Borrow()
		if err != nil {
			return factoryPreparation{}, err
		}
		*factory.serial++
		(*factory.slots)[i] = carrierFactorySlot{active: true, admitted: true, externalPreparation: true,
			serial: *factory.serial, policy: policy, environment: request.Environment, scope: request.Scope}
		return factoryPreparation{owner: factory.owner, index: i, serial: *factory.serial}, nil
	}
	return factoryPreparation{}, resourcev4.ErrCapacity
}

func (s *CarrierSet) preparationLocked(index int, serial uint64) (*carrierSetPreparation, int, error) {
	if index < 0 || index/2 >= len(s.preparations) {
		return nil, 0, resourcev4.ErrOwner
	}
	p, lane := &s.preparations[index/2], index%2
	if !p.active || lane >= int(p.count) {
		return nil, 0, resourcev4.ErrOwner
	}
	if _, err := originalFactorySlot(p.lanes[:p.count], lane, serial); err != nil {
		return nil, 0, err
	}
	return p, lane, nil
}

func (s *CarrierSet) checkPreparation(index int, serial uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return resourcev4.ErrClosed
	}
	s.cleanupPreparationsLocked()
	p, lane, err := s.preparationLocked(index, serial)
	if err != nil {
		return err
	}
	position := &p.lanes[lane]
	if position.closing {
		return resourcev4.ErrClosed
	}
	if position.inUse {
		return resourcev4.ErrCapacity
	}
	if err = position.policy.Check(); err != nil {
		return err
	}
	if err = position.providerEnvironment.Check(position.environment); err != nil {
		return err
	}
	if err = position.floor.CheckAvailable(); err != nil {
		return err
	}
	for route, factory := range s.factories {
		factory.mu.Lock()
		entry := p.routes[route]
		original, checkErr := originalFactorySlot((*factory.slots), entry.index, entry.serial)
		if checkErr == nil {
			if *factory.closed || original.closing {
				checkErr = resourcev4.ErrClosed
			} else {
				checkErr = original.policy.Check()
			}
		}
		factory.mu.Unlock()
		if checkErr != nil {
			return checkErr
		}
	}
	return nil
}

func (s *CarrierSet) prepareCarrier(ctx context.Context, request sessionv4.CarrierPreparationRequest, preparation *factoryPreparation) (*sessionv4.PreparedCarrier, error) {
	if s == nil || ctx == nil || preparation == nil || preparation.owner != s {
		return nil, resourcev4.ErrOwner
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, resourcev4.ErrClosed
	}
	s.cleanupPreparationsLocked()
	p, lane, err := s.preparationLocked(preparation.index, preparation.serial)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	local := *preparation
	local.index = lane
	_, _, _, err = claimFactorySlot(s, p.lanes[:p.count], &s.serial, &local, request)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	selected := -1
	for route, factory := range s.factories {
		factory.mu.Lock()
		matches := !*factory.closed && *factory.document != nil && bytes.Equal(request.Route, (*factory.document).Bytes())
		if matches {
			entry := p.routes[route]
			position, slotErr := originalFactorySlot((*factory.slots), entry.index, entry.serial)
			if slotErr != nil {
				err = slotErr
			} else if position.closing {
				err = resourcev4.ErrClosed
			} else if position.inUse {
				err = resourcev4.ErrCapacity
			} else {
				// The first call may still be validating before it claims the
				// child. That interval already belongs to its original lane.
				for other := range p.count {
					if int(other) != lane && p.lanes[other].inUse && p.selected[other] == route {
						err = resourcev4.ErrCapacity
					}
				}
				if err == nil {
					position.floor, position.providerEnvironment = p.lanes[lane].floor, p.lanes[lane].providerEnvironment
					selected = route
				}
			}
		}
		factory.mu.Unlock()
		if matches {
			break
		}
	}
	if selected < 0 {
		p.lanes[lane].release(local.serial)
		s.mu.Unlock()
		if err == nil {
			err = protocolv4.CBORFailure("carrier_binding_invalid")
		}
		return nil, err
	}
	p.selected[lane], p.running[lane] = selected, true
	s.calls++
	factory, token := s.factories[selected], p.routes[selected]
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		p.running[lane] = false
		s.calls--
		s.cleanupPreparationsLocked()
		s.mu.Unlock()
		s.signal()
	}()
	return factory.prepareCarrier(ctx, request, &token)
}

func (s *CarrierSet) closePreparation(index int, serial uint64) {
	s.mu.Lock()
	if p, lane, err := s.preparationLocked(index, serial); err == nil {
		p.lanes[lane].closeAdmission()
		closed := true
		for i := range p.count {
			closed = closed && (!p.lanes[i].active || p.lanes[i].closing)
		}
		if closed {
			s.closePreparationGroupLocked(p)
		}
	}
	s.cleanupPreparationsLocked()
	s.mu.Unlock()
	s.signal()
}

func (s *CarrierSet) closePreparationGroupLocked(p *carrierSetPreparation) {
	for lane := range p.count {
		p.lanes[lane].closeAdmission()
	}
	for route, factory := range s.factories {
		if factory.owner == nil || p.routes[route].owner == nil {
			continue
		}
		entry := p.routes[route]
		factory.mu.Lock()
		if slot, err := originalFactorySlot((*factory.slots), entry.index, entry.serial); err == nil {
			slot.closeAdmission()
		}
		factory.cleanupLocked()
		factory.mu.Unlock()
	}
}

func (s *CarrierSet) cleanupPreparationsLocked() {
	for i := range s.preparations {
		p := &s.preparations[i]
		if !p.active {
			continue
		}
		active := false
		for lane := range p.count {
			position := &p.lanes[lane]
			if position.inUse && !p.running[lane] && p.selected[lane] >= 0 {
				route := p.selected[lane]
				factory, entry := s.factories[route], p.routes[route]
				factory.mu.Lock()
				slot, err := originalFactorySlot((*factory.slots), entry.index, entry.serial)
				returned := err != nil || !slot.inUse
				if err == nil && returned {
					slot.floor, slot.providerEnvironment = nil, nil
				}
				factory.mu.Unlock()
				if returned {
					position.release(position.serial)
					p.selected[lane] = -1
				}
			}
			active = active || position.active || p.running[lane]
		}
		if !active {
			*p = carrierSetPreparation{}
		}
	}
}

func (s *CarrierSet) signal() {
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// Child retirement enters the set only after dropping its own gate. This
// returns the original lane immediately without a cleanup worker or timer.
func (s *CarrierSet) providerReturned() {
	s.mu.Lock()
	s.cleanupPreparationsLocked()
	s.mu.Unlock()
	s.signal()
}

var _ sessionv4.AdmittingConsumerCarrierFactory = (*CarrierSet)(nil)
