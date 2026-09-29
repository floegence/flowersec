package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

const maxSessionExecutionServices = 128

type serviceExecutionFloor struct {
	binding          rpcv4.ServiceBinding
	durableHistory   *rpcv4.DurableExecutions
	durableAdmission *rpcv4.DurableExecutionAdmission
	history          *rpcv4.VolatileExecutions
	admission        *rpcv4.ExecutionAdmission
}

// The enclosing Session batch owns these actual response and history floors
// before acquisition. Dispatch receives the same objects after its original
// metadata primary has moved into place; no history capacity is reacquired.
type serviceExecutionPreparation struct {
	responses     [5]*resourcev4.ProtectedReservation
	floors        []serviceExecutionFloor
	registry      *rpcv4.ServiceRegistry
	responseBytes uint32
	runtimeBytes  uint64
	providerBytes uint64
}

func validateExecutionServices(registry *rpcv4.ServiceRegistry, bindings []rpcv4.ServiceBinding, methods []UnaryRegistration) error {
	if len(bindings) > maxSessionExecutionServices || len(bindings) != 0 && registry == nil {
		return cryptov4.ErrConfiguration
	}
	for index, binding := range bindings {
		current, err := registry.Lookup(binding.Authority)
		if err != nil {
			return err
		}
		if (binding.History == nil) == (binding.DurableHistory == nil) || current.History != binding.History || current.DurableHistory != binding.DurableHistory || current.Recovery != binding.Recovery {
			return cryptov4.ErrConfiguration
		}
		for _, previous := range bindings[:index] {
			if binding.History != nil && previous.History == binding.History || binding.DurableHistory != nil && previous.DurableHistory == binding.DurableHistory || previous.Authority == binding.Authority {
				return cryptov4.ErrConfiguration
			}
		}
		found := false
		for _, method := range methods {
			found = found || method.Namespace == binding.Authority.Namespace && method.WorkClass == ApplicationShort
		}
		if !found {
			return cryptov4.ErrConfiguration
		}
	}
	return nil
}

// All references were admitted by the enclosing Session batch. The history
// vectors retain their service-wide scope; output vectors belong to this exact
// Session. Neither side borrows another service's budget or authority.
func (d *ServiceDispatch) installExecutionFloors(c ServiceDispatchConfig) error {
	if c.executionPreparation != nil {
		if c.ShortExecutionReservations != ([5]resourcev4.Reference{}) || len(c.ShortExecutionAdmissions) != 0 {
			return cryptov4.ErrConfiguration
		}
		return c.executionPreparation.adopt(d, c)
	}
	var preparation serviceExecutionPreparation
	if err := preparation.reserve(c, d.reservation, nil); err != nil {
		return err
	}
	defer preparation.close()
	return preparation.adopt(d, c)
}

func (p *serviceExecutionPreparation) reserve(c ServiceDispatchConfig, authority resourcev4.Reference, original []resourcev4.Reference) (err error) {
	if p.floors != nil {
		return resourcev4.ErrOwner
	}
	if len(c.ExecutionServices) == 0 {
		if len(original) != 0 || len(c.ShortExecutionAdmissions) != 0 || c.ShortExecutionReservations != ([5]resourcev4.Reference{}) {
			return cryptov4.ErrConfiguration
		}
		return nil
	}
	if c.ShortResponseBytes == 0 {
		return cryptov4.ErrConfiguration
	}
	if original == nil {
		if len(c.ShortExecutionAdmissions) != len(c.ExecutionServices) {
			return cryptov4.ErrConfiguration
		}
	} else if len(original) != 5+4*len(c.ExecutionServices) || len(c.ShortExecutionAdmissions) != 0 || c.ShortExecutionReservations != ([5]resourcev4.Reference{}) {
		return cryptov4.ErrConfiguration
	}
	if err := validateExecutionServices(c.ExecutionRegistry, c.ExecutionServices, c.Methods); err != nil {
		return err
	}
	charges, err := executionFloorCallCharges(c.InvocationRuntimeBytes, c.ShortResponseBytes, c.ExecutionServices)
	if err != nil {
		return err
	}
	p.registry, p.responseBytes, p.runtimeBytes, p.providerBytes = c.ExecutionRegistry, c.ShortResponseBytes, c.InvocationRuntimeBytes, c.DurableProviderRuntimeBytes
	defer func() {
		if err != nil {
			p.close()
		}
	}()
	for i := range p.responses {
		ref := c.ShortExecutionReservations[i]
		if original != nil {
			ref = original[i]
		}
		if err := ref.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
			return err
		}
		p.responses[i], err = resourcev4.NewProtectedReservation(ref, charges[i])
		if err != nil {
			return err
		}
	}
	p.floors = make([]serviceExecutionFloor, len(c.ExecutionServices))
	for i, binding := range c.ExecutionServices {
		var refs [4]resourcev4.Reference
		if original != nil {
			copy(refs[:], original[5+4*i:5+4*(i+1)])
		} else {
			refs = c.ShortExecutionAdmissions[i]
		}
		if binding.DurableHistory != nil {
			if c.DurableProviderRuntimeBytes == 0 {
				return cryptov4.ErrConfiguration
			}
			admission, err := binding.DurableHistory.ReserveShortAdmission(c.ShortResponseBytes, c.InvocationRuntimeBytes, authority, refs)
			if err != nil {
				return err
			}
			p.floors[i] = serviceExecutionFloor{binding: binding, durableHistory: binding.DurableHistory, durableAdmission: admission}
			continue
		}
		admission, err := binding.History.ReserveShortAdmission(c.ShortResponseBytes, c.InvocationRuntimeBytes, authority, refs)
		if err != nil {
			return err
		}
		p.floors[i] = serviceExecutionFloor{binding: binding, history: binding.History, admission: admission}
	}
	return nil
}

func (p *serviceExecutionPreparation) checkConfig(c ServiceDispatchConfig) error {
	if len(p.floors) != len(c.ExecutionServices) {
		return resourcev4.ErrOwner
	}
	if len(p.floors) == 0 {
		return nil
	}
	if p.registry != c.ExecutionRegistry || p.responseBytes != c.ShortResponseBytes || p.runtimeBytes != c.InvocationRuntimeBytes || p.providerBytes != c.DurableProviderRuntimeBytes {
		return resourcev4.ErrOwner
	}
	for i, floor := range p.floors {
		if floor.binding != c.ExecutionServices[i] {
			return resourcev4.ErrOwner
		}
	}
	return nil
}

func (p *serviceExecutionPreparation) checkRequests(c ServiceDispatchConfig, requests []resourcev4.Request) error {
	if err := p.checkConfig(c); err != nil {
		return err
	}
	if len(requests) != p.count() {
		return resourcev4.ErrOwner
	}
	if len(p.floors) == 0 {
		return nil
	}
	for i, protected := range p.responses {
		if err := protected.CheckAdmissionRequest(requests[i]); err != nil {
			return err
		}
	}
	for i, floor := range p.floors {
		var original [4]resourcev4.Request
		copy(original[:], requests[5+4*i:5+4*(i+1)])
		var err error
		if floor.durableAdmission != nil {
			err = floor.durableAdmission.CheckOriginalAdmission(floor.durableHistory, p.responseBytes, original)
		} else {
			err = floor.admission.CheckOriginalAdmission(floor.history, p.responseBytes, original)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *serviceExecutionPreparation) count() int {
	if len(p.floors) == 0 {
		return 0
	}
	return 5 + 4*len(p.floors)
}

func (p *serviceExecutionPreparation) adopt(d *ServiceDispatch, c ServiceDispatchConfig) error {
	if err := p.checkConfig(c); err != nil {
		return err
	}
	if len(d.executionFloors) != 0 || d.shortExecution != ([5]*resourcev4.ProtectedReservation{}) {
		return resourcev4.ErrOwner
	}
	if len(p.floors) != 0 {
		for _, protected := range p.responses {
			if err := protected.CheckAvailable(); err != nil {
				return err
			}
		}
	}
	for _, floor := range p.floors {
		var err error
		if floor.durableAdmission != nil {
			err = floor.durableAdmission.AdoptOriginalAuthority(d.reservation)
		} else {
			err = floor.admission.AdoptOriginalAuthority(d.reservation)
		}
		if err != nil {
			return err
		}
	}
	d.shortExecution, d.executionFloors = p.responses, p.floors
	*p = serviceExecutionPreparation{}
	return nil
}

func (p *serviceExecutionPreparation) close() {
	for _, protected := range p.responses {
		protected.CloseAfterUse()
	}
	for _, floor := range p.floors {
		floor.admission.Close()
		floor.durableAdmission.Close()
	}
	*p = serviceExecutionPreparation{}
}

func (d *ServiceDispatch) closeExecutionFloors() {
	for _, protected := range d.shortExecution {
		protected.CloseAfterUse()
	}
	for _, floor := range d.executionFloors {
		floor.admission.Close()
		floor.durableAdmission.Close()
	}
}

// One protected Session response position can service either exact backend.
// Its original vector covers the larger join geometry without summing two jobs.
func executionFloorCallCharges(runtimeBytes uint64, limit uint32, bindings []rpcv4.ServiceBinding) (charges [5]resourcev4.Vector, err error) {
	charges, err = executionCallCharges(runtimeBytes, limit)
	if err != nil {
		return
	}
	for _, binding := range bindings {
		if binding.DurableHistory == nil {
			continue
		}
		join, e := rpcv4.DurableExecutionJoinCharge(limit, runtimeBytes)
		if e != nil {
			return charges, e
		}
		for i := range join {
			charges[4][i] = max(charges[4][i], join[i])
		}
		break
	}
	return
}
