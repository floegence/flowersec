package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

const maxSessionExecutionServices = 128

type serviceExecutionFloor struct {
	durableHistory   *rpcv4.DurableExecutions
	durableAdmission *rpcv4.DurableExecutionAdmission
	history          *rpcv4.VolatileExecutions
	admission        *rpcv4.ExecutionAdmission
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
	if len(c.ExecutionServices) == 0 {
		if len(c.ShortExecutionAdmissions) != 0 || c.ShortExecutionReservations != ([5]resourcev4.Reference{}) {
			return cryptov4.ErrConfiguration
		}
		return nil
	}
	if len(c.ShortExecutionAdmissions) != len(c.ExecutionServices) || c.ShortResponseBytes == 0 {
		return cryptov4.ErrConfiguration
	}
	charges, err := executionFloorCallCharges(c.InvocationRuntimeBytes, c.ShortResponseBytes, c.ExecutionServices)
	if err != nil {
		return err
	}
	for i, ref := range c.ShortExecutionReservations {
		if err := ref.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
			return err
		}
		d.shortExecution[i], err = resourcev4.NewProtectedReservation(ref, charges[i])
		if err != nil {
			return err
		}
	}
	d.executionFloors = make([]serviceExecutionFloor, len(c.ExecutionServices))
	for i, binding := range c.ExecutionServices {
		if binding.DurableHistory != nil {
			if c.DurableProviderRuntimeBytes == 0 {
				return cryptov4.ErrConfiguration
			}
			admission, err := binding.DurableHistory.ReserveShortAdmission(c.ShortResponseBytes, c.InvocationRuntimeBytes, d.reservation, c.ShortExecutionAdmissions[i])
			if err != nil {
				return err
			}
			d.executionFloors[i] = serviceExecutionFloor{durableHistory: binding.DurableHistory, durableAdmission: admission}
			continue
		}
		admission, err := binding.History.ReserveShortAdmission(c.ShortResponseBytes, c.InvocationRuntimeBytes, d.reservation, c.ShortExecutionAdmissions[i])
		if err != nil {
			return err
		}
		d.executionFloors[i] = serviceExecutionFloor{history: binding.History, admission: admission}
	}
	return nil
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
