package rpcv4

import (
	"context"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// AdmitExecution selects the original Network's installed routes. The Session
// dispatcher cannot substitute an equal-looking table from another owner.
func (c *ServiceConsumer) AdmitExecution(ctx context.Context, history *VolatileExecutions, input *VerifiedInput, caller ExecutionPrincipal, access ExecutionAccess, metadata resourcev4.Reference, runtimeBytes uint64, reserve func(resourcev4.Reference, resourcev4.Reference) error) (ExecutionObservation, *ExecutionWork, *ExecutionJoin, error) {
	return c.admitExecution(ctx, history, input, caller, access, metadata, runtimeBytes, reserve, nil)
}

func (c *ServiceConsumer) AdmitReservedExecution(ctx context.Context, history *VolatileExecutions, input *VerifiedInput, caller ExecutionPrincipal, access ExecutionAccess, metadata resourcev4.Reference, runtimeBytes uint64, admission *ExecutionAdmission, reserve func(resourcev4.Reference, resourcev4.Reference) error) (ExecutionObservation, *ExecutionWork, *ExecutionJoin, error) {
	if admission == nil {
		return ExecutionObservation{}, nil, nil, ErrOwner
	}
	return c.admitExecution(ctx, history, input, caller, access, metadata, runtimeBytes, reserve, admission)
}

func (c *ServiceConsumer) admitExecution(ctx context.Context, history *VolatileExecutions, input *VerifiedInput, caller ExecutionPrincipal, access ExecutionAccess, metadata resourcev4.Reference, runtimeBytes uint64, reserve func(resourcev4.Reference, resourcev4.Reference) error, admission *ExecutionAdmission) (ExecutionObservation, *ExecutionWork, *ExecutionJoin, error) {
	if history == nil {
		return ExecutionObservation{}, nil, nil, ErrOwner
	}
	routes, err := c.executionRoutes(input)
	if err != nil {
		return ExecutionObservation{}, nil, nil, err
	}
	if admission != nil {
		return history.AdmitReservedJoined(ctx, routes, input, caller, access, metadata, runtimeBytes, admission, reserve)
	}
	return history.AdmitJoined(ctx, routes, input, caller, access, metadata, runtimeBytes, reserve)
}

func (c *ServiceConsumer) executionRoutes(input *VerifiedInput) (*ContractRoutes, error) {
	if c == nil || input == nil {
		return nil, ErrOwner
	}
	n := c.network.Load()
	if n == nil {
		return nil, ErrClosed
	}
	n.mu.Lock()
	if err := n.liveLocked(); err != nil {
		n.mu.Unlock()
		return nil, err
	}
	input.mu.Lock()
	bound := input.ticket.network == n && !input.closed
	input.mu.Unlock()
	if !bound || n.inputs == nil {
		n.mu.Unlock()
		return nil, ErrAssociation
	}
	n.inputs.mu.Lock()
	routes := n.inputs.routes
	closed := n.inputs.closed
	n.inputs.mu.Unlock()
	n.mu.Unlock()
	if closed || routes == nil {
		return nil, ErrClosed
	}
	return routes, nil
}

func (c *ServiceConsumer) AdmitDurableExecution(ctx context.Context, history *DurableExecutions, input *VerifiedInput, caller ExecutionPrincipal, access ExecutionAccess, metadata resourcev4.Reference, runtimeBytes uint64, reserve func(resourcev4.Reference, resourcev4.Reference) error) (ExecutionObservation, *DurableExecutionWork, *DurableExecutionJoin, error) {
	if history == nil {
		return ExecutionObservation{}, nil, nil, ErrOwner
	}
	routes, err := c.executionRoutes(input)
	if err != nil {
		return ExecutionObservation{}, nil, nil, err
	}
	return history.AdmitJoined(ctx, routes, input, caller, access, metadata, runtimeBytes, reserve)
}

func (c *ServiceConsumer) AdmitReservedDurableExecution(ctx context.Context, history *DurableExecutions, input *VerifiedInput, caller ExecutionPrincipal, access ExecutionAccess, metadata resourcev4.Reference, runtimeBytes uint64, admission *DurableExecutionAdmission, reserve func(resourcev4.Reference, resourcev4.Reference) error) (ExecutionObservation, *DurableExecutionWork, *DurableExecutionJoin, error) {
	if history == nil {
		return ExecutionObservation{}, nil, nil, ErrOwner
	}
	routes, err := c.executionRoutes(input)
	if err != nil {
		return ExecutionObservation{}, nil, nil, err
	}
	return history.AdmitReservedJoined(ctx, routes, input, caller, access, metadata, runtimeBytes, admission, reserve)
}
