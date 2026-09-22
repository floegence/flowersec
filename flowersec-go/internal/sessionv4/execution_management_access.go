package sessionv4

import (
	"context"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

type executionHistoryAccess struct {
	namespace     string
	query, cancel bool
}

func sessionExecutionHistoryCharge(c SessionPlanConfig) (resourcev4.Vector, error) {
	if len(c.ExecutionHistoryNamespaces) > 128 || !c.Services && len(c.ExecutionHistoryNamespaces) != 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	for i, namespace := range c.ExecutionHistoryNamespaces {
		if !executionIdentityText(namespace) {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		for _, previous := range c.ExecutionHistoryNamespaces[:i] {
			if namespace == previous {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
		}
	}
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(len(c.ExecutionHistoryNamespaces)) * (uint64(unsafe.Sizeof(executionHistoryAccess{})) + 128), resourcev4.Items: uint64(len(c.ExecutionHistoryNamespaces))}, nil
}

func (p *SessionPlan) initializeExecutionHistory(namespaces []string) {
	p.config.ExecutionHistoryNamespaces = nil
	p.lease.executionHistory = make([]executionHistoryAccess, len(namespaces))
	for i, namespace := range namespaces {
		p.lease.executionHistory[i].namespace = strings.Clone(namespace)
	}
}

// SetExecutionHistoryAccess is a trusted local grant for the bound caller's
// history in a predeclared namespace. Query and cancellation are independent
// of dispatch/contract-advertisement permissions and default to denied. Old
// exact contracts need not remain eligible for new business admission.
func (l *ApplicationLease) SetExecutionHistoryAccess(namespace string, query, cancel bool) error {
	if l == nil {
		return ErrApplicationAuthorization
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.reserved || l.revoked || l.binding.ApplicationProfile != "execution" {
		return ErrApplicationAuthorization
	}
	for i := range l.executionHistory {
		permission := &l.executionHistory[i]
		if permission.namespace == namespace {
			permission.query, permission.cancel = query, cancel
			return nil
		}
	}
	return ErrApplicationAuthorization
}

// This compact per-request gate belongs to the protected management service
// position. It retains no dispatcher or method callback and grants only one
// exact target/action. Its lifetime ends with the original response position.
type managementHistoryAuthority struct {
	lease    *ApplicationLease
	endpoint *protocolv4.EndpointAuthorization
	backing  resourcev4.Reference
	target   rpcv4.ExecutionTarget
	cancel   bool
}

func (a *managementHistoryAuthority) WithExecutionAccess(target rpcv4.ExecutionTarget, transfer func(resourcev4.Reference) error) error {
	if a == nil || transfer == nil || target != a.target {
		return rpcv4.ErrExecutionUnauthorized
	}
	return a.endpoint.WithCurrentAuthorization(func() error {
		l := a.lease
		l.mu.Lock()
		defer l.mu.Unlock()
		if !l.authorized || l.authorization != a.endpoint {
			return rpcv4.ErrExecutionUnauthorized
		}
		identity, err := l.executionIdentityLocked()
		if err != nil || identity.Tenant != target.Service.Tenant || identity.Audience != target.Service.Audience || identity.Caller != target.Caller {
			return rpcv4.ErrExecutionUnauthorized
		}
		for _, permission := range l.executionHistory {
			if permission.namespace != target.Service.Namespace {
				continue
			}
			if a.cancel && !permission.cancel || !a.cancel && !permission.query {
				return rpcv4.ErrExecutionUnauthorized
			}
			if err := a.backing.Check(); err != nil {
				return err
			}
			return transfer(a.backing)
		}
		return rpcv4.ErrExecutionUnauthorized
	})
}

// ResolveExecutionManagement is the default original-Session adapter. A wire
// target cannot change tenant/audience/caller or choose a new store. This route
// deliberately supplies no original-RAM continuity proof for an absent record.
func (r *RPCServices) ResolveExecutionManagement(ctx context.Context, target rpcv4.ExecutionTarget, cancel bool) (*rpcv4.VolatileExecutions, rpcv4.ExecutionAccess, error) {
	binding, access, err := r.ResolveExecutionManagementBinding(ctx, target, cancel)
	if err == nil && binding.DurableHistory != nil {
		return nil, nil, rpcv4.ErrExecutionUnsupported
	}
	return binding.History, access, err
}

func (r *RPCServices) ResolveExecutionManagementBinding(ctx context.Context, target rpcv4.ExecutionTarget, cancel bool) (rpcv4.ServiceBinding, rpcv4.ExecutionAccess, error) {
	if r == nil || ctx == nil {
		return rpcv4.ServiceBinding{}, nil, rpcv4.ErrOwner
	}
	if err := ctx.Err(); err != nil {
		return rpcv4.ServiceBinding{}, nil, err
	}
	r.mu.Lock()
	if r.closed || r.retired || r.session.Limits().ApplicationProfile != "execution" {
		r.mu.Unlock()
		return rpcv4.ServiceBinding{}, nil, rpcv4.ErrManagementClosed
	}
	plan, registry, backing := r.plan, r.executionRegistry, r.refs[rpcServicesMetadata]
	r.mu.Unlock()
	if plan == nil || registry == nil {
		return rpcv4.ServiceBinding{}, nil, rpcv4.ErrOwner
	}
	lease, endpoint, err := plan.queryAuthorization()
	if err != nil {
		return rpcv4.ServiceBinding{}, nil, err
	}
	access := &managementHistoryAuthority{lease: lease, endpoint: endpoint, backing: backing, target: target, cancel: cancel}
	var binding rpcv4.ServiceBinding
	err = access.WithExecutionAccess(target, func(authority resourcev4.Reference) error {
		if err := registry.CheckSameEnvironment(authority); err != nil {
			return err
		}
		resolved, err := registry.Lookup(rpcv4.ServiceAuthority{Tenant: target.Service.Tenant, Audience: target.Service.Audience, Namespace: target.Service.Namespace})
		if err == nil {
			binding = resolved
		}
		return err
	})
	if err != nil {
		return rpcv4.ServiceBinding{}, nil, err
	}
	return binding, access, nil
}
