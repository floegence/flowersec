package sessionv4

import (
	"strings"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

// ExecutionSessionIdentity is the trusted application's mapping of the exact
// authenticated Session binding to its stable caller and service authority.
// It is installed by AuthorizeApplication, never decoded from request fields.
type ExecutionSessionIdentity struct {
	Tenant, Audience string
	Caller           rpcv4.ExecutionPrincipal
}
type executionSessionIdentity struct {
	text      [3][128]byte
	lengths   [3]uint8
	authority [32]byte
	bound     bool
}

func executionIdentityText(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for i, c := range []byte(value) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		if i == 0 || !strings.ContainsRune("._:/@-", rune(c)) {
			return false
		}
	}
	return true
}
func (l *ApplicationLease) BindExecutionIdentity(binding ApplicationBinding, identity ExecutionSessionIdentity) error {
	if l == nil || identity.Caller.Authority == ([32]byte{}) {
		return ErrApplicationAuthorization
	}
	values := [3]string{identity.Tenant, identity.Audience, identity.Caller.Subject}
	for _, s := range values {
		if !executionIdentityText(s) {
			return cryptov4.ErrConfiguration
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.reserved || l.revoked || l.binding != binding || binding.ApplicationProfile != "execution" {
		return ErrApplicationAuthorization
	}
	if l.execution.bound {
		return cryptov4.ErrTransition
	}
	for i, s := range values {
		l.execution.lengths[i] = uint8(copy(l.execution.text[i][:], s))
	}
	l.execution.authority, l.execution.bound = identity.Caller.Authority, true
	return nil
}
func (l *ApplicationLease) executionIdentityLocked() (ExecutionSessionIdentity, error) {
	if !l.execution.bound || l.revoked {
		return ExecutionSessionIdentity{}, ErrApplicationAuthorization
	}
	e := &l.execution
	return ExecutionSessionIdentity{Tenant: string(e.text[0][:e.lengths[0]]), Audience: string(e.text[1][:e.lengths[1]]), Caller: rpcv4.ExecutionPrincipal{Authority: e.authority, Subject: string(e.text[2][:e.lengths[2]])}}, nil
}

type serviceExecutionAccess struct {
	dispatcher *ServiceDispatch
	method     uint32
	service    rpcv4.ExecutionService
	caller     rpcv4.ExecutionPrincipal
}

func (a *serviceExecutionAccess) WithExecutionAccess(target rpcv4.ExecutionTarget, action func(resourcev4.Reference) error) error {
	if a == nil || action == nil || target.Service != a.service || target.Caller != a.caller {
		return ErrApplicationAuthorization
	}
	d := a.dispatcher
	if d == nil {
		return ErrApplicationAuthorization
	}
	d.mu.Lock()
	plan := d.plan
	d.mu.Unlock()
	if plan == nil {
		return ErrApplicationAuthorization
	}
	l, authorization, err := plan.queryAuthorization()
	if err != nil {
		return err
	}
	return authorization.WithCurrentAuthorization(func() error {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.revoked || l.authorization != authorization {
			return ErrApplicationAuthorization
		}
		identity, err := l.executionIdentityLocked()
		if err != nil || identity.Tenant != a.service.Tenant || identity.Audience != a.service.Audience || identity.Caller != a.caller {
			return ErrApplicationAuthorization
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if !d.activated || d.closed {
			return ErrApplicationAuthorization
		}
		for _, m := range d.methods {
			if m.registration.Method == a.method && m.allowed {
				return action(d.reservation)
			}
		}
		for _, m := range d.streamMethods {
			if m.registration.Method == a.method && m.allowed {
				return action(d.reservation)
			}
		}
		return ErrApplicationAuthorization
	})
}

func (d *ServiceDispatch) executionAuthority(method uint32, namespace string) (*rpcv4.VolatileExecutions, *serviceExecutionAccess, error) {
	binding, access, err := d.executionBindingAuthority(method, namespace)
	if err == nil && binding.DurableHistory != nil {
		return nil, nil, rpcv4.ErrExecutionUnsupported
	}
	return binding.History, access, err
}

func (d *ServiceDispatch) executionBindingAuthority(method uint32, namespace string) (rpcv4.ServiceBinding, *serviceExecutionAccess, error) {
	if d.executionRegistry == nil {
		return rpcv4.ServiceBinding{}, nil, rpcv4.ErrExecutionUnsupported
	}
	l, _, err := d.plan.queryAuthorization()
	if err != nil {
		return rpcv4.ServiceBinding{}, nil, err
	}
	l.mu.Lock()
	identity, err := l.executionIdentityLocked()
	l.mu.Unlock()
	if err != nil {
		return rpcv4.ServiceBinding{}, nil, err
	}
	service := rpcv4.ExecutionService{Tenant: identity.Tenant, Audience: identity.Audience, Namespace: namespace}
	binding, err := d.executionRegistry.Lookup(rpcv4.ServiceAuthority{Tenant: service.Tenant, Audience: service.Audience, Namespace: service.Namespace})
	if err != nil {
		return rpcv4.ServiceBinding{}, nil, err
	}
	return binding, &serviceExecutionAccess{dispatcher: d, method: method, service: service, caller: identity.Caller}, nil
}
