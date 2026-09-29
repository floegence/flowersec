package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// VerificationNamespace resolves only an independently configured original
// anchor. It neither starts bootstrap nor derives trust from a caller's name.
func (e *Environment) VerificationNamespace(tenant, authority string) (*protocolv4.NamespaceTrustStore, error) {
	if e == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, cryptov4.ErrClosed
	}
	if e.verification == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if err := e.reservation.CheckSameEnvironment(e.verificationBorrow); err != nil {
		return nil, err
	}
	return e.verification.Lookup(tenant, authority)
}

func (e *Environment) checkMaterialVerification(m *ConnectionMaterial) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return cryptov4.ErrClosed
	}
	if e.verification == nil {
		return nil
	}
	if m == nil {
		return cryptov4.ErrConfiguration
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.cleaned || m.lease.lease == nil || m.identity.identity == nil {
		return cryptov4.ErrClosed
	}
	// The original material captures these immutable validation dependencies;
	// its lease/identity uses pin them through physical material cleanup.
	for _, binding := range m.lease.lease.allCredentialBindings() {
		if err := e.verification.CheckNamespace(binding.Namespace); err != nil {
			return err
		}
	}
	return e.verification.CheckNamespace(m.identity.identity.validation.Namespace)
}
