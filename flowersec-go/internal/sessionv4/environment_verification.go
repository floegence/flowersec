package sessionv4

import (
	"context"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"sync"
)

// Each preparation owns one finite original Environment position. Shared
// registry/factory ownership remains external; Close cancels only these calls.
type environmentVerificationPreparation struct {
	claimed      bool
	cancellation *environmentVerificationCancellation
	pin          resourcev4.Reference
}

// The first cancellation caller owns the complete host cancel/AfterFunc stop.
// Concurrent callers join its real return rather than observing only Done.
// This object remains stable even after the fixed preparation slot is cleared.
type environmentVerificationCancellation struct {
	once   sync.Once
	cancel context.CancelFunc
}

func (c *environmentVerificationCancellation) join() {
	if c != nil {
		c.once.Do(c.cancel)
	}
}

// VerificationNamespace uses the original configured reference composition.
// Missing history requires a full independent bootstrap; no caller-selected
// endpoint or cached Head can establish a new namespace owner.
func (e *Environment) VerificationNamespace(tenant, authority string) (*protocolv4.NamespaceTrustStore, error) {
	return e.VerificationNamespaceContext(context.Background(), tenant, authority)
}
func (e *Environment) VerificationNamespaceContext(ctx context.Context, tenant, authority string) (*protocolv4.NamespaceTrustStore, error) {
	if e == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	if e.verification == nil {
		e.mu.Unlock()
		return nil, cryptov4.ErrConfiguration
	}
	if err := e.reservation.CheckSameEnvironment(e.verificationBorrow); err != nil {
		e.mu.Unlock()
		return nil, err
	}
	index := -1
	for i := range e.verificationPreparations {
		if !e.verificationPreparations[i].claimed {
			index = i
			break
		}
	}
	if index < 0 {
		e.mu.Unlock()
		return nil, cryptov4.ErrCapacity
	}
	// Only the original primary owner creates a legal task pin. This pin and
	// position remain until context setup, provider and cancellation really exit.
	pin, err := e.verification.Borrow(e.reservation)
	if err != nil {
		e.mu.Unlock()
		return nil, err
	}
	preparation := &e.verificationPreparations[index]
	*preparation = environmentVerificationPreparation{claimed: true, pin: pin}
	registry, pressure := e.verification, e.namespaceRetirement
	e.verificationActive++
	e.mu.Unlock()
	var cancellation *environmentVerificationCancellation
	defer func() {
		cancellation.join()
		pin.Release()
		e.mu.Lock()
		*preparation = environmentVerificationPreparation{}
		e.verificationActive--
		e.completeLocked()
		e.mu.Unlock()
	}()
	// Host context methods run outside all owner gates. Close may win setup,
	// in which case this exact call is canceled before any provider dispatch.
	operation, cancel := context.WithCancel(ctx)
	cancellation = &environmentVerificationCancellation{cancel: cancel}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	preparation.cancellation = cancellation
	e.mu.Unlock()
	owner, err := registry.Resolve(operation, tenant, authority)
	if err != nil {
		if pressure != nil {
			pressure.RequestPressure()
		}
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, cryptov4.ErrClosed
	}
	if err = e.reservation.CheckSameEnvironment(pin); err != nil {
		return nil, err
	}
	return owner, nil
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
