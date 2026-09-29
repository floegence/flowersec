package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// MaterialNamespaceProvider captures the fixed, independently installed trust
// owners for Artifact, client identity and server identity. This local SDK
// inspection cannot issue credentials, sample time or invoke application work.
type MaterialNamespaceProvider interface {
	MaterialLeaseProvider
	PreparationNamespaces(*timev4.Clock, resourcev4.Reference) ([3]*protocolv4.LiveNamespace, error)
}

// MaterialNamespaceSet contains all independent trust owners needed by a
// source's finite candidate set. The first three positions are Artifact,
// client identity and server identity; remaining positions cover the local
// role's grants and relay identities. Repeated owners are allowed. Count zero
// declares a component source without a complete pre-acquisition promise;
// actual material must still qualify every missing owner before preparation.
type MaterialNamespaceSet struct {
	Owners [protocolv4.MaxSourceCredentials]*protocolv4.LiveNamespace
	Count  uint8
}

// MaterialNamespaceSetProvider is the bounded pre-acquisition inspection for
// sources containing tunnel candidates. It must perform no credential issue,
// time sampling, application callback, or network request.
type MaterialNamespaceSetProvider interface {
	MaterialLeaseProvider
	PreparationNamespaceSet(*timev4.Clock, resourcev4.Reference) (MaterialNamespaceSet, error)
}

func (refs *sourceReferences) reserveSubscriptions(c SourceConnectConfig) error {
	var err error
	if pin := refs.verification; pin.lease != nil {
		bindings := pin.lease.allCredentialBindings()
		if len(bindings) == 0 || len(bindings) > protocolv4.MaxSourceCredentials {
			return resourcev4.ErrConfiguration
		}
		var namespaces [protocolv4.MaxSourceCredentials]*protocolv4.LiveNamespace
		for i, binding := range bindings {
			if binding.Namespace == nil {
				return resourcev4.ErrOwner
			}
			namespaces[i] = binding.Namespace
		}
		refs.subscriptions, err = protocolv4.PrepareCredentialSubscriptions(namespaces[:len(bindings)], true, c.Subscriptions)
		return err
	}
	var namespaces [protocolv4.MaxSourceCredentials]*protocolv4.LiveNamespace
	count, complete := 0, false
	if c.Identity != nil {
		// An admitting provider may return a preparation token that owns the
		// exact source position and its immutable namespace graph. Prefer that
		// token over the public provider view: it keeps the same provider
		// incarnation, generation and cleanup owner through Acquire.
		namespaceSource := c.Provider
		if refs.materialProvider != nil {
			if prepared, ok := refs.materialProvider.(PreparedMaterialNamespaceProvider); ok {
				namespaceSource = prepared
			}
		}
		if source, ok := namespaceSource.(MaterialNamespaceSetProvider); ok {
			set, setErr := source.PreparationNamespaceSet(c.Admission.Core.Clock, c.Environment)
			if setErr != nil {
				return setErr
			}
			if set.Count == 0 {
				if set.Owners != ([protocolv4.MaxSourceCredentials]*protocolv4.LiveNamespace{}) {
					return resourcev4.ErrOwner
				}
				namespaces[0], count = c.Identity.validation.Namespace, 1
			} else if set.Count < 3 || int(set.Count) > len(set.Owners) || set.Owners[1] != c.Identity.validation.Namespace {
				return resourcev4.ErrOwner
			} else {
				namespaces, count, complete = set.Owners, int(set.Count), true
			}
		} else if source, ok := namespaceSource.(MaterialNamespaceProvider); ok {
			var direct [3]*protocolv4.LiveNamespace
			direct, err = source.PreparationNamespaces(c.Admission.Core.Clock, c.Environment)
			if err != nil {
				return err
			}
			if direct[1] != c.Identity.validation.Namespace {
				return resourcev4.ErrOwner
			}
			copy(namespaces[:], direct[:])
			count, complete = len(direct), true
		} else {
			namespaces[0], count = c.Identity.validation.Namespace, 1
		}
	}
	if count == 0 {
		return nil // A component admission recipe has no material source.
	}
	refs.subscriptions, err = protocolv4.PrepareCredentialSubscriptions(namespaces[:count], complete, c.Subscriptions)
	return err
}

// Static material inspection retains the same immutable lease graph until
// source ownership is accepted. It grants no exclusive material/consumption
// right; the existing material selection gate still performs that transition.
func (m *ConnectionMaterial) capturePreparation(environment resourcev4.Reference, generation MaterialGeneration) (artifactLeaseUse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.cleaned || m.used || m.building || m.generation != generation {
		return artifactLeaseUse{}, cryptov4.ErrClosed
	}
	return m.lease.borrow(environment)
}
