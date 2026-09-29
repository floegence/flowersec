package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type MaterialLeaseAdmissionRequest struct {
	Clock       *timev4.Clock
	Environment resourcev4.Reference
	Material    MaterialLeaseRequest
}

// AdmittingMaterialLeaseProvider reserves the original acquisition position and
// output before Acquire. Implementations perform bounded local SDK admission,
// without issuing credentials or invoking application/key/clock callbacks.
type AdmittingMaterialLeaseProvider interface {
	MaterialLeaseProvider
	AdmitMaterialLease(MaterialLeaseAdmissionRequest) (MaterialLeasePreparation, error)
}

type MaterialLeasePreparation interface {
	MaterialLeaseProvider
	Matches(MaterialLeaseProvider) bool
	Check() error
	Close()
}

// A preparation may also expose the exact immutable credential namespace
// graph it reserved with its source position. Source admission consumes this
// view before Acquire and keeps the same token responsible for both provider
// and subscriber cleanup.
//
// This is intentionally a capability interface rather than a second source
// manager: providers that do not implement it remain component-only at the
// public boundary.
type PreparedMaterialNamespaceProvider interface {
	MaterialNamespaceSetProvider
}

func (refs *sourceReferences) reserveMaterialProvider(c SourceConnectConfig) error {
	factory, ok := c.Provider.(AdmittingMaterialLeaseProvider)
	if !ok {
		return nil
	}
	if refs.identity.identity == nil || refs.identity.identity != c.Identity {
		return resourcev4.ErrOwner
	}
	requirements, err := c.Requirements.capture()
	if err != nil {
		return err
	}
	scope := c.Identity.credential.Scope()
	request := MaterialLeaseRequest{IdentityDigest: c.Identity.credential.Facts().Digest,
		Tenant: scope.Tenant, Audience: scope.Audience, Profile: scope.Profile, Role: c.Identity.role, Requirements: requirements}
	refs.materialProvider, err = factory.AdmitMaterialLease(MaterialLeaseAdmissionRequest{
		Clock: c.Admission.Core.Clock, Environment: c.Environment, Material: request})
	if err != nil {
		return err
	}
	if refs.materialProvider == nil || !refs.materialProvider.Matches(c.Provider) {
		return resourcev4.ErrOwner
	}
	return refs.materialProvider.Check()
}
