package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// sourceReferences pins the original source graph before acquisition. Each
// reference has one destination; moving it does not acquire root capacity.
// The attempt owns this value until the source worker takes responsibility.
type sourceReferences struct {
	materialProvider                   MaterialLeasePreparation
	staticOrigin                       *ConnectionMaterial
	subscriptions                      *protocolv4.CredentialSubscriptions
	environmentOrigin                  resourcev4.Reference
	dependenciesOrigin, materialOrigin resourcev4.Reference
	generation                         MaterialGeneration
	shared, establishment              resourcev4.Reference
	workloadSnapshot                   resourcev4.Reference
	workloadSnapshotBytes              uint64
	identity                           identityUse
	poolOrigin                         *PreauthorizedPoolSource
	verification                       artifactLeaseUse
	carriers                           [2]resourcev4.Reference
	carrierFloors                      [2]*resourcev4.ProtectedReservation
	providerPreparations               [2]CarrierPreparation
	carrierOrigin                      resourcev4.Reference
	carrierRuntimeBytes                uint64
	carrierCount                       int
	claimed                            bool
}

func reserveSourceReferences(c SourceConnectConfig) (refs sourceReferences, err error) {
	refs.dependenciesOrigin, refs.materialOrigin, refs.generation = c.Dependencies, c.Material, c.Generation
	refs.environmentOrigin = c.Environment
	refs.poolOrigin, refs.staticOrigin = c.poolSource, c.staticMaterial
	defer func() {
		if err != nil {
			refs.close()
		}
	}()
	// Aggregate-only admission has no source. Actual source admission still
	// requires Dependencies in startSourcePrepared's same-Environment checks.
	if c.Dependencies != (resourcev4.Reference{}) {
		if err = c.Dependencies.CheckSameEnvironment(c.Environment); err != nil {
			return refs, err
		}
		refs.shared, err = c.Dependencies.Borrow()
		if err != nil {
			return refs, err
		}
	}
	if c.Identity != nil {
		if err = c.Material.CheckSameEnvironment(c.Environment); err != nil {
			return refs, err
		}
		refs.identity, err = c.Identity.capture(c.Environment)
		if err == nil {
			refs.establishment, err = c.Material.Borrow()
		}
		if err != nil {
			return refs, err
		}
	}
	if c.poolSource != nil {
		refs.verification, err = c.poolSource.capturePreparation(c.Environment)
		if err != nil {
			return refs, err
		}
	}
	if c.staticMaterial != nil {
		refs.verification, err = c.staticMaterial.capturePreparation(c.Environment, c.Generation)
		if err != nil {
			return refs, err
		}
	}
	if err = refs.reserveMaterialProvider(c); err != nil {
		return refs, err
	}
	if err = refs.reserveSubscriptions(c); err != nil {
		return refs, err
	}
	err = refs.reserveCarriers(c)
	return refs, err
}

func sourceCarrierReferenceCount(c SourceConnectConfig) int {
	if c.Carrier == nil {
		return 0
	}
	count := 2
	if c.ParallelCandidates == 1 {
		count = 1
	}
	if factory, ok := c.Carrier.(AdmittingConsumerCarrierFactory); ok {
		maximum := factory.PreparationParallelism()
		if maximum == 0 || maximum > 2 {
			return 0
		}
		count = min(count, int(maximum))
	}
	return count
}

func (refs *sourceReferences) take(c SourceConnectConfig) (sourceReferences, error) {
	if refs.claimed || refs.staticOrigin != c.staticMaterial || refs.environmentOrigin != c.Environment || refs.dependenciesOrigin != c.Dependencies || refs.materialOrigin != c.Material || refs.generation != c.Generation || refs.identity.identity != c.Identity || refs.poolOrigin != c.poolSource || refs.carrierCount != sourceCarrierReferenceCount(c) || refs.carrierOrigin != c.CarrierReservation || refs.carrierRuntimeBytes != c.CarrierRuntimeBytes {
		return sourceReferences{}, resourcev4.ErrOwner
	}
	if err := refs.shared.CheckSameEnvironment(c.Environment); err != nil {
		return sourceReferences{}, err
	}
	if refs.materialProvider != nil {
		if !refs.materialProvider.Matches(c.Provider) {
			return sourceReferences{}, resourcev4.ErrOwner
		}
		if err := refs.materialProvider.Check(); err != nil {
			return sourceReferences{}, err
		}
	}
	if refs.subscriptions != nil {
		if err := refs.subscriptions.CheckSourcePreparation(c.Subscriptions); err != nil {
			return sourceReferences{}, err
		}
	}
	for _, preparation := range refs.providerPreparations {
		if preparation != nil {
			if !preparation.Matches(c.Carrier) {
				return sourceReferences{}, resourcev4.ErrOwner
			}
			if err := preparation.Check(); err != nil {
				return sourceReferences{}, err
			}
		}
	}
	// Keep every successfully advanced alias here until the entire move has
	// succeeded, so a partial failure is still owned by the original attempt.
	for _, ref := range [...]*resourcev4.Reference{&refs.shared, &refs.establishment, &refs.carriers[0], &refs.carriers[1]} {
		if *ref == (resourcev4.Reference{}) {
			continue
		}
		moved, err := ref.TakeBorrow()
		if err != nil {
			return sourceReferences{}, err
		}
		*ref = moved
	}
	if refs.identity.identity != nil {
		pin, err := refs.identity.take(c.Environment)
		if err != nil {
			return sourceReferences{}, err
		}
		refs.identity = pin
	}
	if refs.verification.lease != nil {
		pin, err := refs.verification.take(c.Environment)
		if err != nil {
			return sourceReferences{}, err
		}
		refs.verification = pin
	}
	if refs.workloadSnapshot != (resourcev4.Reference{}) {
		owned, err := refs.workloadSnapshot.Take(resourcev4.Vector{resourcev4.SDKBytes: refs.workloadSnapshotBytes})
		if err != nil {
			return sourceReferences{}, err
		}
		refs.workloadSnapshot = owned
	}
	result := *refs
	*refs = sourceReferences{claimed: true}
	return result, nil
}

func (refs *sourceReferences) close() {
	refs.workloadSnapshot.Release()
	if refs.materialProvider != nil {
		refs.materialProvider.Close()
	}
	if refs.subscriptions != nil {
		refs.subscriptions.Close()
	}
	for _, preparation := range refs.providerPreparations {
		if preparation != nil {
			preparation.Close()
		}
	}
	for _, floor := range refs.carrierFloors {
		floor.Close()
	}
	for _, ref := range refs.carriers {
		ref.Release()
	}
	refs.identity.release()
	refs.verification.release()
	refs.establishment.Release()
	refs.shared.Release()
	*refs = sourceReferences{claimed: true}
}

func (h *sessionHeadroom) takeSource(c SourceConnectConfig) (sourceReferences, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.claimed {
		return sourceReferences{}, resourcev4.ErrOwner
	}
	return h.source.take(c)
}
