package sessionv4

import (
	"context"
	"errors"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

var ErrSourceContractInvalid = errors.New("sessionv4: source contract invalid")

// MaterialRequirements is compiled from the original local application plan.
// The source must obtain exactly its signed application profile and K; a lower
// peer value cannot silently shrink the plan or enlarge its authority.
type MaterialRequirements struct {
	ApplicationProfile       string
	RPCMaxGeneralOutstanding uint16
	Connection               protocolv4.V4ConnectionRequirements
}

func (r MaterialRequirements) capture() (MaterialRequirements, error) {
	if err := r.Connection.CheckProfile(r.ApplicationProfile); err != nil {
		return r, err
	}
	// The exact profile is compiled above into ApplicationProfile. Do not
	// borrow a caller pointer or expose it to the asynchronous source.
	r.Connection.ApplicationProfile = nil
	return r, nil
}

func (r MaterialRequirements) valid() bool {
	switch r.ApplicationProfile {
	case "transport":
		return r.RPCMaxGeneralOutstanding == 0
	case "services", "execution":
		return r.RPCMaxGeneralOutstanding > 0 && r.RPCMaxGeneralOutstanding <= 1024
	default:
		return false
	}
}

// MaterialLeaseRequest contains only original public identity and requirements.
// It has no signer, static-DH handle, PSK, activation proof or mutable identity
// getter. The source's independently authenticated issuer transport binds this
// request to its configured target/tenant/audience and authorized source profile.
type MaterialLeaseRequest struct {
	IdentityDigest            [32]byte
	Tenant, Audience, Profile string
	Role                      protocolv4.Direction
	Requirements              MaterialRequirements
}

// MaterialLeaseProvider is trusted source composition. AcquireLease returns
// sole lifecycle ownership of a fully verified bounded ArtifactLease. Its
// original method does not return while provider tasks still use this request.
// The caller's Environment already owns execution, cancellation and cleanup;
// this interface creates no queue, replacement worker or alternate authority.
type MaterialLeaseProvider interface {
	AcquireLease(context.Context, MaterialLeaseRequest) (*ArtifactLease, error)
}

// MaterialAcquisition fixes identity, local source generation and all result
// storage before issuer work. It is an original source invocation, not a source
// manager or a resumable token. Close fences publication; the original caller's
// context cancels provider work. Resources remain until Acquire actually exits.
type MaterialAcquisition struct {
	mu                                   sync.Mutex
	ctx                                  context.Context
	deadline                             *timev4.Deadline
	identity                             identityUse
	generation                           MaterialGeneration
	request                              MaterialLeaseRequest
	source                               string
	reservation, material, establishment resourcev4.Reference
	materialCharge                       resourcev4.Vector
	started, active, closed, cleaned     bool
	batched                              bool
	done                                 chan struct{}
}

func MaterialAcquisitionCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(MaterialAcquisition{})), resourcev4.Items: 1, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func NewMaterialAcquisition(ctx context.Context, identity *ApplicationIdentity, generation MaterialGeneration, source string, requirements MaterialRequirements, deadline *timev4.Deadline, runtimeBytes, materialRuntimeBytes uint64, reservation, material resourcev4.Reference) (_ *MaterialAcquisition, err error) {
	return newMaterialAcquisition(ctx, identity, generation, source, requirements, deadline, runtimeBytes, materialRuntimeBytes, reservation, material, nil)
}

func newMaterialAcquisition(ctx context.Context, identity *ApplicationIdentity, generation MaterialGeneration, source string, requirements MaterialRequirements, deadline *timev4.Deadline, runtimeBytes, materialRuntimeBytes uint64, reservation, material resourcev4.Reference, references *sourceReferences) (_ *MaterialAcquisition, err error) {
	if ctx == nil || deadline == nil || identity == nil || generation.Source == ([16]byte{}) || generation.Generation == 0 || !requirements.valid() || source != "preauthorized_pool" && source != "live_authority" || reservation == material {
		return nil, cryptov4.ErrConfiguration
	}
	if requirements, err = requirements.capture(); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = deadline.Check(); err != nil {
		return nil, err
	}
	charge, err := MaterialAcquisitionCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	resultCharge, err := ConnectionMaterialCharge(materialRuntimeBytes)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(material); err != nil {
		return nil, err
	}
	var i identityUse
	var establishment resourcev4.Reference
	if references == nil {
		i, err = identity.capture(reservation)
		if err == nil {
			establishment, err = material.Borrow()
		}
	} else {
		if references.identity.identity != identity || references.materialOrigin != material || references.generation != generation {
			return nil, resourcev4.ErrOwner
		}
		if err = references.establishment.CheckBorrowedFrom(material); err != nil {
			return nil, err
		}
		i, err = references.identity.take(reservation)
		if err == nil {
			establishment, err = references.establishment.TakeBorrow()
			if err == nil {
				references.establishment = resourcev4.Reference{}
			}
		}
	}
	if err != nil {
		i.release()
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		i.release()
		establishment.Release()
		return nil, err
	}
	result, err := material.Take(resultCharge)
	if err != nil {
		owned.Release()
		i.release()
		establishment.Release()
		return nil, err
	}
	scope := identity.credential.Scope()
	a := &MaterialAcquisition{ctx: ctx, deadline: deadline, identity: i, generation: generation, source: source, reservation: owned, material: result, establishment: establishment, materialCharge: resultCharge, done: make(chan struct{}), request: MaterialLeaseRequest{IdentityDigest: identity.credential.Facts().Digest, Tenant: scope.Tenant, Audience: scope.Audience, Profile: scope.Profile, Role: identity.role, Requirements: requirements}}
	return a, nil
}

func (a *MaterialAcquisition) checkLocked() error {
	if a.closed {
		return cryptov4.ErrClosed
	}
	if err := a.reservation.Check(); err != nil {
		return err
	}
	return a.material.Check()
}

// The original active invocation pins ctx, deadline and identity while opaque
// context/clock callbacks run. Publication only checks their captured outcome
// and the original deadline under the owner gate; Close never waits for them.
func (a *MaterialAcquisition) sampleInvocation() (timev4.Sample, error) {
	if err := a.ctx.Err(); err != nil {
		return timev4.Sample{}, err
	}
	return a.deadline.Sample()
}

func (a *MaterialAcquisition) Acquire(provider MaterialLeaseProvider) (*ConnectionMaterial, error) {
	return a.acquire(provider, false)
}

func (a *MaterialAcquisition) acquireBatchMember(provider MaterialLeaseProvider) (*ConnectionMaterial, error) {
	return a.acquire(provider, true)
}

func (a *MaterialAcquisition) acquire(provider MaterialLeaseProvider, batchMember bool) (result *ConnectionMaterial, err error) {
	if a == nil || provider == nil {
		return nil, cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	if a.started || a.active || a.batched != batchMember {
		a.mu.Unlock()
		return nil, cryptov4.ErrTransition
	}
	if err = a.checkLocked(); err != nil {
		a.mu.Unlock()
		return nil, err
	}
	a.active = true
	ctx, request := a.ctx, a.request
	a.mu.Unlock()
	returned, started := false, false
	defer func() {
		if recover() != nil || !returned {
			err = ErrEnvironmentTaskExit
		}
		if err != nil && result != nil {
			result.Close()
			result = nil
		}
		a.mu.Lock()
		a.active = false
		if started || !returned {
			a.closed = true
		}
		a.cleanupLocked()
		a.mu.Unlock()
	}()
	now, err := a.sampleInvocation()
	a.mu.Lock()
	if err == nil {
		err = a.checkLocked()
	}
	if err == nil {
		err = a.deadline.CheckAt(now)
	}
	if err == nil {
		a.started, started = true, true
	}
	a.mu.Unlock()
	if err != nil {
		returned = true
		return nil, err
	}
	if err = a.identity.identity.check(); err != nil {
		returned = true
		return nil, err
	}
	// Key-provider validation can itself block. A concurrent Close must win
	// before issuer work begins, without releasing the captured identity.
	now, err = a.sampleInvocation()
	a.mu.Lock()
	if err == nil {
		err = a.checkLocked()
	}
	if err == nil {
		err = a.deadline.CheckAt(now)
	}
	a.mu.Unlock()
	if err != nil {
		returned = true
		return nil, err
	}
	lease, err := provider.AcquireLease(ctx, request)
	// Even a canceled/failed provider's late owned result must physically leave.
	if lease != nil {
		defer lease.Close()
	}
	if err != nil {
		returned = true
		return nil, err
	}
	now, err = a.sampleInvocation()
	a.mu.Lock()
	if err == nil {
		err = a.checkLocked()
	}
	if err == nil {
		err = a.deadline.CheckAt(now)
	}
	a.mu.Unlock()
	if err != nil {
		returned = true
		return nil, err
	}
	if lease == nil {
		returned = true
		return nil, ErrSourceContractInvalid
	}
	limits := lease.session.Contract.Limits()
	if lease.source != a.source || limits.ApplicationProfile != request.Requirements.ApplicationProfile || limits.RPCMaxGeneralOutstanding != request.Requirements.RPCMaxGeneralOutstanding {
		returned = true
		return nil, ErrSourceContractInvalid
	}
	// Move the original pin, including after identity advertisement retirement.
	a.mu.Lock()
	i := a.identity
	a.identity = identityUse{}
	establishment := a.establishment
	a.establishment = resourcev4.Reference{}
	a.mu.Unlock()
	result, err = newConnectionMaterialPrepared(lease, i, a.generation, a.materialCharge, a.material, establishment)
	if err != nil {
		returned = true
		return nil, err
	}
	now, err = a.sampleInvocation()
	a.mu.Lock()
	// material has moved into result, so only the original invocation, caller
	// cancellation and deadline are checked at this final publication gate.
	if a.closed {
		err = cryptov4.ErrClosed
	} else if err == nil {
		err = a.deadline.CheckAt(now)
	}
	if err == nil {
		err = a.reservation.Check()
	}
	if err == nil {
		// Retire this one-shot owner at the publication gate. The identity
		// and establishment pin have moved to result, whose reservation was
		// carved from the acquisition's material reference; cleanup releases
		// only the acquisition-owned references that remain.
		a.closed = true
	}
	a.mu.Unlock()
	returned = true
	return result, err
}

func (a *MaterialAcquisition) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	a.cleanupLocked()
}

func (a *MaterialAcquisition) cleanupLocked() {
	if !a.closed || a.active || a.cleaned {
		return
	}
	a.identity.release()
	a.establishment.Release()
	a.reservation.Release()
	a.material.Release()
	a.ctx, a.deadline = nil, nil
	a.request = MaterialLeaseRequest{}
	a.source = ""
	a.reservation, a.material, a.establishment = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	a.cleaned = true
	close(a.done)
}

func (a *MaterialAcquisition) WaitCleanup(ctx context.Context) error {
	if a == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-a.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
