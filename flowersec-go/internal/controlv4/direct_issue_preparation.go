package controlv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// The token names the source's original one-call position, not a parallel
// acquisition owner. It is retired as soon as that original method returns.
type directIssuePreparation struct {
	owner           *DirectIssueSource
	serial          uint64
	request         sessionv4.MaterialLeaseRequest
	reservation     resourcev4.Reference
	references      *sessionv4.ArtifactLeaseReferences
	started, closed bool
}

func (p *DirectIssueSource) validRequestLocked(q sessionv4.MaterialLeaseRequest) bool {
	scope := p.credentials[0].Scope()
	return q.IdentityDigest == p.credentials[0].Facts().Digest && q.Role == protocolv4.ClientToServer &&
		q.Tenant == scope.Tenant && q.Audience == scope.Audience && q.Profile == scope.Profile &&
		q.Requirements.ApplicationProfile == p.c.ApplicationProfile && q.Requirements.RPCMaxGeneralOutstanding == p.c.RPCMaxGeneralOutstanding
}

func (p *DirectIssueSource) reserveLeaseLocked() (resourcev4.Reference, error) {
	if p.serial == math.MaxUint64 {
		return resourcev4.Reference{}, resourcev4.ErrCapacity
	}
	p.serial++
	var seed [64]byte
	copy(seed[:24], "direct-issue-source-1")
	copy(seed[24:40], p.c.Owner.Instance[:])
	copy(seed[40:56], p.c.Owner.Backing[:])
	binary.BigEndian.PutUint64(seed[56:], p.serial)
	digest := sha256.Sum256(seed[:])
	owner := p.c.Owner
	copy(owner.Instance[:], digest[:16])
	copy(owner.Backing[:], digest[16:])
	return p.c.Root.Reserve(owner, p.leaseCharge, p.c.Accounts...)
}

func (p *DirectIssueSource) AdmitMaterialLease(request sessionv4.MaterialLeaseAdmissionRequest) (sessionv4.MaterialLeasePreparation, error) {
	if p == nil || request.Clock == nil {
		return nil, resourcev4.ErrConfiguration
	}
	q := request.Material
	if err := q.Requirements.Connection.CheckProfile(q.Requirements.ApplicationProfile); err != nil {
		return nil, err
	}
	q.Requirements.Connection.ApplicationProfile = nil
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, resourcev4.ErrClosed
	}
	if p.busy || p.preparation != nil {
		return nil, ErrBusy
	}
	if request.Clock != p.c.Clock || !p.validRequestLocked(q) {
		return nil, resourcev4.ErrOwner
	}
	if err := p.reservation.CheckSameEnvironment(request.Environment); err != nil {
		return nil, err
	}
	if err := p.shared.Check(); err != nil {
		return nil, err
	}
	ref, err := p.reserveLeaseLocked()
	if err != nil {
		return nil, err
	}
	references, err := sessionv4.NewArtifactLeaseReferences(ref, p.dependencies)
	if err != nil {
		ref.Release()
		return nil, err
	}
	preparation := &directIssuePreparation{owner: p, serial: p.serial, request: q, reservation: ref, references: references}
	p.preparation = preparation
	return preparation, nil
}

func (r *directIssuePreparation) Matches(provider sessionv4.MaterialLeaseProvider) bool {
	p, ok := provider.(*DirectIssueSource)
	return r != nil && ok && p == r.owner
}

func (r *directIssuePreparation) checkLocked() error {
	p := r.owner
	if p.preparation != r || p.serial != r.serial || r.closed || r.started || p.closed || p.busy {
		return resourcev4.ErrOwner
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	if err := p.shared.Check(); err != nil {
		return err
	}
	if err := r.reservation.CheckMinimum(p.leaseCharge); err != nil {
		return err
	}
	return r.references.Check(r.reservation, p.dependencies)
}

func (r *directIssuePreparation) Check() error {
	if r == nil || r.owner == nil {
		return resourcev4.ErrOwner
	}
	r.owner.mu.Lock()
	defer r.owner.mu.Unlock()
	return r.checkLocked()
}

func (r *directIssuePreparation) AcquireLease(ctx context.Context, q sessionv4.MaterialLeaseRequest) (*sessionv4.ArtifactLease, error) {
	if r == nil || r.owner == nil {
		return nil, resourcev4.ErrOwner
	}
	return r.owner.acquireLease(ctx, q, r)
}

// PreparationNamespaceSet keeps the namespace snapshot attached to the same
// admitted source token that will execute AcquireLease. It is intentionally
// read under the source gate and validates the token first, so a copied or
// stale preparation cannot reserve a replacement generation.
func (r *directIssuePreparation) PreparationNamespaceSet(clock *timev4.Clock, environment resourcev4.Reference) (sessionv4.MaterialNamespaceSet, error) {
	if r == nil || r.owner == nil {
		return sessionv4.MaterialNamespaceSet{}, resourcev4.ErrOwner
	}
	p := r.owner
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := r.checkLocked(); err != nil {
		return sessionv4.MaterialNamespaceSet{}, err
	}
	return p.preparationNamespaceSetLocked(clock, environment)
}

func (r *directIssuePreparation) Close() {
	if r == nil || r.owner == nil {
		return
	}
	p := r.owner
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.preparation != r || p.serial != r.serial {
		return
	}
	r.closed = true
	if p.busy {
		if p.cancel != nil {
			p.cancel()
		}
		return
	}
	p.releasePreparationLocked(r)
	p.cleanupLocked()
}

func (p *DirectIssueSource) releasePreparationLocked(r *directIssuePreparation) {
	if r == nil || p.preparation != r || p.busy {
		return
	}
	r.closed = true
	r.references.Close()
	r.references = nil
	r.reservation.Release()
	r.reservation = resourcev4.Reference{}
	r.request = sessionv4.MaterialLeaseRequest{}
	p.preparation = nil
}

var _ sessionv4.AdmittingMaterialLeaseProvider = (*DirectIssueSource)(nil)
var _ sessionv4.MaterialNamespaceSetProvider = (*directIssuePreparation)(nil)
