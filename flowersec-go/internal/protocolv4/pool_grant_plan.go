package protocolv4

import (
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// PoolGrantPlan signs the two original Grants for an independently installed
// pool Artifact and activation. It cannot replace that activation, publish a
// Grant or restore an issuance from durable rows. Its complete private output
// must pass the original pool outbox transaction before either endpoint sees it.
type PoolGrantPlan struct {
	mu                     sync.Mutex
	plan                   *LiveActivationPlan
	parent                 *Credential
	validation             CredentialValidation
	active, issued, closed bool
}

func PoolGrantPlanCharge() (resourcev4.Vector, error) {
	cost, err := LiveActivationPlanCharge(true)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	selection, err := PoolSelectionBackingBytes(65536, 4096)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	parent, err := CredentialBackingBytes("Artifact")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return cost.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(PoolGrantPlan{})) + selection + parent})
}

func NewPoolGrantPlan(artifact, proof *SignedMap, activation ActivationConfiguration, index uint64, c LiveTunnelActivationConfig, reservation, environment resourcev4.Reference) (_ *PoolGrantPlan, err error) {
	if artifact == nil || proof == nil || activation.Rules == nil || c.Issuance == nil || c.Client == nil || c.Server == nil || c.Relay == nil || c.Bindings[0].Namespace == nil || c.Bindings[0].Policy == nil {
		return nil, resourcev4.ErrConfiguration
	}
	if err = artifact.CheckTunnelCandidate(index); err != nil {
		return nil, err
	}
	cost, err := PoolGrantPlanCharge()
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	p := &PoolGrantPlan{plan: &LiveActivationPlan{reservation: owned}, validation: c.Bindings[0]}
	defer func() {
		if err != nil {
			p.Close()
		}
	}()
	p.plan.shared, err = environment.Borrow()
	if err != nil {
		return nil, err
	}
	w, err := NewPoolSelectionWorkspace(65536, 4096)
	if err != nil {
		return nil, err
	}
	b, err := w.BindActivation(artifact, proof, "preauthorized_pool", index)
	if err != nil {
		return nil, err
	}
	if b.proofKey != activation.Key {
		return nil, resourcev4.ErrOwner
	}
	a, err := activation.Rules.BindActivationAuthority(b, artifact, activation.Delegation, activation.Once)
	if err != nil {
		return nil, err
	}
	if a.trust != activation.Binding {
		return nil, resourcev4.ErrOwner
	}
	p.parent, err = artifact.DetachCredential()
	if err != nil {
		return nil, err
	}
	p.plan.binding, p.plan.authority = b, a
	p.plan.fields = LiveActivationFields{Tunnel: true, Tenant: b.tenant, Authority: b.authority, SigningKey: b.signingKey, Audience: b.audience, Profile: b.profile,
		Issuer: b.issuer, Lease: b.lease, Attempt: b.attempt, Artifact: b.artifactDigest, ClientIdentity: b.clientDigest, ServerIdentity: b.serverDigest, Signer: b.proofKey,
		Winner: b.winner, IssuedAt: b.issuedAt, ActivationEnd: b.activationEnd, SessionEnd: b.sessionEnd, ParentInitiationEnd: p.parent.admissionEnd, ParentSessionEnd: p.parent.scope.ExpiresMS}
	if err = p.plan.freezeTunnel(artifact, &c); err != nil {
		return nil, err
	}
	if err = p.check(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *PoolGrantPlan) check() error {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return resourcev4.ErrClosed
	}
	if err := p.plan.reservation.Check(); err != nil {
		return err
	}
	if err := p.plan.shared.Check(); err != nil {
		return err
	}
	v, end := p.validation, p.plan.fields.SessionEnd
	if _, err := v.CheckMaterialCredential(p.parent, end, p.plan.reservation); err != nil {
		return err
	}
	now, err := v.Namespace.clock.Sample()
	if err != nil {
		return err
	}
	if err = p.plan.authority.CheckAdmission(now.Interval); err != nil {
		return err
	}
	r := v.Policy.Requirements()
	if _, err = v.Namespace.CheckDetachedActivation(p.plan.authority, p.parent, v.Issuer, r.StalenessMS, r.SignerLifetimeMS, end); err != nil {
		return err
	}
	for _, bindings := range p.plan.tunnel.bindings {
		grant := bindings[3]
		sample, err := grant.Namespace.clock.Sample()
		if err != nil {
			return err
		}
		if err = sample.LowerBound(grant.Issuer.SigningStart, true); err != nil {
			return err
		}
		if !sample.ValidBefore(grant.Issuer.SigningEnd) {
			return timev4.ErrExpired
		}
	}
	return p.plan.tunnel.checkCurrent(end)
}

// Issue consumes the only signing position even if a signer or its guard fails.
// Short buffers fail before that irreversible boundary. Close retains every
// dependency until the actual signing invocation returns.
func (p *PoolGrantPlan) Issue(dst [2][]byte, guard func() error) (sizes [2]int, err error) {
	if p == nil || guard == nil {
		return sizes, resourcev4.ErrConfiguration
	}
	p.mu.Lock()
	if p.closed || p.issued {
		p.mu.Unlock()
		return sizes, resourcev4.ErrOwner
	}
	for side, grant := range p.plan.tunnel.grants {
		if len(dst[side]) < len(grant.document.Bytes()) {
			p.mu.Unlock()
			return sizes, resourcev4.ErrCapacity
		}
	}
	p.issued, p.active = true, true
	p.mu.Unlock()
	success := false
	defer func() {
		if !success {
			for _, b := range dst {
				clear(b)
			}
			sizes = [2]int{}
		}
		p.mu.Lock()
		p.active = false
		p.cleanupLocked()
		p.mu.Unlock()
	}()
	check := func() error {
		if err := guard(); err != nil {
			return err
		}
		return p.check()
	}
	for side := range dst {
		sizes[side], err = p.plan.tunnel.grants[side].issue(dst[side], check)
		if err != nil {
			return sizes, err
		}
	}
	if err = check(); err != nil {
		return sizes, err
	}
	success = true
	return sizes, nil
}

func (p *PoolGrantPlan) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.cleanupLocked()
}

func (p *PoolGrantPlan) cleanupLocked() {
	if !p.closed || p.active {
		return
	}
	_ = p.plan.Close()
	p.plan, p.parent, p.validation = nil, nil, CredentialValidation{}
}
