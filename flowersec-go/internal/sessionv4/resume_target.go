package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

// ResumeStreamBinding comes from the trusted method/kind registration. It
// contains no peer-selected transport context or stream id.
type ResumeStreamBinding struct {
	Kind, Namespace string
	Method          uint32
	Type            uint32
	ContractDigest  [32]byte
}

// This is a qualification inside the original Stream owner, not a second
// pending table. The operation's existing metadata reservation pays for it.
// Its immutable capability and OpenHandle are the local incarnation fence.
type resumeTarget struct {
	mu                sync.Mutex
	core              *SessionCore
	owner             *StreamOwnership
	handle            OpenHandle
	backing           resourcev4.Reference
	sessionIdentity   resourcev4.Reference
	target            rpcv4.RecoveryTarget
	identity          [16]byte
	checkpoint        protocolv4.ResumeCheckpoint
	generation        uint64
	started, released bool
}

func claimResumeTarget(ctx context.Context, core *SessionCore, owner *StreamOwnership, binding ResumeStreamBinding, policy protocolv4.ServiceContractPolicy, backing resourcev4.Reference, tokenBytes int) (*resumeTarget, error) {
	if ctx == nil || core == nil || core.plan == nil || owner == nil || !canonicalStreamHandlerKind(binding.Kind) || binding.Namespace != policy.Namespace || binding.Type != policy.Type || binding.ContractDigest != policy.Digest || policy.Shape != 0 || policy.Semantics != 1 || policy.ExecutionMode != 1 {
		return nil, cryptov4.ErrConfiguration
	}
	p := core.plan
	p.mu.Lock()
	if p.closed || p.engine == nil || p.admission == nil || p.rpc == nil {
		p.mu.Unlock()
		return nil, cryptov4.ErrNotReady
	}
	a, engine, sessionIdentity := p.admission, p.engine, p.refs[corePlanOwner]
	policyResume := p.config.Session.Resume
	p.mu.Unlock()
	enabled, err := protocolv4.ResumeFeatureSelected(engine.NegotiatedFeatures())
	if err != nil {
		return nil, err
	}
	if !enabled || !policyResume.Enabled || tokenBytes <= 0 || uint64(tokenBytes) > uint64(policyResume.MaxTokenBytes) {
		return nil, rpcv4.ErrExecutionUnsupported
	}
	if engine.TransportContextDigest() == ([32]byte{}) {
		return nil, cryptov4.ErrConfiguration
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.admission != a || owner.rawUsed || owner.users != 0 || owner.cleaning || owner.messages != nil || owner.typed != nil || owner.resume != nil || owner.revoked.Load() || owner.sealed.Load() {
		return nil, ErrStreamOwned
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(owner.handle)
	if err != nil {
		return nil, err
	}
	if a.closed || a.draining || s.owner != owner || !s.accepted || s.cancelled || s.phase != openLive || string(a.metadata[s.metadataStart:s.metadataStart+s.kindSize]) != binding.Kind {
		return nil, ErrStreamOwned
	}
	q, f := owner.queue, owner.flow.receive
	q.mu.Lock()
	defer q.mu.Unlock()
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	if q.writeOwner != owner || f.readOwner != owner || q.waiters != 0 || q.observers != 0 || q.methodTails != 0 || f.readPending || f.readTails != 0 || f.delivered != 0 || q.accepted != 0 || q.rawUsed || f.rawUsed || owner.accepted.Load() != 0 || f.cleaned {
		return nil, ErrStreamOwnershipBusy
	}
	if s.peerLimit < serviceStreamQuantum || f.limit-f.released < serviceStreamQuantum {
		return nil, ErrCredit
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := owner.checkLifetime(); err != nil {
		return nil, err
	}
	if err := engine.CheckApplicationAuthorization(); err != nil {
		return nil, err
	}
	if err := owner.reservation.CheckSameEnvironment(backing); err != nil {
		return nil, err
	}
	hold, err := owner.reservation.Borrow()
	if err != nil {
		return nil, err
	}
	x := &resumeTarget{core: core, owner: owner, handle: owner.handle, backing: hold, target: rpcv4.RecoveryTarget{TransportContext: engine.TransportContextDigest(), StreamID: owner.handle.scope}}
	x.sessionIdentity = sessionIdentity
	var seed [48]byte
	copy(seed[:8], "resume4/")
	copy(seed[8:40], x.target.TransportContext[:])
	binary.BigEndian.PutUint64(seed[40:], x.target.StreamID)
	digest := sha256.Sum256(seed[:])
	copy(x.identity[:], digest[:16])
	owner.resume = x
	return x, nil
}

func (x *resumeTarget) sameSession(core *SessionCore) bool {
	if x == nil || core == nil || core.plan == nil {
		return false
	}
	core.plan.mu.Lock()
	defer core.plan.mu.Unlock()
	return !core.plan.closed && core.plan.refs[corePlanOwner] == x.sessionIdentity
}

func (x *resumeTarget) check(core *SessionCore) error {
	if x == nil {
		return ErrStreamOwned
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.checkLocked(core)
}

func (x *resumeTarget) checkLocked(core *SessionCore) error {
	if x.released || x.core != core || x.owner == nil {
		return ErrStreamOwned
	}
	o := x.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.resume != x || o.admission != x.handle.owner || o.handle != x.handle || o.revoked.Load() || o.sealed.Load() || o.cleaning {
		return ErrStreamOwned
	}
	a := o.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(x.handle)
	if err != nil {
		return err
	}
	if a.closed || !x.started && a.draining || s.cancelled || s.owner != o || !s.accepted {
		return ErrStreamOwned
	}
	if err := o.checkLifetime(); err != nil {
		return err
	}
	if err := x.backing.Check(); err != nil {
		return err
	}
	return a.engine.CheckApplicationAuthorization()
}

// Before Start there are no framing or publication tails. A Close/expiry can
// return this unused qualification without ending the caller's target Stream.
func (x *resumeTarget) releaseUnused() {
	if x == nil {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.started || x.released {
		return
	}
	x.releaseLocked(false)
}

func (x *resumeTarget) releaseLocked(used bool) {
	o := x.owner
	if o != nil {
		o.mu.Lock()
		if o.resume == x {
			o.resume = nil
			o.rawUsed = o.rawUsed || used
			o.notify()
		}
		o.mu.Unlock()
	}
	x.backing.Release()
	x.backing = resourcev4.Reference{}
	x.owner, x.core, x.handle, x.released = nil, nil, OpenHandle{}, true
}
