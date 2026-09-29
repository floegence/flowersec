package sessionv4

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// prepareContractQueryProtection uses only an existing ordinary channel and
// the Session's original query assembly. It creates no channel or connection.
func (r *RPCServices) prepareContractQueryProtection(e *Environment, s *EnvironmentSession) (*contractQueryProtection, error) {
	if r == nil || e == nil || s == nil {
		return nil, cryptov4.ErrConfiguration
	}
	charges, err := contractQueryProtectionCharges()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.closed || r.retired || r.draining.Load() || r.plan == nil || r.rpcPublisherLocked() == nil {
		r.mu.Unlock()
		return nil, cryptov4.ErrNotReady
	}
	if r.callSerial == math.MaxUint64 {
		r.mu.Unlock()
		return nil, cryptov4.ErrCapacity
	}
	r.callSerial++
	var seed [56]byte
	copy(seed[:16], "query-renewal4/")
	copy(seed[16:32], r.owner.Instance[:])
	copy(seed[32:48], r.owner.Backing[:])
	binary.BigEndian.PutUint64(seed[48:], r.callSerial)
	hash := sha256.Sum256(seed[:])
	var requests [4]resourcev4.Request
	var refs [4]resourcev4.Reference
	for j, charge := range charges {
		owner := r.owner
		copy(owner.Instance[:], hash[:16])
		copy(owner.Backing[:], hash[16:])
		owner.Backing[0] ^= byte(j)
		requests[j] = resourcev4.Request{Owner: owner, Charge: charge, Accounts: r.accounts[:r.accountCount]}
	}
	err = r.root.ReserveBatch(requests[:], refs[:])
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	return e.protectContractQuery(s, refs)
}

// contractQueryProtection is the Environment's one shared original renewal
// opportunity. It protects a complete eight-target output, the original
// Session Q2 vector, and an idle original fixed-worker index. Every use still
// occupies the Environment's original J positions and candidate bound.
// Fields are protected by environment.mu; no caller may forge this capability.
type contractQueryProtection struct {
	environment *Environment
	session     *EnvironmentSession
	plan        *SessionPlan
	index       int
	closed      bool
	backing     resourcev4.Reference
	output      *resourcev4.ProtectedReservation
	lane        *rpcv4.ContractQueryRenewal
	worker      *sdkQueryProtection
	batch       contractRenewalBatch
	advancing   bool
	// Session vectors remain separate; all of them share this single J/output
	// opportunity. The selected aliases above cannot change until its real
	// query and consumer tails have left the original Environment position.
	sources [256]*contractQuerySourceProtection
	managed bool
	round   contractRenewalRound
}

type contractQuerySourceProtection struct {
	session     *EnvironmentSession
	plan        *SessionPlan
	lane        *rpcv4.ContractQueryRenewal
	worker      *sdkQueryProtection
	backing     resourcev4.Reference
	outputScope resourcev4.Reference
	closed      bool
}

// Each separately owned backing is acquired in one Root.ReserveBatch before
// protection. Failure unwinds the actual owners; no managed handoff can use a
// partial floor. The Environment index/claim itself is already precharged.
func contractQueryProtectionCharges() ([4]resourcev4.Vector, error) {
	var charges [4]resourcev4.Vector
	charges[0] = resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(contractQueryProtection{})) + uint64(unsafe.Sizeof(contractQuerySourceProtection{})) + contractRenewalDeadlineBytes(), resourcev4.Items: 2}
	output, err := ContractQuerySnapshotsCharge(8)
	if err != nil {
		return charges, err
	}
	charges[1], err = resourcev4.ProtectedCharge(output)
	charges[2] = rpcv4.ContractQueryRenewalCharge()
	charges[3] = sdkQueryProtectionCharge()
	return charges, err
}

func (e *Environment) protectContractQuery(s *EnvironmentSession, refs [4]resourcev4.Reference) (_ *contractQueryProtection, err error) {
	if e == nil || s == nil {
		return nil, cryptov4.ErrConfiguration
	}
	charges, err := contractQueryProtectionCharges()
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.retired || e.queryProtection != nil || len(e.queries) == 0 {
		return nil, cryptov4.ErrClosed
	}
	index := len(e.queries) - 1
	if e.queries[index] != nil || e.queryClaims[index] != nil || e.queryActive+uint32(e.staticContractWork) >= e.contractWorkLimitLocked() {
		return nil, cryptov4.ErrCapacity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.environment != e || s.closed || s.drain != nil || !s.delivered || s.core == nil || s.application == nil {
		return nil, cryptov4.ErrClosed
	}
	for _, ref := range refs {
		if err := ref.CheckSameEnvironment(e.reservation); err != nil {
			return nil, err
		}
	}
	plan := s.application
	plan.mu.Lock()
	defer plan.mu.Unlock()
	if plan.closed || !plan.claimed || plan.queries == nil || plan.queries.initiator.Load() == nil {
		return nil, cryptov4.ErrNotReady
	}
	p := &contractQueryProtection{environment: e, session: s, plan: plan, index: index}
	defer func() {
		if err != nil {
			p.worker.Close()
			p.lane.Close()
			if p.output != nil {
				p.output.CloseAfterUse()
			}
			p.backing.Release()
		}
	}()
	// The shared opportunity belongs to the Environment. Per-Session lane
	// and worker borrows below retain the actual Session scopes independently.
	if err = refs[0].DetachSessionScope(); err != nil {
		return nil, err
	}
	if err = refs[1].DetachSessionScope(); err != nil {
		return nil, err
	}
	p.backing, err = refs[0].Take(charges[0])
	if err != nil {
		return nil, err
	}
	output, _ := ContractQuerySnapshotsCharge(8)
	p.output, err = resourcev4.NewProtectedReservation(refs[1], output)
	if err != nil {
		return nil, err
	}
	scope, err := p.output.BorrowScope(refs[2])
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			scope.Release()
		}
	}()
	p.lane, err = plan.queries.initiator.Load().ProtectRenewal(refs[2])
	if err != nil {
		return nil, err
	}
	borrow, err := plan.reservation.Borrow()
	if err != nil {
		return nil, err
	}
	defer borrow.Release()
	p.worker, err = plan.executor.protectSDKQuery(&plan.queries.group, refs[3], borrow)
	if err != nil {
		return nil, err
	}
	p.sources[0] = &contractQuerySourceProtection{session: s, plan: plan, lane: p.lane, worker: p.worker, outputScope: scope}
	e.queryProtection = p
	return p, nil
}

// reserve atomically checks out the protected output and the same original
// acquisition slot. It cannot overtake a consumer, decoder or provider tail.
func (p *contractQueryProtection) reserve(s *EnvironmentSession) (*contractQueryClaim, resourcev4.Reference, error) {
	if p == nil {
		return nil, resourcev4.Reference{}, cryptov4.ErrConfiguration
	}
	e := p.environment
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.retired || p.closed || e.queryProtection != p {
		return nil, resourcev4.Reference{}, cryptov4.ErrClosed
	}
	if e.queries[p.index] != nil || e.queryClaims[p.index] != nil {
		return nil, resourcev4.Reference{}, cryptov4.ErrCapacity
	}
	source := p.sourceLocked(s)
	if source == nil || source.closed {
		return nil, resourcev4.Reference{}, cryptov4.ErrNotReady
	}
	p.session, p.plan, p.lane, p.worker = source.session, source.plan, source.lane, source.worker
	if err := p.backing.Check(); err != nil {
		return nil, resourcev4.Reference{}, err
	}
	if err := p.worker.available(); err != nil {
		return nil, resourcev4.Reference{}, err
	}
	ref, err := p.output.Checkout()
	if err != nil {
		return nil, resourcev4.Reference{}, err
	}
	if err := source.outputScope.Check(); err != nil {
		ref.Release()
		return nil, resourcev4.Reference{}, err
	}
	claim := &contractQueryClaim{environment: e, index: p.index, protection: p, destination: ref}
	e.queryClaims[p.index] = claim
	e.queryActive++
	return claim, ref, nil
}

func (p *contractQueryProtection) Close() {
	if p == nil {
		return
	}
	e := p.environment
	e.mu.Lock()
	p.closeLocked()
	e.mu.Unlock()
	e.signalMaterials()
}

func (p *contractQueryProtection) closeLocked() {
	if p.closed {
		return
	}
	p.closed = true
	if p.batch.query != nil {
		p.batch.query.Close()
	}
	if p.batch.cancel != nil {
		p.batch.cancel()
	}
	// Existing query and transferred output owners retain their physical
	// responsibility. Withdrawal only seals this future opportunity.
	for _, source := range p.sources {
		if source != nil {
			source.closeLocked()
		}
	}
	p.output.CloseAfterUse()
}

func (e *Environment) collectContractQueryProtectionLocked() {
	p := e.queryProtection
	if p == nil || !p.closed || p.batch.active || p.advancing || e.queries[p.index] != nil || e.queryClaims[p.index] != nil {
		return
	}
	if !p.output.UseComplete() {
		return
	}
	for _, source := range p.sources {
		if source != nil && !source.worker.cleanupComplete() {
			return
		}
	}
	for j, source := range p.sources {
		if source != nil {
			source.outputScope.Release()
			source.backing.Release()
			p.sources[j] = nil
		}
	}
	if !p.output.CleanupComplete() {
		return
	}
	p.backing.Release()
	p.backing = resourcev4.Reference{}
	p.session, p.plan = nil, nil
	e.queryProtection = nil
}

func (p *contractQueryProtection) sourceLocked(s *EnvironmentSession) *contractQuerySourceProtection {
	for _, source := range p.sources {
		if source != nil && source.session == s {
			return source
		}
	}
	return nil
}

func (s *contractQuerySourceProtection) closeLocked() {
	if s.closed {
		return
	}
	s.closed = true
	s.worker.Close()
	s.lane.Close()
}

// Protection counts only while its original position is idle. A live renewal
// already contributes to queryActive, so it is never charged a second J slot.
func (e *Environment) ordinaryContractWorkLimitLocked() uint32 {
	limit := e.contractWorkLimitLocked()
	if p := e.queryProtection; p != nil && e.queries[p.index] == nil && e.queryClaims[p.index] == nil {
		limit--
	}
	return limit
}

func (e *Environment) ordinaryContractQuerySlotLocked(i int) bool {
	return e.queries[i] == nil && e.queryClaims[i] == nil && (e.queryProtection == nil || e.queryProtection.index != i)
}
