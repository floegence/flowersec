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

// A new actual Session contributes only its own original Q/worker references,
// never a second Environment job or response buffer. Callers serialize managed
// changes with renewalMu; ordinary query publication still uses Environment.mu.
func (e *Environment) ensureContractQuerySource(r *RPCServices, s *EnvironmentSession) (*contractQueryProtection, error) {
	e.mu.Lock()
	p := e.queryProtection
	if p != nil {
		if p.closed || e.closed {
			e.mu.Unlock()
			return nil, cryptov4.ErrClosed
		}
		if source := p.sourceLocked(s); source != nil && !source.closed {
			err := source.worker.check()
			if err == nil {
				source.plan.mu.Lock()
				if source.plan.closed || source.plan.queries == nil {
					err = cryptov4.ErrClosed
				} else {
					err = source.lane.CheckInitiator(source.plan.queries.initiator.Load())
				}
				source.plan.mu.Unlock()
			}
			e.mu.Unlock()
			return p, err
		}
	}
	e.mu.Unlock()
	if p == nil {
		return r.prepareContractQueryProtection(e, s)
	}
	charges := [3]resourcev4.Vector{
		{resourcev4.SDKBytes: uint64(unsafe.Sizeof(contractQuerySourceProtection{})), resourcev4.Items: 1},
		rpcv4.ContractQueryRenewalCharge(), sdkQueryProtectionCharge(),
	}
	r.mu.Lock()
	if r.closed || r.retired || r.draining.Load() || r.rpcPublisherLocked() == nil || r.callSerial == math.MaxUint64 {
		r.mu.Unlock()
		return nil, cryptov4.ErrNotReady
	}
	r.callSerial++
	var seed [56]byte
	copy(seed[:16], "renewal-source4/")
	copy(seed[16:32], r.owner.Instance[:])
	copy(seed[32:48], r.owner.Backing[:])
	binary.BigEndian.PutUint64(seed[48:], r.callSerial)
	hash := sha256.Sum256(seed[:])
	var requests [3]resourcev4.Request
	var refs [3]resourcev4.Reference
	for j, charge := range charges {
		owner := r.owner
		copy(owner.Instance[:], hash[:16])
		copy(owner.Backing[:], hash[16:])
		owner.Backing[0] ^= byte(j)
		requests[j] = resourcev4.Request{Owner: owner, Charge: charge, Accounts: r.accounts[:r.accountCount]}
	}
	err := r.root.ReserveBatch(requests[:], refs[:])
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.retired || e.queryProtection != p || p.closed {
		return nil, cryptov4.ErrClosed
	}
	index := -1
	for j, source := range p.sources {
		if source == nil {
			index = j
			break
		}
	}
	if index < 0 {
		return nil, cryptov4.ErrCapacity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.environment != e || s.closed || s.drain != nil || !s.delivered || s.application == nil {
		return nil, cryptov4.ErrNotReady
	}
	plan := s.application
	plan.mu.Lock()
	defer plan.mu.Unlock()
	if plan.closed || !plan.claimed || plan.queries == nil || plan.queries.initiator.Load() == nil {
		return nil, cryptov4.ErrNotReady
	}
	for _, ref := range refs {
		if err := ref.CheckSameEnvironment(e.reservation); err != nil {
			return nil, err
		}
	}
	source := &contractQuerySourceProtection{session: s, plan: plan}
	installed := false
	defer func() {
		if !installed {
			source.closeLocked()
			source.outputScope.Release()
			source.backing.Release()
		}
	}()
	source.outputScope, err = p.output.BorrowScope(refs[0])
	if err != nil {
		return nil, err
	}
	source.backing, err = refs[0].Take(charges[0])
	if err != nil {
		return nil, err
	}
	source.lane, err = plan.queries.initiator.Load().ProtectRenewal(refs[1])
	if err != nil {
		return nil, err
	}
	borrow, err := plan.reservation.Borrow()
	if err != nil {
		return nil, err
	}
	defer borrow.Release()
	source.worker, err = plan.executor.protectSDKQuery(&plan.queries.group, refs[2], borrow)
	if err != nil {
		return nil, err
	}
	p.sources[index], installed = source, true
	return p, nil
}
