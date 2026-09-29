package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// One protected batch is driven incrementally by the original Environment
// coordinator. Each visit installs at most one target. Query decoding remains
// on the original fixed SDK worker; no method owns a background goroutine.
// Environment.mu serializes start/advance; advancing pins all batch fields
// while outside that gate. Close changes only the published cancel/query.
type contractRenewalBatch struct {
	entries      [8]contractRenewalEntry
	results      [8]UnaryContractSnapshot
	query        *ContractQueryAcquisition
	claim        *contractQueryClaim
	snapshots    *ContractQuerySnapshots
	services     *RPCServices
	deadline     *timev4.Deadline
	ctx          context.Context
	cancel       context.CancelFunc
	count, index int
	active       bool
	failure      error
	phase        uint8
	scheduled    bool
}

func (p *contractQueryProtection) startRenewalBatch(entries []contractRenewalEntry, budget contractRenewalBudget, deadline *timev4.Deadline) (err error) {
	if p == nil || len(entries) == 0 || len(entries) > 8 || deadline == nil || budget.Methods < uint16(len(entries)) {
		return cryptov4.ErrConfiguration
	}
	remaining, err := deadline.RemainingMS()
	if err != nil {
		return err
	}
	if budget.DeadlineMS == 0 || remaining > budget.DeadlineMS {
		return errContractRenewalQualification
	}
	e := p.environment
	e.mu.Lock()
	if p.closed || e.closed || p.advancing || p.batch.active || e.queryProtection != p {
		e.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	p.advancing = true
	e.mu.Unlock()
	defer func() { e.mu.Lock(); p.advancing = false; e.mu.Unlock(); e.signalMaterials() }()
	claim, _, err := p.reserve(entries[0].group.session)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := contractRenewalBatch{claim: claim, deadline: deadline, ctx: ctx, cancel: cancel, active: true}
	var targets [8]ServiceContractTarget
	var known [8]protocolv4.ContractQueryKnown
	for j, entry := range entries {
		if entry.client == nil || entry.method == nil || entry.group.session != p.session || entry.group != entries[0].group {
			err = cryptov4.ErrConfiguration
			break
		}
		for _, earlier := range entries[:j] {
			if entry.namespace == earlier.namespace && entry.typeID == earlier.typeID {
				err = cryptov4.ErrConfiguration
				break
			}
		}
		if err != nil {
			break
		}
		c := entry.client
		c.mu.Lock()
		m, findErr := c.methodLocked(entry.typeID)
		if findErr != nil {
			err = findErr
		} else if m != entry.method || c.environment != e || c.namespace != entry.namespace || !c.remoteContracts || !m.installed || m.definition.Method.Contract != entry.digest || m.offer.Digest != entry.digest || c.source.controller != entry.group.controller {
			err = cryptov4.ErrNotReady
		} else if m.update.done != nil {
			err = ErrContractUpdateInProgress
		}
		if err == nil {
			m.update = serviceContractUpdate{target: entry.digest, done: make(chan struct{}), active: true, renewal: true, renewalBudget: budget}
			c.visits++
			b.entries[b.count] = entry
			b.count++
			known[j] = m.known
			targets[j] = ServiceContractTarget{Namespace: entry.namespace, Type: entry.typeID, Wanted: entry.digest, HasWanted: true}
		}
		c.mu.Unlock()
		if err != nil {
			break
		}
		s, r, sourceErr := c.remoteSource()
		if sourceErr != nil {
			err = sourceErr
			break
		}
		if s != p.session || b.services != nil && b.services != r {
			err = cryptov4.ErrNotReady
			break
		}
		b.services = r
		r.mu.Lock()
		routes := r.routes
		closed := r.closed || r.retired || r.draining.Load()
		r.mu.Unlock()
		if closed || routes == nil {
			err = cryptov4.ErrClosed
			break
		}
		targets[j].MaxOfferWindowMS, err = routes.QueryOfferWindow(entry.digest)
		if err != nil {
			break
		}
	}
	if err == nil {
		b.query, err = p.session.beginServiceContractQueryUntil(ctx, targets[:b.count], deadline, claim, known[:b.count])
	}
	if err != nil {
		for j := 0; j < b.count; j++ {
			finishRenewalMethod(&b, j, err)
		}
		cancel()
		claim.release()
		for _, entry := range b.entries[:b.count] {
			entry.client.mu.Lock()
			entry.client.visits--
			entry.client.mu.Unlock()
		}
		return err
	}
	for _, entry := range b.entries[:b.count] {
		entry.client.mu.Lock()
		entry.method.update.query = b.query
		entry.client.mu.Unlock()
	}
	e.mu.Lock()
	p.batch = b
	if p.closed || e.closed {
		cancel()
		b.query.Close()
	}
	e.mu.Unlock()
	return nil
}

// Called with the batch's exclusive coordinator visit, never Environment.mu.
func finishRenewalMethod(b *contractRenewalBatch, index int, failure error) {
	entry := b.entries[index]
	c := entry.client
	if failure != nil {
		b.results[index] = c.remoteFailure(entry.typeID, failure)
	}
	c.mu.Lock()
	u := &entry.method.update
	u.snapshot, u.err, u.active, u.cancel = b.results[index], failure, false, nil
	close(u.done)
	if u.query == nil && u.waiters == 0 {
		*u = serviceContractUpdate{}
	}
	c.mu.Unlock()
}

// Background and explicit Refresh share the same method flight and original
// absolute deadline. Closing or replacing a method revokes installation only;
// this owner waits for the real output/provider/consumer tails before reuse.
func (e *Environment) advanceContractRenewalBatch() bool {
	e.mu.Lock()
	p := e.queryProtection
	if p == nil || p.advancing || !p.batch.active {
		e.mu.Unlock()
		return false
	}
	p.advancing = true
	e.mu.Unlock()
	b := &p.batch
	defer func() { e.mu.Lock(); p.advancing = false; e.mu.Unlock() }()
	switch b.phase {
	case 0:
		wanted := false
		for _, entry := range b.entries[:b.count] {
			entry.client.mu.Lock()
			wanted = wanted || !entry.client.closed && !entry.method.update.superseded
			entry.client.mu.Unlock()
		}
		if !wanted {
			b.cancel()
			b.query.Close()
		}
		select {
		case <-b.query.ready:
		default:
			return true
		}
		b.snapshots, b.failure = b.query.Take()
		b.phase = 1
	case 1:
		failure := b.failure
		entry := b.entries[b.index]
		if failure == nil {
			failure = entry.client.installRemote(b.ctx, entry.method, b.snapshots, b.index, p.session, b.services, b.deadline, &b.results[b.index])
		}
		finishRenewalMethod(b, b.index, failure)
		b.index++
		if b.index == b.count {
			if b.snapshots != nil {
				b.snapshots.Close()
				b.snapshots = nil
			}
			b.claim.release()
			b.query.Close()
			b.phase = 2
		}
	case 2:
		select {
		case <-b.query.done:
		default:
			return true
		}
		b.cancel()
		e.finishManagedRenewalBatch(p)
		for _, entry := range b.entries[:b.count] {
			c := entry.client
			c.mu.Lock()
			u := &entry.method.update
			if u.query == b.query {
				u.query = nil
				if !u.active && u.waiters == 0 {
					*u = serviceContractUpdate{}
				}
			}
			c.visits--
			c.mu.Unlock()
		}
		e.mu.Lock()
		*b = contractRenewalBatch{}
		e.mu.Unlock()
	}
	return true
}
