package sessionv4

import (
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// Runs on the existing Environment coordinator and owns no goroutine, queue,
// timer or connection. Clock sampling precedes the registration/owner gates.
func (e *Environment) advanceManagedContractRenewal() bool {
	e.mu.Lock()
	p, clock := e.queryProtection, e.materialClock
	active := p != nil && p.managed && !p.closed && !e.closed
	e.mu.Unlock()
	if !active {
		return false
	}
	now, sampleErr := clock.Sample()
	e.renewalMu.Lock()
	defer e.renewalMu.Unlock()
	defer e.closeUnusedRenewalSources()
	e.mu.Lock()
	if e.queryProtection != p || p.closed || e.closed || p.advancing || p.batch.active || e.queries[p.index] != nil || e.queryClaims[p.index] != nil {
		e.mu.Unlock()
		return true
	}
	e.mu.Unlock()
	entries, timing := e.collectRenewalEntries(nil, nil, nil, nil)
	defer e.clearRenewalEntries()
	if len(entries) == 0 {
		return false
	}
	if sampleErr != nil {
		return true
	}
	// Capture one existing source per service. A missing or unauthorized
	// source stays in the complete qualification set with its last real group.
	var previous *UnaryServiceClient
	var selected *EnvironmentSession
	var services *RPCServices
	var sourceErr error
	for j := range entries {
		entry := &entries[j]
		if entry.client != previous {
			previous = entry.client
			selected, services, sourceErr = entry.client.remoteSource()
			if sourceErr == nil {
				services.mu.Lock()
				if services.closed || services.retired || services.draining.Load() || services.rpcPublisherLocked() == nil {
					sourceErr = cryptov4.ErrNotReady
				}
				services.mu.Unlock()
			}
		}
		if sourceErr != nil {
			entry.blocked = true
			entry.client.mu.Lock()
			entry.method.renewal.lastError = sourceErr
			entry.client.mu.Unlock()
			continue
		}
		entry.group.session = selected
	}
	budget, err := qualifyContractRenewal(entries, timing)
	if err != nil {
		for _, entry := range entries {
			entry.client.mu.Lock()
			entry.method.renewal.lastError = err
			entry.client.mu.Unlock()
		}
		return true
	}
	// Acquire the new Session's original vectors before moving its future
	// responsibility. Old physical tails remain protected independently.
	previous = nil
	for j := range entries {
		entry := &entries[j]
		if entry.blocked {
			continue
		}
		if entry.client != previous {
			previous = entry.client
			selected, services, sourceErr = entry.client.remoteSource()
			if sourceErr == nil && selected != entry.group.session {
				sourceErr = cryptov4.ErrNotReady
			}
			if sourceErr == nil {
				_, sourceErr = e.ensureContractQuerySource(services, selected)
			}
		}
		if sourceErr != nil {
			entry.blocked = true
			continue
		}
		entry.client.mu.Lock()
		if entry.client.closed || !entry.method.renewal.registered {
			entry.blocked = true
		} else {
			entry.method.renewal.group = entry.group
		}
		entry.client.mu.Unlock()
	}
	round := &p.round
	if round.deadline != nil {
		if err := round.deadline.CheckAt(now); err != nil {
			for j := range entries {
				entry := &entries[j]
				if round.contains(entry.method) {
					entry.client.mu.Lock()
					renewalBackoff(entry.method, now.UpperMS, err)
					entry.method.renewal.exhausted = true
					entry.nextAttemptMS = entry.method.renewal.nextAttemptMS
					entry.blocked = true
					entry.client.mu.Unlock()
				}
			}
			*round = contractRenewalRound{serial: round.serial}
		}
	}
	if round.deadline == nil {
		if round.serial == math.MaxUint64 {
			return true
		}
		count := 0
		for _, entry := range entries {
			if !entry.blocked && !entry.busy && entry.nextAttemptMS <= now.UpperMS && renewalDue(entry, budget, now.UpperMS) {
				entry.client.mu.Lock()
				entry.method.renewal.pendingRound = round.serial + 1
				entry.client.mu.Unlock()
				count++
			}
		}
		if count == 0 {
			return true
		}
		deadline, err := timev4.NewAgeAt(clock, now, budget.DeadlineMS, math.MaxUint64)
		if err != nil {
			*round = contractRenewalRound{serial: round.serial + 1}
			return true
		}
		round.deadline, round.budget, round.serial = deadline, budget, round.serial+1
	}
	// Removing a closed method cannot leave a forever pending round. New
	// registrations wait for the next original round; they do not restart it.
	remaining := 0
	for _, entry := range entries {
		if round.contains(entry.method) {
			remaining++
		}
	}
	if remaining == 0 {
		*round = contractRenewalRound{serial: round.serial}
		return true
	}
	for j := range entries {
		if !round.contains(entries[j].method) {
			entries[j].busy = true
		}
	}
	cursor := 0
	for cursor < len(entries) && entries[cursor].index < e.renewalCursor {
		cursor++
	}
	if cursor == len(entries) {
		cursor = 0
	}
	// Membership is fixed by the original round, while current complete-set
	// qualification can tighten admission for later registrations separately.
	selectionBudget := round.budget
	selectionBudget.Methods = uint16(len(entries))
	indices, count, next, err := selectContractRenewalBatch(entries, selectionBudget, now.UpperMS, cursor)
	if err != nil || count == 0 {
		return true
	}
	e.renewalCursor = entries[next].index
	var batch [8]contractRenewalEntry
	for j, i := range indices[:count] {
		batch[j] = entries[i]
	}
	err = p.startRenewalBatch(batch[:count], round.budget, round.deadline)
	if err != nil {
		for _, entry := range batch[:count] {
			entry.client.mu.Lock()
			renewalBackoff(entry.method, now.UpperMS, err)
			entry.client.mu.Unlock()
		}
	} else {
		e.mu.Lock()
		p.batch.scheduled = true
		e.mu.Unlock()
	}
	return true
}

func renewalDue(e contractRenewalEntry, b contractRenewalBudget, now uint64) bool {
	return e.offer.NotAfterMS <= now || e.offer.NotAfterMS-now <= b.AdvanceMS
}

func (r *contractRenewalRound) contains(m *boundUnaryMethod) bool {
	return r.serial != 0 && m.renewal.pendingRound == r.serial
}

// A completed batch remains the same round through actual cleanup. Success
// retires only that target; failure keeps its original deadline and backoff.
func (e *Environment) finishManagedRenewalBatch(p *contractQueryProtection) {
	b := &p.batch
	if !b.scheduled {
		return
	}
	now, err := e.materialClock.Sample()
	e.renewalMu.Lock()
	defer e.renewalMu.Unlock()
	for j, entry := range b.entries[:b.count] {
		c := entry.client
		c.mu.Lock()
		if b.results[j].Error == nil || c.closed || !entry.method.renewal.registered {
			entry.method.renewal.pendingRound = 0
		} else if err == nil {
			renewalBackoff(entry.method, now.UpperMS, b.results[j].Error)
		}
		c.mu.Unlock()
	}
}
