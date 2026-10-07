package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// Controller replacement acquires and qualifies the candidate's real renewal
// vectors before its original current publication. The returned finite handoff
// holds the registration gate, not a new asynchronous owner. Failure leaves
// the old current and every existing binding's responsibility intact.
func (c *ConnectionController) prepareRenewalCurrent(session *EnvironmentSession, now timev4.Sample) (finish func(bool), err error) {
	e := c.environment
	e.renewalMu.Lock()
	entries, timing := e.collectRenewalEntriesOn(nil, nil, nil, session, c)
	matching := false
	for j := range entries {
		if entries[j].group.controller == c {
			entries[j].group.session = session
			matching = true
		}
	}
	finish = func(published bool) {
		if published {
			if matching {
				e.mu.Lock()
				if e.queryProtection != nil {
					e.queryProtection.managed = true
				}
				e.mu.Unlock()
			}
			for _, entry := range entries {
				if entry.group.controller != c {
					continue
				}
				entry.client.mu.Lock()
				if !entry.client.closed {
					entry.client.promoteCandidateContractLocked(entry.method)
					entry.client.registerRenewalLocked(entry.method, session)
				}
				entry.client.mu.Unlock()
			}
		}
		e.clearRenewalEntries()
		e.closeUnusedRenewalSources()
		e.renewalMu.Unlock()
		e.signalMaterials()
	}
	if !matching {
		return finish, nil
	}
	budget, err := qualifyContractRenewal(entries, timing)
	if err != nil {
		finish(false)
		return nil, err
	}
	for _, entry := range entries {
		if entry.group.controller != c {
			continue
		}
		entry.client.mu.Lock()
		staged, previous := entry.method.candidateContract, entry.method.offer
		entry.client.mu.Unlock()
		if staged.attempt != nil && staged.attempt.candidate == session {
			if err = budget.checkOffer(entry.offer, previous, now); err != nil {
				finish(false)
				return nil, err
			}
		}
	}
	r, _, err := session.controllerRPCIdentity()
	if err != nil {
		finish(false)
		return nil, err
	}
	for _, entry := range entries {
		if entry.group.controller != c {
			continue
		}
		_, mapped, mappingErr := session.controllerRPCIdentity(entry.group.routing.peers)
		if mappingErr != nil || entry.group.routing != mapped {
			finish(false)
			return nil, ErrApplicationAuthorization
		}
	}
	if _, err = e.ensureContractQuerySource(r, session); err != nil {
		finish(false)
		return nil, err
	}
	e.mu.Lock()
	closed := e.closed || e.queryProtection == nil || e.queryProtection.closed
	e.mu.Unlock()
	if closed {
		finish(false)
		return nil, cryptov4.ErrClosed
	}
	return finish, nil
}
