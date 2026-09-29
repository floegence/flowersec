package sessionv4

import (
	"context"
	"math"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type ServiceOfferRefresh uint8

const (
	ServiceOfferRefreshExplicit ServiceOfferRefresh = iota
	ServiceOfferRefreshManaged
)

// ContractRenewalPolicy is a trusted deployment qualification, not a promise
// inferred from peer Offer bytes or a measured fast request. BatchMS includes
// complete acquisition, installation and physical cleanup. The other bounds
// cover the complete round, including allowed rekey/runtime suspension.
type ContractRenewalPolicy struct {
	BatchMS, JoinMS, SuspensionMS, TimeErrorMS uint64
	SourceRemainingMS                          uint64
}

type contractRenewalMethod struct {
	group         contractRenewalGroup
	registered    bool
	nextAttemptMS uint64
	failures      uint8
	lastError     error
	pendingRound  uint64
	exhausted     bool
}

// All round state is protected by Environment.renewalMu. Pending identities
// are retained as original method indices, never copied contracts or jobs.
// Registration can grow the next round without restarting this deadline.
type contractRenewalRound struct {
	deadline *timev4.Deadline
	budget   contractRenewalBudget
	serial   uint64
}

func contractRenewalDeadlineBytes() uint64 { return uint64(unsafe.Sizeof(timev4.Deadline{})) }

func mergeRenewalTiming(t *contractRenewalTiming, p ContractRenewalPolicy) {
	t.BatchMS = max(t.BatchMS, p.BatchMS)
	t.JoinMS = max(t.JoinMS, p.JoinMS)
	t.SuspensionMS = max(t.SuspensionMS, p.SuspensionMS)
	t.TimeErrorMS = max(t.TimeErrorMS, p.TimeErrorMS)
}

// The fixed scratch index is charged with the original Environment. All
// callers hold renewalMu, and discard aliases before releasing that gate.
// A projected install participates before current is changed, so a growing
// complete responsibility set cannot be published on optimistic timing.
func (e *Environment) collectRenewalEntries(candidate *UnaryServiceClient, replacement *boundUnaryMethod, info *protocolv4.ContractSnapshotInfo, session *EnvironmentSession) ([]contractRenewalEntry, contractRenewalTiming) {
	return e.collectRenewalEntriesOn(candidate, replacement, info, session, nil)
}

func (e *Environment) collectRenewalEntriesOn(candidate *UnaryServiceClient, replacement *boundUnaryMethod, info *protocolv4.ContractSnapshotInfo, session *EnvironmentSession, controller *ConnectionController) ([]contractRenewalEntry, contractRenewalTiming) {
	e.mu.Lock()
	defer e.mu.Unlock()
	entries := e.renewalEntries[:0]
	var timing contractRenewalTiming
	for serviceIndex, c := range e.serviceClients {
		if c == nil {
			continue
		}
		c.mu.Lock()
		if c.closed || c.cleaned || !c.managedRenewal || !c.renewalPublished && c != candidate {
			c.mu.Unlock()
			continue
		}
		for j := range c.methods {
			m := &c.methods[j]
			offer, digest, installed := m.offer, m.definition.Method.Contract, m.installed
			staged := m.candidateContract
			projected := controller != nil && c.source.controller == controller && staged.attempt != nil && staged.attempt.candidate == session && staged.generation == m.generation
			if projected {
				offer, installed = staged.offer, true
			}
			if c == candidate && m == replacement && info != nil {
				offer, digest, installed = info.Offer, info.Policy.Digest, true
			}
			if !installed || offer.Digest == ([32]byte{}) {
				continue
			}
			group := m.renewal.group
			if !m.renewal.registered || c == candidate && (replacement == nil || m == replacement) {
				group = contractRenewalGroup{session: session, controller: c.source.controller, routing: c.source.routing}
			}
			if controller != nil && c.source.controller == controller {
				group = contractRenewalGroup{session: session, controller: controller, routing: c.source.routing}
			}
			remaining := c.renewalPolicy.SourceRemainingMS
			if c.renewalPolicy.BatchMS == 0 {
				remaining = 0
			}
			entries = append(entries, contractRenewalEntry{client: c, method: m, group: group, namespace: c.namespace, typeID: m.definition.Type, digest: digest, offer: offer, sourceRemainingMS: remaining, busy: m.update.done != nil, blocked: m.renewal.exhausted, nextAttemptMS: m.renewal.nextAttemptMS, index: uint16(serviceIndex*256 + j)})
			c.visits++
			mergeRenewalTiming(&timing, c.renewalPolicy)
		}
		c.mu.Unlock()
	}
	e.renewalEntries = entries
	return entries, timing
}

func (e *Environment) clearRenewalEntries() {
	for _, entry := range e.renewalEntries {
		entry.client.mu.Lock()
		entry.client.visits--
		entry.client.mu.Unlock()
	}
	clear(e.renewalEntries)
	e.renewalEntries = e.renewalEntries[:0]
}

// closeUnusedRenewalSources drops only future opportunities. An original
// active batch or output/provider tail retains its source and physical index.
func (e *Environment) closeUnusedRenewalSources() {
	e.mu.Lock()
	defer e.mu.Unlock()
	p := e.queryProtection
	if p == nil || !p.managed {
		return
	}
	var wanted [256]bool
	any := false
	for _, c := range e.serviceClients {
		if c == nil {
			continue
		}
		c.mu.Lock()
		if !c.closed && c.renewalPublished && c.managedRenewal {
			for j := range c.methods {
				m := &c.methods[j]
				if !m.renewal.registered {
					continue
				}
				any = true
				for k, source := range p.sources {
					if source != nil && source.session == m.renewal.group.session {
						wanted[k] = true
					}
				}
			}
		}
		c.mu.Unlock()
	}
	if !any {
		p.closeLocked()
		p.round = contractRenewalRound{}
		return
	}
	for j, source := range p.sources {
		if source == nil || wanted[j] {
			continue
		}
		if (p.advancing || p.batch.active || e.queries[p.index] != nil || e.queryClaims[p.index] != nil || !p.output.UseComplete()) && source.session == p.session {
			continue
		}
		source.closeLocked()
		if source.worker.cleanupComplete() {
			source.outputScope.Release()
			source.backing.Release()
			p.sources[j] = nil
		}
	}
}

// prepareManagedPublication is called only after the final initial query has
// released its consumer and exited. It establishes the complete future floor
// before the same source/origin handoff makes the client visible.
func (c *UnaryServiceClient) prepareManagedPublication(session *EnvironmentSession, r *RPCServices, now timev4.Sample) (contractRenewalBudget, error) {
	e := c.environment
	entries, timing := e.collectRenewalEntries(c, nil, nil, session)
	defer e.clearRenewalEntries()
	budget, err := qualifyContractRenewal(entries, timing)
	if len(entries) == 0 {
		return budget, nil
	}
	if err != nil {
		return budget, err
	}
	hasExecution := false
	for _, entry := range entries {
		if entry.client != c {
			continue
		}
		hasExecution = true
		if err = budget.checkOffer(entry.offer, protocolv4.AdmissionOfferBounds{}, now); err != nil {
			return budget, err
		}
	}
	if hasExecution {
		p, err := e.ensureContractQuerySource(r, session)
		if err != nil {
			return budget, err
		}
		e.mu.Lock()
		p.managed = true
		e.mu.Unlock()
	}
	return budget, nil
}

// Called with the method and source installation gates held and renewalMu
// outside them. Only actual execution snapshots register responsibilities.
func (c *UnaryServiceClient) registerRenewalLocked(m *boundUnaryMethod, session *EnvironmentSession) {
	if !c.managedRenewal || !c.renewalPublished {
		return
	}
	if m.offer.Digest == ([32]byte{}) {
		m.renewal = contractRenewalMethod{}
		return
	}
	m.renewal.group = contractRenewalGroup{session: session, controller: c.source.controller, routing: c.source.routing}
	m.renewal.registered = true
	m.renewal.failures, m.renewal.nextAttemptMS, m.renewal.lastError = 0, 0, nil
	m.renewal.exhausted = false
}

func renewalBackoff(m *boundUnaryMethod, now uint64, failure error) {
	if m.renewal.failures < 6 {
		m.renewal.failures++
	}
	delay := uint64(1000) << (m.renewal.failures - 1)
	m.renewal.nextAttemptMS = math.MaxUint64
	if now <= math.MaxUint64-delay {
		m.renewal.nextAttemptMS = now + delay
	}
	m.renewal.lastError = failure
}

// Managed configuration participates in every later explicit installation.
// Its source guarantee remains trusted local input; a long peer Offer alone
// cannot qualify a new responsibility or silently widen an existing policy.
func (c *UnaryServiceClient) prepareManagedInstall(m *boundUnaryMethod, info protocolv4.ContractSnapshotInfo, session *EnvironmentSession, r *RPCServices, now timev4.Sample) error {
	c.mu.Lock()
	active := c.managedRenewal && c.renewalPublished
	previous := m.offer
	c.mu.Unlock()
	if !active || !info.HasOffer {
		return nil
	}
	entries, timing := c.environment.collectRenewalEntries(c, m, &info, session)
	defer c.environment.clearRenewalEntries()
	budget, err := qualifyContractRenewal(entries, timing)
	if err != nil {
		return err
	}
	if previous.Digest != info.Offer.Digest {
		previous = protocolv4.AdmissionOfferBounds{}
	}
	if err = budget.checkOffer(info.Offer, previous, now); err != nil {
		return err
	}
	p, err := c.environment.ensureContractQuerySource(r, session)
	if err != nil {
		return err
	}
	c.environment.mu.Lock()
	p.managed = true
	c.environment.mu.Unlock()
	return nil
}

// managedPublication holds the one registration gate across complete-set
// qualification and the caller's original authenticated SDK-only handoff.
func (c *UnaryServiceClient) managedPublication(ctx context.Context, session *EnvironmentSession, r *RPCServices, now timev4.Sample, action func() error) error {
	e := c.environment
	e.renewalMu.Lock()
	defer e.renewalMu.Unlock()
	defer e.closeUnusedRenewalSources()
	if c.managedRenewal {
		if _, err := c.prepareManagedPublication(session, r, now); err != nil {
			return err
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.retired {
		return cryptov4.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return action()
}

// Public callers receive the same finite local projection for failures; the
// renewal coordinator never changes a method's current window on failure.
var ErrContractRenewalQualification = errContractRenewalQualification

func (c *UnaryServiceClient) checkRenewalProtectionLocked(session *EnvironmentSession) error {
	if !c.managedRenewal {
		return nil
	}
	// The registration gate prevents removal while this publication runs.
	p := c.environment.queryProtection
	if p == nil || p.closed || p.sourceLocked(session) == nil {
		return cryptov4.ErrNotReady
	}
	return nil
}
