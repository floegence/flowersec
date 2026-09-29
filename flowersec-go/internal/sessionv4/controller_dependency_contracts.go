package sessionv4

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// Exact replacement preparation borrows the method's already charged immutable
// canonical body. These finite source/Offer facts occupy its original slot;
// they do not replace current's snapshot or create another contract registry.
type candidateContractSnapshot struct {
	attempt    *controllerAttempt
	services   *RPCServices
	generation uint64
	offer      protocolv4.AdmissionOfferBounds
}

func (s candidateContractSnapshot) matches(r *RPCServices, generation uint64) bool {
	return s.attempt != nil && s.services == r && s.generation == generation
}

// Called with the binding gate held. The original current publication is the
// linearization point; a failed attempt can never install its private Offer.
// A caller racing publication observes the corresponding original snapshot.
func (c *UnaryServiceClient) promoteCandidateContractLocked(m *boundUnaryMethod) {
	c.promoteCandidateWorkloadLocked(m)
	s := m.candidateContract
	if s.attempt == nil || c.source.controller == nil {
		return
	}
	controller := c.source.controller
	controller.mu.Lock()
	published := s.attempt.result.CurrentSwitched
	controller.mu.Unlock()
	if published && s.generation == m.generation {
		if !m.installed {
			m.generation++
		}
		m.installed, m.offer = true, s.offer
		m.dependencyPath = dependencyPathPreparation{}
		m.candidateContract = candidateContractSnapshot{}
	}
}

// The existing attempt task uses ordinary query capacity and the method's
// original single-flight. Each actual query contains at most eight targets,
// and every batch retains the attempt's fixed deadline. It does no Acquire,
// discovery, application execution or current publication.
func (c *ConnectionController) prepareCandidateContracts(a *controllerAttempt, session *EnvironmentSession) error {
	e := c.environment
	for index := range e.serviceClients {
		e.mu.Lock()
		client := e.serviceClients[index]
		if client != nil {
			client.mu.Lock()
			if client.closed || client.cleaned || !client.remoteContracts || client.source.controller != c {
				client.mu.Unlock()
				client = nil
			} else {
				client.visits++
				client.mu.Unlock()
			}
		}
		e.mu.Unlock()
		if client == nil {
			continue
		}
		err := client.prepareCandidateContractBatch(a, session)
		client.mu.Lock()
		client.visits--
		client.mu.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *UnaryServiceClient) prepareCandidateContractBatch(a *controllerAttempt, session *EnvironmentSession) error {
	r, err := c.checkControllerSourceIdentity(session, false)
	if err != nil {
		return err
	}
	var batch [8]*boundUnaryMethod
	var targets [8]ServiceContractTarget
	var output [8]UnaryContractSnapshot
	c.mu.Lock()
	count, pending := 0, false
	for i := range c.methods {
		m := &c.methods[i]
		if (m.requiredDeclarations.Load() == 0 && m.workload.Calls == 0) || m.candidateContract.matches(r, m.generation) {
			continue
		}
		pending = true
		if m.update.done != nil {
			continue
		}
		batch[count] = m
		count++
		if count == len(batch) {
			break
		}
	}
	c.mu.Unlock()
	if !pending {
		return nil
	}
	if count == 0 {
		return cryptov4.ErrNotReady
	}
	if err = a.deadline.Check(); err != nil {
		return err
	}
	if err = r.prepareDependencyChannel(a.ctx, false, a.deadline); err != nil {
		return err
	}
	claim, err := c.environment.reserveContractQuery()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(a.ctx)
	defer cancel()
	c.mu.Lock()
	selected := count
	count = 0
	if !c.closed {
		for _, m := range batch[:selected] {
			if (m.requiredDeclarations.Load() == 0 && m.workload.Calls == 0) || m.update.done != nil || m.candidateContract.matches(r, m.generation) {
				continue
			}
			m.update = serviceContractUpdate{target: m.definition.Method.Contract, done: make(chan struct{}), active: true, cancel: cancel, dependency: true, candidate: a}
			batch[count] = m
			targets[count] = ServiceContractTarget{Namespace: c.namespace, Type: m.definition.Type, Wanted: m.definition.Method.Contract, HasWanted: true}
			count++
		}
	}
	c.mu.Unlock()
	if count == 0 {
		claim.release()
		return cryptov4.ErrNotReady
	}
	c.fetchRemoteBatchOn(ctx, batch[:count], targets[:count], output[:count], a.deadline, claim, session, r, nil)
	for i := 0; i < count; i++ {
		if output[i].Error != nil {
			c.mu.Lock()
			wanted := !c.closed && (batch[i].requiredDeclarations.Load() != 0 || batch[i].workload.Calls != 0)
			c.mu.Unlock()
			if wanted {
				if errors.Is(output[i].Error, ErrContractUpdateInProgress) {
					// An explicit update owns the method next. Keep this same
					// attempt/deadline and requalify its resulting exact digest.
					return cryptov4.ErrNotReady
				}
				return output[i].Error
			}
		}
	}
	// The next bounded attempt wake visits any remaining methods. Path and
	// publication qualification still require the entire live declared union.
	return cryptov4.ErrNotReady
}

func (c *ConnectionController) finishCandidateContracts(a *controllerAttempt) {
	e := c.environment
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, client := range e.serviceClients {
		if client == nil {
			continue
		}
		client.mu.Lock()
		if client.source.controller == c {
			for i := range client.methods {
				m := &client.methods[i]
				if m.candidateWorkload.attempt == a {
					client.promoteCandidateWorkloadLocked(m)
					m.candidateWorkload.workload.seal()
					m.candidateWorkload = candidateMethodWorkload{}
				}
				if m.candidateContract.attempt == a {
					client.promoteCandidateContractLocked(m)
					m.candidateContract = candidateContractSnapshot{}
				}
			}
		}
		client.mu.Unlock()
	}
}
