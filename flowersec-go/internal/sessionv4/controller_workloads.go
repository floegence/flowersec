package sessionv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"

type candidateMethodWorkload struct {
	attempt    *controllerAttempt
	services   *RPCServices
	generation uint64
	workload   *unaryWorkload
}

func (c *UnaryServiceClient) promoteCandidateWorkloadLocked(m *boundUnaryMethod) {
	s := m.candidateWorkload
	controller := c.source.controller
	if s.attempt == nil || controller == nil {
		return
	}
	controller.mu.Lock()
	published := s.attempt.result.CurrentSwitched
	controller.mu.Unlock()
	if !published || s.generation != m.generation {
		return
	}
	old := m.definition.Method.workload
	m.definition.Method.workload = s.workload
	m.candidateWorkload = candidateMethodWorkload{}
	if old != s.workload {
		old.seal()
	}
}

func (c *UnaryServiceClient) workloadReadyLocked(m *boundUnaryMethod, r *RPCServices) error {
	if m.workload.Calls == 0 || c.closed {
		return nil
	}
	if r == nil {
		return cryptov4.ErrNotReady
	}
	w := m.definition.Method.workload
	staged := m.candidateWorkload
	if staged.services == r && staged.generation == m.generation {
		w = staged.workload
	}
	if w == nil || w.services != r {
		return cryptov4.ErrNotReady
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.retired || w.closed || w.cleaned || len(w.slots) != int(m.workload.Calls) {
		return cryptov4.ErrNotReady
	}
	return nil
}

// Replacement uses the candidate Session's original root and table positions.
// The old Session's accepted/late/result tails remain independently charged.
// No method descriptor can silently switch to a Session lacking its target.
func (c *ConnectionController) prepareCandidateWorkloads(a *controllerAttempt, session *EnvironmentSession) error {
	if err := a.workloads.check(); err != nil {
		return err
	}
	e := c.environment
	for index := range e.serviceClients {
		e.mu.Lock()
		client := e.serviceClients[index]
		if client != nil {
			client.mu.Lock()
			if client.closed || client.cleaned || client.source.controller != c {
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
		err := client.prepareCandidateWorkloadBatch(a, session)
		client.mu.Lock()
		client.visits--
		client.mu.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *UnaryServiceClient) prepareCandidateWorkloadBatch(a *controllerAttempt, session *EnvironmentSession) error {
	r, err := c.checkControllerSourceIdentity(session, false)
	if err != nil {
		return err
	}
	for index := 0; ; index++ {
		c.mu.Lock()
		if c.closed || index >= len(c.methods) {
			c.mu.Unlock()
			return nil
		}
		m := &c.methods[index]
		if m.workload.Calls == 0 || c.workloadReadyLocked(m, r) == nil {
			c.mu.Unlock()
			continue
		}
		if c.remoteContracts && !m.candidateContract.matches(r, m.generation) {
			c.mu.Unlock()
			return cryptov4.ErrNotReady
		}
		digest := m.definition.Method.Contract
		c.mu.Unlock()
		if err := a.deadline.Check(); err != nil {
			return err
		}
		candidate, err := c.prepareWorkloadCandidate(m, digest, r, a)
		if err != nil {
			return err
		}
		err = func() error {
			defer candidate.finish()
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.closed || m.definition.Method.Contract != digest {
				return cryptov4.ErrNotReady
			}
			if err := candidate.checkLocked(m); err != nil {
				return err
			}
			controller := c.source.controller
			controller.mu.Lock()
			defer controller.mu.Unlock()
			if controller.closed || controller.attempt != a || a.finished || a.candidate != session || a.ctx.Err() != nil {
				return cryptov4.ErrNotReady
			}
			candidate.installLocked(m, r)
			return nil
		}()
		if err != nil {
			return err
		}
	}
}

// The binding gate selects the workload belonging to this exact Session. A
// streaming dependency cannot borrow an old current's transport declaration.
func (c *UnaryServiceClient) methodWorkloadLocked(m *boundUnaryMethod, r *RPCServices) *unaryWorkload {
	w := m.definition.Method.workload
	if candidate := m.candidateWorkload; candidate.services == r && candidate.generation == m.generation {
		w = candidate.workload
	}
	if w != nil && w.services == r {
		return w
	}
	return nil
}
