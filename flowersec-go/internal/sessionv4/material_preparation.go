package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// materialPreparation pins the original lease while credential-free candidate
// work runs. It is embedded in the admitted source owner. A local exclusive
// preparation is reversible until establishment claims the selected winner;
// neither operation asserts a durable spend.
type materialPreparation struct {
	material *ConnectionMaterial
	indices  [16]uint64
	count    int
	attempt  [16]byte
	budget   protocolv4.PoolAttemptLimits
}

func (p *materialPreparation) begin(m *ConnectionMaterial, generation MaterialGeneration, attempt [16]byte) (err error) {
	if err = p.claim(m, generation, attempt, nil, "", MaterialRequirements{}); err != nil {
		return err
	}
	return p.validate()
}

// claim is a finite local transfer gate. The static Environment path calls it
// before starting asynchronous preparation; no key, clock or provider callback
// may run here. Its rollback leaves an unclosed, unused material with its caller.
func (p *materialPreparation) claim(m *ConnectionMaterial, generation MaterialGeneration, attempt [16]byte, environment *Environment, source string, requirements MaterialRequirements) error {
	if m == nil || p.material != nil || attempt == ([16]byte{}) {
		return cryptov4.ErrConfiguration
	}
	m.mu.Lock()
	if m.closed || m.used || m.building || m.generation != generation {
		m.mu.Unlock()
		return cryptov4.ErrTransition
	}
	l := m.lease.lease
	if environment != nil {
		if m.environment != environment || m.identity.identity.role != protocolv4.ClientToServer {
			m.mu.Unlock()
			return resourcev4.ErrOwner
		}
		if err := m.reservation.CheckSameEnvironment(environment.reservation); err != nil {
			m.mu.Unlock()
			return err
		}
		limits := l.session.Contract.Limits()
		if l.source != source || limits.ApplicationProfile != requirements.ApplicationProfile || limits.RPCMaxGeneralOutstanding != requirements.RPCMaxGeneralOutstanding {
			m.mu.Unlock()
			return ErrSourceContractInvalid
		}
	}
	l.mu.Lock()
	if l.claimed || l.preparing != nil {
		l.mu.Unlock()
		m.mu.Unlock()
		return cryptov4.ErrTransition
	}
	l.preparing = m
	l.mu.Unlock()
	m.building, m.preparing = true, true
	p.material, p.attempt = m, attempt
	m.mu.Unlock()
	return nil
}

// validate uses the original admitted preparation worker and deadline. It may
// invoke the captured key provider, and keeps the claimed material through its
// actual return even when cancellation or expiry seals the original owner.
func (p *materialPreparation) validate() (err error) {
	m := p.material
	if m == nil {
		return cryptov4.ErrConfiguration
	}
	l, attempt := m.lease.lease, p.attempt
	complete := false
	defer func() {
		if !complete {
			p.close()
		}
	}()
	if err = m.check(); err != nil {
		return err
	}
	if l.source == "preauthorized_pool" {
		var ok bool
		p.count, ok = l.maps[1].Field("candidate_selection").Named("PoolSelectionRef", "candidate_indices").CopyUints(p.indices[:])
		if !ok || p.count == 0 {
			return cryptov4.ErrConfiguration
		}
		binding, authority, e := l.activation(p.indices[0])
		if e != nil {
			return e
		}
		if e = binding.MatchOriginal(l.session, attempt, binding.Winner()); e != nil {
			return e
		}
		wire, e := l.maps[1].Bytes()
		if e != nil {
			return e
		}
		facts, e := authority.PoolSpendFacts(wire)
		if e != nil {
			return e
		}
		fields, e := facts.Fields()
		if e != nil {
			return e
		}
		p.budget = fields.Budget
	} else {
		p.count = l.maps[0].Field("candidates").Len()
		if p.count == 0 || p.count > len(p.indices) {
			return cryptov4.ErrConfiguration
		}
		for i := range p.count {
			p.indices[i] = uint64(i)
		}
		// The live projection is issued only after selection. These are the
		// finite local preparation ceilings; a pool additionally narrows them
		// with its independently verified issuance-time budget above.
		p.budget = protocolv4.PoolAttemptLimits{CandidateAddressAttempts: 2, CandidatePreauthBytes: 262144, CandidateWorkUnits: 256, TotalAddressAttempts: 32, TotalPreauthBytes: 8388608, TotalWorkUnits: 8192, ParallelCandidates: 2}
	}
	complete = true
	return nil
}

// candidate copies only the signed public route. No private identity, proof,
// Artifact or activation capability crosses the carrier provider boundary.
func (p *materialPreparation) candidate(position int, dst []byte) (protocolv4.PoolMember, []byte, error) {
	if p.material == nil || position < 0 || position >= p.count {
		return protocolv4.PoolMember{}, nil, cryptov4.ErrConfiguration
	}
	m := p.material
	if err := m.check(); err != nil {
		return protocolv4.PoolMember{}, nil, err
	}
	l, index := m.lease.lease, p.indices[position]
	// Tunnel preparation must have its grant/leg owners before it is enabled.
	if err := l.maps[0].CheckDirectListenerCandidate(index); err != nil {
		return protocolv4.PoolMember{}, nil, err
	}
	closure, err := protocolv4.BindEndpointCredentials(protocolv4.ClientToServer, l.maps[0], index, l.maps[2], l.maps[3], nil, nil)
	if err != nil {
		return protocolv4.PoolMember{}, nil, err
	}
	if _, err = closure.CheckCurrent(l.validation[:], l.session.SessionNotAfterMS); err != nil {
		return protocolv4.PoolMember{}, nil, err
	}
	wire, digest, err := l.maps[0].CopyCandidateRoute(index, dst)
	if err != nil {
		return protocolv4.PoolMember{}, nil, err
	}
	id, ok := l.maps[0].Field("candidates").Index(int(index)).Named("Candidate", "candidate_id").ByteString()
	if !ok || len(id) != 16 {
		return protocolv4.PoolMember{}, nil, cryptov4.ErrConfiguration
	}
	return protocolv4.PoolMember{Index: index, CandidateID: [16]byte(id), RouteDigest: digest}, wire, nil
}

// The source calls close only after every original preparation method and
// loser cleanup exits. Closing material cannot release a still-borrowed route.
func (p *materialPreparation) close() {
	m := p.material
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.preparing {
		l := m.lease.lease
		l.mu.Lock()
		if l.preparing == m {
			l.preparing = nil
		}
		l.mu.Unlock()
		m.preparing, m.building = false, false
		m.cleanupLocked()
	}
	m.mu.Unlock()
	*p = materialPreparation{}
}
