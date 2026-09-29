package protocolv4

import "math"

// DirectIssueRetirementEvidence is an observation of the actual authenticated
// active full State and its original Head. It cannot be submitted as an input
// permission; every retirement transaction obtains this proof from the owner.
type DirectIssueRetirementEvidence struct {
	Head, State                       [32]byte
	ConnectionFloor, LowerMS, UpperMS uint64
}

// ProveRetirement uses the namespace's maximum complete connection impact,
// not just this Artifact's shorter Session end. Both the installed full State
// and observed frontier must cover the original cohort. Original issuer
// retirement does not suppress this history check or grant a signing right.
func (p *DirectIssuePolicy) ProveRetirement(f DirectIssueFacts) (proof DirectIssueRetirementEvidence, ready bool, err error) {
	if err = p.CheckHistoricalFacts(f); err != nil {
		return proof, false, err
	}
	if err = p.trust.Policy(p.policy); err != nil {
		return proof, false, err
	}
	p.trust.mu.Lock()
	n := p.trust.namespace
	p.trust.mu.Unlock()
	if n == nil {
		return proof, false, CBORFailure("revocation_namespace_owner")
	}
	now, err := n.sampleCurrent()
	if err != nil {
		return proof, false, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.active == nil || n.observed == nil || n.rules != p.rules {
		return proof, false, CBORFailure("revocation_state_owner")
	}
	if err = n.continuityAvailable(); err != nil {
		return proof, false, err
	}
	err = n.checkAvailable()
	if err != nil {
		return proof, false, err
	}
	head := n.active.head
	if head.generation != f.Scope.Generation || n.observed.generation != f.Scope.Generation {
		return proof, false, CBORFailure("revocation_namespace_binding")
	}
	if err = n.checkHeadAt(head, now); err != nil {
		return proof, false, err
	}
	requirement := p.policy.Requirements()
	if _, err = head.Deadline(requirement.StalenessMS, requirement.SignerLifetimeMS, math.MaxUint64, now.Interval); err != nil {
		return proof, false, err
	}
	mature, err := p.rules.mature(1, f.Scope.Cohort)
	if err != nil {
		return proof, false, err
	}
	if head.floors[1] <= f.Scope.Cohort || n.observed.floors[1] <= f.Scope.Cohort || now.LowerMS < mature {
		return proof, false, nil
	}
	return DirectIssueRetirementEvidence{Head: head.digest, State: head.stateDigest, ConnectionFloor: head.floors[1], LowerMS: now.LowerMS, UpperMS: now.UpperMS}, true, nil
}
