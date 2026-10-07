package protocolv4

import "testing"

func TestStorageActivationFactsAcceptHistoryAndRejectDetachedMutations(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) {
			fixture := newRuntimeAdmissionFixture(t, source, 0)
			b := fixture.binding
			wire, err := fixture.proof.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			facts := StoredActivationFacts{AdmissionFields: AdmissionFields{Source: b.source, Tenant: b.tenant, Audience: b.audience, Profile: b.profile, SpendAuthority: b.authority, WinnerAuthority: b.winnerAuthority, SigningKey: b.signingKey, Issuer: b.issuer, Lease: b.lease, Attempt: b.attempt, Candidate: b.winner.CandidateID, CandidateIndex: b.winner.Index, Artifact: b.artifactDigest, Proof: b.proofDigest, ClientIdentity: b.clientDigest, ServerIdentity: b.serverDigest, Route: b.winner.RouteDigest, CandidateSet: b.candidateSetDigest, IssuedAt: b.issuedAt, ActivationEnd: b.activationEnd, SessionEnd: b.sessionEnd}, Budget: b.poolBudget, RouteSet: b.routeSetDigest}
			decoder, err := NewStorageFactsDecoder()
			if err != nil {
				t.Fatal(err)
			}
			if err := decoder.CheckActivation(wire, facts); err != nil {
				t.Fatal("original history refused", err)
			}
			for _, change := range []func(*StoredActivationFacts){func(f *StoredActivationFacts) { f.Proof[0] ^= 1 }, func(f *StoredActivationFacts) { f.Lease[0] ^= 1 }, func(f *StoredActivationFacts) { f.ActivationEnd++ }, func(f *StoredActivationFacts) { f.ClientIdentity[0] ^= 1 }, func(f *StoredActivationFacts) { f.Budget.TotalWorkUnits++ }} {
				changed := facts
				change(&changed)
				if err := decoder.CheckActivation(wire, changed); err == nil {
					t.Fatal("detached field escaped exact history checks")
				}
			}
		})
	}
}
