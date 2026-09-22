package protocolv4

import "testing"

func TestActivationAuthorityRequiresExactDetachedProof(t *testing.T) {
	f := newNamespaceFixture(t)
	_, a, _ := f.activation(t, "live_authority")
	original := *a.binding
	if err := a.MatchBinding(&original); err != nil {
		t.Fatal("equal detached facts rejected", err)
	}
	for _, field := range []string{"proof", "end", "key", "source", "budget", "winner_authority"} {
		b := original
		switch field {
		case "proof":
			b.proofDigest[0] ^= 1
		case "end":
			b.activationEnd--
		case "key":
			b.proofKey[0] ^= 1
		case "source":
			b.source = "preauthorized_pool"
		case "budget":
			b.poolBudget.TotalWorkUnits++
		case "winner_authority":
			b.winnerAuthority += "changed"
		}
		if a.MatchBinding(&b) == nil {
			t.Fatal("changed proof facts accepted", field)
		}
	}
	if a.MatchBinding(nil) == nil || (*ActivationAuthority)(nil).MatchBinding(&original) == nil {
		t.Fatal("missing binding accepted")
	}
}

func TestAcceptedDirectListenerRejectsTunnelCandidate(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 0)
	if err := f.artifact.CheckDirectListenerCandidate(0); err != nil {
		t.Fatal(err)
	}
	// Existing runtime fixtures contain a valid direct candidate. Build a
	// valid tunnel route from the shared signed services Artifact fixture.
	seed := oracleSeed(t, "artifact_services_fields")
	artifact := signRuntimeFixture(t, "Artifact", oracleBytes(t, seed.Hex), DecodeContext{})
	candidates := artifact.Field("candidates")
	tunnels := 0
	for i := 0; i < candidates.Len(); i++ {
		path, _ := candidates.Index(i).Named("Candidate", "path_kind").Uint()
		if path == 1 {
			tunnels++
			if artifact.CheckDirectListenerCandidate(uint64(i)) == nil {
				t.Fatal("tunnel accepted by direct listener")
			}
		}
	}
	if tunnels == 0 {
		t.Fatal("fixture did not exercise a signed tunnel candidate")
	}
}
