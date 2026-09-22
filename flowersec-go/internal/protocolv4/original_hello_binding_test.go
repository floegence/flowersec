package protocolv4

import "testing"

func TestOriginalHelloBindingChecksCompleteOriginalFacts(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 5)
	session := f.hello.SessionParameters()
	attempt, winner := f.hello.attempt, f.hello.winner
	if err := f.hello.MatchOriginal(session, attempt, winner); err != nil {
		t.Fatal(err)
	}
	if err := (*HelloBinding)(nil).MatchOriginal(session, attempt, winner); err == nil {
		t.Fatal("nil binding accepted")
	}
	for _, name := range []string{"contract", "artifact", "profile", "issued", "end", "attempt", "index", "candidate", "route"} {
		t.Run(name, func(t *testing.T) {
			s, a, w := session, attempt, winner
			switch name {
			case "contract":
				s.Contract = SessionContract{}
			case "artifact":
				s.ArtifactDigest[0] ^= 1
			case "profile":
				s.Profile += "other"
			case "issued":
				s.IssuedAtMS++
			case "end":
				s.SessionNotAfterMS++
			case "attempt":
				a[0] ^= 1
			case "index":
				w.Index++
			case "candidate":
				w.CandidateID[0] ^= 1
			case "route":
				w.RouteDigest[0] ^= 1
			}
			if f.hello.MatchOriginal(s, a, w) == nil {
				t.Fatal("replacement matched")
			}
		})
	}
	envelope, err := f.artifact.FeatureEnvelope(5, FeatureEnvelopePolicy{3, 3, 3})
	if err != nil {
		t.Fatal(err)
	}
	if err := envelope.MatchCandidate(winner); err != nil {
		t.Fatal(err)
	}
	differentRoute := winner
	differentRoute.RouteDigest[0] ^= 1
	if err := envelope.MatchCandidate(differentRoute); err != nil {
		t.Fatal("envelope unexpectedly checked route", err)
	}
	if f.hello.MatchOriginal(session, attempt, differentRoute) == nil {
		t.Fatal("final route gate bypassed")
	}
	for _, wrong := range []PoolMember{{Index: winner.Index + 1, CandidateID: winner.CandidateID}, {Index: winner.Index, CandidateID: [16]byte{}}} {
		if envelope.MatchCandidate(wrong) == nil {
			t.Fatal("other candidate accepted")
		}
	}
	if (FeatureEnvelope{}).MatchCandidate(PoolMember{}) == nil {
		t.Fatal("uncomputed envelope accepted")
	}
}
