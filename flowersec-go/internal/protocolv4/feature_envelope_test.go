package protocolv4

import (
	"reflect"
	"testing"
)

func envelopeFixture(t *testing.T, allowed, required uint64, resume bool) *SignedMap {
	t.Helper()
	r := newCBORTextReference(t)
	seed := oracleSeed(t, "artifact_pool_sixteen_fields")
	root, _, err := r.decode(oracleBytes(t, seed.Hex), "Artifact", nil, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	if resume {
		execution := oracleSeed(t, "artifact_execution_fields")
		other, _, err := r.decode(oracleBytes(t, execution.Hex), "Artifact", nil, 1<<16)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"session_contract", "resume_policy"} {
			*oracleField(t, r.cborReference, "Artifact", root, name) = *oracleField(t, r.cborReference, "Artifact", other, name)
		}
	}
	oracleField(t, r.cborReference, "Artifact", root, "allowed_features").n = allowed
	oracleField(t, r.cborReference, "Artifact", root, "required_features").n = required
	return signRuntimeFixture(t, "Artifact", root.encode(nil), DecodeContext{})
}

func envelopeSelections(t *testing.T, e FeatureEnvelope) []uint64 {
	t.Helper()
	var result []uint64
	for i := 0; i < e.Len(); i++ {
		selection, ok := e.Selection(i)
		if !ok {
			t.Fatal("missing enumerated selection")
		}
		result = append(result, selection)
	}
	if _, ok := e.Selection(-1); ok {
		t.Fatal("negative index")
	}
	if _, ok := e.Selection(e.Len()); ok {
		t.Fatal("out of range index")
	}
	return result
}

func TestFeatureEnvelopeEveryLegalIntersection(t *testing.T) {
	// The execution fixture enables resume. Its authenticated WT route permits
	// both registered features, so every signed/local/offer/policy intersection
	// can be compared with an exhaustive independent two-bit peer oracle.
	for _, required := range []uint64{0, 1, 2, 3} {
		artifact := envelopeFixture(t, 3, required, true)
		for local := uint64(0); local < 4; local++ {
			for offer := uint64(0); offer < 4; offer++ {
				for route := uint64(0); route < 4; route++ {
					policy := FeatureEnvelopePolicy{LocalCapabilities: local, ProposedOffer: offer, RouteAllowedFeatures: route}
					envelope, err := artifact.FeatureEnvelope(5, policy)
					if offer & ^local != 0 {
						if err != CBORFailure("configuration_capacity") {
							t.Fatal("unimplemented offered feature", local, offer, err)
						}
						continue
					}
					var want []uint64
					for selection := uint64(0); selection < 4; selection++ {
						if selection & ^(offer&route) == 0 && required & ^selection == 0 {
							want = append(want, selection)
						}
					}
					if len(want) == 0 {
						if err != CBORFailure("hello_required_features") {
							t.Fatal("impossible requirement", required, local, offer, route, err)
						}
						continue
					}
					if err != nil {
						t.Fatal(required, local, offer, route, err)
					}
					if got := envelopeSelections(t, envelope); !reflect.DeepEqual(got, want) {
						t.Fatal("incomplete legal selections", required, local, offer, route, got, want)
					}
					if envelope.Policy() != policy || envelope.CandidateIndex() != 5 || !envelope.SessionParameters().Contract.Valid() {
						t.Fatal("original constraints lost")
					}
				}
			}
		}
	}
}

func TestFeatureEnvelopeCanonicalProfileRouteAndUnknownBits(t *testing.T) {
	for _, test := range []struct {
		seed  string
		index uint64
		want  []uint64
	}{
		{"artifact_transport_fields", 1, []uint64{0}},
		{"artifact_local_fields", 0, []uint64{0}},
		{"artifact_pool_sixteen_fields", 5, []uint64{0, 1}},
	} {
		seed := oracleSeed(t, test.seed)
		artifact := signRuntimeFixture(t, "Artifact", oracleBytes(t, seed.Hex), DecodeContext{})
		e, err := artifact.FeatureEnvelope(test.index, FeatureEnvelopePolicy{3, 3, 3})
		if err != nil {
			t.Fatal(test.seed, err)
		}
		if got := envelopeSelections(t, e); !reflect.DeepEqual(got, test.want) {
			t.Fatal(test.seed, got, test.want)
		}
	}
	high := uint64(1) << 63
	artifact := envelopeFixture(t, 3|high, 0, false)
	e, err := artifact.FeatureEnvelope(5, FeatureEnvelopePolicy{3, 3 | high, 3})
	if err != nil || !reflect.DeepEqual(envelopeSelections(t, e), []uint64{0, 1}) {
		t.Fatal("unknown optional offer handling diverged from hello", err)
	}
	if _, err := artifact.FeatureEnvelope(5, FeatureEnvelopePolicy{3 | high, 3, 3}); err != CBORFailure("configuration_capacity") {
		t.Fatal("unregistered trusted capability", err)
	}
	if _, err := artifact.FeatureEnvelope(5, FeatureEnvelopePolicy{3, 3, 3 | high}); err != CBORFailure("hello_route_features") {
		t.Fatal("unregistered route capability", err)
	}
	unknownRequired := envelopeFixture(t, 3|high, high, false)
	if _, err := unknownRequired.FeatureEnvelope(5, FeatureEnvelopePolicy{3, 3 | high, 3}); err != CBORFailure("hello_required_features") {
		t.Fatal("unknown requirement accepted", err)
	}
	for _, id := range []string{"artifact_disabled_required_resume", "artifact_transport_enabled_resume", "artifact_services_enabled_resume", "artifact_resume_not_allowed"} {
		seed := oracleSeed(t, id)
		artifact := signRuntimeFixture(t, "Artifact", oracleBytes(t, seed.Hex), DecodeContext{})
		if _, err := artifact.FeatureEnvelope(0, FeatureEnvelopePolicy{3, 3, 3}); err == nil {
			t.Fatal("canonical Artifact policy bypassed", id)
		}
	}
}

func TestFeatureEnvelopeMatchesActualHelloAndOriginalArtifact(t *testing.T) {
	artifact := envelopeFixture(t, 3, 0, true)
	w, err := NewHelloWorkspace(HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	for offer := uint64(0); offer < 4; offer++ {
		e, err := artifact.FeatureEnvelope(5, FeatureEnvelopePolicy{3, offer, 3})
		if err != nil {
			t.Fatal(err)
		}
		client, err := w.BuildClientHello(make([]byte, 16384), artifact, 5, [16]byte{1}, offer, 2, nil)
		if err != nil {
			t.Fatal(err)
		}
		for peer := uint64(0); peer < 4; peer++ {
			_, h, err := w.BuildServerHello(make([]byte, 16384), artifact, 5, [16]byte{1}, client, peer, HelloPolicy{RouteAllowedFeatures: 3, BindingMode: 1}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.MatchHello(h, ClientToServer); err != nil {
				t.Fatal("actual final intersection missing", offer, peer, err)
			}
			wrong := *h
			wrong.artifact[0] ^= 1
			if e.MatchHello(&wrong, ClientToServer) == nil {
				t.Fatal("other Artifact matched")
			}
			wrong = *h
			wrong.winner.Index++
			if e.MatchHello(&wrong, ClientToServer) == nil {
				t.Fatal("other candidate matched")
			}
			wrong = *h
			wrong.features = uint64(1) << 63
			if e.MatchHello(&wrong, ClientToServer) == nil {
				t.Fatal("unreserved selected feature matched")
			}
		}
	}
}

func TestFeatureEnvelopeDetachedAndFailClosed(t *testing.T) {
	artifact := envelopeFixture(t, 3, 0, true)
	e, err := artifact.FeatureEnvelope(5, FeatureEnvelopePolicy{3, 3, 3})
	if err != nil {
		t.Fatal(err)
	}
	before := envelopeSelections(t, e)
	artifact.Release()
	if got := envelopeSelections(t, e); !reflect.DeepEqual(got, before) {
		t.Fatal("retained original decoder alias")
	}
	if _, err := artifact.FeatureEnvelope(5, FeatureEnvelopePolicy{3, 3, 3}); err != CBORFailure("artifact_owner") {
		t.Fatal("released owner reused", err)
	}
	var empty FeatureEnvelope
	if empty.Len() != 0 || empty.MatchHello(nil, ClientToServer) == nil {
		t.Fatal("empty envelope admitted")
	}
	if _, err := (*SignedMap)(nil).FeatureEnvelope(0, FeatureEnvelopePolicy{}); err != CBORFailure("artifact_owner") {
		t.Fatal(err)
	}
	if FeatureEnvelopeBackingBytes() == 0 {
		t.Fatal("missing retained value charge")
	}
}

func TestFeatureEnvelopeBindsExactOriginalOfferForEachRole(t *testing.T) {
	artifact := envelopeFixture(t, 3, 0, true)
	w, err := NewHelloWorkspace(HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	build := func(clientOffer, serverOffer, route uint64) *HelloBinding {
		t.Helper()
		client, err := w.BuildClientHello(make([]byte, 16384), artifact, 5, [16]byte{1}, clientOffer, 2, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, h, err := w.BuildServerHello(make([]byte, 16384), artifact, 5, [16]byte{1}, client, serverOffer, HelloPolicy{RouteAllowedFeatures: route, BindingMode: 1}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	for _, role := range []Direction{ClientToServer, ServerToClient} {
		local := uint64(3)
		envelope, err := artifact.FeatureEnvelope(5, FeatureEnvelopePolicy{3, local, 3})
		if err != nil {
			t.Fatal(err)
		}
		original := build(local, 1, 3)
		if role == ServerToClient {
			original = build(1, local, 3)
		}
		if err := envelope.MatchHello(original, role); err != nil {
			t.Fatal("original role offer rejected", role, err)
		}
		for _, replacement := range []uint64{1, 3 | (uint64(1) << 63)} {
			changed := build(replacement, 1, 3)
			if role == ServerToClient {
				changed = build(1, replacement, 3)
			}
			if original.FeatureNegotiation().Selected != changed.FeatureNegotiation().Selected {
				t.Fatal("regression case changed selection")
			}
			if err := envelope.MatchHello(changed, role); err != CBORFailure("hello_feature_selection") {
				t.Fatal("different original offer accepted same subset", role, replacement, err)
			}
		}
		changedRoute := build(local, 1, 1)
		if role == ServerToClient {
			changedRoute = build(1, local, 1)
		}
		if changedRoute.FeatureNegotiation().Selected != original.FeatureNegotiation().Selected {
			t.Fatal("route regression changed selection")
		}
		if err := envelope.MatchHello(changedRoute, role); err != CBORFailure("hello_feature_selection") {
			t.Fatal("different route policy accepted same subset", role, err)
		}
		if err := envelope.MatchHello(original, 1-role); err != CBORFailure("hello_feature_selection") {
			t.Fatal("opposite endpoint offer substituted", role, err)
		}
		if err := envelope.MatchHello(original, Direction(255)); err != CBORFailure("hello_feature_selection") {
			t.Fatal("invalid endpoint role", err)
		}
	}
	// Unknown optional bits are ignored for selection, but the original local
	// offer still retains them and must match exactly after authenticated hello.
	withUnknown := uint64(3) | (uint64(1) << 63)
	envelope, err := artifact.FeatureEnvelope(5, FeatureEnvelopePolicy{3, withUnknown, 3})
	if err != nil {
		t.Fatal(err)
	}
	if err := envelope.MatchHello(build(withUnknown, 1, 3), ClientToServer); err != nil {
		t.Fatal("original optional bit lost", err)
	}
	if err := envelope.MatchHello(build(3, 1, 3), ClientToServer); err == nil {
		t.Fatal("removed original optional bit accepted")
	}
}

func TestFeatureEnvelopeAllowsEachPeerOfferWithOriginalLocalOffer(t *testing.T) {
	artifact := envelopeFixture(t, 3, 0, true)
	w, err := NewHelloWorkspace(HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []Direction{ClientToServer, ServerToClient} {
		envelope, err := artifact.FeatureEnvelope(5, FeatureEnvelopePolicy{3, 3, 3})
		if err != nil {
			t.Fatal(err)
		}
		for _, peer := range []uint64{0, 1, 2, 3, 3 | (uint64(1) << 63)} {
			clientOffer, serverOffer := uint64(3), peer
			if role == ServerToClient {
				clientOffer, serverOffer = peer, 3
			}
			client, err := w.BuildClientHello(make([]byte, 16384), artifact, 5, [16]byte{1}, clientOffer, 2, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, h, err := w.BuildServerHello(make([]byte, 16384), artifact, 5, [16]byte{1}, client, serverOffer, HelloPolicy{RouteAllowedFeatures: 3, BindingMode: 1}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := envelope.MatchHello(h, role); err != nil {
				t.Fatal("legal peer offer excluded", role, peer, err)
			}
		}
	}
}
