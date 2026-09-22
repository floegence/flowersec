package protocolv4

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func bindRuntimeHellos(t *testing.T, f *runtimeAdmissionFixture) {
	t.Helper()
	parse := func(id string) *cborRefValue {
		seed := oracleSeed(t, id)
		root, _, err := f.r.decode(oracleBytes(t, seed.Hex), seed.Schema, nil, 1<<16)
		if err != nil {
			t.Fatal(err)
		}
		return root
	}
	client, server := parse("client_hello_fields"), parse("server_hello_fields")
	for name, root := range map[string]*cborRefValue{"ClientHello": client, "ServerHello": server} {
		for _, pair := range []struct {
			field string
			value []byte
		}{{"artifact_digest", f.binding.artifactDigest[:]}, {"candidate_id", f.binding.winner.CandidateID[:]}, {"route_digest", f.binding.winner.RouteDigest[:]}, {"attempt_id", f.binding.attempt[:]}, {"client_nonce", f.binding.sessionNonce[:]}} {
			oracleField(t, f.r.cborReference, name, root, pair.field).data = bytes.Clone(pair.value)
		}
		oracleField(t, f.r.cborReference, name, root, "crypto_profile_id").data = []byte(f.binding.profile)
	}
	oracleField(t, f.r.cborReference, "ClientHello", client, "offered_features").n = 3
	oracleField(t, f.r.cborReference, "ServerHello", server, "server_offered_features").n = 3
	oracleField(t, f.r.cborReference, "ServerHello", server, "selected_features").n = 1 // WT direct; signed ResumePolicy disabled.
	oracleField(t, f.r.cborReference, "ServerHello", server, "binding_mode").n = 1
	f.clientHello, f.serverHello = client.encode(nil), server.encode(nil)
	w, err := NewHelloWorkspace(HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	f.hello, err = w.Bind(f.artifact, f.binding.winner.Index, f.binding.attempt, f.clientHello, f.serverHello, HelloPolicy{RouteAllowedFeatures: 3, BindingMode: 1})
	if err != nil {
		t.Fatal(err)
	}
	f.fsb = f.mutate(t, f.fsb, "FSB4", func(root *cborRefValue) {
		for _, pair := range []struct {
			name  string
			value [32]byte
		}{{"hello_transcript_digest", f.hello.transcript}, {"transport_context_digest", f.hello.transport}} {
			oracleField(t, f.r.cborReference, "FSB4", root, pair.name).data = bytes.Clone(pair.value[:])
		}
		oracleField(t, f.r.cborReference, "FSB4", root, "selected_features").n = f.hello.features
		oracleField(t, f.r.cborReference, "FSB4", root, "binding_mode").n = f.hello.mode
	})
}

func TestRuntimeHelloPreservesBothCompleteOriginalMaps(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "preauthorized_pool", 5)
	digest := sha256.New()
	digest.Write([]byte("flowersec/v4/hello-transcript\x00"))
	var size [4]byte
	for _, wire := range [][]byte{f.clientHello, f.serverHello} {
		binary.BigEndian.PutUint32(size[:], uint32(len(wire)))
		digest.Write(size[:])
		digest.Write(wire)
	}
	if !bytes.Equal(digest.Sum(nil), f.hello.transcript[:]) {
		t.Fatal("hello transcript projection changed")
	}
	// Build the context with the independent reference encoder, including the
	// original Artifact/Route and empty exporter, not a digest of another hash.
	expected, err := f.r.namedMap("TransportContext", map[string]*cborRefValue{
		"profile_revision": {major: 3, data: []byte("4")}, "crypto_profile_id": {major: 3, data: []byte(f.binding.profile)},
		"access_class": {major: 0, n: 0}, "path_kind": {major: 0, n: 0}, "artifact_digest": {major: 2, data: f.binding.artifactDigest[:]}, "route_digest": {major: 2, data: f.binding.winner.RouteDigest[:]},
		"attempt_id": {major: 2, data: f.binding.attempt[:]}, "session_nonce": {major: 2, data: f.binding.sessionNonce[:]}, "hello_transcript_digest": {major: 2, data: digest.Sum(nil)},
		"selected_features": {major: 0, n: 1}, "binding_mode": {major: 0, n: 1}, "exporter_present": {major: 0, n: 0}, "exporter_bytes": {major: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	contextDigest, err := cborSingleMapHash("transport_context_digest", "TransportContext", "full", expected.encode(nil))
	if err != nil || f.hello.transport != [32]byte(contextDigest) {
		t.Fatal("context did not match original canonical input", err)
	}
	if _, err := f.hello.MatchFSB(f.binding, f.fsb, f.certificate); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"hello_transcript_digest", "transport_context_digest"} {
		wrong := f.mutate(t, f.fsb, "FSB4", func(root *cborRefValue) {
			v := oracleField(t, f.r.cborReference, "FSB4", root, field)
			v.data = bytes.Clone(v.data)
			v.data[0] ^= 1
		})
		if _, err := f.hello.MatchFSB(f.binding, wrong, f.certificate); err != CBORFailure("admission_hello_binding") {
			t.Fatal("valid signature changed original hello", err)
		}
	}
}

func TestRuntimeHelloRetainsCanonicalOfferAndRouteFacts(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 5)
	w, err := NewHelloWorkspace(HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	clientOffer, serverOffer := uint64(3)|(uint64(1)<<63), uint64(1)|(uint64(1)<<62)
	client, err := w.BuildClientHello(make([]byte, 16384), f.artifact, 5, f.binding.attempt, clientOffer, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, built, err := w.BuildServerHello(make([]byte, 16384), f.artifact, 5, f.binding.attempt, client, serverOffer, HelloPolicy{RouteAllowedFeatures: 1, BindingMode: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := w.Bind(f.artifact, 5, f.binding.attempt, client, server, HelloPolicy{RouteAllowedFeatures: 1, BindingMode: 1})
	if err != nil {
		t.Fatal(err)
	}
	want := FeatureNegotiation{ClientOffered: clientOffer, ServerOffered: serverOffer, RouteAllowed: 1, Selected: 1}
	if built.FeatureNegotiation() != want || bound.FeatureNegotiation() != want {
		t.Fatal("canonical offer facts lost", built.FeatureNegotiation(), bound.FeatureNegotiation())
	}
	copy := bound.FeatureNegotiation()
	copy.ClientOffered = 0
	copy.ServerOffered = 0
	copy.RouteAllowed = 0
	copy.Selected = 0
	clear(client)
	clear(server)
	if bound.FeatureNegotiation() != want {
		t.Fatal("detached public value or wire alias changed original hello facts")
	}
}

func TestRuntimeHelloExactFeaturesAndMode(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 5)
	w, err := NewHelloWorkspace(HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	client, _, _ := f.r.decode(f.clientHello, "ClientHello", nil, 1<<16)
	server, _, _ := f.r.decode(f.serverHello, "ServerHello", nil, 1<<16)
	for clientOffer := uint64(0); clientOffer < 4; clientOffer++ {
		for serverOffer := uint64(0); serverOffer < 4; serverOffer++ {
			for route := uint64(0); route < 4; route++ {
				oracleField(t, f.r.cborReference, "ClientHello", client, "offered_features").n = clientOffer | (uint64(1) << 63)
				oracleField(t, f.r.cborReference, "ServerHello", server, "server_offered_features").n = serverOffer
				selected := clientOffer & serverOffer & route & 1
				oracleField(t, f.r.cborReference, "ServerHello", server, "selected_features").n = selected
				policy := HelloPolicy{RouteAllowedFeatures: route, BindingMode: 1}
				h, err := w.Bind(f.artifact, 5, f.binding.attempt, client.encode(nil), server.encode(nil), policy)
				if err != nil || h.features != selected {
					t.Fatal("feature intersection", err)
				}
				oracleField(t, f.r.cborReference, "ServerHello", server, "selected_features").n = selected ^ 1
				if _, err := w.Bind(f.artifact, 5, f.binding.attempt, client.encode(nil), server.encode(nil), policy); err == nil {
					t.Fatal("negotiation downgrade accepted")
				}
			}
		}
	}
	if _, err := w.Bind(f.artifact, 5, f.binding.attempt, f.clientHello, f.serverHello, HelloPolicy{RouteAllowedFeatures: 3, BindingMode: 0, Exporter: make([]byte, 32)}); err != CBORFailure("hello_binding_selection") {
		t.Fatal("changed prior binding choice accepted", err)
	}
	if _, err := w.Bind(f.artifact, 5, f.binding.attempt, f.clientHello, f.serverHello, HelloPolicy{RouteAllowedFeatures: 3, BindingMode: 1, Exporter: make([]byte, 32)}); err != CBORFailure("hello_exporter_size") {
		t.Fatal("exporter silently discarded", err)
	}
}

func TestRuntimeHelloOriginalEchoAndOptionalOffers(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "preauthorized_pool", 5)
	w, err := NewHelloWorkspace(HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	policy := HelloPolicy{RouteAllowedFeatures: 3, BindingMode: 1}
	for _, name := range []string{"artifact_digest", "route_digest", "attempt_id", "client_nonce"} {
		server, _, _ := f.r.decode(f.serverHello, "ServerHello", nil, 1<<16)
		value := oracleField(t, f.r.cborReference, "ServerHello", server, name)
		value.data = bytes.Clone(value.data)
		value.data[0] ^= 1
		if _, err := w.Bind(f.artifact, 5, f.binding.attempt, f.clientHello, server.encode(nil), policy); err == nil {
			t.Fatal("different server echo accepted", name)
		}
	}
	client, _, _ := f.r.decode(f.clientHello, "ClientHello", nil, 1<<16)
	oracleField(t, f.r.cborReference, "ClientHello", client, "offered_features").n = 3 | (uint64(1) << 63)
	h, err := w.Bind(f.artifact, 5, f.binding.attempt, client.encode(nil), f.serverHello, policy)
	if err != nil {
		t.Fatal(err)
	}
	if h.features != f.hello.features || h.transcript == f.hello.transcript || h.transport == f.hello.transport {
		t.Fatal("unknown optional offer removed from complete transcript")
	}
	clientWire := client.encode(nil)
	clear(clientWire)
	if h.transcript == ([32]byte{}) {
		t.Fatal("snapshot aliased caller bytes")
	}
}

func TestRuntimeHelloExporterAndWholeRouteFiltering(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "preauthorized_pool", 5)
	w, err := NewHelloWorkspace(HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	server, _, _ := f.r.decode(f.serverHello, "ServerHello", nil, 1<<16)
	oracleField(t, f.r.cborReference, "ServerHello", server, "binding_mode").n = 0
	policy := HelloPolicy{RouteAllowedFeatures: 3, BindingMode: 0, Exporter: bytes.Repeat([]byte{11}, 32)}
	first, err := w.Bind(f.artifact, 5, f.binding.attempt, f.clientHello, server.encode(nil), policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.Exporter[0] ^= 1
	second, err := w.Bind(f.artifact, 5, f.binding.attempt, f.clientHello, server.encode(nil), policy)
	if err != nil {
		t.Fatal(err)
	}
	if first.transcript != second.transcript || first.transport == second.transport {
		t.Fatal("exporter altered hello or failed to bind transport")
	}
	for _, test := range []struct {
		id    string
		index uint64
	}{{"artifact_transport_fields", 1}, {"artifact_local_fields", 0}} {
		seed := oracleSeed(t, test.id)
		artifact := signRuntimeFixture(t, "Artifact", oracleBytes(t, seed.Hex), DecodeContext{})
		a, _ := artifact.Digest("artifact_digest")
		_, route, err := artifact.CopyCandidateRoute(test.index, make([]byte, 16384))
		if err != nil {
			t.Fatal(err)
		}
		id, _ := artifact.Field("candidates").Index(int(test.index)).Named("Candidate", "candidate_id").ByteString()
		nonce, _ := artifact.Field("session_nonce").ByteString()
		client, _, _ := f.r.decode(f.clientHello, "ClientHello", nil, 1<<16)
		server, _, _ := f.r.decode(f.serverHello, "ServerHello", nil, 1<<16)
		for name, root := range map[string]*cborRefValue{"ClientHello": client, "ServerHello": server} {
			for _, pair := range []struct {
				field string
				data  []byte
			}{{"artifact_digest", a[:]}, {"route_digest", route[:]}, {"candidate_id", id}, {"client_nonce", nonce}} {
				oracleField(t, f.r.cborReference, name, root, pair.field).data = pair.data
			}
		}
		oracleField(t, f.r.cborReference, "ServerHello", server, "selected_features").n = 0
		_, err = w.Bind(artifact, test.index, f.binding.attempt, client.encode(nil), server.encode(nil), HelloPolicy{RouteAllowedFeatures: 3, BindingMode: 1})
		if err != nil {
			t.Fatal(test.id, err)
		}
		oracleField(t, f.r.cborReference, "ServerHello", server, "selected_features").n = 1
		if _, err := w.Bind(artifact, test.index, f.binding.attempt, client.encode(nil), server.encode(nil), HelloPolicy{RouteAllowedFeatures: 3, BindingMode: 1}); err != CBORFailure("hello_feature_selection") {
			t.Fatal("WS leg admitted datagram", test.id, err)
		}
		oracleField(t, f.r.cborReference, "ServerHello", server, "selected_features").n = 0
		oracleField(t, f.r.cborReference, "ServerHello", server, "binding_mode").n = 0
		if _, err := w.Bind(artifact, test.index, f.binding.attempt, client.encode(nil), server.encode(nil), policy); err == nil {
			t.Fatal("tunnel/local exporter admitted", test.id)
		}
	}
}
