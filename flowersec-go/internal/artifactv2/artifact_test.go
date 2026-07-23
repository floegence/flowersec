package artifactv2

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSessionContractHashUsesSignedCanonicalPreimage(t *testing.T) {
	session := validSession()
	got, canonical, err := ComputeSessionContractHash(session)
	if err != nil {
		t.Fatal(err)
	}
	wantCanonical := `{"allowed_suites":[1,2],"channel_id":"channel-1","default_suite":1,"establish_timeout_seconds":30,"idle_timeout_seconds":60,"max_inbound_streams":64,"profile":"flowersec/2","rekey_completion_timeout_seconds":30,"rekey_prepare_timeout_seconds":10,"selected_features":0}`
	if string(canonical) != wantCanonical {
		t.Fatalf("canonical session = %s, want %s", canonical, wantCanonical)
	}
	want := labeledHash("flowersec-v2-session-contract\x00", []byte(wantCanonical))
	if got != want {
		t.Fatalf("session hash = %x, want %x", got, want)
	}
}

func TestCanonicalCandidatesUseRegistryValuesAndStableOrdering(t *testing.T) {
	candidates := []Candidate{
		{ID: "w1", Carrier: CarrierWebSocket, URL: "WSS://EXAMPLE.com:443/flowersec/v2/direct", WireProfile: "flowersec-direct/2"},
		{ID: "t1", Carrier: CarrierWebTransport, URL: "https://example.com:443/flowersec/webtransport/v2/direct", WireProfile: "flowersec-direct/2"},
		{ID: "q1", Carrier: CarrierRawQUIC, URL: "quic://[2001:0db8::1]:443/", WireProfile: "flowersec-direct/2"},
	}
	canonicalCandidates, canonical, gotHash, err := CanonicalizeCandidates(PathDirect, candidates)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{canonicalCandidates[0].ID, canonicalCandidates[1].ID, canonicalCandidates[2].ID}; strings.Join(got, ",") != "q1,t1,w1" {
		t.Fatalf("candidate order = %v", got)
	}
	wantCanonical := `[{"carrier":"raw_quic","id":"q1","normalized_url":"quic://[2001:db8::1]","wire_profile":"flowersec-direct/2"},{"carrier":"webtransport","id":"t1","normalized_url":"https://example.com/flowersec/webtransport/v2/direct","wire_profile":"flowersec-direct/2"},{"carrier":"websocket","id":"w1","normalized_url":"wss://example.com/flowersec/v2/direct","wire_profile":"flowersec-direct/2"}]`
	if string(canonical) != wantCanonical {
		t.Fatalf("canonical candidates = %s, want %s", canonical, wantCanonical)
	}
	wantHash := labeledHash("flowersec-v2-candidates\x00", []byte(wantCanonical))
	if gotHash != wantHash {
		t.Fatalf("candidate hash = %x, want %x", gotHash, wantHash)
	}
}

func TestArtifactJSONRoundTripDirectAndTunnel(t *testing.T) {
	for _, kind := range []PathKind{PathDirect, PathTunnel} {
		t.Run(string(kind), func(t *testing.T) {
			artifact := validArtifact(t, kind)
			raw, err := MarshalArtifactJSON(artifact)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeArtifactJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Version != 2 || decoded.Profile != Profile || decoded.Path.Kind != kind {
				t.Fatalf("unexpected decoded artifact: %+v", decoded)
			}
			if len(decoded.Path.Candidates) != 3 || decoded.Session.ContractHash != artifact.Session.ContractHash {
				t.Fatalf("artifact data drifted: %+v", decoded)
			}
			for _, candidate := range decoded.Path.Candidates {
				if candidate.NormalizedURL == "" {
					t.Fatalf("decoded candidate %s has no normalized URL", candidate.ID)
				}
			}
			if bytes.Contains(raw, []byte("normalized_url")) {
				t.Fatalf("artifact must carry source url, not normalized_url: %s", raw)
			}
		})
	}
}

func TestArtifactRejectsDuplicateUnknownAndBusinessFields(t *testing.T) {
	raw, err := MarshalArtifactJSON(validArtifact(t, PathDirect))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		old  string
		new  string
	}{
		{name: "duplicate top-level", old: `"profile":"flowersec/2"`, new: `"profile":"flowersec/2","profile":"flowersec/2"`},
		{name: "unknown top-level", old: `"v":2`, new: `"v":2,"future":true`},
		{name: "business top-level", old: `"v":2`, new: `"v":2,"tenant_id":"tenant-1"`},
		{name: "business path", old: `"kind":"direct"`, new: `"kind":"direct","environment_id":"prod"`},
		{name: "unknown session", old: `"channel_id":"channel-1"`, new: `"channel_id":"channel-1","billing_plan":"pro"`},
		{name: "duplicate candidate", old: `"id":"w1"`, new: `"id":"w1","id":"w2"`},
		{name: "candidate priority", old: `"id":"w1"`, new: `"id":"w1","priority":1`},
		{name: "missing zero-valued idle timeout", old: `"idle_timeout_seconds":60,`, new: ``},
		{name: "missing zero-valued selected features", old: `"selected_features":0,`, new: ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := bytes.Replace(raw, []byte(tt.old), []byte(tt.new), 1)
			if bytes.Equal(mutated, raw) {
				t.Fatalf("fixture token %q not found in %s", tt.old, raw)
			}
			if _, err := DecodeArtifactJSON(bytes.NewReader(mutated)); err == nil {
				t.Fatalf("DecodeArtifactJSON accepted %s", mutated)
			}
		})
	}
}

func TestArtifactRejectsInvalidCandidateRegistryAndBounds(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Artifact)
	}{
		{name: "no candidates", mutate: func(a *Artifact) { a.Path.Candidates = nil }},
		{name: "five candidates", mutate: func(a *Artifact) {
			a.Path.Candidates = append(a.Path.Candidates,
				Candidate{ID: "w2", Carrier: CarrierWebSocket, URL: "wss://two.example/flowersec/v2/direct", WireProfile: "flowersec-direct/2"},
				Candidate{ID: "w3", Carrier: CarrierWebSocket, URL: "wss://three.example/flowersec/v2/direct", WireProfile: "flowersec-direct/2"})
		}},
		{name: "noncanonical carrier", mutate: func(a *Artifact) { a.Path.Candidates[1].Carrier = Carrier("quic") }},
		{name: "bad id", mutate: func(a *Artifact) { a.Path.Candidates[0].ID = "W 1" }},
		{name: "cross path profile", mutate: func(a *Artifact) { a.Path.Candidates[0].WireProfile = "flowersec-tunnel/2" }},
		{name: "wrong websocket scheme", mutate: func(a *Artifact) { a.Path.Candidates[0].URL = "https://example.com/flowersec/v2/direct" }},
		{name: "wrong websocket path", mutate: func(a *Artifact) { a.Path.Candidates[0].URL = "wss://example.com/flowersec/v2/tunnel" }},
		{name: "raw quic query", mutate: func(a *Artifact) { a.Path.Candidates[1].URL = "quic://example.com/?route=x" }},
		{name: "duplicate normalized tuple", mutate: func(a *Artifact) { a.Path.Candidates[2] = a.Path.Candidates[0]; a.Path.Candidates[2].ID = "w2" }},
		{name: "tampered session hash", mutate: func(a *Artifact) { a.Session.ContractHash[0] ^= 1 }},
		{name: "nonfixed timing", mutate: func(a *Artifact) { a.Session.EstablishTimeoutSeconds = 29 }},
		{name: "unsorted suites", mutate: func(a *Artifact) { a.Session.AllowedSuites = []uint16{2, 1} }},
		{name: "business tunnel field on direct", mutate: func(a *Artifact) { a.Path.Token = "attach" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifact := validArtifact(t, PathDirect)
			tt.mutate(&artifact)
			if _, err := MarshalArtifactJSON(artifact); err == nil {
				t.Fatalf("MarshalArtifactJSON accepted %+v", artifact)
			}
		})
	}
}

func TestArtifactNormalizesUnicode15_1UTS46Hosts(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{host: "m\u00fcnich.example", want: "xn--mnich-kva.example"},
		{host: "xn--mnich-kva.example", want: "xn--mnich-kva.example"},
		{host: "fa\u00df.de", want: "xn--fa-hia.de"},
		{host: "\uff26\uff2f\uff2f.example", want: "foo.example"},
		{host: "\U0002ebf0.example", want: "xn--8g0n.example"},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			canonical, _, _, err := CanonicalizeCandidates(PathDirect, []Candidate{{
				ID: "w1", Carrier: CarrierWebSocket,
				URL: "wss://" + tt.host + "/flowersec/v2/direct", WireProfile: "flowersec-direct/2",
			}})
			if err != nil {
				t.Fatalf("CanonicalizeCandidates: %v", err)
			}
			want := "wss://" + tt.want + "/flowersec/v2/direct"
			if canonical[0].NormalizedURL != want {
				t.Fatalf("normalized URL = %q, want %q", canonical[0].NormalizedURL, want)
			}
		})
	}
}

func TestArtifactRejectsInvalidUnicode15_1UTS46Hosts(t *testing.T) {
	for _, host := range []string{
		"a\u200cb.example",
		"\u2ffc.example",
		"xn--.example",
	} {
		t.Run(host, func(t *testing.T) {
			_, _, _, err := CanonicalizeCandidates(PathDirect, []Candidate{{
				ID: "w1", Carrier: CarrierWebSocket,
				URL: "wss://" + host + "/flowersec/v2/direct", WireProfile: "flowersec-direct/2",
			}})
			if err == nil {
				t.Fatal("invalid UTS #46 host was accepted")
			}
		})
	}
}

func TestArtifactValidationPreflightsFSB2ForEveryWinner(t *testing.T) {
	artifact := validArtifact(t, PathDirect)
	artifact.Path.RoutingToken = strings.Repeat("\x01", 6_000)
	_, err := MarshalArtifactJSON(artifact)
	if !errors.Is(err, ErrFSB2PayloadTooLarge) {
		t.Fatalf("error = %v, want ErrFSB2PayloadTooLarge", err)
	}
}

func validArtifact(t *testing.T, kind PathKind) Artifact {
	t.Helper()
	session := validSession()
	hash, _, err := ComputeSessionContractHash(session)
	if err != nil {
		t.Fatal(err)
	}
	session.ContractHash = hash
	path := ArtifactPath{
		Kind:              kind,
		RendezvousGroupID: "group-1",
		ListenerAudience:  "listener-1",
		Candidates: []Candidate{
			{ID: "w1", Carrier: CarrierWebSocket, URL: "wss://example.com/flowersec/v2/" + string(kind), WireProfile: "flowersec-" + string(kind) + "/2"},
			{ID: "q1", Carrier: CarrierRawQUIC, URL: "quic://example.com:443", WireProfile: "flowersec-" + string(kind) + "/2"},
			{ID: "t1", Carrier: CarrierWebTransport, URL: "https://example.com/flowersec/webtransport/v2/" + string(kind), WireProfile: "flowersec-" + string(kind) + "/2"},
		},
	}
	if kind == PathDirect {
		path.RoutingToken = "routing-token"
	} else {
		path.Role = 1
		path.LocalEndpointInstanceID = "endpoint-client"
		path.ExpectedPeerEndpointInstanceID = "endpoint-server"
		path.Token = "attach-token"
	}
	return Artifact{
		Version:     2,
		Profile:     Profile,
		Session:     session,
		Path:        path,
		Scoped:      []ScopeMetadata{},
		Correlation: CorrelationContext{Version: 2, Tags: []CorrelationTag{}},
	}
}

func validSession() SessionContract {
	var psk [32]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	return SessionContract{
		ChannelID:                     "channel-1",
		InitExpireAtUnixSeconds:       2_000_000_000,
		IdleTimeoutSeconds:            60,
		EstablishTimeoutSeconds:       30,
		RekeyPrepareTimeoutSeconds:    10,
		RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams:             64,
		E2EEPSK:                       psk,
		AllowedSuites:                 []uint16{1, 2},
		DefaultSuite:                  1,
		SelectedFeatures:              0,
	}
}

func labeledHash(label string, canonical []byte) [32]byte {
	preimage := make([]byte, 0, len(label)+4+len(canonical))
	preimage = append(preimage, label...)
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(canonical)))
	preimage = append(preimage, size[:]...)
	preimage = append(preimage, canonical...)
	return sha256.Sum256(preimage)
}

func replaceJSONField(t *testing.T, raw []byte, key string, value any) []byte {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object[key] = value
	out, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
