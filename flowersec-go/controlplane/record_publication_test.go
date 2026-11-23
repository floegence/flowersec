package controlplane

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func publicationFixture(t testing.TB, metadata ArtifactMetadata) IssuedArtifact {
	t.Helper()
	now := time.Unix(1_900_000_000, 0)
	endpoints, err := NewEndpointSet(caEndpoint("ws", "wss://edge.example/flowersec/v5/direct"))
	if err != nil {
		t.Fatal(err)
	}
	issuer := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{0x35}, 64)), now)
	issued, err := issuer.IssueDirect(DirectIssueOptions{
		Session: SessionOptions{ChannelID: "publication"}, Endpoints: endpoints,
		RendezvousGroupID: "group", ListenerAudience: "listener", UpstreamAddress: "127.0.0.1:9000", Metadata: metadata,
	})
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

func TestControlPlaneCredentialFormatting(t *testing.T) {
	issued := publicationFixture(t, ArtifactMetadata{})
	for _, value := range []fmt.Stringer{issued, issued.AuthorizationRecord(), AuthorizationResponse{encoded: []byte("private")}} {
		for _, format := range []string{"%d", "%o", "%b", "%+v"} {
			if fmt.Sprintf(format, value) != value.String() {
				t.Fatalf("%T does not redact %s", value, format)
			}
		}
	}
}

func TestDirectRecordPublication(t *testing.T) {
	for _, test := range []struct {
		name     string
		metadata ArtifactMetadata
		digest   string
	}{
		{name: "unscoped", metadata: ArtifactMetadata{CorrelationTags: map[string]string{"trace": `value<>&\"`}}, digest: "4132c7b6a7c96e0950e7f1dabddadac6c6d1585522a695f650b5a9012758d60a"},
		{name: "scoped", metadata: ArtifactMetadata{Scopes: []Scope{{Name: "app", Version: 1, Payload: json.RawMessage(`{"mode":"test"}`)}}}, digest: "21cf96ab92732ed13ac8ccf93056e9c3b5bbaffa6128ec699839626cc3ebb294"},
	} {
		t.Run(test.name, func(t *testing.T) {
			issued := publicationFixture(t, test.metadata)
			fresh := issued.AuthorizationRecord()
			encoded, err := fresh.Encode()
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(encoded)
			if hex.EncodeToString(digest[:]) != test.digest {
				t.Fatalf("persisted record differs from its wire fixture: %x", digest)
			}
			original := bytes.Clone(encoded)
			restored, err := ParseAuthorizationRecord(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if (fresh.issued != nil) != (len(test.metadata.Scopes) == 0) || restored.issued != nil {
				t.Fatal("publication proof crossed its issuance boundary")
			}
			clear(encoded)
			clear(issued.ArtifactJSON())
			if len(test.metadata.Scopes) != 0 {
				clear(test.metadata.Scopes[0].Payload)
			}
			clear(test.metadata.CorrelationTags)
			request := runtimeRequestForCandidate(t, restored, "ws")
			expires := time.Unix(1_900_000_060, 0)
			for _, record := range []AuthorizationRecord{fresh, restored} {
				got, err := record.Encode()
				if err != nil || !bytes.Equal(got, original) {
					t.Fatalf("persisted record changed after caller mutation: %v", err)
				}
				clear(got)
				for _, boundary := range []struct {
					now      time.Time
					decision string
				}{{expires.Add(-time.Nanosecond), "allow"}, {expires, "retry"}} {
					response, err := authorizeRuntimeAt(request, record, "lease", boundary.now)
					var wire runtimeAuthorizationResponseWire
					if err != nil || json.Unmarshal(response.JSON(), &wire) != nil || wire.Decision != boundary.decision || (wire.Decision == "retry" && wire.Reason != "expired_artifact") {
						t.Fatalf("expected %s at expiry boundary: %v", boundary.decision, err)
					}
				}
				if _, err := authorizeRuntimeAt(request, record, "bad lease", expires); !errors.Is(err, ErrInvalidControlPlaneInput) {
					t.Fatalf("invalid lease: %v", err)
				}
				if _, err := authorizeTunnelRuntimeAt(request, record, "lease", expires); !errors.Is(err, ErrInvalidControlPlaneInput) {
					t.Fatalf("tunnel accepted direct request: %v", err)
				}
			}
			request.decoded.Raw[len(request.decoded.Raw)-1] ^= 1
			if _, err := authorizeRuntimeAt(request, fresh, "lease", expires); !errors.Is(err, ErrInvalidControlPlaneInput) {
				t.Fatalf("altered admission accepted at expiry: %v", err)
			}
			var wire authorizationRecordWire
			if err := json.Unmarshal(original, &wire); err != nil {
				t.Fatal(err)
			}
			for _, change := range []func(*authorizationRecordWire){
				func(wire *authorizationRecordWire) { wire.LookupKey = strings.Repeat("a", 43) },
				func(wire *authorizationRecordWire) { wire.AuthorityScope = "foreign" },
				func(wire *authorizationRecordWire) { wire.AllowReplacement = true },
				func(wire *authorizationRecordWire) {
					wire.ArtifactBase64URL = base64.RawURLEncoding.EncodeToString(append(issued.ArtifactJSON(), ' '))
				},
			} {
				altered := wire
				change(&altered)
				data, err := json.Marshal(altered)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ParseAuthorizationRecord(data); !errors.Is(err, ErrInvalidControlPlaneInput) {
					t.Fatalf("altered persisted record: %v", err)
				}
			}
		})
	}
}

func TestIssuedDirectPublicationRejectsChangedRecord(t *testing.T) {
	fresh := publicationFixture(t, ArtifactMetadata{}).AuthorizationRecord()
	for name, change := range map[string]func(*AuthorizationRecord){
		"artifact": func(record *AuthorizationRecord) {
			record.artifactJSON = bytes.Replace(record.artifactJSON, []byte("edge.example"), []byte("peer.example"), 1)
		},
		"lookup":      func(record *AuthorizationRecord) { record.lookupKey = strings.Repeat("A", 43) },
		"scope":       func(record *AuthorizationRecord) { record.authorityScope = "other" },
		"upstream":    func(record *AuthorizationRecord) { record.directUpstream = "127.0.0.1:9001" },
		"replacement": func(record *AuthorizationRecord) { record.allowReplacement = true },
	} {
		t.Run(name, func(t *testing.T) {
			changed := fresh
			change(&changed)
			if got, err := changed.Encode(); !errors.Is(err, ErrInvalidControlPlaneInput) || len(got) != 0 {
				t.Fatalf("altered record published: %v", err)
			}
		})
	}
}

func TestTunnelPublicationKeepsItsOwnArtifact(t *testing.T) {
	endpoints, err := NewEndpointSet(caEndpoint("ws", "wss://edge.example/flowersec/v5/tunnel"))
	if err != nil {
		t.Fatal(err)
	}
	pair, err := NewIssuer().IssueTunnelPair(TunnelIssueOptions{
		Session: SessionOptions{ChannelID: "publication"}, Endpoints: endpoints,
		RendezvousGroupID: "group", ListenerAudience: "listener", FirstEndpointID: "a", SecondEndpointID: "b",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, leg := range []IssuedArtifact{pair.First, pair.Second} {
		invitation := leg.ArtifactJSON()
		stored, err := leg.AuthorizationRecord().Encode()
		if err != nil {
			t.Fatal(err)
		}
		restored, err := ParseAuthorizationRecord(stored)
		if err != nil {
			t.Fatal(err)
		}
		clear(leg.ArtifactJSON())
		clear(stored)
		if !bytes.Equal(invitation, leg.ArtifactJSON()) || !bytes.Equal(invitation, restored.artifactJSON) {
			t.Fatal("clearing caller bytes changed an invitation")
		}
		issuedWire, err := leg.AuthorizationRecord().Encode()
		if err != nil {
			t.Fatal(err)
		}
		restoredWire, err := restored.Encode()
		if err != nil || !bytes.Equal(issuedWire, restoredWire) {
			t.Fatalf("clearing caller bytes changed a persisted record: %v", err)
		}
	}
}

func TestRestoredAuthorizationIsBoundToOneArtifact(t *testing.T) {
	fresh := publicationFixture(t, ArtifactMetadata{}).AuthorizationRecord()
	encoded, err := fresh.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := ParseAuthorizationRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	request := runtimeRequestForCandidate(t, restored, "ws")
	beforeExpiry := time.Unix(1_900_000_001, 0)
	for name, change := range map[string]func(*AuthorizationRecord){
		"changed bytes": func(record *AuthorizationRecord) {
			record.artifactJSON = bytes.Clone(record.artifactJSON)
			record.artifactJSON[0] ^= 1
		},
		"changed decoded artifact": func(record *AuthorizationRecord) { record.artifact = fresh.artifact },
		"wrong lookup key":         func(record *AuthorizationRecord) { record.lookupKey = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := restored
			change(&changed)
			if response, err := authorizeRuntimeAt(request, changed, "lease", beforeExpiry); !errors.Is(err, ErrInvalidControlPlaneInput) || len(response.JSON()) != 0 {
				t.Fatalf("changed record authorized: %v", err)
			}
		})
	}
	clear(encoded)
	if response, err := authorizeRuntimeAt(request, restored, "lease", beforeExpiry); err != nil || len(response.JSON()) == 0 {
		t.Fatalf("intact record rejected after caller mutation: %v", err)
	}
}

func TestTunnelRecordPublication(t *testing.T) {
	first, err := NewEndpointSet(caEndpoint("ingress-a", "quic://edge.example:443"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewEndpointSet(caEndpoint("ingress-b", "quic://edge.example:443"))
	if err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []bool{false, true} {
		for _, scope := range []string{"", "deployment"} {
			pair, err := NewIssuer().IssueTunnelPair(TunnelIssueOptions{
				Session: SessionOptions{ChannelID: "publication"}, FirstEndpoints: first, SecondEndpoints: second,
				FirstEndpointID: "left", SecondEndpointID: "right", RendezvousGroupID: "group", ListenerAudience: "listener",
				AuthorityScope: scope, AllowReplacement: replacement,
			})
			if err != nil {
				t.Fatal(err)
			}
			legs := [2]IssuedArtifact{pair.First, pair.Second}
			for index, leg := range legs {
				record := leg.AuthorizationRecord()
				other := legs[1-index].AuthorizationRecord()
				if record.issued == nil || record.authorityScope == "" || record.authorityScope != other.authorityScope || (scope != "" && scope != record.authorityScope) {
					t.Fatal("missing per-leg proof or pairing scope")
				}
				encoded, err := record.Encode()
				if err != nil {
					t.Fatal(err)
				}
				restored, err := ParseAuthorizationRecord(encoded)
				if err != nil || restored.issued != nil || restored.authorityScope != record.authorityScope || restored.allowReplacement != replacement || restored.lookupKey != record.lookupKey {
					t.Fatalf("incorrect restored record: %v", err)
				}
				request := runtimeRequestForCandidate(t, restored, []string{"ingress-a", "ingress-b"}[index])
				response, err := AuthorizeTunnelRuntime(request, restored, "lease")
				var wire tunnelRuntimeAuthorizationResponseWire
				if err != nil || json.Unmarshal(response.JSON(), &wire) != nil || !response.Allowed() || wire.AuthorityScope != record.authorityScope || wire.AllowReplacement != replacement || wire.ExpectedPeerEndpointInstanceID != []string{"right", "left"}[index] {
					t.Fatalf("incorrect tunnel authorization: %v", err)
				}
				if _, err := AuthorizeTunnelRuntime(request, other, "lease"); !errors.Is(err, ErrInvalidControlPlaneInput) {
					t.Fatal("opposite leg accepted")
				}
				for _, change := range []func(*AuthorizationRecord){
					func(changed *AuthorizationRecord) { changed.issued = other.issued },
					func(changed *AuthorizationRecord) { changed.artifact = other.artifact },
					func(changed *AuthorizationRecord) { changed.artifactJSON = other.artifactJSON },
					func(changed *AuthorizationRecord) { changed.lookupKey = other.lookupKey },
					func(changed *AuthorizationRecord) { changed.authorityScope = "unrelated" },
					func(changed *AuthorizationRecord) { changed.allowReplacement = !replacement },
					func(changed *AuthorizationRecord) { changed.directUpstream = "127.0.0.1:1" },
				} {
					changed := record
					change(&changed)
					if data, err := changed.Encode(); !errors.Is(err, ErrInvalidControlPlaneInput) || len(data) != 0 {
						t.Fatal("changed record published")
					}
				}
			}
		}
	}
	pair, err := NewIssuer().IssueTunnelPair(TunnelIssueOptions{
		Session: SessionOptions{ChannelID: "mixed"}, FirstEndpoints: first, SecondEndpoints: second,
		FirstEndpointID: "left", SecondEndpointID: "right", RendezvousGroupID: "group", ListenerAudience: "listener",
		SecondMetadata: ArtifactMetadata{Scopes: []Scope{{Name: "app", Version: 1, Payload: json.RawMessage(`{"mode":"test"}`)}}},
	})
	if err != nil || pair.First.record.issued == nil || pair.Second.record.issued != nil {
		t.Fatalf("scoped publication did not take its own validation path: %v", err)
	}
	encoded, err := pair.Second.record.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAuthorizationRecord(encoded); err != nil {
		t.Fatal(err)
	}
}

func TestDirectPublicationScopeLimits(t *testing.T) {
	endpoints, err := NewEndpointSet(caEndpoint("ws", "wss://edge.example/flowersec/v5/direct"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, payload string
		valid         bool
	}{
		{"limit", strings.Repeat(`{"x":`, 15) + "1" + strings.Repeat("}", 15), true},
		{"too deep", strings.Repeat(`{"x":`, 16) + "1" + strings.Repeat("}", 16), false},
		{"invalid UTF-8", "{\"x\":\"\xff\"}", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			issuer := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{0x35}, 64)), time.Unix(1_900_000_000, 0))
			issued, err := issuer.IssueDirect(DirectIssueOptions{
				Session: SessionOptions{ChannelID: "scoped"}, Endpoints: endpoints, RendezvousGroupID: "group", ListenerAudience: "listener", UpstreamAddress: "127.0.0.1:9000",
				Metadata: ArtifactMetadata{Scopes: []Scope{{Name: "app", Version: 1, Payload: json.RawMessage(test.payload)}}},
			})
			if !test.valid {
				if !errors.Is(err, ErrInvalidControlPlaneInput) {
					t.Fatalf("invalid scope at issuance: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			record := issued.AuthorizationRecord()
			if record.issued != nil {
				t.Fatal("scoped payload accepted for local publication")
			}
			encoded, err := record.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseAuthorizationRecord(encoded); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDirectPublicationTextBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, host, upstream string
		issue, local         bool
	}{
		{"IDNA host", "b\u00fccher.example", "127.0.0.1:9000", true, true},
		{"invalid host UTF-8", "edge\xff.example", "127.0.0.1:9000", false, false},
		{"invalid upstream UTF-8", "edge.example", "up\xff:9000", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoints, err := NewEndpointSet(caEndpoint("quic", "quic://"+test.host))
			if err != nil {
				t.Fatal(err)
			}
			issuer := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{0x35}, 64)), time.Unix(1_900_000_000, 0))
			issued, err := issuer.IssueDirect(DirectIssueOptions{
				Session: SessionOptions{ChannelID: "text"}, Endpoints: endpoints,
				RendezvousGroupID: "group", ListenerAudience: "listener", UpstreamAddress: test.upstream,
			})
			if !test.issue {
				if !errors.Is(err, ErrInvalidControlPlaneInput) {
					t.Fatalf("invalid host accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			record := issued.AuthorizationRecord()
			if (record.issued != nil) != test.local {
				t.Fatal("unexpected publication path")
			}
			encoded, err := record.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseAuthorizationRecord(encoded); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func BenchmarkDirectRecordEncode(b *testing.B) {
	fresh := publicationFixture(b, ArtifactMetadata{}).AuthorizationRecord()
	encoded, err := fresh.Encode()
	if err != nil {
		b.Fatal(err)
	}
	restored, err := ParseAuthorizationRecord(encoded)
	if err != nil {
		b.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		record AuthorizationRecord
	}{{"issued", fresh}, {"restored", restored}} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := test.record.Encode(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
