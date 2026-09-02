package controlplane

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/privateloopbackv1"
)

type privateLoopbackVectors struct {
	Version       uint8  `json:"version"`
	Profile       string `json:"profile"`
	NestedProfile string `json:"nested_profile"`
	Positive      []struct {
		ID           string `json:"id"`
		Endpoint     string `json:"endpoint"`
		ArtifactJSON string `json:"artifact_json"`
	} `json:"positive"`
	NegativeEndpointValues []string `json:"negative_endpoint_values"`
}

func loadPrivateLoopbackVectors(t *testing.T) privateLoopbackVectors {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/private_loopback_v1/profile_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors privateLoopbackVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Version != 1 || vectors.Profile != PrivateLoopbackProfile || vectors.NestedProfile != artifactv3.Profile || len(vectors.Positive) == 0 {
		t.Fatalf("invalid private loopback vector registry: %#v", vectors)
	}
	return vectors
}

func TestIssuePrivateLoopbackDirectKeepsFlowersecV3ArtifactUnchanged(t *testing.T) {
	vectors := loadPrivateLoopbackVectors(t)
	now := time.Unix(1_900_000_000, 0)
	for _, positive := range vectors.Positive {
		positive := positive
		t.Run(positive.ID, func(t *testing.T) {
			issued, err := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{7}, 256)), now).IssuePrivateLoopbackDirect(PrivateLoopbackIssueOptions{
				Session:           SessionOptions{ChannelID: "channel", ExpiresAt: now.Add(time.Minute)},
				Endpoint:          positive.Endpoint,
				RendezvousGroupID: "group", ListenerAudience: "listener", UpstreamAddress: "127.0.0.1:23998",
			})
			if err != nil {
				t.Fatal(err)
			}
			if got, want := string(issued.ArtifactJSON()), positive.ArtifactJSON; got != want {
				t.Fatalf("issued private profile does not match shared vector\ngot:  %s\nwant: %s", got, want)
			}
			var envelope struct {
				ArtifactBase64URL string `json:"artifact_b64u"`
				Endpoint          string `json:"endpoint"`
				Profile           string `json:"profile"`
				Version           uint8  `json:"v"`
			}
			if err := json.Unmarshal(issued.ArtifactJSON(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Version != 1 || envelope.Profile != PrivateLoopbackProfile || envelope.Endpoint != positive.Endpoint {
				t.Fatalf("private profile envelope = %#v", envelope)
			}
			innerJSON, err := base64.RawURLEncoding.DecodeString(envelope.ArtifactBase64URL)
			if err != nil {
				t.Fatal(err)
			}
			inner, err := artifactv3.DecodeArtifactJSON(bytes.NewReader(innerJSON))
			if err != nil {
				t.Fatal(err)
			}
			_, candidateURL, err := privateloopbackv1.ValidateEndpoint(positive.Endpoint)
			if err != nil || inner.Profile != artifactv3.Profile || len(inner.Path.Candidates) != 1 ||
				inner.Path.Candidates[0].URL != candidateURL || inner.Path.Candidates[0].TLS.Mode != artifactv3.TLSModeCA {
				t.Fatalf("nested v3 artifact = %#v, endpoint error = %v", inner, err)
			}
			if _, err := artifactv3.DecodeArtifactJSON(bytes.NewReader(issued.ArtifactJSON())); !errors.Is(err, artifactv3.ErrInvalidArtifact) {
				t.Fatalf("ordinary v3 decoder error = %v, want invalid artifact", err)
			}
			if issued.LookupKey() == "" || issued.AuthorizationRecord().LookupKey() != issued.LookupKey() {
				t.Fatal("private profile lost its authorization record")
			}
		})
	}
}

func TestIssuedPrivateLoopbackArtifactIsOpaqueAndReturnsClones(t *testing.T) {
	issued, err := NewIssuer().IssuePrivateLoopbackDirect(PrivateLoopbackIssueOptions{
		Session:           SessionOptions{ChannelID: "opaque", ExpiresAt: time.Now().Add(time.Minute)},
		Endpoint:          "ws://127.0.0.1:23998/flowersec/v3/direct",
		RendezvousGroupID: "opaque", ListenerAudience: "listener", UpstreamAddress: "127.0.0.1:23998",
	})
	if err != nil {
		t.Fatal(err)
	}
	first := issued.ArtifactJSON()
	first[0] ^= 0xff
	if second := issued.ArtifactJSON(); len(second) == 0 || second[0] != '{' {
		t.Fatal("ArtifactJSON did not return an independent clone")
	}
	if got := issued.String(); got != "Flowersec.IssuedPrivateLoopbackArtifact" {
		t.Fatalf("String() = %q", got)
	}
	if got := issued.GoString(); got != "controlplane.IssuedPrivateLoopbackArtifact" {
		t.Fatalf("GoString() = %q", got)
	}
	if raw, err := json.Marshal(issued); err != nil || string(raw) != "{}" {
		t.Fatalf("MarshalJSON() = %s, %v", raw, err)
	}
}

func TestIssuePrivateLoopbackDirectRejectsNonPrivateEndpoints(t *testing.T) {
	issuer := NewIssuer()
	for _, endpoint := range append(loadPrivateLoopbackVectors(t).NegativeEndpointValues,
		"ws://127.0.0.1:023998/flowersec/v3/direct") {
		if _, err := issuer.IssuePrivateLoopbackDirect(PrivateLoopbackIssueOptions{Endpoint: endpoint}); !errors.Is(err, ErrInvalidControlPlaneInput) {
			t.Fatalf("endpoint %q error = %v, want invalid input", endpoint, err)
		}
	}
}
