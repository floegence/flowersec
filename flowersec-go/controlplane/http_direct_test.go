package controlplane

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/artifactv3"
)

func TestHTTPDirectArtifactsBindExactPortsAndIndependentAuthorization(t *testing.T) {
	for endpoint, binding := range map[string]string{
		"ws://192.168.1.20:23998/flowersec/v3/direct": "wss://192.168.1.20:23998/flowersec/v3/direct",
		"ws://localhost/flowersec/v3/direct":          "wss://localhost:80/flowersec/v3/direct",
		"ws://localhost:443/flowersec/v3/direct":      "wss://localhost/flowersec/v3/direct",
		"ws://[2001:db8::1]:443/flowersec/v3/direct":  "wss://[2001:db8::1]/flowersec/v3/direct",
	} {
		options := HTTPDirectIssueOptions{
			Session:  SessionOptions{ChannelID: "http-client", ExpiresAt: time.Now().Add(time.Minute)},
			Endpoint: endpoint, RendezvousGroupID: "group", ListenerAudience: "listener", UpstreamAddress: "127.0.0.1:23998",
		}
		issuer := NewIssuer()
		first, err := issuer.IssueHTTPDirect(options)
		if err != nil {
			t.Fatal(err)
		}
		second, err := issuer.IssueHTTPDirect(options)
		if err != nil {
			t.Fatal(err)
		}
		if first.LookupKey() == "" || first.LookupKey() == second.LookupKey() || first.AuthorizationRecord().LookupKey() != first.LookupKey() {
			t.Fatal("clients did not receive independent authorization records")
		}
		var envelope struct {
			Artifact string `json:"artifact_b64u"`
			Endpoint string `json:"endpoint"`
			Profile  string `json:"profile"`
		}
		if err := json.Unmarshal(first.ArtifactJSON(), &envelope); err != nil {
			t.Fatal(err)
		}
		innerBytes, err := base64.RawURLEncoding.DecodeString(envelope.Artifact)
		if err != nil {
			t.Fatal(err)
		}
		inner, err := artifactv3.DecodeArtifactJSON(bytes.NewReader(innerBytes))
		if err != nil {
			t.Fatal(err)
		}
		if envelope.Endpoint != endpoint || envelope.Profile != HTTPDirectProfile || len(inner.Path.Candidates) != 1 ||
			inner.Path.Candidates[0].URL != binding || inner.Path.Candidates[0].ID != "http-direct" {
			t.Fatalf("endpoint binding changed: %s", endpoint)
		}
		clone := first.ArtifactJSON()
		clone[0] ^= 0xff
		if first.ArtifactJSON()[0] != '{' {
			t.Fatal("caller mutated the issued artifact")
		}
		if first.String() != "Flowersec.IssuedHTTPDirectArtifact" || first.GoString() != "controlplane.IssuedHTTPDirectArtifact" {
			t.Fatal("artifact formatting exposed credentials")
		}
		if raw, err := json.Marshal(first); err != nil || string(raw) != "{}" {
			t.Fatal("JSON exposed credentials")
		}
	}
}

func TestHTTPDirectIssuanceRejectsInvalidEndpointAndSession(t *testing.T) {
	issuer := NewIssuer()
	for _, endpoint := range []string{"", "wss://localhost:23998/flowersec/v3/direct", "ws://0.0.0.0:23998/flowersec/v3/direct"} {
		if _, err := issuer.IssueHTTPDirect(HTTPDirectIssueOptions{Endpoint: endpoint}); !errors.Is(err, ErrInvalidControlPlaneInput) {
			t.Fatalf("endpoint %q: %v", endpoint, err)
		}
	}
	if _, err := issuer.IssueHTTPDirect(HTTPDirectIssueOptions{Endpoint: "ws://localhost:23998/flowersec/v3/direct"}); err == nil {
		t.Fatal("missing session authority was accepted")
	}
}
