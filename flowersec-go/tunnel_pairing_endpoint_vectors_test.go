package flowersec

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/artifactv3"
)

type pairingVector struct {
	ArtifactJSON  string `json:"artifact_json"`
	CandidateID   string `json:"candidate_id"`
	CandidateHash string `json:"candidate_set_hash_b64u"`
	Frame         string `json:"fsb5_hex"`
	Binding       string `json:"admission_binding_hex"`
}

type pairingVectors struct {
	Listeners map[string]struct{ URL string }
	Legs      map[string]pairingVector
	Scenarios []struct {
		ID    string
		Steps [][3]string
	}
}

func readPairingVectors(t *testing.T, path string) pairingVectors {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture pairingVectors
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestTunnelPairingEndpointVectors(t *testing.T) {
	fixture := readPairingVectors(t, "../testdata/transport_v5/tunnel_pairing_vectors.json")
	for _, row := range [][3]string{{"client", "A", "B"}, {"server", "B", "A"}} {
		t.Run(row[0], func(t *testing.T) {
			leg := fixture.Legs[row[0]]
			artifact, err := ParseArtifact([]byte(leg.ArtifactJSON))
			if err != nil {
				t.Fatal(err)
			}
			lease, err := NewArtifactLease(artifact, func(context.Context) error { t.Error("unexpected spend"); return errors.New("unexpected spend") })
			if err != nil {
				t.Fatal(err)
			}
			_, err = Connect(t.Context(), lease, ConnectorOptions{TunnelEndpoint: fixture.Listeners[row[2]].URL})
			var failure *ConnectError
			if !errors.As(err, &failure) || failure.Code() != ConnectArtifactInvalid || !hasTunnelEndpoint(lease, fixture.Listeners[row[1]].URL) {
				t.Fatalf("local ingress selection: %v", err)
			}
			if _, idle := lease.claimArtifact(); !idle {
				t.Fatal("wrong ingress claimed lease")
			}
			request, err := artifactv3.BuildRequest(*artifact.value, leg.CandidateID)
			if err != nil {
				t.Fatal(err)
			}
			if base64.RawURLEncoding.EncodeToString(request.CandidateSetHash[:]) != leg.CandidateHash {
				t.Fatal("candidate digest mismatch")
			}
			frame, err := artifactv3.MarshalRequest(request)
			if err != nil || hex.EncodeToString(frame) != leg.Frame {
				t.Fatalf("FSB5 mismatch: %v", err)
			}
			binding := artifactv3.AdmissionBinding(frame)
			if hex.EncodeToString(binding[:]) != leg.Binding {
				t.Fatal("admission binding mismatch")
			}
		})
	}
}
