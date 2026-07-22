package artifactv2_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/artifactv2"
)

type artifactVectorFile struct {
	Version  int                      `json:"version"`
	Profile  string                   `json:"profile"`
	Positive []artifactPositiveVector `json:"positive"`
	FSA2     []artifactFSA2Vector     `json:"fsa2"`
	Negative []artifactNegativeVector `json:"negative"`
}

type artifactPositiveVector struct {
	ID                        string                 `json:"id"`
	ArtifactJSON              string                 `json:"artifact_json"`
	SessionCanonicalJSON      string                 `json:"session_canonical_json"`
	SessionContractHashBase64 string                 `json:"session_contract_hash_b64u"`
	CandidatesCanonicalJSON   string                 `json:"candidates_canonical_json"`
	CandidateSetHashBase64    string                 `json:"candidate_set_hash_b64u"`
	Winners                   []artifactWinnerVector `json:"winners"`
}

type artifactWinnerVector struct {
	CandidateID      string `json:"candidate_id"`
	FSB2Hex          string `json:"fsb2_hex"`
	AdmissionBinding string `json:"admission_binding_hex"`
}

type artifactFSA2Vector struct {
	ID       string `json:"id"`
	Status   uint8  `json:"status"`
	Reason   string `json:"reason"`
	FrameHex string `json:"frame_hex"`
}

type artifactNegativeVector struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	ErrorCode string `json:"error_code"`
}

func TestSharedArtifactAndAdmissionVectors(t *testing.T) {
	fixture := loadArtifactVectors(t)
	if fixture.Version != 1 || fixture.Profile != artifactv2.Profile || len(fixture.Positive) == 0 {
		t.Fatal("invalid artifact fixture header")
	}
	for _, vector := range fixture.Positive {
		t.Run(vector.ID, func(t *testing.T) {
			artifact, err := artifactv2.DecodeArtifactJSON(bytes.NewBufferString(vector.ArtifactJSON))
			if err != nil {
				t.Fatal(err)
			}
			encodedArtifact, err := artifactv2.MarshalArtifactJSON(*artifact)
			if err != nil || string(encodedArtifact) != vector.ArtifactJSON {
				t.Fatalf("artifact canonical encoding mismatch: %v", err)
			}

			sessionHash, sessionCanonical, err := artifactv2.ComputeSessionContractHash(artifact.Session)
			if err != nil || string(sessionCanonical) != vector.SessionCanonicalJSON {
				t.Fatalf("session canonical preimage mismatch: %v", err)
			}
			assertBase64Hash(t, sessionHash, vector.SessionContractHashBase64)

			_, candidatesCanonical, candidateHash, err := artifactv2.CanonicalizeCandidates(
				artifact.Path.Kind,
				artifact.Path.Candidates,
			)
			if err != nil || string(candidatesCanonical) != vector.CandidatesCanonicalJSON {
				t.Fatalf("candidate canonical preimage mismatch: %v", err)
			}
			assertBase64Hash(t, candidateHash, vector.CandidateSetHashBase64)

			for _, winner := range vector.Winners {
				request, err := artifactv2.BuildRequest(*artifact, winner.CandidateID)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := artifactv2.MarshalRequest(request)
				if err != nil {
					t.Fatal(err)
				}
				if got := hex.EncodeToString(raw); got != winner.FSB2Hex {
					t.Fatalf("FSB2 = %s, want %s", got, winner.FSB2Hex)
				}
				decoded, err := artifactv2.ParseRequest(raw)
				if err != nil || !bytes.Equal(decoded.Raw, raw) {
					t.Fatalf("parse FSB2: %v", err)
				}
				if got := hex.EncodeToString(decoded.LocalAdmissionBinding[:]); got != winner.AdmissionBinding {
					t.Fatalf("admission binding = %s, want %s", got, winner.AdmissionBinding)
				}
			}
		})
	}

	reasons := artifactv2.ReasonRegistry{"invalid_token": {}, "capacity": {}}
	for _, vector := range fixture.FSA2 {
		t.Run("fsa2-"+vector.ID, func(t *testing.T) {
			response := artifactv2.AdmissionResponse{
				Status: artifactv2.AdmissionStatus(vector.Status),
				Reason: vector.Reason,
			}
			raw, err := artifactv2.MarshalResponse(response, reasons)
			if err != nil || hex.EncodeToString(raw) != vector.FrameHex {
				t.Fatalf("marshal FSA2: %v", err)
			}
			decoded, err := artifactv2.ParseResponse(raw, reasons)
			if err != nil || decoded != response {
				t.Fatalf("parse FSA2: %#v, %v", decoded, err)
			}
		})
	}
}

func TestSharedArtifactAndAdmissionNegativeVectors(t *testing.T) {
	for _, vector := range loadArtifactVectors(t).Negative {
		t.Run(vector.ID, func(t *testing.T) {
			want := artifactVectorError(vector.ErrorCode)
			var err error
			switch vector.Kind {
			case "artifact_json":
				_, err = artifactv2.DecodeArtifactJSON(bytes.NewBufferString(vector.Value))
			case "fsb2_hex":
				_, err = artifactv2.ParseRequest(decodeHex(t, vector.Value))
			case "fsa2_hex":
				_, err = artifactv2.ParseResponse(
					decodeHex(t, vector.Value),
					artifactv2.ReasonRegistry{"invalid_token": {}, "capacity": {}},
				)
			default:
				t.Fatalf("unknown negative vector kind %q", vector.Kind)
			}
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
		})
	}
}

func loadArtifactVectors(t *testing.T) artifactVectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "transport_v2", "artifact_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture artifactVectorFile
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func artifactVectorError(code string) error {
	switch code {
	case "invalid_artifact":
		return artifactv2.ErrInvalidArtifact
	case "invalid_candidate":
		return artifactv2.ErrInvalidCandidate
	case "fsb2_payload_too_large":
		return artifactv2.ErrFSB2PayloadTooLarge
	case "invalid_fsb2":
		return artifactv2.ErrInvalidFSB2
	case "noncanonical_fsb2":
		return artifactv2.ErrNonCanonicalFSB2
	case "unknown_admission_reason":
		return artifactv2.ErrUnknownAdmissionCode
	case "invalid_fsa2":
		return artifactv2.ErrInvalidFSA2
	default:
		panic("unknown artifact vector error " + code)
	}
}

func assertBase64Hash(t *testing.T, got [32]byte, want string) {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(want)
	if err != nil || !bytes.Equal(got[:], decoded) {
		t.Fatalf("hash = %s, want %s", base64.RawURLEncoding.EncodeToString(got[:]), want)
	}
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
