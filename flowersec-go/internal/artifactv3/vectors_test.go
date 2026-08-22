package artifactv3

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
)

type artifactVectorFile struct {
	Version  int    `json:"version"`
	Profile  string `json:"profile"`
	Positive []struct {
		ID                      string `json:"id"`
		ArtifactJSON            string `json:"artifact_json"`
		SessionCanonicalJSON    string `json:"session_canonical_json"`
		SessionContractHash     string `json:"session_contract_hash_b64u"`
		CandidatesCanonicalJSON string `json:"candidates_canonical_json"`
		CandidateSetHash        string `json:"candidate_set_hash_b64u"`
		TLS                     []struct {
			CandidateID string `json:"candidate_id"`
			DigestHex   string `json:"digest_hex"`
		} `json:"tls_policy_digests"`
		Winners []struct {
			CandidateID      string `json:"candidate_id"`
			FSB3Hex          string `json:"fsb3_hex"`
			AdmissionBinding string `json:"admission_binding_hex"`
		} `json:"winners"`
		AcceptorAdmissionsHash string `json:"acceptor_admissions_hash_hex"`
	} `json:"positive"`
	ScalarBoundaries        []artifactBoundaryVector `json:"scalar_boundaries"`
	ScopedPayloadBoundaries []artifactBoundaryVector `json:"scoped_payload_boundaries"`
	ArtifactByteNegative    []frameNegativeVector    `json:"artifact_byte_negative"`
	FSB3Negative            []frameNegativeVector    `json:"fsb3_negative"`
	FSA3Negative            []frameNegativeVector    `json:"fsa3_negative"`
	ActivePinSnapshots      []struct {
		ID         string    `json:"id"`
		AttemptNow int64     `json:"attempt_now"`
		Declared   TLSPolicy `json:"declared"`
		Active     []string  `json:"active_value_b64u"`
		Result     string    `json:"result"`
	} `json:"active_pin_snapshots"`
	FSA3 []struct {
		Status   AdmissionStatus `json:"status"`
		Reason   string          `json:"reason"`
		FrameHex string          `json:"frame_hex"`
	} `json:"fsa3"`
	Negative []struct {
		ID    string `json:"id"`
		Kind  string `json:"kind"`
		Value string `json:"value"`
	} `json:"negative"`
}

type artifactBoundaryVector struct {
	ID           string `json:"id"`
	Accepted     bool   `json:"accepted"`
	ArtifactJSON string `json:"artifact_json"`
}

type frameNegativeVector struct {
	ID        string `json:"id"`
	ValueHex  string `json:"value_hex"`
	ErrorCode string `json:"error_code"`
}

type urlNormalizationVectorFile struct {
	URLNormalization struct {
		Positive []struct {
			ID         string   `json:"id"`
			Carrier    Carrier  `json:"carrier"`
			PathKind   PathKind `json:"path_kind"`
			Input      string   `json:"input"`
			Normalized string   `json:"normalized"`
		} `json:"positive"`
		Negative []struct {
			ID        string   `json:"id"`
			Carrier   Carrier  `json:"carrier"`
			PathKind  PathKind `json:"path_kind"`
			Input     string   `json:"input"`
			ErrorCode string   `json:"error_code"`
		} `json:"negative"`
	} `json:"url_normalization"`
}

func TestTransportV3ArtifactVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v3/artifact_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors artifactVectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Version != 3 || vectors.Profile != Profile {
		t.Fatal("unexpected vector contract")
	}
	for _, vector := range vectors.Positive {
		t.Run(vector.ID, func(t *testing.T) {
			artifact, err := DecodeArtifactJSON(bytes.NewBufferString(vector.ArtifactJSON))
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := MarshalArtifactJSON(*artifact)
			if err != nil || string(encoded) != vector.ArtifactJSON {
				t.Fatalf("artifact canonical mismatch: %v", err)
			}
			sessionHash, sessionJSON, err := ComputeSessionContractHash(artifact.Session)
			if err != nil || string(sessionJSON) != vector.SessionCanonicalJSON || encodeHash(sessionHash) != vector.SessionContractHash {
				t.Fatalf("session contract mismatch: %v", err)
			}
			canonical, candidateJSON, candidateHash, err := CanonicalizeCandidates(artifact.Path.Kind, artifact.Path.Candidates)
			if err != nil {
				t.Fatal(err)
			}
			if string(candidateJSON) != vector.CandidatesCanonicalJSON || encodeHash(candidateHash) != vector.CandidateSetHash {
				t.Fatal("candidate canonicalization mismatch")
			}
			byID := make(map[string]CanonicalCandidate, len(canonical))
			for _, candidate := range canonical {
				byID[candidate.ID] = candidate
			}
			for _, tlsVector := range vector.TLS {
				digest, err := TLSPolicyDigest(byID[tlsVector.CandidateID].TLS)
				if err != nil || hex.EncodeToString(digest[:]) != tlsVector.DigestHex {
					t.Fatalf("tls policy digest %s mismatch: %v", tlsVector.CandidateID, err)
				}
			}
			frames := make([][]byte, 0, len(vector.Winners))
			for _, winner := range vector.Winners {
				request, err := BuildRequest(*artifact, winner.CandidateID)
				if err != nil {
					t.Fatal(err)
				}
				frame, err := MarshalRequest(request)
				if err != nil || hex.EncodeToString(frame) != winner.FSB3Hex {
					t.Fatalf("FSB3 %s mismatch: %v", winner.CandidateID, err)
				}
				decoded, err := ParseRequest(frame)
				if err != nil || decoded.Request.ChosenCandidateID != winner.CandidateID || !bytes.Equal(decoded.Raw, frame) {
					t.Fatalf("FSB3 %s decode mismatch: %v", winner.CandidateID, err)
				}
				binding := AdmissionBinding(frame)
				if hex.EncodeToString(binding[:]) != winner.AdmissionBinding || decoded.LocalAdmissionBinding != binding {
					t.Fatalf("admission binding %s mismatch", winner.CandidateID)
				}
				frames = append(frames, frame)
			}
			acceptor, err := AcceptorAdmissionsHash(frames)
			if err != nil || hex.EncodeToString(acceptor[:]) != vector.AcceptorAdmissionsHash {
				t.Fatalf("acceptor admissions hash mismatch: %v", err)
			}
		})
	}
	for _, vector := range vectors.Negative {
		t.Run(vector.ID, func(t *testing.T) {
			if vector.Kind != "artifact_json" {
				t.Fatalf("unsupported negative vector kind %q", vector.Kind)
			}
			if _, err := DecodeArtifactJSON(bytes.NewBufferString(vector.Value)); err == nil {
				t.Fatal("invalid artifact accepted")
			}
		})
	}
	for _, group := range [][]artifactBoundaryVector{vectors.ScalarBoundaries, vectors.ScopedPayloadBoundaries} {
		for _, vector := range group {
			t.Run(vector.ID, func(t *testing.T) {
				artifact, err := DecodeArtifactJSON(bytes.NewBufferString(vector.ArtifactJSON))
				if !vector.Accepted {
					if err == nil {
						t.Fatal("rejected artifact boundary was accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := MarshalArtifactJSON(*artifact)
				if err != nil || string(encoded) != vector.ArtifactJSON {
					t.Fatalf("accepted artifact boundary is not canonical: %v", err)
				}
			})
		}
	}
	for _, vector := range vectors.ArtifactByteNegative {
		t.Run(vector.ID, func(t *testing.T) {
			raw, err := hex.DecodeString(vector.ValueHex)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeArtifactJSON(bytes.NewReader(raw)); !errors.Is(err, artifactVectorError(vector.ErrorCode)) {
				t.Fatalf("error = %v, want %s", err, vector.ErrorCode)
			}
		})
	}
	for _, vector := range vectors.FSB3Negative {
		t.Run(vector.ID, func(t *testing.T) {
			raw, err := hex.DecodeString(vector.ValueHex)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseRequest(raw); !errors.Is(err, artifactVectorError(vector.ErrorCode)) {
				t.Fatalf("error = %v, want %s", err, vector.ErrorCode)
			}
		})
	}
	for _, vector := range vectors.FSA3Negative {
		t.Run(vector.ID, func(t *testing.T) {
			raw, err := hex.DecodeString(vector.ValueHex)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseClientResponse(raw); !errors.Is(err, artifactVectorError(vector.ErrorCode)) {
				t.Fatalf("error = %v, want %s", err, vector.ErrorCode)
			}
		})
	}
	for _, vector := range vectors.ActivePinSnapshots {
		t.Run(vector.ID, func(t *testing.T) {
			active, err := ActivePinHashes(vector.Declared, vector.AttemptNow)
			if err != nil {
				t.Fatal(err)
			}
			encoded := make([]string, 0, len(active))
			for _, value := range active {
				encoded = append(encoded, base64.RawURLEncoding.EncodeToString(value[:]))
			}
			if !slices.Equal(encoded, vector.Active) {
				t.Fatalf("active pins = %v, want %v", encoded, vector.Active)
			}
			if vector.Result != "attempt" && vector.Result != "tls_policy_expired" {
				t.Fatalf("unknown active pin result %q", vector.Result)
			}
			if vector.Result == "tls_policy_expired" && len(active) != 0 {
				t.Fatalf("expired policy retained %d active pins", len(active))
			}
		})
	}
	for _, vector := range vectors.FSA3 {
		t.Run(fmt.Sprintf("fsa3-%d-%s", vector.Status, vector.Reason), func(t *testing.T) {
			reasons := ReasonRegistry{}
			if vector.Reason != "" {
				reasons[vector.Reason] = struct{}{}
			}
			frame, err := MarshalResponse(AdmissionResponse{Status: vector.Status, Reason: vector.Reason}, reasons)
			if err != nil || hex.EncodeToString(frame) != vector.FrameHex {
				t.Fatalf("FSA3 encode mismatch: %v", err)
			}
			decoded, err := ParseResponse(frame, reasons)
			if err != nil || decoded.Status != vector.Status || decoded.Reason != vector.Reason {
				t.Fatalf("FSA3 decode mismatch: %v", err)
			}
			crossVersion := bytes.Clone(frame)
			crossVersion[3], crossVersion[4] = '2', 2
			if _, err := ParseResponse(crossVersion, reasons); err == nil {
				t.Fatal("cross-version FSA3 accepted")
			}
		})
	}
}

func artifactVectorError(code string) error {
	switch code {
	case "invalid_artifact":
		return ErrInvalidArtifact
	case "invalid_fsb3":
		return ErrInvalidFSB3
	case "fsb3_payload_too_large":
		return ErrFSB3PayloadTooLarge
	case "noncanonical_fsb3":
		return ErrNonCanonicalFSB3
	case "invalid_fsa3":
		return ErrInvalidFSA3
	default:
		panic("unknown artifact vector error code: " + code)
	}
}

func TestTransportV3URLNormalizationVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v3/idna_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors urlNormalizationVectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.URLNormalization.Positive) == 0 || len(vectors.URLNormalization.Negative) == 0 {
		t.Fatal("URL normalization vectors must be nonempty")
	}
	for _, vector := range vectors.URLNormalization.Positive {
		t.Run("positive-"+vector.ID, func(t *testing.T) {
			normalized, err := normalizeCandidateURL(vector.PathKind, vector.Carrier, vector.Input)
			if err != nil {
				t.Fatal(err)
			}
			if normalized != vector.Normalized {
				t.Fatalf("normalized URL = %q, want %q", normalized, vector.Normalized)
			}
		})
	}
	for _, vector := range vectors.URLNormalization.Negative {
		t.Run("negative-"+vector.ID, func(t *testing.T) {
			if vector.ErrorCode != "invalid_artifact" {
				t.Fatalf("error code = %q, want invalid_artifact", vector.ErrorCode)
			}
			if _, err := normalizeCandidateURL(vector.PathKind, vector.Carrier, vector.Input); err == nil {
				t.Fatal("invalid URL was accepted")
			}
		})
	}
}

func encodeHash(value [32]byte) string {
	return base64.RawURLEncoding.EncodeToString(value[:])
}
