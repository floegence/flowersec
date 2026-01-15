package e2ee

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/flowersec/flowersec/internal/base64url"
)

type e2eeVectorsFile struct {
	TranscriptHash []struct {
		CaseID string `json:"case_id"`
		Inputs struct {
			Version        uint8  `json:"version"`
			Suite          uint16 `json:"suite"`
			Role           uint8  `json:"role"`
			ClientFeatures uint32 `json:"client_features"`
			ServerFeatures uint32 `json:"server_features"`
			ChannelID      string `json:"channel_id"`
			NonceCB64u     string `json:"nonce_c_b64u"`
			NonceSB64u     string `json:"nonce_s_b64u"`
			ClientPubB64u  string `json:"client_eph_pub_b64u"`
			ServerPubB64u  string `json:"server_eph_pub_b64u"`
		} `json:"inputs"`
		Expected struct {
			TranscriptHashB64u string `json:"transcript_hash_b64u"`
		} `json:"expected"`
	} `json:"transcript_hash"`

	RecordFrame []struct {
		CaseID string `json:"case_id"`
		Inputs struct {
			KeyB64u         string `json:"key_b64u"`
			NoncePrefixB64u string `json:"nonce_prefix_b64u"`
			Flags           uint8  `json:"flags"`
			Seq             uint64 `json:"seq"`
			PlaintextUTF8   string `json:"plaintext_utf8"`
			MaxRecordBytes  int    `json:"max_record_bytes"`
		} `json:"inputs"`
		Expected struct {
			FrameB64u string `json:"frame_b64u"`
		} `json:"expected"`
	} `json:"record_frame"`
}

func TestVectors_E2EE(t *testing.T) {
	p := filepath.Join("..", "..", "..", "idl", "flowersec", "testdata", "v1", "e2ee_vectors.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var vf e2eeVectorsFile
	if err := json.Unmarshal(b, &vf); err != nil {
		t.Fatal(err)
	}

	for _, tc := range vf.TranscriptHash {
		t.Run(tc.CaseID, func(t *testing.T) {
			nonceCBytes, err := base64url.Decode(tc.Inputs.NonceCB64u)
			if err != nil || len(nonceCBytes) != 32 {
				t.Fatalf("bad nonce_c: %v len=%d", err, len(nonceCBytes))
			}
			nonceSBytes, err := base64url.Decode(tc.Inputs.NonceSB64u)
			if err != nil || len(nonceSBytes) != 32 {
				t.Fatalf("bad nonce_s: %v len=%d", err, len(nonceSBytes))
			}
			clientPub, err := base64url.Decode(tc.Inputs.ClientPubB64u)
			if err != nil {
				t.Fatal(err)
			}
			serverPub, err := base64url.Decode(tc.Inputs.ServerPubB64u)
			if err != nil {
				t.Fatal(err)
			}
			var nc [32]byte
			var ns [32]byte
			copy(nc[:], nonceCBytes)
			copy(ns[:], nonceSBytes)

			h, err := TranscriptHash(TranscriptInputs{
				Version:        tc.Inputs.Version,
				Suite:          tc.Inputs.Suite,
				Role:           tc.Inputs.Role,
				ClientFeatures: tc.Inputs.ClientFeatures,
				ServerFeatures: tc.Inputs.ServerFeatures,
				ChannelID:      tc.Inputs.ChannelID,
				NonceC:         nc,
				NonceS:         ns,
				ClientEphPub:   clientPub,
				ServerEphPub:   serverPub,
			})
			if err != nil {
				t.Fatal(err)
			}
			got := base64url.Encode(h[:])
			if got != tc.Expected.TranscriptHashB64u {
				t.Fatalf("transcript hash mismatch: got=%s want=%s", got, tc.Expected.TranscriptHashB64u)
			}
		})
	}

	for _, tc := range vf.RecordFrame {
		t.Run(tc.CaseID, func(t *testing.T) {
			keyBytes, err := base64url.Decode(tc.Inputs.KeyB64u)
			if err != nil || len(keyBytes) != 32 {
				t.Fatalf("bad key: %v len=%d", err, len(keyBytes))
			}
			npBytes, err := base64url.Decode(tc.Inputs.NoncePrefixB64u)
			if err != nil || len(npBytes) != 4 {
				t.Fatalf("bad nonce_prefix: %v len=%d", err, len(npBytes))
			}
			var key [32]byte
			var np [4]byte
			copy(key[:], keyBytes)
			copy(np[:], npBytes)
			frame, err := EncryptRecord(key, np, RecordFlag(tc.Inputs.Flags), tc.Inputs.Seq, []byte(tc.Inputs.PlaintextUTF8), tc.Inputs.MaxRecordBytes)
			if err != nil {
				t.Fatal(err)
			}
			got := base64url.Encode(frame)
			if got != tc.Expected.FrameB64u {
				t.Fatalf("record frame mismatch: got=%s want=%s", got, tc.Expected.FrameB64u)
			}
		})
	}
}
