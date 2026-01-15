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

	HandshakeP256 []struct {
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
			ClientPrivB64u string `json:"client_eph_priv_b64u"`
			ServerPrivB64u string `json:"server_eph_priv_b64u"`
			ClientPubB64u  string `json:"client_eph_pub_b64u"`
			ServerPubB64u  string `json:"server_eph_pub_b64u"`
			PSKB64u        string `json:"psk_b64u"`
		} `json:"inputs"`
		Expected struct {
			SharedSecretB64u   string `json:"shared_secret_b64u"`
			TranscriptHashB64u string `json:"transcript_hash_b64u"`
			C2SKeyB64u         string `json:"c2s_key_b64u"`
			S2CKeyB64u         string `json:"s2c_key_b64u"`
			C2SNoncePrefixB64u string `json:"c2s_nonce_prefix_b64u"`
			S2CNoncePrefixB64u string `json:"s2c_nonce_prefix_b64u"`
			RekeyBaseB64u      string `json:"rekey_base_b64u"`
		} `json:"expected"`
	} `json:"handshake_p256"`
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

	for _, tc := range vf.HandshakeP256 {
		t.Run(tc.CaseID, func(t *testing.T) {
			nonceCBytes, err := base64url.Decode(tc.Inputs.NonceCB64u)
			if err != nil || len(nonceCBytes) != 32 {
				t.Fatalf("bad nonce_c: %v len=%d", err, len(nonceCBytes))
			}
			nonceSBytes, err := base64url.Decode(tc.Inputs.NonceSB64u)
			if err != nil || len(nonceSBytes) != 32 {
				t.Fatalf("bad nonce_s: %v len=%d", err, len(nonceSBytes))
			}
			clientPrivBytes, err := base64url.Decode(tc.Inputs.ClientPrivB64u)
			if err != nil {
				t.Fatalf("bad client priv: %v", err)
			}
			serverPrivBytes, err := base64url.Decode(tc.Inputs.ServerPrivB64u)
			if err != nil {
				t.Fatalf("bad server priv: %v", err)
			}
			clientPubBytes, err := base64url.Decode(tc.Inputs.ClientPubB64u)
			if err != nil {
				t.Fatalf("bad client pub: %v", err)
			}
			serverPubBytes, err := base64url.Decode(tc.Inputs.ServerPubB64u)
			if err != nil {
				t.Fatalf("bad server pub: %v", err)
			}
			pskBytes, err := base64url.Decode(tc.Inputs.PSKB64u)
			if err != nil || len(pskBytes) != 32 {
				t.Fatalf("bad psk: %v len=%d", err, len(pskBytes))
			}

			curve, err := curveForSuite(Suite(tc.Inputs.Suite))
			if err != nil {
				t.Fatal(err)
			}
			clientPriv, err := curve.NewPrivateKey(clientPrivBytes)
			if err != nil {
				t.Fatal(err)
			}
			serverPriv, err := curve.NewPrivateKey(serverPrivBytes)
			if err != nil {
				t.Fatal(err)
			}

			clientPub := clientPriv.PublicKey().Bytes()
			if got := base64url.Encode(clientPub); got != tc.Inputs.ClientPubB64u {
				t.Fatalf("client pub mismatch: got=%s want=%s", got, tc.Inputs.ClientPubB64u)
			}
			serverPub := serverPriv.PublicKey().Bytes()
			if got := base64url.Encode(serverPub); got != tc.Inputs.ServerPubB64u {
				t.Fatalf("server pub mismatch: got=%s want=%s", got, tc.Inputs.ServerPubB64u)
			}

			peerPub, err := ParsePublicKey(Suite(tc.Inputs.Suite), serverPubBytes)
			if err != nil {
				t.Fatal(err)
			}
			sharedSecret, err := clientPriv.ECDH(peerPub)
			if err != nil {
				t.Fatal(err)
			}
			if got := base64url.Encode(sharedSecret); got != tc.Expected.SharedSecretB64u {
				t.Fatalf("shared secret mismatch: got=%s want=%s", got, tc.Expected.SharedSecretB64u)
			}

			var nc [32]byte
			var ns [32]byte
			copy(nc[:], nonceCBytes)
			copy(ns[:], nonceSBytes)

			th, err := TranscriptHash(TranscriptInputs{
				Version:        tc.Inputs.Version,
				Suite:          tc.Inputs.Suite,
				Role:           tc.Inputs.Role,
				ClientFeatures: tc.Inputs.ClientFeatures,
				ServerFeatures: tc.Inputs.ServerFeatures,
				ChannelID:      tc.Inputs.ChannelID,
				NonceC:         nc,
				NonceS:         ns,
				ClientEphPub:   clientPubBytes,
				ServerEphPub:   serverPubBytes,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := base64url.Encode(th[:]); got != tc.Expected.TranscriptHashB64u {
				t.Fatalf("transcript hash mismatch: got=%s want=%s", got, tc.Expected.TranscriptHashB64u)
			}

			keys, err := DeriveSessionKeys(pskBytes, Suite(tc.Inputs.Suite), sharedSecret, th)
			if err != nil {
				t.Fatal(err)
			}
			if got := base64url.Encode(keys.C2SKey[:]); got != tc.Expected.C2SKeyB64u {
				t.Fatalf("c2s key mismatch: got=%s want=%s", got, tc.Expected.C2SKeyB64u)
			}
			if got := base64url.Encode(keys.S2CKey[:]); got != tc.Expected.S2CKeyB64u {
				t.Fatalf("s2c key mismatch: got=%s want=%s", got, tc.Expected.S2CKeyB64u)
			}
			if got := base64url.Encode(keys.C2SNoncePre[:]); got != tc.Expected.C2SNoncePrefixB64u {
				t.Fatalf("c2s nonce prefix mismatch: got=%s want=%s", got, tc.Expected.C2SNoncePrefixB64u)
			}
			if got := base64url.Encode(keys.S2CNoncePre[:]); got != tc.Expected.S2CNoncePrefixB64u {
				t.Fatalf("s2c nonce prefix mismatch: got=%s want=%s", got, tc.Expected.S2CNoncePrefixB64u)
			}
			if got := base64url.Encode(keys.RekeyBase[:]); got != tc.Expected.RekeyBaseB64u {
				t.Fatalf("rekey base mismatch: got=%s want=%s", got, tc.Expected.RekeyBaseB64u)
			}
		})
	}
}
