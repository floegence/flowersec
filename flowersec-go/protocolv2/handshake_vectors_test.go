package protocolv2_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	protocolv2 "github.com/floegence/flowersec/flowersec-go/v2/protocolv2"
)

type handshakeVectorFile struct {
	Version int    `json:"version"`
	Profile string `json:"profile"`
	Source  struct {
		Runtime        string `json:"runtime"`
		Implementation string `json:"implementation"`
		Generator      string `json:"generator"`
	} `json:"source"`
	Vectors []handshakeVector `json:"vectors"`
}

type handshakeVector struct {
	ID                              string `json:"id"`
	Suite                           uint16 `json:"suite"`
	Path                            string `json:"path"`
	MaxInboundStreams               uint16 `json:"max_inbound_streams"`
	ChannelID                       string `json:"channel_id"`
	ClientEndpointInstanceID        string `json:"client_endpoint_instance_id"`
	ServerEndpointInstanceID        string `json:"server_endpoint_instance_id"`
	PSKHex                          string `json:"psk_hex"`
	ClientPrivateHex                string `json:"client_private_hex"`
	ServerPrivateHex                string `json:"server_private_hex"`
	ClientPublicBase64URL           string `json:"client_public_b64u"`
	ServerPublicBase64URL           string `json:"server_public_b64u"`
	SharedSecretHex                 string `json:"shared_secret_hex"`
	SessionContractHashBase64URL    string `json:"session_contract_hash_b64u"`
	ClientAdmissionBindingBase64URL string `json:"client_admission_binding_b64u"`
	ServerAdmissionBindingBase64URL string `json:"server_admission_binding_b64u"`
	FSC2Hex                         string `json:"fsc2_hex"`
	ClientInitHex                   string `json:"client_init_hex"`
	ServerCoreHex                   string `json:"server_core_hex"`
	ServerFinishedHex               string `json:"server_finished_hex"`
	ClientCoreHex                   string `json:"client_core_hex"`
	ClientFinishedHex               string `json:"client_finished_hex"`
	HandshakePRKHex                 string `json:"handshake_prk_hex"`
	H0Hex                           string `json:"h0_hex"`
	H1Hex                           string `json:"h1_hex"`
	ServerConfirmKeyHex             string `json:"server_confirm_key_hex"`
	ServerConfirmHex                string `json:"server_confirm_hex"`
	H2Hex                           string `json:"h2_hex"`
	ClientConfirmKeyHex             string `json:"client_confirm_key_hex"`
	ClientConfirmHex                string `json:"client_confirm_hex"`
	H3Hex                           string `json:"h3_hex"`
	SessionPRKHex                   string `json:"session_prk_hex"`
}

func TestNode24HandshakeVectors(t *testing.T) {
	vectorFile := loadHandshakeVectors(t)
	if vectorFile.Version != 1 || vectorFile.Profile != "flowersec/2" || !strings.HasPrefix(vectorFile.Source.Runtime, "v24.") || vectorFile.Source.Implementation != "Node.js built-in crypto only" {
		t.Fatalf("unexpected vector provenance: %+v", vectorFile)
	}
	if vectorFile.Source.Generator != "testdata/transport_v2/generate_handshake_vectors.mjs" || len(vectorFile.Vectors) != 2 {
		t.Fatalf("unexpected vectors: %+v", vectorFile.Source)
	}

	for _, vector := range vectorFile.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			suite := protocolv2.Suite(vector.Suite)
			psk := mustHandshakeHex(t, vector.PSKHex)
			clientPrivate := mustHandshakeHex(t, vector.ClientPrivateHex)
			serverPrivate := mustHandshakeHex(t, vector.ServerPrivateHex)
			clientPublic := mustB64(t, vector.ClientPublicBase64URL)
			serverPublic := mustB64(t, vector.ServerPublicBase64URL)
			if got, err := protocolv2.EphemeralPublicKey(suite, clientPrivate); err != nil || !bytes.Equal(got, clientPublic) {
				t.Fatalf("client public = %x, error=%v", got, err)
			}
			if got, err := protocolv2.EphemeralPublicKey(suite, serverPrivate); err != nil || !bytes.Equal(got, serverPublic) {
				t.Fatalf("server public = %x, error=%v", got, err)
			}
			shared, err := protocolv2.ComputeECDHSharedSecret(suite, clientPrivate, serverPublic)
			if err != nil || !bytes.Equal(shared, mustHandshakeHex(t, vector.SharedSecretHex)) {
				t.Fatalf("shared = %x, error=%v", shared, err)
			}

			fsc2 := mustHandshakeHex(t, vector.FSC2Hex)
			initRaw := mustHandshakeHex(t, vector.ClientInitHex)
			serverCoreRaw := mustHandshakeHex(t, vector.ServerCoreHex)
			serverRaw := mustHandshakeHex(t, vector.ServerFinishedHex)
			clientCoreRaw := mustHandshakeHex(t, vector.ClientCoreHex)
			clientRaw := mustHandshakeHex(t, vector.ClientFinishedHex)
			if err := protocolv2.ParseControlPreface(fsc2); err != nil {
				t.Fatal(err)
			}
			init, err := protocolv2.ParseClientInit(initRaw)
			if err != nil {
				t.Fatal(err)
			}
			server, err := protocolv2.ParseServerFinished(serverRaw, suite)
			if err != nil {
				t.Fatal(err)
			}
			client, err := protocolv2.ParseClientFinished(clientRaw)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := protocolv2.MarshalClientInit(init); err != nil || !bytes.Equal(got, initRaw) {
				t.Fatalf("INIT remarshal error=%v", err)
			}
			if got, err := protocolv2.MarshalServerFinishedCore(server.Core, suite); err != nil || !bytes.Equal(got, serverCoreRaw) {
				t.Fatalf("server core remarshal error=%v", err)
			}
			if got, err := protocolv2.MarshalServerFinished(server, suite); err != nil || !bytes.Equal(got, serverRaw) {
				t.Fatalf("server remarshal error=%v", err)
			}
			if got, err := protocolv2.MarshalClientFinishedCore(client.HandshakeID); err != nil || !bytes.Equal(got, clientCoreRaw) {
				t.Fatalf("client core remarshal error=%v", err)
			}
			if got, err := protocolv2.MarshalClientFinished(client); err != nil || !bytes.Equal(got, clientRaw) {
				t.Fatalf("client remarshal error=%v", err)
			}

			handshakePRK, err := protocolv2.DeriveHandshakePRK(psk, shared)
			if err != nil || !bytes.Equal(handshakePRK[:], mustHandshakeHex(t, vector.HandshakePRKHex)) {
				t.Fatalf("handshake PRK = %x, error=%v", handshakePRK, err)
			}
			h0, err := protocolv2.ComputeHandshakeH0(fsc2, initRaw)
			if err != nil || !bytes.Equal(h0[:], mustHandshakeHex(t, vector.H0Hex)) {
				t.Fatalf("H0 = %x, error=%v", h0, err)
			}
			h1, err := protocolv2.ComputeHandshakeH1(h0, serverCoreRaw)
			if err != nil || !bytes.Equal(h1[:], mustHandshakeHex(t, vector.H1Hex)) {
				t.Fatalf("H1 = %x, error=%v", h1, err)
			}
			serverKey, serverConfirm, err := protocolv2.ComputeServerConfirm(handshakePRK, h1)
			if err != nil || !bytes.Equal(serverKey[:], mustHandshakeHex(t, vector.ServerConfirmKeyHex)) || !bytes.Equal(serverConfirm[:], mustHandshakeHex(t, vector.ServerConfirmHex)) || !protocolv2.VerifyServerConfirm(handshakePRK, h1, server.ServerConfirm) {
				t.Fatalf("server confirm mismatch error=%v", err)
			}
			h2, err := protocolv2.ComputeHandshakeH2(h1, serverRaw, clientCoreRaw)
			if err != nil || !bytes.Equal(h2[:], mustHandshakeHex(t, vector.H2Hex)) {
				t.Fatalf("H2 = %x, error=%v", h2, err)
			}
			clientKey, clientConfirm, err := protocolv2.ComputeClientConfirm(handshakePRK, h2)
			if err != nil || !bytes.Equal(clientKey[:], mustHandshakeHex(t, vector.ClientConfirmKeyHex)) || !bytes.Equal(clientConfirm[:], mustHandshakeHex(t, vector.ClientConfirmHex)) || !protocolv2.VerifyClientConfirm(handshakePRK, h2, client.ClientConfirm) {
				t.Fatalf("client confirm mismatch error=%v", err)
			}
			h3, err := protocolv2.ComputeHandshakeH3(h2, clientRaw)
			if err != nil || !bytes.Equal(h3[:], mustHandshakeHex(t, vector.H3Hex)) {
				t.Fatalf("H3 = %x, error=%v", h3, err)
			}
			sessionPRK := protocolv2.DeriveSessionPRK(h3, handshakePRK)
			if !bytes.Equal(sessionPRK[:], mustHandshakeHex(t, vector.SessionPRKHex)) {
				t.Fatalf("session PRK = %x", sessionPRK)
			}

			path := protocolv2.HandshakeDirect
			if vector.Path == "tunnel" {
				path = protocolv2.HandshakeTunnel
			}
			clientExpectation := protocolv2.HandshakeExpectations{
				Path: path, ChannelID: vector.ChannelID,
				SessionContractHash: mustB6432(t, vector.SessionContractHashBase64URL), Suite: suite,
				MaxInboundStreams:          vector.MaxInboundStreams,
				AdmissionBinding:           mustB6432(t, vector.ClientAdmissionBindingBase64URL),
				ExpectedEndpointInstanceID: vector.ClientEndpointInstanceID,
			}
			if err := protocolv2.ValidateClientInit(init, clientExpectation); err != nil {
				t.Fatal(err)
			}
			serverExpectation := protocolv2.HandshakeExpectations{
				Path: path, SessionContractHash: mustB6432(t, vector.SessionContractHashBase64URL), Suite: suite,
				MaxInboundStreams:          vector.MaxInboundStreams,
				AdmissionBinding:           mustB6432(t, vector.ServerAdmissionBindingBase64URL),
				ExpectedEndpointInstanceID: vector.ServerEndpointInstanceID,
			}
			if err := protocolv2.ValidateServerFinished(server, serverExpectation); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHandshakeConfirmAndTranscriptTampering(t *testing.T) {
	vector := loadHandshakeVectors(t).Vectors[0]
	suite := protocolv2.Suite(vector.Suite)
	handshakePRK := handshakeArray32(t, vector.HandshakePRKHex)
	fsc2 := mustHandshakeHex(t, vector.FSC2Hex)
	initRaw := mustHandshakeHex(t, vector.ClientInitHex)
	serverRaw := mustHandshakeHex(t, vector.ServerFinishedHex)
	clientCore := mustHandshakeHex(t, vector.ClientCoreHex)
	clientRaw := mustHandshakeHex(t, vector.ClientFinishedHex)
	server, err := protocolv2.ParseServerFinished(serverRaw, suite)
	if err != nil {
		t.Fatal(err)
	}
	client, err := protocolv2.ParseClientFinished(clientRaw)
	if err != nil {
		t.Fatal(err)
	}

	init, err := protocolv2.ParseClientInit(initRaw)
	if err != nil {
		t.Fatal(err)
	}
	initTampering := []struct {
		name   string
		mutate func(*protocolv2.ClientInit)
	}{
		{name: "admission binding", mutate: func(v *protocolv2.ClientInit) { v.ClientAdmissionBinding[0] ^= 1 }},
		{name: "session contract hash", mutate: func(v *protocolv2.ClientInit) { v.SessionContractHash[0] ^= 1 }},
		{name: "max inbound streams", mutate: func(v *protocolv2.ClientInit) { v.MaxInboundStreams++ }},
	}
	for _, tt := range initTampering {
		t.Run("INIT "+tt.name, func(t *testing.T) {
			mutated := init
			tt.mutate(&mutated)
			mutatedRaw, marshalErr := protocolv2.MarshalClientInit(mutated)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			h0, hashErr := protocolv2.ComputeHandshakeH0(fsc2, mutatedRaw)
			if hashErr != nil {
				t.Fatal(hashErr)
			}
			h1, hashErr := protocolv2.ComputeHandshakeH1(h0, mustHandshakeHex(t, vector.ServerCoreHex))
			if hashErr != nil {
				t.Fatal(hashErr)
			}
			if protocolv2.VerifyServerConfirm(handshakePRK, h1, server.ServerConfirm) {
				t.Fatalf("server confirm accepted %s tamper", tt.name)
			}
		})
	}

	serverTampering := []struct {
		name   string
		mutate func(*protocolv2.ServerFinished)
	}{
		{name: "admission binding", mutate: func(v *protocolv2.ServerFinished) { v.Core.ServerAdmissionBinding[0] ^= 1 }},
		{name: "session contract hash", mutate: func(v *protocolv2.ServerFinished) { v.Core.SessionContractHash[0] ^= 1 }},
		{name: "max inbound streams", mutate: func(v *protocolv2.ServerFinished) { v.Core.MaxInboundStreams++ }},
		{name: "endpoint instance ID", mutate: func(v *protocolv2.ServerFinished) { v.Core.ServerEndpointInstanceID = "tampered-endpoint" }},
	}
	for _, tt := range serverTampering {
		t.Run("FINISHED "+tt.name, func(t *testing.T) {
			mutated := server
			mutated.Core.HandshakeID = append([]byte(nil), server.Core.HandshakeID...)
			mutated.Core.ServerEphemeralPublic = append([]byte(nil), server.Core.ServerEphemeralPublic...)
			tt.mutate(&mutated)
			mutatedRaw, marshalErr := protocolv2.MarshalServerFinished(mutated, suite)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			h2, hashErr := protocolv2.ComputeHandshakeH2(handshakeArray32(t, vector.H1Hex), mutatedRaw, clientCore)
			if hashErr != nil {
				t.Fatal(hashErr)
			}
			if protocolv2.VerifyClientConfirm(handshakePRK, h2, client.ClientConfirm) {
				t.Fatalf("client confirm accepted %s tamper", tt.name)
			}
		})
	}

	badServerConfirm := server.ServerConfirm
	badServerConfirm[0] ^= 1
	if protocolv2.VerifyServerConfirm(handshakePRK, handshakeArray32(t, vector.H1Hex), badServerConfirm) {
		t.Fatal("accepted tampered server confirm")
	}
	badClientConfirm := client.ClientConfirm
	badClientConfirm[0] ^= 1
	if protocolv2.VerifyClientConfirm(handshakePRK, handshakeArray32(t, vector.H2Hex), badClientConfirm) {
		t.Fatal("accepted tampered client confirm")
	}
}

func TestECDHRejectsInvalidPublicKeysAndAllZeroSecret(t *testing.T) {
	private := make([]byte, 32)
	private[31] = 1
	if _, err := protocolv2.ComputeECDHSharedSecret(protocolv2.SuiteChaCha20Poly1305, private, make([]byte, 32)); err == nil {
		t.Fatal("accepted all-zero X25519 shared secret")
	}
	if _, err := protocolv2.ComputeECDHSharedSecret(protocolv2.SuiteAES256GCM, private, make([]byte, 65)); err == nil {
		t.Fatal("accepted invalid P-256 point")
	}
	if _, err := protocolv2.ParseEphemeralPublicKey(protocolv2.SuiteAES256GCM, append([]byte{2}, make([]byte, 32)...)); err == nil {
		t.Fatal("accepted compressed P-256 point")
	}
}

func loadHandshakeVectors(t *testing.T) handshakeVectorFile {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "transport_v2", "handshake_vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vectors handshakeVectorFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func mustHandshakeHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustB64(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != value {
		t.Fatalf("invalid base64url %q: %v", value, err)
	}
	return raw
}

func mustB6432(t *testing.T, value string) [32]byte {
	t.Helper()
	raw := mustB64(t, value)
	if len(raw) != 32 {
		t.Fatalf("length = %d", len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

func handshakeArray32(t *testing.T, value string) [32]byte {
	t.Helper()
	raw := mustHandshakeHex(t, value)
	if len(raw) != 32 {
		t.Fatalf("length = %d", len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}
