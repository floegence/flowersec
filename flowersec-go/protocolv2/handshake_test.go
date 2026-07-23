package protocolv2_test

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	protocolv2 "github.com/floegence/flowersec/flowersec-go/v2/protocolv2"
)

func TestControlPrefaceFSC2Exact(t *testing.T) {
	raw := protocolv2.MarshalControlPreface()
	if len(raw) != 16 || string(raw[0:4]) != "FSC2" || raw[4] != 2 || raw[5] != 1 || !bytes.Equal(raw[6:], make([]byte, 10)) {
		t.Fatalf("FSC2 = %x", raw)
	}
	if err := protocolv2.ParseControlPreface(raw); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte){
		func(raw []byte) { raw[0] = 'X' },
		func(raw []byte) { raw[4] = 1 },
		func(raw []byte) { raw[5] = 2 },
		func(raw []byte) { raw[6] = 1 },
		func(raw []byte) { raw[15] = 1 },
	} {
		bad := append([]byte(nil), raw...)
		mutate(bad)
		if err := protocolv2.ParseControlPreface(bad); err == nil {
			t.Fatalf("accepted FSC2 %x", bad)
		}
	}
}

func TestFSH2RejectsHeaderAndPayloadLengthBeforeAllocation(t *testing.T) {
	var oversized [protocolv2.HandshakeHeaderSize]byte
	copy(oversized[0:4], "FSH2")
	oversized[4] = 2
	oversized[5] = byte(protocolv2.HandshakeClientInit)
	binary.BigEndian.PutUint32(oversized[8:12], protocolv2.MaxHandshakePayloadBytes+1)
	reader := &countingHandshakeReader{data: oversized[:]}
	_, err := protocolv2.ReadHandshakeFrame(reader)
	if !errors.Is(err, protocolv2.ErrHandshakePayloadTooLarge) {
		t.Fatalf("error = %v", err)
	}
	if reader.bytesRead != protocolv2.HandshakeHeaderSize {
		t.Fatalf("read %d bytes, want header-only", reader.bytesRead)
	}

	valid := validClientInit(t, protocolv2.SuiteChaCha20Poly1305)
	raw, err := protocolv2.MarshalClientInit(valid)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte){
		func(raw []byte) { raw[0] = 'X' },
		func(raw []byte) { raw[4] = 1 },
		func(raw []byte) { raw[5] = 9 },
		func(raw []byte) { raw[6] = 1 },
		func(raw []byte) { binary.BigEndian.PutUint32(raw[8:12], uint32(len(raw))) },
	} {
		bad := append([]byte(nil), raw...)
		mutate(bad)
		if _, err := protocolv2.ParseHandshakeFrame(bad); err == nil {
			t.Fatalf("accepted FSH2 %x", bad[:12])
		}
	}
}

func TestHandshakeJSONRejectsDuplicateUnknownAndNonCanonicalFields(t *testing.T) {
	init := validClientInit(t, protocolv2.SuiteChaCha20Poly1305)
	raw, err := protocolv2.MarshalClientInit(init)
	if err != nil {
		t.Fatal(err)
	}
	payload := raw[protocolv2.HandshakeHeaderSize:]
	channelField := fmt.Sprintf("\"channel_id\":%q", init.ChannelID)
	tests := [][]byte{
		bytes.Replace(payload, []byte(channelField), []byte(channelField+","+channelField), 1),
		append([]byte(`{"future":true,`), payload[1:]...),
		append([]byte(" "), payload...),
	}
	for _, badPayload := range tests {
		bad := rawHandshakeFrame(protocolv2.HandshakeClientInit, badPayload)
		if _, err := protocolv2.ParseClientInit(bad); err == nil {
			t.Fatalf("accepted payload %s", badPayload)
		}
	}

	paddedValue := base64.RawURLEncoding.EncodeToString(init.ClientEphemeralPublic) + "="
	paddedRaw := replaceHandshakeJSONField(t, raw, "client_eph_pub_b64u", paddedValue)
	if _, err := protocolv2.ParseClientInit(paddedRaw); err == nil {
		t.Fatal("accepted padded base64url")
	}
}

func TestClientInitStrictFieldValidation(t *testing.T) {
	base := validClientInit(t, protocolv2.SuiteChaCha20Poly1305)
	tests := []struct {
		name   string
		mutate func(*protocolv2.ClientInit)
	}{
		{name: "profile", mutate: func(v *protocolv2.ClientInit) { v.Profile = "flowersec/1" }},
		{name: "channel", mutate: func(v *protocolv2.ClientInit) { v.ChannelID = "bad channel" }},
		{name: "role", mutate: func(v *protocolv2.ClientInit) { v.ClientRole = 2 }},
		{name: "suite", mutate: func(v *protocolv2.ClientInit) { v.Suite = 3 }},
		{name: "features", mutate: func(v *protocolv2.ClientInit) { v.SelectedFeatures = 1 }},
		{name: "max zero", mutate: func(v *protocolv2.ClientInit) { v.MaxInboundStreams = 0 }},
		{name: "max 129", mutate: func(v *protocolv2.ClientInit) { v.MaxInboundStreams = 129 }},
		{name: "endpoint grammar", mutate: func(v *protocolv2.ClientInit) { v.ClientEndpointInstanceID = "bad endpoint" }},
		{name: "X25519 key length", mutate: func(v *protocolv2.ClientInit) { v.ClientEphemeralPublic = make([]byte, 31) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := base
			value.ClientEphemeralPublic = append([]byte(nil), base.ClientEphemeralPublic...)
			tt.mutate(&value)
			if _, err := protocolv2.MarshalClientInit(value); err == nil {
				t.Fatalf("accepted %+v", value)
			}
		})
	}

	p256 := validClientInit(t, protocolv2.SuiteAES256GCM)
	p256.ClientEphemeralPublic = append([]byte{2}, p256.ClientEphemeralPublic[1:]...)
	if _, err := protocolv2.MarshalClientInit(p256); err == nil {
		t.Fatal("accepted compressed/invalid P-256 key")
	}
}

func TestHandshakeBindingExpectationsRejectTampering(t *testing.T) {
	init := validClientInit(t, protocolv2.SuiteChaCha20Poly1305)
	expect := protocolv2.HandshakeExpectations{
		Path:                       protocolv2.HandshakeDirect,
		ChannelID:                  init.ChannelID,
		SessionContractHash:        init.SessionContractHash,
		Suite:                      init.Suite,
		MaxInboundStreams:          init.MaxInboundStreams,
		AdmissionBinding:           init.ClientAdmissionBinding,
		ExpectedEndpointInstanceID: "",
	}
	if err := protocolv2.ValidateClientInit(init, expect); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*protocolv2.ClientInit){
		func(v *protocolv2.ClientInit) { v.SessionContractHash[0] ^= 1 },
		func(v *protocolv2.ClientInit) { v.ClientAdmissionBinding[0] ^= 1 },
		func(v *protocolv2.ClientInit) { v.MaxInboundStreams++ },
		func(v *protocolv2.ClientInit) { v.ClientEndpointInstanceID = "endpoint-client" },
	}
	for _, mutate := range mutations {
		value := init
		mutate(&value)
		if err := protocolv2.ValidateClientInit(value, expect); err == nil {
			t.Fatalf("binding validation accepted %+v", value)
		}
	}
}

func TestHandshakeAdmissionBindingPolicy(t *testing.T) {
	client := validClientInit(t, protocolv2.SuiteChaCha20Poly1305)
	server := protocolv2.ServerFinished{Core: protocolv2.ServerFinishedCore{
		Suite:                    client.Suite,
		HandshakeID:              bytes.Repeat([]byte{1}, 16),
		ServerEphemeralPublic:    append([]byte(nil), client.ClientEphemeralPublic...),
		NonceS:                   client.NonceC,
		SessionContractHash:      client.SessionContractHash,
		MaxInboundStreams:        client.MaxInboundStreams,
		ServerAdmissionBinding:   client.ClientAdmissionBinding,
		ServerEndpointInstanceID: "server-instance",
	}}
	client.ClientEndpointInstanceID = "client-instance"
	nonzero := client.ClientAdmissionBinding
	mismatch := nonzero
	mismatch[0] ^= 1

	tests := []struct {
		name     string
		path     protocolv2.HandshakePath
		expected [32]byte
		actual   [32]byte
		wantErr  bool
	}{
		{name: "direct exact", path: protocolv2.HandshakeDirect, expected: nonzero, actual: nonzero},
		{name: "direct mismatch", path: protocolv2.HandshakeDirect, expected: mismatch, actual: nonzero, wantErr: true},
		{name: "tunnel authenticated unknown", path: protocolv2.HandshakeTunnel, actual: nonzero},
		{name: "tunnel zero wire", path: protocolv2.HandshakeTunnel, wantErr: true},
		{name: "tunnel exact", path: protocolv2.HandshakeTunnel, expected: nonzero, actual: nonzero},
		{name: "tunnel expected mismatch", path: protocolv2.HandshakeTunnel, expected: mismatch, actual: nonzero, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientMessage := client
			serverMessage := server
			clientMessage.ClientAdmissionBinding = tt.actual
			serverMessage.Core.ServerAdmissionBinding = tt.actual
			expectation := protocolv2.HandshakeExpectations{
				Path: tt.path, ChannelID: client.ChannelID,
				SessionContractHash: client.SessionContractHash,
				Suite:               client.Suite, MaxInboundStreams: client.MaxInboundStreams,
				AdmissionBinding: tt.expected,
			}
			if tt.path == protocolv2.HandshakeTunnel {
				expectation.ExpectedEndpointInstanceID = "client-instance"
			} else {
				clientMessage.ClientEndpointInstanceID = ""
				serverMessage.Core.ServerEndpointInstanceID = ""
			}
			clientErr := protocolv2.ValidateClientInit(clientMessage, expectation)
			if tt.path == protocolv2.HandshakeTunnel {
				expectation.ExpectedEndpointInstanceID = "server-instance"
			}
			serverErr := protocolv2.ValidateServerFinished(serverMessage, expectation)
			if (clientErr != nil) != tt.wantErr || (serverErr != nil) != tt.wantErr {
				t.Fatalf("client error = %v, server error = %v, want error %v", clientErr, serverErr, tt.wantErr)
			}
		})
	}
}

func validClientInit(t *testing.T, suite protocolv2.Suite) protocolv2.ClientInit {
	t.Helper()
	private := make([]byte, 32)
	private[31] = 1
	public, err := protocolv2.EphemeralPublicKey(suite, private)
	if err != nil {
		t.Fatal(err)
	}
	var sessionHash, nonce, binding [32]byte
	for i := range sessionHash {
		sessionHash[i] = byte(i + 1)
		nonce[i] = byte(i + 33)
		binding[i] = byte(i + 65)
	}
	return protocolv2.ClientInit{
		Profile:                  "flowersec/2",
		ChannelID:                "channel-1",
		SessionContractHash:      sessionHash,
		ClientRole:               1,
		Suite:                    suite,
		ClientEphemeralPublic:    public,
		NonceC:                   nonce,
		SelectedFeatures:         0,
		MaxInboundStreams:        64,
		ClientAdmissionBinding:   binding,
		ClientEndpointInstanceID: "",
	}
}

func rawHandshakeFrame(typ protocolv2.HandshakeMessageType, payload []byte) []byte {
	out := make([]byte, protocolv2.HandshakeHeaderSize+len(payload))
	copy(out[0:4], "FSH2")
	out[4] = 2
	out[5] = byte(typ)
	binary.BigEndian.PutUint32(out[8:12], uint32(len(payload)))
	copy(out[12:], payload)
	return out
}

func replaceHandshakeJSONField(t *testing.T, raw []byte, key string, value any) []byte {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(raw[protocolv2.HandshakeHeaderSize:], &object); err != nil {
		t.Fatal(err)
	}
	object[key] = value
	payload, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return rawHandshakeFrame(protocolv2.HandshakeMessageType(raw[5]), payload)
}

type countingHandshakeReader struct {
	data      []byte
	bytesRead int
}

func (r *countingHandshakeReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, errors.New("payload must not be read")
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	r.bytesRead += n
	return n, nil
}
