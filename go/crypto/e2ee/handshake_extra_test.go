package e2ee

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	e2eev1 "github.com/floegence/flowersec/gen/flowersec/e2ee/v1"
	"github.com/floegence/flowersec/internal/base64url"
)

type scriptedTransport struct {
	reads   [][]byte
	writes  [][]byte
	onWrite func([]byte)
}

func (t *scriptedTransport) ReadBinary(_ context.Context) ([]byte, error) {
	if len(t.reads) == 0 {
		return nil, errors.New("unexpected read")
	}
	b := t.reads[0]
	t.reads = t.reads[1:]
	return b, nil
}

func (t *scriptedTransport) WriteBinary(_ context.Context, b []byte) error {
	t.writes = append(t.writes, b)
	if t.onWrite != nil {
		t.onWrite(b)
	}
	return nil
}

func (t *scriptedTransport) Close() error { return nil }

func makeInit(t *testing.T, suite Suite) (e2eev1.E2EE_Init, []byte) {
	t.Helper()
	_, pub, err := GenerateEphemeralKeypair(suite)
	if err != nil {
		t.Fatalf("GenerateEphemeralKeypair failed: %v", err)
	}
	var nonceC [32]byte
	for i := range nonceC {
		nonceC[i] = byte(i + 1)
	}
	init := e2eev1.E2EE_Init{
		ChannelId:        "ch_1",
		Role:             e2eev1.Role_client,
		Version:          ProtocolVersion,
		Suite:            e2eev1.Suite(suite),
		ClientEphPubB64u: base64url.Encode(pub),
		NonceCB64u:       base64url.Encode(nonceC[:]),
		ClientFeatures:   0,
	}
	b, err := json.Marshal(init)
	if err != nil {
		t.Fatalf("marshal init failed: %v", err)
	}
	return init, EncodeHandshakeFrame(HandshakeTypeInit, b)
}

func TestClientHandshakeValidations(t *testing.T) {
	_, err := ClientHandshake(context.Background(), &stubTransport{}, HandshakeOptions{
		PSK:       make([]byte, 32),
		ChannelID: "",
	})
	if err == nil || err.Error() != "missing channel_id" {
		t.Fatalf("expected missing channel_id, got %v", err)
	}

	_, err = ClientHandshake(context.Background(), &stubTransport{}, HandshakeOptions{
		PSK:       make([]byte, 32),
		ChannelID: "ch",
		Suite:     Suite(99),
	})
	if err == nil {
		t.Fatalf("expected unsupported suite error")
	}
}

func TestServerHandshakeRejectsRoleAndSuite(t *testing.T) {
	init, frame := makeInit(t, SuiteX25519HKDFAES256GCM)
	init.Role = e2eev1.Role_server
	b, _ := json.Marshal(init)
	transport := &scriptedTransport{reads: [][]byte{EncodeHandshakeFrame(HandshakeTypeInit, b)}}

	_, err := ServerHandshake(context.Background(), transport, nil, HandshakeOptions{
		PSK:               make([]byte, 32),
		ChannelID:         "ch_1",
		Suite:             SuiteX25519HKDFAES256GCM,
		InitExpireAtUnixS: time.Now().Add(time.Minute).Unix(),
	})
	if err == nil || err.Error() != "unexpected role in init" {
		t.Fatalf("expected role error, got %v", err)
	}

	init, frame = makeInit(t, SuiteX25519HKDFAES256GCM)
	init.Suite = e2eev1.Suite(2)
	b, _ = json.Marshal(init)
	transport = &scriptedTransport{reads: [][]byte{EncodeHandshakeFrame(HandshakeTypeInit, b)}}
	_, err = ServerHandshake(context.Background(), transport, nil, HandshakeOptions{
		PSK:               make([]byte, 32),
		ChannelID:         "ch_1",
		Suite:             SuiteX25519HKDFAES256GCM,
		InitExpireAtUnixS: time.Now().Add(time.Minute).Unix(),
	})
	if err == nil || !errors.Is(err, ErrUnsupportedSuite) {
		t.Fatalf("expected unsupported suite, got %v", err)
	}
	_ = frame
}

func TestServerHandshakeAuthTagMismatch(t *testing.T) {
	psk := make([]byte, 32)
	_, frame := makeInit(t, SuiteX25519HKDFAES256GCM)
	transport := &scriptedTransport{reads: [][]byte{frame}}

	transport.onWrite = func(respFrame []byte) {
		_, payload, err := DecodeHandshakeFrame(respFrame, 8*1024)
		if err != nil {
			return
		}
		var resp e2eev1.E2EE_Resp
		_ = json.Unmarshal(payload, &resp)
		ack := e2eev1.E2EE_Ack{
			HandshakeId:    resp.HandshakeId,
			TimestampUnixS: uint64(time.Now().Unix()),
			AuthTagB64u:    base64url.Encode(make([]byte, 32)),
		}
		b, _ := json.Marshal(ack)
		transport.reads = append(transport.reads, EncodeHandshakeFrame(HandshakeTypeAck, b))
	}

	_, err := ServerHandshake(context.Background(), transport, nil, HandshakeOptions{
		PSK:               psk,
		ChannelID:         "ch_1",
		Suite:             SuiteX25519HKDFAES256GCM,
		InitExpireAtUnixS: time.Now().Add(time.Minute).Unix(),
		ClockSkew:         30 * time.Second,
	})
	if err == nil || err.Error() != "auth tag mismatch" {
		t.Fatalf("expected auth tag mismatch, got %v", err)
	}
}

func TestServerHandshakeTimestampChecks(t *testing.T) {
	psk := make([]byte, 32)
	init, frame := makeInit(t, SuiteX25519HKDFAES256GCM)
	transport := &scriptedTransport{reads: [][]byte{frame}}

	transport.onWrite = func(respFrame []byte) {
		_, payload, err := DecodeHandshakeFrame(respFrame, 8*1024)
		if err != nil {
			return
		}
		var resp e2eev1.E2EE_Resp
		_ = json.Unmarshal(payload, &resp)
		now := time.Now().Unix()
		ack := e2eev1.E2EE_Ack{
			HandshakeId:    resp.HandshakeId,
			TimestampUnixS: uint64(now + 1000),
			AuthTagB64u:    base64url.Encode(make([]byte, 32)),
		}
		b, _ := json.Marshal(ack)
		transport.reads = append(transport.reads, EncodeHandshakeFrame(HandshakeTypeAck, b))
	}

	_, err := ServerHandshake(context.Background(), transport, nil, HandshakeOptions{
		PSK:               psk,
		ChannelID:         "ch_1",
		Suite:             SuiteX25519HKDFAES256GCM,
		InitExpireAtUnixS: time.Now().Add(time.Minute).Unix(),
		ClockSkew:         10 * time.Second,
	})
	if err == nil || err.Error() != "timestamp out of skew" {
		t.Fatalf("expected timestamp skew, got %v", err)
	}

	transport = &scriptedTransport{reads: [][]byte{frame}}
	transport.onWrite = func(respFrame []byte) {
		_, payload, err := DecodeHandshakeFrame(respFrame, 8*1024)
		if err != nil {
			return
		}
		var resp e2eev1.E2EE_Resp
		_ = json.Unmarshal(payload, &resp)
		now := time.Now().Unix()
		ack := e2eev1.E2EE_Ack{
			HandshakeId:    resp.HandshakeId,
			TimestampUnixS: uint64(now),
			AuthTagB64u:    base64url.Encode(make([]byte, 32)),
		}
		b, _ := json.Marshal(ack)
		transport.reads = append(transport.reads, EncodeHandshakeFrame(HandshakeTypeAck, b))
	}

	_, err = ServerHandshake(context.Background(), transport, nil, HandshakeOptions{
		PSK:               psk,
		ChannelID:         "ch_1",
		Suite:             SuiteX25519HKDFAES256GCM,
		InitExpireAtUnixS: time.Now().Add(-10 * time.Second).Unix(),
		ClockSkew:         5 * time.Second,
	})
	if err == nil || err.Error() != "timestamp after init_exp" {
		t.Fatalf("expected timestamp after init_exp, got %v", err)
	}
	_ = init
}

func TestServerHandshakeCacheMaxEntries(t *testing.T) {
	cache := NewServerHandshakeCache()
	cache.SetLimits(0, 1)
	initA, _ := makeInit(t, SuiteX25519HKDFAES256GCM)
	initB, _ := makeInit(t, SuiteX25519HKDFAES256GCM)

	if _, err := cache.getOrCreate(initA, SuiteX25519HKDFAES256GCM, 0); err != nil {
		t.Fatalf("expected first create to succeed, got %v", err)
	}
	if _, err := cache.getOrCreate(initB, SuiteX25519HKDFAES256GCM, 0); err == nil {
		t.Fatalf("expected too many pending handshakes error")
	}
}
