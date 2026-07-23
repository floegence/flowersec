package e2ee

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	e2eev1 "github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/e2ee/v1"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/base64url"
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

type handshakeResponseBarrier struct {
	mu        sync.Mutex
	count     int
	responses chan struct{}
}

func newHandshakeResponseBarrier() *handshakeResponseBarrier {
	return &handshakeResponseBarrier{responses: make(chan struct{})}
}

func (b *handshakeResponseBarrier) arrive() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.count++
	if b.count == 2 {
		close(b.responses)
	}
}

type concurrentAckTransport struct {
	init      e2eev1.E2EE_Init
	initFrame []byte
	psk       []byte
	barrier   *handshakeResponseBarrier
	readCount int
	ackFrame  []byte
}

func (t *concurrentAckTransport) ReadBinary(ctx context.Context) ([]byte, error) {
	t.readCount++
	if t.readCount == 1 {
		return t.initFrame, nil
	}
	if t.readCount != 2 {
		return nil, errors.New("unexpected read")
	}
	select {
	case <-t.barrier.responses:
		return t.ackFrame, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *concurrentAckTransport) WriteBinary(_ context.Context, frame []byte) error {
	ht, payload, err := DecodeHandshakeFrame(frame, 8*1024)
	if err != nil || ht != HandshakeTypeResp {
		return nil
	}
	var resp e2eev1.E2EE_Resp
	if err := json.Unmarshal(payload, &resp); err != nil {
		return err
	}
	clientPub, err := base64url.Decode(t.init.ClientEphPubB64u)
	if err != nil {
		return err
	}
	nonceCBytes, err := base64url.Decode(t.init.NonceCB64u)
	if err != nil {
		return err
	}
	serverPub, err := base64url.Decode(resp.ServerEphPubB64u)
	if err != nil {
		return err
	}
	nonceSBytes, err := base64url.Decode(resp.NonceSB64u)
	if err != nil {
		return err
	}
	var nonceC, nonceS [32]byte
	copy(nonceC[:], nonceCBytes)
	copy(nonceS[:], nonceSBytes)
	th, err := TranscriptHash(TranscriptInputs{
		Version:        ProtocolVersion,
		Suite:          uint16(t.init.Suite),
		Role:           uint8(e2eev1.Role_client),
		ClientFeatures: t.init.ClientFeatures,
		ServerFeatures: resp.ServerFeatures,
		ChannelID:      t.init.ChannelId,
		NonceC:         nonceC,
		NonceS:         nonceS,
		ClientEphPub:   clientPub,
		ServerEphPub:   serverPub,
	})
	if err != nil {
		return err
	}
	timestamp := uint64(time.Now().Unix())
	tag, err := ComputeAuthTag(t.psk, th, timestamp)
	if err != nil {
		return err
	}
	ackJSON, err := json.Marshal(e2eev1.E2EE_Ack{
		HandshakeId:    resp.HandshakeId,
		TimestampUnixS: timestamp,
		AuthTagB64u:    base64url.Encode(tag[:]),
	})
	if err != nil {
		return err
	}
	t.ackFrame = EncodeHandshakeFrame(HandshakeTypeAck, ackJSON)
	t.barrier.arrive()
	return nil
}

func (*concurrentAckTransport) Close() error { return nil }

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
	_, err := ClientHandshake(context.Background(), &stubTransport{}, ClientHandshakeOptions{
		PSK:       make([]byte, 32),
		ChannelID: "",
	})
	if err == nil || err.Error() != "missing channel_id" {
		t.Fatalf("expected missing channel_id, got %v", err)
	}

	_, err = ClientHandshake(context.Background(), &stubTransport{}, ClientHandshakeOptions{
		PSK:       make([]byte, 32),
		ChannelID: "ch",
		Suite:     Suite(99),
	})
	if err == nil {
		t.Fatalf("expected unsupported suite error")
	}
}

func TestHandshakeRejectsNegativeBufferLimitsBeforeTransportIO(t *testing.T) {
	tests := []struct {
		name   string
		client ClientHandshakeOptions
		server ServerHandshakeOptions
	}{
		{
			name: "client inbound",
			client: ClientHandshakeOptions{
				PSK: make([]byte, 32), ChannelID: "ch", MaxBufferedBytes: -1,
			},
		},
		{
			name: "client outbound",
			client: ClientHandshakeOptions{
				PSK: make([]byte, 32), ChannelID: "ch", MaxOutboundBufferedBytes: -1,
			},
		},
		{
			name: "server inbound",
			server: ServerHandshakeOptions{
				PSK: make([]byte, 32), ChannelID: "ch", InitExpireAtUnixS: time.Now().Add(time.Minute).Unix(), MaxBufferedBytes: -1,
			},
		},
		{
			name: "server outbound",
			server: ServerHandshakeOptions{
				PSK: make([]byte, 32), ChannelID: "ch", InitExpireAtUnixS: time.Now().Add(time.Minute).Unix(), MaxOutboundBufferedBytes: -1,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := &stubTransport{}
			var err error
			if test.client.PSK != nil {
				_, err = ClientHandshake(context.Background(), transport, test.client)
			} else {
				_, err = ServerHandshake(context.Background(), transport, nil, test.server)
			}
			if err == nil {
				t.Fatal("expected invalid buffer limit")
			}
			if transport.readCalled || transport.writeCalled {
				t.Fatalf("unexpected transport usage: read=%v write=%v", transport.readCalled, transport.writeCalled)
			}
		})
	}
}

func TestClientHandshakeRequiresServerFinishedPing(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	var initMsg e2eev1.E2EE_Init
	var keys SessionKeys
	var maxRecordBytes = 1 << 20

	transport := &scriptedTransport{}
	transport.onWrite = func(frame []byte) {
		ht, payload, err := DecodeHandshakeFrame(frame, 8*1024)
		if err != nil {
			return
		}
		switch ht {
		case HandshakeTypeInit:
			// Build a valid server response and remember the derived S2C keys.
			if err := json.Unmarshal(payload, &initMsg); err != nil {
				return
			}
			clientPubBytes, err := base64url.Decode(initMsg.ClientEphPubB64u)
			if err != nil {
				return
			}
			nonceCBytes, err := base64url.Decode(initMsg.NonceCB64u)
			if err != nil || len(nonceCBytes) != 32 {
				return
			}
			var nonceC [32]byte
			copy(nonceC[:], nonceCBytes)

			suite := Suite(initMsg.Suite)
			priv, pub, err := GenerateEphemeralKeypair(suite)
			if err != nil {
				return
			}
			var nonceS [32]byte
			for i := range nonceS {
				nonceS[i] = byte(i + 10)
			}
			resp := e2eev1.E2EE_Resp{
				HandshakeId:      "hs_1",
				ServerEphPubB64u: base64url.Encode(pub),
				NonceSB64u:       base64url.Encode(nonceS[:]),
				ServerFeatures:   0,
			}
			respJSON, _ := json.Marshal(resp)
			transport.reads = append(transport.reads, EncodeHandshakeFrame(HandshakeTypeResp, respJSON))

			th, err := TranscriptHash(TranscriptInputs{
				Version:        ProtocolVersion,
				Suite:          uint16(suite),
				Role:           uint8(e2eev1.Role_client),
				ClientFeatures: initMsg.ClientFeatures,
				ServerFeatures: 0,
				ChannelID:      initMsg.ChannelId,
				NonceC:         nonceC,
				NonceS:         nonceS,
				ClientEphPub:   clientPubBytes,
				ServerEphPub:   pub,
			})
			if err != nil {
				return
			}
			peerPub, err := ParsePublicKey(suite, clientPubBytes)
			if err != nil {
				return
			}
			shared, err := priv.ECDH(peerPub)
			if err != nil {
				return
			}
			keys, err = DeriveSessionKeys(psk, suite, shared, th)
			if err != nil {
				return
			}
		case HandshakeTypeAck:
			// Instead of the required server-finished ping, send an app record (seq=1).
			appFrame, err := EncryptRecord(keys.S2CKey, keys.S2CNoncePre, RecordFlagApp, 1, []byte("x"), maxRecordBytes)
			if err != nil {
				return
			}
			transport.reads = append(transport.reads, appFrame)
		}
	}

	_, err := ClientHandshake(context.Background(), transport, ClientHandshakeOptions{
		PSK:                 psk,
		Suite:               SuiteX25519HKDFAES256GCM,
		ChannelID:           "ch_1",
		ClientFeatures:      0,
		MaxHandshakePayload: 8 * 1024,
		MaxRecordBytes:      maxRecordBytes,
	})
	if err == nil || err.Error() != "expected server-finished ping" {
		t.Fatalf("expected server-finished ping error, got %v", err)
	}
}

func TestServerHandshakeRejectsRoleAndSuite(t *testing.T) {
	init, frame := makeInit(t, SuiteX25519HKDFAES256GCM)
	init.Role = e2eev1.Role_server
	b, _ := json.Marshal(init)
	transport := &scriptedTransport{reads: [][]byte{EncodeHandshakeFrame(HandshakeTypeInit, b)}}

	_, err := ServerHandshake(context.Background(), transport, nil, ServerHandshakeOptions{
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
	_, err = ServerHandshake(context.Background(), transport, nil, ServerHandshakeOptions{
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
	init, frame := makeInit(t, SuiteX25519HKDFAES256GCM)
	transport := &scriptedTransport{reads: [][]byte{frame}}
	cache := NewServerHandshakeCache()
	var firstHandshakeID string

	transport.onWrite = func(respFrame []byte) {
		_, payload, err := DecodeHandshakeFrame(respFrame, 8*1024)
		if err != nil {
			return
		}
		var resp e2eev1.E2EE_Resp
		_ = json.Unmarshal(payload, &resp)
		firstHandshakeID = resp.HandshakeId
		ack := e2eev1.E2EE_Ack{
			HandshakeId:    resp.HandshakeId,
			TimestampUnixS: uint64(time.Now().Unix()),
			AuthTagB64u:    base64url.Encode(make([]byte, 32)),
		}
		b, _ := json.Marshal(ack)
		transport.reads = append(transport.reads, EncodeHandshakeFrame(HandshakeTypeAck, b))
	}

	_, err := ServerHandshake(context.Background(), transport, cache, ServerHandshakeOptions{
		PSK:               psk,
		ChannelID:         "ch_1",
		Suite:             SuiteX25519HKDFAES256GCM,
		InitExpireAtUnixS: time.Now().Add(time.Minute).Unix(),
		ClockSkew:         30 * time.Second,
	})
	if err == nil || !errors.Is(err, ErrAuthTagMismatch) {
		t.Fatalf("expected auth tag mismatch, got %v", err)
	}
	next, err := cache.getOrCreate(init, SuiteX25519HKDFAES256GCM, 0)
	if err != nil {
		t.Fatalf("create replacement handshake state: %v", err)
	}
	if next.HandshakeID == firstHandshakeID {
		t.Fatal("failed ACK left the consumed handshake state in the cache")
	}
}

func TestServerHandshakeConsumesSharedStateOnce(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	init, initFrame := makeInit(t, SuiteX25519HKDFAES256GCM)
	cache := NewServerHandshakeCache()
	barrier := newHandshakeResponseBarrier()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	results := make(chan error, 2)
	for range 2 {
		transport := &concurrentAckTransport{
			init:      init,
			initFrame: initFrame,
			psk:       psk,
			barrier:   barrier,
		}
		go func() {
			secure, err := ServerHandshake(ctx, transport, cache, ServerHandshakeOptions{
				PSK:               psk,
				ChannelID:         init.ChannelId,
				Suite:             SuiteX25519HKDFAES256GCM,
				InitExpireAtUnixS: time.Now().Add(time.Minute).Unix(),
				ClockSkew:         30 * time.Second,
			})
			if secure != nil {
				_ = secure.Close()
			}
			results <- err
		}()
	}

	succeeded := 0
	failedUnavailable := 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, errHandshakeStateUnavailable):
			failedUnavailable++
		default:
			t.Fatalf("unexpected handshake result: %v", err)
		}
	}
	if succeeded != 1 || failedUnavailable != 1 {
		t.Fatalf("handshake results: succeeded=%d unavailable=%d", succeeded, failedUnavailable)
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

	_, err := ServerHandshake(context.Background(), transport, nil, ServerHandshakeOptions{
		PSK:               psk,
		ChannelID:         "ch_1",
		Suite:             SuiteX25519HKDFAES256GCM,
		InitExpireAtUnixS: time.Now().Add(time.Minute).Unix(),
		ClockSkew:         10 * time.Second,
	})
	if err == nil || !errors.Is(err, ErrTimestampOutOfSkew) {
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

	_, err = ServerHandshake(context.Background(), transport, nil, ServerHandshakeOptions{
		PSK:               psk,
		ChannelID:         "ch_1",
		Suite:             SuiteX25519HKDFAES256GCM,
		InitExpireAtUnixS: time.Now().Add(-10 * time.Second).Unix(),
		ClockSkew:         5 * time.Second,
	})
	if err == nil || !errors.Is(err, ErrTimestampAfterInitExp) {
		t.Fatalf("expected timestamp after init_exp, got %v", err)
	}
	_ = init
}

func TestServerHandshakeZeroClockSkewIsStrict(t *testing.T) {
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
			TimestampUnixS: uint64(time.Now().Add(time.Second).Unix()),
			AuthTagB64u:    base64url.Encode(make([]byte, 32)),
		}
		b, _ := json.Marshal(ack)
		transport.reads = append(transport.reads, EncodeHandshakeFrame(HandshakeTypeAck, b))
	}

	_, err := ServerHandshake(context.Background(), transport, nil, ServerHandshakeOptions{
		PSK:               psk,
		ChannelID:         "ch_1",
		Suite:             SuiteX25519HKDFAES256GCM,
		InitExpireAtUnixS: time.Now().Add(time.Minute).Unix(),
		ClockSkew:         0,
	})
	if err == nil || !errors.Is(err, ErrTimestampOutOfSkew) {
		t.Fatalf("expected timestamp skew, got %v", err)
	}
}

func TestServerHandshakeRejectsNegativeClockSkew(t *testing.T) {
	transport := &stubTransport{}
	_, err := ServerHandshake(context.Background(), transport, nil, ServerHandshakeOptions{
		PSK:               make([]byte, 32),
		ChannelID:         "ch_1",
		Suite:             SuiteX25519HKDFAES256GCM,
		InitExpireAtUnixS: time.Now().Add(time.Minute).Unix(),
		ClockSkew:         -time.Second,
	})
	if err == nil || !errors.Is(err, ErrInvalidClockSkew) {
		t.Fatalf("expected invalid clock skew, got %v", err)
	}
	if transport.readCalled || transport.writeCalled {
		t.Fatalf("unexpected transport usage: read=%v write=%v", transport.readCalled, transport.writeCalled)
	}
}

func TestServerHandshakeCacheMaxEntries(t *testing.T) {
	cache := NewServerHandshakeCache()
	if err := cache.SetLimits(0, 1); err != nil {
		t.Fatalf("SetLimits failed: %v", err)
	}
	initA, _ := makeInit(t, SuiteX25519HKDFAES256GCM)
	initB, _ := makeInit(t, SuiteX25519HKDFAES256GCM)

	if _, err := cache.getOrCreate(initA, SuiteX25519HKDFAES256GCM, 0); err != nil {
		t.Fatalf("expected first create to succeed, got %v", err)
	}
	if _, err := cache.getOrCreate(initB, SuiteX25519HKDFAES256GCM, 0); err == nil {
		t.Fatalf("expected too many pending handshakes error")
	}
}

func TestServerHandshakeCacheSetLimitsRejectsNegativeValues(t *testing.T) {
	cache := NewServerHandshakeCache()
	if err := cache.SetLimits(-1*time.Second, 0); err == nil {
		t.Fatalf("expected error for negative ttl")
	}
	if err := cache.SetLimits(0, -1); err == nil {
		t.Fatalf("expected error for negative max entries")
	}
}

func TestServerHandshakeRoundsSkewToWholeSeconds(t *testing.T) {
	psk := make([]byte, 32)
	_, frame := makeInit(t, SuiteX25519HKDFAES256GCM)

	tsUnix := time.Now().Unix()
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
			TimestampUnixS: uint64(tsUnix),
			AuthTagB64u:    base64url.Encode(make([]byte, 32)),
		}
		b, _ := json.Marshal(ack)
		transport.reads = append(transport.reads, EncodeHandshakeFrame(HandshakeTypeAck, b))
	}

	_, err := ServerHandshake(context.Background(), transport, nil, ServerHandshakeOptions{
		PSK:               psk,
		ChannelID:         "ch_1",
		Suite:             SuiteX25519HKDFAES256GCM,
		InitExpireAtUnixS: tsUnix - 2,
		ClockSkew:         1500 * time.Millisecond,
	})
	if err == nil || !errors.Is(err, ErrAuthTagMismatch) {
		t.Fatalf("expected auth tag mismatch, got %v", err)
	}
}
