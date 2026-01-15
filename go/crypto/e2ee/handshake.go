package e2ee

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	e2eev1 "github.com/flowersec/flowersec/gen/flowersec/e2ee/v1"
	"github.com/flowersec/flowersec/internal/base64url"
)

type HandshakeOptions struct {
	PSK               []byte
	Suite             Suite
	ChannelID         string
	InitExpireAtUnixS int64
	ClockSkew         time.Duration

	ClientFeatureBits uint32
	ServerFeatureBits uint32

	MaxHandshakePayload int
	MaxRecordBytes      int
}

type ServerHandshakeCache struct {
	mu sync.Mutex
	m  map[string]*serverHandshakeState

	ttl        time.Duration
	maxEntries int
}

type serverHandshakeState struct {
	Key            string
	HandshakeID    string
	Suite          Suite
	ClientInit     e2eev1.E2EE_Init
	ServerPriv     *ecdh.PrivateKey
	ServerPubBytes []byte
	NonceS         [32]byte
	ServerFeatures uint32
	CreatedAt      time.Time
}

func NewServerHandshakeCache() *ServerHandshakeCache {
	return &ServerHandshakeCache{
		m:          make(map[string]*serverHandshakeState),
		ttl:        60 * time.Second,
		maxEntries: 4096,
	}
}

var ErrTooManyPendingHandshakes = errors.New("too many pending handshakes")

// SetLimits configures cache bounds. A zero value disables the corresponding limit.
func (c *ServerHandshakeCache) SetLimits(ttl time.Duration, maxEntries int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ttl = ttl
	c.maxEntries = maxEntries
}

func ClientHandshake(ctx context.Context, t BinaryTransport, opts HandshakeOptions) (*SecureConn, error) {
	if len(opts.PSK) != 32 {
		return nil, ErrInvalidPSK
	}
	if opts.ChannelID == "" {
		return nil, errors.New("missing channel_id")
	}
	if opts.Suite == 0 {
		opts.Suite = SuiteX25519HKDFAES256GCM
	}

	priv, pub, err := GenerateEphemeralKeypair(opts.Suite)
	if err != nil {
		return nil, err
	}
	var nonceC [32]byte
	if _, err := rand.Read(nonceC[:]); err != nil {
		return nil, err
	}

	initMsg := e2eev1.E2EE_Init{
		ChannelId:        opts.ChannelID,
		Role:             e2eev1.Role_client,
		Version:          ProtocolVersion,
		Suite:            e2eev1.Suite(opts.Suite),
		ClientEphPubB64u: base64url.Encode(pub),
		NonceCB64u:       base64url.Encode(nonceC[:]),
		ClientFeatures:   opts.ClientFeatureBits,
	}
	initJSON, err := json.Marshal(initMsg)
	if err != nil {
		return nil, err
	}
	if err := t.WriteBinary(ctx, EncodeHandshakeFrame(HandshakeTypeInit, initJSON)); err != nil {
		return nil, err
	}

	respFrame, err := t.ReadBinary(ctx)
	if err != nil {
		return nil, err
	}
	ht, respJSON, err := DecodeHandshakeFrame(respFrame, opts.MaxHandshakePayload)
	if err != nil {
		return nil, err
	}
	if ht != HandshakeTypeResp {
		return nil, fmt.Errorf("unexpected handshake type: %d", ht)
	}
	var resp e2eev1.E2EE_Resp
	if err := json.Unmarshal(respJSON, &resp); err != nil {
		return nil, err
	}
	if resp.HandshakeId == "" {
		return nil, errors.New("missing handshake_id")
	}

	serverPubBytes, err := base64url.Decode(resp.ServerEphPubB64u)
	if err != nil {
		return nil, err
	}
	nonceSBytes, err := base64url.Decode(resp.NonceSB64u)
	if err != nil {
		return nil, err
	}
	if len(nonceSBytes) != 32 {
		return nil, errors.New("invalid nonce_s length")
	}
	var nonceS [32]byte
	copy(nonceS[:], nonceSBytes)

	peerPub, err := ParsePublicKey(opts.Suite, serverPubBytes)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, err
	}

	th, err := TranscriptHash(TranscriptInputs{
		Version:        ProtocolVersion,
		Suite:          uint16(opts.Suite),
		Role:           uint8(e2eev1.Role_client),
		ClientFeatures: initMsg.ClientFeatures,
		ServerFeatures: resp.ServerFeatures,
		ChannelID:      opts.ChannelID,
		NonceC:         nonceC,
		NonceS:         nonceS,
		ClientEphPub:   pub,
		ServerEphPub:   serverPubBytes,
	})
	if err != nil {
		return nil, err
	}

	keys, err := DeriveSessionKeys(opts.PSK, opts.Suite, sharedSecret, th)
	if err != nil {
		return nil, err
	}

	ts := uint64(time.Now().Unix())
	authTag, err := ComputeAuthTag(opts.PSK, th, ts)
	if err != nil {
		return nil, err
	}
	ack := e2eev1.E2EE_Ack{
		HandshakeId:    resp.HandshakeId,
		TimestampUnixS: ts,
		AuthTagB64u:    base64url.Encode(authTag[:]),
	}
	ackJSON, err := json.Marshal(ack)
	if err != nil {
		return nil, err
	}
	if err := t.WriteBinary(ctx, EncodeHandshakeFrame(HandshakeTypeAck, ackJSON)); err != nil {
		return nil, err
	}

	return NewSecureConn(t, RecordKeyState{
		SendKey:      keys.C2SKey,
		RecvKey:      keys.S2CKey,
		SendNoncePre: keys.C2SNoncePre,
		RecvNoncePre: keys.S2CNoncePre,
		RekeyBase:    keys.RekeyBase,
		Transcript:   th,
		SendDir:      DirC2S,
		RecvDir:      DirS2C,
		SendSeq:      1,
		RecvSeq:      1,
	}, opts.MaxRecordBytes), nil
}

func ServerHandshake(ctx context.Context, t BinaryTransport, cache *ServerHandshakeCache, opts HandshakeOptions) (*SecureConn, error) {
	if len(opts.PSK) != 32 {
		return nil, ErrInvalidPSK
	}
	if cache == nil {
		cache = NewServerHandshakeCache()
	}
	if opts.Suite == 0 {
		opts.Suite = SuiteX25519HKDFAES256GCM
	}

	var initMsg e2eev1.E2EE_Init
	var st *serverHandshakeState

	for {
		frame, err := t.ReadBinary(ctx)
		if err != nil {
			return nil, err
		}
		ht, payload, err := DecodeHandshakeFrame(frame, opts.MaxHandshakePayload)
		if err != nil {
			return nil, err
		}
		if ht != HandshakeTypeInit {
			return nil, fmt.Errorf("unexpected handshake type: %d", ht)
		}
		if err := json.Unmarshal(payload, &initMsg); err != nil {
			return nil, err
		}
		if initMsg.Version != ProtocolVersion {
			return nil, ErrInvalidVersion
		}
		if initMsg.Role != e2eev1.Role_client {
			return nil, errors.New("unexpected role in init")
		}
		if initMsg.ChannelId == "" {
			return nil, errors.New("missing channel_id")
		}
		if opts.ChannelID != "" && subtle.ConstantTimeCompare([]byte(initMsg.ChannelId), []byte(opts.ChannelID)) != 1 {
			return nil, errors.New("channel_id mismatch")
		}

		suite := Suite(initMsg.Suite)
		if suite == 0 {
			suite = opts.Suite
		}
		if opts.Suite != 0 && suite != opts.Suite {
			return nil, ErrUnsupportedSuite
		}

		st, err = cache.getOrCreate(initMsg, suite, opts.ServerFeatureBits)
		if err != nil {
			return nil, err
		}

		resp := e2eev1.E2EE_Resp{
			HandshakeId:      st.HandshakeID,
			ServerEphPubB64u: base64url.Encode(st.ServerPubBytes),
			NonceSB64u:       base64url.Encode(st.NonceS[:]),
			ServerFeatures:   st.ServerFeatures,
		}
		respJSON, err := json.Marshal(resp)
		if err != nil {
			return nil, err
		}
		if err := t.WriteBinary(ctx, EncodeHandshakeFrame(HandshakeTypeResp, respJSON)); err != nil {
			return nil, err
		}
		break
	}

	var ack e2eev1.E2EE_Ack
	for {
		frame, err := t.ReadBinary(ctx)
		if err != nil {
			return nil, err
		}
		ht, payload, err := DecodeHandshakeFrame(frame, opts.MaxHandshakePayload)
		if err != nil {
			return nil, err
		}
		if ht == HandshakeTypeInit {
			// Client retry: respond again using the cached state.
			var retry e2eev1.E2EE_Init
			if err := json.Unmarshal(payload, &retry); err != nil {
				return nil, err
			}
			key, err := fingerprintInit(retry)
			if err != nil {
				return nil, err
			}
			if key != st.Key {
				return nil, errors.New("unexpected init retry parameters")
			}
			resp := e2eev1.E2EE_Resp{
				HandshakeId:      st.HandshakeID,
				ServerEphPubB64u: base64url.Encode(st.ServerPubBytes),
				NonceSB64u:       base64url.Encode(st.NonceS[:]),
				ServerFeatures:   st.ServerFeatures,
			}
			respJSON, err := json.Marshal(resp)
			if err != nil {
				return nil, err
			}
			if err := t.WriteBinary(ctx, EncodeHandshakeFrame(HandshakeTypeResp, respJSON)); err != nil {
				return nil, err
			}
			continue
		}
		if ht != HandshakeTypeAck {
			return nil, fmt.Errorf("unexpected handshake type: %d", ht)
		}
		if err := json.Unmarshal(payload, &ack); err != nil {
			return nil, err
		}
		break
	}

	if ack.HandshakeId != st.HandshakeID {
		return nil, errors.New("handshake_id mismatch")
	}

	now := time.Now()
	skew := opts.ClockSkew
	if skew < 0 {
		skew = 0
	}
	ts := time.Unix(int64(ack.TimestampUnixS), 0)
	if ts.Before(now.Add(-skew)) || ts.After(now.Add(skew)) {
		return nil, errors.New("timestamp out of skew")
	}
	if opts.InitExpireAtUnixS != 0 && int64(ack.TimestampUnixS) > opts.InitExpireAtUnixS+int64(skew.Seconds()) {
		return nil, errors.New("timestamp after init_exp")
	}

	authTagBytes, err := base64url.Decode(ack.AuthTagB64u)
	if err != nil {
		return nil, err
	}
	if len(authTagBytes) != 32 {
		return nil, errors.New("invalid auth tag length")
	}

	clientPubBytes, err := base64url.Decode(initMsg.ClientEphPubB64u)
	if err != nil {
		return nil, err
	}
	nonceCBytes, err := base64url.Decode(initMsg.NonceCB64u)
	if err != nil {
		return nil, err
	}
	if len(nonceCBytes) != 32 {
		return nil, errors.New("invalid nonce_c length")
	}
	var nonceC [32]byte
	copy(nonceC[:], nonceCBytes)

	th, err := TranscriptHash(TranscriptInputs{
		Version:        ProtocolVersion,
		Suite:          uint16(st.Suite),
		Role:           uint8(e2eev1.Role_client),
		ClientFeatures: initMsg.ClientFeatures,
		ServerFeatures: st.ServerFeatures,
		ChannelID:      initMsg.ChannelId,
		NonceC:         nonceC,
		NonceS:         st.NonceS,
		ClientEphPub:   clientPubBytes,
		ServerEphPub:   st.ServerPubBytes,
	})
	if err != nil {
		return nil, err
	}
	expTag, err := ComputeAuthTag(opts.PSK, th, ack.TimestampUnixS)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(expTag[:], authTagBytes) != 1 {
		return nil, errors.New("auth tag mismatch")
	}

	peerPub, err := ParsePublicKey(st.Suite, clientPubBytes)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := st.ServerPriv.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	keys, err := DeriveSessionKeys(opts.PSK, st.Suite, sharedSecret, th)
	if err != nil {
		return nil, err
	}

	cache.delete(st.Key)

	return NewSecureConn(t, RecordKeyState{
		SendKey:      keys.S2CKey,
		RecvKey:      keys.C2SKey,
		SendNoncePre: keys.S2CNoncePre,
		RecvNoncePre: keys.C2SNoncePre,
		RekeyBase:    keys.RekeyBase,
		Transcript:   th,
		SendDir:      DirS2C,
		RecvDir:      DirC2S,
		SendSeq:      1,
		RecvSeq:      1,
	}, opts.MaxRecordBytes), nil
}

func (c *ServerHandshakeCache) getOrCreate(initMsg e2eev1.E2EE_Init, suite Suite, serverFeatures uint32) (*serverHandshakeState, error) {
	key, err := fingerprintInit(initMsg)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(now)
	if st, ok := c.m[key]; ok {
		return st, nil
	}
	if c.maxEntries > 0 && len(c.m) >= c.maxEntries {
		return nil, ErrTooManyPendingHandshakes
	}
	priv, pub, err := GenerateEphemeralKeypair(suite)
	if err != nil {
		return nil, err
	}
	var nonceS [32]byte
	if _, err := rand.Read(nonceS[:]); err != nil {
		return nil, err
	}
	handshakeID, err := randomB64u(24)
	if err != nil {
		return nil, err
	}
	st := &serverHandshakeState{
		Key:            key,
		HandshakeID:    handshakeID,
		Suite:          suite,
		ClientInit:     initMsg,
		ServerPriv:     priv,
		ServerPubBytes: pub,
		NonceS:         nonceS,
		ServerFeatures: serverFeatures,
		CreatedAt:      now,
	}
	c.m[key] = st
	return st, nil
}

func (c *ServerHandshakeCache) delete(key string) {
	c.mu.Lock()
	delete(c.m, key)
	c.mu.Unlock()
}

func (c *ServerHandshakeCache) cleanupLocked(now time.Time) {
	if c.ttl <= 0 {
		return
	}
	for k, st := range c.m {
		if now.Sub(st.CreatedAt) > c.ttl {
			delete(c.m, k)
		}
	}
}

func fingerprintInit(initMsg e2eev1.E2EE_Init) (string, error) {
	b, err := json.Marshal(initMsg)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return base64url.Encode(sum[:]), nil
}

func randomB64u(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64url.Encode(b), nil
}
