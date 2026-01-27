package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/controlplane/token"
	tunnelv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
	"github.com/gorilla/websocket"
)

func signTunnelToken(t *testing.T, priv ed25519.PrivateKey, raw token.Payload) string {
	t.Helper()
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("Marshal(token payload) failed: %v", err)
	}
	payloadB64u := base64.RawURLEncoding.EncodeToString(b)
	signed := token.Prefix + "." + payloadB64u
	sig := ed25519.Sign(priv, []byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestAttachWithEmptyTokenIDIsInvalidToken(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	keysFile := writeTempKeyset(t, issuer.TunnelKeysetFile{
		Keys: []issuer.TunnelKey{{KID: "kid", PubKeyB64: base64url.Encode(pub)}},
	})

	cfg := DefaultConfig()
	cfg.TunnelAudience = "aud"
	cfg.TunnelIssuer = "iss"
	cfg.IssuerKeysFile = keysFile
	cfg.AllowedOrigins = []string{"https://ok"}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	t.Cleanup(s.Close)

	mux := http.NewServeMux()
	s.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + cfg.Path
	c, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{"https://ok"}})
	if err != nil {
		t.Fatalf("Dial() failed: %v", err)
	}
	defer c.Close()

	now := time.Now()
	raw := token.Payload{
		Kid:                "kid",
		Aud:                cfg.TunnelAudience,
		Iss:                cfg.TunnelIssuer,
		ChannelID:          "ch_1",
		Role:               uint8(tunnelv1.Role_client),
		TokenID:            "",
		InitExp:            now.Add(2 * time.Minute).Unix(),
		IdleTimeoutSeconds: 60,
		Iat:                now.Add(-10 * time.Second).Unix(),
		Exp:                now.Add(30 * time.Second).Unix(),
	}
	tokenStr := signTunnelToken(t, priv, raw)

	attach := tunnelv1.Attach{
		V:                  1,
		ChannelId:          raw.ChannelID,
		Role:               tunnelv1.Role_client,
		Token:              tokenStr,
		EndpointInstanceId: base64url.Encode(make([]byte, 16)),
	}
	attachJSON, err := json.Marshal(attach)
	if err != nil {
		t.Fatalf("Marshal(attach) failed: %v", err)
	}
	if err := c.WriteMessage(websocket.TextMessage, attachJSON); err != nil {
		t.Fatalf("WriteMessage() failed: %v", err)
	}

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = c.ReadMessage()
	if err == nil {
		t.Fatal("expected close error")
	}
	var ce *websocket.CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("expected CloseError, got %T: %v", err, err)
	}
	if ce.Code != websocket.ClosePolicyViolation {
		t.Fatalf("expected close code %d, got %d", websocket.ClosePolicyViolation, ce.Code)
	}
	if ce.Text != "invalid_token" {
		t.Fatalf("expected close reason invalid_token, got %q", ce.Text)
	}
}

func TestAttachReadTimeoutIsTimeoutReason(t *testing.T) {
	keysFile := writeTempKeyset(t, issuer.TunnelKeysetFile{
		Keys: []issuer.TunnelKey{{KID: "kid", PubKeyB64: base64url.Encode(make([]byte, ed25519.PublicKeySize))}},
	})

	cfg := DefaultConfig()
	cfg.TunnelAudience = "aud"
	cfg.TunnelIssuer = "iss"
	cfg.IssuerKeysFile = keysFile
	cfg.AllowedOrigins = []string{"https://ok"}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	t.Cleanup(s.Close)

	mux := http.NewServeMux()
	s.Register(mux)

	ts := httptest.NewUnstartedServer(mux)
	var baseCancel context.CancelFunc
	ts.Config.BaseContext = func(_ net.Listener) context.Context {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		baseCancel = cancel
		return ctx
	}
	ts.Start()
	t.Cleanup(ts.Close)
	t.Cleanup(func() {
		if baseCancel != nil {
			baseCancel()
		}
	})

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + cfg.Path
	c, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{"https://ok"}})
	if err != nil {
		t.Fatalf("Dial() failed: %v", err)
	}
	defer c.Close()

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = c.ReadMessage()
	if err == nil {
		t.Fatal("expected close error")
	}
	var ce *websocket.CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("expected CloseError, got %T: %v", err, err)
	}
	if ce.Code != websocket.ClosePolicyViolation {
		t.Fatalf("expected close code %d, got %d", websocket.ClosePolicyViolation, ce.Code)
	}
	if ce.Text != "timeout" {
		t.Fatalf("expected close reason timeout, got %q", ce.Text)
	}
}

func TestAttachWhenMaxChannelsExceededIsTooManyConnections(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	keysFile := writeTempKeyset(t, issuer.TunnelKeysetFile{
		Keys: []issuer.TunnelKey{{KID: "kid", PubKeyB64: base64url.Encode(pub)}},
	})

	cfg := DefaultConfig()
	cfg.TunnelAudience = "aud"
	cfg.TunnelIssuer = "iss"
	cfg.IssuerKeysFile = keysFile
	cfg.AllowedOrigins = []string{"https://ok"}
	cfg.MaxChannels = 1

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	t.Cleanup(s.Close)

	mux := http.NewServeMux()
	s.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + cfg.Path

	c1, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{"https://ok"}})
	if err != nil {
		t.Fatalf("Dial(c1) failed: %v", err)
	}
	t.Cleanup(func() { _ = c1.Close() })

	now := time.Now()
	raw1 := token.Payload{
		Kid:                "kid",
		Aud:                cfg.TunnelAudience,
		Iss:                cfg.TunnelIssuer,
		ChannelID:          "ch_1",
		Role:               uint8(tunnelv1.Role_client),
		TokenID:            "t1",
		InitExp:            now.Add(2 * time.Minute).Unix(),
		IdleTimeoutSeconds: 60,
		Iat:                now.Add(-10 * time.Second).Unix(),
		Exp:                now.Add(30 * time.Second).Unix(),
	}
	attach1 := tunnelv1.Attach{
		V:                  1,
		ChannelId:          raw1.ChannelID,
		Role:               tunnelv1.Role_client,
		Token:              signTunnelToken(t, priv, raw1),
		EndpointInstanceId: base64url.Encode(make([]byte, 16)),
	}
	attach1JSON, err := json.Marshal(attach1)
	if err != nil {
		t.Fatalf("Marshal(attach1) failed: %v", err)
	}
	if err := c1.WriteMessage(websocket.TextMessage, attach1JSON); err != nil {
		t.Fatalf("WriteMessage(attach1) failed: %v", err)
	}

	// Ensure the first channel is registered before attempting the second attach.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if s.Stats().ChannelCount == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected channel count=1, got %d", s.Stats().ChannelCount)
		}
		time.Sleep(5 * time.Millisecond)
	}

	c2, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{"https://ok"}})
	if err != nil {
		t.Fatalf("Dial(c2) failed: %v", err)
	}
	defer c2.Close()

	raw2 := raw1
	raw2.ChannelID = "ch_2"
	raw2.TokenID = "t2"
	attach2 := tunnelv1.Attach{
		V:                  1,
		ChannelId:          raw2.ChannelID,
		Role:               tunnelv1.Role_client,
		Token:              signTunnelToken(t, priv, raw2),
		EndpointInstanceId: base64url.Encode(make([]byte, 16)),
	}
	attach2JSON, err := json.Marshal(attach2)
	if err != nil {
		t.Fatalf("Marshal(attach2) failed: %v", err)
	}
	if err := c2.WriteMessage(websocket.TextMessage, attach2JSON); err != nil {
		t.Fatalf("WriteMessage(attach2) failed: %v", err)
	}

	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = c2.ReadMessage()
	if err == nil {
		t.Fatal("expected close error")
	}
	var ce *websocket.CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("expected CloseError, got %T: %v", err, err)
	}
	if ce.Code != websocket.CloseTryAgainLater {
		t.Fatalf("expected close code %d, got %d", websocket.CloseTryAgainLater, ce.Code)
	}
	if ce.Text != "too_many_connections" {
		t.Fatalf("expected close reason too_many_connections, got %q", ce.Text)
	}
}

func TestAttachWithInitExpMismatchIsInitExpMismatch(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	keysFile := writeTempKeyset(t, issuer.TunnelKeysetFile{
		Keys: []issuer.TunnelKey{{KID: "kid", PubKeyB64: base64url.Encode(pub)}},
	})

	cfg := DefaultConfig()
	cfg.TunnelAudience = "aud"
	cfg.TunnelIssuer = "iss"
	cfg.IssuerKeysFile = keysFile
	cfg.AllowedOrigins = []string{"https://ok"}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	t.Cleanup(s.Close)

	mux := http.NewServeMux()
	s.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + cfg.Path

	c1, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{"https://ok"}})
	if err != nil {
		t.Fatalf("Dial(c1) failed: %v", err)
	}
	t.Cleanup(func() { _ = c1.Close() })

	now := time.Now()
	raw1 := token.Payload{
		Kid:                "kid",
		Aud:                cfg.TunnelAudience,
		Iss:                cfg.TunnelIssuer,
		ChannelID:          "ch_1",
		Role:               uint8(tunnelv1.Role_client),
		TokenID:            "t1",
		InitExp:            now.Add(2 * time.Minute).Unix(),
		IdleTimeoutSeconds: 60,
		Iat:                now.Add(-10 * time.Second).Unix(),
		Exp:                now.Add(30 * time.Second).Unix(),
	}
	attach1 := tunnelv1.Attach{
		V:                  1,
		ChannelId:          raw1.ChannelID,
		Role:               tunnelv1.Role_client,
		Token:              signTunnelToken(t, priv, raw1),
		EndpointInstanceId: base64url.Encode(make([]byte, 16)),
	}
	attach1JSON, err := json.Marshal(attach1)
	if err != nil {
		t.Fatalf("Marshal(attach1) failed: %v", err)
	}
	if err := c1.WriteMessage(websocket.TextMessage, attach1JSON); err != nil {
		t.Fatalf("WriteMessage(attach1) failed: %v", err)
	}

	c2, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{"https://ok"}})
	if err != nil {
		t.Fatalf("Dial(c2) failed: %v", err)
	}
	defer c2.Close()

	raw2 := raw1
	raw2.Role = uint8(tunnelv1.Role_server)
	raw2.TokenID = "t2"
	raw2.InitExp = now.Add(3 * time.Minute).Unix()
	attach2 := tunnelv1.Attach{
		V:                  1,
		ChannelId:          raw2.ChannelID,
		Role:               tunnelv1.Role_server,
		Token:              signTunnelToken(t, priv, raw2),
		EndpointInstanceId: base64url.Encode(make([]byte, 16)),
	}
	attach2JSON, err := json.Marshal(attach2)
	if err != nil {
		t.Fatalf("Marshal(attach2) failed: %v", err)
	}
	if err := c2.WriteMessage(websocket.TextMessage, attach2JSON); err != nil {
		t.Fatalf("WriteMessage(attach2) failed: %v", err)
	}

	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err = c2.ReadMessage()
	if err == nil {
		t.Fatal("expected close error")
	}
	var ce *websocket.CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("expected CloseError, got %T: %v", err, err)
	}
	if ce.Code != websocket.ClosePolicyViolation {
		t.Fatalf("expected close code %d, got %d", websocket.ClosePolicyViolation, ce.Code)
	}
	if ce.Text != "init_exp_mismatch" {
		t.Fatalf("expected close reason init_exp_mismatch, got %q", ce.Text)
	}
}

func TestAttachWithIdleTimeoutMismatchIsIdleTimeoutMismatch(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	keysFile := writeTempKeyset(t, issuer.TunnelKeysetFile{
		Keys: []issuer.TunnelKey{{KID: "kid", PubKeyB64: base64url.Encode(pub)}},
	})

	cfg := DefaultConfig()
	cfg.TunnelAudience = "aud"
	cfg.TunnelIssuer = "iss"
	cfg.IssuerKeysFile = keysFile
	cfg.AllowedOrigins = []string{"https://ok"}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	t.Cleanup(s.Close)

	mux := http.NewServeMux()
	s.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + cfg.Path

	c1, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{"https://ok"}})
	if err != nil {
		t.Fatalf("Dial(c1) failed: %v", err)
	}
	t.Cleanup(func() { _ = c1.Close() })

	now := time.Now()
	raw1 := token.Payload{
		Kid:                "kid",
		Aud:                cfg.TunnelAudience,
		Iss:                cfg.TunnelIssuer,
		ChannelID:          "ch_1",
		Role:               uint8(tunnelv1.Role_client),
		TokenID:            "t1",
		InitExp:            now.Add(2 * time.Minute).Unix(),
		IdleTimeoutSeconds: 60,
		Iat:                now.Add(-10 * time.Second).Unix(),
		Exp:                now.Add(30 * time.Second).Unix(),
	}
	attach1 := tunnelv1.Attach{
		V:                  1,
		ChannelId:          raw1.ChannelID,
		Role:               tunnelv1.Role_client,
		Token:              signTunnelToken(t, priv, raw1),
		EndpointInstanceId: base64url.Encode(make([]byte, 16)),
	}
	attach1JSON, err := json.Marshal(attach1)
	if err != nil {
		t.Fatalf("Marshal(attach1) failed: %v", err)
	}
	if err := c1.WriteMessage(websocket.TextMessage, attach1JSON); err != nil {
		t.Fatalf("WriteMessage(attach1) failed: %v", err)
	}

	c2, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{"https://ok"}})
	if err != nil {
		t.Fatalf("Dial(c2) failed: %v", err)
	}
	defer c2.Close()

	raw2 := raw1
	raw2.Role = uint8(tunnelv1.Role_server)
	raw2.TokenID = "t2"
	raw2.IdleTimeoutSeconds = 61
	attach2 := tunnelv1.Attach{
		V:                  1,
		ChannelId:          raw2.ChannelID,
		Role:               tunnelv1.Role_server,
		Token:              signTunnelToken(t, priv, raw2),
		EndpointInstanceId: base64url.Encode(make([]byte, 16)),
	}
	attach2JSON, err := json.Marshal(attach2)
	if err != nil {
		t.Fatalf("Marshal(attach2) failed: %v", err)
	}
	if err := c2.WriteMessage(websocket.TextMessage, attach2JSON); err != nil {
		t.Fatalf("WriteMessage(attach2) failed: %v", err)
	}

	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err = c2.ReadMessage()
	if err == nil {
		t.Fatal("expected close error")
	}
	var ce *websocket.CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("expected CloseError, got %T: %v", err, err)
	}
	if ce.Code != websocket.ClosePolicyViolation {
		t.Fatalf("expected close code %d, got %d", websocket.ClosePolicyViolation, ce.Code)
	}
	if ce.Text != "idle_timeout_mismatch" {
		t.Fatalf("expected close reason idle_timeout_mismatch, got %q", ce.Text)
	}
}
