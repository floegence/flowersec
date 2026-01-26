package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}
	payloadB64u := base64.RawURLEncoding.EncodeToString(b)
	signed := token.Prefix + "." + payloadB64u
	sig := ed25519.Sign(priv, []byte(signed))
	tokenStr := signed + "." + base64.RawURLEncoding.EncodeToString(sig)

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
