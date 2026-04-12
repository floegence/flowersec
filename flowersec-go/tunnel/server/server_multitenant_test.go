package server

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/controlplane/token"
	tunnelv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
	"github.com/gorilla/websocket"
)

func newMultiTenantAttachVerifier(t *testing.T) (AttachVerifier, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	privA, keysFileA := newVerifierKeypair(t, 1)
	privB, keysFileB := newVerifierKeypair(t, 33)
	tenantsPath := writeTenantFile(t, tenantFile{
		Tenants: []tenantFileEntry{
			{ID: "tenant-a", Audience: "aud-a", Issuer: "iss-a", IssuerKeysFile: keysFileA},
			{ID: "tenant-b", Audience: "aud-b", Issuer: "iss-b", IssuerKeysFile: keysFileB},
		},
	})
	verifier, err := NewMultiTenantVerifier(tenantsPath)
	if err != nil {
		t.Fatalf("NewMultiTenantVerifier() failed: %v", err)
	}
	return verifier, privA, privB
}

func TestAttachWithMultiTenantVerifierAcceptsMatchingScope(t *testing.T) {
	verifier, _, privB := newMultiTenantAttachVerifier(t)

	cfg := DefaultConfig()
	cfg.Verifier = verifier
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
	tokenStr, err := token.Sign(privB, token.Payload{
		Kid:                "kid",
		Aud:                "aud-b",
		Iss:                "iss-b",
		ChannelID:          "ch_mt_ok",
		Role:               uint8(tunnelv1.Role_client),
		TokenID:            "tok_mt_ok",
		InitExp:            now.Add(2 * time.Minute).Unix(),
		IdleTimeoutSeconds: 60,
		Iat:                now.Add(-10 * time.Second).Unix(),
		Exp:                now.Add(30 * time.Second).Unix(),
	})
	if err != nil {
		t.Fatalf("token.Sign() failed: %v", err)
	}

	attachJSON, err := json.Marshal(tunnelv1.Attach{
		V:                  1,
		ChannelId:          "ch_mt_ok",
		Role:               tunnelv1.Role_client,
		Token:              tokenStr,
		EndpointInstanceId: base64url.Encode(make([]byte, 16)),
	})
	if err != nil {
		t.Fatalf("Marshal(attach) failed: %v", err)
	}
	if err := c.WriteMessage(websocket.TextMessage, attachJSON); err != nil {
		t.Fatalf("WriteMessage() failed: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Stats().ChannelCount == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected multi-tenant attach to register a channel")
}

func TestAttachWithMultiTenantVerifierNamespacesChannelAndTokenIDs(t *testing.T) {
	verifier, privA, privB := newMultiTenantAttachVerifier(t)

	cfg := DefaultConfig()
	cfg.Verifier = verifier
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

	attachClient := func(priv ed25519.PrivateKey, aud string, iss string, endpointID string) *websocket.Conn {
		t.Helper()

		c, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{"https://ok"}})
		if err != nil {
			t.Fatalf("Dial() failed: %v", err)
		}

		now := time.Now()
		tokenStr, err := token.Sign(priv, token.Payload{
			Kid:                "kid",
			Aud:                aud,
			Iss:                iss,
			ChannelID:          "ch_shared",
			Role:               uint8(tunnelv1.Role_client),
			TokenID:            "tok_shared",
			InitExp:            now.Add(2 * time.Minute).Unix(),
			IdleTimeoutSeconds: 60,
			Iat:                now.Add(-10 * time.Second).Unix(),
			Exp:                now.Add(30 * time.Second).Unix(),
		})
		if err != nil {
			t.Fatalf("token.Sign() failed: %v", err)
		}

		attachJSON, err := json.Marshal(tunnelv1.Attach{
			V:                  1,
			ChannelId:          "ch_shared",
			Role:               tunnelv1.Role_client,
			Token:              tokenStr,
			EndpointInstanceId: endpointID,
		})
		if err != nil {
			t.Fatalf("Marshal(attach) failed: %v", err)
		}
		if err := c.WriteMessage(websocket.TextMessage, attachJSON); err != nil {
			t.Fatalf("WriteMessage() failed: %v", err)
		}
		return c
	}

	cA := attachClient(privA, "aud-a", "iss-a", base64url.Encode(make([]byte, 16)))
	defer cA.Close()
	cB := attachClient(privB, "aud-b", "iss-b", base64url.Encode([]byte("bbbbbbbbbbbbbbbb")))
	defer cB.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Stats().ChannelCount == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected shared channel_id/token_id to stay isolated across tenants")
}

func TestAttachWithMultiTenantVerifierRejectsUnknownScope(t *testing.T) {
	verifier, privA, _ := newMultiTenantAttachVerifier(t)

	cfg := DefaultConfig()
	cfg.Verifier = verifier
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
	tokenStr, err := token.Sign(privA, token.Payload{
		Kid:                "kid",
		Aud:                "aud-missing",
		Iss:                "iss-missing",
		ChannelID:          "ch_mt_bad",
		Role:               uint8(tunnelv1.Role_client),
		TokenID:            "tok_mt_bad",
		InitExp:            now.Add(2 * time.Minute).Unix(),
		IdleTimeoutSeconds: 60,
		Iat:                now.Add(-10 * time.Second).Unix(),
		Exp:                now.Add(30 * time.Second).Unix(),
	})
	if err != nil {
		t.Fatalf("token.Sign() failed: %v", err)
	}

	attachJSON, err := json.Marshal(tunnelv1.Attach{
		V:                  1,
		ChannelId:          "ch_mt_bad",
		Role:               tunnelv1.Role_client,
		Token:              tokenStr,
		EndpointInstanceId: base64url.Encode(make([]byte, 16)),
	})
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
		t.Fatalf("close code want=%d got=%d", websocket.ClosePolicyViolation, ce.Code)
	}
	if ce.Text != "invalid_token" {
		t.Fatalf("close text want=%q got=%q", "invalid_token", ce.Text)
	}
}
