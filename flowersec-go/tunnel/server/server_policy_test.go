package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/controlplane/token"
	tunnelv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/gorilla/websocket"
)

type stubAuthorizer struct {
	mu              sync.Mutex
	attachDecision  AttachAuthorizationDecision
	attachErr       error
	observeDecision ObserveChannelsResponse
	observeErr      error
	observeCalls    int
	lastAttachReq   AttachAuthorizationRequest
	lastObserveReq  ObserveChannelsRequest
}

func (s *stubAuthorizer) AuthorizeAttach(_ context.Context, req AttachAuthorizationRequest) (AttachAuthorizationDecision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastAttachReq = req
	return s.attachDecision, s.attachErr
}

func (s *stubAuthorizer) ObserveChannels(_ context.Context, req ObserveChannelsRequest) (ObserveChannelsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observeCalls++
	s.lastObserveReq = req
	return s.observeDecision, s.observeErr
}

type blockingAttachAuthorizer struct {
	attachStarted chan context.Context
}

func (a *blockingAttachAuthorizer) AuthorizeAttach(ctx context.Context, _ AttachAuthorizationRequest) (AttachAuthorizationDecision, error) {
	select {
	case a.attachStarted <- ctx:
	default:
	}
	<-ctx.Done()
	return AttachAuthorizationDecision{}, ctx.Err()
}

func (a *blockingAttachAuthorizer) ObserveChannels(context.Context, ObserveChannelsRequest) (ObserveChannelsResponse, error) {
	return ObserveChannelsResponse{}, nil
}

type blockingObserveAuthorizer struct {
	observeStarted chan context.Context
}

func (a *blockingObserveAuthorizer) AuthorizeAttach(context.Context, AttachAuthorizationRequest) (AttachAuthorizationDecision, error) {
	return AttachAuthorizationDecision{Allowed: true}, nil
}

func (a *blockingObserveAuthorizer) ObserveChannels(ctx context.Context, _ ObserveChannelsRequest) (ObserveChannelsResponse, error) {
	select {
	case a.observeStarted <- ctx:
	default:
	}
	<-ctx.Done()
	return ObserveChannelsResponse{}, ctx.Err()
}

func TestAttachDeniedByAuthorizerIsPolicyDenied(t *testing.T) {
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
	cfg.Authorizer = &stubAuthorizer{attachDecision: AttachAuthorizationDecision{Allowed: false}}

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
	tokenStr, err := token.Sign(priv, token.Payload{
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
	})
	if err != nil {
		t.Fatalf("token.Sign() failed: %v", err)
	}

	attachJSON, err := json.Marshal(tunnelv1.Attach{
		V:                  1,
		ChannelId:          "ch_1",
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
	if ce.Text != "policy_denied" {
		t.Fatalf("close text want=%q got=%q", "policy_denied", ce.Text)
	}
}

func TestAttachAuthorizerContextCanceledWhenClientDisconnects(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	keysFile := writeTempKeyset(t, issuer.TunnelKeysetFile{
		Keys: []issuer.TunnelKey{{KID: "kid", PubKeyB64: base64url.Encode(pub)}},
	})

	auth := &blockingAttachAuthorizer{attachStarted: make(chan context.Context, 1)}

	cfg := DefaultConfig()
	cfg.TunnelAudience = "aud"
	cfg.TunnelIssuer = "iss"
	cfg.IssuerKeysFile = keysFile
	cfg.AllowedOrigins = []string{"https://ok"}
	cfg.Authorizer = auth
	cfg.PolicyRequestTimeout = 5 * time.Second

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

	now := time.Now()
	tokenStr, err := token.Sign(priv, token.Payload{
		Kid:                "kid",
		Aud:                cfg.TunnelAudience,
		Iss:                cfg.TunnelIssuer,
		ChannelID:          "ch_ctx",
		Role:               uint8(tunnelv1.Role_client),
		TokenID:            "t-ctx",
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
		ChannelId:          "ch_ctx",
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

	var attachCtx context.Context
	select {
	case attachCtx = <-auth.attachStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for authorizer call")
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	select {
	case <-attachCtx.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("attach authorizer context was not canceled after client disconnect")
	}
	if !errors.Is(attachCtx.Err(), context.Canceled) {
		t.Fatalf("attach authorizer context err want=%v got=%v", context.Canceled, attachCtx.Err())
	}
}

func TestObserveLoopClosesDeniedChannel(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	keysFile := writeTempKeyset(t, issuer.TunnelKeysetFile{
		Keys: []issuer.TunnelKey{{KID: "kid", PubKeyB64: base64url.Encode(pub)}},
	})

	auth := &stubAuthorizer{
		attachDecision: AttachAuthorizationDecision{
			Allowed:              true,
			LeaseExpiresAtUnixMs: time.Now().Add(5 * time.Second).UnixMilli(),
		},
		observeDecision: ObserveChannelsResponse{
			Decisions: []ChannelObservationDecision{{
				ChannelID: "ch_policy",
				Allowed:   false,
			}},
		},
	}

	cfg := DefaultConfig()
	cfg.TunnelAudience = "aud"
	cfg.TunnelIssuer = "iss"
	cfg.IssuerKeysFile = keysFile
	cfg.AllowedOrigins = []string{"https://ok"}
	cfg.Authorizer = auth
	cfg.PolicyObserveInterval = 20 * time.Millisecond
	cfg.PolicyRequestTimeout = 200 * time.Millisecond
	cfg.PolicyBatchSize = 8

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
	tokenStr, err := token.Sign(priv, token.Payload{
		Kid:                "kid",
		Aud:                cfg.TunnelAudience,
		Iss:                cfg.TunnelIssuer,
		ChannelID:          "ch_policy",
		Role:               uint8(tunnelv1.Role_client),
		TokenID:            "t-policy",
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
		ChannelId:          "ch_policy",
		Role:               tunnelv1.Role_client,
		Token:              tokenStr,
		EndpointInstanceId: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	})
	if err != nil {
		t.Fatalf("Marshal(attach) failed: %v", err)
	}
	if err := c.WriteMessage(websocket.TextMessage, attachJSON); err != nil {
		t.Fatalf("WriteMessage() failed: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Stats().ChannelCount == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected observe loop to close the channel")
}

func TestObserveLoopContextCanceledOnServerClose(t *testing.T) {
	auth := &blockingObserveAuthorizer{observeStarted: make(chan context.Context, 1)}
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())

	s := &Server{
		cfg: Config{
			PolicyObserveInterval: 10 * time.Millisecond,
			PolicyRequestTimeout:  5 * time.Second,
			PolicyBatchSize:       1,
		},
		auth:            auth,
		obs:             observability.NoopTunnelObserver,
		channels:        map[string]*channelState{"ch_observe": &channelState{id: "ch_observe"}},
		stopCh:          make(chan struct{}),
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
	}

	done := make(chan struct{})
	go func() {
		s.observeLoop()
		close(done)
	}()

	var observeCtx context.Context
	select {
	case observeCtx = <-auth.observeStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for observe authorizer call")
	}

	s.Close()

	select {
	case <-observeCtx.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("observe authorizer context was not canceled after server close")
	}
	if !errors.Is(observeCtx.Err(), context.Canceled) {
		t.Fatalf("observe authorizer context err want=%v got=%v", context.Canceled, observeCtx.Err())
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("observe loop did not stop after server close")
	}
}
