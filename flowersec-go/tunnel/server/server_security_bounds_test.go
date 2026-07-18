package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/controlplane/token"
	tunnelv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/gorilla/websocket"
)

type fixedAttachVerifier struct {
	verified VerifiedToken
}

func (v fixedAttachVerifier) Verify(string, time.Time, time.Duration) (VerifiedToken, error) {
	return v.verified, nil
}

func (fixedAttachVerifier) Reload() error { return nil }

type attachEvent struct {
	result observability.AttachResult
	reason observability.AttachReason
}

type attachEventObserver struct {
	observability.TunnelObserver
	events chan attachEvent
}

func newAttachEventObserver() *attachEventObserver {
	return &attachEventObserver{
		TunnelObserver: observability.NoopTunnelObserver,
		events:         make(chan attachEvent, 8),
	}
}

func (o *attachEventObserver) Attach(result observability.AttachResult, reason observability.AttachReason) {
	o.events <- attachEvent{result: result, reason: reason}
}

type sequenceAttachAuthorizer struct {
	mu        sync.Mutex
	decisions []AttachAuthorizationDecision
	calls     int
}

func (a *sequenceAttachAuthorizer) AuthorizeAttach(context.Context, AttachAuthorizationRequest) (AttachAuthorizationDecision, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	decision := a.decisions[a.calls]
	a.calls++
	return decision, nil
}

func (*sequenceAttachAuthorizer) ObserveChannels(context.Context, ObserveChannelsRequest) (ObserveChannelsResponse, error) {
	return ObserveChannelsResponse{}, nil
}

type barrierAttachAuthorizer struct {
	started chan struct{}
	release chan struct{}
}

func (a *barrierAttachAuthorizer) AuthorizeAttach(context.Context, AttachAuthorizationRequest) (AttachAuthorizationDecision, error) {
	a.started <- struct{}{}
	<-a.release
	return AttachAuthorizationDecision{Allowed: true}, nil
}

func (*barrierAttachAuthorizer) ObserveChannels(context.Context, ObserveChannelsRequest) (ObserveChannelsResponse, error) {
	return ObserveChannelsResponse{}, nil
}

func TestDefaultConfigIncludesBoundedTokenSecurityDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxTokenLifetime != 2*time.Minute {
		t.Fatalf("MaxTokenLifetime want=%s got=%s", 2*time.Minute, cfg.MaxTokenLifetime)
	}
	if cfg.MaxInitHorizon != 2*time.Minute {
		t.Fatalf("MaxInitHorizon want=%s got=%s", 2*time.Minute, cfg.MaxInitHorizon)
	}
	if cfg.MaxReplayEntries != 4*cfg.MaxConns {
		t.Fatalf("MaxReplayEntries want=%d got=%d", 4*cfg.MaxConns, cfg.MaxReplayEntries)
	}
}

func TestNewDerivesReplayCapacityFromMaxConnections(t *testing.T) {
	cfg := Config{
		AllowedOrigins: []string{"https://ok"},
		Verifier:       fixedAttachVerifier{},
		MaxConns:       7,
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	t.Cleanup(s.Close)

	if s.cfg.MaxReplayEntries != 28 {
		t.Fatalf("MaxReplayEntries want=28 got=%d", s.cfg.MaxReplayEntries)
	}
	cache, ok := s.used.(*TokenUseCache)
	if !ok {
		t.Fatalf("default replay cache type got %T", s.used)
	}
	if cache.maxEntries != 28 {
		t.Fatalf("cache maxEntries want=28 got=%d", cache.maxEntries)
	}
}

func TestNewRejectsInvalidTokenSecurityBounds(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "negative token lifetime", mutate: func(cfg *Config) { cfg.MaxTokenLifetime = -time.Second }},
		{name: "negative init horizon", mutate: func(cfg *Config) { cfg.MaxInitHorizon = -time.Second }},
		{name: "negative replay entries", mutate: func(cfg *Config) { cfg.MaxReplayEntries = -1 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.AllowedOrigins = []string{"https://ok"}
			cfg.Verifier = fixedAttachVerifier{}
			tt.mutate(&cfg)
			_, err := New(cfg)
			var configErr *ConfigError
			if !errors.As(err, &configErr) {
				t.Fatalf("expected ConfigError, got %v", err)
			}
		})
	}
}

func TestAttachRejectsTokensOutsideConfiguredTimeBounds(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name    string
		payload token.Payload
	}{
		{
			name: "token lifetime",
			payload: token.Payload{
				ChannelID: "ch_lifetime", Role: uint8(tunnelv1.Role_client), TokenID: "tok_lifetime",
				Iat: now.Add(-91 * time.Second).Unix(), Exp: now.Add(30 * time.Second).Unix(),
				InitExp: now.Add(2 * time.Minute).Unix(), IdleTimeoutSeconds: 60,
			},
		},
		{
			name: "init horizon",
			payload: token.Payload{
				ChannelID: "ch_horizon", Role: uint8(tunnelv1.Role_client), TokenID: "tok_horizon",
				Iat: now.Add(-10 * time.Second).Unix(), Exp: now.Add(30 * time.Second).Unix(),
				InitExp: now.Add(3 * time.Minute).Unix(), IdleTimeoutSeconds: 60,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verified := VerifiedToken{Audience: "aud", Issuer: "iss", Payload: tt.payload}
			observer := newAttachEventObserver()
			s, wsURL := startSecurityBoundsServer(t, verified, nil, observer)
			conn := dialSecurityBoundsAttach(t, wsURL, tt.payload, 1)
			defer conn.Close()

			event := waitAttachEvent(t, observer)
			if event.result != observability.AttachResultFail || event.reason != observability.AttachReasonInvalidToken {
				t.Fatalf("attach event want fail/invalid_token got %s/%s", event.result, event.reason)
			}
			if s.Stats().ChannelCount != 0 {
				t.Fatal("out-of-bounds token must not create a channel")
			}
		})
	}
}

func TestAttachAuthorizerDenialDoesNotConsumeToken(t *testing.T) {
	now := time.Now()
	payload := token.Payload{
		ChannelID: "ch_authorizer_retry", Role: uint8(tunnelv1.Role_client), TokenID: "tok_authorizer_retry",
		Iat: now.Add(-10 * time.Second).Unix(), Exp: now.Add(30 * time.Second).Unix(),
		InitExp: now.Add(2 * time.Minute).Unix(), IdleTimeoutSeconds: 60,
	}
	authorizer := &sequenceAttachAuthorizer{decisions: []AttachAuthorizationDecision{
		{Allowed: false},
		{Allowed: true},
	}}
	observer := newAttachEventObserver()
	verified := VerifiedToken{Audience: "aud", Issuer: "iss", Payload: payload}
	s, wsURL := startSecurityBoundsServer(t, verified, authorizer, observer)

	denied := dialSecurityBoundsAttach(t, wsURL, payload, 1)
	defer denied.Close()
	first := waitAttachEvent(t, observer)
	if first.reason != observability.AttachReasonPolicyDenied {
		t.Fatalf("first attach reason want policy_denied got %s", first.reason)
	}

	allowed := dialSecurityBoundsAttach(t, wsURL, payload, 2)
	defer allowed.Close()
	second := waitAttachEvent(t, observer)
	if second.result != observability.AttachResultOK || second.reason != observability.AttachReasonOK {
		t.Fatalf("second attach want ok got %s/%s", second.result, second.reason)
	}
	if s.Stats().ChannelCount != 1 {
		t.Fatalf("authorized retry should create one channel, got %d", s.Stats().ChannelCount)
	}
}

func TestConcurrentAttachWithSameTokenAllowsOneUse(t *testing.T) {
	now := time.Now()
	payload := token.Payload{
		ChannelID: "ch_concurrent_replay", Role: uint8(tunnelv1.Role_client), TokenID: "tok_concurrent_replay",
		Iat: now.Add(-10 * time.Second).Unix(), Exp: now.Add(30 * time.Second).Unix(),
		InitExp: now.Add(2 * time.Minute).Unix(), IdleTimeoutSeconds: 60,
	}
	authorizer := &barrierAttachAuthorizer{started: make(chan struct{}, 2), release: make(chan struct{})}
	observer := newAttachEventObserver()
	verified := VerifiedToken{Audience: "aud", Issuer: "iss", Payload: payload}
	_, wsURL := startSecurityBoundsServer(t, verified, authorizer, observer)

	first := dialSecurityBoundsAttach(t, wsURL, payload, 1)
	defer first.Close()
	second := dialSecurityBoundsAttach(t, wsURL, payload, 2)
	defer second.Close()
	waitAuthorizerStart(t, authorizer.started)
	waitAuthorizerStart(t, authorizer.started)
	close(authorizer.release)

	events := []attachEvent{waitAttachEvent(t, observer), waitAttachEvent(t, observer)}
	okCount := 0
	replayCount := 0
	for _, event := range events {
		if event.result == observability.AttachResultOK && event.reason == observability.AttachReasonOK {
			okCount++
		}
		if event.result == observability.AttachResultFail && event.reason == observability.AttachReasonTokenReplay {
			replayCount++
		}
	}
	if okCount != 1 || replayCount != 1 {
		t.Fatalf("events want one ok and one replay, got %#v", events)
	}
}

func startSecurityBoundsServer(t *testing.T, verified VerifiedToken, authorizer Authorizer, observer observability.TunnelObserver) (*Server, string) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.AllowedOrigins = []string{"https://ok"}
	cfg.Verifier = fixedAttachVerifier{verified: verified}
	cfg.Authorizer = authorizer
	cfg.Observer = observer
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	t.Cleanup(s.Close)
	mux := http.NewServeMux()
	s.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return s, "ws" + strings.TrimPrefix(ts.URL, "http") + cfg.Path
}

func dialSecurityBoundsAttach(t *testing.T, wsURL string, payload token.Payload, endpointByte byte) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{"https://ok"}})
	if err != nil {
		t.Fatalf("Dial() failed: %v", err)
	}
	attach := tunnelv1.Attach{
		V:                  1,
		ChannelId:          payload.ChannelID,
		Role:               tunnelv1.Role(payload.Role),
		Token:              "signed-token",
		EndpointInstanceId: base64url.Encode([]byte(strings.Repeat(string([]byte{endpointByte}), 16))),
	}
	if err := conn.WriteJSON(attach); err != nil {
		conn.Close()
		t.Fatalf("WriteJSON() failed: %v", err)
	}
	return conn
}

func waitAttachEvent(t *testing.T, observer *attachEventObserver) attachEvent {
	t.Helper()
	select {
	case event := <-observer.events:
		return event
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for attach event")
		return attachEvent{}
	}
}

func waitAuthorizerStart(t *testing.T, started <-chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for attach authorization")
	}
}
