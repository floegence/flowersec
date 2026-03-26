package e2e_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/controlplane/channelinit"
	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/flowersec-go/rpc"
	"github.com/floegence/flowersec/flowersec-go/tunnel/server"
)

const tunnelOrigin = "https://app.redeven.com"

type tunnelE2EFixture struct {
	t      *testing.T
	tunnel *server.Server
	wsURL  string
}

func newTunnelE2EFixture(t *testing.T, cfg server.Config) *tunnelE2EFixture {
	t.Helper()

	if len(cfg.AllowedOrigins) == 0 {
		cfg.AllowedOrigins = []string{tunnelOrigin}
	}
	if strings.TrimSpace(cfg.Path) == "" {
		cfg.Path = server.DefaultConfig().Path
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = 20 * time.Millisecond
	}

	tun, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	tun.Register(mux)
	ts := httptest.NewServer(mux)

	t.Cleanup(func() {
		ts.Close()
		tun.Close()
	})

	return &tunnelE2EFixture{
		t:      t,
		tunnel: tun,
		wsURL:  "ws" + strings.TrimPrefix(ts.URL, "http") + cfg.Path,
	}
}

func (f *tunnelE2EFixture) waitForChannelCount(want int, timeout time.Duration) {
	f.t.Helper()
	waitForCondition(f.t, timeout, func() bool {
		return f.tunnel.Stats().ChannelCount == want
	}, "expected channel count=%d, got %d", want, f.tunnel.Stats().ChannelCount)
}

type tenantIssuerFixture struct {
	tenantID string
	audience string
	issuerID string
	issuer   *issuer.Keyset
	keyFile  string
}

func newTenantIssuerFixture(t *testing.T, tenantID string, audience string, issuerID string, seedStart byte) tenantIssuerFixture {
	t.Helper()
	iss, keyFile := newTestIssuerWithSeed(t, seedStart)
	return tenantIssuerFixture{
		tenantID: tenantID,
		audience: audience,
		issuerID: issuerID,
		issuer:   iss,
		keyFile:  keyFile,
	}
}

func (tenant tenantIssuerFixture) newGrantPair(t *testing.T, wsURL string, channelID string, idleTimeoutSeconds int32) (*controlv1.ChannelInitGrant, *controlv1.ChannelInitGrant) {
	t.Helper()
	ci := &channelinit.Service{
		Issuer: tenant.issuer,
		Params: channelinit.Params{
			TunnelURL:          wsURL,
			TunnelAudience:     tenant.audience,
			IssuerID:           tenant.issuerID,
			TokenExpSeconds:    60,
			IdleTimeoutSeconds: idleTimeoutSeconds,
		},
	}
	grantC, grantS, err := ci.NewChannelInit(channelID)
	if err != nil {
		t.Fatal(err)
	}
	return grantC, grantS
}

type testTenantsFile struct {
	Tenants []testTenantFileEntry `json:"tenants"`
}

type testTenantFileEntry struct {
	ID             string `json:"id,omitempty"`
	Audience       string `json:"aud"`
	Issuer         string `json:"iss"`
	IssuerKeysFile string `json:"issuer_keys_file"`
}

func writeTenantsFile(t *testing.T, tenants []tenantIssuerFixture) string {
	t.Helper()

	raw := testTenantsFile{
		Tenants: make([]testTenantFileEntry, 0, len(tenants)),
	}
	for _, tenant := range tenants {
		raw.Tenants = append(raw.Tenants, testTenantFileEntry{
			ID:             tenant.tenantID,
			Audience:       tenant.audience,
			Issuer:         tenant.issuerID,
			IssuerKeysFile: tenant.keyFile,
		})
	}

	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "tenants.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

type endpointConnectResult struct {
	session endpoint.Session
	err     error
}

func connectTunnelPair(ctx context.Context, t *testing.T, grantC *controlv1.ChannelInitGrant, grantS *controlv1.ChannelInitGrant) (client.Client, endpoint.Session) {
	t.Helper()

	serverCh := make(chan endpointConnectResult, 1)
	go func() {
		session, err := endpoint.ConnectTunnel(ctx, grantS, endpoint.WithOrigin(tunnelOrigin), endpoint.WithKeepaliveInterval(0))
		serverCh <- endpointConnectResult{session: session, err: err}
	}()

	cli, err := client.ConnectTunnel(ctx, grantC, client.WithOrigin(tunnelOrigin), client.WithKeepaliveInterval(0))
	if err != nil {
		t.Fatal(err)
	}

	result := <-serverCh
	if result.err != nil {
		_ = cli.Close()
		t.Fatal(result.err)
	}

	return cli, result.session
}

func runTunnelRPCOnce(ctx context.Context, t *testing.T, grantC *controlv1.ChannelInitGrant, grantS *controlv1.ChannelInitGrant) string {
	t.Helper()

	cli, sess := connectTunnelPair(ctx, t, grantC, grantS)
	defer cli.Close()
	defer sess.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- serveRPCStream(ctx, sess)
	}()

	payload, rpcErr, err := cli.RPC().Call(ctx, 1, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if rpcErr != nil {
		t.Fatalf("rpc error: %v", rpcErr)
	}

	_ = cli.Close()
	if err := <-serverErrCh; err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func serveRPCStream(ctx context.Context, sess endpoint.Session) error {
	kind, stream, err := sess.AcceptStreamHello(8 * 1024)
	if err != nil {
		return err
	}
	defer stream.Close()

	if kind != "rpc" {
		return fmt.Errorf("unexpected stream kind %q", kind)
	}

	router := rpc.NewRouter()
	router.Register(1, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
		_ = ctx
		_ = payload
		return json.RawMessage(`{"ok":true}`), nil
	})

	err = rpc.NewServer(stream, router).Serve(ctx)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return nil
	case errors.Is(err, io.EOF):
		return nil
	default:
		return err
	}
}

type authorizerRecorder struct {
	mu sync.Mutex

	attachRequests []server.AttachAuthorizationRequest
	attachHeaders  []http.Header

	observeRequests []server.ObserveChannelsRequest
	observeHeaders  []http.Header

	attachResponder  func(server.AttachAuthorizationRequest) server.AttachAuthorizationDecision
	observeResponder func(server.ObserveChannelsRequest) server.ObserveChannelsResponse
}

func newAuthorizerRecorder() *authorizerRecorder {
	return &authorizerRecorder{
		attachResponder: func(server.AttachAuthorizationRequest) server.AttachAuthorizationDecision {
			return server.AttachAuthorizationDecision{Allowed: true}
		},
		observeResponder: func(server.ObserveChannelsRequest) server.ObserveChannelsResponse {
			return server.ObserveChannelsResponse{}
		},
	}
}

func (r *authorizerRecorder) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/attach", r.handleAttach)
	mux.HandleFunc("/observe", r.handleObserve)
	return mux
}

func (r *authorizerRecorder) handleAttach(w http.ResponseWriter, req *http.Request) {
	var body server.AttachAuthorizationRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	r.attachRequests = append(r.attachRequests, body)
	r.attachHeaders = append(r.attachHeaders, req.Header.Clone())
	responder := r.attachResponder
	r.mu.Unlock()

	writeAuthorizerEnvelope(w, responder(body))
}

func (r *authorizerRecorder) handleObserve(w http.ResponseWriter, req *http.Request) {
	var body server.ObserveChannelsRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	r.observeRequests = append(r.observeRequests, body)
	r.observeHeaders = append(r.observeHeaders, req.Header.Clone())
	responder := r.observeResponder
	r.mu.Unlock()

	writeAuthorizerEnvelope(w, responder(body))
}

func (r *authorizerRecorder) attachCallCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.attachRequests)
}

func (r *authorizerRecorder) waitForAttachCalls(t *testing.T, want int, timeout time.Duration) {
	t.Helper()
	waitForCondition(t, timeout, func() bool {
		return r.attachCallCount() >= want
	}, "expected at least %d attach authorizer calls", want)
}

func (r *authorizerRecorder) observeCallCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.observeRequests)
}

func (r *authorizerRecorder) waitForObserveCalls(t *testing.T, want int, timeout time.Duration) {
	t.Helper()
	waitForCondition(t, timeout, func() bool {
		return r.observeCallCount() >= want
	}, "expected at least %d observe authorizer calls", want)
}

func (r *authorizerRecorder) snapshotAttachRequests() []server.AttachAuthorizationRequest {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]server.AttachAuthorizationRequest, len(r.attachRequests))
	copy(out, r.attachRequests)
	return out
}

func (r *authorizerRecorder) snapshotAttachHeaders() []http.Header {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]http.Header, 0, len(r.attachHeaders))
	for _, header := range r.attachHeaders {
		out = append(out, header.Clone())
	}
	return out
}

func (r *authorizerRecorder) snapshotObserveRequests() []server.ObserveChannelsRequest {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]server.ObserveChannelsRequest, len(r.observeRequests))
	copy(out, r.observeRequests)
	return out
}

func (r *authorizerRecorder) snapshotObserveHeaders() []http.Header {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]http.Header, 0, len(r.observeHeaders))
	for _, header := range r.observeHeaders {
		out = append(out, header.Clone())
	}
	return out
}

func writeAuthorizerEnvelope(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"data":    data,
	})
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool, format string, args ...any) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf(format, args...)
}

func newTestIssuerWithSeed(t *testing.T, seedStart byte) (*issuer.Keyset, string) {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedStart + byte(i)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	ks, err := issuer.New("k1", priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ks.ExportTunnelKeyset()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "issuer_keys.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return ks, path
}
