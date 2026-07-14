package server

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/controlplane/token"
	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	tunnelv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/gorilla/websocket"
)

type testObserver struct {
	mu         sync.Mutex
	connCounts []int64
	encrypted  int
	closes     []observability.CloseReason
	replaces   []observability.ReplaceResult
}

func (o *testObserver) ConnCount(n int64) {
	o.mu.Lock()
	o.connCounts = append(o.connCounts, n)
	o.mu.Unlock()
}
func (o *testObserver) ChannelCount(_ int) {}
func (o *testObserver) Attach(_ observability.AttachResult, _ observability.AttachReason) {
}
func (o *testObserver) Replace(result observability.ReplaceResult) {
	o.mu.Lock()
	o.replaces = append(o.replaces, result)
	o.mu.Unlock()
}
func (o *testObserver) Close(r observability.CloseReason) {
	o.mu.Lock()
	o.closes = append(o.closes, r)
	o.mu.Unlock()
}
func (o *testObserver) PairLatency(_ time.Duration) {}
func (o *testObserver) Encrypted() {
	o.mu.Lock()
	o.encrypted++
	o.mu.Unlock()
}

func TestCheckOrigin(t *testing.T) {
	s := &Server{cfg: Config{AllowedOrigins: []string{"https://ok"}, AllowNoOrigin: false}}
	req := httptest.NewRequest(http.MethodGet, "http://example", nil)
	if s.checkOrigin(req) {
		t.Fatalf("expected no origin to be rejected")
	}
	req.Header.Set("Origin", "https://bad")
	if s.checkOrigin(req) {
		t.Fatalf("expected origin to be rejected")
	}
	req.Header.Set("Origin", "https://ok")
	if !s.checkOrigin(req) {
		t.Fatalf("expected origin to be accepted")
	}
}

func TestTrackConnLimits(t *testing.T) {
	obs := &testObserver{}
	s := &Server{cfg: Config{MaxConns: 1}, obs: obs}

	c1 := &websocket.Conn{}
	c2 := &websocket.Conn{}

	if !s.trackConn(c1) {
		t.Fatalf("expected first connection to be accepted")
	}
	if s.trackConn(c2) {
		t.Fatalf("expected second connection to be rejected")
	}
	if len(obs.connCounts) == 0 {
		t.Fatalf("expected observer to be notified")
	}

	s.untrackConn(c1)
	if got := obs.connCounts[len(obs.connCounts)-1]; got != 0 {
		t.Fatalf("expected conn count to return to 0, got %d", got)
	}
}

func TestNewRejectsNegativeMaxTotalQueuedBytes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TunnelAudience = "aud"
	cfg.TunnelIssuer = "iss"
	cfg.IssuerKeysFile = "does-not-matter.json"
	cfg.AllowedOrigins = []string{"https://ok"}
	cfg.MaxTotalQueuedBytes = -1
	if _, err := New(cfg); err == nil {
		t.Fatalf("expected error for negative max total pending bytes")
	}
}

func TestNewRejectsInvalidPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Path = "ws"
	cfg.TunnelAudience = "aud"
	cfg.TunnelIssuer = "iss"
	cfg.IssuerKeysFile = "does-not-matter.json"
	cfg.AllowedOrigins = []string{"https://ok"}
	if _, err := New(cfg); err == nil {
		t.Fatalf("expected error for invalid path")
	}
}

func TestNewRejectsNegativeConfigValues(t *testing.T) {
	base := DefaultConfig()
	base.TunnelAudience = "aud"
	base.TunnelIssuer = "iss"
	base.IssuerKeysFile = "does-not-matter.json"
	base.AllowedOrigins = []string{"https://ok"}

	cases := []struct {
		name string
		mut  func(cfg *Config)
	}{
		{name: "MaxAttachBytes", mut: func(cfg *Config) { cfg.MaxAttachBytes = -1 }},
		{name: "MaxRecordBytes", mut: func(cfg *Config) { cfg.MaxRecordBytes = -1 }},
		{name: "MaxPendingBytes", mut: func(cfg *Config) { cfg.MaxPendingBytes = -1 }},
		{name: "MaxChannels", mut: func(cfg *Config) { cfg.MaxChannels = -1 }},
		{name: "MaxConns", mut: func(cfg *Config) { cfg.MaxConns = -1 }},
		{name: "CleanupInterval", mut: func(cfg *Config) { cfg.CleanupInterval = -1 }},
		{name: "MaxWriteQueueBytes", mut: func(cfg *Config) { cfg.MaxWriteQueueBytes = -1 }},
		{name: "ReplaceCloseCode", mut: func(cfg *Config) { cfg.ReplaceCloseCode = -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mut(&cfg)
			_, err := New(cfg)
			if err == nil {
				t.Fatalf("expected error")
			}
			var ce *ConfigError
			if !errors.As(err, &ce) {
				t.Fatalf("expected *ConfigError, got %T", err)
			}
		})
	}
}

func TestNewRejectsInvalidReplaceCloseCode(t *testing.T) {
	base := DefaultConfig()
	base.TunnelAudience = "aud"
	base.TunnelIssuer = "iss"
	base.IssuerKeysFile = "does-not-matter.json"
	base.AllowedOrigins = []string{"https://ok"}

	codes := []int{1, 999, 1005, 1014, 1015, 5000}
	for _, code := range codes {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			cfg := base
			cfg.ReplaceCloseCode = code
			_, err := New(cfg)
			if err == nil {
				t.Fatalf("expected error for ReplaceCloseCode=%d", code)
			}
			var ce *ConfigError
			if !errors.As(err, &ce) {
				t.Fatalf("expected *ConfigError, got %T", err)
			}
		})
	}
}

func TestNewNormalizesWhitespaceConfigFields(t *testing.T) {
	keysFile := writeTempKeyset(t, issuer.TunnelKeysetFile{
		Keys: []issuer.TunnelKey{{
			KID:       "kid",
			PubKeyB64: base64url.Encode(make([]byte, ed25519.PublicKeySize)),
		}},
	})

	cfg := DefaultConfig()
	cfg.Path = " /ws "
	cfg.TunnelAudience = " aud "
	cfg.TunnelIssuer = " iss "
	cfg.IssuerKeysFile = " " + keysFile + " "
	cfg.AllowedOrigins = []string{" https://ok ", " "}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	t.Cleanup(s.Close)

	if got := s.cfg.Path; got != "/ws" {
		t.Fatalf("Path mismatch: got %q want %q", got, "/ws")
	}
	if got := s.cfg.TunnelAudience; got != "aud" {
		t.Fatalf("TunnelAudience mismatch: got %q want %q", got, "aud")
	}
	if got := s.cfg.TunnelIssuer; got != "iss" {
		t.Fatalf("TunnelIssuer mismatch: got %q want %q", got, "iss")
	}
	if got := s.cfg.IssuerKeysFile; got != keysFile {
		t.Fatalf("IssuerKeysFile mismatch: got %q want %q", got, keysFile)
	}
	if got := s.cfg.AllowedOrigins; len(got) != 1 || got[0] != "https://ok" {
		t.Fatalf("AllowedOrigins mismatch: got=%v want=%v", got, []string{"https://ok"})
	}
}

func TestClose_RejectsNewWebSocketUpgrades(t *testing.T) {
	s := &Server{
		cfg:      Config{Path: "/ws", AllowedOrigins: []string{"example.com"}},
		obs:      observability.NoopTunnelObserver,
		channels: make(map[string]*channelState),
		stopCh:   make(chan struct{}),
	}

	mux := http.NewServeMux()
	s.Register(mux)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	s.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{"http://example.com"}})
	if err == nil {
		t.Fatal("expected dial error")
	}
	if resp == nil {
		t.Fatalf("expected HTTP response, got nil (err=%v)", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

func TestAllowReplaceLocked(t *testing.T) {
	s := &Server{cfg: Config{ReplaceCooldown: 10 * time.Second}}
	st := &channelState{}
	now := time.Unix(0, 0)
	if !s.allowReplaceLocked(st, tunnelv1.Role_client, now) {
		t.Fatalf("expected first replace to pass")
	}
	if s.allowReplaceLocked(st, tunnelv1.Role_client, now.Add(2*time.Second)) {
		t.Fatalf("expected cooldown to block replace")
	}

	s = &Server{cfg: Config{ReplaceWindow: 10 * time.Second, MaxReplacesPerWindow: 2}}
	st = &channelState{}
	if !s.allowReplaceLocked(st, tunnelv1.Role_client, now) || !s.allowReplaceLocked(st, tunnelv1.Role_client, now.Add(time.Second)) {
		t.Fatalf("expected first two replaces to pass")
	}
	if s.allowReplaceLocked(st, tunnelv1.Role_client, now.Add(2*time.Second)) {
		t.Fatalf("expected rate limit to block replace")
	}
}

func testVerifiedToken(role tunnelv1.Role, channelID, tokenID string, now time.Time) VerifiedToken {
	return VerifiedToken{
		Audience: "aud",
		Issuer:   "iss",
		Payload: token.Payload{
			Kid:                "kid",
			Aud:                "aud",
			Iss:                "iss",
			ChannelID:          channelID,
			Role:               uint8(role),
			TokenID:            tokenID,
			InitExp:            now.Add(2 * time.Minute).Unix(),
			IdleTimeoutSeconds: 60,
			Iat:                now.Add(-10 * time.Second).Unix(),
			Exp:                now.Add(30 * time.Second).Unix(),
		},
	}
}

func testAttach(role tunnelv1.Role, channelID, endpointID string) *tunnelv1.Attach {
	return &tunnelv1.Attach{
		V:                  1,
		ChannelId:          channelID,
		Role:               role,
		Token:              "token",
		EndpointInstanceId: endpointID,
	}
}

func TestAddEndpointSameChannelReplacementResetsExistingPair(t *testing.T) {
	obs := &testObserver{}
	s := &Server{
		cfg:      Config{MaxWriteQueueBytes: 1024, MaxRecordBytes: 1024},
		obs:      obs,
		channels: make(map[string]*channelState),
		bw:       sync.Map{},
	}

	oldClientWS, oldClientCleanup := newBlackholeWebSocketConn(t)
	defer oldClientCleanup()
	oldServerWS, oldServerCleanup := newBlackholeWebSocketConn(t)
	defer oldServerCleanup()
	newClientWS, newClientCleanup := newBlackholeWebSocketConn(t)
	defer newClientCleanup()

	now := time.Now()
	verifiedClient := testVerifiedToken(tunnelv1.Role_client, "ch", "tok-client-1", now)
	verifiedServer := testVerifiedToken(tunnelv1.Role_server, "ch", "tok-server-1", now)
	scopeKey := verifiedScopeKey(verifiedClient)

	if err := s.addEndpoint(testAttach(tunnelv1.Role_client, "ch", "client-1"), verifiedClient, scopeKey, AttachAuthorizationDecision{Allowed: true}, nil, oldClientWS); err != nil {
		t.Fatalf("add old client: %v", err)
	}
	if err := s.addEndpoint(testAttach(tunnelv1.Role_server, "ch", "server-1"), verifiedServer, scopeKey, AttachAuthorizationDecision{Allowed: true}, nil, oldServerWS); err != nil {
		t.Fatalf("add old server: %v", err)
	}
	if err := s.addEndpoint(testAttach(tunnelv1.Role_client, "ch", "client-2"), testVerifiedToken(tunnelv1.Role_client, "ch", "tok-client-2", now), scopeKey, AttachAuthorizationDecision{Allowed: true}, nil, newClientWS); err != nil {
		t.Fatalf("replace client: %v", err)
	}

	st := s.channels[scopedChannelKey(scopeKey, "ch")]
	if st == nil {
		t.Fatalf("expected replacement channel to exist")
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.conns) != 1 {
		t.Fatalf("expected replacement to reset old pair and keep one endpoint, got %d", len(st.conns))
	}
	if got := st.conns[tunnelv1.Role_client]; got == nil || got.eid != "client-2" {
		t.Fatalf("expected new client endpoint, got %#v", got)
	}
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if len(obs.replaces) != 1 || obs.replaces[0] != observability.ReplaceResultOK {
		t.Fatalf("expected one ok replace event, got %v", obs.replaces)
	}
}

func TestAddEndpointSameChannelDifferentScopeDoesNotReplace(t *testing.T) {
	s := &Server{
		cfg:      Config{MaxWriteQueueBytes: 1024, MaxRecordBytes: 1024},
		obs:      observability.NoopTunnelObserver,
		channels: make(map[string]*channelState),
		bw:       sync.Map{},
	}

	ws1, cleanup1 := newBlackholeWebSocketConn(t)
	defer cleanup1()
	ws2, cleanup2 := newBlackholeWebSocketConn(t)
	defer cleanup2()

	now := time.Now()
	verified1 := testVerifiedToken(tunnelv1.Role_client, "shared", "tok-1", now)
	verified2 := testVerifiedToken(tunnelv1.Role_client, "shared", "tok-2", now)
	verified2.Audience = "other-aud"
	scope1 := verifiedScopeKey(verified1)
	scope2 := verifiedScopeKey(verified2)

	if err := s.addEndpoint(testAttach(tunnelv1.Role_client, "shared", "client-1"), verified1, scope1, AttachAuthorizationDecision{Allowed: true}, nil, ws1); err != nil {
		t.Fatalf("add first scoped endpoint: %v", err)
	}
	if err := s.addEndpoint(testAttach(tunnelv1.Role_client, "shared", "client-2"), verified2, scope2, AttachAuthorizationDecision{Allowed: true}, nil, ws2); err != nil {
		t.Fatalf("add second scoped endpoint: %v", err)
	}
	if len(s.channels) != 2 {
		t.Fatalf("expected same channel id in different scopes to remain separate, got %d channels", len(s.channels))
	}
	if s.channels[scopedChannelKey(scope1, "shared")] == nil || s.channels[scopedChannelKey(scope2, "shared")] == nil {
		t.Fatalf("expected both scoped channel keys to be present")
	}
}

func TestRouteOrBufferBehavior(t *testing.T) {
	obs := &testObserver{}
	s := &Server{cfg: Config{MaxPendingBytes: 4, MaxRecordBytes: 1 << 20}, obs: obs, channels: make(map[string]*channelState)}

	st := &channelState{conns: make(map[tunnelv1.Role]*endpointConn)}
	s.channels["ch"] = st

	src := &endpointConn{role: tunnelv1.Role_client}
	st.conns = map[tunnelv1.Role]*endpointConn{
		tunnelv1.Role_client: src,
	}

	frame := []byte{1, 2, 3, 4, 5}
	_, _, err := s.routeOrBuffer("ch", tunnelv1.Role_client, src, frame)
	if err == nil {
		t.Fatalf("expected pending overflow")
	}
}

func TestRouteOrBufferGlobalPendingOverflow(t *testing.T) {
	obs := &testObserver{}
	s := &Server{
		cfg:               Config{MaxPendingBytes: 1024, MaxTotalQueuedBytes: 4, MaxRecordBytes: 1 << 20},
		obs:               obs,
		channels:          make(map[string]*channelState),
		resourceObs:       observability.NoopTunnelResourceObserver,
		tenantQueuedBytes: make(map[string]int64),
	}

	st := &channelState{conns: make(map[tunnelv1.Role]*endpointConn)}
	s.channels["ch"] = st
	src := &endpointConn{role: tunnelv1.Role_client, server: s, tenantKey: "tenant"}
	st.conns = map[tunnelv1.Role]*endpointConn{tunnelv1.Role_client: src}

	frame := []byte{1, 2, 3}
	_, _, err := s.routeOrBuffer("ch", tunnelv1.Role_client, src, frame)
	if err != nil {
		t.Fatalf("routeOrBuffer failed: %v", err)
	}
	_, _, err = s.routeOrBuffer("ch", tunnelv1.Role_client, src, frame)
	if err == nil {
		t.Fatalf("expected global pending overflow")
	}
}

func TestQueuedByteBudgetsAreTenantScopedAndGlobal(t *testing.T) {
	s := &Server{
		cfg:               Config{MaxTenantQueuedBytes: 4, MaxTotalQueuedBytes: 6},
		resourceObs:       observability.NoopTunnelResourceObserver,
		tenantQueuedBytes: make(map[string]int64),
	}
	if !s.tryReserveQueuedBytes("tenant-a", 4) {
		t.Fatal("expected tenant-a reservation")
	}
	if s.tryReserveQueuedBytes("tenant-a", 1) {
		t.Fatal("expected tenant budget exhaustion")
	}
	if !s.tryReserveQueuedBytes("tenant-b", 2) {
		t.Fatal("expected tenant-b reservation")
	}
	if s.tryReserveQueuedBytes("tenant-c", 1) {
		t.Fatal("expected global budget exhaustion")
	}
	s.releaseQueuedBytes("tenant-a", 4)
	if !s.tryReserveQueuedBytes("tenant-c", 1) {
		t.Fatal("expected capacity after release")
	}
}

func TestWriteQueueBytesReleaseAfterWriteCompletion(t *testing.T) {
	s := &Server{
		cfg:               Config{MaxTenantQueuedBytes: 4, MaxTotalQueuedBytes: 4},
		resourceObs:       observability.NoopTunnelResourceObserver,
		tenantQueuedBytes: make(map[string]int64),
	}
	ep := newEndpointConn(tunnelv1.Role_client, "eid", &websocket.Conn{})
	ep.server = s
	ep.tenantKey = "tenant"
	done, err := ep.enqueueWrite([]byte("abcd"), 4)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.totalQueuedBytes; got != 4 {
		t.Fatalf("queued bytes = %d", got)
	}
	req, err := ep.nextWrite()
	if err != nil {
		t.Fatal(err)
	}
	ep.finishWrite(req, nil)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := s.totalQueuedBytes; got != 0 {
		t.Fatalf("queued bytes after finish = %d", got)
	}
}

func TestEndpointWritePumpLifecycleRestartsWithoutDroppingFrames(t *testing.T) {
	s := &Server{
		cfg:               Config{MaxTenantQueuedBytes: 8, MaxTotalQueuedBytes: 8},
		resourceObs:       observability.NoopTunnelResourceObserver,
		tenantQueuedBytes: make(map[string]int64),
	}
	ep := newEndpointConn(tunnelv1.Role_client, "eid", &websocket.Conn{})
	ep.server = s
	ep.tenantKey = "tenant"

	drain := func(frames ...string) {
		t.Helper()
		done := make([]<-chan error, 0, len(frames))
		for _, frame := range frames {
			ch, err := ep.enqueueWrite([]byte(frame), 8)
			if err != nil {
				t.Fatalf("enqueueWrite(%q) failed: %v", frame, err)
			}
			done = append(done, ch)
		}
		if !ep.claimWritePump() {
			t.Fatal("expected queued frames to start a write pump")
		}
		if ep.claimWritePump() {
			t.Fatal("expected only one active write pump")
		}
		for i, want := range frames {
			req, err := ep.nextWrite()
			if err != nil {
				t.Fatalf("nextWrite(%d) failed: %v", i, err)
			}
			if got := string(req.frame); got != want {
				t.Fatalf("frame %d = %q, want %q", i, got, want)
			}
			ep.finishWrite(req, nil)
		}
		if _, err := ep.nextWrite(); !errors.Is(err, errWriteQueueIdle) {
			t.Fatalf("nextWrite after drain = %v, want %v", err, errWriteQueueIdle)
		}
		for i, ch := range done {
			if err := <-ch; err != nil {
				t.Fatalf("completion %d failed: %v", i, err)
			}
		}
		ep.outMu.Lock()
		running := ep.outRunning
		queuedBytes := ep.outBytes
		ep.outMu.Unlock()
		if running || queuedBytes != 0 {
			t.Fatalf("writer state after drain: running=%v queued_bytes=%d", running, queuedBytes)
		}
		if got := s.totalQueuedBytes; got != 0 {
			t.Fatalf("total queued bytes after drain = %d", got)
		}
		if got := s.tenantQueuedBytes["tenant"]; got != 0 {
			t.Fatalf("tenant queued bytes after drain = %d", got)
		}
	}

	drain("a", "b")
	drain("c", "d")
	ep.closeWriteQueue(nil)
	if got := s.totalQueuedBytes; got != 0 {
		t.Fatalf("total queued bytes after close = %d", got)
	}
}

func TestEndpointConnEnqueueWriteWaitsForCapacityAndUnblocksOnClose(t *testing.T) {
	ep := newEndpointConn(tunnelv1.Role_client, "eid", &websocket.Conn{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := ep.enqueueWrite([]byte("ab"), 2); err != nil {
			t.Errorf("enqueue first failed: %v", err)
			return
		}
		if _, err := ep.enqueueWrite([]byte("cd"), 2); err == nil {
			t.Errorf("expected second enqueue to block or fail on close")
		}
	}()

	select {
	case <-done:
		t.Fatalf("expected enqueue to block until close")
	case <-time.After(50 * time.Millisecond):
	}

	ep.closeWriteQueue(errWriteQueueClosed)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("enqueue did not unblock after close")
	}
}

func TestEndpointConnCloseWriteQueueDeliversStickyError(t *testing.T) {
	ep := newEndpointConn(tunnelv1.Role_client, "eid", &websocket.Conn{})
	done1, err := ep.enqueueWrite([]byte("a"), 10)
	if err != nil {
		t.Fatalf("enqueue first: %v", err)
	}
	done2, err := ep.enqueueWrite([]byte("b"), 10)
	if err != nil {
		t.Fatalf("enqueue second: %v", err)
	}

	ep.closeWriteQueue(errors.New("closed"))
	if err := <-done1; err == nil || err.Error() != "closed" {
		t.Fatalf("expected sticky close error on first waiter, got %v", err)
	}
	if err := <-done2; err == nil || err.Error() != "closed" {
		t.Fatalf("expected sticky close error on second waiter, got %v", err)
	}
}

func TestRouteOrBufferEncrypted(t *testing.T) {
	obs := &testObserver{}
	s := &Server{cfg: Config{MaxPendingBytes: 0, MaxRecordBytes: 1 << 20}, obs: obs, channels: make(map[string]*channelState)}

	st := &channelState{conns: make(map[tunnelv1.Role]*endpointConn)}
	s.channels["ch"] = st
	src := &endpointConn{role: tunnelv1.Role_client}
	dst := &endpointConn{role: tunnelv1.Role_server}
	st.conns = map[tunnelv1.Role]*endpointConn{
		tunnelv1.Role_client: src,
		tunnelv1.Role_server: dst,
	}

	frame := make([]byte, 4+1+1+8+4)
	copy(frame[:4], []byte(e2ee.RecordMagic))
	frame[4] = e2ee.ProtocolVersion
	frame[5] = 0
	frame[14] = 0
	frame[15] = 0
	frame[16] = 0
	frame[17] = 0
	if !e2ee.LooksLikeRecordFrame(frame, s.cfg.MaxRecordBytes) {
		t.Fatalf("expected frame to look like a record")
	}

	_, _, err := s.routeOrBuffer("ch", tunnelv1.Role_client, src, frame)
	if err != nil {
		t.Fatalf("routeOrBuffer failed: %v", err)
	}
	if !st.sawRecord {
		t.Fatalf("expected channel to be marked as having seen a record frame")
	}
	if obs.encrypted != 1 {
		t.Fatalf("expected observer encrypted count 1, got %d", obs.encrypted)
	}
}

func TestRouteOrBufferDoesNotMarkEncryptedOnHandshakeFrame(t *testing.T) {
	obs := &testObserver{}
	s := &Server{cfg: Config{MaxPendingBytes: 0, MaxRecordBytes: 1 << 20}, obs: obs, channels: make(map[string]*channelState)}

	st := &channelState{conns: make(map[tunnelv1.Role]*endpointConn)}
	s.channels["ch"] = st
	src := &endpointConn{role: tunnelv1.Role_client}
	dst := &endpointConn{role: tunnelv1.Role_server}
	st.conns = map[tunnelv1.Role]*endpointConn{
		tunnelv1.Role_client: src,
		tunnelv1.Role_server: dst,
	}

	// Minimal "looks like" handshake frame: FSEH + version + type + zero payload length.
	frame := make([]byte, 4+1+1+4)
	copy(frame[:4], []byte(e2ee.HandshakeMagic))
	frame[4] = e2ee.ProtocolVersion
	frame[5] = e2ee.HandshakeTypeInit
	frame[6] = 0
	frame[7] = 0
	frame[8] = 0
	frame[9] = 0
	if !e2ee.LooksLikeHandshakeFrame(frame, s.cfg.MaxRecordBytes) {
		t.Fatalf("expected frame to look like a handshake")
	}

	_, _, err := s.routeOrBuffer("ch", tunnelv1.Role_client, src, frame)
	if err != nil {
		t.Fatalf("routeOrBuffer failed: %v", err)
	}
	if st.sawRecord {
		t.Fatalf("expected handshake frame to not mark channel as having seen a record")
	}
	if obs.encrypted != 0 {
		t.Fatalf("expected observer encrypted count 0, got %d", obs.encrypted)
	}
}

func TestCleanupLoopClosesExpiredChannels(t *testing.T) {
	obs := &testObserver{}
	s := &Server{
		cfg:      Config{CleanupInterval: 5 * time.Millisecond},
		obs:      obs,
		used:     NewTokenUseCache(),
		channels: make(map[string]*channelState),
		stopCh:   make(chan struct{}),
	}

	s.channels["expired"] = &channelState{
		id:         "expired",
		initExp:    time.Now().Add(-time.Second).Unix(),
		lastActive: time.Now(),
		conns:      make(map[tunnelv1.Role]*endpointConn),
	}
	s.channels["idle"] = &channelState{
		id:          "idle",
		initExp:     time.Now().Add(time.Second).Unix(),
		idleTimeout: 5 * time.Millisecond,
		lastActive:  time.Now().Add(-time.Second),
		conns:       make(map[tunnelv1.Role]*endpointConn),
		sawRecord:   true,
	}

	done := make(chan struct{})
	go func() {
		s.cleanupLoop()
		close(done)
	}()

	deadline := time.Now().Add(200 * time.Millisecond)
	for {
		if s.Stats().ChannelCount == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected channels to be cleaned up")
		}
		time.Sleep(5 * time.Millisecond)
	}

	s.Close()
	<-done

	obs.mu.Lock()
	closeCount := len(obs.closes)
	obs.mu.Unlock()
	if closeCount == 0 {
		t.Fatalf("expected close reasons to be recorded")
	}
}

func TestCleanupLoopDoesNotCloseInitExpiredWithinSkew(t *testing.T) {
	obs := &testObserver{}
	s := &Server{
		cfg:      Config{CleanupInterval: 5 * time.Millisecond, ClockSkew: 30 * time.Second},
		obs:      obs,
		used:     NewTokenUseCache(),
		channels: make(map[string]*channelState),
		stopCh:   make(chan struct{}),
	}

	s.channels["skewed"] = &channelState{
		id:         "skewed",
		initExp:    time.Now().Add(-time.Second).Unix(),
		lastActive: time.Now(),
		conns:      make(map[tunnelv1.Role]*endpointConn),
	}

	done := make(chan struct{})
	go func() {
		s.cleanupLoop()
		close(done)
	}()

	// Give the cleanup loop time to run at least once.
	time.Sleep(50 * time.Millisecond)

	if got := s.Stats().ChannelCount; got != 1 {
		t.Fatalf("expected channel to remain within skew window, got %d", got)
	}

	s.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for cleanup loop to stop")
	}
}

func TestWriteFrameHonorsWriteTimeoutAgainstBlackhole(t *testing.T) {
	s := &Server{cfg: Config{WriteTimeout: 50 * time.Millisecond}}
	c, cleanup := newBlackholeWebSocketConn(t)
	defer cleanup()

	dst := &endpointConn{ws: c}
	err := s.writeFrame(dst, []byte("hello"))
	if err == nil {
		t.Fatal("expected write timeout error")
	}
	ne, ok := err.(interface{ Timeout() bool })
	if !ok || !ne.Timeout() {
		t.Fatalf("expected timeout error, got %T: %v", err, err)
	}
}

func newBlackholeWebSocketConn(t *testing.T) (*websocket.Conn, func()) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()

		br := bufio.NewReader(serverConn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		key := strings.TrimSpace(req.Header.Get("Sec-Websocket-Key"))
		if key == "" {
			return
		}
		sum := sha1.Sum([]byte(key + websocketGUID))
		accept := base64.StdEncoding.EncodeToString(sum[:])
		_, _ = fmt.Fprintf(serverConn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
		<-stop
	}()

	u, err := url.Parse("ws://example.invalid/ws")
	if err != nil {
		t.Fatalf("url.Parse failed: %v", err)
	}
	c, _, err := websocket.NewClient(clientConn, u, http.Header{}, 1024, 1024)
	if err != nil {
		_ = clientConn.Close()
		t.Fatalf("NewClient failed: %v", err)
	}
	cleanup := func() {
		_ = c.Close()
		_ = clientConn.Close()
		select {
		case <-stop:
		default:
			close(stop)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
	return c, cleanup
}

const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
