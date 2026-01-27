package server

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
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
}

func (o *testObserver) ConnCount(n int64) {
	o.mu.Lock()
	o.connCounts = append(o.connCounts, n)
	o.mu.Unlock()
}
func (o *testObserver) ChannelCount(_ int) {}
func (o *testObserver) Attach(_ observability.AttachResult, _ observability.AttachReason) {
}
func (o *testObserver) Replace(_ observability.ReplaceResult) {}
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

func TestNewRejectsNegativeMaxTotalPendingBytes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TunnelAudience = "aud"
	cfg.TunnelIssuer = "iss"
	cfg.IssuerKeysFile = "does-not-matter.json"
	cfg.AllowedOrigins = []string{"https://ok"}
	cfg.MaxTotalPendingBytes = -1
	if _, err := New(cfg); err == nil {
		t.Fatalf("expected error for negative max total pending bytes")
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
		cfg:      Config{MaxPendingBytes: 1024, MaxTotalPendingBytes: 4, MaxRecordBytes: 1 << 20},
		obs:      obs,
		channels: make(map[string]*channelState),
	}

	st := &channelState{conns: make(map[tunnelv1.Role]*endpointConn)}
	s.channels["ch"] = st
	src := &endpointConn{role: tunnelv1.Role_client}
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
