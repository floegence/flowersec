package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/floegence/flowersec/crypto/e2ee"
	tunnelv1 "github.com/floegence/flowersec/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/observability"
	"github.com/gorilla/websocket"
)

type testObserver struct {
	connCounts []int64
	encrypted  int
	closes     []observability.CloseReason
}

func (o *testObserver) ConnCount(n int64)  { o.connCounts = append(o.connCounts, n) }
func (o *testObserver) ChannelCount(_ int) {}
func (o *testObserver) Attach(_ observability.AttachResult, _ observability.AttachReason) {
}
func (o *testObserver) Replace(_ observability.ReplaceResult) {}
func (o *testObserver) Close(r observability.CloseReason)     { o.closes = append(o.closes, r) }
func (o *testObserver) PairLatency(_ time.Duration)           {}
func (o *testObserver) Encrypted()                            { o.encrypted++ }

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
	if !st.encrypted {
		t.Fatalf("expected channel to be marked encrypted")
	}
	if obs.encrypted != 1 {
		t.Fatalf("expected observer encrypted count 1, got %d", obs.encrypted)
	}
}

func TestCleanupLoopClosesExpiredChannels(t *testing.T) {
	obs := &testObserver{}
	s := &Server{
		cfg:      Config{CleanupInterval: 5 * time.Millisecond, IdleTimeout: 5 * time.Millisecond},
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
		id:         "idle",
		initExp:    time.Now().Add(time.Second).Unix(),
		lastActive: time.Now().Add(-time.Second),
		conns:      make(map[tunnelv1.Role]*endpointConn),
		encrypted:  true,
	}

	go s.cleanupLoop()
	time.Sleep(20 * time.Millisecond)
	close(s.stopCh)

	if len(s.channels) != 0 {
		t.Fatalf("expected channels to be cleaned up")
	}
	if len(obs.closes) == 0 {
		t.Fatalf("expected close reasons to be recorded")
	}
}
