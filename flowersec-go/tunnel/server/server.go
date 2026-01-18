package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/controlplane/token"
	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	tunnelv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/timeutil"
	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/floegence/flowersec/flowersec-go/realtime/ws"
	"github.com/floegence/flowersec/flowersec-go/tunnel/protocol"
	"github.com/gorilla/websocket"
)

type Config struct {
	Path                 string // WebSocket endpoint path (e.g. "/ws").
	TunnelAudience       string // Expected token audience.
	TunnelIssuer         string // Expected token issuer.
	IssuerKeysFile       string // Path to JSON keyset with issuer public keys.
	MaxAttachBytes       int    // Max bytes for initial attach JSON.
	MaxRecordBytes       int    // Max bytes for tunneled record frames.
	MaxPendingBytes      int    // Max bytes buffered before peer connects.
	MaxTotalPendingBytes int    // Max total bytes buffered across all unpaired endpoints.
	MaxChannels          int    // Maximum active channels.
	MaxConns             int    // Maximum concurrent websocket connections.

	AllowedOrigins []string // Allowed Origin header values.
	AllowNoOrigin  bool     // Whether to allow empty Origin.

	IdleTimeout        time.Duration // Close channels idle beyond this duration.
	ClockSkew          time.Duration // Allowed clock skew for token validation.
	CleanupInterval    time.Duration // Background cleanup cadence.
	WriteTimeout       time.Duration // Per-frame websocket write deadline (0 disables).
	MaxWriteQueueBytes int           // Max buffered bytes for websocket writes per endpoint.

	ReplaceCooldown      time.Duration // Minimum interval between same-role replaces.
	ReplaceWindow        time.Duration // Sliding window for replace rate limiting.
	MaxReplacesPerWindow int           // Max replaces allowed per window.
	ReplaceCloseCode     int           // Close code for rate-limited replace.

	Observer observability.TunnelObserver // Optional tunnel metrics observer.
}

// DefaultConfig returns conservative defaults for a tunnel server.
func DefaultConfig() Config {
	return Config{
		Path:                 "/ws",
		MaxAttachBytes:       8 * 1024,
		MaxRecordBytes:       1 << 20,
		MaxPendingBytes:      256 * 1024,
		MaxTotalPendingBytes: 256 * 1024 * 1024,
		MaxChannels:          6000,
		MaxConns:             12000,
		AllowedOrigins:       nil,
		AllowNoOrigin:        false,
		IdleTimeout:          60 * time.Second,
		ClockSkew:            30 * time.Second,
		CleanupInterval:      500 * time.Millisecond,
		WriteTimeout:         10 * time.Second,
		MaxWriteQueueBytes:   1 << 20,
		ReplaceWindow:        10 * time.Second,
		MaxReplacesPerWindow: 5,
		ReplaceCloseCode:     websocket.CloseTryAgainLater,
		Observer:             observability.NoopTunnelObserver,
	}
}

// Server terminates websocket tunnels and routes frames between endpoints.
type Server struct {
	cfg Config // Immutable runtime configuration.

	keys *IssuerKeyset                // Issuer public keys for token verification.
	used *TokenUseCache               // Token replay protection cache.
	obs  observability.TunnelObserver // Metrics observer.

	mu       sync.Mutex               // Guards channel state.
	channels map[string]*channelState // Channel state by channel ID.

	connCount int64    // Current connection count.
	connSet   sync.Map // key: *websocket.Conn, value: struct{}

	totalPendingBytes int64 // Total buffered pending bytes across all channels.

	stopOnce sync.Once     // Ensures shutdown only happens once.
	stopCh   chan struct{} // Signals background cleanup to stop.
}

// Stats captures a snapshot of tunnel server counts.
type Stats struct {
	ConnCount    int64
	ChannelCount int
}

// New validates config, loads the issuer keyset, and starts background cleanup.
func New(cfg Config) (*Server, error) {
	if cfg.Path == "" {
		cfg.Path = "/ws"
	}
	if strings.TrimSpace(cfg.TunnelAudience) == "" {
		return nil, errors.New("missing tunnel audience")
	}
	if strings.TrimSpace(cfg.TunnelIssuer) == "" {
		return nil, errors.New("missing tunnel issuer")
	}
	if len(cfg.AllowedOrigins) == 0 {
		return nil, errors.New("missing allowed origins")
	}
	hasNonEmptyOrigin := false
	for _, o := range cfg.AllowedOrigins {
		if strings.TrimSpace(o) != "" {
			hasNonEmptyOrigin = true
			break
		}
	}
	if !hasNonEmptyOrigin {
		return nil, errors.New("missing allowed origins")
	}
	if cfg.MaxAttachBytes <= 0 {
		cfg.MaxAttachBytes = 8 * 1024
	}
	if cfg.MaxRecordBytes <= 0 {
		cfg.MaxRecordBytes = 1 << 20
	}
	if cfg.MaxPendingBytes <= 0 {
		cfg.MaxPendingBytes = 256 * 1024
	}
	if cfg.MaxTotalPendingBytes < 0 {
		cfg.MaxTotalPendingBytes = 0
	}
	if cfg.MaxChannels <= 0 {
		cfg.MaxChannels = 6000
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 12000
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 60 * time.Second
	}
	if cfg.ClockSkew < 0 {
		cfg.ClockSkew = 0
	}
	cfg.ClockSkew = timeutil.NormalizeSkew(cfg.ClockSkew)
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 500 * time.Millisecond
	}
	if cfg.WriteTimeout < 0 {
		cfg.WriteTimeout = 0
	}
	if cfg.MaxWriteQueueBytes <= 0 {
		cfg.MaxWriteQueueBytes = 1 << 20
	}
	if cfg.MaxWriteQueueBytes < cfg.MaxRecordBytes {
		return nil, errors.New("max write queue bytes must be >= max record bytes")
	}
	if cfg.ReplaceCooldown < 0 {
		cfg.ReplaceCooldown = 0
	}
	if cfg.ReplaceWindow < 0 {
		cfg.ReplaceWindow = 0
	}
	if cfg.MaxReplacesPerWindow < 0 {
		cfg.MaxReplacesPerWindow = 0
	}
	if cfg.ReplaceCloseCode == 0 {
		cfg.ReplaceCloseCode = websocket.CloseTryAgainLater
	}
	if cfg.Observer == nil {
		cfg.Observer = observability.NoopTunnelObserver
	}
	keys, err := LoadIssuerKeysetFile(cfg.IssuerKeysFile)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		keys:     keys,
		used:     NewTokenUseCache(),
		obs:      cfg.Observer,
		channels: make(map[string]*channelState),
		stopCh:   make(chan struct{}),
	}
	go s.cleanupLoop()
	return s, nil
}

// Stats returns a point-in-time view of connection and channel counts.
func (s *Server) Stats() Stats {
	connCount := atomic.LoadInt64(&s.connCount)
	s.mu.Lock()
	channelCount := len(s.channels)
	s.mu.Unlock()
	return Stats{ConnCount: connCount, ChannelCount: channelCount}
}

// ReloadKeys reloads the issuer keyset file on demand.
func (s *Server) ReloadKeys() error {
	keys, err := LoadIssuerKeysetFile(s.cfg.IssuerKeysFile)
	if err != nil {
		return err
	}
	s.keys.Replace(keys.keys)
	return nil
}

// Register installs the websocket and health endpoints on the mux.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc(s.cfg.Path, s.handleWS)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// Close stops background cleanup and prevents new work.
func (s *Server) Close() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

var ErrReplaceRateLimited = errors.New("replace rate limited")

var (
	errUnknownChannel   = errors.New("unknown channel")
	errMissingSrc       = errors.New("missing src")
	errPendingOverflow  = errors.New("pending buffer overflow")
	errWriteQueueClosed = errors.New("write queue closed")
)

type channelState struct {
	mu         sync.Mutex                      // Guards channel state.
	id         string                          // Channel identifier.
	initExp    int64                           // Channel init expiry (Unix seconds).
	sawRecord  bool                            // True once an E2EE record frame (FSEC) is observed.
	flushing   bool                            // True while pairing flush is in progress.
	firstSeen  time.Time                       // When the first endpoint arrived.
	lastActive time.Time                       // Last activity timestamp.
	conns      map[tunnelv1.Role]*endpointConn // Active endpoints by role.
	replace    map[tunnelv1.Role]*replaceState // Replace rate-limit state by role.
}

type replaceState struct {
	last        time.Time // Last replacement time.
	windowStart time.Time // Current rate-limit window start.
	windowCount int       // Replacements within the current window.
}

type writeReq struct {
	frame []byte
	done  chan error
}

type endpointConn struct {
	role tunnelv1.Role   // Endpoint role (client/server).
	eid  string          // Endpoint instance ID (base64url).
	ws   *websocket.Conn // Underlying websocket connection.

	pending      [][]byte // Buffered frames awaiting peer.
	pendingBytes int      // Total buffered bytes.

	outMu     sync.Mutex // Guards write queue state.
	outCond   *sync.Cond // Signals enqueue/dequeue events.
	outQueue  []writeReq // Pending frames to write.
	outHead   int        // Read cursor into outQueue.
	outBytes  int        // Buffered bytes in outQueue.
	outClosed bool       // True once the write queue is closed.
	outErr    error      // Sticky error for blocked writers.
}

func newEndpointConn(role tunnelv1.Role, eid string, ws *websocket.Conn) *endpointConn {
	ep := &endpointConn{role: role, eid: eid, ws: ws}
	ep.outCond = sync.NewCond(&ep.outMu)
	return ep
}

func (ep *endpointConn) closeWriteQueue(err error) {
	ep.outMu.Lock()
	if ep.outClosed {
		ep.outMu.Unlock()
		return
	}
	ep.outClosed = true
	closeErr := err
	if closeErr == nil {
		closeErr = errWriteQueueClosed
	}
	ep.outErr = closeErr
	for i := ep.outHead; i < len(ep.outQueue); i++ {
		req := ep.outQueue[i]
		ep.outQueue[i] = writeReq{}
		ep.outBytes -= len(req.frame)
		if req.done != nil {
			req.done <- closeErr
			close(req.done)
		}
	}
	ep.outQueue = nil
	ep.outHead = 0
	ep.outCond.Broadcast()
	ep.outMu.Unlock()
}

func (ep *endpointConn) enqueueWrite(frame []byte, maxBytes int) (<-chan error, error) {
	ep.outMu.Lock()
	defer ep.outMu.Unlock()
	if maxBytes > 0 && len(frame) > maxBytes {
		return nil, errors.New("frame exceeds write queue limit")
	}
	for !ep.outClosed && maxBytes > 0 && ep.outBytes+len(frame) > maxBytes {
		ep.outCond.Wait()
	}
	if ep.outClosed {
		if ep.outErr != nil {
			return nil, ep.outErr
		}
		return nil, errWriteQueueClosed
	}
	done := make(chan error, 1)
	ep.outQueue = append(ep.outQueue, writeReq{frame: frame, done: done})
	ep.outBytes += len(frame)
	ep.outCond.Signal()
	return done, nil
}

func (ep *endpointConn) nextWrite() (writeReq, error) {
	ep.outMu.Lock()
	defer ep.outMu.Unlock()
	for !ep.outClosed && ep.outHead >= len(ep.outQueue) {
		ep.outCond.Wait()
	}
	if ep.outHead >= len(ep.outQueue) {
		if ep.outErr != nil {
			return writeReq{}, ep.outErr
		}
		return writeReq{}, errWriteQueueClosed
	}
	req := ep.outQueue[ep.outHead]
	ep.outQueue[ep.outHead] = writeReq{}
	ep.outHead++
	if ep.outHead > 1024 && ep.outHead*2 > len(ep.outQueue) {
		ep.outQueue = append([]writeReq(nil), ep.outQueue[ep.outHead:]...)
		ep.outHead = 0
	}
	return req, nil
}

func (ep *endpointConn) finishWrite(req writeReq, err error) {
	ep.outMu.Lock()
	ep.outBytes -= len(req.frame)
	ep.outCond.Broadcast()
	ep.outMu.Unlock()

	if req.done != nil {
		req.done <- err
		close(req.done)
	}
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	c, err := ws.Upgrade(w, r, ws.UpgraderOptions{
		CheckOrigin: s.checkOrigin,
	})
	if err != nil {
		s.obs.Attach(observability.AttachResultFail, observability.AttachReasonUpgradeError)
		return
	}
	uc := c.Underlying()
	if !s.trackConn(uc) {
		s.obs.Attach(observability.AttachResultFail, observability.AttachReasonTooManyConnections)
		_ = c.CloseWithStatus(websocket.CloseTryAgainLater, "too many connections")
		return
	}

	// Read and validate the attach message.
	uc.SetReadLimit(int64(s.cfg.MaxAttachBytes))

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	mt, msg, err := c.ReadMessage(ctx)
	if err != nil || mt != websocket.TextMessage {
		s.obs.Attach(observability.AttachResultFail, observability.AttachReasonExpectedAttach)
		_ = c.CloseWithStatus(websocket.CloseProtocolError, "expected attach")
		s.untrackConn(uc)
		return
	}
	attach, err := protocol.ParseAttachWithConstraints(msg, protocol.AttachConstraints{
		MaxAttachBytes: s.cfg.MaxAttachBytes,
	})
	if err != nil {
		s.obs.Attach(observability.AttachResultFail, observability.AttachReasonInvalidAttach)
		_ = c.CloseWithStatus(websocket.CloseProtocolError, "invalid attach")
		s.untrackConn(uc)
		return
	}

	// Verify the attach token and guard against replay.
	now := time.Now()
	p, err := token.Verify(attach.Token, s.keys, token.VerifyOptions{
		Now:       now,
		Audience:  s.cfg.TunnelAudience,
		Issuer:    s.cfg.TunnelIssuer,
		ClockSkew: s.cfg.ClockSkew,
	})
	if err != nil {
		s.obs.Attach(observability.AttachResultFail, observability.AttachReasonInvalidToken)
		_ = c.CloseWithStatus(websocket.ClosePolicyViolation, "invalid token")
		s.untrackConn(uc)
		return
	}
	if p.ChannelID != attach.ChannelId {
		s.obs.Attach(observability.AttachResultFail, observability.AttachReasonChannelMismatch)
		_ = c.CloseWithStatus(websocket.ClosePolicyViolation, "channel mismatch")
		s.untrackConn(uc)
		return
	}
	if uint8(attach.Role) != p.Role {
		s.obs.Attach(observability.AttachResultFail, observability.AttachReasonRoleMismatch)
		_ = c.CloseWithStatus(websocket.ClosePolicyViolation, "role mismatch")
		s.untrackConn(uc)
		return
	}
	usedUntilUnix := addSkewUnix(p.Exp, s.cfg.ClockSkew)
	if !s.used.TryUse(p.TokenID, usedUntilUnix, now) {
		s.obs.Attach(observability.AttachResultFail, observability.AttachReasonTokenReplay)
		_ = c.CloseWithStatus(websocket.ClosePolicyViolation, "token replay")
		s.untrackConn(uc)
		return
	}

	uc.SetReadLimit(int64(s.cfg.MaxRecordBytes))
	uc.SetReadDeadline(time.Time{})
	if err := s.addEndpoint(attach, p, uc); err != nil {
		if errors.Is(err, ErrReplaceRateLimited) {
			s.obs.Attach(observability.AttachResultFail, observability.AttachReasonReplaceRateLimited)
			_ = c.CloseWithStatus(s.cfg.ReplaceCloseCode, "replace rate limited")
		} else {
			s.obs.Attach(observability.AttachResultFail, observability.AttachReasonAttachFailed)
			_ = c.CloseWithStatus(websocket.CloseInternalServerErr, "attach failed")
		}
		s.untrackConn(uc)
		return
	}
	s.obs.Attach(observability.AttachResultOK, observability.AttachReasonOK)
}

// allowReplaceLocked rate-limits same-role replacements to reduce DoS pressure.
func (s *Server) allowReplaceLocked(st *channelState, role tunnelv1.Role, now time.Time) bool {
	cooldown := s.cfg.ReplaceCooldown
	window := s.cfg.ReplaceWindow
	maxPerWindow := s.cfg.MaxReplacesPerWindow
	if cooldown <= 0 && (window <= 0 || maxPerWindow <= 0) {
		return true
	}
	if st.replace == nil {
		st.replace = make(map[tunnelv1.Role]*replaceState, 2)
	}
	rs := st.replace[role]
	if rs == nil {
		rs = &replaceState{}
		st.replace[role] = rs
	}
	if cooldown > 0 && !rs.last.IsZero() && now.Sub(rs.last) < cooldown {
		return false
	}
	if window > 0 && maxPerWindow > 0 {
		if rs.windowStart.IsZero() || now.Sub(rs.windowStart) >= window {
			rs.windowStart = now
			rs.windowCount = 0
		}
		if rs.windowCount >= maxPerWindow {
			return false
		}
	}
	rs.last = now
	if window > 0 && maxPerWindow > 0 {
		rs.windowCount++
	}
	return true
}

// addEndpoint registers the websocket for a channel and starts routing.
func (s *Server) addEndpoint(a *tunnelv1.Attach, p token.Payload, uc *websocket.Conn) error {
	var toClose []*websocket.Conn
	var startPump bool
	var pairLatency time.Duration
	var channelCount int
	var setChannelCount bool
	var replaceResult observability.ReplaceResult
	var setReplaceResult bool
	var paired bool
	var client *endpointConn
	var server *endpointConn
	var droppedPendingBytes int
	now := time.Now()

	ep := newEndpointConn(a.Role, a.EndpointInstanceId, uc)
	s.mu.Lock()
	st := s.channels[a.ChannelId]
	if st == nil {
		if s.cfg.MaxChannels > 0 && len(s.channels) >= s.cfg.MaxChannels {
			s.mu.Unlock()
			return errors.New("too many channels")
		}
		// First endpoint for the channel.
		st = &channelState{
			id:         a.ChannelId,
			initExp:    p.InitExp,
			firstSeen:  now,
			lastActive: now,
			conns:      make(map[tunnelv1.Role]*endpointConn, 2),
		}
		st.conns[a.Role] = ep
		s.channels[a.ChannelId] = st
		channelCount = len(s.channels)
		setChannelCount = true
		startPump = true
		s.mu.Unlock()
	} else {
		st.mu.Lock()
		if st.initExp != p.InitExp {
			st.mu.Unlock()
			s.mu.Unlock()
			return errors.New("init_exp mismatch")
		}
		if st.conns[a.Role] != nil {
			if !s.allowReplaceLocked(st, a.Role, now) {
				st.mu.Unlock()
				s.mu.Unlock()
				s.obs.Replace(observability.ReplaceResultRateLimited)
				return ErrReplaceRateLimited
			}
			// Replacement semantics: close both sides and reset the channel state.
			replaceState := st.replace
			for _, e := range st.conns {
				droppedPendingBytes += e.pendingBytes
				e.pending = nil
				e.pendingBytes = 0
				e.closeWriteQueue(nil)
				toClose = append(toClose, e.ws)
			}
			delete(s.channels, a.ChannelId)
			old := st
			st = &channelState{
				id:         a.ChannelId,
				initExp:    p.InitExp,
				firstSeen:  now,
				lastActive: now,
				conns:      make(map[tunnelv1.Role]*endpointConn, 2),
				replace:    replaceState,
			}
			st.conns[a.Role] = ep
			s.channels[a.ChannelId] = st
			replaceResult = observability.ReplaceResultOK
			setReplaceResult = true
			startPump = true
			old.mu.Unlock()
			s.mu.Unlock()
			s.subPendingBytes(droppedPendingBytes)
		} else {
			st.conns[a.Role] = ep
			st.lastActive = now
			startPump = true
			client = st.conns[tunnelv1.Role_client]
			server = st.conns[tunnelv1.Role_server]
			if client != nil && server != nil {
				pairLatency = now.Sub(st.firstSeen)
				st.flushing = true
				paired = true
			}
			st.mu.Unlock()
			s.mu.Unlock()
		}
	}

	if setReplaceResult {
		s.obs.Replace(replaceResult)
	}
	if setChannelCount {
		s.obs.ChannelCount(channelCount)
	}
	if pairLatency > 0 {
		s.obs.PairLatency(pairLatency)
	}

	for _, c := range toClose {
		_ = c.Close()
		s.untrackConn(c)
	}

	if startPump {
		go s.pump(a.ChannelId, a.Role, ep)
		go s.writePump(a.ChannelId, a.Role, ep)
	}
	if paired {
		if err := s.flushPending(st, client, server); err != nil {
			s.obs.Close(observability.CloseReasonWriteError)
			s.closeChannel(a.ChannelId)
			return err
		}
	}
	return nil
}

func (s *Server) flushPending(st *channelState, client *endpointConn, server *endpointConn) error {
	if st == nil || client == nil || server == nil {
		return nil
	}
	for {
		st.mu.Lock()
		pendingClient := client.pending
		pendingServer := server.pending
		pendingClientBytes := client.pendingBytes
		pendingServerBytes := server.pendingBytes
		recordNow := false
		if !st.sawRecord && looksLikeRecordPending(pendingClient, pendingServer, s.cfg.MaxRecordBytes) {
			st.sawRecord = true
			recordNow = true
		}
		if len(pendingClient) == 0 && len(pendingServer) == 0 {
			st.flushing = false
			st.mu.Unlock()
			return nil
		}
		client.pending = nil
		client.pendingBytes = 0
		server.pending = nil
		server.pendingBytes = 0
		st.mu.Unlock()
		s.subPendingBytes(pendingClientBytes + pendingServerBytes)
		if recordNow {
			s.obs.Encrypted()
		}

		var flushErr error
		if _, err := s.enqueueFrames(server, pendingClient); err != nil {
			flushErr = err
		}
		if _, err := s.enqueueFrames(client, pendingServer); err != nil && flushErr == nil {
			flushErr = err
		}
		if flushErr != nil {
			return flushErr
		}
	}
}

// pump forwards frames from a source endpoint to its peer.
func (s *Server) pump(channelID string, role tunnelv1.Role, src *endpointConn) {
	var lastWriteDone <-chan error
	for {
		mt, b, err := src.ws.ReadMessage()
		if err != nil {
			s.waitWriteDone(lastWriteDone)
			s.obs.Close(observability.CloseReasonPeerClosed)
			s.closeChannelFrom(channelID, role, src)
			return
		}
		if mt != websocket.BinaryMessage {
			s.waitWriteDone(lastWriteDone)
			s.obs.Close(observability.CloseReasonNonBinaryFrame)
			s.closeChannelFrom(channelID, role, src)
			return
		}
		if s.cfg.MaxRecordBytes > 0 && len(b) > s.cfg.MaxRecordBytes {
			s.waitWriteDone(lastWriteDone)
			s.obs.Close(observability.CloseReasonRecordTooLarge)
			s.closeChannelFrom(channelID, role, src)
			return
		}

		dst, pendingToFlush, err := s.routeOrBuffer(channelID, role, src, b)
		if err != nil {
			switch {
			case errors.Is(err, errUnknownChannel):
				s.obs.Close(observability.CloseReasonUnknownChannel)
			case errors.Is(err, errMissingSrc):
				s.obs.Close(observability.CloseReasonMissingSrc)
			case errors.Is(err, errPendingOverflow):
				s.obs.Close(observability.CloseReasonPendingOverflow)
			default:
				s.obs.Close(observability.CloseReasonPeerClosed)
			}
			s.closeChannelFrom(channelID, role, src)
			return
		}
		if dst == nil {
			continue
		}

		if len(pendingToFlush) > 0 {
			d, err := s.enqueueFrames(dst, pendingToFlush)
			if err != nil {
				s.obs.Close(observability.CloseReasonWriteError)
				s.closeChannelFrom(channelID, role, src)
				return
			}
			lastWriteDone = d
		}
		d, err := s.enqueueFrames(dst, [][]byte{b})
		if err != nil {
			s.obs.Close(observability.CloseReasonWriteError)
			s.closeChannelFrom(channelID, role, src)
			return
		}
		lastWriteDone = d
	}
}

func (s *Server) enqueueFrames(dst *endpointConn, frames [][]byte) (<-chan error, error) {
	var lastDone <-chan error
	for _, f := range frames {
		done, err := dst.enqueueWrite(f, s.cfg.MaxWriteQueueBytes)
		if err != nil {
			return nil, err
		}
		lastDone = done
	}
	return lastDone, nil
}

func (s *Server) writeFrame(dst *endpointConn, frame []byte) error {
	if s.cfg.WriteTimeout > 0 {
		_ = dst.ws.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
	} else {
		_ = dst.ws.SetWriteDeadline(time.Time{})
	}
	return dst.ws.WriteMessage(websocket.BinaryMessage, frame)
}

func (s *Server) writePump(channelID string, role tunnelv1.Role, dst *endpointConn) {
	for {
		req, err := dst.nextWrite()
		if err != nil {
			return
		}
		writeErr := s.writeFrame(dst, req.frame)
		dst.finishWrite(req, writeErr)
		if writeErr != nil {
			dst.closeWriteQueue(writeErr)
			s.obs.Close(observability.CloseReasonWriteError)
			s.closeChannelFrom(channelID, role, dst)
			return
		}
	}
}

func (s *Server) waitWriteDone(done <-chan error) {
	if done == nil {
		return
	}
	timeout := s.cfg.WriteTimeout
	if timeout <= 0 {
		timeout = 100 * time.Millisecond
	}
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

func looksLikeRecordPending(clientPending [][]byte, serverPending [][]byte, maxCipher int) bool {
	for _, frame := range clientPending {
		if looksLikeRecordFrame(frame, maxCipher) {
			return true
		}
	}
	for _, frame := range serverPending {
		if looksLikeRecordFrame(frame, maxCipher) {
			return true
		}
	}
	return false
}

func looksLikeRecordFrame(frame []byte, maxCipher int) bool {
	return e2ee.LooksLikeRecordFrame(frame, maxCipher)
}

// routeOrBuffer returns a destination conn or buffers frames until paired.
func (s *Server) routeOrBuffer(channelID string, role tunnelv1.Role, src *endpointConn, frame []byte) (dst *endpointConn, flush [][]byte, err error) {
	now := time.Now()
	maxCipher := s.cfg.MaxRecordBytes

	var recordNow bool
	s.mu.Lock()
	st := s.channels[channelID]
	if st == nil {
		s.mu.Unlock()
		return nil, nil, errUnknownChannel
	}
	st.mu.Lock()
	s.mu.Unlock()
	st.lastActive = now
	current := st.conns[role]
	if current == nil || current != src {
		st.mu.Unlock()
		if recordNow {
			s.obs.Encrypted()
		}
		return nil, nil, errMissingSrc
	}
	var peerRole tunnelv1.Role
	if role == tunnelv1.Role_client {
		peerRole = tunnelv1.Role_server
	} else {
		peerRole = tunnelv1.Role_client
	}
	dst = st.conns[peerRole]
	// Only treat the channel as having entered the encrypted data state once we observe
	// an E2EE record frame (FSEC). Handshake frames (FSEH) are intentionally excluded
	// so init_exp cleanup behavior matches the design contract.
	if !st.sawRecord && dst != nil && looksLikeRecordFrame(frame, maxCipher) {
		st.sawRecord = true
		recordNow = true
	}
	if dst == nil || st.flushing {
		if s.cfg.MaxPendingBytes > 0 && src.pendingBytes+len(frame) > s.cfg.MaxPendingBytes {
			st.mu.Unlock()
			if recordNow {
				s.obs.Encrypted()
			}
			return nil, nil, errPendingOverflow
		}
		if !s.tryAddPendingBytes(len(frame)) {
			st.mu.Unlock()
			if recordNow {
				s.obs.Encrypted()
			}
			return nil, nil, errPendingOverflow
		}
		cpy := make([]byte, len(frame))
		copy(cpy, frame)
		src.pending = append(src.pending, cpy)
		src.pendingBytes += len(cpy)
		st.mu.Unlock()
		if recordNow {
			s.obs.Encrypted()
		}
		return nil, nil, nil
	}
	if len(src.pending) > 0 {
		flush = src.pending
		flushBytes := src.pendingBytes
		src.pending = nil
		src.pendingBytes = 0
		s.subPendingBytes(flushBytes)
	}
	st.mu.Unlock()
	if recordNow {
		s.obs.Encrypted()
	}
	return dst, flush, nil
}

// closeChannel closes both endpoints and removes channel state.
func (s *Server) closeChannel(channelID string) {
	var conns []*websocket.Conn
	var channelCount int
	var removed bool
	var pendingBytes int
	s.mu.Lock()
	st := s.channels[channelID]
	if st != nil {
		st.mu.Lock()
		for _, e := range st.conns {
			pendingBytes += e.pendingBytes
			e.pending = nil
			e.pendingBytes = 0
			e.closeWriteQueue(nil)
			conns = append(conns, e.ws)
		}
		delete(s.channels, channelID)
		channelCount = len(s.channels)
		removed = true
		st.mu.Unlock()
	}
	s.mu.Unlock()
	s.subPendingBytes(pendingBytes)
	if removed {
		s.obs.ChannelCount(channelCount)
	}
	for _, c := range conns {
		_ = c.Close()
		s.untrackConn(c)
	}
}

// closeChannelFrom shuts down a channel when one endpoint fails.
func (s *Server) closeChannelFrom(channelID string, role tunnelv1.Role, src *endpointConn) {
	var conns []*websocket.Conn
	var channelCount int
	var pendingBytes int
	s.mu.Lock()
	st := s.channels[channelID]
	if st == nil {
		s.mu.Unlock()
		src.closeWriteQueue(nil)
		_ = src.ws.Close()
		s.untrackConn(src.ws)
		return
	}
	st.mu.Lock()
	if st.conns[role] != src {
		st.mu.Unlock()
		s.mu.Unlock()
		src.closeWriteQueue(nil)
		_ = src.ws.Close()
		s.untrackConn(src.ws)
		return
	}
	for _, e := range st.conns {
		pendingBytes += e.pendingBytes
		e.pending = nil
		e.pendingBytes = 0
		e.closeWriteQueue(nil)
		conns = append(conns, e.ws)
	}
	delete(s.channels, channelID)
	channelCount = len(s.channels)
	st.mu.Unlock()
	s.mu.Unlock()
	s.subPendingBytes(pendingBytes)
	s.obs.ChannelCount(channelCount)
	for _, c := range conns {
		_ = c.Close()
		s.untrackConn(c)
	}
}

func (s *Server) tryAddPendingBytes(n int) bool {
	if s.cfg.MaxTotalPendingBytes <= 0 || n <= 0 {
		return true
	}
	newTotal := atomic.AddInt64(&s.totalPendingBytes, int64(n))
	if newTotal > int64(s.cfg.MaxTotalPendingBytes) {
		atomic.AddInt64(&s.totalPendingBytes, -int64(n))
		return false
	}
	return true
}

func (s *Server) subPendingBytes(n int) {
	if s.cfg.MaxTotalPendingBytes <= 0 || n <= 0 {
		return
	}
	atomic.AddInt64(&s.totalPendingBytes, -int64(n))
}

// checkOrigin validates the Origin header against the allow-list.
func (s *Server) checkOrigin(r *http.Request) bool {
	return ws.IsOriginAllowed(r, s.cfg.AllowedOrigins, s.cfg.AllowNoOrigin)
}

// trackConn increments the connection count and enforces MaxConns.
func (s *Server) trackConn(c *websocket.Conn) bool {
	if s.cfg.MaxConns > 0 {
		newCount := atomic.AddInt64(&s.connCount, 1)
		if newCount > int64(s.cfg.MaxConns) {
			newCount = atomic.AddInt64(&s.connCount, -1)
			s.obs.ConnCount(newCount)
			return false
		}
		s.obs.ConnCount(newCount)
	} else {
		newCount := atomic.AddInt64(&s.connCount, 1)
		s.obs.ConnCount(newCount)
	}
	s.connSet.Store(c, struct{}{})
	return true
}

// untrackConn decrements the connection count if tracked.
func (s *Server) untrackConn(c *websocket.Conn) {
	if _, ok := s.connSet.LoadAndDelete(c); !ok {
		return
	}
	newCount := atomic.AddInt64(&s.connCount, -1)
	s.obs.ConnCount(newCount)
}

// cleanupLoop periodically expires idle channels and channels that never enter the encrypted data state.
func (s *Server) cleanupLoop() {
	t := time.NewTicker(s.cfg.CleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			now := time.Now()
			nowUnix := now.Unix()
			s.used.Cleanup(now)

			type closeTarget struct {
				id     string
				reason observability.CloseReason
			}
			var toClose []closeTarget
			s.mu.Lock()
			for id, st := range s.channels {
				st.mu.Lock()
				if !st.sawRecord && nowUnix > addSkewUnix(st.initExp, s.cfg.ClockSkew) {
					toClose = append(toClose, closeTarget{id: id, reason: observability.CloseReasonInitExpired})
					st.mu.Unlock()
					continue
				}
				if s.cfg.IdleTimeout > 0 && now.Sub(st.lastActive) > s.cfg.IdleTimeout {
					toClose = append(toClose, closeTarget{id: id, reason: observability.CloseReasonIdleTimeout})
					st.mu.Unlock()
					continue
				}
				st.mu.Unlock()
			}
			s.mu.Unlock()
			for _, target := range toClose {
				s.obs.Close(target.reason)
				s.closeChannel(target.id)
			}
		}
	}
}
