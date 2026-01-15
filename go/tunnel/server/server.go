package server

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flowersec/flowersec/controlplane/token"
	"github.com/flowersec/flowersec/crypto/e2ee"
	tunnelv1 "github.com/flowersec/flowersec/gen/flowersec/tunnel/v1"
	"github.com/flowersec/flowersec/realtime/ws"
	"github.com/flowersec/flowersec/tunnel/protocol"
	"github.com/gorilla/websocket"
)

type Config struct {
	Path            string // WebSocket endpoint path (e.g. "/ws").
	TunnelAudience  string // Expected token audience.
	TunnelIssuer    string // Expected token issuer.
	IssuerKeysFile  string // Path to JSON keyset with issuer public keys.
	MaxAttachBytes  int    // Max bytes for initial attach JSON.
	MaxRecordBytes  int    // Max bytes for tunneled record frames.
	MaxPendingBytes int    // Max bytes buffered before peer connects.
	MaxChannels     int    // Maximum active channels.
	MaxConns        int    // Maximum concurrent websocket connections.

	AllowedOrigins []string // Allowed Origin header values.
	AllowNoOrigin  bool     // Whether to allow empty Origin.

	IdleTimeout     time.Duration // Close channels idle beyond this duration.
	ClockSkew       time.Duration // Allowed clock skew for token validation.
	CleanupInterval time.Duration // Background cleanup cadence.

	ReplaceCooldown      time.Duration // Minimum interval between same-role replaces.
	ReplaceWindow        time.Duration // Sliding window for replace rate limiting.
	MaxReplacesPerWindow int           // Max replaces allowed per window.
	ReplaceCloseCode     int           // Close code for rate-limited replace.
}

// DefaultConfig returns conservative defaults for a tunnel server.
func DefaultConfig() Config {
	return Config{
		Path:                 "/ws",
		MaxAttachBytes:       8 * 1024,
		MaxRecordBytes:       1 << 20,
		MaxPendingBytes:      256 * 1024,
		MaxChannels:          2048,
		MaxConns:             4096,
		AllowNoOrigin:        true,
		IdleTimeout:          60 * time.Second,
		ClockSkew:            30 * time.Second,
		CleanupInterval:      500 * time.Millisecond,
		ReplaceWindow:        10 * time.Second,
		MaxReplacesPerWindow: 5,
		ReplaceCloseCode:     websocket.CloseTryAgainLater,
	}
}

// Server terminates websocket tunnels and routes frames between endpoints.
type Server struct {
	cfg Config // Immutable runtime configuration.

	keys *IssuerKeyset  // Issuer public keys for token verification.
	used *TokenUseCache // Token replay protection cache.

	mu       sync.Mutex               // Guards channel state.
	channels map[string]*channelState // Channel state by channel ID.

	connCount int64    // Current connection count.
	connSet   sync.Map // key: *websocket.Conn, value: struct{}

	stopOnce sync.Once     // Ensures shutdown only happens once.
	stopCh   chan struct{} // Signals background cleanup to stop.
}

// New validates config, loads the issuer keyset, and starts background cleanup.
func New(cfg Config) (*Server, error) {
	if cfg.Path == "" {
		cfg.Path = "/ws"
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
	if cfg.MaxChannels <= 0 {
		cfg.MaxChannels = 2048
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 4096
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 60 * time.Second
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 500 * time.Millisecond
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
	keys, err := LoadIssuerKeysetFile(cfg.IssuerKeysFile)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		keys:     keys,
		used:     NewTokenUseCache(),
		channels: make(map[string]*channelState),
		stopCh:   make(chan struct{}),
	}
	go s.cleanupLoop()
	return s, nil
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

type channelState struct {
	id         string                          // Channel identifier.
	initExp    int64                           // Channel init expiry (Unix seconds).
	encrypted  bool                            // Whether E2EE record frames observed.
	lastActive time.Time                       // Last activity timestamp.
	conns      map[tunnelv1.Role]*endpointConn // Active endpoints by role.
	replace    map[tunnelv1.Role]*replaceState // Replace rate-limit state by role.
}

type replaceState struct {
	last        time.Time // Last replacement time.
	windowStart time.Time // Current rate-limit window start.
	windowCount int       // Replacements within the current window.
}

type endpointConn struct {
	role tunnelv1.Role   // Endpoint role (client/server).
	eid  string          // Endpoint instance ID (base64url).
	ws   *websocket.Conn // Underlying websocket connection.

	writeMu      sync.Mutex // Serializes writes to the websocket.
	pending      [][]byte   // Buffered frames awaiting peer.
	pendingBytes int        // Total buffered bytes.
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	c, err := ws.Upgrade(w, r, ws.UpgraderOptions{
		CheckOrigin: s.checkOrigin,
	})
	if err != nil {
		return
	}
	uc := c.Underlying()
	if !s.trackConn(uc) {
		_ = c.CloseWithStatus(websocket.CloseTryAgainLater, "too many connections")
		return
	}

	// Read and validate the attach message.
	uc.SetReadLimit(int64(s.cfg.MaxAttachBytes))

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	mt, msg, err := c.ReadMessage(ctx)
	if err != nil || mt != websocket.TextMessage {
		_ = c.CloseWithStatus(websocket.CloseProtocolError, "expected attach")
		s.untrackConn(uc)
		return
	}
	attach, err := protocol.ParseAttachJSON(msg, protocol.AttachConstraints{
		MaxAttachBytes: s.cfg.MaxAttachBytes,
	})
	if err != nil {
		_ = c.CloseWithStatus(websocket.CloseProtocolError, "invalid attach")
		s.untrackConn(uc)
		return
	}

	// Verify the attach token and guard against replay.
	p, err := token.Verify(attach.Token, s.keys, token.VerifyOptions{
		Now:       time.Now(),
		Audience:  s.cfg.TunnelAudience,
		Issuer:    s.cfg.TunnelIssuer,
		ClockSkew: s.cfg.ClockSkew,
	})
	if err != nil {
		_ = c.CloseWithStatus(websocket.ClosePolicyViolation, "invalid token")
		s.untrackConn(uc)
		return
	}
	if p.ChannelID != attach.ChannelId {
		_ = c.CloseWithStatus(websocket.ClosePolicyViolation, "channel mismatch")
		s.untrackConn(uc)
		return
	}
	if uint8(attach.Role) != p.Role {
		_ = c.CloseWithStatus(websocket.ClosePolicyViolation, "role mismatch")
		s.untrackConn(uc)
		return
	}
	if !s.used.TryUse(p.TokenID, p.Exp, time.Now()) {
		_ = c.CloseWithStatus(websocket.ClosePolicyViolation, "token replay")
		s.untrackConn(uc)
		return
	}

	uc.SetReadLimit(int64(s.cfg.MaxRecordBytes))
	uc.SetReadDeadline(time.Time{})
	if err := s.addEndpoint(attach, p, uc); err != nil {
		if errors.Is(err, ErrReplaceRateLimited) {
			_ = c.CloseWithStatus(s.cfg.ReplaceCloseCode, "replace rate limited")
		} else {
			_ = c.CloseWithStatus(websocket.CloseInternalServerErr, "attach failed")
		}
		s.untrackConn(uc)
		return
	}
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
	var flushClientToServer [][]byte
	var flushServerToClient [][]byte
	var lockClient *endpointConn
	var lockServer *endpointConn
	now := time.Now()

	s.mu.Lock()
	st := s.channels[a.ChannelId]
	ep := &endpointConn{role: a.Role, eid: a.EndpointInstanceId, ws: uc}
	if st == nil {
		if s.cfg.MaxChannels > 0 && len(s.channels) >= s.cfg.MaxChannels {
			s.mu.Unlock()
			return errors.New("too many channels")
		}
		// First endpoint for the channel.
		st = &channelState{
			id:         a.ChannelId,
			initExp:    p.InitExp,
			lastActive: now,
			conns:      make(map[tunnelv1.Role]*endpointConn, 2),
		}
		st.conns[a.Role] = ep
		s.channels[a.ChannelId] = st
		startPump = true
		s.mu.Unlock()
	} else {
		if st.initExp != p.InitExp {
			s.mu.Unlock()
			return errors.New("init_exp mismatch")
		}
		if st.conns[a.Role] != nil {
			if !s.allowReplaceLocked(st, a.Role, now) {
				s.mu.Unlock()
				return ErrReplaceRateLimited
			}
			// Replacement semantics: close both sides and reset the channel state.
			replaceState := st.replace
			for _, e := range st.conns {
				toClose = append(toClose, e.ws)
			}
			delete(s.channels, a.ChannelId)
			st = &channelState{
				id:         a.ChannelId,
				initExp:    p.InitExp,
				lastActive: now,
				conns:      make(map[tunnelv1.Role]*endpointConn, 2),
				replace:    replaceState,
			}
			st.conns[a.Role] = ep
			s.channels[a.ChannelId] = st
			startPump = true
			s.mu.Unlock()
		} else {
			st.conns[a.Role] = ep
			st.lastActive = now
			startPump = true
			// If paired, flush buffered frames in a deterministic order while holding destination write locks.
			client := st.conns[tunnelv1.Role_client]
			server := st.conns[tunnelv1.Role_server]
			if client != nil && server != nil {
				lockClient, lockServer = client, server
				lockClient.writeMu.Lock()
				lockServer.writeMu.Lock()
				flushClientToServer = client.pending
				client.pending = nil
				client.pendingBytes = 0
				flushServerToClient = server.pending
				server.pending = nil
				server.pendingBytes = 0
			}
			s.mu.Unlock()
		}
	}

	for _, c := range toClose {
		_ = c.Close()
		s.untrackConn(c)
	}

	if startPump {
		go s.pump(a.ChannelId, a.Role, ep)
	}
	var flushErr error
	if lockClient != nil && lockServer != nil {
		if err := writeFramesLocked(lockServer, flushClientToServer); err != nil {
			flushErr = err
		}
		if err := writeFramesLocked(lockClient, flushServerToClient); err != nil && flushErr == nil {
			flushErr = err
		}
		lockServer.writeMu.Unlock()
		lockClient.writeMu.Unlock()
	}
	if flushErr != nil {
		s.closeChannel(a.ChannelId)
		return flushErr
	}
	return nil
}

// pump forwards frames from a source endpoint to its peer.
func (s *Server) pump(channelID string, role tunnelv1.Role, src *endpointConn) {
	for {
		mt, b, err := src.ws.ReadMessage()
		if err != nil {
			s.closeChannelFrom(channelID, role, src)
			return
		}
		if mt != websocket.BinaryMessage {
			s.closeChannelFrom(channelID, role, src)
			return
		}
		if s.cfg.MaxRecordBytes > 0 && len(b) > s.cfg.MaxRecordBytes {
			s.closeChannelFrom(channelID, role, src)
			return
		}

		dst, pendingToFlush, err := s.routeOrBuffer(channelID, role, b)
		if err != nil {
			s.closeChannelFrom(channelID, role, src)
			return
		}
		if dst == nil {
			continue
		}

		if len(pendingToFlush) > 0 {
			if err := writeFrames(dst, pendingToFlush); err != nil {
				s.closeChannelFrom(channelID, role, src)
				return
			}
		}
		if err := writeFrames(dst, [][]byte{b}); err != nil {
			s.closeChannelFrom(channelID, role, src)
			return
		}
	}
}

func writeFrames(dst *endpointConn, frames [][]byte) error {
	dst.writeMu.Lock()
	defer dst.writeMu.Unlock()
	for _, f := range frames {
		if err := dst.ws.WriteMessage(websocket.BinaryMessage, f); err != nil {
			return err
		}
	}
	return nil
}

func writeFramesLocked(dst *endpointConn, frames [][]byte) error {
	for _, f := range frames {
		if err := dst.ws.WriteMessage(websocket.BinaryMessage, f); err != nil {
			return err
		}
	}
	return nil
}

// routeOrBuffer returns a destination conn or buffers frames until paired.
func (s *Server) routeOrBuffer(channelID string, role tunnelv1.Role, frame []byte) (dst *endpointConn, flush [][]byte, err error) {
	now := time.Now()
	maxCipher := s.cfg.MaxRecordBytes

	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.channels[channelID]
	if st == nil {
		return nil, nil, errors.New("unknown channel")
	}
	st.lastActive = now
	if !st.encrypted && e2ee.LooksLikeRecordFrame(frame, maxCipher) {
		st.encrypted = true
	}
	src := st.conns[role]
	if src == nil {
		return nil, nil, errors.New("missing src")
	}
	var peerRole tunnelv1.Role
	if role == tunnelv1.Role_client {
		peerRole = tunnelv1.Role_server
	} else {
		peerRole = tunnelv1.Role_client
	}
	dst = st.conns[peerRole]
	if dst == nil {
		if s.cfg.MaxPendingBytes > 0 && src.pendingBytes+len(frame) > s.cfg.MaxPendingBytes {
			return nil, nil, errors.New("pending buffer overflow")
		}
		cpy := make([]byte, len(frame))
		copy(cpy, frame)
		src.pending = append(src.pending, cpy)
		src.pendingBytes += len(cpy)
		return nil, nil, nil
	}
	if len(src.pending) > 0 {
		flush = src.pending
		src.pending = nil
		src.pendingBytes = 0
	}
	return dst, flush, nil
}

// closeChannel closes both endpoints and removes channel state.
func (s *Server) closeChannel(channelID string) {
	var conns []*websocket.Conn
	s.mu.Lock()
	st := s.channels[channelID]
	if st != nil {
		for _, e := range st.conns {
			conns = append(conns, e.ws)
		}
		delete(s.channels, channelID)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
		s.untrackConn(c)
	}
}

// closeChannelFrom shuts down a channel when one endpoint fails.
func (s *Server) closeChannelFrom(channelID string, role tunnelv1.Role, src *endpointConn) {
	var conns []*websocket.Conn
	s.mu.Lock()
	st := s.channels[channelID]
	if st == nil || st.conns[role] != src {
		s.mu.Unlock()
		_ = src.ws.Close()
		s.untrackConn(src.ws)
		return
	}
	for _, e := range st.conns {
		conns = append(conns, e.ws)
	}
	delete(s.channels, channelID)
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
		s.untrackConn(c)
	}
}

// checkOrigin validates the Origin header against the allow-list.
func (s *Server) checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return s.cfg.AllowNoOrigin
	}
	for _, allowed := range s.cfg.AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

// trackConn increments the connection count and enforces MaxConns.
func (s *Server) trackConn(c *websocket.Conn) bool {
	if s.cfg.MaxConns > 0 {
		if atomic.AddInt64(&s.connCount, 1) > int64(s.cfg.MaxConns) {
			atomic.AddInt64(&s.connCount, -1)
			return false
		}
	} else {
		atomic.AddInt64(&s.connCount, 1)
	}
	s.connSet.Store(c, struct{}{})
	return true
}

// untrackConn decrements the connection count if tracked.
func (s *Server) untrackConn(c *websocket.Conn) {
	if _, ok := s.connSet.LoadAndDelete(c); !ok {
		return
	}
	atomic.AddInt64(&s.connCount, -1)
}

// cleanupLoop periodically expires idle and never-encrypted channels.
func (s *Server) cleanupLoop() {
	t := time.NewTicker(s.cfg.CleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			now := time.Now()
			s.used.Cleanup(now)

			var toClose []string
			s.mu.Lock()
			for id, st := range s.channels {
				if !st.encrypted && now.Unix() > st.initExp {
					toClose = append(toClose, id)
					continue
				}
				if s.cfg.IdleTimeout > 0 && now.Sub(st.lastActive) > s.cfg.IdleTimeout {
					toClose = append(toClose, id)
					continue
				}
			}
			s.mu.Unlock()
			for _, id := range toClose {
				s.closeChannel(id)
			}
		}
	}
}
