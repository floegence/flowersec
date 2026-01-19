package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/floegence/flowersec/flowersec-go/controlplane/channelinit"
	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
	tunnelv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
	"github.com/floegence/flowersec/flowersec-go/rpc"
	"github.com/floegence/flowersec/flowersec-go/streamhello"
	"github.com/floegence/flowersec/flowersec-go/tunnel/server"
	"github.com/gorilla/websocket"
	hyamux "github.com/hashicorp/yamux"
)

const (
	modeAttachOnly    = "attach-only"
	modeHandshakeOnly = "handshake-only"
	modeFull          = "full"
)

type loadConfig struct {
	mode             string
	targetChannels   int
	ratePerSec       int
	rampStep         int
	rampInterval     time.Duration
	steadyDuration   time.Duration
	workers          int
	connTimeout      time.Duration
	reportInterval   time.Duration
	rpcTimeout       time.Duration
	maxHandshakeSize int
	maxRecordBytes   int
	maxBufferedBytes int

	maxConns        int
	maxChannels     int
	maxPendingBytes int
	idleTimeout     time.Duration
	cleanupInterval time.Duration
}

type connMetrics struct {
	wsOpen     time.Duration
	attachSend time.Duration
	pairReady  time.Duration
	handshake  time.Duration
	rpcCall    time.Duration
	completeAt time.Time
	errStage   string
}

type statsCollector struct {
	mu        sync.Mutex
	startedAt time.Time
	attempts  int
	success   int
	failure   int
	failures  map[string]int
	perSecond map[int64]int

	wsOpen     []int64
	attachSend []int64
	pairReady  []int64
	handshake  []int64
	rpcCall    []int64
}

type latencyStats struct {
	Count  int     `json:"count"`
	MinMs  float64 `json:"min_ms"`
	MaxMs  float64 `json:"max_ms"`
	MeanMs float64 `json:"mean_ms"`
	P50Ms  float64 `json:"p50_ms"`
	P95Ms  float64 `json:"p95_ms"`
	P99Ms  float64 `json:"p99_ms"`
}

type resourceStats struct {
	MaxHeapAlloc  uint64 `json:"max_heap_alloc_bytes"`
	MaxHeapInuse  uint64 `json:"max_heap_inuse_bytes"`
	MaxSysBytes   uint64 `json:"max_sys_bytes"`
	MaxGoroutines int    `json:"max_goroutines"`
}

type liveRegistry struct {
	mu     sync.Mutex
	close  []func()
	active int64
	peak   int64
}

type serverHandle struct {
	ready chan error
	close func()
}

type timingTransport struct {
	inner     e2ee.BinaryTransport
	firstRead atomic.Value
	firstOnce sync.Once
}

func (t *timingTransport) ReadBinary(ctx context.Context) ([]byte, error) {
	b, err := t.inner.ReadBinary(ctx)
	if err == nil {
		t.firstOnce.Do(func() {
			t.firstRead.Store(time.Now())
		})
	}
	return b, err
}

func (t *timingTransport) WriteBinary(ctx context.Context, b []byte) error {
	return t.inner.WriteBinary(ctx, b)
}

func (t *timingTransport) Close() error {
	return t.inner.Close()
}

func (t *timingTransport) FirstReadAt() (time.Time, bool) {
	v := t.firstRead.Load()
	if v == nil {
		return time.Time{}, false
	}
	ts, ok := v.(time.Time)
	return ts, ok && !ts.IsZero()
}

func main() {
	cfg := loadConfig{
		mode:             modeFull,
		targetChannels:   1000,
		ratePerSec:       200,
		rampStep:         0,
		rampInterval:     2 * time.Second,
		steadyDuration:   60 * time.Second,
		workers:          64,
		connTimeout:      10 * time.Second,
		reportInterval:   2 * time.Second,
		rpcTimeout:       5 * time.Second,
		maxHandshakeSize: 8 * 1024,
		maxRecordBytes:   1 << 20,
		maxBufferedBytes: 4 * (1 << 20),
		maxConns:         0,
		maxChannels:      0,
		maxPendingBytes:  256 * 1024,
		idleTimeout:      60 * time.Second,
		cleanupInterval:  50 * time.Millisecond,
	}

	flag.StringVar(&cfg.mode, "mode", cfg.mode, "load mode: attach-only | handshake-only | full")
	flag.IntVar(&cfg.targetChannels, "channels", cfg.targetChannels, "target channel count")
	flag.IntVar(&cfg.ratePerSec, "rate", cfg.ratePerSec, "connection attempts per second (0 = max)")
	flag.IntVar(&cfg.rampStep, "ramp-step", cfg.rampStep, "channels added per ramp step (0 = no ramp)")
	flag.DurationVar(&cfg.rampInterval, "ramp-interval", cfg.rampInterval, "time between ramp steps")
	flag.DurationVar(&cfg.steadyDuration, "steady", cfg.steadyDuration, "steady duration after reaching target")
	flag.IntVar(&cfg.workers, "workers", cfg.workers, "worker goroutines for connection setup")
	flag.DurationVar(&cfg.connTimeout, "conn-timeout", cfg.connTimeout, "per-connection timeout")
	flag.DurationVar(&cfg.reportInterval, "report-interval", cfg.reportInterval, "status report interval")
	flag.DurationVar(&cfg.rpcTimeout, "rpc-timeout", cfg.rpcTimeout, "RPC call timeout in full mode")
	flag.IntVar(&cfg.maxHandshakeSize, "max-handshake-bytes", cfg.maxHandshakeSize, "max handshake payload bytes")
	flag.IntVar(&cfg.maxRecordBytes, "max-record-bytes", cfg.maxRecordBytes, "max encrypted record bytes")
	flag.IntVar(&cfg.maxBufferedBytes, "max-buffered-bytes", cfg.maxBufferedBytes, "max buffered plaintext bytes")
	flag.IntVar(&cfg.maxConns, "max-conns", cfg.maxConns, "tunnel max websocket connections (0 = default)")
	flag.IntVar(&cfg.maxChannels, "max-channels", cfg.maxChannels, "tunnel max active channels (0 = default)")
	flag.IntVar(&cfg.maxPendingBytes, "max-pending-bytes", cfg.maxPendingBytes, "max pending bytes before peer connects")
	flag.DurationVar(&cfg.idleTimeout, "idle-timeout", cfg.idleTimeout, "tunnel idle timeout")
	flag.DurationVar(&cfg.cleanupInterval, "cleanup-interval", cfg.cleanupInterval, "tunnel cleanup interval")
	flag.Parse()

	if err := validateConfig(cfg); err != nil {
		log.Fatal(err)
	}

	logger := log.New(os.Stderr, "[loadgen] ", log.LstdFlags)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()

	iss, keyFile := mustTestIssuer()
	defer os.RemoveAll(filepath.Dir(keyFile))

	wsURL, closeTunnel, err := startTunnel(ctx, cfg, keyFile)
	if err != nil {
		log.Fatal(err)
	}
	defer closeTunnel()

	idleTimeoutSeconds := int32(0)
	if cfg.idleTimeout > 0 {
		idleTimeoutSeconds = int32(cfg.idleTimeout / time.Second)
		if idleTimeoutSeconds <= 0 {
			idleTimeoutSeconds = 1
		}
	}

	ci := &channelinit.Service{
		Issuer: iss,
		Params: channelinit.Params{
			TunnelURL:          wsURL,
			TunnelAudience:     "flowersec-tunnel:loadgen",
			IssuerID:           "issuer-loadgen",
			TokenExpSeconds:    60,
			IdleTimeoutSeconds: idleTimeoutSeconds,
		},
	}

	stats := &statsCollector{
		startedAt: time.Now(),
		failures:  make(map[string]int),
		perSecond: make(map[int64]int),
	}
	metricsCh := make(chan connMetrics, cfg.workers*4)
	doneStats := make(chan struct{})
	go func() {
		for m := range metricsCh {
			stats.add(m)
		}
		close(doneStats)
	}()

	live := &liveRegistry{}
	sampler := startResourceSampler(ctx, cfg.reportInterval)

	if cfg.reportInterval > 0 {
		go func() {
			ticker := time.NewTicker(cfg.reportInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					snap := stats.snapshotCounts()
					logger.Printf("attempts=%d success=%d failure=%d active=%d peak=%d",
						snap.attempts, snap.success, snap.failure,
						atomic.LoadInt64(&live.active), atomic.LoadInt64(&live.peak))
				}
			}
		}()
	}

	jobs := make(chan int, cfg.workers*2)
	var wg sync.WaitGroup
	for i := 0; i < cfg.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				m := runConnection(ctx, ci, wsURL, cfg, idx, live)
				metricsCh <- m
			}
		}()
	}

	total := scheduleJobs(ctx, cfg, jobs)
	wg.Wait()
	close(metricsCh)
	<-doneStats

	if cfg.steadyDuration > 0 && (cfg.mode == modeHandshakeOnly || cfg.mode == modeFull) {
		logger.Printf("steady hold for %s", cfg.steadyDuration)
		select {
		case <-ctx.Done():
		case <-time.After(cfg.steadyDuration):
		}
	}

	live.closeAll()
	cancel()

	output := buildOutput(cfg, total, stats, live, sampler)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(output); err != nil {
		log.Fatal(err)
	}
}

func validateConfig(cfg loadConfig) error {
	switch cfg.mode {
	case modeAttachOnly, modeHandshakeOnly, modeFull:
	default:
		return errors.New("invalid mode: " + cfg.mode)
	}
	if cfg.targetChannels <= 0 {
		return errors.New("channels must be > 0")
	}
	if cfg.workers <= 0 {
		return errors.New("workers must be > 0")
	}
	return nil
}

func scheduleJobs(ctx context.Context, cfg loadConfig, jobs chan<- int) int {
	defer close(jobs)
	idx := 0
	step := cfg.targetChannels
	if cfg.rampStep > 0 {
		step = cfg.rampStep
	}

	var ticker *time.Ticker
	if cfg.ratePerSec > 0 {
		interval := time.Second / time.Duration(cfg.ratePerSec)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	for idx < cfg.targetChannels {
		target := idx + step
		if target > cfg.targetChannels {
			target = cfg.targetChannels
		}
		for idx < target {
			if ticker != nil {
				select {
				case <-ctx.Done():
					return idx
				case <-ticker.C:
				}
			} else if ctx.Err() != nil {
				return idx
			}
			select {
			case <-ctx.Done():
				return idx
			case jobs <- idx:
				idx++
			}
		}
		if idx < cfg.targetChannels && cfg.rampInterval > 0 {
			select {
			case <-ctx.Done():
				return idx
			case <-time.After(cfg.rampInterval):
			}
		}
	}
	return idx
}

func runConnection(ctx context.Context, svc *channelinit.Service, wsURL string, cfg loadConfig, idx int, live *liveRegistry) connMetrics {
	out := connMetrics{}
	out.completeAt = time.Now()

	channelID := "chan_load_" + itoa(idx)
	grantC, grantS, err := svc.NewChannelInit(channelID)
	if err != nil {
		out.errStage = "channel_init"
		return out
	}
	psk, err := base64url.Decode(grantC.E2eePskB64u)
	if err != nil {
		out.errStage = "psk_decode"
		return out
	}

	serverHandle := startServerEndpoint(ctx, wsURL, grantS, psk, cfg)

	connCtx, cancel := context.WithTimeout(ctx, cfg.connTimeout)
	defer cancel()

	var wsConn *websocket.Conn
	var secure *e2ee.SecureChannel
	var sess *hyamux.Session
	keepOpen := false
	defer func() {
		if keepOpen {
			return
		}
		if sess != nil {
			_ = sess.Close()
		}
		if secure != nil {
			_ = secure.Close()
		}
		if wsConn != nil {
			_ = wsConn.Close()
		}
		serverHandle.close()
	}()

	wsStart := time.Now()
	c, _, err := dialTunnel(connCtx, wsURL)
	if err != nil {
		out.wsOpen = time.Since(wsStart)
		out.errStage = "ws_open"
		return out
	}
	wsConn = c
	out.wsOpen = time.Since(wsStart)

	attach := tunnelv1.Attach{
		V:                  1,
		ChannelId:          grantC.ChannelId,
		Role:               tunnelv1.Role_client,
		Token:              grantC.Token,
		EndpointInstanceId: randomEndpointID(),
	}
	attachStart := time.Now()
	b, _ := json.Marshal(attach)
	if err := c.WriteMessage(websocket.TextMessage, b); err != nil {
		out.attachSend = time.Since(attachStart)
		out.errStage = "attach_send"
		return out
	}
	attachEnd := time.Now()
	out.attachSend = attachEnd.Sub(attachStart)

	if cfg.mode == modeAttachOnly {
		serverErr := <-serverHandle.ready
		if serverErr != nil {
			out.errStage = "server_attach"
			return out
		}
		out.completeAt = time.Now()
		return out
	}

	transport := &timingTransport{inner: e2ee.NewWebSocketBinaryTransport(c)}
	hsStart := time.Now()
	secureConn, err := e2ee.ClientHandshake(connCtx, transport, e2ee.ClientHandshakeOptions{
		PSK:                 psk,
		Suite:               e2ee.Suite(grantC.DefaultSuite),
		ChannelID:           grantC.ChannelId,
		ClientFeatures:      0,
		MaxHandshakePayload: cfg.maxHandshakeSize,
		MaxRecordBytes:      cfg.maxRecordBytes,
		MaxBufferedBytes:    cfg.maxBufferedBytes,
	})
	if err != nil {
		out.handshake = time.Since(hsStart)
		out.errStage = "handshake"
		return out
	}
	secure = secureConn
	out.handshake = time.Since(hsStart)

	if ts, ok := transport.FirstReadAt(); ok && ts.After(attachEnd) {
		out.pairReady = ts.Sub(attachEnd)
	}

	serverErr := <-serverHandle.ready
	if serverErr != nil {
		out.errStage = "server_ready"
		return out
	}

	if cfg.mode == modeHandshakeOnly {
		out.completeAt = time.Now()
		live.add(func() {
			live.dec()
			_ = secure.Close()
			_ = wsConn.Close()
			serverHandle.close()
		})
		live.inc()
		keepOpen = true
		return out
	}

	ycfg := hyamux.DefaultConfig()
	ycfg.EnableKeepAlive = false
	ycfg.LogOutput = io.Discard
	sess, err = hyamux.Client(secure, ycfg)
	if err != nil {
		out.errStage = "yamux_client"
		return out
	}

	stream, err := sess.OpenStream()
	if err != nil {
		out.errStage = "yamux_open"
		return out
	}
	if err := streamhello.WriteStreamHello(stream, "rpc"); err != nil {
		_ = stream.Close()
		out.errStage = "rpc_hello"
		return out
	}
	client := rpc.NewClient(stream)
	callCtx, callCancel := context.WithTimeout(ctx, cfg.rpcTimeout)
	rpcStart := time.Now()
	_, _, err = client.Call(callCtx, 1, json.RawMessage(`{"ping":true}`))
	out.rpcCall = time.Since(rpcStart)
	callCancel()
	_ = client.Close()
	if err != nil {
		out.errStage = "rpc_call"
		return out
	}

	out.completeAt = time.Now()
	live.add(func() {
		live.dec()
		_ = sess.Close()
		_ = secure.Close()
		_ = wsConn.Close()
		serverHandle.close()
	})
	live.inc()
	keepOpen = true
	return out
}

func startServerEndpoint(ctx context.Context, wsURL string, grant *controlv1.ChannelInitGrant, psk []byte, cfg loadConfig) serverHandle {
	ready := make(chan error, 1)
	serverCtx, cancel := context.WithCancel(ctx)

	go func() {
		c, _, err := dialTunnel(serverCtx, wsURL)
		if err != nil {
			ready <- err
			return
		}
		defer c.Close()

		attach := tunnelv1.Attach{
			V:                  1,
			ChannelId:          grant.ChannelId,
			Role:               tunnelv1.Role_server,
			Token:              grant.Token,
			EndpointInstanceId: randomEndpointID(),
		}
		b, _ := json.Marshal(attach)
		if err := c.WriteMessage(websocket.TextMessage, b); err != nil {
			ready <- err
			return
		}

		if cfg.mode == modeAttachOnly {
			ready <- nil
			return
		}

		bt := e2ee.NewWebSocketBinaryTransport(c)
		cache := e2ee.NewServerHandshakeCache()
		secure, err := e2ee.ServerHandshake(serverCtx, bt, cache, e2ee.ServerHandshakeOptions{
			PSK:                 psk,
			Suite:               e2ee.Suite(grant.DefaultSuite),
			ChannelID:           grant.ChannelId,
			InitExpireAtUnixS:   grant.ChannelInitExpireAtUnixS,
			ClockSkew:           30 * time.Second,
			ServerFeatures:      1,
			MaxHandshakePayload: cfg.maxHandshakeSize,
			MaxRecordBytes:      cfg.maxRecordBytes,
			MaxBufferedBytes:    cfg.maxBufferedBytes,
		})
		if err != nil {
			ready <- err
			return
		}
		defer secure.Close()

		if cfg.mode == modeHandshakeOnly {
			ready <- nil
			<-serverCtx.Done()
			return
		}

		ycfg := hyamux.DefaultConfig()
		ycfg.EnableKeepAlive = false
		ycfg.LogOutput = io.Discard
		sess, err := hyamux.Server(secure, ycfg)
		if err != nil {
			ready <- err
			return
		}
		defer sess.Close()

		ready <- nil

		go func() {
			<-serverCtx.Done()
			sess.Close()
		}()

		for {
			stream, err := sess.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				defer stream.Close()
				h, err := streamhello.ReadStreamHello(stream, 8*1024)
				if err != nil || h.Kind != "rpc" {
					return
				}
				router := rpc.NewRouter()
				srv := rpc.NewServer(stream, router)
				router.Register(1, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
					_ = ctx
					_ = payload
					_ = srv.Notify(2, json.RawMessage(`{"hello":"world"}`))
					return json.RawMessage(`{"ok":true}`), nil
				})
				_ = srv.Serve(serverCtx)
			}()
		}
	}()

	return serverHandle{
		ready: ready,
		close: cancel,
	}
}

func (s *statsCollector) add(m connMetrics) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if m.errStage == "" {
		s.success++
		if m.wsOpen > 0 {
			s.wsOpen = append(s.wsOpen, m.wsOpen.Nanoseconds())
		}
		if m.attachSend > 0 {
			s.attachSend = append(s.attachSend, m.attachSend.Nanoseconds())
		}
		if m.pairReady > 0 {
			s.pairReady = append(s.pairReady, m.pairReady.Nanoseconds())
		}
		if m.handshake > 0 {
			s.handshake = append(s.handshake, m.handshake.Nanoseconds())
		}
		if m.rpcCall > 0 {
			s.rpcCall = append(s.rpcCall, m.rpcCall.Nanoseconds())
		}
		s.perSecond[m.completeAt.Unix()]++
		return
	}
	s.failure++
	s.failures[m.errStage]++
}

type statsSnapshot struct {
	attempts int
	success  int
	failure  int

	failures  map[string]int
	perSecond map[int64]int

	wsOpen     []int64
	attachSend []int64
	pairReady  []int64
	handshake  []int64
	rpcCall    []int64
}

func (s *statsCollector) snapshotCounts() statsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return statsSnapshot{
		attempts: s.attempts,
		success:  s.success,
		failure:  s.failure,
	}
}

func buildOutput(cfg loadConfig, total int, stats *statsCollector, live *liveRegistry, sampler *resourceStats) map[string]any {
	snap := stats.export()
	duration := time.Since(stats.startedAt)
	successRate := 0.0
	if snap.attempts > 0 {
		successRate = float64(snap.success) / float64(snap.attempts)
	}
	maxPerSec := 0
	for _, v := range snap.perSecond {
		if v > maxPerSec {
			maxPerSec = v
		}
	}
	config := map[string]any{
		"mode":                cfg.mode,
		"channels":            cfg.targetChannels,
		"rate_per_sec":        cfg.ratePerSec,
		"ramp_step":           cfg.rampStep,
		"ramp_interval_ms":    cfg.rampInterval.Milliseconds(),
		"steady_duration_ms":  cfg.steadyDuration.Milliseconds(),
		"workers":             cfg.workers,
		"conn_timeout_ms":     cfg.connTimeout.Milliseconds(),
		"report_interval_ms":  cfg.reportInterval.Milliseconds(),
		"rpc_timeout_ms":      cfg.rpcTimeout.Milliseconds(),
		"max_handshake_bytes": cfg.maxHandshakeSize,
		"max_record_bytes":    cfg.maxRecordBytes,
		"max_buffered_bytes":  cfg.maxBufferedBytes,
		"max_conns":           cfg.maxConns,
		"max_channels":        cfg.maxChannels,
		"max_pending_bytes":   cfg.maxPendingBytes,
		"idle_timeout_ms":     cfg.idleTimeout.Milliseconds(),
		"cleanup_interval_ms": cfg.cleanupInterval.Milliseconds(),
	}
	out := map[string]any{
		"config": config,
		"summary": map[string]any{
			"attempts":          snap.attempts,
			"success":           snap.success,
			"failure":           snap.failure,
			"success_rate":      successRate,
			"duration_seconds":  duration.Seconds(),
			"peak_conn_per_sec": maxPerSec,
			"active_peak":       atomic.LoadInt64(&live.peak),
			"target_channels":   total,
		},
		"failures": snap.failures,
		"latency": map[string]latencyStats{
			"ws_open":     computeLatency(snap.wsOpen),
			"attach_send": computeLatency(snap.attachSend),
			"pair_ready":  computeLatency(snap.pairReady),
			"handshake":   computeLatency(snap.handshake),
			"rpc_call":    computeLatency(snap.rpcCall),
		},
		"resources": sampler,
		"env": map[string]any{
			"go_version": runtime.Version(),
			"gomaxprocs": runtime.GOMAXPROCS(0),
		},
	}
	return out
}

func (s *statsCollector) export() statsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := statsSnapshot{
		attempts: s.attempts,
		success:  s.success,
		failure:  s.failure,

		failures:  make(map[string]int, len(s.failures)),
		perSecond: make(map[int64]int, len(s.perSecond)),

		wsOpen:     append([]int64(nil), s.wsOpen...),
		attachSend: append([]int64(nil), s.attachSend...),
		pairReady:  append([]int64(nil), s.pairReady...),
		handshake:  append([]int64(nil), s.handshake...),
		rpcCall:    append([]int64(nil), s.rpcCall...),
	}
	for k, v := range s.failures {
		cp.failures[k] = v
	}
	for k, v := range s.perSecond {
		cp.perSecond[k] = v
	}
	return cp
}

func computeLatency(samples []int64) latencyStats {
	if len(samples) == 0 {
		return latencyStats{}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	min := samples[0]
	max := samples[len(samples)-1]
	var sum int64
	for _, v := range samples {
		sum += v
	}
	mean := float64(sum) / float64(len(samples))
	return latencyStats{
		Count:  len(samples),
		MinMs:  nsToMs(min),
		MaxMs:  nsToMs(max),
		MeanMs: mean / 1e6,
		P50Ms:  nsToMs(percentile(samples, 0.50)),
		P95Ms:  nsToMs(percentile(samples, 0.95)),
		P99Ms:  nsToMs(percentile(samples, 0.99)),
	}
}

func percentile(samples []int64, p float64) int64 {
	if len(samples) == 0 {
		return 0
	}
	if p <= 0 {
		return samples[0]
	}
	if p >= 1 {
		return samples[len(samples)-1]
	}
	rank := int(float64(len(samples)-1) * p)
	return samples[rank]
}

func nsToMs(ns int64) float64 {
	return float64(ns) / 1e6
}

func (l *liveRegistry) add(closeFn func()) {
	l.mu.Lock()
	l.close = append(l.close, closeFn)
	l.mu.Unlock()
}

func (l *liveRegistry) closeAll() {
	l.mu.Lock()
	fns := append([]func(){}, l.close...)
	l.close = nil
	l.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

func (l *liveRegistry) inc() {
	v := atomic.AddInt64(&l.active, 1)
	for {
		cur := atomic.LoadInt64(&l.peak)
		if v <= cur {
			return
		}
		if atomic.CompareAndSwapInt64(&l.peak, cur, v) {
			return
		}
	}
}

func (l *liveRegistry) dec() {
	atomic.AddInt64(&l.active, -1)
}

func startResourceSampler(ctx context.Context, interval time.Duration) *resourceStats {
	stats := &resourceStats{}
	if interval <= 0 {
		return stats
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				stats.MaxHeapAlloc = maxU64(stats.MaxHeapAlloc, ms.HeapAlloc)
				stats.MaxHeapInuse = maxU64(stats.MaxHeapInuse, ms.HeapInuse)
				stats.MaxSysBytes = maxU64(stats.MaxSysBytes, ms.Sys)
				if g := runtime.NumGoroutine(); g > stats.MaxGoroutines {
					stats.MaxGoroutines = g
				}
			}
		}
	}()
	return stats
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func startTunnel(ctx context.Context, cfg loadConfig, keyFile string) (string, func(), error) {
	tunnelCfg := server.DefaultConfig()
	tunnelCfg.IssuerKeysFile = keyFile
	tunnelCfg.TunnelAudience = "flowersec-tunnel:loadgen"
	tunnelCfg.TunnelIssuer = "issuer-loadgen"
	tunnelCfg.AllowedOrigins = []string{"https://app.redeven.com"}
	if cfg.maxConns > 0 {
		tunnelCfg.MaxConns = cfg.maxConns
	}
	if cfg.maxChannels > 0 {
		tunnelCfg.MaxChannels = cfg.maxChannels
	}
	if cfg.maxRecordBytes > 0 {
		tunnelCfg.MaxRecordBytes = cfg.maxRecordBytes
	}
	if cfg.maxPendingBytes > 0 {
		tunnelCfg.MaxPendingBytes = cfg.maxPendingBytes
	}
	if cfg.cleanupInterval > 0 {
		tunnelCfg.CleanupInterval = cfg.cleanupInterval
	}

	tun, err := server.New(tunnelCfg)
	if err != nil {
		return "", nil, err
	}

	mux := http.NewServeMux()
	tun.Register(mux)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("tunnel serve error: %v", err)
		}
	}()

	closeFn := func() {
		tun.Close()
		shutdownHTTPServer(ctx, srv)
		_ = ln.Close()
	}

	wsURL := "ws://" + ln.Addr().String() + tunnelCfg.Path
	return wsURL, closeFn, nil
}

func shutdownHTTPServer(ctx context.Context, srv *http.Server) {
	stopCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(stopCtx)
}

func mustTestIssuer() (*issuer.Keyset, string) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	priv := ed25519.NewKeyFromSeed(seed)
	ks, err := issuer.New("k1", priv)
	if err != nil {
		panic(err)
	}
	b, err := ks.ExportTunnelKeyset()
	if err != nil {
		panic(err)
	}
	dir, err := os.MkdirTemp("", "flowersec-issuer-*")
	if err != nil {
		panic(err)
	}
	p := filepath.Join(dir, "issuer_keys.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		panic(err)
	}
	_, _ = rand.Read(make([]byte, 1))
	return ks, p
}

func randomEndpointID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64url.Encode(b)
}

func dialTunnel(ctx context.Context, wsURL string) (*websocket.Conn, *http.Response, error) {
	h := http.Header{}
	h.Set("Origin", "https://app.redeven.com")
	return websocket.DefaultDialer.DialContext(ctx, wsURL, h)
}

func itoa(v int) string {
	return strconv.Itoa(v)
}
