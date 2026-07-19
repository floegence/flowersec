package main

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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

	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/controlplane/channelinit"
	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
	fsyamux "github.com/floegence/flowersec/flowersec-go/mux/yamux"
	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/floegence/flowersec/flowersec-go/rpc"
	"github.com/floegence/flowersec/flowersec-go/tunnel/server"
)

const (
	loadgenOrigin          = "https://app.redeven.com"
	streamBenchmarkKind    = "loadgen.stream"
	defaultStreamBytes     = 16 << 20
	defaultFairStreamBytes = 2 << 20
	defaultFairStreams     = 8
	streamBenchmarkSamples = 3
	streamResourceInterval = 10 * time.Millisecond
)

type loadConfig struct {
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
	streamBytes      int
	fairStreamBytes  int
	fairStreams      int

	maxConns        int
	maxChannels     int
	maxPendingBytes int
	idleTimeout     time.Duration
	cleanupInterval time.Duration
}

func (c loadConfig) livenessOptions() fsyamux.LivenessOptions {
	if c.idleTimeout <= 0 {
		return fsyamux.LivenessOptions{}
	}
	interval := c.idleTimeout / 2
	if interval < 500*time.Millisecond {
		interval = 500 * time.Millisecond
	}
	if interval >= c.idleTimeout {
		interval = c.idleTimeout / 2
	}
	return fsyamux.LivenessOptions{Interval: interval, Timeout: min(10*time.Second, interval)}
}

type connMetrics struct {
	connectTotal time.Duration
	wsOpen       time.Duration
	handshake    time.Duration
	rpcCall      time.Duration
	completeAt   time.Time
	errStage     string
}

type statsCollector struct {
	mu        sync.Mutex
	startedAt time.Time
	attempts  int
	success   int
	failure   int
	failures  map[string]int
	perSecond map[int64]int

	connectTotal []int64
	wsOpen       []int64
	handshake    []int64
	rpcCall      []int64
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
	mu                   sync.Mutex
	done                 chan struct{}
	MaxHeapAlloc         uint64 `json:"max_heap_alloc_bytes"`
	MaxHeapInuse         uint64 `json:"max_heap_inuse_bytes"`
	MaxSysBytes          uint64 `json:"max_sys_bytes"`
	MaxGoroutines        int    `json:"max_goroutines"`
	BaselineGoroutines   int    `json:"baseline_goroutines"`
	SteadyGoroutines     int    `json:"steady_state_goroutines"`
	AfterCloseGoroutines int    `json:"after_close_goroutines"`
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

type serverResourceOwner struct {
	mu      sync.Mutex
	closed  bool
	cancel  context.CancelFunc
	session endpoint.Session
}

func (o *serverResourceOwner) setSession(session endpoint.Session) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return false
	}
	o.session = session
	return true
}

func (o *serverResourceOwner) close() {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return
	}
	o.closed = true
	cancel := o.cancel
	session := o.session
	o.mu.Unlock()

	cancel()
	if session != nil {
		_ = session.Close()
	}
}

type connectionObserver struct {
	mu        sync.Mutex
	wsOpen    time.Duration
	handshake time.Duration
}

func (o *connectionObserver) OnConnect(_ client.Path, result observability.ConnectResult, _ observability.ConnectReason, elapsed time.Duration) {
	if result == observability.ConnectResultOK {
		o.mu.Lock()
		o.wsOpen = elapsed
		o.mu.Unlock()
	}
}

func (o *connectionObserver) OnAttach(observability.AttachResult, observability.AttachReason) {}

func (o *connectionObserver) OnHandshake(_ client.Path, result observability.HandshakeResult, _ client.Code, elapsed time.Duration) {
	if result == observability.HandshakeResultOK {
		o.mu.Lock()
		o.handshake = elapsed
		o.mu.Unlock()
	}
}

func (o *connectionObserver) OnDiagnosticEvent(observability.DiagnosticEvent) {}

func (o *connectionObserver) snapshot() (time.Duration, time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.wsOpen, o.handshake
}

type streamingMetrics struct {
	Bytes                        int       `json:"bytes"`
	BackgroundConnections        int       `json:"background_connections"`
	ThroughputMiBPerSec          float64   `json:"throughput_mib_per_sec"`
	ThroughputSamplesMiBPerSec   []float64 `json:"throughput_samples_mib_per_sec"`
	TTFBMilliseconds             float64   `json:"ttfb_ms"`
	TTFBSamplesMilliseconds      []float64 `json:"ttfb_samples_ms"`
	TransferMilliseconds         float64   `json:"transfer_ms"`
	ConcurrentStreams            int       `json:"concurrent_streams"`
	FairStreamBytes              int       `json:"fair_stream_bytes"`
	FairnessCompletionMS         []float64 `json:"fairness_completion_ms"`
	FairnessMedianMilliseconds   float64   `json:"fairness_median_ms"`
	FairnessSlowestMilliseconds  float64   `json:"fairness_slowest_ms"`
	FairnessSlowestToMedianRatio float64   `json:"fairness_slowest_to_median_ratio"`
}

func main() {
	cfg := loadConfig{
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
		streamBytes:      defaultStreamBytes,
		fairStreamBytes:  defaultFairStreamBytes,
		fairStreams:      defaultFairStreams,
		maxConns:         0,
		maxChannels:      0,
		maxPendingBytes:  256 * 1024,
		idleTimeout:      60 * time.Second,
		cleanupInterval:  50 * time.Millisecond,
	}

	flag.IntVar(&cfg.targetChannels, "channels", cfg.targetChannels, "target channel count")
	flag.IntVar(&cfg.ratePerSec, "rate", cfg.ratePerSec, "connection attempts per second (0 = max)")
	flag.IntVar(&cfg.rampStep, "ramp-step", cfg.rampStep, "channels added per ramp step (0 = no ramp)")
	flag.DurationVar(&cfg.rampInterval, "ramp-interval", cfg.rampInterval, "time between ramp steps")
	flag.DurationVar(&cfg.steadyDuration, "steady", cfg.steadyDuration, "steady duration after reaching target")
	flag.IntVar(&cfg.workers, "workers", cfg.workers, "worker goroutines for connection setup")
	flag.DurationVar(&cfg.connTimeout, "conn-timeout", cfg.connTimeout, "per-connection timeout")
	flag.DurationVar(&cfg.reportInterval, "report-interval", cfg.reportInterval, "status report interval")
	flag.DurationVar(&cfg.rpcTimeout, "rpc-timeout", cfg.rpcTimeout, "RPC call timeout")
	flag.IntVar(&cfg.maxHandshakeSize, "max-handshake-bytes", cfg.maxHandshakeSize, "max handshake payload bytes")
	flag.IntVar(&cfg.maxRecordBytes, "max-record-bytes", cfg.maxRecordBytes, "max encrypted record bytes")
	flag.IntVar(&cfg.maxBufferedBytes, "max-buffered-bytes", cfg.maxBufferedBytes, "max buffered plaintext bytes")
	flag.IntVar(&cfg.streamBytes, "stream-benchmark-bytes", cfg.streamBytes, "single-stream transfer size")
	flag.IntVar(&cfg.fairStreamBytes, "fair-stream-bytes", cfg.fairStreamBytes, "bytes transferred by each fairness stream")
	flag.IntVar(&cfg.fairStreams, "fair-streams", cfg.fairStreams, "equal-size concurrent streams used for fairness")
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
	sampler := startResourceSampler(ctx, cfg.reportInterval, runtime.NumGoroutine())

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
				m := runConnection(ctx, ci, cfg, idx, live)
				metricsCh <- m
			}
		}()
	}

	total := scheduleJobs(ctx, cfg, jobs)
	wg.Wait()
	close(metricsCh)
	<-doneStats

	backgroundConnections := int(atomic.LoadInt64(&live.active))
	streaming, err := runStreamingBenchmark(ctx, ci, cfg, sampler.sample)
	if err != nil {
		log.Fatalf("stream benchmark failed: %v", err)
	}
	streaming.BackgroundConnections = backgroundConnections
	sampler.sample()

	if cfg.steadyDuration > 0 {
		logger.Printf("steady hold for %s", cfg.steadyDuration)
		select {
		case <-ctx.Done():
		case <-time.After(cfg.steadyDuration):
		}
	}
	sampler.captureSteadyState()

	live.closeAll()
	afterCloseGoroutines := waitForGoroutineBaseline(sampler.BaselineGoroutines, 5*time.Second)
	sampler.mu.Lock()
	sampler.AfterCloseGoroutines = afterCloseGoroutines
	sampler.mu.Unlock()
	cancel()
	<-sampler.done

	output := buildOutput(cfg, total, stats, live, sampler, streaming)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(output); err != nil {
		log.Fatal(err)
	}
}

func validateConfig(cfg loadConfig) error {
	if cfg.targetChannels <= 0 {
		return errors.New("channels must be > 0")
	}
	if cfg.workers <= 0 {
		return errors.New("workers must be > 0")
	}
	if cfg.streamBytes <= 0 {
		return errors.New("stream-benchmark-bytes must be > 0")
	}
	if cfg.fairStreamBytes <= 0 {
		return errors.New("fair-stream-bytes must be > 0")
	}
	if cfg.fairStreams <= 0 {
		return errors.New("fair-streams must be > 0")
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

func runConnection(ctx context.Context, svc *channelinit.Service, cfg loadConfig, idx int, live *liveRegistry) connMetrics {
	out := connMetrics{completeAt: time.Now()}
	grantC, grantS, err := svc.NewChannelInit("chan_load_" + itoa(idx))
	if err != nil {
		out.errStage = "channel_init"
		return out
	}

	serverHandle := startServerEndpoint(ctx, grantS, cfg)
	keepOpen := false
	var cli client.Client
	defer func() {
		if keepOpen {
			return
		}
		if cli != nil {
			_ = cli.Close()
		}
		serverHandle.close()
	}()

	connCtx, cancel := context.WithTimeout(ctx, cfg.connTimeout)
	defer cancel()
	observer := &connectionObserver{}
	connectStart := time.Now()
	cli, err = client.Connect(connCtx, grantC, clientConnectOptions(cfg, observer)...)
	out.connectTotal = time.Since(connectStart)
	out.wsOpen, out.handshake = observer.snapshot()
	if err != nil {
		out.errStage = connectErrorStage(err)
		return out
	}
	if err := <-serverHandle.ready; err != nil {
		out.errStage = "server_connect"
		return out
	}

	callCtx, callCancel := context.WithTimeout(ctx, cfg.rpcTimeout)
	rpcStart := time.Now()
	_, _, err = cli.RPC().Call(callCtx, 1, json.RawMessage(`{"ping":true}`))
	out.rpcCall = time.Since(rpcStart)
	callCancel()
	if err != nil {
		out.errStage = "rpc_call"
		return out
	}

	out.completeAt = time.Now()
	live.add(func() {
		live.dec()
		_ = cli.Close()
		serverHandle.close()
	})
	live.inc()
	keepOpen = true
	return out
}

func clientConnectOptions(cfg loadConfig, observer observability.ClientObserver) []client.ConnectOption {
	options := []client.ConnectOption{
		client.WithOrigin(loadgenOrigin),
		client.WithConnectTimeout(cfg.connTimeout),
		client.WithHandshakeTimeout(cfg.connTimeout),
		client.WithMaxHandshakePayload(cfg.maxHandshakeSize),
		client.WithMaxRecordBytes(cfg.maxRecordBytes),
		client.WithMaxBufferedBytes(cfg.maxBufferedBytes),
		client.WithTransportSecurityPolicy(client.AllowPlaintextForLoopback),
		client.WithObserver(observer),
	}
	if liveness := cfg.livenessOptions(); liveness.Interval > 0 && liveness.Timeout > 0 {
		options = append(options, client.WithLiveness(liveness))
	} else {
		options = append(options, client.WithLivenessDisabled())
	}
	return options
}

func endpointConnectOptions(cfg loadConfig) []endpoint.ConnectOption {
	options := []endpoint.ConnectOption{
		endpoint.WithOrigin(loadgenOrigin),
		endpoint.WithConnectTimeout(cfg.connTimeout),
		endpoint.WithHandshakeTimeout(cfg.connTimeout),
		endpoint.WithMaxHandshakePayload(cfg.maxHandshakeSize),
		endpoint.WithMaxRecordBytes(cfg.maxRecordBytes),
		endpoint.WithMaxBufferedBytes(cfg.maxBufferedBytes),
		endpoint.WithTransportSecurityPolicy(endpoint.AllowPlaintextForLoopback),
	}
	if liveness := cfg.livenessOptions(); liveness.Interval > 0 && liveness.Timeout > 0 {
		options = append(options, endpoint.WithLiveness(liveness))
	} else {
		options = append(options, endpoint.WithLivenessDisabled())
	}
	return options
}

func connectErrorStage(err error) string {
	var flowersecErr *client.Error
	if errors.As(err, &flowersecErr) && flowersecErr.Stage != "" {
		return string(flowersecErr.Stage)
	}
	return "connect"
}

func startServerEndpoint(ctx context.Context, grant *controlv1.ChannelInitGrant, cfg loadConfig) serverHandle {
	ready := make(chan error, 1)
	serverCtx, cancel := context.WithCancel(ctx)
	owner := &serverResourceOwner{cancel: cancel}

	go func() {
		session, err := endpoint.ConnectTunnel(serverCtx, grant, endpointConnectOptions(cfg)...)
		if err != nil {
			ready <- err
			return
		}
		if !owner.setSession(session) {
			_ = session.Close()
			ready <- context.Canceled
			return
		}
		ready <- nil
		_ = session.ServeStreams(serverCtx, endpoint.DefaultMaxStreamHelloBytes, func(kind string, stream io.ReadWriteCloser) {
			handleServerStream(serverCtx, kind, stream, max(cfg.streamBytes, cfg.fairStreamBytes))
		})
	}()

	return serverHandle{ready: ready, close: owner.close}
}

func handleServerStream(ctx context.Context, kind string, stream io.ReadWriteCloser, maxStreamBytes int) {
	switch kind {
	case "rpc":
		serveRPC(ctx, stream)
	case streamBenchmarkKind:
		_ = serveStreamingResponse(stream, maxStreamBytes)
	}
}

func serveRPC(ctx context.Context, stream io.ReadWriteCloser) {
	router := rpc.NewRouter()
	srv := rpc.NewServer(stream, router)
	router.Register(1, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
		_ = ctx
		_ = payload
		_ = srv.Notify(2, json.RawMessage(`{"hello":"world"}`))
		return json.RawMessage(`{"ok":true}`), nil
	})
	_ = srv.Serve(ctx)
}

func serveStreamingResponse(stream io.ReadWriter, maxStreamBytes int) error {
	var requested uint64
	if err := binary.Read(stream, binary.BigEndian, &requested); err != nil {
		return err
	}
	if requested == 0 || requested > uint64(maxStreamBytes) {
		return fmt.Errorf("invalid stream benchmark size %d", requested)
	}
	chunk := make([]byte, 64*1024)
	remaining := int64(requested)
	for remaining > 0 {
		n := min(int64(len(chunk)), remaining)
		if _, err := stream.Write(chunk[:n]); err != nil {
			return err
		}
		remaining -= n
	}
	return nil
}

func runStreamingBenchmark(ctx context.Context, svc *channelinit.Service, cfg loadConfig, sampleResources func()) (streamingMetrics, error) {
	grantC, grantS, err := svc.NewChannelInit("chan_stream_benchmark")
	if err != nil {
		return streamingMetrics{}, err
	}
	serverHandle := startServerEndpoint(ctx, grantS, cfg)
	defer serverHandle.close()

	connectCtx, cancel := context.WithTimeout(ctx, cfg.connTimeout)
	defer cancel()
	cli, err := client.Connect(connectCtx, grantC, clientConnectOptions(cfg, observability.NoopClientObserver)...)
	if err != nil {
		return streamingMetrics{}, err
	}
	defer cli.Close()
	if err := <-serverHandle.ready; err != nil {
		return streamingMetrics{}, err
	}

	callCtx, callCancel := context.WithTimeout(ctx, cfg.rpcTimeout)
	_, rpcErr, err := cli.RPC().Call(callCtx, 1, json.RawMessage(`{"benchmark":true}`))
	callCancel()
	if err != nil {
		return streamingMetrics{}, err
	}
	if rpcErr != nil {
		return streamingMetrics{}, fmt.Errorf("stream benchmark RPC bootstrap failed: %v", rpcErr.Message)
	}

	benchmarkTimeout := 30 * time.Second
	if cfg.rpcTimeout > benchmarkTimeout {
		benchmarkTimeout = cfg.rpcTimeout
	}
	benchmarkCtx, benchmarkCancel := context.WithTimeout(ctx, benchmarkTimeout)
	defer benchmarkCancel()
	if err := runStreamingMemoryProbe(
		benchmarkCtx,
		cli,
		cfg.fairStreamBytes,
		cfg.fairStreams,
		sampleResources,
	); err != nil {
		return streamingMetrics{}, err
	}

	transferDurations := make([]time.Duration, streamBenchmarkSamples)
	ttfbDurations := make([]time.Duration, streamBenchmarkSamples)
	for i := 0; i < streamBenchmarkSamples; i++ {
		transferDuration, ttfb, err := measureStreamingResponse(benchmarkCtx, cli, cfg.streamBytes)
		if err != nil {
			return streamingMetrics{}, err
		}
		transferDurations[i] = transferDuration
		ttfbDurations[i] = ttfb
	}

	fairDurations, err := measureConcurrentStreamingResponses(
		benchmarkCtx,
		cli,
		cfg.fairStreamBytes,
		cfg.fairStreams,
	)
	if err != nil {
		return streamingMetrics{}, err
	}

	sortedTransfers := append([]time.Duration(nil), transferDurations...)
	sort.Slice(sortedTransfers, func(i, j int) bool { return sortedTransfers[i] < sortedTransfers[j] })
	sortedTTFB := append([]time.Duration(nil), ttfbDurations...)
	sort.Slice(sortedTTFB, func(i, j int) bool { return sortedTTFB[i] < sortedTTFB[j] })
	metrics := newStreamingMetrics(cfg.streamBytes, medianDuration(sortedTransfers), medianDuration(sortedTTFB), fairDurations)
	metrics.ThroughputSamplesMiBPerSec = make([]float64, len(transferDurations))
	metrics.TTFBSamplesMilliseconds = make([]float64, len(ttfbDurations))
	for i := range transferDurations {
		metrics.ThroughputSamplesMiBPerSec[i] = (float64(cfg.streamBytes) / (1024 * 1024)) / transferDurations[i].Seconds()
		metrics.TTFBSamplesMilliseconds[i] = float64(ttfbDurations[i]) / float64(time.Millisecond)
	}
	metrics.FairStreamBytes = cfg.fairStreamBytes
	return metrics, nil
}

func runStreamingMemoryProbe(
	ctx context.Context,
	cli client.Client,
	streamBytes int,
	streams int,
	sampleResources func(),
) error {
	stopSampling := startStreamingResourceProbe(streamResourceInterval, sampleResources)
	defer stopSampling()
	_, err := measureConcurrentStreamingResponses(ctx, cli, streamBytes, streams)
	return err
}

func startStreamingResourceProbe(interval time.Duration, sampleResources func()) func() {
	if sampleResources == nil {
		return func() {}
	}
	sampleResources()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				sampleResources()
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		sampleResources()
	}
}

func measureConcurrentStreamingResponses(
	ctx context.Context,
	cli client.Client,
	streamBytes int,
	streams int,
) ([]time.Duration, error) {
	durations := make([]time.Duration, streams)
	errCh := make(chan error, streams)
	var wg sync.WaitGroup
	var ready sync.WaitGroup
	ready.Add(streams)
	start := make(chan struct{})
	var epoch time.Time
	for i := range durations {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			ready.Done()
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			case <-start:
			}
			_, _, err := measureStreamingResponse(ctx, cli, streamBytes)
			if err != nil {
				errCh <- err
				return
			}
			durations[index] = time.Since(epoch)
		}(i)
	}
	ready.Wait()
	epoch = time.Now()
	close(start)
	wg.Wait()
	close(errCh)
	if err := <-errCh; err != nil {
		return nil, err
	}
	return durations, nil
}

func measureStreamingResponse(ctx context.Context, cli client.Client, size int) (time.Duration, time.Duration, error) {
	started := time.Now()
	stream, err := cli.OpenStream(ctx, streamBenchmarkKind)
	if err != nil {
		return 0, 0, err
	}
	defer stream.Close()
	stopReset := make(chan struct{})
	defer close(stopReset)
	go func() {
		select {
		case <-ctx.Done():
			_ = stream.Reset()
		case <-stopReset:
		}
	}()
	if err := binary.Write(stream, binary.BigEndian, uint64(size)); err != nil {
		return 0, 0, err
	}
	var first [1]byte
	if _, err := io.ReadFull(stream, first[:]); err != nil {
		return 0, 0, err
	}
	ttfb := time.Since(started)
	if _, err := io.CopyN(io.Discard, stream, int64(size-1)); err != nil {
		return 0, 0, err
	}
	return time.Since(started), ttfb, nil
}

func newStreamingMetrics(bytes int, transferDuration, ttfb time.Duration, fairness []time.Duration) streamingMetrics {
	completion := append([]time.Duration(nil), fairness...)
	sort.Slice(completion, func(i, j int) bool { return completion[i] < completion[j] })
	completionMS := make([]float64, len(completion))
	for i, duration := range completion {
		completionMS[i] = float64(duration) / float64(time.Millisecond)
	}

	medianNanoseconds := 0.0
	if len(completion) > 0 {
		middle := len(completion) / 2
		if len(completion)%2 != 0 {
			medianNanoseconds = float64(completion[middle])
		} else {
			medianNanoseconds = (float64(completion[middle-1]) + float64(completion[middle])) / 2
		}
	}
	slowest := time.Duration(0)
	if len(completion) > 0 {
		slowest = completion[len(completion)-1]
	}
	ratio := 0.0
	if medianNanoseconds > 0 {
		ratio = float64(slowest) / medianNanoseconds
	}
	throughput := 0.0
	if transferDuration > 0 {
		throughput = (float64(bytes) / (1024 * 1024)) / transferDuration.Seconds()
	}
	return streamingMetrics{
		Bytes:                        bytes,
		ThroughputMiBPerSec:          throughput,
		TTFBMilliseconds:             float64(ttfb) / float64(time.Millisecond),
		TransferMilliseconds:         float64(transferDuration) / float64(time.Millisecond),
		ConcurrentStreams:            len(completion),
		FairnessCompletionMS:         completionMS,
		FairnessMedianMilliseconds:   medianNanoseconds / float64(time.Millisecond),
		FairnessSlowestMilliseconds:  float64(slowest) / float64(time.Millisecond),
		FairnessSlowestToMedianRatio: ratio,
	}
}

func medianDuration(sorted []time.Duration) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	mid := len(sorted) / 2
	if len(sorted)%2 != 0 {
		return sorted[mid]
	}
	return sorted[mid-1] + (sorted[mid]-sorted[mid-1])/2
}

func (s *statsCollector) add(m connMetrics) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if m.errStage == "" {
		s.success++
		if m.connectTotal > 0 {
			s.connectTotal = append(s.connectTotal, m.connectTotal.Nanoseconds())
		}
		if m.wsOpen > 0 {
			s.wsOpen = append(s.wsOpen, m.wsOpen.Nanoseconds())
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

	connectTotal []int64
	wsOpen       []int64
	handshake    []int64
	rpcCall      []int64
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

func buildOutput(cfg loadConfig, total int, stats *statsCollector, live *liveRegistry, sampler *resourceStats, streaming streamingMetrics) map[string]any {
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
		"channels":             cfg.targetChannels,
		"rate_per_sec":         cfg.ratePerSec,
		"ramp_step":            cfg.rampStep,
		"ramp_interval_ms":     cfg.rampInterval.Milliseconds(),
		"steady_duration_ms":   cfg.steadyDuration.Milliseconds(),
		"workers":              cfg.workers,
		"conn_timeout_ms":      cfg.connTimeout.Milliseconds(),
		"report_interval_ms":   cfg.reportInterval.Milliseconds(),
		"rpc_timeout_ms":       cfg.rpcTimeout.Milliseconds(),
		"max_handshake_bytes":  cfg.maxHandshakeSize,
		"max_record_bytes":     cfg.maxRecordBytes,
		"max_buffered_bytes":   cfg.maxBufferedBytes,
		"stream_bytes":         cfg.streamBytes,
		"fair_stream_bytes":    cfg.fairStreamBytes,
		"fair_streams":         cfg.fairStreams,
		"max_conns":            cfg.maxConns,
		"max_channels":         cfg.maxChannels,
		"max_pending_bytes":    cfg.maxPendingBytes,
		"idle_timeout_ms":      cfg.idleTimeout.Milliseconds(),
		"cleanup_interval_ms":  cfg.cleanupInterval.Milliseconds(),
		"liveness_interval_ms": cfg.livenessOptions().Interval.Milliseconds(),
		"liveness_timeout_ms":  cfg.livenessOptions().Timeout.Milliseconds(),
		"connection_api":       "client.Connect",
		"rpc_stream_residency": "connection_lifetime",
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
			"connect_total": computeLatency(snap.connectTotal),
			"ws_open":       computeLatency(snap.wsOpen),
			"handshake":     computeLatency(snap.handshake),
			"rpc_call":      computeLatency(snap.rpcCall),
		},
		"resources": sampler,
		"streaming": streaming,
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

		connectTotal: append([]int64(nil), s.connectTotal...),
		wsOpen:       append([]int64(nil), s.wsOpen...),
		handshake:    append([]int64(nil), s.handshake...),
		rpcCall:      append([]int64(nil), s.rpcCall...),
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

func startResourceSampler(ctx context.Context, interval time.Duration, baselineGoroutines int) *resourceStats {
	stats := &resourceStats{BaselineGoroutines: baselineGoroutines, done: make(chan struct{})}
	stats.sample()
	if interval <= 0 {
		close(stats.done)
		return stats
	}
	go func() {
		defer close(stats.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats.sample()
			}
		}
	}()
	return stats
}

func (s *resourceStats) sample() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s.mu.Lock()
	s.MaxHeapAlloc = maxU64(s.MaxHeapAlloc, ms.HeapAlloc)
	s.MaxHeapInuse = maxU64(s.MaxHeapInuse, ms.HeapInuse)
	s.MaxSysBytes = maxU64(s.MaxSysBytes, ms.Sys)
	if g := runtime.NumGoroutine(); g > s.MaxGoroutines {
		s.MaxGoroutines = g
	}
	s.mu.Unlock()
}

func (s *resourceStats) captureSteadyState() {
	s.sample()
	steady := runtime.NumGoroutine()
	s.mu.Lock()
	s.SteadyGoroutines = steady
	if steady > s.MaxGoroutines {
		s.MaxGoroutines = steady
	}
	s.mu.Unlock()
}

func waitForGoroutineBaseline(baseline int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	last := runtime.NumGoroutine()
	for time.Now().Before(deadline) {
		runtime.GC()
		last = runtime.NumGoroutine()
		if last <= baseline+16 {
			return last
		}
		time.Sleep(25 * time.Millisecond)
	}
	return last
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
	return ks, p
}

func itoa(v int) string {
	return strconv.Itoa(v)
}
