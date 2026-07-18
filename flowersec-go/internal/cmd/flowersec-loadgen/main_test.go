package main

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/controlplane/channelinit"
)

func TestBuildOutputDeclaresHighLevelConnectionContract(t *testing.T) {
	cfg := loadConfig{targetChannels: 1}
	stats := &statsCollector{startedAt: time.Now(), failures: map[string]int{}, perSecond: map[int64]int{}}
	resources := &resourceStats{done: make(chan struct{})}
	close(resources.done)

	out := buildOutput(cfg, 1, stats, &liveRegistry{}, resources, streamingMetrics{BackgroundConnections: 1})
	config := out["config"].(map[string]any)
	if got := config["connection_api"]; got != "client.Connect" {
		t.Fatalf("connection_api = %v, want client.Connect", got)
	}
	if got := config["rpc_stream_residency"]; got != "connection_lifetime" {
		t.Fatalf("rpc_stream_residency = %v, want connection_lifetime", got)
	}
	if _, exists := config["mode"]; exists {
		t.Fatal("removed loadgen mode must not remain in benchmark output")
	}
	streaming := out["streaming"].(streamingMetrics)
	if streaming.BackgroundConnections != cfg.targetChannels {
		t.Fatalf("streaming background connections = %d, want %d", streaming.BackgroundConnections, cfg.targetChannels)
	}
}

func TestStreamingResourceProbeSamplesUntilStopped(t *testing.T) {
	var samples atomic.Int32
	reached := make(chan struct{})
	var reachedOnce sync.Once
	stop := startStreamingResourceProbe(time.Millisecond, func() {
		if samples.Add(1) >= 2 {
			reachedOnce.Do(func() { close(reached) })
		}
	})
	select {
	case <-reached:
	case <-time.After(time.Second):
		t.Fatal("resource probe did not sample while active")
	}
	stop()
	stoppedAt := samples.Load()
	time.Sleep(5 * time.Millisecond)
	if got := samples.Load(); got != stoppedAt {
		t.Fatalf("resource samples continued after stop: %d -> %d", stoppedAt, got)
	}
}

func TestNewStreamingMetrics(t *testing.T) {
	metrics := newStreamingMetrics(
		16<<20,
		400*time.Millisecond,
		12*time.Millisecond,
		[]time.Duration{100, 105, 110, 115, 120, 125, 130, 180},
	)
	if metrics.Bytes != 16<<20 {
		t.Fatalf("bytes = %d, want %d", metrics.Bytes, 16<<20)
	}
	if metrics.ThroughputMiBPerSec != 40 {
		t.Fatalf("throughput = %v MiB/s, want 40", metrics.ThroughputMiBPerSec)
	}
	if metrics.TTFBMilliseconds != 12 {
		t.Fatalf("TTFB = %v ms, want 12", metrics.TTFBMilliseconds)
	}
	if metrics.ConcurrentStreams != 8 {
		t.Fatalf("concurrent streams = %d, want 8", metrics.ConcurrentStreams)
	}
	if metrics.FairnessSlowestToMedianRatio <= 1 || metrics.FairnessSlowestToMedianRatio >= 2 {
		t.Fatalf("fairness ratio = %v, want between 1 and 2", metrics.FairnessSlowestToMedianRatio)
	}
}

func TestNewStreamingMetricsFairnessAggregateMatchesExportedSamples(t *testing.T) {
	metrics := newStreamingMetrics(
		16<<20,
		400*time.Millisecond,
		12*time.Millisecond,
		[]time.Duration{
			76_643_542 * time.Nanosecond,
			78_411_917 * time.Nanosecond,
			78_425_583 * time.Nanosecond,
			78_446_000 * time.Nanosecond,
			82_116_167 * time.Nanosecond,
			82_128_292 * time.Nanosecond,
			82_134_667 * time.Nanosecond,
			82_356_833 * time.Nanosecond,
		},
	)
	middle := len(metrics.FairnessCompletionMS) / 2
	median := (metrics.FairnessCompletionMS[middle-1] + metrics.FairnessCompletionMS[middle]) / 2
	ratio := metrics.FairnessCompletionMS[len(metrics.FairnessCompletionMS)-1] / median
	if math.Abs(metrics.FairnessMedianMilliseconds-median) > 1e-12 {
		t.Fatalf("fairness median = %.12f, exported sample median = %.12f", metrics.FairnessMedianMilliseconds, median)
	}
	if math.Abs(metrics.FairnessSlowestToMedianRatio-ratio) > 1e-12 {
		t.Fatalf("fairness ratio = %.12f, exported sample ratio = %.12f", metrics.FairnessSlowestToMedianRatio, ratio)
	}
}

func TestHighLevelConnectionAndStreamingBenchmark(t *testing.T) {
	cfg := loadConfig{
		targetChannels:   1,
		workers:          1,
		connTimeout:      5 * time.Second,
		rpcTimeout:       5 * time.Second,
		maxHandshakeSize: 8 * 1024,
		maxRecordBytes:   1 << 20,
		maxBufferedBytes: 4 << 20,
		streamBytes:      64 << 10,
		fairStreamBytes:  32 << 10,
		fairStreams:      8,
		maxPendingBytes:  256 << 10,
		idleTimeout:      60 * time.Second,
		cleanupInterval:  10 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	iss, keyFile := mustTestIssuer()
	defer os.RemoveAll(filepath.Dir(keyFile))
	wsURL, closeTunnel, err := startTunnel(ctx, cfg, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTunnel()

	svc := &channelinit.Service{
		Issuer: iss,
		Params: channelinit.Params{
			TunnelURL:          wsURL,
			TunnelAudience:     "flowersec-tunnel:loadgen",
			IssuerID:           "issuer-loadgen",
			TokenExpSeconds:    60,
			IdleTimeoutSeconds: 60,
		},
	}
	live := &liveRegistry{}
	connection := runConnection(ctx, svc, cfg, 1, live)
	if connection.errStage != "" {
		t.Fatalf("runConnection() stage = %q", connection.errStage)
	}
	if connection.connectTotal <= 0 || connection.rpcCall <= 0 {
		t.Fatalf("runConnection() timings = %+v", connection)
	}
	live.closeAll()

	resourceSamples := 0
	metrics, err := runStreamingBenchmark(ctx, svc, cfg, func() {
		resourceSamples++
	})
	if err != nil {
		t.Fatal(err)
	}
	if resourceSamples < 2 {
		t.Fatalf("resource samples = %d, want memory probe samples", resourceSamples)
	}
	if metrics.Bytes != cfg.streamBytes || len(metrics.ThroughputSamplesMiBPerSec) != streamBenchmarkSamples {
		t.Fatalf("stream metrics = %+v", metrics)
	}
	if metrics.ConcurrentStreams != cfg.fairStreams || metrics.FairnessSlowestToMedianRatio <= 0 {
		t.Fatalf("fairness metrics = %+v", metrics)
	}
}
