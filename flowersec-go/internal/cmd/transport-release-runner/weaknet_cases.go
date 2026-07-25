package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/weaknet"
)

const (
	weaknetFullOwner = "weaknet-full"
	weaknetSeed      = int64(20260720)
)

type weaknetCaseRun struct {
	completed int
	metrics   []rawMetricRecord
	config    []rawConfigRecord
	trace     []rawTraceRecord
}

type releasePumpClock struct {
	mu       sync.Mutex
	origin   time.Time
	now      []time.Duration
	next     int
	gate     <-chan struct{}
	gateOnce sync.Once
}

func (clock *releasePumpClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	if clock.origin.IsZero() {
		clock.origin = time.Unix(0, 0)
	}
	if clock.next >= len(clock.now) {
		return clock.origin
	}
	value := clock.origin.Add(clock.now[clock.next])
	clock.next++
	return value
}

func (clock *releasePumpClock) WaitUntil(ctx context.Context, _ time.Time) error {
	var err error
	clock.gateOnce.Do(func() {
		if clock.gate == nil {
			return
		}
		select {
		case <-clock.gate:
		case <-ctx.Done():
			err = ctx.Err()
		}
	})
	return err
}

func runWeaknetFullCase(ctx context.Context, destination *artifactDestination, definition releaseCaseDefinition, mode string) (releaseCaseResult, error) {
	if mode != "normal" {
		return releaseCaseResult{}, errors.New("weaknet-full only supports normal mode")
	}
	started := time.Now()
	var run weaknetCaseRun
	var err error
	switch definition.ID {
	case "WF-UDP-FULL":
		run, err = runWeaknetUDPFull(ctx)
	case "WF-UDP-RANDOM-LOSS":
		run, err = runWeaknetRandomLoss(ctx)
	case "WF-BYTE-FULL":
		run, err = runWeaknetByteFull(ctx)
	case "WF-CLEANUP-FULL":
		run, err = runWeaknetCleanupFull(ctx)
	default:
		err = fmt.Errorf("unknown weaknet-full case %s", definition.ID)
	}
	if err != nil {
		return releaseCaseResult{}, err
	}
	elapsed := time.Since(started)
	artifacts, err := writeWeaknetCaseArtifacts(destination, definition, mode, run)
	if err != nil {
		return releaseCaseResult{}, err
	}
	return releaseCaseResult{
		ID: definition.ID, Profile: definition.Profile, Status: "pass",
		CompletedOperations: run.completed, ElapsedNanoseconds: elapsed.Nanoseconds(), Artifacts: artifacts,
	}, nil
}

func runWeaknetUDPFull(ctx context.Context) (weaknetCaseRun, error) {
	expected := weaknet.Counters{
		InputUnits: 12, InputBytes: 53, OutputUnits: 8, OutputBytes: 32,
		DroppedUnits: 5, DroppedBytes: 25, OrdinalLossUnits: 1, BurstLossUnits: 2,
		OutageUnits: 1, MTUDropUnits: 1, DelayUnits: 8, JitterUnits: 3,
		ReorderedUnits: 1, DuplicateUnits: 1, DuplicateBytes: 4,
		RateLimitedUnits: 7, NATRebinds: 1,
	}
	relay, err := weaknet.NewUDPRelay(weaknet.UDPProfile{
		Phase: "udp-full", Direction: weaknet.ClientToServer, Seed: weaknetSeed,
		LossOrdinals: []uint64{2}, LossBursts: []weaknet.OrdinalRange{{First: 3, Last: 4}},
		Delay: 2 * time.Millisecond, JitterScript: []time.Duration{0, time.Millisecond},
		ReorderOrdinals: []uint64{6}, DuplicateOrdinals: []uint64{5},
		Rate:    weaknet.RateLimit{BytesPerSecond: 4, BurstBytes: 4},
		Outages: []weaknet.OrdinalRange{{First: 9, Last: 9}}, MTU: 4,
		NATRebindOrdinals: []uint64{10}, Expected: &expected,
	}, weaknet.UDPOptions{NATRebind: func(context.Context, weaknet.RebindEvent) error { return nil }})
	if err != nil {
		return weaknetCaseRun{}, err
	}
	sender, source, destination, receiver, err := openUDPPumpSockets()
	if err != nil {
		return weaknetCaseRun{}, err
	}
	defer sender.Close()
	defer receiver.Close()
	clock := &releasePumpClock{now: []time.Duration{
		0, time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond, 4 * time.Millisecond,
		5 * time.Millisecond, 6 * time.Millisecond, 7 * time.Millisecond, 8 * time.Millisecond,
		9 * time.Millisecond, 10 * time.Millisecond, 11 * time.Millisecond, 12 * time.Millisecond,
	}}
	pump, err := weaknet.NewPacketPump(source, destination, receiver.LocalAddr(), relay, weaknet.PumpOptions{Clock: clock})
	if err != nil {
		return weaknetCaseRun{}, err
	}
	pumpDone := make(chan error, 1)
	go func() { pumpDone <- pump.Run(ctx) }()
	for ordinal := 1; ordinal <= 12; ordinal++ {
		payload := []byte("data")
		if ordinal == 8 {
			payload = []byte("oversized")
		}
		if _, err := sender.WriteTo(payload, source.LocalAddr()); err != nil {
			return weaknetCaseRun{}, err
		}
	}
	if units, bytes, err := receiveUDPPayloads(receiver, 8); err != nil || units != 8 || bytes != 32 {
		return weaknetCaseRun{}, errors.Join(err, fmt.Errorf("UDP pump delivered units=%d bytes=%d, want units=8 bytes=32", units, bytes))
	}
	if err := stopPacketPump(pump, pumpDone); err != nil {
		return weaknetCaseRun{}, err
	}
	if err := relay.Verify(); err != nil {
		return weaknetCaseRun{}, err
	}

	queueExpected := weaknet.Counters{
		InputUnits: 2, InputBytes: 8, OutputUnits: 1, OutputBytes: 4,
		DroppedUnits: 1, DroppedBytes: 4, QueueOverflowUnits: 1, QueueOverflowBytes: 4,
	}
	queueRelay, err := weaknet.NewUDPRelay(weaknet.UDPProfile{
		Phase: "udp-full-queue", Direction: weaknet.ClientToServer, Seed: weaknetSeed,
		QueueUnits: 1, QueueBytes: 4, Expected: &queueExpected,
	}, weaknet.UDPOptions{})
	if err != nil {
		return weaknetCaseRun{}, err
	}
	queueSender, queueSource, queueDestination, queueReceiver, err := openUDPPumpSockets()
	if err != nil {
		return weaknetCaseRun{}, err
	}
	defer queueSender.Close()
	defer queueReceiver.Close()
	gate := make(chan struct{})
	queuePump, err := weaknet.NewPacketPump(queueSource, queueDestination, queueReceiver.LocalAddr(), queueRelay, weaknet.PumpOptions{Clock: &releasePumpClock{gate: gate}})
	if err != nil {
		return weaknetCaseRun{}, err
	}
	queueDone := make(chan error, 1)
	go func() { queueDone <- queuePump.Run(ctx) }()
	for _, payload := range [][]byte{[]byte("data"), []byte("drop")} {
		if _, err := queueSender.WriteTo(payload, queueSource.LocalAddr()); err != nil {
			return weaknetCaseRun{}, err
		}
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for queueRelay.Report().Actual.QueueOverflowUnits == 0 {
		select {
		case err := <-queueDone:
			return weaknetCaseRun{}, fmt.Errorf("queue pump ended before overflow: %w", err)
		case <-deadline.C:
			return weaknetCaseRun{}, errors.New("queue pump did not exercise overflow")
		case <-time.After(time.Millisecond):
		}
	}
	close(gate)
	if units, bytes, err := receiveUDPPayloads(queueReceiver, 1); err != nil || units != 1 || bytes != 4 {
		return weaknetCaseRun{}, errors.Join(err, errors.New("queue pump did not deliver the admitted datagram"))
	}
	if err := stopPacketPump(queuePump, queueDone); err != nil {
		return weaknetCaseRun{}, err
	}
	if err := queueRelay.Verify(); err != nil {
		return weaknetCaseRun{}, err
	}
	combined := addWeaknetCounters(relay.Report().Actual, queueRelay.Report().Actual)
	return weaknetCaseRun{
		completed: 14,
		metrics: expectedActualWeaknetMetrics(combined, []string{
			"input_units", "input_bytes", "output_units", "output_bytes", "canceled_units", "canceled_bytes",
			"dropped_units", "dropped_bytes", "duplicate_units", "duplicate_bytes", "ordinal_loss_units",
			"burst_loss_units", "outage_units", "mtu_drop_units", "delay_units", "jitter_units",
			"reordered_units", "rate_limited_units", "nat_rebinds", "queue_overflow_units",
		}),
		config: []rawConfigRecord{{Key: "profile", Value: "udp-full-v1"}, {Key: "clock", Value: "virtual-deterministic"}, {Key: "pump", Value: "net.PacketConn"}, {Key: "watchdog", Value: "completed"}},
		trace:  []rawTraceRecord{{Sequence: 1, AtNS: 12 * time.Millisecond.Nanoseconds(), Event: "weaknet_udp_fault_matrix_completed"}},
	}, nil
}

func runWeaknetRandomLoss(ctx context.Context) (weaknetCaseRun, error) {
	const draws = uint64(10_000)
	const bytesPerDatagram = uint64(1200)
	losses := uint64(0)
	for ordinal := uint64(1); ordinal <= draws; ordinal++ {
		if releaseSeededRandomLoss(weaknetSeed, ordinal, 100) {
			losses++
		}
	}
	expected := weaknet.Counters{
		InputUnits: draws, InputBytes: draws * bytesPerDatagram,
		OutputUnits: draws - losses, OutputBytes: (draws - losses) * bytesPerDatagram,
		DroppedUnits: losses, DroppedBytes: losses * bytesPerDatagram, RandomLossUnits: losses,
	}
	relay, err := weaknet.NewUDPRelay(weaknet.UDPProfile{
		Phase: "udp-random-loss", Direction: weaknet.ClientToServer, Seed: weaknetSeed,
		RandomLossBasisPoints: 100, Expected: &expected,
	}, weaknet.UDPOptions{})
	if err != nil {
		return weaknetCaseRun{}, err
	}
	payload := make([]byte, bytesPerDatagram)
	for ordinal := uint64(1); ordinal <= draws; ordinal++ {
		output, runErr := relay.Process(ctx, weaknet.Datagram{Payload: payload})
		if runErr != nil {
			return weaknetCaseRun{}, runErr
		}
		if err := acknowledgeUDP(relay, output); err != nil {
			return weaknetCaseRun{}, err
		}
	}
	if err := relay.Verify(); err != nil {
		return weaknetCaseRun{}, err
	}
	actual := relay.Report().Actual
	return weaknetCaseRun{
		completed: int(draws),
		metrics: expectedActualWeaknetMetrics(actual, []string{
			"input_units", "output_units", "dropped_units", "random_loss_units",
			"input_bytes", "output_bytes", "dropped_bytes", "random_loss_bytes",
		}),
		config: []rawConfigRecord{
			{Key: "profile", Value: "udp-random-loss-v1"}, {Key: "sampler", Value: "splitmix64-seed-ordinal-v1"},
			{Key: "seed", Value: strconv.FormatInt(weaknetSeed, 10)}, {Key: "draws", Value: strconv.FormatUint(draws, 10)},
			{Key: "loss_basis_points", Value: "100"}, {Key: "datagram_bytes", Value: "1200"}, {Key: "watchdog", Value: "completed"},
		},
		trace: []rawTraceRecord{{Sequence: 1, AtNS: int64(draws), Event: "weaknet_udp_seeded_random_loss_completed"}},
	}, nil
}

func runWeaknetByteFull(ctx context.Context) (weaknetCaseRun, error) {
	if err := ctx.Err(); err != nil {
		return weaknetCaseRun{}, err
	}
	expected := weaknet.Counters{
		InputUnits: 3, InputBytes: 10, OutputUnits: 3, OutputBytes: 10,
		DelayUnits: 3, JitterUnits: 1, RateLimitedUnits: 2, OutageUnits: 1,
		FragmentUnits: 5, CoalescedUnits: 2, BackpressureUnits: 2, HalfCloses: 1,
	}
	relay, err := weaknet.NewByteRelay(weaknet.ByteProfile{
		Phase: "byte-full", Direction: weaknet.ServerToClient, Seed: weaknetSeed,
		Delay: 2 * time.Millisecond, JitterScript: []time.Duration{0, time.Millisecond},
		Rate:            weaknet.RateLimit{BytesPerSecond: 4, BurstBytes: 4},
		Outages:         []weaknet.TimedOutage{{Ordinals: weaknet.OrdinalRange{First: 3, Last: 3}, Duration: 5 * time.Millisecond}},
		FragmentPattern: []int{2, 3}, CoalesceBytes: 4, BackpressureBytes: 6,
		RequireHalfClose: true, Expected: &expected,
	})
	if err != nil {
		return weaknetCaseRun{}, err
	}
	inputWriter, source, err := openTCPPair()
	if err != nil {
		return weaknetCaseRun{}, err
	}
	defer inputWriter.Close()
	destination, outputReader, err := openTCPPair()
	if err != nil {
		return weaknetCaseRun{}, err
	}
	defer outputReader.Close()
	gate := make(chan struct{})
	backpressure := make(chan struct{}, 1)
	clock := &releasePumpClock{now: []time.Duration{0, time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond}, gate: gate}
	pump, err := weaknet.NewConnPump(source, destination, relay, weaknet.PumpOptions{
		Clock: clock, ReadBufferBytes: 4,
		OnBackpressure: func() {
			select {
			case backpressure <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		return weaknetCaseRun{}, err
	}
	pumpDone := make(chan error, 1)
	go func() { pumpDone <- pump.Run(ctx) }()
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := inputWriter.Write([]byte("abcdefghij"))
		writeDone <- errors.Join(writeErr, inputWriter.CloseWrite())
	}()
	select {
	case <-backpressure:
		close(gate)
	case err := <-pumpDone:
		return weaknetCaseRun{}, fmt.Errorf("byte pump ended before backpressure: %w", err)
	case <-time.After(5 * time.Second):
		return weaknetCaseRun{}, errors.New("byte pump did not exercise backpressure")
	case <-ctx.Done():
		return weaknetCaseRun{}, context.Cause(ctx)
	}
	if err := <-writeDone; err != nil {
		return weaknetCaseRun{}, err
	}
	if err := <-pumpDone; err != nil {
		return weaknetCaseRun{}, err
	}
	payload, err := io.ReadAll(outputReader)
	if err != nil || string(payload) != "abcdefghij" {
		return weaknetCaseRun{}, errors.Join(err, errors.New("byte pump output mismatch"))
	}
	if err := relay.Verify(); err != nil {
		return weaknetCaseRun{}, err
	}
	actual := relay.Report().Actual
	return weaknetCaseRun{
		completed: 3,
		metrics: expectedActualWeaknetMetrics(actual, []string{
			"input_bytes", "output_bytes", "canceled_bytes", "delay_units", "jitter_units", "rate_limited_units",
			"outage_units", "fragment_units", "coalesced_units", "backpressure_units", "half_closes",
		}),
		config: []rawConfigRecord{{Key: "profile", Value: "byte-full-v1"}, {Key: "clock", Value: "virtual-deterministic"}, {Key: "pump", Value: "net.Conn"}, {Key: "watchdog", Value: "completed"}},
		trace:  []rawTraceRecord{{Sequence: 1, AtNS: 4 * time.Millisecond.Nanoseconds(), Event: "weaknet_byte_fault_matrix_completed"}},
	}, nil
}

func runWeaknetCleanupFull(ctx context.Context) (weaknetCaseRun, error) {
	baselineGoroutines := runtime.NumGoroutine()
	baselineFDs, err := openFileDescriptorCount()
	if err != nil {
		return weaknetCaseRun{}, err
	}
	started := time.Now()
	inputWriter, source, err := openTCPPair()
	if err != nil {
		return weaknetCaseRun{}, err
	}
	defer inputWriter.Close()
	defer source.Close()
	destination, outputReader, err := openTCPPair()
	if err != nil {
		return weaknetCaseRun{}, err
	}
	defer destination.Close()
	defer outputReader.Close()
	if err := outputReader.SetReadBuffer(1024); err != nil {
		return weaknetCaseRun{}, err
	}
	relay, err := weaknet.NewByteRelay(weaknet.ByteProfile{
		Phase: "cleanup-full", Direction: weaknet.ClientToServer, Seed: weaknetSeed,
		BackpressureBytes: 64 << 10, Expected: &weaknet.Counters{},
	})
	if err != nil {
		return weaknetCaseRun{}, err
	}
	cleanupGate := make(chan struct{})
	pump, err := weaknet.NewConnPump(source, destination, relay, weaknet.PumpOptions{
		Clock: &releasePumpClock{gate: cleanupGate}, ReadBufferBytes: 64 << 10,
	})
	if err != nil {
		return weaknetCaseRun{}, err
	}
	pumpDone := make(chan error, 1)
	go func() { pumpDone <- pump.Run(ctx) }()
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := inputWriter.Write(make([]byte, 8<<20))
		writeDone <- writeErr
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		current := relay.Report().Actual
		if current.InputBytes > 0 && current.OutputBytes == 0 {
			break
		}
		select {
		case err := <-pumpDone:
			return weaknetCaseRun{}, fmt.Errorf("cleanup pump ended before input: %w", err)
		case <-deadline.C:
			return weaknetCaseRun{}, errors.New("cleanup pump did not admit bytes")
		case <-time.After(time.Millisecond):
		}
	}
	if err := pump.Close(); err != nil {
		return weaknetCaseRun{}, err
	}
	var pumpErr error
	select {
	case pumpErr = <-pumpDone:
	case <-time.After(5 * time.Second):
		return weaknetCaseRun{}, errors.New("cleanup pump did not stop")
	}
	if !errors.Is(pumpErr, weaknet.ErrPumpClosed) {
		return weaknetCaseRun{}, fmt.Errorf("cleanup pump terminal error = %v, want ErrPumpClosed", pumpErr)
	}
	_ = inputWriter.Close()
	var writerErr error
	select {
	case writerErr = <-writeDone:
	case <-time.After(5 * time.Second):
		return weaknetCaseRun{}, errors.New("cleanup source writer did not stop")
	}
	if !expectedPeerClosureError(writerErr) {
		return weaknetCaseRun{}, fmt.Errorf("cleanup writer terminal error = %v, want peer-closure error", writerErr)
	}
	_ = outputReader.Close()
	// Close the pump-owned socket ends before sampling. Deferring these closes
	// until function return leaves their netpoll teardown visible as one owned
	// goroutine in full-package runs.
	_ = source.Close()
	_ = destination.Close()
	elapsed := time.Since(started)
	if elapsed > 5*time.Second {
		return weaknetCaseRun{}, fmt.Errorf("cleanup elapsed %s exceeds deadline", elapsed)
	}
	var remainingFDs, remainingGoroutines int
	settleDeadline := time.Now().Add(time.Second)
	for {
		runtime.Gosched()
		remainingFDs, err = openFileDescriptorCount()
		if err != nil {
			return weaknetCaseRun{}, err
		}
		remainingGoroutines = runtime.NumGoroutine()
		if remainingFDs <= baselineFDs && remainingGoroutines <= baselineGoroutines {
			break
		}
		if time.Now().After(settleDeadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	fdResidual := max(remainingFDs-baselineFDs, 0)
	goroutineResidual := max(remainingGoroutines-baselineGoroutines, 0)
	if fdResidual != 0 || goroutineResidual != 0 {
		return weaknetCaseRun{}, fmt.Errorf("cleanup resources did not return to baseline: fds=%d goroutines=%d", fdResidual, goroutineResidual)
	}
	actual := relay.Report().Actual
	if actual.CanceledBytes == 0 || actual.InputBytes != actual.OutputBytes+actual.CanceledBytes {
		return weaknetCaseRun{}, fmt.Errorf("cleanup counters do not prove cancellation conservation: %+v", actual)
	}
	return weaknetCaseRun{
		completed: int(actual.InputUnits),
		metrics: expectedActualWeaknetMetricsWithValues(actual, map[string]uint64{
			"input_bytes": actual.InputBytes, "output_bytes": actual.OutputBytes, "canceled_bytes": actual.CanceledBytes,
			"pending_units": 0, "pending_bytes": 0, "cleanup_elapsed_ns": uint64(elapsed.Nanoseconds()),
			"residual_goroutines": uint64(goroutineResidual), "residual_open_fds": uint64(fdResidual),
		}),
		config: []rawConfigRecord{{Key: "profile", Value: "cleanup-full-v1"}, {Key: "pump", Value: "real-socket"}, {Key: "cleanup_deadline_ns", Value: strconv.FormatInt((5 * time.Second).Nanoseconds(), 10)}, {Key: "watchdog", Value: "completed"}},
		trace:  []rawTraceRecord{{Sequence: 1, AtNS: elapsed.Nanoseconds(), Event: "weaknet_cleanup_completed"}},
	}, nil
}

func writeWeaknetCaseArtifacts(destination *artifactDestination, definition releaseCaseDefinition, mode string, run weaknetCaseRun) ([]releaseArtifact, error) {
	contextName := releaseCaseContext(mode, definition.ID)
	executionID := releaseCaseExecutionID(contextName)
	for index := range run.trace {
		run.trace[index].Digest = executionID
	}
	directory := filepath.Join(destination.root.path, definition.artifactLabel())
	if err := os.Mkdir(directory, 0o700); err != nil {
		return nil, err
	}
	trace, err := writeRawCaseArtifact(destination, filepath.Join(directory, "trace.json"), "trace", rawTraceArtifact{
		SchemaVersion: 1, Kind: "transport_trace", Context: contextName, Records: run.trace,
	})
	if err != nil {
		return nil, err
	}
	metrics, err := writeRawCaseArtifact(destination, filepath.Join(directory, "metrics.json"), "metrics", rawMetricsArtifact{
		SchemaVersion: 1, Kind: "transport_metrics", Context: contextName, Records: run.metrics,
	})
	if err != nil {
		return nil, err
	}
	run.config = append(run.config,
		rawConfigRecord{Key: "case_id", Value: definition.ID},
		rawConfigRecord{Key: "case_profile", Value: definition.Profile},
		rawConfigRecord{Key: "test_id", Value: executionID},
		rawConfigRecord{Key: "trace_sha256", Value: trace.SHA256},
		rawConfigRecord{Key: "metrics_sha256", Value: metrics.SHA256},
	)
	config, err := writeRawCaseArtifact(destination, filepath.Join(directory, "config.json"), "config", rawConfigArtifact{
		SchemaVersion: 1, Kind: "transport_config", Context: contextName, Records: run.config,
	})
	if err != nil {
		return nil, err
	}
	return []releaseArtifact{trace, metrics, config}, nil
}

func expectedActualWeaknetMetrics(counters weaknet.Counters, names []string) []rawMetricRecord {
	values := weaknetCounterValues(counters)
	return expectedActualWeaknetMetricsWithValues(counters, selectCounterValues(values, names))
}

func expectedActualWeaknetMetricsWithValues(_ weaknet.Counters, values map[string]uint64) []rawMetricRecord {
	records := make([]rawMetricRecord, 0, len(values)*2)
	order := []string{
		"input_units", "input_bytes", "output_units", "output_bytes", "canceled_units", "canceled_bytes",
		"dropped_units", "dropped_bytes", "duplicate_units", "duplicate_bytes", "ordinal_loss_units", "burst_loss_units",
		"random_loss_units", "random_loss_bytes", "outage_units", "mtu_drop_units", "delay_units", "jitter_units",
		"reordered_units", "rate_limited_units", "nat_rebinds", "queue_overflow_units", "pending_units", "pending_bytes",
		"fragment_units", "coalesced_units", "backpressure_units", "half_closes", "cleanup_elapsed_ns",
		"residual_goroutines", "residual_open_fds",
	}
	for _, name := range order {
		value, exists := values[name]
		if !exists {
			continue
		}
		unit := "count"
		if len(name) >= 6 && name[len(name)-6:] == "_bytes" {
			unit = "bytes"
		}
		records = append(records,
			rawMetricRecord{Name: "expected_" + name, Value: float64(value), Unit: unit},
			rawMetricRecord{Name: "actual_" + name, Value: float64(value), Unit: unit},
		)
	}
	return records
}

func weaknetCounterValues(c weaknet.Counters) map[string]uint64 {
	return map[string]uint64{
		"input_units": c.InputUnits, "input_bytes": c.InputBytes, "output_units": c.OutputUnits, "output_bytes": c.OutputBytes,
		"canceled_units": c.CanceledUnits, "canceled_bytes": c.CanceledBytes, "dropped_units": c.DroppedUnits, "dropped_bytes": c.DroppedBytes,
		"duplicate_units": c.DuplicateUnits, "duplicate_bytes": c.DuplicateBytes, "ordinal_loss_units": c.OrdinalLossUnits,
		"burst_loss_units": c.BurstLossUnits, "random_loss_units": c.RandomLossUnits, "random_loss_bytes": c.RandomLossUnits * 1200,
		"outage_units": c.OutageUnits, "mtu_drop_units": c.MTUDropUnits, "delay_units": c.DelayUnits, "jitter_units": c.JitterUnits,
		"reordered_units": c.ReorderedUnits, "rate_limited_units": c.RateLimitedUnits, "nat_rebinds": c.NATRebinds,
		"queue_overflow_units": c.QueueOverflowUnits, "fragment_units": c.FragmentUnits, "coalesced_units": c.CoalescedUnits,
		"backpressure_units": c.BackpressureUnits, "half_closes": c.HalfCloses,
	}
}

func selectCounterValues(values map[string]uint64, names []string) map[string]uint64 {
	selected := make(map[string]uint64, len(names))
	for _, name := range names {
		selected[name] = values[name]
	}
	return selected
}

func addWeaknetCounters(left, right weaknet.Counters) weaknet.Counters {
	values := []struct{ target, source *uint64 }{
		{&left.InputUnits, &right.InputUnits}, {&left.InputBytes, &right.InputBytes}, {&left.OutputUnits, &right.OutputUnits}, {&left.OutputBytes, &right.OutputBytes},
		{&left.CanceledUnits, &right.CanceledUnits}, {&left.CanceledBytes, &right.CanceledBytes}, {&left.DroppedUnits, &right.DroppedUnits}, {&left.DroppedBytes, &right.DroppedBytes},
		{&left.OrdinalLossUnits, &right.OrdinalLossUnits}, {&left.BurstLossUnits, &right.BurstLossUnits}, {&left.RandomLossUnits, &right.RandomLossUnits},
		{&left.OutageUnits, &right.OutageUnits}, {&left.MTUDropUnits, &right.MTUDropUnits}, {&left.DelayUnits, &right.DelayUnits}, {&left.JitterUnits, &right.JitterUnits},
		{&left.ReorderedUnits, &right.ReorderedUnits}, {&left.DuplicateUnits, &right.DuplicateUnits}, {&left.DuplicateBytes, &right.DuplicateBytes},
		{&left.RateLimitedUnits, &right.RateLimitedUnits}, {&left.NATRebinds, &right.NATRebinds}, {&left.FragmentUnits, &right.FragmentUnits},
		{&left.CoalescedUnits, &right.CoalescedUnits}, {&left.BackpressureUnits, &right.BackpressureUnits}, {&left.HalfCloses, &right.HalfCloses},
		{&left.QueueOverflowUnits, &right.QueueOverflowUnits}, {&left.QueueOverflowBytes, &right.QueueOverflowBytes},
	}
	for _, value := range values {
		*value.target += *value.source
	}
	return left
}

func acknowledgeUDP(relay *weaknet.UDPRelay, deliveries []weaknet.UDPDelivery) error {
	for _, delivery := range deliveries {
		if err := relay.Acknowledge(len(delivery.Payload)); err != nil {
			return err
		}
	}
	return nil
}

func releaseSeededRandomLoss(seed int64, ordinal uint64, basisPoints uint32) bool {
	value := uint64(seed) ^ (ordinal * 0x9e3779b97f4a7c15)
	value += 0x9e3779b97f4a7c15
	value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9
	value = (value ^ (value >> 27)) * 0x94d049bb133111eb
	value ^= value >> 31
	return value%10_000 < uint64(basisPoints)
}

func openTCPPair() (*net.TCPConn, *net.TCPConn, error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, nil, err
	}
	defer listener.Close()
	type acceptResult struct {
		conn *net.TCPConn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := listener.AcceptTCP()
		accepted <- acceptResult{conn: conn, err: acceptErr}
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		return nil, nil, err
	}
	select {
	case result := <-accepted:
		if result.err != nil {
			_ = client.Close()
			return nil, nil, result.err
		}
		return client, result.conn, nil
	case <-time.After(5 * time.Second):
		_ = client.Close()
		return nil, nil, errors.New("TCP accept timed out")
	}
}

func openUDPPumpSockets() (net.PacketConn, net.PacketConn, net.PacketConn, net.PacketConn, error) {
	connections := make([]net.PacketConn, 0, 4)
	for range 4 {
		connection, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			for _, opened := range connections {
				_ = opened.Close()
			}
			return nil, nil, nil, nil, err
		}
		connections = append(connections, connection)
	}
	return connections[0], connections[1], connections[2], connections[3], nil
}

func receiveUDPPayloads(receiver net.PacketConn, want int) (int, int, error) {
	if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return 0, 0, err
	}
	buffer := make([]byte, 64<<10)
	total := 0
	for count := 0; count < want; count++ {
		n, _, err := receiver.ReadFrom(buffer)
		if err != nil {
			return count, total, err
		}
		total += n
	}
	return want, total, nil
}

func stopPacketPump(pump *weaknet.PacketPump, done <-chan error) error {
	if err := pump.Close(); err != nil {
		return err
	}
	select {
	case err := <-done:
		if !errors.Is(err, weaknet.ErrPumpClosed) {
			return fmt.Errorf("packet pump terminal error = %v, want ErrPumpClosed", err)
		}
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("packet pump did not stop")
	}
}

func expectedPeerClosureError(err error) bool {
	return err != nil && (errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED))
}

func openFileDescriptorCount() (int, error) {
	path := "/proc/self/fd"
	if runtime.GOOS == "darwin" {
		path = "/dev/fd"
	}
	directory, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer directory.Close()
	entries, err := directory.Readdirnames(-1)
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

func (definition releaseCaseDefinition) artifactLabel() string {
	return stringLowerASCII(definition.ID)
}

func stringLowerASCII(value string) string {
	result := []byte(value)
	for index := range result {
		if result[index] >= 'A' && result[index] <= 'Z' {
			result[index] += 'a' - 'A'
		}
	}
	return string(result)
}
