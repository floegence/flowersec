package performance

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type throughputContractRead struct {
	payload []byte
	err     error
}

type throughputContractStream struct {
	mu          sync.Mutex
	reads       []throughputContractRead
	writes      []byte
	closeWrites atomic.Int32
	resets      atomic.Int32
}

func (stream *throughputContractStream) Read(buffer []byte) (int, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if len(stream.reads) == 0 {
		return 0, io.EOF
	}
	next := stream.reads[0]
	stream.reads = stream.reads[1:]
	return copy(buffer, next.payload), next.err
}

func (stream *throughputContractStream) Write(payload []byte) (int, error) {
	stream.mu.Lock()
	stream.writes = append(stream.writes, payload...)
	stream.mu.Unlock()
	return len(payload), nil
}

func (stream *throughputContractStream) CloseWrite() error {
	stream.closeWrites.Add(1)
	return nil
}

func (stream *throughputContractStream) Close() error { return stream.Reset() }
func (stream *throughputContractStream) Reset() error {
	stream.resets.Add(1)
	return nil
}

type blockingResetThroughputContractStream struct {
	resetStarted chan struct{}
	resetRelease chan struct{}
	startOnce    sync.Once
	resets       atomic.Int32
}

type cancellationBlockedThroughputContractStream struct {
	readStarted chan struct{}
	stopped     chan struct{}
	startOnce   sync.Once
	stopOnce    sync.Once
	resets      atomic.Int32
}

func (stream *cancellationBlockedThroughputContractStream) Read([]byte) (int, error) {
	stream.startOnce.Do(func() { close(stream.readStarted) })
	<-stream.stopped
	return 0, io.ErrClosedPipe
}
func (*cancellationBlockedThroughputContractStream) Write(payload []byte) (int, error) {
	return len(payload), nil
}
func (*cancellationBlockedThroughputContractStream) CloseWrite() error { return nil }
func (stream *cancellationBlockedThroughputContractStream) Close() error {
	return stream.Reset()
}
func (stream *cancellationBlockedThroughputContractStream) Reset() error {
	stream.resets.Add(1)
	stream.stopOnce.Do(func() { close(stream.stopped) })
	return nil
}

func (*blockingResetThroughputContractStream) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (*blockingResetThroughputContractStream) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}
func (*blockingResetThroughputContractStream) CloseWrite() error { return nil }
func (stream *blockingResetThroughputContractStream) Close() error {
	return stream.Reset()
}
func (stream *blockingResetThroughputContractStream) Reset() error {
	stream.resets.Add(1)
	stream.startOnce.Do(func() { close(stream.resetStarted) })
	<-stream.resetRelease
	return nil
}

func TestPayloadThroughputReadErrorDoesNotScheduleAcknowledgement(t *testing.T) {
	payload := []byte{0x11, 0x22}
	ack, err := payloadThroughputAckAllowed(payload, payload, len(payload), io.EOF, "payload throughput request mismatch")
	if ack {
		t.Fatal("payload throughput scheduled an acknowledgement after the read terminated")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("payload throughput read error = %v, want EOF", err)
	}
}

func TestPayloadThroughputReadMismatchRemainsFatal(t *testing.T) {
	payload := []byte{0x11, 0x22}
	got := []byte{0x11, 0x33}
	ack, err := payloadThroughputAckAllowed(got, payload, len(got), nil, "payload throughput request mismatch")
	if ack || err == nil || err.Error() != "payload throughput request mismatch" {
		t.Fatalf("payload throughput mismatch result = ack %v, err %v", ack, err)
	}
}

func TestThroughputMatrixReportUsesEffectiveSampleWindow(t *testing.T) {
	t.Setenv("FLOWERSEC_PERFORMANCE_BUDGET", "20m")
	report := throughputMatrixPerformanceResult("performance/throughput/webtransport", "webtransport", "streaming", nil, nil)
	if got := report.Configuration["fixed sample window"]; got != (1400 * time.Millisecond).String() {
		t.Fatalf("throughput report sample window = %q, want %q", got, (1400 * time.Millisecond).String())
	}
}

func TestThroughputMatrixReportUsesObservedLifecycleCounts(t *testing.T) {
	contract := payloadThroughputContract{PayloadBytes: 1024, Concurrency: 1, SampleDuration: time.Second, Samples: 3, MinBytesPerSecond: 1, MaxP95: time.Second, Direction: payloadClientToServer}
	result := payloadThroughputResult{Samples: []payloadThroughputSample{{Bytes: 1, Duration: time.Second, BytesPerSecond: 1, Latencies: []time.Duration{time.Millisecond}, FINCleanupFailures: 1, ResetCount: 2}}}
	result.Summary = summarizePayloadThroughput(result)
	report := throughputMatrixPerformanceResult("performance/throughput/wss", "websocket", "streaming", []payloadThroughputCoordinateResult{{Contract: contract, Result: result}}, nil)
	observed := map[string]float64{}
	for _, measurement := range report.Measurements {
		if strings.HasSuffix(measurement.Name, "FIN cleanup failures") || strings.HasSuffix(measurement.Name, "reset count") {
			observed[measurement.Name] = measurement.Observed
		}
	}
	if len(observed) != 2 {
		t.Fatalf("lifecycle measurements = %v", observed)
	}
	for name, value := range observed {
		if strings.HasSuffix(name, "FIN cleanup failures") && value != 1 {
			t.Fatalf("%s = %v, want 1", name, value)
		}
		if strings.HasSuffix(name, "reset count") && value != 2 {
			t.Fatalf("%s = %v, want 2", name, value)
		}
	}
}

func TestPayloadThroughputReceiverCompletesReciprocalFINWithoutReset(t *testing.T) {
	payload := []byte{0x11, 0x22}
	stream := &throughputContractStream{reads: []throughputContractRead{{payload: payload}, {err: io.EOF}}}
	lifecycle := &payloadThroughputLifecycleCounters{}
	owner := newPayloadThroughputStreamOwner(context.Background(), stream, lifecycle)
	err := receiveAcknowledgedPayloads(stream, "performance-throughput", payload, "payload mismatch")
	if finishErr := owner.Finish(err == nil); finishErr != nil {
		err = errors.Join(err, finishErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if string(stream.writes) != string([]byte{0xa5}) || stream.closeWrites.Load() != 1 || stream.resets.Load() != 0 {
		t.Fatalf("receiver lifecycle = writes %x, CloseWrite %d, Reset %d", stream.writes, stream.closeWrites.Load(), stream.resets.Load())
	}
	if lifecycle.cleanFINs.Load() != 1 || lifecycle.resets.Load() != 0 {
		t.Fatalf("receiver counters = clean FIN %d, Reset %d", lifecycle.cleanFINs.Load(), lifecycle.resets.Load())
	}
}

func TestPayloadThroughputReceiverMismatchResetsWithoutAcknowledgement(t *testing.T) {
	payload := []byte{0x11, 0x22}
	stream := &throughputContractStream{reads: []throughputContractRead{{payload: []byte{0x11, 0x33}}}}
	lifecycle := &payloadThroughputLifecycleCounters{}
	owner := newPayloadThroughputStreamOwner(context.Background(), stream, lifecycle)
	err := receiveAcknowledgedPayloads(stream, "performance-throughput", payload, "payload mismatch")
	err = errors.Join(err, owner.Finish(err == nil))
	if err == nil || err.Error() != "payload mismatch" {
		t.Fatalf("receiver mismatch error = %v", err)
	}
	if len(stream.writes) != 0 || stream.closeWrites.Load() != 0 || stream.resets.Load() != 1 {
		t.Fatalf("mismatch lifecycle = writes %x, CloseWrite %d, Reset %d", stream.writes, stream.closeWrites.Load(), stream.resets.Load())
	}
	if lifecycle.cleanFINs.Load() != 0 || lifecycle.resets.Load() != 1 {
		t.Fatalf("mismatch counters = clean FIN %d, Reset %d", lifecycle.cleanFINs.Load(), lifecycle.resets.Load())
	}
}

func TestPayloadThroughputCancellationUnblocksOwnedIO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stream := &cancellationBlockedThroughputContractStream{readStarted: make(chan struct{}), stopped: make(chan struct{})}
	owner := newPayloadThroughputStreamOwner(ctx, stream, &payloadThroughputLifecycleCounters{})
	readDone := make(chan error, 1)
	go func() {
		_, err := stream.Read(make([]byte, 1))
		readDone <- err
	}()
	select {
	case <-stream.readStarted:
	case <-time.After(time.Second):
		t.Fatal("blocking read did not start")
	}
	cancel()
	select {
	case err := <-readDone:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("blocked read error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock owned read")
	}
	if err := owner.Finish(false); !errors.Is(err, context.Canceled) {
		t.Fatalf("Finish error = %v, want context canceled", err)
	}
	if stream.resets.Load() != 1 {
		t.Fatalf("Reset count = %d, want 1", stream.resets.Load())
	}
}

func TestPayloadThroughputCancellationWaitsForReset(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stream := &blockingResetThroughputContractStream{resetStarted: make(chan struct{}), resetRelease: make(chan struct{})}
	owner := newPayloadThroughputStreamOwner(ctx, stream, &payloadThroughputLifecycleCounters{})
	cancel()
	select {
	case <-stream.resetStarted:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not start stream reset")
	}
	finished := make(chan error, 1)
	go func() { finished <- owner.Finish(false) }()
	select {
	case err := <-finished:
		t.Fatalf("Finish returned before Reset completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(stream.resetRelease)
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Finish error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Finish did not wait for Reset teardown")
	}
	if stream.resets.Load() != 1 {
		t.Fatalf("Reset count = %d, want 1", stream.resets.Load())
	}
}

func TestPayloadThroughputWorkerFailureCancelsAndJoinsSibling(t *testing.T) {
	siblingStarted := make(chan struct{})
	siblingStopped := make(chan struct{})
	sentinel := errors.New("first worker failure")
	_, err := runPayloadThroughputWorkers(context.Background(), 2, func(ctx context.Context, index int) (payloadThroughputWorkerResult, error) {
		if index == 0 {
			<-siblingStarted
			return payloadThroughputWorkerResult{}, sentinel
		}
		close(siblingStarted)
		<-ctx.Done()
		close(siblingStopped)
		return payloadThroughputWorkerResult{}, context.Cause(ctx)
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("worker group error = %v, want first failure", err)
	}
	select {
	case <-siblingStopped:
	default:
		t.Fatal("worker group returned before canceled sibling stopped")
	}
}

func TestPayloadThroughputRequiresReciprocalEOF(t *testing.T) {
	clean := &throughputContractStream{reads: []throughputContractRead{{err: io.EOF}}}
	if err := requireCleanPayloadThroughputEOF(clean); err != nil {
		t.Fatalf("clean EOF: %v", err)
	}
	trailing := &throughputContractStream{reads: []throughputContractRead{{payload: []byte{0x01}}}}
	if err := requireCleanPayloadThroughputEOF(trailing); err == nil {
		t.Fatal("reciprocal FIN accepted trailing bytes")
	}
}
