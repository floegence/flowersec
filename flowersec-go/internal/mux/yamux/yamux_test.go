package yamux

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestFrameLimitConnChecksDataLengthBeforeBodyRead(t *testing.T) {
	const limit = uint32(256 * 1024)
	header := make([]byte, 12)
	header[1] = 0 // DATA
	binary.BigEndian.PutUint32(header[8:12], limit+1)
	conn := &frameLimitConn{
		Conn:          &bytesConn{Reader: bytes.NewReader(header)},
		maxFrameBytes: limit,
	}
	buf := make([]byte, 12)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected oversized DATA frame rejection")
	}
}

func TestFrameLimitConnAcceptsDataLengthAtLimit(t *testing.T) {
	const limit = uint32(256 * 1024)
	header := make([]byte, 12)
	header[1] = 0 // DATA
	binary.BigEndian.PutUint32(header[8:12], limit)
	conn := &frameLimitConn{
		Conn:          &bytesConn{Reader: bytes.NewReader(header)},
		maxFrameBytes: limit,
	}
	buf := make([]byte, 12)
	if n, err := conn.Read(buf); err != nil || n != len(header) {
		t.Fatalf("Read() = %d, %v", n, err)
	}
}

func TestStreamMemoryManagerDoesNotLeakActiveSlotOnReservationFailure(t *testing.T) {
	manager := &sessionMemoryManager{maxStreams: 2, maxStream: 256 * 1024, maxSession: 256 * 1024}
	first := &streamMemoryManager{session: manager}
	if err := first.ReserveMemory(256*1024, 0); err != nil {
		t.Fatal(err)
	}
	failed := &streamMemoryManager{session: manager}
	if err := failed.ReserveMemory(256*1024, 0); !errors.Is(err, ErrResourceExhausted) {
		t.Fatalf("ReserveMemory() error = %v", err)
	}
	if manager.active != 1 {
		t.Fatalf("active streams after failed reservation = %d, want 1", manager.active)
	}
	first.Done()
	retry := &streamMemoryManager{session: manager}
	if err := retry.ReserveMemory(256*1024, 0); err != nil {
		t.Fatalf("reservation after release failed: %v", err)
	}
}

type bytesConn struct{ io.Reader }

func (*bytesConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (*bytesConn) Close() error                     { return nil }
func (*bytesConn) LocalAddr() net.Addr              { return nil }
func (*bytesConn) RemoteAddr() net.Addr             { return nil }
func (*bytesConn) SetDeadline(time.Time) error      { return nil }
func (*bytesConn) SetReadDeadline(time.Time) error  { return nil }
func (*bytesConn) SetWriteDeadline(time.Time) error { return nil }

type shortWriteConn struct {
	bytesConn
	limit int
}

func (c *shortWriteConn) Write(p []byte) (int, error) {
	if c.limit > 0 && len(p) > c.limit {
		return c.limit, nil
	}
	return len(p), nil
}

func TestDefaultLimits(t *testing.T) {
	got := DefaultLimits()
	if got.MaxActiveStreams != 64 || got.MaxInboundStreams != 32 || got.MaxFrameBytes != 256*1024 ||
		got.PreferredOutboundFrameBytes != 64*1024 || got.MaxStreamWriteQueueBytes != 4*1024*1024 ||
		got.MaxStreamReceiveBytes != 256*1024 ||
		got.MaxSessionReceiveBytes != 16*1024*1024 {
		t.Fatalf("unexpected defaults: %+v", got)
	}
}

func TestValidateLimitsRejectsInvalidRelationships(t *testing.T) {
	if _, err := ValidateLimits(YamuxLimits{MaxActiveStreams: 1, MaxInboundStreams: 2}); err == nil {
		t.Fatal("expected inbound stream limit error")
	}
	if _, err := ValidateLimits(YamuxLimits{MaxFrameBytes: 512 * 1024, MaxStreamReceiveBytes: 256 * 1024}); err == nil {
		t.Fatal("expected frame/receive limit error")
	}
	if _, err := ValidateLimits(YamuxLimits{PreferredOutboundFrameBytes: 64 * 1024, MaxStreamWriteQueueBytes: 32 * 1024}); err != nil {
		t.Fatalf("independent write queue limit was rejected: %v", err)
	}
}

func TestStreamWriteBudgetAdmissionAndRelease(t *testing.T) {
	tracker := newSessionWriteTracker()
	budget := &streamWriteBudget{max: 8, streamID: 1, tracker: tracker}
	if !budget.reserve(8) {
		t.Fatal("exact-limit write was rejected")
	}
	if budget.reserve(1) {
		t.Fatal("overflowing write was accepted")
	}
	if !budget.reserve(0) {
		t.Fatal("zero-length write was rejected")
	}
	budget.release(8)
	if !budget.reserve(8) {
		t.Fatal("released budget was not reusable")
	}
}

func TestStreamWriteTrackerDropsDrainedStreams(t *testing.T) {
	tracker := newSessionWriteTracker()
	const streamCount = 10_000
	for streamID := uint32(1); streamID <= streamCount; streamID++ {
		budget := &streamWriteBudget{max: 1, streamID: streamID, tracker: tracker}
		if !budget.reserve(1) {
			t.Fatalf("reserve stream %d", streamID)
		}
		tracker.release(streamID, 1)
	}

	tracker.mu.RLock()
	tracked := len(tracker.streams)
	tracker.mu.RUnlock()
	if tracked != 0 {
		t.Fatalf("tracked drained streams = %d, want 0", tracked)
	}
}

func TestFrameLimitConnTracksFragmentedAndCoalescedWrites(t *testing.T) {
	tracker := newSessionWriteTracker()
	first := &streamWriteBudget{max: 3, streamID: 1, tracker: tracker}
	second := &streamWriteBudget{max: 2, streamID: 3, tracker: tracker}
	if !first.reserve(3) || !second.reserve(2) {
		t.Fatal("reserve test budgets")
	}
	firstFrame := yamuxDataFrame(1, []byte{1, 2, 3})
	secondFrame := yamuxDataFrame(3, []byte{4, 5})
	conn := &frameLimitConn{Conn: &shortWriteConn{}, writeTracker: tracker}

	if n, err := conn.Write(firstFrame[:5]); err != nil || n != 5 {
		t.Fatalf("fragmented header write = %d, %v", n, err)
	}
	if pendingWriteBytes(first) != 3 {
		t.Fatalf("header fragment released data budget")
	}
	combined := append(append([]byte{}, firstFrame[5:]...), secondFrame...)
	if n, err := conn.Write(combined); err != nil || n != len(combined) {
		t.Fatalf("coalesced write = %d, %v", n, err)
	}
	if pendingWriteBytes(first) != 0 || pendingWriteBytes(second) != 0 {
		t.Fatalf("coalesced frames did not drain both budgets")
	}
}

func TestFrameLimitConnTracksOnlyShortWriteBytes(t *testing.T) {
	tracker := newSessionWriteTracker()
	budget := &streamWriteBudget{max: 4, streamID: 1, tracker: tracker}
	if !budget.reserve(4) {
		t.Fatal("reserve test budget")
	}
	frame := yamuxDataFrame(1, []byte{1, 2, 3, 4})
	underlying := &shortWriteConn{limit: 14}
	conn := &frameLimitConn{Conn: underlying, writeTracker: tracker}

	n, err := conn.Write(frame)
	if err != nil || n != 14 {
		t.Fatalf("short write = %d, %v", n, err)
	}
	if pending := pendingWriteBytes(budget); pending != 2 {
		t.Fatalf("pending after short write = %d, want 2", pending)
	}
	underlying.limit = 0
	if n, err := conn.Write(frame[14:]); err != nil || n != 2 {
		t.Fatalf("short-write remainder = %d, %v", n, err)
	}
	if pending := pendingWriteBytes(budget); pending != 0 {
		t.Fatalf("pending after remainder = %d, want 0", pending)
	}
}

func yamuxDataFrame(streamID uint32, payload []byte) []byte {
	frame := make([]byte, 12+len(payload))
	frame[1] = 0
	binary.BigEndian.PutUint32(frame[4:8], streamID)
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(payload)))
	copy(frame[12:], payload)
	return frame
}

func pendingWriteBytes(budget *streamWriteBudget) int {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budget.pending
}

func TestStreamWriteBudgetTracksQueuedTransportData(t *testing.T) {
	local, remote := net.Pipe()
	client, err := NewClient(local, YamuxLimits{MaxStreamWriteQueueBytes: 8}, LivenessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer remote.Close()
	stream, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte{1}); !errors.Is(err, ErrResourceExhausted) {
		t.Fatalf("write beyond queued transport budget = %v", err)
	}

	go func() { _, _ = io.Copy(io.Discard, remote) }()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := stream.Write([]byte{1}); err == nil {
			break
		} else if !errors.Is(err, ErrResourceExhausted) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("transport drain did not release the stream write budget")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestProbeReturnsACKRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	server, err := NewServer(a, YamuxLimits{}, LivenessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(b, YamuxLimits{}, LivenessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if rtt, err := client.Probe(ctx); err != nil {
		t.Fatalf("Probe() failed: %v", err)
	} else if rtt < 0 {
		t.Fatalf("invalid RTT: %v", rtt)
	}
}

func TestCanceledProbeCallersShareOneBackgroundPing(t *testing.T) {
	local, remote := net.Pipe()
	client, err := NewClient(local, YamuxLimits{}, LivenessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer remote.Close()

	ctx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, err := client.Probe(ctx)
		firstDone <- err
	}()
	firstProbe := waitForActiveProbe(t, client)
	cancel()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("first canceled probe = %v", err)
	}

	for range 100 {
		callerCtx, callerCancel := context.WithTimeout(context.Background(), time.Millisecond)
		_, err := client.Probe(callerCtx)
		callerCancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("canceled shared probe = %v", err)
		}
	}
	client.probeMu.Lock()
	activeProbe := client.probe
	client.probeMu.Unlock()
	if activeProbe != firstProbe {
		t.Fatal("canceled callers started another background ping")
	}

	if err := remote.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		client.probeMu.Lock()
		active := client.probe
		client.probeMu.Unlock()
		if active == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background ping did not finish after transport close")
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForActiveProbe(t *testing.T, session *Session) *probeCall {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		session.probeMu.Lock()
		probe := session.probe
		session.probeMu.Unlock()
		if probe != nil {
			return probe
		}
		if time.Now().After(deadline) {
			t.Fatal("probe did not start")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestOpenStreamContextCancelsBlockedOpen(t *testing.T) {
	local, remote := net.Pipe()
	client, err := NewClient(local, YamuxLimits{MaxActiveStreams: 2, MaxInboundStreams: 1}, LivenessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer remote.Close()
	first, err := client.OpenStream()
	if err != nil {
		t.Fatalf("first OpenStream() failed: %v", err)
	}
	defer first.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := client.OpenStreamContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("OpenStreamContext() error = %v, want deadline exceeded", err)
	}
}

func TestAutomaticLivenessFailureClosesSession(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	client, err := NewClient(a, YamuxLimits{}, LivenessOptions{
		Interval: 10 * time.Millisecond,
		Timeout:  20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-client.LivenessFailures():
		if !errors.Is(err, ErrLivenessTimeout) {
			t.Fatalf("liveness failure = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("automatic liveness did not fail")
	}
	select {
	case <-client.CloseChan():
	case <-time.After(time.Second):
		t.Fatal("session remained open after liveness failure")
	}
}

func TestAutomaticLivenessRemainsHealthyAcrossIntervals(t *testing.T) {
	a, b := net.Pipe()
	options := LivenessOptions{Interval: 10 * time.Millisecond, Timeout: 100 * time.Millisecond}
	server, err := NewServer(a, YamuxLimits{}, options)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(b, YamuxLimits{}, options)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer client.Close()

	timer := time.NewTimer(80 * time.Millisecond)
	defer timer.Stop()
	select {
	case err := <-client.LivenessFailures():
		t.Fatalf("healthy client liveness failed: %v", err)
	case err := <-server.LivenessFailures():
		t.Fatalf("healthy server liveness failed: %v", err)
	case <-timer.C:
	}
	select {
	case <-client.CloseChan():
		t.Fatal("healthy client closed")
	default:
	}
	select {
	case <-server.CloseChan():
		t.Fatal("healthy server closed")
	default:
	}
}
