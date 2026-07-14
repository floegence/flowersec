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

func TestDefaultLimits(t *testing.T) {
	got := DefaultLimits()
	if got.MaxActiveStreams != 64 || got.MaxInboundStreams != 32 || got.MaxFrameBytes != 256*1024 ||
		got.PreferredOutboundFrameBytes != 64*1024 || got.MaxStreamReceiveBytes != 256*1024 ||
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
