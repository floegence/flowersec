package weaknet

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestConnPumpPreservesStreamOrderAcrossJitterAndRateLimits(t *testing.T) {
	expected := Counters{
		InputUnits: 4, InputBytes: 4,
		OutputUnits: 3, OutputBytes: 4,
		DelayUnits: 4, JitterUnits: 2, RateLimitedUnits: 1,
		OutageUnits: 1, CoalescedUnits: 2, HalfCloses: 1,
	}
	relay, err := NewByteRelay(ByteProfile{
		Phase: "conn-pump", Direction: ClientToServer, Seed: 42,
		Delay: time.Millisecond, JitterScript: []time.Duration{0, 2 * time.Millisecond},
		Rate:          RateLimit{BytesPerSecond: 2, BurstBytes: 2},
		Outages:       []TimedOutage{{Ordinals: OrdinalRange{First: 3, Last: 3}, Duration: time.Second}},
		CoalesceBytes: 2, RequireHalfClose: true, Expected: &expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	inputWriter, source := tcpPair(t)
	destination, outputReader := tcpPair(t)
	clock := newInstantPumpClock()
	pump, err := NewConnPump(source, destination, relay, PumpOptions{Clock: clock, ReadBufferBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- pump.Run(context.Background()) }()

	if _, err := inputWriter.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	if err := inputWriter.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(outputReader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("abcd")) {
		t.Fatalf("relayed bytes = %q, want exact source order", payload)
	}
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := relay.Verify(); err != nil {
		t.Fatalf("verify: %v; report=%+v", err, relay.Report())
	}
	if got := len(clock.Deadlines()); got != 3 {
		t.Fatalf("clock waits = %d, want 3", got)
	}
}

func TestConnPumpCancellationUnblocksRead(t *testing.T) {
	relay, err := NewByteRelay(ByteProfile{
		Phase: "conn-cancel", Direction: ServerToClient, Seed: 42, Expected: &Counters{},
	})
	if err != nil {
		t.Fatal(err)
	}
	inputPeer, source := net.Pipe()
	destination, outputPeer := net.Pipe()
	t.Cleanup(func() { _ = inputPeer.Close() })
	t.Cleanup(func() { _ = outputPeer.Close() })
	pump, err := NewConnPump(source, destination, relay, PumpOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- pump.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not unblock Conn.Read")
	}
	if _, err := inputPeer.Write([]byte{1}); err == nil {
		t.Fatal("source peer remained writable after canceled pump")
	}
}

func TestConnPumpCloseUnblocksBlockedDestinationWrite(t *testing.T) {
	expected := Counters{InputUnits: 1, InputBytes: 1024, OutputUnits: 1, OutputBytes: 1024}
	relay, err := NewByteRelay(ByteProfile{
		Phase: "conn-blocked-write", Direction: ClientToServer, Seed: 42,
		BackpressureBytes: 1024, Expected: &expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	inputPeer, source := net.Pipe()
	destination, outputPeer := net.Pipe()
	t.Cleanup(func() { _ = inputPeer.Close() })
	t.Cleanup(func() { _ = outputPeer.Close() })
	pump, err := NewConnPump(source, destination, relay, PumpOptions{ReadBufferBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- pump.Run(context.Background()) }()
	written := make(chan error, 1)
	go func() {
		_, err := inputPeer.Write(make([]byte, 1024))
		written <- err
	}()
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if err := pump.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrPumpClosed) {
			t.Fatalf("Run close error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ConnPump.Close did not unblock destination Write")
	}
	if err := relay.verifyDrained(); err != nil {
		t.Fatalf("relay retained delivery state after blocked write cancellation: %v", err)
	}
	report := relay.Report().Actual
	if report.OutputUnits != 0 || report.OutputBytes != 0 || report.CanceledUnits != 1 || report.CanceledBytes != 1024 {
		t.Fatalf("blocked delivery terminal accounting = %+v", report)
	}
	if err := report.CheckByteConservation(); err != nil {
		t.Fatalf("blocked delivery conservation: %v", err)
	}
}

func TestConnPumpAccountsPartialWriteBeforeTerminalError(t *testing.T) {
	expectedErr := errors.New("destination write failed")
	expected := Counters{
		InputUnits: 1, InputBytes: 4,
		OutputBytes: 2, CanceledUnits: 1, CanceledBytes: 2,
	}
	relay, err := NewByteRelay(ByteProfile{
		Phase: "conn-partial-write", Direction: ClientToServer, Seed: 42, Expected: &expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	inputPeer, source := net.Pipe()
	destination := &partialErrorConn{writeBytes: 2, writeErr: expectedErr}
	t.Cleanup(func() { _ = inputPeer.Close() })
	pump, err := NewConnPump(source, destination, relay, PumpOptions{ReadBufferBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- pump.Run(context.Background()) }()
	if _, err := inputPeer.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, expectedErr) {
		t.Fatalf("Run error = %v, want %v", err, expectedErr)
	}
	if got := destination.Bytes(); !bytes.Equal(got, []byte("ab")) {
		t.Fatalf("destination bytes = %q, want %q", got, "ab")
	}
	if err := relay.Verify(); err != nil {
		t.Fatalf("partial write accounting: %v; report=%+v", err, relay.Report())
	}
}

func TestConnPumpAcknowledgesDeliveredPayloadBeforeCloseWriteError(t *testing.T) {
	expectedErr := errors.New("destination half-close failed")
	expected := Counters{
		InputUnits: 2, InputBytes: 4,
		OutputUnits: 1, OutputBytes: 4, CoalescedUnits: 1, HalfCloses: 1,
	}
	relay, err := NewByteRelay(ByteProfile{
		Phase: "conn-close-write-error", Direction: ClientToServer, Seed: 42,
		CoalesceBytes: 8, RequireHalfClose: true, Expected: &expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := newScriptedConn([]byte("da"), []byte("ta"))
	destination := &closeWriteErrorConn{closeWriteErr: expectedErr}
	pump, err := NewConnPump(source, destination, relay, PumpOptions{ReadBufferBytes: 4})
	if err != nil {
		t.Fatal(err)
	}

	if err := pump.Run(context.Background()); !errors.Is(err, expectedErr) {
		t.Fatalf("Run error = %v, want %v", err, expectedErr)
	}
	if got := destination.Bytes(); !bytes.Equal(got, []byte("data")) {
		t.Fatalf("destination bytes = %q, want %q", got, "data")
	}
	if err := relay.Verify(); err != nil {
		t.Fatalf("delivered prefix accounting: %v; report=%+v", err, relay.Report())
	}
}

func TestConnPumpBackpressureCannotDeadlockACoalescedPrefix(t *testing.T) {
	expected := Counters{
		InputUnits: 3, InputBytes: 6,
		OutputUnits: 2, OutputBytes: 6,
		CoalescedUnits: 1, BackpressureUnits: 1, HalfCloses: 1,
	}
	relay, err := NewByteRelay(ByteProfile{
		Phase: "coalesced-backpressure", Direction: ClientToServer, Seed: 42,
		CoalesceBytes: 4, BackpressureBytes: 4, Expected: &expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := newScriptedConn([]byte("abc"), []byte("def"))
	destination, outputPeer := net.Pipe()
	t.Cleanup(func() { _ = outputPeer.Close() })
	clock := newGatePumpClock()
	backpressured := make(chan struct{}, 1)
	pump, err := NewConnPump(source, destination, relay, PumpOptions{
		Clock: clock, ReadBufferBytes: 4,
		OnBackpressure: func() { backpressured <- struct{}{} },
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- pump.Run(context.Background()) }()
	<-clock.started
	select {
	case <-backpressured:
	case <-time.After(time.Second):
		t.Fatal("pump did not expose modeled backpressure")
	}
	close(clock.release)
	payload, err := io.ReadAll(outputPeer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("abcdef")) {
		t.Fatalf("payload = %q, want exact coalesced stream", payload)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := relay.Verify(); err != nil {
		t.Fatalf("verify: %v; report=%+v", err, relay.Report())
	}
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	var server *net.TCPConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		_ = listener.Close()
		_ = client.Close()
		t.Fatal(err)
	case <-time.After(time.Second):
		_ = listener.Close()
		_ = client.Close()
		t.Fatal("TCP accept timed out")
	}
	_ = listener.Close()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

type scriptedConn struct {
	mu     sync.Mutex
	chunks [][]byte
	closed bool
}

type partialErrorConn struct {
	mu         sync.Mutex
	writeBytes int
	writeErr   error
	written    []byte
	closed     bool
}

type closeWriteErrorConn struct {
	mu            sync.Mutex
	written       []byte
	closeWriteErr error
	closed        bool
}

func (*closeWriteErrorConn) Read([]byte) (int, error) { return 0, io.EOF }
func (conn *closeWriteErrorConn) Write(payload []byte) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.closed {
		return 0, net.ErrClosed
	}
	conn.written = append(conn.written, payload...)
	return len(payload), nil
}
func (*closeWriteErrorConn) LocalAddr() net.Addr              { return testAddr("destination") }
func (*closeWriteErrorConn) RemoteAddr() net.Addr             { return testAddr("peer") }
func (*closeWriteErrorConn) SetDeadline(time.Time) error      { return nil }
func (*closeWriteErrorConn) SetReadDeadline(time.Time) error  { return nil }
func (*closeWriteErrorConn) SetWriteDeadline(time.Time) error { return nil }
func (conn *closeWriteErrorConn) CloseWrite() error           { return conn.closeWriteErr }
func (conn *closeWriteErrorConn) Close() error {
	conn.mu.Lock()
	conn.closed = true
	conn.mu.Unlock()
	return nil
}
func (conn *closeWriteErrorConn) Bytes() []byte {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return append([]byte(nil), conn.written...)
}

func (conn *partialErrorConn) Read([]byte) (int, error) { return 0, io.EOF }
func (conn *partialErrorConn) Write(payload []byte) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.closed {
		return 0, net.ErrClosed
	}
	written := conn.writeBytes
	if written > len(payload) {
		written = len(payload)
	}
	conn.written = append(conn.written, payload[:written]...)
	return written, conn.writeErr
}
func (*partialErrorConn) LocalAddr() net.Addr              { return testAddr("destination") }
func (*partialErrorConn) RemoteAddr() net.Addr             { return testAddr("peer") }
func (*partialErrorConn) SetDeadline(time.Time) error      { return nil }
func (*partialErrorConn) SetReadDeadline(time.Time) error  { return nil }
func (*partialErrorConn) SetWriteDeadline(time.Time) error { return nil }
func (conn *partialErrorConn) Close() error {
	conn.mu.Lock()
	conn.closed = true
	conn.mu.Unlock()
	return nil
}
func (conn *partialErrorConn) Bytes() []byte {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return append([]byte(nil), conn.written...)
}

func newScriptedConn(chunks ...[]byte) *scriptedConn {
	copyChunks := make([][]byte, len(chunks))
	for index, chunk := range chunks {
		copyChunks[index] = append([]byte(nil), chunk...)
	}
	return &scriptedConn{chunks: copyChunks}
}

func (conn *scriptedConn) Read(payload []byte) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.closed {
		return 0, net.ErrClosed
	}
	if len(conn.chunks) == 0 {
		return 0, io.EOF
	}
	written := copy(payload, conn.chunks[0])
	conn.chunks[0] = conn.chunks[0][written:]
	if len(conn.chunks[0]) == 0 {
		conn.chunks = conn.chunks[1:]
	}
	return written, nil
}

func (*scriptedConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (*scriptedConn) LocalAddr() net.Addr              { return testAddr("source") }
func (*scriptedConn) RemoteAddr() net.Addr             { return testAddr("peer") }
func (*scriptedConn) SetDeadline(time.Time) error      { return nil }
func (*scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (*scriptedConn) SetWriteDeadline(time.Time) error { return nil }
func (conn *scriptedConn) Close() error {
	conn.mu.Lock()
	conn.closed = true
	conn.mu.Unlock()
	return nil
}

type testAddr string

func (testAddr) Network() string     { return "test" }
func (addr testAddr) String() string { return string(addr) }

type gatePumpClock struct {
	once    sync.Once
	started chan struct{}
	release chan struct{}
	now     time.Time
}

func newGatePumpClock() *gatePumpClock {
	return &gatePumpClock{
		started: make(chan struct{}), release: make(chan struct{}), now: time.Unix(200, 0),
	}
}

func (clock *gatePumpClock) Now() time.Time { return clock.now }

func (clock *gatePumpClock) WaitUntil(ctx context.Context, _ time.Time) error {
	first := false
	clock.once.Do(func() {
		first = true
		close(clock.started)
	})
	if !first {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-clock.release:
		return nil
	}
}
