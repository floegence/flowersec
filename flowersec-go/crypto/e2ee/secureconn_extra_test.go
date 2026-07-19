package e2ee

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

type recordingTransport struct {
	readCh  chan []byte
	writeCh chan []byte
}

type gatedRecordingTransport struct {
	writes    chan []byte
	releases  chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func newGatedRecordingTransport() *gatedRecordingTransport {
	return &gatedRecordingTransport{
		writes:   make(chan []byte, 4),
		releases: make(chan struct{}, 4),
		closed:   make(chan struct{}),
	}
}

func (t *gatedRecordingTransport) ReadBinary(_ context.Context) ([]byte, error) {
	<-t.closed
	return nil, io.EOF
}

func (t *gatedRecordingTransport) WriteBinary(ctx context.Context, frame []byte) error {
	t.writes <- append([]byte(nil), frame...)
	select {
	case <-t.releases:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-t.closed:
		return io.EOF
	}
}

func (t *gatedRecordingTransport) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

func newRecordingTransport() *recordingTransport {
	return &recordingTransport{readCh: make(chan []byte, 4), writeCh: make(chan []byte, 4)}
}

func (t *recordingTransport) ReadBinary(_ context.Context) ([]byte, error) {
	b, ok := <-t.readCh
	if !ok {
		return nil, io.EOF
	}
	return b, nil
}

func (t *recordingTransport) WriteBinary(_ context.Context, b []byte) error {
	t.writeCh <- b
	return nil
}

func (t *recordingTransport) Close() error {
	close(t.readCh)
	close(t.writeCh)
	return nil
}

func TestSecureChannelPingAndRekey(t *testing.T) {
	tr := newRecordingTransport()
	var key [32]byte
	var nonce [4]byte
	key[0] = 1
	nonce[0] = 2
	keys := RecordKeyState{
		SendKey:      key,
		RecvKey:      key,
		SendNoncePre: nonce,
		RecvNoncePre: nonce,
		RekeyBase:    key,
		Transcript:   key,
		SendDir:      DirC2S,
		RecvDir:      DirS2C,
		SendSeq:      1,
		RecvSeq:      1,
	}
	conn := NewSecureChannel(tr, keys, 1<<20, 0)
	defer conn.Close()

	if err := conn.Ping(); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}
	if err := conn.Rekey(); err != nil {
		t.Fatalf("Rekey failed: %v", err)
	}

	ping := <-tr.writeCh
	rekey := <-tr.writeCh
	if _, _, _, err := DecryptRecord(key, nonce, ping, 1, 1<<20); err != nil {
		t.Fatalf("decrypt ping failed: %v", err)
	}
	flags, seq, _, err := DecryptRecord(key, nonce, rekey, 2, 1<<20)
	if err != nil {
		t.Fatalf("decrypt rekey failed: %v", err)
	}
	if flags != RecordFlagRekey {
		t.Fatalf("expected rekey flag, got %v", flags)
	}
	if seq != 2 {
		t.Fatalf("expected seq 2, got %d", seq)
	}
}

func TestSecureChannelWriteSplitsFrames(t *testing.T) {
	tr := newRecordingTransport()
	var key [32]byte
	var nonce [4]byte
	keys := RecordKeyState{SendKey: key, RecvKey: key, SendNoncePre: nonce, RecvNoncePre: nonce, SendDir: DirC2S, RecvDir: DirS2C}
	conn := NewSecureChannel(tr, keys, 40, 0)
	defer conn.Close()

	payload := make([]byte, 20)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if got := len(tr.writeCh); got < 2 {
		t.Fatalf("expected multiple frames, got %d", got)
	}
}

func TestSecureChannelConcurrentWritesRemainContiguousAcrossRecords(t *testing.T) {
	tr := newGatedRecordingTransport()
	var key [32]byte
	var nonce [4]byte
	key[0] = 1
	nonce[0] = 2
	keys := RecordKeyState{
		SendKey:      key,
		RecvKey:      key,
		SendNoncePre: nonce,
		RecvNoncePre: nonce,
		SendDir:      DirC2S,
		RecvDir:      DirS2C,
		SendSeq:      1,
		RecvSeq:      1,
	}
	conn := NewSecureChannel(tr, keys, 1<<20, 0)
	defer conn.Close()
	if err := conn.SetOutboundRecordChunkBytes(4); err != nil {
		t.Fatalf("SetOutboundRecordChunkBytes failed: %v", err)
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("AAAABBBB"))
		firstDone <- err
	}()
	firstFrame := <-tr.writes

	secondStarted := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondStarted)
		_, err := conn.Write([]byte("CCCC"))
		secondDone <- err
	}()
	<-secondStarted

	// Give the second goroutine time to contend while the first record is blocked.
	// It must not reserve a sequence number until the first logical Write completes.
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		conn.sendMu.Lock()
		nextSeq := conn.keys.SendSeq
		conn.sendMu.Unlock()
		if nextSeq != 2 {
			t.Fatalf("concurrent Write reserved sequence %d before the first Write completed", nextSeq)
		}
		time.Sleep(time.Millisecond)
	}

	tr.releases <- struct{}{}
	secondFrame := <-tr.writes
	tr.releases <- struct{}{}
	thirdFrame := <-tr.writes
	tr.releases <- struct{}{}

	for name, errCh := range map[string]<-chan error{
		"first":  firstDone,
		"second": secondDone,
	} {
		if err := <-errCh; err != nil {
			t.Fatalf("%s Write failed: %v", name, err)
		}
	}

	for i, test := range []struct {
		frame []byte
		want  string
	}{
		{frame: firstFrame, want: "AAAA"},
		{frame: secondFrame, want: "BBBB"},
		{frame: thirdFrame, want: "CCCC"},
	} {
		_, _, plain, err := DecryptRecord(key, nonce, test.frame, uint64(i+1), 1<<20)
		if err != nil {
			t.Fatalf("decrypt frame %d failed: %v", i, err)
		}
		if got := string(plain); got != test.want {
			t.Fatalf("frame %d payload = %q, want %q", i, got, test.want)
		}
	}
}

func TestSecureChannelOutboundAdmissionCountsWaitingLogicalWrites(t *testing.T) {
	tr := newGatedRecordingTransport()
	var key [32]byte
	var nonce [4]byte
	keys := RecordKeyState{
		SendKey: key, RecvKey: key, SendNoncePre: nonce, RecvNoncePre: nonce,
		SendDir: DirC2S, RecvDir: DirS2C, SendSeq: 1, RecvSeq: 1,
	}
	conn := NewSecureChannel(tr, keys, 1<<20, 0)
	defer conn.Close()
	if err := conn.SetMaxOutboundBufferedBytes(8); err != nil {
		t.Fatal(err)
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("12345"))
		firstDone <- err
	}()
	select {
	case <-tr.writes:
	case <-time.After(time.Second):
		t.Fatal("first write did not reach transport")
	}

	if _, err := conn.Write([]byte("6789")); !errors.Is(err, ErrOutboundBufferExceeded) {
		t.Fatalf("aggregate overflow error = %v", err)
	}
	tr.releases <- struct{}{}
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}

	exactDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("12345678"))
		exactDone <- err
	}()
	select {
	case <-tr.writes:
	case <-time.After(time.Second):
		t.Fatal("exact-limit write did not reach transport")
	}
	tr.releases <- struct{}{}
	if err := <-exactDone; err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(nil); err != nil || n != 0 {
		t.Fatalf("zero-length Write() = %d, %v", n, err)
	}
	conn.sendMu.Lock()
	pending := conn.pendingOutboundBytes
	conn.sendMu.Unlock()
	if pending != 0 {
		t.Fatalf("pendingOutboundBytes = %d", pending)
	}
}

func TestSecureChannelOutboundAdmissionReleasesAfterFailure(t *testing.T) {
	tr := newGatedRecordingTransport()
	var key [32]byte
	var nonce [4]byte
	conn := NewSecureChannel(tr, RecordKeyState{
		SendKey: key, RecvKey: key, SendNoncePre: nonce, RecvNoncePre: nonce,
		SendDir: DirC2S, RecvDir: DirS2C, SendSeq: 1, RecvSeq: 1,
	}, 1<<20, 0)
	if err := conn.SetMaxOutboundBufferedBytes(8); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("12345678"))
		done <- err
	}()
	select {
	case <-tr.writes:
	case <-time.After(time.Second):
		t.Fatal("write did not reach transport")
	}
	_ = tr.Close()
	if err := <-done; err == nil {
		t.Fatal("expected write failure")
	}
	conn.sendMu.Lock()
	pending := conn.pendingOutboundBytes
	conn.sendMu.Unlock()
	if pending != 0 {
		t.Fatalf("pendingOutboundBytes = %d", pending)
	}
}

func TestSecureChannelOutboundAdmissionSharedVectors(t *testing.T) {
	var vectors struct {
		Version int `json:"version"`
		Cases   []struct {
			ID         string `json:"id"`
			Limit      int    `json:"limit"`
			Unfinished []int  `json:"unfinished"`
			Next       int    `json:"next"`
			Result     string `json:"result"`
		} `json:"outbound_buffer_admission"`
	}
	readRuntimeContractVectors(t, &vectors)
	if vectors.Version != 1 {
		t.Fatalf("version = %d", vectors.Version)
	}
	for _, test := range vectors.Cases {
		t.Run(test.ID, func(t *testing.T) {
			pending := 0
			for _, n := range test.Unfinished {
				pending += n
			}
			channel := &SecureChannel{
				maxOutboundBufferedBytes: test.Limit,
				pendingOutboundBytes:     pending,
			}
			err := channel.reserveOutboundBytes(test.Next)
			if test.Result == "accepted" {
				if err != nil {
					t.Fatal(err)
				}
				channel.releaseOutboundBytes(test.Next)
				return
			}
			if !errors.Is(err, ErrOutboundBufferExceeded) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func readRuntimeContractVectors(t *testing.T, value any) {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	data, err := os.ReadFile(filepath.Join(root, "testdata/runtime_contract_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatal(err)
	}
}

func TestSecureChannelWriterStopsWhenIdleAndRestartsInOrder(t *testing.T) {
	tr := newRecordingTransport()
	var key [32]byte
	var nonce [4]byte
	key[0] = 1
	nonce[0] = 2
	keys := RecordKeyState{
		SendKey:      key,
		RecvKey:      key,
		SendNoncePre: nonce,
		RecvNoncePre: nonce,
		SendDir:      DirC2S,
		RecvDir:      DirS2C,
		SendSeq:      1,
		RecvSeq:      1,
	}
	conn := NewSecureChannel(tr, keys, 1<<20, 0)
	defer conn.Close()

	writeAndWaitForIdle := func(payload string) {
		t.Helper()
		if _, err := conn.Write([]byte(payload)); err != nil {
			t.Fatalf("Write(%q) failed: %v", payload, err)
		}
		deadline := time.Now().Add(time.Second)
		for {
			conn.sendMu.Lock()
			running := conn.sendRunning
			queued := len(conn.sendQueue)
			conn.sendMu.Unlock()
			if !running && queued == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("writer did not become idle after Write(%q)", payload)
			}
			time.Sleep(time.Millisecond)
		}
	}

	writeAndWaitForIdle("first")
	writeAndWaitForIdle("second")

	for i, want := range []string{"first", "second"} {
		frame := <-tr.writeCh
		_, seq, plain, err := DecryptRecord(key, nonce, frame, uint64(i+1), 1<<20)
		if err != nil {
			t.Fatalf("decrypt frame %d failed: %v", i, err)
		}
		if seq != uint64(i+1) {
			t.Fatalf("frame %d sequence = %d, want %d", i, seq, i+1)
		}
		if got := string(plain); got != want {
			t.Fatalf("frame %d payload = %q, want %q", i, got, want)
		}
	}
}

func TestSecureChannelPingUsesKeepaliveFlagAndAdvancesSeq(t *testing.T) {
	tr := newRecordingTransport()
	var key [32]byte
	var nonce [4]byte
	keys := RecordKeyState{SendKey: key, RecvKey: key, SendNoncePre: nonce, RecvNoncePre: nonce, SendDir: DirC2S, RecvDir: DirS2C, SendSeq: 7, RecvSeq: 1}
	conn := NewSecureChannel(tr, keys, 1<<20, 0)
	defer conn.Close()

	if err := conn.Ping(); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}

	frame := <-tr.writeCh
	flags, seq, plain, err := DecryptRecord(key, nonce, frame, 7, 1<<20)
	if err != nil {
		t.Fatalf("decrypt ping failed: %v", err)
	}
	if flags != RecordFlagPing {
		t.Fatalf("expected ping flag, got %v", flags)
	}
	if seq != 7 {
		t.Fatalf("expected seq 7, got %d", seq)
	}
	if len(plain) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(plain))
	}
}

func TestSecureChannelDefaultsOutboundRecordsTo64KiB(t *testing.T) {
	tr := newRecordingTransport()
	var key [32]byte
	key[0] = 1
	keys := RecordKeyState{SendKey: key, RecvKey: key, SendSeq: 1, RecvSeq: 1}
	conn := NewSecureChannel(tr, keys, 1<<20, 0)
	defer conn.Close()

	payload := make([]byte, DefaultOutboundRecordChunkBytes+1)
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		done <- err
	}()

	first := <-tr.writeCh
	second := <-tr.writeCh
	if got := len(first); got != recordHeaderLen+16+DefaultOutboundRecordChunkBytes {
		t.Fatalf("first record bytes = %d", got)
	}
	if got := len(second); got != recordHeaderLen+16+1 {
		t.Fatalf("second record bytes = %d", got)
	}
	if err := <-done; err != nil {
		t.Fatalf("Write() failed: %v", err)
	}
}

func TestSecureChannelPingHonorsWriteDeadline(t *testing.T) {
	tr := newCancelAwareWriteTransport()
	var key [32]byte
	var nonce [4]byte
	keys := RecordKeyState{SendKey: key, RecvKey: key, SendNoncePre: nonce, RecvNoncePre: nonce, SendDir: DirC2S, RecvDir: DirS2C, SendSeq: 1, RecvSeq: 1}
	conn := NewSecureChannel(tr, keys, 1<<20, 0)
	defer conn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- conn.Ping()
	}()

	select {
	case <-tr.writeCh:
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for ping write to start")
	}

	_ = conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("expected timeout error")
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("expected deadline exceeded, got %T: %v", err, err)
		}
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for Ping to return")
	}
}

func TestSecureChannelReadBlackholeUnblocksOnClose(t *testing.T) {
	tr := newNeverReadTransport()
	var key [32]byte
	var nonce [4]byte
	keys := RecordKeyState{SendKey: key, RecvKey: key, SendNoncePre: nonce, RecvNoncePre: nonce, SendDir: DirC2S, RecvDir: DirS2C, SendSeq: 1, RecvSeq: 1}
	conn := NewSecureChannel(tr, keys, 1<<20, 0)

	readErr := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := conn.Read(b[:])
		readErr <- err
	}()

	select {
	case <-tr.readStarted:
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for blackholed read to start")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	select {
	case err := <-readErr:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("expected EOF after close, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("Read did not unblock after Close")
	}
}

func TestSecureChannelWriteBlockingUnblocksOnClose(t *testing.T) {
	tr := newCancelAwareWriteTransport()
	var key [32]byte
	var nonce [4]byte
	keys := RecordKeyState{SendKey: key, RecvKey: key, SendNoncePre: nonce, RecvNoncePre: nonce, SendDir: DirC2S, RecvDir: DirS2C, SendSeq: 1, RecvSeq: 1}
	conn := NewSecureChannel(tr, keys, 1<<20, 0)

	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("hello"))
		errCh <- err
	}()

	select {
	case <-tr.writeCh:
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for blocking write to start")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("expected write error after Close")
		}
	case <-time.After(time.Second):
		t.Fatalf("Write did not unblock after Close")
	}
}

type neverReadTransport struct {
	readStarted chan struct{}
	closed      chan struct{}
	once        sync.Once
	closeMu     sync.Mutex
	closeCalls  int
}

func newNeverReadTransport() *neverReadTransport {
	return &neverReadTransport{
		readStarted: make(chan struct{}),
		closed:      make(chan struct{}),
	}
}

func (t *neverReadTransport) ReadBinary(_ context.Context) ([]byte, error) {
	t.once.Do(func() { close(t.readStarted) })
	<-t.closed
	return nil, io.EOF
}

func (t *neverReadTransport) WriteBinary(_ context.Context, _ []byte) error {
	return nil
}

func (t *neverReadTransport) Close() error {
	t.closeMu.Lock()
	t.closeCalls++
	t.closeMu.Unlock()
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	return nil
}

func (t *neverReadTransport) closeCount() int {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	return t.closeCalls
}

func TestSecureChannelCloseClearsKeysAndClosesTransportOnce(t *testing.T) {
	tr := newNeverReadTransport()
	keys := RecordKeyState{
		SendKey:      [32]byte{1},
		RecvKey:      [32]byte{2},
		SendNoncePre: [4]byte{3},
		RecvNoncePre: [4]byte{4},
		RekeyBase:    [32]byte{5},
		Transcript:   [32]byte{6},
		SendDir:      DirC2S,
		RecvDir:      DirS2C,
		SendSeq:      1,
		RecvSeq:      1,
	}
	conn := NewSecureChannel(tr, keys, 1<<20, 0)
	select {
	case <-tr.readStarted:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for read loop")
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	conn.sendMu.Lock()
	conn.keyMu.Lock()
	got := conn.keys
	conn.keyMu.Unlock()
	conn.sendMu.Unlock()
	if got != (RecordKeyState{}) {
		t.Fatalf("key state was retained after close: %+v", got)
	}
	if got := tr.closeCount(); got != 1 {
		t.Fatalf("transport close count = %d, want 1", got)
	}
}

func TestSecureChannelConcurrentCloseWaitsForKeyCleanup(t *testing.T) {
	tr := newNeverReadTransport()
	conn := NewSecureChannel(tr, RecordKeyState{SendKey: [32]byte{1}}, 1<<20, 0)
	select {
	case <-tr.readStarted:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for read loop")
	}

	conn.sendMu.Lock()
	firstDone := make(chan error, 1)
	go func() { firstDone <- conn.Close() }()
	deadline := time.Now().Add(time.Second)
	for {
		conn.mu.Lock()
		closed := conn.closed
		conn.mu.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			conn.sendMu.Unlock()
			t.Fatal("first Close did not enter shutdown")
		}
		runtime.Gosched()
	}

	secondDone := make(chan error, 1)
	go func() { secondDone <- conn.Close() }()
	select {
	case err := <-secondDone:
		conn.sendMu.Unlock()
		t.Fatalf("concurrent Close returned before cleanup completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	conn.sendMu.Unlock()
	for index, done := range []<-chan error{firstDone, secondDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Close %d failed: %v", index+1, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("Close %d did not finish", index+1)
		}
	}
	conn.sendMu.Lock()
	conn.keyMu.Lock()
	got := conn.keys
	conn.keyMu.Unlock()
	conn.sendMu.Unlock()
	if got != (RecordKeyState{}) {
		t.Fatalf("key state was retained after concurrent close: %+v", got)
	}
	if got := tr.closeCount(); got != 1 {
		t.Fatalf("transport close count = %d, want 1", got)
	}
}

type blockingMessageTransport struct {
	writeStarted sync.Once
	writeCh      chan struct{}
	releaseCh    chan struct{}
	closed       chan struct{}
}

func newBlockingMessageTransport() *blockingMessageTransport {
	return &blockingMessageTransport{
		writeCh:   make(chan struct{}),
		releaseCh: make(chan struct{}),
		closed:    make(chan struct{}),
	}
}

func (t *blockingMessageTransport) ReadMessage(_ context.Context) (int, []byte, error) {
	<-t.closed
	return 0, nil, io.EOF
}

func (t *blockingMessageTransport) WriteMessage(ctx context.Context, _ int, _ []byte) error {
	t.writeStarted.Do(func() { close(t.writeCh) })
	select {
	case <-t.releaseCh:
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return nil
	case <-ctx.Done():
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		return ctx.Err()
	case <-t.closed:
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return io.EOF
	}
}

func (t *blockingMessageTransport) Close() error {
	select {
	case <-t.closed:
		return nil
	default:
		close(t.closed)
		return nil
	}
}

func TestWebSocketMessageTransportWriteBinaryHonorsContextCancelWithoutDeadline(t *testing.T) {
	tr := newBlockingMessageTransport()
	transport := NewWebSocketMessageTransport(tr)

	writeCtx, writeCancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- transport.WriteBinary(writeCtx, []byte("hello"))
	}()

	select {
	case <-tr.writeCh:
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for WriteBinary to start")
	}

	writeCancel()

	select {
	case err := <-errCh:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("WriteBinary did not return after context cancellation")
	}
}

func TestSecureChannelReadRejectsBadFlag(t *testing.T) {
	tr := newRecordingTransport()
	var key [32]byte
	var nonce [4]byte
	keys := RecordKeyState{SendKey: key, RecvKey: key, SendNoncePre: nonce, RecvNoncePre: nonce, SendDir: DirC2S, RecvDir: DirS2C, SendSeq: 1, RecvSeq: 1}
	conn := NewSecureChannel(tr, keys, 1<<20, 0)
	defer conn.Close()

	frame, err := EncryptRecord(key, nonce, RecordFlagApp, 1, []byte("hi"), 1<<20)
	if err != nil {
		t.Fatalf("EncryptRecord failed: %v", err)
	}
	frame[5] = 9

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := conn.Read(buf)
		errCh <- err
	}()

	tr.readCh <- frame

	select {
	case err := <-errCh:
		if err == nil || !errors.Is(err, ErrRecordBadFlag) {
			t.Fatalf("expected bad flag error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for read error")
	}
}

func TestSecureChannelRekeyUpdatesSendKey(t *testing.T) {
	tr := newRecordingTransport()
	var key [32]byte
	var nonce [4]byte
	key[0] = 1
	nonce[0] = 2
	keys := RecordKeyState{
		SendKey:      key,
		RecvKey:      key,
		SendNoncePre: nonce,
		RecvNoncePre: nonce,
		RekeyBase:    key,
		Transcript:   key,
		SendDir:      DirC2S,
		RecvDir:      DirS2C,
		SendSeq:      1,
		RecvSeq:      1,
	}
	conn := NewSecureChannel(tr, keys, 1<<20, 0)
	defer conn.Close()

	if err := conn.Rekey(); err != nil {
		t.Fatalf("Rekey failed: %v", err)
	}
	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	rekey := <-tr.writeCh
	app := <-tr.writeCh
	_, _, _, err := DecryptRecord(key, nonce, rekey, 1, 1<<20)
	if err != nil {
		t.Fatalf("decrypt rekey failed: %v", err)
	}
	newKey, err := DeriveRekeyKey(key, key, 1, DirC2S)
	if err != nil {
		t.Fatalf("DeriveRekeyKey failed: %v", err)
	}
	if _, _, _, err := DecryptRecord(newKey, nonce, app, 2, 1<<20); err != nil {
		t.Fatalf("expected decrypt with new key to succeed: %v", err)
	}
	if _, _, _, err := DecryptRecord(key, nonce, app, 2, 1<<20); err == nil {
		t.Fatalf("expected decrypt with old key to fail")
	}
}

func TestSecureChannelSendSeqExhaustionFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		call func(*SecureChannel) error
	}{
		{
			name: "write",
			call: func(conn *SecureChannel) error {
				_, err := conn.Write([]byte("hi"))
				return err
			},
		},
		{
			name: "ping",
			call: func(conn *SecureChannel) error {
				return conn.Ping()
			},
		},
		{
			name: "rekey",
			call: func(conn *SecureChannel) error {
				return conn.Rekey()
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tr := newNeverReadTransport()
			var key [32]byte
			var nonce [4]byte
			keys := RecordKeyState{
				SendKey:      key,
				RecvKey:      key,
				SendNoncePre: nonce,
				RecvNoncePre: nonce,
				SendDir:      DirC2S,
				RecvDir:      DirS2C,
				SendSeq:      MaxRecordSeq,
				RecvSeq:      1,
			}
			conn := NewSecureChannel(tr, keys, 1<<20, 0)

			err := tt.call(conn)
			if !errors.Is(err, ErrRecordSeqExhausted) {
				t.Fatalf("expected ErrRecordSeqExhausted, got %v", err)
			}
			if err := conn.Ping(); !errors.Is(err, ErrRecordSeqExhausted) {
				t.Fatalf("expected sticky ErrRecordSeqExhausted, got %v", err)
			}
		})
	}
}

func TestSecureChannelRecvSeqExhaustionFailsClosed(t *testing.T) {
	t.Parallel()

	tr := newRecordingTransport()
	var key [32]byte
	var nonce [4]byte
	keys := RecordKeyState{
		SendKey:      key,
		RecvKey:      key,
		SendNoncePre: nonce,
		RecvNoncePre: nonce,
		SendDir:      DirC2S,
		RecvDir:      DirS2C,
		SendSeq:      1,
		RecvSeq:      MaxRecordSeq,
	}
	conn := NewSecureChannel(tr, keys, 1<<20, 0)
	defer conn.Close()

	frame, err := EncryptRecord(key, nonce, RecordFlagApp, MaxRecordSeq, []byte("hi"), 1<<20)
	if err != nil {
		t.Fatalf("EncryptRecord failed: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 2)
		_, err := conn.Read(buf)
		errCh <- err
	}()

	tr.readCh <- frame

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrRecordSeqExhausted) {
			t.Fatalf("expected ErrRecordSeqExhausted, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for read error")
	}
}
