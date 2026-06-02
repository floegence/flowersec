package e2ee

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

type recordingTransport struct {
	readCh  chan []byte
	writeCh chan []byte
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
