package e2ee

import (
	"context"
	"errors"
	"io"
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

func TestSecureConnSendPingAndRekey(t *testing.T) {
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
	conn := NewSecureConn(tr, keys, 1<<20, 0)
	defer conn.Close()

	if err := conn.SendPing(); err != nil {
		t.Fatalf("SendPing failed: %v", err)
	}
	if err := conn.RekeyNow(); err != nil {
		t.Fatalf("RekeyNow failed: %v", err)
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

func TestSecureConnWriteSplitsFrames(t *testing.T) {
	tr := newRecordingTransport()
	var key [32]byte
	var nonce [4]byte
	keys := RecordKeyState{SendKey: key, RecvKey: key, SendNoncePre: nonce, RecvNoncePre: nonce, SendDir: DirC2S, RecvDir: DirS2C}
	conn := NewSecureConn(tr, keys, 40, 0)
	defer conn.Close()

	payload := make([]byte, 20)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if got := len(tr.writeCh); got < 2 {
		t.Fatalf("expected multiple frames, got %d", got)
	}
}

func TestSecureConnReadRejectsBadFlag(t *testing.T) {
	tr := newRecordingTransport()
	var key [32]byte
	var nonce [4]byte
	keys := RecordKeyState{SendKey: key, RecvKey: key, SendNoncePre: nonce, RecvNoncePre: nonce, SendDir: DirC2S, RecvDir: DirS2C, SendSeq: 1, RecvSeq: 1}
	conn := NewSecureConn(tr, keys, 1<<20, 0)
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

func TestSecureConnRekeyUpdatesSendKey(t *testing.T) {
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
	conn := NewSecureConn(tr, keys, 1<<20, 0)
	defer conn.Close()

	if err := conn.RekeyNow(); err != nil {
		t.Fatalf("RekeyNow failed: %v", err)
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
