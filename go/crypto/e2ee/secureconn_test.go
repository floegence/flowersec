package e2ee

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

type testBinaryTransport struct {
	readCh chan []byte
}

func (t *testBinaryTransport) ReadBinary(_ context.Context) ([]byte, error) {
	b, ok := <-t.readCh
	if !ok {
		return nil, io.EOF
	}
	return b, nil
}

func (t *testBinaryTransport) WriteBinary(_ context.Context, _ []byte) error { return nil }

func (t *testBinaryTransport) Close() error {
	close(t.readCh)
	return nil
}

func TestSecureConnRecvBufferExceeded(t *testing.T) {
	var recvKey [32]byte
	var noncePre [4]byte
	recvKey[0] = 1
	noncePre[0] = 2

	frame, err := EncryptRecord(recvKey, noncePre, RecordFlagApp, 1, make([]byte, 10), 1<<20)
	if err != nil {
		t.Fatalf("EncryptRecord failed: %v", err)
	}

	tr := &testBinaryTransport{readCh: make(chan []byte, 1)}
	conn := NewSecureConn(tr, RecordKeyState{
		RecvKey:      recvKey,
		RecvNoncePre: noncePre,
		RecvSeq:      1,
	}, 1<<20, 5)
	defer conn.Close()

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := conn.Read(buf)
		errCh <- err
	}()

	tr.readCh <- frame

	select {
	case got := <-errCh:
		if !errors.Is(got, ErrRecvBufferExceeded) {
			t.Fatalf("expected ErrRecvBufferExceeded, got %v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for read error")
	}
}
