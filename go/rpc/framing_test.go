package rpc

import (
	"bytes"
	"errors"
	"testing"
)

type errWriter struct{}

func (errWriter) Write(_ []byte) (int, error) { return 0, errors.New("write failed") }

func TestReadJSONFrameTooLarge(t *testing.T) {
	buf := &bytes.Buffer{}
	buf.Write([]byte{0, 0, 0, 5})
	buf.Write([]byte("hello"))
	if _, err := ReadJSONFrame(buf, 4); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected frame too large, got %v", err)
	}
}

func TestWriteJSONFrameWriteError(t *testing.T) {
	if err := WriteJSONFrame(errWriter{}, map[string]any{"ok": true}); err == nil {
		t.Fatalf("expected write error")
	}
}
