package jsonframe

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type errWriter struct{}

func (errWriter) Write(_ []byte) (int, error) { return 0, errors.New("write failed") }

func TestReadJSONFrameTooLarge(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0, 0, 0, 10, 0, 0, 0, 0, 0, 0})
	if _, err := ReadJSONFrame(buf, 4); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestWriteJSONFrameWriterError(t *testing.T) {
	if err := WriteJSONFrame(errWriter{}, map[string]any{"ok": true}); err == nil {
		t.Fatal("expected error")
	}
}

func TestReadJSONFrameEOF(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	if _, err := ReadJSONFrame(buf, 1<<20); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}
