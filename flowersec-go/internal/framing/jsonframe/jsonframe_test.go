package jsonframe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
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

func TestWriteJSONFrameRejectsOversizedPayloadBeforeWriting(t *testing.T) {
	writer := &countingWriter{}
	err := WriteJSONFrame(writer, strings.Repeat("x", DefaultMaxJSONFrameBytes))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
	if writer.writes != 0 {
		t.Fatalf("writes = %d, want zero", writer.writes)
	}
}

func TestWriteJSONFrameSubmitsOneCompleteFrame(t *testing.T) {
	writer := &countingWriter{}
	if err := WriteJSONFrame(writer, map[string]any{"ok": true}); err != nil {
		t.Fatal(err)
	}
	if writer.writes != 1 {
		t.Fatalf("writes = %d, want one complete frame submission", writer.writes)
	}
	if got := int(binary.BigEndian.Uint32(writer.payload[:4])); got != len(writer.payload)-4 {
		t.Fatalf("frame payload length = %d, want %d", got, len(writer.payload)-4)
	}
}

type countingWriter struct {
	writes  int
	payload []byte
}

func (w *countingWriter) Write(payload []byte) (int, error) {
	w.writes++
	w.payload = append(w.payload, payload...)
	return len(payload), nil
}

func TestReadJSONFrameEOF(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	if _, err := ReadJSONFrame(buf, 1<<20); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}
