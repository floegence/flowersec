package flowersec

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type proxyFrameWriteRecorder struct {
	writes [][]byte
	short  bool
}

func (w *proxyFrameWriteRecorder) Write(data []byte) (int, error) {
	w.writes = append(w.writes, bytes.Clone(data))
	if w.short {
		return len(data) - 1, nil
	}
	return len(data), nil
}

func TestProxyWebSocketFrameAvoidsHeaderOnlyStreamRecord(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte("screen frame")} {
		writer := new(proxyFrameWriteRecorder)
		if err := writeProxyWebSocketFrame(writer, 2, payload, 1024); err != nil {
			t.Fatal(err)
		}
		if len(writer.writes) != 1 {
			t.Fatalf("one proxy frame produced %d encrypted stream records", len(writer.writes))
		}
		opcode, decoded, err := readProxyWebSocketFrame(bytes.NewReader(writer.writes[0]), 1024)
		if err != nil || opcode != 2 || !bytes.Equal(decoded, payload) {
			t.Fatalf("wire bytes changed: opcode=%d payload=%q error=%v", opcode, decoded, err)
		}
	}
}

func TestProxyWebSocketFrameRejectsPartialWrite(t *testing.T) {
	writer := &proxyFrameWriteRecorder{short: true}
	if err := writeProxyWebSocketFrame(writer, 2, []byte("frame"), 1024); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("partial frame reported success: %v", err)
	}
}
