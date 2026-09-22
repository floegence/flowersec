package sessionv4

import (
	"bytes"
	"io"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

// v4.go_rpc_channel.credit
func TestProtectedReceiveCreditReturnsThroughOriginalMaintenance(t *testing.T) {
	f, _ := terminationFixture(t, 1, 2)
	s := f.open(t)
	f.start()
	reader, writer := io.Pipe()
	t.Cleanup(func() { reader.Close(); writer.Close() })
	done := f.read(s, reader)
	flow := s.flow.receive
	flow.pool.mu.Lock()
	flow.minimumPromise = 512
	flow.creditLimit = flow.limit
	flow.creditAck = flow.released
	flow.pool.mu.Unlock()
	for i := range 12 {
		payload := bytes.Repeat([]byte{1}, 64)
		if _, err := s.peer.send.Write(f.ctx, payload, false); err != nil {
			t.Fatal("peer stalled", i, err)
		}
		if _, err := writer.Write(s.wire.Bytes()); err != nil {
			t.Fatal(err)
		}
		s.wire.Reset()
		var buf [64]byte
		result, err := flow.ReadInto(f.ctx, buf[:])
		n, terminal := int(result.Progress.Filled), result.ReadTerminal
		if err != nil || n != len(payload) || terminal != protocolv4.V4ReadTerminalOpen {
			t.Fatal(n, terminal, err)
		}
		if flow.pool.Outstanding() != 512 {
			t.Fatal("protected promise became stealable", flow.pool.Outstanding())
		}
		progressTerminal(t, f, "STREAM_ACK_CREDIT")
	}
	if result, ready, err := f.termination.Progress(f.ctx); err != nil || ready || result.Submitted {
		t.Fatal("redundant credit", ready, err)
	}
	// Real FIN releases future minimum while preserving unread bytes; the
	// protected service cannot replenish a terminated direction.
	if _, err := s.peer.send.Write(f.ctx, []byte("end"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(s.wire.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := nativeResult(t, done); err != nil {
		t.Fatal(err)
	}
	var buf [64]byte
	result, err := flow.ReadInto(f.ctx, buf[:])
	n, terminal := int(result.Progress.Filled), result.ReadTerminal
	if n != 3 || terminal != protocolv4.V4ReadTerminalEof || err != nil {
		t.Fatal(n, terminal, err)
	}
	if flow.pool.Outstanding() != 0 {
		t.Fatal("terminal protected credit retained", flow.pool.Outstanding())
	}
	progressTerminal(t, f, "STREAM_ACK_DRAINED")
}
