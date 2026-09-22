package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func TestRecordIOAuthenticatedFrames(t *testing.T) {
	client, server := ioEngine(t, protocolv4.ClientToServer), ioEngine(t, protocolv4.ServerToClient)
	provider := new(shortWriter)
	w, err := NewRecordWriter(client, 1, provider)
	if err != nil {
		t.Fatal(err)
	}
	r, err := newTestRecordReceiver(t, server, protocolv4.ClientToServer, 4096, 128, protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		payload := []byte("actual authenticated DATA")
		result, err := w.WriteData(context.Background(), protocolv4.ClientToServer, uint64(i*len(payload)), i == 1, payload, 128)
		if err != nil || !result.Complete || !result.Submitted || result.Header.Sequence != uint64(i) {
			t.Fatal(result, err)
		}
		received, err := r.Read(context.Background(), bytes.NewReader(provider.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		body, err := received.Body()
		if err != nil {
			t.Fatal(err)
		}
		got, ok := body.Field("data").ByteString()
		if !ok || !bytes.Equal(got, payload) {
			t.Fatal("payload")
		}
		if n, ok := body.Field("sequence").Uint(); !ok || n != result.Header.Sequence {
			t.Fatal("ticket/body mismatch")
		}
		if _, err := r.Receive(context.Background(), provider.Bytes()); !errors.Is(err, cryptov4.ErrCapacity) {
			t.Fatal("decoder owner reused", err)
		}
		received.Release()
		if _, err := received.Body(); !errors.Is(err, cryptov4.ErrClosed) {
			t.Fatal(err)
		}
		provider.Reset()
	}
}

func TestRecordIOForgedMirrorAndClose(t *testing.T) {
	client, server := ioEngine(t, protocolv4.ClientToServer), ioEngine(t, protocolv4.ServerToClient)
	var provider bytes.Buffer
	w, _ := NewRecordWriter(client, 1, &provider)
	r, err := newTestRecordReceiver(t, server, protocolv4.ClientToServer, 4096, 128, protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}})
	if err != nil {
		t.Fatal(err)
	}
	// A valid AEAD cannot authenticate a different logical direction into the
	// Session. The record validator rejects it before advancing receive state.
	if _, err = w.WriteData(context.Background(), protocolv4.ServerToClient, 0, false, []byte("x"), 64); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Receive(context.Background(), provider.Bytes()); err != protocolv4.CBORFailure("record_mirror") {
		t.Fatal(err)
	}
	r.Close()
	if err = r.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Receive(context.Background(), provider.Bytes()); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal(err)
	}
}

func TestRecordIOBuildFailureRetainsTicket(t *testing.T) {
	client := ioEngine(t, protocolv4.ClientToServer)
	var provider bytes.Buffer
	w, _ := NewRecordWriter(client, 1, &provider)
	result, err := w.WriteBuild(context.Background(), protocolv4.FrameStreamData, 32, func(header protocolv4.RecordHeader, dst []byte) (int, error) {
		return 0, protocolv4.CBORFailure("encoder_capacity")
	})
	if err == nil || !result.Submitted || result.Header.Sequence != 0 || result.Complete || provider.Len() != 0 {
		t.Fatal(result, err)
	}
	if _, err = w.WriteData(context.Background(), protocolv4.ClientToServer, 0, false, nil, 32); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("post-ticket failure writer reopened", err)
	}
}
