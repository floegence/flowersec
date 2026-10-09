package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

type receiverOpenNativeStream struct {
	native.Stream
	input io.Reader
}

func (s receiverOpenNativeStream) Read(dst []byte) (int, error) { return s.input.Read(dst) }

func TestNativeOpenReceiverErasesSuccessfulAndPartialInput(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "partial"}[partial], func(t *testing.T) {
			client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
			server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
			var provider bytes.Buffer
			if _, result, err := client.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", []byte{0xff}, &CarrierAssociation{}, client.reservation(&provider, 8), streamTestDeadline(t, client.engine)); err != nil || !result.Complete {
				t.Fatal(result, err)
			}
			wire := provider.Bytes()
			if partial {
				wire = wire[:protocolv4.EnvelopePrefixSize+33]
			}
			n := &nativeStreamTransport{context: context.Background()}
			slot := &nativeStreamSlot{stream: receiverOpenNativeStream{input: bytes.NewReader(wire)}}
			record, err := n.readOpen(slot, server.receiver)
			if partial {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatal("partial native OPEN did not retain the original framing failure", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				record.Release()
			}
			if server.receiver.storageUsed != 0 || !bytes.Equal(server.receiver.storage, make([]byte, len(server.receiver.storage))) {
				t.Fatal("native OPEN backing retained input after its physical owner exited")
			}
		})
	}
}

func TestRecordReceiverReuseErasesSuccessfulAndPartialInput(t *testing.T) {
	client, server := ioEngine(t, protocolv4.ClientToServer), ioEngine(t, protocolv4.ServerToClient)
	var provider bytes.Buffer
	w, err := NewRecordWriter(client, 1, &provider)
	if err != nil {
		t.Fatal(err)
	}
	r, err := newTestRecordReceiver(t, server, protocolv4.ClientToServer, 4096, 128, protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}})
	if err != nil {
		t.Fatal(err)
	}
	assertErased := func() {
		t.Helper()
		if r.storageUsed != 0 || !bytes.Equal(r.storage, make([]byte, len(r.storage))) {
			t.Fatal("original receiver backing retains input after physical exit")
		}
	}
	for _, size := range []int{1024, 1} {
		provider.Reset()
		if _, err := w.WriteData(context.Background(), protocolv4.ClientToServer, 0, false, bytes.Repeat([]byte{0xa5}, size), size+128); err != nil {
			t.Fatal(err)
		}
		record, err := r.Read(context.Background(), bytes.NewReader(provider.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		record.Release()
		assertErased()
	}
	provider.Reset()
	if _, err := w.WriteData(context.Background(), protocolv4.ClientToServer, 0, false, bytes.Repeat([]byte{0x5a}, 1024), 1152); err != nil {
		t.Fatal(err)
	}
	// The prefix lends a full bounded body view even if the original provider
	// exits after copying only a prefix of that body.
	if _, err := r.Read(context.Background(), bytes.NewReader(provider.Bytes()[:protocolv4.EnvelopePrefixSize+33])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	assertErased()
}

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
