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

type recordCaptureReader struct {
	io.Reader
	prefix bool
	body   []byte
}

func (r *recordCaptureReader) Read(dst []byte) (int, error) {
	if r.prefix && r.body == nil {
		r.body = dst
	} else if !r.prefix {
		r.prefix = true
	}
	return r.Reader.Read(dst)
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
			reader := &recordCaptureReader{Reader: bytes.NewReader(wire)}
			slot := &nativeStreamSlot{stream: receiverOpenNativeStream{input: reader}}
			record, err := n.readOpen(slot, server.receiver)
			if partial {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatal("partial native OPEN did not retain the original framing failure", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if len(server.receiver.storage) != len(wire) || cap(server.receiver.storage) != len(wire) {
					t.Fatal("native OPEN did not retain exact envelope backing")
				}
				record.Release()
			}
			if server.receiver.storageUsed != 0 || server.receiver.storage != nil || !bytes.Equal(reader.body, make([]byte, len(reader.body))) {
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
		if r.storageUsed != 0 || r.storage != nil {
			t.Fatal("original receiver backing retains input after physical exit")
		}
	}
	if r.storage != nil {
		t.Fatal("idle eager receiver retained maximum ciphertext")
	}
	for _, size := range []int{1024, 1, 1024} {
		provider.Reset()
		if _, err := w.WriteData(context.Background(), protocolv4.ClientToServer, 0, false, bytes.Repeat([]byte{0xa5}, size), size+128); err != nil {
			t.Fatal(err)
		}
		record, err := r.Read(context.Background(), bytes.NewReader(provider.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		storage := r.storage
		if len(storage) != provider.Len() || cap(storage) != provider.Len() {
			t.Fatal("receiver input did not follow the validated exact envelope")
		}
		record.Release()
		assertErased()
		if !bytes.Equal(storage, make([]byte, len(storage))) {
			t.Fatal("released exact backing retained ciphertext")
		}
	}
	provider.Reset()
	if _, err := w.WriteData(context.Background(), protocolv4.ClientToServer, 0, false, bytes.Repeat([]byte{0x5a}, 1024), 1152); err != nil {
		t.Fatal(err)
	}
	// The prefix lends a full bounded body view even if the original provider
	// exits after copying only a prefix of that body.
	reader := &recordCaptureReader{Reader: bytes.NewReader(provider.Bytes()[:protocolv4.EnvelopePrefixSize+33])}
	if _, err := r.Read(context.Background(), reader); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	assertErased()
	if len(reader.body) != provider.Len()-protocolv4.EnvelopePrefixSize || !bytes.Equal(reader.body, make([]byte, len(reader.body))) {
		t.Fatal("partial provider exit did not clear its complete borrowed body view")
	}
}

func TestRecordReceiverHeldFrameKeepsOriginalBackingThroughClose(t *testing.T) {
	r, root, wire := resourceRecordReceiver(t)
	before := root.Snapshot()
	record, err := r.Read(context.Background(), bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	defer record.Release()
	body, err := record.Body()
	if err != nil {
		t.Fatal(err)
	}
	data, ok := body.Field("data").ByteString()
	if !ok {
		t.Fatal("missing original plaintext view")
	}
	storage, plaintext := r.storage, bytes.Clone(data)
	if _, err := r.Receive(context.Background(), wire); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("held frame admitted a second decoder input", err)
	}
	r.Close()
	if !bytes.Equal(data, plaintext) || !bytes.Equal(storage, wire) || root.Snapshot() != before {
		t.Fatal("logical Close released or rewrote actual held input")
	}
	if err := r.retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("held frame retired before Release", err)
	}
	record.Release()
	if r.storage != nil || !bytes.Equal(data, make([]byte, len(data))) || !bytes.Equal(storage, make([]byte, len(storage))) || root.Snapshot() != before {
		t.Fatal("actual frame exit failed to erase both original owners")
	}
	if err := r.retire(); err != nil {
		t.Fatal(err)
	}
}

func TestRecordReceiverCopiedCandidatesKeepOriginalBoundsAndScopeGates(t *testing.T) {
	for _, nativeData := range []bool{false, true} {
		t.Run(map[bool]string{false: "maintenance", true: "native_data"}[nativeData], func(t *testing.T) {
			r, root, wire := resourceRecordReceiver(t)
			before := root.Snapshot()
			receive := func(candidate []byte, scope uint64) (*ReceivedRecord, error) {
				if nativeData {
					return r.receiveNativeSegments(context.Background(), scope, candidate[:8], candidate[8:17], candidate[17:], nil)
				}
				return r.receiveMaintenance(context.Background(), candidate)
			}
			oversized := make([]byte, protocolv4.EnvelopePrefixSize+int(r.maxFrame)+1)
			if _, err := receive(oversized, 1); !errors.Is(err, protocolv4.ErrPayloadTooLarge) || r.storage != nil || root.Snapshot() != before {
				t.Fatal("idle copied receiver lost its original maximum refusal", err)
			}
			if _, err := receive(wire, 2); !errors.Is(err, protocolv4.ErrRecordScope) || r.storage != nil {
				t.Fatal("copied candidate bypassed original association gate", err)
			}
			if nativeData {
				record, err := receive(wire, 1)
				if err != nil {
					t.Fatal("legal DATA failed after original no-attempt refusal", err)
				}
				if len(r.storage) != len(wire) || cap(r.storage) != len(wire) || !bytes.Equal(r.storage, wire) {
					t.Fatal("native DATA did not keep an exact independent copy")
				}
				record.Release()
			} else {
				client := ioEngine(t, protocolv4.ClientToServer)
				var provider bytes.Buffer
				writer, err := NewRecordWriter(client, 0, &provider)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(writer.Close)
				if _, err := writer.Write(context.Background(), protocolv4.FramePing, pingBody(t, 7)); err != nil {
					t.Fatal(err)
				}
				record, err := receive(provider.Bytes(), 0)
				if err != nil {
					t.Fatal("legal maintenance failed after original scope refusal", err)
				}
				if len(r.storage) != provider.Len() || cap(r.storage) != provider.Len() || !bytes.Equal(r.storage, provider.Bytes()) {
					t.Fatal("maintenance did not keep an exact independent copy")
				}
				record.Release()
			}
			if root.Snapshot() != before || r.storage != nil {
				t.Fatal("copied receiver changed original charge on actual exit")
			}
		})
	}
}

func TestSharedReceiverWholeMessageAuthenticatesIndependentExactCopy(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	ingress := newSharedIngressForTest(t, server)
	if _, err := client.maintenance.Write(context.Background(), protocolv4.FramePing, pingBody(t, 7)); err != nil {
		t.Fatal(err)
	}
	wire := bytes.Clone(client.control.Bytes())
	provider := &sessionMessageProvider{read: func(_ context.Context, dst []byte) (int, error) {
		if len(dst) != 136 || cap(dst) != 136 {
			t.Fatal("whole-message provider lost its original maximum borrow")
		}
		return copy(dst, wire), nil
	}}
	input, _, _ := messageInputFixture(t, context.Background(), provider)
	record, err := ingress.Read(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	defer record.Release()
	storage := ingress.receiver.storage
	if provider.reads.Load() != 1 || input.offset != 0 || input.length != 0 || len(storage) != len(wire) || cap(storage) != len(wire) || !bytes.Equal(storage, wire) {
		t.Fatal("shared authentication lost whole-message framing or exact copy")
	}
	input.mu.Lock()
	for i := range input.buffer {
		input.buffer[i] = 0x55
	}
	input.mu.Unlock()
	if !bytes.Equal(storage, wire) {
		t.Fatal("receiver ciphertext aliased the independent provider buffer")
	}
	body, err := record.Body()
	if err != nil || body.Type != protocolv4.FramePing {
		t.Fatal("whole-message record did not reach original authentication", err)
	}
	record.Release()
	if ingress.receiver.storage != nil || !bytes.Equal(storage, make([]byte, len(storage))) {
		t.Fatal("shared actual record exit retained ciphertext")
	}
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
