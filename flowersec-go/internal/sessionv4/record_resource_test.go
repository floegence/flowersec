package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func newTestRecordReceiver(t *testing.T, engine *cryptov4.Engine, direction protocolv4.Direction, maxFrame uint32, nodeCap int, decodeContext protocolv4.DecodeContext) (*RecordReceiver, error) {
	t.Helper()
	charge, err := RecordReceiverCharge(maxFrame, nodeCap, decodeContext)
	if err != nil {
		return nil, err
	}
	_, ref := testResourceReservation(t, charge, 2)
	r, err := NewRecordReceiver(engine, direction, maxFrame, nodeCap, decodeContext, ref)
	if err == nil {
		t.Cleanup(func() {
			r.Close()
			if err := r.retire(); err != nil {
				t.Error("receiver test left a live read/plaintext owner", err)
			}
		})
	}
	return r, err
}

func TestRecordReceiverRequiresOriginalResourceReservation(t *testing.T) {
	engine := ioEngine(t, protocolv4.ServerToClient)
	bounds := protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}, Selectors: map[string]string{"crypto_profile_id": protocolv4.DHProfileX25519}}
	charge, err := RecordReceiverCharge(4096, 128, bounds)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRecordReceiver(engine, protocolv4.ClientToServer, 4096, 128, bounds, resourcev4.Reference{}); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("decoder allocated without original admission", err)
	}
	root, ref := testResourceReservation(t, charge, 2)
	bounds.Selectors["crypto_profile_id"] = protocolv4.DHProfileP256
	if _, err := NewRecordReceiver(engine, protocolv4.ClientToServer, 4096, 128, bounds, ref); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("selector conflict consumed original reservation", err)
	}
	bounds.Selectors["crypto_profile_id"] = protocolv4.DHProfileX25519
	r, err := NewRecordReceiver(engine, protocolv4.ClientToServer, 4096, 128, bounds, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ref.Release()
	if _, err := NewRecordReceiver(engine, protocolv4.ClientToServer, 4096, 128, bounds, ref); !errors.Is(err, resourcev4.ErrOwner) || root.Snapshot().Reservations != 1 {
		t.Fatal("copied stale reservation attached or refunded receiver", err)
	}
	bounds.Limits["max_data_payload_bytes"] = 1
	bounds.Selectors["crypto_profile_id"] = "changed"
	if r.context.Limits["max_data_payload_bytes"] != 1024 || r.context.Selectors["crypto_profile_id"] != protocolv4.DHProfileX25519 {
		t.Fatal("caller mutated admitted decode bounds")
	}
	r.Close()
	if root.Snapshot().Reservations != 1 || r.storage != nil || r.decoder != nil || r.context.Limits != nil || r.context.Selectors != nil {
		t.Fatal("cleanup retained private backing or refunded live owner metadata")
	}
	if err := r.retire(); err != nil || root.Snapshot().Reservations != 0 {
		t.Fatal("original retirement failed to return reservation", err)
	}
}

func resourceRecordReceiver(t *testing.T) (*RecordReceiver, *resourcev4.Root, []byte) {
	t.Helper()
	client, server := ioEngine(t, protocolv4.ClientToServer), ioEngine(t, protocolv4.ServerToClient)
	var wire bytes.Buffer
	w, err := NewRecordWriter(client, 1, &wire)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	if _, err := w.WriteData(context.Background(), protocolv4.ClientToServer, 0, false, []byte("admitted plaintext"), 128); err != nil {
		t.Fatal(err)
	}
	bounds := protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}}
	charge, err := RecordReceiverCharge(4096, 128, bounds)
	if err != nil {
		t.Fatal(err)
	}
	root, ref := testResourceReservation(t, charge, 2)
	r, err := NewRecordReceiver(server, protocolv4.ClientToServer, 4096, 128, bounds, ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); _ = r.retire() })
	return r, root, wire.Bytes()
}

func TestRecordReceiverResourceClosureFencesAlreadyAuthenticatedFrame(t *testing.T) {
	r, root, wire := resourceRecordReceiver(t)
	held, err := r.Receive(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	root.Close()
	if _, err := held.Body(); !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal("closed resource authority exposed private authenticated bytes", err)
	}
	if err := held.accepted(); !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal("resource closure still admitted incoming activity", err)
	}
	r.Close()
	if err := r.retire(); !errors.Is(err, cryptov4.ErrCapacity) || root.Snapshot().Reservations != 1 {
		t.Fatal("held plaintext refunded by logical Close", err)
	}
	held.Release()
	if held.frame != nil || held.packet != nil || held.incoming != nil {
		t.Fatal("released record retained private frame/key references")
	}
	if err := r.retire(); err != nil || root.Snapshot().Reservations != 0 {
		t.Fatal("real frame exit failed to return original charge", err)
	}
}

type resourceHeldReader struct {
	source           io.Reader
	entered, release chan struct{}
	once             sync.Once
}

func (r *resourceHeldReader) Read(dst []byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	<-r.release
	return r.source.Read(dst)
}

func TestRecordReceiverResourceRetainsOriginalProviderTail(t *testing.T) {
	r, root, wire := resourceRecordReceiver(t)
	provider := &resourceHeldReader{source: bytes.NewReader(wire), entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(provider.release) }) })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := r.Read(ctx, provider); done <- err }()
	select {
	case <-provider.entered:
	case <-ctx.Done():
		t.Fatal("receiver did not enter actual provider")
	}
	before := root.Snapshot().Charged
	r.Close()
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if err := r.WaitCleanup(canceled); !errors.Is(err, context.Canceled) || root.Snapshot().Charged != before || r.storage == nil {
		t.Fatal("cancelled cleanup erased live provider backing", err)
	}
	if err := r.retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("receiver slot retired before its provider exited", err)
	}
	release.Do(func() { close(provider.release) })
	if err := <-done; !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("late read published after Close", err)
	}
	if err := r.WaitCleanup(ctx); err != nil || root.Snapshot().Reservations != 1 {
		t.Fatal("cleanup did not distinguish original receiver retirement", err)
	}
	if err := r.retire(); err != nil || root.Snapshot().Reservations != 0 {
		t.Fatal("actual provider exit failed to settle charge", err)
	}
}
