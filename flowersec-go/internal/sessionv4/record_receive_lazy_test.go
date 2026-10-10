package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func lazyRecordReceiverFixture(t *testing.T) (*RecordReceiver, *resourcev4.Root, []byte) {
	t.Helper()
	client, server := ioEngine(t, protocolv4.ClientToServer), ioEngine(t, protocolv4.ServerToClient)
	var wire bytes.Buffer
	w, err := NewRecordWriter(client, 1, &wire)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	if _, err := w.WriteData(context.Background(), protocolv4.ClientToServer, 0, false, bytes.Repeat([]byte{'x'}, 1024), 1152); err != nil {
		t.Fatal(err)
	}
	bounds := protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}}
	charge, err := RecordReceiverCharge(4096, 128, bounds)
	if err != nil {
		t.Fatal(err)
	}
	root, ref := testResourceReservation(t, charge, 2)
	r, err := newLazyRecordReceiver(server, protocolv4.ClientToServer, 4096, 128, bounds, ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		r.Close()
		if err := r.retire(); err != nil {
			t.Error("lazy receiver retained an actual input owner", err)
		}
	})
	bounds.Limits["max_data_payload_bytes"] = 1
	ref.Release()
	return r, root, wire.Bytes()
}

func TestLazyRecordReceiverReservesFullBackingAndCapturesBounds(t *testing.T) {
	r, root, wire := lazyRecordReceiverFixture(t)
	before := root.Snapshot()
	if r.decoder != nil || r.storage != nil || before.Reservations != 1 || r.context.Limits["max_data_payload_bytes"] != 1024 {
		t.Fatal("unread native receiver allocated backing or lost original admission")
	}
	charge, err := RecordReceiverCharge(4096, 128, r.context)
	if err != nil || before.Charged[resourcev4.SDKBytes] < charge[resourcev4.SDKBytes] {
		t.Fatal("lazy backing escaped its full original charge", err)
	}
	record, err := r.Receive(context.Background(), wire)
	if err != nil {
		t.Fatal("first input did not use the captured full payload bound", err)
	}
	body, err := record.Body()
	if err != nil {
		t.Fatal(err)
	}
	data, ok := body.Field("data").ByteString()
	if !ok || len(data) != 1024 || r.storage != nil {
		t.Fatal("first input reduced the declared frame capacity")
	}
	record.Release()
	decoder := r.decoder
	if err := r.begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.decoder != decoder || r.storage != nil || root.Snapshot() != before {
		t.Fatal("receiver reuse replaced original decoder or acquired resources")
	}
	r.finish()
	r.Close()
	if err := r.WaitCleanup(context.Background()); err != nil || root.Snapshot() != before {
		t.Fatal("logical cleanup refunded the receiver before retirement", err)
	}
	if err := r.retire(); err != nil || root.Snapshot().Reservations != 0 {
		t.Fatal("original receiver retirement retained its charge", err)
	}
}

func TestLazyRecordReceiverRejectsInvalidCapacityBeforeTakingResources(t *testing.T) {
	engine := ioEngine(t, protocolv4.ServerToClient)
	bounds := protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}}
	charge, err := RecordReceiverCharge(4096, 128, bounds)
	if err != nil {
		t.Fatal(err)
	}
	root, ref := testResourceReservation(t, charge, 2)
	before := root.Snapshot()
	for _, test := range []struct {
		frame uint32
		nodes int
	}{{4096, 0}, {4095, 128}} {
		if r, err := newLazyRecordReceiver(engine, protocolv4.ClientToServer, test.frame, test.nodes, bounds, ref); err == nil || r != nil {
			t.Fatal("invalid lazy capacity was deferred until input", test, err)
		}
		if err := ref.Check(); err != nil || root.Snapshot() != before {
			t.Fatal("invalid lazy constructor consumed original admission", err)
		}
	}
	charge[resourcev4.SDKBytes]--
	_, short := testResourceReservation(t, charge, 2)
	if _, err := newLazyRecordReceiver(engine, protocolv4.ClientToServer, 4096, 128, bounds, short); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("unallocated arrays bypassed the full reservation", err)
	}
}

func TestLazyRecordReceiverCloseBeforeFirstInputDoesNotAllocate(t *testing.T) {
	for _, closeRoot := range []bool{false, true} {
		t.Run(map[bool]string{false: "receiver", true: "resource"}[closeRoot], func(t *testing.T) {
			r, root, wire := lazyRecordReceiverFixture(t)
			before := root.Snapshot().Charged
			if closeRoot {
				root.Close()
			} else {
				r.Close()
			}
			if _, err := r.Receive(context.Background(), wire); err == nil || r.decoder != nil || r.storage != nil {
				t.Fatal("closed unread receiver allocated backing or admitted input", err)
			}
			r.Close()
			if err := r.WaitCleanup(context.Background()); err != nil || root.Snapshot().Charged != before {
				t.Fatal("unused receiver cleanup changed original ownership", err)
			}
			if err := r.retire(); err != nil || root.Snapshot().Reservations != 0 {
				t.Fatal("unused receiver retained its full reservation", err)
			}
		})
	}
}

func TestLazyRecordReceiverCloseRetainsActualProviderTail(t *testing.T) {
	r, root, wire := lazyRecordReceiverFixture(t)
	provider := &recordHeldBodyReader{source: bytes.NewReader(wire), entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(provider.release) }) })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := r.Read(ctx, provider); done <- err }()
	select {
	case <-provider.entered:
	case <-ctx.Done():
		t.Fatal("lazy receiver never entered its original provider")
	}
	before := root.Snapshot()
	storage := r.storage
	if len(storage) != len(wire) || cap(storage) != len(wire) {
		t.Fatal("body reader did not borrow the exact original envelope")
	}
	r.Close()
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if err := r.WaitCleanup(canceled); !errors.Is(err, context.Canceled) || r.storage == nil || r.decoder == nil || root.Snapshot() != before {
		t.Fatal("Close released the actual lazy read backing", err)
	}
	if err := r.retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("lazy receiver retired before its provider returned", err)
	}
	release.Do(func() { close(provider.release) })
	if err := <-done; !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("late lazy read published after Close", err)
	}
	if err := r.WaitCleanup(ctx); err != nil || r.storage != nil || r.decoder != nil || root.Snapshot() != before {
		t.Fatal("actual provider exit failed to clear the original backing", err)
	}
	if !bytes.Equal(storage, make([]byte, len(storage))) {
		t.Fatal("late provider exit retained ciphertext")
	}
}
