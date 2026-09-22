package sessionv4

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// v4.go_rpc_channel.batch
func TestRPCBatchWriterUsesOriginalQueueAndActualPublication(t *testing.T) {
	charge, err := RPCBatchWriterCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	f := newServiceFixtureResources(t, 1, [3]uint32{1}, 16384, 2, testAuthorization{}, true, []resourcev4.Vector{StreamOwnershipCharge(), charge})
	provider := &serviceTestWriter{frames: make(chan []byte, 16), entered: make(chan struct{}), release: make(chan struct{})}
	q, _ := f.open(t, BusinessStream, 64, provider)
	h := OpenHandle{f.local.admission, f.flows[0].receive.scope}
	owner := ownFixtureStream(t, f, h, f.reserve(t, StreamOwnershipCharge()))
	writer, err := NewRPCBatchWriter(owner, f.reserve(t, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		writer.Close()
		if err := writer.Retire(); err != nil {
			t.Error(err)
		}
	})
	var first, second [32]byte
	n, err := protocolv4.EncodeRPCFragment(first[:], protocolv4.RPCFragment{Kind: protocolv4.RPCData, Serial: 1, Payload: []byte("ab")})
	if err != nil {
		t.Fatal(err)
	}
	m, err := protocolv4.EncodeRPCFragment(second[:], protocolv4.RPCFragment{Kind: protocolv4.RPCData, Serial: 2, Payload: []byte("cd")})
	if err != nil {
		t.Fatal(err)
	}
	tail, err := writer.TryAccept(context.Background(), [][]byte{first[:n], second[:m]})
	if err != nil || tail != uint64(n+m) || owner.AcceptedBytes() != tail {
		t.Fatal(tail, err)
	}
	if accepted, _, pending, _, _, _, _ := q.Snapshot(); accepted != tail || pending != n+m {
		t.Fatal("batch not in original ring", accepted, pending)
	}
	if _, err := owner.Write(context.Background(), []byte{1}); !errors.Is(err, ErrStreamOwned) {
		t.Fatal("competing writer", err)
	}
	if _, err := writer.TryAccept(context.Background(), [][]byte{first[:n]}); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("second unpublished batch", err)
	}
	f.run(t)
	select {
	case <-provider.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("provider not entered")
	}
	if published, err := writer.Published(tail); published || err != nil {
		t.Fatal("premature publication", published, err)
	}
	if _, err := writer.Published(tail - 1); !errors.Is(err, ErrStreamOwned) {
		t.Fatal("arbitrary frontier", err)
	}
	writer.Close()
	if err := writer.Retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("refunded live provider", err)
	}
	close(provider.release)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		published, err := writer.Published(tail)
		if err != nil {
			t.Fatal(err)
		}
		if published {
			break
		}
		select {
		case <-writer.Wake():
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if err := writer.Retire(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Release(); err != nil {
		t.Fatal(err)
	}
}
