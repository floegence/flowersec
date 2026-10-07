package tunnelworkload

import (
	"bytes"
	"context"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"testing"
	"time"
)

func TestPreparedCapacityRetainsOnlyItsOriginalPositions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	endpoint, err := openCurrentEndpoint(ctx, TopologyQQ, "127.0.0.1", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := endpoint.Close(cleanup); err != nil {
			t.Error(err)
		}
	}()
	if err := endpoint.PrepareCapacity(ctx, 2); err == nil {
		t.Fatal("preparation exceeded the original position capacity")
	}
	preparation, stop := context.WithCancel(ctx)
	defer stop()
	if err := endpoint.PrepareCapacity(preparation, 1); err != nil {
		t.Fatal(err)
	}
	stop()
	if err := endpoint.PrepareCapacity(ctx, 1); err == nil {
		t.Fatal("completed capacity preparation was reusable")
	}
	if err := endpoint.SetEndpointDialNamespace("late-scope"); err == nil {
		t.Fatal("prepared original network scope could be replaced")
	}
	pair, err := endpoint.Connect(ctx)
	if err != nil {
		t.Fatal("preparation caller cancellation reached the transferred owner", err)
	}
	payload := []byte("original-prepared-capacity")
	got, err := pair.CallEcho(ctx, payload)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("original prepared Session application failed", err)
	}
	if err := pair.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.Connect(ctx); err == nil {
		t.Fatal("consumed capacity material was recreated")
	}
}

func TestCurrentCapacityOwnsExactlyItsDeclaredTunnelPositions(t *testing.T) {
	for _, positions := range []int{100, 1000} {
		endpoint, err := OpenCapacityEndpointAt(context.Background(), TopologyQQ, "127.0.0.1", positions)
		if err != nil {
			t.Fatal(err)
		}
		if len(endpoint.slots) != positions || len(endpoint.building) != positions {
			t.Fatal("current capacity changed its finite original position table")
		}
		if err := endpoint.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if endpoint, err := OpenCapacityEndpointAt(context.Background(), TopologyQQ, "127.0.0.1", 999); err == nil {
		endpoint.Close(context.Background())
		t.Fatal("accepted a non-profile capacity")
	}
}
func TestCurrentBrowserStreamCapacityKeepsFiniteNativeEnvelope(t *testing.T) {
	endpoint, err := OpenBrowserStreamCapacityEndpointAt(context.Background(), BrowserTunnelWTWSS, "127.0.0.1", "https://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close(context.Background())
	if len(endpoint.slots) != 100 {
		t.Fatal("browser stream capacity changed its exact session count")
	}
	// The actual provider declaration, including the reserved protocol streams,
	// is shared with original native peer construction.
	if err := interopharness.QUICProviderFor(138).Limits.ValidateV4(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeProviderCapacityIncludesPendingAndMaintenance(t *testing.T) {
	for _, streams := range []uint32{0, 15, 16, 32, 138, 1919} {
		required := uint64(streams) + uint64(min(streams, 128)) + 1
		quic := interopharness.QUICProviderFor(streams)
		wt := interopharness.WebTransportProviderFor(streams)
		if err := quic.Limits.ValidateV4(); err != nil {
			t.Fatal(err)
		}
		if err := wt.Limits.ValidateV4(); err != nil {
			t.Fatal(err)
		}
		if uint64(quic.StreamSlots) < required || uint64(quic.Limits.MaxInboundStreams) < required ||
			uint64(wt.StreamSlots) < required || uint64(wt.Limits.MaxInboundStreams) < required {
			t.Fatalf("%d active streams exceed the declared native envelope", streams)
		}
	}
	for _, streams := range []uint32{1920, ^uint32(0)} {
		if interopharness.QUICProviderFor(streams).Limits.ValidateV4() == nil ||
			interopharness.WebTransportProviderFor(streams).Limits.ValidateV4() == nil {
			t.Fatalf("oversized %d stream envelope became usable", streams)
		}
	}
}
