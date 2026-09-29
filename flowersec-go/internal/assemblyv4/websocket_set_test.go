package assemblyv4

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func TestWebSocketSetRoutesOriginalCandidatesAndRetainsLiveProviders(t *testing.T) {
	first, second := webSocketFactoryTest(t, false), webSocketFactoryTest(t, true)
	c := WebSocketSetConfig{Root: first.root, Owner: admissionResourceKey(first.factory.c.Owner, 600), Clock: first.factory.c.Clock,
		Options: first.factory.c.Options, ConnectionsPerRoute: 1, RuntimeBytes: 8192, FactoryRuntimeBytes: 65536,
		Endpoints: []WebSocketEndpoint{
			{Route: first.request.Route, RemoteAddress: first.factory.c.RemoteAddress, Roots: first.factory.c.Roots},
			{Route: second.request.Route, RemoteAddress: second.factory.c.RemoteAddress, Roots: second.factory.c.Roots},
		}}
	charge, err := WebSocketCarrierSetCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := first.root.Reserve(c.Owner, charge)
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewWebSocketCarrierSet(c, ref, first.request.Config.Environment)
	ref.Release()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		set.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := set.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
	})
	left, err := set.PrepareCarrier(context.Background(), first.request)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPreparedTest(t, left)
	request := second.request
	request.Config.Environment = first.request.Config.Environment
	request.Config.Deadline = first.request.Config.Deadline
	request.Scope = first.request.Scope
	charge, err = sessionv4.PreparedCarrierCharge(request.Config.RuntimeBytes)
	if err != nil {
		t.Fatal(err)
	}
	request.Config.Reservation, err = first.root.Reserve(admissionResourceKey(c.Owner, 604), charge, request.Scope.Tenant, request.Scope.Session)
	if err != nil {
		t.Fatal(err)
	}
	defer request.Config.Reservation.Release()
	right, err := set.PrepareCarrier(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPreparedTest(t, right)
	if first.arrived.Load() != 1 || second.arrived.Load() != 1 || first.data.Load()+second.data.Load() != 0 {
		t.Fatal("set substituted a candidate, retried or disclosed credentials during Prepare")
	}
	bad := request
	bad.Route = []byte{0xa0}
	if provider, err := set.PrepareCarrier(context.Background(), bad); provider != nil || err == nil {
		t.Fatal("unknown route accepted")
	}
	set.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := set.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("set refunded live factory backing", err)
	}
	if err := left.Check(); err != nil {
		t.Fatal("set closure invalidated original prepared carrier", err)
	}
	if err := right.Check(); err != nil {
		t.Fatal("set closure invalidated original prepared carrier", err)
	}
	for _, provider := range []*sessionv4.PreparedCarrier{left, right} {
		_ = provider.Close()
		if err := provider.WaitCleanup(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := provider.Retire(); err != nil {
			t.Fatal(err)
		}
	}
	if err := set.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := set.PrepareCarrier(context.Background(), request); !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal(err)
	}
}

func TestWebSocketSetRefusesDuplicateRoutesBeforeOwnership(t *testing.T) {
	f := webSocketFactoryTest(t, false)
	e := WebSocketEndpoint{Route: f.request.Route, RemoteAddress: f.factory.c.RemoteAddress, Roots: f.factory.c.Roots}
	c := WebSocketSetConfig{Root: f.root, Owner: f.factory.c.Owner, Clock: f.factory.c.Clock, Options: f.factory.c.Options,
		ConnectionsPerRoute: 1, RuntimeBytes: 8192, FactoryRuntimeBytes: 65536, Endpoints: []WebSocketEndpoint{e, e}}
	before := f.root.Snapshot().Charged
	if _, err := WebSocketCarrierSetCharge(c); !errors.Is(err, resourcev4.ErrConfiguration) {
		t.Fatal(err)
	}
	if f.root.Snapshot().Charged != before || f.arrived.Load() != 0 {
		t.Fatal("duplicate routes changed ownership or reached network")
	}
}
