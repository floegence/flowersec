package sessionv4

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
)

func TestServeSourcesToReadyDuplexAndDrain(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) { sessionEstablishmentDuplex(t, source, true, true, true, true) })
	}
}

func TestServeIngressTailAndPublicationGate(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	e := environmentTestOwner(t, f, 248, 1)
	config := ServeConfig{Positions: 1, RuntimeBytes: 8192, DrainTimeoutMS: 1000, Clock: f.trust.clock}
	cost, err := ServeCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := f.root.Reserve(admissionResourceKey(f.owner, 316), cost)
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Release()
	g, err := e.NewServeGroup(context.Background(), config, reservation)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	child, err := g.BeginIngress()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.BeginIngress(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal(err)
	}
	originalGeneration := child.generation
	child.Release()
	child, err = g.BeginIngress()
	if err != nil {
		t.Fatal(err)
	}
	ServeIngress{g, child.index, originalGeneration}.Release()
	op, err := g.Drain(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.BeginIngress(); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal(err)
	}
	if err := child.publish(); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("late publication", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := op.Wait(ctx)
	if err != nil || result.Outcome != Drained {
		t.Fatal("pending ingress fabricated business failure", result, err)
	}
	if g.CleanupStatus() {
		t.Fatal("HTTP callback was prematurely forgotten")
	}
	e.Close()
	wait, stop := context.WithCancel(context.Background())
	stop()
	if err := e.WaitCleanup(wait); !errors.Is(err, context.Canceled) {
		t.Fatal("Environment forgot original Serve callback", err)
	}
	child.Release()
	if err := g.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := g.Retire(); err != nil {
		t.Fatal(err)
	}
}
