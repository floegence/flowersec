package sessionv4

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// These tests replace only a physical cleanup tail. They create no credentials,
// namespace permissions, allow instruction, claim, admission or READY evidence.
func TestTunnelFailedEntranceRetainsTakenCarrierThroughCanceledCleanup(t *testing.T) {
	c, root := preparedTestConfig(t)
	provider := &preparedTestProvider{environment: c.Environment, waitEntered: make(chan struct{}), waitRelease: make(chan struct{})}
	prepared, err := NewPreparedMessages(context.Background(), c, provider)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		select {
		case <-provider.waitRelease:
		default:
			close(provider.waitRelease)
		}
	}()
	recipient := &TunnelServerAllowRecipient{prepared: prepared, done: make(chan struct{})}
	factory := &TunnelAcceptedIngressFactory{result: recipient}
	factory.Close()
	before := root.Snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = factory.WaitCleanup(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cleanup did not wait for the physical tail", err)
	}
	if provider.reads.Load() != 0 || provider.writes.Load() != 0 || provider.retires.Load() != 0 {
		t.Fatal("failed entrance dispatched I/O or retired a live tail")
	}
	if recipient.cleaned || factory.result != recipient || root.Snapshot().Charged != before.Charged {
		t.Fatal("canceled cleanup discarded the original recipient or charge")
	}
	close(provider.waitRelease)
	if err = factory.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !recipient.cleaned || factory.result != nil || provider.closes.Load() != 1 || provider.retires.Load() != 1 {
		t.Fatal("original carrier was not cleaned and retired exactly once")
	}
	if root.Snapshot().Charged == before.Charged {
		t.Fatal("completed physical cleanup retained its unused carrier charge")
	}
	if err = factory.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if provider.closes.Load() != 1 || provider.retires.Load() != 1 {
		t.Fatal("passive cleanup replayed physical retirement")
	}
}

func TestTunnelFailedEntranceRetirementFailureKeepsOriginalRecipient(t *testing.T) {
	c, root := preparedTestConfig(t)
	provider := &preparedTestProvider{environment: c.Environment}
	provider.retireFailure.Store(true)
	prepared, err := NewPreparedMessages(context.Background(), c, provider)
	if err != nil {
		t.Fatal(err)
	}
	recipient := &TunnelServerAllowRecipient{prepared: prepared, done: make(chan struct{})}
	factory := &TunnelAcceptedIngressFactory{result: recipient}
	factory.Close()
	before := root.Snapshot()
	if err = factory.WaitCleanup(context.Background()); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("failed retirement became cleanup success", err)
	}
	if recipient.cleaned || factory.result != recipient || root.Snapshot().Charged != before.Charged {
		t.Fatal("retirement failure released original material backing")
	}
	provider.retireFailure.Store(false)
	if err = factory.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if provider.reads.Load() != 0 || provider.writes.Load() != 0 || provider.closes.Load() != 1 || !recipient.cleaned {
		t.Fatal("cleanup retry redispatched physical preparation or I/O")
	}
}
