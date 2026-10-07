package flowersec

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// These tests exercise original public pair/runtime ownership only. No hop is
// authenticated and no application admission or forwarding result is inferred.
func currentTunnelOwners(t *testing.T) (*resourcev4.Root, *TunnelPair, *TunnelRuntime) {
	t.Helper()
	started := time.Now()
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 1000, MaxAgeMS: 60000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) {
		return timev4.Tick{Milliseconds: uint64(time.Since(started) / time.Millisecond), Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err = clock.InstallTrusted(mark, timev4.Interval{LowerMS: 1000000, UpperMS: 1000002}); err != nil {
		t.Fatal(err)
	}
	deadline, err := timev4.NewDeadline(clock, 1060000)
	if err != nil {
		t.Fatal(err)
	}
	pairConfig := TunnelPairConfig{Clock: clock, PreparationDeadline: deadline, MaxEnvelopeBytes: 4096, RuntimeBytes: 4096}
	pairCharge, err := TunnelPairCharge(pairConfig)
	if err != nil {
		t.Fatal(err)
	}
	options := TunnelRuntimeOptions{MaxActivePairs: 1, RuntimeBytes: 4096}
	runtimeCharge, err := TunnelRuntimeCharge(options)
	if err != nil {
		t.Fatal(err)
	}
	environmentCharge := resourcev4.Vector{resourcev4.Items: 1}
	limit, err := pairCharge.Add(runtimeCharge)
	if err == nil {
		limit, err = limit.Add(environmentCharge)
	}
	if err != nil {
		t.Fatal(err)
	}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 2, ReservationSlots: 3, ReferenceSlots: 12}
	backing, err := resourcev4.BackingBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Limit[resourcev4.SDKBytes] += backing
	root, err := resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	owner := resourcev4.OwnerKey{ProfileRevision: config.ProfileRevision, Environment: [16]byte{1}, Kind: 1, Instance: [16]byte{1}, Backing: [16]byte{1}}
	environment, err := root.Reserve(owner, environmentCharge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(environment.Release)
	owner.Kind, owner.Instance, owner.Backing = 2, [16]byte{2}, [16]byte{2}
	pairReservation, err := root.Reserve(owner, pairCharge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pairReservation.Release)
	pair, err := NewTunnelPair(pairConfig, pairReservation, environment)
	if err != nil {
		t.Fatal(err)
	}
	owner.Kind, owner.Instance, owner.Backing = 3, [16]byte{3}, [16]byte{3}
	options.Reservation, err = root.Reserve(owner, runtimeCharge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(options.Reservation.Release)
	options.Dependencies = environment
	runtime, err := NewTunnelRuntime(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		runtime.Close()
		if err := runtime.WaitCleanup(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return root, pair, runtime
}

func TestCurrentTunnelPairCleanupWaitRetainsOriginalClaim(t *testing.T) {
	root, pair, runtime := currentTunnelOwners(t)
	run, err := pair.ClaimRun(runtime.dependencies)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	t.Cleanup(func() {
		_ = run.Run(canceled)
		pair.Close()
		if err := pair.WaitCleanup(context.Background()); err != nil {
			t.Error(err)
		}
	})
	before := root.Snapshot().Charged
	pair.Close()
	wait, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = pair.WaitCleanup(wait)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("original claimed Run cleanup wait = %v", err)
	}
	if got := root.Snapshot().Charged; got != before {
		t.Fatalf("canceled wait released original pair charges: before=%v after=%v", before, got)
	}
	if _, err := pair.ClaimRun(runtime.dependencies); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatalf("closed claimed pair accepted another Run: %v", err)
	}
	if err := run.Run(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("original canceled Run = %v", err)
	}
	if err := pair.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if root.Snapshot().Charged == before {
		t.Fatal("completed original Run retained the pair charge")
	}
}

// A blocked original method supplies a real outstanding Run tail. The gate
// changes no credential, admission fact, forwarding buffer or signed deadline.
type currentTunnelRunGate struct {
	context.Context
	entered, release chan struct{}
	once             sync.Once
}

func (c *currentTunnelRunGate) Err() error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.Context.Err()
}

func TestCurrentTunnelRuntimeCleanupJoinsOriginalServePair(t *testing.T) {
	root, pair, runtime := currentTunnelOwners(t)
	parent, cancel := context.WithCancel(context.Background())
	gate := &currentTunnelRunGate{Context: parent, entered: make(chan struct{}), release: make(chan struct{})}
	served := make(chan error, 1)
	go func() { served <- runtime.ServePair(gate, pair) }()
	var releaseOnce sync.Once
	release := func() { cancel(); releaseOnce.Do(func() { close(gate.release) }) }
	t.Cleanup(release)
	select {
	case <-gate.entered:
	case <-time.After(time.Second):
		release()
		t.Fatal("original pair Run did not enter")
	}
	before := root.Snapshot().Charged
	runtime.Close()
	wait, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := runtime.WaitCleanup(wait)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		release()
		t.Fatalf("runtime did not join the original ServePair tail: %v", err)
	}
	if got := root.Snapshot().Charged; got != before {
		release()
		t.Fatalf("runtime wait released live original charges: before=%v after=%v", before, got)
	}
	select {
	case err := <-served:
		release()
		t.Fatalf("original Run returned before its tail was released: %v", err)
	default:
	}
	release()
	select {
	case err := <-served:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("original ServePair = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("original ServePair did not finish")
	}
	if err := runtime.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if root.Snapshot().Charged == before {
		t.Fatal("completed original service retained pair/runtime charges")
	}
}
