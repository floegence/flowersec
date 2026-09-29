package sessionv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestApplicationQueryProtectionReservesIdleIndexAndReusesWorker(t *testing.T) {
	f := queryExecutorFixture(t, 1)
	backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128})
	borrow, err := backing.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.executor.protectSDKQuery(&sdkQueryGroup{}, f.reserve(t, 1, sdkQueryProtectionCharge()), borrow)
	borrow.Release()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if s := f.executor.Snapshot(); s.QueryOwners != 1 || s.QueryReady != 0 || s.QueryRunning != 0 {
		t.Fatal(s)
	}
	extra, err := backing.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Release()
	if _, err = f.executor.registerSDKQuery(&sdkQueryGroup{}, 1, &testSDKQueryWork{}, extra); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal(err)
	}
	for range 3 {
		entered, release := make(chan struct{}), make(chan struct{})
		r, err := p.activate(&testSDKQueryWork{step: func() (bool, error) { close(entered); <-release; return false, nil }})
		if err != nil {
			t.Fatal(err)
		}
		r.Wake()
		awaitQuery(t, entered)
		if _, err = p.activate(&testSDKQueryWork{}); err != cryptov4.ErrCapacity {
			t.Fatal(err)
		}
		r.Close()
		if p.available() != cryptov4.ErrCapacity {
			t.Fatal("active worker refunded")
		}
		close(release)
		awaitQuery(t, r.done)
		if err = p.available(); err != nil {
			t.Fatal(err)
		}
		if s := f.executor.Snapshot(); s.QueryOwners != 1 || s.QueryReady != 0 || s.QueryRunning != 0 {
			t.Fatal(s)
		}
	}
	f.executor.Close()
	awaitQuery(t, f.executor.Done())
	p.Close()
	if !p.cleanupComplete() {
		t.Fatal("idle protection retained closed executor")
	}
}

func TestApplicationQueryProtectionCloseRetainsRealWorkerTail(t *testing.T) {
	f := queryExecutorFixture(t, 1)
	backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128})
	borrow, err := backing.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.executor.protectSDKQuery(&sdkQueryGroup{}, f.reserve(t, 1, sdkQueryProtectionCharge()), borrow)
	borrow.Release()
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	r, err := p.activate(&testSDKQueryWork{step: func() (bool, error) { close(entered); <-release; return false, nil }})
	if err != nil {
		t.Fatal(err)
	}
	r.Wake()
	awaitQuery(t, entered)
	p.Close()
	if p.cleanupComplete() || f.executor.Snapshot().QueryOwners != 1 {
		t.Fatal("Close refunded real worker")
	}
	close(release)
	awaitQuery(t, r.done)
	if !p.cleanupComplete() || f.executor.Snapshot().QueryOwners != 0 {
		t.Fatal("worker did not release protection")
	}
}
