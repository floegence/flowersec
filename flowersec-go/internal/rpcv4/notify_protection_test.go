package rpcv4

import (
	"context"
	"errors"
	"testing"
)

func TestNotifyProtectionPreservesQueueAndOriginalTail(t *testing.T) {
	f := newNotifyPublisherFixture(t, 2)
	var position [1]NotifyProtection
	if err := f.p.Protect(position[:]); err != nil {
		t.Fatal(err)
	}
	defer position[0].Close()
	ordinary, err := f.submit(context.Background(), []byte("ordinary"), 10000, &notifyTestGuard{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.submit(context.Background(), nil, 10000, &notifyTestGuard{}); !errors.Is(err, ErrCapacity) {
		t.Fatal("ordinary submission stole protected queue position", err)
	}
	protected, err := f.submit(context.Background(), []byte("protected"), 10000, &notifyTestGuard{}, position[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !ordinary.Progress().HeaderAccepted || protected.Progress().HeaderAccepted {
		t.Fatal("position order replaced original admission order")
	}
	for range 8 {
		f.sink.published = true
		if _, err := f.p.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !protected.Progress().Terminal {
		t.Fatal("publication failed to finish")
	}
	if _, err := f.submit(context.Background(), nil, 10000, &notifyTestGuard{}, position[0]); !errors.Is(err, ErrCapacity) {
		t.Fatal("local publication reproduced a target before workload release", err)
	}
	if err := protected.Release(); err != nil {
		t.Fatal(err)
	}
	if err := position[0].ReleaseUse(); err != nil {
		t.Fatal(err)
	}
	second, err := f.submit(context.Background(), nil, 10000, &notifyTestGuard{}, position[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := position[0].ReleaseUse(); !errors.Is(err, ErrCapacity) {
		t.Fatal("active source tail was refunded", err)
	}
	position[0].Close()
	f.sink.held = true
	f.p.Close()
	if err := f.p.Retire(); !errors.Is(err, ErrCapacity) {
		t.Fatal("closed protection dropped provider tail", err)
	}
	if second.Progress().Terminal {
		t.Fatal("tail was declared complete")
	}
}

func TestNotifyProtectionAtomicBatchAndStaleGeneration(t *testing.T) {
	f := newNotifyPublisherFixture(t, 2)
	var oversized [3]NotifyProtection
	if err := f.p.Protect(oversized[:]); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if oversized != ([3]NotifyProtection{}) {
		t.Fatal("failed batch partially claimed positions")
	}
	var all [2]NotifyProtection
	if err := f.p.Protect(all[:]); err != nil {
		t.Fatal(err)
	}
	old := all[0]
	old.Close()
	var next [1]NotifyProtection
	if err := f.p.Protect(next[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.submit(context.Background(), nil, 10000, &notifyTestGuard{}, old); !errors.Is(err, ErrOwner) {
		t.Fatal("stale token consumed replacement target", err)
	}
	if _, err := f.submit(context.Background(), nil, 10000, &notifyTestGuard{}, next[0]); err != nil {
		t.Fatal(err)
	}
	all[1].Close()
	next[0].Close()
}
