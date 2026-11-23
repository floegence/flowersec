package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	fs "github.com/floegence/flowersec/flowersec-go/v7"
)

func retiredTunnelPositions(count int) *capacityProduct {
	product := &capacityProduct{
		opts:  capacityOptions{Sessions: capacityPairs, OverlapSuccessors: 4, ServerCarrier: "raw-quic"},
		pairs: make(map[string]*capacityPair), seen: make(map[int]string), byKey: make(map[string]*capacityPair),
		stop: func() {},
	}
	for ordinal := range count {
		position := ordinal % capacityPairs
		id := fmt.Sprintf("p%d", position)
		old := product.pairs[id]
		generation := 1
		if old != nil {
			generation++
			id += "-g2"
		}
		pair := &capacityPair{id: id, index: position, generation: generation}
		pair.established.Store(true)
		pair.closing.Store(true)
		pair.retired.Store(true)
		_, pair.stopWatching = context.WithCancel(context.Background())
		pair.stopWatching()
		product.pairs[id], product.byKey[id+"-leg"], product.seen[position] = pair, pair, id
		if old != nil {
			product.overlap = append(product.overlap, capacitySuccession{old, pair})
		}
	}
	product.terminated.Store(uint64(count))
	return product
}

func TestQuiescedTunnelReleasesGenerationOwners(t *testing.T) {
	product := retiredTunnelPositions(capacityPairs + 4)
	ctx := context.Background()
	before, err := product.op(ctx, capacityRequest{Op: "snapshot"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"positions": capacityPairs, "acquired": capacityPairs, "bound": 0, "liveEnds": [2]int{}, "activeSessions": 0, "activeStreams": 0, "residualStreams": 0, "terminated": uint64(capacityPairs + 4), "closed": false}
	if !reflect.DeepEqual(before, want) {
		t.Fatalf("unexpected initial closed inventory: %#v", before)
	}
	for range 2 {
		if _, err := product.op(ctx, capacityRequest{Op: "quiesce"}); err != nil {
			t.Fatal(err)
		}
		after, err := product.op(ctx, capacityRequest{Op: "snapshot"})
		if err != nil || !reflect.DeepEqual(after, before) {
			t.Fatalf("closed inventory changed: %#v, %v", after, err)
		}
		if len(product.pairs)+len(product.byKey)+len(product.seen)+len(product.overlap) != 0 {
			t.Fatalf("retained pairs=%d grants=%d positions=%d successions=%d", len(product.pairs), len(product.byKey), len(product.seen), len(product.overlap))
		}
	}
	if _, err := product.op(ctx, capacityRequest{Op: "close"}); err != nil {
		t.Fatal(err)
	}
}

type closeFailureSession struct {
	fs.Session
	err error
}

func (session *closeFailureSession) Close() error { return session.err }

func TestQuiesceDoesNotDropFailedTunnelOwner(t *testing.T) {
	product := retiredTunnelPositions(1)
	pair := product.pairs["p0"]
	pair.retired.Store(false)
	expected := errors.New("injected close failure")
	pair.ends[0] = &closeFailureSession{err: expected}
	_, err := product.op(context.Background(), capacityRequest{Op: "quiesce"})
	if !errors.Is(err, expected) || product.pairs["p0"] != pair || product.byKey["p0-leg"] != pair || pair.ends[0] == nil {
		t.Fatalf("failed owner lost: %v", err)
	}
}

func TestQuiesceDoesNotHideUnjoinedRetiredTunnelOwner(t *testing.T) {
	product := retiredTunnelPositions(1)
	pair := product.pairs["p0"]
	pair.live.Store(true)
	_, err := product.op(context.Background(), capacityRequest{Op: "quiesce"})
	if err == nil || product.pairs["p0"] != pair {
		t.Fatalf("unjoined retired owner lost: %v", err)
	}
}
