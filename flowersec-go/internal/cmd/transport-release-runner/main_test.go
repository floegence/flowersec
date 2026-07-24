package main

import (
	"context"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
)

func TestWorkloadScheduleContainsEveryIndependentRun(t *testing.T) {
	schedule := workloadSchedule(15)
	if len(schedule) != 3 {
		t.Fatalf("cell count = %d, want 3", len(schedule))
	}
	counts := map[carrier.Kind]int{}
	for _, cell := range schedule {
		counts[cell.Carrier] += len(cell.Runs)
		for index, run := range cell.Runs {
			if run != index+1 {
				t.Fatalf("invalid scheduled cell %+v", cell)
			}
		}
	}
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindQUIC, carrier.KindWebTransport} {
		if counts[kind] != 15 {
			t.Fatalf("%s run count = %d, want 15", kind, counts[kind])
		}
	}
}

func TestCompletedWithinRejectsExpiredContext(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := completedWithin(ctx, time.Now().Add(-time.Second), 2*time.Second); err == nil {
		t.Fatal("accepted completion after context deadline")
	}
}

func TestCompletedWithinRejectsElapsedLimit(t *testing.T) {
	if err := completedWithin(context.Background(), time.Now().Add(-2*time.Second), time.Second); err == nil {
		t.Fatal("accepted completion after explicit phase limit")
	}
}
