package tunnelv2

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv2"
)

func TestDefaultCoordinatorAdmitsPair1024Rejects1025AndReadmitsAfterRelease(t *testing.T) {
	coordinator, err := NewCoordinator(DefaultConfig(), func(context.Context, *artifactv2.DecodedRequest) (Authorization, error) {
		return Authorization{}, errors.New("unused")
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	for pair := 1; pair <= 1024; pair++ {
		if err := coordinator.reserveActivePairLocked(); err != nil {
			t.Fatalf("pair %d rejected: %v", pair, err)
		}
	}
	if err := coordinator.reserveActivePairLocked(); !errors.Is(err, ErrCapacity) {
		t.Fatalf("pair 1025 error = %v, want typed capacity", err)
	}
	coordinator.releaseActivePairLocked()
	if err := coordinator.reserveActivePairLocked(); err != nil {
		t.Fatalf("pair after release rejected: %v", err)
	}
}

func TestCoordinatorActivePairReleaseUnderflowPanics(t *testing.T) {
	coordinator, err := NewCoordinator(DefaultConfig(), func(context.Context, *artifactv2.DecodedRequest) (Authorization, error) {
		return Authorization{}, errors.New("unused")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("active-pair release underflow did not panic")
		}
	}()
	coordinator.releaseActivePairLocked()
}
