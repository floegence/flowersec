package tunnelv3

import (
	"context"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
)

func hashTestLeg(role uint8, credential string, contract, candidates byte, replacement bool) *admittedLeg {
	leg := newExpiryTestLeg(role, time.Now().Add(time.Second))
	leg.authorization.Claims.CredentialID = credential
	leg.authorization.Claims.SessionContractHash[0] = contract
	leg.authorization.Claims.CandidateSetHash[0] = candidates
	leg.authorization.Claims.AllowReplacement = replacement
	return leg
}

func TestCoordinatorHashFieldsIsolatePairGenerations(t *testing.T) {
	coordinator, err := NewCoordinator(Config{PairTimeout: 20 * time.Millisecond}, func(context.Context, *artifactv3.DecodedRequest) (Authorization, error) {
		return Authorization{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	first := hashTestLeg(1, "first-a", 1, 2, false)
	generationA, err := coordinator.register(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}

	second := hashTestLeg(2, "second-b", 3, 4, false)
	generationB, err := coordinator.register(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if generationA == generationB {
		t.Fatal("different contract/candidate hashes shared a generation")
	}
	coordinator.mu.Lock()
	if len(coordinator.groups) != 2 {
		coordinator.mu.Unlock()
		t.Fatalf("hash-isolated groups = %d, want 2", len(coordinator.groups))
	}
	coordinator.mu.Unlock()

	matchingPeer := hashTestLeg(2, "second-a", 1, 2, false)
	matchingGeneration, err := coordinator.register(context.Background(), matchingPeer)
	if err != nil {
		t.Fatal(err)
	}
	if matchingGeneration != generationA {
		t.Fatal("identical contract/candidate hashes did not pair in the existing generation")
	}

	for name, generation := range map[string]*pairGeneration{"matching": generationA, "isolated": generationB} {
		select {
		case <-generation.done:
		case <-time.After(time.Second):
			t.Fatalf("%s generation did not finish", name)
		}
	}
}
