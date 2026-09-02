package tunnelv3

import (
	"context"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/artifactv3"
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
	for _, testCase := range []struct {
		name                      string
		firstContract, firstSet   byte
		secondContract, secondSet byte
	}{
		{name: "contract", firstContract: 1, firstSet: 2, secondContract: 3, secondSet: 2},
		{name: "candidate set", firstContract: 1, firstSet: 2, secondContract: 1, secondSet: 4},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			coordinator, err := NewCoordinator(Config{PairTimeout: 20 * time.Millisecond}, func(context.Context, *artifactv3.DecodedRequest) (Authorization, error) {
				return Authorization{}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			generationA, err := coordinator.register(context.Background(), hashTestLeg(1, "first-a", testCase.firstContract, testCase.firstSet, false))
			if err != nil {
				t.Fatal(err)
			}
			generationB, err := coordinator.register(context.Background(), hashTestLeg(2, "second-b", testCase.secondContract, testCase.secondSet, false))
			if err != nil {
				t.Fatal(err)
			}
			if generationA == generationB {
				t.Fatal("different contract/candidate hashes shared a generation")
			}
			matchingPeer, err := coordinator.register(context.Background(), hashTestLeg(2, "second-a", testCase.firstContract, testCase.firstSet, false))
			if err != nil {
				t.Fatal(err)
			}
			if matchingPeer != generationA {
				t.Fatal("identical contract/candidate hashes did not pair in the existing generation")
			}
			for name, generation := range map[string]*pairGeneration{"matching": generationA, "isolated": generationB} {
				select {
				case <-generation.done:
				case <-time.After(time.Second):
					t.Fatalf("%s generation did not finish", name)
				}
			}
		})
	}
}
