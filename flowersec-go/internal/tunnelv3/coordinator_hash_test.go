package tunnelv3

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/artifactv3"
)

func hashTestLeg(role uint8, credential string, contract, candidates byte) *admittedLeg {
	leg := newExpiryTestLeg(role, time.Now().Add(time.Second))
	leg.authorization.Claims.AuthorityScope = "issuer"
	leg.authorization.Claims.CredentialID = credential
	leg.authorization.Claims.SessionContractHash[0] = contract
	leg.authorization.Claims.CandidateSetHash[0] = candidates
	return leg
}

func TestCoordinatorPairsByContractAcrossIndependentCandidateSets(t *testing.T) {
	coordinator, err := NewCoordinator(Config{PairTimeout: time.Second}, func(context.Context, *artifactv3.DecodedRequest) (Authorization, error) {
		return Authorization{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	register := func(role uint8, id string, contract, candidates byte) *pairGeneration {
		t.Helper()
		g, err := coordinator.register(t.Context(), hashTestLeg(role, id, contract, candidates))
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	a := register(1, "first-a", 1, 2)
	b := register(2, "second-b", 3, 2)
	if a == b {
		t.Fatal("different session contracts shared a generation")
	}
	if register(2, "second-a", 1, 4) != a || register(1, "first-b", 3, 5) != b {
		t.Fatal("matching contracts with independent candidate sets did not pair")
	}
	for _, g := range []*pairGeneration{a, b} {
		select {
		case <-g.done:
		case <-time.After(time.Second):
			t.Fatal("paired generation did not finish")
		}
	}
}

func TestCandidateSetMustMatchLocalAuthorization(t *testing.T) {
	auth := hashTestLeg(1, "first-a", 1, 2).authorization
	c := auth.Claims
	req := &artifactv3.DecodedRequest{Request: artifactv3.Request{
		PathKind: artifactv3.PathTunnel, ChannelID: c.ChannelID, Profile: c.Profile,
		RendezvousGroupID: c.RendezvousGroupID, ListenerAudience: c.ListenerAudience,
		SessionContractHash: c.SessionContractHash, CandidateSetHash: c.CandidateSetHash,
		Role: c.Role, EndpointInstanceID: c.EndpointInstanceID,
	}}
	now := time.Now()
	if err := validateAuthorization(req, auth, now); err != nil {
		t.Fatalf("local candidate set rejected: %v", err)
	}
	req.Request.CandidateSetHash[0] = 4
	if err := validateAuthorization(req, auth, now); !errors.Is(err, ErrInvalidAuthorization) {
		t.Fatalf("mismatched local candidate set: got %v, want invalid authorization", err)
	}
}
