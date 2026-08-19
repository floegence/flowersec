package tunnelv2

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
)

func TestRegisterRevalidatesBothAuthorizationExpiriesBeforeActivation(t *testing.T) {
	for _, expiredRole := range []uint8{1, 2} {
		t.Run(string(rune('0'+expiredRole)), func(t *testing.T) {
			clock := time.Now()
			coordinator, err := NewCoordinator(Config{PairTimeout: time.Hour}, func(context.Context, *artifactv2.DecodedRequest) (Authorization, error) {
				return Authorization{}, errors.New("unused authorizer")
			})
			if err != nil {
				t.Fatal(err)
			}
			coordinator.now = func() time.Time { return clock }

			first := newExpiryTestLeg(1, clock.Add(time.Hour))
			if expiredRole == 1 {
				first.authorization.ExpiresAt = clock.Add(time.Minute)
			}
			generation, err := coordinator.register(context.Background(), first)
			if err != nil {
				t.Fatal(err)
			}

			clock = clock.Add(2 * time.Minute)
			second := newExpiryTestLeg(2, clock.Add(time.Hour))
			if expiredRole == 2 {
				second.authorization.ExpiresAt = clock.Add(-time.Minute)
			}
			pairedGeneration, err := coordinator.register(context.Background(), second)
			if err != nil {
				t.Fatal(err)
			}
			if pairedGeneration != generation {
				t.Fatal("matching legs did not join the same generation")
			}
			select {
			case <-generation.done:
			case <-time.After(time.Second):
				t.Fatal("expired pair was not rejected")
			}
			if !errors.Is(generation.err, ErrInvalidAuthorization) {
				t.Fatalf("generation error = %v, want invalid authorization", generation.err)
			}
			for role, leg := range map[uint8]*admittedLeg{1: first, 2: second} {
				pending := leg.pending.(*expiryTestPendingLeg)
				lease := leg.authorization.Lease.(*expiryTestLease)
				if pending.responses.Load() != 1 || pending.closes.Load() != 1 || lease.releases.Load() != 1 {
					t.Fatalf("role %d cleanup = responses:%d closes:%d releases:%d", role, pending.responses.Load(), pending.closes.Load(), lease.releases.Load())
				}
				if pending.activations.Load() != 0 {
					t.Fatalf("role %d activated after authorization expiry", role)
				}
			}
		})
	}
}

type expiryTestPendingLeg struct {
	responses   atomic.Int32
	activations atomic.Int32
	closes      atomic.Int32
}

func newExpiryTestLeg(role uint8, expiresAt time.Time) *admittedLeg {
	peerRole := uint8(3 - role)
	return &admittedLeg{
		pending: &expiryTestPendingLeg{},
		authorization: Authorization{
			Claims: VerifiedClaims{
				CredentialID: "credential-" + string(rune('0'+role)), ChannelID: "channel", Profile: artifactv2.Profile,
				RendezvousGroupID: "group", ListenerAudience: "audience", Role: role,
				EndpointInstanceID:             "endpoint-" + string(rune('0'+role)),
				ExpectedPeerEndpointInstanceID: "endpoint-" + string(rune('0'+peerRole)),
			},
			ExpiresAt: expiresAt,
			Lease:     &expiryTestLease{},
		},
	}
}

func (leg *expiryTestPendingLeg) CarrierKind() carrier.Kind { return carrier.KindRawQUIC }
func (leg *expiryTestPendingLeg) ReceiveAdmission(context.Context) (*artifactv2.DecodedRequest, error) {
	return nil, errors.New("unused admission read")
}
func (leg *expiryTestPendingLeg) SendAdmission(context.Context, artifactv2.AdmissionResponse, artifactv2.ReasonRegistry) error {
	leg.responses.Add(1)
	return nil
}
func (leg *expiryTestPendingLeg) Activate(context.Context, uint8) (carrier.Session, error) {
	leg.activations.Add(1)
	return nil, errors.New("unexpected activation")
}
func (leg *expiryTestPendingLeg) CloseWithError(context.Context, carrier.ApplicationError) error {
	leg.closes.Add(1)
	return nil
}

type expiryTestLease struct{ releases atomic.Int32 }

func (lease *expiryTestLease) Release() { lease.releases.Add(1) }
