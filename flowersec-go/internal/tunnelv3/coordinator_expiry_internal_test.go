package tunnelv3

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
)

func TestRegisterRevalidatesBothAuthorizationExpiriesBeforeActivation(t *testing.T) {
	for _, expiredRole := range []uint8{1, 2} {
		t.Run(string(rune('0'+expiredRole)), func(t *testing.T) {
			clock := time.Now()
			coordinator, err := NewCoordinator(Config{PairTimeout: time.Hour}, func(context.Context, *artifactv3.DecodedRequest) (Authorization, error) {
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
				if pending.responseStatus.Load() != int32(artifactv3.AdmissionRetryable) || pending.responseReason.Load() != artifactv3.ReasonExpiredArtifact {
					t.Fatalf("role %d expiry response = status:%d reason:%q", role, pending.responseStatus.Load(), pending.responseReason.Load())
				}
				if pending.activations.Load() != 0 {
					t.Fatalf("role %d activated after authorization expiry", role)
				}
			}
		})
	}
}

func TestPendingAuthorizationExpiryUsesExpiredArtifactReason(t *testing.T) {
	coordinator, err := NewCoordinator(Config{PairTimeout: 100 * time.Millisecond}, func(context.Context, *artifactv3.DecodedRequest) (Authorization, error) {
		return Authorization{}, errors.New("unused authorizer")
	})
	if err != nil {
		t.Fatal(err)
	}
	leg := newExpiryTestLeg(1, time.Now().Add(20*time.Millisecond))
	generation, err := coordinator.register(context.Background(), leg)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-generation.done:
	case <-time.After(time.Second):
		t.Fatal("expired pending leg was not rejected")
	}
	if leg.pending.(*expiryTestPendingLeg).responseReason.Load() != artifactv3.ReasonExpiredArtifact {
		t.Fatalf("pending expiry reason = %q, want %q", leg.pending.(*expiryTestPendingLeg).responseReason.Load(), artifactv3.ReasonExpiredArtifact)
	}
}

func TestDefaultReasonRegistryIncludesRetryableExpiredArtifact(t *testing.T) {
	reasons := DefaultReasonRegistry()
	response := artifactv3.AdmissionResponse{
		Status: artifactv3.AdmissionRetryable,
		Reason: artifactv3.ReasonExpiredArtifact,
	}
	if _, err := artifactv3.MarshalResponse(response, reasons); err != nil {
		t.Fatalf("default tunnel registry rejected retryable expiry: %v", err)
	}
}

func TestServeClassifiesPostAuthorizationExpiryAsRetryableExpiredArtifact(t *testing.T) {
	clock := time.Unix(2_000_000_000, 0)
	lease := &expiryTestLease{}
	pending := &serveExpiryPendingLeg{expiryTestPendingLeg: &expiryTestPendingLeg{}}
	coordinator, err := NewCoordinator(Config{}, func(_ context.Context, decoded *artifactv3.DecodedRequest) (Authorization, error) {
		request := decoded.Request
		return Authorization{
			Claims: VerifiedClaims{
				CredentialID: "credential", ChannelID: request.ChannelID, Profile: request.Profile,
				RendezvousGroupID: request.RendezvousGroupID, ListenerAudience: request.ListenerAudience,
				SessionContractHash: request.SessionContractHash, CandidateSetHash: request.CandidateSetHash,
				Role: request.Role, EndpointInstanceID: request.EndpointInstanceID,
				ExpectedPeerEndpointInstanceID: "endpoint-peer",
			},
			ExpiresAt: clock,
			Lease:     lease,
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator.now = func() time.Time { return clock }
	if err := coordinator.Serve(context.Background(), pending); !errors.Is(err, errExpiredAuthorization) {
		t.Fatalf("Serve error = %v, want expired authorization", err)
	}
	if pending.responseStatus.Load() != int32(artifactv3.AdmissionRetryable) || pending.responseReason.Load() != artifactv3.ReasonExpiredArtifact {
		t.Fatalf("expiry response = status:%d reason:%q", pending.responseStatus.Load(), pending.responseReason.Load())
	}
	if lease.releases.Load() != 1 || pending.closes.Load() != 1 {
		t.Fatalf("expiry cleanup = releases:%d closes:%d", lease.releases.Load(), pending.closes.Load())
	}
}

func TestReleaseLeaseDoesNotBlockCoordinatorCleanup(t *testing.T) {
	coordinator, err := NewCoordinator(Config{AdmissionResponseTimeout: 20 * time.Millisecond}, func(context.Context, *artifactv3.DecodedRequest) (Authorization, error) {
		return Authorization{}, errors.New("unused authorizer")
	})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	unblock := make(chan struct{})
	coordinator.releaseLease(blockingLease{started: started, unblock: unblock})
	select {
	case <-started:
	default:
		t.Fatal("lease release was not started")
	}
	close(unblock)
}

func TestServeBoundsAuthorizerThatIgnoresCancellation(t *testing.T) {
	started := make(chan struct{})
	unblock := make(chan struct{})
	coordinator, err := NewCoordinator(Config{
		AdmissionTimeout: 20 * time.Millisecond, AdmissionResponseTimeout: 20 * time.Millisecond,
	}, func(context.Context, *artifactv3.DecodedRequest) (Authorization, error) {
		close(started)
		<-unblock
		return Authorization{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	pending := &blockingAuthorizePendingLeg{}
	startedAt := time.Now()
	serveDone := make(chan error, 1)
	go func() { serveDone <- coordinator.Serve(context.Background(), pending) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("authorizer did not start")
	}
	select {
	case <-serveDone:
		if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
			t.Fatalf("Serve remained blocked for %s", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Serve remained blocked by a cancellation-ignoring authorizer")
	}
	close(unblock)
}

type blockingLease struct {
	started chan struct{}
	unblock chan struct{}
}

type blockingAuthorizePendingLeg struct{}

func (blockingAuthorizePendingLeg) CarrierKind() carrier.Kind { return carrier.KindRawQUIC }
func (blockingAuthorizePendingLeg) ReceiveAdmission(context.Context) (*artifactv3.DecodedRequest, error) {
	return &artifactv3.DecodedRequest{Request: artifactv3.Request{
		PathKind: artifactv3.PathTunnel, ChosenCandidateID: "candidate",
		Candidates: []artifactv3.CanonicalCandidate{{ID: "candidate", Carrier: artifactv3.CarrierRawQUIC}},
	}}, nil
}
func (blockingAuthorizePendingLeg) SendAdmission(context.Context, artifactv3.AdmissionResponse, artifactv3.ReasonRegistry) error {
	return nil
}
func (blockingAuthorizePendingLeg) Activate(context.Context, uint8) (carrier.Session, error) {
	return nil, errors.New("unexpected activation")
}
func (blockingAuthorizePendingLeg) CloseWithError(context.Context, carrier.ApplicationError) error {
	return nil
}

func (lease blockingLease) ReleaseContext(ctx context.Context) {
	close(lease.started)
	select {
	case <-lease.unblock:
	case <-ctx.Done():
	}
}

type expiryTestPendingLeg struct {
	responses      atomic.Int32
	responseStatus atomic.Int32
	responseReason atomic.Value
	activations    atomic.Int32
	closes         atomic.Int32
}

type serveExpiryPendingLeg struct{ *expiryTestPendingLeg }

func (leg *serveExpiryPendingLeg) ReceiveAdmission(context.Context) (*artifactv3.DecodedRequest, error) {
	return &artifactv3.DecodedRequest{Request: artifactv3.Request{
		PathKind: artifactv3.PathTunnel, ChosenCandidateID: "candidate",
		Candidates: []artifactv3.CanonicalCandidate{{ID: "candidate", Carrier: artifactv3.CarrierRawQUIC}},
		ChannelID:  "channel", Profile: artifactv3.Profile, RendezvousGroupID: "group",
		ListenerAudience: "audience", Role: 1, EndpointInstanceID: "endpoint-client",
	}}, nil
}

func newExpiryTestLeg(role uint8, expiresAt time.Time) *admittedLeg {
	peerRole := uint8(3 - role)
	return &admittedLeg{
		pending: &expiryTestPendingLeg{},
		authorization: Authorization{
			Claims: VerifiedClaims{
				CredentialID: "credential-" + string(rune('0'+role)), ChannelID: "channel", Profile: artifactv3.Profile,
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
func (leg *expiryTestPendingLeg) ReceiveAdmission(context.Context) (*artifactv3.DecodedRequest, error) {
	return nil, errors.New("unused admission read")
}
func (leg *expiryTestPendingLeg) SendAdmission(_ context.Context, response artifactv3.AdmissionResponse, _ artifactv3.ReasonRegistry) error {
	leg.responses.Add(1)
	leg.responseStatus.Store(int32(response.Status))
	leg.responseReason.Store(response.Reason)
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

func (lease *expiryTestLease) ReleaseContext(context.Context) { lease.releases.Add(1) }
