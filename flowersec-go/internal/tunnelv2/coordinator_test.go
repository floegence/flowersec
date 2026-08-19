package tunnelv2_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/tunnelv2"
)

func TestDefaultConfigAllows1024ActivePairs(t *testing.T) {
	config := tunnelv2.DefaultConfig()
	if config.MaxConcurrentAdmissions != 1024 || config.MaxActivePairs != 1024 || config.MaxPendingLegs != 1024 {
		t.Fatalf("default tunnel capacity = admissions %d active %d pending %d", config.MaxConcurrentAdmissions, config.MaxActivePairs, config.MaxPendingLegs)
	}
	if config.AdmissionTimeout != 10*time.Second {
		t.Fatalf("default admission timeout = %v", config.AdmissionTimeout)
	}
}

func TestCoordinatorAdmissionTimeoutStopsCredentialRead(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{AdmissionTimeout: 20 * time.Millisecond})
	_, tunnel := memorySessionPair(carrier.KindRawQUIC)
	leg := newPendingLeg(tunnelRequest(1, "client", "silent-token"), tunnel)
	leg.blockReceive = true

	done := serveLeg(coordinator, context.Background(), leg)
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Serve error = %v, want admission deadline", err)
	}
	if leg.authorized.Load() != 0 || leg.closed.Load() != 1 {
		t.Fatalf("silent leg state = authorized:%d closed:%d", leg.authorized.Load(), leg.closed.Load())
	}
}

func TestCoordinatorAdmissionTimeoutStopsAuthorizerAndReleasesCapacity(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{
		AdmissionTimeout:        20 * time.Millisecond,
		MaxConcurrentAdmissions: 1,
	})
	_, blockedTunnel := memorySessionPair(carrier.KindRawQUIC)
	blocked := newPendingLeg(tunnelRequest(1, "client", "blocked-authorizer-timeout"), blockedTunnel)
	blocked.authorizeGate = make(chan struct{})
	blocked.authorizeStarted = make(chan struct{})

	done := serveLeg(coordinator, context.Background(), blocked)
	waitForSignal(t, blocked.authorizeStarted, "blocked authorizer call")
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Serve error = %v, want admission deadline", err)
	}
	if blocked.authorized.Load() != 1 || blocked.closed.Load() != 1 {
		t.Fatalf("timed-out authorizer state = authorized:%d closed:%d", blocked.authorized.Load(), blocked.closed.Load())
	}

	_, nextTunnel := memorySessionPair(carrier.KindRawQUIC)
	next := newPendingLeg(tunnelRequest(1, "client", "slot-after-timeout"), nextTunnel)
	next.authorizeErr = errors.New("authorization probe")
	if err := <-serveLeg(coordinator, context.Background(), next); !errors.Is(err, next.authorizeErr) {
		t.Fatalf("released-slot Serve error = %v", err)
	}
	if next.authorized.Load() != 1 {
		t.Fatalf("released-slot authorizer calls = %d", next.authorized.Load())
	}
}

func TestCoordinatorPreAuthorizationCapacityBoundsAuthorizerCalls(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{
		AdmissionTimeout:        time.Second,
		MaxConcurrentAdmissions: 1,
	})
	_, firstTunnel := memorySessionPair(carrier.KindRawQUIC)
	first := newPendingLeg(tunnelRequest(1, "client", "blocked-authorizer"), firstTunnel)
	gate := make(chan struct{})
	first.authorizeGate = gate
	first.authorizeStarted = make(chan struct{})
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstDone := serveLeg(coordinator, firstCtx, first)
	waitForSignal(t, first.authorizeStarted, "first authorizer call")

	_, rejectedTunnel := memorySessionPair(carrier.KindRawQUIC)
	rejected := newPendingLeg(tunnelRequest(2, "server", "capacity-rejected"), rejectedTunnel)
	if err := <-serveLeg(coordinator, context.Background(), rejected); !errors.Is(err, tunnelv2.ErrCapacity) {
		t.Fatalf("capacity Serve error = %v", err)
	}
	select {
	case <-rejected.received:
		t.Fatal("capacity-rejected leg read credentials")
	default:
	}
	if rejected.authorized.Load() != 0 || rejected.closed.Load() != 1 {
		t.Fatalf("capacity-rejected state = authorized:%d closed:%d", rejected.authorized.Load(), rejected.closed.Load())
	}

	cancelFirst()
	assertServeCanceled(t, firstDone)
	close(gate)
	_, nextTunnel := memorySessionPair(carrier.KindRawQUIC)
	next := newPendingLeg(tunnelRequest(1, "client", "released-admission-slot"), nextTunnel)
	next.authorizeErr = errors.New("authorization probe")
	if err := <-serveLeg(coordinator, context.Background(), next); !errors.Is(err, next.authorizeErr) {
		t.Fatalf("released-slot Serve error = %v", err)
	}
	if next.authorized.Load() != 1 {
		t.Fatalf("released-slot authorizer calls = %d", next.authorized.Load())
	}
}

func TestCoordinatorRejectsInvalidAdmissionConfig(t *testing.T) {
	tests := []struct {
		name   string
		config tunnelv2.Config
	}{
		{name: "timeout", config: tunnelv2.Config{AdmissionTimeout: -time.Second}},
		{name: "capacity", config: tunnelv2.Config{MaxConcurrentAdmissions: -1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := tunnelv2.NewCoordinator(test.config, func(context.Context, *artifactv2.DecodedRequest) (tunnelv2.Authorization, error) {
				return tunnelv2.Authorization{}, nil
			})
			if !errors.Is(err, tunnelv2.ErrInvalidConfig) {
				t.Fatalf("NewCoordinator error = %v, want invalid config", err)
			}
		})
	}
}

func TestCoordinatorWaitsForBothAuthorizedLegsBeforeSuccess(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{})
	clientEndpoint, clientTunnel := memorySessionPair(carrier.KindRawQUIC)
	serverEndpoint, serverTunnel := memorySessionPair(carrier.KindWebTransport)
	client := newPendingLeg(tunnelRequest(1, "client", "client-token"), clientTunnel)
	server := newPendingLeg(tunnelRequest(2, "server", "server-token"), serverTunnel)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientDone := serveLeg(coordinator, ctx, client)
	waitForSignal(t, client.received, "client admission")
	assertNoResponse(t, client)

	serverDone := serveLeg(coordinator, ctx, server)
	assertSuccessResponse(t, client)
	assertSuccessResponse(t, server)

	controlClient := openStream(t, clientEndpoint)
	controlServer := acceptStream(t, serverEndpoint)
	assertOpenStreamRoundTrip(t, controlClient, controlServer, "FSC2", "FSH2")

	cancel()
	assertServeCanceled(t, clientDone)
	assertServeCanceled(t, serverDone)
	assertLeaseReleasedOnce(t, client)
	assertLeaseReleasedOnce(t, server)
}

func TestCoordinatorRejectsChosenCandidateCarrierMismatch(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{})
	_, tunnel := memorySessionPair(carrier.KindWebSocket)
	request := tunnelRequest(1, "client", "carrier-mismatch-token")
	request.Candidates = []artifactv2.CanonicalCandidate{{
		ID: "q1", Carrier: artifactv2.CarrierRawQUIC, NormalizedURL: "quic://example.com", WireProfile: "flowersec-tunnel/2",
	}}
	request.ChosenCandidateID = "q1"
	leg := newPendingLeg(request, tunnel)

	err := <-serveLeg(coordinator, context.Background(), leg)
	if !errors.Is(err, tunnelv2.ErrCarrierMismatch) {
		t.Fatalf("Serve error = %v, want carrier mismatch", err)
	}
	if leg.activations.Load() != 0 {
		t.Fatalf("carrier-mismatched leg activated %d time(s)", leg.activations.Load())
	}
}

func TestCoordinatorSuccessWriteFailureClosesBothLegsWithoutActivation(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{})
	_, clientTunnel := memorySessionPair(carrier.KindRawQUIC)
	_, serverTunnel := memorySessionPair(carrier.KindRawQUIC)
	client := newPendingLeg(tunnelRequest(1, "client", "client-token"), clientTunnel)
	server := newPendingLeg(tunnelRequest(2, "server", "server-token"), serverTunnel)
	server.sendErr = io.ErrClosedPipe

	clientDone := serveLeg(coordinator, context.Background(), client)
	serverDone := serveLeg(coordinator, context.Background(), server)
	if err := <-clientDone; !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("client Serve error = %v", err)
	}
	if err := <-serverDone; !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("server Serve error = %v", err)
	}
	if client.closed.Load() != 1 || server.closed.Load() != 1 {
		t.Fatalf("close counts = client:%d server:%d", client.closed.Load(), server.closed.Load())
	}
	if client.activations.Load() != 0 || server.activations.Load() != 0 {
		t.Fatalf("unexpected activation = client:%d server:%d", client.activations.Load(), server.activations.Load())
	}
	assertLeaseReleasedOnce(t, client)
	assertLeaseReleasedOnce(t, server)
}

func TestCoordinatorPairTimeoutUsesEarlierAuthorizationExpiry(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{PairTimeout: time.Second})
	_, tunnel := memorySessionPair(carrier.KindRawQUIC)
	leg := newPendingLeg(tunnelRequest(1, "client", "expiring-token"), tunnel)
	leg.expiresAt = time.Now().Add(35 * time.Millisecond)

	started := time.Now()
	done := serveLeg(coordinator, context.Background(), leg)
	assertResponse(t, leg, artifactv2.AdmissionRetryable, tunnelv2.ReasonPairTimeout)
	if err := <-done; !errors.Is(err, tunnelv2.ErrPairTimeout) {
		t.Fatalf("Serve error = %v", err)
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("authorization expiry did not bound pair timeout: %v", elapsed)
	}
	if leg.closed.Load() != 1 {
		t.Fatalf("close count = %d", leg.closed.Load())
	}
	assertLeaseReleasedOnce(t, leg)
}

func TestCoordinatorRejectsWaitingNativeStreams(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{})
	_, tunnel := memorySessionPair(carrier.KindRawQUIC)
	base := newPendingLeg(tunnelRequest(1, "client", "guard-token"), tunnel)
	leg := &guardedPendingLeg{pendingLeg: base, extras: make(chan carrier.Stream, 1), started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := serveLeg(coordinator, ctx, leg)
	waitForSignal(t, leg.started, "waiting stream guard")
	probe := newResetProbe()
	leg.extras <- probe
	waitForSignal(t, probe.reset, "extra stream reset")
	assertNoResponse(t, base)

	cancel()
	assertServeCanceled(t, done)
	assertLeaseReleasedOnce(t, base)
}

func TestCoordinatorCredentialReplayDoesNotReplacePendingLeg(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{})
	clientEndpoint, clientTunnel := memorySessionPair(carrier.KindRawQUIC)
	_, replayTunnel := memorySessionPair(carrier.KindRawQUIC)
	serverEndpoint, serverTunnel := memorySessionPair(carrier.KindRawQUIC)
	client := newPendingLeg(tunnelRequest(1, "client", "one-shot-token"), clientTunnel)
	replay := newPendingLeg(tunnelRequest(1, "client", "one-shot-token"), replayTunnel)
	server := newPendingLeg(tunnelRequest(2, "server", "server-token"), serverTunnel)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientDone := serveLeg(coordinator, ctx, client)
	waitForSignal(t, client.received, "first credential")
	assertNoResponse(t, client)

	replayDone := serveLeg(coordinator, context.Background(), replay)
	assertResponse(t, replay, artifactv2.AdmissionReject, tunnelv2.ReasonCredentialReplay)
	if err := <-replayDone; !errors.Is(err, tunnelv2.ErrCredentialReplay) {
		t.Fatalf("replay Serve error = %v", err)
	}
	if client.closed.Load() != 0 {
		t.Fatal("credential replay replaced the authoritative pending leg")
	}

	serverDone := serveLeg(coordinator, ctx, server)
	assertSuccessResponse(t, client)
	assertSuccessResponse(t, server)
	controlClient := openStream(t, clientEndpoint)
	controlServer := acceptStream(t, serverEndpoint)
	cancel()
	assertServeCanceled(t, clientDone)
	assertServeCanceled(t, serverDone)
	_ = controlClient.Reset()
	_ = controlServer.Reset()
	assertLeaseReleasedOnce(t, client)
	assertLeaseReleasedOnce(t, replay)
}

func TestCoordinatorDuplicateRoleReplacesWholePendingGeneration(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{})
	_, oldTunnel := memorySessionPair(carrier.KindRawQUIC)
	clientEndpoint, newTunnel := memorySessionPair(carrier.KindRawQUIC)
	serverEndpoint, serverTunnel := memorySessionPair(carrier.KindRawQUIC)
	oldClient := newPendingLeg(tunnelRequest(1, "client", "old-client-token"), oldTunnel)
	newClient := newPendingLeg(tunnelRequest(1, "client", "new-client-token"), newTunnel)
	server := newPendingLeg(tunnelRequest(2, "server", "new-server-token"), serverTunnel)

	oldDone := serveLeg(coordinator, context.Background(), oldClient)
	waitForSignal(t, oldClient.received, "old client")
	assertNoResponse(t, oldClient)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	newDone := serveLeg(coordinator, ctx, newClient)
	assertResponse(t, oldClient, artifactv2.AdmissionReject, tunnelv2.ReasonReplaced)
	if err := <-oldDone; !errors.Is(err, tunnelv2.ErrReplaced) {
		t.Fatalf("old Serve error = %v", err)
	}
	assertLeaseReleasedOnce(t, oldClient)
	assertNoResponse(t, newClient)

	serverDone := serveLeg(coordinator, ctx, server)
	assertSuccessResponse(t, newClient)
	assertSuccessResponse(t, server)
	controlClient := openStream(t, clientEndpoint)
	controlServer := acceptStream(t, serverEndpoint)
	cancel()
	assertServeCanceled(t, newDone)
	assertServeCanceled(t, serverDone)
	_ = controlClient.Reset()
	_ = controlServer.Reset()
}

func TestCoordinatorReplacementRequiresVerifiedPermission(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{})
	_, oldTunnel := memorySessionPair(carrier.KindRawQUIC)
	_, deniedTunnel := memorySessionPair(carrier.KindRawQUIC)
	_, serverTunnel := memorySessionPair(carrier.KindRawQUIC)
	oldClient := newPendingLeg(tunnelRequest(1, "client", "protected-client"), oldTunnel)
	denied := newPendingLeg(tunnelRequest(1, "client", "ordinary-client"), deniedTunnel)
	denied.allowReplacement = false
	server := newPendingLeg(tunnelRequest(2, "server", "protected-server"), serverTunnel)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	oldDone := serveLeg(coordinator, ctx, oldClient)
	waitForSignal(t, oldClient.received, "protected client")
	assertNoResponse(t, oldClient)
	deniedDone := serveLeg(coordinator, context.Background(), denied)
	assertResponse(t, denied, artifactv2.AdmissionReject, tunnelv2.ReasonReplacementDenied)
	if err := <-deniedDone; !errors.Is(err, tunnelv2.ErrReplacementDenied) {
		t.Fatalf("denied replacement error = %v", err)
	}
	if oldClient.closed.Load() != 0 {
		t.Fatal("denied replacement closed the existing generation")
	}

	serverDone := serveLeg(coordinator, ctx, server)
	assertSuccessResponse(t, oldClient)
	assertSuccessResponse(t, server)
	cancel()
	assertServeCanceled(t, oldDone)
	assertServeCanceled(t, serverDone)
}

func TestCoordinatorPreservesRegisteredAuthorizerResponse(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{Reasons: artifactv2.ReasonRegistry{"policy_busy": {}}})
	_, tunnel := memorySessionPair(carrier.KindRawQUIC)
	leg := newPendingLeg(tunnelRequest(1, "client", "policy-token"), tunnel)
	leg.authorizeErr = &admissionv2.ResponseError{Status: artifactv2.AdmissionRetryable, Reason: "policy_busy"}

	done := serveLeg(coordinator, context.Background(), leg)
	assertResponse(t, leg, artifactv2.AdmissionRetryable, "policy_busy")
	var responseError *admissionv2.ResponseError
	if err := <-done; !errors.As(err, &responseError) || responseError.Reason != "policy_busy" {
		t.Fatalf("Serve error = %v", err)
	}
}

func TestCoordinatorRejectsClaimsThatDoNotBindFSB2(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{})
	_, tunnel := memorySessionPair(carrier.KindRawQUIC)
	leg := newPendingLeg(tunnelRequest(1, "client", "misbound-token"), tunnel)
	leg.mutateClaims = func(claims *tunnelv2.VerifiedClaims) { claims.ListenerAudience = "other-listener" }

	done := serveLeg(coordinator, context.Background(), leg)
	assertResponse(t, leg, artifactv2.AdmissionReject, tunnelv2.ReasonInvalidCredential)
	if err := <-done; !errors.Is(err, tunnelv2.ErrInvalidAuthorization) {
		t.Fatalf("Serve error = %v", err)
	}
	assertLeaseReleasedOnce(t, leg)
}

func TestCoordinatorPairRequiresMirroredEndpointClaims(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{})
	_, clientTunnel := memorySessionPair(carrier.KindRawQUIC)
	_, mismatchedTunnel := memorySessionPair(carrier.KindRawQUIC)
	_, serverTunnel := memorySessionPair(carrier.KindRawQUIC)
	client := newPendingLeg(tunnelRequest(1, "client", "mirror-client"), clientTunnel)
	mismatched := newPendingLeg(tunnelRequest(2, "server", "mirror-bad-server"), mismatchedTunnel)
	mismatched.mutateClaims = func(claims *tunnelv2.VerifiedClaims) { claims.ExpectedPeerEndpointInstanceID = "someone-else" }
	server := newPendingLeg(tunnelRequest(2, "server", "mirror-server"), serverTunnel)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientDone := serveLeg(coordinator, ctx, client)
	waitForSignal(t, client.received, "mirror client")
	assertNoResponse(t, client)
	mismatchDone := serveLeg(coordinator, context.Background(), mismatched)
	assertResponse(t, mismatched, artifactv2.AdmissionReject, tunnelv2.ReasonPairMismatch)
	if err := <-mismatchDone; !errors.Is(err, tunnelv2.ErrPairMismatch) {
		t.Fatalf("mismatched Serve error = %v", err)
	}
	if client.closed.Load() != 0 {
		t.Fatal("pair mismatch closed the compatible waiting leg")
	}

	serverDone := serveLeg(coordinator, ctx, server)
	assertSuccessResponse(t, client)
	assertSuccessResponse(t, server)
	waitForActivations(t, client, server)
	cancel()
	assertServeCanceled(t, clientDone)
	assertServeCanceled(t, serverDone)
}

func TestCoordinatorScopedChannelRejectsDifferentSessionContract(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{})
	_, clientTunnel := memorySessionPair(carrier.KindRawQUIC)
	_, serverTunnel := memorySessionPair(carrier.KindRawQUIC)
	client := &guardedPendingLeg{
		pendingLeg: newPendingLeg(tunnelRequest(1, "client", "contract-client"), clientTunnel),
		extras:     make(chan carrier.Stream),
		started:    make(chan struct{}),
	}
	serverRequest := tunnelRequest(2, "server", "contract-server")
	serverRequest.SessionContractHash[0]++
	server := newPendingLeg(serverRequest, serverTunnel)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientDone := serveLeg(coordinator, ctx, client)
	waitForSignal(t, client.started, "contract client registration")
	serverDone := serveLeg(coordinator, context.Background(), server)
	assertResponse(t, server, artifactv2.AdmissionReject, tunnelv2.ReasonPairMismatch)
	if err := <-serverDone; !errors.Is(err, tunnelv2.ErrPairMismatch) {
		t.Fatalf("server Serve error = %v", err)
	}
	if client.closed.Load() != 0 {
		t.Fatal("contract mismatch disturbed the authoritative waiting generation")
	}
	cancel()
	assertServeCanceled(t, clientDone)
}

func TestCoordinatorPendingAndActiveQuotaRelease(t *testing.T) {
	t.Run("pending", func(t *testing.T) {
		coordinator := newTestCoordinator(t, tunnelv2.Config{MaxPendingLegs: 1})
		_, firstTunnel := memorySessionPair(carrier.KindRawQUIC)
		_, rejectedTunnel := memorySessionPair(carrier.KindRawQUIC)
		_, afterReleaseTunnel := memorySessionPair(carrier.KindRawQUIC)
		first := newPendingLeg(tunnelRequestForChannel(1, "client", "pending-1", "channel-a"), firstTunnel)
		rejected := newPendingLeg(tunnelRequestForChannel(1, "client", "pending-2", "channel-b"), rejectedTunnel)
		afterRelease := newPendingLeg(tunnelRequestForChannel(1, "client", "pending-3", "channel-c"), afterReleaseTunnel)

		ctx, cancel := context.WithCancel(context.Background())
		firstDone := serveLeg(coordinator, ctx, first)
		waitForSignal(t, first.received, "pending quota holder")
		assertNoResponse(t, first)
		rejectedDone := serveLeg(coordinator, context.Background(), rejected)
		assertResponse(t, rejected, artifactv2.AdmissionRetryable, tunnelv2.ReasonCapacity)
		if err := <-rejectedDone; !errors.Is(err, tunnelv2.ErrCapacity) {
			t.Fatalf("capacity error = %v", err)
		}
		cancel()
		assertServeCanceled(t, firstDone)

		afterCtx, afterCancel := context.WithCancel(context.Background())
		afterDone := serveLeg(coordinator, afterCtx, afterRelease)
		waitForSignal(t, afterRelease.received, "post-release pending leg")
		assertNoResponse(t, afterRelease)
		afterCancel()
		assertServeCanceled(t, afterDone)
		assertLeaseReleasedOnce(t, first)
		assertLeaseReleasedOnce(t, rejected)
		assertLeaseReleasedOnce(t, afterRelease)
	})

	t.Run("active", func(t *testing.T) {
		coordinator := newTestCoordinator(t, tunnelv2.Config{MaxActivePairs: 1})
		_, activeClientTunnel := memorySessionPair(carrier.KindRawQUIC)
		_, activeServerTunnel := memorySessionPair(carrier.KindRawQUIC)
		_, blockedClientTunnel := memorySessionPair(carrier.KindRawQUIC)
		_, blockedServerTunnel := memorySessionPair(carrier.KindRawQUIC)
		activeClient := newPendingLeg(tunnelRequestForChannel(1, "client", "active-c", "channel-a"), activeClientTunnel)
		activeServer := newPendingLeg(tunnelRequestForChannel(2, "server", "active-s", "channel-a"), activeServerTunnel)
		blockedClient := newPendingLeg(tunnelRequestForChannel(1, "client", "blocked-c", "channel-b"), blockedClientTunnel)
		blockedServer := newPendingLeg(tunnelRequestForChannel(2, "server", "blocked-s", "channel-b"), blockedServerTunnel)

		activeCtx, cancelActive := context.WithCancel(context.Background())
		activeClientDone := serveLeg(coordinator, activeCtx, activeClient)
		activeServerDone := serveLeg(coordinator, activeCtx, activeServer)
		assertSuccessResponse(t, activeClient)
		assertSuccessResponse(t, activeServer)

		blockedClientDone := serveLeg(coordinator, context.Background(), blockedClient)
		blockedServerDone := serveLeg(coordinator, context.Background(), blockedServer)
		assertResponse(t, blockedClient, artifactv2.AdmissionRetryable, tunnelv2.ReasonCapacity)
		assertResponse(t, blockedServer, artifactv2.AdmissionRetryable, tunnelv2.ReasonCapacity)
		if err := <-blockedClientDone; !errors.Is(err, tunnelv2.ErrCapacity) {
			t.Fatalf("blocked client error = %v", err)
		}
		if err := <-blockedServerDone; !errors.Is(err, tunnelv2.ErrCapacity) {
			t.Fatalf("blocked server error = %v", err)
		}
		cancelActive()
		assertServeCanceled(t, activeClientDone)
		assertServeCanceled(t, activeServerDone)
		assertLeaseReleasedOnce(t, blockedClient)
		assertLeaseReleasedOnce(t, blockedServer)

		_, nextClientTunnel := memorySessionPair(carrier.KindRawQUIC)
		_, nextServerTunnel := memorySessionPair(carrier.KindRawQUIC)
		nextClient := newPendingLeg(tunnelRequestForChannel(1, "client", "next-c", "channel-c"), nextClientTunnel)
		nextServer := newPendingLeg(tunnelRequestForChannel(2, "server", "next-s", "channel-c"), nextServerTunnel)
		nextCtx, cancelNext := context.WithCancel(context.Background())
		nextClientDone := serveLeg(coordinator, nextCtx, nextClient)
		nextServerDone := serveLeg(coordinator, nextCtx, nextServer)
		assertSuccessResponse(t, nextClient)
		assertSuccessResponse(t, nextServer)
		cancelNext()
		assertServeCanceled(t, nextClientDone)
		assertServeCanceled(t, nextServerDone)
	})
}

func TestCoordinatorNewGenerationClosesActivePairBeforeBecomingAuthoritative(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{})
	_, oldClientTunnel := memorySessionPair(carrier.KindRawQUIC)
	_, oldServerTunnel := memorySessionPair(carrier.KindRawQUIC)
	_, newClientTunnel := memorySessionPair(carrier.KindRawQUIC)
	_, newServerTunnel := memorySessionPair(carrier.KindRawQUIC)
	oldClient := newPendingLeg(tunnelRequest(1, "client", "old-active-client"), oldClientTunnel)
	oldServer := newPendingLeg(tunnelRequest(2, "server", "old-active-server"), oldServerTunnel)
	newClient := newPendingLeg(tunnelRequest(1, "client", "new-active-client"), newClientTunnel)
	newServer := newPendingLeg(tunnelRequest(2, "server", "new-active-server"), newServerTunnel)

	oldClientDone := serveLeg(coordinator, context.Background(), oldClient)
	oldServerDone := serveLeg(coordinator, context.Background(), oldServer)
	assertSuccessResponse(t, oldClient)
	assertSuccessResponse(t, oldServer)
	waitForActivations(t, oldClient, oldServer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	newClientDone := serveLeg(coordinator, ctx, newClient)
	if err := <-oldClientDone; !errors.Is(err, tunnelv2.ErrReplaced) {
		t.Fatalf("old client Serve error = %v", err)
	}
	if err := <-oldServerDone; !errors.Is(err, tunnelv2.ErrReplaced) {
		t.Fatalf("old server Serve error = %v", err)
	}
	if oldClient.closed.Load() != 1 || oldServer.closed.Load() != 1 {
		t.Fatalf("old close counts = client:%d server:%d", oldClient.closed.Load(), oldServer.closed.Load())
	}
	assertNoResponse(t, newClient)

	newServerDone := serveLeg(coordinator, ctx, newServer)
	assertSuccessResponse(t, newClient)
	assertSuccessResponse(t, newServer)
	waitForActivations(t, newClient, newServer)
	cancel()
	assertServeCanceled(t, newClientDone)
	assertServeCanceled(t, newServerDone)
}

func TestCoordinatorCleanupHasSingleWinnerAcrossTimeoutAndCancellation(t *testing.T) {
	for iteration := range 50 {
		coordinator := newTestCoordinator(t, tunnelv2.Config{PairTimeout: 5 * time.Millisecond})
		_, tunnel := memorySessionPair(carrier.KindRawQUIC)
		leg := newPendingLeg(tunnelRequest(1, "client", fmt.Sprintf("race-token-%d", iteration)), tunnel)
		ctx, cancel := context.WithCancel(context.Background())
		done := serveLeg(coordinator, ctx, leg)
		waitForSignal(t, leg.received, "race admission")
		time.AfterFunc(5*time.Millisecond, cancel)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("cleanup race did not finish")
		}
		time.Sleep(time.Millisecond)
		assertLeaseReleasedOnce(t, leg)
		if got := leg.closed.Load(); got != 1 {
			t.Fatalf("close count = %d", got)
		}
	}
}

func TestCoordinatorBoundsWaitingGuardShutdown(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{GuardStopTimeout: 10 * time.Millisecond})
	_, clientTunnel := memorySessionPair(carrier.KindRawQUIC)
	_, serverTunnel := memorySessionPair(carrier.KindRawQUIC)
	base := newPendingLeg(tunnelRequest(1, "client", "stuck-guard-client"), clientTunnel)
	client := &stuckGuardLeg{pendingLeg: base, started: make(chan struct{}), release: make(chan struct{})}
	server := newPendingLeg(tunnelRequest(2, "server", "stuck-guard-server"), serverTunnel)

	clientDone := serveLeg(coordinator, context.Background(), client)
	waitForSignal(t, client.started, "stuck guard")
	serverDone := serveLeg(coordinator, context.Background(), server)
	if err := <-clientDone; !errors.Is(err, tunnelv2.ErrWaitingGuardStuck) {
		t.Fatalf("client Serve error = %v", err)
	}
	if err := <-serverDone; !errors.Is(err, tunnelv2.ErrWaitingGuardStuck) {
		t.Fatalf("server Serve error = %v", err)
	}
	close(client.release)
	assertLeaseReleasedOnce(t, base)
	assertLeaseReleasedOnce(t, server)
}

func TestCoordinatorBoundsAdmissionResponseAndActivation(t *testing.T) {
	t.Run("success response", func(t *testing.T) {
		coordinator := newTestCoordinator(t, tunnelv2.Config{AdmissionResponseTimeout: 10 * time.Millisecond})
		_, clientTunnel := memorySessionPair(carrier.KindRawQUIC)
		_, serverTunnel := memorySessionPair(carrier.KindRawQUIC)
		client := newPendingLeg(tunnelRequest(1, "client", "blocked-success-client"), clientTunnel)
		server := newPendingLeg(tunnelRequest(2, "server", "blocked-success-server"), serverTunnel)
		client.blockSend = true
		clientDone := serveLeg(coordinator, context.Background(), client)
		serverDone := serveLeg(coordinator, context.Background(), server)
		if err := <-clientDone; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("client Serve error = %v", err)
		}
		if err := <-serverDone; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("server Serve error = %v", err)
		}
		assertLeaseReleasedOnce(t, client)
		assertLeaseReleasedOnce(t, server)
	})

	t.Run("rejection response", func(t *testing.T) {
		coordinator := newTestCoordinator(t, tunnelv2.Config{
			PairTimeout: 5 * time.Millisecond, AdmissionResponseTimeout: 10 * time.Millisecond,
		})
		_, tunnel := memorySessionPair(carrier.KindRawQUIC)
		leg := newPendingLeg(tunnelRequest(1, "client", "blocked-reject"), tunnel)
		leg.blockSend = true
		done := serveLeg(coordinator, context.Background(), leg)
		if err := <-done; !errors.Is(err, tunnelv2.ErrPairTimeout) {
			t.Fatalf("Serve error = %v", err)
		}
		assertLeaseReleasedOnce(t, leg)
	})

	t.Run("activation", func(t *testing.T) {
		coordinator := newTestCoordinator(t, tunnelv2.Config{ActivationTimeout: 10 * time.Millisecond})
		_, clientTunnel := memorySessionPair(carrier.KindRawQUIC)
		_, serverTunnel := memorySessionPair(carrier.KindRawQUIC)
		client := newPendingLeg(tunnelRequest(1, "client", "blocked-activate-client"), clientTunnel)
		server := newPendingLeg(tunnelRequest(2, "server", "blocked-activate-server"), serverTunnel)
		client.blockActivation = true
		clientDone := serveLeg(coordinator, context.Background(), client)
		serverDone := serveLeg(coordinator, context.Background(), server)
		assertSuccessResponse(t, client)
		assertSuccessResponse(t, server)
		if err := <-clientDone; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("client Serve error = %v", err)
		}
		if err := <-serverDone; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("server Serve error = %v", err)
		}
		assertLeaseReleasedOnce(t, client)
		assertLeaseReleasedOnce(t, server)
	})
}

func TestCoordinatorCleanupDeadlineBoundsPendingLegClose(t *testing.T) {
	coordinator := newTestCoordinator(t, tunnelv2.Config{BridgeLimits: tunnelv2.Limits{
		MaxConcurrentStreams: 8,
		CopyBufferBytes:      1024,
		CleanupTimeout:       20 * time.Millisecond,
	}})
	clientEndpoint, clientTunnel := memorySessionPair(carrier.KindRawQUIC)
	serverEndpoint, serverTunnel := memorySessionPair(carrier.KindRawQUIC)
	release := make(chan struct{})
	client := newPendingLeg(tunnelRequest(1, "client", "cleanup-client"), clientTunnel)
	server := newPendingLeg(tunnelRequest(2, "server", "cleanup-server"), serverTunnel)
	client.closeBlock, server.closeBlock = release, release
	client.closeEntered, server.closeEntered = make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	clientDone := serveLeg(coordinator, ctx, client)
	serverDone := serveLeg(coordinator, ctx, server)
	assertSuccessResponse(t, client)
	assertSuccessResponse(t, server)
	waitForActivations(t, client, server)
	_ = openStream(t, clientEndpoint)
	_ = acceptStream(t, serverEndpoint)
	cancel()
	select {
	case <-client.closeEntered:
	case <-server.closeEntered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for pending leg close")
	}

	result := make(chan error, 2)
	go func() { result <- <-clientDone }()
	go func() { result <- <-serverDone }()
	for range 2 {
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				close(release)
				t.Fatalf("Serve error = %v, want canceled", err)
			}
		case <-time.After(250 * time.Millisecond):
			close(release)
			<-result
			<-result
			t.Fatal("Coordinator cleanup ignored its configured deadline")
		}
	}
	close(release)
}

func newTestCoordinator(t *testing.T, config tunnelv2.Config) *tunnelv2.Coordinator {
	t.Helper()
	coordinator, err := tunnelv2.NewCoordinator(config, func(ctx context.Context, decoded *artifactv2.DecodedRequest) (tunnelv2.Authorization, error) {
		request := decoded.Request
		expected := "server"
		if request.Role == 2 {
			expected = "client"
		}
		leg := currentPendingLeg(decoded)
		leg.authorized.Add(1)
		if leg.authorizeStarted != nil {
			leg.authorizeStartedOnce.Do(func() { close(leg.authorizeStarted) })
		}
		if leg.authorizeGate != nil {
			select {
			case <-leg.authorizeGate:
			case <-ctx.Done():
				return tunnelv2.Authorization{}, ctx.Err()
			}
		}
		if leg.authorizeErr != nil {
			return tunnelv2.Authorization{}, leg.authorizeErr
		}
		claims := tunnelv2.VerifiedClaims{
			CredentialID:                   request.AttachToken,
			ChannelID:                      request.ChannelID,
			Profile:                        request.Profile,
			RendezvousGroupID:              request.RendezvousGroupID,
			SessionContractHash:            request.SessionContractHash,
			CandidateSetHash:               request.CandidateSetHash,
			ListenerAudience:               request.ListenerAudience,
			Role:                           request.Role,
			EndpointInstanceID:             request.EndpointInstanceID,
			ExpectedPeerEndpointInstanceID: expected,
			AllowReplacement:               leg.allowReplacement,
		}
		if leg.mutateClaims != nil {
			leg.mutateClaims(&claims)
		}
		return tunnelv2.Authorization{
			Claims:    claims,
			ExpiresAt: leg.expiresAt,
			Lease:     leg.lease,
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

var pendingLegByBinding sync.Map

func currentPendingLeg(decoded *artifactv2.DecodedRequest) *pendingLeg {
	value, ok := pendingLegByBinding.Load(decoded.LocalAdmissionBinding)
	if !ok {
		panic("test pending leg not registered")
	}
	return value.(*pendingLeg)
}

type pendingLeg struct {
	decoded              *artifactv2.DecodedRequest
	session              carrier.Session
	lease                *countingLease
	received             chan struct{}
	responses            chan artifactv2.AdmissionResponse
	sendErr              error
	activations          atomic.Int32
	activationRole       atomic.Uint32
	closed               atomic.Int32
	expiresAt            time.Time
	allowReplacement     bool
	authorizeErr         error
	mutateClaims         func(*tunnelv2.VerifiedClaims)
	blockSend            bool
	blockActivation      bool
	closeBlock           <-chan struct{}
	closeEntered         chan struct{}
	closeEnteredOnce     sync.Once
	blockReceive         bool
	authorized           atomic.Int32
	authorizeGate        <-chan struct{}
	authorizeStarted     chan struct{}
	authorizeStartedOnce sync.Once
}

var pendingBindingSequence atomic.Uint64

func newPendingLeg(request artifactv2.Request, session carrier.Session) *pendingLeg {
	if len(request.Candidates) == 0 {
		candidateCarrier := artifactv2.CarrierRawQUIC
		switch session.Kind() {
		case carrier.KindWebSocket:
			candidateCarrier = artifactv2.CarrierWebSocket
		case carrier.KindWebTransport:
			candidateCarrier = artifactv2.CarrierWebTransport
		}
		request.Candidates = []artifactv2.CanonicalCandidate{{
			ID: "candidate", Carrier: candidateCarrier, NormalizedURL: "quic://example.com", WireProfile: "flowersec-tunnel/2",
		}}
		request.ChosenCandidateID = "candidate"
	}
	binding := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", request.AttachToken, pendingBindingSequence.Add(1))))
	decoded := &artifactv2.DecodedRequest{Request: request, LocalAdmissionBinding: binding}
	leg := &pendingLeg{
		decoded: decoded, session: session, lease: &countingLease{},
		received: make(chan struct{}), responses: make(chan artifactv2.AdmissionResponse, 2),
		expiresAt:        time.Now().Add(time.Minute),
		allowReplacement: true,
	}
	pendingLegByBinding.Store(binding, leg)
	return leg
}

func (leg *pendingLeg) ReceiveAdmission(ctx context.Context) (*artifactv2.DecodedRequest, error) {
	select {
	case <-leg.received:
	default:
		close(leg.received)
	}
	if leg.blockReceive {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return leg.decoded, nil
}

func (leg *pendingLeg) CarrierKind() carrier.Kind { return leg.session.Kind() }

func (leg *pendingLeg) SendAdmission(ctx context.Context, response artifactv2.AdmissionResponse, _ artifactv2.ReasonRegistry) error {
	if leg.blockSend {
		<-ctx.Done()
		return ctx.Err()
	}
	leg.responses <- response
	return leg.sendErr
}

func (leg *pendingLeg) Activate(ctx context.Context, role uint8) (carrier.Session, error) {
	leg.activations.Add(1)
	leg.activationRole.Store(uint32(role))
	if leg.blockActivation {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return leg.session, nil
}

func (leg *pendingLeg) CloseWithError(ctx context.Context, _ carrier.ApplicationError) error {
	leg.closed.Add(1)
	if leg.closeEntered != nil {
		leg.closeEnteredOnce.Do(func() { close(leg.closeEntered) })
	}
	if leg.closeBlock != nil {
		select {
		case <-leg.closeBlock:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return leg.session.CloseWithErrorContext(ctx, carrier.ApplicationError{})
}

type countingLease struct{ releases atomic.Int32 }

func (lease *countingLease) Release() { lease.releases.Add(1) }

type guardedPendingLeg struct {
	*pendingLeg
	extras  chan carrier.Stream
	started chan struct{}
}

func (leg *guardedPendingLeg) RejectWaitingStreams(ctx context.Context) error {
	close(leg.started)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case stream := <-leg.extras:
			_ = stream.Reset()
		}
	}
}

type resetProbe struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	reset  chan struct{}
	once   sync.Once
}

func newResetProbe() *resetProbe {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &resetProbe{ctx: ctx, cancel: cancel, reset: make(chan struct{})}
}

func (*resetProbe) Read([]byte) (int, error)       { return 0, io.EOF }
func (*resetProbe) Write(p []byte) (int, error)    { return len(p), nil }
func (probe *resetProbe) Context() context.Context { return probe.ctx }
func (*resetProbe) CloseWrite() error              { return nil }
func (probe *resetProbe) StopSending() error       { return probe.Reset() }
func (probe *resetProbe) Reset() error {
	probe.once.Do(func() {
		probe.cancel(carrier.ErrStreamReset)
		close(probe.reset)
	})
	return nil
}
func (probe *resetProbe) Close() error { return probe.Reset() }

type stuckGuardLeg struct {
	*pendingLeg
	started chan struct{}
	release chan struct{}
}

func (leg *stuckGuardLeg) RejectWaitingStreams(context.Context) error {
	close(leg.started)
	<-leg.release
	return nil
}

func tunnelRequest(role uint8, endpoint, credential string) artifactv2.Request {
	return tunnelRequestForChannel(role, endpoint, credential, "channel")
}

func tunnelRequestForChannel(role uint8, endpoint, credential, channel string) artifactv2.Request {
	var sessionHash, candidateHash [32]byte
	sessionHash[0] = 1
	candidateHash[0] = role + 10
	// Both roles must present the same signed candidate set.
	candidateHash[0] = 42
	return artifactv2.Request{
		PathKind: artifactv2.PathTunnel, Profile: artifactv2.Profile,
		ChannelID: channel, SessionContractHash: sessionHash,
		RendezvousGroupID: "group", CandidateSetHash: candidateHash,
		ListenerAudience: "listener", Role: role,
		EndpointInstanceID: endpoint, AttachToken: credential,
	}
}

func serveLeg(coordinator *tunnelv2.Coordinator, ctx context.Context, leg tunnelv2.PendingLeg) <-chan error {
	done := make(chan error, 1)
	go func() { done <- coordinator.Serve(ctx, leg) }()
	return done
}

func waitForSignal(t *testing.T, signal <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}

func assertNoResponse(t *testing.T, leg *pendingLeg) {
	t.Helper()
	select {
	case response := <-leg.responses:
		t.Fatalf("response arrived before pair: %+v", response)
	case <-time.After(20 * time.Millisecond):
	}
}

func assertSuccessResponse(t *testing.T, leg *pendingLeg) {
	t.Helper()
	select {
	case response := <-leg.responses:
		if response.Status != artifactv2.AdmissionSuccess || response.Reason != "" {
			t.Fatalf("response = %+v", response)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for admission success")
	}
}

func assertResponse(t *testing.T, leg *pendingLeg, status artifactv2.AdmissionStatus, reason string) {
	t.Helper()
	select {
	case response := <-leg.responses:
		if response.Status != status || response.Reason != reason {
			t.Fatalf("response = %+v, want status=%d reason=%q", response, status, reason)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for admission response status=%d reason=%q", status, reason)
	}
}

func assertServeCanceled(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop")
	}
}

func assertLeaseReleasedOnce(t *testing.T, leg *pendingLeg) {
	t.Helper()
	if got := leg.lease.releases.Load(); got != 1 {
		t.Fatalf("lease releases = %d", got)
	}
}

func waitForActivations(t *testing.T, legs ...*pendingLeg) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		ready := true
		for _, leg := range legs {
			ready = ready && leg.activations.Load() == 1
		}
		if ready {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for leg activation")
}
