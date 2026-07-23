package main

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
)

type fakeAuthorizationProvider struct {
	response authorizationResponse
	err      error
	mu       sync.Mutex
	released []string
	requests []authorizationRequest
}

func (provider *fakeAuthorizationProvider) Authorize(_ context.Context, request authorizationRequest) (authorizationResponse, error) {
	provider.mu.Lock()
	provider.requests = append(provider.requests, request)
	provider.mu.Unlock()
	return provider.response, provider.err
}

func (provider *fakeAuthorizationProvider) Release(id string) {
	provider.mu.Lock()
	provider.released = append(provider.released, id)
	provider.mu.Unlock()
}

func TestAuthorizeDirectBindsContractAndUpstream(t *testing.T) {
	wire := validAuthorizedSession(t, "channel-a", 32)
	contract, err := wire.contract()
	if err != nil {
		t.Fatal(err)
	}
	provider := &fakeAuthorizationProvider{response: authorizationResponse{
		Decision: "allow", CredentialID: "credential-a", LeaseID: "lease-a", ExpiresAt: time.Now().Add(time.Minute),
		Direct: &directAuthorization{Session: wire, Upstream: upstreamTarget{Network: "tcp", Address: "127.0.0.1:9000"}},
	}}
	decoded := &artifactv2.DecodedRequest{
		Raw: []byte("FSB2 fixture"),
		Request: artifactv2.Request{
			PathKind: artifactv2.PathDirect, ChannelID: "channel-a", SessionContractHash: contract.ContractHash,
		},
	}
	ctx := withAuthorizationContext(context.Background(), authorizationContext{carrier: carrier.KindQUIC})
	response, authorization, err := authorizeDirect(ctx, provider, decoded, runtimeReasons(), 32)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != artifactv2.AdmissionSuccess || authorization == nil || authorization.Upstream.Address != "127.0.0.1:9000" {
		t.Fatalf("unexpected authorization: %+v %+v", response, authorization)
	}
	if len(provider.requests) != 1 || provider.requests[0].Carrier != string(carrier.KindQUIC) || provider.requests[0].RemoteAddress != "" {
		t.Fatalf("unexpected request: %+v", provider.requests)
	}
	authorization.Release()
	authorization.Release()
	if len(provider.released) != 1 || provider.released[0] != "lease-a" {
		t.Fatalf("direct lease release count = %v", provider.released)
	}
}

func TestAuthorizeDirectConvertsProviderFailureToRetry(t *testing.T) {
	provider := &fakeAuthorizationProvider{err: errors.New("offline")}
	decoded := &artifactv2.DecodedRequest{Raw: []byte("FSB2 fixture")}
	ctx := withAuthorizationContext(context.Background(), authorizationContext{carrier: carrier.KindWebSocket, remoteAddress: "127.0.0.1:1"})
	response, authorization, err := authorizeDirect(ctx, provider, decoded, runtimeReasons(), 32)
	if err != nil || authorization != nil || response.Status != artifactv2.AdmissionRetryable || response.Reason != reasonAuthorizationUnavailable {
		t.Fatalf("unexpected retry result: %+v %+v %v", response, authorization, err)
	}
}

func TestTunnelAuthorizerBindsClaimsAndReleasesLeaseOnce(t *testing.T) {
	provider := &fakeAuthorizationProvider{response: authorizationResponse{
		Decision: "allow", CredentialID: "credential-a", LeaseID: "lease-a",
		ExpiresAt: time.Now().Add(time.Minute), ExpectedPeerEndpointInstanceID: "peer-b",
	}}
	decoded := &artifactv2.DecodedRequest{Raw: []byte("FSB2 fixture"), Request: artifactv2.Request{
		PathKind: artifactv2.PathTunnel, Profile: artifactv2.Profile, ChannelID: "channel-a",
		RendezvousGroupID: "group-a", ListenerAudience: "audience-a", Role: 1,
		EndpointInstanceID: "peer-a",
	}}
	ctx := withAuthorizationContext(context.Background(), authorizationContext{carrier: carrier.KindWebTransport, remoteAddress: "127.0.0.1:2"})
	authorization, err := tunnelAuthorizer(provider, runtimeReasons())(ctx, decoded)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Claims.CredentialID != "credential-a" || authorization.Claims.ExpectedPeerEndpointInstanceID != "peer-b" || authorization.Lease == nil {
		t.Fatalf("unexpected claims: %+v", authorization.Claims)
	}
	authorization.Lease.Release()
	authorization.Lease.Release()
	if len(provider.released) != 1 || provider.released[0] != "lease-a" {
		t.Fatalf("lease release count = %v", provider.released)
	}
}

func TestAdmissionDecisionRejectsUnregisteredReason(t *testing.T) {
	_, _, err := admissionDecision(authorizationResponse{Decision: "reject", Reason: "secret_internal_reason"}, runtimeReasons())
	if !errors.Is(err, ErrInvalidAuthorization) {
		t.Fatalf("expected invalid authorization, got %v", err)
	}
}

func validAuthorizedSession(t *testing.T, channel string, maxInbound uint16) authorizedSessionContract {
	t.Helper()
	psk := make([]byte, 32)
	for index := range psk {
		psk[index] = byte(index + 1)
	}
	return authorizedSessionContract{
		ChannelID: channel, InitExpireAtUnixSeconds: time.Now().Add(time.Minute).Unix(),
		IdleTimeoutSeconds: 60, EstablishTimeoutSeconds: 30,
		RekeyPrepareTimeoutSeconds: 10, RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams: maxInbound, E2EEPSKBase64URL: base64.RawURLEncoding.EncodeToString(psk),
		AllowedSuites: []uint16{1, 2}, DefaultSuite: 1,
	}
}

func runtimeReasons() artifactv2.ReasonRegistry {
	return artifactv2.ReasonRegistry{
		reasonAuthorizationDenied: {}, reasonAuthorizationUnavailable: {}, "policy_denied": {},
	}
}
