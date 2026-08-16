package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
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
	ctx := withAuthorizationContext(context.Background(), authorizationContext{carrier: carrier.KindRawQUIC})
	response, authorization, err := authorizeDirect(ctx, provider, decoded, runtimeReasons(), 32)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != artifactv2.AdmissionSuccess || authorization == nil || authorization.Upstream.Address != "127.0.0.1:9000" {
		t.Fatalf("unexpected authorization: %+v %+v", response, authorization)
	}
	if len(provider.requests) != 1 || provider.requests[0].Carrier != string(carrier.KindRawQUIC) || provider.requests[0].RemoteAddress != "" {
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

func TestAuthorizeDirectReleasesAllowLeaseWhenContractIsInvalid(t *testing.T) {
	provider := &fakeAuthorizationProvider{response: authorizationResponse{
		Decision: "allow", CredentialID: "credential-a", LeaseID: "lease-invalid-direct", ExpiresAt: time.Now().Add(time.Minute),
		Direct: &directAuthorization{Session: validAuthorizedSession(t, "wrong-channel", 32), Upstream: upstreamTarget{Network: "tcp", Address: "127.0.0.1:9000"}},
	}}
	decoded := &artifactv2.DecodedRequest{Raw: []byte("FSB2 fixture"), Request: artifactv2.Request{PathKind: artifactv2.PathDirect, ChannelID: "expected-channel"}}
	ctx := withAuthorizationContext(context.Background(), authorizationContext{carrier: carrier.KindWebSocket, remoteAddress: "127.0.0.1:1"})
	if _, authorization, err := authorizeDirect(ctx, provider, decoded, runtimeReasons(), 32); !errors.Is(err, ErrInvalidAuthorization) || authorization != nil {
		t.Fatalf("invalid direct authorization = %+v, %v", authorization, err)
	}
	if len(provider.released) != 1 || provider.released[0] != "lease-invalid-direct" {
		t.Fatalf("released leases = %v, want invalid direct lease", provider.released)
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

func TestTunnelAuthorizerReleasesAllowLeaseWhenClaimsAreInvalid(t *testing.T) {
	provider := &fakeAuthorizationProvider{response: authorizationResponse{
		Decision: "allow", CredentialID: "credential-a", LeaseID: "lease-invalid-tunnel",
		ExpiresAt: time.Now().Add(time.Minute),
	}}
	decoded := &artifactv2.DecodedRequest{Raw: []byte("FSB2 fixture"), Request: artifactv2.Request{PathKind: artifactv2.PathTunnel}}
	ctx := withAuthorizationContext(context.Background(), authorizationContext{carrier: carrier.KindWebSocket, remoteAddress: "127.0.0.1:2"})
	if _, err := tunnelAuthorizer(provider, runtimeReasons())(ctx, decoded); !errors.Is(err, ErrInvalidAuthorization) {
		t.Fatalf("invalid tunnel authorization error = %v", err)
	}
	if len(provider.released) != 1 || provider.released[0] != "lease-invalid-tunnel" {
		t.Fatalf("released leases = %v, want invalid tunnel lease", provider.released)
	}
}

func TestHTTPAuthorizationProviderAcceptsSecretFreeTunnelResponse(t *testing.T) {
	expiresAt := time.Now().Add(time.Minute).UTC().Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"decision":"allow","credential_id":"credential-a","lease_id":"lease-a","expires_at":%q,"expected_peer_endpoint_instance_id":"peer-b","allow_replacement":false}`, expiresAt.Format(time.RFC3339))
	}))
	defer server.Close()

	provider := &httpAuthorizationProvider{url: server.URL, client: server.Client()}
	decision, err := provider.Authorize(context.Background(), authorizationRequest{FSB2Base64URL: "RlNCMg", Carrier: "websocket"})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != "allow" || decision.CredentialID != "credential-a" || decision.ExpectedPeerEndpointInstanceID != "peer-b" || !decision.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("unexpected tunnel authorization: %+v", decision)
	}
}

func TestHTTPAuthorizationProviderRetriesReleaseUntilAcknowledged(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts++
		if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer release-secret" {
			http.Error(writer, "invalid request", http.StatusBadRequest)
			return
		}
		var body struct {
			LeaseID string `json:"lease_id"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.LeaseID != "lease-retry" {
			http.Error(writer, "invalid body", http.StatusBadRequest)
			return
		}
		if attempts < 3 {
			http.Error(writer, "not committed", http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	provider := &httpAuthorizationProvider{
		releaseURL: server.URL,
		token:      "release-secret",
		client:     server.Client(),
		logger:     log.New(io.Discard, "", 0),
	}
	provider.Release("lease-retry")
	if attempts != 3 {
		t.Fatalf("release attempts = %d, want 3", attempts)
	}
}

func TestHTTPAuthorizationProviderRejectsTunnelSessionOverclaim(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(writer, `{"decision":"allow","credential_id":"credential-a","lease_id":"lease-a","expires_at":"2099-01-01T00:00:00Z","expected_peer_endpoint_instance_id":"peer-b","session":{"e2ee_psk_base64url":"secret"}}`)
	}))
	defer server.Close()

	provider := &httpAuthorizationProvider{url: server.URL, client: server.Client()}
	_, err := provider.Authorize(context.Background(), authorizationRequest{FSB2Base64URL: "RlNCMg", Carrier: "websocket"})
	if !errors.Is(err, ErrInvalidAuthorization) {
		t.Fatalf("session overclaim error = %v, want ErrInvalidAuthorization", err)
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
