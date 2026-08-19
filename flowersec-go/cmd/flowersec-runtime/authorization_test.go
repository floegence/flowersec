package main

import (
	"bytes"
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

	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
)

type fakeAuthorizationProvider struct {
	response        authorizationResponse
	err             error
	releaseStarted  chan<- string
	releaseContinue <-chan struct{}
	mu              sync.Mutex
	released        []string
	requests        []authorizationRequest
}

func (provider *fakeAuthorizationProvider) Authorize(_ context.Context, request authorizationRequest) (authorizationResponse, error) {
	provider.mu.Lock()
	provider.requests = append(provider.requests, request)
	provider.mu.Unlock()
	return provider.response, provider.err
}

func (provider *fakeAuthorizationProvider) Release(id string) {
	if provider.releaseStarted != nil {
		provider.releaseStarted <- id
	}
	if provider.releaseContinue != nil {
		<-provider.releaseContinue
	}
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
	decoded := &artifactv3.DecodedRequest{
		Raw: []byte("FSB3 fixture"),
		Request: artifactv3.Request{
			PathKind: artifactv3.PathDirect, ChannelID: "channel-a", SessionContractHash: contract.ContractHash,
			RoutingToken: "routing-token",
		},
	}
	provider.response.CredentialID, _ = credentialIDFor(decoded)
	ctx := withAuthorizationContext(context.Background(), authorizationContext{carrier: carrier.KindRawQUIC, remoteAddress: "127.0.0.1:1"})
	response, authorization, err := authorizeDirect(ctx, provider, decoded, runtimeReasons(), 32)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != artifactv3.AdmissionSuccess || authorization == nil || authorization.Upstream.Address != "127.0.0.1:9000" {
		t.Fatalf("unexpected authorization: %+v %+v", response, authorization)
	}
	if len(provider.requests) != 1 || provider.requests[0].Carrier != string(carrier.KindRawQUIC) || provider.requests[0].RemoteAddress != "127.0.0.1:1" {
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
	decoded := &artifactv3.DecodedRequest{Raw: []byte("FSB3 fixture")}
	ctx := withAuthorizationContext(context.Background(), authorizationContext{carrier: carrier.KindWebSocket, remoteAddress: "127.0.0.1:1"})
	response, authorization, err := authorizeDirect(ctx, provider, decoded, runtimeReasons(), 32)
	if err != nil || authorization != nil || response.Status != artifactv3.AdmissionRetryable || response.Reason != reasonAuthorizationUnavailable {
		t.Fatalf("unexpected retry result: %+v %+v %v", response, authorization, err)
	}
}

func TestAuthorizeDirectReleasesAllowLeaseWhenContractIsInvalid(t *testing.T) {
	provider := &fakeAuthorizationProvider{response: authorizationResponse{
		Decision: "allow", CredentialID: "credential-a", LeaseID: "lease-invalid-direct", ExpiresAt: time.Now().Add(time.Minute),
		Direct: &directAuthorization{Session: validAuthorizedSession(t, "wrong-channel", 32), Upstream: upstreamTarget{Network: "tcp", Address: "127.0.0.1:9000"}},
	}}
	decoded := &artifactv3.DecodedRequest{Raw: []byte("FSB3 fixture"), Request: artifactv3.Request{PathKind: artifactv3.PathDirect, ChannelID: "expected-channel"}}
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
	decoded := &artifactv3.DecodedRequest{Raw: []byte("FSB3 fixture"), Request: artifactv3.Request{
		PathKind: artifactv3.PathTunnel, Profile: artifactv3.Profile, ChannelID: "channel-a",
		RendezvousGroupID: "group-a", ListenerAudience: "audience-a", Role: 1,
		EndpointInstanceID: "peer-a", AttachToken: "attach-token",
	}}
	provider.response.CredentialID, _ = credentialIDFor(decoded)
	ctx := withAuthorizationContext(context.Background(), authorizationContext{carrier: carrier.KindWebTransport, remoteAddress: "127.0.0.1:2"})
	authorization, err := tunnelAuthorizer(provider, runtimeReasons())(ctx, decoded)
	if err != nil {
		t.Fatal(err)
	}
	expectedCredentialID, _ := credentialIDFor(decoded)
	if authorization.Claims.CredentialID != expectedCredentialID || authorization.Claims.ExpectedPeerEndpointInstanceID != "peer-b" || authorization.Lease == nil {
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
	decoded := &artifactv3.DecodedRequest{Raw: []byte("FSB3 fixture"), Request: artifactv3.Request{PathKind: artifactv3.PathTunnel}}
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
	decision, err := provider.Authorize(context.Background(), authorizationRequest{FSB3Base64URL: "RlNCMw", Carrier: "websocket"})
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

func TestHTTPAuthorizationProviderNeverRedirectsSensitiveRequests(t *testing.T) {
	tests := []struct {
		name   string
		status int
		route  string
	}{
		{name: "cross-host-307", status: http.StatusTemporaryRedirect, route: "cross-host"},
		{name: "cross-host-308", status: http.StatusPermanentRedirect, route: "cross-host"},
		{name: "https-to-http-307", status: http.StatusTemporaryRedirect, route: "downgrade"},
		{name: "same-host-308", status: http.StatusPermanentRedirect, route: "same-host"},
	}
	for _, test := range tests {
		t.Run(test.name+"/authorize", func(t *testing.T) {
			fixture := newAuthorizationRedirectFixture(t, test.status, test.route)
			provider := &httpAuthorizationProvider{
				url: fixture.sourceURL, token: "redirect-secret", client: fixture.client,
			}
			_, err := provider.Authorize(context.Background(), authorizationRequest{
				FSB3Base64URL: "sensitive-fsb3", Carrier: "websocket",
			})
			if !errors.Is(err, ErrAuthorizationUnavailable) {
				t.Fatalf("Authorize redirect error = %v, want ErrAuthorizationUnavailable", err)
			}
			fixture.assertRequests(t, 1, "sensitive-fsb3")
		})
		t.Run(test.name+"/release", func(t *testing.T) {
			fixture := newAuthorizationRedirectFixture(t, test.status, test.route)
			provider := &httpAuthorizationProvider{
				releaseURL: fixture.sourceURL, token: "redirect-secret", client: fixture.client,
				logger: log.New(io.Discard, "", 0),
			}
			provider.Release("sensitive-lease")
			fixture.assertRequests(t, maxReleaseAttempts, "sensitive-lease")
		})
	}
}

type authorizationRedirectFixture struct {
	sourceURL     string
	client        *http.Client
	mu            sync.Mutex
	sourceBodies  [][]byte
	sourceHeaders []string
	targetBodies  [][]byte
	targetHeaders []string
}

func newAuthorizationRedirectFixture(t *testing.T, status int, route string) *authorizationRedirectFixture {
	t.Helper()
	fixture := &authorizationRedirectFixture{}
	targetHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		fixture.mu.Lock()
		fixture.targetBodies = append(fixture.targetBodies, body)
		fixture.targetHeaders = append(fixture.targetHeaders, request.Header.Get("Authorization"))
		fixture.mu.Unlock()
		writer.WriteHeader(http.StatusNoContent)
	})
	sourceHandler := func(targetURL func() string) http.HandlerFunc {
		return func(writer http.ResponseWriter, request *http.Request) {
			body, _ := io.ReadAll(request.Body)
			fixture.mu.Lock()
			fixture.sourceBodies = append(fixture.sourceBodies, body)
			fixture.sourceHeaders = append(fixture.sourceHeaders, request.Header.Get("Authorization"))
			fixture.mu.Unlock()
			http.Redirect(writer, request, targetURL(), status)
		}
	}
	switch route {
	case "cross-host":
		target := httptest.NewServer(targetHandler)
		source := httptest.NewServer(sourceHandler(func() string { return target.URL }))
		t.Cleanup(source.Close)
		t.Cleanup(target.Close)
		fixture.sourceURL = source.URL
		fixture.client = source.Client()
	case "downgrade":
		target := httptest.NewServer(targetHandler)
		source := httptest.NewTLSServer(sourceHandler(func() string { return target.URL }))
		t.Cleanup(source.Close)
		t.Cleanup(target.Close)
		fixture.sourceURL = source.URL
		fixture.client = source.Client()
	case "same-host":
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/target" {
				targetHandler.ServeHTTP(writer, request)
				return
			}
			sourceHandler(func() string { return server.URL + "/target" }).ServeHTTP(writer, request)
		}))
		t.Cleanup(server.Close)
		fixture.sourceURL = server.URL + "/source"
		fixture.client = server.Client()
	default:
		t.Fatalf("unknown redirect route %q", route)
	}
	return fixture
}

func (fixture *authorizationRedirectFixture) assertRequests(t *testing.T, sourceCount int, sensitive string) {
	t.Helper()
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.sourceBodies) != sourceCount || len(fixture.sourceHeaders) != sourceCount {
		t.Fatalf("source requests = %d bodies/%d headers, want %d", len(fixture.sourceBodies), len(fixture.sourceHeaders), sourceCount)
	}
	for index := range fixture.sourceBodies {
		if !bytes.Contains(fixture.sourceBodies[index], []byte(sensitive)) || fixture.sourceHeaders[index] != "Bearer redirect-secret" {
			t.Fatalf("source request %d did not carry the expected sensitive credentials", index)
		}
	}
	if len(fixture.targetBodies) != 0 || len(fixture.targetHeaders) != 0 {
		t.Fatalf("redirect target received %d bodies and %d authorization headers", len(fixture.targetBodies), len(fixture.targetHeaders))
	}
}

func TestHTTPAuthorizationProviderRejectsTunnelSessionOverclaim(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(writer, `{"decision":"allow","credential_id":"credential-a","lease_id":"lease-a","expires_at":"2099-01-01T00:00:00Z","expected_peer_endpoint_instance_id":"peer-b","session":{"e2ee_psk_base64url":"secret"}}`)
	}))
	defer server.Close()

	provider := &httpAuthorizationProvider{url: server.URL, client: server.Client()}
	_, err := provider.Authorize(context.Background(), authorizationRequest{FSB3Base64URL: "RlNCMw", Carrier: "websocket"})
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

func runtimeReasons() artifactv3.ReasonRegistry {
	return artifactv3.ReasonRegistry{
		reasonAuthorizationDenied: {}, reasonAuthorizationUnavailable: {}, "policy_denied": {},
	}
}
