package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/admissionv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/tunnelv3"
)

const (
	reasonAuthorizationDenied      = "authorization_denied"
	reasonAuthorizationUnavailable = "authorization_unavailable"
	maxAuthorizationResponseBytes  = 64 << 10
	maxReleaseAttempts             = 3
	releaseRetryBaseDelay          = 100 * time.Millisecond
	defaultReleaseAttemptTimeout   = 10 * time.Second
)

var (
	ErrAuthorizationUnavailable = errors.New("Flowersec runtime authorization unavailable")
	ErrInvalidAuthorization     = errors.New("invalid Flowersec runtime authorization response")
)

type authorizationProvider interface {
	Authorize(context.Context, authorizationRequest) (authorizationResponse, error)
	Release(string)
}

type authorizationRequest struct {
	FSB3Base64URL string `json:"fsb3_base64url"`
	Carrier       string `json:"carrier"`
	RemoteAddress string `json:"remote_address"`
}

type authorizationResponse struct {
	Decision                       string               `json:"decision"`
	Reason                         string               `json:"reason"`
	CredentialID                   string               `json:"credential_id"`
	LeaseID                        string               `json:"lease_id"`
	ExpiresAt                      time.Time            `json:"expires_at"`
	ExpectedPeerEndpointInstanceID string               `json:"expected_peer_endpoint_instance_id"`
	AllowReplacement               bool                 `json:"allow_replacement"`
	Direct                         *directAuthorization `json:"direct"`
}

type directAuthorization struct {
	Session  authorizedSessionContract `json:"session"`
	Upstream upstreamTarget            `json:"upstream"`
	lease    tunnelv3.Lease
}

func (authorization *directAuthorization) Release() {
	if authorization != nil && authorization.lease != nil {
		authorization.lease.Release()
	}
}

type authorizedSessionContract struct {
	ChannelID                     string   `json:"channel_id"`
	InitExpireAtUnixSeconds       int64    `json:"init_expire_at_unix_seconds"`
	IdleTimeoutSeconds            uint32   `json:"idle_timeout_seconds"`
	EstablishTimeoutSeconds       uint16   `json:"establish_timeout_seconds"`
	RekeyPrepareTimeoutSeconds    uint16   `json:"rekey_prepare_timeout_seconds"`
	RekeyCompletionTimeoutSeconds uint16   `json:"rekey_completion_timeout_seconds"`
	MaxInboundStreams             uint16   `json:"max_inbound_streams"`
	E2EEPSKBase64URL              string   `json:"e2ee_psk_base64url"`
	AllowedSuites                 []uint16 `json:"allowed_suites"`
	DefaultSuite                  uint16   `json:"default_suite"`
	SelectedFeatures              uint32   `json:"selected_features"`
}

type upstreamTarget struct {
	Network string `json:"network"`
	Address string `json:"address"`
}

type httpAuthorizationProvider struct {
	url        string
	releaseURL string
	token      string
	client     *http.Client
	logger     *log.Logger
}

func newHTTPAuthorizationProvider(config AuthorizationConfig) (*httpAuthorizationProvider, error) {
	token := ""
	if config.BearerTokenEnv != "" {
		var ok bool
		token, ok = os.LookupEnv(config.BearerTokenEnv)
		if !ok || token == "" {
			return nil, &ConfigError{Field: "authorization.bearer_token_env", Err: errors.New("configured secret is unavailable")}
		}
	}
	return &httpAuthorizationProvider{
		url: config.URL, releaseURL: config.ReleaseURL, token: token,
		client: &http.Client{
			Timeout:       time.Duration(config.TimeoutSeconds) * time.Second,
			CheckRedirect: rejectAuthorizationRedirect,
		},
		logger: log.Default(),
	}, nil
}

func rejectAuthorizationRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func (provider *httpAuthorizationProvider) do(request *http.Request) (*http.Response, error) {
	if provider.client == nil {
		return nil, fmt.Errorf("%w: authorization client unavailable", ErrAuthorizationUnavailable)
	}
	client := *provider.client
	client.CheckRedirect = rejectAuthorizationRedirect
	return client.Do(request)
}

func (provider *httpAuthorizationProvider) Authorize(ctx context.Context, input authorizationRequest) (authorizationResponse, error) {
	requestBody, err := json.Marshal(input)
	if err != nil {
		return authorizationResponse{}, fmt.Errorf("%w: encode request", ErrAuthorizationUnavailable)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.url, bytes.NewReader(requestBody))
	if err != nil {
		return authorizationResponse{}, fmt.Errorf("%w: create request", ErrAuthorizationUnavailable)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if provider.token != "" {
		request.Header.Set("Authorization", "Bearer "+provider.token)
	}
	response, err := provider.do(request)
	if err != nil {
		return authorizationResponse{}, fmt.Errorf("%w: request failed", ErrAuthorizationUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return authorizationResponse{}, fmt.Errorf("%w: unexpected HTTP status %d", ErrAuthorizationUnavailable, response.StatusCode)
	}
	rawResponse, err := io.ReadAll(io.LimitReader(response.Body, maxAuthorizationResponseBytes+1))
	if err != nil {
		return authorizationResponse{}, fmt.Errorf("%w: read response", ErrAuthorizationUnavailable)
	}
	if len(rawResponse) > maxAuthorizationResponseBytes {
		return authorizationResponse{}, fmt.Errorf("%w: response too large", ErrInvalidAuthorization)
	}
	decoder := json.NewDecoder(bytes.NewReader(rawResponse))
	decoder.DisallowUnknownFields()
	var decision authorizationResponse
	if err := decoder.Decode(&decision); err != nil {
		return authorizationResponse{}, fmt.Errorf("%w: invalid JSON", ErrInvalidAuthorization)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return authorizationResponse{}, fmt.Errorf("%w: multiple JSON values", ErrInvalidAuthorization)
	}
	return decision, nil
}

func (provider *httpAuthorizationProvider) Release(leaseID string) {
	if provider == nil || leaseID == "" {
		return
	}
	body, err := json.Marshal(struct {
		LeaseID string `json:"lease_id"`
	}{LeaseID: leaseID})
	if err != nil {
		return
	}
	for attempt := 0; attempt < maxReleaseAttempts; attempt++ {
		if err = provider.releaseAttempt(body); err == nil {
			return
		}
		if attempt+1 < maxReleaseAttempts {
			time.Sleep(releaseRetryBaseDelay * time.Duration(1<<attempt))
		}
	}
	logger := provider.logger
	if logger == nil {
		logger = log.Default()
	}
	logger.Printf("authorization lease %q release was not acknowledged after %d attempts: %v", leaseID, maxReleaseAttempts, err)
}

func (provider *httpAuthorizationProvider) releaseAttempt(body []byte) error {
	if provider.client == nil {
		return fmt.Errorf("%w: release client unavailable", ErrAuthorizationUnavailable)
	}
	timeout := provider.client.Timeout
	if timeout <= 0 {
		timeout = defaultReleaseAttemptTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.releaseURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: create release request", ErrAuthorizationUnavailable)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if provider.token != "" {
		request.Header.Set("Authorization", "Bearer "+provider.token)
	}
	response, err := provider.do(request)
	if err != nil {
		return fmt.Errorf("%w: release request failed", ErrAuthorizationUnavailable)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	_ = response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: release returned HTTP status %d", ErrAuthorizationUnavailable, response.StatusCode)
	}
	return nil
}

type externalLease struct {
	provider authorizationProvider
	id       string
	once     sync.Once
}

func (lease *externalLease) Release() {
	lease.once.Do(func() { lease.provider.Release(lease.id) })
}

type authorizationContext struct {
	carrier       carrier.Kind
	remoteAddress string
}

type authorizationContextKey struct{}

func withAuthorizationContext(ctx context.Context, value authorizationContext) context.Context {
	return context.WithValue(ctx, authorizationContextKey{}, value)
}

func requestForAuthorization(ctx context.Context, decoded *artifactv3.DecodedRequest) (authorizationRequest, error) {
	if decoded == nil || len(decoded.Raw) == 0 {
		return authorizationRequest{}, ErrInvalidAuthorization
	}
	transport, ok := ctx.Value(authorizationContextKey{}).(authorizationContext)
	if !ok || transport.carrier.Validate() != nil || transport.remoteAddress == "" {
		return authorizationRequest{}, ErrInvalidAuthorization
	}
	return authorizationRequest{
		FSB3Base64URL: base64.RawURLEncoding.EncodeToString(decoded.Raw),
		Carrier:       string(transport.carrier), RemoteAddress: transport.remoteAddress,
	}, nil
}

func authorizeDirect(ctx context.Context, provider authorizationProvider, decoded *artifactv3.DecodedRequest, reasons artifactv3.ReasonRegistry, maxInbound uint16) (artifactv3.AdmissionResponse, *directAuthorization, error) {
	input, err := requestForAuthorization(ctx, decoded)
	if err != nil {
		return retryResponse(reasonAuthorizationUnavailable), nil, nil
	}
	decision, err := provider.Authorize(ctx, input)
	if err != nil {
		return retryResponse(reasonAuthorizationUnavailable), nil, nil
	}
	var lease *externalLease
	if decision.Decision == "allow" && decision.LeaseID != "" {
		lease = &externalLease{provider: provider, id: decision.LeaseID}
	}
	releaseOnReturn := lease != nil
	defer func() {
		if releaseOnReturn {
			lease.Release()
		}
	}()
	response, allowed, err := admissionDecision(decision, reasons)
	if err != nil || !allowed {
		return response, nil, err
	}
	if lease == nil {
		return artifactv3.AdmissionResponse{}, nil, ErrInvalidAuthorization
	}
	if decoded.Request.PathKind != artifactv3.PathDirect || decision.Direct == nil ||
		!credentialIDMatches(decoded, decision.CredentialID) || decision.LeaseID == "" || decision.ExpiresAt.IsZero() || !decision.ExpiresAt.After(time.Now()) ||
		decision.ExpectedPeerEndpointInstanceID != "" || decision.AllowReplacement {
		return artifactv3.AdmissionResponse{}, nil, ErrInvalidAuthorization
	}
	contract, err := decision.Direct.Session.contract()
	if err != nil || contract.ChannelID != decoded.Request.ChannelID || contract.ContractHash != decoded.Request.SessionContractHash || contract.MaxInboundStreams != maxInbound || time.Now().Unix() >= contract.InitExpireAtUnixSeconds {
		return artifactv3.AdmissionResponse{}, nil, ErrInvalidAuthorization
	}
	if decision.Direct.Upstream.Network != "tcp" || decision.Direct.Upstream.Address == "" {
		return artifactv3.AdmissionResponse{}, nil, ErrInvalidAuthorization
	}
	decision.Direct.lease = lease
	releaseOnReturn = false
	return response, decision.Direct, nil
}

func tunnelAuthorizer(provider authorizationProvider, reasons artifactv3.ReasonRegistry) tunnelv3.Authorize {
	return func(ctx context.Context, decoded *artifactv3.DecodedRequest) (tunnelv3.Authorization, error) {
		input, err := requestForAuthorization(ctx, decoded)
		if err != nil {
			return tunnelv3.Authorization{}, &admissionv3.ResponseError{Status: artifactv3.AdmissionRetryable, Reason: reasonAuthorizationUnavailable}
		}
		decision, err := provider.Authorize(ctx, input)
		if err != nil {
			return tunnelv3.Authorization{}, &admissionv3.ResponseError{Status: artifactv3.AdmissionRetryable, Reason: reasonAuthorizationUnavailable}
		}
		var lease *externalLease
		if decision.Decision == "allow" && decision.LeaseID != "" {
			lease = &externalLease{provider: provider, id: decision.LeaseID}
		}
		releaseOnReturn := lease != nil
		defer func() {
			if releaseOnReturn {
				lease.Release()
			}
		}()
		response, allowed, err := admissionDecision(decision, reasons)
		if err != nil {
			return tunnelv3.Authorization{}, err
		}
		if !allowed {
			return tunnelv3.Authorization{}, &admissionv3.ResponseError{Status: response.Status, Reason: response.Reason}
		}
		if lease == nil {
			return tunnelv3.Authorization{}, ErrInvalidAuthorization
		}
		if decoded == nil || decoded.Request.PathKind != artifactv3.PathTunnel || decision.Direct != nil ||
			!credentialIDMatches(decoded, decision.CredentialID) || decision.LeaseID == "" || decision.ExpiresAt.IsZero() || !decision.ExpiresAt.After(time.Now()) ||
			decision.ExpectedPeerEndpointInstanceID == "" {
			return tunnelv3.Authorization{}, ErrInvalidAuthorization
		}
		request := decoded.Request
		authorization := tunnelv3.Authorization{
			Claims: tunnelv3.VerifiedClaims{
				CredentialID: decision.CredentialID, ChannelID: request.ChannelID, Profile: request.Profile,
				RendezvousGroupID: request.RendezvousGroupID, SessionContractHash: request.SessionContractHash,
				CandidateSetHash: request.CandidateSetHash, ListenerAudience: request.ListenerAudience,
				Role: request.Role, EndpointInstanceID: request.EndpointInstanceID,
				ExpectedPeerEndpointInstanceID: decision.ExpectedPeerEndpointInstanceID,
				AllowReplacement:               decision.AllowReplacement,
			},
			ExpiresAt: decision.ExpiresAt,
			Lease:     lease,
		}
		releaseOnReturn = false
		return authorization, nil
	}
}

func credentialIDMatches(decoded *artifactv3.DecodedRequest, credentialID string) bool {
	expected, ok := credentialIDFor(decoded)
	return ok && credentialID != "" && subtle.ConstantTimeCompare([]byte(expected), []byte(credentialID)) == 1
}

func credentialIDFor(decoded *artifactv3.DecodedRequest) (string, bool) {
	if decoded == nil {
		return "", false
	}
	credential := decoded.Request.RoutingToken
	if decoded.Request.PathKind == artifactv3.PathTunnel {
		credential = decoded.Request.AttachToken
	}
	if credential == "" {
		return "", false
	}
	digest := sha256.Sum256([]byte(credential))
	return base64.RawURLEncoding.EncodeToString(digest[:]), true
}

func admissionDecision(decision authorizationResponse, reasons artifactv3.ReasonRegistry) (artifactv3.AdmissionResponse, bool, error) {
	switch decision.Decision {
	case "allow":
		if decision.Reason != "" {
			return artifactv3.AdmissionResponse{}, false, ErrInvalidAuthorization
		}
		return artifactv3.AdmissionResponse{Status: artifactv3.AdmissionSuccess}, true, nil
	case "reject", "retry":
		if _, ok := reasons[decision.Reason]; !ok {
			return artifactv3.AdmissionResponse{}, false, ErrInvalidAuthorization
		}
		status := artifactv3.AdmissionReject
		if decision.Decision == "retry" {
			status = artifactv3.AdmissionRetryable
		}
		response := artifactv3.AdmissionResponse{Status: status, Reason: decision.Reason}
		if _, err := artifactv3.MarshalResponse(response, reasons); err != nil {
			return artifactv3.AdmissionResponse{}, false, ErrInvalidAuthorization
		}
		return response, false, nil
	default:
		return artifactv3.AdmissionResponse{}, false, ErrInvalidAuthorization
	}
}

func retryResponse(reason string) artifactv3.AdmissionResponse {
	return artifactv3.AdmissionResponse{Status: artifactv3.AdmissionRetryable, Reason: reason}
}

func (wire authorizedSessionContract) contract() (artifactv3.SessionContract, error) {
	psk, err := base64.RawURLEncoding.DecodeString(wire.E2EEPSKBase64URL)
	if err != nil || len(psk) != 32 {
		return artifactv3.SessionContract{}, ErrInvalidAuthorization
	}
	contract := artifactv3.SessionContract{
		ChannelID: wire.ChannelID, InitExpireAtUnixSeconds: wire.InitExpireAtUnixSeconds,
		IdleTimeoutSeconds: wire.IdleTimeoutSeconds, EstablishTimeoutSeconds: wire.EstablishTimeoutSeconds,
		RekeyPrepareTimeoutSeconds: wire.RekeyPrepareTimeoutSeconds, RekeyCompletionTimeoutSeconds: wire.RekeyCompletionTimeoutSeconds,
		MaxInboundStreams: wire.MaxInboundStreams, AllowedSuites: wire.AllowedSuites,
		DefaultSuite: wire.DefaultSuite, SelectedFeatures: wire.SelectedFeatures,
	}
	copy(contract.E2EEPSK[:], psk)
	hash, _, err := artifactv3.ComputeSessionContractHash(contract)
	if err != nil {
		return artifactv3.SessionContract{}, ErrInvalidAuthorization
	}
	contract.ContractHash = hash
	return contract, nil
}
