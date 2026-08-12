package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/tunnelv2"
)

const (
	reasonAuthorizationDenied      = "authorization_denied"
	reasonAuthorizationUnavailable = "authorization_unavailable"
	maxAuthorizationResponseBytes  = 64 << 10
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
	FSB2Base64URL string `json:"fsb2_base64url"`
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
	lease    tunnelv2.Lease
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
		client: &http.Client{Timeout: time.Duration(config.TimeoutSeconds) * time.Second},
	}, nil
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
	response, err := provider.client.Do(request)
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
	if leaseID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), provider.client.Timeout)
	defer cancel()
	body, err := json.Marshal(struct {
		LeaseID string `json:"lease_id"`
	}{LeaseID: leaseID})
	if err != nil {
		return
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.releaseURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/json")
	if provider.token != "" {
		request.Header.Set("Authorization", "Bearer "+provider.token)
	}
	response, err := provider.client.Do(request)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	_ = response.Body.Close()
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

func requestForAuthorization(ctx context.Context, decoded *artifactv2.DecodedRequest) (authorizationRequest, error) {
	if decoded == nil || len(decoded.Raw) == 0 {
		return authorizationRequest{}, ErrInvalidAuthorization
	}
	transport, ok := ctx.Value(authorizationContextKey{}).(authorizationContext)
	if !ok || transport.carrier.Validate() != nil {
		return authorizationRequest{}, ErrInvalidAuthorization
	}
	return authorizationRequest{
		FSB2Base64URL: base64.RawURLEncoding.EncodeToString(decoded.Raw),
		Carrier:       string(transport.carrier), RemoteAddress: transport.remoteAddress,
	}, nil
}

func authorizeDirect(ctx context.Context, provider authorizationProvider, decoded *artifactv2.DecodedRequest, reasons artifactv2.ReasonRegistry, maxInbound uint16) (artifactv2.AdmissionResponse, *directAuthorization, error) {
	input, err := requestForAuthorization(ctx, decoded)
	if err != nil {
		return retryResponse(reasonAuthorizationUnavailable), nil, nil
	}
	decision, err := provider.Authorize(ctx, input)
	if err != nil {
		return retryResponse(reasonAuthorizationUnavailable), nil, nil
	}
	response, allowed, err := admissionDecision(decision, reasons)
	if err != nil || !allowed {
		return response, nil, err
	}
	if decoded.Request.PathKind != artifactv2.PathDirect || decision.Direct == nil ||
		decision.CredentialID == "" || decision.LeaseID == "" || decision.ExpiresAt.IsZero() || !decision.ExpiresAt.After(time.Now()) ||
		decision.ExpectedPeerEndpointInstanceID != "" || decision.AllowReplacement {
		return artifactv2.AdmissionResponse{}, nil, ErrInvalidAuthorization
	}
	contract, err := decision.Direct.Session.contract()
	if err != nil || contract.ChannelID != decoded.Request.ChannelID || contract.ContractHash != decoded.Request.SessionContractHash || contract.MaxInboundStreams != maxInbound || time.Now().Unix() >= contract.InitExpireAtUnixSeconds {
		return artifactv2.AdmissionResponse{}, nil, ErrInvalidAuthorization
	}
	if decision.Direct.Upstream.Network != "tcp" || decision.Direct.Upstream.Address == "" {
		return artifactv2.AdmissionResponse{}, nil, ErrInvalidAuthorization
	}
	decision.Direct.lease = &externalLease{provider: provider, id: decision.LeaseID}
	return response, decision.Direct, nil
}

func tunnelAuthorizer(provider authorizationProvider, reasons artifactv2.ReasonRegistry) tunnelv2.Authorize {
	return func(ctx context.Context, decoded *artifactv2.DecodedRequest) (tunnelv2.Authorization, error) {
		input, err := requestForAuthorization(ctx, decoded)
		if err != nil {
			return tunnelv2.Authorization{}, &admissionv2.ResponseError{Status: artifactv2.AdmissionRetryable, Reason: reasonAuthorizationUnavailable}
		}
		decision, err := provider.Authorize(ctx, input)
		if err != nil {
			return tunnelv2.Authorization{}, &admissionv2.ResponseError{Status: artifactv2.AdmissionRetryable, Reason: reasonAuthorizationUnavailable}
		}
		response, allowed, err := admissionDecision(decision, reasons)
		if err != nil {
			return tunnelv2.Authorization{}, err
		}
		if !allowed {
			return tunnelv2.Authorization{}, &admissionv2.ResponseError{Status: response.Status, Reason: response.Reason}
		}
		if decoded == nil || decoded.Request.PathKind != artifactv2.PathTunnel || decision.Direct != nil ||
			decision.CredentialID == "" || decision.LeaseID == "" || decision.ExpiresAt.IsZero() ||
			decision.ExpectedPeerEndpointInstanceID == "" {
			return tunnelv2.Authorization{}, ErrInvalidAuthorization
		}
		request := decoded.Request
		return tunnelv2.Authorization{
			Claims: tunnelv2.VerifiedClaims{
				CredentialID: decision.CredentialID, ChannelID: request.ChannelID, Profile: request.Profile,
				RendezvousGroupID: request.RendezvousGroupID, SessionContractHash: request.SessionContractHash,
				CandidateSetHash: request.CandidateSetHash, ListenerAudience: request.ListenerAudience,
				Role: request.Role, EndpointInstanceID: request.EndpointInstanceID,
				ExpectedPeerEndpointInstanceID: decision.ExpectedPeerEndpointInstanceID,
				AllowReplacement:               decision.AllowReplacement,
			},
			ExpiresAt: decision.ExpiresAt,
			Lease:     &externalLease{provider: provider, id: decision.LeaseID},
		}, nil
	}
}

func admissionDecision(decision authorizationResponse, reasons artifactv2.ReasonRegistry) (artifactv2.AdmissionResponse, bool, error) {
	switch decision.Decision {
	case "allow":
		if decision.Reason != "" {
			return artifactv2.AdmissionResponse{}, false, ErrInvalidAuthorization
		}
		return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, true, nil
	case "reject", "retry":
		if _, ok := reasons[decision.Reason]; !ok {
			return artifactv2.AdmissionResponse{}, false, ErrInvalidAuthorization
		}
		status := artifactv2.AdmissionReject
		if decision.Decision == "retry" {
			status = artifactv2.AdmissionRetryable
		}
		return artifactv2.AdmissionResponse{Status: status, Reason: decision.Reason}, false, nil
	default:
		return artifactv2.AdmissionResponse{}, false, ErrInvalidAuthorization
	}
}

func retryResponse(reason string) artifactv2.AdmissionResponse {
	return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionRetryable, Reason: reason}
}

func (wire authorizedSessionContract) contract() (artifactv2.SessionContract, error) {
	psk, err := base64.RawURLEncoding.DecodeString(wire.E2EEPSKBase64URL)
	if err != nil || len(psk) != 32 {
		return artifactv2.SessionContract{}, ErrInvalidAuthorization
	}
	contract := artifactv2.SessionContract{
		ChannelID: wire.ChannelID, InitExpireAtUnixSeconds: wire.InitExpireAtUnixSeconds,
		IdleTimeoutSeconds: wire.IdleTimeoutSeconds, EstablishTimeoutSeconds: wire.EstablishTimeoutSeconds,
		RekeyPrepareTimeoutSeconds: wire.RekeyPrepareTimeoutSeconds, RekeyCompletionTimeoutSeconds: wire.RekeyCompletionTimeoutSeconds,
		MaxInboundStreams: wire.MaxInboundStreams, AllowedSuites: wire.AllowedSuites,
		DefaultSuite: wire.DefaultSuite, SelectedFeatures: wire.SelectedFeatures,
	}
	copy(contract.E2EEPSK[:], psk)
	hash, _, err := artifactv2.ComputeSessionContractHash(contract)
	if err != nil {
		return artifactv2.SessionContract{}, ErrInvalidAuthorization
	}
	contract.ContractHash = hash
	return contract, nil
}
