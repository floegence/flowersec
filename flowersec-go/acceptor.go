package flowersec

// This file exposes the smallest server-side boundary needed by applications
// that own a Flowersec session. Carrier admission, session establishment, and
// tunnel pairing remain implemented by Flowersec internals; callers receive
// only the same public Session contract returned by Connect.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/controlplane"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2"
	websocketadmission "github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2/websocket"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/tunnelv2"
	gorillaws "github.com/gorilla/websocket"
)

const (
	WebSocketDirectPath = "/flowersec/v2/direct"
	WebSocketTunnelPath = "/flowersec/v2/tunnel"
)

var ErrInvalidAcceptor = errors.New("invalid Flowersec acceptor")

// AcceptorOptions configures one carrier-neutral application session owner.
// Authorize must atomically reserve the control-plane record before returning
// an allow response. Release is called exactly once for every accepted lease.
type AcceptorOptions struct {
	AllowedOrigins    []string
	MaxInboundStreams uint16
	MaxDirectSessions uint16
	Authorize         func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error)
	Release           func(context.Context, string)
	OnSession         func(context.Context, Session, string) error
}

type Acceptor struct {
	options     AcceptorOptions
	resources   carrierws.ResourcePolicy
	coordinator *tunnelv2.Coordinator
	directSlots chan struct{}
}

func NewAcceptor(options AcceptorOptions) (*Acceptor, error) {
	if options.Authorize == nil || options.OnSession == nil || len(options.AllowedOrigins) == 0 {
		return nil, ErrInvalidAcceptor
	}
	if options.MaxInboundStreams == 0 {
		options.MaxInboundStreams = 32
	}
	if options.MaxDirectSessions == 0 {
		options.MaxDirectSessions = 512
	}
	resources, err := carrierws.BindSessionResourcePolicy(carrierws.DefaultResourcePolicy(), options.MaxInboundStreams)
	if err != nil {
		return nil, ErrInvalidAcceptor
	}
	acceptor := &Acceptor{options: options, resources: resources, directSlots: make(chan struct{}, options.MaxDirectSessions)}
	coordinatorConfig := tunnelv2.DefaultConfig()
	coordinatorConfig.OnPair = acceptor.onTunnelPair
	coordinator, err := tunnelv2.NewCoordinator(coordinatorConfig, acceptor.authorizeTunnel)
	if err != nil {
		return nil, ErrInvalidAcceptor
	}
	acceptor.coordinator = coordinator
	return acceptor, nil
}

func (acceptor *Acceptor) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(WebSocketDirectPath, acceptor.handleDirect)
	mux.HandleFunc(WebSocketTunnelPath, acceptor.handleTunnel)
	return mux
}

func (acceptor *Acceptor) allowedOrigin(request *http.Request) bool {
	if request == nil {
		return false
	}
	origin := request.Header.Get("Origin")
	for _, allowed := range acceptor.options.AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

func (acceptor *Acceptor) handleDirect(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || !acceptor.allowedOrigin(request) {
		http.Error(writer, "request rejected", http.StatusForbidden)
		return
	}
	connection, err := (&gorillaws.Upgrader{Subprotocols: []string{carrierws.SubprotocolDirect}, CheckOrigin: acceptor.allowedOrigin, HandshakeTimeout: 10 * time.Second}).Upgrade(writer, request, nil)
	if err != nil {
		return
	}
	if !acceptor.acquireDirect() {
		_ = connection.Close()
		return
	}
	defer acceptor.releaseDirect()
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	var decoded *artifactv2.DecodedRequest
	var response controlplane.AuthorizationResponse
	var leaseID string
	decoded, err = websocketadmission.Serve(ctx, connection, acceptor.reasons(), func(authCtx context.Context, candidate *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
		if candidate == nil || candidate.Request.PathKind != artifactv2.PathDirect {
			return artifactv2.AdmissionResponse{}, ErrInvalidAcceptor
		}
		requestBody, marshalErr := artifactv2.MarshalRequest(candidate.Request)
		if marshalErr != nil {
			return artifactv2.AdmissionResponse{}, marshalErr
		}
		authRequest, parseErr := controlplane.ParseRuntimeAuthorizationRequest(requestBody)
		if parseErr != nil {
			return artifactv2.AdmissionResponse{}, parseErr
		}
		response, parseErr = acceptor.options.Authorize(authCtx, authRequest)
		if parseErr != nil {
			return artifactv2.AdmissionResponse{}, parseErr
		}
		decision, decisionErr := responseDecision(response)
		if decisionErr != nil {
			return artifactv2.AdmissionResponse{}, decisionErr
		}
		if decision == "allow" {
			leaseID, parseErr = responseLeaseID(response)
			if parseErr != nil {
				return artifactv2.AdmissionResponse{}, parseErr
			}
		}
		return responseAdmission(response)
	})
	if err != nil {
		_ = connection.Close()
		return
	}
	wire, err := decodeAuthorizationResponse(response)
	if err != nil || wire.Direct == nil {
		_ = connection.Close()
		return
	}
	carrierSession, err := carrierws.NewAfterAdmission(connection, carrierws.ServerRole, carrierws.SubprotocolDirect, acceptor.resources)
	if err != nil {
		_ = connection.Close()
		return
	}
	contract, contractErr := wire.Direct.Session.contract()
	if contractErr != nil {
		_ = connection.Close()
		return
	}
	accepted, err := establishAcceptedSession(ctx, carrierSession, contract, session.PathDirect, session.RoleServer, decoded.LocalAdmissionBinding, decoded.LocalAdmissionBinding)
	if err == nil {
		err = acceptor.options.OnSession(request.Context(), &opaqueSession{inner: accepted}, wire.Session.ChannelID)
	}
	if accepted != nil {
		_ = accepted.Close()
	}
	acceptor.releaseLease(request.Context(), leaseID)
}

func (acceptor *Acceptor) handleTunnel(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || !acceptor.allowedOrigin(request) {
		http.Error(writer, "request rejected", http.StatusForbidden)
		return
	}
	connection, err := (&gorillaws.Upgrader{Subprotocols: []string{carrierws.SubprotocolTunnel}, CheckOrigin: acceptor.allowedOrigin, HandshakeTimeout: 10 * time.Second}).Upgrade(writer, request, nil)
	if err != nil {
		return
	}
	leg, err := tunnelv2.NewWebSocketPendingLeg(connection, acceptor.resources)
	if err != nil {
		_ = connection.Close()
		return
	}
	if err := acceptor.coordinator.Serve(request.Context(), leg); err != nil {
		_ = connection.Close()
	}
}

func (acceptor *Acceptor) authorizeTunnel(ctx context.Context, decoded *artifactv2.DecodedRequest) (tunnelv2.Authorization, error) {
	if decoded == nil {
		return tunnelv2.Authorization{}, ErrInvalidAcceptor
	}
	raw, err := artifactv2.MarshalRequest(decoded.Request)
	if err != nil {
		return tunnelv2.Authorization{}, err
	}
	request, err := controlplane.ParseRuntimeAuthorizationRequest(raw)
	if err != nil {
		return tunnelv2.Authorization{}, err
	}
	response, err := acceptor.options.Authorize(ctx, request)
	if err != nil {
		return tunnelv2.Authorization{}, err
	}
	wire, err := decodeAuthorizationResponse(response)
	if err != nil || wire.Session.ChannelID == "" || wire.ExpectedPeerEndpointInstanceID == "" {
		return tunnelv2.Authorization{}, ErrInvalidAcceptor
	}
	if wire.Decision != "allow" {
		return tunnelv2.Authorization{}, &admissionv2.ResponseError{Status: artifactv2.AdmissionReject, Reason: wire.Reason}
	}
	if wire.LeaseID == "" {
		return tunnelv2.Authorization{}, ErrInvalidAcceptor
	}
	contract, err := wire.Session.contract()
	if err != nil {
		return tunnelv2.Authorization{}, err
	}
	return tunnelv2.Authorization{
		Claims:    tunnelv2.VerifiedClaims{CredentialID: wire.CredentialID, ChannelID: decoded.Request.ChannelID, Profile: decoded.Request.Profile, RendezvousGroupID: decoded.Request.RendezvousGroupID, SessionContractHash: decoded.Request.SessionContractHash, CandidateSetHash: decoded.Request.CandidateSetHash, ListenerAudience: decoded.Request.ListenerAudience, Role: decoded.Request.Role, EndpointInstanceID: decoded.Request.EndpointInstanceID, ExpectedPeerEndpointInstanceID: wire.ExpectedPeerEndpointInstanceID, AllowReplacement: wire.AllowReplacement},
		ExpiresAt: wire.ExpiresAt, Lease: acceptor.lease(wire.LeaseID), Session: contract, AdmissionBinding: decoded.LocalAdmissionBinding,
	}, nil
}

func (acceptor *Acceptor) onTunnelPair(ctx context.Context, client, server carrier.Session, clientAuth, serverAuth tunnelv2.Authorization) error {
	var wait sync.WaitGroup
	errs := make(chan error, 2)
	for _, item := range []struct {
		carrier carrier.Session
		auth    tunnelv2.Authorization
		role    session.SessionRole
		peer    [32]byte
	}{{client, clientAuth, session.RoleClient, serverAuth.AdmissionBinding}, {server, serverAuth, session.RoleServer, clientAuth.AdmissionBinding}} {
		item := item
		wait.Add(1)
		go func() {
			defer wait.Done()
			inner, err := establishAcceptedSession(ctx, item.carrier, item.auth.Session, session.PathTunnel, item.role, item.auth.AdmissionBinding, item.peer)
			if err == nil {
				err = acceptor.options.OnSession(ctx, &opaqueSession{inner: inner}, item.auth.Claims.EndpointInstanceID)
				_ = inner.Close()
			}
			if err != nil {
				errs <- err
			}
			if item.auth.Lease != nil {
				item.auth.Lease.Release()
			}
		}()
	}
	wait.Wait()
	close(errs)
	var err error
	for item := range errs {
		err = errors.Join(err, item)
	}
	return err
}

func establishAcceptedSession(ctx context.Context, carrierSession carrier.Session, contract artifactv2.SessionContract, path session.PathKind, role session.SessionRole, local, peer [32]byte) (session.SessionV2, error) {
	config := session.Config{Role: role, Path: path, ChannelID: contract.ChannelID, SessionContractHash: contract.ContractHash, Suite: protocolv2.Suite(contract.DefaultSuite), PSK: contract.E2EEPSK, MaxInboundStreams: contract.MaxInboundStreams, IdleTimeout: time.Duration(contract.IdleTimeoutSeconds) * time.Second, EstablishTimeout: time.Duration(contract.EstablishTimeoutSeconds) * time.Second, RekeyPrepareTimeout: time.Duration(contract.RekeyPrepareTimeoutSeconds) * time.Second, RekeyCompletionTimeout: time.Duration(contract.RekeyCompletionTimeoutSeconds) * time.Second, LocalAdmissionBinding: local, PeerAdmissionBinding: peer}
	return session.Establish(ctx, carrierSession, config)
}

func (acceptor *Acceptor) acquireDirect() bool {
	select {
	case acceptor.directSlots <- struct{}{}:
		return true
	default:
		return false
	}
}
func (acceptor *Acceptor) releaseDirect() { <-acceptor.directSlots }
func (acceptor *Acceptor) releaseLease(ctx context.Context, leaseID string) {
	if acceptor.options.Release != nil && leaseID != "" {
		acceptor.options.Release(ctx, leaseID)
	}
}
func (acceptor *Acceptor) lease(id string) tunnelv2.Lease {
	return &acceptorLease{release: func() { acceptor.releaseLease(context.Background(), id) }}
}
func (acceptor *Acceptor) reasons() artifactv2.ReasonRegistry {
	return artifactv2.ReasonRegistry{"authorization_denied": {}, "authorization_unavailable": {}, tunnelv2.ReasonCapacity: {}, tunnelv2.ReasonCredentialReplay: {}, tunnelv2.ReasonPairMismatch: {}, tunnelv2.ReasonPairTimeout: {}, tunnelv2.ReasonReplaced: {}, tunnelv2.ReasonReplacementDenied: {}}
}

type acceptorLease struct {
	once    sync.Once
	release func()
}

func (lease *acceptorLease) Release() { lease.once.Do(lease.release) }

type acceptorAuthorizationWire struct {
	Decision, Reason, CredentialID, LeaseID string
	ExpiresAt                               time.Time
	ExpectedPeerEndpointInstanceID          string
	AllowReplacement                        bool
	Session                                 acceptorSessionWire `json:"session"`
	Direct                                  *struct {
		Session acceptorSessionWire `json:"session"`
	} `json:"direct"`
}
type acceptorSessionWire struct {
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

func decodeAuthorizationResponse(response controlplane.AuthorizationResponse) (acceptorAuthorizationWire, error) {
	var wire acceptorAuthorizationWire
	if err := json.Unmarshal(response.JSON(), &wire); err != nil {
		return wire, ErrInvalidAcceptor
	}
	return wire, nil
}
func responseLeaseID(response controlplane.AuthorizationResponse) (string, error) {
	wire, err := decodeAuthorizationResponse(response)
	if err != nil || wire.LeaseID == "" {
		return "", ErrInvalidAcceptor
	}
	return wire.LeaseID, nil
}
func responseDecision(response controlplane.AuthorizationResponse) (string, error) {
	wire, err := decodeAuthorizationResponse(response)
	if err != nil || wire.Decision == "" {
		return "", ErrInvalidAcceptor
	}
	return wire.Decision, nil
}
func responseAdmission(response controlplane.AuthorizationResponse) (artifactv2.AdmissionResponse, error) {
	wire, err := decodeAuthorizationResponse(response)
	if err != nil {
		return artifactv2.AdmissionResponse{}, err
	}
	switch wire.Decision {
	case "allow":
		return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
	case "retry":
		return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionRetryable, Reason: wire.Reason}, nil
	case "reject":
		return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionReject, Reason: wire.Reason}, nil
	default:
		return artifactv2.AdmissionResponse{}, ErrInvalidAcceptor
	}
}

func (wire acceptorSessionWire) contract() (artifactv2.SessionContract, error) {
	psk, err := base64.RawURLEncoding.DecodeString(wire.E2EEPSKBase64URL)
	if err != nil || len(psk) != 32 || wire.ChannelID == "" || wire.MaxInboundStreams == 0 {
		return artifactv2.SessionContract{}, ErrInvalidAcceptor
	}
	contract := artifactv2.SessionContract{
		ChannelID: wire.ChannelID, InitExpireAtUnixSeconds: wire.InitExpireAtUnixSeconds,
		IdleTimeoutSeconds: wire.IdleTimeoutSeconds, EstablishTimeoutSeconds: wire.EstablishTimeoutSeconds,
		RekeyPrepareTimeoutSeconds: wire.RekeyPrepareTimeoutSeconds, RekeyCompletionTimeoutSeconds: wire.RekeyCompletionTimeoutSeconds,
		MaxInboundStreams: wire.MaxInboundStreams, AllowedSuites: wire.AllowedSuites, DefaultSuite: wire.DefaultSuite,
		SelectedFeatures: wire.SelectedFeatures,
	}
	copy(contract.E2EEPSK[:], psk)
	hash, _, err := artifactv2.ComputeSessionContractHash(contract)
	if err != nil {
		return artifactv2.SessionContract{}, ErrInvalidAcceptor
	}
	contract.ContractHash = hash
	return contract, nil
}
