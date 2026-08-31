package flowersec

// This file exposes the direct server boundary for applications that own a
// Flowersec session. Carrier admission and session establishment remain
// implemented by Flowersec internals; callers receive only the same public
// Session contract returned by Connect.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v4/controlplane"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/admissionv3"
	websocketadmission "github.com/floegence/flowersec/flowersec-go/v4/internal/admissionv3/websocket"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/carrier"
	carrierws "github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/websocketv3"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/webtransportv3"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/privateloopbackv1"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/protocolv3"
	internalrpc "github.com/floegence/flowersec/flowersec-go/v4/internal/rpc"
	session "github.com/floegence/flowersec/flowersec-go/v4/internal/sessionv3"
	gorillaws "github.com/gorilla/websocket"
)

const (
	WebSocketDirectPath               = "/flowersec/v3/direct"
	WebSocketTunnelPath               = "/flowersec/v3/tunnel"
	leaseReleaseTimeout               = 10 * time.Second
	applicationCallbackCleanupTimeout = 250 * time.Millisecond
)

var ErrInvalidAcceptor = errors.New("invalid Flowersec acceptor")

type PrivateLoopbackHandlerOptions struct {
	AuthorizeRequest func(*http.Request) bool
}

// AcceptorOptions configures one carrier-neutral application session owner.
// Authorize must atomically reserve the control-plane record before returning
// an allow response. Release is called exactly once for every accepted lease.
type AcceptorOptions struct {
	AllowedOrigins []string
	// Listeners declares the native carrier/path adapters owned by this
	// acceptor. WebSocket adapters are served by Handler; raw QUIC and
	// WebTransport adapters are served by Serve.
	Listeners         []DirectListener
	MaxInboundStreams uint16
	MaxDirectSessions uint16
	Authorize         func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error)
	Release           func(context.Context, string)
	// ResolveHandlers snapshots application handlers after direct authorization
	// and before session establishment. Returning nil installs an empty router.
	ResolveHandlers func(context.Context, controlplane.RuntimeAuthorizationRequest) (*SessionHandlers, error)
	OnSession       func(context.Context, Session, string) error
}

type Acceptor struct {
	options     AcceptorOptions
	resources   carrierws.ResourcePolicy
	directSlots chan struct{}
	listeners   []registeredAcceptorListener
}

func NewAcceptor(options AcceptorOptions) (*Acceptor, error) {
	if options.Authorize == nil || options.OnSession == nil {
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
	listeners := make([]registeredAcceptorListener, 0, len(options.Listeners))
	seen := make(map[string]struct{}, len(options.Listeners))
	for _, registered := range options.Listeners {
		listener, ok := registered.(registeredAcceptorListener)
		if !ok || listener.acceptorPath() != carrier.PathDirect {
			return nil, ErrInvalidAcceptor
		}
		key := string(listener.acceptorCarrier()) + ":" + string(listener.acceptorPath())
		if _, exists := seen[key]; exists {
			return nil, ErrInvalidAcceptor
		}
		seen[key] = struct{}{}
		listeners = append(listeners, listener)
	}
	acceptor := &Acceptor{options: options, resources: resources, directSlots: make(chan struct{}, options.MaxDirectSessions), listeners: listeners}
	return acceptor, nil
}

// Serve runs all registered native raw QUIC and WebTransport listeners until
// ctx is canceled or a listener fails. WebSocket routes remain owned by
// Handler and are intended to run on the application's HTTP server.
func (acceptor *Acceptor) Serve(ctx context.Context) error {
	if acceptor == nil {
		return ErrInvalidAcceptor
	}
	if ctx == nil {
		ctx = context.Background()
	}
	native := make([]registeredAcceptorListener, 0, len(acceptor.listeners))
	for _, listener := range acceptor.listeners {
		if listener.acceptorCarrier() != carrier.KindWebSocket {
			native = append(native, listener)
		}
	}
	if len(native) == 0 {
		return ErrInvalidAcceptor
	}
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(native))
	var listenerWait sync.WaitGroup
	var sessionWait sync.WaitGroup
	var sessionMu sync.Mutex
	acceptingSessions := true
	acceptSession := func(sessionCtx context.Context, current carrier.Session) error {
		sessionMu.Lock()
		if !acceptingSessions {
			sessionMu.Unlock()
			_ = current.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "acceptor closed"})
			return context.Canceled
		}
		sessionWait.Add(1)
		sessionMu.Unlock()
		go func() {
			defer sessionWait.Done()
			_ = acceptor.serveNativeCarrier(sessionCtx, current)
		}()
		return nil
	}
	for _, listener := range native {
		listener := listener
		listenerWait.Add(1)
		go func() {
			defer listenerWait.Done()
			err := listener.serve(serveCtx, acceptSession)
			if err != nil && !errors.Is(err, context.Canceled) {
				errs <- err
			}
		}()
	}
	var result error
	select {
	case <-ctx.Done():
		result = context.Cause(ctx)
	case result = <-errs:
	}
	cancel()
	for _, listener := range native {
		result = errors.Join(result, listener.Close())
	}
	listenerWait.Wait()
	sessionMu.Lock()
	acceptingSessions = false
	sessionMu.Unlock()
	sessionWait.Wait()
	return result
}

func (acceptor *Acceptor) serveNativeCarrier(ctx context.Context, native carrier.Session) error {
	if native == nil {
		return ErrInvalidAcceptor
	}
	observed, ok := native.(interface{ RemoteAddr() net.Addr })
	if !ok || observed.RemoteAddr() == nil || observed.RemoteAddr().String() == "" {
		_ = native.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "address unavailable"})
		return ErrInvalidAcceptor
	}
	transportContext := context.WithValue(ctx, acceptorTransportContextKey{}, acceptorTransportContext{carrier: string(native.Kind()), remoteAddress: observed.RemoteAddr().String()})
	switch native.Path() {
	case carrier.PathDirect:
		return acceptor.serveNativeDirect(transportContext, native)
	case carrier.PathTunnel:
		_ = native.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "wrong runtime boundary"})
		return ErrInvalidAcceptor
	default:
		return ErrInvalidAcceptor
	}
}

func (acceptor *Acceptor) serveNativeDirect(ctx context.Context, native carrier.Session) error {
	if !acceptor.acquireDirect() {
		_ = native.CloseWithError(carrier.ApplicationError{Code: 7, Reason: "capacity"})
		return nil
	}
	defer acceptor.releaseDirect()
	admissionContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	admission, err := acceptorNativeAdmissionStream(admissionContext, native)
	if err != nil {
		return err
	}
	var decoded *artifactv3.DecodedRequest
	var response controlplane.AuthorizationResponse
	var leaseID string
	var router *internalrpc.Router
	var serveHandlers func(context.Context, session.Session) error
	defer func() { acceptor.releaseLease(ctx, leaseID) }()
	decoded, err = admissionv3.Serve(admissionContext, admission, acceptor.reasons(), func(authCtx context.Context, candidate *artifactv3.DecodedRequest) (artifactv3.AdmissionResponse, error) {
		if candidate == nil || candidate.Request.PathKind != artifactv3.PathDirect {
			return artifactv3.AdmissionResponse{}, ErrInvalidAcceptor
		}
		transport, ok := authCtx.Value(acceptorTransportContextKey{}).(acceptorTransportContext)
		if !ok {
			return artifactv3.AdmissionResponse{}, ErrInvalidAcceptor
		}
		authRequest, parseErr := runtimeAuthorizationRequest(candidate, transport.carrier, transport.remoteAddress)
		if parseErr != nil {
			return artifactv3.AdmissionResponse{}, parseErr
		}
		response, parseErr = acceptor.authorize(authCtx, authRequest)
		if parseErr != nil {
			return artifactv3.AdmissionResponse{}, parseErr
		}
		if decision, decisionErr := responseDecision(response); decisionErr != nil {
			return artifactv3.AdmissionResponse{}, decisionErr
		} else if decision == "allow" {
			leaseID, parseErr = responseLeaseID(response)
			if parseErr != nil {
				return artifactv3.AdmissionResponse{}, parseErr
			}
			if acceptor.options.ResolveHandlers != nil {
				handlers, handlerErr := acceptor.resolveHandlers(authCtx, authRequest)
				if handlerErr != nil {
					return artifactv3.AdmissionResponse{}, handlerErr
				}
				router, serveHandlers = acceptedHandlerSnapshot(handlers)
			}
		}
		return responseAdmission(response)
	})
	if err != nil {
		_ = native.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "admission rejected"})
		return err
	}
	wire, err := decodeAuthorizationResponse(response)
	if err != nil || wire.Direct == nil {
		_ = native.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "authorization rejected"})
		return ErrInvalidAcceptor
	}
	contract, err := wire.Direct.Session.contract()
	if err != nil {
		_ = native.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "session contract rejected"})
		return err
	}
	accepted, err := establishAcceptedSession(ctx, native, contract, session.PathDirect, session.RoleServer, "", "", decoded.LocalAdmissionBinding, decoded.LocalAdmissionBinding, router)
	if err == nil {
		err = acceptor.runAcceptedSession(ctx, accepted, wire.Direct.Session.ChannelID, serveHandlers)
	}
	if accepted != nil {
		acceptor.closeAcceptedSession(ctx, accepted)
	}
	return err
}

func acceptorNativeAdmissionStream(ctx context.Context, native carrier.Session) (carrier.Stream, error) {
	if webTransport, ok := native.(*carrierwt.Session); ok {
		return carrierwt.OpenAdmissionStream(ctx, webTransport)
	}
	return native.AcceptStream(ctx)
}

// Handler returns the direct WebSocket boundary. Installing it directly on a
// caller-owned http.Server fails closed; use NewWebSocketHTTPServer so TLS
// policy is fixed before the handshake.
func (acceptor *Acceptor) Handler() http.Handler {
	mux := http.NewServeMux()
	direct := len(acceptor.listeners) == 0
	for _, listener := range acceptor.listeners {
		if listener.acceptorCarrier() != carrier.KindWebSocket {
			continue
		}
		direct = direct || listener.acceptorPath() == carrier.PathDirect
	}
	direct = direct && len(acceptor.options.AllowedOrigins) > 0
	if direct {
		mux.HandleFunc(WebSocketDirectPath, acceptor.handleDirect)
	}
	return &webSocketBoundary{handler: mux, enabled: direct}
}

// PrivateLoopbackHandler returns the direct WebSocket boundary for an
// application-owned HTTP loopback bridge. It accepts only an exact numeric
// loopback Host, RemoteAddr, and same-origin HTTP Origin, and it requires the
// caller to authorize every request before the WebSocket upgrade.
func (acceptor *Acceptor) PrivateLoopbackHandler(options PrivateLoopbackHandlerOptions) (http.Handler, error) {
	if acceptor == nil || options.AuthorizeRequest == nil {
		return nil, ErrInvalidAcceptor
	}
	mux := http.NewServeMux()
	mux.HandleFunc(WebSocketDirectPath, func(writer http.ResponseWriter, request *http.Request) {
		acceptor.handleDirectWithAdmission(
			writer,
			request,
			validatePrivateLoopbackUpgradeRequest,
			options.AuthorizeRequest,
			true,
		)
	})
	return mux, nil
}

func validatePrivateLoopbackUpgradeRequest(request *http.Request) bool {
	if request == nil || request.TLS != nil || !privateloopbackv1.RequestAllowed(request) ||
		!gorillaws.IsWebSocketUpgrade(request) {
		return false
	}
	if versions := request.Header.Values("Sec-WebSocket-Version"); len(versions) != 1 || versions[0] != "13" {
		return false
	}
	protocols := gorillaws.Subprotocols(request)
	if len(protocols) != 1 || protocols[0] != carrierws.SubprotocolDirect {
		return false
	}
	keys := request.Header.Values("Sec-WebSocket-Key")
	if len(keys) != 1 {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(keys[0])
	return err == nil && len(decoded) == 16 && base64.StdEncoding.EncodeToString(decoded) == keys[0]
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
	acceptor.handleDirectWithAdmission(writer, request, func(candidate *http.Request) bool {
		return candidate != nil && candidate.Method == http.MethodGet && carrierws.ValidateServerRequest(candidate) == nil
	}, acceptor.allowedOrigin, false)
}

func (acceptor *Acceptor) handleDirectWithAdmission(
	writer http.ResponseWriter,
	request *http.Request,
	validateRequest func(*http.Request) bool,
	authorizeRequest func(*http.Request) bool,
	privateLoopback bool,
) {
	if request == nil || validateRequest == nil || authorizeRequest == nil ||
		!validateRequest(request) || !authorizeRequest(request) {
		http.Error(writer, "request rejected", http.StatusForbidden)
		return
	}
	connection, err := (&gorillaws.Upgrader{
		Subprotocols: []string{carrierws.SubprotocolDirect},
		CheckOrigin: func(candidate *http.Request) bool {
			return validateRequest(candidate)
		},
		HandshakeTimeout: 10 * time.Second,
	}).Upgrade(writer, request, nil)
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
	var decoded *artifactv3.DecodedRequest
	var response controlplane.AuthorizationResponse
	var leaseID string
	var router *internalrpc.Router
	var serveHandlers func(context.Context, session.Session) error
	defer func() { acceptor.releaseLease(request.Context(), leaseID) }()
	serveAdmission := websocketadmission.Serve
	if privateLoopback {
		serveAdmission = websocketadmission.ServePrivateLoopback
	}
	decoded, err = serveAdmission(ctx, connection, acceptor.reasons(), func(authCtx context.Context, candidate *artifactv3.DecodedRequest) (artifactv3.AdmissionResponse, error) {
		if candidate == nil || candidate.Request.PathKind != artifactv3.PathDirect {
			return artifactv3.AdmissionResponse{}, ErrInvalidAcceptor
		}
		authRequest, parseErr := runtimeAuthorizationRequest(candidate, "websocket", request.RemoteAddr)
		if parseErr != nil {
			return artifactv3.AdmissionResponse{}, parseErr
		}
		response, parseErr = acceptor.authorize(authCtx, authRequest)
		if parseErr != nil {
			return artifactv3.AdmissionResponse{}, parseErr
		}
		decision, decisionErr := responseDecision(response)
		if decisionErr != nil {
			return artifactv3.AdmissionResponse{}, decisionErr
		}
		if decision == "allow" {
			leaseID, parseErr = responseLeaseID(response)
			if parseErr != nil {
				return artifactv3.AdmissionResponse{}, parseErr
			}
			if acceptor.options.ResolveHandlers != nil {
				handlers, handlerErr := acceptor.resolveHandlers(authCtx, authRequest)
				if handlerErr != nil {
					return artifactv3.AdmissionResponse{}, handlerErr
				}
				router, serveHandlers = acceptedHandlerSnapshot(handlers)
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
	var carrierSession *carrierws.Session
	if privateLoopback {
		carrierSession, err = carrierws.NewPrivateLoopbackAfterAdmission(connection, carrierws.ServerRole, acceptor.resources)
	} else {
		carrierSession, err = carrierws.NewAfterAdmission(connection, carrierws.ServerRole, carrierws.SubprotocolDirect, acceptor.resources)
	}
	if err != nil {
		_ = connection.Close()
		return
	}
	contract, contractErr := wire.Direct.Session.contract()
	if contractErr != nil {
		_ = connection.Close()
		return
	}
	accepted, err := establishAcceptedSession(ctx, carrierSession, contract, session.PathDirect, session.RoleServer, "", "", decoded.LocalAdmissionBinding, decoded.LocalAdmissionBinding, router)
	if err == nil {
		err = acceptor.runAcceptedSession(request.Context(), accepted, wire.Direct.Session.ChannelID, serveHandlers)
	}
	if accepted != nil {
		acceptor.closeAcceptedSession(request.Context(), accepted)
	}
}

func acceptedHandlerSnapshot(handlers *SessionHandlers) (*internalrpc.Router, func(context.Context, session.Session) error) {
	if handlers == nil {
		return internalrpc.NewRouter(), nil
	}
	router := handlers.routerForAcceptedSession()
	return router, func(ctx context.Context, current session.Session) error {
		return handlers.Serve(ctx, &opaqueSessionV3{inner: current})
	}
}

func (acceptor *Acceptor) runAcceptedSession(ctx context.Context, current session.Session, endpointID string, serveHandlers func(context.Context, session.Session) error) error {
	callbackCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	callbacks := 1
	results := make(chan error, 2)
	go func() {
		results <- acceptor.options.OnSession(callbackCtx, &opaqueSessionV3{inner: current}, endpointID)
	}()
	if serveHandlers != nil {
		callbacks++
		go func() { results <- serveHandlers(callbackCtx, current) }()
	}
	var first error
	select {
	case first = <-results:
		callbacks--
	case <-ctx.Done():
		first = context.Cause(ctx)
	}
	cancel()
	if callbacks == 0 {
		return first
	}
	timer := time.NewTimer(applicationCallbackCleanupTimeout)
	defer timer.Stop()
	for callbacks != 0 {
		select {
		case callbackErr := <-results:
			callbacks--
			if callbackErr != nil {
				first = errors.Join(first, callbackErr)
			}
		case <-timer.C:
			return first
		}
	}
	return first
}

func (acceptor *Acceptor) closeAcceptedSession(ctx context.Context, current session.Session) {
	if current == nil {
		return
	}
	if ctx.Err() == nil {
		_ = current.Close()
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = current.Close()
	}()
	timer := time.NewTimer(applicationCallbackCleanupTimeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}

type acceptorAuthorizationResult struct {
	response controlplane.AuthorizationResponse
	err      error
}

func (acceptor *Acceptor) authorize(ctx context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
	result := make(chan acceptorAuthorizationResult, 1)
	go func() {
		response, err := acceptor.options.Authorize(ctx, request)
		result <- acceptorAuthorizationResult{response: response, err: err}
	}()
	select {
	case completed := <-result:
		return completed.response, completed.err
	case <-ctx.Done():
		go func() {
			completed := <-result
			if completed.err != nil {
				return
			}
			decision, err := responseDecision(completed.response)
			if err != nil || decision != "allow" {
				return
			}
			leaseID, err := responseLeaseID(completed.response)
			if err == nil {
				acceptor.releaseLease(context.Background(), leaseID)
			}
		}()
		return controlplane.AuthorizationResponse{}, context.Cause(ctx)
	}
}

type acceptorHandlersResult struct {
	handlers *SessionHandlers
	err      error
}

func (acceptor *Acceptor) resolveHandlers(ctx context.Context, request controlplane.RuntimeAuthorizationRequest) (*SessionHandlers, error) {
	result := make(chan acceptorHandlersResult, 1)
	go func() {
		handlers, err := acceptor.options.ResolveHandlers(ctx, request)
		result <- acceptorHandlersResult{handlers: handlers, err: err}
	}()
	select {
	case completed := <-result:
		return completed.handlers, completed.err
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

func establishAcceptedSession(ctx context.Context, carrierSession carrier.Session, contract artifactv3.SessionContract, path session.PathKind, role session.SessionRole, localEndpointID, expectedPeerEndpointID string, local, peer [32]byte, router *internalrpc.Router) (session.Session, error) {
	config := session.Config{Role: role, Path: path, ChannelID: contract.ChannelID, SessionContractHash: contract.ContractHash, Suite: protocolv3.Suite(contract.DefaultSuite), PSK: contract.E2EEPSK, MaxInboundStreams: contract.MaxInboundStreams, IdleTimeout: time.Duration(contract.IdleTimeoutSeconds) * time.Second, EstablishTimeout: time.Duration(contract.EstablishTimeoutSeconds) * time.Second, RekeyPrepareTimeout: time.Duration(contract.RekeyPrepareTimeoutSeconds) * time.Second, RekeyCompletionTimeout: time.Duration(contract.RekeyCompletionTimeoutSeconds) * time.Second, LocalEndpointInstanceID: localEndpointID, ExpectedPeerEndpointInstanceID: expectedPeerEndpointID, LocalAdmissionBinding: local, PeerAdmissionBinding: peer, RPCRouter: router}
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
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), leaseReleaseTimeout)
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer cancel()
			acceptor.options.Release(cleanupCtx, leaseID)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			timer := time.NewTimer(applicationCallbackCleanupTimeout)
			defer timer.Stop()
			select {
			case <-done:
			case <-cleanupCtx.Done():
			case <-timer.C:
			}
		case <-cleanupCtx.Done():
		}
	}
}
func (acceptor *Acceptor) reasons() artifactv3.ReasonRegistry {
	return artifactv3.ReasonRegistry{
		"authorization_denied": {}, "authorization_unavailable": {},
		artifactv3.ReasonExpiredArtifact: {},
	}
}

type acceptorTransportContext struct {
	carrier       string
	remoteAddress string
}

type acceptorTransportContextKey struct{}

func runtimeAuthorizationRequest(decoded *artifactv3.DecodedRequest, observedCarrier, remoteAddress string) (controlplane.RuntimeAuthorizationRequest, error) {
	if decoded == nil || len(decoded.Raw) == 0 || observedCarrier == "" || remoteAddress == "" {
		return controlplane.RuntimeAuthorizationRequest{}, ErrInvalidAcceptor
	}
	encoded, err := json.Marshal(struct {
		FSB3Base64URL string `json:"fsb3_base64url"`
		Carrier       string `json:"carrier"`
		RemoteAddress string `json:"remote_address"`
	}{
		FSB3Base64URL: base64.RawURLEncoding.EncodeToString(decoded.Raw),
		Carrier:       observedCarrier,
		RemoteAddress: remoteAddress,
	})
	if err != nil {
		return controlplane.RuntimeAuthorizationRequest{}, ErrInvalidAcceptor
	}
	return controlplane.ParseRuntimeAuthorizationRequest(encoded)
}

type acceptorAuthorizationWire struct {
	Decision                       string              `json:"decision"`
	Reason                         string              `json:"reason"`
	CredentialID                   string              `json:"credential_id"`
	LeaseID                        string              `json:"lease_id"`
	ExpiresAt                      time.Time           `json:"expires_at"`
	ExpectedPeerEndpointInstanceID string              `json:"expected_peer_endpoint_instance_id"`
	AllowReplacement               bool                `json:"allow_replacement"`
	Session                        acceptorSessionWire `json:"session"`
	Direct                         *struct {
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
func responseAdmission(response controlplane.AuthorizationResponse) (artifactv3.AdmissionResponse, error) {
	wire, err := decodeAuthorizationResponse(response)
	if err != nil {
		return artifactv3.AdmissionResponse{}, err
	}
	switch wire.Decision {
	case "allow":
		return artifactv3.AdmissionResponse{Status: artifactv3.AdmissionSuccess}, nil
	case "retry":
		return artifactv3.AdmissionResponse{Status: artifactv3.AdmissionRetryable, Reason: wire.Reason}, nil
	case "reject":
		return artifactv3.AdmissionResponse{Status: artifactv3.AdmissionReject, Reason: wire.Reason}, nil
	default:
		return artifactv3.AdmissionResponse{}, ErrInvalidAcceptor
	}
}

func (wire acceptorSessionWire) contract() (artifactv3.SessionContract, error) {
	psk, err := base64.RawURLEncoding.DecodeString(wire.E2EEPSKBase64URL)
	if err != nil || len(psk) != 32 || wire.ChannelID == "" || wire.MaxInboundStreams == 0 {
		return artifactv3.SessionContract{}, ErrInvalidAcceptor
	}
	contract := artifactv3.SessionContract{
		ChannelID: wire.ChannelID, InitExpireAtUnixSeconds: wire.InitExpireAtUnixSeconds,
		IdleTimeoutSeconds: wire.IdleTimeoutSeconds, EstablishTimeoutSeconds: wire.EstablishTimeoutSeconds,
		RekeyPrepareTimeoutSeconds: wire.RekeyPrepareTimeoutSeconds, RekeyCompletionTimeoutSeconds: wire.RekeyCompletionTimeoutSeconds,
		MaxInboundStreams: wire.MaxInboundStreams, AllowedSuites: wire.AllowedSuites, DefaultSuite: wire.DefaultSuite,
		SelectedFeatures: wire.SelectedFeatures,
	}
	copy(contract.E2EEPSK[:], psk)
	hash, _, err := artifactv3.ComputeSessionContractHash(contract)
	if err != nil {
		return artifactv3.SessionContract{}, ErrInvalidAcceptor
	}
	contract.ContractHash = hash
	return contract, nil
}
