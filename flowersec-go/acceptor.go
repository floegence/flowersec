package flowersec

// This file exposes the direct server boundary for applications that own a
// Flowersec session. Carrier admission and session establishment remain
// implemented by Flowersec internals; callers receive only the same public
// Session contract returned by Connect.

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/controlplane"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/admissionv3"
	websocketadmission "github.com/floegence/flowersec/flowersec-go/v7/internal/admissionv3/websocket"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/carrier"
	carrierws "github.com/floegence/flowersec/flowersec-go/v7/internal/carrier/websocketv3"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v7/internal/carrier/webtransportv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/httpdirectv1"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/privateloopbackv1"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/protocolv3"
	internalrpc "github.com/floegence/flowersec/flowersec-go/v7/internal/rpc"
	session "github.com/floegence/flowersec/flowersec-go/v7/internal/sessionv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/transportsecurity"
	gorillaws "github.com/gorilla/websocket"
)

const (
	WebSocketDirectPath               = "/flowersec/v5/direct"
	WebSocketTunnelPath               = "/flowersec/v5/tunnel"
	leaseReleaseTimeout               = 10 * time.Second
	applicationCallbackCleanupTimeout = 250 * time.Millisecond
)

var ErrInvalidAcceptor = errors.New("invalid Flowersec acceptor")

type PrivateLoopbackHandlerOptions struct {
	AuthorizeRequest func(*http.Request) bool
}

// AcceptorOptions configures one carrier-neutral application session owner.
// Authorize must atomically consume the credential and durably commit its lease
// before returning allow. Release ends that lease without undoing consumption.
type AcceptorOptions struct {
	AllowedOrigins []string
	// CheckOrigin optionally authorizes each public TLS WebSocket upgrade from
	// current application policy. It is mutually exclusive with AllowedOrigins,
	// must be safe for concurrent calls, and does not replace session authorization.
	CheckOrigin func(*http.Request) bool
	// Listeners declares the native carrier/path adapters owned by this
	// acceptor. WebSocket adapters are served by Handler; raw QUIC and
	// WebTransport adapters are served by Serve.
	Listeners                []DirectListener
	IngressEndpoints         map[DirectListener]string
	MaxInboundStreams        uint16
	MaxDirectSessions        uint16
	RPCFrameLimits           RPCFrameLimits
	MaxConcurrentRPCRequests int
	Authorize                func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error)
	Release                  func(context.Context, string)
	// ResolveHandlers snapshots application handlers after direct authorization
	// and before session establishment. Returning nil installs an empty router.
	ResolveHandlers func(context.Context, controlplane.RuntimeAuthorizationRequest) (*SessionHandlers, error)
	OnSession       func(context.Context, Session, string) error
}

type Acceptor struct {
	ingresses   map[carrier.Kind]string
	options     AcceptorOptions
	resources   carrierws.ResourcePolicy
	directSlots chan struct{}
	listeners   []registeredAcceptorListener
}

func NewAcceptor(options AcceptorOptions) (*Acceptor, error) {
	if options.Authorize == nil || options.Release == nil || options.OnSession == nil || (options.CheckOrigin != nil && len(options.AllowedOrigins) > 0) || !internalrpc.FrameLimits(options.RPCFrameLimits).Valid() || options.MaxConcurrentRPCRequests < 0 {
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
	ingresses := make(map[carrier.Kind]string, len(options.IngressEndpoints))
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
		if endpoint, exists := options.IngressEndpoints[registered]; exists {
			normalized, err := artifactv3.NormalizeDirectEndpoint(artifactv3.Carrier(listener.acceptorCarrier()), endpoint)
			if err != nil {
				return nil, ErrInvalidAcceptor
			}
			ingresses[listener.acceptorCarrier()] = normalized
		}
		listeners = append(listeners, listener)
	}
	if len(ingresses) != len(options.IngressEndpoints) {
		return nil, ErrInvalidAcceptor
	}
	acceptor := &Acceptor{options: options, resources: resources, directSlots: make(chan struct{}, options.MaxDirectSessions), listeners: listeners, ingresses: ingresses}
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
		if !acceptor.acquireDirect() {
			sessionMu.Unlock()
			return current.CloseWithError(carrier.ApplicationError{Code: 7, Reason: "capacity"})
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
	drained := make(chan struct{})
	go func() {
		sessionWait.Wait()
		close(drained)
	}()
	timer := time.NewTimer(applicationCallbackCleanupTimeout)
	defer timer.Stop()
	select {
	case <-drained:
	case <-timer.C:
		result = errors.Join(result, fmt.Errorf("acceptor session cleanup: %w", context.DeadlineExceeded))
	}
	return result
}

func (acceptor *Acceptor) serveNativeCarrier(ctx context.Context, native carrier.Session) error {
	direct := &acceptedDirect{acceptor: acceptor}
	defer direct.finish(ctx)
	if native == nil {
		return ErrInvalidAcceptor
	}
	observed, ok := native.(interface{ RemoteAddr() net.Addr })
	if !ok || observed.RemoteAddr() == nil || observed.RemoteAddr().String() == "" {
		_ = native.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "address unavailable"})
		return ErrInvalidAcceptor
	}
	switch native.Path() {
	case carrier.PathDirect:
		return direct.serveNative(ctx, native, observed.RemoteAddr().String())
	case carrier.PathTunnel:
		_ = native.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "wrong runtime boundary"})
		return ErrInvalidAcceptor
	default:
		_ = native.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "invalid carrier path"})
		return ErrInvalidAcceptor
	}
}

func (direct *acceptedDirect) serveNative(ctx context.Context, native carrier.Session, remoteAddress string) error {
	admissionContext, cancel := context.WithDeadline(ctx, inboundDeadline(ctx))
	defer cancel()
	admission, err := acceptorNativeAdmissionStream(admissionContext, native)
	if err != nil {
		_ = native.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "admission stream unavailable"})
		return err
	}
	observed, ok := native.(interface {
		LocalAddr() net.Addr
		TLSState() tls.ConnectionState
	})
	if !ok {
		_ = native.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "missing listener identity"})
		return ErrInvalidAcceptor
	}
	state := observed.TLSState()
	ingress := directIngress{local: observed.LocalAddr(), state: &state, configured: direct.acceptor.ingresses[native.Kind()]}
	decoded, err := admissionv3.Serve(admissionContext, admission, direct.acceptor.reasons(), direct.authorize(string(native.Kind()), remoteAddress, ingress))
	if err != nil {
		_ = native.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "admission rejected"})
		return err
	}
	return direct.serve(ctx, admissionContext, native, decoded.LocalAdmissionBinding)
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
	direct = direct && (len(acceptor.options.AllowedOrigins) > 0 || acceptor.options.CheckOrigin != nil)
	if direct {
		mux.HandleFunc(WebSocketDirectPath, acceptor.handleDirect)
	}
	return &webSocketBoundary{handler: mux, enabled: direct, direct: acceptor}
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
			webSocketAdmissionPrivate,
		)
	})
	return mux, nil
}

type webSocketAdmissionMode uint8

const (
	webSocketAdmissionTLS webSocketAdmissionMode = iota
	webSocketAdmissionPrivate
	webSocketAdmissionHTTP
)

type HTTPDirectHandlerOptions struct {
	// AuthorizeRequest admits the exact configured HTTP authority and user session.
	// Flowersec also enforces the direct route and a same-origin HTTP Origin.
	AuthorizeRequest func(*http.Request) bool
}

type httpDirectBoundary struct{ handler http.Handler }

func (*httpDirectBoundary) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "Flowersec HTTP direct requires NewHTTPDirectServer", http.StatusForbidden)
}

// HTTPDirectHandler is an explicit public HTTP boundary. It never substitutes
// for the token-admitted private loopback or the ordinary TLS handler.
func (acceptor *Acceptor) HTTPDirectHandler(options HTTPDirectHandlerOptions) (http.Handler, error) {
	if acceptor == nil || options.AuthorizeRequest == nil {
		return nil, ErrInvalidAcceptor
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acceptor.handleDirectWithAdmission(w, r, func(candidate *http.Request) bool {
			return httpdirectv1.RequestAllowed(candidate) && validateDirectUpgradeHeaders(candidate)
		}, options.AuthorizeRequest, webSocketAdmissionHTTP)
	})
	return &httpDirectBoundary{handler: handler}, nil
}

func validatePrivateLoopbackUpgradeRequest(request *http.Request) bool {
	if request == nil || request.TLS != nil || !privateloopbackv1.RequestAllowed(request) ||
		!gorillaws.IsWebSocketUpgrade(request) {
		return false
	}
	return validateDirectUpgradeHeaders(request)
}

func validateDirectUpgradeHeaders(request *http.Request) bool {
	if request == nil || !gorillaws.IsWebSocketUpgrade(request) {
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
	if acceptor.options.CheckOrigin != nil {
		return acceptor.options.CheckOrigin(request)
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
	acceptor.handleDirectWithPolicy(writer, request, nil)
}

func (acceptor *Acceptor) handleDirectWithPolicy(writer http.ResponseWriter, request *http.Request, policy func(*http.Request) bool) {
	acceptor.handleDirectWithAdmission(writer, request, func(candidate *http.Request) bool {
		return candidate != nil && candidate.Method == http.MethodGet && gorillaws.IsWebSocketUpgrade(candidate) && carrierws.ValidateServerRequest(candidate) == nil
	}, func(candidate *http.Request) bool {
		return acceptor.allowedOrigin(candidate) && (policy == nil || policy(candidate))
	}, webSocketAdmissionTLS)
}

func (acceptor *Acceptor) handleDirectWithAdmission(
	writer http.ResponseWriter,
	request *http.Request,
	validateRequest func(*http.Request) bool,
	authorizeRequest func(*http.Request) bool,
	mode webSocketAdmissionMode,
) {
	deadline := time.Now().Add(inboundAdmissionTimeout)
	if request == nil || validateRequest == nil || authorizeRequest == nil ||
		!validateRequest(request) {
		http.Error(writer, "request rejected", http.StatusForbidden)
		return
	}
	if !acceptor.acquireDirect() {
		http.Error(writer, "admission busy", http.StatusServiceUnavailable)
		return
	}
	direct := &acceptedDirect{acceptor: acceptor}
	defer direct.finish(request.Context())
	ctx, cancel := context.WithDeadline(request.Context(), deadline)
	defer cancel()
	if !authorizeRequest(request.WithContext(ctx)) {
		http.Error(writer, "request rejected", http.StatusForbidden)
		return
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || ctx.Err() != nil {
		http.Error(writer, "admission timed out", http.StatusRequestTimeout)
		return
	}
	connection, err := (&gorillaws.Upgrader{
		Subprotocols: []string{carrierws.SubprotocolDirect},
		CheckOrigin: func(candidate *http.Request) bool {
			return validateRequest(candidate)
		},
		HandshakeTimeout: remaining,
	}).Upgrade(writer, request, nil)
	if err != nil {
		return
	}
	serveAdmission := websocketadmission.Serve
	if mode == webSocketAdmissionPrivate {
		serveAdmission = websocketadmission.ServePrivateLoopback
	} else if mode == webSocketAdmissionHTTP {
		serveAdmission = websocketadmission.ServeHTTPDirect
	}
	ingress := directIngress{local: connection.LocalAddr(), state: request.TLS, authority: request.Host, mode: mode}
	if mode == webSocketAdmissionTLS {
		ingress.configured = acceptor.ingresses[carrier.KindWebSocket]
	}
	decoded, err := serveAdmission(ctx, connection, acceptor.reasons(), direct.authorize("websocket", request.RemoteAddr, ingress))
	if err != nil {
		_ = connection.Close()
		return
	}
	var carrierSession *carrierws.Session
	if mode == webSocketAdmissionPrivate {
		carrierSession, err = carrierws.NewPrivateLoopbackAfterAdmission(connection, carrierws.ServerRole, acceptor.resources)
	} else if mode == webSocketAdmissionHTTP {
		carrierSession, err = carrierws.NewHTTPDirectAfterAdmission(connection, carrierws.ServerRole, acceptor.resources)
	} else {
		carrierSession, err = carrierws.NewAfterAdmission(connection, carrierws.ServerRole, carrierws.SubprotocolDirect, acceptor.resources)
	}
	if err != nil {
		_ = connection.Close()
		return
	}
	_ = direct.serve(request.Context(), ctx, carrierSession, decoded.LocalAdmissionBinding)
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

type acceptedDirect struct {
	acceptor      *Acceptor
	workers       sync.WaitGroup
	leaseID       string
	contract      artifactv3.SessionContract
	router        *internalrpc.Router
	serveHandlers func(context.Context, session.Session) error
}

func (direct *acceptedDirect) serve(ctx, establishCtx context.Context, transport carrier.Session, binding [32]byte) error {
	current, err := direct.acceptor.establishAcceptedSession(establishCtx, transport, direct.contract, session.PathDirect, session.RoleServer, "", "", binding, binding, direct.router)
	if err != nil {
		_ = transport.CloseWithErrorContext(establishCtx, carrier.ApplicationError{Code: 6, Reason: "session establishment failed"})
		return err
	}
	callbackCtx, cancel := context.WithCancelCause(ctx)
	if err = context.Cause(callbackCtx); err == nil {
		results := make(chan error, 2)
		direct.workers.Go(func() {
			results <- direct.acceptor.options.OnSession(callbackCtx, &opaqueSessionV3{inner: current}, direct.contract.ChannelID)
		})
		if serveHandlers := direct.serveHandlers; serveHandlers != nil {
			direct.workers.Go(func() { results <- serveHandlers(callbackCtx, current) })
		}
		select {
		case err = <-results:
		case <-ctx.Done():
			err = context.Cause(ctx)
		case <-current.Termination():
			err = current.WaitClosed(context.Background())
		}
	}
	cancel(err)
	_ = current.Close()
	if draining, ok := current.(interface{ WaitCleanup(context.Context) error }); ok {
		_ = draining.WaitCleanup(context.Background())
	}
	return err
}

type directIngress struct {
	local                 net.Addr
	state                 *tls.ConnectionState
	authority, configured string
	mode                  webSocketAdmissionMode
}

func (ingress directIngress) match(decoded *artifactv3.DecodedRequest, kind artifactv3.Carrier) (string, bool) {
	if ingress.local == nil || decoded == nil || decoded.Request.PathKind != artifactv3.PathDirect {
		return "", false
	}
	for _, candidate := range decoded.Request.Candidates {
		if candidate.ID != decoded.Request.ChosenCandidateID || candidate.Carrier != kind {
			continue
		}
		if !transportsecurity.MatchesLocalDirectEndpoint(candidate.NormalizedURL, ingress.configured, ingress.local, ingress.state) {
			return "", false
		}
		if ingress.mode != webSocketAdmissionTLS {
			if kind != artifactv3.CarrierWebSocket || len(decoded.Request.Candidates) != 1 || candidate.TLS.Mode != artifactv3.TLSModeCA {
				return "", false
			}
			profile, id, validate := controlplane.HTTPDirectProfile, "http-direct", httpdirectv1.ValidateEndpoint
			if ingress.mode == webSocketAdmissionPrivate {
				profile, id, validate = controlplane.PrivateLoopbackProfile, "private-loopback", privateloopbackv1.ValidateEndpoint
			}
			_, binding, err := validate("ws://" + ingress.authority + WebSocketDirectPath)
			normalized, normalizeErr := artifactv3.NormalizeDirectEndpoint(kind, binding)
			return profile, err == nil && normalizeErr == nil && normalized == candidate.NormalizedURL && candidate.ID == id
		}
		if ingress.authority != "" {
			normalized, err := artifactv3.NormalizeDirectEndpoint(kind, "wss://"+ingress.authority+WebSocketDirectPath)
			if err != nil || normalized != candidate.NormalizedURL {
				return "", false
			}
		}
		return "", transportsecurity.MatchesDirectIngress(decoded, kind, candidate.NormalizedURL, ingress.state, time.Now())
	}
	return "", false
}

func (direct *acceptedDirect) authorize(observedCarrier, remoteAddress string, ingress directIngress) admissionv3.Authorize {
	return func(ctx context.Context, candidate *artifactv3.DecodedRequest) (artifactv3.AdmissionResponse, error) {
		if candidate == nil || candidate.Request.PathKind != artifactv3.PathDirect {
			return artifactv3.AdmissionResponse{}, ErrInvalidAcceptor
		}
		profile, matches := ingress.match(candidate, artifactv3.Carrier(observedCarrier))
		if !matches {
			return artifactv3.AdmissionResponse{}, ErrInvalidAcceptor
		}
		request, err := runtimeAuthorizationRequestForProfile(candidate, observedCarrier, remoteAddress, profile)
		if err != nil {
			return artifactv3.AdmissionResponse{}, err
		}
		var response artifactv3.AdmissionResponse
		done := make(chan struct{})
		direct.workers.Go(func() {
			defer close(done)
			response, err = direct.prepare(ctx, request, candidate)
		})
		select {
		case <-ctx.Done():
			return artifactv3.AdmissionResponse{}, context.Cause(ctx)
		case <-done:
			return response, err
		}
	}
}

func (direct *acceptedDirect) prepare(ctx context.Context, request controlplane.RuntimeAuthorizationRequest, candidate *artifactv3.DecodedRequest) (artifactv3.AdmissionResponse, error) {
	if err := context.Cause(ctx); err != nil {
		return artifactv3.AdmissionResponse{}, err
	}
	response, err := direct.acceptor.options.Authorize(ctx, request)
	if err != nil {
		return artifactv3.AdmissionResponse{}, err
	}
	wire, err := decodeAuthorizationResponse(response)
	if err != nil {
		return artifactv3.AdmissionResponse{}, err
	}
	if wire.Decision == "allow" {
		direct.leaseID = wire.LeaseID
		if err := context.Cause(ctx); err != nil {
			return artifactv3.AdmissionResponse{}, err
		}
		if direct.leaseID == "" || wire.CredentialID != request.LookupKey() || wire.Direct == nil || wire.ExpiresAt.IsZero() {
			return artifactv3.AdmissionResponse{}, ErrInvalidAcceptor
		}
		if !wire.ExpiresAt.After(time.Now()) {
			return artifactv3.AdmissionResponse{Status: artifactv3.AdmissionRetryable, Reason: artifactv3.ReasonExpiredArtifact}, nil
		}
		direct.contract, err = wire.Direct.Session.contract()
		if err != nil {
			return artifactv3.AdmissionResponse{}, err
		}
		if direct.contract.ChannelID != candidate.Request.ChannelID || direct.contract.ContractHash != candidate.Request.SessionContractHash {
			return artifactv3.AdmissionResponse{}, ErrInvalidAcceptor
		}
		if resolve := direct.acceptor.options.ResolveHandlers; resolve != nil {
			handlers, err := resolve(ctx, request)
			if err != nil {
				return artifactv3.AdmissionResponse{}, err
			}
			if err := context.Cause(ctx); err != nil {
				return artifactv3.AdmissionResponse{}, err
			}
			direct.router, direct.serveHandlers = acceptedHandlerSnapshot(handlers)
		}
		now := time.Now()
		if !wire.ExpiresAt.After(now) || direct.contract.InitExpireAtUnixSeconds <= now.Unix() {
			return artifactv3.AdmissionResponse{Status: artifactv3.AdmissionRetryable, Reason: artifactv3.ReasonExpiredArtifact}, nil
		}
	}
	return wire.admission()
}

func (acceptor *Acceptor) establishAcceptedSession(ctx context.Context, carrierSession carrier.Session, contract artifactv3.SessionContract, path session.PathKind, role session.SessionRole, localEndpointID, expectedPeerEndpointID string, local, peer [32]byte, router *internalrpc.Router) (session.Session, error) {
	config := session.Config{Role: role, Path: path, ChannelID: contract.ChannelID, SessionContractHash: contract.ContractHash, Suite: protocolv3.Suite(contract.DefaultSuite), PSK: contract.E2EEPSK, MaxInboundStreams: contract.MaxInboundStreams, IdleTimeout: time.Duration(contract.IdleTimeoutSeconds) * time.Second, EstablishTimeout: time.Duration(contract.EstablishTimeoutSeconds) * time.Second, RekeyPrepareTimeout: time.Duration(contract.RekeyPrepareTimeoutSeconds) * time.Second, RekeyCompletionTimeout: time.Duration(contract.RekeyCompletionTimeoutSeconds) * time.Second, LocalEndpointInstanceID: localEndpointID, ExpectedPeerEndpointInstanceID: expectedPeerEndpointID, LocalAdmissionBinding: local, PeerAdmissionBinding: peer, RPCRouter: router}
	config.RPCServerOptions.FrameLimits = internalrpc.FrameLimits(acceptor.options.RPCFrameLimits)
	config.RPCServerOptions.MaxConcurrentRequests = acceptor.options.MaxConcurrentRPCRequests
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
func (direct *acceptedDirect) finish(ctx context.Context) {
	defer func() { <-direct.acceptor.directSlots }()
	direct.workers.Wait()
	if direct.leaseID != "" {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), leaseReleaseTimeout)
		defer cancel()
		direct.acceptor.options.Release(cleanupCtx, direct.leaseID)
	}
}
func (acceptor *Acceptor) reasons() artifactv3.ReasonRegistry {
	return artifactv3.ReasonRegistry{
		"authorization_denied": {}, "authorization_unavailable": {}, "permission_denied": {},
		artifactv3.ReasonExpiredArtifact: {},
	}
}

type acceptorTransportContext struct {
	carrier       string
	remoteAddress string
}

type acceptorTransportContextKey struct{}

func runtimeAuthorizationRequest(decoded *artifactv3.DecodedRequest, observedCarrier, remoteAddress string) (controlplane.RuntimeAuthorizationRequest, error) {
	return runtimeAuthorizationRequestForProfile(decoded, observedCarrier, remoteAddress, "")
}

func runtimeAuthorizationRequestForProfile(decoded *artifactv3.DecodedRequest, observedCarrier, remoteAddress, profile string) (controlplane.RuntimeAuthorizationRequest, error) {
	if decoded == nil || len(decoded.Raw) == 0 || observedCarrier == "" || remoteAddress == "" {
		return controlplane.RuntimeAuthorizationRequest{}, ErrInvalidAcceptor
	}
	encoded, err := json.Marshal(struct {
		DirectProfile string `json:"direct_profile,omitempty"`
		FSB3Base64URL string `json:"fsb5_base64url"`
		Carrier       string `json:"carrier"`
		RemoteAddress string `json:"remote_address"`
	}{
		DirectProfile: profile,
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
func (wire acceptorAuthorizationWire) admission() (artifactv3.AdmissionResponse, error) {
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
