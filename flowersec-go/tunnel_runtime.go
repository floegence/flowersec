package flowersec

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/controlplane"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/admissionv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/carrier"
	carrierws "github.com/floegence/flowersec/flowersec-go/v7/internal/carrier/websocketv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/transportsecurity"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/tunnelv3"
	gorillaws "github.com/gorilla/websocket"
)

var ErrInvalidTunnelRuntime = errors.New("invalid Flowersec tunnel runtime")

// TunnelRuntimeOptions configures an untrusted opaque relay. The runtime owns
// admission, pairing, forwarding, capacity, and lease cleanup only.
type TunnelRuntimeOptions struct {
	AllowedOrigins []string
	Listeners      []TunnelListener
	// IngressEndpoints maps each listener to the public URL authorized for it.
	// A forwarder's public URL can differ from the local listening address.
	IngressEndpoints  map[TunnelListener]string
	MaxInboundStreams uint16
	MaxPendingLegs    int
	MaxActivePairs    int
	Authorize         func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.TunnelAuthorizationResponse, error)
	Release           func(context.Context, string)
}

type TunnelRuntime struct {
	options     TunnelRuntimeOptions
	resources   carrierws.ResourcePolicy
	coordinator *tunnelv3.Coordinator
	listeners   []registeredAcceptorListener
	ingresses   map[registeredAcceptorListener]string
}

func NewTunnelRuntime(options TunnelRuntimeOptions) (*TunnelRuntime, error) {
	if options.Authorize == nil || options.Release == nil || len(options.Listeners) == 0 || len(options.IngressEndpoints) != len(options.Listeners) {
		return nil, ErrInvalidTunnelRuntime
	}
	if options.MaxInboundStreams == 0 {
		options.MaxInboundStreams = 32
	}
	resources, err := carrierws.BindSessionResourcePolicy(carrierws.DefaultResourcePolicy(), options.MaxInboundStreams)
	if err != nil {
		return nil, ErrInvalidTunnelRuntime
	}
	listeners := make([]registeredAcceptorListener, 0, len(options.Listeners))
	ingresses := make(map[registeredAcceptorListener]string, len(options.Listeners))
	webSocket := false
	for _, declared := range options.Listeners {
		listener, ok := declared.(registeredAcceptorListener)
		if !ok || listener.acceptorPath() != carrier.PathTunnel {
			return nil, ErrInvalidTunnelRuntime
		}
		if _, duplicate := ingresses[listener]; duplicate {
			return nil, ErrInvalidTunnelRuntime
		}
		endpoint, err := artifactv3.NormalizeTunnelEndpoint(artifactv3.Carrier(listener.acceptorCarrier()), options.IngressEndpoints[declared])
		if err != nil {
			return nil, ErrInvalidTunnelRuntime
		}
		ingresses[listener] = endpoint
		webSocket = webSocket || listener.acceptorCarrier() == carrier.KindWebSocket
		listeners = append(listeners, listener)
	}
	if webSocket && len(options.AllowedOrigins) == 0 {
		return nil, ErrInvalidTunnelRuntime
	}
	runtime := &TunnelRuntime{options: options, resources: resources, listeners: listeners, ingresses: ingresses}
	config := tunnelv3.DefaultConfig()
	if options.MaxPendingLegs != 0 {
		config.MaxPendingLegs = options.MaxPendingLegs
	}
	if options.MaxActivePairs != 0 {
		config.MaxActivePairs = options.MaxActivePairs
	}
	coordinator, err := tunnelv3.NewCoordinator(config, runtime.authorize)
	if err != nil {
		return nil, ErrInvalidTunnelRuntime
	}
	runtime.coordinator = coordinator
	return runtime, nil
}

// Handler returns the sole tunnel WebSocket boundary for NewWebSocketHTTPServer.
// When several WebSocket listeners are registered, use HandlerFor for each.
func (runtime *TunnelRuntime) Handler() http.Handler {
	var selected registeredAcceptorListener
	for _, listener := range runtime.listeners {
		if listener.acceptorCarrier() == carrier.KindWebSocket {
			if selected != nil {
				return &webSocketBoundary{}
			}
			selected = listener
		}
	}
	return runtime.webSocketBoundaryFor(selected)
}

// HandlerFor binds a WebSocket HTTP server to one configured tunnel listener.
// An unknown or non-WebSocket listener cannot be installed on the server.
func (runtime *TunnelRuntime) HandlerFor(listener TunnelListener) http.Handler {
	registered, _ := listener.(registeredAcceptorListener)
	return runtime.webSocketBoundaryFor(registered)
}

func (runtime *TunnelRuntime) webSocketBoundaryFor(listener registeredAcceptorListener) http.Handler {
	endpoint, ok := runtime.ingresses[listener]
	if !ok || listener.acceptorCarrier() != carrier.KindWebSocket {
		return &webSocketBoundary{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc(WebSocketTunnelPath, func(w http.ResponseWriter, r *http.Request) {
		runtime.handleWebSocket(w, r, endpoint)
	})
	return &webSocketBoundary{handler: mux, enabled: true}
}

func (runtime *TunnelRuntime) Serve(ctx context.Context) error {
	if runtime == nil {
		return ErrInvalidTunnelRuntime
	}
	if ctx == nil {
		ctx = context.Background()
	}
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(runtime.listeners))
	var listenerWait sync.WaitGroup
	var sessionWait sync.WaitGroup
	var sessionMu sync.Mutex
	accepting := true
	for _, listener := range runtime.listeners {
		if listener.acceptorCarrier() == carrier.KindWebSocket {
			continue
		}
		listener := listener
		listenerWait.Add(1)
		go func() {
			defer listenerWait.Done()
			err := listener.serve(serveCtx, func(sessionCtx context.Context, native carrier.Session) error {
				sessionMu.Lock()
				if !accepting || serveCtx.Err() != nil {
					sessionMu.Unlock()
					return native.CloseWithError(carrier.ApplicationError{Reason: "runtime closed"})
				}
				sessionWait.Add(1)
				sessionMu.Unlock()
				go func() {
					defer sessionWait.Done()
					_ = runtime.serveNative(sessionCtx, native, runtime.ingresses[listener])
				}()
				return nil
			})
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
	sessionMu.Lock()
	accepting = false
	sessionMu.Unlock()
	for _, listener := range runtime.listeners {
		result = errors.Join(result, listener.Close())
	}
	listenerWait.Wait()
	sessionWait.Wait()
	return result
}

func (runtime *TunnelRuntime) serveNative(ctx context.Context, native carrier.Session, endpoint string) error {
	if native == nil || native.Path() != carrier.PathTunnel {
		return ErrInvalidTunnelRuntime
	}
	stateSource, ok := native.(interface{ TLSState() tls.ConnectionState })
	if !ok {
		_ = native.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "invalid ingress"})
		return ErrInvalidTunnelRuntime
	}
	state := stateSource.TLSState()
	ctx = transportsecurity.WithTunnelIngress(ctx, artifactv3.Carrier(native.Kind()), endpoint, &state)
	observed, ok := native.(interface{ RemoteAddr() net.Addr })
	remote := "native"
	if ok && observed.RemoteAddr() != nil {
		remote = observed.RemoteAddr().String()
	}
	leg, err := tunnelv3.NewPendingNativeLeg(native, func(admissionCtx context.Context) (carrier.Stream, error) {
		return acceptorNativeAdmissionStream(admissionCtx, native)
	})
	if err != nil {
		_ = native.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "admission failed"})
		return err
	}
	return runtime.coordinator.ServeOwnedUntil(context.WithValue(ctx, acceptorTransportContextKey{}, acceptorTransportContext{carrier: string(native.Kind()), remoteAddress: remote}), leg, inboundDeadline(ctx))
}

func (runtime *TunnelRuntime) handleWebSocket(writer http.ResponseWriter, request *http.Request, endpoint string) {
	deadline := time.Now().Add(inboundAdmissionTimeout)
	if request.Method != http.MethodGet || !runtime.allowedOrigin(request) || carrierws.ValidateServerRequest(request) != nil {
		http.Error(writer, "request rejected", http.StatusForbidden)
		return
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		http.Error(writer, "admission timed out", http.StatusRequestTimeout)
		return
	}
	connection, err := (&gorillaws.Upgrader{Subprotocols: []string{carrierws.SubprotocolTunnel}, CheckOrigin: runtime.allowedOrigin, HandshakeTimeout: remaining}).Upgrade(writer, request, nil)
	if err != nil {
		return
	}
	leg, err := tunnelv3.NewWebSocketPendingLeg(connection, runtime.resources)
	if err != nil {
		_ = connection.Close()
		return
	}
	ctx := context.WithValue(request.Context(), acceptorTransportContextKey{}, acceptorTransportContext{carrier: "websocket", remoteAddress: request.RemoteAddr})
	ctx = transportsecurity.WithTunnelIngress(ctx, artifactv3.CarrierWebSocket, endpoint, request.TLS)
	if err := runtime.coordinator.ServeOwnedUntil(ctx, leg, deadline); err != nil {
		_ = connection.Close()
	}
}

func (runtime *TunnelRuntime) allowedOrigin(request *http.Request) bool {
	if request == nil {
		return false
	}
	for _, allowed := range runtime.options.AllowedOrigins {
		if request.Header.Get("Origin") == allowed {
			return true
		}
	}
	return false
}

func (runtime *TunnelRuntime) authorize(ctx context.Context, decoded *artifactv3.DecodedRequest) (tunnelv3.Authorization, error) {
	transport, ok := ctx.Value(acceptorTransportContextKey{}).(acceptorTransportContext)
	if !ok || !transportsecurity.MatchesTunnelIngress(ctx, decoded, time.Now()) {
		return tunnelv3.Authorization{}, ErrInvalidTunnelRuntime
	}
	request, err := runtimeAuthorizationRequest(decoded, transport.carrier, transport.remoteAddress)
	if err != nil {
		return tunnelv3.Authorization{}, err
	}
	response, err := runtime.options.Authorize(ctx, request)
	if err != nil {
		return tunnelv3.Authorization{}, err
	}
	var wire struct {
		AuthorityScope                 string    `json:"authority_scope"`
		Decision                       string    `json:"decision"`
		Reason                         string    `json:"reason"`
		CredentialID                   string    `json:"credential_id"`
		LeaseID                        string    `json:"lease_id"`
		ExpiresAt                      time.Time `json:"expires_at"`
		ExpectedPeerEndpointInstanceID string    `json:"expected_peer_endpoint_instance_id"`
		AllowReplacement               bool      `json:"allow_replacement"`
	}
	decoder := json.NewDecoder(bytes.NewReader(response.JSON()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return tunnelv3.Authorization{}, ErrInvalidTunnelRuntime
	}
	if wire.Decision == "reject" || wire.Decision == "retry" {
		if wire.AuthorityScope != "" || wire.CredentialID != "" || wire.LeaseID != "" || !wire.ExpiresAt.IsZero() ||
			wire.ExpectedPeerEndpointInstanceID != "" || wire.AllowReplacement {
			return tunnelv3.Authorization{}, ErrInvalidTunnelRuntime
		}
		status := artifactv3.AdmissionReject
		if wire.Decision == "retry" {
			status = artifactv3.AdmissionRetryable
		}
		admission := artifactv3.AdmissionResponse{Status: status, Reason: wire.Reason}
		if _, err := artifactv3.MarshalResponse(admission, tunnelv3.DefaultReasonRegistry()); err != nil {
			return tunnelv3.Authorization{}, ErrInvalidTunnelRuntime
		}
		return tunnelv3.Authorization{}, &admissionv3.ResponseError{Status: status, Reason: wire.Reason}
	}
	if wire.Decision != "allow" || wire.LeaseID == "" {
		return tunnelv3.Authorization{}, ErrInvalidTunnelRuntime
	}
	lease := &tunnelRuntimeLease{release: func(ctx context.Context) { runtime.options.Release(ctx, wire.LeaseID) }}
	if wire.Reason != "" || wire.CredentialID != request.LookupKey() || wire.ExpectedPeerEndpointInstanceID == "" || wire.ExpiresAt.IsZero() {
		return tunnelv3.Authorization{Lease: lease}, ErrInvalidTunnelRuntime
	}
	return tunnelv3.Authorization{
		Claims: tunnelv3.VerifiedClaims{
			AuthorityScope: wire.AuthorityScope,
			CredentialID:   wire.CredentialID, ChannelID: decoded.Request.ChannelID, Profile: decoded.Request.Profile,
			RendezvousGroupID: decoded.Request.RendezvousGroupID, SessionContractHash: decoded.Request.SessionContractHash,
			CandidateSetHash: decoded.Request.CandidateSetHash, ListenerAudience: decoded.Request.ListenerAudience,
			Role: decoded.Request.Role, EndpointInstanceID: decoded.Request.EndpointInstanceID,
			ExpectedPeerEndpointInstanceID: wire.ExpectedPeerEndpointInstanceID, AllowReplacement: wire.AllowReplacement,
		},
		ExpiresAt: wire.ExpiresAt,
		Lease:     lease,
	}, nil
}

type tunnelRuntimeLease struct {
	once    sync.Once
	release func(context.Context)
}

func (lease *tunnelRuntimeLease) ReleaseContext(ctx context.Context) {
	lease.once.Do(func() { lease.release(ctx) })
}

func releaseTunnelRuntimeLease(ctx context.Context, release func(context.Context, string), leaseID string) {
	release(ctx, leaseID)
}
