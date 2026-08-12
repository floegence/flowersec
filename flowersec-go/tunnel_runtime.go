package flowersec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/controlplane"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/tunnelv2"
	gorillaws "github.com/gorilla/websocket"
)

var ErrInvalidTunnelRuntime = errors.New("invalid Flowersec tunnel runtime")

// TunnelRuntimeOptions configures an untrusted opaque relay. The runtime owns
// admission, pairing, forwarding, capacity, and lease cleanup only.
type TunnelRuntimeOptions struct {
	AllowedOrigins    []string
	Listeners         []TunnelListener
	MaxInboundStreams uint16
	MaxPendingLegs    int
	MaxActivePairs    int
	Authorize         func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.TunnelAuthorizationResponse, error)
	Release           func(context.Context, string)
}

type TunnelRuntime struct {
	options     TunnelRuntimeOptions
	resources   carrierws.ResourcePolicy
	coordinator *tunnelv2.Coordinator
	listeners   []registeredAcceptorListener
}

func NewTunnelRuntime(options TunnelRuntimeOptions) (*TunnelRuntime, error) {
	if options.Authorize == nil || len(options.Listeners) == 0 {
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
	seen := make(map[carrier.Kind]struct{}, len(options.Listeners))
	webSocket := false
	for _, declared := range options.Listeners {
		listener, ok := declared.(registeredAcceptorListener)
		if !ok || listener.acceptorPath() != carrier.PathTunnel {
			return nil, ErrInvalidTunnelRuntime
		}
		if _, duplicate := seen[listener.acceptorCarrier()]; duplicate {
			return nil, ErrInvalidTunnelRuntime
		}
		seen[listener.acceptorCarrier()] = struct{}{}
		webSocket = webSocket || listener.acceptorCarrier() == carrier.KindWebSocket
		listeners = append(listeners, listener)
	}
	if webSocket && len(options.AllowedOrigins) == 0 {
		return nil, ErrInvalidTunnelRuntime
	}
	runtime := &TunnelRuntime{options: options, resources: resources, listeners: listeners}
	config := tunnelv2.DefaultConfig()
	if options.MaxPendingLegs != 0 {
		config.MaxPendingLegs = options.MaxPendingLegs
	}
	if options.MaxActivePairs != 0 {
		config.MaxActivePairs = options.MaxActivePairs
	}
	coordinator, err := tunnelv2.NewCoordinator(config, runtime.authorize)
	if err != nil {
		return nil, ErrInvalidTunnelRuntime
	}
	runtime.coordinator = coordinator
	return runtime, nil
}

func (runtime *TunnelRuntime) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, listener := range runtime.listeners {
		if listener.acceptorCarrier() == carrier.KindWebSocket {
			mux.HandleFunc(WebSocketTunnelPath, runtime.handleWebSocket)
			break
		}
	}
	return mux
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
	var wait sync.WaitGroup
	for _, listener := range runtime.listeners {
		if listener.acceptorCarrier() == carrier.KindWebSocket {
			continue
		}
		listener := listener
		wait.Add(1)
		go func() {
			defer wait.Done()
			err := listener.serve(serveCtx, func(sessionCtx context.Context, native carrier.Session) error {
				go func() { _ = runtime.serveNative(sessionCtx, native) }()
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
	for _, listener := range runtime.listeners {
		result = errors.Join(result, listener.Close())
	}
	wait.Wait()
	return result
}

func (runtime *TunnelRuntime) serveNative(ctx context.Context, native carrier.Session) error {
	if native == nil || native.Path() != carrier.PathTunnel {
		return ErrInvalidTunnelRuntime
	}
	observed, ok := native.(interface{ RemoteAddr() net.Addr })
	remote := "native"
	if ok && observed.RemoteAddr() != nil {
		remote = observed.RemoteAddr().String()
	}
	admissionCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stream, err := acceptorNativeAdmissionStream(admissionCtx, native)
	if err != nil {
		return err
	}
	leg, err := tunnelv2.NewNativeStreamLeg(native, stream)
	if err != nil {
		return err
	}
	return runtime.coordinator.Serve(context.WithValue(ctx, acceptorTransportContextKey{}, acceptorTransportContext{carrier: string(native.Kind()), remoteAddress: remote}), leg)
}

func (runtime *TunnelRuntime) handleWebSocket(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || !runtime.allowedOrigin(request) {
		http.Error(writer, "request rejected", http.StatusForbidden)
		return
	}
	connection, err := (&gorillaws.Upgrader{Subprotocols: []string{carrierws.SubprotocolTunnel}, CheckOrigin: runtime.allowedOrigin, HandshakeTimeout: 10 * time.Second}).Upgrade(writer, request, nil)
	if err != nil {
		return
	}
	leg, err := tunnelv2.NewWebSocketPendingLeg(connection, runtime.resources)
	if err != nil {
		_ = connection.Close()
		return
	}
	ctx := context.WithValue(request.Context(), acceptorTransportContextKey{}, acceptorTransportContext{carrier: "websocket", remoteAddress: request.RemoteAddr})
	if err := runtime.coordinator.Serve(ctx, leg); err != nil {
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

func (runtime *TunnelRuntime) authorize(ctx context.Context, decoded *artifactv2.DecodedRequest) (tunnelv2.Authorization, error) {
	transport, ok := ctx.Value(acceptorTransportContextKey{}).(acceptorTransportContext)
	if !ok || decoded == nil {
		return tunnelv2.Authorization{}, ErrInvalidTunnelRuntime
	}
	request, err := runtimeAuthorizationRequest(decoded, transport.carrier, transport.remoteAddress)
	if err != nil {
		return tunnelv2.Authorization{}, err
	}
	response, err := runtime.options.Authorize(ctx, request)
	if err != nil {
		return tunnelv2.Authorization{}, err
	}
	var wire struct {
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
	if err := decoder.Decode(&wire); err != nil {
		return tunnelv2.Authorization{}, ErrInvalidTunnelRuntime
	}
	if wire.Decision != "allow" {
		return tunnelv2.Authorization{}, &admissionv2.ResponseError{Status: artifactv2.AdmissionReject, Reason: wire.Reason}
	}
	if wire.CredentialID == "" || wire.LeaseID == "" || wire.ExpectedPeerEndpointInstanceID == "" || wire.ExpiresAt.IsZero() {
		return tunnelv2.Authorization{}, ErrInvalidTunnelRuntime
	}
	return tunnelv2.Authorization{
		Claims: tunnelv2.VerifiedClaims{
			CredentialID: wire.CredentialID, ChannelID: decoded.Request.ChannelID, Profile: decoded.Request.Profile,
			RendezvousGroupID: decoded.Request.RendezvousGroupID, SessionContractHash: decoded.Request.SessionContractHash,
			CandidateSetHash: decoded.Request.CandidateSetHash, ListenerAudience: decoded.Request.ListenerAudience,
			Role: decoded.Request.Role, EndpointInstanceID: decoded.Request.EndpointInstanceID,
			ExpectedPeerEndpointInstanceID: wire.ExpectedPeerEndpointInstanceID, AllowReplacement: wire.AllowReplacement,
		},
		ExpiresAt: wire.ExpiresAt,
		Lease: &tunnelRuntimeLease{release: func() {
			if runtime.options.Release != nil {
				runtime.options.Release(context.Background(), wire.LeaseID)
			}
		}},
	}, nil
}

type tunnelRuntimeLease struct {
	once    sync.Once
	release func()
}

func (lease *tunnelRuntimeLease) Release() { lease.once.Do(lease.release) }
