package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v7"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/admissionv3"
	websocketadmission "github.com/floegence/flowersec/flowersec-go/v7/internal/admissionv3/websocket"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/carrier/rawquicv3"
	carrierws "github.com/floegence/flowersec/flowersec-go/v7/internal/carrier/websocketv3"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v7/internal/carrier/webtransportv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/protocolv3"
	session "github.com/floegence/flowersec/flowersec-go/v7/internal/sessionv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/transportsecurity"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/tunnelv3"
	gorillaws "github.com/gorilla/websocket"
)

const (
	webSocketDirectPath = "/flowersec/v5/direct"
	webSocketTunnelPath = "/flowersec/v5/tunnel"
)

type runtimeServer struct {
	config      Config
	tlsConfig   *tls.Config
	ingresses   []wssIngress
	endpoints   map[artifactv3.Carrier]string
	authorizer  authorizationProvider
	reasons     artifactv3.ReasonRegistry
	coordinator *tunnelv3.Coordinator
	wsResources carrierws.ResourcePolicy
	quicLimits  quicbase.Limits
	directSlots chan struct{}
	services    *directServiceHost
	logger      *log.Logger

	mu         sync.Mutex
	closing    bool
	closers    []io.Closer
	listenerWG sync.WaitGroup
	sessionWG  sync.WaitGroup
}

type wssIngress struct {
	listen, endpoint string
	certificate      tls.Certificate
}
type ingressKey struct{}

func newRuntimeServer(config Config, authorizer authorizationProvider, logger *log.Logger) (*runtimeServer, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	if authorizer == nil {
		return nil, ErrInvalidAuthorization
	}
	services, err := prepareDirectServices(config.DirectServices)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(config.TLS.CertificateFile, config.TLS.PrivateKeyFile)
	if err != nil {
		return nil, &ConfigError{Field: "tls", Err: errors.New("unable to load certificate material")}
	}
	var ingresses []wssIngress
	for _, item := range config.Listeners.WSSTunnelIngresses {
		endpoint, err := artifactv3.NormalizeTunnelEndpoint(artifactv3.CarrierWebSocket, item.Endpoint)
		if err != nil {
			return nil, err
		}
		keypair, err := tls.LoadX509KeyPair(item.TLS.CertificateFile, item.TLS.PrivateKeyFile)
		if err != nil {
			return nil, &ConfigError{Field: "listeners.wss_tunnel_ingresses.tls", Err: errors.New("unable to load certificate material")}
		}
		ingresses = append(ingresses, wssIngress{item.Listen, endpoint, keypair})
	}
	endpoints := make(map[artifactv3.Carrier]string, len(config.Listeners.TunnelEndpoints))
	for kind, raw := range config.Listeners.TunnelEndpoints {
		endpoints[kind], err = artifactv3.NormalizeTunnelEndpoint(kind, raw)
		if err != nil {
			return nil, err
		}
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	reasons := tunnelv3.DefaultReasonRegistry()
	reasons[reasonAuthorizationDenied] = struct{}{}
	reasons[reasonAuthorizationUnavailable] = struct{}{}
	for _, reason := range config.AdmissionReasons {
		reasons[reason] = struct{}{}
	}
	wsResources, err := carrierws.BindSessionResourcePolicy(carrierws.DefaultResourcePolicy(), config.MaxInboundStreams)
	if err != nil {
		return nil, &ConfigError{Field: "max_inbound_streams", Err: err}
	}
	quicLimits, err := quicbase.BindSessionLimits(quicbase.DefaultLimits(), config.MaxInboundStreams)
	if err != nil {
		return nil, &ConfigError{Field: "max_inbound_streams", Err: err}
	}
	coordinatorConfig := tunnelv3.DefaultConfig()
	coordinatorConfig.Reasons = reasons
	coordinatorConfig.AdmissionTimeout = config.admissionTimeout()
	coordinator, err := tunnelv3.NewCoordinator(coordinatorConfig, tunnelAuthorizer(authorizer, reasons))
	if err != nil {
		return nil, err
	}
	return &runtimeServer{
		config: config, ingresses: ingresses, endpoints: endpoints, tlsConfig: &tls.Config{
			Certificates:           []tls.Certificate{certificate},
			MinVersion:             tls.VersionTLS13,
			MaxVersion:             tls.VersionTLS13,
			SessionTicketsDisabled: true,
		},
		authorizer: authorizer, reasons: reasons, coordinator: coordinator,
		wsResources: wsResources, quicLimits: quicLimits,
		directSlots: make(chan struct{}, config.MaxDirectSessions), services: services, logger: logger,
	}, nil
}

func (runtime *runtimeServer) Serve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	serveContext, cancel := context.WithCancel(ctx)
	defer cancel()

	wssListener, err := net.Listen("tcp", runtime.config.Listeners.WSS)
	if err != nil {
		return fmt.Errorf("listen WSS: %w", err)
	}
	runtime.addCloser(wssListener)
	directQUIC, err := runtime.listenRawQUIC(runtime.config.Listeners.RawQUIC.Direct, rawquicv3.ALPNDirect)
	if err != nil {
		runtime.closeListeners()
		return fmt.Errorf("listen direct raw QUIC: %w", err)
	}
	runtime.addCloser(directQUIC)
	tunnelQUIC, err := runtime.listenRawQUIC(runtime.config.Listeners.RawQUIC.Tunnel, rawquicv3.ALPNTunnel)
	if err != nil {
		runtime.closeListeners()
		return fmt.Errorf("listen tunnel raw QUIC: %w", err)
	}
	runtime.addCloser(tunnelQUIC)
	webTransportPacket, err := net.ListenPacket("udp", runtime.config.Listeners.WebTransport)
	if err != nil {
		runtime.closeListeners()
		return fmt.Errorf("listen WebTransport: %w", err)
	}
	runtime.addCloser(webTransportPacket)

	webTransportServer, err := carrierwt.NewServer(runtime.tlsConfig, runtime.quicLimits, runtime.originAllowed)
	if err != nil {
		runtime.closeListeners()
		return err
	}
	runtime.addCloser(webTransportServer)
	webTransportServer.SetHandler(runtime.webTransportHandler(serveContext, webTransportServer))

	wssHTTP := &http.Server{
		Handler:           runtime.webSocketHandler(serveContext),
		ReadHeaderTimeout: runtime.config.admissionTimeout(),
		TLSConfig:         runtime.tlsConfig.Clone(),
	}
	runtime.addCloser(httpServerCloser{server: wssHTTP, timeout: runtime.config.shutdownTimeout()})
	wssTLS := tls.NewListener(wssListener, runtime.tlsConfig.Clone())
	type boundIngress struct {
		server   *http.Server
		listener net.Listener
	}
	var extra []boundIngress
	for _, ingress := range runtime.ingresses {
		listener, err := net.Listen("tcp", ingress.listen)
		if err != nil {
			runtime.closeListeners()
			return fmt.Errorf("listen WSS tunnel ingress: %w", err)
		}
		runtime.addCloser(listener)
		cfg := runtime.tlsConfig.Clone()
		cfg.Certificates = []tls.Certificate{ingress.certificate}
		ctx := context.WithValue(serveContext, ingressKey{}, ingress.endpoint)
		mux := http.NewServeMux()
		mux.HandleFunc(webSocketTunnelPath, func(w http.ResponseWriter, r *http.Request) {
			runtime.handleWebSocket(ctx, w, r, carrierws.SubprotocolTunnel)
		})
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: runtime.config.admissionTimeout(), TLSConfig: cfg}
		runtime.addCloser(httpServerCloser{server: srv, timeout: runtime.config.shutdownTimeout()})
		extra = append(extra, boundIngress{srv, tls.NewListener(listener, cfg)})
	}

	errorsCh := make(chan error, 4+len(extra))
	runtime.listenerWG.Add(4 + len(extra))
	for _, entry := range extra {
		go runtime.runListener(func() error { return entry.server.Serve(entry.listener) }, errorsCh)
	}
	go runtime.runListener(func() error { return wssHTTP.Serve(wssTLS) }, errorsCh)
	go runtime.runListener(func() error { return runtime.acceptRawQUIC(serveContext, directQUIC) }, errorsCh)
	go runtime.runListener(func() error { return runtime.acceptRawQUIC(serveContext, tunnelQUIC) }, errorsCh)
	go runtime.runListener(func() error { return webTransportServer.Serve(webTransportPacket) }, errorsCh)

	var serveErr error
	select {
	case <-ctx.Done():
		serveErr = context.Cause(ctx)
	case serveErr = <-errorsCh:
	}
	cancel()
	runtime.closeListeners()
	runtime.listenerWG.Wait()
	cleanupCtx, stopCleanup := context.WithTimeout(context.Background(), runtime.config.shutdownTimeout())
	defer stopCleanup()
	cleanupErr := runtime.waitForSessions(cleanupCtx)
	if serveErr != nil && !errors.Is(serveErr, context.Canceled) && !errors.Is(serveErr, net.ErrClosed) && !errors.Is(serveErr, http.ErrServerClosed) {
		return errors.Join(serveErr, cleanupErr)
	}
	return cleanupErr
}

func (runtime *runtimeServer) waitForSessions(cleanupCtx context.Context) error {
	sessionsDone := make(chan struct{})
	go func() {
		runtime.sessionWG.Wait()
		close(sessionsDone)
	}()
	select {
	case <-sessionsDone:
		return runtime.coordinator.WaitCleanup(cleanupCtx)
	case <-cleanupCtx.Done():
		return context.Cause(cleanupCtx)
	}
}

func (runtime *runtimeServer) runListener(serve func() error, errorsCh chan<- error) {
	defer runtime.listenerWG.Done()
	if err := serve(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		select {
		case errorsCh <- err:
		default:
		}
	}
}

func (runtime *runtimeServer) listenRawQUIC(address, alpn string) (*rawquicv3.Listener, error) {
	tlsConfig := runtime.tlsConfig.Clone()
	tlsConfig.NextProtos = []string{alpn}
	return rawquicv3.Listen(address, tlsConfig, runtime.quicLimits)
}

func (runtime *runtimeServer) acceptRawQUIC(ctx context.Context, listener *rawquicv3.Listener) error {
	for {
		carrierSession, err := listener.Accept(ctx)
		if err != nil {
			return err
		}
		deadline := time.Now().Add(runtime.config.admissionTimeout())
		if !runtime.beginSession() {
			_ = carrierSession.CloseWithError(carrier.ApplicationError{Reason: "runtime closed"})
			return context.Canceled
		}
		go func() {
			defer runtime.sessionWG.Done()
			sessionContext := withAuthorizationContext(ctx, authorizationContext{
				carrier: carrier.KindRawQUIC, remoteAddress: carrierSession.RemoteAddr().String(),
			})
			if carrierSession.Path() == carrier.PathTunnel {
				runtime.serveRawQUICTunnel(sessionContext, carrierSession, deadline)
				return
			}
			runtime.serveRawQUICDirect(sessionContext, carrierSession, deadline)
		}()
	}
}

func (runtime *runtimeServer) serveRawQUICDirect(ctx context.Context, carrierSession *rawquicv3.Session, deadline time.Time) {
	runtime.serveNativeDirect(ctx, carrierSession, deadline, func(admissionContext context.Context) (carrier.Stream, error) {
		return rawquicv3.AcceptAdmissionStream(admissionContext, carrierSession)
	})
}

func (runtime *runtimeServer) serveWebTransportDirect(ctx context.Context, carrierSession *carrierwt.Session, deadline time.Time) {
	runtime.serveNativeDirect(ctx, carrierSession, deadline, func(admissionContext context.Context) (carrier.Stream, error) {
		return carrierwt.OpenAdmissionStream(admissionContext, carrierSession)
	})
}

func (runtime *runtimeServer) serveNativeDirect(
	ctx context.Context,
	carrierSession carrier.Session,
	deadline time.Time,
	openAdmission func(context.Context) (carrier.Stream, error),
) {
	if !runtime.acquireDirectSlot() {
		_ = carrierSession.CloseWithError(carrier.ApplicationError{Code: 7, Reason: "capacity"})
		return
	}
	defer runtime.releaseDirectSlot()
	admissionContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	admissionStream, err := openAdmission(admissionContext)
	if err != nil {
		_ = carrierSession.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "admission failed"})
		return
	}
	var authorization *directAuthorization
	decoded, err := admissionv3.Serve(admissionContext, admissionStream, runtime.reasons, func(authorizeContext context.Context, decoded *artifactv3.DecodedRequest) (artifactv3.AdmissionResponse, error) {
		if !chosenCarrierMatches(decoded, carrierSession.Kind()) {
			return artifactv3.AdmissionResponse{}, ErrInvalidAuthorization
		}
		response, allowed, authorizeErr := authorizeDirect(authorizeContext, runtime.authorizer, decoded, runtime.reasons, runtime.config.MaxInboundStreams)
		authorization = allowed
		return response, authorizeErr
	})
	if authorization != nil {
		defer runtime.releaseDirectAuthorization(ctx, authorization)
	}
	if err != nil || authorization == nil {
		_ = carrierSession.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "admission rejected"})
		return
	}
	runtime.serveAuthorizedDirect(ctx, admissionContext, carrierSession, decoded, authorization)
}

func (runtime *runtimeServer) serveRawQUICTunnel(ctx context.Context, carrierSession *rawquicv3.Session, deadline time.Time) {
	state := carrierSession.TLSState()
	ctx = transportsecurity.WithTunnelIngress(ctx, artifactv3.CarrierRawQUIC, runtime.endpoints[artifactv3.CarrierRawQUIC], &state)
	runtime.serveNativeTunnel(ctx, carrierSession, deadline, func(admissionContext context.Context) (carrier.Stream, error) {
		return rawquicv3.AcceptAdmissionStream(admissionContext, carrierSession)
	})
}

func (runtime *runtimeServer) serveWebTransportTunnel(ctx context.Context, carrierSession *carrierwt.Session, deadline time.Time) {
	state := carrierSession.TLSState()
	ctx = transportsecurity.WithTunnelIngress(ctx, artifactv3.CarrierWebTransport, runtime.endpoints[artifactv3.CarrierWebTransport], &state)
	runtime.serveNativeTunnel(ctx, carrierSession, deadline, func(admissionContext context.Context) (carrier.Stream, error) {
		return carrierwt.OpenAdmissionStream(admissionContext, carrierSession)
	})
}

func (runtime *runtimeServer) serveNativeTunnel(
	ctx context.Context,
	carrierSession carrier.Session,
	deadline time.Time,
	openAdmission func(context.Context) (carrier.Stream, error),
) {
	leg, err := tunnelv3.NewPendingNativeLeg(carrierSession, openAdmission)
	if err != nil {
		_ = carrierSession.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "admission failed"})
		return
	}
	report := func(err error) {
		runtime.reportTunnelEnd(ctx, string(carrierSession.Kind()), err)
	}
	if carrierSession.Kind() == carrier.KindRawQUIC {
		report(runtime.coordinator.AdmitUntil(ctx, leg, deadline, report))
	} else {
		report(runtime.coordinator.ServeUntil(ctx, leg, deadline))
	}
}

func (runtime *runtimeServer) webSocketHandler(baseContext context.Context) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(webSocketDirectPath, func(writer http.ResponseWriter, request *http.Request) {
		runtime.handleWebSocket(baseContext, writer, request, carrierws.SubprotocolDirect)
	})
	if endpoint := runtime.endpoints[artifactv3.CarrierWebSocket]; endpoint != "" {
		ctx := context.WithValue(baseContext, ingressKey{}, endpoint)
		mux.HandleFunc(webSocketTunnelPath, func(writer http.ResponseWriter, request *http.Request) {
			runtime.handleWebSocket(ctx, writer, request, carrierws.SubprotocolTunnel)
		})
	}
	return mux
}

func (runtime *runtimeServer) handleWebSocket(baseContext context.Context, writer http.ResponseWriter, request *http.Request, subprotocol string) {
	deadline := time.Now().Add(runtime.config.admissionTimeout())
	// Track the handler before it can hijack the connection. A registered
	// tunnel leg transfers to the coordinator, which shutdown also drains.
	if !runtime.beginSession() {
		http.Error(writer, "runtime closed", http.StatusServiceUnavailable)
		return
	}
	defer runtime.sessionWG.Done()
	if request.Method != http.MethodGet || !runtime.originAllowed(request) || carrierws.ValidateServerRequest(request) != nil {
		http.Error(writer, "request rejected", http.StatusForbidden)
		return
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		http.Error(writer, "admission timed out", http.StatusRequestTimeout)
		return
	}
	upgrader := gorillaws.Upgrader{
		Subprotocols: []string{subprotocol}, CheckOrigin: runtime.originAllowed,
		HandshakeTimeout: remaining,
	}
	connection, err := upgrader.Upgrade(writer, request, nil)
	if err != nil {
		return
	}
	ctx := withAuthorizationContext(baseContext, authorizationContext{
		carrier: carrier.KindWebSocket, remoteAddress: request.RemoteAddr,
	})
	if subprotocol == carrierws.SubprotocolTunnel {
		endpoint, _ := baseContext.Value(ingressKey{}).(string)
		ctx = transportsecurity.WithTunnelIngress(ctx, artifactv3.CarrierWebSocket, endpoint, request.TLS)
		leg, err := tunnelv3.NewWebSocketPendingLeg(connection, runtime.wsResources)
		if err != nil {
			_ = connection.Close()
			return
		}
		report := func(err error) {
			runtime.reportTunnelEnd(ctx, "WSS", err)
		}
		report(runtime.coordinator.AdmitUntil(ctx, leg, deadline, report))
		return
	}
	if !runtime.acquireDirectSlot() {
		_ = connection.Close()
		return
	}
	defer runtime.releaseDirectSlot()
	admissionContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var authorization *directAuthorization
	decoded, err := websocketadmission.Serve(admissionContext, connection, runtime.reasons, func(authorizeContext context.Context, decoded *artifactv3.DecodedRequest) (artifactv3.AdmissionResponse, error) {
		if !chosenCarrierMatches(decoded, carrier.KindWebSocket) {
			return artifactv3.AdmissionResponse{}, ErrInvalidAuthorization
		}
		response, allowed, authorizeErr := authorizeDirect(authorizeContext, runtime.authorizer, decoded, runtime.reasons, runtime.config.MaxInboundStreams)
		authorization = allowed
		return response, authorizeErr
	})
	if authorization != nil {
		defer runtime.releaseDirectAuthorization(ctx, authorization)
	}
	if err != nil || authorization == nil {
		_ = connection.Close()
		return
	}
	carrierSession, err := carrierws.NewAfterAdmission(connection, carrierws.ServerRole, subprotocol, runtime.wsResources)
	if err != nil {
		_ = connection.Close()
		return
	}
	runtime.serveAuthorizedDirect(ctx, admissionContext, carrierSession, decoded, authorization)
}

func (runtime *runtimeServer) webTransportHandler(baseContext context.Context, server *carrierwt.Server) http.Handler {
	mux := http.NewServeMux()
	for _, path := range []string{carrierwt.PathDirect, carrierwt.PathTunnel} {
		if path == carrierwt.PathTunnel && runtime.endpoints[artifactv3.CarrierWebTransport] == "" {
			continue
		}
		path := path
		mux.HandleFunc(path, func(writer http.ResponseWriter, request *http.Request) {
			deadline := time.Now().Add(runtime.config.admissionTimeout())
			if !runtime.beginSession() {
				http.Error(writer, "runtime closed", http.StatusServiceUnavailable)
				return
			}
			defer runtime.sessionWG.Done()
			if request.Method != http.MethodConnect || !runtime.originAllowed(request) {
				http.Error(writer, "request rejected", http.StatusForbidden)
				return
			}
			carrierSession, err := server.Upgrade(writer, request)
			if err != nil {
				return
			}
			ctx := withAuthorizationContext(baseContext, authorizationContext{
				carrier: carrier.KindWebTransport, remoteAddress: request.RemoteAddr,
			})
			if path == carrierwt.PathTunnel {
				runtime.serveWebTransportTunnel(ctx, carrierSession, deadline)
			} else {
				runtime.serveWebTransportDirect(ctx, carrierSession, deadline)
			}
		})
	}
	return mux
}

func (runtime *runtimeServer) serveAuthorizedDirect(ctx, establishCtx context.Context, carrierSession carrier.Session, decoded *artifactv3.DecodedRequest, authorization *directAuthorization) {
	contract, err := authorization.Session.contract()
	if err != nil {
		_ = carrierSession.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "session contract rejected"})
		return
	}
	config := session.Config{
		Role: session.RoleServer, Path: session.PathDirect, ChannelID: contract.ChannelID,
		SessionContractHash: contract.ContractHash, Suite: protocolv3.Suite(contract.DefaultSuite),
		PSK: contract.E2EEPSK, MaxInboundStreams: contract.MaxInboundStreams,
		IdleTimeout:            time.Duration(contract.IdleTimeoutSeconds) * time.Second,
		EstablishTimeout:       time.Duration(contract.EstablishTimeoutSeconds) * time.Second,
		RekeyPrepareTimeout:    time.Duration(contract.RekeyPrepareTimeoutSeconds) * time.Second,
		RekeyCompletionTimeout: time.Duration(contract.RekeyCompletionTimeoutSeconds) * time.Second,
		LocalAdmissionBinding:  decoded.LocalAdmissionBinding,
		PeerAdmissionBinding:   decoded.LocalAdmissionBinding,
	}
	grant := directMethodGrant{channel: contract.ChannelID, target: authorization.Upstream}
	if runtime.services != nil {
		runtime.services.installRPC(&config, grant)
	}
	established, err := session.Establish(establishCtx, carrierSession, config)
	if err != nil {
		_ = carrierSession.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "session establishment failed"})
		return
	}
	streamCtx, stopStreams := context.WithCancel(ctx)
	var bridges sync.WaitGroup
	defer func() {
		stopStreams()
		_ = established.Close()
		bridges.Wait()
		if draining, ok := established.(interface{ WaitCleanup(context.Context) error }); ok {
			_ = draining.WaitCleanup(context.Background())
		}
	}()
	for {
		incoming, err := established.AcceptStream(ctx)
		if err != nil {
			return
		}
		if runtime.services != nil {
			runtime.services.dispatchStream(streamCtx, grant, incoming, &bridges)
			continue
		}
		bridges.Go(func() {
			runtime.bridgeDirectStream(streamCtx, incoming.Stream, authorization.Upstream)
		})
	}
}

func (runtime *runtimeServer) releaseDirectAuthorization(parent context.Context, authorization *directAuthorization) {
	if authorization == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), runtime.config.admissionTimeout())
	defer cancel()
	authorization.ReleaseContext(ctx)
}

func (runtime *runtimeServer) bridgeDirectStream(ctx context.Context, stream session.ByteStream, target upstreamTarget) {
	upstream, err := (&net.Dialer{}).DialContext(ctx, target.Network, target.Address)
	if err != nil {
		_ = stream.Reset()
		return
	}
	tcp, ok := upstream.(*net.TCPConn)
	if !ok {
		_ = upstream.Close()
		_ = stream.Reset()
		return
	}
	_ = flowersec.RelayStreams(ctx, stream, tcp)
}

func (runtime *runtimeServer) originAllowed(request *http.Request) bool {
	origin := request.Header.Get("Origin")
	for _, allowed := range runtime.config.AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

func chosenCarrierMatches(decoded *artifactv3.DecodedRequest, kind carrier.Kind) bool {
	if decoded == nil {
		return false
	}
	want := artifactv3.CarrierWebSocket
	if kind == carrier.KindRawQUIC {
		want = artifactv3.CarrierRawQUIC
	} else if kind == carrier.KindWebTransport {
		want = artifactv3.CarrierWebTransport
	} else if kind != carrier.KindWebSocket {
		return false
	}
	for _, candidate := range decoded.Request.Candidates {
		if candidate.ID == decoded.Request.ChosenCandidateID {
			return candidate.Carrier == want
		}
	}
	return false
}

func (runtime *runtimeServer) acquireDirectSlot() bool {
	select {
	case runtime.directSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (runtime *runtimeServer) releaseDirectSlot() { <-runtime.directSlots }

func (runtime *runtimeServer) beginSession() bool {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closing {
		return false
	}
	runtime.sessionWG.Add(1)
	return true
}

func (runtime *runtimeServer) addCloser(closer io.Closer) {
	runtime.mu.Lock()
	runtime.closers = append(runtime.closers, closer)
	runtime.mu.Unlock()
}

func (runtime *runtimeServer) closeListeners() {
	runtime.mu.Lock()
	runtime.closing = true
	closers := runtime.closers
	runtime.closers = nil
	runtime.mu.Unlock()
	for index := len(closers) - 1; index >= 0; index-- {
		_ = closers[index].Close()
	}
}

type httpServerCloser struct {
	server  *http.Server
	timeout time.Duration
}

func (closer httpServerCloser) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), closer.timeout)
	defer cancel()
	return closer.server.Shutdown(ctx)
}

func (runtime *runtimeServer) reportTunnelEnd(ctx context.Context, transport string, err error) {
	if err != nil && ctx.Err() == nil && !normalTunnelClose(err) {
		runtime.logger.Printf("tunnel %s session ended: %v", transport, stableRuntimeError(err))
	}
}

// Bridge joins the close reason with cleanup errors. A cleanup failure must still be reported.
func normalTunnelClose(err error) bool {
	if err == tunnelv3.ErrControlClosed {
		return true
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return false
	}
	causes := joined.Unwrap()
	for _, cause := range causes {
		if !normalTunnelClose(cause) {
			return false
		}
	}
	return len(causes) > 0
}

func stableRuntimeError(err error) error {
	switch {
	case errors.Is(err, tunnelv3.ErrCapacity):
		return tunnelv3.ErrCapacity
	case errors.Is(err, tunnelv3.ErrPairTimeout):
		return tunnelv3.ErrPairTimeout
	case errors.Is(err, tunnelv3.ErrCredentialReplay):
		return tunnelv3.ErrCredentialReplay
	default:
		return errors.New("session failed")
	}
}
