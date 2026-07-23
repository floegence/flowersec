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

	"github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/tunnelv2"
	gorillaws "github.com/gorilla/websocket"
)

const (
	webSocketDirectPath = "/flowersec/v2/direct"
	webSocketTunnelPath = "/flowersec/v2/tunnel"
)

type runtimeServer struct {
	config      Config
	tlsConfig   *tls.Config
	authorizer  authorizationProvider
	reasons     artifactv2.ReasonRegistry
	coordinator *tunnelv2.Coordinator
	wsResources carrierws.ResourcePolicy
	quicLimits  rawquic.Limits
	directSlots chan struct{}
	logger      *log.Logger

	mu         sync.Mutex
	closers    []io.Closer
	listenerWG sync.WaitGroup
	sessionWG  sync.WaitGroup
}

func newRuntimeServer(config Config, authorizer authorizationProvider, logger *log.Logger) (*runtimeServer, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	if authorizer == nil {
		return nil, ErrInvalidAuthorization
	}
	certificate, err := tls.LoadX509KeyPair(config.TLS.CertificateFile, config.TLS.PrivateKeyFile)
	if err != nil {
		return nil, &ConfigError{Field: "tls", Err: errors.New("unable to load certificate material")}
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	reasons := tunnelv2.DefaultReasonRegistry()
	reasons[reasonAuthorizationDenied] = struct{}{}
	reasons[reasonAuthorizationUnavailable] = struct{}{}
	for _, reason := range config.AdmissionReasons {
		reasons[reason] = struct{}{}
	}
	wsResources, err := carrierws.BindSessionResourcePolicy(carrierws.DefaultResourcePolicy(), config.MaxInboundStreams)
	if err != nil {
		return nil, &ConfigError{Field: "max_inbound_streams", Err: err}
	}
	quicLimits, err := rawquic.BindSessionLimits(rawquic.DefaultLimits(), config.MaxInboundStreams)
	if err != nil {
		return nil, &ConfigError{Field: "max_inbound_streams", Err: err}
	}
	coordinatorConfig := tunnelv2.DefaultConfig()
	coordinatorConfig.Reasons = reasons
	coordinator, err := tunnelv2.NewCoordinator(coordinatorConfig, tunnelAuthorizer(authorizer, reasons))
	if err != nil {
		return nil, err
	}
	return &runtimeServer{
		config: config, tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13,
		},
		authorizer: authorizer, reasons: reasons, coordinator: coordinator,
		wsResources: wsResources, quicLimits: quicLimits,
		directSlots: make(chan struct{}, config.MaxDirectSessions), logger: logger,
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
	directQUIC, err := runtime.listenRawQUIC(runtime.config.Listeners.RawQUIC.Direct, rawquic.ALPNDirect)
	if err != nil {
		runtime.closeListeners()
		return fmt.Errorf("listen direct raw QUIC: %w", err)
	}
	runtime.addCloser(directQUIC)
	tunnelQUIC, err := runtime.listenRawQUIC(runtime.config.Listeners.RawQUIC.Tunnel, rawquic.ALPNTunnel)
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

	errorsCh := make(chan error, 4)
	runtime.listenerWG.Add(4)
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
	runtime.sessionWG.Wait()
	if serveErr != nil && !errors.Is(serveErr, context.Canceled) && !errors.Is(serveErr, net.ErrClosed) && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
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

func (runtime *runtimeServer) listenRawQUIC(address, alpn string) (*rawquic.Listener, error) {
	tlsConfig := runtime.tlsConfig.Clone()
	tlsConfig.NextProtos = []string{alpn}
	return rawquic.Listen(address, tlsConfig, runtime.quicLimits)
}

func (runtime *runtimeServer) acceptRawQUIC(ctx context.Context, listener *rawquic.Listener) error {
	for {
		carrierSession, err := listener.Accept(ctx)
		if err != nil {
			return err
		}
		runtime.sessionWG.Add(1)
		go func() {
			defer runtime.sessionWG.Done()
			sessionContext := withAuthorizationContext(ctx, authorizationContext{carrier: carrier.KindQUIC})
			if carrierSession.Path() == carrier.PathTunnel {
				runtime.serveNativeTunnel(sessionContext, carrierSession)
				return
			}
			runtime.serveNativeDirect(sessionContext, carrierSession)
		}()
	}
}

func (runtime *runtimeServer) serveNativeDirect(ctx context.Context, carrierSession carrier.Session) {
	if !runtime.acquireDirectSlot() {
		_ = carrierSession.CloseWithError(carrier.ApplicationError{Code: 7, Reason: "capacity"})
		return
	}
	defer runtime.releaseDirectSlot()
	admissionContext, cancel := context.WithTimeout(ctx, runtime.config.admissionTimeout())
	defer cancel()
	admissionStream, err := carrierSession.AcceptStream(admissionContext)
	if err != nil {
		_ = carrierSession.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "admission failed"})
		return
	}
	var authorization *directAuthorization
	decoded, err := admissionv2.Serve(admissionContext, admissionStream, runtime.reasons, func(authorizeContext context.Context, decoded *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
		if !chosenCarrierMatches(decoded, carrier.KindQUIC) {
			return artifactv2.AdmissionResponse{}, ErrInvalidAuthorization
		}
		response, allowed, authorizeErr := authorizeDirect(authorizeContext, runtime.authorizer, decoded, runtime.reasons, runtime.config.MaxInboundStreams)
		authorization = allowed
		return response, authorizeErr
	})
	if err != nil || authorization == nil {
		_ = carrierSession.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "admission rejected"})
		return
	}
	defer authorization.Release()
	runtime.serveAuthorizedDirect(ctx, carrierSession, decoded, authorization)
}

func (runtime *runtimeServer) serveNativeTunnel(ctx context.Context, carrierSession carrier.Session) {
	admissionContext, cancel := context.WithTimeout(ctx, runtime.config.admissionTimeout())
	defer cancel()
	admissionStream, err := carrierSession.AcceptStream(admissionContext)
	if err != nil {
		_ = carrierSession.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "admission failed"})
		return
	}
	leg, err := tunnelv2.NewNativeStreamLeg(carrierSession, admissionStream)
	if err != nil {
		_ = carrierSession.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "admission failed"})
		return
	}
	if err := runtime.coordinator.Serve(ctx, leg); err != nil && ctx.Err() == nil {
		runtime.logger.Printf("tunnel raw QUIC session ended: %v", stableRuntimeError(err))
	}
}

func (runtime *runtimeServer) webSocketHandler(baseContext context.Context) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(webSocketDirectPath, func(writer http.ResponseWriter, request *http.Request) {
		runtime.handleWebSocket(baseContext, writer, request, carrierws.SubprotocolDirect)
	})
	mux.HandleFunc(webSocketTunnelPath, func(writer http.ResponseWriter, request *http.Request) {
		runtime.handleWebSocket(baseContext, writer, request, carrierws.SubprotocolTunnel)
	})
	return mux
}

func (runtime *runtimeServer) handleWebSocket(baseContext context.Context, writer http.ResponseWriter, request *http.Request, subprotocol string) {
	if request.Method != http.MethodGet || !runtime.originAllowed(request) {
		http.Error(writer, "request rejected", http.StatusForbidden)
		return
	}
	upgrader := gorillaws.Upgrader{
		Subprotocols: []string{subprotocol}, CheckOrigin: runtime.originAllowed,
		HandshakeTimeout: runtime.config.admissionTimeout(),
	}
	connection, err := upgrader.Upgrade(writer, request, nil)
	if err != nil {
		return
	}
	ctx := withAuthorizationContext(baseContext, authorizationContext{
		carrier: carrier.KindWebSocket, remoteAddress: request.RemoteAddr,
	})
	if subprotocol == carrierws.SubprotocolTunnel {
		leg, err := tunnelv2.NewWebSocketPendingLeg(connection, runtime.wsResources, carrierws.LivenessPolicy{})
		if err != nil {
			_ = connection.Close()
			return
		}
		if err := runtime.coordinator.Serve(ctx, leg); err != nil && ctx.Err() == nil {
			runtime.logger.Printf("tunnel WSS session ended: %v", stableRuntimeError(err))
		}
		return
	}
	if !runtime.acquireDirectSlot() {
		_ = connection.Close()
		return
	}
	defer runtime.releaseDirectSlot()
	admissionContext, cancel := context.WithTimeout(ctx, runtime.config.admissionTimeout())
	defer cancel()
	var authorization *directAuthorization
	decoded, err := carrierws.ServeAdmission(admissionContext, connection, runtime.reasons, func(authorizeContext context.Context, decoded *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
		if !chosenCarrierMatches(decoded, carrier.KindWebSocket) {
			return artifactv2.AdmissionResponse{}, ErrInvalidAuthorization
		}
		response, allowed, authorizeErr := authorizeDirect(authorizeContext, runtime.authorizer, decoded, runtime.reasons, runtime.config.MaxInboundStreams)
		authorization = allowed
		return response, authorizeErr
	})
	if err != nil || authorization == nil {
		_ = connection.Close()
		return
	}
	defer authorization.Release()
	carrierSession, err := carrierws.NewAfterAdmission(connection, carrierws.ServerRole, subprotocol, runtime.wsResources, carrierws.LivenessPolicy{})
	if err != nil {
		_ = connection.Close()
		return
	}
	runtime.serveAuthorizedDirect(ctx, carrierSession, decoded, authorization)
}

func (runtime *runtimeServer) webTransportHandler(baseContext context.Context, server *carrierwt.Server) http.Handler {
	mux := http.NewServeMux()
	for _, path := range []string{carrierwt.PathDirect, carrierwt.PathTunnel} {
		path := path
		mux.HandleFunc(path, func(writer http.ResponseWriter, request *http.Request) {
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
			runtime.sessionWG.Add(1)
			go func() {
				defer runtime.sessionWG.Done()
				if path == carrierwt.PathTunnel {
					runtime.serveNativeTunnel(ctx, carrierSession)
				} else {
					runtime.serveNativeDirect(ctx, carrierSession)
				}
			}()
		})
	}
	return mux
}

func (runtime *runtimeServer) serveAuthorizedDirect(ctx context.Context, carrierSession carrier.Session, decoded *artifactv2.DecodedRequest, authorization *directAuthorization) {
	contract, err := authorization.Session.contract()
	if err != nil {
		_ = carrierSession.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "session contract rejected"})
		return
	}
	config := session.Config{
		Role: session.RoleServer, Path: session.PathDirect, ChannelID: contract.ChannelID,
		SessionContractHash: contract.ContractHash, Suite: protocolv2.Suite(contract.DefaultSuite),
		PSK: contract.E2EEPSK, MaxInboundStreams: contract.MaxInboundStreams,
		IdleTimeout:            time.Duration(contract.IdleTimeoutSeconds) * time.Second,
		EstablishTimeout:       time.Duration(contract.EstablishTimeoutSeconds) * time.Second,
		RekeyPrepareTimeout:    time.Duration(contract.RekeyPrepareTimeoutSeconds) * time.Second,
		RekeyCompletionTimeout: time.Duration(contract.RekeyCompletionTimeoutSeconds) * time.Second,
		LocalAdmissionBinding:  decoded.LocalAdmissionBinding,
		PeerAdmissionBinding:   decoded.LocalAdmissionBinding,
	}
	established, err := session.Establish(ctx, carrierSession, config)
	if err != nil {
		return
	}
	defer established.Close()
	for {
		incoming, err := established.AcceptStream(ctx)
		if err != nil {
			return
		}
		runtime.sessionWG.Add(1)
		go func() {
			defer runtime.sessionWG.Done()
			runtime.bridgeDirectStream(ctx, incoming.Stream, authorization.Upstream)
		}()
	}
}

func (runtime *runtimeServer) bridgeDirectStream(ctx context.Context, stream session.ByteStream, target upstreamTarget) {
	upstream, err := (&net.Dialer{}).DialContext(ctx, target.Network, target.Address)
	if err != nil {
		_ = stream.Reset()
		return
	}
	defer upstream.Close()
	var copyWG sync.WaitGroup
	copyWG.Add(2)
	go func() {
		defer copyWG.Done()
		_, _ = io.Copy(upstream, stream)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	go func() {
		defer copyWG.Done()
		_, _ = io.Copy(stream, upstream)
		_ = stream.CloseWrite()
	}()
	copyWG.Wait()
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

func chosenCarrierMatches(decoded *artifactv2.DecodedRequest, kind carrier.Kind) bool {
	if decoded == nil {
		return false
	}
	want := artifactv2.CarrierWebSocket
	if kind == carrier.KindQUIC {
		want = artifactv2.CarrierRawQUIC
	} else if kind == carrier.KindWebTransport {
		want = artifactv2.CarrierWebTransport
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

func (runtime *runtimeServer) addCloser(closer io.Closer) {
	runtime.mu.Lock()
	runtime.closers = append(runtime.closers, closer)
	runtime.mu.Unlock()
}

func (runtime *runtimeServer) closeListeners() {
	runtime.mu.Lock()
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

func stableRuntimeError(err error) error {
	switch {
	case errors.Is(err, tunnelv2.ErrCapacity):
		return tunnelv2.ErrCapacity
	case errors.Is(err, tunnelv2.ErrPairTimeout):
		return tunnelv2.ErrPairTimeout
	case errors.Is(err, tunnelv2.ErrCredentialReplay):
		return tunnelv2.ErrCredentialReplay
	default:
		return errors.New("session failed")
	}
}
