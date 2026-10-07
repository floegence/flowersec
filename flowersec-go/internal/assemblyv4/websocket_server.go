package assemblyv4

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// WebSocketServerConfig fixes one canonical direct network route and one
// certificate chain before listening. Roots independently validates the local
// chain in CA mode; signed pin mode uses only its exact authorized leaf DER.
// The private signing key and root certificates are admitted shared host
// dependencies. ProviderBytesPerConnection includes the qualified TLS/HTTP
// parser and native runtime allowance, separately from the message provider.
type WebSocketServerConfig struct {
	AcceptedRouteCapacity uint16
	// Tunnel bindings name the logical endpoint and actual local relay role.
	Side                       protocolv4.Direction
	Relay                      bool
	Deployment                 protocolv4.RelayDeploymentBinding
	Root                       *resourcev4.Root
	Clock                      *timev4.Clock
	Route                      []byte
	Certificate                tls.Certificate
	Roots                      *x509.CertPool
	Handler                    http.Handler
	Connections                uint16
	HeaderBytes                uint32
	HeaderTimeout, IdleTimeout time.Duration
	RuntimeBytes               uint64
	ProviderBytesPerConnection uint64
}

type webSocketServerSlot struct {
	connection  *serverWebSocketConn
	generation  uint64
	pending     bool
	httpEnded   bool
	socketEnded bool
	handlers    uint32
}

type WebSocketServer struct {
	acceptedRoutes           acceptedRoutePolicies
	mu                       sync.Mutex
	c                        WebSocketServerConfig
	reservation, shared      resourcev4.Reference
	document                 *protocolv4.Document
	routeBinding             protocolv4.CarrierRouteBinding
	leg                      protocolv4.Value
	tunnel                   bool
	subprotocol              string
	policy                   tlspolicy.Policy
	certificates             []*x509.Certificate
	tls                      *tls.Config
	http                     *http.Server
	listener                 *net.TCPListener
	slots                    []webSocketServerSlot
	generation               uint64
	policies                 uint16
	sampling                 uint32
	host, path               string
	port                     uint16
	started, running, closed bool
	closing, cleaned         bool
	wake, stop, done         chan struct{}
	routeScratch             [webSocketFactoryRouteBytes]byte
}

func WebSocketServerCharge(c WebSocketServerConfig) (resourcev4.Vector, error) {
	if c.Root == nil || c.Clock == nil || c.Handler == nil || c.Connections == 0 || c.Connections > 1024 ||
		len(c.Route) == 0 || len(c.Route) > webSocketFactoryRouteBytes || c.RuntimeBytes == 0 || c.ProviderBytesPerConnection == 0 ||
		c.HeaderBytes < 1024 || c.HeaderBytes > 65536 || c.HeaderTimeout <= 0 || c.IdleTimeout <= 0 ||
		c.Certificate.PrivateKey == nil || len(c.Certificate.Certificate) == 0 || len(c.Certificate.Certificate) > 16 ||
		len(c.Certificate.OCSPStaple) != 0 || len(c.Certificate.SignedCertificateTimestamps) != 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	var certBytes uint64
	for _, der := range c.Certificate.Certificate {
		if len(der) == 0 || len(der) > 65536 {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		certBytes += uint64(len(der))
	}
	if certBytes > 262144 || c.ProviderBytesPerConnection > (math.MaxUint64-certBytes*16)/uint64(c.Connections) {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	alternateBytes, err := acceptedRoutePoliciesBacking(c.AcceptedRouteCapacity, webSocketFactoryRouteBytes, webSocketFactoryRouteNodes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	decoder, err := protocolv4.DecoderBackingBytes(webSocketFactoryRouteBytes, webSocketFactoryRouteNodes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	metadata := uint64(unsafe.Sizeof(WebSocketServer{})) + alternateBytes + decoder + certBytes*16 + uint64(c.Connections)*(uint64(unsafe.Sizeof(webSocketServerSlot{}))+uint64(unsafe.Sizeof(serverWebSocketConn{}))) + 16384
	return (resourcev4.Vector{resourcev4.SDKBytes: metadata,
		resourcev4.ProviderBytes: uint64(c.Connections) * c.ProviderBytesPerConnection,
		resourcev4.Items:         1 + uint64(c.Connections), resourcev4.Tasks: 1 + 2*uint64(c.Connections),
		resourcev4.WorkSlots: 1 + uint64(c.Connections), resourcev4.Timers: 2 * uint64(c.Connections),
		resourcev4.Connections: uint64(c.Connections), resourcev4.TLSHandshakes: uint64(c.Connections), resourcev4.NativeHandles: 1 + uint64(c.Connections)}).
		Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewWebSocketServer(c WebSocketServerConfig, reservation, dependencies resourcev4.Reference) (_ *WebSocketServer, err error) {
	charge, err := WebSocketServerCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckRoot(c.Root); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	s := &WebSocketServer{c: c, reservation: owned, shared: shared, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	constructed := false
	defer func() {
		if !constructed {
			s.Close()
		}
	}()
	s.acceptedRoutes, err = newAcceptedRoutePolicies(c.AcceptedRouteCapacity, webSocketFactoryRouteBytes, webSocketFactoryRouteNodes)
	if err != nil {
		return nil, err
	}
	decoder, err := protocolv4.NewDecoder(webSocketFactoryRouteBytes, webSocketFactoryRouteNodes)
	if err != nil {
		return nil, err
	}
	s.document, err = decoder.DecodeMap(c.Route, "Route", protocolv4.DecodeContext{})
	if err != nil {
		return nil, err
	}
	side := protocolv4.ServerToClient
	if c.Deployment != (protocolv4.RelayDeploymentBinding{}) {
		side = c.Side
	} else if c.Side != 0 || c.Relay {
		return nil, resourcev4.ErrConfiguration
	}
	leg, binding, err := s.document.BindCarrierRoute(side, c.Relay, true, 1, c.Deployment)
	if err != nil {
		return nil, err
	}
	pathKind, _ := s.document.Root().Named("Route", "path_kind").Uint()
	s.leg, s.routeBinding, s.tunnel = leg, binding, pathKind == 1
	s.subprotocol, _ = leg.Named("Leg", "subprotocol").Text()
	wantPath, wantProtocol := "/flowersec/v4/direct", websocket.SubprotocolDirect
	if s.tunnel {
		wantPath, wantProtocol = "/flowersec/v4/tunnel", websocket.SubprotocolTunnel
	}
	alpn, _ := leg.Named("Leg", "alpn").Text()
	legPath, _ := leg.Named("Leg", "path").Text()
	if alpn != "http/1.1" || legPath != wantPath || s.subprotocol != wantProtocol {
		return nil, protocolv4.CBORFailure("carrier_binding_invalid")
	}
	s.host, _ = leg.Named("Leg", "host").Text()
	s.path, _ = leg.Named("Leg", "path").Text()
	port, _ := leg.Named("Leg", "port").Uint()
	s.port = uint16(port)
	s.policy, err = tlspolicy.Capture(leg.Named("Leg", "tls_policy"))
	if err != nil || s.policy.RequiresRoots() != (c.Roots != nil) {
		return nil, resourcev4.ErrConfiguration
	}
	if c.Roots != nil {
		s.c.Roots = c.Roots.Clone()
	}
	certificate := tls.Certificate{PrivateKey: c.Certificate.PrivateKey, Certificate: make([][]byte, len(c.Certificate.Certificate))}
	s.certificates = make([]*x509.Certificate, len(certificate.Certificate))
	for index, der := range c.Certificate.Certificate {
		certificate.Certificate[index] = bytes.Clone(der)
		s.certificates[index], err = x509.ParseCertificate(certificate.Certificate[index])
		if err != nil {
			return nil, err
		}
	}
	certificate.Leaf = s.certificates[0]
	s.c.Route, s.c.Certificate = nil, tls.Certificate{}
	if err = s.checkCertificate(); err != nil {
		return nil, err
	}
	s.tls = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"},
		Certificates: []tls.Certificate{certificate}, SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.Version != tls.VersionTLS13 || state.DidResume {
				return websocket.ErrTLSHandshake
			}
			return s.checkCertificate()
		}}
	s.slots = make([]webSocketServerSlot, c.Connections)
	s.http = &http.Server{Handler: http.HandlerFunc(s.serveHTTP), MaxHeaderBytes: int(c.HeaderBytes),
		ReadHeaderTimeout: c.HeaderTimeout, ReadTimeout: c.HeaderTimeout, WriteTimeout: c.HeaderTimeout,
		IdleTimeout: c.IdleTimeout, ConnContext: s.connectionContext, ConnState: s.connectionState}
	constructed = true
	return s, nil
}

func (s *WebSocketServer) checkCertificate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkCertificateLocked()
}

// The caller keeps the original server gate on entry and return. A blocked
// host clock retains server backing but cannot prevent Close from sealing it.
func (s *WebSocketServer) sampleLocked() (timev4.Sample, error) {
	if s.closed {
		return timev4.Sample{}, resourcev4.ErrClosed
	}
	if s.sampling == math.MaxUint32 {
		return timev4.Sample{}, resourcev4.ErrCapacity
	}
	clock := s.c.Clock
	s.sampling++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.sampling--
		s.cleanupLocked()
	}()
	return clock.Sample()
}

func (s *WebSocketServer) checkCertificateLocked() error {
	if s.closed {
		return resourcev4.ErrClosed
	}
	if err := s.reservation.Check(); err != nil {
		return err
	}
	if err := s.shared.Check(); err != nil {
		return err
	}
	now, err := s.sampleLocked()
	if s.closed {
		return resourcev4.ErrClosed
	}
	if err != nil {
		return err
	}
	if err = s.reservation.CheckSameEnvironment(s.shared); err != nil {
		return err
	}
	if now, err = s.c.Clock.RefreshSample(now); err != nil {
		return err
	}
	policy, err := s.policy.Prepare(now.Interval)
	if err != nil {
		return err
	}
	// This checks the server's own immutable chain and signed policy. Actual
	// TLS completion is separately observed on the native HTTP request below.
	_, err = policy.Verify(tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: s.certificates}, s.host, s.c.Roots, now.Interval)
	return err
}

type webSocketServerContextKey struct{}

func (s *WebSocketServer) connectionContext(ctx context.Context, connection net.Conn) context.Context {
	if c := originalServerConnection(connection); c != nil && c.server == s {
		return context.WithValue(ctx, webSocketServerContextKey{}, c)
	}
	return ctx
}

func originalServerConnection(connection net.Conn) *serverWebSocketConn {
	if native, ok := connection.(*tls.Conn); ok {
		original, _ := native.NetConn().(*serverWebSocketConn)
		return original
	}
	return nil
}

func (s *WebSocketServer) connectionState(connection net.Conn, state http.ConnState) {
	if state != http.StateClosed && state != http.StateHijacked {
		return
	}
	c := originalServerConnection(connection)
	if c == nil || c.server != s {
		return
	}
	s.mu.Lock()
	if slot := c.slotLocked(); slot != nil {
		slot.httpEnded = true
		s.releaseConnectionLocked(c.index)
	}
	s.mu.Unlock()
}

func (s *WebSocketServer) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	connection, _ := request.Context().Value(webSocketServerContextKey{}).(*serverWebSocketConn)
	s.mu.Lock()
	if connection == nil || connection.server != s || connection.slotLocked() == nil || s.closed {
		s.mu.Unlock()
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	connection.slotLocked().handlers++
	handler := s.c.Handler
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if slot := connection.slotLocked(); slot != nil {
			slot.handlers--
			s.releaseConnectionLocked(connection.index)
		}
		s.mu.Unlock()
	}()
	if err := s.checkRequest(request); err != nil {
		writer.Header().Set("Connection", "close")
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	handler.ServeHTTP(writer, request)
}

func (s *WebSocketServer) checkRequest(r *http.Request) error {
	if r == nil || r.Method != http.MethodGet || r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.TLS == nil || r.TLS.DidResume {
		return websocket.ErrEndpoint
	}
	connection, _ := r.Context().Value(webSocketServerContextKey{}).(*serverWebSocketConn)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || connection == nil || connection.server != s || connection.slotLocked() == nil {
		return resourcev4.ErrClosed
	}
	if err := s.checkCertificateLocked(); err != nil {
		return err
	}
	if connection.slotLocked() == nil {
		return resourcev4.ErrClosed
	}
	endpoint, err := websocket.ObserveAcceptedEndpoint(r, s.subprotocol)
	if err != nil || !endpoint.TLS13 || endpoint.Host != s.host || endpoint.Port != s.port || endpoint.Path != s.path || !endpoint.Local.IsValid() || endpoint.Local.Port() != s.port {
		return websocket.ErrEndpoint
	}
	if address, err := netip.ParseAddr(s.host); err == nil && address != endpoint.Local.Addr() {
		return websocket.ErrEndpoint
	}
	origin := s.leg.Named("Leg", "origin_policy")
	if origin.Encoded() == nil {
		if endpoint.OriginPresent {
			return websocket.ErrEndpoint
		}
		return nil
	}
	if !endpoint.OriginPresent {
		allowed, _ := origin.Named("OriginPolicy", "allow_absent").Bool()
		if allowed {
			return nil
		}
		return websocket.ErrEndpoint
	}
	values := origin.Named("OriginPolicy", "origins")
	for index := range values.Len() {
		allowed, _ := values.Index(index).Text()
		if allowed == endpoint.Origin {
			return nil
		}
	}
	return websocket.ErrEndpoint
}

func (s *WebSocketServer) checkAcceptedRoute(endpoint protocolv4.AcceptedWebSocketEndpoint, artifact *protocolv4.SignedMap, index uint64, policy protocolv4.HelloPolicy) error {
	if artifact == nil || s.tunnel {
		return resourcev4.ErrConfiguration
	}
	if err := artifact.CheckAcceptedWebSocket(index, endpoint, policy); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return resourcev4.ErrClosed
	}
	if err := s.checkCertificateLocked(); err != nil {
		return err
	}
	route, _, err := artifact.CopyCandidateRoute(index, s.routeScratch[:])
	if err != nil {
		return err
	}
	if !bytes.Equal(route, s.document.Bytes()) {
		now, err := s.sampleLocked()
		if err != nil {
			return err
		}
		return s.acceptedRoutes.check(route, s.certificates, s.host, s.c.Roots, now.Interval)
	}
	return nil
}

// UpgradePolicy is valid only on this server's original HTTP connection. Its
// closure remains backed by the server's connection slot until socket cleanup.
func (s *WebSocketServer) UpgradePolicy() websocket.UpgradeConfig {
	if s == nil {
		return websocket.UpgradeConfig{}
	}
	return websocket.UpgradeConfig{Subprotocol: s.subprotocol, CheckPolicy: s.checkRequest, CheckAcceptedRoute: s.checkAcceptedRoute}
}

func (s *WebSocketServer) borrowPolicy(environment resourcev4.Reference) (resourcev4.Reference, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return resourcev4.Reference{}, resourcev4.ErrClosed
	}
	if err := s.reservation.CheckSameEnvironment(environment); err != nil {
		return resourcev4.Reference{}, err
	}
	if s.policies >= s.c.Connections {
		return resourcev4.Reference{}, resourcev4.ErrCapacity
	}
	ref, err := s.reservation.Borrow()
	if err == nil {
		s.policies++
	}
	return ref, err
}

func (s *WebSocketServer) releasePolicy() {
	s.mu.Lock()
	s.policies--
	s.cleanupLocked()
	s.mu.Unlock()
}

// Serve takes exclusive ownership of a native TCP listener only after validating
// its fixed port. It serves once and closes accepted sockets when it exits.
func (s *WebSocketServer) Serve(listener *net.TCPListener) error {
	if s == nil || listener == nil {
		return resourcev4.ErrConfiguration
	}
	address, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil || address.Port() != s.port {
		return websocket.ErrEndpoint
	}
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return resourcev4.ErrClosed
	}
	s.started, s.running, s.listener = true, true, listener
	s.mu.Unlock()
	err = s.http.Serve(&webSocketServerListener{server: s, listener: listener})
	s.Close()
	s.mu.Lock()
	s.running = false
	s.cleanupLocked()
	s.mu.Unlock()
	return err
}

func (s *WebSocketServer) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed, s.closing = true, true
	close(s.stop)
	server, listener := s.http, s.listener
	s.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	if server != nil {
		_ = server.Close()
	}
	for index := 0; ; index++ {
		s.mu.Lock()
		if index >= len(s.slots) {
			s.mu.Unlock()
			break
		}
		connection := s.slots[index].connection
		s.mu.Unlock()
		if connection != nil {
			_ = connection.Close()
		}
	}
	s.mu.Lock()
	s.closing = false
	s.cleanupLocked()
	s.mu.Unlock()
}

func (s *WebSocketServer) WaitCleanup(ctx context.Context) error {
	if s == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *WebSocketServer) releaseConnectionLocked(index int) {
	slot := &s.slots[index]
	if !slot.pending && slot.connection != nil && slot.httpEnded && slot.socketEnded && slot.handlers == 0 {
		*slot = webSocketServerSlot{}
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
	s.cleanupLocked()
}

func (s *WebSocketServer) cleanupLocked() {
	if s.cleaned || !s.closed || s.closing || s.running || s.policies != 0 || s.sampling != 0 {
		return
	}
	for _, slot := range s.slots {
		if slot.pending || slot.connection != nil {
			return
		}
	}
	s.cleaned = true
	if s.document != nil {
		s.acceptedRoutes.release()
		s.document.Release()
		s.document = nil
	}
	s.c, s.tls, s.certificates = WebSocketServerConfig{}, nil, nil
	s.slots, s.http = nil, nil
	s.shared.Release()
	s.reservation.Release()
	close(s.done)
}

type webSocketServerListener struct {
	server   *WebSocketServer
	listener *net.TCPListener
}

func (l *webSocketServerListener) Addr() net.Addr { return l.listener.Addr() }
func (l *webSocketServerListener) Close() error   { return l.listener.Close() }

func (l *webSocketServerListener) Accept() (net.Conn, error) {
	s := l.server
	index := -1
	for index < 0 {
		s.mu.Lock()
		if s.closed || s.generation == math.MaxUint64 {
			s.mu.Unlock()
			return nil, net.ErrClosed
		}
		for i := range s.slots {
			if s.slots[i].connection == nil && !s.slots[i].pending {
				index = i
				s.generation++
				s.slots[i] = webSocketServerSlot{pending: true, generation: s.generation}
				break
			}
		}
		s.mu.Unlock()
		if index < 0 {
			select {
			case <-s.stop:
				return nil, net.ErrClosed
			case <-s.wake:
			}
		}
	}
	connection, err := l.listener.AcceptTCP()
	s.mu.Lock()
	s.slots[index].pending = false
	if err != nil {
		s.slots[index] = webSocketServerSlot{}
		s.cleanupLocked()
		s.mu.Unlock()
		return nil, err
	}
	if s.closed {
		_ = connection.Close()
		s.slots[index] = webSocketServerSlot{}
		s.cleanupLocked()
		s.mu.Unlock()
		return nil, net.ErrClosed
	}
	wrapped := &serverWebSocketConn{TCPConn: connection, server: s, index: index, generation: s.slots[index].generation}
	s.slots[index].connection = wrapped
	secured := tls.Server(wrapped, s.tls)
	s.mu.Unlock()
	return secured, nil
}

type serverWebSocketConn struct {
	*net.TCPConn
	server     *WebSocketServer
	index      int
	generation uint64
	once       sync.Once
	err        error
}

func (c *serverWebSocketConn) slotLocked() *webSocketServerSlot {
	if c.index < 0 || c.index >= len(c.server.slots) {
		return nil
	}
	slot := &c.server.slots[c.index]
	if slot.connection != c || slot.generation != c.generation {
		return nil
	}
	return slot
}

func (c *serverWebSocketConn) Close() error {
	c.once.Do(func() {
		c.err = c.TCPConn.Close()
		c.server.mu.Lock()
		if slot := c.slotLocked(); slot != nil {
			slot.socketEnded = true
			c.server.releaseConnectionLocked(c.index)
		}
		c.server.mu.Unlock()
	})
	return c.err
}

// Address identifies the immutable public HTTP authority, never a credential.
func (s *WebSocketServer) Address() string {
	if s == nil {
		return ""
	}
	return net.JoinHostPort(s.host, strconv.Itoa(int(s.port)))
}
