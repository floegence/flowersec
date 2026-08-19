// Package transporttest contains the production workloads used by the
// native Transport v2 acceptance and performance tests.
package transporttest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/rawquic"
	carrierws "github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/websocket"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/webtransport"
	carrieryamux "github.com/floegence/flowersec/flowersec-go/v3/internal/mux/yamux"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv2"
	flowersession "github.com/floegence/flowersec/flowersec-go/v3/internal/session"
	gorillaws "github.com/gorilla/websocket"
	"github.com/quic-go/quic-go/http3"
)

const defaultMaxInboundStreams uint16 = 32

// DirectPair owns two established Flowersec v2 sessions and all carrier
// listeners used to create them.
type DirectPair struct {
	Client flowersession.SessionV2
	Server flowersession.SessionV2

	closeOnce sync.Once
	closeErr  error
	closers   []func() error
}

// OpenDirect creates a real TLS carrier connection and completes the
// carrier-neutral Flowersec v2 handshake on both endpoints.
func OpenDirect(ctx context.Context, kind carrier.Kind) (*DirectPair, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	serverTLS, clientTLS, err := localTLS(kind)
	if err != nil {
		return nil, err
	}
	var clientCarrier, serverCarrier carrier.Session
	var closers []func() error
	switch kind {
	case carrier.KindWebSocket:
		clientCarrier, serverCarrier, closers, err = openDirectWebSocket(ctx, serverTLS, clientTLS)
	case carrier.KindRawQUIC:
		clientCarrier, serverCarrier, closers, err = openDirectRawQUIC(ctx, serverTLS, clientTLS)
	case carrier.KindWebTransport:
		clientCarrier, serverCarrier, closers, err = openDirectWebTransport(ctx, serverTLS, clientTLS)
	default:
		err = fmt.Errorf("unsupported direct carrier %q", kind)
	}
	if err != nil {
		closeFunctions(closers)
		return nil, err
	}

	clientConfig, serverConfig := directSessionConfigs(defaultMaxInboundStreams)
	client, server, err := establishPair(ctx, clientCarrier, serverCarrier, clientConfig, serverConfig)
	if err != nil {
		_ = clientCarrier.Close()
		_ = serverCarrier.Close()
		closeFunctions(closers)
		return nil, err
	}
	return &DirectPair{Client: client, Server: server, closers: closers}, nil
}

// RoundTrip transfers request and response bytes over one encrypted logical
// stream and validates both payloads and the public stream metadata boundary.
func (pair *DirectPair) RoundTrip(ctx context.Context, request, response []byte) error {
	if pair == nil || pair.Client == nil || pair.Server == nil {
		return errors.New("direct pair is not established")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	type acceptResult struct {
		incoming flowersession.IncomingStream
		err      error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		incoming, err := pair.Server.AcceptStream(ctx)
		accepted <- acceptResult{incoming: incoming, err: err}
	}()
	opened, err := pair.Client.OpenStream(ctx, "release-roundtrip", flowersession.Metadata{"direction": "client-to-server"})
	if err != nil {
		return fmt.Errorf("open encrypted stream: %w", err)
	}
	defer opened.Close()
	peer := <-accepted
	if peer.err != nil {
		return fmt.Errorf("accept encrypted stream: %w", peer.err)
	}
	defer peer.incoming.Stream.Close()
	if peer.incoming.Kind != "release-roundtrip" || peer.incoming.Metadata["direction"] != "client-to-server" {
		return errors.New("encrypted stream metadata mismatch")
	}
	requestRead := readAll(peer.incoming.Stream)
	if _, err := opened.Write(request); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	if err := opened.CloseWrite(); err != nil {
		return fmt.Errorf("finish request: %w", err)
	}
	gotRequest := <-requestRead
	if gotRequest.err != nil {
		return fmt.Errorf("read request: %w", gotRequest.err)
	}
	if !bytes.Equal(gotRequest.payload, request) {
		return errors.New("request payload mismatch")
	}
	responseRead := readAll(opened)
	if _, err := peer.incoming.Stream.Write(response); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	if err := peer.incoming.Stream.CloseWrite(); err != nil {
		return fmt.Errorf("finish response: %w", err)
	}
	gotResponse := <-responseRead
	if gotResponse.err != nil {
		return fmt.Errorf("read response: %w", gotResponse.err)
	}
	if !bytes.Equal(gotResponse.payload, response) {
		return errors.New("response payload mismatch")
	}
	return nil
}

// Close shuts down encrypted sessions before their listeners and dialers.
func (pair *DirectPair) Close() error {
	if pair == nil {
		return nil
	}
	pair.closeOnce.Do(func() {
		if pair.Client != nil {
			pair.closeErr = errors.Join(pair.closeErr, normalizeCloseError(pair.Client.Close()))
		}
		for label, current := range map[string]flowersession.SessionV2{"client": pair.Client, "server": pair.Server} {
			if current == nil {
				continue
			}
			select {
			case <-current.Termination():
			case <-time.After(3 * time.Second):
				pair.closeErr = errors.Join(pair.closeErr, fmt.Errorf("%s did not terminate after authenticated close", label))
				pair.closeErr = errors.Join(pair.closeErr, normalizeCloseError(current.Close()))
			}
		}
		for index := len(pair.closers) - 1; index >= 0; index-- {
			pair.closeErr = errors.Join(pair.closeErr, normalizeCloseError(pair.closers[index]()))
		}
	})
	return pair.closeErr
}

func openDirectRawQUIC(ctx context.Context, serverTLS, clientTLS *tls.Config) (carrier.Session, carrier.Session, []func() error, error) {
	limits, err := quicbase.BindSessionLimits(quicbase.DefaultLimits(), defaultMaxInboundStreams)
	if err != nil {
		return nil, nil, nil, err
	}
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS, limits)
	if err != nil {
		return nil, nil, nil, err
	}
	closers := []func() error{listener.Close}
	type result struct {
		session *rawquic.Session
		err     error
	}
	accepted := make(chan result, 1)
	go func() {
		session, acceptErr := listener.Accept(ctx)
		accepted <- result{session: session, err: acceptErr}
	}()
	client, err := rawquic.Dial(ctx, listener.Addr().String(), clientTLS, limits)
	if err != nil {
		return nil, nil, closers, err
	}
	server := <-accepted
	if server.err != nil {
		_ = client.Close()
		return nil, nil, closers, server.err
	}
	return client, server.session, closers, nil
}

func openDirectWebSocket(ctx context.Context, serverTLS, clientTLS *tls.Config) (carrier.Session, carrier.Session, []func() error, error) {
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", serverTLS)
	if err != nil {
		return nil, nil, nil, err
	}
	accepted := make(chan *gorillaws.Conn, 1)
	acceptErrors := make(chan error, 1)
	upgrader := gorillaws.Upgrader{Subprotocols: []string{carrierws.SubprotocolDirect}}
	httpServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, upgradeErr := upgrader.Upgrade(writer, request, nil)
		if upgradeErr != nil {
			select {
			case acceptErrors <- upgradeErr:
			default:
			}
			return
		}
		accepted <- conn
	})}
	serveDone := make(chan error, 1)
	go func() { serveDone <- httpServer.Serve(listener) }()
	closers := []func() error{func() error {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr := httpServer.Shutdown(closeCtx)
		serveErr := <-serveDone
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		return errors.Join(shutdownErr, serveErr)
	}}
	dialer := gorillaws.Dialer{Subprotocols: []string{carrierws.SubprotocolDirect}, TLSClientConfig: clientTLS}
	clientConn, _, err := dialer.DialContext(ctx, "wss://"+listener.Addr().String()+"/flowersec/v2/direct", nil)
	if err != nil {
		return nil, nil, closers, err
	}
	var serverConn *gorillaws.Conn
	select {
	case serverConn = <-accepted:
	case err = <-acceptErrors:
		_ = clientConn.Close()
		return nil, nil, closers, err
	case <-ctx.Done():
		_ = clientConn.Close()
		return nil, nil, closers, ctx.Err()
	}
	resources, err := carrierws.BindSessionResourcePolicy(carrierws.DefaultResourcePolicy(), defaultMaxInboundStreams)
	if err != nil {
		_ = clientConn.Close()
		_ = serverConn.Close()
		return nil, nil, closers, err
	}
	serverResult := make(chan struct {
		session *carrierws.Session
		err     error
	}, 1)
	go func() {
		session, sessionErr := carrierws.NewAfterAdmission(serverConn, carrierws.ServerRole, carrierws.SubprotocolDirect, resources)
		serverResult <- struct {
			session *carrierws.Session
			err     error
		}{session: session, err: sessionErr}
	}()
	client, err := carrierws.NewAfterAdmission(clientConn, carrierws.ClientRole, carrierws.SubprotocolDirect, resources)
	if err != nil {
		_ = serverConn.Close()
		return nil, nil, closers, err
	}
	server := <-serverResult
	if server.err != nil {
		_ = client.Close()
		return nil, nil, closers, server.err
	}
	return client, server.session, closers, nil
}

func openDirectWebTransport(ctx context.Context, serverTLS, clientTLS *tls.Config) (carrier.Session, carrier.Session, []func() error, error) {
	limits, err := quicbase.BindSessionLimits(quicbase.DefaultLimits(), defaultMaxInboundStreams)
	if err != nil {
		return nil, nil, nil, err
	}
	server, err := carrierwt.NewServer(serverTLS, limits, func(request *http.Request) bool {
		return request.Header.Get("Origin") == "https://release-runner.flowersec.invalid"
	})
	if err != nil {
		return nil, nil, nil, err
	}
	accepted := make(chan *carrierwt.Session, 1)
	acceptErrors := make(chan error, 1)
	server.SetHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, upgradeErr := server.Upgrade(writer, request)
		if upgradeErr != nil {
			acceptErrors <- upgradeErr
			return
		}
		accepted <- session
	}))
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = server.Close()
		return nil, nil, nil, err
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(packetConn) }()
	dialer, err := carrierwt.NewDialer(clientTLS, limits)
	if err != nil {
		_ = server.Close()
		_ = packetConn.Close()
		return nil, nil, nil, err
	}
	closers := []func() error{
		dialer.Close,
		func() error {
			serverErr := server.Close()
			packetErr := packetConn.Close()
			serveErr := <-serveDone
			if errors.Is(serveErr, net.ErrClosed) || strings.Contains(fmt.Sprint(serveErr), "server closed") {
				serveErr = nil
			}
			return errors.Join(serverErr, packetErr, serveErr)
		},
	}
	target := (&url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort("localhost", fmt.Sprint(packetConn.LocalAddr().(*net.UDPAddr).Port)),
		Path:   carrierwt.PathDirect,
	}).String()
	client, err := dialer.Dial(ctx, target, "https://release-runner.flowersec.invalid")
	if err != nil {
		return nil, nil, closers, err
	}
	select {
	case serverSession := <-accepted:
		return client, serverSession, closers, nil
	case err := <-acceptErrors:
		_ = client.Close()
		return nil, nil, closers, err
	case <-ctx.Done():
		_ = client.Close()
		return nil, nil, closers, ctx.Err()
	}
}

func establishPair(ctx context.Context, clientCarrier, serverCarrier carrier.Session, clientConfig, serverConfig flowersession.Config) (flowersession.SessionV2, flowersession.SessionV2, error) {
	type result struct {
		session flowersession.SessionV2
		err     error
	}
	serverResult := make(chan result, 1)
	go func() {
		established, err := flowersession.Establish(ctx, serverCarrier, serverConfig)
		serverResult <- result{session: established, err: err}
	}()
	client, err := flowersession.Establish(ctx, clientCarrier, clientConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("establish client session: %w", err)
	}
	server := <-serverResult
	if server.err != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("establish server session: %w", server.err)
	}
	return client, server.session, nil
}

func directSessionConfigs(maxInbound uint16) (flowersession.Config, flowersession.Config) {
	var psk, contract, clientAdmission, serverAdmission [32]byte
	for index := 0; index < 32; index++ {
		psk[index] = byte(index + 1)
		contract[index] = byte(index + 33)
		clientAdmission[index] = byte(index + 65)
		serverAdmission[index] = byte(index + 97)
	}
	base := flowersession.Config{
		Path: flowersession.PathDirect, ChannelID: "transport-release-direct",
		SessionContractHash: contract, Suite: protocolv2.SuiteChaCha20Poly1305,
		PSK: psk, MaxInboundStreams: maxInbound,
	}
	client := base
	client.Role = flowersession.RoleClient
	client.LocalAdmissionBinding = clientAdmission
	client.PeerAdmissionBinding = serverAdmission
	server := base
	server.Role = flowersession.RoleServer
	server.LocalAdmissionBinding = serverAdmission
	server.PeerAdmissionBinding = clientAdmission
	return client, server
}

func localTLS(kind carrier.Kind) (*tls.Config, *tls.Config, error) {
	return localTLSForHost(kind, "")
}

func localTLSForHost(kind carrier.Kind, listenHost string) (*tls.Config, *tls.Config, error) {
	nextProtocol := ""
	switch kind {
	case carrier.KindRawQUIC:
		nextProtocol = rawquic.ALPNDirect
	case carrier.KindWebTransport:
		nextProtocol = http3.NextProtoH3
	case carrier.KindWebSocket:
	default:
		return nil, nil, fmt.Errorf("unsupported carrier %q", kind)
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey
	serverName := "localhost"
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1")}
	if listenHost != "" && listenHost != "127.0.0.1" {
		address := net.ParseIP(listenHost)
		if address == nil {
			return nil, nil, errors.New("release TLS host must be an IP address")
		}
		serverName = listenHost
		ipAddresses = append(ipAddresses, address)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(20260724), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: ipAddresses,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	server := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}},
	}
	client := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: serverName}
	if nextProtocol != "" {
		server.NextProtos = []string{nextProtocol}
		client.NextProtos = []string{nextProtocol}
	}
	return server, client, nil
}

type readResult struct {
	payload []byte
	err     error
}

func readAll(reader io.Reader) <-chan readResult {
	result := make(chan readResult, 1)
	go func() {
		payload, err := io.ReadAll(reader)
		result <- readResult{payload: payload, err: err}
	}()
	return result
}

func closeFunctions(closers []func() error) {
	for index := len(closers) - 1; index >= 0; index-- {
		_ = closers[index]()
	}
}

func normalizeCloseError(err error) error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var filtered error
		for _, child := range joined.Unwrap() {
			filtered = errors.Join(filtered, normalizeCloseError(child))
		}
		return filtered
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.EOF) || errors.Is(err, gorillaws.ErrCloseSent) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, carrieryamux.ErrStreamReset) {
		return nil
	}
	var websocketClose *gorillaws.CloseError
	if errors.As(err, &websocketClose) && websocketClose.Code == 4000 {
		switch websocketClose.Text {
		case "session closed", "tunnel bridge closed", "tunnel_closed":
			return nil
		}
	}
	return err
}

// NormalizeCloseError filters only transport errors that mean cleanup already reached a terminal state.
func NormalizeCloseError(err error) error { return normalizeCloseError(err) }
