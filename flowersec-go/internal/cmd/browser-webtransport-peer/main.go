package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/candidatev2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/rawquic"
	carrierws "github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/websocket"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/connectv2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/session"
	flowersessionv3 "github.com/floegence/flowersec/flowersec-go/v3/internal/sessionv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/transporttest"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/tunnelv2"
	"github.com/gorilla/websocket"
)

const testPrivateKeyBase64 = "d2VidHJhbnNwb3J0LWV4YW1wbGUtY2VydC1rZXktMDE="

type endpoint struct {
	URL                      string `json:"url"`
	CertificateHash          string `json:"certificate_hash"`
	CertificateNotAfterUnixS int64  `json:"certificate_not_after_unix_s,omitempty"`
	ArtifactJSON             string `json:"artifact_json,omitempty"`
}

func main() {
	pathFlag := flag.String("path", "direct", "carrier path: direct or tunnel")
	oppositeFlag := flag.String("opposite", "", "mixed tunnel opposite carrier: wss or raw_quic")
	faultedSessionsFlag := flag.Int("faulted-sessions", 0, "accept this many faulted WebTransport sessions and one stream per session")
	dropTransportAfterStreamsFlag := flag.Int("drop-transport-after-streams", 0, "drop the UDP transport after accepting this many logical streams")
	v3ProductDirectFlag := flag.Bool("v3-product-direct", false, "serve one production v3 direct WebTransport session")
	v3PublicCAFlag := flag.Bool("v3-public-ca", false, "use deployment-provided public-CA TLS material in v3 product-direct mode")
	v3DatagramFlag := flag.Bool("v3-datagram", false, "exchange one encrypted v3 DATAGRAM in product-direct mode")
	originFlag := flag.String("origin", "", "exact browser Origin for v3 product-direct mode")
	flag.Parse()
	if *v3ProductDirectFlag {
		must(runV3ProductDirect(*originFlag, *v3PublicCAFlag, *v3DatagramFlag))
		return
	}
	tlsConfig, certificateHash, err := testTLSConfig(time.Now())
	must(err)
	if *oppositeFlag != "" {
		must(runMixedPeer(tlsConfig, certificateHash, *oppositeFlag))
		return
	}
	connectPath, sessionPath, err := pathConfiguration(*pathFlag)
	must(err)
	if *faultedSessionsFlag != 0 {
		must(runFaultedSessionsPeer(tlsConfig, certificateHash, connectPath, *faultedSessionsFlag))
		return
	}
	if *dropTransportAfterStreamsFlag < 0 || *dropTransportAfterStreamsFlag > 8 {
		must(errors.New("drop-transport-after-streams must be between 0 and 8"))
	}
	limits, err := quicbase.BindSessionLimits(quicbase.DefaultLimits(), 64)
	must(err)
	server, err := carrierwt.NewServer(tlsConfig, limits, allowedOrigin)
	must(err)
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	must(err)
	defer packetConn.Close()
	defer server.Close()
	result := make(chan error, 1)
	server.SetHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		result <- serveSession(server, writer, request, sessionPath, *dropTransportAfterStreamsFlag, packetConn.Close)
	}))
	serveDone := make(chan error, 1)
	go func() {
		serveErr := server.Serve(packetConn)
		if *dropTransportAfterStreamsFlag > 0 && errors.Is(serveErr, net.ErrClosed) {
			serveErr = nil
		}
		serveDone <- serveErr
	}()

	address := packetConn.LocalAddr().(*net.UDPAddr)
	must(json.NewEncoder(os.Stdout).Encode(endpoint{
		URL:             fmt.Sprintf("https://127.0.0.1:%d%s", address.Port, connectPath),
		CertificateHash: certificateHash,
	}))

	select {
	case err := <-result:
		must(err)
	case err := <-serveDone:
		must(err)
	case <-time.After(20 * time.Second):
		must(errors.New("WebTransport interop peer timed out"))
	}
}

func runV3ProductDirect(origin string, publicCA, exchangeDatagram bool) error {
	if origin == "" {
		return errors.New("v3 product-direct mode requires an exact browser Origin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var (
		server              *transporttest.ProductDirectEndpoint
		err                 error
		certificateNotAfter int64
	)
	if publicCA {
		candidateHost := os.Getenv("FLOWERSEC_BROWSER_PUBLIC_CA_HOST")
		serverTLS, notAfter, tlsErr := publicCATLSConfig(
			os.Getenv("FLOWERSEC_BROWSER_PUBLIC_CA_CERT"),
			os.Getenv("FLOWERSEC_BROWSER_PUBLIC_CA_KEY"),
		)
		if tlsErr != nil {
			return tlsErr
		}
		server, err = transporttest.OpenProductDirectBrowserEndpointAtWithTLS(
			ctx, "127.0.0.1", candidateHost, origin, serverTLS,
		)
		certificateNotAfter = notAfter
	} else {
		server, err = transporttest.OpenProductDirectBrowserEndpointAt(ctx, "127.0.0.1", origin)
	}
	if err != nil {
		return err
	}
	defer server.Close()
	var issued *transporttest.ProductDirectBrowserArtifact
	if publicCA {
		issued, err = server.IssueBrowserCAArtifact()
	} else {
		issued, err = server.IssueBrowserArtifact()
	}
	if err != nil {
		return err
	}
	defer issued.Cancel()
	certificateHash, err := server.CertificateHashBase64URL()
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(endpoint{
		URL: server.CandidateURL(), CertificateHash: certificateHash,
		CertificateNotAfterUnixS: certificateNotAfter, ArtifactJSON: issued.ArtifactJSON(),
	}); err != nil {
		return err
	}
	established, err := issued.AwaitServer(ctx)
	if err != nil {
		return err
	}
	if exchangeDatagram {
		channel, channelErr := established.UnreliableMessages()
		if channelErr != nil {
			return channelErr
		}
		request, receiveErr := channel.Receive(ctx)
		if receiveErr != nil {
			return receiveErr
		}
		if string(request) != "browser-webtransport-datagram-request" {
			return errors.New("unexpected browser WebTransport datagram request")
		}
		status, sendErr := channel.Send(ctx, []byte("browser-webtransport-datagram-response"), flowersessionv3.UnreliableSendOptions{ExpiresAt: time.Now().Add(5 * time.Second)})
		if sendErr != nil {
			return fmt.Errorf("send browser WebTransport datagram response: %w", sendErr)
		}
		if status != flowersessionv3.UnreliableAccepted {
			return fmt.Errorf("send browser WebTransport datagram response status = %s", status)
		}
	}
	return established.Close()
}

func publicCATLSConfig(certificatePath, privateKeyPath string) (*tls.Config, int64, error) {
	if certificatePath == "" || privateKeyPath == "" {
		return nil, 0, errors.New("v3 public-CA mode requires certificate and private-key paths")
	}
	pair, err := tls.LoadX509KeyPair(certificatePath, privateKeyPath)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, 0, errors.New("v3 public-CA TLS material is invalid")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, 0, errors.New("v3 public-CA leaf certificate is invalid")
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	now := time.Now()
	if !ok || publicKey.Curve != elliptic.P256() || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		leaf.NotAfter.Sub(leaf.NotBefore) > 14*24*time.Hour {
		return nil, 0, errors.New("v3 public-CA leaf does not satisfy the browser pin certificate profile")
	}
	pair.Leaf = leaf
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		Certificates:           []tls.Certificate{pair},
	}, leaf.NotAfter.Unix(), nil
}

func runFaultedSessionsPeer(tlsConfig *tls.Config, certificateHash, connectPath string, count int) error {
	if count < 1 || count > 32 {
		return errors.New("faulted session count must be between 1 and 32")
	}
	limits, err := quicbase.BindSessionLimits(quicbase.DefaultLimits(), 32)
	if err != nil {
		return err
	}
	server, err := carrierwt.NewServer(tlsConfig, limits, allowedOrigin)
	if err != nil {
		return err
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accepted := make(chan error, count)
	closed := make(chan struct{}, count)
	server.SetHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, upgradeErr := server.Upgrade(writer, request)
		if upgradeErr != nil {
			accepted <- upgradeErr
			return
		}
		stream, streamErr := session.AcceptStream(ctx)
		if streamErr == nil {
			if written, writeErr := stream.Write([]byte{1}); writeErr != nil || written != 1 {
				streamErr = errors.Join(writeErr, errors.New("faulted session acceptance acknowledgment failed"))
			} else if closeErr := stream.CloseWrite(); closeErr != nil {
				streamErr = fmt.Errorf("faulted session acceptance acknowledgment close: %w", closeErr)
			}
		}
		accepted <- streamErr
		if streamErr == nil {
			<-stream.Context().Done()
			_ = stream.Reset()
		}
		closed <- struct{}{}
	}))
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return err
	}
	defer packetConn.Close()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(packetConn) }()
	proxy, err := newBrowserFaultProxy(packetConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		return err
	}
	defer proxy.Close()
	address := proxy.LocalAddr().(*net.UDPAddr)
	if err := json.NewEncoder(os.Stdout).Encode(endpoint{
		URL:             fmt.Sprintf("https://127.0.0.1:%d%s", address.Port, connectPath),
		CertificateHash: certificateHash,
	}); err != nil {
		return err
	}
	for range count {
		select {
		case err := <-accepted:
			if err != nil {
				return fmt.Errorf("faulted session acceptance: %w", err)
			}
		case err := <-serveDone:
			return fmt.Errorf("faulted session listener before acceptance: %w", err)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for range count {
		select {
		case <-closed:
		case err := <-serveDone:
			return fmt.Errorf("faulted session listener during cleanup: %w", err)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

type browserFaultProxy struct {
	front  *net.UDPConn
	server *net.UDPAddr

	mu       sync.Mutex
	closed   bool
	paths    map[string]*browserFaultPath
	clientN  uint64
	serverN  uint64
	waiters  sync.WaitGroup
	delivery sync.WaitGroup
}

type browserFaultPath struct {
	connection *net.UDPConn
	client     *net.UDPAddr
}

func newBrowserFaultProxy(server *net.UDPAddr) (*browserFaultProxy, error) {
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, err
	}
	proxy := &browserFaultProxy{front: front, server: server, paths: make(map[string]*browserFaultPath)}
	proxy.waiters.Add(1)
	go proxy.forwardClientPackets()
	return proxy, nil
}

func (proxy *browserFaultProxy) LocalAddr() net.Addr { return proxy.front.LocalAddr() }

func (proxy *browserFaultProxy) forwardClientPackets() {
	defer proxy.waiters.Done()
	buffer := make([]byte, 64<<10)
	for {
		n, client, err := proxy.front.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		path, err := proxy.pathFor(client)
		if err != nil {
			return
		}
		proxy.schedule(path.connection, proxy.server, buffer[:n], true)
	}
}

func (proxy *browserFaultProxy) pathFor(client *net.UDPAddr) (*browserFaultPath, error) {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if path := proxy.paths[client.String()]; path != nil {
		return path, nil
	}
	if proxy.closed {
		return nil, net.ErrClosed
	}
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, err
	}
	path := &browserFaultPath{connection: connection, client: client}
	proxy.paths[client.String()] = path
	proxy.waiters.Add(1)
	go proxy.forwardServerPackets(path)
	return path, nil
}

func (proxy *browserFaultProxy) forwardServerPackets(path *browserFaultPath) {
	defer proxy.waiters.Done()
	buffer := make([]byte, 64<<10)
	for {
		n, _, err := path.connection.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		proxy.schedule(proxy.front, path.client, buffer[:n], false)
	}
}

func (proxy *browserFaultProxy) schedule(connection *net.UDPConn, target *net.UDPAddr, payload []byte, clientToServer bool) {
	proxy.mu.Lock()
	ordinal := proxy.serverN + 1
	if clientToServer {
		ordinal = proxy.clientN + 1
		proxy.clientN = ordinal
	} else {
		proxy.serverN = ordinal
	}
	dropped := proxy.closed || ordinal%50 == 0
	if !dropped {
		proxy.delivery.Add(1)
	}
	proxy.mu.Unlock()
	if dropped {
		return
	}
	jitter := [...]int64{0, 8, -4, 12, -8, 4, -2, 6}
	delay := 60*time.Millisecond + time.Duration(jitter[(ordinal-1)%uint64(len(jitter))])*time.Millisecond
	packet := append([]byte(nil), payload...)
	go func() {
		defer proxy.delivery.Done()
		timer := time.NewTimer(delay)
		defer timer.Stop()
		<-timer.C
		_, _ = connection.WriteToUDP(packet, target)
	}()
}

func (proxy *browserFaultProxy) Close() {
	proxy.mu.Lock()
	if proxy.closed {
		proxy.mu.Unlock()
		return
	}
	proxy.closed = true
	paths := make([]*browserFaultPath, 0, len(proxy.paths))
	for _, path := range proxy.paths {
		paths = append(paths, path)
	}
	proxy.mu.Unlock()
	_ = proxy.front.Close()
	for _, path := range paths {
		_ = path.connection.Close()
	}
	proxy.waiters.Wait()
	proxy.delivery.Wait()
}

func runMixedPeer(tlsConfig *tls.Config, certificateHash, opposite string) error {
	if opposite != "wss" && opposite != "raw_quic" {
		return fmt.Errorf("invalid opposite carrier %q", opposite)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	limits, err := quicbase.BindSessionLimits(quicbase.DefaultLimits(), 64)
	if err != nil {
		return err
	}
	coordinator, err := newMixedCoordinator()
	if err != nil {
		return err
	}
	webTransportServer, err := carrierwt.NewServer(tlsConfig, limits, allowedOrigin)
	if err != nil {
		return err
	}
	defer webTransportServer.Close()
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return err
	}
	defer packetConn.Close()
	legErrors := make(chan error, 3)
	webTransportServer.SetHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		transport, upgradeErr := webTransportServer.Upgrade(writer, request)
		if upgradeErr != nil {
			selectSendError(legErrors, upgradeErr)
			return
		}
		go serveWebTransportCoordinatorLeg(ctx, coordinator, transport, legErrors)
	}))
	go func() { selectSendError(legErrors, webTransportServer.Serve(packetConn)) }()

	var oppositeURL string
	var closeOpposite func() error
	if opposite == "wss" {
		oppositeURL, closeOpposite, err = startMixedWSS(ctx, tlsConfig, coordinator, legErrors)
	} else {
		oppositeURL, closeOpposite, err = startMixedRawQUIC(ctx, tlsConfig, coordinator, legErrors)
	}
	if err != nil {
		return err
	}
	defer closeOpposite()
	webTransportAddress := packetConn.LocalAddr().(*net.UDPAddr)
	webTransportURL := fmt.Sprintf("https://127.0.0.1:%d%s", webTransportAddress.Port, carrierwt.PathTunnel)
	candidates := mixedCandidates(webTransportURL, oppositeURL, opposite)
	browserArtifact, goArtifact, err := mixedArtifacts(candidates)
	if err != nil {
		return err
	}
	rawBrowserArtifact, err := artifactv2.MarshalArtifactJSON(browserArtifact)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(endpoint{
		URL: webTransportURL, CertificateHash: certificateHash, ArtifactJSON: string(rawBrowserArtifact),
	}); err != nil {
		return err
	}

	endpointResult := make(chan error, 1)
	go func() { endpointResult <- connectMixedOpposite(ctx, tlsConfig, goArtifact, opposite) }()
	select {
	case err := <-endpointResult:
		return err
	case err := <-legErrors:
		if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newMixedCoordinator() (*tunnelv2.Coordinator, error) {
	return tunnelv2.NewCoordinator(tunnelv2.DefaultConfig(), func(
		_ context.Context,
		decoded *artifactv2.DecodedRequest,
	) (tunnelv2.Authorization, error) {
		request := decoded.Request
		expected := "endpoint-server"
		if request.Role == 2 {
			expected = "endpoint-client"
		}
		return tunnelv2.Authorization{
			Claims: tunnelv2.VerifiedClaims{
				CredentialID: fmt.Sprintf("%d:%s", request.Role, request.AttachToken),
				ChannelID:    request.ChannelID, Profile: request.Profile,
				RendezvousGroupID:   request.RendezvousGroupID,
				SessionContractHash: request.SessionContractHash,
				CandidateSetHash:    request.CandidateSetHash,
				ListenerAudience:    request.ListenerAudience, Role: request.Role,
				EndpointInstanceID:             request.EndpointInstanceID,
				ExpectedPeerEndpointInstanceID: expected,
			},
			ExpiresAt: time.Now().Add(time.Minute), Lease: mixedLease{},
		}, nil
	})
}

type mixedLease struct{}

func (mixedLease) Release() {}

func serveWebTransportCoordinatorLeg(
	ctx context.Context,
	coordinator *tunnelv2.Coordinator,
	transport *carrierwt.Session,
	errorsCh chan<- error,
) {
	admission, err := carrierwt.OpenAdmissionStream(ctx, transport)
	if err != nil {
		selectSendError(errorsCh, err)
		return
	}
	serveNativeCoordinatorLeg(ctx, coordinator, transport, admission, errorsCh)
}

func serveRawQUICCoordinatorLeg(
	ctx context.Context,
	coordinator *tunnelv2.Coordinator,
	transport *rawquic.Session,
	errorsCh chan<- error,
) {
	admission, err := rawquic.AcceptAdmissionStream(ctx, transport)
	if err != nil {
		selectSendError(errorsCh, err)
		return
	}
	serveNativeCoordinatorLeg(ctx, coordinator, transport, admission, errorsCh)
}

func serveNativeCoordinatorLeg(
	ctx context.Context,
	coordinator *tunnelv2.Coordinator,
	transport carrier.Session,
	admission carrier.Stream,
	errorsCh chan<- error,
) {
	leg, err := tunnelv2.NewNativeStreamLeg(transport, admission)
	if err != nil {
		selectSendError(errorsCh, err)
		return
	}
	selectSendCoordinatorError(errorsCh, coordinator.Serve(ctx, leg))
}

func startMixedWSS(
	ctx context.Context,
	tlsConfig *tls.Config,
	coordinator *tunnelv2.Coordinator,
	errorsCh chan<- error,
) (string, func() error, error) {
	resources, err := carrierws.BindSessionResourcePolicy(carrierws.DefaultResourcePolicy(), 64)
	if err != nil {
		return "", nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	upgrader := websocket.Upgrader{
		Subprotocols: []string{carrierws.SubprotocolTunnel},
		CheckOrigin:  func(*http.Request) bool { return true },
	}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, upgradeErr := upgrader.Upgrade(writer, request, nil)
		if upgradeErr != nil {
			selectSendError(errorsCh, upgradeErr)
			return
		}
		leg, legErr := tunnelv2.NewWebSocketPendingLeg(connection, resources)
		if legErr != nil {
			selectSendError(errorsCh, legErr)
			return
		}
		go func() { selectSendCoordinatorError(errorsCh, coordinator.Serve(ctx, leg)) }()
	})}
	go func() { selectSendError(errorsCh, server.Serve(tls.NewListener(listener, tlsConfig.Clone()))) }()
	return "wss://" + listener.Addr().String() + "/flowersec/v2/tunnel", func() error {
		return errors.Join(server.Close(), listener.Close())
	}, nil
}

func startMixedRawQUIC(
	ctx context.Context,
	tlsConfig *tls.Config,
	coordinator *tunnelv2.Coordinator,
	errorsCh chan<- error,
) (string, func() error, error) {
	limits, err := quicbase.BindSessionLimits(quicbase.DefaultLimits(), 64)
	if err != nil {
		return "", nil, err
	}
	serverTLS := tlsConfig.Clone()
	serverTLS.NextProtos = []string{rawquic.ALPNTunnel}
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS, limits)
	if err != nil {
		return "", nil, err
	}
	go func() {
		transport, acceptErr := listener.Accept(ctx)
		if acceptErr != nil {
			selectSendError(errorsCh, acceptErr)
			return
		}
		serveRawQUICCoordinatorLeg(ctx, coordinator, transport, errorsCh)
	}()
	return "quic://" + listener.Addr().String(), listener.Close, nil
}

func mixedCandidates(webTransportURL, oppositeURL, opposite string) []artifactv2.Candidate {
	candidates := []artifactv2.Candidate{{
		ID: "t1", Carrier: artifactv2.CarrierWebTransport,
		URL: webTransportURL, WireProfile: "flowersec-tunnel/2",
	}}
	if opposite == "wss" {
		return append(candidates, artifactv2.Candidate{
			ID: "w1", Carrier: artifactv2.CarrierWebSocket,
			URL: oppositeURL, WireProfile: "flowersec-tunnel/2",
		})
	}
	return append(candidates, artifactv2.Candidate{
		ID: "q1", Carrier: artifactv2.CarrierRawQUIC,
		URL: oppositeURL, WireProfile: "flowersec-tunnel/2",
	})
}

func mixedArtifacts(candidates []artifactv2.Candidate) (artifactv2.Artifact, artifactv2.Artifact, error) {
	contract := artifactv2.SessionContract{
		ChannelID: "browser-mixed-channel", InitExpireAtUnixSeconds: time.Now().Add(time.Minute).Unix(),
		IdleTimeoutSeconds: 60, EstablishTimeoutSeconds: 30,
		RekeyPrepareTimeoutSeconds: 10, RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams: 64, AllowedSuites: []uint16{1, 2}, DefaultSuite: 1,
	}
	for index := range contract.E2EEPSK {
		contract.E2EEPSK[index] = byte(index + 1)
	}
	hash, _, err := artifactv2.ComputeSessionContractHash(contract)
	if err != nil {
		return artifactv2.Artifact{}, artifactv2.Artifact{}, err
	}
	contract.ContractHash = hash
	base := artifactv2.Artifact{
		Version: 2, Profile: artifactv2.Profile, Session: contract,
		Scoped:      []artifactv2.ScopeMetadata{},
		Correlation: artifactv2.CorrelationContext{Version: 2, Tags: []artifactv2.CorrelationTag{}},
	}
	browser := base
	browser.Path = artifactv2.ArtifactPath{
		Kind: artifactv2.PathTunnel, RendezvousGroupID: "browser-mixed-group",
		ListenerAudience: "browser-mixed-listener", Role: 1,
		LocalEndpointInstanceID: "endpoint-client", ExpectedPeerEndpointInstanceID: "endpoint-server",
		Token: "browser-attach-token", Candidates: append([]artifactv2.Candidate(nil), candidates...),
	}
	goEndpoint := base
	goEndpoint.Path = artifactv2.ArtifactPath{
		Kind: artifactv2.PathTunnel, RendezvousGroupID: "browser-mixed-group",
		ListenerAudience: "browser-mixed-listener", Role: 2,
		LocalEndpointInstanceID: "endpoint-server", ExpectedPeerEndpointInstanceID: "endpoint-client",
		Token: "go-attach-token", Candidates: append([]artifactv2.Candidate(nil), candidates...),
	}
	return browser, goEndpoint, nil
}

func connectMixedOpposite(
	ctx context.Context,
	tlsConfig *tls.Config,
	artifact artifactv2.Artifact,
	opposite string,
) error {
	certificate, err := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	var dial candidatev2.Dial
	var kind artifactv2.Carrier
	if opposite == "wss" {
		webSocketDialer := *websocket.DefaultDialer
		webSocketDialer.TLSClientConfig = clientTLS
		dial, err = candidatev2.NewWebSocketCarrierDial(candidatev2.WebSocketDialConfig{
			Dialer: &webSocketDialer, Resources: carrierws.DefaultResourcePolicy(),
		})
		kind = artifactv2.CarrierWebSocket
	} else {
		dial, err = candidatev2.NewRawQUICCarrierDial(candidatev2.RawQUICDialConfig{
			TLSConfig: clientTLS, Limits: quicbase.DefaultLimits(), Dial: rawquic.Dial,
		})
		kind = artifactv2.CarrierRawQUIC
	}
	if err != nil {
		return err
	}
	factory, err := candidatev2.NewFactory(map[artifactv2.Carrier]candidatev2.Dial{kind: dial})
	if err != nil {
		return err
	}
	connector := connectv2.NewConnector(connectv2.ArtifactLease{
		Artifact: artifact, CommitSpend: func(context.Context) error { return nil },
	}, factory)
	result, err := connector.Connect(ctx)
	if err != nil {
		return err
	}
	if result.Candidate.Carrier != kind {
		return fmt.Errorf("opposite selected %q, want %q", result.Candidate.Carrier, kind)
	}
	defer result.Session.Close()
	incoming, err := result.Session.AcceptStream(ctx)
	if err != nil {
		return err
	}
	payload := make([]byte, len("browser-mixed"))
	_, err = io.ReadFull(incoming.Stream, payload)
	if err != nil {
		return err
	}
	if string(payload) != "browser-mixed" {
		return fmt.Errorf("unexpected mixed payload %q", payload)
	}
	if _, err := incoming.Stream.Write([]byte("go-" + strings.ReplaceAll(opposite, "_", "-"))); err != nil {
		return err
	}
	if err := incoming.Stream.CloseWrite(); err != nil {
		return err
	}
	remaining, err := io.ReadAll(incoming.Stream)
	if err != nil {
		return err
	}
	if len(remaining) != 0 {
		return fmt.Errorf("unexpected trailing mixed payload %q", remaining)
	}
	select {
	case <-result.Session.Termination():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func selectSendError(errorsCh chan<- error, err error) {
	if err == nil {
		return
	}
	select {
	case errorsCh <- err:
	default:
	}
}

func selectSendCoordinatorError(errorsCh chan<- error, err error) {
	if errors.Is(err, tunnelv2.ErrControlClosed) || errors.Is(err, context.Canceled) {
		return
	}
	selectSendError(errorsCh, err)
}

func serveSession(
	server *carrierwt.Server,
	writer http.ResponseWriter,
	request *http.Request,
	sessionPath session.PathKind,
	dropTransportAfterStreams int,
	dropTransport func() error,
) error {
	transport, err := server.Upgrade(writer, request)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admission, err := carrierwt.OpenAdmissionStream(ctx, transport)
	if err != nil {
		return err
	}
	decoded, err := admissionv2.Serve(ctx, admission, nil, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
		return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
	})
	if err != nil {
		return err
	}
	var psk [32]byte
	for index := range psk {
		psk[index] = byte(index + 1)
	}
	peerBinding := decoded.LocalAdmissionBinding
	localEndpointInstanceID := ""
	expectedPeerEndpointInstanceID := ""
	if sessionPath == session.PathTunnel {
		peerBinding = [32]byte{}
		localEndpointInstanceID = "endpoint-server"
		expectedPeerEndpointInstanceID = "endpoint-client"
	}
	established, err := session.Establish(ctx, transport, session.Config{
		Role:                           session.RoleServer,
		Path:                           sessionPath,
		ChannelID:                      decoded.Request.ChannelID,
		SessionContractHash:            decoded.Request.SessionContractHash,
		Suite:                          protocolv2.SuiteChaCha20Poly1305,
		PSK:                            psk,
		MaxInboundStreams:              64,
		LocalAdmissionBinding:          decoded.LocalAdmissionBinding,
		PeerAdmissionBinding:           peerBinding,
		LocalEndpointInstanceID:        localEndpointInstanceID,
		ExpectedPeerEndpointInstanceID: expectedPeerEndpointInstanceID,
	})
	if err != nil {
		return err
	}
	if dropTransportAfterStreams > 0 {
		accepted := make([]session.IncomingStream, 0, dropTransportAfterStreams)
		for range dropTransportAfterStreams {
			incoming, acceptErr := established.AcceptStream(ctx)
			if acceptErr != nil {
				return acceptErr
			}
			accepted = append(accepted, incoming)
		}
		for _, incoming := range accepted {
			var barrier [1]byte
			if _, readErr := io.ReadFull(incoming.Stream, barrier[:]); readErr != nil {
				return fmt.Errorf("read WebTransport drop barrier: %w", readErr)
			}
			if barrier[0] != 1 {
				return fmt.Errorf("invalid WebTransport drop barrier %d", barrier[0])
			}
		}
		if dropTransport == nil {
			return errors.New("missing WebTransport drop fixture")
		}
		if dropErr := dropTransport(); dropErr != nil && !errors.Is(dropErr, net.ErrClosed) {
			return dropErr
		}
		select {
		case <-established.Termination():
			runtime.KeepAlive(accepted)
			return nil
		case <-ctx.Done():
			runtime.KeepAlive(accepted)
			return ctx.Err()
		}
	}
	defer established.Close()

	unreliable, err := established.UnreliableMessages()
	if err != nil {
		return err
	}
	message, err := unreliable.Receive(ctx)
	if err != nil {
		return err
	}
	if string(message) != "browser-datagram" {
		return fmt.Errorf("unexpected DATAGRAM payload %q", message)
	}
	status, err := unreliable.Send(ctx, []byte("go-datagram"), session.UnreliableSendOptions{
		ExpiresAt: time.Now().Add(5 * time.Second),
	})
	if err != nil || status != session.UnreliableAccepted {
		return fmt.Errorf("send DATAGRAM: status=%s err=%w", status, err)
	}

	incoming, err := established.AcceptStream(ctx)
	if err != nil {
		return err
	}
	buffer := make([]byte, 64)
	n, err := incoming.Stream.Read(buffer)
	if err != nil {
		return err
	}
	if string(buffer[:n]) != "hello-go" {
		return fmt.Errorf("unexpected first payload %q", buffer[:n])
	}
	if _, err := incoming.Stream.Write([]byte("hello-ts")); err != nil {
		return err
	}
	if err := established.Rekey(ctx); err != nil {
		return err
	}
	if _, err := incoming.Stream.Write([]byte("go-rekey-ok")); err != nil {
		return err
	}
	n, err = incoming.Stream.Read(buffer)
	if err != nil {
		return err
	}
	if string(buffer[:n]) != "ts-rekey-ok" {
		return fmt.Errorf("unexpected rekey payload %q", buffer[:n])
	}
	n, err = incoming.Stream.Read(buffer)
	if !errors.Is(err, io.EOF) || n != 0 {
		return fmt.Errorf("expected EOF, got n=%d err=%v", n, err)
	}
	if _, err := incoming.Stream.Write([]byte("done")); err != nil {
		return err
	}
	if err := incoming.Stream.CloseWrite(); err != nil {
		return err
	}
	select {
	case <-established.Termination():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func pathConfiguration(value string) (string, session.PathKind, error) {
	switch value {
	case "direct":
		return carrierwt.PathDirect, session.PathDirect, nil
	case "tunnel":
		return carrierwt.PathTunnel, session.PathTunnel, nil
	default:
		return "", "", fmt.Errorf("invalid carrier path %q", value)
	}
}

func allowedOrigin(request *http.Request) bool {
	parsed, err := url.Parse(request.Header.Get("Origin"))
	return err == nil && parsed.Scheme == "http" && parsed.Hostname() == "127.0.0.1" && parsed.Port() != "" &&
		parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func testTLSConfig(now time.Time) (*tls.Config, string, error) {
	privateKeyBytes, err := base64.StdEncoding.DecodeString(testPrivateKeyBase64)
	if err != nil {
		return nil, "", err
	}
	privateKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), privateKeyBytes)
	if err != nil {
		return nil, "", err
	}
	utc := now.UTC()
	validFrom := time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
	validFrom = validFrom.AddDate(0, 0, -int((validFrom.Weekday()+6)%7))
	validUntil := validFrom.Add(13 * 24 * time.Hour)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(validFrom.Unix()),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             validFrom,
		NotAfter:              validUntil,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("::1")},
	}
	certificateDER, err := x509.CreateCertificate(nil, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, "", err
	}
	hash := sha256.Sum256(certificateDER)
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certificateDER},
			PrivateKey:  privateKey,
		}},
	}, base64.RawStdEncoding.EncodeToString(hash[:]), nil
}

func must(err error) {
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
