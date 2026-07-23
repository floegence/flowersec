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
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/connectv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/tunnelv2"
	"github.com/gorilla/websocket"
)

const testPrivateKeyBase64 = "d2VidHJhbnNwb3J0LWV4YW1wbGUtY2VydC1rZXktMDE="

type endpoint struct {
	URL             string `json:"url"`
	CertificateHash string `json:"certificate_hash"`
	ArtifactJSON    string `json:"artifact_json,omitempty"`
}

func main() {
	pathFlag := flag.String("path", "direct", "carrier path: direct or tunnel")
	oppositeFlag := flag.String("opposite", "", "mixed tunnel opposite carrier: wss or raw_quic")
	flag.Parse()
	tlsConfig, certificateHash, err := testTLSConfig(time.Now())
	must(err)
	if *oppositeFlag != "" {
		must(runMixedPeer(tlsConfig, certificateHash, *oppositeFlag))
		return
	}
	connectPath, sessionPath, err := pathConfiguration(*pathFlag)
	must(err)
	limits, err := carrierwt.BindSessionLimits(carrierwt.DefaultLimits(), 64)
	must(err)
	server, err := carrierwt.NewServer(tlsConfig, limits, allowedOrigin)
	must(err)
	result := make(chan error, 1)
	server.SetHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		result <- serveSession(server, writer, request, sessionPath)
	}))
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	must(err)
	defer packetConn.Close()
	defer server.Close()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(packetConn) }()

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

func runMixedPeer(tlsConfig *tls.Config, certificateHash, opposite string) error {
	if opposite != "wss" && opposite != "raw_quic" {
		return fmt.Errorf("invalid opposite carrier %q", opposite)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	limits, err := carrierwt.BindSessionLimits(carrierwt.DefaultLimits(), 64)
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
		go serveNativeCoordinatorLeg(ctx, coordinator, transport, legErrors)
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

func serveNativeCoordinatorLeg(
	ctx context.Context,
	coordinator *tunnelv2.Coordinator,
	transport carrier.Session,
	errorsCh chan<- error,
) {
	admission, err := transport.AcceptStream(ctx)
	if err != nil {
		selectSendError(errorsCh, err)
		return
	}
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
		leg, legErr := tunnelv2.NewWebSocketPendingLeg(connection, resources, carrierws.LivenessPolicy{})
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
	limits, err := rawquic.BindSessionLimits(rawquic.DefaultLimits(), 64)
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
		serveNativeCoordinatorLeg(ctx, coordinator, transport, errorsCh)
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
	var dial connectv2.CarrierDial
	var policy connectv2.Policy
	var kind artifactv2.Carrier
	if opposite == "wss" {
		webSocketDialer := *websocket.DefaultDialer
		webSocketDialer.TLSClientConfig = clientTLS
		dial, err = connectv2.NewWebSocketCarrierDial(connectv2.WebSocketDialConfig{
			Dialer: &webSocketDialer, Resources: carrierws.DefaultResourcePolicy(),
		})
		policy, kind = connectv2.RequireWebSocket, artifactv2.CarrierWebSocket
	} else {
		dial, err = connectv2.NewRawQUICCarrierDial(connectv2.RawQUICDialConfig{
			TLSConfig: clientTLS, Limits: rawquic.DefaultLimits(),
		})
		policy, kind = connectv2.RequireQUICFamily, artifactv2.CarrierRawQUIC
	}
	if err != nil {
		return err
	}
	factory, err := connectv2.NewAdmissionFactory(map[artifactv2.Carrier]connectv2.CarrierDial{kind: dial}, nil)
	if err != nil {
		return err
	}
	connector := connectv2.NewConnector(connectv2.ArtifactLease{
		Artifact: artifact, CommitSpend: func(context.Context) error { return nil },
	}, session.GoCapabilities(), policy, factory)
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
) error {
	transport, err := server.Upgrade(writer, request)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admission, err := transport.AcceptStream(ctx)
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
