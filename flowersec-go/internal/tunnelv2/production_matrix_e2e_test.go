package tunnelv2_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/tunnelv2"
	"github.com/quic-go/quic-go/http3"
)

func TestProductionTunnelCarrierCartesianMatrixCarriesEncryptedSessions(t *testing.T) {
	topologies := []struct {
		name          string
		clientCarrier artifactv2.Carrier
		serverCarrier artifactv2.Carrier
	}{
		{name: "WW", clientCarrier: artifactv2.CarrierWebSocket, serverCarrier: artifactv2.CarrierWebSocket},
		{name: "WQ", clientCarrier: artifactv2.CarrierWebSocket, serverCarrier: artifactv2.CarrierRawQUIC},
		{name: "WT", clientCarrier: artifactv2.CarrierWebSocket, serverCarrier: artifactv2.CarrierWebTransport},
		{name: "QW", clientCarrier: artifactv2.CarrierRawQUIC, serverCarrier: artifactv2.CarrierWebSocket},
		{name: "QQ", clientCarrier: artifactv2.CarrierRawQUIC, serverCarrier: artifactv2.CarrierRawQUIC},
		{name: "QT", clientCarrier: artifactv2.CarrierRawQUIC, serverCarrier: artifactv2.CarrierWebTransport},
		{name: "TW", clientCarrier: artifactv2.CarrierWebTransport, serverCarrier: artifactv2.CarrierWebSocket},
		{name: "TQ", clientCarrier: artifactv2.CarrierWebTransport, serverCarrier: artifactv2.CarrierRawQUIC},
		{name: "TT", clientCarrier: artifactv2.CarrierWebTransport, serverCarrier: artifactv2.CarrierWebTransport},
	}
	for _, topology := range topologies {
		t.Run(topology.name, func(t *testing.T) {
			contract := productionTunnelContract(t)
			clientFSB2 := validTunnelFSB2ForCarrier(
				t, 1, "client", topology.name+"-client", topology.clientCarrier,
			)
			serverFSB2 := validTunnelFSB2ForCarrier(
				t, 2, "server", topology.name+"-server", topology.serverCarrier,
			)
			clientLeg := newProductionTunnelLeg(t, topology.clientCarrier, contract.MaxInboundStreams, clientFSB2)
			serverLeg := newProductionTunnelLeg(t, topology.serverCarrier, contract.MaxInboundStreams, serverFSB2)
			coordinator := newProductionCoordinator(t)
			bridgeContext, cancelBridge := context.WithCancel(context.Background())
			clientServeDone := serveLeg(coordinator, bridgeContext, clientLeg.pending)
			serverServeDone := serveLeg(coordinator, bridgeContext, serverLeg.pending)

			clientCarrierSession := awaitProductionEndpoint(t, clientLeg.endpoint)
			serverCarrierSession := awaitProductionEndpoint(t, serverLeg.endpoint)
			clientConfig, serverConfig := productionTunnelSessionConfigs(contract, clientFSB2, serverFSB2)
			clientSession, serverSession := establishProductionSessionPair(
				t, clientCarrierSession, serverCarrierSession, clientConfig, serverConfig,
			)
			assertEncryptedSessionRoundTrip(
				t, clientSession, serverSession, "client-to-server", topology.name+"-request", topology.name+"-response",
			)
			assertEncryptedSessionRoundTrip(
				t, serverSession, clientSession, "server-to-client", topology.name+"-event", topology.name+"-ack",
			)

			cancelBridge()
			assertProductionServeCanceled(t, clientServeDone)
			assertProductionServeCanceled(t, serverServeDone)
			_ = clientSession.Close()
			_ = serverSession.Close()
		})
	}
}

type productionTunnelLeg struct {
	pending  tunnelv2.PendingLeg
	endpoint <-chan productionEndpointResult
}

type productionEndpointResult struct {
	session carrier.Session
	err     error
}

func newProductionTunnelLeg(
	t *testing.T,
	kind artifactv2.Carrier,
	maxInbound uint16,
	rawFSB2 []byte,
) productionTunnelLeg {
	t.Helper()
	switch kind {
	case artifactv2.CarrierWebSocket:
		return newProductionWebSocketTunnelLeg(t, maxInbound, rawFSB2)
	case artifactv2.CarrierRawQUIC:
		return newProductionRawQUICTunnelLeg(t, maxInbound, rawFSB2)
	case artifactv2.CarrierWebTransport:
		return newProductionWebTransportTunnelLeg(t, maxInbound, rawFSB2)
	default:
		t.Fatalf("unsupported production tunnel carrier %q", kind)
		return productionTunnelLeg{}
	}
}

func newProductionWebSocketTunnelLeg(t *testing.T, maxInbound uint16, rawFSB2 []byte) productionTunnelLeg {
	t.Helper()
	endpointConn, tunnelConn := newTunnelWebSocketPair(t)
	resources, err := carrierws.BindSessionResourcePolicy(carrierws.DefaultResourcePolicy(), maxInbound)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := tunnelv2.NewWebSocketPendingLeg(tunnelConn, resources, carrierws.LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan productionEndpointResult, 1)
	go func() {
		_, commitErr := carrierws.CommitAdmission(context.Background(), endpointConn, rawFSB2, tunnelv2.DefaultReasonRegistry())
		if commitErr != nil {
			result <- productionEndpointResult{err: commitErr}
			return
		}
		session, sessionErr := carrierws.NewAfterAdmission(
			endpointConn, carrierws.ClientRole, carrierws.SubprotocolTunnel, resources, carrierws.LivenessPolicy{},
		)
		result <- productionEndpointResult{session: session, err: sessionErr}
	}()
	return productionTunnelLeg{pending: pending, endpoint: result}
}

func newProductionRawQUICTunnelLeg(t *testing.T, maxInbound uint16, rawFSB2 []byte) productionTunnelLeg {
	t.Helper()
	limits, err := rawquic.BindSessionLimits(rawquic.DefaultLimits(), maxInbound)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, clientTLS := productionCarrierTLS(t, rawquic.ALPNTunnel)
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	tunnelSessionResult := make(chan *rawquic.Session, 1)
	tunnelErrors := make(chan error, 1)
	go func() {
		session, acceptErr := listener.Accept(context.Background())
		if acceptErr != nil {
			tunnelErrors <- acceptErr
			return
		}
		tunnelSessionResult <- session
	}()
	endpointSession, err := rawquic.Dial(context.Background(), listener.Addr().String(), clientTLS, limits)
	if err != nil {
		t.Fatal(err)
	}
	var tunnelSession *rawquic.Session
	select {
	case tunnelSession = <-tunnelSessionResult:
	case err := <-tunnelErrors:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("raw QUIC tunnel accept timed out")
	}
	t.Cleanup(func() { _ = endpointSession.Close() })
	t.Cleanup(func() { _ = tunnelSession.Close() })
	return newProductionNativeTunnelLeg(t, endpointSession, tunnelSession, rawFSB2)
}

func newProductionWebTransportTunnelLeg(t *testing.T, maxInbound uint16, rawFSB2 []byte) productionTunnelLeg {
	t.Helper()
	limits, err := carrierwt.BindSessionLimits(carrierwt.DefaultLimits(), maxInbound)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, clientTLS := productionCarrierTLS(t, http3.NextProtoH3)
	server, err := carrierwt.NewServer(serverTLS, limits, func(request *http.Request) bool {
		return request.Header.Get("Origin") == "https://client.example"
	})
	if err != nil {
		t.Fatal(err)
	}
	tunnelSessions := make(chan *carrierwt.Session, 1)
	tunnelErrors := make(chan error, 1)
	server.SetHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, upgradeErr := server.Upgrade(writer, request)
		if upgradeErr != nil {
			tunnelErrors <- upgradeErr
			return
		}
		tunnelSessions <- session
	}))
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(packetConn) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = packetConn.Close()
		select {
		case <-serveDone:
		case <-time.After(5 * time.Second):
			t.Error("WebTransport tunnel server did not stop")
		}
	})
	dialer, err := carrierwt.NewDialer(clientTLS, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dialer.Close() })
	target := (&url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort("localhost", fmt.Sprint(packetConn.LocalAddr().(*net.UDPAddr).Port)),
		Path:   carrierwt.PathTunnel,
	}).String()
	endpointSession, err := dialer.Dial(context.Background(), target, "https://client.example")
	if err != nil {
		t.Fatal(err)
	}
	var tunnelSession *carrierwt.Session
	select {
	case tunnelSession = <-tunnelSessions:
	case err := <-tunnelErrors:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("WebTransport tunnel upgrade timed out")
	}
	t.Cleanup(func() { _ = endpointSession.Close() })
	t.Cleanup(func() { _ = tunnelSession.Close() })
	return newProductionNativeTunnelLeg(t, endpointSession, tunnelSession, rawFSB2)
}

func newProductionNativeTunnelLeg(
	t *testing.T,
	endpointSession carrier.Session,
	tunnelSession carrier.Session,
	rawFSB2 []byte,
) productionTunnelLeg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	endpointAdmission, err := endpointSession.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan productionEndpointResult, 1)
	go func() {
		_, commitErr := admissionv2.Commit(ctx, endpointAdmission, rawFSB2, tunnelv2.DefaultReasonRegistry())
		result <- productionEndpointResult{session: endpointSession, err: commitErr}
	}()
	tunnelAdmission, err := tunnelSession.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := tunnelv2.NewNativeStreamLeg(tunnelSession, tunnelAdmission)
	if err != nil {
		t.Fatal(err)
	}
	return productionTunnelLeg{pending: pending, endpoint: result}
}

func awaitProductionEndpoint(t *testing.T, result <-chan productionEndpointResult) carrier.Session {
	t.Helper()
	select {
	case endpoint := <-result:
		if endpoint.err != nil {
			t.Fatal(endpoint.err)
		}
		return endpoint.session
	case <-time.After(10 * time.Second):
		t.Fatal("production tunnel admission timed out")
		return nil
	}
}

func establishProductionSessionPair(
	t *testing.T,
	clientCarrierSession carrier.Session,
	serverCarrierSession carrier.Session,
	clientConfig flowersession.Config,
	serverConfig flowersession.Config,
) (flowersession.SessionV2, flowersession.SessionV2) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	type result struct {
		session flowersession.SessionV2
		err     error
	}
	serverResult := make(chan result, 1)
	go func() {
		established, err := flowersession.Establish(ctx, serverCarrierSession, serverConfig)
		serverResult <- result{session: established, err: err}
	}()
	clientSession, err := flowersession.Establish(ctx, clientCarrierSession, clientConfig)
	if err != nil {
		t.Fatalf("client encrypted session establish: %v", err)
	}
	server := <-serverResult
	if server.err != nil {
		t.Fatalf("server encrypted session establish: %v", server.err)
	}
	return clientSession, server.session
}

func assertEncryptedSessionRoundTrip(
	t *testing.T,
	opener flowersession.SessionV2,
	responder flowersession.SessionV2,
	kind, request, response string,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	acceptedResult := make(chan struct {
		incoming flowersession.IncomingStream
		err      error
	}, 1)
	go func() {
		incoming, err := responder.AcceptStream(ctx)
		acceptedResult <- struct {
			incoming flowersession.IncomingStream
			err      error
		}{incoming: incoming, err: err}
	}()
	opened, err := opener.OpenStream(ctx, kind, flowersession.Metadata{"direction": kind})
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	accepted := <-acceptedResult
	if accepted.err != nil {
		t.Fatal(accepted.err)
	}
	defer accepted.incoming.Stream.Close()
	if accepted.incoming.Kind != kind || accepted.incoming.Metadata["direction"] != kind {
		t.Fatalf("incoming stream contract = %+v", accepted.incoming)
	}
	if _, err := opened.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	if err := opened.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	gotRequest, err := io.ReadAll(accepted.incoming.Stream)
	if err != nil || string(gotRequest) != request {
		t.Fatalf("encrypted request = %q, %v", gotRequest, err)
	}
	if _, err := accepted.incoming.Stream.Write([]byte(response)); err != nil {
		t.Fatal(err)
	}
	if err := accepted.incoming.Stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	gotResponse, err := io.ReadAll(opened)
	if err != nil || string(gotResponse) != response {
		t.Fatalf("encrypted response = %q, %v", gotResponse, err)
	}
}

func productionTunnelContract(t *testing.T) artifactv2.SessionContract {
	t.Helper()
	contract := artifactv2.SessionContract{
		ChannelID: "channel", InitExpireAtUnixSeconds: time.Now().Add(time.Hour).Unix(),
		IdleTimeoutSeconds: 60, EstablishTimeoutSeconds: 30,
		RekeyPrepareTimeoutSeconds: 10, RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams: 32, AllowedSuites: []uint16{1}, DefaultSuite: 1,
	}
	for index := range contract.E2EEPSK {
		contract.E2EEPSK[index] = byte(index + 1)
	}
	hash, _, err := artifactv2.ComputeSessionContractHash(contract)
	if err != nil {
		t.Fatal(err)
	}
	contract.ContractHash = hash
	return contract
}

func productionTunnelSessionConfigs(
	contract artifactv2.SessionContract,
	clientFSB2, serverFSB2 []byte,
) (flowersession.Config, flowersession.Config) {
	base := flowersession.Config{
		Path: flowersession.PathTunnel, ChannelID: contract.ChannelID,
		SessionContractHash: contract.ContractHash, Suite: protocolv2.Suite(contract.DefaultSuite),
		PSK: contract.E2EEPSK, MaxInboundStreams: contract.MaxInboundStreams,
		IdleTimeout:            time.Duration(contract.IdleTimeoutSeconds) * time.Second,
		EstablishTimeout:       time.Duration(contract.EstablishTimeoutSeconds) * time.Second,
		RekeyPrepareTimeout:    time.Duration(contract.RekeyPrepareTimeoutSeconds) * time.Second,
		RekeyCompletionTimeout: time.Duration(contract.RekeyCompletionTimeoutSeconds) * time.Second,
	}
	client := base
	client.Role = flowersession.RoleClient
	client.LocalAdmissionBinding = artifactv2.AdmissionBinding(clientFSB2)
	client.PeerAdmissionBinding = artifactv2.AdmissionBinding(serverFSB2)
	client.LocalEndpointInstanceID = "client"
	client.ExpectedPeerEndpointInstanceID = "server"
	server := base
	server.Role = flowersession.RoleServer
	server.LocalAdmissionBinding = artifactv2.AdmissionBinding(serverFSB2)
	server.PeerAdmissionBinding = artifactv2.AdmissionBinding(clientFSB2)
	server.LocalEndpointInstanceID = "server"
	server.ExpectedPeerEndpointInstanceID = "client"
	return client, server
}

func productionCarrierTLS(t *testing.T, nextProtocol string) (*tls.Config, *tls.Config) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	return &tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{nextProtocol},
		}, &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost", NextProtos: []string{nextProtocol},
		}
}
