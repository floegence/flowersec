package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	gorillaws "github.com/gorilla/websocket"
)

func TestEngineRawQUICCarrierConformanceSmoke(t *testing.T) {
	serverTLS, clientTLS := engineTestTLS(t)
	serverTLS.NextProtos = []string{rawquic.ALPNDirect}
	clientTLS.NextProtos = []string{rawquic.ALPNDirect}
	limits, err := rawquic.BindSessionLimits(rawquic.DefaultLimits(), 4)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverCarrierCh := make(chan carrier.Session, 1)
	serverCarrierErr := make(chan error, 1)
	go func() {
		accepted, err := listener.Accept(context.Background())
		if err != nil {
			serverCarrierErr <- err
			return
		}
		serverCarrierCh <- accepted
	}()
	clientCarrier, err := rawquic.Dial(context.Background(), listener.Addr().String(), clientTLS, limits)
	if err != nil {
		t.Fatal(err)
	}
	var serverCarrier carrier.Session
	select {
	case serverCarrier = <-serverCarrierCh:
	case err := <-serverCarrierErr:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("raw QUIC accept timed out")
	}
	clientConfig, serverConfig := directEngineConfigs(4)
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	assertCarrierEngineSmoke(t, client, server)
}

func TestEngineWebSocketCarrierConformanceSmoke(t *testing.T) {
	clientCarrier, serverCarrier := newEngineWebSocketCarrierPair(t)
	clientConfig, serverConfig := directEngineConfigs(4)
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	assertCarrierEngineSmoke(t, client, server)
}

func assertCarrierEngineSmoke(t *testing.T, client, server *engineSession) {
	t.Helper()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan IncomingStream, 1)
	acceptErr := make(chan error, 1)
	go func() {
		incoming, err := server.AcceptStream(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- incoming
	}()
	opened, err := client.OpenStream(ctx, "carrier-smoke", Metadata{"carrier": string(client.ChosenCarrier())})
	if err != nil {
		t.Fatal(err)
	}
	peer := awaitIncoming(t, accepted, acceptErr)
	readResult := readAllAsync(peer.Stream)
	if _, err := opened.Write([]byte("encrypted carrier smoke")); err != nil {
		t.Fatal(err)
	}
	if err := opened.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	result := <-readResult
	if result.err != nil || string(result.payload) != "encrypted carrier smoke" {
		t.Fatalf("payload=%q error=%v", result.payload, result.err)
	}
}

func directEngineConfigs(maxInbound uint16) (Config, Config) {
	client, server := testEngineConfigs(maxInbound)
	client.Path = PathDirect
	client.LocalEndpointInstanceID = ""
	client.ExpectedPeerEndpointInstanceID = ""
	server.Path = PathDirect
	server.LocalEndpointInstanceID = ""
	server.ExpectedPeerEndpointInstanceID = ""
	return client, server
}

func engineTestTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}},
	}, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost"}
}

func newEngineWebSocketCarrierPair(t *testing.T) (carrier.Session, carrier.Session) {
	t.Helper()
	serverConnCh := make(chan *gorillaws.Conn, 1)
	upgrader := gorillaws.Upgrader{Subprotocols: []string{carrierws.SubprotocolDirect}}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err == nil {
			serverConnCh <- conn
		}
	}))
	server.EnableHTTP2 = false
	server.StartTLS()
	t.Cleanup(server.Close)
	dialer := gorillaws.Dialer{
		Subprotocols: []string{carrierws.SubprotocolDirect},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, // Local test server only.
		},
	}
	url := "wss" + strings.TrimPrefix(server.URL, "https")
	clientConn, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	var serverConn *gorillaws.Conn
	select {
	case serverConn = <-serverConnCh:
	case <-time.After(5 * time.Second):
		t.Fatal("WebSocket upgrade timed out")
	}
	resources, err := carrierws.BindSessionResourcePolicy(carrierws.DefaultResourcePolicy(), 4)
	if err != nil {
		t.Fatal(err)
	}
	serverCarrierCh := make(chan carrier.Session, 1)
	serverCarrierErr := make(chan error, 1)
	go func() {
		session, err := carrierws.NewAfterAdmission(serverConn, carrierws.ServerRole, carrierws.SubprotocolDirect, resources, carrierws.LivenessPolicy{})
		if err != nil {
			serverCarrierErr <- err
			return
		}
		serverCarrierCh <- session
	}()
	clientCarrier, err := carrierws.NewAfterAdmission(clientConn, carrierws.ClientRole, carrierws.SubprotocolDirect, resources, carrierws.LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case serverCarrier := <-serverCarrierCh:
		return clientCarrier, serverCarrier
	case err := <-serverCarrierErr:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("WebSocket carrier setup timed out")
	}
	return nil, nil
}
