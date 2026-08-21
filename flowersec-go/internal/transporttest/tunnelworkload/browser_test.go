package tunnelworkload

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/candidatev3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/connectv3"
	flowersession "github.com/floegence/flowersec/flowersec-go/v3/internal/sessionv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/transporttest"
)

func TestBrowserTunnelTopologiesUseProductionWebTransportBrokerPath(t *testing.T) {
	for _, topology := range BrowserTopologies() {
		t.Run(string(topology), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			endpoint, err := OpenBrowserEndpointAt(ctx, topology, "127.0.0.1", "https://127.0.0.1:9000")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cleanupCancel()
				if err := endpoint.Close(cleanupCtx); err != nil {
					t.Error(err)
				}
			}()

			issued, err := endpoint.IssueBrowserArtifact()
			if err != nil {
				t.Fatal(err)
			}
			if err := issued.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			artifact, err := artifactv3.DecodeArtifactJSON(strings.NewReader(issued.ArtifactJSON()))
			if err != nil {
				t.Fatal(err)
			}
			browserSession := connectBrowserWebTransport(t, ctx, endpoint, *artifact)
			serverSession, err := issued.AwaitServer(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer browserSession.Close()
			defer serverSession.Close()

			payload := json.RawMessage(`"browser-tunnel-rpc"`)
			var response json.RawMessage
			if err := browserSession.RPC().Call(ctx, 1, payload, &response); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(response, payload) {
				t.Fatalf("RPC response = %s", response)
			}
			if topology == BrowserTunnelWTQUIC {
				if err := roundTripTunnelDatagrams(ctx, browserSession, serverSession); err != nil {
					t.Fatal(err)
				}
			}

			serverDone := make(chan error, 1)
			go func() { serverDone <- transporttest.ServeBrowserBulkV3(ctx, serverSession, []int64{4096}) }()
			if err := runBrowserBulkClient(ctx, browserSession, 4096); err != nil {
				t.Fatal(err)
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func roundTripTunnelDatagrams(ctx context.Context, client, server flowersession.Session) error {
	clientChannel, err := client.UnreliableMessages()
	if err != nil {
		return err
	}
	serverChannel, err := server.UnreliableMessages()
	if err != nil {
		return err
	}
	request := []byte("webtransport-tunnel-datagram-request")
	response := []byte("webtransport-tunnel-datagram-response")
	status, err := clientChannel.Send(ctx, request, flowersession.UnreliableSendOptions{ExpiresAt: time.Now().Add(5 * time.Second)})
	if err != nil {
		return fmt.Errorf("client datagram send: %w", err)
	}
	if status != flowersession.UnreliableAccepted {
		return fmt.Errorf("client datagram send status = %q", status)
	}
	received, err := serverChannel.Receive(ctx)
	if err != nil {
		return fmt.Errorf("server datagram receive: %w", err)
	}
	if !bytes.Equal(received, request) {
		return fmt.Errorf("server datagram receive = %q", received)
	}
	status, err = serverChannel.Send(ctx, response, flowersession.UnreliableSendOptions{ExpiresAt: time.Now().Add(5 * time.Second)})
	if err != nil {
		return fmt.Errorf("server datagram send: %w", err)
	}
	if status != flowersession.UnreliableAccepted {
		return fmt.Errorf("server datagram send status = %q", status)
	}
	received, err = clientChannel.Receive(ctx)
	if err != nil {
		return fmt.Errorf("client datagram receive: %w", err)
	}
	if !bytes.Equal(received, response) {
		return fmt.Errorf("client datagram receive = %q", received)
	}
	return nil
}

func connectBrowserWebTransport(t *testing.T, ctx context.Context, endpoint *BrowserEndpoint, artifact artifactv3.Artifact) flowersession.Session {
	t.Helper()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: endpoint.roots, ServerName: "127.0.0.1"}
	dial, err := candidatev3.NewWebTransportCarrierDial(candidatev3.WebTransportDialConfig{
		TLSConfig: tlsConfig, Limits: quicbase.DefaultLimits(), Origin: "https://127.0.0.1:9000",
	})
	if err != nil {
		t.Fatal(err)
	}
	factory, err := candidatev3.NewFactory(map[artifactv3.Carrier]candidatev3.Dial{
		artifactv3.CarrierWebTransport: dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	connector := connectv3.NewConnector(connectv3.ArtifactLease{
		Artifact: artifact, CommitSpend: func(context.Context) error { return nil },
	}, factory)
	result, err := connector.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Candidate.ID != "browser-leg" || result.Candidate.Carrier != artifactv3.CarrierWebTransport {
		t.Fatalf("browser selected %+v", result.Candidate)
	}
	return result.Session
}

func runBrowserBulkClient(ctx context.Context, session flowersession.Session, byteCount int64) error {
	outgoing, err := session.OpenStream(ctx, "release-bulk", flowersession.Metadata{"direction": "client-to-server"})
	if err != nil {
		return err
	}
	completed := false
	defer func() {
		if !completed {
			_ = outgoing.Reset()
		}
	}()
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := io.CopyN(outgoing, bytes.NewReader(bytes.Repeat([]byte{0xa5}, int(byteCount))), byteCount)
		writeDone <- errors.Join(writeErr, outgoing.CloseWrite())
	}()
	response, readErr := io.ReadAll(outgoing)
	if err := errors.Join(readErr, <-writeDone); err != nil {
		return err
	}
	if int64(len(response)) != byteCount || !bytes.Equal(response, bytes.Repeat([]byte{0x5a}, int(byteCount))) {
		return errors.New("browser bulk response mismatch")
	}
	completed = true
	return nil
}

func TestBrowserTunnelEndpointRejectsInvalidTopologyAndUsesP256Pin(t *testing.T) {
	if _, err := OpenBrowserEndpointAt(context.Background(), BrowserTopology("browser_tunnel_wt_wt"), "127.0.0.1", "http://127.0.0.1"); err == nil {
		t.Fatal("accepted browser topology outside the frozen matrix")
	}
	endpoint, err := OpenBrowserEndpointAt(context.Background(), BrowserTunnelWTWSS, "127.0.0.1", "http://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close(context.Background())
	encoded, err := endpoint.CertificateHashBase64URL()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(digest) != 32 {
		t.Fatalf("certificate hash = %q: %v", encoded, err)
	}
	expected := sha256.Sum256(endpoint.certificateDER)
	if string(digest) != string(expected[:]) {
		t.Fatalf("certificate hash does not match the served leaf DER")
	}
	certificate, err := x509.ParseCertificate(endpoint.certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		t.Fatal("browser tunnel certificate is not ECDSA P-256")
	}
}

func TestBrowserServerDialUsesConfiguredClientNamespace(t *testing.T) {
	endpoint := &Endpoint{serverDialNamespace: "missing-browser-client-netns"}
	_, err := endpoint.dialTCP(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("server dial ignored its configured client namespace")
	}
}

func TestBrowserServerRawQUICDialUsesConfiguredClientNamespace(t *testing.T) {
	endpoint := &Endpoint{serverDialNamespace: "missing-browser-client-netns"}
	_, err := endpoint.dialRawQUIC(context.Background(), "127.0.0.1:1", nil, quicbase.DefaultLimits())
	if err == nil || !strings.Contains(err.Error(), "network namespaces require Linux") {
		t.Fatalf("raw QUIC server dial error = %v, want namespace setup failure", err)
	}
}

func TestBrowserPeerAdmissionSignalsReadiness(t *testing.T) {
	raw := []byte("server-leg-admission")
	ready := make(chan struct{})
	expectation := &admissionExpectation{raw: raw, expectedPeer: "browser-leg", claimedReady: ready}
	endpoint := &Endpoint{expectations: map[[sha256.Size]byte]*admissionExpectation{
		sha256.Sum256(raw): expectation,
	}}
	decoded := &artifactv3.DecodedRequest{Raw: raw}
	if _, err := endpoint.authorize(context.Background(), decoded); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ready:
	default:
		t.Fatal("server admission did not signal readiness")
	}
	if _, err := endpoint.authorize(context.Background(), decoded); err == nil {
		t.Fatal("claimed server admission was accepted twice")
	}
}

func TestBrowserReleaseEndpointPairTimeoutCoversColdPhase(t *testing.T) {
	plan := transporttest.ProfilePlan{
		Cold: transporttest.ColdPlan{OperationDeadlineSeconds: 53, PhaseDeadlineSeconds: 55},
	}
	endpoint, err := OpenBrowserReleaseEndpointAt(context.Background(), BrowserTunnelWTQUIC, "127.0.0.1", "http://127.0.0.1", plan)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close(context.Background())
	if _, err := OpenBrowserReleaseEndpointAt(context.Background(), BrowserTunnelWTQUIC, "127.0.0.1", "http://127.0.0.1", transporttest.ProfilePlan{
		Cold: transporttest.ColdPlan{OperationDeadlineSeconds: 55, PhaseDeadlineSeconds: 54},
	}); err == nil {
		t.Fatal("accepted browser release profile whose pair timeout cannot cover cold phase")
	}
}

func TestBrowserArtifactPreservesPeerFailureWhenCancellationRacesResult(t *testing.T) {
	peerFailure := errors.New("server leg admission failed")
	for range 64 {
		endpointCtx, endpointCancel := context.WithCancelCause(context.Background())
		endpoint := &Endpoint{ctx: endpointCtx, cancel: endpointCancel, expectations: make(map[[32]byte]*admissionExpectation)}
		browserExpectation := &admissionExpectation{}
		serverExpectation := &admissionExpectation{}
		endpoint.expectations[[32]byte{}] = serverExpectation
		artifactCtx, artifactCancel := context.WithCancelCause(endpointCtx)
		artifact := &BrowserArtifact{
			endpoint:           endpoint,
			browserExpectation: browserExpectation,
			serverExpectation:  serverExpectation,
			result:             make(chan browserConnectResult),
			ctx:                artifactCtx,
			cancel:             artifactCancel,
		}
		go func() { artifact.result <- browserConnectResult{err: peerFailure} }()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := artifact.AwaitServer(ctx)
		if !errors.Is(err, peerFailure) {
			t.Fatalf("peer failure was masked by cancellation: %v", err)
		}
	}
}

func TestBrowserArtifactWaitsForPeerFailureAfterCancellation(t *testing.T) {
	peerFailure := errors.New("server leg session handshake failed")
	endpointCtx, endpointCancel := context.WithCancelCause(context.Background())
	defer endpointCancel(context.Canceled)
	endpoint := &Endpoint{ctx: endpointCtx, cancel: endpointCancel, expectations: make(map[[32]byte]*admissionExpectation)}
	browserExpectation := &admissionExpectation{}
	serverExpectation := &admissionExpectation{}
	endpoint.expectations[[32]byte{}] = serverExpectation
	artifactCtx, artifactCancel := context.WithCancelCause(endpointCtx)
	artifact := &BrowserArtifact{
		endpoint: endpoint, browserExpectation: browserExpectation, serverExpectation: serverExpectation,
		result: make(chan browserConnectResult), ctx: artifactCtx, cancel: artifactCancel,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	go func() {
		time.Sleep(10 * time.Millisecond)
		artifact.result <- browserConnectResult{err: peerFailure}
	}()

	_, err := artifact.AwaitServer(ctx)
	if !errors.Is(err, peerFailure) {
		t.Fatalf("late peer failure was masked by cancellation: %v", err)
	}
}

type browserTestSession struct {
	closed chan struct{}
}

func (s *browserTestSession) Path() flowersession.PathKind       { return flowersession.PathTunnel }
func (s *browserTestSession) EndpointInstanceID() (string, bool) { return "", false }
func (s *browserTestSession) RPC() flowersession.RPCPeer         { return nil }
func (s *browserTestSession) UnreliableMessages() (flowersession.UnreliableMessageChannel, error) {
	return nil, errors.New("unsupported")
}
func (s *browserTestSession) OpenStream(context.Context, string, flowersession.Metadata) (flowersession.ByteStream, error) {
	return nil, errors.New("unsupported")
}
func (s *browserTestSession) AcceptStream(context.Context) (flowersession.IncomingStream, error) {
	return flowersession.IncomingStream{}, errors.New("unsupported")
}
func (s *browserTestSession) Rekey(context.Context) error { return errors.New("unsupported") }
func (s *browserTestSession) ProbeLiveness(context.Context) (time.Duration, error) {
	return 0, errors.New("unsupported")
}
func (s *browserTestSession) Termination() <-chan struct{}     { return s.closed }
func (s *browserTestSession) WaitClosed(context.Context) error { return nil }
func (s *browserTestSession) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return nil
}

func TestDeliverBrowserConnectResultTransfersSessionOwnership(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan browserConnectResult)
	session := &browserTestSession{closed: make(chan struct{})}
	delivered := make(chan struct{})
	go func() {
		deliverBrowserConnectResult(ctx, result, browserConnectResult{session: session})
		close(delivered)
	}()
	select {
	case value := <-result:
		if value.session != session {
			t.Fatal("delivered a different session")
		}
	case <-time.After(time.Second):
		t.Fatal("session result was not delivered")
	}
	cancel()
	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("result delivery did not finish")
	}
	select {
	case <-session.closed:
		t.Fatal("transferred session was closed by producer")
	default:
	}
}

func TestDeliverBrowserConnectResultClosesUndeliveredSessionOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := make(chan browserConnectResult)
	session := &browserTestSession{closed: make(chan struct{})}
	deliverBrowserConnectResult(ctx, result, browserConnectResult{session: session})
	select {
	case <-session.closed:
	case <-time.After(time.Second):
		t.Fatal("undelivered session was not closed")
	}
}
