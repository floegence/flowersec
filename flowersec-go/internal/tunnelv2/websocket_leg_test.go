package tunnelv2_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/tunnelv2"
	gorillaws "github.com/gorilla/websocket"
)

func TestCoordinatorBridgesProductionWebSocketPendingLegs(t *testing.T) {
	clientConn, clientTunnelConn := newTunnelWebSocketPair(t)
	serverConn, serverTunnelConn := newTunnelWebSocketPair(t)
	resources := carrierws.DefaultResourcePolicy()
	clientLeg, err := tunnelv2.NewWebSocketPendingLeg(clientTunnelConn, resources, carrierws.LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	serverLeg, err := tunnelv2.NewWebSocketPendingLeg(serverTunnelConn, resources, carrierws.LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	coordinator := newProductionCoordinator(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientServeDone := serveLeg(coordinator, ctx, clientLeg)
	serverServeDone := serveLeg(coordinator, ctx, serverLeg)

	clientAdmission := commitWebSocketAdmission(clientConn, validTunnelFSB2ForCarrier(t, 1, "client", "wss-client", artifactv2.CarrierWebSocket))
	serverAdmission := commitWebSocketAdmission(serverConn, validTunnelFSB2ForCarrier(t, 2, "server", "wss-server", artifactv2.CarrierWebSocket))
	if err := <-clientAdmission; err != nil {
		t.Fatalf("client admission: %v", err)
	}
	if err := <-serverAdmission; err != nil {
		t.Fatalf("server admission: %v", err)
	}
	clientEndpoint, err := carrierws.NewAfterAdmission(clientConn, carrierws.ClientRole, carrierws.SubprotocolTunnel, resources, carrierws.LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	serverEndpoint, err := carrierws.NewAfterAdmission(serverConn, carrierws.ClientRole, carrierws.SubprotocolTunnel, resources, carrierws.LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}

	controlClient := openStream(t, clientEndpoint)
	controlServer := acceptStream(t, serverEndpoint)
	assertOpenStreamRoundTrip(t, controlClient, controlServer, "FSC2", "FSH2")
	cancel()
	assertProductionServeCanceled(t, clientServeDone)
	assertProductionServeCanceled(t, serverServeDone)
}

func TestCoordinatorBridgesProductionWebSocketAndNativePendingLegs(t *testing.T) {
	webSocketEndpointConn, webSocketTunnelConn := newTunnelWebSocketPair(t)
	resources := carrierws.DefaultResourcePolicy()
	webSocketLeg, err := tunnelv2.NewWebSocketPendingLeg(webSocketTunnelConn, resources, carrierws.LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	nativeEndpoint, nativeTunnel := memorySessionPair(carrier.KindQUIC)
	nativeAdmissionClient, nativeAdmissionServer := memoryStreamPair()
	nativeLeg, err := tunnelv2.NewNativeStreamLeg(nativeTunnel, nativeAdmissionServer)
	if err != nil {
		t.Fatal(err)
	}
	coordinator := newProductionCoordinator(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	webSocketServeDone := serveLeg(coordinator, ctx, webSocketLeg)
	nativeServeDone := serveLeg(coordinator, ctx, nativeLeg)
	webSocketAdmission := commitWebSocketAdmission(webSocketEndpointConn, validTunnelFSB2ForCarrier(t, 1, "client", "mixed-wss", artifactv2.CarrierWebSocket))
	nativeAdmission := make(chan error, 1)
	go func() {
		_, commitErr := admissionv2.Commit(context.Background(), nativeAdmissionClient, validTunnelFSB2(t, 2, "server", "mixed-quic"), tunnelv2.DefaultReasonRegistry())
		nativeAdmission <- commitErr
	}()
	if err := <-webSocketAdmission; err != nil {
		t.Fatal(err)
	}
	if err := <-nativeAdmission; err != nil {
		t.Fatal(err)
	}
	webSocketEndpoint, err := carrierws.NewAfterAdmission(webSocketEndpointConn, carrierws.ClientRole, carrierws.SubprotocolTunnel, resources, carrierws.LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	controlWebSocket := openStream(t, webSocketEndpoint)
	controlNative := acceptStream(t, nativeEndpoint)
	assertOpenStreamRoundTrip(t, controlWebSocket, controlNative, "FSC2", "FSH2")
	cancel()
	assertProductionServeCanceled(t, webSocketServeDone)
	assertProductionServeCanceled(t, nativeServeDone)
}

func TestCoordinatorWebSocketPendingLegRejectsExtraMessageBeforeSuccess(t *testing.T) {
	endpointConn, tunnelConn := newTunnelWebSocketPair(t)
	leg, err := tunnelv2.NewWebSocketPendingLeg(tunnelConn, carrierws.DefaultResourcePolicy(), carrierws.LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	coordinator := newProductionCoordinator(t)
	done := serveLeg(coordinator, context.Background(), leg)
	if err := endpointConn.WriteMessage(gorillaws.BinaryMessage, validTunnelFSB2ForCarrier(t, 1, "client", "early-message", artifactv2.CarrierWebSocket)); err != nil {
		t.Fatal(err)
	}
	_ = endpointConn.WriteMessage(gorillaws.BinaryMessage, []byte("early-yamux"))
	select {
	case err := <-done:
		if !errors.Is(err, carrierws.ErrUnexpectedWaitingMessage) {
			t.Fatalf("Serve error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("coordinator did not reject early WebSocket message")
	}
}

func TestCoordinatorWebSocketAuthorizerRejectDoesNotActivateYamux(t *testing.T) {
	endpointConn, tunnelConn := newTunnelWebSocketPair(t)
	leg, err := tunnelv2.NewWebSocketPendingLeg(tunnelConn, carrierws.DefaultResourcePolicy(), carrierws.LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := tunnelv2.NewCoordinator(tunnelv2.Config{}, func(context.Context, *artifactv2.DecodedRequest) (tunnelv2.Authorization, error) {
		return tunnelv2.Authorization{}, &admissionv2.ResponseError{Status: artifactv2.AdmissionRetryable, Reason: tunnelv2.ReasonCapacity}
	})
	if err != nil {
		t.Fatal(err)
	}
	done := serveLeg(coordinator, context.Background(), leg)
	_, commitErr := carrierws.CommitAdmission(
		context.Background(), endpointConn,
		validTunnelFSB2ForCarrier(t, 1, "client", "rejected-wss", artifactv2.CarrierWebSocket), tunnelv2.DefaultReasonRegistry(),
	)
	var responseError *admissionv2.ResponseError
	if !errors.As(commitErr, &responseError) || responseError.Status != artifactv2.AdmissionRetryable {
		t.Fatalf("CommitAdmission error = %v", commitErr)
	}
	if serveErr := <-done; !errors.As(serveErr, &responseError) {
		t.Fatalf("Serve error = %v", serveErr)
	}
}

func newProductionCoordinator(t *testing.T) *tunnelv2.Coordinator {
	t.Helper()
	coordinator, err := tunnelv2.NewCoordinator(tunnelv2.Config{}, func(_ context.Context, decoded *artifactv2.DecodedRequest) (tunnelv2.Authorization, error) {
		request := decoded.Request
		expected := "server"
		if request.Role == 2 {
			expected = "client"
		}
		return tunnelv2.Authorization{
			Claims: tunnelv2.VerifiedClaims{
				CredentialID: request.AttachToken, ChannelID: request.ChannelID,
				Profile: request.Profile, RendezvousGroupID: request.RendezvousGroupID,
				SessionContractHash: request.SessionContractHash, CandidateSetHash: request.CandidateSetHash,
				ListenerAudience: request.ListenerAudience, Role: request.Role,
				EndpointInstanceID: request.EndpointInstanceID, ExpectedPeerEndpointInstanceID: expected,
				AllowReplacement: true,
			},
			ExpiresAt: time.Now().Add(time.Minute), Lease: &countingLease{},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func commitWebSocketAdmission(conn *gorillaws.Conn, raw []byte) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := carrierws.CommitAdmission(context.Background(), conn, raw, tunnelv2.DefaultReasonRegistry())
		done <- err
	}()
	return done
}

func newTunnelWebSocketPair(t *testing.T) (*gorillaws.Conn, *gorillaws.Conn) {
	t.Helper()
	serverConn := make(chan *gorillaws.Conn, 1)
	upgrader := gorillaws.Upgrader{Subprotocols: []string{carrierws.SubprotocolTunnel}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err == nil {
			serverConn <- conn
		}
	}))
	t.Cleanup(server.Close)
	dialer := gorillaws.Dialer{
		Subprotocols: []string{carrierws.SubprotocolTunnel},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, // test server only
		},
	}
	client, _, err := dialer.Dial("wss"+strings.TrimPrefix(server.URL, "https"), nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case accepted := <-serverConn:
		return client, accepted
	case <-time.After(5 * time.Second):
		t.Fatal("WebSocket upgrade timed out")
		return nil, nil
	}
}

func assertProductionServeCanceled(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("production Serve did not stop")
	}
}
