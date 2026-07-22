package websocket

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/artifactv2"
	gorillaws "github.com/gorilla/websocket"
)

func TestAdmissionCompletesBeforeWebSocketSwitchesToYamux(t *testing.T) {
	clientConn, serverConn := newUpgradedPair(t, SubprotocolDirect)
	reasons := artifactv2.ReasonRegistry{"capacity": {}}
	serverDone := make(chan error, 1)
	go func() {
		_, err := ServeAdmission(context.Background(), serverConn, reasons, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
			return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
		})
		serverDone <- err
	}()
	response, err := CommitAdmission(context.Background(), clientConn, validWebSocketFSB2(t, artifactv2.PathDirect), reasons)
	if err != nil {
		t.Fatalf("CommitAdmission: %v", err)
	}
	if response.Status != artifactv2.AdmissionSuccess {
		t.Fatalf("response = %+v", response)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("ServeAdmission: %v", err)
	}

	resources := DefaultResourcePolicy()
	serverSession := make(chan *Session, 1)
	go func() {
		session, _ := NewAfterAdmission(serverConn, ServerRole, SubprotocolDirect, resources, LivenessPolicy{})
		serverSession <- session
	}()
	client, err := NewAfterAdmission(clientConn, ClientRole, SubprotocolDirect, resources, LivenessPolicy{})
	if err != nil {
		t.Fatalf("client NewAfterAdmission: %v", err)
	}
	server := <-serverSession
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	opened, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream after admission: %v", err)
	}
	if _, err := opened.Write([]byte("ready")); err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = opened.Reset()
	_ = accepted.Reset()
}

func TestAdmissionRejectsTextMessageBeforeAuthorization(t *testing.T) {
	clientConn, serverConn := newUpgradedPair(t, SubprotocolDirect)
	var authorized bool
	serverErr := make(chan error, 1)
	go func() {
		_, err := ServeAdmission(context.Background(), serverConn, artifactv2.ReasonRegistry{}, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
			authorized = true
			return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
		})
		serverErr <- err
	}()
	if err := clientConn.WriteMessage(gorillaws.TextMessage, []byte("FSB2")); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; !errors.Is(err, ErrInvalidAdmissionMessage) {
		t.Fatalf("ServeAdmission text error = %v", err)
	}
	if authorized {
		t.Fatal("text message reached authorizer")
	}
}

func TestAdmissionRejectsOversizedMessageBeforeAuthorization(t *testing.T) {
	clientConn, serverConn := newUpgradedPair(t, SubprotocolDirect)
	var authorized bool
	serverErr := make(chan error, 1)
	go func() {
		_, err := ServeAdmission(context.Background(), serverConn, artifactv2.ReasonRegistry{}, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
			authorized = true
			return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
		})
		serverErr <- err
	}()
	payload := make([]byte, artifactv2.FSB2HeaderSize+artifactv2.MaxCanonicalFSB2Payload+1)
	if err := clientConn.WriteMessage(gorillaws.BinaryMessage, payload); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; !errors.Is(err, ErrInvalidAdmissionMessage) {
		t.Fatalf("ServeAdmission oversized error = %v", err)
	}
	if authorized {
		t.Fatal("oversized message reached authorizer")
	}
}

func TestAdmissionBindsPathKindToNegotiatedSubprotocol(t *testing.T) {
	clientConn, serverConn := newUpgradedPair(t, SubprotocolDirect)
	var authorized bool
	serverErr := make(chan error, 1)
	go func() {
		_, err := ServeAdmission(context.Background(), serverConn, artifactv2.ReasonRegistry{}, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
			authorized = true
			return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
		})
		serverErr <- err
	}()
	if err := clientConn.WriteMessage(gorillaws.BinaryMessage, validWebSocketFSB2(t, artifactv2.PathTunnel)); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; !errors.Is(err, ErrInvalidAdmissionMessage) {
		t.Fatalf("ServeAdmission path binding error = %v", err)
	}
	if authorized {
		t.Fatal("mismatched path reached authorizer")
	}
}

func TestCommitAdmissionClosesConnectionOnEarlyValidationFailure(t *testing.T) {
	clientConn, serverConn := newUpgradedPair(t, SubprotocolDirect)
	_, err := CommitAdmission(context.Background(), clientConn, validWebSocketFSB2(t, artifactv2.PathTunnel), artifactv2.ReasonRegistry{})
	if !errors.Is(err, ErrInvalidAdmissionMessage) {
		t.Fatalf("CommitAdmission path error = %v", err)
	}
	assertWebSocketPeerClosed(t, serverConn)
}

func TestServeAdmissionClosesConnectionForMissingAuthorizer(t *testing.T) {
	clientConn, serverConn := newUpgradedPair(t, SubprotocolDirect)
	if _, err := ServeAdmission(context.Background(), serverConn, artifactv2.ReasonRegistry{}, nil); !errors.Is(err, admissionv2.ErrInvalidAuthorizer) {
		t.Fatalf("ServeAdmission nil authorizer error = %v", err)
	}
	assertWebSocketPeerClosed(t, clientConn)
}

func TestServeAdmissionCancellationIsNotClassifiedAsPeerProtocolError(t *testing.T) {
	clientConn, serverConn := newUpgradedPair(t, SubprotocolDirect)
	t.Cleanup(func() { _ = clientConn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := ServeAdmission(ctx, serverConn, artifactv2.ReasonRegistry{}, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
		return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ServeAdmission cancellation error = %v", err)
	}
	if errors.Is(err, ErrInvalidAdmissionMessage) {
		t.Fatalf("cancellation was classified as invalid peer framing: %v", err)
	}
}

func TestAdmissionCancellationGuardWaitsForStartedClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	guard := newAdmissionCancellation(ctx, func() {
		close(closeStarted)
		<-releaseClose
	})
	cancel()
	<-closeStarted

	finished := make(chan error, 1)
	go func() { finished <- guard.stopAndWait() }()
	select {
	case err := <-finished:
		t.Fatalf("stopAndWait returned before close completed: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	close(releaseClose)
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("stopAndWait error = %v", err)
	}
}

func TestCommitAdmissionReturnsStableFSA2Error(t *testing.T) {
	clientConn, serverConn := newUpgradedPair(t, SubprotocolTunnel)
	reasons := artifactv2.ReasonRegistry{"capacity": {}}
	go func() {
		_, _ = ServeAdmission(context.Background(), serverConn, reasons, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
			return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionRetryable, Reason: "capacity"}, nil
		})
	}()
	response, err := CommitAdmission(context.Background(), clientConn, validWebSocketFSB2(t, artifactv2.PathTunnel), reasons)
	var responseErr *admissionv2.ResponseError
	if !errors.As(err, &responseErr) || response.Status != artifactv2.AdmissionRetryable || responseErr.Reason != "capacity" {
		t.Fatalf("response/error = %+v/%v", response, err)
	}
}

func validWebSocketFSB2(t *testing.T, kind artifactv2.PathKind) []byte {
	t.Helper()
	session := artifactv2.SessionContract{
		ChannelID: "channel-1", InitExpireAtUnixSeconds: time.Now().Add(time.Hour).Unix(), IdleTimeoutSeconds: 60,
		EstablishTimeoutSeconds: 30, RekeyPrepareTimeoutSeconds: 10, RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams: 32, AllowedSuites: []uint16{1, 2}, DefaultSuite: 1,
	}
	for index := range session.E2EEPSK {
		session.E2EEPSK[index] = byte(index + 1)
	}
	hash, _, err := artifactv2.ComputeSessionContractHash(session)
	if err != nil {
		t.Fatal(err)
	}
	session.ContractHash = hash
	path := artifactv2.ArtifactPath{
		Kind: kind, RendezvousGroupID: "group-1", ListenerAudience: "listener-1",
		Candidates: []artifactv2.Candidate{{ID: "w1", Carrier: artifactv2.CarrierWebSocket, URL: "wss://example.test/flowersec/v2/" + string(kind), WireProfile: "flowersec-" + string(kind) + "/2"}},
	}
	if kind == artifactv2.PathDirect {
		path.RoutingToken = "opaque"
	} else {
		path.Role = 1
		path.LocalEndpointInstanceID = "endpoint-client"
		path.ExpectedPeerEndpointInstanceID = "endpoint-server"
		path.Token = "opaque"
	}
	artifact := artifactv2.Artifact{
		Version: 2, Profile: artifactv2.Profile, Session: session,
		Path:   path,
		Scoped: []artifactv2.ScopeMetadata{}, Correlation: artifactv2.CorrelationContext{Version: 2, Tags: []artifactv2.CorrelationTag{}},
	}
	request, err := artifactv2.BuildRequest(artifact, "w1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := artifactv2.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertWebSocketPeerClosed(t *testing.T, conn *gorillaws.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _, err := conn.ReadMessage()
	if err == nil {
		t.Fatal("peer connection remained readable after admission failure")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatalf("peer connection remained open after admission failure: %v", err)
	}
}
