package websocket

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	gorillaws "github.com/gorilla/websocket"
)

var testReasons = artifactv2.ReasonRegistry{"capacity": {}, "invalid_credential": {}}

func TestAdmissionConnectionCloseIsIdempotent(t *testing.T) {
	var calls atomic.Int32
	closeConnection := closeOnce(func() error {
		calls.Add(1)
		return nil
	})
	closeConnection()
	closeConnection()
	if got := calls.Load(); got != 1 {
		t.Fatalf("close calls = %d, want 1", got)
	}
}

func TestServeRejectsInvalidMessagesBeforeAuthorizationAndCloses(t *testing.T) {
	direct := validFSB2(t, artifactv2.PathDirect)
	tunnel := validFSB2(t, artifactv2.PathTunnel)
	oversized := make([]byte, artifactv2.FSB2HeaderSize+artifactv2.MaxCanonicalFSB2Payload+1)
	copy(oversized, "FSB2")
	oversized[4] = 2
	oversized[5] = 1
	binary.BigEndian.PutUint32(oversized[8:12], artifactv2.MaxCanonicalFSB2Payload+1)
	tests := []struct {
		name        string
		messageType int
		payload     []byte
	}{
		{name: "non binary", messageType: gorillaws.TextMessage, payload: direct},
		{name: "truncated FSB2", messageType: gorillaws.BinaryMessage, payload: direct[:artifactv2.FSB2HeaderSize-1]},
		{name: "oversized FSB2", messageType: gorillaws.BinaryMessage, payload: oversized},
		{name: "path mismatch", messageType: gorillaws.BinaryMessage, payload: tunnel},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			client, server := newWebSocketPair(t, carrierws.SubprotocolDirect)
			var authorized atomic.Bool
			result := make(chan error, 1)
			go func() {
				_, err := Serve(context.Background(), server, testReasons, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
					authorized.Store(true)
					return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
				})
				result <- err
			}()
			if err := client.WriteMessage(testCase.messageType, testCase.payload); err != nil {
				t.Fatalf("write invalid message: %v", err)
			}
			if err := receiveResult(t, result); !errors.Is(err, ErrInvalidAdmissionMessage) {
				t.Fatalf("Serve error = %v", err)
			}
			if authorized.Load() {
				t.Fatal("authorizer ran for invalid admission message")
			}
			assertPeerClosed(t, client)
		})
	}
}

func TestServeAuthorizationFailuresCloseConnection(t *testing.T) {
	tests := []struct {
		name      string
		authorize admissionv2.Authorize
		want      error
		response  bool
	}{
		{
			name: "authorizer error",
			authorize: func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
				return artifactv2.AdmissionResponse{}, errAuthorize
			},
			want: errAuthorize,
		},
		{
			name: "rejected",
			authorize: func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
				return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionReject, Reason: "invalid_credential"}, nil
			},
			want:     admissionv2.ErrAdmissionRejected,
			response: true,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			client, server := newWebSocketPair(t, carrierws.SubprotocolDirect)
			result := make(chan error, 1)
			go func() {
				_, err := Serve(context.Background(), server, testReasons, testCase.authorize)
				result <- err
			}()
			if err := client.WriteMessage(gorillaws.BinaryMessage, validFSB2(t, artifactv2.PathDirect)); err != nil {
				t.Fatal(err)
			}
			if testCase.response {
				messageType, payload, err := client.ReadMessage()
				if err != nil || messageType != gorillaws.BinaryMessage {
					t.Fatalf("read rejection = type %d, err %v", messageType, err)
				}
				response, err := artifactv2.ParseResponse(payload, testReasons)
				if err != nil || response.Status != artifactv2.AdmissionReject {
					t.Fatalf("rejection response = %+v, %v", response, err)
				}
			}
			if err := receiveResult(t, result); !errors.Is(err, testCase.want) {
				t.Fatalf("Serve error = %v, want %v", err, testCase.want)
			}
			assertPeerClosed(t, client)
		})
	}
}

func TestServeCancellationInterruptsReadAndCloses(t *testing.T) {
	client, server := newWebSocketPair(t, carrierws.SubprotocolDirect)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := Serve(ctx, server, testReasons, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
			return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
		})
		result <- err
	}()
	cancel()
	if err := receiveResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve error = %v", err)
	}
	assertPeerClosed(t, client)
}

func TestServeRejectsInvalidSubprotocolAndNilAuthorizer(t *testing.T) {
	t.Run("subprotocol", func(t *testing.T) {
		client, server := newWebSocketPair(t, "flowersec.unknown.v2")
		result := make(chan error, 1)
		go func() {
			_, err := Serve(context.Background(), server, testReasons, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
				return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
			})
			result <- err
		}()
		if err := receiveResult(t, result); !errors.Is(err, carrierws.ErrInvalidSubprotocol) {
			t.Fatalf("Serve error = %v", err)
		}
		assertPeerClosed(t, client)
	})

	t.Run("nil authorizer", func(t *testing.T) {
		client, server := newWebSocketPair(t, carrierws.SubprotocolDirect)
		result := make(chan error, 1)
		go func() {
			_, err := Serve(context.Background(), server, testReasons, nil)
			result <- err
		}()
		if err := receiveResult(t, result); !errors.Is(err, admissionv2.ErrInvalidAuthorizer) {
			t.Fatalf("Serve error = %v", err)
		}
		assertPeerClosed(t, client)
	})
}

func TestServeCancellationBeforeResponseWriteCloses(t *testing.T) {
	client, server := newWebSocketPair(t, carrierws.SubprotocolDirect)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := Serve(ctx, server, testReasons, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
			cancel()
			return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
		})
		result <- err
	}()
	if err := client.WriteMessage(gorillaws.BinaryMessage, validFSB2(t, artifactv2.PathDirect)); err != nil {
		t.Fatal(err)
	}
	if err := receiveResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve error = %v", err)
	}
	assertPeerClosed(t, client)
}

func TestServeSuccessKeepsConnectionForSession(t *testing.T) {
	client, server := newWebSocketPair(t, carrierws.SubprotocolDirect)
	result := make(chan error, 1)
	go func() {
		_, err := Serve(context.Background(), server, testReasons, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
			return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
		})
		result <- err
	}()
	if err := client.WriteMessage(gorillaws.BinaryMessage, validFSB2(t, artifactv2.PathDirect)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.ReadMessage(); err != nil {
		t.Fatalf("read success response: %v", err)
	}
	if err := receiveResult(t, result); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if err := client.WriteMessage(gorillaws.BinaryMessage, []byte("session-data")); err != nil {
		t.Fatalf("write after admission: %v", err)
	}
	messageType, payload, err := server.ReadMessage()
	if err != nil || messageType != gorillaws.BinaryMessage || string(payload) != "session-data" {
		t.Fatalf("post-admission message = type %d payload %q err %v", messageType, payload, err)
	}
}

func TestCommitRejectsInvalidResponsesAndCloses(t *testing.T) {
	validResponse, err := artifactv2.MarshalResponse(artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, testReasons)
	if err != nil {
		t.Fatal(err)
	}
	oversized := make([]byte, artifactv2.FSA2HeaderSize+artifactv2.MaxAdmissionReasonBytes+1)
	copy(oversized, "FSA2")
	tests := []struct {
		name        string
		messageType int
		payload     []byte
	}{
		{name: "non binary", messageType: gorillaws.TextMessage, payload: validResponse},
		{name: "truncated FSA2", messageType: gorillaws.BinaryMessage, payload: validResponse[:artifactv2.FSA2HeaderSize-1]},
		{name: "oversized FSA2", messageType: gorillaws.BinaryMessage, payload: oversized},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			client, server := newWebSocketPair(t, carrierws.SubprotocolDirect)
			peerErr := make(chan error, 1)
			go func() {
				_, _, readErr := server.ReadMessage()
				if readErr == nil {
					readErr = server.WriteMessage(testCase.messageType, testCase.payload)
				}
				peerErr <- readErr
			}()
			_, err := Commit(context.Background(), client, validFSB2(t, artifactv2.PathDirect), testReasons)
			if !errors.Is(err, ErrInvalidAdmissionMessage) {
				t.Fatalf("Commit error = %v, want bounded admission failure", err)
			}
			if err := receiveResult(t, peerErr); err != nil {
				t.Fatalf("peer exchange: %v", err)
			}
			assertPeerClosed(t, server)
		})
	}
}

func TestCommitRejectsPathMismatchBeforeSendingCredential(t *testing.T) {
	client, server := newWebSocketPair(t, carrierws.SubprotocolDirect)
	_ = server.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err := Commit(context.Background(), client, validFSB2(t, artifactv2.PathTunnel), testReasons)
	if !errors.Is(err, ErrInvalidAdmissionMessage) {
		t.Fatalf("Commit error = %v", err)
	}
	if _, _, readErr := server.ReadMessage(); readErr == nil {
		t.Fatal("client sent mismatched FSB2 before rejecting it")
	}
}

func TestCommitRejectsInvalidSubprotocolBeforeSendingCredential(t *testing.T) {
	client, server := newWebSocketPair(t, "flowersec.unknown.v2")
	_ = server.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err := Commit(context.Background(), client, validFSB2(t, artifactv2.PathDirect), testReasons)
	if !errors.Is(err, carrierws.ErrInvalidSubprotocol) {
		t.Fatalf("Commit error = %v", err)
	}
	if _, _, readErr := server.ReadMessage(); readErr == nil {
		t.Fatal("client sent FSB2 on an unregistered subprotocol")
	}
}

func TestCommitRejectAndCancellationCloseConnection(t *testing.T) {
	t.Run("reject", func(t *testing.T) {
		client, server := newWebSocketPair(t, carrierws.SubprotocolDirect)
		peerErr := make(chan error, 1)
		go func() {
			_, _, err := server.ReadMessage()
			if err == nil {
				var response []byte
				response, err = artifactv2.MarshalResponse(artifactv2.AdmissionResponse{Status: artifactv2.AdmissionRetryable, Reason: "capacity"}, testReasons)
				if err == nil {
					err = server.WriteMessage(gorillaws.BinaryMessage, response)
				}
			}
			peerErr <- err
		}()
		_, err := Commit(context.Background(), client, validFSB2(t, artifactv2.PathDirect), testReasons)
		if !errors.Is(err, admissionv2.ErrAdmissionRetryable) {
			t.Fatalf("Commit error = %v", err)
		}
		if err := receiveResult(t, peerErr); err != nil {
			t.Fatal(err)
		}
		assertPeerClosed(t, server)
	})

	t.Run("cancel blocked response read", func(t *testing.T) {
		client, server := newWebSocketPair(t, carrierws.SubprotocolDirect)
		ctx, cancel := context.WithCancel(context.Background())
		requestRead := make(chan struct{})
		go func() {
			_, _, _ = server.ReadMessage()
			close(requestRead)
		}()
		result := make(chan error, 1)
		go func() {
			_, err := Commit(ctx, client, validFSB2(t, artifactv2.PathDirect), testReasons)
			result <- err
		}()
		<-requestRead
		cancel()
		if err := receiveResult(t, result); !errors.Is(err, context.Canceled) {
			t.Fatalf("Commit error = %v", err)
		}
		assertPeerClosed(t, server)
	})
}

func TestCommitSuccessKeepsConnectionForSession(t *testing.T) {
	client, server := newWebSocketPair(t, carrierws.SubprotocolDirect)
	peerErr := make(chan error, 1)
	go func() {
		_, _, err := server.ReadMessage()
		if err == nil {
			var response []byte
			response, err = artifactv2.MarshalResponse(artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, testReasons)
			if err == nil {
				err = server.WriteMessage(gorillaws.BinaryMessage, response)
			}
		}
		peerErr <- err
	}()
	if _, err := Commit(context.Background(), client, validFSB2(t, artifactv2.PathDirect), testReasons); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := receiveResult(t, peerErr); err != nil {
		t.Fatal(err)
	}
	if err := server.WriteMessage(gorillaws.BinaryMessage, []byte("session-data")); err != nil {
		t.Fatalf("write after admission: %v", err)
	}
	messageType, payload, err := client.ReadMessage()
	if err != nil || messageType != gorillaws.BinaryMessage || string(payload) != "session-data" {
		t.Fatalf("post-admission message = type %d payload %q err %v", messageType, payload, err)
	}
}

func newWebSocketPair(t *testing.T, subprotocol string) (*gorillaws.Conn, *gorillaws.Conn) {
	t.Helper()
	accepted := make(chan *gorillaws.Conn, 1)
	upgrader := gorillaws.Upgrader{Subprotocols: []string{subprotocol}}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err == nil {
			accepted <- conn
		}
	}))
	t.Cleanup(server.Close)
	dialer := gorillaws.Dialer{Subprotocols: []string{subprotocol}}
	client, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial WebSocket: %v", err)
	}
	var peer *gorillaws.Conn
	select {
	case peer = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("WebSocket upgrade timed out")
	}
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = peer.Close() })
	return client, peer
}

func validFSB2(t *testing.T, path artifactv2.PathKind) []byte {
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
	candidate := artifactv2.Candidate{ID: "ws1", Carrier: artifactv2.CarrierWebSocket, URL: "wss://example.test/flowersec/v2/direct", WireProfile: "flowersec-direct/2"}
	artifactPath := artifactv2.ArtifactPath{
		Kind: path, RendezvousGroupID: "group-1", ListenerAudience: "listener-1", RoutingToken: "opaque",
		Candidates: []artifactv2.Candidate{candidate},
	}
	if path == artifactv2.PathTunnel {
		candidate.WireProfile = "flowersec-tunnel/2"
		candidate.URL = "wss://example.test/flowersec/v2/tunnel"
		artifactPath.Candidates = []artifactv2.Candidate{candidate}
		artifactPath.RoutingToken = ""
		artifactPath.Role = 1
		artifactPath.LocalEndpointInstanceID = "endpoint-1"
		artifactPath.ExpectedPeerEndpointInstanceID = "endpoint-2"
		artifactPath.Token = "attach-token"
	}
	artifact := artifactv2.Artifact{
		Version: 2, Profile: artifactv2.Profile, Session: session, Path: artifactPath,
		Scoped: []artifactv2.ScopeMetadata{}, Correlation: artifactv2.CorrelationContext{Version: 2, Tags: []artifactv2.CorrelationTag{}},
	}
	request, err := artifactv2.BuildRequest(artifact, "ws1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := artifactv2.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func receiveResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("admission operation timed out")
		return nil
	}
}

func assertPeerClosed(t *testing.T, peer *gorillaws.Conn) {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("peer connection remained open after failed admission")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("timed out waiting for peer connection to close")
	}
}

var errAuthorize = errors.New("authorization failed")
