package session

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/rpc"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/v2/internal/rpcwire"
)

func TestSessionTerminationCanBeObservedAndWaited(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 1)
	defer server.Close()

	terminated := client.Termination()
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-terminated:
	case <-time.After(time.Second):
		t.Fatal("Termination was not closed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.WaitClosed(ctx); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("WaitClosed error = %v, want ErrSessionClosed", err)
	}
	canceled, cancelCanceled := context.WithCancel(context.Background())
	cancelCanceled()
	for range 32 {
		if err := client.WaitClosed(canceled); !errors.Is(err, ErrSessionClosed) {
			t.Fatalf("WaitClosed after termination error = %v, want stable ErrSessionClosed", err)
		}
	}
}

func TestEstablishAndBidirectionalLogicalStreams(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 4)
	defer client.Close()
	defer server.Close()

	if client.Path() != PathTunnel || client.ChosenCarrier() != carrier.KindQUIC {
		t.Fatalf("client identity = path:%s carrier:%s", client.Path(), client.ChosenCarrier())
	}
	if got, ok := client.EndpointInstanceID(); !ok || got != "server-instance" {
		t.Fatalf("client peer endpoint = %q, %v", got, ok)
	}
	if got, ok := server.EndpointInstanceID(); !ok || got != "client-instance" {
		t.Fatalf("server peer endpoint = %q, %v", got, ok)
	}

	clientIncoming := make(chan IncomingStream, 1)
	clientAcceptErr := make(chan error, 1)
	go acceptOne(client, clientIncoming, clientAcceptErr)
	serverIncoming := make(chan IncomingStream, 1)
	serverAcceptErr := make(chan error, 1)
	go acceptOne(server, serverIncoming, serverAcceptErr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	clientStream, err := client.OpenStream(ctx, "rpc.echo", Metadata{"request": "client"})
	if err != nil {
		t.Fatalf("client OpenStream: %v", err)
	}
	if clientStream.ID() != 1 || clientStream.ID()%2 != 1 {
		t.Fatalf("client logical id = %d", clientStream.ID())
	}
	serverAccepted := awaitIncoming(t, serverIncoming, serverAcceptErr)
	if serverAccepted.ID != clientStream.ID() || serverAccepted.Kind != "rpc.echo" || serverAccepted.Metadata["request"] != "client" {
		t.Fatalf("server accepted = %+v", serverAccepted)
	}

	serverStream, err := server.OpenStream(ctx, "events", Metadata{"request": "server"})
	if err != nil {
		t.Fatalf("server OpenStream: %v", err)
	}
	if serverStream.ID() != 2 || serverStream.ID()%2 != 0 {
		t.Fatalf("server logical id = %d", serverStream.ID())
	}
	clientAccepted := awaitIncoming(t, clientIncoming, clientAcceptErr)
	if clientAccepted.ID != serverStream.ID() || clientAccepted.Kind != "events" || clientAccepted.Metadata["request"] != "server" {
		t.Fatalf("client accepted = %+v", clientAccepted)
	}

	assertHalfCloseRoundTrip(t, clientStream, serverAccepted.Stream, []byte("client request"), []byte("server response"))
	assertHalfCloseRoundTrip(t, serverStream, clientAccepted.Stream, []byte("server event"), []byte("client ack"))
}

func TestEstablishRejectsCarrierStreamCapacityMismatchBeforeHandshake(t *testing.T) {
	clientCarrier, _ := newMemoryCarrierPair(carrier.KindQUIC)
	clientConfig, _ := testEngineConfigs(2)
	clientCarrier.setMaxIncomingStreams(5)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := Establish(ctx, clientCarrier, clientConfig); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("capacity mismatch = %v, want ErrInvalidConfig", err)
	}
	clientCarrier.streamsMu.Lock()
	openedStreams := len(clientCarrier.streams)
	clientCarrier.streamsMu.Unlock()
	if openedStreams != 0 {
		t.Fatalf("capacity mismatch opened %d carrier streams before rejection", openedStreams)
	}
}

func TestEstablishRejectsCarrierPathMismatchBeforeHandshake(t *testing.T) {
	clientCarrier, _ := newMemoryCarrierPair(carrier.KindQUIC)
	clientConfig, _ := testEngineConfigs(2)
	clientConfig.Path = PathDirect
	clientConfig.LocalEndpointInstanceID = ""
	clientConfig.ExpectedPeerEndpointInstanceID = ""

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := Establish(ctx, clientCarrier, clientConfig); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("path mismatch = %v, want ErrInvalidConfig", err)
	}
	clientCarrier.streamsMu.Lock()
	openedStreams := len(clientCarrier.streams)
	clientCarrier.streamsMu.Unlock()
	if openedStreams != 0 {
		t.Fatalf("path mismatch opened %d carrier streams before rejection", openedStreams)
	}
}

func TestRPCPeerUsesReservedEncryptedStreamsInBothDirections(t *testing.T) {
	clientRouter := rpc.NewRouter()
	serverRouter := rpc.NewRouter()
	clientNotified := make(chan string, 1)
	serverNotified := make(chan string, 1)
	clientRouter.Register(11, echoRPCHandler)
	serverRouter.Register(22, echoRPCHandler)
	clientRouter.Register(31, notifyRPCHandler(clientNotified))
	serverRouter.Register(32, notifyRPCHandler(serverNotified))

	clientConfig, serverConfig := testEngineConfigs(1)
	clientConfig.RPCRouter = clientRouter
	serverConfig.RPCRouter = serverRouter
	clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindQUIC)
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	defer client.Close()
	defer server.Close()

	if client.RPC() == nil || server.RPC() == nil {
		t.Fatal("established SessionV2 returned a nil RPC peer")
	}
	var serverResponse map[string]string
	if err := client.RPC().Call(context.Background(), 22, map[string]string{"from": "client"}, &serverResponse); err != nil {
		t.Fatalf("client RPC Call: %v", err)
	}
	if serverResponse["from"] != "client" {
		t.Fatalf("server RPC response = %#v", serverResponse)
	}
	var clientResponse map[string]string
	if err := server.RPC().Call(context.Background(), 11, map[string]string{"from": "server"}, &clientResponse); err != nil {
		t.Fatalf("server RPC Call: %v", err)
	}
	if clientResponse["from"] != "server" {
		t.Fatalf("client RPC response = %#v", clientResponse)
	}
	if err := client.RPC().Notify(context.Background(), 32, map[string]string{"event": "client"}); err != nil {
		t.Fatalf("client RPC Notify: %v", err)
	}
	if err := server.RPC().Notify(context.Background(), 31, map[string]string{"event": "server"}); err != nil {
		t.Fatalf("server RPC Notify: %v", err)
	}
	select {
	case event := <-serverNotified:
		if event != "client" {
			t.Fatalf("server notification = %q", event)
		}
	case <-time.After(time.Second):
		t.Fatal("server notification timed out")
	}
	select {
	case event := <-clientNotified:
		if event != "server" {
			t.Fatalf("client notification = %q", event)
		}
	case <-time.After(time.Second):
		t.Fatal("client notification timed out")
	}
	if err := client.Rekey(context.Background()); err != nil {
		t.Fatalf("client rekey with active RPC stream: %v", err)
	}
	if err := server.Rekey(context.Background()); err != nil {
		t.Fatalf("server rekey with active RPC stream: %v", err)
	}
	serverResponse = nil
	if err := client.RPC().Call(context.Background(), 22, map[string]string{"from": "epoch-two"}, &serverResponse); err != nil {
		t.Fatalf("RPC Call after consecutive rekey: %v", err)
	}
	if serverResponse["from"] != "epoch-two" {
		t.Fatalf("post-rekey RPC response = %#v", serverResponse)
	}

	acceptContext, cancelAccept := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelAccept()
	if _, err := server.AcceptStream(acceptContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reserved RPC stream leaked through AcceptStream: %v", err)
	}

	accepted := make(chan IncomingStream, 1)
	acceptErr := make(chan error, 1)
	go acceptOne(server, accepted, acceptErr)
	applicationStream, err := client.OpenStream(context.Background(), "application", Metadata{})
	if err != nil {
		t.Fatalf("application OpenStream after RPC: %v", err)
	}
	peer := awaitIncoming(t, accepted, acceptErr)
	if applicationStream.ID() != peer.ID {
		t.Fatalf("application stream IDs = %d/%d", applicationStream.ID(), peer.ID)
	}
	_ = applicationStream.Reset()
	_ = peer.Stream.Reset()
}

func TestOpenStreamCanonicalizesUnicodeMetadataBeforeWritingOPEN(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	accepted := make(chan IncomingStream, 1)
	acceptErr := make(chan error, 1)
	go acceptOne(server, accepted, acceptErr)
	metadata := Metadata{
		"\U00010000": "astral",
		"\ue000":     "bmp",
		"separator":  "\u2028\u2029",
	}
	stream, err := client.OpenStream(context.Background(), "rpc.\U0002ebf0", metadata)
	if err != nil {
		t.Fatalf("OpenStream Unicode metadata: %v", err)
	}
	peer := awaitIncoming(t, accepted, acceptErr)
	if peer.Kind != "rpc.\U0002ebf0" || peer.Metadata["\U00010000"] != "astral" ||
		peer.Metadata["\ue000"] != "bmp" || peer.Metadata["separator"] != "\u2028\u2029" {
		t.Fatalf("accepted Unicode metadata = kind %q metadata %#v", peer.Kind, peer.Metadata)
	}
	_ = stream.Reset()
	_ = peer.Stream.Reset()
}

func echoRPCHandler(_ context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
	return append(json.RawMessage(nil), payload...), nil
}

func notifyRPCHandler(events chan<- string) rpc.Handler {
	return func(_ context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
		var value map[string]string
		if err := json.Unmarshal(payload, &value); err == nil {
			events <- value["event"]
		}
		return nil, nil
	}
}

func TestAdmissionBindingHandshakePolicy(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Config, *Config)
		wantErr   bool
	}{
		{
			name: "direct exact",
			configure: func(client, server *Config) {
				configureDirectPair(client, server)
			},
		},
		{
			name: "direct mismatch",
			configure: func(client, server *Config) {
				configureDirectPair(client, server)
				client.PeerAdmissionBinding[0] ^= 1
			},
			wantErr: true,
		},
		{
			name: "tunnel authenticated unknown",
			configure: func(client, server *Config) {
				client.PeerAdmissionBinding = [32]byte{}
				server.PeerAdmissionBinding = [32]byte{}
			},
		},
		{
			name: "tunnel zero wire",
			configure: func(client, server *Config) {
				client.LocalAdmissionBinding = [32]byte{}
				server.PeerAdmissionBinding = [32]byte{}
			},
			wantErr: true,
		},
		{
			name: "tunnel expected mismatch",
			configure: func(client, server *Config) {
				server.PeerAdmissionBinding[0] ^= 1
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConfig, serverConfig := testEngineConfigs(2)
			tt.configure(&clientConfig, &serverConfig)
			clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindQUIC)
			client, server, clientErr, serverErr := tryEstablishPair(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
			if tt.wantErr {
				if clientErr == nil && serverErr == nil {
					client.Close()
					server.Close()
					t.Fatal("handshake unexpectedly succeeded")
				}
				return
			}
			if clientErr != nil || serverErr != nil {
				t.Fatalf("client error = %v, server error = %v", clientErr, serverErr)
			}
			defer client.Close()
			defer server.Close()
		})
	}
}

func configureDirectPair(client, server *Config) {
	client.Path = PathDirect
	server.Path = PathDirect
	client.LocalEndpointInstanceID = ""
	client.ExpectedPeerEndpointInstanceID = ""
	server.LocalEndpointInstanceID = ""
	server.ExpectedPeerEndpointInstanceID = ""
}

func TestConcurrentStreamsAreIndependentAndIDsAreNeverReused(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindWebSocket, 8)
	defer client.Close()
	defer server.Close()

	const streams = 6
	accepted := make(chan IncomingStream, streams)
	acceptErr := make(chan error, 1)
	go func() {
		for i := 0; i < streams; i++ {
			incoming, err := server.AcceptStream(context.Background())
			if err != nil {
				acceptErr <- err
				return
			}
			accepted <- incoming
		}
	}()

	opened := make(chan ByteStream, streams)
	openErr := make(chan error, streams)
	for i := 0; i < streams; i++ {
		go func(i int) {
			stream, err := client.OpenStream(context.Background(), "parallel", Metadata{"index": int64(i)})
			if err != nil {
				openErr <- err
				return
			}
			opened <- stream
		}(i)
	}

	seen := make(map[uint64]struct{}, streams)
	clientStreams := make([]ByteStream, 0, streams)
	for len(clientStreams) < streams {
		select {
		case err := <-openErr:
			t.Fatal(err)
		case stream := <-opened:
			if stream.ID()%2 != 1 {
				t.Fatalf("client id %d is not odd", stream.ID())
			}
			if _, duplicate := seen[stream.ID()]; duplicate {
				t.Fatalf("reused logical id %d", stream.ID())
			}
			seen[stream.ID()] = struct{}{}
			clientStreams = append(clientStreams, stream)
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent OpenStream timed out")
		}
	}

	serverStreams := make(map[uint64]ByteStream, streams)
	for len(serverStreams) < streams {
		select {
		case err := <-acceptErr:
			t.Fatal(err)
		case incoming := <-accepted:
			serverStreams[incoming.ID] = incoming.Stream
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent AcceptStream timed out")
		}
	}

	for _, stream := range clientStreams {
		payload := []byte{byte(stream.ID())}
		readResult := readAllAsync(serverStreams[stream.ID()])
		if _, err := stream.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := stream.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		result := <-readResult
		if result.err != nil || !bytes.Equal(result.payload, payload) {
			t.Fatalf("stream %d payload=%x error=%v", stream.ID(), result.payload, result.err)
		}
	}
}

func TestMaxInboundStreamsPermitIsContextBounded(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 1)
	defer client.Close()
	defer server.Close()

	accepted := make(chan IncomingStream, 2)
	go func() {
		for i := 0; i < 2; i++ {
			incoming, err := server.AcceptStream(context.Background())
			if err == nil {
				accepted <- incoming
			}
		}
	}()
	first, err := client.OpenStream(context.Background(), "held", Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	firstPeer := <-accepted

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if _, err := client.OpenStream(ctx, "blocked", Metadata{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("permit error = %v", err)
	}
	if err := first.Reset(); err != nil {
		t.Fatal(err)
	}
	_ = firstPeer.Stream.Reset()

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	second, err := client.OpenStream(ctx, "after-reset", Metadata{})
	if err != nil {
		t.Fatalf("OpenStream after permit release: %v", err)
	}
	if second.ID() <= first.ID() {
		t.Fatalf("logical id reused/regressed: first=%d second=%d", first.ID(), second.ID())
	}
}

func TestProbeLivenessAndSessionRekeyGateNewStreams(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 4)
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rtt, err := client.ProbeLiveness(ctx)
	if err != nil || rtt < 0 {
		t.Fatalf("ProbeLiveness = %v, %v", rtt, err)
	}
	if err := client.Rekey(ctx); err != nil {
		t.Fatalf("Rekey: %v", err)
	}

	accepted := make(chan IncomingStream, 1)
	acceptErr := make(chan error, 1)
	go acceptOne(server, accepted, acceptErr)
	stream, err := client.OpenStream(ctx, "post-rekey", Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	concrete, ok := stream.(*encryptedStream)
	if !ok || concrete.sendEpoch != 1 {
		t.Fatalf("post-rekey stream = %T epoch=%d", stream, concrete.sendEpoch)
	}
	peer := awaitIncoming(t, accepted, acceptErr)
	readResult := readAllAsync(peer.Stream)
	if _, err := stream.Write([]byte("epoch-one")); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	result := <-readResult
	if result.err != nil || string(result.payload) != "epoch-one" {
		t.Fatalf("post-rekey payload=%q error=%v", result.payload, result.err)
	}
}

func TestProbeLivenessAllowsMaximumNonceAndWrapsToZero(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	client.pingsMu.Lock()
	client.nextPing = math.MaxUint64
	client.pingsMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := client.ProbeLiveness(ctx); err != nil {
		t.Fatalf("maximum PING nonce: %v", err)
	}
	if _, err := client.ProbeLiveness(ctx); err != nil {
		t.Fatalf("wrapped zero PING nonce: %v", err)
	}
}

func TestTransitionIDMaximumIsUsedExactlyOnce(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	client.pendingRekeyMu.Lock()
	client.nextTransition = math.MaxUint64
	client.pendingRekeyMu.Unlock()
	server.recvTransition = math.MaxUint64 - 1
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Rekey(ctx); err != nil {
		t.Fatalf("maximum transition ID: %v", err)
	}
	if err := client.Rekey(ctx); !errors.Is(err, protocolv2.ErrCounterExhausted) {
		t.Fatalf("transition after maximum error = %v", err)
	}
	awaitSessionGoingAway(t, server, "transition exhaustion")
}

func TestEpochMaximumRekeySendsResourceExhaustedGoAway(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	client.cryptoMu.Lock()
	client.sendEpoch = math.MaxUint32
	client.cryptoMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Rekey(ctx); !errors.Is(err, protocolv2.ErrCounterExhausted) {
		t.Fatalf("maximum epoch Rekey error = %v", err)
	}
	awaitSessionGoingAway(t, server, "epoch exhaustion")
}

func TestControlReadDoesNotWrapEpochAfterMaximum(t *testing.T) {
	var sessionPRK, h3 [32]byte
	for i := range sessionPRK {
		sessionPRK[i] = byte(i + 1)
		h3[i] = byte(i + 33)
	}
	roots, err := protocolv2.DeriveEpochZero(sessionPRK, protocolv2.DirectionServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	material, err := protocolv2.DeriveControlMaterial(roots.ControlRoot, h3, protocolv2.DirectionServerToClient, 0)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := protocolv2.MarshalInnerRecord(protocolv2.InnerPing, make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	header := protocolv2.RecordHeader{Epoch: 0, Sequence: 0, CiphertextLength: uint32(len(inner) + protocolv2.AEADTagBytes)}
	ciphertext, err := protocolv2.SealRecord(protocolv2.SuiteChaCha20Poly1305, material.RecordKey, material.NoncePrefix, h3, 0, protocolv2.DirectionServerToClient, header, inner)
	if err != nil {
		t.Fatal(err)
	}
	rawHeader, err := header.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	local, remote := newMemoryStreamPair(context.Background(), context.Background())
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := remote.Write(append(rawHeader, ciphertext...))
		writeDone <- writeErr
	}()
	session := &engineSession{
		control: local, config: Config{Suite: protocolv2.SuiteChaCha20Poly1305}, h3: h3,
		recvDir: protocolv2.DirectionServerToClient, recvRoots: map[uint32]protocolv2.EpochRoots{0: roots},
		controlRecvEpoch: math.MaxUint32, recvSessionEpoch: math.MaxUint32,
	}
	if _, _, err := session.readControl(); !errors.Is(err, protocolv2.ErrFutureControlEpoch) {
		t.Fatalf("wrapped epoch error = %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestLogicalIDCapSendsResourceExhaustedGoAway(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()
	client.openMu.Lock()
	client.nextID = 2_097_153
	client.openMu.Unlock()
	if _, err := client.OpenStream(context.Background(), "overflow", Metadata{}); !errors.Is(err, ErrResourceExhausted) {
		t.Fatalf("logical ID overflow error = %v", err)
	}
	awaitSessionGoingAway(t, server, "logical ID exhaustion")
}

func TestLogicalIDMaximumSlotCanBeOpened(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()
	client.openMu.Lock()
	client.nextID = protocolv2.MaxLogicalStreamID(protocolv2.RoleClient)
	client.openMu.Unlock()
	accepted := make(chan IncomingStream, 1)
	acceptErr := make(chan error, 1)
	go acceptOne(server, accepted, acceptErr)
	stream, err := client.OpenStream(context.Background(), "last-slot", Metadata{})
	if err != nil {
		t.Fatalf("last logical slot: %v", err)
	}
	if stream.ID() != protocolv2.MaxLogicalStreamID(protocolv2.RoleClient) {
		t.Fatalf("last logical ID = %d", stream.ID())
	}
	peer := awaitIncoming(t, accepted, acceptErr)
	if peer.ID != stream.ID() {
		t.Fatalf("peer last logical ID = %d", peer.ID)
	}
	_ = stream.Reset()
}

func TestGoAwayRejectsInvalidLastAcceptedBoundary(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	server.openMu.Lock()
	server.nextID = 4 // server has allocated logical id 2
	server.openMu.Unlock()
	if err := server.handleControl(protocolv2.InnerGoAway, marshalIDReason(3, 2)); !errors.Is(err, ErrSessionProtocol) {
		t.Fatalf("wrong-parity GOAWAY error = %v", err)
	}
	if err := server.handleControl(protocolv2.InnerGoAway, marshalIDReason(4, 2)); !errors.Is(err, ErrSessionProtocol) {
		t.Fatalf("future GOAWAY boundary error = %v", err)
	}
	if err := server.handleControl(protocolv2.InnerGoAway, marshalIDReason(2, 2)); err != nil {
		t.Fatalf("valid GOAWAY boundary: %v", err)
	}
}

func TestSentAndReceivedGoAwayKeepIndependentBoundaries(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	server.openMu.Lock()
	server.nextID = 4 // server has allocated logical id 2
	server.openMu.Unlock()
	if err := server.sendGoAway(2); err != nil {
		t.Fatal(err)
	}
	if err := server.handleControl(protocolv2.InnerGoAway, marshalIDReason(2, 2)); err != nil {
		t.Fatalf("peer GOAWAY after local GOAWAY: %v", err)
	}
}

func TestSendGoAwayUsesPeerResolvedFrontier(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	client.ledgerMu.Lock()
	if err := client.ledger.PeerReset(2); err != nil {
		client.ledgerMu.Unlock()
		t.Fatal(err)
	}
	client.ledgerMu.Unlock()
	server.openMu.Lock()
	server.nextID = 4 // server has allocated logical id 2
	server.openMu.Unlock()
	if err := client.sendGoAway(2); err != nil {
		t.Fatal(err)
	}
	awaitSessionGoingAway(t, server, "resolved frontier")
	client.openMu.Lock()
	sentBoundary := client.sentGoAwayLastAccepted
	client.openMu.Unlock()
	server.openMu.Lock()
	receivedBoundary := server.goAwayLastAccepted
	server.openMu.Unlock()
	if sentBoundary != 2 || receivedBoundary != 2 {
		t.Fatalf("GOAWAY boundaries = sent:%d received:%d", sentBoundary, receivedBoundary)
	}
}

func TestGoAwayBoundaryCancelsAlreadyAllocatedOpening(t *testing.T) {
	clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindQUIC)
	clientConfig, serverConfig := testEngineConfigs(2)
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	defer client.Close()
	defer server.Close()

	fss2Started := make(chan struct{})
	releaseFSS2 := make(chan struct{})
	var once sync.Once
	clientCarrier.setWriteHook(func(payload []byte) {
		if bytes.HasPrefix(payload, []byte("FSS2")) {
			once.Do(func() { close(fss2Started) })
			<-releaseFSS2
		}
	})
	openResult := make(chan error, 1)
	go func() {
		_, err := client.OpenStream(context.Background(), "past-boundary", Metadata{})
		openResult <- err
	}()
	select {
	case <-fss2Started:
	case <-time.After(time.Second):
		t.Fatal("opening never reached FSS2")
	}
	if err := server.sendGoAway(2); err != nil {
		t.Fatal(err)
	}
	awaitSessionGoingAway(t, client, "peer boundary")
	close(releaseFSS2)
	if err := <-openResult; !errors.Is(err, ErrGoingAway) {
		t.Fatalf("opening past GOAWAY boundary error = %v", err)
	}
}

func TestOpenContextCancellationCommitsResetBeforeLaterRekey(t *testing.T) {
	clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindQUIC)
	clientConfig, serverConfig := testEngineConfigs(2)
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	defer client.Close()
	defer server.Close()

	ackBlocked := make(chan struct{})
	releaseACK := make(chan struct{})
	var once sync.Once
	serverCarrier.setWriteHook(func(payload []byte) {
		if bytes.HasPrefix(payload, []byte("FSR2")) {
			once.Do(func() { close(ackBlocked) })
			<-releaseACK
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	openResult := make(chan error, 1)
	go func() {
		_, err := client.OpenStream(ctx, "cancel-me", Metadata{})
		openResult <- err
	}()
	select {
	case <-ackBlocked:
	case <-time.After(time.Second):
		t.Fatal("server never attempted OPEN_ACK")
	}
	if err := <-openResult; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("OpenStream cancellation = %v", err)
	}
	acceptCtx, acceptCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer acceptCancel()
	if _, err := server.AcceptStream(acceptCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled OPEN was delivered: %v", err)
	}
	close(releaseACK)
	serverCarrier.setWriteHook(nil)

	rekeyCtx, rekeyCancel := context.WithTimeout(context.Background(), time.Second)
	defer rekeyCancel()
	if err := client.Rekey(rekeyCtx); err != nil {
		t.Fatalf("rekey after ordered reset: %v", err)
	}
}

func TestStreamAEADFailureIsStreamScoped(t *testing.T) {
	assertInjectedStreamFailureScoped(t, false, func(stream *memoryStream) { stream.mutateNextCiphertext() })
}

func TestStreamSequenceFailureIsStreamScoped(t *testing.T) {
	assertInjectedStreamFailureScoped(t, true, func(stream *memoryStream) { stream.mutateNextRecordSequence() })
}

func assertInjectedStreamFailureScoped(t *testing.T, allowSenderError bool, mutate func(*memoryStream)) {
	t.Helper()
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	accepted := make(chan IncomingStream, 2)
	acceptErr := make(chan error, 1)
	go func() {
		for i := 0; i < 2; i++ {
			incoming, err := server.AcceptStream(context.Background())
			if err != nil {
				acceptErr <- err
				return
			}
			accepted <- incoming
		}
	}()
	bad, err := client.OpenStream(context.Background(), "bad", Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	badPeer := awaitIncoming(t, accepted, acceptErr)
	badConcrete := bad.(*encryptedStream)
	badCarrier := badConcrete.carrier.(*memoryStream)
	mutate(badCarrier)
	readResult := make(chan error, 1)
	go func() {
		var one [1]byte
		_, err := badPeer.Stream.Read(one[:])
		readResult <- err
	}()
	if _, err := bad.Write([]byte("tampered")); err != nil && !allowSenderError {
		t.Fatalf("sender write: %v", err)
	}
	if err := <-readResult; !errors.Is(err, protocolv2.ErrStreamReset) {
		t.Fatalf("tampered stream read = %v", err)
	}

	good, err := client.OpenStream(context.Background(), "good", Metadata{})
	if err != nil {
		t.Fatalf("session did not survive stream AEAD failure: %v", err)
	}
	goodPeer := awaitIncoming(t, accepted, acceptErr)
	goodRead := readAllAsync(goodPeer.Stream)
	if _, err := good.Write([]byte("still alive")); err != nil {
		t.Fatal(err)
	}
	if err := good.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	result := <-goodRead
	if result.err != nil || string(result.payload) != "still alive" {
		t.Fatalf("good stream payload=%q error=%v", result.payload, result.err)
	}
}

func TestP256HandshakeAndOpen(t *testing.T) {
	clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindQUIC)
	clientConfig, serverConfig := testEngineConfigs(2)
	clientConfig.Suite = protocolv2.SuiteAES256GCM
	serverConfig.Suite = protocolv2.SuiteAES256GCM
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	defer client.Close()
	defer server.Close()
	accepted := make(chan IncomingStream, 1)
	acceptErr := make(chan error, 1)
	go acceptOne(server, accepted, acceptErr)
	stream, err := client.OpenStream(context.Background(), "p256", Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	if peer := awaitIncoming(t, accepted, acceptErr); peer.ID != stream.ID() {
		t.Fatalf("P-256 logical IDs = %d/%d", stream.ID(), peer.ID)
	}
}

func TestPeerResourceExhaustionReturnsOpenReject(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()
	server.inboundPermits <- struct{}{}
	server.inboundPermits <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := client.OpenStream(ctx, "rejected", Metadata{}); !errors.Is(err, ErrOpenRejected) {
		t.Fatalf("OpenStream rejection = %v", err)
	}
	acceptCtx, acceptCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer acceptCancel()
	if _, err := server.AcceptStream(acceptCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("resource-rejected stream was delivered: %v", err)
	}
	<-server.inboundPermits
	<-server.inboundPermits
}

func TestGoAwayRejectsNewOpenWithoutImmediateClose(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()
	if err := client.sendControl(protocolv2.InnerGoAway, marshalIDReason(0, 2)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		server.openMu.Lock()
		goingAway := server.goingAway
		server.openMu.Unlock()
		if goingAway {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("peer did not apply GOAWAY")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := server.OpenStream(context.Background(), "late", Metadata{}); !errors.Is(err, ErrGoingAway) {
		t.Fatalf("OpenStream after GOAWAY = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := server.ProbeLiveness(ctx); err != nil {
		t.Fatalf("GOAWAY closed established control path: %v", err)
	}
}

func TestHandshakeRejectsMismatchedPSK(t *testing.T) {
	clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindQUIC)
	clientConfig, serverConfig := testEngineConfigs(2)
	serverConfig.PSK[0] ^= 1
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	serverResult := make(chan error, 1)
	go func() {
		_, err := Establish(ctx, serverCarrier, serverConfig)
		serverResult <- err
	}()
	if _, err := Establish(ctx, clientCarrier, clientConfig); err == nil {
		t.Fatal("client accepted mismatched PSK")
	}
	if err := <-serverResult; err == nil {
		t.Fatal("server accepted mismatched PSK")
	}
}

func TestHandshakeContextCancelsStalledControlStream(t *testing.T) {
	clientCarrier, _ := newMemoryCarrierPair(carrier.KindQUIC)
	clientConfig, _ := testEngineConfigs(2)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := Establish(ctx, clientCarrier, clientConfig); err == nil {
		t.Fatal("stalled handshake succeeded")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("stalled handshake ignored context for %v", elapsed)
	}
}

func TestEstablishAppliesSessionTimeoutWithoutCallerDeadline(t *testing.T) {
	clientCarrier, _ := newMemoryCarrierPair(carrier.KindQUIC)
	clientConfig, _ := testEngineConfigs(2)
	clientConfig.EstablishTimeout = 30 * time.Millisecond
	started := time.Now()
	if _, err := Establish(context.Background(), clientCarrier, clientConfig); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled Establish error = %v, want deadline", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("stalled Establish ignored session timeout for %v", elapsed)
	}
}

func TestEstablishTimeoutBoundsHangingCarrierCleanup(t *testing.T) {
	clientCarrier, _ := newMemoryCarrierPair(carrier.KindQUIC)
	releaseClose := make(chan struct{})
	defer close(releaseClose)
	clientCarrier.closeBlock = releaseClose
	clientConfig, _ := testEngineConfigs(2)
	clientConfig.EstablishTimeout = 30 * time.Millisecond
	result := make(chan error, 1)
	go func() {
		_, err := Establish(context.Background(), clientCarrier, clientConfig)
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Establish error = %v, want deadline", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Establish timeout remained blocked in carrier cleanup")
	}
}

func TestSessionIdleTimeoutClosesWithoutCallerDeadline(t *testing.T) {
	clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindQUIC)
	clientConfig, serverConfig := testEngineConfigs(2)
	clientConfig.IdleTimeout = 30 * time.Millisecond
	serverConfig.IdleTimeout = 30 * time.Millisecond
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	defer client.Close()
	defer server.Close()

	select {
	case <-client.ctx.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("client ignored the signed session idle timeout")
	}
	select {
	case <-server.ctx.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("server ignored the signed session idle timeout")
	}
}

func TestCloseStopsNewOpensAndUnblocksAccept(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindWebSocket, 2)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := client.OpenStream(ctx, "closed", Metadata{}); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("OpenStream after close = %v", err)
	}
	if _, err := server.AcceptStream(ctx); err == nil {
		t.Fatal("peer AcceptStream remained open after SESSION_CLOSE")
	}
	_ = server.Close()
}

func TestCloseFlushesAuthenticatedSessionCloseBeforeCarrierShutdown(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer server.Close()

	writeBlocked := make(chan struct{})
	releaseWrite := make(chan struct{})
	var once sync.Once
	var writeMu sync.Mutex
	writeCount := 0
	client.control.(*memoryStream).setWriteHook(func(payload []byte) {
		if len(payload) >= 4 && string(payload[:4]) == "FSR2" {
			writeMu.Lock()
			writeCount++
			writeMu.Unlock()
			once.Do(func() { close(writeBlocked) })
			<-releaseWrite
		}
	})
	if err := client.sendControl(protocolv2.InnerPing, make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writeBlocked:
	case <-time.After(time.Second):
		t.Fatal("control writer did not reach the deterministic stall")
	}

	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned before queued control records were flushed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseWrite)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	writeMu.Lock()
	flushedRecords := writeCount
	writeMu.Unlock()
	if flushedRecords != 3 {
		t.Fatalf("flushed control records = %d, want blocked record + GOAWAY + SESSION_CLOSE", flushedRecords)
	}

	deadline := time.Now().Add(time.Second)
	for context.Cause(server.ctx) == nil {
		if time.Now().After(deadline) {
			t.Fatal("peer remained blocked after session close")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCloseDeadlineCoversCarrierShutdown(t *testing.T) {
	clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindQUIC)
	clientConfig, serverConfig := testEngineConfigs(2)
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	defer server.Close()

	releaseCarrierClose := make(chan struct{})
	defer close(releaseCarrierClose)
	clientCarrier.closeBlock = releaseCarrierClose
	closed := make(chan error, 1)
	started := time.Now()
	go func() { closed <- client.Close() }()

	select {
	case err := <-closed:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Close error = %v, want deadline", err)
		}
		if elapsed := time.Since(started); elapsed > sessionCloseFlushTimeout+500*time.Millisecond {
			t.Fatalf("Close exceeded its shutdown deadline: %v", elapsed)
		}
	case <-time.After(sessionCloseFlushTimeout + time.Second):
		t.Fatal("Close remained blocked in carrier shutdown")
	}
	if active := clientCarrier.closeActive.Load(); active != 0 {
		t.Fatalf("carrier close left %d background operation(s) after the shutdown deadline", active)
	}
}

func TestProtocolFailureCannotHoldCloseForeverInCarrierShutdown(t *testing.T) {
	clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindQUIC)
	clientConfig, serverConfig := testEngineConfigs(2)
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	defer server.Close()

	releaseCarrierClose := make(chan struct{})
	clientCarrier.closeBlock = releaseCarrierClose
	go client.fail(errors.New("injected protocol failure"))
	select {
	case <-client.Termination():
	case <-time.After(100 * time.Millisecond):
		t.Fatal("protocol failure did not terminate session state")
	}
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-closed:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Close error = %v, want carrier deadline", err)
		}
	case <-time.After(sessionCloseFlushTimeout + time.Second):
		t.Fatal("Close remained blocked behind protocol-failure carrier shutdown")
	}
	close(releaseCarrierClose)
}

func TestCloseRejectsQueuedAcceptBeforeControlFlushCompletes(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer server.Close()

	queued, err := server.OpenStream(context.Background(), "queued-before-close", Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	defer queued.Close()

	writeBlocked := make(chan struct{})
	releaseWrite := make(chan struct{})
	var once sync.Once
	client.control.(*memoryStream).setWriteHook(func(payload []byte) {
		if len(payload) >= 4 && string(payload[:4]) == "FSR2" {
			once.Do(func() { close(writeBlocked) })
			<-releaseWrite
		}
	})
	if err := client.sendControl(protocolv2.InnerPing, make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writeBlocked:
	case <-time.After(time.Second):
		t.Fatal("control writer did not reach the deterministic stall")
	}

	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	deadline := time.Now().Add(time.Second)
	for {
		client.openMu.Lock()
		goingAway := client.goingAway
		client.openMu.Unlock()
		if goingAway {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close did not enter the GOAWAY state")
		}
		time.Sleep(time.Millisecond)
	}

	acceptContext, cancelAccept := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelAccept()
	if _, err := client.AcceptStream(acceptContext); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("AcceptStream during Close flush = %v, want ErrSessionClosed", err)
	}
	select {
	case err := <-closed:
		t.Fatalf("Close returned before control flush release: %v", err)
	default:
	}
	close(releaseWrite)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestCloseUnblocksAcceptBeforeControlFlushCompletes(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer server.Close()

	acceptResult := make(chan error, 1)
	go func() {
		_, err := client.AcceptStream(context.Background())
		acceptResult <- err
	}()

	writeBlocked := make(chan struct{})
	releaseWrite := make(chan struct{})
	var once sync.Once
	client.control.(*memoryStream).setWriteHook(func(payload []byte) {
		if len(payload) >= 4 && string(payload[:4]) == "FSR2" {
			once.Do(func() { close(writeBlocked) })
			<-releaseWrite
		}
	})
	if err := client.sendControl(protocolv2.InnerPing, make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writeBlocked:
	case <-time.After(time.Second):
		t.Fatal("control writer did not reach the deterministic stall")
	}

	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-acceptResult:
		if !errors.Is(err, ErrSessionClosed) {
			t.Fatalf("blocked AcceptStream during Close flush = %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("blocked AcceptStream waited for control flush")
	}
	select {
	case err := <-closed:
		t.Fatalf("Close returned before control flush release: %v", err)
	default:
	}
	close(releaseWrite)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func establishMemoryPair(t *testing.T, kind carrier.Kind, maxInbound uint16) (*engineSession, *engineSession) {
	t.Helper()
	clientCarrier, serverCarrier := newMemoryCarrierPair(kind)
	clientConfig, serverConfig := testEngineConfigs(maxInbound)
	return establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
}

func establishWithCarriers(t *testing.T, clientCarrier, serverCarrier carrier.Session, clientConfig, serverConfig Config) (*engineSession, *engineSession) {
	t.Helper()
	bindMemoryCarrierCapacity(clientCarrier, clientConfig.MaxInboundStreams)
	bindMemoryCarrierCapacity(serverCarrier, serverConfig.MaxInboundStreams)
	bindMemoryCarrierPath(clientCarrier, clientConfig.Path)
	bindMemoryCarrierPath(serverCarrier, serverConfig.Path)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)

	serverResult := make(chan struct {
		session *engineSession
		err     error
	}, 1)
	go func() {
		established, err := Establish(ctx, serverCarrier, serverConfig)
		concrete, _ := established.(*engineSession)
		serverResult <- struct {
			session *engineSession
			err     error
		}{concrete, err}
	}()
	clientEstablished, err := Establish(ctx, clientCarrier, clientConfig)
	if err != nil {
		t.Fatalf("client Establish: %v", err)
	}
	client, ok := clientEstablished.(*engineSession)
	if !ok {
		t.Fatalf("client concrete type = %T", clientEstablished)
	}
	server := <-serverResult
	if server.err != nil {
		t.Fatalf("server Establish: %v", server.err)
	}
	return client, server.session
}

func tryEstablishPair(t *testing.T, clientCarrier, serverCarrier carrier.Session, clientConfig, serverConfig Config) (*engineSession, *engineSession, error, error) {
	t.Helper()
	bindMemoryCarrierCapacity(clientCarrier, clientConfig.MaxInboundStreams)
	bindMemoryCarrierCapacity(serverCarrier, serverConfig.MaxInboundStreams)
	bindMemoryCarrierPath(clientCarrier, clientConfig.Path)
	bindMemoryCarrierPath(serverCarrier, serverConfig.Path)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	type result struct {
		session *engineSession
		err     error
	}
	serverResult := make(chan result, 1)
	go func() {
		established, err := Establish(ctx, serverCarrier, serverConfig)
		concrete, _ := established.(*engineSession)
		serverResult <- result{session: concrete, err: err}
	}()
	clientEstablished, clientErr := Establish(ctx, clientCarrier, clientConfig)
	client, _ := clientEstablished.(*engineSession)
	server := <-serverResult
	return client, server.session, clientErr, server.err
}

func testEngineConfigs(maxInbound uint16) (Config, Config) {
	var psk, contract, clientAdmission, serverAdmission [32]byte
	for i := 0; i < 32; i++ {
		psk[i] = byte(i + 1)
		contract[i] = byte(i + 33)
		clientAdmission[i] = byte(i + 65)
		serverAdmission[i] = byte(i + 97)
	}
	base := Config{
		Path:                PathTunnel,
		ChannelID:           "session-engine-test",
		SessionContractHash: contract,
		Suite:               protocolv2.SuiteChaCha20Poly1305,
		PSK:                 psk,
		MaxInboundStreams:   maxInbound,
	}
	client := base
	client.Role = RoleClient
	client.LocalAdmissionBinding = clientAdmission
	client.PeerAdmissionBinding = serverAdmission
	client.LocalEndpointInstanceID = "client-instance"
	client.ExpectedPeerEndpointInstanceID = "server-instance"
	server := base
	server.Role = RoleServer
	server.LocalAdmissionBinding = serverAdmission
	server.PeerAdmissionBinding = clientAdmission
	server.LocalEndpointInstanceID = "server-instance"
	server.ExpectedPeerEndpointInstanceID = "client-instance"
	return client, server
}

func acceptOne(session SessionV2, incoming chan<- IncomingStream, errs chan<- error) {
	stream, err := session.AcceptStream(context.Background())
	if err != nil {
		errs <- err
		return
	}
	incoming <- stream
}

func awaitIncoming(t *testing.T, incoming <-chan IncomingStream, errs <-chan error) IncomingStream {
	t.Helper()
	select {
	case stream := <-incoming:
		return stream
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("AcceptStream timed out")
	}
	return IncomingStream{}
}

func awaitSessionGoingAway(t *testing.T, session *engineSession, reason string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		session.openMu.Lock()
		goingAway := session.goingAway
		session.openMu.Unlock()
		if goingAway {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer did not receive GOAWAY for %s", reason)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertHalfCloseRoundTrip(t *testing.T, opener, responder ByteStream, request, response []byte) {
	t.Helper()
	requestResult := readAllAsync(responder)
	if _, err := opener.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := opener.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	gotRequest := <-requestResult
	if gotRequest.err != nil || !bytes.Equal(gotRequest.payload, request) {
		t.Fatalf("request=%q error=%v", gotRequest.payload, gotRequest.err)
	}
	responseResult := readAllAsync(opener)
	if _, err := responder.Write(response); err != nil {
		t.Fatal(err)
	}
	if err := responder.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	gotResponse := <-responseResult
	if gotResponse.err != nil || !bytes.Equal(gotResponse.payload, response) {
		t.Fatalf("response=%q error=%v", gotResponse.payload, gotResponse.err)
	}
}

type readResult struct {
	payload []byte
	err     error
}

func readAllAsync(reader io.Reader) <-chan readResult {
	result := make(chan readResult, 1)
	go func() {
		payload, err := io.ReadAll(reader)
		result <- readResult{payload: payload, err: err}
	}()
	return result
}

type memoryCarrierSession struct {
	kind               carrier.Kind
	path               carrier.Path
	ctx                context.Context
	stop               context.CancelCauseFunc
	maxIncomingStreams uint16

	peer        *memoryCarrierSession
	incoming    chan carrier.Stream
	closed      sync.Once
	streamsMu   sync.Mutex
	streams     []carrier.Stream
	hookMu      sync.RWMutex
	writeHook   func([]byte)
	closeBlock  <-chan struct{}
	closeActive atomic.Int32
}

func newMemoryCarrierPair(kind carrier.Kind) (*memoryCarrierSession, *memoryCarrierSession) {
	clientCtx, clientStop := context.WithCancelCause(context.Background())
	serverCtx, serverStop := context.WithCancelCause(context.Background())
	defaultCapacity, _ := carrier.RequiredIncomingStreams(2)
	client := &memoryCarrierSession{kind: kind, path: carrier.PathTunnel, ctx: clientCtx, stop: clientStop, maxIncomingStreams: defaultCapacity, incoming: make(chan carrier.Stream, 256)}
	server := &memoryCarrierSession{kind: kind, path: carrier.PathTunnel, ctx: serverCtx, stop: serverStop, maxIncomingStreams: defaultCapacity, incoming: make(chan carrier.Stream, 256)}
	client.peer = server
	server.peer = client
	return client, server
}

func (s *memoryCarrierSession) Kind() carrier.Kind                 { return s.kind }
func (s *memoryCarrierSession) Path() carrier.Path                 { return s.path }
func (s *memoryCarrierSession) MaxIncomingStreams() uint16         { return s.maxIncomingStreams }
func (s *memoryCarrierSession) setMaxIncomingStreams(value uint16) { s.maxIncomingStreams = value }

func bindMemoryCarrierPath(session carrier.Session, path PathKind) {
	memory, ok := session.(*memoryCarrierSession)
	if !ok {
		return
	}
	if path == PathDirect {
		memory.path = carrier.PathDirect
	} else {
		memory.path = carrier.PathTunnel
	}
}

func bindMemoryCarrierCapacity(session carrier.Session, maxLogical uint16) {
	memory, ok := session.(*memoryCarrierSession)
	if !ok {
		return
	}
	required, err := carrier.RequiredIncomingStreams(maxLogical)
	if err == nil {
		memory.setMaxIncomingStreams(required)
	}
}

func (s *memoryCarrierSession) OpenStream(ctx context.Context) (carrier.Stream, error) {
	local, remote := newMemoryStreamPair(s.ctx, s.peer.ctx)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, context.Cause(s.ctx)
	case s.peer.incoming <- remote:
		local.owner = s
		remote.owner = s.peer
		s.trackStream(local)
		s.peer.trackStream(remote)
		return local, nil
	}
}

func (s *memoryCarrierSession) AcceptStream(ctx context.Context) (carrier.Stream, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, context.Cause(s.ctx)
	case stream := <-s.incoming:
		return stream, nil
	}
}

func (s *memoryCarrierSession) CloseWithError(applicationError carrier.ApplicationError) error {
	return s.CloseWithErrorContext(context.Background(), applicationError)
}

func (s *memoryCarrierSession) CloseWithErrorContext(ctx context.Context, applicationError carrier.ApplicationError) error {
	s.closeActive.Add(1)
	defer s.closeActive.Add(-1)
	if s.closeBlock != nil {
		select {
		case <-s.closeBlock:
		case <-ctx.Done():
			s.closeNow(applicationError)
			return ctx.Err()
		}
	}
	s.closeNow(applicationError)
	return nil
}

func (s *memoryCarrierSession) closeNow(applicationError carrier.ApplicationError) {
	s.closed.Do(func() {
		err := io.ErrClosedPipe
		if applicationError.Reason != "" {
			err = errors.New(applicationError.Reason)
		}
		s.stop(err)
		s.peer.stop(err)
		s.resetStreams()
		s.peer.resetStreams()
	})
}

func (s *memoryCarrierSession) Close() error { return s.CloseWithError(carrier.ApplicationError{}) }

func (s *memoryCarrierSession) trackStream(stream carrier.Stream) {
	s.streamsMu.Lock()
	s.streams = append(s.streams, stream)
	s.streamsMu.Unlock()
}

func (s *memoryCarrierSession) resetStreams() {
	s.streamsMu.Lock()
	streams := append([]carrier.Stream(nil), s.streams...)
	s.streamsMu.Unlock()
	for _, stream := range streams {
		_ = stream.Reset()
	}
}

func (s *memoryCarrierSession) setWriteHook(hook func([]byte)) {
	s.hookMu.Lock()
	s.writeHook = hook
	s.hookMu.Unlock()
}

func (s *memoryCarrierSession) runWriteHook(payload []byte) {
	s.hookMu.RLock()
	hook := s.writeHook
	s.hookMu.RUnlock()
	if hook != nil {
		hook(payload)
	}
}

type memoryStream struct {
	reader           *io.PipeReader
	writer           *io.PipeWriter
	ctx              context.Context
	stop             context.CancelCauseFunc
	reset            sync.Once
	owner            *memoryCarrierSession
	hookMu           sync.RWMutex
	writeHook        func([]byte)
	mutateMu         sync.Mutex
	mutateCiphertext bool
	mutateSequence   bool
}

func newMemoryStreamPair(leftSession, rightSession context.Context) (*memoryStream, *memoryStream) {
	leftToRightReader, leftToRightWriter := io.Pipe()
	rightToLeftReader, rightToLeftWriter := io.Pipe()
	leftCtx, leftStop := context.WithCancelCause(leftSession)
	rightCtx, rightStop := context.WithCancelCause(rightSession)
	left := &memoryStream{reader: rightToLeftReader, writer: leftToRightWriter, ctx: leftCtx, stop: leftStop}
	right := &memoryStream{reader: leftToRightReader, writer: rightToLeftWriter, ctx: rightCtx, stop: rightStop}
	return left, right
}

func (s *memoryStream) Read(payload []byte) (int, error) { return s.reader.Read(payload) }
func (s *memoryStream) Write(payload []byte) (int, error) {
	s.hookMu.RLock()
	hook := s.writeHook
	s.hookMu.RUnlock()
	if hook != nil {
		hook(payload)
	}
	if s.owner != nil {
		s.owner.runWriteHook(payload)
	}
	s.mutateMu.Lock()
	if s.mutateSequence && len(payload) == protocolv2.RecordHeaderSize && bytes.HasPrefix(payload, []byte("FSR2")) {
		payload = append([]byte(nil), payload...)
		binary.BigEndian.PutUint64(payload[12:20], binary.BigEndian.Uint64(payload[12:20])+1)
		s.mutateSequence = false
	}
	if s.mutateCiphertext && len(payload) != 0 && !bytes.HasPrefix(payload, []byte("FSR2")) {
		payload = append([]byte(nil), payload...)
		payload[len(payload)-1] ^= 1
		s.mutateCiphertext = false
	}
	s.mutateMu.Unlock()
	return s.writer.Write(payload)
}

func (s *memoryStream) setWriteHook(hook func([]byte)) {
	s.hookMu.Lock()
	s.writeHook = hook
	s.hookMu.Unlock()
}
func (s *memoryStream) Context() context.Context { return s.ctx }
func (s *memoryStream) CloseWrite() error        { return s.writer.Close() }

func (s *memoryStream) Reset() error {
	s.reset.Do(func() {
		_ = s.reader.CloseWithError(carrier.ErrStreamReset)
		_ = s.writer.CloseWithError(carrier.ErrStreamReset)
		s.stop(carrier.ErrStreamReset)
	})
	return nil
}

func (s *memoryStream) Close() error { return s.Reset() }

func (s *memoryStream) mutateNextCiphertext() {
	s.mutateMu.Lock()
	s.mutateCiphertext = true
	s.mutateMu.Unlock()
}

func (s *memoryStream) mutateNextRecordSequence() {
	s.mutateMu.Lock()
	s.mutateSequence = true
	s.mutateMu.Unlock()
}
