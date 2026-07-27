package transportrelease

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	carrieryamux "github.com/floegence/flowersec/flowersec-go/v2/internal/mux/yamux"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	gorillaws "github.com/gorilla/websocket"
)

func TestDirectProductionCarriersCarryEncryptedRoundTrip(t *testing.T) {
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindQUIC, carrier.KindWebTransport} {
		t.Run(string(kind), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			pair, err := OpenDirect(ctx, kind)
			if err != nil {
				t.Fatal(err)
			}
			if err := pair.RoundTrip(ctx, []byte("release request"), []byte("release response")); err != nil {
				t.Fatal(err)
			}
			if err := pair.Close(); err != nil {
				t.Fatal(err)
			}
			if err := pair.Close(); err != nil {
				t.Fatalf("second close: %v", err)
			}
		})
	}
}

func TestPairClosePreservesErrorsAndIsIdempotent(t *testing.T) {
	sentinel := errors.New("sentinel cleanup failure")
	pair := &DirectPair{closers: []func() error{func() error { return errors.Join(io.EOF, sentinel) }}}
	for attempt := 1; attempt <= 2; attempt++ {
		err := pair.Close()
		if !errors.Is(err, sentinel) || errors.Is(err, io.EOF) {
			t.Fatalf("close attempt %d error = %v, want sentinel only", attempt, err)
		}
	}
}

func TestEndpointAdmissionClaimsIssuedRequestExactlyOnce(t *testing.T) {
	endpoint := &ProductDirectEndpoint{
		ctx: context.Background(), pending: make(map[[32]byte]*admissionExpectation),
	}
	expected := &admissionExpectation{raw: []byte("issued-fsb2"), result: make(chan productServerResult, 1)}
	if _, err := endpoint.register(expected); err != nil {
		t.Fatal(err)
	}
	request := &artifactv2.DecodedRequest{Raw: append([]byte(nil), expected.raw...)}
	if _, err := endpoint.authorize(context.Background(), request); err != nil {
		t.Fatalf("first authorization: %v", err)
	}
	if _, err := endpoint.authorize(context.Background(), request); err == nil {
		t.Fatal("replayed authorization succeeded")
	}
}

func TestProductDirectCarriersUsePublicConnectorAndAdmission(t *testing.T) {
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindQUIC, carrier.KindWebTransport} {
		t.Run(string(kind), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			pair, err := OpenProductDirect(ctx, kind)
			if err != nil {
				t.Fatal(err)
			}
			if pair.SpendCount() != 1 {
				t.Fatalf("spend count = %d, want 1", pair.SpendCount())
			}
			if err := pair.RoundTrip(ctx, []byte("public request"), []byte("public response")); err != nil {
				t.Fatal(err)
			}
			if err := pair.Close(); err != nil {
				t.Fatal(err)
			}
			if err := pair.Close(); err != nil {
				t.Fatalf("second close: %v", err)
			}
		})
	}
}

func TestProductDirectRPCPreservesExactPayload(t *testing.T) {
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindQUIC, carrier.KindWebTransport} {
		t.Run(string(kind), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			pair, err := OpenProductDirect(ctx, kind)
			if err != nil {
				t.Fatal(err)
			}
			operations, err := RunRPC(ctx, pair, 32, 8, 1024, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if len(operations) != 32 {
				t.Fatalf("operation count = %d, want 32", len(operations))
			}
			if err := pair.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBrowserBulkServerUsesNativeBidirectionalStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pair, err := OpenProductDirect(ctx, carrier.KindWebTransport)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Close()
	serverDone := make(chan error, 1)
	go func() { serverDone <- ServeBrowserBulk(ctx, pair.Server, []int64{64 * 1024, 256 * 1024}) }()
	for _, byteCount := range []int64{64 * 1024, 256 * 1024} {
		accepted := make(chan struct {
			stream releaseByteStream
			err    error
		}, 1)
		go func() {
			incoming, acceptErr := pair.Client.AcceptStream(ctx)
			if acceptErr == nil && (incoming.Kind != "release-bulk" || incoming.Metadata["direction"] != "server-to-client") {
				acceptErr = errors.New("server bulk metadata mismatch")
			}
			accepted <- struct {
				stream releaseByteStream
				err    error
			}{stream: incoming.Stream, err: acceptErr}
		}()
		outgoing, err := pair.Client.OpenStream(ctx, "release-bulk", map[string]any{"direction": "client-to-server"})
		if err != nil {
			t.Fatal(err)
		}
		incoming := <-accepted
		if incoming.err != nil {
			t.Fatal(incoming.err)
		}
		results := make(chan error, 2)
		go func() {
			if err := writeExactFill(ctx, outgoing, byteCount, 0xa5); err != nil {
				results <- fmt.Errorf("client write: %w", err)
				return
			}
			results <- nil
		}()
		go func() {
			if err := readExactFill(ctx, incoming.stream, byteCount, 0x5a); err != nil {
				results <- fmt.Errorf("client read: %w", err)
				return
			}
			results <- incoming.stream.CloseWrite()
		}()
		if err := errors.Join(<-results, <-results); err != nil {
			_ = outgoing.Reset()
			_ = incoming.stream.Reset()
			t.Fatal(err)
		}
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestBrowserNativeIsolationPreservesSiblingFIN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pair, err := OpenProductDirect(ctx, carrier.KindWebTransport)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Close()
	serverDone := make(chan error, 1)
	go func() { serverDone <- ServeBrowserNativeIsolation(ctx, pair.Server) }()

	streams := make([]releaseByteStream, 0, 4)
	for index := range 4 {
		stream, openErr := pair.Client.OpenStream(ctx, "native-isolation", map[string]any{"stream_index": index})
		if openErr != nil {
			t.Fatal(openErr)
		}
		streams = append(streams, stream)
		if count, writeErr := stream.Write([]byte{byte(index)}); writeErr != nil || count != 1 {
			t.Fatalf("stream %d handshake write = %d, %v", index, count, writeErr)
		}
		handshake := make([]byte, 1)
		if _, readErr := io.ReadFull(stream, handshake); readErr != nil || handshake[0] != byte(index)^0xff {
			t.Fatalf("stream %d handshake read = %x, %v", index, handshake, readErr)
		}
	}
	if err := streams[0].Reset(); err != nil {
		t.Fatal(err)
	}

	results := make(chan error, 3)
	for index := 1; index < len(streams); index++ {
		index := index
		go func() {
			stream := streams[index]
			value := byte(0x40 + index)
			if count, writeErr := stream.Write([]byte{value}); writeErr != nil || count != 1 {
				results <- errors.Join(writeErr, io.ErrShortWrite)
				return
			}
			if closeErr := stream.CloseWrite(); closeErr != nil {
				results <- closeErr
				return
			}
			response := make([]byte, 1)
			if _, readErr := io.ReadFull(stream, response); readErr != nil || response[0] != value^0xff {
				results <- errors.Join(readErr, errors.New("sibling response mismatch"))
				return
			}
			if count, readErr := stream.Read(response); count != 0 || !errors.Is(readErr, io.EOF) {
				results <- errors.Join(readErr, errors.New("sibling did not finish with FIN"))
				return
			}
			results <- nil
		}()
	}
	if err := errors.Join(<-results, <-results, <-results); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	var response string
	if err := pair.Client.RPC().Call(ctx, 1, "native-isolation-survivor", &response); err != nil || response != "native-isolation-survivor" {
		t.Fatalf("post-reset RPC = %q, %v", response, err)
	}
}

func TestBrowserBulkServerReadsAndWritesConcurrently(t *testing.T) {
	started := make(chan struct{})
	incoming := &coordinatedBrowserReadStream{writeStarted: started, stopped: make(chan struct{})}
	outgoing := &coordinatedBrowserWriteStream{writeStarted: started, stopped: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := serveBrowserBulkPhase(ctx, incoming, outgoing, 1024); err != nil {
		t.Fatal(err)
	}
	for label, stream := range map[string]interface {
		CloseWriteCount() int32
		ResetCount() int32
	}{"incoming": incoming, "outgoing": outgoing} {
		if got := stream.CloseWriteCount(); got != 1 {
			t.Fatalf("%s CloseWrite count = %d, want 1", label, got)
		}
		if got := stream.ResetCount(); got != 0 {
			t.Fatalf("%s Reset count = %d, want 0", label, got)
		}
	}
}

func TestBrowserBulkServerBoundsOutgoingWriteBeforePeerStreamAcceptance(t *testing.T) {
	started := make(chan struct{})
	session := &acceptAfterWriteSession{
		incoming:    &coordinatedBrowserReadStream{writeStarted: started, stopped: make(chan struct{})},
		outgoing:    &coordinatedBrowserWriteStream{writeStarted: started, stopped: make(chan struct{})},
		termination: make(chan struct{}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	if err := ServeBrowserBulk(ctx, session, []int64{32 * 1024}); err != nil {
		t.Fatal(err)
	}
	if got := session.outgoing.FirstWriteBytes(); got != 16*1024 {
		t.Fatalf("outgoing first write bytes = %d, want one 16 KiB network burst", got)
	}
	if got := session.outgoing.CloseWriteCount(); got != 1 {
		t.Fatalf("outgoing CloseWrite count = %d, want 1", got)
	}
	if got := session.incoming.CloseWriteCount(); got != 1 {
		t.Fatalf("incoming CloseWrite count = %d, want 1", got)
	}
}

func TestBrowserBulkPreopensNextPhaseDuringWarmup(t *testing.T) {
	session := &preopenBulkSession{secondOpened: make(chan struct{}), termination: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if err := ServeBrowserBulk(ctx, session, []int64{1024, 1024}); err != nil {
		t.Fatalf("ServeBrowserBulk error = %v; the next phase must be opened while warmup is active", err)
	}
	if got := session.openCount(); got != 2 {
		t.Fatalf("OpenStream count = %d, want 2", got)
	}
}

func TestProductDirectEndpointReusesListenerForConcurrentArtifacts(t *testing.T) {
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindQUIC, carrier.KindWebTransport} {
		t.Run(string(kind), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			endpoint, err := OpenProductDirectEndpoint(ctx, kind)
			if err != nil {
				t.Fatal(err)
			}
			const connections = 12
			var group sync.WaitGroup
			errors := make(chan error, connections)
			group.Add(connections)
			for ordinal := 1; ordinal <= connections; ordinal++ {
				go func() {
					defer group.Done()
					pair, connectErr := endpoint.Connect(ctx)
					if connectErr != nil {
						errors <- connectErr
						return
					}
					request := []byte(fmt.Sprintf("request-%d", ordinal))
					response := []byte(fmt.Sprintf("response-%d", ordinal))
					if roundTripErr := pair.RoundTrip(ctx, request, response); roundTripErr != nil {
						errors <- roundTripErr
					}
					if closeErr := pair.Close(); closeErr != nil {
						errors <- closeErr
					}
				}()
			}
			group.Wait()
			close(errors)
			for err := range errors {
				t.Error(err)
			}
			if err := endpoint.Close(); err != nil {
				t.Fatal(err)
			}
			if err := endpoint.Close(); err != nil {
				t.Fatalf("second close: %v", err)
			}
		})
	}
}

func TestProductDirectEndpointRejectsNonConcreteListenAddress(t *testing.T) {
	for _, address := range []string{"", "0.0.0.0", "not-an-ip", "224.0.0.1"} {
		if _, err := OpenProductDirectEndpointAt(context.Background(), carrier.KindWebSocket, address); err == nil {
			t.Fatalf("accepted listen address %q", address)
		}
	}
}

func TestProductDirectBrowserEndpointRequiresConcreteOriginAndExposesCertificateHash(t *testing.T) {
	for _, origin := range []string{"", "https://example.test", "file:///tmp/site", "http://0.0.0.0:9000", "http://224.0.0.1"} {
		if _, err := OpenProductDirectBrowserEndpointAt(context.Background(), "127.0.0.1", origin); err == nil {
			t.Fatalf("accepted browser origin %q", origin)
		}
	}
	endpoint, err := OpenProductDirectBrowserEndpointAt(context.Background(), "127.0.0.1", "http://127.0.0.1:9000")
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	encoded, err := endpoint.CertificateHashBase64URL()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("certificate hash = %q: %v", encoded, err)
	}
}

func TestWebTransportReleaseCertificateUsesBrowserCompatibleP256(t *testing.T) {
	serverTLS, _, err := localTLSForHost(carrier.KindWebTransport, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(serverTLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if certificate.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatalf("WebTransport certificate algorithm = %s, want ECDSA P-256", certificate.PublicKeyAlgorithm)
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		t.Fatal("WebTransport certificate does not use ECDSA P-256")
	}
}

func TestBrowserOriginAuthorizationPinsSchemeAndExplicitIPAddress(t *testing.T) {
	allowed := "http://198.18.0.2"
	for _, origin := range []string{"http://198.18.0.2:39123", "http://198.18.0.2"} {
		if !browserOriginAllowed(origin, allowed) {
			t.Fatalf("origin %q was rejected", origin)
		}
	}
	for _, origin := range []string{"https://198.18.0.2:39123", "http://198.18.0.3:39123", "http://example.test:39123", "http://198.18.0.2:39123/path"} {
		if browserOriginAllowed(origin, allowed) {
			t.Fatalf("origin %q was accepted", origin)
		}
	}
	if browserOriginAllowed("http://198.18.0.2:39124", "http://198.18.0.2:39123") {
		t.Fatal("origin with the wrong pinned port was accepted")
	}
}

func TestProductDirectBrowserArtifactsAreFreshAndCancelable(t *testing.T) {
	endpoint, err := OpenProductDirectBrowserEndpointAt(context.Background(), "127.0.0.1", "http://127.0.0.1:9000")
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()

	first, err := endpoint.IssueBrowserArtifact()
	if err != nil {
		t.Fatal(err)
	}
	second, err := endpoint.IssueBrowserArtifact()
	if err != nil {
		t.Fatal(err)
	}
	if first.ArtifactJSON() == second.ArtifactJSON() {
		t.Fatal("browser artifact was reused")
	}
	for _, issued := range []*ProductDirectBrowserArtifact{first, second} {
		var value map[string]any
		if err := json.Unmarshal([]byte(issued.ArtifactJSON()), &value); err != nil {
			t.Fatal(err)
		}
		if value["v"] != float64(2) {
			t.Fatalf("artifact version = %v", value["v"])
		}
		issued.Cancel()
		issued.Cancel()
	}
	endpoint.pendingMu.Lock()
	pending := len(endpoint.pending)
	endpoint.pendingMu.Unlock()
	if pending != 0 {
		t.Fatalf("pending artifacts after cancellation = %d", pending)
	}
	if _, err := first.AwaitServer(context.Background()); err == nil {
		t.Fatal("canceled artifact could be awaited")
	}
}

func TestProductDirectWorkloadsUsePersistentEndpoint(t *testing.T) {
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindQUIC, carrier.KindWebTransport} {
		t.Run(string(kind), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			endpoint, err := OpenProductDirectEndpoint(ctx, kind)
			if err != nil {
				t.Fatal(err)
			}
			defer endpoint.Close()
			connections, err := RunCold(ctx, endpoint, 24, 8, 1000, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if len(connections) != 24 {
				t.Fatalf("connection count = %d, want 24", len(connections))
			}
			pair, err := endpoint.Connect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer pair.Close()
			operations, err := RunRPC(ctx, pair, 64, 8, 1024, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if len(operations) != 64 {
				t.Fatalf("operation count = %d, want 64", len(operations))
			}
			bulk, err := RunBulk(ctx, pair, 64*1024, 256*1024)
			if err != nil {
				t.Fatal(err)
			}
			if bulk.BytesPerDirection != 256*1024 || bulk.Duration <= 0 {
				t.Fatalf("bulk result = %+v", bulk)
			}
		})
	}
}

func TestTransferExactResetsBlockedStreamsAtDeadline(t *testing.T) {
	writer := newBlockingReleaseStream()
	reader := newBlockingReleaseStream()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := transferExact(ctx, writer, reader, 1024, 0xa5)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("transfer error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("blocked transfer cleanup took %v", elapsed)
	}
	for label, stream := range map[string]*blockingReleaseStream{"writer": writer, "reader": reader} {
		select {
		case <-stream.stopped:
		default:
			t.Fatalf("%s was not reset", label)
		}
	}
}

type blockingReleaseStream struct {
	stopped chan struct{}
	once    sync.Once
}

type coordinatedBrowserReadStream struct {
	writeStarted <-chan struct{}
	stopped      chan struct{}
	stopOnce     sync.Once
	closeWrites  atomic.Int32
	resets       atomic.Int32
	read         bool
}

func (stream *coordinatedBrowserReadStream) Read(buffer []byte) (int, error) {
	if stream.read {
		return 0, io.EOF
	}
	select {
	case <-stream.writeStarted:
	case <-stream.stopped:
		return 0, io.ErrClosedPipe
	}
	stream.read = true
	for index := range buffer {
		buffer[index] = 0xa5
	}
	return len(buffer), nil
}

func (stream *coordinatedBrowserReadStream) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (stream *coordinatedBrowserReadStream) CloseWrite() error {
	stream.closeWrites.Add(1)
	return nil
}
func (stream *coordinatedBrowserReadStream) Close() error { return stream.Reset() }
func (stream *coordinatedBrowserReadStream) Reset() error {
	stream.resets.Add(1)
	stream.stopOnce.Do(func() { close(stream.stopped) })
	return nil
}
func (stream *coordinatedBrowserReadStream) CloseWriteCount() int32 { return stream.closeWrites.Load() }
func (stream *coordinatedBrowserReadStream) ResetCount() int32      { return stream.resets.Load() }

type coordinatedBrowserWriteStream struct {
	writeStarted chan struct{}
	stopped      chan struct{}
	startOnce    sync.Once
	stopOnce     sync.Once
	firstWrite   atomic.Int64
	closeWrites  atomic.Int32
	resets       atomic.Int32
}

func (stream *coordinatedBrowserWriteStream) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (stream *coordinatedBrowserWriteStream) Write(buffer []byte) (int, error) {
	stream.startOnce.Do(func() {
		stream.firstWrite.Store(int64(len(buffer)))
		close(stream.writeStarted)
	})
	for _, value := range buffer {
		if value != 0x5a {
			return 0, errors.New("unexpected server bulk payload")
		}
	}
	return len(buffer), nil
}
func (stream *coordinatedBrowserWriteStream) CloseWrite() error {
	stream.closeWrites.Add(1)
	return nil
}
func (stream *coordinatedBrowserWriteStream) Close() error { return stream.Reset() }
func (stream *coordinatedBrowserWriteStream) Reset() error {
	stream.resets.Add(1)
	stream.stopOnce.Do(func() { close(stream.stopped) })
	return nil
}
func (stream *coordinatedBrowserWriteStream) CloseWriteCount() int32 {
	return stream.closeWrites.Load()
}
func (stream *coordinatedBrowserWriteStream) FirstWriteBytes() int64 { return stream.firstWrite.Load() }
func (stream *coordinatedBrowserWriteStream) ResetCount() int32      { return stream.resets.Load() }

type acceptAfterWriteSession struct {
	incoming    *coordinatedBrowserReadStream
	outgoing    *coordinatedBrowserWriteStream
	termination chan struct{}
}

type preopenBulkSession struct {
	mu           sync.Mutex
	opens        int
	secondOpened chan struct{}
	openOnce     sync.Once
	termination  chan struct{}
}

func (*preopenBulkSession) Path() flowersession.PathKind       { return flowersession.PathDirect }
func (*preopenBulkSession) EndpointInstanceID() (string, bool) { return "", false }
func (*preopenBulkSession) RPC() flowersession.RPCPeer         { return nil }
func (*preopenBulkSession) UnreliableMessages() (flowersession.UnreliableMessageChannel, error) {
	return nil, flowersession.ErrUnreliableUnavailable
}
func (session *preopenBulkSession) OpenStream(ctx context.Context, _ string, _ flowersession.Metadata) (flowersession.ByteStream, error) {
	session.mu.Lock()
	session.opens++
	index := session.opens
	session.mu.Unlock()
	if index == 2 {
		session.openOnce.Do(func() { close(session.secondOpened) })
	}
	return &preopenBulkWriteStream{ctx: ctx, index: index, secondOpened: session.secondOpened}, nil
}
func (*preopenBulkSession) AcceptStream(context.Context) (flowersession.IncomingStream, error) {
	return flowersession.IncomingStream{
		Kind: "release-bulk", Metadata: flowersession.Metadata{"direction": "client-to-server"},
		Stream: &preopenBulkReadStream{},
	}, nil
}
func (*preopenBulkSession) Rekey(context.Context) error                          { return nil }
func (*preopenBulkSession) ProbeLiveness(context.Context) (time.Duration, error) { return 0, nil }
func (session *preopenBulkSession) Termination() <-chan struct{}                 { return session.termination }
func (*preopenBulkSession) WaitClosed(context.Context) error                     { return nil }
func (*preopenBulkSession) Close() error                                         { return nil }
func (session *preopenBulkSession) openCount() int {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.opens
}

type preopenBulkWriteStream struct {
	ctx          context.Context
	index        int
	secondOpened <-chan struct{}
}

func (stream *preopenBulkWriteStream) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (stream *preopenBulkWriteStream) Write(payload []byte) (int, error) {
	if stream.index == 1 {
		select {
		case <-stream.secondOpened:
		case <-stream.ctx.Done():
			return 0, context.Cause(stream.ctx)
		}
	}
	for _, value := range payload {
		if value != 0x5a {
			return 0, errors.New("unexpected server bulk payload")
		}
	}
	return len(payload), nil
}
func (*preopenBulkWriteStream) CloseWrite() error    { return nil }
func (*preopenBulkWriteStream) Close() error         { return nil }
func (*preopenBulkWriteStream) Reset() error         { return nil }
func (*preopenBulkWriteStream) ID() uint64           { return 1 }
func (*preopenBulkWriteStream) Kind() string         { return "release-bulk" }
func (*preopenBulkWriteStream) TerminalError() error { return nil }

type preopenBulkReadStream struct{ read bool }

func (stream *preopenBulkReadStream) Read(payload []byte) (int, error) {
	if stream.read {
		return 0, io.EOF
	}
	stream.read = true
	for index := range payload {
		payload[index] = 0xa5
	}
	return len(payload), nil
}
func (*preopenBulkReadStream) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (*preopenBulkReadStream) CloseWrite() error         { return nil }
func (*preopenBulkReadStream) Close() error              { return nil }
func (*preopenBulkReadStream) Reset() error              { return nil }
func (*preopenBulkReadStream) ID() uint64                { return 2 }
func (*preopenBulkReadStream) Kind() string              { return "release-bulk" }
func (*preopenBulkReadStream) TerminalError() error      { return nil }

func (*acceptAfterWriteSession) Path() flowersession.PathKind       { return flowersession.PathDirect }
func (*acceptAfterWriteSession) EndpointInstanceID() (string, bool) { return "", false }
func (*acceptAfterWriteSession) RPC() flowersession.RPCPeer         { return nil }
func (*acceptAfterWriteSession) UnreliableMessages() (flowersession.UnreliableMessageChannel, error) {
	return nil, flowersession.ErrUnreliableUnavailable
}
func (session *acceptAfterWriteSession) OpenStream(context.Context, string, flowersession.Metadata) (flowersession.ByteStream, error) {
	return session.outgoing, nil
}
func (session *acceptAfterWriteSession) AcceptStream(ctx context.Context) (flowersession.IncomingStream, error) {
	select {
	case <-session.outgoing.writeStarted:
		return flowersession.IncomingStream{
			Kind: "release-bulk", Metadata: flowersession.Metadata{"direction": "client-to-server"}, Stream: session.incoming,
		}, nil
	case <-ctx.Done():
		return flowersession.IncomingStream{}, context.Cause(ctx)
	}
}
func (*acceptAfterWriteSession) Rekey(context.Context) error                          { return nil }
func (*acceptAfterWriteSession) ProbeLiveness(context.Context) (time.Duration, error) { return 0, nil }
func (session *acceptAfterWriteSession) Termination() <-chan struct{}                 { return session.termination }
func (*acceptAfterWriteSession) WaitClosed(context.Context) error                     { return nil }
func (*acceptAfterWriteSession) Close() error                                         { return nil }

func (*coordinatedBrowserReadStream) ID() uint64            { return 1 }
func (*coordinatedBrowserReadStream) Kind() string          { return "release-bulk" }
func (*coordinatedBrowserReadStream) TerminalError() error  { return nil }
func (*coordinatedBrowserWriteStream) ID() uint64           { return 2 }
func (*coordinatedBrowserWriteStream) Kind() string         { return "release-bulk" }
func (*coordinatedBrowserWriteStream) TerminalError() error { return nil }

func newBlockingReleaseStream() *blockingReleaseStream {
	return &blockingReleaseStream{stopped: make(chan struct{})}
}

func (stream *blockingReleaseStream) Read([]byte) (int, error) {
	<-stream.stopped
	return 0, io.ErrClosedPipe
}

func (stream *blockingReleaseStream) Write([]byte) (int, error) {
	<-stream.stopped
	return 0, io.ErrClosedPipe
}

func (stream *blockingReleaseStream) CloseWrite() error { return nil }
func (stream *blockingReleaseStream) Close() error      { return stream.Reset() }
func (stream *blockingReleaseStream) Reset() error {
	stream.once.Do(func() { close(stream.stopped) })
	return nil
}

func TestNormalizeCloseErrorAcceptsTerminalDeadline(t *testing.T) {
	if err := normalizeCloseError(context.DeadlineExceeded); err != nil {
		t.Fatalf("normalize terminal deadline = %v", err)
	}
}

func TestNormalizeCloseErrorAcceptsPeerSessionClose(t *testing.T) {
	err := &gorillaws.CloseError{Code: 4000, Text: "session closed"}
	if normalized := normalizeCloseError(err); normalized != nil {
		t.Fatalf("normalize peer session close = %v", normalized)
	}

	for _, unexpected := range []*gorillaws.CloseError{
		{Code: 4000, Text: "session protocol failure"},
		{Code: gorillaws.CloseProtocolError, Text: "protocol error"},
	} {
		if normalized := normalizeCloseError(unexpected); normalized == nil {
			t.Fatalf("normalized unexpected close %#v", unexpected)
		}
	}
}

func TestNormalizeCloseErrorAcceptsPeerYamuxResetOnly(t *testing.T) {
	if normalized := normalizeCloseError(carrieryamux.ErrStreamReset); normalized != nil {
		t.Fatalf("normalize peer Yamux reset = %v", normalized)
	}

	for _, unexpected := range []error{
		carrier.ErrStreamReset,
		protocolv2.ErrStreamReset,
		errors.New("stream reset"),
	} {
		if normalized := normalizeCloseError(unexpected); normalized == nil {
			t.Fatalf("normalized unexpected reset %T: %v", unexpected, unexpected)
		}
	}
}
