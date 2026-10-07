package transporttest

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
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	nativewt "github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	gorillaws "github.com/gorilla/websocket"
)

func browserOriginAllowed(raw, allowed string) bool {
	origin, err := url.Parse(raw)
	if err != nil {
		return false
	}
	want, err := url.Parse(allowed)
	return err == nil && origin.User == nil && origin.Path == "" && origin.RawQuery == "" && origin.Fragment == "" && origin.Scheme == want.Scheme && origin.Hostname() == want.Hostname() && (want.Port() == "" || origin.Port() == want.Port())
}

func requireTransportIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("real carrier and endpoint integration is owned by the final gate")
	}
}

type roundTripContractStream struct {
	reader      *io.PipeReader
	writer      *io.PipeWriter
	resetOnce   sync.Once
	closeWrites atomic.Int32
	closes      atomic.Int32
	resets      atomic.Int32
	finishes    atomic.Int32
}

func (stream *roundTripContractStream) Read(buffer []byte) (int, error) {
	return stream.reader.Read(buffer)
}

func (stream *roundTripContractStream) Write(buffer []byte) (int, error) {
	return stream.writer.Write(buffer)
}

func (stream *roundTripContractStream) CloseWrite() error {
	stream.closeWrites.Add(1)
	return stream.writer.Close()
}

func (stream *roundTripContractStream) Close() error {
	stream.closes.Add(1)
	if stream.finishes.Load() != 0 {
		return nil
	}
	return stream.Reset()
}

func (stream *roundTripContractStream) Reset() error {
	stream.resets.Add(1)
	stream.resetOnce.Do(func() {
		_ = stream.reader.CloseWithError(io.ErrClosedPipe)
		_ = stream.writer.CloseWithError(io.ErrClosedPipe)
	})
	return nil
}

func (stream *roundTripContractStream) WriteAll(ctx context.Context, payload []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return stream.Write(payload)
}
func (stream *roundTripContractStream) Finish(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	stream.finishes.Add(1)
	return nil
}
func newRoundTripContractStreams() (*roundTripContractStream, *roundTripContractStream) {
	clientReader, serverWriter := io.Pipe()
	serverReader, clientWriter := io.Pipe()
	return &roundTripContractStream{reader: clientReader, writer: clientWriter}, &roundTripContractStream{reader: serverReader, writer: serverWriter}
}

func TestProductDirectRoundTripCompletesFINWithoutReset(t *testing.T) {
	client, server := newRoundTripContractStreams()
	if err := roundTripProductStreams(context.Background(), client, server, "public-release-roundtrip", map[string]any{"direction": "client-to-server"}, []byte("request"), []byte("response")); err != nil {
		t.Fatal(err)
	}
	for label, stream := range map[string]*roundTripContractStream{"client": client, "server": server} {
		if stream.closeWrites.Load() != 1 || stream.finishes.Load() != 1 || stream.closes.Load() != 1 || stream.resets.Load() != 0 {
			t.Fatalf("%s lifecycle = CloseWrite %d, Close %d, Reset %d", label, stream.closeWrites.Load(), stream.closes.Load(), stream.resets.Load())
		}
	}
}

func TestProductDirectRoundTripResetsBothStreamsOnFailure(t *testing.T) {
	client, server := newRoundTripContractStreams()
	if err := roundTripProductStreams(context.Background(), client, server, "wrong-kind", map[string]any{"direction": "client-to-server"}, []byte("request"), []byte("response")); err == nil {
		t.Fatal("round trip accepted the wrong stream kind")
	}
	for label, stream := range map[string]*roundTripContractStream{"client": client, "server": server} {
		if stream.closes.Load() != 0 || stream.resets.Load() != 1 {
			t.Fatalf("%s failure lifecycle = Close %d, Reset %d", label, stream.closes.Load(), stream.resets.Load())
		}
	}
}

func newProductMaterialTestClient(t *testing.T, ctx context.Context, endpoint *ProductDirectEndpoint, wire string) *interopharness.Client {
	t.Helper()
	reporter, err := interopharness.NewPeerReporter()
	if err != nil {
		t.Fatal(err)
	}
	reporter.ApplicationProfile = "services"
	t.Cleanup(func() {
		if err := reporter.Close(); err != nil {
			t.Errorf("original consumer cleanup: %v", err)
		}
	})
	client, err := interopharness.NewClient(ctx, reporter, wire, endpoint.server.TrustPEM, endpoint.allowedOrigin, productHandlers(nil))
	if err != nil {
		t.Fatal(err)
	}
	return client
}
func productTestRawWebTransport(t *testing.T, endpoint *ProductDirectEndpoint) *nativewt.Dialer {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(endpoint.server.TrustPEM)) {
		t.Fatal("original deployment roots missing")
	}
	dialer, err := nativewt.NewDialer(&tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots}, quicbase.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := dialer.Close(); err != nil {
			t.Errorf("original raw native cleanup: %v", err)
		}
	})
	return dialer
}
func TestEndpointAdmissionClaimsIssuedRequestExactlyOnce(t *testing.T) {
	requireTransportIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	endpoint, err := OpenProductDirectEndpoint(ctx, carrier.KindWebTransport)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	issued, err := endpoint.IssueBrowserArtifact()
	if err != nil {
		t.Fatal(err)
	}
	defer issued.Cancel()
	first := newProductMaterialTestClient(t, ctx, endpoint, issued.ArtifactJSON())
	session, err := first.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server, err := issued.AwaitServer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !issued.record.Claimed() {
		t.Fatal("original HELLO did not claim independently installed material")
	}
	second := newProductMaterialTestClient(t, ctx, endpoint, issued.ArtifactJSON())
	replayed, err := second.Connect(ctx)
	if replayed != nil {
		_ = replayed.Close()
	}
	if err == nil {
		t.Fatal("same independently signed material was accepted twice")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := server.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestProductDirectWebTransportUpgradeFailurePreservesSiblingArtifact(t *testing.T) {
	requireTransportIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	endpoint, err := OpenProductDirectEndpoint(ctx, carrier.KindWebTransport)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	sibling, err := endpoint.IssueBrowserArtifact()
	if err != nil {
		t.Fatal(err)
	}
	defer sibling.Cancel()
	diagnostic := make(chan error, 1)
	endpoint.SetWebTransportUpgradeDiagnostic(func(err error) {
		select {
		case diagnostic <- err:
		default:
		}
	})
	bad := productTestRawWebTransport(t, endpoint)
	if connection, err := bad.Dial(ctx, endpoint.CandidateURL(), "https://wrong-origin.flowersec.invalid"); err == nil {
		_ = connection.Close()
		t.Fatal("original listener accepted a disallowed origin")
	}
	select {
	case err := <-diagnostic:
		if err == nil {
			t.Fatal("original native upgrade diagnostic is empty")
		}
	case <-ctx.Done():
		t.Fatal("original native upgrade failure was not reported")
	}
	if sibling.record.Claimed() || endpoint.registry.PendingCount() != 1 {
		t.Fatal("failed native upgrade claimed or withdrew the sibling material")
	}
	client := newProductMaterialTestClient(t, ctx, endpoint, sibling.ArtifactJSON())
	session, err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("untouched sibling connect: %v", err)
	}
	server, err := sibling.AwaitServer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pair := &ProductDirectPair{Client: session, Server: server}
	if err := pair.RoundTrip(ctx, []byte("sibling-request"), []byte("sibling-response")); err != nil {
		t.Fatal(err)
	}
	if err := pair.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestProductDirectWebTransportUpgradeFailureReportsDiagnostic(t *testing.T) {
	requireTransportIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	endpoint, err := OpenProductDirectEndpoint(ctx, carrier.KindWebTransport)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	diagnostic := make(chan error, 1)
	endpoint.SetWebTransportUpgradeDiagnostic(func(err error) {
		select {
		case diagnostic <- err:
		default:
		}
	})
	dialer := productTestRawWebTransport(t, endpoint)
	if connection, err := dialer.Dial(ctx, endpoint.CandidateURL(), "https://wrong-origin.flowersec.invalid"); err == nil {
		_ = connection.Close()
		t.Fatal("disallowed native origin succeeded")
	}
	select {
	case err := <-diagnostic:
		if !errors.Is(err, nativewt.ErrOriginPolicyRequired) {
			t.Fatalf("actual native upgrade error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("native upgrade diagnostic did not arrive")
	}
}
func TestProductDirectWebTransportAdmissionFailureReportsDiagnostic(t *testing.T) {
	requireTransportIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	endpoint, err := OpenProductDirectEndpoint(ctx, carrier.KindWebTransport)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	diagnostic := make(chan error, 1)
	endpoint.SetWebTransportAdmissionDiagnostic(func(err error) {
		select {
		case diagnostic <- err:
		default:
		}
	})
	dialer := productTestRawWebTransport(t, endpoint)
	connection, err := dialer.Dial(ctx, endpoint.CandidateURL(), endpoint.allowedOrigin)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	stream, err := nativewt.OpenAdmissionStream(ctx, connection)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Reset()
	wire, err := (protocolv4.Envelope{FrameType: protocolv4.FrameNegotiate, Payload: []byte{0xff}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(wire); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-diagnostic:
		if err == nil {
			t.Fatal("actual malformed HELLO diagnostic is empty")
		}
	case <-ctx.Done():
		t.Fatal("actual malformed HELLO diagnostic did not arrive")
	}
}

func TestProductDirectCarriersUsePublicConnectorAndAdmission(t *testing.T) {
	requireTransportIntegration(t)
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindRawQUIC, carrier.KindWebTransport} {
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
			if kind == carrier.KindWebTransport {
				if err := roundTripProductDirectDatagrams(ctx, pair); err != nil {
					t.Fatal(err)
				}
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

func roundTripProductDirectDatagrams(ctx context.Context, pair *ProductDirectPair) error {
	clientChannel, err := pair.Client.UnreliableMessages()
	if err != nil {
		return err
	}
	serverChannel, err := pair.Server.UnreliableMessages()
	if err != nil {
		return err
	}
	request := []byte("go-webtransport-datagram-request")
	response := []byte("go-webtransport-datagram-response")
	status, err := clientChannel.Send(ctx, request, flowersec.UnreliableSendOptions{ExpiresAt: time.Now().Add(5 * time.Second)})
	if err != nil {
		return fmt.Errorf("client datagram send: %w", err)
	}
	if status != flowersec.UnreliableAccepted {
		return fmt.Errorf("client datagram send status = %q", status)
	}
	received, err := serverChannel.Receive(ctx)
	if err != nil {
		return fmt.Errorf("server datagram receive: %w", err)
	}
	if !bytes.Equal(received, request) {
		return fmt.Errorf("server datagram receive = %q", received)
	}
	serverStatus, err := serverChannel.Send(ctx, response, flowersec.UnreliableSendOptions{ExpiresAt: time.Now().Add(5 * time.Second)})
	if err != nil {
		return fmt.Errorf("server datagram send: %w", err)
	}
	if serverStatus != flowersec.UnreliableAccepted {
		return fmt.Errorf("server datagram send status = %q", serverStatus)
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

func TestProductDirectRPCPreservesExactPayload(t *testing.T) {
	requireTransportIntegration(t)
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindRawQUIC, carrier.KindWebTransport} {
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
	requireTransportIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pair, err := OpenProductDirect(ctx, carrier.KindWebTransport)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pair.Close(); err != nil {
			t.Errorf("original browser workload cleanup: %v", err)
		}
	}()
	serverDone := make(chan error, 1)
	go func() { serverDone <- ServeBrowserBulk(ctx, pair.Server, []int64{64 * 1024, 256 * 1024}) }()
	for _, byteCount := range []int64{64 * 1024, 256 * 1024} {
		metadata, err := flowersec.NewStreamMetadata(map[string]any{"direction": "client-to-server"})
		if err != nil {
			t.Fatal(err)
		}
		outgoing, err := pair.Client.OpenStream(ctx, "release-bulk", metadata)
		if err != nil {
			t.Fatal(err)
		}
		defer outgoing.Close()
		results := make(chan error, 2)
		go func() {
			if err := writeExactFill(ctx, outgoing, byteCount, 0xa5); err != nil {
				results <- fmt.Errorf("client write: %w", err)
				return
			}
			results <- nil
		}()
		go func() {
			if err := readExactFill(ctx, outgoing, byteCount, 0x5a); err != nil {
				results <- fmt.Errorf("client read: %w", err)
				return
			}
			results <- nil
		}()
		if err := errors.Join(<-results, <-results); err != nil {
			_ = outgoing.Reset()
			t.Fatal(err)
		}
		if err := outgoing.Finish(ctx); err != nil {
			t.Fatal(err)
		}
		if err := outgoing.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestBrowserNativeIsolationPreservesSiblingFIN(t *testing.T) {
	requireTransportIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pair, err := OpenProductDirect(ctx, carrier.KindWebTransport)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pair.Close(); err != nil {
			t.Errorf("original browser workload cleanup: %v", err)
		}
	}()
	serverDone := make(chan error, 1)
	go func() { serverDone <- ServeBrowserNativeIsolation(ctx, pair.Server) }()

	streams := make([]releaseByteStream, 0, 4)
	for index := range 4 {
		metadata, metadataErr := flowersec.NewStreamMetadata(map[string]any{"stream_index": index})
		if metadataErr != nil {
			t.Fatal(metadataErr)
		}
		stream, openErr := pair.Client.OpenStream(ctx, "native-isolation", metadata)
		if openErr != nil {
			t.Fatal(openErr)
		}
		defer stream.Close()
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
			results <- errors.Join(stream.Finish(ctx), stream.Close())
		}()
	}
	if err := errors.Join(<-results, <-results, <-results); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	response, err := pair.CallEcho(ctx, []byte("native-isolation-survivor"))
	if err != nil || string(response) != "native-isolation-survivor" {
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

func TestBrowserBulkServerFINAcknowledgesPeerReadCompletion(t *testing.T) {
	readAllowed := make(chan struct{})
	stream := &gatedBrowserBidiStream{
		readAllowed: readAllowed,
		closeWrite:  make(chan struct{}),
		stopped:     make(chan struct{}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveBrowserBulkBidiPhase(ctx, stream, 1024) }()

	prematureFIN := false
	select {
	case <-stream.closeWrite:
		prematureFIN = true
	case <-time.After(20 * time.Millisecond):
	}
	close(readAllowed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if prematureFIN {
		t.Fatal("server sent FIN before consuming the peer bulk direction")
	}
	select {
	case <-stream.closeWrite:
	case <-time.After(time.Second):
		t.Fatal("server did not send FIN after consuming the peer bulk direction")
	}
}

func TestBrowserBulkServerWaitsForResponseBeforeFIN(t *testing.T) {
	stream := newOrderedBrowserBidiStream(64 * 1024)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveBrowserBulkBidiPhase(ctx, stream, 64*1024) }()

	select {
	case <-stream.firstWrite:
	case <-ctx.Done():
		t.Fatal("server response write did not start")
	}
	select {
	case <-stream.readComplete:
	case <-ctx.Done():
		t.Fatal("peer request read did not complete")
	}
	prematureFIN := false
	select {
	case <-stream.closeWrite:
		prematureFIN = true
	case <-time.After(20 * time.Millisecond):
	}
	close(stream.writeAllowed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if prematureFIN {
		t.Fatal("server sent FIN before its bulk response finished")
	}
	select {
	case <-stream.closeWrite:
	case <-ctx.Done():
		t.Fatal("server did not send FIN after both bulk directions completed")
	}
}

func TestProductDirectEndpointReusesListenerForConcurrentArtifacts(t *testing.T) {
	requireTransportIntegration(t)
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindRawQUIC, carrier.KindWebTransport} {
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
						errors <- fmt.Errorf("connect: %w", connectErr)
						return
					}
					request := []byte(fmt.Sprintf("request-%d", ordinal))
					response := []byte(fmt.Sprintf("response-%d", ordinal))
					if roundTripErr := pair.RoundTrip(ctx, request, response); roundTripErr != nil {
						errors <- fmt.Errorf("round trip: %w", roundTripErr)
					}
					if closeErr := pair.Close(); closeErr != nil {
						errors <- fmt.Errorf("cleanup: %w", closeErr)
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
	requireTransportIntegration(t)
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
	expected := sha256.Sum256(endpoint.certificateDER)
	if string(decoded) != string(expected[:]) {
		t.Fatalf("certificate hash does not match the served leaf DER")
	}
}

func TestProductDirectBrowserExternalTLSKeepsCandidateHostAndIssuesCAPolicy(t *testing.T) {
	requireTransportIntegration(t)
	certificate, _, _, _, err := interopharness.TLSMaterial("public-ca-test.example")
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	endpoint, err := OpenProductDirectBrowserEndpointAtWithTLS(
		context.Background(),
		"127.0.0.1",
		"public-ca-test.example",
		"http://127.0.0.1:9000",
		serverTLS,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	if !strings.HasPrefix(endpoint.CandidateURL(), "https://public-ca-test.example:") {
		t.Fatalf("candidate URL = %q", endpoint.CandidateURL())
	}
	issued, err := endpoint.IssueBrowserCAArtifact()
	if err != nil {
		t.Fatal(err)
	}
	defer issued.Cancel()
	document := productTestRoute(t, issued.ArtifactJSON())
	defer document.Release()
	policy := document.Root().Named("Route", "direct_leg").Named("Leg", "tls_policy")
	mode, ok := policy.Named("TLSPolicy", "mode").Uint()
	if !ok || mode != 0 || policy.Named("TLSPolicy", "pins").Len() != 0 {
		t.Fatal("independently signed browser route does not use the captured CA policy")
	}

}

func TestWebTransportTestCertificateUsesBrowserCompatibleP256(t *testing.T) {
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
	requireTransportIntegration(t)
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
		var material interopharness.Material
		if err := json.Unmarshal([]byte(issued.ArtifactJSON()), &material); err != nil {
			t.Fatal(err)
		}
		if material.WireRevision != interopharness.WireRevision {
			t.Fatalf("engineering material revision = %d", material.WireRevision)
		}
		document := productTestRoute(t, issued.ArtifactJSON())
		policy := document.Root().Named("Route", "direct_leg").Named("Leg", "tls_policy")
		mode, ok := policy.Named("TLSPolicy", "mode").Uint()
		pins := policy.Named("TLSPolicy", "pins")
		if !ok || mode != 1 || pins.Len() != 1 {
			document.Release()
			t.Fatal("independently signed browser route does not have exactly one captured pin")
		}
		pin := pins.Index(0)
		digest, ok := pin.Named("TLSPin", "leaf_der_sha256").ByteString()
		if !ok || !bytes.Equal(digest, endpoint.certificateHash[:]) {
			document.Release()
			t.Fatal("independently signed pin differs from the original served DER leaf")
		}
		expires, ok := pin.Named("TLSPin", "not_after_ms").Uint()
		certificate, err := x509.ParseCertificate(endpoint.certificateDER)
		document.Release()
		if err != nil || !ok || expires != uint64(certificate.NotAfter.UnixMilli()) {
			t.Fatalf("independently signed pin expiry = %d, certificate = %v", expires, certificate)
		}
		issued.Cancel()
		issued.Cancel()
	}
	if pending := endpoint.registry.PendingCount(); pending != 0 {
		t.Fatalf("original pending accepted records after cancellation = %d", pending)
	}
	if _, err := first.AwaitServer(context.Background()); err == nil {
		t.Fatal("canceled artifact could be awaited")
	}
}

func TestProductDirectWorkloadsUsePersistentEndpoint(t *testing.T) {
	requireTransportIntegration(t)
	// Its ephemeral endpoints and stores are private to this workload.
	t.Parallel()
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindRawQUIC, carrier.KindWebTransport} {
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
func (*coordinatedBrowserReadStream) Close() error { return nil }
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
	closeWrites  atomic.Int32
	resets       atomic.Int32
}

type gatedBrowserBidiStream struct {
	readAllowed <-chan struct{}
	closeWrite  chan struct{}
	stopped     chan struct{}
	closeOnce   sync.Once
	stopOnce    sync.Once
	read        bool
}

type orderedBrowserBidiStream struct {
	remainingRead int
	readComplete  chan struct{}
	readDone      sync.Once
	firstWrite    chan struct{}
	writeStarted  sync.Once
	writeAllowed  chan struct{}
	closeWrite    chan struct{}
	closeOnce     sync.Once
	closed        atomic.Bool
}

func newOrderedBrowserBidiStream(byteCount int) *orderedBrowserBidiStream {
	return &orderedBrowserBidiStream{
		remainingRead: byteCount,
		readComplete:  make(chan struct{}),
		firstWrite:    make(chan struct{}),
		writeAllowed:  make(chan struct{}),
		closeWrite:    make(chan struct{}),
	}
}

func (stream *orderedBrowserBidiStream) Read(buffer []byte) (int, error) {
	if stream.remainingRead == 0 {
		stream.readDone.Do(func() { close(stream.readComplete) })
		return 0, io.EOF
	}
	count := min(len(buffer), stream.remainingRead)
	for index := range count {
		buffer[index] = 0xa5
	}
	stream.remainingRead -= count
	return count, nil
}

func (stream *orderedBrowserBidiStream) Write(buffer []byte) (int, error) {
	for _, value := range buffer {
		if value != 0x5a {
			return 0, errors.New("unexpected server bulk payload")
		}
	}
	first := false
	stream.writeStarted.Do(func() {
		first = true
		close(stream.firstWrite)
	})
	if first {
		<-stream.writeAllowed
	}
	if stream.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	return len(buffer), nil
}

func (stream *orderedBrowserBidiStream) CloseWrite() error {
	stream.closed.Store(true)
	stream.closeOnce.Do(func() { close(stream.closeWrite) })
	return nil
}
func (*orderedBrowserBidiStream) Close() error         { return nil }
func (*orderedBrowserBidiStream) Reset() error         { return nil }
func (*orderedBrowserBidiStream) ID() uint64           { return 5 }
func (*orderedBrowserBidiStream) Kind() string         { return "release-bulk" }
func (*orderedBrowserBidiStream) TerminalError() error { return nil }

func (stream *gatedBrowserBidiStream) Read(buffer []byte) (int, error) {
	if stream.read {
		return 0, io.EOF
	}
	select {
	case <-stream.readAllowed:
	case <-stream.stopped:
		return 0, io.ErrClosedPipe
	}
	stream.read = true
	for index := range buffer {
		buffer[index] = 0xa5
	}
	return len(buffer), nil
}

func (*gatedBrowserBidiStream) Write(buffer []byte) (int, error) {
	for _, value := range buffer {
		if value != 0x5a {
			return 0, errors.New("unexpected server bulk payload")
		}
	}
	return len(buffer), nil
}

func (stream *gatedBrowserBidiStream) CloseWrite() error {
	stream.closeOnce.Do(func() { close(stream.closeWrite) })
	return nil
}
func (stream *gatedBrowserBidiStream) Close() error { return stream.Reset() }
func (stream *gatedBrowserBidiStream) Reset() error {
	stream.stopOnce.Do(func() { close(stream.stopped) })
	return nil
}
func (*gatedBrowserBidiStream) ID() uint64           { return 3 }
func (*gatedBrowserBidiStream) Kind() string         { return "release-bulk" }
func (*gatedBrowserBidiStream) TerminalError() error { return nil }

func (stream *coordinatedBrowserWriteStream) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (stream *coordinatedBrowserWriteStream) Write(buffer []byte) (int, error) {
	stream.startOnce.Do(func() { close(stream.writeStarted) })
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
func (*coordinatedBrowserWriteStream) Close() error { return nil }
func (stream *coordinatedBrowserWriteStream) Reset() error {
	stream.resets.Add(1)
	stream.stopOnce.Do(func() { close(stream.stopped) })
	return nil
}
func (stream *coordinatedBrowserWriteStream) CloseWriteCount() int32 {
	return stream.closeWrites.Load()
}
func (stream *coordinatedBrowserWriteStream) ResetCount() int32 { return stream.resets.Load() }

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

func TestReconcilePublicSessionCloseErrorRequiresAuthoritativeClosedTermination(t *testing.T) {
	requireTransportIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pair, err := OpenProductDirect(ctx, carrier.KindWebSocket)
	if err != nil {
		t.Fatal(err)
	}
	if err := pair.Server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pair.Server.WaitTermination(ctx); err != nil {
		t.Fatal(err)
	}
	closed := pair.Server.Rekey(ctx)
	var closedFailure *flowersec.SessionError
	if !errors.As(closed, &closedFailure) || closedFailure.Code() != flowersec.SessionClosed {
		t.Fatalf("closed original session projection: %v", closed)
	}
	unexpectedJoined := errors.New("unrelated cleanup failure")
	mixed := errors.Join(closed, unexpectedJoined)
	if remaining := filterSessionClosedErrors(mixed); !errors.Is(remaining, unexpectedJoined) || errors.Is(remaining, closed) {
		t.Fatalf("joined close filtering hid or retained the wrong cause: %v", remaining)
	}
	if isAuthoritativeSessionClosed(mixed) || isAuthoritativeSessionClosed(fmt.Errorf("wrapped: %w", mixed)) {
		t.Fatal("mixed terminal causes were accepted as authoritative closed")
	}
	if err := pair.Close(); err != nil {
		t.Fatalf("original peer-closed pair cleanup: %v", err)
	}
	if err := pair.Close(); err != nil {
		t.Fatalf("second original pair cleanup: %v", err)
	}
	unexpected := errors.New("redacted close failure")
	if err := normalizeCloseError(unexpected); !errors.Is(err, unexpected) {
		t.Fatalf("unproven close failure was hidden: %v", err)
	}
}

func TestNormalizeCloseErrorAcceptsOwnedPeerCloseReasons(t *testing.T) {
	for _, reason := range []string{"session closed", "tunnel bridge closed"} {
		err := &gorillaws.CloseError{Code: 4000, Text: reason}
		if normalized := normalizeCloseError(err); normalized != nil {
			t.Fatalf("normalize peer close %q = %v", reason, normalized)
		}
	}

	for _, unexpected := range []*gorillaws.CloseError{
		{Code: 4000, Text: "session protocol failure"},
		{Code: 4000, Text: "tunnel bridge closure"},
		{Code: gorillaws.CloseProtocolError, Text: "protocol error"},
	} {
		if normalized := normalizeCloseError(unexpected); normalized == nil {
			t.Fatalf("normalized unexpected close %#v", unexpected)
		}
	}
}

func TestNormalizeCloseErrorPreservesDirectionReset(t *testing.T) {
	for _, unexpected := range []error{native.ErrDirectionReset, sessionv4.ErrAbandoned, carrier.ErrStreamReset, errors.New("stream reset")} {
		if normalized := normalizeCloseError(unexpected); normalized == nil {
			t.Fatalf("unproven direction reset was hidden: %T: %v", unexpected, unexpected)
		}
	}
}
func productTestRoute(t *testing.T, wire string) *protocolv4.Document {
	t.Helper()
	var material interopharness.Material
	if err := json.Unmarshal([]byte(wire), &material); err != nil {
		t.Fatal(err)
	}
	decoder, err := protocolv4.NewDecoder(16384, 1024)
	if err != nil {
		t.Fatal(err)
	}
	document, err := decoder.DecodeMap(material.Route, "Route", protocolv4.DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func (*coordinatedBrowserReadStream) Finish(ctx context.Context) error { return ctx.Err() }

func (*coordinatedBrowserWriteStream) Finish(ctx context.Context) error { return ctx.Err() }

func (*gatedBrowserBidiStream) Finish(ctx context.Context) error { return ctx.Err() }

func (*orderedBrowserBidiStream) Finish(ctx context.Context) error { return ctx.Err() }

func (*blockingReleaseStream) Finish(ctx context.Context) error { return ctx.Err() }
