package transportrelease

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
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
