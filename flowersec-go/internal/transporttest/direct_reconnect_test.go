package transporttest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// Each iteration closes real listener-owned sockets. Reconnection acquires a
// fresh signed lease and performs the ordinary SQLite, Noise and READY path;
// an original stream/RPC handle never migrates into its replacement Session.
func TestCurrentDirectInterruptionReleasesOriginalOwnersBeforeReconnect(t *testing.T) {
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindRawQUIC, carrier.KindWebTransport} {
		for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
			t.Run(string(kind)+"/"+profile, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
				defer cancel()
				endpoint, err := OpenProductDirectEndpointWithProfile(ctx, kind, profile)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := endpoint.Close(); err != nil {
						t.Errorf("original listener cleanup: %v", err)
					}
				}()
				baseline := endpoint.server.Runtime.Authority.Root.Snapshot().Charged
				var previous *ProductDirectPair
				for cycle := 0; cycle < 2; cycle++ {
					pair, err := endpoint.Connect(ctx)
					if err != nil {
						t.Fatalf("original connect %d: %v", cycle, err)
					}
					t.Cleanup(func() {
						if err := pair.Close(); err != nil {
							t.Errorf("original pair cleanup: %v", err)
						}
					})
					payload := []byte{byte(cycle), 0x51, 0x6b}
					response, err := pair.CallEcho(ctx, payload)
					if err != nil || !bytes.Equal(response, payload) {
						t.Fatalf("original echo %d: %x %v", cycle, response, err)
					}
					if previous != nil {
						if response, err := previous.CallEcho(ctx, []byte("must-not-migrate")); err == nil || len(response) != 0 {
							t.Fatal("retired original RPC migrated into the replacement Session")
						}
						if previous.Client == pair.Client || previous.Server == pair.Server {
							t.Fatal("fresh original admission reused an old Session handle")
						}
					}
					opened, err := pair.Client.OpenStream(ctx, "weaknet-outage", flowersec.EmptyStreamMetadata())
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = opened.Close() })
					incoming, err := pair.Server.AcceptStream(ctx)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = incoming.Stream.Close() })
					if incoming.Kind != "weaknet-outage" {
						t.Fatal("authenticated interruption stream kind changed")
					}
					if _, err = opened.WriteAll(ctx, payload); err != nil {
						t.Fatal(err)
					}
					received := make([]byte, len(payload))
					if _, err = io.ReadFull(incoming.Stream, received); err != nil || !bytes.Equal(received, payload) {
						t.Fatalf("original active stream before interruption: %x %v", received, err)
					}
					if err = endpoint.InterruptConnections(); err != nil {
						t.Fatalf("actual %s socket interruption: %v", kind, err)
					}
					observed, stop := context.WithTimeout(ctx, 5*time.Second)
					for _, session := range []*flowersec.Session{pair.Client, pair.Server} {
						if err = session.WaitTermination(observed); err == nil || observed.Err() != nil {
							stop()
							t.Fatalf("original physical interruption did not terminate its Session: %v", err)
						}
					}
					if next, err := pair.Client.OpenStream(ctx, "weaknet-outage", flowersec.EmptyStreamMetadata()); err == nil || next != nil {
						t.Fatal("old Session accepted another stream after physical interruption")
					}
					if count, err := opened.WriteAll(ctx, []byte("old-stream")); err == nil || count != 0 {
						t.Fatalf("old stream retained submission capacity: %d %v", count, err)
					}
					// Transport failure revokes I/O; the application still owns
					// the two original raw handles until it explicitly closes them.
					if err = errors.Join(opened.Close(), incoming.Stream.Close()); err != nil {
						t.Fatal(err)
					}
					for _, session := range []*flowersec.Session{pair.Client, pair.Server} {
						if err = session.WaitCleanup(observed); err != nil {
							stop()
							t.Fatalf("original interrupted Session retained provider cleanup: %v status=%+v", err, session.CleanupStatus())
						}
					}
					stop()
					if pair.SpendCount() != 1 {
						t.Fatal("physical interruption changed the original durable spend")
					}
					if err = pair.Close(); err != nil {
						t.Fatalf("original interrupted owners cleanup: %v", err)
					}
					for _, result := range pair.TerminationResults() {
						if !result.Observed || result.Cause == nil {
							t.Fatal("cleanup discarded the original transport terminal failure")
						}
					}
					if got := endpoint.server.Runtime.Authority.Root.Snapshot().Charged; got != baseline {
						t.Fatalf("retired interruption graph retained root charges: before=%v after=%v", baseline, got)
					}
					if endpoint.registry.PendingCount() != 0 {
						t.Fatal("retired interruption graph retained an unclaimed original record")
					}
					previous = pair
				}
				replacement, err := endpoint.Connect(ctx)
				if err != nil {
					t.Fatalf("listener could not admit a final fresh Session: %v", err)
				}
				defer func() {
					if err := replacement.Close(); err != nil {
						t.Error(err)
					}
				}()
				response, err := replacement.CallEcho(ctx, []byte("after-real-reconnect"))
				if err != nil || !bytes.Equal(response, []byte("after-real-reconnect")) {
					t.Fatalf("replacement application: %q %v", response, err)
				}
				if replacement.SpendCount() != 1 {
					t.Fatal("replacement did not retain its own original durable spend")
				}
			})
		}
	}
}

func TestCurrentDirectCanceledAcceptanceCannotConsumeReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	endpoint, err := OpenProductDirectEndpoint(ctx, carrier.KindWebSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := endpoint.Close(); err != nil {
			t.Error(err)
		}
	}()
	policy, err := currentCAPolicy(true)
	if err != nil {
		t.Fatal(err)
	}
	_, record, err := endpoint.issue(policy, endpoint.server.Address, false)
	if err != nil {
		t.Fatal(err)
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if session, err := record.WaitSession(canceled); session != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled original acceptance wait: %v", err)
	}
	if err = record.Close(); err != nil {
		t.Fatal(err)
	}
	if endpoint.registry.PendingCount() != 0 {
		t.Fatal("withdrawn unused original record remained available")
	}
	pair, err := endpoint.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pair.Close(); err != nil {
			t.Error(err)
		}
	}()
	response, err := pair.CallEcho(ctx, []byte("independent-original-record"))
	if err != nil || !bytes.Equal(response, []byte("independent-original-record")) {
		t.Fatalf("independent original admission after withdrawal: %q %v", response, err)
	}
	if pair.SpendCount() != 1 {
		t.Fatal("unused withdrawal consumed the replacement's original durable claim")
	}
}
