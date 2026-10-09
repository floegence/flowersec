package interopharness

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type failedNamespaceBootstrap struct {
	failure error
	queries int
}

func (p *failedNamespaceBootstrap) Query(context.Context, protocolv4.NamespaceBootstrapRequest, []byte) (int, error) {
	p.queries++
	return 0, p.failure
}

func (*failedNamespaceBootstrap) Fetch(context.Context, protocolv4.NamespaceContent, []byte) (int, error) {
	return 0, errors.New("failed bootstrap unexpectedly fetched namespace state")
}

func TestReporterBootstrapFailureRetiresOriginalNamespaceOwner(t *testing.T) {
	for _, failure := range []error{timev4.ErrFutureTimestamp, timev4.ErrExpired} {
		t.Run(failure.Error(), func(t *testing.T) {
			reporter, err := NewPeerReporter()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := reporter.Close(); err != nil {
					t.Error(err)
				}
			}()
			provider := &failedNamespaceBootstrap{failure: failure}
			reporter.bootstrap = provider
			policy, err := protocolv4.EncodeMap(make([]byte, 4096), "TLSPolicy", []protocolv4.Field{{Name: "mode"}, {Name: "require_consumer_tls13_verification", Kind: protocolv4.Boolean, Number: 1}})
			if err != nil {
				t.Fatal(err)
			}
			authority, err := construct(reporter, func() *sessionv4.PublicQUICTestHarness {
				return sessionv4.NewEngineeringNativeHarness(reporter, "preauthorized_pool", protocolv4.DHProfileX25519, "websocket", netip.MustParseAddrPort("127.0.0.1:443"), policy, "https://runner.flowersec.invalid", false)
			})
			if authority != nil || !errors.Is(err, failure) || provider.queries != 1 {
				t.Fatalf("original failed bootstrap: authority=%v, err=%v, queries=%d", authority, err, provider.queries)
			}
			if err := reporter.Close(); err != nil {
				t.Fatalf("failed bootstrap retained a namespace owner: %v", err)
			}
		})
	}
}

func manualEchoPlan(_ *Runtime, role uint8) (fs.StreamHandlerPlanConfig, error) {
	return fs.StreamHandlerPlanConfig{RuntimeBytes: 16384, Handlers: []fs.RawStreamHandlerConfig{{Kind: "engineering/manual", Manual: true, Slots: 2, WorkClass: fs.WorkResident, AuthorizeOpen: func(_ context.Context, binding any, _ []byte) error {
		if binding != role {
			return errors.New("manual OPEN has a foreign application lease")
		}
		return nil
	}}}}, nil
}

func TestReporterClosesClientCarrierBeforeWaitingForRuntime(t *testing.T) {
	for _, kind := range []string{"websocket", "raw-quic", "webtransport"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			serverReporter, err := NewPeerReporter()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := serverReporter.Close(); err != nil {
					t.Error(err)
				}
			}()
			server, err := NewServer(ctx, serverReporter, ServerOptions{Carrier: kind, Handlers: manualEchoPlan})
			if err != nil {
				t.Fatal(err)
			}
			wire, err := server.Material().JSON()
			if err != nil {
				t.Fatal(err)
			}
			clientReporter, err := NewPeerReporter()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := clientReporter.Close(); err != nil {
					t.Error(err)
				}
			}()
			client, err := NewClient(ctx, clientReporter, wire, server.TrustPEM, server.Origin, manualEchoPlan)
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseOwners()
			owner, ok := client.Carrier.(carrierCleanupOwner)
			if !ok {
				t.Fatal("client did not retain its physical carrier owner")
			}
			// Reporter shutdown must retire the original carrier without entering
			// Client.CloseOwners or the one-shot diagnostic cleanup callbacks.
			clientReporter.CloseOwners()
			cleanup, stop := context.WithTimeout(ctx, 2*time.Second)
			defer stop()
			if err := clientReporter.WaitOwners(cleanup); err != nil {
				t.Fatalf("reporter physical owners: %v", err)
			}
			if err := owner.WaitCleanup(cleanup); err != nil {
				t.Fatalf("original client carrier remained live after reporter shutdown: %v", err)
			}
		})
	}
}

// This test exercises the public source, actual namespace bootstrap, SQLite
// consume, network Noise/READY and registered manual dispatch as one graph.
func TestCurrentSourceAndManualStreamRetainOriginalOwners(t *testing.T) {
	for _, kind := range []string{"websocket", "raw-quic", "webtransport"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			serverReporter, err := NewPeerReporter()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := serverReporter.Close(); err != nil {
					t.Error(err)
				}
			}()
			server, err := NewServer(ctx, serverReporter, ServerOptions{Carrier: kind, Handlers: manualEchoPlan})
			if err != nil {
				t.Fatal(err)
			}
			wire, err := server.Material().JSON()
			if err != nil {
				t.Fatal(err)
			}
			clientReporter, err := NewPeerReporter()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := clientReporter.Close(); err != nil {
					t.Error(err)
				}
			}()
			client, err := NewClient(ctx, clientReporter, wire, server.TrustPEM, server.Origin, manualEchoPlan)
			if err != nil {
				t.Fatal(err)
			}
			session, err := client.Connect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			accepted, err := server.WaitSession(ctx)
			if err != nil {
				t.Fatal(err)
			}
			canceled, stop := context.WithCancel(ctx)
			stop()
			if _, err := accepted.AcceptStream(canceled); !errors.Is(err, context.Canceled) {
				t.Fatalf("manual canceled wait changed incoming ownership: %v", err)
			}
			opened, err := session.OpenStream(ctx, "engineering/manual", fs.EmptyStreamMetadata())
			if err != nil {
				t.Fatal(err)
			}
			incoming, err := accepted.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if incoming.Kind != "engineering/manual" {
				t.Fatal("manual dispatch changed the authenticated kind")
			}
			replied := make(chan error, 1)
			go func() {
				payload, err := io.ReadAll(incoming.Stream)
				if err == nil && string(payload) != "request" {
					err = errors.New("manual receiver changed its input")
				}
				if err == nil {
					_, err = incoming.Stream.WriteAll(ctx, []byte("response"))
				}
				if err == nil {
					err = incoming.Stream.Finish(ctx)
				}
				replied <- err
			}()
			if _, err = opened.WriteAll(ctx, []byte("request")); err != nil {
				t.Fatal(err)
			}
			if err = opened.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			reply, err := io.ReadAll(opened)
			if err != nil || string(reply) != "response" {
				t.Fatalf("manual response/FIN: %q %v", reply, err)
			}
			if err = opened.Finish(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err = <-replied:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if err = opened.Close(); err != nil {
				t.Fatal(err)
			}
			if err = incoming.Stream.Close(); err != nil {
				t.Fatal(err)
			}
			if err = session.Close(); err != nil {
				t.Fatal(err)
			}
			if err = accepted.Close(); err != nil {
				t.Fatal(err)
			}
			if err = session.WaitCleanup(ctx); err != nil {
				t.Fatal(err)
			}
			if err = accepted.WaitCleanup(ctx); err != nil {
				t.Fatal(err)
			}
			if client.Runtime.SourceAcquisitions.Load() != 1 || !client.Runtime.PoolSpend.Snapshot().CommitKnown || !client.Runtime.PoolSpend.Snapshot().Retired || client.Runtime.Authorized[0].Load() != 1 || client.Runtime.Released[0].Load() != 1 || server.Runtime.Authorized[1].Load() != 1 || server.Runtime.Released[1].Load() != 1 {
				t.Fatal("actual source/application lease owners did not retire exactly once")
			}
		})
	}
}

func TestLocalBridgeRejectsTokenAndOriginBeforeUpgrade(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reporter, err := NewPeerReporter()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reporter.Close(); err != nil {
			t.Error(err)
		}
	}()
	server, err := NewServer(ctx, reporter, ServerOptions{Carrier: "local-websocket", LocalBridgeToken: "independent-host-token", Handlers: manualEchoPlan})
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []struct{ origin, token string }{{server.Origin, "wrong-token"}, {"http://127.0.0.2", "independent-host-token"}} {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.Origin+"/flowersec/v4/local", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", attempt.origin)
		request.Header.Set("X-Flowersec-Private-Bridge-Token", attempt.token)
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "websocket")
		request.Header.Set("Sec-WebSocket-Version", "13")
		request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		request.Header.Set("Sec-WebSocket-Protocol", "flowersec.local.v4")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusForbidden || strings.Contains(string(body), "101") {
			t.Fatalf("local bridge policy: %d %q", response.StatusCode, body)
		}
	}
	if server.UpgradeAuthorizations.Load() != 0 || server.Runtime.Authorized[1].Load() != 0 {
		t.Fatal("invalid private bridge input reached an upgrade or Session application authorization")
	}
}
