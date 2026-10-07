package interopharness

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
)

func manualEchoPlan(_ *Runtime, role uint8) (fs.StreamHandlerPlanConfig, error) {
	return fs.StreamHandlerPlanConfig{RuntimeBytes: 16384, Handlers: []fs.RawStreamHandlerConfig{{Kind: "engineering/manual", Manual: true, Slots: 2, WorkClass: fs.WorkResident, AuthorizeOpen: func(_ context.Context, binding any, _ []byte) error {
		if binding != role {
			return errors.New("manual OPEN has a foreign application lease")
		}
		return nil
	}}}}, nil
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
