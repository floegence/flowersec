package tunnelworkload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"testing"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
)

func TestBrowserTunnelTopologiesUseProductionWebTransportBrokerPath(t *testing.T) {
	for _, topology := range BrowserTopologies() {
		t.Run(string(topology), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			endpoint, err := OpenBrowserEndpointAt(ctx, topology, "127.0.0.1", "https://127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
				defer stop()
				if err := endpoint.Close(cleanup); err != nil {
					t.Error(err)
				}
			}()
			issued, err := endpoint.IssueBrowserArtifact()
			if err != nil {
				t.Fatal(err)
			}
			if err = issued.Start(ctx); err != nil {
				t.Fatal(err)
			}
			reporter, err := interopharness.NewPeerReporter()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := reporter.Close(); err != nil {
					t.Error(err)
				}
			}()
			installed, binding, err := issued.PoolClientConfiguration()
			if err != nil {
				t.Fatal(err)
			}
			var definition *interopharness.RPCDefinition
			peer, err := interopharness.NewClient(ctx, reporter, issued.ArtifactJSON(), issued.relay.TrustPEM, endpoint.origin, currentTunnelHandlers(&definition), interopharness.ClientOptions{PoolClientDeployment: installed, ServerAllowBinding: binding})
			if err != nil {
				t.Fatal(err)
			}
			client, err := peer.Connect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			server, err := issued.AwaitServer(ctx)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := definition.Bind(ctx, client)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				bound.Close()
				if err := bound.WaitCleanup(ctx); err != nil {
					t.Error(err)
				}
			}()
			input := []byte(`"browser-tunnel-rpc"`)
			response, err := callTunnelEcho(ctx, bound, input)
			if err != nil || !bytes.Equal(response, input) {
				t.Fatalf("original browser service result: %q %v", response, err)
			}
			opened, err := client.OpenStream(ctx, "release-tunnel-bulk", fs.EmptyStreamMetadata())
			if err != nil {
				t.Fatal(err)
			}
			incoming, err := server.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if incoming.Kind != "release-tunnel-bulk" {
				t.Fatal("original stream kind changed")
			}
			transferred := make(chan error, 1)
			go func() {
				if _, err := opened.WriteAll(ctx, bytes.Repeat([]byte{0x42}, 4096)); err != nil {
					transferred <- err
					return
				}
				transferred <- opened.CloseWrite()
			}()
			body, err := io.ReadAll(incoming.Stream)
			if err != nil || !bytes.Equal(body, bytes.Repeat([]byte{0x42}, 4096)) {
				t.Fatalf("original bulk body: %d %v", len(body), err)
			}
			if err = <-transferred; err != nil {
				t.Fatal(err)
			}
			if _, err = incoming.Stream.WriteAll(ctx, []byte("FIN-response")); err != nil {
				t.Fatal(err)
			}
			if err = incoming.Stream.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			reply, err := io.ReadAll(opened)
			if err != nil || string(reply) != "FIN-response" {
				t.Fatalf("original reverse FIN: %q %v", reply, err)
			}
			if err = opened.Finish(ctx); err != nil {
				t.Fatal(err)
			}
			if err = incoming.Stream.Finish(ctx); err != nil {
				t.Fatal(err)
			}
			if err = opened.Close(); err != nil {
				t.Fatal(err)
			}
			if err = incoming.Stream.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = client.ProbeLiveness(ctx, 5000); err != nil {
				t.Fatal(err)
			}
			if topology == BrowserTunnelWTQUIC {
				sender, err := client.UnreliableMessages()
				if err != nil {
					t.Fatal(err)
				}
				receiver, err := server.UnreliableMessages()
				if err != nil {
					t.Fatal(err)
				}
				received := make(chan []byte, 1)
				failure := make(chan error, 1)
				receive, cancelReceive := context.WithTimeout(ctx, 5*time.Second)
				done := make(chan struct{})
				go func() {
					defer close(done)
					value, err := receiver.Receive(receive)
					if err != nil {
						failure <- err
					} else {
						received <- value
					}
				}()
				status, err := sender.Send(receive, []byte("native-browser-datagram"), fs.UnreliableSendOptions{ExpiresAt: time.Now().Add(5 * time.Second)})
				if err != nil || status != fs.UnreliableAccepted {
					cancelReceive()
					<-done
					t.Fatalf("original datagram send: %s %v", status, err)
				}
				select {
				case value := <-received:
					if string(value) != "native-browser-datagram" {
						t.Error("original datagram changed")
					}
				case err := <-failure:
					t.Error(err)
				}
				cancelReceive()
				<-done
			}
		})
	}
}
func TestBrowserCertificateHashMatchesOriginalTLSManifest(t *testing.T) {
	endpoint, err := OpenBrowserEndpointAt(context.Background(), BrowserTunnelWTQUIC, "127.0.0.1", "https://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close(context.Background())
	encoded, err := endpoint.CertificateHashBase64URL()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(endpoint.certificateDER)
	if encoded != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatal("browser hash differs from the original native leaf DER")
	}
	certificate, err := x509.ParseCertificate(endpoint.certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.NotAfter.Sub(certificate.NotBefore) > 14*24*time.Hour {
		t.Fatal("browser leaf exceeds the native certificate-hash lifetime")
	}
}
func TestBrowserOriginMustBeExactConcreteHTTPOrigin(t *testing.T) {
	for _, origin := range []string{"", "https://example.com", "https://0.0.0.0", "https://127.0.0.1/path", "https://127.0.0.1?x=1", "https://user@127.0.0.1"} {
		if err := validateBrowserOrigin(origin); err == nil {
			t.Fatalf("accepted browser Origin %q", origin)
		}
	}
	if !browserOriginAllowed("https://127.0.0.1:8443", "https://127.0.0.1") || browserOriginAllowed("http://127.0.0.1:8443", "https://127.0.0.1") {
		t.Fatal("browser Origin changed its signed scheme or host")
	}
}
func TestBrowserArtifactPreservesReadyPeerFailureOverCallerCancellation(t *testing.T) {
	want := errors.New("original server handshake failed")
	owner, cancel := context.WithCancelCause(context.Background())
	defer cancel(context.Canceled)
	ready := make(chan struct{})
	close(ready)
	artifact := &BrowserArtifact{ctx: owner, cancel: cancel, started: true, ready: ready, result: browserConnectResult{err: want}}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if session, err := artifact.AwaitServer(ctx); session != nil || !errors.Is(err, want) {
		t.Fatalf("ready original failure lost: %v", err)
	}
}
func TestBrowserArtifactCancelPreventsStartAndReleasesOriginalPosition(t *testing.T) {
	endpoint, err := OpenBrowserEndpointAt(context.Background(), BrowserTunnelWTWSS, "127.0.0.1", "https://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close(context.Background())
	artifact, err := endpoint.IssueBrowserArtifact()
	if err != nil {
		t.Fatal(err)
	}
	artifact.Cancel()
	if err := artifact.Start(context.Background()); err == nil {
		t.Fatal("canceled original material started a native handshake")
	}
	endpoint.mu.Lock()
	retained := endpoint.slots[artifact.position]
	endpoint.mu.Unlock()
	if retained != nil {
		t.Fatal("canceled original publication retained its finite position")
	}
}
func TestNativeScopeDoesNotDialWhenNamespaceIsMissing(t *testing.T) {
	called := false
	scope := namespaceSocketScope("missing-flowersec-client-netns")
	if err := scope(context.Background(), func() error { called = true; return nil }); err == nil || called {
		t.Fatalf("native namespace failure fell back to the ordinary network: %v", err)
	}
}
