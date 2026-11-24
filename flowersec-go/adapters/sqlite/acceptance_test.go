package sqlite

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v7"
	"github.com/floegence/flowersec/flowersec-go/v7/controlplane"
	"github.com/gorilla/websocket"
)

const workerEnv = "FLOWERSEC_SQLITE_ACCEPTANCE_WORKER"
const probeOrigin = "https://consumer.example"

type connectionProbe struct {
	Database string
	Artifact []byte
	Root     []byte
	Mode     string
}

func TestCredentialWorker(t *testing.T) {
	if os.Getenv(workerEnv) != "1" {
		return
	}
	var probe connectionProbe
	if err := json.NewDecoder(os.Stdin).Decode(&probe); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	store, err := Open(ctx, probe.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	artifact, err := flowersec.ParseArtifact(probe.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.Lease(artifact)
	if probe.Mode == "lost-ack" || probe.Mode == "exit-after-commit" {
		lease, err = flowersec.NewArtifactLease(artifact, func(ctx context.Context) error {
			if err := store.spend(ctx, artifact.LookupKey()); err != nil {
				return err
			}
			if probe.Mode == "exit-after-commit" {
				os.Exit(42)
			}
			return errors.New("commit acknowledgement unavailable")
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(probe.Root)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	session, err := flowersec.Connect(ctx, lease, flowersec.ConnectorOptions{Origin: probeOrigin, TrustRoots: roots})
	if err != nil {
		os.Exit(41)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

type childResult struct {
	code int
	log  string
}

func startProbe(t *testing.T, probe connectionProbe) <-chan childResult {
	t.Helper()
	input, err := json.Marshal(probe)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan childResult, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCredentialWorker$")
	cmd.Env = append(os.Environ(), workerEnv+"=1")
	cmd.Stdin = bytes.NewReader(input)
	go func() {
		defer cancel()
		output, err := cmd.CombinedOutput()
		if err != nil && cmd.ProcessState == nil {
			done <- childResult{-1, err.Error()}
			return
		}
		done <- childResult{cmd.ProcessState.ExitCode(), string(output)}
	}()
	return done
}

func probeFixture(t *testing.T, handler http.Handler) (connectionProbe, controlplane.AuthorizationRecord) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	server.StartTLS()
	t.Cleanup(server.Close)
	return issueProbe(t, strings.TrimPrefix(server.URL, "https://"), server.Certificate().Raw)
}

func issueProbe(t *testing.T, address string, root []byte) (connectionProbe, controlplane.AuthorizationRecord) {
	t.Helper()
	endpoints, err := controlplane.NewEndpointSet(controlplane.EndpointConfig{
		ID: "ws", URL: "wss://" + address + flowersec.WebSocketDirectPath, TLS: controlplane.CAPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session: controlplane.SessionOptions{ChannelID: "acceptance"}, Endpoints: endpoints,
		RendezvousGroupID: "group", ListenerAudience: "listener", UpstreamAddress: "127.0.0.1:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return connectionProbe{Database: createProbeDatabase(t), Root: root, Artifact: issued.ArtifactJSON()}, issued.AuthorizationRecord()
}

func createProbeDatabase(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.db")
	store, err := Create(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestUncertainSpendWritesNoAdmission(t *testing.T) {
	for _, mode := range []string{"lost-ack", "exit-after-commit", "lost-admission-response"} {
		t.Run(mode, func(t *testing.T) {
			observed := make(chan []byte, 1)
			upgrader := websocket.Upgrader{Subprotocols: []string{"flowersec.direct.v5"}, CheckOrigin: func(req *http.Request) bool { return req.Header.Get("Origin") == probeOrigin }}
			probe, _ := probeFixture(t, http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
				conn, err := upgrader.Upgrade(writer, req, nil)
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, reader, err := conn.NextReader()
				var prefix []byte
				if err == nil {
					prefix, err = io.ReadAll(io.LimitReader(reader, 4))
				}
				if os.IsTimeout(err) {
					t.Error("observer timed out waiting for the peer")
				}
				observed <- prefix
			}))
			check := func(mode string, code int, prefix string) {
				t.Helper()
				probe.Mode = mode
				if result := <-startProbe(t, probe); result.code != code {
					t.Fatalf("%s worker exit %d, want %d: %s", mode, result.code, code, result.log)
				}
				select {
				case got := <-observed:
					if string(got) != prefix {
						t.Fatalf("%s observed %d admission prefix bytes, want %d", mode, len(got), len(prefix))
					}
				case <-time.After(5 * time.Second):
					t.Fatal("missing upgraded peer observation")
				}
			}
			code := 41
			if mode == "exit-after-commit" {
				code = 42
			}
			prefix := ""
			if mode == "lost-admission-response" {
				prefix = "FSB5"
			}
			check(mode, code, prefix)
			store, err := Open(t.Context(), probe.Database)
			if err != nil {
				t.Fatal(err)
			}
			artifact, err := flowersec.ParseArtifact(probe.Artifact)
			if err != nil {
				t.Fatal(err)
			}
			var markers int
			err = store.db.QueryRowContext(t.Context(), "SELECT count(*) FROM client_spends WHERE credential=?", artifact.LookupKey()).Scan(&markers)
			if err := errors.Join(err, store.Close()); err != nil || markers != 1 {
				t.Fatalf("durable spend markers %d, want 1: %v", markers, err)
			}
			check("restart", 41, "")
			probe.Database = createProbeDatabase(t)
			check("observer-control", 41, "FSB5")
		})
	}
}

func TestConcurrentCredentialRedemption(t *testing.T) {
	for _, boundary := range []string{"client-spend", "server-admission"} {
		t.Run(boundary, func(t *testing.T) {
			serverDB := createProbeDatabase(t)
			released := make(chan error, 2)
			var authorizations atomic.Int32
			bothAuthorizing := make(chan struct{})
			bothDialing := make(chan struct{})
			var upgrades atomic.Int32
			acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
				CheckOrigin: func(req *http.Request) bool {
					if upgrades.Add(1) == 2 {
						close(bothDialing)
					}
					select {
					case <-bothDialing:
						return req.Header.Get("Origin") == probeOrigin
					case <-time.After(5 * time.Second):
						t.Error("missing concurrent dial")
						return false
					}
				},
				Authorize: func(ctx context.Context, req controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
					store, err := Open(ctx, serverDB)
					if err != nil {
						return controlplane.AuthorizationResponse{}, err
					}
					defer store.Close()
					ordinal := authorizations.Add(1)
					if ordinal == 2 {
						close(bothAuthorizing)
					}
					if boundary == "server-admission" && ordinal <= 2 {
						select {
						case <-bothAuthorizing:
						case <-time.After(5 * time.Second):
							t.Error("missing concurrent authorization")
							return controlplane.AuthorizationResponse{}, context.DeadlineExceeded
						}
					}
					return store.AuthorizeDirect(ctx, req)
				},
				Release: func(ctx context.Context, id string) {
					store, err := Open(ctx, serverDB)
					if err == nil {
						err = errors.Join(store.ReleaseLease(ctx, id), store.Close())
					}
					released <- err
				},
				OnSession: func(ctx context.Context, _ flowersec.Session, _ string) error {
					<-ctx.Done()
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			certSource := httptest.NewTLSServer(nil)
			certSource.Close()
			endpoint, err := flowersec.NewWebSocketHTTPServer(flowersec.WebSocketHTTPServerOptions{Handler: acceptor.Handler(), TLSConfig: &tls.Config{Certificates: certSource.TLS.Certificates}})
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { defer close(done); _ = endpoint.Serve(listener) }()
			t.Cleanup(func() { endpoint.Close(); listener.Close(); <-done })
			probe, record := issueProbe(t, listener.Addr().String(), certSource.Certificate().Raw)
			publisher, err := Open(t.Context(), serverDB)
			if err != nil {
				t.Fatal(err)
			}
			if err := errors.Join(publisher.Publish(t.Context(), record), publisher.Close()); err != nil {
				t.Fatal(err)
			}
			first := startProbe(t, probe)
			wantRequests := int32(1)
			if boundary == "server-admission" {
				probe.Database = createProbeDatabase(t)
				wantRequests = 2
			}
			second := startProbe(t, probe)
			left, right := <-first, <-second
			if !(left.code == 0 && right.code == 41 || left.code == 41 && right.code == 0) || authorizations.Load() != wantRequests {
				t.Fatalf("workers %+v, %+v and %d authorizations, want one session and %d authorizations", left, right, authorizations.Load(), wantRequests)
			}
			select {
			case err := <-released:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("missing lease release")
			}
			probe.Database = createProbeDatabase(t)
			if replay := <-startProbe(t, probe); replay.code != 41 || authorizations.Load() != wantRequests+1 {
				t.Fatalf("post-release admission %+v, authorizations %d", replay, authorizations.Load())
			}
		})
	}
}
