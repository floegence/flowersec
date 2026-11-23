package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v7"
	"github.com/floegence/flowersec/flowersec-go/v7/controlplane"
	carrierws "github.com/floegence/flowersec/flowersec-go/v7/internal/carrier/websocketv3"
)

func directClientAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func directTestArtifact(t *testing.T, endpoint string) controlplane.IssuedArtifact {
	t.Helper()
	return directTestArtifactForTCP(t, endpoint, "127.0.0.1:8000")
}

func directTestArtifactForTCP(t *testing.T, endpoint, upstream string) controlplane.IssuedArtifact {
	t.Helper()
	endpoints, err := controlplane.NewEndpointSet(controlplane.EndpointConfig{ID: "direct", URL: endpoint, TLS: controlplane.CAPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session:   controlplane.SessionOptions{ChannelID: "direct-client-test", ExpiresAt: time.Now().Add(time.Minute)},
		Endpoints: endpoints, RendezvousGroupID: "test-group", ListenerAudience: "runtime", UpstreamAddress: upstream,
	})
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

func directTestConfig(t *testing.T, issued controlplane.IssuedArtifact) directClientConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "artifact.json")
	if err := os.WriteFile(path, issued.ArtifactJSON(), 0600); err != nil {
		t.Fatal(err)
	}
	return directClientConfig{Role: "direct-client", SpendDirectory: t.TempDir(), Ingress: []directClientIngressSpec{{
		Address: directClientAddress(t), ArtifactFile: path, Origin: "https://app.example", Kind: "application.tcp", Metadata: map[string]any{"service": "reports"}, Slots: 2, TimeoutMS: 15000, ConnectTimeoutMS: 3000,
	}}}
}

func directTestJSON(t *testing.T, config directClientConfig) []byte {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type observedClientPeer struct {
	net.Listener
	dials atomic.Int32
}

func (peer *observedClientPeer) Accept() (net.Conn, error) {
	conn, err := peer.Listener.Accept()
	if err == nil {
		peer.dials.Add(1)
	}
	return conn, err
}

func TestDirectClientProcess(t *testing.T) {
	if len(os.Args) < 4 || os.Args[len(os.Args)-3] != "--" {
		return
	}
	os.Args = append([]string{"flowersec-runtime"}, os.Args[len(os.Args)-2:]...)
	main()
}

func TestDirectClientAuthenticatedForwardingAndRetirement(t *testing.T) {
	bound, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peer := &observedClientPeer{Listener: bound}
	t.Cleanup(func() { peer.Close() })
	issued := directTestArtifact(t, "wss://"+peer.Addr().String()+flowersec.WebSocketDirectPath)
	config := directTestConfig(t, issued)
	marker := filepath.Join(config.SpendDirectory, issued.LookupKey())
	var authorizations atomic.Int32
	blocked := make(chan struct{})
	released := make(chan struct{})
	handlers, err := flowersec.NewSessionHandlers(flowersec.SessionHandlerOptions{MaxConcurrentStreams: 2})
	if err != nil {
		t.Fatal(err)
	}
	err = handlers.HandleStream("application.tcp", func(ctx context.Context, incoming flowersec.IncomingStream) error {
		if incoming.Metadata.Values()["service"] != "reports" {
			return errors.New("missing configured metadata")
		}
		payload, err := io.ReadAll(incoming.Stream)
		if err != nil {
			return err
		}
		if string(payload) == "hold" {
			close(blocked)
			<-ctx.Done()
			return ctx.Err()
		}
		_, err = fmt.Fprintf(incoming.Stream, "reply:%s", payload)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		AllowedOrigins: []string{"https://app.example"},
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			if _, err := os.Stat(marker); err != nil || authorizations.Add(1) != 1 {
				return controlplane.RejectRuntime("permission_denied", false)
			}
			return controlplane.AuthorizeRuntime(request, issued.AuthorizationRecord(), "direct-client-lease")
		},
		Release: func(context.Context, string) { close(released) },
		ResolveHandlers: func(context.Context, controlplane.RuntimeAuthorizationRequest) (*flowersec.SessionHandlers, error) {
			return handlers, nil
		},
		OnSession: func(ctx context.Context, _ flowersec.Session, _ string) error { <-ctx.Done(); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	roots, key := writeTestCertificate(t)
	pair, err := tls.LoadX509KeyPair(roots, key)
	if err != nil {
		t.Fatal(err)
	}
	server, err := flowersec.NewWebSocketHTTPServer(flowersec.WebSocketHTTPServerOptions{Handler: acceptor.Handler(), TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}}})
	if err != nil {
		t.Fatal(err)
	}
	peerDone := make(chan struct{})
	go func() { defer close(peerDone); _ = server.Serve(peer) }()
	t.Cleanup(func() { _ = server.Close(); _ = peer.Close(); <-peerDone })
	config.Ingress[0].TLSRootsFile = roots
	raw := directTestJSON(t, config)
	file := filepath.Join(t.TempDir(), "client.json")
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestDirectClientProcess$", "--", "-config", file)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	done := make(chan struct{})
	var serveErr error
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "direct-client listening on "+config.Ingress[0].Address) {
				close(ready)
			}
		}
		serveErr = errors.Join(scanner.Err(), cmd.Wait())
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("direct client did not stop")
		}
	})
	select {
	case <-ready:
	case <-done:
		t.Fatalf("CLI startup: %v", serveErr)
	case <-time.After(5 * time.Second):
		t.Fatal("CLI did not report its local listener")
	}
	select {
	case <-time.After(60 * time.Millisecond):
	case <-done:
		t.Fatalf("idle listener stopped: %v", serveErr)
	}
	if peer.dials.Load() != 0 {
		t.Fatal("idle listener dialed upstream")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("idle spend: %v", err)
	}
	open := func(payload string) *net.TCPConn {
		t.Helper()
		conn, err := net.DialTimeout("tcp", config.Ingress[0].Address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		tcp := conn.(*net.TCPConn)
		t.Cleanup(func() { tcp.Close() })
		tcp.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = tcp.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		if err = tcp.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		return tcp
	}
	for _, payload := range []string{"first", "second"} {
		reply, err := io.ReadAll(open(payload))
		if err != nil || string(reply) != "reply:"+payload {
			t.Fatalf("reply after TCP FIN: %q, %v", reply, err)
		}
	}
	if authorizations.Load() != 1 || peer.dials.Load() != 1 {
		t.Fatalf("authorizations=%d dials=%d", authorizations.Load(), peer.dials.Load())
	}
	holding := open("hold")
	select {
	case <-blocked:
	case <-time.After(3 * time.Second):
		t.Fatal("peer did not receive blocked request")
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		if serveErr != nil {
			t.Fatal(serveErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not join the active relay")
	}
	if _, err = holding.Read(make([]byte, 1)); err == nil {
		t.Fatal("client TCP remained open")
	}
	select {
	case <-released:
	case <-time.After(3 * time.Second):
		t.Fatal("server authorization was not released")
	}
	if err = run([]string{"-config", file}); !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "already spent") {
		t.Fatalf("CLI restart replay: %v", err)
	}
}

func TestDirectClientConcurrentSpendAndServerAuthorization(t *testing.T) {
	for _, allow := range []bool{true, false} {
		t.Run(fmt.Sprintf("allow=%t", allow), func(t *testing.T) {
			upstream := startEchoServer(t)
			server := httptest.NewUnstartedServer(nil)
			issued := directTestArtifactForTCP(t, "wss://"+server.Listener.Addr().String()+webSocketDirectPath, upstream.Addr().String())
			var admits atomic.Int32
			authority := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path == "/release" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, 64<<10))
				if err != nil {
					http.Error(w, "invalid", 400)
					return
				}
				request, err := controlplane.ParseRuntimeAuthorizationRequest(body)
				if err != nil {
					http.Error(w, "invalid", 400)
					return
				}
				count := admits.Add(1)
				decision, err := controlplane.RejectRuntime(reasonAuthorizationDenied, false)
				if allow && count == 1 {
					decision, err = controlplane.AuthorizeRuntime(request, issued.AuthorizationRecord(), "test-lease")
				}
				if err != nil {
					http.Error(w, "invalid", 400)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(decision.JSON())
			}))
			t.Cleanup(authority.Close)
			resources, err := carrierws.BindSessionResourcePolicy(carrierws.DefaultResourcePolicy(), 32)
			if err != nil {
				t.Fatal(err)
			}
			runtime := &runtimeServer{config: Config{AllowedOrigins: []string{"https://app.example"}, AdmissionTimeoutSeconds: 3, MaxInboundStreams: 32},
				authorizer: &httpAuthorizationProvider{url: authority.URL + "/authorize", releaseURL: authority.URL + "/release", client: authority.Client()}, reasons: runtimeReasons(), wsResources: resources, directSlots: make(chan struct{}, 2), logger: log.New(io.Discard, "", 0)}
			serverCtx, cancelServer := context.WithCancel(t.Context())
			server.Config.Handler = runtime.webSocketHandler(serverCtx)
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
			server.StartTLS()
			t.Cleanup(func() { cancelServer(); server.Close(); runtime.sessionWG.Wait() })
			config := directTestConfig(t, issued)
			roots := filepath.Join(t.TempDir(), "roots.pem")
			if err := os.WriteFile(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			config.Ingress[0].TLSRootsFile = roots
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			var serving sync.WaitGroup
			t.Cleanup(func() { cancel(); serving.Wait() })
			var addresses []string
			for range 2 {
				config.Ingress[0].Address = directClientAddress(t)
				client, err := listenDirectClient(directTestJSON(t, config))
				if err != nil {
					t.Fatal(err)
				}
				addresses = append(addresses, config.Ingress[0].Address)
				serving.Go(func() { _ = client.serve(ctx) })
			}
			replies := make(chan string, 2)
			for _, address := range addresses {
				go func() {
					conn, err := net.DialTimeout("tcp", address, time.Second)
					if err != nil {
						replies <- ""
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
					_, _ = io.WriteString(conn, "unique request")
					_ = conn.(*net.TCPConn).CloseWrite()
					payload, _ := io.ReadAll(conn)
					replies <- string(payload)
				}()
			}
			success := 0
			for range addresses {
				if <-replies == "unique request" {
					success++
				}
			}
			want := 0
			if allow {
				want = 1
			}
			if success != want || admits.Load() != 1 {
				t.Fatalf("successful TCP forwards=%d, want %d; authorizer calls=%d, want 1", success, want, admits.Load())
			}
			if _, err := os.Stat(filepath.Join(config.SpendDirectory, issued.LookupKey())); err != nil {
				t.Fatal("spent marker absent after admission attempt")
			}
		})
	}
}

func TestDirectClientConfigRejectsUnsafeIngress(t *testing.T) {
	issued := directTestArtifact(t, "wss://example.com"+flowersec.WebSocketDirectPath)
	config := directTestConfig(t, issued)
	for _, invalid := range []string{"0.0.0.0:8080", "192.0.2.1:8080", "localhost:8080", "[::]:8080", "127.0.0.1:0"} {
		spec := config.Ingress[0]
		spec.Address = invalid
		if _, err := prepareDirectClientIngress(spec); err == nil {
			t.Errorf("accepted %q", invalid)
		}
	}
	valid := directTestJSON(t, config)
	for _, raw := range [][]byte{
		bytes.Replace(valid, []byte(`"role":`), []byte(`"role":"server","role":`), 1),
		bytes.Replace(valid, []byte(`"role":`), []byte(`"Role":"server","role":`), 1),
		bytes.Replace(valid, []byte(`"role":`), []byte(`"listeners":{},"role":`), 1),
		bytes.Replace(valid, []byte(`"slots":2`), []byte(`"slots":0`), 1),
		bytes.Replace(valid, []byte(`"application.tcp"`), []byte(`"flowersec.rpc.v5"`), 1),
	} {
		if client, err := listenDirectClient(raw); err == nil {
			client.close()
			t.Error("accepted invalid config")
		}
	}
	config.Ingress = append(config.Ingress, config.Ingress[0])
	config.Ingress[1].Address = directClientAddress(t)
	if client, err := listenDirectClient(directTestJSON(t, config)); err == nil {
		client.close()
		t.Fatal("accepted duplicated credential")
	}
	if listener, err := net.Listen("tcp", config.Ingress[0].Address); err != nil {
		t.Fatalf("failed setup leaked first listener: %v", err)
	} else {
		listener.Close()
	}
	if err := os.Chmod(config.Ingress[0].ArtifactFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareDirectClientIngress(config.Ingress[0]); err == nil {
		t.Fatal("accepted world-readable artifact")
	}
}
