package flowersec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/rpc"
	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
)

// TestConnectionControllerRealNetworkRestartReconnect owns a real raw QUIC
// listener for each attempt. Stopping the first listener terminates the
// current Session; the controller must acquire a fresh lease and connect to
// the newly started listener without replaying application operations.
func TestConnectionControllerRealNetworkRestartReconnect(t *testing.T) {
	serverTLS, trustRoots := controllerNetworkTLS(t)
	source := &networkRestartSource{serverTLS: serverTLS}
	controller, err := NewConnectionController(source, ConnectionControllerOptions{Connector: ConnectorOptions{
		TrustRoots: trustRoots, ConnectTimeout: 5 * time.Second,
	}})
	if err != nil {
		t.Fatal(err)
	}
	controller.Start(context.Background())
	t.Cleanup(func() {
		closeController(t, controller)
		source.stopAll()
	})

	first := source.waitServer(t, 0)
	firstSession := waitControllerSessionNetwork(t, controller, source, 5*time.Second)
	oldStream, err := firstSession.OpenStream(context.Background(), "restart-old", StreamMetadata{})
	if err != nil {
		t.Fatalf("open stream on first session: %v", err)
	}
	if err := firstSession.RPC().Notify(context.Background(), 901, map[string]string{"phase": "before-restart"}); err != nil {
		t.Fatalf("notify before restart: %v", err)
	}
	if _, err := oldStream.Write([]byte("before-restart")); err != nil {
		t.Fatalf("write before restart: %v", err)
	}

	// This closes the actual UDP listener and established server session. The
	// next controller attempt starts a fresh listener on a new ephemeral port.
	first.stop()
	terminationCtx, cancelTermination := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelTermination()
	if _, err := firstSession.WaitTermination(terminationCtx); err != nil {
		t.Fatalf("first session did not terminate after listener restart: %v", err)
	}
	secondSession := waitForReplacementSession(t, controller, firstSession, 5*time.Second)
	if source.acquireCount() != 2 {
		t.Fatalf("artifact acquisitions = %d, want 2", source.acquireCount())
	}
	if err := firstSession.RPC().Notify(context.Background(), 902, map[string]string{"phase": "must-not-replay"}); err == nil {
		t.Fatal("old RPC after reconnect unexpectedly succeeded")
	}
	if _, err := oldStream.Write([]byte("must-not-migrate")); err == nil {
		t.Fatal("old stream write after reconnect unexpectedly succeeded")
	}

	// The replacement server has completed only the protocol handshake. A
	// short accept window proves that no application stream was replayed.
	probeCtx, cancelProbe := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelProbe()
	if _, err := secondSession.AcceptStream(probeCtx); err == nil {
		t.Fatal("replacement session received a replayed application stream")
	}
}

func waitControllerSessionNetwork(t *testing.T, controller *ConnectionController, source *networkRestartSource, timeout time.Duration) Session {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		snapshot := controller.Snapshot()
		if snapshot.State == ConnectionConnected && snapshot.CurrentSession != nil {
			return snapshot.CurrentSession
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("controller did not connect: %s; server errors: %s", controller.Snapshot(), source.failureSummary())
	return nil
}

func waitForReplacementSession(t *testing.T, controller *ConnectionController, previous Session, timeout time.Duration) Session {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		snapshot := controller.Snapshot()
		if snapshot.State == ConnectionConnected && snapshot.CurrentSession != nil && snapshot.CurrentSession != previous {
			return snapshot.CurrentSession
		}
		time.Sleep(5 * time.Millisecond)
	}
	snapshot := controller.Snapshot()
	t.Fatalf("controller did not replace session: %s failure=%v", snapshot, snapshot.Failure)
	return nil
}

type networkRestartSource struct {
	mu        sync.Mutex
	serverTLS *tls.Config
	servers   []*networkRestartServer
	acquires  int
}

func (source *networkRestartSource) Acquire(ctx context.Context) (ArtifactLease, *ArtifactSourceError) {
	if err := ctx.Err(); err != nil {
		return ArtifactLease{}, NewTerminalArtifactSourceError(err)
	}
	server, err := startNetworkRestartServer(source.serverTLS.Clone())
	if err != nil {
		return ArtifactLease{}, NewTerminalArtifactSourceError(err)
	}
	artifact, err := controllerNetworkArtifact(server.listener.Addr().String())
	if err != nil {
		server.stop()
		return ArtifactLease{}, NewTerminalArtifactSourceError(err)
	}
	lease, err := NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		server.stop()
		return ArtifactLease{}, NewTerminalArtifactSourceError(err)
	}
	source.mu.Lock()
	source.servers = append(source.servers, server)
	source.acquires++
	source.mu.Unlock()
	return lease, nil
}

func (source *networkRestartSource) waitServer(t *testing.T, index int) *networkRestartServer {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		source.mu.Lock()
		if len(source.servers) > index {
			server := source.servers[index]
			source.mu.Unlock()
			return server
		}
		source.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("network server %d was not started", index)
	return nil
}

func (source *networkRestartSource) acquireCount() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.acquires
}

func (source *networkRestartSource) failureSummary() string {
	source.mu.Lock()
	defer source.mu.Unlock()
	var summaries []string
	for index, server := range source.servers {
		server.mu.Lock()
		err := server.runErr
		server.mu.Unlock()
		if err != nil {
			summaries = append(summaries, fmt.Sprintf("%d:%v", index, err))
		}
	}
	return strings.Join(summaries, "; ")
}

func (source *networkRestartSource) stopAll() {
	source.mu.Lock()
	servers := append([]*networkRestartServer(nil), source.servers...)
	source.mu.Unlock()
	for _, server := range servers {
		server.stop()
	}
}

type networkRestartServer struct {
	listener *rawquic.Listener
	stopOnce sync.Once
	stopCh   chan struct{}
	done     chan error
	runErr   error
	secure   flowersession.SessionV2
	carrier  *rawquic.Session
	mu       sync.Mutex
}

func startNetworkRestartServer(serverTLS *tls.Config) (*networkRestartServer, error) {
	serverTLS.NextProtos = []string{rawquic.ALPNDirect}
	limits, err := quicbase.BindSessionLimits(quicbase.DefaultLimits(), 64)
	if err != nil {
		return nil, err
	}
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS, limits)
	if err != nil {
		return nil, err
	}
	server := &networkRestartServer{listener: listener, stopCh: make(chan struct{}), done: make(chan error, 1)}
	go server.run()
	return server, nil
}

func (server *networkRestartServer) run() {
	finish := func(err error) {
		server.mu.Lock()
		server.runErr = err
		server.mu.Unlock()
		server.done <- err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	carrierSession, err := server.listener.Accept(ctx)
	if err != nil {
		finish(err)
		return
	}
	server.mu.Lock()
	server.carrier = carrierSession
	server.mu.Unlock()
	defer carrierSession.Close()
	admission, err := carrierSession.AcceptStream(ctx)
	if err != nil {
		finish(err)
		return
	}
	decoded, err := admissionv2.Serve(ctx, admission, nil, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
		return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
	})
	if err != nil {
		finish(err)
		return
	}
	contract := decoded.Request
	secure, err := flowersession.Establish(ctx, carrierSession, flowersession.Config{
		Role: flowersession.RoleServer, Path: flowersession.PathDirect,
		ChannelID: contract.ChannelID, SessionContractHash: contract.SessionContractHash,
		Suite: protocolv2.Suite(1), PSK: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		MaxInboundStreams: 64, IdleTimeout: 60 * time.Second, EstablishTimeout: 30 * time.Second,
		RekeyPrepareTimeout: 10 * time.Second, RekeyCompletionTimeout: 30 * time.Second,
		LocalAdmissionBinding: decoded.LocalAdmissionBinding, PeerAdmissionBinding: decoded.LocalAdmissionBinding,
		RPCRouter: rpc.NewRouter(),
	})
	if err != nil {
		finish(err)
		return
	}
	server.mu.Lock()
	server.secure = secure
	server.mu.Unlock()
	select {
	case <-server.stopCh:
		_ = secure.Close()
	case <-secure.Termination():
	}
	finish(nil)
}

func (server *networkRestartServer) stop() {
	server.stopOnce.Do(func() {
		close(server.stopCh)
		server.mu.Lock()
		secure := server.secure
		server.mu.Unlock()
		if secure != nil {
			_ = secure.Close()
		}
		_ = server.listener.Close()
	})
	select {
	case <-server.done:
	case <-time.After(5 * time.Second):
	}
}

func controllerNetworkTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, pool
}

func controllerNetworkArtifact(address string) (Artifact, error) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "transport_v2", "artifact_vectors.json"))
	if err != nil {
		return Artifact{}, err
	}
	var fixture struct {
		Positive []struct {
			ArtifactJSON string `json:"artifact_json"`
		} `json:"positive"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil || len(fixture.Positive) == 0 {
		return Artifact{}, errors.New("invalid artifact fixture")
	}
	decoded, err := artifactv2.DecodeArtifactJSON(strings.NewReader(fixture.Positive[0].ArtifactJSON))
	if err != nil {
		return Artifact{}, err
	}
	decoded.Path.Candidates = []artifactv2.Candidate{{ID: "q1", Carrier: artifactv2.CarrierRawQUIC, URL: "quic://" + address, WireProfile: rawquic.ALPNDirect}}
	encoded, err := artifactv2.MarshalArtifactJSON(*decoded)
	if err != nil {
		return Artifact{}, err
	}
	return ParseArtifact(encoded)
}
