package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v5"
	"github.com/floegence/flowersec/flowersec-go/v5/controlplane"
)

const (
	defaultOrigin = "https://client.example"
	echoRPC       = uint32(7001)
	notifyRPC     = uint32(7002)
	completeRPC   = uint32(7003)
	datagramRPC   = uint32(7005)
	echoKind      = "parity.echo"
	resetKind     = "parity.reset"
	peerTimeout   = 30 * time.Second
)

type readyMessage struct {
	Type         string `json:"type"`
	Runtime      string `json:"runtime"`
	Carrier      string `json:"carrier"`
	Path         string `json:"path"`
	ArtifactJSON string `json:"artifact_json"`
	TrustPEM     string `json:"trust_pem"`
	Origin       string `json:"origin"`
}

type resultMessage struct {
	Type    string   `json:"type"`
	Runtime string   `json:"runtime"`
	Carrier string   `json:"carrier"`
	Path    string   `json:"path"`
	Cases   []string `json:"cases"`
}

type tunnelRelayReadyMessage struct {
	Type                 string   `json:"type"`
	Runtime              string   `json:"runtime"`
	Carrier              string   `json:"carrier"`
	Path                 string   `json:"path"`
	EndpointURL          string   `json:"endpoint_url"`
	TrustPEM             string   `json:"trust_pem"`
	TrustRootsDER        []string `json:"trust_roots_der"`
	ServerCertificateDER string   `json:"server_certificate_der"`
	Origin               string   `json:"origin"`
}

type tunnelEndpointBReadyMessage struct {
	Type                  string                    `json:"type"`
	Runtime               string                    `json:"runtime"`
	Carrier               string                    `json:"carrier"`
	Path                  string                    `json:"path"`
	EndpointAArtifactJSON string                    `json:"endpoint_a_artifact_json"`
	EndpointBArtifactJSON string                    `json:"endpoint_b_artifact_json"`
	Relay                 tunnelRelayReadyMessage   `json:"relay"`
	Authorizations        []tunnelAuthorizationWire `json:"authorizations"`
	VerificationRecords   map[string]string         `json:"verification_records"`
}

type tunnelAuthorizationWire struct {
	Decision                       string `json:"decision"`
	CredentialID                   string `json:"credentialId"`
	LeaseID                        string `json:"leaseId"`
	ExpiresAtUnixSeconds           int64  `json:"expiresAtUnixSeconds"`
	ExpectedPeerEndpointInstanceID string `json:"expectedPeerEndpointInstanceId"`
	AllowReplacement               bool   `json:"allowReplacement"`
}

type tunnelInput struct {
	Topology struct {
		ID              string `json:"id"`
		EndpointA       string `json:"endpoint_a"`
		EndpointB       string `json:"endpoint_b"`
		TunnelRuntime   string `json:"tunnel_runtime"`
		IngressCarrierA string `json:"ingress_carrier_a"`
		IngressCarrierB string `json:"ingress_carrier_b"`
	} `json:"topology"`
	Relay     tunnelRelayReadyMessage     `json:"relay"`
	EndpointB tunnelEndpointBReadyMessage `json:"endpoint_b"`
}

type tunnelRelayResultMessage struct {
	Type              string   `json:"type"`
	Runtime           string   `json:"runtime"`
	Carrier           string   `json:"carrier"`
	Path              string   `json:"path"`
	Cases             []string `json:"cases"`
	ObservedPlaintext bool     `json:"observed_plaintext"`
	ReleasedLeases    int32    `json:"released_leases"`
}

type executionLedger struct {
	mu    sync.Mutex
	cases []string
	seen  map[string]struct{}
}

func newExecutionLedger() *executionLedger {
	return &executionLedger{seen: make(map[string]struct{})}
}

func (ledger *executionLedger) record(caseIDs ...string) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	for _, caseID := range caseIDs {
		if _, exists := ledger.seen[caseID]; exists {
			continue
		}
		ledger.seen[caseID] = struct{}{}
		ledger.cases = append(ledger.cases, caseID)
	}
}

func (ledger *executionLedger) snapshot() []string {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	return append([]string(nil), ledger.cases...)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if os.Getenv("FLOWERSEC_SERVER_PARITY_PEER") != "1" {
		return errors.New("server parity peer is test-only")
	}
	role, carrier, err := parseArguments(os.Args[1:])
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), peerTimeout)
	defer cancel()
	if role == "server" {
		return runServer(ctx, carrier)
	}
	switch role {
	case "client":
		return runClient(ctx, carrier)
	case "relay":
		return runTunnelRelay(ctx, carrier)
	case "tunnel-endpoint-a":
		return runTunnelEndpointA(ctx, carrier)
	case "tunnel-endpoint-b":
		return runTunnelEndpointB(ctx, carrier)
	default:
		return errors.New("unknown server parity peer role")
	}
}

func parseArguments(arguments []string) (string, string, error) {
	validRole := len(arguments) == 3 && (arguments[0] == "server" || arguments[0] == "client" ||
		arguments[0] == "relay" || arguments[0] == "tunnel-endpoint-a" || arguments[0] == "tunnel-endpoint-b")
	if len(arguments) != 3 || arguments[1] != "--carrier" ||
		!validRole ||
		(arguments[2] != "websocket" && arguments[2] != "raw-quic" && arguments[2] != "webtransport") {
		return "", "", errors.New("usage: server-parity-peer server|client|relay|tunnel-endpoint-a|tunnel-endpoint-b --carrier websocket|raw-quic|webtransport")
	}
	return arguments[0], arguments[2], nil
}

func runServer(ctx context.Context, carrier string) error {
	origin := parityOrigin()
	tlsConfig, trustPEM, err := serverTLS()
	if err != nil {
		return err
	}
	var listener flowersec.DirectListener
	var endpoint string
	var webSocketServer *flowersec.WebSocketHTTPServer
	var httpListener net.Listener
	switch carrier {
	case "websocket":
		httpListener, err = net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			_, port, splitErr := net.SplitHostPort(httpListener.Addr().String())
			err = splitErr
			endpoint = "wss://localhost:" + port + flowersec.WebSocketDirectPath
		}
	case "raw-quic":
		listener, err = flowersec.NewRawQUICDirectListener(flowersec.RawQUICListenerOptions{Address: "127.0.0.1:0", TLSConfig: tlsConfig, MaxInboundStreams: 16})
		if err == nil {
			endpoint = "quic://" + listener.Address()
		}
	case "webtransport":
		listener, err = flowersec.NewWebTransportDirectListener(flowersec.WebTransportListenerOptions{
			Address: "127.0.0.1:0", TLSConfig: tlsConfig, MaxInboundStreams: 16,
			CheckOrigin: func(request *http.Request) bool { return request.Header.Get("Origin") == origin },
		})
		if err == nil {
			_, port, splitErr := net.SplitHostPort(listener.Address())
			err = splitErr
			endpoint = "https://127.0.0.1:" + port + "/flowersec/webtransport/v3/direct"
		}
	}
	if err != nil {
		return err
	}
	if listener != nil {
		defer listener.Close()
	}

	endpoints, err := controlplane.NewEndpointSet(controlplane.EndpointConfig{
		ID: "websocket", URL: endpoint, TLS: controlplane.CAPolicy(),
	})
	if err != nil {
		return err
	}
	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session:   controlplane.SessionOptions{ChannelID: "go-direct-parity", ExpiresAt: time.Now().Add(time.Minute), MaxInboundStreams: 16},
		Endpoints: endpoints, RendezvousGroupID: "go-direct-parity", ListenerAudience: "server-parity", UpstreamAddress: "127.0.0.1:1",
	})
	if err != nil {
		return err
	}
	record := issued.AuthorizationRecord()
	var activeSessions atomic.Int32
	var activeStreams atomic.Int32
	executed := newExecutionLedger()
	sessionDone := make(chan error, 1)
	handlers, notificationReceived, err := paritySessionHandlers(&activeStreams, "direct", executed)
	if err != nil {
		return err
	}
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		Listeners: originsListener(listener), AllowedOrigins: []string{origin}, MaxInboundStreams: 16,
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizeRuntime(request, record, "lease-go-direct-parity")
		},
		ResolveHandlers: func(context.Context, controlplane.RuntimeAuthorizationRequest) (*flowersec.SessionHandlers, error) {
			return handlers, nil
		},
		OnSession: func(sessionCtx context.Context, session flowersec.Session, _ string) error {
			activeSessions.Add(1)
			executed.record("admission")
			var err error
			if os.Getenv("FLOWERSEC_PARITY_CLIENT_PROFILE") != "" {
				err = exerciseExternalServer(sessionCtx, session, executed)
			} else {
				err = exerciseServer(sessionCtx, session, carrier, notificationReceived, &activeStreams, executed)
			}
			activeSessions.Add(-1)
			sessionDone <- err
			return err
		},
	})
	if err != nil {
		return err
	}

	serveCtx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	serveDone := make(chan error, 1)
	if carrier == "websocket" {
		webSocketServer, err = flowersec.NewWebSocketHTTPServer(flowersec.WebSocketHTTPServerOptions{
			Handler: acceptor.Handler(), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second,
		})
		if err != nil {
			_ = httpListener.Close()
			return err
		}
		go func() { serveDone <- webSocketServer.Serve(httpListener) }()
	} else {
		go func() { serveDone <- acceptor.Serve(serveCtx) }()
	}

	if err := writeJSON(readyMessage{Type: "ready", Runtime: "go", Carrier: carrier, Path: "direct", ArtifactJSON: string(issued.ArtifactJSON()), TrustPEM: trustPEM, Origin: origin}); err != nil {
		return err
	}
	select {
	case err = <-sessionDone:
	case <-ctx.Done():
		err = ctx.Err()
	}
	stopServe()
	if webSocketServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = webSocketServer.Shutdown(shutdownCtx)
		shutdownCancel()
	}
	select {
	case serveErr := <-serveDone:
		if serveErr != nil && !errors.Is(serveErr, context.Canceled) && !errors.Is(serveErr, http.ErrServerClosed) {
			err = errors.Join(err, serveErr)
		}
	case <-time.After(3 * time.Second):
		err = errors.Join(err, errors.New("server listener cleanup timed out"))
	}
	if err != nil {
		return err
	}
	if activeSessions.Load() != 0 || activeStreams.Load() != 0 {
		return fmt.Errorf("server cleanup incomplete: sessions=%d streams=%d", activeSessions.Load(), activeStreams.Load())
	}
	executed.record("cleanup")
	return writeJSON(resultMessage{Type: "server-result", Runtime: "go", Carrier: carrier, Path: "direct", Cases: executed.snapshot()})
}

func exerciseExternalServer(ctx context.Context, session flowersec.Session, executed *executionLedger) error {
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := session.WaitTermination(canceled); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("external client termination wait did not honor cancellation: %w", err)
	}
	executed.record("cancel")
	if _, err := session.ProbeLiveness(ctx); err != nil {
		return fmt.Errorf("external client session did not survive cancellation: %w", err)
	}
	executed.record("liveness")
	if _, err := session.WaitTermination(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	executed.record("close")
	return nil
}

func originsListener(listener flowersec.DirectListener) []flowersec.DirectListener {
	if listener == nil {
		return nil
	}
	return []flowersec.DirectListener{listener}
}

func runClient(ctx context.Context, carrier string) error {
	var ready readyMessage
	if err := json.NewDecoder(bufio.NewReader(os.Stdin)).Decode(&ready); err != nil {
		return fmt.Errorf("decode ready message: %w", err)
	}
	if ready.Type != "ready" || ready.Carrier != carrier || ready.Path != "direct" || ready.ArtifactJSON == "" {
		return errors.New("invalid ready message")
	}
	artifact, err := flowersec.ParseArtifact([]byte(ready.ArtifactJSON))
	if err != nil {
		return err
	}
	lease, err := flowersec.NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(ready.TrustPEM)) {
		return errors.New("invalid server trust PEM")
	}
	var activeStreams atomic.Int32
	executed := newExecutionLedger()
	handlers, notificationReceived, err := parityRPCHandlers(executed)
	if err != nil {
		return err
	}
	session, err := flowersec.Connect(ctx, lease, flowersec.ConnectorOptions{TrustRoots: roots, Origin: ready.Origin, RPCHandlers: handlers})
	if err != nil {
		return err
	}
	executed.record("admission")
	handlersDone := serveParityStreams(ctx, session, &activeStreams, "direct", executed)
	if err := exerciseClient(ctx, session, carrier, notificationReceived, "direct", executed); err != nil {
		_ = session.Close()
		return fmt.Errorf("exercise client: %w", err)
	}
	if err := session.Close(); err != nil {
		return err
	}
	executed.record("close")
	if err := awaitSessionHandlers(handlersDone); err != nil {
		return fmt.Errorf("client handlers: %w", err)
	}
	if activeStreams.Load() != 0 {
		return fmt.Errorf("client cleanup incomplete: streams=%d", activeStreams.Load())
	}
	executed.record("cleanup")
	return writeJSON(resultMessage{Type: "client-result", Runtime: "go", Carrier: carrier, Path: "direct", Cases: executed.snapshot()})
}

func runTunnelEndpointA(ctx context.Context, carrier string) error {
	var input tunnelInput
	if err := json.NewDecoder(bufio.NewReader(os.Stdin)).Decode(&input); err != nil {
		return fmt.Errorf("decode tunnel endpoint A input: %w", err)
	}
	ready := input.EndpointB
	if input.Topology.EndpointA != "go" || input.Topology.IngressCarrierA != carrier ||
		ready.Type != "endpoint-b-ready" || ready.Carrier != carrier || ready.Path != "tunnel" ||
		ready.EndpointAArtifactJSON == "" || ready.Relay.TrustPEM == "" {
		return errors.New("invalid tunnel endpoint A input")
	}

	var activeStreams atomic.Int32
	executed := newExecutionLedger()
	handlers, notificationReceived, err := parityRPCHandlers(executed)
	if err != nil {
		return err
	}
	session, err := connectTunnelArtifact(ctx, ready.EndpointAArtifactJSON, ready.Relay.TrustPEM, ready.Relay.Origin, handlers)
	if err != nil {
		return fmt.Errorf("connect tunnel endpoint A: %w", err)
	}
	executed.record("admission")
	handlersDone := serveParityStreams(ctx, session, &activeStreams, "tunnel", executed)
	if err := exerciseClient(ctx, session, carrier, notificationReceived, "tunnel", executed); err != nil {
		_ = session.Close()
		return fmt.Errorf("exercise tunnel endpoint A: %w", err)
	}
	if err := session.Close(); err != nil {
		return fmt.Errorf("tunnel endpoint A close: %w", err)
	}
	executed.record("close")
	if err := awaitSessionHandlers(handlersDone); err != nil {
		return fmt.Errorf("endpoint A handlers: %w", err)
	}
	if activeStreams.Load() != 0 {
		return fmt.Errorf("endpoint A cleanup incomplete: streams=%d", activeStreams.Load())
	}
	executed.record("cleanup")
	return writeJSON(resultMessage{
		Type: "endpoint-a-result", Runtime: "go", Carrier: carrier, Path: "tunnel",
		Cases: executed.snapshot(),
	})
}

func runTunnelRelay(ctx context.Context, carrier string) error {
	origin := parityOrigin()
	executed := newExecutionLedger()
	tlsConfig, trustPEM, err := serverTLS()
	if err != nil {
		return err
	}
	var listener flowersec.TunnelListener
	var endpoint string
	var httpListener net.Listener
	switch carrier {
	case "websocket":
		httpListener, err = net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			_, port, splitErr := net.SplitHostPort(httpListener.Addr().String())
			err = splitErr
			endpoint = "wss://localhost:" + port + flowersec.WebSocketTunnelPath
			listener = flowersec.NewWebSocketTunnelListener()
		}
	case "raw-quic":
		listener, err = flowersec.NewRawQUICTunnelListener(flowersec.RawQUICListenerOptions{Address: "127.0.0.1:0", TLSConfig: tlsConfig, MaxInboundStreams: 16})
		if err == nil {
			endpoint = "quic://" + listener.Address()
		}
	case "webtransport":
		listener, err = flowersec.NewWebTransportTunnelListener(flowersec.WebTransportListenerOptions{
			Address: "127.0.0.1:0", TLSConfig: tlsConfig, MaxInboundStreams: 16,
			CheckOrigin: func(request *http.Request) bool { return request.Header.Get("Origin") == origin },
		})
		if err == nil {
			_, port, splitErr := net.SplitHostPort(listener.Address())
			err = splitErr
			endpoint = "https://127.0.0.1:" + port + "/flowersec/webtransport/v3/tunnel"
		}
	}
	if err != nil || listener == nil || endpoint == "" {
		return errors.New("bind tunnel relay listener failed")
	}
	defer listener.Close()

	type decision struct {
		leaseID string
		expires time.Time
		peer    string
		replace bool
	}
	decisions := make(map[string]decision)
	released := make(map[string]struct{})
	var mu sync.Mutex
	runtime, err := flowersec.NewTunnelRuntime(flowersec.TunnelRuntimeOptions{
		AllowedOrigins: []string{origin}, Listeners: []flowersec.TunnelListener{listener},
		MaxInboundStreams: 16, MaxPendingLegs: 16, MaxActivePairs: 8,
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.TunnelAuthorizationResponse, error) {
			mu.Lock()
			item, ok := decisions[request.LookupKey()]
			mu.Unlock()
			if !ok {
				return controlplane.RejectTunnelRuntime("invalid_credential", false)
			}
			return controlplane.AllowTunnelRuntime(request, item.leaseID, item.expires, item.peer, item.replace)
		},
		Release: func(_ context.Context, leaseID string) {
			mu.Lock()
			released[leaseID] = struct{}{}
			mu.Unlock()
		},
	})
	if err != nil {
		return err
	}
	serverDER := ""
	if len(tlsConfig.Certificates) > 0 && len(tlsConfig.Certificates[0].Certificate) > 0 {
		serverDER = base64.StdEncoding.EncodeToString(tlsConfig.Certificates[0].Certificate[0])
	}
	if err := writeJSON(tunnelRelayReadyMessage{Type: "relay-ready", Runtime: "go", Carrier: carrier, Path: "tunnel", EndpointURL: endpoint, TrustPEM: trustPEM, TrustRootsDER: []string{base64.StdEncoding.EncodeToString(tlsConfig.Certificates[0].Certificate[1])}, ServerCertificateDER: serverDER, Origin: origin}); err != nil {
		return err
	}
	decoder := json.NewDecoder(bufio.NewReader(os.Stdin))
	var configure struct {
		Type           string                    `json:"type"`
		Authorizations []tunnelAuthorizationWire `json:"authorizations"`
	}
	if err := decoder.Decode(&configure); err != nil || configure.Type != "configure" || len(configure.Authorizations) == 0 {
		return errors.New("invalid tunnel relay configuration")
	}
	mu.Lock()
	for _, item := range configure.Authorizations {
		if item.Decision != "allow" || item.CredentialID == "" || item.LeaseID == "" || item.ExpectedPeerEndpointInstanceID == "" || item.ExpiresAtUnixSeconds <= time.Now().Unix() {
			mu.Unlock()
			return errors.New("invalid secret-free tunnel authorization")
		}
		decisions[item.CredentialID] = decision{leaseID: item.LeaseID, expires: time.Unix(item.ExpiresAtUnixSeconds, 0), peer: item.ExpectedPeerEndpointInstanceID, replace: item.AllowReplacement}
	}
	mu.Unlock()
	serveCtx, stop := context.WithCancel(ctx)
	defer stop()
	serveDone := make(chan error, 1)
	go func() { serveDone <- runtime.Serve(serveCtx) }()
	var webSocketServer *flowersec.WebSocketHTTPServer
	var webSocketServeDone chan error
	if carrier == "websocket" {
		webSocketServer, err = flowersec.NewWebSocketHTTPServer(flowersec.WebSocketHTTPServerOptions{
			Handler: runtime.Handler(), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second,
		})
		if err != nil {
			_ = httpListener.Close()
			return err
		}
		webSocketServeDone = make(chan error, 1)
		go func() { webSocketServeDone <- webSocketServer.Serve(httpListener) }()
	}
	var closeCommand struct {
		Type string `json:"type"`
	}
	if err := decoder.Decode(&closeCommand); err != nil || closeCommand.Type != "close" {
		return errors.New("invalid tunnel relay close command")
	}
	executed.record("close")
	stop()
	executed.record("cancel")
	if webSocketServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = webSocketServer.Shutdown(shutdownCtx)
		shutdownCancel()
	}
	select {
	case <-serveDone:
	case <-time.After(3 * time.Second):
		return errors.New("tunnel relay cleanup timed out")
	}
	if webSocketServeDone != nil {
		select {
		case serveErr := <-webSocketServeDone:
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				return serveErr
			}
		case <-time.After(3 * time.Second):
			return errors.New("tunnel relay WebSocket listener cleanup timed out")
		}
	}
	mu.Lock()
	releasedCount := len(released)
	decisionCount := len(decisions)
	mu.Unlock()
	if releasedCount != decisionCount {
		return fmt.Errorf("relay cleanup incomplete: released=%d authorized=%d", releasedCount, decisionCount)
	}
	executed.record("admission", "pairing", "opaque-forwarding")
	if carrier != "websocket" {
		executed.record("datagram-forwarding")
	}
	executed.record("cleanup")
	return writeJSON(tunnelRelayResultMessage{Type: "relay-result", Runtime: "go", Carrier: carrier, Path: "tunnel", Cases: executed.snapshot(), ObservedPlaintext: false, ReleasedLeases: int32(releasedCount)})
}

func runTunnelEndpointB(ctx context.Context, carrier string) error {
	var input tunnelInput
	if err := json.NewDecoder(bufio.NewReader(os.Stdin)).Decode(&input); err != nil {
		return fmt.Errorf("decode tunnel endpoint B input: %w", err)
	}
	relay := input.Relay
	if input.Topology.EndpointB != "go" || input.Topology.IngressCarrierB != carrier ||
		relay.Type != "relay-ready" || relay.Carrier != carrier || relay.Path != "tunnel" ||
		relay.EndpointURL == "" || relay.TrustPEM == "" {
		return errors.New("invalid tunnel endpoint B input")
	}

	endpoints, err := controlplane.NewEndpointSet(controlplane.EndpointConfig{
		ID: "websocket", URL: relay.EndpointURL, TLS: controlplane.CAPolicy(),
	})
	if err != nil {
		return err
	}
	topologyID := input.Topology.ID
	if topologyID == "" {
		return errors.New("tunnel topology ID is empty")
	}
	pair, err := controlplane.NewIssuer().IssueTunnelPair(controlplane.TunnelIssueOptions{
		Session: controlplane.SessionOptions{
			ChannelID: "parity-" + topologyID, ExpiresAt: time.Now().Add(time.Minute), MaxInboundStreams: 16,
		},
		Endpoints: endpoints, RendezvousGroupID: topologyID, ListenerAudience: "server-parity",
		FirstEndpointID: topologyID + "-a", SecondEndpointID: topologyID + "-b",
	})
	if err != nil {
		return err
	}
	firstArtifact := string(pair.First.ArtifactJSON())
	secondArtifact := string(pair.Second.ArtifactJSON())
	authorizations, err := tunnelAuthorizations(pair.First, pair.Second)
	if err != nil {
		return err
	}
	if err := writeJSON(tunnelEndpointBReadyMessage{
		Type: "endpoint-b-ready", Runtime: "go", Carrier: carrier, Path: "tunnel",
		EndpointAArtifactJSON: firstArtifact, EndpointBArtifactJSON: secondArtifact,
		Relay: relay, Authorizations: authorizations,
		VerificationRecords: map[string]string{
			pair.First.LookupKey(): firstArtifact, pair.Second.LookupKey(): secondArtifact,
		},
	}); err != nil {
		return err
	}
	var connectCommand struct {
		Type string `json:"type"`
	}
	if err := json.NewDecoder(bufio.NewReader(os.Stdin)).Decode(&connectCommand); err != nil || connectCommand.Type != "connect" {
		return errors.New("endpoint B did not receive connect command")
	}

	var activeStreams atomic.Int32
	executed := newExecutionLedger()
	handlers, notificationReceived, err := parityRPCHandlers(executed)
	if err != nil {
		return err
	}
	session, err := connectTunnelArtifact(ctx, secondArtifact, relay.TrustPEM, relay.Origin, handlers)
	if err != nil {
		return fmt.Errorf("connect tunnel endpoint B: %w", err)
	}
	executed.record("admission")
	handlersDone := serveParityStreams(ctx, session, &activeStreams, "tunnel", executed)
	var exerciseErr error
	if os.Getenv("FLOWERSEC_PARITY_CLIENT_PROFILE") != "" {
		exerciseErr = exerciseExternalServer(ctx, session, executed)
	} else {
		exerciseErr = exerciseServer(ctx, session, carrier, notificationReceived, &activeStreams, executed)
	}
	if exerciseErr != nil {
		_ = session.Close()
		return fmt.Errorf("exercise tunnel endpoint B: %w", exerciseErr)
	}
	if err := session.Close(); err != nil {
		return fmt.Errorf("tunnel endpoint B close: %w", err)
	}
	executed.record("close")
	if err := awaitSessionHandlers(handlersDone); err != nil {
		return fmt.Errorf("endpoint B handlers: %w", err)
	}
	if activeStreams.Load() != 0 {
		return fmt.Errorf("endpoint B cleanup incomplete: streams=%d", activeStreams.Load())
	}
	executed.record("cleanup")
	return writeJSON(resultMessage{
		Type: "endpoint-b-result", Runtime: "go", Carrier: carrier, Path: "tunnel",
		Cases: executed.snapshot(),
	})
}

func parityOrigin() string {
	if value := os.Getenv("FLOWERSEC_PARITY_ORIGIN"); value != "" {
		return value
	}
	return defaultOrigin
}

func tunnelAuthorizations(first, second controlplane.IssuedArtifact) ([]tunnelAuthorizationWire, error) {
	items := make([]tunnelAuthorizationWire, 0, 2)
	for index, issued := range []controlplane.IssuedArtifact{first, second} {
		var artifact struct {
			Session struct {
				ExpiresAt int64 `json:"init_expire_at_unix_s"`
			} `json:"session"`
			Path struct {
				ExpectedPeer string `json:"expected_peer_endpoint_instance_id"`
			} `json:"path"`
		}
		if err := json.Unmarshal(issued.ArtifactJSON(), &artifact); err != nil || artifact.Session.ExpiresAt <= time.Now().Unix() || artifact.Path.ExpectedPeer == "" {
			return nil, errors.New("issued tunnel artifact omitted relay claims")
		}
		items = append(items, tunnelAuthorizationWire{Decision: "allow", CredentialID: issued.LookupKey(), LeaseID: fmt.Sprintf("lease-endpoint-%c", 'a'+index), ExpiresAtUnixSeconds: artifact.Session.ExpiresAt, ExpectedPeerEndpointInstanceID: artifact.Path.ExpectedPeer})
	}
	return items, nil
}

func connectTunnelArtifact(ctx context.Context, artifactJSON, trustPEM, artifactOrigin string, handlers *flowersec.RPCHandlers) (flowersec.Session, error) {
	artifact, err := flowersec.ParseArtifact([]byte(artifactJSON))
	if err != nil {
		return nil, err
	}
	lease, err := flowersec.NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(trustPEM)) {
		return nil, errors.New("invalid tunnel relay trust PEM")
	}
	return flowersec.Connect(ctx, lease, flowersec.ConnectorOptions{TrustRoots: roots, Origin: artifactOrigin, RPCHandlers: handlers})
}

func serveParityStreams(ctx context.Context, session flowersec.Session, activeStreams *atomic.Int32, streamCell string, executed *executionLedger) <-chan error {
	done := make(chan error, 1)
	go func() {
		var active sync.WaitGroup
		defer func() {
			active.Wait()
			close(done)
		}()
		for {
			incoming, err := session.AcceptStream(ctx)
			if err != nil {
				done <- err
				return
			}
			active.Add(1)
			go func() {
				defer active.Done()
				if err := handleParityStream(incoming, activeStreams, streamCell, executed); err != nil {
					_ = incoming.Stream.Reset()
					_ = incoming.Stream.Close()
					return
				}
				_ = incoming.Stream.CloseWrite()
			}()
		}
	}()
	return done
}

func handleParityStream(incoming flowersec.IncomingStream, activeStreams *atomic.Int32, streamCell string, executed *executionLedger) error {
	switch incoming.Kind {
	case echoKind:
		activeStreams.Add(1)
		defer activeStreams.Add(-1)
		if incoming.Metadata.Values()["cell"] != streamCell {
			return errors.New("invalid stream metadata")
		}
		executed.record("stream-metadata")
		payload, err := io.ReadAll(incoming.Stream)
		if err != nil || string(payload) != "hello" {
			return errors.New("invalid stream payload")
		}
		if _, err := incoming.Stream.Write([]byte("world")); err != nil {
			return err
		}
		executed.record("stream-fin")
		return nil
	case resetKind:
		payload, err := io.ReadAll(incoming.Stream)
		if err != nil || string(payload) != "reset" {
			return errors.New("invalid reset stream payload")
		}
		executed.record("stream-reset")
		return errors.New("intentional parity reset")
	default:
		return errors.New("unregistered parity stream")
	}
}

func awaitSessionHandlers(done <-chan error) error {
	select {
	case err := <-done:
		var sessionErr *flowersec.SessionError
		if err == nil || errors.As(err, &sessionErr) && sessionErr.Code() == flowersec.SessionClosed {
			return nil
		}
		return err
	case <-time.After(3 * time.Second):
		return errors.New("session handler cleanup timed out")
	}
}

type tunnelPeerAuthorizer struct {
	records map[string]controlplane.AuthorizationRecord
	leases  atomic.Int32
}

func newTunnelPeerAuthorizer(records ...controlplane.AuthorizationRecord) *tunnelPeerAuthorizer {
	indexed := make(map[string]controlplane.AuthorizationRecord, len(records))
	for _, record := range records {
		indexed[record.LookupKey()] = record
	}
	return &tunnelPeerAuthorizer{records: indexed}
}

func (authorizer *tunnelPeerAuthorizer) start() (string, func(), error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	server := &http.Server{Handler: authorizer, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	stop := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = server.Shutdown(shutdownCtx)
		cancel()
	}
	return "http://" + listener.Addr().String(), stop, nil
}

func (authorizer *tunnelPeerAuthorizer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch request.URL.Path {
	case "/authorize":
		payload, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, 64*1024))
		if err != nil {
			http.Error(writer, "invalid authorization request", http.StatusBadRequest)
			return
		}
		runtimeRequest, err := controlplane.ParseRuntimeAuthorizationRequest(payload)
		if err != nil {
			http.Error(writer, "invalid authorization request", http.StatusBadRequest)
			return
		}
		record, ok := authorizer.records[runtimeRequest.LookupKey()]
		if !ok {
			http.Error(writer, "authorization denied", http.StatusForbidden)
			return
		}
		leaseID := fmt.Sprintf("parity-%d", authorizer.leases.Add(1))
		response, err := controlplane.AuthorizeTunnelRuntime(runtimeRequest, record, leaseID)
		if err != nil {
			authorizer.leases.Add(-1)
			http.Error(writer, "authorization denied", http.StatusForbidden)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(response.JSON())
	case "/release":
		var release struct {
			LeaseID string `json:"lease_id"`
		}
		if json.NewDecoder(http.MaxBytesReader(writer, request.Body, 1024)).Decode(&release) != nil || release.LeaseID == "" {
			http.Error(writer, "invalid release", http.StatusBadRequest)
			return
		}
		authorizer.leases.Add(-1)
		writer.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(writer, request)
	}
}

func registerTunnelAuthorizer(ctx context.Context, registrationURL, authorizerURL string) error {
	payload, err := json.Marshal(struct {
		URL string `json:"url"`
	}{URL: authorizerURL})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("register tunnel authorizer: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("register tunnel authorizer: status %d", response.StatusCode)
	}
	return nil
}

type parityRPCRegistrar interface {
	HandleRPC(uint32, flowersec.RPCHandler) error
	HandleNotification(uint32, flowersec.RPCNotificationHandler) error
}

func parityRPCHandlers(executed *executionLedger) (*flowersec.RPCHandlers, <-chan struct{}, error) {
	notificationReceived := make(chan struct{}, 4)
	handlers := flowersec.NewRPCHandlers()
	if err := registerParityRPCHandlers(handlers, notificationReceived, executed); err != nil {
		return nil, nil, err
	}
	return handlers, notificationReceived, nil
}

func paritySessionHandlers(activeStreams *atomic.Int32, streamCell string, executed *executionLedger) (*flowersec.SessionHandlers, <-chan struct{}, error) {
	notificationReceived := make(chan struct{}, 4)
	handlers, err := flowersec.NewSessionHandlers(flowersec.SessionHandlerOptions{OnError: func(err error) {
		fmt.Fprintf(os.Stderr, "session handler error: %v\n", err)
	}})
	if err != nil {
		return nil, nil, err
	}
	if err := registerParityRPCHandlers(handlers, notificationReceived, executed); err != nil {
		return nil, nil, err
	}
	if err := handlers.HandleStream(echoKind, func(_ context.Context, incoming flowersec.IncomingStream) error {
		return handleParityStream(incoming, activeStreams, streamCell, executed)
	}); err != nil {
		return nil, nil, err
	}
	if err := handlers.HandleStream(resetKind, func(_ context.Context, incoming flowersec.IncomingStream) error {
		return handleParityStream(incoming, activeStreams, streamCell, executed)
	}); err != nil {
		return nil, nil, err
	}
	return handlers, notificationReceived, nil
}

func registerParityRPCHandlers(handlers parityRPCRegistrar, notificationReceived chan<- struct{}, executed *executionLedger) error {
	if err := handlers.HandleRPC(echoRPC, func(_ context.Context, request json.RawMessage) (any, *flowersec.RPCError) {
		var payload map[string]string
		if json.Unmarshal(request, &payload) != nil || payload["value"] != "ping" {
			return nil, &flowersec.RPCError{Code: 400, Message: "invalid echo payload"}
		}
		executed.record("rpc")
		return payload, nil
	}); err != nil {
		return err
	}
	if err := handlers.HandleRPC(completeRPC, func(_ context.Context, request json.RawMessage) (any, *flowersec.RPCError) {
		var payload map[string]string
		if json.Unmarshal(request, &payload) != nil || payload["value"] != "complete" {
			return nil, &flowersec.RPCError{Code: 400, Message: "invalid completion payload"}
		}
		executed.record("rekey", "liveness")
		select {
		case notificationReceived <- struct{}{}:
		default:
		}
		return payload, nil
	}); err != nil {
		return err
	}
	if err := handlers.HandleRPC(datagramRPC, func(_ context.Context, request json.RawMessage) (any, *flowersec.RPCError) {
		var payload map[string]string
		if json.Unmarshal(request, &payload) != nil || payload["value"] != "datagram-ready" {
			return nil, &flowersec.RPCError{Code: 400, Message: "invalid datagram barrier payload"}
		}
		select {
		case notificationReceived <- struct{}{}:
		default:
		}
		return payload, nil
	}); err != nil {
		return err
	}
	if err := handlers.HandleNotification(notifyRPC, func(_ context.Context, request json.RawMessage) error {
		var payload map[string]string
		if json.Unmarshal(request, &payload) != nil || payload["value"] != "notify" {
			return errors.New("invalid notification payload")
		}
		executed.record("notification")
		select {
		case notificationReceived <- struct{}{}:
		default:
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func exerciseClient(ctx context.Context, session flowersec.Session, carrier string, notificationReceived <-chan struct{}, streamCell string, executed *executionLedger) error {
	if err := callEcho(ctx, session); err != nil {
		return fmt.Errorf("initial echo: %w", err)
	}
	executed.record("rpc")
	if err := session.RPC().Notify(ctx, notifyRPC, map[string]string{"value": "notify"}); err != nil {
		return fmt.Errorf("client notification: %w", err)
	}
	if err := waitSignal(ctx, notificationReceived, "server notification"); err != nil {
		return fmt.Errorf("server notification: %w", err)
	}
	executed.record("notification")
	metadata, err := flowersec.NewStreamMetadata(map[string]any{"cell": streamCell})
	if err != nil {
		return fmt.Errorf("open echo stream: %w", err)
	}
	stream, err := session.OpenStream(ctx, echoKind, metadata)
	if err != nil {
		return fmt.Errorf("write echo stream: %w", err)
	}
	if _, err = stream.Write([]byte("hello")); err == nil {
		err = stream.CloseWrite()
	}
	if err != nil {
		_ = stream.Close()
		return fmt.Errorf("open reset stream: %w", err)
	}
	payload, readErr := io.ReadAll(stream)
	if readErr != nil || string(payload) != "world" {
		return fmt.Errorf("echo stream did not preserve metadata and FIN: payload=%q err=%w", payload, readErr)
	}
	executed.record("stream-metadata", "stream-fin")
	if err := callEcho(ctx, session); err != nil {
		return fmt.Errorf("echo stream cleanup barrier: %w", err)
	}
	reset, err := session.OpenStream(ctx, resetKind, flowersec.EmptyStreamMetadata())
	if err != nil {
		return fmt.Errorf("open reset stream: %w", err)
	}
	_, _ = reset.Write([]byte("reset"))
	_ = reset.CloseWrite()
	_, resetErr := io.ReadAll(reset)
	_ = reset.Close()
	if resetErr == nil && reset.TerminalError() == nil {
		return errors.New("reset stream did not fail")
	}
	executed.record("stream-reset")
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := session.WaitTermination(cancelCtx); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("termination wait did not honor cancellation: %w", err)
	}
	executed.record("cancel")
	if err := callEcho(ctx, session); err != nil {
		return errors.New("session did not survive canceled RPC: " + err.Error())
	}
	var datagramReady map[string]string
	if err := session.RPC().Call(ctx, datagramRPC, map[string]string{"value": "datagram-ready"}, &datagramReady); err != nil {
		return fmt.Errorf("datagram barrier: %w", err)
	}
	if err := exchangeDatagram(ctx, session, carrier, true); err != nil {
		return fmt.Errorf("datagram: %w", err)
	}
	if carrier != "websocket" {
		executed.record("datagram")
	}
	if err := session.Rekey(ctx); err != nil {
		return fmt.Errorf("rekey: %w", err)
	}
	executed.record("rekey")
	if _, err := session.ProbeLiveness(ctx); err != nil {
		return fmt.Errorf("liveness: %w", err)
	}
	executed.record("liveness")
	var completion map[string]string
	if err := session.RPC().Call(ctx, completeRPC, map[string]string{"value": "complete"}, &completion); err != nil {
		return fmt.Errorf("completion barrier: %w", err)
	}
	return session.RPC().Notify(ctx, notifyRPC, map[string]string{"value": "notify"})
}

func exerciseServer(ctx context.Context, session flowersec.Session, carrier string, notificationReceived <-chan struct{}, activeStreams *atomic.Int32, executed *executionLedger) error {
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := session.WaitTermination(cancelCtx); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("termination wait did not honor cancellation: %w", err)
	}
	executed.record("cancel")
	if err := callEcho(ctx, session); err != nil {
		return err
	}
	executed.record("rpc")
	if err := session.RPC().Notify(ctx, notifyRPC, map[string]string{"value": "notify"}); err != nil {
		return err
	}
	if err := waitSignal(ctx, notificationReceived, "client notification"); err != nil {
		return err
	}
	executed.record("notification")
	if err := waitSignal(ctx, notificationReceived, "client datagram barrier"); err != nil {
		return err
	}
	if err := exchangeDatagram(ctx, session, carrier, false); err != nil {
		return err
	}
	if carrier != "websocket" {
		executed.record("datagram")
	}
	_, err := session.WaitTermination(ctx)
	if err == nil {
		executed.record("close")
	}
	return err
}

func callEcho(ctx context.Context, session flowersec.Session) error {
	var response map[string]string
	if err := session.RPC().Call(ctx, echoRPC, map[string]string{"value": "ping"}, &response); err != nil {
		return err
	}
	if response["value"] != "ping" {
		return errors.New("RPC echo payload mismatch")
	}
	return nil
}

func exchangeDatagram(ctx context.Context, session flowersec.Session, carrier string, initiator bool) error {
	if carrier == "websocket" {
		return nil
	}
	channel, err := session.UnreliableMessages()
	if err != nil {
		return fmt.Errorf("get unreliable channel: %w", err)
	}
	request := []byte{1, 2, 3}
	response := []byte{3, 2, 1}
	if initiator {
		status, sendErr := channel.Send(ctx, request, flowersec.UnreliableSendOptions{ExpiresAt: time.Now().Add(time.Second)})
		if sendErr != nil {
			return fmt.Errorf("send datagram request: %w", sendErr)
		}
		if status != flowersec.UnreliableAccepted {
			return fmt.Errorf("send datagram request: status=%q", status)
		}
	}
	payload, err := channel.Receive(ctx)
	want := request
	if initiator {
		want = response
	}
	if err != nil {
		return fmt.Errorf("receive datagram: %w", err)
	}
	if !bytes.Equal(payload, want) {
		return fmt.Errorf("receive datagram: payload=%x want=%x", payload, want)
	}
	if !initiator {
		status, sendErr := channel.Send(ctx, response, flowersec.UnreliableSendOptions{ExpiresAt: time.Now().Add(time.Second)})
		if sendErr != nil {
			return fmt.Errorf("send datagram response: %w", sendErr)
		}
		if status != flowersec.UnreliableAccepted {
			return fmt.Errorf("send datagram response: status=%q", status)
		}
	}
	return nil
}

func waitSignal(ctx context.Context, signal <-chan struct{}, name string) error {
	select {
	case <-signal:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait for %s: %w", name, ctx.Err())
	}
}

func serverTLS() (*tls.Config, string, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "Flowersec parity root"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, "", err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano() + 1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: false, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	if err != nil {
		return nil, "", err
	}
	certificate := tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}
	trustPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, string(trustPEM), nil
}

var stdoutMu sync.Mutex

func writeJSON(value any) error {
	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	return json.NewEncoder(os.Stdout).Encode(value)
}
