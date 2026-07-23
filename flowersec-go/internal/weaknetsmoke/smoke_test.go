package weaknetsmoke

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/weaknet"
	gorillaws "github.com/gorilla/websocket"
)

type smokeReport struct {
	SchemaVersion  int         `json:"schema_version"`
	Classification string      `json:"classification"`
	EvidenceScope  string      `json:"evidence_scope"`
	Cases          []smokeCase `json:"cases"`
}

type smokeCase struct {
	Profile        string            `json:"profile"`
	Carrier        string            `json:"carrier"`
	Classification string            `json:"classification"`
	Status         string            `json:"status"`
	Assertions     []string          `json:"assertions"`
	Counters       []counterEvidence `json:"counters"`
	EvidenceSHA256 string            `json:"evidence_sha256"`
}

type counterEvidence struct {
	Phase             string                    `json:"phase"`
	Direction         weaknet.Direction         `json:"direction"`
	Seed              int64                     `json:"seed"`
	ExpectedExact     []exactCounterExpectation `json:"expected_exact,omitempty"`
	ExpectedRelations []relationExpectation     `json:"expected_relations"`
	Actual            weaknet.Counters          `json:"actual"`
}

type exactCounterExpectation struct {
	Counter string `json:"counter"`
	Value   uint64 `json:"value"`
}

type relationExpectation struct {
	Left     string `json:"left"`
	Operator string `json:"operator"`
	Right    string `json:"right"`
}

func TestWeaknetSmoke(t *testing.T) {
	if os.Getenv("FLOWERSEC_RUN_WEAKNET_SMOKE") != "1" {
		t.Skip("run through make weaknet-smoke")
	}
	report := smokeReport{
		SchemaVersion:  1,
		Classification: "local_smoke",
		EvidenceScope:  "userspace socket relays only; not system, netem, qlog, PMTUD, migration, or performance SLO evidence",
		Cases: []smokeCase{
			runRawQUICSmoke(t),
			runWebSocketSmoke(t),
		},
	}
	if err := validateSmokeReport(report); err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("WEAKNET_SMOKE_REPORT")
	if path == "" {
		path = filepath.Join(os.TempDir(), "flowersec-weaknet-smoke.json")
	}
	if err := writeReport(path, report); err != nil {
		t.Fatal(err)
	}
	t.Logf("local_smoke report: %s", path)
}

func runRawQUICSmoke(t *testing.T) smokeCase {
	t.Helper()
	serverTLS, clientTLS := testTLS(t)
	serverTLS.NextProtos = []string{rawquic.ALPNDirect}
	clientTLS.NextProtos = []string{rawquic.ALPNDirect}
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS, rawquic.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	front := listenUDP(t)
	backend := listenUDP(t)
	var clientAddress addressHolder
	forwardExpected := weaknet.Counters{}
	reverseExpected := weaknet.Counters{}
	forwardRelay, err := weaknet.NewUDPRelay(weaknet.UDPProfile{
		Phase: "local-smoke", Direction: weaknet.ClientToServer, Seed: 20260720,
		Delay: time.Millisecond, DuplicateOrdinals: []uint64{1}, Expected: &forwardExpected,
	}, weaknet.UDPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	reverseRelay, err := weaknet.NewUDPRelay(weaknet.UDPProfile{
		Phase: "local-smoke", Direction: weaknet.ServerToClient, Seed: 20260720,
		Delay: time.Millisecond, Expected: &reverseExpected,
	}, weaknet.UDPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	forward, err := weaknet.NewPacketPump(front, backend, nil, forwardRelay, weaknet.PumpOptions{
		PacketTargetResolver: func(source net.Addr) (net.Addr, error) {
			clientAddress.Store(source)
			return listener.Addr(), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := weaknet.NewPacketPump(backend, front, nil, reverseRelay, weaknet.PumpOptions{
		PacketTargetResolver: func(net.Addr) (net.Addr, error) {
			address := clientAddress.Load()
			if address == nil {
				return nil, errors.New("client UDP address is not known")
			}
			return address, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	pumpContext, cancelPumps := context.WithCancel(context.Background())
	pumpDone := []chan error{make(chan error, 1), make(chan error, 1)}
	go func() { pumpDone[0] <- forward.Run(pumpContext) }()
	go func() { pumpDone[1] <- reverse.Run(pumpContext) }()

	serverSessionCh := make(chan carrier.Session, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		session, acceptErr := listener.Accept(context.Background())
		if acceptErr != nil {
			serverErrCh <- acceptErr
			return
		}
		serverSessionCh <- session
	}()
	clientSession, err := rawquic.Dial(context.Background(), front.LocalAddr().String(), clientTLS, rawquic.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	serverSession := awaitSession(t, serverSessionCh, serverErrCh)
	assertResetIsolation(t, clientSession, serverSession)
	_ = clientSession.Close()
	_ = serverSession.Close()
	cancelPumps()
	for _, done := range pumpDone {
		<-done
	}

	forwardReport := forwardRelay.Report()
	reverseReport := reverseRelay.Report()
	assertUDPSmokeCounters(t, forwardReport, true)
	assertUDPSmokeCounters(t, reverseReport, false)
	return finalizeCase(smokeCase{
		Profile: rawquic.ALPNDirect, Carrier: "raw_quic", Classification: "local_smoke", Status: "pass",
		Assertions: []string{"real UDP PacketPump path", "scripted first-packet duplication", "counter conservation", "native reset isolation"},
		Counters: []counterEvidence{
			counterFromReport(forwardReport,
				[]exactCounterExpectation{{Counter: "duplicate_units", Value: 1}},
				[]relationExpectation{
					{Left: "delay_units", Operator: "eq", Right: "output_units_plus_canceled_units"},
					{Left: "input_units_plus_duplicate_units", Operator: "eq", Right: "output_units_plus_dropped_units_plus_canceled_units"},
					{Left: "input_bytes_plus_duplicate_bytes", Operator: "eq", Right: "output_bytes_plus_dropped_bytes_plus_canceled_bytes"},
				}),
			counterFromReport(reverseReport,
				[]exactCounterExpectation{{Counter: "duplicate_units", Value: 0}},
				[]relationExpectation{
					{Left: "delay_units", Operator: "eq", Right: "output_units_plus_canceled_units"},
					{Left: "input_units_plus_duplicate_units", Operator: "eq", Right: "output_units_plus_dropped_units_plus_canceled_units"},
					{Left: "input_bytes_plus_duplicate_bytes", Operator: "eq", Right: "output_bytes_plus_dropped_bytes_plus_canceled_bytes"},
				}),
		},
	})
}

func runWebSocketSmoke(t *testing.T) smokeCase {
	t.Helper()
	serverSessionCh := make(chan carrier.Session, 1)
	serverErrCh := make(chan error, 1)
	upgrader := gorillaws.Upgrader{Subprotocols: []string{carrierws.SubprotocolDirect}}
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			serverErrCh <- err
			return
		}
		_, err = carrierws.ServeAdmission(context.Background(), conn, nil, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
			return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
		})
		if err != nil {
			serverErrCh <- err
			return
		}
		session, err := carrierws.NewAfterAdmission(conn, carrierws.ServerRole, carrierws.SubprotocolDirect, carrierws.DefaultResourcePolicy(), carrierws.LivenessPolicy{})
		if err != nil {
			serverErrCh <- err
			return
		}
		serverSessionCh <- session
	}))
	backend.EnableHTTP2 = false
	backend.StartTLS()
	defer backend.Close()

	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	clientToServerExpected := weaknet.Counters{}
	serverToClientExpected := weaknet.Counters{}
	clientToServerRelay := newByteRelay(t, weaknet.ClientToServer, &clientToServerExpected)
	serverToClientRelay := newByteRelay(t, weaknet.ServerToClient, &serverToClientExpected)
	pumpContext, cancelPumps := context.WithCancel(context.Background())
	pumpDone := []chan error{make(chan error, 1), make(chan error, 1)}
	go func() {
		clientConn, acceptErr := front.Accept()
		if acceptErr != nil {
			serverErrCh <- acceptErr
			return
		}
		backendConn, dialErr := net.Dial("tcp", backend.Listener.Addr().String())
		if dialErr != nil {
			serverErrCh <- dialErr
			return
		}
		forward, pumpErr := weaknet.NewConnPump(clientConn, backendConn, clientToServerRelay, weaknet.PumpOptions{})
		if pumpErr != nil {
			serverErrCh <- pumpErr
			return
		}
		reverse, pumpErr := weaknet.NewConnPump(backendConn, clientConn, serverToClientRelay, weaknet.PumpOptions{})
		if pumpErr != nil {
			serverErrCh <- pumpErr
			return
		}
		go func() { pumpDone[0] <- forward.Run(pumpContext) }()
		go func() { pumpDone[1] <- reverse.Run(pumpContext) }()
	}()

	dialer := gorillaws.Dialer{
		Subprotocols: []string{carrierws.SubprotocolDirect},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, // Local smoke proxy only.
		},
	}
	clientConn, _, err := dialer.Dial("wss://"+front.Addr().String()+"/flowersec/v2/direct", nil)
	if err != nil {
		t.Fatal(err)
	}
	rawFSB2 := validWebSocketFSB2(t)
	if _, err := carrierws.CommitAdmission(context.Background(), clientConn, rawFSB2, nil); err != nil {
		t.Fatal(err)
	}
	clientSession, err := carrierws.NewAfterAdmission(clientConn, carrierws.ClientRole, carrierws.SubprotocolDirect, carrierws.DefaultResourcePolicy(), carrierws.LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	serverSession := awaitSession(t, serverSessionCh, serverErrCh)
	assertResetIsolation(t, clientSession, serverSession)
	_ = clientSession.Close()
	_ = serverSession.Close()
	cancelPumps()
	for _, done := range pumpDone {
		select {
		case <-done:
		case err := <-serverErrCh:
			t.Fatal(err)
		case <-time.After(5 * time.Second):
			t.Fatal("WebSocket ConnPump did not stop")
		}
	}

	clientToServerReport := clientToServerRelay.Report()
	serverToClientReport := serverToClientRelay.Report()
	assertByteSmokeCounters(t, clientToServerReport)
	assertByteSmokeCounters(t, serverToClientReport)
	return finalizeCase(smokeCase{
		Profile: carrierws.SubprotocolDirect, Carrier: "wss", Classification: "local_smoke", Status: "pass",
		Assertions: []string{"real TCP ConnPump path", "TLS 1.3 and WebSocket negotiation", "FSB2/FSA2 admission", "counter conservation", "Yamux reset isolation"},
		Counters: []counterEvidence{
			counterFromReport(clientToServerReport, nil, []relationExpectation{
				{Left: "delay_units", Operator: "eq", Right: "input_units"},
				{Left: "jitter_units", Operator: "eq", Right: "input_units"},
				{Left: "input_bytes", Operator: "eq", Right: "output_bytes_plus_canceled_bytes"},
			}),
			counterFromReport(serverToClientReport, nil, []relationExpectation{
				{Left: "delay_units", Operator: "eq", Right: "input_units"},
				{Left: "jitter_units", Operator: "eq", Right: "input_units"},
				{Left: "input_bytes", Operator: "eq", Right: "output_bytes_plus_canceled_bytes"},
			}),
		},
	})
}

func counterFromReport(report weaknet.Report, exact []exactCounterExpectation, relations []relationExpectation) counterEvidence {
	return counterEvidence{
		Phase: report.Phase, Direction: report.Direction, Seed: report.Seed,
		ExpectedExact: exact, ExpectedRelations: relations, Actual: report.Actual,
	}
}

func validateSmokeReport(report smokeReport) error {
	if report.SchemaVersion != 1 || report.Classification != "local_smoke" {
		return errors.New("weak-network smoke report must be schema v1 local_smoke evidence")
	}
	for _, result := range report.Cases {
		if result.Classification != "local_smoke" || result.Status != "pass" {
			return fmt.Errorf("smoke case %s has invalid classification or status", result.Carrier)
		}
		for _, counters := range result.Counters {
			if err := validateCounterEvidence(counters); err != nil {
				return fmt.Errorf("smoke case %s counters: %w", result.Carrier, err)
			}
		}
		if result.EvidenceSHA256 != smokeCaseDigest(result) {
			return fmt.Errorf("smoke case %s evidence_sha256 does not match its content", result.Carrier)
		}
	}
	return nil
}

func validateCounterEvidence(evidence counterEvidence) error {
	seenExact := make(map[string]struct{}, len(evidence.ExpectedExact))
	for _, expected := range evidence.ExpectedExact {
		if _, duplicate := seenExact[expected.Counter]; duplicate {
			return fmt.Errorf("duplicate exact counter %q", expected.Counter)
		}
		seenExact[expected.Counter] = struct{}{}
		actual, err := counterValue(evidence.Actual, expected.Counter)
		if err != nil {
			return err
		}
		if actual != expected.Value {
			return fmt.Errorf("counter %s = %d, want %d", expected.Counter, actual, expected.Value)
		}
	}
	if len(evidence.ExpectedRelations) == 0 {
		return errors.New("at least one machine-verifiable counter relation is required")
	}
	for _, relation := range evidence.ExpectedRelations {
		if relation.Operator != "eq" {
			return fmt.Errorf("unsupported counter relation operator %q", relation.Operator)
		}
		left, err := counterValue(evidence.Actual, relation.Left)
		if err != nil {
			return err
		}
		right, err := counterValue(evidence.Actual, relation.Right)
		if err != nil {
			return err
		}
		if left != right {
			return fmt.Errorf("counter relation %s = %d, want equal to %s = %d", relation.Left, left, relation.Right, right)
		}
	}
	return nil
}

func counterValue(counters weaknet.Counters, name string) (uint64, error) {
	switch name {
	case "input_units":
		return counters.InputUnits, nil
	case "input_bytes":
		return counters.InputBytes, nil
	case "output_units":
		return counters.OutputUnits, nil
	case "output_bytes":
		return counters.OutputBytes, nil
	case "canceled_units":
		return counters.CanceledUnits, nil
	case "canceled_bytes":
		return counters.CanceledBytes, nil
	case "dropped_units":
		return counters.DroppedUnits, nil
	case "dropped_bytes":
		return counters.DroppedBytes, nil
	case "delay_units":
		return counters.DelayUnits, nil
	case "jitter_units":
		return counters.JitterUnits, nil
	case "duplicate_units":
		return counters.DuplicateUnits, nil
	case "duplicate_bytes":
		return counters.DuplicateBytes, nil
	case "input_units_plus_duplicate_units":
		return counters.InputUnits + counters.DuplicateUnits, nil
	case "output_units_plus_dropped_units":
		return counters.OutputUnits + counters.DroppedUnits, nil
	case "output_units_plus_canceled_units":
		return counters.OutputUnits + counters.CanceledUnits, nil
	case "output_units_plus_dropped_units_plus_canceled_units":
		return counters.OutputUnits + counters.DroppedUnits + counters.CanceledUnits, nil
	case "input_bytes_plus_duplicate_bytes":
		return counters.InputBytes + counters.DuplicateBytes, nil
	case "output_bytes_plus_dropped_bytes":
		return counters.OutputBytes + counters.DroppedBytes, nil
	case "output_bytes_plus_canceled_bytes":
		return counters.OutputBytes + counters.CanceledBytes, nil
	case "output_bytes_plus_dropped_bytes_plus_canceled_bytes":
		return counters.OutputBytes + counters.DroppedBytes + counters.CanceledBytes, nil
	default:
		return 0, fmt.Errorf("unknown counter %q", name)
	}
}

func newByteRelay(t *testing.T, direction weaknet.Direction, expected *weaknet.Counters) *weaknet.ByteRelay {
	t.Helper()
	relay, err := weaknet.NewByteRelay(weaknet.ByteProfile{
		Phase: "local-smoke", Direction: direction, Seed: 20260720,
		Delay: time.Millisecond, JitterScript: []time.Duration{time.Millisecond}, Expected: expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	return relay
}

func assertResetIsolation(t *testing.T, client, server carrier.Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resetStream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resetStream.Write([]byte("reset-me")); err != nil {
		t.Fatal(err)
	}
	if _, err := sibling.Write([]byte("survivor")); err != nil {
		t.Fatal(err)
	}
	serverReset, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	serverSibling, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := resetStream.Reset(); err != nil {
		t.Fatal(err)
	}
	for {
		_, err := serverReset.Read(make([]byte, 32))
		if err != nil {
			if errors.Is(err, io.EOF) {
				t.Fatal("reset stream ended with clean EOF")
			}
			break
		}
	}
	if err := sibling.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(serverSibling)
	if err != nil || string(payload) != "survivor" {
		t.Fatalf("sibling payload=%q error=%v", payload, err)
	}
	if _, err := serverSibling.Write([]byte("still-alive")); err != nil {
		t.Fatal(err)
	}
	if err := serverSibling.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(sibling)
	if err != nil || string(response) != "still-alive" {
		t.Fatalf("sibling response=%q error=%v", response, err)
	}
}

func assertUDPSmokeCounters(t *testing.T, report weaknet.Report, expectDuplicate bool) {
	t.Helper()
	if report.Actual.InputUnits == 0 || report.Actual.DelayUnits != report.Actual.OutputUnits+report.Actual.CanceledUnits {
		t.Fatalf("UDP fault was not exercised: %+v", report.Actual)
	}
	if expectDuplicate && report.Actual.DuplicateUnits != 1 {
		t.Fatalf("UDP duplicate hits=%d, want 1", report.Actual.DuplicateUnits)
	}
	if !expectDuplicate && report.Actual.DuplicateUnits != 0 {
		t.Fatalf("unexpected UDP duplicate hits=%d", report.Actual.DuplicateUnits)
	}
	if err := report.Actual.CheckUDPConservation(); err != nil {
		t.Fatal(err)
	}
}

func assertByteSmokeCounters(t *testing.T, report weaknet.Report) {
	t.Helper()
	if report.Actual.InputBytes == 0 || report.Actual.DelayUnits == 0 || report.Actual.JitterUnits == 0 {
		t.Fatalf("byte-stream fault was not exercised: %+v", report.Actual)
	}
	if err := report.Actual.CheckByteConservation(); err != nil {
		t.Fatal(err)
	}
}

func awaitSession(t *testing.T, sessions <-chan carrier.Session, errs <-chan error) carrier.Session {
	t.Helper()
	select {
	case session := <-sessions:
		return session
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("carrier session timed out")
	}
	return nil
}

func listenUDP(t *testing.T) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

type addressHolder struct {
	mu      sync.RWMutex
	address net.Addr
}

func (holder *addressHolder) Store(address net.Addr) {
	holder.mu.Lock()
	holder.address = address
	holder.mu.Unlock()
}

func (holder *addressHolder) Load() net.Addr {
	holder.mu.RLock()
	defer holder.mu.RUnlock()
	return holder.address
}

func testTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost"}
}

func validWebSocketFSB2(t *testing.T) []byte {
	t.Helper()
	session := artifactv2.SessionContract{
		ChannelID: "weaknet-smoke", InitExpireAtUnixSeconds: time.Now().Add(time.Hour).Unix(), IdleTimeoutSeconds: 60,
		EstablishTimeoutSeconds: 30, RekeyPrepareTimeoutSeconds: 10, RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams: 32, AllowedSuites: []uint16{1, 2}, DefaultSuite: 1,
	}
	for index := range session.E2EEPSK {
		session.E2EEPSK[index] = byte(index + 1)
	}
	hash, _, err := artifactv2.ComputeSessionContractHash(session)
	if err != nil {
		t.Fatal(err)
	}
	session.ContractHash = hash
	artifact := artifactv2.Artifact{
		Version: 2, Profile: artifactv2.Profile, Session: session,
		Path: artifactv2.ArtifactPath{
			Kind: artifactv2.PathDirect, RendezvousGroupID: "weaknet-smoke", ListenerAudience: "local-listener", RoutingToken: "opaque",
			Candidates: []artifactv2.Candidate{{ID: "w1", Carrier: artifactv2.CarrierWebSocket, URL: "wss://localhost/flowersec/v2/direct", WireProfile: rawquic.ALPNDirect}},
		},
		Scoped: []artifactv2.ScopeMetadata{}, Correlation: artifactv2.CorrelationContext{Version: 2, Tags: []artifactv2.CorrelationTag{}},
	}
	request, err := artifactv2.BuildRequest(artifact, "w1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := artifactv2.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func finalizeCase(result smokeCase) smokeCase {
	result.EvidenceSHA256 = smokeCaseDigest(result)
	return result
}

func smokeCaseDigest(result smokeCase) string {
	result.EvidenceSHA256 = ""
	data, _ := json.Marshal(result)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeReport(path string, report smokeReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("publish smoke report: %w", err)
	}
	return nil
}

func TestSmokeReportClassificationDoesNotClaimSystemEvidence(t *testing.T) {
	data, err := json.Marshal(smokeReport{Classification: "local_smoke", EvidenceScope: "not system, netem, qlog, PMTUD, migration, or performance SLO evidence"})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"classification":"system"`, `"performance_pass"`, `"classification":"netem"`} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("local smoke report contains forbidden claim %s", forbidden)
		}
	}
}
