package tunnelworkload

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/connectv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv3"
	flowersession "github.com/floegence/flowersec/flowersec-go/v3/internal/sessionv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/transporttest"
	"github.com/gorilla/websocket"
)

type stalledBulkStream struct {
	reset     chan struct{}
	resetOnce sync.Once
}

type reusableBulkStream struct {
	data        []byte
	offset      int
	warmupBytes int
	closeWrites atomic.Int32
}

func (stream *reusableBulkStream) Read(payload []byte) (int, error) {
	if len(payload) == 1 && (stream.offset == stream.warmupBytes || stream.offset == len(stream.data)) {
		return 0, io.EOF
	}
	if stream.offset == len(stream.data) {
		return 0, io.EOF
	}
	count := copy(payload, stream.data[stream.offset:])
	stream.offset += count
	return count, nil
}
func (*reusableBulkStream) Write(payload []byte) (int, error) { return len(payload), nil }
func (*reusableBulkStream) Close() error                      { return nil }
func (*reusableBulkStream) ID() uint64                        { return 1 }
func (*reusableBulkStream) Kind() string                      { return "release-tunnel-bulk" }
func (*reusableBulkStream) TerminalError() error              { return nil }
func (stream *reusableBulkStream) CloseWrite() error {
	stream.closeWrites.Add(1)
	return nil
}
func (*reusableBulkStream) Reset() error { return nil }

type protocolWindowBulkStream struct {
	reader *bytes.Reader
}

type phaseDelayedBulkStream struct {
	data          []byte
	offset        int
	warmupBytes   int
	warmupDelay   time.Duration
	scoreDelay    time.Duration
	warmupDelayed bool
	scoreDelayed  bool
}

func (stream *phaseDelayedBulkStream) Read(payload []byte) (int, error) {
	if stream.offset == len(stream.data) {
		return 0, io.EOF
	}
	if stream.offset < stream.warmupBytes && !stream.warmupDelayed {
		stream.warmupDelayed = true
		time.Sleep(stream.warmupDelay)
	}
	if stream.offset >= stream.warmupBytes && !stream.scoreDelayed {
		stream.scoreDelayed = true
		time.Sleep(stream.scoreDelay)
	}
	limit := len(stream.data)
	if stream.offset < stream.warmupBytes {
		limit = stream.warmupBytes
	}
	count := copy(payload, stream.data[stream.offset:limit])
	stream.offset += count
	return count, nil
}

func (*phaseDelayedBulkStream) Write(payload []byte) (int, error) { return len(payload), nil }
func (*phaseDelayedBulkStream) Close() error                      { return nil }
func (*phaseDelayedBulkStream) ID() uint64                        { return 3 }
func (*phaseDelayedBulkStream) Kind() string                      { return "release-tunnel-bulk" }
func (*phaseDelayedBulkStream) TerminalError() error              { return nil }
func (*phaseDelayedBulkStream) CloseWrite() error                 { return nil }
func (*phaseDelayedBulkStream) Reset() error                      { return nil }

func (stream *protocolWindowBulkStream) Read(payload []byte) (int, error) {
	return stream.reader.Read(payload)
}
func (*protocolWindowBulkStream) Write(payload []byte) (int, error) {
	if len(payload) > protocolv3.MaxDataBytes {
		return 0, io.ErrShortWrite
	}
	return len(payload), nil
}
func (*protocolWindowBulkStream) Close() error         { return nil }
func (*protocolWindowBulkStream) ID() uint64           { return 2 }
func (*protocolWindowBulkStream) Kind() string         { return "release-tunnel-bulk" }
func (*protocolWindowBulkStream) TerminalError() error { return nil }
func (*protocolWindowBulkStream) CloseWrite() error    { return nil }
func (*protocolWindowBulkStream) Reset() error         { return nil }

func TestTransferExactRespectsProtocolFlowControlRecords(t *testing.T) {
	const total = 64 * 1024
	writer := &protocolWindowBulkStream{reader: bytes.NewReader(nil)}
	reader := &protocolWindowBulkStream{reader: bytes.NewReader(bytes.Repeat([]byte{0xa5}, total))}
	if err := transferExact(context.Background(), writer, reader, total, 0xa5); err != nil {
		t.Fatalf("transfer through protocol-sized flow-control window: %v", err)
	}
}

type oneBulkStreamSession struct {
	flowersession.Session
	opened   flowersession.ByteStream
	incoming flowersession.IncomingStream
	opens    atomic.Int32
	accepts  atomic.Int32
}

func (session *oneBulkStreamSession) OpenStream(ctx context.Context, _ string, _ flowersession.Metadata) (flowersession.ByteStream, error) {
	if session.opens.Add(1) == 1 {
		return session.opened, nil
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (session *oneBulkStreamSession) AcceptStream(ctx context.Context) (flowersession.IncomingStream, error) {
	if session.accepts.Add(1) == 1 {
		return session.incoming, nil
	}
	<-ctx.Done()
	return flowersession.IncomingStream{}, ctx.Err()
}

func TestRunBulkReusesDirectionalStreamsAcrossWarmupAndScore(t *testing.T) {
	const warmup = 64 * 1024
	const score = 256 * 1024
	total := warmup + score
	clientOpened := &reusableBulkStream{}
	serverOpened := &reusableBulkStream{}
	fromClient := &reusableBulkStream{data: bytes.Repeat([]byte{0xa5}, total), warmupBytes: warmup}
	fromServer := &reusableBulkStream{data: bytes.Repeat([]byte{0x5a}, total), warmupBytes: warmup}
	client := &oneBulkStreamSession{
		opened: clientOpened,
		incoming: flowersession.IncomingStream{
			Kind: "release-tunnel-bulk", Metadata: flowersession.Metadata{"direction": "server-to-client"}, Stream: fromServer,
		},
	}
	server := &oneBulkStreamSession{
		opened: serverOpened,
		incoming: flowersession.IncomingStream{
			Kind: "release-tunnel-bulk", Metadata: flowersession.Metadata{"direction": "client-to-server"}, Stream: fromClient,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := RunBulk(ctx, &Pair{Client: client, Server: server}, warmup, score)
	if err != nil {
		t.Fatal(err)
	}
	if result.BytesPerDirection != score || result.Duration <= 0 {
		t.Fatalf("bulk result = %+v, want %d scored bytes", result, score)
	}
	if client.opens.Load() != 1 || server.opens.Load() != 1 || client.accepts.Load() != 1 || server.accepts.Load() != 1 {
		t.Fatalf("bulk stream calls = client open/accept %d/%d server open/accept %d/%d, want 1/1 each",
			client.opens.Load(), client.accepts.Load(), server.opens.Load(), server.accepts.Load())
	}
	if clientOpened.closeWrites.Load() != 1 || serverOpened.closeWrites.Load() != 1 {
		t.Fatalf("bulk CloseWrite counts = client/server %d/%d, want 1/1 after score",
			clientOpened.closeWrites.Load(), serverOpened.closeWrites.Load())
	}
}

func TestRunBulkDoesNotSerializeIndependentDirectionalRecoveryTails(t *testing.T) {
	const bytesPerPhase = 16 * 1024
	const recoveryDelay = 150 * time.Millisecond
	newStream := func(fill byte, warmupDelay, scoreDelay time.Duration) *phaseDelayedBulkStream {
		return &phaseDelayedBulkStream{
			data: bytes.Repeat([]byte{fill}, 2*bytesPerPhase), warmupBytes: bytesPerPhase,
			warmupDelay: warmupDelay, scoreDelay: scoreDelay,
		}
	}
	client := &oneBulkStreamSession{
		opened: newStream(0, 0, 0),
		incoming: flowersession.IncomingStream{
			Kind: "release-tunnel-bulk", Metadata: flowersession.Metadata{"direction": "server-to-client"},
			Stream: newStream(0x5a, 0, recoveryDelay),
		},
	}
	server := &oneBulkStreamSession{
		opened: newStream(0, 0, 0),
		incoming: flowersession.IncomingStream{
			Kind: "release-tunnel-bulk", Metadata: flowersession.Metadata{"direction": "client-to-server"},
			Stream: newStream(0xa5, recoveryDelay, 0),
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Millisecond)
	defer cancel()
	started := time.Now()
	result, err := RunBulk(ctx, &Pair{Client: client, Server: server}, bytesPerPhase, bytesPerPhase)
	if err != nil {
		t.Fatalf("independent directional recovery tails: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= 240*time.Millisecond {
		t.Fatalf("independent directional recovery tails took %s, want under the shared budget", elapsed)
	}
	if result.BytesPerDirection != bytesPerPhase {
		t.Fatalf("bulk bytes = %d, want %d", result.BytesPerDirection, bytesPerPhase)
	}
}

func newStalledBulkStream() *stalledBulkStream {
	return &stalledBulkStream{reset: make(chan struct{})}
}

func (stream *stalledBulkStream) Read([]byte) (int, error) {
	<-stream.reset
	return 0, carrier.ErrStreamReset
}
func (*stalledBulkStream) Write(payload []byte) (int, error) { return len(payload), nil }
func (stream *stalledBulkStream) Close() error               { return stream.Reset() }
func (*stalledBulkStream) ID() uint64                        { return 1 }
func (*stalledBulkStream) Kind() string                      { return "test" }
func (*stalledBulkStream) TerminalError() error              { return nil }
func (*stalledBulkStream) CloseWrite() error                 { return nil }
func (stream *stalledBulkStream) Reset() error {
	stream.resetOnce.Do(func() { close(stream.reset) })
	return nil
}

func TestTransferExactTimeoutReportsDirectionAndProgress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := transferExact(ctx, newStalledBulkStream(), newStalledBulkStream(), 1024, 0xa5)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("transfer timeout = %v", err)
	}
	for _, detail := range []string{"written=1024/1024", "read=0/1024", "write_done=true", "read_done="} {
		if !strings.Contains(err.Error(), detail) {
			t.Fatalf("transfer timeout %q lacks %q", err, detail)
		}
	}
}

func TestBulkPhaseFailureReportsBudgetAndStageTimings(t *testing.T) {
	want := context.DeadlineExceeded
	err := wrapBulkPhaseFailure("score", want, 1500*time.Millisecond, 2500*time.Millisecond, bulkPhaseTiming{
		setup: 400 * time.Millisecond, transfer: 2100 * time.Millisecond,
	})
	if !errors.Is(err, want) {
		t.Fatalf("bulk phase failure = %v, want wrapped deadline", err)
	}
	for _, detail := range []string{
		"tunnel bulk score", "prior_elapsed=1.5s", "remaining_at_start=2.5s", "setup=400ms", "transfer=2.1s",
	} {
		if !strings.Contains(err.Error(), detail) {
			t.Fatalf("bulk phase failure %q lacks %q", err, detail)
		}
	}
}

func TestTunnelPhaseFailurePreservesStageDurationAndFirstError(t *testing.T) {
	want := errors.New("tunnel cold connection 17 timed out")
	err := tunnelPhaseFailure("cold", time.Now().Add(-time.Second), want, context.DeadlineExceeded)
	if !errors.Is(err, want) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("tunnel phase failure = %v, want both causes", err)
	}
	for _, detail := range []string{"tunnel cold phase after", want.Error(), context.DeadlineExceeded.Error()} {
		if !strings.Contains(err.Error(), detail) {
			t.Fatalf("tunnel phase failure %q lacks %q", err, detail)
		}
	}
}

func TestEstablishmentTimelineSeparatesTransportAdmissionAndPairing(t *testing.T) {
	timeline := &establishmentTimeline{}
	started := time.Date(2026, time.August, 5, 2, 0, 0, 0, time.UTC)
	timeline.record(1, "client-leg", artifactv3.CarrierRawQUIC, "quic", started, started.Add(1200*time.Millisecond), nil)
	timeline.record(2, "server-leg", artifactv3.CarrierWebSocket, "tcp_tls", started, started.Add(900*time.Millisecond), nil)
	want := errors.New("admission stream reset: 0xf502")
	timeline.record(1, "client-leg", artifactv3.CarrierRawQUIC, "admission", started.Add(1200*time.Millisecond), started.Add(2*time.Second), want)
	timeline.record(0, "", "", "pairing", started, started.Add(2*time.Second), want)

	diagnostic := timeline.compact()
	for _, detail := range []string{
		`"stage":"tcp_tls"`, `"stage":"quic"`, `"stage":"admission"`, `"stage":"pairing"`,
		`"started_at":"2026-08-05T02:00:00Z"`, `"finished_at":"2026-08-05T02:00:02Z"`,
		`"duration_ms":2000`, `"first_failure":"admission stream reset: 0xf502"`,
	} {
		if !strings.Contains(diagnostic, detail) {
			t.Fatalf("establishment diagnostic %q lacks %q", diagnostic, detail)
		}
	}
}

func TestDiagnosticAttemptRecordsCarrierAndAdmissionFailures(t *testing.T) {
	want := errors.New("admission failed")
	timeline := &establishmentTimeline{}
	attempt := &diagnosticAttempt{
		CandidateAttempt: &diagnosticContractAttempt{prepared: &diagnosticContractPrepared{err: want}},
		timeline:         timeline, role: 1, candidate: artifactv3.Candidate{ID: "client-leg", Carrier: artifactv3.CarrierRawQUIC},
	}
	prepared, err := attempt.Ready(context.Background())
	if err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if _, err := prepared.Commit(context.Background(), func(context.Context) error { return nil }, []byte("FSB3")); !errors.Is(err, want) {
		t.Fatalf("Commit error = %v, want %v", err, want)
	}
	diagnostic := timeline.compact()
	for _, detail := range []string{`"stage":"quic"`, `"stage":"admission"`, `"first_failure":"admission failed"`} {
		if !strings.Contains(diagnostic, detail) {
			t.Fatalf("attempt diagnostic %q lacks %q", diagnostic, detail)
		}
	}
}

type diagnosticContractAttempt struct {
	prepared connectv3.AdmissionCommit
}

func (attempt *diagnosticContractAttempt) Ready(context.Context) (connectv3.AdmissionCommit, error) {
	return attempt.prepared, nil
}

func (*diagnosticContractAttempt) Abort(context.Context) error { return nil }

type diagnosticContractPrepared struct {
	err error
}

func (prepared *diagnosticContractPrepared) Commit(context.Context, func(context.Context) error, []byte) (carrier.Session, error) {
	return nil, prepared.err
}

func (*diagnosticContractPrepared) Close(context.Context) error { return nil }

var _ io.ReadWriteCloser = (*stalledBulkStream)(nil)

type terminalCloseSession struct {
	flowersession.Session
	closeErr   error
	terminated chan struct{}
	closeFn    func()
}

func (session *terminalCloseSession) Termination() <-chan struct{} { return session.terminated }

func TestTunnelAdmissionRequestsMirrorCandidateSetAndPeerRoles(t *testing.T) {
	contract, suffix, err := releaseContractWithStreams(protocolv3.SuiteChaCha20Poly1305, defaultMaxInboundStreams)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := &Endpoint{candidates: []artifactv3.Candidate{
		{ID: "client-leg", Carrier: artifactv3.CarrierRawQUIC, URL: "quic://127.0.0.1:10001", WireProfile: "flowersec-tunnel/3", TLS: artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA}},
		{ID: "server-leg", Carrier: artifactv3.CarrierRawQUIC, URL: "quic://127.0.0.1:10002", WireProfile: "flowersec-tunnel/3", TLS: artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA}},
	}}
	client := endpoint.artifact(contract, "group-"+suffix, 1, "client-"+suffix, "server-"+suffix, "token-c-"+suffix)
	server := endpoint.artifact(contract, "group-"+suffix, 2, "server-"+suffix, "client-"+suffix, "token-s-"+suffix)
	clientRequest, err := artifactv3.BuildRequest(client, "client-leg")
	if err != nil {
		t.Fatal(err)
	}
	serverRequest, err := artifactv3.BuildRequest(server, "server-leg")
	if err != nil {
		t.Fatal(err)
	}
	if clientRequest.CandidateSetHash != serverRequest.CandidateSetHash {
		t.Fatal("mirrored tunnel legs changed the candidate-set hash")
	}
	if clientRequest.Role != 1 || serverRequest.Role != 2 || client.Path.ExpectedPeerEndpointInstanceID != server.Path.LocalEndpointInstanceID || server.Path.ExpectedPeerEndpointInstanceID != client.Path.LocalEndpointInstanceID || clientRequest.EndpointInstanceID != client.Path.LocalEndpointInstanceID || serverRequest.EndpointInstanceID != server.Path.LocalEndpointInstanceID {
		t.Fatalf("unpaired tunnel roles: client=%+v server=%+v", clientRequest, serverRequest)
	}
	if clientRequest.ChosenCandidateID != "client-leg" || serverRequest.ChosenCandidateID != "server-leg" {
		t.Fatalf("tunnel roles selected the wrong candidate: client=%q server=%q", clientRequest.ChosenCandidateID, serverRequest.ChosenCandidateID)
	}
}

func (session *terminalCloseSession) Close() error {
	if session.closeFn != nil {
		session.closeFn()
	}
	return session.closeErr
}

func TestPairCloseAcceptsTerminalSessionCloseErrorsAfterTermination(t *testing.T) {
	terminated := make(chan struct{})
	close(terminated)
	pair := &Pair{
		Client: &terminalCloseSession{closeErr: context.DeadlineExceeded, terminated: terminated},
		Server: &terminalCloseSession{closeErr: context.Canceled, terminated: terminated},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := pair.Close(ctx); err != nil {
		t.Fatalf("Pair.Close terminal errors = %v", err)
	}
}

func TestPairCloseAcceptsPeerTunnelBridgeCloseAfterTermination(t *testing.T) {
	terminated := make(chan struct{})
	close(terminated)
	pair := &Pair{
		Client: &terminalCloseSession{
			closeErr:   &websocket.CloseError{Code: 4000, Text: "tunnel bridge closed"},
			terminated: terminated,
		},
	}
	if err := pair.Close(context.Background()); err != nil {
		t.Fatalf("Pair.Close peer tunnel bridge close = %v", err)
	}
}

func TestPairCloseRetainsUnexpectedSessionCloseErrors(t *testing.T) {
	terminated := make(chan struct{})
	close(terminated)
	want := errors.New("unexpected close failure")
	pair := &Pair{Client: &terminalCloseSession{closeErr: want, terminated: terminated}}
	if err := pair.Close(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Pair.Close error = %v, want %v", err, want)
	}
}

func TestPairClosePrefersCompletedTerminationOverExpiredCleanupContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 64 {
		terminated := make(chan struct{})
		close(terminated)
		pair := &Pair{Client: &terminalCloseSession{terminated: terminated}}
		if err := pair.Close(ctx); err != nil {
			t.Fatalf("Pair.Close completed termination = %v", err)
		}
	}
}

func TestCloseTunnelOwnersClosesSessionsBeforeEndpoint(t *testing.T) {
	terminated := make(chan struct{})
	close(terminated)
	var closed atomic.Int32
	pair := &Pair{
		Client: &terminalCloseSession{terminated: terminated, closeFn: func() { closed.Add(1) }},
		Server: &terminalCloseSession{terminated: terminated, closeFn: func() { closed.Add(1) }},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := closeTunnelOwners(ctx, pair, func(context.Context) error {
		if got := closed.Load(); got != 2 {
			return fmt.Errorf("endpoint closed after %d session closes, want 2", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("close tunnel owners in ownership order: %v", err)
	}
}

func TestRunColdRequiresIndependentCleanupDeadline(t *testing.T) {
	_, err := RunCold(context.Background(), &Endpoint{}, 1, 1, 1, time.Second, 0)
	if err == nil || !errors.Is(err, errInvalidTunnelColdWorkload) {
		t.Fatalf("RunCold cleanup deadline error = %v", err)
	}
}

func TestRunColdStopsSchedulingAndPreservesFirstProductFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	_, err := RunCold(ctx, &Endpoint{}, 3, 1, 2, time.Second, time.Second)
	elapsed := time.Since(started)
	if !errors.Is(err, errEndpointClosed) || !strings.Contains(err.Error(), "tunnel cold connection 1") {
		t.Fatalf("RunCold first failure = %v", err)
	}
	if strings.Contains(err.Error(), "tunnel cold connection 2") || elapsed >= 400*time.Millisecond {
		t.Fatalf("RunCold scheduled after first failure: elapsed=%s error=%v", elapsed, err)
	}
	if ctx.Err() != nil {
		t.Fatalf("RunCold canceled its caller context: %v", ctx.Err())
	}
}

func TestReleaseCoordinatorPairTimeoutCoversColdPhase(t *testing.T) {
	plan := transporttest.ProfilePlan{
		Cold: transporttest.ColdPlan{
			OperationDeadlineSeconds: 53,
			PhaseDeadlineSeconds:     55,
		},
	}
	config, err := releaseCoordinatorConfig(plan)
	if err != nil {
		t.Fatal(err)
	}
	if config.PairTimeout != 55*time.Second || config.AdmissionResponseTimeout != 30*time.Second || config.ActivationTimeout != 30*time.Second {
		t.Fatalf("release coordinator timeouts = pair %s response %s activation %s", config.PairTimeout, config.AdmissionResponseTimeout, config.ActivationTimeout)
	}
}

func TestTopologiesNameEveryWebSocketRawQUICPair(t *testing.T) {
	want := map[Topology][2]carrier.Kind{
		TopologyWW: {carrier.KindWebSocket, carrier.KindWebSocket},
		TopologyQQ: {carrier.KindRawQUIC, carrier.KindRawQUIC},
		TopologyWQ: {carrier.KindWebSocket, carrier.KindRawQUIC},
		TopologyQW: {carrier.KindRawQUIC, carrier.KindWebSocket},
	}
	if len(Topologies()) != len(want) {
		t.Fatalf("topologies = %v", Topologies())
	}
	for topology, carriers := range want {
		client, server, err := topology.Carriers()
		if err != nil {
			t.Fatal(err)
		}
		if client != carriers[0] || server != carriers[1] {
			t.Fatalf("%s carriers = %s/%s, want %s/%s", topology, client, server, carriers[0], carriers[1])
		}
	}
	if _, _, err := Topology("WT").Carriers(); err == nil {
		t.Fatal("accepted topology outside the frozen WW/QQ/WQ/QW matrix")
	}
}

func TestProductionTunnelTopologiesRunColdRPCBulkAndCleanup(t *testing.T) {
	plan := transporttest.ProfilePlan{
		ID: "focused-v1",
		Cold: transporttest.ColdPlan{
			Operations: 2, MaxInflight: 1, StartRatePerSecond: 20,
			OperationDeadlineSeconds: 10, PhaseDeadlineSeconds: 20,
		},
		RPC: transporttest.RPCPlan{
			Operations: 4, RequestBytes: 128, ResponseBytes: 128, Workers: 2,
			OperationDeadlineSeconds: 5, PhaseDeadlineSeconds: 10,
		},
		Bulk: transporttest.BulkPlan{
			WarmupBytesPerDirection: 1024, ScoreBytesPerDirection: 4096,
			PhaseDeadlineSeconds: 10,
		},
		CleanupDeadlineSeconds: 10,
	}
	for _, topology := range Topologies() {
		t.Run(string(topology), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			endpoint, err := OpenEndpointAt(ctx, topology, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			result, err := Run(ctx, endpoint, plan)
			if err != nil {
				t.Fatal(err)
			}
			if result.Topology != topology || len(result.Cold) != plan.Cold.Operations || len(result.RPC) != plan.RPC.Operations {
				t.Fatalf("incomplete workload result: %+v", result)
			}
			if result.Bulk.BytesPerDirection != plan.Bulk.ScoreBytesPerDirection || result.CleanupDuration <= 0 {
				t.Fatalf("incomplete bulk/cleanup result: %+v", result)
			}
		})
	}
}

func TestPeriodicLossQWColdPairingAtFrozenConcurrency(t *testing.T) {
	plan := transporttest.ProfilePlan{
		Cold: transporttest.ColdPlan{
			Operations: 30, MaxInflight: 30, StartRatePerSecond: 15,
			OperationDeadlineSeconds: 5, PhaseDeadlineSeconds: 7,
		},
		CleanupDeadlineSeconds: 2,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	endpoint, err := OpenTestEndpointAt(ctx, TopologyQW, "127.0.0.1", plan)
	if err != nil {
		t.Fatal(err)
	}
	result, err := RunColdDiagnostic(ctx, endpoint, plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Topology != TopologyQW || len(result.Cold) != plan.Cold.Operations {
		t.Fatalf("periodic-loss QW cold operations = %d, want %d", len(result.Cold), plan.Cold.Operations)
	}
	if len(result.RPC) != 0 || len(result.Bulk.Directions) != 0 || result.Bulk.BytesPerDirection != 0 || result.CleanupDuration <= 0 {
		t.Fatalf("cold diagnostic entered later phases or skipped cleanup: %+v", result)
	}
}

func TestProductionTunnelWQCleanupFitsFrozenDeadline(t *testing.T) {
	plan := transporttest.ProfilePlan{
		ID: "cleanup-contract-v1",
		Cold: transporttest.ColdPlan{
			Operations: 1, MaxInflight: 1, StartRatePerSecond: 1,
			OperationDeadlineSeconds: 5, PhaseDeadlineSeconds: 6,
		},
		RPC: transporttest.RPCPlan{
			Operations: 1, RequestBytes: 128, ResponseBytes: 128, Workers: 1,
			OperationDeadlineSeconds: 2, PhaseDeadlineSeconds: 4,
		},
		Bulk: transporttest.BulkPlan{
			WarmupBytesPerDirection: 1024, ScoreBytesPerDirection: 4096,
			PhaseDeadlineSeconds: 5,
		},
		CleanupDeadlineSeconds: 2,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	endpoint, err := OpenEndpointAt(ctx, TopologyWQ, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	result, err := Run(ctx, endpoint, plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.CleanupDuration <= 0 || result.CleanupDuration > 2*time.Second {
		t.Fatalf("WQ cleanup duration = %s, want within frozen 2s deadline", result.CleanupDuration)
	}
}

func TestOpenEndpointAtRejectsNonConcreteAddress(t *testing.T) {
	for _, address := range []string{"", "0.0.0.0", "not-an-ip", "224.0.0.1"} {
		if _, err := OpenEndpointAt(context.Background(), TopologyWW, address); err == nil {
			t.Fatalf("accepted listen address %q", address)
		}
	}
}
