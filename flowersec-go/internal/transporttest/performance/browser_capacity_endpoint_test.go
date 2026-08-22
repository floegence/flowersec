package performance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	flowersession "github.com/floegence/flowersec/flowersec-go/v3/internal/sessionv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/transporttest"
)

func TestBrowserCapacityArtifactBrokerSpendsExactlyOnceAndAuthenticatesTermination(t *testing.T) {
	artifact := newFakeBrowserCapacityArtifact()
	broker, err := newBrowserCapacityArtifactBroker(func() (browserCapacityArtifact, error) { return artifact, nil }, 1000)
	if err != nil {
		t.Fatal(err)
	}
	record, err := broker.issueRecord()
	if err != nil {
		t.Fatal(err)
	}
	request := func(value any) *httptest.ResponseRecorder {
		data, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		httpRequest := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader(data))
		httpRequest.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		broker.ServeHTTP(response, httpRequest)
		return response
	}
	spend := map[string]any{"schema_version": 1, "action": "spend", "token": record.token}
	if response := request(spend); response.Code != http.StatusNoContent {
		t.Fatalf("spend status = %d", response.Code)
	}
	if response := request(spend); response.Code != http.StatusConflict {
		t.Fatalf("replayed spend status = %d", response.Code)
	}
	if artifact.starts != 1 {
		t.Fatalf("artifact starts = %d", artifact.starts)
	}
	if response := request(map[string]any{"schema_version": 1, "action": "terminated", "session_id": record.id, "token": "wrong"}); response.Code != http.StatusConflict {
		t.Fatalf("forged termination status = %d", response.Code)
	}
	select {
	case <-record.termination:
		t.Fatal("forged termination closed the session")
	default:
	}
	if response := request(map[string]any{"schema_version": 1, "action": "terminated", "session_id": record.id, "token": record.token}); response.Code != http.StatusNoContent {
		t.Fatalf("termination status = %d", response.Code)
	}
	select {
	case <-record.termination:
	case <-time.After(time.Second):
		t.Fatal("authenticated termination was not observed")
	}
}

func TestBrowserCapacityAllowedOriginMatchesSecureModuleSite(t *testing.T) {
	if got := browserCapacityAllowedOrigin("192.0.2.10"); got != "https://192.0.2.10" {
		t.Fatalf("browser capacity allowed origin = %q", got)
	}
}

func TestBrowserCapacityOperationDeadlineUsesThePerformanceBudgetContract(t *testing.T) {
	tests := []struct {
		budget string
		tunnel time.Duration
		stream time.Duration
	}{
		{budget: "", tunnel: 30 * time.Second, stream: 60 * time.Second},
		{budget: "10m", tunnel: 10 * time.Second, stream: 20 * time.Second},
		{budget: "20m", tunnel: 10 * time.Second, stream: 20 * time.Second},
	}
	caseIDs := []string{
		"CAP-TUNNEL-WT-WSS-1000",
		"CAP-TUNNEL-WT-QUIC-1000",
		"CAP-STREAM-WT-DIRECT-100X128",
		"CAP-STREAM-WT-WSS-100X128",
		"CAP-STREAM-WT-QUIC-100X128",
	}
	for _, test := range tests {
		t.Run(test.budget, func(t *testing.T) {
			t.Setenv(performanceBudgetEnvironmentName, test.budget)
			for _, caseID := range caseIDs {
				definition, ok := lookupCapacityCase(caseID)
				if !ok {
					t.Fatalf("capacity case %q is missing", caseID)
				}
				want := test.tunnel
				if definition.Kind == capacityBrowserStream {
					want = test.stream
				}
				if got := browserCapacityOperationDeadlineForKind(definition.Kind); got != want {
					t.Errorf("%s operation deadline = %s, want %s", caseID, got, want)
				}
				if got := browserCapacityOperationDeadline(definition); got != want {
					t.Errorf("%s caller operation deadline = %s, want %s", caseID, got, want)
				}
			}
		})
	}
}

func TestBrowserCapacityEndpointHoldsUniqueProductionSessionsUntilCleanup(t *testing.T) {
	var issued int
	broker, err := newBrowserCapacityArtifactBroker(func() (browserCapacityArtifact, error) {
		issued++
		return newFakeBrowserCapacityArtifact(), nil
	}, 1000)
	if err != nil {
		t.Fatal(err)
	}
	control := &fakeBrowserCapacityControl{}
	endpoint := &browserCapacityEndpoint{
		broker: broker, control: control, closeOwner: func(context.Context) error { return nil },
		closeHTTP: func() error { return nil }, wait: func(context.Context) error { return nil }, closeDone: make(chan struct{}),
	}
	first, err := endpoint.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := endpoint.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.ID() == second.ID() || broker.residual() != 2 || issued != 2 {
		t.Fatalf("sessions %q/%q residual=%d issued=%d", first.ID(), second.ID(), broker.residual(), issued)
	}
	for _, session := range []capacitySession{first, second} {
		select {
		case <-session.Termination():
			t.Fatalf("session %s terminated before cleanup", session.ID())
		default:
		}
		if err := session.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		select {
		case <-session.Termination():
		case <-time.After(time.Second):
			t.Fatalf("session %s did not terminate", session.ID())
		}
	}
	if broker.residual() != 0 {
		t.Fatalf("residual sessions = %d", broker.residual())
	}
	if err := endpoint.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if control.connects != 2 || control.closes != 2 || control.quiesces != 1 || control.shutdowns != 1 {
		t.Fatalf("controller calls = connect:%d close:%d quiesce:%d shutdown:%d", control.connects, control.closes, control.quiesces, control.shutdowns)
	}
}

type fakeBrowserCapacityControl struct {
	mu        sync.Mutex
	connects  int
	closes    int
	quiesces  int
	shutdowns int
}

func (control *fakeBrowserCapacityControl) Connect(ctx context.Context, record *browserCapacityRecord) error {
	control.mu.Lock()
	control.connects++
	control.mu.Unlock()
	if err := record.artifact.Start(ctx); err != nil {
		return err
	}
	record.mu.Lock()
	record.spent = true
	record.mu.Unlock()
	return nil
}
func (control *fakeBrowserCapacityControl) CloseSession(_ context.Context, record *browserCapacityRecord) error {
	control.mu.Lock()
	control.closes++
	control.mu.Unlock()
	record.markTerminated()
	record.mu.Lock()
	serverSession, _ := record.session.(*fakeBrowserServerSession)
	record.mu.Unlock()
	if serverSession != nil {
		serverSession.terminate(nil)
	}
	return nil
}
func (*fakeBrowserCapacityControl) OpenStreams(context.Context, int, int) error { return nil }
func (control *fakeBrowserCapacityControl) Shutdown(context.Context) error {
	control.mu.Lock()
	control.shutdowns++
	control.mu.Unlock()
	return nil
}
func (control *fakeBrowserCapacityControl) Quiesce(context.Context) error {
	control.mu.Lock()
	control.quiesces++
	control.mu.Unlock()
	return nil
}
func (*fakeBrowserCapacityControl) Snapshot(context.Context) (browserCapacityControlSnapshot, error) {
	return browserCapacityControlSnapshot{
		SchemaVersion: 1, At: time.Now(), Process: browserCapacityControllerProcessSnapshot{RSSBytes: 1, HeapTotalBytes: 1, MaxRSSKiB: 1},
		Chromium: map[string]float64{"Timestamp": 1}, ProcessTree: linuxProcessTreeSnapshot{At: time.Now(), RootPID: 1, PGID: 1, RSSBytes: 1, OpenFDs: 1, Tasks: 1, ProcessCount: 1, AccountingMode: "pid_starttime_process_tree_fallback", FallbackReason: "test", SampleIntervalMS: 10},
	}, nil
}

func TestAggregateBrowserCapacityResourcesIncludesChromiumProcessTree(t *testing.T) {
	runner := transporttest.ResourceSnapshot{At: time.Now(), RSSBytes: 100, CPUNanoseconds: 200, AllocatedBytes: 300, OpenFDs: 4, Goroutines: 5, Tasks: 6}
	tree := linuxProcessTreeSnapshot{At: time.Now(), RootPID: 10, PGID: 10, RSSBytes: 1000, CgroupMemoryPeak: 1500, CPUNanoseconds: 2000, OpenFDs: 40, Tasks: 60, ProcessCount: 7, AccountingMode: "cgroup_v2"}
	got, err := aggregateBrowserCapacityResources(runner, tree)
	if err != nil {
		t.Fatal(err)
	}
	if got.RSSBytes != 1600 || got.CPUNanoseconds != 2200 || got.OpenFDs != 44 || got.Goroutines != 5 || got.Tasks != 66 || got.AllocatedBytes != 300 {
		t.Fatalf("aggregate = %+v", got)
	}
}

func TestBrowserCapacityResourceSnapshotAppendsOnePhaseAndUnlocks(t *testing.T) {
	endpoint := &browserCapacityEndpoint{
		control: &fakeBrowserCapacityControl{},
		contract: capacityContract{
			MaxRSS: 1 << 30, MaxCPU: time.Minute, MaxOpenFDs: 1024, MaxGoroutines: 1024, MaxTasks: 1024,
		},
	}
	if _, err := endpoint.CaptureResourceSnapshot(); err != nil {
		t.Fatal(err)
	}
	endpoint.resourceMu.Lock()
	defer endpoint.resourceMu.Unlock()
	if len(endpoint.resourceSamples) != 1 || endpoint.resourceSamples[0].Phase != "baseline" {
		t.Fatalf("resource samples = %+v", endpoint.resourceSamples)
	}
}

func TestCapacityMetadataIndexAcceptsCanonicalDecodedInteger(t *testing.T) {
	if !capacityMetadataIndex(json.Number("127"), 127) || capacityMetadataIndex(json.Number("127.5"), 127) || capacityMetadataIndex(json.Number("128"), 127) {
		t.Fatal("capacity metadata index did not preserve the canonical JSON integer boundary")
	}
}

func TestClaimCapacityMetadataIndexAcceptsUniqueOutOfOrderSet(t *testing.T) {
	seen := make([]bool, 4)
	for _, value := range []any{json.Number("3"), float64(1), 0, json.Number("2")} {
		if !claimCapacityMetadataIndex(seen, value) {
			t.Fatalf("failed to claim %v", value)
		}
	}
	if !slices.Equal(seen, []bool{true, true, true, true}) {
		t.Fatalf("claimed indexes = %v", seen)
	}
	for _, value := range []any{0, json.Number("4"), json.Number("1.5"), -1} {
		if claimCapacityMetadataIndex(seen, value) {
			t.Fatalf("accepted duplicate or invalid index %v", value)
		}
	}
}

func TestNormalizeBrowserCapacitySessionCloseAcceptsNormalTermination(t *testing.T) {
	if err := normalizeBrowserCapacitySessionClose(flowersession.ErrSessionClosed); err != nil {
		t.Fatalf("normal session termination = %v", err)
	}
	want := errors.New("transport failed")
	if err := normalizeBrowserCapacitySessionClose(want); !errors.Is(err, want) {
		t.Fatalf("transport failure = %v, want %v", err, want)
	}
}

func TestCloseBrowserCapacityServerSessionPrefersPeerTermination(t *testing.T) {
	session := newFakeBrowserServerSession()
	go func() {
		time.Sleep(10 * time.Millisecond)
		session.terminate(nil)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := closeBrowserCapacityServerSessionAfter(ctx, session, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if session.closeCalls != 0 {
		t.Fatalf("server close calls = %d, want peer termination only", session.closeCalls)
	}
}

func TestCloseBrowserCapacityServerSessionActivelyClosesAfterGrace(t *testing.T) {
	session := newFakeBrowserServerSession()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := closeBrowserCapacityServerSessionAfter(ctx, session, 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if session.closeCalls != 1 {
		t.Fatalf("server close calls = %d, want 1", session.closeCalls)
	}
}

func TestCloseBrowserCapacityServerSessionKeepsProtocolFailure(t *testing.T) {
	session := newFakeBrowserServerSession()
	want := fmt.Errorf("%w: control reset", flowersession.ErrSessionProtocol)
	session.terminate(want)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := closeBrowserCapacityServerSessionAfter(ctx, session, 100*time.Millisecond); !errors.Is(err, flowersession.ErrSessionProtocol) {
		t.Fatalf("server close error = %v, want protocol failure", err)
	}
	if session.closeCalls != 0 {
		t.Fatalf("server close calls = %d, want peer termination only", session.closeCalls)
	}
}

func TestBrowserCapacityResourcePreflightRequiresEveryDescriptorLimit(t *testing.T) {
	valid := browserCapacityResourcePreflight{NOFileSoftLimit: 1 << 20, NOFileHardLimit: 1 << 20, KernelFileMax: 1 << 40}
	if err := validateBrowserCapacityResourcePreflight(valid, 32768); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []browserCapacityResourcePreflight{
		{NOFileSoftLimit: 32767, NOFileHardLimit: 1 << 20, KernelFileMax: 1 << 40},
		{NOFileSoftLimit: 1 << 20, NOFileHardLimit: 32767, KernelFileMax: 1 << 40},
		{NOFileSoftLimit: 1 << 20, NOFileHardLimit: 1 << 20, KernelFileMax: 32767},
	} {
		if err := validateBrowserCapacityResourcePreflight(invalid, 32768); err == nil {
			t.Fatalf("invalid descriptor preflight passed: %+v", invalid)
		}
	}
}

type fakeBrowserCapacityArtifact struct {
	mu       sync.Mutex
	starts   int
	canceled bool
	session  *fakeBrowserServerSession
}

func newFakeBrowserCapacityArtifact() *fakeBrowserCapacityArtifact {
	return &fakeBrowserCapacityArtifact{session: newFakeBrowserServerSession()}
}
func (artifact *fakeBrowserCapacityArtifact) ArtifactJSON() string { return `{"version":3}` }
func (artifact *fakeBrowserCapacityArtifact) Start(context.Context) error {
	artifact.mu.Lock()
	artifact.starts++
	artifact.mu.Unlock()
	return nil
}
func (artifact *fakeBrowserCapacityArtifact) AwaitServer(context.Context) (flowersession.Session, error) {
	artifact.mu.Lock()
	defer artifact.mu.Unlock()
	if artifact.starts != 1 || artifact.canceled {
		return nil, errors.New("artifact was not started exactly once")
	}
	return artifact.session, nil
}
func (artifact *fakeBrowserCapacityArtifact) Cancel() {
	artifact.mu.Lock()
	artifact.canceled = true
	artifact.mu.Unlock()
}

type fakeBrowserServerSession struct {
	termination chan struct{}
	closeOnce   sync.Once
	closeCalls  int
	waitErr     error
}

func newFakeBrowserServerSession() *fakeBrowserServerSession {
	return &fakeBrowserServerSession{termination: make(chan struct{})}
}

func (*fakeBrowserServerSession) Path() flowersession.PathKind       { return flowersession.PathTunnel }
func (*fakeBrowserServerSession) EndpointInstanceID() (string, bool) { return "", false }
func (*fakeBrowserServerSession) RPC() flowersession.RPCPeer         { return nil }
func (*fakeBrowserServerSession) UnreliableMessages() (flowersession.UnreliableMessageChannel, error) {
	return nil, errors.New("unavailable")
}
func (*fakeBrowserServerSession) OpenStream(context.Context, string, flowersession.Metadata) (flowersession.ByteStream, error) {
	return nil, errors.New("unavailable")
}
func (*fakeBrowserServerSession) AcceptStream(context.Context) (flowersession.IncomingStream, error) {
	return flowersession.IncomingStream{}, errors.New("unavailable")
}
func (*fakeBrowserServerSession) Rekey(context.Context) error { return nil }
func (*fakeBrowserServerSession) ProbeLiveness(context.Context) (time.Duration, error) {
	return time.Millisecond, nil
}
func (session *fakeBrowserServerSession) Termination() <-chan struct{} { return session.termination }
func (session *fakeBrowserServerSession) WaitClosed(ctx context.Context) error {
	select {
	case <-session.termination:
		return session.waitErr
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}
func (session *fakeBrowserServerSession) Close() error {
	session.closeCalls++
	session.terminate(nil)
	return nil
}

func (session *fakeBrowserServerSession) terminate(err error) {
	session.waitErr = err
	session.closeOnce.Do(func() { close(session.termination) })
}
