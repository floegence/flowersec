package performance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transporttest"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transporttest/tunnelworkload"
)

func TestBrowserCapacityWorkerCommandPreservesCgroupMountNamespace(t *testing.T) {
	command := browserCapacityWorkerCommand(context.Background(), "fc-1234", "/release/runner")
	want := []string{"/usr/bin/nsenter", "--net=/var/run/netns/fc-1234", "--", "/release/runner", "-test.run=^TestBrowserCapacityWorkerProcess$"}
	if command.Path != want[0] || !slices.Equal(command.Args, want) {
		t.Fatalf("browser capacity worker command = path %q args %v, want %v", command.Path, command.Args, want)
	}
}

func TestFocusedProductionCapacityCase(t *testing.T) {
	skipCapacityWorkloadInShortMode(t)
	id := os.Getenv("FLOWERSEC_TEST_CAPACITY_CASE")
	if id == "" {
		t.Skip("set FLOWERSEC_TEST_CAPACITY_CASE to run one production capacity case")
	}
	definition, ok := lookupCapacityCase(id)
	if !ok {
		t.Fatalf("focused production capacity case %q is unavailable in a Go test process", id)
	}
	ctx, cancel := context.WithTimeout(performanceTestContext, capacityCaseTimeout(definition))
	defer cancel()
	if definition.Kind == capacityBrowserTunnel || definition.Kind == capacityBrowserStream {
		runFocusedBrowserCapacityCase(t, ctx, definition)
		return
	}
	endpoint, err := openProductionCapacityEndpoint(ctx, definition, productionCapacityContract().Sessions)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runCapacityCase(ctx, definition, productionCapacityContract(), endpoint, nil)
	t.Logf("capacity result: %+v", result)
	if err != nil {
		t.Fatal(err)
	}
}

func TestProductionCapacityContractAndRegistryAreFrozen(t *testing.T) {
	contract := productionCapacityContract()
	if contract.Sessions != 1000 || contract.Ramp != 30*time.Second || contract.Hold != 60*time.Second ||
		contract.Cleanup != 30*time.Second || contract.Watchdog != 120*time.Second || contract.MaxGoroutines != 40960 {
		t.Fatalf("production capacity contract = %+v", contract)
	}
	cases := capacityCaseRegistry()
	want := []struct{ id, profile string }{
		{"CAP-DIRECT-WSS-1000", "capacity-direct-wss-1000"},
		{"CAP-DIRECT-QUIC-1000", "capacity-direct-quic-1000"},
		{"CAP-DIRECT-WT-1000", "capacity-direct-webtransport-1000"},
		{"CAP-TUNNEL-WT-WSS-1000", "capacity-tunnel-webtransport-wss-1000"},
		{"CAP-TUNNEL-WT-QUIC-1000", "capacity-tunnel-webtransport-quic-1000"},
		{"CAP-STREAM-WT-DIRECT-100X128", "capacity-streams-webtransport-direct-100x128"},
		{"CAP-STREAM-WT-WSS-100X128", "capacity-streams-webtransport-wss-100x128"},
		{"CAP-STREAM-WT-QUIC-100X128", "capacity-streams-webtransport-quic-100x128"},
		{"CAP-WW-1000", "capacity-tunnel-ww-1000"},
		{"CAP-QQ-1000", "capacity-tunnel-qq-1000"},
		{"CAP-WQ-1000", "capacity-tunnel-wq-1000"},
		{"CAP-QW-1000", "capacity-tunnel-qw-1000"},
	}
	if len(cases) != len(want) {
		t.Fatalf("capacity registry length = %d, want %d", len(cases), len(want))
	}
	for index, definition := range cases {
		if definition.ID != want[index].id || definition.Profile != want[index].profile {
			t.Fatalf("capacity definition[%d] = %+v, want %+v", index, definition, want[index])
		}
	}
}

func TestBrowserCapacityContractUsesFullProcessTreeCalibration(t *testing.T) {
	contract := productionBrowserCapacityContract()
	if contract.MaxRSS != 3<<30 || contract.MaxOpenFDs != 12288 || contract.MaxGoroutines != 40960 || contract.MaxTasks != 8192 ||
		contract.ResourceScope != "go_runner_plus_chromium_process_tree" || contract.CalibrationRSS != 2162716672 || contract.CalibrationOpenFDs != 9350 {
		t.Fatalf("browser capacity contract = %+v", contract)
	}
}

func TestBrowserStreamCapacityContractIsFrozen(t *testing.T) {
	contract := productionBrowserStreamCapacityContract()
	if contract.Sessions != 100 || contract.StreamsPerSession != 128 || contract.MaxRSS != 3<<30 || contract.MaxCPU != 240*time.Second || contract.MaxOpenFDs != 32768 ||
		contract.CalibrationRSS != 0 || contract.CalibrationOpenFDs != 0 || capacitySessionRamp(contract) != 15*time.Second {
		t.Fatalf("browser stream capacity contract = %+v", contract)
	}
	definition, ok := lookupCapacityCase("CAP-STREAM-WT-DIRECT-100X128")
	if !ok || capacityCaseTimeout(definition) != 180*time.Second {
		t.Fatalf("browser stream capacity case timeout = %v, found=%t", capacityCaseTimeout(definition), ok)
	}
	regular, ok := lookupCapacityCase("CAP-DIRECT-WSS-1000")
	if !ok || capacityCaseTimeout(regular) != 150*time.Second {
		t.Fatalf("regular capacity case timeout = %v, found=%t", capacityCaseTimeout(regular), ok)
	}
}

func TestCapacityConnectScheduleReservesCompletionWindow(t *testing.T) {
	sessionRamp := capacitySessionRamp(productionCapacityContract())
	scheduleWindow := capacityConnectScheduleWindow(sessionRamp)
	if scheduleWindow != 22500*time.Millisecond || sessionRamp-scheduleWindow != 7500*time.Millisecond {
		t.Fatalf("capacity connect schedule/completion windows = %v/%v, want 22.5s/7.5s", scheduleWindow, sessionRamp-scheduleWindow)
	}
}

func TestCapacityLatencyAndThroughputBudgetsFailClosed(t *testing.T) {
	if got := percentileDuration([]time.Duration{9, 1, 5, 3, 7}, 50); got != 5 {
		t.Fatalf("p50 = %s, want 5ns", got)
	}
	if got := percentileDuration([]time.Duration{9, 1, 5, 3, 7}, 99); got != 9 {
		t.Fatalf("p99 = %s, want 9ns", got)
	}
	result := capacityCaseResult{
		ConnectP50: 2 * time.Millisecond, ConnectP95: 4 * time.Millisecond, ConnectP99: 6 * time.Millisecond,
		ConnectsPerSecond: 20, LivenessP99: 3 * time.Millisecond, LivenessOpsPerSecond: 12,
	}
	contract := capacityContract{
		MaxConnectP50: 3 * time.Millisecond, MaxConnectP95: 5 * time.Millisecond, MaxConnectP99: 7 * time.Millisecond,
		MaxLivenessP99: 4 * time.Millisecond, MinConnectsPerSecond: 10, MinLivenessOpsPerSecond: 10,
	}
	if err := assertCapacityLatencyBudget(contract, result); err != nil {
		t.Fatalf("accepted within-budget latency: %v", err)
	}
	if err := assertCapacityLivenessBudget(contract, result); err != nil {
		t.Fatalf("accepted within-budget liveness: %v", err)
	}
	result.ConnectP99 = 8 * time.Millisecond
	if err := assertCapacityLatencyBudget(contract, result); err == nil {
		t.Fatal("accepted connect p99 above budget")
	}
	result.ConnectP99 = 6 * time.Millisecond
	result.LivenessOpsPerSecond = 9
	if err := assertCapacityLivenessBudget(contract, result); err == nil {
		t.Fatal("accepted liveness throughput below budget")
	}
}

func TestBrowserWSSStreamCapacityRecordsTightYamuxResources(t *testing.T) {
	definition, ok := lookupCapacityCase("CAP-STREAM-WT-WSS-100X128")
	if !ok {
		t.Fatal("WSS stream capacity case is missing")
	}
	contract := capacityContractForDefinition(definition)
	if contract.YamuxMaxFrameBytes != 256*1024 || contract.YamuxMaxStreamReceiveBytes != 256*1024 ||
		contract.YamuxMaxSessionReceiveBytes != 130*256*1024 || contract.TunnelCopyBufferBytes != 4*1024 {
		t.Fatalf("WSS stream capacity Yamux resources = %+v", contract)
	}
}

func TestCapacityCleanupReservesResourceConvergenceWindow(t *testing.T) {
	regular := capacityContract{Cleanup: 30 * time.Second}
	if got := capacityCleanupCloseWindow(capacityCaseDefinition{Kind: capacityDirect}, regular); got != 20*time.Second {
		t.Fatalf("regular cleanup close window = %s, want 20s", got)
	}
	stream := capacityContract{Cleanup: 30 * time.Second, StreamsPerSession: 128}
	if got := capacityCleanupCloseWindow(capacityCaseDefinition{Kind: capacityBrowserStream}, stream); got != 5*time.Second {
		t.Fatalf("stream cleanup close window = %s, want 5s", got)
	}
	if got := capacityCleanupCloseWindow(capacityCaseDefinition{Kind: capacityBrowserTunnel}, regular); got != 5*time.Second {
		t.Fatalf("browser tunnel cleanup close window = %s, want 5s", got)
	}
}

func TestRunBrowserStreamCapacityCleanupConvergesOneHundredReliableSessions(t *testing.T) {
	skipCapacityWorkloadInShortMode(t)
	contract := capacityContract{
		Sessions: 100, StreamsPerSession: 1,
		Ramp: time.Second, Hold: 100 * time.Millisecond, Cleanup: 600 * time.Millisecond, Watchdog: 1700 * time.Millisecond,
		MaxRSS: 1 << 30, MaxCPU: 2 * time.Second, MaxOpenFDs: 1000, MaxGoroutines: 1000, MaxTasks: 1000,
	}
	endpoint := &fakeCapacityEndpoint{sessionCloseDelay: 360 * time.Millisecond}
	result, err := runCapacityCase(context.Background(), capacityCaseDefinition{ID: "browser-stream-cleanup", Profile: "browser-stream-cleanup"}, contract, endpoint, monotonicSnapshots())
	if err != nil {
		t.Fatal(err)
	}
	if result.CleanupDisconnects != contract.Sessions || result.ResidualSessions != 0 || result.WatchdogTimeouts != 0 {
		t.Fatalf("browser stream cleanup result = %+v", result)
	}
}

func TestRunBrowserTunnelCapacityCleanupConvergesOneThousandReliableSessions(t *testing.T) {
	skipCapacityWorkloadInShortMode(t)
	contract := capacityContract{
		Sessions: 1000,
		Ramp:     3 * time.Second, Hold: 100 * time.Millisecond, Cleanup: 600 * time.Millisecond, Watchdog: 3700 * time.Millisecond,
		MaxRSS: 1 << 30, MaxCPU: 4 * time.Second, MaxOpenFDs: 2000, MaxGoroutines: 2000, MaxTasks: 2000,
	}
	endpoint := &fakeCapacityEndpoint{sessionCloseDelay: 360 * time.Millisecond}
	result, err := runCapacityCase(context.Background(), capacityCaseDefinition{
		ID: "browser-tunnel-cleanup", Profile: "browser-tunnel-cleanup", Kind: capacityBrowserTunnel,
	}, contract, endpoint, monotonicSnapshots())
	if err != nil {
		t.Fatal(err)
	}
	if result.CleanupDisconnects != contract.Sessions || result.ResidualSessions != 0 || result.WatchdogTimeouts != 0 {
		t.Fatalf("browser tunnel cleanup result = %+v", result)
	}
}

func TestDirectCapacityWrappersHoldDistinctProductionSessions(t *testing.T) {
	skipCapacityWorkloadInShortMode(t)
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindRawQUIC, carrier.KindWebTransport} {
		t.Run(string(kind), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			production, err := transporttest.OpenProductDirectEndpoint(ctx, kind)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := &directCapacityEndpoint{endpoint: production}
			first, err := endpoint.Connect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			second, err := endpoint.Connect(ctx)
			if err != nil {
				_ = first.Close(ctx)
				t.Fatal(err)
			}
			if first.ID() == second.ID() {
				t.Fatalf("production session IDs are not unique: %q", first.ID())
			}
			for _, session := range []capacitySession{first, second} {
				select {
				case <-session.Termination():
					t.Fatal("production session terminated before cleanup")
				default:
				}
				if err := session.Close(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if err := endpoint.Close(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRawQUICCapacityPathsCleanEveryShortSampleSession(t *testing.T) {
	skipCapacityWorkloadInShortMode(t)
	tests := []struct {
		name string
		open func(context.Context) (capacityEndpoint, error)
	}{
		{name: "direct", open: func(ctx context.Context) (capacityEndpoint, error) {
			endpoint, err := transporttest.OpenProductDirectEndpoint(ctx, carrier.KindRawQUIC)
			if err != nil {
				return nil, err
			}
			return &directCapacityEndpoint{endpoint: endpoint}, nil
		}},
		{name: "tunnel-qq", open: func(ctx context.Context) (capacityEndpoint, error) {
			endpoint, err := tunnelworkload.OpenEndpointAt(ctx, tunnelworkload.TopologyQQ, "127.0.0.1")
			if err != nil {
				return nil, err
			}
			return &tunnelCapacityEndpoint{endpoint: endpoint}, nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			endpoint, err := test.open(ctx)
			if err != nil {
				t.Fatal(err)
			}
			contract := capacityContract{
				Sessions: 4, Ramp: 400 * time.Millisecond, Hold: 100 * time.Millisecond, Cleanup: 400 * time.Millisecond, Watchdog: 900 * time.Millisecond,
				MaxRSS: 1 << 30, MaxCPU: 10 * time.Second, MaxOpenFDs: 4096, MaxGoroutines: 4096, MaxTasks: 4096,
			}
			result, err := runCapacityCase(ctx, capacityCaseDefinition{ID: "raw-quic-short", Profile: "raw-quic-short"}, contract, endpoint, monotonicSnapshots())
			if err != nil {
				t.Fatal(err)
			}
			if result.Succeeded != 4 || result.UniqueActivePeak != 4 || result.HoldDisconnects != 0 || result.ResidualSessions != 0 {
				t.Fatalf("raw QUIC short capacity result = %+v", result)
			}
		})
	}
}

func skipCapacityWorkloadInShortMode(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("capacity workloads run only in final integration")
	}
}

func TestRunCapacityCaseHoldsUniqueLiveSessionsAndCleansUp(t *testing.T) {
	contract := capacityContract{
		Sessions: 4, Ramp: 20 * time.Millisecond, Hold: 20 * time.Millisecond,
		Cleanup: 20 * time.Millisecond, Watchdog: 60 * time.Millisecond,
		MaxRSS: 1 << 30, MaxCPU: time.Second, MaxOpenFDs: 100, MaxGoroutines: 100, MaxTasks: 100,
	}
	endpoint := &fakeCapacityEndpoint{}
	result, err := runCapacityCase(context.Background(), capacityCaseDefinition{ID: "test", Profile: "test"}, contract, endpoint, monotonicSnapshots())
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.connects != contract.Sessions || endpoint.closes != 1 {
		t.Fatalf("endpoint connects/closes = %d/%d", endpoint.connects, endpoint.closes)
	}
	if result.Attempted != 4 || result.Succeeded != 4 || result.Failed != 0 || result.UniqueActivePeak != 4 ||
		result.HoldDisconnects != 0 || result.LivenessSweeps != 4 || result.LivenessFailures != 0 ||
		result.CleanupDisconnects != 4 || result.ResidualSessions != 0 || result.WatchdogTimeouts != 0 {
		t.Fatalf("capacity result counters = %+v", result)
	}
	wantEvents := []string{"capacity_ramp_completed", "capacity_hold_completed", "capacity_cleanup_completed"}
	wantAt := []int64{contract.Ramp.Nanoseconds(), (contract.Ramp + contract.Hold).Nanoseconds(), contract.Watchdog.Nanoseconds()}
	for index, record := range result.Timeline {
		if record.Event != wantEvents[index] || record.AtNS != wantAt[index] {
			t.Fatalf("trace[%d] = %+v", index, record)
		}
	}
	if len(result.Resources) != 3 || result.Resources[0].ActiveSessions != 4 ||
		result.Resources[1].ActiveSessions != 4 || result.Resources[2].ActiveSessions != 0 ||
		result.Resources[2].ResidualSessions == nil || result.Resources[2].ResidualGoroutines == nil ||
		result.Resources[2].ResidualOpenFDs == nil || result.Resources[2].ResidualTasks == nil {
		t.Fatalf("resource timeline = %+v", result.Resources)
	}
}

func TestRunCapacityCaseClosesEndpointBeforeCleanupResourceSnapshot(t *testing.T) {
	contract := capacityContract{
		Sessions: 2, Ramp: 20 * time.Millisecond, Hold: 20 * time.Millisecond,
		Cleanup: 20 * time.Millisecond, Watchdog: 60 * time.Millisecond,
		MaxRSS: 1 << 30, MaxCPU: time.Second, MaxOpenFDs: 100, MaxGoroutines: 100, MaxTasks: 100,
	}
	endpoint := &fakeCapacityEndpoint{}
	snapshots := monotonicSnapshots()
	var captures int
	capture := func() (transporttest.ResourceSnapshot, error) {
		captures++
		if captures == 4 {
			endpoint.mu.Lock()
			closed := endpoint.closed
			endpoint.mu.Unlock()
			if !closed {
				return transporttest.ResourceSnapshot{}, errors.New("cleanup snapshot preceded endpoint teardown")
			}
		}
		return snapshots()
	}
	if _, err := runCapacityCase(context.Background(), capacityCaseDefinition{ID: "teardown-order", Profile: "teardown-order"}, contract, endpoint, capture); err != nil {
		t.Fatal(err)
	}
	if captures != 4 || endpoint.closes != 1 {
		t.Fatalf("captures/closes = %d/%d", captures, endpoint.closes)
	}
}

func TestRunCapacityCaseSnapshotsQuiescedBrowserBeforeFinalClose(t *testing.T) {
	contract := capacityContract{
		Sessions: 2, Ramp: 20 * time.Millisecond, Hold: 20 * time.Millisecond,
		Cleanup: 20 * time.Millisecond, Watchdog: 60 * time.Millisecond,
		MaxRSS: 1 << 30, MaxCPU: time.Second, MaxOpenFDs: 100, MaxGoroutines: 100, MaxTasks: 100,
	}
	endpoint := &fakeQuiescingCapacityEndpoint{fakeCapacityEndpoint: &fakeCapacityEndpoint{}}
	snapshots := monotonicSnapshots()
	var captures int
	capture := func() (transporttest.ResourceSnapshot, error) {
		captures++
		if captures == 4 {
			endpoint.mu.Lock()
			quiesced, finalized := endpoint.quiesced, endpoint.closed
			endpoint.mu.Unlock()
			if !quiesced || finalized {
				return transporttest.ResourceSnapshot{}, fmt.Errorf("cleanup snapshot lifecycle = quiesced:%t finalized:%t", quiesced, finalized)
			}
		}
		return snapshots()
	}
	if _, err := runCapacityCase(context.Background(), capacityCaseDefinition{ID: "quiesce-order", Profile: "quiesce-order"}, contract, endpoint, capture); err != nil {
		t.Fatal(err)
	}
	if captures != 4 || endpoint.closes != 1 {
		t.Fatalf("captures/closes = %d/%d", captures, endpoint.closes)
	}
}

func TestRunCapacityCaseCancellationClosesEndpointBeforeSessions(t *testing.T) {
	contract := capacityContract{
		Sessions: 1, Ramp: time.Second, Hold: time.Second, Cleanup: 100 * time.Millisecond,
		Watchdog: 2100 * time.Millisecond,
		MaxRSS:   1 << 30, MaxCPU: time.Second, MaxOpenFDs: 100, MaxGoroutines: 100, MaxTasks: 100,
	}
	connected := make(chan struct{})
	endpoint := &fakeCapacityEndpoint{connected: connected}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := runCapacityCase(ctx, capacityCaseDefinition{ID: "cancel-order", Profile: "cancel-order"}, contract, endpoint, monotonicSnapshots())
		done <- err
	}()
	select {
	case <-connected:
	case <-time.After(time.Second):
		t.Fatal("capacity session did not connect")
	}
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runCapacityCase() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled capacity case did not return")
	}
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	if !slices.Equal(endpoint.closeOrder, []string{"endpoint", "session"}) {
		t.Fatalf("cancel cleanup order = %v, want endpoint then session", endpoint.closeOrder)
	}
}

func TestRunCapacityCaseProvesStreamPeakAndZeroResidual(t *testing.T) {
	contract := capacityContract{
		Sessions: 2, StreamsPerSession: 3, Ramp: 20 * time.Millisecond, Hold: 20 * time.Millisecond,
		Cleanup: 20 * time.Millisecond, Watchdog: 60 * time.Millisecond,
		MaxRSS: 1 << 30, MaxCPU: time.Second, MaxOpenFDs: 100, MaxGoroutines: 100, MaxTasks: 100,
	}
	endpoint := &fakeCapacityEndpoint{}
	result, err := runCapacityCase(context.Background(), capacityCaseDefinition{ID: "stream", Profile: "stream"}, contract, endpoint, monotonicSnapshots())
	if err != nil {
		t.Fatal(err)
	}
	if result.CompletedStreams != 6 || result.ActiveStreamPeak != 6 || result.ResidualStreams != 0 || endpoint.openedStreams != 6 {
		t.Fatalf("stream capacity result = %+v endpoint=%+v", result, endpoint)
	}
	if result.Resources[0].ActiveStreams != 6 || result.Resources[1].ActiveStreams != 6 ||
		result.Resources[2].ResidualStreams == nil || *result.Resources[2].ResidualStreams != 0 {
		t.Fatalf("stream resource timeline = %+v", result.Resources)
	}
}

func TestRunCapacityCaseFailsOnDuplicateOrEarlyTermination(t *testing.T) {
	contract := capacityContract{Sessions: 2, Ramp: 10 * time.Millisecond, Hold: 10 * time.Millisecond, Cleanup: 10 * time.Millisecond, Watchdog: 30 * time.Millisecond,
		MaxRSS: 1 << 30, MaxCPU: time.Second, MaxOpenFDs: 100, MaxGoroutines: 100, MaxTasks: 100}
	duplicate := &fakeCapacityEndpoint{duplicateID: true}
	if _, err := runCapacityCase(context.Background(), capacityCaseDefinition{ID: "duplicate"}, contract, duplicate, monotonicSnapshots()); !errors.Is(err, errCapacityDuplicateSession) {
		t.Fatalf("duplicate session error = %v", err)
	}
	if duplicate.closeWhileConnecting {
		t.Fatal("capacity endpoint quiesced while scheduled connects were still running")
	}
	early := &fakeCapacityEndpoint{terminateFirst: true}
	if _, err := runCapacityCase(context.Background(), capacityCaseDefinition{ID: "early"}, contract, early, monotonicSnapshots()); !errors.Is(err, errCapacityHoldDisconnect) {
		t.Fatalf("early termination error = %v", err)
	}
}

func TestBrowserCapacityProfilesFailClosed(t *testing.T) {
	for _, id := range []string{"CAP-TUNNEL-WT-WSS-1000", "CAP-TUNNEL-WT-QUIC-1000"} {
		definition, ok := lookupCapacityCase(id)
		if !ok {
			t.Fatalf("missing %s", id)
		}
		endpoint, err := openProductionCapacityEndpoint(context.Background(), definition, 1000)
		if endpoint != nil || !errors.Is(err, errBrowserCapacityWorkerUnavailable) {
			t.Fatalf("%s endpoint/error = %v/%v", id, endpoint, err)
		}
	}
}

type fakeCapacitySession struct {
	id         string
	done       chan struct{}
	closeOnce  sync.Once
	onClose    func()
	closeDelay time.Duration
}

func (session *fakeCapacitySession) ID() string                   { return session.id }
func (session *fakeCapacitySession) Termination() <-chan struct{} { return session.done }
func (*fakeCapacitySession) ProbeLiveness(context.Context) error  { return nil }
func (session *fakeCapacitySession) Close(ctx context.Context) error {
	if session.closeDelay > 0 {
		timer := time.NewTimer(session.closeDelay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	session.closeOnce.Do(func() {
		close(session.done)
		if session.onClose != nil {
			session.onClose()
		}
	})
	return nil
}

type fakeCapacityEndpoint struct {
	mu                   sync.Mutex
	connects             int
	disconnects          int
	closes               int
	duplicateID          bool
	terminateFirst       bool
	openedStreams        int
	closed               bool
	inflightConnects     int
	closeWhileConnecting bool
	connected            chan struct{}
	connectedOnce        sync.Once
	closeOrder           []string
	sessionCloseDelay    time.Duration
}

type fakeQuiescingCapacityEndpoint struct {
	*fakeCapacityEndpoint
	quiesced bool
}

func (endpoint *fakeQuiescingCapacityEndpoint) Quiesce(context.Context) error {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	endpoint.quiesced = true
	return nil
}

func (endpoint *fakeCapacityEndpoint) OpenStreamCapacity(ctx context.Context, streamsPerSession int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	endpoint.mu.Lock()
	endpoint.openedStreams = endpoint.connects * streamsPerSession
	endpoint.mu.Unlock()
	return nil
}

func (*fakeCapacityEndpoint) ResidualStreamCount() int { return 0 }

func (endpoint *fakeCapacityEndpoint) Connect(context.Context) (capacitySession, error) {
	endpoint.mu.Lock()
	endpoint.inflightConnects++
	endpoint.connects++
	ordinal := endpoint.connects
	endpoint.mu.Unlock()
	defer func() {
		endpoint.mu.Lock()
		endpoint.inflightConnects--
		endpoint.mu.Unlock()
	}()
	id := fmt.Sprintf("session-%d", ordinal)
	if endpoint.duplicateID {
		id = "duplicate"
	}
	session := &fakeCapacitySession{id: id, done: make(chan struct{}), closeDelay: endpoint.sessionCloseDelay, onClose: func() {
		endpoint.mu.Lock()
		endpoint.disconnects++
		endpoint.closeOrder = append(endpoint.closeOrder, "session")
		endpoint.mu.Unlock()
	}}
	if endpoint.connected != nil {
		endpoint.connectedOnce.Do(func() { close(endpoint.connected) })
	}
	if endpoint.terminateFirst && ordinal == 1 {
		go func() {
			time.Sleep(12 * time.Millisecond)
			session.closeOnce.Do(func() { close(session.done) })
		}()
	}
	return session, nil
}

func (endpoint *fakeCapacityEndpoint) Close(context.Context) error {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	if endpoint.closed {
		return nil
	}
	endpoint.closeWhileConnecting = endpoint.inflightConnects != 0
	endpoint.closed = true
	endpoint.closes++
	endpoint.closeOrder = append(endpoint.closeOrder, "endpoint")
	return nil
}

func monotonicSnapshots() resourceSnapshotFunc {
	var mu sync.Mutex
	var cpu uint64
	return func() (transporttest.ResourceSnapshot, error) {
		mu.Lock()
		defer mu.Unlock()
		cpu += uint64(time.Millisecond)
		return transporttest.ResourceSnapshot{At: time.Now(), RSSBytes: 1024, CPUNanoseconds: cpu, OpenFDs: 4, Goroutines: 4, Tasks: 4}, nil
	}
}
