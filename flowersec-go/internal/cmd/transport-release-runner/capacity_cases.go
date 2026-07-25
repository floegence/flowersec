package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/tunnelworkload"
)

var (
	errCapacityDuplicateSession         = errors.New("capacity workload returned a duplicate production session")
	errCapacityHoldDisconnect           = errors.New("capacity session disconnected during the hold phase")
	errCapacityWatchdog                 = errors.New("capacity workload exceeded its watchdog")
	errBrowserCapacityWorkerUnavailable = errors.New("browser capacity requires 1000 live Chromium WebTransport sessions")
)

const (
	capacityCleanupMaxGoroutineDelta = 64
	capacityCleanupMaxOpenFDDelta    = 16
	capacityCleanupMaxTaskDelta      = 16
)

type capacityContract struct {
	Sessions                    int
	StreamsPerSession           int
	Ramp                        time.Duration
	Hold                        time.Duration
	Cleanup                     time.Duration
	Watchdog                    time.Duration
	MaxRSS                      uint64
	MaxCPU                      time.Duration
	MaxOpenFDs                  int
	MaxGoroutines               int
	MaxTasks                    int
	ResourceScope               string
	CalibrationRSS              uint64
	CalibrationOpenFDs          int
	YamuxMaxFrameBytes          int
	YamuxMaxStreamReceiveBytes  int
	YamuxMaxSessionReceiveBytes int
	TunnelCopyBufferBytes       int
}

func productionCapacityContract() capacityContract {
	return capacityContract{
		Sessions: 1000, Ramp: 30 * time.Second, Hold: 60 * time.Second, Cleanup: 30 * time.Second,
		Watchdog: 120 * time.Second, MaxRSS: 1 << 30, MaxCPU: 120 * time.Second,
		MaxOpenFDs: 8192, MaxGoroutines: 40960, MaxTasks: 8192,
		ResourceScope: "go_runner",
	}
}

func productionBrowserCapacityContract() capacityContract {
	contract := productionCapacityContract()
	contract.MaxRSS = 3 << 30
	contract.MaxOpenFDs = 12288
	contract.ResourceScope = "go_runner_plus_chromium_process_tree"
	contract.CalibrationRSS = 2162716672
	contract.CalibrationOpenFDs = 9350
	return contract
}

func productionBrowserStreamCapacityContract() capacityContract {
	contract := productionBrowserCapacityContract()
	contract.Sessions = 100
	contract.StreamsPerSession = 128
	contract.Ramp = 60 * time.Second
	contract.MaxCPU = 240 * time.Second
	contract.MaxOpenFDs = 32768
	contract.Watchdog = contract.Ramp + contract.Hold + contract.Cleanup
	contract.CalibrationRSS = 0
	contract.CalibrationOpenFDs = 0
	return contract
}

func browserCapacityOperationDeadline(definition capacityCaseDefinition) time.Duration {
	if definition.Kind == capacityBrowserStream {
		return 60 * time.Second
	}
	return 30 * time.Second
}

func capacitySessionRamp(contract capacityContract) time.Duration {
	if contract.StreamsPerSession > 0 {
		return contract.Ramp / 4
	}
	return contract.Ramp
}

type capacityCaseKind uint8

const (
	capacityDirect capacityCaseKind = iota + 1
	capacityTunnel
	capacityBrowserTunnel
	capacityBrowserStream
)

type capacityCaseDefinition struct {
	ID              string
	Profile         string
	Kind            capacityCaseKind
	Carrier         carrier.Kind
	Topology        tunnelworkload.Topology
	BrowserTopology tunnelworkload.BrowserTopology
	BrowserDirect   bool
}

var frozenCapacityCases = []capacityCaseDefinition{
	{ID: "CAP-DIRECT-WSS-1000", Profile: "capacity-direct-wss-1000", Kind: capacityDirect, Carrier: carrier.KindWebSocket},
	{ID: "CAP-DIRECT-QUIC-1000", Profile: "capacity-direct-quic-1000", Kind: capacityDirect, Carrier: carrier.KindQUIC},
	{ID: "CAP-DIRECT-WT-1000", Profile: "capacity-direct-webtransport-1000", Kind: capacityDirect, Carrier: carrier.KindWebTransport},
	{ID: "CAP-TUNNEL-WT-WSS-1000", Profile: "capacity-tunnel-webtransport-wss-1000", Kind: capacityBrowserTunnel, BrowserTopology: tunnelworkload.BrowserTunnelWTWSS},
	{ID: "CAP-TUNNEL-WT-QUIC-1000", Profile: "capacity-tunnel-webtransport-quic-1000", Kind: capacityBrowserTunnel, BrowserTopology: tunnelworkload.BrowserTunnelWTQUIC},
	{ID: "CAP-STREAM-WT-DIRECT-100X128", Profile: "capacity-streams-webtransport-direct-100x128", Kind: capacityBrowserStream, BrowserDirect: true},
	{ID: "CAP-STREAM-WT-WSS-100X128", Profile: "capacity-streams-webtransport-wss-100x128", Kind: capacityBrowserStream, BrowserTopology: tunnelworkload.BrowserTunnelWTWSS},
	{ID: "CAP-STREAM-WT-QUIC-100X128", Profile: "capacity-streams-webtransport-quic-100x128", Kind: capacityBrowserStream, BrowserTopology: tunnelworkload.BrowserTunnelWTQUIC},
	{ID: "CAP-WW-1000", Profile: "capacity-tunnel-ww-1000", Kind: capacityTunnel, Topology: tunnelworkload.TopologyWW},
	{ID: "CAP-QQ-1000", Profile: "capacity-tunnel-qq-1000", Kind: capacityTunnel, Topology: tunnelworkload.TopologyQQ},
	{ID: "CAP-WQ-1000", Profile: "capacity-tunnel-wq-1000", Kind: capacityTunnel, Topology: tunnelworkload.TopologyWQ},
	{ID: "CAP-QW-1000", Profile: "capacity-tunnel-qw-1000", Kind: capacityTunnel, Topology: tunnelworkload.TopologyQW},
}

func capacityCaseRegistry() []capacityCaseDefinition {
	return append([]capacityCaseDefinition(nil), frozenCapacityCases...)
}

func lookupCapacityCase(id string) (capacityCaseDefinition, bool) {
	for _, definition := range frozenCapacityCases {
		if definition.ID == id {
			return definition, true
		}
	}
	return capacityCaseDefinition{}, false
}

type capacitySession interface {
	ID() string
	Termination() <-chan struct{}
	ProbeLiveness(context.Context) error
	Close(context.Context) error
}

type capacityEndpoint interface {
	Connect(context.Context) (capacitySession, error)
	Close(context.Context) error
}

type capacityStreamEndpoint interface {
	OpenStreamCapacity(context.Context, int) error
	ResidualStreamCount() int
}

type capacityQuiescingEndpoint interface {
	Quiesce(context.Context) error
}

type resourceSnapshotFunc func() (transportrelease.ResourceSnapshot, error)

type capacityCaseResult struct {
	Attempted          int
	Succeeded          int
	Failed             int
	UniqueActivePeak   int
	HoldDisconnects    int
	CleanupDisconnects int
	ResidualSessions   int
	CompletedStreams   int
	ActiveStreamPeak   int
	ResidualStreams    int
	LivenessSweeps     int
	LivenessFailures   int
	WatchdogTimeouts   int
	Trace              capacityTraceArtifact
	Metrics            rawMetricsArtifact
	Config             rawConfigArtifact
	Resource           caseResourceArtifact
}

type capacityTraceArtifact struct {
	SchemaVersion int                   `json:"schema_version"`
	Kind          string                `json:"kind"`
	Context       string                `json:"context"`
	Records       []capacityTraceRecord `json:"records"`
}

type capacityTraceRecord struct {
	Sequence             uint64 `json:"sequence"`
	AtNS                 int64  `json:"at_ns"`
	Event                string `json:"event"`
	Digest               string `json:"digest"`
	AttemptedSessions    int    `json:"attempted_sessions"`
	SucceededSessions    int    `json:"succeeded_sessions"`
	FailedSessions       int    `json:"failed_sessions"`
	ActiveSessions       int    `json:"active_sessions"`
	UniqueActiveSessions int    `json:"unique_active_sessions"`
	Disconnects          int    `json:"disconnects"`
	CompletedStreams     int    `json:"completed_streams,omitempty"`
	ActiveStreams        int    `json:"active_streams,omitempty"`
	ResidualStreams      int    `json:"residual_streams,omitempty"`
}

type caseResourceArtifact struct {
	SchemaVersion int                  `json:"schema_version"`
	Kind          string               `json:"kind"`
	Context       string               `json:"context"`
	Records       []caseResourceRecord `json:"records"`
}

type caseResourceRecord struct {
	Phase                string `json:"phase,omitempty"`
	AtNS                 int64  `json:"at_ns"`
	ActiveSessions       int    `json:"active_sessions,omitempty"`
	UniqueActiveSessions int    `json:"unique_active_sessions,omitempty"`
	RSSBytes             uint64 `json:"rss_bytes"`
	CPUNanoseconds       uint64 `json:"cpu_nanoseconds,omitempty"`
	OpenFDs              int    `json:"open_fds,omitempty"`
	Goroutines           int    `json:"goroutines"`
	Tasks                int    `json:"tasks,omitempty"`
	ResidualSessions     *int   `json:"residual_sessions,omitempty"`
	ResidualGoroutines   *int   `json:"residual_goroutines,omitempty"`
	ResidualOpenFDs      *int   `json:"residual_open_fds,omitempty"`
	ResidualTasks        *int   `json:"residual_tasks,omitempty"`
	ActiveStreams        int    `json:"active_streams,omitempty"`
	ResidualStreams      *int   `json:"residual_streams,omitempty"`
}

func runCapacityCase(ctx context.Context, definition capacityCaseDefinition, contract capacityContract, endpoint capacityEndpoint, capture resourceSnapshotFunc) (result capacityCaseResult, resultErr error) {
	if err := validateCapacityContract(contract); err != nil {
		return result, err
	}
	if endpoint == nil {
		return result, errors.New("capacity endpoint is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if capture == nil {
		capture = transportrelease.CaptureResourceSnapshot
	}
	base, err := capture()
	if err != nil {
		return result, fmt.Errorf("capture capacity resource baseline: %w", err)
	}
	started := time.Now()
	watchdogAt := started.Add(contract.Watchdog)
	sessions := make([]capacitySession, 0, contract.Sessions)
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), maxDuration(contract.Cleanup, time.Second))
		defer cancel()
		if context.Cause(ctx) != nil {
			resultErr = errors.Join(resultErr, endpoint.Close(cleanupCtx))
			for _, session := range sessions {
				_ = session.Close(cleanupCtx)
			}
			return
		}
		for _, session := range sessions {
			_ = session.Close(cleanupCtx)
		}
		resultErr = errors.Join(resultErr, endpoint.Close(cleanupCtx))
	}()

	type connectResult struct {
		session capacitySession
		err     error
	}
	connected := make(chan connectResult, contract.Sessions)
	rampCtx, cancelRamp := context.WithCancelCause(ctx)
	var rampWG sync.WaitGroup
	defer func() {
		cancelRamp(context.Canceled)
		rampWG.Wait()
		close(connected)
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		for unclaimed := range connected {
			if unclaimed.session != nil {
				resultErr = errors.Join(resultErr, unclaimed.session.Close(cleanupCtx))
			}
		}
	}()
	rampEnd := started.Add(contract.Ramp)
	sessionRamp := capacitySessionRamp(contract)
	sessionRampEnd := started.Add(sessionRamp)
	for ordinal := range contract.Sessions {
		due := started.Add(time.Duration(int64(sessionRamp) * int64(ordinal) / int64(contract.Sessions)))
		rampWG.Add(1)
		go func() {
			defer rampWG.Done()
			if waitErr := waitCapacityUntil(rampCtx, due, watchdogAt); waitErr != nil {
				connected <- connectResult{err: waitErr}
				return
			}
			connectCtx, cancel := context.WithDeadline(rampCtx, sessionRampEnd)
			defer cancel()
			session, connectErr := endpoint.Connect(connectCtx)
			connected <- connectResult{session: session, err: connectErr}
		}()
	}
	ids := make(map[string]struct{}, contract.Sessions)
	for result.Attempted < contract.Sessions {
		remaining := time.Until(sessionRampEnd)
		if remaining <= 0 {
			result.WatchdogTimeouts++
			return result, fmt.Errorf("%w: ramp did not establish %d sessions", errCapacityWatchdog, contract.Sessions)
		}
		timer := time.NewTimer(remaining)
		select {
		case connectedResult := <-connected:
			stopTimer(timer)
			result.Attempted++
			if connectedResult.err != nil || connectedResult.session == nil {
				result.Failed++
				return result, fmt.Errorf("capacity session %d connect: %w", result.Attempted, connectedResult.err)
			}
			if connectedResult.session.ID() == "" {
				return result, errors.New("capacity workload returned an empty production session ID")
			}
			if _, exists := ids[connectedResult.session.ID()]; exists {
				_ = connectedResult.session.Close(context.Background())
				return result, errCapacityDuplicateSession
			}
			ids[connectedResult.session.ID()] = struct{}{}
			sessions = append(sessions, connectedResult.session)
			result.Succeeded++
		case <-timer.C:
			result.WatchdogTimeouts++
			return result, fmt.Errorf("%w: ramp did not establish %d sessions", errCapacityWatchdog, contract.Sessions)
		case <-ctx.Done():
			stopTimer(timer)
			return result, context.Cause(ctx)
		}
	}
	cancelRamp(context.Canceled)
	rampWG.Wait()
	if err := waitCapacityUntil(ctx, sessionRampEnd, watchdogAt); err != nil {
		return result, err
	}
	result.UniqueActivePeak = len(ids)
	if contract.StreamsPerSession > 0 {
		streamEndpoint, ok := endpoint.(capacityStreamEndpoint)
		if !ok {
			return result, errors.New("stream capacity endpoint is unavailable")
		}
		streamCtx, cancel := context.WithDeadline(ctx, rampEnd)
		err := streamEndpoint.OpenStreamCapacity(streamCtx, contract.StreamsPerSession)
		cancel()
		if err != nil {
			return result, fmt.Errorf("open stream capacity workload: %w", err)
		}
		result.CompletedStreams = contract.Sessions * contract.StreamsPerSession
		result.ActiveStreamPeak = result.CompletedStreams
	}
	if err := waitCapacityUntil(ctx, rampEnd, watchdogAt); err != nil {
		return result, err
	}
	rampSnapshot, err := captureCapacityResource(capture, base, contract, "ramp", contract.Ramp, contract.Sessions, contract.Sessions)
	if err != nil {
		return result, err
	}

	terminated := make(chan string, len(sessions))
	for _, session := range sessions {
		go func() {
			<-session.Termination()
			terminated <- session.ID()
		}()
	}
	holdEnd := rampEnd.Add(contract.Hold)
	liveness := time.NewTicker(contract.Hold / 5)
	defer liveness.Stop()
	timer := time.NewTimer(time.Until(holdEnd))
	holdComplete := false
	for !holdComplete {
		select {
		case id := <-terminated:
			stopTimer(timer)
			result.HoldDisconnects++
			return result, fmt.Errorf("%w: %s", errCapacityHoldDisconnect, id)
		case <-liveness.C:
			probeTimeout := minDuration(5*time.Second, contract.Hold/10)
			probeCtx, cancelProbe := context.WithTimeout(ctx, probeTimeout)
			probeErr := probeCapacitySessions(probeCtx, sessions)
			cancelProbe()
			result.LivenessSweeps++
			if probeErr != nil {
				result.LivenessFailures++
				stopTimer(timer)
				return result, fmt.Errorf("capacity hold liveness sweep %d: %w", result.LivenessSweeps, probeErr)
			}
		case <-timer.C:
			holdComplete = true
		case <-ctx.Done():
			stopTimer(timer)
			return result, context.Cause(ctx)
		}
	}
	holdSnapshot, err := captureCapacityResource(capture, base, contract, "hold", contract.Ramp+contract.Hold, contract.Sessions, contract.Sessions)
	if err != nil {
		return result, err
	}

	cleanupEnd := holdEnd.Add(contract.Cleanup)
	cleanupCloseWindow := capacityCleanupCloseWindow(contract.Cleanup)
	closed := make(chan error, len(sessions))
	for ordinal, session := range sessions {
		due := holdEnd.Add(time.Duration(int64(cleanupCloseWindow) * int64(ordinal) / int64(contract.Sessions)))
		go func() {
			if waitErr := waitCapacityUntil(ctx, due, watchdogAt); waitErr != nil {
				closed <- waitErr
				return
			}
			closeCtx, cancel := context.WithDeadline(ctx, cleanupEnd)
			defer cancel()
			closed <- session.Close(closeCtx)
		}()
	}
	for range sessions {
		remaining := time.Until(cleanupEnd)
		if remaining <= 0 {
			result.WatchdogTimeouts++
			return result, fmt.Errorf("%w: cleanup did not complete", errCapacityWatchdog)
		}
		timer := time.NewTimer(remaining)
		select {
		case closeErr := <-closed:
			stopTimer(timer)
			if closeErr != nil {
				return result, fmt.Errorf("capacity session cleanup: %w", closeErr)
			}
			result.CleanupDisconnects++
		case <-timer.C:
			result.WatchdogTimeouts++
			return result, fmt.Errorf("%w: cleanup did not complete", errCapacityWatchdog)
		case <-ctx.Done():
			stopTimer(timer)
			return result, context.Cause(ctx)
		}
	}
	for _, session := range sessions {
		select {
		case <-session.Termination():
		default:
			result.ResidualSessions++
		}
	}
	if result.ResidualSessions != 0 {
		return result, fmt.Errorf("capacity cleanup left %d residual sessions", result.ResidualSessions)
	}
	if contract.StreamsPerSession > 0 {
		result.ResidualStreams = endpoint.(capacityStreamEndpoint).ResidualStreamCount()
		if result.ResidualStreams != 0 {
			return result, fmt.Errorf("capacity cleanup left %d residual streams", result.ResidualStreams)
		}
	}
	closeCtx, cancel := context.WithDeadline(ctx, cleanupEnd)
	var closeErr error
	if quiescing, ok := endpoint.(capacityQuiescingEndpoint); ok {
		closeErr = quiescing.Quiesce(closeCtx)
	} else {
		closeErr = endpoint.Close(closeCtx)
	}
	cancel()
	if closeErr != nil {
		return result, fmt.Errorf("quiesce capacity endpoint: %w", closeErr)
	}
	if err := waitCapacityUntil(ctx, cleanupEnd, watchdogAt); err != nil {
		return result, err
	}
	cleanupSnapshot, err := captureCapacityResource(capture, base, contract, "cleanup", contract.Watchdog, 0, contract.Sessions)
	if err != nil {
		return result, err
	}
	finalizeCtx, finalizeCancel := context.WithTimeout(context.Background(), maxDuration(contract.Cleanup, time.Second))
	finalizeErr := endpoint.Close(finalizeCtx)
	finalizeCancel()
	if finalizeErr != nil {
		return result, fmt.Errorf("finalize capacity endpoint: %w", finalizeErr)
	}
	cleanupSnapshot.ResidualSessions = intPointerValue(result.ResidualSessions)
	cleanupSnapshot.ResidualGoroutines = intPointerValue(nonnegativeDelta(cleanupSnapshot.Goroutines, base.Goroutines))
	cleanupSnapshot.ResidualOpenFDs = intPointerValue(nonnegativeDelta(cleanupSnapshot.OpenFDs, base.OpenFDs))
	cleanupSnapshot.ResidualTasks = intPointerValue(nonnegativeDelta(cleanupSnapshot.Tasks, base.Tasks))
	cleanupSnapshot.ResidualStreams = intPointerValue(result.ResidualStreams)
	if contract.StreamsPerSession > 0 {
		rampSnapshot.ActiveStreams = result.ActiveStreamPeak
		holdSnapshot.ActiveStreams = result.ActiveStreamPeak
	}
	if *cleanupSnapshot.ResidualGoroutines > capacityCleanupMaxGoroutineDelta || *cleanupSnapshot.ResidualOpenFDs > capacityCleanupMaxOpenFDDelta ||
		*cleanupSnapshot.ResidualTasks > capacityCleanupMaxTaskDelta {
		_ = writeCapacityDebugStack()
		return result, fmt.Errorf("capacity cleanup resource residual exceeded: goroutines=%d open_fds=%d tasks=%d",
			*cleanupSnapshot.ResidualGoroutines, *cleanupSnapshot.ResidualOpenFDs, *cleanupSnapshot.ResidualTasks)
	}
	contextName := "case " + definition.ID
	digest := releaseCaseExecutionID(contextName)
	result.Trace = capacityTraceArtifact{SchemaVersion: 1, Kind: "transport_trace", Context: contextName, Records: []capacityTraceRecord{
		capacityTrace(contract, digest, 1, "capacity_ramp_completed", contract.Ramp, result, contract.Sessions, 0),
		capacityTrace(contract, digest, 2, "capacity_hold_completed", contract.Ramp+contract.Hold, result, contract.Sessions, 0),
		capacityTrace(contract, digest, 3, "capacity_cleanup_completed", contract.Watchdog, result, 0, contract.Sessions),
	}}
	result.Metrics = rawMetricsArtifact{SchemaVersion: 1, Kind: "transport_metrics", Context: contextName, Records: []rawMetricRecord{
		{Name: "attempted_sessions", Value: float64(result.Attempted), Unit: "count"},
		{Name: "succeeded_sessions", Value: float64(result.Succeeded), Unit: "count"},
		{Name: "failed_sessions", Value: float64(result.Failed), Unit: "count"},
		{Name: "unique_active_peak", Value: float64(result.UniqueActivePeak), Unit: "count"},
		{Name: "hold_duration_ns", Value: float64(contract.Hold.Nanoseconds()), Unit: "nanoseconds"},
		{Name: "hold_disconnects", Value: float64(result.HoldDisconnects), Unit: "count"},
		{Name: "liveness_sweeps", Value: float64(result.LivenessSweeps), Unit: "count"},
		{Name: "liveness_failures", Value: float64(result.LivenessFailures), Unit: "count"},
		{Name: "cleanup_disconnects", Value: float64(result.CleanupDisconnects), Unit: "count"},
		{Name: "watchdog_timeouts", Value: float64(result.WatchdogTimeouts), Unit: "count"},
		{Name: "cleanup_residual_sessions", Value: float64(result.ResidualSessions), Unit: "count"},
	}}
	if contract.StreamsPerSession > 0 {
		result.Metrics.Records = append(result.Metrics.Records,
			rawMetricRecord{Name: "completed_streams", Value: float64(result.CompletedStreams), Unit: "count"},
			rawMetricRecord{Name: "active_stream_peak", Value: float64(result.ActiveStreamPeak), Unit: "count"},
			rawMetricRecord{Name: "cleanup_residual_streams", Value: float64(result.ResidualStreams), Unit: "count"},
		)
	}
	result.Config = rawConfigArtifact{SchemaVersion: 1, Kind: "transport_config", Context: contextName, Records: []rawConfigRecord{
		{Key: "sessions", Value: strconv.Itoa(contract.Sessions)},
		{Key: "ramp_duration_ns", Value: strconv.FormatInt(contract.Ramp.Nanoseconds(), 10)},
		{Key: "hold_duration_ns", Value: strconv.FormatInt(contract.Hold.Nanoseconds(), 10)},
		{Key: "liveness_sweep_count", Value: "4"},
		{Key: "liveness_sweep_period_ns", Value: strconv.FormatInt((contract.Hold / 5).Nanoseconds(), 10)},
		{Key: "cleanup_duration_ns", Value: strconv.FormatInt(contract.Cleanup.Nanoseconds(), 10)},
		{Key: "cleanup_close_window_ns", Value: strconv.FormatInt(cleanupCloseWindow.Nanoseconds(), 10)},
		{Key: "watchdog_duration_ns", Value: strconv.FormatInt(contract.Watchdog.Nanoseconds(), 10)},
		{Key: "watchdog", Value: "completed"},
		{Key: "resource_scope", Value: contract.ResourceScope},
		{Key: "max_rss_bytes", Value: strconv.FormatUint(contract.MaxRSS, 10)},
		{Key: "max_open_fds", Value: strconv.Itoa(contract.MaxOpenFDs)},
		{Key: "max_goroutines", Value: strconv.Itoa(contract.MaxGoroutines)},
		{Key: "max_tasks", Value: strconv.Itoa(contract.MaxTasks)},
	}}
	if contract.StreamsPerSession > 0 {
		result.Config.Records = append(result.Config.Records,
			rawConfigRecord{Key: "connections_per_session", Value: "1"},
			rawConfigRecord{Key: "streams_per_session", Value: strconv.Itoa(contract.StreamsPerSession)},
		)
	}
	if contract.CalibrationRSS != 0 || contract.CalibrationOpenFDs != 0 {
		result.Config.Records = append(result.Config.Records,
			rawConfigRecord{Key: "browser_calibration_rss_bytes", Value: strconv.FormatUint(contract.CalibrationRSS, 10)},
			rawConfigRecord{Key: "browser_calibration_open_fds", Value: strconv.Itoa(contract.CalibrationOpenFDs)},
		)
	}
	if contract.YamuxMaxFrameBytes != 0 || contract.YamuxMaxStreamReceiveBytes != 0 || contract.YamuxMaxSessionReceiveBytes != 0 {
		result.Config.Records = append(result.Config.Records,
			rawConfigRecord{Key: "yamux_max_frame_bytes", Value: strconv.Itoa(contract.YamuxMaxFrameBytes)},
			rawConfigRecord{Key: "yamux_max_stream_receive_bytes", Value: strconv.Itoa(contract.YamuxMaxStreamReceiveBytes)},
			rawConfigRecord{Key: "yamux_max_session_receive_bytes", Value: strconv.Itoa(contract.YamuxMaxSessionReceiveBytes)},
		)
	}
	if contract.TunnelCopyBufferBytes != 0 {
		result.Config.Records = append(result.Config.Records,
			rawConfigRecord{Key: "tunnel_copy_buffer_bytes", Value: strconv.Itoa(contract.TunnelCopyBufferBytes)},
		)
	}
	result.Resource = caseResourceArtifact{SchemaVersion: 1, Kind: "transport_resource", Context: contextName, Records: []caseResourceRecord{rampSnapshot, holdSnapshot, cleanupSnapshot}}
	return result, nil
}

func writeCapacityDebugStack() error {
	path := os.Getenv("FLOWERSEC_CAPACITY_DEBUG_STACK")
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("capacity debug stack path must be absolute and canonical")
	}
	buffer := make([]byte, 16<<20)
	count := runtime.Stack(buffer, true)
	return os.WriteFile(path, buffer[:count], 0o600)
}

func capacityCleanupCloseWindow(cleanup time.Duration) time.Duration {
	return cleanup * 2 / 3
}

func nonnegativeDelta(value, baseline int) int {
	if value <= baseline {
		return 0
	}
	return value - baseline
}

func validateCapacityContract(contract capacityContract) error {
	if contract.Sessions <= 0 || contract.StreamsPerSession < 0 || contract.Ramp <= 0 || contract.Hold <= 0 || contract.Cleanup <= 0 ||
		contract.Watchdog != contract.Ramp+contract.Hold+contract.Cleanup || contract.MaxRSS == 0 || contract.MaxCPU <= 0 ||
		contract.MaxOpenFDs <= 0 || contract.MaxGoroutines <= 0 || contract.MaxTasks <= 0 {
		return errors.New("capacity contract is incomplete or has a non-exact watchdog timeline")
	}
	return nil
}

func captureCapacityResource(capture resourceSnapshotFunc, base transportrelease.ResourceSnapshot, contract capacityContract, phase string, at time.Duration, active, unique int) (caseResourceRecord, error) {
	snapshot, err := capture()
	if err != nil {
		return caseResourceRecord{}, fmt.Errorf("capture capacity %s resources: %w", phase, err)
	}
	if snapshot.CPUNanoseconds < base.CPUNanoseconds {
		return caseResourceRecord{}, errors.New("capacity CPU counter moved backwards")
	}
	cpu := snapshot.CPUNanoseconds - base.CPUNanoseconds
	if snapshot.RSSBytes > contract.MaxRSS || cpu > uint64(contract.MaxCPU) || snapshot.OpenFDs > contract.MaxOpenFDs ||
		snapshot.Goroutines > contract.MaxGoroutines || snapshot.Tasks > contract.MaxTasks || snapshot.OpenFDs < 0 || snapshot.Tasks < 0 {
		return caseResourceRecord{}, fmt.Errorf("capacity %s resource limit exceeded: rss=%d/%d cpu_ns=%d/%d open_fds=%d/%d goroutines=%d/%d tasks=%d/%d",
			phase, snapshot.RSSBytes, contract.MaxRSS, cpu, contract.MaxCPU.Nanoseconds(), snapshot.OpenFDs, contract.MaxOpenFDs,
			snapshot.Goroutines, contract.MaxGoroutines, snapshot.Tasks, contract.MaxTasks)
	}
	return caseResourceRecord{Phase: phase, AtNS: at.Nanoseconds(), ActiveSessions: active, UniqueActiveSessions: unique,
		RSSBytes: snapshot.RSSBytes, CPUNanoseconds: cpu, OpenFDs: snapshot.OpenFDs, Goroutines: snapshot.Goroutines, Tasks: snapshot.Tasks}, nil
}

func capacityTrace(_ capacityContract, digest string, sequence uint64, event string, at time.Duration, result capacityCaseResult, active, disconnects int) capacityTraceRecord {
	activeStreams := result.ActiveStreamPeak
	if active == 0 {
		activeStreams = 0
	}
	return capacityTraceRecord{Sequence: sequence, AtNS: at.Nanoseconds(), Event: event, Digest: digest,
		AttemptedSessions: result.Attempted, SucceededSessions: result.Succeeded, FailedSessions: result.Failed,
		ActiveSessions: active, UniqueActiveSessions: result.UniqueActivePeak, Disconnects: disconnects,
		CompletedStreams: result.CompletedStreams, ActiveStreams: activeStreams, ResidualStreams: result.ResidualStreams}
}

func waitCapacityUntil(ctx context.Context, due, watchdog time.Time) error {
	if !due.Before(watchdog) && !due.Equal(watchdog) {
		return errCapacityWatchdog
	}
	remaining := time.Until(due)
	if remaining <= 0 {
		return nil
	}
	timer := time.NewTimer(remaining)
	defer stopTimer(timer)
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func stopTimer(timer *time.Timer) {
	if timer != nil && !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func maxDuration(left, right time.Duration) time.Duration {
	if left > right {
		return left
	}
	return right
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func probeCapacitySessions(ctx context.Context, sessions []capacitySession) error {
	results := make(chan error, len(sessions))
	var group sync.WaitGroup
	for _, session := range sessions {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := session.ProbeLiveness(ctx); err != nil {
				results <- fmt.Errorf("session %s: %w", session.ID(), err)
			}
		}()
	}
	group.Wait()
	close(results)
	for err := range results {
		return err
	}
	return nil
}

func openProductionCapacityEndpoint(ctx context.Context, definition capacityCaseDefinition, sessions int) (capacityEndpoint, error) {
	if sessions != productionCapacityContract().Sessions {
		return nil, errors.New("production capacity endpoint requires exactly 1000 sessions")
	}
	switch definition.Kind {
	case capacityDirect:
		endpoint, err := transportrelease.OpenProductDirectEndpoint(ctx, definition.Carrier)
		if err != nil {
			return nil, err
		}
		return &directCapacityEndpoint{endpoint: endpoint}, nil
	case capacityTunnel:
		endpoint, err := tunnelworkload.OpenCapacityEndpointAt(ctx, definition.Topology, "127.0.0.1", sessions)
		if err != nil {
			return nil, err
		}
		return &tunnelCapacityEndpoint{endpoint: endpoint}, nil
	case capacityBrowserTunnel:
		return nil, fmt.Errorf("%w: %s", errBrowserCapacityWorkerUnavailable, definition.BrowserTopology)
	default:
		return nil, errors.New("capacity case has no production topology")
	}
}

type directCapacityEndpoint struct {
	endpoint *transportrelease.ProductDirectEndpoint
}

func (endpoint *directCapacityEndpoint) Connect(ctx context.Context) (capacitySession, error) {
	pair, err := endpoint.endpoint.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &directCapacitySession{pair: pair, id: fmt.Sprintf("direct-%p", pair), termination: joinTermination(pair.Client.Termination(), pair.Server.Termination())}, nil
}

func (endpoint *directCapacityEndpoint) Close(context.Context) error {
	return endpoint.endpoint.Close()
}

type directCapacitySession struct {
	pair        *transportrelease.ProductDirectPair
	id          string
	termination <-chan struct{}
}

func (session *directCapacitySession) ID() string                   { return session.id }
func (session *directCapacitySession) Termination() <-chan struct{} { return session.termination }
func (session *directCapacitySession) ProbeLiveness(ctx context.Context) error {
	_, err := session.pair.Client.ProbeLiveness(ctx)
	return err
}
func (session *directCapacitySession) Close(ctx context.Context) error {
	closed := make(chan error, 1)
	go func() { closed <- session.pair.Close() }()
	select {
	case err := <-closed:
		return err
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

type tunnelCapacityEndpoint struct{ endpoint *tunnelworkload.Endpoint }

func (endpoint *tunnelCapacityEndpoint) Connect(ctx context.Context) (capacitySession, error) {
	pair, err := endpoint.endpoint.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &tunnelCapacitySession{pair: pair, id: fmt.Sprintf("tunnel-%p", pair), termination: joinTermination(pair.Client.Termination(), pair.Server.Termination())}, nil
}

func (endpoint *tunnelCapacityEndpoint) Close(ctx context.Context) error {
	return endpoint.endpoint.Close(ctx)
}

type tunnelCapacitySession struct {
	pair        *tunnelworkload.Pair
	id          string
	termination <-chan struct{}
}

func (session *tunnelCapacitySession) ID() string                   { return session.id }
func (session *tunnelCapacitySession) Termination() <-chan struct{} { return session.termination }
func (session *tunnelCapacitySession) ProbeLiveness(ctx context.Context) error {
	_, err := session.pair.Client.ProbeLiveness(ctx)
	return err
}
func (session *tunnelCapacitySession) Close(ctx context.Context) error {
	return session.pair.Close(ctx)
}

func joinTermination(left, right <-chan struct{}) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		select {
		case <-left:
		case <-right:
		}
		close(done)
	}()
	return done
}
