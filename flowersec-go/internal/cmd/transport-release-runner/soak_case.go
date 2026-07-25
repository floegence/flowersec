package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
)

var (
	errSoakEngineUnavailable = errors.New("production soak migration engine is unavailable")
	errSoakMigrationUnproven = errors.New("soak cycle did not prove a native carrier migration")
)

type soakContract struct {
	Duration               time.Duration
	CyclePeriod            time.Duration
	Cycles                 int
	Reconnects             int
	Migrations             int
	MaxRSSGrowth           uint64
	MaxGoroutineGrowth     int
	MaxOpenFDGrowth        int
	MaxTaskGrowth          int
	ResidualSessions       int
	ResidualGoroutines     int
	ResidualOpenFDs        int
	ResidualTasks          int
	RequireNetworkEvidence bool
}

func productionSoakContract() soakContract {
	return soakContract{
		Duration: 5 * time.Minute, CyclePeriod: time.Minute, Cycles: 5, Reconnects: 5, Migrations: 5,
		MaxRSSGrowth: 64 << 20, MaxGoroutineGrowth: 64, MaxOpenFDGrowth: 16, MaxTaskGrowth: 64,
		RequireNetworkEvidence: true,
	}
}

type soakCycleObservation struct {
	FaultApplied   bool
	Reconnected    bool
	Migrated       bool
	ConnectionID   string
	LocalAddress   string
	RemoteAddress  string
	NativeStreamID int64
	QLOG           []byte
	PCAP           []byte
}

type soakResiduals struct {
	Sessions   int
	Goroutines int
	OpenFDs    int
	Tasks      int
}

type soakCycleEngine interface {
	RunCycle(context.Context, int) (soakCycleObservation, error)
	Close(context.Context) error
	Residuals() (soakResiduals, error)
}

type soakResourceObservation struct {
	Snapshot transportrelease.ResourceSnapshot
	AtNS     int64
}

type soakCaseResult struct {
	FaultCycles      int
	Reconnects       int
	Migrations       int
	RSSGrowth        uint64
	GoroutineGrowth  int
	OpenFDGrowth     int
	TaskGrowth       int
	RSSPeak          uint64
	GoroutinePeak    int
	OpenFDPeak       int
	TaskPeak         int
	Residuals        soakResiduals
	WatchdogTimeouts int
	Trace            soakTraceArtifact
	Metrics          rawMetricsArtifact
	Config           rawConfigArtifact
	Resource         caseResourceArtifact
	QLOG             []byte
	PCAP             []byte
	Sources          []soakCycleSource
}

type soakCycleSource struct {
	Ordinal      int
	ConnectionID string
	QLOG         []byte
	PCAP         []byte
}

type soakTraceArtifact struct {
	SchemaVersion int               `json:"schema_version"`
	Kind          string            `json:"kind"`
	Context       string            `json:"context"`
	Records       []soakTraceRecord `json:"records"`
}

type soakTraceRecord struct {
	Sequence       uint64 `json:"sequence"`
	AtNS           int64  `json:"at_ns"`
	Event          string `json:"event"`
	Digest         string `json:"digest"`
	ConnectionID   string `json:"connection_id"`
	LocalAddress   string `json:"local_address,omitempty"`
	RemoteAddress  string `json:"remote_address,omitempty"`
	NativeStreamID *int64 `json:"native_stream_id,omitempty"`
	QLOGSourceID   string `json:"qlog_source_id,omitempty"`
	PCAPSourceID   string `json:"pcap_source_id,omitempty"`
}

func runProductionSoakCase(ctx context.Context, engine soakCycleEngine) (soakCaseResult, error) {
	if engine == nil {
		return soakCaseResult{}, errSoakEngineUnavailable
	}
	return runSoakCase(ctx, productionSoakContract(), engine, transportrelease.CaptureResourceSnapshot)
}

// runNativeProductionSoakCase owns the production raw-QUIC reconnect and path
// migration engine. The public Flowersec session intentionally stays opaque;
// release evidence uses this internal carrier boundary to exercise Migrate.
func runNativeProductionSoakCase(ctx context.Context) (soakCaseResult, error) {
	engine, err := newRawQUICSoakEvidenceEngine(ctx)
	if err != nil {
		return soakCaseResult{}, err
	}
	return runProductionSoakCase(ctx, engine)
}

func runRegisteredSoakCase(ctx context.Context, destination *artifactDestination, definition releaseCaseDefinition) (releaseCaseResult, error) {
	if definition.ID != "CAP-SOAK-5M" || definition.Profile != "five-minute-weaknet-soak-v1" {
		return releaseCaseResult{}, errors.New("unknown production soak case")
	}
	started := time.Now()
	result, err := runNativeProductionSoakCase(ctx)
	if err != nil {
		return releaseCaseResult{}, err
	}
	artifacts, err := writeSoakCaseArtifacts(destination, definition, result)
	if err != nil {
		return releaseCaseResult{}, err
	}
	elapsed := time.Since(started)
	return releaseCaseResult{ID: definition.ID, Profile: definition.Profile, Status: "pass",
		CompletedOperations: result.Migrations, ElapsedNanoseconds: elapsed.Nanoseconds(),
		Artifacts: artifacts.Artifacts, RawSources: artifacts.RawSources}, nil
}

type soakWrittenArtifacts struct {
	Artifacts  []releaseArtifact
	RawSources []releaseRawSource
}

func writeSoakCaseArtifacts(destination *artifactDestination, definition releaseCaseDefinition, result soakCaseResult) (soakWrittenArtifacts, error) {
	if destination == nil || len(result.QLOG) == 0 || !validClassicPCAP(result.PCAP) ||
		result.Migrations != productionSoakContract().Cycles || len(result.Sources) != productionSoakContract().Cycles {
		return soakWrittenArtifacts{}, errors.New("production soak artifacts require the complete measured network run")
	}
	directory := filepath.Join(destination.root.path, definition.artifactLabel())
	if err := os.Mkdir(directory, 0o700); err != nil {
		return soakWrittenArtifacts{}, err
	}
	rawDirectory := filepath.Join(directory, "raw")
	if err := os.Mkdir(rawDirectory, 0o700); err != nil {
		return soakWrittenArtifacts{}, err
	}
	rawSources := make([]releaseRawSource, 0, len(result.Sources)*2)
	for _, source := range result.Sources {
		values := []struct {
			id, kind, name string
			data           []byte
		}{
			{fmt.Sprintf("qlog-%03d", source.Ordinal), "qlog", fmt.Sprintf("cycle-%03d.sqlog", source.Ordinal), source.QLOG},
			{fmt.Sprintf("pcap-%03d", source.Ordinal), "pcap", fmt.Sprintf("cycle-%03d.pcap", source.Ordinal), source.PCAP},
		}
		for _, value := range values {
			written, err := writeRawCaseArtifactBytes(destination, filepath.Join(rawDirectory, value.name), value.kind, value.data)
			if err != nil {
				return soakWrittenArtifacts{}, err
			}
			rawSources = append(rawSources, releaseRawSource{ID: value.id, Kind: value.kind, Path: written.Path, SHA256: written.SHA256, SizeBytes: written.SizeBytes})
		}
	}
	trace, err := writeRawCaseArtifact(destination, filepath.Join(directory, "trace.json"), "trace", result.Trace)
	if err != nil {
		return soakWrittenArtifacts{}, err
	}
	qlogAttribution, err := buildSoakQLOGAttribution(result.Trace.Context, result.Sources)
	if err != nil {
		return soakWrittenArtifacts{}, err
	}
	qlog, err := writeRawCaseArtifact(destination, filepath.Join(directory, "qlog.qlog"), "qlog", qlogAttribution)
	if err != nil {
		return soakWrittenArtifacts{}, err
	}
	pcapAttribution, err := buildSoakPCAPAttribution(result.Trace.Context, result.Sources)
	if err != nil {
		return soakWrittenArtifacts{}, err
	}
	pcap, err := writeRawCaseArtifact(destination, filepath.Join(directory, "pcap.pcap"), "pcap", pcapAttribution)
	if err != nil {
		return soakWrittenArtifacts{}, err
	}
	metrics, err := writeRawCaseArtifact(destination, filepath.Join(directory, "metrics.json"), "metrics", result.Metrics)
	if err != nil {
		return soakWrittenArtifacts{}, err
	}
	resource, err := writeRawCaseArtifact(destination, filepath.Join(directory, "resource.json"), "resource", result.Resource)
	if err != nil {
		return soakWrittenArtifacts{}, err
	}
	result.Config.Records = append(result.Config.Records,
		rawConfigRecord{Key: "trace_sha256", Value: trace.SHA256},
		rawConfigRecord{Key: "qlog_sha256", Value: qlog.SHA256},
		rawConfigRecord{Key: "pcap_sha256", Value: pcap.SHA256},
		rawConfigRecord{Key: "metrics_sha256", Value: metrics.SHA256},
		rawConfigRecord{Key: "resource_sha256", Value: resource.SHA256},
	)
	config, err := writeRawCaseArtifact(destination, filepath.Join(directory, "config.json"), "config", result.Config)
	if err != nil {
		return soakWrittenArtifacts{}, err
	}
	return soakWrittenArtifacts{Artifacts: []releaseArtifact{trace, qlog, pcap, metrics, resource, config}, RawSources: rawSources}, nil
}

func runSoakCase(ctx context.Context, contract soakContract, engine soakCycleEngine, capture resourceSnapshotFunc) (result soakCaseResult, resultErr error) {
	if err := validateSoakContract(contract); err != nil {
		return result, err
	}
	if engine == nil {
		return result, errSoakEngineUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if capture == nil {
		capture = transportrelease.CaptureResourceSnapshot
	}
	startSnapshot, err := capture()
	if err != nil {
		return result, fmt.Errorf("capture soak start resources: %w", err)
	}
	started := time.Now()
	contextName := "case CAP-SOAK-5M"
	digest := releaseCaseExecutionID(contextName)
	result.Trace = soakTraceArtifact{SchemaVersion: 1, Kind: "transport_trace", Context: contextName,
		Records: []soakTraceRecord{{Sequence: 1, AtNS: 0, Event: "soak_started", Digest: digest}}}
	resourceSeries := []soakResourceObservation{{Snapshot: startSnapshot, AtNS: 0}}
	connectionIDs := make(map[string]struct{}, contract.Cycles)
	closed := false
	defer func() {
		if closed {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, engine.Close(cleanupCtx))
	}()
	for ordinal := 1; ordinal <= contract.Cycles; ordinal++ {
		cycleEnd := started.Add(time.Duration(ordinal) * contract.CyclePeriod)
		cycleCtx, cancel := context.WithDeadline(ctx, cycleEnd)
		observation, cycleErr := engine.RunCycle(cycleCtx, ordinal)
		cancel()
		if cycleErr != nil {
			if errors.Is(cycleErr, context.DeadlineExceeded) {
				result.WatchdogTimeouts++
			}
			return result, fmt.Errorf("soak cycle %d: %w", ordinal, cycleErr)
		}
		if !observation.FaultApplied {
			return result, fmt.Errorf("soak cycle %d did not prove its weak-network fault", ordinal)
		}
		if !observation.Reconnected {
			return result, fmt.Errorf("soak cycle %d did not prove reconnect", ordinal)
		}
		if !observation.Migrated {
			return result, fmt.Errorf("%w: cycle %d", errSoakMigrationUnproven, ordinal)
		}
		if contract.RequireNetworkEvidence {
			if observation.ConnectionID == "" || observation.LocalAddress == "" || observation.RemoteAddress == "" ||
				observation.NativeStreamID < 0 || len(observation.QLOG) == 0 || !validClassicPCAP(observation.PCAP) {
				return result, fmt.Errorf("soak cycle %d did not produce complete native qlog/pcap/path evidence", ordinal)
			}
			qlogConnectionID, streamIDs, inspectErr := inspectNativeQLOG(observation.QLOG)
			if inspectErr != nil || qlogConnectionID != observation.ConnectionID {
				return result, fmt.Errorf("soak cycle %d qlog connection binding: %w", ordinal, errors.Join(inspectErr, errors.New("connection ID mismatch")))
			}
			if _, exists := streamIDs[observation.NativeStreamID]; !exists {
				return result, fmt.Errorf("soak cycle %d native stream is absent from qlog", ordinal)
			}
			if _, duplicate := connectionIDs[observation.ConnectionID]; duplicate {
				return result, fmt.Errorf("soak cycle %d reused QUIC connection ID %s", ordinal, observation.ConnectionID)
			}
			connectionIDs[observation.ConnectionID] = struct{}{}
			result.QLOG = append(result.QLOG, observation.QLOG...)
			result.PCAP, err = appendClassicPCAP(result.PCAP, observation.PCAP)
			if err != nil {
				return result, fmt.Errorf("soak cycle %d pcap series: %w", ordinal, err)
			}
			result.Sources = append(result.Sources, soakCycleSource{Ordinal: ordinal, ConnectionID: observation.ConnectionID,
				QLOG: append([]byte(nil), observation.QLOG...), PCAP: append([]byte(nil), observation.PCAP...)})
		}
		if err := waitCapacityUntil(ctx, cycleEnd, started.Add(contract.Duration)); err != nil {
			if errors.Is(err, errCapacityWatchdog) || errors.Is(err, context.DeadlineExceeded) {
				result.WatchdogTimeouts++
			}
			return result, err
		}
		result.FaultCycles++
		result.Reconnects++
		result.Migrations++
		cycleAt := time.Since(started).Nanoseconds()
		cycleSnapshot, snapshotErr := capture()
		if snapshotErr != nil {
			return result, fmt.Errorf("capture soak cycle %d resources: %w", ordinal, snapshotErr)
		}
		resourceAt, timestampErr := resourceSnapshotElapsedNS(startSnapshot, cycleSnapshot)
		if timestampErr != nil {
			return result, fmt.Errorf("capture soak cycle %d timestamp: %w", ordinal, timestampErr)
		}
		resourceSeries = append(resourceSeries, soakResourceObservation{Snapshot: cycleSnapshot, AtNS: resourceAt})
		streamID := observation.NativeStreamID
		result.Trace.Records = append(result.Trace.Records, soakTraceRecord{
			Sequence: uint64(len(result.Trace.Records) + 1), AtNS: cycleAt,
			Event: "fault_cycle_completed", Digest: digest, ConnectionID: observation.ConnectionID,
			LocalAddress: observation.LocalAddress, RemoteAddress: observation.RemoteAddress, NativeStreamID: &streamID,
			QLOGSourceID: fmt.Sprintf("qlog-%03d", ordinal), PCAPSourceID: fmt.Sprintf("pcap-%03d", ordinal),
		})
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	closeErr := engine.Close(cleanupCtx)
	cancel()
	closed = true
	if closeErr != nil {
		return result, fmt.Errorf("close soak engine: %w", closeErr)
	}
	result.Residuals, err = engine.Residuals()
	if err != nil {
		return result, fmt.Errorf("capture soak engine residuals: %w", err)
	}
	finishSnapshot, err := capture()
	if err != nil {
		return result, fmt.Errorf("capture soak end resources: %w", err)
	}
	finishResourceAt, err := resourceSnapshotElapsedNS(startSnapshot, finishSnapshot)
	if err != nil {
		return result, fmt.Errorf("capture soak end timestamp: %w", err)
	}
	completedAt := time.Since(started).Nanoseconds()
	resourceSeries = append(resourceSeries, soakResourceObservation{Snapshot: finishSnapshot, AtNS: finishResourceAt})
	if err := completeSoakResources(&result, contract, resourceSeries); err != nil {
		return result, err
	}
	result.Trace.Records = append(result.Trace.Records, soakTraceRecord{
		Sequence: uint64(len(result.Trace.Records) + 1), AtNS: completedAt, Event: "soak_completed", Digest: digest,
	})
	result.Metrics = rawMetricsArtifact{SchemaVersion: 1, Kind: "transport_metrics", Context: contextName, Records: []rawMetricRecord{
		{Name: "duration_ns", Value: float64(contract.Duration.Nanoseconds()), Unit: "nanoseconds"},
		{Name: "fault_cycle_count", Value: float64(result.FaultCycles), Unit: "count"},
		{Name: "reconnect_count", Value: float64(result.Reconnects), Unit: "count"},
		{Name: "migration_count", Value: float64(result.Migrations), Unit: "count"},
		{Name: "rss_growth_bytes", Value: float64(result.RSSGrowth), Unit: "bytes"},
		{Name: "goroutine_growth", Value: float64(result.GoroutineGrowth), Unit: "count"},
		{Name: "open_fd_growth", Value: float64(result.OpenFDGrowth), Unit: "count"},
		{Name: "task_growth", Value: float64(result.TaskGrowth), Unit: "count"},
		{Name: "rss_peak_bytes", Value: float64(result.RSSPeak), Unit: "bytes"},
		{Name: "goroutine_peak", Value: float64(result.GoroutinePeak), Unit: "count"},
		{Name: "open_fd_peak", Value: float64(result.OpenFDPeak), Unit: "count"},
		{Name: "task_peak", Value: float64(result.TaskPeak), Unit: "count"},
		{Name: "residual_sessions", Value: float64(result.Residuals.Sessions), Unit: "count"},
		{Name: "residual_goroutines", Value: float64(result.Residuals.Goroutines), Unit: "count"},
		{Name: "residual_open_fds", Value: float64(result.Residuals.OpenFDs), Unit: "count"},
		{Name: "residual_tasks", Value: float64(result.Residuals.Tasks), Unit: "count"},
		{Name: "watchdog_timeouts", Value: float64(result.WatchdogTimeouts), Unit: "count"},
	}}
	result.Config = rawConfigArtifact{SchemaVersion: 1, Kind: "transport_config", Context: contextName, Records: []rawConfigRecord{
		{Key: "profile", Value: "five-minute-weaknet-soak-v1"},
		{Key: "duration_ns", Value: strconv.FormatInt(contract.Duration.Nanoseconds(), 10)},
		{Key: "fault_cycle_period_ns", Value: strconv.FormatInt(contract.CyclePeriod.Nanoseconds(), 10)},
		{Key: "fault_cycle_count", Value: strconv.Itoa(contract.Cycles)},
		{Key: "reconnect_count", Value: strconv.Itoa(contract.Reconnects)},
		{Key: "migration_count", Value: strconv.Itoa(contract.Migrations)},
		{Key: "watchdog", Value: "completed"},
	}}
	result.Resource = caseResourceArtifact{SchemaVersion: 1, Kind: "transport_resource", Context: contextName,
		Records: make([]caseResourceRecord, 0, len(resourceSeries))}
	for index, observation := range resourceSeries {
		phase := "soak_start"
		if index > 0 && index <= contract.Cycles {
			phase = fmt.Sprintf("soak_cycle_%03d", index)
		} else if index == len(resourceSeries)-1 {
			phase = "soak_end"
		}
		snapshot := observation.Snapshot
		record := caseResourceRecord{Phase: phase, AtNS: observation.AtNS, RSSBytes: snapshot.RSSBytes, OpenFDs: snapshot.OpenFDs, Goroutines: snapshot.Goroutines, Tasks: snapshot.Tasks}
		if phase == "soak_end" {
			record.ResidualSessions = intPointerValue(result.Residuals.Sessions)
			record.ResidualGoroutines = intPointerValue(result.Residuals.Goroutines)
			record.ResidualOpenFDs = intPointerValue(result.Residuals.OpenFDs)
			record.ResidualTasks = intPointerValue(result.Residuals.Tasks)
		}
		result.Resource.Records = append(result.Resource.Records, record)
	}
	return result, nil
}

func validateSoakContract(contract soakContract) error {
	if contract.Duration <= 0 || contract.CyclePeriod <= 0 || contract.Cycles <= 0 ||
		contract.Duration != time.Duration(contract.Cycles)*contract.CyclePeriod || contract.Reconnects != contract.Cycles || contract.Migrations != contract.Cycles ||
		contract.MaxRSSGrowth == 0 || contract.MaxGoroutineGrowth < 0 || contract.MaxOpenFDGrowth < 0 || contract.MaxTaskGrowth < 0 ||
		contract.ResidualSessions < 0 || contract.ResidualGoroutines < 0 || contract.ResidualOpenFDs < 0 || contract.ResidualTasks < 0 {
		return errors.New("soak contract is incomplete or internally inconsistent")
	}
	return nil
}

func completeSoakResources(result *soakCaseResult, contract soakContract, series []soakResourceObservation) error {
	if len(series) != contract.Cycles+2 {
		return fmt.Errorf("soak resource series has %d samples, want %d", len(series), contract.Cycles+2)
	}
	if series[0].AtNS != 0 {
		return errors.New("soak resource series must start at zero")
	}
	for index := 1; index < len(series); index++ {
		if series[index].AtNS <= series[index-1].AtNS {
			return errors.New("soak resource snapshot timestamps are not strictly increasing")
		}
	}
	start, finish := series[0].Snapshot, series[len(series)-1].Snapshot
	result.RSSGrowth = positiveUint64Delta(finish.RSSBytes, start.RSSBytes)
	result.GoroutineGrowth = positiveIntDelta(finish.Goroutines, start.Goroutines)
	result.OpenFDGrowth = positiveIntDelta(finish.OpenFDs, start.OpenFDs)
	result.TaskGrowth = positiveIntDelta(finish.Tasks, start.Tasks)
	for _, observation := range series {
		sample := observation.Snapshot
		result.RSSPeak = max(result.RSSPeak, sample.RSSBytes)
		result.GoroutinePeak = max(result.GoroutinePeak, sample.Goroutines)
		result.OpenFDPeak = max(result.OpenFDPeak, sample.OpenFDs)
		result.TaskPeak = max(result.TaskPeak, sample.Tasks)
	}
	if result.RSSGrowth > contract.MaxRSSGrowth || result.GoroutineGrowth > contract.MaxGoroutineGrowth ||
		result.OpenFDGrowth > contract.MaxOpenFDGrowth || result.TaskGrowth > contract.MaxTaskGrowth {
		return errors.New("soak resource growth exceeded the frozen hourly limit")
	}
	if result.Residuals != (soakResiduals{Sessions: contract.ResidualSessions, Goroutines: contract.ResidualGoroutines, OpenFDs: contract.ResidualOpenFDs, Tasks: contract.ResidualTasks}) {
		return fmt.Errorf("soak cleanup residuals = %+v, want the frozen zero-residual contract", result.Residuals)
	}
	return nil
}

func resourceSnapshotElapsedNS(start, observed transportrelease.ResourceSnapshot) (int64, error) {
	if start.At.IsZero() || observed.At.IsZero() || !observed.At.After(start.At) {
		return 0, errors.New("resource snapshot has an invalid measured timestamp")
	}
	return observed.At.Sub(start.At).Nanoseconds(), nil
}

func positiveUint64Delta(finish, start uint64) uint64 {
	if finish <= start {
		return 0
	}
	return finish - start
}

func positiveIntDelta(finish, start int) int {
	if finish <= start {
		return 0
	}
	return finish - start
}

func appendClassicPCAP(existing, next []byte) ([]byte, error) {
	if !validClassicPCAP(next) {
		return nil, errors.New("invalid classic pcap")
	}
	if len(existing) == 0 {
		return append([]byte(nil), next...), nil
	}
	if !validClassicPCAP(existing) || !bytes.Equal(existing[:24], next[:24]) {
		return nil, errors.New("pcap global headers differ")
	}
	return append(existing, next[24:]...), nil
}

func intPointerValue(value int) *int { return &value }

type rawQUICSoakEngine struct {
	listener  *rawquic.Listener
	clientTLS *tls.Config

	mu               sync.Mutex
	client           *rawquic.Session
	server           *rawquic.Session
	closed           bool
	captureEvidence  bool
	resourceStart    transportrelease.ResourceSnapshot
	resourceFinish   transportrelease.ResourceSnapshot
	resourceErr      error
	resourceFinished bool
}

func newRawQUICSoakEngine(ctx context.Context) (*rawQUICSoakEngine, error) {
	return newRawQUICSoakEngineWithEvidence(ctx, false)
}

func newRawQUICSoakEvidenceEngine(ctx context.Context) (*rawQUICSoakEngine, error) {
	return newRawQUICSoakEngineWithEvidence(ctx, true)
}

func newRawQUICSoakEngineWithEvidence(ctx context.Context, captureEvidence bool) (*rawQUICSoakEngine, error) {
	resourceStart, err := transportrelease.CaptureResourceSnapshot()
	if err != nil {
		return nil, fmt.Errorf("capture raw QUIC soak baseline: %w", err)
	}
	serverTLS, clientTLS, err := soakTLS()
	if err != nil {
		return nil, err
	}
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS, rawquic.DefaultLimits())
	if err != nil {
		return nil, err
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			_ = listener.Close()
			return nil, context.Cause(ctx)
		default:
		}
	}
	return &rawQUICSoakEngine{listener: listener, clientTLS: clientTLS, captureEvidence: captureEvidence, resourceStart: resourceStart}, nil
}

func (engine *rawQUICSoakEngine) RunCycle(ctx context.Context, ordinal int) (soakCycleObservation, error) {
	if ordinal < 1 {
		return soakCycleObservation{}, errors.New("soak cycle ordinal must be positive")
	}
	var qlogCapture *nativeQLOGCapture
	var packetCapture *packetCapture
	var captureDirectory string
	captureFinished := false
	if engine.captureEvidence {
		var err error
		qlogCapture, err = startNativeQLOGCapture()
		if err != nil {
			return soakCycleObservation{}, err
		}
		captureDirectory, err = os.MkdirTemp("", "flowersec-soak-pcap-")
		if err != nil {
			_, _, _ = qlogCapture.finish(nil)
			return soakCycleObservation{}, err
		}
		defer os.RemoveAll(captureDirectory)
		packetCapture, err = startPacketCapture(ctx, "", "lo", filepath.Join(captureDirectory, "traffic.pcap"))
		if err != nil {
			_, _, _ = qlogCapture.finish(nil)
			return soakCycleObservation{}, err
		}
		defer func() {
			if captureFinished {
				return
			}
			_, _, _ = qlogCapture.finish(nil)
			_ = packetCapture.Stop()
		}()
	}
	engine.mu.Lock()
	if engine.closed {
		engine.mu.Unlock()
		return soakCycleObservation{}, errors.New("raw QUIC soak engine is closed")
	}
	oldClient, oldServer := engine.client, engine.server
	engine.client, engine.server = nil, nil
	engine.mu.Unlock()
	if oldClient == nil || oldServer == nil {
		var connectErr error
		oldClient, oldServer, connectErr = engine.connectPair(ctx)
		if connectErr != nil {
			return soakCycleObservation{}, fmt.Errorf("cycle %d baseline connection: %w", ordinal, connectErr)
		}
		if _, err := rawQUICSoakRoundTrip(ctx, oldClient, oldServer, 0); err != nil {
			_ = oldClient.Close()
			_ = oldServer.Close()
			return soakCycleObservation{}, fmt.Errorf("cycle %d baseline round trip: %w", ordinal, err)
		}
	}
	// Closing both ends is an actual transport outage. The next connection and
	// its migrated path must be newly established; no counter is predeclared.
	faultApplied := true
	if oldClient != nil {
		if err := oldClient.Close(); err != nil {
			return soakCycleObservation{}, fmt.Errorf("cycle %d client outage: %w", ordinal, err)
		}
	}
	if oldServer != nil {
		if err := oldServer.Close(); err != nil {
			return soakCycleObservation{}, fmt.Errorf("cycle %d server outage: %w", ordinal, err)
		}
	}
	client, server, err := engine.connectPair(ctx)
	if err != nil {
		return soakCycleObservation{}, fmt.Errorf("cycle %d reconnect: %w", ordinal, err)
	}
	if _, err := rawQUICSoakRoundTrip(ctx, client, server, ordinal); err != nil {
		_ = client.Close()
		_ = server.Close()
		return soakCycleObservation{}, fmt.Errorf("cycle %d pre-migration round trip: %w", ordinal, err)
	}
	path, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		_ = client.Close()
		_ = server.Close()
		return soakCycleObservation{}, err
	}
	if err := client.Migrate(ctx, path); err != nil {
		_ = client.Close()
		_ = server.Close()
		return soakCycleObservation{}, fmt.Errorf("cycle %d native migration: %w", ordinal, err)
	}
	streamID, err := rawQUICSoakRoundTrip(ctx, client, server, ordinal)
	if err != nil {
		_ = client.Close()
		_ = server.Close()
		return soakCycleObservation{}, fmt.Errorf("cycle %d post-migration round trip: %w", ordinal, err)
	}
	engine.mu.Lock()
	if engine.closed {
		engine.mu.Unlock()
		_ = client.Close()
		_ = server.Close()
		return soakCycleObservation{}, errors.New("raw QUIC soak engine closed during cycle")
	}
	engine.client, engine.server = client, server
	engine.mu.Unlock()
	observation := soakCycleObservation{FaultApplied: faultApplied, Reconnected: true, Migrated: true,
		LocalAddress: client.LocalAddr().String(), RemoteAddress: client.RemoteAddr().String(), NativeStreamID: streamID}
	if engine.captureEvidence {
		qlog, connectionID, qlogErr := qlogCapture.finish([]int64{streamID})
		captureErr := packetCapture.Stop()
		pcap, readErr := os.ReadFile(filepath.Join(captureDirectory, "traffic.pcap"))
		if err := errors.Join(qlogErr, captureErr, readErr); err != nil {
			return soakCycleObservation{}, err
		}
		observation.ConnectionID, observation.QLOG, observation.PCAP = connectionID, qlog, pcap
		captureFinished = true
	}
	return observation, nil
}

func (engine *rawQUICSoakEngine) connectPair(ctx context.Context) (*rawquic.Session, *rawquic.Session, error) {
	accepted := make(chan struct {
		session *rawquic.Session
		err     error
	}, 1)
	go func() {
		session, err := engine.listener.Accept(ctx)
		accepted <- struct {
			session *rawquic.Session
			err     error
		}{session: session, err: err}
	}()
	client, err := rawquic.Dial(ctx, engine.listener.Addr().String(), engine.clientTLS.Clone(), rawquic.DefaultLimits())
	if err != nil {
		return nil, nil, err
	}
	peer := <-accepted
	if peer.err != nil || peer.session == nil {
		_ = client.Close()
		return nil, nil, peer.err
	}
	return client, peer.session, nil
}

func rawQUICSoakRoundTrip(ctx context.Context, client, server *rawquic.Session, ordinal int) (int64, error) {
	accepted := make(chan struct {
		stream io.ReadWriteCloser
		err    error
	}, 1)
	go func() {
		stream, err := server.AcceptStream(ctx)
		accepted <- struct {
			stream io.ReadWriteCloser
			err    error
		}{stream: stream, err: err}
	}()
	stream, err := client.OpenStream(ctx)
	if err != nil {
		return -1, err
	}
	streamID := nativeStreamID(stream)
	defer stream.Close()
	message := []byte(fmt.Sprintf("soak-cycle-%d", ordinal))
	if _, err := stream.Write(message); err != nil {
		return -1, err
	}
	if err := stream.CloseWrite(); err != nil {
		return -1, err
	}
	peer := <-accepted
	if peer.err != nil {
		return -1, peer.err
	}
	defer peer.stream.Close()
	got, err := io.ReadAll(peer.stream)
	if err != nil {
		return -1, err
	}
	if string(got) != string(message) {
		return -1, errors.New("post-migration payload mismatch")
	}
	return streamID, nil
}

func (engine *rawQUICSoakEngine) Close(ctx context.Context) error {
	if engine == nil {
		return nil
	}
	engine.mu.Lock()
	if engine.closed {
		err := engine.resourceErr
		engine.mu.Unlock()
		return err
	}
	engine.closed = true
	client, server, listener := engine.client, engine.server, engine.listener
	engine.client, engine.server, engine.listener = nil, nil, nil
	engine.mu.Unlock()
	var result error
	if client != nil {
		result = errors.Join(result, client.Close())
	}
	if server != nil {
		result = errors.Join(result, server.Close())
	}
	if listener != nil {
		result = errors.Join(result, listener.Close())
	}
	finish, captureErr := captureSoakResidualSnapshot(ctx, engine.resourceStart)
	engine.mu.Lock()
	engine.resourceFinish = finish
	engine.resourceErr = captureErr
	engine.resourceFinished = captureErr == nil
	engine.mu.Unlock()
	result = errors.Join(result, captureErr)
	return result
}

func (engine *rawQUICSoakEngine) Residuals() (soakResiduals, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	residual := 0
	if engine.client != nil {
		residual++
	}
	if engine.server != nil {
		residual++
	}
	if engine.resourceErr != nil {
		return soakResiduals{}, engine.resourceErr
	}
	finish := engine.resourceFinish
	if !engine.resourceFinished {
		var err error
		finish, err = transportrelease.CaptureResourceSnapshot()
		if err != nil {
			return soakResiduals{}, err
		}
	}
	return soakResiduals{Sessions: residual,
		Goroutines: positiveIntDelta(finish.Goroutines, engine.resourceStart.Goroutines),
		OpenFDs:    positiveIntDelta(finish.OpenFDs, engine.resourceStart.OpenFDs),
		Tasks:      positiveIntDelta(finish.Tasks, engine.resourceStart.Tasks)}, nil
}

func captureSoakResidualSnapshot(ctx context.Context, baseline transportrelease.ResourceSnapshot) (transportrelease.ResourceSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		snapshot, err := transportrelease.CaptureResourceSnapshot()
		if err != nil {
			return transportrelease.ResourceSnapshot{}, err
		}
		if snapshot.Goroutines <= baseline.Goroutines && snapshot.OpenFDs <= baseline.OpenFDs && snapshot.Tasks <= baseline.Tasks {
			return snapshot, nil
		}
		select {
		case <-ctx.Done():
			return snapshot, fmt.Errorf("raw QUIC soak resources did not return to baseline: goroutines=%d/%d open_fds=%d/%d tasks=%d/%d: %w",
				snapshot.Goroutines, baseline.Goroutines, snapshot.OpenFDs, baseline.OpenFDs, snapshot.Tasks, baseline.Tasks, context.Cause(ctx))
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func soakTLS() (*tls.Config, *tls.Config, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	server := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{rawquic.ALPNDirect}, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}}}
	client := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{rawquic.ALPNDirect}, RootCAs: roots, ServerName: "localhost"}
	return server, client, nil
}
