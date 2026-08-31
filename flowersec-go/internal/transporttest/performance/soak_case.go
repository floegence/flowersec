package performance

import (
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
	"strconv"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/quicbase"
	rawquic "github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/rawquicv3"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/transporttest"
)

var (
	errSoakEngineUnavailable = errors.New("production soak migration engine is unavailable")
	errSoakMigrationUnproven = errors.New("soak cycle did not prove a native carrier migration")
)

const soakCleanupGrace = 5 * time.Second

type soakContract struct {
	Duration           time.Duration
	CyclePeriod        time.Duration
	CPUTimeBudget      time.Duration
	Cycles             int
	Reconnects         int
	Migrations         int
	MaxRSSGrowth       uint64
	MaxGoroutineGrowth int
	MaxOpenFDGrowth    int
	MaxTaskGrowth      int
	ResidualSessions   int
	ResidualGoroutines int
	ResidualOpenFDs    int
	ResidualTasks      int
}

func productionSoakContract() soakContract {
	contract := soakContract{
		Duration: 5 * time.Minute, CyclePeriod: time.Minute, CPUTimeBudget: 5 * time.Minute, Cycles: 5, Reconnects: 5, Migrations: 5,
		MaxRSSGrowth: 64 << 20, MaxGoroutineGrowth: 64, MaxOpenFDGrowth: 16, MaxTaskGrowth: 64,
	}
	if duration, configured := scaledPerformanceDuration(30 * time.Second); configured {
		contract.Duration = duration
		contract.CyclePeriod = duration / 3
		contract.Cycles = 3
		contract.Reconnects = 3
		contract.Migrations = 3
	}
	return contract
}

type soakCycleObservation struct {
	FaultApplied   bool
	Reconnected    bool
	Migrated       bool
	ConnectionID   string
	LocalAddress   string
	RemoteAddress  string
	NativeStreamID int64
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
	Snapshot transporttest.ResourceSnapshot
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
	Timeline         []soakTraceRecord
	Metrics          metrics
	Config           configuration
	Resources        []caseResourceRecord
}

type soakTraceRecord struct {
	Sequence       uint64 `json:"sequence"`
	AtNS           int64  `json:"at_ns"`
	Event          string `json:"event"`
	ConnectionID   string `json:"connection_id"`
	LocalAddress   string `json:"local_address,omitempty"`
	RemoteAddress  string `json:"remote_address,omitempty"`
	NativeStreamID *int64 `json:"native_stream_id,omitempty"`
}

func runProductionSoakCase(ctx context.Context, engine soakCycleEngine) (soakCaseResult, error) {
	if engine == nil {
		return soakCaseResult{}, errSoakEngineUnavailable
	}
	return runSoakCase(ctx, productionSoakContract(), engine, transporttest.CaptureResourceSnapshot)
}

// runNativeProductionSoakCase owns the production raw-QUIC reconnect and path
// migration engine. The public Flowersec session intentionally stays opaque;
// test output uses this internal carrier boundary to exercise Migrate.
func runNativeProductionSoakCase(ctx context.Context, contract soakContract) (soakCaseResult, error) {
	engine, err := newRawQUICSoakEngine(ctx)
	if err != nil {
		return soakCaseResult{}, err
	}
	return runSoakCase(ctx, contract, engine, transporttest.CaptureResourceSnapshot)
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
		capture = transporttest.CaptureResourceSnapshot
	}
	startSnapshot, err := capture()
	if err != nil {
		return result, fmt.Errorf("capture soak start resources: %w", err)
	}
	started := time.Now()
	result.Timeline = []soakTraceRecord{{Sequence: 1, AtNS: 0, Event: "soak_started"}}
	resourceSeries := []soakResourceObservation{{Snapshot: startSnapshot, AtNS: 0}}
	closed := false
	defer func() {
		if closed {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), soakCleanupGrace)
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
		result.Timeline = append(result.Timeline, soakTraceRecord{
			Sequence: uint64(len(result.Timeline) + 1), AtNS: cycleAt,
			Event: "fault_cycle_completed", ConnectionID: observation.ConnectionID,
			LocalAddress: observation.LocalAddress, RemoteAddress: observation.RemoteAddress, NativeStreamID: &streamID,
		})
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), soakCleanupGrace)
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
	result.Timeline = append(result.Timeline, soakTraceRecord{
		Sequence: uint64(len(result.Timeline) + 1), AtNS: completedAt, Event: "soak_completed",
	})
	result.Metrics = metrics{Records: []metric{
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
	result.Config = configuration{Records: []configurationValue{
		{Key: "profile", Value: "five-minute-weaknet-soak-v1"},
		{Key: "duration_ns", Value: strconv.FormatInt(contract.Duration.Nanoseconds(), 10)},
		{Key: "fault_cycle_period_ns", Value: strconv.FormatInt(contract.CyclePeriod.Nanoseconds(), 10)},
		{Key: "fault_cycle_count", Value: strconv.Itoa(contract.Cycles)},
		{Key: "reconnect_count", Value: strconv.Itoa(contract.Reconnects)},
		{Key: "migration_count", Value: strconv.Itoa(contract.Migrations)},
		{Key: "watchdog", Value: "completed"},
	}}
	result.Resources = make([]caseResourceRecord, 0, len(resourceSeries))
	for index, observation := range resourceSeries {
		phase := "soak_start"
		if index > 0 && index <= contract.Cycles {
			phase = fmt.Sprintf("soak_cycle_%03d", index)
		} else if index == len(resourceSeries)-1 {
			phase = "soak_end"
		}
		snapshot := observation.Snapshot
		if snapshot.CPUNanoseconds < startSnapshot.CPUNanoseconds {
			return result, errors.New("soak CPU counter moved backwards")
		}
		record := caseResourceRecord{Phase: phase, AtNS: observation.AtNS, RSSBytes: snapshot.RSSBytes, CPUNanoseconds: snapshot.CPUNanoseconds - startSnapshot.CPUNanoseconds, OpenFDs: snapshot.OpenFDs, Goroutines: snapshot.Goroutines, Tasks: snapshot.Tasks}
		if phase == "soak_end" {
			record.ResidualSessions = intPointerValue(result.Residuals.Sessions)
			record.ResidualGoroutines = intPointerValue(result.Residuals.Goroutines)
			record.ResidualOpenFDs = intPointerValue(result.Residuals.OpenFDs)
			record.ResidualTasks = intPointerValue(result.Residuals.Tasks)
		}
		result.Resources = append(result.Resources, record)
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

func resourceSnapshotElapsedNS(start, observed transporttest.ResourceSnapshot) (int64, error) {
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

func intPointerValue(value int) *int { return &value }

type rawQUICSoakEngine struct {
	listener  *rawquic.Listener
	clientTLS *tls.Config

	mu               sync.Mutex
	client           *rawquic.Session
	server           *rawquic.Session
	closed           bool
	resourceStart    transporttest.ResourceSnapshot
	resourceFinish   transporttest.ResourceSnapshot
	resourceErr      error
	resourceFinished bool
}

func newRawQUICSoakEngine(ctx context.Context) (*rawQUICSoakEngine, error) {
	resourceStart, err := transporttest.CaptureResourceSnapshot()
	if err != nil {
		return nil, fmt.Errorf("capture raw QUIC soak baseline: %w", err)
	}
	serverTLS, clientTLS, err := soakTLS()
	if err != nil {
		return nil, err
	}
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS, quicbase.DefaultLimits())
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
	return &rawQUICSoakEngine{listener: listener, clientTLS: clientTLS, resourceStart: resourceStart}, nil
}

func (engine *rawQUICSoakEngine) RunCycle(ctx context.Context, ordinal int) (soakCycleObservation, error) {
	if ordinal < 1 {
		return soakCycleObservation{}, errors.New("soak cycle ordinal must be positive")
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
	client, err := rawquic.Dial(ctx, engine.listener.Addr().String(), engine.clientTLS.Clone(), quicbase.DefaultLimits())
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
		finish, err = transporttest.CaptureResourceSnapshot()
		if err != nil {
			return soakResiduals{}, err
		}
	}
	return soakResiduals{Sessions: residual,
		Goroutines: positiveIntDelta(finish.Goroutines, engine.resourceStart.Goroutines),
		OpenFDs:    positiveIntDelta(finish.OpenFDs, engine.resourceStart.OpenFDs),
		Tasks:      ownedTaskResidual(engine.resourceStart, finish)}, nil
}

// Linux task counts include Go scheduler threads, which may remain parked after
// transport-owned goroutines and descriptors have been released. They are a
// growth metric, not an engine-owned residual unless the owned counters remain.
func ownedTaskResidual(start, finish transporttest.ResourceSnapshot) int {
	if finish.Goroutines <= start.Goroutines && finish.OpenFDs <= start.OpenFDs {
		return 0
	}
	return positiveIntDelta(finish.Tasks, start.Tasks)
}

func captureSoakResidualSnapshot(ctx context.Context, baseline transporttest.ResourceSnapshot) (transporttest.ResourceSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		snapshot, err := transporttest.CaptureResourceSnapshot()
		if err != nil {
			return transporttest.ResourceSnapshot{}, err
		}
		if snapshot.Goroutines <= baseline.Goroutines && snapshot.OpenFDs <= baseline.OpenFDs {
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
	server := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{rawquic.ALPNDirect}, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}}}
	client := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{rawquic.ALPNDirect}, RootCAs: roots, ServerName: "localhost"}
	return server, client, nil
}
