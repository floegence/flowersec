package performance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	flowersession "github.com/floegence/flowersec/flowersec-go/v3/internal/sessionv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/transporttest"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/transporttest/linuxnetlab"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/transporttest/tunnelworkload"
)

type browserCapacityEndpointConfig struct {
	Topology          tunnelworkload.BrowserTopology
	ProfileID         string
	Sessions          int
	StreamsPerSession int
	SourceRoot        string
	ClientNamespace   string
	ServerNamespace   string
	ServerAddress     string
	OutputDirectory   string
	OperationDeadline time.Duration
}

const browserDirectWebTransportTopology tunnelworkload.BrowserTopology = "browser_webtransport"

type browserCapacityControl interface {
	Connect(context.Context, *browserCapacityRecord) error
	CloseSession(context.Context, *browserCapacityRecord) error
	OpenStreams(context.Context, int, int) error
	Snapshot(context.Context) (browserCapacityControlSnapshot, error)
	Quiesce(context.Context) error
	Shutdown(context.Context) error
}

type browserCapacityControllerProcessSnapshot struct {
	RSSBytes              uint64 `json:"rss_bytes"`
	HeapTotalBytes        uint64 `json:"heap_total_bytes"`
	HeapUsedBytes         uint64 `json:"heap_used_bytes"`
	UserCPUMicroseconds   uint64 `json:"user_cpu_microseconds"`
	SystemCPUMicroseconds uint64 `json:"system_cpu_microseconds"`
	MaxRSSKiB             uint64 `json:"max_rss_kib"`
}

type browserCapacityControlSnapshot struct {
	SchemaVersion  int                                      `json:"schema_version"`
	At             time.Time                                `json:"at"`
	ActiveSessions int                                      `json:"active_sessions"`
	Process        browserCapacityControllerProcessSnapshot `json:"process"`
	Chromium       map[string]float64                       `json:"chromium"`
	ProcessTree    linuxProcessTreeSnapshot                 `json:"process_tree"`
}

type browserCapacityProducerResourceSample struct {
	Phase      string                         `json:"phase"`
	Controller browserCapacityControlSnapshot `json:"controller"`
	Runner     transporttest.ResourceSnapshot `json:"runner"`
	Aggregate  transporttest.ResourceSnapshot `json:"aggregate"`
}

type browserCapacityProducerResourceArtifact struct {
	SchemaVersion int                                     `json:"schema_version"`
	Kind          string                                  `json:"kind"`
	Preflight     browserCapacityResourcePreflight        `json:"preflight"`
	Records       []browserCapacityProducerResourceSample `json:"records"`
}

type browserCapacityResourcePreflight struct {
	NOFileSoftLimit uint64 `json:"nofile_soft_limit"`
	NOFileHardLimit uint64 `json:"nofile_hard_limit"`
	KernelFileMax   uint64 `json:"kernel_file_max"`
}

type browserCapacityEndpoint struct {
	broker            *browserCapacityArtifactBroker
	control           browserCapacityControl
	closeOwner        func(context.Context) error
	closeHTTP         func() error
	wait              func(context.Context) error
	output            []string
	topology          tunnelworkload.BrowserTopology
	profileID         string
	sessions          int
	streamsPerSession int
	contract          capacityContract
	resourcePreflight browserCapacityResourcePreflight
	resourceOutput    string

	resourceMu      sync.Mutex
	resourceSamples []browserCapacityProducerResourceSample
	streamMu        sync.Mutex
	heldStreams     map[string][]flowersession.ByteStream

	quiesceOnce sync.Once
	quiesceDone chan struct{}
	quiesceErr  error
	closeOnce   sync.Once
	closeDone   chan struct{}
	closeErr    error
}

type directBrowserCapacityArtifact struct {
	*transporttest.ProductDirectBrowserArtifact
}

func (*directBrowserCapacityArtifact) Start(context.Context) error { return nil }

// openProductionBrowserCapacityEndpoint creates the production Chromium and Go
// production legs inside the same Linux network namespaces used by browser
// release cells. The caller must run in the client namespace so every browser
// session traverses the veth link instead of a loopback shortcut.
func openProductionBrowserCapacityEndpoint(ctx context.Context, config browserCapacityEndpointConfig) (*browserCapacityEndpoint, error) {
	if !supportedLinuxRunnerArchitecture(runtime.GOOS, runtime.GOARCH) {
		return nil, errors.New("browser capacity endpoint requires Linux amd64 or arm64")
	}
	heldSessions := config.Sessions == 1000 && config.StreamsPerSession == 0 &&
		(config.Topology == tunnelworkload.BrowserTunnelWTWSS || config.Topology == tunnelworkload.BrowserTunnelWTQUIC)
	streamCapacity := config.Sessions == 100 && config.StreamsPerSession == 128 &&
		(config.Topology == browserDirectWebTransportTopology || config.Topology == tunnelworkload.BrowserTunnelWTWSS || config.Topology == tunnelworkload.BrowserTunnelWTQUIC)
	capacityKind := capacityBrowserTunnel
	if streamCapacity {
		capacityKind = capacityBrowserStream
	}
	if (!heldSessions && !streamCapacity) ||
		config.ProfileID == "" || config.ClientNamespace == "" || config.ServerNamespace == "" || config.ClientNamespace == config.ServerNamespace ||
		net.ParseIP(config.ServerAddress) == nil || !filepath.IsAbs(config.SourceRoot) || !filepath.IsAbs(config.OutputDirectory) ||
		config.OperationDeadline != browserCapacityOperationDeadlineForKind(capacityKind) {
		return nil, errors.New("browser capacity endpoint configuration is incomplete")
	}
	contract := productionBrowserCapacityContract()
	if streamCapacity {
		contract = productionBrowserStreamCapacityContract()
	}
	resourcePreflight, err := captureBrowserCapacityResourcePreflight(contract.MaxOpenFDs)
	if err != nil {
		return nil, err
	}
	if err := linuxnetlab.RequireCurrentNamespace(config.ClientNamespace); err != nil {
		return nil, err
	}
	for _, relative := range []string{
		"flowersec-ts/scripts/browser-capacity-controller.mjs",
		"flowersec-ts/scripts/chromium-netns-launcher.sh",
		"flowersec-ts/dist/browser/index.js",
	} {
		if info, err := os.Stat(filepath.Join(config.SourceRoot, relative)); err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("browser capacity source is incomplete: %s", relative)
		}
	}
	entries, err := os.ReadDir(config.OutputDirectory)
	if err != nil || len(entries) != 0 {
		return nil, errors.New("browser capacity output directory must exist and be empty")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	allowedOrigin := browserCapacityAllowedOrigin(config.ServerAddress)
	var issue func() (browserCapacityArtifact, error)
	var certificate func() (string, error)
	var cleanupOwner func(context.Context) error
	if err := linuxnetlab.InNamespace(config.ServerNamespace, func() error {
		if config.Topology == browserDirectWebTransportTopology {
			owner, openErr := transporttest.OpenProductDirectBrowserStreamCapacityEndpointAt(context.Background(), config.ServerAddress, allowedOrigin)
			if openErr != nil {
				return openErr
			}
			issue = func() (browserCapacityArtifact, error) {
				artifact, issueErr := owner.IssueBrowserArtifact()
				if issueErr != nil {
					return nil, issueErr
				}
				return &directBrowserCapacityArtifact{ProductDirectBrowserArtifact: artifact}, nil
			}
			certificate = owner.CertificateHashBase64URL
			cleanupOwner = func(context.Context) error { return owner.Close() }
			return nil
		}
		var owner *tunnelworkload.BrowserEndpoint
		var openErr error
		if streamCapacity {
			owner, openErr = tunnelworkload.OpenBrowserStreamCapacityEndpointAt(context.Background(), config.Topology, config.ServerAddress, allowedOrigin)
		} else {
			owner, openErr = tunnelworkload.OpenBrowserCapacityEndpointAt(context.Background(), config.Topology, config.ServerAddress, allowedOrigin, config.Sessions)
		}
		if openErr != nil {
			return openErr
		}
		issue = func() (browserCapacityArtifact, error) { return owner.IssueBrowserArtifact() }
		certificate = owner.CertificateHashBase64URL
		cleanupOwner = owner.Close
		return nil
	}); err != nil {
		return nil, err
	}
	certificateHash, err := certificate()
	if err != nil {
		return nil, errors.Join(err, cleanupOwner(context.Background()))
	}
	broker, err := newBrowserCapacityArtifactBroker(issue, config.Sessions)
	if err != nil {
		return nil, errors.Join(err, cleanupOwner(context.Background()))
	}
	listener, server, eventSinkURL, err := startBrowserArtifactHTTPServer(config.ServerNamespace, config.ServerAddress, broker)
	if err != nil {
		return nil, errors.Join(err, cleanupOwner(context.Background()))
	}
	closeHTTP := func() error { return closeBrowserArtifactHTTPServer(server, listener) }
	control, wait, output, err := startBrowserCapacityControl(ctx, config, eventSinkURL, certificateHash)
	if err != nil {
		broker.cancelAll()
		return nil, errors.Join(err, closeHTTP(), cleanupOwner(context.Background()))
	}
	return &browserCapacityEndpoint{
		broker: broker, control: control, closeOwner: cleanupOwner, closeHTTP: closeHTTP, wait: wait,
		output: output, topology: config.Topology, profileID: config.ProfileID, sessions: config.Sessions, streamsPerSession: config.StreamsPerSession,
		contract: contract, resourcePreflight: resourcePreflight,
		resourceOutput: filepath.Join(config.OutputDirectory, "producer-resource.json"), heldStreams: make(map[string][]flowersession.ByteStream),
		quiesceDone: make(chan struct{}), closeDone: make(chan struct{}),
	}, nil
}

func browserCapacityAllowedOrigin(serverAddress string) string {
	return "https://" + serverAddress
}

func captureBrowserCapacityResourcePreflight(maxOpenFDs int) (browserCapacityResourcePreflight, error) {
	var nofile syscall.Rlimit
	if maxOpenFDs <= 0 || syscall.Getrlimit(syscall.RLIMIT_NOFILE, &nofile) != nil {
		return browserCapacityResourcePreflight{}, errors.New("browser capacity cannot read RLIMIT_NOFILE")
	}
	data, err := os.ReadFile("/proc/sys/fs/file-max")
	if err != nil {
		return browserCapacityResourcePreflight{}, fmt.Errorf("browser capacity cannot read kernel fs.file-max: %w", err)
	}
	kernelFileMax, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return browserCapacityResourcePreflight{}, errors.New("browser capacity kernel fs.file-max is invalid")
	}
	preflight := browserCapacityResourcePreflight{NOFileSoftLimit: nofile.Cur, NOFileHardLimit: nofile.Max, KernelFileMax: kernelFileMax}
	if err := validateBrowserCapacityResourcePreflight(preflight, maxOpenFDs); err != nil {
		return browserCapacityResourcePreflight{}, err
	}
	return preflight, nil
}

func validateBrowserCapacityResourcePreflight(preflight browserCapacityResourcePreflight, maxOpenFDs int) error {
	want := uint64(maxOpenFDs)
	if maxOpenFDs <= 0 || preflight.NOFileSoftLimit < want || preflight.NOFileHardLimit < want || preflight.KernelFileMax < want {
		return fmt.Errorf(
			"browser capacity descriptor preflight is below the frozen ceiling: soft=%d hard=%d kernel_file_max=%d want_at_least=%d",
			preflight.NOFileSoftLimit, preflight.NOFileHardLimit, preflight.KernelFileMax, maxOpenFDs,
		)
	}
	return nil
}

func (endpoint *browserCapacityEndpoint) OpenStreamCapacity(ctx context.Context, streamsPerSession int) error {
	if endpoint == nil || endpoint.sessions != 100 || endpoint.streamsPerSession != 128 || streamsPerSession != 128 {
		return errors.New("browser stream capacity requires exactly 100 sessions and 128 streams per session")
	}
	records := endpoint.broker.snapshotRecords()
	if len(records) != endpoint.sessions {
		return errors.New("browser stream capacity sessions are incomplete")
	}
	sort.Slice(records, func(left, right int) bool { return records[left].id < records[right].id })
	type streamResult struct {
		record *browserCapacityRecord
		stream flowersession.ByteStream
		err    error
	}
	type streamProgress struct {
		accepted          atomic.Int64
		metadataValidated atomic.Int64
		payloadRead       atomic.Int64
		ackWritten        atomic.Int64
	}
	progress := &streamProgress{}
	progressError := func(message string, cause error) error {
		return errors.Join(fmt.Errorf(
			"%s: accepted=%d metadata_validated=%d payload_read=%d ack_written=%d want=%d",
			message, progress.accepted.Load(), progress.metadataValidated.Load(), progress.payloadRead.Load(), progress.ackWritten.Load(), endpoint.sessions*streamsPerSession,
		), cause)
	}
	ready := make(chan streamResult, endpoint.sessions*streamsPerSession)
	for sessionIndex, record := range records {
		record.mu.Lock()
		serverSession := record.session
		record.mu.Unlock()
		if serverSession == nil {
			return errors.New("browser stream capacity server session is unavailable")
		}
		go func() {
			seenStreamIndexes := make([]bool, streamsPerSession)
			for range streamsPerSession {
				incoming, err := serverSession.AcceptStream(ctx)
				if err != nil {
					ready <- streamResult{err: err}
					return
				}
				progress.accepted.Add(1)
				if incoming.Kind != "capacity-bidi" || !capacityMetadataIndex(incoming.Metadata["session_index"], sessionIndex) ||
					!claimCapacityMetadataIndex(seenStreamIndexes, incoming.Metadata["stream_index"]) {
					ready <- streamResult{err: errors.New("browser stream capacity metadata mismatch")}
					return
				}
				progress.metadataValidated.Add(1)
				go func() {
					payload := make([]byte, 2)
					if _, err := io.ReadFull(incoming.Stream, payload); err != nil {
						ready <- streamResult{err: err}
						return
					}
					progress.payloadRead.Add(1)
					ack := []byte{payload[0] ^ 0xff, payload[1] ^ 0xff}
					if written, err := incoming.Stream.Write(ack); err != nil || written != len(ack) {
						ready <- streamResult{err: errors.Join(err, io.ErrShortWrite)}
						return
					}
					progress.ackWritten.Add(1)
					ready <- streamResult{record: record, stream: incoming.Stream}
				}()
			}
		}()
	}
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- endpoint.control.OpenStreams(ctx, endpoint.sessions, streamsPerSession) }()
	controllerCompleted := false
	for completed := 0; completed < endpoint.sessions*streamsPerSession; completed++ {
		select {
		case result := <-ready:
			if result.err != nil || result.stream == nil || result.record == nil {
				return progressError("browser stream capacity server workload failed", result.err)
			}
			endpoint.streamMu.Lock()
			endpoint.heldStreams[result.record.id] = append(endpoint.heldStreams[result.record.id], result.stream)
			endpoint.streamMu.Unlock()
		case err := <-controllerDone:
			if err != nil {
				return progressError("browser stream capacity controller stopped before the server workload completed", err)
			}
			controllerCompleted = true
			controllerDone = nil
		case <-ctx.Done():
			return progressError("browser stream capacity server workload deadline exceeded", context.Cause(ctx))
		}
	}
	if controllerCompleted {
		return nil
	}
	select {
	case err := <-controllerDone:
		if err != nil {
			return progressError("browser stream capacity controller workload failed", err)
		}
		return nil
	case <-ctx.Done():
		return progressError("browser stream capacity controller workload deadline exceeded", context.Cause(ctx))
	}
}

func (endpoint *browserCapacityEndpoint) ResidualStreamCount() int {
	if endpoint == nil {
		return 0
	}
	endpoint.streamMu.Lock()
	defer endpoint.streamMu.Unlock()
	residual := 0
	for _, streams := range endpoint.heldStreams {
		residual += len(streams)
	}
	return residual
}

func claimCapacityMetadataIndex(seen []bool, value any) bool {
	var parsed int64
	switch typed := value.(type) {
	case json.Number:
		var err error
		parsed, err = typed.Int64()
		if err != nil {
			return false
		}
	case float64:
		if typed != math.Trunc(typed) || typed > math.MaxInt64 || typed < math.MinInt64 {
			return false
		}
		parsed = int64(typed)
	case int:
		parsed = int64(typed)
	default:
		return false
	}
	if parsed < 0 || parsed >= int64(len(seen)) || seen[parsed] {
		return false
	}
	seen[parsed] = true
	return true
}

func capacityMetadataIndex(value any, want int) bool {
	switch typed := value.(type) {
	case json.Number:
		parsed, err := typed.Int64()
		return err == nil && parsed == int64(want)
	case float64:
		return typed == float64(want)
	case int:
		return typed == want
	default:
		return false
	}
}

func (endpoint *browserCapacityEndpoint) Connect(ctx context.Context) (capacitySession, error) {
	if endpoint == nil || endpoint.broker == nil || endpoint.control == nil {
		return nil, errors.New("browser capacity endpoint is not initialized")
	}
	record, err := endpoint.broker.issueRecord()
	if err != nil {
		return nil, err
	}
	if err := endpoint.control.Connect(ctx, record); err != nil {
		record.artifact.Cancel()
		endpoint.broker.remove(record)
		return nil, err
	}
	session, err := record.artifact.AwaitServer(ctx)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		closeErr := endpoint.control.CloseSession(cleanupCtx, record)
		cancel()
		endpoint.broker.remove(record)
		return nil, errors.Join(err, closeErr)
	}
	record.mu.Lock()
	if !record.spent {
		record.mu.Unlock()
		_ = session.Close()
		endpoint.broker.remove(record)
		return nil, errors.New("Chromium connected without committing the one-shot artifact")
	}
	record.session = session
	record.mu.Unlock()
	go func() {
		<-session.Termination()
		record.markTerminated()
	}()
	return &browserCapacitySession{endpoint: endpoint, record: record, done: make(chan struct{})}, nil
}

func (endpoint *browserCapacityEndpoint) Close(ctx context.Context) error {
	if endpoint == nil {
		return nil
	}
	endpoint.closeOnce.Do(func() {
		defer close(endpoint.closeDone)
		endpoint.closeErr = errors.Join(endpoint.Quiesce(ctx), endpoint.control.Shutdown(ctx), endpoint.wait(ctx), endpoint.writeProducerResourceOutput())
		endpoint.closeErr = errors.Join(endpoint.closeErr, endpoint.verifyOutput())
	})
	select {
	case <-endpoint.closeDone:
		return endpoint.closeErr
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (endpoint *browserCapacityEndpoint) Quiesce(ctx context.Context) error {
	if endpoint == nil {
		return nil
	}
	endpoint.quiesceOnce.Do(func() {
		if endpoint.quiesceDone == nil {
			endpoint.quiesceDone = make(chan struct{})
		}
		defer close(endpoint.quiesceDone)
		if residual := endpoint.broker.residual(); residual != 0 {
			endpoint.quiesceErr = fmt.Errorf("browser capacity endpoint has %d residual sessions", residual)
			endpoint.broker.cancelAll()
		}
		endpoint.quiesceErr = errors.Join(endpoint.quiesceErr, endpoint.control.Quiesce(ctx), endpoint.closeHTTP(), endpoint.closeOwner(ctx))
	})
	select {
	case <-endpoint.quiesceDone:
		return endpoint.quiesceErr
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (endpoint *browserCapacityEndpoint) verifyOutput() error {
	if len(endpoint.output) == 0 {
		return nil
	}
	if len(endpoint.output) != 5 {
		return errors.New("browser capacity endpoint has an incomplete output inventory")
	}
	for _, path := range endpoint.output {
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("browser capacity output is missing: %s", filepath.Base(path))
		}
	}
	resultData, err := os.ReadFile(endpoint.output[2])
	if err != nil {
		return err
	}
	var result struct {
		SchemaVersion     int                            `json:"schema_version"`
		Classification    string                         `json:"classification"`
		Topology          tunnelworkload.BrowserTopology `json:"topology"`
		ProfileID         string                         `json:"profile_id"`
		ConnectedSessions int                            `json:"connected_sessions"`
		UniqueSessions    int                            `json:"unique_sessions"`
		PeakActive        int                            `json:"peak_active_sessions"`
		ClosedSessions    int                            `json:"closed_sessions"`
		ResidualSessions  int                            `json:"residual_sessions"`
		CompletedStreams  int                            `json:"completed_streams"`
		PeakActiveStreams int                            `json:"peak_active_streams"`
		ClosedStreams     int                            `json:"closed_streams"`
		ResidualStreams   int                            `json:"residual_streams"`
		LivenessSweeps    int                            `json:"liveness_sweeps"`
		LivenessFailures  int                            `json:"liveness_failures"`
		Events            []map[string]json.RawMessage   `json:"events"`
		Resources         []map[string]json.RawMessage   `json:"resource_samples"`
	}
	if err := json.Unmarshal(resultData, &result); err != nil {
		return err
	}
	if result.SchemaVersion != 1 || result.Classification != "raw_chromium_webtransport_capacity" ||
		result.Topology != endpoint.topology || result.ProfileID != endpoint.profileID ||
		result.ConnectedSessions != endpoint.sessions || result.UniqueSessions != endpoint.sessions ||
		result.PeakActive != endpoint.sessions || result.ClosedSessions != endpoint.sessions || result.ResidualSessions != 0 ||
		result.LivenessSweeps < 1 || result.LivenessFailures != 0 || len(result.Events) < endpoint.sessions*3 || len(result.Resources) < 4 {
		return errors.New("Chromium capacity output does not prove the exact live-session contract")
	}
	wantStreams := endpoint.sessions * endpoint.streamsPerSession
	if result.CompletedStreams != wantStreams || result.PeakActiveStreams != wantStreams || result.ClosedStreams != wantStreams || result.ResidualStreams != 0 {
		return errors.New("Chromium capacity output does not prove the exact stream contract")
	}
	configData, err := os.ReadFile(endpoint.output[3])
	if err != nil {
		return err
	}
	var config struct {
		SchemaVersion         int                            `json:"schema_version"`
		Topology              tunnelworkload.BrowserTopology `json:"topology"`
		ProfileID             string                         `json:"profile_id"`
		Sessions              int                            `json:"sessions"`
		Workload              string                         `json:"workload"`
		ConnectionsPerSession int                            `json:"connections_per_session"`
		StreamsPerSession     int                            `json:"streams_per_session"`
	}
	if err := json.Unmarshal(configData, &config); err != nil || config.SchemaVersion != 1 || config.Topology != endpoint.topology ||
		config.ProfileID != endpoint.profileID || config.Sessions != endpoint.sessions || config.ConnectionsPerSession != 1 ||
		config.StreamsPerSession != endpoint.streamsPerSession || config.Workload != func() string {
		if endpoint.streamsPerSession > 0 {
			return "stream_capacity"
		}
		return "held_sessions"
	}() {
		return errors.New("Chromium capacity output configuration is mismatched")
	}
	traceHeader := make([]byte, 4)
	trace, err := os.Open(endpoint.output[1])
	if err != nil {
		return err
	}
	_, readErr := io.ReadFull(trace, traceHeader)
	closeErr := trace.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(traceHeader, []byte{'P', 'K', 3, 4}) {
		return errors.New("Chromium capacity trace is not a non-empty Playwright trace archive")
	}
	return nil
}

func (endpoint *browserCapacityEndpoint) writeProducerResourceOutput() error {
	if endpoint.resourceOutput == "" {
		return nil
	}
	endpoint.resourceMu.Lock()
	records := append([]browserCapacityProducerResourceSample(nil), endpoint.resourceSamples...)
	endpoint.resourceMu.Unlock()
	if len(records) != 4 {
		return fmt.Errorf("browser capacity producer resource sample count = %d, want 4", len(records))
	}
	wantPhases := []string{"baseline", "ramp", "hold", "cleanup"}
	for index := range records {
		if records[index].Phase != wantPhases[index] {
			return errors.New("browser capacity producer resource phases are incomplete")
		}
	}
	if err := validateBrowserCapacityResourcePreflight(endpoint.resourcePreflight, endpoint.contract.MaxOpenFDs); err != nil {
		return err
	}
	data, err := json.MarshalIndent(browserCapacityProducerResourceArtifact{
		SchemaVersion: 1, Kind: "transport_producer_resource", Preflight: endpoint.resourcePreflight, Records: records,
	}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(endpoint.resourceOutput, data, 0o600)
}

func (endpoint *browserCapacityEndpoint) OutputPaths() []string {
	if endpoint == nil {
		return nil
	}
	return append([]string(nil), endpoint.output...)
}

func (endpoint *browserCapacityEndpoint) CaptureResourceSnapshot() (transporttest.ResourceSnapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	controller, err := endpoint.control.Snapshot(ctx)
	if err != nil {
		return transporttest.ResourceSnapshot{}, fmt.Errorf("capture Chromium capacity resources: %w", err)
	}
	runner, err := transporttest.CaptureResourceSnapshot()
	if err != nil {
		return transporttest.ResourceSnapshot{}, err
	}
	snapshot, err := aggregateBrowserCapacityResources(runner, controller.ProcessTree)
	if err != nil {
		return transporttest.ResourceSnapshot{}, err
	}
	contract := endpoint.contract
	// CPU is cumulative for both the Go runner and Chromium cgroup. The
	// capacity runner owns the baseline and enforces MaxCPU against the delta;
	// rejecting the absolute counter here would charge pre-workload CPU to the
	// measured case and suppress its final resource artifact.
	if snapshot.RSSBytes > contract.MaxRSS || snapshot.OpenFDs > contract.MaxOpenFDs ||
		snapshot.Goroutines > contract.MaxGoroutines || snapshot.Tasks > contract.MaxTasks {
		return transporttest.ResourceSnapshot{}, fmt.Errorf(
			"Chromium capacity resource limit exceeded: rss=%d/%d process_tree_rss=%d cgroup_memory_current=%d cgroup_memory_peak=%d sampled_rss_peak=%d accounting=%s open_fds=%d/%d goroutines=%d/%d tasks=%d/%d",
			snapshot.RSSBytes, contract.MaxRSS, controller.ProcessTree.RSSBytes,
			controller.ProcessTree.CgroupMemoryCurrent,
			controller.ProcessTree.CgroupMemoryPeak, controller.ProcessTree.SampledRSSPeak,
			controller.ProcessTree.AccountingMode, snapshot.OpenFDs, contract.MaxOpenFDs,
			snapshot.Goroutines, contract.MaxGoroutines, snapshot.Tasks, contract.MaxTasks,
		)
	}
	endpoint.resourceMu.Lock()
	phases := []string{"baseline", "ramp", "hold", "cleanup"}
	if len(endpoint.resourceSamples) >= len(phases) {
		endpoint.resourceMu.Unlock()
		return transporttest.ResourceSnapshot{}, errors.New("browser capacity captured too many producer resource samples")
	}
	endpoint.resourceSamples = append(endpoint.resourceSamples, browserCapacityProducerResourceSample{
		Phase: phases[len(endpoint.resourceSamples)], Controller: controller, Runner: runner, Aggregate: snapshot,
	})
	endpoint.resourceMu.Unlock()
	return snapshot, nil
}

func aggregateBrowserCapacityResources(runner transporttest.ResourceSnapshot, tree linuxProcessTreeSnapshot) (transporttest.ResourceSnapshot, error) {
	var browserMemory uint64
	switch tree.AccountingMode {
	case "cgroup_v2", "cgroup_v2_sampled_peak":
		if tree.CgroupMemoryCurrent == 0 || tree.CgroupMemoryPeak < tree.CgroupMemoryCurrent {
			return transporttest.ResourceSnapshot{}, errors.New("browser capacity cgroup memory counters are invalid")
		}
		browserMemory = tree.CgroupMemoryPeak
	case "pid_starttime_process_tree_fallback":
		browserMemory = max(tree.RSSBytes, tree.SampledRSSPeak)
	default:
		return transporttest.ResourceSnapshot{}, errors.New("browser capacity memory accounting mode is invalid")
	}
	if runner.At.IsZero() || tree.At.IsZero() || tree.RootPID <= 0 || tree.PGID <= 0 || tree.ProcessCount <= 0 || tree.Tasks < tree.ProcessCount ||
		runner.RSSBytes > math.MaxUint64-browserMemory || runner.CPUNanoseconds > math.MaxUint64-tree.CPUNanoseconds ||
		runner.OpenFDs > math.MaxInt-tree.OpenFDs || runner.Tasks > math.MaxInt-tree.Tasks {
		return transporttest.ResourceSnapshot{}, errors.New("browser capacity aggregate resource counters are invalid")
	}
	at := runner.At
	if tree.At.After(at) {
		at = tree.At
	}
	return transporttest.ResourceSnapshot{
		At: at, RSSBytes: runner.RSSBytes + browserMemory, CPUNanoseconds: runner.CPUNanoseconds + tree.CPUNanoseconds,
		AllocatedBytes: runner.AllocatedBytes, OpenFDs: runner.OpenFDs + tree.OpenFDs, Goroutines: runner.Goroutines, Tasks: runner.Tasks + tree.Tasks,
	}, nil
}

type browserCapacitySession struct {
	endpoint *browserCapacityEndpoint
	record   *browserCapacityRecord
	once     sync.Once
	done     chan struct{}
	err      error
}

func (session *browserCapacitySession) ID() string { return session.record.id }
func (session *browserCapacitySession) Termination() <-chan struct{} {
	return session.record.termination
}
func (session *browserCapacitySession) ProbeLiveness(ctx context.Context) error {
	session.record.mu.Lock()
	serverSession := session.record.session
	session.record.mu.Unlock()
	if serverSession == nil {
		return errors.New("browser capacity server session is unavailable")
	}
	_, err := serverSession.ProbeLiveness(ctx)
	return err
}
func (session *browserCapacitySession) Close(ctx context.Context) error {
	session.once.Do(func() {
		defer close(session.done)
		session.endpoint.streamMu.Lock()
		heldStreams := append([]flowersession.ByteStream(nil), session.endpoint.heldStreams[session.record.id]...)
		delete(session.endpoint.heldStreams, session.record.id)
		session.endpoint.streamMu.Unlock()
		var streamErr error
		for _, stream := range heldStreams {
			streamErr = errors.Join(streamErr, stream.Close())
		}
		controllerErr := session.endpoint.control.CloseSession(ctx, session.record)
		session.record.mu.Lock()
		serverSession := session.record.session
		session.record.mu.Unlock()
		var serverErr error
		if serverSession != nil {
			serverErr = closeBrowserCapacityServerSession(ctx, serverSession)
		}
		if controllerErr == nil && streamErr == nil && serverErr == nil {
			session.record.markTerminated()
			session.endpoint.broker.remove(session.record)
		}
		session.err = errors.Join(controllerErr, streamErr, serverErr)
	})
	select {
	case <-session.done:
		return session.err
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func closeBrowserCapacityServerSession(ctx context.Context, session flowersession.Session) error {
	return closeBrowserCapacityServerSessionAfter(ctx, session, 2*time.Second)
}

func closeBrowserCapacityServerSessionAfter(ctx context.Context, session flowersession.Session, peerTerminationGrace time.Duration) error {
	if peerTerminationGrace <= 0 {
		return errors.New("browser capacity peer termination grace must be positive")
	}
	select {
	case <-session.Termination():
		return normalizeBrowserCapacitySessionClose(session.WaitClosed(ctx))
	case <-time.After(peerTerminationGrace):
		// The peer close may have won the timer race. Recheck before initiating
		// the server side close so orderly GOAWAY propagation remains authoritative.
		select {
		case <-session.Termination():
			return normalizeBrowserCapacitySessionClose(session.WaitClosed(ctx))
		default:
		}
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	closed := make(chan error, 1)
	go func() { closed <- session.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			return normalizeBrowserCapacitySessionClose(err)
		}
		return normalizeBrowserCapacitySessionClose(session.WaitClosed(ctx))
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func normalizeBrowserCapacitySessionClose(err error) error {
	if errors.Is(err, flowersession.ErrSessionClosed) {
		return nil
	}
	return err
}

type remoteBrowserCapacityControl struct {
	url         string
	client      *http.Client
	sampler     *linuxProcessTreeSampler
	maxSessions int
}

func (control *remoteBrowserCapacityControl) Connect(ctx context.Context, record *browserCapacityRecord) error {
	var response struct {
		SchemaVersion int    `json:"schema_version"`
		SessionID     string `json:"session_id"`
	}
	if err := control.post(ctx, "/v1/connect", map[string]any{
		"schema_version": 1, "session_id": record.id, "token": record.token, "artifact_json": record.artifact.ArtifactJSON(),
	}, &response); err != nil {
		return err
	}
	if response.SchemaVersion != 1 || response.SessionID != record.id {
		return errors.New("browser capacity controller returned a mismatched session")
	}
	return nil
}

func (control *remoteBrowserCapacityControl) CloseSession(ctx context.Context, record *browserCapacityRecord) error {
	var response struct {
		SchemaVersion int    `json:"schema_version"`
		SessionID     string `json:"session_id"`
	}
	if err := control.post(ctx, "/v1/close", map[string]any{
		"schema_version": 1, "session_id": record.id, "token": record.token,
	}, &response); err != nil {
		return err
	}
	if response.SchemaVersion != 1 || response.SessionID != record.id {
		return errors.New("browser capacity controller returned a mismatched cleanup")
	}
	return nil
}

func (control *remoteBrowserCapacityControl) OpenStreams(ctx context.Context, sessions, streamsPerSession int) error {
	var response struct {
		SchemaVersion    int `json:"schema_version"`
		CompletedStreams int `json:"completed_streams"`
		ActiveStreams    int `json:"active_streams"`
	}
	if err := control.post(ctx, "/v1/open-streams", map[string]any{
		"schema_version": 1, "sessions": sessions, "connections_per_session": 1, "streams_per_session": streamsPerSession,
	}, &response); err != nil {
		return err
	}
	if response.SchemaVersion != 1 || response.CompletedStreams != 12800 || response.ActiveStreams != 12800 {
		return errors.New("browser capacity controller returned a mismatched stream workload")
	}
	return nil
}

func (control *remoteBrowserCapacityControl) Shutdown(ctx context.Context) error {
	return control.post(ctx, "/v1/shutdown", map[string]any{"schema_version": 1}, nil)
}

func (control *remoteBrowserCapacityControl) Quiesce(ctx context.Context) error {
	return control.post(ctx, "/v1/quiesce", map[string]any{"schema_version": 1}, nil)
}

func (control *remoteBrowserCapacityControl) Snapshot(ctx context.Context) (browserCapacityControlSnapshot, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, control.url+"/v1/snapshot", nil)
	if err != nil {
		return browserCapacityControlSnapshot{}, err
	}
	response, err := control.client.Do(request)
	if err != nil {
		return browserCapacityControlSnapshot{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return browserCapacityControlSnapshot{}, err
	}
	if response.StatusCode != http.StatusOK {
		return browserCapacityControlSnapshot{}, fmt.Errorf("browser capacity snapshot HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var snapshot browserCapacityControlSnapshot
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil || snapshot.SchemaVersion != 1 || snapshot.At.IsZero() ||
		snapshot.ActiveSessions < 0 || snapshot.ActiveSessions > control.maxSessions || snapshot.Process.RSSBytes == 0 ||
		snapshot.Process.HeapTotalBytes == 0 || snapshot.Process.HeapUsedBytes > snapshot.Process.HeapTotalBytes || snapshot.Process.MaxRSSKiB == 0 ||
		len(snapshot.Chromium) == 0 {
		return browserCapacityControlSnapshot{}, errors.New("browser capacity controller returned an invalid resource snapshot")
	}
	for name, value := range snapshot.Chromium {
		if name == "" || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return browserCapacityControlSnapshot{}, errors.New("browser capacity controller returned invalid Chromium telemetry")
		}
	}
	if control.sampler == nil {
		return browserCapacityControlSnapshot{}, errors.New("browser capacity process-tree sampler is unavailable")
	}
	tree, err := control.sampler.Snapshot()
	if err != nil {
		return browserCapacityControlSnapshot{}, err
	}
	snapshot.ProcessTree = tree
	return snapshot, nil
}

func (control *remoteBrowserCapacityControl) post(ctx context.Context, path string, input any, output any) error {
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, control.url+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := control.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("browser capacity controller HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	if output != nil {
		if err := json.Unmarshal(body, output); err != nil {
			return err
		}
	}
	return nil
}

func startBrowserCapacityControl(ctx context.Context, config browserCapacityEndpointConfig, eventSinkURL, certificateHash string) (browserCapacityControl, func(context.Context) error, []string, error) {
	temporary, err := os.MkdirTemp("", "flowersec-browser-capacity-*")
	if err != nil {
		return nil, nil, nil, err
	}
	planPath := filepath.Join(temporary, "plan.json")
	plan := map[string]any{
		"schema_version": 1, "topology": config.Topology, "profile_id": config.ProfileID, "sessions": config.Sessions,
		"workload": func() string {
			if config.StreamsPerSession > 0 {
				return "stream_capacity"
			}
			return "held_sessions"
		}(),
		"connections_per_session": 1, "streams_per_session": config.StreamsPerSession,
		"certificate_hash": certificateHash, "client_netns": config.ClientNamespace,
		"module_bind_address": config.ServerAddress, "module_advertise_host": config.ServerAddress,
		"control_bind_address": config.ServerAddress, "event_sink_url": eventSinkURL,
		"output_directory": config.OutputDirectory, "operation_deadline_ms": config.OperationDeadline.Milliseconds(),
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		_ = os.RemoveAll(temporary)
		return nil, nil, nil, err
	}
	if err := os.WriteFile(planPath, planJSON, 0o600); err != nil {
		_ = os.RemoveAll(temporary)
		return nil, nil, nil, err
	}
	node, err := exec.LookPath("node")
	if err != nil {
		_ = os.RemoveAll(temporary)
		return nil, nil, nil, err
	}
	controllerPath := filepath.Join(config.SourceRoot, "flowersec-ts", "scripts", "browser-capacity-controller.mjs")
	command := exec.Command("ip", "netns", "exec", config.ServerNamespace, node, controllerPath, "--plan", planPath)
	command.Dir = filepath.Join(config.SourceRoot, "flowersec-ts")
	preparedCgroup, err := prepareBrowserCapacityCommand(command)
	if err != nil {
		_ = os.RemoveAll(temporary)
		return nil, nil, nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = preparedCgroup.abort()
		_ = os.RemoveAll(temporary)
		return nil, nil, nil, err
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		_ = preparedCgroup.abort()
		_ = os.RemoveAll(temporary)
		return nil, nil, nil, err
	}
	if err := preparedCgroup.afterStart(); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = preparedCgroup.abort()
		_ = os.RemoveAll(temporary)
		return nil, nil, nil, err
	}
	sampler, err := newLinuxProcessTreeSampler(command.Process.Pid, preparedCgroup.path, preparedCgroup.fallbackReason)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = preparedCgroup.abort()
		_ = os.RemoveAll(temporary)
		return nil, nil, nil, err
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	ready := make(chan struct {
		URL string
		Err error
	}, 1)
	go func() {
		var envelope struct {
			SchemaVersion int    `json:"schema_version"`
			Status        string `json:"status"`
			ControlURL    string `json:"control_url"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(stdout, 64<<10)).Decode(&envelope)
		if decodeErr == nil && (envelope.SchemaVersion != 1 || envelope.Status != "ready" || envelope.ControlURL == "") {
			decodeErr = errors.New("browser capacity controller returned an invalid startup envelope")
		}
		ready <- struct {
			URL string
			Err error
		}{URL: envelope.ControlURL, Err: decodeErr}
	}()
	startupTimer := time.NewTimer(config.OperationDeadline)
	defer startupTimer.Stop()
	var controlURL string
	select {
	case result := <-ready:
		if result.Err != nil {
			_ = sampler.Kill()
			<-waitDone
			_ = sampler.Close()
			_ = os.RemoveAll(temporary)
			return nil, nil, nil, fmt.Errorf("start browser capacity controller: %w: %s", result.Err, strings.TrimSpace(stderr.String()))
		}
		controlURL = result.URL
	case err := <-waitDone:
		_ = sampler.Kill()
		_ = sampler.Close()
		_ = os.RemoveAll(temporary)
		return nil, nil, nil, fmt.Errorf("browser capacity controller exited during startup: %w: %s", err, strings.TrimSpace(stderr.String()))
	case <-startupTimer.C:
		_ = sampler.Kill()
		<-waitDone
		_ = sampler.Close()
		_ = os.RemoveAll(temporary)
		return nil, nil, nil, errors.New("browser capacity controller startup deadline exceeded")
	case <-ctx.Done():
		_ = sampler.Kill()
		<-waitDone
		_ = sampler.Close()
		_ = os.RemoveAll(temporary)
		return nil, nil, nil, context.Cause(ctx)
	}
	control := &remoteBrowserCapacityControl{url: controlURL, client: &http.Client{Transport: &http.Transport{DisableKeepAlives: false, MaxIdleConnsPerHost: 1000}}, sampler: sampler, maxSessions: config.Sessions}
	wait := func(waitCtx context.Context) error {
		select {
		case waitErr := <-waitDone:
			var killErr error
			if waitErr != nil {
				killErr = sampler.Kill()
			}
			stderrErr := writeBrowserCapacityStderr(config.OutputDirectory, stderr.Bytes())
			samplerErr := sampler.Close()
			removeErr := os.RemoveAll(temporary)
			return errors.Join(waitErr, killErr, stderrErr, samplerErr, removeErr)
		case <-waitCtx.Done():
			killErr := sampler.Kill()
			waitErr := <-waitDone
			stderrErr := writeBrowserCapacityStderr(config.OutputDirectory, stderr.Bytes())
			samplerErr := sampler.Close()
			removeErr := os.RemoveAll(temporary)
			return errors.Join(context.Cause(waitCtx), killErr, waitErr, stderrErr, samplerErr, removeErr)
		}
	}
	output := []string{
		filepath.Join(config.OutputDirectory, "chromium-netlog.json"),
		filepath.Join(config.OutputDirectory, "chromium-trace.zip"),
		filepath.Join(config.OutputDirectory, "controller-result.json"),
		filepath.Join(config.OutputDirectory, "controller-config.json"),
		filepath.Join(config.OutputDirectory, "producer-resource.json"),
	}
	return control, wait, output, nil
}

func writeBrowserCapacityStderr(directory string, value []byte) error {
	if len(bytes.TrimSpace(value)) == 0 {
		return nil
	}
	return os.WriteFile(filepath.Join(directory, "controller-stderr.log"), value, 0o600)
}
