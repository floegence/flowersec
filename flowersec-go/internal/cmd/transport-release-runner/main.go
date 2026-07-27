package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/linuxnetlab"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/tunnelworkload"
)

const (
	baselineTarget      = "direct-clean-baseline"
	networkCellTarget   = "direct-network-profile-cell"
	tunnelCellTarget    = "tunnel-network-profile-cell"
	browserCellTarget   = "browser-webtransport-cell"
	adaptiveCellTarget  = "adaptive-selection-cell"
	caseSuiteTarget     = "release-case-suite"
	networkWorkerArg    = "--network-cell-worker"
	systemWorkerArg     = "--weaknet-system-worker"
	browserWorkerArg    = "--browser-cell-worker"
	networkModeDirect   = "direct"
	networkModeTunnel   = "tunnel"
	networkModeAdaptive = "adaptive"
)

var gitSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type baselineReport struct {
	SchemaVersion   int                     `json:"schema_version"`
	Classification  string                  `json:"classification"`
	SourceSHA       string                  `json:"source_sha"`
	ManifestDigest  string                  `json:"manifest_digest"`
	ManifestSHA256  string                  `json:"manifest_file_sha256"`
	BPFObjectSHA256 string                  `json:"bpf_object_sha256"`
	Runner          baselineRunner          `json:"runner"`
	StartedAt       time.Time               `json:"started_at"`
	FinishedAt      time.Time               `json:"finished_at"`
	Results         []baselineCarrierResult `json:"results"`
}

type networkCellReport struct {
	SchemaVersion   int                          `json:"schema_version"`
	Classification  string                       `json:"classification"`
	SourceSHA       string                       `json:"source_sha"`
	ManifestDigest  string                       `json:"manifest_digest"`
	ManifestSHA256  string                       `json:"manifest_file_sha256"`
	Runner          baselineRunner               `json:"runner"`
	ProfileID       string                       `json:"profile_id"`
	Network         transportrelease.NetworkPlan `json:"network"`
	Fault           transportrelease.FaultPlan   `json:"fault_plan"`
	BPFObjectSHA256 string                       `json:"bpf_object_sha256"`
	StartedAt       time.Time                    `json:"started_at"`
	FinishedAt      time.Time                    `json:"finished_at"`
	Results         []baselineCarrierResult      `json:"results"`
}

type tunnelCellReport struct {
	SchemaVersion   int                          `json:"schema_version"`
	Classification  string                       `json:"classification"`
	SourceSHA       string                       `json:"source_sha"`
	ManifestDigest  string                       `json:"manifest_digest"`
	ManifestSHA256  string                       `json:"manifest_file_sha256"`
	Runner          baselineRunner               `json:"runner"`
	ProfileID       string                       `json:"profile_id"`
	Network         transportrelease.NetworkPlan `json:"network"`
	Fault           transportrelease.FaultPlan   `json:"fault_plan"`
	Topology        tunnelworkload.Topology      `json:"topology"`
	BPFObjectSHA256 string                       `json:"bpf_object_sha256"`
	StartedAt       time.Time                    `json:"started_at"`
	FinishedAt      time.Time                    `json:"finished_at"`
	Results         []tunnelCarrierResult        `json:"results"`
}

type browserCellReport struct {
	SchemaVersion   int                          `json:"schema_version"`
	Classification  string                       `json:"classification"`
	SourceSHA       string                       `json:"source_sha"`
	ManifestDigest  string                       `json:"manifest_digest"`
	ManifestSHA256  string                       `json:"manifest_file_sha256"`
	Runner          baselineRunner               `json:"runner"`
	ProfileID       string                       `json:"profile_id"`
	Network         transportrelease.NetworkPlan `json:"network"`
	Fault           transportrelease.FaultPlan   `json:"fault_plan"`
	Topology        string                       `json:"topology"`
	BPFObjectSHA256 string                       `json:"bpf_object_sha256,omitempty"`
	StartedAt       time.Time                    `json:"started_at"`
	FinishedAt      time.Time                    `json:"finished_at"`
	Results         []browserCellResult          `json:"results"`
}

type browserCellResult struct {
	Run       int                 `json:"run"`
	Workload  json.RawMessage     `json:"workload"`
	Kernel    networkKernelResult `json:"kernel"`
	Artifacts []releaseArtifact   `json:"artifacts"`
}

type baselineRunner struct {
	OS            string `json:"os"`
	Architecture  string `json:"architecture"`
	KernelRelease string `json:"kernel_release"`
}

type baselineCarrierResult struct {
	Run             int                                  `json:"run"`
	Carrier         string                               `json:"carrier"`
	Cold            []transportrelease.ConnectOperation  `json:"cold"`
	RPC             []transportrelease.Operation         `json:"rpc"`
	Bulk            transportrelease.BulkResult          `json:"bulk"`
	CleanupDuration time.Duration                        `json:"cleanup_duration_ns"`
	Resource        transportrelease.ResourceMeasurement `json:"resource"`
	Phases          []baselinePhaseMeasurement           `json:"phases"`
	Kernel          *networkKernelResult                 `json:"kernel,omitempty"`
	Artifacts       []releaseArtifact                    `json:"artifacts"`
}

type baselinePhaseMeasurement struct {
	Phase         string                               `json:"phase"`
	Resource      transportrelease.ResourceMeasurement `json:"resource"`
	ActiveStreams int                                  `json:"active_streams"`
	KernelStart   *linuxnetlab.KernelFaultEvidence     `json:"kernel_start,omitempty"`
	KernelFinish  *linuxnetlab.KernelFaultEvidence     `json:"kernel_finish,omitempty"`
}

type networkKernelResult struct {
	ClientNamespace string                          `json:"client_namespace"`
	ServerNamespace string                          `json:"server_namespace"`
	ClientInterface string                          `json:"client_interface"`
	ServerInterface string                          `json:"server_interface"`
	ClientAddress   string                          `json:"client_address"`
	ServerAddress   string                          `json:"server_address"`
	Faults          linuxnetlab.KernelFaultEvidence `json:"faults"`
}

type networkWorkerRequest struct {
	Mode               string                               `json:"mode"`
	Kind               carrier.Kind                         `json:"kind"`
	Topology           tunnelworkload.Topology              `json:"topology"`
	AdaptiveCandidates []transportrelease.AdaptiveCandidate `json:"adaptive_candidates,omitempty"`
	Plan               transportrelease.ProfilePlan         `json:"plan"`
	ClientNamespace    string                               `json:"client_namespace"`
	ServerNamespace    string                               `json:"server_namespace"`
	ServerAddress      string                               `json:"server_address"`
	KernelCounters     bool                                 `json:"kernel_counters,omitempty"`
}

type tunnelCarrierResult struct {
	Run       int                                  `json:"run"`
	Workload  tunnelworkload.Result                `json:"workload"`
	Resource  transportrelease.ResourceMeasurement `json:"resource"`
	Kernel    *networkKernelResult                 `json:"kernel,omitempty"`
	Artifacts []releaseArtifact                    `json:"artifacts"`
}

var networkWorkerArguments = func() []string { return []string{networkWorkerArg} }

func main() {
	if len(os.Args) == 2 && os.Args[1] == browserWorkerArg {
		workerContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stopSignals()
		if err := runBrowserWorkerWithContext(workerContext, os.Stdin, os.Stdout); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == networkWorkerArg {
		if err := runNetworkWorker(os.Stdin, os.Stdout); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == systemWorkerArg {
		if err := runWeaknetSystemWorker(os.Stdin, os.Stdout); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	runnerContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopSignals()
	if err := runWithContext(runnerContext, os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) (resultErr error) {
	return runWithContext(context.Background(), args)
}

func supportedLinuxRunnerArchitecture(goos, goarch string) bool {
	if goos != "linux" {
		return false
	}
	switch goarch {
	case "amd64", "arm64":
		return true
	default:
		return false
	}
}

func runWithContext(runnerContext context.Context, args []string) (resultErr error) {
	if runnerContext == nil {
		return errors.New("runner context is required")
	}
	flags := flag.NewFlagSet("transport-release-runner", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	target := flags.String("target", "", "runner target")
	manifestPath := flags.String("manifest", "", "performance manifest path")
	reportPath := flags.String("report", "", "new baseline report path")
	sourceSHA := flags.String("source-sha", "", "exact source commit")
	sourceRoot := flags.String("source-root", "", "clean source checkout root")
	profileID := flags.String("profile", "", "frozen network profile")
	carrierName := flags.String("carrier", "", "direct carrier")
	topologyName := flags.String("topology", "", "tunnel carrier topology")
	bpfObject := flags.String("bpf-object", "", "compiled packet-fault eBPF object")
	artifactDir := flags.String("artifact-dir", "", "existing empty release artifact directory")
	caseOwner := flags.String("case-owner", "", "registered case owner")
	caseMode := flags.String("case-mode", "", "normal or race case execution mode")
	caseID := flags.String("case-id", "", "exact registered case")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if (*target != baselineTarget && *target != networkCellTarget && *target != tunnelCellTarget && *target != browserCellTarget && *target != adaptiveCellTarget && *target != caseSuiteTarget) || *manifestPath == "" || *reportPath == "" || *artifactDir == "" || !gitSHAPattern.MatchString(*sourceSHA) || *sourceRoot == "" || flags.NArg() != 0 {
		return errors.New("runner requires a supported --target, --manifest, --report, --artifact-dir, --source-root, and a full --source-sha")
	}
	destination, err := newArtifactDestination(*artifactDir, *reportPath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, destination.Close()) }()
	if !supportedLinuxRunnerArchitecture(runtime.GOOS, runtime.GOARCH) {
		return errors.New("direct clean baseline requires Linux amd64 or arm64")
	}
	if err := verifySourceCheckout(*sourceRoot, *manifestPath, *sourceSHA); err != nil {
		return err
	}
	plan, manifest, err := transportrelease.LoadReleasePlan(*manifestPath)
	if err != nil {
		return err
	}
	if *target == caseSuiteTarget {
		if *profileID != "" || *carrierName != "" || *topologyName != "" {
			return errors.New("release case suite does not accept performance profile or topology flags")
		}
		needsBPF := *caseOwner == quicNativeProofOwner || *caseOwner == "weaknet-system" || *caseOwner == "quic-native-race"
		if needsBPF != (*bpfObject != "") {
			return errors.New("release case suite BPF object does not match its owner")
		}
		return runCaseSuite(runnerContext, *reportPath, destination, *sourceSHA, *sourceRoot, *caseOwner, *caseMode, *caseID, *bpfObject, plan, manifest)
	}
	if *caseOwner != "" || *caseMode != "" || *caseID != "" {
		return errors.New("performance cell targets do not accept case owner, mode, or ID")
	}
	if *target == networkCellTarget {
		if *topologyName != "" {
			return errors.New("direct network profile cell does not accept --topology")
		}
		return runNetworkCell(*reportPath, destination, *sourceSHA, *profileID, carrier.Kind(*carrierName), *bpfObject, plan, manifest)
	}
	if *target == tunnelCellTarget {
		if *carrierName != "" {
			return errors.New("tunnel network profile cell does not accept --carrier")
		}
		return runTunnelCell(*reportPath, destination, *sourceSHA, *profileID, tunnelworkload.Topology(*topologyName), *bpfObject, plan, manifest)
	}
	if *target == browserCellTarget {
		if *carrierName != "" {
			return errors.New("browser WebTransport cell does not accept --carrier")
		}
		return runBrowserCell(*reportPath, destination, *sourceSHA, *sourceRoot, *profileID, *topologyName, *bpfObject, plan, manifest)
	}
	if *target == adaptiveCellTarget {
		if *carrierName != "" {
			return errors.New("adaptive selection cell does not accept --carrier")
		}
		return runAdaptiveCell(*reportPath, destination, *sourceSHA, *profileID, *topologyName, *bpfObject, plan, manifest)
	}
	if *profileID != "" || *carrierName != "" || *topologyName != "" || *bpfObject == "" {
		return errors.New("direct clean baseline requires --bpf-object and does not accept network profile flags")
	}
	bpfBytes, err := linuxnetlab.ReadVerifiedBPFObject(*bpfObject)
	if err != nil {
		return err
	}
	frozenBPFObject, cleanupBPFObject, err := freezeBPFObject(bpfBytes)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, cleanupBPFObject()) }()
	bpfDigest := sha256.Sum256(bpfBytes)
	kernel, err := kernelRelease()
	if err != nil {
		return err
	}
	report := baselineReport{
		SchemaVersion: 1, Classification: "linux_transport_workload_baseline",
		SourceSHA: *sourceSHA, ManifestDigest: manifest.Digest,
		ManifestSHA256: hex.EncodeToString(manifest.SHA256Sum[:]), BPFObjectSHA256: hex.EncodeToString(bpfDigest[:]),
		Runner:    baselineRunner{OS: runtime.GOOS, Architecture: runtime.GOARCH, KernelRelease: kernel},
		StartedAt: time.Now().UTC(),
	}
	cellDeadline := time.Duration(plan.Clean.CellWatchdogMinutes) * time.Minute
	globalCtx, cancel := context.WithTimeout(context.Background(), 3*cellDeadline)
	defer cancel()
	for _, cell := range workloadSchedule(plan.RunCount) {
		cellCtx, cancelCell := context.WithTimeout(globalCtx, cellDeadline)
		cellStarted := time.Now()
		for _, runNumber := range cell.Runs {
			result, err := runNetworkCarrier(cellCtx, cell.Carrier, plan.Clean, runNumber, frozenBPFObject, destination)
			if err != nil {
				cancelCell()
				return fmt.Errorf("%s run %d baseline: %w", cell.Carrier, runNumber, err)
			}
			result.Run = runNumber
			report.Results = append(report.Results, result)
		}
		deadlineErr := completedWithin(cellCtx, cellStarted, cellDeadline)
		cancelCell()
		if deadlineErr != nil {
			return fmt.Errorf("%s cell watchdog: %w", cell.Carrier, deadlineErr)
		}
	}
	report.FinishedAt = time.Now().UTC()
	if err := destination.Verify(); err != nil {
		return err
	}
	return writeNewReport(*reportPath, report)
}

type scheduledCell struct {
	Carrier carrier.Kind
	Runs    []int
}

func workloadSchedule(runCount int) []scheduledCell {
	carriers := []carrier.Kind{carrier.KindWebSocket, carrier.KindQUIC, carrier.KindWebTransport}
	schedule := make([]scheduledCell, 0, len(carriers))
	for _, kind := range carriers {
		cell := scheduledCell{Carrier: kind, Runs: make([]int, 0, runCount)}
		for run := 1; run <= runCount; run++ {
			cell.Runs = append(cell.Runs, run)
		}
		schedule = append(schedule, cell)
	}
	return schedule
}

func runCarrier(ctx context.Context, kind carrier.Kind, plan transportrelease.ProfilePlan) (baselineCarrierResult, error) {
	endpoint, err := transportrelease.OpenProductDirectEndpoint(ctx, kind)
	if err != nil {
		return baselineCarrierResult{}, err
	}
	return runEndpointCarrier(ctx, endpoint, kind, plan, nil)
}

type kernelEvidenceSampler func(context.Context) (linuxnetlab.KernelFaultEvidence, error)

func runEndpointCarrier(ctx context.Context, endpoint *transportrelease.ProductDirectEndpoint, kind carrier.Kind, plan transportrelease.ProfilePlan, sampleKernel kernelEvidenceSampler) (baselineCarrierResult, error) {
	resourceStart, err := transportrelease.CaptureResourceSnapshot()
	if err != nil {
		return baselineCarrierResult{}, err
	}
	endpointClosed := false
	defer func() {
		if !endpointClosed {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = closeWithin(cleanupCtx, endpoint.Close)
			cancel()
		}
	}()
	phases := make([]baselinePhaseMeasurement, 0, 4)
	var phaseKernelStart *linuxnetlab.KernelFaultEvidence
	startPhase := func() error {
		phaseKernelStart = nil
		if sampleKernel == nil {
			return nil
		}
		snapshot, err := sampleKernel(ctx)
		if err != nil {
			return err
		}
		phaseKernelStart = &snapshot
		return nil
	}
	finishPhase := func(name string, start transportrelease.ResourceSnapshot, activeStreams int) error {
		finish, err := transportrelease.CaptureResourceSnapshot()
		if err != nil {
			return err
		}
		measurement, err := transportrelease.CompleteResourceMeasurement(start, finish)
		if err != nil {
			return err
		}
		var kernelFinish *linuxnetlab.KernelFaultEvidence
		if sampleKernel != nil {
			snapshot, err := sampleKernel(ctx)
			if err != nil {
				return err
			}
			kernelFinish = &snapshot
		}
		phases = append(phases, baselinePhaseMeasurement{Phase: name, Resource: measurement, ActiveStreams: activeStreams, KernelStart: phaseKernelStart, KernelFinish: kernelFinish})
		return nil
	}
	if err := startPhase(); err != nil {
		return baselineCarrierResult{}, err
	}
	coldResourceStart, err := transportrelease.CaptureResourceSnapshot()
	if err != nil {
		return baselineCarrierResult{}, err
	}
	coldLimit := time.Duration(plan.Cold.PhaseDeadlineSeconds) * time.Second
	coldCtx, cancelCold := context.WithTimeout(ctx, coldLimit)
	coldStarted := time.Now()
	cold, err := transportrelease.RunCold(
		coldCtx, endpoint, plan.Cold.Operations, plan.Cold.MaxInflight, plan.Cold.StartRatePerSecond,
		time.Duration(plan.Cold.OperationDeadlineSeconds)*time.Second,
	)
	deadlineErr := completedWithin(coldCtx, coldStarted, coldLimit)
	cancelCold()
	if err != nil || deadlineErr != nil {
		return baselineCarrierResult{}, errors.Join(err, deadlineErr)
	}
	if err := finishPhase("cold", coldResourceStart, 0); err != nil {
		return baselineCarrierResult{}, err
	}
	if err := startPhase(); err != nil {
		return baselineCarrierResult{}, err
	}
	rpcResourceStart, err := transportrelease.CaptureResourceSnapshot()
	if err != nil {
		return baselineCarrierResult{}, err
	}
	rpcLimit := time.Duration(plan.RPC.PhaseDeadlineSeconds) * time.Second
	rpcCtx, cancelRPC := context.WithTimeout(ctx, rpcLimit)
	rpcStarted := time.Now()
	pair, err := endpoint.Connect(rpcCtx)
	if err != nil {
		cancelRPC()
		return baselineCarrierResult{}, err
	}
	pairClosed := false
	defer func() {
		if !pairClosed {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = closeWithin(cleanupCtx, pair.Close)
			cancel()
		}
	}()
	rpc, err := transportrelease.RunRPC(
		rpcCtx, pair, plan.RPC.Operations, plan.RPC.Workers, plan.RPC.RequestBytes,
		time.Duration(plan.RPC.OperationDeadlineSeconds)*time.Second,
	)
	deadlineErr = completedWithin(rpcCtx, rpcStarted, rpcLimit)
	cancelRPC()
	if err != nil || deadlineErr != nil {
		return baselineCarrierResult{}, errors.Join(err, deadlineErr)
	}
	if err := finishPhase("rpc", rpcResourceStart, 0); err != nil {
		return baselineCarrierResult{}, err
	}
	if err := startPhase(); err != nil {
		return baselineCarrierResult{}, err
	}
	bulkResourceStart, err := transportrelease.CaptureResourceSnapshot()
	if err != nil {
		return baselineCarrierResult{}, err
	}
	bulkLimit := time.Duration(plan.Bulk.PhaseDeadlineSeconds) * time.Second
	bulkCtx, cancelBulk := context.WithTimeout(ctx, bulkLimit)
	bulkStarted := time.Now()
	bulk, err := transportrelease.RunBulk(bulkCtx, pair, plan.Bulk.WarmupBytesPerDirection, plan.Bulk.ScoreBytesPerDirection)
	deadlineErr = completedWithin(bulkCtx, bulkStarted, bulkLimit)
	cancelBulk()
	if err != nil || deadlineErr != nil {
		return baselineCarrierResult{}, errors.Join(err, deadlineErr)
	}
	if err := finishPhase("bulk", bulkResourceStart, bulk.ActiveStreams); err != nil {
		return baselineCarrierResult{}, err
	}
	if err := startPhase(); err != nil {
		return baselineCarrierResult{}, err
	}
	cleanupResourceStart, err := transportrelease.CaptureResourceSnapshot()
	if err != nil {
		return baselineCarrierResult{}, err
	}
	cleanupStarted := time.Now()
	cleanupLimit := time.Duration(plan.CleanupDeadlineSeconds) * time.Second
	cleanupCtx, cancelCleanup := context.WithTimeout(ctx, cleanupLimit)
	pairClosed = true
	endpointClosed = true
	err = closeWithin(cleanupCtx, func() error { return errors.Join(pair.Close(), endpoint.Close()) })
	deadlineErr = completedWithin(cleanupCtx, cleanupStarted, cleanupLimit)
	cancelCleanup()
	if err != nil || deadlineErr != nil {
		return baselineCarrierResult{}, errors.Join(err, deadlineErr)
	}
	if err := finishPhase("cleanup", cleanupResourceStart, 0); err != nil {
		return baselineCarrierResult{}, err
	}
	resourceFinish, err := transportrelease.CaptureResourceSnapshot()
	if err != nil {
		return baselineCarrierResult{}, err
	}
	resource, err := transportrelease.CompleteResourceMeasurement(resourceStart, resourceFinish)
	if err != nil {
		return baselineCarrierResult{}, err
	}
	return baselineCarrierResult{
		Carrier: string(kind), Cold: cold, RPC: rpc, Bulk: bulk,
		CleanupDuration: time.Since(cleanupStarted), Resource: resource, Phases: phases,
	}, nil
}

func runNetworkCell(reportPath string, destination *artifactDestination, sourceSHA, profileID string, kind carrier.Kind, bpfObject string, plan transportrelease.ReleasePlan, manifest transportrelease.ManifestBinding) (resultErr error) {
	if profileID != "mobile-v1" && profileID != "edge-v1" {
		return errors.New("network profile cell requires mobile-v1 or edge-v1")
	}
	if err := kind.Validate(); err != nil {
		return err
	}
	if bpfObject == "" {
		return errors.New("network profile cell requires --bpf-object")
	}
	bpfBytes, err := linuxnetlab.ReadVerifiedBPFObject(bpfObject)
	if err != nil {
		return err
	}
	frozenBPFObject, cleanupBPFObject, err := freezeBPFObject(bpfBytes)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, cleanupBPFObject()) }()
	bpfDigest := sha256.Sum256(bpfBytes)
	profile := plan.Mobile
	if profileID == "edge-v1" {
		profile = plan.Edge
	}
	kernel, err := kernelRelease()
	if err != nil {
		return err
	}
	report := networkCellReport{
		SchemaVersion: 1, Classification: "linux_kernel_network_profile",
		SourceSHA: sourceSHA, ManifestDigest: manifest.Digest,
		ManifestSHA256: hex.EncodeToString(manifest.SHA256Sum[:]),
		Runner:         baselineRunner{OS: runtime.GOOS, Architecture: runtime.GOARCH, KernelRelease: kernel},
		ProfileID:      profile.ID, Network: profile.Network, Fault: profile.Fault,
		BPFObjectSHA256: hex.EncodeToString(bpfDigest[:]), StartedAt: time.Now().UTC(),
	}
	cellDeadline := time.Duration(profile.CellWatchdogMinutes) * time.Minute
	cellCtx, cancelCell := context.WithTimeout(context.Background(), cellDeadline)
	defer cancelCell()
	cellStarted := time.Now()
	for runNumber := 1; runNumber <= plan.RunCount; runNumber++ {
		result, err := runNetworkCarrier(cellCtx, kind, profile, runNumber, frozenBPFObject, destination)
		if err != nil {
			return fmt.Errorf("%s %s run %d: %w", profile.ID, kind, runNumber, err)
		}
		result.Run = runNumber
		report.Results = append(report.Results, result)
	}
	if err := completedWithin(cellCtx, cellStarted, cellDeadline); err != nil {
		return fmt.Errorf("%s %s cell watchdog: %w", profile.ID, kind, err)
	}
	report.FinishedAt = time.Now().UTC()
	if err := destination.Verify(); err != nil {
		return err
	}
	return writeNewReport(reportPath, report)
}

func freezeBPFObject(value []byte) (path string, cleanup func() error, resultErr error) {
	if len(value) == 0 {
		return "", nil, errors.New("BPF object bytes are required")
	}
	directory, err := os.MkdirTemp("", "flowersec-release-bpf-*")
	if err != nil {
		return "", nil, err
	}
	completed := false
	defer func() {
		if !completed {
			resultErr = errors.Join(resultErr, os.RemoveAll(directory))
		}
	}()
	path = filepath.Join(directory, "packet_fault.o")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", nil, err
	}
	if _, err := file.Write(value); err != nil {
		_ = file.Close()
		return "", nil, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", nil, err
	}
	if err := file.Close(); err != nil {
		return "", nil, err
	}
	if err := os.Chmod(path, 0o400); err != nil {
		return "", nil, err
	}
	completed = true
	return path, func() error { return os.RemoveAll(directory) }, nil
}

func runNetworkCarrier(ctx context.Context, kind carrier.Kind, plan transportrelease.ProfilePlan, runNumber int, bpfObject string, destination *artifactDestination) (result baselineCarrierResult, resultErr error) {
	cellID := strings.ReplaceAll(plan.ID+"-"+string(kind), "_", "-")
	config, err := linuxnetlab.ConfigForCell(cellID, runNumber, plan.Network.LinkMTU, plan.Network.Firewall)
	if err != nil {
		return result, err
	}
	lab, err := linuxnetlab.Open(ctx, linuxnetlab.ExecRunner{}, config)
	if err != nil {
		return result, err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Duration(plan.CleanupDeadlineSeconds)*time.Second)
		resultErr = errors.Join(resultErr, lab.Close(cleanupCtx))
		cancel()
	}()
	if bpfObject != "" {
		profile, err := faultProfileFromPlan(plan, bpfObject)
		if err != nil {
			return result, err
		}
		if err := lab.ApplyFaultProfile(ctx, profile); err != nil {
			return result, err
		}
	} else if plan.ID != "clean-v1" {
		return result, errors.New("only the clean profile may run without a BPF object")
	}
	var runArtifacts *runEvidence
	if destination != nil {
		label := fmt.Sprintf("%s-%s-run-%03d", plan.ID, strings.ReplaceAll(string(kind), "_", "-"), runNumber)
		runArtifacts, err = startRunEvidence(ctx, destination, label, config.ClientNamespace, config.ClientInterface)
		if err != nil {
			return result, err
		}
		defer func() {
			artifacts, finishErr := runArtifacts.Finish()
			result.Artifacts = artifacts
			resultErr = errors.Join(resultErr, finishErr)
		}()
	}
	executable, err := os.Executable()
	if err != nil {
		return result, err
	}
	request := networkWorkerRequest{
		Mode: networkModeDirect, Kind: kind, Plan: plan, ClientNamespace: config.ClientNamespace, ServerNamespace: config.ServerNamespace,
		ServerAddress: config.ServerAddress.Addr().String(), KernelCounters: bpfObject != "",
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return result, err
	}
	arguments := append([]string{"netns", "exec", config.ClientNamespace, executable}, networkWorkerArguments()...)
	command := exec.CommandContext(ctx, "ip", arguments...)
	if runArtifacts != nil {
		command.Env = commandEnvironmentWithQLOG(runArtifacts.qlogDir)
	}
	command.Stdin = bytes.NewReader(requestJSON)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		if bpfObject == "" {
			return result, fmt.Errorf("network worker: %w: stdout=%s stderr=%s", err, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()))
		}
		evidenceCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		evidence, evidenceErr := lab.FaultEvidence(evidenceCtx)
		cancel()
		return result, fmt.Errorf("network worker: %w: stdout=%s stderr=%s kernel_evidence=%+v evidence_error=%v", err, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()), evidence, evidenceErr)
	}
	if err := json.NewDecoder(&stdout).Decode(&result); err != nil {
		return result, fmt.Errorf("decode network worker result: %w", err)
	}
	if result.Carrier != string(kind) {
		return result, errors.New("network worker returned the wrong carrier")
	}
	var evidence linuxnetlab.KernelFaultEvidence
	if bpfObject != "" {
		evidenceCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		evidence, err = lab.FaultEvidence(evidenceCtx)
		cancel()
		if err != nil {
			return result, err
		}
		if err := validateKernelEvidence(plan, evidence); err != nil {
			return result, err
		}
	}
	result.Kernel = &networkKernelResult{
		ClientNamespace: config.ClientNamespace, ServerNamespace: config.ServerNamespace,
		ClientInterface: config.ClientInterface, ServerInterface: config.ServerInterface,
		ClientAddress: config.ClientAddress.String(), ServerAddress: config.ServerAddress.String(),
		Faults: evidence,
	}
	return result, nil
}

func runTunnelCell(reportPath string, destination *artifactDestination, sourceSHA, profileID string, topology tunnelworkload.Topology, bpfObject string, plan transportrelease.ReleasePlan, manifest transportrelease.ManifestBinding) (resultErr error) {
	if _, _, err := topology.Carriers(); err != nil {
		return err
	}
	profile, err := tunnelProfile(plan, profileID, bpfObject)
	if err != nil {
		return err
	}
	frozenBPFObject := ""
	bpfDigest := ""
	if bpfObject != "" {
		bpfBytes, err := linuxnetlab.ReadVerifiedBPFObject(bpfObject)
		if err != nil {
			return err
		}
		var cleanupBPFObject func() error
		frozenBPFObject, cleanupBPFObject, err = freezeBPFObject(bpfBytes)
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, cleanupBPFObject()) }()
		digest := sha256.Sum256(bpfBytes)
		bpfDigest = hex.EncodeToString(digest[:])
	}
	kernel, err := kernelRelease()
	if err != nil {
		return err
	}
	report := tunnelCellReport{
		SchemaVersion: 1, Classification: "linux_kernel_tunnel_network_profile",
		SourceSHA: sourceSHA, ManifestDigest: manifest.Digest,
		ManifestSHA256: hex.EncodeToString(manifest.SHA256Sum[:]),
		Runner:         baselineRunner{OS: runtime.GOOS, Architecture: runtime.GOARCH, KernelRelease: kernel},
		ProfileID:      profile.ID, Network: profile.Network, Fault: profile.Fault, Topology: topology,
		BPFObjectSHA256: bpfDigest, StartedAt: time.Now().UTC(),
	}
	cellDeadline := time.Duration(profile.CellWatchdogMinutes) * time.Minute
	cellCtx, cancelCell := context.WithTimeout(context.Background(), cellDeadline)
	defer cancelCell()
	cellStarted := time.Now()
	for runNumber := 1; runNumber <= plan.RunCount; runNumber++ {
		result, err := runNetworkTunnel(cellCtx, topology, profile, runNumber, frozenBPFObject, destination)
		if err != nil {
			return fmt.Errorf("%s %s run %d: %w", profile.ID, topology, runNumber, err)
		}
		result.Run = runNumber
		report.Results = append(report.Results, result)
	}
	if err := completedWithin(cellCtx, cellStarted, cellDeadline); err != nil {
		return fmt.Errorf("%s %s cell watchdog: %w", profile.ID, topology, err)
	}
	report.FinishedAt = time.Now().UTC()
	if err := destination.Verify(); err != nil {
		return err
	}
	return writeNewReport(reportPath, report)
}

func tunnelProfile(plan transportrelease.ReleasePlan, profileID, bpfObject string) (transportrelease.ProfilePlan, error) {
	switch profileID {
	case "clean-v1":
		if bpfObject != "" {
			return transportrelease.ProfilePlan{}, errors.New("clean tunnel cell does not accept a BPF object")
		}
		return plan.Clean, nil
	case "mobile-v1":
		if bpfObject == "" {
			return transportrelease.ProfilePlan{}, errors.New("mobile tunnel cell requires a BPF object")
		}
		return plan.Mobile, nil
	case "edge-v1":
		if bpfObject == "" {
			return transportrelease.ProfilePlan{}, errors.New("edge tunnel cell requires a BPF object")
		}
		return plan.Edge, nil
	default:
		return transportrelease.ProfilePlan{}, errors.New("tunnel cell requires clean-v1, mobile-v1, or edge-v1")
	}
}

func runNetworkTunnel(ctx context.Context, topology tunnelworkload.Topology, plan transportrelease.ProfilePlan, runNumber int, bpfObject string, destination *artifactDestination) (result tunnelCarrierResult, resultErr error) {
	cellID := strings.ToLower(plan.ID + "-tunnel-" + string(topology))
	config, err := linuxnetlab.ConfigForCell(cellID, runNumber, plan.Network.LinkMTU, plan.Network.Firewall)
	if err != nil {
		return result, err
	}
	lab, err := linuxnetlab.Open(ctx, linuxnetlab.ExecRunner{}, config)
	if err != nil {
		return result, err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Duration(plan.CleanupDeadlineSeconds)*time.Second)
		resultErr = errors.Join(resultErr, lab.Close(cleanupCtx))
		cancel()
	}()
	if bpfObject != "" {
		profile, err := faultProfileFromPlan(plan, bpfObject)
		if err != nil {
			return result, err
		}
		if err := lab.ApplyFaultProfile(ctx, profile); err != nil {
			return result, err
		}
	} else if plan.ID != "clean-v1" {
		return result, errors.New("only the clean tunnel profile may run without a BPF object")
	}
	var runArtifacts *runEvidence
	if destination != nil {
		label := fmt.Sprintf("%s-tunnel-%s-run-%03d", plan.ID, strings.ToLower(string(topology)), runNumber)
		runArtifacts, err = startRunEvidence(ctx, destination, label, config.ClientNamespace, config.ClientInterface)
		if err != nil {
			return result, err
		}
		defer func() {
			artifacts, finishErr := runArtifacts.Finish()
			result.Artifacts = artifacts
			resultErr = errors.Join(resultErr, finishErr)
		}()
	}
	executable, err := os.Executable()
	if err != nil {
		return result, err
	}
	request := networkWorkerRequest{
		Mode: networkModeTunnel, Topology: topology, Plan: plan,
		ClientNamespace: config.ClientNamespace, ServerNamespace: config.ServerNamespace,
		ServerAddress: config.ServerAddress.Addr().String(),
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return result, err
	}
	arguments := append([]string{"netns", "exec", config.ClientNamespace, executable}, networkWorkerArguments()...)
	command := exec.CommandContext(ctx, "ip", arguments...)
	if runArtifacts != nil {
		command.Env = commandEnvironmentWithQLOG(runArtifacts.qlogDir)
	}
	command.Stdin = bytes.NewReader(requestJSON)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		if bpfObject == "" {
			return result, fmt.Errorf("tunnel network worker: %w: stdout=%s stderr=%s", err, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()))
		}
		evidenceCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		evidence, evidenceErr := lab.FaultEvidence(evidenceCtx)
		cancel()
		return result, fmt.Errorf("tunnel network worker: %w: stdout=%s stderr=%s kernel_evidence=%+v evidence_error=%v", err, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()), evidence, evidenceErr)
	}
	if err := json.NewDecoder(&stdout).Decode(&result); err != nil {
		return result, fmt.Errorf("decode tunnel network worker result: %w", err)
	}
	if result.Workload.Topology != topology {
		return result, errors.New("network worker returned the wrong tunnel topology")
	}
	var evidence linuxnetlab.KernelFaultEvidence
	if bpfObject != "" {
		evidenceCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		evidence, err = lab.FaultEvidence(evidenceCtx)
		cancel()
		if err != nil {
			return result, err
		}
		if err := validateKernelEvidence(plan, evidence); err != nil {
			return result, err
		}
	}
	result.Kernel = &networkKernelResult{
		ClientNamespace: config.ClientNamespace, ServerNamespace: config.ServerNamespace,
		ClientInterface: config.ClientInterface, ServerInterface: config.ServerInterface,
		ClientAddress: config.ClientAddress.String(), ServerAddress: config.ServerAddress.String(), Faults: evidence,
	}
	return result, nil
}

func validateKernelEvidence(plan transportrelease.ProfilePlan, evidence linuxnetlab.KernelFaultEvidence) error {
	network := plan.Network
	counterOnly := plan.ID == "clean-v1"
	if counterOnly {
		if len(network.JitterMilliseconds) != 1 || network.JitterMilliseconds[0] != 0 || network.Loss.Mode != "none" || plan.Fault != (transportrelease.FaultPlan{}) {
			return errors.New("clean kernel evidence requires the counter-only network profile")
		}
	} else if len(network.JitterMilliseconds) != 8 {
		return errors.New("kernel evidence requires the frozen eight-slot jitter schedule")
	}
	for direction, stats := range map[string]linuxnetlab.KernelFaultStats{"client": evidence.Client, "server": evidence.Server} {
		if stats.Packets == 0 || stats.Bytes == 0 || stats.MTUDropPackets != 0 || stats.GSOPackets != 0 ||
			stats.TimestampErrors != 0 || stats.DuplicateErrors != 0 {
			return fmt.Errorf("%s kernel fault counters are incomplete: %+v", direction, stats)
		}
		accounted := stats.DeliveredPackets + stats.OutageDropPackets + stats.PeriodicLossPackets + stats.BurstLossPackets
		if counterOnly {
			if accounted != stats.Packets || stats.DeliveredPackets != stats.Packets || stats.DelayPackets != 0 || stats.JitterPackets != 0 ||
				stats.PeriodicLossPackets != 0 || stats.BurstLossPackets != 0 || stats.ReorderPackets != 0 || stats.DuplicatePackets != 0 ||
				stats.OutageDropPackets != 0 || stats.JitterSlotPackets != ([8]uint64{}) {
				return fmt.Errorf("%s counter-only kernel packet conservation failed: %+v", direction, stats)
			}
			continue
		}
		if accounted != stats.Packets || stats.DelayPackets != stats.DeliveredPackets {
			return fmt.Errorf("%s kernel packet conservation failed: %+v", direction, stats)
		}
		if plan.Fault.OutageDuration > 0 {
			if stats.FirstPacketNS == 0 || stats.OutageDropPackets == 0 {
				return fmt.Errorf("%s kernel outage was not exercised: %+v", direction, stats)
			}
		} else if stats.OutageDropPackets != 0 {
			return fmt.Errorf("%s kernel outage counters are unexpected: %+v", direction, stats)
		}
		wantPeriodic, wantBurst := uint64(0), uint64(0)
		wantReorderEligible, wantDuplicateEligible := uint64(0), uint64(0)
		var wantSlots [8]uint64
		for ordinal := uint64(1); ordinal <= stats.Packets; ordinal++ {
			deterministicLoss := false
			switch network.Loss.Mode {
			case "periodic":
				if ordinal%uint64(network.Loss.EveryNth) == 0 {
					wantPeriodic++
					deterministicLoss = true
				}
			case "burst":
				position := (ordinal-1)%uint64(network.Loss.BlockSize) + 1
				if position >= uint64(network.Loss.BurstFirst) && position <= uint64(network.Loss.BurstLast) {
					wantBurst++
					deterministicLoss = true
				}
			}
			if !deterministicLoss {
				slot := (ordinal - 1) % uint64(len(wantSlots))
				wantSlots[slot]++
				if selectedFaultOrdinal(ordinal, plan.Fault.ReorderPercent, 0) {
					wantReorderEligible++
				}
				period := faultOrdinalPeriod(plan.Fault.DuplicatePercent)
				if selectedFaultOrdinal(ordinal, plan.Fault.DuplicatePercent, period/2) {
					wantDuplicateEligible++
				}
			}
		}
		lossDeficit := wantPeriodic + wantBurst - stats.PeriodicLossPackets - stats.BurstLossPackets
		if stats.PeriodicLossPackets > wantPeriodic || stats.BurstLossPackets > wantBurst || lossDeficit > stats.OutageDropPackets {
			return fmt.Errorf("%s kernel deterministic loss counters are invalid: %+v", direction, stats)
		}
		var gotSlots, wantSlotTotal, gotJitter uint64
		for slot := range wantSlots {
			if stats.JitterSlotPackets[slot] > wantSlots[slot] {
				return fmt.Errorf("%s kernel jitter slot %d exceeds its deterministic schedule: %+v", direction, slot, stats)
			}
			gotSlots += stats.JitterSlotPackets[slot]
			wantSlotTotal += wantSlots[slot]
			if network.JitterMilliseconds[slot] != 0 {
				gotJitter += stats.JitterSlotPackets[slot]
			}
		}
		if gotSlots != stats.DeliveredPackets || wantSlotTotal-gotSlots != stats.OutageDropPackets-lossDeficit || stats.JitterPackets != gotJitter ||
			!faultCountWithinOutageBound(stats.ReorderPackets, wantReorderEligible, stats.OutageDropPackets) ||
			!faultCountWithinOutageBound(stats.DuplicatePackets, wantDuplicateEligible, stats.OutageDropPackets) {
			return fmt.Errorf("%s kernel fault conservation failed: %+v", direction, stats)
		}
	}
	return nil
}

func faultOrdinalPeriod(percent int) uint64 {
	if percent <= 0 || 100%percent != 0 {
		return 0
	}
	return uint64(100 / percent)
}

func selectedFaultOrdinal(ordinal uint64, percent int, offset uint64) bool {
	period := faultOrdinalPeriod(percent)
	return period != 0 && (ordinal-1+offset)%period == 0
}

func faultCountWithinOutageBound(actual, eligible, outage uint64) bool {
	if actual > eligible {
		return false
	}
	return eligible-actual <= outage
}

func runNetworkWorker(input io.Reader, output io.Writer) error {
	decoder := json.NewDecoder(io.LimitReader(input, 64<<10))
	decoder.DisallowUnknownFields()
	var request networkWorkerRequest
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("decode network worker request: %w", err)
	}
	if request.Plan.ID != "clean-v1" && request.Plan.ID != "mobile-v1" && request.Plan.ID != "edge-v1" {
		return errors.New("network worker requires a frozen release profile")
	}
	if err := linuxnetlab.RequireCurrentNamespace(request.ClientNamespace); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(request.Plan.CellWatchdogMinutes)*time.Minute)
	defer cancel()
	switch request.Mode {
	case networkModeDirect:
		if err := request.Kind.Validate(); err != nil {
			return err
		}
		var endpoint *transportrelease.ProductDirectEndpoint
		if err := linuxnetlab.InNamespace(request.ServerNamespace, func() error {
			var openErr error
			endpoint, openErr = transportrelease.OpenProductDirectEndpointAt(ctx, request.Kind, request.ServerAddress)
			return openErr
		}); err != nil {
			return err
		}
		var sampleKernel kernelEvidenceSampler
		if request.KernelCounters {
			sampleKernel = func(sampleCtx context.Context) (linuxnetlab.KernelFaultEvidence, error) {
				return linuxnetlab.ReadFaultEvidence(sampleCtx, request.ClientNamespace, request.ServerNamespace)
			}
		}
		result, err := runEndpointCarrier(ctx, endpoint, request.Kind, request.Plan, sampleKernel)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(result)
	case networkModeTunnel:
		if _, _, err := request.Topology.Carriers(); err != nil {
			return err
		}
		resourceStart, err := transportrelease.CaptureResourceSnapshot()
		if err != nil {
			return err
		}
		var endpoint *tunnelworkload.Endpoint
		if err := linuxnetlab.InNamespace(request.ServerNamespace, func() error {
			var openErr error
			endpoint, openErr = tunnelworkload.OpenEndpointAt(ctx, request.Topology, request.ServerAddress)
			return openErr
		}); err != nil {
			return err
		}
		workload, err := tunnelworkload.Run(ctx, endpoint, request.Plan)
		if err != nil {
			return err
		}
		resourceFinish, err := transportrelease.CaptureResourceSnapshot()
		if err != nil {
			return err
		}
		resource, err := transportrelease.CompleteResourceMeasurement(resourceStart, resourceFinish)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(tunnelCarrierResult{Workload: workload, Resource: resource})
	case networkModeAdaptive:
		return runAdaptiveNetworkWorker(ctx, output, request)
	default:
		return errors.New("network worker mode is outside the frozen release matrix")
	}
}

func faultProfileFromPlan(plan transportrelease.ProfilePlan, bpfObject string) (linuxnetlab.FaultProfile, error) {
	network := plan.Network
	if plan.ID == "clean-v1" {
		if network.Shape != nil || network.OneWayDelayMilliseconds != 0 || len(network.JitterMilliseconds) != 1 || network.JitterMilliseconds[0] != 0 ||
			network.Loss.Mode != "none" || plan.Fault != (transportrelease.FaultPlan{}) {
			return linuxnetlab.FaultProfile{}, errors.New("clean profile differs from the counter-only network contract")
		}
		return linuxnetlab.FaultProfile{BPFObject: bpfObject, LossMode: linuxnetlab.LossNone, Jitter: []time.Duration{0}, LinkMTU: network.LinkMTU}, nil
	}
	if network.Shape == nil {
		return linuxnetlab.FaultProfile{}, errors.New("network profile requires a frozen traffic shape")
	}
	profile := linuxnetlab.FaultProfile{
		BPFObject:         bpfObject,
		BaseDelay:         time.Duration(network.OneWayDelayMilliseconds) * time.Millisecond,
		RateBitsPerSecond: network.Shape.RateBitsPerSecond,
		TokenBurstBytes:   network.Shape.TokenBurstBytes,
		QueueBytes:        network.Shape.QueueBytes,
		LinkMTU:           network.LinkMTU,
		ReorderPercent:    plan.Fault.ReorderPercent,
		DuplicatePercent:  plan.Fault.DuplicatePercent,
		OutageStart:       plan.Fault.OutageStart,
		OutageDuration:    plan.Fault.OutageDuration,
	}
	if profile.ReorderPercent > 0 {
		profile.ReorderDelay = 250 * time.Millisecond
	}
	for _, jitter := range network.JitterMilliseconds {
		profile.Jitter = append(profile.Jitter, time.Duration(jitter)*time.Millisecond)
	}
	switch network.Loss.Mode {
	case "periodic":
		profile.LossMode, profile.EveryNth = linuxnetlab.LossPeriodic, network.Loss.EveryNth
	case "burst":
		profile.LossMode = linuxnetlab.LossBurst
		profile.BlockSize, profile.BurstFirst, profile.BurstLast = network.Loss.BlockSize, network.Loss.BurstFirst, network.Loss.BurstLast
	default:
		return linuxnetlab.FaultProfile{}, errors.New("network profile requires periodic or burst loss")
	}
	return profile, nil
}

func completedWithin(ctx context.Context, started time.Time, limit time.Duration) error {
	finished := time.Now()
	if finished.Sub(started) > limit {
		return context.DeadlineExceeded
	}
	if deadline, ok := ctx.Deadline(); ok && !finished.Before(deadline) {
		return context.DeadlineExceeded
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	return nil
}

func closeWithin(ctx context.Context, closeFunc func() error) error {
	result := make(chan error, 1)
	go func() { result <- closeFunc() }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func verifySourceCheckout(root, manifestPath, sourceSHA string) error {
	cleanRoot := filepath.Clean(root)
	if !filepath.IsAbs(cleanRoot) || cleanRoot == string(filepath.Separator) {
		return errors.New("source root must be an absolute checkout path")
	}
	resolvedRoot, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil {
		return errors.New("source root must resolve to an existing checkout")
	}
	cleanRoot = resolvedRoot
	expectedManifest := filepath.Join(cleanRoot, "testdata", "transport_v2", "performance_manifest.json")
	resolvedManifest, err := filepath.EvalSymlinks(filepath.Clean(manifestPath))
	if err != nil || resolvedManifest != expectedManifest {
		return errors.New("performance manifest must be the fixed file in the source checkout")
	}
	top, err := gitOutput(cleanRoot, "rev-parse", "--show-toplevel")
	if err != nil || top != cleanRoot {
		return errors.New("source root is not the exact Git checkout root")
	}
	head, err := gitOutput(cleanRoot, "rev-parse", "HEAD")
	if err != nil || head != sourceSHA {
		return errors.New("source checkout HEAD does not match source SHA")
	}
	status, err := gitOutput(cleanRoot, "status", "--porcelain", "--untracked-files=all")
	if err != nil || status != "" {
		return errors.New("source checkout must be clean")
	}
	return nil
}

func gitOutput(root string, args ...string) (string, error) {
	commandArgs := append([]string{"-C", root}, args...)
	command := exec.Command("git", commandArgs...)
	command.Env = make([]string, 0, len(os.Environ()))
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "GIT_") {
			command.Env = append(command.Env, item)
		}
	}
	output, err := command.Output()
	return strings.TrimSpace(string(output)), err
}

func kernelRelease() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", errors.New("Linux kernel release is empty")
	}
	return value, nil
}

func writeNewReport(path string, report any) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return errors.New("baseline report path must be an absolute file path")
	}
	directory := filepath.Dir(clean)
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	if resolved != directory {
		return errors.New("baseline report directory must not traverse symlinks")
	}
	if _, err := os.Lstat(clean); err == nil {
		return errors.New("baseline report already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".transport-baseline-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, clean); err != nil {
		return err
	}
	return nil
}
