package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/linuxnetlab"
)

const (
	adaptiveNativeTopology = "adaptive_native"
	adaptiveWebTopology    = "adaptive_web"
)

type adaptiveCellReport struct {
	SchemaVersion   int                                  `json:"schema_version"`
	Classification  string                               `json:"classification"`
	SourceSHA       string                               `json:"source_sha"`
	ManifestDigest  string                               `json:"manifest_digest"`
	ManifestSHA256  string                               `json:"manifest_file_sha256"`
	Runner          baselineRunner                       `json:"runner"`
	ProfileID       string                               `json:"profile_id"`
	Topology        string                               `json:"topology"`
	Candidates      []transportrelease.AdaptiveCandidate `json:"candidates"`
	BPFObjectSHA256 string                               `json:"bpf_object_sha256"`
	StartedAt       time.Time                            `json:"started_at"`
	FinishedAt      time.Time                            `json:"finished_at"`
	Results         []adaptiveStageResult                `json:"results"`
}

type adaptiveStageResult struct {
	Run             int                                         `json:"run"`
	ProfileID       string                                      `json:"profile_id"`
	Cold            []transportrelease.AdaptiveConnectOperation `json:"cold"`
	CleanupDuration time.Duration                               `json:"cleanup_duration_ns"`
	Resource        transportrelease.ResourceMeasurement        `json:"resource"`
	Kernel          *networkKernelResult                        `json:"kernel,omitempty"`
	Artifacts       []releaseArtifact                           `json:"artifacts"`
}

func adaptiveCandidatesForTopology(topology string) ([]transportrelease.AdaptiveCandidate, error) {
	switch topology {
	case adaptiveNativeTopology:
		return []transportrelease.AdaptiveCandidate{
			{ID: "runtime-wss", Kind: carrier.KindWebSocket},
			{ID: "runtime-raw-quic", Kind: carrier.KindQUIC},
		}, nil
	case adaptiveWebTopology:
		return []transportrelease.AdaptiveCandidate{
			{ID: "runtime-wss", Kind: carrier.KindWebSocket},
			{ID: "runtime-webtransport", Kind: carrier.KindWebTransport},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported adaptive topology %q", topology)
	}
}

func adaptiveStageExecutionPlan(plan transportrelease.ReleasePlan, stage transportrelease.ProfilePlan, topology string) (transportrelease.ProfilePlan, error) {
	if topology == adaptiveWebTopology {
		// This is a local shutdown ceiling, not additional signed cell time. The
		// parent cell context still enforces the five-minute manifest watchdog.
		stage = webTransportExecutionPlan(stage)
	}
	if stage.ID != "mobile-v1" {
		return stage, nil
	}
	if plan.RunCount < 1 {
		return transportrelease.ProfilePlan{}, errors.New("adaptive execution requires a positive run count")
	}
	perRunSlack := plan.Adaptive.HarnessSlackSeconds / plan.RunCount
	if perRunSlack < 3 {
		return transportrelease.ProfilePlan{}, errors.New("adaptive mobile execution requires at least three seconds of harness slack per run")
	}
	stage.Cold.OperationDeadlineSeconds += perRunSlack
	stage.Cold.PhaseDeadlineSeconds += perRunSlack
	return stage, nil
}

func runAdaptiveCell(parent context.Context, reportPath string, destination *artifactDestination, sourceSHA, profileID, topology, bpfObject string, plan transportrelease.ReleasePlan, manifest transportrelease.ManifestBinding) (resultErr error) {
	if profileID != plan.Adaptive.ID || profileID != "adaptive-selection-v1" {
		return errors.New("adaptive selection cell requires adaptive-selection-v1")
	}
	candidates, err := adaptiveCandidatesForTopology(topology)
	if err != nil {
		return err
	}
	if bpfObject == "" {
		return errors.New("adaptive selection cell requires a BPF object for its mobile stage")
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
	kernel, err := kernelRelease()
	if err != nil {
		return err
	}
	report := adaptiveCellReport{
		SchemaVersion: 1, Classification: "linux_transport_adaptive_selection",
		SourceSHA: sourceSHA, ManifestDigest: manifest.Digest,
		ManifestSHA256: hex.EncodeToString(manifest.SHA256Sum[:]),
		Runner:         baselineRunner{OS: runtime.GOOS, Architecture: runtime.GOARCH, KernelRelease: kernel},
		ProfileID:      profileID, Topology: topology, Candidates: candidates,
		BPFObjectSHA256: hex.EncodeToString(bpfDigest[:]), StartedAt: time.Now().UTC(),
	}
	cellDeadline := time.Duration(plan.Adaptive.CellWatchdogMinutes) * time.Minute
	cellCtx, cancelCell := newCellContext(parent, cellDeadline)
	defer cancelCell()
	cellStarted := time.Now()
	for _, stage := range []struct {
		profile transportrelease.ProfilePlan
		bpf     string
	}{
		{profile: plan.Clean},
		{profile: plan.Mobile, bpf: frozenBPFObject},
	} {
		executionPlan, err := adaptiveStageExecutionPlan(plan, stage.profile, topology)
		if err != nil {
			return err
		}
		for runNumber := 1; runNumber <= plan.RunCount; runNumber++ {
			result, err := runNetworkAdaptive(cellCtx, topology, candidates, executionPlan, runNumber, stage.bpf, destination)
			if err != nil {
				return fmt.Errorf("%s %s run %d: %w", executionPlan.ID, topology, runNumber, err)
			}
			result.Run = runNumber
			report.Results = append(report.Results, result)
		}
	}
	if err := completedWithin(cellCtx, cellStarted, cellDeadline); err != nil {
		return fmt.Errorf("%s cell watchdog: %w", topology, err)
	}
	report.FinishedAt = time.Now().UTC()
	if err := destination.Verify(); err != nil {
		return err
	}
	return writeNewReport(reportPath, report)
}

func runNetworkAdaptive(ctx context.Context, topology string, candidates []transportrelease.AdaptiveCandidate, plan transportrelease.ProfilePlan, runNumber int, bpfObject string, destination *artifactDestination) (result adaptiveStageResult, resultErr error) {
	if len(candidates) != 2 {
		return result, errors.New("adaptive network run requires two candidates")
	}
	cellID := strings.ReplaceAll(plan.ID+"-"+topology, "_", "-")
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
		return result, errors.New("only the clean adaptive stage may run without a BPF object")
	}
	var runArtifacts *runEvidence
	if destination != nil {
		label := fmt.Sprintf("%s-%s-run-%03d", plan.ID, strings.ReplaceAll(topology, "_", "-"), runNumber)
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
		Mode: networkModeAdaptive, Plan: plan, AdaptiveCandidates: candidates,
		ClientNamespace: config.ClientNamespace, ServerNamespace: config.ServerNamespace,
		ServerAddress: config.ServerAddress.Addr().String(),
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return result, err
	}
	command := networkWorkerCommand(ctx, config.ClientNamespace, executable)
	if runArtifacts != nil {
		command.Env = commandEnvironmentWithQLOG(runArtifacts.qlogDir)
	}
	command.Stdin = bytes.NewReader(requestJSON)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		if bpfObject == "" {
			return result, fmt.Errorf("adaptive network worker: %w: stdout=%s stderr=%s", err, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()))
		}
		evidenceCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		evidence, evidenceErr := lab.FaultEvidence(evidenceCtx)
		cancel()
		return result, fmt.Errorf("adaptive network worker: %w: stdout=%s stderr=%s kernel_evidence=%+v evidence_error=%v", err, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()), evidence, evidenceErr)
	}
	if err := json.NewDecoder(&stdout).Decode(&result); err != nil {
		return result, fmt.Errorf("decode adaptive network worker result: %w", err)
	}
	if result.ProfileID != plan.ID || len(result.Cold) != plan.Cold.Operations {
		return result, errors.New("adaptive network worker returned an incomplete stage")
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

func runAdaptiveNetworkWorker(ctx context.Context, output io.Writer, request networkWorkerRequest) error {
	if len(request.AdaptiveCandidates) != 2 {
		return errors.New("adaptive worker requires exactly two candidates")
	}
	resourceStart, err := transportrelease.CaptureResourceSnapshot()
	if err != nil {
		return err
	}
	var endpoint *transportrelease.AdaptiveEndpoint
	if err := linuxnetlab.InNamespace(request.ServerNamespace, func() error {
		var openErr error
		endpoint, openErr = transportrelease.OpenAdaptiveEndpointAt(ctx, request.ServerAddress, request.AdaptiveCandidates)
		return openErr
	}); err != nil {
		return err
	}
	coldLimit := time.Duration(request.Plan.Cold.PhaseDeadlineSeconds) * time.Second
	coldCtx, cancelCold := context.WithTimeout(ctx, coldLimit)
	coldStarted := time.Now()
	cold, runErr := transportrelease.RunAdaptiveCold(coldCtx, endpoint, request.Plan.Cold)
	deadlineErr := completedWithin(coldCtx, coldStarted, coldLimit)
	cancelCold()
	cleanupStarted := time.Now()
	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), time.Duration(request.Plan.CleanupDeadlineSeconds)*time.Second)
	closeErr := closeWithin(cleanupCtx, endpoint.Close)
	cancelCleanup()
	cleanupDuration := time.Since(cleanupStarted)
	if runErr != nil || deadlineErr != nil || closeErr != nil {
		return errors.Join(runErr, deadlineErr, closeErr)
	}
	resourceFinish, err := transportrelease.CaptureResourceSnapshot()
	if err != nil {
		return err
	}
	resource, err := transportrelease.CompleteResourceMeasurement(resourceStart, resourceFinish)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(adaptiveStageResult{
		ProfileID: request.Plan.ID, Cold: cold, CleanupDuration: cleanupDuration, Resource: resource,
	})
}
