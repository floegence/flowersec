package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/linuxnetlab"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/tunnelworkload"
)

func runRegisteredCapacityCase(ctx context.Context, destination *artifactDestination, releaseDefinition releaseCaseDefinition, sourceRoot string, plan transportrelease.ReleasePlan) (releaseCaseResult, error) {
	definition, ok := lookupCapacityCase(releaseDefinition.ID)
	if !ok || definition.Profile != releaseDefinition.Profile {
		return releaseCaseResult{}, errors.New("registered capacity definition is not frozen")
	}
	if definition.Kind == capacityBrowserTunnel || definition.Kind == capacityBrowserStream {
		return runRegisteredBrowserCapacityCase(ctx, destination, definition, sourceRoot, plan)
	}
	return runRegisteredGoCapacityCase(ctx, destination, definition)
}

func runRegisteredGoCapacityCase(ctx context.Context, destination *artifactDestination, definition capacityCaseDefinition) (result releaseCaseResult, resultErr error) {
	// Capacity cases model independent deployments. Return unreachable heap from
	// the previous case before enforcing this case's absolute RSS contract; the
	// The five-minute soak separately owns cross-cycle growth and residual detection.
	debug.FreeOSMemory()
	evidence, err := startRunEvidence(ctx, destination, releaseCaseDefinition{ID: definition.ID}.artifactLabel(), "", "lo")
	if err != nil {
		return result, err
	}
	defer func() {
		artifacts, finishErr := evidence.Finish()
		inventory, inventoryErr := finalizeCapacityEvidence(destination, evidence.directory, definition, artifacts)
		result.Artifacts, result.RawSources, result.Attachments = inventory.Artifacts, inventory.RawSources, inventory.Attachments
		resultErr = errors.Join(resultErr, finishErr, inventoryErr)
	}()
	restore, err := setCapacityEvidenceEnvironment(evidence.qlogDir)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, restore()) }()
	endpoint, err := openProductionCapacityEndpoint(ctx, definition, productionCapacityContract().Sessions)
	if err != nil {
		return result, err
	}
	started := time.Now()
	capacityResult, err := runCapacityCase(ctx, definition, productionCapacityContract(), endpoint, nil)
	if err != nil {
		return result, err
	}
	if capacityRequiresQLOG(definition) {
		drainCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = waitForCapacityQLOGDrain(drainCtx, evidence.qlogDir)
		cancel()
		if err != nil {
			return result, err
		}
	}
	if err := writeCapacityCoreArtifacts(destination, evidence.directory, capacityResult); err != nil {
		return result, err
	}
	return releaseCaseResult{
		ID: definition.ID, Profile: definition.Profile, Status: "pass", CompletedOperations: capacityResult.Succeeded,
		ElapsedNanoseconds: time.Since(started).Nanoseconds(),
	}, nil
}

func runRegisteredBrowserCapacityCase(ctx context.Context, destination *artifactDestination, definition capacityCaseDefinition, sourceRoot string, plan transportrelease.ReleasePlan) (result releaseCaseResult, resultErr error) {
	if !filepath.IsAbs(sourceRoot) || plan.Clean.Network.LinkMTU <= 0 || plan.Clean.Network.Firewall == "" {
		return result, errors.New("browser capacity suite requires the clean source root and network contract")
	}
	cellID := strings.ToLower(strings.ReplaceAll(definition.ID, "_", "-"))
	config, err := linuxnetlab.ConfigForCell(cellID, 1, plan.Clean.Network.LinkMTU, plan.Clean.Network.Firewall)
	if err != nil {
		return result, err
	}
	lab, err := linuxnetlab.Open(ctx, linuxnetlab.ExecRunner{}, config)
	if err != nil {
		return result, err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), productionCapacityContract().Cleanup)
		resultErr = errors.Join(resultErr, lab.Close(cleanupCtx))
		cancel()
	}()
	evidence, err := startRunEvidence(ctx, destination, releaseCaseDefinition{ID: definition.ID}.artifactLabel(), config.ClientNamespace, config.ClientInterface)
	if err != nil {
		return result, err
	}
	defer func() {
		artifacts, finishErr := evidence.Finish()
		inventory, inventoryErr := finalizeCapacityEvidence(destination, evidence.directory, definition, artifacts)
		result.Artifacts, result.RawSources, result.Attachments = inventory.Artifacts, inventory.RawSources, inventory.Attachments
		resultErr = errors.Join(resultErr, finishErr, inventoryErr)
	}()
	browserEvidence := filepath.Join(evidence.directory, "browser")
	if err := os.Mkdir(browserEvidence, 0o700); err != nil {
		return result, err
	}
	executable, err := os.Executable()
	if err != nil {
		return result, err
	}
	request := browserWorkerRequest{
		Mode: "capacity", Topology: browserCapacityTopology(definition),
		ClientNamespace: config.ClientNamespace, ServerNamespace: config.ServerNamespace,
		ServerAddress: config.ServerAddress.Addr().String(), SourceRoot: sourceRoot,
		Capacity: &browserCapacityWorkerPlan{CaseID: definition.ID, EvidenceDirectory: browserEvidence, OperationDeadline: browserCapacityOperationDeadline(definition).Milliseconds()},
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return result, err
	}
	command := browserCapacityWorkerCommand(ctx, config.ClientNamespace, executable)
	configureBrowserWorkerCommand(command)
	command.Env = commandEnvironmentWithQLOG(evidence.qlogDir)
	command.Stdin = bytes.NewReader(requestJSON)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	started := time.Now()
	if err := command.Run(); err != nil {
		return result, fmt.Errorf("browser capacity worker: %w: stdout=%s stderr=%s", err, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()))
	}
	var worker browserCapacityWorkerResult
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decoder.DisallowUnknownFields()
	contract := capacityContractForDefinition(definition)
	if err := decoder.Decode(&worker); err != nil || worker.SchemaVersion != 1 || worker.Status != "passed" || worker.CaseID != definition.ID ||
		worker.Result.Succeeded != contract.Sessions || worker.Result.ResidualSessions != 0 || worker.Result.ResidualStreams != 0 ||
		(contract.StreamsPerSession > 0 && (worker.Result.CompletedStreams != contract.Sessions*contract.StreamsPerSession || worker.Result.ActiveStreamPeak != contract.Sessions*contract.StreamsPerSession)) {
		return result, errors.New("browser capacity worker returned a mismatched result")
	}
	wantEvidence := []string{
		filepath.Join(browserEvidence, "chromium-netlog.json"), filepath.Join(browserEvidence, "chromium-trace.zip"),
		filepath.Join(browserEvidence, "controller-result.json"), filepath.Join(browserEvidence, "controller-config.json"),
		filepath.Join(browserEvidence, "producer-resource.json"),
	}
	if !slices.Equal(worker.EvidencePaths, wantEvidence) {
		return result, errors.New("browser capacity worker returned an unexpected evidence inventory")
	}
	if err := writeCapacityCoreArtifacts(destination, evidence.directory, worker.Result); err != nil {
		return result, err
	}
	return releaseCaseResult{
		ID: definition.ID, Profile: definition.Profile, Status: "pass", CompletedOperations: func() int {
			if worker.Result.CompletedStreams > 0 {
				return worker.Result.CompletedStreams
			}
			return worker.Result.Succeeded
		}(),
		ElapsedNanoseconds: time.Since(started).Nanoseconds(),
	}, nil
}

func browserCapacityWorkerCommand(ctx context.Context, namespace, executable string) *exec.Cmd {
	return exec.CommandContext(ctx, "/usr/bin/nsenter", "--net=/var/run/netns/"+namespace, "--", executable, browserWorkerArg)
}

func browserCapacityTopology(definition capacityCaseDefinition) string {
	if definition.BrowserDirect {
		return string(browserDirectWebTransportTopology)
	}
	return string(definition.BrowserTopology)
}

func capacityContractForDefinition(definition capacityCaseDefinition) capacityContract {
	if definition.Kind == capacityBrowserStream {
		contract := productionBrowserStreamCapacityContract()
		if definition.BrowserTopology == tunnelworkload.BrowserTunnelWTWSS {
			contract.YamuxMaxFrameBytes = 256 * 1024
			contract.YamuxMaxStreamReceiveBytes = 256 * 1024
			contract.YamuxMaxSessionReceiveBytes = 130 * 256 * 1024
		}
		if definition.BrowserTopology == tunnelworkload.BrowserTunnelWTWSS || definition.BrowserTopology == tunnelworkload.BrowserTunnelWTQUIC {
			contract.TunnelCopyBufferBytes = 4 * 1024
		}
		return contract
	}
	if definition.Kind == capacityBrowserTunnel {
		return productionBrowserCapacityContract()
	}
	return productionCapacityContract()
}

func capacityCaseTimeout(definition capacityCaseDefinition) time.Duration {
	return capacityContractForDefinition(definition).Watchdog + 30*time.Second
}

func writeCapacityCoreArtifacts(destination *artifactDestination, directory string, result capacityCaseResult) error {
	for _, artifact := range []struct {
		name  string
		kind  string
		value any
	}{
		{name: "trace.json", kind: "trace", value: result.Trace},
		{name: "metrics.json", kind: "metrics", value: result.Metrics},
		{name: "resource.json", kind: "resource", value: result.Resource},
		{name: "config.json", kind: "config", value: result.Config},
	} {
		if _, err := writeRawCaseArtifact(destination, filepath.Join(directory, artifact.name), artifact.kind, artifact.value); err != nil {
			return err
		}
	}
	return nil
}

func setCapacityEvidenceEnvironment(qlogDirectory string) (func() error, error) {
	if !filepath.IsAbs(qlogDirectory) {
		return nil, errors.New("capacity qlog directory must be absolute")
	}
	type previousValue struct {
		value string
		set   bool
	}
	previous := make(map[string]previousValue, 2)
	for key, value := range map[string]string{"QLOGDIR": qlogDirectory, "FLOWERSEC_TRANSPORT_RELEASE_EVIDENCE": "1"} {
		old, set := os.LookupEnv(key)
		previous[key] = previousValue{value: old, set: set}
		if err := os.Setenv(key, value); err != nil {
			return nil, err
		}
	}
	return func() error {
		var result error
		for key, old := range previous {
			if old.set {
				result = errors.Join(result, os.Setenv(key, old.value))
			} else {
				result = errors.Join(result, os.Unsetenv(key))
			}
		}
		return result
	}, nil
}
