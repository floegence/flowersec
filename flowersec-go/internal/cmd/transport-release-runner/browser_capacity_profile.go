package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/tunnelworkload"
)

type browserCapacityWorkerPlan struct {
	CaseID            string `json:"case_id"`
	EvidenceDirectory string `json:"evidence_directory"`
	OperationDeadline int64  `json:"operation_deadline_ms"`
}

type browserCapacityWorkerResult struct {
	SchemaVersion int                `json:"schema_version"`
	Status        string             `json:"status"`
	CaseID        string             `json:"case_id"`
	Result        capacityCaseResult `json:"result"`
	EvidencePaths []string           `json:"evidence_paths"`
}

func validateBrowserCapacityWorkerPlan(plan browserCapacityWorkerPlan, sourceRoot string) error {
	if !filepath.IsAbs(plan.EvidenceDirectory) || !filepath.IsAbs(sourceRoot) {
		return errors.New("browser capacity worker plan is invalid")
	}
	definition, ok := lookupCapacityCase(plan.CaseID)
	if !ok || (definition.Kind != capacityBrowserTunnel && definition.Kind != capacityBrowserStream) {
		return errors.New("browser capacity worker requires a frozen Chromium capacity case")
	}
	if time.Duration(plan.OperationDeadline)*time.Millisecond != browserCapacityOperationDeadline(definition) {
		return errors.New("browser capacity worker operation deadline is not frozen for its workload")
	}
	entries, err := os.ReadDir(plan.EvidenceDirectory)
	if err != nil || len(entries) != 0 {
		return errors.New("browser capacity worker evidence directory must exist and be empty")
	}
	for _, relative := range []string{
		"flowersec-ts/scripts/browser-capacity-controller.mjs",
		"flowersec-ts/scripts/chromium-netns-launcher.sh",
		"flowersec-ts/dist/browser/index.js",
	} {
		if info, err := os.Stat(filepath.Join(sourceRoot, relative)); err != nil || !info.Mode().IsRegular() {
			return errors.New("browser capacity worker source is incomplete")
		}
	}
	return nil
}

func runBrowserCapacityWorker(request browserWorkerRequest, output io.Writer) error {
	definition, ok := lookupCapacityCase(request.Capacity.CaseID)
	if !ok || (definition.Kind != capacityBrowserTunnel && definition.Kind != capacityBrowserStream) || browserCapacityTopology(definition) != request.Topology {
		return errors.New("browser capacity worker case and topology do not match")
	}
	result, evidencePaths, err := runBrowserTunnelCapacityProfile(context.Background(), definition, browserCapacityEndpointConfig{
		Topology: definition.BrowserTopology, SourceRoot: request.SourceRoot,
		ClientNamespace: request.ClientNamespace, ServerNamespace: request.ServerNamespace, ServerAddress: request.ServerAddress,
		EvidenceDirectory: request.Capacity.EvidenceDirectory,
		OperationDeadline: time.Duration(request.Capacity.OperationDeadline) * time.Millisecond,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(browserCapacityWorkerResult{
		SchemaVersion: 1, Status: "passed", CaseID: definition.ID, Result: result, EvidencePaths: evidencePaths,
	})
}

// runBrowserTunnelCapacityProfile is the capacity-suite wiring point for the
// Chromium WebTransport capacity cases. It deliberately accepts a frozen case
// definition rather than a carrier override so direct, WSS, and raw-QUIC Go
// legs cannot be substituted at collection time.
func runBrowserTunnelCapacityProfile(ctx context.Context, definition capacityCaseDefinition, config browserCapacityEndpointConfig) (capacityCaseResult, []string, error) {
	if (definition.Kind != capacityBrowserTunnel && definition.Kind != capacityBrowserStream) || definition.ID == "" || definition.Profile == "" ||
		(browserCapacityTopology(definition) != string(config.Topology) && config.Topology != "") {
		return capacityCaseResult{}, nil, errors.New("browser capacity profile requires a frozen Chromium case")
	}
	contract := capacityContractForDefinition(definition)
	config.Topology = tunnelworkload.BrowserTopology(browserCapacityTopology(definition))
	config.ProfileID = definition.Profile
	config.Sessions = contract.Sessions
	config.StreamsPerSession = contract.StreamsPerSession
	endpoint, err := openProductionBrowserCapacityEndpoint(ctx, config)
	if err != nil {
		return capacityCaseResult{}, nil, err
	}
	result, err := runCapacityCase(ctx, definition, contract, endpoint, endpoint.CaptureResourceSnapshot)
	return result, endpoint.EvidencePaths(), err
}
