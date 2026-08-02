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
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/linuxnetlab"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/tunnelworkload"
)

const browserDirectTopology = "browser_webtransport"

func runBrowserCell(parent context.Context, reportPath string, destination *artifactDestination, sourceSHA, sourceRoot, profileID, topology, bpfObject string, runShard int, plan transportrelease.ReleasePlan, manifest transportrelease.ManifestBinding) (resultErr error) {
	if topology == "" {
		topology = browserDirectTopology
	}
	if !supportedBrowserTopology(topology) {
		return errors.New("browser cell requires browser_webtransport, browser_tunnel_wt_wss, or browser_tunnel_wt_quic")
	}
	profile := plan.Clean
	if profileID == "mobile-v1" {
		profile = plan.Mobile
	} else if profileID == "edge-v1" {
		profile = plan.Edge
	} else if profileID != "clean-v1" {
		return errors.New("browser WebTransport cell requires clean-v1, mobile-v1, or edge-v1")
	}
	if profileID == "clean-v1" && bpfObject != "" {
		return errors.New("clean browser WebTransport cell does not accept a BPF object")
	}
	if profileID != "clean-v1" && bpfObject == "" {
		return errors.New("weak-network browser WebTransport cell requires --bpf-object")
	}
	var frozenBPFObject, bpfDigest string
	if bpfObject != "" {
		bpfBytes, err := linuxnetlab.ReadVerifiedBPFObject(bpfObject)
		if err != nil {
			return err
		}
		var cleanup func() error
		frozenBPFObject, cleanup, err = freezeBPFObject(bpfBytes)
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, cleanup()) }()
		digest := sha256.Sum256(bpfBytes)
		bpfDigest = hex.EncodeToString(digest[:])
	}
	kernel, err := kernelRelease()
	if err != nil {
		return err
	}
	report := browserCellReport{
		SchemaVersion: 1, Classification: "linux_chromium_webtransport_profile",
		SourceSHA: sourceSHA, ManifestDigest: manifest.Digest, ManifestSHA256: hex.EncodeToString(manifest.SHA256Sum[:]),
		Runner:    baselineRunner{OS: runtime.GOOS, Architecture: runtime.GOARCH, KernelRelease: kernel},
		ProfileID: profile.ID, Network: profile.Network, Topology: topology, BPFObjectSHA256: bpfDigest,
		Fault:     profile.Fault,
		StartedAt: time.Now().UTC(),
	}
	cellDeadline := time.Duration(profile.CellWatchdogMinutes) * time.Minute
	runOne := func(shardCtx context.Context, runNumber int) error {
		result, err := runBrowserNetworkCarrier(shardCtx, topology, profile, runNumber, frozenBPFObject, sourceRoot, destination)
		if err != nil {
			return fmt.Errorf("run %d: %w", runNumber, err)
		}
		report.Results = append(report.Results, result)
		return nil
	}
	if runShard == 0 {
		err = runForcedProfileShards(parent, plan.RunCount, cellDeadline, runOne)
	} else {
		report.ShardIndex = runShard
		report.ShardCount = len(forcedProfileRunShards(plan.RunCount))
		err = runSelectedForcedProfileShard(parent, plan.RunCount, runShard, cellDeadline, runOne)
	}
	if err != nil {
		return fmt.Errorf("%s browser WebTransport: %w", profile.ID, err)
	}
	report.FinishedAt = time.Now().UTC()
	if err := destination.Verify(); err != nil {
		return err
	}
	return writeNewReport(reportPath, report)
}

func runBrowserNetworkCarrier(ctx context.Context, topology string, plan transportrelease.ProfilePlan, runNumber int, bpfObject, sourceRoot string, destination *artifactDestination) (result browserCellResult, resultErr error) {
	label := fmt.Sprintf("%s-%s-run-%03d", plan.ID, strings.ReplaceAll(topology, "_", "-"), runNumber)
	return runBrowserNetworkCarrierWithLabel(ctx, topology, plan, runNumber, bpfObject, sourceRoot, destination, label)
}

func runBrowserNetworkCarrierWithLabel(ctx context.Context, topology string, plan transportrelease.ProfilePlan, runNumber int, bpfObject, sourceRoot string, destination *artifactDestination, label string) (result browserCellResult, resultErr error) {
	plan = forcedBrowserWebTransportExecutionPlan(plan)
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
	}
	evidence, err := startRunEvidence(ctx, destination, label, config.ClientNamespace, config.ClientInterface)
	if err != nil {
		return result, err
	}
	defer func() {
		artifacts, finishErr := evidence.Finish()
		result.Artifacts = artifacts
		resultErr = errors.Join(resultErr, finishErr)
	}()
	executable, err := os.Executable()
	if err != nil {
		return result, err
	}
	request := newBrowserWorkerRequest(plan, topology, runNumber, config, sourceRoot, evidence.directory)
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return result, err
	}
	command := exec.CommandContext(ctx, "ip", "netns", "exec", config.ClientNamespace, executable, browserWorkerArg)
	configureBrowserWorkerCommand(command)
	command.Env = commandEnvironmentWithQLOG(evidence.qlogDir)
	command.Stdin = bytes.NewReader(requestJSON)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return result, fmt.Errorf("browser worker: %w: stdout=%s stderr=%s", err, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()))
	}
	var envelope struct {
		SchemaVersion int    `json:"schema_version"`
		Topology      string `json:"topology"`
		ProfileID     string `json:"profile_id"`
		RunNumber     int    `json:"run_number"`
		Status        string `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil || envelope.SchemaVersion != 1 || envelope.Topology != topology ||
		envelope.ProfileID != plan.ID || envelope.RunNumber != runNumber || envelope.Status != "passed" {
		return result, errors.New("browser worker returned a mismatched result")
	}
	result = browserCellResult{Run: runNumber, Workload: append(json.RawMessage(nil), stdout.Bytes()...)}
	var faults linuxnetlab.KernelFaultEvidence
	if bpfObject != "" {
		evidenceCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		faults, err = lab.FaultEvidence(evidenceCtx)
		cancel()
		if err != nil {
			return result, err
		}
		if err := validateKernelEvidence(plan, faults); err != nil {
			return result, err
		}
	}
	result.Kernel = networkKernelResult{
		ClientNamespace: config.ClientNamespace, ServerNamespace: config.ServerNamespace,
		ClientInterface: config.ClientInterface, ServerInterface: config.ServerInterface,
		ClientAddress: config.ClientAddress.String(), ServerAddress: config.ServerAddress.String(), Faults: faults,
	}
	return result, nil
}

type browserWorkerRequest struct {
	Mode              string                       `json:"mode,omitempty"`
	Plan              transportrelease.ProfilePlan `json:"plan"`
	Topology          string                       `json:"topology"`
	RunNumber         int                          `json:"run_number"`
	ClientNamespace   string                       `json:"client_namespace"`
	ServerNamespace   string                       `json:"server_namespace"`
	ClientAddress     string                       `json:"client_address,omitempty"`
	ServerAddress     string                       `json:"server_address"`
	SourceRoot        string                       `json:"source_root"`
	EvidenceDirectory string                       `json:"evidence_directory,omitempty"`
	Capacity          *browserCapacityWorkerPlan   `json:"capacity,omitempty"`
}

func newBrowserWorkerRequest(plan transportrelease.ProfilePlan, topology string, runNumber int, config linuxnetlab.Config, sourceRoot, evidenceDirectory string) browserWorkerRequest {
	return browserWorkerRequest{
		Plan: plan, Topology: topology, RunNumber: runNumber,
		ClientNamespace: config.ClientNamespace, ServerNamespace: config.ServerNamespace,
		ClientAddress: config.ClientAddress.Addr().String(), ServerAddress: config.ServerAddress.Addr().String(),
		SourceRoot: sourceRoot, EvidenceDirectory: evidenceDirectory,
	}
}

func browserWorkerAllowedOrigin(request browserWorkerRequest) string {
	return "http://" + request.ClientAddress
}

type browserCollectorPlan struct {
	SchemaVersion       int                          `json:"schema_version"`
	Topology            string                       `json:"topology"`
	ProfileID           string                       `json:"profile_id"`
	RunNumber           int                          `json:"run_number"`
	Mode                string                       `json:"mode"`
	ArtifactSourceURL   string                       `json:"artifact_source_url"`
	CertificateHash     string                       `json:"certificate_hash"`
	ClientNamespace     string                       `json:"client_netns"`
	ModuleBindAddress   string                       `json:"module_bind_address"`
	ModuleAdvertiseHost string                       `json:"module_advertise_host"`
	EvidenceDirectory   string                       `json:"evidence_directory"`
	CellDeadlineMS      int64                        `json:"cell_deadline_ms"`
	Cold                browserCollectorColdPlan     `json:"cold"`
	RPC                 browserCollectorRPCPlan      `json:"rpc"`
	Bulk                browserCollectorBulkPlan     `json:"bulk"`
	CleanupDeadlineMS   int64                        `json:"cleanup_deadline_ms"`
	Network             transportrelease.NetworkPlan `json:"network"`
}

type browserCollectorColdPlan struct {
	Operations          int   `json:"operations"`
	MaxInflight         int   `json:"max_inflight"`
	StartRatePerSecond  int   `json:"start_rate_per_second"`
	OperationDeadlineMS int64 `json:"operation_deadline_ms"`
	PhaseDeadlineMS     int64 `json:"phase_deadline_ms"`
}

type browserCollectorRPCPlan struct {
	Operations          int   `json:"operations"`
	Workers             int   `json:"workers"`
	RequestBytes        int   `json:"request_bytes"`
	OperationDeadlineMS int64 `json:"operation_deadline_ms"`
	PhaseDeadlineMS     int64 `json:"phase_deadline_ms"`
}

type browserCollectorBulkPlan struct {
	WarmupBytesPerDirection int64 `json:"warmup_bytes_per_direction"`
	ScoreBytesPerDirection  int64 `json:"score_bytes_per_direction"`
	PhaseDeadlineMS         int64 `json:"phase_deadline_ms"`
}

func runBrowserWorker(input io.Reader, output io.Writer) (resultErr error) {
	return runBrowserWorkerWithContext(context.Background(), input, output)
}

func runBrowserWorkerWithContext(parent context.Context, input io.Reader, output io.Writer) (resultErr error) {
	if parent == nil {
		return errors.New("browser worker context is required")
	}
	decoder := json.NewDecoder(io.LimitReader(input, 128<<10))
	decoder.DisallowUnknownFields()
	var request browserWorkerRequest
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("decode browser worker request")
	}
	if err := validateBrowserWorkerRequest(request); err != nil {
		return err
	}
	if err := linuxnetlab.RequireCurrentNamespace(request.ClientNamespace); err != nil {
		return err
	}
	if request.Mode == "capacity" {
		return runBrowserCapacityWorker(parent, request, output)
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(request.Plan.CellWatchdogMinutes)*time.Minute)
	defer cancel()

	allowedOrigin := browserWorkerAllowedOrigin(request)
	var certificateHash string
	var source *browserArtifactSource
	var closeEndpoint func() error
	if err := linuxnetlab.InNamespace(request.ServerNamespace, func() error {
		if request.Topology == browserDirectTopology {
			endpoint, openErr := transportrelease.OpenProductDirectBrowserEndpointAt(ctx, request.ServerAddress, allowedOrigin)
			if openErr != nil {
				return openErr
			}
			closeEndpoint = endpoint.Close
			certificateHash, openErr = endpoint.CertificateHashBase64URL()
			if openErr != nil {
				return openErr
			}
			source, openErr = newBrowserArtifactSource(endpoint, request.Plan, request.Topology, request.RunNumber)
			return openErr
		}
		endpoint, openErr := tunnelworkload.OpenBrowserReleaseEndpointAt(
			ctx, tunnelworkload.BrowserTopology(request.Topology), request.ServerAddress, allowedOrigin, request.Plan,
		)
		if openErr != nil {
			return openErr
		}
		closeEndpoint = func() error {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Duration(request.Plan.CleanupDeadlineSeconds)*time.Second)
			defer cancel()
			return endpoint.Close(cleanupCtx)
		}
		certificateHash, openErr = endpoint.CertificateHashBase64URL()
		if openErr != nil {
			return openErr
		}
		source, openErr = newBrowserTunnelArtifactSource(endpoint, request.Plan, request.Topology, request.RunNumber)
		return openErr
	}); err != nil {
		if closeEndpoint != nil {
			return errors.Join(err, closeEndpoint())
		}
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, closeEndpoint()) }()
	listener, server, sourceURL, err := startBrowserArtifactHTTPServer(request.ServerNamespace, request.ServerAddress, source)
	if err != nil {
		return err
	}
	serverClosed := false
	defer func() {
		if !serverClosed {
			resultErr = errors.Join(resultErr, closeBrowserArtifactHTTPServer(server, listener))
		}
	}()

	collectorPlan := newBrowserCollectorPlan(request, sourceURL, certificateHash)
	collectorResult, err := executeBrowserCollector(ctx, request.SourceRoot, request.ClientNamespace, collectorPlan)
	serverClosed = true
	closeErr := closeBrowserArtifactHTTPServer(server, listener)
	finalizeErr := source.Finalize(ctx, err != nil)
	if err != nil || closeErr != nil || finalizeErr != nil {
		return errors.Join(err, closeErr, finalizeErr)
	}
	if _, err := output.Write(collectorResult); err != nil {
		return err
	}
	return nil
}

func validateBrowserWorkerRequest(request browserWorkerRequest) error {
	if !supportedLinuxRunnerArchitecture(runtime.GOOS, runtime.GOARCH) {
		return errors.New("browser release worker requires Linux amd64 or arm64")
	}
	if !supportedBrowserTopology(request.Topology) ||
		request.ClientNamespace == "" || request.ServerNamespace == "" || request.ClientNamespace == request.ServerNamespace ||
		net.ParseIP(request.ServerAddress) == nil || (request.Mode != "capacity" && net.ParseIP(request.ClientAddress) == nil) || !filepath.IsAbs(request.SourceRoot) {
		return errors.New("browser release worker request is outside the supported topology")
	}
	if request.Mode == "capacity" {
		if request.Capacity == nil || request.RunNumber != 0 || request.Plan.ID != "" || request.EvidenceDirectory != "" {
			return errors.New("browser capacity worker request is outside the frozen capacity matrix")
		}
		return validateBrowserCapacityWorkerPlan(*request.Capacity, request.SourceRoot)
	}
	if request.Mode != "" || request.Capacity != nil || request.RunNumber < 1 || !filepath.IsAbs(request.EvidenceDirectory) {
		return errors.New("browser release worker mode is invalid")
	}
	plan := request.Plan
	if plan.ID == "" || plan.Cold.Operations < 1 || plan.Cold.MaxInflight < 1 || plan.Cold.MaxInflight > plan.Cold.Operations ||
		plan.Cold.StartRatePerSecond < 1 || plan.Cold.OperationDeadlineSeconds < 1 || plan.Cold.PhaseDeadlineSeconds < 1 ||
		plan.RPC.Operations < 1 || plan.RPC.Workers < 1 || plan.RPC.Workers > plan.RPC.Operations || plan.RPC.RequestBytes < 2 ||
		plan.RPC.OperationDeadlineSeconds < 1 || plan.RPC.PhaseDeadlineSeconds < 1 ||
		plan.Bulk.WarmupBytesPerDirection < 1 || plan.Bulk.ScoreBytesPerDirection < 1 || plan.Bulk.PhaseDeadlineSeconds < 1 ||
		plan.CleanupDeadlineSeconds < 1 || plan.CellWatchdogMinutes < 1 || plan.Cold.Retries != 0 || plan.RPC.Retries != 0 {
		return errors.New("browser release worker plan is invalid")
	}
	for _, relative := range []string{
		"flowersec-ts/scripts/browser-release-collector.mjs",
		"flowersec-ts/scripts/chromium-netns-launcher.sh",
		"flowersec-ts/dist/browser/index.js",
	} {
		info, err := os.Stat(filepath.Join(request.SourceRoot, relative))
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("browser release worker source is incomplete: %s", relative)
		}
	}
	return nil
}

func supportedBrowserTopology(topology string) bool {
	return topology == browserDirectTopology || supportedBrowserTunnelTopology(topology)
}

func supportedBrowserTunnelTopology(topology string) bool {
	return topology == string(tunnelworkload.BrowserTunnelWTWSS) || topology == string(tunnelworkload.BrowserTunnelWTQUIC)
}

func startBrowserArtifactHTTPServer(namespace, address string, handler http.Handler) (net.Listener, *http.Server, string, error) {
	var listener net.Listener
	if err := linuxnetlab.InNamespace(namespace, func() error {
		var listenErr error
		listener, listenErr = net.Listen("tcp4", net.JoinHostPort(address, "0"))
		return listenErr
	}); err != nil {
		return nil, nil, "", err
	}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second,
	}
	go func() { _ = server.Serve(listener) }()
	port := listener.Addr().(*net.TCPAddr).Port
	return listener, server, "http://" + net.JoinHostPort(address, fmt.Sprint(port)) + "/artifacts", nil
}

func closeBrowserArtifactHTTPServer(server *http.Server, listener net.Listener) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdownErr := server.Shutdown(ctx)
	listenerErr := listener.Close()
	if errors.Is(listenerErr, net.ErrClosed) {
		listenerErr = nil
	}
	return errors.Join(shutdownErr, listenerErr)
}

func newBrowserCollectorPlan(request browserWorkerRequest, sourceURL, certificateHash string) browserCollectorPlan {
	request.Plan = forcedBrowserWebTransportExecutionPlan(request.Plan)
	seconds := func(value int) int64 { return int64(value) * 1000 }
	return browserCollectorPlan{
		SchemaVersion: 1, Topology: request.Topology, ProfileID: request.Plan.ID, RunNumber: request.RunNumber, Mode: "forced",
		ArtifactSourceURL: sourceURL, CertificateHash: certificateHash, ClientNamespace: request.ClientNamespace,
		ModuleBindAddress: request.ClientAddress, ModuleAdvertiseHost: request.ClientAddress,
		EvidenceDirectory: request.EvidenceDirectory,
		CellDeadlineMS:    seconds(request.Plan.CellWatchdogMinutes * 60), CleanupDeadlineMS: seconds(request.Plan.CleanupDeadlineSeconds),
		Cold: browserCollectorColdPlan{
			Operations: request.Plan.Cold.Operations, MaxInflight: request.Plan.Cold.MaxInflight,
			StartRatePerSecond:  request.Plan.Cold.StartRatePerSecond,
			OperationDeadlineMS: seconds(request.Plan.Cold.OperationDeadlineSeconds), PhaseDeadlineMS: seconds(request.Plan.Cold.PhaseDeadlineSeconds),
		},
		RPC: browserCollectorRPCPlan{
			Operations: request.Plan.RPC.Operations, Workers: request.Plan.RPC.Workers, RequestBytes: request.Plan.RPC.RequestBytes,
			OperationDeadlineMS: seconds(request.Plan.RPC.OperationDeadlineSeconds), PhaseDeadlineMS: seconds(request.Plan.RPC.PhaseDeadlineSeconds),
		},
		Bulk: browserCollectorBulkPlan{
			WarmupBytesPerDirection: request.Plan.Bulk.WarmupBytesPerDirection,
			ScoreBytesPerDirection:  request.Plan.Bulk.ScoreBytesPerDirection,
			PhaseDeadlineMS:         seconds(request.Plan.Bulk.PhaseDeadlineSeconds),
		},
		Network: request.Plan.Network,
	}
}

func executeBrowserCollector(ctx context.Context, sourceRoot, serverNamespace string, plan browserCollectorPlan) ([]byte, error) {
	directory, err := os.MkdirTemp("", "flowersec-browser-collector-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	planPath := filepath.Join(directory, "plan.json")
	resultPath := filepath.Join(directory, "result.json")
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(planPath, planJSON, 0o600); err != nil {
		return nil, err
	}
	node, err := exec.LookPath("node")
	if err != nil {
		return nil, err
	}
	collector := filepath.Join(sourceRoot, "flowersec-ts", "scripts", "browser-release-collector.mjs")
	command := exec.CommandContext(ctx, "ip", "netns", "exec", serverNamespace, node, collector, "--plan", planPath, "--result", resultPath)
	command.Dir = filepath.Join(sourceRoot, "flowersec-ts")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		result, _ := os.ReadFile(resultPath)
		return nil, fmt.Errorf("browser collector: %w: stdout=%s stderr=%s result=%s", err, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()), strings.TrimSpace(string(result)))
	}
	result, err := os.ReadFile(resultPath)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		SchemaVersion  int    `json:"schema_version"`
		Classification string `json:"classification"`
		Status         string `json:"status"`
	}
	if err := json.Unmarshal(result, &envelope); err != nil || envelope.SchemaVersion != 1 || envelope.Classification != "raw_browser_transport_workload" || envelope.Status != "passed" {
		return nil, errors.New("browser collector returned an invalid result")
	}
	return result, nil
}
