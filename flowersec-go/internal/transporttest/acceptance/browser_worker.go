package acceptance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/transporttest"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transporttest/linuxnetlab"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transporttest/tunnelworkload"
)

type browserWorkerRequest struct {
	Browser         string                    `json:"browser"`
	Plan            transporttest.ProfilePlan `json:"plan"`
	Topology        string                    `json:"topology"`
	RunNumber       int                       `json:"run_number"`
	ClientNamespace string                    `json:"client_namespace"`
	ServerNamespace string                    `json:"server_namespace"`
	ClientAddress   string                    `json:"client_address"`
	ServerAddress   string                    `json:"server_address"`
	SourceRoot      string                    `json:"source_root"`
	OutputDirectory string                    `json:"output_directory"`
	Diagnostic      bool                      `json:"diagnostic"`
}
type BrowserWorkerRequest = browserWorkerRequest

type browserRunnerPlan struct {
	SchemaVersion       int                       `json:"schema_version"`
	Browser             string                    `json:"browser"`
	Topology            string                    `json:"topology"`
	ProfileID           string                    `json:"profile_id"`
	RunNumber           int                       `json:"run_number"`
	Mode                string                    `json:"mode"`
	ColdDiagnostic      bool                      `json:"cold_diagnostic"`
	DiagnosticsEnabled  bool                      `json:"diagnostics_enabled"`
	Policy              string                    `json:"policy"`
	ArtifactSourceURL   string                    `json:"artifact_source_url"`
	CertificateHash     string                    `json:"certificate_hash"`
	ClientNamespace     string                    `json:"client_netns"`
	ModuleBindAddress   string                    `json:"module_bind_address"`
	ModuleAdvertiseHost string                    `json:"module_advertise_host"`
	OutputDirectory     string                    `json:"output_directory"`
	CellDeadlineMS      int64                     `json:"cell_deadline_ms"`
	Cold                browserRunnerColdPlan     `json:"cold"`
	RPC                 browserRunnerRPCPlan      `json:"rpc"`
	Bulk                browserRunnerBulkPlan     `json:"bulk"`
	CleanupDeadlineMS   int64                     `json:"cleanup_deadline_ms"`
	Network             transporttest.NetworkPlan `json:"network"`
}

type browserRunnerColdPlan struct {
	Operations          int   `json:"operations"`
	MaxInflight         int   `json:"max_inflight"`
	StartRatePerSecond  int   `json:"start_rate_per_second"`
	OperationDeadlineMS int64 `json:"operation_deadline_ms"`
	PhaseDeadlineMS     int64 `json:"phase_deadline_ms"`
}

type browserRunnerRPCPlan struct {
	Operations          int   `json:"operations"`
	Workers             int   `json:"workers"`
	RequestBytes        int   `json:"request_bytes"`
	OperationDeadlineMS int64 `json:"operation_deadline_ms"`
	PhaseDeadlineMS     int64 `json:"phase_deadline_ms"`
}

type browserRunnerBulkPlan struct {
	WarmupBytesPerDirection int64 `json:"warmup_bytes_per_direction"`
	ScoreBytesPerDirection  int64 `json:"score_bytes_per_direction"`
	PhaseDeadlineMS         int64 `json:"phase_deadline_ms"`
}

type browserWorkloadResult struct {
	SchemaVersion int    `json:"schema_version"`
	Topology      string `json:"topology"`
	ProfileID     string `json:"profile_id"`
	RunNumber     int    `json:"run_number"`
	Status        string `json:"status"`
}

func runBrowserWorkload(ctx context.Context, request browserWorkerRequest) (result browserWorkloadResult, resultErr error) {
	if err := validateBrowserWorkerRequest(request); err != nil {
		return result, err
	}
	allowedOrigin := browserModuleOriginForRequest(request)
	var certificateHash string
	var source *browserArtifactSource
	var closeEndpoint func() error
	if err := linuxnetlab.InNamespace(request.ServerNamespace, func() error {
		if request.Topology == browserDirectTopology {
			endpoint, openErr := transporttest.OpenProductDirectBrowserEndpointAt(ctx, request.ServerAddress, allowedOrigin)
			if openErr != nil {
				return openErr
			}
			closeEndpoint = endpoint.Close
			certificateHash, openErr = endpoint.CertificateHashBase64URL()
			if openErr == nil {
				source, openErr = newDirectBrowserSource(endpoint, request.Plan, request.Topology, request.RunNumber)
			}
			return openErr
		}
		endpoint, openErr := tunnelworkload.OpenBrowserReleaseEndpointAt(
			ctx, tunnelworkload.BrowserTopology(request.Topology), request.ServerAddress, allowedOrigin, request.Plan,
		)
		if openErr != nil {
			return openErr
		}
		closeEndpoint = func() error {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Duration(request.Plan.CleanupDeadlineSeconds)*time.Second)
			defer cleanupCancel()
			return endpoint.Close(cleanupCtx)
		}
		certificateHash, openErr = endpoint.CertificateHashBase64URL()
		if openErr == nil {
			endpoint.SetServerDialNamespace(request.ClientNamespace)
			source, openErr = newTunnelBrowserSource(endpoint, request.Plan, request.Topology, request.RunNumber)
		}
		return openErr
	}); err != nil {
		if closeEndpoint != nil {
			return result, errors.Join(err, closeEndpoint())
		}
		return result, err
	}
	source.workloadStart = func() error { return nil }
	source.coldDiagnostic = request.Diagnostic
	defer func() { resultErr = errors.Join(resultErr, closeEndpoint()) }()
	controlNamespace, controlAddress := browserControlPlaneForRequest(request)
	listener, server, sourceURL, err := startBrowserSourceServer(controlNamespace, controlAddress, source)
	if err != nil {
		return result, err
	}
	serverClosed := false
	defer func() {
		if !serverClosed {
			resultErr = errors.Join(resultErr, closeBrowserSourceServer(server, listener))
		}
	}()
	var runErr error
	result, runErr = executeBrowserRunner(ctx, request, sourceURL, certificateHash)
	serverClosed = true
	closeErr := closeBrowserSourceServer(server, listener)
	finalizeTimeout := time.Duration(request.Plan.CleanupDeadlineSeconds) * time.Second
	if finalizeTimeout < 5*time.Second {
		finalizeTimeout = 5 * time.Second
	}
	finalizeCtx, finalizeCancel := context.WithTimeout(context.Background(), finalizeTimeout)
	finalizeErr := source.Finalize(finalizeCtx, runErr != nil)
	finalizeCancel()
	if runErr != nil || closeErr != nil || finalizeErr != nil {
		return result, errors.Join(runErr, closeErr, finalizeErr)
	}
	return result, nil
}

func browserModuleOriginForRequest(request browserWorkerRequest) string {
	_, address := browserRuntimePlacement(request)
	scheme := "http://"
	if request.Browser == BrowserFirefox {
		scheme = "https://"
	}
	return scheme + address
}

func browserControlPlaneForRequest(request browserWorkerRequest) (string, string) {
	return browserRuntimePlacement(request)
}

func browserRuntimePlacement(request browserWorkerRequest) (string, string) {
	return request.ClientNamespace, request.ClientAddress
}

func validateBrowserWorkerRequest(request browserWorkerRequest) error {
	if (request.Browser != "" && request.Browser != BrowserChromium && request.Browser != BrowserFirefox) ||
		!supportedBrowserTopology(request.Topology) || request.RunNumber < 1 ||
		request.ClientNamespace == "" || request.ServerNamespace == "" || request.ClientNamespace == request.ServerNamespace ||
		net.ParseIP(request.ClientAddress) == nil || net.ParseIP(request.ServerAddress) == nil ||
		!filepath.IsAbs(request.SourceRoot) || !filepath.IsAbs(request.OutputDirectory) {
		return errors.New("acceptance browser worker request is invalid")
	}
	plan := request.Plan
	if plan.ID == "" || plan.Cold.Operations < 1 || plan.Cold.MaxInflight < 1 || plan.Cold.MaxInflight > plan.Cold.Operations ||
		plan.Cold.Retries != 0 || plan.RPC.Retries != 0 || plan.CellWatchdogMinutes < 1 || plan.CleanupDeadlineSeconds < 1 {
		return errors.New("acceptance browser worker plan is invalid")
	}
	for _, relative := range []string{
		"flowersec-ts/scripts/browser-test-runner.mjs", "flowersec-ts/scripts/chromium-netns-launcher.sh", "flowersec-ts/dist/browser/index.js",
	} {
		if info, err := os.Stat(filepath.Join(request.SourceRoot, relative)); err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("acceptance browser source is incomplete: %s", relative)
		}
	}
	return nil
}

func supportedBrowserTopology(topology string) bool {
	return topology == browserDirectTopology || topology == "browser_tunnel_wt_wss" || topology == "browser_tunnel_wt_quic"
}

func startBrowserSourceServer(namespace, address string, handler http.Handler) (net.Listener, *http.Server, string, error) {
	var listener net.Listener
	if err := linuxnetlab.InNamespace(namespace, func() error {
		var listenErr error
		listener, listenErr = net.Listen("tcp4", net.JoinHostPort(address, "0"))
		return listenErr
	}); err != nil {
		return nil, nil, "", err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	go func() { _ = server.Serve(listener) }()
	port := listener.Addr().(*net.TCPAddr).Port
	return listener, server, "http://" + net.JoinHostPort(address, fmt.Sprint(port)) + "/artifacts", nil
}

func closeBrowserSourceServer(server *http.Server, listener net.Listener) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdownErr := server.Shutdown(ctx)
	listenerErr := listener.Close()
	if errors.Is(listenerErr, net.ErrClosed) {
		listenerErr = nil
	}
	return errors.Join(shutdownErr, listenerErr)
}

func executeBrowserRunner(ctx context.Context, request browserWorkerRequest, sourceURL, certificateHash string) (browserWorkloadResult, error) {
	var result browserWorkloadResult
	plan := browserRunnerPlanForRequest(request, sourceURL, certificateHash)
	temporary, err := os.MkdirTemp(request.OutputDirectory, "runner-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(temporary)
	planPath, resultPath := filepath.Join(temporary, "plan.json"), filepath.Join(temporary, "result.json")
	raw, err := json.Marshal(plan)
	if err != nil {
		return result, err
	}
	if err := os.WriteFile(planPath, raw, 0o600); err != nil {
		return result, err
	}
	node, err := exec.LookPath("node")
	if err != nil {
		return result, err
	}
	runner := filepath.Join(request.SourceRoot, "flowersec-ts/scripts/browser-test-runner.mjs")
	runtimeNamespace, _ := browserRuntimePlacement(request)
	command := exec.Command("ip", "netns", "exec", runtimeNamespace, node, runner, "--plan", planPath, "--result", resultPath)
	command.Dir = filepath.Join(request.SourceRoot, "flowersec-ts")
	command.Env, err = browserRunnerEnvironment(os.Environ(), temporary, request.Diagnostic)
	if err != nil {
		return result, err
	}
	var stdout, stderr boundedBuffer
	stdout.limit, stderr.limit = 64<<10, 64<<10
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := runBrowserCommand(ctx, command); err != nil {
		resultText, _ := os.ReadFile(resultPath)
		return result, fmt.Errorf("browser test runner: %w: stdout=%s stderr=%s result=%s", err, stdout.String(), stderr.String(), boundedText(string(resultText), 64<<10))
	}
	resultJSON, err := os.ReadFile(resultPath)
	if err != nil {
		return result, err
	}
	var envelope struct {
		browserWorkloadResult
		Classification string `json:"classification"`
	}
	if json.Unmarshal(resultJSON, &envelope) != nil || envelope.SchemaVersion != 1 || envelope.Classification != "browser_transport_result" || envelope.Status != "passed" {
		return result, errors.New("browser test runner returned an invalid result")
	}
	return envelope.browserWorkloadResult, nil
}

func runBrowserCommand(ctx context.Context, command *exec.Cmd) error {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		select {
		case err := <-done:
			return errors.Join(context.Cause(ctx), err)
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-done
			return errors.Join(context.Cause(ctx), errors.New("browser subprocess ignored SIGTERM"))
		}
	}
}

func withoutEnvironment(environment []string, key string) []string {
	prefix := key + "="
	result := environment[:0]
	for _, value := range environment {
		if !strings.HasPrefix(value, prefix) {
			result = append(result, value)
		}
	}
	return result
}

func browserRunnerEnvironment(environment []string, outputDirectory string, debug bool) ([]string, error) {
	environment = withoutEnvironment(environment, "QLOGDIR")
	if !debug {
		return environment, nil
	}
	qlogDirectory := filepath.Join(outputDirectory, "qlog")
	if err := os.Mkdir(qlogDirectory, 0o700); err != nil {
		return nil, err
	}
	return append(environment, "QLOGDIR="+qlogDirectory), nil
}

func browserRunnerPlanForRequest(request browserWorkerRequest, sourceURL, certificateHash string) browserRunnerPlan {
	seconds := func(value int) int64 { return int64(value) * 1000 }
	_, runtimeAddress := browserRuntimePlacement(request)
	browser := request.Browser
	if browser == "" {
		browser = BrowserChromium
	}
	return browserRunnerPlan{
		SchemaVersion: 1, Browser: browser, Topology: request.Topology, ProfileID: request.Plan.ID, RunNumber: request.RunNumber,
		Mode: "forced", ColdDiagnostic: request.Diagnostic, DiagnosticsEnabled: request.Diagnostic,
		Policy: "require_quic_family", ArtifactSourceURL: sourceURL, CertificateHash: certificateHash,
		ClientNamespace: request.ClientNamespace, ModuleBindAddress: runtimeAddress, ModuleAdvertiseHost: runtimeAddress,
		OutputDirectory: request.OutputDirectory, CellDeadlineMS: seconds(request.Plan.CellWatchdogMinutes * 60),
		CleanupDeadlineMS: seconds(request.Plan.CleanupDeadlineSeconds), Network: request.Plan.Network,
		Cold: browserRunnerColdPlan{Operations: request.Plan.Cold.Operations, MaxInflight: request.Plan.Cold.MaxInflight, StartRatePerSecond: request.Plan.Cold.StartRatePerSecond, OperationDeadlineMS: seconds(request.Plan.Cold.OperationDeadlineSeconds), PhaseDeadlineMS: seconds(request.Plan.Cold.PhaseDeadlineSeconds)},
		RPC:  browserRunnerRPCPlan{Operations: request.Plan.RPC.Operations, Workers: request.Plan.RPC.Workers, RequestBytes: request.Plan.RPC.RequestBytes, OperationDeadlineMS: seconds(request.Plan.RPC.OperationDeadlineSeconds), PhaseDeadlineMS: seconds(request.Plan.RPC.PhaseDeadlineSeconds)},
		Bulk: browserRunnerBulkPlan{WarmupBytesPerDirection: request.Plan.Bulk.WarmupBytesPerDirection, ScoreBytesPerDirection: request.Plan.Bulk.ScoreBytesPerDirection, PhaseDeadlineMS: seconds(request.Plan.Bulk.PhaseDeadlineSeconds)},
	}
}
