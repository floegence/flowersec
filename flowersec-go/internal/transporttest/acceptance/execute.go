package acceptance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/transporttest"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transporttest/linuxnetlab"
)

// RunTest executes one minimal browser smoke test. It owns all setup,
// child processes, privileged resources, assertions, and teardown.
func RunTest(ctx context.Context, run RunContext, topology string) (resultErr error) {
	return runTest(ctx, run, topology)
}

// RunSingleTest executes the same browser smoke cell without runner progress.
func RunSingleTest(ctx context.Context, run RunContext, topology string) (resultErr error) {
	return runTest(ctx, run, topology)
}

func runTest(ctx context.Context, run RunContext, topology string) (resultErr error) {
	if ctx == nil || run.validate() != nil || !supportedBrowserTopology(topology) {
		return errors.New("acceptance test input is invalid")
	}
	cleanupBrowserSource, err := prepareBrowserSource(ctx, run.Root)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, cleanupBrowserSource()) }()
	if err := linuxnetlab.RecoverOwnedStaleResources(ctx, linuxnetlab.ExecRunner{}, acceptanceTestID(topology)); err != nil {
		return fmt.Errorf("recover stale acceptance resources: %w", err)
	}
	return runBrowserAcceptance(ctx, run, topology, browserSmokePlan(), 1)
}

func prepareBrowserSource(ctx context.Context, sourceRoot string) (func() error, error) {
	packageRoot := filepath.Join(sourceRoot, "flowersec-ts")
	dist := filepath.Join(packageRoot, "dist")
	command := exec.CommandContext(ctx, "npm", "run", "build")
	command.Dir = packageRoot
	if combined, err := command.CombinedOutput(); err != nil {
		_ = os.RemoveAll(dist)
		return nil, fmt.Errorf("build browser acceptance source: %w: %s", err, boundedText(string(combined), 64<<10))
	}
	return func() error { return os.RemoveAll(dist) }, nil
}

func browserSmokePlan() transporttest.ProfilePlan {
	return transporttest.ProfilePlan{
		ID:                     "browser-smoke-v1",
		Cold:                   transporttest.ColdPlan{Operations: 1, MaxInflight: 1, Retries: 0, StartRatePerSecond: 1, OperationDeadlineSeconds: 5, PhaseDeadlineSeconds: 8},
		RPC:                    transporttest.RPCPlan{Operations: 1, RequestBytes: 128, ResponseBytes: 128, Workers: 1, Retries: 0, OperationDeadlineSeconds: 3, PhaseDeadlineSeconds: 5},
		Bulk:                   transporttest.BulkPlan{WarmupBytesPerDirection: 1024, ScoreBytesPerDirection: 4096, PhaseDeadlineSeconds: 4},
		Network:                transporttest.NetworkPlan{LinkMTU: 1500, Firewall: "allow-test-tcp-udp-return-icmp-ptb-only-v1"},
		CleanupDeadlineSeconds: 5, CellWatchdogMinutes: 2,
	}
}

func runNumbers(parent context.Context, runs []int, limit time.Duration, run func(context.Context, int) error) error {
	if parent == nil || len(runs) == 0 || limit <= 0 || run == nil {
		return errors.New("acceptance shard contract is invalid")
	}
	ctx, cancel := context.WithTimeout(parent, limit)
	defer cancel()
	for _, runNumber := range runs {
		if err := run(ctx, runNumber); err != nil {
			return fmt.Errorf("run %d: %w", runNumber, err)
		}
	}
	return context.Cause(ctx)
}

func runBrowserAcceptance(ctx context.Context, run RunContext, topology string, plan transporttest.ProfilePlan, runNumber int) (resultErr error) {
	plan = browserExecutionPlan(plan)
	cellID := strings.ReplaceAll(run.RunID+"-"+topology, "_", "-")
	config, err := linuxnetlab.ConfigForTestRun(acceptanceTestID(topology), cellID, runNumber, plan.Network.LinkMTU, plan.Network.Firewall)
	if err != nil {
		return err
	}
	lab, err := linuxnetlab.Open(ctx, linuxnetlab.ExecRunner{}, config)
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Duration(plan.CleanupDeadlineSeconds)*time.Second)
		resultErr = errors.Join(resultErr, lab.Close(cleanupCtx))
		cancel()
	}()
	outputDirectory, err := os.MkdirTemp(run.TempDir, "browser-runtime-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(outputDirectory)) }()
	request := browserWorkerRequest{
		Browser: run.browser(), Plan: plan, Topology: topology, RunNumber: runNumber,
		ClientNamespace: config.ClientNamespace, ServerNamespace: config.ServerNamespace,
		ClientAddress: config.ClientAddress.Addr().String(), ServerAddress: config.ServerAddress.Addr().String(),
		SourceRoot: run.Root, OutputDirectory: outputDirectory, Diagnostic: run.Debug,
	}
	result, runErr := runBrowserWorkload(ctx, request)
	if runErr != nil {
		return runErr
	}
	if result.Topology != topology || result.ProfileID != plan.ID || result.RunNumber != runNumber || result.Status != "passed" {
		return errors.New("browser worker returned a mismatched acceptance result")
	}
	return nil
}

func acceptanceTestID(topology string) string {
	switch topology {
	case BrowserDirectTopology:
		return "browser/webtransport"
	case BrowserTunnelWTWSS:
		return "browser/tunnel-wt-wss"
	case BrowserTunnelWTQUIC:
		return "browser/tunnel-wt-quic"
	default:
		return ""
	}
}

func browserExecutionPlan(plan transporttest.ProfilePlan) transporttest.ProfilePlan {
	cleanupWaves := (plan.Cold.Operations + plan.Cold.MaxInflight - 1) / plan.Cold.MaxInflight
	phaseSeconds := cleanupWaves*plan.CleanupDeadlineSeconds + 1
	scheduleSeconds := (plan.Cold.Operations - 1 + plan.Cold.StartRatePerSecond - 1) / plan.Cold.StartRatePerSecond
	operationSeconds := scheduleSeconds + plan.Cold.OperationDeadlineSeconds + 1
	if phaseSeconds < operationSeconds {
		phaseSeconds = operationSeconds
	}
	if plan.Cold.PhaseDeadlineSeconds < phaseSeconds {
		plan.Cold.PhaseDeadlineSeconds = phaseSeconds
	}
	return plan
}
