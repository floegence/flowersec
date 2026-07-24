package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
)

const baselineTarget = "direct-clean-baseline"

var gitSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

var buildSourceSHA string

type baselineReport struct {
	SchemaVersion  int                     `json:"schema_version"`
	Classification string                  `json:"classification"`
	SourceSHA      string                  `json:"source_sha"`
	ManifestDigest string                  `json:"manifest_digest"`
	ManifestSHA256 string                  `json:"manifest_file_sha256"`
	Runner         baselineRunner          `json:"runner"`
	StartedAt      time.Time               `json:"started_at"`
	FinishedAt     time.Time               `json:"finished_at"`
	Results        []baselineCarrierResult `json:"results"`
}

type baselineRunner struct {
	OS            string `json:"os"`
	Architecture  string `json:"architecture"`
	KernelRelease string `json:"kernel_release"`
}

type baselineCarrierResult struct {
	Run             int                                 `json:"run"`
	Carrier         string                              `json:"carrier"`
	Cold            []transportrelease.ConnectOperation `json:"cold"`
	RPC             []transportrelease.Operation        `json:"rpc"`
	Bulk            transportrelease.BulkResult         `json:"bulk"`
	CleanupDuration time.Duration                       `json:"cleanup_duration_ns"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("transport-release-runner", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	target := flags.String("target", "", "runner target")
	manifestPath := flags.String("manifest", "", "performance manifest path")
	reportPath := flags.String("report", "", "new baseline report path")
	sourceSHA := flags.String("source-sha", "", "exact source commit")
	sourceRoot := flags.String("source-root", "", "clean source checkout root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *target != baselineTarget || *manifestPath == "" || *reportPath == "" || !gitSHAPattern.MatchString(*sourceSHA) || *sourceRoot == "" || flags.NArg() != 0 {
		return errors.New("runner requires --target direct-clean-baseline, --manifest, --report, --source-root, and a full --source-sha")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return errors.New("direct clean baseline requires Linux amd64")
	}
	actualSourceSHA, err := executableSourceSHA()
	if err != nil {
		return err
	}
	if actualSourceSHA != *sourceSHA {
		return fmt.Errorf("source SHA %s does not match executable revision %s", *sourceSHA, actualSourceSHA)
	}
	if err := verifySourceCheckout(*sourceRoot, *manifestPath, *sourceSHA); err != nil {
		return err
	}
	plan, manifest, err := transportrelease.LoadReleasePlan(*manifestPath)
	if err != nil {
		return err
	}
	kernel, err := kernelRelease()
	if err != nil {
		return err
	}
	report := baselineReport{
		SchemaVersion: 1, Classification: "linux_transport_workload_baseline",
		SourceSHA: *sourceSHA, ManifestDigest: manifest.Digest,
		ManifestSHA256: hex.EncodeToString(manifest.SHA256Sum[:]),
		Runner:         baselineRunner{OS: runtime.GOOS, Architecture: runtime.GOARCH, KernelRelease: kernel},
		StartedAt:      time.Now().UTC(),
	}
	cellDeadline := time.Duration(plan.Clean.CellWatchdogMinutes) * time.Minute
	globalCtx, cancel := context.WithTimeout(context.Background(), 3*cellDeadline)
	defer cancel()
	for _, cell := range workloadSchedule(plan.RunCount) {
		cellCtx, cancelCell := context.WithTimeout(globalCtx, cellDeadline)
		cellStarted := time.Now()
		for _, runNumber := range cell.Runs {
			result, err := runCarrier(cellCtx, cell.Carrier, plan.Clean)
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
	endpointClosed := false
	defer func() {
		if !endpointClosed {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = closeWithin(cleanupCtx, endpoint.Close)
			cancel()
		}
	}()
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
	bulkLimit := time.Duration(plan.Bulk.PhaseDeadlineSeconds) * time.Second
	bulkCtx, cancelBulk := context.WithTimeout(ctx, bulkLimit)
	bulkStarted := time.Now()
	bulk, err := transportrelease.RunBulk(bulkCtx, pair, plan.Bulk.WarmupBytesPerDirection, plan.Bulk.ScoreBytesPerDirection)
	deadlineErr = completedWithin(bulkCtx, bulkStarted, bulkLimit)
	cancelBulk()
	if err != nil || deadlineErr != nil {
		return baselineCarrierResult{}, errors.Join(err, deadlineErr)
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
	return baselineCarrierResult{
		Carrier: string(kind), Cold: cold, RPC: rpc, Bulk: bulk,
		CleanupDuration: time.Since(cleanupStarted),
	}, nil
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

func executableSourceSHA() (string, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", errors.New("executable has no Go build information")
	}
	var revision, modified string
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value
		}
	}
	if revision != "" {
		if !gitSHAPattern.MatchString(revision) || modified != "false" {
			return "", errors.New("executable VCS stamp is not a clean full Git revision")
		}
		if buildSourceSHA != "" && buildSourceSHA != revision {
			return "", errors.New("executable VCS and linked source revisions disagree")
		}
		return revision, nil
	}
	if !gitSHAPattern.MatchString(buildSourceSHA) {
		return "", errors.New("executable requires a full linked buildSourceSHA when automatic VCS stamping is unavailable")
	}
	return buildSourceSHA, nil
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

func writeNewReport(path string, report baselineReport) error {
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
