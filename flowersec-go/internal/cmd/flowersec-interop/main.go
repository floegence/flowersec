package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/interopprotocol"
)

type profileDocument struct {
	Version  int                    `json:"version"`
	Seed     int64                  `json:"seed"`
	Variants []variant              `json:"variants"`
	Profiles map[string]profileSpec `json:"profiles"`
}

type variant struct {
	Transport string `json:"transport"`
	Suite     string `json:"suite"`
}

type profileSpec struct {
	DeadlineMS       int                                     `json:"deadline_ms"`
	CellDeadlineMS   int                                     `json:"cell_deadline_ms"`
	MaxParallelCells int                                     `json:"max_parallel_cells"`
	Streams          interopprotocol.StreamWorkload          `json:"streams"`
	Rekey            interopprotocol.RekeyWorkload           `json:"rekey"`
	LivenessProbes   int                                     `json:"liveness_probes"`
	RPC              interopprotocol.RPCWorkload             `json:"rpc"`
	Proxy            interopprotocol.ProxyWorkload           `json:"proxy"`
	ReconnectCycles  int                                     `json:"reconnect_cycles"`
	LimitChecks      int                                     `json:"limit_checks"`
	Diagnostics      []interopprotocol.DiagnosticExpectation `json:"diagnostics"`
}

func (p profileSpec) workload() interopprotocol.Workload {
	return interopprotocol.Workload{
		Streams: p.Streams, Rekey: p.Rekey, LivenessProbes: p.LivenessProbes,
		RPC: p.RPC, Proxy: p.Proxy, ReconnectCycles: p.ReconnectCycles, LimitChecks: p.LimitChecks,
	}
}

var matrixCells = []string{
	"go_to_go",
	"typescript_to_go",
	"swift_to_go",
	"rust_to_go",
	"go_to_typescript",
	"go_to_swift",
	"go_to_rust",
}

func main() {
	profileName := flag.String("profile", "smoke", "interop profile: smoke or stress")
	cellsValue := flag.String("cells", strings.Join(matrixCells, ","), "comma-separated directed matrix cells")
	reportPath := flag.String("report", "", "optional JSON result path")
	deadlineMS := flag.Int("deadline-ms", 0, "explicit execution deadline override that may only reduce the profile budget")
	flag.Parse()

	if err := run(*profileName, *cellsValue, *reportPath, *deadlineMS); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(profileName, cellsValue, reportPath string, deadlineOverrideMS int) (returnErr error) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}
	document, err := loadProfiles(filepath.Join(repoRoot, "testdata/interop/v1/profiles.json"))
	if err != nil {
		return err
	}
	profile, ok := document.Profiles[profileName]
	if !ok {
		return fmt.Errorf("unknown interop profile %q", profileName)
	}
	if deadlineOverrideMS < 0 || deadlineOverrideMS > profile.DeadlineMS {
		return fmt.Errorf("deadline override must be between 0 and the %s profile budget", profileName)
	}
	deadlineMS := profile.DeadlineMS
	if deadlineOverrideMS > 0 {
		deadlineMS = deadlineOverrideMS
	}
	if err := profile.workload().Validate(); err != nil {
		return fmt.Errorf("invalid %s workload: %w", profileName, err)
	}
	cells, err := parseCells(cellsValue)
	if err != nil {
		return err
	}
	if !slices.Contains(cells, "go_to_go") {
		return errors.New("the Go -> Go baseline is mandatory")
	}
	if err := prepareHarnesses(repoRoot, cells); err != nil {
		return err
	}

	environment, err := newEnvironment(repoRoot)
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, environment.Close())
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(deadlineMS)*time.Millisecond)
	defer cancel()
	report := matrixReport{
		V: 1, Profile: profileName, Seed: document.Seed, StartedAt: time.Now().UTC(),
		Commit: gitCommit(repoRoot), Tools: toolVersions(),
		Cells: make([]cellReport, 0, len(cells)*len(document.Variants)),
	}

	baselineCtx, baselineCancel := context.WithTimeout(ctx, time.Duration(profile.CellDeadlineMS)*time.Millisecond)
	baselineReports, baselineErr := runBaselineVariants(
		baselineCtx,
		document.Variants,
		profile.Diagnostics,
		func(value variant) (timedResult, error) {
			return environment.runGoBaseline(baselineCtx, value, profile.workload())
		},
	)
	baselineCancel()
	report.Cells = append(report.Cells, baselineReports...)
	if baselineErr != nil {
		report.finalize()
		return errors.Join(baselineErr, writeReport(reportPath, report))
	}

	externalReports, externalErr := runExternalMatrix(
		ctx, environment, repoRoot, profileName, cells, document.Variants, profile,
	)
	report.Cells = append(report.Cells, externalReports...)
	if externalErr != nil {
		report.finalize()
		return errors.Join(externalErr, writeReport(reportPath, report))
	}
	report.finalize()
	if err := writeReport(reportPath, report); err != nil {
		return err
	}
	return interopprotocol.Encode(os.Stdout, report)
}

type externalCellJob struct {
	index int
	cell  string
}

type externalCellResult struct {
	index   int
	reports []cellReport
	err     error
}

func runExternalMatrix(
	ctx context.Context,
	environment *environment,
	repoRoot, profileName string,
	cells []string,
	variants []variant,
	profile profileSpec,
) ([]cellReport, error) {
	jobs := make([]externalCellJob, 0, len(cells)-1)
	for _, cell := range cells {
		if cell != "go_to_go" {
			jobs = append(jobs, externalCellJob{index: len(jobs), cell: cell})
		}
	}
	if len(jobs) == 0 {
		return nil, nil
	}

	return runExternalJobs(ctx, jobs, profile.MaxParallelCells, func(groupCtx context.Context, job externalCellJob) ([]cellReport, error) {
		return runExternalDirectedCell(
			groupCtx, environment, repoRoot, profileName, job.cell, variants, profile,
		)
	})
}

func runBaselineVariants(
	ctx context.Context,
	variants []variant,
	expected []interopprotocol.DiagnosticExpectation,
	runVariant func(variant) (timedResult, error),
) ([]cellReport, error) {
	reports := make([]cellReport, 0, len(variants))
	for _, value := range variants {
		if err := ctx.Err(); err != nil {
			return reports, err
		}
		result, runErr := runVariant(value)
		if runErr == nil {
			runErr = interopprotocol.ValidateDiagnostics(result.Diagnostics, value.Transport, expected)
		}
		reports = append(reports, newCellReport("go_to_go", value, result, runErr))
		if runErr != nil {
			return reports, fmt.Errorf("Go reference baseline %s/%s failed: %w", value.Transport, value.Suite, runErr)
		}
	}
	return reports, nil
}

func runExternalJobs(
	ctx context.Context,
	jobs []externalCellJob,
	maxParallel int,
	runJob func(context.Context, externalCellJob) ([]cellReport, error),
) ([]cellReport, error) {
	if maxParallel <= 0 {
		return nil, errors.New("external matrix parallelism must be positive")
	}
	if runJob == nil {
		return nil, errors.New("external matrix job runner is required")
	}
	if len(jobs) == 0 {
		return nil, ctx.Err()
	}
	groupCtx, cancelGroup := context.WithCancel(ctx)
	defer cancelGroup()
	jobChannel := make(chan externalCellJob, len(jobs))
	resultChannel := make(chan externalCellResult, len(jobs))
	for _, job := range jobs {
		jobChannel <- job
	}
	close(jobChannel)

	var failureOnce sync.Once
	var workers sync.WaitGroup
	workerCount := min(maxParallel, len(jobs))
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for job := range jobChannel {
				if groupCtx.Err() != nil {
					return
				}
				reports, err := runJob(groupCtx, job)
				resultChannel <- externalCellResult{index: job.index, reports: reports, err: err}
				if err != nil {
					failureOnce.Do(func() {
						cancelGroup()
					})
					return
				}
			}
		}()
	}
	workers.Wait()
	close(resultChannel)

	ordered := make([][]cellReport, len(jobs))
	orderedErrors := make([]error, len(jobs))
	for result := range resultChannel {
		ordered[result.index] = result.reports
		orderedErrors[result.index] = result.err
	}
	reports := make([]cellReport, 0, len(jobs))
	for _, cellReports := range ordered {
		reports = append(reports, cellReports...)
	}
	if err := errors.Join(orderedErrors...); err != nil {
		return reports, err
	}
	return reports, ctx.Err()
}

func runExternalDirectedCell(
	ctx context.Context,
	environment *environment,
	repoRoot, profileName, cell string,
	variants []variant,
	profile profileSpec,
) ([]cellReport, error) {
	cellCtx, cancelCell := context.WithTimeout(
		ctx, time.Duration(profile.CellDeadlineMS)*time.Millisecond,
	)
	defer cancelCell()
	reports := make([]cellReport, 0, len(variants))
	for _, value := range variants {
		result, runErr := environment.runExternalCell(
			cellCtx, repoRoot, cell, profileName, value, profile.workload(),
		)
		if runErr == nil {
			runErr = interopprotocol.ValidateDiagnostics(result.Diagnostics, value.Transport, profile.Diagnostics)
		}
		reports = append(reports, newCellReport(cell, value, result, runErr))
		if runErr != nil {
			return reports, fmt.Errorf(
				"interop cell %s %s/%s failed: %w",
				cell, value.Transport, value.Suite, runErr,
			)
		}
	}
	return reports, nil
}

func loadProfiles(path string) (profileDocument, error) {
	file, err := os.Open(path)
	if err != nil {
		return profileDocument{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var document profileDocument
	if err := decoder.Decode(&document); err != nil {
		return profileDocument{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return profileDocument{}, errors.New("profiles JSON contains trailing data")
	}
	if document.Version != 1 || document.Seed <= 0 || len(document.Variants) != 4 {
		return profileDocument{}, errors.New("invalid interop profiles document")
	}
	for name, profile := range document.Profiles {
		if profile.DeadlineMS <= 0 || profile.CellDeadlineMS <= 0 ||
			profile.MaxParallelCells <= 0 || profile.MaxParallelCells > 2 {
			return profileDocument{}, fmt.Errorf("profile %q has invalid execution limits", name)
		}
		if err := interopprotocol.ValidateDiagnosticExpectations(profile.Diagnostics, profile.LimitChecks); err != nil {
			return profileDocument{}, fmt.Errorf("profile %q diagnostics: %w", name, err)
		}
	}
	return document, nil
}

func parseCells(value string) ([]string, error) {
	parts := strings.Split(value, ",")
	seen := make(map[string]struct{}, len(parts))
	cells := make([]string, 0, len(parts))
	for _, part := range parts {
		cell := strings.TrimSpace(part)
		if !slices.Contains(matrixCells, cell) {
			return nil, fmt.Errorf("unknown matrix cell %q", cell)
		}
		if _, exists := seen[cell]; exists {
			return nil, fmt.Errorf("duplicate matrix cell %q", cell)
		}
		seen[cell] = struct{}{}
		cells = append(cells, cell)
	}
	return cells, nil
}

func findRepoRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "stability/interop_matrix.json")); err == nil {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", errors.New("repository root not found")
		}
		directory = parent
	}
}
