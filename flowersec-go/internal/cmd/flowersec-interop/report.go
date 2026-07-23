package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"slices"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/interopprotocol"
)

type matrixReport struct {
	V          int               `json:"v"`
	Profile    string            `json:"profile"`
	Seed       int64             `json:"seed"`
	Commit     string            `json:"commit"`
	Tools      map[string]string `json:"tools"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt time.Time         `json:"finished_at"`
	Cells      []cellReport      `json:"cells"`
	Summaries  []cellSummary     `json:"cell_summaries"`
}

type cellSummary struct {
	Cell  string `json:"cell"`
	P50MS int64  `json:"p50_ms"`
	P95MS int64  `json:"p95_ms"`
	P99MS int64  `json:"p99_ms"`
}

type cellReport struct {
	Cell        string                       `json:"cell"`
	Transport   string                       `json:"transport"`
	Suite       string                       `json:"suite"`
	Metrics     interopprotocol.Metrics      `json:"metrics"`
	Diagnostics []interopprotocol.Diagnostic `json:"diagnostics"`
	DurationMS  int64                        `json:"duration_ms"`
	Error       string                       `json:"error,omitempty"`
}

type timedResult struct {
	Metrics     interopprotocol.Metrics
	Diagnostics []interopprotocol.Diagnostic
	Duration    time.Duration
}

func newCellReport(cell string, value variant, result timedResult, err error) cellReport {
	report := cellReport{
		Cell: cell, Transport: value.Transport, Suite: value.Suite,
		Metrics: result.Metrics, Diagnostics: result.Diagnostics, DurationMS: result.Duration.Milliseconds(),
	}
	if err != nil {
		report.Error = err.Error()
	}
	return report
}

func writeReport(path string, report matrixReport) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func (report *matrixReport) finalize() {
	report.FinishedAt = time.Now().UTC()
	grouped := make(map[string][]int64)
	order := make([]string, 0)
	for _, cell := range report.Cells {
		if _, ok := grouped[cell.Cell]; !ok {
			order = append(order, cell.Cell)
		}
		grouped[cell.Cell] = append(grouped[cell.Cell], cell.DurationMS)
	}
	report.Summaries = make([]cellSummary, 0, len(order))
	for _, cell := range order {
		values := grouped[cell]
		slices.Sort(values)
		report.Summaries = append(report.Summaries, cellSummary{
			Cell: cell, P50MS: percentile(values, 50), P95MS: percentile(values, 95),
			P99MS: percentile(values, 99),
		})
	}
}

func percentile(values []int64, percentage int) int64 {
	if len(values) == 0 {
		return 0
	}
	index := (percentage*len(values) + 99) / 100
	return values[max(0, index-1)]
}

func toolVersions() map[string]string {
	commands := map[string][]string{
		"go": {"go", "version"}, "node": {"node", "--version"},
		"npm": {"npm", "--version"}, "rustc": {"rustc", "--version"},
		"swift": {"swift", "--version"},
	}
	versions := make(map[string]string, len(commands))
	for name, arguments := range commands {
		command := exec.Command(arguments[0], arguments[1:]...)
		output, err := command.Output()
		if err != nil {
			versions[name] = "unavailable"
			continue
		}
		versions[name] = stringTrimSpace(output)
	}
	return versions
}

func gitCommit(repoRoot string) string {
	command := exec.Command("git", "rev-parse", "HEAD")
	command.Dir = repoRoot
	output, err := command.Output()
	if err != nil {
		return "unknown"
	}
	return stringTrimSpace(output)
}

func stringTrimSpace(value []byte) string {
	for len(value) > 0 && (value[len(value)-1] == '\n' || value[len(value)-1] == '\r' || value[len(value)-1] == ' ') {
		value = value[:len(value)-1]
	}
	if len(value) == 0 {
		return "unknown"
	}
	return string(value)
}

func joinedError(current *error, err error) {
	if err == nil {
		return
	}
	*current = errors.Join(*current, err)
}
