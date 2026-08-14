package perfreport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

type Status string

const (
	StatusPass        Status = "PASS"
	StatusFail        Status = "FAIL"
	StatusUnsupported Status = "UNSUPPORTED"
)

type Section string

const (
	SectionConnectionEstablishment Section = "Connection Establishment"
	SectionSingleConnection        Section = "Single-Connection Throughput"
	SectionStreamingThroughput     Section = "Streaming Throughput"
	SectionCapacity                Section = "Capacity"
	SectionResourceUsage           Section = "Resource Usage"
	SectionSoak                    Section = "Soak and Stability"
)

var sectionOrder = []Section{
	SectionConnectionEstablishment,
	SectionSingleConnection,
	SectionStreamingThroughput,
	SectionCapacity,
	SectionResourceUsage,
	SectionSoak,
}

type Measurement struct {
	Name       string  `json:"name"`
	Observed   float64 `json:"observed"`
	Threshold  float64 `json:"threshold"`
	Unit       string  `json:"unit"`
	Comparator string  `json:"comparator"`
	Status     Status  `json:"status"`
}

func (value Measurement) Validate() error {
	if strings.TrimSpace(value.Name) == "" || strings.TrimSpace(value.Unit) == "" {
		return errors.New("measurement name and unit are required")
	}
	if math.IsNaN(value.Observed) || math.IsInf(value.Observed, 0) || math.IsNaN(value.Threshold) || math.IsInf(value.Threshold, 0) {
		return errors.New("measurement observed and threshold values must be finite")
	}
	if value.Comparator != "<=" && value.Comparator != ">=" && value.Comparator != "==" {
		return fmt.Errorf("measurement comparator %q is invalid", value.Comparator)
	}
	if value.Status != StatusPass && value.Status != StatusFail {
		return fmt.Errorf("measurement status %q is invalid", value.Status)
	}
	passed := value.Observed == value.Threshold
	if value.Comparator == "<=" {
		passed = value.Observed <= value.Threshold
	} else if value.Comparator == ">=" {
		passed = value.Observed >= value.Threshold
	}
	if passed != (value.Status == StatusPass) {
		return errors.New("measurement status does not match observed threshold comparison")
	}
	return nil
}

type RawSample struct {
	Round  int                `json:"round"`
	Phase  string             `json:"phase,omitempty"`
	Values map[string]float64 `json:"values"`
}

type CaseResult struct {
	ID            string            `json:"id"`
	Section       Section           `json:"section"`
	Status        Status            `json:"status"`
	StartedAt     time.Time         `json:"started_at,omitempty"`
	EndedAt       time.Time         `json:"ended_at,omitempty"`
	Stage         string            `json:"stage,omitempty"`
	FirstError    string            `json:"first_error,omitempty"`
	Limitation    string            `json:"limitation,omitempty"`
	Configuration map[string]string `json:"configuration,omitempty"`
	Measurements  []Measurement     `json:"measurements,omitempty"`
	RawSamples    []RawSample       `json:"raw_samples,omitempty"`
}

func (value CaseResult) Validate() error {
	if strings.TrimSpace(value.ID) == "" {
		return errors.New("case ID is required")
	}
	if value.Status != StatusPass && value.Status != StatusFail && value.Status != StatusUnsupported {
		return fmt.Errorf("case %s status %q is invalid", value.ID, value.Status)
	}
	if value.Status == StatusUnsupported {
		if strings.TrimSpace(value.Limitation) == "" {
			return fmt.Errorf("unsupported case %s requires a capability reason", value.ID)
		}
		return nil
	}
	if value.Section == "" {
		return fmt.Errorf("case %s section is required", value.ID)
	}
	if value.Status == StatusPass && len(value.Measurements) == 0 {
		return fmt.Errorf("successful case %s has no observed metrics", value.ID)
	}
	if value.Status == StatusFail && strings.TrimSpace(value.FirstError) == "" {
		return fmt.Errorf("failed case %s requires its first error", value.ID)
	}
	for _, measurement := range value.Measurements {
		if err := measurement.Validate(); err != nil {
			return fmt.Errorf("case %s measurement %q: %w", value.ID, measurement.Name, err)
		}
		if value.Status == StatusPass && measurement.Status != StatusPass {
			return fmt.Errorf("successful case %s contains failed measurement %q", value.ID, measurement.Name)
		}
	}
	for _, sample := range value.RawSamples {
		if sample.Round <= 0 || len(sample.Values) == 0 {
			return fmt.Errorf("case %s has an empty raw sample", value.ID)
		}
		for name, observed := range sample.Values {
			if strings.TrimSpace(name) == "" || math.IsNaN(observed) || math.IsInf(observed, 0) {
				return fmt.Errorf("case %s has an invalid raw sample", value.ID)
			}
		}
	}
	return nil
}

type Environment struct {
	HostName        string `json:"host_name"`
	OS              string `json:"os"`
	Kernel          string `json:"kernel"`
	Architecture    string `json:"architecture"`
	CPUModel        string `json:"cpu_model"`
	LogicalCPUs     int    `json:"logical_cpus"`
	MemoryBytes     uint64 `json:"memory_bytes"`
	GoVersion       string `json:"go_version"`
	NodeVersion     string `json:"node_version"`
	ChromiumVersion string `json:"chromium_version"`
}

type Report struct {
	SourceSHA   string        `json:"source_sha"`
	Status      Status        `json:"status"`
	StartedAt   time.Time     `json:"started_at"`
	EndedAt     time.Time     `json:"ended_at"`
	Budget      time.Duration `json:"budget_ns,omitempty"`
	Environment Environment   `json:"environment"`
	Cases       []CaseResult  `json:"cases"`
}

func (value Report) Validate() error {
	if !validSHA(value.SourceSHA) || value.Status != StatusPass && value.Status != StatusFail {
		return errors.New("report identity or status is invalid")
	}
	if value.StartedAt.IsZero() || value.EndedAt.Before(value.StartedAt) {
		return errors.New("report timestamps are invalid")
	}
	if value.Environment.HostName != "udesk24" || value.Environment.LogicalCPUs <= 0 || value.Environment.MemoryBytes == 0 {
		return errors.New("performance reports require the explicit udesk24 environment")
	}
	if len(value.Cases) == 0 {
		return errors.New("report contains no cases")
	}
	seen := make(map[string]struct{}, len(value.Cases))
	failed := false
	for _, result := range value.Cases {
		if _, duplicate := seen[result.ID]; duplicate {
			return fmt.Errorf("duplicate case ID %q", result.ID)
		}
		seen[result.ID] = struct{}{}
		if err := result.Validate(); err != nil {
			return err
		}
		failed = failed || result.Status == StatusFail
	}
	if failed != (value.Status == StatusFail) {
		return errors.New("overall report status does not match case statuses")
	}
	return nil
}

func validSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func Percentile(values []float64, quantile float64) float64 {
	if len(values) == 0 || quantile < 0 || quantile > 1 || math.IsNaN(quantile) {
		return math.NaN()
	}
	ordered := slices.Clone(values)
	for _, value := range ordered {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return math.NaN()
		}
	}
	sort.Float64s(ordered)
	index := int(math.Ceil(quantile*float64(len(ordered)))) - 1
	if index < 0 {
		index = 0
	}
	return ordered[index]
}

func ThroughputMiBPerSecond(verifiedBytes uint64, duration time.Duration) float64 {
	if verifiedBytes == 0 || duration <= 0 {
		return math.NaN()
	}
	return float64(verifiedBytes) / float64(1<<20) / duration.Seconds()
}

// CPU utilization is process-tree CPU time divided by wall time and logical CPUs.
func CPUUtilizationPercent(cpuTime, wallTime time.Duration, logicalCPUs int) float64 {
	if cpuTime < 0 || wallTime <= 0 || logicalCPUs <= 0 {
		return math.NaN()
	}
	return cpuTime.Seconds() / wallTime.Seconds() / float64(logicalCPUs) * 100
}

func PerSessionMemoryBytes(peakRSS, baselineRSS uint64, sessions int) float64 {
	if sessions <= 0 || peakRSS < baselineRSS {
		return math.NaN()
	}
	return float64(peakRSS-baselineRSS) / float64(sessions)
}

func WriteCaseResult(path string, result CaseResult) error {
	if err := result.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return writeAtomic(path, append(data, '\n'), 0o600)
}

func ReadCaseResult(path string) (CaseResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return CaseResult{}, err
	}
	var result CaseResult
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return CaseResult{}, err
	}
	if err := result.Validate(); err != nil {
		return CaseResult{}, err
	}
	return result, nil
}

func WriteMarkdown(path string, report Report) error {
	if err := report.Validate(); err != nil {
		return err
	}
	if filepath.Ext(path) != ".md" {
		return errors.New("performance report path must end in .md")
	}
	return writeAtomic(path, renderMarkdown(report), 0o644)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".flowersec-performance-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func renderMarkdown(report Report) []byte {
	var output bytes.Buffer
	passed, failed, unsupported := 0, 0, 0
	for _, result := range report.Cases {
		switch result.Status {
		case StatusPass:
			passed++
		case StatusFail:
			failed++
		case StatusUnsupported:
			unsupported++
		}
	}
	fmt.Fprint(&output, "# Flowersec Performance Report\n\n")
	fmt.Fprint(&output, "## Executive Summary\n\n")
	fmt.Fprintf(&output, "| Field | Value |\n|---|---|\n| Source SHA | `%s` |\n", report.SourceSHA)
	if report.Budget > 0 {
		fmt.Fprintf(&output, "| Wall-clock budget | %s |\n", report.Budget)
	}
	fmt.Fprintf(&output, "| Overall status | **%s** |\n| Started | %s |\n| Ended | %s |\n| Total duration | %s |\n| Passed / Failed / Unsupported | %d / %d / %d |\n\n", report.Status, report.StartedAt.Format(time.RFC3339), report.EndedAt.Format(time.RFC3339), report.EndedAt.Sub(report.StartedAt).Round(time.Millisecond), passed, failed, unsupported)
	env := report.Environment
	fmt.Fprint(&output, "## Test Environment\n\n")
	fmt.Fprintf(&output, "| Field | Value |\n|---|---|\n| Host | **%s** |\n| OS | %s |\n| Kernel | %s |\n| Architecture | %s |\n| CPU | %s (%d logical CPUs) |\n| Memory | %.2f GiB |\n| Go | %s |\n| Node | %s |\n| Chromium | %s |\n\n", env.HostName, env.OS, env.Kernel, env.Architecture, env.CPUModel, env.LogicalCPUs, float64(env.MemoryBytes)/float64(1<<30), env.GoVersion, env.NodeVersion, env.ChromiumVersion)
	fmt.Fprint(&output, "## Threshold and Result Summary\n\n")
	fmt.Fprintln(&output, "| Case | Metric | Observed | Threshold | Unit | Comparator | Status |\n|---|---|---:|---:|---|---|---|")
	for _, result := range report.Cases {
		for _, measurement := range result.Measurements {
			fmt.Fprintf(&output, "| %s | %s | %.3f | %.3f | %s | %s | %s |\n", escape(result.ID), escape(measurement.Name), measurement.Observed, measurement.Threshold, escape(measurement.Unit), measurement.Comparator, measurement.Status)
		}
	}
	fmt.Fprintln(&output)
	for _, section := range sectionOrder {
		fmt.Fprintf(&output, "## %s\n\n", section)
		found := false
		for _, result := range report.Cases {
			metrics := measurementsForSection(result, section)
			if result.Section != section && len(metrics) == 0 {
				continue
			}
			found = true
			fmt.Fprintf(&output, "### %s\n\nStatus: **%s**\n\n", result.ID, result.Status)
			if !result.StartedAt.IsZero() && !result.EndedAt.Before(result.StartedAt) {
				fmt.Fprintf(&output, "Started: %s  \nEnded: %s  \nDuration: %s\n\n", result.StartedAt.Format(time.RFC3339), result.EndedAt.Format(time.RFC3339), result.EndedAt.Sub(result.StartedAt).Round(time.Millisecond))
			}
			if section == SectionResourceUsage {
				fmt.Fprint(&output, "CPU utilization is process or process-tree CPU time divided by monotonic wall time and logical CPU count. CPU time is retained as a separate observed metric.\n\n")
			}
			if len(result.Configuration) > 0 {
				keys := make([]string, 0, len(result.Configuration))
				for key := range result.Configuration {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					fmt.Fprintf(&output, "- %s: %s\n", key, result.Configuration[key])
				}
				fmt.Fprintln(&output)
			}
			if result.Limitation != "" {
				fmt.Fprintf(&output, "Capability limitation: %s\n\n", result.Limitation)
			}
			if len(metrics) > 0 {
				fmt.Fprintln(&output, "| Metric | Observed | Threshold | Unit | Status |\n|---|---:|---:|---|---|")
				for _, metric := range metrics {
					fmt.Fprintf(&output, "| %s | %.3f | %s %.3f | %s | %s |\n", escape(metric.Name), metric.Observed, metric.Comparator, metric.Threshold, escape(metric.Unit), metric.Status)
				}
				fmt.Fprintln(&output)
			}
		}
		if !found {
			fmt.Fprint(&output, "No cases were registered for this section.\n\n")
		}
	}
	fmt.Fprint(&output, "## Failures and Limitations\n\n")
	hasFailure := false
	for _, result := range report.Cases {
		if result.Status == StatusFail {
			hasFailure = true
			fmt.Fprintf(&output, "- `%s`, stage `%s`: %s\n", result.ID, result.Stage, result.FirstError)
		} else if result.Status == StatusUnsupported {
			hasFailure = true
			fmt.Fprintf(&output, "- `%s` unsupported: %s\n", result.ID, result.Limitation)
		}
	}
	if !hasFailure {
		fmt.Fprintln(&output, "None.")
	}
	fmt.Fprint(&output, "\n## Raw Samples Appendix\n\n")
	for _, result := range report.Cases {
		if len(result.RawSamples) == 0 {
			continue
		}
		fmt.Fprintf(&output, "### %s\n\n| Round | Phase | Measurements |\n|---:|---|---|\n", result.ID)
		for _, sample := range result.RawSamples {
			keys := make([]string, 0, len(sample.Values))
			for key := range sample.Values {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(keys))
			for _, key := range keys {
				parts = append(parts, fmt.Sprintf("%s=%.3f", key, sample.Values[key]))
			}
			fmt.Fprintf(&output, "| %d | %s | %s |\n", sample.Round, escape(sample.Phase), strings.Join(parts, "; "))
		}
		fmt.Fprintln(&output)
	}
	return output.Bytes()
}

func measurementsForSection(result CaseResult, section Section) []Measurement {
	if result.Section == section {
		return result.Measurements
	}
	var selected []Measurement
	for _, measurement := range result.Measurements {
		name := strings.ToLower(measurement.Name)
		switch section {
		case SectionConnectionEstablishment:
			if strings.Contains(name, "connect") || strings.Contains(name, "attempted sessions") || strings.Contains(name, "succeeded sessions") {
				selected = append(selected, measurement)
			}
		case SectionResourceUsage:
			if strings.Contains(name, "rss") || strings.Contains(name, "cpu") || strings.Contains(name, "memory per") || strings.Contains(name, "open fd") || strings.Contains(name, "goroutine") || strings.Contains(name, "task/process") {
				selected = append(selected, measurement)
			}
		}
	}
	return selected
}

func escape(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "|", "\\|"), "\n", " ")
}
