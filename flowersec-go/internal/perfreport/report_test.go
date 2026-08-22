package perfreport

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMeasurementRequiresObservedThresholdUnitAndComparator(t *testing.T) {
	valid := Measurement{Name: "connect p95", Observed: 12, Threshold: 15, Unit: "ms", Comparator: "<=", Status: StatusPass}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Measurement){
		func(value *Measurement) { value.Observed = math.NaN() },
		func(value *Measurement) { value.Threshold = math.Inf(1) },
		func(value *Measurement) { value.Unit = "" },
		func(value *Measurement) { value.Comparator = "" },
	} {
		value := valid
		mutate(&value)
		if err := value.Validate(); err == nil {
			t.Fatalf("invalid measurement accepted: %+v", value)
		}
	}
}

func TestPerformanceCalculations(t *testing.T) {
	values := []float64{1, 2, 3, 4, 5}
	if got := Percentile(values, 0.50); got != 3 {
		t.Fatalf("p50 = %v", got)
	}
	if got := Percentile(values, 0.95); got != 5 {
		t.Fatalf("p95 = %v", got)
	}
	if got := ThroughputMiBPerSecond(10<<20, 2*time.Second); got != 5 {
		t.Fatalf("throughput = %v", got)
	}
	if got := CPUUtilizationPercent(8*time.Second, 2*time.Second, 4); got != 100 {
		t.Fatalf("CPU utilization = %v", got)
	}
	if got := PerSessionMemoryBytes(2100, 100, 10); got != 200 {
		t.Fatalf("per-session memory = %v", got)
	}
	if !math.IsNaN(Percentile(nil, .5)) || !math.IsNaN(ThroughputMiBPerSecond(1, 0)) || !math.IsNaN(CPUUtilizationPercent(time.Second, time.Second, 0)) || !math.IsNaN(PerSessionMemoryBytes(1, 1, 0)) {
		t.Fatal("invalid calculation input did not produce NaN")
	}
}

func TestWriteMarkdownPreservesObservedMetricsAndPartialFailure(t *testing.T) {
	started := time.Date(2026, 8, 14, 1, 2, 3, 0, time.UTC)
	report := Report{
		SourceSHA: strings.Repeat("a", 40), Status: StatusFail, StartedAt: started, EndedAt: started.Add(3 * time.Second),
		Environment: Environment{HostName: "udesk24", OS: "Ubuntu 24.04", Kernel: "6.8", Architecture: "amd64", CPUModel: "Test CPU", LogicalCPUs: 8, MemoryBytes: 16 << 30, GoVersion: "go1.24", NodeVersion: "v22", ChromiumVersion: "Chromium 130"},
		Cases:       []CaseResult{{ID: "performance/throughput/wss", Section: SectionStreamingThroughput, Status: StatusFail, Stage: "measurement", FirstError: "connection reset", Measurements: []Measurement{{Name: "throughput", Observed: 42.5, Threshold: 50, Unit: "MiB/s", Comparator: ">=", Status: StatusFail}}, RawSamples: []RawSample{{Round: 1, Values: map[string]float64{"throughput_mib_s": 42.5}}}}},
	}
	path := filepath.Join(t.TempDir(), "performance-report.md")
	if err := WriteMarkdown(path, report); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"# Flowersec Performance Report", "Overall status | **FAIL**", "udesk24", "Observed", "Threshold", "MiB/s", "42.500", "performance/throughput/wss", "connection reset", "Raw Samples Appendix"} {
		if !strings.Contains(text, want) {
			t.Fatalf("report missing %q:\n%s", want, text)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("report produced sidecars: %v", entries)
	}
}

func TestReportRejectsMissingMetricsAndUnnamedHost(t *testing.T) {
	report := Report{SourceSHA: strings.Repeat("b", 40), Status: StatusPass, StartedAt: time.Now(), EndedAt: time.Now().Add(time.Second), Environment: Environment{HostName: "udesk24", LogicalCPUs: 1, MemoryBytes: 1}, Cases: []CaseResult{{ID: "case", Section: SectionCapacity, Status: StatusPass}}}
	if err := report.Validate(); err == nil {
		t.Fatal("successful case without observed metrics was accepted")
	}
	report.Cases[0].Measurements = []Measurement{{Name: "sessions", Observed: 1000, Threshold: 1000, Unit: "sessions", Comparator: ">=", Status: StatusPass}}
	report.Environment.HostName = "  "
	if err := report.Validate(); err == nil {
		t.Fatal("performance report accepted an unnamed host")
	}
}
