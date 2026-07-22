package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
)

const (
	manifestSchemaVersion     = 1
	manifestDigestPrefix      = "sha256:"
	signedRatioFormulaVersion = "transport-ratio-v1"
	mib                       = 1024 * 1024
	kib                       = 1024
)

type signedProfile struct {
	id                     string
	cold                   ColdWorkload
	rpc                    RPCWorkload
	bulk                   BulkWorkload
	cleanupDeadlineSeconds int
	cellWatchdogMinutes    int
}

const signedFirewallPolicy = "allow-test-tcp-udp-return-icmp-ptb-only-v1"

var signedCapacityContract = CapacityContract{
	Sessions:           1000,
	RampDurationNS:     30 * 1e9,
	HoldDurationNS:     60 * 1e9,
	CleanupDurationNS:  30 * 1e9,
	WatchdogDurationNS: 120 * 1e9,
	MaxRSSBytes:        1024 * mib,
	MaxCPUNanoseconds:  120 * 1e9,
	MaxOpenFDs:         8192,
	MaxGoroutines:      8192,
	MaxTasks:           8192,
}

var signedSoakContract = SoakContract{
	DurationNS:                3600 * 1e9,
	FaultCyclePeriodNS:        60 * 1e9,
	FaultCycleCount:           60,
	ReconnectCount:            60,
	MigrationCount:            60,
	MaxRSSGrowthBytesPerHour:  64 * mib,
	MaxGoroutineGrowthPerHour: 64,
	MaxOpenFDGrowthPerHour:    16,
	MaxTaskGrowthPerHour:      64,
	ResidualSessions:          0,
	ResidualGoroutines:        0,
	ResidualOpenFDs:           0,
	ResidualTasks:             0,
}

var signedFaultMatrix = []FaultMatrixContract{
	{ProfileID: "clean-v1", Carrier: "wss", ReorderPercent: 0, DuplicatePercent: 0},
	{ProfileID: "clean-v1", Carrier: "raw_quic", ReorderPercent: 0, DuplicatePercent: 0},
	{ProfileID: "clean-v1", Carrier: "webtransport", ReorderPercent: 0, DuplicatePercent: 0},
	{ProfileID: "mobile-v1", Carrier: "wss", ReorderPercent: 1, DuplicatePercent: 1, OutageStartNS: 1e9, OutageDurationNS: 2e9},
	{ProfileID: "mobile-v1", Carrier: "raw_quic", ReorderPercent: 1, DuplicatePercent: 1, OutageStartNS: 1e9, OutageDurationNS: 2e9, MigrationStartNS: 2e9, MigrationValidatedNS: 2500 * 1e6},
	{ProfileID: "mobile-v1", Carrier: "webtransport", ReorderPercent: 1, DuplicatePercent: 1, OutageStartNS: 1e9, OutageDurationNS: 2e9},
	{ProfileID: "edge-v1", Carrier: "wss", ReorderPercent: 2, DuplicatePercent: 2, OutageStartNS: 1e9, OutageDurationNS: 2e9},
	{ProfileID: "edge-v1", Carrier: "raw_quic", ReorderPercent: 2, DuplicatePercent: 2, OutageStartNS: 1e9, OutageDurationNS: 2e9, MigrationStartNS: 2e9, MigrationValidatedNS: 2500 * 1e6},
	{ProfileID: "edge-v1", Carrier: "webtransport", ReorderPercent: 2, DuplicatePercent: 2, OutageStartNS: 1e9, OutageDurationNS: 2e9},
}

var signedNetworks = map[string]*NetworkProfile{
	// clean-v1 is frozen here because the signed plan defined an unshaped clean
	// network but did not otherwise assign exact packet-layer parameters.
	"clean-v1": {
		EvidenceLayer: "kernel_packet", OneWayDelayMilliseconds: 0,
		JitterMilliseconds: []int{0}, Loss: NetworkLoss{Mode: "none"},
		ReorderPercent: 0, DuplicatePercent: 0, Shape: nil,
		LinkMTU: 1500, Firewall: signedFirewallPolicy, shapePresent: true,
	},
	"mobile-v1": {
		EvidenceLayer: "kernel_packet", OneWayDelayMilliseconds: 60,
		JitterMilliseconds: []int{0, 8, -4, 12, -8, 4, -2, 6},
		Loss:               NetworkLoss{Mode: "periodic", EveryNth: 50},
		ReorderPercent:     0, DuplicatePercent: 0,
		Shape:   &NetworkShape{RateBitsPerSecond: 5_000_000, TokenBurstBytes: 32_768, QueueBytes: 262_144},
		LinkMTU: 1280, Firewall: signedFirewallPolicy, shapePresent: true,
	},
	"edge-v1": {
		EvidenceLayer: "kernel_packet", OneWayDelayMilliseconds: 150,
		JitterMilliseconds: []int{0, 30, -20, 45, -35, 10, -5, 25},
		Loss:               NetworkLoss{Mode: "burst", BlockSize: 100, BurstFirst: 41, BurstLast: 45},
		ReorderPercent:     0, DuplicatePercent: 0,
		Shape:   &NetworkShape{RateBitsPerSecond: 1_000_000, TokenBurstBytes: 16_384, QueueBytes: 65_536},
		LinkMTU: 1280, Firewall: signedFirewallPolicy, shapePresent: true,
	},
	"adaptive-selection-v1": nil,
}

var signedMetricContracts = []MetricContract{
	{ID: "connect_p50_ms", Decision: "observe", Unit: "milliseconds"},
	{ID: "connect_p95_ms", Decision: "observe", Unit: "milliseconds"},
	{ID: "connect_p99_ms", Decision: "observe", Unit: "milliseconds"},
	{ID: "rpc_p50_ms", Decision: "observe", Unit: "milliseconds"},
	{ID: "rpc_p95_ms", Decision: "observe", Unit: "milliseconds"},
	{ID: "rpc_p99_ms", Decision: "observe", Unit: "milliseconds"},
	{ID: "bulk_goodput_mbps", Decision: "observe", Unit: "megabits_per_second"},
	{ID: "cpu_ns_per_delivered_byte", Decision: "observe", Unit: "nanoseconds_per_byte"},
	{ID: "rss_bytes", Decision: "observe", Unit: "bytes"},
	{ID: "alloc_bytes", Decision: "observe", Unit: "bytes"},
	{ID: "retransmit_amplification_ratio", Decision: "observe", Unit: "ratio"},
	{ID: "loss_recovery_ms", Decision: "observe", Unit: "milliseconds"},
	{ID: "active_streams", Decision: "observe", Unit: "count"},
	{ID: "cleanup_latency_ms", Decision: "observe", Unit: "milliseconds"},
	metricUpper("clean_revision_cpu_per_byte_ratio", 1.15, "ratio"),
	metricUpper("clean_revision_cold_p95_ratio", 1.15, "ratio"),
	metricUpper("clean_revision_cold_p99_ratio", 1.15, "ratio"),
	metricUpper("clean_revision_rpc_p99_ratio", 1.15, "ratio"),
	metricLower("clean_revision_throughput_ratio", 0.85, "ratio"),
	metricUpper("clean_quic_cpu_per_byte_ratio", 1.5, "ratio"),
	metricLower("clean_quic_bulk_throughput_ratio", 0.8, "ratio"),
	metricUpper("clean_quic_cold_p95_ratio", 1.2, "ratio"),
	metricUpper("clean_quic_cold_p99_ratio", 1.5, "ratio"),
	metricUpper("clean_quic_rpc_p99_ratio", 1.2, "ratio"),
	metricUpper("clean_webtransport_cold_p99_ratio", 1.5, "ratio"),
	metricUpper("clean_webtransport_rpc_p99_ratio", 1.2, "ratio"),
	metricLower("clean_webtransport_throughput_ratio", 0.8, "ratio"),
	metricUpper("mobile_cold_p99_ms", 1720, "milliseconds"),
	metricUpper("mobile_rpc_p99_ms", 860, "milliseconds"),
	metricLower("mobile_bulk_goodput_mbps", 4, "megabits_per_second"),
	metricUpper("mobile_cpu_per_delivered_byte_vs_clean_ratio", 3, "ratio"),
	metricUpper("mobile_retransmit_amplification_ratio", 0.5, "ratio"),
	metricUpper("mobile_migration_first_rpc_ms", 860, "milliseconds"),
	metricUpper("mobile_outage_recovery_overhead_ms", 1360, "milliseconds"),
	metricUpper("mobile_native_interactive_rpc_p99_ms", 860, "milliseconds"),
	metricUpper("mobile_native_interactive_vs_idle_ratio", 3, "ratio"),
	metricUpper("edge_cold_p99_ms", 4400, "milliseconds"),
	metricUpper("edge_rpc_p99_ms", 2200, "milliseconds"),
	metricLower("edge_bulk_goodput_mbps", 0.7, "megabits_per_second"),
	metricUpper("edge_cpu_per_delivered_byte_vs_clean_ratio", 4, "ratio"),
	metricUpper("edge_retransmit_amplification_ratio", 1, "ratio"),
	metricUpper("edge_migration_first_rpc_ms", 1400, "milliseconds"),
	metricUpper("edge_outage_recovery_overhead_ms", 1900, "milliseconds"),
	metricUpper("adaptive_cold_formula_ratio", 1, "ratio"),
	metricUpper("adaptive_cpu_connect_formula_ratio", 1, "ratio"),
	metricUpper("adaptive_web_cold_formula_ratio", 1, "ratio"),
}

var nativeObservationMetrics = []string{
	"connect_p50_ms", "connect_p95_ms", "connect_p99_ms",
	"rpc_p50_ms", "rpc_p95_ms", "rpc_p99_ms", "bulk_goodput_mbps",
	"cpu_ns_per_delivered_byte", "rss_bytes", "alloc_bytes",
	"retransmit_amplification_ratio", "loss_recovery_ms", "active_streams", "cleanup_latency_ms",
}

var browserObservationMetrics = []string{
	"connect_p50_ms", "connect_p95_ms", "connect_p99_ms",
	"rpc_p50_ms", "rpc_p95_ms", "rpc_p99_ms", "bulk_goodput_mbps",
	"active_streams", "cleanup_latency_ms",
}

func metricUpper(id string, threshold float64, unit string) MetricContract {
	return MetricContract{ID: id, Decision: "upper", Threshold: float64Pointer(threshold), Unit: unit}
}

func metricLower(id string, threshold float64, unit string) MetricContract {
	return MetricContract{ID: id, Decision: "lower", Threshold: float64Pointer(threshold), Unit: unit}
}

func float64Pointer(value float64) *float64 { return &value }

var signedProfiles = []signedProfile{
	{
		id:                     "clean-v1",
		cold:                   ColdWorkload{Operations: 2000, MaxInflight: 32, Retries: 0, StartRatePerSecond: 100, OperationDeadlineSeconds: 10, PhaseDeadlineSeconds: 30},
		rpc:                    RPCWorkload{Operations: 2000, RequestBytes: 1024, ResponseBytes: 1024, Workers: 32, Retries: 0, OperationDeadlineSeconds: 2, PhaseDeadlineSeconds: 10},
		bulk:                   BulkWorkload{WarmupBytesPerDirection: mib, ScoreBytesPerDirection: 64 * mib, PhaseDeadlineSeconds: 15},
		cleanupDeadlineSeconds: 5,
		cellWatchdogMinutes:    15,
	},
	{
		id:                     "mobile-v1",
		cold:                   ColdWorkload{Operations: 2000, MaxInflight: 32, Retries: 0, StartRatePerSecond: 15, OperationDeadlineSeconds: 15, PhaseDeadlineSeconds: 150},
		rpc:                    RPCWorkload{Operations: 2000, RequestBytes: 1024, ResponseBytes: 1024, Workers: 32, Retries: 0, OperationDeadlineSeconds: 5, PhaseDeadlineSeconds: 70},
		bulk:                   BulkWorkload{WarmupBytesPerDirection: mib, ScoreBytesPerDirection: 16 * mib, PhaseDeadlineSeconds: 55},
		cleanupDeadlineSeconds: 5,
		cellWatchdogMinutes:    70,
	},
	{
		id:                     "edge-v1",
		cold:                   ColdWorkload{Operations: 2000, MaxInflight: 32, Retries: 0, StartRatePerSecond: 5, OperationDeadlineSeconds: 30, PhaseDeadlineSeconds: 430},
		rpc:                    RPCWorkload{Operations: 2000, RequestBytes: 1024, ResponseBytes: 1024, Workers: 32, Retries: 0, OperationDeadlineSeconds: 10, PhaseDeadlineSeconds: 170},
		bulk:                   BulkWorkload{WarmupBytesPerDirection: 128 * kib, ScoreBytesPerDirection: 2 * mib, PhaseDeadlineSeconds: 80},
		cleanupDeadlineSeconds: 20,
		cellWatchdogMinutes:    175,
	},
}

func loadPerformanceManifest(path string) (*PerformanceManifest, error) {
	var manifest PerformanceManifest
	if err := decodeStrictFile(path, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func validateManifest(manifest *PerformanceManifest) error {
	if manifest == nil {
		return errors.New("manifest is nil")
	}
	if err := validateManifestDigest(manifest); err != nil {
		return err
	}
	if manifest.SchemaVersion != manifestSchemaVersion {
		return fmt.Errorf("schema_version = %d, want %d", manifest.SchemaVersion, manifestSchemaVersion)
	}
	if manifest.RatioFormulaVersion != signedRatioFormulaVersion {
		return fmt.Errorf("ratio_formula_version = %q, want %q", manifest.RatioFormulaVersion, signedRatioFormulaVersion)
	}
	if manifest.RunCount != 15 {
		return fmt.Errorf("run_count = %d, want exactly 15 independent runs", manifest.RunCount)
	}
	if manifest.Bootstrap.Resamples != 10000 {
		return fmt.Errorf("bootstrap resamples = %d, want 10000", manifest.Bootstrap.Resamples)
	}
	if manifest.Bootstrap.Seed != 20260720 {
		return fmt.Errorf("bootstrap seed = %d, want 20260720", manifest.Bootstrap.Seed)
	}
	if manifest.Bootstrap.ConfidencePercent != 95 || manifest.Bootstrap.Cluster != "run" || manifest.Bootstrap.Estimator != "mean" {
		return fmt.Errorf("bootstrap must use a run-cluster mean with a 95%% confidence interval")
	}
	if !reflect.DeepEqual(manifest.Capacity, signedCapacityContract) {
		return fmt.Errorf("capacity contract does not match the signed 1000-session resource and timeline limits")
	}
	if !reflect.DeepEqual(manifest.Soak, signedSoakContract) {
		return fmt.Errorf("soak contract does not match the signed one-hour fault-cycle and resource-slope limits")
	}
	if err := validateFaultMatrix(manifest.FaultMatrix); err != nil {
		return err
	}
	if err := validateProfiles(manifest); err != nil {
		return err
	}
	if err := validateMetricContracts(manifest.MetricContracts); err != nil {
		return err
	}
	return validateSchedule(manifest)
}

func validateFaultMatrix(matrix []FaultMatrixContract) error {
	if len(matrix) != len(signedFaultMatrix) {
		return fmt.Errorf("fault_matrix must contain exactly %d profile/carrier contracts", len(signedFaultMatrix))
	}
	want := append([]FaultMatrixContract(nil), signedFaultMatrix...)
	got := append([]FaultMatrixContract(nil), matrix...)
	sort.Slice(want, func(i, j int) bool { return want[i].ProfileID+want[i].Carrier < want[j].ProfileID+want[j].Carrier })
	sort.Slice(got, func(i, j int) bool { return got[i].ProfileID+got[i].Carrier < got[j].ProfileID+got[j].Carrier })
	for index := range want {
		if got[index] != want[index] {
			return fmt.Errorf("fault_matrix contract %s/%s does not match the signed reorder/duplicate/outage schedule", got[index].ProfileID, got[index].Carrier)
		}
	}
	return nil
}

func canonicalManifest(manifest *PerformanceManifest) ([]byte, error) {
	if manifest == nil {
		return nil, errors.New("manifest is nil")
	}
	copy := *manifest
	copy.Digest = ""
	return json.Marshal(copy)
}

func manifestDigest(manifest *PerformanceManifest) (string, error) {
	canonical, err := canonicalManifest(manifest)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return manifestDigestPrefix + hex.EncodeToString(sum[:]), nil
}

func validateManifestDigest(manifest *PerformanceManifest) error {
	want, err := manifestDigest(manifest)
	if err != nil {
		return err
	}
	if manifest.Digest != want {
		return fmt.Errorf("manifest digest mismatch: got %q, want %q", manifest.Digest, want)
	}
	return nil
}

func validateProfiles(manifest *PerformanceManifest) error {
	if len(manifest.Profiles) != 4 {
		return fmt.Errorf("profiles must contain exactly clean-v1, mobile-v1, edge-v1, and adaptive-selection-v1")
	}
	profiles := make(map[string]*PerformanceProfile, len(manifest.Profiles))
	for index := range manifest.Profiles {
		profile := &manifest.Profiles[index]
		if _, exists := profiles[profile.ID]; exists {
			return fmt.Errorf("duplicate profile ID %q", profile.ID)
		}
		profiles[profile.ID] = profile
	}
	for _, signed := range signedProfiles {
		profile, exists := profiles[signed.id]
		if !exists {
			return fmt.Errorf("missing profile %q", signed.id)
		}
		if err := validateForcedProfile(profile, signed, manifest.RunCount); err != nil {
			return err
		}
	}
	adaptive, exists := profiles["adaptive-selection-v1"]
	if !exists {
		return errors.New("missing profile \"adaptive-selection-v1\"")
	}
	return validateAdaptiveProfile(adaptive, profiles, manifest.RunCount)
}

func validateForcedProfile(profile *PerformanceProfile, signed signedProfile, runs int) error {
	if !profile.networkPresent || profile.Network == nil || !profile.Network.shapePresent {
		return fmt.Errorf("%s network profile must explicitly include network and shape, including JSON null for unshaped clean-v1", profile.ID)
	}
	if profile.Mode != "forced" {
		return fmt.Errorf("profile %s mode = %q, want forced", profile.ID, profile.Mode)
	}
	if profile.Cold == nil {
		return fmt.Errorf("profile %s missing cold workload", profile.ID)
	}
	if err := validateCold(profile.ID, *profile.Cold, signed.cold); err != nil {
		return err
	}
	if profile.RPC == nil {
		return fmt.Errorf("profile %s missing RPC workload", profile.ID)
	}
	if err := validateRPC(profile.ID, *profile.RPC, signed.rpc); err != nil {
		return err
	}
	if profile.Bulk == nil {
		return fmt.Errorf("profile %s missing bulk workload", profile.ID)
	}
	if *profile.Bulk != signed.bulk {
		return fmt.Errorf("profile %s bulk bytes or phase deadline do not match the signed workload", profile.ID)
	}
	if profile.CleanupDeadlineSeconds != signed.cleanupDeadlineSeconds {
		return fmt.Errorf("profile %s cleanup phase deadline = %d, want %d", profile.ID, profile.CleanupDeadlineSeconds, signed.cleanupDeadlineSeconds)
	}
	if len(profile.AdaptiveStages) != 0 {
		return fmt.Errorf("forced profile %s must not define adaptive stages", profile.ID)
	}
	if profile.HarnessSlackSeconds != 0 {
		return fmt.Errorf("forced profile %s harness slack must be zero", profile.ID)
	}
	phaseSeconds := profile.Cold.PhaseDeadlineSeconds + profile.RPC.PhaseDeadlineSeconds + profile.Bulk.PhaseDeadlineSeconds + profile.CleanupDeadlineSeconds
	if runs*phaseSeconds+profile.HarnessSlackSeconds > profile.CellWatchdogMinutes*60 {
		return fmt.Errorf("profile %s cell watchdog cannot cover phase deadlines for all runs", profile.ID)
	}
	if profile.CellWatchdogMinutes != signed.cellWatchdogMinutes {
		return fmt.Errorf("profile %s cell watchdog = %d minutes, want %d", profile.ID, profile.CellWatchdogMinutes, signed.cellWatchdogMinutes)
	}
	if !reflect.DeepEqual(profile.Network, signedNetworks[profile.ID]) {
		return fmt.Errorf("%s network profile does not match the frozen packet-layer contract", profile.ID)
	}
	return nil
}

func validateAdaptiveProfile(profile *PerformanceProfile, profiles map[string]*PerformanceProfile, runs int) error {
	if !profile.networkPresent {
		return errors.New("adaptive-selection-v1 must explicitly declare network as JSON null")
	}
	if profile.Mode != "adaptive" {
		return fmt.Errorf("profile adaptive-selection-v1 mode = %q, want adaptive", profile.Mode)
	}
	if profile.Cold != nil || profile.RPC != nil || profile.Bulk != nil || profile.CleanupDeadlineSeconds != 0 {
		return errors.New("adaptive profile must not define RPC or bulk workloads or a top-level phase")
	}
	if len(profile.AdaptiveStages) != 2 {
		return errors.New("adaptive stages must contain clean-v1 then mobile-v1 exactly once")
	}
	for index, profileID := range []string{"clean-v1", "mobile-v1"} {
		stage := profile.AdaptiveStages[index]
		base := profiles[profileID]
		if stage.ProfileID != profileID || base == nil || base.Cold == nil || stage.Cold != *base.Cold || stage.CleanupDeadlineSeconds != base.CleanupDeadlineSeconds {
			return fmt.Errorf("adaptive stages must reuse the exact %s cold and cleanup contract", profileID)
		}
	}
	if profile.HarnessSlackSeconds != 450 {
		return fmt.Errorf("adaptive-selection-v1 harness slack = %d seconds, want 450", profile.HarnessSlackSeconds)
	}
	if profile.CellWatchdogMinutes != 55 {
		return fmt.Errorf("adaptive-selection-v1 cell watchdog = %d minutes, want 55", profile.CellWatchdogMinutes)
	}
	if profile.Network != nil {
		return errors.New("adaptive-selection-v1 network must be null because its stages reuse clean-v1 and mobile-v1")
	}
	perRun := 0
	for _, stage := range profile.AdaptiveStages {
		perRun += stage.Cold.PhaseDeadlineSeconds + stage.CleanupDeadlineSeconds
	}
	if runs*perRun+profile.HarnessSlackSeconds > profile.CellWatchdogMinutes*60 {
		return errors.New("adaptive-selection-v1 cell watchdog cannot cover both profile stages for all runs")
	}
	return nil
}

func validateMetricContracts(got []MetricContract) error {
	if len(got) != len(signedMetricContracts) {
		return fmt.Errorf("metric_contracts contains %d entries, want %d", len(got), len(signedMetricContracts))
	}
	wanted := make(map[string]MetricContract, len(signedMetricContracts))
	for _, contract := range signedMetricContracts {
		wanted[contract.ID] = contract
	}
	seen := make(map[string]struct{}, len(got))
	for _, contract := range got {
		if strings.TrimSpace(contract.ID) == "" || strings.TrimSpace(contract.Unit) == "" {
			return errors.New("metric contract ID and unit must be non-empty")
		}
		if _, duplicate := seen[contract.ID]; duplicate {
			return fmt.Errorf("duplicate metric contract %q", contract.ID)
		}
		seen[contract.ID] = struct{}{}
		expected, exists := wanted[contract.ID]
		if !exists {
			return fmt.Errorf("unknown metric contract %q", contract.ID)
		}
		if contract.Decision != expected.Decision || contract.Unit != expected.Unit || !sameThreshold(contract.Threshold, expected.Threshold) {
			return fmt.Errorf("metric contract %s does not match its signed decision, threshold, and unit", contract.ID)
		}
		if contract.Decision == "observe" && contract.Threshold != nil {
			return fmt.Errorf("observe metric contract %s must not define a threshold", contract.ID)
		}
		if contract.Decision != "observe" && contract.Threshold == nil {
			return fmt.Errorf("decision metric contract %s must define a threshold", contract.ID)
		}
	}
	return nil
}

func sameThreshold(left, right *float64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func validateCold(profileID string, got, want ColdWorkload) error {
	if got.Operations != want.Operations {
		return fmt.Errorf("profile %s cold operations = %d, want %d", profileID, got.Operations, want.Operations)
	}
	if got.MaxInflight != want.MaxInflight {
		return fmt.Errorf("profile %s cold max_inflight = %d, want %d", profileID, got.MaxInflight, want.MaxInflight)
	}
	if got.Retries != want.Retries {
		return fmt.Errorf("profile %s cold retries = %d, want zero", profileID, got.Retries)
	}
	if got.StartRatePerSecond != want.StartRatePerSecond {
		return fmt.Errorf("profile %s cold start_rate_per_second = %d, want %d", profileID, got.StartRatePerSecond, want.StartRatePerSecond)
	}
	if got.OperationDeadlineSeconds != want.OperationDeadlineSeconds {
		return fmt.Errorf("profile %s cold operation deadline = %d, want %d", profileID, got.OperationDeadlineSeconds, want.OperationDeadlineSeconds)
	}
	scheduleTail := ceilDiv(got.Operations-1, got.StartRatePerSecond)
	if scheduleTail+got.OperationDeadlineSeconds > got.PhaseDeadlineSeconds {
		return fmt.Errorf("profile %s cold phase cannot cover its open-loop schedule tail and operation deadline", profileID)
	}
	if got.PhaseDeadlineSeconds != want.PhaseDeadlineSeconds {
		return fmt.Errorf("profile %s cold phase deadline = %d, want %d", profileID, got.PhaseDeadlineSeconds, want.PhaseDeadlineSeconds)
	}
	return nil
}

func validateRPC(profileID string, got, want RPCWorkload) error {
	if got.Operations != want.Operations {
		return fmt.Errorf("profile %s RPC operations = %d, want %d", profileID, got.Operations, want.Operations)
	}
	if got.RequestBytes != want.RequestBytes {
		return fmt.Errorf("profile %s RPC request_bytes = %d, want %d", profileID, got.RequestBytes, want.RequestBytes)
	}
	if got.ResponseBytes != want.ResponseBytes {
		return fmt.Errorf("profile %s RPC response_bytes = %d, want %d", profileID, got.ResponseBytes, want.ResponseBytes)
	}
	if got.Workers != want.Workers {
		return fmt.Errorf("profile %s RPC workers = %d, want %d", profileID, got.Workers, want.Workers)
	}
	if got.Retries != 0 {
		return fmt.Errorf("profile %s RPC retries = %d, want zero", profileID, got.Retries)
	}
	if got.OperationDeadlineSeconds != want.OperationDeadlineSeconds {
		return fmt.Errorf("profile %s RPC operation deadline = %d, want %d", profileID, got.OperationDeadlineSeconds, want.OperationDeadlineSeconds)
	}
	if got.PhaseDeadlineSeconds != want.PhaseDeadlineSeconds {
		return fmt.Errorf("profile %s RPC phase deadline = %d, want %d", profileID, got.PhaseDeadlineSeconds, want.PhaseDeadlineSeconds)
	}
	if got.Workers > got.Operations || got.OperationDeadlineSeconds > got.PhaseDeadlineSeconds {
		return fmt.Errorf("profile %s RPC phase is not self-consistent", profileID)
	}
	return nil
}

func validateSchedule(manifest *PerformanceManifest) error {
	if manifest.EligibleLaneCount <= 0 {
		return errors.New("eligible_lane_count must be positive")
	}
	if manifest.GlobalSetupMinutes != 60 {
		return fmt.Errorf("global setup/teardown hard cap = %d minutes, want 60", manifest.GlobalSetupMinutes)
	}
	if manifest.MaximumLaneMinutes != 480 {
		return fmt.Errorf("maximum_lane_minutes = %d, want 480", manifest.MaximumLaneMinutes)
	}
	profiles := make(map[string]PerformanceProfile, len(manifest.Profiles))
	for _, profile := range manifest.Profiles {
		profiles[profile.ID] = profile
	}
	seenCells := make(map[string]struct{}, len(manifest.Cells))
	profileCells := make(map[string]int, len(manifest.Profiles))
	for _, cell := range manifest.Cells {
		if strings.TrimSpace(cell.ID) == "" {
			return errors.New("cell ID must not be empty")
		}
		if _, exists := seenCells[cell.ID]; exists {
			return fmt.Errorf("duplicate cell ID %q", cell.ID)
		}
		seenCells[cell.ID] = struct{}{}
		profile, exists := profiles[cell.ProfileID]
		if !exists {
			return fmt.Errorf("cell %s references unknown profile %q", cell.ID, cell.ProfileID)
		}
		profileCells[cell.ProfileID]++
		if cell.DurationMinutes != profile.CellWatchdogMinutes {
			return fmt.Errorf("cell %s duration %d does not match profile watchdog %d", cell.ID, cell.DurationMinutes, profile.CellWatchdogMinutes)
		}
		if err := validateCellSelection(cell, profile.Mode); err != nil {
			return err
		}
	}
	for _, profile := range manifest.Profiles {
		if profileCells[profile.ID] == 0 {
			return fmt.Errorf("profile %s has no registered cell", profile.ID)
		}
	}
	limits := map[string]int{"clean-v1": 10, "mobile-v1": 9, "edge-v1": 9, "adaptive-selection-v1": 2}
	for profileID, limit := range limits {
		if profileCells[profileID] > limit {
			return fmt.Errorf("profile %s cell count %d exceeds preregistered limit %d", profileID, profileCells[profileID], limit)
		}
	}
	if err := validateCellCoverage(manifest.Cells); err != nil {
		return err
	}
	if err := validateCellMetrics(manifest.Cells); err != nil {
		return err
	}
	loads, err := allocateLPT(manifest.Cells, manifest.EligibleLaneCount)
	if err != nil {
		return err
	}
	requiredWatchdog := loads[len(loads)-1] + manifest.GlobalSetupMinutes
	if requiredWatchdog > manifest.MaximumLaneMinutes {
		return fmt.Errorf("LPT schedule plus setup requires %d minutes, exceeding 480 minutes", requiredWatchdog)
	}
	if manifest.GlobalWatchdogMinutes != requiredWatchdog {
		return fmt.Errorf("global watchdog %d minutes must equal recomputed LPT requirement %d", manifest.GlobalWatchdogMinutes, requiredWatchdog)
	}
	return nil
}

func validateCellCoverage(cells []PerformanceCell) error {
	required := map[string][]string{
		"clean-v1":              {"direct_wss_revision", "direct_wss", "direct_quic", "ww", "qq", "wq", "qw", "browser_webtransport", "browser_tunnel_wt_wss", "browser_tunnel_wt_quic"},
		"mobile-v1":             {"direct_wss", "direct_quic", "ww", "qq", "wq", "qw", "browser_webtransport", "browser_tunnel_wt_wss", "browser_tunnel_wt_quic"},
		"edge-v1":               {"direct_wss", "direct_quic", "ww", "qq", "wq", "qw", "browser_webtransport", "browser_tunnel_wt_wss", "browser_tunnel_wt_quic"},
		"adaptive-selection-v1": {"adaptive_native", "adaptive_web"},
	}
	seen := make(map[string]map[string]int, len(required))
	for profileID := range required {
		seen[profileID] = make(map[string]int)
	}
	for _, cell := range cells {
		profileTopologies, exists := seen[cell.ProfileID]
		if !exists {
			continue
		}
		profileTopologies[cell.Topology]++
		if cell.Topology == "direct_wss_revision" {
			if cell.ProfileID != "clean-v1" || !slices.Equal(cell.Variants, []string{"base", "candidate"}) {
				return fmt.Errorf("direct WSS revision cell must be clean-v1 with base and candidate variants")
			}
		} else if len(cell.Variants) != 0 {
			return fmt.Errorf("cell %s must not define variants outside the direct WSS revision cell", cell.ID)
		}
	}
	for profileID, topologies := range required {
		for _, topology := range topologies {
			if seen[profileID][topology] == 0 {
				return fmt.Errorf("profile %s is missing required topology %s", profileID, topology)
			}
		}
		if len(seen[profileID]) != len(topologies) {
			return fmt.Errorf("profile %s contains a topology outside the signed coverage set", profileID)
		}
		for topology, count := range seen[profileID] {
			if count != 1 {
				return fmt.Errorf("profile %s has duplicate topology %s", profileID, topology)
			}
		}
	}
	for _, cell := range cells {
		if err := validateTopologySelection(cell); err != nil {
			return err
		}
	}
	return nil
}

func validateTopologySelection(cell PerformanceCell) error {
	type selection struct {
		policy     string
		candidates []string
	}
	wanted := map[string]selection{
		"direct_wss_revision":    {policy: "RequireWebSocket", candidates: []string{"candidate-wss"}},
		"direct_wss":             {policy: "RequireWebSocket", candidates: []string{"direct-wss"}},
		"direct_quic":            {policy: "RequireQUICFamily", candidates: []string{"direct-raw-quic"}},
		"ww":                     {policy: "RequireWebSocket", candidates: []string{"tunnel-ww"}},
		"qq":                     {policy: "RequireQUICFamily", candidates: []string{"tunnel-qq"}},
		"wq":                     {policy: "RequireWebSocket", candidates: []string{"tunnel-wq"}},
		"qw":                     {policy: "RequireQUICFamily", candidates: []string{"tunnel-qw"}},
		"browser_webtransport":   {policy: "RequireQUICFamily", candidates: []string{"browser-webtransport"}},
		"browser_tunnel_wt_wss":  {policy: "RequireQUICFamily", candidates: []string{"tunnel-wt-wss"}},
		"browser_tunnel_wt_quic": {policy: "RequireQUICFamily", candidates: []string{"tunnel-wt-quic"}},
		"adaptive_native":        {policy: "Adaptive", candidates: []string{"runtime-wss", "runtime-raw-quic"}},
		"adaptive_web":           {policy: "Adaptive", candidates: []string{"runtime-wss", "runtime-webtransport"}},
	}
	expected, exists := wanted[cell.Topology]
	if !exists {
		return fmt.Errorf("cell %s uses unknown topology %s", cell.ID, cell.Topology)
	}
	if cell.Policy != expected.policy || !sameStringSet(cell.SupportedCandidates, expected.candidates) {
		return fmt.Errorf("cell %s topology %s does not match its signed policy and candidate set", cell.ID, cell.Topology)
	}
	return nil
}

func validateCellMetrics(cells []PerformanceCell) error {
	for _, cell := range cells {
		want, err := requiredMetricsForCell(cell)
		if err != nil {
			return err
		}
		if !sameStringSet(cell.RequiredMetrics, want) {
			return fmt.Errorf("cell %s required_metrics do not match the signed metric mapping", cell.ID)
		}
	}
	return nil
}

func requiredMetricsForCell(cell PerformanceCell) ([]string, error) {
	var metrics []string
	switch cell.ProfileID {
	case "clean-v1":
		if isBrowserWebTransportTopology(cell.Topology) {
			metrics = append(metrics, browserObservationMetrics...)
		} else {
			metrics = append(metrics, nativeObservationMetrics...)
		}
		switch cell.Topology {
		case "direct_wss_revision":
			metrics = append(metrics,
				"clean_revision_cpu_per_byte_ratio", "clean_revision_cold_p95_ratio",
				"clean_revision_cold_p99_ratio", "clean_revision_rpc_p99_ratio",
				"clean_revision_throughput_ratio",
			)
		case "direct_quic":
			metrics = append(metrics,
				"clean_quic_cpu_per_byte_ratio", "clean_quic_bulk_throughput_ratio",
				"clean_quic_cold_p95_ratio", "clean_quic_cold_p99_ratio", "clean_quic_rpc_p99_ratio",
			)
		case "browser_webtransport":
			metrics = append(metrics, "clean_webtransport_cold_p99_ratio", "clean_webtransport_rpc_p99_ratio", "clean_webtransport_throughput_ratio")
		}
	case "mobile-v1":
		if isBrowserWebTransportTopology(cell.Topology) {
			metrics = append(metrics, browserObservationMetrics...)
			metrics = append(metrics, "mobile_cold_p99_ms", "mobile_rpc_p99_ms", "mobile_bulk_goodput_mbps", "mobile_outage_recovery_overhead_ms")
		} else {
			metrics = append(metrics, nativeObservationMetrics...)
			metrics = append(metrics,
				"mobile_cold_p99_ms", "mobile_rpc_p99_ms", "mobile_bulk_goodput_mbps",
				"mobile_cpu_per_delivered_byte_vs_clean_ratio", "mobile_retransmit_amplification_ratio",
				"mobile_outage_recovery_overhead_ms",
			)
		}
		if cell.Topology == "direct_quic" {
			metrics = append(metrics,
				"mobile_migration_first_rpc_ms", "mobile_native_interactive_rpc_p99_ms",
				"mobile_native_interactive_vs_idle_ratio",
			)
		}
	case "edge-v1":
		if isBrowserWebTransportTopology(cell.Topology) {
			metrics = append(metrics, browserObservationMetrics...)
			metrics = append(metrics, "edge_cold_p99_ms", "edge_rpc_p99_ms", "edge_bulk_goodput_mbps", "edge_outage_recovery_overhead_ms")
		} else {
			metrics = append(metrics, nativeObservationMetrics...)
			metrics = append(metrics,
				"edge_cold_p99_ms", "edge_rpc_p99_ms", "edge_bulk_goodput_mbps",
				"edge_cpu_per_delivered_byte_vs_clean_ratio", "edge_retransmit_amplification_ratio",
				"edge_outage_recovery_overhead_ms",
			)
		}
		if cell.Topology == "direct_quic" {
			metrics = append(metrics, "edge_migration_first_rpc_ms")
		}
	case "adaptive-selection-v1":
		if cell.Topology == "adaptive_web" {
			metrics = []string{"connect_p50_ms", "connect_p95_ms", "connect_p99_ms", "active_streams", "cleanup_latency_ms", "adaptive_web_cold_formula_ratio"}
		} else {
			metrics = []string{
				"connect_p50_ms", "connect_p95_ms", "connect_p99_ms",
				"cpu_ns_per_delivered_byte", "active_streams", "cleanup_latency_ms",
				"adaptive_cold_formula_ratio", "adaptive_cpu_connect_formula_ratio",
			}
		}
	default:
		return nil, fmt.Errorf("cell %s uses unknown profile %s", cell.ID, cell.ProfileID)
	}
	return metrics, nil
}

func isBrowserWebTransportTopology(topology string) bool {
	return strings.HasPrefix(topology, "browser_")
}

func validateCellSelection(cell PerformanceCell, mode string) error {
	if len(cell.SupportedCandidates) == 0 || len(cell.SupportedCandidates) > 4 {
		return fmt.Errorf("cell %s supported_candidates must contain 1..4 entries", cell.ID)
	}
	candidates := append([]string(nil), cell.SupportedCandidates...)
	slices.Sort(candidates)
	for index, candidate := range candidates {
		if strings.TrimSpace(candidate) == "" || index > 0 && candidate == candidates[index-1] {
			return fmt.Errorf("cell %s supported_candidates must be unique and non-empty", cell.ID)
		}
	}
	if mode == "forced" {
		if len(cell.SupportedCandidates) != 1 {
			return fmt.Errorf("forced cell %s must declare exactly one supported candidate", cell.ID)
		}
		if cell.Policy != "RequireWebSocket" && cell.Policy != "RequireQUICFamily" {
			return fmt.Errorf("forced cell %s has invalid explicit policy %q", cell.ID, cell.Policy)
		}
		return nil
	}
	if mode == "adaptive" {
		if len(cell.SupportedCandidates) < 2 {
			return fmt.Errorf("adaptive cell %s must declare every supported candidate", cell.ID)
		}
		if cell.Policy != "Adaptive" {
			return fmt.Errorf("adaptive cell %s policy = %q, want Adaptive", cell.ID, cell.Policy)
		}
		return nil
	}
	return fmt.Errorf("cell %s profile has unknown mode %q", cell.ID, mode)
}

func allocateLPT(cells []PerformanceCell, laneCount int) ([]int, error) {
	if laneCount <= 0 {
		return nil, errors.New("eligible lane count must be positive")
	}
	durations := make([]int, len(cells))
	for index, cell := range cells {
		if cell.DurationMinutes <= 0 {
			return nil, fmt.Errorf("cell %s duration must be positive", cell.ID)
		}
		durations[index] = cell.DurationMinutes
	}
	sort.Sort(sort.Reverse(sort.IntSlice(durations)))
	loads := make([]int, laneCount)
	for _, duration := range durations {
		minimum := 0
		for lane := 1; lane < len(loads); lane++ {
			if loads[lane] < loads[minimum] {
				minimum = lane
			}
		}
		loads[minimum] += duration
	}
	sort.Ints(loads)
	return loads, nil
}

func ceilDiv(numerator, denominator int) int {
	if numerator <= 0 {
		return 0
	}
	if denominator <= 0 {
		return int(^uint(0) >> 1)
	}
	return 1 + (numerator-1)/denominator
}
