package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

const (
	evidenceConnectionID          = "8394c8f03e515708"
	seededRandomLossSeed          = int64(20260720)
	seededRandomLossDraws         = uint64(10_000)
	seededRandomLossBasisPoints   = uint32(100)
	seededRandomLossDatagramBytes = uint64(1200)
	outageStartNS                 = int64(1e9)
	outageDurationNS              = int64(2e9)
	rebindAtNS                    = int64(2e9)
)

// Every registered case that does not have a richer protocol-specific
// validator still needs an explicit identity and artifact-binding contract.
// Keep this list closed so a newly added case cannot silently inherit a
// permissive default.
var registeredCaseIdentityFallback = map[string]struct{}{
	"CS-C1": {}, "CS-C2": {}, "CS-C3": {}, "CS-C4": {}, "CS-C5": {}, "CS-C6": {},
	"BS-C7": {}, "BS-C8": {},
	"NS-N1": {}, "NS-N2": {}, "NS-N3": {}, "NS-N4": {}, "BN-N5": {},
	"CF-C1": {}, "CF-C2": {}, "CF-C3": {}, "CF-C4": {}, "CF-C5": {}, "CF-C6": {}, "CF-C7": {}, "CF-C8": {},
	"NP-FLOW-FULL": {}, "NP-RESET-FIN": {}, "NP-TARGET-LOSS": {}, "NP-MAXDATA": {}, "NP-STREAM-LIMIT": {},
}

func validateCaseEvidenceSemantics(builder *resultBuilder, manifest *PerformanceManifest, context string, evidence CaseEvidence, baseDir string) error {
	if evidence.ID == "CAP-SOAK-HOURLY" {
		return validateSoakCase(builder, manifest.Soak, context, evidence, baseDir)
	}
	if strings.HasPrefix(evidence.ID, "CAP-") {
		return validateCapacityCase(builder, manifest.Capacity, context, evidence, baseDir)
	}
	switch evidence.ID {
	case "WF-UDP-FULL":
		metrics, config, trace, err := loadCaseCore(builder, context, evidence, baseDir)
		if err != nil {
			return err
		}
		fields := []string{
			"input_units", "input_bytes", "output_units", "output_bytes", "canceled_units", "canceled_bytes",
			"dropped_units", "dropped_bytes", "duplicate_units", "duplicate_bytes", "ordinal_loss_units",
			"burst_loss_units", "outage_units", "mtu_drop_units", "delay_units", "jitter_units",
			"reordered_units", "rate_limited_units", "nat_rebinds", "queue_overflow_units",
		}
		values, err := expectedActualCounters(metrics, fields)
		if err != nil {
			return err
		}
		for _, field := range fields[10:] {
			if values[field] <= 0 {
				return fmt.Errorf("fault counter %s was not exercised", field)
			}
		}
		if values["input_units"]+values["duplicate_units"] != values["output_units"]+values["dropped_units"]+values["canceled_units"] ||
			values["input_bytes"]+values["duplicate_bytes"] != values["output_bytes"]+values["dropped_bytes"]+values["canceled_bytes"] {
			return errors.New("UDP expected/actual counters violate unit or byte conservation")
		}
		if err := requireConfig(config, map[string]string{
			"profile": "udp-full-v1", "clock": "virtual-deterministic", "pump": "net.PacketConn",
			"watchdog": "completed",
		}); err != nil {
			return err
		}
		return requireTraceEvent(trace, "weaknet_udp_fault_matrix_completed")
	case "WF-UDP-RANDOM-LOSS":
		metrics, config, trace, err := loadCaseCore(builder, context, evidence, baseDir)
		if err != nil {
			return err
		}
		wantLosses := uint64(0)
		for ordinal := uint64(1); ordinal <= seededRandomLossDraws; ordinal++ {
			if seededEvidenceRandomLoss(seededRandomLossSeed, ordinal, seededRandomLossBasisPoints) {
				wantLosses++
			}
		}
		values, err := expectedActualCounters(metrics, []string{
			"input_units", "output_units", "dropped_units", "random_loss_units",
			"input_bytes", "output_bytes", "dropped_bytes", "random_loss_bytes",
		})
		if err != nil || uint64(values["input_units"]) != seededRandomLossDraws || uint64(values["random_loss_units"]) != wantLosses ||
			values["dropped_units"] != values["random_loss_units"] || values["input_units"] != values["output_units"]+values["dropped_units"] || wantLosses == 0 {
			return errors.New("seeded random-loss counters do not match the frozen sampler")
		}
		if uint64(values["input_bytes"]) != seededRandomLossDraws*seededRandomLossDatagramBytes || uint64(values["random_loss_bytes"]) != wantLosses*seededRandomLossDatagramBytes ||
			values["dropped_bytes"] != values["random_loss_bytes"] || values["input_bytes"] != values["output_bytes"]+values["dropped_bytes"] {
			return errors.New("seeded random-loss byte counters violate frozen datagram-size conservation")
		}
		if err := requireConfig(config, map[string]string{
			"profile": "udp-random-loss-v1", "sampler": "splitmix64-seed-ordinal-v1", "seed": "20260720",
			"draws": "10000", "loss_basis_points": "100", "datagram_bytes": "1200", "watchdog": "completed",
		}); err != nil {
			return err
		}
		return requireTraceEvent(trace, "weaknet_udp_seeded_random_loss_completed")
	case "WF-BYTE-FULL":
		metrics, config, trace, err := loadCaseCore(builder, context, evidence, baseDir)
		if err != nil {
			return err
		}
		fields := []string{
			"input_bytes", "output_bytes", "canceled_bytes", "delay_units", "jitter_units", "rate_limited_units",
			"outage_units", "fragment_units", "coalesced_units", "backpressure_units", "half_closes",
		}
		values, err := expectedActualCounters(metrics, fields)
		if err != nil {
			return err
		}
		for _, field := range fields[3:] {
			if values[field] <= 0 {
				return fmt.Errorf("fault counter %s was not exercised", field)
			}
		}
		if values["input_bytes"] != values["output_bytes"]+values["canceled_bytes"] {
			return errors.New("byte expected/actual counters violate conservation")
		}
		if err := requireConfig(config, map[string]string{
			"profile": "byte-full-v1", "clock": "virtual-deterministic", "pump": "net.Conn",
			"watchdog": "completed",
		}); err != nil {
			return err
		}
		return requireTraceEvent(trace, "weaknet_byte_fault_matrix_completed")
	case "WF-CLEANUP-FULL":
		metrics, config, trace, err := loadCaseCore(builder, context, evidence, baseDir)
		if err != nil {
			return err
		}
		fields := []string{"input_bytes", "output_bytes", "canceled_bytes", "pending_units", "pending_bytes"}
		values, err := expectedActualCounters(metrics, fields)
		if err != nil {
			return err
		}
		if values["canceled_bytes"] <= 0 || values["pending_units"] != 0 || values["pending_bytes"] != 0 ||
			values["input_bytes"] != values["output_bytes"]+values["canceled_bytes"] {
			return errors.New("cleanup expected/actual counters do not prove drained cancellation conservation")
		}
		if err := requireConfig(config, map[string]string{
			"profile": "cleanup-full-v1", "pump": "real-socket", "watchdog": "completed",
		}); err != nil {
			return err
		}
		return requireTraceEvent(trace, "weaknet_cleanup_completed")
	case "SYS-COMMON-KERNEL":
		metrics, config, trace, err := loadCaseCore(builder, context, evidence, baseDir)
		if err != nil {
			return err
		}
		faults := []string{"delay", "jitter", "periodic_loss", "burst_loss", "duplicate", "reorder", "rate_limit", "outage"}
		values, err := expectedActualCounters(metrics, append(append([]string(nil), faults...), "outage_duration_ns"))
		if err != nil {
			return err
		}
		for _, fault := range faults {
			if values[fault] <= 0 {
				return fmt.Errorf("kernel fault %s was not exercised", fault)
			}
		}
		ebpfPackets, packetsErr := metricValueWithUnit(metrics, "ebpf_packets", "count")
		ebpfBytes, bytesErr := metricValueWithUnit(metrics, "ebpf_bytes", "bytes")
		watchdogs, watchdogErr := metricValueWithUnit(metrics, "watchdog_timeouts", "count")
		if packetsErr != nil || bytesErr != nil || watchdogErr != nil || ebpfPackets <= 0 || ebpfBytes <= 0 || watchdogs != 0 {
			return errors.New("tc/eBPF/watchdog metrics are incomplete")
		}
		if err := requireConfig(config, map[string]string{
			"os": "linux", "namespace": "isolated", "tc": "netem-v1", "ebpf": "enabled", "watchdog": "completed",
			"connection_id": evidenceConnectionID, "outage_start_ns": "1000000000", "outage_duration_ns": "2000000000",
		}); err != nil {
			return err
		}
		if err := requireMetricConnectionID(metrics, evidenceConnectionID); err != nil {
			return err
		}
		ordered, err := requireOrderedTrace(trace, evidenceConnectionID, []string{"outage_started", "outage_ended", "kernel_fault_matrix_completed"})
		if err != nil || ordered[0].AtNS != outageStartNS || ordered[1].AtNS-ordered[0].AtNS != outageDurationNS ||
			values["outage"] != 1 || values["outage_duration_ns"] != float64(ordered[1].AtNS-ordered[0].AtNS) {
			return errors.New("outage trace does not match its frozen schedule, counters, duration, or connection ID")
		}
		pcapData, err := loadCaseArtifact(builder, context, evidence, "pcap", baseDir)
		if err != nil {
			return err
		}
		return validatePCAPConnectionID(pcapData, evidenceConnectionID)
	case "SYS-PMTUD-WSS-RECOVER-IPV4", "SYS-PMTUD-WSS-RECOVER-IPV6",
		"SYS-PMTUD-WSS-TIMEOUT-IPV4", "SYS-PMTUD-WSS-TIMEOUT-IPV6":
		return validateWSSPMTUDCase(builder, context, evidence, baseDir)
	case "NP-REBIND", "SYS-MIGRATION-REBIND":
		return validateRebindCase(builder, context, evidence, baseDir)
	case "NP-PMTUD-STATE", "SYS-PMTUD-QUIC-IPV4", "SYS-PMTUD-QUIC-IPV6":
		return validateQUICPMTUDCase(builder, context, evidence, baseDir)
	default:
		if _, exists := registeredCaseIdentityFallback[evidence.ID]; !exists {
			return fmt.Errorf("case %s has no frozen semantic validator", evidence.ID)
		}
		return validateRegisteredCaseIdentity(builder, context, evidence, baseDir)
	}
}

func validateSoakCase(builder *resultBuilder, contract SoakContract, context string, evidence CaseEvidence, baseDir string) error {
	metrics, config, trace, err := loadCaseCore(builder, context, evidence, baseDir)
	if err != nil {
		return err
	}
	if err := requireConfig(config, map[string]string{
		"profile":               "hourly-weaknet-soak-v1",
		"duration_ns":           strconv.FormatInt(contract.DurationNS, 10),
		"fault_cycle_period_ns": strconv.FormatInt(contract.FaultCyclePeriodNS, 10),
		"fault_cycle_count":     strconv.Itoa(contract.FaultCycleCount),
		"reconnect_count":       strconv.Itoa(contract.ReconnectCount),
		"migration_count":       strconv.Itoa(contract.MigrationCount),
		"watchdog":              "completed",
	}); err != nil {
		return fmt.Errorf("soak effective config: %w", err)
	}
	metricUnits := map[string]string{
		"duration_ns": "nanoseconds", "fault_cycle_count": "count", "reconnect_count": "count", "migration_count": "count",
		"rss_growth_bytes": "bytes", "goroutine_growth": "count", "open_fd_growth": "count", "task_growth": "count",
		"residual_sessions": "count", "residual_goroutines": "count", "residual_open_fds": "count", "residual_tasks": "count", "watchdog_timeouts": "count",
	}
	values := make(map[string]float64, len(metricUnits))
	for name, unit := range metricUnits {
		value, valueErr := metricValueWithUnit(metrics, name, unit)
		if valueErr != nil || value < 0 || mathTrunc(value) != value {
			return fmt.Errorf("soak metric %s is missing, has the wrong unit, or is not a nonnegative integer", name)
		}
		values[name] = value
	}
	if values["duration_ns"] != float64(contract.DurationNS) ||
		values["fault_cycle_count"] != float64(contract.FaultCycleCount) ||
		values["reconnect_count"] != float64(contract.ReconnectCount) ||
		values["migration_count"] != float64(contract.MigrationCount) ||
		values["rss_growth_bytes"] > float64(contract.MaxRSSGrowthBytesPerHour) ||
		values["goroutine_growth"] > float64(contract.MaxGoroutineGrowthPerHour) ||
		values["open_fd_growth"] > float64(contract.MaxOpenFDGrowthPerHour) ||
		values["task_growth"] > float64(contract.MaxTaskGrowthPerHour) ||
		values["residual_sessions"] != float64(contract.ResidualSessions) ||
		values["residual_goroutines"] != float64(contract.ResidualGoroutines) ||
		values["residual_open_fds"] != float64(contract.ResidualOpenFDs) ||
		values["residual_tasks"] != float64(contract.ResidualTasks) || values["watchdog_timeouts"] != 0 {
		return errors.New("soak metrics do not prove the frozen duration, cycles, reconnect/migration counts, resource slopes, and zero residuals")
	}
	if len(trace.Records) != contract.FaultCycleCount+2 || trace.Records[0].Event != "soak_started" || trace.Records[0].AtNS != 0 ||
		trace.Records[0].ConnectionID != evidenceConnectionID || trace.Records[0].Digest != caseExecutionID(context) ||
		trace.Records[len(trace.Records)-1].Event != "soak_completed" || trace.Records[len(trace.Records)-1].AtNS != contract.DurationNS ||
		trace.Records[len(trace.Records)-1].ConnectionID != evidenceConnectionID || trace.Records[len(trace.Records)-1].Digest != caseExecutionID(context) {
		return errors.New("soak trace does not contain the complete one-hour start/cycle/completion timeline")
	}
	for index := 1; index <= contract.FaultCycleCount; index++ {
		record := trace.Records[index]
		if record.Event != "fault_cycle_completed" || record.AtNS != int64(index)*contract.FaultCyclePeriodNS ||
			record.ConnectionID != evidenceConnectionID || record.Digest != caseExecutionID(context) {
			return errors.New("soak trace cycle schedule or execution identity is invalid")
		}
	}
	resourceData, err := loadCaseArtifact(builder, context, evidence, "resource", baseDir)
	if err != nil {
		return err
	}
	var resource ResourceArtifact
	if err := decodeStrictJSON(resourceData, &resource); err != nil {
		return err
	}
	if len(resource.Records) != 2 || resource.Records[0].Phase != "soak_start" || resource.Records[1].Phase != "soak_end" ||
		resource.Records[0].AtNS != 0 || resource.Records[1].AtNS != contract.DurationNS ||
		resource.Records[0].ActiveSessions != 0 || resource.Records[1].ActiveSessions != 0 ||
		resource.Records[0].UniqueActiveSessions != 0 || resource.Records[1].UniqueActiveSessions != 0 {
		return errors.New("soak resource timeline must contain zero-session start/end samples for the full duration")
	}
	start, finish := resource.Records[0], resource.Records[1]
	residuals := []struct {
		name     string
		observed *int
	}{
		{name: "residual_sessions", observed: finish.ResidualSessions},
		{name: "residual_goroutines", observed: finish.ResidualGoroutines},
		{name: "residual_open_fds", observed: finish.ResidualOpenFDs},
		{name: "residual_tasks", observed: finish.ResidualTasks},
	}
	for _, residual := range residuals {
		if residual.observed == nil || *residual.observed < 0 || float64(*residual.observed) != values[residual.name] {
			return fmt.Errorf("soak resource %s must be present and match the typed residual metric", residual.name)
		}
	}
	if finish.RSSBytes < start.RSSBytes || finish.RSSBytes-start.RSSBytes > contract.MaxRSSGrowthBytesPerHour ||
		finish.Goroutines < start.Goroutines || finish.Goroutines-start.Goroutines > contract.MaxGoroutineGrowthPerHour ||
		finish.OpenFDs < start.OpenFDs || finish.OpenFDs-start.OpenFDs > contract.MaxOpenFDGrowthPerHour ||
		finish.Tasks < start.Tasks || finish.Tasks-start.Tasks > contract.MaxTaskGrowthPerHour {
		return errors.New("soak resource slope exceeds the frozen RSS/goroutine/fd/task limits")
	}
	if finish.Goroutines-start.Goroutines != int(values["goroutine_growth"]) ||
		finish.OpenFDs-start.OpenFDs != int(values["open_fd_growth"]) || finish.Tasks-start.Tasks != int(values["task_growth"]) ||
		finish.RSSBytes-start.RSSBytes != uint64(values["rss_growth_bytes"]) {
		return errors.New("soak resource slope counters do not bind the typed resource timeline")
	}
	return nil
}

func validateRegisteredCaseIdentity(builder *resultBuilder, context string, evidence CaseEvidence, baseDir string) error {
	traceData, err := loadCaseArtifact(builder, context, evidence, "trace", baseDir)
	if err != nil {
		return err
	}
	configData, err := loadCaseArtifact(builder, context, evidence, "config", baseDir)
	if err != nil {
		return err
	}
	var trace TraceArtifact
	var config ConfigArtifact
	if err := decodeStrictJSON(traceData, &trace); err != nil {
		return err
	}
	if err := decodeStrictJSON(configData, &config); err != nil {
		return err
	}
	if trace.Context != context || config.Context != context {
		return errors.New("case identity artifacts are bound to a different execution context")
	}
	executionID := caseExecutionID(context)
	traceRef := evidence.Evidence["trace"]
	required := map[string]string{
		"case_id":      evidence.ID,
		"case_profile": evidence.Profile,
		"test_id":      executionID,
		"trace_sha256": traceRef.SHA256,
		"watchdog":     "completed",
	}
	if metricsRef, exists := evidence.Evidence["metrics"]; exists {
		metricsData, metricsErr := loadCaseArtifact(builder, context, evidence, "metrics", baseDir)
		if metricsErr != nil {
			return metricsErr
		}
		var metrics MetricsArtifact
		if err := decodeStrictJSON(metricsData, &metrics); err != nil {
			return err
		}
		if metrics.Context != context {
			return errors.New("case metrics are bound to a different execution context")
		}
		completed, metricErr := metricValueWithUnit(metrics, "completed_operations", "count")
		if metricErr != nil || completed <= 0 || mathTrunc(completed) != completed {
			return errors.New("case metrics do not prove a positive completed operation count")
		}
		required["metrics_sha256"] = metricsRef.SHA256
	}
	if err := requireConfig(config, required); err != nil {
		return fmt.Errorf("case identity binding: %w", err)
	}
	if len(trace.Records) != 1 || trace.Records[0].Event != "completed" || trace.Records[0].Digest != executionID {
		return errors.New("case identity trace must contain one completed event with the deterministic test ID")
	}
	return nil
}

func caseExecutionID(context string) string {
	digest := sha256.Sum256([]byte("flowersec-transport-case-v1\x00" + context))
	return hex.EncodeToString(digest[:])
}

func seededEvidenceRandomLoss(seed int64, ordinal uint64, basisPoints uint32) bool {
	value := uint64(seed) ^ (ordinal * 0x9e3779b97f4a7c15)
	value += 0x9e3779b97f4a7c15
	value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9
	value = (value ^ (value >> 27)) * 0x94d049bb133111eb
	value ^= value >> 31
	return value%10_000 < uint64(basisPoints)
}

func validateCapacityCase(builder *resultBuilder, contract CapacityContract, context string, evidence CaseEvidence, baseDir string) error {
	metrics, config, trace, err := loadCaseCore(builder, context, evidence, baseDir)
	if err != nil {
		return err
	}
	if err := requireConfig(config, map[string]string{
		"sessions":             strconv.Itoa(contract.Sessions),
		"ramp_duration_ns":     strconv.FormatInt(contract.RampDurationNS, 10),
		"hold_duration_ns":     strconv.FormatInt(contract.HoldDurationNS, 10),
		"cleanup_duration_ns":  strconv.FormatInt(contract.CleanupDurationNS, 10),
		"watchdog_duration_ns": strconv.FormatInt(contract.WatchdogDurationNS, 10),
		"watchdog":             "completed",
	}); err != nil {
		return fmt.Errorf("capacity effective config: %w", err)
	}
	values := make(map[string]float64)
	for name, unit := range map[string]string{
		"attempted_sessions": "count", "succeeded_sessions": "count", "failed_sessions": "count",
		"unique_active_peak": "count", "hold_duration_ns": "nanoseconds", "hold_disconnects": "count",
		"cleanup_disconnects": "count", "watchdog_timeouts": "count", "cleanup_residual_sessions": "count",
	} {
		value, valueErr := metricValueWithUnit(metrics, name, unit)
		if valueErr != nil || value < 0 || mathTrunc(value) != value {
			return fmt.Errorf("capacity metric %s is missing, has the wrong unit, or is not a nonnegative integer", name)
		}
		values[name] = value
	}
	target := float64(contract.Sessions)
	if values["attempted_sessions"] != target || values["succeeded_sessions"] != target || values["failed_sessions"] != 0 ||
		values["attempted_sessions"] != values["succeeded_sessions"]+values["failed_sessions"] ||
		values["unique_active_peak"] != target || values["hold_duration_ns"] != float64(contract.HoldDurationNS) ||
		values["hold_disconnects"] != 0 || values["cleanup_disconnects"] != target ||
		values["watchdog_timeouts"] != 0 || values["cleanup_residual_sessions"] != 0 {
		return errors.New("capacity counters do not prove 1000 unique held sessions with zero failures, watchdogs, hold disconnects, and cleanup residuals")
	}
	ordered, err := requireOrderedTrace(trace, "", []string{"capacity_ramp_completed", "capacity_hold_completed", "capacity_cleanup_completed"})
	if err != nil {
		return fmt.Errorf("capacity trace: %w", err)
	}
	wantTimes := []int64{
		contract.RampDurationNS,
		contract.RampDurationNS + contract.HoldDurationNS,
		contract.RampDurationNS + contract.HoldDurationNS + contract.CleanupDurationNS,
	}
	for index, record := range ordered {
		if record.AtNS != wantTimes[index] || record.AttemptedSessions != contract.Sessions ||
			record.SucceededSessions != contract.Sessions || record.FailedSessions != 0 ||
			record.UniqueActiveSessions != contract.Sessions {
			return errors.New("capacity trace counters or phase timestamps do not match the frozen contract")
		}
	}
	if ordered[0].ActiveSessions != contract.Sessions || ordered[0].Disconnects != 0 ||
		ordered[1].ActiveSessions != contract.Sessions || ordered[1].Disconnects != 0 ||
		ordered[2].ActiveSessions != 0 || ordered[2].Disconnects != contract.Sessions {
		return errors.New("capacity trace does not prove an intact hold interval followed by complete disconnect cleanup")
	}
	resourceData, err := loadCaseArtifact(builder, context, evidence, "resource", baseDir)
	if err != nil {
		return err
	}
	var resource ResourceArtifact
	if err := decodeStrictJSON(resourceData, &resource); err != nil {
		return err
	}
	if err := validateCapacityResourceTimeline(resource, contract, wantTimes); err != nil {
		return err
	}
	return nil
}

func validateCapacityResourceTimeline(artifact ResourceArtifact, contract CapacityContract, wantTimes []int64) error {
	if len(artifact.Records) != 3 {
		return errors.New("capacity resource timeline must contain ramp, hold, and cleanup samples")
	}
	phases := []string{"ramp", "hold", "cleanup"}
	previousCPU := uint64(0)
	for index, record := range artifact.Records {
		if record.Phase != phases[index] || record.AtNS != wantTimes[index] || record.CPUNanoseconds < previousCPU ||
			record.RSSBytes > contract.MaxRSSBytes || record.CPUNanoseconds > contract.MaxCPUNanoseconds ||
			record.OpenFDs < 0 || record.OpenFDs > contract.MaxOpenFDs || record.Goroutines > contract.MaxGoroutines ||
			record.Tasks < 0 || record.Tasks > contract.MaxTasks || record.UniqueActiveSessions != contract.Sessions {
			return errors.New("capacity resource timeline is incomplete, non-monotonic, or exceeds a frozen resource limit")
		}
		if index < 2 && record.ActiveSessions != contract.Sessions || index == 2 && record.ActiveSessions != 0 {
			return errors.New("capacity resource timeline active sessions do not match ramp/hold/cleanup state")
		}
		previousCPU = record.CPUNanoseconds
	}
	return nil
}

func loadCaseArtifact(builder *resultBuilder, context string, evidence CaseEvidence, kind, baseDir string) ([]byte, error) {
	artifact, exists := evidence.Evidence[kind]
	if !exists {
		return nil, fmt.Errorf("missing %s", kind)
	}
	data, ok := readArtifact(builder, context, kind, artifact, baseDir)
	if !ok {
		return nil, fmt.Errorf("invalid %s", kind)
	}
	return data, nil
}

func validateRebindCase(builder *resultBuilder, context string, evidence CaseEvidence, baseDir string) error {
	metrics, config, trace, err := loadCaseCore(builder, context, evidence, baseDir)
	if err != nil {
		return err
	}
	configRequired := map[string]string{
		"connection_id": evidenceConnectionID, "rebind_mode": "same-ip-port", "rebind_at_ns": "2000000000", "watchdog": "completed",
	}
	traceEvent := "native_path_rebind_completed"
	if evidence.ID == "SYS-MIGRATION-REBIND" {
		configRequired["os"] = "linux"
		configRequired["namespace"] = "isolated"
		configRequired["tc"] = "netem-v1"
		traceEvent = "kernel_path_rebind_completed"
	}
	if err := requireConfig(config, configRequired); err != nil {
		return err
	}
	values, err := metricValuesWithUnit(metrics, "count", []string{
		"path_updates", "path_validations", "rpc_before_rebind", "rpc_after_rebind", "watchdog_timeouts",
	})
	if err != nil || values["path_updates"] != 1 || values["path_validations"] != 1 ||
		values["rpc_before_rebind"] != 1 || values["rpc_after_rebind"] != 1 || values["watchdog_timeouts"] != 0 {
		return errors.New("rebind metrics do not prove one validated path update with RPC continuity")
	}
	if err := requireMetricConnectionID(metrics, configRequired["connection_id"]); err != nil {
		return err
	}
	ordered, err := requireOrderedTrace(trace, configRequired["connection_id"], []string{
		"rpc_before_rebind", "rebind_scheduled", "path_updated", "path_validated", "rpc_after_rebind", traceEvent,
	})
	if err != nil || ordered[1].AtNS != rebindAtNS {
		return errors.New("rebind trace does not match its frozen schedule, event order, counters, or connection ID")
	}
	qlogData, err := loadCaseArtifact(builder, context, evidence, "qlog", baseDir)
	if err != nil {
		return err
	}
	pcapData, err := loadCaseArtifact(builder, context, evidence, "pcap", baseDir)
	if err != nil {
		return err
	}
	return validateCorrelatedPathTransition(qlogData, pcapData, configRequired["connection_id"])
}

func validateQUICPMTUDCase(builder *resultBuilder, context string, evidence CaseEvidence, baseDir string) error {
	metrics, config, trace, err := loadCaseCore(builder, context, evidence, baseDir)
	if err != nil {
		return err
	}
	version := 4
	required := map[string]string{
		"link_mtu": "1280", "expected_terminal": "recovered", "actual_terminal": "recovered", "watchdog": "completed",
		"connection_id": evidenceConnectionID,
	}
	traceEvent := "userspace_pmtud_state_converged"
	if evidence.ID == "NP-PMTUD-STATE" {
		required["pmtud"] = "userspace-state-machine-v1"
		required["ip_family"] = "ipv4"
	} else {
		required["os"] = "linux"
		required["namespace"] = "isolated"
		required["firewall"] = "allow-icmp-ptb"
		required["pmtud"] = "kernel-quic-v1"
		traceEvent = "kernel_quic_pmtud_recovered"
		if evidence.ID == "SYS-PMTUD-QUIC-IPV6" {
			version = 6
			required["ip_family"] = "ipv6"
		} else {
			required["ip_family"] = "ipv4"
		}
	}
	if err := requireConfig(config, required); err != nil {
		return err
	}
	metricNames := []string{"oversized_udp_packets", "constrained_udp_packets", "pmtud_recoveries", "rpc_completed", "watchdog_timeouts"}
	if evidence.ID != "NP-PMTUD-STATE" {
		metricNames = append(metricNames, "icmp_ptb_received")
	}
	values, err := metricValuesWithUnit(metrics, "count", metricNames)
	if err != nil || values["oversized_udp_packets"] < 1 || values["constrained_udp_packets"] < 1 ||
		values["pmtud_recoveries"] != 1 || values["rpc_completed"] < 1 || values["watchdog_timeouts"] != 0 {
		return errors.New("QUIC PMTUD metrics do not prove one recovered oversized-to-constrained path")
	}
	if evidence.ID != "NP-PMTUD-STATE" && values["icmp_ptb_received"] < 1 {
		return errors.New("kernel QUIC PMTUD metrics do not prove ICMP PTB reception")
	}
	if err := requireTraceEventForConnection(trace, traceEvent, required["connection_id"]); err != nil {
		return err
	}
	qlogData, err := loadCaseArtifact(builder, context, evidence, "qlog", baseDir)
	if err != nil {
		return err
	}
	if err := validateOrderedQlogConnection(qlogData, required["connection_id"], []string{
		"transport:packet_too_large", "transport:metrics_updated", "application:rpc_completed",
	}); err != nil {
		return fmt.Errorf("QUIC PMTUD qlog does not prove a same-connection post-recovery RPC: %w", err)
	}
	pcapData, err := loadCaseArtifact(builder, context, evidence, "pcap", baseDir)
	if err != nil {
		return err
	}
	return validateQUICPMTUDCaptureForConnection(pcapData, version, evidence.ID != "NP-PMTUD-STATE", required["connection_id"])
}

func loadCaseCore(builder *resultBuilder, context string, evidence CaseEvidence, baseDir string) (MetricsArtifact, ConfigArtifact, TraceArtifact, error) {
	var metrics MetricsArtifact
	var config ConfigArtifact
	var trace TraceArtifact
	for kind, target := range map[string]any{"metrics": &metrics, "config": &config, "trace": &trace} {
		artifact, exists := evidence.Evidence[kind]
		if !exists {
			return metrics, config, trace, fmt.Errorf("missing %s", kind)
		}
		data, ok := readArtifact(builder, context, kind, artifact, baseDir)
		if !ok {
			return metrics, config, trace, fmt.Errorf("invalid %s", kind)
		}
		if err := decodeStrictJSON(data, target); err != nil {
			return metrics, config, trace, err
		}
	}
	return metrics, config, trace, nil
}

func expectedActualCounters(artifact MetricsArtifact, fields []string) (map[string]float64, error) {
	records, err := metricRecordValues(artifact)
	if err != nil {
		return nil, err
	}
	result := make(map[string]float64, len(fields))
	for _, field := range fields {
		expected, expectedOK := records["expected_"+field]
		actual, actualOK := records["actual_"+field]
		unit := counterUnit(field)
		if !expectedOK || !actualOK {
			return nil, fmt.Errorf("expected/actual counters for %s are missing, unequal, negative, or fractional", field)
		}
		if expected.Unit != unit || actual.Unit != unit {
			return nil, fmt.Errorf("expected/actual counter unit for %s must be %s", field, unit)
		}
		if expected.Value != actual.Value || expected.Value < 0 || mathTrunc(expected.Value) != expected.Value {
			return nil, fmt.Errorf("expected/actual counters for %s are missing, unequal, negative, or fractional", field)
		}
		result[field] = actual.Value
	}
	return result, nil
}

func counterUnit(field string) string {
	switch {
	case strings.HasSuffix(field, "_bytes"):
		return "bytes"
	case strings.HasSuffix(field, "_ns"):
		return "nanoseconds"
	default:
		return "count"
	}
}

func metricRecordValues(artifact MetricsArtifact) (map[string]MetricCounterRecord, error) {
	values := make(map[string]MetricCounterRecord, len(artifact.Records))
	for _, record := range artifact.Records {
		if _, duplicate := values[record.Name]; duplicate {
			return nil, fmt.Errorf("duplicate metric %s", record.Name)
		}
		values[record.Name] = record
	}
	return values, nil
}

func metricValues(artifact MetricsArtifact) (map[string]float64, error) {
	records, err := metricRecordValues(artifact)
	if err != nil {
		return nil, err
	}
	values := make(map[string]float64, len(records))
	for name, record := range records {
		values[name] = record.Value
	}
	return values, nil
}

func metricValueWithUnit(artifact MetricsArtifact, name, unit string) (float64, error) {
	records, err := metricRecordValues(artifact)
	if err != nil {
		return 0, err
	}
	record, exists := records[name]
	if !exists || record.Unit != unit {
		return 0, fmt.Errorf("metric %s must exist with unit %s", name, unit)
	}
	return record.Value, nil
}

func metricValuesWithUnit(artifact MetricsArtifact, unit string, names []string) (map[string]float64, error) {
	values := make(map[string]float64, len(names))
	for _, name := range names {
		value, err := metricValueWithUnit(artifact, name, unit)
		if err != nil {
			return nil, err
		}
		values[name] = value
	}
	return values, nil
}

func requireMetricConnectionID(artifact MetricsArtifact, connectionID string) error {
	for _, record := range artifact.Records {
		if record.ConnectionID != connectionID {
			return fmt.Errorf("metric %s is not bound to connection ID %s", record.Name, connectionID)
		}
	}
	return nil
}

func requireConfig(artifact ConfigArtifact, required map[string]string) error {
	values := make(map[string]string, len(artifact.Records))
	for _, record := range artifact.Records {
		if _, duplicate := values[record.Key]; duplicate {
			return fmt.Errorf("duplicate config %s", record.Key)
		}
		values[record.Key] = record.Value
	}
	for key, want := range required {
		if values[key] != want {
			return fmt.Errorf("effective config %s = %q, want %q", key, values[key], want)
		}
	}
	return nil
}

func requireTraceEvent(artifact TraceArtifact, event string) error {
	if !slices.ContainsFunc(artifact.Records, func(record TraceRecord) bool { return record.Event == event }) {
		return fmt.Errorf("trace is missing %s", event)
	}
	return nil
}

func requireTraceEventForConnection(artifact TraceArtifact, event, connectionID string) error {
	if !slices.ContainsFunc(artifact.Records, func(record TraceRecord) bool {
		return record.Event == event && record.ConnectionID == connectionID
	}) {
		return fmt.Errorf("trace is missing %s for connection ID %s", event, connectionID)
	}
	return nil
}

func requireOrderedTrace(artifact TraceArtifact, connectionID string, events []string) ([]TraceRecord, error) {
	if len(artifact.Records) != len(events) {
		return nil, fmt.Errorf("trace contains %d records, want exactly %d raw events", len(artifact.Records), len(events))
	}
	for index, record := range artifact.Records {
		if record.Event != events[index] || index > 0 && record.AtNS <= artifact.Records[index-1].AtNS ||
			connectionID != "" && record.ConnectionID != connectionID {
			return nil, fmt.Errorf("trace event %d does not match ordered event %s and connection ID %s", index+1, events[index], connectionID)
		}
	}
	return artifact.Records, nil
}

func validateWSSPMTUDCase(builder *resultBuilder, context string, evidence CaseEvidence, baseDir string) error {
	metrics, config, trace, err := loadCaseCore(builder, context, evidence, baseDir)
	if err != nil {
		return err
	}
	recovered := strings.Contains(evidence.ID, "RECOVER")
	terminal := "timed_out"
	firewall := "drop-icmp-ptb"
	event := "pmtud_timed_out"
	if recovered {
		terminal, firewall, event = "recovered", "allow-icmp-ptb", "pmtud_recovered"
	}
	if err := requireConfig(config, map[string]string{
		"os": "linux", "namespace": "isolated", "firewall": firewall,
		"expected_terminal": terminal, "actual_terminal": terminal, "watchdog": "completed",
	}); err != nil {
		return err
	}
	if err := requireTraceEvent(trace, event); err != nil {
		return err
	}
	values, err := metricValues(metrics)
	if err != nil || values["watchdog_timeouts"] != 0 || recovered && values["rpc_completed"] < 1 || !recovered && values["timeout_observed"] < 1 {
		return errors.New("WSS PMTUD terminal metrics do not match recover/timeout semantics")
	}
	artifact, exists := evidence.Evidence["tcp_info"]
	if !exists {
		return errors.New("missing tcp_info")
	}
	data, ok := readArtifact(builder, context, "tcp_info", artifact, baseDir)
	if !ok {
		return errors.New("invalid tcp_info")
	}
	var tcpInfo TCPInfoArtifact
	if err := decodeStrictJSON(data, &tcpInfo); err != nil || len(tcpInfo.Records) < 2 {
		return errors.New("WSS PMTUD requires at least two TCP_INFO observations")
	}
	first := tcpInfo.Records[0]
	last := tcpInfo.Records[len(tcpInfo.Records)-1]
	if recovered && !(first.SendMSSBytes > 1280 && last.SendMSSBytes <= 1280) {
		return errors.New("recover evidence does not prove MSS adaptation")
	}
	if !recovered && !(first.SendMSSBytes > 1280 && last.SendMSSBytes > 1280 && last.RetransmittedBytes > first.RetransmittedBytes) {
		return errors.New("timeout evidence does not prove persistent oversized retransmission")
	}
	pcapData, err := loadCaseArtifact(builder, context, evidence, "pcap", baseDir)
	if err != nil {
		return err
	}
	version := 4
	if strings.HasSuffix(evidence.ID, "IPV6") {
		version = 6
	}
	return validateWSSPMTUDCapture(pcapData, tcpInfo, recovered, version)
}

func validateWSSPMTUDCapture(pcapData []byte, tcpInfo TCPInfoArtifact, recovered bool, version int) error {
	packets, err := parseClassicPCAP(pcapData)
	if err != nil {
		return err
	}
	first, last := tcpInfo.Records[0], tcpInfo.Records[len(tcpInfo.Records)-1]
	for packetIndex, packet := range packets {
		if packet.ipVersion != version || packet.protocol != 6 || packet.length <= 1280 {
			continue
		}
		local := packet.sourceEndpoint()
		remote := packet.destinationEndpoint()
		if first.LocalAddress != local.Addr().String() || first.LocalPort != local.Port() ||
			first.RemoteAddress != remote.Addr().String() || first.RemotePort != remote.Port() ||
			last.LocalAddress != first.LocalAddress || last.LocalPort != first.LocalPort ||
			last.RemoteAddress != first.RemoteAddress || last.RemotePort != first.RemotePort ||
			last.SocketCookie != first.SocketCookie || !(first.AtNS < packet.atNS && packet.atNS < last.AtNS) {
			continue
		}
		if !recovered {
			return nil
		}
		for _, candidate := range packets[packetIndex+1:] {
			isPTB := version == 4 && candidate.protocol == 1 && candidate.icmpType == 3 && candidate.icmpCode == 4 ||
				version == 6 && candidate.protocol == 58 && candidate.icmpType == 2
			if isPTB && candidate.quotesFlow(packet) && packet.atNS < candidate.atNS && candidate.atNS < last.AtNS {
				return nil
			}
		}
		return errors.New("WSS recover capture has no ICMP PTB with the quoted TCP tuple inside the TCP_INFO time window")
	}
	return errors.New("TCP_INFO observations do not bind one socket tuple/cookie and time window around the oversized TCP packet")
}

func mathTrunc(value float64) float64 {
	return float64(int64(value))
}
