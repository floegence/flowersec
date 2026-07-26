package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
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
	if evidence.ID == "CAP-SOAK-5M" {
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
		pcapData, err := loadCaseSemanticArtifact(builder, context, evidence, "pcap", baseDir)
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
	case "BN-N5", "BS-C7", "BS-C8":
		return validateBrowserSmokeCase(builder, context, evidence, baseDir)
	default:
		if _, exists := registeredCaseIdentityFallback[evidence.ID]; !exists {
			return fmt.Errorf("case %s has no frozen semantic validator", evidence.ID)
		}
		return validateRegisteredCaseIdentity(builder, context, evidence, baseDir)
	}
}

func validateBrowserSmokeCase(builder *resultBuilder, context string, evidence CaseEvidence, baseDir string) error {
	metrics, config, trace, err := loadCaseCore(builder, context, evidence, baseDir)
	if err != nil {
		return err
	}
	topology := "browser_webtransport"
	if evidence.ID == "BS-C8" {
		topology = "browser_tunnel_wt_wss"
	}
	attachmentIndex := slices.IndexFunc(evidence.Attachments, func(attachment EvidenceAttachment) bool {
		return attachment.Kind == "browser-controller-result"
	})
	if attachmentIndex < 0 {
		return errors.New("browser smoke evidence is missing its raw Chromium workload attachment")
	}
	attachment := evidence.Attachments[attachmentIndex].Artifact
	qlogCount, pcapCount := 0, 0
	for _, source := range evidence.RawSources {
		switch source.Kind {
		case "qlog":
			qlogCount++
		case "pcap":
			pcapCount++
		}
	}
	if qlogCount < 1 || pcapCount != 1 {
		return errors.New("browser smoke evidence is missing raw qlog or exact pcap sources")
	}
	if err := requireConfig(config, map[string]string{
		"case_id": evidence.ID, "case_profile": evidence.Profile, "topology": topology,
		"browser_engine": "chromium", "producer": "production-browser-worker", "browser_result_sha256": attachment.SHA256,
		"trace_sha256": evidence.Evidence["trace"].SHA256, "metrics_sha256": evidence.Evidence["metrics"].SHA256,
		"raw_qlog_count": strconv.Itoa(qlogCount), "watchdog": "completed",
	}); err != nil {
		return fmt.Errorf("browser smoke effective config: %w", err)
	}
	wantCompleted := float64(3)
	if evidence.ID == "BN-N5" {
		wantCompleted = 8
	}
	values, err := metricValuesWithUnit(metrics, "count", []string{"completed_operations", "browser_sessions", "rpc_completed", "watchdog_timeouts", "residual_sessions", "residual_streams"})
	if err != nil || values["completed_operations"] != wantCompleted || values["browser_sessions"] != 2 || values["rpc_completed"] != 1 ||
		values["watchdog_timeouts"] != 0 || values["residual_sessions"] != 0 || values["residual_streams"] != 0 {
		return errors.New("browser smoke metrics do not prove the frozen operations and zero residuals")
	}
	events := []string{"browser_session_connected", "smoke_rpc_completed", "browser_session_closed"}
	if evidence.ID == "BN-N5" {
		events = []string{"browser_session_connected", "native_streams_opened", "native_stream_reset", "native_siblings_completed", "rpc_completed", "smoke_rpc_completed", "browser_session_closed"}
	}
	if _, err := requireOrderedTrace(trace, "", events); err != nil {
		return fmt.Errorf("browser smoke trace: %w", err)
	}
	if evidence.ID != "BN-N5" {
		return nil
	}
	qlogData, err := loadCaseArtifact(builder, context, evidence, "qlog", baseDir)
	if err != nil {
		return err
	}
	var attribution PacketAttributionArtifact
	if decodeStrictJSON(qlogData, &attribution) != nil || attribution.SchemaVersion != 1 || attribution.Kind != "transport_qlog_attribution" ||
		attribution.Context != context || len(attribution.Records) != 5 {
		return errors.New("browser native isolation qlog attribution identity is invalid")
	}
	connectionID := attribution.Records[0].ConnectionGroupID
	opened := make(map[uint64]struct{}, 4)
	for index, record := range attribution.Records[:4] {
		if record.Sequence != uint64(index+1) || record.Event != "transport:stream_opened" || record.NativeStreamID == nil || record.ConnectionGroupID != connectionID {
			return errors.New("browser native isolation qlog does not prove four ordered STREAM_OPENED records")
		}
		opened[*record.NativeStreamID] = struct{}{}
	}
	reset := attribution.Records[4]
	if len(opened) != 4 || reset.Sequence != 5 || reset.Event != "transport:reset_stream" || reset.NativeStreamID == nil || reset.ConnectionGroupID != connectionID {
		return errors.New("browser native isolation qlog does not prove one connection-scoped RESET_STREAM")
	}
	if _, exists := opened[*reset.NativeStreamID]; !exists {
		return errors.New("browser native isolation reset does not target one of the opened streams")
	}
	return nil
}

func validateSoakCase(builder *resultBuilder, contract SoakContract, context string, evidence CaseEvidence, baseDir string) error {
	metrics, config, trace, err := loadCaseCore(builder, context, evidence, baseDir)
	if err != nil {
		return err
	}
	if err := requireConfig(config, map[string]string{
		"profile":               "five-minute-weaknet-soak-v1",
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
		"rss_peak_bytes": "bytes", "goroutine_peak": "count", "open_fd_peak": "count", "task_peak": "count",
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
	completionLimit := contract.DurationNS + (5 * time.Second).Nanoseconds()
	if len(trace.Records) != contract.FaultCycleCount+2 || trace.Records[0].Event != "soak_started" || trace.Records[0].AtNS != 0 ||
		trace.Records[0].ConnectionID != "" || trace.Records[0].Digest != caseExecutionID(context) ||
		trace.Records[len(trace.Records)-1].Event != "soak_completed" || trace.Records[len(trace.Records)-1].AtNS < contract.DurationNS ||
		trace.Records[len(trace.Records)-1].AtNS > completionLimit ||
		trace.Records[len(trace.Records)-1].ConnectionID != "" || trace.Records[len(trace.Records)-1].Digest != caseExecutionID(context) {
		return errors.New("soak trace does not contain the complete five-minute start/cycle/completion timeline")
	}
	qlogData, err := loadCaseArtifact(builder, context, evidence, "qlog", baseDir)
	if err != nil {
		return err
	}
	pcapData, err := loadCaseArtifact(builder, context, evidence, "pcap", baseDir)
	if err != nil {
		return err
	}
	var qlogAttribution, pcapAttribution PacketAttributionArtifact
	if decodeStrictJSON(qlogData, &qlogAttribution) != nil || decodeStrictJSON(pcapData, &pcapAttribution) != nil ||
		qlogAttribution.Kind != "transport_qlog_attribution" || pcapAttribution.Kind != "transport_pcap_attribution" ||
		qlogAttribution.Context != context || pcapAttribution.Context != context ||
		len(qlogAttribution.Records) != contract.FaultCycleCount || len(pcapAttribution.Records) != contract.FaultCycleCount {
		return errors.New("soak typed attribution does not index one raw qlog and pcap source per cycle")
	}
	seenConnections := make(map[string]struct{}, contract.FaultCycleCount)
	for index := 1; index <= contract.FaultCycleCount; index++ {
		record := trace.Records[index]
		lowerBound := int64(index) * contract.FaultCyclePeriodNS
		upperBound := completionLimit
		if index < contract.FaultCycleCount {
			upperBound = int64(index+1) * contract.FaultCyclePeriodNS
		}
		if record.Event != "fault_cycle_completed" || record.AtNS < lowerBound || record.AtNS >= upperBound ||
			record.ConnectionID == "" || record.Digest != caseExecutionID(context) || record.NativeStreamID == nil || *record.NativeStreamID < 0 ||
			record.QLOGSourceID != fmt.Sprintf("qlog-%03d", index) || record.PCAPSourceID != fmt.Sprintf("pcap-%03d", index) {
			return errors.New("soak trace cycle schedule or execution identity is invalid")
		}
		local, localErr := netip.ParseAddrPort(record.LocalAddress)
		remote, remoteErr := netip.ParseAddrPort(record.RemoteAddress)
		if localErr != nil || remoteErr != nil || !local.IsValid() || !remote.IsValid() || local == remote {
			return errors.New("soak trace cycle path tuple is invalid")
		}
		if _, duplicate := seenConnections[record.ConnectionID]; duplicate {
			return errors.New("soak trace reuses a connection ID")
		}
		seenConnections[record.ConnectionID] = struct{}{}
		qlogRecord, pcapRecord := qlogAttribution.Records[index-1], pcapAttribution.Records[index-1]
		if qlogRecord.Sequence != uint64(index) || qlogRecord.SourceID != record.QLOGSourceID || qlogRecord.ConnectionGroupID != record.ConnectionID ||
			qlogRecord.Event != "transport:packet_sent" || qlogRecord.ByteOffset < 0 || qlogRecord.ByteLength <= 0 || qlogRecord.UnixNanoseconds <= 0 ||
			len(qlogRecord.SourceSHA256) != 64 || qlogRecord.PacketNumber == nil || qlogRecord.PacketNumberSpace == "" {
			return errors.New("soak qlog attribution is not bound to its cycle trace")
		}
		if pcapRecord.Sequence != uint64(index) || pcapRecord.SourceID != record.PCAPSourceID || pcapRecord.ByteOffset < 24 ||
			pcapRecord.ByteLength <= 16 || pcapRecord.UnixNanoseconds <= 0 || len(pcapRecord.SourceSHA256) != 64 ||
			pcapRecord.Event != "" || pcapRecord.ConnectionGroupID != "" || pcapRecord.PacketNumber != nil || pcapRecord.PacketNumberSpace != "" {
			return errors.New("soak pcap attribution is not bound to its cycle trace")
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
	if len(resource.Records) != contract.FaultCycleCount+2 || resource.Records[0].Phase != "soak_start" ||
		resource.Records[len(resource.Records)-1].Phase != "soak_end" || resource.Records[0].AtNS != 0 ||
		resource.Records[len(resource.Records)-1].AtNS < contract.DurationNS ||
		resource.Records[len(resource.Records)-1].AtNS > completionLimit {
		return errors.New("soak resource timeline must contain start, every cycle, and end samples")
	}
	for index := 1; index <= contract.FaultCycleCount; index++ {
		lowerBound := int64(index) * contract.FaultCyclePeriodNS
		upperBound := completionLimit
		if index < contract.FaultCycleCount {
			upperBound = int64(index+1) * contract.FaultCyclePeriodNS
		}
		if resource.Records[index].Phase != fmt.Sprintf("soak_cycle_%03d", index) ||
			resource.Records[index].AtNS < lowerBound || resource.Records[index].AtNS >= upperBound ||
			resource.Records[index].ResidualSessions != nil || resource.Records[index].ResidualGoroutines != nil ||
			resource.Records[index].ResidualOpenFDs != nil || resource.Records[index].ResidualTasks != nil {
			return errors.New("soak resource cycle series is incomplete or out of schedule")
		}
	}
	start, finish := resource.Records[0], resource.Records[len(resource.Records)-1]
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
	rssGrowth := positiveUint64EvidenceDelta(finish.RSSBytes, start.RSSBytes)
	goroutineGrowth := positiveIntEvidenceDelta(finish.Goroutines, start.Goroutines)
	openFDGrowth := positiveIntEvidenceDelta(finish.OpenFDs, start.OpenFDs)
	taskGrowth := positiveIntEvidenceDelta(finish.Tasks, start.Tasks)
	var rssPeak uint64
	var goroutinePeak, openFDPeak, taskPeak int
	for _, sample := range resource.Records {
		rssPeak = max(rssPeak, sample.RSSBytes)
		goroutinePeak = max(goroutinePeak, sample.Goroutines)
		openFDPeak = max(openFDPeak, sample.OpenFDs)
		taskPeak = max(taskPeak, sample.Tasks)
	}
	if rssGrowth > contract.MaxRSSGrowthBytesPerHour || goroutineGrowth > contract.MaxGoroutineGrowthPerHour ||
		openFDGrowth > contract.MaxOpenFDGrowthPerHour || taskGrowth > contract.MaxTaskGrowthPerHour {
		return errors.New("soak resource slope exceeds the frozen RSS/goroutine/fd/task limits")
	}
	if goroutineGrowth != int(values["goroutine_growth"]) || openFDGrowth != int(values["open_fd_growth"]) ||
		taskGrowth != int(values["task_growth"]) || rssGrowth != uint64(values["rss_growth_bytes"]) ||
		rssPeak != uint64(values["rss_peak_bytes"]) || goroutinePeak != int(values["goroutine_peak"]) ||
		openFDPeak != int(values["open_fd_peak"]) || taskPeak != int(values["task_peak"]) {
		return errors.New("soak resource slope and peak counters do not bind the typed resource series")
	}
	return nil
}

func positiveUint64EvidenceDelta(finish, start uint64) uint64 {
	if finish <= start {
		return 0
	}
	return finish - start
}
func positiveIntEvidenceDelta(finish, start int) int {
	if finish <= start {
		return 0
	}
	return finish - start
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
	var nativeQLOG *rawNativeQLOGSummary
	if qlogRef, exists := evidence.Evidence["qlog"]; exists {
		qlogData, qlogErr := loadCaseArtifact(builder, context, evidence, "qlog", baseDir)
		if qlogErr != nil {
			return qlogErr
		}
		if strings.Contains(string(qlogData), string([]byte{0x1e})) {
			summary, parseErr := parseRawNativeQLOGEvidence(qlogData)
			if parseErr != nil {
				return parseErr
			}
			nativeQLOG = &summary
		} else if isTypedQLOGAttribution(qlogData) {
			summary, parseErr := loadNativeQLOGAttribution(builder, context, evidence, qlogData, baseDir)
			if parseErr != nil {
				return parseErr
			}
			nativeQLOG = &summary
		}
		if nativeQLOG != nil {
			required["qlog_sha256"] = qlogRef.SHA256
			required["qlog_source"] = "quic-go-json-seq-v0.3"
			required["qlog_connection_id"] = nativeQLOG.connectionID
		}
	}
	if err := requireConfig(config, required); err != nil {
		return fmt.Errorf("case identity binding: %w", err)
	}
	if nativeQLOG != nil {
		if err := validateNativeApplicationTrace(evidence.ID, trace, executionID, *nativeQLOG); err != nil {
			return err
		}
	} else if len(trace.Records) != 1 || trace.Records[0].Event != "completed" || trace.Records[0].Digest != executionID {
		return errors.New("case identity trace must contain one completed event with the deterministic test ID")
	}
	return nil
}

func loadNativeQLOGAttribution(builder *resultBuilder, context string, evidence CaseEvidence, data []byte, baseDir string) (rawNativeQLOGSummary, error) {
	var attribution PacketAttributionArtifact
	if err := decodeStrictJSON(data, &attribution); err != nil {
		return rawNativeQLOGSummary{}, err
	}
	if attribution.SchemaVersion != 1 || attribution.Kind != "transport_qlog_attribution" || attribution.Context != context || len(attribution.Records) == 0 {
		return rawNativeQLOGSummary{}, errors.New("native qlog attribution identity is incomplete")
	}
	sources := make(map[string]validatedRawSource)
	qlogCount := 0
	for _, raw := range evidence.RawSources {
		if raw.Kind != "qlog" {
			continue
		}
		qlogCount++
		wantID := fmt.Sprintf("qlog-%03d", qlogCount)
		if raw.ID != wantID {
			return rawNativeQLOGSummary{}, fmt.Errorf("native raw qlog source ID = %q, want %q", raw.ID, wantID)
		}
		rawContext := context + " raw sources"
		rawData, ok := readArtifact(builder, rawContext, "raw_qlog", raw.Artifact, baseDir)
		if !ok {
			return rawNativeQLOGSummary{}, fmt.Errorf("native raw qlog source %s is invalid", raw.ID)
		}
		if _, duplicate := sources[raw.ID]; duplicate {
			return rawNativeQLOGSummary{}, fmt.Errorf("native raw qlog source %s is duplicated", raw.ID)
		}
		sources[raw.ID] = validatedRawSource{id: raw.ID, kind: "qlog", digest: raw.Artifact.SHA256, data: rawData}
	}
	if len(sources) != 1 {
		return rawNativeQLOGSummary{}, fmt.Errorf("native qlog attribution requires exactly one immutable raw qlog source; got %d", len(sources))
	}
	seen := make(map[string]struct{}, len(sources))
	for index, record := range attribution.Records {
		source, exists := sources[record.SourceID]
		if record.Sequence != uint64(index+1) || !exists || record.SourceSHA256 != source.digest {
			return rawNativeQLOGSummary{}, fmt.Errorf("native qlog attribution record %d does not bind an indexed raw source", index+1)
		}
		if err := validateAttributedQLOGRecord(source, record); err != nil {
			return rawNativeQLOGSummary{}, fmt.Errorf("native qlog attribution record %d does not match immutable source bytes: %w", index+1, err)
		}
		seen[source.id] = struct{}{}
	}
	for id, source := range sources {
		if _, exists := seen[id]; !exists {
			return rawNativeQLOGSummary{}, fmt.Errorf("native raw qlog source %s has no attribution record", id)
		}
		if err := validateRawNativeQLOGEvidence(context, source.data); err != nil {
			return rawNativeQLOGSummary{}, err
		}
		return parseRawNativeQLOGEvidence(source.data)
	}
	return rawNativeQLOGSummary{}, errors.New("native raw qlog source is unavailable")
}

func validateNativeApplicationTrace(caseID string, trace TraceArtifact, executionID string, qlog rawNativeQLOGSummary) error {
	if len(trace.Records) < 2 {
		return errors.New("native application trace must contain observations and completion")
	}
	last := trace.Records[len(trace.Records)-1]
	if last.Event != "completed" || last.Digest != executionID || last.ConnectionID != qlog.connectionID {
		return errors.New("native application trace completion is not bound to the raw qlog connection")
	}
	observed := make(map[int64]string)
	for _, record := range trace.Records[:len(trace.Records)-1] {
		if record.Digest != executionID || record.ConnectionID != qlog.connectionID || record.NativeStreamID == nil || *record.NativeStreamID < 0 {
			return errors.New("native application observation is not bound to the raw qlog connection and stream")
		}
		if _, exists := qlog.streamIDs[*record.NativeStreamID]; !exists {
			return fmt.Errorf("native application stream %d is absent from raw qlog STREAM frames", *record.NativeStreamID)
		}
		observed[*record.NativeStreamID] = record.Event
	}
	switch caseID {
	case "NS-N1":
		if len(observed) < 8 {
			return errors.New("native application trace does not bind eight distinct streams")
		}
	case "NS-N2", "NS-N4", "NP-FLOW-FULL":
		var blocked, rpc *int64
		for _, record := range trace.Records {
			if record.NativeStreamID == nil {
				continue
			}
			switch record.Event {
			case "native_stream_blocked":
				blocked = record.NativeStreamID
			case "rpc_completed":
				rpc = record.NativeStreamID
			}
		}
		if blocked == nil || rpc == nil || *blocked == *rpc {
			return errors.New("native flow trace does not bind blocked and sibling streams")
		}
		if _, exists := qlog.blockedIDs[*blocked]; !exists {
			return errors.New("native blocked stream is absent from raw qlog STREAM_DATA_BLOCKED frames")
		}
	case "NS-N3", "NP-RESET-FIN":
		var reset, rpc *int64
		for _, record := range trace.Records {
			if record.NativeStreamID == nil {
				continue
			}
			switch record.Event {
			case "native_stream_reset":
				reset = record.NativeStreamID
			case "rpc_completed":
				rpc = record.NativeStreamID
			}
		}
		if reset == nil || rpc == nil || *reset == *rpc {
			return errors.New("native reset trace does not bind reset and sibling streams")
		}
		if _, resetSeen := qlog.resetIDs[*reset]; !resetSeen {
			return errors.New("native reset stream is absent from raw qlog RESET_STREAM frames")
		}
		if _, stopSeen := qlog.stoppedIDs[*reset]; !stopSeen {
			return errors.New("native reset stream is absent from raw qlog STOP_SENDING frames")
		}
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
	caseID := strings.TrimPrefix(strings.TrimPrefix(context, "race case "), "case ")
	streamCapacity := strings.HasPrefix(caseID, "CAP-STREAM-WT-")
	browserAggregate := caseID == "CAP-TUNNEL-WT-WSS-1000" || caseID == "CAP-TUNNEL-WT-QUIC-1000" || streamCapacity
	if streamCapacity {
		contract.Sessions = 100
		contract.RampDurationNS = int64(60 * time.Second)
		contract.WatchdogDurationNS = contract.RampDurationNS + contract.HoldDurationNS + contract.CleanupDurationNS
	}
	if browserAggregate {
		contract.MaxRSSBytes = 3 << 30
		contract.MaxOpenFDs = 12288
	}
	if streamCapacity {
		contract.MaxCPUNanoseconds = uint64(240 * time.Second)
		contract.MaxOpenFDs = 32768
	}
	metrics, config, trace, err := loadCaseCore(builder, context, evidence, baseDir)
	if err != nil {
		return err
	}
	requiredConfig := map[string]string{
		"sessions":                 strconv.Itoa(contract.Sessions),
		"ramp_duration_ns":         strconv.FormatInt(contract.RampDurationNS, 10),
		"hold_duration_ns":         strconv.FormatInt(contract.HoldDurationNS, 10),
		"liveness_sweep_count":     "4",
		"liveness_sweep_period_ns": strconv.FormatInt(contract.HoldDurationNS/5, 10),
		"cleanup_duration_ns":      strconv.FormatInt(contract.CleanupDurationNS, 10),
		"watchdog_duration_ns":     strconv.FormatInt(contract.WatchdogDurationNS, 10),
		"watchdog":                 "completed",
		"resource_scope": func() string {
			if browserAggregate {
				return "go_runner_plus_chromium_process_tree"
			}
			return "go_runner"
		}(),
		"max_rss_bytes":  strconv.FormatUint(contract.MaxRSSBytes, 10),
		"max_open_fds":   strconv.Itoa(contract.MaxOpenFDs),
		"max_goroutines": strconv.Itoa(contract.MaxGoroutines),
		"max_tasks":      strconv.Itoa(contract.MaxTasks),
	}
	if streamCapacity {
		requiredConfig["connections_per_session"] = "1"
		requiredConfig["streams_per_session"] = "128"
	}
	if err := requireConfig(config, requiredConfig); err != nil {
		return fmt.Errorf("capacity effective config: %w", err)
	}
	values := make(map[string]float64)
	requiredMetrics := map[string]string{
		"attempted_sessions": "count", "succeeded_sessions": "count", "failed_sessions": "count",
		"unique_active_peak": "count", "hold_duration_ns": "nanoseconds", "hold_disconnects": "count",
		"liveness_sweeps": "count", "liveness_failures": "count",
		"cleanup_disconnects": "count", "watchdog_timeouts": "count", "cleanup_residual_sessions": "count",
	}
	if streamCapacity {
		requiredMetrics["completed_streams"] = "count"
		requiredMetrics["active_stream_peak"] = "count"
		requiredMetrics["cleanup_residual_streams"] = "count"
	}
	for name, unit := range requiredMetrics {
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
		values["hold_disconnects"] != 0 || values["liveness_sweeps"] != 4 || values["liveness_failures"] != 0 || values["cleanup_disconnects"] != target ||
		values["watchdog_timeouts"] != 0 || values["cleanup_residual_sessions"] != 0 {
		return errors.New("capacity counters do not prove 1000 unique held sessions with zero failures, watchdogs, hold disconnects, and cleanup residuals")
	}
	if streamCapacity && (values["completed_streams"] != 12800 || values["active_stream_peak"] != 12800 || values["cleanup_residual_streams"] != 0) {
		return errors.New("stream capacity counters do not prove 100 live sessions, 12800 completed and peak streams, and zero cleanup residual streams")
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
		if streamCapacity && (record.CompletedStreams != 12800 || record.ResidualStreams != 0 ||
			(index < 2 && record.ActiveStreams != 12800) || (index == 2 && record.ActiveStreams != 0)) {
			return errors.New("stream capacity trace does not prove completed, peak-active, and zero-residual stream counters")
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
	if err := validateCapacityResourceTimeline(resource, contract, wantTimes, streamCapacity); err != nil {
		return err
	}
	if streamCapacity {
		qlogData, err := loadCaseArtifact(builder, context, evidence, "qlog", baseDir)
		if err != nil {
			return err
		}
		var attribution PacketAttributionArtifact
		if decodeStrictJSON(qlogData, &attribution) != nil || attribution.SchemaVersion != 1 || attribution.Kind != "transport_qlog_attribution" || attribution.Context != context {
			return errors.New("stream capacity qlog attribution identity is invalid")
		}
		if err := validateCapacityStreamQLOGAttribution(attribution); err != nil {
			return err
		}
	}
	return nil
}

func validateCapacityStreamQLOGAttribution(attribution PacketAttributionArtifact) error {
	perConnection := make(map[string]map[uint64]struct{}, 100)
	previousAt := int64(0)
	streamRecords := 0
	for index, record := range attribution.Records {
		if record.Sequence != uint64(index+1) || strings.TrimSpace(record.Event) == "" || strings.TrimSpace(record.ConnectionGroupID) == "" ||
			record.UnixNanoseconds < previousAt {
			return errors.New("stream capacity qlog sequence, timestamp, or source identity is invalid")
		}
		previousAt = record.UnixNanoseconds
		if record.NativeStreamID == nil {
			if record.Event == "transport:stream_opened" {
				return errors.New("stream capacity qlog generic source binding is invalid")
			}
			continue
		}
		if record.Event != "transport:stream_opened" || *record.NativeStreamID < 12 || *record.NativeStreamID%4 != 0 {
			return errors.New("stream capacity qlog STREAM_OPENED identity is invalid")
		}
		streamRecords++
		streams := perConnection[record.ConnectionGroupID]
		if streams == nil {
			streams = make(map[uint64]struct{}, 128)
			perConnection[record.ConnectionGroupID] = streams
		}
		if _, duplicate := streams[*record.NativeStreamID]; duplicate {
			return errors.New("stream capacity qlog reuses a connection-scoped native stream ID")
		}
		streams[*record.NativeStreamID] = struct{}{}
	}
	if streamRecords != 100*128 {
		return fmt.Errorf("stream capacity qlog contains %d STREAM_OPENED records, want %d", streamRecords, 100*128)
	}
	if len(perConnection) != 100 {
		return fmt.Errorf("stream capacity qlog contains %d connection groups, want 100", len(perConnection))
	}
	for connectionID, streams := range perConnection {
		if len(streams) != 128 {
			return fmt.Errorf("stream capacity qlog connection %s contains %d streams, want 128", connectionID, len(streams))
		}
	}
	return nil
}

func validateCapacityResourceTimeline(artifact ResourceArtifact, contract CapacityContract, wantTimes []int64, streamCapacity bool) error {
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
		if streamCapacity && ((index < 2 && record.ActiveStreams != 12800) || (index == 2 && record.ActiveStreams != 0)) {
			return errors.New("stream capacity resource timeline does not prove the 12800-stream peak and cleanup")
		}
		previousCPU = record.CPUNanoseconds
	}
	cleanup := artifact.Records[2]
	if cleanup.ResidualSessions == nil || cleanup.ResidualGoroutines == nil || cleanup.ResidualOpenFDs == nil || cleanup.ResidualTasks == nil ||
		*cleanup.ResidualSessions != 0 || *cleanup.ResidualGoroutines < 0 || *cleanup.ResidualGoroutines > 64 ||
		*cleanup.ResidualOpenFDs < 0 || *cleanup.ResidualOpenFDs > 16 || *cleanup.ResidualTasks < 0 || *cleanup.ResidualTasks > 16 {
		return errors.New("capacity cleanup resource residuals are missing or exceed the frozen small leak bounds")
	}
	if streamCapacity && (cleanup.ResidualStreams == nil || *cleanup.ResidualStreams != 0) {
		return errors.New("stream capacity cleanup residual is missing or nonzero")
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

func loadCaseSemanticArtifact(builder *resultBuilder, context string, evidence CaseEvidence, kind, baseDir string) ([]byte, error) {
	data, err := loadCaseArtifact(builder, context, evidence, kind, baseDir)
	if err != nil || !isTypedPacketAttribution(data, kind) {
		return data, err
	}
	sources, err := loadCaseAttributedRawSources(builder, context, evidence, kind, data, baseDir)
	if err != nil {
		return nil, err
	}
	if len(sources) != 1 {
		return nil, fmt.Errorf("%s semantic validation requires exactly one immutable raw source; got %d", kind, len(sources))
	}
	return sources[0].data, nil
}

func loadCaseAttributedRawSources(builder *resultBuilder, context string, evidence CaseEvidence, kind string, data []byte, baseDir string) ([]validatedRawSource, error) {
	if kind != "pcap" && kind != "qlog" {
		return nil, fmt.Errorf("unsupported attributed raw source kind %q", kind)
	}
	if err := validateTypedStructuredArtifact(context, kind+"_attribution", data); err != nil {
		return nil, err
	}
	var attribution PacketAttributionArtifact
	if err := decodeStrictJSON(data, &attribution); err != nil {
		return nil, err
	}
	sources := make(map[string]validatedRawSource)
	ordered := make([]validatedRawSource, 0)
	count := 0
	for _, raw := range evidence.RawSources {
		if raw.Kind != kind {
			continue
		}
		count++
		wantID := fmt.Sprintf("%s-%03d", kind, count)
		if raw.ID != wantID {
			return nil, fmt.Errorf("%s raw source ID = %q, want %q", kind, raw.ID, wantID)
		}
		rawContext := context + " raw " + raw.ID
		if isNativeQLOGCase(evidence.ID) {
			rawContext = context + " raw sources"
		}
		rawData, ok := readArtifact(builder, rawContext, "raw_"+kind, raw.Artifact, baseDir)
		if !ok {
			return nil, fmt.Errorf("%s raw source %s is invalid", kind, raw.ID)
		}
		if _, duplicate := sources[raw.ID]; duplicate {
			return nil, fmt.Errorf("%s raw source %s is duplicated", kind, raw.ID)
		}
		source := validatedRawSource{id: raw.ID, kind: kind, digest: raw.Artifact.SHA256, path: raw.Artifact.Path, data: rawData}
		sources[raw.ID] = source
		ordered = append(ordered, source)
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("%s attribution has no immutable raw sources", kind)
	}
	seen := make(map[string]struct{}, len(sources))
	qlogRecords := make(map[string][]PacketAttributionRecord)
	for index, record := range attribution.Records {
		source, exists := sources[record.SourceID]
		if record.Sequence != uint64(index+1) || !exists || record.SourceSHA256 != source.digest {
			return nil, fmt.Errorf("%s attribution record %d does not bind an indexed raw source", kind, index+1)
		}
		if kind == "pcap" {
			if validateErr := validateAttributedPCAPRecord(source.data, record); validateErr != nil {
				return nil, fmt.Errorf("%s attribution record %d does not match immutable source bytes: %w", kind, index+1, validateErr)
			}
		} else {
			qlogRecords[source.id] = append(qlogRecords[source.id], record)
		}
		seen[source.id] = struct{}{}
	}
	for id, records := range qlogRecords {
		if validateErr := validateAttributedQLOGRecords(sources[id], records); validateErr != nil {
			return nil, fmt.Errorf("qlog attribution for source %s does not match immutable source bytes: %w", id, validateErr)
		}
	}
	for id := range sources {
		if _, exists := seen[id]; !exists {
			return nil, fmt.Errorf("%s raw source %s has no attribution record", kind, id)
		}
	}
	return ordered, nil
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
	qlogData, err := loadCaseSemanticArtifact(builder, context, evidence, "qlog", baseDir)
	if err != nil {
		return err
	}
	pcapData, err := loadCaseSemanticArtifact(builder, context, evidence, "pcap", baseDir)
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
	qlogData, err := loadCaseSemanticArtifact(builder, context, evidence, "qlog", baseDir)
	if err != nil {
		return err
	}
	if err := validateOrderedQlogConnection(qlogData, required["connection_id"], []string{
		"transport:packet_too_large", "transport:metrics_updated", "application:rpc_completed",
	}); err != nil {
		return fmt.Errorf("QUIC PMTUD qlog does not prove a same-connection post-recovery RPC: %w", err)
	}
	pcapData, err := loadCaseSemanticArtifact(builder, context, evidence, "pcap", baseDir)
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
	pcapData, err := loadCaseSemanticArtifact(builder, context, evidence, "pcap", baseDir)
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
