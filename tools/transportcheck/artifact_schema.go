package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strings"
)

type qlogEvent struct {
	name string
	data map[string]any
}

func validateQlogEvidence(context string, data []byte) error {
	var document struct {
		QlogVersion string `json:"qlog_version"`
		Title       string `json:"title"`
		Traces      []struct {
			Events []json.RawMessage `json:"events"`
		} `json:"traces"`
	}
	if err := decodeSingleJSON(data, &document); err != nil || document.QlogVersion == "" || document.Title != context ||
		len(document.Traces) != 1 || len(document.Traces[0].Events) == 0 {
		return errors.New("missing version, exact title, single trace, or events")
	}
	events := make([]qlogEvent, 0, len(document.Traces[0].Events))
	for _, raw := range document.Traces[0].Events {
		var fields []json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != 4 {
			return errors.New("event must use [time, category, name, data]")
		}
		var at float64
		var category, name string
		var eventData map[string]any
		if json.Unmarshal(fields[0], &at) != nil || !finite(at) || at < 0 || json.Unmarshal(fields[1], &category) != nil ||
			json.Unmarshal(fields[2], &name) != nil || json.Unmarshal(fields[3], &eventData) != nil || category == "" || name == "" {
			return errors.New("event time, category, name, or data is invalid")
		}
		events = append(events, qlogEvent{name: category + ":" + name, data: eventData})
	}
	for _, event := range events {
		if err := validateQlogEventFields(event); err != nil {
			return err
		}
	}
	required, streamCount, forbidden := qlogRequirements(context)
	position := -1
	for _, want := range required {
		found := -1
		for index := position + 1; index < len(events); index++ {
			if events[index].name == want {
				found = index
				break
			}
		}
		if found < 0 {
			return fmt.Errorf("missing ordered %s event", strings.ToUpper(strings.TrimPrefix(want, "transport:")))
		}
		position = found
	}
	for _, event := range events {
		if slices.Contains(forbidden, event.name) {
			return fmt.Errorf("forbidden %s event", event.name)
		}
	}
	if strings.HasPrefix(context, "case ") || strings.HasPrefix(context, "race case ") {
		if err := validateQlogCaseCorrelation(context, events); err != nil {
			return err
		}
	}
	if streamCount > 0 {
		ids := make(map[string]struct{})
		for _, event := range events {
			if event.name != "transport:stream_opened" {
				continue
			}
			id, exists := event.data["stream_id"]
			if exists {
				ids[fmt.Sprint(id)] = struct{}{}
			}
		}
		if len(ids) < streamCount {
			return fmt.Errorf("contains %d distinct native stream IDs, want at least %d", len(ids), streamCount)
		}
	}
	return nil
}

func validateQlogCaseCorrelation(context string, events []qlogEvent) error {
	caseID := strings.TrimPrefix(strings.TrimPrefix(context, "race case "), "case ")
	if len(events) == 0 {
		return errors.New("case qlog has no events to correlate")
	}
	connectionID := ""
	for _, event := range events {
		value, exists := event.data["connection_id"]
		candidate, isString := value.(string)
		if !exists || !isString || strings.TrimSpace(candidate) == "" {
			return fmt.Errorf("case qlog event %s is missing connection_id", event.name)
		}
		if connectionID == "" {
			connectionID = candidate
		} else if candidate != connectionID {
			return fmt.Errorf("case qlog event %s uses a different connection_id", event.name)
		}
	}
	streamID := func(event qlogEvent) (int64, bool) {
		value, exists := event.data["stream_id"]
		number, ok := value.(float64)
		return int64(number), exists && ok && finite(number) && number >= 0 && number == float64(int64(number))
	}
	requestID := func(event qlogEvent) (string, bool) {
		value, exists := event.data["request_id"]
		text, ok := value.(string)
		return text, exists && ok && strings.TrimSpace(text) != ""
	}
	var blocked, reset, stopped, rpc, released []int64
	for _, event := range events {
		id, hasID := streamID(event)
		switch event.name {
		case "transport:stream_data_blocked":
			if !hasID {
				return errors.New("stream_data_blocked must bind stream_id")
			}
			blocked = append(blocked, id)
		case "transport:reset_stream":
			if !hasID {
				return errors.New("reset_stream must bind stream_id")
			}
			reset = append(reset, id)
		case "transport:stop_sending":
			if !hasID {
				return errors.New("stop_sending must bind stream_id")
			}
			stopped = append(stopped, id)
		case "application:rpc_completed":
			if !hasID {
				return errors.New("rpc_completed must bind stream_id")
			}
			if _, ok := requestID(event); !ok {
				return errors.New("rpc_completed must bind request_id")
			}
			rpc = append(rpc, id)
		case "application:targeted_loss_released":
			if !hasID {
				return errors.New("targeted_loss_released must bind stream_id")
			}
			released = append(released, id)
		}
	}
	if caseID == "NS-N2" || caseID == "NS-N4" || caseID == "NP-FLOW-FULL" {
		if len(blocked) == 0 || len(rpc) == 0 || blocked[0] == rpc[0] {
			return errors.New("flow-isolation qlog must prove a blocked stream and a different sibling RPC stream")
		}
	}
	if caseID == "NS-N3" || caseID == "NP-RESET-FIN" {
		if len(reset) == 0 || len(stopped) == 0 || len(rpc) == 0 || reset[0] != stopped[0] || reset[0] == rpc[0] {
			return errors.New("reset-isolation qlog must correlate reset/stop on one stream and RPC on a sibling")
		}
	}
	if caseID == "NP-TARGET-LOSS" {
		if len(released) == 0 || len(rpc) == 0 || released[0] == rpc[0] {
			return errors.New("targeted-loss qlog must correlate the released target and a different sibling RPC")
		}
	}
	return nil
}

func validateQlogEventFields(event qlogEvent) error {
	requireNumber := func(fields ...string) bool {
		for _, field := range fields {
			value, exists := event.data[field]
			number, ok := value.(float64)
			if !exists || !ok || !finite(number) || number < 0 {
				return false
			}
		}
		return true
	}
	requireString := func(fields ...string) bool {
		for _, field := range fields {
			value, exists := event.data[field]
			text, ok := value.(string)
			if !exists || !ok || strings.TrimSpace(text) == "" {
				return false
			}
		}
		return true
	}
	valid := true
	switch event.name {
	case "transport:stream_opened":
		valid = requireNumber("stream_id") && requireString("stream_type")
	case "transport:stream_data_blocked":
		valid = requireNumber("stream_id", "limit")
	case "application:rpc_completed":
		valid = requireString("request_id", "status") && event.data["status"] == "ok"
		if _, exists := event.data["connection_id"]; exists {
			valid = valid && requireString("connection_id")
		}
	case "transport:reset_stream", "transport:stop_sending":
		valid = requireNumber("stream_id", "error_code")
	case "transport:data_blocked":
		valid = requireNumber("limit")
	case "transport:streams_blocked":
		valid = requireNumber("stream_limit")
	case "connectivity:path_updated":
		valid = requireString("old_path", "new_path", "remote_path", "connection_id") && event.data["old_path"] != event.data["new_path"]
	case "connectivity:path_validated":
		valid = requireString("new_path", "remote_path", "connection_id")
	case "recovery:packet_lost":
		valid = requireNumber("packet_number")
	case "application:targeted_loss_released":
		valid = requireNumber("stream_id", "missing_offset")
	case "transport:packet_too_large":
		valid = requireNumber("packet_size") && requireString("connection_id") && event.data["packet_size"].(float64) > 1280
	case "transport:metrics_updated":
		valid = requireNumber("smoothed_rtt_ns", "bytes_in_flight")
		if _, exists := event.data["connection_id"]; exists {
			valid = valid && requireString("connection_id")
		}
	case "transport:connection_started":
		valid = requireString("connection_id")
	case "application:capacity_completed":
		valid = requireNumber("sessions") && event.data["sessions"].(float64) >= 1000
	}
	if !valid {
		return fmt.Errorf("qlog event %s is missing required semantic fields", event.name)
	}
	return nil
}

func qlogRequirements(context string) (required []string, streamCount int, forbidden []string) {
	caseID := strings.TrimPrefix(strings.TrimPrefix(context, "race case "), "case ")
	if !strings.HasPrefix(context, "case ") && !strings.HasPrefix(context, "race case ") {
		return []string{"transport:metrics_updated"}, 0, nil
	}
	switch caseID {
	case "NS-N1":
		return []string{"transport:stream_opened"}, 8, nil
	case "NS-N2", "NS-N4", "NP-FLOW-FULL":
		return []string{"transport:stream_data_blocked", "application:rpc_completed"}, 0, []string{"transport:data_blocked"}
	case "NS-N3", "NP-RESET-FIN":
		return []string{"transport:reset_stream", "transport:stop_sending", "application:rpc_completed"}, 0, nil
	case "BN-N5":
		return []string{"transport:stream_opened", "transport:reset_stream", "application:rpc_completed"}, 4, nil
	case "NP-TARGET-LOSS":
		return []string{"recovery:packet_lost", "application:rpc_completed", "application:targeted_loss_released"}, 0, nil
	case "NP-MAXDATA":
		return []string{"transport:data_blocked"}, 0, nil
	case "NP-STREAM-LIMIT":
		return []string{"transport:streams_blocked"}, 0, nil
	case "NP-REBIND", "SYS-MIGRATION-REBIND":
		return []string{"connectivity:path_updated", "connectivity:path_validated", "application:rpc_completed"}, 0, nil
	case "NP-PMTUD-STATE", "SYS-PMTUD-QUIC-IPV4", "SYS-PMTUD-QUIC-IPV6":
		return []string{"transport:packet_too_large", "transport:metrics_updated", "application:rpc_completed"}, 0, nil
	case "CAP-DIRECT-QUIC-1000", "CAP-DIRECT-WT-1000", "CAP-TUNNEL-WT-WSS-1000", "CAP-TUNNEL-WT-QUIC-1000", "CAP-QQ-1000", "CAP-WQ-1000", "CAP-QW-1000":
		return []string{"transport:connection_started", "application:capacity_completed"}, 0, nil
	default:
		return []string{"transport:metrics_updated"}, 0, nil
	}
}

func checkPhaseOperationSeries(builder *resultBuilder, context string, runNumber int, phase expectedPhase, evidence PhaseEvidence, baseDir string) {
	artifactRef, exists := evidence.Artifacts["samples"]
	if !exists {
		return
	}
	data, ok := readArtifact(builder, context, "samples", artifactRef, baseDir)
	if !ok {
		return
	}
	var artifact OperationSeriesArtifact
	if err := decodeStrictJSON(data, &artifact); err != nil || len(artifact.Records) != 1 {
		return
	}
	record := artifact.Records[0]
	if record.RunNumber != runNumber {
		builder.fail("%s raw operation run_number = %d, want %d", context, record.RunNumber, runNumber)
	}
	if record.OperationCount != phase.sampleCount {
		builder.fail("%s raw operation count = %d, want %d", context, record.OperationCount, phase.sampleCount)
	}
	contract, err := signedOperationContract(phase.profileID, phase.phase)
	if err != nil {
		builder.fail("%s has no frozen raw operation contract: %v", context, err)
		return
	}
	if record.OperationDeadlineNS != contract.operationDeadlineNS || record.PhaseDeadlineNS != contract.phaseDeadlineNS {
		builder.fail("%s raw operation and phase deadlines do not match the frozen workload", context)
	}
	starts, startErr := expandIntRuns(record.StartDelayNS, record.OperationCount, true)
	durations, durationErr := expandIntRuns(record.DurationNS, record.OperationCount, true)
	retries, retryErr := expandIntRuns(record.RetryCounts, record.OperationCount, true)
	inputs, inputErr := expandIntRuns(record.InputBytes, record.OperationCount, true)
	outputs, outputErr := expandIntRuns(record.OutputBytes, record.OperationCount, true)
	scored, scoredErr := expandIntRuns(record.ScoredBytes, record.OperationCount, true)
	scoreDurations, scoreDurationErr := expandIntRuns(record.ScoreDurationNS, record.OperationCount, true)
	if err := errors.Join(startErr, durationErr, retryErr, inputErr, outputErr, scoredErr, scoreDurationErr); err != nil {
		builder.fail("%s raw operation series cannot be expanded: %v", context, err)
		return
	}
	retryCount := int64(0)
	for _, count := range retries {
		if count != 0 {
			retryCount = 1
			break
		}
	}
	if retryCount != 0 || evidence.RetryCount == nil || int64(*evidence.RetryCount) != retryCount {
		builder.inconclusive("%s retry_count is not derived from raw operations", context)
	}
	if len(record.FailureOrdinals) != 0 || evidence.FailureCount == nil || *evidence.FailureCount != len(record.FailureOrdinals) {
		builder.inconclusive("%s failure_count is not derived from raw operations", context)
	}
	if evidence.SampleCount == nil || *evidence.SampleCount != record.OperationCount {
		builder.inconclusive("%s sample_count is not derived from raw operations", context)
	}
	if contract.scheduledIntervalNS > 0 && record.ScheduledIntervalNS != contract.scheduledIntervalNS {
		builder.fail("%s scheduled interval = %dns, want %dns", context, record.ScheduledIntervalNS, contract.scheduledIntervalNS)
	}
	type boundary struct {
		at    int64
		delta int
	}
	events := make([]boundary, 0, 2*record.OperationCount)
	for index := 0; index < record.OperationCount; index++ {
		if record.ScheduledFirstNS > record.PhaseDeadlineNS || record.ScheduledIntervalNS > 0 &&
			int64(index) > (record.PhaseDeadlineNS-record.ScheduledFirstNS)/record.ScheduledIntervalNS {
			builder.fail("%s operation %d scheduled timestamp overflows or exceeds the phase deadline", context, index+1)
			break
		}
		scheduled := record.ScheduledFirstNS + int64(index)*record.ScheduledIntervalNS
		if starts[index] > record.PhaseDeadlineNS-scheduled {
			builder.fail("%s operation %d start timestamp exceeds the phase deadline", context, index+1)
			break
		}
		start := scheduled + starts[index]
		if durations[index] <= 0 || durations[index] > record.OperationDeadlineNS || durations[index] > record.PhaseDeadlineNS-start {
			builder.fail("%s operation %d violates its operation or phase deadline", context, index+1)
			break
		}
		completion := start + durations[index]
		if inputs[index] != contract.inputBytes || outputs[index] != contract.outputBytes || scored[index] != contract.scoredBytes {
			builder.fail("%s operation %d payload bytes do not match the frozen workload", context, index+1)
			break
		}
		if contract.scoredBytes > 0 && scoreDurations[index] <= 0 || contract.scoredBytes == 0 && scoreDurations[index] != 0 {
			builder.fail("%s operation %d score duration does not match the frozen workload", context, index+1)
			break
		}
		events = append(events, boundary{at: start, delta: 1}, boundary{at: completion, delta: -1})
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].at == events[j].at {
			return events[i].delta < events[j].delta
		}
		return events[i].at < events[j].at
	})
	current, maximum := 0, 0
	for _, event := range events {
		current += event.delta
		if current > maximum {
			maximum = current
		}
	}
	if maximum != record.MaxInflightObserved || maximum > contract.maxInflight {
		builder.fail("%s max inflight is not derived from raw operation timestamps or exceeds the frozen cap", context)
	}
}

type rawOperationContract struct {
	operationDeadlineNS int64
	phaseDeadlineNS     int64
	maxInflight         int
	scheduledIntervalNS int64
	inputBytes          int64
	outputBytes         int64
	scoredBytes         int64
}

func signedOperationContract(profileID, phase string) (rawOperationContract, error) {
	for _, profile := range signedProfiles {
		if profile.id != profileID {
			continue
		}
		switch phase {
		case "cold":
			return rawOperationContract{
				operationDeadlineNS: int64(profile.cold.OperationDeadlineSeconds) * 1e9,
				phaseDeadlineNS:     int64(profile.cold.PhaseDeadlineSeconds) * 1e9,
				maxInflight:         profile.cold.MaxInflight,
				scheduledIntervalNS: 1e9 / int64(profile.cold.StartRatePerSecond),
			}, nil
		case "rpc":
			return rawOperationContract{
				operationDeadlineNS: int64(profile.rpc.OperationDeadlineSeconds) * 1e9,
				phaseDeadlineNS:     int64(profile.rpc.PhaseDeadlineSeconds) * 1e9,
				maxInflight:         profile.rpc.Workers,
				scheduledIntervalNS: 1e6,
				inputBytes:          int64(profile.rpc.RequestBytes), outputBytes: int64(profile.rpc.ResponseBytes),
			}, nil
		case "bulk":
			bytes := int64(profile.bulk.WarmupBytesPerDirection + profile.bulk.ScoreBytesPerDirection)
			return rawOperationContract{
				operationDeadlineNS: int64(profile.bulk.PhaseDeadlineSeconds) * 1e9,
				phaseDeadlineNS:     int64(profile.bulk.PhaseDeadlineSeconds) * 1e9,
				maxInflight:         2, scheduledIntervalNS: 1e6,
				inputBytes: bytes, outputBytes: bytes, scoredBytes: int64(profile.bulk.ScoreBytesPerDirection),
			}, nil
		case "cleanup":
			return rawOperationContract{
				operationDeadlineNS: int64(profile.cleanupDeadlineSeconds) * 1e9,
				phaseDeadlineNS:     int64(profile.cleanupDeadlineSeconds) * 1e9,
				maxInflight:         1,
			}, nil
		}
	}
	return rawOperationContract{}, fmt.Errorf("unknown profile/phase %s/%s", profileID, phase)
}

func deriveMetricRun(run MetricRunSample) (float64, error) {
	if len(run.Sources) == 0 && len(run.OperandGraph) == 0 {
		return 0, errors.New("sources must bind at least one exact raw run artifact")
	}
	for _, source := range run.Sources {
		decoded, err := hex.DecodeString(source.ArtifactSHA256)
		if err != nil || len(decoded) != 32 {
			return 0, errors.New("sources contain an invalid digest")
		}
	}
	for _, operand := range run.OperandGraph {
		decoded, err := hex.DecodeString(operand.Source.ArtifactSHA256)
		if err != nil || len(decoded) != 32 {
			return 0, errors.New("operand graph contains an invalid digest")
		}
	}
	switch run.Derivation {
	case "mean", "max", "p50", "p95", "p99":
		values, err := expandFloatRuns(run.Observations)
		if err != nil || len(values) == 0 {
			return 0, errors.New("observation derivation requires finite raw observations")
		}
		switch run.Derivation {
		case "mean":
			return mean(values), nil
		case "max":
			return slices.Max(values), nil
		default:
			slices.Sort(values)
			probability := map[string]float64{"p50": .50, "p95": .95, "p99": .99}[run.Derivation]
			return quantile(values, probability), nil
		}
	case "ratio":
		if run.Numerator == nil || run.Denominator == nil || *run.Denominator <= 0 || !finite(*run.Numerator) || !finite(*run.Denominator) {
			return 0, errors.New("ratio requires finite numerator and positive denominator")
		}
		return *run.Numerator / *run.Denominator, nil
	case "duration_ms":
		if run.DurationNanoseconds == nil || *run.DurationNanoseconds < 0 {
			return 0, errors.New("duration_ms requires a non-negative duration")
		}
		return float64(*run.DurationNanoseconds) / 1e6, nil
	case "goodput_mbps":
		if run.DurationNanoseconds == nil || run.DeliveredBytes == nil || *run.DurationNanoseconds <= 0 || *run.DeliveredBytes == 0 {
			return 0, errors.New("goodput requires positive delivered bytes and duration")
		}
		return float64(*run.DeliveredBytes) * 8 * 1e3 / float64(*run.DurationNanoseconds), nil
	default:
		return 0, fmt.Errorf("unknown derivation %q", run.Derivation)
	}
}

func requiredMetricDerivation(metricID string) string {
	if strings.HasSuffix(metricID, "_ratio") || metricID == "cpu_ns_per_delivered_byte" {
		return "ratio"
	}
	if strings.Contains(metricID, "goodput_mbps") {
		return "goodput_mbps"
	}
	if strings.Contains(metricID, "p50") {
		return "p50"
	}
	if strings.Contains(metricID, "p95") {
		return "p95"
	}
	if strings.Contains(metricID, "p99") {
		return "p99"
	}
	if metricID == "rss_bytes" || metricID == "alloc_bytes" || metricID == "active_streams" {
		return "max"
	}
	return "duration_ms"
}

func validateMetricRunContract(manifest *PerformanceManifest, cellID, metricID string, run MetricRunSample) error {
	var cell *PerformanceCell
	for index := range manifest.Cells {
		if manifest.Cells[index].ID == cellID {
			cell = &manifest.Cells[index]
			break
		}
	}
	if cell == nil {
		return errors.New("unknown performance cell")
	}
	var profile *PerformanceProfile
	for index := range manifest.Profiles {
		if manifest.Profiles[index].ID == cell.ProfileID {
			profile = &manifest.Profiles[index]
			break
		}
	}
	switch run.Derivation {
	case "p50", "p95", "p99":
		values, err := expandFloatRuns(run.Observations)
		if err != nil {
			return err
		}
		want := 2000
		if profile != nil && profile.Mode == "adaptive" {
			want = 0
			for _, stage := range profile.AdaptiveStages {
				want += stage.Cold.Operations
			}
		}
		if len(values) != want {
			return fmt.Errorf("percentile has %d raw operation observations, want %d", len(values), want)
		}
	case "goodput_mbps":
		if profile == nil || profile.Bulk == nil || run.DeliveredBytes == nil || run.DurationNanoseconds == nil {
			return errors.New("goodput is missing its frozen profile or raw byte/time inputs")
		}
		if *run.DeliveredBytes != uint64(profile.Bulk.ScoreBytesPerDirection) {
			return fmt.Errorf("delivered bytes = %d, want score bytes %d", *run.DeliveredBytes, profile.Bulk.ScoreBytesPerDirection)
		}
		if *run.DurationNanoseconds <= 0 || *run.DurationNanoseconds > int64(profile.Bulk.PhaseDeadlineSeconds)*1e9 {
			return errors.New("goodput duration exceeds the frozen bulk phase deadline")
		}
	case "duration_ms":
		if metricID == "cleanup_latency_ms" {
			if profile == nil || run.DurationNanoseconds == nil {
				return errors.New("cleanup deadline requires a frozen profile and duration")
			}
			deadline := profile.CleanupDeadlineSeconds
			for _, stage := range profile.AdaptiveStages {
				deadline = max(deadline, stage.CleanupDeadlineSeconds)
			}
			if *run.DurationNanoseconds < 0 || *run.DurationNanoseconds > int64(deadline)*1e9 {
				return errors.New("cleanup deadline exceeded")
			}
		}
	}
	return nil
}

func expandFloatRuns(runs []FloatRunLength) ([]float64, error) {
	count := 0
	for _, run := range runs {
		if run.Count <= 0 || !finite(run.Value) || count > 1_000_000-run.Count {
			return nil, errors.New("invalid observation run length")
		}
		count += run.Count
	}
	values := make([]float64, 0, count)
	for _, run := range runs {
		for range run.Count {
			values = append(values, run.Value)
		}
	}
	return values, nil
}

func expandIntRuns(runs []IntRunLength, want int, nonnegative bool) ([]int64, error) {
	values := make([]int64, 0, want)
	for _, run := range runs {
		if run.Count <= 0 || len(values) > want-run.Count || nonnegative && run.Value < 0 {
			return nil, errors.New("invalid integer run length")
		}
		for range run.Count {
			values = append(values, run.Value)
		}
	}
	if len(values) != want {
		return nil, fmt.Errorf("expanded operation field has %d values, want %d", len(values), want)
	}
	return values, nil
}

func finite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}

func validateTypedStructuredArtifact(context, kind string, data []byte) error {
	switch kind {
	case "samples":
		var artifact OperationSeriesArtifact
		if err := decodeStrictJSON(data, &artifact); err != nil {
			return err
		}
		if artifact.SchemaVersion != 1 || artifact.Kind != "transport_samples" || artifact.Context != context || len(artifact.Records) != 1 {
			return errors.New("samples must contain one bound operation series")
		}
		return validateOperationSeriesShape(artifact.Records[0])
	case "trace":
		var artifact TraceArtifact
		if err := decodeStrictJSON(data, &artifact); err != nil {
			return err
		}
		if artifact.SchemaVersion != 1 || artifact.Kind != "transport_trace" || artifact.Context != context || len(artifact.Records) == 0 {
			return errors.New("trace must contain typed operation records")
		}
		for index, record := range artifact.Records {
			if record.Sequence != uint64(index+1) || record.AtNS < 0 || index > 0 && record.AtNS < artifact.Records[index-1].AtNS ||
				strings.TrimSpace(record.Event) == "" || !validSHA256(record.Digest) {
				return errors.New("trace record sequence, timestamp, event, or digest is invalid")
			}
		}
		return nil
	case "metrics":
		var artifact MetricsArtifact
		if err := decodeStrictJSON(data, &artifact); err != nil {
			return err
		}
		if artifact.SchemaVersion != 1 || artifact.Kind != "transport_metrics" || artifact.Context != context || len(artifact.Records) == 0 {
			return errors.New("metrics must contain typed operation records")
		}
		for _, record := range artifact.Records {
			if strings.TrimSpace(record.Name) == "" || strings.TrimSpace(record.Unit) == "" || !finite(record.Value) {
				return errors.New("metric counter is invalid")
			}
		}
		return nil
	case "config":
		var artifact ConfigArtifact
		if err := decodeStrictJSON(data, &artifact); err != nil {
			return err
		}
		if artifact.SchemaVersion != 1 || artifact.Kind != "transport_config" || artifact.Context != context || len(artifact.Records) == 0 {
			return errors.New("config must contain typed operation records")
		}
		for _, record := range artifact.Records {
			if strings.TrimSpace(record.Key) == "" || strings.TrimSpace(record.Value) == "" {
				return errors.New("config record is invalid")
			}
		}
		return nil
	case "resource":
		var artifact ResourceArtifact
		if err := decodeStrictJSON(data, &artifact); err != nil {
			return err
		}
		if artifact.SchemaVersion != 1 || artifact.Kind != "transport_resource" || artifact.Context != context || len(artifact.Records) == 0 {
			return errors.New("resource must contain typed operation records")
		}
		for _, record := range artifact.Records {
			if record.AtNS < 0 || record.RSSBytes == 0 || record.Goroutines <= 0 {
				return errors.New("resource record is invalid")
			}
		}
		for _, measurement := range artifact.Measurements {
			if err := validateResourceMeasurement(measurement); err != nil {
				return err
			}
		}
		return nil
	case "tcp_info":
		var artifact TCPInfoArtifact
		if err := decodeStrictJSON(data, &artifact); err != nil {
			return err
		}
		if artifact.SchemaVersion != 1 || artifact.Kind != "transport_tcp_info" || artifact.Context != context || len(artifact.Records) == 0 {
			return errors.New("tcp_info must contain typed operation records")
		}
		for index, record := range artifact.Records {
			local, localErr := netip.ParseAddr(record.LocalAddress)
			remote, remoteErr := netip.ParseAddr(record.RemoteAddress)
			if record.AtNS < 0 || index > 0 && record.AtNS <= artifact.Records[index-1].AtNS ||
				record.SendMSSBytes == 0 || localErr != nil || remoteErr != nil || !local.IsValid() || !remote.IsValid() ||
				record.LocalPort == 0 || record.RemotePort == 0 || strings.TrimSpace(record.SocketCookie) == "" {
				return errors.New("tcp_info record is invalid")
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown structured artifact kind %q", kind)
	}
}

func validateResourceMeasurement(measurement ScopedResourceMeasurement) error {
	if strings.TrimSpace(measurement.Name) == "" || !finite(measurement.Value) || measurement.Value < 0 ||
		(measurement.ProfileID == "") != (measurement.Phase == "") {
		return errors.New("resource measurement is invalid")
	}
	name := measurement.Name
	unit := ""
	positive := false
	integer := false
	switch {
	case strings.HasSuffix(name, "cpu_nanoseconds"), strings.HasSuffix(name, "cpu_connect_nanoseconds"):
		unit, integer = "nanoseconds", true
	case strings.HasSuffix(name, "delivered_bytes"):
		unit, positive, integer = "bytes", true, true
	case strings.HasSuffix(name, "retransmitted_bytes"), name == "rss_bytes", name == "alloc_bytes":
		unit, integer = "bytes", true
	case name == "active_streams":
		unit, integer = "count", true
	case strings.HasSuffix(name, ".nanoseconds"):
		unit, integer = "nanoseconds", true
	case name == "interactive.rpc_p99_milliseconds", name == "idle.rpc_p99_milliseconds":
		unit = "milliseconds"
	default:
		return fmt.Errorf("resource measurement %s is outside the frozen field schema", name)
	}
	if measurement.Unit != unit || positive && measurement.Value <= 0 || integer && mathTrunc(measurement.Value) != measurement.Value {
		return fmt.Errorf("resource measurement %s must use unit %s and its frozen numeric domain", name, unit)
	}
	return nil
}

func validateOperationSeriesShape(record OperationSeriesRecord) error {
	if record.RunNumber <= 0 || record.OperationCount <= 0 || record.ScheduledFirstNS < 0 || record.ScheduledIntervalNS < 0 ||
		record.OperationDeadlineNS <= 0 || record.PhaseDeadlineNS <= 0 || record.MaxInflightObserved <= 0 ||
		!validSHA256(record.ExpectedPayloadSHA256) || record.ExpectedPayloadSHA256 != record.ActualPayloadSHA256 {
		return errors.New("operation series metadata, deadline, inflight, or payload hash is invalid")
	}
	for _, field := range [][]IntRunLength{record.StartDelayNS, record.DurationNS, record.RetryCounts, record.InputBytes, record.OutputBytes, record.ScoredBytes, record.ScoreDurationNS} {
		if _, err := expandIntRuns(field, record.OperationCount, true); err != nil {
			return err
		}
	}
	if len(record.FailureOrdinals) != 0 {
		return errors.New("operation series contains failed operations")
	}
	return nil
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
