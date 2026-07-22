package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
)

var errMetricSourceMissing = errors.New("metric raw source is missing")

func validateAndDeriveMetricSources(builder *resultBuilder, report *EvidenceReport, manifest *PerformanceManifest, cellID, metricID string, run MetricRunSample, baseDir string) error {
	cell, evidenceRun, err := metricEvidenceRun(report, cellID, run.RunNumber)
	if err != nil {
		return err
	}
	for _, source := range run.Sources {
		if source.CellID != cellID || source.RunNumber != run.RunNumber {
			return fmt.Errorf("source cell %q differs from same cell %q", source.CellID, cellID)
		}
		if !validSHA256(source.ArtifactSHA256) || strings.TrimSpace(source.Kind) == "" || strings.TrimSpace(source.Field) == "" {
			return errors.New("source kind, field, or digest is invalid")
		}
	}
	if requiresMetricFaultBinding(metricID) {
		if err := validateMetricFaultBinding(builder, manifest, cellID, cell, evidenceRun, run.FaultBinding, run.DurationNanoseconds, metricID, baseDir); err != nil {
			return err
		}
	}

	derivation := requiredMetricDerivation(metricID)
	switch derivation {
	case "p50", "p95", "p99":
		phase := "cold"
		if strings.Contains(metricID, "rpc") {
			phase = "rpc"
		}
		var derived []float64
		for _, source := range run.Sources {
			if source.Kind != "samples" || source.Field != "duration_ns" || source.Phase != phase {
				return fmt.Errorf("percentile source must use %s duration_ns samples", phase)
			}
			record, err := operationSource(builder, cell, evidenceRun, source, baseDir)
			if err != nil {
				return err
			}
			values, err := expandIntRuns(record.DurationNS, record.OperationCount, true)
			if err != nil {
				return err
			}
			for _, value := range values {
				derived = append(derived, float64(value)/1e6)
			}
		}
		observed, err := expandFloatRuns(run.Observations)
		if err != nil || !sameFloatValues(observed, derived) {
			return errors.New("percentile observations are not derived from the bound operation durations")
		}
	case "goodput_mbps":
		if len(run.Sources) != 1 || run.Sources[0].Kind != "samples" || run.Sources[0].Phase != "bulk" || run.Sources[0].Field != "score_goodput" {
			return errors.New("goodput must bind one bulk score_goodput operation source")
		}
		record, err := operationSource(builder, cell, evidenceRun, run.Sources[0], baseDir)
		if err != nil {
			return err
		}
		scored, err := expandIntRuns(record.ScoredBytes, record.OperationCount, true)
		if err != nil {
			return err
		}
		durations, err := expandIntRuns(record.ScoreDurationNS, record.OperationCount, true)
		if err != nil || len(scored) == 0 || len(durations) != len(scored) {
			return errors.New("bulk score series is invalid")
		}
		delivered := slices.Min(scored)
		duration := slices.Max(durations)
		if delivered <= 0 || duration <= 0 || run.DeliveredBytes == nil || run.DurationNanoseconds == nil ||
			*run.DeliveredBytes != uint64(delivered) || *run.DurationNanoseconds != duration {
			return errors.New("goodput bytes/time are not derived from the slower bound bulk direction")
		}
	case "ratio":
		return validateRatioFormula(builder, report, cellID, metricID, run, baseDir)
	case "max":
		if len(run.Sources) != 1 {
			return errors.New("max metric requires one run resource source")
		}
		value, err := resourceSource(builder, cell, evidenceRun, run.Sources[0], metricID, baseDir)
		if err != nil {
			return err
		}
		observed, err := expandFloatRuns(run.Observations)
		if err != nil || len(observed) != 1 || !sameFloat(observed[0], value) {
			return errors.New("max observation is not derived from the bound run resource measurement")
		}
	case "duration_ms":
		if metricID == "cleanup_latency_ms" {
			if len(run.Sources) == 0 || run.DurationNanoseconds == nil {
				return errors.New("cleanup duration requires cleanup operation sources")
			}
			maximum := int64(0)
			for _, source := range run.Sources {
				if source.Kind != "samples" || source.Phase != "cleanup" || source.Field != "duration_ns" {
					return errors.New("cleanup duration must bind cleanup duration_ns samples")
				}
				record, err := operationSource(builder, cell, evidenceRun, source, baseDir)
				if err != nil {
					return err
				}
				values, err := expandIntRuns(record.DurationNS, record.OperationCount, true)
				if err != nil || len(values) != 1 {
					return errors.New("cleanup operation duration is invalid")
				}
				maximum = max(maximum, values[0])
			}
			if *run.DurationNanoseconds != maximum {
				return errors.New("cleanup duration is not derived from the bound cleanup operations")
			}
			break
		}
		if len(run.Sources) != 1 || run.DurationNanoseconds == nil {
			return errors.New("duration metric requires one run resource source")
		}
		value, err := resourceSource(builder, cell, evidenceRun, run.Sources[0], metricID+".nanoseconds", baseDir)
		if err != nil {
			return err
		}
		if !sameFloat(float64(*run.DurationNanoseconds), value) {
			return errors.New("duration is not derived from the bound run resource measurement")
		}
	default:
		return fmt.Errorf("unsupported metric derivation %q", derivation)
	}
	return nil
}

func requiresMetricFaultBinding(metricID string) bool {
	return strings.Contains(metricID, "outage_recovery") || strings.Contains(metricID, "migration_first_rpc")
}

type metricFaultEventContract struct {
	event            string
	recoveryEvent    string
	requireMigration bool
	requireFirstRPC  bool
}

func metricFaultContract(metricID string) (metricFaultEventContract, error) {
	switch {
	case strings.Contains(metricID, "migration_first_rpc"):
		return metricFaultEventContract{
			event: "path_updated", recoveryEvent: "path_validated", requireMigration: true, requireFirstRPC: true,
		}, nil
	case strings.Contains(metricID, "outage_recovery"):
		return metricFaultEventContract{event: "outage_started", recoveryEvent: "outage_recovered"}, nil
	default:
		return metricFaultEventContract{}, fmt.Errorf("%s has no frozen fault event contract", metricID)
	}
}

func validateMetricFaultBinding(builder *resultBuilder, manifest *PerformanceManifest, cellID string, cell *CellEvidence, run *RunEvidence, binding *MetricFaultBinding, durationNS *int64, metricID, baseDir string) error {
	contract, err := metricFaultContract(metricID)
	if err != nil {
		return err
	}
	if binding == nil || binding.Phase != "rpc" || !validSHA256(binding.TraceSHA256) || !validSHA256(binding.PCAPSHA256) ||
		strings.TrimSpace(binding.ProfileID) == "" || strings.TrimSpace(binding.Carrier) == "" || strings.TrimSpace(binding.ConnectionID) == "" || strings.TrimSpace(binding.RequestID) == "" ||
		strings.TrimSpace(binding.Event) == "" || strings.TrimSpace(binding.RecoveryEvent) == "" ||
		binding.StartAtNS < 0 || binding.RecoveryAtNS <= binding.StartAtNS || binding.FirstRPCAtNS <= binding.RecoveryAtNS || durationNS == nil || *durationNS <= 0 {
		return fmt.Errorf("%s requires a complete same-run fault binding", metricID)
	}
	if binding.Event != contract.event || binding.RecoveryEvent != contract.recoveryEvent {
		return fmt.Errorf("%s fault binding event contract must be %s -> %s", metricID, contract.event, contract.recoveryEvent)
	}
	var manifestCell *PerformanceCell
	for index := range manifest.Cells {
		if manifest.Cells[index].ID == cellID {
			manifestCell = &manifest.Cells[index]
			break
		}
	}
	if manifestCell == nil {
		return fmt.Errorf("%s fault binding references unknown cell %s", metricID, cellID)
	}
	wantCarrier, err := carrierForTopology(manifestCell.Topology)
	if err != nil {
		return err
	}
	var matrix *FaultMatrixContract
	for index := range manifest.FaultMatrix {
		candidate := &manifest.FaultMatrix[index]
		if candidate.ProfileID == manifestCell.ProfileID && candidate.Carrier == wantCarrier {
			matrix = candidate
			break
		}
	}
	if matrix == nil {
		return fmt.Errorf("%s has no fault matrix contract for %s/%s", metricID, manifestCell.ProfileID, wantCarrier)
	}
	if binding.ProfileID != matrix.ProfileID || binding.Carrier != matrix.Carrier ||
		binding.ReorderPercent != matrix.ReorderPercent || binding.DuplicatePercent != matrix.DuplicatePercent {
		return fmt.Errorf("%s fault binding does not match the frozen %s/%s fault matrix cell", metricID, matrix.ProfileID, matrix.Carrier)
	}
	matrixEnd := matrix.OutageStartNS + matrix.OutageDurationNS
	invalidSchedule := matrix.OutageDurationNS <= 0
	if contract.requireMigration {
		invalidSchedule = invalidSchedule || matrix.MigrationStartNS <= matrix.OutageStartNS || matrix.MigrationValidatedNS <= matrix.MigrationStartNS ||
			matrix.MigrationValidatedNS >= matrixEnd || binding.StartAtNS != matrix.MigrationStartNS || binding.RecoveryAtNS != matrix.MigrationValidatedNS
	} else {
		invalidSchedule = invalidSchedule || binding.StartAtNS != matrix.OutageStartNS || binding.RecoveryAtNS != matrixEnd
	}
	if invalidSchedule {
		return fmt.Errorf("%s fault binding does not match the frozen outage schedule", metricID)
	}
	var phase *PhaseEvidence
	for index := range run.Phases {
		if run.Phases[index].Phase == binding.Phase {
			phase = &run.Phases[index]
			break
		}
	}
	if phase == nil {
		return fmt.Errorf("%s fault binding phase %q is missing", metricID, binding.Phase)
	}
	traceRef, ok := phase.Artifacts["trace"]
	if !ok || traceRef.SHA256 != binding.TraceSHA256 {
		return fmt.Errorf("%s fault binding trace digest is not the same run rpc trace", metricID)
	}
	pcapRef, ok := phase.Artifacts["pcap"]
	if !ok || pcapRef.SHA256 != binding.PCAPSHA256 {
		return fmt.Errorf("%s fault binding pcap digest is not the same run rpc capture", metricID)
	}
	qlogRef, hasQlog := phase.Artifacts["qlog"]
	if contract.requireMigration && !hasQlog {
		return fmt.Errorf("%s migration fault binding requires a same-run rpc qlog", metricID)
	}
	if hasQlog {
		if !validSHA256(binding.QlogSHA256) || qlogRef.SHA256 != binding.QlogSHA256 {
			return fmt.Errorf("%s fault binding qlog digest is not the same run rpc qlog", metricID)
		}
	} else if binding.QlogSHA256 != "" {
		return fmt.Errorf("%s fault binding qlog digest is present without a same-run rpc qlog", metricID)
	}
	traceContext := fmt.Sprintf("cell %s run %d phase %s/%s", cell.CellID, run.RunNumber, phase.ProfileID, phase.Phase)
	traceData, ok := readArtifact(builder, traceContext, "trace", traceRef, baseDir)
	if !ok {
		return fmt.Errorf("%s fault trace artifact is invalid", metricID)
	}
	var trace TraceArtifact
	if err := decodeStrictJSON(traceData, &trace); err != nil || trace.Context != traceContext {
		return fmt.Errorf("%s fault trace context is invalid", metricID)
	}
	if err := validateMetricFaultTimeline(trace, traceContext, binding, durationNS, metricID, contract); err != nil {
		return err
	}
	if contract.requireMigration {
		qlogData, qlogOK := readArtifact(builder, traceContext, "qlog", qlogRef, baseDir)
		pcapData, pcapOK := readArtifact(builder, traceContext, "pcap", pcapRef, baseDir)
		if !qlogOK || !pcapOK {
			return fmt.Errorf("%s migration qlog or pcap artifact is invalid", metricID)
		}
		if err := validateMetricMigrationQlog(qlogData, binding); err != nil {
			return fmt.Errorf("%s migration qlog does not prove the validated-path first RPC identity and timestamp: %w", metricID, err)
		}
		if err := validateCorrelatedPathTransition(qlogData, pcapData, binding.ConnectionID); err != nil {
			return fmt.Errorf("%s migration qlog and pcap do not prove one correlated path transition: %w", metricID, err)
		}
	}
	return nil
}

func validateMetricFaultTimeline(trace TraceArtifact, traceContext string, binding *MetricFaultBinding, durationNS *int64, metricID string, contract metricFaultEventContract) error {
	startIndex, recoveryIndex, rpcIndex := -1, -1, -1
	startCount, recoveryCount, rpcCount := 0, 0, 0
	executionID := caseExecutionID(traceContext)
	for index, record := range trace.Records {
		if record.ConnectionID != binding.ConnectionID {
			continue
		}
		switch record.Event {
		case contract.event:
			startCount++
			if record.AtNS == binding.StartAtNS && record.Digest == executionID {
				startIndex = index
			}
		case contract.recoveryEvent:
			recoveryCount++
			if record.AtNS == binding.RecoveryAtNS && record.Digest == executionID {
				recoveryIndex = index
			}
		case "rpc_completed":
			if contract.requireFirstRPC && recoveryIndex >= 0 && index > recoveryIndex && rpcIndex < 0 {
				if record.MetricID != metricID {
					return fmt.Errorf("%s fault trace contains an earlier same-connection RPC after recovery", metricID)
				}
				if record.RequestID != binding.RequestID {
					return fmt.Errorf("%s fault trace RPC request identity differs from the binding", metricID)
				}
				rpcIndex = index
			}
			if record.MetricID == metricID {
				rpcCount++
				if !contract.requireFirstRPC {
					rpcIndex = index
				}
				if record.AtNS != binding.FirstRPCAtNS || record.RequestID != binding.RequestID || record.Digest != executionID {
					return fmt.Errorf("%s post-recovery RPC does not match its bound request identity, timestamp, and execution identity", metricID)
				}
			}
		}
	}
	if startCount != 1 || recoveryCount != 1 || rpcCount != 1 || startIndex < 0 || recoveryIndex <= startIndex || rpcIndex <= recoveryIndex ||
		binding.FirstRPCAtNS-binding.RecoveryAtNS != *durationNS {
		return fmt.Errorf("%s fault trace does not prove its frozen event order, post-recovery RPC, and first RPC duration", metricID)
	}
	return nil
}

func validateMetricMigrationQlog(data []byte, binding *MetricFaultBinding) error {
	var document struct {
		Traces []struct {
			Events []json.RawMessage `json:"events"`
		} `json:"traces"`
	}
	if err := decodeSingleJSON(data, &document); err != nil || len(document.Traces) != 1 {
		return errors.New("migration qlog is invalid")
	}
	required := []struct {
		name string
		atNS int64
	}{
		{name: "connectivity:path_updated", atNS: binding.StartAtNS},
		{name: "connectivity:path_validated", atNS: binding.RecoveryAtNS},
		{name: "application:rpc_completed", atNS: binding.FirstRPCAtNS},
	}
	position := 0
	counts := make(map[string]int, len(required))
	for _, raw := range document.Traces[0].Events {
		var fields []json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || len(fields) != 4 {
			return errors.New("migration qlog event is invalid")
		}
		var at float64
		var category, name string
		var eventData map[string]any
		if json.Unmarshal(fields[0], &at) != nil || json.Unmarshal(fields[1], &category) != nil ||
			json.Unmarshal(fields[2], &name) != nil || json.Unmarshal(fields[3], &eventData) != nil {
			return errors.New("migration qlog event fields are invalid")
		}
		qualified := category + ":" + name
		requiredIndex := slices.IndexFunc(required, func(candidate struct {
			name string
			atNS int64
		}) bool {
			return candidate.name == qualified
		})
		if requiredIndex < 0 {
			continue
		}
		counts[qualified]++
		if position >= len(required) || requiredIndex != position || at != float64(required[position].atNS) ||
			fmt.Sprint(eventData["connection_id"]) != binding.ConnectionID {
			return fmt.Errorf("migration qlog event %s is out of order or has a different time/connection", qualified)
		}
		if qualified == "application:rpc_completed" && fmt.Sprint(eventData["request_id"]) != binding.RequestID {
			return errors.New("migration qlog RPC request identity differs from the timed trace RPC")
		}
		position++
	}
	if position != len(required) {
		return fmt.Errorf("migration qlog contains %d of %d bound path/RPC events", position, len(required))
	}
	for _, event := range required {
		if counts[event.name] != 1 {
			return fmt.Errorf("migration qlog event %s appears %d times, want exactly once", event.name, counts[event.name])
		}
	}
	return nil
}

func carrierForTopology(topology string) (string, error) {
	switch topology {
	case "direct_wss", "ww", "wq", "direct_wss_revision":
		return "wss", nil
	case "direct_quic", "qq", "qw":
		return "raw_quic", nil
	case "browser_webtransport", "browser_tunnel_wt_wss", "browser_tunnel_wt_quic":
		return "webtransport", nil
	case "adaptive_native":
		return "raw_quic", nil
	case "adaptive_web":
		return "webtransport", nil
	default:
		return "", fmt.Errorf("unknown performance topology %q for fault matrix binding", topology)
	}
}

func metricEvidenceRun(report *EvidenceReport, cellID string, runNumber int) (*CellEvidence, *RunEvidence, error) {
	for cellIndex := range report.Cells {
		cell := &report.Cells[cellIndex]
		if cell.CellID != cellID {
			continue
		}
		for runIndex := range cell.Runs {
			if cell.Runs[runIndex].RunNumber == runNumber {
				return cell, &cell.Runs[runIndex], nil
			}
		}
		return nil, nil, fmt.Errorf("cell %s has no run %d", cellID, runNumber)
	}
	return nil, nil, fmt.Errorf("unknown cell %s", cellID)
}

func operationSource(builder *resultBuilder, cell *CellEvidence, run *RunEvidence, source MetricSourceRef, baseDir string) (OperationSeriesRecord, error) {
	phase, context, err := metricSourcePhase(cell.CellID, run, source)
	if err != nil {
		return OperationSeriesRecord{}, err
	}
	artifact, exists := phase.Artifacts["samples"]
	if !exists || artifact.SHA256 != source.ArtifactSHA256 {
		return OperationSeriesRecord{}, errors.New("operation source digest does not match the exact phase artifact")
	}
	data, ok := readArtifact(builder, context, "samples", artifact, baseDir)
	if !ok {
		return OperationSeriesRecord{}, errors.New("operation source artifact is invalid")
	}
	var envelope OperationSeriesArtifact
	if err := decodeStrictJSON(data, &envelope); err != nil || len(envelope.Records) != 1 {
		return OperationSeriesRecord{}, errors.New("operation source is not one typed series")
	}
	return envelope.Records[0], nil
}

func metricSourcePhase(cellID string, run *RunEvidence, source MetricSourceRef) (*PhaseEvidence, string, error) {
	if source.VariantID == "" {
		if len(run.Variants) != 0 {
			return nil, "", errors.New("variant cell source omits variant_id")
		}
		for index := range run.Phases {
			phase := &run.Phases[index]
			if phase.ProfileID == source.ProfileID && phase.Phase == source.Phase {
				return phase, fmt.Sprintf("cell %s run %d phase %s/%s", cellID, run.RunNumber, source.ProfileID, source.Phase), nil
			}
		}
	} else {
		for variantIndex := range run.Variants {
			variant := &run.Variants[variantIndex]
			if variant.ID != source.VariantID {
				continue
			}
			for phaseIndex := range variant.Phases {
				phase := &variant.Phases[phaseIndex]
				if phase.ProfileID == source.ProfileID && phase.Phase == source.Phase {
					return phase, fmt.Sprintf("cell %s run %d variant %s phase %s/%s", cellID, run.RunNumber, source.VariantID, source.ProfileID, source.Phase), nil
				}
			}
		}
	}
	return nil, "", fmt.Errorf("%w: source profile/phase is not present in the exact run scope", errMetricSourceMissing)
}

func resourceSource(builder *resultBuilder, cell *CellEvidence, run *RunEvidence, source MetricSourceRef, field, baseDir string) (float64, error) {
	if source.Kind != "resource" || source.Field != field || source.CellID != cell.CellID || source.RunNumber != run.RunNumber ||
		run.Resource.SHA256 != source.ArtifactSHA256 {
		return 0, fmt.Errorf("resource source does not bind exact field %s", field)
	}
	context := fmt.Sprintf("cell %s run %d resource", cell.CellID, run.RunNumber)
	data, ok := readArtifact(builder, context, "resource", run.Resource, baseDir)
	if !ok {
		return 0, errors.New("run resource artifact is invalid")
	}
	var artifact ResourceArtifact
	if err := decodeStrictJSON(data, &artifact); err != nil {
		return 0, err
	}
	found := false
	value := 0.0
	for _, measurement := range artifact.Measurements {
		if measurement.Name != field || measurement.VariantID != source.VariantID ||
			measurement.ProfileID != source.ProfileID || measurement.Phase != source.Phase {
			continue
		}
		if found {
			return 0, fmt.Errorf("duplicate run resource field %s", field)
		}
		found, value = true, measurement.Value
	}
	if !found {
		return 0, fmt.Errorf("run resource field %s is missing", field)
	}
	return value, nil
}

func sameFloatValues(left, right []float64) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if math.IsNaN(left[index]) || math.IsNaN(right[index]) || !sameFloat(left[index], right[index]) {
			return false
		}
	}
	return true
}
