package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	formulaDirect     = "numerator/denominator"
	formulaNormalized = "(numerator_value/numerator_bytes)/(denominator_value/denominator_bytes)"
)

type ratioOperandContract struct {
	name      string
	reduction string
	cellID    string
	variantID string
	profileID string
	phase     string
	kind      string
	field     string
}

type ratioContract struct {
	formula  string
	operands []ratioOperandContract
}

func ratioFormulaContract(cellID, metricID string) (ratioContract, error) {
	resource := func(name, sourceCell, variant, profile, phase, field string) ratioOperandContract {
		return ratioOperandContract{name: name, reduction: "value", cellID: sourceCell, variantID: variant,
			profileID: profile, phase: phase, kind: "resource", field: field}
	}
	samples := func(name, sourceCell, variant, profile, phase, reduction, field string) ratioOperandContract {
		return ratioOperandContract{name: name, reduction: reduction, cellID: sourceCell, variantID: variant,
			profileID: profile, phase: phase, kind: "samples", field: field}
	}
	direct := func(numerator, denominator ratioOperandContract) ratioContract {
		return ratioContract{formula: formulaDirect, operands: []ratioOperandContract{numerator, denominator}}
	}
	normalized := func(numeratorValue, numeratorBytes, denominatorValue, denominatorBytes ratioOperandContract) ratioContract {
		return ratioContract{formula: formulaNormalized,
			operands: []ratioOperandContract{numeratorValue, numeratorBytes, denominatorValue, denominatorBytes}}
	}

	switch metricID {
	case "cpu_ns_per_delivered_byte":
		if cellID == "clean-01" {
			return direct(
				resource("numerator", cellID, "candidate", "clean-v1", "bulk", "variant.candidate.cpu_nanoseconds"),
				resource("denominator", cellID, "candidate", "clean-v1", "bulk", "variant.candidate.delivered_bytes")), nil
		}
		return direct(resource("numerator", cellID, "", "", "", "cpu_nanoseconds"),
			resource("denominator", cellID, "", "", "", "delivered_bytes")), nil
	case "retransmit_amplification_ratio", "mobile_retransmit_amplification_ratio", "edge_retransmit_amplification_ratio":
		if cellID == "clean-01" {
			return direct(
				resource("numerator", cellID, "candidate", "clean-v1", "bulk", "variant.candidate.retransmitted_bytes"),
				resource("denominator", cellID, "candidate", "clean-v1", "bulk", "variant.candidate.delivered_bytes")), nil
		}
		return direct(resource("numerator", cellID, "", "", "", "retransmitted_bytes"),
			resource("denominator", cellID, "", "", "", "delivered_bytes")), nil
	case "clean_revision_cpu_per_byte_ratio":
		return normalized(
			resource("numerator_value", cellID, "candidate", "clean-v1", "bulk", "variant.candidate.cpu_nanoseconds"),
			resource("numerator_bytes", cellID, "candidate", "clean-v1", "bulk", "variant.candidate.delivered_bytes"),
			resource("denominator_value", cellID, "base", "clean-v1", "bulk", "variant.base.cpu_nanoseconds"),
			resource("denominator_bytes", cellID, "base", "clean-v1", "bulk", "variant.base.delivered_bytes")), nil
	case "clean_revision_cold_p95_ratio", "clean_revision_cold_p99_ratio":
		reduction := "p95"
		if strings.Contains(metricID, "p99") {
			reduction = "p99"
		}
		return direct(
			samples("numerator", cellID, "candidate", "clean-v1", "cold", reduction, "duration_ns"),
			samples("denominator", cellID, "base", "clean-v1", "cold", reduction, "duration_ns")), nil
	case "clean_revision_rpc_p99_ratio":
		return direct(
			samples("numerator", cellID, "candidate", "clean-v1", "rpc", "p99", "duration_ns"),
			samples("denominator", cellID, "base", "clean-v1", "rpc", "p99", "duration_ns")), nil
	case "clean_revision_throughput_ratio":
		return direct(
			samples("numerator", cellID, "candidate", "clean-v1", "bulk", "goodput_mbps", "score_goodput"),
			samples("denominator", cellID, "base", "clean-v1", "bulk", "goodput_mbps", "score_goodput")), nil
	case "clean_quic_cpu_per_byte_ratio":
		return normalized(
			resource("numerator_value", cellID, "", "", "", "cpu_nanoseconds"),
			resource("numerator_bytes", cellID, "", "", "", "delivered_bytes"),
			resource("denominator_value", "clean-02", "", "", "", "cpu_nanoseconds"),
			resource("denominator_bytes", "clean-02", "", "", "", "delivered_bytes")), nil
	case "clean_quic_bulk_throughput_ratio":
		return direct(
			samples("numerator", cellID, "", "clean-v1", "bulk", "goodput_mbps", "score_goodput"),
			samples("denominator", "clean-02", "", "clean-v1", "bulk", "goodput_mbps", "score_goodput")), nil
	case "clean_quic_cold_p95_ratio", "clean_quic_cold_p99_ratio":
		reduction := "p95"
		if strings.Contains(metricID, "p99") {
			reduction = "p99"
		}
		return direct(
			samples("numerator", cellID, "", "clean-v1", "cold", reduction, "duration_ns"),
			samples("denominator", "clean-02", "", "clean-v1", "cold", reduction, "duration_ns")), nil
	case "clean_quic_rpc_p99_ratio":
		return direct(
			samples("numerator", cellID, "", "clean-v1", "rpc", "p99", "duration_ns"),
			 samples("denominator", "clean-02", "", "clean-v1", "rpc", "p99", "duration_ns")), nil
	case "clean_webtransport_cold_p99_ratio":
		return direct(
			samples("numerator", cellID, "", "clean-v1", "cold", "p99", "duration_ns"),
			samples("denominator", "clean-02", "", "clean-v1", "cold", "p99", "duration_ns")), nil
	case "clean_webtransport_rpc_p99_ratio":
		return direct(
			samples("numerator", cellID, "", "clean-v1", "rpc", "p99", "duration_ns"),
			samples("denominator", "clean-02", "", "clean-v1", "rpc", "p99", "duration_ns")), nil
	case "clean_webtransport_throughput_ratio":
		return direct(
			samples("numerator", cellID, "", "clean-v1", "bulk", "goodput_mbps", "score_goodput"),
			samples("denominator", "clean-02", "", "clean-v1", "bulk", "goodput_mbps", "score_goodput")), nil
	case "mobile_cpu_per_delivered_byte_vs_clean_ratio", "edge_cpu_per_delivered_byte_vs_clean_ratio":
		baseline, err := cleanBaselineCell(cellID)
		if err != nil {
			return ratioContract{}, err
		}
		return normalized(
			resource("numerator_value", cellID, "", "", "", "cpu_nanoseconds"),
			resource("numerator_bytes", cellID, "", "", "", "delivered_bytes"),
			resource("denominator_value", baseline, "", "", "", "cpu_nanoseconds"),
			resource("denominator_bytes", baseline, "", "", "", "delivered_bytes")), nil
	case "mobile_native_interactive_vs_idle_ratio":
		return direct(
			resource("numerator", "mobile-02", "", "mobile-v1", "rpc", "interactive.rpc_p99_milliseconds"),
			resource("denominator", "mobile-02", "", "mobile-v1", "rpc", "idle.rpc_p99_milliseconds")), nil
	case "adaptive_cold_formula_ratio", "adaptive_web_cold_formula_ratio":
		return direct(
			samples("numerator", cellID, "", "mobile-v1", "cold", "p95", "duration_ns"),
			samples("denominator", cellID, "", "clean-v1", "cold", "p95", "duration_ns")), nil
	case "adaptive_cpu_connect_formula_ratio":
		return direct(
			resource("numerator", cellID, "", "mobile-v1", "cold", "profile.mobile-v1.cpu_connect_nanoseconds"),
			resource("denominator", cellID, "", "clean-v1", "cold", "profile.clean-v1.cpu_connect_nanoseconds")), nil
	default:
		return ratioContract{}, fmt.Errorf("ratio metric %s has no frozen formula graph", metricID)
	}
}

func cleanBaselineCell(cellID string) (string, error) {
	suffixes := map[string]string{"01": "clean-02", "02": "clean-03", "03": "clean-04", "04": "clean-05", "05": "clean-06", "06": "clean-07"}
	for suffix, baseline := range suffixes {
		if strings.HasSuffix(cellID, "-"+suffix) && (strings.HasPrefix(cellID, "mobile-") || strings.HasPrefix(cellID, "edge-")) {
			return baseline, nil
		}
	}
	return "", fmt.Errorf("cell %s has no clean topology baseline", cellID)
}

func validateRatioFormula(builder *resultBuilder, report *EvidenceReport, cellID, metricID string, run MetricRunSample, baseDir string) error {
	contract, err := ratioFormulaContract(cellID, metricID)
	if err != nil {
		return err
	}
	if run.Formula != contract.formula || len(run.OperandGraph) != len(contract.operands) || len(run.Sources) != 0 {
		return errors.New("ratio formula or operand graph shape differs from the frozen contract")
	}
	values := make([]float64, len(contract.operands))
	for index, want := range contract.operands {
		got := run.OperandGraph[index]
		if got.Name != want.name || got.Reduction != want.reduction || got.Source.CellID != want.cellID ||
			got.Source.RunNumber != run.RunNumber || got.Source.VariantID != want.variantID ||
			got.Source.ProfileID != want.profileID || got.Source.Phase != want.phase ||
			got.Source.Kind != want.kind || got.Source.Field != want.field || !validSHA256(got.Source.ArtifactSHA256) {
			return fmt.Errorf("ratio operand %d does not match its frozen cell/run/variant/profile/phase/kind/field binding", index)
		}
		sourceCell, sourceRun, err := metricEvidenceRun(report, got.Source.CellID, got.Source.RunNumber)
		if err != nil {
			return err
		}
		if err := validateMetricSourceScope(sourceRun, got.Source); err != nil {
			return err
		}
		switch got.Source.Kind {
		case "resource":
			values[index], err = resourceSource(builder, sourceCell, sourceRun, got.Source, got.Source.Field, baseDir)
		case "samples":
			var record OperationSeriesRecord
			record, err = operationSource(builder, sourceCell, sourceRun, got.Source, baseDir)
			if err == nil {
				values[index], err = reduceOperationOperand(record, got.Reduction)
			}
		default:
			err = fmt.Errorf("unsupported ratio operand kind %q", got.Source.Kind)
		}
		if err != nil {
			return err
		}
	}
	var numerator, denominator float64
	switch contract.formula {
	case formulaDirect:
		numerator, denominator = values[0], values[1]
	case formulaNormalized:
		if values[1] <= 0 || values[3] <= 0 {
			return errors.New("normalized ratio byte operands must be positive")
		}
		numerator, denominator = values[0]/values[1], values[2]/values[3]
	default:
		return errors.New("unknown frozen ratio formula")
	}
	if denominator <= 0 || run.Numerator == nil || run.Denominator == nil ||
		!sameFloat(*run.Numerator, numerator) || !sameFloat(*run.Denominator, denominator) {
		return errors.New("ratio inputs are not recomputed from the frozen operand graph")
	}
	return nil
}

func ratioOperandGraph(report *EvidenceReport, cellID, metricID string, runNumber int) (string, []MetricOperand, error) {
	contract, err := ratioFormulaContract(cellID, metricID)
	if err != nil {
		return "", nil, err
	}
	operands := make([]MetricOperand, len(contract.operands))
	for index, operand := range contract.operands {
		_, run, err := metricEvidenceRun(report, operand.cellID, runNumber)
		if err != nil {
			return "", nil, err
		}
		source := MetricSourceRef{
			CellID: operand.cellID, RunNumber: runNumber, VariantID: operand.variantID,
			ProfileID: operand.profileID, Phase: operand.phase, Kind: operand.kind, Field: operand.field,
		}
		switch operand.kind {
		case "resource":
			source.ArtifactSHA256 = run.Resource.SHA256
		case "samples":
			phase, _, err := metricSourcePhase(operand.cellID, run, source)
			if err != nil {
				return "", nil, err
			}
			source.ArtifactSHA256 = phase.Artifacts["samples"].SHA256
		default:
			return "", nil, fmt.Errorf("unsupported operand kind %q", operand.kind)
		}
		operands[index] = MetricOperand{Name: operand.name, Reduction: operand.reduction, Source: source}
	}
	return contract.formula, operands, nil
}

func validateMetricSourceScope(run *RunEvidence, source MetricSourceRef) error {
	phases := run.Phases
	if source.VariantID != "" {
		index := slices.IndexFunc(run.Variants, func(variant VariantEvidence) bool { return variant.ID == source.VariantID })
		if index < 0 {
			return fmt.Errorf("%w: source variant %s is not present in the exact run", errMetricSourceMissing, source.VariantID)
		}
		phases = run.Variants[index].Phases
	} else if len(run.Variants) != 0 {
		return errors.New("source omits variant_id for a variant run")
	}
	if source.ProfileID == "" && source.Phase == "" {
		return nil
	}
	if source.ProfileID == "" || source.Phase == "" || !slices.ContainsFunc(phases, func(phase PhaseEvidence) bool {
		return phase.ProfileID == source.ProfileID && phase.Phase == source.Phase
	}) {
		return fmt.Errorf("%w: source profile/phase is not present in the exact run scope", errMetricSourceMissing)
	}
	return nil
}

func reduceOperationOperand(record OperationSeriesRecord, reduction string) (float64, error) {
	switch reduction {
	case "p95", "p99":
		values, err := expandIntRuns(record.DurationNS, record.OperationCount, true)
		if err != nil || len(values) == 0 {
			return 0, errors.New("duration operand series is invalid")
		}
		slices.Sort(values)
		probability := 0.95
		if reduction == "p99" {
			probability = 0.99
		}
		floatValues := make([]float64, len(values))
		for index, value := range values {
			floatValues[index] = float64(value) / 1e6
		}
		return quantile(floatValues, probability), nil
	case "goodput_mbps":
		scored, err := expandIntRuns(record.ScoredBytes, record.OperationCount, true)
		if err != nil || len(scored) == 0 {
			return 0, errors.New("goodput byte operand series is invalid")
		}
		durations, err := expandIntRuns(record.ScoreDurationNS, record.OperationCount, true)
		if err != nil || len(durations) != len(scored) {
			return 0, errors.New("goodput duration operand series is invalid")
		}
		return float64(slices.Min(scored)) * 8 * 1e3 / float64(slices.Max(durations)), nil
	default:
		return 0, fmt.Errorf("unsupported operation operand reduction %q", reduction)
	}
}
