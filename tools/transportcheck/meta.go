package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
)

func loadEvidenceMetaSchema(path string) (*EvidenceMetaSchema, error) {
	var schema EvidenceMetaSchema
	if err := decodeStrictFile(path, &schema); err != nil {
		return nil, err
	}
	return &schema, nil
}

func validateEvidenceMetaSchema(schema *EvidenceMetaSchema) error {
	if schema == nil {
		return errors.New("evidence meta-schema is nil")
	}
	if schema.SchemaVersion != 1 || schema.SignedClassification != "signed_transport_evidence" {
		return errors.New("evidence meta-schema must freeze schema v1 signed_transport_evidence")
	}
	if !slices.Equal(schema.TDDStages, []string{"red", "green", "refactor"}) {
		return errors.New("evidence meta-schema must require red, green, and refactor in order")
	}
	wanted := map[string]EvidenceGateContract{
		"transport-v2-unit":           {Target: "transport-v2-unit", AllowedClassifications: []string{"contract_only"}},
		"transport-conformance-smoke": {Target: "transport-conformance-smoke", AllowedClassifications: []string{"local_smoke"}},
		"transport-browser-smoke":     {Target: "transport-browser-smoke", AllowedClassifications: []string{"local_smoke"}},
		"transport-interop-smoke":     {Target: "transport-interop-smoke", AllowedClassifications: []string{"local_smoke"}},
		"weaknet-smoke":               {Target: "weaknet-smoke", AllowedClassifications: []string{"local_smoke"}, ReportRequired: true},
		"quic-native-smoke":           {Target: "quic-native-smoke", AllowedClassifications: []string{"local_smoke"}},
		"quic-native-race-smoke":      {Target: "quic-native-race-smoke", AllowedClassifications: []string{"local_smoke"}},
	}
	if len(schema.Gates) != len(wanted) {
		return fmt.Errorf("evidence meta-schema contains %d gates, want %d", len(schema.Gates), len(wanted))
	}
	seen := make(map[string]struct{}, len(schema.Gates))
	for _, gate := range schema.Gates {
		if _, duplicate := seen[gate.Target]; duplicate {
			return fmt.Errorf("duplicate evidence gate %q", gate.Target)
		}
		seen[gate.Target] = struct{}{}
		expected, exists := wanted[gate.Target]
		if !exists || !slices.Equal(gate.AllowedClassifications, expected.AllowedClassifications) || gate.ReportRequired != expected.ReportRequired {
			return fmt.Errorf("evidence gate %q does not match its frozen classification contract", gate.Target)
		}
	}
	return nil
}

func validateGateDeclaration(schema *EvidenceMetaSchema, target, classification string) error {
	if err := validateEvidenceMetaSchema(schema); err != nil {
		return err
	}
	for _, gate := range schema.Gates {
		if gate.Target != target {
			continue
		}
		if !slices.Contains(gate.AllowedClassifications, classification) {
			return fmt.Errorf("gate %s does not permit classification %s", target, classification)
		}
		return nil
	}
	return fmt.Errorf("unknown evidence gate target %q", target)
}

func validateGateReport(schema *EvidenceMetaSchema, target, classification, reportPath string) error {
	if err := validateGateDeclaration(schema, target, classification); err != nil {
		return err
	}
	var contract *EvidenceGateContract
	for index := range schema.Gates {
		if schema.Gates[index].Target == target {
			contract = &schema.Gates[index]
			break
		}
	}
	if contract.ReportRequired && strings.TrimSpace(reportPath) == "" {
		return fmt.Errorf("gate %s requires a report", target)
	}
	if strings.TrimSpace(reportPath) == "" {
		return nil
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return err
	}
	var envelope struct {
		SchemaVersion  int    `json:"schema_version"`
		Classification string `json:"classification"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("decode gate report: %w", err)
	}
	if envelope.SchemaVersion != 1 || envelope.Classification != classification {
		return fmt.Errorf("gate report classification = %q schema_version = %d, want %q schema v1", envelope.Classification, envelope.SchemaVersion, classification)
	}
	return nil
}
