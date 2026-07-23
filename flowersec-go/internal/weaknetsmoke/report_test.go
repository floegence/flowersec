package weaknetsmoke

import (
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/weaknet"
)

func TestCounterEvidenceValidatesExactCountersAndRelations(t *testing.T) {
	evidence := counterEvidence{
		ExpectedExact: []exactCounterExpectation{{Counter: "duplicate_units", Value: 1}},
		ExpectedRelations: []relationExpectation{
			{Left: "delay_units", Operator: "eq", Right: "input_units"},
			{Left: "input_bytes", Operator: "eq", Right: "output_bytes"},
		},
		Actual: weaknet.Counters{
			InputUnits: 2, InputBytes: 128, OutputUnits: 2, OutputBytes: 128,
			DelayUnits: 2, DuplicateUnits: 1,
		},
	}
	if err := validateCounterEvidence(evidence); err != nil {
		t.Fatalf("valid counter evidence: %v", err)
	}

	evidence.Actual.DuplicateUnits = 0
	if err := validateCounterEvidence(evidence); err == nil || !strings.Contains(err.Error(), "duplicate_units") {
		t.Fatalf("exact mismatch error = %v", err)
	}
}

func TestWSSDelayAndJitterRelateToInputWritesNotOutputDeliveries(t *testing.T) {
	actual := weaknet.Counters{
		InputUnits: 2, InputBytes: 128, OutputUnits: 3, OutputBytes: 128,
		DelayUnits: 2, JitterUnits: 2, HalfCloses: 1,
	}
	valid := counterEvidence{
		ExpectedRelations: []relationExpectation{
			{Left: "delay_units", Operator: "eq", Right: "input_units"},
			{Left: "jitter_units", Operator: "eq", Right: "input_units"},
			{Left: "input_bytes", Operator: "eq", Right: "output_bytes"},
		},
		Actual: actual,
	}
	if err := validateCounterEvidence(valid); err != nil {
		t.Fatalf("valid WSS relation: %v", err)
	}

	invalid := valid
	invalid.ExpectedRelations = []relationExpectation{{Left: "delay_units", Operator: "eq", Right: "output_units"}}
	if err := validateCounterEvidence(invalid); err == nil || !strings.Contains(err.Error(), "delay_units") {
		t.Fatalf("false WSS relation error = %v", err)
	}
}

func TestCounterEvidenceRejectsUnknownCounterAndOperator(t *testing.T) {
	tests := []counterEvidence{
		{ExpectedExact: []exactCounterExpectation{{Counter: "invented", Value: 0}}},
		{ExpectedRelations: []relationExpectation{{Left: "input_units", Operator: "gte", Right: "output_units"}}},
	}
	for _, evidence := range tests {
		if err := validateCounterEvidence(evidence); err == nil {
			t.Fatalf("validateCounterEvidence(%+v) succeeded", evidence)
		}
	}
}

func TestSmokeReportRejectsCaseTamperingAfterHash(t *testing.T) {
	result := finalizeCase(smokeCase{
		Profile: "profile", Carrier: "wss", Classification: "local_smoke", Status: "pass",
		Assertions: []string{"original"},
		Counters: []counterEvidence{{
			ExpectedRelations: []relationExpectation{{Left: "input_bytes", Operator: "eq", Right: "output_bytes"}},
			Actual:            weaknet.Counters{InputBytes: 1, OutputBytes: 1},
		}},
	})
	report := smokeReport{SchemaVersion: 1, Classification: "local_smoke", Cases: []smokeCase{result}}
	if err := validateSmokeReport(report); err != nil {
		t.Fatalf("valid hashed report: %v", err)
	}
	report.Cases[0].Assertions[0] = "tampered"
	if err := validateSmokeReport(report); err == nil || !strings.Contains(err.Error(), "evidence_sha256") {
		t.Fatalf("tampered case error = %v", err)
	}
}
