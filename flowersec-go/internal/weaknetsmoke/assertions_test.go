package weaknetsmoke

import (
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/weaknet"
)

func TestCounterAssertionsValidateExactCountersAndRelations(t *testing.T) {
	assertion := counterAssertion{
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
	if err := validateCounterAssertion(assertion); err != nil {
		t.Fatalf("valid counter assertion: %v", err)
	}

	assertion.Actual.DuplicateUnits = 0
	if err := validateCounterAssertion(assertion); err == nil || !strings.Contains(err.Error(), "duplicate_units") {
		t.Fatalf("exact mismatch error = %v", err)
	}
}

func TestWSSDelayAndJitterRelateToInputWritesNotOutputDeliveries(t *testing.T) {
	actual := weaknet.Counters{
		InputUnits: 2, InputBytes: 128, OutputUnits: 3, OutputBytes: 128,
		DelayUnits: 2, JitterUnits: 2, HalfCloses: 1,
	}
	valid := counterAssertion{
		ExpectedRelations: []relationExpectation{
			{Left: "delay_units", Operator: "eq", Right: "input_units"},
			{Left: "jitter_units", Operator: "eq", Right: "input_units"},
			{Left: "input_bytes", Operator: "eq", Right: "output_bytes"},
		},
		Actual: actual,
	}
	if err := validateCounterAssertion(valid); err != nil {
		t.Fatalf("valid WSS relation: %v", err)
	}

	invalid := valid
	invalid.ExpectedRelations = []relationExpectation{{Left: "delay_units", Operator: "eq", Right: "output_units"}}
	if err := validateCounterAssertion(invalid); err == nil || !strings.Contains(err.Error(), "delay_units") {
		t.Fatalf("false WSS relation error = %v", err)
	}
}

func TestCounterAssertionsRejectUnknownCounterAndOperator(t *testing.T) {
	tests := []counterAssertion{
		{ExpectedExact: []exactCounterExpectation{{Counter: "invented", Value: 0}}},
		{ExpectedRelations: []relationExpectation{{Left: "input_units", Operator: "gte", Right: "output_units"}}},
	}
	for _, assertion := range tests {
		if err := validateCounterAssertion(assertion); err == nil {
			t.Fatalf("validateCounterAssertion(%+v) succeeded", assertion)
		}
	}
}

func TestSmokeCaseRequiresBehaviorAssertions(t *testing.T) {
	result := smokeCase{Profile: "local-v1", Carrier: "wss"}
	if err := validateSmokeCase(result); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete smoke case error = %v", err)
	}
}
