package main

import (
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
)

func TestWeaknetSystemCasesFreezeEightRealLinuxPlans(t *testing.T) {
	if len(weaknetSystemCases) != 8 {
		t.Fatalf("system case count = %d", len(weaknetSystemCases))
	}
	if err := validateReleaseCaseDefinitions(weaknetSystemCases); err != nil {
		t.Fatal(err)
	}
	for _, definition := range weaknetSystemCases {
		plan, err := planWeaknetSystemCase(definition)
		if err != nil {
			t.Fatalf("%s: %v", definition.ID, err)
		}
		if plan.InitialMTU < plan.ConstrainedMTU || plan.ConstrainedMTU != 1280 {
			t.Fatalf("%s plan = %+v", definition.ID, plan)
		}
		if plan.RequireTCPInfo != (definition.Carrier == carrier.KindWebSocket) {
			t.Fatalf("%s TCP_INFO plan = %+v", definition.ID, plan)
		}
	}
}
