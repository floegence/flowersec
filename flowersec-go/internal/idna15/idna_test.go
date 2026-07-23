package idna15_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/idna15"
)

func TestLookupASCIIUsesFrozenUnicode15_1UTS46(t *testing.T) {
	fixture := loadFixture(t)
	if fixture.UnicodeVersion != idna15.UnicodeVersion {
		t.Fatalf("fixture Unicode version = %q", fixture.UnicodeVersion)
	}
	for _, test := range fixture.Positive {
		t.Run(test.ID, func(t *testing.T) {
			got, err := idna15.LookupASCII(test.Input)
			if err != nil {
				t.Fatalf("LookupASCII: %v", err)
			}
			if got != test.ASCII {
				t.Fatalf("LookupASCII = %q, want %q", got, test.ASCII)
			}
		})
	}
}

func TestLookupASCIIRejectsInvalidUTS46Hosts(t *testing.T) {
	for _, test := range loadFixture(t).Negative {
		t.Run(test.ID, func(t *testing.T) {
			if _, err := idna15.LookupASCII(test.Input); err == nil {
				t.Fatal("invalid host was accepted")
			}
		})
	}
}

type fixture struct {
	UnicodeVersion string `json:"unicode_version"`
	Positive       []struct {
		ID    string `json:"id"`
		Input string `json:"input"`
		ASCII string `json:"ascii"`
	} `json:"positive"`
	Negative []struct {
		ID    string `json:"id"`
		Input string `json:"input"`
	} `json:"negative"`
}

func loadFixture(t *testing.T) fixture {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/transport_v2/idna_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var decoded fixture
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}
