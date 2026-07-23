package origin_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v2/origin"
)

func TestPolicyV2ExactAndSingleLabelWildcard(t *testing.T) {
	policy, err := origin.NewPolicyV2(origin.PolicyV2Options{
		Rules: []string{
			"https://app.example.com",
			"https://*.cn.example.com:8443",
			"https://[2001:db8::1]:8443",
		},
	})
	if err != nil {
		t.Fatalf("NewPolicyV2: %v", err)
	}
	tests := []struct {
		value string
		want  bool
	}{
		{value: "https://app.example.com", want: true},
		{value: "https://APP.EXAMPLE.COM:443", want: true},
		{value: "https://a.cn.example.com:8443", want: true},
		{value: "https://a.b.cn.example.com:8443", want: false},
		{value: "https://cn.example.com:8443", want: false},
		{value: "https://a.cn.example.com", want: false},
		{value: "https://[2001:0db8:0:0::1]:8443", want: true},
		{value: "http://app.example.com", want: false},
		{value: "null", want: false},
		{value: "", want: false},
	}
	for _, tt := range tests {
		if got := policy.Allows(tt.value); got != tt.want {
			t.Errorf("Allows(%q) = %v, want %v", tt.value, got, tt.want)
		}
	}
}

func TestPolicyV2NormalizesUnicode15_1AndALabels(t *testing.T) {
	policy, err := origin.NewPolicyV2(origin.PolicyV2Options{Rules: []string{
		"https://b\u00fccher.example",
		"https://*.fa\u00df.example",
		"https://\U0002ebf0.example",
	}})
	if err != nil {
		t.Fatalf("NewPolicyV2: %v", err)
	}
	for _, value := range []string{
		"https://xn--bcher-kva.example",
		"https://shop.xn--fa-hia.example",
		"https://xn--8g0n.example",
	} {
		if !policy.Allows(value) {
			t.Errorf("Allows(%q) = false", value)
		}
	}
	if _, err := origin.NewPolicyV2(origin.PolicyV2Options{Rules: []string{
		"https://b\u00fccher.example", "https://xn--bcher-kva.example",
	}}); !errors.Is(err, origin.ErrDuplicatePolicyV2Rule) {
		t.Fatalf("U-label/A-label duplicate error = %v", err)
	}
}

func TestPolicyV2RejectsDuplicateOrCommaJoinedOriginHeaders(t *testing.T) {
	policy, err := origin.NewPolicyV2(origin.PolicyV2Options{Rules: []string{"https://app.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, values := range [][]string{
		{"https://app.example.com", "https://evil.example.com"},
		{"https://app.example.com, https://evil.example.com"},
	} {
		request := &http.Request{Header: make(http.Header)}
		for _, value := range values {
			request.Header.Add("Origin", value)
		}
		if policy.CheckRequest(request) {
			t.Fatalf("duplicate/spoofed Origin was accepted: %#v", values)
		}
	}
}

func TestPolicyV2MissingOriginRequiresExplicitNativeOptIn(t *testing.T) {
	strict, err := origin.NewPolicyV2(origin.PolicyV2Options{Rules: []string{"https://app.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if strict.Allows("") {
		t.Fatal("missing Origin was allowed by default")
	}
	native, err := origin.NewPolicyV2(origin.PolicyV2Options{
		Rules: []string{"https://app.example.com"}, AllowMissingForNativeClients: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !native.Allows("") {
		t.Fatal("explicit native missing-Origin policy was not honored")
	}
}

func TestPolicyV2RejectsUnsafeRuleGrammar(t *testing.T) {
	invalid := []string{
		"http://app.example.com",
		"https://*",
		"https://*.com",
		"https://*.co.uk",
		"https://*.*.example.com",
		"https://a.*.example.com",
		"https://example.com/path",
		"https://example.com?query=1",
		"https://example.com#fragment",
		"https://user@example.com",
		"https://example.com.",
		"https://exa_mple.com",
		"null",
	}
	for _, rule := range invalid {
		if _, err := origin.NewPolicyV2(origin.PolicyV2Options{Rules: []string{rule}}); !errors.Is(err, origin.ErrInvalidPolicyV2) {
			t.Errorf("NewPolicyV2(%q) error = %v", rule, err)
		}
	}
}

func TestPolicyV2RejectsDuplicateCanonicalRulesAndEmptyPolicy(t *testing.T) {
	if _, err := origin.NewPolicyV2(origin.PolicyV2Options{}); !errors.Is(err, origin.ErrInvalidPolicyV2) {
		t.Fatalf("empty policy error = %v", err)
	}
	if _, err := origin.NewPolicyV2(origin.PolicyV2Options{Rules: []string{
		"https://app.example.com", "https://APP.EXAMPLE.COM:443",
	}}); !errors.Is(err, origin.ErrDuplicatePolicyV2Rule) {
		t.Fatalf("duplicate policy error = %v", err)
	}
}
