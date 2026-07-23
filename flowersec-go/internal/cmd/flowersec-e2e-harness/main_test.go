package main

import (
	"reflect"
	"testing"

	e2eev1 "github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/e2ee/v1"
)

func TestParseSuite(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  e2eev1.Suite
	}{
		{name: "x25519", input: "x25519", want: e2eev1.Suite_X25519_HKDF_SHA256_AES_256_GCM},
		{name: "p256", input: "p256", want: e2eev1.Suite_P256_HKDF_SHA256_AES_256_GCM},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseSuite(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("parseSuite(%q) = %d, want %d", test.input, got, test.want)
			}
		})
	}
}

func TestParseSuiteRejectsUnknownValue(t *testing.T) {
	t.Parallel()

	if _, err := parseSuite("P-256"); err == nil {
		t.Fatal("parseSuite must reject values outside the documented flag contract")
	}
}

func TestHarnessAllowedOrigins(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		extra string
		want  []string
	}{
		{name: "default", want: []string{e2eOrigin}},
		{name: "browser site", extra: "http://127.0.0.1:43210", want: []string{e2eOrigin, "http://127.0.0.1:43210"}},
		{name: "duplicate", extra: e2eOrigin, want: []string{e2eOrigin}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := harnessAllowedOrigins(test.extra)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("harnessAllowedOrigins(%q) = %#v, want %#v", test.extra, got, test.want)
			}
		})
	}
}

func TestHarnessAllowedOriginsRejectsUnsafeValues(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"*",
		"http://*",
		"https://*.example.test",
		"127.0.0.1:43210",
		"file:///tmp/site",
		"http://127.0.0.1:43210/path",
	} {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, err := harnessAllowedOrigins(value); err == nil {
				t.Fatalf("harnessAllowedOrigins(%q) must fail", value)
			}
		})
	}
}
