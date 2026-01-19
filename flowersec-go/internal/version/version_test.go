package version

import (
	"strings"
	"testing"
)

func TestString_UsesProvidedValues(t *testing.T) {
	got := String("v1.2.3", "abc", "2020-01-01T00:00:00Z")
	want := "v1.2.3 (abc) 2020-01-01T00:00:00Z"
	if got != want {
		t.Fatalf("unexpected version string: got %q, want %q", got, want)
	}
}

func TestString_OmitsUnknownVCSFields(t *testing.T) {
	got := String("v1.2.3", "unknown", "unknown")
	want := "v1.2.3"
	if got != want {
		t.Fatalf("unexpected version string: got %q, want %q", got, want)
	}
}

func TestString_DefaultsToDev(t *testing.T) {
	got := String("", "unknown", "unknown")
	if got == "" {
		t.Fatalf("expected non-empty version string")
	}
	if strings.Contains(got, "unknown") {
		t.Fatalf("expected VCS placeholders to be omitted, got %q", got)
	}
}
