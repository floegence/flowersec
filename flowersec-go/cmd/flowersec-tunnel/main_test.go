package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	fsversion "github.com/floegence/flowersec/flowersec-go/internal/version"
)

func TestVersionString_UsesLdflags(t *testing.T) {
	oldVersion := version
	oldCommit := commit
	oldDate := date
	t.Cleanup(func() {
		version = oldVersion
		commit = oldCommit
		date = oldDate
	})

	version = "v1.2.3"
	commit = "deadbeef"
	date = "2026-01-01T00:00:00Z"

	got := fsversion.String(version, commit, date)
	if !strings.Contains(got, "v1.2.3") {
		t.Fatalf("expected version in output, got %q", got)
	}
	if !strings.Contains(got, "deadbeef") {
		t.Fatalf("expected commit in output, got %q", got)
	}
	if !strings.Contains(got, "2026-01-01T00:00:00Z") {
		t.Fatalf("expected date in output, got %q", got)
	}
}

func TestRun_VersionFlag(t *testing.T) {
	oldVersion := version
	t.Cleanup(func() { version = oldVersion })
	version = "v9.9.9"

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"--version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) == "" {
		t.Fatalf("expected version output")
	}
}

func TestRun_HelpMarksRequiredFlags(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	help := stderr.String()
	if !strings.Contains(help, "Examples:") {
		t.Fatalf("expected help to include Examples, help=%q", help)
	}
	if !strings.Contains(help, "Exit codes:") {
		t.Fatalf("expected help to include exit codes, help=%q", help)
	}
	if !strings.Contains(help, "issuer keyset file (kid->ed25519 pubkey) (required)") {
		t.Fatalf("expected issuer-keys-file to be marked required, help=%q", help)
	}
	if !strings.Contains(help, "expected token audience (required)") {
		t.Fatalf("expected aud to be marked required, help=%q", help)
	}
}

func TestResolveAdvertiseHost_DefaultsToBindAddr(t *testing.T) {
	main, hostOnly, wasSet, err := resolveAdvertiseHost("0.0.0.0:8080", "")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if wasSet {
		t.Fatalf("expected wasSet=false")
	}
	if main != "0.0.0.0:8080" {
		t.Fatalf("unexpected main: %q", main)
	}
	if hostOnly != "0.0.0.0" {
		t.Fatalf("unexpected hostOnly: %q", hostOnly)
	}
}

func TestResolveAdvertiseHost_HostOnlyUsesBindPort(t *testing.T) {
	main, hostOnly, wasSet, err := resolveAdvertiseHost("0.0.0.0:8080", "example.com")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !wasSet {
		t.Fatalf("expected wasSet=true")
	}
	if main != "example.com:8080" {
		t.Fatalf("unexpected main: %q", main)
	}
	if hostOnly != "example.com" {
		t.Fatalf("unexpected hostOnly: %q", hostOnly)
	}
}

func TestResolveAdvertiseHost_HostPortOverridesBindPort(t *testing.T) {
	main, hostOnly, wasSet, err := resolveAdvertiseHost("0.0.0.0:8080", "example.com:9999")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !wasSet {
		t.Fatalf("expected wasSet=true")
	}
	if main != "example.com:9999" {
		t.Fatalf("unexpected main: %q", main)
	}
	if hostOnly != "example.com" {
		t.Fatalf("unexpected hostOnly: %q", hostOnly)
	}
}

func TestResolveAdvertiseHost_URLIsAccepted(t *testing.T) {
	main, hostOnly, wasSet, err := resolveAdvertiseHost("0.0.0.0:8080", "https://example.com:7777")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !wasSet {
		t.Fatalf("expected wasSet=true")
	}
	if main != "example.com:7777" {
		t.Fatalf("unexpected main: %q", main)
	}
	if hostOnly != "example.com" {
		t.Fatalf("unexpected hostOnly: %q", hostOnly)
	}
}

func TestResolveAdvertiseHost_StripsIPv6Brackets(t *testing.T) {
	main, hostOnly, wasSet, err := resolveAdvertiseHost("[::]:8080", "[::1]")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !wasSet {
		t.Fatalf("expected wasSet=true")
	}
	if main != "[::1]:8080" {
		t.Fatalf("unexpected main: %q", main)
	}
	if hostOnly != "::1" {
		t.Fatalf("unexpected hostOnly: %q", hostOnly)
	}
}

func TestRun_MissingRequiredFlags_PrintsUsage(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"--listen", "127.0.0.1:0"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "Usage:") || !strings.Contains(stderr.String(), "flowersec-tunnel") {
		t.Fatalf("expected usage in stderr, got %q", stderr.String())
	}
}

func TestSplitCSVEnv(t *testing.T) {
	t.Setenv("FSEC_TUNNEL_ALLOW_ORIGIN", "a,b, c,,")
	got := splitCSVEnv("FSEC_TUNNEL_ALLOW_ORIGIN")
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitCSVEnv mismatch: got=%v want=%v", got, want)
	}
}

func TestEnvBoolWithErr(t *testing.T) {
	t.Setenv("FSEC_TUNNEL_ALLOW_NO_ORIGIN", "true")
	v, err := envBoolWithErr("FSEC_TUNNEL_ALLOW_NO_ORIGIN", false)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if v != true {
		t.Fatalf("expected true, got %v", v)
	}
}

func TestEnvIntWithErr_Invalid(t *testing.T) {
	t.Setenv("FSEC_TUNNEL_MAX_CONNS", "nope")
	_, err := envIntWithErr("FSEC_TUNNEL_MAX_CONNS", 0)
	if err == nil {
		t.Fatalf("expected error")
	}
}
