package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	fsversion "github.com/floegence/flowersec/flowersec-go/internal/version"
)

func writeTenantConfigForCLI(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	ks, err := issuer.NewRandom("k1")
	if err != nil {
		t.Fatalf("issuer.NewRandom() failed: %v", err)
	}
	keysJSON, err := ks.ExportTunnelKeyset()
	if err != nil {
		t.Fatalf("ExportTunnelKeyset() failed: %v", err)
	}
	keysPath := filepath.Join(tmp, "issuer_keys.json")
	if err := os.WriteFile(keysPath, keysJSON, 0o600); err != nil {
		t.Fatalf("WriteFile(keys) failed: %v", err)
	}
	tenantsPath := filepath.Join(tmp, "tenants.json")
	payload := map[string]any{
		"tenants": []map[string]string{{
			"id":               "tenant-a",
			"aud":              "aud-a",
			"iss":              "iss-a",
			"issuer_keys_file": keysPath,
		}},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal(tenants) failed: %v", err)
	}
	if err := os.WriteFile(tenantsPath, b, 0o600); err != nil {
		t.Fatalf("WriteFile(tenants) failed: %v", err)
	}
	return tenantsPath
}

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
	if !strings.Contains(help, "multi-tenant verifier config file") {
		t.Fatalf("expected help to include tenants-file, help=%q", help)
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

func TestResolveAdvertiseHost_RejectsInvalidHostPort(t *testing.T) {
	_, _, _, err := resolveAdvertiseHost("0.0.0.0:8080", "example.com:abc")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "invalid --advertise-host") {
		t.Fatalf("unexpected error: %v", err)
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

func TestRun_WhitespaceRequiredFlags_AreTreatedAsMissing(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"--issuer-keys-file", " ",
			"--aud", "aud",
			"--iss", "iss",
			"--allow-origin", "https://ok",
		},
		&stdout,
		&stderr,
	)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "missing --issuer-keys-file") {
		t.Fatalf("expected missing required flags message, got %q", stderr.String())
	}
}

func TestRun_WhitespaceAllowOrigin_IsTreatedAsMissing(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"--issuer-keys-file", "issuer_keys.json",
			"--aud", "aud",
			"--iss", "iss",
			"--allow-origin", " ",
		},
		&stdout,
		&stderr,
	)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "missing --allow-origin") {
		t.Fatalf("expected missing allow-origin message, got %q", stderr.String())
	}
}

func TestRun_TenantsFileCannotBeCombinedWithLegacyFlags(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"--tenants-file", "tenants.json",
			"--issuer-keys-file", "issuer_keys.json",
			"--allow-origin", "https://ok",
		},
		&stdout,
		&stderr,
	)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "cannot combine --tenants-file") {
		t.Fatalf("expected tenants-file conflict, got %q", stderr.String())
	}
}

func TestRun_TenantsFileAllowsOmittingLegacyFlags(t *testing.T) {
	tenantsPath := writeTenantConfigForCLI(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"--tenants-file", tenantsPath,
			"--allow-origin", "https://ok",
			"--max-write-queue-bytes", "1",
		},
		&stdout,
		&stderr,
	)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d (stderr=%q)", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "missing --issuer-keys-file") {
		t.Fatalf("tenants-file should satisfy legacy verifier flags, stderr=%q", stderr.String())
	}
}

func TestParseHeaderValues(t *testing.T) {
	headers, err := parseHeaderValues([]string{"X-Test: one", "Authorization: Bearer abc"})
	if err != nil {
		t.Fatalf("parseHeaderValues() failed: %v", err)
	}
	want := http.Header{
		"X-Test":        []string{"one"},
		"Authorization": []string{"Bearer abc"},
	}
	if !reflect.DeepEqual(headers, want) {
		t.Fatalf("headers mismatch: got=%v want=%v", headers, want)
	}

	if _, err := parseHeaderValues([]string{"invalid"}); err == nil {
		t.Fatalf("expected invalid header error")
	}
}

func TestRun_ServerConfigErrors_AreUsageErrors(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"--issuer-keys-file", "issuer_keys.json",
			"--aud", "aud",
			"--iss", "iss",
			"--allow-origin", "https://ok",
			"--max-write-queue-bytes", "1",
		},
		&stdout,
		&stderr,
	)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "max write queue bytes must be >= max record bytes") {
		t.Fatalf("expected config error message, got %q", stderr.String())
	}
}

func TestRun_NegativeMaxTotalPendingBytes_IsUsageError(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"--issuer-keys-file", "issuer_keys.json",
			"--aud", "aud",
			"--iss", "iss",
			"--allow-origin", "https://ok",
			"--max-total-pending-bytes", "-1",
		},
		&stdout,
		&stderr,
	)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--max-total-pending-bytes must be >= 0") {
		t.Fatalf("expected error message in stderr, got %q", stderr.String())
	}
}

func TestSelectAllowedOrigins_FlagOverridesEnv(t *testing.T) {
	env := []string{"a", "b"}
	flags := []string{"c"}
	got := selectAllowedOrigins(env, flags)
	want := []string{"c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selectAllowedOrigins mismatch: got=%v want=%v", got, want)
	}
}

func TestSelectAllowedOrigins_UsesEnvWhenFlagMissing(t *testing.T) {
	env := []string{"a", "b"}
	got := selectAllowedOrigins(env, nil)
	want := []string{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selectAllowedOrigins mismatch: got=%v want=%v", got, want)
	}
}

func TestSelectAuthorizerHeaders_FlagOverridesEnv(t *testing.T) {
	env := []string{"X-Test: env"}
	flags := []string{"X-Test: flag"}
	got := selectAuthorizerHeaders(env, flags)
	want := []string{"X-Test: flag"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selectAuthorizerHeaders mismatch: got=%v want=%v", got, want)
	}
}

func TestSelectAuthorizerHeaders_UsesEnvWhenFlagMissing(t *testing.T) {
	env := []string{"X-Test: env", "Authorization: Bearer token"}
	got := selectAuthorizerHeaders(env, nil)
	want := []string{"X-Test: env", "Authorization: Bearer token"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selectAuthorizerHeaders mismatch: got=%v want=%v", got, want)
	}
}
