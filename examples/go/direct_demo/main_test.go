package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun_HelpIncludesExamplesAndExitCodes(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--help"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, errOut.String())
	}
	help := errOut.String()
	if !strings.Contains(help, "Examples:") {
		t.Fatalf("expected help to include Examples, help=%q", help)
	}
	if !strings.Contains(help, "Output:") {
		t.Fatalf("expected help to include Output, help=%q", help)
	}
	if !strings.Contains(help, "Exit codes:") {
		t.Fatalf("expected help to include Exit codes, help=%q", help)
	}
}

func TestRun_MissingAllowOriginIsUsageError(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(nil, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d (stderr=%q)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "missing --allow-origin") {
		t.Fatalf("expected missing allow-origin error, stderr=%q", errOut.String())
	}
}

func TestRun_VersionFlag(t *testing.T) {
	t.Parallel()

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

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--version"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, errOut.String())
	}
	s := out.String()
	if !strings.Contains(s, "v1.2.3") || !strings.Contains(s, "deadbeef") || !strings.Contains(s, "2026-01-01T00:00:00Z") {
		t.Fatalf("unexpected version output: %q", s)
	}
}
