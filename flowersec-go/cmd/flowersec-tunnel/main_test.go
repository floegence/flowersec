package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
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

	got := versionString()
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
