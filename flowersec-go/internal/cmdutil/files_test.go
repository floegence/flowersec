package cmdutil

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRefuseOverwrite_AllowsMissing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "missing.json")
	if err := RefuseOverwrite(p, false); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestRefuseOverwrite_UsageErrorWhenExists(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.json")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := RefuseOverwrite(p, false)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !IsUsage(err) {
		t.Fatalf("expected UsageError, got %T: %v", err, err)
	}
}

func TestRefuseOverwrite_PropagatesStatErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based permission test is not portable on windows")
	}

	parent := t.TempDir()
	noAccess := filepath.Join(parent, "no-access")
	if err := os.MkdirAll(noAccess, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	p := filepath.Join(noAccess, "x.json")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Remove execute permission so Stat fails.
	if err := os.Chmod(noAccess, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(noAccess, 0o700) })

	err := RefuseOverwrite(p, false)
	if err == nil {
		t.Fatalf("expected error")
	}
	if IsUsage(err) {
		t.Fatalf("expected non-usage error, got %T: %v", err, err)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected non-not-exist error, got %v", err)
	}
}
