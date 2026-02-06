package cmdutil

import (
	"testing"
	"time"
)

func TestEnvString_TrimsAndFallsBack(t *testing.T) {
	t.Setenv("X", "  ok  ")
	if got := EnvString("X", "fallback"); got != "ok" {
		t.Fatalf("unexpected value: %q", got)
	}
	t.Setenv("X", "   ")
	if got := EnvString("X", "fallback"); got != "fallback" {
		t.Fatalf("unexpected fallback: %q", got)
	}
}

func TestEnvBool_ParsesAndFallsBack(t *testing.T) {
	t.Setenv("B", "")
	got, err := EnvBool("B", true)
	if err != nil || got != true {
		t.Fatalf("unexpected: got=%v err=%v", got, err)
	}
	t.Setenv("B", "false")
	got, err = EnvBool("B", true)
	if err != nil || got != false {
		t.Fatalf("unexpected: got=%v err=%v", got, err)
	}
	t.Setenv("B", "nope")
	_, err = EnvBool("B", true)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestEnvDuration_ParsesAndFallsBack(t *testing.T) {
	t.Setenv("D", "")
	got, err := EnvDuration("D", 123*time.Millisecond)
	if err != nil || got != 123*time.Millisecond {
		t.Fatalf("unexpected: got=%v err=%v", got, err)
	}
	t.Setenv("D", "1s")
	got, err = EnvDuration("D", 0)
	if err != nil || got != time.Second {
		t.Fatalf("unexpected: got=%v err=%v", got, err)
	}
	t.Setenv("D", "bad")
	_, err = EnvDuration("D", 0)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestSplitCSVEnv_TrimsAndDropsEmpty(t *testing.T) {
	t.Setenv("CSV", " a,  ,b,,  c ")
	got := SplitCSVEnv("CSV")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("unexpected parts: %#v", got)
	}
}
