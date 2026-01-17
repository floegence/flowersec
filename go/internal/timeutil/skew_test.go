package timeutil

import (
	"math"
	"testing"
	"time"
)

func TestSkewSecondsCeil(t *testing.T) {
	if got := SkewSecondsCeil(0); got != 0 {
		t.Fatalf("got %d, want 0", got)
	}
	if got := SkewSecondsCeil(-1 * time.Second); got != 0 {
		t.Fatalf("got %d, want 0", got)
	}
	if got := SkewSecondsCeil(1 * time.Nanosecond); got != 1 {
		t.Fatalf("got %d, want 1", got)
	}
	if got := SkewSecondsCeil(999 * time.Millisecond); got != 1 {
		t.Fatalf("got %d, want 1", got)
	}
	if got := SkewSecondsCeil(1 * time.Second); got != 1 {
		t.Fatalf("got %d, want 1", got)
	}
	if got := SkewSecondsCeil(1500 * time.Millisecond); got != 2 {
		t.Fatalf("got %d, want 2", got)
	}
}

func TestNormalizeSkew(t *testing.T) {
	if got := NormalizeSkew(0); got != 0 {
		t.Fatalf("got %v, want 0", got)
	}
	if got := NormalizeSkew(1500 * time.Millisecond); got != 2*time.Second {
		t.Fatalf("got %v, want 2s", got)
	}
}

func TestAddSkewUnix(t *testing.T) {
	if got := AddSkewUnix(100, 0); got != 100 {
		t.Fatalf("got %d, want 100", got)
	}
	if got := AddSkewUnix(100, 30*time.Second+time.Nanosecond); got != 131 {
		t.Fatalf("got %d, want 131", got)
	}
	if got := AddSkewUnix(math.MaxInt64-1, 5*time.Second); got != math.MaxInt64 {
		t.Fatalf("got %d, want MaxInt64", got)
	}
}
