package server

import (
	"math"
	"testing"
	"time"
)

func TestTokenUseCache(t *testing.T) {
	c := NewTokenUseCache()
	now := time.Unix(100, 0)

	if c.TryUse("", 200, now) {
		t.Fatalf("expected empty token to be rejected")
	}
	if !c.TryUse("tok", 200, now) {
		t.Fatalf("expected first use to succeed")
	}
	if c.TryUse("tok", 200, now) {
		t.Fatalf("expected reuse to fail")
	}

	c.Cleanup(time.Unix(300, 0))
	if !c.TryUse("tok", 400, time.Unix(300, 0)) {
		t.Fatalf("expected reuse after cleanup to succeed")
	}
}

func TestTokenUseCacheHonorsSkewWindow(t *testing.T) {
	c := NewTokenUseCache()
	now := time.Unix(100, 0)

	// Simulate a token with exp already in the past, but within a 30s clock skew window.
	expUnix := int64(90)
	usedUntil := addSkewUnix(expUnix, 30*time.Second)
	if usedUntil <= now.Unix() {
		t.Fatalf("expected usedUntil to extend into the future, got %d", usedUntil)
	}

	if !c.TryUse("tok", usedUntil, now) {
		t.Fatalf("expected first use to succeed")
	}
	if c.TryUse("tok", usedUntil, time.Unix(110, 0)) {
		t.Fatalf("expected reuse within usedUntil to fail")
	}
	if !c.TryUse("tok", usedUntil, time.Unix(usedUntil+1, 0)) {
		t.Fatalf("expected reuse after usedUntil to succeed")
	}
}

func TestAddSkewUnix(t *testing.T) {
	if got := addSkewUnix(100, 0); got != 100 {
		t.Fatalf("expected no skew to keep value, got %d", got)
	}
	if got := addSkewUnix(100, 30*time.Second); got != 130 {
		t.Fatalf("expected 30s skew to add 30, got %d", got)
	}
	if got := addSkewUnix(100, 30*time.Second+time.Nanosecond); got != 131 {
		t.Fatalf("expected ceil seconds, got %d", got)
	}
	if got := addSkewUnix(math.MaxInt64-1, 5*time.Second); got != math.MaxInt64 {
		t.Fatalf("expected overflow to clamp, got %d", got)
	}
}
