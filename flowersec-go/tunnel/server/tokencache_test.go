package server

import (
	"math"
	"testing"
	"time"
)

func exerciseReplayCacheContract(t *testing.T, c ReplayCache) {
	t.Helper()
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

func TestTokenUseCache(t *testing.T) {
	exerciseReplayCacheContract(t, NewTokenUseCache())
}

func TestReplayCacheContractForInMemoryImplementation(t *testing.T) {
	exerciseReplayCacheContract(t, NewTokenUseCache())
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

type testReplayCache struct {
	delegate     ReplayCache
	tryUseCalls  int
	cleanupCalls int
}

func (c *testReplayCache) TryUse(replayKey string, usedUntilUnix int64, now time.Time) bool {
	c.tryUseCalls++
	return c.delegate.TryUse(replayKey, usedUntilUnix, now)
}

func (c *testReplayCache) Cleanup(now time.Time) {
	c.cleanupCalls++
	c.delegate.Cleanup(now)
}

type testReplayVerifier struct{}

func (testReplayVerifier) Verify(string, time.Time, time.Duration) (VerifiedToken, error) {
	return VerifiedToken{}, nil
}

func (testReplayVerifier) Reload() error { return nil }

func TestServerUsesConfiguredReplayCache(t *testing.T) {
	cache := &testReplayCache{delegate: NewTokenUseCache()}
	cfg := DefaultConfig()
	cfg.AllowedOrigins = []string{"https://ok"}
	cfg.Verifier = testReplayVerifier{}
	cfg.ReplayCache = cache

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	t.Cleanup(s.Close)

	if s.used != cache {
		t.Fatalf("expected server to use configured replay cache")
	}
	if !s.used.TryUse("scope\x00tok", time.Now().Add(time.Minute).Unix(), time.Now()) {
		t.Fatalf("expected configured replay cache to accept first use")
	}
	if cache.tryUseCalls != 1 {
		t.Fatalf("expected configured replay cache to observe TryUse, got %d", cache.tryUseCalls)
	}
}

func TestTokenUseCacheScopesReplayKeysByTenant(t *testing.T) {
	c := NewTokenUseCache()
	now := time.Unix(100, 0)

	scopeA := scopedTokenUseKey(tenantScopeKey("aud-a", "iss-a"), "tok")
	scopeB := scopedTokenUseKey(tenantScopeKey("aud-b", "iss-b"), "tok")

	if !c.TryUse(scopeA, 200, now) {
		t.Fatalf("expected first use in scope A to succeed")
	}
	if !c.TryUse(scopeB, 200, now) {
		t.Fatalf("expected first use in scope B to succeed")
	}
	if c.TryUse(scopeA, 200, now) {
		t.Fatalf("expected reuse in scope A to fail")
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
