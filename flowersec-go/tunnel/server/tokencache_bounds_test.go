package server

import (
	"sync"
	"testing"
	"time"
)

func newTestTokenUseCache(t *testing.T, maxEntries int) *TokenUseCache {
	t.Helper()
	c, err := NewTokenUseCache(maxEntries)
	if err != nil {
		t.Fatalf("NewTokenUseCache(%d) failed: %v", maxEntries, err)
	}
	return c
}

func TestNewTokenUseCacheRejectsNonPositiveCapacity(t *testing.T) {
	for _, maxEntries := range []int{0, -1} {
		if _, err := NewTokenUseCache(maxEntries); err == nil {
			t.Fatalf("expected maxEntries=%d to be rejected", maxEntries)
		}
	}
}

func TestTokenUseCacheRejectsNewKeyAtCapacity(t *testing.T) {
	c := newTestTokenUseCache(t, 2)
	now := time.Unix(100, 0)
	if !c.TryUse("first", 200, now) || !c.TryUse("second", 200, now) {
		t.Fatal("expected cache to accept entries up to its capacity")
	}
	if c.TryUse("third", 200, now) {
		t.Fatal("expected cache to reject a new key at capacity")
	}
	if got := len(c.used); got != 2 {
		t.Fatalf("cache size want=2 got=%d", got)
	}
}

func TestTokenUseCacheCleansExpiredEntriesBeforeRejectingAtCapacity(t *testing.T) {
	c := newTestTokenUseCache(t, 2)
	initialNow := time.Unix(100, 0)
	if !c.TryUse("expired", 101, initialNow) || !c.TryUse("active", 300, initialNow) {
		t.Fatal("expected initial entries to be accepted")
	}
	if !c.TryUse("replacement", 300, time.Unix(102, 0)) {
		t.Fatal("expected expired capacity to be reclaimed")
	}
	if _, ok := c.used["expired"]; ok {
		t.Fatal("expected expired entry to be removed")
	}
}

func TestTokenUseCacheDoesNotEvictActiveEntries(t *testing.T) {
	c := newTestTokenUseCache(t, 2)
	now := time.Unix(100, 0)
	if !c.TryUse("first", 200, now) || !c.TryUse("second", 300, now) {
		t.Fatal("expected initial entries to be accepted")
	}
	if c.TryUse("third", 400, time.Unix(150, 0)) {
		t.Fatal("expected full cache with active entries to reject a new key")
	}
	if c.TryUse("first", 400, time.Unix(150, 0)) || c.TryUse("second", 400, time.Unix(150, 0)) {
		t.Fatal("expected active replay keys to remain protected")
	}
}

func TestTokenUseCacheConcurrentUseAllowsExactlyOneSuccess(t *testing.T) {
	const goroutines = 64
	c := newTestTokenUseCache(t, 1)
	now := time.Unix(100, 0)
	start := make(chan struct{})
	results := make(chan bool, goroutines)
	var wg sync.WaitGroup

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- c.TryUse("shared", 200, now)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	for success := range results {
		if success {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent uses want=1 got=%d", successes)
	}
}
