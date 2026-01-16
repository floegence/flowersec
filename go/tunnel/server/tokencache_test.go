package server

import (
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
