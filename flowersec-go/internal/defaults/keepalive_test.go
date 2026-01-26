package defaults

import (
	"testing"
	"time"
)

func TestKeepaliveInterval(t *testing.T) {
	t.Run("non-positive idle disables keepalive", func(t *testing.T) {
		if got := KeepaliveInterval(0); got != 0 {
			t.Fatalf("expected 0, got %v", got)
		}
		if got := KeepaliveInterval(-1); got != 0 {
			t.Fatalf("expected 0, got %v", got)
		}
	})

	t.Run("idle/2 default", func(t *testing.T) {
		if got := KeepaliveInterval(60); got != 30*time.Second {
			t.Fatalf("expected 30s, got %v", got)
		}
	})

	t.Run("min clamp and strict less than idle", func(t *testing.T) {
		idle := 1 * time.Second
		if got := KeepaliveInterval(1); got != 500*time.Millisecond {
			t.Fatalf("expected 500ms, got %v", got)
		} else if got >= idle {
			t.Fatalf("expected keepalive interval < idle, got interval=%v idle=%v", got, idle)
		}
	})
}
