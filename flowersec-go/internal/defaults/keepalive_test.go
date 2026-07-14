package defaults

import (
	"testing"
	"time"
)

func TestLiveness(t *testing.T) {
	t.Run("non-positive idle disables liveness", func(t *testing.T) {
		if interval, timeout := Liveness(0); interval != 0 || timeout != 0 {
			t.Fatalf("expected disabled liveness, got interval=%v timeout=%v", interval, timeout)
		}
		if interval, timeout := Liveness(-1); interval != 0 || timeout != 0 {
			t.Fatalf("expected disabled liveness, got interval=%v timeout=%v", interval, timeout)
		}
	})

	t.Run("idle/2 interval and capped timeout", func(t *testing.T) {
		interval, timeout := Liveness(60)
		if interval != 30*time.Second || timeout != 10*time.Second {
			t.Fatalf("unexpected liveness defaults: interval=%v timeout=%v", interval, timeout)
		}
	})

	t.Run("min clamp and strict less than idle", func(t *testing.T) {
		idle := 1 * time.Second
		interval, timeout := Liveness(1)
		if interval != 500*time.Millisecond || timeout != interval {
			t.Fatalf("unexpected liveness defaults: interval=%v timeout=%v", interval, timeout)
		} else if interval >= idle {
			t.Fatalf("expected liveness interval < idle, got interval=%v idle=%v", interval, idle)
		}
	})
}
