package contextutil

import (
	"context"
	"testing"
	"time"
)

func TestWithTimeout_NilParent_NoTimeoutReturnsNonNilContext(t *testing.T) {
	ctx, cancel := WithTimeout(nil, 0)
	t.Cleanup(cancel)
	if ctx == nil {
		t.Fatalf("expected non-nil context")
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("expected nil Err, got %v", err)
	}
}

func TestWithTimeout_NilParent_WithTimeoutIsCancelable(t *testing.T) {
	ctx, cancel := WithTimeout(nil, 5*time.Second)
	if ctx == nil {
		t.Fatalf("expected non-nil context")
	}
	cancel()
	if got := ctx.Err(); got != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", got)
	}
}
