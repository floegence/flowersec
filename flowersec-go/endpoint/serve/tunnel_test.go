package serve

import (
	"context"
	"strings"
	"testing"
)

func TestServeTunnel_MissingServer(t *testing.T) {
	t.Parallel()

	err := ServeTunnel(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "missing server") {
		t.Fatalf("unexpected error: %v", err)
	}
}
