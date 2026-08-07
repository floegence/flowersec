package performance

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestBrowserCapacityWorkerPreservesParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := runBrowserCapacityWorker(ctx, browserWorkerRequest{}, io.Discard)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runBrowserCapacityWorker() error = %v, want context.Canceled", err)
	}
}

func TestBrowserWorkerRejectsNilContext(t *testing.T) {
	err := runBrowserWorkerWithContext(nil, nil, io.Discard)
	if err == nil || err.Error() != "browser worker context is required" {
		t.Fatalf("runBrowserWorkerWithContext() error = %v", err)
	}
}
