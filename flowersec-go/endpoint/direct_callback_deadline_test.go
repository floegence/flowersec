package endpoint

import (
	"context"
	"errors"
	"testing"
)

func TestAwaitCallbackResult_ContextWinsAtCompletionBoundary(t *testing.T) {
	for range 1_000 {
		ctx, cancel := context.WithCancel(context.Background())
		results := make(chan callbackResult[int], 1)
		resultReady := make(chan struct{})
		go func() {
			results <- callbackResult[int]{value: 42}
			close(resultReady)
		}()

		<-resultReady
		cancel()
		value, err := awaitCallbackResult(ctx, results)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("awaitCallbackResult() error = %v, want context.Canceled", err)
		}
		if value != 0 {
			t.Fatalf("awaitCallbackResult() value = %d, want zero value", value)
		}
	}
}
