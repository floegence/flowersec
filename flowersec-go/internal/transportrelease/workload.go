package transportrelease

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Operation records one real workload operation without pre-aggregating its
// timing or byte evidence.
type Operation struct {
	Ordinal       int
	StartedAt     time.Time
	Duration      time.Duration
	InputBytes    int
	OutputBytes   int
	PayloadSHA256 [32]byte
}

// RunRPC executes an exact-count concurrent echo workload over the public
// carrier-neutral RPC surface. It performs no retries.
func RunRPC(ctx context.Context, pair *ProductDirectPair, operations, workers, payloadBytes int) ([]Operation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if pair == nil || pair.Client == nil || operations < 1 || workers < 1 || workers > operations || payloadBytes < 2 {
		return nil, errors.New("invalid RPC workload")
	}
	payload := json.RawMessage(append(append([]byte{'"'}, bytes.Repeat([]byte{'x'}, payloadBytes-2)...), '"'))
	wantHash := sha256.Sum256(payload)
	results := make([]Operation, operations)
	var next atomic.Int64
	var group sync.WaitGroup
	workErrors := make(chan error, workers)
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			for {
				ordinal := int(next.Add(1))
				if ordinal > operations {
					return
				}
				if err := ctx.Err(); err != nil {
					workErrors <- err
					return
				}
				started := time.Now()
				var response json.RawMessage
				if err := pair.Client.RPC().Call(ctx, 1, payload, &response); err != nil {
					workErrors <- fmt.Errorf("RPC operation %d: %w", ordinal, err)
					return
				}
				duration := time.Since(started)
				if !bytes.Equal(response, payload) {
					workErrors <- fmt.Errorf("RPC operation %d payload mismatch", ordinal)
					return
				}
				results[ordinal-1] = Operation{
					Ordinal: ordinal, StartedAt: started, Duration: duration,
					InputBytes: len(payload), OutputBytes: len(response), PayloadSHA256: wantHash,
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		group.Wait()
		close(done)
	}()
	select {
	case <-ctx.Done():
		<-done
		return nil, ctx.Err()
	case <-done:
	}
	close(workErrors)
	var joined error
	for err := range workErrors {
		joined = errors.Join(joined, err)
	}
	if joined != nil {
		return nil, joined
	}
	for index, result := range results {
		if result.Ordinal != index+1 || result.Duration <= 0 || result.InputBytes != payloadBytes || result.OutputBytes != payloadBytes || result.PayloadSHA256 != wantHash {
			return nil, fmt.Errorf("RPC operation %d is incomplete", index+1)
		}
	}
	return results, nil
}
