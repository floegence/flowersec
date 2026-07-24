package transportrelease

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
)

// Operation records one real workload operation without pre-aggregating its
// timing or byte evidence.
type Operation struct {
	Ordinal       int           `json:"ordinal"`
	StartedAt     time.Time     `json:"started_at"`
	Duration      time.Duration `json:"duration_ns"`
	InputBytes    int           `json:"input_bytes"`
	OutputBytes   int           `json:"output_bytes"`
	PayloadSHA256 [32]byte      `json:"payload_sha256"`
}

// ConnectOperation records one distinct artifact-to-READY connection and its
// bounded cleanup. ScheduledAt is the frozen rate schedule, not a reconstruction.
type ConnectOperation struct {
	Ordinal         int           `json:"ordinal"`
	ScheduledAt     time.Time     `json:"scheduled_at"`
	StartedAt       time.Time     `json:"started_at"`
	Duration        time.Duration `json:"duration_ns"`
	CleanupDuration time.Duration `json:"cleanup_duration_ns"`
}

// BulkResult records the scored simultaneous transfer in both directions.
type BulkResult struct {
	StartedAt         time.Time     `json:"started_at"`
	Duration          time.Duration `json:"duration_ns"`
	BytesPerDirection int64         `json:"bytes_per_direction"`
}

// RunCold connects an exact number of independently issued artifacts at the
// requested start rate. It applies no retry path and never exceeds maxInflight.
func RunCold(ctx context.Context, endpoint *ProductDirectEndpoint, operations, maxInflight, startRatePerSecond int, operationDeadline time.Duration) ([]ConnectOperation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if endpoint == nil || operations < 1 || maxInflight < 1 || maxInflight > operations || startRatePerSecond < 1 || operationDeadline <= 0 {
		return nil, errors.New("invalid cold-connect workload")
	}
	results := make([]ConnectOperation, operations)
	workErrors := make(chan error, operations)
	semaphore := make(chan struct{}, maxInflight)
	var group sync.WaitGroup
	phaseStart := time.Now()
	interval := time.Second / time.Duration(startRatePerSecond)
	for ordinal := 1; ordinal <= operations; ordinal++ {
		scheduled := phaseStart.Add(time.Duration(ordinal-1) * interval)
		if err := waitUntil(ctx, scheduled); err != nil {
			workErrors <- err
			break
		}
		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			workErrors <- context.Cause(ctx)
			ordinal = operations
			continue
		}
		group.Add(1)
		go func(ordinal int, scheduled time.Time) {
			defer group.Done()
			defer func() { <-semaphore }()
			operationCtx, cancel := context.WithTimeout(ctx, operationDeadline)
			defer cancel()
			started := time.Now()
			pair, err := endpoint.Connect(operationCtx)
			duration := time.Since(started)
			if err != nil {
				workErrors <- fmt.Errorf("cold connection %d: %w", ordinal, err)
				return
			}
			cleanupStarted := time.Now()
			closeErr := pair.Close()
			cleanupDuration := time.Since(cleanupStarted)
			if closeErr != nil {
				workErrors <- fmt.Errorf("cold connection %d cleanup: %w", ordinal, closeErr)
				return
			}
			results[ordinal-1] = ConnectOperation{
				Ordinal: ordinal, ScheduledAt: scheduled, StartedAt: started,
				Duration: duration, CleanupDuration: cleanupDuration,
			}
		}(ordinal, scheduled)
	}
	group.Wait()
	if err := contextCompletionError(ctx); err != nil {
		return nil, err
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
		if result.Ordinal != index+1 || result.Duration <= 0 || result.CleanupDuration <= 0 || result.StartedAt.Before(result.ScheduledAt) {
			return nil, fmt.Errorf("cold connection %d is incomplete", index+1)
		}
	}
	return results, nil
}

// RunRPC executes an exact-count concurrent echo workload over the public
// carrier-neutral RPC surface. It performs no retries.
func RunRPC(ctx context.Context, pair *ProductDirectPair, operations, workers, payloadBytes int, operationDeadline time.Duration) ([]Operation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if pair == nil || pair.Client == nil || operations < 1 || workers < 1 || workers > operations || payloadBytes < 2 || operationDeadline <= 0 {
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
				operationCtx, cancel := context.WithTimeout(ctx, operationDeadline)
				err := pair.Client.RPC().Call(operationCtx, 1, payload, &response)
				cancel()
				if err != nil {
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
	if err := contextCompletionError(ctx); err != nil {
		return nil, err
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

func contextCompletionError(ctx context.Context) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// RunBulk performs a non-scored warmup followed by a scored transfer over two
// independent encrypted streams, one opened by each endpoint.
func RunBulk(ctx context.Context, pair *ProductDirectPair, warmupBytesPerDirection, scoreBytesPerDirection int64) (BulkResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if pair == nil || pair.Client == nil || pair.Server == nil || warmupBytesPerDirection < 1 || scoreBytesPerDirection < 1 {
		return BulkResult{}, errors.New("invalid bulk workload")
	}
	if _, err := runBulkPhase(ctx, pair, warmupBytesPerDirection); err != nil {
		return BulkResult{}, fmt.Errorf("bulk warmup: %w", err)
	}
	started := time.Now()
	duration, err := runBulkPhase(ctx, pair, scoreBytesPerDirection)
	if err != nil {
		return BulkResult{}, fmt.Errorf("bulk score: %w", err)
	}
	return BulkResult{StartedAt: started, Duration: duration, BytesPerDirection: scoreBytesPerDirection}, nil
}

type releaseByteStream interface {
	io.Reader
	io.Writer
	io.Closer
	CloseWrite() error
	Reset() error
}

type acceptedReleaseStream struct {
	kind      string
	direction string
	stream    releaseByteStream
	err       error
}

func runBulkPhase(ctx context.Context, pair *ProductDirectPair, bytesPerDirection int64) (time.Duration, error) {
	phaseCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	clientAccepted := make(chan acceptedReleaseStream, 1)
	serverAccepted := make(chan acceptedReleaseStream, 1)
	go func() {
		incoming, err := pair.Client.AcceptStream(phaseCtx)
		clientAccepted <- normalizePublicIncoming(incoming, err)
	}()
	go func() {
		incoming, err := pair.Server.AcceptStream(phaseCtx)
		serverAccepted <- normalizeInternalIncoming(incoming, err)
	}()
	clientOpened, err := pair.Client.OpenStream(phaseCtx, "release-bulk", flowersec.Metadata{"direction": "client-to-server"})
	if err != nil {
		return 0, err
	}
	serverOpened, err := pair.Server.OpenStream(phaseCtx, "release-bulk", flowersession.Metadata{"direction": "server-to-client"})
	if err != nil {
		_ = clientOpened.Reset()
		return 0, err
	}
	fromClient := <-serverAccepted
	fromServer := <-clientAccepted
	if fromClient.err != nil || fromServer.err != nil {
		_ = clientOpened.Reset()
		_ = serverOpened.Reset()
		return 0, errors.Join(fromClient.err, fromServer.err)
	}
	streams := []releaseByteStream{clientOpened, serverOpened, fromClient.stream, fromServer.stream}
	defer func() {
		for _, stream := range streams {
			_ = stream.Close()
		}
	}()
	if fromClient.kind != "release-bulk" || fromClient.direction != "client-to-server" ||
		fromServer.kind != "release-bulk" || fromServer.direction != "server-to-client" {
		return 0, errors.New("bulk stream metadata mismatch")
	}
	started := time.Now()
	errorsByDirection := make(chan error, 2)
	go func() {
		directionErr := transferExact(phaseCtx, clientOpened, fromClient.stream, bytesPerDirection, 0xa5)
		if directionErr != nil {
			cancel(directionErr)
		}
		errorsByDirection <- directionErr
	}()
	go func() {
		directionErr := transferExact(phaseCtx, serverOpened, fromServer.stream, bytesPerDirection, 0x5a)
		if directionErr != nil {
			cancel(directionErr)
		}
		errorsByDirection <- directionErr
	}()
	phaseDone := phaseCtx.Done()
	for completed := 0; completed < 2; {
		select {
		case directionErr := <-errorsByDirection:
			err = errors.Join(err, directionErr)
			completed++
		case <-phaseDone:
			err = errors.Join(err, context.Cause(phaseCtx))
			for _, stream := range streams {
				_ = stream.Reset()
			}
			phaseDone = nil
		}
	}
	return time.Since(started), err
}

func normalizePublicIncoming(incoming flowersec.IncomingStream, err error) acceptedReleaseStream {
	return acceptedReleaseStream{
		kind: incoming.Kind, direction: fmt.Sprint(incoming.Metadata["direction"]), stream: incoming.Stream, err: err,
	}
}

func normalizeInternalIncoming(incoming flowersession.IncomingStream, err error) acceptedReleaseStream {
	return acceptedReleaseStream{
		kind: incoming.Kind, direction: fmt.Sprint(incoming.Metadata["direction"]), stream: incoming.Stream, err: err,
	}
}

func transferExact(ctx context.Context, writer, reader releaseByteStream, total int64, fill byte) error {
	type transferResult struct{ err error }
	results := make(chan transferResult, 2)
	var resetOnce sync.Once
	reset := func() {
		resetOnce.Do(func() {
			_ = writer.Reset()
			_ = reader.Reset()
		})
	}
	stopCancellation := context.AfterFunc(ctx, reset)
	defer stopCancellation()
	go func() {
		chunk := bytes.Repeat([]byte{fill}, 32*1024)
		remaining := total
		var err error
		for remaining > 0 {
			current := int64(len(chunk))
			if remaining < current {
				current = remaining
			}
			var count int
			count, err = writer.Write(chunk[:current])
			remaining -= int64(count)
			if err != nil {
				break
			}
			if int64(count) != current {
				err = io.ErrShortWrite
				break
			}
		}
		if err == nil {
			err = writer.CloseWrite()
		}
		results <- transferResult{err: err}
	}()
	go func() {
		readBytes, readErr := io.CopyN(io.Discard, reader, total)
		if readErr == nil {
			var trailing [1]byte
			if count, err := reader.Read(trailing[:]); count != 0 || !errors.Is(err, io.EOF) {
				readErr = errors.New("bulk stream did not end at the exact byte boundary")
			}
		}
		results <- transferResult{err: errors.Join(readErr, exactByteCount("bulk read", readBytes, total))}
	}()
	var joined error
	ctxDone := ctx.Done()
	for completed := 0; completed < 2; {
		select {
		case result := <-results:
			joined = errors.Join(joined, result.err)
			if result.err != nil {
				reset()
			}
			completed++
		case <-ctxDone:
			joined = errors.Join(joined, context.Cause(ctx))
			reset()
			ctxDone = nil
		}
	}
	return joined
}

func exactByteCount(label string, got, want int64) error {
	if got == want {
		return nil
	}
	return fmt.Errorf("%s bytes = %d, want %d", label, got, want)
}

func waitUntil(ctx context.Context, deadline time.Time) error {
	delay := time.Until(deadline)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}
