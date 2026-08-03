package tunnelworkload

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

	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
)

var errInvalidTunnelColdWorkload = errors.New("invalid tunnel cold-connect workload")

// Result contains the unaggregated evidence for one topology/profile run.
type Result struct {
	Topology        Topology                            `json:"topology"`
	Cold            []transportrelease.ConnectOperation `json:"cold"`
	RPC             []transportrelease.Operation        `json:"rpc"`
	Bulk            transportrelease.BulkResult         `json:"bulk"`
	CleanupDuration time.Duration                       `json:"cleanup_duration_ns"`
}

// Run executes one frozen cold/RPC/bulk workload and owns final pair and
// endpoint cleanup. The release runner repeats this call for each independent
// run rather than reusing transport state across runs.
func Run(ctx context.Context, endpoint *Endpoint, plan transportrelease.ProfilePlan) (result Result, resultErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if endpoint == nil || plan.RPC.RequestBytes != plan.RPC.ResponseBytes {
		return Result{}, errors.New("invalid production tunnel workload")
	}
	result.Topology = endpoint.topology
	endpointClosed := false
	defer func() {
		if !endpointClosed {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			resultErr = errors.Join(resultErr, endpoint.Close(cleanupCtx))
			cancel()
		}
	}()

	coldLimit := time.Duration(plan.Cold.PhaseDeadlineSeconds) * time.Second
	coldCtx, cancelCold := context.WithTimeout(ctx, coldLimit)
	coldStarted := time.Now()
	result.Cold, resultErr = RunCold(
		coldCtx, endpoint, plan.Cold.Operations, plan.Cold.MaxInflight,
		plan.Cold.StartRatePerSecond, time.Duration(plan.Cold.OperationDeadlineSeconds)*time.Second,
		time.Duration(plan.CleanupDeadlineSeconds)*time.Second,
	)
	deadlineErr := completedWithin(coldCtx, coldStarted, coldLimit)
	cancelCold()
	if resultErr != nil || deadlineErr != nil {
		return Result{}, errors.Join(resultErr, deadlineErr)
	}

	rpcLimit := time.Duration(plan.RPC.PhaseDeadlineSeconds) * time.Second
	rpcCtx, cancelRPC := context.WithTimeout(ctx, rpcLimit)
	rpcStarted := time.Now()
	pair, err := endpoint.Connect(rpcCtx)
	if err != nil {
		cancelRPC()
		return Result{}, err
	}
	pairClosed := false
	defer func() {
		if !pairClosed {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			resultErr = errors.Join(resultErr, pair.Close(cleanupCtx))
			cancel()
		}
	}()
	result.RPC, resultErr = RunRPC(
		rpcCtx, pair, plan.RPC.Operations, plan.RPC.Workers,
		plan.RPC.RequestBytes, time.Duration(plan.RPC.OperationDeadlineSeconds)*time.Second,
	)
	deadlineErr = completedWithin(rpcCtx, rpcStarted, rpcLimit)
	cancelRPC()
	if resultErr != nil || deadlineErr != nil {
		return Result{}, errors.Join(resultErr, deadlineErr)
	}

	bulkLimit := time.Duration(plan.Bulk.PhaseDeadlineSeconds) * time.Second
	bulkCtx, cancelBulk := context.WithTimeout(ctx, bulkLimit)
	bulkStarted := time.Now()
	result.Bulk, resultErr = RunBulk(
		bulkCtx, pair, plan.Bulk.WarmupBytesPerDirection, plan.Bulk.ScoreBytesPerDirection,
	)
	deadlineErr = completedWithin(bulkCtx, bulkStarted, bulkLimit)
	cancelBulk()
	if resultErr != nil || deadlineErr != nil {
		return Result{}, errors.Join(resultErr, deadlineErr)
	}

	cleanupStarted := time.Now()
	cleanupLimit := time.Duration(plan.CleanupDeadlineSeconds) * time.Second
	cleanupCtx, cancelCleanup := context.WithTimeout(ctx, cleanupLimit)
	pairClosed = true
	endpointClosed = true
	resultErr = errors.Join(pair.Close(cleanupCtx), endpoint.Close(cleanupCtx))
	deadlineErr = completedWithin(cleanupCtx, cleanupStarted, cleanupLimit)
	cancelCleanup()
	if resultErr != nil || deadlineErr != nil {
		return Result{}, errors.Join(resultErr, deadlineErr)
	}
	result.CleanupDuration = time.Since(cleanupStarted)
	return result, nil
}

// RunCold issues independently paired tunnel artifacts at the frozen rate.
func RunCold(
	ctx context.Context,
	endpoint *Endpoint,
	operations, maxInflight, startRatePerSecond int,
	operationDeadline, cleanupDeadline time.Duration,
) ([]transportrelease.ConnectOperation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if endpoint == nil || operations < 1 || maxInflight < 1 || maxInflight > operations || startRatePerSecond < 1 || operationDeadline <= 0 || cleanupDeadline <= 0 {
		return nil, errInvalidTunnelColdWorkload
	}
	results := make([]transportrelease.ConnectOperation, operations)
	workerCtx, cancelWorkers := context.WithCancelCause(ctx)
	defer cancelWorkers(nil)
	firstFailure := make(chan error, 1)
	reportFailure := func(err error) {
		if ctx.Err() != nil {
			return
		}
		select {
		case firstFailure <- err:
			cancelWorkers(err)
		default:
		}
	}
	semaphore := make(chan struct{}, maxInflight)
	var group sync.WaitGroup
	phaseStart := time.Now()
	interval := time.Second / time.Duration(startRatePerSecond)
schedule:
	for ordinal := 1; ordinal <= operations; ordinal++ {
		scheduled := phaseStart.Add(time.Duration(ordinal-1) * interval)
		if err := waitUntil(workerCtx, scheduled); err != nil {
			break
		}
		select {
		case semaphore <- struct{}{}:
		case <-workerCtx.Done():
			break schedule
		}
		group.Add(1)
		go func(ordinal int, scheduled time.Time) {
			defer group.Done()
			defer func() { <-semaphore }()
			operationCtx, cancel := context.WithTimeout(workerCtx, operationDeadline)
			defer cancel()
			started := time.Now()
			pair, err := endpoint.Connect(operationCtx)
			duration := time.Since(started)
			if err != nil {
				reportFailure(fmt.Errorf("tunnel cold connection %d: %w", ordinal, err))
				return
			}
			cleanupStarted := time.Now()
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), cleanupDeadline)
			closeErr := pair.Close(cleanupCtx)
			cleanupCancel()
			cleanupDuration := time.Since(cleanupStarted)
			if closeErr != nil {
				reportFailure(fmt.Errorf("tunnel cold connection %d cleanup: %w", ordinal, closeErr))
				return
			}
			results[ordinal-1] = transportrelease.ConnectOperation{
				Ordinal: ordinal, ScheduledAt: scheduled, StartedAt: started,
				Duration: duration, CleanupDuration: cleanupDuration,
			}
		}(ordinal, scheduled)
	}
	group.Wait()
	select {
	case err := <-firstFailure:
		return nil, err
	default:
	}
	if err := contextCompletionError(ctx); err != nil {
		return nil, err
	}
	for index, operation := range results {
		if operation.Ordinal != index+1 || operation.Duration <= 0 || operation.CleanupDuration <= 0 || operation.StartedAt.Before(operation.ScheduledAt) {
			return nil, fmt.Errorf("tunnel cold connection %d is incomplete", index+1)
		}
	}
	return results, nil
}

// RunRPC executes an exact-count echo workload over the encrypted tunnel.
func RunRPC(ctx context.Context, pair *Pair, operations, workers, payloadBytes int, operationDeadline time.Duration) ([]transportrelease.Operation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if pair == nil || pair.Client == nil || operations < 1 || workers < 1 || workers > operations || payloadBytes < 2 || operationDeadline <= 0 {
		return nil, errors.New("invalid tunnel RPC workload")
	}
	payload := json.RawMessage(append(append([]byte{'"'}, bytes.Repeat([]byte{'x'}, payloadBytes-2)...), '"'))
	wantHash := sha256.Sum256(payload)
	results := make([]transportrelease.Operation, operations)
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
					workErrors <- fmt.Errorf("tunnel RPC operation %d: %w", ordinal, err)
					return
				}
				if !bytes.Equal(response, payload) {
					workErrors <- fmt.Errorf("tunnel RPC operation %d payload mismatch", ordinal)
					return
				}
				results[ordinal-1] = transportrelease.Operation{
					Ordinal: ordinal, StartedAt: started, Duration: time.Since(started),
					InputBytes: len(payload), OutputBytes: len(response), PayloadSHA256: wantHash,
				}
			}
		}()
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
	for index, operation := range results {
		if operation.Ordinal != index+1 || operation.Duration <= 0 || operation.InputBytes != payloadBytes || operation.OutputBytes != payloadBytes || operation.PayloadSHA256 != wantHash {
			return nil, fmt.Errorf("tunnel RPC operation %d is incomplete", index+1)
		}
	}
	return results, nil
}

// RunBulk performs warmup and scored simultaneous transfers in both
// endpoint-to-endpoint directions.
func RunBulk(ctx context.Context, pair *Pair, warmupBytesPerDirection, scoreBytesPerDirection int64) (transportrelease.BulkResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if pair == nil || pair.Client == nil || pair.Server == nil || warmupBytesPerDirection < 1 || scoreBytesPerDirection < 1 {
		return transportrelease.BulkResult{}, errors.New("invalid tunnel bulk workload")
	}
	if _, err := runBulkPhase(ctx, pair, warmupBytesPerDirection); err != nil {
		return transportrelease.BulkResult{}, fmt.Errorf("tunnel bulk warmup: %w", err)
	}
	started := time.Now()
	duration, err := runBulkPhase(ctx, pair, scoreBytesPerDirection)
	if err != nil {
		return transportrelease.BulkResult{}, fmt.Errorf("tunnel bulk score: %w", err)
	}
	return transportrelease.BulkResult{StartedAt: started, Duration: duration, BytesPerDirection: scoreBytesPerDirection}, nil
}

type acceptedStream struct {
	kind      string
	direction string
	stream    flowersession.ByteStream
	err       error
}

func runBulkPhase(ctx context.Context, pair *Pair, bytesPerDirection int64) (time.Duration, error) {
	phaseCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	clientAccepted := make(chan acceptedStream, 1)
	serverAccepted := make(chan acceptedStream, 1)
	go acceptReleaseStream(phaseCtx, pair.Client, clientAccepted)
	go acceptReleaseStream(phaseCtx, pair.Server, serverAccepted)
	clientOpened, err := pair.Client.OpenStream(phaseCtx, "release-tunnel-bulk", flowersession.Metadata{"direction": "client-to-server"})
	if err != nil {
		return 0, err
	}
	serverOpened, err := pair.Server.OpenStream(phaseCtx, "release-tunnel-bulk", flowersession.Metadata{"direction": "server-to-client"})
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
	streams := []flowersession.ByteStream{clientOpened, serverOpened, fromClient.stream, fromServer.stream}
	defer func() {
		for _, stream := range streams {
			_ = stream.Close()
		}
	}()
	if fromClient.kind != "release-tunnel-bulk" || fromClient.direction != "client-to-server" ||
		fromServer.kind != "release-tunnel-bulk" || fromServer.direction != "server-to-client" {
		return 0, errors.New("tunnel bulk stream metadata mismatch")
	}
	started := time.Now()
	errorsByDirection := make(chan error, 2)
	go func() {
		errorsByDirection <- transferExact(phaseCtx, clientOpened, fromClient.stream, bytesPerDirection, 0xa5)
	}()
	go func() {
		errorsByDirection <- transferExact(phaseCtx, serverOpened, fromServer.stream, bytesPerDirection, 0x5a)
	}()
	var joined error
	ctxDone := phaseCtx.Done()
	for completed := 0; completed < 2; {
		select {
		case directionErr := <-errorsByDirection:
			joined = errors.Join(joined, directionErr)
			if directionErr != nil {
				cancel(directionErr)
			}
			completed++
		case <-ctxDone:
			joined = errors.Join(joined, context.Cause(phaseCtx))
			for _, stream := range streams {
				_ = stream.Reset()
			}
			ctxDone = nil
		}
	}
	return time.Since(started), joined
}

func acceptReleaseStream(ctx context.Context, session flowersession.SessionV2, result chan<- acceptedStream) {
	incoming, err := session.AcceptStream(ctx)
	result <- acceptedStream{
		kind: incoming.Kind, direction: fmt.Sprint(incoming.Metadata["direction"]), stream: incoming.Stream, err: err,
	}
}

func transferExact(ctx context.Context, writer, reader flowersession.ByteStream, total int64, fill byte) error {
	results := make(chan error, 2)
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
		chunk := bytes.Repeat([]byte{fill}, 64*1024)
		remaining := total
		var writeErr error
		for remaining > 0 {
			current := int64(len(chunk))
			if remaining < current {
				current = remaining
			}
			count, err := writer.Write(chunk[:current])
			remaining -= int64(count)
			if err != nil {
				writeErr = err
				break
			}
			if int64(count) != current {
				writeErr = io.ErrShortWrite
				break
			}
		}
		if writeErr == nil {
			writeErr = writer.CloseWrite()
		}
		results <- writeErr
	}()
	go func() {
		readBytes, readErr := io.CopyN(io.Discard, reader, total)
		if readErr == nil {
			var trailing [1]byte
			if count, err := reader.Read(trailing[:]); count != 0 || !errors.Is(err, io.EOF) {
				readErr = errors.New("tunnel bulk stream did not end at the exact byte boundary")
			}
		}
		if readBytes != total {
			readErr = errors.Join(readErr, fmt.Errorf("tunnel bulk read bytes = %d, want %d", readBytes, total))
		}
		results <- readErr
	}()
	var joined error
	ctxDone := ctx.Done()
	for completed := 0; completed < 2; {
		select {
		case err := <-results:
			joined = errors.Join(joined, err)
			if err != nil {
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

func completedWithin(ctx context.Context, started time.Time, limit time.Duration) error {
	finished := time.Now()
	if limit <= 0 || finished.Sub(started) > limit {
		return context.DeadlineExceeded
	}
	if deadline, ok := ctx.Deadline(); ok && !finished.Before(deadline) {
		return context.DeadlineExceeded
	}
	return context.Cause(ctx)
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
