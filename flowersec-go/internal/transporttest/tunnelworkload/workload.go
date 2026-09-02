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

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv3"
	flowersession "github.com/floegence/flowersec/flowersec-go/v5/internal/sessionv3"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/transporttest"
)

var errInvalidTunnelColdWorkload = errors.New("invalid tunnel cold-connect workload")

// Result contains the unaggregated observations for one topology/profile run.
type Result struct {
	Topology        Topology                         `json:"topology"`
	Cold            []transporttest.ConnectOperation `json:"cold"`
	RPC             []transporttest.Operation        `json:"rpc"`
	Bulk            transporttest.BulkResult         `json:"bulk"`
	CleanupDuration time.Duration                    `json:"cleanup_duration_ns"`
}

func closeTunnelOwners(ctx context.Context, pair *Pair, closeEndpoint func(context.Context) error) error {
	pairErr := pair.Close(ctx)
	endpointErr := closeEndpoint(ctx)
	if pairErr != nil {
		pairErr = fmt.Errorf("close tunnel pair: %w", pairErr)
	}
	if endpointErr != nil {
		endpointErr = fmt.Errorf("close tunnel endpoint: %w", endpointErr)
	}
	return errors.Join(pairErr, endpointErr)
}

// Run executes one frozen cold/RPC/bulk workload and owns final pair and
// endpoint cleanup. The test runner repeats this call for each independent
// run rather than reusing transport state across runs.
func Run(ctx context.Context, endpoint *Endpoint, plan transporttest.ProfilePlan) (result Result, resultErr error) {
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
		return Result{}, tunnelPhaseFailure("cold", coldStarted, resultErr, deadlineErr)
	}

	rpcLimit := time.Duration(plan.RPC.PhaseDeadlineSeconds) * time.Second
	rpcCtx, cancelRPC := context.WithTimeout(ctx, rpcLimit)
	rpcStarted := time.Now()
	pair, err := endpoint.Connect(rpcCtx)
	if err != nil {
		cancelRPC()
		return Result{}, tunnelPhaseFailure("rpc setup", rpcStarted, err)
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
		return Result{}, tunnelPhaseFailure("rpc", rpcStarted, resultErr, deadlineErr)
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
		return Result{}, tunnelPhaseFailure("bulk", bulkStarted, resultErr, deadlineErr)
	}

	cleanupStarted := time.Now()
	cleanupLimit := time.Duration(plan.CleanupDeadlineSeconds) * time.Second
	cleanupCtx, cancelCleanup := context.WithTimeout(ctx, cleanupLimit)
	pairClosed = true
	endpointClosed = true
	resultErr = closeTunnelOwners(cleanupCtx, pair, endpoint.Close)
	deadlineErr = completedWithin(cleanupCtx, cleanupStarted, cleanupLimit)
	cancelCleanup()
	if resultErr != nil || deadlineErr != nil {
		return Result{}, tunnelPhaseFailure("cleanup", cleanupStarted, resultErr, deadlineErr)
	}
	result.CleanupDuration = time.Since(cleanupStarted)
	return result, nil
}

// RunColdDiagnostic exercises the frozen cold-connect phase in the same
// endpoint and fault context as the full workload, then closes the endpoint.
// It intentionally does not enter RPC or bulk phases.
func RunColdDiagnostic(ctx context.Context, endpoint *Endpoint, plan transporttest.ProfilePlan) (result Result, resultErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if endpoint == nil || plan.Cold.Operations < 1 || plan.CleanupDeadlineSeconds < 1 {
		return Result{}, errors.New("invalid production tunnel cold diagnostic")
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
		return Result{}, tunnelPhaseFailure("cold", coldStarted, resultErr, deadlineErr)
	}

	cleanupStarted := time.Now()
	cleanupCtx, cancelCleanup := context.WithTimeout(ctx, time.Duration(plan.CleanupDeadlineSeconds)*time.Second)
	endpointClosed = true
	resultErr = endpoint.Close(cleanupCtx)
	deadlineErr = completedWithin(cleanupCtx, cleanupStarted, time.Duration(plan.CleanupDeadlineSeconds)*time.Second)
	cancelCleanup()
	if resultErr != nil || deadlineErr != nil {
		return Result{}, tunnelPhaseFailure("cleanup", cleanupStarted, resultErr, deadlineErr)
	}
	result.CleanupDuration = time.Since(cleanupStarted)
	return result, nil
}

func tunnelPhaseFailure(phase string, started time.Time, failures ...error) error {
	return fmt.Errorf("tunnel %s phase after %s: %w", phase, time.Since(started), errors.Join(failures...))
}

// RunCold issues independently paired tunnel artifacts at the frozen rate.
func RunCold(
	ctx context.Context,
	endpoint *Endpoint,
	operations, maxInflight, startRatePerSecond int,
	operationDeadline, cleanupDeadline time.Duration,
) ([]transporttest.ConnectOperation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if endpoint == nil || operations < 1 || maxInflight < 1 || maxInflight > operations || startRatePerSecond < 1 || operationDeadline <= 0 || cleanupDeadline <= 0 {
		return nil, errInvalidTunnelColdWorkload
	}
	results := make([]transporttest.ConnectOperation, operations)
	workerCtx, cancelWorkers := context.WithCancelCause(ctx)
	defer cancelWorkers(nil)
	firstFailure := make(chan error, 1)
	reportFailure := func(err error) {
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
			results[ordinal-1] = transporttest.ConnectOperation{
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
func RunRPC(ctx context.Context, pair *Pair, operations, workers, payloadBytes int, operationDeadline time.Duration) ([]transporttest.Operation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if pair == nil || pair.Client == nil || operations < 1 || workers < 1 || workers > operations || payloadBytes < 2 || operationDeadline <= 0 {
		return nil, errors.New("invalid tunnel RPC workload")
	}
	payload := json.RawMessage(append(append([]byte{'"'}, bytes.Repeat([]byte{'x'}, payloadBytes-2)...), '"'))
	wantHash := sha256.Sum256(payload)
	results := make([]transporttest.Operation, operations)
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
				results[ordinal-1] = transporttest.Operation{
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
func RunBulk(ctx context.Context, pair *Pair, warmupBytesPerDirection, scoreBytesPerDirection int64) (transporttest.BulkResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if pair == nil || pair.Client == nil || pair.Server == nil || warmupBytesPerDirection < 1 || scoreBytesPerDirection < 1 {
		return transporttest.BulkResult{}, errors.New("invalid tunnel bulk workload")
	}
	bulkStarted := time.Now()
	bulkRemaining := deadlineRemaining(ctx)
	streams, setup, err := openBulkStreams(ctx, pair)
	if err != nil {
		return transporttest.BulkResult{}, wrapBulkPhaseFailure("warmup", err, 0, bulkRemaining, bulkPhaseTiming{setup: setup})
	}
	defer streams.close()
	directions := []bulkDirection{{
		name: "client-to-server", writer: streams.clientOpened, reader: streams.fromClient, fill: 0xa5,
	}, {
		name: "server-to-client", writer: streams.serverOpened, reader: streams.fromServer, fill: 0x5a,
	}}
	phaseCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	results := make(chan bulkDirectionResult, len(directions))
	for _, direction := range directions {
		go func(direction bulkDirection) {
			result := runBulkDirection(phaseCtx, direction, warmupBytesPerDirection, scoreBytesPerDirection)
			if result.err != nil {
				cancel(result.err)
			}
			results <- result
		}(direction)
	}
	var joined error
	var scoreStarted time.Time
	var scoreDuration time.Duration
	for range directions {
		result := <-results
		if result.err != nil {
			joined = errors.Join(joined, fmt.Errorf("%s %s: %w", result.name, result.stage, result.err))
		}
		if scoreStarted.IsZero() || (!result.scoreStarted.IsZero() && result.scoreStarted.Before(scoreStarted)) {
			scoreStarted = result.scoreStarted
		}
		if result.scoreDuration > scoreDuration {
			scoreDuration = result.scoreDuration
		}
	}
	if joined != nil {
		return transporttest.BulkResult{}, wrapBulkPhaseFailure(
			"directional", joined, time.Since(bulkStarted), deadlineRemaining(ctx), bulkPhaseTiming{setup: setup},
		)
	}
	return transporttest.BulkResult{StartedAt: scoreStarted, Duration: scoreDuration, BytesPerDirection: scoreBytesPerDirection}, nil
}

type bulkDirection struct {
	name   string
	writer flowersession.ByteStream
	reader flowersession.ByteStream
	fill   byte
}

type bulkDirectionResult struct {
	name          string
	stage         string
	scoreStarted  time.Time
	scoreDuration time.Duration
	err           error
}

func runBulkDirection(ctx context.Context, direction bulkDirection, warmupBytes, scoreBytes int64) bulkDirectionResult {
	result := bulkDirectionResult{name: direction.name, stage: "warmup"}
	if err := transferExactPhase(ctx, direction.writer, direction.reader, warmupBytes, direction.fill, false); err != nil {
		result.err = err
		return result
	}
	result.stage = "score"
	result.scoreStarted = time.Now()
	result.err = transferExactPhase(ctx, direction.writer, direction.reader, scoreBytes, direction.fill, true)
	result.scoreDuration = time.Since(result.scoreStarted)
	return result
}

type bulkPhaseTiming struct {
	setup    time.Duration
	transfer time.Duration
}

func wrapBulkPhaseFailure(phase string, err error, priorElapsed, remainingAtStart time.Duration, timing bulkPhaseTiming) error {
	return fmt.Errorf(
		"tunnel bulk %s: prior_elapsed=%s remaining_at_start=%s setup=%s transfer=%s: %w",
		phase, priorElapsed, remainingAtStart, timing.setup, timing.transfer, err,
	)
}

func deadlineRemaining(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	remaining := time.Until(deadline)
	if remaining < 0 {
		return 0
	}
	return remaining
}

type acceptedStream struct {
	kind      string
	direction string
	stream    flowersession.ByteStream
	err       error
}

type bulkStreams struct {
	clientOpened flowersession.ByteStream
	serverOpened flowersession.ByteStream
	fromClient   flowersession.ByteStream
	fromServer   flowersession.ByteStream
}

func (streams bulkStreams) all() []flowersession.ByteStream {
	return []flowersession.ByteStream{streams.clientOpened, streams.serverOpened, streams.fromClient, streams.fromServer}
}

func (streams bulkStreams) close() {
	for _, stream := range streams.all() {
		if stream != nil {
			_ = stream.Close()
		}
	}
}

func openBulkStreams(ctx context.Context, pair *Pair) (bulkStreams, time.Duration, error) {
	started := time.Now()
	clientAccepted := make(chan acceptedStream, 1)
	serverAccepted := make(chan acceptedStream, 1)
	go acceptReleaseStream(ctx, pair.Client, clientAccepted)
	go acceptReleaseStream(ctx, pair.Server, serverAccepted)
	clientOpened, err := pair.Client.OpenStream(ctx, "release-tunnel-bulk", flowersession.Metadata{"direction": "client-to-server"})
	if err != nil {
		return bulkStreams{}, time.Since(started), err
	}
	serverOpened, err := pair.Server.OpenStream(ctx, "release-tunnel-bulk", flowersession.Metadata{"direction": "server-to-client"})
	if err != nil {
		_ = clientOpened.Reset()
		return bulkStreams{}, time.Since(started), err
	}
	fromClient := <-serverAccepted
	fromServer := <-clientAccepted
	if fromClient.err != nil || fromServer.err != nil {
		_ = clientOpened.Reset()
		_ = serverOpened.Reset()
		return bulkStreams{}, time.Since(started), errors.Join(fromClient.err, fromServer.err)
	}
	streams := bulkStreams{clientOpened: clientOpened, serverOpened: serverOpened, fromClient: fromClient.stream, fromServer: fromServer.stream}
	if fromClient.kind != "release-tunnel-bulk" || fromClient.direction != "client-to-server" ||
		fromServer.kind != "release-tunnel-bulk" || fromServer.direction != "server-to-client" {
		streams.close()
		return bulkStreams{}, time.Since(started), errors.New("tunnel bulk stream metadata mismatch")
	}
	return streams, time.Since(started), nil
}

func acceptReleaseStream(ctx context.Context, session flowersession.Session, result chan<- acceptedStream) {
	incoming, err := session.AcceptStream(ctx)
	result <- acceptedStream{
		kind: incoming.Kind, direction: fmt.Sprint(incoming.Metadata["direction"]), stream: incoming.Stream, err: err,
	}
}

func transferExact(ctx context.Context, writer, reader flowersession.ByteStream, total int64, fill byte) error {
	return transferExactPhase(ctx, writer, reader, total, fill, true)
}

func transferExactPhase(ctx context.Context, writer, reader flowersession.ByteStream, total int64, fill byte, final bool) error {
	results := make(chan error, 2)
	var writtenBytes, readBytes atomic.Int64
	var writeDone, readDone atomic.Bool
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
		chunk := bytes.Repeat([]byte{fill}, protocolv3.MaxDataBytes)
		remaining := total
		var writeErr error
		for remaining > 0 {
			current := int64(len(chunk))
			if remaining < current {
				current = remaining
			}
			count, err := writer.Write(chunk[:current])
			remaining -= int64(count)
			writtenBytes.Add(int64(count))
			if err != nil {
				writeErr = err
				break
			}
			if int64(count) != current {
				writeErr = io.ErrShortWrite
				break
			}
		}
		if writeErr == nil && final {
			writeErr = writer.CloseWrite()
		}
		writeDone.Store(true)
		results <- writeErr
	}()
	go func() {
		copied, readErr := io.CopyN(atomicDiscard{count: &readBytes}, reader, total)
		if readErr == nil && final {
			var trailing [1]byte
			if count, err := reader.Read(trailing[:]); count != 0 || !errors.Is(err, io.EOF) {
				readErr = errors.New("tunnel bulk stream did not end at the exact byte boundary")
			}
		}
		if copied != total {
			readErr = errors.Join(readErr, fmt.Errorf("tunnel bulk read bytes = %d, want %d", copied, total))
		}
		readDone.Store(true)
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
			joined = errors.Join(joined, context.Cause(ctx), fmt.Errorf(
				"tunnel bulk progress: written=%d/%d read=%d/%d write_done=%t read_done=%t",
				writtenBytes.Load(), total, readBytes.Load(), total, writeDone.Load(), readDone.Load(),
			))
			reset()
			ctxDone = nil
		}
	}
	return joined
}

type atomicDiscard struct {
	count *atomic.Int64
}

func (writer atomicDiscard) Write(payload []byte) (int, error) {
	writer.count.Add(int64(len(payload)))
	return len(payload), nil
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
