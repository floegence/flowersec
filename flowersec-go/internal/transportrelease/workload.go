package transportrelease

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
)

// Operation records one real workload operation without pre-aggregating its
// timing or byte evidence.
type Operation struct {
	Ordinal       int           `json:"ordinal"`
	ScheduledAt   time.Time     `json:"scheduled_at"`
	StartedAt     time.Time     `json:"started_at"`
	Duration      time.Duration `json:"duration_ns"`
	InputBytes    int           `json:"input_bytes"`
	OutputBytes   int           `json:"output_bytes"`
	PayloadSHA256 [32]byte      `json:"payload_sha256"`
}

// ConnectOperation records one distinct artifact-to-READY connection and its
// bounded cleanup. ScheduledAt is the frozen rate schedule, not a reconstruction.
type ConnectOperation struct {
	Ordinal          int           `json:"ordinal"`
	ScheduledAt      time.Time     `json:"scheduled_at"`
	StartedAt        time.Time     `json:"started_at"`
	Duration         time.Duration `json:"duration_ns"`
	CleanupDuration  time.Duration `json:"cleanup_duration_ns"`
	StartedCandidate string        `json:"started_candidate"`
	WinnerCandidate  string        `json:"winner_candidate"`
	CommitCount      int           `json:"commit_count"`
	CredentialWrites int           `json:"credential_write_count"`
}

type BulkPhaseDirection struct {
	Direction     string        `json:"direction"`
	ScheduledAt   time.Time     `json:"scheduled_at"`
	StartedAt     time.Time     `json:"started_at"`
	Duration      time.Duration `json:"duration_ns"`
	Bytes         int64         `json:"bytes"`
	PayloadSHA256 [32]byte      `json:"payload_sha256"`
}

type BulkDirection struct {
	Direction string             `json:"direction"`
	Warmup    BulkPhaseDirection `json:"warmup"`
	Score     BulkPhaseDirection `json:"score"`
}

// BulkResult records both measured directions and preserves the slower scored
// duration used by the release metric contract.
type BulkResult struct {
	StartedAt         time.Time       `json:"started_at"`
	Duration          time.Duration   `json:"duration_ns"`
	BytesPerDirection int64           `json:"bytes_per_direction"`
	ActiveStreams     int             `json:"active_streams"`
	Directions        []BulkDirection `json:"directions"`
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
			candidate := directCandidateID(endpoint.kind)
			spends := pair.SpendCount()
			results[ordinal-1] = ConnectOperation{
				Ordinal: ordinal, ScheduledAt: scheduled, StartedAt: started,
				Duration: duration, CleanupDuration: cleanupDuration,
				StartedCandidate: candidate, WinnerCandidate: candidate,
				CommitCount: int(spends), CredentialWrites: int(spends),
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
		if result.Ordinal != index+1 || result.Duration <= 0 || result.CleanupDuration <= 0 || result.StartedAt.Before(result.ScheduledAt) ||
			result.StartedCandidate == "" || result.WinnerCandidate != result.StartedCandidate || result.CommitCount != 1 || result.CredentialWrites != 1 {
			return nil, fmt.Errorf("cold connection %d is incomplete", index+1)
		}
	}
	return results, nil
}

func directCandidateID(kind carrier.Kind) string {
	switch kind {
	case carrier.KindWebSocket:
		return "direct-wss"
	case carrier.KindQUIC:
		return "direct-raw-quic"
	case carrier.KindWebTransport:
		return "direct-webtransport"
	default:
		return ""
	}
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
	phaseStart := time.Now()
	const interval = time.Millisecond
	semaphore := make(chan struct{}, workers)
	var group sync.WaitGroup
	workErrors := make(chan error, operations)
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
				Ordinal: ordinal, ScheduledAt: scheduled, StartedAt: started, Duration: duration,
				InputBytes: len(payload), OutputBytes: len(response), PayloadSHA256: wantHash,
			}
		}(ordinal, scheduled)
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
		if result.Ordinal != index+1 || !result.ScheduledAt.Equal(phaseStart.Add(time.Duration(index)*interval)) || result.StartedAt.Before(result.ScheduledAt) ||
			result.Duration <= 0 || result.InputBytes != payloadBytes || result.OutputBytes != payloadBytes || result.PayloadSHA256 != wantHash {
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
	warmup, _, err := runBulkPhase(ctx, pair, warmupBytesPerDirection)
	if err != nil {
		return BulkResult{}, fmt.Errorf("bulk warmup: %w", err)
	}
	score, activeStreams, err := runBulkPhase(ctx, pair, scoreBytesPerDirection)
	if err != nil {
		return BulkResult{}, fmt.Errorf("bulk score: %w", err)
	}
	if len(warmup) != 2 || len(score) != 2 {
		return BulkResult{}, errors.New("bulk direction evidence is incomplete")
	}
	directions := make([]BulkDirection, 2)
	for index, direction := range []string{"client-to-server", "server-to-client"} {
		if warmup[index].Direction != direction || score[index].Direction != direction {
			return BulkResult{}, errors.New("bulk direction evidence order is invalid")
		}
		directions[index] = BulkDirection{Direction: direction, Warmup: warmup[index], Score: score[index]}
	}
	duration := max(score[0].Duration, score[1].Duration)
	started := score[0].StartedAt
	if score[1].StartedAt.Before(started) {
		started = score[1].StartedAt
	}
	return BulkResult{StartedAt: started, Duration: duration, BytesPerDirection: scoreBytesPerDirection, ActiveStreams: activeStreams, Directions: directions}, nil
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

func runBulkPhase(ctx context.Context, pair *ProductDirectPair, bytesPerDirection int64) ([]BulkPhaseDirection, int, error) {
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
		return nil, 0, err
	}
	serverOpened, err := pair.Server.OpenStream(phaseCtx, "release-bulk", flowersession.Metadata{"direction": "server-to-client"})
	if err != nil {
		_ = clientOpened.Reset()
		return nil, 0, err
	}
	fromClient := <-serverAccepted
	fromServer := <-clientAccepted
	if fromClient.err != nil || fromServer.err != nil {
		_ = clientOpened.Reset()
		_ = serverOpened.Reset()
		return nil, 0, errors.Join(fromClient.err, fromServer.err)
	}
	streams := []releaseByteStream{clientOpened, serverOpened, fromClient.stream, fromServer.stream}
	defer func() {
		for _, stream := range streams {
			_ = stream.Close()
		}
	}()
	if fromClient.kind != "release-bulk" || fromClient.direction != "client-to-server" ||
		fromServer.kind != "release-bulk" || fromServer.direction != "server-to-client" {
		return nil, 0, errors.New("bulk stream metadata mismatch")
	}
	activeStreams := 2
	phaseStart := time.Now()
	resultsByDirection := make(chan BulkPhaseDirection, 2)
	errorsByDirection := make(chan error, 2)
	go func() {
		scheduled := phaseStart
		if waitErr := waitUntil(phaseCtx, scheduled); waitErr != nil {
			resultsByDirection <- BulkPhaseDirection{Direction: "client-to-server", ScheduledAt: scheduled}
			errorsByDirection <- waitErr
			return
		}
		measurement, directionErr := transferExactMeasured(phaseCtx, clientOpened, fromClient.stream, bytesPerDirection, 0xa5)
		measurement.Direction = "client-to-server"
		measurement.ScheduledAt = scheduled
		if directionErr != nil {
			cancel(directionErr)
		}
		resultsByDirection <- measurement
		errorsByDirection <- directionErr
	}()
	go func() {
		scheduled := phaseStart.Add(time.Millisecond)
		if waitErr := waitUntil(phaseCtx, scheduled); waitErr != nil {
			resultsByDirection <- BulkPhaseDirection{Direction: "server-to-client", ScheduledAt: scheduled}
			errorsByDirection <- waitErr
			return
		}
		measurement, directionErr := transferExactMeasured(phaseCtx, serverOpened, fromServer.stream, bytesPerDirection, 0x5a)
		measurement.Direction = "server-to-client"
		measurement.ScheduledAt = scheduled
		if directionErr != nil {
			cancel(directionErr)
		}
		resultsByDirection <- measurement
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
	measurements := []BulkPhaseDirection{<-resultsByDirection, <-resultsByDirection}
	slices.SortFunc(measurements, func(left, right BulkPhaseDirection) int { return strings.Compare(left.Direction, right.Direction) })
	return measurements, activeStreams, err
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
	_, err := transferExactMeasured(ctx, writer, reader, total, fill)
	return err
}

func transferExactMeasured(ctx context.Context, writer, reader releaseByteStream, total int64, fill byte) (BulkPhaseDirection, error) {
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
	started := time.Now()
	writtenHash := sha256.New()
	readHash := sha256.New()
	go func() {
		chunk := bytes.Repeat([]byte{fill}, 64*1024)
		remaining := total
		var err error
		for remaining > 0 {
			current := int64(len(chunk))
			if remaining < current {
				current = remaining
			}
			var count int
			count, err = io.MultiWriter(writer, writtenHash).Write(chunk[:current])
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
		readBytes, readErr := io.CopyN(readHash, reader, total)
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
	measurement := BulkPhaseDirection{StartedAt: started, Duration: time.Since(started), Bytes: total}
	copy(measurement.PayloadSHA256[:], readHash.Sum(nil))
	if !bytes.Equal(writtenHash.Sum(nil), readHash.Sum(nil)) {
		joined = errors.Join(joined, errors.New("bulk payload digest mismatch"))
	}
	return measurement, joined
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
