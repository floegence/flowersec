package performance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	flowersession "github.com/floegence/flowersec/flowersec-go/v3/internal/sessionv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/transporttest"
)

type payloadThroughputContract struct {
	PayloadBytes      int
	Concurrency       int
	SampleDuration    time.Duration
	Samples           int
	MinBytesPerSecond float64
	MaxP95            time.Duration
	Direction         payloadDirection
}

type payloadDirection string

const (
	payloadClientToServer payloadDirection = "client-to-server"
	payloadServerToClient payloadDirection = "server-to-client"
	payloadFullDuplex     payloadDirection = "full-duplex"
)

func productionPayloadThroughputContract() payloadThroughputContract {
	contract := payloadThroughputContract{
		PayloadBytes: 64 << 10, Concurrency: 4, SampleDuration: 5 * time.Second, Samples: 3,
		MinBytesPerSecond: 1 << 20, MaxP95: 2 * time.Second, Direction: payloadClientToServer,
	}
	if duration, configured := scaledPerformanceDuration(700 * time.Millisecond); configured {
		contract.SampleDuration = duration
	}
	return contract
}

func productionSingleConnectionThroughputContracts() []payloadThroughputContract {
	result := make([]payloadThroughputContract, 0, 3)
	sampleDuration := 5 * time.Second
	if duration, configured := scaledPerformanceDuration(700 * time.Millisecond); configured {
		sampleDuration = duration
	}
	for _, direction := range []payloadDirection{payloadClientToServer, payloadServerToClient, payloadFullDuplex} {
		result = append(result, payloadThroughputContract{PayloadBytes: 1 << 20, Concurrency: 1, SampleDuration: sampleDuration, Samples: 3, MinBytesPerSecond: 1 << 20, MaxP95: 2 * time.Second, Direction: direction})
	}
	return result
}

func productionStreamingThroughputContracts() []payloadThroughputContract {
	result := make([]payloadThroughputContract, 0, 9)
	sampleDuration := 5 * time.Second
	if duration, configured := scaledPerformanceDuration(700 * time.Millisecond); configured {
		sampleDuration = duration
	}
	for _, payloadBytes := range []int{1 << 10, 64 << 10, 1 << 20} {
		for _, direction := range []payloadDirection{payloadClientToServer, payloadServerToClient, payloadFullDuplex} {
			result = append(result, payloadThroughputContract{PayloadBytes: payloadBytes, Concurrency: 4, SampleDuration: sampleDuration, Samples: 3, MinBytesPerSecond: 1 << 20, MaxP95: 2 * time.Second, Direction: direction})
		}
	}
	return result
}

type payloadThroughputSample struct {
	Bytes              uint64
	Duration           time.Duration
	BytesPerSecond     float64
	Latencies          []time.Duration
	FINCleanupFailures uint64
	ResetCount         uint64
}

type payloadThroughputResult struct {
	Carrier   carrier.Kind
	Baseline  caseResourceRecord
	Resources []caseResourceRecord
	Samples   []payloadThroughputSample
	Summary   payloadThroughputSummary
}

type payloadThroughputSummary struct {
	Bytes          uint64
	Duration       time.Duration
	BytesPerSecond float64
	P50            time.Duration
	P95            time.Duration
	P99            time.Duration
}

func validatePayloadThroughputContract(contract payloadThroughputContract) error {
	if contract.Direction == "" {
		contract.Direction = payloadClientToServer
	}
	if contract.PayloadBytes <= 0 || contract.Concurrency <= 0 || contract.SampleDuration <= 0 || contract.Samples < 3 ||
		contract.MinBytesPerSecond <= 0 || contract.MaxP95 <= 0 {
		return errors.New("payload throughput contract is incomplete")
	}
	if contract.Direction != payloadClientToServer && contract.Direction != payloadServerToClient && contract.Direction != payloadFullDuplex {
		return errors.New("payload throughput direction is invalid")
	}
	return nil
}

func validatePayloadThroughputCarrier(kind carrier.Kind) error {
	if kind != carrier.KindWebSocket && kind != carrier.KindRawQUIC && kind != carrier.KindWebTransport {
		return fmt.Errorf("payload throughput workload does not own carrier %q", kind)
	}
	return nil
}

func runProductionPayloadThroughput(ctx context.Context, kind carrier.Kind, contract payloadThroughputContract) (result payloadThroughputResult, resultErr error) {
	result.Carrier = kind
	if err := validatePayloadThroughputContract(contract); err != nil {
		return result, err
	}
	if err := validatePayloadThroughputCarrier(kind); err != nil {
		return result, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	base, err := transporttest.CaptureResourceSnapshot()
	if err != nil {
		return result, fmt.Errorf("capture %s payload throughput baseline: %w", kind, err)
	}
	resourceStarted := time.Now()
	result.Baseline = caseResourceRecord{Phase: "baseline", RSSBytes: base.RSSBytes, OpenFDs: base.OpenFDs, Goroutines: base.Goroutines, Tasks: base.Tasks}
	result.Resources = append(result.Resources, result.Baseline)
	endpoint, err := transporttest.OpenProductDirectEndpoint(ctx, kind)
	if err != nil {
		return result, fmt.Errorf("open %s payload throughput endpoint: %w", kind, err)
	}
	defer func() {
		if closeErr := endpoint.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close %s payload throughput endpoint: %w", kind, closeErr))
		}
	}()

	payload := makePayload(contract.PayloadBytes)
	if contract.Direction == "" {
		contract.Direction = payloadClientToServer
	}
	result.Samples = make([]payloadThroughputSample, 0, contract.Samples)
	for sample := 0; sample < contract.Samples; sample++ {
		pair, connectErr := endpoint.Connect(ctx)
		if connectErr != nil {
			return result, fmt.Errorf("connect %s payload throughput sample %d: %w", kind, sample+1, connectErr)
		}
		warmupBytes := min(len(payload), 64<<10)
		if warmupErr := pair.RoundTrip(ctx, payload[:warmupBytes], payload[:warmupBytes]); warmupErr != nil {
			_ = pair.Close()
			return result, fmt.Errorf("warm up %s payload throughput sample %d: %w", kind, sample+1, warmupErr)
		}
		measured, err := runPayloadThroughputSample(ctx, pair, payload, contract)
		closeErr := pair.Close()
		if err != nil {
			return result, errors.Join(fmt.Errorf("%s payload throughput sample %d: %w", kind, sample+1, err), closeErr)
		}
		if closeErr != nil {
			return result, fmt.Errorf("close %s payload throughput sample %d: %w", kind, sample+1, closeErr)
		}
		result.Samples = append(result.Samples, measured)
		snapshot, snapshotErr := transporttest.CaptureResourceSnapshot()
		if snapshotErr != nil {
			return result, fmt.Errorf("capture %s payload throughput sample %d resources: %w", kind, sample+1, snapshotErr)
		}
		if snapshot.CPUNanoseconds < base.CPUNanoseconds {
			return result, errors.New("payload throughput CPU counter moved backwards")
		}
		result.Resources = append(result.Resources, caseResourceRecord{Phase: fmt.Sprintf("measured sample %d", sample+1), AtNS: time.Since(resourceStarted).Nanoseconds(), RSSBytes: snapshot.RSSBytes, CPUNanoseconds: snapshot.CPUNanoseconds - base.CPUNanoseconds, OpenFDs: snapshot.OpenFDs, Goroutines: snapshot.Goroutines, Tasks: snapshot.Tasks})
	}
	result.Summary = summarizePayloadThroughput(result)
	if err := validatePayloadThroughputResult(contract, result); err != nil {
		return result, fmt.Errorf("%s payload throughput budget: %w", kind, err)
	}
	return result, nil
}

func runPayloadThroughputSample(ctx context.Context, pair *transporttest.ProductDirectPair, payload []byte, contract payloadThroughputContract) (payloadThroughputSample, error) {
	if pair == nil || pair.Client == nil || pair.Server == nil {
		return payloadThroughputSample{}, errors.New("payload throughput session is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	started := time.Now()
	scheduleDeadline := started.Add(contract.SampleDuration)
	lifecycle := &payloadThroughputLifecycleCounters{}
	var establishMu sync.Mutex
	workerResults, err := runPayloadThroughputWorkers(ctx, contract.Concurrency, func(operationCtx context.Context, _ int) (payloadThroughputWorkerResult, error) {
		requestBytes, workerLatencies, workerErr := runPayloadThroughputStreamDirection(operationCtx, pair, payload, scheduleDeadline, contract.Direction, &establishMu, lifecycle)
		return payloadThroughputWorkerResult{Bytes: requestBytes, Latencies: workerLatencies}, workerErr
	})
	if err != nil {
		return payloadThroughputSample{}, err
	}
	measured := payloadThroughputSample{Duration: time.Since(started), ResetCount: lifecycle.resets.Load()}
	for _, workerResult := range workerResults {
		measured.Bytes += workerResult.Bytes
		measured.Latencies = append(measured.Latencies, workerResult.Latencies...)
	}
	expectedCleanFINs := uint64(contract.Concurrency * 2)
	cleanFINs := lifecycle.cleanFINs.Load()
	if cleanFINs < expectedCleanFINs {
		measured.FINCleanupFailures = expectedCleanFINs - cleanFINs
	} else if cleanFINs > expectedCleanFINs {
		measured.FINCleanupFailures = cleanFINs - expectedCleanFINs
	}
	if measured.FINCleanupFailures != 0 || measured.ResetCount != 0 {
		return measured, fmt.Errorf("payload throughput stream cleanup: clean FIN endpoints = %d/%d, resets = %d", cleanFINs, expectedCleanFINs, measured.ResetCount)
	}
	if measured.Duration <= 0 || measured.Bytes == 0 || len(measured.Latencies) < contract.Concurrency {
		return payloadThroughputSample{}, errors.New("payload throughput sample completed without the minimum measured operations")
	}
	measured.BytesPerSecond = float64(measured.Bytes) / measured.Duration.Seconds()
	return measured, nil
}

type payloadThroughputWorkerResult struct {
	Bytes     uint64
	Latencies []time.Duration
}

func runPayloadThroughputWorkers(ctx context.Context, concurrency int, worker func(context.Context, int) (payloadThroughputWorkerResult, error)) ([]payloadThroughputWorkerResult, error) {
	operationCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	results := make(chan payloadThroughputWorkerResult, concurrency)
	var group sync.WaitGroup
	for workerIndex := 0; workerIndex < concurrency; workerIndex++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			result, err := worker(operationCtx, index)
			if err != nil {
				cancel(err)
				return
			}
			results <- result
		}(workerIndex)
	}
	group.Wait()
	close(results)
	if err := context.Cause(operationCtx); err != nil {
		return nil, err
	}
	collected := make([]payloadThroughputWorkerResult, 0, concurrency)
	for result := range results {
		collected = append(collected, result)
	}
	if len(collected) != concurrency {
		return nil, fmt.Errorf("payload throughput workers = %d, want %d", len(collected), concurrency)
	}
	return collected, nil
}

type payloadThroughputLifecycleCounters struct {
	cleanFINs atomic.Uint64
	resets    atomic.Uint64
}

type payloadThroughputStreamOwner struct {
	ctx              context.Context
	stream           throughputByteStream
	lifecycle        *payloadThroughputLifecycleCounters
	resetOnce        sync.Once
	resetErr         error
	stopCancellation func() bool
	cancellationDone chan struct{}
	finishOnce       sync.Once
	finishErr        error
}

func newPayloadThroughputStreamOwner(ctx context.Context, stream throughputByteStream, lifecycle *payloadThroughputLifecycleCounters) *payloadThroughputStreamOwner {
	if ctx == nil {
		ctx = context.Background()
	}
	owner := &payloadThroughputStreamOwner{ctx: ctx, stream: stream, lifecycle: lifecycle, cancellationDone: make(chan struct{})}
	owner.stopCancellation = context.AfterFunc(ctx, func() {
		owner.reset()
		close(owner.cancellationDone)
	})
	return owner
}

func (owner *payloadThroughputStreamOwner) reset() {
	owner.resetOnce.Do(func() {
		if owner.lifecycle != nil {
			owner.lifecycle.resets.Add(1)
		}
		owner.resetErr = owner.stream.Reset()
	})
}

func (owner *payloadThroughputStreamOwner) Finish(clean bool) error {
	owner.finishOnce.Do(func() {
		if !clean {
			owner.reset()
		}
		if !owner.stopCancellation() {
			<-owner.cancellationDone
			owner.finishErr = errors.Join(context.Cause(owner.ctx), owner.resetErr)
			return
		}
		if !clean {
			owner.finishErr = owner.resetErr
			return
		}
		if owner.lifecycle != nil {
			owner.lifecycle.cleanFINs.Add(1)
		}
	})
	return owner.finishErr
}

type payloadThroughputReceiverWorker struct {
	ready chan error
	done  chan error
}

func startPayloadThroughputReceiver(
	ctx context.Context,
	cancel context.CancelCauseFunc,
	lifecycle *payloadThroughputLifecycleCounters,
	accept func(context.Context) (string, throughputByteStream, error),
	serve func(string, throughputByteStream) error,
) *payloadThroughputReceiverWorker {
	worker := &payloadThroughputReceiverWorker{ready: make(chan error, 1), done: make(chan error, 1)}
	go func() {
		kind, stream, err := accept(ctx)
		if err != nil {
			worker.ready <- err
			cancel(err)
			worker.done <- err
			return
		}
		owner := newPayloadThroughputStreamOwner(ctx, stream, lifecycle)
		worker.ready <- nil
		err = serve(kind, stream)
		err = errors.Join(err, owner.Finish(err == nil))
		if err != nil {
			cancel(err)
		}
		worker.done <- err
	}()
	return worker
}

func (worker *payloadThroughputReceiverWorker) WaitReady(ctx context.Context) error {
	select {
	case err := <-worker.ready:
		return err
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (worker *payloadThroughputReceiverWorker) Wait() error { return <-worker.done }

func joinPayloadThroughputAttemptError(primary, receiver error) error {
	if primary == nil {
		return receiver
	}
	if receiver == nil || errors.Is(receiver, primary) {
		return primary
	}
	return errors.Join(primary, receiver)
}

func runPayloadThroughputStream(ctx context.Context, pair *transporttest.ProductDirectPair, payload []byte, deadline time.Time, establishMu *sync.Mutex, lifecycle *payloadThroughputLifecycleCounters) (sent uint64, latencies []time.Duration, resultErr error) {
	establishMu.Lock()
	locked := true
	defer func() {
		if locked {
			establishMu.Unlock()
		}
	}()
	attemptCtx, cancelAttempt := context.WithCancelCause(ctx)
	receiver := startPayloadThroughputReceiver(attemptCtx, cancelAttempt, lifecycle, func(acceptCtx context.Context) (string, throughputByteStream, error) {
		incoming, err := pair.Server.AcceptStream(acceptCtx)
		if err != nil {
			return "", nil, err
		}
		return incoming.Kind, incoming.Stream, nil
	}, func(kind string, stream throughputByteStream) error {
		return receiveAcknowledgedPayloads(stream, kind, payload, "payload throughput request mismatch")
	})
	receiverJoined := false
	defer func() {
		if resultErr != nil {
			cancelAttempt(resultErr)
		} else {
			cancelAttempt(nil)
		}
		if !receiverJoined {
			resultErr = joinPayloadThroughputAttemptError(resultErr, receiver.Wait())
		}
	}()
	metadata, err := flowersec.NewStreamMetadata(map[string]any{"direction": "client-to-server"})
	if err != nil {
		return 0, nil, err
	}
	stream, err := pair.Client.OpenStream(attemptCtx, "performance-throughput", metadata)
	if err != nil {
		return 0, nil, err
	}
	owner := newPayloadThroughputStreamOwner(attemptCtx, stream, lifecycle)
	completed := false
	defer func() { resultErr = errors.Join(resultErr, owner.Finish(completed)) }()
	if err := receiver.WaitReady(attemptCtx); err != nil {
		return 0, nil, err
	}
	establishMu.Unlock()
	locked = false
	ack := make([]byte, 1)
	for time.Now().Before(deadline) {
		if remaining := time.Until(deadline); remaining <= contractPayloadOperationGuard() {
			break
		}
		operationStarted := time.Now()
		written, err := stream.Write(payload)
		if err != nil {
			return sent, latencies, err
		}
		if written != len(payload) {
			return sent, latencies, fmt.Errorf("payload throughput short write: %d/%d", written, len(payload))
		}
		if _, err := io.ReadFull(stream, ack); err != nil || ack[0] != 0xa5 {
			return sent, latencies, errors.Join(errors.New("payload throughput acknowledgement mismatch"), err)
		}
		sent += uint64(written)
		latencies = append(latencies, time.Since(operationStarted))
	}
	if err := stream.CloseWrite(); err != nil {
		return sent, latencies, err
	}
	receiverErr := receiver.Wait()
	receiverJoined = true
	if receiverErr != nil {
		return sent, latencies, receiverErr
	}
	if err := requireCleanPayloadThroughputEOF(stream); err != nil {
		return sent, latencies, err
	}
	completed = true
	return sent, latencies, nil
}

type throughputByteStream interface {
	io.Reader
	io.Writer
	io.Closer
	CloseWrite() error
	Reset() error
}

func runPayloadThroughputStreamDirection(ctx context.Context, pair *transporttest.ProductDirectPair, payload []byte, deadline time.Time, direction payloadDirection, establishMu *sync.Mutex, lifecycle *payloadThroughputLifecycleCounters) (uint64, []time.Duration, error) {
	if direction == "" || direction == payloadClientToServer {
		return runPayloadThroughputStream(ctx, pair, payload, deadline, establishMu, lifecycle)
	}
	if direction == payloadServerToClient {
		return runReversePayloadThroughputStream(ctx, pair, payload, deadline, establishMu, lifecycle)
	}
	if direction == payloadFullDuplex {
		return runFullDuplexPayloadThroughputStream(ctx, pair, payload, deadline, establishMu, lifecycle)
	}
	return 0, nil, errors.New("payload throughput direction is invalid")
}

func runReversePayloadThroughputStream(ctx context.Context, pair *transporttest.ProductDirectPair, payload []byte, deadline time.Time, establishMu *sync.Mutex, lifecycle *payloadThroughputLifecycleCounters) (sent uint64, latencies []time.Duration, resultErr error) {
	establishMu.Lock()
	locked := true
	defer func() {
		if locked {
			establishMu.Unlock()
		}
	}()
	attemptCtx, cancelAttempt := context.WithCancelCause(ctx)
	receiver := startPayloadThroughputReceiver(attemptCtx, cancelAttempt, lifecycle, func(acceptCtx context.Context) (string, throughputByteStream, error) {
		incoming, err := pair.Client.AcceptStream(acceptCtx)
		if err != nil {
			return "", nil, err
		}
		return incoming.Kind, incoming.Stream, nil
	}, func(kind string, stream throughputByteStream) error {
		return receiveAcknowledgedPayloads(stream, kind, payload, "reverse payload throughput mismatch")
	})
	receiverJoined := false
	defer func() {
		if resultErr != nil {
			cancelAttempt(resultErr)
		} else {
			cancelAttempt(nil)
		}
		if !receiverJoined {
			resultErr = joinPayloadThroughputAttemptError(resultErr, receiver.Wait())
		}
	}()
	stream, err := pair.Server.OpenStream(attemptCtx, "performance-throughput", flowersession.Metadata{"direction": string(payloadServerToClient)})
	if err != nil {
		return 0, nil, err
	}
	owner := newPayloadThroughputStreamOwner(attemptCtx, stream, lifecycle)
	completed := false
	defer func() { resultErr = errors.Join(resultErr, owner.Finish(completed)) }()
	if err := receiver.WaitReady(attemptCtx); err != nil {
		return 0, nil, err
	}
	establishMu.Unlock()
	locked = false
	ack := make([]byte, 1)
	for time.Now().Before(deadline) {
		if time.Until(deadline) <= contractPayloadOperationGuard() {
			break
		}
		operationStarted := time.Now()
		written, writeErr := stream.Write(payload)
		if writeErr != nil || written != len(payload) {
			return sent, latencies, errors.Join(io.ErrShortWrite, writeErr)
		}
		if _, readErr := io.ReadFull(stream, ack); readErr != nil || ack[0] != 0xa5 {
			return sent, latencies, errors.Join(errors.New("reverse payload acknowledgement mismatch"), readErr)
		}
		sent += uint64(len(payload))
		latencies = append(latencies, time.Since(operationStarted))
	}
	if err := stream.CloseWrite(); err != nil {
		return sent, latencies, err
	}
	receiverErr := receiver.Wait()
	receiverJoined = true
	if receiverErr != nil {
		return sent, latencies, receiverErr
	}
	if err := requireCleanPayloadThroughputEOF(stream); err != nil {
		return sent, latencies, err
	}
	completed = true
	return sent, latencies, nil
}

func runFullDuplexPayloadThroughputStream(ctx context.Context, pair *transporttest.ProductDirectPair, payload []byte, deadline time.Time, establishMu *sync.Mutex, lifecycle *payloadThroughputLifecycleCounters) (verified uint64, latencies []time.Duration, resultErr error) {
	establishMu.Lock()
	locked := true
	defer func() {
		if locked {
			establishMu.Unlock()
		}
	}()
	attemptCtx, cancelAttempt := context.WithCancelCause(ctx)
	receiver := startPayloadThroughputReceiver(attemptCtx, cancelAttempt, lifecycle, func(acceptCtx context.Context) (string, throughputByteStream, error) {
		incoming, err := pair.Server.AcceptStream(acceptCtx)
		if err != nil {
			return "", nil, err
		}
		return incoming.Kind, incoming.Stream, nil
	}, func(kind string, stream throughputByteStream) error {
		return receiveFullDuplexPayloads(attemptCtx, cancelAttempt, stream, kind, payload)
	})
	receiverJoined := false
	defer func() {
		if resultErr != nil {
			cancelAttempt(resultErr)
		} else {
			cancelAttempt(nil)
		}
		if !receiverJoined {
			resultErr = joinPayloadThroughputAttemptError(resultErr, receiver.Wait())
		}
	}()
	metadata, err := flowersec.NewStreamMetadata(map[string]any{"direction": string(payloadFullDuplex)})
	if err != nil {
		return 0, nil, err
	}
	client, err := pair.Client.OpenStream(attemptCtx, "performance-throughput", metadata)
	if err != nil {
		return 0, nil, err
	}
	owner := newPayloadThroughputStreamOwner(attemptCtx, client, lifecycle)
	completed := false
	defer func() { resultErr = errors.Join(resultErr, owner.Finish(completed)) }()
	if err := receiver.WaitReady(attemptCtx); err != nil {
		return 0, nil, err
	}
	establishMu.Unlock()
	locked = false
	for time.Now().Before(deadline) {
		if time.Until(deadline) <= contractPayloadOperationGuard() {
			break
		}
		started := time.Now()
		if written, err := client.Write([]byte{0x5a}); err != nil || written != 1 {
			return verified, latencies, errors.Join(io.ErrShortWrite, err)
		}
		if err := exchangeVerifiedStreamSide(attemptCtx, cancelAttempt, client, payload); err != nil {
			return verified, latencies, err
		}
		verified += uint64(len(payload) * 2)
		latencies = append(latencies, time.Since(started))
	}
	if err := client.CloseWrite(); err != nil {
		return verified, latencies, err
	}
	receiverErr := receiver.Wait()
	receiverJoined = true
	if receiverErr != nil {
		return verified, latencies, receiverErr
	}
	if err := requireCleanPayloadThroughputEOF(client); err != nil {
		return verified, latencies, err
	}
	completed = true
	return verified, latencies, nil
}

func receiveAcknowledgedPayloads(stream throughputByteStream, kind string, payload []byte, mismatchMessage string) error {
	if kind != "performance-throughput" {
		return fmt.Errorf("payload throughput stream kind = %q", kind)
	}
	buffer := make([]byte, len(payload))
	for {
		count, readErr := readFullPayload(stream, buffer)
		ack, validateErr := payloadThroughputAckAllowed(buffer, payload, count, readErr, mismatchMessage)
		if errors.Is(validateErr, io.EOF) && count == 0 {
			return stream.CloseWrite()
		}
		if validateErr != nil {
			return validateErr
		}
		if ack {
			if written, writeErr := stream.Write([]byte{0xa5}); writeErr != nil || written != 1 {
				return errors.Join(io.ErrShortWrite, writeErr)
			}
		}
	}
}

func receiveFullDuplexPayloads(ctx context.Context, cancel context.CancelCauseFunc, stream throughputByteStream, kind string, payload []byte) error {
	if kind != "performance-throughput" {
		return fmt.Errorf("payload throughput stream kind = %q", kind)
	}
	marker := make([]byte, 1)
	for {
		count, readErr := io.ReadFull(stream, marker)
		if count == 0 && errors.Is(readErr, io.EOF) {
			return stream.CloseWrite()
		}
		if readErr != nil || marker[0] != 0x5a {
			return errors.Join(errors.New("full-duplex operation marker mismatch"), readErr)
		}
		if err := exchangeVerifiedStreamSide(ctx, cancel, stream, payload); err != nil {
			return err
		}
	}
}

func requireCleanPayloadThroughputEOF(stream throughputByteStream) error {
	buffer := make([]byte, 1)
	count, err := stream.Read(buffer)
	if count == 0 && errors.Is(err, io.EOF) {
		return nil
	}
	if count != 0 {
		return errors.New("payload throughput stream received bytes after reciprocal FIN")
	}
	if err == nil {
		return io.ErrNoProgress
	}
	return fmt.Errorf("payload throughput reciprocal FIN: %w", err)
}

func exchangeVerifiedStreamSide(ctx context.Context, cancel context.CancelCauseFunc, stream throughputByteStream, payload []byte) error {
	type writeResult struct {
		count int
		err   error
	}
	written := make(chan writeResult, 1)
	go func() {
		count, err := stream.Write(payload)
		if err != nil || count != len(payload) {
			err = errors.Join(io.ErrShortWrite, err)
			cancel(err)
		}
		written <- writeResult{count: count, err: err}
	}()
	buffer := make([]byte, len(payload))
	_, readErr := io.ReadFull(stream, buffer)
	if readErr != nil || !equalPayload(buffer, payload) {
		readErr = errors.Join(errors.New("full-duplex payload mismatch"), readErr)
		cancel(readErr)
	}
	result := <-written
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if readErr != nil || result.err != nil || result.count != len(payload) {
		return errors.Join(readErr, result.err)
	}
	return nil
}

func contractPayloadOperationGuard() time.Duration { return 2 * time.Millisecond }

func payloadThroughputAckAllowed(buffer, payload []byte, count int, readErr error, mismatchMessage string) (bool, error) {
	if count > 0 && !equalPayload(buffer[:count], payload[:count]) {
		return false, errors.New(mismatchMessage)
	}
	if readErr != nil {
		return false, readErr
	}
	return count > 0, nil
}

func readFullPayload(stream interface{ Read([]byte) (int, error) }, buffer []byte) (int, error) {
	read := 0
	for read < len(buffer) {
		count, err := stream.Read(buffer[read:])
		read += count
		if err != nil {
			return read, err
		}
		if count == 0 {
			return read, io.ErrNoProgress
		}
	}
	return read, nil
}

func equalPayload(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validatePayloadThroughputResult(contract payloadThroughputContract, result payloadThroughputResult) error {
	if err := validatePayloadThroughputContract(contract); err != nil {
		return err
	}
	if len(result.Samples) != contract.Samples {
		return fmt.Errorf("payload throughput samples = %d, want %d", len(result.Samples), contract.Samples)
	}
	for index, sample := range result.Samples {
		if sample.Bytes == 0 || sample.Duration <= 0 || len(sample.Latencies) == 0 || sample.BytesPerSecond < contract.MinBytesPerSecond {
			return fmt.Errorf("payload throughput sample %d is below %.0f bytes/s: %+v", index+1, contract.MinBytesPerSecond, sample)
		}
		if p95 := percentileDuration(sample.Latencies, 95); p95 > contract.MaxP95 {
			return fmt.Errorf("payload throughput sample %d p95 %s exceeds %s", index+1, p95, contract.MaxP95)
		}
	}
	return nil
}

func summarizePayloadThroughput(result payloadThroughputResult) payloadThroughputSummary {
	var summary payloadThroughputSummary
	var latencies []time.Duration
	for _, sample := range result.Samples {
		summary.Bytes += sample.Bytes
		summary.Duration += sample.Duration
		latencies = append(latencies, sample.Latencies...)
	}
	if summary.Duration > 0 {
		summary.BytesPerSecond = float64(summary.Bytes) / summary.Duration.Seconds()
	}
	summary.P50 = percentileDuration(latencies, 50)
	summary.P95 = percentileDuration(latencies, 95)
	summary.P99 = percentileDuration(latencies, 99)
	return summary
}

func makePayload(size int) []byte {
	payload := make([]byte, size)
	for index := range payload {
		payload[index] = byte(index*31 + 17)
	}
	return payload
}
