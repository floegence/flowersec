package performance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transporttest"
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
	Bytes          uint64
	Duration       time.Duration
	BytesPerSecond float64
	Latencies      []time.Duration
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
	started := time.Now()
	scheduleDeadline := started.Add(contract.SampleDuration)
	operationCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var transferred atomic.Uint64
	var latencies []time.Duration
	var latenciesMu sync.Mutex
	errorsSeen := make(chan error, contract.Concurrency)
	var group sync.WaitGroup
	var establishMu sync.Mutex
	for worker := 0; worker < contract.Concurrency; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			requestBytes, workerLatencies, err := runPayloadThroughputStreamDirection(operationCtx, pair, payload, scheduleDeadline, contract.Direction, &establishMu)
			if err != nil {
				errorsSeen <- err
				return
			}
			transferred.Add(requestBytes)
			latenciesMu.Lock()
			latencies = append(latencies, workerLatencies...)
			latenciesMu.Unlock()
		}()
	}
	group.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			return payloadThroughputSample{}, err
		}
	}
	measured := payloadThroughputSample{Bytes: transferred.Load(), Duration: time.Since(started)}
	measured.Latencies = latencies
	if measured.Duration <= 0 || measured.Bytes == 0 || len(measured.Latencies) < contract.Concurrency {
		return payloadThroughputSample{}, errors.New("payload throughput sample completed without the minimum measured operations")
	}
	measured.BytesPerSecond = float64(measured.Bytes) / measured.Duration.Seconds()
	return measured, nil
}

func runPayloadThroughputStream(ctx context.Context, pair *transporttest.ProductDirectPair, payload []byte, deadline time.Time, establishMu *sync.Mutex) (uint64, []time.Duration, error) {
	establishMu.Lock()
	locked := true
	defer func() {
		if locked {
			establishMu.Unlock()
		}
	}()
	accepted := make(chan error, 1)
	ready := make(chan error, 1)
	go func() {
		incoming, err := pair.Server.AcceptStream(ctx)
		if err != nil {
			ready <- err
			accepted <- err
			return
		}
		ready <- nil
		defer incoming.Stream.Close()
		if incoming.Kind != "performance-throughput" {
			accepted <- fmt.Errorf("payload throughput stream kind = %q", incoming.Kind)
			return
		}
		buffer := make([]byte, len(payload))
		for {
			count, readErr := readFullPayload(incoming.Stream, buffer)
			if count > 0 && !equalPayload(buffer[:count], payload[:count]) {
				accepted <- errors.New("payload throughput request mismatch")
				return
			}
			if count > 0 {
				if written, writeErr := incoming.Stream.Write([]byte{0xa5}); writeErr != nil || written != 1 {
					accepted <- errors.Join(io.ErrShortWrite, writeErr)
					return
				}
			}
			if readErr != nil {
				accepted <- readErr
				return
			}
		}
	}()
	metadata, err := flowersec.NewStreamMetadata(map[string]any{"direction": "client-to-server"})
	if err != nil {
		return 0, nil, err
	}
	stream, err := pair.Client.OpenStream(ctx, "performance-throughput", metadata)
	if err != nil {
		return 0, nil, err
	}
	if err := <-ready; err != nil {
		_ = stream.Reset()
		return 0, nil, err
	}
	establishMu.Unlock()
	locked = false
	completed := false
	defer func() {
		if !completed {
			_ = stream.Reset()
		}
	}()
	var sent uint64
	var latencies []time.Duration
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
	select {
	case err := <-accepted:
		if !errors.Is(err, io.EOF) {
			return sent, latencies, err
		}
		completed = true
		return sent, latencies, nil
	case <-ctx.Done():
		_ = stream.Reset()
		return sent, latencies, context.Cause(ctx)
	}
}

type throughputByteStream interface {
	io.Reader
	io.Writer
	io.Closer
	CloseWrite() error
	Reset() error
}

func runPayloadThroughputStreamDirection(ctx context.Context, pair *transporttest.ProductDirectPair, payload []byte, deadline time.Time, direction payloadDirection, establishMu *sync.Mutex) (uint64, []time.Duration, error) {
	if direction == "" || direction == payloadClientToServer {
		return runPayloadThroughputStream(ctx, pair, payload, deadline, establishMu)
	}
	if direction == payloadServerToClient {
		return runReversePayloadThroughputStream(ctx, pair, payload, deadline, establishMu)
	}
	if direction == payloadFullDuplex {
		return runFullDuplexPayloadThroughputStream(ctx, pair, payload, deadline, establishMu)
	}
	return 0, nil, errors.New("payload throughput direction is invalid")
}

func runReversePayloadThroughputStream(ctx context.Context, pair *transporttest.ProductDirectPair, payload []byte, deadline time.Time, establishMu *sync.Mutex) (uint64, []time.Duration, error) {
	establishMu.Lock()
	locked := true
	defer func() {
		if locked {
			establishMu.Unlock()
		}
	}()
	accepted := make(chan error, 1)
	ready := make(chan error, 1)
	go func() {
		incoming, err := pair.Client.AcceptStream(ctx)
		if err != nil {
			ready <- err
			accepted <- err
			return
		}
		ready <- nil
		defer incoming.Stream.Close()
		if incoming.Kind != "performance-throughput" {
			accepted <- fmt.Errorf("payload throughput stream kind = %q", incoming.Kind)
			return
		}
		buffer := make([]byte, len(payload))
		for {
			count, readErr := readFullPayload(incoming.Stream, buffer)
			if count > 0 && !equalPayload(buffer[:count], payload[:count]) {
				accepted <- errors.New("reverse payload throughput mismatch")
				return
			}
			if count > 0 {
				if written, writeErr := incoming.Stream.Write([]byte{0xa5}); writeErr != nil || written != 1 {
					accepted <- errors.Join(io.ErrShortWrite, writeErr)
					return
				}
			}
			if readErr != nil {
				accepted <- readErr
				return
			}
		}
	}()
	stream, err := pair.Server.OpenStream(ctx, "performance-throughput", flowersession.Metadata{"direction": string(payloadServerToClient)})
	if err != nil {
		return 0, nil, err
	}
	if err := <-ready; err != nil {
		_ = stream.Reset()
		return 0, nil, err
	}
	establishMu.Unlock()
	locked = false
	defer stream.Close()
	var sent uint64
	var latencies []time.Duration
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
	select {
	case err := <-accepted:
		if !errors.Is(err, io.EOF) {
			return sent, latencies, err
		}
		return sent, latencies, nil
	case <-ctx.Done():
		_ = stream.Reset()
		return sent, latencies, context.Cause(ctx)
	}
}

func runFullDuplexPayloadThroughputStream(ctx context.Context, pair *transporttest.ProductDirectPair, payload []byte, deadline time.Time, establishMu *sync.Mutex) (uint64, []time.Duration, error) {
	establishMu.Lock()
	locked := true
	defer func() {
		if locked {
			establishMu.Unlock()
		}
	}()
	accepted := make(chan error, 1)
	ready := make(chan error, 1)
	go func() {
		incoming, err := pair.Server.AcceptStream(ctx)
		if err != nil {
			ready <- err
			accepted <- err
			return
		}
		ready <- nil
		defer incoming.Stream.Close()
		if incoming.Kind != "performance-throughput" {
			accepted <- fmt.Errorf("payload throughput stream kind = %q", incoming.Kind)
			return
		}
		marker := make([]byte, 1)
		for {
			_, readErr := io.ReadFull(incoming.Stream, marker)
			if errors.Is(readErr, io.EOF) {
				accepted <- io.EOF
				return
			}
			if readErr != nil || marker[0] != 0x5a {
				accepted <- errors.Join(errors.New("full-duplex operation marker mismatch"), readErr)
				return
			}
			if err := exchangeVerifiedStreamSide(incoming.Stream, payload); err != nil {
				accepted <- err
				return
			}
		}
	}()
	metadata, err := flowersec.NewStreamMetadata(map[string]any{"direction": string(payloadFullDuplex)})
	if err != nil {
		return 0, nil, err
	}
	client, err := pair.Client.OpenStream(ctx, "performance-throughput", metadata)
	if err != nil {
		return 0, nil, err
	}
	if err := <-ready; err != nil {
		_ = client.Reset()
		return 0, nil, err
	}
	establishMu.Unlock()
	locked = false
	defer client.Close()
	var verified uint64
	var latencies []time.Duration
	for time.Now().Before(deadline) {
		if time.Until(deadline) <= contractPayloadOperationGuard() {
			break
		}
		started := time.Now()
		if written, err := client.Write([]byte{0x5a}); err != nil || written != 1 {
			return verified, latencies, errors.Join(io.ErrShortWrite, err)
		}
		if err := exchangeVerifiedStreamSide(client, payload); err != nil {
			return verified, latencies, err
		}
		verified += uint64(len(payload) * 2)
		latencies = append(latencies, time.Since(started))
	}
	if err := client.CloseWrite(); err != nil {
		return verified, latencies, err
	}
	select {
	case err := <-accepted:
		if !errors.Is(err, io.EOF) {
			return verified, latencies, err
		}
		return verified, latencies, nil
	case <-ctx.Done():
		_ = client.Reset()
		return verified, latencies, context.Cause(ctx)
	}
}

func exchangeVerifiedStreamSide(stream throughputByteStream, payload []byte) error {
	type writeResult struct {
		count int
		err   error
	}
	written := make(chan writeResult, 1)
	go func() { count, err := stream.Write(payload); written <- writeResult{count: count, err: err} }()
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, buffer); err != nil || !equalPayload(buffer, payload) {
		return errors.Join(errors.New("full-duplex payload mismatch"), err)
	}
	result := <-written
	if result.err != nil || result.count != len(payload) {
		return errors.Join(io.ErrShortWrite, result.err)
	}
	return nil
}

func contractPayloadOperationGuard() time.Duration { return 2 * time.Millisecond }

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
