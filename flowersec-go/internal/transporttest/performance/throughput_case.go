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
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transporttest"
)

type payloadThroughputContract struct {
	PayloadBytes      int
	Concurrency       int
	SampleDuration    time.Duration
	Samples           int
	MinBytesPerSecond float64
	MaxP95            time.Duration
}

func productionPayloadThroughputContract() payloadThroughputContract {
	return payloadThroughputContract{
		PayloadBytes: 64 << 10, Concurrency: 4, SampleDuration: 5 * time.Second, Samples: 3,
		MinBytesPerSecond: 1 << 20, MaxP95: 2 * time.Second,
	}
}

type payloadThroughputSample struct {
	Bytes          uint64
	Duration       time.Duration
	BytesPerSecond float64
	Latencies      []time.Duration
}

type payloadThroughputResult struct {
	Carrier carrier.Kind
	Samples []payloadThroughputSample
	Summary payloadThroughputSummary
}

type payloadThroughputSummary struct {
	Bytes          uint64
	Duration       time.Duration
	BytesPerSecond float64
	P50            time.Duration
	P95            time.Duration
}

func validatePayloadThroughputContract(contract payloadThroughputContract) error {
	if contract.PayloadBytes <= 0 || contract.Concurrency <= 0 || contract.SampleDuration <= 0 || contract.Samples < 3 ||
		contract.MinBytesPerSecond <= 0 || contract.MaxP95 <= 0 {
		return errors.New("payload throughput contract is incomplete")
	}
	return nil
}

func validatePayloadThroughputCarrier(kind carrier.Kind) error {
	if kind != carrier.KindWebSocket && kind != carrier.KindRawQUIC {
		return fmt.Errorf("payload throughput workload does not own carrier %q", kind)
	}
	return nil
}

func runProductionPayloadThroughput(ctx context.Context, kind carrier.Kind, contract payloadThroughputContract) (result payloadThroughputResult, resultErr error) {
	if err := validatePayloadThroughputContract(contract); err != nil {
		return result, err
	}
	if err := validatePayloadThroughputCarrier(kind); err != nil {
		return result, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
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
	result.Carrier = kind
	result.Samples = make([]payloadThroughputSample, 0, contract.Samples)
	for sample := 0; sample < contract.Samples; sample++ {
		pair, connectErr := endpoint.Connect(ctx)
		if connectErr != nil {
			return result, fmt.Errorf("connect %s payload throughput sample %d: %w", kind, sample+1, connectErr)
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
	for worker := 0; worker < contract.Concurrency; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			requestBytes, workerLatencies, err := runPayloadThroughputStream(operationCtx, pair, payload, scheduleDeadline)
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

func runPayloadThroughputStream(ctx context.Context, pair *transporttest.ProductDirectPair, payload []byte, deadline time.Time) (uint64, []time.Duration, error) {
	accepted := make(chan error, 1)
	go func() {
		incoming, err := pair.Server.AcceptStream(ctx)
		if err != nil {
			accepted <- err
			return
		}
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
	return summary
}

func makePayload(size int) []byte {
	payload := make([]byte, size)
	for index := range payload {
		payload[index] = byte(index*31 + 17)
	}
	return payload
}
