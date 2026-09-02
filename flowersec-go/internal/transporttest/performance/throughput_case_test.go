package performance

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrier"
)

func TestFocusedProductionPayloadThroughputCase(t *testing.T) {
	var kind carrier.Kind
	switch os.Getenv("FLOWERSEC_TEST_THROUGHPUT_CARRIER") {
	case "":
		t.Skip("set FLOWERSEC_TEST_THROUGHPUT_CARRIER to run one production payload throughput case")
	case "websocket":
		kind = carrier.KindWebSocket
	case "raw-quic":
		kind = carrier.KindRawQUIC
	case "webtransport":
		kind = carrier.KindWebTransport
	default:
		t.Fatal("FLOWERSEC_TEST_THROUGHPUT_CARRIER must be websocket, raw-quic, or webtransport")
	}
	contracts := []payloadThroughputContract{productionPayloadThroughputContract()}
	switch os.Getenv("FLOWERSEC_TEST_THROUGHPUT_MODE") {
	case "":
	case "single-connection":
		contracts = productionSingleConnectionThroughputContracts()
	case "streaming":
		contracts = productionStreamingThroughputContracts()
	default:
		t.Fatal("FLOWERSEC_TEST_THROUGHPUT_MODE must be single-connection or streaming")
	}
	totalDuration := 30 * time.Second
	for _, contract := range contracts {
		totalDuration += time.Duration(contract.Samples) * contract.SampleDuration
	}
	ctx, cancel := context.WithTimeout(performanceTestContext, totalDuration)
	defer cancel()
	results := make([]payloadThroughputCoordinateResult, 0, len(contracts))
	var runErr error
	for _, contract := range contracts {
		result, err := runProductionPayloadThroughput(ctx, kind, contract)
		results = append(results, payloadThroughputCoordinateResult{Contract: contract, Result: result, Err: err})
		if err != nil {
			runErr = err
			break
		}
	}
	if reportErr := writeFocusedPerformanceResult(throughputMatrixPerformanceResult(os.Getenv("FLOWERSEC_TEST_CASE_ID"), kind, os.Getenv("FLOWERSEC_TEST_THROUGHPUT_MODE"), results, runErr)); reportErr != nil {
		t.Fatal(reportErr)
	}
	if runErr != nil {
		t.Fatal(runErr)
	}
}

func TestProductionPayloadThroughputContractIsFrozen(t *testing.T) {
	contract := productionPayloadThroughputContract()
	if contract.PayloadBytes != 64<<10 || contract.Concurrency != 4 || contract.SampleDuration != 5*time.Second ||
		contract.Samples != 3 || contract.MinBytesPerSecond != 1<<20 || contract.MaxP95 != 2*time.Second {
		t.Fatalf("payload throughput contract = %+v", contract)
	}
	if err := validatePayloadThroughputContract(contract); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindRawQUIC} {
		if err := validatePayloadThroughputCarrier(kind); err != nil {
			t.Fatalf("required carrier %q rejected: %v", kind, err)
		}
	}
	if err := validatePayloadThroughputCarrier(carrier.KindWebTransport); err != nil {
		t.Fatal("optional WebTransport payload throughput carrier was rejected")
	}
}

func TestProductionThroughputMatricesAreCompleteWithoutRelaxingThresholds(t *testing.T) {
	single := productionSingleConnectionThroughputContracts()
	if len(single) != 3 {
		t.Fatalf("single-connection coordinates = %d, want 3", len(single))
	}
	streaming := productionStreamingThroughputContracts()
	if len(streaming) != 9 {
		t.Fatalf("streaming coordinates = %d, want 9", len(streaming))
	}
	wantPayloads := map[int]bool{1 << 10: false, 64 << 10: false, 1 << 20: false}
	wantDirections := map[payloadDirection]bool{payloadClientToServer: false, payloadServerToClient: false, payloadFullDuplex: false}
	for _, contract := range append(single, streaming...) {
		if contract.MinBytesPerSecond != 1<<20 || contract.MaxP95 != 2*time.Second || contract.Samples != 3 || contract.SampleDuration != 5*time.Second {
			t.Fatalf("throughput threshold was changed: %+v", contract)
		}
		if err := validatePayloadThroughputContract(contract); err != nil {
			t.Fatal(err)
		}
		wantPayloads[contract.PayloadBytes] = true
		wantDirections[contract.Direction] = true
	}
	for payload, found := range wantPayloads {
		if !found {
			t.Fatalf("streaming payload %d is missing", payload)
		}
	}
	for direction, found := range wantDirections {
		if !found {
			t.Fatalf("direction %s is missing", direction)
		}
	}
}

func TestPayloadThroughputResultRequiresEveryMeasuredSample(t *testing.T) {
	contract := payloadThroughputContract{
		PayloadBytes: 1024, Concurrency: 2, SampleDuration: time.Second, Samples: 3,
		MinBytesPerSecond: 1024, MaxP95: time.Second,
	}
	valid := payloadThroughputResult{Samples: []payloadThroughputSample{
		{Bytes: 2048, Duration: time.Second, BytesPerSecond: 2048, Latencies: []time.Duration{time.Millisecond}},
		{Bytes: 3072, Duration: time.Second, BytesPerSecond: 3072, Latencies: []time.Duration{2 * time.Millisecond}},
		{Bytes: 4096, Duration: time.Second, BytesPerSecond: 4096, Latencies: []time.Duration{3 * time.Millisecond}},
	}}
	if err := validatePayloadThroughputResult(contract, valid); err != nil {
		t.Fatal(err)
	}
	missing := valid
	missing.Samples = missing.Samples[:2]
	if err := validatePayloadThroughputResult(contract, missing); err == nil {
		t.Fatal("throughput result accepted fewer than three measured samples")
	}
	belowBudget := valid
	belowBudget.Samples = append([]payloadThroughputSample(nil), valid.Samples...)
	belowBudget.Samples[1].BytesPerSecond = 1023
	if err := validatePayloadThroughputResult(contract, belowBudget); err == nil {
		t.Fatal("throughput result accepted one sample below the static budget")
	}
	tooSlow := valid
	tooSlow.Samples = append([]payloadThroughputSample(nil), valid.Samples...)
	tooSlow.Samples[2].Latencies = []time.Duration{time.Second + time.Nanosecond}
	if err := validatePayloadThroughputResult(contract, tooSlow); err == nil {
		t.Fatal("throughput result accepted a sample above the latency budget")
	}
}

func TestPayloadThroughputDirectionsTransferVerifiedBytes(t *testing.T) {
	for _, payloadBytes := range []int{1 << 10, 64 << 10, 1 << 20} {
		for _, direction := range []payloadDirection{payloadClientToServer, payloadServerToClient, payloadFullDuplex} {
			t.Run(fmt.Sprintf("%d/%s", payloadBytes, direction), func(t *testing.T) {
				contract := payloadThroughputContract{PayloadBytes: payloadBytes, Concurrency: 4, SampleDuration: 30 * time.Millisecond, Samples: 3, MinBytesPerSecond: 1, MaxP95: 2 * time.Second, Direction: direction}
				ctx, cancel := context.WithTimeout(performanceTestContext, 5*time.Second)
				defer cancel()
				result, err := runProductionPayloadThroughput(ctx, carrier.KindWebSocket, contract)
				if err != nil {
					t.Fatal(err)
				}
				if result.Summary.Bytes == 0 || result.Summary.P99 <= 0 || len(result.Resources) != 4 {
					t.Fatalf("direction %s result = %+v", direction, result)
				}
				for sampleIndex, sample := range result.Samples {
					if sample.FINCleanupFailures != 0 || sample.ResetCount != 0 {
						t.Fatalf("direction %s sample %d cleanup = FIN failures %d, resets %d", direction, sampleIndex+1, sample.FINCleanupFailures, sample.ResetCount)
					}
				}
			})
		}
	}
}

func TestSummarizePayloadThroughputReportsBytesPerSecondAndLatency(t *testing.T) {
	result := payloadThroughputResult{Samples: []payloadThroughputSample{
		{Bytes: 3000, Duration: time.Second, BytesPerSecond: 3000, Latencies: []time.Duration{time.Millisecond, 3 * time.Millisecond}},
		{Bytes: 2000, Duration: time.Second, BytesPerSecond: 2000, Latencies: []time.Duration{2 * time.Millisecond, 4 * time.Millisecond}},
		{Bytes: 1000, Duration: time.Second, BytesPerSecond: 1000, Latencies: []time.Duration{5 * time.Millisecond, 6 * time.Millisecond}},
	}}
	summary := summarizePayloadThroughput(result)
	if summary.Bytes != 6000 || summary.BytesPerSecond != 2000 || summary.P50 != 3*time.Millisecond || summary.P95 != 6*time.Millisecond {
		t.Fatalf("payload throughput summary = %+v", summary)
	}
}

func TestThroughputReportPreservesMetricsWhenResourceThresholdFails(t *testing.T) {
	contract := productionSingleConnectionThroughputContracts()[0]
	result := payloadThroughputResult{
		Carrier:  carrier.KindWebSocket,
		Baseline: caseResourceRecord{RSSBytes: 1},
		Resources: []caseResourceRecord{
			{Phase: "baseline", RSSBytes: 1},
			{Phase: "measured sample 1", AtNS: int64(15 * time.Second), RSSBytes: 2, CPUNanoseconds: uint64(121 * time.Second)},
		},
		Samples: []payloadThroughputSample{
			{Bytes: 10 << 20, Duration: 5 * time.Second, BytesPerSecond: 2 << 20, Latencies: []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond}},
			{Bytes: 10 << 20, Duration: 5 * time.Second, BytesPerSecond: 2 << 20, Latencies: []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond}},
			{Bytes: 10 << 20, Duration: 5 * time.Second, BytesPerSecond: 2 << 20, Latencies: []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond}},
		},
	}
	result.Summary = summarizePayloadThroughput(result)
	report := throughputMatrixPerformanceResult("performance/single-connection/wss", carrier.KindWebSocket, "single-connection", []payloadThroughputCoordinateResult{{Contract: contract, Result: result}}, nil)
	if report.Status != "FAIL" || report.Stage != "measurement" || !strings.Contains(report.FirstError, "CPU time") {
		t.Fatalf("threshold failure was not promoted to the case: %+v", report)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("failed report did not preserve valid observed metrics: %v", err)
	}
}

func TestRawQUICPayloadThroughputCompletesFINWithoutReset(t *testing.T) {
	if os.Getenv("FLOWERSEC_TEST_THROUGHPUT_RAW_QUIC_REGRESSION") != "1" {
		t.Skip("set FLOWERSEC_TEST_THROUGHPUT_RAW_QUIC_REGRESSION=1 to run the raw QUIC FIN regression")
	}
	contract := payloadThroughputContract{
		PayloadBytes: 64 << 10, Concurrency: 1, SampleDuration: 250 * time.Millisecond, Samples: 3,
		MinBytesPerSecond: 1, MaxP95: 2 * time.Second,
	}
	ctx, cancel := context.WithTimeout(performanceTestContext, 10*time.Second)
	defer cancel()
	if _, err := runProductionPayloadThroughput(ctx, carrier.KindRawQUIC, contract); err != nil {
		t.Fatal(err)
	}
}
