package performance

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
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
	default:
		t.Fatal("FLOWERSEC_TEST_THROUGHPUT_CARRIER must be websocket or raw-quic")
	}
	contract := productionPayloadThroughputContract()
	ctx, cancel := context.WithTimeout(performanceTestContext, time.Duration(contract.Samples)*contract.SampleDuration+30*time.Second)
	defer cancel()
	result, err := runProductionPayloadThroughput(ctx, kind, contract)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("payload throughput: carrier=%s samples=%d bytes=%d bytes_per_second=%.0f p50=%s p95=%s",
		result.Carrier, len(result.Samples), result.Summary.Bytes, result.Summary.BytesPerSecond, result.Summary.P50, result.Summary.P95)
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
	if err := validatePayloadThroughputCarrier(carrier.KindWebTransport); err == nil {
		t.Fatal("optional WebTransport entered the required Go payload throughput workload")
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
