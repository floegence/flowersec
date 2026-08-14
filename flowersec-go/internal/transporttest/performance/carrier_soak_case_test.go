package performance

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transporttest"
)

type carrierSoakContract struct {
	Duration           time.Duration
	CyclePeriod        time.Duration
	Cycles             int
	MaxRSSGrowth       uint64
	MaxGoroutineGrowth int
	MaxOpenFDGrowth    int
	MaxTaskGrowth      int
}

type carrierSoakResult struct {
	Cycles          int
	Baseline        transporttest.ResourceSnapshot
	Finish          transporttest.ResourceSnapshot
	RSSPeak         uint64
	GoroutinePeak   int
	OpenFDPeak      int
	TaskPeak        int
	RSSGrowth       uint64
	GoroutineGrowth int
	OpenFDGrowth    int
	TaskGrowth      int
	Resources       []transporttest.ResourceSnapshot
}

func TestProductionCarrierSoakContractIsFrozen(t *testing.T) {
	contract := productionCarrierSoakContract()
	if contract.Duration != 5*time.Minute || contract.CyclePeriod != time.Minute || contract.Cycles != 5 ||
		contract.MaxRSSGrowth != 64<<20 || contract.MaxGoroutineGrowth != 64 || contract.MaxOpenFDGrowth != 16 || contract.MaxTaskGrowth != 64 {
		t.Fatalf("carrier soak contract = %+v", contract)
	}
	if _, err := runProductionCarrierSoak(context.Background(), carrier.KindRawQUIC, contract); err == nil {
		t.Fatal("raw QUIC entered the non-migrating carrier soak")
	}
}

func productionCarrierSoakContract() carrierSoakContract {
	return carrierSoakContract{
		Duration: 5 * time.Minute, CyclePeriod: time.Minute, Cycles: 5,
		MaxRSSGrowth: 64 << 20, MaxGoroutineGrowth: 64, MaxOpenFDGrowth: 16, MaxTaskGrowth: 64,
	}
}

func TestFocusedProductionCarrierSoakCase(t *testing.T) {
	if os.Getenv("FLOWERSEC_TEST_SOAK") != "1" {
		if os.Getenv("FLOWERSEC_REQUIRED_PERFORMANCE") == "1" {
			t.Fatal("required performance carrier soak environment is incomplete")
		}
		t.Skip("set FLOWERSEC_TEST_SOAK=1 to run the production carrier soak")
	}
	var kind carrier.Kind
	switch os.Getenv("FLOWERSEC_TEST_SOAK_CARRIER") {
	case "websocket":
		kind = carrier.KindWebSocket
	case "webtransport":
		kind = carrier.KindWebTransport
	default:
		t.Fatal("FLOWERSEC_TEST_SOAK_CARRIER must be websocket or webtransport")
	}
	ctx, cancel := context.WithTimeout(performanceTestContext, productionCarrierSoakContract().Duration+30*time.Second)
	defer cancel()
	result, err := runProductionCarrierSoak(ctx, kind, productionCarrierSoakContract())
	if reportErr := writeFocusedPerformanceResult(carrierSoakPerformanceResult(kind, result, productionCarrierSoakContract(), err)); reportErr != nil {
		t.Fatal(reportErr)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func runProductionCarrierSoak(ctx context.Context, kind carrier.Kind, contract carrierSoakContract) (result carrierSoakResult, resultErr error) {
	if kind != carrier.KindWebSocket && kind != carrier.KindWebTransport {
		return result, fmt.Errorf("carrier soak does not own %q", kind)
	}
	if contract.Duration <= 0 || contract.CyclePeriod <= 0 || contract.Cycles < 1 ||
		contract.Duration != time.Duration(contract.Cycles)*contract.CyclePeriod {
		return result, fmt.Errorf("carrier soak contract is invalid: %+v", contract)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	baseline, err := transporttest.CaptureResourceSnapshot()
	if err != nil {
		return result, fmt.Errorf("capture %s soak baseline: %w", kind, err)
	}
	result.Baseline = baseline
	result.RSSPeak, result.GoroutinePeak, result.OpenFDPeak, result.TaskPeak = baseline.RSSBytes, baseline.Goroutines, baseline.OpenFDs, baseline.Tasks
	result.Resources = append(result.Resources, baseline)
	endpoint, err := transporttest.OpenProductDirectEndpoint(ctx, kind)
	if err != nil {
		return result, fmt.Errorf("open %s soak endpoint: %w", kind, err)
	}
	defer endpoint.Close()
	started := time.Now()
	for cycle := 1; cycle <= contract.Cycles; cycle++ {
		cycleDeadline := started.Add(time.Duration(cycle) * contract.CyclePeriod)
		cycleCtx, cancel := context.WithDeadline(ctx, cycleDeadline.Add(2*time.Second))
		pair, connectErr := endpoint.Connect(cycleCtx)
		if connectErr == nil && pair.SpendCount() != 1 {
			connectErr = fmt.Errorf("cycle %d %s artifact spend count = %d, want 1", cycle, kind, pair.SpendCount())
		}
		if connectErr == nil {
			connectErr = pair.RoundTrip(cycleCtx,
				[]byte(fmt.Sprintf("soak-%s-request-%d", kind, cycle)),
				[]byte(fmt.Sprintf("soak-%s-response-%d", kind, cycle)))
		}
		if connectErr == nil {
			connectErr = holdCarrierSoakSession(cycleCtx, pair, cycleDeadline)
		}
		if pair != nil {
			connectErr = joinCarrierSoakErrors(connectErr, pair.Close())
		}
		cancel()
		if connectErr != nil {
			return result, fmt.Errorf("cycle %d %s production reconnect: %w", cycle, kind, connectErr)
		}
		if err := waitCapacityUntil(ctx, cycleDeadline, started.Add(contract.Duration)); err != nil {
			return result, fmt.Errorf("cycle %d %s hold: %w", cycle, kind, err)
		}
		snapshot, err := transporttest.CaptureResourceSnapshot()
		if err != nil {
			return result, fmt.Errorf("capture %s soak cycle %d: %w", kind, cycle, err)
		}
		result.Cycles++
		result.Resources = append(result.Resources, snapshot)
		result.RSSPeak = max(result.RSSPeak, snapshot.RSSBytes)
		result.GoroutinePeak = max(result.GoroutinePeak, snapshot.Goroutines)
		result.OpenFDPeak = max(result.OpenFDPeak, snapshot.OpenFDs)
		result.TaskPeak = max(result.TaskPeak, snapshot.Tasks)
	}
	if err := endpoint.Close(); err != nil {
		return result, fmt.Errorf("close %s soak endpoint: %w", kind, err)
	}
	finish, err := transporttest.CaptureResourceSnapshot()
	if err != nil {
		return result, fmt.Errorf("capture %s soak cleanup: %w", kind, err)
	}
	result.Finish = finish
	result.Resources = append(result.Resources, finish)
	result.RSSPeak = max(result.RSSPeak, finish.RSSBytes)
	result.GoroutinePeak = max(result.GoroutinePeak, finish.Goroutines)
	result.OpenFDPeak = max(result.OpenFDPeak, finish.OpenFDs)
	result.TaskPeak = max(result.TaskPeak, finish.Tasks)
	result.RSSGrowth = positiveUint64Delta(finish.RSSBytes, baseline.RSSBytes)
	result.GoroutineGrowth = positiveIntDelta(finish.Goroutines, baseline.Goroutines)
	result.OpenFDGrowth = positiveIntDelta(finish.OpenFDs, baseline.OpenFDs)
	result.TaskGrowth = positiveIntDelta(finish.Tasks, baseline.Tasks)
	if result.RSSGrowth > contract.MaxRSSGrowth {
		return result, fmt.Errorf("%s soak rss growth %d exceeds budget %d", kind, result.RSSGrowth, contract.MaxRSSGrowth)
	}
	if result.GoroutineGrowth > contract.MaxGoroutineGrowth {
		return result, fmt.Errorf("%s soak goroutine growth %d exceeds budget %d", kind, result.GoroutineGrowth, contract.MaxGoroutineGrowth)
	}
	if result.OpenFDGrowth > contract.MaxOpenFDGrowth {
		return result, fmt.Errorf("%s soak fd growth %d exceeds budget %d", kind, result.OpenFDGrowth, contract.MaxOpenFDGrowth)
	}
	if result.TaskGrowth > contract.MaxTaskGrowth {
		return result, fmt.Errorf("%s soak task growth %d exceeds budget %d", kind, result.TaskGrowth, contract.MaxTaskGrowth)
	}
	return result, nil
}

func holdCarrierSoakSession(ctx context.Context, pair *transporttest.ProductDirectPair, deadline time.Time) error {
	if pair == nil || pair.Client == nil {
		return fmt.Errorf("carrier soak session is unavailable")
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	timer := time.NewTimer(time.Until(deadline))
	defer stopTimer(timer)
	for {
		select {
		case <-ticker.C:
			if _, err := pair.Client.ProbeLiveness(ctx); err != nil {
				return fmt.Errorf("carrier soak liveness: %w", err)
			}
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
}

func joinCarrierSoakErrors(left, right error) error {
	if left != nil {
		return fmt.Errorf("%w; close: %v", left, right)
	}
	return right
}
