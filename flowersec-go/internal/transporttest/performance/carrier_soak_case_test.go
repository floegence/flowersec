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

func TestProductionCarrierSoakContractIsFrozen(t *testing.T) {
	contract := productionCarrierSoakContract()
	if contract.Duration != 5*time.Minute || contract.CyclePeriod != time.Minute || contract.Cycles != 5 ||
		contract.MaxRSSGrowth != 64<<20 || contract.MaxGoroutineGrowth != 64 || contract.MaxOpenFDGrowth != 16 || contract.MaxTaskGrowth != 64 {
		t.Fatalf("carrier soak contract = %+v", contract)
	}
	if err := runProductionCarrierSoak(context.Background(), carrier.KindRawQUIC, contract); err == nil {
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
	if err := runProductionCarrierSoak(ctx, kind, productionCarrierSoakContract()); err != nil {
		t.Fatal(err)
	}
}

func runProductionCarrierSoak(ctx context.Context, kind carrier.Kind, contract carrierSoakContract) error {
	if kind != carrier.KindWebSocket && kind != carrier.KindWebTransport {
		return fmt.Errorf("carrier soak does not own %q", kind)
	}
	if contract.Duration <= 0 || contract.CyclePeriod <= 0 || contract.Cycles < 1 ||
		contract.Duration != time.Duration(contract.Cycles)*contract.CyclePeriod {
		return fmt.Errorf("carrier soak contract is invalid: %+v", contract)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	baseline, err := transporttest.CaptureResourceSnapshot()
	if err != nil {
		return fmt.Errorf("capture %s soak baseline: %w", kind, err)
	}
	endpoint, err := transporttest.OpenProductDirectEndpoint(ctx, kind)
	if err != nil {
		return fmt.Errorf("open %s soak endpoint: %w", kind, err)
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
			return fmt.Errorf("cycle %d %s production reconnect: %w", cycle, kind, connectErr)
		}
		if err := waitCapacityUntil(ctx, cycleDeadline, started.Add(contract.Duration)); err != nil {
			return fmt.Errorf("cycle %d %s hold: %w", cycle, kind, err)
		}
	}
	if err := endpoint.Close(); err != nil {
		return fmt.Errorf("close %s soak endpoint: %w", kind, err)
	}
	finish, err := transporttest.CaptureResourceSnapshot()
	if err != nil {
		return fmt.Errorf("capture %s soak cleanup: %w", kind, err)
	}
	if rss := positiveUint64Delta(finish.RSSBytes, baseline.RSSBytes); rss > contract.MaxRSSGrowth {
		return fmt.Errorf("%s soak rss growth %d exceeds budget %d", kind, rss, contract.MaxRSSGrowth)
	}
	if goroutines := positiveIntDelta(finish.Goroutines, baseline.Goroutines); goroutines > contract.MaxGoroutineGrowth {
		return fmt.Errorf("%s soak goroutine growth %d exceeds budget %d", kind, goroutines, contract.MaxGoroutineGrowth)
	}
	if fds := positiveIntDelta(finish.OpenFDs, baseline.OpenFDs); fds > contract.MaxOpenFDGrowth {
		return fmt.Errorf("%s soak fd growth %d exceeds budget %d", kind, fds, contract.MaxOpenFDGrowth)
	}
	if tasks := positiveIntDelta(finish.Tasks, baseline.Tasks); tasks > contract.MaxTaskGrowth {
		return fmt.Errorf("%s soak task growth %d exceeds budget %d", kind, tasks, contract.MaxTaskGrowth)
	}
	return nil
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
