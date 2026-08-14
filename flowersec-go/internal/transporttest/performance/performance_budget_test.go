package performance

import (
	"testing"
	"time"
)

func TestTenMinutePerformanceBudgetPreservesCoverageWithinSevenMinuteMeasurementPlan(t *testing.T) {
	t.Setenv("FLOWERSEC_PERFORMANCE_BUDGET", "10m")

	capacity := productionCapacityContract()
	browser := productionBrowserCapacityContract()
	browserStreams := productionBrowserStreamCapacityContract()
	if capacity.Sessions != 1000 || browser.Sessions != 1000 || browserStreams.Sessions != 100 || browserStreams.StreamsPerSession != 128 {
		t.Fatalf("performance coverage changed: capacity=%+v browser=%+v browser streams=%+v", capacity, browser, browserStreams)
	}
	if capacity.MaxCPU != 120*time.Second || browser.MaxCPU != 150*time.Second || browserStreams.MaxCPU != 240*time.Second ||
		capacity.MaxRSS != 1<<30 || browser.MaxRSS != 3<<30 ||
		capacity.MaxConnectP50 != 5*time.Second || capacity.MaxConnectP95 != 15*time.Second || capacity.MaxConnectP99 != 25*time.Second {
		t.Fatalf("capacity thresholds changed: capacity=%+v browser=%+v browser streams=%+v", capacity, browser, browserStreams)
	}
	for name, contract := range map[string]capacityContract{"capacity": capacity, "browser": browser, "browser streams": browserStreams} {
		if got := contract.Ramp + contract.Hold + contract.Cleanup; got != 20*time.Second {
			t.Fatalf("%s window = %s, want 20s", name, got)
		}
	}

	soak := productionSoakContract()
	carrierSoak := productionCarrierSoakContract()
	if soak.Duration != 30*time.Second || soak.Cycles != 3 || soak.Reconnects != 3 || soak.Migrations != 3 {
		t.Fatalf("migration soak = %+v", soak)
	}
	if carrierSoak.Duration != 30*time.Second || carrierSoak.Cycles != 3 {
		t.Fatalf("carrier soak = %+v", carrierSoak)
	}
	if soak.MaxRSSGrowth != 64<<20 || carrierSoak.MaxRSSGrowth != 64<<20 {
		t.Fatalf("soak thresholds changed: migration=%+v carrier=%+v", soak, carrierSoak)
	}
	if soak.CPUTimeBudget != 5*time.Minute || carrierSoak.CPUTimeBudget != 5*time.Minute {
		t.Fatalf("soak CPU thresholds changed: migration=%+v carrier=%+v", soak, carrierSoak)
	}

	single := productionSingleConnectionThroughputContracts()
	streaming := productionStreamingThroughputContracts()
	if len(single) != 3 || len(streaming) != 9 {
		t.Fatalf("throughput coordinates = single %d streaming %d", len(single), len(streaming))
	}
	for _, contract := range append(append([]payloadThroughputContract(nil), single...), streaming...) {
		if contract.Samples != 3 || contract.SampleDuration != 700*time.Millisecond {
			t.Fatalf("throughput sampling changed incorrectly: %+v", contract)
		}
		if contract.MinBytesPerSecond != 1<<20 || contract.MaxP95 != 2*time.Second {
			t.Fatalf("throughput thresholds changed: %+v", contract)
		}
	}

	measurementPlan := 12*(capacity.Ramp+capacity.Hold+capacity.Cleanup) +
		soak.Duration + 2*carrierSoak.Duration +
		3*time.Duration(single[0].Samples)*single[0].SampleDuration +
		3*9*time.Duration(streaming[0].Samples)*streaming[0].SampleDuration
	if measurementPlan > 7*time.Minute {
		t.Fatalf("ten-minute performance measurement plan = %s, want <= 7m", measurementPlan)
	}
}

func TestCustomPerformanceBudgetScalesMeasurementWindows(t *testing.T) {
	t.Setenv("FLOWERSEC_PERFORMANCE_BUDGET", "20m")
	capacity := productionCapacityContract()
	soak := productionSoakContract()
	single := productionSingleConnectionThroughputContracts()
	if capacity.Ramp+capacity.Hold+capacity.Cleanup != 40*time.Second {
		t.Fatalf("20m capacity window = %s", capacity.Ramp+capacity.Hold+capacity.Cleanup)
	}
	if soak.Duration != time.Minute || soak.CyclePeriod != 20*time.Second {
		t.Fatalf("20m soak = %+v", soak)
	}
	if single[0].SampleDuration != 1400*time.Millisecond {
		t.Fatalf("20m throughput sample window = %s", single[0].SampleDuration)
	}
}
