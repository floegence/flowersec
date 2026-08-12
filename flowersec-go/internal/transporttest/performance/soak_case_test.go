package performance

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/transporttest"
)

func TestProductionSoakContractIsFrozen(t *testing.T) {
	contract := productionSoakContract()
	if contract.Duration != 5*time.Minute || contract.CyclePeriod != time.Minute || contract.Cycles != 5 ||
		contract.Reconnects != 5 || contract.Migrations != 5 {
		t.Fatalf("production soak contract = %+v", contract)
	}
}

func TestOwnedTaskResidualIgnoresParkedRuntimeThreads(t *testing.T) {
	start := transporttest.ResourceSnapshot{Goroutines: 4, OpenFDs: 7, Tasks: 8}
	finish := transporttest.ResourceSnapshot{Goroutines: 4, OpenFDs: 7, Tasks: 12}
	if got := ownedTaskResidual(start, finish); got != 0 {
		t.Fatalf("parked runtime task residual = %d, want 0", got)
	}
	finish.Goroutines++
	if got := ownedTaskResidual(start, finish); got != 4 {
		t.Fatalf("owned task residual = %d, want 4", got)
	}
}

func TestFocusedProductionSoakCase(t *testing.T) {
	if os.Getenv("FLOWERSEC_TEST_SOAK") != "1" {
		if os.Getenv("FLOWERSEC_REQUIRED_PERFORMANCE") == "1" {
			t.Fatal("required performance soak environment is incomplete")
		}
		t.Skip("set FLOWERSEC_TEST_SOAK=1 to run the production soak")
	}
	ctx, cancel := context.WithTimeout(performanceTestContext, productionSoakContract().Duration+30*time.Second)
	defer cancel()
	result, err := runNativeProductionSoakCase(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("soak metrics: %+v", result.Metrics)
	if result.FaultCycles != 5 || result.Reconnects != 5 || result.Migrations != 5 || result.Residuals != (soakResiduals{}) {
		t.Fatalf("production soak result = %+v", result)
	}
}

func TestRunSoakCaseRequiresObservedCyclesReconnectsAndMigrations(t *testing.T) {
	contract := soakContract{Duration: 30 * time.Millisecond, CyclePeriod: 10 * time.Millisecond, Cycles: 3, Reconnects: 3, Migrations: 3,
		MaxRSSGrowth: 1024, MaxGoroutineGrowth: 4, MaxOpenFDGrowth: 4, MaxTaskGrowth: 4}
	engine := &fakeSoakEngine{}
	result, err := runSoakCase(context.Background(), contract, engine, monotonicSnapshots())
	if err != nil {
		t.Fatal(err)
	}
	if engine.cycles != 3 || engine.closed != 1 || result.FaultCycles != 3 || result.Reconnects != 3 || result.Migrations != 3 {
		t.Fatalf("engine/result = %+v / %+v", engine, result)
	}
	if len(result.Timeline) != 5 || result.Timeline[0].Event != "soak_started" ||
		result.Timeline[4].Event != "soak_completed" || result.Timeline[4].AtNS < contract.Duration.Nanoseconds() {
		t.Fatalf("soak trace = %+v", result.Timeline)
	}
	for index := 1; index <= contract.Cycles; index++ {
		if result.Timeline[index].AtNS < int64(index)*contract.CyclePeriod.Nanoseconds() ||
			result.Resources[index].AtNS < int64(index)*contract.CyclePeriod.Nanoseconds() {
			t.Fatalf("cycle %d measured trace/resource timestamp is early: trace=%d resource=%d", index,
				result.Timeline[index].AtNS, result.Resources[index].AtNS)
		}
	}
	if result.Resources[len(result.Resources)-1].AtNS < contract.Duration.Nanoseconds() {
		t.Fatal("soak completion resource timestamp is early")
	}
	if len(result.Resources) != contract.Cycles+2 || result.Resources[len(result.Resources)-1].ResidualSessions == nil ||
		*result.Resources[len(result.Resources)-1].ResidualSessions != 0 {
		t.Fatalf("soak resources = %+v", result.Resources)
	}
}

func TestRunSoakCaseAcceptsResourceDeclineAndRetainsIntermediatePeak(t *testing.T) {
	contract := soakContract{Duration: 20 * time.Millisecond, CyclePeriod: 10 * time.Millisecond, Cycles: 2, Reconnects: 2, Migrations: 2,
		MaxRSSGrowth: 1024, MaxGoroutineGrowth: 4, MaxOpenFDGrowth: 4, MaxTaskGrowth: 4}
	started := time.Now()
	snapshots := []transporttest.ResourceSnapshot{
		{At: started, RSSBytes: 100, Goroutines: 10, OpenFDs: 10, Tasks: 10},
		{At: started.Add(10 * time.Millisecond), RSSBytes: 140, Goroutines: 14, OpenFDs: 14, Tasks: 14},
		{At: started.Add(20 * time.Millisecond), RSSBytes: 120, Goroutines: 12, OpenFDs: 12, Tasks: 12},
		{At: started.Add(21 * time.Millisecond), RSSBytes: 80, Goroutines: 8, OpenFDs: 8, Tasks: 8},
	}
	index := 0
	result, err := runSoakCase(context.Background(), contract, &fakeSoakEngine{}, func() (transporttest.ResourceSnapshot, error) {
		value := snapshots[index]
		index++
		return value, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RSSGrowth != 0 || result.GoroutineGrowth != 0 || result.OpenFDGrowth != 0 || result.TaskGrowth != 0 {
		t.Fatalf("declining final resources produced growth: %+v", result)
	}
	if result.RSSPeak != 140 || result.GoroutinePeak != 14 || result.OpenFDPeak != 14 || result.TaskPeak != 14 {
		t.Fatalf("intermediate resource peak was not retained: %+v", result)
	}
}

func TestRunSoakCaseUsesMeasuredSnapshotTimestampsForResources(t *testing.T) {
	contract := soakContract{Duration: time.Millisecond, CyclePeriod: time.Millisecond, Cycles: 1, Reconnects: 1, Migrations: 1,
		MaxRSSGrowth: 1024, MaxGoroutineGrowth: 4, MaxOpenFDGrowth: 4, MaxTaskGrowth: 4}
	started := time.Now()
	snapshots := []transporttest.ResourceSnapshot{
		{At: started, RSSBytes: 100, Goroutines: 4, OpenFDs: 4, Tasks: 4},
		{At: started.Add(7 * time.Millisecond), RSSBytes: 100, Goroutines: 4, OpenFDs: 4, Tasks: 4},
		{At: started.Add(9 * time.Millisecond), RSSBytes: 100, Goroutines: 4, OpenFDs: 4, Tasks: 4},
	}
	index := 0
	result, err := runSoakCase(context.Background(), contract, &fakeSoakEngine{}, func() (transporttest.ResourceSnapshot, error) {
		value := snapshots[index]
		index++
		return value, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Resources[1].AtNS != (7*time.Millisecond).Nanoseconds() ||
		result.Resources[2].AtNS != (9*time.Millisecond).Nanoseconds() {
		t.Fatalf("resource timestamps = %+v", result.Resources)
	}
	if result.Timeline[1].AtNS == result.Resources[1].AtNS {
		t.Fatal("trace timestamp was reconstructed from the resource snapshot")
	}
}

func TestRunSoakCaseFailsClosedWithoutMigrationProof(t *testing.T) {
	contract := soakContract{Duration: 10 * time.Millisecond, CyclePeriod: 10 * time.Millisecond, Cycles: 1, Reconnects: 1, Migrations: 1,
		MaxRSSGrowth: 1024, MaxGoroutineGrowth: 4, MaxOpenFDGrowth: 4, MaxTaskGrowth: 4}
	engine := &fakeSoakEngine{omitMigration: true}
	if _, err := runSoakCase(context.Background(), contract, engine, monotonicSnapshots()); !errors.Is(err, errSoakMigrationUnproven) {
		t.Fatalf("missing migration error = %v", err)
	}
	if _, err := runProductionSoakCase(context.Background(), nil); !errors.Is(err, errSoakEngineUnavailable) {
		t.Fatalf("missing production engine error = %v", err)
	}
}

func TestRawQUICSoakEnginePerformsRealReconnectAndMigration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	engine, err := newRawQUICSoakEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for ordinal := 1; ordinal <= 2; ordinal++ {
		observation, err := engine.RunCycle(ctx, ordinal)
		if err != nil {
			t.Fatal(err)
		}
		if !observation.FaultApplied || !observation.Reconnected || !observation.Migrated {
			t.Fatalf("cycle %d observation = %+v", ordinal, observation)
		}
	}
	residuals, err := engine.Residuals()
	if err != nil {
		t.Fatal(err)
	}
	if residual := residuals.Sessions; residual != 2 {
		t.Fatalf("live raw QUIC sessions = %d, want 2", residual)
	}
	if err := engine.Close(ctx); err != nil {
		t.Fatal(err)
	}
	residuals, err = engine.Residuals()
	if err != nil {
		t.Fatal(err)
	}
	if residual := residuals.Sessions; residual != 0 {
		t.Fatalf("residual raw QUIC sessions = %d, want 0", residual)
	}
	if residuals.Goroutines != 0 || residuals.OpenFDs != 0 || residuals.Tasks != 0 {
		t.Fatalf("raw QUIC resource residuals = %+v", residuals)
	}
}

type fakeSoakEngine struct {
	cycles        int
	closed        int
	omitMigration bool
}

func (engine *fakeSoakEngine) RunCycle(context.Context, int) (soakCycleObservation, error) {
	engine.cycles++
	return soakCycleObservation{FaultApplied: true, Reconnected: true, Migrated: !engine.omitMigration}, nil
}

func (engine *fakeSoakEngine) Close(context.Context) error { engine.closed++; return nil }
func (engine *fakeSoakEngine) Residuals() (soakResiduals, error) {
	return soakResiduals{}, nil
}
