package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
)

func TestProductionSoakContractIsFrozen(t *testing.T) {
	contract := productionSoakContract()
	if contract.Duration != time.Hour || contract.CyclePeriod != time.Minute || contract.Cycles != 60 ||
		contract.Reconnects != 60 || contract.Migrations != 60 {
		t.Fatalf("production soak contract = %+v", contract)
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
	if len(result.Trace.Records) != 5 || result.Trace.Records[0].Event != "soak_started" ||
		result.Trace.Records[4].Event != "soak_completed" || result.Trace.Records[4].AtNS < contract.Duration.Nanoseconds() {
		t.Fatalf("soak trace = %+v", result.Trace.Records)
	}
	for index := 1; index <= contract.Cycles; index++ {
		if result.Trace.Records[index].AtNS < int64(index)*contract.CyclePeriod.Nanoseconds() ||
			result.Resource.Records[index].AtNS < int64(index)*contract.CyclePeriod.Nanoseconds() {
			t.Fatalf("cycle %d measured trace/resource timestamp is early: trace=%d resource=%d", index,
				result.Trace.Records[index].AtNS, result.Resource.Records[index].AtNS)
		}
	}
	if result.Resource.Records[len(result.Resource.Records)-1].AtNS < contract.Duration.Nanoseconds() {
		t.Fatal("soak completion resource timestamp is early")
	}
	if len(result.Resource.Records) != contract.Cycles+2 || result.Resource.Records[len(result.Resource.Records)-1].ResidualSessions == nil ||
		*result.Resource.Records[len(result.Resource.Records)-1].ResidualSessions != 0 {
		t.Fatalf("soak resources = %+v", result.Resource.Records)
	}
}

func TestRunSoakCaseAcceptsResourceDeclineAndRetainsIntermediatePeak(t *testing.T) {
	contract := soakContract{Duration: 20 * time.Millisecond, CyclePeriod: 10 * time.Millisecond, Cycles: 2, Reconnects: 2, Migrations: 2,
		MaxRSSGrowth: 1024, MaxGoroutineGrowth: 4, MaxOpenFDGrowth: 4, MaxTaskGrowth: 4}
	started := time.Now()
	snapshots := []transportrelease.ResourceSnapshot{
		{At: started, RSSBytes: 100, Goroutines: 10, OpenFDs: 10, Tasks: 10},
		{At: started.Add(10 * time.Millisecond), RSSBytes: 140, Goroutines: 14, OpenFDs: 14, Tasks: 14},
		{At: started.Add(20 * time.Millisecond), RSSBytes: 120, Goroutines: 12, OpenFDs: 12, Tasks: 12},
		{At: started.Add(21 * time.Millisecond), RSSBytes: 80, Goroutines: 8, OpenFDs: 8, Tasks: 8},
	}
	index := 0
	result, err := runSoakCase(context.Background(), contract, &fakeSoakEngine{}, func() (transportrelease.ResourceSnapshot, error) {
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
	snapshots := []transportrelease.ResourceSnapshot{
		{At: started, RSSBytes: 100, Goroutines: 4, OpenFDs: 4, Tasks: 4},
		{At: started.Add(7 * time.Millisecond), RSSBytes: 100, Goroutines: 4, OpenFDs: 4, Tasks: 4},
		{At: started.Add(9 * time.Millisecond), RSSBytes: 100, Goroutines: 4, OpenFDs: 4, Tasks: 4},
	}
	index := 0
	result, err := runSoakCase(context.Background(), contract, &fakeSoakEngine{}, func() (transportrelease.ResourceSnapshot, error) {
		value := snapshots[index]
		index++
		return value, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Resource.Records[1].AtNS != (7*time.Millisecond).Nanoseconds() ||
		result.Resource.Records[2].AtNS != (9*time.Millisecond).Nanoseconds() {
		t.Fatalf("resource timestamps = %+v", result.Resource.Records)
	}
	if result.Trace.Records[1].AtNS == result.Resource.Records[1].AtNS {
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

func TestSoakRawSourceAttributionBindsExactQLOGAndPCAPBytes(t *testing.T) {
	qlog := testSoakQLOG(t, "0123456789abcdef")
	pcap := testSoakPCAP()
	sources := []soakCycleSource{{Ordinal: 1, ConnectionID: "0123456789abcdef", QLOG: qlog, PCAP: pcap}}
	qlogAttribution, err := buildSoakQLOGAttribution("case CAP-SOAK-HOURLY", sources)
	if err != nil {
		t.Fatal(err)
	}
	pcapAttribution, err := buildSoakPCAPAttribution("case CAP-SOAK-HOURLY", sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(qlogAttribution.Records) != 1 || qlogAttribution.Records[0].SourceID != "qlog-001" ||
		qlogAttribution.Records[0].ConnectionGroupID != sources[0].ConnectionID || qlogAttribution.Records[0].ByteLength <= 0 ||
		len(pcapAttribution.Records) != 1 || pcapAttribution.Records[0].SourceID != "pcap-001" || pcapAttribution.Records[0].ByteOffset != 24 {
		t.Fatalf("qlog/pcap attribution = %+v / %+v", qlogAttribution, pcapAttribution)
	}
	sources[0].ConnectionID = "fedcba9876543210"
	if _, err := buildSoakQLOGAttribution("case CAP-SOAK-HOURLY", sources); err == nil {
		t.Fatal("qlog connection ID mismatch was accepted")
	}
}

func testSoakQLOG(t *testing.T, connectionID string) []byte {
	t.Helper()
	header := map[string]any{
		"file_schema": "urn:ietf:params:qlog:file:sequential", "serialization_format": "application/qlog+json-seq",
		"qlog_version": "0.3", "qlog_format": "JSON-SEQ", "code_version": "v0.60.0",
		"trace": map[string]any{"common_fields": map[string]any{"group_id": connectionID,
			"reference_time": map[string]any{"clock_type": "monotonic", "epoch": "unknown", "wall_clock_time": "2026-07-25T00:00:00Z"}}},
	}
	event := map[string]any{"time": 1, "name": "transport:packet_sent", "data": map[string]any{
		"header": map[string]any{"packet_type": "1RTT", "packet_number": 1},
		"frames": []any{map[string]any{"frame_type": "stream", "stream_id": 4, "offset": 0, "length": 1}},
	}}
	var output bytes.Buffer
	for _, value := range []any{header, event} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		output.WriteByte(0x1e)
		output.Write(data)
		output.WriteByte('\n')
	}
	return output.Bytes()
}

func testSoakPCAP() []byte {
	data := make([]byte, 24+16+4)
	copy(data[:4], []byte{0xd4, 0xc3, 0xb2, 0xa1})
	binary.LittleEndian.PutUint32(data[20:24], 101)
	binary.LittleEndian.PutUint32(data[24:28], 1)
	binary.LittleEndian.PutUint32(data[28:32], 2)
	binary.LittleEndian.PutUint32(data[32:36], 4)
	binary.LittleEndian.PutUint32(data[36:40], 4)
	copy(data[40:], []byte{1, 2, 3, 4})
	return data
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
