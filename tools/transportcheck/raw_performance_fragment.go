package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"time"
)

type producerFieldGap struct {
	Scope  string `json:"scope"`
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

type rawPerformanceFragment struct {
	CellID string             `json:"cell_id"`
	Run    RunEvidence        `json:"run"`
	Gaps   []producerFieldGap `json:"gaps"`
}

type rawBaselineReport struct {
	SchemaVersion   int                        `json:"schema_version"`
	Classification  string                     `json:"classification"`
	SourceSHA       string                     `json:"source_sha"`
	ManifestDigest  string                     `json:"manifest_digest"`
	ManifestSHA256  string                     `json:"manifest_file_sha256"`
	BPFObjectSHA256 string                     `json:"bpf_object_sha256"`
	Runner          rawBaselineRunner          `json:"runner"`
	StartedAt       time.Time                  `json:"started_at"`
	FinishedAt      time.Time                  `json:"finished_at"`
	Results         []rawBaselineCarrierResult `json:"results"`
}

type rawBaselineRunner struct {
	OS            string `json:"os"`
	Architecture  string `json:"architecture"`
	KernelRelease string `json:"kernel_release"`
}

type rawBaselineCarrierResult struct {
	Run             int                    `json:"run"`
	Carrier         string                 `json:"carrier"`
	Cold            []rawConnectOperation  `json:"cold"`
	RPC             []rawRPCOperation      `json:"rpc"`
	Bulk            rawBulkResult          `json:"bulk"`
	CleanupDuration int64                  `json:"cleanup_duration_ns"`
	Resource        rawResourceMeasurement `json:"resource"`
	Phases          []rawPhaseMeasurement  `json:"phases"`
	Kernel          json.RawMessage        `json:"kernel,omitempty"`
	Artifacts       []rawReleaseArtifact   `json:"artifacts"`
}

type rawConnectOperation struct {
	Ordinal          int       `json:"ordinal"`
	ScheduledAt      time.Time `json:"scheduled_at"`
	StartedAt        time.Time `json:"started_at"`
	Duration         int64     `json:"duration_ns"`
	CleanupDuration  int64     `json:"cleanup_duration_ns"`
	StartedCandidate string    `json:"started_candidate"`
	WinnerCandidate  string    `json:"winner_candidate"`
	CommitCount      int       `json:"commit_count"`
	CredentialWrites int       `json:"credential_write_count"`
}

type rawRPCOperation struct {
	Ordinal       int       `json:"ordinal"`
	ScheduledAt   time.Time `json:"scheduled_at"`
	StartedAt     time.Time `json:"started_at"`
	Duration      int64     `json:"duration_ns"`
	InputBytes    int       `json:"input_bytes"`
	OutputBytes   int       `json:"output_bytes"`
	PayloadSHA256 [32]byte  `json:"payload_sha256"`
}

type rawBulkResult struct {
	StartedAt         time.Time          `json:"started_at"`
	Duration          int64              `json:"duration_ns"`
	BytesPerDirection int64              `json:"bytes_per_direction"`
	ActiveStreams     int                `json:"active_streams"`
	Directions        []rawBulkDirection `json:"directions"`
}

type rawBulkDirection struct {
	Direction string                `json:"direction"`
	Warmup    rawBulkPhaseDirection `json:"warmup"`
	Score     rawBulkPhaseDirection `json:"score"`
}

type rawBulkPhaseDirection struct {
	Direction     string    `json:"direction"`
	ScheduledAt   time.Time `json:"scheduled_at"`
	StartedAt     time.Time `json:"started_at"`
	Duration      int64     `json:"duration_ns"`
	Bytes         int64     `json:"bytes"`
	PayloadSHA256 [32]byte  `json:"payload_sha256"`
}

type rawResourceMeasurement struct {
	StartedAt      time.Time           `json:"started_at"`
	FinishedAt     time.Time           `json:"finished_at"`
	CPUNanoseconds uint64              `json:"cpu_nanoseconds"`
	AllocatedBytes uint64              `json:"allocated_bytes"`
	Start          rawResourceSnapshot `json:"start"`
	Finish         rawResourceSnapshot `json:"finish"`
}

type rawResourceSnapshot struct {
	At             time.Time `json:"at"`
	RSSBytes       uint64    `json:"rss_bytes"`
	CPUNanoseconds uint64    `json:"cpu_nanoseconds"`
	AllocatedBytes uint64    `json:"allocated_bytes"`
	OpenFDs        int       `json:"open_fds"`
	Goroutines     int       `json:"goroutines"`
	Tasks          int       `json:"tasks"`
}

type rawPhaseMeasurement struct {
	Phase         string                 `json:"phase"`
	Resource      rawResourceMeasurement `json:"resource"`
	ActiveStreams int                    `json:"active_streams"`
	KernelStart   *rawKernelEvidence     `json:"kernel_start,omitempty"`
	KernelFinish  *rawKernelEvidence     `json:"kernel_finish,omitempty"`
}

type rawKernelEvidence struct {
	Client rawKernelFaultStats `json:"client"`
	Server rawKernelFaultStats `json:"server"`
}

type rawKernelFaultStats struct {
	Packets             uint64    `json:"packets"`
	Bytes               uint64    `json:"bytes"`
	DelayPackets        uint64    `json:"delay_packets"`
	JitterPackets       uint64    `json:"jitter_packets"`
	PeriodicLossPackets uint64    `json:"periodic_loss_packets"`
	BurstLossPackets    uint64    `json:"burst_loss_packets"`
	MTUDropPackets      uint64    `json:"mtu_drop_packets"`
	GSOPackets          uint64    `json:"gso_packets"`
	TimestampErrors     uint64    `json:"timestamp_errors"`
	ReorderPackets      uint64    `json:"reorder_packets"`
	DuplicatePackets    uint64    `json:"duplicate_packets"`
	DuplicateErrors     uint64    `json:"duplicate_errors"`
	OutageDropPackets   uint64    `json:"outage_drop_packets"`
	FirstPacketNS       uint64    `json:"first_packet_ns"`
	DeliveredPackets    uint64    `json:"delivered_packets"`
	JitterSlotPackets   [8]uint64 `json:"jitter_slot_packets"`
}

type rawReleaseArtifact struct {
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// assembleRawCleanDirectFragment converts only fields that are present in the
// low-level baseline report. Gaps stay explicit until the producer records the
// missing phase-scoped measurements.
func assembleRawCleanDirectFragment(reportPath, cellID string, runNumber int, writer *typedArtifactWriter) (_ rawPerformanceFragment, resultErr error) {
	carrier := map[string]string{"clean-02": "websocket", "clean-03": "raw_quic"}[cellID]
	if carrier == "" || runNumber < 1 || writer == nil {
		return rawPerformanceFragment{}, errors.New("raw clean direct fragment request is invalid")
	}
	checkpoint := writer.checkpoint()
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, writer.rollback(checkpoint))
		}
	}()
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return rawPerformanceFragment{}, err
	}
	var report rawBaselineReport
	if err := decodeStrictJSON(data, &report); err != nil {
		return rawPerformanceFragment{}, err
	}
	if report.SchemaVersion != 1 || report.Classification != "linux_transport_workload_baseline" ||
		!gitSHAPattern.MatchString(report.SourceSHA) || report.ManifestDigest == "" || !validSHA256(report.ManifestSHA256) || !validSHA256(report.BPFObjectSHA256) ||
		report.Runner.OS != "linux" || report.Runner.Architecture == "" || report.Runner.KernelRelease == "" ||
		report.StartedAt.IsZero() || !report.FinishedAt.After(report.StartedAt) {
		return rawPerformanceFragment{}, errors.New("raw baseline report identity is invalid")
	}
	matches := make([]rawBaselineCarrierResult, 0, 1)
	for _, result := range report.Results {
		if result.Run == runNumber && result.Carrier == carrier {
			matches = append(matches, result)
		}
	}
	if len(matches) == 0 {
		return rawPerformanceFragment{}, fmt.Errorf("raw baseline has no %s run %d", carrier, runNumber)
	}
	if len(matches) != 1 {
		return rawPerformanceFragment{}, fmt.Errorf("raw baseline has %d %s run %d records, want exactly one", len(matches), carrier, runNumber)
	}
	result := matches[0]
	if !result.Resource.StartedAt.IsZero() && result.Resource.StartedAt.Before(report.StartedAt) ||
		!result.Resource.FinishedAt.IsZero() && result.Resource.FinishedAt.After(report.FinishedAt) {
		return rawPerformanceFragment{}, errors.New("raw baseline result falls outside the report time boundary")
	}
	attributed, err := prepareRawPhaseArtifacts(reportPath, cellID, result)
	if err != nil {
		return rawPerformanceFragment{}, fmt.Errorf("raw phase attribution: %w", err)
	}
	contextPrefix := fmt.Sprintf("cell %s run %d", cellID, runNumber)
	rawSources, err := writeRawEvidenceSources(writer, contextPrefix+" raw sources", fmt.Sprintf("%s-run-%02d", cellID, runNumber), attributed)
	if err != nil {
		return rawPerformanceFragment{}, fmt.Errorf("%s raw sources: %w", contextPrefix, err)
	}
	cold, selection, err := rawColdSeries(result.Cold, cellID, runNumber)
	if err != nil {
		return rawPerformanceFragment{}, fmt.Errorf("%s cold: %w", contextPrefix, err)
	}
	cleanup, err := rawCleanupSeries(result.CleanupDuration, runNumber)
	if err != nil {
		return rawPerformanceFragment{}, fmt.Errorf("%s cleanup: %w", contextPrefix, err)
	}
	resourceContext := contextPrefix + " resource"
	resource, err := rawRunResourceArtifact(resourceContext, result, attributed.retransmittedBytes, attributed.lossRecoveryNS)
	if err != nil {
		return rawPerformanceFragment{}, fmt.Errorf("%s resource: %w", contextPrefix, err)
	}
	rpc, err := rawRPCSeries(result.RPC, runNumber)
	if err != nil {
		return rawPerformanceFragment{}, fmt.Errorf("%s rpc: %w", contextPrefix, err)
	}
	bulk, err := rawBulkSeries(result.Bulk, runNumber)
	if err != nil {
		return rawPerformanceFragment{}, fmt.Errorf("%s bulk: %w", contextPrefix, err)
	}
	coldContext := contextPrefix + " phase clean-v1/cold"
	coldRef, err := writer.WriteJSON(coldContext, "samples", fmt.Sprintf("%s-run-%02d-cold-samples", cellID, runNumber), OperationSeriesArtifact{
		SchemaVersion: 1, Kind: "transport_samples", Context: coldContext, Records: []OperationSeriesRecord{cold},
	})
	if err != nil {
		return rawPerformanceFragment{}, err
	}
	coldTraceRef, err := writeRawPhaseTrace(writer, coldContext, fmt.Sprintf("%s-run-%02d-cold-trace", cellID, runNumber), result.Cold)
	if err != nil {
		return rawPerformanceFragment{}, err
	}
	coldSupplement, err := writeRawPhaseSupplements(writer, coldContext, fmt.Sprintf("%s-run-%02d-cold", cellID, runNumber), report.ManifestDigest, attributed.phases["cold"])
	if err != nil {
		return rawPerformanceFragment{}, err
	}
	rpcContext := contextPrefix + " phase clean-v1/rpc"
	rpcRef, err := writer.WriteJSON(rpcContext, "samples", fmt.Sprintf("%s-run-%02d-rpc-samples", cellID, runNumber), OperationSeriesArtifact{
		SchemaVersion: 1, Kind: "transport_samples", Context: rpcContext, Records: []OperationSeriesRecord{rpc},
	})
	if err != nil {
		return rawPerformanceFragment{}, err
	}
	rpcTraceRef, err := writeRawPhaseTrace(writer, rpcContext, fmt.Sprintf("%s-run-%02d-rpc-trace", cellID, runNumber), result.RPC)
	if err != nil {
		return rawPerformanceFragment{}, err
	}
	rpcSupplement, err := writeRawPhaseSupplements(writer, rpcContext, fmt.Sprintf("%s-run-%02d-rpc", cellID, runNumber), report.ManifestDigest, attributed.phases["rpc"])
	if err != nil {
		return rawPerformanceFragment{}, err
	}
	bulkContext := contextPrefix + " phase clean-v1/bulk"
	bulkRef, err := writer.WriteJSON(bulkContext, "samples", fmt.Sprintf("%s-run-%02d-bulk-samples", cellID, runNumber), OperationSeriesArtifact{
		SchemaVersion: 1, Kind: "transport_samples", Context: bulkContext, Records: []OperationSeriesRecord{bulk},
	})
	if err != nil {
		return rawPerformanceFragment{}, err
	}
	bulkTraceRef, err := writeRawPhaseTrace(writer, bulkContext, fmt.Sprintf("%s-run-%02d-bulk-trace", cellID, runNumber), result.Bulk)
	if err != nil {
		return rawPerformanceFragment{}, err
	}
	bulkSupplement, err := writeRawPhaseSupplements(writer, bulkContext, fmt.Sprintf("%s-run-%02d-bulk", cellID, runNumber), report.ManifestDigest, attributed.phases["bulk"])
	if err != nil {
		return rawPerformanceFragment{}, err
	}

	cleanupContext := contextPrefix + " phase clean-v1/cleanup"
	cleanupRef, err := writer.WriteJSON(cleanupContext, "samples", fmt.Sprintf("%s-run-%02d-cleanup-samples", cellID, runNumber), OperationSeriesArtifact{
		SchemaVersion: 1, Kind: "transport_samples", Context: cleanupContext, Records: []OperationSeriesRecord{cleanup},
	})
	if err != nil {
		return rawPerformanceFragment{}, err
	}
	cleanupTraceRef, err := writeRawPhaseTrace(writer, cleanupContext, fmt.Sprintf("%s-run-%02d-cleanup-trace", cellID, runNumber), struct {
		Duration int64 `json:"duration_ns"`
	}{result.CleanupDuration})
	if err != nil {
		return rawPerformanceFragment{}, err
	}
	cleanupSupplement, err := writeRawPhaseSupplements(writer, cleanupContext, fmt.Sprintf("%s-run-%02d-cleanup", cellID, runNumber), report.ManifestDigest, attributed.phases["cleanup"])
	if err != nil {
		return rawPerformanceFragment{}, err
	}
	resourceRef, err := writer.WriteJSON(resourceContext, "resource", fmt.Sprintf("%s-run-%02d-resource", cellID, runNumber), resource)
	if err != nil {
		return rawPerformanceFragment{}, err
	}
	fragment := rawPerformanceFragment{
		CellID: cellID,
		Run: RunEvidence{RunNumber: runNumber, Resource: resourceRef, RawSources: rawSources, Phases: []PhaseEvidence{
			{ProfileID: "clean-v1", Phase: "cold", SampleCount: rawIntPointer(len(result.Cold)), FailureCount: rawIntPointer(0), RetryCount: rawIntPointer(0), Selection: selection, Artifacts: mergeRawArtifacts(coldSupplement, "samples", coldRef, "trace", coldTraceRef)},
			{ProfileID: "clean-v1", Phase: "rpc", SampleCount: rawIntPointer(len(result.RPC)), FailureCount: rawIntPointer(0), RetryCount: rawIntPointer(0), Artifacts: mergeRawArtifacts(rpcSupplement, "samples", rpcRef, "trace", rpcTraceRef)},
			{ProfileID: "clean-v1", Phase: "bulk", SampleCount: rawIntPointer(2), FailureCount: rawIntPointer(0), RetryCount: rawIntPointer(0), Artifacts: mergeRawArtifacts(bulkSupplement, "samples", bulkRef, "trace", bulkTraceRef)},
			{ProfileID: "clean-v1", Phase: "cleanup", SampleCount: rawIntPointer(1), FailureCount: rawIntPointer(0), RetryCount: rawIntPointer(0), Artifacts: mergeRawArtifacts(cleanupSupplement, "samples", cleanupRef, "trace", cleanupTraceRef)},
		}},
		Gaps: make([]producerFieldGap, 0),
	}
	return fragment, nil
}

func rawColdSeries(operations []rawConnectOperation, cellID string, runNumber int) (OperationSeriesRecord, SelectionEvidence, error) {
	contract, err := signedOperationContract("clean-v1", "cold")
	if err != nil {
		return OperationSeriesRecord{}, SelectionEvidence{}, err
	}
	if len(operations) != 2000 {
		return OperationSeriesRecord{}, SelectionEvidence{}, fmt.Errorf("operation count = %d, want 2000", len(operations))
	}
	candidate := map[string]string{"clean-02": "direct-wss", "clean-03": "direct-raw-quic"}[cellID]
	if candidate == "" {
		return OperationSeriesRecord{}, SelectionEvidence{}, errors.New("cold selection cell is invalid")
	}
	origin := operations[0].ScheduledAt
	starts := make([]int64, len(operations))
	durations := make([]int64, len(operations))
	boundaries := make([]rawBoundary, 0, 2*len(operations))
	for index, operation := range operations {
		wantScheduled := origin.Add(time.Duration(index) * time.Duration(contract.scheduledIntervalNS))
		if operation.Ordinal != index+1 || operation.ScheduledAt.IsZero() || operation.StartedAt.IsZero() || !operation.ScheduledAt.Equal(wantScheduled) ||
			operation.StartedAt.Before(operation.ScheduledAt) || operation.Duration <= 0 || operation.Duration > contract.operationDeadlineNS || operation.CleanupDuration <= 0 ||
			operation.StartedCandidate != candidate || operation.WinnerCandidate != candidate || operation.CommitCount != 1 || operation.CredentialWrites != 1 {
			return OperationSeriesRecord{}, SelectionEvidence{}, fmt.Errorf("operation %d does not preserve the measured frozen schedule and selection", index+1)
		}
		scheduledOffset := operation.ScheduledAt.Sub(origin).Nanoseconds()
		starts[index] = operation.StartedAt.Sub(operation.ScheduledAt).Nanoseconds()
		if scheduledOffset > contract.phaseDeadlineNS || starts[index] > contract.phaseDeadlineNS-scheduledOffset ||
			operation.Duration > contract.phaseDeadlineNS-scheduledOffset-starts[index] {
			return OperationSeriesRecord{}, SelectionEvidence{}, fmt.Errorf("operation %d exceeds the measured frozen phase deadline", index+1)
		}
		durations[index] = operation.Duration
		started := operation.StartedAt.Sub(origin).Nanoseconds()
		boundaries = append(boundaries, rawBoundary{at: started, delta: 1}, rawBoundary{at: started + operation.Duration, delta: -1})
	}
	maximum := maximumRawInflight(boundaries)
	if maximum < 1 || maximum > contract.maxInflight {
		return OperationSeriesRecord{}, SelectionEvidence{}, fmt.Errorf("measured max inflight = %d, limit %d", maximum, contract.maxInflight)
	}
	empty := sha256.Sum256(nil)
	record := OperationSeriesRecord{
		RunNumber: runNumber, OperationCount: len(operations), ScheduledFirstNS: 0, ScheduledIntervalNS: contract.scheduledIntervalNS,
		StartDelayNS: compressInt64(starts), DurationNS: compressInt64(durations), RetryCounts: constantIntRun(len(operations), 0),
		InputBytes: constantIntRun(len(operations), 0), OutputBytes: constantIntRun(len(operations), 0), ScoredBytes: constantIntRun(len(operations), 0), ScoreDurationNS: constantIntRun(len(operations), 0),
		OperationDeadlineNS: contract.operationDeadlineNS, PhaseDeadlineNS: contract.phaseDeadlineNS, MaxInflightObserved: maximum,
		ExpectedPayloadSHA256: hex.EncodeToString(empty[:]), ActualPayloadSHA256: hex.EncodeToString(empty[:]),
	}
	selection := SelectionEvidence{
		OperationCount: len(operations), StartedCandidates: map[string]int{candidate: len(operations)},
		WinnerCount: len(operations), SingleBarrierOperations: len(operations), CommitCount: len(operations), CredentialWriteCount: len(operations),
	}
	return record, selection, nil
}

func rawRPCSeries(operations []rawRPCOperation, runNumber int) (OperationSeriesRecord, error) {
	contract, err := signedOperationContract("clean-v1", "rpc")
	if err != nil {
		return OperationSeriesRecord{}, err
	}
	if len(operations) != 2000 {
		return OperationSeriesRecord{}, fmt.Errorf("operation count = %d, want 2000", len(operations))
	}
	origin := operations[0].ScheduledAt
	starts := make([]int64, len(operations))
	durations := make([]int64, len(operations))
	boundaries := make([]rawBoundary, 0, 2*len(operations))
	payload := append(append([]byte{'"'}, make([]byte, contract.inputBytes-2)...), '"')
	for index := 1; index < len(payload)-1; index++ {
		payload[index] = 'x'
	}
	expectedPayload := sha256.Sum256(payload)
	for index, operation := range operations {
		wantScheduled := origin.Add(time.Duration(index) * time.Duration(contract.scheduledIntervalNS))
		if operation.Ordinal != index+1 || operation.ScheduledAt.IsZero() || operation.StartedAt.IsZero() || !operation.ScheduledAt.Equal(wantScheduled) ||
			operation.StartedAt.Before(operation.ScheduledAt) || operation.Duration <= 0 || operation.Duration > contract.operationDeadlineNS ||
			int64(operation.InputBytes) != contract.inputBytes || int64(operation.OutputBytes) != contract.outputBytes || operation.PayloadSHA256 != expectedPayload {
			return OperationSeriesRecord{}, fmt.Errorf("operation %d does not preserve the measured frozen RPC contract", index+1)
		}
		scheduledOffset := operation.ScheduledAt.Sub(origin).Nanoseconds()
		starts[index] = operation.StartedAt.Sub(operation.ScheduledAt).Nanoseconds()
		if scheduledOffset > contract.phaseDeadlineNS || starts[index] > contract.phaseDeadlineNS-scheduledOffset ||
			operation.Duration > contract.phaseDeadlineNS-scheduledOffset-starts[index] {
			return OperationSeriesRecord{}, fmt.Errorf("operation %d exceeds the measured frozen RPC phase deadline", index+1)
		}
		durations[index] = operation.Duration
		started := scheduledOffset + starts[index]
		boundaries = append(boundaries, rawBoundary{at: started, delta: 1}, rawBoundary{at: started + operation.Duration, delta: -1})
	}
	maximum := maximumRawInflight(boundaries)
	if maximum < 1 || maximum > contract.maxInflight {
		return OperationSeriesRecord{}, fmt.Errorf("measured RPC max inflight = %d, limit %d", maximum, contract.maxInflight)
	}
	payloadDigest := hex.EncodeToString(expectedPayload[:])
	return OperationSeriesRecord{
		RunNumber: runNumber, OperationCount: len(operations), ScheduledFirstNS: 0, ScheduledIntervalNS: contract.scheduledIntervalNS,
		StartDelayNS: compressInt64(starts), DurationNS: compressInt64(durations), RetryCounts: constantIntRun(len(operations), 0),
		InputBytes: constantIntRun(len(operations), contract.inputBytes), OutputBytes: constantIntRun(len(operations), contract.outputBytes),
		ScoredBytes: constantIntRun(len(operations), 0), ScoreDurationNS: constantIntRun(len(operations), 0),
		OperationDeadlineNS: contract.operationDeadlineNS, PhaseDeadlineNS: contract.phaseDeadlineNS, MaxInflightObserved: maximum,
		ExpectedPayloadSHA256: payloadDigest, ActualPayloadSHA256: payloadDigest,
	}, nil
}

func rawBulkSeries(bulk rawBulkResult, runNumber int) (OperationSeriesRecord, error) {
	contract, err := signedOperationContract("clean-v1", "bulk")
	if err != nil {
		return OperationSeriesRecord{}, err
	}
	if len(bulk.Directions) != 2 || bulk.ActiveStreams != 2 || bulk.BytesPerDirection != contract.scoredBytes {
		return OperationSeriesRecord{}, errors.New("bulk direction count, active streams, or scored bytes are invalid")
	}
	warmupBytes := contract.inputBytes - contract.scoredBytes
	expectedDirections := []struct {
		name string
		fill byte
	}{{"client-to-server", 0xa5}, {"server-to-client", 0x5a}}
	starts := make([]int64, 2)
	durations := make([]int64, 2)
	scoreDurations := make([]int64, 2)
	boundaries := make([]rawBoundary, 0, 4)
	expectedHash := sha256.New()
	actualHash := sha256.New()
	var scoreOrigin time.Time
	for index, expected := range expectedDirections {
		direction := bulk.Directions[index]
		if direction.Direction != expected.name || direction.Warmup.Direction != expected.name || direction.Score.Direction != expected.name {
			return OperationSeriesRecord{}, errors.New("bulk direction identity is invalid")
		}
		for _, phaseEntry := range []struct {
			name  string
			value rawBulkPhaseDirection
		}{{"warmup", direction.Warmup}, {"score", direction.Score}} {
			phaseName, phase := phaseEntry.name, phaseEntry.value
			wantBytes := warmupBytes
			if phaseName == "score" {
				wantBytes = contract.scoredBytes
			}
			wantDigest := repeatedByteSHA256(expected.fill, wantBytes)
			if phase.ScheduledAt.IsZero() || phase.StartedAt.Before(phase.ScheduledAt) || phase.Duration <= 0 || phase.Bytes != wantBytes || phase.PayloadSHA256 != wantDigest {
				return OperationSeriesRecord{}, fmt.Errorf("bulk %s %s record is invalid", expected.name, phaseName)
			}
			_, _ = expectedHash.Write(wantDigest[:])
			_, _ = actualHash.Write(phase.PayloadSHA256[:])
		}
		if index == 0 {
			scoreOrigin = direction.Score.ScheduledAt
		}
		wantScheduled := scoreOrigin.Add(time.Duration(index) * time.Duration(contract.scheduledIntervalNS))
		if !direction.Score.ScheduledAt.Equal(wantScheduled) {
			return OperationSeriesRecord{}, fmt.Errorf("bulk %s score does not preserve the frozen direction schedule", expected.name)
		}
		starts[index] = direction.Score.StartedAt.Sub(direction.Score.ScheduledAt).Nanoseconds()
		durations[index] = direction.Score.Duration
		scoreDurations[index] = direction.Score.Duration
		scheduledOffset := direction.Score.ScheduledAt.Sub(scoreOrigin).Nanoseconds()
		if scheduledOffset > contract.phaseDeadlineNS || starts[index] > contract.phaseDeadlineNS-scheduledOffset ||
			durations[index] > contract.phaseDeadlineNS-scheduledOffset-starts[index] {
			return OperationSeriesRecord{}, fmt.Errorf("bulk %s exceeds the frozen phase deadline", expected.name)
		}
		started := scheduledOffset + starts[index]
		boundaries = append(boundaries, rawBoundary{at: started, delta: 1}, rawBoundary{at: started + durations[index], delta: -1})
	}
	maximum := maximumRawInflight(boundaries)
	if maximum < 1 || maximum > contract.maxInflight || bulk.Duration != max(durations[0], durations[1]) || !bulk.StartedAt.Equal(minimumTime(bulk.Directions[0].Score.StartedAt, bulk.Directions[1].Score.StartedAt)) {
		return OperationSeriesRecord{}, errors.New("bulk aggregate timing is not derived from both scored directions")
	}
	expectedDigest := expectedHash.Sum(nil)
	actualDigest := actualHash.Sum(nil)
	if !slices.Equal(expectedDigest, actualDigest) {
		return OperationSeriesRecord{}, errors.New("bulk combined payload digest mismatch")
	}
	return OperationSeriesRecord{
		RunNumber: runNumber, OperationCount: 2, ScheduledFirstNS: 0, ScheduledIntervalNS: contract.scheduledIntervalNS,
		StartDelayNS: compressInt64(starts), DurationNS: compressInt64(durations), RetryCounts: constantIntRun(2, 0),
		InputBytes: constantIntRun(2, contract.inputBytes), OutputBytes: constantIntRun(2, contract.outputBytes),
		ScoredBytes: constantIntRun(2, contract.scoredBytes), ScoreDurationNS: compressInt64(scoreDurations),
		OperationDeadlineNS: contract.operationDeadlineNS, PhaseDeadlineNS: contract.phaseDeadlineNS, MaxInflightObserved: maximum,
		ExpectedPayloadSHA256: hex.EncodeToString(expectedDigest), ActualPayloadSHA256: hex.EncodeToString(actualDigest),
	}, nil
}

func repeatedByteSHA256(value byte, count int64) [sha256.Size]byte {
	digest := sha256.New()
	chunk := make([]byte, 64*1024)
	for index := range chunk {
		chunk[index] = value
	}
	for remaining := count; remaining > 0; {
		current := int64(len(chunk))
		if remaining < current {
			current = remaining
		}
		_, _ = digest.Write(chunk[:current])
		remaining -= current
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func minimumTime(left, right time.Time) time.Time {
	if right.Before(left) {
		return right
	}
	return left
}

func rawCleanupSeries(duration int64, runNumber int) (OperationSeriesRecord, error) {
	contract, err := signedOperationContract("clean-v1", "cleanup")
	if err != nil {
		return OperationSeriesRecord{}, err
	}
	if duration <= 0 || duration > contract.operationDeadlineNS {
		return OperationSeriesRecord{}, errors.New("measured cleanup duration is outside the frozen deadline")
	}
	empty := sha256.Sum256(nil)
	return OperationSeriesRecord{
		RunNumber: runNumber, OperationCount: 1, DurationNS: constantIntRun(1, duration), StartDelayNS: constantIntRun(1, 0),
		RetryCounts: constantIntRun(1, 0), InputBytes: constantIntRun(1, 0), OutputBytes: constantIntRun(1, 0),
		ScoredBytes: constantIntRun(1, 0), ScoreDurationNS: constantIntRun(1, 0), OperationDeadlineNS: contract.operationDeadlineNS,
		PhaseDeadlineNS: contract.phaseDeadlineNS, MaxInflightObserved: 1,
		ExpectedPayloadSHA256: hex.EncodeToString(empty[:]), ActualPayloadSHA256: hex.EncodeToString(empty[:]),
	}, nil
}

type rawBoundary struct {
	at    int64
	delta int
}

func maximumRawInflight(boundaries []rawBoundary) int {
	sort.Slice(boundaries, func(left, right int) bool {
		if boundaries[left].at == boundaries[right].at {
			return boundaries[left].delta < boundaries[right].delta
		}
		return boundaries[left].at < boundaries[right].at
	})
	current, maximum := 0, 0
	for _, boundary := range boundaries {
		current += boundary.delta
		maximum = max(maximum, current)
	}
	return maximum
}

func compressInt64(values []int64) []IntRunLength {
	if len(values) == 0 {
		return nil
	}
	runs := []IntRunLength{{Count: 1, Value: values[0]}}
	for _, value := range values[1:] {
		last := &runs[len(runs)-1]
		if last.Value == value {
			last.Count++
		} else {
			runs = append(runs, IntRunLength{Count: 1, Value: value})
		}
	}
	return runs
}

func constantIntRun(count int, value int64) []IntRunLength {
	return []IntRunLength{{Count: count, Value: value}}
}

func rawIntPointer(value int) *int {
	return &value
}

func writeRawPhaseTrace(writer *typedArtifactWriter, context, stem string, raw any) (EvidenceArtifact, error) {
	data, err := json.Marshal(raw)
	if err != nil {
		return EvidenceArtifact{}, err
	}
	digest := sha256.Sum256(data)
	return writer.WriteJSON(context, "trace", stem, TraceArtifact{
		SchemaVersion: 1, Kind: "transport_trace", Context: context,
		Records: []TraceRecord{{Sequence: 1, AtNS: 0, Event: "raw_phase_indexed", Digest: hex.EncodeToString(digest[:])}},
	})
}

func rawRunResourceArtifact(context string, result rawBaselineCarrierResult, retransmittedBytes uint64, lossRecoveryNS int64) (ResourceArtifact, error) {
	resource := result.Resource
	bulkFinished := result.Bulk.StartedAt.Add(time.Duration(result.Bulk.Duration))
	if resource.StartedAt.IsZero() || !resource.FinishedAt.After(resource.StartedAt) || !resource.Start.At.Equal(resource.StartedAt) || !resource.Finish.At.Equal(resource.FinishedAt) ||
		resource.Start.RSSBytes == 0 || resource.Finish.RSSBytes == 0 || resource.Start.Goroutines <= 0 || resource.Finish.Goroutines <= 0 ||
		resource.Finish.CPUNanoseconds < resource.Start.CPUNanoseconds || resource.CPUNanoseconds != resource.Finish.CPUNanoseconds-resource.Start.CPUNanoseconds ||
		resource.Finish.AllocatedBytes < resource.Start.AllocatedBytes || resource.AllocatedBytes != resource.Finish.AllocatedBytes-resource.Start.AllocatedBytes ||
		resource.CPUNanoseconds == 0 || resource.AllocatedBytes == 0 || result.Bulk.StartedAt.IsZero() || result.Bulk.Duration <= 0 ||
		result.Bulk.StartedAt.Before(resource.StartedAt) || bulkFinished.After(resource.FinishedAt) ||
		result.Bulk.BytesPerDirection <= 0 || uint64(result.Bulk.BytesPerDirection) > ^uint64(0)/2 {
		return ResourceArtifact{}, errors.New("raw run resource measurement is incomplete")
	}
	delivered := uint64(result.Bulk.BytesPerDirection) * 2
	records := []ResourceRecord{
		{Phase: "run_start", AtNS: 0, RSSBytes: resource.Start.RSSBytes, CPUNanoseconds: resource.Start.CPUNanoseconds, OpenFDs: resource.Start.OpenFDs, Goroutines: resource.Start.Goroutines, Tasks: resource.Start.Tasks},
	}
	peakRSS := max(resource.Start.RSSBytes, resource.Finish.RSSBytes)
	for _, phase := range result.Phases {
		if phase.Resource.StartedAt.Before(resource.StartedAt) || phase.Resource.FinishedAt.After(resource.FinishedAt) ||
			!phase.Resource.Start.At.Equal(phase.Resource.StartedAt) || !phase.Resource.Finish.At.Equal(phase.Resource.FinishedAt) {
			return ResourceArtifact{}, fmt.Errorf("phase %s resource falls outside the run or has inconsistent snapshots", phase.Phase)
		}
		peakRSS = max(peakRSS, phase.Resource.Start.RSSBytes, phase.Resource.Finish.RSSBytes)
		records = append(records,
			ResourceRecord{Phase: phase.Phase + "_start", AtNS: phase.Resource.StartedAt.Sub(resource.StartedAt).Nanoseconds(), RSSBytes: phase.Resource.Start.RSSBytes, CPUNanoseconds: phase.Resource.Start.CPUNanoseconds, OpenFDs: phase.Resource.Start.OpenFDs, Goroutines: phase.Resource.Start.Goroutines, Tasks: phase.Resource.Start.Tasks},
			ResourceRecord{Phase: phase.Phase + "_finish", AtNS: phase.Resource.FinishedAt.Sub(resource.StartedAt).Nanoseconds(), RSSBytes: phase.Resource.Finish.RSSBytes, CPUNanoseconds: phase.Resource.Finish.CPUNanoseconds, OpenFDs: phase.Resource.Finish.OpenFDs, Goroutines: phase.Resource.Finish.Goroutines, Tasks: phase.Resource.Finish.Tasks},
		)
	}
	records = append(records, ResourceRecord{Phase: "run_finish", AtNS: resource.FinishedAt.Sub(resource.StartedAt).Nanoseconds(), RSSBytes: resource.Finish.RSSBytes, CPUNanoseconds: resource.Finish.CPUNanoseconds, OpenFDs: resource.Finish.OpenFDs, Goroutines: resource.Finish.Goroutines, Tasks: resource.Finish.Tasks})
	artifact := ResourceArtifact{
		SchemaVersion: 1, Kind: "transport_resource", Context: context,
		Records: records,
		Measurements: []ScopedResourceMeasurement{
			{Name: "cpu_nanoseconds", Value: float64(resource.CPUNanoseconds), Unit: "nanoseconds"},
			{Name: "delivered_bytes", Value: float64(delivered), Unit: "bytes"},
			{Name: "retransmitted_bytes", Value: float64(retransmittedBytes), Unit: "bytes"},
			{Name: "rss_bytes", Value: float64(peakRSS), Unit: "bytes"},
			{Name: "alloc_bytes", Value: float64(resource.AllocatedBytes), Unit: "bytes"},
			{Name: "active_streams", Value: float64(result.Bulk.ActiveStreams), Unit: "count"},
			{Name: "loss_recovery_ms.nanoseconds", Value: float64(lossRecoveryNS), Unit: "nanoseconds"},
			{Name: "cleanup_latency_ms.nanoseconds", Value: float64(result.CleanupDuration), Unit: "nanoseconds"},
		},
	}
	return artifact, nil
}

func mergeRawArtifacts(existing map[string]EvidenceArtifact, firstKind string, first EvidenceArtifact, secondKind string, second EvidenceArtifact) map[string]EvidenceArtifact {
	result := make(map[string]EvidenceArtifact, len(existing)+2)
	for kind, artifact := range existing {
		result[kind] = artifact
	}
	result[firstKind] = first
	result[secondKind] = second
	return result
}

func rawBaselineProducerGaps(cellID string, result rawBaselineCarrierResult) []producerFieldGap {
	gaps := []producerFieldGap{
		{Scope: "run", Field: "retransmitted_bytes", Reason: "the raw resource producer does not record TCP_INFO or QUIC retransmission bytes"},
		{Scope: "phase", Field: "packet_attribution", Reason: "pcap and qlog artifacts cover the whole run and are not attributed to phase boundaries"},
		{Scope: "phase", Field: "kernel_fault_counters", Reason: "kernel counters are run-scoped and cannot be assigned to individual phases"},
	}
	if !slices.ContainsFunc(result.Artifacts, func(artifact rawReleaseArtifact) bool { return artifact.Kind == "pcap" }) {
		gaps = append(gaps, producerFieldGap{Scope: "run", Field: "pcap", Reason: "the raw result references no packet capture"})
	}
	if cellID == "clean-03" {
		gaps = append(gaps, producerFieldGap{Scope: "phase", Field: "qlog_document", Reason: "raw qlog JSON sequences are not correlated to exact phase operations"})
	}
	return gaps
}
