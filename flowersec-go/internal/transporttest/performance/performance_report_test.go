package performance

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/perfreport"
)

func writeFocusedPerformanceResult(result perfreport.CaseResult) error {
	path := os.Getenv("FLOWERSEC_TEST_RESULT_PATH")
	if path == "" {
		return nil
	}
	return perfreport.WriteCaseResult(path, result)
}

func measured(name string, observed, threshold float64, unit, comparator string) perfreport.Measurement {
	passed := observed == threshold
	if comparator == "<=" {
		passed = observed <= threshold
	} else if comparator == ">=" {
		passed = observed >= threshold
	}
	status := perfreport.StatusFail
	if passed && !math.IsNaN(observed) && !math.IsInf(observed, 0) {
		status = perfreport.StatusPass
	}
	return perfreport.Measurement{Name: name, Observed: observed, Threshold: threshold, Unit: unit, Comparator: comparator, Status: status}
}

func finalizePerformanceResult(result perfreport.CaseResult) perfreport.CaseResult {
	if result.Status != perfreport.StatusPass {
		return result
	}
	for _, measurement := range result.Measurements {
		if measurement.Status != perfreport.StatusFail {
			continue
		}
		result.Status = perfreport.StatusFail
		result.Stage = "measurement"
		result.FirstError = fmt.Sprintf("%s observed %.3f %s, threshold %s %.3f %s", measurement.Name, measurement.Observed, measurement.Unit, measurement.Comparator, measurement.Threshold, measurement.Unit)
		break
	}
	return result
}

func capacityPerformanceResult(definition capacityCaseDefinition, contract capacityContract, result capacityCaseResult, caseErr error) perfreport.CaseResult {
	status := perfreport.StatusPass
	stage, firstError := "", ""
	if caseErr != nil {
		status, stage, firstError = perfreport.StatusFail, "capacity workload", caseErr.Error()
	}
	caseID := "performance/capacity/" + strings.ToLower(definition.ID)
	successRate := 0.0
	if result.Attempted > 0 {
		successRate = float64(result.Succeeded) / float64(result.Attempted) * 100
	}
	measurements := []perfreport.Measurement{
		measured("attempted sessions", float64(result.Attempted), float64(contract.Sessions), "sessions", "=="),
		measured("succeeded sessions", float64(result.Succeeded), float64(contract.Sessions), "sessions", ">="),
		measured("connection success rate", successRate, 100, "%", ">="),
		measured("failed sessions", float64(result.Failed), 0, "sessions", "<="),
		measured("active session peak", float64(result.UniqueActivePeak), float64(contract.Sessions), "sessions", ">="),
		measured("hold disconnects", float64(result.HoldDisconnects), 0, "disconnects", "<="),
		measured("residual sessions", float64(result.ResidualSessions), 0, "sessions", "<="),
		measured("watchdog timeouts", float64(result.WatchdogTimeouts), 0, "timeouts", "<="),
		measured("connect p50", durationMS(result.ConnectP50), durationMS(contract.MaxConnectP50), "ms", "<="),
		measured("connect p95", durationMS(result.ConnectP95), durationMS(contract.MaxConnectP95), "ms", "<="),
		measured("connect p99", durationMS(result.ConnectP99), durationMS(contract.MaxConnectP99), "ms", "<="),
		measured("connect max", durationMS(result.ConnectMax), durationMS(contract.Watchdog), "ms", "<="),
		measured("connections per second", result.ConnectsPerSecond, contract.MinConnectsPerSecond, "connections/s", ">="),
		measured("liveness p99", durationMS(result.LivenessP99), durationMS(contract.MaxLivenessP99), "ms", "<="),
	}
	if contract.StreamsPerSession > 0 {
		expectedStreams := contract.Sessions * contract.StreamsPerSession
		measurements = append(measurements,
			measured("completed streams", float64(result.CompletedStreams), float64(expectedStreams), "streams", ">="),
			measured("stream rate", result.StreamsPerSecond, contract.MinStreamsPerSecond, "streams/s", ">="),
			measured("residual streams", float64(result.ResidualStreams), 0, "streams", "<="),
		)
	}
	if len(result.Resources) > 0 {
		measurements = append(measurements, capacityResourceMeasurements(result, contract)...)
	}
	raw := capacityRawSamples(result)
	return finalizePerformanceResult(perfreport.CaseResult{
		ID: caseID, Section: perfreport.SectionCapacity, Status: status, Stage: stage, FirstError: firstError,
		Configuration: map[string]string{
			"profile": definition.Profile, "sessions": fmt.Sprint(contract.Sessions), "streams per session": fmt.Sprint(contract.StreamsPerSession),
			"ramp": contract.Ramp.String(), "hold": contract.Hold.String(), "cleanup": contract.Cleanup.String(), "watchdog": contract.Watchdog.String(),
			"carrier/path": capacityCarrierPath(definition), "resource scope": contract.ResourceScope, "resource sampling": "baseline and phase boundaries",
		},
		Measurements: measurements, RawSamples: raw,
	})
}

func capacityCarrierPath(definition capacityCaseDefinition) string {
	if definition.Kind == capacityDirect {
		return string(definition.Carrier) + "/direct"
	}
	if definition.Kind == capacityTunnel {
		return strings.ToLower(strings.TrimPrefix(definition.ID, "CAP-")) + "/tunnel"
	}
	if definition.Kind == capacityBrowserStream {
		return "webtransport/reliable-stream"
	}
	return "webtransport/tunnel"
}

func capacityResourceMeasurements(result capacityCaseResult, contract capacityContract) []perfreport.Measurement {
	baselineRSS := result.Baseline.RSSBytes
	peakRSS, peakCPU := baselineRSS, uint64(0)
	peakFD, peakGoroutines, peakTasks := result.Baseline.OpenFDs, result.Baseline.Goroutines, result.Baseline.Tasks
	peakCPUPercent := 0.0
	previousCPU, previousAt := uint64(0), int64(0)
	for _, sample := range result.Resources {
		peakRSS = max(peakRSS, sample.RSSBytes)
		peakCPU = max(peakCPU, sample.CPUNanoseconds)
		peakFD = max(peakFD, sample.OpenFDs)
		peakGoroutines = max(peakGoroutines, sample.Goroutines)
		peakTasks = max(peakTasks, sample.Tasks)
		if sample.AtNS > previousAt && sample.CPUNanoseconds >= previousCPU {
			utilization := perfreport.CPUUtilizationPercent(time.Duration(sample.CPUNanoseconds-previousCPU), time.Duration(sample.AtNS-previousAt), runtime.NumCPU())
			if !math.IsNaN(utilization) {
				peakCPUPercent = max(peakCPUPercent, utilization)
			}
		}
		previousCPU, previousAt = sample.CPUNanoseconds, sample.AtNS
	}
	wall := time.Duration(previousAt)
	avgCPU := perfreport.CPUUtilizationPercent(time.Duration(peakCPU), wall, runtime.NumCPU())
	perSession := perfreport.PerSessionMemoryBytes(peakRSS, baselineRSS, max(result.UniqueActivePeak, 1))
	return []perfreport.Measurement{
		measured("RSS baseline", float64(baselineRSS), float64(contract.MaxRSS), "bytes", "<="),
		measured("RSS peak", float64(peakRSS), float64(contract.MaxRSS), "bytes", "<="),
		measured("RSS delta", float64(peakRSS-baselineRSS), float64(contract.MaxRSS), "bytes", "<="),
		measured("memory per active session", perSession, float64(contract.MaxRSS)/float64(max(contract.Sessions, 1)), "bytes/session", "<="),
		measured("CPU time", float64(peakCPU)/1e9, contract.MaxCPU.Seconds(), "CPU-s", "<="),
		measured("average normalized CPU utilization", avgCPU, 100, "% logical CPU capacity", "<="),
		measured("peak normalized CPU utilization", peakCPUPercent, 100, "% logical CPU capacity", "<="),
		measured("open FD peak", float64(peakFD), float64(contract.MaxOpenFDs), "FDs", "<="),
		measured("goroutine peak", float64(peakGoroutines), float64(contract.MaxGoroutines), "goroutines", "<="),
		measured("task/process peak", float64(peakTasks), float64(contract.MaxTasks), "tasks", "<="),
	}
}

func capacityRawSamples(result capacityCaseResult) []perfreport.RawSample {
	raw := make([]perfreport.RawSample, 0, len(result.Resources))
	for index, sample := range result.Resources {
		raw = append(raw, perfreport.RawSample{Round: index + 1, Phase: sample.Phase, Values: map[string]float64{
			"at_ms": float64(sample.AtNS) / 1e6, "active_sessions": float64(sample.ActiveSessions), "rss_bytes": float64(sample.RSSBytes),
			"cpu_seconds": float64(sample.CPUNanoseconds) / 1e9, "open_fds": float64(sample.OpenFDs), "goroutines": float64(sample.Goroutines), "tasks": float64(sample.Tasks),
		}})
	}
	return raw
}

func throughputPerformanceResult(result payloadThroughputResult, contract payloadThroughputContract, caseErr error) perfreport.CaseResult {
	status, stage, firstError := perfreport.StatusPass, "", ""
	if caseErr != nil {
		status, stage, firstError = perfreport.StatusFail, "streaming throughput", caseErr.Error()
	}
	rates := make([]float64, 0, len(result.Samples))
	raw := make([]perfreport.RawSample, 0, len(result.Samples))
	operations := 0
	for index, sample := range result.Samples {
		rate := sample.BytesPerSecond / float64(1<<20)
		rates = append(rates, rate)
		operations += len(sample.Latencies)
		raw = append(raw, perfreport.RawSample{Round: index + 1, Phase: "measured", Values: map[string]float64{"verified_bytes": float64(sample.Bytes), "window_seconds": sample.Duration.Seconds(), "throughput_mib_s": rate, "operations": float64(len(sample.Latencies))}})
	}
	medianRate, peakRate := perfreport.Percentile(rates, .5), perfreport.Percentile(rates, 1)
	caseID := "performance/throughput/" + carrierReportName(string(result.Carrier))
	return finalizePerformanceResult(perfreport.CaseResult{ID: caseID, Section: perfreport.SectionStreamingThroughput, Status: status, Stage: stage, FirstError: firstError,
		Configuration: map[string]string{"carrier": string(result.Carrier), "direction": "client-to-server", "payload": fmt.Sprintf("%d bytes", contract.PayloadBytes), "concurrency": fmt.Sprint(contract.Concurrency), "warm-up": "one verified operation per worker", "measured samples": fmt.Sprint(contract.Samples), "fixed sample window": contract.SampleDuration.String(), "peak definition": "maximum sustained throughput across fixed measured windows"},
		Measurements: []perfreport.Measurement{
			measured("sustained median throughput", medianRate, contract.MinBytesPerSecond/float64(1<<20), "MiB/s", ">="),
			measured("sustained peak throughput", peakRate, contract.MinBytesPerSecond/float64(1<<20), "MiB/s", ">="),
			measured("verified bytes", float64(result.Summary.Bytes), 1, "bytes", ">="),
			measured("operations", float64(operations), float64(contract.Concurrency*contract.Samples), "operations", ">="),
			measured("operation p50", durationMS(result.Summary.P50), durationMS(contract.MaxP95), "ms", "<="),
			measured("operation p95", durationMS(result.Summary.P95), durationMS(contract.MaxP95), "ms", "<="),
			measured("operation p99", durationMS(result.Summary.P99), durationMS(contract.MaxP95), "ms", "<="),
		}, RawSamples: raw})
}

type payloadThroughputCoordinateResult struct {
	Contract payloadThroughputContract
	Result   payloadThroughputResult
	Err      error
}

func throughputMatrixPerformanceResult(caseID string, kind carrier.Kind, mode string, results []payloadThroughputCoordinateResult, caseErr error) perfreport.CaseResult {
	status, stage, firstError := perfreport.StatusPass, "", ""
	if caseErr != nil {
		status, stage, firstError = perfreport.StatusFail, mode+" throughput", caseErr.Error()
	}
	if caseID == "" {
		caseID = "performance/throughput/" + carrierReportName(string(kind))
	}
	section := perfreport.SectionStreamingThroughput
	if mode == "single-connection" {
		section = perfreport.SectionSingleConnection
	}
	measurements := make([]perfreport.Measurement, 0, len(results)*8)
	raw := make([]perfreport.RawSample, 0, len(results)*3)
	for coordinateIndex, coordinate := range results {
		if len(coordinate.Result.Samples) == 0 {
			continue
		}
		prefix := string(coordinate.Contract.Direction) + " / " + fmt.Sprintf("%d bytes", coordinate.Contract.PayloadBytes)
		rates := make([]float64, 0, len(coordinate.Result.Samples))
		operations := 0
		var finCleanupFailures uint64
		var resetCount uint64
		for sampleIndex, sample := range coordinate.Result.Samples {
			rate := sample.BytesPerSecond / float64(1<<20)
			rates = append(rates, rate)
			operations += len(sample.Latencies)
			finCleanupFailures += sample.FINCleanupFailures
			resetCount += sample.ResetCount
			raw = append(raw, perfreport.RawSample{Round: coordinateIndex*100 + sampleIndex + 1, Phase: prefix + " measured", Values: map[string]float64{"verified_bytes": float64(sample.Bytes), "window_seconds": sample.Duration.Seconds(), "throughput_mib_s": rate, "operations": float64(len(sample.Latencies))}})
		}
		seconds := coordinate.Result.Summary.Duration.Seconds()
		opsPerSecond := math.NaN()
		if seconds > 0 {
			opsPerSecond = float64(operations) / seconds
		}
		thresholdMiB := coordinate.Contract.MinBytesPerSecond / float64(1<<20)
		measurements = append(measurements,
			measured(prefix+" sustained median throughput", perfreport.Percentile(rates, .5), thresholdMiB, "MiB/s", ">="),
			measured(prefix+" sustained peak throughput", perfreport.Percentile(rates, 1), thresholdMiB, "MiB/s", ">="),
			measured(prefix+" verified bytes", float64(coordinate.Result.Summary.Bytes), 1, "bytes", ">="),
			measured(prefix+" operations per second", opsPerSecond, 1, "operations/s", ">="),
			measured(prefix+" operation p50", durationMS(coordinate.Result.Summary.P50), durationMS(coordinate.Contract.MaxP95), "ms", "<="),
			measured(prefix+" operation p95", durationMS(coordinate.Result.Summary.P95), durationMS(coordinate.Contract.MaxP95), "ms", "<="),
			measured(prefix+" operation p99", durationMS(coordinate.Result.Summary.P99), durationMS(coordinate.Contract.MaxP95), "ms", "<="),
			measured(prefix+" verification failures", 0, 0, "failures", "<="),
			measured(prefix+" FIN cleanup failures", float64(finCleanupFailures), 0, "failures", "<="),
			measured(prefix+" reset count", float64(resetCount), 0, "resets", "<="),
		)
	}
	measurements = append(measurements, throughputResourceMeasurements(results)...)
	for coordinateIndex, coordinate := range results {
		for sampleIndex, sample := range coordinate.Result.Resources {
			raw = append(raw, perfreport.RawSample{Round: 10000 + coordinateIndex*100 + sampleIndex + 1, Phase: fmt.Sprintf("resource %s %d bytes %s", coordinate.Contract.Direction, coordinate.Contract.PayloadBytes, sample.Phase), Values: map[string]float64{"at_ms": float64(sample.AtNS) / 1e6, "rss_bytes": float64(sample.RSSBytes), "cpu_seconds": float64(sample.CPUNanoseconds) / 1e9, "open_fds": float64(sample.OpenFDs), "goroutines": float64(sample.Goroutines), "tasks": float64(sample.Tasks)}})
		}
	}
	sampleWindow := throughputMatrixSampleWindow(mode, results)
	return finalizePerformanceResult(perfreport.CaseResult{
		ID: caseID, Section: section, Status: status, Stage: stage, FirstError: firstError,
		Configuration: map[string]string{"carrier": string(kind), "mode": mode, "warm-up": "one verified 64 KiB bidirectional round trip before each measured window", "measured samples per coordinate": "3", "fixed sample window": sampleWindow.String(), "peak definition": "maximum sustained throughput across fixed measured windows", "byte accounting": "only fully read and content-verified bytes", "stream cleanup": "FIN required; reset only on failure", "resource scope": "Go test runner process", "resource sampling": "baseline and after each fixed measured window"},
		Measurements:  measurements, RawSamples: raw,
	})
}

func throughputMatrixSampleWindow(mode string, results []payloadThroughputCoordinateResult) time.Duration {
	for _, coordinate := range results {
		if coordinate.Contract.SampleDuration > 0 {
			return coordinate.Contract.SampleDuration
		}
	}
	if mode == "single-connection" {
		contracts := productionSingleConnectionThroughputContracts()
		if len(contracts) > 0 {
			return contracts[0].SampleDuration
		}
	} else {
		contracts := productionStreamingThroughputContracts()
		if len(contracts) > 0 {
			return contracts[0].SampleDuration
		}
	}
	return 0
}

func throughputResourceMeasurements(results []payloadThroughputCoordinateResult) []perfreport.Measurement {
	if len(results) == 0 || len(results[0].Result.Resources) == 0 {
		return nil
	}
	limits := productionCapacityContract()
	baselineRSS := results[0].Result.Baseline.RSSBytes
	peakRSS := baselineRSS
	peakFD, peakGoroutines, peakTasks := 0, 0, 0
	var totalCPU uint64
	var totalWall time.Duration
	peakCPUPercent := 0.0
	for _, coordinate := range results {
		var previousCPU uint64
		var previousAt int64
		for _, sample := range coordinate.Result.Resources {
			peakRSS = max(peakRSS, sample.RSSBytes)
			peakFD = max(peakFD, sample.OpenFDs)
			peakGoroutines = max(peakGoroutines, sample.Goroutines)
			peakTasks = max(peakTasks, sample.Tasks)
			if sample.AtNS > previousAt && sample.CPUNanoseconds >= previousCPU {
				utilization := perfreport.CPUUtilizationPercent(time.Duration(sample.CPUNanoseconds-previousCPU), time.Duration(sample.AtNS-previousAt), runtime.NumCPU())
				if !math.IsNaN(utilization) {
					peakCPUPercent = max(peakCPUPercent, utilization)
				}
			}
			previousCPU, previousAt = sample.CPUNanoseconds, sample.AtNS
		}
		totalCPU += previousCPU
		totalWall += time.Duration(previousAt)
	}
	deltaRSS := uint64(0)
	if peakRSS > baselineRSS {
		deltaRSS = peakRSS - baselineRSS
	}
	measurements := []perfreport.Measurement{
		measured("RSS baseline", float64(baselineRSS), float64(limits.MaxRSS), "bytes", "<="),
		measured("RSS peak", float64(peakRSS), float64(limits.MaxRSS), "bytes", "<="),
		measured("RSS delta", float64(deltaRSS), float64(limits.MaxRSS), "bytes", "<="),
		measured("open FD peak", float64(peakFD), float64(limits.MaxOpenFDs), "FDs", "<="),
		measured("goroutine peak", float64(peakGoroutines), float64(limits.MaxGoroutines), "goroutines", "<="),
		measured("task/process peak", float64(peakTasks), float64(limits.MaxTasks), "tasks", "<="),
	}
	if totalWall > 0 {
		averageCPU := perfreport.CPUUtilizationPercent(time.Duration(totalCPU), totalWall, runtime.NumCPU())
		measurements = append(measurements,
			measured("CPU time", float64(totalCPU)/1e9, limits.MaxCPU.Seconds(), "CPU-s", "<="),
			measured("average normalized CPU utilization", averageCPU, 100, "% logical CPU capacity", "<="),
			measured("peak normalized CPU utilization", peakCPUPercent, 100, "% logical CPU capacity", "<="),
		)
	}
	return measurements
}

func soakPerformanceResult(id string, result soakCaseResult, contract soakContract, caseErr error) perfreport.CaseResult {
	status, stage, firstError := perfreport.StatusPass, "", ""
	if caseErr != nil {
		status, stage, firstError = perfreport.StatusFail, "soak workload", caseErr.Error()
	}
	raw := make([]perfreport.RawSample, 0, len(result.Resources))
	for index, sample := range result.Resources {
		raw = append(raw, perfreport.RawSample{Round: index + 1, Phase: sample.Phase, Values: map[string]float64{"at_ms": float64(sample.AtNS) / 1e6, "rss_bytes": float64(sample.RSSBytes), "open_fds": float64(sample.OpenFDs), "goroutines": float64(sample.Goroutines), "tasks": float64(sample.Tasks)}})
	}
	measurements := []perfreport.Measurement{
		measured("fault cycles", float64(result.FaultCycles), float64(contract.Cycles), "cycles", ">="), measured("reconnect cycles", float64(result.Reconnects), float64(contract.Reconnects), "cycles", ">="), measured("migration cycles", float64(result.Migrations), float64(contract.Migrations), "cycles", ">="),
		measured("RSS growth", float64(result.RSSGrowth), float64(contract.MaxRSSGrowth), "bytes", "<="), measured("RSS peak", float64(result.RSSPeak), float64(productionCapacityContract().MaxRSS), "bytes", "<="),
		measured("goroutine growth", float64(result.GoroutineGrowth), float64(contract.MaxGoroutineGrowth), "goroutines", "<="), measured("open FD growth", float64(result.OpenFDGrowth), float64(contract.MaxOpenFDGrowth), "FDs", "<="), measured("task growth", float64(result.TaskGrowth), float64(contract.MaxTaskGrowth), "tasks", "<="),
		measured("residual sessions", float64(result.Residuals.Sessions), float64(contract.ResidualSessions), "sessions", "<="), measured("residual goroutines", float64(result.Residuals.Goroutines), float64(contract.ResidualGoroutines), "goroutines", "<="), measured("residual FDs", float64(result.Residuals.OpenFDs), float64(contract.ResidualOpenFDs), "FDs", "<="), measured("residual tasks", float64(result.Residuals.Tasks), float64(contract.ResidualTasks), "tasks", "<="), measured("watchdog timeouts", float64(result.WatchdogTimeouts), 0, "timeouts", "<="),
	}
	measurements = append(measurements, soakResourceMeasurements(result.Resources, contract.CPUTimeBudget)...)
	return finalizePerformanceResult(perfreport.CaseResult{ID: id, Section: perfreport.SectionSoak, Status: status, Stage: stage, FirstError: firstError,
		Configuration: map[string]string{"duration": contract.Duration.String(), "cycle period": contract.CyclePeriod.String(), "resource sampling": "baseline, each cycle, and cleanup"},
		Measurements:  measurements, RawSamples: raw})
}

func soakResourceMeasurements(resources []caseResourceRecord, duration time.Duration) []perfreport.Measurement {
	if len(resources) < 2 {
		return nil
	}
	baselineRSS, peakRSS := resources[0].RSSBytes, resources[0].RSSBytes
	var cpuTime uint64
	peakCPU := 0.0
	previousCPU, previousAt := uint64(0), int64(0)
	for _, sample := range resources {
		peakRSS = max(peakRSS, sample.RSSBytes)
		cpuTime = max(cpuTime, sample.CPUNanoseconds)
		if sample.AtNS > previousAt && sample.CPUNanoseconds >= previousCPU {
			utilization := perfreport.CPUUtilizationPercent(time.Duration(sample.CPUNanoseconds-previousCPU), time.Duration(sample.AtNS-previousAt), runtime.NumCPU())
			if !math.IsNaN(utilization) {
				peakCPU = max(peakCPU, utilization)
			}
		}
		previousCPU, previousAt = sample.CPUNanoseconds, sample.AtNS
	}
	averageCPU := perfreport.CPUUtilizationPercent(time.Duration(cpuTime), time.Duration(previousAt), runtime.NumCPU())
	return []perfreport.Measurement{
		measured("RSS baseline", float64(baselineRSS), float64(productionCapacityContract().MaxRSS), "bytes", "<="),
		measured("CPU time", float64(cpuTime)/1e9, duration.Seconds()*float64(runtime.NumCPU()), "CPU-s", "<="),
		measured("average normalized CPU utilization", averageCPU, 100, "% logical CPU capacity", "<="),
		measured("peak normalized CPU utilization", peakCPU, 100, "% logical CPU capacity", "<="),
	}
}

func carrierSoakPerformanceResult(kind carrier.Kind, result carrierSoakResult, contract carrierSoakContract, caseErr error) perfreport.CaseResult {
	status, stage, firstError := perfreport.StatusPass, "", ""
	if caseErr != nil {
		status, stage, firstError = perfreport.StatusFail, "carrier soak workload", caseErr.Error()
	}
	raw := make([]perfreport.RawSample, 0, len(result.Resources))
	for index, sample := range result.Resources {
		raw = append(raw, perfreport.RawSample{Round: index + 1, Phase: "resource sample", Values: map[string]float64{
			"rss_bytes": float64(sample.RSSBytes), "cpu_seconds": float64(sample.CPUNanoseconds) / 1e9,
			"open_fds": float64(sample.OpenFDs), "goroutines": float64(sample.Goroutines), "tasks": float64(sample.Tasks),
		}})
	}
	measurements := []perfreport.Measurement{
		measured("reconnect cycles", float64(result.Cycles), float64(contract.Cycles), "cycles", ">="),
		measured("RSS baseline", float64(result.Baseline.RSSBytes), float64(productionCapacityContract().MaxRSS), "bytes", "<="),
		measured("RSS growth", float64(result.RSSGrowth), float64(contract.MaxRSSGrowth), "bytes", "<="),
		measured("RSS peak", float64(result.RSSPeak), float64(productionCapacityContract().MaxRSS), "bytes", "<="),
		measured("goroutine growth", float64(result.GoroutineGrowth), float64(contract.MaxGoroutineGrowth), "goroutines", "<="),
		measured("goroutine peak", float64(result.GoroutinePeak), float64(productionCapacityContract().MaxGoroutines), "goroutines", "<="),
		measured("open FD growth", float64(result.OpenFDGrowth), float64(contract.MaxOpenFDGrowth), "FDs", "<="),
		measured("open FD peak", float64(result.OpenFDPeak), float64(productionCapacityContract().MaxOpenFDs), "FDs", "<="),
		measured("task growth", float64(result.TaskGrowth), float64(contract.MaxTaskGrowth), "tasks", "<="),
		measured("task peak", float64(result.TaskPeak), float64(productionCapacityContract().MaxTasks), "tasks", "<="),
	}
	if len(result.Resources) >= 2 && result.Finish.CPUNanoseconds >= result.Baseline.CPUNanoseconds {
		cpuTime := result.Finish.CPUNanoseconds - result.Baseline.CPUNanoseconds
		averageCPU := perfreport.CPUUtilizationPercent(time.Duration(cpuTime), contract.Duration, runtime.NumCPU())
		peakCPU := 0.0
		previousCPU, previousAt := result.Baseline.CPUNanoseconds, result.Baseline.At
		for _, sample := range result.Resources[1:] {
			if sample.CPUNanoseconds >= previousCPU && sample.At.After(previousAt) {
				utilization := perfreport.CPUUtilizationPercent(time.Duration(sample.CPUNanoseconds-previousCPU), sample.At.Sub(previousAt), runtime.NumCPU())
				if !math.IsNaN(utilization) {
					peakCPU = max(peakCPU, utilization)
				}
			}
			previousCPU, previousAt = sample.CPUNanoseconds, sample.At
		}
		measurements = append(measurements,
			measured("CPU time", float64(cpuTime)/1e9, contract.CPUTimeBudget.Seconds()*float64(runtime.NumCPU()), "CPU-s", "<="),
			measured("average normalized CPU utilization", averageCPU, 100, "% logical CPU capacity", "<="),
			measured("peak normalized CPU utilization", peakCPU, 100, "% logical CPU capacity", "<="),
		)
	}
	return finalizePerformanceResult(perfreport.CaseResult{
		ID: "performance/soak/" + carrierReportName(string(kind)), Section: perfreport.SectionSoak, Status: status, Stage: stage, FirstError: firstError,
		Configuration: map[string]string{"carrier": string(kind), "duration": contract.Duration.String(), "cycle period": contract.CyclePeriod.String(), "resource sampling": "baseline, each cycle, and cleanup"},
		Measurements:  measurements, RawSamples: raw,
	})
}

func durationMS(value time.Duration) float64 { return float64(value) / float64(time.Millisecond) }

func carrierReportName(name string) string {
	if name == "websocket" {
		return "wss"
	}
	return name
}

func sortedDurations(values []time.Duration) []time.Duration {
	copyOf := append([]time.Duration(nil), values...)
	sort.Slice(copyOf, func(i, j int) bool { return copyOf[i] < copyOf[j] })
	return copyOf
}
