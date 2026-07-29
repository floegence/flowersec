package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/tunnelworkload"
)

type profileShardHeader struct {
	index, count      int
	started, finished time.Time
}

func profileShardReportName(shard int) string {
	return fmt.Sprintf("shard-%02d.json", shard)
}

func mergeNetworkCellShardReports(reports []networkCellReport, runCount int) (networkCellReport, error) {
	if len(reports) == 0 {
		return networkCellReport{}, errors.New("direct shard reports are required")
	}
	metadata := networkShardMetadata(reports[0])
	headers := make([]profileShardHeader, len(reports))
	results := make([][]baselineCarrierResult, len(reports))
	for index, report := range reports {
		if !reflect.DeepEqual(networkShardMetadata(report), metadata) {
			return networkCellReport{}, errors.New("direct shard report metadata drifted")
		}
		headers[index] = profileShardHeader{index: report.ShardIndex, count: report.ShardCount, started: report.StartedAt, finished: report.FinishedAt}
		results[index] = report.Results
	}
	mergedResults, started, finished, err := mergeProfileShardResults(headers, results, runCount,
		func(result baselineCarrierResult) int { return result.Run },
		func(result baselineCarrierResult) []releaseArtifact { return result.Artifacts },
	)
	if err != nil {
		return networkCellReport{}, fmt.Errorf("direct shard reports: %w", err)
	}
	carrierName := mergedResults[0].Carrier
	if carrier.Kind(carrierName).Validate() != nil {
		return networkCellReport{}, errors.New("direct shard reports have an invalid carrier")
	}
	for _, result := range mergedResults {
		if result.Carrier != carrierName {
			return networkCellReport{}, errors.New("direct shard report carrier drifted")
		}
	}
	merged := reports[0]
	merged.StartedAt, merged.FinishedAt = started, finished
	merged.ShardIndex, merged.ShardCount = 0, 0
	merged.Results = mergedResults
	return merged, nil
}

func networkShardMetadata(report networkCellReport) networkCellReport {
	report.StartedAt = time.Time{}
	report.FinishedAt = time.Time{}
	report.ShardIndex = 0
	report.ShardCount = 0
	report.Results = nil
	return report
}

func mergeTunnelCellShardReports(reports []tunnelCellReport, runCount int) (tunnelCellReport, error) {
	if len(reports) == 0 {
		return tunnelCellReport{}, errors.New("tunnel shard reports are required")
	}
	metadata := tunnelShardMetadata(reports[0])
	headers := make([]profileShardHeader, len(reports))
	results := make([][]tunnelCarrierResult, len(reports))
	for index, report := range reports {
		if !reflect.DeepEqual(tunnelShardMetadata(report), metadata) {
			return tunnelCellReport{}, errors.New("tunnel shard report metadata drifted")
		}
		headers[index] = profileShardHeader{index: report.ShardIndex, count: report.ShardCount, started: report.StartedAt, finished: report.FinishedAt}
		results[index] = report.Results
	}
	mergedResults, started, finished, err := mergeProfileShardResults(headers, results, runCount,
		func(result tunnelCarrierResult) int { return result.Run },
		func(result tunnelCarrierResult) []releaseArtifact { return result.Artifacts },
	)
	if err != nil {
		return tunnelCellReport{}, fmt.Errorf("tunnel shard reports: %w", err)
	}
	for _, result := range mergedResults {
		if result.Workload.Topology != reports[0].Topology {
			return tunnelCellReport{}, errors.New("tunnel shard report topology drifted")
		}
	}
	merged := reports[0]
	merged.StartedAt, merged.FinishedAt = started, finished
	merged.ShardIndex, merged.ShardCount = 0, 0
	merged.Results = mergedResults
	return merged, nil
}

func tunnelShardMetadata(report tunnelCellReport) tunnelCellReport {
	report.StartedAt = time.Time{}
	report.FinishedAt = time.Time{}
	report.ShardIndex = 0
	report.ShardCount = 0
	report.Results = nil
	return report
}

func mergeProfileShardResults[T any](headers []profileShardHeader, results [][]T, runCount int, runNumber func(T) int, artifacts func(T) []releaseArtifact) ([]T, time.Time, time.Time, error) {
	shards := forcedProfileRunShards(runCount)
	if len(shards) == 0 || len(headers) != len(shards) || len(results) != len(shards) {
		return nil, time.Time{}, time.Time{}, errors.New("reports must contain every forced profile shard")
	}
	seenShards := make(map[int]struct{}, len(shards))
	seenRuns := make(map[int]struct{}, runCount)
	seenArtifacts := make(map[string]struct{})
	merged := make([]T, 0, runCount)
	var started, finished time.Time
	for index, header := range headers {
		if header.index < 1 || header.index > len(shards) || header.count != len(shards) || header.started.IsZero() || header.finished.Before(header.started) {
			return nil, time.Time{}, time.Time{}, errors.New("shard header contract is invalid")
		}
		if _, duplicate := seenShards[header.index]; duplicate {
			return nil, time.Time{}, time.Time{}, errors.New("shard index is duplicated")
		}
		seenShards[header.index] = struct{}{}
		if started.IsZero() || header.started.Before(started) {
			started = header.started
		}
		if header.finished.After(finished) {
			finished = header.finished
		}
		expectedRuns := shards[header.index-1]
		if len(results[index]) != len(expectedRuns) {
			return nil, time.Time{}, time.Time{}, errors.New("shard run count is incomplete")
		}
		for resultIndex, result := range results[index] {
			run := runNumber(result)
			if run != expectedRuns[resultIndex] {
				return nil, time.Time{}, time.Time{}, errors.New("shard run sequence is invalid")
			}
			if _, duplicate := seenRuns[run]; duplicate {
				return nil, time.Time{}, time.Time{}, errors.New("shard run is duplicated")
			}
			seenRuns[run] = struct{}{}
			resultArtifacts := artifacts(result)
			if len(resultArtifacts) == 0 {
				return nil, time.Time{}, time.Time{}, errors.New("shard run is not bound to artifacts")
			}
			for _, artifact := range resultArtifacts {
				if artifact.Path == "" {
					return nil, time.Time{}, time.Time{}, errors.New("shard artifact path is empty")
				}
				if _, duplicate := seenArtifacts[artifact.Path]; duplicate {
					return nil, time.Time{}, time.Time{}, errors.New("shard artifact path is duplicated")
				}
				seenArtifacts[artifact.Path] = struct{}{}
			}
			merged = append(merged, result)
		}
	}
	if len(seenRuns) != runCount {
		return nil, time.Time{}, time.Time{}, errors.New("shard reports do not cover every run")
	}
	sort.Slice(merged, func(left, right int) bool { return runNumber(merged[left]) < runNumber(merged[right]) })
	for index, result := range merged {
		if runNumber(result) != index+1 {
			return nil, time.Time{}, time.Time{}, errors.New("shard reports do not form the canonical run sequence")
		}
	}
	return merged, started, finished, nil
}

func mergeNetworkCellShardReportFiles(root, reportPath string, shardPaths []string, sourceSHA, profileID string, kind carrier.Kind, plan transportrelease.ReleasePlan, manifest transportrelease.ManifestBinding) (resultErr error) {
	if err := kind.Validate(); err != nil {
		return err
	}
	reports, directory, err := readProfileShardReports[networkCellReport](root, reportPath, shardPaths, plan.RunCount, func(report networkCellReport) int { return report.ShardIndex })
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, directory.Close()) }()
	merged, err := mergeNetworkCellShardReports(reports, plan.RunCount)
	if err != nil {
		return err
	}
	profile, err := profilePlanForShardMerge(plan, profileID)
	if err != nil {
		return err
	}
	if err := validateProfileShardMetadata(merged.SourceSHA, merged.ManifestDigest, merged.ManifestSHA256, merged.ProfileID, merged.Network, merged.Fault, merged.BPFObjectSHA256, sourceSHA, profile, manifest); err != nil {
		return err
	}
	if merged.SchemaVersion != 1 || merged.Classification != "linux_kernel_network_profile" || merged.Runner.OS != "linux" || !supportedLinuxRunnerArchitecture(merged.Runner.OS, merged.Runner.Architecture) || merged.Runner.KernelRelease == "" {
		return errors.New("direct shard reports have invalid runner metadata")
	}
	for _, result := range merged.Results {
		if result.Carrier != string(kind) {
			return errors.New("direct shard reports do not match the requested carrier")
		}
	}
	if err := verifyProfileReportArtifacts(root, networkArtifacts(merged.Results)); err != nil {
		return err
	}
	return writeMergedProfileReport(directory, reportPath, merged)
}

func mergeTunnelCellShardReportFiles(root, reportPath string, shardPaths []string, sourceSHA, profileID string, topology tunnelworkload.Topology, plan transportrelease.ReleasePlan, manifest transportrelease.ManifestBinding) (resultErr error) {
	if _, _, err := topology.Carriers(); err != nil {
		return err
	}
	reports, directory, err := readProfileShardReports[tunnelCellReport](root, reportPath, shardPaths, plan.RunCount, func(report tunnelCellReport) int { return report.ShardIndex })
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, directory.Close()) }()
	merged, err := mergeTunnelCellShardReports(reports, plan.RunCount)
	if err != nil {
		return err
	}
	profile, err := profilePlanForShardMerge(plan, profileID)
	if err != nil {
		return err
	}
	if merged.Topology != topology {
		return errors.New("tunnel shard reports do not match the requested topology")
	}
	if err := validateProfileShardMetadata(merged.SourceSHA, merged.ManifestDigest, merged.ManifestSHA256, merged.ProfileID, merged.Network, merged.Fault, merged.BPFObjectSHA256, sourceSHA, profile, manifest); err != nil {
		return err
	}
	if merged.SchemaVersion != 1 || merged.Classification != "linux_kernel_tunnel_network_profile" || merged.Runner.OS != "linux" || !supportedLinuxRunnerArchitecture(merged.Runner.OS, merged.Runner.Architecture) || merged.Runner.KernelRelease == "" {
		return errors.New("tunnel shard reports have invalid runner metadata")
	}
	if err := verifyProfileReportArtifacts(root, tunnelArtifacts(merged.Results)); err != nil {
		return err
	}
	return writeMergedProfileReport(directory, reportPath, merged)
}

func readProfileShardReports[T any](root, reportPath string, shardPaths []string, runCount int, shardIndex func(T) int) ([]T, *pinnedDirectory, error) {
	cleanRoot := filepath.Clean(root)
	cleanReport := filepath.Clean(reportPath)
	if !filepath.IsAbs(cleanRoot) || !filepath.IsAbs(cleanReport) || filepath.Dir(cleanReport) != cleanRoot || filepath.Base(cleanReport) != "cell.json" {
		return nil, nil, errors.New("profile shard merge requires a canonical cell.json in the report root")
	}
	resolvedRoot, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil || resolvedRoot != cleanRoot {
		return nil, nil, errors.New("profile shard merge root must not traverse symlinks")
	}
	directory, err := pinDirectory(cleanRoot)
	if err != nil {
		return nil, nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = directory.Close()
		}
	}()
	expectedShards := forcedProfileRunShards(runCount)
	if len(shardPaths) != len(expectedShards) {
		return nil, nil, errors.New("profile shard merge requires every shard report")
	}
	reports := make([]T, 0, len(shardPaths))
	seenPaths := make(map[string]struct{}, len(shardPaths))
	for _, rawPath := range shardPaths {
		path := filepath.Clean(rawPath)
		if !filepath.IsAbs(path) || filepath.Dir(path) != cleanRoot {
			return nil, nil, errors.New("profile shard report must be a direct child of the report root")
		}
		if _, duplicate := seenPaths[path]; duplicate {
			return nil, nil, errors.New("profile shard report path is duplicated")
		}
		seenPaths[path] = struct{}{}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || resolved != path {
			return nil, nil, errors.New("profile shard report path must not traverse symlinks")
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, nil, err
		}
		decoder := json.NewDecoder(io.LimitReader(file, 32<<20))
		decoder.DisallowUnknownFields()
		var report T
		decodeErr := decoder.Decode(&report)
		if decodeErr == nil && decoder.Decode(&struct{}{}) != io.EOF {
			decodeErr = errors.New("profile shard report has trailing data")
		}
		closeErr := file.Close()
		if decodeErr != nil || closeErr != nil {
			return nil, nil, errors.Join(decodeErr, closeErr)
		}
		if filepath.Base(path) != profileShardReportName(shardIndex(report)) {
			return nil, nil, errors.New("profile shard report filename does not match its index")
		}
		reports = append(reports, report)
	}
	closeOnError = false
	return reports, directory, nil
}

func profilePlanForShardMerge(plan transportrelease.ReleasePlan, profileID string) (transportrelease.ProfilePlan, error) {
	switch profileID {
	case "mobile-v1":
		return plan.Mobile, nil
	case "edge-v1":
		return plan.Edge, nil
	default:
		return transportrelease.ProfilePlan{}, errors.New("network profile shard merge requires mobile-v1 or edge-v1")
	}
}

func validateProfileShardMetadata(sourceSHA, manifestDigest, manifestSHA, profileID string, network transportrelease.NetworkPlan, fault transportrelease.FaultPlan, bpfDigest, expectedSHA string, profile transportrelease.ProfilePlan, manifest transportrelease.ManifestBinding) error {
	if sourceSHA != expectedSHA || manifestDigest != manifest.Digest || manifestSHA != hex.EncodeToString(manifest.SHA256Sum[:]) || profileID != profile.ID || !reflect.DeepEqual(network, profile.Network) || !reflect.DeepEqual(fault, profile.Fault) {
		return errors.New("profile shard reports do not match the frozen source or manifest")
	}
	if len(bpfDigest) != sha256.Size*2 {
		return errors.New("profile shard reports have an invalid BPF digest")
	}
	if _, err := hex.DecodeString(bpfDigest); err != nil {
		return errors.New("profile shard reports have an invalid BPF digest")
	}
	return nil
}

func networkArtifacts(results []baselineCarrierResult) [][]releaseArtifact {
	artifacts := make([][]releaseArtifact, len(results))
	for index, result := range results {
		artifacts[index] = result.Artifacts
	}
	return artifacts
}

func tunnelArtifacts(results []tunnelCarrierResult) [][]releaseArtifact {
	artifacts := make([][]releaseArtifact, len(results))
	for index, result := range results {
		artifacts[index] = result.Artifacts
	}
	return artifacts
}

func verifyProfileReportArtifacts(root string, groups [][]releaseArtifact) (resultErr error) {
	directory, err := pinDirectory(root)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, directory.Close()) }()
	seen := make(map[string]struct{})
	for _, artifacts := range groups {
		for _, artifact := range artifacts {
			if artifact.Kind == "" || artifact.SizeBytes <= 0 || len(artifact.SHA256) != sha256.Size*2 {
				return errors.New("profile report artifact contract is invalid")
			}
			if _, err := hex.DecodeString(artifact.SHA256); err != nil {
				return errors.New("profile report artifact digest is invalid")
			}
			clean := filepath.Clean(filepath.FromSlash(artifact.Path))
			if artifact.Path == "" || artifact.Path != filepath.ToSlash(clean) || clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
				return errors.New("profile report artifact path is invalid")
			}
			if _, duplicate := seen[artifact.Path]; duplicate {
				return errors.New("profile report artifact path is duplicated")
			}
			seen[artifact.Path] = struct{}{}
			path := filepath.Join(root, clean)
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil || resolved != path {
				return errors.New("profile report artifact path must not traverse symlinks")
			}
			info, err := os.Stat(path)
			if err != nil || !info.Mode().IsRegular() || info.Size() != artifact.SizeBytes {
				return errors.New("profile report artifact size or type changed")
			}
			value, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			switch artifact.Kind {
			case "classic-pcap":
				if !validClassicPCAP(value) {
					return errors.New("profile report pcap artifact is invalid")
				}
			case "qlog-json-seq":
				if filepath.Ext(path) != ".sqlog" || len(value) == 0 {
					return errors.New("profile report qlog artifact is invalid")
				}
			default:
				return errors.New("profile report artifact kind is invalid")
			}
			digest := sha256.Sum256(value)
			if hex.EncodeToString(digest[:]) != artifact.SHA256 {
				return fmt.Errorf("profile report artifact digest changed: %s", artifact.Path)
			}
		}
	}
	return directory.Verify()
}

func writeMergedProfileReport(directory *pinnedDirectory, reportPath string, report any) error {
	if err := directory.Verify(); err != nil {
		return err
	}
	if err := writeNewReport(reportPath, report); err != nil {
		return err
	}
	return directory.Verify()
}
