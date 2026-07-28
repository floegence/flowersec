package main

import (
	"context"
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

	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
)

type stringFlagValues []string

func (values *stringFlagValues) String() string { return strings.Join(*values, ",") }

func (values *stringFlagValues) Set(value string) error {
	if value == "" {
		return errors.New("shard report path is required")
	}
	*values = append(*values, value)
	return nil
}

func runSelectedForcedProfileShard(parent context.Context, runCount, shardIndex int, shardDeadline time.Duration, run func(context.Context, int) error) error {
	if parent == nil || shardDeadline <= 0 || run == nil {
		return errors.New("forced profile shard contract is invalid")
	}
	runs, err := forcedProfileRunShard(runCount, shardIndex)
	if err != nil {
		return err
	}
	shardCtx, cancelShard := newCellContext(parent, shardDeadline)
	started := time.Now()
	defer cancelShard()
	for _, runNumber := range runs {
		if err := run(shardCtx, runNumber); err != nil {
			return err
		}
	}
	if err := completedWithin(shardCtx, started, shardDeadline); err != nil {
		return fmt.Errorf("runs %d-%d shard watchdog: %w", runs[0], runs[len(runs)-1], err)
	}
	return nil
}

func mergeBrowserCellShardReports(reports []browserCellReport, runCount int) (browserCellReport, error) {
	shards := forcedProfileRunShards(runCount)
	if len(shards) == 0 || len(reports) != len(shards) {
		return browserCellReport{}, errors.New("browser shard reports must contain every forced profile shard")
	}

	seenShards := make(map[int]struct{}, len(shards))
	seenRuns := make(map[int]struct{}, runCount)
	seenArtifacts := make(map[string]struct{})
	results := make([]browserCellResult, 0, runCount)
	var merged browserCellReport
	var metadata browserCellReport
	var startedAt, finishedAt time.Time

	for _, report := range reports {
		if report.SchemaVersion != 1 || report.Classification != "linux_chromium_webtransport_profile" ||
			report.ShardCount != len(shards) || report.ShardIndex < 1 || report.ShardIndex > len(shards) ||
			report.StartedAt.IsZero() || report.FinishedAt.Before(report.StartedAt) {
			return browserCellReport{}, errors.New("browser shard report contract is invalid")
		}
		if _, duplicate := seenShards[report.ShardIndex]; duplicate {
			return browserCellReport{}, errors.New("browser shard report index is duplicated")
		}
		seenShards[report.ShardIndex] = struct{}{}

		candidateMetadata := browserShardMetadata(report)
		if len(seenShards) == 1 {
			metadata = candidateMetadata
			merged = report
			startedAt, finishedAt = report.StartedAt, report.FinishedAt
		} else if !reflect.DeepEqual(candidateMetadata, metadata) {
			return browserCellReport{}, errors.New("browser shard report metadata drifted")
		} else {
			if report.StartedAt.Before(startedAt) {
				startedAt = report.StartedAt
			}
			if report.FinishedAt.After(finishedAt) {
				finishedAt = report.FinishedAt
			}
		}

		expectedRuns := shards[report.ShardIndex-1]
		if len(report.Results) != len(expectedRuns) {
			return browserCellReport{}, errors.New("browser shard report run count is incomplete")
		}
		for index, result := range report.Results {
			var workload struct {
				SchemaVersion int    `json:"schema_version"`
				Topology      string `json:"topology"`
				ProfileID     string `json:"profile_id"`
				RunNumber     int    `json:"run_number"`
				Status        string `json:"status"`
			}
			if result.Run != expectedRuns[index] || len(result.Artifacts) == 0 || json.Unmarshal(result.Workload, &workload) != nil ||
				workload.SchemaVersion != 1 || workload.Topology != report.Topology || workload.ProfileID != report.ProfileID ||
				workload.RunNumber != result.Run || workload.Status != "passed" {
				return browserCellReport{}, errors.New("browser shard report run sequence is invalid")
			}
			if _, duplicate := seenRuns[result.Run]; duplicate {
				return browserCellReport{}, errors.New("browser shard report run is duplicated")
			}
			seenRuns[result.Run] = struct{}{}
			for _, artifact := range result.Artifacts {
				if _, duplicate := seenArtifacts[artifact.Path]; duplicate {
					return browserCellReport{}, errors.New("browser shard report artifact is duplicated")
				}
				seenArtifacts[artifact.Path] = struct{}{}
			}
			results = append(results, result)
		}
	}

	if len(seenRuns) != runCount {
		return browserCellReport{}, errors.New("browser shard reports do not cover every run")
	}
	sort.Slice(results, func(left, right int) bool { return results[left].Run < results[right].Run })
	for index, result := range results {
		if result.Run != index+1 {
			return browserCellReport{}, errors.New("browser shard reports do not form the canonical run sequence")
		}
	}
	merged.StartedAt, merged.FinishedAt = startedAt, finishedAt
	merged.ShardIndex, merged.ShardCount = 0, 0
	merged.Results = results
	return merged, nil
}

func browserShardMetadata(report browserCellReport) browserCellReport {
	report.StartedAt = time.Time{}
	report.FinishedAt = time.Time{}
	report.ShardIndex = 0
	report.ShardCount = 0
	report.Results = nil
	return report
}

func verifyBrowserCellReportArtifacts(root string, report browserCellReport) (resultErr error) {
	directory, err := pinDirectory(root)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, directory.Close()) }()
	seen := make(map[string]struct{})
	for _, result := range report.Results {
		for _, artifact := range result.Artifacts {
			if artifact.Kind == "" || artifact.SizeBytes <= 0 || len(artifact.SHA256) != sha256.Size*2 {
				return errors.New("browser report artifact contract is invalid")
			}
			if _, err := hex.DecodeString(artifact.SHA256); err != nil {
				return errors.New("browser report artifact digest is invalid")
			}
			clean := filepath.Clean(filepath.FromSlash(artifact.Path))
			if artifact.Path == "" || artifact.Path != filepath.ToSlash(clean) || clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
				return errors.New("browser report artifact path is invalid")
			}
			if _, duplicate := seen[artifact.Path]; duplicate {
				return errors.New("browser report artifact path is duplicated")
			}
			seen[artifact.Path] = struct{}{}
			path := filepath.Join(root, clean)
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil || resolved != path {
				return errors.New("browser report artifact path must not traverse symlinks")
			}
			info, err := os.Stat(path)
			if err != nil || !info.Mode().IsRegular() || info.Size() != artifact.SizeBytes {
				return errors.New("browser report artifact size or type changed")
			}
			value, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			switch artifact.Kind {
			case "classic-pcap":
				if filepath.Base(path) != "traffic.pcap" && filepath.Ext(path) != ".pcap" {
					return errors.New("browser report pcap artifact path is invalid")
				}
				if !validClassicPCAP(value) {
					return errors.New("browser report pcap artifact is invalid")
				}
			case "qlog-json-seq":
				if filepath.Ext(path) != ".sqlog" || len(value) == 0 {
					return errors.New("browser report qlog artifact is invalid")
				}
			default:
				return errors.New("browser report artifact kind is invalid")
			}
			digest := sha256.Sum256(value)
			if hex.EncodeToString(digest[:]) != artifact.SHA256 {
				return fmt.Errorf("browser report artifact digest changed: %s", artifact.Path)
			}
		}
	}
	return directory.Verify()
}

func mergeBrowserCellShardReportFiles(root, reportPath string, shardPaths []string, sourceSHA, profileID, topology string, plan transportrelease.ReleasePlan, manifest transportrelease.ManifestBinding) (resultErr error) {
	cleanRoot := filepath.Clean(root)
	cleanReport := filepath.Clean(reportPath)
	if !filepath.IsAbs(cleanRoot) || !filepath.IsAbs(cleanReport) || filepath.Dir(cleanReport) != cleanRoot || filepath.Base(cleanReport) != "cell.json" {
		return errors.New("browser shard merge requires a canonical cell.json in the report root")
	}
	if !supportedBrowserTopology(topology) {
		return errors.New("browser shard merge requires a supported browser topology")
	}
	resolvedRoot, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil || resolvedRoot != cleanRoot {
		return errors.New("browser shard merge root must not traverse symlinks")
	}
	directory, err := pinDirectory(cleanRoot)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, directory.Close()) }()

	expectedShards := forcedProfileRunShards(plan.RunCount)
	if len(shardPaths) != len(expectedShards) {
		return errors.New("browser shard merge requires every shard report")
	}
	reports := make([]browserCellReport, 0, len(shardPaths))
	seenPaths := make(map[string]struct{}, len(shardPaths))
	for _, rawPath := range shardPaths {
		path := filepath.Clean(rawPath)
		if !filepath.IsAbs(path) || filepath.Dir(path) != cleanRoot {
			return errors.New("browser shard report must be a direct child of the report root")
		}
		if _, duplicate := seenPaths[path]; duplicate {
			return errors.New("browser shard report path is duplicated")
		}
		seenPaths[path] = struct{}{}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || resolved != path {
			return errors.New("browser shard report path must not traverse symlinks")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		decoder := json.NewDecoder(io.LimitReader(file, 32<<20))
		decoder.DisallowUnknownFields()
		var report browserCellReport
		decodeErr := decoder.Decode(&report)
		if decodeErr == nil && decoder.Decode(&struct{}{}) != io.EOF {
			decodeErr = errors.New("browser shard report has trailing data")
		}
		closeErr := file.Close()
		if decodeErr != nil || closeErr != nil {
			return errors.Join(decodeErr, closeErr)
		}
		if filepath.Base(path) != fmt.Sprintf("shard-%02d.json", report.ShardIndex) {
			return errors.New("browser shard report filename does not match its index")
		}
		reports = append(reports, report)
	}

	merged, err := mergeBrowserCellShardReports(reports, plan.RunCount)
	if err != nil {
		return err
	}
	profile, err := browserProfilePlan(plan, profileID)
	if err != nil {
		return err
	}
	manifestSHA := hex.EncodeToString(manifest.SHA256Sum[:])
	if merged.SourceSHA != sourceSHA || merged.ManifestDigest != manifest.Digest || merged.ManifestSHA256 != manifestSHA ||
		merged.ProfileID != profile.ID || merged.Topology != topology ||
		!reflect.DeepEqual(merged.Network, profile.Network) || !reflect.DeepEqual(merged.Fault, profile.Fault) {
		return errors.New("browser shard reports do not match the frozen source or manifest")
	}
	if (profileID == "clean-v1") != (merged.BPFObjectSHA256 == "") {
		return errors.New("browser shard reports have an invalid BPF identity")
	}
	if merged.BPFObjectSHA256 != "" {
		if len(merged.BPFObjectSHA256) != sha256.Size*2 {
			return errors.New("browser shard reports have an invalid BPF digest")
		}
		if _, err := hex.DecodeString(merged.BPFObjectSHA256); err != nil {
			return errors.New("browser shard reports have an invalid BPF digest")
		}
	}
	if err := verifyBrowserCellReportArtifacts(cleanRoot, merged); err != nil {
		return err
	}
	if err := directory.Verify(); err != nil {
		return err
	}
	if err := writeNewReport(cleanReport, merged); err != nil {
		return err
	}
	return directory.Verify()
}

func browserProfilePlan(plan transportrelease.ReleasePlan, profileID string) (transportrelease.ProfilePlan, error) {
	switch profileID {
	case "clean-v1":
		return plan.Clean, nil
	case "mobile-v1":
		return plan.Mobile, nil
	case "edge-v1":
		return plan.Edge, nil
	default:
		return transportrelease.ProfilePlan{}, errors.New("browser shard merge requires a browser performance profile")
	}
}
