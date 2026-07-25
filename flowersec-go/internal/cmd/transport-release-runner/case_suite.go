package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/tunnelworkload"
)

const conformanceSmokeOwner = "transport-conformance-smoke"

type releaseCaseDefinition struct {
	ID              string
	Profile         string
	Carrier         carrier.Kind
	Topology        tunnelworkload.Topology
	BrowserTopology string
	Suite           protocolv2.Suite
}

var conformanceSmokeCases = []releaseCaseDefinition{
	{ID: "CS-C1", Profile: "direct-wss-x25519", Carrier: carrier.KindWebSocket, Suite: protocolv2.SuiteChaCha20Poly1305},
	{ID: "CS-C2", Profile: "direct-raw-quic-p256", Carrier: carrier.KindQUIC, Suite: protocolv2.SuiteAES256GCM},
	{ID: "CS-C3", Profile: "tunnel-wss-wss-p256", Topology: tunnelworkload.TopologyWW, Suite: protocolv2.SuiteAES256GCM},
	{ID: "CS-C4", Profile: "tunnel-quic-quic-x25519", Topology: tunnelworkload.TopologyQQ, Suite: protocolv2.SuiteChaCha20Poly1305},
	{ID: "CS-C5", Profile: "tunnel-wss-quic-x25519", Topology: tunnelworkload.TopologyWQ, Suite: protocolv2.SuiteChaCha20Poly1305},
	{ID: "CS-C6", Profile: "tunnel-quic-wss-p256", Topology: tunnelworkload.TopologyQW, Suite: protocolv2.SuiteAES256GCM},
}

type releaseCaseRun struct {
	CompletedOperations int
	NegotiatedSuite     protocolv2.Suite
}

type caseSuiteReport struct {
	SchemaVersion  int                 `json:"schema_version"`
	Classification string              `json:"classification"`
	SourceSHA      string              `json:"source_sha"`
	ManifestDigest string              `json:"manifest_digest"`
	ManifestSHA256 string              `json:"manifest_file_sha256"`
	Runner         baselineRunner      `json:"runner"`
	Owner          string              `json:"owner"`
	Mode           string              `json:"mode"`
	StartedAt      time.Time           `json:"started_at"`
	FinishedAt     time.Time           `json:"finished_at"`
	Results        []releaseCaseResult `json:"results"`
}

type releaseCaseResult struct {
	ID                  string             `json:"id"`
	Profile             string             `json:"profile"`
	Status              string             `json:"status"`
	CompletedOperations int                `json:"completed_operations"`
	ElapsedNanoseconds  int64              `json:"elapsed_nanoseconds"`
	Artifacts           []releaseArtifact  `json:"artifacts"`
	RawSources          []releaseRawSource `json:"raw_sources,omitempty"`
	Attachments         []releaseRawSource `json:"attachments,omitempty"`
}

type releaseRawSource struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type rawTraceArtifact struct {
	SchemaVersion int              `json:"schema_version"`
	Kind          string           `json:"kind"`
	Context       string           `json:"context"`
	Records       []rawTraceRecord `json:"records"`
}

type rawTraceRecord struct {
	Sequence       uint64 `json:"sequence"`
	AtNS           int64  `json:"at_ns"`
	Event          string `json:"event"`
	Digest         string `json:"digest"`
	ConnectionID   string `json:"connection_id,omitempty"`
	NativeStreamID *int64 `json:"native_stream_id,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
	Status         string `json:"status,omitempty"`
}

type rawMetricsArtifact struct {
	SchemaVersion int               `json:"schema_version"`
	Kind          string            `json:"kind"`
	Context       string            `json:"context"`
	Records       []rawMetricRecord `json:"records"`
}

type rawMetricRecord struct {
	Name         string  `json:"name"`
	Value        float64 `json:"value"`
	Unit         string  `json:"unit"`
	ConnectionID string  `json:"connection_id,omitempty"`
}

type rawConfigArtifact struct {
	SchemaVersion int               `json:"schema_version"`
	Kind          string            `json:"kind"`
	Context       string            `json:"context"`
	Records       []rawConfigRecord `json:"records"`
}

type rawConfigRecord struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func runCaseSuite(reportPath string, destination *artifactDestination, sourceSHA, sourceRoot, owner, mode, caseID, bpfObject string, plan transportrelease.ReleasePlan, manifest transportrelease.ManifestBinding) error {
	if mode == "race" && !raceDetectorEnabled() {
		return errors.New("race case suite requires a runner built with Go race instrumentation")
	}
	definitions, err := registeredCasesForOwnerAndID(owner, mode, caseID)
	if err != nil {
		return err
	}
	if err := validateReleaseCaseDefinitions(definitions); err != nil {
		return err
	}
	kernel, err := kernelRelease()
	if err != nil {
		return err
	}
	report := caseSuiteReport{
		SchemaVersion: 1, Classification: "linux_transport_case_suite", SourceSHA: sourceSHA,
		ManifestDigest: manifest.Digest, ManifestSHA256: hex.EncodeToString(manifest.SHA256Sum[:]),
		Runner: baselineRunner{OS: "linux", Architecture: "amd64", KernelRelease: kernel},
		Owner:  owner, Mode: mode, StartedAt: time.Now().UTC(),
	}
	for _, definition := range definitions {
		if owner == browserSmokeOwner {
			caseCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			result, runErr := runBrowserSmokeCase(caseCtx, destination, definition, mode, sourceRoot, plan)
			cancel()
			if runErr != nil {
				return fmt.Errorf("case %s: %w", definition.ID, runErr)
			}
			report.Results = append(report.Results, result)
			continue
		}
		if owner == weaknetSystemOwner {
			caseCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			result, runErr := runWeaknetSystemCase(caseCtx, destination, definition, bpfObject)
			cancel()
			if runErr != nil {
				return fmt.Errorf("case %s: %w", definition.ID, runErr)
			}
			report.Results = append(report.Results, result)
			continue
		}
		if owner == soakOwner {
			caseCtx, cancel := context.WithTimeout(context.Background(), productionSoakContract().Duration+2*time.Minute)
			result, runErr := runRegisteredSoakCase(caseCtx, destination, definition)
			cancel()
			if runErr != nil {
				return fmt.Errorf("case %s: %w", definition.ID, runErr)
			}
			report.Results = append(report.Results, result)
			continue
		}
		if owner == capacityOwner {
			capacityDefinition, ok := lookupCapacityCase(definition.ID)
			if !ok || capacityDefinition.Profile != definition.Profile {
				return fmt.Errorf("case %s: registered capacity definition is not frozen", definition.ID)
			}
			caseCtx, cancel := context.WithTimeout(context.Background(), capacityCaseTimeout(capacityDefinition))
			result, runErr := runRegisteredCapacityCase(caseCtx, destination, definition, sourceRoot, plan)
			cancel()
			if runErr != nil {
				return fmt.Errorf("case %s: %w", definition.ID, runErr)
			}
			report.Results = append(report.Results, result)
			continue
		}
		if owner == weaknetFullOwner {
			caseCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			result, runErr := runWeaknetFullCase(caseCtx, destination, definition, mode)
			cancel()
			if runErr != nil {
				return fmt.Errorf("case %s: %w", definition.ID, runErr)
			}
			report.Results = append(report.Results, result)
			continue
		}
		if owner == quicNativeSmokeOwner {
			caseCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			result, runErr := runNativeSmokeCase(caseCtx, destination, definition, mode)
			cancel()
			if runErr != nil {
				return fmt.Errorf("case %s: %w", definition.ID, runErr)
			}
			report.Results = append(report.Results, result)
			continue
		}
		if owner == quicNativeProofOwner {
			caseCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			result, runErr := runNativeProofCase(caseCtx, destination, definition, mode, bpfObject)
			cancel()
			if runErr != nil {
				return fmt.Errorf("case %s: %w", definition.ID, runErr)
			}
			report.Results = append(report.Results, result)
			continue
		}
		if owner == quicNativeRaceOwner {
			caseCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			result, runErr := runNativeRaceCase(caseCtx, destination, definition, mode, sourceRoot, bpfObject, plan)
			cancel()
			if runErr != nil {
				return fmt.Errorf("case %s: %w", definition.ID, runErr)
			}
			report.Results = append(report.Results, result)
			continue
		}
		started := time.Now()
		caseCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		completed, runErr := runConformanceSmokeCase(caseCtx, definition)
		cancel()
		if runErr != nil {
			return fmt.Errorf("case %s: %w", definition.ID, runErr)
		}
		elapsed := time.Since(started)
		artifacts, err := writeCaseIdentityArtifactsForMode(destination, definition, mode, completed, elapsed)
		if err != nil {
			return fmt.Errorf("case %s artifacts: %w", definition.ID, err)
		}
		report.Results = append(report.Results, releaseCaseResult{
			ID: definition.ID, Profile: definition.Profile, Status: "pass",
			CompletedOperations: completed.CompletedOperations, ElapsedNanoseconds: elapsed.Nanoseconds(), Artifacts: artifacts,
		})
	}
	report.FinishedAt = time.Now().UTC()
	if err := destination.Verify(); err != nil {
		return err
	}
	return writeNewReport(reportPath, report)
}

func runConformanceSmokeCase(ctx context.Context, definition releaseCaseDefinition) (releaseCaseRun, error) {
	request := []byte("flowersec-release-case-request")
	response := []byte("flowersec-release-case-response")
	if definition.Carrier != "" {
		endpoint, err := transportrelease.OpenProductDirectEndpointWithSuite(ctx, definition.Carrier, definition.Suite)
		if err != nil {
			return releaseCaseRun{}, err
		}
		pair, err := endpoint.Connect(ctx)
		if err != nil {
			return releaseCaseRun{}, errors.Join(err, endpoint.Close())
		}
		roundTripErr := pair.RoundTrip(ctx, request, response)
		closeErr := errors.Join(pair.Close(), endpoint.Close())
		if roundTripErr != nil || closeErr != nil {
			return releaseCaseRun{}, errors.Join(roundTripErr, closeErr)
		}
		if pair.Suite != definition.Suite {
			return releaseCaseRun{}, fmt.Errorf("negotiated suite %d, want %d", pair.Suite, definition.Suite)
		}
		return releaseCaseRun{CompletedOperations: 1, NegotiatedSuite: pair.Suite}, nil
	}
	if definition.Topology == "" {
		return releaseCaseRun{}, errors.New("case has no production carrier or tunnel topology")
	}
	endpoint, err := tunnelworkload.OpenEndpointAtWithSuite(ctx, definition.Topology, "127.0.0.1", definition.Suite)
	if err != nil {
		return releaseCaseRun{}, err
	}
	pair, err := endpoint.Connect(ctx)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return releaseCaseRun{}, errors.Join(err, endpoint.Close(cleanupCtx))
	}
	operations, runErr := tunnelworkload.RunRPC(ctx, pair, 1, 1, 1024, 5*time.Second)
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	closeErr := errors.Join(pair.Close(cleanupCtx), endpoint.Close(cleanupCtx))
	cancel()
	if runErr != nil || closeErr != nil || len(operations) != 1 {
		return releaseCaseRun{}, errors.Join(runErr, closeErr)
	}
	if pair.Suite != definition.Suite {
		return releaseCaseRun{}, fmt.Errorf("negotiated suite %d, want %d", pair.Suite, definition.Suite)
	}
	return releaseCaseRun{CompletedOperations: len(operations), NegotiatedSuite: pair.Suite}, nil
}

func writeCaseIdentityArtifacts(destination *artifactDestination, definition releaseCaseDefinition, completed releaseCaseRun, elapsed time.Duration) ([]releaseArtifact, error) {
	return writeCaseIdentityArtifactsForMode(destination, definition, "normal", completed, elapsed)
}

func writeCaseIdentityArtifactsForMode(destination *artifactDestination, definition releaseCaseDefinition, mode string, completed releaseCaseRun, elapsed time.Duration) ([]releaseArtifact, error) {
	if destination == nil || completed.CompletedOperations < 1 || completed.NegotiatedSuite != definition.Suite || elapsed <= 0 {
		return nil, errors.New("case artifacts require a destination and a successful measured workload")
	}
	contextName := releaseCaseContext(mode, definition.ID)
	executionID := releaseCaseExecutionID(contextName)
	directory := filepath.Join(destination.root.path, definition.artifactLabel())
	if err := os.Mkdir(directory, 0o700); err != nil {
		return nil, err
	}
	trace, err := writeRawCaseArtifact(destination, filepath.Join(directory, "trace.json"), "trace", rawTraceArtifact{
		SchemaVersion: 1, Kind: "transport_trace", Context: contextName,
		Records: []rawTraceRecord{{Sequence: 1, AtNS: elapsed.Nanoseconds(), Event: "completed", Digest: executionID}},
	})
	if err != nil {
		return nil, err
	}
	metrics, err := writeRawCaseArtifact(destination, filepath.Join(directory, "metrics.json"), "metrics", rawMetricsArtifact{
		SchemaVersion: 1, Kind: "transport_metrics", Context: contextName,
		Records: []rawMetricRecord{
			{Name: "completed_operations", Value: float64(completed.CompletedOperations), Unit: "count"},
			{Name: "elapsed_nanoseconds", Value: float64(elapsed.Nanoseconds()), Unit: "nanoseconds"},
		},
	})
	if err != nil {
		return nil, err
	}
	config, err := writeRawCaseArtifact(destination, filepath.Join(directory, "config.json"), "config", rawConfigArtifact{
		SchemaVersion: 1, Kind: "transport_config", Context: contextName,
		Records: []rawConfigRecord{
			{Key: "case_id", Value: definition.ID},
			{Key: "case_profile", Value: definition.Profile},
			{Key: "suite", Value: fmt.Sprint(uint16(completed.NegotiatedSuite))},
			{Key: "test_id", Value: executionID},
			{Key: "trace_sha256", Value: trace.SHA256},
			{Key: "metrics_sha256", Value: metrics.SHA256},
			{Key: "watchdog", Value: "completed"},
		},
	})
	if err != nil {
		return nil, err
	}
	return []releaseArtifact{trace, metrics, config}, nil
}

func releaseCaseExecutionID(contextName string) string {
	digest := sha256.Sum256([]byte("flowersec-transport-case-v1\x00" + contextName))
	return hex.EncodeToString(digest[:])
}

func writeRawCaseArtifact(destination *artifactDestination, path, kind string, value any) (releaseArtifact, error) {
	if err := destination.Verify(); err != nil {
		return releaseArtifact{}, err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return releaseArtifact{}, err
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return releaseArtifact{}, err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return releaseArtifact{}, err
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		return releaseArtifact{}, err
	}
	if err := destination.Verify(); err != nil {
		return releaseArtifact{}, err
	}
	relative, err := filepath.Rel(destination.reportParent.path, path)
	if err != nil || relative == "." || strings.HasPrefix(relative, "..") {
		return releaseArtifact{}, errors.New("case artifact is outside the report directory")
	}
	digest := sha256.Sum256(data)
	return releaseArtifact{Kind: kind, Path: filepath.ToSlash(relative), SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(data))}, nil
}

func writeRawCaseArtifactBytes(destination *artifactDestination, path, kind string, data []byte) (releaseArtifact, error) {
	if err := destination.Verify(); err != nil {
		return releaseArtifact{}, err
	}
	if len(data) == 0 {
		return releaseArtifact{}, errors.New("case artifact must not be empty")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return releaseArtifact{}, err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return releaseArtifact{}, err
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		return releaseArtifact{}, err
	}
	if err := destination.Verify(); err != nil {
		return releaseArtifact{}, err
	}
	relative, err := filepath.Rel(destination.reportParent.path, path)
	if err != nil || relative == "." || strings.HasPrefix(relative, "..") {
		return releaseArtifact{}, errors.New("case artifact is outside the report directory")
	}
	digest := sha256.Sum256(data)
	return releaseArtifact{Kind: kind, Path: filepath.ToSlash(relative), SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(data))}, nil
}
