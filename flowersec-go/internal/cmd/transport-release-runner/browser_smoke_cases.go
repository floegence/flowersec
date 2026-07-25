package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
)

type browserSmokeWorkload struct {
	SchemaVersion      int       `json:"schema_version"`
	Classification     string    `json:"classification"`
	Status             string    `json:"status"`
	Topology           string    `json:"topology"`
	ProfileID          string    `json:"profile_id"`
	RunNumber          int       `json:"run_number"`
	StartedAt          time.Time `json:"started_at"`
	FinishedAt         time.Time `json:"finished_at"`
	SessionConnectedAt time.Time `json:"session_connected_at"`
	SessionClosedAt    time.Time `json:"session_closed_at"`
	Browser            struct {
		Engine      string   `json:"engine"`
		Version     string   `json:"version"`
		Diagnostics []string `json:"diagnostics"`
	} `json:"browser"`
	SpendCount        int               `json:"spend_count"`
	CleanupDurationNS int64             `json:"cleanup_duration_ns"`
	Cold              []json.RawMessage `json:"cold"`
	RPC               []struct {
		Ordinal       int       `json:"ordinal"`
		StartedAt     time.Time `json:"started_at"`
		DurationNS    int64     `json:"duration_ns"`
		InputBytes    int       `json:"input_bytes"`
		OutputBytes   int       `json:"output_bytes"`
		PayloadSHA256 string    `json:"payload_sha256"`
	} `json:"rpc"`
	Bulk            json.RawMessage `json:"bulk"`
	NativeIsolation *struct {
		OpenedStreams    int `json:"opened_streams"`
		ResetStreams     int `json:"reset_streams"`
		SiblingStreams   int `json:"sibling_streams"`
		CompletedRPCs    int `json:"completed_rpcs"`
		ResidualStreams  int `json:"residual_streams"`
		ResidualSessions int `json:"residual_sessions"`
		Events           []struct {
			Event       string    `json:"event"`
			At          time.Time `json:"at"`
			StreamCount int       `json:"stream_count,omitempty"`
			RequestID   string    `json:"request_id,omitempty"`
			Status      string    `json:"status,omitempty"`
		} `json:"events"`
	} `json:"native_isolation,omitempty"`
}

func runBrowserSmokeCase(ctx context.Context, destination *artifactDestination, definition releaseCaseDefinition, mode, sourceRoot string, releasePlan transportrelease.ReleasePlan) (releaseCaseResult, error) {
	if destination == nil || (mode != "normal" && mode != "race") || !filepath.IsAbs(sourceRoot) || definition.BrowserTopology == "" || definition.Profile == "" {
		return releaseCaseResult{}, errors.New("browser smoke producer is not initialized")
	}
	profile := browserSmokeProfile(definition, releasePlan.Clean)
	cell, err := runBrowserNetworkCarrierWithLabel(ctx, definition.BrowserTopology, profile, 1, "", sourceRoot, destination, definition.artifactLabel())
	if err != nil {
		return releaseCaseResult{}, err
	}
	var workload browserSmokeWorkload
	decoder := json.NewDecoder(bytes.NewReader(cell.Workload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&workload); err != nil {
		return releaseCaseResult{}, fmt.Errorf("decode browser smoke workload: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return releaseCaseResult{}, errors.New("browser smoke workload contains trailing JSON")
	}
	if workload.SchemaVersion != 1 || workload.Classification != "raw_browser_transport_workload" || workload.Status != "passed" ||
		workload.Topology != definition.BrowserTopology || workload.ProfileID != definition.Profile || workload.RunNumber != 1 ||
		workload.Browser.Engine != "chromium" || strings.TrimSpace(workload.Browser.Version) == "" || len(workload.Cold) != 1 || len(workload.RPC) != 1 || len(workload.Bulk) == 0 ||
		workload.StartedAt.IsZero() || workload.FinishedAt.Before(workload.StartedAt) || workload.SessionConnectedAt.Before(workload.StartedAt) ||
		workload.SessionClosedAt.Before(workload.SessionConnectedAt) || workload.FinishedAt.Before(workload.SessionClosedAt) || workload.RPC[0].Ordinal != 1 ||
		workload.RPC[0].DurationNS <= 0 || workload.RPC[0].InputBytes != 32 || workload.RPC[0].OutputBytes != 32 || len(workload.RPC[0].PayloadSHA256) != 64 {
		return releaseCaseResult{}, errors.New("browser smoke workload does not prove the frozen Chromium operation")
	}
	if definition.ID == "BN-N5" {
		native := workload.NativeIsolation
		if native == nil || native.OpenedStreams != 4 || native.ResetStreams != 1 || native.SiblingStreams != 3 || native.CompletedRPCs != 1 ||
			native.ResidualStreams != 0 || native.ResidualSessions != 0 || len(native.Events) != 4 {
			return releaseCaseResult{}, errors.New("browser native isolation workload is incomplete")
		}
		wantEvents := []string{"native_streams_opened", "native_stream_reset", "native_siblings_completed", "rpc_completed"}
		previous := workload.SessionConnectedAt
		for index, event := range native.Events {
			if event.Event != wantEvents[index] || event.At.Before(previous) || event.At.After(workload.SessionClosedAt) {
				return releaseCaseResult{}, errors.New("browser native isolation event timeline is invalid")
			}
			previous = event.At
		}
	} else if workload.NativeIsolation != nil {
		return releaseCaseResult{}, errors.New("ordinary browser smoke workload unexpectedly ran native isolation")
	}
	return writeBrowserSmokeEvidence(destination, definition, mode, workload, cell.Artifacts)
}

func browserSmokeProfile(definition releaseCaseDefinition, clean transportrelease.ProfilePlan) transportrelease.ProfilePlan {
	return transportrelease.ProfilePlan{
		ID: definition.Profile,
		Cold: transportrelease.ColdPlan{
			Operations: 1, MaxInflight: 1, StartRatePerSecond: 1, OperationDeadlineSeconds: 10, PhaseDeadlineSeconds: 15,
		},
		RPC: transportrelease.RPCPlan{
			Operations: 1, Workers: 1, RequestBytes: 32, ResponseBytes: 32, OperationDeadlineSeconds: 5, PhaseDeadlineSeconds: 10,
		},
		Bulk:    transportrelease.BulkPlan{WarmupBytesPerDirection: 1, ScoreBytesPerDirection: 1, PhaseDeadlineSeconds: 10},
		Network: clean.Network, CleanupDeadlineSeconds: 5, CellWatchdogMinutes: 2,
	}
}

func writeBrowserSmokeEvidence(destination *artifactDestination, definition releaseCaseDefinition, mode string, workload browserSmokeWorkload, produced []releaseArtifact) (releaseCaseResult, error) {
	contextName := releaseCaseContext(mode, definition.ID)
	directory := filepath.Join(destination.root.path, definition.artifactLabel())
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		return releaseCaseResult{}, errors.New("browser smoke evidence directory is unavailable")
	}
	executionID := releaseCaseExecutionID(contextName)
	workloadData, err := json.Marshal(workload)
	if err != nil {
		return releaseCaseResult{}, err
	}
	attachmentArtifact, err := writeRawCaseArtifactBytes(destination, filepath.Join(directory, "browser-result.json"), "browser-controller-result", append(workloadData, '\n'))
	if err != nil {
		return releaseCaseResult{}, err
	}
	atNS := func(at time.Time) int64 { return max(0, at.Sub(workload.StartedAt).Nanoseconds()) }
	traceRecords := []rawTraceRecord{{Sequence: 1, AtNS: atNS(workload.SessionConnectedAt), Event: "browser_session_connected", Digest: executionID}}
	if definition.ID == "BN-N5" {
		for _, event := range workload.NativeIsolation.Events {
			traceRecords = append(traceRecords, rawTraceRecord{
				Sequence: uint64(len(traceRecords) + 1), AtNS: atNS(event.At), Event: event.Event, Digest: executionID,
				RequestID: event.RequestID, Status: event.Status,
			})
		}
	}
	rpcFinished := workload.RPC[0].StartedAt.Add(time.Duration(workload.RPC[0].DurationNS))
	traceRecords = append(traceRecords, rawTraceRecord{Sequence: uint64(len(traceRecords) + 1), AtNS: atNS(rpcFinished), Event: "smoke_rpc_completed", Digest: executionID, RequestID: "browser-smoke-rpc", Status: "ok"})
	traceRecords = append(traceRecords, rawTraceRecord{Sequence: uint64(len(traceRecords) + 1), AtNS: atNS(workload.SessionClosedAt), Event: "browser_session_closed", Digest: executionID})
	for index := 1; index < len(traceRecords); index++ {
		if traceRecords[index].AtNS < traceRecords[index-1].AtNS {
			return releaseCaseResult{}, errors.New("browser smoke source events are not monotonic")
		}
	}
	trace, err := writeRawCaseArtifact(destination, filepath.Join(directory, "trace.json"), "trace", rawTraceArtifact{SchemaVersion: 1, Kind: "transport_trace", Context: contextName, Records: traceRecords})
	if err != nil {
		return releaseCaseResult{}, err
	}
	completed := 3
	if definition.ID == "BN-N5" {
		completed = 8
	}
	metrics, err := writeRawCaseArtifact(destination, filepath.Join(directory, "metrics.json"), "metrics", rawMetricsArtifact{SchemaVersion: 1, Kind: "transport_metrics", Context: contextName, Records: []rawMetricRecord{
		{Name: "completed_operations", Value: float64(completed), Unit: "count"},
		{Name: "browser_sessions", Value: 2, Unit: "count"},
		{Name: "rpc_completed", Value: 1, Unit: "count"},
		{Name: "watchdog_timeouts", Value: 0, Unit: "count"},
		{Name: "residual_sessions", Value: 0, Unit: "count"},
		{Name: "residual_streams", Value: 0, Unit: "count"},
	}})
	if err != nil {
		return releaseCaseResult{}, err
	}
	result := releaseCaseResult{ID: definition.ID, Profile: definition.Profile, Status: "pass", CompletedOperations: completed, ElapsedNanoseconds: workload.FinishedAt.Sub(workload.StartedAt).Nanoseconds(), Artifacts: []releaseArtifact{trace, metrics}}
	counts := make(map[string]int)
	for _, artifact := range produced {
		kind := ""
		switch artifact.Kind {
		case "classic-pcap":
			kind = "pcap"
		case "qlog-json-seq":
			kind = "qlog"
		default:
			continue
		}
		counts[kind]++
		result.RawSources = append(result.RawSources, releaseRawSource{ID: fmt.Sprintf("%s-%03d", kind, counts[kind]), Kind: kind, Path: artifact.Path, SHA256: artifact.SHA256, SizeBytes: artifact.SizeBytes})
	}
	result.Attachments = []releaseRawSource{{ID: "browser-controller-result-001", Kind: "browser-controller-result", Path: attachmentArtifact.Path, SHA256: attachmentArtifact.SHA256, SizeBytes: attachmentArtifact.SizeBytes}}
	if counts["pcap"] != 1 || counts["qlog"] == 0 {
		return releaseCaseResult{}, errors.New("browser smoke evidence is missing raw pcap or qlog sources")
	}
	configRecords := []rawConfigRecord{
		{Key: "case_id", Value: definition.ID}, {Key: "case_profile", Value: definition.Profile}, {Key: "topology", Value: definition.BrowserTopology},
		{Key: "browser_engine", Value: "chromium"}, {Key: "browser_version", Value: workload.Browser.Version}, {Key: "producer", Value: "production-browser-worker"},
		{Key: "browser_result_sha256", Value: attachmentArtifact.SHA256}, {Key: "trace_sha256", Value: trace.SHA256}, {Key: "metrics_sha256", Value: metrics.SHA256},
		{Key: "raw_qlog_count", Value: fmt.Sprint(counts["qlog"])}, {Key: "watchdog", Value: "completed"},
	}
	if definition.ID == "BN-N5" {
		attribution, attributionErr := browserNativeIsolationQLOGAttribution(destination, contextName, result.RawSources)
		if attributionErr != nil {
			return releaseCaseResult{}, attributionErr
		}
		qlog, writeErr := writeRawCaseArtifact(destination, filepath.Join(directory, "qlog.json"), "qlog", attribution)
		if writeErr != nil {
			return releaseCaseResult{}, writeErr
		}
		result.Artifacts = append(result.Artifacts, qlog)
		configRecords = append(configRecords, rawConfigRecord{Key: "qlog_sha256", Value: qlog.SHA256})
	}
	config, err := writeRawCaseArtifact(destination, filepath.Join(directory, "config.json"), "config", rawConfigArtifact{SchemaVersion: 1, Kind: "transport_config", Context: contextName, Records: configRecords})
	if err != nil {
		return releaseCaseResult{}, err
	}
	result.Artifacts = append(result.Artifacts, config)
	return result, nil
}

func browserNativeIsolationQLOGAttribution(destination *artifactDestination, contextName string, sources []releaseRawSource) (capacityAttributionArtifact, error) {
	for _, source := range sources {
		if source.Kind != "qlog" {
			continue
		}
		path := filepath.Join(destination.reportParent.path, filepath.FromSlash(source.Path))
		data, err := os.ReadFile(path)
		if err != nil {
			return capacityAttributionArtifact{}, err
		}
		records, err := browserNativeIsolationQLOGRecords(data, source)
		if err != nil {
			return capacityAttributionArtifact{}, fmt.Errorf("attribute %s: %w", source.ID, err)
		}
		if len(records) == 0 {
			continue
		}
		for index := range records {
			records[index].Sequence = uint64(index + 1)
		}
		return capacityAttributionArtifact{SchemaVersion: 1, Kind: "transport_qlog_attribution", Context: contextName, Records: records}, nil
	}
	return capacityAttributionArtifact{}, errors.New("browser native isolation raw qlog does not prove four streams and one reset")
}

func browserNativeIsolationQLOGRecords(data []byte, source releaseRawSource) ([]capacityAttributionRecord, error) {
	digest := sha256.Sum256(data)
	if source.SHA256 != hex.EncodeToString(digest[:]) {
		return nil, errors.New("qlog source digest changed before browser attribution")
	}
	framedRecords, err := capacityQLOGRecords(data)
	if err != nil {
		return nil, err
	}
	var reference time.Time
	groupID := ""
	opened := make(map[uint64]capacityAttributionRecord, 4)
	orderedIDs := make([]uint64, 0, 4)
	var reset *capacityAttributionRecord
	for _, framed := range framedRecords {
		var object map[string]json.RawMessage
		if json.Unmarshal(framed.payload, &object) != nil {
			return nil, errors.New("qlog JSON sequence record is invalid")
		}
		if traceRaw, ok := object["trace"]; ok {
			var trace struct {
				CommonFields struct {
					GroupID       string `json:"group_id"`
					ReferenceTime struct {
						WallClockTime string `json:"wall_clock_time"`
					} `json:"reference_time"`
				} `json:"common_fields"`
			}
			if json.Unmarshal(traceRaw, &trace) != nil || strings.TrimSpace(trace.CommonFields.GroupID) == "" {
				return nil, errors.New("qlog sequence header identity is invalid")
			}
			reference, err = time.Parse(time.RFC3339Nano, trace.CommonFields.ReferenceTime.WallClockTime)
			if err != nil {
				return nil, errors.New("qlog sequence reference time is invalid")
			}
			groupID = trace.CommonFields.GroupID
			continue
		}
		var event struct {
			Time float64        `json:"time"`
			Name string         `json:"name"`
			Data map[string]any `json:"data"`
		}
		if reference.IsZero() || json.Unmarshal(framed.payload, &event) != nil || event.Time < 0 || event.Data == nil {
			return nil, errors.New("qlog event identity is invalid")
		}
		frames, ok := event.Data["frames"].([]any)
		if !ok {
			continue
		}
		packetNumber, packetSpace, hasPacket := capacityQLOGPacketIdentity(event.Data)
		newRecord := func(eventName string, streamID uint64) capacityAttributionRecord {
			id := streamID
			record := capacityAttributionRecord{
				SourceID: source.ID, SourceSHA256: source.SHA256, ByteOffset: framed.offset, ByteLength: framed.length,
				UnixNanoseconds: reference.UTC().Add(time.Duration(event.Time * float64(time.Millisecond))).UnixNano(),
				Event:           eventName, ConnectionGroupID: groupID, NativeStreamID: &id,
			}
			if hasPacket {
				record.PacketNumber, record.PacketNumberSpace = &packetNumber, packetSpace
			}
			return record
		}
		for _, rawFrame := range frames {
			frame, ok := rawFrame.(map[string]any)
			streamID, idOK := capacityQLOGUint(frame["stream_id"])
			if !ok || !idOK {
				continue
			}
			switch frame["frame_type"] {
			case "stream":
				if streamID >= 12 && streamID%4 == 0 && len(orderedIDs) < 4 {
					if _, exists := opened[streamID]; !exists {
						opened[streamID] = newRecord("transport:stream_opened", streamID)
						orderedIDs = append(orderedIDs, streamID)
					}
				}
			case "reset_stream":
				if _, exists := opened[streamID]; exists && reset == nil {
					record := newRecord("transport:reset_stream", streamID)
					reset = &record
				}
			}
		}
	}
	if len(orderedIDs) != 4 || reset == nil {
		return nil, nil
	}
	result := make([]capacityAttributionRecord, 0, 5)
	for _, streamID := range orderedIDs {
		result = append(result, opened[streamID])
	}
	result = append(result, *reset)
	for index := 1; index < len(result); index++ {
		if result[index].UnixNanoseconds < result[index-1].UnixNanoseconds {
			return nil, errors.New("browser native isolation qlog events are not ordered")
		}
	}
	return result, nil
}
