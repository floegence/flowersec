package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/tunnelworkload"
)

const quicNativeSmokeOwner = "quic-native-smoke"

type nativeCaseRun struct {
	completed    int
	observations []nativeApplicationObservation
	qlog         []byte
	connectionID string
}

type nativeApplicationObservation struct {
	event     string
	streamID  int64
	requestID string
	status    string
}

var nativeSmokeCases = []releaseCaseDefinition{
	{ID: "NS-N1", Profile: "native-stream-structure", Carrier: carrier.KindQUIC},
	{ID: "NS-N2", Profile: "native-flow-isolation", Carrier: carrier.KindQUIC},
	{ID: "NS-N3", Profile: "native-reset-isolation", Carrier: carrier.KindQUIC},
	{ID: "NS-N4", Profile: "mixed-bridge-isolation", Topology: tunnelworkload.TopologyQW},
}

func runNativeSmokeCase(ctx context.Context, destination *artifactDestination, definition releaseCaseDefinition, mode string) (releaseCaseResult, error) {
	if mode != "normal" {
		return releaseCaseResult{}, errors.New("quic-native-smoke only supports normal mode")
	}
	capture, err := startNativeQLOGCapture()
	if err != nil {
		return releaseCaseResult{}, err
	}
	started := time.Now()
	var run nativeCaseRun
	switch definition.ID {
	case "NS-N1":
		run, err = runEightNativeStreams(ctx)
	case "NS-N2":
		run, err = runNativeFlowIsolation(ctx)
	case "NS-N3":
		run, err = runNativeResetIsolation(ctx)
	case "NS-N4":
		run, err = runMixedTunnelFlowIsolation(ctx)
	default:
		err = fmt.Errorf("unknown native smoke case %s", definition.ID)
	}
	expectedStreamIDs := make([]int64, 0, len(run.observations))
	for _, observation := range run.observations {
		expectedStreamIDs = append(expectedStreamIDs, observation.streamID)
	}
	qlog, connectionID, captureErr := capture.finish(expectedStreamIDs)
	err = errors.Join(err, captureErr)
	if err != nil {
		return releaseCaseResult{}, err
	}
	run.qlog = qlog
	run.connectionID = connectionID
	elapsed := time.Since(started)
	written, err := writeNativeCaseArtifacts(destination, definition, mode, run, elapsed)
	if err != nil {
		return releaseCaseResult{}, err
	}
	return releaseCaseResult{
		ID: definition.ID, Profile: definition.Profile, Status: "pass",
		CompletedOperations: run.completed, ElapsedNanoseconds: elapsed.Nanoseconds(), Artifacts: written.Artifacts, RawSources: written.RawSources,
	}, nil
}

func runEightNativeStreams(ctx context.Context) (nativeCaseRun, error) {
	client, server, closePair, err := openNativeQUICPair(ctx, rawquic.DefaultLimits())
	if err != nil {
		return nativeCaseRun{}, err
	}
	defer closePair()
	observations := make([]nativeApplicationObservation, 0, 8)
	seen := make(map[int64]struct{}, 8)
	for index := range 8 {
		opened, err := client.OpenStream(ctx)
		if err != nil {
			return nativeCaseRun{}, err
		}
		id := nativeStreamID(opened)
		if id < 0 {
			return nativeCaseRun{}, errors.New("raw QUIC stream did not expose its native ID")
		}
		if _, duplicate := seen[id]; duplicate {
			return nativeCaseRun{}, fmt.Errorf("native stream ID %d was reused", id)
		}
		seen[id] = struct{}{}
		if _, err := opened.Write([]byte{byte(index)}); err != nil {
			return nativeCaseRun{}, err
		}
		accepted, err := server.AcceptStream(ctx)
		if err != nil {
			return nativeCaseRun{}, err
		}
		payload := make([]byte, 1)
		if _, err := io.ReadFull(accepted, payload); err != nil || payload[0] != byte(index) || nativeStreamID(accepted) != id {
			return nativeCaseRun{}, errors.Join(err, errors.New("native stream payload or ID mismatch"))
		}
		observations = append(observations, nativeApplicationObservation{event: "native_stream_observed", streamID: id})
		_ = opened.Reset()
		_ = accepted.Reset()
	}
	return nativeCaseRun{completed: len(seen), observations: observations}, nil
}

func runNativeFlowIsolation(ctx context.Context) (nativeCaseRun, error) {
	limits := rawquic.DefaultLimits()
	limits.InitialStreamReceiveWindow = 16 << 10
	limits.MaxStreamReceiveWindow = 16 << 10
	limits.InitialConnectionReceiveWindow = 256 << 10
	limits.MaxConnectionReceiveWindow = 256 << 10
	client, server, closePair, err := openNativeQUICPair(ctx, limits)
	if err != nil {
		return nativeCaseRun{}, fmt.Errorf("open flow-isolation pair: %w", err)
	}
	defer closePair()
	blocked, err := client.OpenStream(ctx)
	if err != nil {
		return nativeCaseRun{}, err
	}
	blockedID := nativeStreamID(blocked)
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := blocked.Write(make([]byte, 8<<20))
		writeDone <- writeErr
	}()
	accepted := make(chan struct {
		stream carrier.Stream
		err    error
	}, 1)
	go func() {
		stream, acceptErr := server.AcceptStream(ctx)
		accepted <- struct {
			stream carrier.Stream
			err    error
		}{stream: stream, err: acceptErr}
	}()
	var serverBlocked carrier.Stream
	select {
	case result := <-accepted:
		if result.err != nil {
			return nativeCaseRun{}, fmt.Errorf("accept blocked stream: %w", result.err)
		}
		serverBlocked = result.stream
	case err := <-writeDone:
		return nativeCaseRun{}, fmt.Errorf("unread native stream completed before accept: %w", err)
	case <-ctx.Done():
		return nativeCaseRun{}, context.Cause(ctx)
	}
	select {
	case err := <-writeDone:
		return nativeCaseRun{}, fmt.Errorf("unread native stream did not flow-control block: %w", err)
	case <-time.After(50 * time.Millisecond):
	case <-ctx.Done():
		return nativeCaseRun{}, context.Cause(ctx)
	}
	siblingID, err := nativeCarrierRoundTrip(ctx, client, server, []byte("interactive"), []byte("ok"))
	if err != nil {
		return nativeCaseRun{}, fmt.Errorf("flow-isolation sibling: %w", err)
	}
	_ = blocked.Reset()
	_ = serverBlocked.Reset()
	return nativeCaseRun{completed: 2, observations: []nativeApplicationObservation{
		{event: "native_stream_blocked", streamID: blockedID},
		{event: "rpc_completed", streamID: siblingID, requestID: "native-flow-sibling", status: "ok"},
	}}, nil
}

func runNativeResetIsolation(ctx context.Context) (nativeCaseRun, error) {
	client, server, closePair, err := openNativeQUICPair(ctx, rawquic.DefaultLimits())
	if err != nil {
		return nativeCaseRun{}, err
	}
	defer closePair()
	reset, err := client.OpenStream(ctx)
	if err != nil {
		return nativeCaseRun{}, err
	}
	resetID := nativeStreamID(reset)
	if _, err := reset.Write([]byte("reset-me")); err != nil {
		return nativeCaseRun{}, err
	}
	serverReset, err := server.AcceptStream(ctx)
	if err != nil {
		return nativeCaseRun{}, err
	}
	if err := reset.Reset(); err != nil {
		return nativeCaseRun{}, err
	}
	buffer := make([]byte, 32)
	for {
		_, readErr := serverReset.Read(buffer)
		if readErr == nil {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			return nativeCaseRun{}, errors.New("reset stream ended with clean FIN")
		}
		break
	}
	siblingID, err := nativeCarrierRoundTrip(ctx, client, server, []byte("survivor"), []byte("still-alive"))
	if err != nil {
		return nativeCaseRun{}, err
	}
	_ = serverReset.Reset()
	return nativeCaseRun{completed: 2, observations: []nativeApplicationObservation{
		{event: "native_stream_reset", streamID: resetID},
		{event: "rpc_completed", streamID: siblingID, requestID: "native-reset-sibling", status: "ok"},
	}}, nil
}

func runMixedTunnelFlowIsolation(ctx context.Context) (nativeCaseRun, error) {
	endpoint, err := tunnelworkload.OpenEndpointAt(ctx, tunnelworkload.TopologyQW, "127.0.0.1")
	if err != nil {
		return nativeCaseRun{}, err
	}
	pair, err := endpoint.Connect(ctx)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return nativeCaseRun{}, errors.Join(err, endpoint.Close(cleanupCtx))
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = errors.Join(pair.Close(cleanupCtx), endpoint.Close(cleanupCtx))
	}()
	blocked, err := pair.Client.OpenStream(ctx, "native-flow-blocked", map[string]any{"role": "blocked"})
	if err != nil {
		return nativeCaseRun{}, err
	}
	blockedID, ok := flowersession.ReleaseEvidenceNativeStreamID(blocked)
	if !ok {
		return nativeCaseRun{}, errors.New("mixed tunnel blocked stream has no internal native identity")
	}
	serverBlocked, err := pair.Server.AcceptStream(ctx)
	if err != nil {
		return nativeCaseRun{}, err
	}
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := blocked.Write(make([]byte, 32<<20))
		writeDone <- writeErr
	}()
	select {
	case err := <-writeDone:
		return nativeCaseRun{}, fmt.Errorf("mixed tunnel blocked stream completed unexpectedly: %w", err)
	case <-time.After(50 * time.Millisecond):
	case <-ctx.Done():
		return nativeCaseRun{}, context.Cause(ctx)
	}
	sibling, err := pair.Client.OpenStream(ctx, "native-flow-sibling", map[string]any{"role": "sibling"})
	if err != nil {
		return nativeCaseRun{}, err
	}
	siblingID, ok := flowersession.ReleaseEvidenceNativeStreamID(sibling)
	if !ok || siblingID == blockedID {
		return nativeCaseRun{}, errors.New("mixed tunnel sibling has no distinct internal native identity")
	}
	if _, err := sibling.Write([]byte("interactive")); err != nil {
		return nativeCaseRun{}, err
	}
	if err := sibling.CloseWrite(); err != nil {
		return nativeCaseRun{}, err
	}
	serverSibling, err := pair.Server.AcceptStream(ctx)
	if err != nil {
		return nativeCaseRun{}, err
	}
	request, err := io.ReadAll(serverSibling.Stream)
	if err != nil || string(request) != "interactive" {
		return nativeCaseRun{}, errors.Join(err, errors.New("mixed tunnel sibling request mismatch"))
	}
	if _, err := serverSibling.Stream.Write([]byte("ok")); err != nil {
		return nativeCaseRun{}, err
	}
	if err := serverSibling.Stream.CloseWrite(); err != nil {
		return nativeCaseRun{}, err
	}
	response, err := io.ReadAll(sibling)
	if err != nil || string(response) != "ok" {
		return nativeCaseRun{}, errors.Join(err, errors.New("mixed tunnel sibling response mismatch"))
	}
	_ = sibling.Close()
	_ = serverSibling.Stream.Close()
	_ = blocked.Reset()
	_ = serverBlocked.Stream.Reset()
	select {
	case <-writeDone:
	case <-ctx.Done():
		return nativeCaseRun{}, errors.New("mixed tunnel reset did not release blocked writer")
	}
	return nativeCaseRun{completed: 2, observations: []nativeApplicationObservation{
		{event: "native_stream_blocked", streamID: blockedID},
		{event: "rpc_completed", streamID: siblingID, requestID: "mixed-bridge-sibling", status: "ok"},
	}}, nil
}

type nativeWrittenArtifacts struct {
	Artifacts  []releaseArtifact
	RawSources []releaseRawSource
}

func writeNativeCaseArtifacts(destination *artifactDestination, definition releaseCaseDefinition, mode string, run nativeCaseRun, elapsed time.Duration) (nativeWrittenArtifacts, error) {
	contextName := releaseCaseContext(mode, definition.ID)
	executionID := releaseCaseExecutionID(contextName)
	directory := filepath.Join(destination.root.path, definition.artifactLabel())
	if err := os.Mkdir(directory, 0o700); err != nil {
		return nativeWrittenArtifacts{}, err
	}
	rawDirectory := filepath.Join(directory, "raw")
	if err := os.Mkdir(rawDirectory, 0o700); err != nil {
		return nativeWrittenArtifacts{}, err
	}
	rawQLOG, err := writeRawCaseArtifactBytes(destination, filepath.Join(rawDirectory, "qlog-001.sqlog"), "qlog-json-seq", run.qlog)
	if err != nil {
		return nativeWrittenArtifacts{}, err
	}
	rawSource := releaseRawSource{ID: "qlog-001", Kind: "qlog", Path: rawQLOG.Path, SHA256: rawQLOG.SHA256, SizeBytes: rawQLOG.SizeBytes}
	observationTimes, completedAt, err := nativeObservationQLOGTimes(run.qlog, run.observations)
	if err != nil {
		return nativeWrittenArtifacts{}, err
	}
	traceRecords := make([]rawTraceRecord, 0, len(run.observations)+1)
	for index, observation := range run.observations {
		streamID := observation.streamID
		traceRecords = append(traceRecords, rawTraceRecord{
			Sequence: uint64(index + 1), AtNS: observationTimes[index], Event: observation.event, Digest: executionID,
			ConnectionID: run.connectionID, NativeStreamID: &streamID, RequestID: observation.requestID, Status: observation.status,
		})
	}
	traceRecords = append(traceRecords, rawTraceRecord{
		Sequence: uint64(len(traceRecords) + 1), AtNS: completedAt,
		Event: "completed", Digest: executionID, ConnectionID: run.connectionID,
	})
	trace, err := writeRawCaseArtifact(destination, filepath.Join(directory, "trace.json"), "trace", rawTraceArtifact{
		SchemaVersion: 1, Kind: "transport_trace", Context: contextName,
		Records: traceRecords,
	})
	if err != nil {
		return nativeWrittenArtifacts{}, err
	}
	attributionRecord, err := firstCapacityQLOGAttribution(run.qlog, rawSource)
	if err != nil {
		return nativeWrittenArtifacts{}, err
	}
	attributionRecord.Sequence = 1
	qlog, err := writeRawCaseArtifact(destination, filepath.Join(directory, "qlog.json"), "qlog", capacityAttributionArtifact{
		SchemaVersion: 1, Kind: "transport_qlog_attribution", Context: contextName, Records: []capacityAttributionRecord{attributionRecord},
	})
	if err != nil {
		return nativeWrittenArtifacts{}, err
	}
	var artifacts []releaseArtifact
	artifacts = append(artifacts, trace, qlog)
	var metrics releaseArtifact
	if definition.ID != "NS-N1" {
		metrics, err = writeRawCaseArtifact(destination, filepath.Join(directory, "metrics.json"), "metrics", rawMetricsArtifact{
			SchemaVersion: 1, Kind: "transport_metrics", Context: contextName,
			Records: []rawMetricRecord{{Name: "completed_operations", Value: float64(run.completed), Unit: "count"}, {Name: "watchdog_timeouts", Value: 0, Unit: "count"}},
		})
		if err != nil {
			return nativeWrittenArtifacts{}, err
		}
		artifacts = append(artifacts, metrics)
	}
	configRecords := []rawConfigRecord{
		{Key: "case_id", Value: definition.ID}, {Key: "case_profile", Value: definition.Profile},
		{Key: "test_id", Value: executionID}, {Key: "trace_sha256", Value: trace.SHA256},
		{Key: "qlog_sha256", Value: qlog.SHA256}, {Key: "qlog_source", Value: "quic-go-json-seq-v0.3"},
		{Key: "qlog_connection_id", Value: run.connectionID},
		{Key: "watchdog", Value: "completed"},
	}
	if metrics.Kind != "" {
		configRecords = append(configRecords, rawConfigRecord{Key: "metrics_sha256", Value: metrics.SHA256})
	}
	config, err := writeRawCaseArtifact(destination, filepath.Join(directory, "config.json"), "config", rawConfigArtifact{
		SchemaVersion: 1, Kind: "transport_config", Context: contextName, Records: configRecords,
	})
	if err != nil {
		return nativeWrittenArtifacts{}, err
	}
	artifacts = append(artifacts, config)
	return nativeWrittenArtifacts{Artifacts: artifacts, RawSources: []releaseRawSource{rawSource}}, nil
}

func nativeObservationQLOGTimes(data []byte, observations []nativeApplicationObservation) ([]int64, int64, error) {
	records, err := capacityQLOGRecords(data)
	if err != nil {
		return nil, 0, err
	}
	var reference time.Time
	times := make([]int64, len(observations))
	completedAt := int64(0)
	nextObservation := 0
	lossObserved := false
	for _, framed := range records {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(framed.payload, &object); err != nil {
			return nil, 0, errors.New("native qlog sequence record is invalid")
		}
		if traceRaw, ok := object["trace"]; ok {
			var header struct {
				CommonFields struct {
					ReferenceTime struct {
						WallClockTime string `json:"wall_clock_time"`
					} `json:"reference_time"`
				} `json:"common_fields"`
			}
			if json.Unmarshal(traceRaw, &header) != nil {
				return nil, 0, errors.New("native qlog reference time is invalid")
			}
			reference, err = time.Parse(time.RFC3339Nano, header.CommonFields.ReferenceTime.WallClockTime)
			if err != nil {
				return nil, 0, errors.New("native qlog reference time is invalid")
			}
			continue
		}
		var event struct {
			Time float64 `json:"time"`
			Name string  `json:"name"`
			Data struct {
				Frames []map[string]any `json:"frames"`
			} `json:"data"`
		}
		if reference.IsZero() || json.Unmarshal(framed.payload, &event) != nil || math.IsNaN(event.Time) || math.IsInf(event.Time, 0) || event.Time < 0 {
			return nil, 0, errors.New("native qlog event time is invalid")
		}
		at := reference.UTC().Add(time.Duration(event.Time * float64(time.Millisecond))).UnixNano()
		if at > completedAt {
			completedAt = at
		}
		if event.Name == "recovery:packet_lost" {
			lossObserved = true
		}
		for _, frame := range event.Data.Frames {
			if nextObservation >= len(observations) {
				break
			}
			frameType, _ := frame["frame_type"].(string)
			streamValue, hasStream := frame["stream_id"].(float64)
			observation := observations[nextObservation]
			preferred := map[string]string{
				"native_stream_blocked": "stream_data_blocked", "native_stream_reset": "reset_stream",
				"native_connection_blocked": "data_blocked", "native_stream_observed": "stream", "rpc_completed": "stream",
				"targeted_loss_released": "stream",
			}[observation.event]
			matchesStream := hasStream && streamValue == float64(observation.streamID)
			matchesFrame := preferred == "data_blocked" && frameType == preferred || matchesStream && frameType == preferred
			if matchesFrame && (observation.event != "targeted_loss_released" || lossObserved) {
				times[nextObservation] = at
				nextObservation++
			}
		}
	}
	if nextObservation != len(observations) {
		return nil, 0, fmt.Errorf("native observation %d is absent from or out of order in raw qlog", nextObservation)
	}
	if len(times) > 0 && completedAt < times[len(times)-1] {
		return nil, 0, errors.New("native qlog completion precedes application observations")
	}
	return times, completedAt, nil
}

func nativePostLossStreamID(data []byte) (int64, error) {
	records, err := capacityQLOGRecords(data)
	if err != nil {
		return -1, err
	}
	lossObserved := false
	for _, framed := range records {
		var event struct {
			Name string `json:"name"`
			Data struct {
				Frames []map[string]any `json:"frames"`
			} `json:"data"`
		}
		if err := json.Unmarshal(framed.payload, &event); err != nil {
			return -1, errors.New("native targeted-loss qlog record is invalid")
		}
		if event.Name == "recovery:packet_lost" {
			lossObserved = true
			continue
		}
		if !lossObserved || event.Name != "transport:packet_sent" {
			continue
		}
		for _, frame := range event.Data.Frames {
			if frameType, _ := frame["frame_type"].(string); frameType != "stream" {
				continue
			}
			streamID, ok := frame["stream_id"].(float64)
			if !ok || streamID < 0 || streamID != math.Trunc(streamID) || streamID > math.MaxInt64 {
				return -1, errors.New("native targeted-loss qlog stream ID is invalid")
			}
			return int64(streamID), nil
		}
	}
	if !lossObserved {
		return -1, errors.New("native targeted-loss qlog has no packet loss event")
	}
	return -1, errors.New("native targeted-loss qlog has no STREAM frame sent after packet loss")
}

func nativeStreamID(stream carrier.Stream) int64 {
	if identified, ok := stream.(interface{ NativeStreamID() int64 }); ok {
		return identified.NativeStreamID()
	}
	return -1
}

func nativeCarrierRoundTrip(ctx context.Context, client, server carrier.Session, request, response []byte) (int64, error) {
	opened, err := client.OpenStream(ctx)
	if err != nil {
		return -1, fmt.Errorf("open sibling: %w", err)
	}
	defer opened.Close()
	id := nativeStreamID(opened)
	if _, err := opened.Write(request); err != nil {
		return -1, fmt.Errorf("write sibling request: %w", err)
	}
	if err := opened.CloseWrite(); err != nil {
		return -1, fmt.Errorf("close sibling request: %w", err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		return -1, fmt.Errorf("accept sibling: %w", err)
	}
	defer accepted.Close()
	payload, err := io.ReadAll(accepted)
	if err != nil || string(payload) != string(request) {
		return -1, errors.Join(err, errors.New("native sibling request mismatch"))
	}
	if _, err := accepted.Write(response); err != nil {
		return -1, fmt.Errorf("write sibling response: %w", err)
	}
	if err := accepted.CloseWrite(); err != nil {
		return -1, fmt.Errorf("close sibling response: %w", err)
	}
	payload, err = io.ReadAll(opened)
	if err != nil || string(payload) != string(response) {
		return -1, errors.Join(err, errors.New("native sibling response mismatch"))
	}
	return id, nil
}

type nativeQLOGCapture struct {
	directory string
	previous  map[string]*string
}

func startNativeQLOGCapture() (*nativeQLOGCapture, error) {
	directory, err := os.MkdirTemp("", "flowersec-native-qlog-")
	if err != nil {
		return nil, err
	}
	previous := make(map[string]*string, 2)
	for key, value := range map[string]string{"QLOGDIR": directory, "FLOWERSEC_TRANSPORT_RELEASE_EVIDENCE": "1"} {
		if old, exists := os.LookupEnv(key); exists {
			copy := old
			previous[key] = &copy
		} else {
			previous[key] = nil
		}
		if err := os.Setenv(key, value); err != nil {
			_ = os.RemoveAll(directory)
			return nil, err
		}
	}
	return &nativeQLOGCapture{directory: directory, previous: previous}, nil
}

func (capture *nativeQLOGCapture) finish(expectedStreamIDs []int64) ([]byte, string, error) {
	var restoreErr error
	for key, previous := range capture.previous {
		if previous == nil {
			restoreErr = errors.Join(restoreErr, os.Unsetenv(key))
		} else {
			restoreErr = errors.Join(restoreErr, os.Setenv(key, *previous))
		}
	}
	defer os.RemoveAll(capture.directory)
	paths, err := filepath.Glob(filepath.Join(capture.directory, "*.sqlog"))
	if err != nil {
		return nil, "", errors.Join(restoreErr, err)
	}
	sort.Strings(paths)
	var candidates []struct {
		data         []byte
		connectionID string
		client       bool
	}
	for _, path := range paths {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, "", errors.Join(restoreErr, readErr)
		}
		connectionID, streamIDs, parseErr := inspectNativeQLOG(data)
		if parseErr != nil || !containsEveryNativeStreamID(streamIDs, expectedStreamIDs) {
			continue
		}
		candidates = append(candidates, struct {
			data         []byte
			connectionID string
			client       bool
		}{data: data, connectionID: connectionID, client: strings.HasSuffix(path, "_client.sqlog")})
	}
	if len(candidates) == 0 {
		return nil, "", errors.Join(restoreErr, errors.New("no raw quic-go qlog contains the observed native streams"))
	}
	for _, candidate := range candidates {
		if candidate.client {
			return candidate.data, candidate.connectionID, restoreErr
		}
	}
	return candidates[0].data, candidates[0].connectionID, restoreErr
}

func inspectNativeQLOG(data []byte) (string, map[int64]struct{}, error) {
	streamIDs := make(map[int64]struct{})
	connectionID := ""
	for _, record := range bytes.Split(data, []byte{0x1e}) {
		record = bytes.TrimSpace(record)
		if len(record) == 0 {
			continue
		}
		var object struct {
			Trace *struct {
				CommonFields struct {
					GroupID string `json:"group_id"`
				} `json:"common_fields"`
			} `json:"trace"`
			Data struct {
				Frames []map[string]any `json:"frames"`
			} `json:"data"`
		}
		if err := json.Unmarshal(record, &object); err != nil {
			return "", nil, err
		}
		if object.Trace != nil {
			connectionID = object.Trace.CommonFields.GroupID
		}
		for _, frame := range object.Data.Frames {
			value, ok := frame["stream_id"].(float64)
			if ok && value >= 0 && value == float64(int64(value)) {
				streamIDs[int64(value)] = struct{}{}
			}
		}
	}
	if strings.TrimSpace(connectionID) == "" || len(streamIDs) == 0 {
		return "", nil, errors.New("qlog is missing a connection group or native stream frames")
	}
	return connectionID, streamIDs, nil
}

func containsEveryNativeStreamID(actual map[int64]struct{}, expected []int64) bool {
	for _, id := range expected {
		if _, exists := actual[id]; !exists {
			return false
		}
	}
	return true
}

func openNativeQUICPair(ctx context.Context, limits rawquic.Limits) (*rawquic.Session, *rawquic.Session, func() error, error) {
	serverTLS, clientTLS, err := nativeReleaseTLS()
	if err != nil {
		return nil, nil, nil, err
	}
	serverTLS.NextProtos = []string{rawquic.ALPNDirect}
	clientTLS.NextProtos = []string{rawquic.ALPNDirect}
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS, limits)
	if err != nil {
		return nil, nil, nil, err
	}
	serverResult := make(chan struct {
		session *rawquic.Session
		err     error
	}, 1)
	go func() {
		session, acceptErr := listener.Accept(ctx)
		serverResult <- struct {
			session *rawquic.Session
			err     error
		}{session: session, err: acceptErr}
	}()
	client, err := rawquic.Dial(ctx, listener.Addr().String(), clientTLS, limits)
	if err != nil {
		_ = listener.Close()
		return nil, nil, nil, err
	}
	result := <-serverResult
	if result.err != nil {
		_ = client.Close()
		_ = listener.Close()
		return nil, nil, nil, result.err
	}
	return client, result.session, func() error {
		return errors.Join(client.Close(), result.session.Close(), listener.Close())
	}, nil
}

func nativeReleaseTLS() (*tls.Config, *tls.Config, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "flowersec-native-release"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	server := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}}}
	client := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost"}
	return server, client, nil
}
