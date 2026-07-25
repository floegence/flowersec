package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTypedArtifactWriterCreatesBoundArtifact(t *testing.T) {
	directory := canonicalTestDirectory(t)
	writer, err := newTypedArtifactWriter(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	})

	context := "cell clean-02 run 1 phase clean-v1/rpc"
	artifact, err := writer.WriteJSON(context, "metrics", "clean-02-run-01-rpc-metrics", MetricsArtifact{
		SchemaVersion: 1,
		Kind:          "transport_metrics",
		Context:       context,
		Records:       []MetricCounterRecord{{Name: "rpc_operations", Value: 2000, Unit: "count"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	builder := resultBuilder{status: statusPass, artifactPaths: make(map[string]string), artifactRoot: root}
	data, ok := readArtifact(&builder, context, "metrics", artifact, directory)
	if !ok || builder.status != statusPass {
		t.Fatalf("read bound artifact = %v, status = %s, issues = %v", ok, builder.status, builder.issues)
	}
	if err := validateTypedStructuredArtifact(context, "metrics", data); err != nil {
		t.Fatalf("validate typed artifact: %v", err)
	}
	for _, path := range []string{artifact.Path, artifact.MetaPath} {
		info, err := os.Stat(filepath.Join(directory, path))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 600", path, info.Mode().Perm())
		}
	}
}

func TestTypedArtifactWriterRejectsDigestReuseAcrossClaims(t *testing.T) {
	writer, err := newTypedArtifactWriter(canonicalTestDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	data := []byte(`{"schema_version":1}`)
	if _, err := writer.Write("claim one", "config", "first", ".json", data); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write("claim two", "config", "second", ".json", data); err == nil || !strings.Contains(err.Error(), "already claimed by claim one config") {
		t.Fatalf("digest reuse error = %v", err)
	}
}

func TestAssembleRawCleanDirectFragmentConvertsMeasuredFields(t *testing.T) {
	report := validRawBaselineReport(t, "websocket")
	reportPath := writeRawBaselineReport(t, report)
	directory := canonicalTestDirectory(t)
	writer, err := newTypedArtifactWriter(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })

	fragment, err := assembleRawCleanDirectFragment(reportPath, "clean-02", 1, writer)
	if err != nil {
		t.Fatal(err)
	}
	if fragment.CellID != "clean-02" || fragment.Run.RunNumber != 1 || len(fragment.Run.Phases) != 4 {
		t.Fatalf("unexpected fragment identity: %+v", fragment)
	}
	if len(fragment.Gaps) != 0 {
		t.Fatalf("complete raw producer gaps = %+v, want none", fragment.Gaps)
	}
	if len(fragment.Run.RawSources) != 1 || fragment.Run.RawSources[0].ID != "pcap-001" || fragment.Run.RawSources[0].Kind != "pcap" {
		t.Fatalf("raw source inventory = %+v, want one immutable pcap", fragment.Run.RawSources)
	}

	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	builder := resultBuilder{status: statusPass, artifactPaths: make(map[string]string), artifactRoot: root}
	seenPaths := make(map[string]struct{})
	seenDigests := make(map[string]struct{})
	for _, phase := range fragment.Run.Phases {
		context := "cell clean-02 run 1 phase " + phase.ProfileID + "/" + phase.Phase
		for kind, artifact := range phase.Artifacts {
			assertReadableTypedArtifact(t, &builder, directory, context, kind, artifact)
			assertUniqueArtifactClaim(t, seenPaths, seenDigests, artifact)
		}
	}
	assertReadableTypedArtifact(t, &builder, directory, "cell clean-02 run 1 resource", "resource", fragment.Run.Resource)
	assertUniqueArtifactClaim(t, seenPaths, seenDigests, fragment.Run.Resource)
	for _, source := range fragment.Run.RawSources {
		assertReadableTypedArtifact(t, &builder, directory, "cell clean-02 run 1 raw sources", "raw_"+source.Kind, source.Artifact)
		assertUniqueArtifactClaim(t, seenPaths, seenDigests, source.Artifact)
	}
	if builder.status != statusPass {
		t.Fatalf("artifact status = %s, issues = %v", builder.status, builder.issues)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 44 {
		t.Fatalf("artifact directory contains %d entries, want 22 artifacts and sidecars", len(entries))
	}
}

func TestAssembleRawCleanDirectFragmentRejectsScheduleMutation(t *testing.T) {
	report := validRawBaselineReport(t, "websocket")
	mutationIndex := len(report.Results[0].Cold) / 2
	report.Results[0].Cold[mutationIndex].ScheduledAt = report.Results[0].Cold[mutationIndex].ScheduledAt.Add(time.Nanosecond)
	reportPath := writeRawBaselineReport(t, report)
	directory := canonicalTestDirectory(t)
	writer, err := newTypedArtifactWriter(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	if _, err := assembleRawCleanDirectFragment(reportPath, "clean-02", 1, writer); err == nil || !strings.Contains(err.Error(), "frozen schedule") {
		t.Fatalf("schedule mutation error = %v", err)
	}
	assertDirectoryEmpty(t, directory)
}

func TestAssembleRawCleanDirectFragmentCorrelatesQUICPhases(t *testing.T) {
	report := validRawBaselineReport(t, "raw_quic")
	directory := canonicalTestDirectory(t)
	writer, err := newTypedArtifactWriter(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	fragment, err := assembleRawCleanDirectFragment(writeRawBaselineReport(t, report), "clean-03", 1, writer)
	if err != nil {
		t.Fatal(err)
	}
	if len(fragment.Gaps) != 0 {
		t.Fatalf("raw QUIC gaps = %+v, want none", fragment.Gaps)
	}
	for _, phase := range fragment.Run.Phases {
		if _, ok := phase.Artifacts["qlog_attribution"]; !ok {
			t.Fatalf("phase %s has no qlog attribution", phase.Phase)
		}
	}
	if len(fragment.Run.RawSources) != 2 || fragment.Run.RawSources[0].Kind != "pcap" || fragment.Run.RawSources[1].Kind != "qlog" {
		t.Fatalf("raw QUIC source inventory = %+v", fragment.Run.RawSources)
	}
}

func TestAssembleRawCleanDirectFragmentRejectsMissingProducerData(t *testing.T) {
	t.Run("run", func(t *testing.T) {
		report := validRawBaselineReport(t, "websocket")
		report.Results = nil
		assertRawFragmentError(t, report, "has no websocket run 1")
	})
	t.Run("resource", func(t *testing.T) {
		report := validRawBaselineReport(t, "websocket")
		report.Results[0].Resource = rawResourceMeasurement{}
		assertRawFragmentError(t, report, "resource measurement is incomplete")
	})
}

func validRawBaselineReport(t *testing.T, carrier string) rawBaselineReport {
	t.Helper()
	profile := signedProfiles[0]
	if profile.id != "clean-v1" {
		t.Fatalf("first signed profile = %s, want clean-v1", profile.id)
	}
	contract, err := signedOperationContract("clean-v1", "cold")
	if err != nil {
		t.Fatal(err)
	}
	origin := time.Date(2026, time.July, 25, 1, 2, 3, 0, time.UTC)
	cold := make([]rawConnectOperation, profile.cold.Operations)
	candidate := map[string]string{"websocket": "direct-wss", "raw_quic": "direct-raw-quic"}[carrier]
	for index := range cold {
		scheduled := origin.Add(time.Duration(index) * time.Duration(contract.scheduledIntervalNS))
		cold[index] = rawConnectOperation{
			Ordinal: index + 1, ScheduledAt: scheduled, StartedAt: scheduled.Add(time.Millisecond),
			Duration: 2 * int64(time.Millisecond), CleanupDuration: int64(time.Millisecond),
			StartedCandidate: candidate, WinnerCandidate: candidate, CommitCount: 1, CredentialWrites: 1,
		}
	}
	rpcOrigin := origin.Add(1200 * time.Millisecond)
	rpcPayload := append(append([]byte{'"'}, make([]byte, 1022)...), '"')
	for index := 1; index < len(rpcPayload)-1; index++ {
		rpcPayload[index] = 'x'
	}
	rpcDigest := sha256.Sum256(rpcPayload)
	rpc := make([]rawRPCOperation, profile.rpc.Operations)
	for index := range rpc {
		scheduled := rpcOrigin.Add(time.Duration(index) * time.Millisecond)
		rpc[index] = rawRPCOperation{Ordinal: index + 1, ScheduledAt: scheduled, StartedAt: scheduled.Add(100 * time.Microsecond),
			Duration: int64(500 * time.Microsecond), InputBytes: 1024, OutputBytes: 1024, PayloadSHA256: rpcDigest}
	}
	warmupBytes := int64(profile.bulk.WarmupBytesPerDirection)
	scoreBytes := int64(profile.bulk.ScoreBytesPerDirection)
	scoreOrigin := origin.Add(1650 * time.Millisecond)
	bulkDirections := make([]rawBulkDirection, 2)
	for index, direction := range []struct {
		name string
		fill byte
	}{{"client-to-server", 0xa5}, {"server-to-client", 0x5a}} {
		bulkDirections[index] = rawBulkDirection{
			Direction: direction.name,
			Warmup: rawBulkPhaseDirection{Direction: direction.name, ScheduledAt: origin.Add(1500*time.Millisecond + time.Duration(index)*time.Millisecond),
				StartedAt: origin.Add(1500*time.Millisecond + time.Duration(index)*time.Millisecond), Duration: int64(20 * time.Millisecond), Bytes: warmupBytes, PayloadSHA256: repeatedByteSHA256(direction.fill, warmupBytes)},
			Score: rawBulkPhaseDirection{Direction: direction.name, ScheduledAt: scoreOrigin.Add(time.Duration(index) * time.Millisecond),
				StartedAt: scoreOrigin.Add(time.Duration(index) * time.Millisecond), Duration: int64(100 * time.Millisecond), Bytes: scoreBytes, PayloadSHA256: repeatedByteSHA256(direction.fill, scoreBytes)},
		}
	}
	resourceStart := origin.Add(-time.Second)
	resourceFinish := origin.Add(2 * time.Second)
	kernelPackets := uint64(10)
	phaseMeasurement := func(phase string, start, finish time.Time, active int) rawPhaseMeasurement {
		startKernel := &rawKernelEvidence{Client: rawKernelFaultStats{Packets: kernelPackets, Bytes: kernelPackets * 100, DeliveredPackets: kernelPackets}, Server: rawKernelFaultStats{Packets: kernelPackets, Bytes: kernelPackets * 100, DeliveredPackets: kernelPackets}}
		kernelPackets += 10
		finishKernel := &rawKernelEvidence{Client: rawKernelFaultStats{Packets: kernelPackets, Bytes: kernelPackets * 100, DeliveredPackets: kernelPackets}, Server: rawKernelFaultStats{Packets: kernelPackets, Bytes: kernelPackets * 100, DeliveredPackets: kernelPackets}}
		return rawPhaseMeasurement{Phase: phase, ActiveStreams: active, KernelStart: startKernel, KernelFinish: finishKernel, Resource: rawResourceMeasurement{
			StartedAt: start, FinishedAt: finish, CPUNanoseconds: 100, AllocatedBytes: 200,
			Start:  rawResourceSnapshot{At: start, RSSBytes: 4096, CPUNanoseconds: 100, AllocatedBytes: 1000, OpenFDs: 8, Goroutines: 3, Tasks: 3},
			Finish: rawResourceSnapshot{At: finish, RSSBytes: 8192, CPUNanoseconds: 200, AllocatedBytes: 1200, OpenFDs: 9, Goroutines: 4, Tasks: 4},
		}}
	}
	return rawBaselineReport{
		SchemaVersion: 1, Classification: "linux_transport_workload_baseline",
		SourceSHA: strings.Repeat("a", 40), ManifestDigest: "transport-v2-performance-r2",
		ManifestSHA256: strings.Repeat("b", 64), BPFObjectSHA256: strings.Repeat("d", 64),
		Runner:    rawBaselineRunner{OS: "linux", Architecture: "amd64", KernelRelease: "6.8.0-1031-azure"},
		StartedAt: resourceStart.Add(-time.Second), FinishedAt: resourceFinish.Add(time.Second),
		Results: []rawBaselineCarrierResult{{
			Run: 1, Carrier: carrier, Cold: cold, RPC: rpc,
			Bulk: rawBulkResult{StartedAt: scoreOrigin, Duration: int64(100 * time.Millisecond), BytesPerDirection: scoreBytes,
				ActiveStreams: 2, Directions: bulkDirections},
			CleanupDuration: 10 * int64(time.Millisecond),
			Resource: rawResourceMeasurement{
				StartedAt: resourceStart, FinishedAt: resourceFinish, CPUNanoseconds: 200, AllocatedBytes: 500,
				Start:  rawResourceSnapshot{At: resourceStart, RSSBytes: 4096, CPUNanoseconds: 100, AllocatedBytes: 1000, OpenFDs: 8, Goroutines: 3, Tasks: 3},
				Finish: rawResourceSnapshot{At: resourceFinish, RSSBytes: 8192, CPUNanoseconds: 300, AllocatedBytes: 1500, OpenFDs: 9, Goroutines: 4, Tasks: 4},
			},
			Phases: []rawPhaseMeasurement{
				phaseMeasurement("cold", origin.Add(-100*time.Millisecond), origin.Add(1100*time.Millisecond), 0),
				phaseMeasurement("rpc", rpcOrigin, origin.Add(1400*time.Millisecond), 0),
				phaseMeasurement("bulk", origin.Add(1500*time.Millisecond), origin.Add(1800*time.Millisecond), 2),
				phaseMeasurement("cleanup", origin.Add(1850*time.Millisecond), origin.Add(1900*time.Millisecond), 0),
			},
		}},
	}
}

func writeRawBaselineReport(t *testing.T, report rawBaselineReport) string {
	t.Helper()
	directory := t.TempDir()
	if len(report.Results) != 0 {
		result := &report.Results[0]
		pcap := encodeRawTestPCAP(result.Phases)
		if err := os.WriteFile(filepath.Join(directory, "raw.pcap"), pcap, 0o600); err != nil {
			t.Fatal(err)
		}
		pcapDigest := sha256.Sum256(pcap)
		result.Artifacts = append(result.Artifacts, rawReleaseArtifact{Kind: "classic-pcap", Path: "raw.pcap", SHA256: fmt.Sprintf("%x", pcapDigest), SizeBytes: int64(len(pcap))})
		if result.Carrier == "raw_quic" {
			qlog := encodeRawTestQLOG(report.StartedAt, result.Phases)
			if err := os.WriteFile(filepath.Join(directory, "raw.sqlog"), qlog, 0o600); err != nil {
				t.Fatal(err)
			}
			qlogDigest := sha256.Sum256(qlog)
			result.Artifacts = append(result.Artifacts, rawReleaseArtifact{Kind: "qlog-json-seq", Path: "raw.sqlog", SHA256: fmt.Sprintf("%x", qlogDigest), SizeBytes: int64(len(qlog))})
		}
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "baseline.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func encodeRawTestPCAP(phases []rawPhaseMeasurement) []byte {
	buffer := &bytes.Buffer{}
	_ = binary.Write(buffer, binary.LittleEndian, uint32(0xa1b2c3d4))
	_ = binary.Write(buffer, binary.LittleEndian, uint16(2))
	_ = binary.Write(buffer, binary.LittleEndian, uint16(4))
	_ = binary.Write(buffer, binary.LittleEndian, int32(0))
	_ = binary.Write(buffer, binary.LittleEndian, uint32(0))
	_ = binary.Write(buffer, binary.LittleEndian, uint32(65535))
	_ = binary.Write(buffer, binary.LittleEndian, uint32(1))
	for index, phase := range phases {
		at := phase.Resource.StartedAt.Add(phase.Resource.FinishedAt.Sub(phase.Resource.StartedAt) / 2)
		packet := rawTestTCPPacket(uint32(1000+index*32), byte(index+1))
		_ = binary.Write(buffer, binary.LittleEndian, uint32(at.Unix()))
		_ = binary.Write(buffer, binary.LittleEndian, uint32(at.Nanosecond()/1000))
		_ = binary.Write(buffer, binary.LittleEndian, uint32(len(packet)))
		_ = binary.Write(buffer, binary.LittleEndian, uint32(len(packet)))
		_, _ = buffer.Write(packet)
	}
	return buffer.Bytes()
}

func rawTestTCPPacket(sequence uint32, payload byte) []byte {
	packet := make([]byte, 14+20+20+1)
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	packet[14], packet[23] = 0x45, 6
	binary.BigEndian.PutUint16(packet[16:18], uint16(len(packet)-14))
	copy(packet[26:30], []byte{10, 0, 0, 1})
	copy(packet[30:34], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[34:36], 8443)
	binary.BigEndian.PutUint16(packet[36:38], 9443)
	binary.BigEndian.PutUint32(packet[38:42], sequence)
	packet[46], packet[len(packet)-1] = 5<<4, payload
	return packet
}

func encodeRawTestQLOG(reference time.Time, phases []rawPhaseMeasurement) []byte {
	buffer := &bytes.Buffer{}
	header := map[string]any{
		"file_schema": "urn:ietf:params:qlog:file:sequential", "serialization_format": "application/qlog+json-seq",
		"qlog_version": "0.3", "qlog_format": "JSON-SEQ", "code_version": "v0.60.0",
		"trace": map[string]any{"common_fields": map[string]any{"group_id": "fixture", "reference_time": map[string]any{
			"clock_type": "monotonic", "epoch": "unknown", "wall_clock_time": reference.Format(time.RFC3339Nano),
		}}},
	}
	writeSequence := func(value any) {
		buffer.WriteByte(0x1e)
		encoded, _ := json.Marshal(value)
		buffer.Write(encoded)
		buffer.WriteByte('\n')
	}
	writeSequence(header)
	for index, phase := range phases {
		at := phase.Resource.StartedAt.Add(phase.Resource.FinishedAt.Sub(phase.Resource.StartedAt) / 2)
		writeSequence(map[string]any{"time": float64(at.Sub(reference).Nanoseconds()) / 1e6, "name": "recovery:metrics_updated", "data": map[string]any{"smoothed_rtt": index + 1, "bytes_in_flight": 1}})
	}
	return buffer.Bytes()
}

func TestSplitQLOGCountsOnlyRepeatedStreamRangesWithinTraceIdentity(t *testing.T) {
	reference := time.Date(2026, 7, 20, 1, 2, 3, 0, time.UTC)
	phases := []rawPhaseMeasurement{{Phase: "bulk", Resource: rawResourceMeasurement{StartedAt: reference, FinishedAt: reference.Add(10 * time.Second)}}}
	header := func(packetType string, packetNumber int) map[string]any {
		return map[string]any{"packet_type": packetType, "packet_number": packetNumber}
	}
	stream := func(streamID, offset, length int) []any {
		return []any{map[string]any{"frame_type": "stream", "stream_id": streamID, "offset": offset, "length": length}}
	}
	source := encodeRawQLOGSequence(reference, "connection-a", nil, []map[string]any{
		{"time": 100.0, "name": "transport:packet_sent", "data": map[string]any{"header": header("1RTT", 1), "frames": stream(4, 0, 100)}},
		{"time": 150.0, "name": "recovery:packet_lost", "data": map[string]any{"header": header("1RTT", 1)}},
		{"time": 200.0, "name": "transport:packet_sent", "data": map[string]any{"header": header("1RTT", 2), "frames": stream(4, 50, 100)}},
		{"time": 250.0, "name": "transport:packet_sent", "data": map[string]any{"header": header("Initial", 2), "frames": []any{map[string]any{"frame_type": "ack"}}}},
	})
	otherConnection := encodeRawQLOGSequence(reference, "connection-b", nil, []map[string]any{
		{"time": 300.0, "name": "transport:packet_sent", "data": map[string]any{"header": header("1RTT", 1), "frames": stream(4, 0, 100)}},
	})
	output, retransmitted, err := splitQLOGByPhase([][]byte{source, otherConnection}, phases)
	if err != nil {
		t.Fatal(err)
	}
	if retransmitted != 50 {
		t.Fatalf("retransmitted bytes = %d, want repeated STREAM overlap 50", retransmitted)
	}
	if len(output["bulk"].Records) == 0 {
		t.Fatal("bulk qlog was not phase-attributed")
	}
}

func TestSplitQLOGRejectsPacketIdentityCollisionsAndOrphanLoss(t *testing.T) {
	reference := time.Date(2026, 7, 20, 1, 2, 3, 0, time.UTC)
	phases := []rawPhaseMeasurement{{Phase: "bulk", Resource: rawResourceMeasurement{StartedAt: reference, FinishedAt: reference.Add(10 * time.Second)}}}
	header := map[string]any{"packet_type": "1RTT", "packet_number": 7}
	tests := []struct {
		name   string
		events []map[string]any
	}{
		{name: "duplicate sent", events: []map[string]any{
			{"time": 1.0, "name": "transport:packet_sent", "data": map[string]any{"header": header}},
			{"time": 2.0, "name": "transport:packet_sent", "data": map[string]any{"header": header}},
		}},
		{name: "duplicate lost", events: []map[string]any{
			{"time": 1.0, "name": "transport:packet_sent", "data": map[string]any{"header": header}},
			{"time": 2.0, "name": "recovery:packet_lost", "data": map[string]any{"header": header}},
			{"time": 3.0, "name": "recovery:packet_lost", "data": map[string]any{"header": header}},
		}},
		{name: "orphan lost", events: []map[string]any{
			{"time": 1.0, "name": "recovery:packet_lost", "data": map[string]any{"header": header}},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := encodeRawQLOGSequence(reference, "connection-a", nil, test.events)
			if _, _, err := splitQLOGByPhase([][]byte{source}, phases); err == nil {
				t.Fatal("accepted ambiguous packet correlation")
			}
		})
	}
}

func TestParseQLOGSequenceRejectsHeaderOrTimeUnitDrift(t *testing.T) {
	reference := time.Date(2026, 7, 20, 1, 2, 3, 0, time.UTC)
	events := []map[string]any{{"time": 1.0, "name": "recovery:metrics_updated", "data": map[string]any{"smoothed_rtt": 1}}}
	tests := []struct {
		name     string
		override map[string]any
		groupID  string
	}{
		{name: "producer version drift", override: map[string]any{"code_version": "v0.61.0"}, groupID: "connection-a"},
		{name: "format drift", override: map[string]any{"qlog_format": "JSON"}, groupID: "connection-a"},
		{name: "clock drift", override: map[string]any{"clock_type": "wall"}, groupID: "connection-a"},
		{name: "missing connection identity", groupID: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseQLOGSequence(encodeRawQLOGSequence(reference, test.groupID, test.override, events)); err == nil {
				t.Fatal("accepted qlog header whose millisecond time contract is not frozen")
			}
		})
	}
}

func encodeRawQLOGSequence(reference time.Time, groupID string, override map[string]any, events []map[string]any) []byte {
	header := map[string]any{
		"file_schema": "urn:ietf:params:qlog:file:sequential", "serialization_format": "application/qlog+json-seq",
		"qlog_version": "0.3", "qlog_format": "JSON-SEQ", "code_version": "v0.60.0",
	}
	clockType := "monotonic"
	for key, value := range override {
		if key == "clock_type" {
			clockType = fmt.Sprint(value)
		} else {
			header[key] = value
		}
	}
	header["trace"] = map[string]any{"common_fields": map[string]any{"group_id": groupID, "reference_time": map[string]any{
		"clock_type": clockType, "epoch": "unknown", "wall_clock_time": reference.Format(time.RFC3339Nano),
	}}}
	buffer := &bytes.Buffer{}
	for _, record := range append([]map[string]any{header}, events...) {
		buffer.WriteByte(0x1e)
		encoded, _ := json.Marshal(record)
		buffer.Write(encoded)
		buffer.WriteByte('\n')
	}
	return buffer.Bytes()
}

func assertReadableTypedArtifact(t *testing.T, builder *resultBuilder, directory, context, kind string, artifact EvidenceArtifact) {
	t.Helper()
	data, ok := readArtifact(builder, context, kind, artifact, directory)
	if !ok {
		t.Fatalf("read %s artifact: %v", kind, builder.issues)
	}
	if kind == "pcap" || kind == "raw_pcap" {
		if !validPCAP(data) {
			t.Fatal("raw pcap source is invalid")
		}
		return
	}
	if kind == "qlog" || kind == "raw_qlog" {
		if err := validateQlogEvidence(context, data); err != nil {
			t.Fatalf("validate qlog artifact: %v", err)
		}
		return
	}
	if err := validateTypedStructuredArtifact(context, kind, data); err != nil {
		t.Fatalf("validate %s artifact: %v", kind, err)
	}
}

func assertUniqueArtifactClaim(t *testing.T, paths, digests map[string]struct{}, artifact EvidenceArtifact) {
	t.Helper()
	for _, path := range []string{artifact.Path, artifact.MetaPath} {
		if _, exists := paths[path]; exists {
			t.Fatalf("reused artifact path %q", path)
		}
		paths[path] = struct{}{}
	}
	for _, digest := range []string{artifact.SHA256, artifact.MetaSHA256} {
		if _, exists := digests[digest]; exists {
			t.Fatalf("reused artifact digest %q", digest)
		}
		digests[digest] = struct{}{}
	}
}

func assertRawFragmentError(t *testing.T, report rawBaselineReport, want string) {
	t.Helper()
	directory := canonicalTestDirectory(t)
	writer, err := newTypedArtifactWriter(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	_, err = assembleRawCleanDirectFragment(writeRawBaselineReport(t, report), "clean-02", 1, writer)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("fragment error = %v, want %q", err, want)
	}
	assertDirectoryEmpty(t, directory)
}

func assertDirectoryEmpty(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("directory contains %d partial artifacts", len(entries))
	}
}

func canonicalTestDirectory(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}
