package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSystemCaseTypedAttributionResolvesImmutableRawSources(t *testing.T) {
	for _, kind := range []string{"pcap", "qlog"} {
		t.Run(kind, func(t *testing.T) {
			builder, evidence, attribution, directory := systemAttributionFixture(t, kind)
			data, err := json.Marshal(attribution)
			if err != nil {
				t.Fatal(err)
			}
			sources, err := loadCaseAttributedRawSources(builder, "case SYS-MIGRATION-REBIND", evidence, kind, data, directory)
			if err != nil {
				t.Fatal(err)
			}
			if len(sources) != 1 || sources[0].id != kind+"-001" || len(sources[0].data) == 0 || builder.status != statusPass {
				t.Fatalf("resolved %s sources = %+v, status=%s issues=%v", kind, sources, builder.status, builder.issues)
			}
		})
	}
}

func TestSystemCaseTypedAttributionRejectsTamperedBindings(t *testing.T) {
	tests := []struct {
		name      string
		kind      string
		wantIssue string
		mutate    func(*PacketAttributionRecord)
	}{
		{name: "wrong source", kind: "qlog", wantIssue: "does not bind an indexed raw source", mutate: func(record *PacketAttributionRecord) { record.SourceID = "qlog-999" }},
		{name: "wrong digest", kind: "qlog", wantIssue: "does not bind an indexed raw source", mutate: func(record *PacketAttributionRecord) { record.SourceSHA256 = strings.Repeat("0", 64) }},
		{name: "wrong range", kind: "qlog", wantIssue: "range is not an exact source event record", mutate: func(record *PacketAttributionRecord) { record.ByteOffset++ }},
		{name: "wrong timestamp", kind: "qlog", wantIssue: "time, event, or connection identity", mutate: func(record *PacketAttributionRecord) { record.UnixNanoseconds++ }},
		{name: "wrong connection", kind: "qlog", wantIssue: "time, event, or connection identity", mutate: func(record *PacketAttributionRecord) { record.ConnectionGroupID = "fedcba9876543210" }},
		{name: "wrong packet number", kind: "qlog", wantIssue: "packet number or PN space", mutate: func(record *PacketAttributionRecord) { *record.PacketNumber++ }},
		{name: "pcap wrong range", kind: "pcap", wantIssue: "exact source record", mutate: func(record *PacketAttributionRecord) { record.ByteLength++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			builder, evidence, attribution, directory := systemAttributionFixture(t, test.kind)
			test.mutate(&attribution.Records[0])
			data, err := json.Marshal(attribution)
			if err != nil {
				t.Fatal(err)
			}
			_, err = loadCaseAttributedRawSources(builder, "case SYS-MIGRATION-REBIND", evidence, test.kind, data, directory)
			if err == nil || !strings.Contains(err.Error(), test.wantIssue) {
				t.Fatalf("tampered attribution error = %v, want %q", err, test.wantIssue)
			}
		})
	}
}

func systemAttributionFixture(t *testing.T, kind string) (*resultBuilder, CaseEvidence, PacketAttributionArtifact, string) {
	t.Helper()
	directory := canonicalTestDirectory(t)
	writer, err := newTypedArtifactWriter(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	builder := &resultBuilder{status: statusPass, artifactPaths: make(map[string]string), artifactRoot: root}
	context := "case SYS-MIGRATION-REBIND"
	evidence := CaseEvidence{ID: "SYS-MIGRATION-REBIND"}

	if kind == "pcap" {
		raw := encodeClassicPCAP([][]byte{syntheticIPPacket(t, 4, 17, 96, 1)})
		artifact, err := writer.Write(context+" raw pcap-001", "raw_pcap", "system-pcap-001", ".pcap", raw)
		if err != nil {
			t.Fatal(err)
		}
		evidence.RawSources = []RawEvidenceSource{{ID: "pcap-001", Kind: "pcap", Artifact: artifact}}
		return builder, evidence, PacketAttributionArtifact{
			SchemaVersion: 1, Kind: "transport_pcap_attribution", Context: context,
			Records: []PacketAttributionRecord{{Sequence: 1, SourceID: "pcap-001", SourceSHA256: artifact.SHA256,
				ByteOffset: 24, ByteLength: 112, UnixNanoseconds: time.Unix(1, 0).UnixNano()}},
		}, directory
	}

	groupID := "8394c8f03e515708"
	reference := time.Date(2026, 7, 25, 4, 0, 0, 0, time.UTC)
	raw := encodeRawQLOGSequence(reference, groupID, nil, []map[string]any{fixtureRawQLOGPacketEvent(1, 7, nil)})
	artifact, err := writer.Write(context+" raw qlog-001", "raw_qlog", "system-qlog-001", ".qlog", raw)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseQLOGSequenceSource(raw, "qlog-001")
	if err != nil || len(parsed) != 1 {
		t.Fatalf("parse raw qlog = %v/%d", err, len(parsed))
	}
	packetNumber := uint64(7)
	evidence.RawSources = []RawEvidenceSource{{ID: "qlog-001", Kind: "qlog", Artifact: artifact}}
	return builder, evidence, PacketAttributionArtifact{
		SchemaVersion: 1, Kind: "transport_qlog_attribution", Context: context,
		Records: []PacketAttributionRecord{{Sequence: 1, SourceID: "qlog-001", SourceSHA256: artifact.SHA256,
			ByteOffset: parsed[0].recordOffset, ByteLength: parsed[0].recordLength, UnixNanoseconds: parsed[0].at.UnixNano(),
			Event: parsed[0].name, ConnectionGroupID: groupID, PacketNumberSpace: "1RTT", PacketNumber: &packetNumber}},
	}, directory
}
