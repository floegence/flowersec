package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestValidateCapacityStreamQLOGAttributionUsesConnectionScopedStreamIDs(t *testing.T) {
	artifact := PacketAttributionArtifact{SchemaVersion: 1, Kind: "transport_qlog_attribution", Context: "case CAP-STREAM-WT-DIRECT-100X128"}
	for connection := range 100 {
		for stream := range 128 {
			streamID := uint64(12 + stream*4)
			artifact.Records = append(artifact.Records, PacketAttributionRecord{
				Sequence: uint64(len(artifact.Records) + 1), UnixNanoseconds: int64(len(artifact.Records) + 1),
				Event: "transport:stream_opened", ConnectionGroupID: fmt.Sprintf("connection-%03d", connection), NativeStreamID: &streamID,
			})
		}
	}
	if err := validateCapacityStreamQLOGAttribution(artifact); err != nil {
		t.Fatal(err)
	}
	duplicate := *artifact.Records[len(artifact.Records)-1].NativeStreamID
	artifact.Records[len(artifact.Records)-1].ConnectionGroupID = artifact.Records[0].ConnectionGroupID
	artifact.Records[len(artifact.Records)-1].NativeStreamID = &duplicate
	if err := validateCapacityStreamQLOGAttribution(artifact); err == nil {
		t.Fatal("duplicate connection-scoped native stream ID was accepted")
	}
}

func TestValidateQlogEvidenceRestrictsTypedAttributionToFrozenCases(t *testing.T) {
	streamID := uint64(12)
	packetNumber := uint64(1)
	artifact := PacketAttributionArtifact{SchemaVersion: 1, Kind: "transport_qlog_attribution", Records: []PacketAttributionRecord{{
		Sequence: 1, SourceID: "qlog-001", SourceSHA256: strings.Repeat("a", 64), ByteOffset: 100, ByteLength: 200,
		UnixNanoseconds: 1, Event: "transport:stream_opened", ConnectionGroupID: "connection-001",
		PacketNumberSpace: "1RTT", PacketNumber: &packetNumber, NativeStreamID: &streamID,
	}}}
	for _, context := range []string{"case BN-N5", "case CAP-STREAM-WT-DIRECT-100X128", "case NS-N2"} {
		artifact.Context = context
		data, err := json.Marshal(artifact)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateQlogEvidence(context, data); err != nil {
			t.Fatalf("%s rejected typed attribution: %v", context, err)
		}
	}
	artifact.Context = "case CS-C1"
	data, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateQlogEvidence(artifact.Context, data); err == nil {
		t.Fatal("non-native legacy case accepted typed qlog attribution")
	}
}
