package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestRawNativeQLOGAndApplicationTraceAreSeparatedAndCorrelated(t *testing.T) {
	qlog := rawNativeQLOGFixture(t, []map[string]any{
		{"frame_type": "stream", "stream_id": 0, "offset": 0, "length": 16384},
		{"frame_type": "stream_data_blocked", "stream_id": 0, "limit": 16384},
		{"frame_type": "stream", "stream_id": 4, "offset": 0, "length": 11},
	})
	if err := validateQlogEvidence("case NS-N2", qlog); err != nil {
		t.Fatal(err)
	}
	summary, err := parseRawNativeQLOGEvidence(qlog)
	if err != nil {
		t.Fatal(err)
	}
	blocked, sibling := int64(0), int64(4)
	trace := TraceArtifact{SchemaVersion: 1, Kind: "transport_trace", Context: "case NS-N2", Records: []TraceRecord{
		{Sequence: 1, AtNS: 1, Event: "native_stream_blocked", Digest: caseExecutionID("case NS-N2"), ConnectionID: summary.connectionID, NativeStreamID: &blocked},
		{Sequence: 2, AtNS: 2, Event: "rpc_completed", Digest: caseExecutionID("case NS-N2"), ConnectionID: summary.connectionID, NativeStreamID: &sibling, RequestID: "sibling", Status: "ok"},
		{Sequence: 3, AtNS: 3, Event: "completed", Digest: caseExecutionID("case NS-N2"), ConnectionID: summary.connectionID},
	}}
	if err := validateNativeApplicationTrace("NS-N2", trace, caseExecutionID("case NS-N2"), summary); err != nil {
		t.Fatal(err)
	}
	missing := int64(8)
	trace.Records[1].NativeStreamID = &missing
	if err := validateNativeApplicationTrace("NS-N2", trace, caseExecutionID("case NS-N2"), summary); err == nil {
		t.Fatal("application stream absent from raw qlog was accepted")
	}
}

func TestRawNativeQLOGRejectsApplicationEvents(t *testing.T) {
	qlog := rawNativeQLOGFixture(t, []map[string]any{{"frame_type": "stream", "stream_id": 0, "offset": 0, "length": 1}})
	application, err := json.Marshal(map[string]any{
		"time": 2, "name": "application:rpc_completed", "data": map[string]any{"request_id": "forbidden"},
	})
	if err != nil {
		t.Fatal(err)
	}
	qlog = append(qlog, 0x1e)
	qlog = append(qlog, application...)
	qlog = append(qlog, '\n')
	if err := validateQlogEvidence("case NS-N1", qlog); err == nil {
		t.Fatal("application event in raw transport qlog was accepted")
	}
}

func rawNativeQLOGFixture(t *testing.T, frames []map[string]any) []byte {
	t.Helper()
	header := map[string]any{
		"file_schema": "urn:ietf:params:qlog:file:sequential", "serialization_format": "application/qlog+json-seq",
		"qlog_version": "0.3", "qlog_format": "JSON-SEQ", "code_version": "test",
		"trace": map[string]any{"common_fields": map[string]any{"group_id": "0123456789abcdef"}},
	}
	event := map[string]any{"time": 1, "name": "transport:packet_sent", "data": map[string]any{
		"header": map[string]any{"packet_type": "1RTT", "packet_number": 1}, "frames": frames,
	}}
	var output bytes.Buffer
	for _, value := range []any{header, event} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		output.WriteByte(0x1e)
		output.Write(data)
		output.WriteByte('\n')
	}
	return output.Bytes()
}
