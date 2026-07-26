package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCapacityQLOGDrainWaitsForCompleteJSONSequence(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "connection_client.sqlog")
	header := `{"trace":{"common_fields":{"group_id":"connection-a","reference_time":{"wall_clock_time":"2026-07-25T03:00:00Z"}}}}`
	event := `{"time":1,"name":"transport:packet_sent","data":{"frames":[]}}`
	if err := os.WriteFile(path, []byte("\x1e"+header+"\n\x1e"), 0o600); err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 1)
	go func() {
		time.Sleep(3 * capacityQLOGDrainPollInterval)
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err == nil {
			_, err = file.WriteString(event + "\n")
		}
		if file != nil {
			err = errors.Join(err, file.Close())
		}
		completed <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitForCapacityQLOGDrain(ctx, directory); err != nil {
		t.Fatal(err)
	}
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
}

func TestCapacityQLOGFilesReadyRejectsTruncatedRecord(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "connection_server.sqlog")
	if err := os.WriteFile(path, []byte("\x1e{}\n\x1e{\"time\":"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ready, err := capacityQLOGFilesReady(directory); ready || err == nil {
		t.Fatalf("truncated qlog ready=%t err=%v", ready, err)
	}
}

func TestCapacityQLOGAttributionBindsExactRawSourceRecord(t *testing.T) {
	reference := time.Date(2026, 7, 25, 3, 0, 0, 0, time.UTC)
	header := fmt.Sprintf(`{"file_schema":"urn:ietf:params:qlog:file:sequential","serialization_format":"application/qlog+json-seq","qlog_version":"0.3","qlog_format":"JSON-SEQ","code_version":"v0.60.0","trace":{"common_fields":{"group_id":"connection-a","reference_time":{"clock_type":"monotonic","epoch":"unknown","wall_clock_time":%q}}}}`, reference.Format(time.RFC3339Nano))
	event := `{"time":1.5,"name":"transport:packet_sent","data":{"header":{"packet_number":7,"packet_type":"1RTT"},"frames":[]}}`
	data := []byte("\x1e" + header + "\n\x1e" + event + "\n")
	digest := sha256.Sum256(data)
	source := releaseRawSource{ID: "qlog-001", Kind: "qlog", SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(data))}
	record, err := firstCapacityQLOGAttribution(data, source)
	if err != nil {
		t.Fatal(err)
	}
	if record.SourceID != source.ID || record.SourceSHA256 != source.SHA256 || record.ByteOffset != int64(len(header)+2) ||
		record.ByteLength != int64(len(event)+2) || record.UnixNanoseconds != reference.Add(1500*time.Microsecond).UnixNano() ||
		record.Event != "transport:packet_sent" || record.ConnectionGroupID != "connection-a" || record.PacketNumber == nil ||
		*record.PacketNumber != 7 || record.PacketNumberSpace != "1RTT" {
		t.Fatalf("qlog attribution = %+v", record)
	}
}

func TestBrowserStreamCapacityQLOGAttributionBindsFirstApplicationBidiFrame(t *testing.T) {
	reference := time.Date(2026, 7, 25, 3, 0, 0, 0, time.UTC)
	header := map[string]any{
		"file_schema": "urn:ietf:params:qlog:file:sequential", "serialization_format": "application/qlog+json-seq",
		"qlog_version": "0.3", "qlog_format": "JSON-SEQ", "code_version": "v0.60.0",
		"trace": map[string]any{"common_fields": map[string]any{
			"group_id": "connection-a", "reference_time": map[string]any{"wall_clock_time": reference.Format(time.RFC3339Nano)},
		}},
	}
	events := []any{
		map[string]any{"time": 1.0, "name": "transport:packet_received", "data": map[string]any{
			"header": map[string]any{"packet_number": 7, "packet_type": "1RTT"},
			"frames": []any{
				map[string]any{"frame_type": "stream", "stream_id": 0},
				map[string]any{"frame_type": "stream", "stream_id": 12},
				map[string]any{"frame_type": "stream", "stream_id": 12},
			},
		}},
		map[string]any{"time": 2.0, "name": "transport:packet_received", "data": map[string]any{
			"header": map[string]any{"packet_number": 8, "packet_type": "1RTT"},
			"frames": []any{map[string]any{"frame_type": "stream", "stream_id": 16}},
		}},
	}
	var raw bytes.Buffer
	for _, value := range append([]any{header}, events...) {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		raw.WriteByte(0x1e)
		raw.Write(data)
		raw.WriteByte('\n')
	}
	digest := sha256.Sum256(raw.Bytes())
	source := releaseRawSource{ID: "qlog-001", Kind: "qlog", SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(raw.Len())}
	records, err := browserStreamCapacityQLOGAttributions(raw.Bytes(), source)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].NativeStreamID == nil || *records[0].NativeStreamID != 12 || records[1].NativeStreamID == nil || *records[1].NativeStreamID != 16 ||
		records[0].Event != "transport:stream_opened" || records[0].ConnectionGroupID != "connection-a" || records[0].PacketNumber == nil || *records[0].PacketNumber != 7 {
		t.Fatalf("stream attributions = %+v", records)
	}
}

func TestBrowserStreamCapacityQLOGAttributionBindsNonStreamSource(t *testing.T) {
	reference := time.Date(2026, 7, 25, 3, 0, 0, 0, time.UTC)
	header := fmt.Sprintf(`{"trace":{"common_fields":{"group_id":"connection-control","reference_time":{"wall_clock_time":%q}}}}`, reference.Format(time.RFC3339Nano))
	event := `{"time":1,"name":"transport:packet_sent","data":{"header":{"packet_number":9,"packet_type":"1RTT"},"frames":[]}}`
	data := []byte("\x1e" + header + "\n\x1e" + event + "\n")
	digest := sha256.Sum256(data)
	source := releaseRawSource{ID: "qlog-210", Kind: "qlog", SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(data))}
	records, err := browserStreamCapacityQLOGAttributions(data, source)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].SourceID != source.ID || records[0].NativeStreamID != nil ||
		records[0].Event != "transport:packet_sent" || records[0].PacketNumber == nil || *records[0].PacketNumber != 9 {
		t.Fatalf("non-stream attribution = %+v", records)
	}
}

func TestValidateBrowserStreamCapacityAttributionsUsesConnectionScopedStreamIDs(t *testing.T) {
	records := make([]capacityAttributionRecord, 0, 100*128)
	for connection := range 100 {
		for stream := range 128 {
			streamID := uint64(12 + stream*4)
			records = append(records, capacityAttributionRecord{
				Event: "transport:stream_opened", ConnectionGroupID: fmt.Sprintf("connection-%03d", connection), NativeStreamID: &streamID,
			})
		}
	}
	if err := validateBrowserStreamCapacityAttributions(records); err != nil {
		t.Fatal(err)
	}
	records = append(records, capacityAttributionRecord{Event: "transport:packet_sent", ConnectionGroupID: "connection-control"})
	if err := validateBrowserStreamCapacityAttributions(records); err != nil {
		t.Fatalf("non-stream source binding was rejected: %v", err)
	}
	duplicate := *records[len(records)-2].NativeStreamID
	records[len(records)-2].NativeStreamID = &duplicate
	records[len(records)-2].ConnectionGroupID = records[0].ConnectionGroupID
	if err := validateBrowserStreamCapacityAttributions(records); err == nil {
		t.Fatal("duplicate connection-scoped stream identity was accepted")
	}
}
