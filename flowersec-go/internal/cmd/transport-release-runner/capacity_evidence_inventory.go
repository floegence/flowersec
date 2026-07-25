package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/tunnelworkload"
)

type capacityAttributionArtifact struct {
	SchemaVersion int                         `json:"schema_version"`
	Kind          string                      `json:"kind"`
	Context       string                      `json:"context"`
	Records       []capacityAttributionRecord `json:"records"`
}

type capacityAttributionRecord struct {
	Sequence          uint64  `json:"sequence"`
	SourceID          string  `json:"source_id"`
	SourceSHA256      string  `json:"source_sha256"`
	ByteOffset        int64   `json:"byte_offset"`
	ByteLength        int64   `json:"byte_length"`
	UnixNanoseconds   int64   `json:"unix_nanoseconds"`
	Event             string  `json:"event,omitempty"`
	ConnectionGroupID string  `json:"connection_group_id,omitempty"`
	PacketNumberSpace string  `json:"packet_number_space,omitempty"`
	PacketNumber      *uint64 `json:"packet_number,omitempty"`
	NativeStreamID    *uint64 `json:"native_stream_id,omitempty"`
}

type capacityEvidenceInventory struct {
	Artifacts   []releaseArtifact
	RawSources  []releaseRawSource
	Attachments []releaseRawSource
}

const capacityQLOGDrainPollInterval = 10 * time.Millisecond

func waitForCapacityQLOGDrain(ctx context.Context, directory string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if !filepath.IsAbs(directory) {
		return errors.New("capacity qlog drain requires an absolute directory")
	}
	ticker := time.NewTicker(capacityQLOGDrainPollInterval)
	defer ticker.Stop()
	var lastErr error
	for {
		ready, err := capacityQLOGFilesReady(directory)
		if ready && err == nil {
			return nil
		}
		if err != nil {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("capacity qlog drain: %w", errors.Join(context.Cause(ctx), lastErr))
		case <-ticker.C:
		}
	}
}

func capacityQLOGFilesReady(directory string) (bool, error) {
	open, err := capacityQLOGDirectoryHasOpenFiles(directory)
	if err != nil || open {
		return false, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false, err
	}
	count := 0
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".sqlog" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return false, err
		}
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("capacity qlog %s is not a regular file", entry.Name())
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return false, err
		}
		records, err := capacityQLOGRecords(data)
		if err != nil {
			return false, fmt.Errorf("capacity qlog %s is incomplete: %w", entry.Name(), err)
		}
		for _, record := range records {
			if !json.Valid(record.payload) {
				return false, fmt.Errorf("capacity qlog %s contains an incomplete JSON record", entry.Name())
			}
		}
		count++
	}
	if count == 0 {
		return false, errors.New("capacity qlog directory contains no qlog files")
	}
	return true, nil
}

func capacityQLOGDirectoryHasOpenFiles(directory string) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, nil
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err != nil {
			continue
		}
		target = strings.TrimSuffix(target, " (deleted)")
		relative, err := filepath.Rel(directory, target)
		if err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && filepath.Ext(relative) == ".sqlog" {
			return true, nil
		}
	}
	return false, nil
}

func finalizeCapacityEvidence(destination *artifactDestination, directory string, definition capacityCaseDefinition, summarized []releaseArtifact) (capacityEvidenceInventory, error) {
	if destination == nil || !filepath.IsAbs(directory) {
		return capacityEvidenceInventory{}, errors.New("capacity evidence inventory requires a pinned destination and absolute case directory")
	}
	result := capacityEvidenceInventory{}
	rawCounts := make(map[string]int)
	attachmentCounts := make(map[string]int)
	for _, artifact := range summarized {
		switch artifact.Kind {
		case "trace", "metrics", "resource", "config":
			result.Artifacts = append(result.Artifacts, artifact)
		case "classic-pcap", "qlog-json-seq", "chromium-netlog":
			kind := map[string]string{"classic-pcap": "pcap", "qlog-json-seq": "qlog", "chromium-netlog": "netlog"}[artifact.Kind]
			rawCounts[kind]++
			result.RawSources = append(result.RawSources, releaseRawSource{
				ID: fmt.Sprintf("%s-%03d", kind, rawCounts[kind]), Kind: kind,
				Path: artifact.Path, SHA256: artifact.SHA256, SizeBytes: artifact.SizeBytes,
			})
		case "playwright-trace", "browser-controller-result", "browser-controller-config", "producer-resource", "browser-controller-stderr":
			attachmentCounts[artifact.Kind]++
			result.Attachments = append(result.Attachments, releaseRawSource{
				ID: fmt.Sprintf("%s-%03d", artifact.Kind, attachmentCounts[artifact.Kind]), Kind: artifact.Kind,
				Path: artifact.Path, SHA256: artifact.SHA256, SizeBytes: artifact.SizeBytes,
			})
		default:
			return capacityEvidenceInventory{}, fmt.Errorf("capacity evidence contains unsupported summarized kind %q", artifact.Kind)
		}
	}
	if len(result.Artifacts) != 4 || rawCounts["pcap"] != 1 {
		return capacityEvidenceInventory{}, errors.New("capacity evidence is missing its four core artifacts or exact packet capture")
	}
	if capacityRequiresQLOG(definition) {
		if rawCounts["qlog"] == 0 {
			return capacityEvidenceInventory{}, errors.New("capacity evidence requires indexed raw qlog sources")
		}
		attribution, err := capacityQLOGAttribution(destination, definition, result.RawSources)
		if err != nil {
			return capacityEvidenceInventory{}, err
		}
		written, err := writeRawCaseArtifact(destination, filepath.Join(directory, "qlog.json"), "qlog", attribution)
		if err != nil {
			return capacityEvidenceInventory{}, err
		}
		result.Artifacts = append(result.Artifacts, written)
	}
	return result, nil
}

func capacityRequiresQLOG(definition capacityCaseDefinition) bool {
	switch definition.Kind {
	case capacityDirect:
		return definition.Carrier == carrier.KindQUIC || definition.Carrier == carrier.KindWebTransport
	case capacityTunnel:
		return definition.Topology != tunnelworkload.TopologyWW
	case capacityBrowserTunnel, capacityBrowserStream:
		return true
	default:
		return false
	}
}

func capacityQLOGAttribution(destination *artifactDestination, definition capacityCaseDefinition, sources []releaseRawSource) (capacityAttributionArtifact, error) {
	attribution := capacityAttributionArtifact{SchemaVersion: 1, Kind: "transport_qlog_attribution", Context: "case " + definition.ID}
	for _, source := range sources {
		if source.Kind != "qlog" {
			continue
		}
		path := filepath.Join(destination.reportParent.path, filepath.FromSlash(source.Path))
		data, err := os.ReadFile(path)
		if err != nil {
			return capacityAttributionArtifact{}, err
		}
		if definition.Kind == capacityBrowserStream {
			records, extractErr := browserStreamCapacityQLOGAttributions(data, source)
			if extractErr != nil {
				return capacityAttributionArtifact{}, fmt.Errorf("attribute %s: %w", source.ID, extractErr)
			}
			attribution.Records = append(attribution.Records, records...)
			continue
		}
		record, extractErr := firstCapacityQLOGAttribution(data, source)
		if extractErr != nil {
			return capacityAttributionArtifact{}, fmt.Errorf("attribute %s: %w", source.ID, extractErr)
		}
		attribution.Records = append(attribution.Records, record)
	}
	if len(attribution.Records) == 0 {
		return capacityAttributionArtifact{}, errors.New("capacity qlog attribution has no records")
	}
	if definition.Kind == capacityBrowserStream {
		if err := validateBrowserStreamCapacityAttributions(attribution.Records); err != nil {
			return capacityAttributionArtifact{}, err
		}
		sort.Slice(attribution.Records, func(left, right int) bool {
			if attribution.Records[left].UnixNanoseconds != attribution.Records[right].UnixNanoseconds {
				return attribution.Records[left].UnixNanoseconds < attribution.Records[right].UnixNanoseconds
			}
			if attribution.Records[left].SourceID != attribution.Records[right].SourceID {
				return attribution.Records[left].SourceID < attribution.Records[right].SourceID
			}
			return *attribution.Records[left].NativeStreamID < *attribution.Records[right].NativeStreamID
		})
	}
	for index := range attribution.Records {
		attribution.Records[index].Sequence = uint64(index + 1)
	}
	return attribution, nil
}

func browserStreamCapacityQLOGAttributions(data []byte, source releaseRawSource) ([]capacityAttributionRecord, error) {
	digest := sha256.Sum256(data)
	if source.SHA256 != hex.EncodeToString(digest[:]) {
		return nil, errors.New("qlog source digest changed before attribution")
	}
	records, err := capacityQLOGRecords(data)
	if err != nil {
		return nil, err
	}
	var reference time.Time
	groupID := ""
	seen := make(map[uint64]struct{}, 128)
	result := make([]capacityAttributionRecord, 0, 128)
	for _, framed := range records {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(framed.payload, &object); err != nil {
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
			if err := json.Unmarshal(traceRaw, &trace); err != nil || strings.TrimSpace(trace.CommonFields.GroupID) == "" {
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
		if reference.IsZero() || json.Unmarshal(framed.payload, &event) != nil || math.IsNaN(event.Time) || math.IsInf(event.Time, 0) || event.Time < 0 || event.Data == nil {
			return nil, errors.New("qlog event identity is invalid")
		}
		frames, ok := event.Data["frames"].([]any)
		if !ok {
			continue
		}
		packetNumber, packetSpace, hasPacket := capacityQLOGPacketIdentity(event.Data)
		for _, rawFrame := range frames {
			frame, ok := rawFrame.(map[string]any)
			streamID, streamOK := capacityQLOGUint(frame["stream_id"])
			if !ok || frame["frame_type"] != "stream" || !streamOK || streamID < 12 || streamID%4 != 0 {
				continue
			}
			if _, duplicate := seen[streamID]; duplicate {
				continue
			}
			seen[streamID] = struct{}{}
			id := streamID
			record := capacityAttributionRecord{
				SourceID: source.ID, SourceSHA256: source.SHA256, ByteOffset: framed.offset, ByteLength: framed.length,
				UnixNanoseconds: reference.UTC().Add(time.Duration(event.Time * float64(time.Millisecond))).UnixNano(),
				Event:           "transport:stream_opened", ConnectionGroupID: groupID, NativeStreamID: &id,
			}
			if hasPacket {
				record.PacketNumber, record.PacketNumberSpace = &packetNumber, packetSpace
			}
			result = append(result, record)
		}
	}
	return result, nil
}

func capacityQLOGPacketIdentity(data map[string]any) (uint64, string, bool) {
	header, ok := data["header"].(map[string]any)
	if !ok {
		return 0, "", false
	}
	packetNumber, numberOK := capacityQLOGUint(header["packet_number"])
	packetSpace, typeOK := header["packet_type"].(string)
	return packetNumber, packetSpace, numberOK && typeOK && strings.TrimSpace(packetSpace) != ""
}

func validateBrowserStreamCapacityAttributions(records []capacityAttributionRecord) error {
	if len(records) != 100*128 {
		return fmt.Errorf("browser stream capacity qlog proves %d opened streams, want %d", len(records), 100*128)
	}
	perConnection := make(map[string]map[uint64]struct{}, 100)
	for _, record := range records {
		if record.Event != "transport:stream_opened" || record.NativeStreamID == nil || *record.NativeStreamID < 12 || *record.NativeStreamID%4 != 0 ||
			strings.TrimSpace(record.ConnectionGroupID) == "" {
			return errors.New("browser stream capacity qlog attribution has an invalid STREAM_OPENED identity")
		}
		streams := perConnection[record.ConnectionGroupID]
		if streams == nil {
			streams = make(map[uint64]struct{}, 128)
			perConnection[record.ConnectionGroupID] = streams
		}
		if _, duplicate := streams[*record.NativeStreamID]; duplicate {
			return errors.New("browser stream capacity qlog attribution reuses a connection stream ID")
		}
		streams[*record.NativeStreamID] = struct{}{}
	}
	if len(perConnection) != 100 {
		return fmt.Errorf("browser stream capacity qlog proves %d connections, want 100", len(perConnection))
	}
	for connectionID, streams := range perConnection {
		if len(streams) != 128 {
			return fmt.Errorf("browser stream capacity qlog connection %s proves %d streams, want 128", connectionID, len(streams))
		}
	}
	return nil
}

type capacityQLOGRecord struct {
	offset  int64
	length  int64
	payload []byte
}

func firstCapacityQLOGAttribution(data []byte, source releaseRawSource) (capacityAttributionRecord, error) {
	digest := sha256.Sum256(data)
	if source.SHA256 != hex.EncodeToString(digest[:]) {
		return capacityAttributionRecord{}, errors.New("qlog source digest changed before attribution")
	}
	records, err := capacityQLOGRecords(data)
	if err != nil {
		return capacityAttributionRecord{}, err
	}
	var reference time.Time
	groupID := ""
	for _, framed := range records {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(framed.payload, &object); err != nil {
			return capacityAttributionRecord{}, errors.New("qlog JSON sequence record is invalid")
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
			if err := json.Unmarshal(traceRaw, &trace); err != nil || strings.TrimSpace(trace.CommonFields.GroupID) == "" {
				return capacityAttributionRecord{}, errors.New("qlog sequence header identity is invalid")
			}
			reference, err = time.Parse(time.RFC3339Nano, trace.CommonFields.ReferenceTime.WallClockTime)
			if err != nil {
				return capacityAttributionRecord{}, errors.New("qlog sequence reference time is invalid")
			}
			groupID = trace.CommonFields.GroupID
			continue
		}
		var event struct {
			Time float64        `json:"time"`
			Name string         `json:"name"`
			Data map[string]any `json:"data"`
		}
		if reference.IsZero() || json.Unmarshal(framed.payload, &event) != nil || math.IsNaN(event.Time) || math.IsInf(event.Time, 0) || event.Time < 0 ||
			!strings.Contains(event.Name, ":") || event.Data == nil {
			return capacityAttributionRecord{}, errors.New("qlog event identity is invalid")
		}
		result := capacityAttributionRecord{
			SourceID: source.ID, SourceSHA256: source.SHA256, ByteOffset: framed.offset, ByteLength: framed.length,
			UnixNanoseconds: reference.UTC().Add(time.Duration(event.Time * float64(time.Millisecond))).UnixNano(),
			Event:           event.Name, ConnectionGroupID: groupID,
		}
		if header, ok := event.Data["header"].(map[string]any); ok {
			packetNumber, numberOK := capacityQLOGUint(header["packet_number"])
			packetType, typeOK := header["packet_type"].(string)
			if numberOK && typeOK && strings.TrimSpace(packetType) != "" {
				result.PacketNumber, result.PacketNumberSpace = &packetNumber, packetType
			}
		}
		return result, nil
	}
	return capacityAttributionRecord{}, errors.New("qlog sequence has no event records")
}

func capacityQLOGRecords(data []byte) ([]capacityQLOGRecord, error) {
	var records []capacityQLOGRecord
	for cursor := 0; cursor < len(data); {
		relative := bytes.IndexByte(data[cursor:], 0x1e)
		if relative < 0 {
			if len(bytes.TrimSpace(data[cursor:])) != 0 {
				return nil, errors.New("qlog JSON sequence contains trailing bytes")
			}
			break
		}
		start := cursor + relative
		if len(bytes.TrimSpace(data[cursor:start])) != 0 {
			return nil, errors.New("qlog JSON sequence contains bytes outside record separators")
		}
		next := bytes.IndexByte(data[start+1:], 0x1e)
		finish := len(data)
		if next >= 0 {
			finish = start + 1 + next
		}
		payload := bytes.TrimSpace(data[start+1 : finish])
		if len(payload) == 0 {
			return nil, errors.New("qlog JSON sequence contains an empty record")
		}
		records = append(records, capacityQLOGRecord{offset: int64(start), length: int64(finish - start), payload: payload})
		cursor = finish
	}
	if len(records) < 2 {
		return nil, errors.New("qlog JSON sequence is missing its header or events")
	}
	return records, nil
}

func capacityQLOGUint(value any) (uint64, bool) {
	number, ok := value.(float64)
	return uint64(number), ok && !math.IsNaN(number) && !math.IsInf(number, 0) && number >= 0 && number == math.Trunc(number)
}
