package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

type soakAttributionArtifact struct {
	SchemaVersion int                     `json:"schema_version"`
	Kind          string                  `json:"kind"`
	Context       string                  `json:"context"`
	Records       []soakAttributionRecord `json:"records"`
}

type soakAttributionRecord struct {
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
}

func buildSoakQLOGAttribution(contextName string, sources []soakCycleSource) (soakAttributionArtifact, error) {
	artifact := soakAttributionArtifact{SchemaVersion: 1, Kind: "transport_qlog_attribution", Context: contextName,
		Records: make([]soakAttributionRecord, 0, len(sources))}
	for index, source := range sources {
		record, err := firstSoakQLOGEvent(source.QLOG)
		if err != nil {
			return soakAttributionArtifact{}, fmt.Errorf("cycle %d qlog attribution: %w", source.Ordinal, err)
		}
		record.Sequence = uint64(index + 1)
		record.SourceID = fmt.Sprintf("qlog-%03d", source.Ordinal)
		if record.ConnectionGroupID != source.ConnectionID {
			return soakAttributionArtifact{}, errors.New("qlog attribution connection ID mismatch")
		}
		artifact.Records = append(artifact.Records, record)
	}
	return artifact, nil
}

func buildSoakPCAPAttribution(contextName string, sources []soakCycleSource) (soakAttributionArtifact, error) {
	artifact := soakAttributionArtifact{SchemaVersion: 1, Kind: "transport_pcap_attribution", Context: contextName,
		Records: make([]soakAttributionRecord, 0, len(sources))}
	for index, source := range sources {
		record, err := firstSoakPCAPPacket(source.PCAP)
		if err != nil {
			return soakAttributionArtifact{}, fmt.Errorf("cycle %d pcap attribution: %w", source.Ordinal, err)
		}
		record.Sequence = uint64(index + 1)
		record.SourceID = fmt.Sprintf("pcap-%03d", source.Ordinal)
		artifact.Records = append(artifact.Records, record)
	}
	return artifact, nil
}

func firstSoakQLOGEvent(data []byte) (soakAttributionRecord, error) {
	digest := sha256.Sum256(data)
	var reference time.Time
	groupID := ""
	for cursor := 0; cursor < len(data); {
		relative := bytes.IndexByte(data[cursor:], 0x1e)
		if relative < 0 {
			break
		}
		start := cursor + relative
		nextRelative := bytes.IndexByte(data[start+1:], 0x1e)
		finish := len(data)
		if nextRelative >= 0 {
			finish = start + 1 + nextRelative
		}
		payload := bytes.TrimSpace(data[start+1 : finish])
		var envelope map[string]json.RawMessage
		if json.Unmarshal(payload, &envelope) != nil {
			return soakAttributionRecord{}, errors.New("invalid qlog JSON sequence record")
		}
		if raw, header := envelope["trace"]; header {
			var trace struct {
				CommonFields struct {
					GroupID       string `json:"group_id"`
					ReferenceTime struct {
						WallClockTime string `json:"wall_clock_time"`
					} `json:"reference_time"`
				} `json:"common_fields"`
			}
			if json.Unmarshal(raw, &trace) != nil {
				return soakAttributionRecord{}, errors.New("invalid qlog trace header")
			}
			var err error
			reference, err = time.Parse(time.RFC3339Nano, trace.CommonFields.ReferenceTime.WallClockTime)
			if err != nil {
				return soakAttributionRecord{}, errors.New("invalid qlog wall clock reference")
			}
			groupID = trace.CommonFields.GroupID
			cursor = finish
			continue
		}
		var event struct {
			Time float64        `json:"time"`
			Name string         `json:"name"`
			Data map[string]any `json:"data"`
		}
		if json.Unmarshal(payload, &event) != nil || reference.IsZero() || event.Time < 0 || math.IsNaN(event.Time) || math.IsInf(event.Time, 0) {
			return soakAttributionRecord{}, errors.New("invalid qlog event")
		}
		if event.Name != "transport:packet_sent" {
			cursor = finish
			continue
		}
		header, ok := event.Data["header"].(map[string]any)
		packetNumberFloat, numberOK := header["packet_number"].(float64)
		packetSpace, spaceOK := header["packet_type"].(string)
		if !ok || !numberOK || !spaceOK || packetNumberFloat < 0 || packetNumberFloat != math.Trunc(packetNumberFloat) {
			return soakAttributionRecord{}, errors.New("invalid qlog packet header")
		}
		packetNumber := uint64(packetNumberFloat)
		return soakAttributionRecord{SourceSHA256: hex.EncodeToString(digest[:]), ByteOffset: int64(start), ByteLength: int64(finish - start),
			UnixNanoseconds: reference.UTC().Add(time.Duration(event.Time * float64(time.Millisecond))).UnixNano(), Event: event.Name,
			ConnectionGroupID: groupID, PacketNumberSpace: packetSpace, PacketNumber: &packetNumber}, nil
	}
	return soakAttributionRecord{}, errors.New("qlog has no packet_sent event")
}

func firstSoakPCAPPacket(data []byte) (soakAttributionRecord, error) {
	if len(data) < 40 {
		return soakAttributionRecord{}, errors.New("pcap is truncated")
	}
	var order binary.ByteOrder
	nanosecond := false
	switch [4]byte(data[:4]) {
	case [4]byte{0xd4, 0xc3, 0xb2, 0xa1}:
		order = binary.LittleEndian
	case [4]byte{0xa1, 0xb2, 0xc3, 0xd4}:
		order = binary.BigEndian
	case [4]byte{0x4d, 0x3c, 0xb2, 0xa1}:
		order, nanosecond = binary.LittleEndian, true
	case [4]byte{0xa1, 0xb2, 0x3c, 0x4d}:
		order, nanosecond = binary.BigEndian, true
	default:
		return soakAttributionRecord{}, errors.New("invalid classic pcap magic")
	}
	included := int(order.Uint32(data[32:36]))
	if included <= 0 || 40+included > len(data) {
		return soakAttributionRecord{}, errors.New("invalid pcap packet record")
	}
	fraction := int64(order.Uint32(data[28:32]))
	if !nanosecond {
		fraction *= 1000
	}
	digest := sha256.Sum256(data)
	return soakAttributionRecord{SourceSHA256: hex.EncodeToString(digest[:]), ByteOffset: 24, ByteLength: int64(16 + included),
		UnixNanoseconds: time.Unix(int64(order.Uint32(data[24:28])), fraction).UTC().UnixNano()}, nil
}
