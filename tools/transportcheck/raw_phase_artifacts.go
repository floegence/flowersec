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
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

type rawPhaseArtifactPayload struct {
	phase           string
	pcapAttribution PacketAttributionArtifact
	qlogAttribution PacketAttributionArtifact
	metrics         MetricsArtifact
}

type rawAttributedArtifacts struct {
	phases             map[string]rawPhaseArtifactPayload
	pcapSources        [][]byte
	qlogSources        [][]byte
	retransmittedBytes uint64
	lossRecoveryNS     int64
}

func writeRawEvidenceSources(writer *typedArtifactWriter, context, stem string, attributed rawAttributedArtifacts) ([]RawEvidenceSource, error) {
	if writer == nil || strings.TrimSpace(context) == "" || !typedArtifactStemPattern.MatchString(stem) {
		return nil, errors.New("raw evidence source request is invalid")
	}
	sources := make([]RawEvidenceSource, 0, len(attributed.pcapSources)+len(attributed.qlogSources))
	for index, data := range attributed.pcapSources {
		id := fmt.Sprintf("pcap-%03d", index+1)
		artifact, err := writer.Write(context, "raw_pcap", stem+"-"+id, ".pcap", data)
		if err != nil {
			return nil, err
		}
		sources = append(sources, RawEvidenceSource{ID: id, Kind: "pcap", Artifact: artifact})
	}
	for index, data := range attributed.qlogSources {
		id := fmt.Sprintf("qlog-%03d", index+1)
		artifact, err := writer.Write(context, "raw_qlog", stem+"-"+id, ".qlog", data)
		if err != nil {
			return nil, err
		}
		sources = append(sources, RawEvidenceSource{ID: id, Kind: "qlog", Artifact: artifact})
	}
	if len(sources) == 0 {
		return nil, errors.New("raw evidence source inventory is empty")
	}
	return sources, nil
}

func prepareRawPhaseArtifacts(reportPath, cellID string, result rawBaselineCarrierResult) (rawAttributedArtifacts, error) {
	phaseBounds, err := validatedRawPhaseBounds(result.Phases)
	if err != nil {
		return rawAttributedArtifacts{}, err
	}
	pcapArtifact, err := uniqueRawArtifact(result.Artifacts, "classic-pcap")
	if err != nil {
		return rawAttributedArtifacts{}, err
	}
	pcapData, err := readBoundRawArtifact(reportPath, pcapArtifact)
	if err != nil {
		return rawAttributedArtifacts{}, fmt.Errorf("raw pcap: %w", err)
	}
	pcapPhases, tcpRetransmitted, err := splitClassicPCAPByPhase(pcapData, phaseBounds)
	if err != nil {
		return rawAttributedArtifacts{}, err
	}
	qlogPhases := make(map[string]PacketAttributionArtifact)
	qlogSources := make([][]byte, 0)
	quicRetransmitted := uint64(0)
	if cellID == "clean-03" {
		qlogs := rawArtifactsOfKind(result.Artifacts, "qlog-json-seq")
		if len(qlogs) == 0 {
			return rawAttributedArtifacts{}, errors.New("raw QUIC run has no qlog JSON sequence")
		}
		qlogSources = make([][]byte, 0, len(qlogs))
		for _, artifact := range qlogs {
			data, err := readBoundRawArtifact(reportPath, artifact)
			if err != nil {
				return rawAttributedArtifacts{}, fmt.Errorf("raw qlog %s: %w", artifact.Path, err)
			}
			qlogSources = append(qlogSources, data)
		}
		qlogPhases, quicRetransmitted, err = splitQLOGByPhase(qlogSources, phaseBounds)
		if err != nil {
			return rawAttributedArtifacts{}, err
		}
	}

	resultPayload := rawAttributedArtifacts{
		phases: make(map[string]rawPhaseArtifactPayload, len(phaseBounds)), pcapSources: [][]byte{pcapData}, qlogSources: qlogSources,
		retransmittedBytes: tcpRetransmitted + quicRetransmitted,
	}
	for _, bound := range phaseBounds {
		pcap := pcapPhases[bound.Phase]
		if len(pcap.Records) == 0 {
			return rawAttributedArtifacts{}, fmt.Errorf("phase %s has no attributed packets", bound.Phase)
		}
		metrics, err := rawPhaseKernelMetrics(bound)
		if err != nil {
			return rawAttributedArtifacts{}, fmt.Errorf("phase %s kernel metrics: %w", bound.Phase, err)
		}
		resultPayload.phases[bound.Phase] = rawPhaseArtifactPayload{phase: bound.Phase, pcapAttribution: pcap, qlogAttribution: qlogPhases[bound.Phase], metrics: MetricsArtifact{
			SchemaVersion: 1, Kind: "transport_metrics", Records: metrics,
		}}
	}
	return resultPayload, nil
}

func writeRawPhaseSupplements(writer *typedArtifactWriter, context, stem, manifestDigest string, payload rawPhaseArtifactPayload) (map[string]EvidenceArtifact, error) {
	payload.pcapAttribution.Context = context
	pcap, err := writer.WriteJSON(context, "pcap_attribution", stem+"-pcap-attribution", payload.pcapAttribution)
	if err != nil {
		return nil, err
	}
	payload.metrics.Context = context
	metrics, err := writer.WriteJSON(context, "metrics", stem+"-metrics", payload.metrics)
	if err != nil {
		return nil, err
	}
	artifacts := map[string]EvidenceArtifact{"pcap_attribution": pcap, "metrics": metrics}
	if len(payload.qlogAttribution.Records) != 0 {
		payload.qlogAttribution.Context = context
		qlog, err := writer.WriteJSON(context, "qlog_attribution", stem+"-qlog-attribution", payload.qlogAttribution)
		if err != nil {
			return nil, err
		}
		artifacts["qlog_attribution"] = qlog
	}
	records, err := performanceNetworkConfigRecords(manifestDigest, "clean-v1", payload.phase)
	if err != nil {
		return nil, err
	}
	records = append(records, ConfigRecord{Key: "pcap_attribution_sha256", Value: pcap.SHA256}, ConfigRecord{Key: "ebpf_metrics_sha256", Value: metrics.SHA256})
	if qlog, ok := artifacts["qlog_attribution"]; ok {
		records = append(records, ConfigRecord{Key: "qlog_attribution_sha256", Value: qlog.SHA256})
	}
	config, err := writer.WriteJSON(context, "config", stem+"-config", ConfigArtifact{SchemaVersion: 1, Kind: "transport_config", Context: context, Records: records})
	if err != nil {
		return nil, err
	}
	artifacts["config"] = config
	return artifacts, nil
}

func validatedRawPhaseBounds(phases []rawPhaseMeasurement) ([]rawPhaseMeasurement, error) {
	want := []string{"cold", "rpc", "bulk", "cleanup"}
	if len(phases) != len(want) {
		return nil, fmt.Errorf("phase measurement count = %d, want %d", len(phases), len(want))
	}
	result := append([]rawPhaseMeasurement(nil), phases...)
	for index := range result {
		phase := result[index]
		if phase.Phase != want[index] || phase.Resource.StartedAt.IsZero() || !phase.Resource.FinishedAt.After(phase.Resource.StartedAt) ||
			index > 0 && phase.Resource.StartedAt.Before(result[index-1].Resource.FinishedAt) || phase.KernelStart == nil || phase.KernelFinish == nil {
			return nil, fmt.Errorf("phase %d identity, time boundary, or kernel snapshots are incomplete", index+1)
		}
	}
	return result, nil
}

func rawPhaseKernelMetrics(phase rawPhaseMeasurement) ([]MetricCounterRecord, error) {
	deltaClient, err := subtractRawKernelStats(phase.KernelFinish.Client, phase.KernelStart.Client)
	if err != nil {
		return nil, err
	}
	deltaServer, err := subtractRawKernelStats(phase.KernelFinish.Server, phase.KernelStart.Server)
	if err != nil {
		return nil, err
	}
	packets := deltaClient.Packets + deltaServer.Packets
	bytesCount := deltaClient.Bytes + deltaServer.Bytes
	if packets == 0 || bytesCount == 0 {
		return nil, errors.New("counter-only eBPF snapshots contain no phase traffic")
	}
	if deltaClient.DeliveredPackets != deltaClient.Packets || deltaServer.DeliveredPackets != deltaServer.Packets {
		return nil, errors.New("clean phase eBPF counters do not conserve delivered packets")
	}
	zeroFields := []uint64{
		deltaClient.DelayPackets, deltaClient.JitterPackets, deltaClient.PeriodicLossPackets, deltaClient.BurstLossPackets, deltaClient.MTUDropPackets,
		deltaClient.GSOPackets, deltaClient.TimestampErrors, deltaClient.ReorderPackets, deltaClient.DuplicatePackets, deltaClient.DuplicateErrors, deltaClient.OutageDropPackets,
		deltaServer.DelayPackets, deltaServer.JitterPackets, deltaServer.PeriodicLossPackets, deltaServer.BurstLossPackets, deltaServer.MTUDropPackets,
		deltaServer.GSOPackets, deltaServer.TimestampErrors, deltaServer.ReorderPackets, deltaServer.DuplicatePackets, deltaServer.DuplicateErrors, deltaServer.OutageDropPackets,
	}
	if slices.ContainsFunc(zeroFields, func(value uint64) bool { return value != 0 }) {
		return nil, errors.New("clean phase eBPF snapshots contain injected faults or kernel errors")
	}
	records := []MetricCounterRecord{{Name: "ebpf_packets", Value: float64(packets), Unit: "count"}, {Name: "ebpf_bytes", Value: float64(bytesCount), Unit: "bytes"}}
	for _, name := range phaseFaultCounterNames {
		records = append(records, MetricCounterRecord{Name: name, Value: 0, Unit: phaseFaultMetricUnit(name)})
	}
	return records, nil
}

func subtractRawKernelStats(finish, start rawKernelFaultStats) (rawKernelFaultStats, error) {
	finishValues := []uint64{finish.Packets, finish.Bytes, finish.DelayPackets, finish.JitterPackets, finish.PeriodicLossPackets, finish.BurstLossPackets, finish.MTUDropPackets, finish.GSOPackets, finish.TimestampErrors, finish.ReorderPackets, finish.DuplicatePackets, finish.DuplicateErrors, finish.OutageDropPackets, finish.DeliveredPackets}
	startValues := []uint64{start.Packets, start.Bytes, start.DelayPackets, start.JitterPackets, start.PeriodicLossPackets, start.BurstLossPackets, start.MTUDropPackets, start.GSOPackets, start.TimestampErrors, start.ReorderPackets, start.DuplicatePackets, start.DuplicateErrors, start.OutageDropPackets, start.DeliveredPackets}
	for index := range finishValues {
		if finishValues[index] < startValues[index] {
			return rawKernelFaultStats{}, errors.New("kernel counter regressed within phase")
		}
	}
	return rawKernelFaultStats{
		Packets: finish.Packets - start.Packets, Bytes: finish.Bytes - start.Bytes,
		DelayPackets: finish.DelayPackets - start.DelayPackets, JitterPackets: finish.JitterPackets - start.JitterPackets,
		PeriodicLossPackets: finish.PeriodicLossPackets - start.PeriodicLossPackets, BurstLossPackets: finish.BurstLossPackets - start.BurstLossPackets,
		MTUDropPackets: finish.MTUDropPackets - start.MTUDropPackets, GSOPackets: finish.GSOPackets - start.GSOPackets,
		TimestampErrors: finish.TimestampErrors - start.TimestampErrors, ReorderPackets: finish.ReorderPackets - start.ReorderPackets,
		DuplicatePackets: finish.DuplicatePackets - start.DuplicatePackets, DuplicateErrors: finish.DuplicateErrors - start.DuplicateErrors,
		OutageDropPackets: finish.OutageDropPackets - start.OutageDropPackets, DeliveredPackets: finish.DeliveredPackets - start.DeliveredPackets,
	}, nil
}

func uniqueRawArtifact(artifacts []rawReleaseArtifact, kind string) (rawReleaseArtifact, error) {
	matches := rawArtifactsOfKind(artifacts, kind)
	if len(matches) != 1 {
		return rawReleaseArtifact{}, fmt.Errorf("raw result contains %d %s artifacts, want exactly one", len(matches), kind)
	}
	return matches[0], nil
}

func rawArtifactsOfKind(artifacts []rawReleaseArtifact, kind string) []rawReleaseArtifact {
	return slices.DeleteFunc(append([]rawReleaseArtifact(nil), artifacts...), func(artifact rawReleaseArtifact) bool { return artifact.Kind != kind })
}

func readBoundRawArtifact(reportPath string, artifact rawReleaseArtifact) ([]byte, error) {
	if artifact.Path == "" || filepath.IsAbs(filepath.FromSlash(artifact.Path)) || !validSHA256(artifact.SHA256) || artifact.SizeBytes <= 0 {
		return nil, errors.New("raw artifact metadata is invalid")
	}
	base, err := filepath.EvalSymlinks(filepath.Dir(reportPath))
	if err != nil {
		return nil, err
	}
	candidate := filepath.Clean(filepath.Join(base, filepath.FromSlash(artifact.Path)))
	relative, err := filepath.Rel(base, candidate)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("raw artifact path escapes the report directory")
	}
	canonical, digest, err := snapshotRegularFile(candidate, false)
	if err != nil || canonical != candidate {
		return nil, errors.New("raw artifact path is not a pinned regular file")
	}
	info, err := os.Stat(canonical)
	if err != nil || digest != artifact.SHA256 || info.Size() != artifact.SizeBytes {
		return nil, errors.New("raw artifact size or digest mismatch")
	}
	return os.ReadFile(canonical)
}

type pcapFormat struct {
	order      binary.ByteOrder
	nanosecond bool
}

func splitClassicPCAPByPhase(data []byte, phases []rawPhaseMeasurement) (map[string]PacketAttributionArtifact, uint64, error) {
	if len(data) < 24 {
		return nil, 0, errors.New("classic pcap is truncated")
	}
	format, err := parsePCAPFormat(data[:4])
	if err != nil {
		return nil, 0, err
	}
	linkType := format.order.Uint32(data[20:24])
	if linkType != 1 {
		return nil, 0, fmt.Errorf("classic pcap link type = %d, want Ethernet", linkType)
	}
	sourceDigest := sha256.Sum256(data)
	sourceSHA256 := hex.EncodeToString(sourceDigest[:])
	outputs := make(map[string]PacketAttributionArtifact, len(phases))
	for _, phase := range phases {
		outputs[phase.Phase] = PacketAttributionArtifact{SchemaVersion: 1, Kind: "transport_pcap_attribution"}
	}
	seenTCP := make(map[string][]tcpSequenceRange)
	var retransmitted uint64
	for offset := 24; offset < len(data); {
		if len(data)-offset < 16 {
			return nil, 0, errors.New("classic pcap record header is truncated")
		}
		header := data[offset : offset+16]
		included := int(format.order.Uint32(header[8:12]))
		original := int(format.order.Uint32(header[12:16]))
		if included <= 0 || original < included || included > len(data)-offset-16 {
			return nil, 0, errors.New("classic pcap record length is invalid")
		}
		record := data[offset : offset+16+included]
		fraction := int64(format.order.Uint32(header[4:8]))
		if !format.nanosecond {
			fraction *= 1000
		}
		if fraction < 0 || fraction >= int64(time.Second) {
			return nil, 0, errors.New("classic pcap timestamp fraction is invalid")
		}
		at := time.Unix(int64(format.order.Uint32(header[0:4])), fraction).UTC()
		matched := ""
		for _, phase := range phases {
			if !at.Before(phase.Resource.StartedAt) && !at.After(phase.Resource.FinishedAt) {
				if matched != "" {
					return nil, 0, errors.New("classic pcap packet belongs to overlapping phases")
				}
				matched = phase.Phase
			}
		}
		if matched != "" {
			attribution := outputs[matched]
			attribution.Records = append(attribution.Records, PacketAttributionRecord{
				Sequence: uint64(len(attribution.Records) + 1), SourceID: "pcap-001", SourceSHA256: sourceSHA256,
				ByteOffset: int64(offset), ByteLength: int64(len(record)), UnixNanoseconds: at.UnixNano(),
			})
			outputs[matched] = attribution
			key, sequence, payloadBytes, ok := tcpPayloadSequence(record[16:])
			if ok && payloadBytes > 0 {
				retransmitted += overlapTCPBytes(seenTCP[key], sequence, sequence+uint64(payloadBytes))
				seenTCP[key] = mergeTCPRange(seenTCP[key], sequence, sequence+uint64(payloadBytes))
			}
		}
		offset += 16 + included
	}
	return outputs, retransmitted, nil
}

func parsePCAPFormat(magic []byte) (pcapFormat, error) {
	switch [4]byte(magic) {
	case [4]byte{0xd4, 0xc3, 0xb2, 0xa1}:
		return pcapFormat{order: binary.LittleEndian}, nil
	case [4]byte{0xa1, 0xb2, 0xc3, 0xd4}:
		return pcapFormat{order: binary.BigEndian}, nil
	case [4]byte{0x4d, 0x3c, 0xb2, 0xa1}:
		return pcapFormat{order: binary.LittleEndian, nanosecond: true}, nil
	case [4]byte{0xa1, 0xb2, 0x3c, 0x4d}:
		return pcapFormat{order: binary.BigEndian, nanosecond: true}, nil
	default:
		return pcapFormat{}, errors.New("classic pcap magic is invalid")
	}
}

type tcpSequenceRange struct{ start, finish uint64 }

func tcpPayloadSequence(packet []byte) (string, uint64, int, bool) {
	if len(packet) < 14 {
		return "", 0, 0, false
	}
	offset, etherType := 14, binary.BigEndian.Uint16(packet[12:14])
	if etherType == 0x8100 && len(packet) >= 18 {
		offset, etherType = 18, binary.BigEndian.Uint16(packet[16:18])
	}
	var source, destination []byte
	var protocol byte
	var transport []byte
	switch etherType {
	case 0x0800:
		if len(packet) < offset+20 {
			return "", 0, 0, false
		}
		headerLength := int(packet[offset]&0x0f) * 4
		if headerLength < 20 || len(packet) < offset+headerLength {
			return "", 0, 0, false
		}
		protocol, source, destination, transport = packet[offset+9], packet[offset+12:offset+16], packet[offset+16:offset+20], packet[offset+headerLength:]
	case 0x86dd:
		if len(packet) < offset+40 {
			return "", 0, 0, false
		}
		protocol, source, destination, transport = packet[offset+6], packet[offset+8:offset+24], packet[offset+24:offset+40], packet[offset+40:]
	default:
		return "", 0, 0, false
	}
	if protocol != 6 || len(transport) < 20 {
		return "", 0, 0, false
	}
	headerLength := int(transport[12]>>4) * 4
	if headerLength < 20 || len(transport) < headerLength {
		return "", 0, 0, false
	}
	sequence := uint64(binary.BigEndian.Uint32(transport[4:8]))
	if transport[13]&0x02 != 0 {
		sequence++
	}
	key := hex.EncodeToString(source) + ":" + fmt.Sprint(binary.BigEndian.Uint16(transport[0:2])) + ">" + hex.EncodeToString(destination) + ":" + fmt.Sprint(binary.BigEndian.Uint16(transport[2:4]))
	return key, sequence, len(transport) - headerLength, true
}

func overlapTCPBytes(ranges []tcpSequenceRange, start, finish uint64) uint64 {
	var total uint64
	for _, item := range ranges {
		left, right := max(start, item.start), min(finish, item.finish)
		if right > left {
			total += right - left
		}
	}
	return min(total, finish-start)
}

func mergeTCPRange(ranges []tcpSequenceRange, start, finish uint64) []tcpSequenceRange {
	ranges = append(ranges, tcpSequenceRange{start: start, finish: finish})
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	merged := ranges[:0]
	for _, item := range ranges {
		if len(merged) == 0 || item.start > merged[len(merged)-1].finish {
			merged = append(merged, item)
		} else if item.finish > merged[len(merged)-1].finish {
			merged[len(merged)-1].finish = item.finish
		}
	}
	return merged
}

type rawQLOGEvent struct {
	at           time.Time
	relativeNS   int64
	name         string
	data         map[string]any
	sourceID     string
	sourceSHA256 string
	groupID      string
	recordOffset int64
	recordLength int64
	sequence     int
}

func splitQLOGByPhase(sources [][]byte, phases []rawPhaseMeasurement) (map[string]PacketAttributionArtifact, uint64, error) {
	events := make([]rawQLOGEvent, 0)
	for index, source := range sources {
		parsed, err := parseQLOGSequenceSource(source, fmt.Sprintf("qlog-%03d", index+1))
		if err != nil {
			return nil, 0, err
		}
		events = append(events, parsed...)
	}
	sort.Slice(events, func(i, j int) bool {
		if !events[i].at.Equal(events[j].at) {
			return events[i].at.Before(events[j].at)
		}
		if events[i].sourceID != events[j].sourceID {
			return events[i].sourceID < events[j].sourceID
		}
		return events[i].sequence < events[j].sequence
	})
	sentPackets := make(map[string]struct{})
	lostPackets := make(map[string]struct{})
	streamRanges := make(map[string][]tcpSequenceRange)
	var retransmitted uint64
	for _, event := range events {
		switch event.name {
		case "transport:packet_sent":
			packetKey, err := qlogPacketKey(event)
			if err != nil {
				return nil, 0, err
			}
			if _, duplicate := sentPackets[packetKey]; duplicate {
				return nil, 0, fmt.Errorf("qlog contains duplicate packet_sent %s", packetKey)
			}
			sentPackets[packetKey] = struct{}{}
			frames, ok := event.data["frames"].([]any)
			if !ok {
				continue
			}
			for _, rawFrame := range frames {
				frame, ok := rawFrame.(map[string]any)
				if !ok || frame["frame_type"] != "stream" {
					continue
				}
				streamID, streamOK := qlogUint(frame["stream_id"])
				offset, offsetOK := qlogUint(frame["offset"])
				length, lengthOK := qlogUint(frame["length"])
				if !streamOK || !offsetOK || !lengthOK || length == 0 || offset > math.MaxUint64-length {
					return nil, 0, errors.New("qlog STREAM frame has invalid stream_id, offset, or length")
				}
				streamKey := event.sourceID + "/" + fmt.Sprint(streamID)
				if retransmitted > math.MaxUint64-overlapTCPBytes(streamRanges[streamKey], offset, offset+length) {
					return nil, 0, errors.New("qlog retransmitted STREAM byte count overflows")
				}
				retransmitted += overlapTCPBytes(streamRanges[streamKey], offset, offset+length)
				streamRanges[streamKey] = mergeTCPRange(streamRanges[streamKey], offset, offset+length)
			}
		case "recovery:packet_lost":
			packetKey, err := qlogPacketKey(event)
			if err != nil {
				return nil, 0, err
			}
			if _, exists := sentPackets[packetKey]; !exists {
				return nil, 0, fmt.Errorf("qlog lost packet %s has no same-trace packet_sent", packetKey)
			}
			if _, duplicate := lostPackets[packetKey]; duplicate {
				return nil, 0, fmt.Errorf("qlog contains duplicate packet_lost %s", packetKey)
			}
			lostPackets[packetKey] = struct{}{}
		}
	}
	result := make(map[string]PacketAttributionArtifact, len(phases))
	for _, phase := range phases {
		attribution := PacketAttributionArtifact{SchemaVersion: 1, Kind: "transport_qlog_attribution"}
		for _, event := range events {
			if event.at.Before(phase.Resource.StartedAt) || event.at.After(phase.Resource.FinishedAt) {
				continue
			}
			record := PacketAttributionRecord{
				Sequence: uint64(len(attribution.Records) + 1), SourceID: event.sourceID, SourceSHA256: event.sourceSHA256,
				ByteOffset: event.recordOffset, ByteLength: event.recordLength, UnixNanoseconds: event.at.UnixNano(),
				Event: event.name, ConnectionGroupID: event.groupID,
			}
			if header, ok := event.data["header"].(map[string]any); ok {
				packetNumber, numberOK := qlogUint(header["packet_number"])
				packetType, typeOK := header["packet_type"].(string)
				if numberOK && typeOK && strings.TrimSpace(packetType) != "" {
					record.PacketNumber, record.PacketNumberSpace = &packetNumber, packetType
				}
			}
			attribution.Records = append(attribution.Records, record)
		}
		if len(attribution.Records) == 0 {
			return nil, 0, fmt.Errorf("phase %s has no correlated qlog events", phase.Phase)
		}
		result[phase.Phase] = attribution
	}
	return result, retransmitted, nil
}

func parseQLOGSequence(data []byte) ([]rawQLOGEvent, error) {
	return parseQLOGSequenceSource(data, "qlog-001")
}

func parseQLOGSequenceSource(data []byte, sourceID string) ([]rawQLOGEvent, error) {
	if !typedArtifactStemPattern.MatchString(sourceID) {
		return nil, errors.New("qlog source ID is invalid")
	}
	records, err := rawQLOGSequenceRecords(data)
	if err != nil {
		return nil, err
	}
	var reference time.Time
	headerSeen := false
	sourceDigest := sha256.Sum256(data)
	result := make([]rawQLOGEvent, 0, len(records))
	groupID := ""
	for sequence, framed := range records {
		record := framed.payload
		var object map[string]json.RawMessage
		if err := json.Unmarshal(record, &object); err != nil {
			return nil, errors.New("qlog JSON sequence record is invalid")
		}
		if traceRaw, ok := object["trace"]; ok {
			if headerSeen || len(result) != 0 {
				return nil, errors.New("qlog sequence must contain exactly one leading header")
			}
			var trace struct {
				CommonFields struct {
					GroupID       string `json:"group_id"`
					ReferenceTime struct {
						ClockType     string `json:"clock_type"`
						Epoch         string `json:"epoch"`
						WallClockTime string `json:"wall_clock_time"`
					} `json:"reference_time"`
				} `json:"common_fields"`
			}
			var header struct {
				FileSchema          string `json:"file_schema"`
				SerializationFormat string `json:"serialization_format"`
				QlogVersion         string `json:"qlog_version"`
				QlogFormat          string `json:"qlog_format"`
				CodeVersion         string `json:"code_version"`
			}
			if json.Unmarshal(record, &header) != nil || json.Unmarshal(traceRaw, &trace) != nil ||
				header.FileSchema != "urn:ietf:params:qlog:file:sequential" || header.SerializationFormat != "application/qlog+json-seq" ||
				header.QlogVersion != "0.3" || header.QlogFormat != "JSON-SEQ" || header.CodeVersion != "v0.60.0" ||
				strings.TrimSpace(trace.CommonFields.GroupID) == "" ||
				trace.CommonFields.ReferenceTime.ClockType != "monotonic" || trace.CommonFields.ReferenceTime.Epoch != "unknown" {
				return nil, errors.New("qlog sequence header is invalid")
			}
			parsed, err := time.Parse(time.RFC3339Nano, trace.CommonFields.ReferenceTime.WallClockTime)
			if err != nil {
				return nil, errors.New("qlog sequence wall clock reference is invalid")
			}
			reference = parsed.UTC()
			headerSeen = true
			groupID = trace.CommonFields.GroupID
			continue
		}
		if reference.IsZero() {
			return nil, errors.New("qlog event precedes its sequence header")
		}
		var event struct {
			Time float64        `json:"time"`
			Name string         `json:"name"`
			Data map[string]any `json:"data"`
		}
		if json.Unmarshal(record, &event) != nil || !finite(event.Time) || event.Time < 0 ||
			event.Time > float64(math.MaxInt64)/float64(time.Millisecond) || !strings.Contains(event.Name, ":") || event.Data == nil {
			return nil, errors.New("qlog event record is invalid")
		}
		// quic-go qlogwriter v0.60 emits qlog 0.3 JSON-SEQ with relative
		// event times in milliseconds. Header validation above prevents a
		// future producer unit change from being interpreted silently.
		relativeNS := int64(event.Time * float64(time.Millisecond))
		result = append(result, rawQLOGEvent{
			at: reference.Add(time.Duration(relativeNS)), relativeNS: relativeNS, name: event.Name, data: event.Data,
			sourceID: sourceID, sourceSHA256: hex.EncodeToString(sourceDigest[:]), groupID: groupID,
			recordOffset: framed.offset, recordLength: framed.length, sequence: sequence,
		})
	}
	if !headerSeen || len(result) == 0 {
		return nil, errors.New("qlog sequence is missing its header or events")
	}
	return result, nil
}

type rawQLOGSequenceRecord struct {
	offset  int64
	length  int64
	payload []byte
}

func rawQLOGSequenceRecords(data []byte) ([]rawQLOGSequenceRecord, error) {
	var records []rawQLOGSequenceRecord
	for cursor := 0; cursor < len(data); {
		relative := bytes.IndexByte(data[cursor:], 0x1e)
		if relative < 0 {
			if len(bytes.TrimSpace(data[cursor:])) != 0 {
				return nil, errors.New("qlog JSON sequence contains bytes outside record separators")
			}
			break
		}
		start := cursor + relative
		if len(bytes.TrimSpace(data[cursor:start])) != 0 {
			return nil, errors.New("qlog JSON sequence contains bytes outside record separators")
		}
		nextRelative := bytes.IndexByte(data[start+1:], 0x1e)
		finish := len(data)
		if nextRelative >= 0 {
			finish = start + 1 + nextRelative
		}
		payload := bytes.TrimSpace(data[start+1 : finish])
		if len(payload) == 0 {
			return nil, errors.New("qlog JSON sequence contains an empty record")
		}
		records = append(records, rawQLOGSequenceRecord{offset: int64(start), length: int64(finish - start), payload: payload})
		cursor = finish
	}
	if len(records) == 0 {
		return nil, errors.New("qlog JSON sequence contains no records")
	}
	return records, nil
}

func nestedQLOGUint(data map[string]any, object, field string) (uint64, bool) {
	nested, ok := data[object].(map[string]any)
	if !ok {
		return 0, false
	}
	value, ok := nested[field].(float64)
	return uint64(value), ok && finite(value) && value >= 0 && value == math.Trunc(value)
}

func qlogUint(value any) (uint64, bool) {
	number, ok := value.(float64)
	return uint64(number), ok && finite(number) && number >= 0 && number == math.Trunc(number)
}

func qlogPacketKey(event rawQLOGEvent) (string, error) {
	header, ok := event.data["header"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("qlog event %s lacks packet header", event.name)
	}
	packetNumber, numberOK := qlogUint(header["packet_number"])
	packetType, typeOK := header["packet_type"].(string)
	if !numberOK || !typeOK || strings.TrimSpace(packetType) == "" {
		return "", fmt.Errorf("qlog event %s lacks packet number or PN space", event.name)
	}
	return event.sourceID + "/" + packetType + "/" + fmt.Sprint(packetNumber), nil
}
