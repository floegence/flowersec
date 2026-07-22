package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

type packetObservation struct {
	atNS             int64
	ipVersion        int
	protocol         uint8
	length           int
	source           netip.Addr
	destination      netip.Addr
	sourcePort       uint16
	destinationPort  uint16
	transportPayload []byte
	icmpType         uint8
	icmpCode         uint8
	quoted           *packetObservation
}

func (packet packetObservation) sourceEndpoint() netip.AddrPort {
	return netip.AddrPortFrom(packet.source, packet.sourcePort)
}

func (packet packetObservation) destinationEndpoint() netip.AddrPort {
	return netip.AddrPortFrom(packet.destination, packet.destinationPort)
}

func validatePCAPEvidence(context string, data []byte) error {
	packets, err := parseClassicPCAP(data)
	if err != nil || len(packets) == 0 {
		return errors.New("capture must be classic pcap with parseable raw-IP or Ethernet packets")
	}
	require := func(version int, protocol uint8, oversized bool) bool {
		for _, packet := range packets {
			if packet.ipVersion == version && packet.protocol == protocol && (!oversized || packet.length > 1280) {
				return true
			}
		}
		return false
	}
	caseID := strings.TrimPrefix(strings.TrimPrefix(context, "race case "), "case ")
	switch {
	case strings.Contains(caseID, "PMTUD-QUIC-IPV4"):
		if !require(4, 17, true) {
			return errors.New("missing IPv4 UDP packet larger than 1280 bytes")
		}
	case strings.Contains(caseID, "PMTUD-QUIC-IPV6"):
		if !require(6, 17, true) {
			return errors.New("missing IPv6 UDP packet larger than 1280 bytes / 1232-byte UDP payload")
		}
	case strings.Contains(caseID, "PMTUD-WSS") && strings.Contains(caseID, "IPV4"):
		if !require(4, 6, true) {
			return errors.New("missing IPv4 TCP packet larger than 1280 bytes")
		}
	case strings.Contains(caseID, "PMTUD-WSS") && strings.Contains(caseID, "IPV6"):
		if !require(6, 6, true) {
			return errors.New("missing IPv6 TCP packet larger than 1280 bytes")
		}
	case caseID == "SYS-COMMON-KERNEL":
		if !(require(4, 6, false) || require(6, 6, false)) || !(require(4, 17, false) || require(6, 17, false)) {
			return errors.New("common-kernel capture must contain both TCP and UDP packets")
		}
	case caseID == "NP-REBIND" || caseID == "SYS-MIGRATION-REBIND":
		if _, _, _, err := pcapUDPPathTransition(packets, nil); err != nil {
			return err
		}
	default:
		if !require(4, 17, false) && !require(6, 17, false) && !require(4, 6, false) && !require(6, 6, false) {
			return errors.New("capture has no TCP or UDP packet")
		}
	}
	return nil
}

func pcapUDPPathTransition(packets []packetObservation, connectionID []byte) (netip.AddrPort, netip.AddrPort, netip.AddrPort, error) {
	for firstIndex, first := range packets {
		if first.protocol != 17 || !first.sourceEndpoint().IsValid() || !first.destinationEndpoint().IsValid() ||
			len(connectionID) > 0 && !packetCarriesQUICConnectionID(first, connectionID) {
			continue
		}
		for _, next := range packets[firstIndex+1:] {
			if next.protocol != 17 || next.ipVersion != first.ipVersion ||
				next.destinationEndpoint() != first.destinationEndpoint() || next.sourceEndpoint() == first.sourceEndpoint() ||
				len(connectionID) > 0 && !packetCarriesQUICConnectionID(next, connectionID) {
				continue
			}
			return first.sourceEndpoint(), next.sourceEndpoint(), first.destinationEndpoint(), nil
		}
	}
	return netip.AddrPort{}, netip.AddrPort{}, netip.AddrPort{},
		errors.New("migration capture must show an ordered local AddrPort change on one correlated UDP remote path")
}

func validateCorrelatedPathTransition(qlogData, pcapData []byte, connectionID string) error {
	cid, err := hex.DecodeString(connectionID)
	if err != nil || len(cid) < 4 || len(cid) > 20 {
		return errors.New("migration QUIC connection ID must be 4..20 bytes of hex")
	}
	packets, err := parseClassicPCAP(pcapData)
	if err != nil {
		return err
	}
	oldLocal, newLocal, remote, err := pcapUDPPathTransition(packets, cid)
	if err != nil {
		return err
	}
	var document struct {
		Traces []struct {
			Events []json.RawMessage `json:"events"`
		} `json:"traces"`
	}
	if err := decodeSingleJSON(qlogData, &document); err != nil || len(document.Traces) != 1 {
		return errors.New("path transition qlog is invalid")
	}
	matched := 0
	updated := false
	validated := false
	rpcAfterValidation := false
	for _, raw := range document.Traces[0].Events {
		var fields []json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || len(fields) != 4 {
			continue
		}
		var category, name string
		var data map[string]any
		if json.Unmarshal(fields[1], &category) != nil || json.Unmarshal(fields[2], &name) != nil || json.Unmarshal(fields[3], &data) != nil {
			continue
		}
		qualified := category + ":" + name
		if qualified == "connectivity:path_validated" && fmt.Sprint(data["connection_id"]) == connectionID {
			validatedLocal, localErr := netip.ParseAddrPort(fmt.Sprint(data["new_path"]))
			validatedRemote, remoteErr := netip.ParseAddrPort(fmt.Sprint(data["remote_path"]))
			if updated && localErr == nil && remoteErr == nil && validatedLocal == newLocal && validatedRemote == remote {
				validated = true
			}
			continue
		}
		if qualified == "application:rpc_completed" && validated && fmt.Sprint(data["connection_id"]) == connectionID {
			rpcAfterValidation = true
			continue
		}
		if qualified != "connectivity:path_updated" {
			continue
		}
		oldPath, oldErr := netip.ParseAddrPort(fmt.Sprint(data["old_path"]))
		newPath, newErr := netip.ParseAddrPort(fmt.Sprint(data["new_path"]))
		remotePath, remoteErr := netip.ParseAddrPort(fmt.Sprint(data["remote_path"]))
		if oldErr != nil || newErr != nil || remoteErr != nil || oldPath != oldLocal || newPath != newLocal || remotePath != remote ||
			fmt.Sprint(data["connection_id"]) != connectionID {
			return errors.New("qlog path transition does not match the ordered pcap UDP 5-tuple")
		}
		matched++
		updated = true
	}
	if matched != 1 || !validated || !rpcAfterValidation {
		return fmt.Errorf("qlog migration identity/order mismatch: path_updates=%d path_validated=%t rpc_after_validation=%t", matched, validated, rpcAfterValidation)
	}
	return nil
}

func validateQUICPMTUDCapture(data []byte, version int) error {
	return validateQUICPMTUDCaptureForConnection(data, version, false, "")
}

func validateQUICPMTUDCaptureForConnection(data []byte, version int, requirePTB bool, connectionID string) error {
	packets, err := parseClassicPCAP(data)
	if err != nil {
		return err
	}
	var cid []byte
	if connectionID != "" {
		cid, err = hex.DecodeString(connectionID)
		if err != nil || len(cid) < 4 || len(cid) > 20 {
			return errors.New("PMTUD QUIC connection ID must be 4..20 bytes of hex")
		}
	}
	for index, oversized := range packets {
		if oversized.ipVersion != version || oversized.protocol != 17 || oversized.length <= 1280 ||
			len(cid) > 0 && !packetCarriesQUICConnectionID(oversized, cid) {
			continue
		}
		ptbIndex := index
		if requirePTB {
			ptbIndex = -1
			for candidateIndex := index + 1; candidateIndex < len(packets); candidateIndex++ {
				candidate := packets[candidateIndex]
				if candidate.quotesFlow(oversized) && ((version == 4 && candidate.protocol == 1 && candidate.icmpType == 3 && candidate.icmpCode == 4) ||
					(version == 6 && candidate.protocol == 58 && candidate.icmpType == 2)) {
					ptbIndex = candidateIndex
					break
				}
			}
			if ptbIndex < 0 {
				continue
			}
		}
		for _, constrained := range packets[ptbIndex+1:] {
			if constrained.ipVersion == version && constrained.protocol == 17 && constrained.length <= 1280 &&
				constrained.sourceEndpoint() == oversized.sourceEndpoint() &&
				constrained.destinationEndpoint() == oversized.destinationEndpoint() &&
				(len(cid) == 0 || packetCarriesQUICConnectionID(constrained, cid)) {
				return nil
			}
		}
	}
	return errors.New("PMTUD capture must show one QUIC identity with oversized UDP, matching ICMP PTB quoted tuple when required, then constrained UDP")
}

func validatePCAPConnectionID(data []byte, connectionID string) error {
	cid, err := hex.DecodeString(connectionID)
	if err != nil || len(cid) < 4 || len(cid) > 20 {
		return errors.New("pcap connection ID must be 4..20 bytes of hex")
	}
	packets, err := parseClassicPCAP(data)
	if err != nil {
		return err
	}
	for _, packet := range packets {
		if packet.protocol == 17 && packetCarriesQUICConnectionID(packet, cid) {
			return nil
		}
	}
	return errors.New("pcap has no UDP packet bound to the configured QUIC connection ID")
}

func validateOrderedQlogConnection(data []byte, connectionID string, required []string) error {
	var document struct {
		Traces []struct {
			Events []json.RawMessage `json:"events"`
		} `json:"traces"`
	}
	if err := decodeSingleJSON(data, &document); err != nil || len(document.Traces) != 1 {
		return errors.New("qlog is invalid")
	}
	position := 0
	lastTime := -1.0
	counts := make(map[string]int, len(required))
	for _, raw := range document.Traces[0].Events {
		var fields []json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || len(fields) != 4 {
			return errors.New("qlog event is invalid")
		}
		var at float64
		var category, name string
		var eventData map[string]any
		if json.Unmarshal(fields[0], &at) != nil || json.Unmarshal(fields[1], &category) != nil ||
			json.Unmarshal(fields[2], &name) != nil || json.Unmarshal(fields[3], &eventData) != nil {
			return errors.New("qlog event fields are invalid")
		}
		qualified := category + ":" + name
		if !slices.Contains(required, qualified) {
			continue
		}
		counts[qualified]++
		if position >= len(required) || qualified != required[position] || at <= lastTime || fmt.Sprint(eventData["connection_id"]) != connectionID {
			return fmt.Errorf("qlog event %s is out of order or bound to another connection", qualified)
		}
		position++
		lastTime = at
	}
	if position != len(required) {
		return fmt.Errorf("qlog contains %d of %d ordered same-connection recovery events", position, len(required))
	}
	for _, name := range required {
		if counts[name] != 1 {
			return fmt.Errorf("qlog event %s appears %d times, want exactly once", name, counts[name])
		}
	}
	return nil
}

func packetCarriesQUICConnectionID(packet packetObservation, connectionID []byte) bool {
	return len(packet.transportPayload) >= 1+len(connectionID) && packet.transportPayload[0]&0x40 != 0 &&
		bytes.Equal(packet.transportPayload[1:1+len(connectionID)], connectionID)
}

func (packet packetObservation) quotesFlow(flow packetObservation) bool {
	return packet.quoted != nil && packet.quoted.ipVersion == flow.ipVersion && packet.quoted.protocol == flow.protocol &&
		packet.quoted.sourceEndpoint() == flow.sourceEndpoint() && packet.quoted.destinationEndpoint() == flow.destinationEndpoint()
}

func parseClassicPCAP(data []byte) ([]packetObservation, error) {
	if len(data) < 24 {
		return nil, errors.New("short pcap")
	}
	magic := binary.BigEndian.Uint32(data[:4])
	var order binary.ByteOrder
	switch magic {
	case 0xa1b2c3d4, 0xa1b23c4d:
		order = binary.BigEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		order = binary.LittleEndian
	default:
		return nil, errors.New("pcapng is not accepted for semantic packet derivation")
	}
	linkType := order.Uint32(data[20:24])
	var packets []packetObservation
	offset := 24
	for offset+16 <= len(data) {
		captured := int(order.Uint32(data[offset+8 : offset+12]))
		if captured <= 0 || offset+16+captured > len(data) {
			return nil, errors.New("invalid packet record length")
		}
		packet, err := parseCapturedIP(linkType, data[offset+16:offset+16+captured])
		if err != nil {
			return nil, err
		}
		seconds := int64(order.Uint32(data[offset : offset+4]))
		fraction := int64(order.Uint32(data[offset+4 : offset+8]))
		packet.atNS = seconds*1e9 + fraction*1e3
		packets = append(packets, packet)
		offset += 16 + captured
	}
	if offset != len(data) {
		return nil, errors.New("trailing or incomplete pcap record")
	}
	return packets, nil
}

func parseCapturedIP(linkType uint32, packet []byte) (packetObservation, error) {
	switch linkType {
	case 1:
		if len(packet) < 14 {
			return packetObservation{}, errors.New("short Ethernet packet")
		}
		etherType := binary.BigEndian.Uint16(packet[12:14])
		if etherType != 0x0800 && etherType != 0x86dd {
			return packetObservation{}, fmt.Errorf("unsupported Ethernet payload type %#x", etherType)
		}
		packet = packet[14:]
	case 101:
	default:
		return packetObservation{}, fmt.Errorf("unsupported pcap link type %d", linkType)
	}
	if len(packet) == 0 {
		return packetObservation{}, errors.New("empty IP packet")
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return packetObservation{}, errors.New("short IPv4 packet")
		}
		length := int(binary.BigEndian.Uint16(packet[2:4]))
		header := int(packet[0]&0x0f) * 4
		if header < 20 || length < header || length > len(packet) {
			return packetObservation{}, errors.New("invalid IPv4 length")
		}
		if binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return packetObservation{}, errors.New("fragmented IPv4 packets cannot prove a transport 5-tuple")
		}
		var source [4]byte
		copy(source[:], packet[12:16])
		var destination [4]byte
		copy(destination[:], packet[16:20])
		observation := packetObservation{ipVersion: 4, protocol: packet[9], length: length,
			source: netip.AddrFrom4(source), destination: netip.AddrFrom4(destination)}
		if observation.protocol == 1 {
			return packetWithICMPQuote(observation, packet[header:length])
		}
		return packetWithPorts(observation, packet[header:length])
	case 6:
		if len(packet) < 40 {
			return packetObservation{}, errors.New("short IPv6 packet")
		}
		length := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
		if length > len(packet) {
			return packetObservation{}, errors.New("invalid IPv6 length")
		}
		var source [16]byte
		copy(source[:], packet[8:24])
		var destination [16]byte
		copy(destination[:], packet[24:40])
		observation := packetObservation{ipVersion: 6, protocol: packet[6], length: length,
			source: netip.AddrFrom16(source), destination: netip.AddrFrom16(destination)}
		if observation.protocol == 58 {
			return packetWithICMPQuote(observation, packet[40:length])
		}
		return packetWithPorts(observation, packet[40:length])
	default:
		return packetObservation{}, errors.New("capture packet is not IPv4 or IPv6")
	}
}

func packetWithPorts(observation packetObservation, payload []byte) (packetObservation, error) {
	if observation.protocol != 6 && observation.protocol != 17 {
		return observation, nil
	}
	minimum := 20
	if observation.protocol == 17 {
		minimum = 8
	}
	if len(payload) < minimum {
		return packetObservation{}, errors.New("short TCP/UDP header")
	}
	if observation.protocol == 17 {
		udpLength := int(binary.BigEndian.Uint16(payload[4:6]))
		if udpLength < 8 || udpLength > len(payload) {
			return packetObservation{}, errors.New("invalid UDP length")
		}
	} else {
		headerLength := int(payload[12]>>4) * 4
		if headerLength < 20 || headerLength > len(payload) {
			return packetObservation{}, errors.New("invalid TCP header length")
		}
	}
	observation.sourcePort = binary.BigEndian.Uint16(payload[:2])
	observation.destinationPort = binary.BigEndian.Uint16(payload[2:4])
	if observation.protocol == 17 {
		observation.transportPayload = append([]byte(nil), payload[8:]...)
	} else {
		headerLength := int(payload[12]>>4) * 4
		observation.transportPayload = append([]byte(nil), payload[headerLength:]...)
	}
	if observation.sourcePort == 0 || observation.destinationPort == 0 {
		return packetObservation{}, errors.New("TCP/UDP endpoint uses port zero")
	}
	return observation, nil
}

func packetWithICMPQuote(observation packetObservation, payload []byte) (packetObservation, error) {
	if len(payload) < 8 {
		return packetObservation{}, errors.New("short ICMP PTB packet")
	}
	observation.icmpType, observation.icmpCode = payload[0], payload[1]
	quoted, err := parseQuotedFlow(payload[8:])
	if err != nil {
		return packetObservation{}, fmt.Errorf("parse ICMP quoted packet: %w", err)
	}
	if quoted.protocol != 6 && quoted.protocol != 17 {
		return packetObservation{}, errors.New("ICMP quote does not contain TCP or UDP")
	}
	observation.quoted = &quoted
	return observation, nil
}

func parseQuotedFlow(packet []byte) (packetObservation, error) {
	if len(packet) == 0 {
		return packetObservation{}, errors.New("empty ICMP quote")
	}
	var observation packetObservation
	var transport []byte
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 28 {
			return packetObservation{}, errors.New("short quoted IPv4 transport tuple")
		}
		header := int(packet[0]&0x0f) * 4
		declared := int(binary.BigEndian.Uint16(packet[2:4]))
		if header < 20 || declared < header+8 || len(packet) < header+8 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return packetObservation{}, errors.New("invalid quoted IPv4 transport tuple")
		}
		var source [4]byte
		copy(source[:], packet[12:16])
		var destination [4]byte
		copy(destination[:], packet[16:20])
		observation = packetObservation{ipVersion: 4, protocol: packet[9], length: declared,
			source: netip.AddrFrom4(source), destination: netip.AddrFrom4(destination)}
		transport = packet[header : header+8]
	case 6:
		if len(packet) < 48 {
			return packetObservation{}, errors.New("short quoted IPv6 transport tuple")
		}
		declared := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
		if declared < 48 {
			return packetObservation{}, errors.New("invalid quoted IPv6 transport tuple")
		}
		var source [16]byte
		copy(source[:], packet[8:24])
		var destination [16]byte
		copy(destination[:], packet[24:40])
		observation = packetObservation{ipVersion: 6, protocol: packet[6], length: declared,
			source: netip.AddrFrom16(source), destination: netip.AddrFrom16(destination)}
		transport = packet[40:48]
	default:
		return packetObservation{}, errors.New("ICMP quote is not IPv4 or IPv6")
	}
	if observation.protocol != 6 && observation.protocol != 17 {
		return packetObservation{}, errors.New("ICMP quote does not contain TCP or UDP")
	}
	observation.sourcePort = binary.BigEndian.Uint16(transport[:2])
	observation.destinationPort = binary.BigEndian.Uint16(transport[2:4])
	if observation.sourcePort == 0 || observation.destinationPort == 0 {
		return packetObservation{}, errors.New("quoted TCP/UDP endpoint uses port zero")
	}
	return observation, nil
}
