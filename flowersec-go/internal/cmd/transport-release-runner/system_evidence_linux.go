//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

type systemPMTUDEvidence struct {
	OversizedPackets   uint64
	ConstrainedPackets uint64
	ICMPPTBPackets     uint64
	Recoveries         uint64
}

func deriveSystemPMTUDEvidence(pcap, qlog []byte, ipv6 bool) (systemPMTUDEvidence, error) {
	threshold := float64(1252)
	if ipv6 {
		threshold = 1232
	}
	evidence, err := deriveSystemPMTUDQLOG(qlog, threshold)
	if err != nil {
		return systemPMTUDEvidence{}, err
	}
	ptb, err := countSystemICMPPTB(pcap, ipv6)
	if err != nil {
		return systemPMTUDEvidence{}, err
	}
	evidence.ICMPPTBPackets = ptb
	if evidence.ICMPPTBPackets == 0 {
		return systemPMTUDEvidence{}, fmt.Errorf("raw PMTUD evidence is incomplete: %+v", evidence)
	}
	return evidence, nil
}

func deriveSystemPMTUDQLOG(qlog []byte, threshold float64) (systemPMTUDEvidence, error) {
	var evidence systemPMTUDEvidence
	var sawOversizedPacket, sawConstrainedMTU bool
	for _, record := range bytes.Split(qlog, []byte{0x1e}) {
		record = bytes.TrimSpace(record)
		if len(record) == 0 {
			continue
		}
		var event struct {
			Name string `json:"name"`
			Data struct {
				MTU float64 `json:"mtu"`
				Raw struct {
					Length float64 `json:"length"`
				} `json:"raw"`
				Frames []struct {
					Type string `json:"frame_type"`
				} `json:"frames"`
			} `json:"data"`
		}
		if err := json.Unmarshal(record, &event); err != nil {
			return systemPMTUDEvidence{}, fmt.Errorf("decode PMTUD qlog record: %w", err)
		}
		switch event.Name {
		case "recovery:mtu_updated":
			if sawOversizedPacket && event.Data.MTU > 0 && event.Data.MTU <= threshold {
				sawConstrainedMTU = true
			}
		case "transport:packet_sent":
			streamData := false
			for _, frame := range event.Data.Frames {
				if frame.Type == "stream" {
					streamData = true
				}
			}
			if event.Data.Raw.Length <= 0 {
				continue
			}
			if !sawConstrainedMTU && event.Data.Raw.Length > threshold {
				sawOversizedPacket = true
				evidence.OversizedPackets++
			}
			if sawConstrainedMTU && streamData && event.Data.Raw.Length <= threshold {
				evidence.ConstrainedPackets++
			}
		}
	}
	if sawOversizedPacket && sawConstrainedMTU && evidence.ConstrainedPackets > 0 {
		evidence.Recoveries = 1
	}
	if evidence.OversizedPackets == 0 || evidence.ConstrainedPackets == 0 || evidence.Recoveries != 1 {
		return systemPMTUDEvidence{}, fmt.Errorf("raw PMTUD evidence is incomplete: %+v", evidence)
	}
	return evidence, nil
}

func countSystemICMPPTB(data []byte, ipv6 bool) (uint64, error) {
	if len(data) < 24 {
		return 0, errors.New("PMTUD pcap is truncated")
	}
	var order binary.ByteOrder
	switch binary.BigEndian.Uint32(data[:4]) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		order = binary.BigEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		order = binary.LittleEndian
	default:
		return 0, errors.New("PMTUD evidence requires classic pcap")
	}
	linkType := order.Uint32(data[20:24])
	var count uint64
	for offset := 24; offset < len(data); {
		if offset+16 > len(data) {
			return 0, errors.New("PMTUD pcap record header is truncated")
		}
		captured := int(order.Uint32(data[offset+8 : offset+12]))
		offset += 16
		if captured <= 0 || offset+captured > len(data) {
			return 0, errors.New("PMTUD pcap record is truncated")
		}
		packet := data[offset : offset+captured]
		offset += captured
		if linkType == 1 {
			if len(packet) < 14 {
				return 0, errors.New("PMTUD ethernet record is truncated")
			}
			packet = packet[14:]
		} else if linkType != 101 {
			return 0, fmt.Errorf("unsupported PMTUD pcap link type %d", linkType)
		}
		if len(packet) < 20 {
			continue
		}
		if !ipv6 && packet[0]>>4 == 4 {
			header := int(packet[0]&0xf) * 4
			if header >= 20 && len(packet) >= header+2 && packet[9] == 1 && packet[header] == 3 && packet[header+1] == 4 {
				count++
			}
		}
		if ipv6 && packet[0]>>4 == 6 && len(packet) >= 42 && packet[6] == 58 && packet[40] == 2 {
			count++
		}
	}
	return count, nil
}
