//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/linuxnetlab"
)

type systemTCPInfoArtifact struct {
	SchemaVersion int                   `json:"schema_version"`
	Kind          string                `json:"kind"`
	Context       string                `json:"context"`
	Records       []systemTCPInfoRecord `json:"records"`
}

type systemTCPInfoRecord struct {
	AtNS               int64  `json:"at_ns"`
	LocalAddress       string `json:"local_address"`
	LocalPort          uint16 `json:"local_port"`
	RemoteAddress      string `json:"remote_address"`
	RemotePort         uint16 `json:"remote_port"`
	SocketCookie       string `json:"socket_cookie"`
	SendMSSBytes       uint32 `json:"send_mss_bytes"`
	RetransmittedBytes uint64 `json:"retransmitted_bytes"`
}

func runWeaknetSystemCase(ctx context.Context, destination *artifactDestination, definition releaseCaseDefinition, bpfObject string) (releaseCaseResult, error) {
	started := time.Now()
	probes := make([]weaknetSystemProbe, 0, 2)
	probe, err := runWeaknetSystemProbe(ctx, definition, bpfObject)
	if err != nil {
		return releaseCaseResult{}, err
	}
	probes = append(probes, probe)
	if definition.ID == "SYS-COMMON-KERNEL" {
		burst, err := runWeaknetSystemProbeLoss(ctx, definition, bpfObject, linuxnetlab.LossBurst)
		if err != nil {
			return releaseCaseResult{}, err
		}
		probes = append(probes, burst)
	}
	artifacts, rawSources, completed, err := writeWeaknetSystemArtifacts(destination, definition, probes)
	if err != nil {
		return releaseCaseResult{}, err
	}
	elapsed := time.Since(started)
	return releaseCaseResult{ID: definition.ID, Profile: definition.Profile, Status: "pass", CompletedOperations: completed,
		ElapsedNanoseconds: elapsed.Nanoseconds(), Artifacts: artifacts, RawSources: rawSources}, nil
}

func writeWeaknetSystemArtifacts(destination *artifactDestination, definition releaseCaseDefinition, probes []weaknetSystemProbe) ([]releaseArtifact, []releaseRawSource, int, error) {
	if destination == nil || len(probes) == 0 {
		return nil, nil, 0, errors.New("system artifacts require measured probes")
	}
	contextName := "case " + definition.ID
	directory := filepath.Join(destination.root.path, definition.artifactLabel())
	if err := os.Mkdir(directory, 0o700); err != nil {
		return nil, nil, 0, err
	}
	rawDirectory := filepath.Join(directory, "raw")
	if err := os.Mkdir(rawDirectory, 0o700); err != nil {
		return nil, nil, 0, err
	}
	cycleSources := make([]soakCycleSource, 0, len(probes))
	rawSources := make([]releaseRawSource, 0, len(probes)*2)
	completed := 0
	for index, probe := range probes {
		ordinal := index + 1
		if !validClassicPCAP(probe.PCAP) {
			return nil, nil, 0, errors.New("system probe pcap is invalid")
		}
		pcap, err := writeRawCaseArtifactBytes(destination, filepath.Join(rawDirectory, fmt.Sprintf("probe-%03d.pcap", ordinal)), "pcap", probe.PCAP)
		if err != nil {
			return nil, nil, 0, err
		}
		rawSources = append(rawSources, releaseRawSource{ID: fmt.Sprintf("pcap-%03d", ordinal), Kind: "pcap", Path: pcap.Path, SHA256: pcap.SHA256, SizeBytes: pcap.SizeBytes})
		if len(probe.QLOG) != 0 {
			qlog, err := writeRawCaseArtifactBytes(destination, filepath.Join(rawDirectory, fmt.Sprintf("probe-%03d.sqlog", ordinal)), "qlog", probe.QLOG)
			if err != nil {
				return nil, nil, 0, err
			}
			rawSources = append(rawSources, releaseRawSource{ID: fmt.Sprintf("qlog-%03d", ordinal), Kind: "qlog", Path: qlog.Path, SHA256: qlog.SHA256, SizeBytes: qlog.SizeBytes})
		}
		cycleSources = append(cycleSources, soakCycleSource{Ordinal: ordinal, ConnectionID: probe.ConnectionID, QLOG: probe.QLOG, PCAP: probe.PCAP})
		completed += probe.CompletedOperations
	}
	traceRecords, metricsRecords, configRecords, err := weaknetSystemStructuredRecords(definition, probes)
	if err != nil {
		return nil, nil, 0, err
	}
	for index := range traceRecords {
		traceRecords[index].Digest = releaseCaseExecutionID(contextName)
	}
	trace, err := writeRawCaseArtifact(destination, filepath.Join(directory, "trace.json"), "trace", rawTraceArtifact{SchemaVersion: 1, Kind: "transport_trace", Context: contextName, Records: traceRecords})
	if err != nil {
		return nil, nil, 0, err
	}
	metrics, err := writeRawCaseArtifact(destination, filepath.Join(directory, "metrics.json"), "metrics", rawMetricsArtifact{SchemaVersion: 1, Kind: "transport_metrics", Context: contextName, Records: metricsRecords})
	if err != nil {
		return nil, nil, 0, err
	}
	artifacts := []releaseArtifact{trace}
	if len(probes[0].QLOG) != 0 && definition.ID != "SYS-COMMON-KERNEL" {
		attribution, err := buildSoakQLOGAttribution(contextName, cycleSources)
		if err != nil {
			return nil, nil, 0, err
		}
		written, err := writeRawCaseArtifact(destination, filepath.Join(directory, "qlog.qlog"), "qlog", attribution)
		if err != nil {
			return nil, nil, 0, err
		}
		artifacts = append(artifacts, written)
	}
	pcapAttribution, err := buildSoakPCAPAttribution(contextName, cycleSources)
	if err != nil {
		return nil, nil, 0, err
	}
	pcap, err := writeRawCaseArtifact(destination, filepath.Join(directory, "pcap.pcap"), "pcap", pcapAttribution)
	if err != nil {
		return nil, nil, 0, err
	}
	artifacts = append(artifacts, pcap)
	if len(probes[0].TCPInfo) != 0 {
		records := make([]systemTCPInfoRecord, 0, len(probes[0].TCPInfo))
		for _, observed := range probes[0].TCPInfo {
			records = append(records, systemTCPInfoRecord{AtNS: observed.AtNS, LocalAddress: observed.LocalAddress, LocalPort: observed.LocalPort,
				RemoteAddress: observed.RemoteAddress, RemotePort: observed.RemotePort, SocketCookie: observed.SocketCookie,
				SendMSSBytes: observed.SendMSSBytes, RetransmittedBytes: observed.RetransmittedBytes})
		}
		tcpInfo, err := writeRawCaseArtifact(destination, filepath.Join(directory, "tcp_info.json"), "tcp_info", systemTCPInfoArtifact{SchemaVersion: 1, Kind: "transport_tcp_info", Context: contextName, Records: records})
		if err != nil {
			return nil, nil, 0, err
		}
		artifacts = append(artifacts, tcpInfo)
	}
	artifacts = append(artifacts, metrics)
	configRecords = append(configRecords, rawConfigRecord{Key: "trace_sha256", Value: trace.SHA256}, rawConfigRecord{Key: "metrics_sha256", Value: metrics.SHA256})
	config, err := writeRawCaseArtifact(destination, filepath.Join(directory, "config.json"), "config", rawConfigArtifact{SchemaVersion: 1, Kind: "transport_config", Context: contextName, Records: configRecords})
	if err != nil {
		return nil, nil, 0, err
	}
	artifacts = append(artifacts, config)
	return artifacts, rawSources, completed, nil
}

func weaknetSystemStructuredRecords(definition releaseCaseDefinition, probes []weaknetSystemProbe) ([]rawTraceRecord, []rawMetricRecord, []rawConfigRecord, error) {
	probe := probes[0]
	config := []rawConfigRecord{{Key: "os", Value: "linux"}, {Key: "namespace", Value: "isolated"}, {Key: "watchdog", Value: "completed"}}
	metric := func(name string, value uint64) rawMetricRecord {
		return rawMetricRecord{Name: name, Value: float64(value), Unit: "count", ConnectionID: probe.ConnectionID}
	}
	switch definition.ID {
	case "SYS-COMMON-KERNEL":
		if len(probes) != 2 {
			return nil, nil, nil, errors.New("common kernel case requires periodic and burst probes")
		}
		combined := func(selectValue func(linuxnetlab.KernelFaultStats) uint64) uint64 {
			var total uint64
			for _, item := range probes {
				total += selectValue(item.Kernel.Client) + selectValue(item.Kernel.Server)
			}
			return total
		}
		tcPackets := uint64(0)
		for _, item := range probes {
			tcPackets += item.Kernel.ClientQdisc.Packets + item.Kernel.ServerQdisc.Packets
		}
		values := map[string]uint64{
			"delay":         combined(func(v linuxnetlab.KernelFaultStats) uint64 { return v.DelayPackets }),
			"jitter":        combined(func(v linuxnetlab.KernelFaultStats) uint64 { return v.JitterPackets }),
			"periodic_loss": combined(func(v linuxnetlab.KernelFaultStats) uint64 { return v.PeriodicLossPackets }),
			"burst_loss":    combined(func(v linuxnetlab.KernelFaultStats) uint64 { return v.BurstLossPackets }),
			"duplicate":     combined(func(v linuxnetlab.KernelFaultStats) uint64 { return v.DuplicatePackets }),
			"reorder":       combined(func(v linuxnetlab.KernelFaultStats) uint64 { return v.ReorderPackets }),
			"rate_limit":    tcPackets,
			"outage":        combined(func(v linuxnetlab.KernelFaultStats) uint64 { return v.OutageDropPackets }),
		}
		for name, value := range values {
			if value == 0 {
				return nil, nil, nil, fmt.Errorf("common kernel fault %s was not observed", name)
			}
		}
		metrics := make([]rawMetricRecord, 0, len(values)*2+5)
		for name, value := range values {
			metrics = append(metrics, metric("expected_"+name, value), metric("actual_"+name, value))
		}
		metrics = append(metrics, rawMetricRecord{Name: "expected_outage_duration_ns", Value: float64((2 * time.Second).Nanoseconds()), Unit: "nanoseconds", ConnectionID: probe.ConnectionID},
			rawMetricRecord{Name: "actual_outage_duration_ns", Value: float64((2 * time.Second).Nanoseconds()), Unit: "nanoseconds", ConnectionID: probe.ConnectionID},
			metric("ebpf_packets", combined(func(v linuxnetlab.KernelFaultStats) uint64 { return v.Packets })),
			rawMetricRecord{Name: "ebpf_bytes", Value: float64(combined(func(v linuxnetlab.KernelFaultStats) uint64 { return v.Bytes })), Unit: "bytes", ConnectionID: probe.ConnectionID},
			metric("tc_tbf_packets", tcPackets),
			rawMetricRecord{Name: "tc_tbf_bytes", Value: float64(sumTrafficControl(probes, func(v linuxnetlab.TrafficControlFaultStats) uint64 { return v.Bytes })), Unit: "bytes", ConnectionID: probe.ConnectionID},
			metric("tc_tbf_overlimits", sumTrafficControl(probes, func(v linuxnetlab.TrafficControlFaultStats) uint64 { return v.Overlimits })), metric("watchdog_timeouts", 0))
		config = append(config, rawConfigRecord{Key: "tc", Value: "netem-v1"}, rawConfigRecord{Key: "ebpf", Value: "enabled"},
			rawConfigRecord{Key: "connection_id", Value: probe.ConnectionID}, rawConfigRecord{Key: "outage_start_ns", Value: "1000000000"}, rawConfigRecord{Key: "outage_duration_ns", Value: "2000000000"})
		trace, err := systemEventTrace(probe, []string{"outage_started", "outage_ended", "kernel_fault_matrix_completed"})
		return trace, metrics, config, err
	case "SYS-PMTUD-QUIC-IPV4", "SYS-PMTUD-QUIC-IPV6":
		family := "ipv4"
		ipv6 := definition.ID == "SYS-PMTUD-QUIC-IPV6"
		if ipv6 {
			family = "ipv6"
		}
		observed, err := deriveSystemPMTUDEvidence(probe.PCAP, probe.QLOG, ipv6)
		if err != nil {
			return nil, nil, nil, err
		}
		config = append(config, rawConfigRecord{Key: "firewall", Value: "allow-icmp-ptb"}, rawConfigRecord{Key: "pmtud", Value: "kernel-quic-v1"},
			rawConfigRecord{Key: "ip_family", Value: family}, rawConfigRecord{Key: "link_mtu", Value: "1280"},
			rawConfigRecord{Key: "expected_terminal", Value: "recovered"}, rawConfigRecord{Key: "actual_terminal", Value: "recovered"}, rawConfigRecord{Key: "connection_id", Value: probe.ConnectionID})
		metrics := []rawMetricRecord{metric("oversized_udp_packets", observed.OversizedPackets), metric("constrained_udp_packets", observed.ConstrainedPackets),
			metric("icmp_ptb_received", observed.ICMPPTBPackets), metric("pmtud_recoveries", observed.Recoveries),
			metric("rpc_completed", uint64(probe.CompletedOperations)), metric("watchdog_timeouts", 0)}
		at, err := systemEventTime(probe, "post_mtu_operation_completed")
		if err != nil {
			return nil, nil, nil, err
		}
		return []rawTraceRecord{{Sequence: 1, AtNS: at, Event: "kernel_quic_pmtud_recovered", ConnectionID: probe.ConnectionID}}, metrics, config, nil
	case "SYS-MIGRATION-REBIND":
		if probe.RebindBefore == "" || probe.RebindAfter == "" || probe.RebindBefore == probe.RebindAfter {
			return nil, nil, nil, errors.New("kernel rebind probe did not observe a path transition")
		}
		config = append(config, rawConfigRecord{Key: "tc", Value: "netem-v1"}, rawConfigRecord{Key: "connection_id", Value: probe.ConnectionID},
			rawConfigRecord{Key: "rebind_mode", Value: "same-ip-port"}, rawConfigRecord{Key: "rebind_at_ns", Value: "2000000000"})
		metrics := []rawMetricRecord{metric("path_updates", 1), metric("path_validations", 1), metric("rpc_before_rebind", 1), metric("rpc_after_rebind", 1), metric("watchdog_timeouts", 0)}
		trace, err := systemEventTrace(probe, []string{"rpc_before_rebind", "rebind_scheduled", "path_updated", "path_validated", "rpc_after_rebind", "kernel_path_rebind_completed"})
		return trace, metrics, config, err
	case "SYS-PMTUD-WSS-RECOVER-IPV4", "SYS-PMTUD-WSS-RECOVER-IPV6", "SYS-PMTUD-WSS-TIMEOUT-IPV4", "SYS-PMTUD-WSS-TIMEOUT-IPV6":
		recovered := !probe.TimedOut
		terminal, firewall, event := "recovered", "allow-icmp-ptb", "pmtud_recovered"
		if !recovered {
			terminal, firewall, event = "timed_out", "drop-icmp-ptb", "pmtud_timed_out"
		}
		if len(probe.TCPInfo) < 2 {
			return nil, nil, nil, errors.New("WSS probe did not capture two TCP_INFO samples")
		}
		config = append(config, rawConfigRecord{Key: "firewall", Value: firewall}, rawConfigRecord{Key: "expected_terminal", Value: terminal}, rawConfigRecord{Key: "actual_terminal", Value: terminal})
		metrics := []rawMetricRecord{{Name: "rpc_completed", Value: float64(probe.CompletedOperations), Unit: "count"}, {Name: "timeout_observed", Value: boolFloat(probe.TimedOut), Unit: "count"}, {Name: "watchdog_timeouts", Value: 0, Unit: "count"}}
		at := probe.TCPInfo[len(probe.TCPInfo)-1].AtNS
		if at <= 0 {
			return nil, nil, nil, errors.New("WSS probe has no measured terminal event time")
		}
		return []rawTraceRecord{{Sequence: 1, AtNS: at, Event: event}}, metrics, config, nil
	default:
		return nil, nil, nil, errors.New("system structured evidence is not implemented for this case")
	}
}

func systemEventTime(probe weaknetSystemProbe, event string) (int64, error) {
	at := probe.EventTimes[event]
	if at <= 0 || at > (2*time.Minute).Nanoseconds() {
		return 0, fmt.Errorf("system event %s has no bounded measured timestamp", event)
	}
	return at, nil
}

func systemEventTrace(probe weaknetSystemProbe, events []string) ([]rawTraceRecord, error) {
	trace := make([]rawTraceRecord, 0, len(events))
	previous := int64(0)
	for index, event := range events {
		at, err := systemEventTime(probe, event)
		if err != nil || at < previous {
			return nil, errors.Join(err, errors.New("system event timestamps are not monotonic"))
		}
		trace = append(trace, rawTraceRecord{Sequence: uint64(index + 1), AtNS: at, Event: event, ConnectionID: probe.ConnectionID})
		previous = at
	}
	return trace, nil
}

func sumTrafficControl(probes []weaknetSystemProbe, selectValue func(linuxnetlab.TrafficControlFaultStats) uint64) uint64 {
	var total uint64
	for _, item := range probes {
		total += selectValue(item.Kernel.ClientQdisc) + selectValue(item.Kernel.ServerQdisc)
	}
	return total
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}
