//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func runNativeProofSystemCase(ctx context.Context, destination *artifactDestination, definition releaseCaseDefinition, mode, bpfObject string) (releaseCaseResult, error) {
	if (mode != "normal" && (mode != "race" || definition.ID != "NP-REBIND")) || bpfObject == "" {
		return releaseCaseResult{}, errors.New("native proof system cases require a supported mode and the frozen eBPF object")
	}
	system := releaseCaseDefinition{ID: "SYS-COMMON-KERNEL", Profile: "linux-netns-tc-ebpf-common-kernel"}
	switch definition.ID {
	case "NP-REBIND":
		system = releaseCaseDefinition{ID: "SYS-MIGRATION-REBIND", Profile: "linux-real-path-migration-rebind", Carrier: definition.Carrier}
	case "NP-PMTUD-STATE":
		system = releaseCaseDefinition{ID: "SYS-PMTUD-QUIC-IPV4", Profile: "kernel-pmtud-quic-ipv4", Carrier: definition.Carrier}
	case "NP-TARGET-LOSS":
	default:
		return releaseCaseResult{}, fmt.Errorf("unsupported native proof system case %s", definition.ID)
	}
	started := time.Now()
	probe, err := runWeaknetSystemProbe(ctx, system, bpfObject)
	if err != nil {
		return releaseCaseResult{}, err
	}
	var artifacts []releaseArtifact
	var sources []releaseRawSource
	if definition.ID == "NP-TARGET-LOSS" {
		artifacts, sources, err = writeNativeTargetLossArtifacts(destination, definition, mode, probe)
	} else {
		artifacts, sources, err = writeNativeProofProbeArtifacts(destination, definition, system, mode, probe)
	}
	if err != nil {
		return releaseCaseResult{}, err
	}
	return releaseCaseResult{ID: definition.ID, Profile: definition.Profile, Status: "pass", CompletedOperations: probe.CompletedOperations,
		ElapsedNanoseconds: time.Since(started).Nanoseconds(), Artifacts: artifacts, RawSources: sources}, nil
}

func writeNativeTargetLossArtifacts(destination *artifactDestination, definition releaseCaseDefinition, mode string, probe weaknetSystemProbe) ([]releaseArtifact, []releaseRawSource, error) {
	streamID, err := nativePostLossStreamID(probe.QLOG)
	if err != nil {
		return nil, nil, err
	}
	run := nativeCaseRun{completed: probe.CompletedOperations, qlog: probe.QLOG, connectionID: probe.ConnectionID,
		observations: []nativeApplicationObservation{{event: "targeted_loss_released", streamID: streamID}, {event: "rpc_completed", streamID: streamID, requestID: "target-loss-survivor", status: "ok"}}}
	written, err := writeNativeCaseArtifacts(destination, definition, mode, run, time.Second)
	if err != nil {
		return nil, nil, err
	}
	directory := filepath.Join(destination.root.path, definition.artifactLabel())
	rawPCAP, err := writeRawCaseArtifactBytes(destination, filepath.Join(directory, "raw", "pcap-001.pcap"), "pcap", probe.PCAP)
	if err != nil {
		return nil, nil, err
	}
	pcapSource := releaseRawSource{ID: "pcap-001", Kind: "pcap", Path: rawPCAP.Path, SHA256: rawPCAP.SHA256, SizeBytes: rawPCAP.SizeBytes}
	attribution, err := buildSoakPCAPAttribution(releaseCaseContext(mode, definition.ID), []soakCycleSource{{Ordinal: 1, ConnectionID: probe.ConnectionID, PCAP: probe.PCAP}})
	if err != nil {
		return nil, nil, err
	}
	pcap, err := writeRawCaseArtifact(destination, filepath.Join(directory, "pcap.json"), "pcap", attribution)
	if err != nil {
		return nil, nil, err
	}
	return append(written.Artifacts, pcap), append(written.RawSources, pcapSource), nil
}

func writeNativeProofProbeArtifacts(destination *artifactDestination, definition, system releaseCaseDefinition, mode string, probe weaknetSystemProbe) ([]releaseArtifact, []releaseRawSource, error) {
	directory := filepath.Join(destination.root.path, definition.artifactLabel())
	if err := os.MkdirAll(filepath.Join(directory, "raw"), 0o700); err != nil {
		return nil, nil, err
	}
	rawPCAP, err := writeRawCaseArtifactBytes(destination, filepath.Join(directory, "raw", "pcap-001.pcap"), "pcap", probe.PCAP)
	if err != nil {
		return nil, nil, err
	}
	rawQLOG, err := writeRawCaseArtifactBytes(destination, filepath.Join(directory, "raw", "qlog-001.sqlog"), "qlog-json-seq", probe.QLOG)
	if err != nil {
		return nil, nil, err
	}
	sources := []releaseRawSource{{ID: "pcap-001", Kind: "pcap", Path: rawPCAP.Path, SHA256: rawPCAP.SHA256, SizeBytes: rawPCAP.SizeBytes},
		{ID: "qlog-001", Kind: "qlog", Path: rawQLOG.Path, SHA256: rawQLOG.SHA256, SizeBytes: rawQLOG.SizeBytes}}
	traceRecords, metricsRecords, configRecords, err := weaknetSystemStructuredRecords(system, []weaknetSystemProbe{probe})
	if err != nil {
		return nil, nil, err
	}
	if definition.ID == "NP-REBIND" {
		traceRecords[len(traceRecords)-1].Event = "native_path_rebind_completed"
	} else {
		traceRecords[0].Event = "userspace_pmtud_state_converged"
		for index := range configRecords {
			if configRecords[index].Key == "pmtud" {
				configRecords[index].Value = "userspace-state-machine-v1"
			}
		}
	}
	contextName := releaseCaseContext(mode, definition.ID)
	for index := range traceRecords {
		traceRecords[index].Digest = releaseCaseExecutionID(contextName)
	}
	trace, err := writeRawCaseArtifact(destination, filepath.Join(directory, "trace.json"), "trace", rawTraceArtifact{SchemaVersion: 1, Kind: "transport_trace", Context: contextName, Records: traceRecords})
	if err != nil {
		return nil, nil, err
	}
	metrics, err := writeRawCaseArtifact(destination, filepath.Join(directory, "metrics.json"), "metrics", rawMetricsArtifact{SchemaVersion: 1, Kind: "transport_metrics", Context: contextName, Records: metricsRecords})
	if err != nil {
		return nil, nil, err
	}
	cycle := []soakCycleSource{{Ordinal: 1, ConnectionID: probe.ConnectionID, QLOG: probe.QLOG, PCAP: probe.PCAP}}
	qlogAttribution, err := buildSoakQLOGAttribution(contextName, cycle)
	if err != nil {
		return nil, nil, err
	}
	qlog, err := writeRawCaseArtifact(destination, filepath.Join(directory, "qlog.json"), "qlog", qlogAttribution)
	if err != nil {
		return nil, nil, err
	}
	pcapAttribution, err := buildSoakPCAPAttribution(contextName, cycle)
	if err != nil {
		return nil, nil, err
	}
	pcap, err := writeRawCaseArtifact(destination, filepath.Join(directory, "pcap.json"), "pcap", pcapAttribution)
	if err != nil {
		return nil, nil, err
	}
	configRecords = append(configRecords, rawConfigRecord{Key: "case_id", Value: definition.ID}, rawConfigRecord{Key: "case_profile", Value: definition.Profile},
		rawConfigRecord{Key: "test_id", Value: releaseCaseExecutionID(contextName)}, rawConfigRecord{Key: "trace_sha256", Value: trace.SHA256}, rawConfigRecord{Key: "metrics_sha256", Value: metrics.SHA256})
	config, err := writeRawCaseArtifact(destination, filepath.Join(directory, "config.json"), "config", rawConfigArtifact{SchemaVersion: 1, Kind: "transport_config", Context: contextName, Records: configRecords})
	if err != nil {
		return nil, nil, err
	}
	return []releaseArtifact{trace, qlog, pcap, metrics, config}, sources, nil
}
