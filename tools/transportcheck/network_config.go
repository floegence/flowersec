package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

func performanceNetworkConfigRecords(manifestDigest, profileID, phase string) ([]ConfigRecord, error) {
	network, exists := signedNetworks[profileID]
	if !exists || network == nil {
		return nil, fmt.Errorf("unknown effective network profile %q", profileID)
	}
	encoded, err := json.Marshal(network)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return []ConfigRecord{
		{Key: "effective_network_json", Value: string(encoded)},
		{Key: "effective_network_sha256", Value: hex.EncodeToString(digest[:])},
		{Key: "effective_profile_id", Value: profileID},
		{Key: "effective_tc_config_sha256", Value: signedRunnerConfigDigest},
		{Key: "effective_runner_policy_id", Value: "flowersec-linux-release-v1"},
		{Key: "performance_manifest_digest", Value: manifestDigest},
		{Key: "phase", Value: phase},
	}, nil
}

func validatePerformanceNetworkConfig(builder *resultBuilder, context string, evidence PhaseEvidence, manifest *PerformanceManifest, cell PerformanceCell, phase, baseDir string) error {
	ref, exists := evidence.Artifacts["config"]
	if !exists {
		return errors.New("effective network config artifact is missing")
	}
	data, ok := readArtifact(builder, context, "config", ref, baseDir)
	if !ok {
		return errors.New("effective network config artifact is invalid")
	}
	var artifact ConfigArtifact
	if err := decodeStrictJSON(data, &artifact); err != nil {
		return err
	}
	records, err := performanceNetworkConfigRecords(manifest.Digest, evidence.ProfileID, phase)
	if err != nil {
		return err
	}
	bindings := []struct {
		kind string
		key  string
	}{{"pcap", "pcap_sha256"}, {"metrics", "ebpf_metrics_sha256"}}
	if _, exists := evidence.Artifacts["qlog"]; exists {
		bindings = append(bindings, struct {
			kind string
			key  string
		}{"qlog", "qlog_sha256"})
	}
	for _, binding := range bindings {
		ref, exists := evidence.Artifacts[binding.kind]
		if !exists || !validSHA256(ref.SHA256) {
			return fmt.Errorf("missing bound %s artifact", binding.kind)
		}
		records = append(records, ConfigRecord{Key: binding.key, Value: ref.SHA256})
	}
	if err := requireExactConfig(artifact, records); err != nil {
		return err
	}
	return validatePhaseFaultCounters(builder, context, evidence, manifest, cell.Topology, baseDir)
}

var phaseFaultCounterNames = []string{
	"fault_delay_packets", "fault_jitter_packets", "fault_periodic_loss_packets",
	"fault_burst_loss_packets", "fault_rate_limited_packets", "fault_mtu_drop_packets",
	"fault_queue_overflow_packets", "fault_reorder_packets", "fault_duplicate_packets",
	"fault_outage_events", "fault_outage_duration_ns",
}

func phaseFaultMetricUnit(name string) string {
	if name == "fault_outage_duration_ns" {
		return "nanoseconds"
	}
	return "count"
}

func validatePhaseFaultCounters(builder *resultBuilder, context string, evidence PhaseEvidence, manifest *PerformanceManifest, topology, baseDir string) error {
	data, ok := readArtifact(builder, context, "metrics", evidence.Artifacts["metrics"], baseDir)
	if !ok {
		return errors.New("phase eBPF metrics artifact is invalid")
	}
	var artifact MetricsArtifact
	if err := decodeStrictJSON(data, &artifact); err != nil {
		return err
	}
	values := make(map[string]MetricCounterRecord, len(artifact.Records))
	for _, record := range artifact.Records {
		if _, exists := values[record.Name]; exists {
			return fmt.Errorf("duplicate phase metric %s", record.Name)
		}
		values[record.Name] = record
	}
	profileID := evidence.ProfileID
	wantHit := map[string]bool{}
	switch profileID {
	case "clean-v1":
	case "mobile-v1":
		for _, name := range []string{"fault_delay_packets", "fault_jitter_packets", "fault_periodic_loss_packets", "fault_rate_limited_packets", "fault_mtu_drop_packets", "fault_queue_overflow_packets", "fault_reorder_packets", "fault_duplicate_packets", "fault_outage_events"} {
			wantHit[name] = true
		}
	case "edge-v1":
		for _, name := range []string{"fault_delay_packets", "fault_jitter_packets", "fault_burst_loss_packets", "fault_rate_limited_packets", "fault_mtu_drop_packets", "fault_queue_overflow_packets", "fault_reorder_packets", "fault_duplicate_packets", "fault_outage_events"} {
			wantHit[name] = true
		}
	default:
		return fmt.Errorf("unknown phase network profile %s", profileID)
	}
	for _, name := range phaseFaultCounterNames {
		record, exists := values[name]
		unit := phaseFaultMetricUnit(name)
		if !exists || record.Unit != unit || record.Value < 0 || mathTrunc(record.Value) != record.Value {
			return fmt.Errorf("phase fault metric %s is missing or has invalid %s integer domain", name, unit)
		}
		if name == "fault_outage_duration_ns" {
			continue
		}
		if wantHit[name] && record.Value <= 0 {
			return fmt.Errorf("configured phase fault %s was not exercised", name)
		}
		if !wantHit[name] && record.Value != 0 {
			return fmt.Errorf("phase fault %s was injected outside the frozen network profile", name)
		}
	}
	carrier, err := carrierForTopology(topology)
	if err != nil {
		return err
	}
	var matrix *FaultMatrixContract
	for index := range manifest.FaultMatrix {
		candidate := &manifest.FaultMatrix[index]
		if candidate.ProfileID == profileID && candidate.Carrier == carrier {
			matrix = candidate
			break
		}
	}
	if matrix == nil {
		return fmt.Errorf("phase %s has no fault matrix contract for %s/%s", context, profileID, carrier)
	}
	if duration := values["fault_outage_duration_ns"]; duration.Value != float64(matrix.OutageDurationNS) {
		return fmt.Errorf("phase fault outage duration = %v, want %d", duration.Value, matrix.OutageDurationNS)
	}
	for name, unit := range map[string]string{"ebpf_packets": "count", "ebpf_bytes": "bytes"} {
		record, exists := values[name]
		if !exists || record.Unit != unit || record.Value <= 0 || mathTrunc(record.Value) != record.Value {
			return fmt.Errorf("phase %s does not contain positive typed eBPF %s", context, name)
		}
	}
	return nil
}

func requireExactConfig(artifact ConfigArtifact, want []ConfigRecord) error {
	if len(artifact.Records) != len(want) {
		return fmt.Errorf("config has %d records, want exactly %d", len(artifact.Records), len(want))
	}
	values := make(map[string]string, len(artifact.Records))
	for _, record := range artifact.Records {
		if _, exists := values[record.Key]; exists {
			return fmt.Errorf("duplicate config %s", record.Key)
		}
		values[record.Key] = record.Value
	}
	for _, record := range want {
		if values[record.Key] != record.Value {
			return fmt.Errorf("config %s = %q, want %q", record.Key, values[record.Key], record.Value)
		}
	}
	return nil
}
