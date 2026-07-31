package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	signedRunnerConfigDigest = "9f1b2e9660b032f5633d675166e8646c20d1def23fcd13376dff8871f4e9668d"
	signedRunnerConfigPath   = "runner_effective_config.json"
)

func loadEvidenceTrustPolicy(path string) (*EvidenceTrustPolicy, error) {
	var policy EvidenceTrustPolicy
	if err := decodeStrictFile(path, &policy); err != nil {
		return nil, err
	}
	if err := validateEvidenceTrustPolicy(&policy); err != nil {
		return nil, err
	}
	if err := validateRunnerEffectiveConfigFile(filepath.Dir(path), &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

func validateEvidenceTrustPolicy(policy *EvidenceTrustPolicy) error {
	if policy == nil || policy.SchemaVersion != 1 || !validSHA256(policy.TrustStoreSHA256) ||
		!validSHA256(policy.PublicKeySHA256) || strings.TrimSpace(policy.KeyID) == "" {
		return errors.New("evidence trust policy must freeze schema v1, key ID, trust-store digest, and public-key digest")
	}
	runner := policy.Runner
	if runner.ID == "" || runner.OS != "linux" || !slices.Equal(runner.Architectures, []string{"amd64", "arm64"}) ||
		runner.Namespace != "isolated" || runner.TrafficControl == "" || runner.PacketCounters == "" ||
		!validSHA256(runner.EffectiveConfigSHA256) || runner.EffectiveConfigPath != signedRunnerConfigPath ||
		runner.Architecture != "" || runner.KernelRelease != "" || runner.ExecutableSHA256 != "" ||
		runner.SourceSHA256 != "" || runner.ArgvSHA256 != "" {
		return errors.New("evidence trust policy must freeze portable Linux runner capabilities, namespace, traffic control, and packet counters")
	}
	if runner.EffectiveConfigSHA256 != signedRunnerConfigDigest {
		return errors.New("evidence trust policy does not match the repository-audited effective tc/eBPF config digest")
	}
	return nil
}

func validateRunnerEffectiveConfigFile(baseDir string, policy *EvidenceTrustPolicy) error {
	if err := validateEvidenceTrustPolicy(policy); err != nil {
		return err
	}
	path := filepath.Join(baseDir, filepath.Clean(policy.Runner.EffectiveConfigPath))
	if filepath.Dir(path) != filepath.Clean(baseDir) {
		return errors.New("runner effective config must be a sibling of the trust policy")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read runner effective config: %w", err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != policy.Runner.EffectiveConfigSHA256 {
		return errors.New("runner effective config file does not match the policy digest")
	}
	var artifact ConfigArtifact
	if err := decodeStrictJSON(data, &artifact); err != nil {
		return fmt.Errorf("decode runner effective config: %w", err)
	}
	if artifact.SchemaVersion != 1 || artifact.Kind != "transport_runner_effective_config" || artifact.Context != policy.Runner.ID {
		return errors.New("runner effective config has invalid schema, kind, or runner binding")
	}
	want, err := runnerEffectiveConfigRecords()
	if err != nil {
		return err
	}
	if err := requireExactConfig(artifact, want); err != nil {
		return fmt.Errorf("runner effective config differs from the repository contract: %w", err)
	}
	return nil
}

func runnerEffectiveConfigRecords() ([]ConfigRecord, error) {
	records := []ConfigRecord{
		{Key: "ebpf_counter_schema", Value: "phase-profile-artifact-v1"},
		{Key: "ebpf_program", Value: "ebpf-v1"},
		{Key: "firewall", Value: signedFirewallPolicy},
		{Key: "namespace", Value: "isolated"},
		{Key: "namespace_backend", Value: "ip-netns-v1"},
		{Key: "os", Value: "linux"},
		{Key: "runner_id", Value: "flowersec-linux-release-v1"},
		{Key: "traffic_control", Value: "tc-netem-v1"},
	}
	frozenContracts := []struct {
		key   string
		value any
	}{
		{key: "capacity_contract", value: signedCapacityContract},
		{key: "seeded_random_loss_contract", value: struct {
			Sampler       string `json:"sampler"`
			Seed          int64  `json:"seed"`
			Draws         uint64 `json:"draws"`
			BasisPoints   uint32 `json:"loss_basis_points"`
			DatagramBytes uint64 `json:"datagram_bytes"`
		}{"splitmix64-seed-ordinal-v1", seededRandomLossSeed, seededRandomLossDraws, seededRandomLossBasisPoints, seededRandomLossDatagramBytes}},
		{key: "outage_contract", value: struct {
			ConnectionID string `json:"connection_id"`
			StartNS      int64  `json:"start_ns"`
			DurationNS   int64  `json:"duration_ns"`
		}{evidenceConnectionID, outageStartNS, outageDurationNS}},
		{key: "rebind_contract", value: struct {
			ConnectionID string `json:"connection_id"`
			AtNS         int64  `json:"at_ns"`
			Mode         string `json:"mode"`
		}{evidenceConnectionID, rebindAtNS, "same-ip-port"}},
		{key: "quic_pmtud_contract", value: struct {
			ConnectionID  string   `json:"connection_id"`
			OrderedEvents []string `json:"ordered_events"`
		}{evidenceConnectionID, []string{"transport:packet_too_large", "transport:metrics_updated", "application:rpc_completed"}}},
	}
	for _, contract := range frozenContracts {
		encoded, err := json.Marshal(contract.value)
		if err != nil {
			return nil, err
		}
		records = append(records, ConfigRecord{Key: contract.key, Value: string(encoded)})
	}
	for _, profileID := range []string{"clean-v1", "mobile-v1", "edge-v1"} {
		encoded, err := json.Marshal(signedNetworks[profileID])
		if err != nil {
			return nil, err
		}
		records = append(records, ConfigRecord{Key: "network_profile_" + profileID, Value: string(encoded)})
	}
	slices.SortFunc(records, func(left, right ConfigRecord) int { return strings.Compare(left.Key, right.Key) })
	return records, nil
}

func validateTrustStoreAgainstPolicy(path string, trustStore *EvidenceTrustStore, policy *EvidenceTrustPolicy) error {
	if err := validateEvidenceTrustPolicy(policy); err != nil {
		return err
	}
	if err := validateEvidenceTrustStore(trustStore); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != policy.TrustStoreSHA256 {
		return errors.New("evidence trust store does not match the repository-audited digest")
	}
	if len(trustStore.Keys) != 1 || trustStore.Keys[0].KeyID != policy.KeyID {
		return errors.New("evidence trust store does not contain exactly the repository-audited key ID")
	}
	publicKey, _ := base64.StdEncoding.DecodeString(trustStore.Keys[0].PublicKey)
	publicDigest := sha256.Sum256(publicKey)
	if hex.EncodeToString(publicDigest[:]) != policy.PublicKeySHA256 {
		return errors.New("evidence trust store public key does not match the repository-audited digest")
	}
	return nil
}

func validateRunnerAgainstPolicy(runner EvidenceRunner, policy *EvidenceTrustPolicy) error {
	if err := validateEvidenceTrustPolicy(policy); err != nil {
		return err
	}
	want := policy.Runner
	if runner.ID != want.ID || runner.OS != want.OS || !slices.Contains(want.Architectures, runner.Architecture) ||
		runner.KernelRelease == "" || runner.Namespace != want.Namespace ||
		runner.TrafficControl != want.TrafficControl || runner.PacketCounters != want.PacketCounters ||
		runner.EffectiveConfigSHA256 != want.EffectiveConfigSHA256 || !validSHA256(runner.ExecutableSHA256) ||
		!validSHA256(runner.SourceSHA256) || !validSHA256(runner.ArgvSHA256) {
		return fmt.Errorf("signed runner identity does not match repository-audited portable Linux runner policy")
	}
	return nil
}

func validateRunnerLocalConfig(local RunnerLocalConfig, policy *EvidenceTrustPolicy) error {
	if err := validateEvidenceTrustPolicy(policy); err != nil {
		return err
	}
	if local.SchemaVersion != 1 || local.RunnerID != policy.Runner.ID || local.OS != policy.Runner.OS ||
		!slices.Contains(policy.Runner.Architectures, local.Architecture) || strings.TrimSpace(local.KernelRelease) == "" ||
		!validSHA256(local.ExecutableSHA256) || !validSHA256(local.SourceSHA256) || !validSHA256(local.ArgvSHA256) {
		return errors.New("runner local config must bind one supported host and complete deterministic build identity")
	}
	return nil
}

func validRunnerLocalConfigShape(local RunnerLocalConfig) bool {
	return local.SchemaVersion == 1 && strings.TrimSpace(local.RunnerID) != "" && local.OS == "linux" &&
		(local.Architecture == "amd64" || local.Architecture == "arm64") && strings.TrimSpace(local.KernelRelease) != "" &&
		validSHA256(local.ExecutableSHA256) && validSHA256(local.SourceSHA256) && validSHA256(local.ArgvSHA256)
}
