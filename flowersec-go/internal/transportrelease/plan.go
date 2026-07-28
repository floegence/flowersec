package transportrelease

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

const FrozenPerformanceManifestDigest = "sha256:328c680ff4f843435ac5574b494e57ba6c21e7161bb9020e678ec0d76ab7ca10"

var frozenPerformanceManifestSHA256 = [32]byte{
	0x14, 0xca, 0x3e, 0x7e, 0x3a, 0x90, 0x94, 0x63,
	0xa1, 0x0a, 0x34, 0x73, 0xeb, 0xe8, 0x3b, 0xed,
	0x45, 0xaf, 0x8d, 0x80, 0x08, 0xde, 0xea, 0xdc,
	0x50, 0x31, 0xf0, 0x09, 0x93, 0x93, 0xf7, 0x5d,
}

// ReleasePlan is the executable workload subset of the frozen performance
// manifest. Other cells remain owned by their topology-specific collectors.
type ReleasePlan struct {
	RunCount int
	Clean    ProfilePlan
	Mobile   ProfilePlan
	Edge     ProfilePlan
	Adaptive AdaptivePlan
}

type AdaptivePlan struct {
	ID                  string
	Stages              []AdaptiveStagePlan
	HarnessSlackSeconds int
	CellWatchdogMinutes int
}

type AdaptiveStagePlan struct {
	ProfileID              string   `json:"profile_id"`
	Cold                   ColdPlan `json:"cold"`
	CleanupDeadlineSeconds int      `json:"cleanup_deadline_seconds"`
}

type ManifestBinding struct {
	Digest    string
	SHA256Sum [32]byte
}

type ProfilePlan struct {
	ID                     string
	Cold                   ColdPlan
	RPC                    RPCPlan
	Bulk                   BulkPlan
	Network                NetworkPlan
	Fault                  FaultPlan
	CleanupDeadlineSeconds int
	CellWatchdogMinutes    int
}

type FaultPlan struct {
	ReorderPercent   int           `json:"reorder_percent"`
	DuplicatePercent int           `json:"duplicate_percent"`
	OutageStart      time.Duration `json:"outage_start_ns"`
	OutageDuration   time.Duration `json:"outage_duration_ns"`
}

type NetworkPlan struct {
	EvidenceLayer           string     `json:"evidence_layer"`
	OneWayDelayMilliseconds int        `json:"one_way_delay_milliseconds"`
	JitterMilliseconds      []int      `json:"jitter_milliseconds"`
	Loss                    LossPlan   `json:"loss"`
	ReorderPercent          int        `json:"reorder_percent"`
	DuplicatePercent        int        `json:"duplicate_percent"`
	Shape                   *ShapePlan `json:"shape"`
	LinkMTU                 int        `json:"link_mtu"`
	Firewall                string     `json:"firewall"`
}

type LossPlan struct {
	Mode       string `json:"mode"`
	EveryNth   int    `json:"every_nth"`
	BlockSize  int    `json:"block_size"`
	BurstFirst int    `json:"burst_first"`
	BurstLast  int    `json:"burst_last"`
}

type ShapePlan struct {
	RateBitsPerSecond int `json:"rate_bits_per_second"`
	TokenBurstBytes   int `json:"token_burst_bytes"`
	QueueBytes        int `json:"queue_bytes"`
}

type ColdPlan struct {
	Operations               int `json:"operations"`
	MaxInflight              int `json:"max_inflight"`
	Retries                  int `json:"retries"`
	StartRatePerSecond       int `json:"start_rate_per_second"`
	OperationDeadlineSeconds int `json:"operation_deadline_seconds"`
	PhaseDeadlineSeconds     int `json:"phase_deadline_seconds"`
}

type RPCPlan struct {
	Operations               int `json:"operations"`
	RequestBytes             int `json:"request_bytes"`
	ResponseBytes            int `json:"response_bytes"`
	Workers                  int `json:"workers"`
	Retries                  int `json:"retries"`
	OperationDeadlineSeconds int `json:"operation_deadline_seconds"`
	PhaseDeadlineSeconds     int `json:"phase_deadline_seconds"`
}

type BulkPlan struct {
	WarmupBytesPerDirection int64 `json:"warmup_bytes_per_direction"`
	ScoreBytesPerDirection  int64 `json:"score_bytes_per_direction"`
	PhaseDeadlineSeconds    int   `json:"phase_deadline_seconds"`
}

type manifestPlan struct {
	SchemaVersion int    `json:"schema_version"`
	Digest        string `json:"digest"`
	RunCount      int    `json:"run_count"`
	Profiles      []struct {
		ID                     string              `json:"id"`
		Mode                   string              `json:"mode"`
		Cold                   *ColdPlan           `json:"cold"`
		RPC                    *RPCPlan            `json:"rpc"`
		Bulk                   *BulkPlan           `json:"bulk"`
		Network                *NetworkPlan        `json:"network"`
		AdaptiveStages         []AdaptiveStagePlan `json:"adaptive_stages"`
		HarnessSlackSeconds    int                 `json:"harness_slack_seconds"`
		CleanupDeadlineSeconds int                 `json:"cleanup_deadline_seconds"`
		CellWatchdogMinutes    int                 `json:"cell_watchdog_minutes"`
	} `json:"profiles"`
	FaultMatrix []struct {
		ProfileID        string `json:"profile_id"`
		Carrier          string `json:"carrier"`
		ReorderPercent   int    `json:"reorder_percent"`
		DuplicatePercent int    `json:"duplicate_percent"`
		OutageStartNS    int64  `json:"outage_start_ns"`
		OutageDurationNS int64  `json:"outage_duration_ns"`
	} `json:"fault_matrix"`
}

// LoadReleasePlan reads workload values from the manifest instead of copying
// them into runner flags or reconstructing them after collection.
func LoadReleasePlan(path string) (ReleasePlan, ManifestBinding, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ReleasePlan{}, ManifestBinding{}, err
	}
	var manifest manifestPlan
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return ReleasePlan{}, ManifestBinding{}, err
	}
	rawSum := sha256.Sum256(raw)
	if manifest.SchemaVersion != 1 || manifest.RunCount != 15 || manifest.Digest != FrozenPerformanceManifestDigest || rawSum != frozenPerformanceManifestSHA256 {
		return ReleasePlan{}, ManifestBinding{}, errors.New("performance manifest does not match the frozen release contract")
	}
	binding := ManifestBinding{Digest: manifest.Digest, SHA256Sum: rawSum}
	faultPlans, err := loadFaultPlans(manifest.FaultMatrix)
	if err != nil {
		return ReleasePlan{}, ManifestBinding{}, err
	}
	profiles := make(map[string]ProfilePlan, 3)
	var adaptive AdaptivePlan
	for _, profile := range manifest.Profiles {
		if profile.ID == "adaptive-selection-v1" {
			if profile.Mode != "adaptive" || profile.Cold != nil || profile.RPC != nil || profile.Bulk != nil || profile.Network != nil ||
				profile.CleanupDeadlineSeconds != 0 || len(profile.AdaptiveStages) != 2 {
				return ReleasePlan{}, ManifestBinding{}, errors.New("adaptive-selection-v1 workload is incomplete")
			}
			adaptive = AdaptivePlan{
				ID: profile.ID, Stages: append([]AdaptiveStagePlan(nil), profile.AdaptiveStages...),
				HarnessSlackSeconds: profile.HarnessSlackSeconds, CellWatchdogMinutes: profile.CellWatchdogMinutes,
			}
			continue
		}
		if profile.ID != "clean-v1" && profile.ID != "mobile-v1" && profile.ID != "edge-v1" {
			continue
		}
		if profile.Mode != "forced" || profile.Cold == nil || profile.RPC == nil || profile.Bulk == nil || profile.Network == nil {
			return ReleasePlan{}, ManifestBinding{}, fmt.Errorf("%s workload is incomplete", profile.ID)
		}
		plan := ProfilePlan{
			ID: profile.ID, Cold: *profile.Cold, RPC: *profile.RPC, Bulk: *profile.Bulk,
			Network: *profile.Network, Fault: faultPlans[profile.ID],
			CleanupDeadlineSeconds: profile.CleanupDeadlineSeconds, CellWatchdogMinutes: profile.CellWatchdogMinutes,
		}
		if err := validateProfilePlan(plan); err != nil {
			return ReleasePlan{}, ManifestBinding{}, err
		}
		profiles[profile.ID] = plan
	}
	if len(profiles) != 3 {
		return ReleasePlan{}, ManifestBinding{}, errors.New("performance manifest must contain clean-v1, mobile-v1, and edge-v1 profiles")
	}
	if err := validateAdaptivePlan(adaptive, profiles, manifest.RunCount); err != nil {
		return ReleasePlan{}, ManifestBinding{}, err
	}
	return ReleasePlan{
		RunCount: manifest.RunCount,
		Clean:    profiles["clean-v1"], Mobile: profiles["mobile-v1"], Edge: profiles["edge-v1"],
		Adaptive: adaptive,
	}, binding, nil
}

func validateAdaptivePlan(plan AdaptivePlan, profiles map[string]ProfilePlan, runCount int) error {
	if plan.ID != "adaptive-selection-v1" || len(plan.Stages) != 2 || plan.HarnessSlackSeconds != 45 || plan.CellWatchdogMinutes != 5 {
		return errors.New("adaptive-selection-v1 does not match the frozen release contract")
	}
	phaseSeconds := 0
	for index, profileID := range []string{"clean-v1", "mobile-v1"} {
		stage := plan.Stages[index]
		profile, ok := profiles[profileID]
		if !ok || stage.ProfileID != profileID || stage.Cold != profile.Cold || stage.CleanupDeadlineSeconds != profile.CleanupDeadlineSeconds {
			return fmt.Errorf("adaptive stage %d must reuse the exact %s cold and cleanup workload", index+1, profileID)
		}
		phaseSeconds += stage.Cold.PhaseDeadlineSeconds + stage.CleanupDeadlineSeconds
	}
	if runCount*phaseSeconds+plan.HarnessSlackSeconds > plan.CellWatchdogMinutes*60 {
		return errors.New("adaptive-selection-v1 watchdog cannot cover every real stage run")
	}
	return nil
}

func loadFaultPlans(rows []struct {
	ProfileID        string `json:"profile_id"`
	Carrier          string `json:"carrier"`
	ReorderPercent   int    `json:"reorder_percent"`
	DuplicatePercent int    `json:"duplicate_percent"`
	OutageStartNS    int64  `json:"outage_start_ns"`
	OutageDurationNS int64  `json:"outage_duration_ns"`
}) (map[string]FaultPlan, error) {
	wantCarriers := map[string]struct{}{"wss": {}, "raw_quic": {}, "webtransport": {}}
	plans := make(map[string]FaultPlan, 3)
	seen := make(map[string]map[string]struct{}, 3)
	for _, row := range rows {
		if row.ProfileID != "clean-v1" && row.ProfileID != "mobile-v1" && row.ProfileID != "edge-v1" {
			continue
		}
		if _, ok := wantCarriers[row.Carrier]; !ok {
			return nil, fmt.Errorf("fault matrix has unsupported carrier %q", row.Carrier)
		}
		if seen[row.ProfileID] == nil {
			seen[row.ProfileID] = make(map[string]struct{}, 3)
		}
		if _, duplicate := seen[row.ProfileID][row.Carrier]; duplicate {
			return nil, fmt.Errorf("fault matrix repeats %s/%s", row.ProfileID, row.Carrier)
		}
		seen[row.ProfileID][row.Carrier] = struct{}{}
		plan := FaultPlan{
			ReorderPercent: row.ReorderPercent, DuplicatePercent: row.DuplicatePercent,
			OutageStart: time.Duration(row.OutageStartNS), OutageDuration: time.Duration(row.OutageDurationNS),
		}
		if previous, ok := plans[row.ProfileID]; ok && previous != plan {
			return nil, fmt.Errorf("fault matrix differs by carrier for %s", row.ProfileID)
		}
		plans[row.ProfileID] = plan
	}
	for _, profileID := range []string{"clean-v1", "mobile-v1", "edge-v1"} {
		if len(seen[profileID]) != len(wantCarriers) {
			return nil, fmt.Errorf("fault matrix is incomplete for %s", profileID)
		}
	}
	return plans, nil
}

func validateProfilePlan(plan ProfilePlan) error {
	if plan.Cold.Operations < 1 || plan.Cold.MaxInflight < 1 || plan.Cold.MaxInflight > plan.Cold.Operations ||
		plan.Cold.StartRatePerSecond < 1 || plan.Cold.OperationDeadlineSeconds < 1 || plan.Cold.PhaseDeadlineSeconds < 1 ||
		plan.RPC.Operations < 1 || plan.RPC.Workers < 1 || plan.RPC.Workers > plan.RPC.Operations ||
		plan.RPC.RequestBytes < 2 || plan.RPC.ResponseBytes != plan.RPC.RequestBytes ||
		plan.RPC.OperationDeadlineSeconds < 1 || plan.RPC.PhaseDeadlineSeconds < 1 ||
		plan.Bulk.WarmupBytesPerDirection < 1 || plan.Bulk.ScoreBytesPerDirection < 1 || plan.Bulk.PhaseDeadlineSeconds < 1 ||
		plan.CleanupDeadlineSeconds < 1 || plan.CellWatchdogMinutes < 1 {
		return fmt.Errorf("profile %s has invalid workload bounds", plan.ID)
	}
	if plan.Cold.Retries != 0 || plan.RPC.Retries != 0 {
		return fmt.Errorf("profile %s must execute with zero retries", plan.ID)
	}
	if err := validateNetworkPlan(plan); err != nil {
		return err
	}
	return nil
}

func validateNetworkPlan(plan ProfilePlan) error {
	network := plan.Network
	if network.EvidenceLayer != "kernel_packet" || network.OneWayDelayMilliseconds < 0 ||
		len(network.JitterMilliseconds) == 0 || network.ReorderPercent < 0 || network.DuplicatePercent < 0 ||
		network.LinkMTU < 1280 || network.Firewall == "" {
		return fmt.Errorf("profile %s has invalid network bounds", plan.ID)
	}
	for _, jitter := range network.JitterMilliseconds {
		if network.OneWayDelayMilliseconds+jitter < 0 {
			return fmt.Errorf("profile %s has negative effective network delay", plan.ID)
		}
	}
	switch network.Loss.Mode {
	case "none":
		if network.Loss.EveryNth != 0 || network.Loss.BlockSize != 0 || network.Loss.BurstFirst != 0 || network.Loss.BurstLast != 0 {
			return fmt.Errorf("profile %s has invalid none loss plan", plan.ID)
		}
	case "periodic":
		if network.Loss.EveryNth < 2 {
			return fmt.Errorf("profile %s has invalid periodic loss plan", plan.ID)
		}
	case "burst":
		if network.Loss.BlockSize < 1 || network.Loss.BurstFirst < 1 || network.Loss.BurstLast < network.Loss.BurstFirst || network.Loss.BurstLast > network.Loss.BlockSize {
			return fmt.Errorf("profile %s has invalid burst loss plan", plan.ID)
		}
	default:
		return fmt.Errorf("profile %s has unknown loss mode", plan.ID)
	}
	if network.Shape != nil && (network.Shape.RateBitsPerSecond < 1 || network.Shape.TokenBurstBytes < 1 || network.Shape.QueueBytes < network.Shape.TokenBurstBytes) {
		return fmt.Errorf("profile %s has invalid traffic shape", plan.ID)
	}
	return nil
}
