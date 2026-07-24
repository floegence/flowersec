package transportrelease

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const FrozenPerformanceManifestDigest = "sha256:86435fbb90771090976a01a19f630faa783adbb0f6cc250ddbd8b0712c8cadee"

var frozenPerformanceManifestSHA256 = [32]byte{
	0x24, 0xa4, 0xb5, 0xd1, 0x0f, 0x63, 0xff, 0x19,
	0x5b, 0x46, 0x80, 0xe3, 0xeb, 0xa9, 0xc8, 0x74,
	0x6f, 0x6e, 0x44, 0x30, 0x26, 0xa5, 0x6c, 0xef,
	0x4c, 0x4d, 0x90, 0xa7, 0xac, 0x0c, 0xf1, 0x2e,
}

// ReleasePlan is the executable workload subset of the frozen performance
// manifest. Other cells remain owned by their topology-specific collectors.
type ReleasePlan struct {
	RunCount int
	Clean    ProfilePlan
	Mobile   ProfilePlan
	Edge     ProfilePlan
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
	CleanupDeadlineSeconds int
	CellWatchdogMinutes    int
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
		ID                     string       `json:"id"`
		Mode                   string       `json:"mode"`
		Cold                   *ColdPlan    `json:"cold"`
		RPC                    *RPCPlan     `json:"rpc"`
		Bulk                   *BulkPlan    `json:"bulk"`
		Network                *NetworkPlan `json:"network"`
		CleanupDeadlineSeconds int          `json:"cleanup_deadline_seconds"`
		CellWatchdogMinutes    int          `json:"cell_watchdog_minutes"`
	} `json:"profiles"`
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
	profiles := make(map[string]ProfilePlan, 3)
	for _, profile := range manifest.Profiles {
		if profile.ID != "clean-v1" && profile.ID != "mobile-v1" && profile.ID != "edge-v1" {
			continue
		}
		if profile.Mode != "forced" || profile.Cold == nil || profile.RPC == nil || profile.Bulk == nil || profile.Network == nil {
			return ReleasePlan{}, ManifestBinding{}, fmt.Errorf("%s workload is incomplete", profile.ID)
		}
		plan := ProfilePlan{
			ID: profile.ID, Cold: *profile.Cold, RPC: *profile.RPC, Bulk: *profile.Bulk,
			Network:                *profile.Network,
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
	return ReleasePlan{
		RunCount: manifest.RunCount,
		Clean:    profiles["clean-v1"], Mobile: profiles["mobile-v1"], Edge: profiles["edge-v1"],
	}, binding, nil
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
