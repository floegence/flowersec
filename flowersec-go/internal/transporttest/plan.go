package transporttest

import "time"

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
