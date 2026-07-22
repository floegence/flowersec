package main

import "encoding/json"

type PerformanceManifest struct {
	SchemaVersion         int                   `json:"schema_version"`
	Digest                string                `json:"digest,omitempty"`
	RatioFormulaVersion   string                `json:"ratio_formula_version"`
	RunCount              int                   `json:"run_count"`
	Bootstrap             BootstrapContract     `json:"bootstrap"`
	Capacity              CapacityContract      `json:"capacity"`
	Soak                  SoakContract          `json:"soak"`
	Profiles              []PerformanceProfile  `json:"profiles"`
	MetricContracts       []MetricContract      `json:"metric_contracts"`
	EligibleLaneCount     int                   `json:"eligible_lane_count"`
	GlobalSetupMinutes    int                   `json:"global_setup_teardown_minutes"`
	GlobalWatchdogMinutes int                   `json:"global_watchdog_minutes"`
	MaximumLaneMinutes    int                   `json:"maximum_lane_minutes"`
	Cells                 []PerformanceCell     `json:"cells"`
	FaultMatrix           []FaultMatrixContract `json:"fault_matrix"`
}

type FaultMatrixContract struct {
	ProfileID            string `json:"profile_id"`
	Carrier              string `json:"carrier"`
	ReorderPercent       int    `json:"reorder_percent"`
	DuplicatePercent     int    `json:"duplicate_percent"`
	OutageStartNS        int64  `json:"outage_start_ns"`
	OutageDurationNS     int64  `json:"outage_duration_ns"`
	MigrationStartNS     int64  `json:"migration_start_ns,omitempty"`
	MigrationValidatedNS int64  `json:"migration_validated_ns,omitempty"`
}

type CapacityContract struct {
	Sessions           int    `json:"sessions"`
	RampDurationNS     int64  `json:"ramp_duration_ns"`
	HoldDurationNS     int64  `json:"hold_duration_ns"`
	CleanupDurationNS  int64  `json:"cleanup_duration_ns"`
	WatchdogDurationNS int64  `json:"watchdog_duration_ns"`
	MaxRSSBytes        uint64 `json:"max_rss_bytes"`
	MaxCPUNanoseconds  uint64 `json:"max_cpu_nanoseconds"`
	MaxOpenFDs         int    `json:"max_open_fds"`
	MaxGoroutines      int    `json:"max_goroutines"`
	MaxTasks           int    `json:"max_tasks"`
}

type SoakContract struct {
	DurationNS                int64  `json:"duration_ns"`
	FaultCyclePeriodNS        int64  `json:"fault_cycle_period_ns"`
	FaultCycleCount           int    `json:"fault_cycle_count"`
	ReconnectCount            int    `json:"reconnect_count"`
	MigrationCount            int    `json:"migration_count"`
	MaxRSSGrowthBytesPerHour  uint64 `json:"max_rss_growth_bytes_per_hour"`
	MaxGoroutineGrowthPerHour int    `json:"max_goroutine_growth_per_hour"`
	MaxOpenFDGrowthPerHour    int    `json:"max_open_fd_growth_per_hour"`
	MaxTaskGrowthPerHour      int    `json:"max_task_growth_per_hour"`
	ResidualSessions          int    `json:"residual_sessions"`
	ResidualGoroutines        int    `json:"residual_goroutines"`
	ResidualOpenFDs           int    `json:"residual_open_fds"`
	ResidualTasks             int    `json:"residual_tasks"`
}

type BootstrapContract struct {
	Resamples         int    `json:"resamples"`
	Seed              int    `json:"seed"`
	ConfidencePercent int    `json:"confidence_percent"`
	Cluster           string `json:"cluster"`
	Estimator         string `json:"estimator"`
}

type PerformanceProfile struct {
	ID                     string          `json:"id"`
	Mode                   string          `json:"mode"`
	Cold                   *ColdWorkload   `json:"cold,omitempty"`
	RPC                    *RPCWorkload    `json:"rpc,omitempty"`
	Bulk                   *BulkWorkload   `json:"bulk,omitempty"`
	CleanupDeadlineSeconds int             `json:"cleanup_deadline_seconds,omitempty"`
	AdaptiveStages         []AdaptiveStage `json:"adaptive_stages,omitempty"`
	HarnessSlackSeconds    int             `json:"harness_slack_seconds"`
	CellWatchdogMinutes    int             `json:"cell_watchdog_minutes"`
	Network                *NetworkProfile `json:"network"`
	networkPresent         bool
}

type NetworkProfile struct {
	EvidenceLayer           string        `json:"evidence_layer"`
	OneWayDelayMilliseconds int           `json:"one_way_delay_milliseconds"`
	JitterMilliseconds      []int         `json:"jitter_milliseconds"`
	Loss                    NetworkLoss   `json:"loss"`
	ReorderPercent          int           `json:"reorder_percent"`
	DuplicatePercent        int           `json:"duplicate_percent"`
	Shape                   *NetworkShape `json:"shape"`
	LinkMTU                 int           `json:"link_mtu"`
	Firewall                string        `json:"firewall"`
	shapePresent            bool
}

func (profile *PerformanceProfile) UnmarshalJSON(data []byte) error {
	type alias PerformanceProfile
	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*profile = PerformanceProfile(decoded)
	_, profile.networkPresent = fields["network"]
	return nil
}

func (profile *NetworkProfile) UnmarshalJSON(data []byte) error {
	type alias NetworkProfile
	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*profile = NetworkProfile(decoded)
	_, profile.shapePresent = fields["shape"]
	return nil
}

type NetworkLoss struct {
	Mode       string `json:"mode"`
	EveryNth   int    `json:"every_nth,omitempty"`
	BlockSize  int    `json:"block_size,omitempty"`
	BurstFirst int    `json:"burst_first,omitempty"`
	BurstLast  int    `json:"burst_last,omitempty"`
}

type NetworkShape struct {
	RateBitsPerSecond int `json:"rate_bits_per_second"`
	TokenBurstBytes   int `json:"token_burst_bytes"`
	QueueBytes        int `json:"queue_bytes"`
}

type ColdWorkload struct {
	Operations               int `json:"operations"`
	MaxInflight              int `json:"max_inflight"`
	Retries                  int `json:"retries"`
	StartRatePerSecond       int `json:"start_rate_per_second"`
	OperationDeadlineSeconds int `json:"operation_deadline_seconds"`
	PhaseDeadlineSeconds     int `json:"phase_deadline_seconds"`
}

type RPCWorkload struct {
	Operations               int `json:"operations"`
	RequestBytes             int `json:"request_bytes"`
	ResponseBytes            int `json:"response_bytes"`
	Workers                  int `json:"workers"`
	Retries                  int `json:"retries"`
	OperationDeadlineSeconds int `json:"operation_deadline_seconds"`
	PhaseDeadlineSeconds     int `json:"phase_deadline_seconds"`
}

type BulkWorkload struct {
	WarmupBytesPerDirection int `json:"warmup_bytes_per_direction"`
	ScoreBytesPerDirection  int `json:"score_bytes_per_direction"`
	PhaseDeadlineSeconds    int `json:"phase_deadline_seconds"`
}

type AdaptiveStage struct {
	ProfileID              string       `json:"profile_id"`
	Cold                   ColdWorkload `json:"cold"`
	CleanupDeadlineSeconds int          `json:"cleanup_deadline_seconds"`
}

type PerformanceCell struct {
	ID                  string   `json:"id"`
	ProfileID           string   `json:"profile_id"`
	Policy              string   `json:"policy"`
	SupportedCandidates []string `json:"supported_candidates"`
	DurationMinutes     int      `json:"duration_minutes"`
	Topology            string   `json:"topology"`
	Variants            []string `json:"variants"`
	RequiredMetrics     []string `json:"required_metrics"`
}

type MetricContract struct {
	ID        string   `json:"id"`
	Decision  string   `json:"decision"`
	Threshold *float64 `json:"threshold,omitempty"`
	Unit      string   `json:"unit"`
}

type CaseRegistry struct {
	SchemaVersion int              `json:"schema_version"`
	Cases         []CaseDefinition `json:"cases"`
}

type CaseDefinition struct {
	ID             string   `json:"id"`
	Owner          string   `json:"owner"`
	RaceOwner      string   `json:"race_owner,omitempty"`
	Mode           string   `json:"mode"`
	Required       bool     `json:"required"`
	Profile        string   `json:"profile"`
	EvidenceFields []string `json:"evidence_fields"`
}

type EvidenceReport struct {
	SchemaVersion  int                 `json:"schema_version"`
	Classification string              `json:"classification"`
	ManifestDigest string              `json:"manifest_digest"`
	Source         EvidenceSource      `json:"source"`
	Runner         EvidenceRunner      `json:"runner"`
	TDD            []TDDEvidenceRecord `json:"tdd"`
	Cells          []CellEvidence      `json:"cells"`
	Cases          []CaseEvidence      `json:"cases"`
	Attestation    EvidenceAttestation `json:"attestation"`
	baseDir        string
}

type EvidenceRunner struct {
	ID                    string `json:"id"`
	OS                    string `json:"os"`
	Architecture          string `json:"architecture"`
	KernelRelease         string `json:"kernel_release"`
	Namespace             string `json:"namespace"`
	TrafficControl        string `json:"traffic_control"`
	PacketCounters        string `json:"packet_counters"`
	EffectiveConfigSHA256 string `json:"effective_config_sha256"`
	ExecutableSHA256      string `json:"executable_sha256"`
	SourceSHA256          string `json:"source_sha256"`
	ArgvSHA256            string `json:"argv_sha256"`
}

type EvidenceTrustPolicy struct {
	SchemaVersion    int                  `json:"schema_version"`
	TrustStoreSHA256 string               `json:"trust_store_sha256"`
	KeyID            string               `json:"key_id"`
	PublicKeySHA256  string               `json:"public_key_sha256"`
	Runner           EvidenceRunnerPolicy `json:"runner"`
}

type EvidenceRunnerPolicy struct {
	ID                    string `json:"id"`
	OS                    string `json:"os"`
	Architecture          string `json:"architecture"`
	KernelRelease         string `json:"kernel_release"`
	Namespace             string `json:"namespace"`
	TrafficControl        string `json:"traffic_control"`
	PacketCounters        string `json:"packet_counters"`
	EffectiveConfigSHA256 string `json:"effective_config_sha256"`
	EffectiveConfigPath   string `json:"effective_config_path"`
	ExecutableSHA256      string `json:"executable_sha256"`
	SourceSHA256          string `json:"source_sha256"`
	ArgvSHA256            string `json:"argv_sha256"`
}

type EvidenceAttestation struct {
	Scheme    string `json:"scheme"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature,omitempty"`
}

type EvidenceTrustStore struct {
	SchemaVersion int                  `json:"schema_version"`
	Keys          []TrustedEvidenceKey `json:"keys"`
}

type TrustedEvidenceKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type EvidenceSource struct {
	BaseSHA            string `json:"base_sha"`
	FinalSHA           string `json:"final_sha"`
	Dirty              *bool  `json:"dirty"`
	UntrackedFileCount *int   `json:"untracked_file_count"`
}

type TDDEvidenceRecord struct {
	Slice    string           `json:"slice"`
	Red      TDDStageEvidence `json:"red"`
	Green    TDDStageEvidence `json:"green"`
	Refactor TDDStageEvidence `json:"refactor"`
}

type TDDStageEvidence struct {
	Command          string           `json:"command"`
	Args             []string         `json:"args"`
	TestID           string           `json:"test_id"`
	SourceSHA256     string           `json:"source_sha256"`
	BinarySHA256     string           `json:"binary_sha256"`
	FailureAssertion string           `json:"failure_assertion,omitempty"`
	StartedAtNS      int64            `json:"started_at_ns"`
	FinishedAtNS     int64            `json:"finished_at_ns"`
	ExitCode         *int             `json:"exit_code"`
	Artifact         EvidenceArtifact `json:"artifact"`
	OutputArtifact   EvidenceArtifact `json:"output_artifact"`
}

type RepositoryState struct {
	BaseSHA            string
	FinalSHA           string
	Dirty              bool
	UntrackedFileCount int
	BaseIsAncestor     bool
}

type EvidenceMetaSchema struct {
	SchemaVersion        int                    `json:"schema_version"`
	SignedClassification string                 `json:"signed_classification"`
	TDDStages            []string               `json:"tdd_stages"`
	Gates                []EvidenceGateContract `json:"gates"`
}

type EvidenceGateContract struct {
	Target                 string   `json:"target"`
	AllowedClassifications []string `json:"allowed_classifications"`
	ReportRequired         bool     `json:"report_required"`
}

type CellEvidence struct {
	CellID              string                    `json:"cell_id"`
	Policy              string                    `json:"policy"`
	SupportedCandidates []string                  `json:"supported_candidates"`
	ElapsedNanoseconds  *int64                    `json:"elapsed_nanoseconds"`
	Runs                []RunEvidence             `json:"runs"`
	Metrics             map[string]MetricEvidence `json:"metrics"`
}

type MetricEvidence struct {
	Samples    int              `json:"samples"`
	Estimate   *float64         `json:"estimate"`
	LowerCI    *float64         `json:"lower_ci"`
	UpperCI    *float64         `json:"upper_ci"`
	RawSamples EvidenceArtifact `json:"raw_samples"`
}

type MetricSamplesArtifact struct {
	SchemaVersion int               `json:"schema_version"`
	CellID        string            `json:"cell_id"`
	MetricID      string            `json:"metric_id"`
	Runs          []MetricRunSample `json:"runs"`
}

type MetricRunSample struct {
	RunNumber           int                 `json:"run_number"`
	Derivation          string              `json:"derivation"`
	Observations        []FloatRunLength    `json:"observations,omitempty"`
	Numerator           *float64            `json:"numerator,omitempty"`
	Denominator         *float64            `json:"denominator,omitempty"`
	DurationNanoseconds *int64              `json:"duration_nanoseconds,omitempty"`
	DeliveredBytes      *uint64             `json:"delivered_bytes,omitempty"`
	Sources             []MetricSourceRef   `json:"sources"`
	Formula             string              `json:"formula,omitempty"`
	OperandGraph        []MetricOperand     `json:"operand_graph,omitempty"`
	FaultBinding        *MetricFaultBinding `json:"fault_binding,omitempty"`
}

type MetricFaultBinding struct {
	Phase            string `json:"phase"`
	ProfileID        string `json:"profile_id"`
	Carrier          string `json:"carrier"`
	ReorderPercent   int    `json:"reorder_percent"`
	DuplicatePercent int    `json:"duplicate_percent"`
	TraceSHA256      string `json:"trace_sha256"`
	QlogSHA256       string `json:"qlog_sha256,omitempty"`
	PCAPSHA256       string `json:"pcap_sha256"`
	ConnectionID     string `json:"connection_id"`
	RequestID        string `json:"request_id"`
	StartAtNS        int64  `json:"start_at_ns"`
	RecoveryAtNS     int64  `json:"recovery_at_ns"`
	FirstRPCAtNS     int64  `json:"first_rpc_at_ns"`
	Event            string `json:"event"`
	RecoveryEvent    string `json:"recovery_event"`
}

type MetricOperand struct {
	Name      string          `json:"name"`
	Reduction string          `json:"reduction"`
	Source    MetricSourceRef `json:"source"`
}

type MetricSourceRef struct {
	CellID         string `json:"cell_id"`
	RunNumber      int    `json:"run_number"`
	VariantID      string `json:"variant_id,omitempty"`
	ProfileID      string `json:"profile_id,omitempty"`
	Phase          string `json:"phase,omitempty"`
	Kind           string `json:"kind"`
	Field          string `json:"field"`
	ArtifactSHA256 string `json:"artifact_sha256"`
}

type FloatRunLength struct {
	Count int     `json:"count"`
	Value float64 `json:"value"`
}

type IntRunLength struct {
	Count int   `json:"count"`
	Value int64 `json:"value"`
}

type OperationSeriesArtifact struct {
	SchemaVersion int                     `json:"schema_version"`
	Kind          string                  `json:"kind"`
	Context       string                  `json:"context"`
	Records       []OperationSeriesRecord `json:"records"`
}

type OperationSeriesRecord struct {
	RunNumber             int            `json:"run_number"`
	OperationCount        int            `json:"operation_count"`
	ScheduledFirstNS      int64          `json:"scheduled_first_ns"`
	ScheduledIntervalNS   int64          `json:"scheduled_interval_ns"`
	StartDelayNS          []IntRunLength `json:"start_delay_ns"`
	DurationNS            []IntRunLength `json:"duration_ns"`
	RetryCounts           []IntRunLength `json:"retry_counts"`
	InputBytes            []IntRunLength `json:"input_bytes"`
	OutputBytes           []IntRunLength `json:"output_bytes"`
	ScoredBytes           []IntRunLength `json:"scored_bytes"`
	ScoreDurationNS       []IntRunLength `json:"score_duration_ns"`
	FailureOrdinals       []int          `json:"failure_ordinals"`
	OperationDeadlineNS   int64          `json:"operation_deadline_ns"`
	PhaseDeadlineNS       int64          `json:"phase_deadline_ns"`
	MaxInflightObserved   int            `json:"max_inflight_observed"`
	ExpectedPayloadSHA256 string         `json:"expected_payload_sha256"`
	ActualPayloadSHA256   string         `json:"actual_payload_sha256"`
}

type TraceArtifact struct {
	SchemaVersion int           `json:"schema_version"`
	Kind          string        `json:"kind"`
	Context       string        `json:"context"`
	Records       []TraceRecord `json:"records"`
}

type TraceRecord struct {
	Sequence             uint64 `json:"sequence"`
	AtNS                 int64  `json:"at_ns"`
	Event                string `json:"event"`
	Digest               string `json:"digest"`
	ConnectionID         string `json:"connection_id,omitempty"`
	RequestID            string `json:"request_id,omitempty"`
	MetricID             string `json:"metric_id,omitempty"`
	AttemptedSessions    int    `json:"attempted_sessions,omitempty"`
	SucceededSessions    int    `json:"succeeded_sessions,omitempty"`
	FailedSessions       int    `json:"failed_sessions,omitempty"`
	ActiveSessions       int    `json:"active_sessions,omitempty"`
	UniqueActiveSessions int    `json:"unique_active_sessions,omitempty"`
	Disconnects          int    `json:"disconnects,omitempty"`
}

type ExecutionLogArtifact struct {
	SchemaVersion int      `json:"schema_version"`
	Kind          string   `json:"kind"`
	Context       string   `json:"context"`
	Role          string   `json:"role"`
	Command       string   `json:"command"`
	Args          []string `json:"args"`
	TestName      string   `json:"test_name"`
	ExitCode      int      `json:"exit_code"`
	Tests         []string `json:"tests,omitempty"`
	Output        string   `json:"output,omitempty"`
}

type MetricsArtifact struct {
	SchemaVersion int                   `json:"schema_version"`
	Kind          string                `json:"kind"`
	Context       string                `json:"context"`
	Records       []MetricCounterRecord `json:"records"`
}

type MetricCounterRecord struct {
	Name         string  `json:"name"`
	Value        float64 `json:"value"`
	Unit         string  `json:"unit"`
	ConnectionID string  `json:"connection_id,omitempty"`
}

type ConfigArtifact struct {
	SchemaVersion int            `json:"schema_version"`
	Kind          string         `json:"kind"`
	Context       string         `json:"context"`
	Records       []ConfigRecord `json:"records"`
}

type ConfigRecord struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type ResourceArtifact struct {
	SchemaVersion int                         `json:"schema_version"`
	Kind          string                      `json:"kind"`
	Context       string                      `json:"context"`
	Records       []ResourceRecord            `json:"records"`
	Measurements  []ScopedResourceMeasurement `json:"measurements,omitempty"`
}

type ScopedResourceMeasurement struct {
	Name      string  `json:"name"`
	Value     float64 `json:"value"`
	Unit      string  `json:"unit"`
	VariantID string  `json:"variant_id,omitempty"`
	ProfileID string  `json:"profile_id,omitempty"`
	Phase     string  `json:"phase,omitempty"`
}

type ResourceRecord struct {
	Phase                string `json:"phase,omitempty"`
	AtNS                 int64  `json:"at_ns"`
	ActiveSessions       int    `json:"active_sessions,omitempty"`
	UniqueActiveSessions int    `json:"unique_active_sessions,omitempty"`
	RSSBytes             uint64 `json:"rss_bytes"`
	CPUNanoseconds       uint64 `json:"cpu_nanoseconds,omitempty"`
	OpenFDs              int    `json:"open_fds,omitempty"`
	Goroutines           int    `json:"goroutines"`
	Tasks                int    `json:"tasks,omitempty"`
	ResidualSessions     *int   `json:"residual_sessions,omitempty"`
	ResidualGoroutines   *int   `json:"residual_goroutines,omitempty"`
	ResidualOpenFDs      *int   `json:"residual_open_fds,omitempty"`
	ResidualTasks        *int   `json:"residual_tasks,omitempty"`
}

type TCPInfoArtifact struct {
	SchemaVersion int             `json:"schema_version"`
	Kind          string          `json:"kind"`
	Context       string          `json:"context"`
	Records       []TCPInfoRecord `json:"records"`
}

type TCPInfoRecord struct {
	AtNS               int64  `json:"at_ns"`
	LocalAddress       string `json:"local_address"`
	LocalPort          uint16 `json:"local_port"`
	RemoteAddress      string `json:"remote_address"`
	RemotePort         uint16 `json:"remote_port"`
	SocketCookie       string `json:"socket_cookie"`
	SendMSSBytes       uint32 `json:"send_mss_bytes"`
	RetransmittedBytes uint64 `json:"retransmitted_bytes"`
}

type ArtifactMetadata struct {
	SchemaVersion  int    `json:"schema_version"`
	Context        string `json:"context"`
	Kind           string `json:"kind"`
	ArtifactPath   string `json:"artifact_path"`
	ArtifactSHA256 string `json:"artifact_sha256"`
}

type RunEvidence struct {
	RunNumber int               `json:"run_number"`
	Resource  EvidenceArtifact  `json:"resource"`
	Phases    []PhaseEvidence   `json:"phases"`
	Variants  []VariantEvidence `json:"variants,omitempty"`
}

type VariantEvidence struct {
	ID     string          `json:"id"`
	Phases []PhaseEvidence `json:"phases"`
}

type PhaseEvidence struct {
	ProfileID    string                      `json:"profile_id"`
	Phase        string                      `json:"phase"`
	SampleCount  *int                        `json:"sample_count"`
	FailureCount *int                        `json:"failure_count"`
	RetryCount   *int                        `json:"retry_count"`
	Selection    SelectionEvidence           `json:"selection"`
	Artifacts    map[string]EvidenceArtifact `json:"artifacts"`
}

type SelectionEvidence struct {
	OperationCount          int            `json:"operation_count"`
	StartedCandidates       map[string]int `json:"started_candidates"`
	WinnerCount             int            `json:"winner_count"`
	SingleBarrierOperations int            `json:"single_barrier_operations"`
	CommitCount             int            `json:"commit_count"`
	CredentialWriteCount    int            `json:"credential_write_count"`
}

type EvidenceArtifact struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	MetaPath   string `json:"meta_path"`
	MetaSHA256 string `json:"meta_sha256"`
}

type CaseEvidence struct {
	ID        string                      `json:"id"`
	Owner     string                      `json:"owner"`
	Mode      string                      `json:"mode"`
	Profile   string                      `json:"profile"`
	Status    string                      `json:"status"`
	Evidence  map[string]EvidenceArtifact `json:"evidence"`
	Execution *CaseExecutionEvidence      `json:"execution,omitempty"`
}

type CaseExecutionEvidence struct {
	Command          string           `json:"command"`
	Args             []string         `json:"args"`
	TestName         string           `json:"test_name"`
	SourceSHA256     string           `json:"source_sha256"`
	BinarySHA256     string           `json:"binary_sha256"`
	TestListArtifact EvidenceArtifact `json:"test_list_artifact"`
	OutputArtifact   EvidenceArtifact `json:"output_artifact"`
}

type checkStatus string

const (
	statusPass         checkStatus = "pass"
	statusInconclusive checkStatus = "inconclusive"
	statusFail         checkStatus = "fail"
)

type CheckResult struct {
	Status checkStatus
	Issues []string
}
