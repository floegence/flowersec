package flowersec

import (
	"context"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// All components below retain their original resource authority. A deployment
// supplies qualified clock/provider limits; constructors never infer them from
// wall time, machine memory, peer values or another TransportEnvironment's configuration.
type ResourceAccountKey = resourcev4.AccountKey
type ResourceAccountKind = resourcev4.AccountKind
type ResourceRequest = resourcev4.Request

const (
	SDKBytes           = resourcev4.SDKBytes
	ProviderBytes      = resourcev4.ProviderBytes
	DiskBytes          = resourcev4.DiskBytes
	Items              = resourcev4.Items
	WorkSlots          = resourcev4.WorkSlots
	Tasks              = resourcev4.Tasks
	Timers             = resourcev4.Timers
	Connections        = resourcev4.Connections
	TLSHandshakes      = resourcev4.TLSHandshakes
	Sessions           = resourcev4.Sessions
	NativeHandles      = resourcev4.NativeHandles
	TenantAccount      = resourcev4.TenantAccount
	EnvironmentAccount = resourcev4.EnvironmentAccount
	SessionAccount     = resourcev4.SessionAccount
	DirectionAccount   = resourcev4.DirectionAccount
	PoolAccount        = resourcev4.PoolAccount
)

type Clock = timev4.Clock
type ClockProfile = timev4.Profile
type ClockRate = timev4.Rate
type ClockTick = timev4.Tick
type ClockMark = timev4.Mark
type TimeInterval = timev4.Interval
type Deadline = timev4.Deadline

// NewClock borrows a bounded, concurrency-safe local monotonic adapter. It
// invokes the adapter outside its state gates; the adapter must not do I/O or
// application work. Incarnation changes and failed reads invalidate continuity.
func NewClock(profile ClockProfile, sample func() (ClockTick, error)) (*Clock, error) {
	return timev4.NewClock(profile, sample)
}
func NewDeadline(clock *Clock, absoluteCapMS uint64) (*Deadline, error) {
	return timev4.NewDeadline(clock, absoluteCapMS)
}
func NewAge(clock *Clock, durationMS, parentCapMS uint64) (*Deadline, error) {
	return timev4.NewAge(clock, durationMS, parentCapMS)
}

type VerificationContinuity = protocolv4.VerificationContinuity
type VerificationNamespaces = protocolv4.NamespaceRegistry
type VerificationNamespacesConfig = protocolv4.NamespaceRegistryConfig
type NamespaceTrustRoot = protocolv4.NamespaceTrustRoot
type NamespaceTrustLimits = protocolv4.NamespaceTrustLimits
type NamespaceRules = protocolv4.NamespaceRules
type LiveNamespace = protocolv4.LiveNamespace
type NamespaceAllocation = protocolv4.NamespaceAllocation
type NamespaceBootstrapLimits = protocolv4.NamespaceBootstrapLimits
type NamespaceBootstrapRequest = protocolv4.NamespaceBootstrapRequest
type NamespaceBootstrapProvider = protocolv4.NamespaceBootstrapProvider
type NamespaceRefreshRequest = protocolv4.NamespaceRefreshRequest
type NamespaceRefreshProvider = protocolv4.NamespaceRefreshProvider
type NamespaceRefreshLimits = protocolv4.NamespaceRefreshLimits
type NamespaceRefreshConfig = protocolv4.NamespaceRefreshConfig
type NamespaceRefresh = protocolv4.NamespaceRefresh
type NamespaceContent = protocolv4.NamespaceContent
type NamespaceOnlineBootstrap = protocolv4.NamespaceOnlineBootstrap
type NamespaceDurabilityConfig = protocolv4.NamespaceDurabilityConfig
type NamespaceContinuityScope = protocolv4.NamespaceContinuityScope
type NamespaceContinuityVersion = protocolv4.NamespaceContinuityVersion
type NamespaceContinuityLimits = protocolv4.NamespaceContinuityLimits
type NamespaceContinuityStore = protocolv4.NamespaceContinuityStore

const (
	OnlineBootstrap = protocolv4.OnlineBootstrap
	DurableRestore  = protocolv4.DurableRestore
)

func VerificationNamespacesCharge(c VerificationNamespacesConfig) (ResourceVector, error) {
	return protocolv4.NamespaceRegistryCharge(c)
}
func NewVerificationNamespaces(c VerificationNamespacesConfig, reservation ResourceReference) (*VerificationNamespaces, error) {
	return protocolv4.NewNamespaceRegistry(c, reservation)
}
func NamespaceTrustCharge(c NamespaceTrustLimits) (ResourceVector, error) {
	return protocolv4.NamespaceTrustCharge(c)
}
func NewNamespaceTrustAnchor(root NamespaceTrustRoot, limits NamespaceTrustLimits, clock *Clock, reservation, dependenciesBorrow ResourceReference) (*NamespaceTrustStore, error) {
	return protocolv4.NewNamespaceTrustAnchor(root, limits, clock, reservation, dependenciesBorrow)
}
func NamespaceBootstrapCharge(c NamespaceBootstrapLimits) (ResourceVector, error) {
	return protocolv4.NamespaceBootstrapCharge(c)
}
func NewNamespaceOnlineBootstrap(ctx context.Context, trust *NamespaceTrustStore, limits NamespaceBootstrapLimits, allocation NamespaceAllocation, reservation ResourceReference) (*NamespaceOnlineBootstrap, error) {
	return protocolv4.NewNamespaceOnlineBootstrap(ctx, trust, limits, allocation, reservation)
}
func NamespaceRefreshCharge(limits NamespaceRefreshLimits, configBytes int) (ResourceVector, error) {
	return protocolv4.NamespaceRefreshCharge(limits, configBytes)
}
func NewNamespaceRefresh(namespace *LiveNamespace, trust *NamespaceTrustStore, limits NamespaceRefreshLimits, reservation ResourceReference) (*NamespaceRefresh, error) {
	return protocolv4.NewNamespaceRefresh(namespace, trust, limits, reservation)
}
func NewNamespaceDurableBootstrap(ctx context.Context, trust *NamespaceTrustStore, limits NamespaceBootstrapLimits, allocation NamespaceAllocation, reservation ResourceReference, durability NamespaceDurabilityConfig) (*NamespaceOnlineBootstrap, error) {
	return protocolv4.NewNamespaceDurableBootstrap(ctx, trust, limits, allocation, reservation, durability)
}
func NamespaceDurabilityCharge(limits NamespaceContinuityLimits) (ResourceVector, error) {
	return protocolv4.NamespaceDurabilityCharge(limits)
}
func RestoreNamespace(ctx, environment context.Context, trust *NamespaceTrustStore, c NamespaceDurabilityConfig, subscribers uint32, allocation NamespaceAllocation) (*LiveNamespace, error) {
	return protocolv4.RestoreNamespace(ctx, environment, trust, c, subscribers, allocation)
}

type ApplicationExecutor = sessionv4.ApplicationExecutor
type ApplicationExecutorConfig = sessionv4.ApplicationExecutorConfig
type ApplicationExecutorSnapshot = sessionv4.ApplicationExecutorSnapshot
type ExecutorOperationsSnapshot = sessionv4.ExecutorOperationsSnapshot
type ApplicationResourceProfile = sessionv4.ApplicationResourceProfile

const (
	ApplicationProfileCustom      = sessionv4.ApplicationProfileCustom
	ApplicationProfileClient      = sessionv4.ApplicationProfileClient
	ApplicationProfileServer      = sessionv4.ApplicationProfileServer
	ApplicationProfileConstrained = sessionv4.ApplicationProfileConstrained
)

func ApplicationExecutorPreset(profile ApplicationResourceProfile, runtimeBytes, runtimeBytesPerTask uint64, execution, diagnostics bool) (ApplicationExecutorConfig, error) {
	return sessionv4.ApplicationExecutorPreset(profile, runtimeBytes, runtimeBytesPerTask, execution, diagnostics)
}

type SessionPlan = sessionv4.SessionPlan
type SessionPlanConfig = sessionv4.SessionPlanConfig
type ApplicationBinding = sessionv4.ApplicationBinding
type ApplicationLease = sessionv4.ApplicationLease
type AuthenticatedRequestContext = sessionv4.AuthenticatedRequestContext
type AuthorizeApplicationResult = sessionv4.AuthorizeApplicationResult
type ContractQueryMethod = sessionv4.ContractQueryMethod
type StreamHandlerPlan = sessionv4.StreamHandlerPlan
type StreamHandlerPlanConfig = sessionv4.StreamHandlerPlanConfig
type RawStreamHandlerConfig = sessionv4.RawStreamHandlerConfig
type DelegatedStreamService = sessionv4.DelegatedStreamService
type DelegatedStreamOptions = sessionv4.DelegatedStreamOptions
type DelegatedStreamServe = sessionv4.DelegatedStreamServe
type RawStreamMetadataType = protocolv4.RawStreamMetadataType
type RawStreamMetadataField = protocolv4.RawStreamMetadataField
type RawStreamMetadataContract = protocolv4.RawStreamMetadataContract
type StreamOwnership = sessionv4.StreamOwnership

func SessionCoreRequirements(c SessionCoreConfig) (ResourceVector, uint32, error) {
	return sessionv4.SessionCoreRequirements(c)
}

func SessionCoreReferenceSlots(c SessionCoreConfig) (uint32, error) {
	return sessionv4.SessionCoreReferenceSlots(c)
}

func ApplicationExecutorCharge(c ApplicationExecutorConfig) (ResourceVector, error) {
	return sessionv4.ApplicationExecutorCharge(c)
}
func NewApplicationExecutor(c ApplicationExecutorConfig, reservation ResourceReference) (*ApplicationExecutor, error) {
	return sessionv4.NewApplicationExecutor(c, reservation)
}
func SessionPlanCharge(c SessionPlanConfig) (ResourceVector, error) {
	return sessionv4.SessionPlanCharge(c)
}
func NewSessionPlan(c SessionPlanConfig, executor *ApplicationExecutor, metadata, task, completion, dependenciesBorrow ResourceReference) (*SessionPlan, error) {
	return sessionv4.NewSessionPlan(c, executor, metadata, task, completion, dependenciesBorrow)
}
func StreamHandlerPlanCharge(c StreamHandlerPlanConfig) (ResourceVector, error) {
	return sessionv4.StreamHandlerPlanCharge(c)
}
func NewStreamHandlerPlan(c StreamHandlerPlanConfig, executor *ApplicationExecutor, reservation, delegatesBorrow ResourceReference) (*StreamHandlerPlan, error) {
	return sessionv4.NewStreamHandlerPlan(c, executor, reservation, delegatesBorrow)
}

type SessionCoreConfig = sessionv4.SessionCoreConfig
type SessionStreamConfig = sessionv4.SessionStreamConfig
type SessionStreamHandlerConfig = sessionv4.SessionStreamHandlerConfig
type OpenLimits = sessionv4.OpenLimits
type AutomaticLivenessPolicy = sessionv4.AutomaticLivenessPolicy
type MaintenanceMessagePolicy = sessionv4.MaintenanceMessagePolicy
type StreamTerminationPolicy = sessionv4.StreamTerminationPolicy
type RekeyPhaseBudgets = sessionv4.RekeyPhaseBudgets
type SharedDiscardPolicy = sessionv4.SharedDiscardPolicy
type MaintenanceIngressPolicy = sessionv4.MaintenanceIngressPolicy
type InitialConfig = sessionv4.InitialConfig
type InitialLimits = sessionv4.InitialLimits
type MaintenanceReserve = cryptov4.MaintenanceReserve
type EngineResourceOptions = cryptov4.EngineResourceOptions
type HelloLimits = protocolv4.HelloLimits
type HelloPolicy = protocolv4.HelloPolicy
type FeatureEnvelope = protocolv4.FeatureEnvelope
type CarrierAttemptBudget = sessionv4.CarrierAttemptBudget
type LiveGrantPreparation = protocolv4.LiveGrantPreparation

type SourceLiveIssuance = sessionv4.SourceLiveIssuance
type LiveProofVerification = sessionv4.LiveProofVerification
type InitialMessages = sessionv4.InitialMessages
type ConnectionGuarantees = protocolv4.V4ConnectionGuarantees
type RequiredGuarantees = protocolv4.V4ConnectionRequirements
type MethodRoutes = rpcv4.MethodRoutes
type ContractRoutesConfig = rpcv4.ContractRoutesConfig
type QueryBinding = rpcv4.QueryBinding
type ServiceRegistry = rpcv4.ServiceRegistry
type ServiceRegistryConfig = rpcv4.ServiceRegistryConfig
type ServiceBinding = rpcv4.ServiceBinding
type IssuerPermission = protocolv4.IssuerPermission
type CredentialPolicy = protocolv4.CredentialPolicy
type CredentialScope = protocolv4.CredentialScope
type DecodeContext = protocolv4.DecodeContext

func ServiceRegistryCharge(c ServiceRegistryConfig) (ResourceVector, error) {
	return rpcv4.ServiceRegistryCharge(c)
}
func NewServiceRegistry(c ServiceRegistryConfig, reservation ResourceReference) (*ServiceRegistry, error) {
	return rpcv4.NewServiceRegistry(c, reservation)
}
func RPCServicesRequirements(c RPCServicesConfig) (ResourceVector, uint32, error) {
	return sessionv4.RPCServicesRequirements(c)
}

func EnvironmentCharge(c EnvironmentConfig) (ResourceVector, error) {
	return sessionv4.EnvironmentCharge(c)
}
func ApplicationIdentityCharge(nodes int, runtimeBytes uint64) (ResourceVector, error) {
	return sessionv4.ApplicationIdentityCharge(nodes, runtimeBytes)
}
func ArtifactLeaseCharge(mapBytes, nodes int, runtimeBytes uint64, tunnelCounts ...int) (ResourceVector, error) {
	return sessionv4.ArtifactLeaseCharge(mapBytes, nodes, runtimeBytes, tunnelCounts...)
}
func ConnectionMaterialCharge(runtimeBytes uint64) (ResourceVector, error) {
	return sessionv4.ConnectionMaterialCharge(runtimeBytes)
}
func SessionAdmissionRequirements(c SessionAdmissionConfig) (ResourceVector, uint32, error) {
	return sessionv4.SessionAdmissionRequirements(c)
}
func SourcePreparationCharge(c SourceConnectConfig) (ResourceVector, error) {
	return sessionv4.SourcePreparationCharge(c)
}

func SourceCarrierCharge(runtimeBytes uint64) (ResourceVector, error) {
	return sessionv4.SourceCarrierCharge(runtimeBytes)
}
func MaterialAcquisitionCharge(runtimeBytes uint64) (ResourceVector, error) {
	return sessionv4.MaterialAcquisitionCharge(runtimeBytes)
}
func EstablishmentCharge(c EstablishmentLimits) (ResourceVector, error) {
	return sessionv4.EstablishmentCharge(c)
}
func CredentialSubscriptionsCharge() ResourceVector {
	return protocolv4.CredentialSubscriptionsCharge()
}
func PreparedCarrierCharge(runtimeBytes uint64) (ResourceVector, error) {
	return sessionv4.PreparedCarrierCharge(runtimeBytes)
}
func NewPreparedStream(ctx context.Context, c PreparedCarrierConfig, stream io.ReadWriteCloser) (*PreparedCarrier, error) {
	return sessionv4.NewPreparedStream(ctx, c, stream)
}
func NewPreparedMessages(ctx context.Context, c PreparedCarrierConfig, messages InitialMessages) (*PreparedCarrier, error) {
	return sessionv4.NewPreparedMessages(ctx, c, messages)
}

type ArtifactLeaseTunnel = sessionv4.ArtifactLeaseTunnel
type ArtifactLeaseTunnelBytes = sessionv4.ArtifactLeaseTunnelBytes

// NamespaceOnlineRetirement keeps complete verification history charged until
// an independent full bootstrap and original-owner quiescence prove deletion.
type NamespaceOnlineRetirement = protocolv4.NamespaceOnlineRetirement

func NamespaceOnlineRetirementCharge(l NamespaceBootstrapLimits) (ResourceVector, error) {
	return protocolv4.NamespaceOnlineRetirementCharge(l)
}
func NewNamespaceOnlineRetirement(ctx context.Context, registry *VerificationNamespaces, previous, next *NamespaceTrustStore, limits NamespaceBootstrapLimits, allocation NamespaceAllocation, reservation ResourceReference) (*NamespaceOnlineRetirement, error) {
	return protocolv4.NewNamespaceOnlineRetirement(ctx, registry, previous, next, limits, allocation, reservation)
}

// NamespaceRetirementService is the original Environment's single bounded
// pressure worker. Configure an independently authorized factory explicitly;
// lack of coverage retains history and cannot fall back to ordinary eviction.
type NamespaceRetirementFactory = protocolv4.NamespaceRetirementFactory
type NamespaceRetirementService = protocolv4.NamespaceRetirementService
type NamespaceRetirementServiceConfig = protocolv4.NamespaceRetirementServiceConfig
type NamespaceRetirementServiceStatus = protocolv4.NamespaceRetirementServiceStatus

func NamespaceRetirementServiceCharge(c NamespaceRetirementServiceConfig) (ResourceVector, error) {
	return protocolv4.NamespaceRetirementServiceCharge(c)
}
func NewNamespaceRetirementService(ctx context.Context, registry *VerificationNamespaces, factory NamespaceRetirementFactory, c NamespaceRetirementServiceConfig, reservation ResourceReference) (*NamespaceRetirementService, error) {
	return protocolv4.NewNamespaceRetirementService(ctx, registry, factory, c, reservation)
}

// NamespaceReferenceFactory provides the trusted online cold-start and history
// retirement composition for a fixed finite deployment authority map.
type NamespaceReferenceConfig = protocolv4.NamespaceReferenceConfig
type NamespaceReferenceFactory = protocolv4.NamespaceReferenceFactory

func NamespaceReferenceFactoryCharge(configs []NamespaceReferenceConfig, runtimeBytes uint64) (ResourceVector, error) {
	return protocolv4.NamespaceReferenceFactoryCharge(configs, runtimeBytes)
}
func NewNamespaceReferenceFactory(ctx context.Context, registry *VerificationNamespaces, clock *Clock, configs []NamespaceReferenceConfig, runtimeBytes uint64, reservation ResourceReference) (*NamespaceReferenceFactory, error) {
	return protocolv4.NewNamespaceReferenceFactory(ctx, registry, clock, configs, runtimeBytes, reservation)
}
func (e *TransportEnvironment) VerificationNamespace(ctx context.Context, tenant, authority string) (*NamespaceTrustStore, error) {
	if e == nil || e.inner == nil {
		return nil, ErrTransportUnavailable
	}
	return e.inner.VerificationNamespaceContext(ctx, tenant, authority)
}
