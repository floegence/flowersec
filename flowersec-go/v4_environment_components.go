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
// wall time, machine memory, peer values or another Environment's configuration.
type V4ResourceAccountKey = resourcev4.AccountKey
type V4ResourceAccountKind = resourcev4.AccountKind
type V4ResourceRequest = resourcev4.Request

const (
	V4SDKBytes           = resourcev4.SDKBytes
	V4ProviderBytes      = resourcev4.ProviderBytes
	V4DiskBytes          = resourcev4.DiskBytes
	V4Items              = resourcev4.Items
	V4WorkSlots          = resourcev4.WorkSlots
	V4Tasks              = resourcev4.Tasks
	V4Timers             = resourcev4.Timers
	V4Connections        = resourcev4.Connections
	V4TLSHandshakes      = resourcev4.TLSHandshakes
	V4Sessions           = resourcev4.Sessions
	V4NativeHandles      = resourcev4.NativeHandles
	V4TenantAccount      = resourcev4.TenantAccount
	V4EnvironmentAccount = resourcev4.EnvironmentAccount
	V4SessionAccount     = resourcev4.SessionAccount
	V4DirectionAccount   = resourcev4.DirectionAccount
	V4PoolAccount        = resourcev4.PoolAccount
)

type V4Clock = timev4.Clock
type V4ClockProfile = timev4.Profile
type V4ClockRate = timev4.Rate
type V4ClockTick = timev4.Tick
type V4ClockMark = timev4.Mark
type V4TimeInterval = timev4.Interval
type V4Deadline = timev4.Deadline

// NewV4Clock borrows a bounded, concurrency-safe local monotonic adapter. It
// invokes the adapter outside its state gates; the adapter must not do I/O or
// application work. Incarnation changes and failed reads invalidate continuity.
func NewV4Clock(profile V4ClockProfile, sample func() (V4ClockTick, error)) (*V4Clock, error) {
	return timev4.NewClock(profile, sample)
}
func NewV4Deadline(clock *V4Clock, absoluteCapMS uint64) (*V4Deadline, error) {
	return timev4.NewDeadline(clock, absoluteCapMS)
}
func NewV4Age(clock *V4Clock, durationMS, parentCapMS uint64) (*V4Deadline, error) {
	return timev4.NewAge(clock, durationMS, parentCapMS)
}

type V4VerificationContinuity = protocolv4.VerificationContinuity
type V4VerificationNamespaces = protocolv4.NamespaceRegistry
type V4VerificationNamespacesConfig = protocolv4.NamespaceRegistryConfig
type V4NamespaceTrustRoot = protocolv4.NamespaceTrustRoot
type V4NamespaceTrustLimits = protocolv4.NamespaceTrustLimits
type V4NamespaceRules = protocolv4.NamespaceRules
type V4LiveNamespace = protocolv4.LiveNamespace
type V4NamespaceAllocation = protocolv4.NamespaceAllocation
type V4NamespaceBootstrapLimits = protocolv4.NamespaceBootstrapLimits
type V4NamespaceBootstrapRequest = protocolv4.NamespaceBootstrapRequest
type V4NamespaceBootstrapProvider = protocolv4.NamespaceBootstrapProvider
type V4NamespaceContent = protocolv4.NamespaceContent
type V4NamespaceOnlineBootstrap = protocolv4.NamespaceOnlineBootstrap
type V4NamespaceDurabilityConfig = protocolv4.NamespaceDurabilityConfig
type V4NamespaceContinuityScope = protocolv4.NamespaceContinuityScope
type V4NamespaceContinuityVersion = protocolv4.NamespaceContinuityVersion
type V4NamespaceContinuityLimits = protocolv4.NamespaceContinuityLimits
type V4NamespaceContinuityStore = protocolv4.NamespaceContinuityStore

const (
	V4OnlineBootstrap = protocolv4.OnlineBootstrap
	V4DurableRestore  = protocolv4.DurableRestore
)

func V4VerificationNamespacesCharge(c V4VerificationNamespacesConfig) (V4ResourceVector, error) {
	return protocolv4.NamespaceRegistryCharge(c)
}
func NewV4VerificationNamespaces(c V4VerificationNamespacesConfig, reservation V4ResourceReference) (*V4VerificationNamespaces, error) {
	return protocolv4.NewNamespaceRegistry(c, reservation)
}
func V4NamespaceTrustCharge(c V4NamespaceTrustLimits) (V4ResourceVector, error) {
	return protocolv4.NamespaceTrustCharge(c)
}
func NewV4NamespaceTrustAnchor(root V4NamespaceTrustRoot, limits V4NamespaceTrustLimits, clock *V4Clock, reservation, dependenciesBorrow V4ResourceReference) (*V4NamespaceTrustStore, error) {
	return protocolv4.NewNamespaceTrustAnchor(root, limits, clock, reservation, dependenciesBorrow)
}
func V4NamespaceBootstrapCharge(c V4NamespaceBootstrapLimits) (V4ResourceVector, error) {
	return protocolv4.NamespaceBootstrapCharge(c)
}
func NewV4NamespaceOnlineBootstrap(ctx context.Context, trust *V4NamespaceTrustStore, limits V4NamespaceBootstrapLimits, allocation V4NamespaceAllocation, reservation V4ResourceReference) (*V4NamespaceOnlineBootstrap, error) {
	return protocolv4.NewNamespaceOnlineBootstrap(ctx, trust, limits, allocation, reservation)
}
func NewV4NamespaceDurableBootstrap(ctx context.Context, trust *V4NamespaceTrustStore, limits V4NamespaceBootstrapLimits, allocation V4NamespaceAllocation, reservation V4ResourceReference, durability V4NamespaceDurabilityConfig) (*V4NamespaceOnlineBootstrap, error) {
	return protocolv4.NewNamespaceDurableBootstrap(ctx, trust, limits, allocation, reservation, durability)
}
func V4NamespaceDurabilityCharge(limits V4NamespaceContinuityLimits) (V4ResourceVector, error) {
	return protocolv4.NamespaceDurabilityCharge(limits)
}
func RestoreV4Namespace(ctx, environment context.Context, trust *V4NamespaceTrustStore, c V4NamespaceDurabilityConfig, subscribers uint32, allocation V4NamespaceAllocation) (*V4LiveNamespace, error) {
	return protocolv4.RestoreNamespace(ctx, environment, trust, c, subscribers, allocation)
}

type V4ApplicationExecutor = sessionv4.ApplicationExecutor
type V4ApplicationExecutorConfig = sessionv4.ApplicationExecutorConfig
type V4SessionPlan = sessionv4.SessionPlan
type V4SessionPlanConfig = sessionv4.SessionPlanConfig
type V4ApplicationBinding = sessionv4.ApplicationBinding
type V4ApplicationLease = sessionv4.ApplicationLease
type V4AuthenticatedRequestContext = sessionv4.AuthenticatedRequestContext
type V4AuthorizeApplicationResult = sessionv4.AuthorizeApplicationResult
type V4ContractQueryMethod = sessionv4.ContractQueryMethod
type V4StreamHandlerPlan = sessionv4.StreamHandlerPlan
type V4StreamHandlerPlanConfig = sessionv4.StreamHandlerPlanConfig
type V4RawStreamHandlerConfig = sessionv4.RawStreamHandlerConfig
type V4RawStreamMetadataType = protocolv4.RawStreamMetadataType
type V4RawStreamMetadataField = protocolv4.RawStreamMetadataField
type V4RawStreamMetadataContract = protocolv4.RawStreamMetadataContract
type V4StreamOwnership = sessionv4.StreamOwnership

func V4ApplicationExecutorCharge(c V4ApplicationExecutorConfig) (V4ResourceVector, error) {
	return sessionv4.ApplicationExecutorCharge(c)
}
func NewV4ApplicationExecutor(c V4ApplicationExecutorConfig, reservation V4ResourceReference) (*V4ApplicationExecutor, error) {
	return sessionv4.NewApplicationExecutor(c, reservation)
}
func V4SessionPlanCharge(c V4SessionPlanConfig) (V4ResourceVector, error) {
	return sessionv4.SessionPlanCharge(c)
}
func NewV4SessionPlan(c V4SessionPlanConfig, executor *V4ApplicationExecutor, metadata, task, completion, dependenciesBorrow V4ResourceReference) (*V4SessionPlan, error) {
	return sessionv4.NewSessionPlan(c, executor, metadata, task, completion, dependenciesBorrow)
}
func V4StreamHandlerPlanCharge(c V4StreamHandlerPlanConfig) (V4ResourceVector, error) {
	return sessionv4.StreamHandlerPlanCharge(c)
}
func NewV4StreamHandlerPlan(c V4StreamHandlerPlanConfig, executor *V4ApplicationExecutor, reservation, delegatesBorrow V4ResourceReference) (*V4StreamHandlerPlan, error) {
	return sessionv4.NewStreamHandlerPlan(c, executor, reservation, delegatesBorrow)
}

type V4SessionCoreConfig = sessionv4.SessionCoreConfig
type V4SessionStreamConfig = sessionv4.SessionStreamConfig
type V4SessionStreamHandlerConfig = sessionv4.SessionStreamHandlerConfig
type V4OpenLimits = sessionv4.OpenLimits
type V4AutomaticLivenessPolicy = sessionv4.AutomaticLivenessPolicy
type V4MaintenanceMessagePolicy = sessionv4.MaintenanceMessagePolicy
type V4StreamTerminationPolicy = sessionv4.StreamTerminationPolicy
type V4RekeyPhaseBudgets = sessionv4.RekeyPhaseBudgets
type V4SharedDiscardPolicy = sessionv4.SharedDiscardPolicy
type V4MaintenanceIngressPolicy = sessionv4.MaintenanceIngressPolicy
type V4InitialConfig = sessionv4.InitialConfig
type V4InitialLimits = sessionv4.InitialLimits
type V4MaintenanceReserve = cryptov4.MaintenanceReserve
type V4EngineResourceOptions = cryptov4.EngineResourceOptions
type V4HelloLimits = protocolv4.HelloLimits
type V4HelloPolicy = protocolv4.HelloPolicy
type V4FeatureEnvelope = protocolv4.FeatureEnvelope
type V4CarrierAttemptBudget = sessionv4.CarrierAttemptBudget
type V4LiveGrantPreparation = protocolv4.LiveGrantPreparation

type V4SourceLiveIssuance = sessionv4.SourceLiveIssuance
type V4LiveProofVerification = sessionv4.LiveProofVerification
type V4InitialMessages = sessionv4.InitialMessages
type V4ConnectionGuarantees = protocolv4.V4ConnectionGuarantees
type V4RequiredGuarantees = protocolv4.V4ConnectionRequirements
type V4MethodRoutes = rpcv4.MethodRoutes
type V4ContractRoutesConfig = rpcv4.ContractRoutesConfig
type V4QueryBinding = rpcv4.QueryBinding
type V4ServiceRegistry = rpcv4.ServiceRegistry
type V4ServiceRegistryConfig = rpcv4.ServiceRegistryConfig
type V4ServiceBinding = rpcv4.ServiceBinding
type V4IssuerPermission = protocolv4.IssuerPermission
type V4CredentialPolicy = protocolv4.CredentialPolicy
type V4CredentialScope = protocolv4.CredentialScope
type V4DecodeContext = protocolv4.DecodeContext

func V4ServiceRegistryCharge(c V4ServiceRegistryConfig) (V4ResourceVector, error) {
	return rpcv4.ServiceRegistryCharge(c)
}
func NewV4ServiceRegistry(c V4ServiceRegistryConfig, reservation V4ResourceReference) (*V4ServiceRegistry, error) {
	return rpcv4.NewServiceRegistry(c, reservation)
}
func V4RPCServicesRequirements(c V4RPCServicesConfig) (V4ResourceVector, uint32, error) {
	return sessionv4.RPCServicesRequirements(c)
}

func V4EnvironmentCharge(c V4EnvironmentConfig) (V4ResourceVector, error) {
	return sessionv4.EnvironmentCharge(c)
}
func V4ApplicationIdentityCharge(nodes int, runtimeBytes uint64) (V4ResourceVector, error) {
	return sessionv4.ApplicationIdentityCharge(nodes, runtimeBytes)
}
func V4ArtifactLeaseCharge(mapBytes, nodes int, runtimeBytes uint64, tunnelCounts ...int) (V4ResourceVector, error) {
	return sessionv4.ArtifactLeaseCharge(mapBytes, nodes, runtimeBytes, tunnelCounts...)
}
func V4ConnectionMaterialCharge(runtimeBytes uint64) (V4ResourceVector, error) {
	return sessionv4.ConnectionMaterialCharge(runtimeBytes)
}
func V4SessionAdmissionRequirements(c V4SessionAdmissionConfig) (V4ResourceVector, uint32, error) {
	return sessionv4.SessionAdmissionRequirements(c)
}
func V4SourcePreparationCharge(c V4SourceConnectConfig) (V4ResourceVector, error) {
	return sessionv4.SourcePreparationCharge(c)
}

func V4SourceCarrierCharge(runtimeBytes uint64) (V4ResourceVector, error) {
	return sessionv4.SourceCarrierCharge(runtimeBytes)
}
func V4MaterialAcquisitionCharge(runtimeBytes uint64) (V4ResourceVector, error) {
	return sessionv4.MaterialAcquisitionCharge(runtimeBytes)
}
func V4EstablishmentCharge(c V4EstablishmentLimits) (V4ResourceVector, error) {
	return sessionv4.EstablishmentCharge(c)
}
func V4CredentialSubscriptionsCharge() V4ResourceVector {
	return protocolv4.CredentialSubscriptionsCharge()
}
func V4PreparedCarrierCharge(runtimeBytes uint64) (V4ResourceVector, error) {
	return sessionv4.PreparedCarrierCharge(runtimeBytes)
}
func NewV4PreparedStream(ctx context.Context, c V4PreparedCarrierConfig, stream io.ReadWriteCloser) (*V4PreparedCarrier, error) {
	return sessionv4.NewPreparedStream(ctx, c, stream)
}
func NewV4PreparedMessages(ctx context.Context, c V4PreparedCarrierConfig, messages V4InitialMessages) (*V4PreparedCarrier, error) {
	return sessionv4.NewPreparedMessages(ctx, c, messages)
}

type V4ArtifactLeaseTunnel = sessionv4.ArtifactLeaseTunnel
type V4ArtifactLeaseTunnelBytes = sessionv4.ArtifactLeaseTunnelBytes
