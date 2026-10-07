//! Normal service binding and once-only preparation use the authenticated
//! bootstrap, actual captured contracts and the shared application services.
use crate::{
    ApplicationInvocationContext,
    contract_acceptance_v4::ContractAcceptance,
    environment_v4::{ResourceCharge, ResourceLimits},
    rpc_wire_v4::{self, ApplicationHeader, HeaderScalar},
    service_contract::{
        AsyncMessageCodec, MessageCodec, MethodDefinition, ServiceDefinition, ServiceError,
        ServiceFailure, ServiceSemantics, ServiceShape,
    },
    service_operation_v4::{ResponseCodec, UnaryOperation},
    service_peer_v4::{ContractAvailability, ContractQueryTarget, ContractSnapshot, ServicePeer},
};
use futures_util::FutureExt;
use std::{
    fmt,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, ServiceError>;
fn failure(code: ServiceFailure) -> ServiceError {
    ServiceError(code)
}
// Encoding is actual ordinary work on the captured Session even when its
// eventual result uses a detached account or a borrowed synchronous slot.
fn admit_encoding_work(
    peer: &crate::service_peer_v4::PeerInner,
) -> Result<crate::environment_v4::BusinessActivity> {
    let session = peer
        .session
        .session()
        .map_err(|_| failure(ServiceFailure::Closed))?;
    session
        .controller_publication_gate(|| peer.account.begin_business_work())
        .map_err(|_| failure(ServiceFailure::Closed))
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseLimitPolicy {
    Fixed(u32),
    FollowContractMaximum,
}
#[derive(Clone, Debug)]
pub struct ExecutionReferenceIdentity {
    pub target_domain: String,
    pub tenant: String,
    pub audience: String,
    pub caller_subject: String,
    pub caller_authority: [u8; 32],
}
#[derive(Clone, Debug)]
pub struct ServiceStreamBinding {
    pub stream_kind: String,
    pub stream_metadata: crate::crypto_v4::Metadata,
}
#[derive(Clone, Debug)]
pub struct ServiceResumeBinding {
    pub stream_kind: String,
    pub stream_metadata: crate::crypto_v4::Metadata,
}
#[derive(Clone, Debug)]
pub struct ServiceBindingOptions {
    pub method: MethodDefinition,
    pub acceptance: ContractAcceptance,
    pub response_limit: ResponseLimitPolicy,
    pub execution_reference_identity: Option<ExecutionReferenceIdentity>,
    pub streaming: Option<ServiceStreamBinding>,
    pub resume: Option<ServiceResumeBinding>,
}
/// The complete definition remains available; only these methods are queried
/// during initial binding. An omitted selection initializes every method.
#[derive(Clone, Debug, Default)]
pub struct ServiceBindingSelection {
    pub initial_methods: Option<Vec<MethodDefinition>>,
}
#[derive(Clone, Debug)]
pub struct ServiceMethodRefreshResult {
    pub method: MethodDefinition,
    pub result: std::result::Result<(), ServiceError>,
}
/// One finite renewal worker belongs to this service and its original Session.
#[derive(Clone, Debug)]
pub struct ManagedOfferRenewal {
    pub renew_before: Duration,
    pub query_timeout: Duration,
    pub retry_after: Duration,
}
impl Default for ManagedOfferRenewal {
    fn default() -> Self {
        Self {
            renew_before: Duration::from_secs(5),
            query_timeout: Duration::from_secs(5),
            retry_after: Duration::from_secs(1),
        }
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct ManagedOfferRenewalProgress {
    pub running: bool,
    pub refreshes: u64,
    pub failure: Option<ServiceError>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceAdmission {
    Queue,
    TryNow,
}
#[derive(Clone, Debug)]
pub struct UnaryPrepareOptions {
    pub timeout: Duration,
    pub response_limit_bytes: Option<u32>,
    pub admission_not_after_ms: Option<u64>,
    pub operation_id: Option<[u8; 32]>,
    pub context: Option<ApplicationInvocationContext>,
    pub admission: ServiceAdmission,
    pub application_error_codecs: Vec<crate::ApplicationErrorCodec>,
}
impl Default for UnaryPrepareOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            response_limit_bytes: None,
            admission_not_after_ms: None,
            operation_id: None,
            context: None,
            admission: ServiceAdmission::Queue,
            application_error_codecs: Vec::new(),
        }
    }
}
pub(crate) struct ServiceBindingPreparation {
    charge: ResourceCharge,
    queries: std::collections::VecDeque<ResourceCharge>,
    references: std::collections::VecDeque<Option<ResourceCharge>>,
}
impl ServiceBindingPreparation {
    fn binding_limits(count: usize) -> Result<ResourceLimits> {
        if count == 0 || count > 256 {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        Ok(ResourceLimits {
            sdk_bytes: 8192 + count as u64 * 4160 + 1536,
            items: count as u64 + 3,
            tasks: 1,
            timers: 1,
            ..ResourceLimits::default()
        })
    }
    pub(crate) fn preparation_limits(options: &[ServiceBindingOptions]) -> Result<ResourceLimits> {
        let mut limits = Self::binding_limits(options.len())?;
        for batch in options.chunks(8) {
            limits = crate::crypto_v4::connect::candidate_add_limits(
                limits,
                ServicePeer::query_preparation_limits(batch.len())?,
            )?;
        }
        for option in options {
            if option.execution_reference_identity.is_some() {
                limits = crate::crypto_v4::connect::candidate_add_limits(
                    limits,
                    crate::OperationReferenceCodec::preparation_limits(),
                )?;
            }
        }
        Ok(limits)
    }
    pub(crate) fn new_prepaid(
        account: &crate::environment_v4::ResourceAccount,
        options: &[ServiceBindingOptions],
        mut backing: ResourceCharge,
    ) -> Result<Self> {
        if !backing.matches(account, Self::preparation_limits(options)?) {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let charge = backing.split(Self::binding_limits(options.len())?)?;
        let mut queries = std::collections::VecDeque::with_capacity(options.len().div_ceil(8));
        for batch in options.chunks(8) {
            queries.push_back(backing.split(ServicePeer::query_preparation_limits(batch.len())?)?);
        }
        let mut references = std::collections::VecDeque::with_capacity(options.len());
        for option in options {
            references.push_back(if option.execution_reference_identity.is_some() {
                Some(backing.split(crate::OperationReferenceCodec::preparation_limits())?)
            } else {
                None
            });
        }
        Ok(Self {
            charge,
            queries,
            references,
        })
    }
}
#[derive(Clone)]
struct BoundMethod {
    options: ServiceBindingOptions,
    snapshot: ContractSnapshot,
    generation: u64,
    rpc_class: crate::rpc_channel_v4::RPCChannelClass,
    reference_codec: Option<Arc<crate::OperationReferenceCodec>>,
    pool: Option<crate::preaccepted_streams_v4::PoolDemand>,
    pool_policy: Option<crate::StreamingPoolPolicy>,
}
// A replacement carries only the verified method snapshots. It never borrows
// an old peer/channel or transfers an old operation's publication authority.
#[derive(Clone)]
pub(crate) struct ServiceRebindBaseline {
    namespace: String,
    methods: Vec<MethodRebindBaseline>,
}
#[derive(Clone)]
struct MethodRebindBaseline {
    method: MethodDefinition,
    snapshot: ContractSnapshot,
    generation: u64,
    rpc_class: crate::rpc_channel_v4::RPCChannelClass,
}
impl ServiceRebindBaseline {
    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }
    pub(crate) fn same_revision(&self, other: &Self) -> bool {
        self.namespace == other.namespace
            && self.methods.len() == other.methods.len()
            && self.methods.iter().all(|old| {
                other.method(&old.method).is_some_and(|next| {
                    old.generation == next.generation
                        && old.rpc_class == next.rpc_class
                        && old
                            .snapshot
                            .contract
                            .as_ref()
                            .map(|contract| contract.digest())
                            == next
                                .snapshot
                                .contract
                                .as_ref()
                                .map(|contract| contract.digest())
                })
            })
    }
    fn method(&self, method: &MethodDefinition) -> Option<&MethodRebindBaseline> {
        self.methods.iter().find(|old| old.method.same(method))
    }
}
pub(crate) struct ServiceRebindGuard<'a> {
    _gate: std::sync::MutexGuard<'a, ()>,
}
struct ClientInner {
    peer: ServicePeer,
    definition: ServiceDefinition,
    methods: Mutex<Vec<BoundMethod>>,
    update_gate: Mutex<()>,
    charge: Mutex<ResourceCharge>,
    closed: std::sync::atomic::AtomicBool,
    cancellation: CancellationToken,
    renewal: Mutex<ManagedOfferRenewalProgress>,
    inflight: std::sync::atomic::AtomicUsize,
    changed: tokio::sync::Notify,
}
struct ServiceRefreshGuard(Arc<ClientInner>);
impl Drop for ServiceRefreshGuard {
    fn drop(&mut self) {
        self.0
            .inflight
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        self.0.changed.notify_waiters();
    }
}
impl Drop for ClientInner {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}
impl fmt::Debug for ClientInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceClient { <opaque> }")
    }
}
#[derive(Clone, Debug)]
pub struct ServiceClient(Arc<ClientInner>);
impl ServicePeer {
    pub async fn bind(
        &self,
        definition: ServiceDefinition,
        options: Vec<ServiceBindingOptions>,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<ServiceClient> {
        self.bind_with_streaming_pools(definition, options, Vec::new(), timeout, cancellation)
            .await
    }
    /// Required targets become actually accepted before this normal binding
    /// returns. Empty speculative Streams spend real active, ID and credit
    /// capacity and expire after thirty idle seconds; they never hold a request.
    pub async fn bind_with_streaming_pools(
        &self,
        definition: ServiceDefinition,
        options: Vec<ServiceBindingOptions>,
        requirements: Vec<crate::StreamingPoolRequirement>,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<ServiceClient> {
        self.bind_with_backing(
            definition,
            options,
            requirements,
            timeout,
            cancellation,
            None,
            None,
            ServiceBindingSelection::default(),
        )
        .await
    }
    #[cfg(test)]
    pub(crate) async fn bind_replacement_prepaid(
        &self,
        definition: ServiceDefinition,
        options: Vec<ServiceBindingOptions>,
        timeout: Duration,
        cancellation: CancellationToken,
        charge: ResourceCharge,
        baseline: Option<ServiceRebindBaseline>,
    ) -> Result<ServiceClient> {
        self.bind_with_backing(
            definition,
            options,
            Vec::new(),
            timeout,
            cancellation,
            Some(charge),
            baseline,
            ServiceBindingSelection::default(),
        )
        .await
    }
    pub async fn bind_selected(
        &self,
        definition: ServiceDefinition,
        options: Vec<ServiceBindingOptions>,
        selection: ServiceBindingSelection,
        requirements: Vec<crate::StreamingPoolRequirement>,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<ServiceClient> {
        self.bind_with_backing(
            definition,
            options,
            requirements,
            timeout,
            cancellation,
            None,
            None,
            selection,
        )
        .await
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Service preparation keeps request/response codecs, original method binding and durable save ownership explicit."
    )]
    pub(crate) async fn bind_replacement_selected_prepaid(
        &self,
        definition: ServiceDefinition,
        options: Vec<ServiceBindingOptions>,
        selection: ServiceBindingSelection,
        timeout: Duration,
        cancellation: CancellationToken,
        charge: ResourceCharge,
        baseline: Option<ServiceRebindBaseline>,
    ) -> Result<ServiceClient> {
        self.bind_with_backing(
            definition,
            options,
            Vec::new(),
            timeout,
            cancellation,
            Some(charge),
            baseline,
            selection,
        )
        .await
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Service preparation keeps request/response codecs, original method binding and durable save ownership explicit."
    )]
    async fn bind_with_backing(
        &self,
        definition: ServiceDefinition,
        options: Vec<ServiceBindingOptions>,
        requirements: Vec<crate::StreamingPoolRequirement>,
        timeout: Duration,
        cancellation: CancellationToken,
        prepaid: Option<ResourceCharge>,
        baseline: Option<ServiceRebindBaseline>,
        selection: ServiceBindingSelection,
    ) -> Result<ServiceClient> {
        self.0.check()?;
        if let Some(old) = &baseline
            && (old.namespace != definition.namespace()
                || old.methods.len() != options.len()
                || options
                    .iter()
                    .any(|option| old.method(&option.method).is_none()))
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        if requirements.len() > 128
            || requirements.iter().enumerate().any(|(index, requirement)| {
                requirement.method.shape() != ServiceShape::ServerStreaming
                    || !definition.contains(&requirement.method)
                    || requirements[..index]
                        .iter()
                        .any(|old| old.method.same(&requirement.method))
            })
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        if requirements
            .iter()
            .filter(|requirement| {
                requirement.policy == crate::StreamingPoolPolicy::RequiredForDispatch
            })
            .count()
            > 2
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| failure(ServiceFailure::DeadlineExceeded))?;
        if options.len() != definition.methods().len()
            || options.iter().enumerate().any(|(index, option)| {
                !definition.contains(&option.method)
                    || options[..index]
                        .iter()
                        .any(|old| old.method.same(&option.method))
            })
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        if options.iter().any(|option| {
            (option.method.shape() == ServiceShape::ServerStreaming) != option.streaming.is_some()
                || option.streaming.as_ref().is_some_and(|stream| {
                    stream.stream_kind.is_empty()
                        || stream.stream_kind.len() > 128
                        || stream.stream_kind.starts_with("flowersec.")
                        || stream.stream_kind.starts_with("flowersec/")
                        || stream.stream_metadata.is_typed()
                })
                || option.resume.as_ref().is_some_and(|resume| {
                    option.method.shape() != ServiceShape::Unary
                        || option.method.semantics() != ServiceSemantics::Execution
                        || resume.stream_kind.is_empty()
                        || resume.stream_kind.len() > 128
                        || resume.stream_kind.starts_with("flowersec.")
                        || resume.stream_kind.starts_with("flowersec/")
                        || resume.stream_metadata.is_typed()
                })
        }) {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let mut prepared = prepaid
            .map(|charge| ServiceBindingPreparation::new_prepaid(&self.0.account, &options, charge))
            .transpose()?;
        let was_prepaid = prepared.is_some();
        let charge = if let Some(prepared) = &mut prepared {
            prepared
                .charge
                .split(ServiceBindingPreparation::binding_limits(options.len())?)?
        } else {
            self.0
                .account
                .reserve(ServiceBindingPreparation::binding_limits(options.len())?)?
        };
        if let Some(initial) = &selection.initial_methods
            && (initial.len() > options.len()
                || initial.iter().enumerate().any(|(index, method)| {
                    !definition.contains(method)
                        || initial[..index].iter().any(|old| old.same(method))
                }))
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let selected: Vec<_> = options
            .iter()
            .filter(|option| {
                selection
                    .initial_methods
                    .as_ref()
                    .is_none_or(|initial| initial.iter().any(|method| method.same(&option.method)))
            })
            .collect();
        if requirements.iter().any(|requirement| {
            requirement.policy == crate::StreamingPoolPolicy::RequiredForDispatch
                && !selected
                    .iter()
                    .any(|option| option.method.same(&requirement.method))
        }) {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let mut captured = Vec::with_capacity(selected.len());
        for batch in selected.chunks(8) {
            if cancellation.is_cancelled() {
                return Err(failure(ServiceFailure::Canceled));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(failure(ServiceFailure::DeadlineExceeded));
            }
            let targets: Vec<_> = batch
                .iter()
                .map(|option| ContractQueryTarget {
                    namespace: definition.namespace().to_owned(),
                    type_id: option.method.type_id(),
                    wanted_digest: baseline
                        .as_ref()
                        .and_then(|old| old.method(&option.method))
                        .filter(|_| option.acceptance.locks_digest())
                        .and_then(|old| {
                            old.snapshot
                                .contract
                                .as_ref()
                                .map(|contract| contract.digest())
                        }),
                    known: baseline
                        .as_ref()
                        .and_then(|old| old.method(&option.method))
                        .and_then(|old| old.snapshot.contract.clone()),
                })
                .collect();
            let snapshots = if let Some(prepared) = &mut prepared {
                let mut backing = prepared
                    .queries
                    .pop_front()
                    .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
                let charge =
                    backing.split(ServicePeer::query_preparation_limits(targets.len())?)?;
                self.query_contracts_prepaid(&targets, remaining, cancellation.clone(), charge)
                    .await?
            } else {
                self.query_contracts(&targets, remaining, cancellation.clone())
                    .await?
            };
            if snapshots.len() != batch.len() {
                return Err(failure(ServiceFailure::Protocol));
            }
            for (option, snapshot) in batch.iter().zip(snapshots) {
                let previous = baseline.as_ref().and_then(|old| old.method(&option.method));
                capture_binding(
                    &definition,
                    option,
                    &snapshot,
                    previous
                        .filter(|old| old.snapshot.contract.is_some())
                        .map(|old| &old.snapshot),
                    false,
                )?;
                captured.push((option.method.type_id(), snapshot));
            }
        }
        let mut methods = Vec::with_capacity(options.len());
        for option in &options {
            let previous = baseline.as_ref().and_then(|old| old.method(&option.method));
            let snapshot = captured
                .iter()
                .find(|(id, _)| *id == option.method.type_id())
                .map(|(_, snapshot)| snapshot.clone())
                .unwrap_or(ContractSnapshot {
                    availability: ContractAvailability::Unavailable,
                    contract: None,
                    offer: None,
                });
            let generation = if snapshot.contract.is_none() {
                0
            } else {
                previous.map_or(Ok(1), |old| {
                    old.generation
                        .checked_add(1)
                        .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))
                })?
            };
            let reference_charge = if let Some(prepared) = &mut prepared {
                prepared
                    .references
                    .pop_front()
                    .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?
            } else {
                None
            };
            let reference_codec = match (&option.execution_reference_identity, reference_charge) {
                (Some(identity), Some(charge)) => {
                    Some(Arc::new(crate::OperationReferenceCodec::new_prepaid(
                        &self.0.account,
                        identity.target_domain.clone(),
                        charge,
                    )?))
                }
                (Some(identity), None) if !was_prepaid => {
                    Some(Arc::new(crate::OperationReferenceCodec::new(
                        self.0.account.environment_root().clone(),
                        identity.target_domain.clone(),
                    )?))
                }
                (None, None) => None,
                _ => return Err(failure(ServiceFailure::ConfigurationCapacity)),
            };
            if (option.method.semantics() == ServiceSemantics::Execution)
                != reference_codec.is_some()
            {
                return Err(failure(ServiceFailure::ConfigurationCapacity));
            }
            let pool_policy = requirements
                .iter()
                .find(|requirement| requirement.method.same(&option.method))
                .map(|requirement| requirement.policy);
            methods.push(BoundMethod {
                options: option.clone(),
                snapshot,
                generation,
                rpc_class: previous
                    .map_or(crate::rpc_channel_v4::RPCChannelClass::Interactive, |old| {
                        old.rpc_class
                    }),
                reference_codec,
                pool: None,
                pool_policy,
            });
        }
        self.0.check()?;
        let session = self
            .0
            .session
            .session()
            .map_err(|_| failure(ServiceFailure::Closed))?;
        // Register the complete simultaneous target set before waiting on any
        // target, so an impossible set fails at initialization rather than TTL.
        let indices: Vec<_> = methods
            .iter()
            .enumerate()
            .filter_map(|(index, binding)| {
                binding
                    .pool_policy
                    .filter(|_| binding.snapshot.contract.is_some())
                    .map(|_| index)
            })
            .collect();
        let mut requested = Vec::with_capacity(indices.len());
        for index in &indices {
            let binding = &methods[*index];
            requested.push((
                pool_target(&definition, binding)?,
                binding.pool_policy.expect("frozen pool policy"),
            ));
        }
        let demands = session.demand_stream_pools(&self.0, requested)?;
        for (index, demand) in indices.into_iter().zip(demands) {
            methods[index].pool = demand;
        }
        for binding in &methods {
            if binding.pool_policy == Some(crate::StreamingPoolPolicy::RequiredForDispatch) {
                binding
                    .pool
                    .as_ref()
                    .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?
                    .wait_ready(deadline, &cancellation)
                    .await?;
            }
        }
        self.0.account.with_security(|| {
            if cancellation.is_cancelled() {
                return Err(failure(ServiceFailure::Canceled));
            }
            if Instant::now() >= deadline {
                return Err(failure(ServiceFailure::DeadlineExceeded));
            }
            if self.0.closed.load(std::sync::atomic::Ordering::Acquire) {
                return Err(failure(ServiceFailure::Closed));
            }
            Ok(ServiceClient(Arc::new(ClientInner {
                peer: self.clone(),
                definition,
                methods: Mutex::new(methods),
                update_gate: Mutex::new(()),
                charge: Mutex::new(charge),
                closed: std::sync::atomic::AtomicBool::new(false),
                cancellation: CancellationToken::new(),
                renewal: Mutex::new(ManagedOfferRenewalProgress::default()),
                inflight: std::sync::atomic::AtomicUsize::new(0),
                changed: tokio::sync::Notify::new(),
            })))
        })?
    }
}
fn pool_target(
    definition: &ServiceDefinition,
    binding: &BoundMethod,
) -> Result<crate::preaccepted_streams_v4::PoolTarget> {
    let stream = binding
        .options
        .streaming
        .as_ref()
        .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
    let contract = binding
        .snapshot
        .contract
        .as_ref()
        .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
    Ok(crate::preaccepted_streams_v4::PoolTarget {
        namespace: definition.namespace().to_owned(),
        type_id: binding.options.method.type_id(),
        contract: contract.digest(),
        kind: stream.stream_kind.clone(),
        metadata: stream.stream_metadata.clone(),
        limit: (contract.uint(23)? as usize).max(contract.uint(10)? as usize),
    })
}
fn capture_binding(
    definition: &ServiceDefinition,
    options: &ServiceBindingOptions,
    snapshot: &ContractSnapshot,
    current: Option<&ContractSnapshot>,
    explicit: bool,
) -> Result<()> {
    if (options.method.shape() == ServiceShape::ServerStreaming) != options.streaming.is_some()
        || options.streaming.as_ref().is_some_and(|binding| {
            binding.stream_kind.is_empty()
                || binding.stream_kind.len() > 128
                || binding.stream_kind.starts_with("flowersec.")
                || binding.stream_kind.starts_with("flowersec/")
                || binding.stream_metadata.is_typed()
        })
    {
        return Err(failure(ServiceFailure::ConfigurationCapacity));
    }
    if let Some(resume) = &options.resume
        && (options.method.shape() != ServiceShape::Unary
            || options.method.semantics() != ServiceSemantics::Execution
            || resume.stream_kind.is_empty()
            || resume.stream_kind.len() > 128
            || resume.stream_kind.starts_with("flowersec.")
            || resume.stream_kind.starts_with("flowersec/")
            || resume.stream_metadata.is_typed()
            || snapshot.contract.as_ref().is_none_or(|contract| {
                contract.optional_uint(13) != Some(1) || contract.optional_uint(15).is_none()
            }))
    {
        return Err(failure(ServiceFailure::ContractMismatch));
    }
    if snapshot.availability != ContractAvailability::Available {
        return Err(failure(ServiceFailure::ServiceUnavailable));
    }
    let contract = snapshot
        .contract
        .as_ref()
        .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
    contract.check_method(definition, &options.method)?;
    options
        .acceptance
        .check(
            contract.encoded(),
            current
                .and_then(|current| current.contract.as_ref().map(|contract| contract.encoded())),
            explicit,
        )
        .map_err(|_| failure(ServiceFailure::ContractPolicyRejected))?;
    if options.method.shape() != ServiceShape::Notify {
        let limit = match options.response_limit {
            ResponseLimitPolicy::Fixed(limit) => u64::from(limit),
            ResponseLimitPolicy::FollowContractMaximum => contract.uint(10)?,
        };
        if limit < contract.uint(9)? || limit > contract.uint(10)? {
            return Err(failure(ServiceFailure::ResponseLimitUnsupported));
        }
    }
    if options.method.semantics() == ServiceSemantics::Execution && snapshot.offer.is_none() {
        return Err(failure(ServiceFailure::ContractMismatch));
    }
    Ok(())
}
impl ServiceClient {
    pub fn close(&self) {
        let _update = self
            .0
            .update_gate
            .lock()
            .expect("service Close/admission gate");
        let _renewal = self
            .0
            .renewal
            .lock()
            .expect("service Close/renewal admission");
        self.0
            .closed
            .store(true, std::sync::atomic::Ordering::Release);
        self.0.cancellation.cancel();
        self.0.changed.notify_waiters();
    }
    pub fn cleanup_status(&self) -> crate::CleanupStatus {
        let running = self
            .0
            .renewal
            .lock()
            .expect("service renewal lifecycle")
            .running;
        let inflight = self.0.inflight.load(std::sync::atomic::Ordering::Acquire);
        let complete =
            self.0.closed.load(std::sync::atomic::Ordering::Acquire) && !running && inflight == 0;
        crate::CleanupStatus {
            complete,
            cleanup_incomplete: !complete,
            pending_callbacks: u64::from(running) + inflight as u64,
        }
    }
    pub async fn wait_cleanup(&self) -> crate::CleanupStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return status;
            }
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep_until(deadline) => return self.cleanup_status() }
        }
    }
    pub fn renewal_progress(&self) -> ManagedOfferRenewalProgress {
        *self.0.renewal.lock().expect("service renewal progress")
    }
    pub fn start_managed_offer_renewal(&self, policy: ManagedOfferRenewal) -> Result<()> {
        if policy.query_timeout.is_zero()
            || policy.retry_after.is_zero()
            || policy.renew_before.is_zero()
            || policy.query_timeout > Duration::from_secs(60)
            || policy.retry_after > Duration::from_secs(60)
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        self.0.peer.0.check()?;
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| failure(ServiceFailure::ConfigurationCapacity))?;
        let mut renewal = self.0.renewal.lock().expect("service renewal admission");
        if renewal.running {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        if self.0.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(failure(ServiceFailure::Closed));
        }
        let mut prepared = self
            .0
            .charge
            .lock()
            .expect("prepaid original service renewal");
        let charge = prepared.split(ResourceLimits {
            sdk_bytes: 1024 + self.0.definition.methods().len() as u64 * 64,
            items: 1,
            tasks: 1,
            timers: 1,
            ..ResourceLimits::default()
        })?;
        let tail_charge =
            prepared.split(crate::application_tails_v4::ApplicationTails::resources())?;
        drop(prepared);
        let session = self
            .0
            .peer
            .0
            .session
            .session()
            .map_err(|_| failure(ServiceFailure::Closed))?;
        let tail = session
            .application_tail_reserved(tail_charge)
            .map_err(|_| failure(ServiceFailure::Closed))?;
        let original_cancellation = tail.cancellation();
        renewal.running = true;
        renewal.failure = None;
        drop(renewal);
        let owner = Arc::downgrade(&self.0);
        let cancellation = self.0.cancellation.clone();
        runtime.spawn(async move {
            let _charge = charge; let _tail = tail;
            loop {
                let Some(inner) = owner.upgrade() else { break; };
                if cancellation.is_cancelled() || original_cancellation.is_cancelled() { break; }
                let now = match inner.peer.0.account.security_time() { Ok(now) => now, Err(_) => break };
                let margin = u64::try_from(policy.renew_before.as_millis()).unwrap_or(u64::MAX);
                let methods: Vec<_> = inner.methods.lock().expect("service renewal targets").iter().filter(|binding|
                    binding.options.method.semantics() == ServiceSemantics::Execution && binding.snapshot.contract.is_some()
                    && binding.snapshot.offer.as_ref().is_none_or(|offer| offer.not_after_ms().saturating_sub(now.upper_ms) <= margin))
                    .map(|binding| binding.options.method.clone()).collect();
                if !methods.is_empty() {
                    let client = ServiceClient(inner.clone());
                    let refreshed = client.refresh_methods(&methods, false, policy.query_timeout, cancellation.child_token()).await;
                    let mut progress = inner.renewal.lock().expect("service renewal outcome");
                    match refreshed {
                        Ok(results) => {
                            progress.refreshes = progress.refreshes.saturating_add(results.iter().filter(|result| result.result.is_ok()).count() as u64);
                            progress.failure = results.iter().find_map(|result| result.result.as_ref().err().copied());
                        },
                        Err(error) => progress.failure = Some(error),
                    }
                }
                drop(inner);
                tokio::select! { _ = cancellation.cancelled() => break, _ = original_cancellation.cancelled() => break,
                    _ = tokio::time::sleep(policy.retry_after) => {} }
            }
            drop(_tail); drop(_charge);
            if let Some(inner) = owner.upgrade() {
                inner.renewal.lock().expect("service renewal actual exit").running = false;
                inner.changed.notify_waiters();
            }
        });
        Ok(())
    }
    pub(crate) fn retain_rebind_source(
        &self,
        expected: &ServiceRebindBaseline,
    ) -> Result<ServiceRebindGuard<'_>> {
        let gate = self
            .0
            .update_gate
            .lock()
            .expect("original service source publication gate");
        if self.0.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(failure(ServiceFailure::Closed));
        }
        if !self.rebind_baseline()?.same_revision(expected) {
            return Err(failure(ServiceFailure::OperationConflict));
        }
        Ok(ServiceRebindGuard { _gate: gate })
    }
    pub(crate) fn rebind_baseline(&self) -> Result<ServiceRebindBaseline> {
        let methods = self
            .0
            .methods
            .lock()
            .expect("captured service replacement baseline");
        let mut captured = Vec::new();
        captured
            .try_reserve_exact(methods.len())
            .map_err(|_| failure(ServiceFailure::ResourceExhausted))?;
        captured.extend(methods.iter().map(|binding| MethodRebindBaseline {
            method: binding.options.method.clone(),
            snapshot: binding.snapshot.clone(),
            generation: binding.generation,
            rpc_class: binding.rpc_class,
        }));
        Ok(ServiceRebindBaseline {
            namespace: self.0.definition.namespace().to_owned(),
            methods: captured,
        })
    }
    /// Set this captured method's trusted local RPC scheduling policy. It does
    /// not change the authenticated ServiceContract or receiver priority.
    pub fn set_rpc_channel_class(
        &self,
        method: &MethodDefinition,
        class: crate::RPCChannelClass,
    ) -> Result<()> {
        let _gate = self
            .0
            .update_gate
            .lock()
            .expect("RPC method scheduling policy");
        self.0.peer.0.check()?;
        if self.0.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(failure(ServiceFailure::Closed));
        }
        let mut methods = self.0.methods.lock().expect("service methods");
        let binding = methods
            .iter_mut()
            .find(|binding| binding.options.method.same(method))
            .ok_or_else(|| failure(ServiceFailure::NotReady))?;
        binding.rpc_class = class;
        Ok(())
    }
    /// Replace one current advertisement only after its complete policy check.
    /// Existing preparations retain their exact previous contract and cutoff.
    pub async fn refresh(
        &self,
        method: &MethodDefinition,
        explicit_update: bool,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<()> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| failure(ServiceFailure::DeadlineExceeded))?;
        if cancellation.is_cancelled() {
            return Err(failure(ServiceFailure::Canceled));
        }
        let old = {
            let _admission = self.0.update_gate.lock().expect("refresh/Close admission");
            let old = self.binding(method)?;
            self.0
                .inflight
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            old
        };
        let _refresh = ServiceRefreshGuard(self.0.clone());
        let targets = [ContractQueryTarget {
            namespace: self.0.definition.namespace().to_owned(),
            type_id: method.type_id(),
            wanted_digest: None,
            known: old.snapshot.contract.clone(),
        }];
        let query_cancel = cancellation.child_token();
        let query = self
            .0
            .peer
            .query_contracts(&targets, timeout, query_cancel.clone());
        tokio::pin!(query);
        let mut snapshots = tokio::select! {
            result = &mut query => result?,
            _ = self.0.cancellation.cancelled() => { query_cancel.cancel(); let _ = query.await; return Err(failure(ServiceFailure::Closed)); },
        };
        let candidate = snapshots
            .pop()
            .ok_or_else(|| failure(ServiceFailure::Protocol))?;
        capture_binding(
            &self.0.definition,
            &old.options,
            &candidate,
            Some(&old.snapshot),
            explicit_update,
        )?;
        let mut next_binding = old.clone();
        next_binding.snapshot = candidate;
        if let Some(policy) = old.pool_policy {
            let session = self
                .0
                .peer
                .0
                .session
                .session()
                .map_err(|_| failure(ServiceFailure::Closed))?;
            next_binding.pool = session.demand_stream_pool(
                &self.0.peer.0,
                pool_target(&self.0.definition, &next_binding)?,
                policy,
            )?;
            if policy == crate::StreamingPoolPolicy::RequiredForDispatch {
                let pool = next_binding
                    .pool
                    .as_ref()
                    .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
                tokio::select! { result = pool.wait_ready(deadline, &cancellation) => result?,
                _ = self.0.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)) }
            }
        }
        // The source publication gate orders installation against Controller
        // replacement. The query itself runs without holding this local gate.
        let _update = self
            .0
            .update_gate
            .lock()
            .expect("original service source publication gate");
        self.0.peer.0.account.with_security(|| {
            if cancellation.is_cancelled() {
                return Err(failure(ServiceFailure::Canceled));
            }
            if Instant::now() >= deadline {
                return Err(failure(ServiceFailure::DeadlineExceeded));
            }
            if self.0.closed.load(std::sync::atomic::Ordering::Acquire)
                || self
                    .0
                    .peer
                    .0
                    .closed
                    .load(std::sync::atomic::Ordering::Acquire)
            {
                return Err(failure(ServiceFailure::Closed));
            }
            let mut methods = self.0.methods.lock().expect("service bindings");
            let binding = methods
                .iter_mut()
                .find(|binding| binding.options.method.same(method))
                .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
            if binding.generation != old.generation {
                return Err(failure(ServiceFailure::OperationConflict));
            }
            let next = binding
                .generation
                .checked_add(1)
                .ok_or_else(|| failure(ServiceFailure::ResourceExhausted))?;
            next_binding.generation = next;
            Ok(std::mem::replace(binding, next_binding))
        })??;
        Ok(())
    }
    fn binding(&self, method: &MethodDefinition) -> Result<BoundMethod> {
        if self.0.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(failure(ServiceFailure::Closed));
        }
        self.0.peer.0.check()?;
        self.0
            .methods
            .lock()
            .expect("service bindings")
            .iter()
            .find(|binding| binding.options.method.same(method))
            .cloned()
            .ok_or_else(|| failure(ServiceFailure::ContractMismatch))
    }
    fn ready_binding(&self, method: &MethodDefinition) -> Result<BoundMethod> {
        let binding = self.binding(method)?;
        if binding.snapshot.contract.is_none() {
            return Err(failure(ServiceFailure::NotReady));
        }
        Ok(binding)
    }
    /// Refresh known methods independently. A failure never rolls back another
    /// method already installed by this bounded call.
    pub async fn refresh_methods(
        &self,
        methods: &[MethodDefinition],
        explicit_update: bool,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<Vec<ServiceMethodRefreshResult>> {
        if methods.is_empty()
            || methods.len() > 256
            || methods.iter().enumerate().any(|(index, method)| {
                !self.0.definition.contains(method)
                    || methods[..index].iter().any(|old| old.same(method))
            })
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| failure(ServiceFailure::DeadlineExceeded))?;
        let mut results = Vec::new();
        results
            .try_reserve_exact(methods.len())
            .map_err(|_| failure(ServiceFailure::ResourceExhausted))?;
        for method in methods {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let result = if cancellation.is_cancelled() {
                Err(failure(ServiceFailure::Canceled))
            } else if remaining.is_zero() {
                Err(failure(ServiceFailure::DeadlineExceeded))
            } else {
                self.refresh(method, explicit_update, remaining, cancellation.clone())
                    .await
            };
            results.push(ServiceMethodRefreshResult {
                method: method.clone(),
                result,
            });
        }
        Ok(results)
    }
    pub fn contract(&self, method: &MethodDefinition) -> Result<ContractSnapshot> {
        let binding = self.ready_binding(method)?;
        if binding.snapshot.contract.is_none() {
            return Err(failure(ServiceFailure::NotReady));
        }
        Ok(binding.snapshot)
    }
    pub fn prepare_unary<I: Sync + 'static, O: Send + 'static>(
        &self,
        method: &MethodDefinition,
        value: &I,
        request_codec: Arc<dyn MessageCodec<I>>,
        response_codec: Arc<dyn MessageCodec<O>>,
        options: UnaryPrepareOptions,
    ) -> Result<UnaryOperation<O>> {
        let prepared = self.prepare_owner(
            method,
            request_codec.definition(),
            response_codec.definition(),
            request_codec.application_bytes(),
            response_codec.application_bytes(),
            &options,
        )?;
        let mut payload = Zeroizing::new(vec![0u8; prepared.request_limit]);
        let group = &self.0.peer.0.group;
        let mut encode = |context: ApplicationInvocationContext| {
            let _business = admit_encoding_work(&self.0.peer.0)?;
            std::panic::catch_unwind(AssertUnwindSafe(|| {
                request_codec.encode_with_context(value, &mut payload, &context)
            }))
            .unwrap_or_else(|_| Err(failure(ServiceFailure::EncodeFailed)))
        };
        let length = match options.context.as_ref() {
            Some(context) => group.synchronous_stage(context, encode)??,
            None => {
                let position = group.try_ordinary(false, None)?;
                let invocation = position.enter()?;
                encode(invocation.context())?
            }
        };
        if length > prepared.request_limit {
            return Err(failure(ServiceFailure::EncodeFailed));
        }
        payload.truncate(length);
        Self::complete_prepare(
            prepared,
            method,
            payload,
            ResponseCodec::Sync(response_codec),
            options,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Service preparation keeps request/response codecs, original method binding and durable save ownership explicit."
    )]
    pub async fn prepare_and_save_unary<I: Sync + 'static, O: Send + 'static>(
        &self,
        method: &MethodDefinition,
        value: &I,
        request_codec: Arc<dyn MessageCodec<I>>,
        response_codec: Arc<dyn MessageCodec<O>>,
        options: UnaryPrepareOptions,
        store: Arc<dyn crate::OperationReferenceStore>,
        cancellation: CancellationToken,
    ) -> std::result::Result<crate::SavedUnaryPreparation<O>, crate::PrepareAndSaveError> {
        if method.semantics() != ServiceSemantics::Execution {
            return Err(crate::PrepareAndSaveError::Preparation(failure(
                ServiceFailure::ConfigurationCapacity,
            )));
        }
        let context = options.context.clone();
        let operation = self
            .prepare_unary(method, value, request_codec, response_codec, options)
            .map_err(crate::PrepareAndSaveError::Preparation)?;
        crate::reference_store_v4::save(
            operation,
            store,
            self.0.peer.0.account.clone(),
            self.0.peer.0.group.clone(),
            context,
            cancellation,
        )
        .await
        .map_err(crate::PrepareAndSaveError::Save)
    }
    pub async fn prepare_unary_async<I: Send + Sync + 'static, O: Send + 'static>(
        &self,
        method: &MethodDefinition,
        value: Arc<I>,
        request_codec: Arc<dyn AsyncMessageCodec<I>>,
        response_codec: Arc<dyn AsyncMessageCodec<O>>,
        options: UnaryPrepareOptions,
        cancellation: CancellationToken,
    ) -> Result<UnaryOperation<O>> {
        let prepared = self.prepare_owner(
            method,
            request_codec.definition(),
            response_codec.definition(),
            request_codec.application_bytes(),
            response_codec.application_bytes(),
            &options,
        )?;
        let position = self
            .0
            .peer
            .0
            .group
            .try_ordinary(false, options.context.as_ref())?;
        let business = admit_encoding_work(&self.0.peer.0)?;
        let delivery = Arc::new(Mutex::new(true));
        let original_cancellation = cancellation.child_token();
        let _observer = PreparationObserver {
            delivery: delivery.clone(),
            cancellation: original_cancellation.clone(),
        };
        let method = method.clone();
        let deadline = prepared.deadline;
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _business = business;
            let invocation = match position.enter() {
                Ok(invocation) => invocation,
                Err(error) => {
                    let _ = sender.send(Err(error.into()));
                    return;
                }
            };
            let permitted = prepared.account.with_security(|| {
                *delivery.lock().expect("preparation delivery")
                    && !original_cancellation.is_cancelled()
                    && Instant::now() < deadline
            });
            if !matches!(permitted, Ok(true)) {
                let _ = sender.send(Err(failure(ServiceFailure::Canceled)));
                return;
            }
            let callback =
                AssertUnwindSafe(request_codec.encode(&value, invocation.context())).catch_unwind();
            tokio::pin!(callback);
            let outcome = loop {
                tokio::select! {
                    outcome = &mut callback => break outcome,
                    _ = original_cancellation.cancelled() => { invocation.cancel(); break callback.await; },
                    _ = tokio::time::sleep_until(deadline) => {
                        *delivery.lock().expect("preparation delivery") = false; invocation.cancel(); break callback.await;
                    },
                    _ = prepared.account.security_changed() => {},
                    _ = tokio::time::sleep(prepared.account.next_security_check()) => {},
                }
                if prepared.account.check().is_err() {
                    *delivery.lock().expect("preparation delivery") = false; invocation.cancel(); break callback.await;
                }
            }.unwrap_or_else(|_| Err(failure(ServiceFailure::EncodeFailed)));
            drop(invocation);
            drop(position);
            let payload = match outcome {
                Ok(payload) if payload.len() <= prepared.request_limit => payload,
                Ok(_) => {
                    let _ = sender.send(Err(failure(ServiceFailure::EncodeFailed)));
                    return;
                }
                Err(error) => {
                    let _ = sender.send(Err(error));
                    return;
                }
            };
            if !*delivery.lock().expect("preparation delivery")
                || original_cancellation.is_cancelled()
                || Instant::now() >= deadline
            {
                let _ = sender.send(Err(failure(ServiceFailure::Canceled)));
                return;
            }
            let candidate = Self::complete_prepare(
                prepared,
                &method,
                Zeroizing::new(payload),
                ResponseCodec::Async(response_codec),
                options,
            );
            match candidate {
                Err(error) => {
                    let _ = sender.send(Err(error));
                }
                Ok(operation) => {
                    // Move only a prepared operation under the original result
                    // delivery gate; failed sends retain the owner until exit.
                    let account = operation.result_account();
                    let delivered = account.with_security(|| {
                        let gate = delivery.lock().expect("preparation delivery");
                        if !*gate
                            || original_cancellation.is_cancelled()
                            || Instant::now() >= deadline
                        {
                            return Err((sender, operation));
                        }
                        Ok(sender.send(Ok(operation)))
                    });
                    match delivered {
                        Ok(Err((sender, operation))) => {
                            operation.close();
                            let _ = sender.send(Err(failure(ServiceFailure::Canceled)));
                        }
                        Ok(Ok(Err(Ok(operation)))) => operation.close(),
                        _ => {}
                    }
                }
            }
        });
        tokio::select! {
            result = receiver => result.unwrap_or_else(|_| Err(failure(ServiceFailure::ServiceUnavailable))),
            _ = cancellation.cancelled() => Err(failure(ServiceFailure::Canceled)),
            _ = tokio::time::sleep_until(deadline) => Err(failure(ServiceFailure::DeadlineExceeded)),
        }
    }
    fn prepare_owner(
        &self,
        method: &MethodDefinition,
        request: &crate::MessageDefinition,
        response: &crate::MessageDefinition,
        request_bytes: u64,
        response_bytes: u64,
        options: &UnaryPrepareOptions,
    ) -> Result<PreparedOwner> {
        self.prepare_owner_for(
            ServiceShape::Unary,
            method,
            request,
            response,
            request_bytes,
            response_bytes,
            options,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Service preparation keeps request/response codecs, original method binding and durable save ownership explicit."
    )]
    fn prepare_owner_for(
        &self,
        shape: ServiceShape,
        method: &MethodDefinition,
        request: &crate::MessageDefinition,
        response: &crate::MessageDefinition,
        request_bytes: u64,
        response_bytes: u64,
        options: &UnaryPrepareOptions,
    ) -> Result<PreparedOwner> {
        self.prepare_owner_for_mode(
            shape,
            method,
            request,
            response,
            request_bytes,
            response_bytes,
            options,
            false,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Service preparation keeps request/response codecs, original method binding and durable save ownership explicit."
    )]
    fn prepare_owner_for_mode(
        &self,
        shape: ServiceShape,
        method: &MethodDefinition,
        request: &crate::MessageDefinition,
        response: &crate::MessageDefinition,
        request_bytes: u64,
        response_bytes: u64,
        options: &UnaryPrepareOptions,
        resume: bool,
    ) -> Result<PreparedOwner> {
        self.capture_owner(
            shape,
            method,
            request,
            response,
            request_bytes,
            response_bytes,
            options,
            resume,
            false,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Service preparation keeps request/response codecs, original method binding and durable save ownership explicit."
    )]
    fn capture_owner(
        &self,
        shape: ServiceShape,
        method: &MethodDefinition,
        request: &crate::MessageDefinition,
        response: &crate::MessageDefinition,
        request_bytes: u64,
        response_bytes: u64,
        options: &UnaryPrepareOptions,
        resume: bool,
        continuation: bool,
    ) -> Result<PreparedOwner> {
        if method.shape() != shape
            || options.timeout.is_zero()
            || options.timeout > Duration::from_secs(90)
            || request != &method.options().request
            || method.options().response.as_ref() != Some(response)
            || request_bytes == 0 && !continuation
            || response_bytes == 0
            || request_bytes > 1 << 30
            || response_bytes > 1 << 30
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        if options.application_error_codecs.len() > 64
            || options
                .application_error_codecs
                .iter()
                .enumerate()
                .any(|(index, codec)| {
                    !method.options().errors.contains(codec.definition())
                        || options.application_error_codecs[..index]
                            .iter()
                            .any(|old| old.definition().code == codec.definition().code)
                })
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let binding = self.ready_binding(method)?;
        if binding.options.resume.is_some() != resume {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let contract = binding
            .snapshot
            .contract
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
        let limit = match options.response_limit_bytes {
            Some(limit) => limit,
            None => match binding.options.response_limit {
                ResponseLimitPolicy::Fixed(limit) => limit,
                ResponseLimitPolicy::FollowContractMaximum => contract.uint(10)? as u32,
            },
        };
        if u64::from(limit) < contract.uint(9)? || u64::from(limit) > contract.uint(10)? {
            return Err(failure(ServiceFailure::ResponseLimitUnsupported));
        }
        let now = self.0.peer.0.account.security_time()?;
        let maximum = if method.semantics() == ServiceSemantics::Execution {
            contract.uint(17)?
        } else {
            contract.uint(11)?
        };
        if options.timeout.as_millis() > u128::from(maximum) {
            return Err(failure(ServiceFailure::DeadlineExceeded));
        }
        let cap = now
            .lower_ms
            .checked_add(options.timeout.as_millis() as u64)
            .ok_or_else(|| failure(ServiceFailure::DeadlineExceeded))?;
        if cap <= now.upper_ms {
            return Err(failure(ServiceFailure::DeadlineExceeded));
        }
        let deadline = Instant::now() + Duration::from_millis(cap - now.upper_ms);
        let admission = if method.semantics() == ServiceSemantics::Execution && !continuation {
            let offer = binding
                .snapshot
                .offer
                .as_ref()
                .ok_or_else(|| failure(ServiceFailure::AdmissionWindowClosed))?;
            let cutoff = options
                .admission_not_after_ms
                .unwrap_or(
                    offer
                        .not_after_ms()
                        .min(now.lower_ms.saturating_add(contract.uint(16)?)),
                )
                .min(cap);
            offer.check_interval(contract, cutoff, now.lower_ms, now.upper_ms)?;
            Some(cutoff)
        } else {
            if options.admission_not_after_ms.is_some() || options.operation_id.is_some() {
                return Err(failure(ServiceFailure::ConfigurationCapacity));
            }
            None
        };
        let account = self.0.peer.0.account.reserve_result()?;
        let group = account.application_group()?;
        let completion = group.completion_owner(options.context.as_ref())?;
        let request_limit = contract.uint(23)? as usize;
        let error_bytes =
            options
                .application_error_codecs
                .iter()
                .try_fold(0u64, |total, codec| {
                    total
                        .checked_add(codec.allowance())
                        .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))
                })?;
        let bytes = request_bytes
            .checked_add(response_bytes)
            .and_then(|bytes| bytes.checked_add(error_bytes))
            .and_then(|bytes| bytes.checked_add(request_limit as u64))
            .and_then(|bytes| bytes.checked_add(2 * u64::from(limit) + 16384))
            .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
        let charge = account.reserve(ResourceLimits {
            sdk_bytes: bytes,
            items: 4,
            tasks: if shape == ServiceShape::ServerStreaming {
                3
            } else {
                2
            },
            timers: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let callback_tail = self.0.peer.0.application_tail()?;
        Ok(PreparedOwner {
            callback_tail,
            peer: Arc::downgrade(&self.0.peer.0),
            binding,
            account,
            group,
            completion,
            charge,
            request_limit,
            response_limit: limit,
            cap,
            admission,
            deadline,
        })
    }
    fn complete_prepare<O: Send + 'static>(
        prepared: PreparedOwner,
        method: &MethodDefinition,
        payload: Zeroizing<Vec<u8>>,
        codec: ResponseCodec<O>,
        options: UnaryPrepareOptions,
    ) -> Result<UnaryOperation<O>> {
        let (header, reference) = Self::request_header(&prepared, method, &payload, &options)?;
        prepared.account.check()?;
        let peer = prepared
            .peer
            .upgrade()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        let offer = prepared.binding.snapshot.offer.clone();
        let operation = UnaryOperation::prepare(
            &peer,
            prepared.account,
            prepared.group,
            prepared.completion,
            prepared.callback_tail,
            codec,
            prepared.charge,
            header,
            payload,
            prepared.deadline,
            options.context,
            method.options().errors.clone(),
            options.application_error_codecs,
            reference,
            None,
        );
        operation.capture_admission_offer(offer);
        operation.capture_rpc_class(prepared.binding.rpc_class);
        Ok(operation)
    }
    pub(crate) fn reselect_unary<O: Send + 'static>(
        &self,
        method: &MethodDefinition,
        original: &UnaryOperation<O>,
    ) -> Result<UnaryOperation<O>> {
        let transfer = original.controller_preparation()?;
        let binding = self.ready_binding(method)?;
        let contract = binding
            .snapshot
            .contract
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::NotReady))?;
        if contract.digest() != transfer.header.bytes(6)?
            || transfer.payload.len() > contract.uint(23)? as usize
        {
            return Err(failure(ServiceFailure::ContractPolicyRejected));
        }
        if let Some(reference) = &transfer.reference {
            let target = reference.target();
            let identity = binding
                .options
                .execution_reference_identity
                .as_ref()
                .ok_or_else(|| failure(ServiceFailure::PermissionDenied))?;
            if reference.target_domain() != identity.target_domain
                || target.tenant != identity.tenant
                || target.audience != identity.audience
                || target.caller_subject != identity.caller_subject
                || target.caller_authority != identity.caller_authority
            {
                return Err(failure(ServiceFailure::PermissionDenied));
            }
        }
        let response_limit = u32::try_from(transfer.header.uint(8)?)
            .map_err(|_| failure(ServiceFailure::ResponseLimitUnsupported))?;
        let now = self.0.peer.0.account.security_time()?;
        let cap = transfer.header.uint(5)?;
        let remaining = cap
            .checked_sub(now.upper_ms)
            .filter(|remaining| *remaining > 0)
            .ok_or_else(|| failure(ServiceFailure::DeadlineExceeded))?;
        if method.semantics() == ServiceSemantics::Execution {
            let cutoff = u64::from_be_bytes(
                transfer.header.bytes(1)?[..8]
                    .try_into()
                    .expect("original execution cutoff"),
            );
            transfer
                .offer
                .as_ref()
                .ok_or_else(|| failure(ServiceFailure::AdmissionWindowClosed))?
                .check_interval(contract, cutoff, now.lower_ms, now.upper_ms)?;
        }
        let operation_id = if method.semantics() == ServiceSemantics::Execution {
            Some(transfer.header.bytes(1)?)
        } else {
            None
        };
        let options = UnaryPrepareOptions {
            timeout: Duration::from_millis(remaining),
            response_limit_bytes: Some(response_limit),
            admission_not_after_ms: operation_id
                .map(|id| u64::from_be_bytes(id[..8].try_into().expect("fixed execution cutoff"))),
            operation_id,
            context: transfer.context.clone(),
            admission: ServiceAdmission::Queue,
            application_error_codecs: transfer.error_codecs.clone(),
        };
        let prepared = self.prepare_owner(
            method,
            &method.options().request,
            transfer.codec.definition(),
            method.options().request.max_message_bytes() as u64,
            match &transfer.codec {
                ResponseCodec::Sync(codec) => codec.application_bytes(),
                ResponseCodec::Async(codec) => codec.application_bytes(),
            },
            &options,
        )?;
        let peer = prepared
            .peer
            .upgrade()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        let operation = UnaryOperation::prepare(
            &peer,
            prepared.account,
            prepared.group,
            prepared.completion,
            prepared.callback_tail,
            transfer.codec,
            prepared.charge,
            transfer.header,
            transfer.payload,
            transfer.deadline,
            transfer.context,
            method.options().errors.clone(),
            transfer.error_codecs,
            transfer.reference,
            Some(transfer.diagnostics),
        );
        operation.capture_admission_offer(transfer.offer);
        operation.capture_rpc_class(transfer.rpc_class);
        Ok(operation)
    }
    fn request_header(
        prepared: &PreparedOwner,
        method: &MethodDefinition,
        payload: &[u8],
        options: &UnaryPrepareOptions,
    ) -> Result<(ApplicationHeader, Option<crate::OperationReference>)> {
        Self::request_header_for(prepared, method, payload, options, false)
    }
    fn request_header_for(
        prepared: &PreparedOwner,
        method: &MethodDefinition,
        payload: &[u8],
        options: &UnaryPrepareOptions,
        resume: bool,
    ) -> Result<(ApplicationHeader, Option<crate::OperationReference>)> {
        let contract = prepared
            .binding
            .snapshot
            .contract
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
        let mut fields = [None; 11];
        fields[2] = Some(HeaderScalar::Uint(u64::from(method.type_id())));
        fields[3] = Some(HeaderScalar::Uint(payload.len() as u64));
        fields[5] = Some(HeaderScalar::Uint(prepared.cap));
        fields[6] = Some(HeaderScalar::Bytes(contract.digest()));
        fields[8] = Some(HeaderScalar::Uint(u64::from(prepared.response_limit)));
        fields[7] = Some(HeaderScalar::Uint(u64::from(
            options.admission == ServiceAdmission::TryNow,
        )));
        let kind = if method.semantics() == ServiceSemantics::Execution {
            let cutoff = prepared
                .admission
                .ok_or_else(|| failure(ServiceFailure::AdmissionWindowClosed))?;
            let mut operation = options.operation_id.unwrap_or([0; 32]);
            if options.operation_id.is_none() {
                ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut operation)
                    .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
                operation[..8].copy_from_slice(&cutoff.to_be_bytes());
            }
            if u64::from_be_bytes(
                operation[..8]
                    .try_into()
                    .map_err(|_| failure(ServiceFailure::ConfigurationCapacity))?,
            ) != cutoff
            {
                return Err(failure(ServiceFailure::ConfigurationCapacity));
            }
            fields[1] = Some(HeaderScalar::Bytes(operation));
            fields[4] = Some(HeaderScalar::Bytes([0; 32]));
            if resume {
                "resume_request"
            } else if method.shape() == ServiceShape::ServerStreaming {
                "execution_stream_request"
            } else {
                "execution_unary_request"
            }
        } else {
            if method.shape() == ServiceShape::ServerStreaming {
                "transient_stream_request"
            } else {
                "transient_unary_request"
            }
        };
        let mut header = ApplicationHeader::create(kind, fields)?;
        if method.semantics() == ServiceSemantics::Execution {
            fields[4] = Some(HeaderScalar::Bytes(rpc_wire_v4::execution_digest(
                contract.encoded(),
                &header,
                payload,
            )?));
            header = ApplicationHeader::create(kind, fields)?;
        }
        let reference = match (
            &prepared.binding.reference_codec,
            &prepared.binding.options.execution_reference_identity,
        ) {
            (Some(codec), Some(identity)) => Some(codec.capture(
                crate::ExecutionTarget {
                    tenant: identity.tenant.clone(),
                    audience: identity.audience.clone(),
                    namespace: contract.namespace().to_owned(),
                    caller_subject: identity.caller_subject.clone(),
                    caller_authority: identity.caller_authority,
                    operation_id: header.bytes(1)?,
                    request_digest: header.bytes(4)?,
                    contract_digest: contract.digest(),
                },
                &header,
                contract,
            )?),
            (None, None) => None,
            _ => return Err(failure(ServiceFailure::ConfigurationCapacity)),
        };
        Ok((header, reference))
    }
    pub fn prepare_resume(
        &self,
        method: &MethodDefinition,
        target: &crate::Stream,
        token: &crate::ApplicationCheckpointToken,
        options: UnaryPrepareOptions,
    ) -> Result<UnaryOperation<crate::ApplicationResumeResult>> {
        self.prepare_resume_with_limit(method, target, token, options, 0)
    }
    fn prepare_resume_with_limit(
        &self,
        method: &MethodDefinition,
        target: &crate::Stream,
        token: &crate::ApplicationCheckpointToken,
        options: UnaryPrepareOptions,
        continuation_limit: usize,
    ) -> Result<UnaryOperation<crate::ApplicationResumeResult>> {
        let response = method
            .options()
            .response
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
        let prepared = self.prepare_owner_for_mode(
            ServiceShape::Unary,
            method,
            &method.options().request,
            response,
            16384,
            8192,
            &options,
            true,
        )?;
        let binding = prepared
            .binding
            .options
            .resume
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
        let identity = prepared
            .binding
            .options
            .execution_reference_identity
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
        let contract = prepared
            .binding
            .snapshot
            .contract
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
        if token.tenant != identity.tenant
            || token.audience != identity.audience
            || token.caller != identity.caller_subject
            || token.namespace != contract.namespace()
        {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        let peer = prepared
            .peer
            .upgrade()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        let session = peer
            .session
            .session()
            .map_err(|_| failure(ServiceFailure::Closed))?;
        let signed = session
            .checkpoint_policy()
            .map_err(|_| failure(ServiceFailure::PermissionDenied))?;
        let now = prepared.account.security_time()?;
        if token.encoded().len() > signed.max_token_bytes as usize
            || now.lower_ms < token.issued_at_ms()
            || now.upper_ms >= token.expires_at_ms()
        {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        target
            .check_resume_metadata(&session, &binding.stream_kind, &binding.stream_metadata)
            .map_err(|_| failure(ServiceFailure::ContractMismatch))?;
        // No recovery operation identity exists before this original target
        // qualification and local incarnation have been captured.
        let (messages, target_binding) =
            crate::rpc_stream_messages_v4::StreamMessages::prepare_resume(
                &session,
                &peer.channel,
                target,
                &binding.stream_kind,
                prepared
                    .request_limit
                    .max(prepared.response_limit as usize)
                    .max(continuation_limit),
                false,
                prepared.deadline,
            )?;
        let messages = Arc::new(messages);
        messages.retain_peer(&peer);
        let payload = Zeroizing::new(
            crate::checkpoint_v4::ApplicationResumeRequest::prepare(token, target_binding.clone())?
                .encoded()?,
        );
        if payload.len() > prepared.request_limit {
            return Err(failure(ServiceFailure::EncodeFailed));
        }
        let result_size = crate::ApplicationResumeResult::accepted(
            token.checkpoint().clone(),
            token
                .generation()
                .checked_add(1)
                .ok_or_else(|| failure(ServiceFailure::OperationConflict))?,
        )?
        .encoded()?
        .len();
        if result_size > prepared.response_limit as usize
            || result_size > response.max_message_bytes() as usize
        {
            return Err(failure(ServiceFailure::ResponseLimitUnsupported));
        }
        let (header, reference) =
            Self::request_header_for(&prepared, method, &payload, &options, true)?;
        messages.set_resume_request(header.clone())?;
        messages.check_resume_target(&session, &target_binding)?;
        let codec = Arc::new(crate::message_codec_v4::ResumeResultCodec::new(
            response.clone(),
        ));
        Ok(UnaryOperation::prepare_resume(
            &peer,
            prepared.account,
            prepared.group,
            prepared.completion,
            prepared.callback_tail,
            ResponseCodec::Sync(codec),
            prepared.charge,
            header,
            payload,
            prepared.deadline,
            options.context,
            method.options().errors.clone(),
            options.application_error_codecs,
            reference,
            messages,
            target_binding,
            token.expires_at_ms(),
        ))
    }
    /// Capture both finite graphs before Start. The original selector never
    /// sends its request again; accepted Resume alone activates its item reader.
    #[expect(
        clippy::too_many_arguments,
        reason = "Service preparation keeps request/response codecs, original method binding and durable save ownership explicit."
    )]
    pub fn prepare_stream_resume<O: Send + 'static>(
        &self,
        resume_method: &MethodDefinition,
        original_method: &MethodDefinition,
        target: &crate::Stream,
        token: &crate::ApplicationCheckpointToken,
        original: &crate::StreamingResumeState,
        item_codec: Arc<dyn MessageCodec<O>>,
        item_error_codecs: Vec<crate::ApplicationErrorCodec>,
        options: UnaryPrepareOptions,
    ) -> Result<crate::StreamingResumeOperation<O>> {
        let header = original.request();
        let reference = original.reference();
        let selector = reference.target();
        if selector.tenant != token.tenant
            || selector.audience != token.audience
            || selector.namespace != token.namespace
            || selector.caller_subject != token.caller
            || selector.operation_id != token.operation
            || selector.request_digest != token.request
            || original_method.semantics() != ServiceSemantics::Execution
            || original_method.shape() != ServiceShape::ServerStreaming
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let now = self.0.peer.0.account.security_time()?;
        if now.upper_ms >= original.until_ms() {
            return Err(failure(ServiceFailure::DeadlineExceeded));
        }
        let mut continuation_options = options.clone();
        continuation_options.application_error_codecs = item_error_codecs;
        continuation_options.response_limit_bytes = Some(header.uint(8)? as u32);
        continuation_options.timeout = Duration::from_millis(original.until_ms() - now.upper_ms);
        continuation_options.admission_not_after_ms = None;
        continuation_options.operation_id = None;
        let prepared = self.capture_owner(
            ServiceShape::ServerStreaming,
            original_method,
            &original_method.options().request,
            item_codec.definition(),
            0,
            item_codec.application_bytes(),
            &continuation_options,
            false,
            true,
        )?;
        let contract = prepared
            .binding
            .snapshot
            .contract
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
        let identity = prepared
            .binding
            .options
            .execution_reference_identity
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
        let limits = original.limits();
        if contract.digest() != selector.contract_digest
            || contract.type_id() != header.type_id()?
            || contract.optional_uint(13) != Some(1)
            || contract.uint(24)? != u64::from(limits.max_item_count)
            || contract.uint(25)? != limits.max_payload_bytes
            || contract.uint(26)? != limits.max_duration_ms
            || identity.tenant != selector.tenant
            || identity.audience != selector.audience
            || identity.caller_subject != selector.caller_subject
            || identity.caller_authority != selector.caller_authority
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let binding = prepared
            .binding
            .options
            .streaming
            .clone()
            .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
        let resume_binding = self
            .0
            .methods
            .lock()
            .expect("bound methods")
            .iter()
            .find(|bound| bound.options.method.same(resume_method))
            .and_then(|bound| bound.options.resume.clone())
            .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
        if binding.stream_kind != resume_binding.stream_kind
            || binding.stream_metadata != resume_binding.stream_metadata
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let operation = self.prepare_resume_with_limit(
            resume_method,
            target,
            token,
            options.clone(),
            prepared.response_limit as usize,
        )?;
        let messages = operation.resume_messages()?;
        let peer = prepared
            .peer
            .upgrade()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        let continuation = crate::StreamingOperation::prepare(
            &peer,
            prepared.account,
            prepared.completion,
            prepared.charge,
            messages,
            crate::streaming_operation_v4::StreamingTransport::Resume,
            binding,
            header,
            Zeroizing::new(Vec::new()),
            prepared.deadline,
            limits,
            ResponseCodec::Sync(item_codec),
            original_method.options().errors.clone(),
            continuation_options.application_error_codecs,
            Some(reference),
            options.context,
        )?;
        continuation.retain_resume_state(original)?;
        operation.bind_resume_continuation(Arc::new(continuation.clone()))?;
        Ok(crate::StreamingResumeOperation {
            operation,
            continuation,
        })
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Service preparation keeps request/response codecs, original method binding and durable save ownership explicit."
    )]
    pub async fn prepare_stream_resume_and_save<O: Send + 'static>(
        &self,
        resume_method: &MethodDefinition,
        original_method: &MethodDefinition,
        target: &crate::Stream,
        token: &crate::ApplicationCheckpointToken,
        original: &crate::StreamingResumeState,
        item_codec: Arc<dyn MessageCodec<O>>,
        item_error_codecs: Vec<crate::ApplicationErrorCodec>,
        options: UnaryPrepareOptions,
        store: Arc<dyn crate::OperationReferenceStore>,
        cancellation: CancellationToken,
    ) -> std::result::Result<crate::SavedStreamingResumePreparation<O>, crate::PrepareAndSaveError>
    {
        let context = options.context.clone();
        let operation = self
            .prepare_stream_resume(
                resume_method,
                original_method,
                target,
                token,
                original,
                item_codec,
                item_error_codecs,
                options,
            )
            .map_err(crate::PrepareAndSaveError::Preparation)?;
        let saved = crate::reference_store_v4::save(
            operation.operation.clone(),
            store,
            self.0.peer.0.account.clone(),
            self.0.peer.0.group.clone(),
            context,
            cancellation,
        )
        .await
        .map_err(crate::PrepareAndSaveError::Save)?;
        Ok(crate::SavedStreamingResumePreparation {
            operation,
            reference: saved.reference,
            receipt: saved.receipt,
        })
    }
    pub async fn prepare_resume_and_save(
        &self,
        method: &MethodDefinition,
        target: &crate::Stream,
        token: &crate::ApplicationCheckpointToken,
        options: UnaryPrepareOptions,
        store: Arc<dyn crate::OperationReferenceStore>,
        cancellation: CancellationToken,
    ) -> std::result::Result<
        crate::SavedUnaryPreparation<crate::ApplicationResumeResult>,
        crate::PrepareAndSaveError,
    > {
        let context = options.context.clone();
        let operation = self
            .prepare_resume(method, target, token, options)
            .map_err(crate::PrepareAndSaveError::Preparation)?;
        crate::reference_store_v4::save(
            operation,
            store,
            self.0.peer.0.account.clone(),
            self.0.peer.0.group.clone(),
            context,
            cancellation,
        )
        .await
        .map_err(crate::PrepareAndSaveError::Save)
    }
    pub fn resume(
        &self,
        method: &MethodDefinition,
        target: &crate::Stream,
        token: &crate::ApplicationCheckpointToken,
        options: UnaryPrepareOptions,
    ) -> Result<UnaryOperation<crate::ApplicationResumeResult>> {
        let operation = self.prepare_resume(method, target, token, options)?;
        operation.start()?;
        Ok(operation)
    }
    pub fn prepare_stream_operation<I: Sync + 'static, O: Send + 'static>(
        &self,
        method: &MethodDefinition,
        value: &I,
        request_codec: Arc<dyn MessageCodec<I>>,
        item_codec: Arc<dyn MessageCodec<O>>,
        options: crate::StreamingPrepareOptions,
    ) -> Result<crate::StreamingOperation<O>> {
        let common = options.common();
        let prepared = self.prepare_owner_for(
            ServiceShape::ServerStreaming,
            method,
            request_codec.definition(),
            item_codec.definition(),
            request_codec.application_bytes(),
            item_codec.application_bytes(),
            &common,
        )?;
        prepared
            .binding
            .options
            .streaming
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
        let peer = prepared
            .peer
            .upgrade()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        let session = peer
            .session
            .session()
            .map_err(|_| failure(ServiceFailure::Closed))?;
        let (messages, preparation) = self.stream_transport(
            &prepared,
            &session,
            options.context.is_some() || options.admission == ServiceAdmission::TryNow,
        )?;
        let mut payload = Zeroizing::new(vec![0; prepared.request_limit]);
        let mut encode = |context: ApplicationInvocationContext| {
            let _business = admit_encoding_work(&peer)?;
            std::panic::catch_unwind(AssertUnwindSafe(|| {
                request_codec.encode_with_context(value, &mut payload, &context)
            }))
            .unwrap_or_else(|_| Err(failure(ServiceFailure::EncodeFailed)))
        };
        let length = match options.context.as_ref() {
            Some(context) => peer.group.synchronous_stage(context, encode)??,
            None => {
                let position = peer.group.try_ordinary(false, None)?;
                let invocation = position.enter()?;
                encode(invocation.context())?
            }
        };
        if length > prepared.request_limit {
            return Err(failure(ServiceFailure::EncodeFailed));
        }
        payload.truncate(length);
        Self::complete_stream_prepare(
            prepared,
            method,
            payload,
            ResponseCodec::Sync(item_codec),
            options,
            messages,
            preparation,
        )
    }
    /// Persist the exact prepared execution-stream reference before returning
    /// its Start-capable handle. The store receives no payload or replay key.
    #[expect(
        clippy::too_many_arguments,
        reason = "Service preparation keeps request/response codecs, original method binding and durable save ownership explicit."
    )]
    pub async fn prepare_and_save_stream<I: Sync + 'static, O: Send + 'static>(
        &self,
        method: &MethodDefinition,
        value: &I,
        request_codec: Arc<dyn MessageCodec<I>>,
        item_codec: Arc<dyn MessageCodec<O>>,
        options: crate::StreamingPrepareOptions,
        store: Arc<dyn crate::OperationReferenceStore>,
        cancellation: CancellationToken,
    ) -> std::result::Result<crate::SavedStreamingPreparation<O>, crate::PrepareAndSaveError> {
        if method.semantics() != ServiceSemantics::Execution {
            return Err(crate::PrepareAndSaveError::Preparation(failure(
                ServiceFailure::ConfigurationCapacity,
            )));
        }
        let context = options.context.clone();
        let operation = self
            .prepare_stream_operation(method, value, request_codec, item_codec, options)
            .map_err(crate::PrepareAndSaveError::Preparation)?;
        crate::reference_store_v4::save_streaming(
            operation,
            store,
            self.0.peer.0.account.clone(),
            self.0.peer.0.group.clone(),
            context,
            cancellation,
        )
        .await
        .map_err(crate::PrepareAndSaveError::Save)
    }
    /// Async-codec counterpart of `prepare_and_save_stream`; preparation and
    /// persistence use separate child scopes so cancellation cannot duplicate
    /// or silently discard the original operation owner.
    #[expect(
        clippy::too_many_arguments,
        reason = "Service preparation keeps request/response codecs, original method binding and durable save ownership explicit."
    )]
    pub async fn prepare_and_save_stream_async<I: Send + Sync + 'static, O: Send + 'static>(
        &self,
        method: &MethodDefinition,
        value: Arc<I>,
        request_codec: Arc<dyn AsyncMessageCodec<I>>,
        item_codec: Arc<dyn AsyncMessageCodec<O>>,
        options: crate::StreamingPrepareOptions,
        store: Arc<dyn crate::OperationReferenceStore>,
        cancellation: CancellationToken,
    ) -> std::result::Result<crate::SavedStreamingPreparation<O>, crate::PrepareAndSaveError> {
        if method.semantics() != ServiceSemantics::Execution {
            return Err(crate::PrepareAndSaveError::Preparation(failure(
                ServiceFailure::ConfigurationCapacity,
            )));
        }
        let context = options.context.clone();
        let operation = self
            .prepare_stream_operation_async(
                method,
                value,
                request_codec,
                item_codec,
                options,
                cancellation.child_token(),
            )
            .await
            .map_err(crate::PrepareAndSaveError::Preparation)?;
        crate::reference_store_v4::save_streaming(
            operation,
            store,
            self.0.peer.0.account.clone(),
            self.0.peer.0.group.clone(),
            context,
            cancellation,
        )
        .await
        .map_err(crate::PrepareAndSaveError::Save)
    }
    fn stream_transport(
        &self,
        prepared: &PreparedOwner,
        session: &crate::crypto_v4::Session,
        require_accepted: bool,
    ) -> Result<(
        Arc<crate::rpc_stream_messages_v4::StreamMessages>,
        crate::streaming_operation_v4::StreamingTransport,
    )> {
        if require_accepted {
            let demand = match &prepared.binding.pool {
                Some(pool) => Some(pool.clone()),
                None if prepared.binding.pool_policy.is_some() => session.demand_stream_pool(
                    &self.0.peer.0,
                    pool_target(&self.0.definition, &prepared.binding)?,
                    crate::StreamingPoolPolicy::OnUse,
                )?,
                None => None,
            }
            .ok_or_else(|| failure(ServiceFailure::DependencyUnavailable))?;
            return Ok((
                demand.checkout()?,
                crate::streaming_operation_v4::StreamingTransport::Accepted,
            ));
        }
        let peer = prepared
            .peer
            .upgrade()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        let (messages, preparation) = crate::rpc_stream_messages_v4::StreamMessages::prepare(
            session,
            &peer.channel,
            prepared.request_limit.max(prepared.response_limit as usize),
            None,
        )?;
        messages.retain_peer(&peer);
        Ok((
            Arc::new(messages),
            crate::streaming_operation_v4::StreamingTransport::Opening(preparation),
        ))
    }
    fn complete_stream_prepare<O: Send + 'static>(
        prepared: PreparedOwner,
        method: &MethodDefinition,
        payload: Zeroizing<Vec<u8>>,
        codec: ResponseCodec<O>,
        options: crate::StreamingPrepareOptions,
        messages: Arc<crate::rpc_stream_messages_v4::StreamMessages>,
        preparation: crate::streaming_operation_v4::StreamingTransport,
    ) -> Result<crate::StreamingOperation<O>> {
        let peer = prepared
            .peer
            .upgrade()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        let (header, reference) =
            Self::request_header(&prepared, method, &payload, &options.common())?;
        let contract = prepared
            .binding
            .snapshot
            .contract
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
        let limits = crate::StreamingLimits {
            max_item_count: contract.uint(24)? as u32,
            max_payload_bytes: contract.uint(25)?,
            max_duration_ms: contract.uint(26)?,
        };
        let stream_binding = prepared
            .binding
            .options
            .streaming
            .clone()
            .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
        messages.set_response_request(header.clone())?;
        crate::streaming_operation_v4::StreamingOperation::prepare(
            &peer,
            prepared.account,
            prepared.completion,
            prepared.charge,
            messages,
            preparation,
            stream_binding,
            header,
            payload,
            prepared.deadline,
            limits,
            codec,
            method.options().errors.clone(),
            options.application_error_codecs,
            reference,
            options.context,
        )
    }
    /// The asynchronous request callback has one original invocation and one
    /// delivery gate. Cancellation abandons delivery, never its actual exit.
    pub async fn prepare_stream_operation_async<I: Send + Sync + 'static, O: Send + 'static>(
        &self,
        method: &MethodDefinition,
        value: Arc<I>,
        request_codec: Arc<dyn AsyncMessageCodec<I>>,
        item_codec: Arc<dyn AsyncMessageCodec<O>>,
        options: crate::StreamingPrepareOptions,
        cancellation: CancellationToken,
    ) -> Result<crate::StreamingOperation<O>> {
        let common = options.common();
        let prepared = self.prepare_owner_for(
            ServiceShape::ServerStreaming,
            method,
            request_codec.definition(),
            item_codec.definition(),
            request_codec.application_bytes(),
            item_codec.application_bytes(),
            &common,
        )?;
        prepared
            .binding
            .options
            .streaming
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
        let peer = prepared
            .peer
            .upgrade()
            .ok_or_else(|| failure(ServiceFailure::Closed))?;
        let session = peer
            .session
            .session()
            .map_err(|_| failure(ServiceFailure::Closed))?;
        let (messages, preparation) = self.stream_transport(
            &prepared,
            &session,
            options.context.is_some() || options.admission == ServiceAdmission::TryNow,
        )?;
        let business = admit_encoding_work(&peer)?;
        let ordinary = peer.group.admit_ordinary(
            false,
            options.context.as_ref(),
            options.admission == ServiceAdmission::TryNow,
        )?;
        let deadline = prepared.deadline;
        let position = tokio::select! {
            position = ordinary.position() => position?,
            _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)),
            _ = tokio::time::sleep_until(deadline) => return Err(failure(ServiceFailure::DeadlineExceeded)),
        };
        let delivery = Arc::new(Mutex::new(true));
        let original_cancellation = cancellation.child_token();
        let _observer = PreparationObserver {
            delivery: delivery.clone(),
            cancellation: original_cancellation.clone(),
        };
        let method = method.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _business = business;
            let invocation = match position.enter() {
                Ok(invocation) => invocation,
                Err(error) => {
                    let _ = sender.send(Err(error.into()));
                    return;
                }
            };
            let permitted = prepared.account.with_security(|| {
                *delivery.lock().expect("preparation delivery")
                    && !original_cancellation.is_cancelled()
                    && Instant::now() < deadline
            });
            if !matches!(permitted, Ok(true)) {
                let _ = sender.send(Err(failure(ServiceFailure::Canceled)));
                return;
            }
            let callback =
                AssertUnwindSafe(request_codec.encode(&value, invocation.context())).catch_unwind();
            tokio::pin!(callback);
            let outcome = loop {
                tokio::select! {
                    outcome = &mut callback => break outcome,
                    _ = original_cancellation.cancelled() => {
                        messages.close(); invocation.cancel(); break callback.await;
                    },
                    _ = tokio::time::sleep_until(deadline) => {
                        *delivery.lock().expect("preparation delivery") = false;
                        messages.close(); invocation.cancel(); break callback.await;
                    },
                    _ = prepared.account.security_changed() => {},
                    _ = tokio::time::sleep(prepared.account.next_security_check()) => {},
                }
                if prepared.account.check().is_err()
                    || invocation.context().check_cancellation().is_err()
                {
                    *delivery.lock().expect("preparation delivery") = false;
                    messages.close();
                    invocation.cancel();
                    break callback.await;
                }
            }
            .unwrap_or_else(|_| Err(failure(ServiceFailure::EncodeFailed)));
            drop(invocation);
            drop(position);
            let payload = match outcome {
                Ok(payload) if payload.len() <= prepared.request_limit => Zeroizing::new(payload),
                _ => {
                    let _ = sender.send(Err(failure(ServiceFailure::EncodeFailed)));
                    return;
                }
            };
            if !*delivery.lock().expect("preparation delivery")
                || original_cancellation.is_cancelled()
                || Instant::now() >= deadline
            {
                let _ = sender.send(Err(failure(ServiceFailure::Canceled)));
                return;
            }
            let candidate = Self::complete_stream_prepare(
                prepared,
                &method,
                payload,
                ResponseCodec::Async(item_codec),
                options,
                messages,
                preparation,
            );
            match candidate {
                Err(error) => {
                    let _ = sender.send(Err(error));
                }
                Ok(operation) => {
                    let account = operation.result_account();
                    let delivered = account.with_security(|| {
                        let gate = delivery.lock().expect("preparation delivery");
                        if !*gate
                            || original_cancellation.is_cancelled()
                            || Instant::now() >= deadline
                        {
                            return Err((sender, operation));
                        }
                        Ok(sender.send(Ok(operation)))
                    });
                    match delivered {
                        Ok(Err((sender, operation))) => {
                            operation.close();
                            let _ = sender.send(Err(failure(ServiceFailure::Canceled)));
                        }
                        Ok(Ok(Err(Ok(operation)))) => operation.close(),
                        _ => {}
                    }
                }
            }
        });
        tokio::select! {
            result = receiver => result.unwrap_or_else(|_| Err(failure(ServiceFailure::ServiceUnavailable))),
            _ = cancellation.cancelled() => Err(failure(ServiceFailure::Canceled)),
            _ = tokio::time::sleep_until(deadline) => Err(failure(ServiceFailure::DeadlineExceeded)),
        }
    }
    pub async fn stream_async<I: Send + Sync + 'static, O: Send + 'static>(
        &self,
        method: &MethodDefinition,
        value: Arc<I>,
        request_codec: Arc<dyn AsyncMessageCodec<I>>,
        item_codec: Arc<dyn AsyncMessageCodec<O>>,
        options: crate::StreamingPrepareOptions,
        cancellation: CancellationToken,
    ) -> Result<crate::StreamingOperation<O>> {
        let operation = self
            .prepare_stream_operation_async(
                method,
                value,
                request_codec,
                item_codec,
                options,
                cancellation,
            )
            .await?;
        operation.start()?;
        Ok(operation)
    }
    pub fn stream<I: Sync + 'static, O: Send + 'static>(
        &self,
        method: &MethodDefinition,
        value: &I,
        request_codec: Arc<dyn MessageCodec<I>>,
        item_codec: Arc<dyn MessageCodec<O>>,
        options: crate::StreamingPrepareOptions,
    ) -> Result<crate::StreamingOperation<O>> {
        let operation =
            self.prepare_stream_operation(method, value, request_codec, item_codec, options)?;
        operation.start()?;
        Ok(operation)
    }
}
struct PreparedOwner {
    callback_tail: crate::application_tails_v4::ApplicationTail,
    peer: std::sync::Weak<crate::service_peer_v4::PeerInner>,
    binding: BoundMethod,
    account: crate::environment_v4::ResourceAccount,
    group: crate::application_executor_v4::ApplicationGroup,
    completion: crate::application_executor_v4::CompletionOwner,
    charge: ResourceCharge,
    request_limit: usize,
    response_limit: u32,
    cap: u64,
    admission: Option<u64>,
    deadline: Instant,
}

struct PreparationObserver {
    delivery: Arc<Mutex<bool>>,
    cancellation: CancellationToken,
}
impl Drop for PreparationObserver {
    fn drop(&mut self) {
        *self.delivery.lock().expect("preparation delivery") = false;
        self.cancellation.cancel();
    }
}

#[derive(Clone, Debug)]
pub struct NotificationPrepareOptions {
    pub timeout: Duration,
    pub operation_id: Option<[u8; 32]>,
    pub admission_not_after_ms: Option<u64>,
    pub context: Option<ApplicationInvocationContext>,
}
impl Default for NotificationPrepareOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            operation_id: None,
            admission_not_after_ms: None,
            context: None,
        }
    }
}
impl ServiceClient {
    /// Encode once against the captured method and original invocation. Start
    /// submits the returned operation once; no waiter or reconnect re-encodes it.
    pub async fn prepare_notification<T: Send + Sync + 'static>(
        &self,
        notifications: &crate::NotificationPeer,
        method: &MethodDefinition,
        value: Arc<T>,
        codec: Arc<dyn MessageCodec<T>>,
        options: NotificationPrepareOptions,
        cancellation: CancellationToken,
    ) -> Result<crate::NotificationOperation> {
        self.0.peer.0.check()?;
        notifications.catalog(&self.0.peer.0.account)?;
        if method.shape() != ServiceShape::Notify
            || codec.definition() != &method.options().request
            || codec.application_bytes() == 0
            || codec.application_bytes() > 1 << 30
            || options.timeout.is_zero()
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let binding = self.ready_binding(method)?;
        let contract = binding
            .snapshot
            .contract
            .as_ref()
            .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?
            .clone();
        if options.timeout.as_millis() > u128::from(contract.uint(11)?) {
            return Err(failure(ServiceFailure::DeadlineExceeded));
        }
        let now = self.0.peer.0.account.security_time()?;
        let cap = now
            .lower_ms
            .checked_add(options.timeout.as_millis() as u64)
            .ok_or_else(|| failure(ServiceFailure::DeadlineExceeded))?;
        if cap <= now.upper_ms {
            return Err(failure(ServiceFailure::DeadlineExceeded));
        }
        let deadline = Instant::now() + Duration::from_millis(cap - now.upper_ms);
        let execution = if method.semantics() == ServiceSemantics::Execution {
            let offer = binding
                .snapshot
                .offer
                .as_ref()
                .ok_or_else(|| failure(ServiceFailure::AdmissionWindowClosed))?
                .clone();
            let cutoff = options
                .admission_not_after_ms
                .unwrap_or(
                    offer
                        .not_after_ms()
                        .min(now.lower_ms.saturating_add(contract.uint(16)?)),
                )
                .min(cap);
            offer.check_interval(&contract, cutoff, now.lower_ms, now.upper_ms)?;
            let mut operation = options.operation_id.unwrap_or([0; 32]);
            if options.operation_id.is_none() {
                ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut operation)
                    .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
                operation[..8].copy_from_slice(&cutoff.to_be_bytes());
            }
            if u64::from_be_bytes(
                operation[..8]
                    .try_into()
                    .map_err(|_| failure(ServiceFailure::Protocol))?,
            ) != cutoff
            {
                return Err(failure(ServiceFailure::ConfigurationCapacity));
            }
            Some((operation, offer))
        } else {
            if options.operation_id.is_some() || options.admission_not_after_ms.is_some() {
                return Err(failure(ServiceFailure::ConfigurationCapacity));
            }
            None
        };
        let account = self.0.peer.0.account.reserve_result()?;
        let group = account.application_group()?;
        let maximum = contract.uint(23)? as usize;
        let retained = {
            let value = value.as_ref() as &dyn std::any::Any;
            if let Some(value) = value.downcast_ref::<Vec<u8>>() {
                value.capacity() as u64
            } else if let Some(value) = value.downcast_ref::<String>() {
                value.capacity() as u64
            } else {
                std::mem::size_of::<T>() as u64
            }
        };
        let charge = Arc::new(account.reserve(ResourceLimits {
            sdk_bytes: codec.application_bytes() + retained + 2 * maximum as u64 + 8192,
            items: 3,
            tasks: 2,
            timers: 1,
            ..ResourceLimits::default()
        })?);
        let payload = if let Some(context) = options
            .context
            .as_ref()
            .filter(|_| crate::message_codec_v4::controlled(codec.as_ref()))
        {
            group.synchronous_stage(context, |context| {
                let _business = admit_encoding_work(&self.0.peer.0)?;
                let mut payload = Zeroizing::new(vec![0; maximum]);
                let size = codec.encode_with_context(value.as_ref(), &mut payload, &context)?;
                if size > maximum {
                    return Err(failure(ServiceFailure::EncodeFailed));
                }
                payload.truncate(size);
                Ok(payload)
            })??
        } else {
            let business = admit_encoding_work(&self.0.peer.0)?;
            let position = tokio::select! { position = group.ordinary(false, options.context.as_ref()) => position?,
            _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)),
            _ = tokio::time::sleep_until(deadline) => return Err(failure(ServiceFailure::DeadlineExceeded)) };
            let invocation = position.enter()?;
            let original = invocation.cancellation();
            let backing = charge.clone();
            let worker_backing = backing.clone();
            let callback_codec = codec.clone();
            let callback_value = value.clone();
            let callback_account = account.clone();
            let callback_cancellation = cancellation.clone();
            let (sender, receiver) = tokio::sync::oneshot::channel();
            tokio::task::spawn_blocking(move || {
                let _business = business;
                let _backing = worker_backing;
                let outcome = (|| {
                    callback_account.check()?;
                    if callback_cancellation.is_cancelled() || Instant::now() >= deadline {
                        return Err(failure(ServiceFailure::Canceled));
                    }
                    let mut payload = Zeroizing::new(vec![0; maximum]);
                    let size = std::panic::catch_unwind(AssertUnwindSafe(|| {
                        callback_codec.encode_with_context(
                            callback_value.as_ref(),
                            &mut payload,
                            &invocation.context(),
                        )
                    }))
                    .unwrap_or_else(|_| Err(failure(ServiceFailure::EncodeFailed)))?;
                    if size > maximum {
                        return Err(failure(ServiceFailure::EncodeFailed));
                    }
                    payload.truncate(size);
                    Ok(payload)
                })();
                let _ = sender.send(outcome);
                drop(invocation);
                drop(position);
            });
            tokio::select! { payload = receiver => payload.map_err(|_| failure(ServiceFailure::EncodeFailed))??,
            _ = cancellation.cancelled() => { original.cancel(); return Err(failure(ServiceFailure::Canceled)); },
            _ = tokio::time::sleep_until(deadline) => { original.cancel(); return Err(failure(ServiceFailure::DeadlineExceeded)); } }
        };
        account.check()?;
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            return Err(failure(ServiceFailure::Canceled));
        }
        let now = account.security_time()?;
        let remaining = cap
            .checked_sub(now.upper_ms)
            .filter(|remaining| *remaining != 0)
            .ok_or_else(|| failure(ServiceFailure::DeadlineExceeded))?;
        let operation = notifications.prepare_encoded_owned(
            &contract,
            &payload,
            Duration::from_millis(remaining),
            execution.as_ref().map(|(id, offer)| (*id, offer)),
            Some((account, charge)),
        )?;
        if let (Some(codec), Some(identity)) = (
            &binding.reference_codec,
            &binding.options.execution_reference_identity,
        ) {
            operation.capture_reference(codec, identity, &contract)?;
        }
        Ok(operation)
    }
}
