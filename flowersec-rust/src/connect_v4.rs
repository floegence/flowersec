//! Current direct carrier assembly for one original authorized attempt.
use super::*;
use crate::{
    api_v4::TransportEnvironment,
    application_lifetime_v4::{ApplicationLifetime, ApplicationLimits, CallbackKind},
    environment_v4::{
        EnvironmentCharge, EnvironmentError, EnvironmentRoot, ResourceAccount, ResourceCharge,
        ResourceLimits,
    },
    namespace_v4::verifier::{
        NamespaceVerifier,
        credential::{DirectCredentialInput, reserve_direct_connection},
    },
    pool_v4::{PoolSpendOwner, PoolStoreError, PoolStoreFailure, SQLitePoolStore},
};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex, atomic::AtomicUsize},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
#[path = "direct_carrier_v4.rs"]
mod direct_carrier;
#[path = "direct_listener_v4.rs"]
mod direct_listener;
#[path = "hop_authentication_v4.rs"]
mod hop;
#[path = "native_v4.rs"]
mod native;
#[path = "registered_pool_server_v4.rs"]
pub(crate) mod registered_pool;
#[path = "reverse_tunnel_v4.rs"]
pub(crate) mod reverse;
#[path = "serve_v4.rs"]
pub(crate) mod serve;
#[path = "wss_v4.rs"]
pub(crate) mod wss;
pub use reverse::ReverseTunnelProviderOptions;
#[path = "native_relay_pair_v4.rs"]
mod native_relay_pair;
#[path = "relay_hop_authentication_v4.rs"]
mod relay_hop;
#[path = "relay_original_delivery_v4.rs"]
mod relay_original_delivery;
#[path = "relay_publication_v4.rs"]
pub(crate) mod relay_publication;
#[path = "wss_relay_host_v4.rs"]
pub(crate) mod wss_relay_host;
pub use relay_original_delivery::{
    OriginalRelayDelivery, RelayLiveControlDeployment, RelayLiveForwardingProgress,
    RelayLivePreparationLimits, RelayOriginalDeliveryHandle, RelayOriginalDeliveryOptions,
    RelayOriginalIssuer, RemoteRelayPublication,
};
pub use relay_publication::{
    OriginalRelayPoolPublication, OriginalRelayPoolWinner, RelayParentRegistration,
    RelayPoolPublicationInput,
};
pub use wss_relay_host::{
    WssRelayHost, WssRelayHostOptions, WssRelayLegOptions, WssRelayPublication,
};
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConnectError {
    #[error("v4 connection configuration is invalid")]
    Configuration,
    #[error("v4 connection resource capacity is exhausted")]
    Capacity,
    #[error("v4 connection authorization failed")]
    Authorization,
    #[error("v4 TLS verification failed")]
    Tls,
    #[error("v4 carrier failed")]
    Carrier,
    #[error("v4 admission or handshake failed")]
    Protocol,
    #[error("live_authorization_unknown")]
    LiveAuthorizationUnknown,
    #[error("v4 connection failed after original live authorization: {0:?}")]
    LiveAuthorized(PostAuthorizationFailure),
    #[error("v4 connection failed while original admission outcome is unknown: {failure:?}")]
    AdmissionUnknown {
        profile: ConnectionSourceProfile,
        failure: PostSpendFailure,
    },
    #[error("v4 connection failed after verified admission: {failure:?}")]
    Admitted {
        profile: ConnectionSourceProfile,
        failure: PostSpendFailure,
    },
    #[error("v4 connection failed after authenticated dual READY: {failure:?}")]
    Ready {
        profile: ConnectionSourceProfile,
        failure: PostSpendFailure,
    },
    #[error("v4 connection was canceled")]
    Canceled,
    #[error("v4 connection deadline expired")]
    Deadline,
    #[error(transparent)]
    Pool(#[from] PoolStoreError),
    #[error("v4 connection failed after irreversible pool consumption: {0:?}")]
    Spent(PostSpendFailure),
    /// Physical cleanup exceeded the original finite bound. The attempt's
    /// authorization and publication facts remain independently authoritative.
    #[error("cleanup_incomplete: v4 connection cleanup remains unknown ({failure:?})")]
    CleanupIncomplete {
        facts: ConnectionAttemptFacts,
        failure: PostSpendFailure,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionSourceProfile {
    PreauthorizedPool,
    LiveAuthority,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionPhase {
    NotStarted,
    SpentNotAdmitted,
    AdmittedNotReady,
    Ready,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionSpendState {
    Unspent,
    Spent,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionAdmissionState {
    NotStarted,
    InFlight,
    Admitted,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionNetworkReady {
    NotStarted,
    Ready,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionApplicationPublish {
    NotStarted,
    Published,
    Failed,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionQueryAvailability {
    Unavailable,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionAttemptFacts {
    pub phase: ConnectionPhase,
    pub spend_state: ConnectionSpendState,
    pub admission_state: ConnectionAdmissionState,
    pub network_ready: ConnectionNetworkReady,
    pub application_publish: ConnectionApplicationPublish,
    pub source_profile: Option<ConnectionSourceProfile>,
    pub query_availability: ConnectionQueryAvailability,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostAuthorizationFailure {
    Configuration,
    Capacity,
    Authorization,
    Tls,
    Carrier,
    Protocol,
    Canceled,
    Deadline,
}
/// The original pool transaction committed. No variant grants retry or adoption
/// authority for the consumed credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostSpendFailure {
    Configuration,
    Capacity,
    Authorization,
    Tls,
    Carrier,
    Protocol,
    Canceled,
    Deadline,
    Pool(PoolStoreError),
}
impl ConnectError {
    fn after_live_authorization(self) -> Self {
        Self::LiveAuthorized(match self {
            Self::Configuration => PostAuthorizationFailure::Configuration,
            Self::Capacity => PostAuthorizationFailure::Capacity,
            Self::Authorization => PostAuthorizationFailure::Authorization,
            Self::Tls => PostAuthorizationFailure::Tls,
            Self::Carrier => PostAuthorizationFailure::Carrier,
            Self::Canceled => PostAuthorizationFailure::Canceled,
            Self::Deadline => PostAuthorizationFailure::Deadline,
            Self::LiveAuthorized(cause) => cause,
            Self::AdmissionUnknown { failure: cause, .. }
            | Self::Admitted { failure: cause, .. }
            | Self::Ready { failure: cause, .. } => match cause {
                PostSpendFailure::Configuration => PostAuthorizationFailure::Configuration,
                PostSpendFailure::Capacity => PostAuthorizationFailure::Capacity,
                PostSpendFailure::Authorization => PostAuthorizationFailure::Authorization,
                PostSpendFailure::Tls => PostAuthorizationFailure::Tls,
                PostSpendFailure::Carrier => PostAuthorizationFailure::Carrier,
                PostSpendFailure::Protocol | PostSpendFailure::Pool(_) => {
                    PostAuthorizationFailure::Protocol
                }
                PostSpendFailure::Canceled => PostAuthorizationFailure::Canceled,
                PostSpendFailure::Deadline => PostAuthorizationFailure::Deadline,
            },
            _ => PostAuthorizationFailure::Protocol,
        })
    }
    fn during_admission(self, profile: ConnectionSourceProfile) -> Self {
        Self::AdmissionUnknown {
            profile,
            failure: self.post_spend_failure(),
        }
    }
    fn after_admission(self, profile: ConnectionSourceProfile) -> Self {
        Self::Admitted {
            profile,
            failure: self.post_spend_failure(),
        }
    }
    fn after_ready(self, profile: ConnectionSourceProfile) -> Self {
        Self::Ready {
            profile,
            failure: self.post_spend_failure(),
        }
    }
    fn post_spend_failure(self) -> PostSpendFailure {
        match self {
            Self::Configuration => PostSpendFailure::Configuration,
            Self::Capacity => PostSpendFailure::Capacity,
            Self::Authorization => PostSpendFailure::Authorization,
            Self::Tls => PostSpendFailure::Tls,
            Self::Carrier => PostSpendFailure::Carrier,
            Self::Protocol | Self::LiveAuthorizationUnknown => PostSpendFailure::Protocol,
            Self::LiveAuthorized(cause) => match cause {
                PostAuthorizationFailure::Configuration => PostSpendFailure::Configuration,
                PostAuthorizationFailure::Capacity => PostSpendFailure::Capacity,
                PostAuthorizationFailure::Authorization => PostSpendFailure::Authorization,
                PostAuthorizationFailure::Tls => PostSpendFailure::Tls,
                PostAuthorizationFailure::Carrier => PostSpendFailure::Carrier,
                PostAuthorizationFailure::Protocol => PostSpendFailure::Protocol,
                PostAuthorizationFailure::Canceled => PostSpendFailure::Canceled,
                PostAuthorizationFailure::Deadline => PostSpendFailure::Deadline,
            },
            Self::Canceled => PostSpendFailure::Canceled,
            Self::Deadline => PostSpendFailure::Deadline,
            Self::Pool(error) => PostSpendFailure::Pool(error),
            Self::Spent(cause)
            | Self::AdmissionUnknown { failure: cause, .. }
            | Self::Admitted { failure: cause, .. }
            | Self::Ready { failure: cause, .. }
            | Self::CleanupIncomplete { failure: cause, .. } => cause,
        }
    }
    fn after_spend(self) -> Self {
        Self::Spent(self.post_spend_failure())
    }
    fn cleanup_incomplete(self) -> Self {
        Self::CleanupIncomplete {
            facts: self.connection_facts(),
            failure: self.post_spend_failure(),
        }
    }
    pub fn connection_facts(self) -> ConnectionAttemptFacts {
        if let Self::CleanupIncomplete { facts, .. } = self {
            return facts;
        }
        let (spend_state, admission_state, network_ready, source_profile) = match self {
            Self::AdmissionUnknown { profile, .. } => (
                ConnectionSpendState::Spent,
                ConnectionAdmissionState::Unknown,
                ConnectionNetworkReady::NotStarted,
                Some(profile),
            ),
            Self::Admitted { profile, .. } => (
                ConnectionSpendState::Spent,
                ConnectionAdmissionState::Admitted,
                ConnectionNetworkReady::NotStarted,
                Some(profile),
            ),
            Self::Ready { profile, .. } => (
                ConnectionSpendState::Spent,
                ConnectionAdmissionState::Admitted,
                ConnectionNetworkReady::Ready,
                Some(profile),
            ),
            Self::Spent(_) => (
                ConnectionSpendState::Spent,
                ConnectionAdmissionState::NotStarted,
                ConnectionNetworkReady::NotStarted,
                Some(ConnectionSourceProfile::PreauthorizedPool),
            ),
            Self::LiveAuthorized(_) => (
                ConnectionSpendState::Spent,
                ConnectionAdmissionState::NotStarted,
                ConnectionNetworkReady::NotStarted,
                Some(ConnectionSourceProfile::LiveAuthority),
            ),
            Self::LiveAuthorizationUnknown => (
                ConnectionSpendState::Unknown,
                ConnectionAdmissionState::NotStarted,
                ConnectionNetworkReady::NotStarted,
                Some(ConnectionSourceProfile::LiveAuthority),
            ),
            Self::Pool(error) => (
                match error.write_state {
                    crate::pool_v4::PoolWriteState::NotSubmitted => ConnectionSpendState::Unspent,
                    crate::pool_v4::PoolWriteState::Committed => ConnectionSpendState::Spent,
                    crate::pool_v4::PoolWriteState::Unknown => ConnectionSpendState::Unknown,
                },
                ConnectionAdmissionState::NotStarted,
                ConnectionNetworkReady::NotStarted,
                Some(ConnectionSourceProfile::PreauthorizedPool),
            ),
            _ => (
                ConnectionSpendState::Unspent,
                ConnectionAdmissionState::NotStarted,
                ConnectionNetworkReady::NotStarted,
                None,
            ),
        };
        let phase = if network_ready == ConnectionNetworkReady::Ready {
            ConnectionPhase::Ready
        } else if admission_state == ConnectionAdmissionState::Admitted {
            ConnectionPhase::AdmittedNotReady
        } else if spend_state == ConnectionSpendState::Unknown
            || admission_state == ConnectionAdmissionState::Unknown
        {
            ConnectionPhase::Unknown
        } else if spend_state == ConnectionSpendState::Spent {
            ConnectionPhase::SpentNotAdmitted
        } else {
            ConnectionPhase::NotStarted
        };
        ConnectionAttemptFacts {
            phase,
            spend_state,
            admission_state,
            network_ready,
            application_publish: ConnectionApplicationPublish::NotStarted,
            source_profile,
            query_availability: ConnectionQueryAvailability::Unavailable,
        }
    }
}
impl From<CryptoError> for ConnectError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Capacity => Self::Capacity,
            CryptoError::Configuration => Self::Configuration,
            CryptoError::Deadline => Self::Deadline,
            CryptoError::Authorization(error) => error.into(),
            _ => Self::Protocol,
        }
    }
}
impl From<codec::Error> for ConnectError {
    fn from(value: codec::Error) -> Self {
        CryptoError::from(value).into()
    }
}
impl From<EnvironmentError> for ConnectError {
    fn from(e: EnvironmentError) -> Self {
        match e {
            EnvironmentError::Capacity => Self::Capacity,
            EnvironmentError::Configuration => Self::Configuration,
            _ => Self::Authorization,
        }
    }
}
type ConnectResult<T> = std::result::Result<T, ConnectError>;

pub(crate) fn candidate_add_limits(
    a: ResourceLimits,
    b: ResourceLimits,
) -> std::result::Result<ResourceLimits, EnvironmentError> {
    Ok(ResourceLimits {
        sdk_bytes: a
            .sdk_bytes
            .checked_add(b.sdk_bytes)
            .ok_or(EnvironmentError::Capacity)?,
        provider_bytes: a
            .provider_bytes
            .checked_add(b.provider_bytes)
            .ok_or(EnvironmentError::Capacity)?,
        disk_bytes: a
            .disk_bytes
            .checked_add(b.disk_bytes)
            .ok_or(EnvironmentError::Capacity)?,
        items: a
            .items
            .checked_add(b.items)
            .ok_or(EnvironmentError::Capacity)?,
        work_slots: a
            .work_slots
            .checked_add(b.work_slots)
            .ok_or(EnvironmentError::Capacity)?,
        tasks: a
            .tasks
            .checked_add(b.tasks)
            .ok_or(EnvironmentError::Capacity)?,
        timers: a
            .timers
            .checked_add(b.timers)
            .ok_or(EnvironmentError::Capacity)?,
        connections: a
            .connections
            .checked_add(b.connections)
            .ok_or(EnvironmentError::Capacity)?,
        tls_handshakes: a
            .tls_handshakes
            .checked_add(b.tls_handshakes)
            .ok_or(EnvironmentError::Capacity)?,
        sessions: a
            .sessions
            .checked_add(b.sessions)
            .ok_or(EnvironmentError::Capacity)?,
        native_handles: a
            .native_handles
            .checked_add(b.native_handles)
            .ok_or(EnvironmentError::Capacity)?,
    })
}

pub(crate) enum PreparationCharge {
    Account(ResourceCharge),
    Environment(EnvironmentCharge),
}
impl From<EnvironmentCharge> for PreparationCharge {
    fn from(charge: EnvironmentCharge) -> Self {
        Self::Environment(charge)
    }
}
impl From<ResourceCharge> for PreparationCharge {
    fn from(charge: ResourceCharge) -> Self {
        Self::Account(charge)
    }
}

/// One original provider's complete preparation geometry. Reverse listeners
/// retain three distinct physical owners; dialed carriers retain one charge.
#[derive(Clone, Copy)]
pub(crate) struct ControllerProviderCosts {
    pub(super) listener: Option<ResourceLimits>,
    pub(super) connection: ResourceLimits,
    pub(super) tls: Option<ResourceLimits>,
}
impl ControllerProviderCosts {
    fn total(self) -> ConnectResult<ResourceLimits> {
        let limits = candidate_add_limits(self.connection, self.listener.unwrap_or_default())?;
        Ok(candidate_add_limits(limits, self.tls.unwrap_or_default())?)
    }
}
pub(crate) struct ControllerProviderCharges {
    pub(super) listener: Option<ResourceCharge>,
    pub(super) connection: ResourceCharge,
    pub(super) tls: Option<ResourceCharge>,
}
/// The same cost definitions feed pre-acquisition root backing and each real
/// consumer. A live bound is reduced to these exact costs before attachment.
pub(crate) struct ControllerCandidateCosts {
    provider: ControllerProviderCosts,
    provider_candidates: Vec<(u8, ControllerProviderCosts)>,
    handshake: ResourceLimits,
    hop: Option<ResourceLimits>,
    application: Option<ResourceLimits>,
    services: Option<ResourceLimits>,
    management: Option<ResourceLimits>,
    managed_query: Option<crate::FixedContractQuery>,
    bindings: Vec<ResourceLimits>,
    native_application: Option<ResourceLimits>,
}
fn controller_service_cost_error(failure: serve::ServeError) -> ConnectError {
    match failure.code {
        serve::ServeFailure::Capacity => ConnectError::Capacity,
        serve::ServeFailure::Closed | serve::ServeFailure::Canceled => ConnectError::Canceled,
        _ => ConnectError::Configuration,
    }
}
impl ControllerCandidateCosts {
    fn services(
        handlers: Option<&(serve::HandlerPlan, ApplicationLimits)>,
        managed_query: Option<crate::FixedContractQuery>,
    ) -> ConnectResult<Option<ResourceLimits>> {
        if let Some((plan, _)) = handlers
            && let Some(limits) = plan
                .service_preparation_limits()
                .map_err(controller_service_cost_error)?
        {
            return Ok(Some(limits));
        }
        managed_query
            .map(|query| {
                controller_service_plan(query)
                    .preparation_limits()
                    .map_err(controller_service_cost_error)
            })
            .transpose()
    }
    fn from_shape(
        shape: RecordShape,
        automatic: bool,
        provider: ControllerProviderCosts,
        native: bool,
        tunnel: bool,
        handlers: Option<&(serve::HandlerPlan, ApplicationLimits)>,
        managed: &[crate::connection_controller_v4::ManagedServiceConfiguration],
    ) -> ConnectResult<Self> {
        let managed_query = managed.first().map(|service| service.query);
        let services = Self::services(handlers, managed_query)?;
        let management = if shape.application_profile == 2
            && !handlers.is_some_and(|(plan, _)| plan.has_management_plan())
        {
            Some(
                crate::ExecutionManagement::preparation_limits(0, 0)
                    .map_err(|_| ConnectError::Capacity)?,
            )
        } else {
            None
        };
        let mut bindings = Vec::with_capacity(managed.len());
        for service in managed {
            bindings.push(
                crate::service_client_v4::ServiceBindingPreparation::preparation_limits(
                    &service.methods,
                )
                .map_err(|failure| match failure.0 {
                    crate::ServiceFailure::ResourceExhausted
                    | crate::ServiceFailure::ConfigurationCapacity => ConnectError::Capacity,
                    _ => ConnectError::Configuration,
                })?,
            );
        }
        let native_application = if native {
            Some(native::Provider::application_preparation_limits(
                shape.max_frame + 8,
                shape.application_profile,
            )?)
        } else {
            None
        };
        Ok(Self {
            provider,
            provider_candidates: vec![(0, provider)],
            handshake: HandshakePreflight::preparation_limits(&shape, automatic)?,
            hop: tunnel.then(hop::EndpointHop::preparation_limits),
            application: handlers
                .map(|(_, limits)| ApplicationLifetime::preparation_limits(*limits))
                .transpose()?,
            services,
            management,
            managed_query,
            bindings,
            native_application,
        })
    }
    pub(crate) fn for_pool(
        material: &PoolConnectionMaterial,
        options: &WssConnectOptions,
        reverse: Option<&Arc<reverse::Capture>>,
        handlers: Option<&(serve::HandlerPlan, ApplicationLimits)>,
        managed: &[crate::connection_controller_v4::ManagedServiceConfiguration],
    ) -> ConnectResult<Self> {
        let mut candidates = Vec::new();
        let mut native = false;
        if let Some(reverse) = reverse {
            let policy = wss::Policy::new_reverse(material, options)?;
            native = policy.carrier != 1;
            candidates.push((
                material
                    .admission
                    .pool
                    .as_ref()
                    .map_or(0, |facts| facts.candidate_index),
                reverse.controller_preparation_costs(
                    &policy,
                    &material.admission.account,
                    options,
                )?,
            ));
        } else {
            let indices = if let Some(facts) = &material.admission.pool {
                let selection = decode(
                    &facts.selection,
                    "PoolSelectionRef",
                    4096,
                    Context::default(),
                )?;
                selection
                    .field("PoolSelectionRef", "candidate_indices")?
                    .children()?
                    .map(|value| {
                        u8::try_from(value?.uint()?).map_err(|_| ConnectError::Configuration)
                    })
                    .collect::<ConnectResult<Vec<_>>>()?
            } else {
                vec![
                    material
                        .admission
                        .pool
                        .as_ref()
                        .map_or(0, |facts| facts.candidate_index),
                ]
            };
            for index in indices {
                let policy = wss::Policy::new_candidate(material, options, index)?;
                native |= policy.carrier != 1;
                candidates.push((
                    index,
                    ControllerProviderCosts {
                        listener: None,
                        connection: policy.preparation_limits(options)?,
                        tls: None,
                    },
                ));
            }
        }
        let provider = candidates
            .first()
            .map(|(_, provider)| *provider)
            .ok_or(ConnectError::Configuration)?;
        let mut costs = Self::from_shape(
            RecordShape::from_artifact(decode(
                &material.bytes.artifact,
                "Artifact",
                65536,
                Context::default(),
            )?)?,
            material.admission.account.automatic_liveness().is_some(),
            provider,
            native,
            material.tunnel_credentials.is_some(),
            handlers,
            managed,
        )?;
        costs.provider_candidates = candidates;
        Ok(costs)
    }
    pub(crate) fn for_live(
        material: &crate::live_material_source_v4::LiveConnectionMaterial,
        handlers: Option<&(serve::HandlerPlan, ApplicationLimits)>,
        managed: &[crate::connection_controller_v4::ManagedServiceConfiguration],
    ) -> ConnectResult<Self> {
        let options = &material.generation.provider;
        let policy = if material.generation.reverse.is_some() {
            wss::Policy::new_live_reverse_tunnel(
                &material.bytes.artifact,
                &material.pending,
                options,
            )?
        } else if material.generation.tunnel.is_some() {
            wss::Policy::new_live_tunnel(&material.bytes.artifact, &material.pending, options)?
        } else {
            wss::Policy::new_live(&material.bytes.artifact, &material.pending, options)?
        };
        let provider = if let Some(reverse) = &material.generation.reverse {
            reverse.controller_preparation_costs(&policy, &material.pending.account, options)?
        } else {
            ControllerProviderCosts {
                listener: None,
                connection: policy.preparation_limits(options)?,
                tls: None,
            }
        };
        Self::from_shape(
            RecordShape::from_artifact(decode(
                &material.bytes.artifact,
                "Artifact",
                65536,
                Context::default(),
            )?)?,
            material.pending.account.automatic_liveness().is_some(),
            provider,
            policy.carrier != 1,
            material.generation.tunnel.is_some(),
            handlers,
            managed,
        )
    }
    pub(crate) fn live_upper(
        options: &WssConnectOptions,
        reverse: bool,
        handlers: Option<&(serve::HandlerPlan, ApplicationLimits)>,
        managed: &[crate::connection_controller_v4::ManagedServiceConfiguration],
    ) -> ConnectResult<Self> {
        if !(1..=64).contains(&options.queue_messages)
            || !(16384..=262144).contains(&options.prepare_bytes)
            || options.native_runtime_bytes < 1 << 20
        {
            return Err(ConnectError::Configuration);
        }
        // Issuance has not supplied a route. The supported record limits bound
        // every accepted carrier and signed geometry; only root bears this
        // upper bound, which is shrunk before tenant/Session attachment.
        let connection = ResourceLimits {
            sdk_bytes: (1_048_584u64)
                .checked_mul(options.queue_messages as u64 + 4)
                .and_then(|bytes| bytes.checked_add(16384))
                .ok_or(ConnectError::Capacity)?,
            provider_bytes: options
                .native_runtime_bytes
                .checked_add(options.prepare_bytes as u64)
                .and_then(|bytes| bytes.checked_add(524288))
                .ok_or(ConnectError::Capacity)?,
            items: options.queue_messages as u64 + 8,
            tasks: 24,
            work_slots: 24,
            timers: 8,
            connections: 1,
            tls_handshakes: 1,
            native_handles: 32,
            ..ResourceLimits::default()
        };
        Self::from_shape(
            RecordShape {
                max_frame: 1_048_576,
                max_streams: 1035,
                max_credit: 8 << 20,
                idle_duration_ms: 0,
                application_profile: 2,
                datagrams: true,
                rekey_envelope: [1, 1, 1],
                service_ms: 1,
            },
            true,
            if reverse {
                reverse::Capture::controller_upper_costs(options)?
            } else {
                ControllerProviderCosts {
                    listener: None,
                    connection,
                    tls: None,
                }
            },
            true,
            true,
            handlers,
            managed,
        )
    }
    pub(crate) fn total(&self) -> ConnectResult<ResourceLimits> {
        let mut limits =
            candidate_add_limits(controller_work_limits(), controller_session_limits())?;
        limits = candidate_add_limits(limits, controller_received_limits())?;
        if self.provider_candidates.is_empty() {
            limits = candidate_add_limits(limits, self.provider.total()?)?;
        } else {
            for (_, provider) in &self.provider_candidates {
                limits = candidate_add_limits(limits, provider.total()?)?;
            }
        }
        limits = candidate_add_limits(limits, self.handshake)?;
        limits = candidate_add_limits(limits, self.hop.unwrap_or_default())?;
        limits = candidate_add_limits(limits, self.application.unwrap_or_default())?;
        limits = candidate_add_limits(limits, self.services.unwrap_or_default())?;
        limits = candidate_add_limits(limits, self.management.unwrap_or_default())?;
        limits = candidate_add_limits(limits, self.native_application.unwrap_or_default())?;
        for binding in &self.bindings {
            limits = candidate_add_limits(limits, *binding)?;
        }
        Ok(limits)
    }
}
fn controller_service_plan(query: crate::FixedContractQuery) -> serve::ServicePlan {
    serve::ServicePlan {
        query,
        unary: Vec::new(),
        notifications: Vec::new(),
        streaming: Vec::new(),
        resume: Vec::new(),
        result_read: None,
        management: None,
    }
}
/// Exact account charges move into their ordinary physical owners, without a
/// second capacity reservation after the source hands off its original material.
pub(crate) struct ControllerPrepaidCharges {
    cleanup: Arc<ConnectCleanup>,
    work: ResourceCharge,
    session: ResourceCharge,
    received: ResourceCharge,
    provider: Vec<(u8, ControllerProviderCharges)>,
    handshake: ResourceCharge,
    hop: Option<ResourceCharge>,
    application: Option<ResourceCharge>,
    services: Option<ResourceCharge>,
    management: Option<ResourceCharge>,
    managed_query: Option<crate::FixedContractQuery>,
    bindings: Vec<ResourceCharge>,
    native_application: Option<ResourceCharge>,
}
impl ControllerPrepaidCharges {
    pub(crate) fn split_from(
        charge: &mut ResourceCharge,
        costs: &ControllerCandidateCosts,
    ) -> std::result::Result<Self, EnvironmentError> {
        let provider_costs = if costs.provider_candidates.is_empty() {
            vec![(0, costs.provider)]
        } else {
            costs.provider_candidates.clone()
        };
        let mut provider = Vec::with_capacity(provider_costs.len());
        for (index, limits) in provider_costs {
            provider.push((
                index,
                ControllerProviderCharges {
                    listener: limits
                        .listener
                        .map(|value| charge.split(value))
                        .transpose()?,
                    connection: charge.split(limits.connection)?,
                    tls: limits.tls.map(|value| charge.split(value)).transpose()?,
                },
            ));
        }
        Ok(Self {
            cleanup: ConnectCleanup::new(),
            work: charge.split(controller_work_limits())?,
            session: charge.split(controller_session_limits())?,
            received: charge.split(controller_received_limits())?,
            provider,
            handshake: charge.split(costs.handshake)?,
            hop: costs.hop.map(|limits| charge.split(limits)).transpose()?,
            application: costs
                .application
                .map(|limits| charge.split(limits))
                .transpose()?,
            services: costs
                .services
                .map(|limits| charge.split(limits))
                .transpose()?,
            management: costs
                .management
                .map(|limits| charge.split(limits))
                .transpose()?,
            managed_query: costs.managed_query,
            bindings: costs
                .bindings
                .iter()
                .map(|limits| charge.split(*limits))
                .collect::<std::result::Result<_, _>>()?,
            native_application: costs
                .native_application
                .map(|limits| charge.split(limits))
                .transpose()?,
        })
    }
    pub(crate) fn cleanup_observer(&self) -> Arc<ConnectCleanup> {
        self.cleanup.clone()
    }
    pub(crate) fn take_bindings(&mut self) -> Vec<ResourceCharge> {
        std::mem::take(&mut self.bindings)
    }
}
fn controller_work_limits() -> ResourceLimits {
    ResourceLimits {
        sdk_bytes: 655_360,
        items: 8,
        timers: 1,
        work_slots: 8,
        tasks: 2,
        sessions: 0,
        ..ResourceLimits::default()
    }
}
fn controller_session_limits() -> ResourceLimits {
    ResourceLimits {
        sdk_bytes: 4096,
        items: 1,
        timers: 2,
        work_slots: 1,
        tasks: 1,
        sessions: 0,
        ..ResourceLimits::default()
    }
}
fn controller_received_limits() -> ResourceLimits {
    ResourceLimits {
        sdk_bytes: 1024,
        items: 1,
        work_slots: 1,
        tasks: 1,
        sessions: 0,
        ..ResourceLimits::default()
    }
}
/// Generated private identity material. Only its public provisioning keys leave
/// this original handle; it cannot assert certificate or transport trust.
#[derive(Clone, Debug)]
pub struct IdentityKeys {
    inner: Arc<LocalKeys>,
    owner: Arc<KeyOwner>,
    profile: Profile,
}
#[derive(Debug)]
struct KeyOwner {
    environment: Arc<EnvironmentRoot>,
    _charge: EnvironmentCharge,
}
impl IdentityKeys {
    pub(crate) fn new(environment: Arc<EnvironmentRoot>, profile: &str) -> ConnectResult<Self> {
        let profile = Profile::parse(profile)?;
        let charge = environment.reserve_environment(ResourceLimits {
            sdk_bytes: 8192,
            items: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        Ok(Self {
            inner: LocalKeys::generate(profile)?,
            profile,
            owner: Arc::new(KeyOwner {
                environment,
                _charge: charge,
            }),
        })
    }
    pub(crate) fn import(
        environment: Arc<EnvironmentRoot>,
        profile: &str,
        signing_seed: [u8; 32],
        noise_private: [u8; 32],
    ) -> ConnectResult<Self> {
        let signing_seed = Zeroizing::new(signing_seed);
        let noise_private = Zeroizing::new(noise_private);
        let profile = Profile::parse(profile)?;
        let charge = environment.reserve_environment(ResourceLimits {
            sdk_bytes: 8192,
            items: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let inner = LocalKeys::from_provisioning(profile, signing_seed, noise_private)?;
        Ok(Self {
            inner,
            profile,
            owner: Arc::new(KeyOwner {
                environment,
                _charge: charge,
            }),
        })
    }
    pub(crate) fn sign_original_control(&self, message: &[u8]) -> ConnectResult<[u8; 64]> {
        Ok(self.inner.sign(message)?)
    }
    pub(crate) fn belongs_to(&self, environment: &Arc<EnvironmentRoot>) -> bool {
        Arc::ptr_eq(environment, &self.owner.environment)
    }
    pub(crate) fn verify_certificate_identity(&self, bytes: &[u8]) -> ConnectResult<()> {
        let certificate = decode(bytes, "IdentityCertificate", 8192, Context::default())?;
        if certificate
            .field("IdentityCertificate", "crypto_profile_id")?
            .text()?
            != self.profile()
            || certificate.b::<32>("IdentityCertificate", "ed25519_public_key")?
                != self.ed25519_public_key()
            || certificate
                .field("IdentityCertificate", "noise_static_public_key")?
                .field("NoiseStaticPublicKey", "public_key_bytes")?
                .bytes()?
                != self.noise_static_public_key()
        {
            return Err(ConnectError::Authorization);
        }
        Ok(())
    }
    pub fn profile(&self) -> &'static str {
        self.profile.name()
    }
    pub fn ed25519_public_key(&self) -> [u8; 32] {
        self.inner.ed_public()
    }
    pub fn noise_static_public_key(&self) -> &[u8] {
        self.inner.dh_public()
    }
}
/// Original nonce-bound namespace verification and refresh owner.
#[derive(Debug)]
pub struct Namespace {
    verifier: Mutex<NamespaceVerifier>,
    bootstrap_waiting: std::sync::atomic::AtomicBool,
}
/// Custody of one original bootstrap request. A provider that uses a physical
/// worker must move this request into that worker until its I/O and cleanup
/// actually finish. Dropping an observing future does not refund that tail.
pub struct NamespaceBootstrapRequest {
    nonce: [u8; 32],
    _tail: Arc<EnvironmentCharge>,
}
impl fmt::Debug for NamespaceBootstrapRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NamespaceBootstrapRequest { <original custody> }")
    }
}
impl NamespaceBootstrapRequest {
    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }
}
struct NamespaceBootstrapWait<'a> {
    namespace: &'a Namespace,
    completed: bool,
}
impl Drop for NamespaceBootstrapWait<'_> {
    fn drop(&mut self) {
        let mut verifier = self.namespace.verifier.lock().expect("namespace owner");
        if !self.completed {
            verifier.cancel_bootstrap_wait();
        }
        self.namespace
            .bootstrap_waiting
            .store(false, std::sync::atomic::Ordering::Release);
    }
}
impl Namespace {
    pub(crate) fn new(verifier: NamespaceVerifier) -> Self {
        Self {
            verifier: Mutex::new(verifier),
            bootstrap_waiting: std::sync::atomic::AtomicBool::new(false),
        }
    }
    pub fn bootstrap_nonce(&self) -> [u8; 32] {
        self.verifier
            .lock()
            .expect("namespace owner")
            .bootstrap_nonce()
    }
    pub fn bootstrap(
        &self,
        response: &[u8],
        state: &[u8],
    ) -> std::result::Result<(), EnvironmentError> {
        let mut verifier = self.verifier.lock().expect("namespace owner");
        if self
            .bootstrap_waiting
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(EnvironmentError::Closed);
        }
        verifier.bootstrap(response, state)
    }
    /// Verify one original nonce-bound response and complete State, waiting only
    /// when trusted time has not yet proved their required lower bound. The
    /// original namespace prepays one timer and retains all earlier deadlines;
    /// each wake repeats full verification of these same borrowed bytes.
    /// Dropping a pending future cancels its timer and permanently ends this
    /// original bootstrap attempt; an installed namespace is not revoked.
    pub async fn bootstrap_when_ready(
        &self,
        response: &[u8],
        state: &[u8],
    ) -> std::result::Result<(), EnvironmentError> {
        self.bootstrap_original(false, |_| std::future::ready(Ok((response, state))))
            .await
    }
    /// Fetch one original response using this namespace's nonce, then verify the
    /// fixed response/State pair. Acquisition and time proof share the original
    /// deadline, single-flight gate and one charged timer. The callback is called
    /// once. It must own its I/O or move the request custody into its real worker.
    pub async fn bootstrap_from<Fetch, FetchFuture, Error>(
        &self,
        fetch: Fetch,
    ) -> std::result::Result<(), Error>
    where
        Fetch: FnOnce(NamespaceBootstrapRequest) -> FetchFuture,
        FetchFuture: std::future::Future<Output = std::result::Result<(Vec<u8>, Vec<u8>), Error>>,
        Error: From<EnvironmentError>,
    {
        self.bootstrap_original(true, fetch).await
    }
    async fn bootstrap_original<Fetch, FetchFuture, Response, State, Error>(
        &self,
        fetching: bool,
        fetch: Fetch,
    ) -> std::result::Result<(), Error>
    where
        Fetch: FnOnce(NamespaceBootstrapRequest) -> FetchFuture,
        FetchFuture: std::future::Future<Output = std::result::Result<(Response, State), Error>>,
        Response: AsRef<[u8]>,
        State: AsRef<[u8]>,
        Error: From<EnvironmentError>,
    {
        let (environment, charge, nonce) = {
            let mut verifier = self.verifier.lock().expect("namespace owner");
            if self
                .bootstrap_waiting
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return Err(EnvironmentError::Closed.into());
            }
            let (environment, charge) = verifier.bootstrap_wait_owner(fetching)?;
            self.bootstrap_waiting
                .store(true, std::sync::atomic::Ordering::Release);
            (environment, charge, verifier.bootstrap_nonce())
        };
        let charge = Arc::new(charge);
        // The provider future and loop's Sleep/Notify futures drop before this
        // guard. Any physical provider worker retains its own original custody.
        let mut wait = NamespaceBootstrapWait {
            namespace: self,
            completed: false,
        };
        let fetched = {
            let future = fetch(NamespaceBootstrapRequest {
                nonce,
                _tail: charge.clone(),
            });
            tokio::pin!(future);
            loop {
                let changed = environment.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let deadline = self
                    .verifier
                    .lock()
                    .expect("namespace owner")
                    .bootstrap_acquisition_deadline()?;
                tokio::select! {
                    result = &mut future => break result,
                    () = tokio::time::sleep_until(deadline) => {},
                    () = &mut changed => {},
                }
            }
        };
        let (response, state) = fetched?;
        let result = loop {
            let result = self
                .verifier
                .lock()
                .expect("namespace owner")
                .bootstrap(response.as_ref(), state.as_ref());
            match result {
                Ok(()) => break Ok(()),
                Err(EnvironmentError::TimePending) => {}
                Err(error) => break Err(error.into()),
            }
            // Register after the verification's temporary allocations are
            // released, then recheck the original owner to avoid a lost close.
            let changed = environment.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let wake = match self
                .verifier
                .lock()
                .expect("namespace owner")
                .bootstrap_wake()
            {
                Ok(wake) => wake,
                Err(error) => break Err(error.into()),
            };
            tokio::select! {
                () = tokio::time::sleep_until(wake) => {},
                () = &mut changed => {},
            }
        };
        wait.completed = true;
        result
    }
    pub fn refresh(
        &self,
        trust: Option<&[u8]>,
        head: &[u8],
        state: &[u8],
    ) -> std::result::Result<(), EnvironmentError> {
        let mut verifier = self.verifier.lock().expect("namespace owner");
        if self
            .bootstrap_waiting
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(EnvironmentError::Closed);
        }
        verifier.refresh(trust, head, state)
    }
}
/// Exact issuer bytes, consumed into one immutable material owner.
pub struct PoolCredentialBytes {
    pub artifact: Vec<u8>,
    pub client_certificate: Vec<u8>,
    pub server_certificate: Vec<u8>,
    pub activation: Vec<u8>,
}
impl fmt::Debug for PoolCredentialBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PoolCredentialBytes { <redacted> }")
    }
}
impl Drop for PoolCredentialBytes {
    fn drop(&mut self) {
        self.artifact.zeroize();
    }
}
/// The selected original leg's public hop credentials. The remote leg's
/// Grant is never copied into endpoint material.
pub struct TunnelPoolCredentialBytes {
    pub connection: PoolCredentialBytes,
    pub grant: Vec<u8>,
    pub relay_certificate: Vec<u8>,
}
impl fmt::Debug for TunnelPoolCredentialBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TunnelPoolCredentialBytes { <redacted> }")
    }
}
struct TunnelCredentialStorage {
    grant: Vec<u8>,
    relay_certificate: Vec<u8>,
}
/// Independently installed control destination and exact server-leg Grant.
/// Recipient metadata comes from that authenticated server registration, never
/// from a tunnel peer or from the control URL. No Artifact or PSK is published.
pub struct TunnelServerAllowConfiguration {
    pub control: crate::ControlHTTPSConfiguration,
    pub recipient: [u8; 16],
    pub incarnation: [u8; 16],
    pub grant: Vec<u8>,
}
impl fmt::Debug for TunnelServerAllowConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TunnelServerAllowConfiguration { <opaque> }")
    }
}
struct PoolTunnelServerAllow {
    control: Arc<crate::control_https_v4::ControlHTTPS>,
    recipient: [u8; 16],
    incarnation: [u8; 16],
    grant: Zeroizing<Vec<u8>>,
    _charge: ResourceCharge,
}
/// One physical HTTP exchange prepared within the original pool Connect. This
/// private state is moved into publication only after its own consume returns.
struct PreparedPoolServerAllow {
    control: Arc<crate::control_https_v4::ControlHTTPS>,
    request: Zeroizing<Vec<u8>>,
    custody: Arc<crate::control_https_v4::ControlHTTPSCustody>,
    prepaid: crate::control_https_v4::ControlHTTPSPrepayment,
    bindings: [crate::namespace_v4::NamespaceBinding; 2],
    not_before_ms: u64,
    not_after_ms: u64,
}
const POOL_SERVER_ALLOW_WIRE_BYTES: usize = 9302 + 1024;
fn server_allow_control_error(error: crate::ControlHTTPSFailure) -> ConnectError {
    match error {
        crate::ControlHTTPSFailure::Configuration => ConnectError::Configuration,
        crate::ControlHTTPSFailure::Capacity => ConnectError::Capacity,
        crate::ControlHTTPSFailure::Canceled => ConnectError::Canceled,
        crate::ControlHTTPSFailure::Deadline => ConnectError::Deadline,
        crate::ControlHTTPSFailure::Rejected => ConnectError::Authorization,
        crate::ControlHTTPSFailure::Unavailable => ConnectError::Carrier,
    }
}
impl PreparedPoolServerAllow {
    async fn publish(
        self,
        root: &Arc<EnvironmentRoot>,
        admission: &CredentialAdmission,
        provider: &direct_carrier::Provider,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> ConnectResult<()> {
        let PreparedPoolServerAllow {
            control,
            request,
            custody,
            prepaid,
            bindings,
            not_before_ms,
            not_after_ms,
        } = self;
        let until = deadline.min(Instant::now() + std::time::Duration::from_secs(2));
        let native_cancel = provider.cancellation();
        let carrier = provider.identity();
        let publication_guard = || {
            if cancel.is_cancelled() || native_cancel.is_cancelled() || root.is_closed() {
                return Err(crate::ControlHTTPSFailure::Canceled);
            }
            let now = root
                .sample()
                .map_err(|_| crate::ControlHTTPSFailure::Unavailable)?;
            if now.lower_ms < not_before_ms {
                return Err(crate::ControlHTTPSFailure::Rejected);
            }
            if Instant::now() >= until || now.upper_ms >= not_after_ms {
                return Err(crate::ControlHTTPSFailure::Deadline);
            }
            provider
                .check()
                .map_err(|_| crate::ControlHTTPSFailure::Unavailable)?;
            if provider.identity() != carrier {
                return Err(crate::ControlHTTPSFailure::Rejected);
            }
            admission
                .pool_activation
                .as_ref()
                .ok_or(crate::ControlHTTPSFailure::Rejected)?
                .authorize(admission)
                .map_err(|_| crate::ControlHTTPSFailure::Rejected)?;
            for binding in bindings {
                root.check_namespace_binding(binding)
                    .map_err(|_| crate::ControlHTTPSFailure::Rejected)?;
            }
            Ok(())
        };
        publication_guard().map_err(server_allow_control_error)?;
        let response = tokio::select! {
            result = control.post_prepaid_original_delivery(&request, cancel,
                &publication_guard, custody, prepaid) => result.map_err(server_allow_control_error)?,
            _ = native_cancel.cancelled() => return Err(ConnectError::Canceled),
            _ = tokio::time::sleep_until(until) => return Err(ConnectError::Deadline),
        };
        // This is the existing adapter's bounded receipt acknowledgement, not
        // a second credential, spend confirmation, or recovered dispatch right.
        if response.as_slice() != [0xf5] {
            return Err(ConnectError::Protocol);
        }
        publication_guard().map_err(server_allow_control_error)
    }
}
pub struct PoolConnectionMaterial {
    admission: CredentialAdmission,
    bytes: PoolCredentialBytes,
    keys: IdentityKeys,
    namespaces: Vec<Arc<Namespace>>,
    tunnel_credentials: Option<TunnelCredentialStorage>,
    server_allow: Option<PoolTunnelServerAllow>,
    registered_pool: Option<Arc<registered_pool::RegisteredPoolControl>>,
    _charge: ResourceCharge,
}
fn first_pool_candidate(proof: &[u8], source: codec::ActivationSource) -> ConnectResult<u8> {
    if source != codec::ActivationSource::PreauthorizedPool {
        return Ok(0);
    }
    let activation = decode(
        proof,
        "ActivationAuthorization",
        4096,
        Context::with_activation_source(source),
    )?;
    Ok(activation
        .field("ActivationAuthorization", "candidate_selection")?
        .field("PoolSelectionRef", "candidate_indices")?
        .at(0)?
        .uint()? as u8)
}
impl PoolConnectionMaterial {
    /// Capture the exact server Grant and original registration before any
    /// native preparation or pool spend. The client Grant stays role-specific.
    pub fn with_tunnel_server_allow(
        mut self,
        configuration: TunnelServerAllowConfiguration,
    ) -> ConnectResult<Self> {
        if self.server_allow.is_some()
            || self.admission.source != codec::ActivationSource::PreauthorizedPool
            || self
                .admission
                .tunnel
                .as_ref()
                .is_none_or(|hop| hop.endpoint_role != 0)
            || configuration.recipient == [0; 16]
            || configuration.incarnation == [0; 16]
            || configuration.grant.is_empty()
            || configuration.grant.len() > 9302
            || configuration.grant.capacity() > 18604
            || configuration.control.timeout > std::time::Duration::from_secs(2)
        {
            return Err(ConnectError::Configuration);
        }
        let root = self.keys.owner.environment.clone();
        let charge = self.admission.account.reserve(ResourceLimits {
            sdk_bytes: configuration.grant.capacity() as u64 + 1024,
            items: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let control = Arc::new(
            crate::control_https_v4::ControlHTTPS::new(root, configuration.control)
                .map_err(server_allow_control_error)?,
        );
        self.server_allow = Some(PoolTunnelServerAllow {
            control,
            recipient: configuration.recipient,
            incarnation: configuration.incarnation,
            grant: Zeroizing::new(configuration.grant),
            _charge: charge,
        });
        self.verify_server_allow()?;
        Ok(self)
    }
    fn verify_server_allow(
        &self,
    ) -> ConnectResult<crate::namespace_v4::verifier::credential::tunnel::EndpointHopVerification>
    {
        let allow = self
            .server_allow
            .as_ref()
            .ok_or(ConnectError::Configuration)?;
        let credentials = self
            .tunnel_credentials
            .as_ref()
            .ok_or(ConnectError::Configuration)?;
        let grant = decode(&credentials.grant, "Grant", 9302, Context::default())?;
        let service = grant.field("Grant", "service")?.text()?;
        let audience = grant.field("Grant", "audience")?.text()?;
        let guards: Vec<_> = self
            .namespaces
            .iter()
            .map(|namespace| {
                namespace
                    .verifier
                    .lock()
                    .expect("pool server allow namespace")
            })
            .collect();
        let refs: Vec<_> = guards.iter().map(|verifier| &**verifier).collect();
        Ok(
            crate::namespace_v4::verifier::credential::verify_pool_server_allow(
                &self.keys.owner.environment,
                &refs,
                &self.admission,
                DirectCredentialInput {
                    artifact: &self.bytes.artifact,
                    client_certificate: &self.bytes.client_certificate,
                    server_certificate: &self.bytes.server_certificate,
                    activation: &self.bytes.activation,
                    source: self.admission.source,
                    candidate_index: self
                        .admission
                        .pool
                        .as_ref()
                        .ok_or(ConnectError::Configuration)?
                        .candidate_index,
                },
                crate::namespace_v4::verifier::credential::tunnel::TunnelHopInput {
                    grant: &allow.grant,
                    relay_certificate: &credentials.relay_certificate,
                    endpoint_role: 1,
                    service,
                    audience,
                },
            )?,
        )
    }
    fn prepare_server_allow(
        &self,
        cleanup: &Arc<ConnectCleanup>,
    ) -> ConnectResult<Option<PreparedPoolServerAllow>> {
        if self.tunnel_credentials.is_none() {
            if self.server_allow.is_some() {
                return Err(ConnectError::Configuration);
            }
            return Ok(None);
        }
        let allow = self
            .server_allow
            .as_ref()
            .ok_or(ConnectError::Configuration)?;
        let verified = self.verify_server_allow()?;
        let artifact = decode(&self.bytes.artifact, "Artifact", 65536, Context::default())?;
        let tenant = artifact.field("Artifact", "tenant_id")?.text()?;
        let audience = artifact.field("Artifact", "audience")?.text()?;
        let index = self
            .admission
            .pool
            .as_ref()
            .ok_or(ConnectError::Configuration)?
            .candidate_index;
        let not_after_ms = verified
            .not_after_ms
            .min(self.admission.initiation_not_after_ms)
            .min(artifact.u("Artifact", "session_not_after_ms")?);
        if self.keys.owner.environment.sample()?.upper_ms >= not_after_ms {
            return Err(ConnectError::Deadline);
        }
        let charge = self.admission.account.reserve(ResourceLimits {
            sdk_bytes: POOL_SERVER_ALLOW_WIRE_BYTES as u64,
            items: 2,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let pending = cleanup.controls.clone();
        pending.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let custody =
            crate::control_https_v4::ControlHTTPSCustody::with_cleanup(charge, move || {
                pending.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            });
        let mut request = Zeroizing::new(Vec::new());
        request
            .try_reserve_exact(POOL_SERVER_ALLOW_WIRE_BYTES)
            .map_err(|_| ConnectError::Capacity)?;
        codec::encode_head(&mut request, 4, 14);
        t(&mut request, "tunnel-server-allow-1");
        t(&mut request, tenant);
        t(&mut request, audience);
        for value in [
            self.admission.artifact_digest.as_slice(),
            verified.facts.grant_digest.as_slice(),
            verified.facts.relay_identity_digest.as_slice(),
            self.admission.attempt_id.as_slice(),
            verified.facts.pairing_id.as_slice(),
            verified.facts.leg_id.as_slice(),
            allow.recipient.as_slice(),
            allow.incarnation.as_slice(),
        ] {
            b(&mut request, value);
        }
        codec::encode_head(&mut request, 4, 3);
        u(&mut request, u64::from(index));
        b(&mut request, &self.admission.candidate_id);
        b(&mut request, &self.admission.route_digest);
        u(&mut request, not_after_ms);
        b(&mut request, &allow.grant);
        if request.len() > POOL_SERVER_ALLOW_WIRE_BYTES {
            return Err(ConnectError::Configuration);
        }
        let prepaid = allow
            .control
            .prepare_original_delivery(request.len(), 1, Some(&custody))
            .map_err(server_allow_control_error)?;
        Ok(Some(PreparedPoolServerAllow {
            control: allow.control.clone(),
            request,
            custody,
            prepaid,
            bindings: verified.bindings,
            not_before_ms: verified.not_before_ms,
            not_after_ms,
        }))
    }
    pub(crate) fn internal_artifact_digest(&self) -> [u8; 32] {
        self.admission.artifact_digest
    }
    pub(crate) fn matches_top_up_identity(
        &self,
        identity: &IdentityKeys,
        certificate: &[u8],
    ) -> bool {
        self.keys.ed25519_public_key() == identity.ed25519_public_key()
            && self.keys.noise_static_public_key() == identity.noise_static_public_key()
            && self.bytes.client_certificate == certificate
    }
    pub(crate) fn resource_account(&self) -> &ResourceAccount {
        &self.admission.account
    }
}
impl fmt::Debug for PoolConnectionMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PoolConnectionMaterial { <opaque> }")
    }
}
/// The complete signed path, rather than only the local leg, determines
/// reliable progress, isolation and datagram guarantees. It is inspected while
/// the original Source still owns its material, before acquisition consumes it.
pub(crate) fn supports_route_requirements(
    artifact_bytes: &[u8],
    endpoint_role: Option<u8>,
    requirements: &crate::api_v4::ConnectionRequirements,
) -> std::result::Result<(), crate::material_source_v4::MaterialSourceError> {
    use crate::material_source_v4::MaterialSourceError;
    let artifact = decode(artifact_bytes, "Artifact", 65536, Context::default())
        .map_err(|_| MaterialSourceError::MaterialUnavailable)?;
    let profile = artifact
        .field("Artifact", "session_contract")
        .and_then(|contract| contract.u("SessionContract", "application_profile"))
        .map_err(|_| MaterialSourceError::MaterialUnavailable)?;
    let profile = match profile {
        0 => "transport",
        1 => "services",
        2 => "execution",
        _ => return Err(MaterialSourceError::MaterialUnavailable),
    };
    if requirements
        .application_profile
        .as_deref()
        .is_some_and(|expected| expected != profile)
    {
        return Err(MaterialSourceError::ConnectionRequirementUnavailable);
    }
    let candidates = artifact
        .field("Artifact", "candidates")
        .map_err(|_| MaterialSourceError::MaterialUnavailable)?;
    let local_field = match endpoint_role {
        None => "direct_leg",
        Some(0) => "client_leg",
        Some(1) => "server_leg",
        _ => return Err(MaterialSourceError::MaterialUnavailable),
    };
    let mut saw_route = false;
    for candidate in candidates
        .children()
        .map_err(|_| MaterialSourceError::MaterialUnavailable)?
    {
        let candidate = candidate.map_err(|_| MaterialSourceError::MaterialUnavailable)?;
        let tunnel = candidate
            .u("Candidate", "path_kind")
            .map_err(|_| MaterialSourceError::MaterialUnavailable)?
            == 1;
        if tunnel != endpoint_role.is_some() {
            continue;
        }
        saw_route = true;
        let fields: &[&str] = if tunnel {
            &["client_leg", "server_leg"]
        } else {
            &["direct_leg"]
        };
        let mut complete_path_native = true;
        for field in fields {
            let carrier = candidate
                .field("Candidate", field)
                .and_then(|leg| leg.u("Leg", "carrier"))
                .map_err(|_| MaterialSourceError::MaterialUnavailable)?;
            if carrier > 2 {
                return Err(MaterialSourceError::MaterialUnavailable);
            }
            complete_path_native &= carrier == 0 || carrier == 2;
        }
        if (requirements.independent_reliable_read_progress
            || requirements.bound_stream_input_isolation)
            && !complete_path_native
        {
            continue;
        }
        if requirements.datagram
            && (!complete_path_native
                || artifact
                    .u("Artifact", "allowed_features")
                    .map_err(|_| MaterialSourceError::MaterialUnavailable)?
                    & 1
                    == 0)
        {
            continue;
        }
        let local = candidate
            .field("Candidate", local_field)
            .map_err(|_| MaterialSourceError::MaterialUnavailable)?;
        if requirements.local_consumer_tls13_verification
            && (local
                .u("Leg", "access_class")
                .map_err(|_| MaterialSourceError::MaterialUnavailable)?
                != 0
                || endpoint_role
                    .is_some_and(|role| local.u("Leg", "dialer_role") != Ok(u64::from(role))))
        {
            continue;
        }
        return Ok(());
    }
    if saw_route {
        return Err(MaterialSourceError::RequiredGuaranteeUnavailable);
    }
    Err(MaterialSourceError::MaterialUnavailable)
}
impl PoolConnectionMaterial {
    pub(crate) fn supports_requirements(
        &self,
        requirements: &crate::api_v4::ConnectionRequirements,
    ) -> std::result::Result<(), crate::material_source_v4::MaterialSourceError> {
        supports_route_requirements(
            &self.bytes.artifact,
            self.admission.tunnel.as_ref().map(|hop| hop.endpoint_role),
            requirements,
        )?;
        if requirements.datagram
            && self
                .admission
                .tunnel
                .as_ref()
                .is_some_and(|hop| hop.limits.max_datagram_bytes <= 75)
        {
            return Err(
                crate::material_source_v4::MaterialSourceError::RequiredGuaranteeUnavailable,
            );
        }
        Ok(())
    }
    pub(crate) fn validate_provider(&self, options: &WssConnectOptions) -> ConnectResult<()> {
        wss::Policy::new(self, options).map(|_| ())
    }
    pub(crate) fn new(
        environment: Arc<EnvironmentRoot>,
        namespaces: Vec<Arc<Namespace>>,
        keys: IdentityKeys,
        bytes: PoolCredentialBytes,
    ) -> ConnectResult<Self> {
        Self::for_role(environment, namespaces, keys, bytes, Role::Client)
    }
    fn for_role(
        environment: Arc<EnvironmentRoot>,
        namespaces: Vec<Arc<Namespace>>,
        keys: IdentityKeys,
        bytes: PoolCredentialBytes,
        role: Role,
    ) -> ConnectResult<Self> {
        Self::for_role_source(
            environment,
            namespaces,
            keys,
            bytes,
            role,
            codec::ActivationSource::PreauthorizedPool,
        )
    }
    pub(crate) fn new_tunnel(
        environment: Arc<EnvironmentRoot>,
        namespaces: Vec<Arc<Namespace>>,
        keys: IdentityKeys,
        bytes: TunnelPoolCredentialBytes,
        service: &str,
        audience: &str,
        role: Role,
    ) -> ConnectResult<Self> {
        let TunnelPoolCredentialBytes {
            connection,
            grant,
            relay_certificate,
        } = bytes;
        Self::for_role_credentials(
            environment,
            namespaces,
            keys,
            connection,
            role,
            codec::ActivationSource::PreauthorizedPool,
            Some((
                TunnelCredentialStorage {
                    grant,
                    relay_certificate,
                },
                service,
                audience,
            )),
        )
    }
    fn for_role_source(
        environment: Arc<EnvironmentRoot>,
        namespaces: Vec<Arc<Namespace>>,
        keys: IdentityKeys,
        bytes: PoolCredentialBytes,
        role: Role,
        source: codec::ActivationSource,
    ) -> ConnectResult<Self> {
        Self::for_role_credentials(environment, namespaces, keys, bytes, role, source, None)
    }
    fn for_role_credentials(
        environment: Arc<EnvironmentRoot>,
        namespaces: Vec<Arc<Namespace>>,
        keys: IdentityKeys,
        bytes: PoolCredentialBytes,
        role: Role,
        source: codec::ActivationSource,
        tunnel: Option<(TunnelCredentialStorage, &str, &str)>,
    ) -> ConnectResult<Self> {
        Self::assemble_role_credentials(
            environment,
            namespaces,
            keys,
            bytes,
            role,
            source,
            tunnel,
            None,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Connection assembly retains original material, prepaid resources and physical cleanup custody across failure."
    )]
    pub(super) fn from_original_live_server_admission(
        environment: Arc<EnvironmentRoot>,
        namespaces: Vec<Arc<Namespace>>,
        keys: IdentityKeys,
        bytes: TunnelPoolCredentialBytes,
        service: &str,
        audience: &str,
        admission: CredentialAdmission,
        storage: ResourceCharge,
    ) -> ConnectResult<Self> {
        if !admission.account.belongs_to(&environment)
            || admission.source != codec::ActivationSource::LiveAuthority
            || admission
                .tunnel
                .as_ref()
                .is_none_or(|hop| hop.endpoint_role != 1)
        {
            return Err(ConnectError::Configuration);
        }
        admission.account.check()?;
        if !storage.matches(
            &admission.account,
            ResourceLimits {
                sdk_bytes: 98_304 + 18_432,
                items: 1,
                work_slots: 1,
                ..ResourceLimits::default()
            },
        ) {
            return Err(ConnectError::Configuration);
        }
        let TunnelPoolCredentialBytes {
            connection,
            grant,
            relay_certificate,
        } = bytes;
        Self::assemble_role_credentials(
            environment,
            namespaces,
            keys,
            connection,
            Role::Server,
            codec::ActivationSource::LiveAuthority,
            Some((
                TunnelCredentialStorage {
                    grant,
                    relay_certificate,
                },
                service,
                audience,
            )),
            Some((admission, storage)),
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Connection assembly retains original material, prepaid resources and physical cleanup custody across failure."
    )]
    fn assemble_role_credentials(
        environment: Arc<EnvironmentRoot>,
        mut namespaces: Vec<Arc<Namespace>>,
        keys: IdentityKeys,
        bytes: PoolCredentialBytes,
        role: Role,
        source: codec::ActivationSource,
        tunnel: Option<(TunnelCredentialStorage, &str, &str)>,
        original: Option<(CredentialAdmission, ResourceCharge)>,
    ) -> ConnectResult<Self> {
        let namespace_limit = if tunnel.is_some() { 8 } else { 3 };
        if !Arc::ptr_eq(&environment, &keys.owner.environment)
            || namespaces.is_empty()
            || namespaces.len() > namespace_limit
            || namespaces.capacity() > namespace_limit
            || tunnel.as_ref().is_some_and(|(hop, service, audience)| {
                hop.grant.capacity() > 9302
                    || hop.relay_certificate.capacity() > 8192
                    || service.is_empty()
                    || audience.is_empty()
                    || service.len() > 128
                    || audience.len() > 128
            })
            || bytes.artifact.len() > 65536
            || bytes.artifact.capacity() > 65536
            || bytes.client_certificate.len() > 8192
            || bytes.client_certificate.capacity() > 8192
            || bytes.server_certificate.len() > 8192
            || bytes.server_certificate.capacity() > 8192
            || bytes.activation.len() > 4096
            || bytes.activation.capacity() > 4096
        {
            return Err(ConnectError::Configuration);
        }
        for (i, n) in namespaces.iter().enumerate() {
            if namespaces[..i].iter().any(|old| Arc::ptr_eq(old, n)) {
                return Err(ConnectError::Configuration);
            }
        }
        // One stable original-owner order prevents reversed caller vectors from
        // deadlocking concurrent material verification.
        namespaces.sort_unstable_by_key(Arc::as_ptr);
        let (admission, charge) = if let Some(original) = original {
            original
        } else {
            let guards: Vec<_> = namespaces
                .iter()
                .map(|n| n.verifier.lock().expect("namespace owner"))
                .collect();
            let refs: Vec<_> = guards.iter().map(|v| &**v).collect();
            let input = DirectCredentialInput {
                artifact: &bytes.artifact,
                client_certificate: &bytes.client_certificate,
                server_certificate: &bytes.server_certificate,
                activation: &bytes.activation,
                source,
                candidate_index: first_pool_candidate(&bytes.activation, source)?,
            };
            let admission = if let Some((hop, service, audience)) = &tunnel {
                crate::namespace_v4::verifier::credential::tunnel::reserve_tunnel_connection(
                    &environment,
                    &refs,
                    input,
                    crate::namespace_v4::verifier::credential::tunnel::TunnelHopInput {
                        grant: &hop.grant,
                        relay_certificate: &hop.relay_certificate,
                        endpoint_role: role.index() as u8,
                        service,
                        audience,
                    },
                )?
            } else {
                reserve_direct_connection(&environment, &refs, input)?
            };
            drop(guards);
            let charge = admission.account.reserve(ResourceLimits {
                sdk_bytes: 98_304 + if tunnel.is_some() { 18_432 } else { 0 },
                items: 1,
                work_slots: 1,
                tasks: 0,
                sessions: 0,
                ..ResourceLimits::default()
            })?;
            (admission, charge)
        };
        let artifact = decode(&bytes.artifact, "Artifact", 65536, Context::default())?;
        let contract = artifact.field("Artifact", "session_contract")?;
        let cert = decode(
            if role == Role::Client {
                &bytes.client_certificate
            } else {
                &bytes.server_certificate
            },
            "IdentityCertificate",
            8192,
            Context::default(),
        )?;
        let noise = cert.field("IdentityCertificate", "noise_static_public_key")?;
        if artifact.u("Artifact", "required_features")?
            & !crate::checkpoint_v4::application_features(artifact)?
            != 0
            || contract.u("SessionContract", "application_profile")? == 2
                && !environment.application_config().execution
            || cert.b::<32>("IdentityCertificate", "ed25519_public_key")?
                != keys.ed25519_public_key()
            || noise
                .field("NoiseStaticPublicKey", "public_key_bytes")?
                .bytes()?
                != keys.noise_static_public_key()
            || artifact.field("Artifact", "crypto_profile_id")?.text()? != keys.profile()
        {
            return Err(ConnectError::Configuration);
        }
        let activation = decode(
            &bytes.activation,
            "ActivationAuthorization",
            4096,
            Context::with_activation_source(source),
        )?;
        if source == codec::ActivationSource::PreauthorizedPool
            && activation
                .field("ActivationAuthorization", "candidate_selection")?
                .field("PoolSelectionRef", "candidate_indices")?
                .len()?
                != 1
        {
            return Err(ConnectError::Configuration);
        }
        Ok(Self {
            admission,
            bytes,
            keys,
            namespaces,
            tunnel_credentials: tunnel.map(|(storage, _, _)| storage),
            server_allow: None,
            registered_pool: None,
            _charge: charge,
        })
    }
}
pub(crate) fn verify_live_source_policy(
    environment: &Arc<EnvironmentRoot>,
    namespaces: &[Arc<Namespace>],
    certificates: [&[u8]; 2],
    issuer: [u8; 16],
    signing_key_id: &str,
) -> ConnectResult<[[u8; 32]; 2]> {
    let guards: Vec<_> = namespaces
        .iter()
        .map(|namespace| namespace.verifier.lock().expect("live source namespace"))
        .collect();
    let references: Vec<_> = guards.iter().map(|guard| &**guard).collect();
    Ok(
        crate::namespace_v4::verifier::credential::verify_live_source_configuration(
            environment,
            &references,
            certificates,
            issuer,
            signing_key_id,
        )?,
    )
}
pub(crate) fn prepare_live_material(
    environment: &Arc<EnvironmentRoot>,
    namespaces: &[Arc<Namespace>],
    bytes: &PoolCredentialBytes,
    attempt: [u8; 16],
    signing_key_id: &str,
) -> ConnectResult<crate::namespace_v4::verifier::credential::PendingDirectAdmission> {
    let guards: Vec<_> = namespaces
        .iter()
        .map(|namespace| namespace.verifier.lock().expect("live material namespace"))
        .collect();
    let references: Vec<_> = guards.iter().map(|guard| &**guard).collect();
    Ok(
        crate::namespace_v4::verifier::credential::reserve_live_direct_preparation(
            environment,
            &references,
            DirectCredentialInput {
                artifact: &bytes.artifact,
                client_certificate: &bytes.client_certificate,
                server_certificate: &bytes.server_certificate,
                activation: &[],
                source: codec::ActivationSource::LiveAuthority,
                candidate_index: 0,
            },
            attempt,
            signing_key_id,
        )?,
    )
}
pub(crate) fn prepare_live_tunnel_material(
    environment: &Arc<EnvironmentRoot>,
    namespaces: &[Arc<Namespace>],
    bytes: &PoolCredentialBytes,
    attempt: [u8; 16],
    signing_key_id: &str,
) -> ConnectResult<crate::namespace_v4::verifier::credential::PendingDirectAdmission> {
    let guards: Vec<_> = namespaces
        .iter()
        .map(|namespace| {
            namespace
                .verifier
                .lock()
                .expect("live tunnel material namespace")
        })
        .collect();
    let references: Vec<_> = guards.iter().map(|guard| &**guard).collect();
    Ok(
        crate::namespace_v4::verifier::credential::reserve_live_tunnel_preparation(
            environment,
            &references,
            DirectCredentialInput {
                artifact: &bytes.artifact,
                client_certificate: &bytes.client_certificate,
                server_certificate: &bytes.server_certificate,
                activation: &[],
                source: codec::ActivationSource::LiveAuthority,
                candidate_index: 0,
            },
            attempt,
            signing_key_id,
        )?,
    )
}
pub(crate) fn validate_live_provider(
    artifact: &[u8],
    admission: &crate::namespace_v4::verifier::credential::PendingDirectAdmission,
    options: &WssConnectOptions,
) -> ConnectResult<()> {
    wss::Policy::new_live(artifact, admission, options).map(|_| ())
}
pub(crate) fn validate_live_tunnel_provider(
    artifact: &[u8],
    admission: &crate::namespace_v4::verifier::credential::PendingDirectAdmission,
    options: &WssConnectOptions,
) -> ConnectResult<()> {
    wss::Policy::new_live_tunnel(artifact, admission, options).map(|_| ())
}
pub(crate) fn validate_live_reverse_tunnel_provider(
    artifact: &[u8],
    admission: &crate::namespace_v4::verifier::credential::PendingDirectAdmission,
    options: &WssConnectOptions,
    reverse: &Arc<reverse::Capture>,
) -> ConnectResult<()> {
    reverse.validate_live(artifact, admission, options)
}
/// One numeric address, with signed host/SNI/route identity and no DNS retry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BindingMode {
    DirectExporter,
    #[default]
    AuthenticatedContext,
}
impl BindingMode {
    fn wire(self) -> u64 {
        match self {
            Self::DirectExporter => 0,
            Self::AuthenticatedContext => 1,
        }
    }
}
/// A fixed binding choice is checked before the original pool consumption.
#[derive(Clone, Debug)]
pub struct WssConnectOptions {
    pub binding_mode: BindingMode,
    pub remote_address: IpAddr,
    pub origin: Option<String>,
    pub ca_certificates_der: Vec<Vec<u8>>,
    pub timeout: Duration,
    pub publication_timeout: Duration,
    pub queue_messages: usize,
    pub prepare_bytes: usize,
    pub native_runtime_bytes: u64,
}
impl WssConnectOptions {
    pub(super) fn same_installation(&self, original: &Self) -> bool {
        self.binding_mode == original.binding_mode
            && self.remote_address == original.remote_address
            && self.origin == original.origin
            && self.ca_certificates_der == original.ca_certificates_der
            && self.timeout == original.timeout
            && self.publication_timeout == original.publication_timeout
            && self.queue_messages == original.queue_messages
            && self.prepare_bytes == original.prepare_bytes
            && self.native_runtime_bytes == original.native_runtime_bytes
    }
}
fn u(out: &mut Vec<u8>, value: u64) {
    codec::encode_head(out, 0, value)
}
fn b(out: &mut Vec<u8>, value: &[u8]) {
    codec::encode_head(out, 2, value.len() as u64);
    out.extend_from_slice(value)
}
fn t(out: &mut Vec<u8>, value: &str) {
    codec::encode_head(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes())
}
fn encode(count: u64, build: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut v = Vec::with_capacity(16384);
    codec::encode_head(&mut v, 5, count);
    build(&mut v);
    v
}
fn envelope(frame: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(payload.len() + 8);
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(&[frame, 0, 0, 0]);
    v.extend_from_slice(payload);
    v
}
fn payload(wire: &[u8], frame: u8, limit: usize) -> ConnectResult<&[u8]> {
    if wire.len() < 8
        || wire[4..8] != [frame, 0, 0, 0]
        || wire.len() - 8 > limit
        || u32::from_be_bytes(wire[..4].try_into().map_err(|_| ConnectError::Protocol)?) as usize
            != wire.len() - 8
    {
        return Err(ConnectError::Protocol);
    }
    Ok(&wire[8..])
}
struct ReadySubmission(Option<[u8; 103]>);
impl ReadyWriter for ReadySubmission {
    fn submit_ready(&mut self, payload: &[u8; 103]) -> Result<()> {
        if self.0.is_some() {
            return Err(CryptoError::State);
        }
        self.0 = Some(*payload);
        Ok(())
    }
}
struct PreparedSessionGuard(Option<Session>);
impl Drop for PreparedSessionGuard {
    fn drop(&mut self) {
        if let Some(session) = self.0.take() {
            session.close();
        }
    }
}
struct ConnectGuard(Option<Arc<wss::Provider>>);
impl Drop for ConnectGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.0.take() {
            provider.close();
        }
    }
}
pub(crate) async fn connect(
    environment: &TransportEnvironment,
    material: PoolConnectionMaterial,
    store: Arc<SQLitePoolStore>,
    options: WssConnectOptions,
    cancel: CancellationToken,
) -> ConnectResult<Session> {
    connect_with_handler_plan(environment, material, store, options, None, cancel).await
}

/// Connect the original pool attempt while reusing the same immutable inbound
/// handler assembly as Serve. The plan is captured and charged before pool
/// consumption; after READY it owns all incoming application streams.
pub(crate) async fn connect_with_handler_plan(
    environment: &TransportEnvironment,
    material: PoolConnectionMaterial,
    store: Arc<SQLitePoolStore>,
    options: WssConnectOptions,
    handler_plan: Option<(serve::HandlerPlan, ApplicationLimits)>,
    cancel: CancellationToken,
) -> ConnectResult<Session> {
    connect_with_handler_plan_requirements(
        environment,
        material,
        store,
        options,
        handler_plan,
        crate::ConnectionRequirements::default(),
        cancel,
    )
    .await
}
pub(crate) async fn connect_with_handler_plan_requirements(
    environment: &TransportEnvironment,
    material: PoolConnectionMaterial,
    store: Arc<SQLitePoolStore>,
    options: WssConnectOptions,
    handler_plan: Option<(serve::HandlerPlan, ApplicationLimits)>,
    requirements: crate::ConnectionRequirements,
    cancel: CancellationToken,
) -> ConnectResult<Session> {
    connect_with_provider_requirements(
        environment,
        material,
        store,
        options,
        handler_plan,
        requirements,
        None,
        cancel,
    )
    .await
}
#[expect(
    clippy::too_many_arguments,
    reason = "Connection assembly retains original material, prepaid resources and physical cleanup custody across failure."
)]
pub(crate) async fn connect_with_provider_requirements(
    environment: &TransportEnvironment,
    material: PoolConnectionMaterial,
    store: Arc<SQLitePoolStore>,
    options: WssConnectOptions,
    handler_plan: Option<(serve::HandlerPlan, ApplicationLimits)>,
    requirements: crate::ConnectionRequirements,
    reverse: Option<Arc<reverse::Capture>>,
    cancel: CancellationToken,
) -> ConnectResult<Session> {
    material
        .supports_requirements(&requirements)
        .map_err(|_| ConnectError::Configuration)?;
    connect_original(
        environment,
        OriginalDirectInput::Pool(material, store),
        options,
        handler_plan,
        requirements,
        reverse,
        cancel,
        None,
        None,
    )
    .await
}
pub(crate) async fn connect_live_with_handler_plan(
    environment: &TransportEnvironment,
    material: crate::live_material_source_v4::LiveConnectionMaterial,
    handler_plan: Option<(serve::HandlerPlan, ApplicationLimits)>,
    requirements: crate::ConnectionRequirements,
    cancel: CancellationToken,
) -> ConnectResult<Session> {
    let options = material.generation.provider.clone();
    supports_route_requirements(
        &material.bytes.artifact,
        material.generation.tunnel.as_ref().map(|_| 0),
        &requirements,
    )
    .map_err(|_| ConnectError::Configuration)?;
    let reverse = material.generation.reverse.clone();
    connect_original(
        environment,
        OriginalDirectInput::Live(material),
        options,
        handler_plan,
        requirements,
        reverse,
        cancel,
        None,
        None,
    )
    .await
}
#[expect(
    clippy::too_many_arguments,
    reason = "Connection assembly retains original material, prepaid resources and physical cleanup custody across failure."
)]
pub(crate) async fn connect_with_provider_requirements_prepaid(
    environment: &TransportEnvironment,
    material: PoolConnectionMaterial,
    store: Arc<SQLitePoolStore>,
    options: WssConnectOptions,
    handler_plan: Option<(serve::HandlerPlan, ApplicationLimits)>,
    requirements: crate::ConnectionRequirements,
    reverse: Option<Arc<reverse::Capture>>,
    cancel: CancellationToken,
    prepaid: ControllerPrepaidCharges,
    notification_hook: Option<Arc<dyn crate::connection_controller_v4::NotificationCandidateHook>>,
) -> ConnectResult<Session> {
    material
        .supports_requirements(&requirements)
        .map_err(|_| ConnectError::Configuration)?;
    connect_original(
        environment,
        OriginalDirectInput::Pool(material, store),
        options,
        handler_plan,
        requirements,
        reverse,
        cancel,
        Some(prepaid),
        notification_hook,
    )
    .await
}
pub(crate) async fn connect_live_with_handler_plan_prepaid(
    environment: &TransportEnvironment,
    material: crate::live_material_source_v4::LiveConnectionMaterial,
    handler_plan: Option<(serve::HandlerPlan, ApplicationLimits)>,
    requirements: crate::ConnectionRequirements,
    cancel: CancellationToken,
    prepaid: ControllerPrepaidCharges,
    notification_hook: Option<Arc<dyn crate::connection_controller_v4::NotificationCandidateHook>>,
) -> ConnectResult<Session> {
    let options = material.generation.provider.clone();
    supports_route_requirements(
        &material.bytes.artifact,
        material.generation.tunnel.as_ref().map(|_| 0),
        &requirements,
    )
    .map_err(|_| ConnectError::Configuration)?;
    let reverse = material.generation.reverse.clone();
    connect_original(
        environment,
        OriginalDirectInput::Live(material),
        options,
        handler_plan,
        requirements,
        reverse,
        cancel,
        Some(prepaid),
        notification_hook,
    )
    .await
}
#[expect(
    clippy::large_enum_variant,
    reason = "The single connection attempt owns its original credential value without another heap allocation."
)]
enum OriginalDirectInput {
    Pool(PoolConnectionMaterial, Arc<SQLitePoolStore>),
    Live(crate::live_material_source_v4::LiveConnectionMaterial),
}
impl OriginalDirectInput {
    fn account(&self) -> ResourceAccount {
        match self {
            Self::Pool(material, _) => material.admission.account.clone(),
            Self::Live(material) => material.pending.account.clone(),
        }
    }
    fn artifact(&self) -> &[u8] {
        match self {
            Self::Pool(material, _) => &material.bytes.artifact,
            Self::Live(material) => &material.bytes.artifact,
        }
    }
    fn candidate_indices(&self) -> ConnectResult<Vec<u8>> {
        let OriginalDirectInput::Pool(material, _) = self else {
            return Ok(vec![0]);
        };
        let Some(facts) = material.admission.pool.as_ref() else {
            return Ok(vec![
                material
                    .admission
                    .pool
                    .as_ref()
                    .map_or(0, |facts| facts.candidate_index),
            ]);
        };
        let selection = decode(
            &facts.selection,
            "PoolSelectionRef",
            4096,
            Context::default(),
        )?;
        let indices = selection.field("PoolSelectionRef", "candidate_indices")?;
        let mut result = Vec::new();
        for value in indices.children()? {
            result.push(u8::try_from(value?.uint()?).map_err(|_| ConnectError::Configuration)?);
        }
        if result.is_empty() || result.len() > 2 {
            return Err(ConnectError::Configuration);
        }
        Ok(result)
    }
    fn policy_candidate(
        &self,
        options: &WssConnectOptions,
        reverse: bool,
        index: u8,
    ) -> ConnectResult<wss::Policy> {
        match self {
            OriginalDirectInput::Pool(material, _) if !reverse => {
                wss::Policy::new_candidate(material, options, index)
            }
            _ => self.policy(options, reverse),
        }
    }
    fn policy(&self, options: &WssConnectOptions, reverse: bool) -> ConnectResult<wss::Policy> {
        match self {
            Self::Pool(material, _) if reverse => wss::Policy::new_reverse(material, options),
            Self::Pool(material, _) => wss::Policy::new(material, options),
            Self::Live(material) if reverse => wss::Policy::new_live_reverse_tunnel(
                &material.bytes.artifact,
                &material.pending,
                options,
            ),
            Self::Live(material) => {
                if material.generation.tunnel.is_some() {
                    wss::Policy::new_live_tunnel(
                        &material.bytes.artifact,
                        &material.pending,
                        options,
                    )
                } else {
                    wss::Policy::new_live(&material.bytes.artifact, &material.pending, options)
                }
            }
        }
    }
    fn artifact_digest(&self) -> [u8; 32] {
        match self {
            Self::Pool(material, _) => material.admission.artifact_digest,
            Self::Live(material) => material.pending.artifact_digest,
        }
    }
}
/// The original Connect owns one observer and one timer through its return.
/// Physical owners retain the existing counters after a bounded wait expires.
pub(crate) struct ConnectCleanup {
    session: Mutex<Option<Session>>,
    started: Mutex<Option<Instant>>,
    candidates: [Arc<AtomicUsize>; 2],
    controls: Arc<AtomicUsize>,
}
impl ConnectCleanup {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            session: Mutex::new(None),
            started: Mutex::new(None),
            candidates: std::array::from_fn(|_| Arc::new(AtomicUsize::new(0))),
            controls: Arc::new(AtomicUsize::new(0)),
        })
    }
    pub(super) fn start(&self) -> Instant {
        *self
            .started
            .lock()
            .expect("original Connect cleanup origin")
            .get_or_insert_with(Instant::now)
    }
    pub(super) fn deadline(&self) -> Instant {
        (self.start() + Duration::from_secs(10)).min(Instant::now() + Duration::from_secs(5))
    }
    pub(super) fn preparations(&self) -> Arc<AtomicUsize> {
        self.candidates[0].clone()
    }
    pub(crate) fn status(&self) -> crate::api_v4::CleanupStatus {
        let pending = self
            .candidates
            .iter()
            .map(|pending| pending.load(std::sync::atomic::Ordering::Acquire) as u64)
            .sum::<u64>()
            .saturating_add(self.controls.load(std::sync::atomic::Ordering::Acquire) as u64);
        let (session_status, retired) = {
            let mut session = self
                .session
                .lock()
                .expect("original unpublished Session cleanup");
            let status = session.as_ref().map(Session::cleanup_status);
            let retired = if status.as_ref().is_some_and(|status| status.complete) {
                session.take()
            } else {
                None
            };
            (status, retired)
        };
        drop(retired);
        let complete = pending == 0 && session_status.as_ref().is_none_or(|status| status.complete);
        crate::api_v4::CleanupStatus {
            complete,
            cleanup_incomplete: !complete,
            pending_callbacks: pending
                .saturating_add(session_status.map_or(0, |status| status.pending_callbacks)),
        }
    }
    pub(crate) fn complete(&self) -> bool {
        self.status().complete
    }
    fn retain_session(&self, session: Session) {
        *self
            .session
            .lock()
            .expect("original unpublished Session cleanup") = Some(session);
    }
}
async fn wait_candidate_cleanup(pending: &AtomicUsize, deadline: Instant) -> bool {
    loop {
        if pending.load(std::sync::atomic::Ordering::Acquire) == 0 {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        // One timer serves both progress observation and the fixed deadline.
        tokio::time::sleep_until((now + Duration::from_millis(10)).min(deadline)).await;
    }
}
async fn finish_candidate_race<F>(
    winner: (u8, direct_carrier::Provider, mpsc::Receiver<Vec<u8>>),
    loser: F,
    loser_pending: &AtomicUsize,
    cleanup: &ConnectCleanup,
) -> ConnectResult<(u8, direct_carrier::Provider, mpsc::Receiver<Vec<u8>>)>
where
    F: std::future::Future<
            Output = ConnectResult<(direct_carrier::Provider, mpsc::Receiver<Vec<u8>>)>,
        >,
{
    let mut winner_guard = direct_carrier::Guard(Some(winner.1.clone()));
    let deadline = cleanup.deadline();
    match tokio::time::timeout_at(deadline, loser).await {
        Ok(Ok((provider, incoming))) => {
            provider.close();
            drop(incoming);
        }
        Ok(Err(_)) => {}
        Err(_) => return Err(ConnectError::Deadline.cleanup_incomplete()),
    }
    if !wait_candidate_cleanup(loser_pending, deadline).await {
        return Err(ConnectError::Deadline.cleanup_incomplete());
    }
    winner.1.check()?;
    winner_guard.0 = None;
    Ok(winner)
}
async fn finish_after_candidate_failure<F>(
    candidate: F,
    index: u8,
    failed_pending: &AtomicUsize,
    cleanup: &ConnectCleanup,
) -> ConnectResult<(u8, direct_carrier::Provider, mpsc::Receiver<Vec<u8>>)>
where
    F: std::future::Future<
            Output = ConnectResult<(direct_carrier::Provider, mpsc::Receiver<Vec<u8>>)>,
        >,
{
    let deadline = cleanup.deadline();
    tokio::pin!(candidate);
    tokio::select! {
        result = &mut candidate => {
            let (provider, incoming) = result?;
            let mut guard = direct_carrier::Guard(Some(provider.clone()));
            if !wait_candidate_cleanup(failed_pending, deadline).await {
                return Err(ConnectError::Deadline.cleanup_incomplete());
            }
            provider.check()?;
            guard.0 = None;
            Ok((index, provider, incoming))
        },
        complete = wait_candidate_cleanup(failed_pending, deadline) => {
            if !complete { return Err(ConnectError::Deadline.cleanup_incomplete()); }
            // The failed tail has physically exited. The remaining concrete
            // provider preparation keeps its original bounded Prepare deadline.
            candidate.await.map(|(provider, incoming)| (index, provider, incoming))
        },
    }
}
fn take_prepaid_provider(
    charges: &mut Vec<(u8, ControllerProviderCharges)>,
    index: u8,
) -> ConnectResult<ControllerProviderCharges> {
    let position = charges
        .iter()
        .position(|(candidate, _)| *candidate == index)
        .ok_or(ConnectError::Configuration)?;
    Ok(charges.swap_remove(position).1)
}
fn fund_direct_prepaid(
    policy: &mut wss::Policy,
    account: &ResourceAccount,
    options: &WssConnectOptions,
    charges: ControllerProviderCharges,
) -> ConnectResult<()> {
    if charges.listener.is_some() || charges.tls.is_some() {
        return Err(ConnectError::Configuration);
    }
    policy.fund_prepaid(account, options, charges.connection)
}
#[expect(
    clippy::too_many_arguments,
    reason = "Connection assembly retains original material, prepaid resources and physical cleanup custody across failure."
)]
async fn prepare_pool_candidate_race_prepaid(
    input: &OriginalDirectInput,
    account: &ResourceAccount,
    options: &WssConnectOptions,
    deadline: Instant,
    cancel: &CancellationToken,
    indices: Vec<u8>,
    mut charges: Vec<(u8, ControllerProviderCharges)>,
    diagnostic: &Arc<crate::diagnostics_v4::DiagnosticActivity>,
    cleanup: &Arc<ConnectCleanup>,
) -> ConnectResult<(u8, direct_carrier::Provider, mpsc::Receiver<Vec<u8>>)> {
    if indices.len() < 2 {
        let index = indices[0];
        let mut policy = input.policy_candidate(options, false, index)?;
        let (per, total) = policy
            .preparation_capacity
            .ok_or(ConnectError::Configuration)?;
        let budget = flowersec_native_transport::PreparationBudget::with_capacity(total)
            .map_err(native::budget_error)?;
        policy.preparation_budget =
            Some(budget.begin_candidate(per).map_err(native::budget_error)?);
        fund_direct_prepaid(
            &mut policy,
            account,
            options,
            take_prepaid_provider(&mut charges, index)?,
        )?;
        let (provider, incoming) = direct_carrier::Provider::prepare_tracked_observed_with_cleanup(
            account.clone(),
            policy,
            options.clone(),
            deadline,
            cancel.clone(),
            cleanup.preparations(),
            diagnostic,
            Some(cleanup.clone()),
        )
        .await?;
        return Ok((index, provider, incoming));
    }
    let mut limits = None;
    let mut policies = Vec::new();
    for index in indices {
        let mut policy = input.policy_candidate(options, false, index)?;
        if policy.preparation_parallel != Some(2) {
            return Err(ConnectError::Configuration);
        }
        let (per, total) = policy
            .preparation_capacity
            .ok_or(ConnectError::Configuration)?;
        if limits.is_some_and(|expected| expected != total) {
            return Err(ConnectError::Authorization);
        }
        limits = Some(total);
        fund_direct_prepaid(
            &mut policy,
            account,
            options,
            take_prepaid_provider(&mut charges, index)?,
        )?;
        policies.push((index, policy, per));
    }
    let budget = flowersec_native_transport::PreparationBudget::with_capacity(
        limits.ok_or(ConnectError::Configuration)?,
    )
    .map_err(native::budget_error)?;
    for (_, policy, per) in &mut policies {
        policy.preparation_budget =
            Some(budget.begin_candidate(*per).map_err(native::budget_error)?);
    }
    let first = policies.remove(0);
    let second = policies.remove(0);
    let first_cancel = cancel.child_token();
    let second_cancel = cancel.child_token();
    let first_future = direct_carrier::Provider::prepare_tracked_observed_with_cleanup(
        account.clone(),
        first.1,
        options.clone(),
        deadline,
        first_cancel.clone(),
        cleanup.candidates[0].clone(),
        diagnostic,
        Some(cleanup.clone()),
    );
    let second_future = async {
        diagnostic.set_attempt(2);
        direct_carrier::Provider::prepare_tracked_observed_with_cleanup(
            account.clone(),
            second.1,
            options.clone(),
            deadline,
            second_cancel.clone(),
            cleanup.candidates[1].clone(),
            diagnostic,
            Some(cleanup.clone()),
        )
        .await
    };
    tokio::pin!(first_future);
    tokio::pin!(second_future);
    tokio::select! {
        result = &mut first_future => match result {
            Ok((provider, incoming)) => {
                cleanup.start(); second_cancel.cancel();
                finish_candidate_race((first.0, provider, incoming), second_future, &cleanup.candidates[1], cleanup).await
            },
            Err(_) => {
                cleanup.start();
                finish_after_candidate_failure(second_future, second.0, &cleanup.candidates[0], cleanup).await
            },
        },
        result = &mut second_future => match result {
            Ok((provider, incoming)) => {
                cleanup.start(); first_cancel.cancel();
                finish_candidate_race((second.0, provider, incoming), first_future, &cleanup.candidates[0], cleanup).await
            },
            Err(_) => {
                cleanup.start();
                finish_after_candidate_failure(first_future, first.0, &cleanup.candidates[1], cleanup).await
            },
        },
        _ = cancel.cancelled() => {
            cleanup.start(); first_cancel.cancel(); second_cancel.cancel();
            // Dropping the original preparation futures closes their guarded
            // physical owners. The outer original Connect waits those tails.
            Err(ConnectError::Canceled)
        }
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "Connection assembly retains original material, prepaid resources and physical cleanup custody across failure."
)]
async fn prepare_pool_candidate_race(
    input: &OriginalDirectInput,
    account: &ResourceAccount,
    options: &WssConnectOptions,
    deadline: Instant,
    cancel: &CancellationToken,
    indices: Vec<u8>,
    diagnostic: &Arc<crate::diagnostics_v4::DiagnosticActivity>,
    cleanup: &Arc<ConnectCleanup>,
) -> ConnectResult<(u8, direct_carrier::Provider, mpsc::Receiver<Vec<u8>>)> {
    if indices.len() < 2 {
        let index = indices[0];
        let mut policy = input.policy_candidate(options, false, index)?;
        let (per, total) = policy
            .preparation_capacity
            .ok_or(ConnectError::Configuration)?;
        let budget = flowersec_native_transport::PreparationBudget::with_capacity(total)
            .map_err(native::budget_error)?;
        policy.preparation_budget =
            Some(budget.begin_candidate(per).map_err(native::budget_error)?);
        let (provider, incoming) = direct_carrier::Provider::prepare_tracked_observed_with_cleanup(
            account.clone(),
            policy,
            options.clone(),
            deadline,
            cancel.clone(),
            cleanup.preparations(),
            diagnostic,
            Some(cleanup.clone()),
        )
        .await?;
        return Ok((index, provider, incoming));
    }
    let mut limits = None;
    let mut policies = Vec::new();
    for index in indices {
        let policy = input.policy_candidate(options, false, index)?;
        if policy.preparation_parallel != Some(2) {
            return Err(ConnectError::Configuration);
        }
        let (per, total) = policy
            .preparation_capacity
            .ok_or(ConnectError::Configuration)?;
        if let Some(expected) = limits {
            if expected != total {
                return Err(ConnectError::Authorization);
            }
        } else {
            limits = Some(total);
        }
        policies.push((index, policy, per));
    }
    let budget = flowersec_native_transport::PreparationBudget::with_capacity(
        limits.ok_or(ConnectError::Configuration)?,
    )
    .map_err(native::budget_error)?;
    for (_, policy, per) in &mut policies {
        policy.preparation_budget =
            Some(budget.begin_candidate(*per).map_err(native::budget_error)?);
    }
    let first = policies.remove(0);
    let second = policies.remove(0);
    let first_cancel = cancel.child_token();
    let second_cancel = cancel.child_token();
    let first_future = direct_carrier::Provider::prepare_tracked_observed_with_cleanup(
        account.clone(),
        first.1,
        options.clone(),
        deadline,
        first_cancel.clone(),
        cleanup.candidates[0].clone(),
        diagnostic,
        Some(cleanup.clone()),
    );
    let second_future = async {
        diagnostic.set_attempt(2);
        direct_carrier::Provider::prepare_tracked_observed_with_cleanup(
            account.clone(),
            second.1,
            options.clone(),
            deadline,
            second_cancel.clone(),
            cleanup.candidates[1].clone(),
            diagnostic,
            Some(cleanup.clone()),
        )
        .await
    };
    tokio::pin!(first_future);
    tokio::pin!(second_future);
    tokio::select! {
        result = &mut first_future => match result {
            Ok((provider, incoming)) => {
                cleanup.start(); second_cancel.cancel();
                finish_candidate_race((first.0, provider, incoming), second_future, &cleanup.candidates[1], cleanup).await
            },
            Err(_) => {
                cleanup.start();
                finish_after_candidate_failure(second_future, second.0, &cleanup.candidates[0], cleanup).await
            },
        },
        result = &mut second_future => match result {
            Ok((provider, incoming)) => {
                cleanup.start(); first_cancel.cancel();
                finish_candidate_race((second.0, provider, incoming), first_future, &cleanup.candidates[0], cleanup).await
            },
            Err(_) => {
                cleanup.start();
                finish_after_candidate_failure(first_future, first.0, &cleanup.candidates[1], cleanup).await
            },
        },
        _ = cancel.cancelled() => {
            cleanup.start(); first_cancel.cancel(); second_cancel.cancel();
            // Dropping the original preparation futures closes their guarded
            // physical owners. The outer original Connect waits those tails.
            Err(ConnectError::Canceled)
        }
    }
}
fn identity_boundary_error(root: &EnvironmentRoot, error: CryptoError) -> ConnectError {
    if matches!(error, CryptoError::Authentication | CryptoError::Key) {
        root.diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::IdentityFailures);
    }
    ConnectError::from(error)
}

fn connect_diagnostic_code(error: &ConnectError) -> crate::DiagnosticCode {
    match error {
        ConnectError::Canceled => crate::DiagnosticCode::Canceled,
        ConnectError::Deadline => crate::DiagnosticCode::Timeout,
        ConnectError::Capacity => crate::DiagnosticCode::ResourceRejected,
        ConnectError::Tls => crate::DiagnosticCode::TlsRejected,
        ConnectError::Authorization => crate::DiagnosticCode::IdentityRejected,
        ConnectError::Pool(pool) => match pool.code {
            PoolStoreFailure::SpentUnknown | PoolStoreFailure::RelayClaimUnknown => {
                crate::DiagnosticCode::SpendUnknown
            }
            PoolStoreFailure::StorageUnavailable
            | PoolStoreFailure::StorageFormat
            | PoolStoreFailure::HistoryUnknown
            | PoolStoreFailure::OwnerUnavailable
            | PoolStoreFailure::Closed => crate::DiagnosticCode::StoreUnavailable,
            PoolStoreFailure::SpendConflict
            | PoolStoreFailure::AdmissionConflict
            | PoolStoreFailure::RelayPublicationConflict
            | PoolStoreFailure::RelayClaimConflict
            | PoolStoreFailure::WinnerConflict
            | PoolStoreFailure::Fenced => crate::DiagnosticCode::ReservationConflict,
            PoolStoreFailure::Capacity => crate::DiagnosticCode::ResourceRejected,
            PoolStoreFailure::Configuration => crate::DiagnosticCode::Other,
        },
        ConnectError::LiveAuthorizationUnknown => crate::DiagnosticCode::SpendUnknown,
        ConnectError::LiveAuthorized(cause) => match cause {
            PostAuthorizationFailure::Capacity => crate::DiagnosticCode::ResourceRejected,
            PostAuthorizationFailure::Authorization => crate::DiagnosticCode::IdentityRejected,
            PostAuthorizationFailure::Tls => crate::DiagnosticCode::TlsRejected,
            PostAuthorizationFailure::Canceled => crate::DiagnosticCode::Canceled,
            PostAuthorizationFailure::Deadline => crate::DiagnosticCode::Timeout,
            _ => crate::DiagnosticCode::Protocol,
        },
        ConnectError::AdmissionUnknown { failure, .. }
        | ConnectError::Admitted { failure, .. }
        | ConnectError::Ready { failure, .. }
        | ConnectError::Spent(failure)
        | ConnectError::CleanupIncomplete { failure, .. } => match failure {
            PostSpendFailure::Capacity => crate::DiagnosticCode::ResourceRejected,
            PostSpendFailure::Authorization => crate::DiagnosticCode::IdentityRejected,
            PostSpendFailure::Tls => crate::DiagnosticCode::TlsRejected,
            PostSpendFailure::Canceled => crate::DiagnosticCode::Canceled,
            PostSpendFailure::Deadline => crate::DiagnosticCode::Timeout,
            PostSpendFailure::Pool(pool) => connect_diagnostic_code(&ConnectError::Pool(*pool)),
            _ => crate::DiagnosticCode::Protocol,
        },
        ConnectError::Configuration | ConnectError::Carrier | ConnectError::Protocol => {
            crate::DiagnosticCode::Protocol
        }
    }
}

struct OriginalConnectOutcome {
    diagnostic: Arc<crate::diagnostics_v4::DiagnosticActivity>,
    session: Option<Session>,
    settled: bool,
}
impl Drop for OriginalConnectOutcome {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        self.diagnostic.fail(
            crate::DiagnosticCode::Canceled,
            crate::DiagnosticRetryDisposition::DoNotRetry,
        );
        if let Some(session) = &self.session {
            // Transfer the canceled observation before closing the undelivered
            // Session. Its original worker retains application and native tails.
            session.attach_connect_diagnostic(self.diagnostic.clone());
            session.close();
        } else {
            // Prepared providers retain physical tails across Future drop.
            self.diagnostic.closed();
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Connection assembly retains original material, prepaid resources and physical cleanup custody across failure."
)]
async fn connect_original(
    environment: &TransportEnvironment,
    input: OriginalDirectInput,
    options: WssConnectOptions,
    handler_plan: Option<(serve::HandlerPlan, ApplicationLimits)>,
    requirements: crate::ConnectionRequirements,
    reverse: Option<Arc<reverse::Capture>>,
    cancel: CancellationToken,
    prepaid: Option<ControllerPrepaidCharges>,
    notification_hook: Option<Arc<dyn crate::connection_controller_v4::NotificationCandidateHook>>,
) -> ConnectResult<Session> {
    let account = input.account();
    let diagnostic = account.diagnostic_activity(crate::DiagnosticPhase::Connect, 1);
    let cleanup = prepaid.as_ref().map_or_else(
        ConnectCleanup::new,
        ControllerPrepaidCharges::cleanup_observer,
    );
    let mut physical_provider = None;
    let mut outcome = OriginalConnectOutcome {
        diagnostic: diagnostic.clone(),
        session: None,
        settled: false,
    };
    let mut work_owner = None;
    let result = connect_original_attempt(
        environment,
        input,
        options,
        handler_plan,
        requirements,
        reverse,
        cancel,
        prepaid,
        notification_hook,
        diagnostic.clone(),
        &mut physical_provider,
        &mut outcome.session,
        &mut work_owner,
        &cleanup,
    )
    .await;
    let result = match result {
        Ok(session) => {
            diagnostic.succeed();
            session.attach_connect_diagnostic(diagnostic.clone());
            Ok(session)
        }
        Err(error) => {
            diagnostic.fail(
                connect_diagnostic_code(&error),
                crate::DiagnosticRetryDisposition::DoNotRetry,
            );
            let already_incomplete = matches!(error, ConnectError::CleanupIncomplete { .. });
            if already_incomplete {
                report_connect_cleanup_timeout(&diagnostic);
            }
            let deadline = cleanup.deadline();
            if let Some(session) = &outcome.session {
                cleanup.retain_session(session.clone());
                session.attach_connect_diagnostic(diagnostic.clone());
                session.close();
            } else if let Some(provider) = &physical_provider {
                provider.retain_connect_diagnostic(diagnostic.clone());
            }
            if let Some(provider) = &physical_provider {
                provider.close();
            }
            // Observe the same Session Close and preparation owners. The
            // original work prepayment remains live through this one-timer wait.
            let incomplete = !wait_connect_cleanup(
                outcome.session.as_ref(),
                physical_provider.as_ref(),
                &cleanup,
                deadline,
            )
            .await;
            if incomplete && !already_incomplete {
                report_connect_cleanup_timeout(&diagnostic);
            }
            // A failed Session's own original worker requests Closed only after
            // its core, application and native cleanup really completes.
            if outcome.session.is_none() {
                diagnostic.closed();
            }
            Err(if incomplete {
                error.cleanup_incomplete()
            } else {
                error
            })
        }
    };
    outcome.settled = true;
    drop(work_owner);
    result
}
async fn wait_connect_cleanup(
    session: Option<&Session>,
    provider: Option<&direct_carrier::Provider>,
    cleanup: &ConnectCleanup,
    deadline: Instant,
) -> bool {
    loop {
        let session_status = session.map(Session::cleanup_status);
        let provider_complete = provider.is_none_or(|provider| provider.cleanup().complete);
        if session_status.as_ref().is_none_or(|status| status.complete)
            && provider_complete
            && cleanup.complete()
        {
            return true;
        }
        let now = Instant::now();
        if session_status.is_some_and(|status| status.cleanup_incomplete) || now >= deadline {
            return false;
        }
        tokio::time::sleep_until((now + Duration::from_millis(10)).min(deadline)).await;
    }
}
fn report_connect_cleanup_timeout(diagnostic: &crate::diagnostics_v4::DiagnosticActivity) {
    diagnostic.observe(
        crate::DiagnosticMetric::CleanupTimeouts,
        crate::DiagnosticState::Other,
        crate::DiagnosticPhase::Close,
        crate::DiagnosticCode::CleanupTimeout,
    );
    diagnostic.event(
        crate::DiagnosticState::Other,
        crate::DiagnosticPhase::Close,
        crate::DiagnosticCode::CleanupTimeout,
        crate::DiagnosticRetryDisposition::DoNotRetry,
    );
}

#[expect(
    clippy::too_many_arguments,
    reason = "Connection assembly retains original material, prepaid resources and physical cleanup custody across failure."
)]
async fn connect_original_attempt(
    environment: &TransportEnvironment,
    input: OriginalDirectInput,
    options: WssConnectOptions,
    handler_plan: Option<(serve::HandlerPlan, ApplicationLimits)>,
    requirements: crate::ConnectionRequirements,
    reverse: Option<Arc<reverse::Capture>>,
    cancel: CancellationToken,
    prepaid: Option<ControllerPrepaidCharges>,
    notification_hook: Option<Arc<dyn crate::connection_controller_v4::NotificationCandidateHook>>,
    diagnostic: Arc<crate::diagnostics_v4::DiagnosticActivity>,
    physical_provider: &mut Option<direct_carrier::Provider>,
    physical_session: &mut Option<Session>,
    work_owner: &mut Option<ResourceCharge>,
    cleanup: &Arc<ConnectCleanup>,
) -> ConnectResult<Session> {
    let account = input.account();
    if !environment.owns_account(&account)
        || !tokio::runtime::Handle::try_current().is_ok_and(|handle| {
            handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
        })
    {
        return Err(ConnectError::Configuration);
    }
    let handler_plan = handler_plan
        .map(|(plan, limits)| {
            let plan = plan
                .capture(environment.root())
                .map_err(|_| ConnectError::Authorization)?;
            plan.validate_limits(limits)
                .map_err(|_| ConnectError::Configuration)?;
            Ok::<_, ConnectError>((plan, limits))
        })
        .transpose()?;
    let mut prepaid = prepaid;
    let application = if let Some((_, limits)) = &handler_plan {
        let lifetime = if let Some(prepaid) = &mut prepaid {
            ApplicationLifetime::with_prepaid(
                account.clone(),
                *limits,
                CancellationToken::new(),
                prepaid
                    .application
                    .take()
                    .ok_or(ConnectError::Configuration)?,
            )?
        } else {
            ApplicationLifetime::with_cancellation(
                account.clone(),
                *limits,
                CancellationToken::new(),
            )?
        };
        Some(lifetime)
    } else {
        if prepaid
            .as_ref()
            .is_some_and(|prepaid| prepaid.application.is_some())
        {
            return Err(ConnectError::Configuration);
        }
        None
    };
    // Freeze every configured graph from the same acquisition backing before
    // Prepare, irreversible pool consumption or original live authorization.
    let artifact_view = decode(input.artifact(), "Artifact", 65536, Context::default())?;
    let application_profile = artifact_view
        .field("Artifact", "session_contract")?
        .u("SessionContract", "application_profile")? as u8;
    let peer_identity = artifact_view.b::<32>("Artifact", "server_identity_digest")?;
    let prepared_services = if let Some(prepaid) = &mut prepaid {
        let has_services = handler_plan
            .as_ref()
            .map(|(plan, _)| plan.service_preparation_limits())
            .transpose()
            .map_err(controller_service_cost_error)?
            .flatten()
            .is_some();
        if has_services {
            handler_plan
                .as_ref()
                .ok_or(ConnectError::Configuration)?
                .0
                .reserve_services_prepaid(
                    &account,
                    application_profile,
                    peer_identity,
                    prepaid.services.take(),
                )
        } else if let Some(query) = prepaid.managed_query {
            controller_service_plan(query)
                .reserve_prepaid(
                    &account,
                    application_profile,
                    peer_identity,
                    prepaid.services.take().ok_or(ConnectError::Configuration)?,
                )
                .map(Some)
        } else if prepaid.services.is_none() {
            Ok(None)
        } else {
            return Err(ConnectError::Configuration);
        }
    } else {
        handler_plan
            .as_ref()
            .map(|(plan, _)| plan.reserve_services(&account, application_profile, peer_identity))
            .transpose()
            .map(Option::flatten)
    }
    .map_err(|failure| match failure.code {
        serve::ServeFailure::Capacity => ConnectError::Capacity,
        serve::ServeFailure::Closed => ConnectError::Canceled,
        _ => ConnectError::Configuration,
    })?;
    // Execution always owns the fixed M initializer, including the default
    // Controller plan with no inbound history grants. Its complete backing is
    // acquired before the original connection consumes admission authority.
    let prepared_default_management = if application_profile == 2
        && !handler_plan
            .as_ref()
            .is_some_and(|(plan, _)| plan.has_management_plan())
    {
        let management = if let Some(prepaid) = &mut prepaid {
            crate::ExecutionManagement::prepare_installation_prepaid(
                &account,
                0,
                application_profile,
                peer_identity,
                &[],
                prepaid
                    .management
                    .take()
                    .ok_or(ConnectError::Configuration)?,
            )
        } else {
            crate::ExecutionManagement::prepare_installation(
                &account,
                0,
                application_profile,
                peer_identity,
                &[],
            )
        };
        Some(management.map_err(|_| ConnectError::Capacity)?)
    } else {
        if prepaid
            .as_ref()
            .is_some_and(|prepaid| prepaid.management.is_some())
        {
            return Err(ConnectError::Configuration);
        }
        None
    };
    let tunnel = match &input {
        OriginalDirectInput::Pool(material, _) => material.tunnel_credentials.is_some(),
        OriginalDirectInput::Live(material) => material.generation.tunnel.is_some(),
    };
    let hop_charge = if tunnel {
        Some(if let Some(prepaid) = &mut prepaid {
            prepaid.hop.take().ok_or(ConnectError::Configuration)?
        } else {
            account.reserve(hop::EndpointHop::preparation_limits())?
        })
    } else {
        None
    };
    let (
        work,
        session_charge,
        received,
        mut prepaid_provider,
        prepaid_handshake,
        native_application_charge,
    ) = if let Some(prepaid) = prepaid {
        if !prepaid.work.matches(&account, controller_work_limits())
            || !prepaid
                .session
                .matches(&account, controller_session_limits())
            || !prepaid
                .received
                .matches(&account, controller_received_limits())
            || !prepaid.bindings.is_empty()
        {
            return Err(ConnectError::Configuration);
        }
        (
            prepaid.work,
            prepaid.session,
            prepaid.received,
            Some(prepaid.provider),
            Some(prepaid.handshake),
            prepaid.native_application,
        )
    } else {
        (
            account.reserve(controller_work_limits())?,
            account.reserve(controller_session_limits())?,
            account.reserve(controller_received_limits())?,
            None,
            None,
            None,
        )
    };
    *work_owner = Some(work);
    let deadline = Instant::now()
        .checked_add(options.timeout.min(Duration::from_secs(30)))
        .ok_or(ConnectError::Configuration)?;
    let binding_mode = options.binding_mode;
    let shape = RecordShape::from_artifact(artifact_view)?;
    let record_reservation = if let Some(charge) = prepaid_handshake {
        HandshakePreflight::new_prepaid(account.clone(), shape, Role::Client, charge)?
    } else {
        HandshakePreflight::new(account.clone(), shape, Role::Client)?
    };
    let artifact_digest = input.artifact_digest();
    let (selected_candidate, provider, mut incoming) = if let Some(reverse) = reverse {
        let policy = input.policy(&options, true)?;
        let result = if let OriginalDirectInput::Live(material) = &input {
            let tunnel = material
                .generation
                .tunnel
                .as_ref()
                .ok_or(ConnectError::Configuration)?;
            reverse
                .prepare_live(
                    account.clone(),
                    input.artifact(),
                    policy,
                    options.clone(),
                    deadline,
                    cancel.clone(),
                    prepaid_provider
                        .take()
                        .map(|mut charges| take_prepaid_provider(&mut charges, 0))
                        .transpose()?,
                    tunnel.control.clone(),
                    &material.pending,
                    Some(diagnostic.clone()),
                    Some(cleanup.clone()),
                )
                .await?
        } else if let Some(mut charges) = prepaid_provider.take() {
            let index = match &input {
                OriginalDirectInput::Pool(material, _) => material
                    .admission
                    .pool
                    .as_ref()
                    .map_or(0, |facts| facts.candidate_index),
                OriginalDirectInput::Live(_) => 0,
            };
            let prepaid = take_prepaid_provider(&mut charges, index)?;
            reverse
                .prepare_prepaid(
                    account.clone(),
                    input.artifact(),
                    policy,
                    options.clone(),
                    deadline,
                    cancel.clone(),
                    prepaid,
                    Some(diagnostic.clone()),
                    Some(cleanup.clone()),
                )
                .await?
        } else {
            reverse
                .prepare(
                    account.clone(),
                    input.artifact(),
                    policy,
                    options.clone(),
                    deadline,
                    cancel.clone(),
                    Some(diagnostic.clone()),
                    Some(cleanup.clone()),
                )
                .await?
        };
        (None, result.0, result.1)
    } else if let Some(mut prepaid) = prepaid_provider {
        if matches!(&input, OriginalDirectInput::Pool(..)) {
            let indices = input.candidate_indices()?;
            let (index, provider, incoming) = prepare_pool_candidate_race_prepaid(
                &input,
                &account,
                &options,
                deadline,
                &cancel,
                indices,
                prepaid,
                &diagnostic,
                cleanup,
            )
            .await?;
            (Some(index), provider, incoming)
        } else {
            let mut policy = input.policy(&options, false)?;
            fund_direct_prepaid(
                &mut policy,
                &account,
                &options,
                take_prepaid_provider(&mut prepaid, 0)?,
            )?;
            let result = direct_carrier::Provider::prepare_tracked_observed_with_cleanup(
                account.clone(),
                policy,
                options.clone(),
                deadline,
                cancel.clone(),
                cleanup.preparations(),
                &diagnostic,
                Some(cleanup.clone()),
            )
            .await?;
            (None, result.0, result.1)
        }
    } else if matches!(&input, OriginalDirectInput::Pool(..)) {
        let indices = input.candidate_indices()?;
        let (index, provider, incoming) = prepare_pool_candidate_race(
            &input,
            &account,
            &options,
            deadline,
            &cancel,
            indices,
            &diagnostic,
            cleanup,
        )
        .await?;
        (Some(index), provider, incoming)
    } else {
        let policy = input.policy(&options, false)?;
        let result = direct_carrier::Provider::prepare_tracked_observed_with_cleanup(
            account.clone(),
            policy,
            options.clone(),
            deadline,
            cancel.clone(),
            cleanup.preparations(),
            &diagnostic,
            Some(cleanup.clone()),
        )
        .await?;
        (None, result.0, result.1)
    };
    cleanup.start();
    *physical_provider = Some(provider.clone());
    let mut guard = direct_carrier::Guard(Some(provider.clone()));
    provider.fund_application(
        &account,
        shape.max_frame + 8,
        shape.application_profile,
        native_application_charge,
    )?;
    if requirements.datagram
        && provider.feature_mask_for_candidate(artifact_view, selected_candidate.unwrap_or(0))? & 1
            == 0
    {
        return Err(ConnectError::Configuration);
    }
    if artifact_view.u("Artifact", "required_features")?
        & !provider.feature_mask_for_candidate(artifact_view, selected_candidate.unwrap_or(0))?
        != 0
    {
        return Err(ConnectError::Configuration);
    }
    let exporter = provider.binding(binding_mode, artifact_digest)?;
    // Native Prepare has completed on this selected physical owner. End only
    // its DNS/TLS/H3 input phase before irreversible spend or live TxB; later
    // Flowersec/HOP input keeps its separate original preauth reservations.
    provider.complete_preparation()?;
    let mut original_hop = hop_charge
        .map(|charge| hop::EndpointHop::prepare(&account, &provider, charge))
        .transpose()?;
    // Every predictable HOP envelope and signed byte limit is checked while
    // the original pool activation is still unspent. Live Grant bytes fill the
    // same already reserved workspace after the one original authorization.
    if let OriginalDirectInput::Pool(material, _) = &input
        && let Some(credentials) = &material.tunnel_credentials
    {
        original_hop = Some(
            original_hop
                .take()
                .ok_or(ConnectError::Configuration)?
                .bind(
                    &material.admission,
                    &credentials.grant,
                    &material.bytes.client_certificate,
                    &credentials.relay_certificate,
                    &material.keys,
                )?,
        );
    }
    let (
        mut admission,
        bytes,
        keys,
        namespaces,
        tunnel_credentials,
        _material_charge,
        registered_custody,
        server_allow_publication,
    ) = match input {
        OriginalDirectInput::Pool(mut material, store) => {
            if let Some(index) = selected_candidate {
                material
                    .admission
                    .select_prepared_candidate(&material.bytes.artifact, index)
                    .map_err(ConnectError::from)?;
            }
            // All destination, grant, wire and native/provider publication
            // backing is fixed while this original activation is unspent.
            let server_allow_publication = material.prepare_server_allow(cleanup)?;
            let owner = PoolSpendOwner::new(provider.identity(), 1, deadline, cancel.clone())?
                .bind_carrier(provider.cancellation());
            let PoolConnectionMaterial {
                admission,
                bytes,
                keys,
                namespaces,
                tunnel_credentials,
                server_allow: _server_allow,
                registered_pool: _registered_pool,
                _charge,
            } = material;
            (
                store.consume(admission, owner)?,
                bytes,
                keys,
                namespaces,
                tunnel_credentials,
                _charge,
                None,
                server_allow_publication,
            )
        }
        OriginalDirectInput::Live(material) => {
            let crate::live_material_source_v4::LiveConnectionMaterial {
                generation,
                pending,
                mut bytes,
                _storage,
                _registered_custody,
            } = material;
            provider.check()?;
            let native_cancel = provider.cancellation();
            let tunnel = generation.tunnel.as_ref().map(|details| {
                (
                    details.control.clone(),
                    details.relay_certificate.to_vec(),
                    details.service.clone(),
                    details.audience.clone(),
                )
            });
            let tunnel_request = if tunnel.is_some() {
                Some(
                    crate::live_material_source_v4::LiveSourceGeneration::authorization_request(
                        &pending,
                        &bytes.artifact,
                    )?,
                )
            } else {
                None
            };
            let (proof, client_grant) = if let Some((control, _, _, _)) = tunnel.as_ref() {
                let request = tunnel_request
                    .as_ref()
                    .expect("live tunnel authorization request");
                tokio::select! {
                    result = control.relay_prepare(request, &cancel) => result?,
                    _ = cancel.cancelled() => return Err(ConnectError::LiveAuthorizationUnknown),
                    _ = native_cancel.cancelled() => return Err(ConnectError::LiveAuthorizationUnknown),
                    _ = tokio::time::sleep_until(deadline) => return Err(ConnectError::LiveAuthorizationUnknown),
                };
                let authorization = tokio::select! {
                    result = control.authorize_tunnel(request, &cancel) => result?,
                    _ = cancel.cancelled() => return Err(ConnectError::LiveAuthorizationUnknown),
                    _ = native_cancel.cancelled() => return Err(ConnectError::LiveAuthorizationUnknown),
                    _ = tokio::time::sleep_until(deadline) => return Err(ConnectError::LiveAuthorizationUnknown),
                };
                (authorization.activation, Some(authorization.client_grant))
            } else {
                let proof = tokio::select! {
                    result = generation.authorize(&pending, &bytes.artifact, &cancel) => result?,
                    _ = cancel.cancelled() => return Err(ConnectError::LiveAuthorizationUnknown),
                    _ = native_cancel.cancelled() => return Err(ConnectError::LiveAuthorizationUnknown),
                    _ = tokio::time::sleep_until(deadline) => return Err(ConnectError::LiveAuthorizationUnknown),
                };
                (proof.to_vec(), None)
            };
            // Complete credential verification under the current namespace
            // locks, then release them before any original control I/O. The
            // remote continuation may itself need the same namespace owner.
            let (admission, tunnel_credentials) = {
                let guards: Vec<_> = generation
                    .namespaces
                    .iter()
                    .map(|namespace| {
                        namespace
                            .verifier
                            .lock()
                            .expect("original live proof namespace")
                    })
                    .collect();
                let references: Vec<_> = guards.iter().map(|namespace| &**namespace).collect();
                if let Some((_, relay_certificate, service, audience)) = tunnel.as_ref() {
                    let grant = client_grant
                        .as_ref()
                        .ok_or(ConnectError::LiveAuthorizationUnknown)?;
                    let admission = pending
                        .complete_tunnel(
                            environment.root(),
                            &references,
                            &bytes.artifact,
                            &bytes.client_certificate,
                            &bytes.server_certificate,
                            &proof,
                            grant,
                            relay_certificate,
                            service,
                            audience,
                        )
                        .map_err(|_| {
                            account.diagnostic_count(
                                crate::diagnostics_v4::DiagnosticCounter::IdentityFailures,
                            );
                            ConnectError::LiveAuthorizationUnknown
                        })?;
                    (
                        admission,
                        Some(TunnelCredentialStorage {
                            grant: grant.to_vec(),
                            relay_certificate: relay_certificate.to_vec(),
                        }),
                    )
                } else {
                    let admission = pending
                        .complete(environment.root(), &references, &bytes.artifact, &proof)
                        .map_err(|_| {
                            account.diagnostic_count(
                                crate::diagnostics_v4::DiagnosticCounter::IdentityFailures,
                            );
                            ConnectError::LiveAuthorizationUnknown
                        })?;
                    (admission, None)
                }
            };
            if let Some(credentials) = &tunnel_credentials {
                original_hop = Some(
                    original_hop
                        .take()
                        .ok_or(ConnectError::Configuration)?
                        .bind(
                            &admission,
                            &credentials.grant,
                            &bytes.client_certificate,
                            &credentials.relay_certificate,
                            &generation.keys,
                        )
                        .map_err(ConnectError::after_live_authorization)?,
                );
            }
            if let Some((control, _, _, _)) = tunnel.as_ref() {
                let request = tunnel_request
                    .as_ref()
                    .ok_or(ConnectError::LiveAuthorizationUnknown)?;
                let grant = client_grant
                    .as_ref()
                    .ok_or(ConnectError::LiveAuthorizationUnknown)?;
                tokio::select! {
                    result = control.relay_activate_client(request, &proof, grant, &cancel) => result.map_err(ConnectError::after_live_authorization)?,
                    _ = cancel.cancelled() => return Err(ConnectError::Canceled.after_live_authorization()),
                    _ = native_cancel.cancelled() => return Err(ConnectError::Carrier.after_live_authorization()),
                    _ = tokio::time::sleep_until(deadline) => return Err(ConnectError::Deadline.after_live_authorization()),
                };
            }
            bytes.activation = proof;
            provider
                .check()
                .map_err(ConnectError::after_live_authorization)?;
            (
                admission,
                bytes,
                generation.keys.clone(),
                generation.namespaces.clone(),
                tunnel_credentials,
                _storage,
                _registered_custody,
                None,
            )
        }
    };
    let from_pool = admission.source == codec::ActivationSource::PreauthorizedPool;
    let mut admission_started = false;
    let mut admission_confirmed = false;
    let mut ready_confirmed = false;
    let future = async {
        // Keep the acquired registered owner through native Session assembly.
        // Successful delivery has already transferred its Account custody.
        let _registered_custody = registered_custody;
        if let Some(publication) = server_allow_publication {
            publication
                .publish(environment.root(), &admission, &provider, deadline, &cancel)
                .await?;
        }
        if let Some(hop) = &mut original_hop {
            hop.authenticate(
                &mut admission,
                &provider,
                &mut incoming,
                &keys,
                deadline,
                &cancel,
            )
            .await?;
        }
        let _original_hop_credentials = tunnel_credentials;
        let artifact = decode(&bytes.artifact, "Artifact", 65536, Context::default())?;
        let nonce = artifact.b::<32>("Artifact", "session_nonce")?;
        let offered_features = crate::checkpoint_v4::application_features(artifact)?
            & provider.feature_mask_for(artifact)?;
        let hello = encode(11, |out| {
            for key in 0..11 {
                u(out, key);
                match key {
                    0 => t(out, "flowersec/4"),
                    1 => t(out, "4"),
                    2 => t(out, keys.profile()),
                    3 => b(out, &admission.artifact_digest),
                    4 => b(out, &admission.candidate_id),
                    5 => b(out, &admission.route_digest),
                    6 => b(out, &admission.attempt_id),
                    7 => b(out, &nonce),
                    8 => u(out, offered_features),
                    9 => u(out, 1 << binding_mode.wire()),
                    10 => b(out, &[]),
                    _ => unreachable!(),
                }
            }
        });
        decode(&hello, "ClientHello", 16384, Context::default())?;
        provider.send(envelope(1, &hello)).await?;
        let sh_wire = provider.receive_prepared(&mut incoming).await?;
        let server_hello = payload(&sh_wire, 1, 16384)?.to_vec();
        let sh = decode(&server_hello, "ServerHello", 16384, Context::default())?;
        let selected_features =
            offered_features & sh.u("ServerHello", "server_offered_features")?;
        if sh.u("ServerHello", "binding_mode")? != binding_mode.wire()
            || sh.u("ServerHello", "selected_features")? != selected_features
            || artifact.u("Artifact", "required_features")? & !selected_features != 0
            || sh.b::<32>("ServerHello", "server_nonce")? == [0; 32]
        {
            return Err(ConnectError::Protocol);
        }
        let ch = decode(&hello, "ClientHello", 16384, Context::default())?;
        for name in [
            "protocol_id",
            "profile_revision",
            "crypto_profile_id",
            "artifact_digest",
            "candidate_id",
            "route_digest",
            "attempt_id",
            "client_nonce",
        ] {
            same(ch, "ClientHello", name, sh, "ServerHello", name)?;
        }
        let transcript: [u8; 32] = Sha256::digest(domain(
            b"flowersec/v4/hello-transcript\0",
            &[&hello, &server_hello],
        )?)
        .into();
        let context = encode(13, |out| {
            for key in 0..13 {
                u(out, key);
                match key {
                    0 => t(out, "4"),
                    1 => t(out, keys.profile()),
                    2 => u(out, 0),
                    3 => u(out, u64::from(admission.tunnel.is_some())),
                    9 => u(out, selected_features),
                    4 => b(out, &admission.artifact_digest),
                    5 => b(out, &admission.route_digest),
                    6 => b(out, &admission.attempt_id),
                    7 => b(out, &nonce),
                    8 => b(out, &transcript),
                    10 => u(out, binding_mode.wire()),
                    11 => u(out, u64::from(binding_mode == BindingMode::DirectExporter)),
                    12 => b(out, exporter.as_ref().map_or(&[], |v| v.as_slice())),
                    _ => unreachable!(),
                }
            }
        });
        let digest = codec::digest(
            "transport_context_digest",
            decode(&context, "TransportContext", 4096, Context::default())?,
        )?;
        let mut admission_nonce = [0; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut admission_nonce)
            .map_err(|_| ConnectError::Protocol)?;
        let tenant = artifact.field("Artifact", "tenant_id")?.text()?;
        let issuer = artifact.b::<16>("Artifact", "issuer_key_id")?;
        let lease = artifact.b::<16>("Artifact", "lease_id")?;
        let fields = |out: &mut Vec<u8>| {
            for key in 0..15 {
                u(out, key);
                match key {
                    0 => b(out, &admission.artifact_digest),
                    1 => t(out, tenant),
                    2 => b(out, &issuer),
                    3 => b(out, &lease),
                    4 => b(out, &nonce),
                    5 => b(out, &admission.candidate_id),
                    6 => b(out, &admission.route_digest),
                    7 => b(out, &admission.attempt_id),
                    8 => b(out, &admission_nonce),
                    9 => b(out, &transcript),
                    10 => u(out, selected_features),
                    11 => u(out, binding_mode.wire()),
                    12 => b(out, &digest),
                    13 => b(out, &bytes.activation),
                    14 => b(out, &bytes.client_certificate),
                    _ => unreachable!(),
                }
            }
        };
        let unsigned = encode(15, fields);
        let signature = keys
            .inner
            .sign(&domain(b"flowersec/v4/fsb4/signature\0", &[&unsigned])?)?;
        let fsb = encode(16, |out| {
            fields(out);
            u(out, 15);
            b(out, &signature)
        });
        admission_started = true;
        provider.send(envelope(2, &fsb)).await?;
        let fsa_wire = provider.receive_prepared(&mut incoming).await?;
        let fsa = payload(&fsa_wire, 3, 16384)?;
        let application_binding = serve::ApplicationBinding {
            artifact: admission.artifact_digest,
            client_identity: admission.certificate_digests[0],
            server_identity: admission.certificate_digests[1],
            route: admission.route_digest,
            attempt: admission.attempt_id,
            candidate: admission.candidate_id,
        };
        let mut handshake = Handshake::new_reserved(
            admission,
            Role::Client,
            keys.inner.clone(),
            HandshakeInput {
                artifact: &bytes.artifact,
                client_hello: &hello,
                server_hello: &server_hello,
                transport_context: &context,
                fsb: &fsb,
                fsa,
            },
            Some(record_reservation),
        )
        .map_err(|error| identity_boundary_error(environment.root(), error))?;
        admission_confirmed = true;
        let mut noise = [0; 81];
        let size = handshake.write_noise(&mut noise)?;
        provider.send(envelope(4, &noise[..size])).await?;
        noise.zeroize();
        let response = provider.receive_prepared(&mut incoming).await?;
        handshake
            .read_noise(payload(&response, 4, 81)?)
            .map_err(|error| identity_boundary_error(environment.root(), error))?;
        let mut ready = ReadySubmission(None);
        handshake.submit_ready(&mut ready)?;
        let local_ready = ready.0.take().ok_or(ConnectError::Protocol)?;
        let records = handshake.prepare_session_records()?;
        let transport = provider.transport(keys, namespaces);
        let mut session =
            Session::adopt_paused(environment.root(), records, transport, Some(session_charge))
                .map_err(|_| ConnectError::Protocol)?;
        *physical_session = Some(session.clone());
        let mut prepared_guard = PreparedSessionGuard(Some(session.clone()));
        if let Some(application) = &application {
            session
                .attach_application(application.clone())
                .map_err(|_| ConnectError::Authorization)?;
            let cleanup = application
                .enter(CallbackKind::Cleanup)
                .map_err(|_| ConnectError::Authorization)?;
            let child = session.clone();
            let original_application = application.clone();
            // Install cleanup before any service graph or local READY. Every
            // pre-publication error retains this same physical cleanup owner.
            tokio::spawn(async move {
                let _cleanup = cleanup;
                child.wait_termination().await;
                original_application.close();
                loop {
                    let notified = original_application.changed().notified_owned();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if original_application.cleanup_status().pending_callbacks == 1 {
                        break;
                    }
                    notified.await;
                }
                let _ = original_application.release(true);
            });
        }
        if let Some((plan, _)) = &handler_plan {
            plan.bind(&session);
        }
        if let Some(prepared) = prepared_services {
            let services = prepared
                .install(&session)
                .map_err(|failure| match failure.code {
                    serve::ServeFailure::Capacity => ConnectError::Capacity,
                    serve::ServeFailure::Closed => ConnectError::Canceled,
                    _ => ConnectError::Authorization,
                })?;
            session = session.with_configured_services(services);
        }
        if let Some(prepared) = prepared_default_management {
            crate::ExecutionManagement::prepare_default(&session, prepared)
                .map_err(|_| ConnectError::Authorization)?;
        }
        if let Some(hook) = notification_hook.as_ref() {
            hook.candidate(session.clone());
        }
        provider.check()?;
        provider.send(envelope(5, &local_ready)).await?;
        let response = provider.receive_prepared(&mut incoming).await?;
        handshake
            .verify_ready(payload(&response, 5, 103)?)
            .map_err(|error| identity_boundary_error(environment.root(), error))?;
        handshake.confirm_prepared_ready()?;
        ready_confirmed = true;
        provider.check()?;
        provider.bind_receiver(session.receiver())?;
        provider.activate();
        session.activate_protocol();
        if session.termination_cause().is_some() {
            return Err(ConnectError::Protocol);
        }
        if let (Some((plan, _)), Some(application)) = (handler_plan, application) {
            plan.dispatch(session.clone(), application_binding, application);
        }
        let receiver = session.receiver();
        let receiver_tail = provider.receiver()?;
        let input_provider = provider.clone();
        tokio::spawn(async move {
            let _charge = received;
            let _tail = receiver_tail;
            let mut termination = Box::pin(receiver.wait_termination());
            loop {
                tokio::select! {
                    result = incoming.recv() => match result {
                        Some(wire) => {
                            match input_provider.receive_maintenance(&receiver, &wire) {
                                Ok(crate::crypto_v4::ReceiveDisposition::Applied
                                    | crate::crypto_v4::ReceiveDisposition::Isolated { .. }
                                    | crate::crypto_v4::ReceiveDisposition::Discarded { .. }) => {},
                                Err(cause) => {
                                    receiver.close_input(cause);
                                    break;
                                }
                            }
                        }
                        None => {
                            receiver.close_input(crate::SessionError::OperationFailed);
                            break;
                        }
                    },
                    _ = &mut termination => break,
                }
            }
        });
        prepared_guard.0 = None;
        Ok(session)
    };
    // The authenticated exchange carries the prepared service graph. Keep its
    // state out of the select frame so nested credential validation fits on
    // the caller's ordinary executor stack.
    let future = Box::pin(future);
    let result = tokio::select! {_ = cancel.cancelled()=>Err(ConnectError::Canceled), _ = tokio::time::sleep_until(deadline)=>Err(ConnectError::Deadline), result=future=>result};
    if result.is_ok() {
        guard.0 = None;
    }
    let source_profile = if from_pool {
        ConnectionSourceProfile::PreauthorizedPool
    } else {
        ConnectionSourceProfile::LiveAuthority
    };
    result.map_err(|error| {
        if ready_confirmed {
            error.after_ready(source_profile)
        } else if admission_confirmed {
            error.after_admission(source_profile)
        } else if admission_started {
            error.during_admission(source_profile)
        } else if from_pool {
            error.after_spend()
        } else {
            error.after_live_authorization()
        }
    })
}

#[cfg(test)]
#[path = "connect_v4_tests.rs"]
mod tests;
