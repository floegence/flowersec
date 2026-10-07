//! The authenticated fixed RPC bootstrap is shared by contract queries and
//! application methods. Registration, channel and result ownership stay finite.
use crate::{
    ApplicationInvocationContext,
    api_v4::CleanupStatus,
    application_executor_v4::{ApplicationGroup, ApplicationPosition, OrdinaryAdmission},
    codec_v4::{self as codec, Limits, Value},
    crypto_v4::Session,
    environment_v4::{ResourceAccount, ResourceCharge, ResourceLimits},
    execution_history::{ExecutionIdentity, ExecutionService},
    rpc_channel_v4::{
        ChannelLimits, IncomingMessage, PublicationFact, RPCChannel, ReplySlot, RequestInput,
    },
    rpc_wire_v4::{ApplicationHeader, HeaderScalar},
    service_contract::{
        AdmissionOffer, ServiceContract, ServiceError, ServiceFailure, ServiceSemantics,
        ServiceShape,
    },
};
use async_trait::async_trait;
use futures_util::FutureExt;
use std::{
    fmt,
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Notify, time::Instant};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, ServiceError>;
fn error(code: ServiceFailure) -> ServiceError {
    ServiceError(code)
}
fn parsed<T>(value: codec::Result<T>) -> Result<T> {
    value.map_err(|_| error(ServiceFailure::Protocol))
}
fn head(output: &mut Vec<u8>, major: u8, value: u64) {
    codec::encode_head(output, major, value);
}
fn data(output: &mut Vec<u8>, bytes: &[u8]) {
    head(output, 2, bytes.len() as u64);
    output.extend_from_slice(bytes);
}
fn text(output: &mut Vec<u8>, value: &str) {
    head(output, 3, value.len() as u64);
    output.extend_from_slice(value.as_bytes());
}

pub(crate) struct ContractQueryPreparation {
    charge: ResourceCharge,
    owner: ResourceCharge,
    rpc: crate::rpc_channel_v4::QuerySendPreparation,
    contracts: Vec<ResourceCharge>,
}
impl ContractQueryPreparation {
    fn new_prepaid(
        account: &ResourceAccount,
        count: usize,
        mut backing: ResourceCharge,
    ) -> Result<Self> {
        if !backing.matches(account, ServicePeer::query_preparation_limits(count)?) {
            return Err(error(ServiceFailure::ConfigurationCapacity));
        }
        let charge = backing.split(ServicePeer::query_storage_limits(count)?)?;
        let owner = backing
            .split(crate::application_executor_v4::ApplicationGroup::query_preparation_limits())?;
        let rpc = crate::rpc_channel_v4::QuerySendPreparation::new_prepaid(
            account,
            backing.split(crate::rpc_channel_v4::QuerySendPreparation::preparation_limits()?)?,
        )?;
        let mut contracts = Vec::with_capacity(count);
        for _ in 0..count {
            contracts.push(backing.split(ServiceContract::preparation_limits())?);
        }
        Ok(Self {
            charge,
            owner,
            rpc,
            contracts,
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedContractQuery {
    pub type_id: u32,
    pub contract_digest: [u8; 32],
}
#[derive(Clone, Debug)]
pub struct FixedResultRead {
    pub type_id: u32,
    pub contract_digest: [u8; 32],
    pub max_result_bytes: u32,
    pub grants: Vec<crate::ExecutionHistoryGrant>,
}
#[derive(Clone, Debug)]
pub struct ContractQueryTarget {
    pub namespace: String,
    pub type_id: u32,
    pub wanted_digest: Option<[u8; 32]>,
    pub known: Option<ServiceContract>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractAvailability {
    Available,
    Denied,
    Unavailable,
}
#[derive(Clone, Debug)]
pub struct ContractSnapshot {
    pub availability: ContractAvailability,
    pub contract: Option<ServiceContract>,
    pub offer: Option<AdmissionOffer>,
}
#[derive(Clone, Debug)]
pub struct UnaryRequestContext {
    pub invocation: ApplicationInvocationContext,
    pub cancellation: CancellationToken,
    pub execution_identity: Option<ExecutionIdentity>,
    pub execution: Option<crate::ExecutionInvocation>,
    pub(crate) publication: crate::ResponsePublication,
    pub(crate) maintenance: Option<crate::MaintenanceOwner>,
}
impl UnaryRequestContext {
    pub fn response_publication(&self) -> crate::ResponsePublication {
        self.publication.clone()
    }
    pub fn maintenance_owner(&self) -> Result<crate::MaintenanceOwner> {
        let owner = self
            .maintenance
            .clone()
            .ok_or_else(|| error(ServiceFailure::ServiceUnavailable))?;
        owner.check_available()?;
        Ok(owner)
    }
}
#[derive(Debug)]
pub struct UnaryResponse {
    pub payload: Vec<u8>,
    pub application_error_code: Option<u32>,
}
#[async_trait]
pub trait UnaryServiceHandler: fmt::Debug + Send + Sync + 'static {
    async fn authorize(&self, context: UnaryRequestContext) -> Result<()>;
    async fn handle(&self, context: UnaryRequestContext, request: &[u8]) -> Result<UnaryResponse>;
    fn application_bytes(&self) -> u64 {
        65536
    }
}
#[derive(Clone, Debug)]
pub struct UnaryServiceRegistration {
    pub contract: ServiceContract,
    pub offer: Option<AdmissionOffer>,
    pub offer_window_ms: Option<u64>,
    pub query_allowed: bool,
    pub resident: bool,
    pub handler: Arc<dyn UnaryServiceHandler>,
    pub execution: Option<ExecutionService>,
    /// Captured by the trusted authenticated Session assembly, never a payload.
    pub caller: Option<ExecutionIdentity>,
}
impl UnaryServiceRegistration {
    fn current_offer(&self, account: &ResourceAccount) -> Result<Option<AdmissionOffer>> {
        match self.offer_window_ms {
            Some(window) => {
                let now = account.security_time()?;
                Ok(Some(AdmissionOffer::current(
                    &self.contract,
                    now.lower_ms,
                    now.upper_ms,
                    window,
                )?))
            }
            None => Ok(self.offer.clone()),
        }
    }
}
pub(crate) struct ServicePeerPreparation {
    group: ApplicationGroup,
    charge: ResourceCharge,
    channel: crate::rpc_channel_v4::ChannelPreparation,
    stream: crate::crypto_v4::StreamPreparation,
    channels: crate::rpc_channel_v4::ChannelSetPreparation,
    tail: ResourceCharge,
}
pub(crate) struct PeerInner {
    pub(crate) session: crate::crypto_v4::SessionLink,
    pub(crate) account: ResourceAccount,
    pub(crate) group: ApplicationGroup,
    pub(crate) channel: Arc<RPCChannel>,
    maintenance: Option<crate::MaintenanceOwner>,
    query: FixedContractQuery,
    registrations: Arc<[UnaryServiceRegistration]>,
    result_read: Option<FixedResultRead>,
    catalogs_sealed: AtomicBool,
    cancellation: CancellationToken,
    pub(crate) closed: AtomicBool,
    lifetime: Arc<PeerLifetime>,
    catalog_gate: Mutex<()>,
    notification_catalog: Mutex<Option<NotificationCatalog>>,
    streaming_catalog: Mutex<Option<StreamingCatalog>>,
    resume_catalog: Mutex<Option<ResumeCatalog>>,
}
struct NotificationCatalog {
    registrations: Arc<[crate::NotificationServiceRegistration]>,
    closed: Arc<AtomicBool>,
    _charge: ResourceCharge,
}
struct StreamingCatalog {
    registrations: Arc<[crate::StreamingServiceRegistration]>,
    _memberships: Vec<crate::streaming_service_v4::StreamingMembership>,
    _charge: ResourceCharge,
}
struct ResumeCatalog {
    registrations: Arc<[crate::ResumeServiceRegistration]>,
    _memberships: Vec<crate::resume_service_v4::ResumeMembership>,
    _charge: ResourceCharge,
}
struct PeerLifetime {
    workers: AtomicUsize,
    changed: Notify,
    charge: Mutex<Option<ResourceCharge>>,
    tail: crate::application_tails_v4::ApplicationTail,
}
impl fmt::Debug for PeerInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServicePeer { <opaque> }")
    }
}
#[derive(Clone, Debug)]
pub struct ServicePeer(pub(crate) Arc<PeerInner>);
impl ServicePeer {
    /// Install the same Session's frozen notification advertisements in its
    /// original fixed contract query registry. It never registers RPC handlers.
    pub fn attach_notifications(&self, notifications: &crate::NotificationPeer) -> Result<()> {
        self.attach_notifications_prepared(notifications, None)
    }
    pub(crate) fn attach_notifications_prepared(
        &self,
        notifications: &crate::NotificationPeer,
        reserved: Option<ResourceCharge>,
    ) -> Result<()> {
        self.0.check()?;
        let _catalog_gate = self
            .0
            .catalog_gate
            .lock()
            .expect("service catalog installation");
        if self.0.catalogs_sealed.load(Ordering::Acquire) {
            return Err(error(ServiceFailure::Closed));
        }
        let registrations = notifications.catalog(&self.0.account)?;
        if registrations.iter().any(|entry| {
            entry.contract.type_id() == self.0.query.type_id
                || self
                    .0
                    .registrations
                    .iter()
                    .any(|unary| unary.contract.type_id() == entry.contract.type_id())
                || self
                    .0
                    .result_read
                    .as_ref()
                    .is_some_and(|read| read.type_id == entry.contract.type_id())
        }) {
            return Err(error(ServiceFailure::ContractMismatch));
        }
        {
            let streaming = self
                .0
                .streaming_catalog
                .lock()
                .expect("streaming contract catalog");
            if registrations.iter().any(|notification| {
                streaming.as_ref().is_some_and(|catalog| {
                    catalog.registrations.iter().any(|entry| {
                        entry.service.contract().type_id() == notification.contract.type_id()
                    })
                })
            }) {
                return Err(error(ServiceFailure::ContractMismatch));
            }
        }
        {
            let resume = self
                .0
                .resume_catalog
                .lock()
                .expect("Resume contract catalog");
            if registrations.iter().any(|entry| {
                resume.as_ref().is_some_and(|catalog| {
                    catalog.registrations.iter().any(|resume| {
                        resume.service.contract().type_id() == entry.contract.type_id()
                    })
                })
            }) {
                return Err(error(ServiceFailure::ContractMismatch));
            }
        }
        let bytes = registrations.iter().try_fold(8192u64, |total, entry| {
            total
                .checked_add(
                    4096 + entry
                        .handler
                        .as_ref()
                        .map_or(0, |handler| handler.application_bytes()),
                )
                .ok_or_else(|| error(ServiceFailure::ConfigurationCapacity))
        })?;
        let charge = match reserved {
            Some(charge) => charge,
            None => self.0.account.reserve(ResourceLimits {
                sdk_bytes: bytes,
                items: registrations.len() as u64 + 1,
                ..ResourceLimits::default()
            })?,
        };
        let mut prepared = Some(NotificationCatalog {
            registrations,
            closed: notifications.publication_gate(),
            _charge: charge,
        });
        self.0.account.with_security(|| {
            let mut catalog = self
                .0
                .notification_catalog
                .lock()
                .expect("notification contract catalog");
            if self.0.closed.load(Ordering::Acquire) || catalog.is_some() {
                return Err(error(ServiceFailure::ContractMismatch));
            }
            *catalog = prepared.take();
            Ok(())
        })??;
        drop(prepared);
        Ok(())
    }
    /// Publish the same frozen business Stream declarations in this Session's
    /// original contract query registry and exact authenticated membership.
    pub fn attach_streaming(
        &self,
        registrations: Vec<crate::StreamingServiceRegistration>,
    ) -> Result<()> {
        self.attach_streaming_prepared(registrations, None)
    }
    pub(crate) fn attach_streaming_prepared(
        &self,
        registrations: Vec<crate::StreamingServiceRegistration>,
        reserved: Option<(
            ResourceCharge,
            Vec<crate::streaming_service_v4::StreamingMembership>,
        )>,
    ) -> Result<()> {
        self.0.check()?;
        let _catalog_gate = self
            .0
            .catalog_gate
            .lock()
            .expect("service catalog installation");
        if self.0.catalogs_sealed.load(Ordering::Acquire) {
            return Err(error(ServiceFailure::Closed));
        }
        if registrations.len() > 128
            || registrations.iter().enumerate().any(|(index, entry)| {
                let type_id = entry.service.contract().type_id();
                type_id == self.0.query.type_id
                    || self
                        .0
                        .registrations
                        .iter()
                        .any(|unary| unary.contract.type_id() == type_id)
                    || self
                        .0
                        .result_read
                        .as_ref()
                        .is_some_and(|read| read.type_id == type_id)
                    || registrations[..index]
                        .iter()
                        .any(|old| old.service.contract().type_id() == type_id)
            })
        {
            return Err(error(ServiceFailure::ContractMismatch));
        }
        {
            let notifications = self
                .0
                .notification_catalog
                .lock()
                .expect("notification contract catalog");
            if registrations.iter().any(|entry| {
                notifications.as_ref().is_some_and(|catalog| {
                    catalog.registrations.iter().any(|notification| {
                        notification.contract.type_id() == entry.service.contract().type_id()
                    })
                })
            }) {
                return Err(error(ServiceFailure::ContractMismatch));
            }
        }
        {
            let resume = self
                .0
                .resume_catalog
                .lock()
                .expect("Resume contract catalog");
            if registrations.iter().any(|entry| {
                resume.as_ref().is_some_and(|catalog| {
                    catalog.registrations.iter().any(|resume| {
                        resume.service.contract().type_id() == entry.service.contract().type_id()
                    })
                })
            }) {
                return Err(error(ServiceFailure::ContractMismatch));
            }
        }
        let (charge, memberships) = match reserved {
            Some((charge, memberships)) => {
                if memberships.len() != registrations.len() {
                    return Err(error(ServiceFailure::ConfigurationCapacity));
                }
                for membership in &memberships {
                    membership.install(self)?;
                }
                (charge, memberships)
            }
            None => {
                let charge = self.0.account.reserve(ResourceLimits {
                    sdk_bytes: 8192 + registrations.len() as u64 * 4096,
                    items: registrations.len() as u64 + 1,
                    ..ResourceLimits::default()
                })?;
                let mut memberships = Vec::with_capacity(registrations.len());
                for registration in &registrations {
                    memberships.push(
                        registration
                            .service
                            .bind(self, registration.caller.clone())?,
                    );
                }
                (charge, memberships)
            }
        };
        let mut prepared = Some(StreamingCatalog {
            registrations: registrations.into(),
            _memberships: memberships,
            _charge: charge,
        });
        self.0.account.with_security(|| {
            let mut catalog = self
                .0
                .streaming_catalog
                .lock()
                .expect("streaming contract catalog");
            if self.0.closed.load(Ordering::Acquire) || catalog.is_some() {
                return Err(error(ServiceFailure::Closed));
            }
            *catalog = prepared.take();
            Ok(())
        })??;
        drop(prepared);
        Ok(())
    }
    /// Register Resume advertisements and authenticated membership on the same
    /// pre-READY fixed query owner as the original durable methods.
    pub fn attach_resume(
        &self,
        registrations: Vec<crate::ResumeServiceRegistration>,
    ) -> Result<()> {
        self.attach_resume_prepared(registrations, None)
    }
    pub(crate) fn attach_resume_prepared(
        &self,
        registrations: Vec<crate::ResumeServiceRegistration>,
        reserved: Option<(
            ResourceCharge,
            Vec<crate::resume_service_v4::ResumeMembership>,
        )>,
    ) -> Result<()> {
        self.0.check()?;
        let _catalog_gate = self
            .0
            .catalog_gate
            .lock()
            .expect("service catalog installation");
        if self.0.catalogs_sealed.load(Ordering::Acquire) {
            return Err(error(ServiceFailure::Closed));
        }
        if registrations.len() > 128 {
            return Err(error(ServiceFailure::ConfigurationCapacity));
        }
        {
            let streaming = self
                .0
                .streaming_catalog
                .lock()
                .expect("streaming contract catalog");
            let notifications = self
                .0
                .notification_catalog
                .lock()
                .expect("notification contract catalog");
            for (index, entry) in registrations.iter().enumerate() {
                let contract = entry.service.contract();
                let original = entry.service.original_contract();
                let type_id = contract.type_id();
                if type_id == self.0.query.type_id
                    || self
                        .0
                        .registrations
                        .iter()
                        .any(|entry| entry.contract.type_id() == type_id)
                    || self
                        .0
                        .result_read
                        .as_ref()
                        .is_some_and(|read| read.type_id == type_id)
                    || registrations[..index]
                        .iter()
                        .any(|old| old.service.contract().type_id() == type_id)
                    || streaming.as_ref().is_some_and(|catalog| {
                        catalog
                            .registrations
                            .iter()
                            .any(|entry| entry.service.contract().type_id() == type_id)
                    })
                    || notifications.as_ref().is_some_and(|catalog| {
                        catalog
                            .registrations
                            .iter()
                            .any(|entry| entry.contract.type_id() == type_id)
                    })
                {
                    return Err(error(ServiceFailure::ContractMismatch));
                }
                let execution = match original.shape() {
                    ServiceShape::Unary => self
                        .0
                        .registrations
                        .iter()
                        .find(|entry| entry.contract.digest() == original.digest())
                        .and_then(|entry| entry.execution.as_ref()),
                    ServiceShape::ServerStreaming => streaming
                        .as_ref()
                        .and_then(|catalog| {
                            catalog.registrations.iter().find(|entry| {
                                entry.service.contract().digest() == original.digest()
                            })
                        })
                        .and_then(|entry| entry.service.execution_service()),
                    _ => None,
                };
                if execution.is_none_or(|execution| {
                    !Arc::ptr_eq(&execution.0, &entry.service.execution().0)
                }) {
                    return Err(error(ServiceFailure::ContractMismatch));
                }
            }
        }
        let (charge, memberships) = match reserved {
            Some((charge, memberships)) => {
                if memberships.len() != registrations.len() {
                    return Err(error(ServiceFailure::ConfigurationCapacity));
                }
                for membership in &memberships {
                    membership.install(self)?;
                }
                (charge, memberships)
            }
            None => {
                let charge = self.0.account.reserve(ResourceLimits {
                    sdk_bytes: 8192 + registrations.len() as u64 * 4096,
                    items: registrations.len() as u64 + 1,
                    ..ResourceLimits::default()
                })?;
                let mut memberships = Vec::with_capacity(registrations.len());
                for entry in &registrations {
                    memberships.push(entry.service.bind(self, entry.caller.clone())?);
                }
                (charge, memberships)
            }
        };
        let mut prepared = Some(ResumeCatalog {
            registrations: registrations.into(),
            _memberships: memberships,
            _charge: charge,
        });
        self.0.account.with_security(|| {
            let mut catalog = self
                .0
                .resume_catalog
                .lock()
                .expect("Resume contract catalog");
            if self.0.closed.load(Ordering::Acquire) || catalog.is_some() {
                return Err(error(ServiceFailure::Closed));
            }
            *catalog = prepared.take();
            Ok(())
        })??;
        drop(prepared);
        Ok(())
    }
    pub(crate) fn create(
        session: &Session,
        query: FixedContractQuery,
        registrations: Vec<UnaryServiceRegistration>,
    ) -> Result<Self> {
        Self::create_with_result_read(session, query, registrations, None)
    }
    pub(crate) fn create_with_result_read(
        session: &Session,
        query: FixedContractQuery,
        registrations: Vec<UnaryServiceRegistration>,
        result_read: Option<FixedResultRead>,
    ) -> Result<Self> {
        let (_, profile, identity) = session
            .service_identity()
            .map_err(|_| error(ServiceFailure::PermissionDenied))?;
        let prepared = Self::prepare_installation(
            &session.application_account(),
            profile,
            identity,
            query,
            &registrations,
            result_read.as_ref(),
        )?;
        Self::create_prepared(session, query, registrations, result_read, prepared)
    }
    pub(crate) fn validate_installation(
        account: &ResourceAccount,
        profile: u8,
        authenticated_identity: [u8; 32],
        query: FixedContractQuery,
        registrations: &[UnaryServiceRegistration],
        result_read: Option<&FixedResultRead>,
    ) -> Result<()> {
        if query.type_id == 0 || query.contract_digest == [0; 32] || registrations.len() > 256 {
            return Err(error(ServiceFailure::ConfigurationCapacity));
        }
        if let Some(read) = &result_read {
            if profile != 2 {
                return Err(error(ServiceFailure::PermissionDenied));
            }
            if read.type_id == 0
                || read.type_id == query.type_id
                || read.contract_digest == [0; 32]
                || read.max_result_bytes == 0
                || read.max_result_bytes > 1 << 20
                || read.grants.len() > 128
            {
                return Err(error(ServiceFailure::ConfigurationCapacity));
            }
            for grant in &read.grants {
                grant.validate_binding(account, profile, authenticated_identity)?;
            }
        }
        for (index, registration) in registrations.iter().enumerate() {
            registration
                .contract
                .check_environment(account.environment_root())?;
            if profile == 0
                || registration.contract.semantics() == ServiceSemantics::Execution && profile != 2
                || registration.contract.shape() != ServiceShape::Unary
                || registration.contract.type_id() == query.type_id
                || result_read
                    .as_ref()
                    .is_some_and(|read| read.type_id == registration.contract.type_id())
                || registration
                    .caller
                    .as_ref()
                    .is_some_and(|caller| caller.identity_digest != authenticated_identity)
                || registration.contract.field(20).is_some()
                    && registration
                        .execution
                        .as_ref()
                        .is_none_or(|service| !service.recovery_configured())
                || registration.handler.application_bytes() == 0
                || registration.handler.application_bytes() > 1 << 30
                || registration.offer_window_ms.is_some_and(|window| {
                    window == 0
                        || registration
                            .contract
                            .uint(16)
                            .map_or(true, |maximum| window > maximum)
                })
                || registrations[..index]
                    .iter()
                    .any(|old| old.contract.type_id() == registration.contract.type_id())
                || (registration.contract.semantics() == ServiceSemantics::Execution)
                    != (registration.execution.is_some()
                        && registration.caller.is_some()
                        && (registration.offer.is_some() || registration.offer_window_ms.is_some()))
            {
                return Err(error(ServiceFailure::ConfigurationCapacity));
            }
        }
        Ok(())
    }
    pub(crate) fn prepare_installation(
        account: &ResourceAccount,
        profile: u8,
        identity: [u8; 32],
        query: FixedContractQuery,
        registrations: &[UnaryServiceRegistration],
        result_read: Option<&FixedResultRead>,
    ) -> Result<ServicePeerPreparation> {
        let charge =
            account.reserve(Self::preparation_limits(registrations.len(), result_read)?)?;
        Self::prepare_installation_prepaid(
            account,
            profile,
            identity,
            query,
            registrations,
            result_read,
            charge,
        )
    }
    pub(crate) fn preparation_limits(
        count: usize,
        result_read: Option<&FixedResultRead>,
    ) -> Result<ResourceLimits> {
        let limits = crate::crypto_v4::connect::candidate_add_limits(
            ResourceLimits {
                sdk_bytes: 131072 + count as u64 * 1024,
                items: count as u64 + 8,
                tasks: 1,
                work_slots: 1,
                ..ResourceLimits::default()
            },
            crate::rpc_channel_v4::ChannelPreparation::preparation_limits(ChannelLimits {
                max_messages: 128,
                max_payload_bytes: 1 << 20,
                result_read_bytes: result_read.map_or(0, |read| read.max_result_bytes as usize),
            })?,
        )?;
        let limits = crate::crypto_v4::connect::candidate_add_limits(
            limits,
            crate::crypto_v4::StreamPreparation::preparation_limits(),
        )?;
        let limits = crate::crypto_v4::connect::candidate_add_limits(
            limits,
            crate::rpc_channel_v4::ChannelSetPreparation::limits(ChannelLimits {
                max_messages: 128,
                max_payload_bytes: 1 << 20,
                result_read_bytes: result_read.map_or(0, |read| read.max_result_bytes as usize),
            })?,
        )?;
        let limits = crate::crypto_v4::connect::candidate_add_limits(
            limits,
            ApplicationGroup::preparation_limits(),
        )?;
        Ok(crate::crypto_v4::connect::candidate_add_limits(
            limits,
            crate::application_tails_v4::ApplicationTails::resources(),
        )?)
    }
    pub(crate) fn prepare_installation_prepaid(
        account: &ResourceAccount,
        profile: u8,
        identity: [u8; 32],
        query: FixedContractQuery,
        registrations: &[UnaryServiceRegistration],
        result_read: Option<&FixedResultRead>,
        mut backing: ResourceCharge,
    ) -> Result<ServicePeerPreparation> {
        Self::validate_installation(
            account,
            profile,
            identity,
            query,
            registrations,
            result_read,
        )?;
        if !backing.matches(
            account,
            Self::preparation_limits(registrations.len(), result_read)?,
        ) {
            return Err(error(ServiceFailure::ConfigurationCapacity));
        }
        let charge = backing.split(ResourceLimits {
            sdk_bytes: 131072 + registrations.len() as u64 * 1024,
            items: registrations.len() as u64 + 8,
            tasks: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let channel_limits = ChannelLimits {
            max_messages: 128,
            max_payload_bytes: 1 << 20,
            result_read_bytes: result_read.map_or(0, |read| read.max_result_bytes as usize),
        };
        let channel_charge = backing.split(
            crate::rpc_channel_v4::ChannelPreparation::preparation_limits(channel_limits)?,
        )?;
        let stream_charge =
            backing.split(crate::crypto_v4::StreamPreparation::preparation_limits())?;
        let channels = crate::rpc_channel_v4::ChannelSetPreparation::new(
            account,
            channel_limits,
            backing.split(crate::rpc_channel_v4::ChannelSetPreparation::limits(
                channel_limits,
            )?)?,
        )?;
        let group_charge = backing.split(ApplicationGroup::preparation_limits())?;
        Ok(ServicePeerPreparation {
            group: account.application_group_prepaid(group_charge)?,
            charge,
            channel: crate::rpc_channel_v4::ChannelPreparation::new_prepaid(
                account,
                channel_limits,
                channel_charge,
            )?,
            stream: crate::crypto_v4::StreamPreparation::new_prepaid(
                account.clone(),
                stream_charge,
            )
            .map_err(|_| error(ServiceFailure::ResourceExhausted))?,
            channels,
            tail: backing,
        })
    }
    pub fn maintenance_owner(&self) -> Result<crate::MaintenanceOwner> {
        let owner = self
            .0
            .maintenance
            .clone()
            .ok_or_else(|| error(ServiceFailure::ServiceUnavailable))?;
        owner.check_root(self.0.account.environment_root())?;
        Ok(owner)
    }
    pub(crate) fn create_prepared(
        session: &Session,
        query: FixedContractQuery,
        registrations: Vec<UnaryServiceRegistration>,
        result_read: Option<FixedResultRead>,
        prepared: ServicePeerPreparation,
    ) -> Result<Self> {
        let account = session.application_account();
        let (_, profile, identity) = session
            .service_identity()
            .map_err(|_| error(ServiceFailure::PermissionDenied))?;
        Self::validate_installation(
            &account,
            profile,
            identity,
            query,
            &registrations,
            result_read.as_ref(),
        )?;
        let maintenance = session.maintenance_owner().ok();
        if registrations
            .iter()
            .any(|entry| entry.contract.bool(21).unwrap_or(false))
            && maintenance.is_none()
        {
            return Err(error(ServiceFailure::ConfigurationCapacity));
        }
        let ServicePeerPreparation {
            group,
            charge,
            channel: channel_prepared,
            stream: stream_prepared,
            channels,
            tail: tail_charge,
        } = prepared;
        let tail = session
            .application_tail_reserved(tail_charge)
            .map_err(|_| error(ServiceFailure::Closed))?;
        let cancellation = tail.cancellation();
        let stream = session
            .claim_rpc_bootstrap_prepared(stream_prepared)
            .map_err(|_| error(ServiceFailure::ServiceUnavailable))?;
        let bootstrap_backing = channel_prepared.clone();
        let (channel, mut incoming) = RPCChannel::new_prepared(
            Arc::new(stream),
            account.clone(),
            ChannelLimits {
                max_messages: 128,
                max_payload_bytes: 1 << 20,
                result_read_bytes: result_read
                    .as_ref()
                    .map_or(0, |read| read.max_result_bytes as usize),
            },
            channel_prepared,
        )?;
        channel.install_channels(session, channels, bootstrap_backing)?;
        let peer = Self(Arc::new(PeerInner {
            session: session.link(),
            account,
            group,
            channel,
            query,
            maintenance,
            registrations: registrations.into(),
            result_read,
            catalogs_sealed: AtomicBool::new(false),
            catalog_gate: Mutex::new(()),
            notification_catalog: Mutex::new(None),
            streaming_catalog: Mutex::new(None),
            resume_catalog: Mutex::new(None),
            cancellation,
            closed: AtomicBool::new(false),
            lifetime: Arc::new(PeerLifetime {
                workers: AtomicUsize::new(1),
                changed: Notify::new(),
                charge: Mutex::new(Some(charge)),
                tail,
            }),
        }));
        let owner = peer.0.clone();
        tokio::spawn(async move {
            loop {
                let message = tokio::select! {
                    _ = owner.cancellation.cancelled() => break,
                    input = incoming.recv() => match input { Some(input) => input, None => break },
                };
                if !message.admitted {
                    let _ = owner.refuse(
                        message.into_request().reply,
                        error(ServiceFailure::ServiceUnavailable),
                    );
                    continue;
                }
                if message.header.kind() == "query_contracts_request" {
                    let position = match owner.group.contract_query() {
                        Ok(position) => position,
                        Err(error) => {
                            let _ = owner.refuse(message.into_request().reply, error.into());
                            continue;
                        }
                    };
                    owner.lifetime.workers.fetch_add(1, Ordering::AcqRel);
                    let current = owner.clone();
                    tokio::spawn(async move {
                        let _worker = PeerWorker(current.lifetime.clone());
                        let invocation = match position.enter().await {
                            Ok(invocation) => invocation,
                            Err(failure) => {
                                let _ =
                                    current.refuse(message.into_request().reply, failure.into());
                                return;
                            }
                        };
                        current
                            .query_response(message.into_request(), invocation)
                            .await;
                    });
                } else if message.header.kind() == "read_result_request" {
                    let _ = owner.dispatch_result_read(message);
                } else {
                    if owner.dispatch_unary(message).is_err()
                        && owner.closed.load(Ordering::Acquire)
                    {
                        break;
                    }
                }
            }
            owner.closed.store(true, Ordering::Release);
            owner.cancellation.cancel();
            owner.close_streaming();
            owner.group.close();
            owner.channel.close();
            drop(PeerWorker(owner.lifetime.clone()));
        });
        Ok(peer)
    }
    /// Read a retained unary result through the ordinary RPC channel. The
    /// fixed binding is installed locally and never supplied by the reference.
    pub async fn read_result(
        &self,
        reference: &crate::OperationReference,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<bytes::Bytes> {
        let diagnostics = self
            .0
            .account
            .diagnostic_activity(crate::DiagnosticPhase::Application, 1);
        let outcome = async {
        self.0.check()?;
        if reference.shape() != ServiceShape::Unary
            || timeout.is_zero()
            || timeout > Duration::from_secs(30)
        {
            return Err(error(ServiceFailure::ConfigurationCapacity));
        }
        let binding = self
            .0
            .result_read
            .as_ref()
            .ok_or_else(|| error(ServiceFailure::ServiceUnavailable))?;
        let result_account = self.0.account.reserve_result()?;
        let charge = result_account.reserve(ResourceLimits {
            sdk_bytes: binding.max_result_bytes as u64 + 8192,
            items: 2,
            tasks: 1,
            ..ResourceLimits::default()
        })?;
        let now = self.0.account.security_time()?;
        let cap = now
            .lower_ms
            .checked_add(timeout.as_millis() as u64)
            .ok_or_else(|| error(ServiceFailure::DeadlineExceeded))?;
        if cap <= now.upper_ms {
            return Err(error(ServiceFailure::DeadlineExceeded));
        }
        let deadline = Instant::now() + timeout;
        let mut payload = Zeroizing::new(Vec::with_capacity(1024));
        crate::operation_reference_v4::encode_target(&mut payload, &reference.target());
        let mut fields = [None; 11];
        fields[2] = Some(HeaderScalar::Uint(binding.type_id as u64));
        fields[3] = Some(HeaderScalar::Uint(payload.len() as u64));
        fields[5] = Some(HeaderScalar::Uint(cap));
        fields[6] = Some(HeaderScalar::Bytes(binding.contract_digest));
        let header = ApplicationHeader::create("read_result_request", fields)?;
        let account = self.0.account.clone();
        let original = cancellation.child_token();
        let delivery = original.clone();
        let publication_diagnostics = diagnostics.clone();
        let published = self.0.channel.send(
            header,
            &payload,
            0,
            original.clone(),
            Arc::new(move || {
                let _original_diagnostics = &publication_diagnostics;
                account.check()?;
                if delivery.is_cancelled() {
                    return Err(error(ServiceFailure::Canceled));
                }
                if account.security_time()?.upper_ms >= cap {
                    return Err(error(ServiceFailure::DeadlineExceeded));
                }
                Ok(())
            }),
        )?;
        let observer = ResultReadWait(original);
        let receipt = tokio::select! {
            receipt = published.publication => receipt.map_err(|_| error(ServiceFailure::ServiceUnavailable))?,
            _ = cancellation.cancelled() => return Err(error(ServiceFailure::Canceled)),
            _ = tokio::time::sleep_until(deadline) => return Err(error(ServiceFailure::DeadlineExceeded)),
        };
        if receipt.fact != PublicationFact::Committed {
            return Err(error(
                receipt.error.unwrap_or(ServiceFailure::ServiceUnavailable),
            ));
        }
        let mut response = published
            .response
            .ok_or_else(|| error(ServiceFailure::Protocol))?;
        let response = tokio::select! { response = &mut response => response.map_err(|_| error(ServiceFailure::ServiceUnavailable))?,
        _ = cancellation.cancelled() => Err(error(ServiceFailure::Canceled)),
        _ = tokio::time::sleep_until(deadline) => Err(error(ServiceFailure::DeadlineExceeded)) };
        let response = match response {
            Ok(response) => response,
            Err(failure) => {
                if let Ok(stop) = self.0.channel.abandon(&published.origin, published.serial) {
                    let _ = stop.await;
                }
                return Err(failure);
            }
        };
        if response.aborted || response.completed_at_upper_ms >= cap {
            return Err(error(ServiceFailure::DeadlineExceeded));
        }
        if response.header.sdk_error() {
            return Err(ServiceError::from_sdk_payload(&response.payload)?);
        }
        if response.header.kind() != "read_result_response"
            || response.payload.len() > binding.max_result_bytes as usize
        {
            return Err(error(ServiceFailure::Protocol));
        }
        result_account.with_security(|| {
            if cancellation.is_cancelled() {
                Err(error(ServiceFailure::Canceled))
            } else {
                Ok(())
            }
        })??;
        result_account.detach_result();
        drop(observer);
        Ok(bytes::Bytes::from_owner(RetainedResultPayload {
            bytes: response.payload,
            _charge: charge,
        }))
        }.await;
        diagnostics.service_outcome(&outcome);
        outcome
    }
    pub(crate) fn seal_catalogs(&self) {
        let _gate = self
            .0
            .catalog_gate
            .lock()
            .expect("service catalog installation");
        self.0.catalogs_sealed.store(true, Ordering::Release);
    }
    pub fn close(&self) {
        self.0.closed.store(true, Ordering::Release);
        self.0.cancellation.cancel();
        self.0.close_streaming();
        self.0.group.close();
        self.0.channel.close();
        self.0.lifetime.changed.notify_waiters();
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let channel = self.0.channel.cleanup_status();
        let workers = self.0.lifetime.workers.load(Ordering::Acquire);
        CleanupStatus {
            complete: channel.complete && workers == 0,
            cleanup_incomplete: !channel.complete || workers != 0,
            pending_callbacks: workers as u64,
        }
    }
    pub async fn wait_cleanup(&self) -> CleanupStatus {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let changed = self.0.lifetime.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return status;
            }
            tokio::select! { _ = changed => {}, _ = self.0.channel.wait_cleanup() => {},
            _ = tokio::time::sleep_until(deadline) => return self.cleanup_status() }
        }
    }
    pub(crate) fn uses_query(&self, query: FixedContractQuery) -> bool {
        self.0.query == query
    }
    fn query_storage_limits(target_count: usize) -> Result<ResourceLimits> {
        if target_count == 0 || target_count > 8 {
            return Err(error(ServiceFailure::ConfigurationCapacity));
        }
        Ok(ResourceLimits {
            sdk_bytes: 8192 + target_count as u64 * 9216,
            items: target_count as u64 + 2,
            tasks: 1,
            timers: 1,
            ..ResourceLimits::default()
        })
    }
    pub(crate) fn query_preparation_limits(target_count: usize) -> Result<ResourceLimits> {
        let limits = crate::crypto_v4::connect::candidate_add_limits(
            Self::query_storage_limits(target_count)?,
            crate::rpc_channel_v4::QuerySendPreparation::preparation_limits()?,
        )?;
        let mut limits = crate::crypto_v4::connect::candidate_add_limits(
            limits,
            ApplicationGroup::query_preparation_limits(),
        )?;
        for _ in 0..target_count {
            limits = crate::crypto_v4::connect::candidate_add_limits(
                limits,
                ServiceContract::preparation_limits(),
            )?;
        }
        Ok(limits)
    }
    pub async fn query_contracts(
        &self,
        targets: &[ContractQueryTarget],
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<Vec<ContractSnapshot>> {
        self.query_contracts_with_backing(targets, timeout, cancellation, None)
            .await
    }
    pub(crate) async fn query_contracts_prepaid(
        &self,
        targets: &[ContractQueryTarget],
        timeout: Duration,
        cancellation: CancellationToken,
        charge: ResourceCharge,
    ) -> Result<Vec<ContractSnapshot>> {
        self.query_contracts_with_backing(targets, timeout, cancellation, Some(charge))
            .await
    }
    async fn query_contracts_with_backing(
        &self,
        targets: &[ContractQueryTarget],
        timeout: Duration,
        cancellation: CancellationToken,
        prepaid: Option<ResourceCharge>,
    ) -> Result<Vec<ContractSnapshot>> {
        let diagnostics = self
            .0
            .account
            .diagnostic_activity(crate::DiagnosticPhase::Application, 1);
        let outcome = async {
        let limits = Self::query_storage_limits(targets.len())?;
        if timeout.is_zero() || timeout > Duration::from_secs(90) {
            return Err(error(ServiceFailure::ConfigurationCapacity));
        }
        self.0.check()?;
        let (_owner, _charge, rpc_prepaid, contract_prepaid) = if let Some(charge) = prepaid {
            let prepared =
                ContractQueryPreparation::new_prepaid(&self.0.account, targets.len(), charge)?;
            (
                self.0.group.query_owner_prepaid(prepared.owner)?,
                prepared.charge,
                Some(prepared.rpc),
                Some(prepared.contracts),
            )
        } else {
            (
                self.0.group.query_owner()?,
                self.0.account.reserve(limits)?,
                None,
                None,
            )
        };
        let mut payload = Vec::with_capacity(2048);
        head(&mut payload, 5, 1);
        head(&mut payload, 0, 0);
        head(&mut payload, 4, targets.len() as u64);
        for (index, target) in targets.iter().enumerate() {
            if target.type_id == 0
                || targets[..index]
                    .iter()
                    .any(|old| old.namespace == target.namespace && old.type_id == target.type_id)
            {
                return Err(error(ServiceFailure::ConfigurationCapacity));
            }
            if let Some(known) = &target.known {
                known.check_environment(self.0.account.environment_root())?;
                if known.namespace() != target.namespace
                    || known.type_id() != target.type_id
                    || target
                        .wanted_digest
                        .is_some_and(|wanted| wanted != known.digest())
                {
                    return Err(error(ServiceFailure::ContractMismatch));
                }
            }
            head(
                &mut payload,
                5,
                2 + u64::from(target.wanted_digest.is_some()) + u64::from(target.known.is_some()),
            );
            head(&mut payload, 0, 0);
            text(&mut payload, &target.namespace);
            head(&mut payload, 0, 1);
            head(&mut payload, 0, u64::from(target.type_id));
            if let Some(wanted) = target.wanted_digest {
                head(&mut payload, 0, 2);
                data(&mut payload, &wanted);
            }
            if let Some(known) = &target.known {
                head(&mut payload, 0, 3);
                data(&mut payload, &known.digest());
            }
        }
        parsed(codec::decode(
            &payload,
            "ContractTargets",
            Limits {
                bytes: 2048,
                nodes: 96,
            },
            None,
        ))?;
        let now = self.0.account.security_time()?;
        let cap = now
            .lower_ms
            .checked_add(timeout.as_millis() as u64)
            .ok_or_else(|| error(ServiceFailure::DeadlineExceeded))?;
        if cap <= now.upper_ms {
            return Err(error(ServiceFailure::DeadlineExceeded));
        }
        let deadline = Instant::now() + Duration::from_millis(cap - now.upper_ms);
        let mut fields = [None; 11];
        fields[2] = Some(HeaderScalar::Uint(u64::from(self.0.query.type_id)));
        fields[3] = Some(HeaderScalar::Uint(payload.len() as u64));
        fields[5] = Some(HeaderScalar::Uint(cap));
        fields[6] = Some(HeaderScalar::Bytes(self.0.query.contract_digest));
        let account = self.0.account.clone();
        let channel_cancellation = cancellation.child_token();
        let guard_cancellation = channel_cancellation.clone();
        let header = ApplicationHeader::create("query_contracts_request", fields)?;
        let publication_diagnostics = diagnostics.clone();
        let guard: Arc<dyn Fn() -> Result<()> + Send + Sync> = Arc::new(move || {
            let _original_diagnostics = &publication_diagnostics;
            account.check()?;
            if guard_cancellation.is_cancelled() {
                return Err(error(ServiceFailure::Canceled));
            }
            if Instant::now() >= deadline {
                Err(error(ServiceFailure::DeadlineExceeded))
            } else {
                Ok(())
            }
        });
        let published = if let Some(prepared) = rpc_prepaid {
            self.0.channel.send_query_prepaid(
                header,
                &payload,
                channel_cancellation.clone(),
                guard,
                prepared,
            )?
        } else {
            self.0
                .channel
                .send(header, &payload, 0, channel_cancellation.clone(), guard)?
        };
        let mut publication = published.publication;
        let mut canceled = None;
        let receipt = tokio::select! {
            receipt = &mut publication => receipt,
            _ = cancellation.cancelled() => { canceled = Some(error(ServiceFailure::Canceled)); channel_cancellation.cancel(); publication.await },
            _ = tokio::time::sleep_until(deadline) => { canceled = Some(error(ServiceFailure::DeadlineExceeded)); channel_cancellation.cancel(); publication.await },
        }.map_err(|_| error(ServiceFailure::Closed))?;
        if let Some(failure) = canceled {
            if receipt.fact == PublicationFact::Committed
                && let Ok(stop) = self.0.channel.abandon(&published.origin, published.serial) {
                    let _ = stop.await;
                }
            return Err(failure);
        }
        if receipt.fact != PublicationFact::Committed {
            return Err(error(
                receipt.error.unwrap_or(ServiceFailure::ServiceUnavailable),
            ));
        }
        let response = published
            .response
            .ok_or_else(|| error(ServiceFailure::Protocol))?;
        let response = tokio::select! {
            biased;
            response = response => response.map_err(|_| error(ServiceFailure::Closed))?,
            _ = cancellation.cancelled() => Err(error(ServiceFailure::Canceled)),
            _ = tokio::time::sleep_until(deadline) => Err(error(ServiceFailure::DeadlineExceeded)),
        };
        let response = match response {
            Ok(response) => response,
            Err(failure) => {
                if let Ok(stop) = self.0.channel.abandon(&published.origin, published.serial) {
                    let _ = stop.await;
                }
                return Err(failure);
            }
        };
        if response.completed_at_upper_ms >= cap {
            return Err(error(ServiceFailure::DeadlineExceeded));
        }
        if response.aborted {
            return Err(error(ServiceFailure::ServiceUnavailable));
        }
        if response.header.sdk_error() {
            return Err(ServiceError::from_sdk_payload(&response.payload)?);
        }
        self.0.check()?;
        let snapshots = self
            .0
            .capture_snapshots(&response.payload, targets, contract_prepaid)?;
        self.0
            .account
            .with_security(|| snapshots)
            .map_err(Into::into)
        }.await;
        diagnostics.service_outcome(&outcome);
        outcome
    }
}
pub(crate) struct PeerWorker(Arc<PeerLifetime>);
impl Drop for PeerWorker {
    fn drop(&mut self) {
        if self.0.workers.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.charge.lock().expect("service peer charge").take();
            self.0.tail.finish();
        }
        self.0.changed.notify_waiters();
    }
}
impl PeerInner {
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
    pub(crate) fn retain_worker(&self) -> PeerWorker {
        self.lifetime.workers.fetch_add(1, Ordering::AcqRel);
        PeerWorker(self.lifetime.clone())
    }
    fn close_streaming(&self) {
        let catalog = self
            .streaming_catalog
            .lock()
            .expect("streaming contract catalog")
            .take();
        let resume = self
            .resume_catalog
            .lock()
            .expect("Resume contract catalog")
            .take();
        drop((catalog, resume));
    }
    pub(crate) fn application_tail(&self) -> Result<crate::application_tails_v4::ApplicationTail> {
        Ok(self.lifetime.tail.sibling()?)
    }
    pub(crate) fn check(&self) -> Result<()> {
        self.account.check()?;
        if self.closed.load(Ordering::Acquire) {
            return Err(error(ServiceFailure::Closed));
        }
        Ok(())
    }
    fn capture_snapshots(
        &self,
        payload: &[u8],
        targets: &[ContractQueryTarget],
        prepaid: Option<Vec<ResourceCharge>>,
    ) -> Result<Vec<ContractSnapshot>> {
        let mut prepaid = prepaid.map(Vec::into_iter);
        let value = parsed(codec::decode(
            payload,
            "ContractSnapshots",
            Limits {
                bytes: 73728,
                nodes: 512,
            },
            None,
        ))?;
        let items = parsed(value.field("ContractSnapshots", "items"))?;
        if parsed(items.len())? != targets.len() {
            return Err(error(ServiceFailure::Protocol));
        }
        let mut snapshots = Vec::with_capacity(targets.len());
        for (index, item) in parsed(items.children())?.enumerate() {
            let item = parsed(item)?;
            if parsed(item.u("ContractSnapshot", "target_index"))? != index as u64 {
                return Err(error(ServiceFailure::Protocol));
            }
            let status = parsed(item.u("ContractSnapshot", "status"))?;
            let target = &targets[index];
            let capture_charge = prepaid
                .as_mut()
                .map(|charges| {
                    charges
                        .next()
                        .ok_or_else(|| error(ServiceFailure::ConfigurationCapacity))
                })
                .transpose()?;
            let contract = match status {
                0 => {
                    let canonical = parsed(
                        item.field("ContractSnapshot", "contract")
                            .and_then(Value::bytes),
                    )?;
                    Some(if let Some(charge) = capture_charge {
                        ServiceContract::capture_prepaid(&self.account, canonical, charge)?
                    } else {
                        ServiceContract::capture_root(self.account.environment_root(), canonical)?
                    })
                }
                1 => {
                    let digest = parsed(item.b::<32>("ContractSnapshot", "contract_digest"))?;
                    Some(
                        target
                            .known
                            .as_ref()
                            .filter(|known| known.digest() == digest)
                            .ok_or_else(|| error(ServiceFailure::ContractMismatch))?
                            .clone(),
                    )
                }
                2 | 3 => None,
                _ => return Err(error(ServiceFailure::Protocol)),
            };
            if contract.as_ref().is_some_and(|contract| {
                contract.namespace() != target.namespace
                    || contract.type_id() != target.type_id
                    || target
                        .wanted_digest
                        .is_some_and(|digest| contract.digest() != digest)
            }) {
                return Err(error(ServiceFailure::ContractMismatch));
            }
            let encoded_offer = parsed(item.optional("ContractSnapshot", "offer"))?;
            let offer = match (&contract, encoded_offer) {
                (Some(contract), Some(offer))
                    if contract.semantics() == ServiceSemantics::Execution =>
                {
                    Some(AdmissionOffer::capture(
                        parsed(offer.bytes())?,
                        contract,
                        contract.uint(16)?,
                    )?)
                }
                (Some(contract), None) if contract.semantics() != ServiceSemantics::Execution => {
                    None
                }
                (None, None) => None,
                _ => return Err(error(ServiceFailure::ContractMismatch)),
            };
            snapshots.push(ContractSnapshot {
                availability: match status {
                    0 | 1 => ContractAvailability::Available,
                    2 => ContractAvailability::Denied,
                    _ => ContractAvailability::Unavailable,
                },
                contract,
                offer,
            });
        }
        Ok(snapshots)
    }
    async fn query_response(
        self: &Arc<Self>,
        request: RequestInput,
        _invocation: crate::application_executor_v4::ApplicationInvocation,
    ) {
        let outcome = self.build_query_response(&request.header, &request.payload, request.aborted);
        match outcome {
            Ok(payload) => {
                let header = match request.header.response(
                    "query_contracts_response",
                    payload.len() as u32,
                    None,
                ) {
                    Ok(header) => header,
                    Err(failure) => {
                        let _ = self.refuse(request.reply, failure);
                        return;
                    }
                };
                let account = self.account.clone();
                let cancellation = self.cancellation.clone();
                let cap = request.header.uint(5).unwrap_or(0);
                if let Ok(receipt) = self.channel.reply(
                    request.reply,
                    header,
                    &payload,
                    Arc::new(move || {
                        account.check()?;
                        if cancellation.is_cancelled() {
                            return Err(error(ServiceFailure::Closed));
                        }
                        if account.security_time()?.upper_ms >= cap {
                            return Err(error(ServiceFailure::DeadlineExceeded));
                        }
                        Ok(())
                    }),
                ) {
                    let _ = receipt.await;
                }
            }
            Err(failure) => {
                let _ = self.refuse(request.reply, failure);
            }
        }
    }
    fn build_query_response(
        &self,
        header: &ApplicationHeader,
        request: &[u8],
        aborted: bool,
    ) -> Result<Vec<u8>> {
        self.check()?;
        if aborted {
            return Err(error(ServiceFailure::RequestMessageAborted));
        }
        if header.type_id()? != self.query.type_id || header.bytes(6)? != self.query.contract_digest
        {
            return Err(error(ServiceFailure::Protocol));
        }
        let _charge = self.account.reserve(ResourceLimits {
            sdk_bytes: 81920,
            items: 10,
            ..ResourceLimits::default()
        })?;
        let document = parsed(codec::decode(
            request,
            "ContractTargets",
            Limits {
                bytes: 2048,
                nodes: 96,
            },
            None,
        ))?;
        let targets = parsed(document.field("ContractTargets", "targets"))?;
        let mut payload = Vec::with_capacity(73728);
        head(&mut payload, 5, 1);
        head(&mut payload, 0, 0);
        head(&mut payload, 4, parsed(targets.len())? as u64);
        for (index, target) in parsed(targets.children())?.enumerate() {
            let target = parsed(target)?;
            let namespace = parsed(
                target
                    .field("ContractTarget", "service_namespace")
                    .and_then(Value::text),
            )?;
            let type_id = parsed(target.u("ContractTarget", "method_type_id"))? as u32;
            let wanted = parsed(target.optional("ContractTarget", "wanted_contract_digest"))?
                .map(|value| parsed(value.bytes()))
                .transpose()?;
            let known = parsed(target.optional("ContractTarget", "known_contract_digest"))?
                .map(|value| parsed(value.bytes()))
                .transpose()?;
            let registration = self.registrations.iter().find(|entry| {
                entry.contract.namespace() == namespace && entry.contract.type_id() == type_id
            });
            let notification = self
                .notification_catalog
                .lock()
                .expect("notification contract catalog")
                .as_ref()
                .filter(|catalog| !catalog.closed.load(Ordering::Acquire))
                .and_then(|catalog| {
                    catalog.registrations.iter().find(|entry| {
                        entry.contract.namespace() == namespace
                            && entry.contract.type_id() == type_id
                    })
                })
                .cloned();
            let streaming = self
                .streaming_catalog
                .lock()
                .expect("streaming contract catalog")
                .as_ref()
                .and_then(|catalog| {
                    catalog.registrations.iter().find(|entry| {
                        entry.service.contract().namespace() == namespace
                            && entry.service.contract().type_id() == type_id
                    })
                })
                .cloned();
            let resume = self
                .resume_catalog
                .lock()
                .expect("Resume contract catalog")
                .as_ref()
                .and_then(|catalog| {
                    catalog.registrations.iter().find(|entry| {
                        entry.service.contract().namespace() == namespace
                            && entry.service.contract().type_id() == type_id
                    })
                })
                .cloned();
            let captured = if let Some(entry) = registration {
                Some((
                    entry.contract.clone(),
                    entry.query_allowed,
                    entry.current_offer(&self.account)?,
                ))
            } else if let Some(entry) = streaming {
                Some((
                    entry.service.contract().clone(),
                    entry.query_allowed,
                    entry.service.offer(&self.account)?,
                ))
            } else if let Some(entry) = resume {
                Some((
                    entry.service.contract().clone(),
                    entry.query_allowed,
                    entry.service.offer(&self.account)?,
                ))
            } else {
                notification.map(|entry| (entry.contract, entry.query_allowed, entry.offer))
            };
            let now = self.account.security_time()?;
            let available = captured.as_ref().filter(|(contract, allowed, offer)| {
                *allowed
                    && wanted.is_none_or(|wanted| wanted == contract.digest())
                    && offer.as_ref().is_none_or(|offer| {
                        now.lower_ms >= offer.not_before_ms() && now.upper_ms < offer.not_after_ms()
                    })
            });
            if let Some((contract, _, offer)) = available {
                let unchanged = known.is_some_and(|digest| digest == contract.digest());
                head(&mut payload, 5, 3 + u64::from(offer.is_some()));
                head(&mut payload, 0, 0);
                head(&mut payload, 0, index as u64);
                head(&mut payload, 0, 1);
                head(&mut payload, 0, u64::from(unchanged));
                if unchanged {
                    head(&mut payload, 0, 3);
                    data(&mut payload, &contract.digest());
                } else {
                    head(&mut payload, 0, 2);
                    data(&mut payload, contract.encoded());
                }
                if let Some(offer) = offer {
                    head(&mut payload, 0, 4);
                    data(&mut payload, &offer.encode());
                }
            } else {
                head(&mut payload, 5, 2);
                head(&mut payload, 0, 0);
                head(&mut payload, 0, index as u64);
                head(&mut payload, 0, 1);
                head(
                    &mut payload,
                    0,
                    if captured.is_some_and(|(_, allowed, _)| !allowed) {
                        2
                    } else {
                        3
                    },
                );
            }
        }
        parsed(codec::decode(
            &payload,
            "ContractSnapshots",
            Limits {
                bytes: 73728,
                nodes: 512,
            },
            None,
        ))?;
        Ok(payload)
    }
    fn refuse(&self, reply: ReplySlot, failure: ServiceError) -> Result<()> {
        let request = reply.request();
        let kind = match request.kind() {
            "execution_unary_request" => "execution_unary_sdk_error",
            "transient_unary_request" => "transient_unary_sdk_error",
            "query_contracts_request" => "query_contracts_sdk_error",
            "read_result_request" => "read_result_sdk_error",
            _ => return Err(error(ServiceFailure::Protocol)),
        };
        let code = if failure.0 == ServiceFailure::RequestMessageAborted {
            1
        } else {
            match failure.0 {
                ServiceFailure::ContractMismatch => 3,
                ServiceFailure::ResponseLimitUnsupported => 4,
                ServiceFailure::ResourceExhausted | ServiceFailure::DependencyUnavailable => 5,
                ServiceFailure::PermissionDenied => 7,
                ServiceFailure::DeadlineExceeded => 8,
                ServiceFailure::ServiceFailed => 9,
                ServiceFailure::OperationConflict => 11,
                ServiceFailure::ResultExpired => 12,
                _ => 10,
            }
        };
        let payload = [0xa1, 0, code];
        let header = request.response(kind, payload.len() as u32, None)?;
        let account = self.account.clone();
        let cancellation = self.cancellation.clone();
        let _receipt = self.channel.reply(
            reply,
            header,
            &payload,
            Arc::new(move || {
                account.check()?;
                if cancellation.is_cancelled() {
                    return Err(error(ServiceFailure::Closed));
                }
                Ok(())
            }),
        )?;
        Ok(())
    }
    fn dispatch_result_read(self: &Arc<Self>, message: IncomingMessage) -> Result<()> {
        let request = message.into_request();
        let setup = (|| {
            self.check()?;
            if request.aborted {
                return Err(error(ServiceFailure::RequestMessageAborted));
            }
            let read = self
                .result_read
                .as_ref()
                .ok_or_else(|| error(ServiceFailure::ServiceUnavailable))?;
            if request.header.type_id()? != read.type_id
                || request.header.bytes(6)? != read.contract_digest
            {
                return Err(error(ServiceFailure::ContractMismatch));
            }
            let target = crate::execution_management_v4::target_decode(&request.payload)?;
            let grant = read
                .grants
                .iter()
                .find(|grant| grant.check(&self.account, &target, false).is_ok())
                .cloned()
                .ok_or_else(|| error(ServiceFailure::PermissionDenied))?;
            let now = self.account.security_time()?;
            let cap = request.header.uint(5)?;
            if now.upper_ms >= cap || cap > now.lower_ms.saturating_add(30000) {
                return Err(error(ServiceFailure::DeadlineExceeded));
            }
            let position = self.group.admit_ordinary(false, None, false)?;
            let charge = self.account.reserve(ResourceLimits {
                sdk_bytes: read.max_result_bytes as u64 + 8192,
                items: 2,
                tasks: 1,
                ..ResourceLimits::default()
            })?;
            Ok((
                target,
                grant,
                position,
                charge,
                read.max_result_bytes as usize,
                cap,
            ))
        })();
        let (target, grant, position, charge, maximum, cap) = match setup {
            Ok(setup) => setup,
            Err(failure) => return self.refuse(request.reply, failure),
        };
        self.lifetime.workers.fetch_add(1, Ordering::AcqRel);
        let peer = Arc::downgrade(self);
        let account = self.account.clone();
        let cancellation = self.cancellation.clone();
        let worker = PeerWorker(self.lifetime.clone());
        tokio::spawn(async move {
            let _worker = worker;
            let _charge = charge;
            let outcome = async {
                let position = tokio::select! { position = position.position() => position.map_err(ServiceError::from)?,
                    _ = cancellation.cancelled() => return Err(error(ServiceFailure::Closed)) };
                let invocation = position.enter()?;
                if account.security_time()?.upper_ms >= cap { return Err(error(ServiceFailure::DeadlineExceeded)); }
                let mut payload = Zeroizing::new(vec![0; maximum]);
                let (length, _) = grant.read(&account, &target, &mut payload)?;
                payload.truncate(length); drop(invocation); drop(position); Ok(payload)
            }.await;
            if let Some(peer) = peer.upgrade() {
                match outcome {
                    Ok(payload) => {
                        let header = match request.header.response(
                            "read_result_response",
                            payload.len() as u32,
                            None,
                        ) {
                            Ok(header) => header,
                            Err(failure) => {
                                let _ = peer.refuse(request.reply, failure);
                                return;
                            }
                        };
                        if let Ok(receipt) = peer.channel.reply(
                            request.reply,
                            header,
                            &payload,
                            Arc::new(move || {
                                account.check()?;
                                grant.check(&account, &target, false)?;
                                if cancellation.is_cancelled() {
                                    return Err(error(ServiceFailure::Closed));
                                }
                                if account.security_time()?.upper_ms >= cap {
                                    return Err(error(ServiceFailure::DeadlineExceeded));
                                }
                                Ok(())
                            }),
                        ) {
                            let _ = receipt.await;
                        }
                    }
                    Err(failure) => {
                        let _ = peer.refuse(request.reply, failure);
                    }
                }
            }
        });
        Ok(())
    }
    fn dispatch_unary(self: &Arc<Self>, message: IncomingMessage) -> Result<()> {
        let request = message.into_request();
        let admission = (|| {
            self.check()?;
            if request.aborted {
                return Err(error(ServiceFailure::RequestMessageAborted));
            }
            let registration = self
                .registrations
                .iter()
                .find(|entry| {
                    entry.contract.type_id() == request.header.type_id().unwrap_or(0)
                        && entry.contract.digest() == request.header.bytes(6).unwrap_or([0; 32])
                })
                .cloned()
                .ok_or_else(|| error(ServiceFailure::ContractMismatch))?;
            let execution = registration.contract.semantics() == ServiceSemantics::Execution;
            if request.aborted
                || request.header.kind()
                    != if execution {
                        "execution_unary_request"
                    } else {
                        "transient_unary_request"
                    }
                || request.payload.len() as u64 > registration.contract.uint(23)?
                || request.header.uint(8)? < registration.contract.uint(9)?
                || request.header.uint(8)? > registration.contract.uint(10)?
            {
                return Err(error(ServiceFailure::ContractMismatch));
            }
            let position = self.group.admit_ordinary(
                registration.resident,
                None,
                request.header.uint(7)? == 1,
            )?;
            let charge = self.account.reserve(ResourceLimits {
                sdk_bytes: registration.handler.application_bytes()
                    + request.header.uint(8)?
                    + 8192,
                items: 3,
                tasks: 1,
                ..ResourceLimits::default()
            })?;
            Ok((registration, position, charge))
        })();
        let (registration, position, charge) = match admission {
            Ok(admission) => admission,
            Err(failure) => {
                return self.refuse(request.reply, failure);
            }
        };
        self.lifetime.workers.fetch_add(1, Ordering::AcqRel);
        let tail = DispatchTail {
            peer: Arc::downgrade(self),
            account: self.account.clone(),
            cancellation: self.cancellation.clone(),
            _worker: PeerWorker(self.lifetime.clone()),
            _charge: charge,
        };
        tokio::spawn(async move {
            tail.run_unary(request, registration, position).await;
        });
        Ok(())
    }
}
/// A noncooperative callback owns its original finite tail and actual executor
/// position. It does not retain the RPC channel, Stream or Session graph.
struct DispatchTail {
    peer: Weak<PeerInner>,
    account: ResourceAccount,
    cancellation: CancellationToken,
    _worker: PeerWorker,
    _charge: ResourceCharge,
}
impl DispatchTail {
    fn check(&self) -> Result<()> {
        self.account.check()?;
        if self.cancellation.is_cancelled() {
            return Err(error(ServiceFailure::Closed));
        }
        Ok(())
    }
    async fn run_unary(
        self,
        request: RequestInput,
        registration: UnaryServiceRegistration,
        admission: OrdinaryAdmission,
    ) {
        let publication = if registration.contract.bool(21).unwrap_or(false) {
            let (serial, generation) = request.reply.publication_binding();
            match registration.contract.uint(22).and_then(|flush_ms| {
                crate::ResponsePublication::prepare(
                    self.account.clone(),
                    flush_ms,
                    request.header.uint(5)?,
                    serial,
                    generation,
                    self.peer
                        .upgrade()
                        .and_then(|peer| peer.maintenance.clone())
                        .ok_or_else(|| error(ServiceFailure::ServiceUnavailable))?,
                )
            }) {
                Ok(publication) => publication,
                Err(failure) => {
                    if let Some(peer) = self.peer.upgrade() {
                        let _ = peer.refuse(request.reply, failure);
                    }
                    return;
                }
            }
        } else {
            crate::ResponsePublication::not_applicable()
        };
        let _publication_tail = publication.tail();
        let reply = request.reply;
        let position = tokio::select! {
            position = admission.position() => position.map_err(ServiceError::from),
            _ = self.cancellation.cancelled() => Err(error(ServiceFailure::Closed)),
        };
        let outcome = match position {
            Ok(position) => {
                publication
                    .within_handler(self.invoke_unary(
                        &request.header,
                        &request.payload,
                        registration,
                        position,
                        publication.clone(),
                    ))
                    .await
            }
            Err(failure) => Err(failure),
        };
        publication.handler_returned();
        if let Some(peer) = self.peer.upgrade() {
            match outcome {
                Ok(response) => {
                    let kind = match (
                        request.header.kind(),
                        response.application_error_code.is_some(),
                    ) {
                        ("execution_unary_request", true) => "execution_unary_application_error",
                        ("execution_unary_request", false) => "execution_unary_response",
                        ("transient_unary_request", true) => "transient_unary_application_error",
                        _ => "transient_unary_response",
                    };
                    let selected = request
                        .header
                        .response(
                            kind,
                            response.payload.len() as u32,
                            response.application_error_code,
                        )
                        .and_then(|header| {
                            publication
                                .bind_response(&response.payload)
                                .map(|deadline| (header, deadline))
                        });
                    match selected {
                        Ok((header, deadline)) => {
                            let account = self.account.clone();
                            let cancellation = self.cancellation.clone();
                            let cap = request.header.uint(5).unwrap_or(0);
                            match peer.channel.reply_observed(
                                reply,
                                header,
                                &response.payload,
                                Arc::new(move || {
                                    account.check()?;
                                    if cancellation.is_cancelled() {
                                        return Err(error(ServiceFailure::Closed));
                                    }
                                    if account.security_time()?.upper_ms >= cap
                                        || deadline.is_some_and(|limit| Instant::now() >= limit)
                                    {
                                        return Err(error(ServiceFailure::DeadlineExceeded));
                                    }
                                    Ok(())
                                }),
                                publication.handoff_observer(),
                            ) {
                                Ok(receipt) => publication.observe(receipt).await,
                                Err(failure) => publication.publication_failed(failure),
                            }
                        }
                        Err(failure) => {
                            publication.publication_failed(failure);
                            let _ = peer.refuse(reply, failure);
                        }
                    }
                }
                Err(failure) => {
                    publication.unknown(crate::ResponsePublicationCause::ResponseSuperseded);
                    let _ = peer.refuse(reply, failure);
                }
            }
        } else {
            publication.unknown(crate::ResponsePublicationCause::OwnerUnavailable);
        }
    }
    async fn await_application<T>(
        &self,
        callback: impl std::future::Future<Output = Result<T>>,
        cancellation: &CancellationToken,
        cap: u64,
    ) -> Result<T> {
        tokio::pin!(callback);
        loop {
            tokio::select! {
                outcome = &mut callback => return outcome,
                _ = cancellation.cancelled() => {
                    let _ = callback.await;
                    return Err(error(ServiceFailure::Canceled));
                }
                _ = self.cancellation.cancelled() => {
                    cancellation.cancel();
                    let _ = callback.await;
                    return Err(error(ServiceFailure::Closed));
                }
                _ = self.account.security_changed() => {},
                _ = tokio::time::sleep(self.account.next_security_check()) => {},
            }
            let checked = self.check().and_then(|_| {
                if self.account.security_time()?.upper_ms >= cap {
                    Err(error(ServiceFailure::DeadlineExceeded))
                } else {
                    Ok(())
                }
            });
            if let Err(failure) = checked {
                cancellation.cancel();
                let _ = callback.await;
                return Err(failure);
            }
        }
    }
    async fn invoke_unary(
        &self,
        header: &ApplicationHeader,
        payload: &[u8],
        registration: UnaryServiceRegistration,
        position: ApplicationPosition,
        publication: crate::ResponsePublication,
    ) -> Result<UnaryResponse> {
        self.check()?;
        let invocation = position.enter()?;
        let wire_cap = header.uint(5)?;
        let duration = registration
            .contract
            .uint(if registration.execution.is_some() {
                18
            } else {
                12
            })?;
        let cap = wire_cap;
        let cancellation = self.cancellation.child_token();
        let context = UnaryRequestContext {
            invocation: invocation.context(),
            cancellation: cancellation.clone(),
            execution_identity: registration.caller.clone(),
            execution: None,
            publication,
            maintenance: self
                .peer
                .upgrade()
                .and_then(|peer| peer.maintenance.clone()),
        };
        self.await_application(
            async {
                AssertUnwindSafe(registration.handler.authorize(context.clone()))
                    .catch_unwind()
                    .await
                    .map_err(|_| error(ServiceFailure::PermissionDenied))?
            },
            &context.cancellation,
            cap,
        )
        .await?;
        self.check()?;
        if self.account.security_time()?.upper_ms >= cap {
            return Err(error(ServiceFailure::DeadlineExceeded));
        }
        let attempt = if let Some(execution) = &registration.execution {
            let offer = registration
                .current_offer(&self.account)?
                .ok_or_else(|| error(ServiceFailure::AdmissionWindowClosed))?;
            Some(Arc::new(
                execution.admit(
                    &registration.contract,
                    &offer,
                    registration
                        .caller
                        .as_ref()
                        .ok_or_else(|| error(ServiceFailure::PermissionDenied))?,
                    header,
                    payload,
                    &self.account,
                    || self.check(),
                )?,
            ))
        } else {
            None
        };
        // Keep exit tied to this callback future, including early failures and
        // cancellation, even when the application retains its invocation.
        let _callback_exit = attempt
            .as_ref()
            .map(|attempt| crate::execution_history::ExecutionCallbackExit::new(attempt.clone()));
        let response = if let Some(attempt) = &attempt {
            if attempt.created() {
                let now = self.account.security_time()?;
                let cap = attempt
                    .execution_cap(wire_cap, duration)
                    .inspect_err(|failure| {
                        attempt.fail(failure.0);
                    })?;
                if now.upper_ms >= cap {
                    return Err(error(ServiceFailure::DeadlineExceeded));
                }
                attempt.enter(|| self.check()).inspect_err(|failure| {
                    attempt.fail(failure.0);
                })?;
                let session = self
                    .peer
                    .upgrade()
                    .ok_or_else(|| error(ServiceFailure::Closed))?
                    .session
                    .clone();
                let context = UnaryRequestContext {
                    cancellation: attempt.cancellation()?,
                    execution: crate::ExecutionInvocation::for_request(
                        attempt.clone(),
                        session,
                        &registration.contract,
                    )?,
                    ..context
                };
                let callback_cancellation = context.cancellation.clone();
                let outcome = self
                    .await_application(
                        async {
                            AssertUnwindSafe(registration.handler.handle(context, payload))
                                .catch_unwind()
                                .await
                                .map_err(|_| error(ServiceFailure::ServiceFailed))?
                        },
                        &callback_cancellation,
                        cap,
                    )
                    .await;
                match outcome {
                    Ok(response) => {
                        if response.payload.len() as u64 > header.uint(8)?
                            || response.payload.len() as u64
                                > registration
                                    .contract
                                    .response_payload_limit(response.application_error_code)?
                        {
                            attempt.fail(ServiceFailure::ResourceExhausted);
                            return Err(error(ServiceFailure::ResourceExhausted));
                        }
                        attempt
                            .finish(
                                &response.payload,
                                response.application_error_code,
                                cap,
                                || self.check(),
                            )
                            .inspect_err(|failure| {
                                attempt.fail(failure.0);
                            })?;
                        response
                    }
                    Err(failure) => {
                        attempt.fail(failure.0);
                        return Err(failure);
                    }
                }
            } else {
                drop(invocation);
                drop(position);
                attempt.wait_terminal(&self.cancellation).await?;
                let mut payload = vec![0u8; header.uint(8)? as usize];
                let (length, application_error_code) = attempt.copy_result(&mut payload)?;
                payload.truncate(length);
                UnaryResponse {
                    payload,
                    application_error_code,
                }
            }
        } else {
            let now = self.account.security_time()?;
            let cap = wire_cap.min(
                now.lower_ms
                    .checked_add(duration)
                    .ok_or_else(|| error(ServiceFailure::DeadlineExceeded))?,
            );
            if now.upper_ms >= cap {
                return Err(error(ServiceFailure::DeadlineExceeded));
            }
            let callback_cancellation = context.cancellation.clone();
            self.await_application(
                async {
                    AssertUnwindSafe(registration.handler.handle(context, payload))
                        .catch_unwind()
                        .await
                        .map_err(|_| error(ServiceFailure::ServiceFailed))?
                },
                &callback_cancellation,
                cap,
            )
            .await?
        };
        if response.payload.len() as u64 > header.uint(8)?
            || response.payload.len() as u64
                > registration
                    .contract
                    .response_payload_limit(response.application_error_code)?
        {
            return Err(error(ServiceFailure::ResourceExhausted));
        }
        if let Some(attempt) = attempt {
            attempt.exit();
        }
        Ok(response)
    }
}

struct RetainedResultPayload {
    bytes: Zeroizing<Vec<u8>>,
    _charge: ResourceCharge,
}
impl AsRef<[u8]> for RetainedResultPayload {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

struct ResultReadWait(CancellationToken);
impl Drop for ResultReadWait {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
