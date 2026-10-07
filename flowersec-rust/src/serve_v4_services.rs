//! Frozen service installation for one original accepted Session. Capacity is
//! reserved before irreversible admission and transferred before local READY.
use super::*;
use crate::crypto_v4::connect::candidate_add_limits;
use crate::execution_management_v4::ManagementPreparation;
use crate::notification_peer_v4::NotificationPreparation;
use crate::resume_service_v4::ResumeMembership;
use crate::service_peer_v4::ServicePeerPreparation;
use crate::streaming_service_v4::StreamingMembership;
use crate::{
    ExecutionHistoryGrant, ExecutionManagement, FixedContractQuery, FixedResultRead,
    NotificationPeer, NotificationServiceRegistration, ResumeServiceRegistration, ServicePeer,
    StreamingServiceRegistration, UnaryServiceRegistration,
    service_contract::{ServiceError, ServiceFailure},
};
use std::result::Result;

fn service_error(error: ServiceError) -> ServeError {
    ServeError::new(match error.0 {
        ServiceFailure::ResourceExhausted | ServiceFailure::ConfigurationCapacity => {
            ServeFailure::Capacity
        }
        ServiceFailure::Closed => ServeFailure::Closed,
        ServiceFailure::Canceled => ServeFailure::Canceled,
        ServiceFailure::PermissionDenied => ServeFailure::Rejected,
        _ => ServeFailure::Configuration,
    })
}
/// The directory, methods and trusted history grants captured by resolve_handlers.
/// Registration does not execute an application handler or spend authority.
#[derive(Clone, Debug)]
pub struct ServicePlan {
    pub query: FixedContractQuery,
    pub unary: Vec<UnaryServiceRegistration>,
    pub notifications: Vec<NotificationServiceRegistration>,
    pub streaming: Vec<StreamingServiceRegistration>,
    pub resume: Vec<ResumeServiceRegistration>,
    pub result_read: Option<FixedResultRead>,
    pub management: Option<Vec<ExecutionHistoryGrant>>,
}
impl ServicePlan {
    pub(super) fn capture(self, root: &Arc<EnvironmentRoot>) -> Result<Self, ServeError> {
        if self.query.type_id == 0
            || self.query.contract_digest == [0; 32]
            || self.unary.len() > 256
            || self.notifications.len() > 256
            || self.streaming.len() > 128
            || self.resume.len() > 128
        {
            return Err(ServeError::new(ServeFailure::Configuration));
        }
        let mut types = std::collections::BTreeSet::new();
        types.insert(self.query.type_id);
        if let Some(read) = &self.result_read {
            if read.type_id == 0
                || read.contract_digest == [0; 32]
                || !types.insert(read.type_id)
                || read.max_result_bytes == 0
                || read.max_result_bytes > 1 << 20
                || read.grants.len() > 128
            {
                return Err(ServeError::new(ServeFailure::Configuration));
            }
            for grant in &read.grants {
                grant.validate_environment(root).map_err(service_error)?;
            }
        }
        for contract in self
            .unary
            .iter()
            .map(|entry| &entry.contract)
            .chain(self.notifications.iter().map(|entry| &entry.contract))
            .chain(self.streaming.iter().map(|entry| entry.service.contract()))
            .chain(self.resume.iter().map(|entry| entry.service.contract()))
        {
            contract.check_environment(root).map_err(service_error)?;
            if !types.insert(contract.type_id()) {
                return Err(ServeError::new(ServeFailure::Configuration));
            }
        }
        for entry in &self.resume {
            let original = entry.service.original_contract();
            let execution = match original.shape() {
                crate::ServiceShape::Unary => self
                    .unary
                    .iter()
                    .find(|registered| registered.contract.digest() == original.digest())
                    .and_then(|registered| registered.execution.as_ref()),
                crate::ServiceShape::ServerStreaming => self
                    .streaming
                    .iter()
                    .find(|registered| registered.service.contract().digest() == original.digest())
                    .and_then(|registered| registered.service.execution_service()),
                _ => None,
            };
            if execution
                .is_none_or(|execution| !Arc::ptr_eq(&execution.0, &entry.service.execution().0))
            {
                return Err(ServeError::new(ServeFailure::Configuration));
            }
        }
        if let Some(grants) = &self.management {
            if grants.len() > 128 {
                return Err(ServeError::new(ServeFailure::Configuration));
            }
            for grant in grants {
                grant.validate_environment(root).map_err(service_error)?;
            }
        }
        Ok(self)
    }
    fn notification_catalog_limits(&self) -> Result<ResourceLimits, ServeError> {
        if self.notifications.is_empty() {
            return Ok(ResourceLimits::default());
        }
        let bytes = self
            .notifications
            .iter()
            .try_fold(8192u64, |total, entry| {
                total.checked_add(4096)?.checked_add(
                    entry
                        .handler
                        .as_ref()
                        .map_or(0, |handler| handler.application_bytes()),
                )
            })
            .ok_or_else(|| ServeError::new(ServeFailure::Capacity))?;
        Ok(ResourceLimits {
            sdk_bytes: bytes,
            items: self.notifications.len() as u64 + 1,
            ..ResourceLimits::default()
        })
    }
    fn catalog_limits(count: usize) -> ResourceLimits {
        if count == 0 {
            ResourceLimits::default()
        } else {
            ResourceLimits {
                sdk_bytes: 8192 + count as u64 * 4096,
                items: count as u64 + 1,
                ..ResourceLimits::default()
            }
        }
    }
    pub(crate) fn preparation_limits(&self) -> Result<ResourceLimits, ServeError> {
        let mut limits =
            ServicePeer::preparation_limits(self.unary.len(), self.result_read.as_ref())
                .map_err(service_error)?;
        if !self.notifications.is_empty() {
            limits = candidate_add_limits(
                limits,
                NotificationPeer::preparation_limits(&self.notifications).map_err(service_error)?,
            )?;
            limits = candidate_add_limits(limits, self.notification_catalog_limits()?)?;
        }
        limits = candidate_add_limits(limits, Self::catalog_limits(self.streaming.len()))?;
        for _ in &self.streaming {
            limits = candidate_add_limits(
                limits,
                crate::streaming_service_v4::RegisteredStreamingService::preparation_limits(),
            )?;
        }
        limits = candidate_add_limits(limits, Self::catalog_limits(self.resume.len()))?;
        for _ in &self.resume {
            limits = candidate_add_limits(
                limits,
                crate::resume_service_v4::RegisteredResumeService::preparation_limits(),
            )?;
        }
        if let Some(grants) = &self.management {
            limits = candidate_add_limits(
                limits,
                ExecutionManagement::preparation_limits(grants.len(), 1).map_err(service_error)?,
            )?;
        }
        Ok(limits)
    }
    pub(super) fn reserve(
        &self,
        account: &ResourceAccount,
        profile: u8,
        identity: [u8; 32],
    ) -> Result<PreparedServicePlan, ServeError> {
        let charge = account.reserve(self.preparation_limits()?)?;
        self.reserve_prepaid(account, profile, identity, charge)
    }
    pub(crate) fn reserve_prepaid(
        &self,
        account: &ResourceAccount,
        profile: u8,
        identity: [u8; 32],
        mut backing: ResourceCharge,
    ) -> Result<PreparedServicePlan, ServeError> {
        if profile == 0 || !backing.matches(account, self.preparation_limits()?) {
            return Err(ServeError::new(ServeFailure::Configuration));
        }
        let peer_charge = backing.split(
            ServicePeer::preparation_limits(self.unary.len(), self.result_read.as_ref())
                .map_err(service_error)?,
        )?;
        let peer = ServicePeer::prepare_installation_prepaid(
            account,
            profile,
            identity,
            self.query,
            &self.unary,
            self.result_read.as_ref(),
            peer_charge,
        )
        .map_err(service_error)?;
        let notifications = if self.notifications.is_empty() {
            None
        } else {
            let charge = backing.split(
                NotificationPeer::preparation_limits(&self.notifications).map_err(service_error)?,
            )?;
            Some(
                NotificationPeer::prepare_installation_prepaid(
                    account,
                    profile,
                    identity,
                    &self.notifications,
                    charge,
                )
                .map_err(service_error)?,
            )
        };
        let notification_catalog = if notifications.is_some() {
            Some(backing.split(self.notification_catalog_limits()?)?)
        } else {
            None
        };
        let streaming_catalog = if self.streaming.is_empty() {
            None
        } else {
            let charge = backing.split(Self::catalog_limits(self.streaming.len()))?;
            let mut memberships = Vec::with_capacity(self.streaming.len());
            for entry in &self.streaming {
                let membership_charge = backing.split(
                    crate::streaming_service_v4::RegisteredStreamingService::preparation_limits(),
                )?;
                memberships.push(
                    entry
                        .service
                        .prepare_binding_prepaid(
                            account,
                            profile,
                            identity,
                            entry.caller.clone(),
                            membership_charge,
                        )
                        .map_err(service_error)?,
                );
            }
            Some((charge, memberships))
        };
        let resume_catalog = if self.resume.is_empty() {
            None
        } else {
            let charge = backing.split(Self::catalog_limits(self.resume.len()))?;
            let mut memberships = Vec::with_capacity(self.resume.len());
            for entry in &self.resume {
                let membership_charge = backing.split(
                    crate::resume_service_v4::RegisteredResumeService::preparation_limits(),
                )?;
                memberships.push(
                    entry
                        .service
                        .prepare_binding_prepaid(
                            account,
                            profile,
                            identity,
                            entry.caller.clone(),
                            membership_charge,
                        )
                        .map_err(service_error)?,
                );
            }
            Some((charge, memberships))
        };
        let management = if let Some(grants) = &self.management {
            let charge = backing.split(
                ExecutionManagement::preparation_limits(grants.len(), 1).map_err(service_error)?,
            )?;
            Some(
                ExecutionManagement::prepare_installation_prepaid(
                    account, 1, profile, identity, grants, charge,
                )
                .map_err(service_error)?,
            )
        } else {
            None
        };
        Ok(PreparedServicePlan {
            plan: self.clone(),
            peer,
            notifications,
            notification_catalog,
            streaming_catalog,
            resume_catalog,
            management,
            maintenance: None,
        })
    }
}
pub(crate) struct PreparedServicePlan {
    pub(crate) maintenance: Option<crate::MaintenanceOwner>,
    plan: ServicePlan,
    peer: ServicePeerPreparation,
    notifications: Option<NotificationPreparation>,
    notification_catalog: Option<ResourceCharge>,
    streaming_catalog: Option<(ResourceCharge, Vec<StreamingMembership>)>,
    resume_catalog: Option<(ResourceCharge, Vec<ResumeMembership>)>,
    management: Option<ManagementPreparation>,
}
impl PreparedServicePlan {
    pub(crate) fn install(self, session: &Session) -> Result<AcceptedServices, ServeError> {
        let Self {
            plan,
            peer,
            notifications,
            notification_catalog,
            streaming_catalog,
            resume_catalog,
            management,
            maintenance,
        } = self;
        session.install_maintenance_owner(maintenance);
        // The partial owner closes every original installed graph on failure.
        let mut installed = InstalledServices {
            peer: None,
            notifications: None,
            management: None,
        };
        installed.peer = Some(
            ServicePeer::create_prepared(session, plan.query, plan.unary, plan.result_read, peer)
                .map_err(service_error)?,
        );
        let peer = installed
            .peer
            .as_ref()
            .expect("original accepted service peer");
        if let Some(prepared) = notifications {
            installed.notifications = Some(
                NotificationPeer::create_prepared(session, plan.notifications, prepared)
                    .map_err(service_error)?,
            );
            peer.attach_notifications_prepared(
                installed
                    .notifications
                    .as_ref()
                    .expect("original notification peer"),
                notification_catalog,
            )
            .map_err(service_error)?;
        }
        if let Some(prepared) = streaming_catalog {
            peer.attach_streaming_prepared(plan.streaming, Some(prepared))
                .map_err(service_error)?;
        }
        if let Some(prepared) = resume_catalog {
            peer.attach_resume_prepared(plan.resume, Some(prepared))
                .map_err(service_error)?;
        }
        if let Some(prepared) = management {
            installed.management = Some(
                ExecutionManagement::prepare(
                    session,
                    plan.management.expect("frozen management grants"),
                    Some(prepared),
                )
                .map_err(service_error)?,
            );
        }
        peer.seal_catalogs();
        Ok(AcceptedServices(Arc::new(installed)))
    }
}
struct InstalledServices {
    peer: Option<ServicePeer>,
    notifications: Option<NotificationPeer>,
    management: Option<ExecutionManagement>,
}
impl InstalledServices {
    fn close(&self) {
        if let Some(peer) = &self.peer {
            peer.close();
        }
        if let Some(peer) = &self.notifications {
            peer.close();
        }
        if let Some(management) = &self.management {
            management.close();
        }
    }
}
impl Drop for InstalledServices {
    fn drop(&mut self) {
        self.close();
    }
}
/// Handles to the same pre-READY service graphs, exposed at application handoff.
#[derive(Clone)]
pub struct AcceptedServices(Arc<InstalledServices>);
impl fmt::Debug for AcceptedServices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AcceptedServices { <opaque> }")
    }
}
impl AcceptedServices {
    pub fn service_peer(&self) -> ServicePeer {
        self.0
            .peer
            .as_ref()
            .expect("original accepted service peer")
            .clone()
    }
    pub fn notifications(&self) -> Option<NotificationPeer> {
        self.0.notifications.clone()
    }
    pub fn management(&self) -> Option<ExecutionManagement> {
        self.0.management.clone()
    }
    pub(super) fn close(&self) {
        self.0.close();
    }
}
