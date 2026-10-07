//! SDK-owned material acquisition captures one identity, credential set, profile,
//! spend ledger and original provider. A source cannot manufacture authority or
//! switch a prepared operation to another material after acquisition.
use crate::{
    api_v4::{ConnectionRequirements, TransportEnvironment},
    crypto_v4::{
        IdentityKeys, Namespace,
        connect::{
            PoolConnectionMaterial, PoolCredentialBytes, ReverseTunnelProviderOptions,
            TunnelPoolCredentialBytes, WssConnectOptions,
        },
    },
    environment_v4::{EnvironmentCharge, EnvironmentRoot, ResourceCharge, ResourceLimits},
    pool_v4::SQLitePoolStore,
};
use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationProfile {
    Transport,
    Services,
    Execution,
}
impl ApplicationProfile {
    pub(crate) fn wire(self) -> u64 {
        match self {
            Self::Transport => 0,
            Self::Services => 1,
            Self::Execution => 2,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Services => "services",
            Self::Execution => "execution",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MaterialSourceError {
    #[error("material_unavailable")]
    MaterialUnavailable,
    #[error("source_exhausted")]
    SourceExhausted,
    #[error("source_unavailable")]
    SourceUnavailable,
    #[error("source_contract_invalid")]
    SourceContractInvalid,
    #[error("spent_unknown")]
    SpentUnknown,
    #[error("configuration_capacity")]
    ConfigurationCapacity,
    #[error("connection_requirement_unavailable")]
    ConnectionRequirementUnavailable,
    #[error("required_guarantee_unavailable")]
    RequiredGuaranteeUnavailable,
    #[error("connection acquisition canceled")]
    Canceled,
}
impl From<crate::TransportConnectError> for MaterialSourceError {
    fn from(error: crate::TransportConnectError) -> Self {
        match error {
            crate::TransportConnectError::Capacity => Self::ConfigurationCapacity,
            _ => Self::MaterialUnavailable,
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct ConnectionRequest {
    pub requirements: ConnectionRequirements,
    pub handlers: Option<(crate::HandlerPlan, crate::ApplicationLimits)>,
}
/// Trusted deployment configuration. Its signed credentials and namespaces
/// remain independently verified by the original material capture engine.
#[derive(Debug)]
pub struct PreauthorizedPoolSourceConfiguration {
    pub namespaces: Vec<Arc<Namespace>>,
    pub identity: IdentityKeys,
    pub credentials: Vec<PoolCredentialBytes>,
    pub spend_ledger: Arc<SQLitePoolStore>,
    pub provider: WssConnectOptions,
    pub application_profile: ApplicationProfile,
}
/// Independent hop service permissions accompany original issued tunnel
/// material. The Source captures them before verifying any peer credential.
#[derive(Debug)]
pub struct PreauthorizedTunnelPoolSourceConfiguration {
    pub namespaces: Vec<Arc<Namespace>>,
    pub identity: IdentityKeys,
    pub credentials: Vec<TunnelPoolCredentialBytes>,
    pub spend_ledger: Arc<SQLitePoolStore>,
    pub provider: WssConnectOptions,
    pub application_profile: ApplicationProfile,
    pub relay_service: String,
    pub relay_audience: String,
}
#[derive(Debug)]
pub struct PreauthorizedReverseTunnelPoolSourceConfiguration {
    pub namespaces: Vec<Arc<Namespace>>,
    pub identity: IdentityKeys,
    pub credentials: Vec<TunnelPoolCredentialBytes>,
    pub spend_ledger: Arc<SQLitePoolStore>,
    pub provider: ReverseTunnelProviderOptions,
    pub application_profile: ApplicationProfile,
    pub relay_service: String,
    pub relay_audience: String,
}
/// Scalar evidence from the original source acquisition gate. Observation
/// neither captures material nor grants another acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaterialAcquisitionObservation {
    pub acquisitions: u64,
    pub generation: u64,
}
struct PoolState {
    material: VecDeque<PoolConnectionMaterial>,
    live: Option<Arc<crate::live_material_source_v4::LiveSourceGeneration>>,
    generation: u64,
    acquisitions: u64,
    closed: bool,
    acquiring: bool,
    durable: std::collections::BTreeSet<[u8; 32]>,
}
pub(crate) struct Owner {
    root: Arc<EnvironmentRoot>,
    namespaces: Vec<Arc<Namespace>>,
    store: Option<Arc<SQLitePoolStore>>,
    provider: Option<WssConnectOptions>,
    profile: ApplicationProfile,
    capacity: usize,
    tunnel_scope: Option<(String, String)>,
    reverse: Option<Arc<crate::crypto_v4::connect::reverse::Capture>>,
    top_up: Mutex<Option<std::sync::Weak<crate::top_up_v4::TopUpOwner>>>,
    state: Mutex<PoolState>,
    _charge: EnvironmentCharge,
}
impl fmt::Debug for Owner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MaterialSourceOwner { <opaque> }")
    }
}
impl Owner {
    pub(crate) fn close(&self) {
        // Keep the source lock order consistent with durable acquisition,
        // which takes state before looking up the TopUp owner. Taking the
        // TopUp mutex first here would permit a state -> top_up / top_up ->
        // state deadlock during close racing with acquisition.
        let records = {
            let mut state = self.state.lock().expect("material source");
            state.closed = true;
            (std::mem::take(&mut state.material), state.live.take())
        };
        drop(records);
        let top_up = {
            let top_up = self.top_up.lock().expect("pool source TopUp owner");
            top_up.as_ref().and_then(std::sync::Weak::upgrade)
        };
        // Never invoke the TopUp lifecycle gate while holding either source
        // mutex. Recovery publication checks source state before that gate.
        if let Some(owner) = top_up {
            owner.close();
        }
    }
}
#[derive(Clone)]
pub struct ConnectionMaterialSource(Arc<Owner>);
struct PoolMaterialError {
    error: MaterialSourceError,
    close_owner: Option<Arc<crate::top_up_v4::TopUpOwner>>,
}
impl PoolMaterialError {
    fn plain(error: MaterialSourceError) -> Self {
        Self {
            error,
            close_owner: None,
        }
    }
    fn close(owner: Arc<crate::top_up_v4::TopUpOwner>, error: MaterialSourceError) -> Self {
        Self {
            error,
            close_owner: Some(owner),
        }
    }
}

struct LiveAcquireSlot(Arc<Owner>);
impl Drop for LiveAcquireSlot {
    fn drop(&mut self) {
        self.0
            .state
            .lock()
            .expect("original live Acquire exit")
            .acquiring = false;
    }
}
impl fmt::Debug for ConnectionMaterialSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnectionMaterialSource { <opaque> }")
    }
}
/// One acquired record. Identity and provider handles are captured together;
/// callers cannot replace either or reuse its single consumption right.
#[expect(
    clippy::large_enum_variant,
    reason = "The bounded source slot retains original pool or live material inline under its existing reservation."
)]
enum OriginalMaterial {
    Pool(PoolConnectionMaterial),
    Live(crate::live_material_source_v4::LiveConnectionMaterial),
}
pub struct ConnectionMaterial {
    owner: Arc<Owner>,
    material: OriginalMaterial,
    generation: u64,
    requirements: ConnectionRequirements,
}
impl ConnectionMaterial {
    pub(crate) fn source_profile(&self) -> crate::ConnectionSourceProfile {
        match &self.material {
            OriginalMaterial::Pool(_) => crate::ConnectionSourceProfile::PreauthorizedPool,
            OriginalMaterial::Live(_) => crate::ConnectionSourceProfile::LiveAuthority,
        }
    }
}
impl fmt::Debug for ConnectionMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnectionMaterial { <opaque> }")
    }
}
#[derive(Debug)]
pub struct LocalDirectMaterialSource;
impl LocalDirectMaterialSource {
    pub fn live_authority(
        environment: &TransportEnvironment,
        configuration: crate::LiveAuthoritySourceConfiguration,
    ) -> Result<ConnectionMaterialSource, MaterialSourceError> {
        ConnectionMaterialSource::live(environment, configuration)
    }
    pub fn live_tunnel_authority(
        environment: &TransportEnvironment,
        configuration: crate::LiveAuthoritySourceConfiguration,
        tunnel: crate::LiveTunnelSourceConfiguration,
    ) -> Result<ConnectionMaterialSource, MaterialSourceError> {
        ConnectionMaterialSource::live_tunnel(environment, configuration, tunnel)
    }
    /// The original live client leg listens at this independently installed
    /// address. TxA cannot substitute a different physical listener.
    pub fn live_reverse_tunnel_authority(
        environment: &TransportEnvironment,
        configuration: crate::LiveAuthoritySourceConfiguration,
        tunnel: crate::LiveTunnelSourceConfiguration,
        provider: ReverseTunnelProviderOptions,
    ) -> Result<ConnectionMaterialSource, MaterialSourceError> {
        ConnectionMaterialSource::live_reverse_tunnel(environment, configuration, tunnel, provider)
    }
    /// Consume one independently installed original TxA Artifact through the
    /// signed registered control endpoint. Failure cannot reopen that Artifact.
    pub fn registered_live_tunnel_authority(
        environment: &TransportEnvironment,
        configuration: crate::RegisteredLiveTunnelSourceConfiguration,
    ) -> Result<ConnectionMaterialSource, MaterialSourceError> {
        ConnectionMaterialSource::registered_live(environment, configuration, None)
    }
    /// Keep the original configured A listener while its one registered
    /// preparation and authorization attempt completes on the same Account.
    pub fn registered_live_reverse_tunnel_authority(
        environment: &TransportEnvironment,
        mut configuration: crate::RegisteredLiveTunnelSourceConfiguration,
        provider: ReverseTunnelProviderOptions,
    ) -> Result<ConnectionMaterialSource, MaterialSourceError> {
        let (reverse, original_provider) =
            crate::crypto_v4::connect::reverse::Capture::new(environment.root().clone(), provider)?;
        configuration.source.provider = original_provider;
        ConnectionMaterialSource::registered_live(environment, configuration, Some(reverse))
    }
    pub fn preauthorized_pool(
        environment: &TransportEnvironment,
        configuration: PreauthorizedPoolSourceConfiguration,
    ) -> Result<ConnectionMaterialSource, MaterialSourceError> {
        ConnectionMaterialSource::pool(environment, configuration)
    }
    /// Original server registrations and Grants correspond one-for-one with
    /// the issued tunnel credentials. Neither acquisition nor reconnect can
    /// infer a new recipient or recover a publication from a spend row.
    pub fn preauthorized_tunnel_pool_with_server_allow(
        environment: &TransportEnvironment,
        configuration: PreauthorizedTunnelPoolSourceConfiguration,
        server_allows: Vec<crate::TunnelServerAllowConfiguration>,
    ) -> Result<ConnectionMaterialSource, MaterialSourceError> {
        ConnectionMaterialSource::preauthorized_tunnel_pool_with_server_allow(
            environment,
            configuration,
            server_allows,
        )
    }
    pub fn preauthorized_reverse_tunnel_pool_with_server_allow(
        environment: &TransportEnvironment,
        configuration: PreauthorizedReverseTunnelPoolSourceConfiguration,
        server_allows: Vec<crate::TunnelServerAllowConfiguration>,
    ) -> Result<ConnectionMaterialSource, MaterialSourceError> {
        ConnectionMaterialSource::preauthorized_reverse_tunnel_pool_with_server_allow(
            environment,
            configuration,
            server_allows,
        )
    }
}
impl ConnectionMaterialSource {
    fn registered_live(
        environment: &TransportEnvironment,
        configuration: crate::RegisteredLiveTunnelSourceConfiguration,
        reverse: Option<Arc<crate::crypto_v4::connect::reverse::Capture>>,
    ) -> Result<Self, MaterialSourceError> {
        let profile = configuration.source.application_profile;
        let charge = environment
            .root()
            .reserve_environment(ResourceLimits {
                sdk_bytes: 8192,
                items: 4,
                work_slots: 1,
                ..ResourceLimits::default()
            })
            .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
        let live = crate::live_material_source_v4::LiveSourceGeneration::capture_registered(
            environment.root().clone(),
            configuration,
            reverse.clone(),
        )?;
        let source = Self(Arc::new(Owner {
            root: environment.root().clone(),
            namespaces: Vec::new(),
            store: None,
            provider: None,
            profile,
            capacity: 0,
            tunnel_scope: None,
            reverse,
            top_up: Mutex::new(None),
            state: Mutex::new(PoolState {
                material: VecDeque::new(),
                live: Some(live),
                generation: 1,
                acquisitions: 0,
                closed: false,
                acquiring: false,
                durable: std::collections::BTreeSet::new(),
            }),
            _charge: charge,
        }));
        environment
            .root()
            .register_material_source(&source.0)
            .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
        Ok(source)
    }
    fn live(
        environment: &TransportEnvironment,
        configuration: crate::LiveAuthoritySourceConfiguration,
    ) -> Result<Self, MaterialSourceError> {
        Self::live_with_tunnel(environment, configuration, None)
    }
    fn live_tunnel(
        environment: &TransportEnvironment,
        configuration: crate::LiveAuthoritySourceConfiguration,
        tunnel: crate::LiveTunnelSourceConfiguration,
    ) -> Result<Self, MaterialSourceError> {
        Self::live_with_tunnel(environment, configuration, Some(tunnel))
    }
    fn live_reverse_tunnel(
        environment: &TransportEnvironment,
        mut configuration: crate::LiveAuthoritySourceConfiguration,
        tunnel: crate::LiveTunnelSourceConfiguration,
        provider: ReverseTunnelProviderOptions,
    ) -> Result<Self, MaterialSourceError> {
        let (reverse, original_provider) =
            crate::crypto_v4::connect::reverse::Capture::new(environment.root().clone(), provider)?;
        configuration.provider = original_provider;
        Self::live_with_reverse(environment, configuration, Some(tunnel), Some(reverse))
    }
    fn live_with_tunnel(
        environment: &TransportEnvironment,
        configuration: crate::LiveAuthoritySourceConfiguration,
        tunnel: Option<crate::LiveTunnelSourceConfiguration>,
    ) -> Result<Self, MaterialSourceError> {
        Self::live_with_reverse(environment, configuration, tunnel, None)
    }
    fn live_with_reverse(
        environment: &TransportEnvironment,
        configuration: crate::LiveAuthoritySourceConfiguration,
        tunnel: Option<crate::LiveTunnelSourceConfiguration>,
        reverse: Option<Arc<crate::crypto_v4::connect::reverse::Capture>>,
    ) -> Result<Self, MaterialSourceError> {
        let profile = configuration.application_profile;
        let charge = environment
            .root()
            .reserve_environment(ResourceLimits {
                sdk_bytes: 8192,
                items: 4,
                work_slots: 1,
                ..ResourceLimits::default()
            })
            .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
        let live = crate::live_material_source_v4::LiveSourceGeneration::capture_with_reverse(
            environment.root().clone(),
            configuration,
            tunnel,
            reverse.clone(),
        )?;
        let source = Self(Arc::new(Owner {
            root: environment.root().clone(),
            namespaces: Vec::new(),
            store: None,
            provider: None,
            profile,
            capacity: 0,
            tunnel_scope: None,
            reverse,
            top_up: Mutex::new(None),
            state: Mutex::new(PoolState {
                material: VecDeque::new(),
                live: Some(live),
                generation: 1,
                acquisitions: 0,
                closed: false,
                acquiring: false,
                durable: std::collections::BTreeSet::new(),
            }),
            _charge: charge,
        }));
        environment
            .root()
            .register_material_source(&source.0)
            .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
        Ok(source)
    }
    /// Capture a complete new original live configuration before publishing its
    /// generation. A failed capture leaves current and acquired material intact.
    pub fn replace_live_generation(
        &self,
        configuration: crate::LiveAuthoritySourceConfiguration,
    ) -> Result<(), MaterialSourceError> {
        if configuration.application_profile != self.0.profile || self.0.store.is_some() {
            return Err(MaterialSourceError::ConnectionRequirementUnavailable);
        }
        let observed = {
            let state = self
                .0
                .state
                .lock()
                .expect("live source identity generation");
            if state.closed
                || state.live.is_none()
                || state
                    .live
                    .as_ref()
                    .is_some_and(|generation| generation.tunnel.is_some())
            {
                return Err(MaterialSourceError::MaterialUnavailable);
            }
            state.generation
        };
        let captured = crate::live_material_source_v4::LiveSourceGeneration::capture(
            self.0.root.clone(),
            configuration,
        )?;
        let previous = {
            let mut state = self
                .0
                .state
                .lock()
                .expect("live source generation publication");
            if state.closed || state.generation != observed {
                return Err(MaterialSourceError::MaterialUnavailable);
            }
            state.generation = state
                .generation
                .checked_add(1)
                .ok_or(MaterialSourceError::ConfigurationCapacity)?;
            state.live.replace(captured)
        };
        drop(previous);
        Ok(())
    }
    pub fn replace_live_tunnel_generation(
        &self,
        configuration: crate::LiveAuthoritySourceConfiguration,
        tunnel: crate::LiveTunnelSourceConfiguration,
    ) -> Result<(), MaterialSourceError> {
        if configuration.application_profile != self.0.profile || self.0.store.is_some() {
            return Err(MaterialSourceError::ConnectionRequirementUnavailable);
        }
        let observed = {
            let state = self.0.state.lock().expect("live tunnel source generation");
            if state.closed
                || state.live.is_none()
                || state
                    .live
                    .as_ref()
                    .is_none_or(|generation| generation.tunnel.is_none())
            {
                return Err(MaterialSourceError::MaterialUnavailable);
            }
            state.generation
        };
        let captured = crate::live_material_source_v4::LiveSourceGeneration::capture_with_reverse(
            self.0.root.clone(),
            configuration,
            Some(tunnel),
            self.0.reverse.clone(),
        )?;
        let previous = {
            let mut state = self
                .0
                .state
                .lock()
                .expect("live tunnel generation publication");
            if state.closed || state.generation != observed {
                return Err(MaterialSourceError::MaterialUnavailable);
            }
            state.generation = state
                .generation
                .checked_add(1)
                .ok_or(MaterialSourceError::ConfigurationCapacity)?;
            state.live.replace(captured)
        };
        drop(previous);
        Ok(())
    }
    /// One SDK-owned asynchronous Acquire for either configured source mode.
    /// Closing/replacing the source does not redirect this captured acquisition.
    pub async fn acquire_async(
        &self,
        environment: &TransportEnvironment,
        request: &ConnectionRequest,
        cancellation: &CancellationToken,
    ) -> Result<ConnectionMaterial, MaterialSourceError> {
        if self.0.store.is_some() {
            return self.acquire(environment, request, cancellation);
        }
        if !self.belongs_to(environment) {
            return Err(MaterialSourceError::MaterialUnavailable);
        }
        if request
            .requirements
            .application_profile
            .as_ref()
            .is_some_and(|profile| profile != self.0.profile.name())
        {
            return Err(MaterialSourceError::ConnectionRequirementUnavailable);
        }
        if cancellation.is_cancelled() {
            return Err(MaterialSourceError::Canceled);
        }
        let (snapshot, generation) = {
            let mut state = self.0.state.lock().expect("original live Acquire");
            if state.closed || self.0.root.is_closed() {
                return Err(MaterialSourceError::MaterialUnavailable);
            }
            if state.acquiring {
                return Err(MaterialSourceError::ConfigurationCapacity);
            }
            let snapshot = state
                .live
                .clone()
                .ok_or(MaterialSourceError::MaterialUnavailable)?;
            snapshot.supports_requirements(&request.requirements)?;
            state.acquisitions = state
                .acquisitions
                .checked_add(1)
                .ok_or(MaterialSourceError::ConfigurationCapacity)?;
            state.acquiring = true;
            (snapshot, state.generation)
        };
        let _slot = LiveAcquireSlot(self.0.clone());
        let material = snapshot
            .acquire(&request.requirements, cancellation)
            .await?;
        Ok(ConnectionMaterial {
            owner: self.0.clone(),
            material: OriginalMaterial::Live(material),
            generation,
            requirements: request.requirements.clone(),
        })
    }
    /// Controller-only acquisition that moves its already allocated candidate
    /// backing into the original Session account before a pool record is spent.
    /// Live authority can identify that account only after its one original
    /// issuance has been verified, so that path attaches before publishing the
    /// acquired material to the controller.
    pub(crate) async fn acquire_with_backing(
        &self,
        environment: &TransportEnvironment,
        request: &ConnectionRequest,
        cancellation: &CancellationToken,
        backing: &mut EnvironmentCharge,
        handlers: Option<&(crate::HandlerPlan, crate::ApplicationLimits)>,
        managed: &[crate::connection_controller_v4::ManagedServiceConfiguration],
    ) -> Result<
        (
            ConnectionMaterial,
            ResourceCharge,
            crate::crypto_v4::connect::ControllerPrepaidCharges,
        ),
        MaterialSourceError,
    > {
        if self.0.store.is_some() {
            if !self.belongs_to(environment) {
                return Err(MaterialSourceError::MaterialUnavailable);
            }
            if request
                .requirements
                .application_profile
                .as_ref()
                .is_some_and(|profile| profile != self.0.profile.name())
            {
                return Err(MaterialSourceError::ConnectionRequirementUnavailable);
            }
            if cancellation.is_cancelled() {
                return Err(MaterialSourceError::Canceled);
            }
            let mut state = self
                .0
                .state
                .lock()
                .expect("material source reserved Acquire");
            if state.closed || state.live.is_some() || self.0.root.is_closed() {
                return Err(MaterialSourceError::MaterialUnavailable);
            }
            let material = state
                .material
                .front()
                .ok_or(MaterialSourceError::MaterialUnavailable)?;
            material.supports_requirements(&request.requirements)?;
            let options = self
                .0
                .provider
                .as_ref()
                .ok_or(MaterialSourceError::MaterialUnavailable)?;
            let costs = crate::crypto_v4::connect::ControllerCandidateCosts::for_pool(
                material,
                options,
                self.0.reverse.as_ref(),
                handlers,
                managed,
            )?;
            let mut connection_backing = self
                .0
                .root
                .reserve_environment(costs.total()?)
                .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
            let mut connection_charge = connection_backing
                .attach(material.resource_account())
                .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
            let charge = backing
                .attach(material.resource_account())
                .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
            let prepaid = crate::crypto_v4::connect::ControllerPrepaidCharges::split_from(
                &mut connection_charge,
                &costs,
            )
            .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
            let acquisitions = state
                .acquisitions
                .checked_add(1)
                .ok_or(MaterialSourceError::ConfigurationCapacity)?;
            let material = match self.take_pool_material(&mut state) {
                Ok(material) => material,
                Err(failure) => {
                    drop(state);
                    if let Some(owner) = failure.close_owner {
                        owner.close();
                    }
                    return Err(failure.error);
                }
            };
            state.acquisitions = acquisitions;
            return Ok((
                ConnectionMaterial {
                    owner: self.0.clone(),
                    material: OriginalMaterial::Pool(material),
                    generation: state.generation,
                    requirements: request.requirements.clone(),
                },
                charge,
                prepaid,
            ));
        }
        if !self.belongs_to(environment) {
            return Err(MaterialSourceError::MaterialUnavailable);
        }
        if request
            .requirements
            .application_profile
            .as_ref()
            .is_some_and(|profile| profile != self.0.profile.name())
        {
            return Err(MaterialSourceError::ConnectionRequirementUnavailable);
        }
        if cancellation.is_cancelled() {
            return Err(MaterialSourceError::Canceled);
        }
        let (snapshot, generation) = {
            let mut state = self.0.state.lock().expect("live source reserved Acquire");
            if state.closed || self.0.root.is_closed() {
                return Err(MaterialSourceError::MaterialUnavailable);
            }
            if state.acquiring {
                return Err(MaterialSourceError::ConfigurationCapacity);
            }
            let snapshot = state
                .live
                .clone()
                .ok_or(MaterialSourceError::MaterialUnavailable)?;
            snapshot.supports_requirements(&request.requirements)?;
            state.acquisitions = state
                .acquisitions
                .checked_add(1)
                .ok_or(MaterialSourceError::ConfigurationCapacity)?;
            state.acquiring = true;
            (snapshot, state.generation)
        };
        let _slot = LiveAcquireSlot(self.0.clone());
        let upper = crate::crypto_v4::connect::ControllerCandidateCosts::live_upper(
            &snapshot.provider,
            snapshot.reverse.is_some(),
            handlers,
            managed,
        )?;
        let mut connection_backing = self
            .0
            .root
            .reserve_environment(upper.total()?)
            .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
        let material = snapshot
            .acquire(&request.requirements, cancellation)
            .await?;
        let costs = crate::crypto_v4::connect::ControllerCandidateCosts::for_live(
            &material, handlers, managed,
        )?;
        connection_backing
            .shrink_to(costs.total()?)
            .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
        let mut connection_charge = connection_backing
            .attach(&material.pending.account)
            .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
        let charge = backing
            .attach(&material.pending.account)
            .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
        let prepaid = crate::crypto_v4::connect::ControllerPrepaidCharges::split_from(
            &mut connection_charge,
            &costs,
        )
        .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
        Ok((
            ConnectionMaterial {
                owner: self.0.clone(),
                material: OriginalMaterial::Live(material),
                generation,
                requirements: request.requirements.clone(),
            },
            charge,
            prepaid,
        ))
    }
    pub fn preauthorized_tunnel_pool_with_server_allow(
        environment: &TransportEnvironment,
        configuration: PreauthorizedTunnelPoolSourceConfiguration,
        server_allows: Vec<crate::TunnelServerAllowConfiguration>,
    ) -> Result<Self, MaterialSourceError> {
        if server_allows.len() != configuration.credentials.len() || server_allows.capacity() > 128
        {
            return Err(MaterialSourceError::MaterialUnavailable);
        }
        Self::preauthorized_tunnel_pool(environment, configuration)?
            .capture_server_allows(server_allows)
    }
    pub fn preauthorized_reverse_tunnel_pool_with_server_allow(
        environment: &TransportEnvironment,
        configuration: PreauthorizedReverseTunnelPoolSourceConfiguration,
        server_allows: Vec<crate::TunnelServerAllowConfiguration>,
    ) -> Result<Self, MaterialSourceError> {
        if server_allows.len() != configuration.credentials.len() || server_allows.capacity() > 128
        {
            return Err(MaterialSourceError::MaterialUnavailable);
        }
        Self::preauthorized_reverse_tunnel_pool(environment, configuration)?
            .capture_server_allows(server_allows)
    }
    fn capture_server_allows(
        self,
        server_allows: Vec<crate::TunnelServerAllowConfiguration>,
    ) -> Result<Self, MaterialSourceError> {
        {
            let mut state = self.0.state.lock().expect("original tunnel pool source");
            if state.closed
                || self.0.root.is_closed()
                || server_allows.len() != state.material.len()
            {
                return Err(MaterialSourceError::MaterialUnavailable);
            }
            // Rotate exactly the original batch length. This transfers setup
            // into its existing material owner while preserving lease order.
            for configuration in server_allows {
                let material = state
                    .material
                    .pop_front()
                    .ok_or(MaterialSourceError::MaterialUnavailable)?;
                state
                    .material
                    .push_back(material.with_tunnel_server_allow(configuration)?);
            }
        }
        Ok(self)
    }
    pub fn preauthorized_tunnel_pool(
        environment: &TransportEnvironment,
        configuration: PreauthorizedTunnelPoolSourceConfiguration,
    ) -> Result<Self, MaterialSourceError> {
        let PreauthorizedTunnelPoolSourceConfiguration {
            namespaces,
            identity,
            credentials,
            spend_ledger,
            provider,
            application_profile,
            relay_service,
            relay_audience,
        } = configuration;
        let common = PreauthorizedPoolSourceConfiguration {
            namespaces,
            identity,
            credentials: Vec::new(),
            spend_ledger,
            provider,
            application_profile,
        };
        Self::pool_records(
            environment,
            common,
            Some((credentials, relay_service, relay_audience)),
            None,
        )
    }
    pub fn preauthorized_reverse_tunnel_pool(
        environment: &TransportEnvironment,
        configuration: PreauthorizedReverseTunnelPoolSourceConfiguration,
    ) -> Result<Self, MaterialSourceError> {
        let PreauthorizedReverseTunnelPoolSourceConfiguration {
            namespaces,
            identity,
            credentials,
            spend_ledger,
            provider,
            application_profile,
            relay_service,
            relay_audience,
        } = configuration;
        let (reverse, provider) =
            crate::crypto_v4::connect::reverse::Capture::new(environment.root().clone(), provider)?;
        let common = PreauthorizedPoolSourceConfiguration {
            namespaces,
            identity,
            credentials: Vec::new(),
            spend_ledger,
            provider,
            application_profile,
        };
        Self::pool_records(
            environment,
            common,
            Some((credentials, relay_service, relay_audience)),
            Some(reverse),
        )
    }
    fn pool(
        environment: &TransportEnvironment,
        configuration: PreauthorizedPoolSourceConfiguration,
    ) -> Result<Self, MaterialSourceError> {
        Self::pool_records(environment, configuration, None, None)
    }
    fn pool_records(
        environment: &TransportEnvironment,
        configuration: PreauthorizedPoolSourceConfiguration,
        tunnel: Option<(Vec<TunnelPoolCredentialBytes>, String, String)>,
        reverse: Option<Arc<crate::crypto_v4::connect::reverse::Capture>>,
    ) -> Result<Self, MaterialSourceError> {
        let count = tunnel
            .as_ref()
            .map_or(configuration.credentials.len(), |(records, _, _)| {
                records.len()
            });
        let namespace_limit = if tunnel.is_some() { 8 } else { 3 };
        if count > 128
            || configuration.namespaces.capacity() > namespace_limit
            || tunnel.as_ref().is_some_and(|(_, service, audience)| {
                service.is_empty()
                    || audience.is_empty()
                    || service.capacity() > 128
                    || audience.capacity() > 128
            })
            || configuration.provider.ca_certificates_der.capacity() > 32
            || !configuration.spend_ledger.belongs_to(environment.root())
            || configuration.provider.ca_certificates_der.len() > 32
            || configuration
                .provider
                .origin
                .as_ref()
                .is_some_and(|origin| origin.len() > 2048 || origin.capacity() > 4096)
            || configuration.provider.timeout.is_zero()
            || configuration.provider.timeout > Duration::from_secs(30)
            || configuration.provider.publication_timeout.is_zero()
            || configuration.provider.publication_timeout > Duration::from_secs(5)
            || !(1..=64).contains(&configuration.provider.queue_messages)
            || !(16384..=262144).contains(&configuration.provider.prepare_bytes)
            || configuration.provider.native_runtime_bytes < 1 << 20
        {
            return Err(MaterialSourceError::MaterialUnavailable);
        }
        let tls_bytes = configuration
            .provider
            .ca_certificates_der
            .iter()
            .try_fold(0u64, |total, certificate| {
                if certificate.is_empty()
                    || certificate.len() > 65536
                    || certificate.capacity() > 65536
                {
                    return None;
                }
                total.checked_add(certificate.capacity() as u64)
            })
            .ok_or(MaterialSourceError::ConfigurationCapacity)?;
        let charge = environment
            .root()
            .reserve_environment(ResourceLimits {
                sdk_bytes: 8192 + tls_bytes + 128 * 256,
                items: 128 + 4,
                work_slots: 1,
                ..ResourceLimits::default()
            })
            .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
        let (material, tunnel_scope) = if let Some((records, service, audience)) = tunnel {
            let material = capture_tunnel_batch(
                environment.root(),
                &configuration.namespaces,
                &configuration.identity,
                records,
                configuration.application_profile,
                &service,
                &audience,
            )?;
            (material, Some((service, audience)))
        } else {
            (
                capture_batch(
                    environment.root(),
                    &configuration.namespaces,
                    &configuration.identity,
                    configuration.credentials,
                    configuration.application_profile,
                )?,
                None,
            )
        };
        for original in &material {
            if let Some(reverse) = &reverse {
                reverse.validate(original, &configuration.provider)?;
            } else {
                original.validate_provider(&configuration.provider)?;
            }
        }
        let source = Self(Arc::new(Owner {
            root: environment.root().clone(),
            namespaces: configuration.namespaces,
            store: Some(configuration.spend_ledger),
            provider: Some(configuration.provider),
            profile: configuration.application_profile,
            capacity: 128,
            tunnel_scope,
            reverse,
            top_up: Mutex::new(None),
            state: Mutex::new(PoolState {
                material,
                live: None,
                generation: 1,
                acquisitions: 0,
                closed: false,
                acquiring: false,
                durable: std::collections::BTreeSet::new(),
            }),
            _charge: charge,
        }));
        environment
            .root()
            .register_material_source(&source.0)
            .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
        Ok(source)
    }
    pub(crate) fn top_up_store_context(
        &self,
    ) -> Result<(Arc<EnvironmentRoot>, Arc<SQLitePoolStore>), MaterialSourceError> {
        let state = self.0.state.lock().expect("original durable pool source");
        if state.closed
            || self.0.root.is_closed()
            || state.live.is_some()
            || self.0.tunnel_scope.is_some()
            || self.0.reverse.is_some()
        {
            return Err(MaterialSourceError::SourceUnavailable);
        }
        Ok((
            self.0.root.clone(),
            self.0
                .store
                .clone()
                .ok_or(MaterialSourceError::SourceContractInvalid)?,
        ))
    }
    pub(crate) fn top_up_context(
        &self,
        identity: &IdentityKeys,
        certificate: &[u8],
    ) -> Result<(Arc<EnvironmentRoot>, Arc<SQLitePoolStore>), MaterialSourceError> {
        if !identity.belongs_to(&self.0.root)
            || identity.verify_certificate_identity(certificate).is_err()
            || self.0.tunnel_scope.is_some()
            || self.0.reverse.is_some()
            || certificate.is_empty()
            || certificate.len() > 8192
        {
            return Err(MaterialSourceError::SourceContractInvalid);
        }
        let state = self
            .0
            .state
            .lock()
            .expect("original TopUp identity capture");
        if state.closed
            || state.live.is_some()
            || state
                .material
                .iter()
                .any(|material| !material.matches_top_up_identity(identity, certificate))
        {
            return Err(MaterialSourceError::SourceContractInvalid);
        }
        Ok((
            self.0.root.clone(),
            self.0
                .store
                .clone()
                .ok_or(MaterialSourceError::SourceContractInvalid)?,
        ))
    }
    pub(crate) fn release_top_up(&self, owner: &Arc<crate::top_up_v4::TopUpOwner>) {
        let mut current = self.0.top_up.lock().expect("unique original TopUp owner");
        let matches = current
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .is_some_and(|existing| Arc::ptr_eq(&existing, owner));
        if matches {
            *current = None;
        }
    }
    pub(crate) fn claim_top_up(
        &self,
        owner: &Arc<crate::top_up_v4::TopUpOwner>,
    ) -> Result<(), MaterialSourceError> {
        let mut current = self.0.top_up.lock().expect("unique original TopUp owner");
        if current
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .is_some()
        {
            return Err(MaterialSourceError::SourceContractInvalid);
        }
        *current = Some(Arc::downgrade(owner));
        Ok(())
    }
    pub(crate) fn restore_top_up_materials(
        &self,
        identity: &IdentityKeys,
        certificate: &[u8],
        mut entries: Vec<crate::pool_v4::top_up::InstalledMaterial>,
        decoder: &dyn crate::top_up_v4::TopUpMaterialDecoder,
        owner: &Arc<crate::top_up_v4::TopUpOwner>,
        expected_acquisitions: u64,
    ) -> Result<(), MaterialSourceError> {
        let now = self
            .0
            .root
            .sample()
            .map_err(|_| MaterialSourceError::SourceUnavailable)?;
        for entry in entries.iter().filter(|entry| entry.expiry <= now.upper_ms) {
            owner
                .consume_material(&entry.artifact)
                .map_err(|_| MaterialSourceError::SourceUnavailable)?;
        }
        entries.retain(|entry| entry.expiry > now.upper_ms);
        self.install_top_up_materials(
            identity,
            certificate,
            &mut entries,
            decoder,
            owner,
            Some(expected_acquisitions),
            |_| Ok(()),
        )
        .map_err(|_| MaterialSourceError::SourceContractInvalid)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Top-up installation binds the original source generation and decoder to the same guarded commit."
    )]
    pub(crate) fn install_top_up_materials(
        &self,
        identity: &IdentityKeys,
        certificate: &[u8],
        entries: &mut [crate::pool_v4::top_up::InstalledMaterial],
        decoder: &dyn crate::top_up_v4::TopUpMaterialDecoder,
        owner: &Arc<crate::top_up_v4::TopUpOwner>,
        expected_acquisitions: Option<u64>,
        commit: impl FnOnce(
            &[crate::pool_v4::top_up::InstalledMaterial],
        ) -> Result<(), crate::top_up_v4::TopUpError>,
    ) -> Result<(), crate::top_up_v4::TopUpError> {
        use crate::top_up_v4::{TopUpError, TopUpErrorCode};
        let refused = || TopUpError(TopUpErrorCode::SourceContractInvalid);
        let now = self
            .0
            .root
            .sample()
            .map_err(|_| TopUpError(TopUpErrorCode::SourceUnavailable))?;
        let mut credentials = Vec::with_capacity(entries.len());
        for entry in entries.iter_mut() {
            if entry.expiry <= now.upper_ms {
                return Err(TopUpError(TopUpErrorCode::RelinkRequired));
            }
            let credential = decoder.decode(&entry.bytes)?;
            let artifact = crate::codec_v4::decode(
                &credential.artifact,
                "Artifact",
                crate::codec_v4::Limits {
                    bytes: 65536,
                    nodes: 16384,
                },
                None,
            )
            .map_err(|_| refused())?;
            let signed_end = artifact
                .field("Artifact", "initiation_not_after_ms")
                .and_then(crate::codec_v4::Value::uint)
                .map_err(|_| refused())?;
            if entry.expiry > signed_end {
                return Err(refused());
            }
            let digest =
                crate::codec_v4::digest("artifact_digest", artifact).map_err(|_| refused())?;
            if entry.artifact != [0; 32] && entry.artifact != digest {
                return Err(refused());
            }
            entry.artifact = digest;
            credentials.push(credential);
        }
        let captured = capture_batch(
            &self.0.root,
            &self.0.namespaces,
            identity,
            credentials,
            self.0.profile,
        )
        .map_err(|_| refused())?;
        for material in &captured {
            if !material.matches_top_up_identity(identity, certificate) {
                return Err(refused());
            }
            material
                .validate_provider(self.0.provider.as_ref().ok_or_else(refused)?)
                .map_err(|_| refused())?;
        }
        let mut state = self
            .0
            .state
            .lock()
            .expect("whole Applied batch publication");
        if state.closed || self.0.root.is_closed() {
            return Err(TopUpError(TopUpErrorCode::SourceUnavailable));
        }
        if expected_acquisitions.is_some_and(|expected| state.acquisitions != expected) {
            // Acquire consumed or otherwise advanced the source after the
            // durable snapshot. Never reinsert that stale batch.
            return Err(TopUpError(TopUpErrorCode::SourceStateUnknown));
        }
        let original = self
            .0
            .top_up
            .lock()
            .expect("original pool TopUp ownership")
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .ok_or_else(refused)?;
        if !Arc::ptr_eq(&original, owner)
            || state
                .material
                .len()
                .checked_add(captured.len())
                .is_none_or(|count| count > self.0.capacity)
        {
            return Err(TopUpError(TopUpErrorCode::CapacityExhausted));
        }
        if captured.iter().any(|candidate| {
            state
                .material
                .iter()
                .any(|old| old.internal_artifact_digest() == candidate.internal_artifact_digest())
        }) {
            return Err(TopUpError(TopUpErrorCode::OperationConflict));
        }
        commit(entries)?;
        for material in captured {
            state.durable.insert(material.internal_artifact_digest());
            state.material.push_back(material);
        }
        Ok(())
    }
    pub(crate) fn belongs_to(&self, environment: &TransportEnvironment) -> bool {
        Arc::ptr_eq(environment.root(), &self.0.root)
            && self
                .0
                .store
                .as_ref()
                .is_none_or(|store| store.belongs_to(environment.root()))
    }
    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    /// Source authorization profiles are captured at construction. A controller
    /// may rotate among independent owners only within the original profile.
    pub(crate) fn same_activation_profile(&self, other: &Self) -> bool {
        self.0.store.is_some() == other.0.store.is_some()
    }
    /// Wait for the original reverse listener to bind during Connect. The
    /// observation is bounded and does not authorize or activate its carrier.
    pub async fn wait_reverse_listener_ready(
        &self,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> Result<std::net::SocketAddr, ConnectionError> {
        let capture = self
            .0
            .reverse
            .as_ref()
            .ok_or(MaterialSourceError::MaterialUnavailable)?;
        Ok(capture.wait_ready(timeout, cancellation).await?)
    }
    pub fn acquisition_observation(&self) -> MaterialAcquisitionObservation {
        let state = self
            .0
            .state
            .lock()
            .expect("original source acquisition observation");
        MaterialAcquisitionObservation {
            acquisitions: state.acquisitions,
            generation: state.generation,
        }
    }
    pub fn application_profile(&self) -> ApplicationProfile {
        self.0.profile
    }
    pub fn is_closed(&self) -> bool {
        self.0.state.lock().expect("material source").closed || self.0.root.is_closed()
    }
    pub fn close(&self) {
        self.0.close();
    }
    /// Publish one complete new snapshot. Failure leaves the previous snapshot
    /// intact, and previously acquired records keep their original identity.
    pub fn replace_pool_generation(
        &self,
        credentials: Vec<PoolCredentialBytes>,
        identity: IdentityKeys,
    ) -> Result<(), MaterialSourceError> {
        if self
            .0
            .top_up
            .lock()
            .expect("original TopUp source")
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .is_some()
        {
            return Err(MaterialSourceError::SourceContractInvalid);
        }
        if self.0.tunnel_scope.is_some() {
            return Err(MaterialSourceError::ConnectionRequirementUnavailable);
        }
        if credentials.is_empty() || credentials.len() > self.0.capacity {
            return Err(MaterialSourceError::ConfigurationCapacity);
        }
        let observed_generation = {
            let state = self.0.state.lock().expect("material source");
            if state.closed || state.live.is_some() {
                return Err(MaterialSourceError::MaterialUnavailable);
            }
            state.generation
        };
        let captured = capture_batch(
            &self.0.root,
            &self.0.namespaces,
            &identity,
            credentials,
            self.0.profile,
        )?;
        for original in &captured {
            original.validate_provider(
                self.0
                    .provider
                    .as_ref()
                    .ok_or(MaterialSourceError::MaterialUnavailable)?,
            )?;
        }
        let old = {
            let mut state = self.0.state.lock().expect("material source replacement");
            if state.closed || state.generation != observed_generation {
                return Err(MaterialSourceError::MaterialUnavailable);
            }
            state.generation = state
                .generation
                .checked_add(1)
                .ok_or(MaterialSourceError::ConfigurationCapacity)?;
            std::mem::replace(&mut state.material, captured)
        };
        drop(old);
        Ok(())
    }
    pub fn replace_tunnel_pool_generation(
        &self,
        credentials: Vec<TunnelPoolCredentialBytes>,
        identity: IdentityKeys,
    ) -> Result<(), MaterialSourceError> {
        let (service, audience) = self
            .0
            .tunnel_scope
            .as_ref()
            .ok_or(MaterialSourceError::ConnectionRequirementUnavailable)?;
        if credentials.is_empty() || credentials.len() > self.0.capacity {
            return Err(MaterialSourceError::ConfigurationCapacity);
        }
        let observed = {
            let state = self.0.state.lock().expect("tunnel pool generation");
            if state.closed || state.live.is_some() {
                return Err(MaterialSourceError::MaterialUnavailable);
            }
            state.generation
        };
        let captured = capture_tunnel_batch(
            &self.0.root,
            &self.0.namespaces,
            &identity,
            credentials,
            self.0.profile,
            service,
            audience,
        )?;
        let provider = self
            .0
            .provider
            .as_ref()
            .ok_or(MaterialSourceError::MaterialUnavailable)?;
        for original in &captured {
            if let Some(reverse) = &self.0.reverse {
                reverse.validate(original, provider)?;
            } else {
                original.validate_provider(provider)?;
            }
        }
        let old = {
            let mut state = self.0.state.lock().expect("tunnel pool publication");
            if state.closed || state.generation != observed {
                return Err(MaterialSourceError::MaterialUnavailable);
            }
            state.generation = state
                .generation
                .checked_add(1)
                .ok_or(MaterialSourceError::ConfigurationCapacity)?;
            std::mem::replace(&mut state.material, captured)
        };
        drop(old);
        Ok(())
    }
    fn take_pool_material(
        &self,
        state: &mut PoolState,
    ) -> std::result::Result<PoolConnectionMaterial, PoolMaterialError> {
        let material = state
            .material
            .pop_front()
            .ok_or_else(|| PoolMaterialError::plain(MaterialSourceError::SourceExhausted))?;
        let artifact = material.internal_artifact_digest();
        if state.durable.contains(&artifact) {
            let owner = self
                .0
                .top_up
                .lock()
                .expect("original durable pool acquisition")
                .as_ref()
                .and_then(std::sync::Weak::upgrade);
            let Some(owner) = owner else {
                state.material.push_front(material);
                return Err(PoolMaterialError::plain(
                    MaterialSourceError::SourceUnavailable,
                ));
            };
            if let Err(error) = owner.consume_material(&artifact) {
                let fenced = matches!(
                    error.code,
                    crate::PoolStoreFailure::Fenced
                        | crate::PoolStoreFailure::HistoryUnknown
                        | crate::PoolStoreFailure::StorageFormat
                        | crate::PoolStoreFailure::Closed
                        | crate::PoolStoreFailure::OwnerUnavailable
                );
                if error.write_state == crate::PoolWriteState::NotSubmitted && !fenced {
                    // Nothing was submitted; this original material remains
                    // unused. End only this call, without hiding other entries.
                    state.material.push_front(material);
                    return Err(PoolMaterialError::plain(
                        MaterialSourceError::SourceUnavailable,
                    ));
                }
                // Unknown removal or lost durable ownership blocks this source's
                // original acquisition gate. Keep unrelated material backing
                // until source cleanup; the owner is closed by the caller after
                // releasing the source state mutex.
                state.closed = true;
                return Err(PoolMaterialError::close(
                    owner,
                    if error.write_state == crate::PoolWriteState::Unknown {
                        MaterialSourceError::SpentUnknown
                    } else {
                        MaterialSourceError::SourceUnavailable
                    },
                ));
            }
            state.durable.remove(&artifact);
        }
        Ok(material)
    }
    pub fn acquire(
        &self,
        environment: &TransportEnvironment,
        request: &ConnectionRequest,
        cancellation: &CancellationToken,
    ) -> Result<ConnectionMaterial, MaterialSourceError> {
        // Profile and original provider refusal precede removal of any record.
        if !self.belongs_to(environment) {
            return Err(MaterialSourceError::MaterialUnavailable);
        }
        if request
            .requirements
            .application_profile
            .as_ref()
            .is_some_and(|profile| profile != self.0.profile.name())
        {
            return Err(MaterialSourceError::ConnectionRequirementUnavailable);
        }
        if cancellation.is_cancelled() {
            return Err(MaterialSourceError::Canceled);
        }
        let mut state = self.0.state.lock().expect("material source Acquire");
        if state.closed || state.live.is_some() || self.0.root.is_closed() {
            return Err(MaterialSourceError::SourceUnavailable);
        }
        let material = state
            .material
            .front()
            .ok_or(MaterialSourceError::SourceExhausted)?;
        material.supports_requirements(&request.requirements)?;
        let acquisitions = state
            .acquisitions
            .checked_add(1)
            .ok_or(MaterialSourceError::ConfigurationCapacity)?;
        let material = match self.take_pool_material(&mut state) {
            Ok(material) => material,
            Err(failure) => {
                drop(state);
                if let Some(owner) = failure.close_owner {
                    owner.close();
                }
                return Err(failure.error);
            }
        };
        state.acquisitions = acquisitions;
        Ok(ConnectionMaterial {
            owner: self.0.clone(),
            material: OriginalMaterial::Pool(material),
            generation: state.generation,
            requirements: request.requirements.clone(),
        })
    }
}
fn capture_batch(
    root: &Arc<EnvironmentRoot>,
    namespaces: &[Arc<Namespace>],
    identity: &IdentityKeys,
    credentials: Vec<PoolCredentialBytes>,
    profile: ApplicationProfile,
) -> Result<VecDeque<PoolConnectionMaterial>, MaterialSourceError> {
    let mut captured = VecDeque::with_capacity(credentials.len());
    let mut leases = std::collections::BTreeSet::new();
    for bytes in credentials {
        let artifact = crate::codec_v4::decode(
            &bytes.artifact,
            "Artifact",
            crate::codec_v4::Limits {
                bytes: 65536,
                nodes: 16384,
            },
            None,
        )
        .map_err(|_| MaterialSourceError::MaterialUnavailable)?;
        if artifact
            .field("Artifact", "session_contract")
            .and_then(|contract| contract.u("SessionContract", "application_profile"))
            .map_err(|_| MaterialSourceError::MaterialUnavailable)?
            != profile.wire()
        {
            return Err(MaterialSourceError::ConnectionRequirementUnavailable);
        }
        let digest = crate::codec_v4::digest("artifact_digest", artifact)
            .map_err(|_| MaterialSourceError::MaterialUnavailable)?;
        if !leases.insert(digest) {
            return Err(MaterialSourceError::MaterialUnavailable);
        }
        captured.push_back(PoolConnectionMaterial::new(
            root.clone(),
            namespaces.to_vec(),
            identity.clone(),
            bytes,
        )?);
    }
    Ok(captured)
}
fn capture_tunnel_batch(
    root: &Arc<EnvironmentRoot>,
    namespaces: &[Arc<Namespace>],
    identity: &IdentityKeys,
    credentials: Vec<TunnelPoolCredentialBytes>,
    profile: ApplicationProfile,
    service: &str,
    audience: &str,
) -> Result<VecDeque<PoolConnectionMaterial>, MaterialSourceError> {
    let mut captured = VecDeque::with_capacity(credentials.len());
    let mut leases = std::collections::BTreeSet::new();
    for bytes in credentials {
        let artifact = crate::codec_v4::decode(
            &bytes.connection.artifact,
            "Artifact",
            crate::codec_v4::Limits {
                bytes: 65536,
                nodes: 16384,
            },
            None,
        )
        .map_err(|_| MaterialSourceError::MaterialUnavailable)?;
        if artifact
            .field("Artifact", "session_contract")
            .and_then(|contract| contract.u("SessionContract", "application_profile"))
            .map_err(|_| MaterialSourceError::MaterialUnavailable)?
            != profile.wire()
        {
            return Err(MaterialSourceError::ConnectionRequirementUnavailable);
        }
        let digest = crate::codec_v4::digest("artifact_digest", artifact)
            .map_err(|_| MaterialSourceError::MaterialUnavailable)?;
        if !leases.insert(digest) {
            return Err(MaterialSourceError::MaterialUnavailable);
        }
        captured.push_back(PoolConnectionMaterial::new_tunnel(
            root.clone(),
            namespaces.to_vec(),
            identity.clone(),
            bytes,
            service,
            audience,
            crate::crypto_v4::Role::Client,
        )?);
    }
    Ok(captured)
}
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error(transparent)]
    Source(#[from] MaterialSourceError),
    #[error(transparent)]
    Connect(#[from] crate::TransportConnectError),
}
impl ConnectionError {
    /// Detached evidence captured at the original spend/admission/READY gates.
    /// This projection performs no query and carries no credential or Session.
    pub fn connection_facts(&self) -> crate::ConnectionAttemptFacts {
        match self {
            Self::Source(_) => crate::TransportConnectError::Configuration.connection_facts(),
            Self::Connect(error) => error.connection_facts(),
        }
    }
}
impl TransportEnvironment {
    /// Ordinary source entry point. Exactly one SDK Acquire supplies the whole
    /// material before the existing winner, spend, activation and READY flow.
    pub async fn connect(
        &self,
        source: &ConnectionMaterialSource,
        request: ConnectionRequest,
        cancellation: CancellationToken,
    ) -> Result<crate::Session, ConnectionError> {
        let handlers = request
            .handlers
            .as_ref()
            .map(|(plan, limits)| {
                let captured = plan
                    .capture(self.root())
                    .map_err(|_| crate::TransportConnectError::Authorization)?;
                captured
                    .validate_limits(*limits)
                    .map_err(|_| crate::TransportConnectError::Configuration)?;
                Ok::<_, crate::TransportConnectError>((captured, *limits))
            })
            .transpose()?;
        let material = source.acquire_async(self, &request, &cancellation).await?;
        self.connect_material_with_handlers(material, handlers, cancellation)
            .await
    }
    /// Advanced entry point for an already acquired immutable set. Closing or
    /// replacing its source cannot redirect this original attempt.
    pub async fn connect_material(
        &self,
        material: ConnectionMaterial,
        cancellation: CancellationToken,
    ) -> Result<crate::Session, ConnectionError> {
        self.connect_material_with_handlers(material, None, cancellation)
            .await
    }
    pub async fn connect_material_with_handlers(
        &self,
        material: ConnectionMaterial,
        handlers: Option<(crate::HandlerPlan, crate::ApplicationLimits)>,
        cancellation: CancellationToken,
    ) -> Result<crate::Session, ConnectionError> {
        self.connect_material_with_handlers_and_prepaid(
            material,
            handlers,
            cancellation,
            None,
            None,
        )
        .await
    }
    pub(crate) async fn connect_material_with_controller_prepaid(
        &self,
        material: ConnectionMaterial,
        handlers: Option<(crate::HandlerPlan, crate::ApplicationLimits)>,
        cancellation: CancellationToken,
        prepaid: crate::crypto_v4::connect::ControllerPrepaidCharges,
        notification_hook: Arc<dyn crate::connection_controller_v4::NotificationCandidateHook>,
    ) -> Result<crate::Session, ConnectionError> {
        self.connect_material_with_handlers_and_prepaid(
            material,
            handlers,
            cancellation,
            Some(prepaid),
            Some(notification_hook),
        )
        .await
    }
    async fn connect_material_with_handlers_and_prepaid(
        &self,
        material: ConnectionMaterial,
        handlers: Option<(crate::HandlerPlan, crate::ApplicationLimits)>,
        cancellation: CancellationToken,
        prepaid: Option<crate::crypto_v4::connect::ControllerPrepaidCharges>,
        notification_hook: Option<
            Arc<dyn crate::connection_controller_v4::NotificationCandidateHook>,
        >,
    ) -> Result<crate::Session, ConnectionError> {
        if !Arc::ptr_eq(self.root(), &material.owner.root) {
            return Err(MaterialSourceError::MaterialUnavailable.into());
        }
        let ConnectionMaterial {
            owner,
            material,
            generation: _generation,
            requirements,
        } = material;
        match material {
            OriginalMaterial::Pool(material) => {
                let store = owner
                    .store
                    .clone()
                    .ok_or(MaterialSourceError::MaterialUnavailable)?;
                let provider = owner
                    .provider
                    .clone()
                    .ok_or(MaterialSourceError::MaterialUnavailable)?;
                let session = match prepaid {
                    Some(prepaid) => {
                        crate::crypto_v4::connect::connect_with_provider_requirements_prepaid(
                            self,
                            material,
                            store,
                            provider,
                            handlers,
                            requirements,
                            owner.reverse.clone(),
                            cancellation,
                            prepaid,
                            notification_hook.clone(),
                        )
                        .await?
                    }
                    None => {
                        crate::crypto_v4::connect::connect_with_provider_requirements(
                            self,
                            material,
                            store,
                            provider,
                            handlers,
                            requirements,
                            owner.reverse.clone(),
                            cancellation,
                        )
                        .await?
                    }
                };
                Ok(session)
            }
            OriginalMaterial::Live(material) => {
                let session = match prepaid {
                    Some(prepaid) => {
                        crate::crypto_v4::connect::connect_live_with_handler_plan_prepaid(
                            self,
                            material,
                            handlers,
                            requirements,
                            cancellation,
                            prepaid,
                            notification_hook,
                        )
                        .await?
                    }
                    None => {
                        crate::crypto_v4::connect::connect_live_with_handler_plan(
                            self,
                            material,
                            handlers,
                            requirements,
                            cancellation,
                        )
                        .await?
                    }
                };
                Ok(session)
            }
        }
    }
}

/// Establish the current transport Session from one captured material source.
/// Exactly one SDK Acquire supplies the original identity, provider and spend
/// authority before the winner, activation and READY flow begins.
pub async fn connect(
    environment: &TransportEnvironment,
    source: &ConnectionMaterialSource,
    request: ConnectionRequest,
    cancellation: CancellationToken,
) -> Result<crate::Session, ConnectionError> {
    environment.connect(source, request, cancellation).await
}
