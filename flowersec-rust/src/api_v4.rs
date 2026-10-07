use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::environment_v4::{
    EnvironmentError, EnvironmentRoot, ResourceAccount, ResourceCharge, ResourceLimits,
    TransportEnvironmentOptions, WeakResourceAccount,
};
use bytes::Bytes;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio::time::{Instant, sleep_until};
use tokio_util::sync::CancellationToken;

const MAX_PREPARED_WRITE_BYTES: usize = 2_162_688;
const MAX_PREPARED_WRITE_OPERATIONS: usize = 128;
const PREPARED_WRITE_LIFETIME: Duration = Duration::from_secs(60);

/// The original provider session's finite prepared-write budget.
///
/// Every stream in one session must expose the same owner. This capability is
/// only a resource owner; it does not grant transport or application authority.
#[derive(Debug)]
pub struct WriteStagingOwner {
    state: Mutex<WriteStagingState>,
    lifetime: Duration,
    changed: Notify,
    account: Option<ResourceAccount>,
}
#[derive(Debug, Default)]
struct WriteStagingState {
    bytes: usize,
    operations: usize,
    closed: bool,
}
impl Default for WriteStagingOwner {
    fn default() -> Self {
        Self {
            state: Mutex::new(WriteStagingState::default()),
            lifetime: PREPARED_WRITE_LIFETIME,
            changed: Notify::new(),
            account: None,
        }
    }
}
impl WriteStagingOwner {
    /// Construct once for a provider session, then share across its streams.
    pub fn new() -> Self {
        Self::default()
    }
    pub(crate) fn from_account(account: ResourceAccount) -> Self {
        Self {
            account: Some(account),
            ..Self::new()
        }
    }
    /// Seal new preparation and unaccepted suffixes. Outstanding native writes
    /// retain their reservations until they actually exit.
    pub fn close(&self) {
        self.state.lock().expect("write staging lock").closed = true;
        self.changed.notify_waiters();
    }
    fn reserve(self: &Arc<Self>, bytes: usize) -> Result<WriteReservations, SessionError> {
        self.reserve_with_backing(bytes, None)
    }
    fn reserve_with_backing(
        self: &Arc<Self>,
        bytes: usize,
        prepaid: Option<ResourceCharge>,
    ) -> Result<WriteReservations, SessionError> {
        let limits = WriteOperation::preparation_limits(bytes)?;
        let mut charge = if let Some(charge) = prepaid {
            let account = self.account.as_ref().ok_or(SessionError::OperationFailed)?;
            if !charge.matches(account, limits) {
                return Err(SessionError::OperationFailed);
            }
            Some(charge)
        } else {
            self.account
                .as_ref()
                .map(|account| account.reserve(limits))
                .transpose()
                .map_err(environment_session_error)?
        };
        let data_charge = charge
            .as_mut()
            .map(|charge| {
                charge.split(ResourceLimits {
                    sdk_bytes: bytes as u64,
                    ..ResourceLimits::default()
                })
            })
            .transpose()
            .map_err(environment_session_error)?;
        let timer_charge = charge
            .as_mut()
            .map(|charge| {
                charge.split(ResourceLimits {
                    tasks: 1,
                    timers: 1,
                    ..ResourceLimits::default()
                })
            })
            .transpose()
            .map_err(environment_session_error)?;
        let native_charge = charge
            .as_mut()
            .map(|charge| {
                charge.split(ResourceLimits {
                    tasks: 1,
                    ..ResourceLimits::default()
                })
            })
            .transpose()
            .map_err(environment_session_error)?;
        let mut state = self.state.lock().expect("write staging lock");
        if state.closed {
            return Err(SessionError::Closed);
        }
        if bytes > MAX_PREPARED_WRITE_BYTES
            || state.operations >= MAX_PREPARED_WRITE_OPERATIONS
            || state
                .bytes
                .checked_add(bytes)
                .is_none_or(|n| n > MAX_PREPARED_WRITE_BYTES)
        {
            return Err(SessionError::ResourceExhausted);
        }
        let deadline = Instant::now()
            .checked_add(self.lifetime)
            .ok_or(SessionError::OperationFailed)?;
        state.bytes += bytes;
        state.operations += 1;
        Ok(WriteReservations {
            staging: WriteStagingReservation {
                owner: self.clone(),
                bytes,
                _charge: data_charge,
            },
            metadata: WriteMetadataReservation {
                owner: self.clone(),
                _charge: charge,
            },
            deadline,
            timer_charge,
            native_charge,
        })
    }
}
/// An original staging vector acquired before a bridge source read.  Moving
/// it into a WriteOperation preserves the same slot and physical charges.
pub(crate) struct BridgeWriteReservation {
    reservations: WriteReservations,
    maximum_bytes: usize,
}
struct WriteReservations {
    staging: WriteStagingReservation,
    metadata: WriteMetadataReservation,
    deadline: Instant,
    timer_charge: Option<ResourceCharge>,
    native_charge: Option<ResourceCharge>,
}
struct WriteStagingReservation {
    owner: Arc<WriteStagingOwner>,
    bytes: usize,
    _charge: Option<ResourceCharge>,
}
impl Drop for WriteStagingReservation {
    fn drop(&mut self) {
        self.owner.state.lock().expect("write staging lock").bytes -= self.bytes;
    }
}
struct WriteMetadataReservation {
    owner: Arc<WriteStagingOwner>,
    _charge: Option<ResourceCharge>,
}
impl Drop for WriteMetadataReservation {
    fn drop(&mut self) {
        self.owner
            .state
            .lock()
            .expect("write staging lock")
            .operations -= 1;
    }
}

use crate::transport::{ByteStream, SessionError};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConnectionRequirements {
    pub independent_reliable_read_progress: bool,
    pub bound_stream_input_isolation: bool,
    pub datagram: bool,
    pub local_consumer_tls13_verification: bool,
    pub application_profile: Option<String>,
}

#[derive(Debug)]
pub struct TransportEnvironment {
    root: Arc<EnvironmentRoot>,
}
impl Drop for TransportEnvironment {
    fn drop(&mut self) {
        self.root.close();
    }
}
impl Default for TransportEnvironment {
    fn default() -> Self {
        Self::with_options(TransportEnvironmentOptions::default())
            .expect("default environment capacities")
    }
}
impl TransportEnvironment {
    pub fn new() -> Self {
        Self::default()
    }
    pub(crate) fn root(&self) -> &Arc<EnvironmentRoot> {
        &self.root
    }
    pub fn with_options(options: TransportEnvironmentOptions) -> Result<Self, EnvironmentError> {
        Ok(Self {
            root: EnvironmentRoot::new(options)?,
        })
    }
    /// Bind the fixed live tunnel authority controls to this environment.
    /// The returned owner keeps both control transports on the same resource and
    /// namespace root as every source or session created from this environment.
    pub fn live_tunnel_authority_control(
        &self,
        configuration: crate::LiveTunnelAuthorityControlConfiguration,
    ) -> Result<Arc<crate::LiveTunnelAuthorityControl>, crate::MaterialSourceError> {
        crate::live_material_source_v4::LiveTunnelAuthorityControl::new(
            self.root.clone(),
            configuration,
        )
    }
    // The transport assembly owns this verifier until all namespace users exit.
    // Construction alone does not bootstrap trust or publish a live Session.
    pub(crate) fn namespace_verifier(
        &self,
        root: crate::namespace_v4::verifier::NamespaceTrustRoot,
        state_bytes: usize,
        node_cap: usize,
    ) -> Result<crate::namespace_v4::verifier::NamespaceVerifier, EnvironmentError> {
        crate::namespace_v4::verifier::NamespaceVerifier::new(
            self.root.clone(),
            root,
            state_bytes,
            node_cap,
        )
    }
    /// Credential admission is private until the native v4 carrier, original
    /// spend/admission and Noise/READY assembly can consume this same owner.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "The native v4 connection assembly is not yet wired"
        )
    )]
    pub(crate) fn reserve_direct_credentials(
        &self,
        verifiers: &[&crate::namespace_v4::verifier::NamespaceVerifier],
        input: crate::namespace_v4::verifier::credential::DirectCredentialInput<'_>,
    ) -> Result<crate::namespace_v4::verifier::credential::CredentialAdmission, EnvironmentError>
    {
        crate::namespace_v4::verifier::credential::reserve_direct_connection(
            &self.root, verifiers, input,
        )
    }
    #[cfg(test)]
    pub(crate) fn adopt_ready_session(
        &self,
        engine: crate::crypto_v4::RecordEngine,
        transport: Box<dyn crate::crypto_v4::SessionTransport>,
    ) -> Result<crate::crypto_v4::Session, SessionError> {
        crate::crypto_v4::Session::adopt(&self.root, engine, transport, None)
    }
    pub fn import_message_stream_definition(
        &self,
        canonical: &[u8],
    ) -> Result<crate::MessageStreamDefinition, crate::ServiceError> {
        crate::typed_message_stream_v4::MessageStreamDefinition::import(&self.root, canonical)
    }
    pub fn define_message_stream(
        &self,
        kind: &str,
        revision: &str,
        opener_to_acceptor: crate::MessageDefinition,
        acceptor_to_opener: crate::MessageDefinition,
    ) -> Result<crate::MessageStreamDefinition, crate::ServiceError> {
        crate::typed_message_stream_v4::MessageStreamDefinition::define(
            &self.root,
            kind,
            revision,
            opener_to_acceptor,
            acceptor_to_opener,
        )
    }
    pub fn sqlite_operation_reference_store(
        &self,
        options: crate::SQLiteReferenceStoreOptions,
    ) -> Result<crate::SQLiteOperationReferenceStore, crate::ServiceError> {
        crate::sqlite_reference_store_v4::SQLiteOperationReferenceStore::open(
            self.root.clone(),
            options,
        )
    }
    /// Discharge a failed-open backing only after the host has removed its
    /// retained database and journals under the declared retention policy.
    pub fn release_removed_reference_store(
        &self,
        path: &std::path::Path,
    ) -> Result<(), crate::ServiceError> {
        let owner = self.root.reference_store(path).ok_or(crate::ServiceError(
            crate::ServiceFailure::ConfigurationCapacity,
        ))?;
        crate::SQLiteOperationReferenceStore(owner).release_removed()
    }
    pub fn operation_reference_codec(
        &self,
        target_domain: String,
    ) -> Result<crate::OperationReferenceCodec, crate::ServiceError> {
        crate::operation_reference_v4::OperationReferenceCodec::new(
            self.root.clone(),
            target_domain,
        )
    }
    /// Install an opt-in detailed diagnostic callback. Events are projected to
    /// the finite public whitelist and delivered by a dedicated sink worker.
    pub fn diagnostic_sink(
        &self,
        options: crate::DiagnosticSinkOptions,
        callback: crate::DiagnosticCallback,
    ) -> Result<crate::DiagnosticSink, EnvironmentError> {
        self.root.diagnostic_sink(options, callback)
    }
    /// Unsampled finite counters are available even with detailed diagnostics disabled.
    pub fn diagnostic_counts(&self) -> crate::TransportDiagnosticCounts {
        self.root.diagnostic_counts()
    }
    /// Finite marginal histograms for an unsampled metric; snapshots have no labels supplied by applications.
    pub fn diagnostic_metric(
        &self,
        metric: crate::DiagnosticMetric,
    ) -> crate::DiagnosticMetricCounts {
        self.root.diagnostic_metric(metric)
    }
    /// Observe or close the sink configured for production events on this Environment.
    pub fn configured_diagnostic_sink(&self) -> Option<crate::DiagnosticSink> {
        self.root.configured_diagnostic_sink()
    }
    pub fn application_executor_config(&self) -> &crate::ApplicationExecutorConfig {
        self.root.application_config()
    }
    pub fn application_executor_snapshot(&self) -> crate::ApplicationExecutorSnapshot {
        self.root.application_snapshot()
    }
    /// One continuous execution history per exact service configuration.
    /// Durable admission is selected by the service binding/provider; this
    /// owner implements the Environment-local volatile execution profile.
    pub fn execution_service(
        &self,
        options: crate::execution_history::ExecutionServiceOptions,
    ) -> Result<crate::execution_history::ExecutionService, crate::service_contract::ServiceError>
    {
        self.root.execution_service(options, None)
    }
    pub fn identity_keys(
        &self,
        profile: &str,
    ) -> Result<crate::crypto_v4::IdentityKeys, crate::crypto_v4::ConnectError> {
        crate::crypto_v4::IdentityKeys::new(self.root.clone(), profile)
    }
    /// Import original application-provisioned identity keys. These keys do
    /// not assert certificate trust, namespace authorization or carrier policy.
    pub fn import_identity_keys(
        &self,
        profile: &str,
        signing_seed: [u8; 32],
        noise_private: [u8; 32],
    ) -> Result<crate::crypto_v4::IdentityKeys, crate::crypto_v4::ConnectError> {
        crate::crypto_v4::IdentityKeys::import(
            self.root.clone(),
            profile,
            signing_seed,
            noise_private,
        )
    }
    pub fn namespace(
        &self,
        trust: crate::namespace_v4::verifier::NamespaceTrustRoot,
        state_bytes: usize,
        node_cap: usize,
    ) -> Result<Arc<crate::crypto_v4::Namespace>, EnvironmentError> {
        Ok(Arc::new(crate::crypto_v4::Namespace::new(
            self.namespace_verifier(trust, state_bytes, node_cap)?,
        )))
    }
    pub fn pool_connection_material(
        &self,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        bytes: crate::crypto_v4::PoolCredentialBytes,
    ) -> Result<crate::crypto_v4::PoolConnectionMaterial, crate::crypto_v4::ConnectError> {
        crate::crypto_v4::PoolConnectionMaterial::new(self.root.clone(), namespaces, keys, bytes)
    }
    pub async fn connect_pool_wss(
        &self,
        material: crate::crypto_v4::PoolConnectionMaterial,
        store: Arc<crate::pool_v4::SQLitePoolStore>,
        options: crate::crypto_v4::WssConnectOptions,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<crate::crypto_v4::Session, crate::crypto_v4::ConnectError> {
        crate::crypto_v4::connect::connect(self, material, store, options, cancellation).await
    }
    /// Connect the fixed current direct carrier selected by the signed route.
    /// Both WSS and raw QUIC use the same original spend and READY owner.
    pub async fn connect_pool_direct(
        &self,
        material: crate::crypto_v4::PoolConnectionMaterial,
        store: Arc<crate::pool_v4::SQLitePoolStore>,
        options: crate::crypto_v4::WssConnectOptions,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<crate::crypto_v4::Session, crate::crypto_v4::ConnectError> {
        crate::crypto_v4::connect::connect(self, material, store, options, cancellation).await
    }
    /// Establish a pool WSS Session with the same immutable inbound handler
    /// plan used by Serve. The plan is captured before irreversible spend.
    pub async fn connect_pool_wss_with_handler_plan(
        &self,
        material: crate::crypto_v4::PoolConnectionMaterial,
        store: Arc<crate::pool_v4::SQLitePoolStore>,
        options: crate::crypto_v4::WssConnectOptions,
        handler_plan: crate::crypto_v4::connect::serve::HandlerPlan,
        application_limits: crate::application_lifetime_v4::ApplicationLimits,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<crate::crypto_v4::Session, crate::crypto_v4::ConnectError> {
        crate::crypto_v4::connect::connect_with_handler_plan(
            self,
            material,
            store,
            options,
            Some((handler_plan, application_limits)),
            cancellation,
        )
        .await
    }
    pub fn live_accepted_material_source(
        &self,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        maximum: usize,
    ) -> Result<
        Arc<crate::crypto_v4::connect::serve::OriginalLiveAcceptedSource>,
        crate::TransportConnectError,
    > {
        crate::crypto_v4::connect::serve::OriginalLiveAcceptedSource::new(
            self.root.clone(),
            namespaces,
            keys,
            maximum,
        )
    }
    pub fn wss_relay_host(
        &self,
        keys: crate::crypto_v4::IdentityKeys,
        ledger: Arc<crate::pool_v4::relay::SQLiteRelayLedger>,
        options: crate::crypto_v4::connect::WssRelayHostOptions,
    ) -> Result<crate::crypto_v4::connect::WssRelayHost, crate::TransportConnectError> {
        crate::crypto_v4::connect::WssRelayHost::new(self.root.clone(), keys, ledger, options)
    }
    /// Construct a relay host that takes ownership of its already-bound
    /// WebSocket listener leg. Its address must match the listener leg's
    /// `listen_address`; any unused prebound socket is rejected.
    pub fn wss_relay_host_on_listener(
        &self,
        listener: std::net::TcpListener,
        keys: crate::crypto_v4::IdentityKeys,
        ledger: Arc<crate::pool_v4::relay::SQLiteRelayLedger>,
        options: crate::crypto_v4::connect::WssRelayHostOptions,
    ) -> Result<crate::crypto_v4::connect::WssRelayHost, crate::TransportConnectError> {
        crate::crypto_v4::connect::WssRelayHost::new_with_listener(
            self.root.clone(),
            keys,
            ledger,
            options,
            listener,
        )
    }
    /// Construct a relay host that takes ownership of an already-bound UDP
    /// listener leg for raw QUIC or WebTransport ingress.
    pub fn wss_relay_host_on_udp_socket(
        &self,
        socket: std::net::UdpSocket,
        keys: crate::crypto_v4::IdentityKeys,
        ledger: Arc<crate::pool_v4::relay::SQLiteRelayLedger>,
        options: crate::crypto_v4::connect::WssRelayHostOptions,
    ) -> Result<crate::crypto_v4::connect::WssRelayHost, crate::TransportConnectError> {
        crate::crypto_v4::connect::WssRelayHost::new_with_udp_socket(
            self.root.clone(),
            keys,
            ledger,
            options,
            socket,
        )
    }
    /// Original issuer-side projection of one verified pool selection. The
    /// resulting public object contains no parent Artifact or Session secrets.
    /// Capture one original live relay publication with its own verified
    /// issuance context and trusted winner authority.
    pub fn relay_live_publication(
        &self,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        input: crate::crypto_v4::connect::RelayPoolPublicationInput,
        winner_authority: String,
    ) -> Result<crate::crypto_v4::connect::OriginalRelayPoolPublication, crate::TransportConnectError>
    {
        crate::crypto_v4::connect::relay_publication::capture_live(
            self.root.clone(),
            namespaces,
            input,
            winner_authority,
        )
    }
    pub fn relay_pool_publication(
        &self,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        input: crate::crypto_v4::connect::RelayPoolPublicationInput,
    ) -> Result<crate::crypto_v4::connect::OriginalRelayPoolPublication, crate::TransportConnectError>
    {
        crate::crypto_v4::connect::relay_publication::capture_pool(
            self.root.clone(),
            namespaces,
            input,
        )
    }
    /// Host a finite original issued batch of logical server tunnel legs.
    /// Each server leg prepares and authenticates its own relay hop, then uses
    /// the configured shared admission authority before publishing a Session.
    #[expect(
        clippy::too_many_arguments,
        reason = "Public Serve entry points keep namespaces, identity, admission and physical listener ownership explicit."
    )]
    pub async fn serve_tunnel_pool(
        &self,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        credentials: Vec<crate::crypto_v4::TunnelPoolCredentialBytes>,
        relay_service: String,
        relay_audience: String,
        admission: Arc<crate::pool_v4::admission::SQLiteAdmissionAuthority>,
        options: crate::crypto_v4::connect::serve::TunnelServeOptions,
    ) -> Result<
        crate::crypto_v4::connect::serve::TunnelServeHandle,
        crate::crypto_v4::connect::serve::ServeError,
    > {
        crate::crypto_v4::connect::serve::serve_tunnel_pool(
            self.root.clone(),
            namespaces,
            keys,
            credentials,
            relay_service,
            relay_audience,
            admission,
            options,
        )
        .await
        .map_err(Into::into)
    }
    /// Consume the next original live delivery and start its exact server leg.
    /// The delivery ACK retains the verified material in a bounded queue;
    /// this call waits separately for that same material's carrier Prepare.
    #[expect(
        clippy::too_many_arguments,
        reason = "Public Serve entry points keep namespaces, identity, admission and physical listener ownership explicit."
    )]
    pub async fn serve_live_tunnel_publication(
        &self,
        delivery: &crate::crypto_v4::connect::serve::LiveServerDeliveryHandle,
        timeout: Duration,
        cancellation: CancellationToken,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        relay_service: String,
        relay_audience: String,
        admission: Arc<crate::pool_v4::admission::SQLiteAdmissionAuthority>,
        options: crate::crypto_v4::connect::serve::TunnelServeOptions,
    ) -> Result<
        crate::crypto_v4::connect::serve::TunnelServeHandle,
        crate::crypto_v4::connect::serve::ServeError,
    > {
        let material = delivery
            .next_tunnel_publication(timeout, &cancellation)
            .await?;
        self.serve_original_live_tunnel_material(
            material,
            namespaces,
            keys,
            relay_service,
            relay_audience,
            admission,
            options,
        )
        .await
    }
    /// Transfer a locally published or received live server-leg owner into
    /// Serve without rebuilding its verified Account from detached bytes.
    #[expect(
        clippy::too_many_arguments,
        reason = "Public Serve entry points keep namespaces, identity, admission and physical listener ownership explicit."
    )]
    pub async fn serve_original_live_tunnel_material(
        &self,
        material: crate::crypto_v4::connect::serve::OriginalLiveTunnelServerMaterial,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        relay_service: String,
        relay_audience: String,
        admission: Arc<crate::pool_v4::admission::SQLiteAdmissionAuthority>,
        options: crate::crypto_v4::connect::serve::TunnelServeOptions,
    ) -> Result<
        crate::crypto_v4::connect::serve::TunnelServeHandle,
        crate::crypto_v4::connect::serve::ServeError,
    > {
        let prepare_timeout = options.provider.timeout;
        let prepare_cancellation = options.cancellation.clone();
        let handle = crate::crypto_v4::connect::serve::serve_live_tunnel(
            self.root.clone(),
            namespaces,
            keys,
            material,
            relay_service,
            relay_audience,
            admission,
            options,
        )
        .await?;
        if let Err(error) = handle
            .wait_prepared(prepare_timeout, &prepare_cancellation)
            .await
        {
            handle.close();
            let _ = handle.wait_cleanup().await;
            return Err(error.into());
        }
        Ok(handle)
    }
    /// Prepare the original physical listener before live tunnel publication.
    /// The bound listener awaits the original publication's account and Grant.
    pub fn prepare_live_reverse_tunnel_listener(
        &self,
        provider: crate::crypto_v4::connect::ReverseTunnelProviderOptions,
        carrier: crate::LiveAuthorityCarrier,
        host: String,
        maximum_publications: usize,
    ) -> Result<
        crate::crypto_v4::connect::serve::LiveReverseTunnelListener,
        crate::TransportConnectError,
    > {
        let carrier = match carrier {
            crate::LiveAuthorityCarrier::RawQuic => 0,
            crate::LiveAuthorityCarrier::WebSocket => 1,
            crate::LiveAuthorityCarrier::WebTransport => 2,
        };
        crate::crypto_v4::connect::serve::prepare_live_reverse_listener(
            self.root.clone(),
            provider,
            carrier,
            host,
            maximum_publications,
        )
    }
    /// Consume one original live publication on its already-bound listener.
    /// Return the Serve handle after that same listener reaches readiness.
    #[expect(
        clippy::too_many_arguments,
        reason = "Public Serve entry points keep namespaces, identity, admission and physical listener ownership explicit."
    )]
    pub async fn serve_live_tunnel_publication_on_original_listener(
        &self,
        delivery: &crate::crypto_v4::connect::serve::LiveServerDeliveryHandle,
        timeout: Duration,
        cancellation: CancellationToken,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        relay_service: String,
        relay_audience: String,
        admission: Arc<crate::pool_v4::admission::SQLiteAdmissionAuthority>,
        options: crate::crypto_v4::connect::serve::LiveReverseTunnelServeOptions,
    ) -> Result<
        crate::crypto_v4::connect::serve::TunnelServeHandle,
        crate::crypto_v4::connect::serve::ServeError,
    > {
        let material = match delivery
            .next_tunnel_publication(timeout, &cancellation)
            .await
        {
            Ok(material) => material,
            Err(error) => {
                options.listener.close();
                let _ = options.listener.wait_cleanup().await;
                return Err(error.into());
            }
        };
        self.serve_original_live_tunnel_material_on_original_listener(
            material,
            namespaces,
            keys,
            relay_service,
            relay_audience,
            admission,
            options,
        )
        .await
    }
    /// Move a verified original live publication onto its already bound B
    /// listener. The same physical listener and Account survive the handoff.
    #[expect(
        clippy::too_many_arguments,
        reason = "Public Serve entry points keep namespaces, identity, admission and physical listener ownership explicit."
    )]
    pub async fn serve_original_live_tunnel_material_on_original_listener(
        &self,
        material: crate::crypto_v4::connect::serve::OriginalLiveTunnelServerMaterial,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        relay_service: String,
        relay_audience: String,
        admission: Arc<crate::pool_v4::admission::SQLiteAdmissionAuthority>,
        options: crate::crypto_v4::connect::serve::LiveReverseTunnelServeOptions,
    ) -> Result<
        crate::crypto_v4::connect::serve::TunnelServeHandle,
        crate::crypto_v4::connect::serve::ServeError,
    > {
        let prepare_timeout = options.listener.preparation_timeout();
        let prepare_cancellation = options.cancellation.clone();
        let handle = crate::crypto_v4::connect::serve::serve_live_tunnel_on_original_listener(
            self.root.clone(),
            namespaces,
            keys,
            material,
            relay_service,
            relay_audience,
            admission,
            options,
        )
        .await?;
        if let Err(error) = handle
            .wait_reverse_listener_ready(prepare_timeout, &prepare_cancellation)
            .await
        {
            handle.close();
            let _ = handle.wait_cleanup().await;
            return Err(error.into());
        }
        Ok(handle)
    }
    /// Consume one original live reverse publication and expose its exact
    /// listener only after the bounded native or WSS listener is ready.
    #[expect(
        clippy::too_many_arguments,
        reason = "Public Serve entry points keep namespaces, identity, admission and physical listener ownership explicit."
    )]
    pub async fn serve_reverse_live_tunnel_publication(
        &self,
        delivery: &crate::crypto_v4::connect::serve::LiveServerDeliveryHandle,
        timeout: Duration,
        cancellation: CancellationToken,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        relay_service: String,
        relay_audience: String,
        admission: Arc<crate::pool_v4::admission::SQLiteAdmissionAuthority>,
        options: crate::crypto_v4::connect::serve::ReverseTunnelServeOptions,
    ) -> Result<
        crate::crypto_v4::connect::serve::TunnelServeHandle,
        crate::crypto_v4::connect::serve::ServeError,
    > {
        let material = delivery
            .next_tunnel_publication(timeout, &cancellation)
            .await?;
        self.serve_original_reverse_live_tunnel_material(
            material,
            namespaces,
            keys,
            relay_service,
            relay_audience,
            admission,
            options,
        )
        .await
    }
    /// Consume one original verified live server leg as a physical listener.
    /// A failed Prepare retires this owner rather than recreating its material.
    #[expect(
        clippy::too_many_arguments,
        reason = "Public Serve entry points keep namespaces, identity, admission and physical listener ownership explicit."
    )]
    pub async fn serve_original_reverse_live_tunnel_material(
        &self,
        material: crate::crypto_v4::connect::serve::OriginalLiveTunnelServerMaterial,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        relay_service: String,
        relay_audience: String,
        admission: Arc<crate::pool_v4::admission::SQLiteAdmissionAuthority>,
        options: crate::crypto_v4::connect::serve::ReverseTunnelServeOptions,
    ) -> Result<
        crate::crypto_v4::connect::serve::TunnelServeHandle,
        crate::crypto_v4::connect::serve::ServeError,
    > {
        let prepare_timeout = options.provider.timeout;
        let prepare_cancellation = options.cancellation.clone();
        let handle = crate::crypto_v4::connect::serve::serve_reverse_live_tunnel(
            self.root.clone(),
            namespaces,
            keys,
            material,
            relay_service,
            relay_audience,
            admission,
            options,
        )
        .await?;
        if let Err(error) = handle
            .wait_reverse_listener_ready(prepare_timeout, &prepare_cancellation)
            .await
        {
            handle.close();
            let _ = handle.wait_cleanup().await;
            return Err(error.into());
        }
        Ok(handle)
    }
    /// Host one original logical server leg as the physical tunnel listener.
    #[expect(
        clippy::too_many_arguments,
        reason = "Public Serve entry points keep namespaces, identity, admission and physical listener ownership explicit."
    )]
    pub async fn serve_reverse_tunnel_pool(
        &self,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        credentials: Vec<crate::crypto_v4::TunnelPoolCredentialBytes>,
        relay_service: String,
        relay_audience: String,
        admission: Arc<crate::pool_v4::admission::SQLiteAdmissionAuthority>,
        options: crate::crypto_v4::connect::serve::ReverseTunnelServeOptions,
    ) -> Result<
        crate::crypto_v4::connect::serve::TunnelServeHandle,
        crate::crypto_v4::connect::serve::ServeError,
    > {
        crate::crypto_v4::connect::serve::serve_reverse_tunnel_pool(
            self.root.clone(),
            namespaces,
            keys,
            credentials,
            relay_service,
            relay_audience,
            admission,
            options,
        )
        .await
        .map_err(Into::into)
    }
    /// Host reverse tunnel ingress on a TCP listener already bound by the
    /// deployment owner. This handoff currently applies to WebSocket relay
    /// ingress; the bound address must match `options.provider.listen_address`.
    #[expect(
        clippy::too_many_arguments,
        reason = "Public Serve entry points keep namespaces, identity, admission and physical listener ownership explicit."
    )]
    pub async fn serve_reverse_tunnel_pool_on_listener(
        &self,
        listener: std::net::TcpListener,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        credentials: Vec<crate::crypto_v4::TunnelPoolCredentialBytes>,
        relay_service: String,
        relay_audience: String,
        admission: Arc<crate::pool_v4::admission::SQLiteAdmissionAuthority>,
        options: crate::crypto_v4::connect::serve::ReverseTunnelServeOptions,
    ) -> Result<
        crate::crypto_v4::connect::serve::TunnelServeHandle,
        crate::crypto_v4::connect::serve::ServeError,
    > {
        crate::crypto_v4::connect::serve::serve_reverse_pool_on_listener(
            self.root.clone(),
            namespaces,
            keys,
            credentials,
            relay_service,
            relay_audience,
            admission,
            options,
            listener,
        )
        .await
        .map_err(Into::into)
    }
    /// Host reverse tunnel ingress on a UDP socket already bound by the
    /// deployment owner. The actual address must match `provider.listen_address`.
    #[expect(
        clippy::too_many_arguments,
        reason = "Public Serve entry points keep namespaces, identity, admission and physical listener ownership explicit."
    )]
    pub async fn serve_reverse_tunnel_pool_on_udp_socket(
        &self,
        socket: std::net::UdpSocket,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        credentials: Vec<crate::crypto_v4::TunnelPoolCredentialBytes>,
        relay_service: String,
        relay_audience: String,
        admission: Arc<crate::pool_v4::admission::SQLiteAdmissionAuthority>,
        options: crate::crypto_v4::connect::serve::ReverseTunnelServeOptions,
    ) -> Result<
        crate::crypto_v4::connect::serve::TunnelServeHandle,
        crate::crypto_v4::connect::serve::ServeError,
    > {
        crate::crypto_v4::connect::serve::serve_reverse_pool_on_udp_socket(
            self.root.clone(),
            namespaces,
            keys,
            credentials,
            relay_service,
            relay_audience,
            admission,
            options,
            socket,
        )
        .await
        .map_err(Into::into)
    }
    /// Host current raw QUIC with the same application callbacks, durable
    /// admission, configured services and bounded Drain used by the WSS host.
    pub async fn serve_raw_quic(
        &self,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        source: Arc<dyn crate::crypto_v4::connect::serve::AcceptedMaterialSource>,
        admission: Arc<crate::pool_v4::admission::SQLiteAdmissionAuthority>,
        identity: crate::crypto_v4::connect::serve::WssServerIdentity,
        options: crate::crypto_v4::connect::serve::WssServeOptions,
    ) -> Result<
        crate::crypto_v4::connect::serve::ServeHandle,
        crate::crypto_v4::connect::serve::ServeError,
    > {
        crate::crypto_v4::connect::serve::serve_raw_quic(
            self.root.clone(),
            namespaces,
            keys,
            source,
            admission,
            identity,
            options,
        )
        .await
        .map_err(Into::into)
    }
    /// Host the fixed HTTP/3 WebTransport mapping on a dedicated connection.
    /// CONNECT Origin is checked by the native listener before Flowersec HELLO.
    /// Serve raw QUIC on a UDP socket already bound by the deployment owner.
    /// Its address must match `options.listen_address`; Serve owns the socket
    /// through cancellation and provider cleanup.
    #[expect(
        clippy::too_many_arguments,
        reason = "Public Serve entry points keep namespaces, identity, admission and physical listener ownership explicit."
    )]
    pub async fn serve_raw_quic_on_socket(
        &self,
        socket: std::net::UdpSocket,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        source: Arc<dyn crate::crypto_v4::connect::serve::AcceptedMaterialSource>,
        admission: Arc<crate::pool_v4::admission::SQLiteAdmissionAuthority>,
        identity: crate::crypto_v4::connect::serve::WssServerIdentity,
        options: crate::crypto_v4::connect::serve::WssServeOptions,
    ) -> Result<
        crate::crypto_v4::connect::serve::ServeHandle,
        crate::crypto_v4::connect::serve::ServeError,
    > {
        crate::crypto_v4::connect::serve::serve_raw_quic_on_socket(
            self.root.clone(),
            namespaces,
            keys,
            source,
            admission,
            identity,
            options,
            socket,
        )
        .await
        .map_err(Into::into)
    }
    /// Serve WebTransport on a UDP socket already bound by the deployment
    /// owner. Its address must match `options.listen_address`; Serve owns the
    /// socket through cancellation and provider cleanup.
    #[expect(
        clippy::too_many_arguments,
        reason = "Public Serve entry points keep namespaces, identity, admission and physical listener ownership explicit."
    )]
    pub async fn serve_webtransport_on_socket(
        &self,
        socket: std::net::UdpSocket,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        source: Arc<dyn crate::crypto_v4::connect::serve::AcceptedMaterialSource>,
        admission: Arc<crate::pool_v4::admission::SQLiteAdmissionAuthority>,
        identity: crate::crypto_v4::connect::serve::WssServerIdentity,
        options: crate::crypto_v4::connect::serve::WssServeOptions,
    ) -> Result<
        crate::crypto_v4::connect::serve::ServeHandle,
        crate::crypto_v4::connect::serve::ServeError,
    > {
        crate::crypto_v4::connect::serve::serve_webtransport_on_socket(
            self.root.clone(),
            namespaces,
            keys,
            source,
            admission,
            identity,
            options,
            socket,
        )
        .await
        .map_err(Into::into)
    }
    pub async fn serve_webtransport(
        &self,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        source: Arc<dyn crate::crypto_v4::connect::serve::AcceptedMaterialSource>,
        admission: Arc<crate::pool_v4::admission::SQLiteAdmissionAuthority>,
        identity: crate::crypto_v4::connect::serve::WssServerIdentity,
        options: crate::crypto_v4::connect::serve::WssServeOptions,
    ) -> Result<
        crate::crypto_v4::connect::serve::ServeHandle,
        crate::crypto_v4::connect::serve::ServeError,
    > {
        crate::crypto_v4::connect::serve::serve_webtransport(
            self.root.clone(),
            namespaces,
            keys,
            source,
            admission,
            identity,
            options,
        )
        .await
        .map_err(Into::into)
    }
    /// Serve WSS on a listener already bound by the deployment owner. The
    /// listener address must match `options.listen_address`; ownership moves
    /// into Serve and remains there through cancellation and cleanup.
    #[expect(
        clippy::too_many_arguments,
        reason = "Public Serve entry points keep namespaces, identity, admission and physical listener ownership explicit."
    )]
    pub async fn serve_wss_on_listener(
        &self,
        listener: std::net::TcpListener,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        source: Arc<dyn crate::crypto_v4::connect::serve::AcceptedMaterialSource>,
        admission: Arc<crate::pool_v4::admission::SQLiteAdmissionAuthority>,
        identity: crate::crypto_v4::connect::serve::WssServerIdentity,
        options: crate::crypto_v4::connect::serve::WssServeOptions,
    ) -> Result<
        crate::crypto_v4::connect::serve::ServeHandle,
        crate::crypto_v4::connect::serve::ServeError,
    > {
        crate::crypto_v4::connect::serve::serve_wss_on_listener(
            self.root.clone(),
            namespaces,
            keys,
            source,
            admission,
            identity,
            options,
            listener,
        )
        .await
        .map_err(Into::into)
    }
    pub async fn serve_wss(
        &self,
        namespaces: Vec<Arc<crate::crypto_v4::Namespace>>,
        keys: crate::crypto_v4::IdentityKeys,
        source: Arc<dyn crate::crypto_v4::connect::serve::AcceptedMaterialSource>,
        admission: Arc<crate::pool_v4::admission::SQLiteAdmissionAuthority>,
        identity: crate::crypto_v4::connect::serve::WssServerIdentity,
        options: crate::crypto_v4::connect::serve::WssServeOptions,
    ) -> Result<
        crate::crypto_v4::connect::serve::ServeHandle,
        crate::crypto_v4::connect::serve::ServeError,
    > {
        crate::crypto_v4::connect::serve::serve(
            self.root.clone(),
            namespaces,
            keys,
            source,
            admission,
            identity,
            options,
        )
        .await
        .map_err(Into::into)
    }
    pub fn handler_plan(
        &self,
        options: crate::crypto_v4::connect::serve::HandlerPlanOptions,
    ) -> Result<
        crate::crypto_v4::connect::serve::HandlerPlan,
        crate::crypto_v4::connect::serve::ServeError,
    > {
        crate::crypto_v4::connect::serve::HandlerPlan::new(self.root.clone(), options)
    }
    pub(crate) fn owns_account(&self, account: &ResourceAccount) -> bool {
        account.belongs_to(&self.root)
    }
    pub fn sqlite_pool_backing(
        &self,
        path: impl AsRef<std::path::Path>,
        limits: crate::pool_v4::SQLitePoolLimits,
    ) -> Result<crate::pool_v4::SQLitePoolBacking, crate::pool_v4::PoolStoreError> {
        crate::pool_v4::SQLitePoolBacking::new(self.root.clone(), path.as_ref(), limits)
    }
    pub async fn close(&self) -> Result<CleanupStatus, SessionError> {
        self.root.close();
        Ok(self.wait_cleanup().await)
    }
    pub fn is_closed(&self) -> bool {
        self.root.is_closed()
    }
    pub fn resource_usage(&self) -> ResourceLimits {
        self.root.charged()
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let (complete, cleanup_incomplete) = self.root.cleanup();
        CleanupStatus {
            complete,
            cleanup_incomplete,
            pending_callbacks: self.root.diagnostic_pending_callbacks(),
        }
    }
    pub async fn wait_cleanup(&self) -> CleanupStatus {
        // An observation of an active Environment is finite too. Its timeout
        // does not close the root or replace the original Close deadline.
        let observation_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let changed = self.root.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete || status.cleanup_incomplete {
                return status;
            }
            let deadline = self
                .root
                .cleanup_deadline()
                .map_or(observation_deadline, |original| {
                    original.min(observation_deadline)
                });
            if Instant::now() >= deadline {
                return CleanupStatus {
                    cleanup_incomplete: true,
                    ..status
                };
            }
            tokio::select! { _ = changed => {}, _ = sleep_until(deadline) => {} }
        }
    }
}
fn environment_session_error(error: EnvironmentError) -> SessionError {
    match error {
        EnvironmentError::Closed => SessionError::Closed,
        EnvironmentError::Capacity => SessionError::ResourceExhausted,
        _ => SessionError::OperationFailed,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupStatus {
    pub complete: bool,
    pub cleanup_incomplete: bool,
    pub pending_callbacks: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadProgress {
    pub offset: u64,
    pub filled: u64,
    pub target: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadWaitStatus {
    Ready,
    Blocked,
    WaitCanceled,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadStreamStatus {
    Open,
    Eof,
    Aborted,
    Error,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadCause {
    DelimiterNotFound,
    UnexpectedEof,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadErrorCode {
    ProtocolViolation,
    FramingError,
    AuthenticationFailed,
    SequenceError,
    ReplayDetected,
    CryptoFailure,
    RekeyFailed,
    ResourceExhausted,
    StreamSequenceError,
    StreamDataInvalid,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadErrorScope {
    Session,
    Stream,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadRetryDisposition {
    PreserveFacts,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadError {
    pub code: ReadErrorCode,
    pub scope: ReadErrorScope,
    pub retry_disposition: ReadRetryDisposition,
}
impl ReadError {
    pub fn new(code: ReadErrorCode) -> Self {
        Self {
            code,
            scope: match code {
                ReadErrorCode::StreamSequenceError | ReadErrorCode::StreamDataInvalid => {
                    ReadErrorScope::Stream
                }
                _ => ReadErrorScope::Session,
            },
            retry_disposition: ReadRetryDisposition::PreserveFacts,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadResult {
    pub data: Bytes,
    pub progress: ReadProgress,
    pub wait_status: ReadWaitStatus,
    pub stream_status: ReadStreamStatus,
    pub cause: Option<ReadCause>,
    pub error: Option<ReadError>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadMethodFailureReason {
    InvalidArgument,
    TargetMismatch,
    ReadInProgress,
    PrefixFrozen,
    AlreadyDelivered,
    Closed,
    TimePending,
    TimeUnavailable,
    AuthorizationDenied,
    OwnerUnavailable,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReaderCursorSnapshot {
    pub offset: u64,
    pub transferred_bytes: u64,
    pub target: u64,
    pub stream_status: ReadStreamStatus,
    pub target_cause: Option<ReadCause>,
    pub stream_error: Option<ReadError>,
    pub complete: bool,
    pub frozen: bool,
    pub delivered: bool,
    pub closed: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Flowersec read method failed: {reason:?}")]
pub struct ReadMethodFailure {
    pub reason: ReadMethodFailureReason,
    pub cursor: Option<ReaderCursorSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReaderCursorOptions {
    pub exact: Option<u64>,
    pub delimiter: Option<Bytes>,
    pub max_bytes: u64,
}

#[derive(Debug)]
struct ReadDirectionState {
    claimed: bool,
    offset: u64,
}

/// The stream's shared receive-direction owner, without an adapter receive queue.
/// Providers must use it for ordinary reads as well as cursor transfers.
#[derive(Debug)]
pub struct StreamReadOwner {
    state: Mutex<ReadDirectionState>,
    max_cursor_bytes: usize,
    delivery: Arc<ReadDeliveryAuthorization>,
}
impl StreamReadOwner {
    pub fn new(max_cursor_bytes: usize) -> Self {
        Self {
            state: Mutex::new(ReadDirectionState {
                claimed: false,
                offset: 0,
            }),
            max_cursor_bytes,
            delivery: Arc::new(ReadDeliveryAuthorization::new()),
        }
    }
    pub(crate) fn from_account(max_cursor_bytes: usize, account: ResourceAccount) -> Self {
        let mut owner = Self::new(max_cursor_bytes);
        owner.delivery = Arc::new(ReadDeliveryAuthorization {
            valid: Mutex::new(true),
            account: Some(account.downgrade()),
        });
        owner
    }
    pub fn acquire(self: &Arc<Self>) -> Result<StreamReadPermit, SessionError> {
        let mut state = self.state.lock().expect("read direction lock");
        if state.claimed {
            return Err(SessionError::ReadInProgress);
        }
        state.claimed = true;
        Ok(StreamReadPermit {
            owner: self.clone(),
            start_offset: state.offset,
        })
    }
    pub fn max_cursor_bytes(&self) -> usize {
        self.max_cursor_bytes
    }
    /// Returns the original stream-owned result handoff capability.
    ///
    /// Providers use this when exposing a cursor. The capability has no
    /// constructor and can only be used to authorize a handoff while the
    /// original stream owner remains valid.
    pub fn delivery_authorization(&self) -> Arc<ReadDeliveryAuthorization> {
        self.delivery.clone()
    }
    /// Permanently revoke future handoff of private cursor payloads.
    pub fn revoke_delivery(&self) {
        self.delivery.revoke();
    }
}

/// Opaque authorization retained by a private read-result owner.
///
/// This is deliberately separate from the receive-direction permit. A stream
/// may finish reading and retain a complete private prefix, but a reset or
/// other trusted owner failure still closes the final application handoff.
#[derive(Debug)]
pub struct ReadDeliveryAuthorization {
    valid: Mutex<bool>,
    account: Option<WeakResourceAccount>,
}
impl ReadDeliveryAuthorization {
    fn new() -> Self {
        Self {
            valid: Mutex::new(true),
            account: None,
        }
    }
    pub fn revoke(&self) {
        self.revoke_with(|| ());
    }
    pub(crate) fn revoke_with<T>(&self, close: impl FnOnce() -> T) -> T {
        let mut valid = self.valid.lock().expect("read delivery lock");
        *valid = false;
        close()
    }
}

/// Holds the sole permission to move bytes from the stream's receive queue.
#[derive(Debug)]
pub struct StreamReadPermit {
    owner: Arc<StreamReadOwner>,
    start_offset: u64,
}
impl StreamReadPermit {
    pub fn start_offset(&self) -> u64 {
        self.start_offset
    }
    pub(crate) fn belongs_to(&self, owner: &Arc<StreamReadOwner>) -> bool {
        Arc::ptr_eq(&self.owner, owner)
    }
    pub(crate) fn can_advance(&self, bytes: usize) -> bool {
        self.owner
            .state
            .lock()
            .expect("read direction lock")
            .offset
            .checked_add(bytes as u64)
            .is_some()
    }
    /// Commit only the byte range actually removed from the receive queue.
    /// Call while holding that queue's transfer gate, before exposing its capacity.
    pub fn advance(&self, bytes: usize) -> Result<u64, SessionError> {
        let mut state = self.owner.state.lock().expect("read direction lock");
        state.offset = state
            .offset
            .checked_add(bytes as u64)
            .ok_or(SessionError::OperationFailed)?;
        Ok(state.offset)
    }
}
impl Drop for StreamReadPermit {
    fn drop(&mut self) {
        self.owner
            .state
            .lock()
            .expect("read direction lock")
            .claimed = false;
    }
}

struct CursorState {
    stream: Option<Arc<dyn ByteStream>>,
    permit: Option<StreamReadPermit>,
    _metadata_charge: Option<ResourceCharge>,
    data_charge: Option<ResourceCharge>,
    prefix: Vec<u8>,
    progress: ReadProgress,
    stream_status: ReadStreamStatus,
    cause: Option<ReadCause>,
    error: Option<ReadError>,
    matched: usize,
    complete: bool,
    frozen: bool,
    delivered: bool,
    closed: bool,
}
impl CursorState {
    fn snapshot(&self) -> ReaderCursorSnapshot {
        ReaderCursorSnapshot {
            offset: self.progress.offset,
            transferred_bytes: self.progress.filled,
            target: self.progress.target.expect("cursor target"),
            stream_status: self.stream_status,
            target_cause: self.cause,
            stream_error: self.error,
            complete: self.complete,
            frozen: self.frozen,
            delivered: self.delivered,
            closed: self.closed,
        }
    }
    fn failure(&self, reason: ReadMethodFailureReason) -> ReadMethodFailure {
        ReadMethodFailure {
            reason,
            cursor: Some(self.snapshot()),
        }
    }
    fn check(&self) -> Result<(), ReadMethodFailure> {
        if self.delivered {
            return Err(self.failure(ReadMethodFailureReason::AlreadyDelivered));
        }
        if self.closed {
            return Err(self.failure(ReadMethodFailureReason::Closed));
        }
        Ok(())
    }
}

/// One immutable read target with a single owned payload handoff.
/// Partial progress and its direction permit outlive individual wait futures.
pub struct ReaderCursor {
    // Terminal snapshots may observe a surviving stream without keeping its
    // provider/key graph alive after a complete private candidate forms.
    stream_observer: std::sync::Weak<dyn ByteStream>,
    result_account: Option<ResourceAccount>,
    direction: Arc<StreamReadOwner>,
    delivery: Arc<ReadDeliveryAuthorization>,
    options: ReaderCursorOptions,
    failure_table: [usize; 32],
    state: Mutex<CursorState>,
    read_gate: AsyncMutex<()>,
    changed: Notify,
}
impl std::fmt::Debug for ReaderCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReaderCursor")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}
impl ReaderCursor {
    pub fn new(
        stream: Arc<dyn ByteStream>,
        mut options: ReaderCursorOptions,
    ) -> Result<Self, ReadMethodFailure> {
        let failure = |reason| ReadMethodFailure {
            reason,
            cursor: None,
        };
        let target = match (options.exact, options.delimiter.as_deref()) {
            (Some(target), None) => usize::try_from(target).ok(),
            (None, Some(delimiter))
                if !delimiter.is_empty()
                    && delimiter.len() <= 32
                    && options.max_bytes >= delimiter.len() as u64 =>
            {
                usize::try_from(options.max_bytes).ok()
            }
            _ => None,
        }
        .ok_or_else(|| failure(ReadMethodFailureReason::InvalidArgument))?;
        let direction = stream
            .read_owner()
            .ok_or_else(|| failure(ReadMethodFailureReason::OwnerUnavailable))?;
        let delivery = stream
            .read_delivery_owner()
            .ok_or_else(|| failure(ReadMethodFailureReason::OwnerUnavailable))?;
        if !Arc::ptr_eq(&delivery, &direction.delivery) {
            return Err(failure(ReadMethodFailureReason::OwnerUnavailable));
        }
        if target > direction.max_cursor_bytes() {
            return Err(failure(ReadMethodFailureReason::InvalidArgument));
        }
        let permit = direction
            .acquire()
            .map_err(|_| failure(ReadMethodFailureReason::ReadInProgress))?;
        let result_account = delivery
            .account
            .as_ref()
            .map(|account| {
                account
                    .upgrade()
                    .ok_or(EnvironmentError::Closed)?
                    .reserve_result()
            })
            .transpose()
            .map_err(|_| failure(ReadMethodFailureReason::OwnerUnavailable))?;
        let mut charge = result_account
            .as_ref()
            .map(|account| {
                account.reserve(ResourceLimits {
                    sdk_bytes: (target as u64)
                        .checked_add(std::mem::size_of::<ReaderCursor>() as u64)
                        .ok_or(EnvironmentError::Capacity)?,
                    items: 1,
                    work_slots: 1,
                    ..ResourceLimits::default()
                })
            })
            .transpose()
            .map_err(|_| failure(ReadMethodFailureReason::OwnerUnavailable))?;
        let data_charge = charge
            .as_mut()
            .map(|charge| {
                charge.split(ResourceLimits {
                    sdk_bytes: target as u64,
                    ..ResourceLimits::default()
                })
            })
            .transpose()
            .map_err(|_| failure(ReadMethodFailureReason::OwnerUnavailable))?;
        let mut prefix = Vec::new();
        prefix
            .try_reserve_exact(target)
            .map_err(|_| failure(ReadMethodFailureReason::OwnerUnavailable))?;
        if let Some(delimiter) = &options.delimiter {
            options.delimiter = Some(Bytes::copy_from_slice(delimiter));
        }
        let mut failure_table = [0; 32];
        if let Some(delimiter) = &options.delimiter {
            let mut matched = 0;
            for i in 1..delimiter.len() {
                while matched > 0 && delimiter[i] != delimiter[matched] {
                    matched = failure_table[matched - 1];
                }
                if delimiter[i] == delimiter[matched] {
                    matched += 1;
                }
                failure_table[i] = matched;
            }
        }
        let offset = permit.start_offset();
        if offset.checked_add(target as u64).is_none() {
            return Err(failure(ReadMethodFailureReason::InvalidArgument));
        }
        let (stream_status, stream_error) = stream.read_state();
        let complete = target == 0 || stream_status != ReadStreamStatus::Open;
        if complete && let Some(account) = &result_account {
            account.detach_result();
        }
        Ok(Self {
            stream_observer: Arc::downgrade(&stream),
            result_account,
            direction,
            delivery,
            options,
            failure_table,
            state: Mutex::new(CursorState {
                stream: (!complete).then_some(stream),
                permit: Some(permit),
                _metadata_charge: charge,
                data_charge,
                prefix,
                progress: ReadProgress {
                    offset,
                    filled: 0,
                    target: Some(target as u64),
                },
                stream_status,
                cause: (target > 0 && stream_status == ReadStreamStatus::Eof)
                    .then_some(ReadCause::UnexpectedEof),
                error: stream_error,
                matched: 0,
                complete,
                frozen: false,
                delivered: false,
                closed: false,
            }),
            read_gate: AsyncMutex::new(()),
            changed: Notify::new(),
        })
    }
    pub fn progress(&self) -> ReadProgress {
        self.state.lock().expect("cursor lock").progress.clone()
    }
    pub fn snapshot(&self) -> ReaderCursorSnapshot {
        self.state.lock().expect("cursor lock").snapshot()
    }
    pub fn belongs_to(&self, owner: &Arc<StreamReadOwner>) -> bool {
        Arc::ptr_eq(&self.direction, owner)
    }

    /// Provider integration: transfer only the returned prefix length while
    /// holding the original receive queue's gate. The rest stays in that queue.
    /// The input must be authenticated, and the provider must retain no alias to
    /// the cursor's private destination. This operation never calls application code.
    pub fn transfer_from(&self, input: &[u8]) -> Result<usize, SessionError> {
        let mut state = self.state.lock().expect("cursor lock");
        if state.closed || state.frozen || state.complete || state.delivered {
            return Ok(0);
        }
        let remaining =
            (state.progress.target.expect("cursor target") - state.progress.filled) as usize;
        let mut take = input.len().min(remaining);
        let mut matched = state.matched;
        let mut found = false;
        if let Some(delimiter) = &self.options.delimiter {
            for (i, byte) in input[..take].iter().enumerate() {
                while matched > 0 && *byte != delimiter[matched] {
                    matched = self.failure_table[matched - 1];
                }
                if *byte == delimiter[matched] {
                    matched += 1;
                }
                if matched == delimiter.len() {
                    take = i + 1;
                    found = true;
                    break;
                }
            }
        }
        let offset = state
            .permit
            .as_ref()
            .expect("cursor read permit")
            .advance(take)?;
        state.prefix.extend_from_slice(&input[..take]);
        state.progress.filled += take as u64;
        state.progress.offset = offset;
        state.matched = matched;
        let stream = if found || take == remaining {
            state.complete = true;
            if self.options.delimiter.is_some() && !found {
                state.cause = Some(ReadCause::DelimiterNotFound);
            }
            state.stream.take()
        } else {
            None
        };
        drop(state);
        if stream.is_some()
            && let Some(account) = &self.result_account
        {
            account.detach_result();
        }
        drop(stream);
        Ok(take)
    }
    /// Provider integration: publish a real input terminal state without
    /// manufacturing an error code when the provider has only an abort fact.
    pub fn terminate_input(&self, status: ReadStreamStatus, error: Option<ReadError>) {
        assert_eq!(status == ReadStreamStatus::Error, error.is_some());
        assert_ne!(status, ReadStreamStatus::Open);
        let mut state = self.state.lock().expect("cursor lock");
        if state.closed || state.delivered {
            return;
        }
        state.stream_status = status;
        state.error = error;
        if !state.complete && status == ReadStreamStatus::Eof {
            state.cause = Some(ReadCause::UnexpectedEof);
        }
        state.complete = true;
        let stream = state.stream.take();
        drop(state);
        if let Some(account) = &self.result_account {
            account.detach_result();
        }
        drop(stream);
    }
    fn terminate_error(&self, error: SessionError) {
        match error {
            SessionError::ResourceExhausted => self.terminate_input(
                ReadStreamStatus::Error,
                Some(ReadError::new(ReadErrorCode::ResourceExhausted)),
            ),
            SessionError::RekeyFailed => self.terminate_input(
                ReadStreamStatus::Error,
                Some(ReadError::new(ReadErrorCode::RekeyFailed)),
            ),
            _ => self.terminate_input(ReadStreamStatus::Aborted, None),
        }
    }
    pub async fn read_exactly(&self) -> Result<ReadResult, ReadMethodFailure> {
        self.state.lock().expect("cursor lock").check()?;
        if self.options.exact.is_none() {
            return Err(self
                .state
                .lock()
                .expect("cursor lock")
                .failure(ReadMethodFailureReason::TargetMismatch));
        }
        self.read().await
    }
    pub async fn read_until(&self) -> Result<ReadResult, ReadMethodFailure> {
        self.state.lock().expect("cursor lock").check()?;
        if self.options.delimiter.is_none() {
            return Err(self
                .state
                .lock()
                .expect("cursor lock")
                .failure(ReadMethodFailureReason::TargetMismatch));
        }
        self.read().await
    }
    pub async fn read_line(&self) -> Result<ReadResult, ReadMethodFailure> {
        self.state.lock().expect("cursor lock").check()?;
        if self.options.delimiter.as_deref() != Some(b"\n") {
            return Err(self
                .state
                .lock()
                .expect("cursor lock")
                .failure(ReadMethodFailureReason::TargetMismatch));
        }
        self.read().await
    }
    pub async fn take_prefix(&self) -> Result<ReadResult, ReadMethodFailure> {
        {
            let mut state = self.state.lock().expect("cursor lock");
            state.check()?;
            state.frozen = true;
        }
        self.changed.notify_waiters();
        let _gate = self.read_gate.lock().await;
        if let Some(account) = &self.result_account {
            account.detach_result();
        }
        self.deliver()
    }
    pub fn close(&self) {
        let (permit, stream, charge) = {
            let mut state = self.state.lock().expect("cursor lock");
            if state.delivered || state.closed {
                return;
            }
            state.closed = true;
            state.prefix = Vec::new();
            (
                state.permit.take(),
                state.stream.take(),
                state.data_charge.take(),
            )
        };
        drop(permit);
        if let Some(account) = &self.result_account {
            account.detach_result();
        }
        drop(stream);
        drop(charge);
        self.changed.notify_waiters();
    }
    fn deliver(&self) -> Result<ReadResult, ReadMethodFailure> {
        self.refresh_terminal();
        let transfer = || {
            // Hold the original delivery gate through the owned payload move.
            // A reset/revocation cannot win between the check and that move.
            let authorized = self.delivery.valid.lock().expect("read delivery lock");
            let mut state = self.state.lock().expect("cursor lock");
            state.check()?;
            if !*authorized {
                return Err(state.failure(ReadMethodFailureReason::AuthorizationDenied));
            }
            state.delivered = true;
            let result = ReadResult {
                data: Bytes::from(std::mem::take(&mut state.prefix)),
                progress: state.progress.clone(),
                wait_status: ReadWaitStatus::Ready,
                stream_status: state.stream_status,
                cause: state.cause,
                error: state.error,
            };
            Ok((
                result,
                state.permit.take(),
                state.stream.take(),
                state.data_charge.take(),
            ))
        };
        let transferred = if let Some(account) = &self.result_account {
            account.with_security(transfer).map_err(|error| {
                self.state
                    .lock()
                    .expect("cursor lock")
                    .failure(match error {
                        EnvironmentError::TimePending => ReadMethodFailureReason::TimePending,
                        EnvironmentError::TimeUnavailable => {
                            ReadMethodFailureReason::TimeUnavailable
                        }
                        _ => ReadMethodFailureReason::AuthorizationDenied,
                    })
            })?
        } else {
            transfer()
        };
        let (result, permit, stream, charge) = transferred?;
        drop(permit);
        drop(stream);
        drop(charge);
        Ok(result)
    }
    fn refresh_terminal(&self) {
        let stream = {
            let state = self.state.lock().expect("cursor lock");
            if state.closed || state.delivered || state.stream_status != ReadStreamStatus::Open {
                return;
            }
            state
                .stream
                .clone()
                .or_else(|| self.stream_observer.upgrade())
        };
        if let Some(stream) = stream {
            let (status, error) = stream.read_state();
            if status != ReadStreamStatus::Open {
                self.terminate_input(status, error);
            }
        }
    }
    async fn read(&self) -> Result<ReadResult, ReadMethodFailure> {
        let _gate = self.read_gate.try_lock().map_err(|_| {
            self.state
                .lock()
                .expect("cursor lock")
                .failure(ReadMethodFailureReason::ReadInProgress)
        })?;
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let stream = {
                let state = self.state.lock().expect("cursor lock");
                state.check()?;
                if state.frozen {
                    return Err(state.failure(ReadMethodFailureReason::PrefixFrozen));
                }
                if state.complete {
                    drop(state);
                    return self.deliver();
                }
                state.stream.as_ref().expect("live cursor stream").clone()
            };
            tokio::select! {
                biased;
                _ = &mut changed => {},
                result = stream.read_cursor_piece(self) => {
                    if let Err(error) = result { self.terminate_error(error); }
                }
            }
        }
    }
}
impl Drop for ReaderCursor {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteProgress {
    pub requested_bytes: u64,
    pub accepted_bytes: u64,
    pub phase: String,
    pub terminal_reason: Option<String>,
    pub cleanup: CleanupStatus,
}

/// Opaque original Stream qualification.  Only the provider owner creates
/// it; dropping one permit releases precisely that permit's responsibility.
pub struct StreamWritePreparationPermit {
    release: Option<Box<dyn FnOnce() + Send + Sync>>,
}
impl StreamWritePreparationPermit {
    pub(crate) fn new(release: impl FnOnce() + Send + Sync + 'static) -> Self {
        Self {
            release: Some(Box::new(release)),
        }
    }
}
impl std::fmt::Debug for StreamWritePreparationPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StreamWritePreparationPermit { <opaque> }")
    }
}
impl Drop for StreamWritePreparationPermit {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            release();
        }
    }
}
struct PreparedWrite {
    preparation: Option<StreamWritePreparationPermit>,
    stream: Arc<dyn ByteStream>,
    payload: Bytes,
    staging: WriteStagingReservation,
    native_charge: Option<ResourceCharge>,
}

struct WriteState {
    input: Option<PreparedWrite>,
    progress: WriteProgress,
    stopped: Option<SessionError>,
    deadline: Instant,
    started: bool,
    start_error: Option<SessionError>,
    waiters: usize,
}

pub(crate) type FirstByteGate =
    Arc<dyn Fn(crate::environment_v4::TrustedTimeSample) -> Result<(), SessionError> + Send + Sync>;
struct WriteOwner {
    diagnostics: Mutex<Option<Arc<crate::diagnostics_v4::DiagnosticActivity>>>,
    state: Mutex<WriteState>,
    first_byte_gate: Option<FirstByteGate>,
    changed: Notify,
    // Results, waiters and the one timer keep the original finite metadata
    // slot. This owner has no reference back to the Session or its keys.
    metadata: Option<WriteMetadataReservation>,
}
impl WriteOwner {
    fn finish_diagnostics(&self) {
        let progress = self.state.lock().expect("operation lock").progress.clone();
        if progress.phase != "terminal" {
            return;
        }
        if let Some(diagnostics) = self.diagnostics.lock().expect("write diagnostics").as_ref() {
            match progress.terminal_reason.as_deref() {
                Some("complete") => diagnostics.succeed(),
                Some("canceled") => diagnostics.session_failure(SessionError::Canceled),
                Some("deadline_exceeded") => diagnostics.session_failure(SessionError::Timeout),
                Some("stream_terminated") => diagnostics.session_failure(SessionError::Closed),
                _ => diagnostics.session_failure(SessionError::OperationFailed),
            }
        }
    }
    fn stop(&self, error: SessionError) {
        let input = {
            let mut state = self.state.lock().expect("operation lock");
            if state.progress.phase == "terminal" || state.stopped.is_some() {
                return;
            }
            if state.started && state.progress.accepted_bytes == state.progress.requested_bytes {
                return;
            }
            state.stopped = Some(error);
            if !state.started {
                state.start_error = Some(error);
                state.input.take()
            } else {
                None
            }
        };
        if let Some(input) = input {
            // Provider references and reservations can have destructors. They
            // leave outside the operation gate, before cleanup becomes complete.
            drop(input);
            let mut state = self.state.lock().expect("operation lock");
            state.progress.phase = "terminal".into();
            state.progress.terminal_reason = Some(write_reason(error).into());
            state.progress.cleanup.complete = true;
        }
        self.finish_diagnostics();
        self.changed.notify_waiters();
    }
    async fn monitor(self: Arc<Self>, _timer_charge: Option<ResourceCharge>) {
        let root = self
            .metadata
            .as_ref()
            .expect("admitted write metadata")
            .owner
            .clone();
        loop {
            let changed = self.changed.notified();
            let root_changed = root.changed.notified();
            tokio::pin!(changed, root_changed);
            changed.as_mut().enable();
            root_changed.as_mut().enable();
            let deadline = {
                let state = self.state.lock().expect("operation lock");
                if state.progress.phase == "terminal"
                    || state.stopped.is_some()
                    || (state.started
                        && state.progress.accepted_bytes == state.progress.requested_bytes)
                {
                    return;
                }
                state.deadline
            };
            if root.state.lock().expect("write staging lock").closed {
                self.stop(SessionError::Closed);
                return;
            }
            if let Some(account) = &root.account {
                match account.check() {
                    Ok(())
                    | Err(EnvironmentError::TimePending | EnvironmentError::TimeUnavailable) => {}
                    Err(error) => {
                        self.stop(environment_session_error(error));
                        return;
                    }
                }
            }
            let wake = root
                .account
                .as_ref()
                .and_then(|account| Instant::now().checked_add(account.next_security_check()))
                .map_or(deadline, |tick| tick.min(deadline));
            tokio::select! {
                biased;
                _ = root_changed => {}
                _ = changed => {}
                _ = async {
                    if let Some(account) = &root.account { account.security_changed().await; }
                    else { std::future::pending::<()>().await; }
                } => {}
                _ = sleep_until(wake) => {
                    if Instant::now() >= deadline {
                        self.stop(SessionError::Timeout);
                        return;
                    }
                }
            }
        }
    }
}
fn write_reason(error: SessionError) -> &'static str {
    match error {
        SessionError::Canceled => "canceled",
        SessionError::Timeout => "deadline_exceeded",
        SessionError::Closed | SessionError::StreamReset => "stream_terminated",
        _ => "failed",
    }
}

/// The original write request's acceptance gate, shared with its native stream.
/// Implementations call `accept` only after securing the actual ordered send
/// responsibility; canceled suffixes must never reach that boundary.
#[derive(Clone)]
pub struct WriteRequestAdmission {
    owner: Arc<WriteOwner>,
}
impl std::fmt::Debug for WriteRequestAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WriteRequestAdmission { <opaque> }")
    }
}
impl WriteRequestAdmission {
    pub fn accept(&self, bytes: usize) -> Result<(), SessionError> {
        let root = &self.owner.metadata.as_ref().expect("write metadata").owner;
        if let Some(account) = &root.account {
            return account
                .with_security_time(|now| self.accept_local(bytes, Some(now)))
                .map_err(environment_session_error)?;
        }
        self.accept_local(bytes, None)
    }
    fn accept_local(
        &self,
        bytes: usize,
        now: Option<crate::environment_v4::TrustedTimeSample>,
    ) -> Result<(), SessionError> {
        let root = &self.owner.metadata.as_ref().expect("write metadata").owner;
        // Lock order is original session staging gate, then this request.
        let root_state = root.state.lock().expect("write staging lock");
        let mut state = self.owner.state.lock().expect("operation lock");
        if state.progress.phase != "running" {
            return Err(SessionError::OperationFailed);
        }
        if bytes == 0 {
            return Ok(());
        }
        let accepted = state
            .progress
            .accepted_bytes
            .checked_add(bytes as u64)
            .filter(|total| *total <= state.progress.requested_bytes)
            .ok_or(SessionError::OperationFailed)?;
        let error = state.stopped.or_else(|| {
            if root_state.closed {
                return Some(SessionError::Closed);
            }
            if Instant::now() >= state.deadline {
                return Some(SessionError::Timeout);
            }
            if state.progress.accepted_bytes == 0
                && let Some(gate) = &self.owner.first_byte_gate
            {
                match now {
                    Some(now) => {
                        if let Err(error) = gate(now) {
                            return Some(error);
                        }
                    }
                    None => return Some(SessionError::OperationFailed),
                }
            }
            None
        });
        if let Some(error) = error {
            state.stopped = Some(error);
            drop(state);
            drop(root_state);
            self.owner.changed.notify_waiters();
            return Err(error);
        }
        state.progress.accepted_bytes = accepted;
        drop(state);
        drop(root_state);
        self.owner.changed.notify_waiters();
        Ok(())
    }
    pub async fn canceled(&self) {
        loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let done = {
                let state = self.owner.state.lock().expect("operation lock");
                state.stopped.is_some() || state.progress.phase == "terminal"
            };
            if done {
                return;
            }
            changed.await;
        }
    }
}

struct WriteWaitPermit(Arc<WriteOwner>);
impl Drop for WriteWaitPermit {
    fn drop(&mut self) {
        self.0.state.lock().expect("operation lock").waiters -= 1;
    }
}

/// Keeps one write and its final progress alive independently of wait futures.
/// Requires the stream's original staging owner and ordered admission gate.
pub struct WriteOperation {
    owner: Arc<WriteOwner>,
}
impl std::fmt::Debug for WriteOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteOperation")
            .field("progress", &self.progress())
            .finish()
    }
}
impl WriteOperation {
    pub fn prepare(stream: Arc<dyn ByteStream>, payload: Bytes) -> Self {
        let requested = payload.len() as u64;
        match Self::try_prepare_public(stream, payload) {
            Ok(operation) => operation,
            Err(error) => Self {
                owner: Arc::new(WriteOwner {
                    diagnostics: Mutex::new(None),
                    first_byte_gate: None,
                    state: Mutex::new(WriteState {
                        input: None,
                        progress: WriteProgress {
                            requested_bytes: requested,
                            accepted_bytes: 0,
                            phase: "terminal".into(),
                            terminal_reason: Some(write_reason(error).into()),
                            cleanup: CleanupStatus {
                                complete: true,
                                cleanup_incomplete: false,
                                pending_callbacks: 0,
                            },
                        },
                        stopped: Some(error),
                        deadline: Instant::now(),
                        started: false,
                        start_error: Some(error),
                        waiters: 0,
                    }),
                    changed: Notify::new(),
                    metadata: None,
                }),
            },
        }
    }
    fn try_prepare_public(
        stream: Arc<dyn ByteStream>,
        payload: Bytes,
    ) -> Result<Self, SessionError> {
        let diagnostics = stream.write_staging_owner().and_then(|owner| {
            owner
                .account
                .as_ref()
                .map(|account| account.diagnostic_activity(crate::DiagnosticPhase::Application, 1))
        });
        let result = Self::try_prepare(stream, payload);
        match &result {
            Ok(operation) => {
                *operation
                    .owner
                    .diagnostics
                    .lock()
                    .expect("write diagnostics") = diagnostics;
                operation.owner.finish_diagnostics();
            }
            Err(error) => {
                if let Some(diagnostics) = diagnostics {
                    diagnostics.session_failure(*error);
                }
            }
        }
        result
    }
    pub(crate) fn try_prepare(
        stream: Arc<dyn ByteStream>,
        payload: Bytes,
    ) -> Result<Self, SessionError> {
        Self::try_prepare_guarded(stream, payload, None)
    }
    pub(crate) fn preparation_limits(bytes: usize) -> Result<ResourceLimits, SessionError> {
        if bytes > MAX_PREPARED_WRITE_BYTES {
            return Err(SessionError::ResourceExhausted);
        }
        Ok(ResourceLimits {
            sdk_bytes: (bytes as u64)
                .checked_add(std::mem::size_of::<WriteOwner>() as u64)
                .ok_or(SessionError::ResourceExhausted)?,
            items: 1,
            work_slots: 1,
            tasks: 2,
            timers: 1,
            ..ResourceLimits::default()
        })
    }
    pub(crate) fn try_prepare_guarded(
        stream: Arc<dyn ByteStream>,
        payload: Bytes,
        first_byte_gate: Option<FirstByteGate>,
    ) -> Result<Self, SessionError> {
        Self::try_prepare_guarded_with_backing(stream, payload, first_byte_gate, None)
    }
    pub(crate) fn try_prepare_guarded_prepaid(
        stream: Arc<dyn ByteStream>,
        payload: Bytes,
        first_byte_gate: Option<FirstByteGate>,
        charge: ResourceCharge,
    ) -> Result<Self, SessionError> {
        Self::try_prepare_guarded_with_backing(stream, payload, first_byte_gate, Some(charge))
    }
    fn try_prepare_guarded_with_backing(
        stream: Arc<dyn ByteStream>,
        payload: Bytes,
        first_byte_gate: Option<FirstByteGate>,
        prepaid: Option<ResourceCharge>,
    ) -> Result<Self, SessionError> {
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| SessionError::OperationFailed)?;
        let preparation = stream.write_preparation_permit()?;
        let root = stream
            .write_staging_owner()
            .ok_or(SessionError::OperationFailed)?;
        let reservations = if prepaid.is_some() {
            root.reserve_with_backing(payload.len(), prepaid)?
        } else {
            root.reserve(payload.len())?
        };
        Self::from_reservations(
            stream,
            payload,
            first_byte_gate,
            reservations,
            preparation,
            runtime,
        )
    }
    pub(crate) fn reserve_bridge_write(
        stream: &dyn ByteStream,
        maximum_bytes: usize,
    ) -> Result<BridgeWriteReservation, SessionError> {
        let root = stream
            .write_staging_owner()
            .ok_or(SessionError::OperationFailed)?;
        Ok(BridgeWriteReservation {
            reservations: root.reserve(maximum_bytes)?,
            maximum_bytes,
        })
    }
    pub(crate) fn try_prepare_bridge(
        stream: Arc<dyn ByteStream>,
        payload: Bytes,
        reservation: BridgeWriteReservation,
        stop: &tokio_util::sync::CancellationToken,
    ) -> Result<Self, SessionError> {
        if payload.len() > reservation.maximum_bytes {
            return Err(SessionError::ResourceExhausted);
        }
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| SessionError::OperationFailed)?;
        let preparation = stream.write_preparation_permit()?;
        let stop = stop.clone();
        let gate = Arc::new(move |_now: crate::environment_v4::TrustedTimeSample| {
            if stop.is_cancelled() {
                Err(SessionError::Canceled)
            } else {
                Ok(())
            }
        });
        Self::from_reservations(
            stream,
            payload,
            Some(gate),
            reservation.reservations,
            preparation,
            runtime,
        )
    }
    fn from_reservations(
        stream: Arc<dyn ByteStream>,
        payload: Bytes,
        first_byte_gate: Option<FirstByteGate>,
        reservations: WriteReservations,
        preparation: Option<StreamWritePreparationPermit>,
        runtime: tokio::runtime::Handle,
    ) -> Result<Self, SessionError> {
        // Bytes can be a tiny slice of an arbitrarily large backing. Snapshot
        // into exact owned storage so the reservation accounts for what we retain.
        let mut snapshot = Vec::new();
        snapshot
            .try_reserve_exact(payload.len())
            .map_err(|_| SessionError::ResourceExhausted)?;
        snapshot.extend_from_slice(&payload);
        let requested_bytes = payload.len() as u64;
        drop(payload);
        let owner = Arc::new(WriteOwner {
            diagnostics: Mutex::new(None),
            first_byte_gate,
            state: Mutex::new(WriteState {
                input: Some(PreparedWrite {
                    preparation,
                    stream,
                    payload: Bytes::from(snapshot.into_boxed_slice()),
                    staging: reservations.staging,
                    native_charge: reservations.native_charge,
                }),
                progress: WriteProgress {
                    requested_bytes,
                    accepted_bytes: 0,
                    phase: "prepared".into(),
                    terminal_reason: None,
                    cleanup: CleanupStatus {
                        complete: false,
                        cleanup_incomplete: false,
                        pending_callbacks: 0,
                    },
                },
                stopped: None,
                deadline: reservations.deadline,
                started: false,
                start_error: None,
                waiters: 0,
            }),
            changed: Notify::new(),
            metadata: Some(reservations.metadata),
        });
        runtime.spawn(owner.clone().monitor(reservations.timer_charge));
        Ok(Self { owner })
    }
    pub async fn start(&self) -> Result<(), SessionError> {
        if let Some(account) = self
            .owner
            .metadata
            .as_ref()
            .and_then(|r| r.owner.account.as_ref())
            && let Err(error) = account.check()
        {
            if matches!(
                error,
                EnvironmentError::TimePending | EnvironmentError::TimeUnavailable
            ) {
                // A temporary gate failure leaves the original input and fixed
                // deadline owned by this operation for a subsequent Start.
                return Err(environment_session_error(error));
            }
            let error = environment_session_error(error);
            self.owner.stop(error);
            return Err(error);
        }
        let root = self.owner.metadata.as_ref().map(|r| r.owner.clone());
        let root_state = root
            .as_ref()
            .map(|root| root.state.lock().expect("write staging lock"));
        let mut state = self.owner.state.lock().expect("operation lock");
        if state.started {
            return state.start_error.map_or(Ok(()), Err);
        }
        if let Some(error) = state.start_error.or(state.stopped) {
            return Err(error);
        }
        let error = if root_state.as_ref().is_none_or(|s| s.closed) {
            Some(SessionError::Closed)
        } else if Instant::now() >= state.deadline {
            Some(SessionError::Timeout)
        } else {
            None
        };
        if let Some(error) = error {
            drop(state);
            drop(root_state);
            self.owner.stop(error);
            return Err(error);
        }
        let runtime = match tokio::runtime::Handle::try_current() {
            Ok(runtime) => runtime,
            Err(_) => {
                drop(state);
                drop(root_state);
                self.owner.stop(SessionError::OperationFailed);
                return Err(SessionError::OperationFailed);
            }
        };
        state.started = true;
        let input = state.input.take().expect("prepared write input");
        state.progress.phase = "running".into();
        state.progress.cleanup.pending_callbacks = 1;
        let owner = self.owner.clone();
        runtime.spawn(async move {
            use futures_util::FutureExt;
            let admission = WriteRequestAdmission {
                owner: owner.clone(),
            };
            let PreparedWrite {
                preparation,
                stream,
                payload,
                staging,
                native_charge,
            } = input;
            let result = std::panic::AssertUnwindSafe(stream.write_prepared(payload, &admission))
                .catch_unwind()
                .await
                .unwrap_or(Err(SessionError::OperationFailed));
            // Retain staging through the native future, including canceled tails.
            drop(stream);
            drop(preparation);
            drop(staging);
            drop(native_charge);
            let mut state = owner.state.lock().expect("operation lock");
            let reason = match result {
                Ok(()) if state.progress.accepted_bytes == state.progress.requested_bytes => {
                    "complete"
                }
                Ok(()) => state.stopped.map_or("failed", write_reason),
                Err(error) => write_reason(state.stopped.unwrap_or(error)),
            };
            state.progress.terminal_reason = Some(reason.into());
            state.progress.phase = "terminal".into();
            state.progress.cleanup.pending_callbacks = 0;
            state.progress.cleanup.complete = true;
            drop(state);
            owner.finish_diagnostics();
            owner.changed.notify_waiters();
        });
        Ok(())
    }
    pub async fn wait(&self) -> Result<WriteProgress, SessionError> {
        let _permit = {
            let mut state = self.owner.state.lock().expect("operation lock");
            if state.progress.phase == "terminal" {
                return Ok(state.progress.clone());
            }
            if state.waiters >= 4 {
                return Err(SessionError::ResourceExhausted);
            }
            state.waiters += 1;
            WriteWaitPermit(self.owner.clone())
        };
        loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let progress = self.progress();
            if progress.phase == "terminal" {
                return Ok(progress);
            }
            changed.await;
        }
    }
    pub fn cancel(&self) {
        self.owner.stop(SessionError::Canceled);
    }
    /// Permanently withdraw before the original first-byte acceptance gate.
    /// A committed prefix keeps its complete remaining write responsibility.
    pub(crate) fn cancel_unsubmitted(&self) -> bool {
        let input = {
            let mut state = self.owner.state.lock().expect("operation lock");
            if state.progress.accepted_bytes != 0 || state.progress.phase == "terminal" {
                return false;
            }
            state.stopped = Some(SessionError::Canceled);
            if !state.started {
                state.start_error = Some(SessionError::Canceled);
                state.input.take()
            } else {
                None
            }
        };
        if let Some(input) = input {
            drop(input);
            let mut state = self.owner.state.lock().expect("operation lock");
            state.progress.phase = "terminal".into();
            state.progress.terminal_reason = Some("canceled".into());
            state.progress.cleanup.complete = true;
        }
        self.owner.finish_diagnostics();
        self.owner.changed.notify_waiters();
        true
    }
    pub fn progress(&self) -> WriteProgress {
        self.owner
            .state
            .lock()
            .expect("operation lock")
            .progress
            .clone()
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        self.progress().cleanup
    }
}

#[derive(Debug)]
pub struct OperationNotificationSubscription {
    closed: Mutex<bool>,
    changed: Notify,
}
impl OperationNotificationSubscription {
    pub fn new() -> Self {
        Self {
            closed: Mutex::new(false),
            changed: Notify::new(),
        }
    }
    pub fn close(&self) {
        *self.closed.lock().expect("subscription lock") = true;
        self.changed.notify_waiters();
    }
    pub async fn wait_closed(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if *self.closed.lock().expect("subscription lock") {
                return;
            }
            changed.await;
        }
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        CleanupStatus {
            complete: *self.closed.lock().expect("subscription lock"),
            cleanup_incomplete: false,
            pending_callbacks: 0,
        }
    }
}

impl Default for OperationNotificationSubscription {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationStatus {
    NotStarted,
    Pending,
    Accepted,
    Executing,
    Completed,
    Failed,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultPayload {
    pub status: OperationStatus,
    pub payload: Option<Bytes>,
}
#[derive(Debug)]
pub struct StreamExt;
impl StreamExt {
    pub fn reader_cursor(
        stream: Arc<dyn ByteStream>,
        options: ReaderCursorOptions,
    ) -> Result<ReaderCursor, ReadMethodFailure> {
        ReaderCursor::new(stream, options)
    }
    pub fn prepare_write(
        stream: Arc<dyn ByteStream>,
        payload: Bytes,
    ) -> Result<WriteOperation, SessionError> {
        WriteOperation::try_prepare_public(stream, payload)
    }
}

#[cfg(test)]
mod write_owner_tests {
    use super::*;
    use async_trait::async_trait;
    use tokio::sync::Semaphore;

    #[derive(Debug)]
    struct NativeWrite {
        staging: Arc<WriteStagingOwner>,
        read_owner: Arc<StreamReadOwner>,
        entered: Semaphore,
        release: Semaphore,
    }
    impl NativeWrite {
        fn new(staging: Arc<WriteStagingOwner>) -> Arc<Self> {
            let read_owner = Arc::new(staging.account.clone().map_or_else(
                || StreamReadOwner::new(1024),
                |account| StreamReadOwner::from_account(1024, account),
            ));
            Arc::new(Self {
                staging,
                read_owner,
                entered: Semaphore::new(0),
                release: Semaphore::new(0),
            })
        }
    }
    #[async_trait]
    impl ByteStream for NativeWrite {
        fn internal_test_id(&self) -> u64 {
            0
        }
        fn kind(&self) -> &str {
            "test"
        }
        fn terminal_error(&self) -> Option<SessionError> {
            None
        }
        fn write_staging_owner(&self) -> Option<Arc<WriteStagingOwner>> {
            Some(self.staging.clone())
        }
        fn read_owner(&self) -> Option<Arc<StreamReadOwner>> {
            Some(self.read_owner.clone())
        }
        fn read_delivery_owner(&self) -> Option<Arc<ReadDeliveryAuthorization>> {
            Some(self.read_owner.delivery_authorization())
        }
        async fn read(&self) -> Result<Option<Bytes>, SessionError> {
            Err(SessionError::OperationFailed)
        }
        async fn write(&self, _: Bytes) -> Result<usize, SessionError> {
            Err(SessionError::OperationFailed)
        }
        async fn write_prepared(
            &self,
            payload: Bytes,
            admission: &WriteRequestAdmission,
        ) -> Result<(), SessionError> {
            let first = payload.len().min(2);
            admission.accept(first)?;
            self.entered.add_permits(1);
            self.release.acquire().await.unwrap().forget();
            admission.accept(payload.len() - first)
        }
        async fn close_write(&self) -> Result<(), SessionError> {
            Ok(())
        }
        async fn reset(&self) -> Result<(), SessionError> {
            Ok(())
        }
        async fn close(&self) -> Result<(), SessionError> {
            Ok(())
        }
    }
    fn short_owner() -> Arc<WriteStagingOwner> {
        Arc::new(WriteStagingOwner {
            lifetime: Duration::from_millis(10),
            ..WriteStagingOwner::new()
        })
    }
    fn charge(root: &WriteStagingOwner) -> (usize, usize) {
        let state = root.state.lock().unwrap();
        (state.bytes, state.operations)
    }

    #[tokio::test]
    async fn public_write_diagnostics_keep_one_original_context_through_canceled_native_tail() {
        use crate::environment_v4::tests::{bounds, environment};
        use crate::{DiagnosticMetric, DiagnosticPhase, DiagnosticState};
        let environment = environment();
        let (sink, events) = crate::diagnostics_v4::capture_for_test(&environment);
        let account = environment.admit([1; 32], bounds()).unwrap();
        let staging = Arc::new(WriteStagingOwner::from_account(account));
        let stream = NativeWrite::new(staging);
        let operation =
            StreamExt::prepare_write(stream.clone(), Bytes::from_static(b"abcd")).unwrap();
        operation.start().await.unwrap();
        stream.entered.acquire().await.unwrap().forget();
        {
            let waiting = operation.wait();
            tokio::pin!(waiting);
            tokio::select! { _ = &mut waiting => panic!("original callback is blocked"), _ = tokio::task::yield_now() => {} }
        }
        assert_eq!(
            environment
                .diagnostic_metric(DiagnosticMetric::ApplicationOperations)
                .total,
            1
        );
        assert_eq!(
            environment
                .diagnostic_metric(DiagnosticMetric::ApplicationFailures)
                .total,
            0
        );
        operation.cancel();
        assert!(!operation.cleanup_status().complete);
        assert_eq!(
            environment
                .diagnostic_metric(DiagnosticMetric::ApplicationFailures)
                .total,
            0
        );
        stream.release.add_permits(1);
        let progress = operation.wait().await.unwrap();
        assert_eq!(progress.terminal_reason.as_deref(), Some("canceled"));
        assert!(progress.cleanup.complete);
        assert_eq!(
            environment
                .diagnostic_metric(DiagnosticMetric::ApplicationFailures)
                .total,
            1
        );
        drop(operation);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let finished = events
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|event| event.state == DiagnosticState::Closed);
                if finished {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        {
            let records = events.lock().unwrap();
            let ids: std::collections::BTreeSet<_> =
                records.iter().map(|event| event.correlation_id).collect();
            assert_eq!(ids.len(), 1);
            assert_eq!(
                records
                    .iter()
                    .filter(|event| event.phase == DiagnosticPhase::Application
                        && event.state == DiagnosticState::Canceled)
                    .count(),
                1
            );
        }
        sink.close();
        assert!(sink.wait_cleanup().await.complete);
    }

    #[tokio::test]
    async fn environment_close_retains_original_running_task_and_payload_charges() {
        use crate::environment_v4::tests::{bounds, environment};
        let environment = environment();
        let baseline = environment.charged();
        let account = environment.admit([1; 32], bounds()).unwrap();
        let staging = Arc::new(WriteStagingOwner::from_account(account));
        let stream = NativeWrite::new(staging.clone());
        let operation =
            WriteOperation::try_prepare(stream.clone(), Bytes::from_static(b"abcd")).unwrap();
        assert_eq!(environment.charged().tasks, 2);
        operation.start().await.unwrap();
        stream.entered.acquire().await.unwrap().forget();
        environment.close();
        // The native task has already accepted a prefix and is still holding
        // the real backing even after its authorization is permanently sealed.
        tokio::time::timeout(Duration::from_secs(1), async {
            while environment.charged().tasks > 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(operation.progress().accepted_bytes, 2);
        assert_eq!(
            environment.charged().sdk_bytes,
            baseline.sdk_bytes + 4 + std::mem::size_of::<WriteOwner>() as u64
        );
        assert!(!environment.cleanup().0);
        stream.release.add_permits(1);
        let result = operation.wait().await.unwrap();
        assert_eq!(result.accepted_bytes, 2);
        assert_eq!(environment.charged().tasks, 0);
        assert_eq!(
            environment.charged().sdk_bytes,
            baseline.sdk_bytes + std::mem::size_of::<WriteOwner>() as u64
        );
        drop((operation, stream, staging));
        assert_eq!(environment.charged(), baseline);
        assert!(environment.cleanup().0);
    }

    #[tokio::test]
    async fn complete_cursor_releases_the_original_session_slot_before_take() {
        use crate::environment_v4::tests::{bounds, environment};
        let environment = environment();
        let account = environment.admit([1; 32], bounds()).unwrap();
        let staging = Arc::new(WriteStagingOwner::from_account(account));
        let stream = NativeWrite::new(staging.clone());
        let cursor = ReaderCursor::new(
            stream.clone(),
            ReaderCursorOptions {
                exact: Some(4),
                delimiter: None,
                max_bytes: 4,
            },
        )
        .unwrap();
        cursor.transfer_from(b"body").unwrap();
        drop((stream, staging));
        assert_eq!(environment.charged().sessions, 0);
        assert_eq!(environment.charged().work_slots, 1);
        assert_eq!(
            cursor.take_prefix().await.unwrap().data,
            Bytes::from_static(b"body")
        );
        assert_eq!(environment.charged().work_slots, 1);
        drop(cursor);
        assert_eq!(environment.charged().work_slots, 0);
    }

    #[tokio::test]
    async fn cursor_handoff_uses_original_environment_gate_and_retains_metadata() {
        use crate::environment_v4::tests::{bounds, environment};
        let environment = environment();
        let baseline = environment.charged();
        let account = environment.admit([1; 32], bounds()).unwrap();
        let staging = Arc::new(WriteStagingOwner::from_account(account.clone()));
        let stream = NativeWrite::new(staging.clone());
        let options = ReaderCursorOptions {
            exact: Some(4),
            delimiter: None,
            max_bytes: 4,
        };
        let first = ReaderCursor::new(stream.clone(), options.clone()).unwrap();
        first.transfer_from(b"body").unwrap();
        assert_eq!(Arc::strong_count(&stream), 1);
        assert_eq!(
            first.take_prefix().await.unwrap().data,
            Bytes::from_static(b"body")
        );
        assert_eq!(
            environment.charged().sdk_bytes,
            baseline.sdk_bytes + std::mem::size_of::<ReaderCursor>() as u64
        );
        assert_eq!(environment.charged().work_slots, 1);
        let second = ReaderCursor::new(stream.clone(), options).unwrap();
        second.transfer_from(b"next").unwrap();
        account.revoke();
        assert_eq!(
            second.take_prefix().await.unwrap_err().reason,
            ReadMethodFailureReason::AuthorizationDenied
        );
        assert!(!second.snapshot().delivered);
        second.close();
        assert_eq!(environment.charged().work_slots, 2);
        drop((first, second, stream, staging, account));
        assert_eq!(environment.charged(), baseline);
    }

    #[tokio::test]
    async fn prepared_expiry_reclaims_input_without_start_or_wait() {
        let root = short_owner();
        let stream = NativeWrite::new(root.clone());
        let operation =
            WriteOperation::try_prepare(stream.clone(), Bytes::from_static(b"body")).unwrap();
        assert_eq!(charge(&root), (4, 1));
        // No Start or Wait drives expiration: the original owner already owns
        // its finite timer responsibility from Prepare.
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            operation.progress().terminal_reason.as_deref(),
            Some("deadline_exceeded")
        );
        assert!(operation.cleanup_status().complete);
        assert_eq!(Arc::strong_count(&stream), 1);
        assert_eq!(charge(&root), (0, 1));
        assert_eq!(operation.start().await, Err(SessionError::Timeout));
        drop(operation);
        assert_eq!(charge(&root), (0, 0));
    }

    #[tokio::test]
    async fn shared_session_staging_rejects_other_stream_but_not_another_session() {
        let root = Arc::new(WriteStagingOwner::new());
        let first = NativeWrite::new(root.clone());
        let second = NativeWrite::new(root.clone());
        let independent = NativeWrite::new(Arc::new(WriteStagingOwner::new()));
        let operation =
            WriteOperation::try_prepare(first, Bytes::from(vec![0; MAX_PREPARED_WRITE_BYTES]))
                .unwrap();
        assert_eq!(
            WriteOperation::try_prepare(second.clone(), Bytes::from_static(b"x")).unwrap_err(),
            SessionError::ResourceExhausted
        );
        let other = WriteOperation::try_prepare(independent, Bytes::from_static(b"x")).unwrap();
        other.cancel();
        operation.cancel();
        let next = WriteOperation::try_prepare(second, Bytes::from_static(b"x")).unwrap();
        next.cancel();
    }

    #[tokio::test]
    async fn expired_running_write_keeps_charge_until_accepted_tail_exits() {
        let root = Arc::new(WriteStagingOwner::new());
        let stream = NativeWrite::new(root.clone());
        let operation =
            WriteOperation::try_prepare(stream.clone(), Bytes::from_static(b"abcd")).unwrap();
        operation.start().await.unwrap();
        stream.entered.acquire().await.unwrap().forget();
        // Move the test deadline only after native ownership is observed;
        // machine scheduling cannot expire the prepared phase accidentally.
        operation.owner.state.lock().unwrap().deadline = Instant::now();
        operation.owner.changed.notify_waiters();
        tokio::time::timeout(Duration::from_secs(1), async {
            while operation.owner.state.lock().unwrap().stopped.is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(operation.progress().accepted_bytes, 2);
        assert!(!operation.cleanup_status().complete);
        assert_eq!(charge(&root), (4, 1));
        stream.release.add_permits(1);
        let result = operation.wait().await.unwrap();
        assert_eq!(result.accepted_bytes, 2);
        assert_eq!(result.terminal_reason.as_deref(), Some("deadline_exceeded"));
        assert!(result.cleanup.complete);
        assert_eq!(charge(&root), (0, 1));
    }

    #[tokio::test]
    async fn session_owner_close_reclaims_prepared_input_and_closes_admission() {
        let root = Arc::new(WriteStagingOwner::new());
        let stream = NativeWrite::new(root.clone());
        let operation =
            WriteOperation::try_prepare(stream.clone(), Bytes::from_static(b"body")).unwrap();
        root.close();
        let result = tokio::time::timeout(Duration::from_secs(1), operation.wait())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.accepted_bytes, 0);
        assert_eq!(result.terminal_reason.as_deref(), Some("stream_terminated"));
        assert_eq!(charge(&root), (0, 1));
        assert_eq!(
            WriteOperation::try_prepare(stream, Bytes::new()).unwrap_err(),
            SessionError::Closed
        );
    }

    #[tokio::test]
    async fn completed_result_metadata_stays_in_the_original_finite_budget() {
        let root = Arc::new(WriteStagingOwner::new());
        let stream = NativeWrite::new(root.clone());
        let mut operations = Vec::new();
        for _ in 0..MAX_PREPARED_WRITE_OPERATIONS {
            let operation = WriteOperation::try_prepare(stream.clone(), Bytes::new()).unwrap();
            operation.cancel();
            operations.push(operation);
        }
        assert_eq!(charge(&root), (0, MAX_PREPARED_WRITE_OPERATIONS));
        assert_eq!(
            WriteOperation::try_prepare(stream.clone(), Bytes::new()).unwrap_err(),
            SessionError::ResourceExhausted
        );
        operations.clear();
        // Each original timer returns its metadata reference on actual exit;
        // cooperative scheduling need not run all 128 tasks in one yield.
        tokio::time::timeout(Duration::from_secs(1), async {
            while charge(&root).1 != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(charge(&root), (0, 0));
        WriteOperation::try_prepare(stream, Bytes::new())
            .unwrap()
            .cancel();
    }
}
