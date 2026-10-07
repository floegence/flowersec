//! Logical server hosting over original issued tunnel legs. Physical dialing
//! never consumes the client's pool lease and never changes the logical role.
use super::*;
#[path = "pool_server_allow_v4.rs"]
mod pool_allow;
pub use pool_allow::{PoolServerAllowBinding, PoolServerAllowOptions};

#[derive(Clone, Debug)]
pub struct TunnelServeOptions {
    pub callbacks: Arc<dyn ServeCallbacks>,
    pub application_limits: ApplicationLimits,
    pub cancellation: CancellationToken,
    pub provider: WssConnectOptions,
}
#[derive(Debug)]
pub struct ReverseTunnelServeOptions {
    pub callbacks: Arc<dyn ServeCallbacks>,
    pub application_limits: ApplicationLimits,
    pub cancellation: CancellationToken,
    pub provider: super::super::reverse::ReverseTunnelProviderOptions,
}
/// Physical live B ingress prepared from its independent installation before
/// TxB. The one-shot original publication supplies the account and Grant later.
/// Binding this socket gives no authorization or Session publication right.
pub struct LiveReverseTunnelListener {
    listener: Option<Arc<super::super::reverse::SharedRelayListener>>,
    provider: WssConnectOptions,
    changed: Arc<Notify>,
    observers: AtomicUsize,
    cleanup_until: Mutex<Option<Instant>>,
    _charge: EnvironmentCharge,
}
impl fmt::Debug for LiveReverseTunnelListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LiveReverseTunnelListener { <opaque> }")
    }
}
#[derive(Debug)]
pub struct LiveReverseTunnelServeOptions {
    pub callbacks: Arc<dyn ServeCallbacks>,
    pub application_limits: ApplicationLimits,
    pub cancellation: CancellationToken,
    pub listener: LiveReverseTunnelListener,
}
#[derive(Clone)]
pub(super) struct OriginalListenerReadiness {
    listener: Arc<super::super::reverse::SharedRelayListener>,
    provider: WssConnectOptions,
}
impl OriginalListenerReadiness {
    pub(super) fn belongs_to(&self, root: &Arc<EnvironmentRoot>) -> bool {
        self.listener.belongs_to(root)
    }
    pub(super) fn matches(
        &self,
        listener: &Arc<super::super::reverse::SharedRelayListener>,
        options: &WssConnectOptions,
    ) -> bool {
        Arc::ptr_eq(&self.listener, listener) && self.provider.same_installation(options)
    }
    pub(super) fn check_ready(&self) -> ConnectResult<()> {
        if !self.listener.physical_binding_ready()? {
            return Err(ConnectError::Carrier);
        }
        Ok(())
    }
    pub(super) fn reverse_installation(
        &self,
        options: &super::super::reverse::ReverseTunnelProviderOptions,
    ) -> ConnectResult<(
        Arc<super::super::reverse::SharedRelayListener>,
        WssConnectOptions,
    )> {
        self.check_ready()?;
        if !self.listener.matches_reverse_installation(options) {
            return Err(ConnectError::Configuration);
        }
        Ok((self.listener.clone(), self.provider.clone()))
    }
    pub(super) fn validate(
        &self,
        root: &Arc<EnvironmentRoot>,
        artifact: &[u8],
        registration: &crate::namespace_v4::verifier::credential::VerifiedLiveTunnelRegistration,
    ) -> ConnectResult<()> {
        if !self.belongs_to(root) {
            return Err(ConnectError::Configuration);
        }
        self.listener
            .validate_live_server_registration(artifact, registration, &self.provider)
    }
    pub(super) async fn wait_ready(
        &self,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> ConnectResult<()> {
        self.listener
            .wait_ready(timeout, cancellation)
            .await
            .map(|_| ())
    }
}
struct LiveListenerObserver<'a>(&'a LiveReverseTunnelListener);
impl Drop for LiveListenerObserver<'_> {
    fn drop(&mut self) {
        self.0.observers.fetch_sub(1, Ordering::AcqRel);
    }
}
impl LiveReverseTunnelListener {
    pub(crate) fn preparation_timeout(&self) -> Duration {
        self.provider.timeout
    }
    pub(super) fn original_readiness(&self) -> ConnectResult<OriginalListenerReadiness> {
        Ok(OriginalListenerReadiness {
            listener: self
                .listener
                .as_ref()
                .ok_or(ConnectError::Canceled)?
                .clone(),
            provider: self.provider.clone(),
        })
    }
    pub fn local_address(&self) -> std::net::SocketAddr {
        self.listener
            .as_ref()
            .expect("original live listener")
            .local_address()
    }
    pub async fn wait_ready(
        &self,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> ConnectResult<std::net::SocketAddr> {
        self.listener
            .as_ref()
            .ok_or(ConnectError::Canceled)?
            .wait_ready(timeout, cancellation)
            .await
    }
    pub fn close(&self) {
        if let Some(listener) = &self.listener {
            listener.close();
        }
        self.cleanup_until
            .lock()
            .expect("original live listener cleanup deadline")
            .get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
        self.changed.notify_waiters();
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let complete = self
            .listener
            .as_ref()
            .is_none_or(|listener| listener.cleanup_complete());
        let elapsed = self
            .cleanup_until
            .lock()
            .expect("original live listener cleanup deadline")
            .is_some_and(|deadline| Instant::now() >= deadline);
        CleanupStatus {
            complete,
            cleanup_incomplete: !complete && elapsed,
            pending_callbacks: u64::from(!complete),
        }
    }
    pub async fn wait_cleanup(&self) -> ConnectResult<CleanupStatus> {
        self.observers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 16).then_some(count + 1)
            })
            .map_err(|_| ConnectError::Capacity)?;
        let _observer = LiveListenerObserver(self);
        let until = *self
            .cleanup_until
            .lock()
            .expect("original live listener cleanup deadline")
            .get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete || status.cleanup_incomplete {
                return Ok(status);
            }
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep_until(until) => return Ok(self.cleanup_status()) }
        }
    }
}
impl Drop for LiveReverseTunnelListener {
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) fn prepare_live_reverse_listener(
    root: Arc<EnvironmentRoot>,
    provider: super::super::reverse::ReverseTunnelProviderOptions,
    carrier: u8,
    host: String,
    maximum_publications: usize,
) -> ConnectResult<LiveReverseTunnelListener> {
    if !(1..=64).contains(&maximum_publications) {
        return Err(ConnectError::Configuration);
    }
    let charge = root.reserve_environment(ResourceLimits {
        sdk_bytes: 4096,
        items: 1,
        work_slots: 16,
        timers: 16,
        ..ResourceLimits::default()
    })?;
    let (capture, provider) = super::super::reverse::Capture::new(root, provider)?;
    let listener = super::super::reverse::SharedRelayListener::new(
        capture,
        provider.clone(),
        maximum_publications,
        true,
    )?;
    let changed = Arc::new(Notify::new());
    listener.observe_cleanup(changed.clone())?;
    listener.start_installed(carrier, host)?;
    Ok(LiveReverseTunnelListener {
        listener: Some(listener),
        provider,
        changed,
        observers: AtomicUsize::new(0),
        cleanup_until: Mutex::new(None),
        _charge: charge,
    })
}

#[expect(
    clippy::large_enum_variant,
    reason = "This single consumed batch moves original live material without a second heap owner."
)]
enum OriginalTunnelBatch {
    Pool(Vec<TunnelPoolCredentialBytes>),
    RegisteredPool(super::super::registered_pool::RegisteredPoolTunnelServerMaterial),
    Live(super::live_source::OriginalLiveTunnelServerMaterial),
}
impl OriginalTunnelBatch {
    fn shape(&self) -> ConnectResult<(usize, AcceptedAuthorizationProfile)> {
        match self {
            Self::Pool(credentials)
                if !credentials.is_empty()
                    && credentials.len() <= 64
                    && credentials.capacity() <= 64 =>
            {
                Ok((
                    credentials.len(),
                    AcceptedAuthorizationProfile::PreauthorizedPool,
                ))
            }
            Self::Pool(_) => Err(ConnectError::Configuration),
            Self::RegisteredPool(_) => Ok((1, AcceptedAuthorizationProfile::PreauthorizedPool)),
            Self::Live(_) => Ok((1, AcceptedAuthorizationProfile::LiveAuthority)),
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Tunnel serving keeps original credential, admission, relay audience and physical listener inputs explicit."
)]
pub(crate) async fn serve_live_tunnel_on_original_listener(
    root: Arc<EnvironmentRoot>,
    namespaces: Vec<Arc<Namespace>>,
    keys: IdentityKeys,
    material: super::live_source::OriginalLiveTunnelServerMaterial,
    relay_service: String,
    relay_audience: String,
    admission: Arc<SQLiteAdmissionAuthority>,
    options: LiveReverseTunnelServeOptions,
) -> ConnectResult<TunnelServeHandle> {
    let LiveReverseTunnelServeOptions {
        mut listener,
        callbacks,
        application_limits,
        cancellation,
    } = options;
    let original = listener
        .listener
        .as_ref()
        .ok_or(ConnectError::Configuration)?;
    if !original.belongs_to(&root) {
        return Err(ConnectError::Configuration);
    }
    let options = TunnelServeOptions {
        callbacks,
        application_limits,
        cancellation,
        provider: listener.provider.clone(),
    };
    // Transfer this exact original socket and verified material owner. No
    // rebind or Account reconstruction follows TxB.
    let original = listener
        .listener
        .take()
        .ok_or(ConnectError::Configuration)?;
    let result = serve_original(
        root,
        namespaces,
        keys,
        OriginalTunnelBatch::Live(material),
        relay_service,
        relay_audience,
        admission,
        options,
        Some(original.clone()),
    )
    .await;
    if result.is_err() {
        original.close();
        // The physical worker keeps its backing until it actually exits.
        let _ = original.wait_original_cleanup(Duration::from_secs(5)).await;
    }
    result
}

/// The original host owns every prepared leg, unpublished child and callback.
/// Accept and Drain retain the same behavior as the direct server host.
#[derive(Debug)]
pub struct TunnelServeHandle {
    owner: Arc<ServeOwner>,
    incoming: tokio::sync::Mutex<mpsc::Receiver<Session>>,
    reverse: Option<Arc<super::super::reverse::SharedRelayListener>>,
    pool_allow: Option<Arc<pool_allow::PoolAllow>>,
    registered_pool: Option<Arc<super::super::registered_pool::RegisteredPoolControl>>,
}
impl TunnelServeHandle {
    /// Install the independent authenticated A-to-B control entrance. Pool
    /// slots remain dormant until this exact recipient accepts an original
    /// server Allow; installation alone never invokes provider preparation.
    pub async fn serve_pool_allow(
        &self,
        identity: WssServerIdentity,
        options: PoolServerAllowOptions,
    ) -> ConnectResult<PoolServerAllowBinding> {
        let binding = self
            .pool_allow
            .as_ref()
            .ok_or(ConnectError::Configuration)?
            .install(identity, options)
            .await?;
        if let Some(control) = &self.registered_pool
            && let Err(error) = control.installed(&self.owner.stop).await
        {
            self.owner.close();
            return Err(error);
        }
        Ok(binding)
    }
    /// Wait until every original server leg has completed native carrier
    /// preparation. This is the publication barrier used by live-authority
    /// delivery before it acknowledges that the B-side route is ready; it does
    /// not claim or authenticate a relay Grant and does not wait for Session
    /// READY.
    pub async fn wait_prepared(
        &self,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> ConnectResult<()> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) || cancellation.is_cancelled() {
            return Err(if cancellation.is_cancelled() {
                ConnectError::Canceled
            } else {
                ConnectError::Configuration
            });
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ConnectError::Configuration)?;
        let Some(_observer) = self.owner.observe()? else {
            return Err(ConnectError::Canceled);
        };
        loop {
            let changed = self.owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if cancellation.is_cancelled() {
                return Err(ConnectError::Canceled);
            }
            if Instant::now() >= deadline {
                return Err(ConnectError::Deadline);
            }
            {
                let gate = self
                    .owner
                    .gate
                    .lock()
                    .expect("tunnel carrier preparation state");
                if gate.closed || self.owner.root.is_closed() {
                    return Err(ConnectError::Canceled);
                }
                let progress = gate
                    .preparation
                    .as_ref()
                    .ok_or(ConnectError::Configuration)?;
                if let Some(error) = progress.failure {
                    return Err(error);
                }
                if progress.completed == progress.target {
                    return Ok(());
                }
            }
            tokio::select! {
                _ = changed => {},
                _ = cancellation.cancelled() => return Err(ConnectError::Canceled),
                _ = tokio::time::sleep_until(deadline) => return Err(ConnectError::Deadline),
            }
        }
    }
    pub async fn wait_reverse_listener_ready(
        &self,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> ConnectResult<std::net::SocketAddr> {
        self.reverse
            .as_ref()
            .ok_or(ConnectError::Configuration)?
            .wait_ready(timeout, cancellation)
            .await
    }
    pub async fn accept(&self) -> Option<Session> {
        self.incoming.lock().await.recv().await
    }
    pub fn close(&self) {
        self.owner.close();
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let mut status = self.owner.cleanup();
        let pending = self
            .pool_allow
            .as_ref()
            .map_or(0, |allow| allow.physical_pending())
            + self
                .registered_pool
                .as_ref()
                .map_or(0, |control| control.physical_pending());
        status.complete &= pending == 0;
        status.pending_callbacks += pending;
        status.cleanup_incomplete |= pending != 0
            && self
                .owner
                .cleanup_deadline
                .lock()
                .expect("Allow cleanup deadline")
                .is_some_and(|deadline| Instant::now() >= deadline);
        status
    }
    pub async fn wait_cleanup(&self) -> ConnectResult<CleanupStatus> {
        let status = self.cleanup_status();
        if status.complete || status.cleanup_incomplete {
            return Ok(status);
        }
        let Some(_wait) = self.owner.observe()? else {
            return Ok(self.cleanup_status());
        };
        loop {
            let notified = self.owner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete || status.cleanup_incomplete {
                return Ok(status);
            }
            let deadline = *self
                .owner
                .cleanup_deadline
                .lock()
                .expect("tunnel Serve cleanup deadline");
            if let Some(deadline) = deadline {
                tokio::select! {
                    _ = &mut notified => {},
                    _ = tokio::time::sleep_until(deadline) => return Ok(self.cleanup_status()),
                }
            } else {
                notified.await;
            }
        }
    }
    pub fn drain(&self, timeout: Duration) -> ConnectResult<ServeDrainOperation> {
        drain::start(&self.owner, timeout)
    }
    pub async fn wait_drain(&self) -> ConnectResult<ServeDrainResult> {
        drain::wait(&self.owner).await
    }
}
impl Drop for TunnelServeHandle {
    fn drop(&mut self) {
        self.owner.close();
    }
}

pub(crate) async fn serve_registered_pool(
    original: super::super::registered_pool::RegisteredPoolTunnelServerMaterial,
    admission: Arc<SQLiteAdmissionAuthority>,
    options: TunnelServeOptions,
) -> ConnectResult<TunnelServeHandle> {
    let service = original.relay_service.clone();
    let audience = original.relay_audience.clone();
    let material = &original.material;
    serve_original(
        material.admission.account.environment_root().clone(),
        material.namespaces.clone(),
        material.keys.clone(),
        OriginalTunnelBatch::RegisteredPool(original),
        service,
        audience,
        admission,
        options,
        None,
    )
    .await
}
pub(crate) async fn serve_reverse_registered_pool(
    original: super::super::registered_pool::RegisteredPoolTunnelServerMaterial,
    admission: Arc<SQLiteAdmissionAuthority>,
    options: ReverseTunnelServeOptions,
) -> ConnectResult<TunnelServeHandle> {
    let service = original.relay_service.clone();
    let audience = original.relay_audience.clone();
    let material = &original.material;
    serve_reverse_original_with_socket(
        material.admission.account.environment_root().clone(),
        material.namespaces.clone(),
        material.keys.clone(),
        OriginalTunnelBatch::RegisteredPool(original),
        service,
        audience,
        admission,
        options,
        None,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "Tunnel serving keeps original credential, admission, relay audience and physical listener inputs explicit."
)]
pub(crate) async fn serve_pool(
    root: Arc<EnvironmentRoot>,
    namespaces: Vec<Arc<Namespace>>,
    keys: IdentityKeys,
    credentials: Vec<TunnelPoolCredentialBytes>,
    relay_service: String,
    relay_audience: String,
    admission: Arc<SQLiteAdmissionAuthority>,
    options: TunnelServeOptions,
) -> ConnectResult<TunnelServeHandle> {
    serve_original(
        root,
        namespaces,
        keys,
        OriginalTunnelBatch::Pool(credentials),
        relay_service,
        relay_audience,
        admission,
        options,
        None,
    )
    .await
}
#[expect(
    clippy::too_many_arguments,
    reason = "Tunnel serving keeps original credential, admission, relay audience and physical listener inputs explicit."
)]
pub(crate) async fn serve_live_tunnel(
    root: Arc<EnvironmentRoot>,
    namespaces: Vec<Arc<Namespace>>,
    keys: IdentityKeys,
    material: super::live_source::OriginalLiveTunnelServerMaterial,
    relay_service: String,
    relay_audience: String,
    admission: Arc<SQLiteAdmissionAuthority>,
    options: TunnelServeOptions,
) -> ConnectResult<TunnelServeHandle> {
    serve_original(
        root,
        namespaces,
        keys,
        OriginalTunnelBatch::Live(material),
        relay_service,
        relay_audience,
        admission,
        options,
        None,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "Tunnel serving keeps original credential, admission, relay audience and physical listener inputs explicit."
)]
pub(crate) async fn serve_reverse_live_tunnel(
    root: Arc<EnvironmentRoot>,
    namespaces: Vec<Arc<Namespace>>,
    keys: IdentityKeys,
    material: super::live_source::OriginalLiveTunnelServerMaterial,
    relay_service: String,
    relay_audience: String,
    admission: Arc<SQLiteAdmissionAuthority>,
    options: ReverseTunnelServeOptions,
) -> ConnectResult<TunnelServeHandle> {
    let (original, provider) = material.original_reverse_installation(&options.provider)?;
    let options = TunnelServeOptions {
        callbacks: options.callbacks,
        application_limits: options.application_limits,
        cancellation: options.cancellation,
        provider,
    };
    serve_original(
        root,
        namespaces,
        keys,
        OriginalTunnelBatch::Live(material),
        relay_service,
        relay_audience,
        admission,
        options,
        Some(original),
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "Tunnel serving keeps original credential, admission, relay audience and physical listener inputs explicit."
)]
pub(crate) async fn serve_reverse_pool(
    root: Arc<EnvironmentRoot>,
    namespaces: Vec<Arc<Namespace>>,
    keys: IdentityKeys,
    credentials: Vec<TunnelPoolCredentialBytes>,
    relay_service: String,
    relay_audience: String,
    admission: Arc<SQLiteAdmissionAuthority>,
    options: ReverseTunnelServeOptions,
) -> ConnectResult<TunnelServeHandle> {
    serve_reverse_pool_with_socket(
        root,
        namespaces,
        keys,
        credentials,
        relay_service,
        relay_audience,
        admission,
        options,
        None,
    )
    .await
}
#[expect(
    clippy::too_many_arguments,
    reason = "Tunnel serving keeps original credential, admission, relay audience and physical listener inputs explicit."
)]
pub(crate) async fn serve_reverse_pool_on_listener(
    root: Arc<EnvironmentRoot>,
    namespaces: Vec<Arc<Namespace>>,
    keys: IdentityKeys,
    credentials: Vec<TunnelPoolCredentialBytes>,
    relay_service: String,
    relay_audience: String,
    admission: Arc<SQLiteAdmissionAuthority>,
    options: ReverseTunnelServeOptions,
    listener: std::net::TcpListener,
) -> ConnectResult<TunnelServeHandle> {
    serve_reverse_pool_with_socket(
        root,
        namespaces,
        keys,
        credentials,
        relay_service,
        relay_audience,
        admission,
        options,
        Some(super::super::reverse::PreboundSocket::Tcp(listener)),
    )
    .await
}
#[expect(
    clippy::too_many_arguments,
    reason = "Tunnel serving keeps original credential, admission, relay audience and physical listener inputs explicit."
)]
pub(crate) async fn serve_reverse_pool_on_udp_socket(
    root: Arc<EnvironmentRoot>,
    namespaces: Vec<Arc<Namespace>>,
    keys: IdentityKeys,
    credentials: Vec<TunnelPoolCredentialBytes>,
    relay_service: String,
    relay_audience: String,
    admission: Arc<SQLiteAdmissionAuthority>,
    options: ReverseTunnelServeOptions,
    socket: std::net::UdpSocket,
) -> ConnectResult<TunnelServeHandle> {
    serve_reverse_pool_with_socket(
        root,
        namespaces,
        keys,
        credentials,
        relay_service,
        relay_audience,
        admission,
        options,
        Some(super::super::reverse::PreboundSocket::Udp(socket)),
    )
    .await
}
#[expect(
    clippy::too_many_arguments,
    reason = "Tunnel serving keeps original credential, admission, relay audience and physical listener inputs explicit."
)]
async fn serve_reverse_pool_with_socket(
    root: Arc<EnvironmentRoot>,
    namespaces: Vec<Arc<Namespace>>,
    keys: IdentityKeys,
    credentials: Vec<TunnelPoolCredentialBytes>,
    relay_service: String,
    relay_audience: String,
    admission: Arc<SQLiteAdmissionAuthority>,
    options: ReverseTunnelServeOptions,
    listener: Option<super::super::reverse::PreboundSocket>,
) -> ConnectResult<TunnelServeHandle> {
    serve_reverse_original_with_socket(
        root,
        namespaces,
        keys,
        OriginalTunnelBatch::Pool(credentials),
        relay_service,
        relay_audience,
        admission,
        options,
        listener,
    )
    .await
}
#[expect(
    clippy::too_many_arguments,
    reason = "Tunnel serving keeps original credential, admission, relay audience and physical listener inputs explicit."
)]
async fn serve_reverse_original_with_socket(
    root: Arc<EnvironmentRoot>,
    namespaces: Vec<Arc<Namespace>>,
    keys: IdentityKeys,
    originals: OriginalTunnelBatch,
    relay_service: String,
    relay_audience: String,
    admission: Arc<SQLiteAdmissionAuthority>,
    options: ReverseTunnelServeOptions,
    listener: Option<super::super::reverse::PreboundSocket>,
) -> ConnectResult<TunnelServeHandle> {
    // All original reverse legs share one physical listener. Each queued
    // material retains its own account and signed Grant; EndpointHop reads
    // the relay HELLO and verifies possession on the assigned connection.
    let (maximum_pairs, _) = originals.shape()?;
    let (capture, provider) =
        super::super::reverse::Capture::new_with_socket(root.clone(), options.provider, listener)?;
    let reverse = super::super::reverse::SharedRelayListener::new(
        capture,
        provider.clone(),
        maximum_pairs,
        true,
    )?;
    let options = TunnelServeOptions {
        callbacks: options.callbacks,
        application_limits: options.application_limits,
        cancellation: options.cancellation,
        provider,
    };
    serve_original(
        root,
        namespaces,
        keys,
        originals,
        relay_service,
        relay_audience,
        admission,
        options,
        Some(reverse),
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "Tunnel serving keeps original credential, admission, relay audience and physical listener inputs explicit."
)]
async fn serve_original(
    root: Arc<EnvironmentRoot>,
    namespaces: Vec<Arc<Namespace>>,
    keys: IdentityKeys,
    originals: OriginalTunnelBatch,
    relay_service: String,
    relay_audience: String,
    admission: Arc<SQLiteAdmissionAuthority>,
    options: TunnelServeOptions,
    reverse: Option<Arc<super::super::reverse::SharedRelayListener>>,
) -> ConnectResult<TunnelServeHandle> {
    options.application_limits.charge()?;
    let (count, profile) = originals.shape()?;
    if !keys.belongs_to(&root)
        || !admission.belongs_to(&root)
        || options.provider.binding_mode != BindingMode::AuthenticatedContext
        || options.cancellation.is_cancelled()
        || !tokio::runtime::Handle::try_current().is_ok_and(|handle| {
            handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
        })
    {
        return Err(ConnectError::Configuration);
    }
    let charge = root.reserve_environment(serve_charge(count))?;
    // Fully capture each original signed server leg before any carrier opens.
    // A failed capture cannot partially publish a host or replace a previous
    // server leg with another credential after a network failure.
    let mut captured = Vec::new();
    captured
        .try_reserve_exact(count)
        .map_err(|_| ConnectError::Capacity)?;
    let capture_application = |material: PoolConnectionMaterial| -> ConnectResult<(PoolConnectionMaterial, EnvironmentCharge)> {
        if let Some(reverse) = &reverse { reverse.validate(&material, &options.provider)?; }
        else { material.validate_provider(&options.provider)?; }
        let application_charge = root.reserve_environment(ResourceLimits {
            sdk_bytes: 32768 + options.application_limits.control_callback_bytes * 2,
            items: 8, tasks: 2, work_slots: 2, timers: 1, ..ResourceLimits::default()
        })?;
        Ok((material, application_charge))
    };
    match originals {
        OriginalTunnelBatch::Pool(credentials) => {
            for bytes in credentials {
                let material = PoolConnectionMaterial::new_tunnel(
                    root.clone(),
                    namespaces.clone(),
                    keys.clone(),
                    bytes,
                    &relay_service,
                    &relay_audience,
                    Role::Server,
                )?;
                let (material, charge) = capture_application(material)?;
                captured.push((material, charge, None));
            }
        }
        OriginalTunnelBatch::RegisteredPool(original) => {
            let (material, charge) = capture_application(original.material)?;
            captured.push((material, charge, None));
        }
        OriginalTunnelBatch::Live(original) => {
            let (material, prepared) = original.capture(
                &root,
                &namespaces,
                &keys,
                &relay_service,
                &relay_audience,
                &options.provider,
                reverse.as_ref(),
            )?;
            let (material, charge) = capture_application(material)?;
            captured.push((material, charge, prepared));
        }
    }
    let registered_pool = captured
        .first()
        .and_then(|entry| entry.0.registered_pool.clone());
    let diagnostic = root.diagnostic_activity(crate::DiagnosticPhase::Serve, 1);
    diagnostic.succeed();
    let owner = Arc::new(ServeOwner {
        root,
        diagnostic,
        diagnostic_closed: AtomicBool::new(false),
        gate: Mutex::new(Gate {
            closed: false,
            drain: None,
            preparation: Some(PreparationProgress {
                target: count,
                completed: 0,
                failure: None,
            }),
            slots: (0..count).map(|_| None).collect(),
            generation: 0,
        }),
        changed: Notify::new(),
        stop: CancellationToken::new(),
        pump_done: AtomicBool::new(false),
        charge: Mutex::new(Some(charge)),
        cleanup_deadline: Mutex::new(None),
        observers: AtomicUsize::new(0),
    });
    let pool_allow = if profile == AcceptedAuthorizationProfile::PreauthorizedPool {
        Some(pool_allow::PoolAllow::new(
            &owner,
            &captured,
            options.cancellation.clone(),
        )?)
    } else {
        None
    };
    if pool_allow.is_some()
        && let Some(listener) = &reverse
    {
        let policy = wss::Policy::new_reverse_endpoint(&captured[0].0, &options.provider)?;
        // Install only the physical socket. No Grant route is queued and
        // no application/provider preparation callback is dispatched yet.
        listener.start_installed(policy.carrier, policy.host)?;
    }
    let (published, incoming) = mpsc::channel(count);
    let runtime = RuntimeOptions {
        callbacks: options.callbacks,
        application_limits: options.application_limits,
        cancellation: options.cancellation.clone(),
        binding_mode: BindingMode::AuthenticatedContext,
        max_frame_bytes: 1 << 20,
        handshake_timeout: options.provider.timeout,
        queue_messages: options.provider.queue_messages,
        prepare_bytes: options.provider.prepare_bytes,
        native_runtime_bytes: options.provider.native_runtime_bytes,
        origin: options.provider.origin.clone(),
    };
    let config = Arc::new(Configuration {
        carrier: 0,
        keys,
        namespaces,
        source: None,
        profile,
        admission,
        options: runtime,
        socket: None,
        certificate: Vec::new(),
    });
    let provider = options.provider;
    let pump_owner = owner.clone();
    let pump_reverse = reverse.clone();
    let pump_allow = pool_allow.clone();
    let pump_registered = registered_pool.clone();
    tokio::spawn(async move {
        let _pump = PumpTail(pump_owner.clone());
        for (index, (material, application_charge, prepared)) in captured.into_iter().enumerate() {
            if pump_owner.stop.is_cancelled()
                || config.options.cancellation.is_cancelled()
                || pump_owner.root.is_closed()
            {
                pump_owner.close();
                break;
            }
            let cancel = CancellationToken::new();
            let invocation = Invocation::new(cancel.clone(), application_charge);
            let generation = {
                let mut gate = pump_owner
                    .gate
                    .lock()
                    .expect("tunnel Serve publication gate");
                if gate.closed {
                    break;
                }
                let Some(generation) = gate.generation.checked_add(1) else {
                    drop(gate);
                    pump_owner.close();
                    break;
                };
                gate.generation = generation;
                gate.slots[index] = Some(Slot {
                    generation,
                    cancel: cancel.clone(),
                    session: None,
                    provider: None,
                    prepared: false,
                    pending: true,
                    drain: None,
                    drain_done: false,
                    drain_starting: false,
                    tail_done: false,
                    invocation: Some(invocation.clone()),
                    diagnostic: Some(
                        pump_owner
                            .root
                            .diagnostic_activity(crate::DiagnosticPhase::Accept, 1),
                    ),
                });
                generation
            };
            let owner = pump_owner.clone();
            let config = config.clone();
            let options = provider.clone();
            let published = published.clone();
            let tail = PendingTail {
                owner: owner.clone(),
                index,
                generation,
            };
            let reverse = pump_reverse.clone();
            let allow = pump_allow.clone();
            tokio::spawn(async move {
                let _tail = tail;
                host_leg(
                    &owner,
                    &config,
                    index,
                    generation,
                    material,
                    options,
                    cancel,
                    invocation,
                    published,
                    reverse,
                    prepared,
                    allow.clone(),
                )
                .await;
                if let Some(allow) = allow {
                    allow.retire(index);
                }
            });
        }
        drop(published);
        // Exhausting the finite issued batch does not close healthy Sessions.
        // This single prepaid pump still owns Drain, cancellation and cleanup.
        loop {
            if pump_owner.root.is_closed() || config.options.cancellation.is_cancelled() {
                pump_owner.close();
            }
            pump_owner.poll_drain();
            pump_owner.collect_finished();
            let done = {
                let gate = pump_owner.gate.lock().expect("tunnel Serve cleanup");
                if gate.closed
                    && let Some(reverse) = &pump_reverse
                {
                    reverse.close();
                }
                gate.closed
                    && gate.slots.iter().all(Option::is_none)
                    && pump_allow
                        .as_ref()
                        .is_none_or(|allow| allow.physical_pending() == 0)
                    && pump_registered
                        .as_ref()
                        .is_none_or(|control| control.physical_pending() == 0)
                    && pump_reverse
                        .as_ref()
                        .is_none_or(|reverse| reverse.cleanup_complete())
            };
            if done {
                break;
            }
            tokio::select! { _ = pump_owner.changed.notified() => {},
            _ = tokio::time::sleep(Duration::from_millis(10)) => {} }
        }
    });
    Ok(TunnelServeHandle {
        owner,
        incoming: tokio::sync::Mutex::new(incoming),
        reverse,
        pool_allow,
        registered_pool,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "Tunnel serving keeps original credential, admission, relay audience and physical listener inputs explicit."
)]
async fn host_leg(
    owner: &Arc<ServeOwner>,
    config: &Arc<Configuration>,
    index: usize,
    generation: u64,
    mut material: PoolConnectionMaterial,
    options: WssConnectOptions,
    cancel: CancellationToken,
    invocation: Arc<Invocation>,
    published: mpsc::Sender<Session>,
    reverse: Option<Arc<super::super::reverse::SharedRelayListener>>,
    mut original_preparation: Option<super::live_source::OriginalLiveServerPreparation>,
    pool_allow: Option<Arc<pool_allow::PoolAllow>>,
) {
    let prepared = async {
        owner.check(index, generation)?;
        let allow_deadline = match &pool_allow {
            Some(allow) => Some(allow.wait(index, &cancel).await?), None => None,
        };
        owner.check(index, generation)?;
        let mut deadline = Instant::now().checked_add(options.timeout).ok_or(ConnectError::Configuration)?;
        if let Some(until) = allow_deadline { deadline = deadline.min(until); }
        // A server tunnel leg owns the same bounded HOP workspace as a
        // client leg. Reserve it before opening a provider or entering the
        // listener handshake; the charge is transferred into the eventual
        // EndpointHop owner and is never reserved a second time.
        let mut hop_charge = if original_preparation.is_none() && material.tunnel_credentials.is_some() {
            Some(material.admission.account.reserve(
                super::super::hop::EndpointHop::preparation_limits(),
            )?)
        } else {
            None
        };
        let policy = if reverse.is_some() { wss::Policy::new_reverse_endpoint(&material, &options)? }
            else { wss::Policy::new(&material, &options)? };
        let completes_preparation = reverse.is_none() && original_preparation.is_none();
        let (provider, mut incoming) = if let Some(original) = original_preparation.as_mut() {
            if reverse.is_some() { return Err(ConnectError::Configuration); }
            original.validate(&options)?;
            let (provider, incoming, original_deadline, prepared_hop_charge) = original.take_for_serve()?;
            deadline = deadline.min(original_deadline);
            hop_charge = prepared_hop_charge;
            (provider, incoming)
        } else if let Some(reverse) = reverse {
            let credentials = material.tunnel_credentials.as_ref().ok_or(ConnectError::Configuration)?;
            let mut accepted = reverse.prepare_endpoint(material.admission.account.clone(), &credentials.grant, policy,
                deadline, cancel.clone()).await?;
            let provider = accepted.provider.clone();
            accepted.guard.0 = None;
            (provider, accepted.incoming)
        } else {
            super::super::direct_carrier::Provider::prepare(material.admission.account.clone(), policy, options,
                deadline, cancel.clone()).await?
        };
        let guard = super::super::direct_carrier::Guard(Some(provider.clone()));
        {
            let mut gate = owner.gate.lock().expect("original tunnel carrier");
            let closed = gate.closed;
            let slot = gate.slots[index].as_mut().ok_or(ConnectError::Canceled)?;
            if closed || slot.generation != generation { return Err(ConnectError::Canceled); }
            slot.provider = Some(provider.clone());
        }
        owner.changed.notify_waiters();
        let result = {
            let authentication = async {
                if completes_preparation { provider.complete_preparation()?; }
                material.admission.account.check()?;
                owner.check(index, generation)?;
                {
                    let mut gate = owner.gate.lock().expect("original completed tunnel Prepare");
                    if gate.closed { return Err(ConnectError::Canceled); }
                    let slot = gate.slots[index].as_ref().filter(|slot| slot.generation == generation && !slot.cancel.is_cancelled())
                        .ok_or(ConnectError::Canceled)?;
                    if slot.prepared { return Err(ConnectError::Configuration); }
                    let progress = gate.preparation.as_mut().ok_or(ConnectError::Configuration)?;
                    progress.completed = progress.completed.checked_add(1).filter(|count| *count <= progress.target)
                        .ok_or(ConnectError::Capacity)?;
                    gate.slots[index].as_mut().ok_or(ConnectError::Canceled)?.prepared = true;
                }
                owner.changed.notify_waiters();
                if let Some(allow) = &pool_allow { allow.check_dispatch(index)?; }
                let credentials = material.tunnel_credentials.as_ref().ok_or(ConnectError::Configuration)?;
                let mut hop = super::super::hop::EndpointHop::prepare(
                    &material.admission.account,
                    &provider,
                    hop_charge.ok_or(ConnectError::Configuration)?,
                )?.bind(
                    &material.admission,
                    &credentials.grant,
                    &material.bytes.server_certificate,
                    &credentials.relay_certificate,
                    &material.keys,
                )?;
                hop.authenticate(&mut material.admission, &provider, &mut incoming, &material.keys, deadline, &cancel).await?;
                owner.check(index, generation)?;
                establish(owner, config, (index, generation), &provider, &mut incoming, deadline, &invocation, Some(material)).await
            };
            tokio::pin!(authentication);
            tokio::select! {
                result = &mut authentication => result,
                _ = cancel.cancelled() => { invocation.revoke(); provider.close(); authentication.await },
                _ = tokio::time::sleep_until(deadline) => { invocation.revoke(); provider.close(); authentication.await },
            }
        };
        if let Err(error) = &result { record_preparation_failure(owner, index, generation, *error); }
        finish_original_child(owner, config, index, generation, cancel.clone(), provider, incoming,
            guard, result, invocation.clone(), published).await;
        Ok::<_, ConnectError>(())
    }.await;
    if let Err(error) = prepared {
        record_preparation_failure(owner, index, generation, error);
        invocation
            .finish(&config.options.callbacks, application::complete())
            .await;
        invocation.retire();
    }
}

fn record_preparation_failure(
    owner: &Arc<ServeOwner>,
    index: usize,
    generation: u64,
    error: ConnectError,
) {
    let mut gate = owner.gate.lock().expect("original failed tunnel Prepare");
    if gate.slots[index]
        .as_ref()
        .is_some_and(|slot| slot.generation == generation && !slot.prepared)
        && let Some(progress) = &mut gate.preparation
    {
        progress.failure.get_or_insert(error);
    }
    drop(gate);
    owner.changed.notify_waiters();
}
