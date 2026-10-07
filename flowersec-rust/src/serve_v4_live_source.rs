//! Bounded original live delivery. Registration precedes the authority's TxB;
//! only its retained publication handle can install the confirmed proof. No
//! status lookup or durable reopen API can reconstruct that handle.
use super::*;
#[path = "registered_live_server_v4.rs"]
mod registered;
pub use registered::{
    RegisteredLiveServerControlConfiguration, RegisteredLiveServerPreparation,
    RegisteredLiveTunnelServerPublication,
};

struct Record {
    generation: u64,
    lease: (String, [u8; 16], [u8; 16]),
    artifact_digest: [u8; 32],
    tunnel: bool,
    cutoff: u64,
    bytes: Option<PoolCredentialBytes>,
    publishing: bool,
    published: bool,
    taken: bool,
    retired: bool,
    preparation_pending: bool,
    control_pending: bool,
}
struct State {
    records: Vec<Option<Record>>,
    generation: u64,
    closed: bool,
}
/// The trusted control host retains each registration in its original issued
/// Artifact owner. It publishes only after that same TxB is explicitly known
/// committed, while its original invocation and publication guard remain live.
pub struct OriginalLiveAcceptedSource {
    root: Arc<EnvironmentRoot>,
    namespaces: Vec<Arc<Namespace>>,
    keys: IdentityKeys,
    state: Mutex<State>,
    delivery_active: std::sync::atomic::AtomicBool,
    preparations: std::sync::atomic::AtomicUsize,
    preparation_changed: Notify,
    stop: CancellationToken,
    _charge: EnvironmentCharge,
}
impl fmt::Debug for OriginalLiveAcceptedSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalLiveAcceptedSource { <opaque> }")
    }
}
/// One server-local allow publication position. It is not serializable and
/// cannot be adopted after a process restart, failed publication or lookup.
pub struct OriginalLiveServerPublication {
    source: Arc<OriginalLiveAcceptedSource>,
    index: usize,
    generation: u64,
    completed: bool,
}
/// Retained original continuation for a live tunnel server leg. The server
/// Grant is joined only after the original TxB result; the relay certificate,
/// service and audience are fixed before TxB and cannot be replaced later.
pub struct OriginalLiveTunnelServerPublication {
    inner: OriginalLiveServerPublication,
    relay_certificate: Vec<u8>,
    service: String,
    audience: String,
    listener_announced: bool,
    registration:
        Option<crate::namespace_v4::verifier::credential::OriginalLiveTunnelServerRegistration>,
    storage: Option<ResourceCharge>,
    prepared: Option<OriginalLiveServerPreparation>,
    original_listener: Option<super::tunnel::OriginalListenerReadiness>,
    original_attempt: Option<[u8; 16]>,
}
/// One verified original server-leg publication. This owner retains the same
/// ArtifactAccount, signed proof, Grant and storage charge through queueing and
/// native Prepare. It cannot be cloned, serialized or reconstructed from bytes.
pub struct OriginalLiveTunnelServerMaterial {
    material: PoolConnectionMaterial,
    service: String,
    audience: String,
    delivery_charge: Option<EnvironmentCharge>,
    prepared: Option<OriginalLiveServerPreparation>,
    original_listener: Option<super::tunnel::OriginalListenerReadiness>,
}
/// The actual forward B carrier prepared before TxB. Its original input queue,
/// monotonic deadline and cleanup backing stay with this custody owner until
/// Serve consumes it or its original provider has actually joined.
pub(super) struct OriginalLiveServerPreparation {
    source: Arc<OriginalLiveAcceptedSource>,
    index: usize,
    generation: u64,
    options: WssConnectOptions,
    provider_cancellation: CancellationToken,
    runtime: tokio::runtime::Handle,
    physical_prepare_tails: Arc<std::sync::atomic::AtomicUsize>,
    retirement: Option<ResourceCharge>,
    parts: Option<OriginalLiveServerPreparationParts>,
}
struct OriginalLiveServerPreparationParts {
    provider: super::super::direct_carrier::Provider,
    incoming: Option<mpsc::Receiver<Vec<u8>>>,
    deadline: Instant,
    _account: ResourceAccount,
    _retirement: ResourceCharge,
    hop_charge: Option<ResourceCharge>,
    watch_cancel: CancellationToken,
    watch_done: Arc<std::sync::atomic::AtomicBool>,
}
type OriginalLiveServerTake = (
    super::super::direct_carrier::Provider,
    mpsc::Receiver<Vec<u8>>,
    Instant,
    Option<ResourceCharge>,
);
impl OriginalLiveServerPreparation {
    pub(super) fn validate(&self, options: &WssConnectOptions) -> ConnectResult<()> {
        let parts = self.parts.as_ref().ok_or(ConnectError::Authorization)?;
        if !self.options.same_installation(options) {
            return Err(ConnectError::Configuration);
        }
        let state = self
            .source
            .state
            .lock()
            .expect("original live B prepared publication fence");
        let record = state.records[self.index]
            .as_ref()
            .filter(|record| record.generation == self.generation)
            .ok_or(ConnectError::Authorization)?;
        if state.closed || record.retired {
            return Err(ConnectError::Canceled);
        }
        if self.source.root.sample()?.upper_ms >= record.cutoff {
            return Err(ConnectError::Deadline);
        }
        drop(state);
        if Instant::now() >= parts.deadline {
            return Err(ConnectError::Deadline);
        }
        parts._account.check()?;
        parts.provider.check()
    }
    pub(super) fn take_for_serve(&mut self) -> ConnectResult<OriginalLiveServerTake> {
        let state = self
            .source
            .state
            .lock()
            .expect("original live B carrier transfer fence");
        let record = state.records[self.index]
            .as_ref()
            .filter(|record| record.generation == self.generation)
            .ok_or(ConnectError::Authorization)?;
        if state.closed || record.retired {
            return Err(ConnectError::Canceled);
        }
        if self.source.root.sample()?.upper_ms >= record.cutoff {
            return Err(ConnectError::Deadline);
        }
        let parts = self.parts.as_mut().ok_or(ConnectError::Authorization)?;
        if Instant::now() >= parts.deadline {
            return Err(ConnectError::Deadline);
        }
        parts._account.check()?;
        parts.provider.check()?;
        let incoming = parts.incoming.take().ok_or(ConnectError::Authorization)?;
        parts.watch_cancel.cancel();
        Ok((
            parts.provider.clone(),
            incoming,
            parts.deadline,
            parts.hop_charge.take(),
        ))
    }
}
impl Drop for OriginalLiveServerPreparation {
    fn drop(&mut self) {
        // Withdrawal also covers a prepared result that the caller never
        // observed; its original worker remains counted through actual exit.
        self.provider_cancellation.cancel();
        let Some(mut parts) = self.parts.take() else {
            if self
                .physical_prepare_tails
                .load(std::sync::atomic::Ordering::Acquire)
                == 0
            {
                self.source
                    .complete_preparation_cleanup(self.index, self.generation);
            } else {
                let source = self.source.clone();
                let index = self.index;
                let generation = self.generation;
                let pending = self.physical_prepare_tails.clone();
                let retirement = self.retirement.take();
                self.runtime.spawn(async move {
                    while pending.load(std::sync::atomic::Ordering::Acquire) != 0 {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    source.complete_preparation_cleanup(index, generation);
                    drop(retirement);
                });
            }
            return;
        };
        parts.watch_cancel.cancel();
        parts.provider.close();
        // Releasing a delivery or failed Serve input retires the actual
        // provider. An elapsed cleanup observation is never a refund barrier.
        parts.incoming.take();
        let source = self.source.clone();
        let index = self.index;
        let generation = self.generation;
        let physical_tails = self.physical_prepare_tails.clone();
        if parts.provider.cleanup().complete
            && parts.watch_done.load(std::sync::atomic::Ordering::Acquire)
            && physical_tails.load(std::sync::atomic::Ordering::Acquire) == 0
        {
            source.complete_preparation_cleanup(index, generation);
        } else {
            self.runtime.spawn(async move {
                while !parts.provider.cleanup().complete
                    || !parts.watch_done.load(std::sync::atomic::Ordering::Acquire)
                    || physical_tails.load(std::sync::atomic::Ordering::Acquire) != 0
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                source.complete_preparation_cleanup(index, generation);
                drop(parts);
            });
        }
    }
}
impl fmt::Debug for OriginalLiveTunnelServerMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalLiveTunnelServerMaterial { <opaque> }")
    }
}
impl OriginalLiveTunnelServerMaterial {
    pub(super) fn retain_delivery_charge(&mut self, charge: EnvironmentCharge) {
        self.delivery_charge = Some(charge);
    }
    fn check_original_prepared(&self, cancellation: &CancellationToken) -> ConnectResult<()> {
        let account = &self.material.admission.account;
        if cancellation.is_cancelled() {
            return Err(ConnectError::Canceled);
        }
        account.check()?;
        if self.material.keys.owner.environment.sample()?.upper_ms
            >= self.material.admission.initiation_not_after_ms
        {
            return Err(ConnectError::Deadline);
        }
        match (&self.prepared, &self.original_listener) {
            (Some(original), None) => original.validate(&original.options)?,
            (None, Some(listener)) => listener.check_ready()?,
            _ => return Err(ConnectError::Configuration),
        }
        Ok(())
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Live material capture validates the original identity, namespace, relay audience and listener together."
    )]
    pub(super) fn capture(
        self,
        root: &Arc<EnvironmentRoot>,
        namespaces: &[Arc<Namespace>],
        keys: &IdentityKeys,
        service: &str,
        audience: &str,
        options: &WssConnectOptions,
        reverse: Option<&Arc<super::super::reverse::SharedRelayListener>>,
    ) -> ConnectResult<(
        PoolConnectionMaterial,
        Option<OriginalLiveServerPreparation>,
    )> {
        self.material.admission.account.check()?;
        if root.sample()?.upper_ms >= self.material.admission.initiation_not_after_ms {
            return Err(ConnectError::Authorization);
        }
        if !self.material.admission.account.belongs_to(root)
            || !keys.belongs_to(root)
            || self.material.admission.source != codec::ActivationSource::LiveAuthority
            || self
                .material
                .admission
                .tunnel
                .as_ref()
                .is_none_or(|hop| hop.endpoint_role != 1)
            || service != self.service
            || audience != self.audience
            || keys.profile() != self.material.keys.profile()
            || keys.ed25519_public_key() != self.material.keys.ed25519_public_key()
            || keys.noise_static_public_key() != self.material.keys.noise_static_public_key()
            || namespaces.len() != self.material.namespaces.len()
            || namespaces.iter().enumerate().any(|(index, namespace)| {
                namespaces[..index]
                    .iter()
                    .any(|old| Arc::ptr_eq(old, namespace))
                    || !self
                        .material
                        .namespaces
                        .iter()
                        .any(|original| Arc::ptr_eq(original, namespace))
            })
        {
            return Err(ConnectError::Configuration);
        }
        match (
            reverse,
            self.original_listener.as_ref(),
            self.prepared.as_ref(),
        ) {
            (None, None, Some(prepared)) => prepared.validate(options)?,
            (Some(listener), Some(original), None) => {
                if !original.matches(listener, options) {
                    return Err(ConnectError::Configuration);
                }
            }
            _ => return Err(ConnectError::Configuration),
        }
        // Account storage was reserved by original publication verification.
        // Drop only the temporary delivery backing after transferring that
        // original verified owner; never reverify into a second Account here.
        Ok((self.material, self.prepared))
    }
    pub(super) fn original_reverse_installation(
        &self,
        options: &super::super::reverse::ReverseTunnelProviderOptions,
    ) -> ConnectResult<(
        Arc<super::super::reverse::SharedRelayListener>,
        WssConnectOptions,
    )> {
        self.original_listener
            .as_ref()
            .ok_or(ConnectError::Configuration)?
            .reverse_installation(options)
    }
}
impl fmt::Debug for OriginalLiveTunnelServerPublication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalLiveTunnelServerPublication { <opaque> }")
    }
}
impl fmt::Debug for OriginalLiveServerPublication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalLiveServerPublication { <opaque> }")
    }
}
impl OriginalLiveAcceptedSource {
    pub(crate) fn new(
        root: Arc<EnvironmentRoot>,
        mut namespaces: Vec<Arc<Namespace>>,
        keys: IdentityKeys,
        maximum: usize,
    ) -> ConnectResult<Arc<Self>> {
        if !(1..=128).contains(&maximum)
            || namespaces.is_empty()
            || namespaces.len() > 8
            || namespaces.capacity() > 8
            || !Arc::ptr_eq(&root, &keys.owner.environment)
            || namespaces.iter().enumerate().any(|(index, namespace)| {
                namespaces[..index]
                    .iter()
                    .any(|old| Arc::ptr_eq(old, namespace))
            })
        {
            return Err(ConnectError::Configuration);
        }
        namespaces.sort_unstable_by_key(Arc::as_ptr);
        let charge = root.reserve_environment(ResourceLimits {
            sdk_bytes: maximum as u64 * (3 * 90_112 + 4096) + 32_768,
            items: maximum as u64 * 4 + 1,
            work_slots: maximum as u64,
            ..ResourceLimits::default()
        })?;
        Ok(Arc::new(Self {
            root,
            namespaces,
            keys,
            state: Mutex::new(State {
                records: (0..maximum).map(|_| None).collect(),
                generation: 0,
                closed: false,
            }),
            delivery_active: std::sync::atomic::AtomicBool::new(false),
            preparations: std::sync::atomic::AtomicUsize::new(0),
            preparation_changed: Notify::new(),
            stop: CancellationToken::new(),
            _charge: charge,
        }))
    }
    /// Called by trusted original issuance before TxB. The private authority
    /// owner keeps the returned handle; consumers never receive it.
    pub fn register_original(
        self: &Arc<Self>,
        bytes: PoolCredentialBytes,
    ) -> ConnectResult<OriginalLiveServerPublication> {
        if !bytes.activation.is_empty()
            || bytes.artifact.len() > 65536
            || bytes.artifact.capacity() > 65536
            || bytes.client_certificate.len() > 8192
            || bytes.client_certificate.capacity() > 8192
            || bytes.server_certificate.len() > 8192
            || bytes.server_certificate.capacity() > 8192
        {
            return Err(ConnectError::Configuration);
        }
        let artifact = decode(&bytes.artifact, "Artifact", 65536, Context::default())?;
        let client = decode(
            &bytes.client_certificate,
            "IdentityCertificate",
            8192,
            Context::default(),
        )?;
        let server = decode(
            &bytes.server_certificate,
            "IdentityCertificate",
            8192,
            Context::default(),
        )?;
        if artifact.field("Artifact", "candidates")?.len()? != 1
            || artifact.b::<32>("Artifact", "client_identity_digest")?
                != codec::digest("certificate_digest", client)?
            || artifact.b::<32>("Artifact", "server_identity_digest")?
                != codec::digest("certificate_digest", server)?
            || server.b::<32>("IdentityCertificate", "ed25519_public_key")?
                != self.keys.ed25519_public_key()
            || server
                .field("IdentityCertificate", "noise_static_public_key")?
                .field("NoiseStaticPublicKey", "public_key_bytes")?
                .bytes()?
                != self.keys.noise_static_public_key()
            || artifact.field("Artifact", "crypto_profile_id")?.text()? != self.keys.profile()
        {
            return Err(ConnectError::Configuration);
        }
        let candidate = artifact.field("Artifact", "candidates")?.at(0)?;
        let tunnel = match candidate.u("Candidate", "path_kind")? {
            0 => false,
            1 => true,
            _ => return Err(ConnectError::Configuration),
        };
        let lease = (
            artifact.field("Artifact", "tenant_id")?.text()?.to_owned(),
            artifact.b("Artifact", "issuer_key_id")?,
            artifact.b("Artifact", "lease_id")?,
        );
        let digest = codec::digest("artifact_digest", artifact)?;
        let cutoff = artifact.u("Artifact", "initiation_not_after_ms")?;
        let now = self.root.sample()?;
        if now.lower_ms < artifact.u("Artifact", "issued_at_ms")? || now.upper_ms >= cutoff {
            return Err(ConnectError::Authorization);
        }
        let mut state = self
            .state
            .lock()
            .expect("original live server registration");
        if state.closed || self.root.is_closed() {
            return Err(ConnectError::Canceled);
        }
        for slot in &mut state.records {
            if slot.as_ref().is_some_and(|record| {
                !record.publishing
                    && !record.preparation_pending
                    && !record.control_pending
                    && now.lower_ms >= record.cutoff
            }) {
                *slot = None;
            }
        }
        if state
            .records
            .iter()
            .flatten()
            .any(|record| record.lease == lease || record.artifact_digest == digest)
        {
            return Err(ConnectError::Authorization);
        }
        let index = state
            .records
            .iter()
            .position(Option::is_none)
            .ok_or(ConnectError::Capacity)?;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(ConnectError::Capacity)?;
        let generation = state.generation;
        state.records[index] = Some(Record {
            generation,
            lease,
            artifact_digest: digest,
            tunnel,
            cutoff,
            bytes: Some(bytes),
            publishing: false,
            published: false,
            taken: false,
            retired: false,
            preparation_pending: false,
            control_pending: false,
        });
        Ok(OriginalLiveServerPublication {
            source: self.clone(),
            index,
            generation,
            completed: false,
        })
    }
    /// Register the server recipient before the original live TxB. The
    /// endpoint Grant is deliberately supplied to `publish_tunnel` only after
    /// that same TxB has returned its complete signed result.
    pub fn register_tunnel_original(
        self: &Arc<Self>,
        bytes: PoolCredentialBytes,
        relay_certificate: Vec<u8>,
        service: String,
        audience: String,
    ) -> ConnectResult<OriginalLiveTunnelServerPublication> {
        self.register_tunnel_original_with_signer(bytes, relay_certificate, service, audience, None)
    }
    pub(super) fn register_tunnel_original_with_signer(
        self: &Arc<Self>,
        bytes: PoolCredentialBytes,
        relay_certificate: Vec<u8>,
        service: String,
        audience: String,
        signing_key: Option<&str>,
    ) -> ConnectResult<OriginalLiveTunnelServerPublication> {
        if relay_certificate.is_empty()
            || relay_certificate.len() > 8192
            || relay_certificate.capacity() > 8192
            || service.is_empty()
            || service.len() > 128
            || service.capacity() > 256
            || audience.is_empty()
            || audience.len() > 128
            || audience.capacity() > 256
        {
            return Err(ConnectError::Configuration);
        }
        let artifact = decode(&bytes.artifact, "Artifact", 65536, Context::default())?;
        let candidate = artifact.field("Artifact", "candidates")?.at(0)?;
        if candidate.u("Candidate", "path_kind")? != 1 {
            return Err(ConnectError::Configuration);
        }
        let guards: Vec<_> = self
            .namespaces
            .iter()
            .map(|namespace| {
                namespace
                    .verifier
                    .lock()
                    .expect("original live B registration namespace")
            })
            .collect();
        let references: Vec<_> = guards.iter().map(|guard| &**guard).collect();
        let registration = crate::namespace_v4::verifier::credential::reserve_original_live_tunnel_server_registration(
            &self.root, &references, DirectCredentialInput {
                artifact: &bytes.artifact, client_certificate: &bytes.client_certificate,
                server_certificate: &bytes.server_certificate, activation: &[],
                source: codec::ActivationSource::LiveAuthority, candidate_index: 0,
            }, signing_key)?;
        drop(guards);
        let storage = registration
            .registration()
            .account()
            .reserve(ResourceLimits {
                sdk_bytes: 98_304 + 18_432,
                items: 1,
                work_slots: 1,
                ..ResourceLimits::default()
            })?;
        let inner = self.register_original(bytes)?;
        Ok(OriginalLiveTunnelServerPublication {
            inner,
            relay_certificate,
            service,
            audience,
            listener_announced: false,
            registration: Some(registration),
            storage: Some(storage),
            prepared: None,
            original_listener: None,
            original_attempt: None,
        })
    }

    fn retain_registered_control(
        self: &Arc<Self>,
        index: usize,
        generation: u64,
        charge: ResourceCharge,
    ) -> ConnectResult<Arc<crate::control_https_v4::ControlHTTPSCustody>> {
        let mut state = self.state.lock().expect("original live B control custody");
        if state.closed || self.root.is_closed() {
            return Err(ConnectError::Canceled);
        }
        let record = state.records[index]
            .as_mut()
            .filter(|record| record.generation == generation)
            .ok_or(ConnectError::Authorization)?;
        if record.retired
            || record.publishing
            || record.published
            || record.taken
            || record.control_pending
        {
            return Err(ConnectError::Authorization);
        }
        record.control_pending = true;
        self.preparations
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let source = self.clone();
        Ok(crate::control_https_v4::ControlHTTPSCustody::with_cleanup(
            charge,
            move || {
                let mut state = source
                    .state
                    .lock()
                    .expect("original live B control physically released");
                if let Some(record) = state.records[index]
                    .as_mut()
                    .filter(|record| record.generation == generation)
                {
                    record.control_pending = false;
                }
                source
                    .preparations
                    .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                source.preparation_changed.notify_waiters();
            },
        ))
    }
    pub(super) fn pending_preparations(&self) -> usize {
        self.preparations.load(std::sync::atomic::Ordering::Acquire)
    }
    pub(super) fn preparation_cleanup_notify(&self) -> &Notify {
        &self.preparation_changed
    }
    fn complete_preparation_cleanup(&self, index: usize, generation: u64) {
        let mut state = self.state.lock().expect("original live B provider joined");
        if let Some(record) = state.records[index]
            .as_mut()
            .filter(|record| record.generation == generation)
        {
            record.preparation_pending = false;
        }
        self.preparations
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        self.preparation_changed.notify_waiters();
    }
    pub fn close(&self) {
        let mut state = self
            .state
            .lock()
            .expect("original live server source close");
        state.closed = true;
        self.stop.cancel();
        for record in state.records.iter_mut().flatten() {
            record.retired = true;
            record.bytes = None;
        }
    }
    fn retire(&self, index: usize, generation: u64) {
        let mut state = self
            .state
            .lock()
            .expect("original live server publication retirement");
        if let Some(record) = state.records[index]
            .as_mut()
            .filter(|record| record.generation == generation)
        {
            record.retired = true;
            record.publishing = false;
            record.bytes = None;
        }
    }
}
impl OriginalLiveServerPublication {
    fn check_pending_original(&self) -> ConnectResult<()> {
        let source = &self.source;
        let state = source
            .state
            .lock()
            .expect("original live registration check");
        if state.closed || source.root.is_closed() {
            return Err(ConnectError::Canceled);
        }
        let record = state.records[self.index]
            .as_ref()
            .filter(|record| record.generation == self.generation)
            .ok_or(ConnectError::Authorization)?;
        if record.retired
            || record.publishing
            || record.published
            || record.taken
            || source.root.sample()?.upper_ms >= record.cutoff
        {
            return Err(ConnectError::Authorization);
        }
        Ok(())
    }
    /// The control host calls this from the retained, confirmed TxB continuation,
    /// after checking its authenticated authority invocation and deadline. The
    /// SDK verifies the original proof independently before opening lookup.
    pub fn publish_original(
        mut self,
        activation: Vec<u8>,
        cancellation: &CancellationToken,
    ) -> ConnectResult<()> {
        let mut activation = Zeroizing::new(activation);
        if cancellation.is_cancelled() {
            return Err(ConnectError::Canceled);
        }
        if activation.is_empty() || activation.len() > 4096 || activation.capacity() > 4096 {
            return Err(ConnectError::Configuration);
        }
        let source = &self.source;
        let bytes = {
            let mut state = source
                .state
                .lock()
                .expect("original live server publication");
            if state.closed || source.root.is_closed() {
                return Err(ConnectError::Canceled);
            }
            let record = state.records[self.index]
                .as_mut()
                .filter(|record| record.generation == self.generation)
                .ok_or(ConnectError::Authorization)?;
            if record.retired
                || record.publishing
                || record.published
                || record.taken
                || source.root.sample()?.upper_ms >= record.cutoff
            {
                return Err(ConnectError::Authorization);
            }
            record.publishing = true;
            let mut bytes = record.bytes.take().ok_or(ConnectError::Authorization)?;
            bytes.activation = std::mem::take(&mut *activation);
            bytes
        };
        // Every signature, namespace, time and local key gate uses the same
        // current verifier as the native accepted establishment below.
        let material = PoolConnectionMaterial::for_role_source(
            source.root.clone(),
            source.namespaces.clone(),
            source.keys.clone(),
            bytes,
            Role::Server,
            codec::ActivationSource::LiveAuthority,
        )?;
        let mut state = source
            .state
            .lock()
            .expect("original live server publication completion");
        if state.closed || source.root.is_closed() || cancellation.is_cancelled() {
            return Err(ConnectError::Canceled);
        }
        let record = state.records[self.index]
            .as_mut()
            .filter(|record| record.generation == self.generation)
            .ok_or(ConnectError::Authorization)?;
        if record.retired
            || !record.publishing
            || source.root.sample()?.upper_ms >= material.admission.initiation_not_after_ms
        {
            return Err(ConnectError::Authorization);
        }
        record.cutoff = material.admission.initiation_not_after_ms;
        record.bytes = Some(material.bytes);
        record.publishing = false;
        record.published = true;
        self.completed = true;
        Ok(())
    }
}
impl OriginalLiveTunnelServerPublication {
    /// Prepare the independently installed forward B leg before TxB. This
    /// consumes no activation permission and sends no HOP_AUTH. The signed
    /// server delivery later transfers this exact carrier into Serve.
    pub async fn prepare_original_carrier(
        mut self,
        options: WssConnectOptions,
        cancellation: &CancellationToken,
    ) -> ConnectResult<Self> {
        self.inner.check_pending_original()?;
        if self.prepared.is_some()
            || self.listener_announced
            || cancellation.is_cancelled()
            || !tokio::runtime::Handle::try_current().is_ok_and(|runtime| {
                runtime.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
            })
        {
            return Err(if cancellation.is_cancelled() {
                ConnectError::Canceled
            } else {
                ConnectError::Configuration
            });
        }
        let source = self.inner.source.clone();
        let registration = self
            .registration
            .as_ref()
            .ok_or(ConnectError::Authorization)?
            .registration();
        let (policy, cutoff) = {
            let state = source
                .state
                .lock()
                .expect("original live B forward preparation");
            let record = state.records[self.inner.index]
                .as_ref()
                .filter(|record| record.generation == self.inner.generation)
                .ok_or(ConnectError::Authorization)?;
            let bytes = record.bytes.as_ref().ok_or(ConnectError::Authorization)?;
            (
                wss::Policy::new_live_server_carrier_registration(
                    &bytes.artifact,
                    registration,
                    &options,
                )?,
                record.cutoff,
            )
        };
        let remaining = cutoff
            .checked_sub(source.root.sample()?.upper_ms)
            .filter(|value| *value != 0)
            .ok_or(ConnectError::Deadline)?;
        let deadline = Instant::now()
            .checked_add(options.timeout.min(Duration::from_millis(remaining)))
            .ok_or(ConnectError::Configuration)?;
        let account = registration.account().clone();
        // Fund the server HOP workspace before the original physical carrier
        // is prepared. Publication custody transfers this exact charge into
        // EndpointHop; no later reserve or second budget is created.
        let hop_charge =
            Some(account.reserve(super::super::hop::EndpointHop::preparation_limits())?);
        // The cleanup worker is funded before native allocation or dialing.
        let retirement = account.reserve(ResourceLimits {
            sdk_bytes: 8192,
            items: 1,
            tasks: 3,
            work_slots: 1,
            timers: 3,
            ..ResourceLimits::default()
        })?;
        {
            let mut state = source
                .state
                .lock()
                .expect("original live B forward carrier custody");
            if state.closed || source.root.is_closed() {
                return Err(ConnectError::Canceled);
            }
            let record = state.records[self.inner.index]
                .as_mut()
                .filter(|record| record.generation == self.inner.generation)
                .ok_or(ConnectError::Authorization)?;
            if record.retired
                || record.publishing
                || record.published
                || record.taken
                || record.preparation_pending
            {
                return Err(ConnectError::Authorization);
            }
            record.preparation_pending = true;
            source
                .preparations
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        let provider_cancellation = cancellation.child_token();
        let mut original = OriginalLiveServerPreparation {
            source: source.clone(),
            index: self.inner.index,
            generation: self.inner.generation,
            options: options.clone(),
            provider_cancellation: provider_cancellation.clone(),
            runtime: tokio::runtime::Handle::current(),
            physical_prepare_tails: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            retirement: Some(retirement),
            parts: None,
        };
        let preparing = super::super::direct_carrier::Provider::prepare_tracked(
            account.clone(),
            policy,
            options,
            deadline,
            provider_cancellation.clone(),
            original.physical_prepare_tails.clone(),
        );
        tokio::pin!(preparing);
        let (provider, incoming) = tokio::select! {
            result = &mut preparing => result?,
            _ = source.stop.cancelled() => {
                provider_cancellation.cancel();
                preparing.await?
            }
        };
        let watch_cancel = CancellationToken::new();
        let watch_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        original.parts = Some(OriginalLiveServerPreparationParts {
            provider: provider.clone(),
            incoming: Some(incoming),
            deadline,
            _account: account,
            _retirement: original
                .retirement
                .take()
                .ok_or(ConnectError::Authorization)?,
            hop_charge,
            watch_cancel: watch_cancel.clone(),
            watch_done: watch_done.clone(),
        });
        let watch_source = source.clone();
        let watch_provider = provider.clone();
        let original_cancellation = cancellation.clone();
        original.runtime.spawn(async move {
            tokio::select! {
                biased;
                _ = watch_cancel.cancelled() => {},
                _ = watch_source.stop.cancelled() => watch_provider.close(),
                _ = original_cancellation.cancelled() => watch_provider.close(),
                _ = tokio::time::sleep_until(deadline) => watch_provider.close(),
            }
            watch_done.store(true, std::sync::atomic::Ordering::Release);
            watch_source.preparation_changed.notify_waiters();
        });
        self.prepared = Some(original);
        provider.complete_preparation()?;
        self.inner.check_pending_original()?;
        if cancellation.is_cancelled() {
            return Err(ConnectError::Canceled);
        }
        let original = self.prepared.as_ref().ok_or(ConnectError::Authorization)?;
        original.validate(&original.options)?;
        Ok(self)
    }
    /// Announce only this original B registration and its independently bound
    /// listener before TxB. The returned object is the same non-cloneable
    /// publication continuation; readiness creates no Grant or Session owner.
    /// Failure retires this registration through its original Drop guard.
    pub async fn announce_original_listener_ready(
        self,
        listener: &LiveReverseTunnelListener,
        control: &Arc<crate::LiveTunnelAuthorityControl>,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> ConnectResult<Self> {
        let readiness = listener.original_readiness()?;
        self.announce_original_readiness(&readiness, control, timeout, cancellation)
            .await
    }
    pub(super) async fn announce_original_readiness(
        mut self,
        listener: &super::tunnel::OriginalListenerReadiness,
        control: &Arc<crate::LiveTunnelAuthorityControl>,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> ConnectResult<Self> {
        if self.listener_announced
            || self.prepared.is_some()
            || !control.belongs_to(&self.inner.source.root)
            || timeout.is_zero()
            || timeout > Duration::from_secs(30)
            || cancellation.is_cancelled()
        {
            return Err(if cancellation.is_cancelled() {
                ConnectError::Canceled
            } else {
                ConnectError::Configuration
            });
        }
        let source = self.inner.source.clone();
        let until = Instant::now()
            .checked_add(timeout)
            .ok_or(ConnectError::Configuration)?;
        let retained = self
            .registration
            .as_mut()
            .ok_or(ConnectError::Authorization)?;
        retained.restrict_signer(control.activation_signing_key_id())?;
        let registration = retained.registration();
        {
            let state = source
                .state
                .lock()
                .expect("original live B listener registration");
            if state.closed || source.root.is_closed() {
                return Err(ConnectError::Canceled);
            }
            let record = state.records[self.inner.index]
                .as_ref()
                .filter(|record| record.generation == self.inner.generation)
                .ok_or(ConnectError::Authorization)?;
            if record.retired
                || record.publishing
                || record.published
                || record.taken
                || source.root.sample()?.upper_ms >= record.cutoff
            {
                return Err(ConnectError::Authorization);
            }
            let bytes = record.bytes.as_ref().ok_or(ConnectError::Authorization)?;
            listener.validate(&source.root, &bytes.artifact, registration)?;
        }
        let notification = async {
            listener.wait_ready(timeout, cancellation).await?;
            self.inner.check_pending_original()?;
            registration.account().check()?;
            control
                .relay_ready_projection(
                    registration.artifact_digest(),
                    registration.candidate_id(),
                    registration.route_digest(),
                    1,
                    cancellation,
                )
                .await?;
            self.inner.check_pending_original()?;
            registration.account().check()?;
            Ok::<_, ConnectError>(())
        };
        tokio::select! {
            result = notification => result?,
            _ = cancellation.cancelled() => return Err(ConnectError::Canceled),
            _ = tokio::time::sleep_until(until) => return Err(ConnectError::Deadline),
        }
        self.listener_announced = true;
        self.original_listener = Some(listener.clone());
        Ok(self)
    }
    fn reserve_original_attempt(&mut self, attempt: [u8; 16]) -> ConnectResult<()> {
        self.inner.check_pending_original()?;
        self.registration
            .as_ref()
            .ok_or(ConnectError::Authorization)?
            .registration()
            .account()
            .check()?;
        if attempt == [0; 16] || self.original_attempt.is_some() {
            return Err(ConnectError::Authorization);
        }
        self.original_attempt = Some(attempt);
        Ok(())
    }
    /// Complete the original live TxB with its server Grant and verify the
    /// resulting activation and tunnel endpoint material under the original
    /// source profile. The returned material remains bound to this exact
    /// publication position and is not recoverable by lookup after failure.
    pub fn publish_tunnel(
        self,
        activation: Vec<u8>,
        server_grant: Vec<u8>,
        cancellation: &CancellationToken,
    ) -> ConnectResult<OriginalLiveTunnelServerMaterial> {
        self.publish_with_grant(activation, server_grant, cancellation)
    }

    fn publish_with_grant(
        mut self,
        activation: Vec<u8>,
        server_grant: Vec<u8>,
        cancellation: &CancellationToken,
    ) -> ConnectResult<OriginalLiveTunnelServerMaterial> {
        let mut activation = Zeroizing::new(activation);
        let mut server_grant = Zeroizing::new(server_grant);
        if cancellation.is_cancelled()
            || activation.is_empty()
            || activation.len() > 4096
            || activation.capacity() > 4096
            || server_grant.is_empty()
            || server_grant.len() > 9302
            || server_grant.capacity() > 9302
        {
            return Err(if cancellation.is_cancelled() {
                ConnectError::Canceled
            } else {
                ConnectError::Configuration
            });
        }
        if let Some(original) = self.original_attempt {
            let proof = decode(
                &activation,
                "ActivationAuthorization",
                4096,
                Context::with_activation_source(codec::ActivationSource::LiveAuthority),
            )?;
            if proof.b::<16>("ActivationAuthorization", "attempt_id")? != original {
                return Err(ConnectError::Authorization);
            }
        }
        if self.prepared.is_none() && self.original_listener.is_none() {
            return Err(ConnectError::Configuration);
        }
        if let Some(prepared) = &self.prepared {
            prepared.validate(&prepared.options)?;
        }
        if let Some(listener) = &self.original_listener {
            listener.check_ready()?;
        }
        let source = &self.inner.source;
        let bytes = {
            let mut state = source
                .state
                .lock()
                .expect("original live tunnel publication");
            if state.closed || source.root.is_closed() {
                return Err(ConnectError::Canceled);
            }
            let record = state.records[self.inner.index]
                .as_mut()
                .filter(|record| record.generation == self.inner.generation)
                .ok_or(ConnectError::Authorization)?;
            if record.retired
                || record.publishing
                || record.published
                || record.taken
                || source.root.sample()?.upper_ms >= record.cutoff
            {
                return Err(ConnectError::Authorization);
            }
            record.publishing = true;
            let mut bytes = record.bytes.take().ok_or(ConnectError::Authorization)?;
            bytes.activation = std::mem::take(&mut *activation);
            bytes
        };
        let tunnel = TunnelPoolCredentialBytes {
            connection: bytes,
            grant: std::mem::take(&mut *server_grant),
            relay_certificate: self.relay_certificate,
        };
        let guards: Vec<_> = source
            .namespaces
            .iter()
            .map(|namespace| {
                namespace
                    .verifier
                    .lock()
                    .expect("original live B delivery namespace")
            })
            .collect();
        let references: Vec<_> = guards.iter().map(|guard| &**guard).collect();
        let admission = self
            .registration
            .take()
            .ok_or(ConnectError::Authorization)?
            .consume_server_delivery(
                &source.root,
                &references,
                &tunnel.connection.artifact,
                &tunnel.connection.client_certificate,
                &tunnel.connection.server_certificate,
                &tunnel.connection.activation,
                &tunnel.grant,
                &tunnel.relay_certificate,
                &self.service,
                &self.audience,
            )?;
        drop(guards);
        let material = PoolConnectionMaterial::from_original_live_server_admission(
            source.root.clone(),
            source.namespaces.clone(),
            source.keys.clone(),
            tunnel,
            &self.service,
            &self.audience,
            admission,
            self.storage.take().ok_or(ConnectError::Authorization)?,
        )?;
        let cutoff = material.admission.initiation_not_after_ms;
        let mut state = source
            .state
            .lock()
            .expect("original live tunnel publication completion");
        if state.closed || source.root.is_closed() || cancellation.is_cancelled() {
            return Err(ConnectError::Canceled);
        }
        let record = state.records[self.inner.index]
            .as_mut()
            .filter(|record| record.generation == self.inner.generation)
            .ok_or(ConnectError::Authorization)?;
        if record.retired || !record.publishing || source.root.sample()?.upper_ms >= cutoff {
            return Err(ConnectError::Authorization);
        }
        record.cutoff = cutoff;
        // The original verified material moves to its one-shot Serve owner.
        // The direct resolver excludes tunnel records and retains no second
        // connection copy or reconstruction authority.
        record.bytes = None;
        record.publishing = false;
        record.published = true;
        record.taken = true;
        self.inner.completed = true;
        Ok(OriginalLiveTunnelServerMaterial {
            material,
            service: self.service,
            audience: self.audience,
            delivery_charge: None,
            prepared: self.prepared,
            original_listener: self.original_listener,
        })
    }
}
impl Drop for OriginalLiveServerPublication {
    fn drop(&mut self) {
        if !self.completed {
            self.source.retire(self.index, self.generation);
        }
    }
}
#[async_trait]
impl AcceptedMaterialSource for OriginalLiveAcceptedSource {
    fn authorization_profile(&self) -> AcceptedAuthorizationProfile {
        AcceptedAuthorizationProfile::LiveAuthority
    }
    async fn resolve(
        &self,
        hello: &[u8],
        cancellation: CancellationToken,
    ) -> ConnectResult<PoolCredentialBytes> {
        if cancellation.is_cancelled() {
            return Err(ConnectError::Canceled);
        }
        let hello = decode(hello, "ClientHello", 16384, Context::default())?;
        let digest = hello.b::<32>("ClientHello", "artifact_digest")?;
        let mut state = self
            .state
            .lock()
            .expect("original live server material capture");
        if state.closed || self.root.is_closed() {
            return Err(ConnectError::Canceled);
        }
        let record = state
            .records
            .iter_mut()
            .flatten()
            .find(|record| !record.tunnel && record.artifact_digest == digest)
            .ok_or(ConnectError::Authorization)?;
        if record.retired
            || !record.published
            || record.publishing
            || record.taken
            || self.root.sample()?.upper_ms >= record.cutoff
        {
            return Err(ConnectError::Authorization);
        }
        let bytes = record.bytes.as_ref().ok_or(ConnectError::Authorization)?;
        let proof = decode(
            &bytes.activation,
            "ActivationAuthorization",
            4096,
            Context::with_activation_source(codec::ActivationSource::LiveAuthority),
        )?;
        same(
            hello,
            "ClientHello",
            "attempt_id",
            proof,
            "ActivationAuthorization",
            "attempt_id",
        )?;
        same(
            hello,
            "ClientHello",
            "candidate_id",
            proof,
            "ActivationAuthorization",
            "candidate_selection",
        )?;
        same(
            hello,
            "ClientHello",
            "route_digest",
            proof,
            "ActivationAuthorization",
            "route_selection",
        )?;
        record.taken = true;
        record.bytes.take().ok_or(ConnectError::Authorization)
    }
}

#[path = "live_server_delivery_v4.rs"]
pub(crate) mod remote;
pub use remote::{
    LiveServerDeliveryHandle, LiveServerDeliveryOptions, OriginalLiveServerDelivery,
    RemoteLiveServerPublication, RemoteLiveTunnelServerPublication,
};
