//! Native direct WSS assembly for one original preauthorized pool attempt.
use super::*;
use crate::{
    api_v4::TransportEnvironment,
    application_lifetime_v4::{ApplicationLifetime, ApplicationLimits, CallbackKind},
    environment_v4::{EnvironmentCharge, EnvironmentRoot},
    namespace_v4::verifier::{
        NamespaceVerifier,
        credential::{DirectCredentialInput, reserve_direct_connection},
    },
    pool_v4::{PoolSpendOwner, PoolStoreError, SQLitePoolStore},
};
use std::{net::IpAddr, sync::Mutex};
use tokio_util::sync::CancellationToken;
#[path = "serve_v4.rs"]
pub(crate) mod serve;
#[path = "wss_v4.rs"]
pub(crate) mod wss;
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
    #[error("v4 connection was canceled")]
    Canceled,
    #[error("v4 connection deadline expired")]
    Deadline,
    #[error(transparent)]
    Pool(#[from] PoolStoreError),
    #[error("v4 connection failed after irreversible pool consumption: {0:?}")]
    Spent(PostSpendFailure),
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
    fn after_spend(self) -> Self {
        Self::Spent(match self {
            Self::Configuration => PostSpendFailure::Configuration,
            Self::Capacity => PostSpendFailure::Capacity,
            Self::Authorization => PostSpendFailure::Authorization,
            Self::Tls => PostSpendFailure::Tls,
            Self::Carrier => PostSpendFailure::Carrier,
            Self::Protocol => PostSpendFailure::Protocol,
            Self::Canceled => PostSpendFailure::Canceled,
            Self::Deadline => PostSpendFailure::Deadline,
            Self::Pool(error) => PostSpendFailure::Pool(error),
            Self::Spent(cause) => cause,
        })
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
}
impl Namespace {
    pub(crate) fn new(verifier: NamespaceVerifier) -> Self {
        Self {
            verifier: Mutex::new(verifier),
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
        self.verifier
            .lock()
            .expect("namespace owner")
            .bootstrap(response, state)
    }
    pub fn refresh(
        &self,
        trust: Option<&[u8]>,
        head: &[u8],
        state: &[u8],
    ) -> std::result::Result<(), EnvironmentError> {
        self.verifier
            .lock()
            .expect("namespace owner")
            .refresh(trust, head, state)
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
        f.write_str("V4PoolCredentialBytes { <redacted> }")
    }
}
impl Drop for PoolCredentialBytes {
    fn drop(&mut self) {
        self.artifact.zeroize();
    }
}
pub struct PoolConnectionMaterial {
    admission: CredentialAdmission,
    bytes: PoolCredentialBytes,
    keys: IdentityKeys,
    namespaces: Vec<Arc<Namespace>>,
    _charge: ResourceCharge,
}
impl fmt::Debug for PoolConnectionMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("V4PoolConnectionMaterial { <opaque> }")
    }
}
impl PoolConnectionMaterial {
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
        mut namespaces: Vec<Arc<Namespace>>,
        keys: IdentityKeys,
        bytes: PoolCredentialBytes,
        role: Role,
    ) -> ConnectResult<Self> {
        if !Arc::ptr_eq(&environment, &keys.owner.environment)
            || namespaces.is_empty()
            || namespaces.len() > 3
            || bytes.artifact.len() > 65536
            || bytes.client_certificate.len() > 8192
            || bytes.server_certificate.len() > 8192
            || bytes.activation.len() > 4096
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
        let guards: Vec<_> = namespaces
            .iter()
            .map(|n| n.verifier.lock().expect("namespace owner"))
            .collect();
        let refs: Vec<_> = guards.iter().map(|v| &**v).collect();
        let admission = reserve_direct_connection(
            &environment,
            &refs,
            DirectCredentialInput {
                artifact: &bytes.artifact,
                client_certificate: &bytes.client_certificate,
                server_certificate: &bytes.server_certificate,
                activation: &bytes.activation,
                source: codec::ActivationSource::PreauthorizedPool,
                candidate_index: 0,
            },
        )?;
        drop(guards);
        let charge = admission.account.reserve(ResourceLimits {
            sdk_bytes: 98_304,
            items: 1,
            work_slots: 1,
            tasks: 0,
            sessions: 0,
            ..ResourceLimits::default()
        })?;
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
        if artifact.field("Artifact", "candidates")?.len()? != 1
            || artifact.u("Artifact", "required_features")? != 0
            || contract.u("SessionContract", "application_profile")? != 0
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
            Context::with_activation_source(codec::ActivationSource::PreauthorizedPool),
        )?;
        if activation
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
            _charge: charge,
        })
    }
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
    if !environment.owns_account(&material.admission.account)
        || !tokio::runtime::Handle::try_current()
            .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    {
        return Err(ConnectError::Configuration);
    }
    let account = material.admission.account.clone();
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
    let application = if let Some((_, limits)) = &handler_plan {
        Some(
            ApplicationLifetime::with_cancellation(
                account.clone(),
                *limits,
                CancellationToken::new(),
            )
            .map_err(ConnectError::from)?,
        )
    } else {
        None
    };
    let work = account.reserve(ResourceLimits {
        sdk_bytes: 655_360,
        items: 8,
        timers: 1,
        work_slots: 8,
        tasks: 2,
        sessions: 0,
        ..ResourceLimits::default()
    })?;
    let deadline = Instant::now()
        .checked_add(options.timeout.min(Duration::from_secs(30)))
        .ok_or(ConnectError::Configuration)?;
    let policy = wss::Policy::new(&material, &options)?;
    let binding_mode = options.binding_mode;
    let (provider, mut incoming) =
        wss::Provider::prepare(account.clone(), policy, options, deadline, cancel.clone()).await?;
    let mut guard = ConnectGuard(Some(provider.clone()));
    let exporter = provider.binding(binding_mode, material.admission.artifact_digest)?;
    let owner = PoolSpendOwner::new(provider.identity(), 1, deadline, cancel.clone())?
        .bind_carrier(provider.cancellation());
    let PoolConnectionMaterial {
        admission,
        bytes,
        keys,
        namespaces,
        _charge,
    } = material;
    let record_reservation = HandshakePreflight::new(
        account.clone(),
        RecordShape::from_artifact(decode(
            &bytes.artifact,
            "Artifact",
            65536,
            Context::default(),
        )?)?,
        Role::Client,
    )?;
    let session_charge = account.reserve(ResourceLimits {
        sdk_bytes: 4096,
        items: 1,
        timers: 2,
        work_slots: 1,
        tasks: 1,
        sessions: 0,
        ..ResourceLimits::default()
    })?;
    let received = account.reserve(ResourceLimits {
        sdk_bytes: 1024,
        items: 1,
        work_slots: 1,
        tasks: 1,
        sessions: 0,
        ..ResourceLimits::default()
    })?;
    let admission = store.consume(admission, owner)?;
    let future = async {
        let artifact = decode(&bytes.artifact, "Artifact", 65536, Context::default())?;
        let nonce = artifact.b::<32>("Artifact", "session_nonce")?;
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
                    8 => u(out, 0),
                    9 => u(out, 1 << binding_mode.wire()),
                    10 => b(out, &[]),
                    _ => unreachable!(),
                }
            }
        });
        decode(&hello, "ClientHello", 16384, Context::default())?;
        provider.send(envelope(1, &hello)).await?;
        let sh_wire = incoming.recv().await.ok_or(ConnectError::Carrier)?;
        let server_hello = payload(&sh_wire, 1, 16384)?.to_vec();
        let sh = decode(&server_hello, "ServerHello", 16384, Context::default())?;
        if sh.u("ServerHello", "binding_mode")? != binding_mode.wire()
            || sh.u("ServerHello", "selected_features")? != 0
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
                    2 | 3 | 9 => u(out, 0),
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
                    10 => u(out, 0),
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
        provider.send(envelope(2, &fsb)).await?;
        let fsa_wire = incoming.recv().await.ok_or(ConnectError::Carrier)?;
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
        )?;
        let mut noise = [0; 81];
        let size = handshake.write_noise(&mut noise)?;
        provider.send(envelope(4, &noise[..size])).await?;
        noise.zeroize();
        let response = incoming.recv().await.ok_or(ConnectError::Carrier)?;
        handshake.read_noise(payload(&response, 4, 81)?)?;
        let mut ready = ReadySubmission(None);
        handshake.submit_ready(&mut ready)?;
        provider
            .send(envelope(5, &ready.0.take().ok_or(ConnectError::Protocol)?))
            .await?;
        let response = incoming.recv().await.ok_or(ConnectError::Carrier)?;
        handshake.verify_ready(payload(&response, 5, 103)?)?;
        provider.check()?;
        let records = handshake.into_records()?;
        provider.activate();
        let transport = wss::Transport::new(provider.clone(), keys, namespaces);
        let session = environment
            .adopt_ready_session_reserved(records, Box::new(transport), session_charge)
            .map_err(|_| ConnectError::Protocol)?;
        if let (Some((plan, _)), Some(application)) = (handler_plan, application) {
            session
                .attach_application(application.clone())
                .map_err(|_| ConnectError::Authorization)?;
            let cleanup = application
                .enter(CallbackKind::Cleanup)
                .map_err(|_| ConnectError::Authorization)?;
            plan.bind(&session);
            plan.dispatch(session.clone(), application_binding, application.clone());
            let child = session.clone();
            tokio::spawn(async move {
                let _cleanup = cleanup;
                child.wait_termination().await;
                application.close();
                loop {
                    let notified = application.changed().notified_owned();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if application.cleanup_status().pending_callbacks == 1 {
                        break;
                    }
                    notified.await;
                }
                let _ = application.release(true);
            });
        }
        let receiver = session.receiver();
        let receiver_tail = provider.receiver();
        tokio::spawn(async move {
            let _charge = received;
            let _tail = receiver_tail;
            while let Some(wire) = incoming.recv().await {
                if receiver.receive(&wire).is_err() {
                    receiver.close();
                    return;
                }
            }
            receiver.close();
        });
        Ok(session)
    };
    let result = tokio::select! {_ = cancel.cancelled()=>Err(ConnectError::Canceled), _ = tokio::time::sleep_until(deadline)=>Err(ConnectError::Deadline), result=future=>result};
    drop(work);
    if result.is_ok() {
        guard.0 = None;
    }
    result.map_err(ConnectError::after_spend)
}

#[cfg(test)]
#[path = "connect_v4_tests.rs"]
mod tests;
