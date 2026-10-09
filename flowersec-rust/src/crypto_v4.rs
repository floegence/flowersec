//! Noise/READY composition over original credential, carrier and durable pool
//! owners. Only completed native assembly publishes the public Session API.
use crate::{
    codec_v4::{self as codec, Context, Limits, Value},
    environment_v4::{EnvironmentError, ResourceAccount, ResourceCharge, ResourceLimits},
    namespace_v4::verifier::credential::CredentialAdmission,
};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc, time::Duration};
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};
#[path = "connect_v4.rs"]
pub(crate) mod connect;
#[path = "crypto_v4_keys.rs"]
mod keys;
#[path = "crypto_v4_records.rs"]
mod records;
pub use connect::{
    BindingMode, ConnectError, IdentityKeys, Namespace, NamespaceBootstrapRequest,
    PoolConnectionMaterial, PoolCredentialBytes, PostAuthorizationFailure, PostSpendFailure,
    TunnelPoolCredentialBytes, TunnelServerAllowConfiguration, WssConnectOptions,
};
pub(crate) use keys::LocalKeys;
pub(crate) use records::ReliableSession;
pub(crate) use records::{
    DatagramLease, NativeStreamBinding, ReceiveDisposition, RecordEngine, ResumeMessageClaim,
    SessionLink, SessionReceiver, SessionTransport, StreamPreparation, StreamPublicationAdmission,
};
pub use records::{
    DrainOperation, DrainOutcome, DrainResult, Metadata, OpenRequest, ProbeOutcome, ProbeResult,
    RawStreamMetadataContract, RawStreamMetadataField, RawStreamMetadataType, Session, Stream,
    UnreliableMessages,
};
#[cfg(test)]
pub(crate) use records::{
    MaintenanceReceiveProbe, TerminalPublicationProbe, install_maintenance_receive_probe,
    install_terminal_publication_probe,
};

/// The original ordered publisher completes the actual publication of these
/// bytes before returning. It cannot retain a key, reseal, or report only queue
/// admission. Exclusive &mut access serializes all old records and markers.
/// A provider's original finite business publication position. It remains
/// claimed while the same publisher waits for a rekey ticket; maintenance can
/// continue through its existing reserved path.
pub(crate) struct DataPublicationClaim {
    release: Option<Box<dyn FnOnce() + Send>>,
}
impl DataPublicationClaim {
    pub(crate) fn new(release: impl FnOnce() + Send + 'static) -> Self {
        Self {
            release: Some(Box::new(release)),
        }
    }
}
impl Drop for DataPublicationClaim {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            release();
        }
    }
}
pub(crate) struct DeferredStreamCommit {
    pub(crate) view: Arc<records::StreamView>,
    pub(crate) scope: u64,
    pub(crate) end: u64,
    pub(crate) fin: bool,
}
pub(crate) struct DeferredPublication {
    pub(crate) handoff: Option<Arc<dyn Fn() + Send + Sync>>,
    pub(crate) stream: Option<DeferredStreamCommit>,
    pub(crate) published_scope: Option<u64>,
    pub(crate) rekey_success: bool,
    pub(crate) probe: Option<records::ProbePublication>,
    /// Number of sealed records at the point this tail was deferred.
    /// Successful native prefixes can therefore commit only the tails whose
    /// records were actually accepted.
    pub(crate) record_index: usize,
}
impl DeferredPublication {
    pub(crate) fn rekey_success() -> Self {
        Self {
            rekey_success: true,
            ..Self::handoff(None)
        }
    }
    pub(crate) fn handoff(handoff: Option<Arc<dyn Fn() + Send + Sync>>) -> Self {
        Self {
            handoff,
            stream: None,
            published_scope: None,
            record_index: 0,
            rekey_success: false,
            probe: None,
        }
    }
    pub(crate) fn stream(view: Arc<records::StreamView>, scope: u64, end: u64, fin: bool) -> Self {
        Self {
            handoff: None,
            stream: Some(DeferredStreamCommit {
                view,
                scope,
                end,
                fin,
            }),
            published_scope: None,
            record_index: 0,
            rekey_success: false,
            probe: None,
        }
    }
    pub(crate) fn published(scope: u64) -> Self {
        Self {
            handoff: None,
            stream: None,
            published_scope: Some(scope),
            record_index: 0,
            rekey_success: false,
            probe: None,
        }
    }
}
pub(crate) trait RecordPublisher {
    /// Bind the fixed management future to its original allocated scope before
    /// any OPEN record can consume a sequence or enter native publication.
    fn prepare_management_stream(&mut self, _scope: u64) -> Result<()> {
        Ok(())
    }
    /// Prepay record staging and every associated completion tail before
    /// mutating a reliable frontier or consuming its AEAD sequence.
    fn prepare_publication(&mut self, _record_bytes: usize, _deferred_tails: usize) -> Result<()> {
        Ok(())
    }
    fn publish(&mut self, record: &[u8]) -> Result<()>;
    fn publish_seal(&mut self, work: records::RecordWork, record: &mut [u8]) -> Result<()> {
        work.seal(record)?;
        self.publish(record)
    }
    fn is_deferred(&self) -> bool {
        false
    }
    fn defer_publication(&mut self, _publication: DeferredPublication) {}
    fn try_claim_data(
        &mut self,
        _scope: u64,
        _maximum_record_bytes: usize,
    ) -> Result<DataPublicationClaim> {
        Err(CryptoError::Capacity)
    }
    fn data_publication_permitted(&self, _scope: u64) -> bool {
        true
    }
    /// A trusted native publisher may report the actual failure of this
    /// original application record's write direction. The bool is only the
    /// native normal-drained hint; it never supplies authenticated drain proof.
    fn failed_stream_publication(&self, _scope: u64) -> Option<bool> {
        None
    }
    /// Sticky generation of known local provider stalls, including those that
    /// began and ended during a synchronous publication callback.
    fn liveness_stall_generation(&self) -> u64 {
        0
    }
    fn liveness_stalled(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CryptoError {
    #[error("v4 cryptographic configuration is invalid")]
    Configuration,
    #[error("v4 cryptographic authentication failed")]
    Authentication,
    #[error("v4 key operation failed")]
    Key,
    #[error("v4 cryptographic owner is closed or out of phase")]
    State,
    #[error("v4 cryptographic capacity is exhausted")]
    Capacity,
    #[error("v4 cryptographic deadline expired")]
    Deadline,
    #[error("liveness_path_unresponsive")]
    LivenessPathUnresponsive,
    #[error("v4 record sequence is invalid")]
    Sequence,
    #[error("v4 authorization failed: {0}")]
    Authorization(#[from] EnvironmentError),
}
type Result<T> = std::result::Result<T, CryptoError>;
impl From<codec::Error> for CryptoError {
    fn from(_: codec::Error) -> Self {
        Self::Authentication
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Profile {
    X25519,
    P256,
}
impl Profile {
    fn parse(name: &str) -> Result<Self> {
        match name {
            "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1" => Ok(Self::X25519),
            "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1" => Ok(Self::P256),
            _ => Err(CryptoError::Configuration),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::X25519 => "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1",
            Self::P256 => "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1",
        }
    }
    fn protocol(self) -> &'static str {
        match self {
            Self::X25519 => "Noise_KKpsk0_25519_ChaChaPoly_SHA256",
            Self::P256 => "Noise_KKpsk0_P256_AESGCM_SHA256",
        }
    }
    fn public_len(self) -> usize {
        match self {
            Self::X25519 => 32,
            Self::P256 => 65,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Role {
    Client,
    Server,
}
impl Role {
    fn index(self) -> usize {
        match self {
            Self::Client => 0,
            Self::Server => 1,
        }
    }
}

/// Original immutable messages from the one admitted carrier exchange. Its
/// provider must independently qualify actual TLS/context and irreversible
/// admission before calling this private boundary; no boolean can assert it.
pub(crate) struct HandshakeInput<'a> {
    pub(crate) artifact: &'a [u8],
    pub(crate) client_hello: &'a [u8],
    pub(crate) server_hello: &'a [u8],
    pub(crate) transport_context: &'a [u8],
    pub(crate) fsb: &'a [u8],
    pub(crate) fsa: &'a [u8],
}
impl fmt::Debug for HandshakeInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HandshakeInput { <redacted> }")
    }
}
struct Binding {
    profile: Profile,
    role: Role,
    context: [u8; 32],
    admission: [u8; 32],
    certificates: [[u8; 32]; 2],
    service_authorities: [[u8; 32]; 2],
    ed: [[u8; 32]; 2],
    fsb: [u8; 32],
    fsa: [u8; 32],
    features: u64,
    resume: Option<crate::checkpoint_v4::ResumeSessionPolicy>,
    shape: RecordShape,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecordShape {
    max_frame: usize,
    max_streams: usize,
    max_credit: u64,
    idle_duration_ms: u64,
    application_profile: u8,
    datagrams: bool,
    rekey_envelope: [u64; 3],
    service_ms: u64,
}
impl RecordShape {
    fn from_artifact(artifact: Value<'_>) -> Result<Self> {
        let contract = field(artifact, "Artifact", "session_contract")?;
        let max_frame = usize::try_from(contract.u("SessionContract", "max_frame")?)
            .map_err(|_| CryptoError::Configuration)?;
        let max_streams = usize::try_from(contract.u("SessionContract", "max_streams")?)
            .map_err(|_| CryptoError::Configuration)?;
        let envelope = field(contract, "SessionContract", "rekey_envelope")?;
        let rekey_envelope = [
            envelope.u("RekeyEnvelope", "burst_rounds")?,
            envelope.u("RekeyEnvelope", "refill_period_ms")?,
            envelope.u("RekeyEnvelope", "request_start_budget_ms")?,
        ];
        let service_ms = artifact
            .u("Artifact", "session_not_after_ms")?
            .checked_sub(artifact.u("Artifact", "issued_at_ms")?)
            .ok_or(CryptoError::Configuration)?;
        Ok(Self {
            max_frame,
            max_streams,
            max_credit: contract.u("SessionContract", "max_credit")?,
            idle_duration_ms: contract.u("SessionContract", "idle_duration_ms")?,
            application_profile: contract.u("SessionContract", "application_profile")? as u8,
            datagrams: artifact.u("Artifact", "allowed_features")? & 1 != 0,
            rekey_envelope,
            service_ms,
        })
    }
}
struct BoundMaterial {
    binding: Binding,
    psk: Zeroizing<[u8; 32]>,
    peer: Vec<u8>,
    prologue: Vec<u8>,
}
fn decode<'a>(raw: &'a [u8], name: &str, cap: usize, context: Context) -> Result<Value<'a>> {
    Ok(codec::decode_context(
        raw,
        name,
        Limits {
            bytes: cap,
            nodes: 65_536,
        },
        None,
        context,
    )?)
}
fn field<'a>(v: Value<'a>, schema: &str, name: &str) -> Result<Value<'a>> {
    Ok(v.field(schema, name)?)
}
fn bytes<'a>(v: Value<'a>, schema: &str, name: &str) -> Result<&'a [u8]> {
    Ok(field(v, schema, name)?.bytes()?)
}
fn same(a: Value<'_>, an: &str, af: &str, b: Value<'_>, bn: &str, bf: &str) -> Result<()> {
    if field(a, an, af)?.raw() != field(b, bn, bf)?.raw() {
        return Err(CryptoError::Authentication);
    }
    Ok(())
}
fn expect_bytes(value: Value<'_>, schema: &str, name: &str, expected: &[u8]) -> Result<()> {
    if bytes(value, schema, name)? != expected {
        return Err(CryptoError::Authentication);
    }
    Ok(())
}
fn domain(label: &[u8], parts: &[&[u8]]) -> Result<Vec<u8>> {
    let size = parts
        .iter()
        .try_fold(label.len(), |n, p| n.checked_add(4)?.checked_add(p.len()))
        .ok_or(CryptoError::Capacity)?;
    let mut out = Vec::new();
    out.try_reserve_exact(size)
        .map_err(|_| CryptoError::Capacity)?;
    out.extend_from_slice(label);
    for part in parts {
        out.extend_from_slice(
            &u32::try_from(part.len())
                .map_err(|_| CryptoError::Capacity)?
                .to_be_bytes(),
        );
        out.extend_from_slice(part);
    }
    Ok(out)
}
fn expand(root: &[u8; 32], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::from_prk(root)
        .map_err(|_| CryptoError::Key)?
        .expand(info, key.as_mut())
        .map_err(|_| CryptoError::Key)?;
    Ok(key)
}
fn mac(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("SHA256 key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}
fn bind(
    admission: &CredentialAdmission,
    role: Role,
    local: &LocalKeys,
    input: &HandshakeInput<'_>,
    scratch: &mut Vec<u8>,
) -> Result<BoundMaterial> {
    let artifact = decode(input.artifact, "Artifact", 65_536, Context::default())?;
    if codec::digest("artifact_digest", artifact)? != admission.artifact_digest {
        return Err(CryptoError::Authentication);
    }
    let profile = Profile::parse(field(artifact, "Artifact", "crypto_profile_id")?.text()?)?;
    let context = Context::with_activation_source(admission.source);
    let fsb = decode(input.fsb, "FSB4", 65_536, context)?;
    let fsa = decode(input.fsa, "FSA4", 16_384, context)?;
    let client = decode(
        bytes(fsb, "FSB4", "client_certificate")?,
        "IdentityCertificate",
        8192,
        Context::default(),
    )?;
    let server = decode(
        bytes(fsa, "FSA4", "server_certificate")?,
        "IdentityCertificate",
        8192,
        Context::default(),
    )?;
    let certificates = [
        codec::digest("certificate_digest", client)?,
        codec::digest("certificate_digest", server)?,
    ];
    if certificates != admission.certificate_digests {
        return Err(CryptoError::Authentication);
    }
    let mut ed = [[0; 32]; 2];
    let mut service_authorities = [[0; 32]; 2];
    let mut dh = [&[][..]; 2];
    for (i, certificate) in [client, server].into_iter().enumerate() {
        if certificate.u("IdentityCertificate", "role")? != i as u64 {
            return Err(CryptoError::Authentication);
        }
        same(
            certificate,
            "IdentityCertificate",
            "crypto_profile_id",
            artifact,
            "Artifact",
            "crypto_profile_id",
        )?;
        // A local routing comparison is derived only after credential
        // admission. It excludes expiry, generation and signature so renewal
        // preserves logical authority, while tenant/subject/audience and the
        // independently verified namespace authority remain bound.
        let mut identity = sha2::Sha256::new();
        identity.update(b"flowersec/controller-service-authority/v1\0");
        for name in [
            "tenant_id",
            "subject_id",
            "audience",
            "revocation_authority_id",
        ] {
            let value = certificate
                .field("IdentityCertificate", name)?
                .text()?
                .as_bytes();
            identity.update((value.len() as u32).to_be_bytes());
            identity.update(value);
        }
        service_authorities[i] = identity.finalize().into();
        ed[i] = certificate.b("IdentityCertificate", "ed25519_public_key")?;
        if !codec::valid_ed25519_key(&ed[i]) {
            return Err(CryptoError::Key);
        }
        let key = field(
            certificate,
            "IdentityCertificate",
            "noise_static_public_key",
        )?;
        dh[i] = bytes(key, "NoiseStaticPublicKey", "public_key_bytes")?;
        keys::check_public(profile, dh[i])?;
    }
    if local.ed_public() != ed[role.index()] || local.dh_public() != dh[role.index()] {
        return Err(CryptoError::Key);
    }
    codec::verify_signature("FSB4", fsb, &ed[0], scratch)?;
    codec::verify_signature("FSA4", fsa, &ed[1], scratch)?;
    let activation = decode(
        bytes(fsb, "FSB4", "activation_authorization")?,
        "ActivationAuthorization",
        4096,
        context,
    )?;
    if codec::digest("activation_digest", activation)? != admission.activation_digest {
        return Err(CryptoError::Authentication);
    }
    for name in ["tenant_id", "issuer_key_id", "lease_id", "session_nonce"] {
        same(fsb, "FSB4", name, artifact, "Artifact", name)?;
    }
    for (name, expected) in [
        ("artifact_digest", admission.artifact_digest.as_slice()),
        ("candidate_id", admission.candidate_id.as_slice()),
        ("route_digest", admission.route_digest.as_slice()),
        ("attempt_id", admission.attempt_id.as_slice()),
    ] {
        expect_bytes(fsb, "FSB4", name, expected)?;
    }
    let ch = decode(input.client_hello, "ClientHello", 4096, Context::default())?;
    let sh = decode(input.server_hello, "ServerHello", 4096, Context::default())?;
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
    for name in [
        "artifact_digest",
        "candidate_id",
        "route_digest",
        "attempt_id",
    ] {
        same(ch, "ClientHello", name, fsb, "FSB4", name)?;
    }
    same(
        ch,
        "ClientHello",
        "crypto_profile_id",
        artifact,
        "Artifact",
        "crypto_profile_id",
    )?;
    same(
        ch,
        "ClientHello",
        "client_nonce",
        artifact,
        "Artifact",
        "session_nonce",
    )?;
    let transcript: [u8; 32] = Sha256::digest(domain(
        b"flowersec/v4/hello-transcript\0",
        &[input.client_hello, input.server_hello],
    )?)
    .into();
    let tc = decode(
        input.transport_context,
        "TransportContext",
        4096,
        Context::default(),
    )?;
    for name in ["crypto_profile_id", "session_nonce"] {
        same(tc, "TransportContext", name, artifact, "Artifact", name)?;
    }
    for name in ["artifact_digest", "route_digest", "attempt_id"] {
        same(tc, "TransportContext", name, fsb, "FSB4", name)?;
    }
    expect_bytes(
        tc,
        "TransportContext",
        "hello_transcript_digest",
        &transcript,
    )?;
    let tunnel = admission.tunnel.as_ref();
    if tc.u("TransportContext", "path_kind")? != u64::from(tunnel.is_some())
        || tc.u("TransportContext", "access_class")? != 0
        || tunnel
            .is_some_and(|hop| !hop.authenticated() || hop.endpoint_role as usize != role.index())
    {
        return Err(CryptoError::Configuration);
    }
    let mode = sh.u("ServerHello", "binding_mode")?;
    if mode > 1 || ch.u("ClientHello", "supported_binding_modes")? & (1 << mode) == 0 {
        return Err(CryptoError::Authentication);
    }
    let features = sh.u("ServerHello", "selected_features")?;
    let offered = ch.u("ClientHello", "offered_features")?
        & sh.u("ServerHello", "server_offered_features")?
        & artifact.u("Artifact", "allowed_features")?
        & 3;
    if features != offered || artifact.u("Artifact", "required_features")? & !features != 0 {
        return Err(CryptoError::Authentication);
    }
    let context_digest = codec::digest("transport_context_digest", tc)?;
    let admission_binding = codec::digest("admission_binding", fsb)?;
    for (map, schema) in [(fsb, "FSB4"), (fsa, "FSA4"), (tc, "TransportContext")] {
        expect_bytes(map, schema, "hello_transcript_digest", &transcript)?;
        if map.u(schema, "binding_mode")? != mode || map.u(schema, "selected_features")? != features
        {
            return Err(CryptoError::Authentication);
        }
        if schema != "TransportContext" {
            expect_bytes(map, schema, "transport_context_digest", &context_digest)?;
        }
    }
    if fsa.u("FSA4", "status")? != 0 || fsa.u("FSA4", "code")? != 0 {
        return Err(CryptoError::Authentication);
    }
    expect_bytes(fsa, "FSA4", "route_digest", &admission.route_digest)?;
    expect_bytes(fsa, "FSA4", "admission_binding", &admission_binding)?;
    expect_bytes(fsa, "FSA4", "client_identity_digest", &certificates[0])?;
    expect_bytes(fsa, "FSA4", "server_identity_digest", &certificates[1])?;
    let shape = RecordShape::from_artifact(artifact)?;
    let psk = Zeroizing::new(artifact.b("Artifact", "e2ee_psk")?);
    // The only prologue encoding: original complete signed FSB/FSA, no caller
    // supplied alternative and no canonical re-encoding of either object.
    let mut prologue = domain(
        b"flowersec/v4/noise-prologue\0",
        &[b"4", profile.name().as_bytes()],
    )?;
    prologue
        .try_reserve_exact(2 + 12 + 32 + input.fsb.len() + input.fsa.len())
        .map_err(|_| CryptoError::Capacity)?;
    prologue.extend_from_slice(&[0, 1]);
    for part in [context_digest.as_slice(), input.fsb, input.fsa] {
        prologue.extend_from_slice(&(part.len() as u32).to_be_bytes());
        prologue.extend_from_slice(part);
    }
    Ok(BoundMaterial {
        binding: Binding {
            profile,
            role,
            context: context_digest,
            admission: admission_binding,
            certificates,
            service_authorities,
            ed,
            fsb: codec::digest("fsb_digest", fsb)?,
            fsa: codec::digest("fsa_digest", fsa)?,
            features,
            resume: crate::checkpoint_v4::ResumeSessionPolicy::capture(artifact, features)?,
            shape,
        },
        psk,
        peer: dh[1 - role.index()].to_vec(),
        prologue,
    })
}

// Snow keeps its symmetric state private. Clear its configurable PSK through
// the supported API on every exit; our own DH/Split/root material is zeroizing.
// Snow/ring internal temporaries remain subject to the libraries' destruction
// behavior. Logical closure does not promise physical whole-process erasure.
struct NoiseState(snow::HandshakeState);
impl std::ops::Deref for NoiseState {
    type Target = snow::HandshakeState;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for NoiseState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for NoiseState {
    fn drop(&mut self) {
        let _ = self.0.set_psk(0, &[0; 32]);
        std::hint::black_box(&self.0);
    }
}
pub(crate) struct Handshake {
    account: ResourceAccount,
    _charge: ResourceCharge,
    binding: Binding,
    keys: Option<Arc<LocalKeys>>,
    state: Option<NoiseState>,
    records: Option<RecordEngine>,
    records_transferred: bool,
    ready_keys: Option<[Zeroizing<[u8; 32]>; 2]>,
    record_reservation: Option<records::RecordReservation>,
    deadline: Instant,
    initiation_cutoff: u64,
    hash: [u8; 32],
    written: bool,
    read: bool,
    local_signed: bool,
    local_submitted: bool,
    peer_seen: bool,
    peer_verified: bool,
    closed: bool,
    ready: [u8; 103],
    pool_activation: Option<crate::pool_v4::PoolActivation>,
}
impl fmt::Debug for Handshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Handshake { <redacted> }")
    }
}
/// A private writer's success means it owns the exact READY's irreversible
/// submission obligation. Failure/uncertainty closes the attempt; no marker API
/// can turn merely generated bytes into local submission.
pub(crate) trait ReadyWriter {
    fn submit_ready(&mut self, payload: &[u8; 103]) -> Result<()>;
}
struct HandshakePreflight {
    records: records::RecordReservation,
    charge: ResourceCharge,
    scratch: Zeroizing<Vec<u8>>,
}
impl HandshakePreflight {
    fn handshake_limits() -> ResourceLimits {
        ResourceLimits {
            sdk_bytes: 262_144,
            items: 4,
            timers: 1,
            work_slots: 1,
            tasks: 1,
            ..ResourceLimits::default()
        }
    }
    fn preparation_limits(shape: &RecordShape, automatic: bool) -> Result<ResourceLimits> {
        Ok(connect::candidate_add_limits(
            Self::handshake_limits(),
            records::RecordReservation::preparation_limits(shape, automatic)?,
        )?)
    }
    fn new(account: ResourceAccount, shape: RecordShape, role: Role) -> Result<Self> {
        let charge = account.reserve(Self::preparation_limits(
            &shape,
            account.automatic_liveness().is_some(),
        )?)?;
        Self::new_prepaid(account, shape, role, charge)
    }
    fn new_prepaid(
        account: ResourceAccount,
        shape: RecordShape,
        role: Role,
        mut backing: ResourceCharge,
    ) -> Result<Self> {
        if !backing.matches(
            &account,
            Self::preparation_limits(&shape, account.automatic_liveness().is_some())?,
        ) {
            return Err(CryptoError::Configuration);
        }
        let charge = backing.split(Self::handshake_limits())?;
        let mut scratch = Zeroizing::new(Vec::new());
        scratch
            .try_reserve_exact(65_664)
            .map_err(|_| CryptoError::Capacity)?;
        Ok(Self {
            records: records::RecordReservation::new_prepaid(account, shape, role, backing)?,
            charge,
            scratch,
        })
    }
}
impl Handshake {
    #[cfg(test)]
    pub(crate) fn new(
        admission: CredentialAdmission,
        role: Role,
        local: Arc<LocalKeys>,
        input: HandshakeInput<'_>,
    ) -> Result<Self> {
        Self::new_reserved(admission, role, local, input, None)
    }
    fn new_reserved(
        mut admission: CredentialAdmission,
        role: Role,
        local: Arc<LocalKeys>,
        input: HandshakeInput<'_>,
        reservation: Option<HandshakePreflight>,
    ) -> Result<Self> {
        if reservation
            .as_ref()
            .is_some_and(|r| !r.records.owns(&admission.account))
        {
            return Err(CryptoError::Configuration);
        }
        let pool_activation = if admission.source == codec::ActivationSource::PreauthorizedPool
            && role == Role::Client
        {
            admission
                .pool_activation
                .as_ref()
                .ok_or(CryptoError::State)?
                .authorize(&admission)
                .map_err(|_| CryptoError::State)?;
            let activation = admission.pool_activation.take().ok_or(CryptoError::State)?;
            Some(activation)
        } else {
            None
        };
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(10))
            .ok_or(CryptoError::Deadline)?;
        let account = admission.account.clone();
        let (charge, mut scratch, reservation) = match reservation {
            Some(HandshakePreflight {
                records,
                charge,
                scratch,
            }) => (charge, scratch, Some(records)),
            None => {
                let charge = account.reserve(ResourceLimits {
                    sdk_bytes: 262_144,
                    items: 4,
                    timers: 1,
                    work_slots: 1,
                    tasks: 1,
                    sessions: 0,
                    ..ResourceLimits::default()
                })?;
                let mut scratch = Zeroizing::new(Vec::new());
                scratch
                    .try_reserve_exact(65_664)
                    .map_err(|_| CryptoError::Capacity)?;
                (charge, scratch, None)
            }
        };
        if account.security_time()?.upper_ms >= admission.initiation_not_after_ms {
            return Err(CryptoError::Deadline);
        }
        let BoundMaterial {
            binding,
            psk,
            peer,
            prologue,
        } = bind(&admission, role, &local, &input, &mut scratch)?;
        let params = binding
            .profile
            .protocol()
            .parse()
            .map_err(|_| CryptoError::Configuration)?;
        let builder = snow::Builder::with_resolver(params, local.resolver(binding.profile)?)
            .local_private_key(&[0; 32])
            .map_err(|_| CryptoError::Key)?
            .remote_public_key(&peer)
            .map_err(|_| CryptoError::Key)?
            .psk(0, &psk)
            .map_err(|_| CryptoError::Key)?
            .prologue(&prologue)
            .map_err(|_| CryptoError::Configuration)?;
        let state = match role {
            Role::Client => builder.build_initiator(),
            Role::Server => builder.build_responder(),
        }
        .map_err(|_| CryptoError::Key)?;
        let result = Self {
            account,
            _charge: charge,
            binding,
            keys: Some(local),
            state: Some(NoiseState(state)),
            records: None,
            records_transferred: false,
            ready_keys: None,
            record_reservation: reservation,
            deadline,
            initiation_cutoff: admission.initiation_not_after_ms,
            hash: [0; 32],
            written: false,
            read: false,
            local_signed: false,
            local_submitted: false,
            peer_seen: false,
            peer_verified: false,
            closed: false,
            ready: [0; 103],
            pool_activation,
        };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> Result<()> {
        if self.closed || Instant::now() >= self.deadline {
            return Err(CryptoError::Deadline);
        }
        if let Some(activation) = &self.pool_activation {
            activation.check().map_err(|_| CryptoError::State)?;
        }
        if self.account.security_time()?.upper_ms >= self.initiation_cutoff {
            return Err(CryptoError::Deadline);
        }
        if let Some(records) = &self.records {
            records.check()?;
        }
        Ok(())
    }
    fn run<T>(&mut self, action: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let result = self.check().and_then(|()| action(self)).and_then(|v| {
            self.check()?;
            Ok(v)
        });
        if result.is_err() {
            self.close();
        }
        result
    }
    pub(crate) fn write_noise(&mut self, out: &mut [u8; 81]) -> Result<usize> {
        let result = self.run(|this| {
            let mut state = this.state.take().ok_or(CryptoError::State)?;
            if this.written || !state.is_my_turn() || state.is_handshake_finished() {
                return Err(CryptoError::State);
            }
            let n = state
                .write_message(&[], out)
                .map_err(|_| CryptoError::Authentication)?;
            if n != this.binding.profile.public_len() + 16 {
                return Err(CryptoError::Authentication);
            }
            this.written = true;
            if this.binding.role == Role::Client {
                state.set_psk(0, &[0; 32]).map_err(|_| CryptoError::Key)?;
            }
            this.state = Some(state);
            Ok(n)
        });
        if result.is_err() {
            out.zeroize();
        }
        result
    }
    pub(crate) fn read_noise(&mut self, message: &[u8]) -> Result<()> {
        self.run(|this| {
            let mut state = this.state.take().ok_or(CryptoError::State)?;
            if this.read
                || state.is_my_turn()
                || message.len() != this.binding.profile.public_len() + 16
            {
                return Err(CryptoError::State);
            }
            keys::check_public(
                this.binding.profile,
                &message[..this.binding.profile.public_len()],
            )?;
            if state
                .read_message(message, &mut [])
                .map_err(|_| CryptoError::Authentication)?
                != 0
            {
                return Err(CryptoError::Authentication);
            }
            this.read = true;
            if this.binding.role == Role::Server {
                state.set_psk(0, &[0; 32]).map_err(|_| CryptoError::Key)?;
            }
            this.state = Some(state);
            Ok(())
        })
    }
    fn finish_noise(&mut self) -> Result<()> {
        if self.records.is_some() || self.records_transferred {
            return Ok(());
        }
        let mut state = self.state.take().ok_or(CryptoError::State)?;
        if !self.written || !self.read || !state.is_handshake_finished() {
            return Err(CryptoError::State);
        }
        self.hash = state
            .get_handshake_hash()
            .try_into()
            .map_err(|_| CryptoError::Authentication)?;
        let info = domain(
            b"flowersec/v4/initial-root\0",
            &[
                self.binding.profile.name().as_bytes(),
                &self.hash,
                &self.binding.context,
            ],
        )?;
        let born = self.account.security_time()?;
        let (i2r, r2i) = state.dangerously_get_raw_split();
        let i2r = Zeroizing::new(i2r);
        let _r2i = Zeroizing::new(r2i);
        let root = expand(&i2r, &info)?;
        // No into_transport_mode or cipher operation ever consumes Split keys.
        drop(state);
        let reservation = match self.record_reservation.take() {
            Some(reservation) => reservation,
            None => records::RecordReservation::new(
                self.account.clone(),
                self.binding.shape,
                self.binding.role,
            )?,
        };
        self.records = Some(RecordEngine::prepare_reserved(
            reservation,
            &self.binding,
            self.hash,
            born,
            root,
        )?);
        Ok(())
    }
    fn ready_inputs(&self, role: usize, proof: Option<&[u8; 64]>) -> Result<Vec<u8>> {
        let mut map = Vec::with_capacity(512);
        codec::encode_head(&mut map, 5, if proof.is_some() { 10 } else { 8 });
        codec::encode_head(&mut map, 0, 0);
        codec::encode_head(&mut map, 0, role as u64);
        codec::encode_head(&mut map, 0, 1);
        codec::encode_head(&mut map, 3, self.binding.profile.name().len() as u64);
        map.extend_from_slice(self.binding.profile.name().as_bytes());
        for (i, value) in [
            &self.hash,
            &self.binding.fsb,
            &self.binding.fsa,
            &self.binding.context,
            &self.binding.admission,
            &self.binding.certificates[role],
        ]
        .into_iter()
        .enumerate()
        {
            codec::encode_head(&mut map, 0, i as u64 + 2);
            codec::encode_head(&mut map, 2, 32);
            map.extend_from_slice(value);
        }
        if let Some(proof) = proof {
            codec::encode_head(&mut map, 0, 8);
            codec::encode_head(&mut map, 0, self.binding.features);
            codec::encode_head(&mut map, 0, 9);
            codec::encode_head(&mut map, 2, 64);
            map.extend_from_slice(proof);
        }
        domain(
            if proof.is_some() {
                b"flowersec/v4/ready-mac\0"
            } else {
                b"flowersec/v4/ready-identity\0"
            },
            &[&map],
        )
    }
    fn ready_key(&self, role: usize) -> Result<Zeroizing<[u8; 32]>> {
        if let Some(keys) = &self.ready_keys {
            return Ok(Zeroizing::new(**keys.get(role).ok_or(CryptoError::State)?));
        }
        let mut info = domain(
            b"flowersec/v4/ready-key\0",
            &[
                self.binding.profile.name().as_bytes(),
                &self.hash,
                &self.binding.context,
            ],
        )?;
        info.push(role as u8);
        self.records
            .as_ref()
            .ok_or(CryptoError::State)?
            .derive_ready_key(&info)
    }
    pub(crate) fn submit_ready(&mut self, writer: &mut dyn ReadyWriter) -> Result<()> {
        self.run(|this| {
            if this.local_signed || this.local_submitted {
                return Err(CryptoError::State);
            }
            this.finish_noise()?;
            this.local_signed = true;
            let role = this.binding.role.index();
            let input = this.ready_inputs(role, None)?;
            let proof = this.keys.as_ref().ok_or(CryptoError::State)?.sign(&input)?;
            this.check()?;
            let key = this.ready_key(role)?;
            let tag = mac(&key, &this.ready_inputs(role, Some(&proof))?);
            this.ready[..4].copy_from_slice(&[0xa2, 0, 0x58, 0x40]);
            this.ready[4..68].copy_from_slice(&proof);
            this.ready[68..71].copy_from_slice(&[1, 0x58, 0x20]);
            this.ready[71..].copy_from_slice(&tag);
            this.check()?;
            writer.submit_ready(&this.ready)?;
            this.account.with_security(|| this.local_submitted = true)?;
            this.ready.zeroize();
            Ok(())
        })
    }
    pub(crate) fn verify_ready(&mut self, wire: &[u8]) -> Result<()> {
        self.run(|this| {
            if this.peer_seen {
                return Err(CryptoError::State);
            }
            this.peer_seen = true;
            this.finish_noise()?;
            if wire.len() != 103
                || wire[..4] != [0xa2, 0, 0x58, 0x40]
                || wire[68..71] != [1, 0x58, 0x20]
            {
                return Err(CryptoError::Authentication);
            }
            let proof: [u8; 64] = wire[4..68]
                .try_into()
                .map_err(|_| CryptoError::Authentication)?;
            let role = 1 - this.binding.role.index();
            let key = this.ready_key(role)?;
            let mut verifier =
                Hmac::<Sha256>::new_from_slice(key.as_ref()).map_err(|_| CryptoError::Key)?;
            verifier.update(&this.ready_inputs(role, Some(&proof))?);
            verifier
                .verify_slice(&wire[71..])
                .map_err(|_| CryptoError::Authentication)?;
            if !codec::strict_verify(
                &proof,
                &this.ready_inputs(role, None)?,
                &this.binding.ed[role],
            ) {
                return Err(CryptoError::Authentication);
            }
            this.account.with_security(|| this.peer_verified = true)?;
            Ok(())
        })
    }
    /// Transfer only into a private paused Session so its frozen graphs can be
    /// installed before local READY publication. The handshake retains the
    /// exact original proof verifier and irreversible continuation gate.
    pub(crate) fn prepare_session_records(&mut self) -> Result<RecordEngine> {
        self.check()?;
        if !self.local_submitted || self.records_transferred {
            return Err(CryptoError::State);
        }
        self.ready_keys = Some([self.ready_key(0)?, self.ready_key(1)?]);
        let mut records = self.records.take().ok_or(CryptoError::State)?;
        let now = self.account.security_time()?;
        self.account.with_security(|| records.start(now))??;
        self.records_transferred = true;
        Ok(records)
    }
    /// The private prepared Session cannot activate until both original READY
    /// obligations and the original spend/authorization owner remain valid.
    pub(crate) fn confirm_prepared_ready(mut self) -> Result<()> {
        self.check()?;
        if !self.records_transferred || !self.local_submitted || !self.peer_verified {
            return Err(CryptoError::State);
        }
        self.close();
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn into_records(mut self) -> Result<RecordEngine> {
        self.check()?;
        if !self.local_submitted || !self.peer_verified {
            return Err(CryptoError::State);
        }
        let mut records = self.records.take().ok_or(CryptoError::State)?;
        let now = self.account.security_time()?;
        self.account.with_security(|| records.start(now))??;
        self.close();
        Ok(records)
    }
    fn close(&mut self) {
        self.closed = true;
        self.state = None;
        self.records = None;
        self.record_reservation = None;
        self.keys = None;
        self.pool_activation = None;
        self.ready.zeroize();
        self.ready_keys = None;
    }
}
impl Drop for Handshake {
    fn drop(&mut self) {
        self.close();
    }
}
#[cfg(test)]
#[path = "crypto_v4_tests.rs"]
mod tests;
