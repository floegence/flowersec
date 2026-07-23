//! Opaque Transport v2 artifact acquisition and durable spend boundary.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, future::Future, pin::Pin, sync::Arc};

const MAX_ARTIFACT_BYTES: usize = 65_536;
#[allow(dead_code)]
const MAX_CANONICAL_FSB2_PAYLOAD: usize = 32_768;
#[allow(dead_code)]
const MAX_ADMISSION_REASON_BYTES: usize = 64;

/// A validated Transport v2 artifact.
///
/// The wire fields are intentionally not exposed. Consumers pass this handle to
/// session APIs without learning carrier credentials or cryptographic material.
///
/// ```
/// use flowersec::artifact_v2::Artifact;
/// let raw = br#"{\"v\":2}"#;
/// assert!(Artifact::parse(raw).is_err());
/// ```
///
/// ```compile_fail
/// use flowersec::artifact_v2::Artifact;
/// let artifact = Artifact::default();
/// ```
///
/// ```compile_fail
/// use flowersec::artifact_v2::Artifact;
/// fn serialize(artifact: &Artifact) {
///     let _ = serde_json::to_string(artifact);
/// }
/// ```
///
/// ```compile_fail
/// use flowersec::artifact_v2::Artifact;
/// fn expose(artifact: &Artifact) {
///     let _ = artifact.encode();
/// }
/// ```
#[derive(Clone)]
pub struct Artifact(#[allow(dead_code)] Arc<ValidatedArtifact>);

impl std::fmt::Debug for Artifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Artifact { <opaque> }")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("Flowersec v2 artifact is too large")]
    TooLarge,
    #[error("invalid Flowersec v2 artifact")]
    InvalidArtifact,
    #[error("invalid Flowersec v2 candidate")]
    InvalidCandidate,
    #[error("invalid FSB2 admission request")]
    InvalidFsb2,
    #[error("FSB2 canonical payload is too large")]
    Fsb2PayloadTooLarge,
    #[error("invalid FSA2 admission response")]
    InvalidFsa2,
    #[error("unknown FSA2 admission reason")]
    UnknownAdmissionReason,
}

#[derive(Debug)]
struct ValidatedArtifact {
    #[allow(dead_code)]
    canonical_json: Box<[u8]>,
    #[allow(dead_code)]
    wire: ArtifactWire,
}

impl Artifact {
    pub fn parse(input: impl AsRef<[u8]>) -> Result<Self, ArtifactError> {
        let input = input.as_ref();
        if input.len() > MAX_ARTIFACT_BYTES {
            return Err(ArtifactError::TooLarge);
        }
        reject_duplicate_json_keys(input)?;
        let wire: ArtifactWire =
            serde_json::from_slice(input).map_err(|_| ArtifactError::InvalidArtifact)?;
        validate(&wire)?;
        let canonical = serde_json::to_vec(&wire).map_err(|_| ArtifactError::InvalidArtifact)?;
        if canonical.len() > MAX_ARTIFACT_BYTES {
            return Err(ArtifactError::TooLarge);
        }
        Ok(Self(Arc::new(ValidatedArtifact {
            canonical_json: canonical.into(),
            wire,
        })))
    }

    /// Returns the canonical wire form to crate-owned session connectors.
    #[allow(dead_code)]
    pub(crate) fn encode(&self) -> Box<[u8]> {
        self.0.canonical_json.clone()
    }

    #[allow(dead_code)]
    pub(crate) fn encode_fsb2(
        &self,
        chosen_candidate_id: &str,
    ) -> Result<EncodedFsb2, ArtifactError> {
        let candidates = canonicalize_candidates(&self.0.wire)?;
        if !candidates
            .iter()
            .any(|candidate| candidate.id == chosen_candidate_id)
        {
            return Err(ArtifactError::InvalidFsb2);
        }
        let candidate_json =
            serde_json::to_vec(&candidates).map_err(|_| ArtifactError::InvalidFsb2)?;
        let candidate_hash = hash_canonical(b"flowersec-v2-candidates\0", &candidate_json);
        let session_hash =
            decode32(&self.0.wire.session.contract_hash_b64u).ok_or(ArtifactError::InvalidFsb2)?;
        let (path_code, payload) = match &self.0.wire.path {
            PathWire::Direct {
                rendezvous_group_id,
                listener_audience,
                routing_token,
                ..
            } => (
                1,
                serde_json::to_vec(&DirectFsb2Wire {
                    candidate_set_hash_b64u: URL_SAFE_NO_PAD.encode(candidate_hash),
                    candidates,
                    channel_id: self.0.wire.session.channel_id.clone(),
                    chosen_candidate_id: chosen_candidate_id.to_owned(),
                    listener_audience: listener_audience.clone(),
                    profile: self.0.wire.profile.clone(),
                    rendezvous_group_id: rendezvous_group_id.clone(),
                    routing_token: routing_token.clone(),
                    session_contract_hash_b64u: URL_SAFE_NO_PAD.encode(session_hash),
                })
                .map_err(|_| ArtifactError::InvalidFsb2)?,
            ),
            PathWire::Tunnel {
                rendezvous_group_id,
                listener_audience,
                role,
                local_endpoint_instance_id,
                token,
                ..
            } => (
                2,
                serde_json::to_vec(&TunnelFsb2Wire {
                    attach_token: token.clone(),
                    candidate_set_hash_b64u: URL_SAFE_NO_PAD.encode(candidate_hash),
                    candidates,
                    channel_id: self.0.wire.session.channel_id.clone(),
                    chosen_candidate_id: chosen_candidate_id.to_owned(),
                    endpoint_instance_id: local_endpoint_instance_id.clone(),
                    listener_audience: listener_audience.clone(),
                    profile: self.0.wire.profile.clone(),
                    rendezvous_group_id: rendezvous_group_id.clone(),
                    role: *role,
                    session_contract_hash_b64u: URL_SAFE_NO_PAD.encode(session_hash),
                })
                .map_err(|_| ArtifactError::InvalidFsb2)?,
            ),
        };
        if payload.len() > MAX_CANONICAL_FSB2_PAYLOAD {
            return Err(ArtifactError::Fsb2PayloadTooLarge);
        }
        let mut raw = Vec::with_capacity(12 + payload.len());
        raw.extend_from_slice(b"FSB2");
        raw.extend_from_slice(&[2, path_code, 0, 0]);
        raw.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        raw.extend_from_slice(&payload);
        let binding = hash_admission(&raw);
        Ok(EncodedFsb2 { raw, binding })
    }

    pub(crate) fn raw_quic_dial_plan(&self) -> Result<RawQuicDialPlan, ArtifactError> {
        let (
            path,
            role,
            local_endpoint_instance_id,
            expected_peer_endpoint_instance_id,
            candidates,
        ) = match &self.0.wire.path {
            PathWire::Direct { candidates, .. } => (
                crate::transport_v2::PathKind::Direct,
                crate::transport_v2::SessionRole::Client,
                None,
                None,
                candidates,
            ),
            PathWire::Tunnel {
                role,
                local_endpoint_instance_id,
                expected_peer_endpoint_instance_id,
                candidates,
                ..
            } => (
                crate::transport_v2::PathKind::Tunnel,
                if *role == 1 {
                    crate::transport_v2::SessionRole::Client
                } else {
                    crate::transport_v2::SessionRole::Server
                },
                Some(local_endpoint_instance_id.clone()),
                Some(expected_peer_endpoint_instance_id.clone()),
                candidates,
            ),
        };
        let raw_quic_candidates = candidates
            .iter()
            .filter(|candidate| matches!(candidate.carrier, CarrierWire::RawQuic))
            .map(|candidate| {
                let normalized_url = normalize_url(
                    if path == crate::transport_v2::PathKind::Direct {
                        "direct"
                    } else {
                        "tunnel"
                    },
                    candidate,
                )?;
                let url = url::Url::parse(&normalized_url)
                    .map_err(|_| ArtifactError::InvalidCandidate)?;
                Ok(RawQuicCandidatePlan {
                    id: candidate.id.clone(),
                    host: url
                        .host_str()
                        .ok_or(ArtifactError::InvalidCandidate)?
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .to_owned(),
                    port: url.port().unwrap_or(443),
                })
            })
            .collect::<Result<Vec<_>, ArtifactError>>()?;
        if raw_quic_candidates.is_empty() {
            return Err(ArtifactError::InvalidCandidate);
        }
        let session = &self.0.wire.session;
        let psk = decode32(&session.e2ee_psk_b64u).ok_or(ArtifactError::InvalidArtifact)?;
        let contract_hash =
            decode32(&session.contract_hash_b64u).ok_or(ArtifactError::InvalidArtifact)?;
        let suite = match session.default_suite {
            1 => crate::protocol_v2::CipherSuiteV2::ChaCha20Poly1305,
            2 => crate::protocol_v2::CipherSuiteV2::Aes256Gcm,
            _ => return Err(ArtifactError::InvalidArtifact),
        };
        Ok(RawQuicDialPlan {
            candidates: raw_quic_candidates,
            path,
            local_endpoint_instance_id,
            expected_peer_endpoint_instance_id,
            expires_at_unix_seconds: session.init_expire_at_unix_s,
            session_config: crate::session_v2::SessionConfigV2 {
                role,
                path,
                channel_id: session.channel_id.clone(),
                session_contract_hash: contract_hash,
                suite,
                psk,
                max_inbound_streams: session.max_inbound_streams,
                idle_timeout: std::time::Duration::from_secs(u64::from(
                    session.idle_timeout_seconds,
                )),
                local_admission_binding: [0; 32],
                peer_admission_binding: None,
                local_endpoint_instance_id: None,
                expected_peer_endpoint_instance_id: None,
                rpc_handler: None,
                deadlines: crate::session_v2::SessionDeadlinesV2 {
                    establish: std::time::Duration::from_secs(u64::from(
                        session.establish_timeout_seconds,
                    )),
                    rekey_prepare: std::time::Duration::from_secs(u64::from(
                        session.rekey_prepare_timeout_seconds,
                    )),
                    rekey_completion: std::time::Duration::from_secs(u64::from(
                        session.rekey_completion_timeout_seconds,
                    )),
                    ..Default::default()
                },
            },
            session_contract: crate::raw_quic_v2::SessionContractV2 {
                channel_id: session.channel_id.clone(),
                idle_timeout_seconds: u64::from(session.idle_timeout_seconds),
                establish_timeout_seconds: u64::from(session.establish_timeout_seconds),
                rekey_prepare_timeout_seconds: u64::from(session.rekey_prepare_timeout_seconds),
                rekey_completion_timeout_seconds: u64::from(
                    session.rekey_completion_timeout_seconds,
                ),
                max_inbound_streams: session.max_inbound_streams,
                psk,
                allowed_suites: session.allowed_suites.clone(),
                default_suite: session.default_suite,
                selected_features: session.selected_features,
                contract_hash,
            },
        })
    }
}

pub(crate) struct RawQuicDialPlan {
    pub(crate) candidates: Vec<RawQuicCandidatePlan>,
    pub(crate) path: crate::transport_v2::PathKind,
    pub(crate) local_endpoint_instance_id: Option<String>,
    pub(crate) expected_peer_endpoint_instance_id: Option<String>,
    pub(crate) expires_at_unix_seconds: i64,
    pub(crate) session_config: crate::session_v2::SessionConfigV2,
    pub(crate) session_contract: crate::raw_quic_v2::SessionContractV2,
}

#[derive(Clone, Debug)]
pub(crate) struct RawQuicCandidatePlan {
    pub(crate) id: String,
    pub(crate) host: String,
    pub(crate) port: u16,
}

#[allow(dead_code)]
pub(crate) struct EncodedFsb2 {
    pub(crate) raw: Vec<u8>,
    pub(crate) binding: [u8; 32],
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
struct CanonicalCandidate {
    carrier: CarrierWire,
    id: String,
    normalized_url: String,
    wire_profile: String,
}

#[derive(Serialize)]
#[allow(dead_code)]
struct DirectFsb2Wire {
    candidate_set_hash_b64u: String,
    candidates: Vec<CanonicalCandidate>,
    channel_id: String,
    chosen_candidate_id: String,
    listener_audience: String,
    profile: String,
    rendezvous_group_id: String,
    routing_token: String,
    session_contract_hash_b64u: String,
}

#[derive(Serialize)]
#[allow(dead_code)]
struct TunnelFsb2Wire {
    attach_token: String,
    candidate_set_hash_b64u: String,
    candidates: Vec<CanonicalCandidate>,
    channel_id: String,
    chosen_candidate_id: String,
    endpoint_instance_id: String,
    listener_audience: String,
    profile: String,
    rendezvous_group_id: String,
    role: u8,
    session_contract_hash_b64u: String,
}

#[allow(dead_code)]
fn canonicalize_candidates(wire: &ArtifactWire) -> Result<Vec<CanonicalCandidate>, ArtifactError> {
    let (kind, source) = match &wire.path {
        PathWire::Direct { candidates, .. } => ("direct", candidates),
        PathWire::Tunnel { candidates, .. } => ("tunnel", candidates),
    };
    let mut candidates = source
        .iter()
        .map(|candidate| {
            Ok(CanonicalCandidate {
                carrier: candidate.carrier,
                id: candidate.id.clone(),
                normalized_url: normalize_url(kind, candidate)?,
                wire_profile: candidate.wire_profile.clone(),
            })
        })
        .collect::<Result<Vec<_>, ArtifactError>>()?;
    candidates.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    Ok(candidates)
}

#[allow(dead_code)]
fn hash_canonical(domain: &[u8], canonical: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(domain.len() + 4 + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&(canonical.len() as u32).to_be_bytes());
    preimage.extend_from_slice(canonical);
    Sha256::digest(preimage).into()
}

#[allow(dead_code)]
fn hash_admission(raw: &[u8]) -> [u8; 32] {
    let mut preimage = b"flowersec-v2-admission\0".to_vec();
    preimage.extend_from_slice(raw);
    Sha256::digest(preimage).into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum AdmissionStatus {
    Success,
    Reject,
    Retryable,
}

#[derive(Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct AdmissionResponse {
    pub(crate) status: AdmissionStatus,
    pub(crate) reason: String,
}

#[allow(dead_code)]
pub(crate) fn decode_fsa2(
    raw: &[u8],
    reasons: &[&str],
) -> Result<AdmissionResponse, ArtifactError> {
    if raw.len() < 8 || &raw[..4] != b"FSA2" || raw[4] != 2 {
        return Err(ArtifactError::InvalidFsa2);
    }
    let reason_len = u16::from_be_bytes([raw[6], raw[7]]) as usize;
    if reason_len > MAX_ADMISSION_REASON_BYTES || raw.len() != 8 + reason_len {
        return Err(ArtifactError::InvalidFsa2);
    }
    let reason = std::str::from_utf8(&raw[8..]).map_err(|_| ArtifactError::InvalidFsa2)?;
    let status = match raw[5] {
        0 if reason.is_empty() => AdmissionStatus::Success,
        1 | 2 if valid_reason(reason) => {
            if !reasons.contains(&reason) {
                return Err(ArtifactError::UnknownAdmissionReason);
            }
            if raw[5] == 1 {
                AdmissionStatus::Reject
            } else {
                AdmissionStatus::Retryable
            }
        }
        _ => return Err(ArtifactError::InvalidFsa2),
    };
    Ok(AdmissionResponse {
        status,
        reason: reason.to_owned(),
    })
}

#[allow(dead_code)]
fn valid_reason(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= MAX_ADMISSION_REASON_BYTES
        && reason.as_bytes()[0].is_ascii_lowercase()
        && reason
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn reject_duplicate_json_keys(input: &[u8]) -> Result<(), ArtifactError> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    DuplicateKeySeed
        .deserialize(&mut deserializer)
        .map_err(|_| ArtifactError::InvalidArtifact)?;
    deserializer
        .end()
        .map_err(|_| ArtifactError::InvalidArtifact)
}

struct DuplicateKeySeed;

impl<'de> DeserializeSeed<'de> for DuplicateKeySeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateKeyVisitor)
    }
}

struct DuplicateKeyVisitor;

impl<'de> Visitor<'de> for DuplicateKeyVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate object key"));
            }
            map.next_value_seed(DuplicateKeySeed)?;
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(DuplicateKeySeed)?.is_some() {}
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateKeySeed.deserialize(deserializer)
    }
    fn visit_bytes<E>(self, _: &[u8]) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_byte_buf<E>(self, _: Vec<u8>) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateKeySeed.deserialize(deserializer)
    }
}

type SpendFuture = Pin<Box<dyn Future<Output = Result<(), ArtifactSpendError>> + Send + 'static>>;
type SpendFn = Box<dyn FnMut() -> SpendFuture + Send>;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ArtifactSpendError {
    #[error("artifact spend has already been committed")]
    AlreadyCommitted,
    #[error("artifact spend commit failed: {0}")]
    Commit(String),
}

/// Owns an artifact until the caller durably records its successful spend.
pub struct ArtifactLease {
    artifact: Artifact,
    commit: SpendFn,
    committed: bool,
}

impl std::fmt::Debug for ArtifactLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArtifactLease")
            .field("artifact", &self.artifact)
            .field("committed", &self.committed)
            .finish()
    }
}

impl ArtifactLease {
    pub fn new<F, Fut>(artifact: Artifact, mut commit: F) -> Self
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), ArtifactSpendError>> + Send + 'static,
    {
        Self {
            artifact,
            commit: Box::new(move || Box::pin(commit())),
            committed: false,
        }
    }

    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }

    /// Marks the artifact spent only after the durable callback succeeds.
    /// A failed callback remains retryable; a successful callback cannot repeat.
    pub async fn commit_spend(&mut self) -> Result<(), ArtifactSpendError> {
        if self.committed {
            return Err(ArtifactSpendError::AlreadyCommitted);
        }
        (self.commit)().await?;
        self.committed = true;
        Ok(())
    }

    pub fn is_committed(&self) -> bool {
        self.committed
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactWire {
    v: u8,
    profile: String,
    session: SessionWire,
    path: PathWire,
    scoped: Vec<ScopeWire>,
    correlation: CorrelationWire,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionWire {
    channel_id: String,
    init_expire_at_unix_s: i64,
    idle_timeout_seconds: u32,
    establish_timeout_seconds: u16,
    rekey_prepare_timeout_seconds: u16,
    rekey_completion_timeout_seconds: u16,
    max_inbound_streams: u16,
    e2ee_psk_b64u: String,
    allowed_suites: Vec<u16>,
    default_suite: u16,
    selected_features: u32,
    contract_hash_b64u: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum PathWire {
    Direct {
        rendezvous_group_id: String,
        listener_audience: String,
        routing_token: String,
        candidates: Vec<CandidateWire>,
    },
    Tunnel {
        rendezvous_group_id: String,
        listener_audience: String,
        role: u8,
        local_endpoint_instance_id: String,
        expected_peer_endpoint_instance_id: String,
        token: String,
        candidates: Vec<CandidateWire>,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateWire {
    id: String,
    carrier: CarrierWire,
    url: String,
    wire_profile: String,
}

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CarrierWire {
    Websocket,
    RawQuic,
    Webtransport,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScopeWire {
    scope: String,
    scope_version: u16,
    critical: bool,
    payload: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CorrelationWire {
    v: u8,
    tags: Vec<CorrelationTagWire>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CorrelationTagWire {
    key: String,
    value: String,
}

fn validate(wire: &ArtifactWire) -> Result<(), ArtifactError> {
    if wire.v != 2 || wire.profile != "flowersec/2" {
        return Err(ArtifactError::InvalidArtifact);
    }
    validate_session(&wire.session)?;
    let (kind, group, audience, candidates) = match &wire.path {
        PathWire::Direct {
            rendezvous_group_id,
            listener_audience,
            routing_token,
            candidates,
        } => {
            if !valid_ascii(routing_token, 8192) {
                return Err(ArtifactError::InvalidArtifact);
            }
            ("direct", rendezvous_group_id, listener_audience, candidates)
        }
        PathWire::Tunnel {
            rendezvous_group_id,
            listener_audience,
            role,
            local_endpoint_instance_id,
            expected_peer_endpoint_instance_id,
            token,
            candidates,
        } => {
            if !matches!(role, 1 | 2)
                || !valid_id(local_endpoint_instance_id, 128)
                || !valid_id(expected_peer_endpoint_instance_id, 128)
                || local_endpoint_instance_id == expected_peer_endpoint_instance_id
                || !valid_ascii(token, 8192)
            {
                return Err(ArtifactError::InvalidArtifact);
            }
            ("tunnel", rendezvous_group_id, listener_audience, candidates)
        }
    };
    if !valid_id(group, 128) || !valid_id(audience, 128) {
        return Err(ArtifactError::InvalidArtifact);
    }
    validate_candidates(kind, candidates)?;
    if wire.scoped.len() > 8 {
        return Err(ArtifactError::InvalidArtifact);
    }
    let mut scopes = HashSet::new();
    for scope in &wire.scoped {
        if scope.scope_version == 0
            || !valid_lower_id(&scope.scope, 64)
            || !scopes.insert(&scope.scope)
            || serde_json::to_vec(&scope.payload).map_or(true, |v| v.len() > 4096)
        {
            return Err(ArtifactError::InvalidArtifact);
        }
    }
    if wire.correlation.v != 2 || wire.correlation.tags.len() > 8 {
        return Err(ArtifactError::InvalidArtifact);
    }
    let mut tags = HashSet::new();
    for tag in &wire.correlation.tags {
        if !valid_lower_id(&tag.key, 32) || !valid_ascii(&tag.value, 128) || !tags.insert(&tag.key)
        {
            return Err(ArtifactError::InvalidArtifact);
        }
    }
    Ok(())
}

fn validate_session(s: &SessionWire) -> Result<(), ArtifactError> {
    if !valid_id(&s.channel_id, 128)
        || s.init_expire_at_unix_s <= 0
        || s.establish_timeout_seconds != 30
        || s.rekey_prepare_timeout_seconds != 10
        || s.rekey_completion_timeout_seconds != 30
        || !(1..=128).contains(&s.max_inbound_streams)
        || s.selected_features != 0
    {
        return Err(ArtifactError::InvalidArtifact);
    }
    if decode32(&s.e2ee_psk_b64u).is_none() || decode32(&s.contract_hash_b64u).is_none() {
        return Err(ArtifactError::InvalidArtifact);
    }
    if s.allowed_suites.is_empty()
        || !s.allowed_suites.windows(2).all(|w| w[0] < w[1])
        || !s.allowed_suites.iter().all(|x| matches!(x, 1 | 2))
        || !s.allowed_suites.contains(&s.default_suite)
    {
        return Err(ArtifactError::InvalidArtifact);
    }
    let canonical = serde_json::json!({"allowed_suites":s.allowed_suites,"channel_id":s.channel_id,"default_suite":s.default_suite,"establish_timeout_seconds":s.establish_timeout_seconds,"idle_timeout_seconds":s.idle_timeout_seconds,"max_inbound_streams":s.max_inbound_streams,"profile":"flowersec/2","rekey_completion_timeout_seconds":s.rekey_completion_timeout_seconds,"rekey_prepare_timeout_seconds":s.rekey_prepare_timeout_seconds,"selected_features":s.selected_features});
    let bytes = serde_json::to_vec(&canonical).map_err(|_| ArtifactError::InvalidArtifact)?;
    let mut preimage = b"flowersec-v2-session-contract\0".to_vec();
    preimage.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    preimage.extend_from_slice(&bytes);
    if Sha256::digest(preimage)[..] != decode32(&s.contract_hash_b64u).unwrap() {
        return Err(ArtifactError::InvalidArtifact);
    }
    Ok(())
}

fn validate_candidates(kind: &str, candidates: &[CandidateWire]) -> Result<(), ArtifactError> {
    if candidates.is_empty() || candidates.len() > 4 {
        return Err(ArtifactError::InvalidCandidate);
    }
    let mut ids = HashSet::new();
    let mut tuples = HashSet::new();
    for c in candidates {
        if !valid_lower_id(&c.id, 64)
            || !ids.insert(&c.id)
            || c.url.is_empty()
            || c.url.len() > 2048
            || c.wire_profile != format!("flowersec-{kind}/2")
        {
            return Err(ArtifactError::InvalidCandidate);
        }
        let normalized = normalize_url(kind, c)?;
        if !tuples.insert(format!(
            "{:?}\0{}\0{}",
            c.carrier, normalized, c.wire_profile
        )) {
            return Err(ArtifactError::InvalidCandidate);
        }
    }
    Ok(())
}

fn normalize_url(kind: &str, c: &CandidateWire) -> Result<String, ArtifactError> {
    if c.url.contains(['\\', '?', '#', '%']) {
        return Err(ArtifactError::InvalidCandidate);
    }
    let mut url = url::Url::parse(&c.url).map_err(|_| ArtifactError::InvalidCandidate)?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ArtifactError::InvalidCandidate);
    }
    let (scheme, path) = match c.carrier {
        CarrierWire::Websocket => ("wss", format!("/flowersec/v2/{kind}")),
        CarrierWire::RawQuic => ("quic", String::new()),
        CarrierWire::Webtransport => ("https", format!("/flowersec/webtransport/v2/{kind}")),
    };
    if url.scheme() != scheme
        || (matches!(c.carrier, CarrierWire::RawQuic) && !matches!(url.path(), "" | "/"))
        || (!matches!(c.carrier, CarrierWire::RawQuic) && url.path() != path)
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ArtifactError::InvalidCandidate);
    }
    if url.port() == Some(443) {
        url.set_port(None)
            .map_err(|_| ArtifactError::InvalidCandidate)?;
    }
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    let text = url.to_string();
    Ok(text.strip_suffix('/').unwrap_or(&text).to_string())
}

fn decode32(value: &str) -> Option<[u8; 32]> {
    let raw = URL_SAFE_NO_PAD.decode(value).ok()?;
    let out: [u8; 32] = raw.try_into().ok()?;
    (URL_SAFE_NO_PAD.encode(out) == value).then_some(out)
}

fn valid_id(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b))
}
fn valid_lower_id(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}
fn valid_ascii(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.is_ascii()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    #[test]
    fn admission_encoding_matches_shared_vectors_byte_for_byte() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../testdata/transport_v2/artifact_vectors.json"
        ))
        .unwrap();
        for vector in fixture["positive"].as_array().unwrap() {
            let wire: serde_json::Value =
                serde_json::from_str(vector["artifact_json"].as_str().unwrap()).unwrap();
            if !wire["path"]["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .any(|candidate| candidate["carrier"] == "raw_quic")
            {
                continue;
            }
            let artifact = Artifact::parse(vector["artifact_json"].as_str().unwrap()).unwrap();
            let candidates = canonicalize_candidates(&artifact.0.wire).unwrap();
            let canonical = serde_json::to_vec(&candidates).unwrap();
            assert_eq!(
                canonical,
                vector["candidates_canonical_json"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
            );
            assert_eq!(
                URL_SAFE_NO_PAD.encode(hash_canonical(b"flowersec-v2-candidates\0", &canonical)),
                vector["candidate_set_hash_b64u"].as_str().unwrap()
            );
            for winner in vector["winners"].as_array().unwrap() {
                let encoded = artifact
                    .encode_fsb2(winner["candidate_id"].as_str().unwrap())
                    .unwrap();
                assert_eq!(
                    encoded.raw,
                    decode_hex(winner["fsb2_hex"].as_str().unwrap())
                );
                assert_eq!(
                    encoded.binding.as_slice(),
                    decode_hex(winner["admission_binding_hex"].as_str().unwrap())
                );
            }
            assert!(matches!(
                artifact.encode_fsb2("absent"),
                Err(ArtifactError::InvalidFsb2)
            ));
        }
    }

    #[test]
    fn raw_quic_plan_stays_internal_and_matches_signed_artifact() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../testdata/transport_v2/artifact_vectors.json"
        ))
        .unwrap();
        for vector in fixture["positive"].as_array().unwrap() {
            let artifact = Artifact::parse(vector["artifact_json"].as_str().unwrap()).unwrap();
            let plan = artifact.raw_quic_dial_plan().unwrap();
            assert_eq!(plan.candidates[0].id, "q1");
            assert!(!plan.candidates[0].host.starts_with('['));
            assert_eq!(plan.candidates[0].port, 443);
            assert_eq!(
                plan.session_contract.contract_hash,
                plan.session_config.session_contract_hash
            );
            assert_eq!(plan.session_contract.psk, plan.session_config.psk);
            assert_eq!(
                plan.session_contract.canonical_hash(),
                plan.session_contract.contract_hash
            );
        }
    }

    #[test]
    fn fsa2_strict_decode_matches_shared_positive_and_negative_vectors() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../testdata/transport_v2/artifact_vectors.json"
        ))
        .unwrap();
        let reasons = ["invalid_token", "capacity"];
        for vector in fixture["fsa2"].as_array().unwrap() {
            let decoded =
                decode_fsa2(&decode_hex(vector["frame_hex"].as_str().unwrap()), &reasons).unwrap();
            let expected_status = match vector["status"].as_u64().unwrap() {
                0 => AdmissionStatus::Success,
                1 => AdmissionStatus::Reject,
                2 => AdmissionStatus::Retryable,
                _ => unreachable!(),
            };
            assert_eq!(decoded.status, expected_status);
            assert_eq!(decoded.reason, vector["reason"].as_str().unwrap());
        }
        for vector in fixture["negative"].as_array().unwrap() {
            if vector["kind"] != "fsa2_hex" {
                continue;
            }
            let error =
                decode_fsa2(&decode_hex(vector["value"].as_str().unwrap()), &reasons).unwrap_err();
            match vector["error_code"].as_str().unwrap() {
                "invalid_fsa2" => assert!(matches!(error, ArtifactError::InvalidFsa2)),
                "unknown_admission_reason" => {
                    assert!(matches!(error, ArtifactError::UnknownAdmissionReason))
                }
                code => panic!("unexpected shared error code {code}"),
            }
        }
        let mut trailing = decode_hex(fixture["fsa2"][0]["frame_hex"].as_str().unwrap());
        trailing.push(0);
        assert!(matches!(
            decode_fsa2(&trailing, &reasons),
            Err(ArtifactError::InvalidFsa2)
        ));
    }

    #[tokio::test]
    async fn lease_commits_exactly_once_and_retries_failure() {
        let raw = include_str!("../../testdata/transport_v2/artifact_vectors.json");
        let value: serde_json::Value = serde_json::from_str(raw).unwrap();
        let artifact =
            Artifact::parse(value["positive"][0]["artifact_json"].as_str().unwrap()).unwrap();
        assert_eq!(
            &*artifact.encode(),
            value["positive"][0]["artifact_json"]
                .as_str()
                .unwrap()
                .as_bytes()
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let mut lease = ArtifactLease::new(artifact, move || {
            let n = observed.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    Err(ArtifactSpendError::Commit("disk".into()))
                } else {
                    Ok(())
                }
            }
        });
        assert!(matches!(
            lease.commit_spend().await,
            Err(ArtifactSpendError::Commit(_))
        ));
        assert!(!lease.is_committed());
        assert!(lease.commit_spend().await.is_ok());
        assert!(lease.is_committed());
        assert_eq!(
            lease.commit_spend().await,
            Err(ArtifactSpendError::AlreadyCommitted)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
