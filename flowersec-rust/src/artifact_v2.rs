//! Opaque Transport v2 artifact acquisition and durable spend boundary.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, future::Future, pin::Pin, sync::Arc};

const MAX_ARTIFACT_BYTES: usize = 65_536;

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
