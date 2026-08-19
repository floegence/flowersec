//! Strict, physically isolated Flowersec v3 artifact and admission codec.

#![cfg_attr(not(test), allow(dead_code))]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    future::Future,
    net::Ipv6Addr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::Duration,
};

use crate::{
    protocol_v3::CipherSuiteV3,
    transport_v3::{PathKind, SessionRole},
};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_ARTIFACT_BYTES: usize = 65_536;
const MAX_CANDIDATE_BYTES: usize = 2_304;
const MAX_CANDIDATE_SET_BYTES: usize = 12_288;
const MAX_FSB3_PAYLOAD_BYTES: usize = 32_768;
const FORBIDDEN_FSA3_REASONS: &[&str] = &[
    "browser_pin_opaque",
    "ca_untrusted",
    "pin_mismatch",
    "pin_tls_unknown",
    "tls_failed",
    "tls_pin_mismatch",
    "tls_policy_expired",
    "tls_untrusted",
    "tls_unsupported",
    "transport_security_failed",
    "transport_security_unsupported",
];

#[derive(Clone)]
pub struct ArtifactV3(Arc<ValidatedArtifactV3>, Option<Arc<HashSet<String>>>);

impl std::fmt::Debug for ArtifactV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ArtifactV3 { <opaque> }")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ArtifactErrorV3 {
    #[error("Flowersec v3 artifact is too large")]
    TooLarge,
    #[error("invalid Flowersec v3 artifact")]
    Invalid,
}

#[derive(Debug)]
struct ValidatedArtifactV3 {
    canonical_json: Box<[u8]>,
    wire: ArtifactWireV3,
    candidates: Vec<CanonicalCandidateV3>,
    candidate_set_json: Box<[u8]>,
    candidate_set_hash: [u8; 32],
}

impl ArtifactV3 {
    pub fn parse(input: impl AsRef<[u8]>) -> Result<Self, ArtifactErrorV3> {
        let input = input.as_ref();
        if input.len() > MAX_ARTIFACT_BYTES {
            return Err(ArtifactErrorV3::TooLarge);
        }
        preflight_artifact_json(input)?;
        let value: Value = serde_json::from_slice(input).map_err(|_| ArtifactErrorV3::Invalid)?;
        let canonical = jcs_value(&value)?;
        if canonical.as_slice() != input {
            return Err(ArtifactErrorV3::Invalid);
        }
        let wire: ArtifactWireV3 =
            serde_json::from_value(value).map_err(|_| ArtifactErrorV3::Invalid)?;
        let candidates = validate_artifact(&wire)?;
        let candidate_set_json = jcs_serialize(&candidates)?;
        if candidate_set_json.len() > MAX_CANDIDATE_SET_BYTES {
            return Err(ArtifactErrorV3::Invalid);
        }
        let candidate_set_hash = hash_lp(b"flowersec-v3-candidates\0", &candidate_set_json);
        Ok(Self(
            Arc::new(ValidatedArtifactV3 {
                canonical_json: canonical.into(),
                wire,
                candidates,
                candidate_set_json: candidate_set_json.into(),
                candidate_set_hash,
            }),
            None,
        ))
    }

    pub(crate) fn encode(&self) -> Box<[u8]> {
        self.0.canonical_json.clone()
    }

    pub(crate) fn expires_at_unix_seconds(&self) -> u64 {
        self.0.wire.session.init_expire_at_unix_s
    }

    pub(crate) fn canonical_candidates(&self) -> &[CanonicalCandidateV3] {
        &self.0.candidates
    }

    pub(crate) fn path_kind_for_controller(&self) -> &'static str {
        self.0.wire.path.kind()
    }

    pub(crate) fn with_controller_candidate_ids(&self, ids: HashSet<String>) -> Self {
        Self(self.0.clone(), Some(Arc::new(ids)))
    }

    pub(crate) fn candidate_set_hash(&self) -> [u8; 32] {
        self.0.candidate_set_hash
    }

    pub(crate) fn connection_plan(&self) -> Result<ConnectionPlanV3, ArtifactErrorV3> {
        let wire = &self.0.wire;
        let (path, role, local_endpoint_instance_id, expected_peer_endpoint_instance_id) =
            match &wire.path {
                PathWireV3::Direct { .. } => (PathKind::Direct, SessionRole::Client, None, None),
                PathWireV3::Tunnel {
                    role,
                    local_endpoint_instance_id,
                    expected_peer_endpoint_instance_id,
                    ..
                } => (
                    PathKind::Tunnel,
                    if *role == 1 {
                        SessionRole::Client
                    } else {
                        SessionRole::Server
                    },
                    Some(local_endpoint_instance_id.clone()),
                    Some(expected_peer_endpoint_instance_id.clone()),
                ),
            };
        let session = &wire.session;
        let suite = match session.default_suite {
            1 => CipherSuiteV3::ChaCha20Poly1305,
            2 => CipherSuiteV3::Aes256Gcm,
            _ => return Err(ArtifactErrorV3::Invalid),
        };
        Ok(ConnectionPlanV3 {
            candidates: self
                .0
                .candidates
                .iter()
                .filter(|candidate| {
                    self.1
                        .as_ref()
                        .is_none_or(|ids| ids.contains(&candidate.id))
                })
                .cloned()
                .collect(),
            path,
            role,
            local_endpoint_instance_id,
            expected_peer_endpoint_instance_id,
            expires_at_unix_seconds: session.init_expire_at_unix_s,
            session: SessionParametersV3 {
                channel_id: session.channel_id.clone(),
                session_contract_hash: decode32(&session.contract_hash_b64u)
                    .ok_or(ArtifactErrorV3::Invalid)?,
                suite,
                psk: decode32(&session.e2ee_psk_b64u).ok_or(ArtifactErrorV3::Invalid)?,
                max_inbound_streams: u16::try_from(session.max_inbound_streams)
                    .map_err(|_| ArtifactErrorV3::Invalid)?,
                idle_timeout: Duration::from_secs(session.idle_timeout_seconds),
                establish_timeout: Duration::from_secs(session.establish_timeout_seconds),
                rekey_prepare_timeout: Duration::from_secs(session.rekey_prepare_timeout_seconds),
                rekey_completion_timeout: Duration::from_secs(
                    session.rekey_completion_timeout_seconds,
                ),
            },
        })
    }

    pub(crate) fn encode_fsb3(
        &self,
        chosen_candidate_id: &str,
    ) -> Result<EncodedFsb3, ArtifactErrorV3> {
        if !self
            .0
            .candidates
            .iter()
            .any(|candidate| candidate.id == chosen_candidate_id)
        {
            return Err(ArtifactErrorV3::Invalid);
        }
        let wire = &self.0.wire;
        let common = |object: &mut serde_json::Map<String, Value>| -> Result<(), ArtifactErrorV3> {
            object.insert(
                "candidate_set_hash_b64u".into(),
                Value::String(URL_SAFE_NO_PAD.encode(self.0.candidate_set_hash)),
            );
            object.insert(
                "candidates".into(),
                serde_json::from_slice(&self.0.candidate_set_json)
                    .map_err(|_| ArtifactErrorV3::Invalid)?,
            );
            object.insert(
                "channel_id".into(),
                Value::String(wire.session.channel_id.clone()),
            );
            object.insert(
                "chosen_candidate_id".into(),
                Value::String(chosen_candidate_id.to_owned()),
            );
            object.insert(
                "listener_audience".into(),
                Value::String(wire.path.listener_audience().to_owned()),
            );
            object.insert("profile".into(), Value::String("flowersec/3".into()));
            object.insert(
                "rendezvous_group_id".into(),
                Value::String(wire.path.rendezvous_group_id().to_owned()),
            );
            object.insert(
                "session_contract_hash_b64u".into(),
                Value::String(wire.session.contract_hash_b64u.clone()),
            );
            Ok(())
        };
        let (path_code, payload_value) = match &wire.path {
            PathWireV3::Direct { routing_token, .. } => {
                let mut object = serde_json::Map::new();
                common(&mut object)?;
                object.insert("routing_token".into(), Value::String(routing_token.clone()));
                (1, Value::Object(object))
            }
            PathWireV3::Tunnel {
                role,
                local_endpoint_instance_id,
                token,
                ..
            } => {
                let mut object = serde_json::Map::new();
                common(&mut object)?;
                object.insert("attach_token".into(), Value::String(token.clone()));
                object.insert(
                    "endpoint_instance_id".into(),
                    Value::String(local_endpoint_instance_id.clone()),
                );
                object.insert("role".into(), Value::from(*role));
                (2, Value::Object(object))
            }
        };
        let payload = jcs_value(&payload_value)?;
        if payload.is_empty() || payload.len() > MAX_FSB3_PAYLOAD_BYTES {
            return Err(ArtifactErrorV3::Invalid);
        }
        let mut raw = Vec::with_capacity(12 + payload.len());
        raw.extend_from_slice(b"FSB3");
        raw.extend_from_slice(&[3, path_code, 0, 0]);
        raw.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        raw.extend_from_slice(&payload);
        let mut preimage = b"flowersec-v3-admission\0".to_vec();
        preimage.extend_from_slice(&raw);
        Ok(EncodedFsb3 {
            raw,
            binding: Sha256::digest(preimage).into(),
            chosen_candidate_id: chosen_candidate_id.to_owned(),
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EncodedFsb3 {
    pub(crate) raw: Vec<u8>,
    pub(crate) binding: [u8; 32],
    chosen_candidate_id: String,
}

pub(crate) fn acceptor_admissions_hash(
    frames: &[EncodedFsb3],
) -> Result<[u8; 32], ArtifactErrorV3> {
    if frames.is_empty() || frames.len() > 4 {
        return Err(ArtifactErrorV3::Invalid);
    }
    let mut ordered = frames.iter().collect::<Vec<_>>();
    ordered
        .sort_unstable_by(|left, right| left.chosen_candidate_id.cmp(&right.chosen_candidate_id));
    if !ordered
        .windows(2)
        .all(|pair| pair[0].chosen_candidate_id < pair[1].chosen_candidate_id)
    {
        return Err(ArtifactErrorV3::Invalid);
    }
    let mut preimage = b"flowersec-v3-acceptor-admissions\0".to_vec();
    for frame in ordered {
        let length = u32::try_from(frame.raw.len()).map_err(|_| ArtifactErrorV3::Invalid)?;
        preimage.extend_from_slice(&length.to_be_bytes());
        preimage.extend_from_slice(&frame.raw);
    }
    Ok(Sha256::digest(preimage).into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionStatusV3 {
    Success,
    Reject,
    Retryable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionResponseV3 {
    pub(crate) status: AdmissionStatusV3,
    pub(crate) reason: String,
}

pub(crate) fn decode_fsa3(frame: &[u8]) -> Result<AdmissionResponseV3, ArtifactErrorV3> {
    if frame.len() < 8 || &frame[..4] != b"FSA3" || frame[4] != 3 {
        return Err(ArtifactErrorV3::Invalid);
    }
    let status = match frame[5] {
        0 => AdmissionStatusV3::Success,
        1 => AdmissionStatusV3::Reject,
        2 => AdmissionStatusV3::Retryable,
        _ => return Err(ArtifactErrorV3::Invalid),
    };
    let length = usize::from(u16::from_be_bytes([frame[6], frame[7]]));
    if length > 64 || frame.len() != 8 + length {
        return Err(ArtifactErrorV3::Invalid);
    }
    let reason = std::str::from_utf8(&frame[8..])
        .map_err(|_| ArtifactErrorV3::Invalid)?
        .to_owned();
    match status {
        AdmissionStatusV3::Success if !reason.is_empty() => return Err(ArtifactErrorV3::Invalid),
        AdmissionStatusV3::Reject | AdmissionStatusV3::Retryable
            if !valid_reason(&reason) || FORBIDDEN_FSA3_REASONS.contains(&reason.as_str()) =>
        {
            return Err(ArtifactErrorV3::Invalid);
        }
        _ => {}
    }
    Ok(AdmissionResponseV3 { status, reason })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactWireV3 {
    v: u8,
    profile: String,
    session: SessionWireV3,
    path: PathWireV3,
    scoped: Vec<ScopeWireV3>,
    correlation: CorrelationWireV3,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionWireV3 {
    channel_id: String,
    init_expire_at_unix_s: u64,
    idle_timeout_seconds: u64,
    establish_timeout_seconds: u64,
    rekey_prepare_timeout_seconds: u64,
    rekey_completion_timeout_seconds: u64,
    max_inbound_streams: u64,
    e2ee_psk_b64u: String,
    allowed_suites: Vec<u64>,
    default_suite: u64,
    selected_features: u64,
    contract_hash_b64u: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum PathWireV3 {
    Direct {
        rendezvous_group_id: String,
        listener_audience: String,
        routing_token: String,
        candidates: Vec<CandidateWireV3>,
    },
    Tunnel {
        rendezvous_group_id: String,
        listener_audience: String,
        role: u64,
        local_endpoint_instance_id: String,
        expected_peer_endpoint_instance_id: String,
        token: String,
        candidates: Vec<CandidateWireV3>,
    },
}

impl PathWireV3 {
    fn kind(&self) -> &'static str {
        match self {
            Self::Direct { .. } => "direct",
            Self::Tunnel { .. } => "tunnel",
        }
    }
    fn candidates(&self) -> &[CandidateWireV3] {
        match self {
            Self::Direct { candidates, .. } | Self::Tunnel { candidates, .. } => candidates,
        }
    }
    fn rendezvous_group_id(&self) -> &str {
        match self {
            Self::Direct {
                rendezvous_group_id,
                ..
            }
            | Self::Tunnel {
                rendezvous_group_id,
                ..
            } => rendezvous_group_id,
        }
    }
    fn listener_audience(&self) -> &str {
        match self {
            Self::Direct {
                listener_audience, ..
            }
            | Self::Tunnel {
                listener_audience, ..
            } => listener_audience,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateWireV3 {
    id: String,
    carrier: CarrierWireV3,
    url: String,
    wire_profile: String,
    tls: TlsPolicyWireV3,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CarrierWireV3 {
    Websocket,
    RawQuic,
    Webtransport,
}

impl CarrierWireV3 {
    fn as_str(self) -> &'static str {
        match self {
            Self::Websocket => "websocket",
            Self::RawQuic => "raw_quic",
            Self::Webtransport => "webtransport",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum TlsPolicyWireV3 {
    Ca {},
    Pin { pins: Vec<PinWireV3> },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PinWireV3 {
    pub(crate) algorithm: String,
    pub(crate) value_b64u: String,
    pub(crate) not_after_unix_s: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScopeWireV3 {
    scope: String,
    scope_version: u64,
    critical: bool,
    payload: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CorrelationWireV3 {
    v: u8,
    tags: Vec<CorrelationTagWireV3>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CorrelationTagWireV3 {
    key: String,
    value: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CanonicalCandidateV3 {
    pub(crate) carrier: CarrierWireV3,
    pub(crate) id: String,
    pub(crate) normalized_url: String,
    pub(crate) tls: TlsPolicyWireV3,
    pub(crate) wire_profile: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TunnelFsb3WireV3 {
    attach_token: String,
    candidate_set_hash_b64u: String,
    candidates: Vec<CanonicalCandidateV3>,
    channel_id: String,
    chosen_candidate_id: String,
    endpoint_instance_id: String,
    listener_audience: String,
    profile: String,
    rendezvous_group_id: String,
    role: u64,
    session_contract_hash_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectFsb3WireV3 {
    candidate_set_hash_b64u: String,
    candidates: Vec<CanonicalCandidateV3>,
    channel_id: String,
    chosen_candidate_id: String,
    listener_audience: String,
    profile: String,
    rendezvous_group_id: String,
    routing_token: String,
    session_contract_hash_b64u: String,
}

#[derive(Debug)]
pub(crate) struct DecodedTunnelFsb3V3 {
    pub(crate) attach_token: String,
    pub(crate) candidate_set_hash_b64u: String,
    pub(crate) channel_id: String,
    pub(crate) endpoint_instance_id: String,
    pub(crate) listener_audience: String,
    pub(crate) rendezvous_group_id: String,
    pub(crate) role: u8,
    pub(crate) session_contract_hash_b64u: String,
}

pub(crate) fn decode_direct_fsb3(raw: &[u8]) -> Result<(), ArtifactErrorV3> {
    let value = decode_fsb3_payload(raw, 1)?;
    let wire: DirectFsb3WireV3 =
        serde_json::from_value(value).map_err(|_| ArtifactErrorV3::Invalid)?;
    if wire.profile != "flowersec/3"
        || !valid_ascii(&wire.routing_token, 8192)
        || !valid_registry_id(&wire.channel_id, 128)
        || !valid_registry_id(&wire.listener_audience, 128)
        || !valid_registry_id(&wire.rendezvous_group_id, 128)
        || decode32(&wire.session_contract_hash_b64u).is_none()
    {
        return Err(ArtifactErrorV3::Invalid);
    }
    validate_fsb3_candidates(
        &wire.candidates,
        "direct",
        "flowersec-direct/3",
        &wire.candidate_set_hash_b64u,
        &wire.chosen_candidate_id,
    )?;
    Ok(())
}

pub(crate) fn decode_tunnel_fsb3(
    raw: &[u8],
    observed_carrier: CarrierWireV3,
) -> Result<DecodedTunnelFsb3V3, ArtifactErrorV3> {
    let value = decode_fsb3_payload(raw, 2)?;
    let wire: TunnelFsb3WireV3 =
        serde_json::from_value(value).map_err(|_| ArtifactErrorV3::Invalid)?;
    if wire.profile != "flowersec/3"
        || !matches!(wire.role, 1 | 2)
        || !valid_ascii(&wire.attach_token, 8192)
        || !valid_registry_id(&wire.channel_id, 128)
        || !valid_registry_id(&wire.endpoint_instance_id, 128)
        || !valid_registry_id(&wire.listener_audience, 128)
        || !valid_registry_id(&wire.rendezvous_group_id, 128)
        || decode32(&wire.session_contract_hash_b64u).is_none()
    {
        return Err(ArtifactErrorV3::Invalid);
    }

    let chosen = validate_fsb3_candidates(
        &wire.candidates,
        "tunnel",
        "flowersec-tunnel/3",
        &wire.candidate_set_hash_b64u,
        &wire.chosen_candidate_id,
    )?;
    if chosen.carrier != observed_carrier {
        return Err(ArtifactErrorV3::Invalid);
    }

    Ok(DecodedTunnelFsb3V3 {
        attach_token: wire.attach_token,
        candidate_set_hash_b64u: wire.candidate_set_hash_b64u,
        channel_id: wire.channel_id,
        endpoint_instance_id: wire.endpoint_instance_id,
        listener_audience: wire.listener_audience,
        rendezvous_group_id: wire.rendezvous_group_id,
        role: wire.role as u8,
        session_contract_hash_b64u: wire.session_contract_hash_b64u,
    })
}

fn decode_fsb3_payload(raw: &[u8], path_code: u8) -> Result<Value, ArtifactErrorV3> {
    if raw.len() < 12
        || &raw[..4] != b"FSB3"
        || raw[4] != 3
        || raw[5] != path_code
        || raw[6..8] != [0, 0]
    {
        return Err(ArtifactErrorV3::Invalid);
    }
    let payload_length = u32::from_be_bytes(
        raw[8..12]
            .try_into()
            .map_err(|_| ArtifactErrorV3::Invalid)?,
    ) as usize;
    if payload_length == 0
        || payload_length > MAX_FSB3_PAYLOAD_BYTES
        || raw.len() != 12 + payload_length
    {
        return Err(ArtifactErrorV3::Invalid);
    }
    let payload = &raw[12..];
    reject_duplicate_json_keys(payload)?;
    let value: Value = serde_json::from_slice(payload).map_err(|_| ArtifactErrorV3::Invalid)?;
    if jcs_value(&value)? != payload {
        return Err(ArtifactErrorV3::Invalid);
    }
    Ok(value)
}

fn validate_fsb3_candidates<'a>(
    candidates: &'a [CanonicalCandidateV3],
    path: &str,
    wire_profile: &str,
    candidate_set_hash_b64u: &str,
    chosen_candidate_id: &str,
) -> Result<&'a CanonicalCandidateV3, ArtifactErrorV3> {
    if !valid_candidate_id(chosen_candidate_id) || candidates.is_empty() || candidates.len() > 4 {
        return Err(ArtifactErrorV3::Invalid);
    }

    let mut endpoints = HashSet::new();
    for candidate in candidates {
        if !valid_candidate_id(&candidate.id)
            || candidate.wire_profile != wire_profile
            || normalize_url_v3(path, candidate.carrier, &candidate.normalized_url)?
                != candidate.normalized_url
        {
            return Err(ArtifactErrorV3::Invalid);
        }
        validate_tls_policy(&candidate.tls)?;
        if jcs_serialize(candidate)?.len() > MAX_CANDIDATE_BYTES {
            return Err(ArtifactErrorV3::Invalid);
        }
        let endpoint = format!(
            "{}\0{}\0{}",
            candidate.carrier.as_str(),
            path,
            candidate.normalized_url
        );
        if !endpoints.insert(endpoint) {
            return Err(ArtifactErrorV3::Invalid);
        }
    }
    if !candidates.windows(2).all(|pair| pair[0].id < pair[1].id) {
        return Err(ArtifactErrorV3::Invalid);
    }
    let candidate_set_json = jcs_serialize(candidates)?;
    if candidate_set_json.len() > MAX_CANDIDATE_SET_BYTES
        || decode32(candidate_set_hash_b64u)
            != Some(hash_lp(b"flowersec-v3-candidates\0", &candidate_set_json))
    {
        return Err(ArtifactErrorV3::Invalid);
    }
    candidates
        .iter()
        .find(|candidate| candidate.id == chosen_candidate_id)
        .ok_or(ArtifactErrorV3::Invalid)
}

pub(crate) struct ConnectionPlanV3 {
    pub(crate) candidates: Vec<CanonicalCandidateV3>,
    pub(crate) path: PathKind,
    pub(crate) role: SessionRole,
    pub(crate) local_endpoint_instance_id: Option<String>,
    pub(crate) expected_peer_endpoint_instance_id: Option<String>,
    pub(crate) expires_at_unix_seconds: u64,
    pub(crate) session: SessionParametersV3,
}

pub(crate) struct SessionParametersV3 {
    pub(crate) channel_id: String,
    pub(crate) session_contract_hash: [u8; 32],
    pub(crate) suite: CipherSuiteV3,
    pub(crate) psk: [u8; 32],
    pub(crate) max_inbound_streams: u16,
    pub(crate) idle_timeout: Duration,
    pub(crate) establish_timeout: Duration,
    pub(crate) rekey_prepare_timeout: Duration,
    pub(crate) rekey_completion_timeout: Duration,
}

impl CanonicalCandidateV3 {
    pub(crate) fn policy_digest(&self) -> Result<[u8; 32], ArtifactErrorV3> {
        Ok(hash_lp(
            b"flowersec-v3-tls-policy\0",
            &jcs_serialize(&self.tls)?,
        ))
    }

    pub(crate) fn active_pin_hashes(
        &self,
        attempt_now: u64,
    ) -> Result<Option<Vec<[u8; 32]>>, TransportSecurityFailureV3> {
        match &self.tls {
            TlsPolicyWireV3::Ca {} => Ok(None),
            TlsPolicyWireV3::Pin { pins } => {
                let active = pins
                    .iter()
                    .filter(|pin| attempt_now < pin.not_after_unix_s)
                    .map(|pin| {
                        decode32(&pin.value_b64u).ok_or(TransportSecurityFailureV3::InvalidArtifact)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if active.is_empty() {
                    Err(TransportSecurityFailureV3::PolicyExpired)
                } else {
                    Ok(Some(active))
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransportSecurityFailureV3 {
    InvalidArtifact,
    Unsupported,
    PolicyExpired,
    CaUntrusted,
    PinMismatch,
    UnknownTls,
}

fn validate_artifact(wire: &ArtifactWireV3) -> Result<Vec<CanonicalCandidateV3>, ArtifactErrorV3> {
    if wire.v != 3 || wire.profile != "flowersec/3" {
        return Err(ArtifactErrorV3::Invalid);
    }
    validate_session(&wire.session)?;
    if !valid_registry_id(wire.path.rendezvous_group_id(), 128)
        || !valid_registry_id(wire.path.listener_audience(), 128)
    {
        return Err(ArtifactErrorV3::Invalid);
    }
    match &wire.path {
        PathWireV3::Direct { routing_token, .. } if !valid_ascii(routing_token, 8192) => {
            return Err(ArtifactErrorV3::Invalid);
        }
        PathWireV3::Tunnel {
            role,
            local_endpoint_instance_id,
            expected_peer_endpoint_instance_id,
            token,
            ..
        } if !matches!(role, 1 | 2)
            || !valid_registry_id(local_endpoint_instance_id, 128)
            || !valid_registry_id(expected_peer_endpoint_instance_id, 128)
            || local_endpoint_instance_id == expected_peer_endpoint_instance_id
            || !valid_ascii(token, 8192) =>
        {
            return Err(ArtifactErrorV3::Invalid);
        }
        _ => {}
    }
    let candidates = validate_candidates(wire.path.kind(), wire.path.candidates())?;
    if wire.scoped.len() > 8 {
        return Err(ArtifactErrorV3::Invalid);
    }
    let mut scopes = HashSet::new();
    for scope in &wire.scoped {
        if !(1..=65535).contains(&scope.scope_version)
            || !valid_lower_id(&scope.scope, 64)
            || !scopes.insert(scope.scope.as_str())
        {
            return Err(ArtifactErrorV3::Invalid);
        }
        let payload = Value::Object(scope.payload.clone());
        if jcs_value(&payload)?.len() > 4096 {
            return Err(ArtifactErrorV3::Invalid);
        }
        let mut nodes = 0;
        validate_scoped_value(&payload, 1, &mut nodes, true)?;
    }
    if wire.correlation.v != 3 || wire.correlation.tags.len() > 8 {
        return Err(ArtifactErrorV3::Invalid);
    }
    let mut tags = HashSet::new();
    for tag in &wire.correlation.tags {
        if !valid_lower_id(&tag.key, 32)
            || !valid_ascii(&tag.value, 128)
            || !tags.insert(tag.key.as_str())
        {
            return Err(ArtifactErrorV3::Invalid);
        }
    }
    Ok(candidates)
}

fn validate_session(session: &SessionWireV3) -> Result<(), ArtifactErrorV3> {
    if !valid_registry_id(&session.channel_id, 128)
        || !(1..=MAX_SAFE_INTEGER).contains(&session.init_expire_at_unix_s)
        || session.idle_timeout_seconds > u64::from(u32::MAX)
        || session.establish_timeout_seconds != 30
        || session.rekey_prepare_timeout_seconds != 10
        || session.rekey_completion_timeout_seconds != 30
        || !(1..=128).contains(&session.max_inbound_streams)
        || session.selected_features != 0
        || decode32(&session.e2ee_psk_b64u).is_none()
        || decode32(&session.contract_hash_b64u).is_none()
        || session.allowed_suites.is_empty()
        || !session
            .allowed_suites
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || !session
            .allowed_suites
            .iter()
            .all(|value| matches!(value, 1 | 2))
        || !session.allowed_suites.contains(&session.default_suite)
    {
        return Err(ArtifactErrorV3::Invalid);
    }
    let projection = serde_json::json!({
        "allowed_suites": session.allowed_suites, "channel_id": session.channel_id,
        "default_suite": session.default_suite, "establish_timeout_seconds": session.establish_timeout_seconds,
        "idle_timeout_seconds": session.idle_timeout_seconds, "max_inbound_streams": session.max_inbound_streams,
        "profile": "flowersec/3", "rekey_completion_timeout_seconds": session.rekey_completion_timeout_seconds,
        "rekey_prepare_timeout_seconds": session.rekey_prepare_timeout_seconds, "selected_features": session.selected_features,
    });
    let expected = hash_lp(b"flowersec-v3-session-contract\0", &jcs_value(&projection)?);
    if decode32(&session.contract_hash_b64u) != Some(expected) {
        return Err(ArtifactErrorV3::Invalid);
    }
    Ok(())
}

fn validate_candidates(
    kind: &str,
    source: &[CandidateWireV3],
) -> Result<Vec<CanonicalCandidateV3>, ArtifactErrorV3> {
    if source.is_empty() || source.len() > 4 {
        return Err(ArtifactErrorV3::Invalid);
    }
    let mut ids = HashSet::new();
    let mut endpoints = HashSet::new();
    let mut candidates = Vec::with_capacity(source.len());
    for candidate in source {
        if !valid_candidate_id(&candidate.id)
            || !ids.insert(candidate.id.as_str())
            || candidate.wire_profile != format!("flowersec-{kind}/3")
        {
            return Err(ArtifactErrorV3::Invalid);
        }
        validate_tls_policy(&candidate.tls)?;
        let normalized_url = normalize_url_v3(kind, candidate.carrier, &candidate.url)?;
        let endpoint = format!("{}\0{kind}\0{normalized_url}", candidate.carrier.as_str());
        if !endpoints.insert(endpoint) {
            return Err(ArtifactErrorV3::Invalid);
        }
        let canonical = CanonicalCandidateV3 {
            carrier: candidate.carrier,
            id: candidate.id.clone(),
            normalized_url,
            tls: candidate.tls.clone(),
            wire_profile: candidate.wire_profile.clone(),
        };
        if jcs_serialize(&canonical)?.len() > MAX_CANDIDATE_BYTES {
            return Err(ArtifactErrorV3::Invalid);
        }
        candidates.push(canonical);
    }
    candidates.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    Ok(candidates)
}

fn validate_tls_policy(policy: &TlsPolicyWireV3) -> Result<(), ArtifactErrorV3> {
    let TlsPolicyWireV3::Pin { pins } = policy else {
        return Ok(());
    };
    if pins.is_empty() || pins.len() > 4 {
        return Err(ArtifactErrorV3::Invalid);
    }
    for pin in pins {
        if pin.algorithm != "sha-256"
            || !(1..=MAX_SAFE_INTEGER).contains(&pin.not_after_unix_s)
            || decode32(&pin.value_b64u).is_none()
        {
            return Err(ArtifactErrorV3::Invalid);
        }
    }
    if !pins.windows(2).all(|pair| {
        (pair[0].algorithm.as_str(), pair[0].value_b64u.as_str())
            < (pair[1].algorithm.as_str(), pair[1].value_b64u.as_str())
    }) {
        return Err(ArtifactErrorV3::Invalid);
    }
    Ok(())
}

fn validate_scoped_value(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
    root: bool,
) -> Result<(), ArtifactErrorV3> {
    if depth > 16 {
        return Err(ArtifactErrorV3::Invalid);
    }
    *nodes += 1;
    if *nodes > 256 {
        return Err(ArtifactErrorV3::Invalid);
    }
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(number) if is_safe_json_integer(number) => Ok(()),
        Value::String(value) if value.len() <= 1024 => Ok(()),
        Value::Array(values) if !root && values.len() <= 64 => values
            .iter()
            .try_for_each(|value| validate_scoped_value(value, depth + 1, nodes, false)),
        Value::Object(values) if values.len() <= 64 => {
            if values.keys().any(|key| key.len() > 128) {
                return Err(ArtifactErrorV3::Invalid);
            }
            values
                .values()
                .try_for_each(|value| validate_scoped_value(value, depth + 1, nodes, false))
        }
        _ => Err(ArtifactErrorV3::Invalid),
    }
}

pub(crate) fn normalize_url_v3(
    kind: &str,
    carrier: CarrierWireV3,
    raw: &str,
) -> Result<String, ArtifactErrorV3> {
    if raw.is_empty() || raw.len() > 2048 || raw.contains(['\\', '?', '#', '%']) {
        return Err(ArtifactErrorV3::Invalid);
    }
    let (scheme_raw, remainder) = raw.split_once("://").ok_or(ArtifactErrorV3::Invalid)?;
    if scheme_raw.is_empty()
        || !scheme_raw.as_bytes()[0].is_ascii_alphabetic()
        || !scheme_raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
    {
        return Err(ArtifactErrorV3::Invalid);
    }
    let scheme = scheme_raw.to_ascii_lowercase();
    let (authority, path) = remainder.find('/').map_or((remainder, ""), |index| {
        (&remainder[..index], &remainder[index..])
    });
    if authority.is_empty() || authority.contains('@') {
        return Err(ArtifactErrorV3::Invalid);
    }
    let (host, port) = normalize_authority(authority)?;
    let expected = match carrier {
        CarrierWireV3::Websocket if scheme == "wss" => format!("/flowersec/v3/{kind}"),
        CarrierWireV3::RawQuic if scheme == "quic" && matches!(path, "" | "/") => String::new(),
        CarrierWireV3::Webtransport if scheme == "https" => {
            format!("/flowersec/webtransport/v3/{kind}")
        }
        _ => return Err(ArtifactErrorV3::Invalid),
    };
    if !matches!(carrier, CarrierWireV3::RawQuic) && path != expected {
        return Err(ArtifactErrorV3::Invalid);
    }
    let normalized = format!(
        "{scheme}://{host}{}{expected}",
        port.map(|value| format!(":{value}")).unwrap_or_default()
    );
    if normalized.len() > 2048 {
        return Err(ArtifactErrorV3::Invalid);
    }
    Ok(normalized)
}

fn normalize_authority(authority: &str) -> Result<(String, Option<u16>), ArtifactErrorV3> {
    let (host, port_text) = if let Some(after_open) = authority.strip_prefix('[') {
        let close = after_open.find(']').ok_or(ArtifactErrorV3::Invalid)?;
        let address = &after_open[..close];
        if address.contains('.') || address.is_empty() {
            return Err(ArtifactErrorV3::Invalid);
        }
        let tail = &after_open[close + 1..];
        let port = if tail.is_empty() {
            None
        } else {
            Some(tail.strip_prefix(':').ok_or(ArtifactErrorV3::Invalid)?)
        };
        let parsed: Ipv6Addr = address.parse().map_err(|_| ArtifactErrorV3::Invalid)?;
        (format!("[{parsed}]"), port)
    } else {
        if authority.matches(':').count() > 1 {
            return Err(ArtifactErrorV3::Invalid);
        }
        let (raw_host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)));
        if raw_host.is_empty() {
            return Err(ArtifactErrorV3::Invalid);
        }
        let host = if raw_host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            normalize_ipv4(raw_host)?
        } else {
            let ascii =
                crate::idna_v3::lookup_ascii(raw_host).map_err(|_| ArtifactErrorV3::Invalid)?;
            let last = ascii.rsplit('.').next().ok_or(ArtifactErrorV3::Invalid)?;
            let lower = last.to_ascii_lowercase();
            if lower.bytes().all(|b| b.is_ascii_digit())
                || lower
                    .strip_prefix("0x")
                    .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err(ArtifactErrorV3::Invalid);
            }
            ascii
        };
        (host, port)
    };
    let port = match port_text {
        None => None,
        Some(value) if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
            let parsed: u32 = value.parse().map_err(|_| ArtifactErrorV3::Invalid)?;
            if !(1..=65535).contains(&parsed) {
                return Err(ArtifactErrorV3::Invalid);
            }
            (parsed != 443).then_some(parsed as u16)
        }
        _ => return Err(ArtifactErrorV3::Invalid),
    };
    Ok((host, port))
}

fn normalize_ipv4(value: &str) -> Result<String, ArtifactErrorV3> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 4 {
        return Err(ArtifactErrorV3::Invalid);
    }
    let mut normalized = Vec::with_capacity(4);
    for part in parts {
        if part.is_empty() || part.len() > 1 && part.starts_with('0') {
            return Err(ArtifactErrorV3::Invalid);
        }
        let octet: u8 = part.parse().map_err(|_| ArtifactErrorV3::Invalid)?;
        normalized.push(octet.to_string());
    }
    Ok(normalized.join("."))
}

pub(crate) fn decode32(value: &str) -> Option<[u8; 32]> {
    if value.contains('=') {
        return None;
    }
    let decoded: [u8; 32] = URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()?;
    (URL_SAFE_NO_PAD.encode(decoded) == value).then_some(decoded)
}

fn valid_registry_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b))
}
fn valid_lower_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}
fn valid_candidate_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}
fn valid_ascii(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.is_ascii()
}
fn valid_reason(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

pub(crate) fn hash_lp(domain: &[u8], canonical: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(domain.len() + 4 + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&(canonical.len() as u32).to_be_bytes());
    preimage.extend_from_slice(canonical);
    Sha256::digest(preimage).into()
}

pub(crate) fn jcs_serialize<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, ArtifactErrorV3> {
    let value = serde_json::to_value(value).map_err(|_| ArtifactErrorV3::Invalid)?;
    jcs_value(&value)
}

pub(crate) fn jcs_value(value: &Value) -> Result<Vec<u8>, ArtifactErrorV3> {
    fn encode(value: &Value, output: &mut Vec<u8>) -> Result<(), ArtifactErrorV3> {
        match value {
            Value::Null => output.extend_from_slice(b"null"),
            Value::Bool(true) => output.extend_from_slice(b"true"),
            Value::Bool(false) => output.extend_from_slice(b"false"),
            Value::Number(number) => {
                if !is_safe_json_integer(number) {
                    return Err(ArtifactErrorV3::Invalid);
                }
                output.extend_from_slice(number.to_string().as_bytes());
            }
            Value::String(value) => output.extend_from_slice(
                serde_json::to_string(value)
                    .map_err(|_| ArtifactErrorV3::Invalid)?
                    .as_bytes(),
            ),
            Value::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    encode(value, output)?;
                }
                output.push(b']');
            }
            Value::Object(values) => {
                let mut entries = values.iter().collect::<Vec<_>>();
                entries
                    .sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
                output.push(b'{');
                for (index, (key, value)) in entries.into_iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    output.extend_from_slice(
                        serde_json::to_string(key)
                            .map_err(|_| ArtifactErrorV3::Invalid)?
                            .as_bytes(),
                    );
                    output.push(b':');
                    encode(value, output)?;
                }
                output.push(b'}');
            }
        }
        Ok(())
    }
    let mut output = Vec::new();
    encode(value, &mut output)?;
    Ok(output)
}

fn is_safe_json_integer(number: &serde_json::Number) -> bool {
    number
        .as_i64()
        .is_some_and(|value| (-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&value))
        || number
            .as_u64()
            .is_some_and(|value| value <= MAX_SAFE_INTEGER)
}

pub(crate) fn reject_duplicate_json_keys(input: &[u8]) -> Result<(), ArtifactErrorV3> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    DuplicateKeySeedV3
        .deserialize(&mut deserializer)
        .map_err(|_| ArtifactErrorV3::Invalid)?;
    deserializer.end().map_err(|_| ArtifactErrorV3::Invalid)
}

fn preflight_artifact_json(input: &[u8]) -> Result<(), ArtifactErrorV3> {
    reject_negative_zero_tokens(input)?;
    reject_duplicate_json_keys(input)?;
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    ArtifactScopedPreflightSeedV3
        .deserialize(&mut deserializer)
        .map_err(|_| ArtifactErrorV3::Invalid)?;
    deserializer.end().map_err(|_| ArtifactErrorV3::Invalid)
}

fn reject_negative_zero_tokens(input: &[u8]) -> Result<(), ArtifactErrorV3> {
    let mut in_string = false;
    let mut escaped = false;
    for index in 0..input.len() {
        let byte = input[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        if byte == b'"' {
            in_string = true;
            continue;
        }
        if byte == b'-' && input.get(index + 1) == Some(&b'0') {
            let tail = input.get(index + 2).copied();
            if tail.is_none_or(|value| {
                matches!(value, b',' | b'}' | b']' | b' ' | b'\n' | b'\r' | b'\t')
            }) {
                return Err(ArtifactErrorV3::Invalid);
            }
        }
    }
    Ok(())
}

struct ArtifactScopedPreflightSeedV3;
impl<'de> DeserializeSeed<'de> for ArtifactScopedPreflightSeedV3 {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(ArtifactScopedPreflightVisitorV3)
    }
}

struct ArtifactScopedPreflightVisitorV3;
impl<'de> Visitor<'de> for ArtifactScopedPreflightVisitorV3 {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a Flowersec v3 artifact object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if key == "scoped" {
                map.next_value_seed(ScopedArrayPreflightSeedV3)?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct ScopedArrayPreflightSeedV3;
impl<'de> DeserializeSeed<'de> for ScopedArrayPreflightSeedV3 {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(ScopedArrayPreflightVisitorV3)
    }
}

struct ScopedArrayPreflightVisitorV3;
impl<'de> Visitor<'de> for ScopedArrayPreflightVisitorV3 {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an array of Flowersec v3 scoped entries")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        while sequence
            .next_element_seed(ScopedEntryPreflightSeedV3)?
            .is_some()
        {}
        Ok(())
    }
}

struct ScopedEntryPreflightSeedV3;
impl<'de> DeserializeSeed<'de> for ScopedEntryPreflightSeedV3 {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(ScopedEntryPreflightVisitorV3)
    }
}

struct ScopedEntryPreflightVisitorV3;
impl<'de> Visitor<'de> for ScopedEntryPreflightVisitorV3 {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a Flowersec v3 scoped entry object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if key == "payload" {
                let nodes = std::cell::Cell::new(0);
                map.next_value_seed(ScopedValuePreflightSeedV3 {
                    depth: 1,
                    nodes: &nodes,
                    root: true,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct ScopedValuePreflightSeedV3<'a> {
    depth: usize,
    nodes: &'a std::cell::Cell<usize>,
    root: bool,
}

impl<'de> DeserializeSeed<'de> for ScopedValuePreflightSeedV3<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        if self.depth > 16 || self.nodes.get() >= 256 {
            return Err(serde::de::Error::custom(
                "scoped payload exceeds depth or node limit",
            ));
        }
        self.nodes.set(self.nodes.get() + 1);
        deserializer.deserialize_any(ScopedValuePreflightVisitorV3 {
            depth: self.depth,
            nodes: self.nodes,
            root: self.root,
        })
    }
}

struct ScopedValuePreflightVisitorV3<'a> {
    depth: usize,
    nodes: &'a std::cell::Cell<usize>,
    root: bool,
}

impl<'de> Visitor<'de> for ScopedValuePreflightVisitorV3<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded Flowersec v3 scoped payload value")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut members = 0;
        while let Some(key) = map.next_key::<String>()? {
            members += 1;
            if members > 64 || key.len() > 128 {
                return Err(serde::de::Error::custom(
                    "scoped payload object exceeds member or key limit",
                ));
            }
            map.next_value_seed(ScopedValuePreflightSeedV3 {
                depth: self.depth + 1,
                nodes: self.nodes,
                root: false,
            })?;
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        if self.root {
            return Err(serde::de::Error::custom(
                "scoped payload root must be an object",
            ));
        }
        let mut elements = 0;
        while elements < 64 {
            if sequence
                .next_element_seed(ScopedValuePreflightSeedV3 {
                    depth: self.depth + 1,
                    nodes: self.nodes,
                    root: false,
                })?
                .is_none()
            {
                return Ok(());
            }
            elements += 1;
        }
        // Probe only with IgnoredAny after the bounded prefix. This detects a
        // 65th element without recursively entering its value or consuming
        // scoped node/depth budget for rejected input.
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom(
                "scoped payload array exceeds element limit",
            ));
        }
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<(), E> {
        if (-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&value) {
            Ok(())
        } else {
            Err(E::custom("scoped payload integer exceeds safe range"))
        }
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<(), E> {
        if value <= MAX_SAFE_INTEGER {
            Ok(())
        } else {
            Err(E::custom("scoped payload integer exceeds safe range"))
        }
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<(), E> {
        let _ = value;
        Err(E::custom(
            "scoped payload number is not a canonical integer",
        ))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<(), E> {
        if value.len() <= 1024 {
            Ok(())
        } else {
            Err(E::custom("scoped payload string exceeds byte limit"))
        }
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<(), E> {
        self.visit_str(&value)
    }

    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
}

struct DuplicateKeySeedV3;
impl<'de> DeserializeSeed<'de> for DuplicateKeySeedV3 {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(DuplicateKeyVisitorV3)
    }
}
struct DuplicateKeyVisitorV3;
impl<'de> Visitor<'de> for DuplicateKeyVisitorV3 {
    type Value = ();
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate object key"));
            }
            map.next_value_seed(DuplicateKeySeedV3)?;
        }
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(DuplicateKeySeedV3)?.is_some() {}
        Ok(())
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E>(self, _: String) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        DuplicateKeySeedV3.deserialize(deserializer)
    }
}

type LeaseFutureV3 =
    Pin<Box<dyn Future<Output = Result<(), ArtifactSpendErrorV3>> + Send + 'static>>;
type LeaseCallbackV3 = Box<dyn FnOnce() -> LeaseFutureV3 + Send>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ArtifactSpendErrorV3 {
    #[error("artifact lease transition is no longer available")]
    Unavailable,
    #[error("artifact spend commit failed")]
    CommitFailed,
}

#[derive(Clone)]
pub struct ArtifactLeaseV3 {
    artifact: ArtifactV3,
    shared: Arc<LeaseStateV3>,
    controller_capability: Option<Arc<AtomicBool>>,
}
impl std::fmt::Debug for ArtifactLeaseV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ArtifactLeaseV3 { <opaque> }")
    }
}
struct LeaseStateV3 {
    state: AtomicU8,
    spend: Mutex<Option<LeaseCallbackV3>>,
    retire: Mutex<Option<LeaseCallbackV3>>,
}

impl ArtifactLeaseV3 {
    pub fn new<F, Fut>(artifact: ArtifactV3, spend: F) -> Self
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), ArtifactSpendErrorV3>> + Send + 'static,
    {
        Self::new_with_retire(artifact, spend, || async { Ok(()) })
    }
    pub fn new_with_retire<F, Fut, R, RFut>(artifact: ArtifactV3, spend: F, retire: R) -> Self
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), ArtifactSpendErrorV3>> + Send + 'static,
        R: FnOnce() -> RFut + Send + 'static,
        RFut: Future<Output = Result<(), ArtifactSpendErrorV3>> + Send + 'static,
    {
        Self {
            artifact,
            shared: Arc::new(LeaseStateV3 {
                state: AtomicU8::new(0),
                spend: Mutex::new(Some(Box::new(move || Box::pin(spend())))),
                retire: Mutex::new(Some(Box::new(move || Box::pin(retire())))),
            }),
            controller_capability: None,
        }
    }

    pub(crate) fn artifact_for_connector(&self) -> &ArtifactV3 {
        &self.artifact
    }

    pub(crate) fn claim_for_controller(
        &self,
    ) -> Result<ClaimedArtifactLeaseV3, ArtifactSpendErrorV3> {
        self.shared
            .state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ArtifactSpendErrorV3::Unavailable)?;
        Ok(ClaimedArtifactLeaseV3 {
            artifact: self.artifact.clone(),
            shared: self.shared.clone(),
            controller_capability: Some(Arc::new(AtomicBool::new(false))),
        })
    }

    pub(crate) fn claim(&self) -> Result<ClaimedArtifactLeaseV3, ArtifactSpendErrorV3> {
        if let Some(capability) = &self.controller_capability {
            capability
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| ArtifactSpendErrorV3::Unavailable)?;
            if self.shared.state.load(Ordering::Acquire) != 1 {
                return Err(ArtifactSpendErrorV3::Unavailable);
            }
        } else {
            self.shared
                .state
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| ArtifactSpendErrorV3::Unavailable)?;
        }
        Ok(ClaimedArtifactLeaseV3 {
            artifact: self.artifact.clone(),
            shared: self.shared.clone(),
            controller_capability: None,
        })
    }
}

pub(crate) struct ClaimedArtifactLeaseV3 {
    artifact: ArtifactV3,
    shared: Arc<LeaseStateV3>,
    controller_capability: Option<Arc<AtomicBool>>,
}
impl ClaimedArtifactLeaseV3 {
    pub(crate) fn artifact(&self) -> &ArtifactV3 {
        &self.artifact
    }
    pub(crate) fn connector_lease_with_artifact(&self, artifact: ArtifactV3) -> ArtifactLeaseV3 {
        let controller_capability = self
            .controller_capability
            .as_ref()
            .expect("only a controller-owned claim can create a connector lease")
            .clone();
        ArtifactLeaseV3 {
            artifact,
            shared: self.shared.clone(),
            controller_capability: Some(controller_capability),
        }
    }
    pub(crate) fn is_consumed(&self) -> bool {
        self.shared.state.load(Ordering::Acquire) == 3
    }
    pub(crate) async fn commit_spend(
        self,
    ) -> Result<ConsumedArtifactLeaseV3, ArtifactSpendErrorV3> {
        self.shared
            .state
            .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ArtifactSpendErrorV3::Unavailable)?;
        let callback = self
            .shared
            .spend
            .lock()
            .map_err(|_| ArtifactSpendErrorV3::CommitFailed)?
            .take()
            .ok_or(ArtifactSpendErrorV3::Unavailable)?;
        let result = callback().await;
        self.shared.state.store(3, Ordering::Release);
        result.map(|_| ConsumedArtifactLeaseV3 {
            _shared: self.shared,
        })
    }
    pub(crate) async fn retire(self) -> Result<(), ArtifactSpendErrorV3> {
        self.shared
            .state
            .compare_exchange(1, 4, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ArtifactSpendErrorV3::Unavailable)?;
        let callback = self
            .shared
            .retire
            .lock()
            .map_err(|_| ArtifactSpendErrorV3::CommitFailed)?
            .take();
        match callback {
            Some(callback) => callback().await,
            None => Ok(()),
        }
    }
}
pub(crate) struct ConsumedArtifactLeaseV3 {
    _shared: Arc<LeaseStateV3>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::sync::atomic::AtomicUsize;

    #[derive(Deserialize)]
    struct ArtifactVectorsV3 {
        positive: Vec<PositiveArtifactVectorV3>,
        negative: Vec<NegativeArtifactVectorV3>,
        scalar_boundaries: Vec<ArtifactBoundaryVectorV3>,
        scoped_payload_boundaries: Vec<ArtifactBoundaryVectorV3>,
        artifact_byte_negative: Vec<FrameNegativeVectorV3>,
        fsb3_negative: Vec<FrameNegativeVectorV3>,
        fsa3_negative: Vec<FrameNegativeVectorV3>,
        active_pin_snapshots: Vec<ActivePinSnapshotVectorV3>,
        fsa3: Vec<FsaVectorV3>,
    }

    #[derive(Deserialize)]
    struct PositiveArtifactVectorV3 {
        id: String,
        artifact_json: String,
        session_canonical_json: String,
        session_contract_hash_b64u: String,
        candidates_canonical_json: String,
        candidate_set_hash_b64u: String,
        tls_policy_digests: Vec<TlsPolicyDigestVectorV3>,
        winners: Vec<WinnerVectorV3>,
        acceptor_admissions_hash_hex: String,
    }

    #[derive(Deserialize)]
    struct TlsPolicyDigestVectorV3 {
        candidate_id: String,
        digest_hex: String,
    }

    #[derive(Deserialize)]
    struct WinnerVectorV3 {
        candidate_id: String,
        fsb3_hex: String,
        admission_binding_hex: String,
    }

    #[derive(Deserialize)]
    struct NegativeArtifactVectorV3 {
        id: String,
        kind: String,
        value: String,
    }

    #[derive(Deserialize)]
    struct ArtifactBoundaryVectorV3 {
        id: String,
        accepted: bool,
        artifact_json: String,
    }

    #[derive(Deserialize)]
    struct FrameNegativeVectorV3 {
        id: String,
        value_hex: String,
        error_code: String,
    }

    #[derive(Deserialize)]
    struct ActivePinSnapshotVectorV3 {
        id: String,
        attempt_now: u64,
        declared: TlsPolicyWireV3,
        active_value_b64u: Vec<String>,
        result: String,
    }

    #[derive(Deserialize)]
    struct FsaVectorV3 {
        id: String,
        status: u8,
        reason: String,
        frame_hex: String,
    }

    fn artifact_vectors() -> ArtifactVectorsV3 {
        serde_json::from_str(include_str!(
            "../../testdata/transport_v3/artifact_vectors.json"
        ))
        .expect("parse shared Flowersec v3 artifact vectors")
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert!(value.len().is_multiple_of(2));
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("ASCII hex");
                u8::from_str_radix(text, 16).expect("valid hex")
            })
            .collect()
    }

    fn encode_tunnel_fsb3_payload(value: &Value) -> Vec<u8> {
        let payload = jcs_value(value).unwrap();
        let mut raw = Vec::with_capacity(12 + payload.len());
        raw.extend_from_slice(b"FSB3\x03\x02\0\0");
        raw.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        raw.extend_from_slice(&payload);
        raw
    }

    fn recompute_candidate_set_hash(value: &mut Value) {
        let canonical = jcs_value(&value["candidates"]).unwrap();
        value["candidate_set_hash_b64u"] = Value::String(
            URL_SAFE_NO_PAD.encode(hash_lp(b"flowersec-v3-candidates\0", &canonical)),
        );
    }

    fn tunnel_fsb3_vector() -> Vec<u8> {
        let vectors = artifact_vectors();
        let vector = vectors
            .positive
            .into_iter()
            .find(|vector| vector.id == "tunnel-mixed-security")
            .expect("shared tunnel artifact vector");
        decode_hex(
            &vector
                .winners
                .into_iter()
                .find(|winner| winner.candidate_id == "q-pin")
                .expect("shared raw QUIC winner")
                .fsb3_hex,
        )
    }

    fn valid_artifact() -> Vec<u8> {
        let projection = serde_json::json!({"allowed_suites":[1],"channel_id":"channel","default_suite":1,"establish_timeout_seconds":30,"idle_timeout_seconds":0,"max_inbound_streams":1,"profile":"flowersec/3","rekey_completion_timeout_seconds":30,"rekey_prepare_timeout_seconds":10,"selected_features":0});
        let contract = URL_SAFE_NO_PAD.encode(hash_lp(
            b"flowersec-v3-session-contract\0",
            &jcs_value(&projection).unwrap(),
        ));
        let value = serde_json::json!({"correlation":{"tags":[],"v":3},"path":{"candidates":[{"carrier":"websocket","id":"a","tls":{"mode":"ca"},"url":"wss://example.com:0443/flowersec/v3/direct","wire_profile":"flowersec-direct/3"}],"kind":"direct","listener_audience":"listener","rendezvous_group_id":"group","routing_token":"token"},"profile":"flowersec/3","scoped":[],"session":{"allowed_suites":[1],"channel_id":"channel","contract_hash_b64u":contract,"default_suite":1,"e2ee_psk_b64u":URL_SAFE_NO_PAD.encode([7u8;32]),"establish_timeout_seconds":30,"idle_timeout_seconds":0,"init_expire_at_unix_s":9999999999u64,"max_inbound_streams":1,"rekey_completion_timeout_seconds":30,"rekey_prepare_timeout_seconds":10,"selected_features":0},"v":3});
        jcs_value(&value).unwrap()
    }

    fn scoped_preflight_input(payload: &str) -> Vec<u8> {
        format!(r#"{{"scoped":[{{"payload":{payload}}}]}}"#).into_bytes()
    }

    #[test]
    fn parses_strict_artifact_and_binds_tls_into_fsb3() {
        let encoded_artifact = valid_artifact();
        let artifact = ArtifactV3::parse(&encoded_artifact).unwrap();
        assert_eq!(artifact.encode().as_ref(), encoded_artifact);
        assert_eq!(artifact.expires_at_unix_seconds(), 9_999_999_999);
        assert_eq!(
            artifact.canonical_candidates()[0].normalized_url,
            "wss://example.com/flowersec/v3/direct"
        );
        let frame = artifact.encode_fsb3("a").unwrap();
        assert_eq!(&frame.raw[..5], b"FSB3\x03");
        assert_eq!(
            frame.binding,
            Sha256::digest([b"flowersec-v3-admission\0".as_slice(), frame.raw.as_slice()].concat())
                [..]
        );
        assert_ne!(artifact.candidate_set_hash(), [0; 32]);
        assert_ne!(acceptor_admissions_hash(&[frame]).unwrap(), [0; 32]);

        let success = decode_fsa3(b"FSA3\x03\x00\x00\x00").unwrap();
        assert_eq!(success.status, AdmissionStatusV3::Success);
        let retryable = decode_fsa3(b"FSA3\x03\x02\x00\x10expired_artifact").unwrap();
        assert_eq!(retryable.status, AdmissionStatusV3::Retryable);
        assert_eq!(retryable.reason, "expired_artifact");
        assert!(decode_fsa3(b"FSA3\x03\x01\x00\x081invalid").is_err());
        assert!(decode_fsa3(b"FSA3\x03\x01\x00\x08_invalid").is_err());
        assert!(decode_fsa3(b"FSA3\x03\x01\x00\x10tls_pin_mismatch").is_err());
    }

    #[test]
    fn version_isolation_admission_frames_reject_v2_mutations() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../testdata/transport_v3/version_isolation_vectors.json"
        ))
        .unwrap();
        for frame in fixture["frames"].as_array().unwrap() {
            let id = frame["id"].as_str().unwrap();
            if id == "fsb3" || id == "fsa3" {
                let valid = decode_hex(frame["v3_hex"].as_str().unwrap());
                let magic = decode_hex(frame["v2_magic_hex"].as_str().unwrap());
                let version = decode_hex(frame["v2_version_hex"].as_str().unwrap());
                if id == "fsb3" {
                    decode_direct_fsb3(&valid).unwrap();
                    assert!(decode_direct_fsb3(&magic).is_err());
                    assert!(decode_direct_fsb3(&version).is_err());
                } else {
                    decode_fsa3(&valid).unwrap();
                    assert!(decode_fsa3(&magic).is_err());
                    assert!(decode_fsa3(&version).is_err());
                }
            }
        }
    }

    #[test]
    fn tunnel_fsb3_decoder_revalidates_the_complete_candidate_projection() {
        let raw = tunnel_fsb3_vector();
        let decoded = decode_tunnel_fsb3(&raw, CarrierWireV3::RawQuic).unwrap();
        assert_eq!(decoded.attach_token, "attach-token-v3");
        assert_eq!(decoded.channel_id, "channel-3");
        assert_eq!(decoded.endpoint_instance_id, "endpoint-client");
        assert_eq!(decoded.role, 1);
        assert!(decode_tunnel_fsb3(&raw, CarrierWireV3::Websocket).is_err());

        let base: Value = serde_json::from_slice(&raw[12..]).unwrap();
        let mut invalid_payloads = Vec::new();

        let mut unknown_candidate_field = base.clone();
        unknown_candidate_field["candidates"][0]["unexpected"] = Value::Bool(true);
        recompute_candidate_set_hash(&mut unknown_candidate_field);
        invalid_payloads.push(("candidate schema", unknown_candidate_field));

        let mut hash_mismatch = base.clone();
        hash_mismatch["candidate_set_hash_b64u"] =
            Value::String(URL_SAFE_NO_PAD.encode([0x5a; 32]));
        invalid_payloads.push(("candidate set hash", hash_mismatch));

        let mut unsorted = base.clone();
        unsorted["candidates"].as_array_mut().unwrap().swap(0, 1);
        recompute_candidate_set_hash(&mut unsorted);
        invalid_payloads.push(("candidate order", unsorted));

        let mut invalid_tls = base.clone();
        invalid_tls["candidates"][0]["tls"]["pins"][0]["algorithm"] =
            Value::String("sha-512".into());
        recompute_candidate_set_hash(&mut invalid_tls);
        invalid_payloads.push(("TLS policy", invalid_tls));

        let mut unnormalized_url = base.clone();
        unnormalized_url["candidates"][0]["normalized_url"] =
            Value::String("QUIC://[2001:db8::1]".into());
        recompute_candidate_set_hash(&mut unnormalized_url);
        invalid_payloads.push(("normalized URL", unnormalized_url));

        let mut duplicate_endpoint = base;
        duplicate_endpoint["candidates"][1]["carrier"] =
            duplicate_endpoint["candidates"][0]["carrier"].clone();
        duplicate_endpoint["candidates"][1]["normalized_url"] =
            duplicate_endpoint["candidates"][0]["normalized_url"].clone();
        recompute_candidate_set_hash(&mut duplicate_endpoint);
        invalid_payloads.push(("endpoint uniqueness", duplicate_endpoint));

        for (case, payload) in invalid_payloads {
            assert!(
                decode_tunnel_fsb3(
                    &encode_tunnel_fsb3_payload(&payload),
                    CarrierWireV3::RawQuic
                )
                .is_err(),
                "accepted invalid {case}"
            );
        }
    }

    #[test]
    fn rejects_noncanonical_unknown_and_legacy_inputs() {
        let canonical = valid_artifact();
        let spaced = [b" ".as_slice(), canonical.as_slice()].concat();
        assert_eq!(
            ArtifactV3::parse(spaced).unwrap_err(),
            ArtifactErrorV3::Invalid
        );
        let legacy = String::from_utf8(canonical)
            .unwrap()
            .replace("flowersec/3", "flowersec/2");
        assert_eq!(
            ArtifactV3::parse(legacy).unwrap_err(),
            ArtifactErrorV3::Invalid
        );
    }

    #[test]
    fn artifact_preflight_rejects_scoped_payload_allocation_boundaries() {
        let too_deep = format!(r#"{{"value":{}null{}}}"#, "[".repeat(15), "]".repeat(15));
        let too_many_nodes = format!(
            r#"{{"a":[{}],"b":[{}],"c":[{}],"d":[{}]}}"#,
            ["null"; 64].join(","),
            ["null"; 64].join(","),
            ["null"; 64].join(","),
            ["null"; 64].join(",")
        );
        let too_many_members = format!(
            "{{{}}}",
            (0..65)
                .map(|index| format!(r#""k{index}":null"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        let mut array_elements = vec!["null".to_string(); 64];
        array_elements.push(format!("{}null{}", "[".repeat(64), "]".repeat(64)));
        let too_many_elements = format!(r#"{{"value":[{}]}}"#, array_elements.join(","));
        let oversized_key = format!(r#"{{"{}":null}}"#, "k".repeat(129));
        let oversized_string = format!(r#"{{"value":"{}"}}"#, "x".repeat(1025));

        for payload in [
            too_deep,
            too_many_nodes,
            too_many_members,
            too_many_elements,
            oversized_key,
            oversized_string,
        ] {
            assert_eq!(
                preflight_artifact_json(&scoped_preflight_input(&payload)),
                Err(ArtifactErrorV3::Invalid)
            );
        }
    }

    #[test]
    fn artifact_preflight_rejects_escaped_nested_duplicate_keys() {
        let input = scoped_preflight_input(r#"{"nested":{"mode":"ca","m\u006fde":"pin"}}"#);
        assert_eq!(
            preflight_artifact_json(&input),
            Err(ArtifactErrorV3::Invalid)
        );
    }

    #[test]
    fn pin_policy_uses_declared_set_for_digest_and_active_snapshot_for_attempt() {
        let first = URL_SAFE_NO_PAD.encode([1u8; 32]);
        let second = URL_SAFE_NO_PAD.encode([2u8; 32]);
        let policy = TlsPolicyWireV3::Pin {
            pins: vec![
                PinWireV3 {
                    algorithm: "sha-256".into(),
                    value_b64u: first,
                    not_after_unix_s: 10,
                },
                PinWireV3 {
                    algorithm: "sha-256".into(),
                    value_b64u: second,
                    not_after_unix_s: 20,
                },
            ],
        };
        validate_tls_policy(&policy).unwrap();
        let candidate = CanonicalCandidateV3 {
            carrier: CarrierWireV3::Websocket,
            id: "a".into(),
            normalized_url: "wss://example.com/flowersec/v3/direct".into(),
            tls: policy,
            wire_profile: "flowersec-direct/3".into(),
        };
        assert_eq!(
            candidate.active_pin_hashes(10).unwrap().unwrap(),
            vec![[2; 32]]
        );
        assert_eq!(
            candidate.active_pin_hashes(20),
            Err(TransportSecurityFailureV3::PolicyExpired)
        );
        assert_ne!(candidate.policy_digest().unwrap(), [0; 32]);
    }

    #[tokio::test]
    async fn copied_lease_has_one_atomic_owner_and_terminal_states() {
        let artifact = ArtifactV3::parse(valid_artifact()).unwrap();
        let spends = Arc::new(AtomicUsize::new(0));
        let capture = spends.clone();
        let lease = ArtifactLeaseV3::new(artifact, move || async move {
            capture.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let copy = lease.clone();
        let claimed = lease.claim().unwrap();
        assert!(matches!(
            copy.claim(),
            Err(ArtifactSpendErrorV3::Unavailable)
        ));
        claimed.commit_spend().await.unwrap();
        assert_eq!(spends.load(Ordering::SeqCst), 1);
        assert!(matches!(
            copy.claim(),
            Err(ArtifactSpendErrorV3::Unavailable)
        ));

        let artifact = ArtifactV3::parse(valid_artifact()).unwrap();
        let retires = Arc::new(AtomicUsize::new(0));
        let capture = retires.clone();
        let lease = ArtifactLeaseV3::new_with_retire(
            artifact,
            || async { Ok(()) },
            move || async move {
                capture.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );
        let claimed = lease.claim().unwrap();
        assert_eq!(claimed.artifact().expires_at_unix_seconds(), 9_999_999_999);
        claimed.retire().await.unwrap();
        assert_eq!(retires.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn controller_claim_is_the_shared_one_shot_owner() {
        let artifact = ArtifactV3::parse(valid_artifact()).unwrap();
        let spends = Arc::new(AtomicUsize::new(0));
        let capture = spends.clone();
        let lease = ArtifactLeaseV3::new(artifact, move || async move {
            capture.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let one_shot_copy = lease.clone();
        let controller_claim = lease.claim_for_controller().unwrap();

        assert!(matches!(
            one_shot_copy.claim(),
            Err(ArtifactSpendErrorV3::Unavailable)
        ));
        let connector_lease =
            controller_claim.connector_lease_with_artifact(controller_claim.artifact().clone());
        let connector_copy = connector_lease.clone();
        let connector_claim = connector_lease.claim().unwrap();
        assert!(matches!(
            connector_copy.claim(),
            Err(ArtifactSpendErrorV3::Unavailable)
        ));
        connector_claim.commit_spend().await.unwrap();
        assert_eq!(spends.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn controller_and_one_shot_claims_have_exactly_one_concurrent_winner() {
        let artifact = ArtifactV3::parse(valid_artifact()).unwrap();
        let lease = ArtifactLeaseV3::new(artifact, || async { Ok(()) });
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let controller_lease = lease.clone();
        let controller_barrier = barrier.clone();
        let controller = std::thread::spawn(move || {
            controller_barrier.wait();
            controller_lease.claim_for_controller()
        });
        let one_shot_barrier = barrier.clone();
        let one_shot = std::thread::spawn(move || {
            one_shot_barrier.wait();
            lease.claim()
        });
        barrier.wait();
        let controller = controller.join().unwrap();
        let one_shot = one_shot.join().unwrap();

        assert_ne!(controller.is_ok(), one_shot.is_ok());
        if let Ok(claimed) = controller {
            claimed.retire().await.unwrap();
        }
        if let Ok(claimed) = one_shot {
            claimed.retire().await.unwrap();
        }
    }

    #[test]
    fn internal_security_failures_keep_the_fixed_registry() {
        assert_eq!(
            [
                TransportSecurityFailureV3::Unsupported,
                TransportSecurityFailureV3::CaUntrusted,
                TransportSecurityFailureV3::PinMismatch,
                TransportSecurityFailureV3::UnknownTls,
            ]
            .len(),
            4
        );
    }

    #[test]
    fn url_normalization_rejects_legacy_numeric_hosts_and_plaintext() {
        assert_eq!(
            normalize_url_v3(
                "direct",
                CarrierWireV3::Websocket,
                "wss://127.0.0.1:443/flowersec/v3/direct"
            )
            .unwrap(),
            "wss://127.0.0.1/flowersec/v3/direct"
        );
        for value in [
            "ws://127.0.0.1/flowersec/v3/direct",
            "wss://127.1/flowersec/v3/direct",
            "wss://example.1/flowersec/v3/direct",
            "wss://example.0x/flowersec/v3/direct",
        ] {
            assert!(
                normalize_url_v3("direct", CarrierWireV3::Websocket, value).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn shared_artifact_vectors_freeze_canonicalization_and_admission_bytes() {
        let vectors = artifact_vectors();
        assert!(!vectors.positive.is_empty());
        for vector in vectors.positive {
            let artifact = ArtifactV3::parse(vector.artifact_json.as_bytes())
                .unwrap_or_else(|error| panic!("{}: {error:?}", vector.id));
            assert_eq!(
                artifact.encode().as_ref(),
                vector.artifact_json.as_bytes(),
                "{} artifact canonical JSON",
                vector.id
            );
            let session = &artifact.0.wire.session;
            let session_projection = serde_json::json!({
                "allowed_suites": session.allowed_suites,
                "channel_id": session.channel_id,
                "default_suite": session.default_suite,
                "establish_timeout_seconds": session.establish_timeout_seconds,
                "idle_timeout_seconds": session.idle_timeout_seconds,
                "max_inbound_streams": session.max_inbound_streams,
                "profile": "flowersec/3",
                "rekey_completion_timeout_seconds": session.rekey_completion_timeout_seconds,
                "rekey_prepare_timeout_seconds": session.rekey_prepare_timeout_seconds,
                "selected_features": session.selected_features,
            });
            let session_canonical = jcs_value(&session_projection).unwrap();
            assert_eq!(
                session_canonical,
                vector.session_canonical_json.as_bytes(),
                "{} session canonical JSON",
                vector.id
            );
            assert_eq!(
                URL_SAFE_NO_PAD.encode(hash_lp(
                    b"flowersec-v3-session-contract\0",
                    &session_canonical,
                )),
                vector.session_contract_hash_b64u,
                "{} session contract hash",
                vector.id
            );
            assert_eq!(
                artifact.0.candidate_set_json.as_ref(),
                vector.candidates_canonical_json.as_bytes(),
                "{} candidate set canonical JSON",
                vector.id
            );
            assert_eq!(
                URL_SAFE_NO_PAD.encode(artifact.candidate_set_hash()),
                vector.candidate_set_hash_b64u,
                "{} candidate set hash",
                vector.id
            );
            for digest in vector.tls_policy_digests {
                let candidate = artifact
                    .canonical_candidates()
                    .iter()
                    .find(|candidate| candidate.id == digest.candidate_id)
                    .unwrap_or_else(|| panic!("{} missing {}", vector.id, digest.candidate_id));
                assert_eq!(
                    candidate.policy_digest().unwrap().as_slice(),
                    decode_hex(&digest.digest_hex),
                    "{} {} TLS policy digest",
                    vector.id,
                    digest.candidate_id
                );
            }
            let mut admissions = Vec::new();
            for winner in vector.winners {
                let admission = artifact.encode_fsb3(&winner.candidate_id).unwrap();
                assert_eq!(
                    admission.raw,
                    decode_hex(&winner.fsb3_hex),
                    "{} {} FSB3",
                    vector.id,
                    winner.candidate_id
                );
                assert_eq!(
                    admission.binding.as_slice(),
                    decode_hex(&winner.admission_binding_hex),
                    "{} {} admission binding",
                    vector.id,
                    winner.candidate_id
                );
                admissions.push(admission);
            }
            assert_eq!(
                acceptor_admissions_hash(&admissions).unwrap().as_slice(),
                decode_hex(&vector.acceptor_admissions_hash_hex),
                "{} acceptor admissions hash",
                vector.id
            );
        }
        for vector in vectors.active_pin_snapshots {
            let candidate = CanonicalCandidateV3 {
                carrier: CarrierWireV3::Websocket,
                id: "snapshot".into(),
                normalized_url: "wss://example.com/flowersec/v3/direct".into(),
                tls: vector.declared,
                wire_profile: "flowersec-direct/3".into(),
            };
            match vector.result.as_str() {
                "attempt" => {
                    let active = candidate
                        .active_pin_hashes(vector.attempt_now)
                        .unwrap_or_else(|error| panic!("{}: {error:?}", vector.id))
                        .expect("pin snapshot policy");
                    assert_eq!(
                        active
                            .iter()
                            .map(|value| URL_SAFE_NO_PAD.encode(value))
                            .collect::<Vec<_>>(),
                        vector.active_value_b64u,
                        "{} active pin snapshot",
                        vector.id
                    );
                }
                "tls_policy_expired" => assert_eq!(
                    candidate.active_pin_hashes(vector.attempt_now),
                    Err(TransportSecurityFailureV3::PolicyExpired),
                    "{} expired pin snapshot",
                    vector.id
                ),
                other => panic!("{} unknown snapshot result {other}", vector.id),
            }
        }
    }

    #[test]
    fn shared_artifact_negative_and_fsa3_vectors_are_enforced() {
        let vectors = artifact_vectors();
        let mut negative_ids = HashSet::new();
        for vector in vectors.negative {
            negative_ids.insert(vector.id.clone());
            assert_eq!(vector.kind, "artifact_json", "{} vector kind", vector.id);
            assert_eq!(
                ArtifactV3::parse(vector.value).unwrap_err(),
                ArtifactErrorV3::Invalid,
                "{}",
                vector.id
            );
        }
        assert!(negative_ids.contains("scope-payload-positive-safe-integer-overflow"));
        assert!(negative_ids.contains("scope-payload-negative-safe-integer-overflow"));
        for vector in vectors
            .scalar_boundaries
            .into_iter()
            .chain(vectors.scoped_payload_boundaries)
        {
            let parsed = ArtifactV3::parse(vector.artifact_json.as_bytes());
            if vector.accepted {
                let artifact = parsed.unwrap_or_else(|error| panic!("{}: {error:?}", vector.id));
                assert_eq!(
                    artifact.encode().as_ref(),
                    vector.artifact_json.as_bytes(),
                    "{}",
                    vector.id
                );
            } else {
                assert!(parsed.is_err(), "{} unexpectedly accepted", vector.id);
            }
        }
        for vector in vectors.artifact_byte_negative {
            let _ = &vector.error_code;
            assert!(
                ArtifactV3::parse(decode_hex(&vector.value_hex)).is_err(),
                "{} unexpectedly accepted",
                vector.id
            );
        }
        for vector in vectors.fsb3_negative {
            let _ = &vector.error_code;
            let raw = decode_hex(&vector.value_hex);
            let rejected = match raw.get(5) {
                Some(1) => decode_direct_fsb3(&raw).is_err(),
                Some(2) => decode_tunnel_fsb3(&raw, CarrierWireV3::RawQuic).is_err(),
                _ => {
                    decode_direct_fsb3(&raw).is_err()
                        && decode_tunnel_fsb3(&raw, CarrierWireV3::RawQuic).is_err()
                }
            };
            assert!(rejected, "{} unexpectedly accepted", vector.id);
        }
        for vector in vectors.fsa3_negative {
            let _ = &vector.error_code;
            assert!(
                decode_fsa3(&decode_hex(&vector.value_hex)).is_err(),
                "{} unexpectedly accepted",
                vector.id
            );
        }
        for vector in vectors.fsa3 {
            let decoded = decode_fsa3(&decode_hex(&vector.frame_hex))
                .unwrap_or_else(|error| panic!("{}: {error:?}", vector.id));
            let expected_status = match vector.status {
                0 => AdmissionStatusV3::Success,
                1 => AdmissionStatusV3::Reject,
                2 => AdmissionStatusV3::Retryable,
                status => panic!("{} unexpected status {status}", vector.id),
            };
            assert_eq!(decoded.status, expected_status, "{}", vector.id);
            assert_eq!(decoded.reason, vector.reason, "{}", vector.id);
        }
    }
}
