//! Opaque server-side artifact issuance and runtime authorization.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::Artifact;

const DEFAULT_ARTIFACT_LIFETIME: Duration = Duration::from_secs(60);
const MAX_ARTIFACT_LIFETIME: Duration = Duration::from_secs(300);
const MAX_RECORD_BYTES: usize = 96 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ControlPlaneError {
    #[error("invalid Flowersec control-plane input")]
    InvalidInput,
    #[error("Flowersec artifact issuance failed")]
    IssuanceFailed,
    #[error("Flowersec authorization request is expired")]
    Expired,
}

#[derive(Clone, Debug)]
pub struct SessionOptions {
    pub channel_id: String,
    pub expires_at: Option<SystemTime>,
    pub idle_timeout: Duration,
    pub max_inbound_streams: u16,
}

impl SessionOptions {
    pub fn new(channel_id: impl Into<String>) -> Self {
        Self {
            channel_id: channel_id.into(),
            expires_at: None,
            idle_timeout: Duration::from_secs(60),
            max_inbound_streams: 32,
        }
    }
}

#[derive(Clone)]
pub struct EndpointSet {
    urls: Arc<[String]>,
}

impl fmt::Debug for EndpointSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EndpointSet { <opaque> }")
    }
}

impl EndpointSet {
    pub fn new<I, S>(urls: I) -> Result<Self, ControlPlaneError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let urls = urls.into_iter().map(Into::into).collect::<Vec<_>>();
        if urls.is_empty()
            || urls.len() > 4
            || urls.iter().any(|url| url.is_empty() || url.trim() != url)
        {
            return Err(ControlPlaneError::InvalidInput);
        }
        for url in &urls {
            let scheme = url
                .split_once("://")
                .map(|(scheme, _)| scheme.to_ascii_lowercase());
            if !matches!(scheme.as_deref(), Some("ws" | "wss" | "quic" | "https")) {
                return Err(ControlPlaneError::InvalidInput);
            }
        }
        Ok(Self { urls: urls.into() })
    }
}

#[derive(Clone)]
pub struct DirectIssueOptions {
    pub session: SessionOptions,
    pub endpoints: EndpointSet,
    pub rendezvous_group_id: String,
    pub listener_audience: String,
    pub upstream_address: String,
}

impl fmt::Debug for DirectIssueOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DirectIssueOptions { <opaque> }")
    }
}

#[derive(Clone)]
pub struct TunnelIssueOptions {
    pub session: SessionOptions,
    pub endpoints: EndpointSet,
    pub rendezvous_group_id: String,
    pub listener_audience: String,
    pub first_endpoint_id: String,
    pub second_endpoint_id: String,
    pub allow_replacement: bool,
}

impl fmt::Debug for TunnelIssueOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TunnelIssueOptions { <opaque> }")
    }
}

pub struct Issuer {}

impl fmt::Debug for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Issuer { <opaque> }")
    }
}

impl Issuer {
    pub fn new() -> Self {
        Self {}
    }

    pub fn issue_direct(
        &self,
        options: DirectIssueOptions,
    ) -> Result<IssuedArtifact, ControlPlaneError> {
        if !valid_id(&options.session.channel_id, 128)
            || !valid_id(&options.rendezvous_group_id, 128)
            || !valid_id(&options.listener_audience, 128)
            || !valid_tcp_address(&options.upstream_address)
        {
            return Err(ControlPlaneError::InvalidInput);
        }
        let upstream = options.upstream_address;
        let session = self.build_session(&options.session)?;
        let artifact_json = self.build_artifact(
            &session,
            &options.endpoints,
            &options.rendezvous_group_id,
            &options.listener_audience,
            PathInput::Direct,
        )?;
        IssuedArtifact::from_json(artifact_json, false, Some(upstream))
    }

    pub fn issue_tunnel_pair(
        &self,
        options: TunnelIssueOptions,
    ) -> Result<IssuedTunnelPair, ControlPlaneError> {
        if !valid_id(&options.session.channel_id, 128)
            || !valid_id(&options.rendezvous_group_id, 128)
            || !valid_id(&options.listener_audience, 128)
            || !valid_id(&options.first_endpoint_id, 128)
            || !valid_id(&options.second_endpoint_id, 128)
            || options.first_endpoint_id == options.second_endpoint_id
        {
            return Err(ControlPlaneError::InvalidInput);
        }
        let session = self.build_session(&options.session)?;
        let first = self.build_artifact(
            &session,
            &options.endpoints,
            &options.rendezvous_group_id,
            &options.listener_audience,
            PathInput::Tunnel {
                role: 1,
                local: options.first_endpoint_id.clone(),
                peer: options.second_endpoint_id.clone(),
                token: self.credential()?,
            },
        )?;
        let second = self.build_artifact(
            &session,
            &options.endpoints,
            &options.rendezvous_group_id,
            &options.listener_audience,
            PathInput::Tunnel {
                role: 2,
                local: options.second_endpoint_id,
                peer: options.first_endpoint_id,
                token: self.credential()?,
            },
        )?;
        Ok(IssuedTunnelPair {
            first: IssuedArtifact::from_json(first, options.allow_replacement, None)?,
            second: IssuedArtifact::from_json(second, options.allow_replacement, None)?,
        })
    }

    fn credential(&self) -> Result<String, ControlPlaneError> {
        let mut bytes = [0_u8; 32];
        rand::fill(&mut bytes);
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    fn build_session(&self, session: &SessionOptions) -> Result<Value, ControlPlaneError> {
        let now = SystemTime::now();
        let expiry = session
            .expires_at
            .unwrap_or(now + DEFAULT_ARTIFACT_LIFETIME);
        if expiry <= now
            || expiry > now + MAX_ARTIFACT_LIFETIME
            || session.idle_timeout.is_zero()
            || session.idle_timeout.as_secs() > u32::MAX as u64
            || !(1..=128).contains(&session.max_inbound_streams)
        {
            return Err(ControlPlaneError::InvalidInput);
        }
        let mut psk = [0_u8; 32];
        rand::fill(&mut psk);
        let contract = json!({"allowed_suites":[1,2],"channel_id":session.channel_id,"default_suite":1,"establish_timeout_seconds":30,"idle_timeout_seconds":session.idle_timeout.as_secs(),"max_inbound_streams":session.max_inbound_streams,"profile":"flowersec/2","rekey_completion_timeout_seconds":30,"rekey_prepare_timeout_seconds":10,"selected_features":0});
        let bytes = serde_json::to_vec(&contract).map_err(|_| ControlPlaneError::IssuanceFailed)?;
        let mut preimage = b"flowersec-v2-session-contract\0".to_vec();
        preimage.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        preimage.extend_from_slice(&bytes);
        let hash = Sha256::digest(preimage);
        Ok(
            json!({"channel_id":session.channel_id,"init_expire_at_unix_s":expiry.duration_since(UNIX_EPOCH).map_err(|_| ControlPlaneError::InvalidInput)?.as_secs(),"idle_timeout_seconds":session.idle_timeout.as_secs(),"establish_timeout_seconds":30,"rekey_prepare_timeout_seconds":10,"rekey_completion_timeout_seconds":30,"max_inbound_streams":session.max_inbound_streams,"e2ee_psk_b64u":URL_SAFE_NO_PAD.encode(psk),"allowed_suites":[1,2],"default_suite":1,"selected_features":0,"contract_hash_b64u":URL_SAFE_NO_PAD.encode(hash)}),
        )
    }

    fn build_artifact(
        &self,
        session: &Value,
        endpoints: &EndpointSet,
        group: &str,
        audience: &str,
        path: PathInput,
    ) -> Result<Vec<u8>, ControlPlaneError> {
        let candidates = endpoints
            .urls
            .iter()
            .enumerate()
            .map(|(index, url)| candidate_json(url, index, matches!(&path, PathInput::Direct)))
            .collect::<Result<Vec<_>, _>>()?;
        let path = match path {
            PathInput::Direct => {
                json!({"kind":"direct","rendezvous_group_id":group,"listener_audience":audience,"routing_token":self.credential()?,"candidates":candidates})
            }
            PathInput::Tunnel {
                role,
                local,
                peer,
                token,
            } => {
                json!({"kind":"tunnel","rendezvous_group_id":group,"listener_audience":audience,"role":role,"local_endpoint_instance_id":local,"expected_peer_endpoint_instance_id":peer,"token":token,"candidates":candidates})
            }
        };
        let value = json!({"v":2,"profile":"flowersec/2","session":session,"path":path,"scoped":[],"correlation":{"v":2,"tags":[]}});
        let encoded = serde_json::to_vec(&value).map_err(|_| ControlPlaneError::IssuanceFailed)?;
        Artifact::parse(&encoded).map_err(|_| ControlPlaneError::InvalidInput)?;
        Ok(encoded)
    }
}

impl Default for Issuer {
    fn default() -> Self {
        Self::new()
    }
}

enum PathInput {
    Direct,
    Tunnel {
        role: u8,
        local: String,
        peer: String,
        token: String,
    },
}

fn candidate_json(url: &str, index: usize, direct: bool) -> Result<Value, ControlPlaneError> {
    let (scheme, _) = url
        .split_once("://")
        .ok_or(ControlPlaneError::InvalidInput)?;
    let (carrier, id) = match scheme.to_ascii_lowercase().as_str() {
        "ws" | "wss" => (
            "websocket",
            format!(
                "websocket{}",
                if index == 0 {
                    String::new()
                } else {
                    format!("-{}", index + 1)
                }
            ),
        ),
        "quic" => (
            "raw_quic",
            format!(
                "raw-quic{}",
                if index == 0 {
                    String::new()
                } else {
                    format!("-{}", index + 1)
                }
            ),
        ),
        "https" => (
            "webtransport",
            format!(
                "webtransport{}",
                if index == 0 {
                    String::new()
                } else {
                    format!("-{}", index + 1)
                }
            ),
        ),
        _ => return Err(ControlPlaneError::InvalidInput),
    };
    let mut normalized = url::Url::parse(url).map_err(|_| ControlPlaneError::InvalidInput)?;
    if !matches!(scheme.to_ascii_lowercase().as_str(), "quic") {
        let path = if scheme.eq_ignore_ascii_case("https") {
            format!(
                "/flowersec/webtransport/v2/{}",
                if direct { "direct" } else { "tunnel" }
            )
        } else {
            format!("/flowersec/v2/{}", if direct { "direct" } else { "tunnel" })
        };
        normalized.set_path(&path);
    }
    let normalized = normalized.to_string().trim_end_matches('/').to_owned();
    let wire_profile = if direct {
        "flowersec-direct/2"
    } else {
        "flowersec-tunnel/2"
    };
    Ok(json!({"id":id,"carrier":carrier,"url":normalized,"wire_profile":wire_profile}))
}

fn valid_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b))
}
fn valid_lower_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}
fn valid_tcp_address(value: &str) -> bool {
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    !host.is_empty() && port.parse::<u16>().is_ok_and(|port| port != 0)
}

#[derive(Clone)]
pub struct IssuedArtifact {
    artifact_json: Arc<[u8]>,
    record: AuthorizationRecord,
}
impl fmt::Debug for IssuedArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuedArtifact { <opaque> }")
    }
}
impl IssuedArtifact {
    fn from_json(
        artifact_json: Vec<u8>,
        allow_replacement: bool,
        upstream: Option<String>,
    ) -> Result<Self, ControlPlaneError> {
        let artifact =
            Artifact::parse(&artifact_json).map_err(|_| ControlPlaneError::InvalidInput)?;
        let value: Value =
            serde_json::from_slice(&artifact_json).map_err(|_| ControlPlaneError::InvalidInput)?;
        let path = value.get("path").ok_or(ControlPlaneError::InvalidInput)?;
        let credential = path
            .get("routing_token")
            .or_else(|| path.get("token"))
            .and_then(Value::as_str)
            .ok_or(ControlPlaneError::InvalidInput)?;
        let lookup_key = URL_SAFE_NO_PAD.encode(Sha256::digest(credential.as_bytes()));
        if (path.get("kind").and_then(Value::as_str) == Some("direct")) != upstream.is_some()
            || (path.get("kind").and_then(Value::as_str) == Some("direct") && allow_replacement)
        {
            return Err(ControlPlaneError::InvalidInput);
        }
        let shared: Arc<[u8]> = artifact_json.into();
        Ok(Self {
            artifact_json: shared.clone(),
            record: AuthorizationRecord {
                artifact_json: shared,
                lookup_key,
                direct_upstream: upstream,
                allow_replacement,
                artifact,
            },
        })
    }
    pub fn artifact_json(&self) -> Vec<u8> {
        self.artifact_json.to_vec()
    }
    pub fn authorization_record(&self) -> AuthorizationRecord {
        self.record.clone()
    }
    pub fn lookup_key(&self) -> &str {
        self.record.lookup_key()
    }
    pub fn runtime_authorization_request(
        &self,
        carrier: &str,
        remote_address: &str,
    ) -> Result<RuntimeAuthorizationRequest, ControlPlaneError> {
        let value: Value = serde_json::from_slice(&self.artifact_json)
            .map_err(|_| ControlPlaneError::InvalidInput)?;
        let candidate = value["path"]["candidates"]
            .as_array()
            .and_then(|candidates| {
                candidates.iter().find(|candidate| {
                    candidate["carrier"]
                        .as_str()
                        .is_some_and(|value| value == carrier)
                })
            })
            .ok_or(ControlPlaneError::InvalidInput)?;
        let candidate_id = candidate["id"]
            .as_str()
            .ok_or(ControlPlaneError::InvalidInput)?;
        let artifact =
            Artifact::parse(&self.artifact_json).map_err(|_| ControlPlaneError::InvalidInput)?;
        let encoded = artifact
            .encode_fsb2(candidate_id)
            .map_err(|_| ControlPlaneError::InvalidInput)?;
        let body = json!({"fsb2_base64url":URL_SAFE_NO_PAD.encode(encoded.raw),"carrier":carrier,"remote_address":remote_address});
        RuntimeAuthorizationRequest::parse(
            &serde_json::to_vec(&body).map_err(|_| ControlPlaneError::IssuanceFailed)?,
        )
    }
}

#[derive(Clone)]
pub struct IssuedTunnelPair {
    first: IssuedArtifact,
    second: IssuedArtifact,
}
impl fmt::Debug for IssuedTunnelPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuedTunnelPair { <opaque> }")
    }
}
impl IssuedTunnelPair {
    pub fn first(&self) -> &IssuedArtifact {
        &self.first
    }
    pub fn second(&self) -> &IssuedArtifact {
        &self.second
    }
}

#[derive(Clone)]
pub struct AuthorizationRecord {
    artifact_json: Arc<[u8]>,
    lookup_key: String,
    direct_upstream: Option<String>,
    allow_replacement: bool,
    artifact: Artifact,
}
impl fmt::Debug for AuthorizationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizationRecord { <opaque> }")
    }
}
impl AuthorizationRecord {
    pub fn lookup_key(&self) -> &str {
        &self.lookup_key
    }
    pub fn encode(&self) -> Result<Vec<u8>, ControlPlaneError> {
        let wire = json!({"schema_version":1,"artifact_base64url":URL_SAFE_NO_PAD.encode(&*self.artifact_json),"lookup_key":self.lookup_key,"direct_upstream":self.direct_upstream,"allow_replacement":self.allow_replacement});
        serde_json::to_vec(&wire).map_err(|_| ControlPlaneError::IssuanceFailed)
    }
    pub fn parse(encoded: &[u8]) -> Result<Self, ControlPlaneError> {
        if encoded.is_empty() || encoded.len() > MAX_RECORD_BYTES {
            return Err(ControlPlaneError::InvalidInput);
        }
        let value: Value =
            serde_json::from_slice(encoded).map_err(|_| ControlPlaneError::InvalidInput)?;
        let object = value.as_object().ok_or(ControlPlaneError::InvalidInput)?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "schema_version"
                    | "artifact_base64url"
                    | "lookup_key"
                    | "direct_upstream"
                    | "allow_replacement"
            )
        }) || object.get("schema_version").and_then(Value::as_u64) != Some(1)
        {
            return Err(ControlPlaneError::InvalidInput);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(
                object
                    .get("artifact_base64url")
                    .and_then(Value::as_str)
                    .ok_or(ControlPlaneError::InvalidInput)?,
            )
            .map_err(|_| ControlPlaneError::InvalidInput)?;
        let artifact = Artifact::parse(&raw).map_err(|_| ControlPlaneError::InvalidInput)?;
        let value: Value =
            serde_json::from_slice(&raw).map_err(|_| ControlPlaneError::InvalidInput)?;
        let path = value.get("path").ok_or(ControlPlaneError::InvalidInput)?;
        let credential = path
            .get("routing_token")
            .or_else(|| path.get("token"))
            .and_then(Value::as_str)
            .ok_or(ControlPlaneError::InvalidInput)?;
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(credential.as_bytes()));
        let lookup = object
            .get("lookup_key")
            .and_then(Value::as_str)
            .ok_or(ControlPlaneError::InvalidInput)?;
        if expected != lookup {
            return Err(ControlPlaneError::InvalidInput);
        }
        let direct = path.get("kind").and_then(Value::as_str) == Some("direct");
        let upstream = object
            .get("direct_upstream")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let allow = object
            .get("allow_replacement")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if direct != upstream.is_some() || (direct && allow) {
            return Err(ControlPlaneError::InvalidInput);
        }
        Ok(Self {
            artifact_json: raw.into(),
            lookup_key: lookup.into(),
            direct_upstream: upstream,
            allow_replacement: allow,
            artifact,
        })
    }
}

#[derive(Clone)]
pub struct RuntimeAuthorizationRequest {
    raw: Arc<[u8]>,
    lookup_key: String,
    chosen_candidate_id: String,
    carrier: String,
    remote_address: String,
}
impl fmt::Debug for RuntimeAuthorizationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuntimeAuthorizationRequest { <opaque> }")
    }
}
impl RuntimeAuthorizationRequest {
    pub fn parse(encoded: &[u8]) -> Result<Self, ControlPlaneError> {
        if encoded.is_empty() || encoded.len() > 64 * 1024 {
            return Err(ControlPlaneError::InvalidInput);
        }
        let value: Value =
            serde_json::from_slice(encoded).map_err(|_| ControlPlaneError::InvalidInput)?;
        let object = value.as_object().ok_or(ControlPlaneError::InvalidInput)?;
        if object.len() != 3
            || object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "fsb2_base64url" | "carrier" | "remote_address"
                )
            })
        {
            return Err(ControlPlaneError::InvalidInput);
        }
        let carrier = object
            .get("carrier")
            .and_then(Value::as_str)
            .filter(|value| matches!(*value, "websocket" | "raw_quic" | "webtransport"))
            .ok_or(ControlPlaneError::InvalidInput)?;
        let remote = object
            .get("remote_address")
            .and_then(Value::as_str)
            .ok_or(ControlPlaneError::InvalidInput)?;
        if remote.is_empty()
            || remote.len() > 512
            || remote.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(ControlPlaneError::InvalidInput);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(
                object
                    .get("fsb2_base64url")
                    .and_then(Value::as_str)
                    .ok_or(ControlPlaneError::InvalidInput)?,
            )
            .map_err(|_| ControlPlaneError::InvalidInput)?;
        if raw.len() < 12
            || &raw[..4] != b"FSB2"
            || raw[4] != 2
            || !matches!(raw[5], 1 | 2)
            || raw[6] != 0
            || raw[7] != 0
        {
            return Err(ControlPlaneError::InvalidInput);
        }
        let len = u32::from_be_bytes(
            raw[8..12]
                .try_into()
                .map_err(|_| ControlPlaneError::InvalidInput)?,
        ) as usize;
        if len == 0 || len != raw.len() - 12 {
            return Err(ControlPlaneError::InvalidInput);
        }
        let payload: Value =
            serde_json::from_slice(&raw[12..]).map_err(|_| ControlPlaneError::InvalidInput)?;
        let chosen = payload
            .get("chosen_candidate_id")
            .and_then(Value::as_str)
            .filter(|value| valid_lower_id(value, 64))
            .ok_or(ControlPlaneError::InvalidInput)?;
        let candidates = payload
            .get("candidates")
            .and_then(Value::as_array)
            .filter(|items| !items.is_empty() && items.len() <= 4)
            .ok_or(ControlPlaneError::InvalidInput)?;
        let carrier_matches = candidates.iter().any(|candidate| {
            candidate.get("id").and_then(Value::as_str) == Some(chosen)
                && candidate.get("carrier").and_then(Value::as_str) == Some(carrier)
        });
        if !carrier_matches {
            return Err(ControlPlaneError::InvalidInput);
        }
        let credential = match raw[5] {
            1 => payload.get("routing_token"),
            2 => payload.get("attach_token"),
            _ => None,
        }
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(ControlPlaneError::InvalidInput)?;
        Ok(Self {
            raw: raw.into(),
            lookup_key: URL_SAFE_NO_PAD.encode(Sha256::digest(credential.as_bytes())),
            chosen_candidate_id: chosen.into(),
            carrier: carrier.into(),
            remote_address: remote.into(),
        })
    }
    pub fn lookup_key(&self) -> &str {
        &self.lookup_key
    }

    pub fn carrier(&self) -> &str {
        &self.carrier
    }

    pub fn remote_address(&self) -> &str {
        &self.remote_address
    }

    pub fn authorize(
        &self,
        record: &AuthorizationRecord,
        lease_id: &str,
    ) -> Result<RuntimeAuthorizationResponse, ControlPlaneError> {
        if !valid_id(lease_id, 128)
            || subtle::ConstantTimeEq::ct_eq(
                self.lookup_key.as_bytes(),
                record.lookup_key.as_bytes(),
            )
            .unwrap_u8()
                != 1
        {
            return Err(ControlPlaneError::InvalidInput);
        }
        let artifact_value: Value = serde_json::from_slice(&record.artifact_json)
            .map_err(|_| ControlPlaneError::InvalidInput)?;
        let expiry = artifact_value["session"]["init_expire_at_unix_s"]
            .as_i64()
            .ok_or(ControlPlaneError::InvalidInput)?;
        if SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ControlPlaneError::InvalidInput)?
            .as_secs()
            >= expiry as u64
        {
            return Err(ControlPlaneError::Expired);
        }
        let encoded = record
            .artifact
            .encode_fsb2(&self.chosen_candidate_id)
            .map_err(|_| ControlPlaneError::InvalidInput)?;
        if encoded.raw.len() != self.raw.len()
            || subtle::ConstantTimeEq::ct_eq(encoded.raw.as_slice(), self.raw.as_ref()).unwrap_u8()
                != 1
        {
            return Err(ControlPlaneError::InvalidInput);
        }
        let session = runtime_session(&artifact_value)?;
        let mut response = json!({"decision":"allow","credential_id":record.lookup_key,"lease_id":lease_id,"expires_at":format_rfc3339(expiry)?});
        if artifact_value["path"]["kind"].as_str() != Some("direct") {
            return Err(ControlPlaneError::InvalidInput);
        }
        response["direct"] = json!({"session":session,"upstream":{"network":"tcp","address":record.direct_upstream.as_deref().ok_or(ControlPlaneError::InvalidInput)?}});
        Ok(RuntimeAuthorizationResponse {
            encoded: serde_json::to_vec(&response)
                .map_err(|_| ControlPlaneError::IssuanceFailed)?
                .into(),
        })
    }

    pub fn authorize_tunnel(
        &self,
        record: &AuthorizationRecord,
        lease_id: &str,
    ) -> Result<TunnelAuthorizationResponse, ControlPlaneError> {
        if !valid_id(lease_id, 128)
            || subtle::ConstantTimeEq::ct_eq(
                self.lookup_key.as_bytes(),
                record.lookup_key.as_bytes(),
            )
            .unwrap_u8()
                != 1
        {
            return Err(ControlPlaneError::InvalidInput);
        }
        let artifact_value: Value = serde_json::from_slice(&record.artifact_json)
            .map_err(|_| ControlPlaneError::InvalidInput)?;
        if artifact_value["path"]["kind"].as_str() != Some("tunnel") {
            return Err(ControlPlaneError::InvalidInput);
        }
        let expiry = artifact_value["session"]["init_expire_at_unix_s"]
            .as_i64()
            .ok_or(ControlPlaneError::InvalidInput)?;
        if SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ControlPlaneError::InvalidInput)?
            .as_secs()
            >= expiry as u64
        {
            return Err(ControlPlaneError::Expired);
        }
        let encoded = record
            .artifact
            .encode_fsb2(&self.chosen_candidate_id)
            .map_err(|_| ControlPlaneError::InvalidInput)?;
        if encoded.raw.len() != self.raw.len()
            || subtle::ConstantTimeEq::ct_eq(encoded.raw.as_slice(), self.raw.as_ref()).unwrap_u8()
                != 1
        {
            return Err(ControlPlaneError::InvalidInput);
        }
        allow_tunnel_runtime(
            self,
            lease_id,
            UNIX_EPOCH + Duration::from_secs(expiry as u64),
            artifact_value["path"]["expected_peer_endpoint_instance_id"]
                .as_str()
                .ok_or(ControlPlaneError::InvalidInput)?,
            record.allow_replacement,
        )
    }
}

/// Builds a secret-free allow response after an application-owned authorizer
/// has verified a tunnel request. An untrusted relay receives pairing and lease
/// claims without an Artifact, authorization record, Session contract, or PSK.
pub fn allow_tunnel_runtime(
    request: &RuntimeAuthorizationRequest,
    lease_id: &str,
    expires_at: SystemTime,
    expected_peer_endpoint_instance_id: &str,
    allow_replacement: bool,
) -> Result<TunnelAuthorizationResponse, ControlPlaneError> {
    if request.raw.get(5) != Some(&2)
        || !valid_id(lease_id, 128)
        || !valid_id(expected_peer_endpoint_instance_id, 128)
    {
        return Err(ControlPlaneError::InvalidInput);
    }
    let payload: Value = serde_json::from_slice(
        request
            .raw
            .get(12..)
            .ok_or(ControlPlaneError::InvalidInput)?,
    )
    .map_err(|_| ControlPlaneError::InvalidInput)?;
    if payload.get("endpoint_instance_id").and_then(Value::as_str)
        == Some(expected_peer_endpoint_instance_id)
    {
        return Err(ControlPlaneError::InvalidInput);
    }
    let expiry = expires_at
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ControlPlaneError::InvalidInput)?
        .as_secs();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ControlPlaneError::InvalidInput)?
        .as_secs();
    if expiry <= now || expiry > i64::MAX as u64 {
        return Err(ControlPlaneError::InvalidInput);
    }
    let response = json!({
        "decision": "allow",
        "credential_id": request.lookup_key,
        "lease_id": lease_id,
        "expires_at": format_rfc3339(expiry as i64)?,
        "expected_peer_endpoint_instance_id": expected_peer_endpoint_instance_id,
        "allow_replacement": allow_replacement,
    });
    Ok(TunnelAuthorizationResponse {
        encoded: serde_json::to_vec(&response)
            .map_err(|_| ControlPlaneError::IssuanceFailed)?
            .into(),
    })
}

/// Builds a secret-free terminal rejection for an opaque tunnel leg.
pub fn reject_tunnel_runtime(
    reason: &str,
) -> Result<TunnelAuthorizationResponse, ControlPlaneError> {
    tunnel_denial("reject", reason)
}

/// Builds a secret-free retry response for an opaque tunnel leg.
pub fn retry_tunnel_runtime(
    reason: &str,
) -> Result<TunnelAuthorizationResponse, ControlPlaneError> {
    tunnel_denial("retry", reason)
}

fn tunnel_denial(
    decision: &str,
    reason: &str,
) -> Result<TunnelAuthorizationResponse, ControlPlaneError> {
    if !valid_lower_id(reason, 64) {
        return Err(ControlPlaneError::InvalidInput);
    }
    Ok(TunnelAuthorizationResponse {
        encoded: serde_json::to_vec(&json!({"decision":decision,"reason":reason}))
            .map_err(|_| ControlPlaneError::IssuanceFailed)?
            .into(),
    })
}

#[derive(Clone)]
pub struct TunnelAuthorizationResponse {
    encoded: Arc<[u8]>,
}
impl fmt::Debug for TunnelAuthorizationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TunnelAuthorizationResponse { <opaque> }")
    }
}
impl TunnelAuthorizationResponse {
    pub fn json(&self) -> Vec<u8> {
        self.encoded.to_vec()
    }
}

#[derive(Clone)]
pub struct RuntimeAuthorizationResponse {
    encoded: Arc<[u8]>,
}
impl fmt::Debug for RuntimeAuthorizationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuntimeAuthorizationResponse { <opaque> }")
    }
}
impl RuntimeAuthorizationResponse {
    pub fn json(&self) -> Vec<u8> {
        self.encoded.to_vec()
    }
}

pub fn reject_runtime(reason: &str) -> Result<RuntimeAuthorizationResponse, ControlPlaneError> {
    if !valid_lower_id(reason, 64) {
        return Err(ControlPlaneError::InvalidInput);
    }
    Ok(RuntimeAuthorizationResponse {
        encoded: serde_json::to_vec(&json!({"decision":"reject","reason":reason}))
            .map_err(|_| ControlPlaneError::IssuanceFailed)?
            .into(),
    })
}

pub fn retry_runtime(reason: &str) -> Result<RuntimeAuthorizationResponse, ControlPlaneError> {
    if !valid_lower_id(reason, 64) {
        return Err(ControlPlaneError::InvalidInput);
    }
    Ok(RuntimeAuthorizationResponse {
        encoded: serde_json::to_vec(&json!({"decision":"retry","reason":reason}))
            .map_err(|_| ControlPlaneError::IssuanceFailed)?
            .into(),
    })
}

fn runtime_session(artifact: &Value) -> Result<Value, ControlPlaneError> {
    let session = artifact
        .get("session")
        .and_then(Value::as_object)
        .ok_or(ControlPlaneError::InvalidInput)?;
    Ok(json!({
        "channel_id": session.get("channel_id").ok_or(ControlPlaneError::InvalidInput)?,
        "init_expire_at_unix_seconds": session.get("init_expire_at_unix_s").ok_or(ControlPlaneError::InvalidInput)?,
        "idle_timeout_seconds": session.get("idle_timeout_seconds").ok_or(ControlPlaneError::InvalidInput)?,
        "establish_timeout_seconds": session.get("establish_timeout_seconds").ok_or(ControlPlaneError::InvalidInput)?,
        "rekey_prepare_timeout_seconds": session.get("rekey_prepare_timeout_seconds").ok_or(ControlPlaneError::InvalidInput)?,
        "rekey_completion_timeout_seconds": session.get("rekey_completion_timeout_seconds").ok_or(ControlPlaneError::InvalidInput)?,
        "max_inbound_streams": session.get("max_inbound_streams").ok_or(ControlPlaneError::InvalidInput)?,
        "e2ee_psk_base64url": session.get("e2ee_psk_b64u").ok_or(ControlPlaneError::InvalidInput)?,
        "allowed_suites": session.get("allowed_suites").ok_or(ControlPlaneError::InvalidInput)?,
        "default_suite": session.get("default_suite").ok_or(ControlPlaneError::InvalidInput)?,
        "selected_features": session.get("selected_features").ok_or(ControlPlaneError::InvalidInput)?,
    }))
}

fn format_rfc3339(timestamp: i64) -> Result<String, ControlPlaneError> {
    if timestamp < 0 {
        return Err(ControlPlaneError::InvalidInput);
    }
    let days = timestamp / 86_400;
    let seconds = timestamp % 86_400;
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3_600,
        seconds % 3_600 / 60,
        seconds % 60
    ))
}
