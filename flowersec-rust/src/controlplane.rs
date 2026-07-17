//! Framework-neutral controlplane clients, codecs, tokens, issuers, and channel initialization.

pub mod http {
    use crate::{ConnectArtifact, artifact::ArtifactError};
    use serde::{Deserialize, Serialize};
    use serde_json::{Map, Value};
    use std::{collections::BTreeMap, fmt};

    pub const DEFAULT_ARTIFACT_PATH: &str = "/v1/connect/artifact";
    pub const DEFAULT_ENTRY_ARTIFACT_PATH: &str = "/v1/connect/artifact/entry";

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ArtifactRequest {
        pub endpoint_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub payload: Option<Map<String, Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub correlation: Option<ArtifactCorrelationInput>,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ArtifactCorrelationInput {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub trace_id: Option<String>,
    }

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub struct ArtifactRequestMetadata {
        pub request_id: String,
        pub remote_addr: String,
        pub host: String,
        pub origin: String,
        pub user_agent: String,
        pub authenticated_subject: String,
        pub attributes: BTreeMap<String, String>,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct ArtifactIssueInput {
        pub endpoint_id: String,
        pub payload: Option<Map<String, Value>>,
        pub trace_id: String,
        pub entry_ticket: String,
        pub is_entry: bool,
        pub metadata: ArtifactRequestMetadata,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub struct ErrorBody {
        pub code: String,
        pub message: String,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub struct ErrorEnvelope {
        pub error: ErrorBody,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct RequestError {
        pub status: u16,
        pub code: String,
        pub message: String,
    }

    impl RequestError {
        pub fn new(status: u16, code: impl Into<String>, message: impl Into<String>) -> Self {
            Self {
                status,
                code: code.into(),
                message: message.into(),
            }
        }
    }

    impl fmt::Display for RequestError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(&self.message)
        }
    }

    impl std::error::Error for RequestError {}

    #[derive(Debug, thiserror::Error)]
    pub enum CodecError {
        #[error("{0}")]
        Request(#[from] RequestError),
        #[error("artifact encoding failed: {0}")]
        Artifact(#[from] ArtifactError),
        #[error("JSON encoding failed: {0}")]
        Json(#[from] serde_json::Error),
    }

    pub fn decode_artifact_request(
        content_type: &str,
        body: &[u8],
        max_body_bytes: usize,
    ) -> Result<ArtifactRequest, RequestError> {
        if content_type
            .split(';')
            .next()
            .map(str::trim)
            .filter(|value| value.eq_ignore_ascii_case("application/json"))
            .is_none()
        {
            return Err(RequestError::new(
                415,
                "unsupported_media_type",
                "content type must be application/json",
            ));
        }
        let max_body_bytes = if max_body_bytes == 0 {
            crate::defaults::CONTROLPLANE_MAX_REQUEST_BODY_BYTES
        } else {
            max_body_bytes
        };
        if body.len() > max_body_bytes {
            return Err(RequestError::new(
                413,
                "body_too_large",
                format!("request body exceeds {max_body_bytes} bytes"),
            ));
        }
        if body.iter().all(u8::is_ascii_whitespace) {
            return Err(RequestError::new(
                400,
                "invalid_json",
                "request body must be a JSON object",
            ));
        }
        let mut request: ArtifactRequest = serde_json::from_slice(body)
            .map_err(|_| RequestError::new(400, "invalid_json", "malformed JSON request body"))?;
        request.endpoint_id = request.endpoint_id.trim().to_owned();
        if request.endpoint_id.is_empty() {
            return Err(RequestError::new(400, "invalid_request", "bad endpoint_id"));
        }
        if let Some(correlation) = &mut request.correlation {
            correlation.trace_id = correlation
                .trace_id
                .take()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty());
        }
        Ok(request)
    }

    pub fn encode_artifact_envelope(artifact: &ConnectArtifact) -> Result<Vec<u8>, CodecError> {
        let artifact_json = artifact.to_json()?;
        let artifact_value: Value = serde_json::from_slice(&artifact_json)?;
        Ok(serde_json::to_vec(&serde_json::json!({
            "connect_artifact": artifact_value
        }))?)
    }

    pub fn encode_error_envelope(
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&ErrorEnvelope {
            error: ErrorBody {
                code: code.into(),
                message: message.into(),
            },
        })
    }

    pub fn bearer_token(authorization: &str) -> Option<&str> {
        authorization
            .trim()
            .strip_prefix("Bearer ")
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }
}

pub mod client {
    use super::http::{
        ArtifactCorrelationInput, ArtifactRequest, DEFAULT_ARTIFACT_PATH,
        DEFAULT_ENTRY_ARTIFACT_PATH, ErrorEnvelope,
    };
    use crate::{ConnectArtifact, artifact::ArtifactError, defaults};
    use futures_util::StreamExt as _;
    use reqwest::{Client, StatusCode, header::HeaderMap};
    use serde_json::{Map, Value};

    #[derive(Clone, Debug)]
    pub struct ConnectArtifactRequestConfig {
        pub base_url: String,
        pub path: Option<String>,
        pub endpoint_id: String,
        pub payload: Option<Map<String, Value>>,
        pub trace_id: Option<String>,
        pub headers: HeaderMap,
        pub client: Option<Client>,
        pub max_response_body_bytes: usize,
    }

    impl ConnectArtifactRequestConfig {
        pub fn new(endpoint_id: impl Into<String>) -> Self {
            Self {
                base_url: String::new(),
                path: None,
                endpoint_id: endpoint_id.into(),
                payload: None,
                trace_id: None,
                headers: HeaderMap::new(),
                client: None,
                max_response_body_bytes: defaults::CONTROLPLANE_MAX_RESPONSE_BODY_BYTES,
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct EntryConnectArtifactRequestConfig {
        pub request: ConnectArtifactRequestConfig,
        pub entry_ticket: String,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct RequestError {
        pub status: u16,
        pub code: String,
        pub message: String,
        pub response_body: Vec<u8>,
    }

    impl std::fmt::Display for RequestError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(&self.message)
        }
    }

    impl std::error::Error for RequestError {}

    #[derive(Debug, thiserror::Error)]
    pub enum ClientError {
        #[error("{0}")]
        InvalidInput(&'static str),
        #[error("controlplane HTTP request failed: {0}")]
        Transport(#[from] reqwest::Error),
        #[error("controlplane response exceeded {limit} bytes")]
        ResponseTooLarge { limit: usize },
        #[error("{0}")]
        Request(#[from] RequestError),
        #[error("invalid controlplane response: {0}")]
        InvalidResponse(&'static str),
        #[error("invalid connect artifact: {0}")]
        Artifact(#[from] ArtifactError),
        #[error("invalid controlplane JSON: {0}")]
        Json(#[from] serde_json::Error),
    }

    pub async fn request_connect_artifact(
        config: ConnectArtifactRequestConfig,
    ) -> Result<ConnectArtifact, ClientError> {
        request(config, None).await
    }

    pub async fn request_entry_connect_artifact(
        config: EntryConnectArtifactRequestConfig,
    ) -> Result<ConnectArtifact, ClientError> {
        let entry_ticket = config.entry_ticket.trim().to_owned();
        if entry_ticket.is_empty() {
            return Err(ClientError::InvalidInput("entry ticket is required"));
        }
        request(config.request, Some(&entry_ticket)).await
    }

    async fn request(
        mut config: ConnectArtifactRequestConfig,
        entry_ticket: Option<&str>,
    ) -> Result<ConnectArtifact, ClientError> {
        config.endpoint_id = config.endpoint_id.trim().to_owned();
        if config.endpoint_id.is_empty() {
            return Err(ClientError::InvalidInput("endpoint id is required"));
        }
        let trace_id = config
            .trace_id
            .take()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let body = ArtifactRequest {
            endpoint_id: config.endpoint_id,
            payload: config.payload,
            correlation: trace_id.map(|trace_id| ArtifactCorrelationInput {
                trace_id: Some(trace_id),
            }),
        };
        let default_path = if entry_ticket.is_some() {
            DEFAULT_ENTRY_ARTIFACT_PATH
        } else {
            DEFAULT_ARTIFACT_PATH
        };
        let path = config
            .path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(default_path);
        let url = build_url(&config.base_url, path);
        let client = config.client.unwrap_or_default();
        let mut builder = client.post(url).headers(config.headers).json(&body);
        if let Some(entry_ticket) = entry_ticket {
            builder = builder.bearer_auth(entry_ticket);
        }
        let response = builder.send().await?;
        let status = response.status();
        let limit = if config.max_response_body_bytes == 0 {
            defaults::CONTROLPLANE_MAX_RESPONSE_BODY_BYTES
        } else {
            config.max_response_body_bytes
        };
        let response_body = read_bounded(response, limit).await?;
        if !status.is_success() {
            return Err(decode_request_error(status, response_body).into());
        }
        let envelope: Value = serde_json::from_slice(&response_body)?;
        let artifact = envelope
            .as_object()
            .and_then(|value| value.get("connect_artifact"))
            .ok_or(ClientError::InvalidResponse("missing connect_artifact"))?;
        let artifact_json = serde_json::to_vec(artifact)?;
        Ok(ConnectArtifact::from_json(&artifact_json)?)
    }

    async fn read_bounded(
        response: reqwest::Response,
        limit: usize,
    ) -> Result<Vec<u8>, ClientError> {
        if response
            .content_length()
            .is_some_and(|content_length| content_length > limit as u64)
        {
            return Err(ClientError::ResponseTooLarge { limit });
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if body.len().saturating_add(chunk.len()) > limit {
                return Err(ClientError::ResponseTooLarge { limit });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    fn decode_request_error(status: StatusCode, response_body: Vec<u8>) -> RequestError {
        let fallback = format!("controlplane request failed: {}", status.as_u16());
        let mut code = String::new();
        let mut message = fallback;
        if let Ok(envelope) = serde_json::from_slice::<ErrorEnvelope>(&response_body) {
            code = envelope.error.code.trim().to_owned();
            let candidate = envelope.error.message.trim();
            if !candidate.is_empty() {
                message = candidate.to_owned();
            }
        } else if let Ok(text) = std::str::from_utf8(&response_body) {
            let text = text.trim();
            if !text.is_empty() {
                message = text.to_owned();
            }
        }
        RequestError {
            status: status.as_u16(),
            code,
            message,
            response_body,
        }
    }

    fn build_url(base_url: &str, path: &str) -> String {
        let base_url = base_url.trim().trim_end_matches('/');
        if base_url.is_empty() {
            path.to_owned()
        } else {
            format!("{base_url}{path}")
        }
    }
}

pub mod token {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
    use serde::{Deserialize, Serialize};
    use std::{
        collections::HashMap,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use subtle::ConstantTimeEq as _;

    pub const PREFIX: &str = "FST2";
    const MAX_CHANNEL_ID_BYTES: usize = 256;

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub struct Payload {
        pub kid: String,
        pub aud: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub iss: String,
        pub channel_id: String,
        pub role: u8,
        pub token_id: String,
        pub init_exp: i64,
        pub idle_timeout_seconds: i32,
        pub iat: i64,
        pub exp: i64,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct ParsedToken {
        pub payload: Payload,
        pub signed: Vec<u8>,
        pub signature: Vec<u8>,
    }

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub struct VerifyOptions {
        pub now_unix_s: Option<i64>,
        pub audience: Option<String>,
        pub issuer: Option<String>,
        pub clock_skew: Duration,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
    pub enum TokenError {
        #[error("token invalid format")]
        InvalidFormat,
        #[error("token invalid base64url")]
        InvalidBase64,
        #[error("token invalid json")]
        InvalidJson,
        #[error("token unknown kid")]
        UnknownKid,
        #[error("token invalid signature")]
        InvalidSignature,
        #[error("token invalid audience")]
        InvalidAudience,
        #[error("token invalid issuer")]
        InvalidIssuer,
        #[error("token expired")]
        Expired,
        #[error("token iat in future")]
        IatInFuture,
        #[error("token init window expired")]
        InitExpired,
        #[error("token exp > init_exp")]
        ExpAfterInit,
        #[error("token invalid idle timeout")]
        InvalidIdleTimeout,
    }

    pub trait KeyLookup {
        fn lookup(&self, kid: &str) -> Option<VerifyingKey>;
    }

    impl KeyLookup for HashMap<String, VerifyingKey> {
        fn lookup(&self, kid: &str) -> Option<VerifyingKey> {
            self.get(kid).copied()
        }
    }

    pub fn sign(signing_key: &SigningKey, mut payload: Payload) -> Result<String, TokenError> {
        validate_payload_for_signing(&mut payload)?;
        let payload_json = serde_json::to_vec(&payload).map_err(|_| TokenError::InvalidJson)?;
        let signed = format!("{PREFIX}.{}", URL_SAFE_NO_PAD.encode(payload_json));
        let signature = signing_key.sign(signed.as_bytes());
        Ok(format!(
            "{signed}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }

    pub fn parse(token: &str) -> Result<ParsedToken, TokenError> {
        let mut parts = token.split('.');
        let prefix = parts.next();
        let payload_part = parts.next();
        let signature_part = parts.next();
        if prefix != Some(PREFIX)
            || payload_part.is_none()
            || signature_part.is_none()
            || parts.next().is_some()
        {
            return Err(TokenError::InvalidFormat);
        }
        let payload_part = payload_part.unwrap_or_default();
        let signature_part = signature_part.unwrap_or_default();
        let payload_json = URL_SAFE_NO_PAD
            .decode(payload_part)
            .map_err(|_| TokenError::InvalidBase64)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature_part)
            .map_err(|_| TokenError::InvalidBase64)?;
        let payload = serde_json::from_slice(&payload_json).map_err(|_| TokenError::InvalidJson)?;
        Ok(ParsedToken {
            payload,
            signed: format!("{PREFIX}.{payload_part}").into_bytes(),
            signature,
        })
    }

    pub fn verify(
        token: &str,
        keys: &impl KeyLookup,
        options: &VerifyOptions,
    ) -> Result<Payload, TokenError> {
        verify_parsed(parse(token)?, keys, options)
    }

    pub fn verify_parsed(
        mut parsed: ParsedToken,
        keys: &impl KeyLookup,
        options: &VerifyOptions,
    ) -> Result<Payload, TokenError> {
        validate_payload(&mut parsed.payload)?;
        let public_key = keys
            .lookup(parsed.payload.kid.trim())
            .ok_or(TokenError::UnknownKid)?;
        let signature =
            Signature::from_slice(&parsed.signature).map_err(|_| TokenError::InvalidSignature)?;
        public_key
            .verify(&parsed.signed, &signature)
            .map_err(|_| TokenError::InvalidSignature)?;
        if let Some(audience) = options.audience.as_deref() {
            if !constant_time_eq(parsed.payload.aud.as_bytes(), audience.as_bytes()) {
                return Err(TokenError::InvalidAudience);
            }
        }
        if let Some(issuer) = options.issuer.as_deref() {
            if !constant_time_eq(parsed.payload.iss.as_bytes(), issuer.as_bytes()) {
                return Err(TokenError::InvalidIssuer);
            }
        }
        validate_timestamps(
            parsed.payload.init_exp,
            parsed.payload.iat,
            parsed.payload.exp,
        )?;
        let now = options.now_unix_s.unwrap_or_else(system_time_unix_s);
        let skew = skew_seconds_ceil(options.clock_skew);
        if parsed.payload.iat > now.saturating_add(skew) {
            return Err(TokenError::IatInFuture);
        }
        let earliest = now.saturating_sub(skew);
        if parsed.payload.init_exp < earliest {
            return Err(TokenError::InitExpired);
        }
        if parsed.payload.exp < earliest {
            return Err(TokenError::Expired);
        }
        Ok(parsed.payload)
    }

    pub fn equal_signed_part(left: &str, right: &str) -> bool {
        match (signed_part(left), signed_part(right)) {
            (Some(left), Some(right)) => constant_time_eq(left.as_bytes(), right.as_bytes()),
            _ => false,
        }
    }

    fn signed_part(value: &str) -> Option<&str> {
        value.rsplit_once('.').map(|(part, _)| part)
    }

    fn validate_payload_for_signing(payload: &mut Payload) -> Result<(), TokenError> {
        if payload.kid.trim().is_empty() || payload.aud.trim().is_empty() {
            return Err(TokenError::InvalidFormat);
        }
        validate_payload(payload)?;
        if payload.init_exp <= 0 || payload.iat <= 0 || payload.exp <= 0 {
            return Err(TokenError::InvalidFormat);
        }
        validate_timestamps(payload.init_exp, payload.iat, payload.exp)
    }

    fn validate_payload(payload: &mut Payload) -> Result<(), TokenError> {
        if payload.kid.trim().is_empty() || payload.token_id.trim().is_empty() {
            return Err(TokenError::InvalidFormat);
        }
        payload.channel_id = payload.channel_id.trim().to_owned();
        if payload.channel_id.is_empty() || payload.channel_id.len() > MAX_CHANNEL_ID_BYTES {
            return Err(TokenError::InvalidFormat);
        }
        if !matches!(payload.role, 1 | 2) {
            return Err(TokenError::InvalidFormat);
        }
        if payload.idle_timeout_seconds <= 0 {
            return Err(TokenError::InvalidIdleTimeout);
        }
        Ok(())
    }

    fn validate_timestamps(init_exp: i64, iat: i64, exp: i64) -> Result<(), TokenError> {
        if exp > init_exp {
            return Err(TokenError::ExpAfterInit);
        }
        if iat > exp {
            return Err(TokenError::InvalidFormat);
        }
        Ok(())
    }

    fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
        left.len() == right.len() && bool::from(left.ct_eq(right))
    }

    fn skew_seconds_ceil(duration: Duration) -> i64 {
        let seconds = duration.as_secs();
        let rounded = seconds.saturating_add(u64::from(duration.subsec_nanos() != 0));
        i64::try_from(rounded).unwrap_or(i64::MAX)
    }

    fn system_time_unix_s() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or_default()
    }
}

pub mod issuer {
    use super::token::{self, Payload, TokenError};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use rand::rngs::OsRng;
    use serde::Serialize;
    use std::{collections::HashMap, sync::RwLock};

    struct ActiveSigningKey {
        kid: String,
        signing_key: SigningKey,
    }

    impl std::fmt::Debug for ActiveSigningKey {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("ActiveSigningKey")
                .field("kid", &self.kid)
                .field("signing_key", &"[REDACTED]")
                .finish()
        }
    }

    #[derive(Debug)]
    struct KeyMaterial {
        active: ActiveSigningKey,
        verification_keys: HashMap<String, VerifyingKey>,
    }

    #[derive(Debug)]
    pub struct Keyset {
        material: RwLock<KeyMaterial>,
    }

    #[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
    pub enum IssuerError {
        #[error("key id is required")]
        MissingKid,
        #[error("verification key is missing")]
        MissingVerificationKey,
        #[error("verification key conflicts with the existing key id")]
        VerificationKeyConflict,
        #[error("the active verification key cannot be retired")]
        ActiveVerificationKey,
        #[error("issuer keyset lock is poisoned")]
        Poisoned,
        #[error("token signing failed: {0}")]
        Token(#[from] TokenError),
        #[error("keyset JSON encoding failed: {0}")]
        Json(String),
    }

    #[derive(Serialize)]
    struct TunnelKeysetFile {
        keys: Vec<TunnelKey>,
    }

    #[derive(Serialize)]
    struct TunnelKey {
        kid: String,
        pubkey_b64u: String,
    }

    impl Keyset {
        pub fn new(kid: impl Into<String>, signing_key: SigningKey) -> Result<Self, IssuerError> {
            let kid = kid.into().trim().to_owned();
            if kid.is_empty() {
                return Err(IssuerError::MissingKid);
            }
            let verifying_key = signing_key.verifying_key();
            Ok(Self {
                material: RwLock::new(KeyMaterial {
                    active: ActiveSigningKey {
                        kid: kid.clone(),
                        signing_key,
                    },
                    verification_keys: HashMap::from([(kid, verifying_key)]),
                }),
            })
        }

        pub fn new_random(kid: impl Into<String>) -> Result<Self, IssuerError> {
            Self::new(kid, SigningKey::generate(&mut OsRng))
        }

        pub fn current_kid(&self) -> Result<String, IssuerError> {
            Ok(self
                .material
                .read()
                .map_err(|_| IssuerError::Poisoned)?
                .active
                .kid
                .clone())
        }

        pub fn public_keys(&self) -> Result<HashMap<String, VerifyingKey>, IssuerError> {
            let material = self.material.read().map_err(|_| IssuerError::Poisoned)?;
            Ok(material.verification_keys.clone())
        }

        pub fn sign_token(&self, mut payload: Payload) -> Result<String, IssuerError> {
            let material = self.material.read().map_err(|_| IssuerError::Poisoned)?;
            payload.kid.clone_from(&material.active.kid);
            Ok(token::sign(&material.active.signing_key, payload)?)
        }

        pub fn add_verification_key(
            &self,
            kid: impl Into<String>,
            verifying_key: VerifyingKey,
        ) -> Result<(), IssuerError> {
            let kid = kid.into().trim().to_owned();
            if kid.is_empty() {
                return Err(IssuerError::MissingKid);
            }
            let mut material = self.material.write().map_err(|_| IssuerError::Poisoned)?;
            match material.verification_keys.get(&kid) {
                Some(existing) if existing == &verifying_key => Ok(()),
                Some(_) => Err(IssuerError::VerificationKeyConflict),
                None => {
                    material.verification_keys.insert(kid, verifying_key);
                    Ok(())
                }
            }
        }

        pub fn rotate(
            &self,
            kid: impl Into<String>,
            signing_key: SigningKey,
        ) -> Result<(), IssuerError> {
            let kid = kid.into().trim().to_owned();
            if kid.is_empty() {
                return Err(IssuerError::MissingKid);
            }
            let verifying_key = signing_key.verifying_key();
            let mut material = self.material.write().map_err(|_| IssuerError::Poisoned)?;
            match material.verification_keys.get(&kid) {
                Some(existing) if existing == &verifying_key => {}
                Some(_) => return Err(IssuerError::VerificationKeyConflict),
                None => return Err(IssuerError::MissingVerificationKey),
            }
            material.active = ActiveSigningKey { kid, signing_key };
            Ok(())
        }

        pub fn retire_verification_key(&self, kid: &str) -> Result<(), IssuerError> {
            let kid = kid.trim();
            if kid.is_empty() {
                return Err(IssuerError::MissingKid);
            }
            let mut material = self.material.write().map_err(|_| IssuerError::Poisoned)?;
            if material.active.kid == kid {
                return Err(IssuerError::ActiveVerificationKey);
            }
            if material.verification_keys.remove(kid).is_none() {
                return Err(IssuerError::MissingVerificationKey);
            }
            Ok(())
        }

        pub fn export_tunnel_keyset(&self) -> Result<Vec<u8>, IssuerError> {
            let mut keys = self
                .public_keys()?
                .into_iter()
                .map(|(kid, public_key)| TunnelKey {
                    kid,
                    pubkey_b64u: URL_SAFE_NO_PAD.encode(public_key.to_bytes()),
                })
                .collect::<Vec<_>>();
            keys.sort_by(|left, right| left.kid.cmp(&right.kid));
            serde_json::to_vec_pretty(&TunnelKeysetFile { keys })
                .map_err(|error| IssuerError::Json(error.to_string()))
        }
    }
}

pub mod channelinit {
    use super::{
        issuer::{IssuerError, Keyset},
        token::Payload,
    };
    use crate::generated::flowersec::controlplane::v1::{ChannelInitGrant, Role, Suite};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::{RngCore as _, rngs::OsRng};
    use std::{
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use zeroize::Zeroizing;

    pub const CHANNEL_INIT_WINDOW: Duration = Duration::from_secs(120);
    pub const DEFAULT_IDLE_TIMEOUT_SECONDS: i32 = 60;
    pub const DEFAULT_TOKEN_EXP_SECONDS: i64 = 60;

    #[derive(Clone, Debug)]
    pub struct Params {
        pub tunnel_url: String,
        pub tunnel_audience: String,
        pub issuer_id: String,
        pub token_exp_seconds: i64,
        pub idle_timeout_seconds: i32,
        pub clock_skew: Duration,
        pub allowed_suites: Vec<Suite>,
        pub default_suite: Option<Suite>,
    }

    impl Default for Params {
        fn default() -> Self {
            Self {
                tunnel_url: String::new(),
                tunnel_audience: String::new(),
                issuer_id: String::new(),
                token_exp_seconds: 0,
                idle_timeout_seconds: 0,
                clock_skew: Duration::ZERO,
                allowed_suites: Vec::new(),
                default_suite: None,
            }
        }
    }

    type Clock = dyn Fn() -> i64 + Send + Sync;

    pub struct Service {
        issuer: Arc<Keyset>,
        params: Params,
        now: Arc<Clock>,
    }

    impl std::fmt::Debug for Service {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("Service")
                .field("issuer", &self.issuer)
                .field("params", &self.params)
                .field("now", &"Clock(..)")
                .finish()
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
    pub enum ChannelInitError {
        #[error("missing tunnel url")]
        MissingTunnelUrl,
        #[error("missing tunnel audience")]
        MissingTunnelAudience,
        #[error("missing issuer id")]
        MissingIssuerId,
        #[error("invalid channel id")]
        InvalidChannelId,
        #[error("token_exp_seconds must be >= 0")]
        InvalidTokenExpiration,
        #[error("idle_timeout_seconds must be >= 0")]
        InvalidIdleTimeout,
        #[error("unsupported suite")]
        UnsupportedSuite,
        #[error("default suite not allowed")]
        DefaultSuiteNotAllowed,
        #[error("channel init expired")]
        Expired,
        #[error("invalid grant")]
        InvalidGrant,
        #[error("token issuance failed: {0}")]
        Issuer(#[from] IssuerError),
    }

    impl Service {
        pub fn new(issuer: Arc<Keyset>, params: Params) -> Self {
            Self {
                issuer,
                params,
                now: Arc::new(system_time_unix_s),
            }
        }

        pub fn with_clock(
            issuer: Arc<Keyset>,
            params: Params,
            now: impl Fn() -> i64 + Send + Sync + 'static,
        ) -> Self {
            Self {
                issuer,
                params,
                now: Arc::new(now),
            }
        }

        pub fn new_channel_init(
            &self,
            channel_id: impl Into<String>,
        ) -> Result<(ChannelInitGrant, ChannelInitGrant), ChannelInitError> {
            self.validate_params()?;
            let channel_id = normalize_channel_id(channel_id.into())?;
            let mut psk = Zeroizing::new([0_u8; 32]);
            OsRng.fill_bytes(psk.as_mut());
            let psk_b64u = URL_SAFE_NO_PAD.encode(psk.as_ref());
            let now = (self.now)();
            let init_exp = now.saturating_add(CHANNEL_INIT_WINDOW.as_secs() as i64);
            let token_exp_seconds = self.token_exp_seconds()?;
            let idle_timeout_seconds = self.idle_timeout_seconds()?;
            let allowed_suites = normalize_suites(&self.params.allowed_suites)?;
            let default_suite = self.params.default_suite.unwrap_or(allowed_suites[0]);
            if !allowed_suites.contains(&default_suite) {
                return Err(ChannelInitError::DefaultSuiteNotAllowed);
            }
            let client_token = self.sign_role_token(
                &channel_id,
                Role::Client,
                init_exp,
                idle_timeout_seconds,
                token_exp_seconds,
                now,
            )?;
            let server_token = self.sign_role_token(
                &channel_id,
                Role::Server,
                init_exp,
                idle_timeout_seconds,
                token_exp_seconds,
                now,
            )?;
            let grant = |role, token| ChannelInitGrant {
                tunnel_url: self.params.tunnel_url.clone(),
                channel_id: channel_id.clone(),
                channel_init_expire_at_unix_s: init_exp,
                idle_timeout_seconds,
                role,
                token,
                e2ee_psk_b64u: psk_b64u.clone(),
                allowed_suites: allowed_suites.clone(),
                default_suite,
            };
            Ok((
                grant(Role::Client, client_token),
                grant(Role::Server, server_token),
            ))
        }

        pub fn reissue_token(
            &self,
            grant: &ChannelInitGrant,
        ) -> Result<ChannelInitGrant, ChannelInitError> {
            if self.params.tunnel_audience.trim().is_empty() {
                return Err(ChannelInitError::MissingTunnelAudience);
            }
            if self.params.issuer_id.trim().is_empty() {
                return Err(ChannelInitError::MissingIssuerId);
            }
            if grant.idle_timeout_seconds <= 0 {
                return Err(ChannelInitError::InvalidGrant);
            }
            let now = (self.now)();
            let skew = skew_seconds_ceil(self.params.clock_skew);
            if now > grant.channel_init_expire_at_unix_s.saturating_add(skew) {
                return Err(ChannelInitError::Expired);
            }
            let token = self.sign_role_token(
                &grant.channel_id,
                grant.role,
                grant.channel_init_expire_at_unix_s,
                grant.idle_timeout_seconds,
                self.token_exp_seconds()?,
                now,
            )?;
            let mut result = grant.clone();
            result.token = token;
            Ok(result)
        }

        fn validate_params(&self) -> Result<(), ChannelInitError> {
            if self.params.tunnel_url.trim().is_empty() {
                return Err(ChannelInitError::MissingTunnelUrl);
            }
            if self.params.tunnel_audience.trim().is_empty() {
                return Err(ChannelInitError::MissingTunnelAudience);
            }
            if self.params.issuer_id.trim().is_empty() {
                return Err(ChannelInitError::MissingIssuerId);
            }
            self.token_exp_seconds()?;
            self.idle_timeout_seconds()?;
            Ok(())
        }

        fn token_exp_seconds(&self) -> Result<i64, ChannelInitError> {
            match self.params.token_exp_seconds {
                value if value < 0 => Err(ChannelInitError::InvalidTokenExpiration),
                0 => Ok(DEFAULT_TOKEN_EXP_SECONDS),
                value => Ok(value),
            }
        }

        fn idle_timeout_seconds(&self) -> Result<i32, ChannelInitError> {
            match self.params.idle_timeout_seconds {
                value if value < 0 => Err(ChannelInitError::InvalidIdleTimeout),
                0 => Ok(DEFAULT_IDLE_TIMEOUT_SECONDS),
                value => Ok(value),
            }
        }

        fn sign_role_token(
            &self,
            channel_id: &str,
            role: Role,
            init_exp: i64,
            idle_timeout_seconds: i32,
            token_exp_seconds: i64,
            now: i64,
        ) -> Result<String, ChannelInitError> {
            let mut token_id = Zeroizing::new([0_u8; 24]);
            OsRng.fill_bytes(token_id.as_mut());
            let iat = now.min(init_exp);
            let exp = iat.saturating_add(token_exp_seconds).min(init_exp);
            Ok(self.issuer.sign_token(Payload {
                kid: String::new(),
                aud: self.params.tunnel_audience.clone(),
                iss: self.params.issuer_id.clone(),
                channel_id: channel_id.to_owned(),
                role: role as u8,
                token_id: URL_SAFE_NO_PAD.encode(token_id.as_ref()),
                init_exp,
                idle_timeout_seconds,
                iat,
                exp,
            })?)
        }
    }

    fn normalize_channel_id(channel_id: String) -> Result<String, ChannelInitError> {
        let channel_id = channel_id.trim().to_owned();
        if channel_id.is_empty() || channel_id.len() > 256 {
            return Err(ChannelInitError::InvalidChannelId);
        }
        Ok(channel_id)
    }

    fn normalize_suites(suites: &[Suite]) -> Result<Vec<Suite>, ChannelInitError> {
        let suites = if suites.is_empty() {
            &[Suite::X25519HkdfSha256Aes256Gcm][..]
        } else {
            suites
        };
        let mut result = Vec::with_capacity(suites.len());
        for suite in suites {
            if !matches!(
                suite,
                Suite::X25519HkdfSha256Aes256Gcm | Suite::P256HkdfSha256Aes256Gcm
            ) {
                return Err(ChannelInitError::UnsupportedSuite);
            }
            if !result.contains(suite) {
                result.push(*suite);
            }
        }
        if result.is_empty() {
            return Err(ChannelInitError::UnsupportedSuite);
        }
        Ok(result)
    }

    fn skew_seconds_ceil(duration: Duration) -> i64 {
        let seconds = duration.as_secs();
        let rounded = seconds.saturating_add(u64::from(duration.subsec_nanos() != 0));
        i64::try_from(rounded).unwrap_or(i64::MAX)
    }

    fn system_time_unix_s() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::{channelinit, client, http, issuer, token};
    use crate::{
        ConnectArtifact,
        generated::flowersec::controlplane::v1::{Role, Suite},
    };
    use ed25519_dalek::SigningKey;
    use serde::Deserialize;
    use serde_json::json;
    use std::{sync::Arc, time::Duration};

    #[derive(Deserialize)]
    struct TokenVectors {
        cases: Vec<TokenVector>,
    }

    #[derive(Deserialize)]
    struct TokenVector {
        inputs: TokenInputs,
        expected: TokenExpected,
    }

    #[derive(Deserialize)]
    struct TokenInputs {
        ed25519_seed_hex: String,
        payload: token::Payload,
    }

    #[derive(Deserialize)]
    struct TokenExpected {
        token: String,
    }

    #[test]
    fn fst2_token_matches_shared_golden_vector() {
        let vectors: TokenVectors = serde_json::from_str(include_str!(
            "../../idl/flowersec/testdata/v1/token_vectors.json"
        ))
        .expect("vectors");
        for vector in vectors.cases {
            let seed = decode_hex_32(&vector.inputs.ed25519_seed_hex);
            let signing_key = SigningKey::from_bytes(&seed);
            let signed = token::sign(&signing_key, vector.inputs.payload.clone()).expect("sign");
            assert_eq!(signed, vector.expected.token);
            let keys = std::collections::HashMap::from([(
                vector.inputs.payload.kid.clone(),
                signing_key.verifying_key(),
            )]);
            let verified = token::verify(
                &signed,
                &keys,
                &token::VerifyOptions {
                    now_unix_s: Some(vector.inputs.payload.iat),
                    audience: Some(vector.inputs.payload.aud.clone()),
                    issuer: Some(vector.inputs.payload.iss.clone()),
                    clock_skew: Duration::ZERO,
                },
            )
            .expect("verify");
            assert_eq!(verified, vector.inputs.payload);
        }
    }

    #[test]
    fn artifact_request_codec_is_strict_and_bounded() {
        let request = http::decode_artifact_request(
            "application/json; charset=utf-8",
            br#"{"endpoint_id":" endpoint-1 ","correlation":{"trace_id":" trace-1 "}}"#,
            1024,
        )
        .expect("decode");
        assert_eq!(request.endpoint_id, "endpoint-1");
        assert_eq!(
            request.correlation.and_then(|value| value.trace_id),
            Some("trace-1".to_owned())
        );
        let error = http::decode_artifact_request(
            "application/json",
            br#"{"endpoint_id":"endpoint-1","unknown":true}"#,
            1024,
        )
        .expect_err("unknown field");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "invalid_json");
        let error =
            http::decode_artifact_request("text/plain", b"{}", 1024).expect_err("content type");
        assert_eq!(error.status, 415);
    }

    #[test]
    fn issuer_rotation_and_channel_init_preserve_grant_contract() {
        let issuer = Arc::new(issuer::Keyset::new_random("k1").expect("issuer"));
        let service = channelinit::Service::with_clock(
            issuer.clone(),
            channelinit::Params {
                tunnel_url: "wss://tunnel.example.test/v1/tunnel".to_owned(),
                tunnel_audience: "flowersec-tunnel:test".to_owned(),
                issuer_id: "issuer-test".to_owned(),
                allowed_suites: vec![
                    Suite::X25519HkdfSha256Aes256Gcm,
                    Suite::P256HkdfSha256Aes256Gcm,
                ],
                ..channelinit::Params::default()
            },
            || 1_700_000_000,
        );
        let (client_grant, server_grant) = service
            .new_channel_init(" channel-test ")
            .expect("channel init");
        assert_eq!(client_grant.role, Role::Client);
        assert_eq!(server_grant.role, Role::Server);
        assert_eq!(client_grant.e2ee_psk_b64u, server_grant.e2ee_psk_b64u);
        assert_ne!(client_grant.token, server_grant.token);
        let keys = issuer.public_keys().expect("public keys");
        let payload = token::verify(
            &client_grant.token,
            &keys,
            &token::VerifyOptions {
                now_unix_s: Some(1_700_000_000),
                audience: Some("flowersec-tunnel:test".to_owned()),
                issuer: Some("issuer-test".to_owned()),
                clock_skew: Duration::ZERO,
            },
        )
        .expect("token verify");
        assert_eq!(payload.channel_id, "channel-test");
        assert_eq!(payload.role, Role::Client as u8);
        let replacement = SigningKey::from_bytes(&[7_u8; 32]);
        issuer
            .add_verification_key("k2", replacement.verifying_key())
            .expect("prepublish replacement");
        issuer.rotate("k2", replacement).expect("rotate");
        let refreshed = service.reissue_token(&client_grant).expect("reissue");
        assert_ne!(refreshed.token, client_grant.token);
        assert_eq!(
            token::parse(&refreshed.token).expect("parse").payload.kid,
            "k2"
        );
        let exported: serde_json::Value =
            serde_json::from_slice(&issuer.export_tunnel_keyset().expect("export"))
                .expect("keyset json");
        assert_eq!(exported["keys"][0]["kid"], "k1");
        assert_eq!(exported["keys"][1]["kid"], "k2");
    }

    #[tokio::test]
    async fn artifact_client_preserves_structured_http_error() {
        use tokio::{
            io::{AsyncReadExt as _, AsyncWriteExt as _},
            net::TcpListener,
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request = vec![0_u8; 4096];
            let _ = socket.read(&mut request).await.expect("read");
            let body = br#"{"error":{"code":"denied","message":"request denied"}}"#;
            let response = format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("headers");
            socket.write_all(body).await.expect("body");
        });
        let mut config = client::ConnectArtifactRequestConfig::new("endpoint-1");
        config.base_url = format!("http://{address}");
        let error = client::request_connect_artifact(config)
            .await
            .expect_err("request error");
        let client::ClientError::Request(error) = error else {
            panic!("unexpected error")
        };
        assert_eq!(error.status, 403);
        assert_eq!(error.code, "denied");
        assert_eq!(error.message, "request denied");
        server.await.expect("server");
    }

    #[test]
    fn artifact_envelope_round_trips() {
        let artifact_json = serde_json::to_vec(&json!({
            "v": 1,
            "transport": "tunnel",
            "tunnel_grant": {
                "tunnel_url": "wss://tunnel.example.test/v1/tunnel",
                "channel_id": "channel-test",
                "channel_init_expire_at_unix_s": 1_700_000_120_i64,
                "idle_timeout_seconds": 60,
                "role": 1,
                "token": "token",
                "e2ee_psk_b64u": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "allowed_suites": [1, 2],
                "default_suite": 1
            }
        }))
        .expect("json");
        let artifact = ConnectArtifact::from_json(&artifact_json).expect("artifact");
        let envelope = http::encode_artifact_envelope(&artifact).expect("envelope");
        let value: serde_json::Value = serde_json::from_slice(&envelope).expect("decode");
        assert_eq!(value["connect_artifact"]["transport"], "tunnel");
    }

    fn decode_hex_32(input: &str) -> [u8; 32] {
        assert_eq!(input.len(), 64);
        let mut output = [0_u8; 32];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16).expect("hex");
        }
        output
    }
}
