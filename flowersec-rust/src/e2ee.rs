use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use hmac::{Hmac, Mac};
use p256::{PublicKey as P256PublicKey, SecretKey as P256SecretKey, ecdh::diffie_hellman};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    defaults,
    generated::flowersec::e2ee::v1 as wire,
    transport::{WebSocketMessage, WebSocketMessageKind, WebSocketTransport},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

pub const HANDSHAKE_MAGIC: &[u8; 4] = b"FSEH";
pub const RECORD_MAGIC: &[u8; 4] = b"FSEC";
pub const PROTOCOL_VERSION: u8 = 1;
pub const HANDSHAKE_TYPE_INIT: u8 = 1;
pub const HANDSHAKE_TYPE_RESP: u8 = 2;
pub const HANDSHAKE_TYPE_ACK: u8 = 3;
pub const HANDSHAKE_HEADER_LEN: usize = 10;
pub const RECORD_HEADER_LEN: usize = 18;
pub const GCM_TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Suite {
    X25519HkdfSha256Aes256Gcm = 1,
    P256HkdfSha256Aes256Gcm = 2,
}

impl TryFrom<u16> for Suite {
    type Error = E2eeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::X25519HkdfSha256Aes256Gcm),
            2 => Ok(Self::P256HkdfSha256Aes256Gcm),
            _ => Err(E2eeError::UnsupportedSuite),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecordFlag {
    App = 0,
    Ping = 1,
    Rekey = 2,
}

impl TryFrom<u8> for RecordFlag {
    type Error = E2eeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::App),
            1 => Ok(Self::Ping),
            2 => Ok(Self::Rekey),
            _ => Err(E2eeError::InvalidRecordFlag),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Direction {
    ClientToServer = 1,
    ServerToClient = 2,
}

#[derive(Debug, thiserror::Error)]
pub enum E2eeError {
    #[error("unsupported E2EE suite")]
    UnsupportedSuite,
    #[error("PSK must be exactly 32 bytes")]
    InvalidPsk,
    #[error("invalid key material")]
    InvalidKey,
    #[error("invalid frame magic")]
    InvalidMagic,
    #[error("invalid protocol version")]
    InvalidVersion,
    #[error("invalid frame length")]
    InvalidLength,
    #[error("record exceeds configured limit")]
    RecordTooLarge,
    #[error("record sequence does not match")]
    InvalidRecordSequence,
    #[error("record flag is invalid")]
    InvalidRecordFlag,
    #[error("record authentication failed")]
    RecordDecrypt,
    #[error("transcript input is invalid")]
    InvalidTranscript,
    #[error("HKDF expansion failed")]
    Hkdf,
    #[error("WebSocket transport failed: {0}")]
    Transport(#[from] std::io::Error),
    #[error("handshake JSON is invalid: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("handshake authentication failed")]
    Authentication,
    #[error("handshake timestamp is invalid")]
    InvalidTimestamp,
    #[error("server handshake state is unavailable")]
    HandshakeStateUnavailable,
    #[error("too many pending server handshakes")]
    TooManyPendingHandshakes,
    #[error("transport closed")]
    Closed,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret32([u8; 32]);

impl Secret32 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Secret32 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Secret32([REDACTED])")
    }
}

#[derive(Debug)]
pub struct SessionKeys {
    pub c2s_key: Secret32,
    pub s2c_key: Secret32,
    pub c2s_nonce_prefix: [u8; 4],
    pub s2c_nonce_prefix: [u8; 4],
    pub rekey_base: Secret32,
}

#[derive(Clone, Debug)]
pub struct TranscriptInputs<'a> {
    pub version: u8,
    pub suite: u16,
    pub role: u8,
    pub client_features: u32,
    pub server_features: u32,
    pub channel_id: &'a str,
    pub nonce_c: [u8; 32],
    pub nonce_s: [u8; 32],
    pub client_ephemeral_public_key: &'a [u8],
    pub server_ephemeral_public_key: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecryptedRecord {
    pub flags: RecordFlag,
    pub sequence: u64,
    pub plaintext: Vec<u8>,
}

pub enum EphemeralPrivateKey {
    X25519(X25519Secret),
    P256(P256SecretKey),
}

impl std::fmt::Debug for EphemeralPrivateKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EphemeralPrivateKey([REDACTED])")
    }
}

pub fn generate_ephemeral_keypair(
    suite: Suite,
) -> Result<(EphemeralPrivateKey, Vec<u8>), E2eeError> {
    match suite {
        Suite::X25519HkdfSha256Aes256Gcm => {
            let private = X25519Secret::random_from_rng(OsRng);
            let public = X25519PublicKey::from(&private);
            Ok((
                EphemeralPrivateKey::X25519(private),
                public.as_bytes().to_vec(),
            ))
        }
        Suite::P256HkdfSha256Aes256Gcm => {
            let private = P256SecretKey::random(&mut OsRng);
            let public = private.public_key();
            Ok((
                EphemeralPrivateKey::P256(private),
                public.to_sec1_bytes().to_vec(),
            ))
        }
    }
}

pub fn derive_shared_secret(
    suite: Suite,
    private_key: &[u8],
    peer_public_key: &[u8],
) -> Result<Secret32, E2eeError> {
    match suite {
        Suite::X25519HkdfSha256Aes256Gcm => {
            let private: [u8; 32] = private_key.try_into().map_err(|_| E2eeError::InvalidKey)?;
            let public: [u8; 32] = peer_public_key
                .try_into()
                .map_err(|_| E2eeError::InvalidKey)?;
            let shared = X25519Secret::from(private).diffie_hellman(&X25519PublicKey::from(public));
            Ok(Secret32::new(*shared.as_bytes()))
        }
        Suite::P256HkdfSha256Aes256Gcm => {
            let private =
                P256SecretKey::from_slice(private_key).map_err(|_| E2eeError::InvalidKey)?;
            let public = P256PublicKey::from_sec1_bytes(peer_public_key)
                .map_err(|_| E2eeError::InvalidKey)?;
            let shared = diffie_hellman(private.to_nonzero_scalar(), public.as_affine());
            let mut bytes = [0_u8; 32];
            bytes.copy_from_slice(shared.raw_secret_bytes());
            Ok(Secret32::new(bytes))
        }
    }
}

impl EphemeralPrivateKey {
    pub fn derive_shared_secret(&self, peer_public_key: &[u8]) -> Result<Secret32, E2eeError> {
        match self {
            Self::X25519(private) => {
                let public: [u8; 32] = peer_public_key
                    .try_into()
                    .map_err(|_| E2eeError::InvalidKey)?;
                let shared = private.diffie_hellman(&X25519PublicKey::from(public));
                Ok(Secret32::new(*shared.as_bytes()))
            }
            Self::P256(private) => {
                let public = P256PublicKey::from_sec1_bytes(peer_public_key)
                    .map_err(|_| E2eeError::InvalidKey)?;
                let shared = diffie_hellman(private.to_nonzero_scalar(), public.as_affine());
                let mut bytes = [0_u8; 32];
                bytes.copy_from_slice(shared.raw_secret_bytes());
                Ok(Secret32::new(bytes))
            }
        }
    }
}

pub fn transcript_hash(input: &TranscriptInputs<'_>) -> Result<[u8; 32], E2eeError> {
    if input.channel_id.is_empty()
        || input.channel_id.len() > u16::MAX as usize
        || input.client_ephemeral_public_key.is_empty()
        || input.client_ephemeral_public_key.len() > u16::MAX as usize
        || input.server_ephemeral_public_key.is_empty()
        || input.server_ephemeral_public_key.len() > u16::MAX as usize
    {
        return Err(E2eeError::InvalidTranscript);
    }
    let mut transcript = Vec::with_capacity(160);
    transcript.extend_from_slice(b"flowersec-e2ee-v1");
    transcript.push(input.version);
    transcript.extend_from_slice(&input.suite.to_be_bytes());
    transcript.push(input.role);
    transcript.extend_from_slice(&input.client_features.to_be_bytes());
    transcript.extend_from_slice(&input.server_features.to_be_bytes());
    append_u16_bytes(&mut transcript, input.channel_id.as_bytes());
    transcript.extend_from_slice(&input.nonce_c);
    transcript.extend_from_slice(&input.nonce_s);
    append_u16_bytes(&mut transcript, input.client_ephemeral_public_key);
    append_u16_bytes(&mut transcript, input.server_ephemeral_public_key);
    Ok(Sha256::digest(&transcript).into())
}

pub fn derive_session_keys(
    psk: &[u8],
    shared_secret: &[u8],
    transcript: [u8; 32],
) -> Result<SessionKeys, E2eeError> {
    if psk.len() != 32 {
        return Err(E2eeError::InvalidPsk);
    }
    let mut input_key_material = Vec::with_capacity(shared_secret.len() + transcript.len());
    input_key_material.extend_from_slice(shared_secret);
    input_key_material.extend_from_slice(&transcript);
    let hkdf = hkdf::Hkdf::<Sha256>::new(Some(psk), &input_key_material);
    Ok(SessionKeys {
        c2s_key: Secret32::new(expand_32(&hkdf, b"flowersec-e2ee-v1:c2s:key")?),
        s2c_key: Secret32::new(expand_32(&hkdf, b"flowersec-e2ee-v1:s2c:key")?),
        rekey_base: Secret32::new(expand_32(&hkdf, b"flowersec-e2ee-v1:rekey_base")?),
        c2s_nonce_prefix: expand_4(&hkdf, b"flowersec-e2ee-v1:c2s:nonce_prefix")?,
        s2c_nonce_prefix: expand_4(&hkdf, b"flowersec-e2ee-v1:s2c:nonce_prefix")?,
    })
}

pub fn compute_auth_tag(
    psk: &[u8],
    transcript: [u8; 32],
    timestamp_unix_s: u64,
) -> Result<[u8; 32], E2eeError> {
    if psk.len() != 32 {
        return Err(E2eeError::InvalidPsk);
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(psk).map_err(|_| E2eeError::InvalidPsk)?;
    mac.update(&transcript);
    mac.update(&timestamp_unix_s.to_be_bytes());
    Ok(mac.finalize().into_bytes().into())
}

pub fn encode_handshake_frame(handshake_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HANDSHAKE_HEADER_LEN + payload.len());
    frame.extend_from_slice(HANDSHAKE_MAGIC);
    frame.push(PROTOCOL_VERSION);
    frame.push(handshake_type);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub fn decode_handshake_frame(
    frame: &[u8],
    max_payload_bytes: usize,
) -> Result<(u8, &[u8]), E2eeError> {
    if frame.len() < HANDSHAKE_HEADER_LEN {
        return Err(E2eeError::InvalidLength);
    }
    if &frame[..4] != HANDSHAKE_MAGIC {
        return Err(E2eeError::InvalidMagic);
    }
    if frame[4] != PROTOCOL_VERSION {
        return Err(E2eeError::InvalidVersion);
    }
    let length = u32::from_be_bytes(frame[6..10].try_into().expect("fixed header")) as usize;
    if length > max_payload_bytes || frame.len() != HANDSHAKE_HEADER_LEN + length {
        return Err(E2eeError::InvalidLength);
    }
    Ok((frame[5], &frame[HANDSHAKE_HEADER_LEN..]))
}

pub fn max_plaintext_bytes(max_record_bytes: usize) -> usize {
    max_record_bytes.saturating_sub(RECORD_HEADER_LEN + GCM_TAG_LEN)
}

pub fn encrypt_record(
    key: &[u8; 32],
    nonce_prefix: [u8; 4],
    flags: RecordFlag,
    sequence: u64,
    plaintext: &[u8],
    max_record_bytes: usize,
) -> Result<Vec<u8>, E2eeError> {
    if RECORD_HEADER_LEN + plaintext.len() + GCM_TAG_LEN > max_record_bytes
        || plaintext.len() + GCM_TAG_LEN > u32::MAX as usize
    {
        return Err(E2eeError::RecordTooLarge);
    }
    let ciphertext_length = plaintext.len() + GCM_TAG_LEN;
    let mut header = Vec::with_capacity(RECORD_HEADER_LEN);
    header.extend_from_slice(RECORD_MAGIC);
    header.push(PROTOCOL_VERSION);
    header.push(flags as u8);
    header.extend_from_slice(&sequence.to_be_bytes());
    header.extend_from_slice(&(ciphertext_length as u32).to_be_bytes());
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| E2eeError::InvalidKey)?;
    let nonce = record_nonce(nonce_prefix, sequence);
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| E2eeError::RecordDecrypt)?;
    header.extend_from_slice(&ciphertext);
    Ok(header)
}

pub fn decrypt_record(
    key: &[u8; 32],
    nonce_prefix: [u8; 4],
    frame: &[u8],
    expected_sequence: u64,
    max_record_bytes: usize,
) -> Result<DecryptedRecord, E2eeError> {
    if frame.len() > max_record_bytes {
        return Err(E2eeError::RecordTooLarge);
    }
    if frame.len() < RECORD_HEADER_LEN + GCM_TAG_LEN {
        return Err(E2eeError::InvalidLength);
    }
    if &frame[..4] != RECORD_MAGIC {
        return Err(E2eeError::InvalidMagic);
    }
    if frame[4] != PROTOCOL_VERSION {
        return Err(E2eeError::InvalidVersion);
    }
    let flags = RecordFlag::try_from(frame[5])?;
    let sequence = u64::from_be_bytes(frame[6..14].try_into().expect("fixed header"));
    if sequence != expected_sequence {
        return Err(E2eeError::InvalidRecordSequence);
    }
    let ciphertext_length =
        u32::from_be_bytes(frame[14..18].try_into().expect("fixed header")) as usize;
    if ciphertext_length < GCM_TAG_LEN || frame.len() != RECORD_HEADER_LEN + ciphertext_length {
        return Err(E2eeError::InvalidLength);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| E2eeError::InvalidKey)?;
    let nonce = record_nonce(nonce_prefix, sequence);
    let plaintext = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &frame[RECORD_HEADER_LEN..],
                aad: &frame[..RECORD_HEADER_LEN],
            },
        )
        .map_err(|_| E2eeError::RecordDecrypt)?;
    Ok(DecryptedRecord {
        flags,
        sequence,
        plaintext,
    })
}

pub fn derive_rekey_key(
    rekey_base: &[u8; 32],
    transcript: [u8; 32],
    sequence: u64,
    direction: Direction,
) -> Result<Secret32, E2eeError> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(rekey_base).map_err(|_| E2eeError::InvalidKey)?;
    mac.update(&transcript);
    mac.update(&sequence.to_be_bytes());
    mac.update(&[direction as u8]);
    let salt: [u8; 32] = mac.finalize().into_bytes().into();
    let hkdf = hkdf::Hkdf::<Sha256>::new(Some(&salt), b"flowersec-e2ee-v1:rekey");
    Ok(Secret32::new(expand_32(
        &hkdf,
        b"flowersec-e2ee-v1:rekey:key",
    )?))
}

fn append_u16_bytes(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u16).to_be_bytes());
    target.extend_from_slice(value);
}

fn expand_32(hkdf: &hkdf::Hkdf<Sha256>, info: &[u8]) -> Result<[u8; 32], E2eeError> {
    let mut output = [0_u8; 32];
    hkdf.expand(info, &mut output)
        .map_err(|_| E2eeError::Hkdf)?;
    Ok(output)
}

fn expand_4(hkdf: &hkdf::Hkdf<Sha256>, info: &[u8]) -> Result<[u8; 4], E2eeError> {
    let mut output = [0_u8; 4];
    hkdf.expand(info, &mut output)
        .map_err(|_| E2eeError::Hkdf)?;
    Ok(output)
}

fn record_nonce(prefix: [u8; 4], sequence: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&prefix);
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

#[derive(Clone, Debug)]
pub struct ClientHandshakeOptions {
    pub psk: Secret32,
    pub suite: Suite,
    pub channel_id: String,
    pub client_features: u32,
    pub max_handshake_payload_bytes: usize,
    pub max_record_bytes: usize,
    pub max_outbound_buffered_bytes: usize,
    pub outbound_record_chunk_bytes: usize,
}

impl ClientHandshakeOptions {
    pub fn new(psk: Secret32, suite: Suite, channel_id: impl Into<String>) -> Self {
        Self {
            psk,
            suite,
            channel_id: channel_id.into(),
            client_features: 0,
            max_handshake_payload_bytes: defaults::MAX_HANDSHAKE_PAYLOAD_BYTES,
            max_record_bytes: defaults::MAX_RECORD_BYTES,
            max_outbound_buffered_bytes: defaults::MAX_OUTBOUND_BUFFERED_BYTES,
            outbound_record_chunk_bytes: defaults::OUTBOUND_RECORD_CHUNK_BYTES,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerHandshakeOptions {
    pub psk: Secret32,
    pub suite: Suite,
    pub channel_id: Option<String>,
    pub init_expires_at_unix_s: i64,
    pub clock_skew: Duration,
    pub server_features: u32,
    pub max_handshake_payload_bytes: usize,
    pub max_record_bytes: usize,
    pub max_outbound_buffered_bytes: usize,
    pub outbound_record_chunk_bytes: usize,
}

impl ServerHandshakeOptions {
    pub fn new(psk: Secret32, suite: Suite, init_expires_at_unix_s: i64) -> Self {
        Self {
            psk,
            suite,
            channel_id: None,
            init_expires_at_unix_s,
            clock_skew: defaults::HANDSHAKE_CLOCK_SKEW,
            server_features: 0,
            max_handshake_payload_bytes: defaults::MAX_HANDSHAKE_PAYLOAD_BYTES,
            max_record_bytes: defaults::MAX_RECORD_BYTES,
            max_outbound_buffered_bytes: defaults::MAX_OUTBOUND_BUFFERED_BYTES,
            outbound_record_chunk_bytes: defaults::OUTBOUND_RECORD_CHUNK_BYTES,
        }
    }
}

#[derive(Debug)]
pub struct ServerHandshakeCache {
    state: Mutex<HashMap<[u8; 32], Arc<CachedServerHandshake>>>,
    ttl: Duration,
    max_entries: usize,
}

#[derive(Debug)]
struct CachedServerHandshake {
    handshake_id: String,
    suite: Suite,
    private_key: EphemeralPrivateKey,
    public_key: Vec<u8>,
    nonce_s: [u8; 32],
    server_features: u32,
    created_at: Instant,
}

impl Default for ServerHandshakeCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(60), 4096)
    }
}

impl ServerHandshakeCache {
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
        }
    }

    async fn get_or_create(
        &self,
        fingerprint: [u8; 32],
        suite: Suite,
        server_features: u32,
    ) -> Result<Arc<CachedServerHandshake>, E2eeError> {
        let mut state = self.state.lock().await;
        if !self.ttl.is_zero() {
            state.retain(|_, value| value.created_at.elapsed() <= self.ttl);
        }
        if let Some(existing) = state.get(&fingerprint) {
            return Ok(existing.clone());
        }
        if self.max_entries > 0 && state.len() >= self.max_entries {
            return Err(E2eeError::TooManyPendingHandshakes);
        }
        let (private_key, public_key) = generate_ephemeral_keypair(suite)?;
        let mut nonce_s = [0_u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_s);
        let mut handshake_id = [0_u8; 24];
        rand::RngCore::fill_bytes(&mut OsRng, &mut handshake_id);
        let value = Arc::new(CachedServerHandshake {
            handshake_id: URL_SAFE_NO_PAD.encode(handshake_id),
            suite,
            private_key,
            public_key,
            nonce_s,
            server_features,
            created_at: Instant::now(),
        });
        state.insert(fingerprint, value.clone());
        Ok(value)
    }

    async fn take(
        &self,
        fingerprint: [u8; 32],
        expected: &Arc<CachedServerHandshake>,
    ) -> Result<Arc<CachedServerHandshake>, E2eeError> {
        let mut state = self.state.lock().await;
        match state.remove(&fingerprint) {
            Some(value) if Arc::ptr_eq(&value, expected) => Ok(value),
            Some(value) => {
                state.insert(fingerprint, value);
                Err(E2eeError::HandshakeStateUnavailable)
            }
            None => Err(E2eeError::HandshakeStateUnavailable),
        }
    }
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
struct SendState {
    key: Secret32,
    nonce_prefix: [u8; 4],
    rekey_base: Secret32,
    transcript: [u8; 32],
    #[zeroize(skip)]
    direction: Direction,
    next_sequence: u64,
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
struct ReceiveState {
    key: Secret32,
    nonce_prefix: [u8; 4],
    rekey_base: Secret32,
    transcript: [u8; 32],
    #[zeroize(skip)]
    direction: Direction,
    next_sequence: u64,
}

pub struct SecureChannel<T: WebSocketTransport> {
    transport: Arc<T>,
    send: Mutex<SendState>,
    receive: Mutex<ReceiveState>,
    max_record_bytes: usize,
    max_outbound_buffered_bytes: usize,
    outbound_record_chunk_bytes: usize,
}

impl<T: WebSocketTransport> std::fmt::Debug for SecureChannel<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecureChannel")
            .field("max_record_bytes", &self.max_record_bytes)
            .field(
                "max_outbound_buffered_bytes",
                &self.max_outbound_buffered_bytes,
            )
            .field(
                "outbound_record_chunk_bytes",
                &self.outbound_record_chunk_bytes,
            )
            .finish_non_exhaustive()
    }
}

impl<T: WebSocketTransport> SecureChannel<T> {
    pub async fn write(&self, payload: &[u8]) -> Result<(), E2eeError> {
        if payload.len() > self.max_outbound_buffered_bytes {
            return Err(E2eeError::RecordTooLarge);
        }
        let max_plaintext = max_plaintext_bytes(self.max_record_bytes);
        let chunk_bytes = self.outbound_record_chunk_bytes.min(max_plaintext);
        if chunk_bytes == 0 {
            return Err(E2eeError::RecordTooLarge);
        }
        let mut send = self.send.lock().await;
        for chunk in payload.chunks(chunk_bytes) {
            let sequence = reserve_sequence(&mut send.next_sequence)?;
            let frame = encrypt_record(
                send.key.expose(),
                send.nonce_prefix,
                RecordFlag::App,
                sequence,
                chunk,
                self.max_record_bytes,
            )?;
            send_binary(&*self.transport, frame).await?;
        }
        Ok(())
    }

    pub async fn read(&self) -> Result<Vec<u8>, E2eeError> {
        let mut receive = self.receive.lock().await;
        loop {
            let frame = receive_binary(&*self.transport).await?;
            let record = decrypt_record(
                receive.key.expose(),
                receive.nonce_prefix,
                &frame,
                receive.next_sequence,
                self.max_record_bytes,
            )?;
            receive.next_sequence = next_sequence(record.sequence)?;
            match record.flags {
                RecordFlag::App => return Ok(record.plaintext),
                RecordFlag::Ping => {}
                RecordFlag::Rekey => {
                    receive.key = derive_rekey_key(
                        receive.rekey_base.expose(),
                        receive.transcript,
                        record.sequence,
                        receive.direction,
                    )?;
                }
            }
        }
    }

    pub async fn ping(&self) -> Result<(), E2eeError> {
        self.send_control(RecordFlag::Ping).await
    }

    pub async fn rekey(&self) -> Result<(), E2eeError> {
        let mut send = self.send.lock().await;
        let sequence = reserve_sequence(&mut send.next_sequence)?;
        let frame = encrypt_record(
            send.key.expose(),
            send.nonce_prefix,
            RecordFlag::Rekey,
            sequence,
            &[],
            self.max_record_bytes,
        )?;
        send_binary(&*self.transport, frame).await?;
        send.key = derive_rekey_key(
            send.rekey_base.expose(),
            send.transcript,
            sequence,
            send.direction,
        )?;
        Ok(())
    }

    pub async fn close(&self) -> Result<(), E2eeError> {
        self.transport.close().await.map_err(E2eeError::Transport)
    }

    async fn send_control(&self, flag: RecordFlag) -> Result<(), E2eeError> {
        let mut send = self.send.lock().await;
        let sequence = reserve_sequence(&mut send.next_sequence)?;
        let frame = encrypt_record(
            send.key.expose(),
            send.nonce_prefix,
            flag,
            sequence,
            &[],
            self.max_record_bytes,
        )?;
        send_binary(&*self.transport, frame).await
    }
}

pub async fn client_handshake<T: WebSocketTransport>(
    transport: Arc<T>,
    options: ClientHandshakeOptions,
) -> Result<SecureChannel<T>, E2eeError> {
    if options.channel_id.is_empty() {
        return Err(E2eeError::InvalidTranscript);
    }
    let (private_key, client_public_key) = generate_ephemeral_keypair(options.suite)?;
    let mut nonce_c = [0_u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_c);
    let init = wire::E2EE_Init {
        channel_id: options.channel_id.clone(),
        role: wire::Role::Client,
        version: PROTOCOL_VERSION,
        suite: wire_suite(options.suite),
        client_eph_pub_b64u: URL_SAFE_NO_PAD.encode(&client_public_key),
        nonce_c_b64u: URL_SAFE_NO_PAD.encode(nonce_c),
        client_features: options.client_features,
    };
    send_handshake(&*transport, HANDSHAKE_TYPE_INIT, &init).await?;
    let (response_type, response_payload) =
        receive_handshake(&*transport, options.max_handshake_payload_bytes).await?;
    if response_type != HANDSHAKE_TYPE_RESP {
        return Err(E2eeError::InvalidLength);
    }
    let response: wire::E2EE_Resp = serde_json::from_slice(&response_payload)?;
    let server_public_key = decode_base64(&response.server_eph_pub_b64u)?;
    let nonce_s = decode_array::<32>(&response.nonce_s_b64u)?;
    let transcript = transcript_hash(&TranscriptInputs {
        version: PROTOCOL_VERSION,
        suite: options.suite as u16,
        role: wire::Role::Client as u8,
        client_features: options.client_features,
        server_features: response.server_features,
        channel_id: &options.channel_id,
        nonce_c,
        nonce_s,
        client_ephemeral_public_key: &client_public_key,
        server_ephemeral_public_key: &server_public_key,
    })?;
    let shared_secret = private_key.derive_shared_secret(&server_public_key)?;
    let keys = derive_session_keys(options.psk.expose(), shared_secret.expose(), transcript)?;
    let timestamp = unix_time_s()?;
    let auth_tag = compute_auth_tag(options.psk.expose(), transcript, timestamp)?;
    send_handshake(
        &*transport,
        HANDSHAKE_TYPE_ACK,
        &wire::E2EE_Ack {
            handshake_id: response.handshake_id,
            timestamp_unix_s: timestamp,
            auth_tag_b64u: URL_SAFE_NO_PAD.encode(auth_tag),
        },
    )
    .await?;
    let finished = receive_binary(&*transport).await?;
    let proof = decrypt_record(
        keys.s2c_key.expose(),
        keys.s2c_nonce_prefix,
        &finished,
        1,
        options.max_record_bytes,
    )?;
    if proof.flags != RecordFlag::Ping || !proof.plaintext.is_empty() {
        return Err(E2eeError::Authentication);
    }
    Ok(secure_channel(
        transport,
        keys,
        transcript,
        true,
        options.max_record_bytes,
        options.max_outbound_buffered_bytes,
        options.outbound_record_chunk_bytes,
    ))
}

pub async fn server_handshake<T: WebSocketTransport>(
    transport: Arc<T>,
    cache: &ServerHandshakeCache,
    options: ServerHandshakeOptions,
) -> Result<SecureChannel<T>, E2eeError> {
    let (init_type, init_payload) =
        receive_handshake(&*transport, options.max_handshake_payload_bytes).await?;
    if init_type != HANDSHAKE_TYPE_INIT {
        return Err(E2eeError::InvalidLength);
    }
    let init: wire::E2EE_Init = serde_json::from_slice(&init_payload)?;
    validate_init(&init, &options)?;
    let suite = suite_from_wire(init.suite);
    let fingerprint: [u8; 32] = Sha256::digest(&init_payload).into();
    let state = cache
        .get_or_create(fingerprint, suite, options.server_features)
        .await?;
    send_server_response(&*transport, &state).await?;

    let ack = loop {
        let (message_type, payload) =
            receive_handshake(&*transport, options.max_handshake_payload_bytes).await?;
        if message_type == HANDSHAKE_TYPE_INIT {
            let retry_fingerprint: [u8; 32] = Sha256::digest(&payload).into();
            if retry_fingerprint != fingerprint {
                return Err(E2eeError::Authentication);
            }
            send_server_response(&*transport, &state).await?;
            continue;
        }
        if message_type != HANDSHAKE_TYPE_ACK {
            return Err(E2eeError::InvalidLength);
        }
        break serde_json::from_slice::<wire::E2EE_Ack>(&payload)?;
    };
    let state = cache.take(fingerprint, &state).await?;
    if ack.handshake_id != state.handshake_id {
        return Err(E2eeError::Authentication);
    }
    validate_timestamp(ack.timestamp_unix_s, &options)?;
    let client_public_key = decode_base64(&init.client_eph_pub_b64u)?;
    let nonce_c = decode_array::<32>(&init.nonce_c_b64u)?;
    let transcript = transcript_hash(&TranscriptInputs {
        version: PROTOCOL_VERSION,
        suite: state.suite as u16,
        role: wire::Role::Client as u8,
        client_features: init.client_features,
        server_features: state.server_features,
        channel_id: &init.channel_id,
        nonce_c,
        nonce_s: state.nonce_s,
        client_ephemeral_public_key: &client_public_key,
        server_ephemeral_public_key: &state.public_key,
    })?;
    let expected_tag = compute_auth_tag(options.psk.expose(), transcript, ack.timestamp_unix_s)?;
    let actual_tag = decode_array::<32>(&ack.auth_tag_b64u)?;
    if !constant_time_eq(&expected_tag, &actual_tag) {
        return Err(E2eeError::Authentication);
    }
    let shared_secret = state.private_key.derive_shared_secret(&client_public_key)?;
    let keys = derive_session_keys(options.psk.expose(), shared_secret.expose(), transcript)?;
    let finished = encrypt_record(
        keys.s2c_key.expose(),
        keys.s2c_nonce_prefix,
        RecordFlag::Ping,
        1,
        &[],
        options.max_record_bytes,
    )?;
    send_binary(&*transport, finished).await?;
    Ok(secure_channel(
        transport,
        keys,
        transcript,
        false,
        options.max_record_bytes,
        options.max_outbound_buffered_bytes,
        options.outbound_record_chunk_bytes,
    ))
}

fn secure_channel<T: WebSocketTransport>(
    transport: Arc<T>,
    keys: SessionKeys,
    transcript: [u8; 32],
    client: bool,
    max_record_bytes: usize,
    max_outbound_buffered_bytes: usize,
    outbound_record_chunk_bytes: usize,
) -> SecureChannel<T> {
    let SessionKeys {
        c2s_key,
        s2c_key,
        c2s_nonce_prefix,
        s2c_nonce_prefix,
        rekey_base,
    } = keys;
    let duplicate_rekey = Secret32::new(*rekey_base.expose());
    let (send, receive) = if client {
        (
            SendState {
                key: c2s_key,
                nonce_prefix: c2s_nonce_prefix,
                rekey_base,
                transcript,
                direction: Direction::ClientToServer,
                next_sequence: 1,
            },
            ReceiveState {
                key: s2c_key,
                nonce_prefix: s2c_nonce_prefix,
                rekey_base: duplicate_rekey,
                transcript,
                direction: Direction::ServerToClient,
                next_sequence: 2,
            },
        )
    } else {
        (
            SendState {
                key: s2c_key,
                nonce_prefix: s2c_nonce_prefix,
                rekey_base,
                transcript,
                direction: Direction::ServerToClient,
                next_sequence: 2,
            },
            ReceiveState {
                key: c2s_key,
                nonce_prefix: c2s_nonce_prefix,
                rekey_base: duplicate_rekey,
                transcript,
                direction: Direction::ClientToServer,
                next_sequence: 1,
            },
        )
    };
    SecureChannel {
        transport,
        send: Mutex::new(send),
        receive: Mutex::new(receive),
        max_record_bytes,
        max_outbound_buffered_bytes,
        outbound_record_chunk_bytes,
    }
}

fn validate_init(
    init: &wire::E2EE_Init,
    options: &ServerHandshakeOptions,
) -> Result<(), E2eeError> {
    if init.version != PROTOCOL_VERSION || init.role != wire::Role::Client {
        return Err(E2eeError::InvalidVersion);
    }
    if init.channel_id.is_empty()
        || options
            .channel_id
            .as_ref()
            .is_some_and(|expected| expected != &init.channel_id)
        || suite_from_wire(init.suite) != options.suite
    {
        return Err(E2eeError::Authentication);
    }
    Ok(())
}

fn validate_timestamp(timestamp: u64, options: &ServerHandshakeOptions) -> Result<(), E2eeError> {
    let now = unix_time_s()? as i128;
    let timestamp = timestamp as i128;
    let skew = options.clock_skew.as_secs() as i128;
    if timestamp < now - skew || timestamp > now + skew {
        return Err(E2eeError::InvalidTimestamp);
    }
    if timestamp > options.init_expires_at_unix_s as i128 + skew {
        return Err(E2eeError::InvalidTimestamp);
    }
    Ok(())
}

async fn send_server_response<T: WebSocketTransport>(
    transport: &T,
    state: &CachedServerHandshake,
) -> Result<(), E2eeError> {
    send_handshake(
        transport,
        HANDSHAKE_TYPE_RESP,
        &wire::E2EE_Resp {
            handshake_id: state.handshake_id.clone(),
            server_eph_pub_b64u: URL_SAFE_NO_PAD.encode(&state.public_key),
            nonce_s_b64u: URL_SAFE_NO_PAD.encode(state.nonce_s),
            server_features: state.server_features,
        },
    )
    .await
}

async fn send_handshake<T: WebSocketTransport, M: serde::Serialize>(
    transport: &T,
    handshake_type: u8,
    message: &M,
) -> Result<(), E2eeError> {
    let payload = serde_json::to_vec(message)?;
    send_binary(transport, encode_handshake_frame(handshake_type, &payload)).await
}

async fn receive_handshake<T: WebSocketTransport>(
    transport: &T,
    max_payload_bytes: usize,
) -> Result<(u8, Vec<u8>), E2eeError> {
    let frame = receive_binary(transport).await?;
    let (message_type, payload) = decode_handshake_frame(&frame, max_payload_bytes)?;
    Ok((message_type, payload.to_vec()))
}

async fn send_binary<T: WebSocketTransport>(
    transport: &T,
    payload: Vec<u8>,
) -> Result<(), E2eeError> {
    transport
        .send(WebSocketMessage {
            kind: WebSocketMessageKind::Binary,
            payload: payload.into(),
        })
        .await
        .map_err(E2eeError::Transport)
}

async fn receive_binary<T: WebSocketTransport>(transport: &T) -> Result<Vec<u8>, E2eeError> {
    let message = transport.receive().await?.ok_or(E2eeError::Closed)?;
    if message.kind != WebSocketMessageKind::Binary {
        return Err(E2eeError::InvalidLength);
    }
    Ok(message.payload.to_vec())
}

fn reserve_sequence(next: &mut u64) -> Result<u64, E2eeError> {
    if *next == u64::MAX {
        return Err(E2eeError::InvalidRecordSequence);
    }
    let sequence = *next;
    *next += 1;
    Ok(sequence)
}

fn next_sequence(current: u64) -> Result<u64, E2eeError> {
    current
        .checked_add(1)
        .filter(|next| *next != 0)
        .ok_or(E2eeError::InvalidRecordSequence)
}

fn unix_time_s() -> Result<u64, E2eeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| E2eeError::InvalidTimestamp)
}

fn decode_base64(value: &str) -> Result<Vec<u8>, E2eeError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| E2eeError::InvalidKey)
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], E2eeError> {
    decode_base64(value)?
        .try_into()
        .map_err(|_| E2eeError::InvalidKey)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn wire_suite(suite: Suite) -> wire::Suite {
    match suite {
        Suite::X25519HkdfSha256Aes256Gcm => wire::Suite::X25519HkdfSha256Aes256Gcm,
        Suite::P256HkdfSha256Aes256Gcm => wire::Suite::P256HkdfSha256Aes256Gcm,
    }
}

fn suite_from_wire(suite: wire::Suite) -> Suite {
    match suite {
        wire::Suite::X25519HkdfSha256Aes256Gcm => Suite::X25519HkdfSha256Aes256Gcm,
        wire::Suite::P256HkdfSha256Aes256Gcm => Suite::P256HkdfSha256Aes256Gcm,
    }
}
