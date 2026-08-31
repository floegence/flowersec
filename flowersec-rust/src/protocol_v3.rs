//! Carrier-neutral Flowersec v3 wire and cryptographic primitives.
//!
//! This module is intentionally stateless. Session actors must enforce sequence
//! monotonicity, epoch transitions, replay rejection, and bounded buffering.

#![allow(dead_code)]

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::unicode151_generated::assigned as unicode151_assigned;

pub const SETUP_PREFACE_V3_SIZE: usize = 56;
pub const RECORD_HEADER_V3_SIZE: usize = 24;
pub const INNER_HEADER_V3_SIZE: usize = 8;
pub const AEAD_TAG_V3_SIZE: usize = 16;
pub const MAX_DATA_V3_BYTES: usize = 16_384;
pub const MAX_CIPHERTEXT_V3_BYTES: usize =
    INNER_HEADER_V3_SIZE + MAX_DATA_V3_BYTES + AEAD_TAG_V3_SIZE;
pub const OPEN_FIXED_PAYLOAD_V3_BYTES: usize = 46;
pub const MAX_OPEN_V3_BYTES: usize = 8_192;
pub const MAX_OPEN_KIND_V3_BYTES: usize = 128;
pub const MAX_OPEN_METADATA_V3_BYTES: usize = 4_096;
pub(crate) const UNRELIABLE_HEADER_V3_SIZE: usize = 32;
pub(crate) const MAX_UNRELIABLE_PLAINTEXT_V3_BYTES: usize = 976;
pub(crate) const MAX_UNRELIABLE_WIRE_V3_BYTES: usize =
    UNRELIABLE_HEADER_V3_SIZE + MAX_UNRELIABLE_PLAINTEXT_V3_BYTES + AEAD_TAG_V3_SIZE;

pub(crate) const EPOCH_ZERO_LABEL_V3: &[u8] = b"flowersec v3 epoch zero";
pub(crate) const CONTROL_ROOT_LABEL_V3: &[u8] = b"flowersec v3 control root";
pub(crate) const STREAM_ROOT_LABEL_V3: &[u8] = b"flowersec v3 stream root";
pub(crate) const SETUP_ROOT_LABEL_V3: &[u8] = b"flowersec v3 setup root";
pub(crate) const REKEY_ROOT_LABEL_V3: &[u8] = b"flowersec v3 rekey root";
pub(crate) const NEXT_EPOCH_LABEL_V3: &[u8] = b"flowersec v3 next epoch";
pub(crate) const STREAM_LABEL_V3: &[u8] = b"flowersec v3 stream";
pub(crate) const CONTROL_LABEL_V3: &[u8] = b"flowersec v3 control";
pub(crate) const RECORD_KEY_LABEL_V3: &[u8] = b"flowersec v3 record key";
pub(crate) const NONCE_LABEL_V3: &[u8] = b"flowersec v3 nonce";
pub(crate) const UNRELIABLE_ROOT_LABEL_V3: &[u8] = b"flowersec v3 unreliable root";
pub(crate) const UNRELIABLE_LABEL_V3: &[u8] = b"flowersec v3 unreliable";
pub(crate) const UNRELIABLE_KEY_LABEL_V3: &[u8] = b"flowersec v3 unreliable key";
pub(crate) const UNRELIABLE_NONCE_LABEL_V3: &[u8] = b"flowersec v3 unreliable nonce";
pub(crate) const UNRELIABLE_AAD_LABEL_V3: &[u8] = b"flowersec-v3-unreliable";
pub(crate) const SETUP_MAC_LABEL_V3: &[u8] = b"flowersec-v3-setup";
pub(crate) const RECORD_AAD_LABEL_V3: &[u8] = b"flowersec-v3-record";
pub(crate) const OPEN_DOMAIN_V3: &[u8] = b"flowersec-v3-open\0";

const MAX_OPEN_METADATA_DEPTH: usize = 4;
const MAX_OPEN_METADATA_NODES: usize = 64;
const MAX_OPEN_METADATA_KEYS: usize = 64;
const MAX_OPEN_METADATA_ARRAY: usize = 32;
const MAX_OPEN_METADATA_KEY_BYTES: usize = 64;
const MAX_OPEN_METADATA_STRING_BYTES: usize = 512;
const MAX_IJSON_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const PROTOCOL_V3_VERSION: u8 = 3;

/// Stable failures produced by the v3 wire and cryptographic primitives.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtocolV3Error {
    #[error("invalid v3 direction")]
    InvalidDirection,
    #[error("invalid FSS3 setup preface")]
    InvalidSetupPreface,
    #[error("invalid FSR3 record header")]
    InvalidRecordHeader,
    #[error("FSR3 record is too large")]
    RecordTooLarge,
    #[error("invalid FSR3 inner record")]
    InvalidInnerRecord,
    #[error("invalid Flowersec v3 OPEN payload")]
    InvalidOpenPayload,
    #[error("v3 record authentication failed")]
    Authentication,
    #[error("v3 cryptographic operation failed")]
    Crypto,
    #[error("v3 HKDF expansion failed")]
    Hkdf,
    #[error("invalid Flowersec v3 unreliable message")]
    InvalidUnreliableMessage,
}

/// Direction of one v3 record key schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DirectionV3 {
    ClientToServer = 1,
    ServerToClient = 2,
}

impl TryFrom<u8> for DirectionV3 {
    type Error = ProtocolV3Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ClientToServer),
            2 => Ok(Self::ServerToClient),
            _ => Err(ProtocolV3Error::InvalidDirection),
        }
    }
}

/// AEAD suites defined by the Flowersec v3 profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherSuiteV3 {
    ChaCha20Poly1305,
    Aes256Gcm,
}

/// Role that allocated a logical stream identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StreamOpenerRoleV3 {
    Client = 1,
    Server = 2,
}

/// Directional roots for one session epoch.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EpochRootsV3 {
    epoch_secret: [u8; 32],
    control_root: [u8; 32],
    stream_root: [u8; 32],
    setup_root: [u8; 32],
    rekey_root: [u8; 32],
}

impl EpochRootsV3 {
    pub(crate) fn epoch_secret(&self) -> &[u8; 32] {
        &self.epoch_secret
    }

    pub fn control_root(&self) -> &[u8; 32] {
        &self.control_root
    }

    pub fn stream_root(&self) -> &[u8; 32] {
        &self.stream_root
    }

    pub fn setup_root(&self) -> &[u8; 32] {
        &self.setup_root
    }

    pub fn rekey_root(&self) -> &[u8; 32] {
        &self.rekey_root
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct UnreliableMaterialV3 {
    key: [u8; 32],
    nonce_prefix: [u8; 4],
}

impl std::fmt::Debug for UnreliableMaterialV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("UnreliableMaterialV3([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnreliableHeaderV3 {
    pub epoch: u32,
    pub sequence: u64,
    pub expires_at_unix_ms: u64,
    pub ciphertext_length: u32,
}

impl UnreliableHeaderV3 {
    pub(crate) fn encode(self) -> Result<[u8; UNRELIABLE_HEADER_V3_SIZE], ProtocolV3Error> {
        let ciphertext_length = usize::try_from(self.ciphertext_length)
            .map_err(|_| ProtocolV3Error::InvalidUnreliableMessage)?;
        if !(AEAD_TAG_V3_SIZE + 1..=MAX_UNRELIABLE_PLAINTEXT_V3_BYTES + AEAD_TAG_V3_SIZE)
            .contains(&ciphertext_length)
            || self.expires_at_unix_ms == 0
        {
            return Err(ProtocolV3Error::InvalidUnreliableMessage);
        }
        let mut raw = [0_u8; UNRELIABLE_HEADER_V3_SIZE];
        raw[..4].copy_from_slice(b"FSD3");
        raw[4] = PROTOCOL_V3_VERSION;
        raw[6..8].copy_from_slice(&(UNRELIABLE_HEADER_V3_SIZE as u16).to_be_bytes());
        raw[8..12].copy_from_slice(&self.epoch.to_be_bytes());
        raw[12..20].copy_from_slice(&self.sequence.to_be_bytes());
        raw[20..28].copy_from_slice(&self.expires_at_unix_ms.to_be_bytes());
        raw[28..32].copy_from_slice(&self.ciphertext_length.to_be_bytes());
        Ok(raw)
    }

    pub(crate) fn decode(raw: &[u8]) -> Result<Self, ProtocolV3Error> {
        if raw.len() != UNRELIABLE_HEADER_V3_SIZE
            || &raw[..4] != b"FSD3"
            || raw[4] != PROTOCOL_V3_VERSION
            || raw[5] != 0
            || u16::from_be_bytes(raw[6..8].try_into().unwrap()) != UNRELIABLE_HEADER_V3_SIZE as u16
        {
            return Err(ProtocolV3Error::InvalidUnreliableMessage);
        }
        let header = Self {
            epoch: u32::from_be_bytes(raw[8..12].try_into().unwrap()),
            sequence: u64::from_be_bytes(raw[12..20].try_into().unwrap()),
            expires_at_unix_ms: u64::from_be_bytes(raw[20..28].try_into().unwrap()),
            ciphertext_length: u32::from_be_bytes(raw[28..32].try_into().unwrap()),
        };
        header.encode()?;
        Ok(header)
    }
}

impl std::fmt::Debug for EpochRootsV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EpochRootsV3([REDACTED])")
    }
}

/// Per-stream record key material for one direction and epoch.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecordMaterialV3 {
    secret: [u8; 32],
    record_key: [u8; 32],
    nonce_prefix: [u8; 4],
}

impl RecordMaterialV3 {
    #[cfg(test)]
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    pub fn record_key(&self) -> &[u8; 32] {
        &self.record_key
    }

    pub fn nonce_prefix(&self) -> &[u8; 4] {
        &self.nonce_prefix
    }
}

impl std::fmt::Debug for RecordMaterialV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RecordMaterialV3([REDACTED])")
    }
}

/// Fixed FSS3 setup preface fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupPrefaceV3 {
    opener_role: StreamOpenerRoleV3,
    logical_stream_id: u64,
    initial_epoch: u32,
    setup_mac: [u8; 32],
}

impl SetupPrefaceV3 {
    pub fn new(
        opener_role: StreamOpenerRoleV3,
        logical_stream_id: u64,
        initial_epoch: u32,
    ) -> Self {
        Self {
            opener_role,
            logical_stream_id,
            initial_epoch,
            setup_mac: [0; 32],
        }
    }

    pub fn set_setup_mac(&mut self, setup_mac: [u8; 32]) {
        self.setup_mac = setup_mac;
    }

    pub const fn opener_role(&self) -> StreamOpenerRoleV3 {
        self.opener_role
    }

    pub const fn logical_stream_id(&self) -> u64 {
        self.logical_stream_id
    }

    pub const fn initial_epoch(&self) -> u32 {
        self.initial_epoch
    }

    pub const fn setup_mac(&self) -> &[u8; 32] {
        &self.setup_mac
    }

    pub fn encode(&self) -> Result<[u8; SETUP_PREFACE_V3_SIZE], ProtocolV3Error> {
        if !valid_logical_stream_id(self.opener_role, self.logical_stream_id) {
            return Err(ProtocolV3Error::InvalidSetupPreface);
        }
        let mut output = [0_u8; SETUP_PREFACE_V3_SIZE];
        output[..4].copy_from_slice(b"FSS3");
        output[4] = PROTOCOL_V3_VERSION;
        output[5] = self.opener_role as u8;
        output[8..16].copy_from_slice(&self.logical_stream_id.to_be_bytes());
        output[16..20].copy_from_slice(&self.initial_epoch.to_be_bytes());
        output[24..].copy_from_slice(&self.setup_mac);
        Ok(output)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, ProtocolV3Error> {
        if raw.len() != SETUP_PREFACE_V3_SIZE
            || &raw[..4] != b"FSS3"
            || raw[4] != PROTOCOL_V3_VERSION
            || raw[6] != 0
            || raw[7] != 0
            || raw[20..24] != [0; 4]
        {
            return Err(ProtocolV3Error::InvalidSetupPreface);
        }
        let opener_role = match raw[5] {
            1 => StreamOpenerRoleV3::Client,
            2 => StreamOpenerRoleV3::Server,
            _ => return Err(ProtocolV3Error::InvalidSetupPreface),
        };
        let logical_stream_id = u64::from_be_bytes(raw[8..16].try_into().unwrap());
        if !valid_logical_stream_id(opener_role, logical_stream_id) {
            return Err(ProtocolV3Error::InvalidSetupPreface);
        }
        let mut setup_mac = [0; 32];
        setup_mac.copy_from_slice(&raw[24..56]);
        Ok(Self {
            opener_role,
            logical_stream_id,
            initial_epoch: u32::from_be_bytes(raw[16..20].try_into().unwrap()),
            setup_mac,
        })
    }
}

/// Fixed authenticated FSR3 record header fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordHeaderV3 {
    epoch: u32,
    sequence: u64,
    ciphertext_length: u32,
}

/// Canonical Flowersec v3 OPEN fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenPayloadV3 {
    logical_stream_id: u64,
    fss3_hash: [u8; 32],
    kind: String,
    metadata: Vec<u8>,
}

impl OpenPayloadV3 {
    pub fn new(
        logical_stream_id: u64,
        fss3_hash: [u8; 32],
        kind: String,
        metadata: Vec<u8>,
    ) -> Self {
        Self {
            logical_stream_id,
            fss3_hash,
            kind,
            metadata,
        }
    }

    pub const fn logical_stream_id(&self) -> u64 {
        self.logical_stream_id
    }

    pub const fn fss3_hash(&self) -> &[u8; 32] {
        &self.fss3_hash
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }
}

impl RecordHeaderV3 {
    pub const fn new(epoch: u32, sequence: u64, ciphertext_length: u32) -> Self {
        Self {
            epoch,
            sequence,
            ciphertext_length,
        }
    }

    pub const fn ciphertext_length(self) -> u32 {
        self.ciphertext_length
    }

    pub const fn epoch(self) -> u32 {
        self.epoch
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub fn encode(&self) -> Result<[u8; RECORD_HEADER_V3_SIZE], ProtocolV3Error> {
        if self.ciphertext_length < AEAD_TAG_V3_SIZE as u32 {
            return Err(ProtocolV3Error::InvalidRecordHeader);
        }
        if self.ciphertext_length as usize > MAX_CIPHERTEXT_V3_BYTES {
            return Err(ProtocolV3Error::RecordTooLarge);
        }
        let mut output = [0_u8; RECORD_HEADER_V3_SIZE];
        output[..4].copy_from_slice(b"FSR3");
        output[4] = PROTOCOL_V3_VERSION;
        output[5] = RECORD_HEADER_V3_SIZE as u8;
        output[8..12].copy_from_slice(&self.epoch.to_be_bytes());
        output[12..20].copy_from_slice(&self.sequence.to_be_bytes());
        output[20..24].copy_from_slice(&self.ciphertext_length.to_be_bytes());
        Ok(output)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, ProtocolV3Error> {
        if raw.len() != RECORD_HEADER_V3_SIZE
            || &raw[..4] != b"FSR3"
            || raw[4] != PROTOCOL_V3_VERSION
            || raw[5] != RECORD_HEADER_V3_SIZE as u8
            || raw[6] != 0
            || raw[7] != 0
        {
            return Err(ProtocolV3Error::InvalidRecordHeader);
        }
        let header = Self::new(
            u32::from_be_bytes(raw[8..12].try_into().unwrap()),
            u64::from_be_bytes(raw[12..20].try_into().unwrap()),
            u32::from_be_bytes(raw[20..24].try_into().unwrap()),
        );
        header.encode()?;
        Ok(header)
    }
}

/// Inner record types implemented by this crypto slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InnerRecordTypeV3 {
    Open = 1,
    OpenAck = 2,
    OpenReject = 3,
    Data = 4,
    Fin = 5,
    StreamKeyUpdate = 6,
    SessionReady = 16,
    Ping = 17,
    Pong = 18,
    SessionKeyUpdate = 19,
    StreamReset = 20,
    GoAway = 21,
    SessionClose = 22,
    SessionReadyAck = 23,
    SessionKeyUpdateAck = 24,
    StreamKeyUpdateAck = 25,
    SessionReadyConfirm = 26,
}

impl TryFrom<u8> for InnerRecordTypeV3 {
    type Error = ProtocolV3Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Open),
            2 => Ok(Self::OpenAck),
            3 => Ok(Self::OpenReject),
            4 => Ok(Self::Data),
            5 => Ok(Self::Fin),
            6 => Ok(Self::StreamKeyUpdate),
            16 => Ok(Self::SessionReady),
            17 => Ok(Self::Ping),
            18 => Ok(Self::Pong),
            19 => Ok(Self::SessionKeyUpdate),
            20 => Ok(Self::StreamReset),
            21 => Ok(Self::GoAway),
            22 => Ok(Self::SessionClose),
            23 => Ok(Self::SessionReadyAck),
            24 => Ok(Self::SessionKeyUpdateAck),
            25 => Ok(Self::StreamKeyUpdateAck),
            26 => Ok(Self::SessionReadyConfirm),
            _ => Err(ProtocolV3Error::InvalidInnerRecord),
        }
    }
}

/// Derives the directional epoch-zero roots from an existing session PRK.
pub fn derive_epoch_zero_v3(
    session_prk: &[u8; 32],
    direction: DirectionV3,
) -> Result<EpochRootsV3, ProtocolV3Error> {
    let epoch_secret = expand_32(
        session_prk,
        &label_with(EPOCH_ZERO_LABEL_V3, &[&[direction as u8]]),
    )?;
    Ok(EpochRootsV3 {
        epoch_secret,
        control_root: expand_32(&epoch_secret, &label_with(CONTROL_ROOT_LABEL_V3, &[]))?,
        stream_root: expand_32(&epoch_secret, &label_with(STREAM_ROOT_LABEL_V3, &[]))?,
        setup_root: expand_32(&epoch_secret, &label_with(SETUP_ROOT_LABEL_V3, &[]))?,
        rekey_root: expand_32(&epoch_secret, &label_with(REKEY_ROOT_LABEL_V3, &[]))?,
    })
}

/// Derives record material for one logical stream, direction, and epoch.
pub fn derive_stream_material_v3(
    stream_root: &[u8; 32],
    h3: &[u8; 32],
    logical_stream_id: u64,
    direction: DirectionV3,
    epoch: u32,
) -> Result<RecordMaterialV3, ProtocolV3Error> {
    if logical_stream_id == 0 {
        return Err(ProtocolV3Error::InvalidSetupPreface);
    }
    let stream_id = logical_stream_id.to_be_bytes();
    let epoch_bytes = epoch.to_be_bytes();
    let secret = expand_32(
        stream_root,
        &label_with(
            STREAM_LABEL_V3,
            &[h3, &stream_id, &[direction as u8], &epoch_bytes],
        ),
    )?;
    Ok(RecordMaterialV3 {
        secret,
        record_key: expand_32(&secret, &label_with(RECORD_KEY_LABEL_V3, &[]))?,
        nonce_prefix: expand_4(&secret, &label_with(NONCE_LABEL_V3, &[]))?,
    })
}

pub fn derive_control_material_v3(
    control_root: &[u8; 32],
    h3: &[u8; 32],
    direction: DirectionV3,
    epoch: u32,
) -> Result<RecordMaterialV3, ProtocolV3Error> {
    let epoch_bytes = epoch.to_be_bytes();
    let stream_id = 0_u64.to_be_bytes();
    let secret = expand_32(
        control_root,
        &label_with(
            CONTROL_LABEL_V3,
            &[h3, &stream_id, &[direction as u8], &epoch_bytes],
        ),
    )?;
    Ok(RecordMaterialV3 {
        secret,
        record_key: expand_32(&secret, &label_with(RECORD_KEY_LABEL_V3, &[]))?,
        nonce_prefix: expand_4(&secret, &label_with(NONCE_LABEL_V3, &[]))?,
    })
}

pub(crate) fn derive_unreliable_material_v3(
    roots: &EpochRootsV3,
    h3: &[u8; 32],
    direction: DirectionV3,
    epoch: u32,
) -> Result<UnreliableMaterialV3, ProtocolV3Error> {
    let unreliable_root = expand_32(
        roots.epoch_secret(),
        &label_with(UNRELIABLE_ROOT_LABEL_V3, &[]),
    )?;
    let material = expand_32(
        &unreliable_root,
        &label_with(
            UNRELIABLE_LABEL_V3,
            &[h3, &[direction as u8], &epoch.to_be_bytes()],
        ),
    )?;
    Ok(UnreliableMaterialV3 {
        key: expand_32(&material, &label_with(UNRELIABLE_KEY_LABEL_V3, &[]))?,
        nonce_prefix: expand_4(&material, &label_with(UNRELIABLE_NONCE_LABEL_V3, &[]))?,
    })
}

pub(crate) fn seal_unreliable_v3(
    suite: CipherSuiteV3,
    material: &UnreliableMaterialV3,
    h3: &[u8; 32],
    direction: DirectionV3,
    header: UnreliableHeaderV3,
    plaintext: &[u8],
) -> Result<Vec<u8>, ProtocolV3Error> {
    if plaintext.is_empty()
        || plaintext.len() > MAX_UNRELIABLE_PLAINTEXT_V3_BYTES
        || plaintext.len() + AEAD_TAG_V3_SIZE != header.ciphertext_length as usize
    {
        return Err(ProtocolV3Error::InvalidUnreliableMessage);
    }
    let raw_header = header.encode()?;
    let aad = label_with(
        UNRELIABLE_AAD_LABEL_V3,
        &[h3, &[direction as u8], &raw_header],
    );
    let nonce = record_nonce(material.nonce_prefix, header.sequence);
    match suite {
        CipherSuiteV3::ChaCha20Poly1305 => seal_chacha(&material.key, nonce, &aad, plaintext),
        CipherSuiteV3::Aes256Gcm => {
            let cipher =
                Aes256Gcm::new_from_slice(&material.key).map_err(|_| ProtocolV3Error::Crypto)?;
            cipher
                .encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| ProtocolV3Error::Crypto)
        }
    }
}

pub(crate) fn open_unreliable_v3(
    suite: CipherSuiteV3,
    material: &UnreliableMaterialV3,
    h3: &[u8; 32],
    direction: DirectionV3,
    header: UnreliableHeaderV3,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ProtocolV3Error> {
    if ciphertext.len() != header.ciphertext_length as usize {
        return Err(ProtocolV3Error::InvalidUnreliableMessage);
    }
    let raw_header = header.encode()?;
    let aad = label_with(
        UNRELIABLE_AAD_LABEL_V3,
        &[h3, &[direction as u8], &raw_header],
    );
    let nonce = record_nonce(material.nonce_prefix, header.sequence);
    match suite {
        CipherSuiteV3::ChaCha20Poly1305 => open_chacha(&material.key, nonce, &aad, ciphertext),
        CipherSuiteV3::Aes256Gcm => {
            let cipher =
                Aes256Gcm::new_from_slice(&material.key).map_err(|_| ProtocolV3Error::Crypto)?;
            cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| ProtocolV3Error::Authentication)
        }
    }
}

pub fn derive_next_epoch_v3(
    rekey_root: &[u8; 32],
    h3: &[u8; 32],
    direction: DirectionV3,
    next_epoch: u32,
) -> Result<EpochRootsV3, ProtocolV3Error> {
    let epoch = next_epoch.to_be_bytes();
    let secret = expand_32(
        rekey_root,
        &label_with(NEXT_EPOCH_LABEL_V3, &[h3, &[direction as u8], &epoch]),
    )?;
    Ok(EpochRootsV3 {
        epoch_secret: secret,
        control_root: expand_32(&secret, &label_with(CONTROL_ROOT_LABEL_V3, &[]))?,
        stream_root: expand_32(&secret, &label_with(STREAM_ROOT_LABEL_V3, &[]))?,
        setup_root: expand_32(&secret, &label_with(SETUP_ROOT_LABEL_V3, &[]))?,
        rekey_root: expand_32(&secret, &label_with(REKEY_ROOT_LABEL_V3, &[]))?,
    })
}

/// Computes the setup MAC over the fixed preface fields and handshake hash.
pub fn compute_setup_mac_v3(
    setup_root: &[u8; 32],
    h3: &[u8; 32],
    preface: &SetupPrefaceV3,
) -> Result<[u8; 32], ProtocolV3Error> {
    let raw = preface.encode()?;
    let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(setup_root)
        .map_err(|_| ProtocolV3Error::Crypto)?;
    mac.update(&label_with(SETUP_MAC_LABEL_V3, &[]));
    mac.update(h3);
    mac.update(&raw[..24]);
    Ok(mac.finalize().into_bytes().into())
}

pub fn verify_setup_mac_v3(setup_root: &[u8; 32], h3: &[u8; 32], preface: &SetupPrefaceV3) -> bool {
    use subtle::ConstantTimeEq;
    compute_setup_mac_v3(setup_root, h3, preface)
        .map(|expected| expected.ct_eq(preface.setup_mac()).into())
        .unwrap_or(false)
}

pub fn compute_fss3_hash_v3(raw: &[u8]) -> Result<[u8; 32], ProtocolV3Error> {
    SetupPrefaceV3::decode(raw)?;
    Ok(Sha256::digest(raw).into())
}

pub fn compute_open_hash_v3(raw: &[u8]) -> Result<[u8; 32], ProtocolV3Error> {
    decode_open_payload_v3(raw)?;
    let mut hash = Sha256::new();
    hash.update(OPEN_DOMAIN_V3);
    hash.update((raw.len() as u32).to_be_bytes());
    hash.update(raw);
    Ok(hash.finalize().into())
}

/// Encodes one bounded inner record.
pub fn encode_inner_record_v3(
    record_type: InnerRecordTypeV3,
    payload: &[u8],
) -> Result<Vec<u8>, ProtocolV3Error> {
    validate_inner_payload(record_type, payload.len())?;
    let payload_length =
        u32::try_from(payload.len()).map_err(|_| ProtocolV3Error::InvalidInnerRecord)?;
    let mut output = Vec::with_capacity(INNER_HEADER_V3_SIZE + payload.len());
    output.push(record_type as u8);
    output.extend_from_slice(&[0; 3]);
    output.extend_from_slice(&payload_length.to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn decode_inner_record_v3(raw: &[u8]) -> Result<(InnerRecordTypeV3, &[u8]), ProtocolV3Error> {
    if raw.len() < INNER_HEADER_V3_SIZE || raw[1..4] != [0; 3] {
        return Err(ProtocolV3Error::InvalidInnerRecord);
    }
    let payload_length = u32::from_be_bytes(raw[4..8].try_into().unwrap()) as usize;
    if INNER_HEADER_V3_SIZE.checked_add(payload_length) != Some(raw.len()) {
        return Err(ProtocolV3Error::InvalidInnerRecord);
    }
    let record_type = InnerRecordTypeV3::try_from(raw[0])?;
    validate_inner_payload(record_type, payload_length)?;
    Ok((record_type, &raw[INNER_HEADER_V3_SIZE..]))
}

#[cfg(test)]
pub(crate) fn security_accepts(kind: &str, raw: &[u8]) -> bool {
    match kind {
        "fsr3_hex" => RecordHeaderV3::decode(raw).is_ok(),
        "open_hex" => decode_open_payload_v3(raw).is_ok(),
        _ => false,
    }
}

#[cfg(feature = "__flowersec_internal_fuzzing")]
pub fn fuzz_parse(raw: &[u8]) {
    let _ = SetupPrefaceV3::decode(raw);
    let _ = RecordHeaderV3::decode(raw);
    let _ = UnreliableHeaderV3::decode(raw);
    let _ = decode_inner_record_v3(raw);
    let _ = decode_open_payload_v3(raw);
}

fn validate_inner_payload(
    record_type: InnerRecordTypeV3,
    payload_length: usize,
) -> Result<(), ProtocolV3Error> {
    let valid = match record_type {
        InnerRecordTypeV3::Open => (1..=MAX_OPEN_V3_BYTES).contains(&payload_length),
        InnerRecordTypeV3::Data => (1..=MAX_DATA_V3_BYTES).contains(&payload_length),
        InnerRecordTypeV3::Fin
        | InnerRecordTypeV3::SessionReady
        | InnerRecordTypeV3::SessionReadyAck
        | InnerRecordTypeV3::SessionReadyConfirm => payload_length == 0,
        InnerRecordTypeV3::OpenAck => payload_length == 32,
        InnerRecordTypeV3::OpenReject => payload_length == 34,
        InnerRecordTypeV3::StreamKeyUpdate => payload_length == 12,
        InnerRecordTypeV3::Ping | InnerRecordTypeV3::Pong => payload_length == 8,
        InnerRecordTypeV3::SessionKeyUpdate
        | InnerRecordTypeV3::SessionKeyUpdateAck
        | InnerRecordTypeV3::StreamKeyUpdateAck => payload_length == 20,
        InnerRecordTypeV3::StreamReset | InnerRecordTypeV3::GoAway => payload_length == 10,
        InnerRecordTypeV3::SessionClose => payload_length == 2,
    };
    valid
        .then_some(())
        .ok_or(ProtocolV3Error::InvalidInnerRecord)
}

/// Encodes one canonical OPEN payload.
pub fn encode_open_payload_v3(payload: &OpenPayloadV3) -> Result<Vec<u8>, ProtocolV3Error> {
    if payload.logical_stream_id == 0 || !valid_open_kind(&payload.kind) {
        return Err(ProtocolV3Error::InvalidOpenPayload);
    }
    let metadata = canonical_open_metadata(&payload.metadata, true)?;
    let total = OPEN_FIXED_PAYLOAD_V3_BYTES
        .checked_add(payload.kind.len())
        .and_then(|value| value.checked_add(metadata.len()))
        .filter(|value| *value <= MAX_OPEN_V3_BYTES)
        .ok_or(ProtocolV3Error::InvalidOpenPayload)?;
    let kind_length =
        u16::try_from(payload.kind.len()).map_err(|_| ProtocolV3Error::InvalidOpenPayload)?;
    let metadata_length =
        u32::try_from(metadata.len()).map_err(|_| ProtocolV3Error::InvalidOpenPayload)?;
    let mut output = vec![0_u8; total];
    output[..8].copy_from_slice(&payload.logical_stream_id.to_be_bytes());
    output[8..40].copy_from_slice(&payload.fss3_hash);
    output[40..42].copy_from_slice(&kind_length.to_be_bytes());
    output[42..46].copy_from_slice(&metadata_length.to_be_bytes());
    output[46..46 + payload.kind.len()].copy_from_slice(payload.kind.as_bytes());
    output[46 + payload.kind.len()..].copy_from_slice(&metadata);
    Ok(output)
}

/// Decodes and validates one canonical OPEN payload.
pub fn decode_open_payload_v3(raw: &[u8]) -> Result<OpenPayloadV3, ProtocolV3Error> {
    if raw.len() < OPEN_FIXED_PAYLOAD_V3_BYTES || raw.len() > MAX_OPEN_V3_BYTES {
        return Err(ProtocolV3Error::InvalidOpenPayload);
    }
    let logical_stream_id = u64::from_be_bytes(
        raw[..8]
            .try_into()
            .map_err(|_| ProtocolV3Error::InvalidOpenPayload)?,
    );
    if logical_stream_id == 0 {
        return Err(ProtocolV3Error::InvalidOpenPayload);
    }
    let kind_length = usize::from(u16::from_be_bytes([raw[40], raw[41]]));
    let metadata_length = u32::from_be_bytes(raw[42..46].try_into().unwrap()) as usize;
    if OPEN_FIXED_PAYLOAD_V3_BYTES
        .checked_add(kind_length)
        .and_then(|value| value.checked_add(metadata_length))
        != Some(raw.len())
    {
        return Err(ProtocolV3Error::InvalidOpenPayload);
    }
    let kind_end = 46 + kind_length;
    let kind = std::str::from_utf8(&raw[46..kind_end])
        .map_err(|_| ProtocolV3Error::InvalidOpenPayload)?
        .to_owned();
    if !valid_open_kind(&kind) {
        return Err(ProtocolV3Error::InvalidOpenPayload);
    }
    let metadata = canonical_open_metadata(&raw[kind_end..], false)?;
    let mut fss3_hash = [0_u8; 32];
    fss3_hash.copy_from_slice(&raw[8..40]);
    Ok(OpenPayloadV3::new(
        logical_stream_id,
        fss3_hash,
        kind,
        metadata,
    ))
}

/// Builds the AAD binding a record to its handshake, stream, and direction.
pub fn record_aad_v3(
    h3: &[u8; 32],
    logical_stream_id: u64,
    direction: DirectionV3,
    header: &RecordHeaderV3,
) -> Result<Vec<u8>, ProtocolV3Error> {
    let stream_id = logical_stream_id.to_be_bytes();
    let raw_header = header.encode()?;
    Ok(label_with(
        RECORD_AAD_LABEL_V3,
        &[h3, &stream_id, &[direction as u8], &raw_header],
    ))
}

#[allow(clippy::too_many_arguments)]
/// Seals one record. Callers must never reuse a key/sequence nonce pair.
pub fn seal_record_v3(
    suite: CipherSuiteV3,
    key: &[u8; 32],
    nonce_prefix: &[u8; 4],
    h3: &[u8; 32],
    logical_stream_id: u64,
    direction: DirectionV3,
    header: &RecordHeaderV3,
    plaintext: &[u8],
) -> Result<Vec<u8>, ProtocolV3Error> {
    if plaintext
        .len()
        .checked_add(AEAD_TAG_V3_SIZE)
        .and_then(|length| u32::try_from(length).ok())
        != Some(header.ciphertext_length)
    {
        return Err(ProtocolV3Error::InvalidRecordHeader);
    }
    let aad = record_aad_v3(h3, logical_stream_id, direction, header)?;
    let nonce = record_nonce(*nonce_prefix, header.sequence);
    match suite {
        CipherSuiteV3::ChaCha20Poly1305 => seal_chacha(key, nonce, &aad, plaintext),
        CipherSuiteV3::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ProtocolV3Error::Crypto)?;
            cipher
                .encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| ProtocolV3Error::Crypto)
        }
    }
}

#[allow(clippy::too_many_arguments)]
/// Authenticates and opens one record under its complete record context.
pub fn open_record_v3(
    suite: CipherSuiteV3,
    key: &[u8; 32],
    nonce_prefix: &[u8; 4],
    h3: &[u8; 32],
    logical_stream_id: u64,
    direction: DirectionV3,
    header: &RecordHeaderV3,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ProtocolV3Error> {
    if ciphertext.len() != header.ciphertext_length as usize {
        return Err(ProtocolV3Error::InvalidRecordHeader);
    }
    let aad = record_aad_v3(h3, logical_stream_id, direction, header)?;
    let nonce = record_nonce(*nonce_prefix, header.sequence);
    match suite {
        CipherSuiteV3::ChaCha20Poly1305 => open_chacha(key, nonce, &aad, ciphertext),
        CipherSuiteV3::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ProtocolV3Error::Crypto)?;
            cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| ProtocolV3Error::Authentication)
        }
    }
}

fn seal_chacha(
    key: &[u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, ProtocolV3Error> {
    let key = LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| ProtocolV3Error::Crypto)?,
    );
    let mut output = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut output,
    )
    .map_err(|_| ProtocolV3Error::Crypto)?;
    Ok(output)
}

fn open_chacha(
    key: &[u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ProtocolV3Error> {
    let key = LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| ProtocolV3Error::Crypto)?,
    );
    let mut output = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut output,
        )
        .map_err(|_| ProtocolV3Error::Authentication)?;
    Ok(plaintext.to_vec())
}

fn record_nonce(prefix: [u8; 4], sequence: u64) -> [u8; 12] {
    let sequence_bytes = sequence.to_be_bytes();
    std::array::from_fn(|index| match index {
        0..4 => prefix[index],
        index => sequence_bytes[index - 4],
    })
}

fn valid_logical_stream_id(role: StreamOpenerRoleV3, logical_stream_id: u64) -> bool {
    match role {
        StreamOpenerRoleV3::Client => logical_stream_id != 0 && logical_stream_id & 1 == 1,
        StreamOpenerRoleV3::Server => logical_stream_id != 0 && logical_stream_id & 1 == 0,
    }
}

fn expand_32(prk: &[u8; 32], info: &[u8]) -> Result<[u8; 32], ProtocolV3Error> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|_| ProtocolV3Error::Hkdf)?;
    let mut output = [0_u8; 32];
    hkdf.expand(info, &mut output)
        .map_err(|_| ProtocolV3Error::Hkdf)?;
    Ok(output)
}

fn expand_4(prk: &[u8; 32], info: &[u8]) -> Result<[u8; 4], ProtocolV3Error> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|_| ProtocolV3Error::Hkdf)?;
    let mut output = [0_u8; 4];
    hkdf.expand(info, &mut output)
        .map_err(|_| ProtocolV3Error::Hkdf)?;
    Ok(output)
}

fn label_with(label: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let capacity = label.len() + 1 + parts.iter().map(|part| part.len()).sum::<usize>();
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(label);
    output.push(0);
    for part in parts {
        output.extend_from_slice(part);
    }
    output
}

pub(crate) fn valid_open_kind(value: &str) -> bool {
    if !valid_open_unicode_string(value, MAX_OPEN_KIND_V3_BYTES, false) {
        return false;
    }
    let Some(first) = value.chars().next() else {
        return false;
    };
    let Some(last) = value.chars().next_back() else {
        return false;
    };
    !first.is_whitespace() && !last.is_whitespace()
}

fn canonical_open_metadata(raw: &[u8], allow_empty: bool) -> Result<Vec<u8>, ProtocolV3Error> {
    if raw.is_empty() && allow_empty {
        return Ok(b"{}".to_vec());
    }
    if raw.is_empty() || raw.len() > MAX_OPEN_METADATA_V3_BYTES {
        return Err(ProtocolV3Error::InvalidOpenPayload);
    }
    let value: Value =
        serde_json::from_slice(raw).map_err(|_| ProtocolV3Error::InvalidOpenPayload)?;
    if !value.is_object() {
        return Err(ProtocolV3Error::InvalidOpenPayload);
    }
    let mut nodes = -1_i32;
    validate_metadata_value(&value, 1, &mut nodes)?;
    let mut canonical = Vec::with_capacity(raw.len());
    append_canonical_json(&mut canonical, &value)?;
    if canonical.len() > MAX_OPEN_METADATA_V3_BYTES || canonical != raw {
        return Err(ProtocolV3Error::InvalidOpenPayload);
    }
    Ok(canonical)
}

pub(crate) fn canonical_open_metadata_value_v3(value: &Value) -> Result<Vec<u8>, ProtocolV3Error> {
    if !value.is_object() {
        return Err(ProtocolV3Error::InvalidOpenPayload);
    }
    let mut nodes = -1_i32;
    validate_metadata_value(value, 1, &mut nodes)?;
    let mut canonical = Vec::new();
    append_canonical_json(&mut canonical, value)?;
    if canonical.len() > MAX_OPEN_METADATA_V3_BYTES {
        return Err(ProtocolV3Error::InvalidOpenPayload);
    }
    Ok(canonical)
}

fn validate_metadata_value(
    value: &Value,
    depth: usize,
    nodes: &mut i32,
) -> Result<(), ProtocolV3Error> {
    if depth > MAX_OPEN_METADATA_DEPTH {
        return Err(ProtocolV3Error::InvalidOpenPayload);
    }
    *nodes += 1;
    if *nodes > MAX_OPEN_METADATA_NODES as i32 {
        return Err(ProtocolV3Error::InvalidOpenPayload);
    }
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(number) => match number.as_i64() {
            Some(value) if (-MAX_IJSON_SAFE_INTEGER..=MAX_IJSON_SAFE_INTEGER).contains(&value) => {
                Ok(())
            }
            _ => Err(ProtocolV3Error::InvalidOpenPayload),
        },
        Value::String(value) => {
            if valid_open_unicode_string(value, MAX_OPEN_METADATA_STRING_BYTES, true) {
                Ok(())
            } else {
                Err(ProtocolV3Error::InvalidOpenPayload)
            }
        }
        Value::Array(values) => {
            if values.len() > MAX_OPEN_METADATA_ARRAY {
                return Err(ProtocolV3Error::InvalidOpenPayload);
            }
            for value in values {
                validate_metadata_value(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > MAX_OPEN_METADATA_KEYS {
                return Err(ProtocolV3Error::InvalidOpenPayload);
            }
            for (key, value) in values {
                if !valid_open_unicode_string(key, MAX_OPEN_METADATA_KEY_BYTES, false) {
                    return Err(ProtocolV3Error::InvalidOpenPayload);
                }
                validate_metadata_value(value, depth + 1, nodes)?;
            }
            Ok(())
        }
    }
}

fn append_canonical_json(output: &mut Vec<u8>, value: &Value) -> Result<(), ProtocolV3Error> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => append_canonical_json_string(output, value),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                append_canonical_json(output, value)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            let mut keys: Vec<&str> = values.keys().map(String::as_str).collect();
            keys.sort_by(|left, right| compare_utf16(left, right));
            output.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                append_canonical_json_string(output, key);
                output.push(b':');
                append_canonical_json(output, &values[key])?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn append_canonical_json_string(output: &mut Vec<u8>, value: &str) {
    output.push(b'"');
    for byte in value.as_bytes() {
        if matches!(*byte, b'"' | b'\\') {
            output.push(b'\\');
        }
        output.push(*byte);
    }
    output.push(b'"');
}

fn compare_utf16(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn valid_open_unicode_string(value: &str, max_bytes: usize, allow_empty: bool) -> bool {
    if value.len() > max_bytes
        || (!allow_empty && value.is_empty())
        || !value.nfc().eq(value.chars())
    {
        return false;
    }
    value.chars().all(|scalar| {
        !matches!(scalar as u32, 0x00..=0x1f | 0x7f..=0x9f) && unicode151_assigned(scalar as u32)
    })
}

#[cfg(test)]
mod unreliable_message_tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    #[test]
    fn version_isolation_protocol_frames_reject_v2_mutations() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../testdata/transport_v3/version_isolation_vectors.json"
        ))
        .unwrap();
        for frame in fixture["frames"].as_array().unwrap() {
            let id = frame["id"].as_str().unwrap();
            if !matches!(id, "fss3" | "fsr3" | "fsd3") {
                continue;
            }
            let decode = |field: &str| {
                frame[field]
                    .as_str()
                    .unwrap()
                    .as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect::<Vec<_>>()
            };
            let valid = decode("v3_hex");
            let magic = decode("v2_magic_hex");
            let version = decode("v2_version_hex");
            match id {
                "fss3" => {
                    SetupPrefaceV3::decode(&valid).unwrap();
                    assert!(SetupPrefaceV3::decode(&magic).is_err());
                    assert!(SetupPrefaceV3::decode(&version).is_err());
                }
                "fsr3" => {
                    RecordHeaderV3::decode(&valid).unwrap();
                    assert!(RecordHeaderV3::decode(&magic).is_err());
                    assert!(RecordHeaderV3::decode(&version).is_err());
                }
                "fsd3" => {
                    UnreliableHeaderV3::decode(&valid).unwrap();
                    assert!(UnreliableHeaderV3::decode(&magic).is_err());
                    assert!(UnreliableHeaderV3::decode(&version).is_err());
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn fsd3_header_and_domain_separated_aead_are_strict() {
        let session_prk = [0x31; 32];
        let h3 = [0x42; 32];
        let roots = derive_epoch_zero_v3(&session_prk, DirectionV3::ClientToServer).unwrap();
        let material =
            derive_unreliable_material_v3(&roots, &h3, DirectionV3::ClientToServer, 0).unwrap();
        let header = UnreliableHeaderV3 {
            epoch: 0,
            sequence: 7,
            expires_at_unix_ms: 2_000_000_000_000,
            ciphertext_length: (4 + AEAD_TAG_V3_SIZE) as u32,
        };
        let raw = header.encode().unwrap();
        assert_eq!(&raw[..4], b"FSD3");
        assert_eq!(raw[4], PROTOCOL_V3_VERSION);
        assert_eq!(u16::from_be_bytes(raw[6..8].try_into().unwrap()), 32);
        assert_eq!(UnreliableHeaderV3::decode(&raw).unwrap(), header);

        let ciphertext = seal_unreliable_v3(
            CipherSuiteV3::ChaCha20Poly1305,
            &material,
            &h3,
            DirectionV3::ClientToServer,
            header,
            b"data",
        )
        .unwrap();
        assert_ne!(ciphertext, b"data");
        assert_eq!(
            open_unreliable_v3(
                CipherSuiteV3::ChaCha20Poly1305,
                &material,
                &h3,
                DirectionV3::ClientToServer,
                header,
                &ciphertext,
            )
            .unwrap(),
            b"data"
        );

        let peer_roots = derive_epoch_zero_v3(&session_prk, DirectionV3::ServerToClient).unwrap();
        let peer_material =
            derive_unreliable_material_v3(&peer_roots, &h3, DirectionV3::ServerToClient, 0)
                .unwrap();
        assert!(
            open_unreliable_v3(
                CipherSuiteV3::ChaCha20Poly1305,
                &peer_material,
                &h3,
                DirectionV3::ServerToClient,
                header,
                &ciphertext,
            )
            .is_err(),
            "unreliable keys must be direction-separated"
        );
        let mut altered_h3 = h3;
        altered_h3[0] ^= 1;
        assert!(
            open_unreliable_v3(
                CipherSuiteV3::ChaCha20Poly1305,
                &material,
                &altered_h3,
                DirectionV3::ClientToServer,
                header,
                &ciphertext,
            )
            .is_err(),
            "unreliable AAD must bind the FSH3 transcript"
        );
    }

    #[test]
    fn fsd3_rejects_empty_oversize_and_mutated_header_context() {
        let roots = derive_epoch_zero_v3(&[0x51; 32], DirectionV3::ClientToServer).unwrap();
        let material =
            derive_unreliable_material_v3(&roots, &[0x61; 32], DirectionV3::ClientToServer, 0)
                .unwrap();
        let header = UnreliableHeaderV3 {
            epoch: 0,
            sequence: 1,
            expires_at_unix_ms: 2_000_000_000_000,
            ciphertext_length: (1 + AEAD_TAG_V3_SIZE) as u32,
        };
        assert!(
            seal_unreliable_v3(
                CipherSuiteV3::Aes256Gcm,
                &material,
                &[0x61; 32],
                DirectionV3::ClientToServer,
                header,
                b"",
            )
            .is_err()
        );
        let mut invalid = header.encode().unwrap();
        invalid[5] = 1;
        assert!(UnreliableHeaderV3::decode(&invalid).is_err());
        let oversized = UnreliableHeaderV3 {
            ciphertext_length: (MAX_UNRELIABLE_PLAINTEXT_V3_BYTES + AEAD_TAG_V3_SIZE + 1) as u32,
            ..header
        };
        assert!(oversized.encode().is_err());
        let zero_expiry = UnreliableHeaderV3 {
            expires_at_unix_ms: 0,
            ..header
        };
        assert!(zero_expiry.encode().is_err());
        let mut zero_raw = header.encode().unwrap();
        zero_raw[20..28].fill(0);
        assert!(UnreliableHeaderV3::decode(&zero_raw).is_err());
        let tag_only = UnreliableHeaderV3 {
            ciphertext_length: AEAD_TAG_V3_SIZE as u32,
            ..header
        };
        assert!(tag_only.encode().is_err());
        let mut tag_only_raw = header.encode().unwrap();
        tag_only_raw[28..32].copy_from_slice(&(AEAD_TAG_V3_SIZE as u32).to_be_bytes());
        assert!(UnreliableHeaderV3::decode(&tag_only_raw).is_err());
    }

    #[test]
    fn consumes_shared_fsd3_datagram_vectors() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../testdata/transport_v3/datagram_vectors.json"
        ))
        .unwrap();
        assert_eq!(fixture["schema_version"], 3);
        let vectors = fixture["vectors"].as_array().unwrap();
        assert!(!vectors.is_empty());
        for vector in vectors {
            let decode = |name: &str| {
                URL_SAFE_NO_PAD
                    .decode(vector[name].as_str().unwrap())
                    .unwrap()
            };
            let session_prk: [u8; 32] = decode("session_prk_b64u").try_into().unwrap();
            let h3: [u8; 32] = decode("h3_b64u").try_into().unwrap();
            let direction =
                DirectionV3::try_from(vector["direction"].as_u64().unwrap() as u8).unwrap();
            let epoch = vector["epoch"].as_u64().unwrap() as u32;
            let sequence = vector["sequence"].as_u64().unwrap();
            let plaintext = decode("plaintext_b64u");
            let suite = match vector["suite"].as_u64().unwrap() {
                1 => CipherSuiteV3::ChaCha20Poly1305,
                2 => CipherSuiteV3::Aes256Gcm,
                _ => panic!("unknown shared DATAGRAM suite"),
            };

            let epoch_zero = derive_epoch_zero_v3(&session_prk, direction).unwrap();
            let roots =
                derive_next_epoch_v3(epoch_zero.rekey_root(), &h3, direction, epoch).unwrap();
            assert_eq!(
                roots.epoch_secret().as_slice(),
                decode("epoch_secret_b64u").as_slice()
            );
            let root = expand_32(
                roots.epoch_secret(),
                &label_with(UNRELIABLE_ROOT_LABEL_V3, &[]),
            )
            .unwrap();
            assert_eq!(root.as_slice(), decode("unreliable_root_b64u").as_slice());
            let secret = expand_32(
                &root,
                &label_with(
                    UNRELIABLE_LABEL_V3,
                    &[&h3, &[direction as u8], &epoch.to_be_bytes()],
                ),
            )
            .unwrap();
            assert_eq!(secret.as_slice(), decode("material_secret_b64u").as_slice());
            let material = derive_unreliable_material_v3(&roots, &h3, direction, epoch).unwrap();
            assert_eq!(
                material.key.as_slice(),
                decode("record_key_b64u").as_slice()
            );
            assert_eq!(
                material.nonce_prefix.as_slice(),
                decode("nonce_prefix_b64u").as_slice()
            );
            assert_eq!(
                record_nonce(material.nonce_prefix, sequence),
                decode("nonce_b64u").as_slice()
            );
            let header = UnreliableHeaderV3 {
                epoch,
                sequence,
                expires_at_unix_ms: vector["expires_at_unix_ms"].as_u64().unwrap(),
                ciphertext_length: (plaintext.len() + AEAD_TAG_V3_SIZE) as u32,
            };
            let raw_header = header.encode().unwrap();
            assert_eq!(hex_lower(&raw_header), vector["header_hex"]);
            let aad = label_with(
                UNRELIABLE_AAD_LABEL_V3,
                &[&h3, &[direction as u8], &raw_header],
            );
            assert_eq!(aad, decode("aad_b64u"));
            let ciphertext =
                seal_unreliable_v3(suite, &material, &h3, direction, header, &plaintext).unwrap();
            assert_eq!(ciphertext, decode("ciphertext_b64u"));
            let mut wire = raw_header.to_vec();
            wire.extend_from_slice(&ciphertext);
            assert_eq!(wire, decode("wire_b64u"));
        }
    }

    #[test]
    fn version_isolation_crypto_labels_keep_v3_domain_separation() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../testdata/transport_v3/version_isolation_vectors.json"
        ))
        .unwrap();
        let labels = fixture["crypto_label_mutations"].as_array().unwrap();
        assert!(!labels.is_empty());
        for mutation in labels {
            let id = mutation["id"].as_str().unwrap();
            let v3 = mutation["v3"].as_str().unwrap();
            let v2 = mutation["v2"].as_str().unwrap();
            let expected: Vec<u8> = match id {
                "session-contract" => crate::artifact_v3::SESSION_CONTRACT_LABEL_V3.to_vec(),
                "candidates" => crate::artifact_v3::CANDIDATES_LABEL_V3.to_vec(),
                "admission" => crate::artifact_v3::ADMISSION_LABEL_V3.to_vec(),
                "runtime-capability" => crate::transport_v3::RUNTIME_CAPABILITY_LABEL_V3.to_vec(),
                "handshake" => crate::transport_v3::HANDSHAKE_DOMAIN_V3.to_vec(),
                "server-finished" => crate::transport_v3::SERVER_FINISHED_LABEL_V3.to_vec(),
                "client-finished" => crate::transport_v3::CLIENT_FINISHED_LABEL_V3.to_vec(),
                "epoch-zero" => EPOCH_ZERO_LABEL_V3.to_vec(),
                "control-root" => CONTROL_ROOT_LABEL_V3.to_vec(),
                "stream-root" => STREAM_ROOT_LABEL_V3.to_vec(),
                "setup-root" => SETUP_ROOT_LABEL_V3.to_vec(),
                "rekey-root" => REKEY_ROOT_LABEL_V3.to_vec(),
                "next-epoch" => NEXT_EPOCH_LABEL_V3.to_vec(),
                "stream" => STREAM_LABEL_V3.to_vec(),
                "control" => CONTROL_LABEL_V3.to_vec(),
                "record-key" => RECORD_KEY_LABEL_V3.to_vec(),
                "nonce" => NONCE_LABEL_V3.to_vec(),
                "unreliable-root" => UNRELIABLE_ROOT_LABEL_V3.to_vec(),
                "unreliable" => UNRELIABLE_LABEL_V3.to_vec(),
                "unreliable-key" => UNRELIABLE_KEY_LABEL_V3.to_vec(),
                "unreliable-nonce" => UNRELIABLE_NONCE_LABEL_V3.to_vec(),
                "unreliable-aad" => UNRELIABLE_AAD_LABEL_V3.to_vec(),
                "setup-mac" => [SETUP_MAC_LABEL_V3, b"\0"].concat(),
                "record-aad" => [RECORD_AAD_LABEL_V3, b"\0"].concat(),
                "open" => OPEN_DOMAIN_V3.to_vec(),
                "acceptor-admissions" => crate::artifact_v3::ACCEPTOR_ADMISSIONS_LABEL_V3.to_vec(),
                other => panic!("unknown crypto label mutation {other}"),
            };
            assert_eq!(v3.as_bytes(), expected.as_slice(), "{id} production label");
            assert_ne!(v2.as_bytes(), expected.as_slice(), "{id} v2 label leaked");
        }
        let roots = derive_epoch_zero_v3(&[0x11; 32], DirectionV3::ClientToServer).unwrap();
        let peer = derive_epoch_zero_v3(&[0x12; 32], DirectionV3::ClientToServer).unwrap();
        assert_ne!(roots.control_root(), peer.control_root());
        assert_ne!(roots.stream_root(), peer.stream_root());
        assert_ne!(roots.setup_root(), peer.setup_root());
        assert_ne!(roots.rekey_root(), peer.rekey_root());
    }

    fn hex_lower(raw: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut output = String::with_capacity(raw.len() * 2);
        for byte in raw {
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }
}
