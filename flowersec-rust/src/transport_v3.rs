//! Runtime capability and TLS verifier contract for Flowersec v3.

#![allow(dead_code)]

use std::{fmt, io, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

use crate::artifact_v3::{ArtifactErrorV3, hash_lp, jcs_serialize};

pub(crate) use crate::transport_v2::{
    ByteStream, IncomingStream, JsonObject, NotificationSubscription, PathKind, RpcCallError,
    RpcError, RpcPeer, Session, SessionError, SessionRole, SessionTermination, StreamMetadata,
    UnreliableMessageChannel, UnreliableMessageError, UnreliableSendOutcome,
};

/// v3 carrier identity. This is deliberately a distinct type from the v2
/// identity so a v3 candidate cannot accidentally be routed through a v2
/// capability table.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) enum CarrierKind {
    #[serde(rename = "websocket")]
    Wss,
    #[serde(rename = "raw_quic")]
    RawQuic,
    #[serde(rename = "webtransport")]
    WebTransport,
}

/// One reliable bidirectional v3 carrier stream.
#[async_trait]
pub(crate) trait CarrierStreamV3: fmt::Debug + Send + Sync + 'static {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize>;
    async fn write(&self, payload: &[u8]) -> io::Result<usize>;
    async fn close_write(&self) -> io::Result<()>;
    async fn close_write_delivered(&self) -> io::Result<()> {
        self.close_write().await
    }
    async fn stop_sending(&self) -> io::Result<()>;
    async fn reset(&self) -> io::Result<()>;
    async fn close(&self) -> io::Result<()>;
}

/// Carrier-neutral source of reliable v3 streams.
#[async_trait]
pub(crate) trait CarrierSessionV3: fmt::Debug + Send + Sync + 'static {
    fn kind(&self) -> CarrierKind;
    fn set_multiplexer_client(&self, _client: bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "carrier has no configurable multiplexer role",
        ))
    }
    fn inbound_bidirectional_stream_capacity(&self) -> u32;
    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>>;
    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>>;
    fn unreliable_message_max_size(&self) -> Option<usize> {
        None
    }
    async fn send_unreliable_message(
        &self,
        _payload: Bytes,
    ) -> Result<(), CarrierUnreliableMessageErrorV3> {
        Err(CarrierUnreliableMessageErrorV3::Unavailable)
    }
    async fn receive_unreliable_message(&self) -> Result<Bytes, CarrierUnreliableMessageErrorV3> {
        Err(CarrierUnreliableMessageErrorV3::Unavailable)
    }
    async fn close(&self) -> io::Result<()>;
    fn abort(&self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CarrierUnreliableMessageErrorV3 {
    #[error("unreliable messages are unavailable on this carrier")]
    Unavailable,
    #[error("unreliable message exceeds the negotiated maximum")]
    TooLarge,
    #[error("unreliable message was dropped by the bounded send budget")]
    Dropped,
    #[error("unreliable message carrier is closed")]
    Closed,
}

pub(crate) const MAX_LOGICAL_INBOUND_STREAMS_V3: u16 = 128;
pub(crate) const SESSION_PROFILE_V3: &str = "flowersec/3";
pub(crate) const DIRECT_PROFILE_V3: &str = "flowersec-direct/3";
pub(crate) const TUNNEL_PROFILE_V3: &str = "flowersec-tunnel/3";
pub(crate) const ALPN_DIRECT_V3: &[u8] = b"flowersec-direct/3";
pub(crate) const ALPN_TUNNEL_V3: &[u8] = b"flowersec-tunnel/3";
pub(crate) const HANDSHAKE_DOMAIN_V3: &[u8] = b"flowersec-v3-handshake\0";
pub(crate) const SERVER_FINISHED_LABEL_V3: &[u8] = b"flowersec v3 server finished";
pub(crate) const CLIENT_FINISHED_LABEL_V3: &[u8] = b"flowersec v3 client finished";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CarrierStreamLimitErrorV3 {
    #[error("logical max inbound streams must be in 1..=128, got {0}")]
    InvalidLogicalLimit(u16),
    #[error("carrier inbound stream limit overflow")]
    Overflow,
}

pub(crate) fn carrier_inbound_stream_limit_v3(
    logical_max: u16,
) -> Result<u32, CarrierStreamLimitErrorV3> {
    if !(1..=MAX_LOGICAL_INBOUND_STREAMS_V3).contains(&logical_max) {
        return Err(CarrierStreamLimitErrorV3::InvalidLogicalLimit(logical_max));
    }
    u32::from(logical_max)
        .checked_add(2)
        .ok_or(CarrierStreamLimitErrorV3::Overflow)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum CarrierV3 {
    RawQuic,
    Websocket,
    Webtransport,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
enum NetworkModeV3 {
    Dial,
    Listen,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
enum SessionRoleV3 {
    Client,
    Server,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
enum PathV3 {
    Direct,
    Tunnel,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct RuntimeCapabilityTupleV3 {
    carrier: CarrierV3,
    datagrams: bool,
    migration: bool,
    network_mode: NetworkModeV3,
    path: PathV3,
    reliable_streams: bool,
    security_modes: Vec<String>,
    session_role: SessionRoleV3,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct UnsupportedCarrierV3 {
    carrier: CarrierV3,
    reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RuntimeCapabilityDescriptorV3 {
    language: String,
    runtime: String,
    schema_version: u8,
    tuples: Vec<RuntimeCapabilityTupleV3>,
    unsupported: Vec<UnsupportedCarrierV3>,
}

impl RuntimeCapabilityDescriptorV3 {
    pub(crate) fn native_rust() -> Self {
        let mut tuples = Vec::new();
        for carrier in [CarrierV3::RawQuic, CarrierV3::Websocket] {
            let (datagrams, migration) =
                (carrier == CarrierV3::RawQuic, carrier == CarrierV3::RawQuic);
            for (network_mode, path, session_role) in [
                (NetworkModeV3::Dial, PathV3::Direct, SessionRoleV3::Client),
                (NetworkModeV3::Dial, PathV3::Tunnel, SessionRoleV3::Client),
                (NetworkModeV3::Dial, PathV3::Tunnel, SessionRoleV3::Server),
                (NetworkModeV3::Listen, PathV3::Direct, SessionRoleV3::Server),
            ] {
                tuples.push(RuntimeCapabilityTupleV3 {
                    carrier,
                    datagrams,
                    migration: migration && network_mode == NetworkModeV3::Dial,
                    network_mode,
                    path,
                    reliable_streams: true,
                    security_modes: if network_mode == NetworkModeV3::Dial {
                        vec!["ca".into(), "pin".into()]
                    } else {
                        vec![]
                    },
                    session_role,
                });
            }
        }
        tuples.sort_by_key(|tuple| {
            (
                tuple.carrier,
                tuple.network_mode,
                tuple.session_role,
                tuple.path,
            )
        });
        Self {
            language: "rust".into(),
            runtime: "native".into(),
            schema_version: 3,
            tuples,
            unsupported: vec![UnsupportedCarrierV3 {
                carrier: CarrierV3::Webtransport,
                reason: "driver_unavailable".into(),
            }],
        }
    }

    pub(crate) fn canonical_json(&self) -> Result<Vec<u8>, ArtifactErrorV3> {
        self.validate()?;
        jcs_serialize(self)
    }
    pub(crate) fn decode(input: &[u8]) -> Result<Self, ArtifactErrorV3> {
        crate::artifact_v3::reject_duplicate_json_keys(input)?;
        let descriptor: Self =
            serde_json::from_slice(input).map_err(|_| ArtifactErrorV3::Invalid)?;
        let canonical = descriptor.canonical_json()?;
        if canonical != input {
            return Err(ArtifactErrorV3::Invalid);
        }
        Ok(descriptor)
    }
    pub(crate) fn digest(&self) -> Result<[u8; 32], ArtifactErrorV3> {
        Ok(hash_lp(
            b"flowersec-v3-runtime-capability\0",
            &self.canonical_json()?,
        ))
    }

    fn validate(&self) -> Result<(), ArtifactErrorV3> {
        if self.schema_version != 3
            || !capability_token(&self.language)
            || !capability_token(&self.runtime)
            || self.tuples.len() + self.unsupported.len() == 0
        {
            return Err(ArtifactErrorV3::Invalid);
        }

        let mut previous_tuple: Option<&RuntimeCapabilityTupleV3> = None;
        for tuple in &self.tuples {
            validate_capability_tuple(tuple)?;
            if previous_tuple.is_some_and(|previous| {
                capability_tuple_identity(previous) >= capability_tuple_identity(tuple)
            }) {
                return Err(ArtifactErrorV3::Invalid);
            }
            previous_tuple = Some(tuple);
        }
        let mut previous_unsupported: Option<CarrierV3> = None;
        for unsupported in &self.unsupported {
            if !registered_unsupported_reason(&unsupported.reason)
                || previous_unsupported.is_some_and(|previous| previous >= unsupported.carrier)
                || self
                    .tuples
                    .iter()
                    .any(|tuple| tuple.carrier == unsupported.carrier)
            {
                return Err(ArtifactErrorV3::Invalid);
            }
            previous_unsupported = Some(unsupported.carrier);
        }
        for carrier in [
            CarrierV3::RawQuic,
            CarrierV3::Websocket,
            CarrierV3::Webtransport,
        ] {
            let supported = self.tuples.iter().any(|tuple| tuple.carrier == carrier);
            let unsupported = self.unsupported.iter().any(|item| item.carrier == carrier);
            if supported == unsupported {
                return Err(ArtifactErrorV3::Invalid);
            }
        }

        validate_registered_runtime(self)
    }

    fn validate_local_rust_profile(&self) -> Result<(), ArtifactErrorV3> {
        if self != &Self::native_rust() {
            return Err(ArtifactErrorV3::Invalid);
        }
        self.validate()
    }
}

fn capability_token(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn capability_tuple_identity(
    tuple: &RuntimeCapabilityTupleV3,
) -> (CarrierV3, NetworkModeV3, SessionRoleV3, PathV3) {
    (
        tuple.carrier,
        tuple.network_mode,
        tuple.session_role,
        tuple.path,
    )
}

fn validate_capability_tuple(tuple: &RuntimeCapabilityTupleV3) -> Result<(), ArtifactErrorV3> {
    let valid_deployment = match tuple.path {
        PathV3::Direct => {
            (tuple.network_mode == NetworkModeV3::Dial
                && tuple.session_role == SessionRoleV3::Client)
                || (tuple.network_mode == NetworkModeV3::Listen
                    && tuple.session_role == SessionRoleV3::Server)
        }
        PathV3::Tunnel => tuple.network_mode == NetworkModeV3::Dial,
    };
    let valid_modes = if tuple.network_mode == NetworkModeV3::Listen {
        tuple.security_modes.is_empty()
    } else {
        matches!(tuple.security_modes.as_slice(), [mode] if mode == "ca" || mode == "pin")
            || tuple.security_modes == ["ca", "pin"]
    };
    if !tuple.reliable_streams
        || !valid_deployment
        || !valid_modes
        || (tuple.carrier == CarrierV3::Websocket && (tuple.datagrams || tuple.migration))
    {
        return Err(ArtifactErrorV3::Invalid);
    }
    Ok(())
}

fn registered_tuples(
    carrier: CarrierV3,
    datagrams: bool,
    dial_migration: bool,
    include_listener: bool,
    security_modes: &[&str],
) -> Vec<RuntimeCapabilityTupleV3> {
    let tuple =
        |network_mode, path, session_role, migration, modes: &[&str]| RuntimeCapabilityTupleV3 {
            carrier,
            datagrams,
            migration,
            network_mode,
            path,
            reliable_streams: true,
            security_modes: modes.iter().map(|mode| (*mode).into()).collect(),
            session_role,
        };
    let mut tuples = vec![
        tuple(
            NetworkModeV3::Dial,
            PathV3::Direct,
            SessionRoleV3::Client,
            dial_migration,
            security_modes,
        ),
        tuple(
            NetworkModeV3::Dial,
            PathV3::Tunnel,
            SessionRoleV3::Client,
            dial_migration,
            security_modes,
        ),
        tuple(
            NetworkModeV3::Dial,
            PathV3::Tunnel,
            SessionRoleV3::Server,
            dial_migration,
            security_modes,
        ),
    ];
    if include_listener {
        tuples.push(tuple(
            NetworkModeV3::Listen,
            PathV3::Direct,
            SessionRoleV3::Server,
            false,
            &[],
        ));
    }
    tuples
}

fn validate_registered_carrier(
    descriptor: &RuntimeCapabilityDescriptorV3,
    carrier: CarrierV3,
    tuple_sets: Vec<Vec<RuntimeCapabilityTupleV3>>,
    unsupported_reasons: &[&str],
) -> Result<(), ArtifactErrorV3> {
    let actual = descriptor
        .tuples
        .iter()
        .filter(|tuple| tuple.carrier == carrier)
        .cloned()
        .collect::<Vec<_>>();
    if let Some(unsupported) = descriptor
        .unsupported
        .iter()
        .find(|unsupported| unsupported.carrier == carrier)
    {
        if !actual.is_empty() || !unsupported_reasons.contains(&unsupported.reason.as_str()) {
            return Err(ArtifactErrorV3::Invalid);
        }
    } else if !tuple_sets.iter().any(|expected| expected == &actual) {
        return Err(ArtifactErrorV3::Invalid);
    }
    Ok(())
}

fn validate_registered_runtime(
    descriptor: &RuntimeCapabilityDescriptorV3,
) -> Result<(), ArtifactErrorV3> {
    let ca = &["ca"];
    let ca_pin = &["ca", "pin"];
    let id = (descriptor.language.as_str(), descriptor.runtime.as_str());
    let adapter_absent = &["adapter_not_composed"];
    match id {
        ("go", "native") => {
            validate_registered_carrier(
                descriptor,
                CarrierV3::RawQuic,
                vec![registered_tuples(
                    CarrierV3::RawQuic,
                    true,
                    true,
                    true,
                    ca_pin,
                )],
                adapter_absent,
            )?;
            validate_registered_carrier(
                descriptor,
                CarrierV3::Websocket,
                vec![registered_tuples(
                    CarrierV3::Websocket,
                    false,
                    false,
                    true,
                    ca_pin,
                )],
                adapter_absent,
            )?;
            validate_registered_carrier(
                descriptor,
                CarrierV3::Webtransport,
                vec![registered_tuples(
                    CarrierV3::Webtransport,
                    true,
                    false,
                    true,
                    ca_pin,
                )],
                adapter_absent,
            )
        }
        ("typescript", "browser") => {
            validate_registered_carrier(
                descriptor,
                CarrierV3::RawQuic,
                vec![],
                &["browser_no_raw_udp"],
            )?;
            validate_registered_carrier(
                descriptor,
                CarrierV3::Websocket,
                vec![registered_tuples(
                    CarrierV3::Websocket,
                    false,
                    false,
                    false,
                    ca,
                )],
                &["browser_websocket_api_unavailable"],
            )?;
            validate_registered_carrier(
                descriptor,
                CarrierV3::Webtransport,
                vec![
                    registered_tuples(CarrierV3::Webtransport, true, false, false, ca),
                    registered_tuples(CarrierV3::Webtransport, true, false, false, ca_pin),
                ],
                &["browser_webtransport_api_unavailable"],
            )
        }
        ("typescript", "node") => {
            validate_registered_carrier(
                descriptor,
                CarrierV3::RawQuic,
                vec![registered_tuples(
                    CarrierV3::RawQuic,
                    true,
                    false,
                    true,
                    ca_pin,
                )],
                &["node_native_transport_unavailable"],
            )?;
            validate_registered_carrier(
                descriptor,
                CarrierV3::Websocket,
                vec![registered_tuples(
                    CarrierV3::Websocket,
                    false,
                    false,
                    true,
                    ca_pin,
                )],
                &[],
            )?;
            validate_registered_carrier(
                descriptor,
                CarrierV3::Webtransport,
                vec![],
                &["node_webtransport_driver_unavailable"],
            )
        }
        ("rust", "native") => {
            validate_registered_carrier(
                descriptor,
                CarrierV3::RawQuic,
                vec![registered_tuples(
                    CarrierV3::RawQuic,
                    true,
                    true,
                    true,
                    ca_pin,
                )],
                &[],
            )?;
            validate_registered_carrier(
                descriptor,
                CarrierV3::Websocket,
                vec![registered_tuples(
                    CarrierV3::Websocket,
                    false,
                    false,
                    true,
                    ca_pin,
                )],
                &[],
            )?;
            validate_registered_carrier(
                descriptor,
                CarrierV3::Webtransport,
                vec![],
                &["driver_unavailable"],
            )
        }
        ("swift", "ios" | "macos") => {
            validate_registered_carrier(
                descriptor,
                CarrierV3::RawQuic,
                vec![],
                &["swift_apple_client_profile_excludes_raw_quic"],
            )?;
            validate_registered_carrier(
                descriptor,
                CarrierV3::Websocket,
                vec![registered_tuples(
                    CarrierV3::Websocket,
                    false,
                    false,
                    false,
                    ca_pin,
                )],
                &[],
            )?;
            validate_registered_carrier(
                descriptor,
                CarrierV3::Webtransport,
                vec![],
                &["swift_apple_client_profile_excludes_webtransport"],
            )
        }
        ("swift", "linux") => {
            validate_registered_carrier(
                descriptor,
                CarrierV3::RawQuic,
                vec![],
                &["swift_apple_client_profile_excludes_raw_quic"],
            )?;
            validate_registered_carrier(
                descriptor,
                CarrierV3::Websocket,
                vec![],
                &["websocket_adapter_not_supported_on_linux"],
            )?;
            validate_registered_carrier(
                descriptor,
                CarrierV3::Webtransport,
                vec![],
                &["swift_apple_client_profile_excludes_webtransport"],
            )
        }
        _ => Err(ArtifactErrorV3::Invalid),
    }
}

fn registered_unsupported_reason(reason: &str) -> bool {
    matches!(
        reason,
        "adapter_not_composed"
            | "browser_no_raw_udp"
            | "browser_websocket_api_unavailable"
            | "browser_webtransport_api_unavailable"
            | "driver_unavailable"
            | "node_native_transport_unavailable"
            | "node_webtransport_driver_unavailable"
            | "swift_apple_client_profile_excludes_raw_quic"
            | "swift_apple_client_profile_excludes_webtransport"
            | "websocket_adapter_not_supported_on_linux"
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeafPublicKeyV3 {
    EcdsaP256,
    Other,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct PresentedLeafV3<'a> {
    pub(crate) der: &'a [u8],
    pub(crate) not_before_unix_s: i64,
    pub(crate) not_after_unix_s: i64,
    pub(crate) public_key: LeafPublicKeyV3,
    pub(crate) tls_proof_complete: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PinVerificationErrorV3 {
    InvalidCertificateProfile,
    PinMismatch,
    TlsProofFailed,
}

pub(crate) fn verify_pinned_leaf(
    leaf: PresentedLeafV3<'_>,
    active_pins: &[[u8; 32]],
    now: i64,
) -> Result<(), PinVerificationErrorV3> {
    if leaf.der.is_empty()
        || now < leaf.not_before_unix_s
        || now >= leaf.not_after_unix_s
        || leaf
            .not_after_unix_s
            .checked_sub(leaf.not_before_unix_s)
            .is_none_or(|duration| duration > 1_209_600)
        || leaf.public_key != LeafPublicKeyV3::EcdsaP256
    {
        return Err(PinVerificationErrorV3::InvalidCertificateProfile);
    }
    let digest: [u8; 32] = Sha256::digest(leaf.der).into();
    if !active_pins.iter().any(|pin| digest.ct_eq(pin).into()) {
        return Err(PinVerificationErrorV3::PinMismatch);
    }
    if !leaf.tls_proof_complete {
        return Err(PinVerificationErrorV3::TlsProofFailed);
    }
    Ok(())
}

pub(crate) const V3_FRAME_MAGICS: [[u8; 4]; 7] = [
    *b"FSB3", *b"FSA3", *b"FSC3", *b"FSH3", *b"FSS3", *b"FSR3", *b"FSD3",
];
#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_v3::acceptor_admissions_hash;
    use std::collections::HashSet;

    #[derive(Deserialize)]
    struct CapabilityVectorsV3 {
        vectors: Vec<CapabilityVectorV3>,
        invalid: Vec<InvalidCapabilityVectorV3>,
    }

    #[derive(Deserialize)]
    struct CapabilityVectorV3 {
        name: String,
        canonical_json: String,
        digest_hex: String,
    }

    #[derive(Deserialize)]
    struct InvalidCapabilityVectorV3 {
        id: String,
        value: String,
        error_code: String,
    }

    #[derive(Deserialize)]
    struct GoIssuerAdmissionVectorV3 {
        artifact_json: String,
        chosen_candidate_id: String,
        fsb3_hex: String,
        admission_binding_hex: String,
        acceptor_admissions_hash_hex: String,
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert!(value.len().is_multiple_of(2));
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                    .expect("valid hex")
            })
            .collect()
    }
    #[test]
    fn native_capability_is_strict_and_domain_separated() {
        let descriptor = RuntimeCapabilityDescriptorV3::native_rust();
        descriptor.validate_local_rust_profile().unwrap();
        let canonical = String::from_utf8(descriptor.canonical_json().unwrap()).unwrap();
        assert!(canonical.contains("\"schemaVersion\":3"));
        assert!(canonical.contains("\"securityModes\":[\"ca\",\"pin\"]"));
        assert_ne!(descriptor.digest().unwrap(), [0; 32]);
        assert!(V3_FRAME_MAGICS.iter().all(|magic| magic[3] == b'3'));
    }

    #[test]
    fn native_capability_rejects_partial_or_mutated_registry_tuples() {
        let mut partial = RuntimeCapabilityDescriptorV3::native_rust();
        partial.tuples.pop();
        assert_eq!(partial.validate(), Err(ArtifactErrorV3::Invalid));

        let mut mutated = RuntimeCapabilityDescriptorV3::native_rust();
        let raw_quic_dial = mutated
            .tuples
            .iter_mut()
            .find(|tuple| {
                tuple.carrier == CarrierV3::RawQuic && tuple.network_mode == NetworkModeV3::Dial
            })
            .expect("native Rust raw-QUIC dial tuple");
        raw_quic_dial.migration = false;
        assert_eq!(mutated.validate(), Err(ArtifactErrorV3::Invalid));
    }
    #[test]
    fn carrier_contract_is_physically_isolated_from_v2() {
        let transport = include_str!("transport_v3.rs");
        let session = include_str!("session_v3.rs");
        for (prefix, suffix) in [
            ("CarrierSession", "V2"),
            ("CarrierStream", "V2"),
            ("CarrierStreamLimitError", "V2"),
            ("carrier_inbound_stream_limit_", "v2"),
        ] {
            let forbidden = format!("{prefix}{suffix}");
            assert!(
                !transport.contains(&forbidden),
                "transport_v3 contains {forbidden}"
            );
            assert!(
                !session.contains(&forbidden),
                "session_v3 contains {forbidden}"
            );
        }
        assert_eq!(carrier_inbound_stream_limit_v3(1), Ok(3));
        assert_eq!(carrier_inbound_stream_limit_v3(128), Ok(130));
        assert_eq!(
            carrier_inbound_stream_limit_v3(0),
            Err(CarrierStreamLimitErrorV3::InvalidLogicalLimit(0))
        );
        assert_eq!(
            carrier_inbound_stream_limit_v3(129),
            Err(CarrierStreamLimitErrorV3::InvalidLogicalLimit(129))
        );
    }
    #[test]
    fn pinned_leaf_requires_profile_hash_and_completed_tls_proof() {
        let der = b"leaf";
        let pin: [u8; 32] = Sha256::digest(der).into();
        let leaf = PresentedLeafV3 {
            der,
            not_before_unix_s: 10,
            not_after_unix_s: 20,
            public_key: LeafPublicKeyV3::EcdsaP256,
            tls_proof_complete: true,
        };
        assert_eq!(verify_pinned_leaf(leaf, &[pin], 10), Ok(()));
        assert_eq!(
            verify_pinned_leaf(
                PresentedLeafV3 {
                    tls_proof_complete: false,
                    ..leaf
                },
                &[pin],
                10
            ),
            Err(PinVerificationErrorV3::TlsProofFailed)
        );
        assert_eq!(
            verify_pinned_leaf(leaf, &[[0; 32]], 10),
            Err(PinVerificationErrorV3::PinMismatch)
        );
        assert_eq!(
            verify_pinned_leaf(leaf, &[pin], 20),
            Err(PinVerificationErrorV3::InvalidCertificateProfile)
        );
        assert_eq!(
            verify_pinned_leaf(
                PresentedLeafV3 {
                    public_key: LeafPublicKeyV3::Other,
                    ..leaf
                },
                &[pin],
                10
            ),
            Err(PinVerificationErrorV3::InvalidCertificateProfile)
        );
    }

    #[test]
    fn shared_capability_vectors_all_match_exact_bytes_and_digests() {
        let vectors: CapabilityVectorsV3 = serde_json::from_str(include_str!(
            "../../testdata/transport_v3/capability_vectors.json"
        ))
        .expect("parse shared Flowersec v3 capability vectors");
        let expected_names = HashSet::from([
            "go-native",
            "typescript-browser-ca-only",
            "typescript-browser-chromium-151.0.7922.34",
            "typescript-node",
            "rust-native",
            "swift-ios",
            "swift-macos",
            "swift-linux",
        ]);
        assert_eq!(vectors.vectors.len(), expected_names.len());
        let mut names = HashSet::new();
        for vector in &vectors.vectors {
            assert!(
                names.insert(vector.name.as_str()),
                "duplicate {}",
                vector.name
            );
            let descriptor =
                RuntimeCapabilityDescriptorV3::decode(vector.canonical_json.as_bytes())
                    .unwrap_or_else(|error| panic!("{}: {error:?}", vector.name));
            let canonical = descriptor
                .canonical_json()
                .unwrap_or_else(|error| panic!("{}: {error:?}", vector.name));
            assert_eq!(
                canonical,
                vector.canonical_json.as_bytes(),
                "{} canonical JSON",
                vector.name
            );
            assert_eq!(
                descriptor.digest().unwrap().as_slice(),
                decode_hex(&vector.digest_hex),
                "{} digest",
                vector.name
            );
        }
        assert_eq!(names, expected_names);
        assert!(vectors.invalid.len() >= 20);
        for vector in &vectors.invalid {
            assert!(
                RuntimeCapabilityDescriptorV3::decode(vector.value.as_bytes()).is_err(),
                "{} unexpectedly accepted",
                vector.id
            );
            assert_eq!(vector.error_code, "invalid_capability");
        }
        let vector = vectors
            .vectors
            .iter()
            .find(|vector| vector.name == "rust-native")
            .expect("rust-native capability vector");
        let descriptor = RuntimeCapabilityDescriptorV3::native_rust();
        assert_eq!(
            descriptor.canonical_json().unwrap(),
            vector.canonical_json.as_bytes()
        );
        assert_eq!(
            descriptor.digest().unwrap().as_slice(),
            decode_hex(&vector.digest_hex)
        );
    }

    #[test]
    fn consumes_go_production_issuer_admission_vector() {
        let vector: GoIssuerAdmissionVectorV3 = serde_json::from_str(include_str!(
            "../../testdata/transport_v3/go_issuer_admission_vectors.json"
        ))
        .expect("parse Go issuer admission vector");
        let artifact = crate::artifact_v3::ArtifactV3::parse(vector.artifact_json.as_bytes())
            .expect("decode Go-issued artifact");
        let frame = artifact
            .encode_fsb3(&vector.chosen_candidate_id)
            .expect("encode Go-issued FSB3");
        assert_eq!(frame.raw, decode_hex(&vector.fsb3_hex));
        assert_eq!(
            frame.binding,
            decode_hex(&vector.admission_binding_hex).as_slice()
        );
        assert_eq!(
            acceptor_admissions_hash(&[frame]).unwrap().as_slice(),
            decode_hex(&vector.acceptor_admissions_hash_hex)
        );
    }
}
