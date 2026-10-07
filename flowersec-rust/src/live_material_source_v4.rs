//! Original configured live direct issuance. TxA returns only the Artifact;
//! native Prepare precedes the one TxB call, whose signed proof completes the
//! same account and immutable attempt before HELLO/FSB/Noise/READY.
use crate::{
    ApplicationProfile, ControlHTTPSConfiguration, MaterialSourceError,
    codec_v4::{self as codec, Limits},
    control_https_v4::ControlHTTPS,
    crypto_v4::{
        IdentityKeys, Namespace,
        connect::{PoolCredentialBytes, WssConnectOptions},
    },
    environment_v4::{EnvironmentCharge, EnvironmentRoot, ResourceCharge, ResourceLimits},
    namespace_v4::verifier::credential::PendingDirectAdmission,
};
use std::{fmt, sync::Arc};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[path = "registered_live_client_v4.rs"]
mod registered;
use registered::RegisteredLiveClientControl;

const LIVE_TUNNEL_GRANT_BYTES: usize = 9_302;
const LIVE_TUNNEL_RESPONSE_BYTES: usize = 4_096 + LIVE_TUNNEL_GRANT_BYTES + 128;

/// The installed live issuance deployment fixes one direct carrier before
/// acquisition. An issued Artifact must independently match this selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveAuthorityCarrier {
    RawQuic,
    WebSocket,
    WebTransport,
}
impl LiveAuthorityCarrier {
    fn wire(self) -> u64 {
        match self {
            Self::RawQuic => 0,
            Self::WebSocket => 1,
            Self::WebTransport => 2,
        }
    }
    fn supports(
        &self,
        requirements: &crate::ConnectionRequirements,
    ) -> Result<(), MaterialSourceError> {
        if *self == Self::WebSocket
            && (requirements.independent_reliable_read_progress
                || requirements.bound_stream_input_isolation
                || requirements.datagram)
        {
            return Err(MaterialSourceError::RequiredGuaranteeUnavailable);
        }
        Ok(())
    }
}
pub struct LiveAuthoritySourceConfiguration {
    pub namespaces: Vec<Arc<Namespace>>,
    pub identity: IdentityKeys,
    pub client_certificate: Vec<u8>,
    pub server_certificate: Vec<u8>,
    pub artifact_issuer_key_id: [u8; 16],
    pub activation_signing_key_id: String,
    pub issuance: ControlHTTPSConfiguration,
    pub activation: ControlHTTPSConfiguration,
    pub provider: WssConnectOptions,
    pub carrier: LiveAuthorityCarrier,
    pub application_profile: ApplicationProfile,
}
impl fmt::Debug for LiveAuthoritySourceConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LiveAuthoritySourceConfiguration { <opaque> }")
    }
}
/// Additional trusted configuration for a live tunnel source. The endpoint
/// Grant and relay identity are held by the original source owner; callers do
/// not provide a server-leg credential or a replacement route after Acquire.
#[derive(Debug)]
pub struct LiveTunnelSourceConfiguration {
    pub control: LiveTunnelAuthorityControlConfiguration,
    pub relay_certificate: Vec<u8>,
    pub relay_service: String,
    pub relay_audience: String,
}

/// Original TxA material plus independently installed registered control.
/// Acquire consumes the Artifact once, creates its original Account and random
/// attempt, and retains that custody through actual native Prepare and TxB.
pub struct RegisteredLiveTunnelSourceConfiguration {
    pub source: LiveAuthoritySourceConfiguration,
    pub tunnel: LiveTunnelSourceConfiguration,
    pub artifact: Vec<u8>,
    pub authority: String,
}
impl fmt::Debug for RegisteredLiveTunnelSourceConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegisteredLiveTunnelSourceConfiguration { <opaque> }")
    }
}

/// Fixed live tunnel control owner. The relay-ready and relay-prepare calls
/// bind one native prepared attempt. The client activation handoff carries only
/// this leg's Grant; the paired server Grant remains owned by the original
/// B-host publication continuation.
#[derive(Clone, Debug)]
pub struct LiveTunnelAuthorityControlConfiguration {
    pub activation: ControlHTTPSConfiguration,
    pub relay_preparation: ControlHTTPSConfiguration,
    pub activation_signing_key_id: String,
}
#[derive(Debug)]
pub struct LiveTunnelAuthorization {
    pub activation: Vec<u8>,
    /// The live TxB response contains only the Grant for this client leg.
    /// The server leg Grant is delivered independently through the original
    /// retained B-host publication capability and is never read back here.
    pub client_grant: Vec<u8>,
}
#[derive(Debug)]
pub struct LiveTunnelAuthorityControl {
    root: Arc<EnvironmentRoot>,
    activation: Arc<ControlHTTPS>,
    relay_preparation: Arc<ControlHTTPS>,
    signing_key_id: String,
    registered: Option<Arc<RegisteredLiveClientControl>>,
    external_relay: bool,
}
impl LiveTunnelAuthorityControl {
    pub(crate) fn new(
        root: Arc<EnvironmentRoot>,
        configuration: LiveTunnelAuthorityControlConfiguration,
    ) -> Result<Arc<Self>, MaterialSourceError> {
        if configuration.activation_signing_key_id.is_empty()
            || configuration.activation_signing_key_id.len() > 128
            || configuration.activation_signing_key_id.capacity() > 256
            || configuration.relay_preparation.base_path.len() > 128
            || configuration.relay_preparation.base_path.capacity() > 256
            || configuration.activation.base_path.len() > 128
            || configuration.activation.base_path.capacity() > 256
        {
            return Err(MaterialSourceError::MaterialUnavailable);
        }
        let external_relay = configuration.relay_preparation.base_path.is_empty();
        let activation = Arc::new(
            ControlHTTPS::new(root.clone(), configuration.activation)
                .map_err(|_| MaterialSourceError::MaterialUnavailable)?,
        );
        let relay_preparation = Arc::new(
            ControlHTTPS::new(root.clone(), configuration.relay_preparation)
                .map_err(|_| MaterialSourceError::MaterialUnavailable)?,
        );
        Ok(Arc::new(Self {
            root,
            activation,
            relay_preparation,
            signing_key_id: configuration.activation_signing_key_id,
            registered: None,
            external_relay,
        }))
    }
    pub(crate) async fn relay_ready(
        &self,
        pending: &PendingDirectAdmission,
        cancellation: &CancellationToken,
    ) -> Result<(), crate::TransportConnectError> {
        if let Some(registered) = &self.registered {
            if self.external_relay {
                self.relay_ready_projection(
                    pending.artifact_digest,
                    pending.candidate_id,
                    pending.route_digest,
                    0,
                    cancellation,
                )
                .await?;
            }
            return registered.prepare_listener(pending, cancellation).await;
        }
        self.relay_ready_projection(
            pending.artifact_digest,
            pending.candidate_id,
            pending.route_digest,
            0,
            cancellation,
        )
        .await
    }
    pub(crate) fn belongs_to(&self, root: &Arc<EnvironmentRoot>) -> bool {
        Arc::ptr_eq(root, &self.root)
    }
    pub(crate) async fn relay_ready_projection(
        &self,
        artifact: [u8; 32],
        candidate: [u8; 16],
        route: [u8; 32],
        role: u8,
        cancellation: &CancellationToken,
    ) -> Result<(), crate::TransportConnectError> {
        if role > 1 || artifact == [0; 32] || candidate == [0; 16] || route == [0; 32] {
            return Err(crate::TransportConnectError::Configuration);
        }
        let mut body = Vec::with_capacity(192);
        codec::encode_head(&mut body, 4, 5);
        for (kind, bytes) in [
            (3, b"tunnel-relay-ready-1".as_slice()),
            (2, artifact.as_slice()),
            (2, candidate.as_slice()),
            (2, route.as_slice()),
        ] {
            codec::encode_head(&mut body, kind, bytes.len() as u64);
            body.extend_from_slice(bytes);
        }
        codec::encode_head(&mut body, 0, u64::from(role));
        if let Some(registered) = &self.registered {
            return registered
                .relay_exchange(
                    &self.relay_preparation,
                    "/tunnel/relay-ready",
                    &body,
                    cancellation,
                )
                .await;
        }
        let reply = self
            .relay_preparation
            .post("/tunnel/relay-ready", &body, 1, cancellation)
            .await
            .map_err(|_| crate::TransportConnectError::LiveAuthorizationUnknown)?;
        if reply.as_slice() != [0xf5] {
            return Err(crate::TransportConnectError::Protocol);
        }
        Ok(())
    }
    pub async fn relay_prepare(
        &self,
        request: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<(), crate::TransportConnectError> {
        if let Some(registered) = &self.registered {
            if self.external_relay {
                registered
                    .relay_exchange(
                        &self.relay_preparation,
                        "/tunnel/relay-prepare",
                        request,
                        cancellation,
                    )
                    .await?;
            }
            return registered.prepare_request(request, cancellation).await;
        }
        if request.is_empty() || request.len() > 8192 {
            return Err(crate::TransportConnectError::Configuration);
        }
        let reply = self
            .relay_preparation
            .post("/tunnel/relay-prepare", request, 1, cancellation)
            .await
            .map_err(|_| crate::TransportConnectError::LiveAuthorizationUnknown)?;
        if reply.as_slice() != [0xf5] {
            return Err(crate::TransportConnectError::Protocol);
        }
        Ok(())
    }
    /// Commit the client leg after TxB. The authority-side relay control owns
    /// the paired server Grant retained by the original B-host publication;
    /// this call carries only the exact proof and client Grant from this
    /// attempt. A failed or uncertain response is terminal for this attempt.
    pub async fn relay_activate_client(
        &self,
        request: &[u8],
        activation: &[u8],
        client_grant: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<(), crate::TransportConnectError> {
        if request.is_empty()
            || request.len() > 8192
            || activation.is_empty()
            || activation.len() > 4096
            || client_grant.is_empty()
            || client_grant.len() > LIVE_TUNNEL_GRANT_BYTES
        {
            return Err(crate::TransportConnectError::Configuration);
        }
        let mut body = Zeroizing::new(Vec::with_capacity(
            request.len() + activation.len() + client_grant.len() + 64,
        ));
        codec::encode_head(&mut body, 4, 4);
        let tag = b"tunnel-relay-activate-client-1".as_slice();
        codec::encode_head(&mut body, 3, tag.len() as u64);
        body.extend_from_slice(tag);
        for bytes in [request, activation, client_grant] {
            codec::encode_head(&mut body, 2, bytes.len() as u64);
            body.extend_from_slice(bytes);
        }
        if let Some(registered) = &self.registered {
            if self.external_relay {
                registered
                    .relay_exchange(
                        &self.relay_preparation,
                        "/tunnel/relay-activate-client",
                        &body,
                        cancellation,
                    )
                    .await?;
            }
            return registered.complete_delivery(request, activation, client_grant, cancellation);
        }
        let reply = self
            .relay_preparation
            .post("/tunnel/relay-activate-client", &body, 1, cancellation)
            .await
            .map_err(|_| crate::TransportConnectError::LiveAuthorizationUnknown)?;
        if reply.as_slice() != [0xf5] {
            return Err(crate::TransportConnectError::Protocol);
        }
        Ok(())
    }
    pub async fn authorize_tunnel(
        &self,
        request: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<LiveTunnelAuthorization, crate::TransportConnectError> {
        if let Some(registered) = &self.registered {
            return registered.authorize(request, cancellation).await;
        }
        if request.is_empty() || request.len() > 8192 {
            return Err(crate::TransportConnectError::Configuration);
        }
        let response = self
            .activation
            .post(
                "/live/authorize",
                request,
                LIVE_TUNNEL_RESPONSE_BYTES,
                cancellation,
            )
            .await
            .map_err(|_| crate::TransportConnectError::LiveAuthorizationUnknown)?;
        let value = codec::decode_control_array(
            &response,
            Limits {
                bytes: LIVE_TUNNEL_RESPONSE_BYTES,
                nodes: 16_384,
            },
        )?;
        if value.raw().first().map(|byte| *byte >> 5) != Some(4)
            || value.len()? != 3
            || value.at(0)?.text()? != "live-tunnel-material-1"
        {
            return Err(crate::TransportConnectError::Protocol);
        }
        let activation = value.at(1)?.bytes()?.to_vec();
        let client_grant = value.at(2)?.bytes()?.to_vec();
        if activation.is_empty()
            || activation.len() > 4096
            || client_grant.is_empty()
            || client_grant.len() > LIVE_TUNNEL_GRANT_BYTES
        {
            return Err(crate::TransportConnectError::Protocol);
        }
        Ok(LiveTunnelAuthorization {
            activation,
            client_grant,
        })
    }
    pub fn activation_signing_key_id(&self) -> &str {
        &self.signing_key_id
    }
}
pub(crate) struct LiveSourceGeneration {
    pub(crate) root: Arc<EnvironmentRoot>,
    pub(crate) namespaces: Vec<Arc<Namespace>>,
    pub(crate) keys: IdentityKeys,
    client: Zeroizing<Vec<u8>>,
    server: Zeroizing<Vec<u8>>,
    issuer: [u8; 16],
    signing_key_id: String,
    issuance: Arc<ControlHTTPS>,
    activation: Arc<ControlHTTPS>,
    profile: ApplicationProfile,
    pub(crate) tunnel: Option<LiveTunnelSourceDetails>,
    pub(crate) reverse: Option<Arc<crate::crypto_v4::connect::reverse::Capture>>,
    pub(crate) provider: WssConnectOptions,
    carrier: LiveAuthorityCarrier,
    _charge: EnvironmentCharge,
    registered_artifact: Option<std::sync::Mutex<Option<Zeroizing<Vec<u8>>>>>,
    _registered_storage: Option<EnvironmentCharge>,
}
impl fmt::Debug for LiveSourceGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LiveSourceGeneration { <opaque> }")
    }
}
pub(crate) struct LiveConnectionMaterial {
    pub(crate) generation: Arc<LiveSourceGeneration>,
    pub(crate) pending: PendingDirectAdmission,
    pub(crate) bytes: PoolCredentialBytes,
    pub(crate) _storage: ResourceCharge,
    pub(crate) _registered_custody: Option<registered::OriginalCustody>,
}
#[derive(Debug)]
pub(crate) struct LiveTunnelSourceDetails {
    pub(crate) control: Arc<LiveTunnelAuthorityControl>,
    pub(crate) relay_certificate: Zeroizing<Vec<u8>>,
    pub(crate) service: String,
    pub(crate) audience: String,
}
impl fmt::Debug for LiveConnectionMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LiveConnectionMaterial { <opaque> }")
    }
}
impl LiveSourceGeneration {
    pub(crate) fn capture(
        root: Arc<EnvironmentRoot>,
        configuration: LiveAuthoritySourceConfiguration,
    ) -> Result<Arc<Self>, MaterialSourceError> {
        Self::capture_with_tunnel(root, configuration, None)
    }
    pub(crate) fn capture_with_tunnel(
        root: Arc<EnvironmentRoot>,
        configuration: LiveAuthoritySourceConfiguration,
        tunnel_configuration: Option<LiveTunnelSourceConfiguration>,
    ) -> Result<Arc<Self>, MaterialSourceError> {
        Self::capture_with_reverse(root, configuration, tunnel_configuration, None)
    }
    pub(crate) fn capture_with_reverse(
        root: Arc<EnvironmentRoot>,
        mut configuration: LiveAuthoritySourceConfiguration,
        tunnel_configuration: Option<LiveTunnelSourceConfiguration>,
        reverse: Option<Arc<crate::crypto_v4::connect::reverse::Capture>>,
    ) -> Result<Arc<Self>, MaterialSourceError> {
        if reverse.is_some() && tunnel_configuration.is_none() {
            return Err(MaterialSourceError::MaterialUnavailable);
        }
        if !configuration.identity.belongs_to(&root)
            || configuration.namespaces.is_empty()
            || configuration.namespaces.len() > if tunnel_configuration.is_some() { 8 } else { 3 }
            || configuration.namespaces.capacity()
                > if tunnel_configuration.is_some() { 8 } else { 3 }
            || configuration.client_certificate.is_empty()
            || configuration.client_certificate.len() > 8192
            || configuration.client_certificate.capacity() > 8192
            || configuration.server_certificate.is_empty()
            || configuration.server_certificate.len() > 8192
            || configuration.server_certificate.capacity() > 8192
            || configuration.activation_signing_key_id.is_empty()
            || configuration.activation_signing_key_id.len() > 128
            || configuration.activation_signing_key_id.capacity() > 256
            || configuration.provider.timeout.is_zero()
            || configuration.provider.timeout > std::time::Duration::from_secs(30)
            || configuration.provider.publication_timeout.is_zero()
            || configuration.provider.publication_timeout > std::time::Duration::from_secs(5)
            || !(1..=64).contains(&configuration.provider.queue_messages)
            || !(16384..=262144).contains(&configuration.provider.prepare_bytes)
            || configuration.provider.native_runtime_bytes < 1048576
            || configuration.provider.ca_certificates_der.capacity() > 32
            || configuration
                .provider
                .origin
                .as_ref()
                .is_some_and(|origin| origin.len() > 2048 || origin.capacity() > 4096)
        {
            return Err(MaterialSourceError::MaterialUnavailable);
        }
        let ca_bytes = configuration
            .provider
            .ca_certificates_der
            .iter()
            .try_fold(0u64, |sum, certificate| {
                if certificate.is_empty()
                    || certificate.len() > 65536
                    || certificate.capacity() > 65536
                {
                    return None;
                }
                sum.checked_add(certificate.capacity() as u64)
            })
            .ok_or(MaterialSourceError::ConfigurationCapacity)?;
        let charge = root
            .reserve_environment(ResourceLimits {
                sdk_bytes: 65536 + ca_bytes,
                items: 8,
                work_slots: 1,
                ..ResourceLimits::default()
            })
            .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
        configuration.namespaces.sort_unstable_by_key(Arc::as_ptr);
        if configuration
            .namespaces
            .windows(2)
            .any(|pair| Arc::ptr_eq(&pair[0], &pair[1]))
        {
            return Err(MaterialSourceError::MaterialUnavailable);
        }
        configuration
            .identity
            .verify_certificate_identity(&configuration.client_certificate)?;
        crate::crypto_v4::connect::verify_live_source_policy(
            &root,
            &configuration.namespaces,
            [
                &configuration.client_certificate,
                &configuration.server_certificate,
            ],
            configuration.artifact_issuer_key_id,
            &configuration.activation_signing_key_id,
        )?;
        let issuance = Arc::new(
            ControlHTTPS::new(root.clone(), configuration.issuance)
                .map_err(|_| MaterialSourceError::MaterialUnavailable)?,
        );
        let activation = Arc::new(
            ControlHTTPS::new(root.clone(), configuration.activation)
                .map_err(|_| MaterialSourceError::MaterialUnavailable)?,
        );
        let tunnel = if let Some(tunnel) = tunnel_configuration {
            if tunnel.control.activation_signing_key_id != configuration.activation_signing_key_id
                || tunnel.relay_certificate.is_empty()
                || tunnel.relay_certificate.len() > 8192
                || tunnel.relay_certificate.capacity() > 8192
                || tunnel.relay_service.is_empty()
                || tunnel.relay_service.len() > 128
                || tunnel.relay_service.capacity() > 256
                || tunnel.relay_audience.is_empty()
                || tunnel.relay_audience.len() > 128
                || tunnel.relay_audience.capacity() > 256
            {
                return Err(MaterialSourceError::MaterialUnavailable);
            }
            let control = LiveTunnelAuthorityControl::new(root.clone(), tunnel.control)?;
            Some(LiveTunnelSourceDetails {
                control,
                relay_certificate: Zeroizing::new(tunnel.relay_certificate),
                service: tunnel.relay_service,
                audience: tunnel.relay_audience,
            })
        } else {
            None
        };
        Ok(Arc::new(Self {
            root,
            namespaces: configuration.namespaces,
            keys: configuration.identity,
            client: Zeroizing::new(configuration.client_certificate),
            server: Zeroizing::new(configuration.server_certificate),
            issuer: configuration.artifact_issuer_key_id,
            signing_key_id: configuration.activation_signing_key_id,
            issuance,
            activation,
            profile: configuration.application_profile,
            tunnel,
            reverse,
            provider: configuration.provider,
            carrier: configuration.carrier,
            _charge: charge,
            registered_artifact: None,
            _registered_storage: None,
        }))
    }
    pub(crate) fn capture_registered(
        root: Arc<EnvironmentRoot>,
        configuration: RegisteredLiveTunnelSourceConfiguration,
        reverse: Option<Arc<crate::crypto_v4::connect::reverse::Capture>>,
    ) -> Result<Arc<Self>, MaterialSourceError> {
        let RegisteredLiveTunnelSourceConfiguration {
            source,
            tunnel,
            artifact,
            authority,
        } = configuration;
        let artifact = Zeroizing::new(artifact);
        if artifact.is_empty()
            || artifact.len() > 65536
            || artifact.capacity() > 65536
            || source.activation.base_path != "/flowersec/control/live"
            || tunnel.control.activation.base_path != "/flowersec/control/live"
            || tunnel.control.relay_preparation.base_path.is_empty()
                && tunnel.control.relay_preparation.client_chain_der.first()
                    != tunnel.control.activation.client_chain_der.first()
        {
            return Err(MaterialSourceError::MaterialUnavailable);
        }
        let storage = root
            .reserve_environment(ResourceLimits {
                sdk_bytes: 65536,
                items: 1,
                work_slots: 1,
                ..ResourceLimits::default()
            })
            .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
        let mut generation =
            Self::capture_with_reverse(root.clone(), source, Some(tunnel), reverse)?;
        let original =
            Arc::get_mut(&mut generation).ok_or(MaterialSourceError::MaterialUnavailable)?;
        let tunnel = original
            .tunnel
            .as_mut()
            .ok_or(MaterialSourceError::MaterialUnavailable)?;
        let control =
            Arc::get_mut(&mut tunnel.control).ok_or(MaterialSourceError::MaterialUnavailable)?;
        control.registered = Some(RegisteredLiveClientControl::new(
            root,
            control.activation.clone(),
            original.keys.clone(),
            &artifact,
            authority,
        )?);
        original.registered_artifact = Some(std::sync::Mutex::new(Some(artifact)));
        original._registered_storage = Some(storage);
        Ok(generation)
    }
    pub(crate) fn supports_requirements(
        &self,
        requirements: &crate::ConnectionRequirements,
    ) -> Result<(), MaterialSourceError> {
        if requirements
            .application_profile
            .as_ref()
            .is_some_and(|profile| profile != self.profile.name())
        {
            return Err(MaterialSourceError::ConnectionRequirementUnavailable);
        }
        self.carrier.supports(requirements)
    }
    pub(crate) async fn acquire(
        self: &Arc<Self>,
        requirements: &crate::ConnectionRequirements,
        cancellation: &CancellationToken,
    ) -> Result<LiveConnectionMaterial, MaterialSourceError> {
        // Reject unavailable installed capabilities before TxA or material
        // allocation. This does not trust the issuance reply to advertise them.
        self.supports_requirements(requirements)?;
        if cancellation.is_cancelled() {
            return Err(MaterialSourceError::Canceled);
        }
        crate::crypto_v4::connect::verify_live_source_policy(
            &self.root,
            &self.namespaces,
            [&self.client, &self.server],
            self.issuer,
            &self.signing_key_id,
        )?;
        let mut storage = self
            .root
            .reserve_environment(ResourceLimits {
                sdk_bytes: 163840,
                items: 4,
                work_slots: 1,
                ..ResourceLimits::default()
            })
            .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
        let artifact = if let Some(installed) = &self.registered_artifact {
            installed
                .lock()
                .expect("registered original TxA acquisition")
                .take()
                .ok_or(MaterialSourceError::MaterialUnavailable)?
        } else {
            let mut request = [0u8; 35];
            request[..3].copy_from_slice(&[0x81, 0x58, 0x20]);
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut request[3..])
                .map_err(|_| MaterialSourceError::MaterialUnavailable)?;
            let path = if self.tunnel.is_some() {
                "/issue/artifact"
            } else {
                "/issue/direct"
            };

            self.issuance
                .post(path, &request, 65536, cancellation)
                .await
                .map_err(|error| match error {
                    crate::ControlHTTPSFailure::Canceled => MaterialSourceError::Canceled,
                    crate::ControlHTTPSFailure::Capacity => {
                        MaterialSourceError::ConfigurationCapacity
                    }
                    _ => MaterialSourceError::MaterialUnavailable,
                })?
        };
        let document = codec::decode(
            &artifact,
            "Artifact",
            Limits {
                bytes: 65536,
                nodes: 16384,
            },
            None,
        )
        .map_err(|_| MaterialSourceError::MaterialUnavailable)?;
        if document
            .b::<16>("Artifact", "issuer_key_id")
            .map_err(|_| MaterialSourceError::MaterialUnavailable)?
            != self.issuer
            || document
                .field("Artifact", "candidates")
                .and_then(|candidates| candidates.len())
                .map_err(|_| MaterialSourceError::MaterialUnavailable)?
                == 0
            || document
                .field("Artifact", "session_contract")
                .and_then(|contract| contract.u("SessionContract", "application_profile"))
                .map_err(|_| MaterialSourceError::MaterialUnavailable)?
                != self.profile.wire()
            || document
                .u("Artifact", "required_features")
                .map_err(|_| MaterialSourceError::MaterialUnavailable)?
                & !crate::checkpoint_v4::application_features(document)
                    .map_err(|_| MaterialSourceError::MaterialUnavailable)?
                != 0
            || self.profile == ApplicationProfile::Execution
                && !self.root.application_config().execution
            || document
                .field("Artifact", "crypto_profile_id")
                .and_then(|profile| profile.text())
                .map_err(|_| MaterialSourceError::MaterialUnavailable)?
                != self.keys.profile()
        {
            return Err(MaterialSourceError::ConnectionRequirementUnavailable);
        }
        let candidate = document
            .field("Artifact", "candidates")
            .and_then(|candidates| candidates.at(0))
            .map_err(|_| MaterialSourceError::MaterialUnavailable)?;
        let tunnel = self.tunnel.is_some();
        let expected_path = u64::from(tunnel);
        let candidate_path = candidate
            .u("Candidate", "path_kind")
            .map_err(|_| MaterialSourceError::MaterialUnavailable)?;
        if candidate_path != expected_path {
            return Err(MaterialSourceError::ConnectionRequirementUnavailable);
        }
        let leg_field = if tunnel { "client_leg" } else { "direct_leg" };
        if candidate
            .field("Candidate", leg_field)
            .and_then(|leg| leg.u("Leg", "carrier"))
            .map_err(|_| MaterialSourceError::MaterialUnavailable)?
            != self.carrier.wire()
        {
            return Err(MaterialSourceError::ConnectionRequirementUnavailable);
        }
        crate::crypto_v4::connect::supports_route_requirements(
            &artifact,
            tunnel.then_some(0),
            requirements,
        )?;
        let mut attempt = [0; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut attempt)
            .map_err(|_| MaterialSourceError::MaterialUnavailable)?;
        let bytes = PoolCredentialBytes {
            artifact: artifact.to_vec(),
            client_certificate: self.client.to_vec(),
            server_certificate: self.server.to_vec(),
            activation: Vec::new(),
        };
        let pending = if tunnel {
            crate::crypto_v4::connect::prepare_live_tunnel_material(
                &self.root,
                &self.namespaces,
                &bytes,
                attempt,
                &self.signing_key_id,
            )?
        } else {
            crate::crypto_v4::connect::prepare_live_material(
                &self.root,
                &self.namespaces,
                &bytes,
                attempt,
                &self.signing_key_id,
            )?
        };
        let registered_custody = if let Some(registered) = self
            .tunnel
            .as_ref()
            .and_then(|tunnel| tunnel.control.registered.as_ref())
        {
            registered.bind_original(&pending)?;
            Some(registered.original_custody())
        } else {
            None
        };
        let storage = storage
            .attach(&pending.account)
            .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
        if let Some(reverse) = &self.reverse {
            crate::crypto_v4::connect::validate_live_reverse_tunnel_provider(
                &bytes.artifact,
                &pending,
                &self.provider,
                reverse,
            )?;
        } else if tunnel {
            crate::crypto_v4::connect::validate_live_tunnel_provider(
                &bytes.artifact,
                &pending,
                &self.provider,
            )?;
        } else {
            crate::crypto_v4::connect::validate_live_provider(
                &bytes.artifact,
                &pending,
                &self.provider,
            )?;
        }
        if cancellation.is_cancelled() {
            return Err(MaterialSourceError::Canceled);
        }
        Ok(LiveConnectionMaterial {
            generation: self.clone(),
            pending,
            bytes,
            _storage: storage,
            _registered_custody: registered_custody,
        })
    }
    pub(crate) fn authorization_request(
        pending: &PendingDirectAdmission,
        artifact_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, crate::TransportConnectError> {
        let artifact = codec::decode(
            artifact_bytes,
            "Artifact",
            Limits {
                bytes: 65536,
                nodes: 16384,
            },
            None,
        )?;
        let mut request = Zeroizing::new(Vec::with_capacity(1024));
        codec::encode_head(&mut request, 4, 13);
        for text in [
            "live-authorization-1",
            artifact.field("Artifact", "tenant_id")?.text()?,
            artifact.field("Artifact", "audience")?.text()?,
            artifact.field("Artifact", "crypto_profile_id")?.text()?,
        ] {
            codec::encode_head(&mut request, 3, text.len() as u64);
            request.extend_from_slice(text.as_bytes());
        }
        let issuer = artifact.b::<16>("Artifact", "issuer_key_id")?;
        let lease = artifact.b::<16>("Artifact", "lease_id")?;
        for bytes in [
            issuer.as_slice(),
            lease.as_slice(),
            pending.attempt_id.as_slice(),
            pending.artifact_digest.as_slice(),
            pending.certificate_digests[0].as_slice(),
            pending.certificate_digests[1].as_slice(),
        ] {
            codec::encode_head(&mut request, 2, bytes.len() as u64);
            request.extend_from_slice(bytes);
        }
        codec::encode_head(&mut request, 4, 3);
        codec::encode_head(&mut request, 0, u64::from(pending.candidate_index));
        for bytes in [
            pending.candidate_id.as_slice(),
            pending.route_digest.as_slice(),
        ] {
            codec::encode_head(&mut request, 2, bytes.len() as u64);
            request.extend_from_slice(bytes);
        }
        codec::encode_head(&mut request, 0, pending.initiation_not_after_ms);
        codec::encode_head(&mut request, 0, 1);
        Ok(request)
    }

    pub(crate) async fn authorize(
        &self,
        pending: &PendingDirectAdmission,
        artifact_bytes: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Zeroizing<Vec<u8>>, crate::TransportConnectError> {
        pending.account.check()?;
        let request = Self::authorization_request(pending, artifact_bytes)?;
        // One original dispatch. An unavailable reply is not an allow fact and
        // never causes a second TxB, credential reissue or handshake replay.
        let custody = crate::control_https_v4::ControlHTTPSCustody::new(pending.account.reserve(
            ResourceLimits {
                sdk_bytes: 49152,
                items: 3,
                work_slots: 1,
                ..ResourceLimits::default()
            },
        )?);
        let guard = || {
            if cancellation.is_cancelled() || self.root.is_closed() {
                return Err(crate::ControlHTTPSFailure::Canceled);
            }
            pending
                .account
                .check()
                .map_err(|_| crate::ControlHTTPSFailure::Rejected)?;
            if self
                .root
                .sample()
                .map_err(|_| crate::ControlHTTPSFailure::Unavailable)?
                .upper_ms
                >= pending.initiation_not_after_ms
            {
                return Err(crate::ControlHTTPSFailure::Deadline);
            }
            Ok(())
        };
        self.activation
            .post_owned(
                "/live/authorize",
                &request,
                4096,
                cancellation,
                false,
                &guard,
                custody,
            )
            .await
            .map_err(|_| crate::TransportConnectError::LiveAuthorizationUnknown)
    }
}
