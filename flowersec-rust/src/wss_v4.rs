//! One bounded native TLS/WebSocket worker per original prepared carrier.
use super::*;
use crate::api_v4::CleanupStatus;
use futures_util::{SinkExt, StreamExt};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::{
        Resumption, WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::{mpsc, oneshot},
};
use tokio_tungstenite::{
    client_async_with_config,
    tungstenite::{Message, client::IntoClientRequest, protocol::WebSocketConfig},
};
use x509_parser::{
    extensions::ParsedExtension,
    oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY},
    prelude::{FromDer, X509Certificate, X509Version},
};

pub(super) type RequestAuthorizationFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = std::result::Result<
                    super::serve::RequestAuthorization,
                    super::serve::ServeError,
                >,
            > + Send,
    >,
>;
pub(super) struct AcceptHooks<R, A> {
    pub(super) retain: R,
    pub(super) authorize: A,
}
#[derive(Clone, Debug)]
pub(super) struct PinPolicy {
    pub(super) digest: [u8; 32],
    pub(super) start: u64,
    pub(super) end: u64,
}
#[derive(Clone, Debug)]
pub(super) struct Policy {
    pub(super) carrier: u8,
    pub(super) preparation_budget: Option<flowersec_native_transport::CandidatePreparationBudget>,
    pub(super) preparation_capacity: Option<(
        flowersec_native_transport::PreparationLimits,
        flowersec_native_transport::PreparationLimits,
    )>,
    pub(super) preparation_parallel: Option<u8>,
    pub(super) path_kind: u8,
    pub(super) max_streams: usize,
    pub(super) max_credit: u64,
    pub(super) artifact: [u8; 32],
    binding_mode: BindingMode,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) path: String,
    subprotocol: String,
    origin: Option<String>,
    pub(super) pins: Option<Vec<PinPolicy>>,
    pub(super) maximum: usize,
    pub(super) live_maximum: usize,
    pub(super) ca: Vec<Vec<u8>>,
    pub(super) relay_budget: Option<Arc<RelayBudget>>,
    original_prepare: Option<Arc<Mutex<Option<ResourceCharge>>>>,
}

impl Policy {
    #[cfg(test)]
    pub(super) fn test_policy(
        limits: crate::namespace_v4::verifier::credential::tunnel::TunnelLimits,
        carrier: u8,
        host: String,
        port: u16,
        ca: Vec<Vec<u8>>,
        pin: Option<[u8; 32]>,
        budget: Arc<RelayBudget>,
    ) -> ConnectResult<Self> {
        if !(0..=2).contains(&carrier) || host.is_empty() || port == 0 {
            return Err(ConnectError::Configuration);
        }
        Ok(Self {
            carrier,
            preparation_budget: None,
            preparation_capacity: None,
            preparation_parallel: None,
            path_kind: 1,
            max_streams: 8,
            max_credit: limits.max_queue_bytes,
            artifact: [7; 32],
            binding_mode: BindingMode::AuthenticatedContext,
            host,
            port,
            path: "/flowersec/v4/tunnel".into(),
            subprotocol: "flowersec.tunnel.v4".into(),
            origin: None,
            pins: pin.map(|digest| {
                vec![PinPolicy {
                    digest,
                    start: 0,
                    end: 100_000,
                }]
            }),
            maximum: limits.max_envelope_bytes as usize,
            live_maximum: limits.max_envelope_bytes as usize,
            ca,
            relay_budget: Some(budget),
            original_prepare: None,
        })
    }
}

impl Policy {
    pub(super) fn fund_prepaid(
        &mut self,
        account: &ResourceAccount,
        options: &WssConnectOptions,
        charge: ResourceCharge,
    ) -> ConnectResult<()> {
        if self.original_prepare.is_some()
            || !charge.matches(account, self.preparation_limits(options)?)
        {
            return Err(ConnectError::Configuration);
        }
        self.original_prepare = Some(Arc::new(Mutex::new(Some(charge))));
        Ok(())
    }
    pub(super) fn fund_relay(
        &mut self,
        account: &ResourceAccount,
        vector: ResourceLimits,
    ) -> ConnectResult<()> {
        if self.relay_budget.is_none() || self.original_prepare.is_some() {
            return Err(ConnectError::Configuration);
        }
        self.original_prepare = Some(Arc::new(Mutex::new(Some(account.reserve(vector)?))));
        Ok(())
    }
    pub(super) fn take_preparation(
        &self,
        account: &ResourceAccount,
        vector: ResourceLimits,
    ) -> ConnectResult<ResourceCharge> {
        if let Some(original) = &self.original_prepare {
            let charge = original
                .lock()
                .expect("original native preparation prepayment")
                .take()
                .ok_or(ConnectError::Configuration)?;
            if !charge.matches(account, vector) {
                return Err(ConnectError::Configuration);
            }
            Ok(charge)
        } else {
            Ok(account.reserve(vector)?)
        }
    }
    pub(super) fn preparation_limits(
        &self,
        options: &WssConnectOptions,
    ) -> ConnectResult<ResourceLimits> {
        if self.carrier == 1 {
            Ok(ResourceLimits {
                sdk_bytes: (self.maximum as u64)
                    .checked_mul(options.queue_messages as u64 + 4)
                    .and_then(|bytes| bytes.checked_add(16384))
                    .ok_or(ConnectError::Capacity)?,
                provider_bytes: options
                    .native_runtime_bytes
                    .checked_add(options.prepare_bytes as u64)
                    .and_then(|bytes| bytes.checked_add(524288))
                    .ok_or(ConnectError::Capacity)?,
                items: options.queue_messages as u64 + 8,
                work_slots: 4,
                tasks: 4,
                timers: 2,
                connections: 1,
                tls_handshakes: 1,
                native_handles: 8,
                ..ResourceLimits::default()
            })
        } else {
            let capacity = self
                .max_streams
                .checked_mul(2)
                .and_then(|value| value.checked_add(11))
                .ok_or(ConnectError::Capacity)?;
            let window = (capacity as u64)
                .checked_mul(self.live_maximum as u64)
                .and_then(|value| value.checked_add(self.max_credit))
                .and_then(|value| value.checked_add(self.maximum as u64))
                .and_then(|value| value.checked_add(if self.carrier == 2 { 65536 } else { 0 }))
                .ok_or(ConnectError::Capacity)?;
            let required = window
                .checked_add(options.prepare_bytes as u64)
                .and_then(|value| value.checked_add(196608))
                .and_then(|value| value.checked_add((capacity as u64 + 2).checked_mul(16384)?))
                .ok_or(ConnectError::Capacity)?;
            if options.native_runtime_bytes < required {
                return Err(ConnectError::Capacity);
            }
            Ok(ResourceLimits {
                sdk_bytes: (self.maximum as u64)
                    .checked_mul(options.queue_messages as u64 + 4)
                    .ok_or(ConnectError::Capacity)?,
                provider_bytes: options.native_runtime_bytes,
                items: options.queue_messages as u64 + 8,
                tasks: 24,
                work_slots: 24,
                timers: 8,
                connections: 1,
                tls_handshakes: 1,
                native_handles: 32,
                ..ResourceLimits::default()
            })
        }
    }
    pub(super) fn new_candidate(
        material: &PoolConnectionMaterial,
        options: &WssConnectOptions,
        index: u8,
    ) -> ConnectResult<Self> {
        Self::from_route_candidate(
            &material.bytes.artifact,
            material.admission.artifact_digest,
            &material.admission.account,
            Some(material.bytes.activation.as_slice()),
            options,
            material
                .admission
                .tunnel
                .as_ref()
                .map(|hop| hop.endpoint_role),
            false,
            index,
        )
    }
    pub(super) fn new(
        material: &PoolConnectionMaterial,
        options: &WssConnectOptions,
    ) -> ConnectResult<Self> {
        Self::from_route(
            &material.bytes.artifact,
            material.admission.artifact_digest,
            &material.admission.account,
            (material.admission.source == codec::ActivationSource::PreauthorizedPool)
                .then_some(material.bytes.activation.as_slice()),
            options,
            material
                .admission
                .tunnel
                .as_ref()
                .map(|hop| hop.endpoint_role),
            false,
        )
    }
    pub(super) fn new_reverse(
        material: &PoolConnectionMaterial,
        options: &WssConnectOptions,
    ) -> ConnectResult<Self> {
        let role = material
            .admission
            .tunnel
            .as_ref()
            .ok_or(ConnectError::Configuration)?
            .endpoint_role;
        Self::from_route(
            &material.bytes.artifact,
            material.admission.artifact_digest,
            &material.admission.account,
            (material.admission.source == codec::ActivationSource::PreauthorizedPool)
                .then_some(material.bytes.activation.as_slice()),
            options,
            Some(role),
            true,
        )
    }
    pub(super) fn new_reverse_endpoint(
        material: &PoolConnectionMaterial,
        options: &WssConnectOptions,
    ) -> ConnectResult<Self> {
        let mut policy = Self::new_reverse(material, options)?;
        policy.relay_budget = None;
        Ok(policy)
    }
    /// The relay sees only the issuer's verified public Grant projection. Its
    /// provider configuration and physical direction are installed separately.
    pub(super) fn new_relay(
        endpoint: &super::relay_publication::RelayEndpoint,
        account: &ResourceAccount,
        options: &WssConnectOptions,
        listener: bool,
    ) -> ConnectResult<Self> {
        if options.timeout.is_zero()
            || options.timeout > Duration::from_secs(30)
            || options.publication_timeout.is_zero()
            || options.publication_timeout > Duration::from_secs(5)
            || !(1..=64).contains(&options.queue_messages)
            || !(16384..=262144).contains(&options.prepare_bytes)
            || options.native_runtime_bytes < 1048576
            || options.native_runtime_bytes > (1 << 30)
            || options.binding_mode != BindingMode::AuthenticatedContext
        {
            return Err(ConnectError::Configuration);
        }
        let grant = decode(&endpoint.grant, "Grant", 9302, Context::default())?;
        let route = grant.field("Grant", "route_descriptor")?;
        Self::from_public_relay_route(
            route,
            "Route",
            endpoint.hop.endpoint_role,
            endpoint.hop.limits,
            grant
                .field("Grant", "parent_ref")?
                .b("GrantParentRef", "artifact_digest")?,
            account,
            options,
            listener,
        )
    }
    pub(super) fn new_live_relay_preparation(
        candidate: &[u8],
        role: u8,
        limits: crate::namespace_v4::verifier::credential::tunnel::TunnelLimits,
        artifact: [u8; 32],
        account: &ResourceAccount,
        options: &WssConnectOptions,
        listener: bool,
    ) -> ConnectResult<Self> {
        if role > 1 || artifact == [0; 32] {
            return Err(ConnectError::Configuration);
        }
        let candidate = decode(candidate, "Candidate", 65536, Context::default())?;
        if candidate.u("Candidate", "path_kind")? != 1 {
            return Err(ConnectError::Configuration);
        }
        Self::from_public_relay_route(
            candidate,
            "Candidate",
            role,
            limits,
            artifact,
            account,
            options,
            listener,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "WSS preparation keeps authenticated route inputs separate from physical socket and resource ownership."
    )]
    fn from_public_relay_route(
        route: Value<'_>,
        schema: &str,
        role: u8,
        limits: crate::namespace_v4::verifier::credential::tunnel::TunnelLimits,
        artifact: [u8; 32],
        account: &ResourceAccount,
        options: &WssConnectOptions,
        listener: bool,
    ) -> ConnectResult<Self> {
        if options.timeout.is_zero()
            || options.timeout > Duration::from_secs(30)
            || options.publication_timeout.is_zero()
            || options.publication_timeout > Duration::from_secs(5)
            || !(1..=64).contains(&options.queue_messages)
            || !(16384..=262144).contains(&options.prepare_bytes)
            || options.native_runtime_bytes < 1048576
            || options.native_runtime_bytes > (1 << 30)
            || options.binding_mode != BindingMode::AuthenticatedContext
        {
            return Err(ConnectError::Configuration);
        }
        let leg = route.field(
            schema,
            if role == 0 {
                "client_leg"
            } else {
                "server_leg"
            },
        )?;
        let carrier = leg.u("Leg", "carrier")? as u8;
        let tuple = match carrier {
            0 => ("flowersec-tunnel/4", "", ""),
            1 => ("http/1.1", "/flowersec/v4/tunnel", "flowersec.tunnel.v4"),
            2 => ("h3", "/flowersec/webtransport/v4/tunnel", ""),
            _ => return Err(ConnectError::Configuration),
        };
        if leg.u("Leg", "access_class")? != 0
            || leg.u(
                "Leg",
                if listener {
                    "listener_role"
                } else {
                    "dialer_role"
                },
            )? != 2
            || leg.field("Leg", "alpn")?.text()? != tuple.0
            || leg.field("Leg", "path")?.text()? != tuple.1
            || leg.field("Leg", "subprotocol")?.text()? != tuple.2
        {
            return Err(ConnectError::Configuration);
        }
        let host = leg.field("Leg", "host")?.text()?.to_owned();
        if host
            .parse::<IpAddr>()
            .is_ok_and(|address| address != options.remote_address)
        {
            return Err(ConnectError::Configuration);
        }
        let origin = options.origin.clone();
        if carrier == 0 && origin.is_some() || carrier == 2 && !listener && origin.is_some() {
            return Err(ConnectError::Configuration);
        }
        if let Some(policy) = leg.optional("Leg", "origin_policy")? {
            match &origin {
                None if !policy.field("OriginPolicy", "allow_absent")?.boolean()? => {
                    return Err(ConnectError::Configuration);
                }
                Some(origin)
                    if !policy
                        .field("OriginPolicy", "origins")?
                        .children()?
                        .any(|value| value.is_ok_and(|value| value.text() == Ok(origin))) =>
                {
                    return Err(ConnectError::Configuration);
                }
                _ => {}
            }
        } else if origin.is_some() {
            return Err(ConnectError::Configuration);
        }
        let tls = leg.field("Leg", "tls_policy")?;
        let pins = if tls.u("TLSPolicy", "mode")? == 0 {
            if !listener
                && (options.ca_certificates_der.is_empty()
                    || options.ca_certificates_der.len() > 16
                    || options.ca_certificates_der.iter().any(|certificate| {
                        certificate.is_empty() || certificate.capacity() > 65536
                    }))
            {
                return Err(ConnectError::Configuration);
            }
            None
        } else {
            let mut pins = Vec::new();
            let now = account.security_time()?;
            for pin in tls.field("TLSPolicy", "pins")?.children()? {
                let pin = pin?;
                let start = pin.u("TLSPin", "not_before_ms")?;
                let end = pin.u("TLSPin", "not_after_ms")?;
                if now.lower_ms >= start && now.upper_ms < end {
                    pins.push(PinPolicy {
                        digest: pin.b("TLSPin", "leaf_der_sha256")?,
                        start,
                        end,
                    });
                }
            }
            if pins.is_empty() {
                return Err(ConnectError::Tls);
            }
            Some(pins)
        };
        let live_maximum =
            usize::try_from(limits.max_envelope_bytes).map_err(|_| ConnectError::Capacity)?;
        if !(10354..=(1 << 20) + 8).contains(&live_maximum)
            || options.native_runtime_bytes
                < (live_maximum.max(65544) * 2 + options.prepare_bytes + 196608) as u64
        {
            return Err(ConnectError::Capacity);
        }
        let mappings = limits
            .max_pending_native_mappings
            .checked_add(limits.max_resident_native_mappings)
            .ok_or(ConnectError::Capacity)?;
        let max_streams =
            usize::try_from(mappings.div_ceil(2)).map_err(|_| ConnectError::Capacity)?;
        let max_credit = limits.max_queue_bytes;
        Ok(Self {
            carrier,
            preparation_budget: None,
            preparation_capacity: None,
            preparation_parallel: None,
            path_kind: 1,
            max_streams,
            max_credit,
            artifact,
            binding_mode: BindingMode::AuthenticatedContext,
            host,
            port: leg.u("Leg", "port")? as u16,
            path: tuple.1.to_owned(),
            subprotocol: tuple.2.to_owned(),
            origin,
            pins,
            maximum: live_maximum,
            live_maximum,
            ca: options.ca_certificates_der.clone(),
            relay_budget: Some(RelayBudget::new(account.clone(), limits)?),
            original_prepare: None,
        })
    }
    pub(super) fn new_live(
        artifact: &[u8],
        admission: &crate::namespace_v4::verifier::credential::PendingDirectAdmission,
        options: &WssConnectOptions,
    ) -> ConnectResult<Self> {
        Self::from_route(
            artifact,
            admission.artifact_digest,
            &admission.account,
            None,
            options,
            None,
            false,
        )
    }
    pub(super) fn new_live_tunnel(
        artifact: &[u8],
        admission: &crate::namespace_v4::verifier::credential::PendingDirectAdmission,
        options: &WssConnectOptions,
    ) -> ConnectResult<Self> {
        Self::from_route(
            artifact,
            admission.artifact_digest,
            &admission.account,
            None,
            options,
            Some(0),
            false,
        )
    }
    pub(super) fn new_live_reverse_tunnel(
        artifact: &[u8],
        admission: &crate::namespace_v4::verifier::credential::PendingDirectAdmission,
        options: &WssConnectOptions,
    ) -> ConnectResult<Self> {
        Self::from_route(
            artifact,
            admission.artifact_digest,
            &admission.account,
            None,
            options,
            Some(0),
            true,
        )
    }
    pub(super) fn new_live_server_carrier_registration(
        artifact: &[u8],
        registration: &crate::namespace_v4::verifier::credential::VerifiedLiveTunnelRegistration,
        options: &WssConnectOptions,
    ) -> ConnectResult<Self> {
        Self::from_route(
            artifact,
            registration.artifact_digest(),
            registration.account(),
            None,
            options,
            Some(1),
            false,
        )
    }
    pub(super) fn new_live_server_listener_registration(
        artifact: &[u8],
        registration: &crate::namespace_v4::verifier::credential::VerifiedLiveTunnelRegistration,
        options: &WssConnectOptions,
    ) -> ConnectResult<Self> {
        Self::from_route(
            artifact,
            registration.artifact_digest(),
            registration.account(),
            None,
            options,
            Some(1),
            true,
        )
    }
    fn from_route(
        artifact_bytes: &[u8],
        artifact_digest: [u8; 32],
        account: &ResourceAccount,
        pool_activation: Option<&[u8]>,
        options: &WssConnectOptions,
        endpoint_role: Option<u8>,
        reverse: bool,
    ) -> ConnectResult<Self> {
        Self::from_route_candidate(
            artifact_bytes,
            artifact_digest,
            account,
            pool_activation,
            options,
            endpoint_role,
            reverse,
            0,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "WSS preparation keeps authenticated route inputs separate from physical socket and resource ownership."
    )]
    pub(super) fn from_route_candidate(
        artifact_bytes: &[u8],
        artifact_digest: [u8; 32],
        account: &ResourceAccount,
        pool_activation: Option<&[u8]>,
        options: &WssConnectOptions,
        endpoint_role: Option<u8>,
        reverse: bool,
        candidate_index: u8,
    ) -> ConnectResult<Self> {
        if options.timeout.is_zero()
            || options.timeout > Duration::from_secs(30)
            || options.publication_timeout.is_zero()
            || options.publication_timeout > Duration::from_secs(5)
            || !(1..=64).contains(&options.queue_messages)
            || !(16_384..=262_144).contains(&options.prepare_bytes)
            || options.native_runtime_bytes < 1 << 20
        {
            return Err(ConnectError::Configuration);
        }
        let artifact = decode(artifact_bytes, "Artifact", 65536, Context::default())?;
        let candidate = artifact
            .field("Artifact", "candidates")?
            .at(candidate_index as usize)?;
        let path_kind = candidate.u("Candidate", "path_kind")? as u8;
        if path_kind != u8::from(endpoint_role.is_some())
            || endpoint_role.is_some_and(|role| role > 1)
            || path_kind == 1 && options.binding_mode != BindingMode::AuthenticatedContext
        {
            return Err(ConnectError::Configuration);
        }
        let field = match endpoint_role {
            None => "direct_leg",
            Some(0) => "client_leg",
            Some(1) => "server_leg",
            _ => return Err(ConnectError::Configuration),
        };
        let leg = candidate.field("Candidate", field)?;
        if let Some(role) = endpoint_role {
            let expected = if reverse {
                (2, u64::from(role))
            } else {
                (u64::from(role), 2)
            };
            if leg.u("Leg", "dialer_role")? != expected.0
                || leg.u("Leg", "listener_role")? != expected.1
            {
                return Err(ConnectError::Configuration);
            }
        }
        let carrier = leg.u("Leg", "carrier")? as u8;
        let tuple = match (path_kind, carrier) {
            (0, 0) => ("flowersec-direct/4", "", ""),
            (0, 1) => ("http/1.1", "/flowersec/v4/direct", "flowersec.direct.v4"),
            (0, 2) => ("h3", "/flowersec/webtransport/v4/direct", ""),
            (1, 0) => ("flowersec-tunnel/4", "", ""),
            (1, 1) => ("http/1.1", "/flowersec/v4/tunnel", "flowersec.tunnel.v4"),
            (1, 2) => ("h3", "/flowersec/webtransport/v4/tunnel", ""),
            _ => return Err(ConnectError::Configuration),
        };
        if leg.u("Leg", "access_class")? != 0
            || leg.field("Leg", "alpn")?.text()? != tuple.0
            || leg.field("Leg", "path")?.text()? != tuple.1
            || leg.field("Leg", "subprotocol")?.text()? != tuple.2
        {
            return Err(ConnectError::Configuration);
        }
        let host = leg.field("Leg", "host")?.text()?.to_owned();
        if host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip != options.remote_address)
        {
            return Err(ConnectError::Configuration);
        }
        let origin = options.origin.clone();
        if carrier != 1 && origin.is_some() {
            return Err(ConnectError::Configuration);
        }
        if let Some(policy) = leg.optional("Leg", "origin_policy")? {
            match &origin {
                None => {
                    if !policy.field("OriginPolicy", "allow_absent")?.boolean()? {
                        return Err(ConnectError::Configuration);
                    }
                }
                Some(value) => {
                    if !policy
                        .field("OriginPolicy", "origins")?
                        .children()?
                        .any(|v| v.is_ok_and(|v| v.text() == Ok(value.as_str())))
                    {
                        return Err(ConnectError::Configuration);
                    }
                }
            }
        } else if origin.is_some() {
            return Err(ConnectError::Configuration);
        }
        let (preparation_capacity, preparation_parallel) =
            if let Some(pool_activation) = pool_activation {
                let activation = decode(
                    pool_activation,
                    "ActivationAuthorization",
                    4096,
                    Context::with_activation_source(codec::ActivationSource::PreauthorizedPool),
                )?;
                let budget = activation
                    .field("ActivationAuthorization", "candidate_selection")?
                    .field("PoolSelectionRef", "attempt_budget")?;
                let per = budget.field("PoolAttemptBudget", "per_candidate")?;
                let per_limits = flowersec_native_transport::PreparationLimits {
                    preauth_input_bytes: per.u("CandidateAttemptBudget", "preauth_bytes")?,
                    address_attempts: u32::try_from(
                        per.u("CandidateAttemptBudget", "address_attempts")?,
                    )
                    .map_err(|_| ConnectError::Configuration)?,
                    work_units: per.u("CandidateAttemptBudget", "work_units")?,
                };
                let total_limits = flowersec_native_transport::PreparationLimits {
                    preauth_input_bytes: budget.u("PoolAttemptBudget", "total_preauth_bytes")?,
                    address_attempts: u32::try_from(
                        budget.u("PoolAttemptBudget", "total_address_attempts")?,
                    )
                    .map_err(|_| ConnectError::Configuration)?,
                    work_units: budget.u("PoolAttemptBudget", "total_work_units")?,
                };
                let parallel = u8::try_from(budget.u("PoolAttemptBudget", "parallel_candidates")?)
                    .map_err(|_| ConnectError::Configuration)?;
                if per_limits.preauth_input_bytes < options.prepare_bytes as u64
                    || total_limits.preauth_input_bytes < options.prepare_bytes as u64
                    || per_limits.address_attempts == 0
                    || per_limits.work_units == 0
                    || total_limits.address_attempts == 0
                    || total_limits.work_units == 0
                    || total_limits.preauth_input_bytes < per_limits.preauth_input_bytes
                    || total_limits.address_attempts < per_limits.address_attempts
                    || total_limits.work_units < per_limits.work_units
                    || parallel == 0
                    || parallel > 2
                {
                    return Err(ConnectError::Configuration);
                }
                (Some((per_limits, total_limits)), Some(parallel))
            } else {
                (None, None)
            };
        let tls = leg.field("Leg", "tls_policy")?;
        let pins = if tls.u("TLSPolicy", "mode")? == 0 {
            if !reverse
                && (options.ca_certificates_der.is_empty()
                    || options.ca_certificates_der.len() > 64
                    || options
                        .ca_certificates_der
                        .iter()
                        .map(Vec::len)
                        .sum::<usize>()
                        > 262144)
            {
                return Err(ConnectError::Configuration);
            }
            None
        } else {
            let mut pins = Vec::new();
            for p in tls.field("TLSPolicy", "pins")?.children()? {
                let p = p?;
                pins.push(PinPolicy {
                    digest: p.b("TLSPin", "leaf_der_sha256")?,
                    start: p.u("TLSPin", "not_before_ms")?,
                    end: p.u("TLSPin", "not_after_ms")?,
                });
            }
            let now = account.security_time()?;
            pins.retain(|p| now.lower_ms >= p.start && now.upper_ms < p.end);
            if pins.is_empty() {
                return Err(ConnectError::Tls);
            }
            Some(pins)
        };
        let maximum = artifact
            .field("Artifact", "session_contract")?
            .u("SessionContract", "max_frame")? as usize
            + 8;
        if path_kind == 1 && maximum < 10_346 + 8 {
            return Err(ConnectError::Capacity);
        }
        if options.native_runtime_bytes
            < (maximum.max(65544) * 2 + options.prepare_bytes + 196608) as u64
        {
            return Err(ConnectError::Capacity);
        }
        Ok(Self {
            carrier,
            preparation_budget: None,
            preparation_capacity,
            preparation_parallel,
            path_kind,
            max_streams: artifact
                .field("Artifact", "session_contract")?
                .u("SessionContract", "max_streams")? as usize,
            max_credit: artifact
                .field("Artifact", "session_contract")?
                .u("SessionContract", "max_credit")?,
            artifact: artifact_digest,
            binding_mode: options.binding_mode,
            host,
            port: leg.u("Leg", "port")? as u16,
            path: leg.field("Leg", "path")?.text()?.to_owned(),
            subprotocol: leg.field("Leg", "subprotocol")?.text()?.to_owned(),
            origin,
            pins,
            maximum: maximum.max(65544),
            live_maximum: maximum,
            ca: options.ca_certificates_der.clone(),
            relay_budget: None,
            original_prepare: None,
        })
    }
}
/// Installed before native Prepare from the original verified Grant. Every
/// complete envelope read and every original native write attempt uses this
/// same meter; queue drops and unsuccessful/uncertain writes do not refund it.
#[derive(Debug)]
pub(super) struct RelayBudget {
    pub(super) account: ResourceAccount,
    total: u64,
    maximum: u64,
    rate: u64,
    state: Mutex<(Instant, u64)>,
    _charge: ResourceCharge,
}
#[cfg(test)]
pub(super) fn test_relay_budget(
    account: ResourceAccount,
    limits: crate::namespace_v4::verifier::credential::tunnel::TunnelLimits,
) -> ConnectResult<Arc<RelayBudget>> {
    RelayBudget::new(account, limits)
}

#[cfg(test)]
impl RelayBudget {
    pub(super) fn test_reserved_bytes(&self) -> u64 {
        self.state.lock().expect("test relay meter observation").1
    }
}

impl RelayBudget {
    fn new(
        account: ResourceAccount,
        limits: crate::namespace_v4::verifier::credential::tunnel::TunnelLimits,
    ) -> ConnectResult<Arc<Self>> {
        if limits.max_rate_bytes_per_s == 0 || limits.max_total_bytes == 0 {
            return Err(ConnectError::Configuration);
        }
        let charge = account.reserve(ResourceLimits {
            sdk_bytes: 4096,
            items: 1,
            work_slots: 2,
            timers: 2,
            ..ResourceLimits::default()
        })?;
        Ok(Arc::new(Self {
            account,
            total: limits.max_total_bytes,
            maximum: limits.max_envelope_bytes,
            rate: limits.max_rate_bytes_per_s,
            state: Mutex::new((Instant::now(), 0)),
            _charge: charge,
        }))
    }
    pub(super) async fn reserve(
        &self,
        bytes: usize,
        cancellation: &CancellationToken,
    ) -> ConnectResult<()> {
        self.account.check()?;
        let due = {
            let mut state = self
                .state
                .lock()
                .expect("original signed relay byte budget");
            let total = state
                .1
                .checked_add(bytes as u64)
                .ok_or(ConnectError::Capacity)?;
            if bytes as u64 > self.maximum || total > self.total {
                return Err(ConnectError::Capacity);
            }
            let numerator = (bytes as u128)
                .checked_mul(1_000_000_000)
                .ok_or(ConnectError::Capacity)?;
            let nanos = numerator
                .checked_add(self.rate as u128 - 1)
                .ok_or(ConnectError::Capacity)?
                / self.rate as u128;
            let due = state
                .0
                .max(Instant::now())
                .checked_add(Duration::from_nanos(
                    u64::try_from(nanos).map_err(|_| ConnectError::Capacity)?,
                ))
                .ok_or(ConnectError::Capacity)?;
            state.0 = due;
            state.1 = total;
            due
        };
        loop {
            self.account.check()?;
            if cancellation.is_cancelled() {
                return Err(ConnectError::Canceled);
            }
            if Instant::now() >= due {
                return Ok(());
            }
            tokio::select! { _ = cancellation.cancelled() => return Err(ConnectError::Canceled),
            _ = tokio::time::sleep_until(due.min(Instant::now() + Duration::from_millis(10))) => {} }
        }
    }
}
#[derive(Debug)]
struct Clock(ResourceAccount);
impl rustls::time_provider::TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        self.0
            .security_time()
            .ok()
            .map(|n| UnixTime::since_unix_epoch(Duration::from_millis(n.upper_ms)))
    }
}
#[derive(Debug)]
struct Verifier {
    account: ResourceAccount,
    ca: Option<Arc<WebPkiServerVerifier>>,
    pins: Option<Vec<PinPolicy>>,
    supported: WebPkiSupportedAlgorithms,
    validity: Arc<Mutex<Option<(u64, u64)>>>,
}
fn tls_error() -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
}
pub(super) fn interval(
    der: &[u8],
    now: crate::environment_v4::TrustedTimeSample,
) -> std::result::Result<(u64, u64), rustls::Error> {
    let (remaining, cert) = X509Certificate::from_der(der).map_err(|_| tls_error())?;
    let start = u64::try_from(cert.validity().not_before.timestamp())
        .ok()
        .and_then(|n| n.checked_mul(1000))
        .ok_or_else(tls_error)?;
    let end = u64::try_from(cert.validity().not_after.timestamp())
        .ok()
        .and_then(|n| n.checked_mul(1000))
        .ok_or_else(tls_error)?;
    if !remaining.is_empty() || now.lower_ms < start || now.upper_ms >= end {
        return Err(tls_error());
    }
    Ok((start, end))
}
pub(super) fn pin_profile(der: &[u8]) -> std::result::Result<(), rustls::Error> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| tls_error())?;
    let key = cert.public_key();
    if cert.version() != X509Version::V3
        || key.algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY
        || !key
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .is_some_and(|oid| oid == OID_EC_P256)
        || cert
            .validity()
            .not_after
            .timestamp()
            .checked_sub(cert.validity().not_before.timestamp())
            .is_none_or(|d| d <= 0 || d > 1_209_600)
    {
        return Err(tls_error());
    }
    let mut seen = std::collections::HashSet::new();
    for extension in cert.extensions() {
        if !seen.insert(extension.oid.clone()) {
            return Err(tls_error());
        }
        match extension.parsed_extension() {
            ParsedExtension::KeyUsage(k) if !k.digital_signature() => return Err(tls_error()),
            ParsedExtension::ExtendedKeyUsage(k) if !k.server_auth && !k.any => {
                return Err(tls_error());
            }
            ParsedExtension::KeyUsage(_)
            | ParsedExtension::ExtendedKeyUsage(_)
            | ParsedExtension::BasicConstraints(_)
            | ParsedExtension::SubjectAlternativeName(_) => {}
            _ if extension.critical => return Err(tls_error()),
            _ => {}
        }
    }
    Ok(())
}
impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if chain.len() > 15 || leaf.len() + chain.iter().map(|c| c.len()).sum::<usize>() > 262144 {
            return Err(tls_error());
        }
        let now = self.account.security_time().map_err(|_| tls_error())?;
        let (mut from, mut until) = interval(leaf.as_ref(), now)?;
        if let Some(ca) = &self.ca {
            ca.verify_server_cert(
                leaf,
                chain,
                name,
                ocsp,
                UnixTime::since_unix_epoch(Duration::from_millis(now.lower_ms)),
            )?;
            ca.verify_server_cert(
                leaf,
                chain,
                name,
                ocsp,
                UnixTime::since_unix_epoch(Duration::from_millis(now.upper_ms)),
            )?;
            for cert in chain {
                let (a, b) = interval(cert.as_ref(), now)?;
                from = from.max(a);
                until = until.min(b);
            }
        } else {
            pin_profile(leaf.as_ref())?;
            let digest: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
            let pin = self
                .pins
                .as_ref()
                .and_then(|pins| {
                    pins.iter().find(|p| {
                        p.digest == digest
                            && p.start >= from
                            && p.end <= until
                            && now.lower_ms >= p.start
                            && now.upper_ms < p.end
                    })
                })
                .ok_or_else(tls_error)?;
            from = pin.start;
            until = pin.end;
        }
        *self.validity.lock().expect("TLS validity") = Some((from, until));
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(tls_error())
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, signature, &self.supported)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}
struct Meter {
    remaining: AtomicUsize,
    enabled: AtomicBool,
    budget: Option<flowersec_native_transport::CandidatePreparationBudget>,
}
struct LimitedIo {
    tcp: TcpStream,
    meter: Arc<Meter>,
}
impl Meter {
    fn take(&self, count: usize) -> io::Result<()> {
        if self.enabled.load(Ordering::Acquire)
            && self
                .remaining
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    n.checked_sub(count)
                })
                .is_err()
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
}
impl AsyncRead for LimitedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let allowed = if self.meter.enabled.load(Ordering::Acquire) {
            out.remaining()
                .min(self.meter.remaining.load(Ordering::Acquire))
        } else {
            out.remaining()
        };
        if allowed == 0 && out.remaining() != 0 {
            return Poll::Ready(Err(io::ErrorKind::PermissionDenied.into()));
        }
        let mut limited = ReadBuf::new(&mut out.initialize_unfilled()[..allowed]);
        match Pin::new(&mut self.tcp).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                let count = limited.filled().len();
                self.meter.take(count)?;
                if self.meter.enabled.load(Ordering::Acquire)
                    && let Some(budget) = &self.meter.budget
                {
                    budget
                        .debit_input(count as u64, u64::from(count != 0))
                        .map_err(|_| io::ErrorKind::PermissionDenied)?;
                }
                out.advance(count);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl AsyncWrite for LimitedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(budget) = &self.meter.budget {
            budget
                .check()
                .map_err(|_| io::ErrorKind::PermissionDenied)?;
        }
        Pin::new(&mut self.tcp).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_shutdown(cx)
    }
}
struct SendCommand {
    wire: Vec<u8>,
    reply: oneshot::Sender<ConnectResult<()>>,
}
#[derive(Clone)]
enum Security {
    Account(ResourceAccount),
    Environment(Arc<EnvironmentRoot>),
}
type ProviderCharge = PreparationCharge;
struct BoundExporter {
    artifact: [u8; 32],
    value: Zeroizing<[u8; 32]>,
}
pub(crate) struct Provider {
    preparation_budget: Option<flowersec_native_transport::CandidatePreparationBudget>,
    security: Mutex<Security>,
    id: [u8; 16],
    cancel: CancellationToken,
    commands: mpsc::Sender<SendCommand>,
    pending: AtomicUsize,
    read_stall: AtomicBool,
    stall_generation: AtomicU64,
    receivers: AtomicUsize,
    done: AtomicBool,
    accepted_preparation_pending: AtomicBool,
    preparation_observer_done: AtomicBool,
    cleanup_changed: tokio::sync::Notify,
    live: AtomicBool,
    validity: Arc<Mutex<Option<(u64, u64)>>>,
    deadline: Instant,
    publication_timeout: Duration,
    maximum: usize,
    live_maximum: AtomicUsize,
    relay_budget: Mutex<Option<Arc<RelayBudget>>>,
    relay_unassigned: AtomicBool,
    relay_assigned: tokio::sync::Notify,
    charge: Mutex<Option<ProviderCharge>>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    exporter: Mutex<Option<BoundExporter>>,
    first_hello: Mutex<Option<Vec<u8>>>,
    connect_diagnostic: OnceLock<Arc<crate::diagnostics_v4::DiagnosticActivity>>,
    connect_physical: Mutex<Option<crate::diagnostics_v4::DiagnosticPhysicalTail>>,
    connect_preparation: Mutex<Option<direct_carrier::PreparationTail>>,
    connect_cleanup: Option<Weak<ConnectCleanup>>,
}
// The original accepted task owns its authorization future independently of
// the native thread. Thread exit alone cannot refund this preparation frame.
struct AcceptedPreparationGuard(Arc<Provider>);
impl Drop for AcceptedPreparationGuard {
    fn drop(&mut self) {
        self.0
            .accepted_preparation_pending
            .store(false, Ordering::Release);
        self.0.cleanup_changed.notify_waiters();
    }
}
impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WssProvider { <opaque> }")
    }
}
impl Provider {
    pub(super) async fn prepare(
        account: ResourceAccount,
        policy: Policy,
        options: WssConnectOptions,
        deadline: Instant,
        caller: CancellationToken,
    ) -> ConnectResult<(Arc<Self>, mpsc::Receiver<Vec<u8>>)> {
        Self::prepare_original(account, policy, options, deadline, caller, None).await
    }
    pub(super) async fn prepare_observed(
        account: ResourceAccount,
        policy: Policy,
        options: WssConnectOptions,
        deadline: Instant,
        caller: CancellationToken,
        tail: direct_carrier::PreparationTail,
    ) -> ConnectResult<(Arc<Self>, mpsc::Receiver<Vec<u8>>)> {
        Self::prepare_original(account, policy, options, deadline, caller, Some(tail)).await
    }
    async fn prepare_original(
        account: ResourceAccount,
        policy: Policy,
        options: WssConnectOptions,
        deadline: Instant,
        caller: CancellationToken,
        preparation_tail: Option<direct_carrier::PreparationTail>,
    ) -> ConnectResult<(Arc<Self>, mpsc::Receiver<Vec<u8>>)> {
        if policy.carrier != 1 {
            return Err(ConnectError::Configuration);
        }
        let mut charge = policy.take_preparation(&account, policy.preparation_limits(&options)?)?;
        let tls_charge = charge.split(ResourceLimits {
            tls_handshakes: 1,
            ..ResourceLimits::default()
        })?;
        let (commands, rx) = mpsc::channel(1);
        let (incoming, input) = mpsc::channel(options.queue_messages);
        let (prepared, ready) = oneshot::channel();
        let mut id = [0; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id)
            .map_err(|_| ConnectError::Carrier)?;
        let provider = Arc::new(Self {
            preparation_budget: policy.preparation_budget.clone(),
            security: Mutex::new(Security::Account(account)),
            id,
            cancel: CancellationToken::new(),
            commands,
            pending: AtomicUsize::new(0),
            read_stall: AtomicBool::new(false),
            stall_generation: AtomicU64::new(0),
            receivers: AtomicUsize::new(0),
            done: AtomicBool::new(false),
            accepted_preparation_pending: AtomicBool::new(false),
            preparation_observer_done: AtomicBool::new(false),
            cleanup_changed: tokio::sync::Notify::new(),
            live: AtomicBool::new(false),
            validity: Arc::new(Mutex::new(None)),
            deadline,
            publication_timeout: options.publication_timeout,
            maximum: policy.maximum,
            live_maximum: AtomicUsize::new(policy.live_maximum),
            relay_budget: Mutex::new(policy.relay_budget.clone()),
            relay_unassigned: AtomicBool::new(false),
            relay_assigned: tokio::sync::Notify::new(),
            charge: Mutex::new(Some(ProviderCharge::Account(charge))),
            thread: Mutex::new(None),
            exporter: Mutex::new(None),
            first_hello: Mutex::new(None),
            connect_diagnostic: OnceLock::new(),
            connect_physical: Mutex::new(None),
            connect_preparation: Mutex::new(None),
            connect_cleanup: preparation_tail
                .as_ref()
                .and_then(|tail| tail.cleanup_owner().map(|cleanup| Arc::downgrade(&cleanup))),
        });
        let mut guard = ConnectGuard(Some(provider.clone()));
        let worker = provider.clone();
        let thread = std::thread::Builder::new()
            .name("flowersec-v4-wss".into())
            .stack_size(512 * 1024)
            .spawn(move || {
                let tail = WorkerTail(worker.clone());
                if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    runtime.block_on(
                        worker.drive(policy, options, rx, incoming, prepared, tls_charge),
                    );
                }
                drop(tail);
                worker.cleanup_changed.notify_waiters();
            });
        let spawned = thread.is_ok();
        match thread {
            Ok(thread) => *provider.thread.lock().expect("WSS thread") = Some(thread),
            Err(_) => provider.done.store(true, Ordering::Release),
        }
        // The observer owns the original preparation task until the worker
        // thread is joined and its provider charge is refunded.
        Self::spawn_cleanup_observer(provider.clone(), preparation_tail);
        if !spawned {
            return Err(ConnectError::Capacity);
        }
        let result = tokio::select! {_ = caller.cancelled()=>Err(ConnectError::Canceled),_ = tokio::time::sleep_until(deadline)=>Err(ConnectError::Deadline),result=ready=>result.unwrap_or(Err(ConnectError::Carrier))};
        if let Err(failure) = result.and_then(|()| provider.check()) {
            provider.close();
            return Err(failure);
        }
        guard.0 = None;
        Ok((provider, input))
    }
    fn spawn_cleanup_observer(
        physical: Arc<Self>,
        preparation_tail: Option<direct_carrier::PreparationTail>,
    ) {
        tokio::spawn(async move {
            // Receiver drops can wake this notification too. Keep waiting
            // until WorkerTail has set done, then observe the actual OS
            // thread exit before joining and refunding the provider charge.
            loop {
                if physical.done.load(Ordering::Acquire) {
                    break;
                }
                let notified = physical.cleanup_changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if physical.done.load(Ordering::Acquire) {
                    break;
                }
                notified.await;
            }
            loop {
                let notified = physical.cleanup_changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if physical.cleanup_physical().complete {
                    break;
                }
                tokio::select! {
                    _ = notified => {},
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                }
            }
            // The same full provider reservation funds this observer. Take
            // it only after thread join and receiver retirement, then refund
            // immediately before publishing completion and retiring tails.
            let charge = physical.charge.lock().expect("WSS observer charge").take();
            drop(charge);
            physical
                .preparation_observer_done
                .store(true, Ordering::Release);
            physical.cleanup();
            drop(preparation_tail);
        });
    }
    fn account(&self) -> ConnectResult<ResourceAccount> {
        match &*self.security.lock().expect("WSS security owner") {
            Security::Account(account) => Ok(account.clone()),
            Security::Environment(_) => Err(ConnectError::Configuration),
        }
    }
    pub(super) fn attach(&self, account: ResourceAccount) -> ConnectResult<()> {
        let mut security = self.security.lock().expect("WSS security owner");
        let Security::Environment(root) = &*security else {
            return Err(ConnectError::Configuration);
        };
        if !account.belongs_to(root) {
            return Err(ConnectError::Configuration);
        }
        let mut charge = self.charge.lock().expect("WSS charge");
        match charge.as_mut() {
            Some(ProviderCharge::Environment(held)) => {
                let attached = held.attach(&account)?;
                *charge = Some(ProviderCharge::Account(attached));
            }
            Some(ProviderCharge::Account(held)) if held.belongs_to(&account) => {}
            _ => return Err(ConnectError::Configuration),
        }
        *security = Security::Account(account);
        Ok(())
    }
    #[cfg(test)]
    pub(super) async fn accept(
        root: Arc<EnvironmentRoot>,
        tcp: std::net::TcpStream,
        policy: super::serve::SocketPolicy,
        deadline: Instant,
        caller: CancellationToken,
        charges: (PreparationCharge, PreparationCharge),
        hooks: AcceptHooks<
            impl FnOnce(Arc<Self>),
            impl FnOnce(super::serve::ServeRequestContext) -> RequestAuthorizationFuture,
        >,
    ) -> ConnectResult<(Arc<Self>, mpsc::Receiver<Vec<u8>>)> {
        Self::accept_observed(root, tcp, policy, deadline, caller, charges, None, hooks).await
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "WSS preparation keeps authenticated route inputs separate from physical socket and resource ownership."
    )]
    pub(super) async fn accept_observed(
        root: Arc<EnvironmentRoot>,
        tcp: std::net::TcpStream,
        policy: super::serve::SocketPolicy,
        deadline: Instant,
        caller: CancellationToken,
        charges: (PreparationCharge, PreparationCharge),
        preparation_tail: Option<direct_carrier::PreparationTail>,
        hooks: AcceptHooks<
            impl FnOnce(Arc<Self>),
            impl FnOnce(super::serve::ServeRequestContext) -> RequestAuthorizationFuture,
        >,
    ) -> ConnectResult<(Arc<Self>, mpsc::Receiver<Vec<u8>>)> {
        let AcceptHooks { retain, authorize } = hooks;
        let (charge, tls_charge) = charges;
        // Declare before the frame's queues so its Drop follows their release
        // on refusal and Future withdrawal.
        let _accepted_preparation;
        let (commands, rx) = mpsc::channel(1);
        let (incoming, input) = mpsc::channel(policy.queue_messages);
        let (prepared, ready) = oneshot::channel();
        let (request_sender, request_receiver) = oneshot::channel();
        let (decision_sender, decision_receiver) = std::sync::mpsc::sync_channel(1);
        let request_cancel = caller.clone();
        let mut id = [0; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id)
            .map_err(|_| ConnectError::Carrier)?;
        let provider = Arc::new(Self {
            preparation_budget: None,
            security: Mutex::new(Security::Environment(root)),
            id,
            cancel: CancellationToken::new(),
            commands,
            pending: AtomicUsize::new(0),
            read_stall: AtomicBool::new(false),
            stall_generation: AtomicU64::new(0),
            receivers: AtomicUsize::new(0),
            done: AtomicBool::new(false),
            accepted_preparation_pending: AtomicBool::new(true),
            preparation_observer_done: AtomicBool::new(false),
            cleanup_changed: tokio::sync::Notify::new(),
            live: AtomicBool::new(false),
            validity: Arc::new(Mutex::new(Some(policy.validity))),
            deadline,
            publication_timeout: policy.publication_timeout,
            maximum: policy.maximum,
            live_maximum: AtomicUsize::new(policy.maximum),
            relay_budget: Mutex::new(policy.relay_budget.clone()),
            relay_unassigned: AtomicBool::new(policy.relay_unassigned),
            relay_assigned: tokio::sync::Notify::new(),
            charge: Mutex::new(Some(charge)),
            thread: Mutex::new(None),
            exporter: Mutex::new(None),
            first_hello: Mutex::new(None),
            connect_diagnostic: OnceLock::new(),
            connect_physical: Mutex::new(None),
            connect_cleanup: preparation_tail
                .as_ref()
                .and_then(|tail| tail.cleanup_owner().map(|cleanup| Arc::downgrade(&cleanup))),
            connect_preparation: Mutex::new(preparation_tail),
        });
        let mut guard = ConnectGuard(Some(provider.clone()));
        _accepted_preparation = AcceptedPreparationGuard(provider.clone());
        retain(provider.clone());
        let worker = provider.clone();
        let thread = std::thread::Builder::new()
            .name("flowersec-v4-wss-accept".into())
            .stack_size(512 * 1024)
            .spawn(move || {
                let _tail = WorkerTail(worker.clone());
                if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    runtime.block_on(async {
                        let established = tokio::select! {
                            _ = worker.cancel.cancelled() => Err(ConnectError::Canceled),
                            _ = tokio::time::sleep_until(deadline) => Err(ConnectError::Deadline),
                            result = worker.accept_socket(tcp, &policy, request_sender, decision_receiver, request_cancel) => result,
                        };
                        drop(tls_charge);
                        match established {
                            Ok(socket) => {
                                if prepared.send(Ok(())).is_ok() {
                                    worker.drive_socket(socket, rx, incoming).await;
                                }
                            }
                            Err(error) => {
                                let _ = prepared.send(Err(error));
                            }
                        }
                    });
                }
            });
        let spawned = thread.is_ok();
        match thread {
            Ok(thread) => *provider.thread.lock().expect("WSS thread") = Some(thread),
            Err(_) => provider.done.store(true, Ordering::Release),
        }
        // Accepted providers must retain their original charge until the
        // worker thread has really joined; the observer is part of that
        // provider-owned cleanup chain.
        Self::spawn_cleanup_observer(provider.clone(), None);
        if !spawned {
            return Err(ConnectError::Capacity);
        }
        let mut ready = ready;
        let result = tokio::select! {
            _ = caller.cancelled() => Err(ConnectError::Canceled),
            _ = tokio::time::sleep_until(deadline) => Err(ConnectError::Deadline),
            result = &mut ready => result.unwrap_or(Err(ConnectError::Carrier)),
            request = request_receiver => {
                let mut native_result = None;
                if let Ok(request) = request
                    && !caller.is_cancelled() && Instant::now() < deadline && provider.check().is_ok()
                {
                    // The callback runs on the original accepted task, outside
                    // the native worker. Cancellation closes the native path
                    // but cannot discard this future or its original charge.
                    let authorizing = authorize(request);
                    tokio::pin!(authorizing);
                    let allowed = tokio::select! {
                        result = &mut authorizing => result.is_ok_and(|r| r.allowed),
                        _ = caller.cancelled() => { provider.close(); let _ = authorizing.await; false },
                        _ = tokio::time::sleep_until(deadline) => { caller.cancel(); provider.close(); let _ = authorizing.await; false },
                        result = &mut ready => {
                            caller.cancel(); provider.close();
                            native_result = Some(result.unwrap_or(Err(ConnectError::Carrier)));
                            let _ = authorizing.await;
                            false
                        },
                    } && !caller.is_cancelled() && Instant::now() < deadline;
                    let _ = decision_sender.send(allowed);
                } else {
                    caller.cancel();
                    provider.close();
                }
                match native_result { Some(result) => result, None => ready.await.unwrap_or(Err(ConnectError::Carrier)) }
            }
        };
        if let Err(error) = result.and_then(|()| provider.check()) {
            provider.close();
            return Err(error);
        }
        guard.0 = None;
        Ok((provider, input))
    }
    #[expect(
        clippy::result_large_err,
        reason = "Tungstenite fixes the HTTP error response type"
    )]
    async fn accept_socket(
        &self,
        tcp: std::net::TcpStream,
        policy: &super::serve::SocketPolicy,
        request_sender: oneshot::Sender<super::serve::ServeRequestContext>,
        decision_receiver: std::sync::mpsc::Receiver<bool>,
        caller: CancellationToken,
    ) -> ConnectResult<tokio_tungstenite::WebSocketStream<tokio_rustls::server::TlsStream<LimitedIo>>>
    {
        self.check()?;
        let local_address = tcp.local_addr().map_err(|_| ConnectError::Carrier)?;
        let remote_address = tcp.peer_addr().map_err(|_| ConnectError::Carrier)?;
        let tcp = TcpStream::from_std(tcp).map_err(|_| ConnectError::Carrier)?;
        tcp.set_nodelay(true).map_err(|_| ConnectError::Carrier)?;
        let meter = Arc::new(Meter {
            remaining: AtomicUsize::new(policy.prepare_bytes),
            enabled: AtomicBool::new(true),
            budget: None,
        });
        let tls = tokio_rustls::TlsAcceptor::from(policy.tls.clone())
            .accept(LimitedIo {
                tcp,
                meter: meter.clone(),
            })
            .await
            .map_err(|_| ConnectError::Tls)?;
        if tls.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
            || tls.get_ref().1.alpn_protocol() != Some(b"http/1.1")
            || (policy.host.parse::<IpAddr>().is_err()
                && tls.get_ref().1.server_name() != Some(policy.host.as_str()))
        {
            return Err(ConnectError::Tls);
        }
        let config = WebSocketConfig::default()
            .read_buffer_size(16384)
            .write_buffer_size(0)
            .max_write_buffer_size(policy.maximum + 1024)
            .max_message_size(Some(policy.maximum))
            .max_frame_size(Some(policy.maximum));
        let mut socket = tokio_tungstenite::accept_hdr_async_with_config(tls, move |request: &tokio_tungstenite::tungstenite::handshake::server::Request, mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
            let headers = request.headers();
            let origin = headers.get("origin").and_then(|v| v.to_str().ok());
            let valid_origin = match origin { None => policy.allow_absent_origin && !headers.contains_key("origin"), Some(origin) => policy.origins.iter().any(|v| v == origin) };
            if request.method() != "GET" || request.version() != http::Version::HTTP_11
                || headers.len() > 32 || headers.iter().map(|(k,v)| k.as_str().len() + v.as_bytes().len()).sum::<usize>() > 16384
                || headers.contains_key("content-length") || headers.contains_key("transfer-encoding")
                || request.uri().path_and_query().map(|v| v.as_str()) != Some(if policy.path_kind == 1 {"/flowersec/v4/tunnel"}else{"/flowersec/v4/direct"})
                || headers.get_all("host").iter().count()!=1 || headers.get("host").and_then(|v|v.to_str().ok()) != Some(policy.authority.as_str())
                || headers.get_all("sec-websocket-protocol").iter().count()!=1 || headers.get("sec-websocket-protocol").and_then(|v|v.to_str().ok()) != Some(if policy.path_kind == 1 {"flowersec.tunnel.v4"}else{"flowersec.direct.v4"})
                || headers.get_all("origin").iter().count()>1 || headers.contains_key("sec-websocket-extensions") || !valid_origin {
                return Err(tokio_tungstenite::tungstenite::http::Response::builder().status(403).body(None).expect("fixed refusal"));
            }
            let context = super::serve::ServeRequestContext {
                method: "GET".into(), target: if policy.path_kind == 1 {"/flowersec/v4/tunnel".into()}else{"/flowersec/v4/direct".into()}, authority: policy.authority.clone(),
                origin: origin.map(str::to_owned), headers: headers.iter().map(|(k,v)| (k.as_str().to_owned(), v.as_bytes().to_vec())).collect(),
                local_address, remote_address, cancellation: caller.clone(),
            };
            let sent = request_sender.send(context).is_ok();
            let allowed = sent && loop {
                if caller.is_cancelled() || self.cancel.is_cancelled() || self.check().is_err() || Instant::now() >= self.deadline { break false; }
                match decision_receiver.recv_timeout(Duration::from_millis(10)) {
                    Ok(allowed) => break allowed,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {},
                    Err(_) => break false,
                }
            };
            if !allowed {
                return Err(tokio_tungstenite::tungstenite::http::Response::builder().status(403).body(None).expect("fixed refusal"));
            }
            response.headers_mut().insert("sec-websocket-protocol", (if policy.path_kind == 1 {"flowersec.tunnel.v4"}else{"flowersec.direct.v4"}).parse().expect("fixed subprotocol"));
            Ok(response)
        }, Some(config)).await.map_err(|_|ConnectError::Carrier)?;
        meter.enabled.store(false, Ordering::Release);
        if policy.binding_mode == BindingMode::DirectExporter {
            // Retain the first original HELLO under the existing preauth
            // position before splitting TLS ownership. It is forwarded once
            // to the same accepted material lookup, never read a second time.
            let Message::Binary(wire) = socket
                .next()
                .await
                .ok_or(ConnectError::Carrier)?
                .map_err(|_| ConnectError::Carrier)?
            else {
                return Err(ConnectError::Protocol);
            };
            let hello = decode(
                payload(&wire, 1, 16384)?,
                "ClientHello",
                16384,
                Context::default(),
            )?;
            let artifact = hello.b::<32>("ClientHello", "artifact_digest")?;
            let tls = socket.get_ref().get_ref().1;
            if tls.handshake_kind() == Some(rustls::HandshakeKind::Resumed) {
                return Err(ConnectError::Tls);
            }
            let value = tls
                .export_keying_material([0u8; 32], b"EXPORTER-flowersec-v4", Some(&artifact))
                .map_err(|_| ConnectError::Tls)?;
            self.install_exporter(artifact, value)?;
            *self.first_hello.lock().expect("original HELLO") = Some(wire.to_vec());
        }
        self.check()?;
        Ok(socket)
    }
    fn install_exporter(&self, artifact: [u8; 32], value: [u8; 32]) -> ConnectResult<()> {
        let value = Zeroizing::new(value);
        self.check()?;
        let mut exporter = self.exporter.lock().expect("original TLS binding");
        if exporter.is_some() || artifact == [0; 32] {
            return Err(ConnectError::Configuration);
        }
        *exporter = Some(BoundExporter { artifact, value });
        Ok(())
    }
    pub(super) fn binding(
        &self,
        mode: BindingMode,
        artifact: [u8; 32],
    ) -> ConnectResult<Option<Zeroizing<[u8; 32]>>> {
        self.check()?;
        if mode == BindingMode::AuthenticatedContext {
            return Ok(None);
        }
        let bound = self.exporter.lock().expect("original TLS binding");
        let bound = bound.as_ref().ok_or(ConnectError::Tls)?;
        if bound.artifact != artifact {
            return Err(ConnectError::Authorization);
        }
        Ok(Some(Zeroizing::new(*bound.value)))
    }
    pub(super) fn receiver(self: &Arc<Self>) -> ConnectResult<ReceiverGuard> {
        let charge = self.charge.lock().expect("WSS receiver owner");
        if charge.is_none() || self.cancel.is_cancelled() {
            return Err(ConnectError::Carrier);
        }
        self.receivers.fetch_add(1, Ordering::AcqRel);
        Ok(ReceiverGuard(self.clone()))
    }
    pub(super) fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }
    pub(super) fn identity(&self) -> [u8; 16] {
        self.id
    }
    pub(super) fn complete_preparation(&self) -> ConnectResult<()> {
        self.check()?;
        if let Some(budget) = &self.preparation_budget {
            budget.complete().map_err(native::budget_error)?;
        }
        Ok(())
    }
    pub(super) fn check(&self) -> ConnectResult<()> {
        if let Some(budget) = &self.preparation_budget {
            budget.check().map_err(native::budget_error)?;
        }
        if self.cancel.is_cancelled() || self.done.load(Ordering::Acquire) {
            return Err(ConnectError::Carrier);
        }
        if !self.live.load(Ordering::Acquire) && Instant::now() >= self.deadline {
            return Err(ConnectError::Deadline);
        }
        let security = self.security.lock().expect("WSS security owner").clone();
        let now = match &security {
            Security::Account(account) => account.security_time()?,
            Security::Environment(root) => {
                if root.is_closed() {
                    return Err(ConnectError::Canceled);
                }
                root.sample()?
            }
        };
        if let Some((start, end)) = *self.validity.lock().expect("TLS validity")
            && (now.lower_ms < start || now.upper_ms >= end)
        {
            return Err(ConnectError::Tls);
        }
        Ok(())
    }
    fn relay_budget(&self) -> Option<Arc<RelayBudget>> {
        self.relay_budget.lock().expect("relay meter owner").clone()
    }
    pub(super) async fn assign_relay(
        &self,
        account: ResourceAccount,
        budget: Arc<RelayBudget>,
        first_bytes: usize,
        prepaid: ResourceCharge,
    ) -> ConnectResult<()> {
        if !self.relay_unassigned.load(Ordering::Acquire) || self.live.load(Ordering::Acquire) {
            return Err(ConnectError::Configuration);
        }
        // Charge the actual first read before any HOP claim or proof. The reader
        // is suspended, so no later queued read can escape the original meter.
        budget.reserve(first_bytes, &self.cancel).await?;
        {
            let mut security = self
                .security
                .lock()
                .expect("original ingress security owner");
            let Security::Environment(root) = &*security else {
                return Err(ConnectError::Configuration);
            };
            if !account.belongs_to(root) {
                return Err(ConnectError::Configuration);
            }
            let mut charge = self
                .charge
                .lock()
                .expect("original ingress prepaid backing");
            let Some(ProviderCharge::Environment(held)) = charge.as_mut() else {
                return Err(ConnectError::Configuration);
            };
            let attached = held.attach_prepaid(&account, prepaid)?;
            *charge = Some(ProviderCharge::Account(attached));
            *security = Security::Account(account);
        }
        let mut installed = self
            .relay_budget
            .lock()
            .expect("original relay meter installation");
        if installed.is_some() {
            return Err(ConnectError::Configuration);
        }
        *installed = Some(budget);
        drop(installed);
        self.relay_unassigned.store(false, Ordering::Release);
        self.relay_assigned.notify_waiters();
        self.check()
    }
    pub(super) fn assign_endpoint(
        &self,
        account: ResourceAccount,
        prepaid: ResourceCharge,
    ) -> ConnectResult<()> {
        if !self.relay_unassigned.load(Ordering::Acquire)
            || self.live.load(Ordering::Acquire)
            || self.relay_budget().is_some()
        {
            return Err(ConnectError::Configuration);
        }
        {
            let mut security = self
                .security
                .lock()
                .expect("original endpoint ingress security");
            let Security::Environment(root) = &*security else {
                return Err(ConnectError::Configuration);
            };
            if !account.belongs_to(root) {
                return Err(ConnectError::Configuration);
            }
            let mut charge = self
                .charge
                .lock()
                .expect("original endpoint ingress backing");
            let Some(ProviderCharge::Environment(held)) = charge.as_mut() else {
                return Err(ConnectError::Configuration);
            };
            let attached = held.attach_prepaid(&account, prepaid)?;
            *charge = Some(ProviderCharge::Account(attached));
            *security = Security::Account(account);
        }
        self.relay_unassigned.store(false, Ordering::Release);
        self.relay_assigned.notify_waiters();
        self.check()
    }
    pub(super) fn bind_frame_limit(&self, maximum: usize) -> ConnectResult<()> {
        if self.live.load(Ordering::Acquire) || maximum < 8 || maximum > self.maximum {
            return Err(ConnectError::Configuration);
        }
        self.live_maximum.store(maximum, Ordering::Release);
        Ok(())
    }
    pub(super) fn activate(&self) {
        self.exporter.lock().expect("original TLS binding").take();
        self.live.store(true, Ordering::Release);
    }
    fn submit(&self, wire: Vec<u8>) -> ConnectResult<oneshot::Receiver<ConnectResult<()>>> {
        self.check()?;
        let maximum = if self.live.load(Ordering::Acquire) {
            self.live_maximum.load(Ordering::Acquire)
        } else {
            self.maximum
        };
        if wire.len() > maximum
            || self
                .pending
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(ConnectError::Capacity);
        }
        let (reply, wait) = oneshot::channel();
        if self.commands.try_send(SendCommand { wire, reply }).is_err() {
            self.pending.store(0, Ordering::Release);
            return Err(ConnectError::Carrier);
        }
        Ok(wait)
    }
    pub(super) async fn send(&self, wire: Vec<u8>) -> ConnectResult<()> {
        let wait = self.submit(wire)?;
        wait.await.map_err(|_| ConnectError::Carrier)??;
        self.check()
    }
    pub(crate) fn close(&self) {
        if let Some(cleanup) = &self.connect_cleanup
            && let Some(cleanup) = cleanup.upgrade()
        {
            cleanup.start();
        }
        self.cancel.cancel();
    }
    pub(super) fn cleanup(&self) -> CleanupStatus {
        let mut status = self.cleanup_physical();
        let observer_done = self.preparation_observer_done.load(Ordering::Acquire);
        status.complete &= observer_done;
        status.pending_callbacks += u64::from(!observer_done);
        if status.complete {
            // Release mutex guards before dropping physical tails. A tail can
            // own the cleanup controller, whose Session drop may re-enter
            // provider.close()/cleanup().
            let diagnostic_tail = self
                .connect_physical
                .lock()
                .expect("Connect diagnostic physical owner")
                .take();
            let preparation_tail = self
                .connect_preparation
                .lock()
                .expect("Connect preparation physical owner")
                .take();
            drop(diagnostic_tail);
            drop(preparation_tail);
        }
        status
    }
    fn cleanup_physical(&self) -> CleanupStatus {
        let mut thread = self.thread.lock().expect("WSS thread");
        let complete = self.done.load(Ordering::Acquire)
            && !self.accepted_preparation_pending.load(Ordering::Acquire)
            && self.receivers.load(Ordering::Acquire) == 0
            && thread
                .as_ref()
                .is_none_or(std::thread::JoinHandle::is_finished);
        if complete && let Some(thread) = thread.take() {
            let _ = thread.join();
        }
        CleanupStatus {
            complete,
            cleanup_incomplete: false,
            pending_callbacks: (self.pending.load(Ordering::Acquire)
                + self.receivers.load(Ordering::Acquire)) as u64
                + u64::from(self.accepted_preparation_pending.load(Ordering::Acquire)),
        }
    }
    #[cfg(test)]
    pub(super) fn retain_connect_preparation(&self, preparation: direct_carrier::PreparationTail) {
        *self
            .connect_preparation
            .lock()
            .expect("Connect preparation physical owner") = Some(preparation);
        self.cleanup();
    }
    pub(super) fn retain_connect_diagnostic(
        self: &Arc<Self>,
        diagnostic: Arc<crate::diagnostics_v4::DiagnosticActivity>,
    ) {
        let _ = self.connect_diagnostic.set(diagnostic.clone());
        let mut physical = self
            .connect_physical
            .lock()
            .expect("Connect diagnostic physical owner");
        if physical.is_none() {
            *physical = Some(diagnostic.retain_physical());
        }
        drop(physical);
        self.cleanup();
    }
    async fn establish(
        &self,
        policy: &Policy,
        options: &WssConnectOptions,
    ) -> ConnectResult<tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<LimitedIo>>>
    {
        self.check()?;
        let account = self.account()?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let ca = if policy.pins.is_none() {
            let mut roots = rustls::RootCertStore::empty();
            for der in &policy.ca {
                roots
                    .add(CertificateDer::from(der.clone()))
                    .map_err(|_| ConnectError::Configuration)?;
            }
            Some(
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                    .build()
                    .map_err(|_| ConnectError::Configuration)?,
            )
        } else {
            None
        };
        let verifier = Arc::new(Verifier {
            account: account.clone(),
            ca,
            pins: policy.pins.clone(),
            supported: provider.signature_verification_algorithms,
            validity: self.validity.clone(),
        });
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| ConnectError::Configuration)?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        config.time_provider = Arc::new(Clock(account));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.resumption = Resumption::disabled();
        config.enable_early_data = false;
        let remote = SocketAddr::new(options.remote_address, policy.port);
        if let Some(budget) = &policy.preparation_budget {
            budget.debit_address().map_err(native::budget_error)?;
        }
        let tcp = TcpStream::connect(remote)
            .await
            .map_err(|_| ConnectError::Carrier)?;
        if tcp.peer_addr().map_err(|_| ConnectError::Carrier)? != remote {
            return Err(ConnectError::Carrier);
        }
        tcp.set_nodelay(true).map_err(|_| ConnectError::Carrier)?;
        let meter = Arc::new(Meter {
            remaining: AtomicUsize::new(options.prepare_bytes),
            enabled: AtomicBool::new(true),
            budget: policy.preparation_budget.clone(),
        });
        let io = LimitedIo {
            tcp,
            meter: meter.clone(),
        };
        let name =
            ServerName::try_from(policy.host.clone()).map_err(|_| ConnectError::Configuration)?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, io)
            .await
            .map_err(|_| ConnectError::Tls)?;
        if tls.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
            || tls.get_ref().1.alpn_protocol() != Some(b"http/1.1")
        {
            return Err(ConnectError::Tls);
        }
        self.check()?;
        let host = if policy.host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]", policy.host)
        } else {
            policy.host.clone()
        };
        let mut request = format!("wss://{}:{}{}", host, policy.port, policy.path)
            .into_client_request()
            .map_err(|_| ConnectError::Configuration)?;
        request.headers_mut().insert(
            "sec-websocket-protocol",
            policy
                .subprotocol
                .parse()
                .map_err(|_| ConnectError::Configuration)?,
        );
        if let Some(origin) = &policy.origin {
            request.headers_mut().insert(
                "origin",
                origin.parse().map_err(|_| ConnectError::Configuration)?,
            );
        }
        let config = WebSocketConfig::default()
            .read_buffer_size(16384)
            .write_buffer_size(0)
            .max_write_buffer_size(policy.maximum + 1024)
            .max_message_size(Some(policy.maximum))
            .max_frame_size(Some(policy.maximum));
        let (websocket, response) = client_async_with_config(request, tls, Some(config))
            .await
            .map_err(|_| ConnectError::Carrier)?;
        if response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok())
            != Some(policy.subprotocol.as_str())
            || response.headers().contains_key("sec-websocket-extensions")
        {
            return Err(ConnectError::Carrier);
        }
        meter.enabled.store(false, Ordering::Release);
        if policy.binding_mode == BindingMode::DirectExporter {
            let tls = websocket.get_ref().get_ref().1;
            if tls.handshake_kind() == Some(rustls::HandshakeKind::Resumed) {
                return Err(ConnectError::Tls);
            }
            // rustls consumes the complete label without adding a prefix.
            let value = tls
                .export_keying_material([0u8; 32], b"EXPORTER-flowersec-v4", Some(&policy.artifact))
                .map_err(|_| ConnectError::Tls)?;
            self.install_exporter(policy.artifact, value)?;
        }
        self.check()?;
        Ok(websocket)
    }
    async fn drive(
        &self,
        policy: Policy,
        options: WssConnectOptions,
        commands: mpsc::Receiver<SendCommand>,
        incoming: mpsc::Sender<Vec<u8>>,
        prepared: oneshot::Sender<ConnectResult<()>>,
        tls_charge: ResourceCharge,
    ) {
        let websocket = {
            let establishing = self.establish(&policy, &options);
            tokio::pin!(establishing);
            loop {
                tokio::select! {_ = self.cancel.cancelled()=>{let _=prepared.send(Err(ConnectError::Canceled));return;},_ = tokio::time::sleep(Duration::from_millis(10))=>{if let Err(e)=self.check(){let _=prepared.send(Err(e));return;}},result=&mut establishing=>match result{Ok(w)=>break w,Err(e)=>{let _=prepared.send(Err(e));return;}}}
            }
        };
        // The exact preparation future exited; this handshake position can
        // return independently of the still-owned socket/runtime tail.
        drop(tls_charge);
        if prepared.send(Ok(())).is_err() {
            return;
        }
        self.drive_socket(websocket, commands, incoming).await;
    }
    async fn drive_socket<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        websocket: tokio_tungstenite::WebSocketStream<S>,
        mut commands: mpsc::Receiver<SendCommand>,
        incoming: mpsc::Sender<Vec<u8>>,
    ) {
        let first = self.first_hello.lock().expect("original HELLO").take();
        if let Some(wire) = first
            && incoming.try_send(wire).is_err()
        {
            return;
        }
        let (mut sink, mut stream) = websocket.split();
        let writing = async {
            while let Some(command) = commands.recv().await {
                let result = match self.check() {
                    Err(e) => Err(e),
                    Ok(()) => match tokio::time::timeout(self.publication_timeout, async {
                        if let Some(budget) = self.relay_budget() {
                            budget.reserve(command.wire.len(), &self.cancel).await?;
                        }
                        self.check()?;
                        sink.send(Message::Binary(command.wire.into()))
                            .await
                            .map_err(|_| ConnectError::Carrier)
                    })
                    .await
                    {
                        Ok(Ok(())) => self.check(),
                        Ok(Err(failure)) => Err(failure),
                        Err(_) => Err(ConnectError::Deadline),
                    },
                };
                self.pending.store(0, Ordering::Release);
                let failed = result.is_err();
                let _ = command.reply.send(result);
                if failed {
                    break;
                }
            }
        };
        let reading = async {
            while let Some(message) = stream.next().await {
                match message {
                    Ok(Message::Binary(bytes)) => {
                        let maximum = if self.live.load(Ordering::Acquire) {
                            self.live_maximum.load(Ordering::Acquire)
                        } else {
                            self.maximum
                        };
                        if bytes.len() > maximum || self.check().is_err() {
                            break;
                        }
                        let unassigned = self.relay_unassigned.load(Ordering::Acquire);
                        if unassigned && bytes.len() > 10354 {
                            break;
                        }
                        if let Some(budget) = self.relay_budget()
                            && (budget.reserve(bytes.len(), &self.cancel).await.is_err()
                                || self.check().is_err())
                        {
                            break;
                        }
                        match incoming.try_send(bytes.to_vec()) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                            Err(mpsc::error::TrySendError::Full(bytes)) => {
                                // Sticky generation survives a stall that ends
                                // before the original Session can reacquire its gate.
                                self.read_stall.store(true, Ordering::Release);
                                if self
                                    .stall_generation
                                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                                        n.checked_add(1)
                                    })
                                    .is_err()
                                {
                                    break;
                                }
                                let result = incoming.send(bytes).await;
                                self.read_stall.store(false, Ordering::Release);
                                if result.is_err() {
                                    break;
                                }
                            }
                        }
                        if unassigned {
                            loop {
                                let changed = self.relay_assigned.notified();
                                tokio::pin!(changed);
                                changed.as_mut().enable();
                                if !self.relay_unassigned.load(Ordering::Acquire) {
                                    break;
                                }
                                tokio::select! { _ = self.cancel.cancelled() => return, _ = changed => {} }
                            }
                        }
                    }
                    _ => break,
                }
            }
        };
        tokio::select! {_ = self.cancel.cancelled()=>{},_ = writing=>{},_ = reading=>{},_ = async{loop{tokio::time::sleep(Duration::from_millis(10)).await;if self.check().is_err(){break;}}}=>{}}
    }
}
struct WorkerTail(Arc<Provider>);
impl Drop for WorkerTail {
    fn drop(&mut self) {
        self.0.close();
        self.0.exporter.lock().expect("original TLS binding").take();
        if let Some(mut wire) = self.0.first_hello.lock().expect("original HELLO").take() {
            wire.zeroize();
        }
        self.0.pending.store(0, Ordering::Release);
        self.0.done.store(true, Ordering::Release);
        self.0.cleanup_changed.notify_waiters();
    }
}
pub(super) struct ReceiverGuard(Arc<Provider>);
impl Drop for ReceiverGuard {
    fn drop(&mut self) {
        self.0.receivers.fetch_sub(1, Ordering::AcqRel);
        self.0.cleanup_changed.notify_waiters();
    }
}
pub(super) struct Transport {
    provider: Arc<Provider>,
    data_slot: Arc<AtomicU64>,
    _keys: IdentityKeys,
    _namespaces: Vec<Arc<Namespace>>,
}
impl Transport {
    pub(super) fn new(
        provider: Arc<Provider>,
        keys: IdentityKeys,
        namespaces: Vec<Arc<Namespace>>,
    ) -> Self {
        Self {
            provider,
            data_slot: Arc::new(AtomicU64::new(0)),
            _keys: keys,
            _namespaces: namespaces,
        }
    }
}
impl RecordPublisher for Transport {
    fn try_claim_data(
        &mut self,
        scope: u64,
        maximum_record_bytes: usize,
    ) -> Result<super::DataPublicationClaim> {
        self.provider.check().map_err(|_| CryptoError::State)?;
        if scope == 0
            || !self.provider.live.load(Ordering::Acquire)
            || maximum_record_bytes > self.provider.live_maximum.load(Ordering::Acquire)
            || self.provider.pending.load(Ordering::Acquire) != 0
        {
            return Err(CryptoError::Capacity);
        }
        self.data_slot
            .compare_exchange(0, scope, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| CryptoError::Capacity)?;
        let slot = self.data_slot.clone();
        Ok(super::DataPublicationClaim::new(move || {
            slot.store(0, Ordering::Release);
        }))
    }
    fn data_publication_permitted(&self, scope: u64) -> bool {
        let claimed = self.data_slot.load(Ordering::Acquire);
        claimed == 0 || claimed == scope
    }
    fn liveness_stall_generation(&self) -> u64 {
        self.provider.stall_generation.load(Ordering::Acquire)
    }
    fn liveness_stalled(&self) -> bool {
        self.provider.read_stall.load(Ordering::Acquire)
    }
    fn publish(&mut self, wire: &[u8]) -> Result<()> {
        let wait = self
            .provider
            .submit(wire.to_vec())
            .map_err(|_| CryptoError::State)?;
        let receive = || {
            wait.blocking_recv()
                .map_err(|_| CryptoError::State)?
                .map_err(|_| CryptoError::State)
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(receive)
            }
            Ok(_) => {
                self.provider.close();
                Err(CryptoError::Configuration)
            }
            Err(_) => receive(),
        }
    }
}
impl SessionTransport for Transport {
    fn close_signal(&self) -> Option<Arc<dyn Fn() + Send + Sync>> {
        let provider = self.provider.clone();
        Some(Arc::new(move || provider.close()))
    }
    fn cleanup_signal(&self) -> Option<Arc<dyn Fn() -> CleanupStatus + Send + Sync>> {
        let provider = self.provider.clone();
        Some(Arc::new(move || provider.cleanup()))
    }
    fn close(&mut self) {
        self.provider.close();
    }
    fn cleanup_status(&self) -> CleanupStatus {
        self.provider.cleanup()
    }
    fn stream_cleanup_status(&self, _: u64) -> CleanupStatus {
        CleanupStatus {
            complete: self.provider.pending.load(Ordering::Acquire) == 0,
            cleanup_incomplete: false,
            pending_callbacks: self.provider.pending.load(Ordering::Acquire) as u64,
        }
    }
}
impl Drop for Transport {
    fn drop(&mut self) {
        self.provider.close();
    }
}

#[cfg(test)]
#[path = "wss_v4_cleanup_tests.rs"]
pub(super) mod cleanup_tests;
