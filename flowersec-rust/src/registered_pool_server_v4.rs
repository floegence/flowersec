//! Original registered pool B acquisition. Installation acknowledgements never
//! authorize carrier preparation; that remains gated by the same Serve's Allow.
use super::*;
use crate::control_https_v4::{ControlHTTPS, ControlHTTPSCustody};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug)]
pub struct RegisteredPoolServerConfiguration {
    pub control: crate::ControlHTTPSConfiguration,
    pub authority: String,
    pub connection: PoolCredentialBytes,
    pub relay_certificate: Vec<u8>,
    pub relay_service: String,
    pub relay_audience: String,
}
/// An original, verified role-1 material owner. It cannot be serialized,
/// cloned, recovered from a ledger, or installed into more than one Serve.
#[derive(Debug)]
pub struct RegisteredPoolTunnelServerMaterial {
    pub(crate) material: PoolConnectionMaterial,
    pub(crate) relay_service: String,
    pub(crate) relay_audience: String,
    grants: [[u8; 32]; 2],
}
impl RegisteredPoolTunnelServerMaterial {
    /// Public comparison facts only; these digests cannot authorize a hop.
    pub fn grant_bytes_digests(&self) -> [[u8; 32]; 2] {
        self.grants
    }
    pub async fn serve(
        self,
        admission: Arc<crate::SQLiteAdmissionAuthority>,
        options: serve::TunnelServeOptions,
    ) -> ConnectResult<serve::TunnelServeHandle> {
        serve::serve_registered_pool(self, admission, options).await
    }
    pub async fn serve_reverse(
        self,
        admission: Arc<crate::SQLiteAdmissionAuthority>,
        options: serve::ReverseTunnelServeOptions,
    ) -> ConnectResult<serve::TunnelServeHandle> {
        serve::serve_reverse_registered_pool(self, admission, options).await
    }
}
pub(crate) struct RegisteredPoolControl {
    root: Arc<EnvironmentRoot>,
    account: ResourceAccount,
    transport: ControlHTTPS,
    keys: IdentityKeys,
    authority: String,
    incarnation: Zeroizing<[u8; 32]>,
    parent: [u8; 32],
    candidate: u8,
    continuation: Zeroizing<Vec<u8>>,
    grant: [u8; 32],
    lease: Vec<u8>,
    projection: Vec<u8>,
    cutoff: u64,
    deadline: Instant,
    phase: AtomicU8,
    cancellation: CancellationToken,
    physical: Arc<AtomicUsize>,
    _charge: ResourceCharge,
}
impl fmt::Debug for RegisteredPoolControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegisteredPoolControl { <opaque> }")
    }
}
#[derive(Serialize)]
struct Payload<'a> {
    kind: &'a str,
    incarnation: String,
    parent: String,
    candidate: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    continuation: Option<String>,
}
impl Drop for Payload<'_> {
    fn drop(&mut self) {
        self.incarnation.zeroize();
        if let Some(value) = &mut self.continuation {
            value.zeroize();
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    incarnation: String,
    authority: String,
    #[serde(default, rename = "clientGrant")]
    client: String,
    #[serde(default, rename = "serverGrant")]
    server: String,
    #[serde(default)]
    continuation: String,
    #[serde(default)]
    lease: String,
    #[serde(default)]
    projection: String,
    #[serde(default)]
    prepared: bool,
    #[serde(default)]
    matched: bool,
}
impl Drop for Reply {
    fn drop(&mut self) {
        self.incarnation.zeroize();
        self.continuation.zeroize();
    }
}
fn bytes(value: &str, maximum: usize, exact: Option<usize>) -> ConnectResult<Vec<u8>> {
    if value.is_empty() || value.len() > maximum.div_ceil(3) * 4 {
        return Err(ConnectError::Protocol);
    }
    let mut decoded = Zeroizing::new(STANDARD.decode(value).map_err(|_| ConnectError::Protocol)?);
    if decoded.is_empty()
        || decoded.len() > maximum
        || exact.is_some_and(|n| decoded.len() != n)
        || STANDARD.encode(decoded.as_slice()) != value
    {
        return Err(ConnectError::Protocol);
    }
    Ok(std::mem::take(&mut *decoded))
}
fn signed_request(keys: &IdentityKeys, payload: &Payload<'_>) -> ConnectResult<Zeroizing<Vec<u8>>> {
    let content =
        Zeroizing::new(serde_json::to_vec(payload).map_err(|_| ConnectError::Configuration)?);
    let mut signed = Zeroizing::new(Vec::with_capacity(content.len() + 40));
    signed.extend_from_slice(b"flowersec/original-tunnel-control/1\0");
    signed.extend_from_slice(&content);
    let proof = Zeroizing::new(keys.inner.sign(&signed)?);
    #[derive(Serialize)]
    struct Envelope<'a> {
        payload: &'a str,
        proof: String,
    }
    Ok(Zeroizing::new(
        serde_json::to_vec(&Envelope {
            payload: std::str::from_utf8(&content).map_err(|_| ConnectError::Configuration)?,
            proof: STANDARD.encode(proof.as_slice()),
        })
        .map_err(|_| ConnectError::Configuration)?,
    ))
}
fn reply(wire: &[u8], authority: &str, incarnation: &[u8]) -> ConnectResult<Reply> {
    let reply: Reply = serde_json::from_slice(wire).map_err(|_| ConnectError::Protocol)?;
    if reply.authority != authority || reply.incarnation != STANDARD.encode(incarnation) {
        return Err(ConnectError::Authorization);
    }
    Ok(reply)
}
// This is the shared control projection, not Rust's durable ledger encoding.
// Derive every byte from locally verified facts before using the continuation.
fn selection(material: &PoolConnectionMaterial) -> ConnectResult<(Vec<u8>, Vec<u8>)> {
    let a = &material.admission;
    let facts = a.pool.as_ref().ok_or(ConnectError::Configuration)?;
    let parent = decode(
        &material.bytes.artifact,
        "Artifact",
        65536,
        Context::default(),
    )?;
    let proof = decode(
        &material.bytes.activation,
        "ActivationAuthorization",
        4096,
        Context::with_activation_source(codec::ActivationSource::PreauthorizedPool),
    )?;
    let set = proof
        .field("ActivationAuthorization", "candidate_selection")?
        .b::<32>("PoolSelectionRef", "candidate_set_digest")?;
    let mut lease = Vec::with_capacity(161);
    lease.push(facts.tenant.len() as u8);
    lease.extend_from_slice(facts.tenant.as_bytes());
    lease.extend_from_slice(&facts.issuer);
    lease.extend_from_slice(&facts.lease);
    let mut projection = Vec::with_capacity(1024);
    codec::encode_head(&mut projection, 4, 18);
    for text in [
        "flowersec/parent-winner/1",
        "preauthorized_pool",
        &facts.tenant,
        &facts.winner_authority,
        parent.field("Artifact", "audience")?.text()?,
    ] {
        codec::encode_head(&mut projection, 3, text.len() as u64);
        projection.extend_from_slice(text.as_bytes());
    }
    for value in [
        facts.issuer.as_slice(),
        facts.lease.as_slice(),
        a.artifact_digest.as_slice(),
        a.activation_digest.as_slice(),
        set.as_slice(),
        a.candidate_id.as_slice(),
        a.route_digest.as_slice(),
        a.attempt_id.as_slice(),
        a.certificate_digests[0].as_slice(),
        a.certificate_digests[1].as_slice(),
    ] {
        codec::encode_head(&mut projection, 2, value.len() as u64);
        projection.extend_from_slice(value);
    }
    for value in [
        facts.issued_at,
        proof.u("ActivationAuthorization", "activation_not_after_ms")?,
        facts.session_end,
    ] {
        codec::encode_head(&mut projection, 0, value);
    }
    Ok((lease, projection))
}
impl RegisteredPoolControl {
    fn check(&self, cancel: &CancellationToken) -> ConnectResult<()> {
        if self.cancellation.is_cancelled() || cancel.is_cancelled() || self.root.is_closed() {
            return Err(ConnectError::Canceled);
        }
        self.account.check()?;
        if Instant::now() >= self.deadline || self.root.sample()?.upper_ms >= self.cutoff {
            return Err(ConnectError::Deadline);
        }
        Ok(())
    }
    pub(crate) fn physical_pending(&self) -> u64 {
        self.physical.load(Ordering::Acquire) as u64
    }
    async fn call(
        &self,
        kind: &str,
        cancel: &CancellationToken,
        deadline: Instant,
        owner: &(dyn Fn() -> ConnectResult<()> + Sync),
    ) -> ConnectResult<Reply> {
        let deadline = self.deadline.min(deadline);
        let check = || {
            self.check(cancel)?;
            owner()?;
            if Instant::now() >= deadline {
                return Err(ConnectError::Deadline);
            }
            Ok(())
        };
        check()?;
        let charge = self.account.reserve(ResourceLimits {
            sdk_bytes: 16384,
            items: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        self.physical.fetch_add(1, Ordering::AcqRel);
        let physical = self.physical.clone();
        let custody = ControlHTTPSCustody::with_cleanup(charge, move || {
            physical.fetch_sub(1, Ordering::AcqRel);
        });
        let body = signed_request(
            &self.keys,
            &Payload {
                kind,
                incarnation: STANDARD.encode(self.incarnation.as_slice()),
                parent: STANDARD.encode(self.parent),
                candidate: self.candidate,
                grant: (kind == "prepared_ack").then(|| STANDARD.encode(self.grant)),
                continuation: Some(STANDARD.encode(self.continuation.as_slice())),
            },
        )?;
        let guard = || check().map_err(|_| crate::ControlHTTPSFailure::Rejected);
        let wire = tokio::select! {
            result = self.transport.post_registered_pool(&body, 1024, cancel, &guard, custody) => result.map_err(server_allow_control_error)?,
            _ = self.cancellation.cancelled() => return Err(ConnectError::Canceled),
            _ = tokio::time::sleep_until(deadline) => return Err(ConnectError::Deadline),
        };
        check()?;
        let reply = reply(&wire, &self.authority, self.incarnation.as_slice())?;
        if !reply.client.is_empty()
            || !reply.server.is_empty()
            || !reply.continuation.is_empty()
            || !reply.lease.is_empty()
            || !reply.projection.is_empty()
        {
            return Err(ConnectError::Protocol);
        }
        Ok(reply)
    }
    pub(crate) async fn installed(&self, cancel: &CancellationToken) -> ConnectResult<()> {
        self.phase
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ConnectError::Authorization)?;
        let reply = self
            .call("prepared_ack", cancel, self.deadline, &|| Ok(()))
            .await?;
        if !reply.prepared || reply.matched {
            return Err(ConnectError::Protocol);
        }
        self.phase.store(2, Ordering::Release);
        Ok(())
    }
    pub(crate) async fn continue_winner(
        &self,
        material: &PoolConnectionMaterial,
        cancel: &CancellationToken,
        deadline: Instant,
        owner: &(dyn Fn() -> ConnectResult<()> + Sync),
    ) -> ConnectResult<()> {
        self.check(cancel)?;
        let (lease, projection) = selection(material)?;
        if lease != self.lease || projection != self.projection {
            return Err(ConnectError::Authorization);
        }
        // Claim the original invocation before IO. Failure, unknown result or
        // cancellation leaves the position terminal and can never cause retry.
        self.phase
            .compare_exchange(2, 3, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ConnectError::Authorization)?;
        let reply = self
            .call("winner_continue", cancel, deadline, owner)
            .await?;
        if !reply.matched || reply.prepared {
            return Err(ConnectError::Protocol);
        }
        self.phase.store(4, Ordering::Release);
        Ok(())
    }
}
impl TransportEnvironment {
    pub async fn register_pool_tunnel_server(
        &self,
        namespaces: Vec<Arc<Namespace>>,
        keys: IdentityKeys,
        configuration: RegisteredPoolServerConfiguration,
        cancellation: CancellationToken,
    ) -> ConnectResult<RegisteredPoolTunnelServerMaterial> {
        let root = self.root().clone();
        if !keys.belongs_to(&root)
            || cancellation.is_cancelled()
            || configuration.control.base_path != "/flowersec/control/tunnel"
            || configuration.authority.is_empty()
            || configuration.authority.len() > 128
        {
            return Err(ConnectError::Configuration);
        }
        let storage = root.reserve_environment(ResourceLimits {
            sdk_bytes: 524288,
            items: 8,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let custody = ControlHTTPSCustody::new_environment(storage);
        let artifact = decode(
            &configuration.connection.artifact,
            "Artifact",
            65536,
            Context::default(),
        )?;
        let parent = codec::digest("artifact_digest", artifact)?;
        let cutoff = artifact.u("Artifact", "initiation_not_after_ms")?;
        let candidate = first_pool_candidate(
            &configuration.connection.activation,
            codec::ActivationSource::PreauthorizedPool,
        )?;
        let remaining = cutoff
            .checked_sub(root.sample()?.upper_ms)
            .filter(|n| *n > 0)
            .ok_or(ConnectError::Deadline)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(remaining))
            .ok_or(ConnectError::Configuration)?;
        let mut incarnation = Zeroizing::new([0; 32]);
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut *incarnation)
            .map_err(|_| ConnectError::Configuration)?;
        if *incarnation == [0; 32] {
            return Err(ConnectError::Configuration);
        }
        let transport = ControlHTTPS::new(root.clone(), configuration.control)
            .map_err(server_allow_control_error)?;
        let body = signed_request(
            &keys,
            &Payload {
                kind: "prepare",
                incarnation: STANDARD.encode(incarnation.as_slice()),
                parent: STANDARD.encode(parent),
                candidate,
                grant: None,
                continuation: None,
            },
        )?;
        let guard = || {
            if root.is_closed() || cancellation.is_cancelled() {
                return Err(crate::ControlHTTPSFailure::Canceled);
            }
            if Instant::now() >= deadline
                || root
                    .sample()
                    .map_err(|_| crate::ControlHTTPSFailure::Rejected)?
                    .upper_ms
                    >= cutoff
            {
                return Err(crate::ControlHTTPSFailure::Deadline);
            }
            Ok(())
        };
        let wire = tokio::select! {
            result = transport.post_registered_pool(&body, 40960, &cancellation, &guard, custody.clone()) => result.map_err(server_allow_control_error)?,
            _ = tokio::time::sleep_until(deadline) => return Err(ConnectError::Deadline),
        };
        guard().map_err(server_allow_control_error)?;
        let response = reply(&wire, &configuration.authority, incarnation.as_slice())?;
        if response.prepared || response.matched {
            return Err(ConnectError::Protocol);
        }
        let client = bytes(&response.client, 9302, None)?;
        let server = bytes(&response.server, 9302, None)?;
        let wire_digests = [
            Sha256::digest(&client).into(),
            Sha256::digest(&server).into(),
        ];
        let continuation = Zeroizing::new(bytes(&response.continuation, 32, Some(32))?);
        if continuation.iter().all(|b| *b == 0) {
            return Err(ConnectError::Protocol);
        }
        let lease = bytes(&response.lease, 161, None)?;
        let projection = bytes(&response.projection, 8192, None)?;
        let mut material = PoolConnectionMaterial::new_tunnel(
            root.clone(),
            namespaces,
            keys.clone(),
            TunnelPoolCredentialBytes {
                connection: configuration.connection,
                grant: server,
                relay_certificate: configuration.relay_certificate,
            },
            &configuration.relay_service,
            &configuration.relay_audience,
            Role::Server,
        )?;
        let grants = {
            let guards: Vec<_> = material
                .namespaces
                .iter()
                .map(|n| n.verifier.lock().expect("original pool namespace"))
                .collect();
            let verifiers: Vec<_> = guards.iter().map(|g| &**g).collect();
            let hop = material
                .tunnel_credentials
                .as_ref()
                .ok_or(ConnectError::Configuration)?;
            let verified = crate::namespace_v4::verifier::credential::verify_pool_hop(
                &root,
                &verifiers,
                &material.admission,
                DirectCredentialInput {
                    artifact: &material.bytes.artifact,
                    client_certificate: &material.bytes.client_certificate,
                    server_certificate: &material.bytes.server_certificate,
                    activation: &material.bytes.activation,
                    source: codec::ActivationSource::PreauthorizedPool,
                    candidate_index: candidate,
                },
                crate::namespace_v4::verifier::credential::tunnel::TunnelHopInput {
                    grant: &client,
                    relay_certificate: &hop.relay_certificate,
                    endpoint_role: 0,
                    service: &configuration.relay_service,
                    audience: &configuration.relay_audience,
                },
            )?;
            [
                verified.facts.grant_digest,
                material.admission.tunnel.as_ref().unwrap().grant_digest,
            ]
        };
        let (local_lease, local_projection) = selection(&material)?;
        if lease != local_lease || projection != local_projection {
            return Err(ConnectError::Authorization);
        }
        let charge = material.admission.account.reserve(ResourceLimits {
            sdk_bytes: 16384,
            items: 2,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        material.registered_pool = Some(Arc::new(RegisteredPoolControl {
            root,
            account: material.admission.account.clone(),
            transport,
            keys,
            authority: configuration.authority,
            incarnation,
            parent,
            candidate,
            continuation,
            grant: grants[1],
            lease,
            projection,
            cutoff: cutoff.min(material.admission.initiation_not_after_ms),
            deadline,
            phase: AtomicU8::new(0),
            cancellation,
            physical: Arc::new(AtomicUsize::new(0)),
            _charge: charge,
        }));
        Ok(RegisteredPoolTunnelServerMaterial {
            material,
            relay_service: configuration.relay_service,
            relay_audience: configuration.relay_audience,
            grants: wire_digests,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Payload<'static> {
        Payload {
            kind: "prepare",
            incarnation: STANDARD.encode([1; 32]),
            parent: STANDARD.encode([2; 32]),
            candidate: 0,
            grant: None,
            continuation: None,
        }
    }

    #[test]
    fn registered_pool_bytes_require_canonical_shape_and_size() {
        let encoded = STANDARD.encode([3, 4, 5]);
        assert_eq!(bytes(&encoded, 3, None).unwrap(), vec![3, 4, 5]);
        assert_eq!(bytes(&encoded, 3, Some(3)).unwrap(), vec![3, 4, 5]);
        for value in ["", "!!!!", "Aw=", "AwQ"] {
            assert!(bytes(value, 3, None).is_err(), "accepted {value:?}");
        }
        assert!(bytes(&encoded, 2, None).is_err());
        assert!(bytes(&encoded, 3, Some(2)).is_err());
    }

    #[test]
    fn registered_pool_reply_binds_authority_and_incarnation() {
        let wire = br#"{"authority":"authority","incarnation":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","prepared":true}"#;
        let parsed = reply(wire, "authority", &[1; 32]).unwrap();
        assert!(parsed.prepared);
        assert!(matches!(
            reply(wire, "other", &[1; 32]),
            Err(ConnectError::Authorization)
        ));
        assert!(matches!(
            reply(wire, "authority", &[2; 32]),
            Err(ConnectError::Authorization)
        ));
        assert!(matches!(
            reply(b"{}", "authority", &[1; 32]),
            Err(ConnectError::Protocol)
        ));
    }

    #[test]
    fn registered_pool_signed_request_contains_domain_bound_signature() {
        let fixture = crate::namespace_v4::verifier::credential::tests::Fixture::with_identity(
            codec::ActivationSource::PreauthorizedPool,
            "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1",
            None,
        );
        let keys = fixture
            .environment
            .identity_keys("fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1")
            .unwrap();
        let body = signed_request(&keys, &payload()).unwrap();
        let envelope: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let content = envelope["payload"].as_str().unwrap().as_bytes();
        let proof = STANDARD
            .decode(envelope["proof"].as_str().unwrap())
            .unwrap();
        assert_eq!(proof.len(), 64);
        assert!(
            content
                .windows(b"\"kind\":\"prepare\"".len())
                .any(|window| { window == b"\"kind\":\"prepare\"" })
        );
        assert_ne!(envelope["payload"], serde_json::Value::Null);
        assert_ne!(envelope["proof"], serde_json::Value::Null);
        drop(fixture);
    }

    #[test]
    fn registered_pool_payload_serializes_optional_control_fields() {
        let mut value = payload();
        value.grant = Some(STANDARD.encode([4; 32]));
        value.continuation = Some(STANDARD.encode([5; 32]));
        let json = serde_json::to_value(&value).unwrap();
        assert_eq!(json["kind"], "prepare");
        assert_eq!(json["candidate"], 0);
        assert!(json["grant"].as_str().is_some());
        assert!(json["continuation"].as_str().is_some());
    }
}
