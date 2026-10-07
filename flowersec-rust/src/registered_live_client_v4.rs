//! Client custody for one original installed TxA and the signed registered
//! control protocol. An interrupted operation permanently retires its phase.
use super::*;
use crate::{
    codec_v4::{Context, Value},
    environment_v4::ResourceAccount,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use zeroize::Zeroize;

pub(crate) struct RegisteredLiveClientControl {
    root: Arc<EnvironmentRoot>,
    transport: Arc<ControlHTTPS>,
    keys: IdentityKeys,
    authority: String,
    parent: [u8; 32],
    incarnation: Zeroizing<[u8; 32]>,
    state: Mutex<State>,
    _charge: EnvironmentCharge,
}
impl fmt::Debug for RegisteredLiveClientControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegisteredLiveClientControl { <opaque> }")
    }
}
struct Bound {
    account: ResourceAccount,
    attempt: [u8; 16],
    candidate: [u8; 16],
    route: [u8; 32],
    cutoff: u64,
    deadline: tokio::time::Instant,
    _charge: Arc<crate::control_https_v4::ControlHTTPSCustody>,
}
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Unbound,
    Bound,
    Preparing,
    Prepared,
    Authorizing,
    Delivered,
    HandedOff,
    Failed,
}
struct State {
    bound: Option<Bound>,
    phase: Phase,
    request: Option<Zeroizing<Vec<u8>>>,
    delivery: Option<[[u8; 32]; 2]>,
}
/// The acquired material owns withdrawal even if connection planning fails
/// before any control operation begins. It cannot be adopted by a new Acquire.
pub(crate) struct OriginalCustody(Arc<RegisteredLiveClientControl>);
impl Drop for OriginalCustody {
    fn drop(&mut self) {
        self.0.retire();
    }
}
struct Operation<'a> {
    control: &'a RegisteredLiveClientControl,
    committed: bool,
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.control.retire();
        }
    }
}
#[derive(Serialize)]
struct Payload<'a> {
    kind: &'a str,
    incarnation: String,
    parent: String,
    candidate: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authentication: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<RequestProjection>,
}
impl Drop for Payload<'_> {
    fn drop(&mut self) {
        self.incarnation.zeroize();
        if let Some(authentication) = &mut self.authentication {
            authentication.zeroize();
        }
        if let Some(signature) = &mut self.signature {
            signature.zeroize();
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestProjection {
    authority: String,
    tenant: String,
    audience: String,
    crypto_profile: String,
    candidate_index: u64,
    #[serde(rename = "activationNotAfterMS")]
    activation_not_after_ms: String,
    attempt_no: u8,
    issuer: String,
    lease: String,
    attempt: String,
    artifact: String,
    client_identity: String,
    server_identity: String,
    #[serde(rename = "candidateID")]
    candidate_id: String,
    route_digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    incarnation: String,
    authority: String,
    #[serde(default, rename = "clientGrant")]
    client_grant: String,
    #[serde(default, rename = "serverGrant")]
    server_grant: String,
    #[serde(default)]
    delivered: bool,
    #[serde(default)]
    matched: bool,
    #[serde(default)]
    prepared: bool,
    #[serde(default)]
    registered: bool,
    #[serde(default)]
    reserved: bool,
    #[serde(default)]
    attempt: String,
    #[serde(default)]
    activation: String,
    #[serde(default)]
    grant: String,
    #[serde(default)]
    continuation: String,
    #[serde(default)]
    lease: String,
    #[serde(default)]
    projection: String,
}
impl Drop for Reply {
    fn drop(&mut self) {
        self.incarnation.zeroize();
        self.activation.zeroize();
        self.grant.zeroize();
        self.client_grant.zeroize();
        self.server_grant.zeroize();
        self.continuation.zeroize();
    }
}
fn failure() -> crate::TransportConnectError {
    crate::TransportConnectError::LiveAuthorizationUnknown
}
impl RegisteredLiveClientControl {
    pub(crate) fn new(
        root: Arc<EnvironmentRoot>,
        transport: Arc<ControlHTTPS>,
        keys: IdentityKeys,
        artifact: &[u8],
        authority: String,
    ) -> Result<Arc<Self>, MaterialSourceError> {
        if !keys.belongs_to(&root)
            || authority.is_empty()
            || authority.len() > 128
            || authority.capacity() > 256
            || !authority.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(MaterialSourceError::MaterialUnavailable);
        }
        let charge = root
            .reserve_environment(ResourceLimits {
                sdk_bytes: 196608,
                items: 4,
                work_slots: 1,
                ..ResourceLimits::default()
            })
            .map_err(|_| MaterialSourceError::ConfigurationCapacity)?;
        let artifact = codec::decode(
            artifact,
            "Artifact",
            Limits {
                bytes: 65536,
                nodes: 16384,
            },
            None,
        )
        .map_err(|_| MaterialSourceError::MaterialUnavailable)?;
        let parent = codec::digest("artifact_digest", artifact)
            .map_err(|_| MaterialSourceError::MaterialUnavailable)?;
        let mut incarnation = Zeroizing::new([0; 32]);
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), incarnation.as_mut())
            .map_err(|_| MaterialSourceError::MaterialUnavailable)?;
        if *incarnation == [0; 32] {
            return Err(MaterialSourceError::MaterialUnavailable);
        }
        Ok(Arc::new(Self {
            root,
            transport,
            keys,
            authority,
            parent,
            incarnation,
            state: Mutex::new(State {
                bound: None,
                phase: Phase::Unbound,
                request: None,
                delivery: None,
            }),
            _charge: charge,
        }))
    }
    fn retire(&self) {
        let mut state = self
            .state
            .lock()
            .expect("registered original A custody withdrawal");
        if state.phase != Phase::HandedOff {
            state.phase = Phase::Failed;
        }
        state.request.take();
        state.delivery.take();
        state.bound.take();
    }
    pub(crate) fn original_custody(self: &Arc<Self>) -> OriginalCustody {
        OriginalCustody(self.clone())
    }
    pub(crate) fn bind_original(
        &self,
        pending: &PendingDirectAdmission,
    ) -> Result<(), crate::TransportConnectError> {
        pending.account.check()?;
        if !pending.account.belongs_to(&self.root)
            || pending.path_kind != 1
            || pending.artifact_digest != self.parent
            || pending.attempt_id == [0; 16]
        {
            return Err(failure());
        }
        let remaining = pending
            .initiation_not_after_ms
            .checked_sub(self.root.sample()?.upper_ms)
            .filter(|remaining| *remaining != 0)
            .ok_or_else(failure)?;
        let deadline = tokio::time::Instant::now()
            .checked_add(std::time::Duration::from_millis(remaining))
            .ok_or_else(failure)?;
        let charge = pending.account.reserve(ResourceLimits {
            sdk_bytes: 49152,
            items: 3,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let mut state = self.state.lock().expect("registered original A binding");
        if state.phase != Phase::Unbound {
            return Err(failure());
        }
        state.bound = Some(Bound {
            account: pending.account.clone(),
            attempt: pending.attempt_id,
            candidate: pending.candidate_id,
            route: pending.route_digest,
            cutoff: pending.initiation_not_after_ms,
            deadline,
            _charge: crate::control_https_v4::ControlHTTPSCustody::new(charge),
        });
        state.phase = Phase::Bound;
        Ok(())
    }
    fn check(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<tokio::time::Instant, crate::TransportConnectError> {
        if cancellation.is_cancelled() || self.root.is_closed() {
            return Err(failure());
        }
        let state = self.state.lock().expect("registered original A check");
        if matches!(
            state.phase,
            Phase::Failed | Phase::Unbound | Phase::HandedOff
        ) {
            return Err(failure());
        }
        let bound = state.bound.as_ref().ok_or_else(failure)?;
        bound.account.check()?;
        if self.root.sample()?.upper_ms >= bound.cutoff
            || tokio::time::Instant::now() >= bound.deadline
        {
            return Err(failure());
        }
        Ok(bound.deadline)
    }
    fn request<'a>(
        &self,
        wire: &'a [u8],
    ) -> Result<(Value<'a>, [u8; 16]), crate::TransportConnectError> {
        let request = codec::decode_control_array(
            wire,
            Limits {
                bytes: 8192,
                nodes: 128,
            },
        )?;
        if request.len()? != 13
            || request.at(0)?.text()? != "live-authorization-1"
            || request.at(10)?.len()? != 3
            || request.at(10)?.at(0)?.uint()? != 0
            || request.at(12)?.uint()? != 1
        {
            return Err(failure());
        }
        let state = self
            .state
            .lock()
            .expect("registered original A request binding");
        let bound = state.bound.as_ref().ok_or_else(failure)?;
        let attempt: [u8; 16] = request.at(6)?.bytes()?.try_into().map_err(|_| failure())?;
        if attempt != bound.attempt
            || request.at(7)?.bytes()? != self.parent.as_slice()
            || request.at(10)?.at(1)?.bytes()? != bound.candidate.as_slice()
            || request.at(10)?.at(2)?.bytes()? != bound.route.as_slice()
            || request.at(11)?.uint()? != bound.cutoff
        {
            return Err(failure());
        }
        Ok((request, attempt))
    }
    /// An external RelayHost uses the same original A Account and deadline as
    /// registered authority delivery. Withdrawal retires both control paths.
    pub(crate) async fn relay_exchange(
        &self,
        transport: &ControlHTTPS,
        path: &'static str,
        wire: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<(), crate::TransportConnectError> {
        let deadline = self.check(cancellation)?;
        let custody = self
            .state
            .lock()
            .expect("registered original A relay custody")
            .bound
            .as_ref()
            .ok_or_else(failure)?
            ._charge
            .clone();
        let mut operation = Operation {
            control: self,
            committed: false,
        };
        let guard = || {
            self.check(cancellation)
                .map(|_| ())
                .map_err(|_| crate::ControlHTTPSFailure::Rejected)
        };
        let reply = tokio::select! {
            result = transport.post_owned(path, wire, 1, cancellation, false, &guard, custody) => result.map_err(|_| failure())?,
            _ = tokio::time::sleep_until(deadline) => return Err(failure()),
        };
        self.check(cancellation)?;
        if reply.as_slice() != [0xf5] {
            return Err(failure());
        }
        operation.committed = true;
        Ok(())
    }
    async fn call(
        &self,
        payload: Payload<'_>,
        cancellation: &CancellationToken,
    ) -> Result<Reply, crate::TransportConnectError> {
        let deadline = self.check(cancellation)?;
        let custody = self
            .state
            .lock()
            .expect("registered original A writer custody")
            .bound
            .as_ref()
            .ok_or_else(failure)?
            ._charge
            .clone();
        let content = Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| failure())?);
        let mut message = Zeroizing::new(Vec::with_capacity(content.len() + 40));
        message.extend_from_slice(b"flowersec/original-tunnel-control/1\0");
        message.extend_from_slice(&content);
        let proof = Zeroizing::new(self.keys.sign_original_control(&message)?);
        #[derive(Serialize)]
        struct Envelope<'a> {
            payload: &'a str,
            proof: String,
        }
        let body = Zeroizing::new(
            serde_json::to_vec(&Envelope {
                payload: std::str::from_utf8(&content).map_err(|_| failure())?,
                proof: STANDARD.encode(proof.as_slice()),
            })
            .map_err(|_| failure())?,
        );
        let guard = || {
            self.check(cancellation)
                .map(|_| ())
                .map_err(|_| crate::ControlHTTPSFailure::Rejected)
        };
        let response = tokio::select! {
            result = self.transport.post_registered_live(&body, 32768, cancellation, &guard, custody) => result.map_err(|_| failure())?,
            _ = tokio::time::sleep_until(deadline) => return Err(failure()),
        };
        self.check(cancellation)?;
        let reply: Reply = serde_json::from_slice(&response).map_err(|_| failure())?;
        if reply.incarnation != payload.incarnation
            || reply.authority != self.authority
            || reply.delivered
            || reply.matched
            || reply.registered
            || reply.reserved
            || !reply.client_grant.is_empty()
            || !reply.server_grant.is_empty()
            || !reply.attempt.is_empty()
            || !reply.activation.is_empty()
            || !reply.continuation.is_empty()
            || !reply.lease.is_empty()
            || !reply.projection.is_empty()
            || payload.kind == "live_client_prepared"
                && (!reply.prepared || !reply.grant.is_empty())
            || payload.kind == "live_authorize" && (reply.prepared || reply.grant.is_empty())
        {
            return Err(failure());
        }
        Ok(reply)
    }
    fn payload(&self, kind: &'static str) -> Payload<'static> {
        Payload {
            kind,
            incarnation: STANDARD.encode(self.incarnation.as_slice()),
            parent: STANDARD.encode(self.parent),
            candidate: 0,
            attempt: None,
            authentication: None,
            signature: None,
            request: None,
        }
    }
    pub(crate) async fn prepare_listener(
        &self,
        pending: &PendingDirectAdmission,
        cancellation: &CancellationToken,
    ) -> Result<(), crate::TransportConnectError> {
        self.check(cancellation)?;
        {
            let state = self
                .state
                .lock()
                .expect("registered original A listener identity");
            let bound = state.bound.as_ref().ok_or_else(failure)?;
            if pending.artifact_digest != self.parent
                || pending.attempt_id != bound.attempt
                || pending.candidate_id != bound.candidate
                || pending.route_digest != bound.route
            {
                return Err(failure());
            }
        }
        self.prepare(cancellation).await
    }
    async fn prepare(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<(), crate::TransportConnectError> {
        self.check(cancellation)?;
        let attempt = {
            let mut state = self
                .state
                .lock()
                .expect("registered original A prepare once");
            if state.phase != Phase::Bound {
                return Err(failure());
            }
            state.phase = Phase::Preparing;
            state.bound.as_ref().ok_or_else(failure)?.attempt
        };
        let mut operation = Operation {
            control: self,
            committed: false,
        };
        let mut payload = self.payload("live_client_prepared");
        payload.attempt = Some(STANDARD.encode(attempt));
        self.call(payload, cancellation).await?;
        let mut state = self
            .state
            .lock()
            .expect("registered original A preparation completion");
        if state.phase != Phase::Preparing {
            return Err(failure());
        }
        state.phase = Phase::Prepared;
        operation.committed = true;
        Ok(())
    }
    pub(crate) async fn prepare_request(
        &self,
        request: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<(), crate::TransportConnectError> {
        self.check(cancellation)?;
        self.request(request)?;
        let prepared = self
            .state
            .lock()
            .expect("registered original A native completion")
            .phase
            == Phase::Prepared;
        if !prepared {
            self.prepare(cancellation).await?;
        }
        let mut state = self
            .state
            .lock()
            .expect("registered original A canonical request capture");
        if state.phase != Phase::Prepared || state.request.is_some() {
            return Err(failure());
        }
        state.request = Some(Zeroizing::new(request.to_vec()));
        Ok(())
    }
    pub(crate) async fn authorize(
        &self,
        wire: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<LiveTunnelAuthorization, crate::TransportConnectError> {
        self.check(cancellation)?;
        let (request, _) = self.request(wire)?;
        {
            let mut state = self.state.lock().expect("registered original A TxB once");
            if state.phase != Phase::Prepared
                || state.request.as_ref().map(|request| request.as_slice()) != Some(wire)
            {
                return Err(failure());
            }
            state.phase = Phase::Authorizing;
        }
        let mut operation = Operation {
            control: self,
            committed: false,
        };
        let mut authentication = Zeroizing::new(Vec::with_capacity(wire.len() + 32));
        authentication.resize(32, 0);
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut authentication[..32])
            .map_err(|_| failure())?;
        if authentication[..32] == [0; 32] {
            return Err(failure());
        }
        authentication.extend_from_slice(wire);
        let signature = Zeroizing::new(self.keys.sign_original_control(&authentication)?);
        let mut payload = self.payload("live_authorize");
        payload.authentication = Some(STANDARD.encode(authentication.as_slice()));
        payload.signature = Some(STANDARD.encode(signature.as_slice()));
        payload.request = Some(RequestProjection {
            authority: self.authority.clone(),
            tenant: request.at(1)?.text()?.to_owned(),
            audience: request.at(2)?.text()?.to_owned(),
            crypto_profile: request.at(3)?.text()?.to_owned(),
            candidate_index: 0,
            activation_not_after_ms: request.at(11)?.uint()?.to_string(),
            attempt_no: 1,
            issuer: STANDARD.encode(request.at(4)?.bytes()?),
            lease: STANDARD.encode(request.at(5)?.bytes()?),
            attempt: STANDARD.encode(request.at(6)?.bytes()?),
            artifact: STANDARD.encode(request.at(7)?.bytes()?),
            client_identity: STANDARD.encode(request.at(8)?.bytes()?),
            server_identity: STANDARD.encode(request.at(9)?.bytes()?),
            candidate_id: STANDARD.encode(request.at(10)?.at(1)?.bytes()?),
            route_digest: STANDARD.encode(request.at(10)?.at(2)?.bytes()?),
        });
        let reply = self.call(payload, cancellation).await?;
        let wire = decode_base64(&reply.grant, LIVE_TUNNEL_RESPONSE_BYTES)?;
        let value = codec::decode_control_array(
            &wire,
            Limits {
                bytes: LIVE_TUNNEL_RESPONSE_BYTES,
                nodes: 16,
            },
        )?;
        if value.len()? != 3 || value.at(0)?.text()? != "live-tunnel-material-1" {
            return Err(failure());
        }
        let proof = value.at(1)?.bytes()?;
        let grant = value.at(2)?.bytes()?;
        if proof.is_empty()
            || proof.len() > 4096
            || grant.is_empty()
            || grant.len() > LIVE_TUNNEL_GRANT_BYTES
        {
            return Err(failure());
        }
        let digests = delivery_digests(proof, grant)?;
        let mut state = self
            .state
            .lock()
            .expect("registered original A delivery custody");
        if state.phase != Phase::Authorizing {
            return Err(failure());
        }
        state.delivery = Some(digests);
        state.phase = Phase::Delivered;
        operation.committed = true;
        Ok(LiveTunnelAuthorization {
            activation: proof.to_vec(),
            client_grant: grant.to_vec(),
        })
    }
    pub(crate) fn complete_delivery(
        &self,
        request: &[u8],
        proof: &[u8],
        grant: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<(), crate::TransportConnectError> {
        self.check(cancellation)?;
        let digests = delivery_digests(proof, grant)?;
        let mut state = self
            .state
            .lock()
            .expect("registered original A verified delivery handoff");
        if state.phase != Phase::Delivered
            || state.request.as_ref().map(|wire| wire.as_slice()) != Some(request)
            || state.delivery != Some(digests)
        {
            return Err(failure());
        }
        state.phase = Phase::HandedOff;
        // Session/native owners now retain the original Account. This source
        // stays one-shot without holding retired control storage indefinitely.
        state.request.take();
        state.delivery.take();
        state.bound.take();
        Ok(())
    }
}
fn delivery_digests(
    proof: &[u8],
    grant: &[u8],
) -> Result<[[u8; 32]; 2], crate::TransportConnectError> {
    let proof = codec::decode_context(
        proof,
        "ActivationAuthorization",
        Limits {
            bytes: 4096,
            nodes: 512,
        },
        None,
        Context::with_activation_source(codec::ActivationSource::LiveAuthority),
    )?;
    let grant = codec::decode(
        grant,
        "Grant",
        Limits {
            bytes: LIVE_TUNNEL_GRANT_BYTES,
            nodes: 2048,
        },
        None,
    )?;
    Ok([
        codec::digest("activation_digest", proof)?,
        codec::digest("grant_digest", grant)?,
    ])
}
fn decode_base64(
    value: &str,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, crate::TransportConnectError> {
    if value.is_empty() || value.len() > maximum.div_ceil(3) * 4 {
        return Err(failure());
    }
    let bytes = Zeroizing::new(STANDARD.decode(value).map_err(|_| failure())?);
    if bytes.is_empty()
        || bytes.len() > maximum
        || Zeroizing::new(STANDARD.encode(bytes.as_slice())).as_str() != value
    {
        return Err(failure());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec_v4::tests::hex;

    fn corpus(id: &str) -> Vec<u8> {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../../testdata/transport_v4/corpus.json")).unwrap();
        hex(corpus["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["id"] == id)
            .unwrap()["hex"]
            .as_str()
            .unwrap())
    }

    #[test]
    fn registered_live_base64_requires_canonical_bounded_bytes() {
        let encoded = STANDARD.encode([7, 8, 9]);
        assert_eq!(decode_base64(&encoded, 3).unwrap().as_slice(), &[7, 8, 9]);
        for value in ["", "!!!!", "Bw=", "Bw", "BwgJAA=="] {
            assert!(decode_base64(value, 3).is_err(), "accepted {value:?}");
        }
        assert!(decode_base64(&encoded, 2).is_err());
    }

    #[test]
    fn registered_live_delivery_digests_accept_valid_live_material_only() {
        let proof = corpus("activation_live_fields");
        let grant = corpus("grant_fields");
        let digests = delivery_digests(&proof, &grant).unwrap();
        assert_ne!(digests[0], [0; 32]);
        assert_ne!(digests[1], [0; 32]);
        assert!(delivery_digests(&proof[..proof.len() - 1], &grant).is_err());
        assert!(delivery_digests(&proof, &[0x80]).is_err());
    }
}
