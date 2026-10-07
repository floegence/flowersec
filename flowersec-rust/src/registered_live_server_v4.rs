//! One original B registration over the independently installed signed JSON
//! control protocol. No operation retries or reopens a publication capability.
use super::*;
use crate::control_https_v4::{ControlHTTPS, ControlHTTPSConfiguration};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Debug)]
pub struct RegisteredLiveServerControlConfiguration {
    pub control: ControlHTTPSConfiguration,
    /// Independently installed external RelayHost control. Reverse readiness
    /// uses B's same original mTLS identity; the authority retains Grant delivery.
    pub relay_preparation: Option<ControlHTTPSConfiguration>,
    pub authority: String,
    pub activation_signing_key_id: String,
}
/// The independently installed physical B owner used in the same original
/// registration operation as the authority's native relay preparation.
pub enum RegisteredLiveServerPreparation<'a> {
    Carrier(WssConnectOptions),
    Listener(&'a LiveReverseTunnelListener),
}
impl fmt::Debug for RegisteredLiveServerPreparation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegisteredLiveServerPreparation { <opaque> }")
    }
}
pub struct RegisteredLiveTunnelServerPublication {
    original: Option<OriginalLiveTunnelServerPublication>,
    control: RegisteredLiveServerControl,
    completed: bool,
}
impl fmt::Debug for RegisteredLiveTunnelServerPublication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegisteredLiveTunnelServerPublication { <opaque> }")
    }
}
struct RegisteredLiveServerControl {
    source: Arc<OriginalLiveAcceptedSource>,
    index: usize,
    generation: u64,
    account: ResourceAccount,
    transport: ControlHTTPS,
    relay_preparation: Option<ControlHTTPS>,
    authority: String,
    incarnation: Zeroizing<[u8; 16]>,
    recipient: [u8; 16],
    parent: [u8; 32],
    cutoff: u64,
    deadline: Instant,
    _charge: Arc<crate::control_https_v4::ControlHTTPSCustody>,
}
#[derive(Serialize)]
struct Payload<'a> {
    kind: &'a str,
    incarnation: String,
    parent: String,
    candidate: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    activation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant: Option<String>,
}
#[derive(Deserialize, Default)]
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
fn decode_base64(value: &str, maximum: usize, exact: Option<usize>) -> ConnectResult<Vec<u8>> {
    if value.is_empty() || value.len() > maximum.div_ceil(3) * 4 {
        return Err(ConnectError::Protocol);
    }
    let mut bytes = Zeroizing::new(STANDARD.decode(value).map_err(|_| ConnectError::Protocol)?);
    if bytes.is_empty()
        || bytes.len() > maximum
        || exact.is_some_and(|size| bytes.len() != size)
        || Zeroizing::new(STANDARD.encode(bytes.as_slice())).as_str() != value
    {
        return Err(ConnectError::Protocol);
    }
    Ok(std::mem::take(&mut *bytes).into_boxed_slice().into_vec())
}
impl RegisteredLiveServerControl {
    fn check(&self, cancellation: &CancellationToken) -> ConnectResult<()> {
        if cancellation.is_cancelled() || self.source.root.is_closed() {
            return Err(ConnectError::Canceled);
        }
        self.account.check()?;
        if Instant::now() >= self.deadline || self.source.root.sample()?.upper_ms >= self.cutoff {
            return Err(ConnectError::Deadline);
        }
        let state = self
            .source
            .state
            .lock()
            .expect("registered original B control owner");
        let record = state.records[self.index]
            .as_ref()
            .filter(|record| record.generation == self.generation)
            .ok_or(ConnectError::Authorization)?;
        if state.closed || record.retired {
            return Err(ConnectError::Authorization);
        }
        if self.source.root.sample()?.upper_ms >= record.cutoff {
            return Err(ConnectError::Deadline);
        }
        Ok(())
    }
    async fn relay_ready(
        &self,
        candidate: [u8; 16],
        route: [u8; 32],
        cancellation: &CancellationToken,
    ) -> ConnectResult<()> {
        let Some(relay) = &self.relay_preparation else {
            return Ok(());
        };
        self.check(cancellation)?;
        let mut wire = Zeroizing::new(Vec::with_capacity(192));
        codec::encode_head(&mut wire, 4, 5);
        for (kind, bytes) in [
            (3, b"tunnel-relay-ready-1".as_slice()),
            (2, self.parent.as_slice()),
            (2, candidate.as_slice()),
            (2, route.as_slice()),
        ] {
            codec::encode_head(&mut wire, kind, bytes.len() as u64);
            wire.extend_from_slice(bytes);
        }
        codec::encode_head(&mut wire, 0, 1);
        let guard = || {
            self.check(cancellation)
                .map_err(|_| crate::ControlHTTPSFailure::Rejected)
        };
        let response = tokio::select! {
            result = relay.post_owned("/tunnel/relay-ready", &wire, 1, cancellation, false, &guard, self._charge.clone()) =>
                result.map_err(|_| ConnectError::Authorization)?,
            _ = tokio::time::sleep_until(self.deadline) => return Err(ConnectError::Deadline),
        };
        self.check(cancellation)?;
        if response.as_slice() != [0xf5] {
            return Err(ConnectError::Protocol);
        }
        Ok(())
    }
    async fn call(
        &self,
        kind: &str,
        attempt: Option<[u8; 16]>,
        digests: Option<[[u8; 32]; 2]>,
        cancellation: &CancellationToken,
    ) -> ConnectResult<Reply> {
        self.check(cancellation)?;
        let payload = Payload {
            kind,
            incarnation: STANDARD.encode(self.incarnation.as_slice()),
            parent: STANDARD.encode(self.parent),
            candidate: 0,
            recipient: (kind == "live_register").then(|| STANDARD.encode(self.recipient)),
            attempt: attempt.map(|value| STANDARD.encode(value)),
            activation: digests.map(|value| STANDARD.encode(value[0])),
            grant: digests.map(|value| STANDARD.encode(value[1])),
        };
        let content =
            Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| ConnectError::Configuration)?);
        let mut message = Zeroizing::new(Vec::with_capacity(content.len() + 40));
        message.extend_from_slice(b"flowersec/original-tunnel-control/1\0");
        message.extend_from_slice(&content);
        let proof = Zeroizing::new(
            self.source
                .keys
                .inner
                .sign(&message)
                .map_err(|_| ConnectError::Authorization)?,
        );
        #[derive(Serialize)]
        struct Envelope<'a> {
            payload: &'a str,
            proof: String,
        }
        let body = Zeroizing::new(
            serde_json::to_vec(&Envelope {
                payload: std::str::from_utf8(&content).map_err(|_| ConnectError::Configuration)?,
                proof: STANDARD.encode(proof.as_slice()),
            })
            .map_err(|_| ConnectError::Configuration)?,
        );
        self.check(cancellation)?;
        let cutoff = {
            let state = self
                .source
                .state
                .lock()
                .expect("registered original B tightened delivery cutoff");
            state.records[self.index]
                .as_ref()
                .filter(|record| record.generation == self.generation)
                .ok_or(ConnectError::Authorization)?
                .cutoff
                .min(self.cutoff)
        };
        let remaining = cutoff
            .checked_sub(self.source.root.sample()?.upper_ms)
            .filter(|remaining| *remaining != 0)
            .ok_or(ConnectError::Deadline)?;
        let deadline = self.deadline.min(
            Instant::now()
                .checked_add(Duration::from_millis(remaining))
                .ok_or(ConnectError::Configuration)?,
        );
        let guard = || {
            self.check(cancellation).map_err(|error| match error {
                ConnectError::Canceled => crate::control_https_v4::ControlHTTPSFailure::Canceled,
                ConnectError::Deadline => crate::control_https_v4::ControlHTTPSFailure::Deadline,
                _ => crate::control_https_v4::ControlHTTPSFailure::Rejected,
            })
        };
        let exchange = self.transport.post_registered_live(
            &body,
            32768,
            cancellation,
            &guard,
            self._charge.clone(),
        );
        let wire = tokio::select! {
            result = exchange => result.map_err(|error| match error {
                crate::control_https_v4::ControlHTTPSFailure::Canceled => ConnectError::Canceled,
                crate::control_https_v4::ControlHTTPSFailure::Deadline => ConnectError::Deadline,
                crate::control_https_v4::ControlHTTPSFailure::Capacity => ConnectError::Capacity,
                crate::control_https_v4::ControlHTTPSFailure::Configuration => ConnectError::Configuration,
                _ => ConnectError::Authorization,
            })?,
            _ = tokio::time::sleep_until(deadline) => return Err(ConnectError::Deadline),
        };
        self.check(cancellation)?;
        let reply: Reply = serde_json::from_slice(&wire).map_err(|_| ConnectError::Protocol)?;
        if reply.incarnation != payload.incarnation
            || reply.authority != self.authority
            || !reply.client_grant.is_empty()
            || !reply.server_grant.is_empty()
            || !reply.continuation.is_empty()
            || !reply.lease.is_empty()
            || !reply.projection.is_empty()
            || reply.matched
            || reply.prepared
        {
            return Err(ConnectError::Protocol);
        }
        let valid = match kind {
            "live_register" => {
                reply.registered
                    && !reply.reserved
                    && !reply.delivered
                    && reply.attempt.is_empty()
                    && reply.activation.is_empty()
                    && reply.grant.is_empty()
            }
            "live_reservation" => {
                !reply.registered
                    && !reply.reserved
                    && !reply.delivered
                    && reply.activation.is_empty()
                    && reply.grant.is_empty()
                    && !reply.attempt.is_empty()
            }
            "live_reserved" => {
                reply.reserved
                    && !reply.registered
                    && !reply.delivered
                    && reply.attempt.is_empty()
                    && reply.activation.is_empty()
                    && reply.grant.is_empty()
            }
            "live_receive" => {
                !reply.registered
                    && !reply.reserved
                    && !reply.delivered
                    && !reply.attempt.is_empty()
                    && !reply.activation.is_empty()
                    && !reply.grant.is_empty()
            }
            "live_allow_ack" => {
                reply.delivered
                    && !reply.registered
                    && !reply.reserved
                    && reply.attempt.is_empty()
                    && reply.activation.is_empty()
                    && reply.grant.is_empty()
            }
            _ => false,
        };
        if !valid {
            return Err(ConnectError::Protocol);
        }
        Ok(reply)
    }
}
impl OriginalLiveTunnelServerPublication {
    /// Join the authority's original registration and B's actual preparation.
    /// Forward native dialing and remote registration run concurrently because
    /// the authority prepares its original relay leg during that registration.
    pub async fn register_original_control(
        mut self,
        mut configuration: RegisteredLiveServerControlConfiguration,
        preparation: RegisteredLiveServerPreparation<'_>,
        cancellation: &CancellationToken,
    ) -> ConnectResult<RegisteredLiveTunnelServerPublication> {
        self.inner.check_pending_original()?;
        if configuration.control.base_path != "/flowersec/control/live"
            || configuration.authority.is_empty()
            || configuration.authority.len() > 128
            || configuration.authority.capacity() > 256
            || !configuration
                .authority
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
            || configuration.activation_signing_key_id.is_empty()
            || configuration.activation_signing_key_id.len() > 128
            || configuration.activation_signing_key_id.capacity() > 256
        {
            return Err(ConnectError::Configuration);
        }
        if let Some(relay) = &configuration.relay_preparation
            && (!relay.base_path.is_empty()
                || relay.client_chain_der.first() != configuration.control.client_chain_der.first())
        {
            return Err(ConnectError::Configuration);
        }
        let registration = self
            .registration
            .as_mut()
            .ok_or(ConnectError::Authorization)?;
        registration.restrict_signer(&configuration.activation_signing_key_id)?;
        let account = registration.registration().account().clone();
        let parent = registration.registration().artifact_digest();
        let source = self.inner.source.clone();
        let cutoff = {
            let state = source
                .state
                .lock()
                .expect("registered original B immutable cutoff");
            state.records[self.inner.index]
                .as_ref()
                .filter(|record| record.generation == self.inner.generation)
                .ok_or(ConnectError::Authorization)?
                .cutoff
        };
        let remaining = cutoff
            .checked_sub(source.root.sample()?.upper_ms)
            .filter(|remaining| *remaining != 0)
            .ok_or(ConnectError::Deadline)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(remaining))
            .ok_or(ConnectError::Configuration)?;
        configuration.control.timeout = configuration
            .control
            .timeout
            .min(Duration::from_millis(remaining));
        if let Some(relay) = &mut configuration.relay_preparation {
            relay.timeout = relay.timeout.min(Duration::from_millis(remaining));
        }
        let charge = account.reserve(ResourceLimits {
            sdk_bytes: 196608,
            items: 4,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let mut incarnation = Zeroizing::new([0; 16]);
        let mut recipient = [0; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), incarnation.as_mut())
            .map_err(|_| ConnectError::Carrier)?;
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut recipient)
            .map_err(|_| ConnectError::Carrier)?;
        if *incarnation == [0; 16] || recipient == [0; 16] {
            return Err(ConnectError::Carrier);
        }
        let transport = ControlHTTPS::new(source.root.clone(), configuration.control)
            .map_err(|_| ConnectError::Configuration)?;
        let relay_preparation = configuration
            .relay_preparation
            .map(|relay| {
                ControlHTTPS::new(source.root.clone(), relay)
                    .map_err(|_| ConnectError::Configuration)
            })
            .transpose()?;
        let custody =
            source.retain_registered_control(self.inner.index, self.inner.generation, charge)?;
        let control = RegisteredLiveServerControl {
            source: source.clone(),
            index: self.inner.index,
            generation: self.inner.generation,
            account,
            transport,
            relay_preparation,
            authority: configuration.authority,
            incarnation,
            recipient,
            parent,
            cutoff,
            deadline,
            _charge: custody,
        };
        let operation_cancel = cancellation.child_token();
        let listener_preparation =
            matches!(&preparation, RegisteredLiveServerPreparation::Listener(_));
        let remote = async {
            let result = control
                .call("live_register", None, None, &operation_cancel)
                .await;
            if result.is_err() {
                operation_cancel.cancel();
            }
            result
        };
        let local = async {
            let result = async {
                match preparation {
                    RegisteredLiveServerPreparation::Carrier(options) => {
                        self.prepare_original_carrier(options, &operation_cancel)
                            .await
                    }
                    RegisteredLiveServerPreparation::Listener(listener) => {
                        let readiness = listener.original_readiness()?;
                        let registration = self
                            .registration
                            .as_ref()
                            .ok_or(ConnectError::Authorization)?
                            .registration();
                        {
                            let state = source
                                .state
                                .lock()
                                .expect("registered original B listener installation");
                            let bytes = state.records[self.inner.index]
                                .as_ref()
                                .and_then(|record| record.bytes.as_ref())
                                .ok_or(ConnectError::Authorization)?;
                            readiness.validate(&source.root, &bytes.artifact, registration)?;
                        }
                        readiness
                            .wait_ready(listener.preparation_timeout(), &operation_cancel)
                            .await?;
                        self.inner.check_pending_original()?;
                        let registration = self
                            .registration
                            .as_ref()
                            .ok_or(ConnectError::Authorization)?
                            .registration();
                        control
                            .relay_ready(
                                registration.candidate_id(),
                                registration.route_digest(),
                                &operation_cancel,
                            )
                            .await?;
                        self.inner.check_pending_original()?;
                        self.listener_announced = true;
                        self.original_listener = Some(readiness);
                        Ok(self)
                    }
                }
            }
            .await;
            if result.is_err() {
                operation_cancel.cancel();
            }
            result
        };
        let original = if listener_preparation {
            // The bound listener must announce its original READY before the
            // authority can register B. These control exchanges share one
            // Account TLS position and retain the same immutable deadline.
            let original = local.await?;
            remote.await?;
            original
        } else {
            // A dialed carrier and the authority's original preparation may
            // depend on one another, so both must advance and join together.
            let (remote, local) = tokio::join!(remote, local);
            match (remote, local) {
                // Preserve local failure instead of its sibling's cancellation.
                (Err(ConnectError::Canceled), Err(failure)) => return Err(failure),
                (remote, local) => {
                    remote?;
                    local?
                }
            }
        };
        control.check(cancellation)?;
        Ok(RegisteredLiveTunnelServerPublication {
            original: Some(original),
            control,
            completed: false,
        })
    }
}
impl RegisteredLiveTunnelServerPublication {
    /// Consume one original reservation and TxB delivery. B verifies the exact
    /// signed bytes on its retained registration before acknowledging their
    /// digests; transport failure discards this capability instead of retrying.
    pub async fn receive_original_publication(
        mut self,
        cancellation: &CancellationToken,
    ) -> ConnectResult<OriginalLiveTunnelServerMaterial> {
        let reservation = self
            .control
            .call("live_reservation", None, None, cancellation)
            .await?;
        let attempt: [u8; 16] = decode_base64(&reservation.attempt, 16, Some(16))?
            .try_into()
            .map_err(|_| ConnectError::Protocol)?;
        self.original
            .as_mut()
            .ok_or(ConnectError::Authorization)?
            .reserve_original_attempt(attempt)?;
        self.control
            .call("live_reserved", Some(attempt), None, cancellation)
            .await?;
        let reply = self
            .control
            .call("live_receive", None, None, cancellation)
            .await?;
        if decode_base64(&reply.attempt, 16, Some(16))?.as_slice() != attempt.as_slice() {
            return Err(ConnectError::Authorization);
        }
        let mut activation = Zeroizing::new(decode_base64(&reply.activation, 4096, None)?);
        let mut grant = Zeroizing::new(decode_base64(&reply.grant, 9302, None)?);
        let proof_view = decode(
            &activation,
            "ActivationAuthorization",
            4096,
            Context::with_activation_source(codec::ActivationSource::LiveAuthority),
        )?;
        let grant_view = decode(&grant, "Grant", 9302, Context::default())?;
        let digests = [
            codec::digest("activation_digest", proof_view)?,
            codec::digest("grant_digest", grant_view)?,
        ];
        let material = self
            .original
            .take()
            .ok_or(ConnectError::Authorization)?
            .publish_tunnel(
                std::mem::take(&mut *activation),
                std::mem::take(&mut *grant),
                cancellation,
            )?;
        material.check_original_prepared(cancellation)?;
        self.control
            .call("live_allow_ack", Some(attempt), Some(digests), cancellation)
            .await?;
        material.check_original_prepared(cancellation)?;
        self.control.check(cancellation)?;
        self.completed = true;
        Ok(material)
    }
}
impl Drop for RegisteredLiveTunnelServerPublication {
    fn drop(&mut self) {
        if !self.completed {
            self.control
                .source
                .retire(self.control.index, self.control.generation);
        }
    }
}
