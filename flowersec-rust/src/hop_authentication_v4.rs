//! HOP possession belongs to the original prepared physical carrier. A relay
//! proof authenticates that hop and never substitutes for FSB4 or dual READY.

use super::*;
use crate::namespace_v4::verifier::credential::tunnel::VerifiedTunnelHop;
use tokio::sync::mpsc;

const HELLO_BYTES: usize = 10_346;
const PROOF_BYTES: usize = 70;
const CHALLENGE_BYTES: usize = 129;

pub(super) struct EndpointHop {
    account: ResourceAccount,
    carrier: [u8; 16],
    challenge: [u8; 32],
    hello: Vec<u8>,
    context: Vec<u8>,
    message: Zeroizing<Vec<u8>>,
    phase: u8,
    initiation_end: u64,
    _charge: ResourceCharge,
}
impl fmt::Debug for EndpointHop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EndpointHop { <opaque> }")
    }
}
impl EndpointHop {
    pub(crate) fn preparation_limits() -> ResourceLimits {
        ResourceLimits {
            sdk_bytes: 49_152,
            items: 3,
            work_slots: 1,
            ..ResourceLimits::default()
        }
    }
    /// Retain the complete HOP workspace before pool consumption or live TxB.
    /// Controller backing is transferred from the original pre-acquisition plan.
    pub(super) fn prepare(
        account: &ResourceAccount,
        provider: &direct_carrier::Provider,
        charge: ResourceCharge,
    ) -> ConnectResult<Self> {
        if !charge.matches(account, Self::preparation_limits()) || provider.identity() == [0; 16] {
            return Err(ConnectError::Configuration);
        }
        account.check()?;
        provider.check()?;
        let mut challenge = [0; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut challenge)
            .map_err(|_| ConnectError::Authorization)?;
        if challenge == [0; 32] {
            return Err(ConnectError::Authorization);
        }
        let mut hello = Vec::new();
        hello
            .try_reserve_exact(HELLO_BYTES)
            .map_err(|_| ConnectError::Capacity)?;
        let mut context = Vec::new();
        context
            .try_reserve_exact(CHALLENGE_BYTES)
            .map_err(|_| ConnectError::Capacity)?;
        let mut message = Zeroizing::new(Vec::new());
        message
            .try_reserve_exact(512)
            .map_err(|_| ConnectError::Capacity)?;
        Ok(Self {
            account: account.clone(),
            carrier: provider.identity(),
            challenge,
            hello,
            context,
            message,
            phase: 0,
            initiation_end: 0,
            _charge: charge,
        })
    }
    /// Pool inputs are fully checked before consume. Live authorization fills
    /// this same already allocated owner when its original Grant becomes known.
    pub(super) fn bind(
        mut self,
        admission: &CredentialAdmission,
        grant: &[u8],
        local_certificate: &[u8],
        relay_certificate: &[u8],
        keys: &IdentityKeys,
    ) -> ConnectResult<Self> {
        let facts = admission
            .tunnel
            .as_ref()
            .ok_or(ConnectError::Configuration)?;
        if self.initiation_end != 0
            || !self.account.same_owner(&admission.account)
            || facts.authenticated()
            || facts.endpoint_key != keys.ed25519_public_key()
        {
            return Err(ConnectError::Configuration);
        }
        let original_grant = decode(grant, "Grant", 9302, Context::default())?;
        let certificate = decode(
            local_certificate,
            "IdentityCertificate",
            8192,
            Context::default(),
        )?;
        let relay = decode(
            relay_certificate,
            "IdentityCertificate",
            8192,
            Context::default(),
        )?;
        if codec::digest("grant_digest", original_grant)? != facts.grant_digest
            || certificate.b::<32>("IdentityCertificate", "ed25519_public_key")?
                != facts.endpoint_key
            || certificate.u("IdentityCertificate", "role")? != u64::from(facts.endpoint_role)
            || codec::digest("certificate_digest", certificate)?
                != admission.certificate_digests[facts.endpoint_role as usize]
            || codec::digest("certificate_digest", relay)? != facts.relay_identity_digest
        {
            return Err(ConnectError::Authorization);
        }
        fn byte_string_len(bytes: &[u8]) -> usize {
            bytes.len()
                + match bytes.len() {
                    0..24 => 1,
                    24..256 => 2,
                    _ => 3,
                }
        }
        // Exact canonical sizes are checked before filling the fixed workspace.
        let endpoint_bytes = 58 + byte_string_len(grant) + byte_string_len(local_certificate);
        let relay_bytes = 57 + byte_string_len(relay_certificate);
        if endpoint_bytes > HELLO_BYTES
            || relay_bytes > HELLO_BYTES
            || facts.limits.max_envelope_bytes < (endpoint_bytes.max(relay_bytes) + 8) as u64
            || facts.limits.max_total_bytes
                < (endpoint_bytes + relay_bytes + 16 + 2 * (PROOF_BYTES + 8)) as u64
        {
            return Err(ConnectError::Capacity);
        }
        admission.account.check()?;
        codec::encode_head(&mut self.hello, 5, 4);
        for field in [0, 1, 2, 4] {
            u(&mut self.hello, field);
            match field {
                0 => u(&mut self.hello, 0),
                1 => b(&mut self.hello, &self.carrier),
                2 => b(&mut self.hello, &self.challenge),
                4 => b(&mut self.hello, relay_certificate),
                _ => unreachable!(),
            }
        }
        decode(
            &self.hello,
            "HOP_AUTH_HELLO",
            HELLO_BYTES,
            Context::hop_relay(),
        )?;
        self.hello.clear();
        codec::encode_head(&mut self.hello, 5, 5);
        for field in 0..5 {
            u(&mut self.hello, field);
            match field {
                0 => u(&mut self.hello, 0),
                1 => b(&mut self.hello, &self.carrier),
                2 => b(&mut self.hello, &self.challenge),
                3 => b(&mut self.hello, grant),
                4 => b(&mut self.hello, local_certificate),
                _ => unreachable!(),
            }
        }
        decode(
            &self.hello,
            "HOP_AUTH_HELLO",
            HELLO_BYTES,
            Context::hop_endpoint(),
        )?;
        self.initiation_end = admission.initiation_not_after_ms;
        Ok(self)
    }
    fn check(&self, provider: &direct_carrier::Provider) -> ConnectResult<()> {
        let now = self.account.security_time()?;
        if now.upper_ms >= self.initiation_end {
            return Err(ConnectError::Authorization);
        }
        if provider.identity() != self.carrier {
            return Err(ConnectError::Configuration);
        }
        provider.check()
    }
    fn accept_hello(&mut self, wire: &[u8], facts: &VerifiedTunnelHop) -> ConnectResult<()> {
        let hello = decode(
            payload(wire, 16, HELLO_BYTES)?,
            "HOP_AUTH_HELLO",
            HELLO_BYTES,
            Context::hop_relay(),
        )?;
        let original = hello
            .field("HOP_AUTH_HELLO", "identity_certificate")?
            .bytes()?;
        let certificate = decode(original, "IdentityCertificate", 8192, Context::default())?;
        if codec::digest("certificate_digest", certificate)? != facts.relay_identity_digest
            || certificate.u("IdentityCertificate", "role")? != 2
            || certificate.b::<32>("IdentityCertificate", "ed25519_public_key")? != facts.relay_key
        {
            return Err(ConnectError::Authorization);
        }
        let remote_incarnation = hello.b::<16>("HOP_AUTH_HELLO", "local_incarnation")?;
        let remote_challenge = hello.b::<32>("HOP_AUTH_HELLO", "local_challenge")?;
        if remote_incarnation == [0; 16] || remote_challenge == [0; 32] {
            return Err(ConnectError::Protocol);
        }
        let dialer = facts.dialer_role == facts.endpoint_role;
        self.context.clear();
        codec::encode_head(&mut self.context, 5, 7);
        for field in 0..7 {
            u(&mut self.context, field);
            match field {
                0 => b(
                    &mut self.context,
                    if dialer {
                        &self.carrier
                    } else {
                        &remote_incarnation
                    },
                ),
                1 => b(
                    &mut self.context,
                    if dialer {
                        &remote_incarnation
                    } else {
                        &self.carrier
                    },
                ),
                2 => b(&mut self.context, &facts.leg_id),
                3 => u(&mut self.context, u64::from(facts.dialer_role)),
                4 => u(&mut self.context, u64::from(facts.listener_role)),
                5 => b(
                    &mut self.context,
                    if dialer {
                        &self.challenge
                    } else {
                        &remote_challenge
                    },
                ),
                6 => b(
                    &mut self.context,
                    if dialer {
                        &remote_challenge
                    } else {
                        &self.challenge
                    },
                ),
                _ => unreachable!(),
            }
        }
        if self.context.len() != CHALLENGE_BYTES {
            return Err(ConnectError::Protocol);
        }
        decode(
            &self.context,
            "HopChallengeContext",
            CHALLENGE_BYTES,
            Context::default(),
        )?;
        Ok(())
    }
    fn possession(&mut self, facts: &VerifiedTunnelHop, role: u8) -> ConnectResult<()> {
        if role != facts.endpoint_role && role != 2 || self.context.len() != CHALLENGE_BYTES {
            return Err(ConnectError::Protocol);
        }
        self.message.zeroize();
        self.message.clear();
        self.message
            .extend_from_slice(b"flowersec/v4/grant-possession\0");
        for part in [
            facts.grant_digest.as_slice(),
            facts.route_digest.as_slice(),
            facts.leg_id.as_slice(),
            facts.pairing_id.as_slice(),
            self.context.as_slice(),
        ] {
            self.message
                .extend_from_slice(&(part.len() as u32).to_be_bytes());
            self.message.extend_from_slice(part);
        }
        self.message.push(role);
        Ok(())
    }
    async fn execute(
        &mut self,
        admission: &mut CredentialAdmission,
        provider: &direct_carrier::Provider,
        incoming: &mut mpsc::Receiver<Vec<u8>>,
        keys: &IdentityKeys,
    ) -> ConnectResult<()> {
        if self.phase != 0 || !self.account.same_owner(&admission.account) {
            return Err(ConnectError::Configuration);
        }
        // Any cancellation or partial publication permanently consumes this
        // physical HOP owner. It has no reopen or retry transition.
        self.phase = 1;
        let facts = admission
            .tunnel
            .as_ref()
            .ok_or(ConnectError::Configuration)?;
        self.check(provider)?;
        if facts.dialer_role == facts.endpoint_role {
            provider.send(envelope(16, &self.hello)).await?;
            self.check(provider)?;
            let wire = provider.receive_prepared(incoming).await?;
            self.accept_hello(&wire, facts)?;
        } else {
            let wire = provider.receive_prepared(incoming).await?;
            self.accept_hello(&wire, facts)?;
            self.check(provider)?;
            provider.send(envelope(16, &self.hello)).await?;
        }
        self.check(provider)?;
        self.possession(facts, facts.endpoint_role)?;
        let proof = keys.inner.sign(&self.message)?;
        self.check(provider)?;
        let proof_wire = encode(2, |out| {
            u(out, 0);
            u(out, 1);
            u(out, 1);
            b(out, &proof);
        });
        decode(
            &proof_wire,
            "HOP_AUTH_ENDPOINT_PROOF",
            PROOF_BYTES,
            Context::default(),
        )?;
        provider.send(envelope(16, &proof_wire)).await?;
        self.check(provider)?;
        let reply = provider.receive_prepared(incoming).await?;
        let reply = decode(
            payload(&reply, 16, PROOF_BYTES)?,
            "HOP_AUTH_RELAY_PROOF",
            PROOF_BYTES,
            Context::default(),
        )?;
        self.possession(facts, 2)?;
        if !codec::strict_verify(
            &reply.b::<64>("HOP_AUTH_RELAY_PROOF", "proof")?,
            &self.message,
            &facts.relay_key,
        ) {
            return Err(ConnectError::Authorization);
        }
        self.check(provider)?;
        admission
            .tunnel
            .as_mut()
            .ok_or(ConnectError::Configuration)?
            .complete_possession(self.carrier)?;
        self.phase = 2;
        Ok(())
    }
    pub(super) async fn authenticate(
        &mut self,
        admission: &mut CredentialAdmission,
        provider: &direct_carrier::Provider,
        incoming: &mut mpsc::Receiver<Vec<u8>>,
        keys: &IdentityKeys,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> ConnectResult<()> {
        let native_cancellation = provider.cancellation();
        let result = tokio::select! {
            result = self.execute(admission, provider, incoming, keys) => result,
            _ = cancellation.cancelled() => Err(ConnectError::Canceled),
            _ = native_cancellation.cancelled() => Err(ConnectError::Carrier),
            _ = tokio::time::sleep_until(deadline) => Err(ConnectError::Deadline),
        };
        if result.is_err() {
            self.phase = 3;
            provider.close();
        }
        result
    }
}
