//! Relay possession is issued only by the original successful durable claim on
//! this physical maintenance owner. HELLO, namespace, parent selection, proof,
//! time and prepayment gates precede that irreversible operation.
use super::relay_publication::{RelayEndpoint, RelayParentRegistration};
use super::*;
use crate::pool_v4::relay::{OriginalRelayClaim, RelayPossession};
use tokio::sync::mpsc;

pub(super) struct RelayHop {
    account: ResourceAccount,
    carrier: [u8; 16],
    challenge: [u8; 32],
    relay: [u8; 16],
    invocation: [u8; 16],
    generation: u64,
    hello: Vec<u8>,
    context: Vec<u8>,
    message: Zeroizing<Vec<u8>>,
    phase: u8,
    initial_bytes: u64,
    claim_charge: Option<ResourceCharge>,
    _charge: ResourceCharge,
}
impl fmt::Debug for RelayHop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelayHop { <opaque> }")
    }
}
impl RelayHop {
    pub(super) fn new(
        registration: &RelayParentRegistration,
        role: u8,
        provider: &direct_carrier::Provider,
        keys: &IdentityKeys,
        relay: [u8; 16],
        generation: u64,
        mut charge: ResourceCharge,
    ) -> ConnectResult<Self> {
        let endpoint = registration
            .endpoints
            .get(role as usize)
            .ok_or(ConnectError::Configuration)?;
        let facts = &endpoint.hop;
        let account = registration.original.account(role)?;
        if !keys.belongs_to(account.environment_root())
            || keys.ed25519_public_key() != facts.relay_key
            || provider.identity() == [0; 16]
            || relay == [0; 16]
            || generation == 0
        {
            return Err(ConnectError::Configuration);
        }
        if !charge.matches(
            &account,
            ResourceLimits {
                sdk_bytes: 57344,
                items: 6,
                work_slots: 3,
                ..ResourceLimits::default()
            },
        ) {
            return Err(ConnectError::Configuration);
        }
        let claim_charge = charge.split(ResourceLimits {
            sdk_bytes: 8192,
            items: 2,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        provider.check()?;
        let mut challenge = [0; 32];
        let mut invocation = [0; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut challenge)
            .map_err(|_| ConnectError::Authorization)?;
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut invocation)
            .map_err(|_| ConnectError::Authorization)?;
        if challenge == [0; 32] || invocation == [0; 16] {
            return Err(ConnectError::Authorization);
        }
        let carrier = provider.identity();
        let hello = encode(4, |out| {
            u(out, 0);
            u(out, 0);
            u(out, 1);
            b(out, &carrier);
            u(out, 2);
            b(out, &challenge);
            u(out, 4);
            b(out, &registration.relay_certificate);
        });
        let original_endpoint = encode(5, |out| {
            u(out, 0);
            u(out, 0);
            u(out, 1);
            b(out, &carrier);
            u(out, 2);
            b(out, &challenge);
            u(out, 3);
            b(out, &endpoint.grant);
            u(out, 4);
            b(out, &endpoint.certificate);
        });
        decode(&hello, "HOP_AUTH_HELLO", 10346, Context::hop_relay())?;
        decode(
            &original_endpoint,
            "HOP_AUTH_HELLO",
            10346,
            Context::hop_endpoint(),
        )?;
        if facts.limits.max_envelope_bytes < (hello.len().max(original_endpoint.len()) + 8) as u64
            || facts.limits.max_total_bytes
                < (hello.len() + original_endpoint.len() + 16 + 156) as u64
        {
            return Err(ConnectError::Capacity);
        }
        let mut context = Vec::new();
        context
            .try_reserve_exact(129)
            .map_err(|_| ConnectError::Capacity)?;
        let mut message = Zeroizing::new(Vec::new());
        message
            .try_reserve_exact(512)
            .map_err(|_| ConnectError::Capacity)?;
        Ok(Self {
            account,
            carrier,
            challenge,
            relay,
            invocation,
            generation,
            hello,
            context,
            message,
            phase: 0,
            initial_bytes: 0,
            claim_charge: Some(claim_charge),
            _charge: charge,
        })
    }
    fn check(
        &self,
        registration: &RelayParentRegistration,
        provider: &direct_carrier::Provider,
    ) -> ConnectResult<()> {
        registration.original.check()?;
        self.account.check()?;
        if provider.identity() != self.carrier {
            return Err(ConnectError::Configuration);
        }
        provider.check()
    }
    fn accept_hello(&mut self, endpoint: &RelayEndpoint, wire: &[u8]) -> ConnectResult<()> {
        self.initial_bytes = self
            .initial_bytes
            .checked_add(wire.len() as u64)
            .ok_or(ConnectError::Capacity)?;
        let hello = decode(
            payload(wire, 16, 10346)?,
            "HOP_AUTH_HELLO",
            10346,
            Context::hop_endpoint(),
        )?;
        if hello.field("HOP_AUTH_HELLO", "grant")?.bytes()? != endpoint.grant
            || hello
                .field("HOP_AUTH_HELLO", "identity_certificate")?
                .bytes()?
                != endpoint.certificate
        {
            return Err(ConnectError::Authorization);
        }
        let remote = hello.b::<16>("HOP_AUTH_HELLO", "local_incarnation")?;
        let challenge = hello.b::<32>("HOP_AUTH_HELLO", "local_challenge")?;
        if remote == [0; 16] || challenge == [0; 32] {
            return Err(ConnectError::Protocol);
        }
        let facts = &endpoint.hop;
        let local_dialer = facts.dialer_role == 2;
        self.context.clear();
        codec::encode_head(&mut self.context, 5, 7);
        for field in 0..7 {
            u(&mut self.context, field);
            match field {
                0 => b(
                    &mut self.context,
                    if local_dialer { &self.carrier } else { &remote },
                ),
                1 => b(
                    &mut self.context,
                    if local_dialer { &remote } else { &self.carrier },
                ),
                2 => b(&mut self.context, &facts.leg_id),
                3 => u(&mut self.context, facts.dialer_role as u64),
                4 => u(&mut self.context, facts.listener_role as u64),
                5 => b(
                    &mut self.context,
                    if local_dialer {
                        &self.challenge
                    } else {
                        &challenge
                    },
                ),
                6 => b(
                    &mut self.context,
                    if local_dialer {
                        &challenge
                    } else {
                        &self.challenge
                    },
                ),
                _ => unreachable!(),
            }
        }
        if self.context.len() != 129 {
            return Err(ConnectError::Protocol);
        }
        decode(
            &self.context,
            "HopChallengeContext",
            129,
            Context::default(),
        )?;
        Ok(())
    }
    fn possession(&mut self, endpoint: &RelayEndpoint, role: u8) -> ConnectResult<()> {
        if self.context.len() != 129 || role != 2 && role != endpoint.hop.endpoint_role {
            return Err(ConnectError::Protocol);
        }
        let facts = &endpoint.hop;
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
    #[expect(
        clippy::too_many_arguments,
        reason = "HOP authentication binds the original registration, endpoint, keys and carrier under one caller deadline."
    )]
    async fn execute(
        &mut self,
        registration: &RelayParentRegistration,
        endpoint: &RelayEndpoint,
        provider: &direct_carrier::Provider,
        incoming: &mut mpsc::Receiver<Vec<u8>>,
        keys: &IdentityKeys,
        deadline: Instant,
        caller: &CancellationToken,
        first_hello: Option<Vec<u8>>,
    ) -> ConnectResult<OriginalRelayClaim> {
        if self.phase != 0 {
            return Err(ConnectError::Configuration);
        }
        self.phase = 1;
        self.check(registration, provider)?;
        self.initial_bytes = self.hello.len() as u64 + 8;
        if endpoint.hop.dialer_role == 2 {
            if first_hello.is_some() {
                return Err(ConnectError::Configuration);
            }
            provider.send(envelope(16, &self.hello)).await?;
            let wire = provider.receive_prepared(incoming).await?;
            self.accept_hello(endpoint, &wire)?;
        } else {
            let wire = match first_hello {
                Some(wire) => wire,
                None => provider.receive_prepared(incoming).await?,
            };
            self.accept_hello(endpoint, &wire)?;
            self.check(registration, provider)?;
            provider.send(envelope(16, &self.hello)).await?;
        }
        self.check(registration, provider)?;
        let wire = provider.receive_prepared(incoming).await?;
        self.initial_bytes = self
            .initial_bytes
            .checked_add(wire.len() as u64)
            .ok_or(ConnectError::Capacity)?;
        let proof = decode(
            payload(&wire, 16, 70)?,
            "HOP_AUTH_ENDPOINT_PROOF",
            70,
            Context::default(),
        )?;
        let proof = proof.b::<64>("HOP_AUTH_ENDPOINT_PROOF", "proof")?;
        self.possession(endpoint, endpoint.hop.endpoint_role)?;
        if !codec::strict_verify(&proof, &self.message, &endpoint.hop.endpoint_key) {
            return Err(ConnectError::Authorization);
        }
        self.check(registration, provider)?;
        let mut evidence = Vec::with_capacity(512);
        codec::encode_head(&mut evidence, 4, 4);
        b(&mut evidence, &endpoint.hop.grant_digest);
        b(&mut evidence, &endpoint.hop.route_digest);
        b(&mut evidence, &self.context);
        b(&mut evidence, &proof);
        if caller.is_cancelled() || provider.cancellation().is_cancelled() {
            return Err(ConnectError::Canceled);
        }
        // The original native guard is retained through the synchronous COMMIT
        // continuation. Cancellation after it never restores this leg slot.
        let original = registration.original.claim_original(RelayPossession {
            role: endpoint.hop.endpoint_role,
            relay: self.relay,
            invocation: self.invocation,
            carrier: self.carrier,
            generation: self.generation,
            evidence,
            deadline,
            cancellation: provider.cancellation(),
            prepaid: self.claim_charge.take(),
        })?;
        self.check(registration, provider)?;
        original.check()?;
        if caller.is_cancelled() {
            return Err(ConnectError::Canceled);
        }
        if Instant::now() >= deadline {
            return Err(ConnectError::Deadline);
        }
        self.possession(endpoint, 2)?;
        let proof = keys.inner.sign(&self.message)?;
        self.check(registration, provider)?;
        original.check()?;
        let reply = encode(2, |out| {
            u(out, 0);
            u(out, 2);
            u(out, 1);
            b(out, &proof);
        });
        decode(&reply, "HOP_AUTH_RELAY_PROOF", 70, Context::default())?;
        self.initial_bytes = self
            .initial_bytes
            .checked_add(reply.len() as u64 + 8)
            .ok_or(ConnectError::Capacity)?;
        if self.initial_bytes > endpoint.hop.limits.max_total_bytes {
            return Err(ConnectError::Capacity);
        }
        provider.send(envelope(16, &reply)).await?;
        self.check(registration, provider)?;
        original.check()?;
        self.phase = 2;
        Ok(original)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "HOP authentication binds the original registration, endpoint, keys and carrier under one caller deadline."
    )]
    pub(super) async fn authenticate(
        &mut self,
        registration: &RelayParentRegistration,
        role: u8,
        provider: &direct_carrier::Provider,
        incoming: &mut mpsc::Receiver<Vec<u8>>,
        keys: &IdentityKeys,
        deadline: Instant,
        cancellation: &CancellationToken,
        first_hello: Option<Vec<u8>>,
    ) -> ConnectResult<OriginalRelayClaim> {
        let endpoint = registration
            .endpoints
            .get(role as usize)
            .ok_or(ConnectError::Configuration)?;
        let native = provider.cancellation();
        let result = tokio::select! {
            result = self.execute(registration, endpoint, provider, incoming, keys, deadline, cancellation, first_hello) => result,
            _ = native.cancelled() => Err(ConnectError::Carrier), _ = cancellation.cancelled() => Err(ConnectError::Canceled),
            _ = tokio::time::sleep_until(deadline) => Err(ConnectError::Deadline),
        };
        if result.is_err() {
            self.phase = 3;
            provider.close();
        }
        result
    }
}
