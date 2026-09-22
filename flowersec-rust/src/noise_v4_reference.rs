//! Fixed-material Noise library reference. Not linked into the production SDK.
//!
//! The caller supplies public test fixtures, not authenticated admission facts.
//! No entropy, runtime owner, deadline, READY or provider qualification is implied.
use hkdf::Hkdf;
use serde::Deserialize;
use sha2::Sha256;
use snow::{
    Builder, Error, HandshakeState,
    params::{CipherChoice, DHChoice, HashChoice, NoiseParams},
    resolvers::{CryptoResolver, RingResolver},
    types::{Cipher, Dh, Hash, Random},
};
use zeroize::Zeroizing;

use super::{dh, registry};

pub(crate) const FAILURE: &str = "noise_reference_failed";

#[derive(Clone, Deserialize)]
pub(crate) struct Profile {
    pub(crate) noise_protocol_name: String,
    pub(crate) dh_public_bytes: usize,
    pub(crate) dh_secret_bytes: usize,
    pub(crate) handshake_message_bytes: usize,
}

pub(crate) fn profile(name: &str) -> Result<Profile, &'static str> {
    let profiles: std::collections::BTreeMap<String, Profile> =
        serde_json::from_str(registry::CRYPTO_PROFILES_JSON).map_err(|_| FAILURE)?;
    profiles.get(name).cloned().ok_or(FAILURE)
}

struct FixedOnlyRandom;

impl Random for FixedOnlyRandom {
    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Error> {
        Err(Error::Rng)
    }
}

struct ProfileDh {
    profile: &'static str,
    name: &'static str,
    public_bytes: usize,
    private: Option<Zeroizing<Vec<u8>>>,
    public: Vec<u8>,
}

impl Dh for ProfileDh {
    fn name(&self) -> &'static str {
        self.name
    }
    fn pub_len(&self) -> usize {
        self.public_bytes
    }
    fn priv_len(&self) -> usize {
        registry::DH_PRIVATE_BYTES
    }
    fn dh_len(&self) -> usize {
        registry::DH_SECRET_BYTES
    }
    fn set(&mut self, private: &[u8]) {
        // Snow's setter has no Result. Reject material before Builder is called;
        // retain no usable key if an unexpected invalid setter call occurs.
        self.private = None;
        self.public.clear();
        if let Ok(public) = dh::public(self.profile, private) {
            self.public = public;
            self.private = Some(Zeroizing::new(private.to_vec()));
        }
    }
    fn generate(&mut self, _rng: &mut dyn Random) -> Result<(), Error> {
        Err(Error::Rng)
    }
    fn pubkey(&self) -> &[u8] {
        &self.public
    }
    fn privkey(&self) -> &[u8] {
        self.private
            .as_deref()
            .map_or(&[], |bytes| bytes.as_slice())
    }
    fn dh(&self, public: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let private = self.private.as_ref().ok_or(Error::Dh)?;
        // Snow passes its fixed MAXDHLEN backing array, even for X25519.
        // The outer constructor/message parser has already checked wire
        // length. Select the declared public field, never shorten a wire key.
        let public_field = public.get(..self.public_bytes).ok_or(Error::Dh)?;
        if public[self.public_bytes..].iter().any(|byte| *byte != 0) {
            return Err(Error::Dh);
        }
        // Every real es/ss/ee/se call passes the profile's zero-result gate
        // before Snow can MixKey. Original peer bytes remain in Snow's hash.
        let result =
            Zeroizing::new(dh::derive(self.profile, private, public_field).map_err(|_| Error::Dh)?);
        out.get_mut(..registry::DH_SECRET_BYTES)
            .ok_or(Error::Dh)?
            .copy_from_slice(&result);
        Ok(())
    }
}

struct Resolver;

impl CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(FixedOnlyRandom))
    }
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        let (profile, name, public_bytes) = match choice {
            DHChoice::Curve25519 => (
                registry::DH_PROFILE_X25519,
                "25519",
                registry::DH_X25519_PUBLIC_BYTES,
            ),
            DHChoice::P256 => (
                registry::DH_PROFILE_P256,
                "P256",
                registry::DH_P256_PUBLIC_BYTES,
            ),
            _ => return None,
        };
        Some(Box::new(ProfileDh {
            profile,
            name,
            public_bytes,
            private: None,
            public: Vec::new(),
        }))
    }
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        match choice {
            HashChoice::SHA256 => RingResolver.resolve_hash(choice),
            _ => None,
        }
    }
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        RingResolver.resolve_cipher(choice)
    }
}

pub(crate) struct FixedInput<'a> {
    pub(crate) profile: &'a str,
    pub(crate) initiator: bool,
    pub(crate) local_private: &'a [u8],
    pub(crate) local_public: &'a [u8],
    pub(crate) remote_public: &'a [u8],
    pub(crate) ephemeral_private: &'a [u8],
    pub(crate) psk: &'a [u8],
    pub(crate) prologue: &'a [u8],
    pub(crate) context_digest: [u8; 32],
}

pub(crate) struct FixedHandshake {
    state: Option<HandshakeState>,
    profile_name: String,
    spec: Profile,
    context_digest: [u8; 32],
    written: bool,
    read: bool,
}

pub(crate) struct Finished {
    pub(crate) handshake_hash: [u8; 32],
    root: Zeroizing<[u8; 32]>,
}

impl FixedHandshake {
    pub(crate) fn new(input: FixedInput<'_>) -> Result<Self, &'static str> {
        let spec = profile(input.profile)?;
        let actual_public = dh::public(input.profile, input.local_private).map_err(|_| FAILURE)?;
        dh::public(input.profile, input.ephemeral_private).map_err(|_| FAILURE)?;
        if actual_public != input.local_public
            || input.remote_public.len() != spec.dh_public_bytes
            || input.psk.len() != registry::DH_SECRET_BYTES
            || spec.dh_secret_bytes != registry::DH_SECRET_BYTES
        {
            return Err(FAILURE);
        }
        if input.profile == registry::DH_PROFILE_P256 {
            // Form validation without inventing a dummy DH or rejecting valid
            // zero-x points. Zero shared results fail at the actual DH call.
            if input.remote_public[0] != 4
                || p256::PublicKey::from_sec1_bytes(input.remote_public).is_err()
            {
                return Err(FAILURE);
            }
        }
        let params: NoiseParams = spec.noise_protocol_name.parse().map_err(|_| FAILURE)?;
        let builder = Builder::with_resolver(params, Box::new(Resolver))
            .local_private_key(input.local_private)
            .map_err(|_| FAILURE)?
            .remote_public_key(input.remote_public)
            .map_err(|_| FAILURE)?
            .fixed_ephemeral_key_for_testing_only(input.ephemeral_private)
            .prologue(input.prologue)
            .map_err(|_| FAILURE)?
            .psk(0, input.psk.try_into().map_err(|_| FAILURE)?)
            .map_err(|_| FAILURE)?;
        let state = if input.initiator {
            builder.build_initiator()
        } else {
            builder.build_responder()
        }
        .map_err(|_| FAILURE)?;
        Ok(Self {
            state: Some(state),
            profile_name: input.profile.to_owned(),
            spec,
            context_digest: input.context_digest,
            written: false,
            read: false,
        })
    }

    pub(crate) fn write(&mut self) -> Result<Vec<u8>, &'static str> {
        // Take before any fallible operation: errors permanently consume this
        // reference attempt, even though Snow can restore symmetric state.
        let mut state = self.state.take().ok_or(FAILURE)?;
        if self.written || !state.is_my_turn() || state.is_handshake_finished() {
            return Err(FAILURE);
        }
        let mut message = vec![0; self.spec.handshake_message_bytes];
        let length = state
            .write_message(&[], &mut message)
            .map_err(|_| FAILURE)?;
        if length != message.len() {
            return Err(FAILURE);
        }
        self.written = true;
        self.state = Some(state);
        Ok(message)
    }

    pub(crate) fn read(&mut self, message: &[u8]) -> Result<(), &'static str> {
        let mut state = self.state.take().ok_or(FAILURE)?;
        if self.read || state.is_my_turn() || message.len() != self.spec.handshake_message_bytes {
            return Err(FAILURE);
        }
        if state.read_message(message, &mut []).map_err(|_| FAILURE)? != 0 {
            return Err(FAILURE);
        }
        self.read = true;
        self.state = Some(state);
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<Finished, &'static str> {
        let mut state = self.state.take().ok_or(FAILURE)?;
        if !self.written || !self.read || !state.is_handshake_finished() {
            return Err(FAILURE);
        }
        let handshake_hash: [u8; 32] =
            state.get_handshake_hash().try_into().map_err(|_| FAILURE)?;
        // Always the first canonical i2r output, including for the responder.
        // Neither Split output enters a Noise transport cipher operation.
        let (i2r, r2i) = state.dangerously_get_raw_split();
        let i2r = Zeroizing::new(i2r);
        let _r2i = Zeroizing::new(r2i);
        let root = initial_root(
            &self.profile_name,
            &handshake_hash,
            &self.context_digest,
            &i2r,
        )?;
        Ok(Finished {
            handshake_hash,
            root,
        })
    }
}

// Independent encoder for this generated domain's LP fields. It deliberately
// accepts only initial_root, not arbitrary maps or caller-selected KDF domains.
fn initial_root_info(
    profile_name: &str,
    hash: &[u8; 32],
    context: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    profile(profile_name)?;
    let domains: Vec<serde_json::Value> =
        serde_json::from_str(registry::DOMAIN_REGISTRY_JSON).map_err(|_| FAILURE)?;
    let domain = domains
        .iter()
        .find(|d| d["name"] == "initial_root")
        .ok_or(FAILURE)?;
    let mut info = decode_hex(domain["label_bytes"].as_str().ok_or(FAILURE)?)?;
    for part in domain["input_schema"]["parts"].as_array().ok_or(FAILURE)? {
        let value: &[u8] = match (part["name"].as_str(), part["encoding"].as_str()) {
            (Some("profile"), Some("lp-ascii")) => profile_name.as_bytes(),
            (Some("handshake_hash"), Some("lp-bytes")) => hash,
            (Some("context_digest"), Some("lp-bytes")) => context,
            _ => return Err(FAILURE),
        };
        info.extend_from_slice(
            &u32::try_from(value.len())
                .map_err(|_| FAILURE)?
                .to_be_bytes(),
        );
        info.extend_from_slice(value);
    }
    Ok(info)
}

fn initial_root(
    profile: &str,
    hash: &[u8; 32],
    context: &[u8; 32],
    i2r: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let info = initial_root_info(profile, hash, context)?;
    let mut root = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::from_prk(i2r)
        .map_err(|_| FAILURE)?
        .expand(&info, root.as_mut())
        .map_err(|_| FAILURE)?;
    Ok(root)
}

pub(crate) fn decode_hex(value: &str) -> Result<Vec<u8>, &'static str> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(FAILURE);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| FAILURE)?, 16)
                .map_err(|_| FAILURE)
        })
        .collect()
}

#[cfg(test)]
impl Finished {
    pub(crate) fn same_root(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.root.as_ref().ct_eq(other.root.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared_corpus() -> serde_json::Value {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/transport_v4/noise.json"
        ))
        .unwrap();
        let corpus: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(corpus["schema_sha256"], registry::SCHEMA_SHA256);
        assert_eq!(corpus["transcripts"].as_array().unwrap().len(), 2);
        corpus
    }

    fn fixture_bytes(object: &serde_json::Value, name: &str) -> Vec<u8> {
        decode_hex(object[name].as_str().unwrap()).unwrap()
    }

    fn shared_state(
        corpus: &serde_json::Value,
        transcript: &serde_json::Value,
        initiator: bool,
    ) -> FixedHandshake {
        let input = &corpus["inputs"];
        let (local, peer) = if initiator {
            ("client", "server")
        } else {
            ("server", "client")
        };
        let name = transcript["profile"].as_str().unwrap();
        let private = fixture_bytes(input, &format!("{local}_static_private_hex"));
        let public = dh::public(name, &private).unwrap();
        let remote = dh::public(
            name,
            &fixture_bytes(input, &format!("{peer}_static_private_hex")),
        )
        .unwrap();
        FixedHandshake::new(FixedInput {
            profile: name,
            initiator,
            local_private: &private,
            local_public: &public,
            remote_public: &remote,
            ephemeral_private: &fixture_bytes(input, &format!("{local}_ephemeral_private_hex")),
            psk: &fixture_bytes(input, "psk_hex"),
            prologue: &fixture_bytes(input, "prologue_hex"),
            context_digest: fixture_bytes(input, "context_digest_hex")
                .try_into()
                .unwrap(),
        })
        .unwrap()
    }

    #[test]
    fn shared_captured_transcripts_and_canonical_splits() {
        let corpus = shared_corpus();
        let mut covered = std::collections::BTreeSet::new();
        for transcript in corpus["transcripts"].as_array().unwrap() {
            covered.insert(transcript["profile"].as_str().unwrap());
            for initiator in [true, false] {
                let mut state = shared_state(&corpus, transcript, initiator);
                if !initiator {
                    state
                        .read(&fixture_bytes(transcript, "message1_hex"))
                        .unwrap();
                }
                assert_eq!(
                    state.write().unwrap(),
                    fixture_bytes(
                        transcript,
                        if initiator {
                            "message1_hex"
                        } else {
                            "message2_hex"
                        }
                    )
                );
                if initiator {
                    state
                        .read(&fixture_bytes(transcript, "message2_hex"))
                        .unwrap();
                }
                // Fixture comparison only. This additional library Split is
                // test work, not another protocol completion or root export.
                let (i2r, r2i) = state.state.as_mut().unwrap().dangerously_get_raw_split();
                let i2r = Zeroizing::new(i2r);
                let r2i = Zeroizing::new(r2i);
                assert_eq!(i2r.as_slice(), fixture_bytes(transcript, "split_i2r_hex"));
                assert_eq!(r2i.as_slice(), fixture_bytes(transcript, "split_r2i_hex"));
                let finished = state.finish().unwrap();
                assert_eq!(
                    finished.handshake_hash.as_slice(),
                    fixture_bytes(transcript, "handshake_hash_hex")
                );
                assert_eq!(
                    finished.root.as_slice(),
                    fixture_bytes(transcript, "initial_root_hex")
                );
                assert_eq!(
                    initial_root_info(
                        transcript["profile"].as_str().unwrap(),
                        &finished.handshake_hash,
                        &fixture_bytes(&corpus["inputs"], "context_digest_hex")
                            .try_into()
                            .unwrap()
                    )
                    .unwrap(),
                    fixture_bytes(transcript, "initial_root_info_hex")
                );
                assert!(state.finish().is_err());
                assert!(state.write().is_err());
                assert!(state.read(&[]).is_err());
            }
        }
        assert_eq!(
            covered,
            std::collections::BTreeSet::from([
                registry::DH_PROFILE_X25519,
                registry::DH_PROFILE_P256
            ])
        );
    }

    #[test]
    fn shared_message_negatives_consume_attempt() {
        let corpus = shared_corpus();
        let mut count = 0;
        for transcript in corpus["transcripts"].as_array().unwrap() {
            let negatives: Vec<_> = corpus["negatives"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|v| v["transcript"] == transcript["id"])
                .collect();
            assert_eq!(
                negatives.len(),
                4 * profile(transcript["profile"].as_str().unwrap())
                    .unwrap()
                    .handshake_message_bytes
                    + 4
            );
            for negative in negatives {
                count += 1;
                assert_eq!(negative["expected_error"], FAILURE);
                let flight = negative["flight"].as_u64().unwrap();
                assert!(flight == 1 || flight == 2);
                let mut state = shared_state(&corpus, transcript, flight == 2);
                if flight == 2 {
                    state.write().unwrap();
                }
                assert_eq!(
                    state.read(&fixture_bytes(negative, "message_hex")),
                    Err(FAILURE),
                    "{}",
                    negative["id"]
                );
                assert!(state.finish().is_err());
                assert!(state.write().is_err());
                assert!(state.read(&[]).is_err());
            }
        }
        assert_eq!(count, corpus["negatives"].as_array().unwrap().len());
    }

    // An adversarial fixture emitter changes only the exposed public bytes.
    // The actual DH scalar and all Noise token/hash/AEAD operations stay in
    // their library implementations. Production local generation stays canonical.
    struct AliasDh {
        inner: Box<dyn Dh>,
        public: Vec<u8>,
        static_alias: bool,
        ephemeral_alias: bool,
    }

    impl Dh for AliasDh {
        fn name(&self) -> &'static str {
            self.inner.name()
        }
        fn pub_len(&self) -> usize {
            self.inner.pub_len()
        }
        fn priv_len(&self) -> usize {
            self.inner.priv_len()
        }
        fn dh_len(&self) -> usize {
            self.inner.dh_len()
        }
        fn set(&mut self, private: &[u8]) {
            self.inner.set(private);
            self.public = self.inner.pubkey().to_vec();
            if (self.static_alias && private == [0x11; 32])
                || (self.ephemeral_alias && private == [0x33; 32])
            {
                self.public[31] |= 0x80;
            }
        }
        fn generate(&mut self, rng: &mut dyn Random) -> Result<(), Error> {
            self.inner.generate(rng)
        }
        fn pubkey(&self) -> &[u8] {
            &self.public
        }
        fn privkey(&self) -> &[u8] {
            self.inner.privkey()
        }
        fn dh(&self, peer: &[u8], out: &mut [u8]) -> Result<(), Error> {
            self.inner.dh(peer, out)
        }
    }

    struct AliasResolver {
        static_alias: bool,
        ephemeral_alias: bool,
    }

    impl CryptoResolver for AliasResolver {
        fn resolve_rng(&self) -> Option<Box<dyn Random>> {
            Resolver.resolve_rng()
        }
        fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
            if *choice != DHChoice::Curve25519 {
                return None;
            }
            Some(Box::new(AliasDh {
                inner: Resolver.resolve_dh(choice)?,
                public: Vec::new(),
                static_alias: self.static_alias,
                ephemeral_alias: self.ephemeral_alias,
            }))
        }
        fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
            Resolver.resolve_hash(choice)
        }
        fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
            Resolver.resolve_cipher(choice)
        }
    }

    #[test]
    fn original_x25519_aliases_complete_with_different_transcripts() {
        let name = registry::DH_PROFILE_X25519;
        let prologue = b"public original-byte Noise fixture";
        let context = [0x66; 32];
        let mut final_hashes = std::collections::BTreeSet::new();
        for peer_initiator in [true, false] {
            for static_alias in [false, true] {
                for ephemeral_alias in [false, true] {
                    let mut peer_public = dh::public(name, &[0x11; 32]).unwrap();
                    if static_alias {
                        peer_public[31] |= 0x80;
                    }
                    let local_public = dh::public(name, &[0x22; 32]).unwrap();
                    let mut local = FixedHandshake::new(FixedInput {
                        profile: name,
                        initiator: !peer_initiator,
                        local_private: &[0x22; 32],
                        local_public: &local_public,
                        remote_public: &peer_public,
                        ephemeral_private: &[0x44; 32],
                        psk: &[0x55; 32],
                        prologue,
                        context_digest: context,
                    })
                    .unwrap();
                    let builder = Builder::with_resolver(
                        profile(name).unwrap().noise_protocol_name.parse().unwrap(),
                        Box::new(AliasResolver {
                            static_alias,
                            ephemeral_alias,
                        }),
                    )
                    .local_private_key(&[0x11; 32])
                    .unwrap()
                    .remote_public_key(&local_public)
                    .unwrap()
                    .fixed_ephemeral_key_for_testing_only(&[0x33; 32])
                    .prologue(prologue)
                    .unwrap()
                    .psk(0, &[0x55; 32])
                    .unwrap();
                    let mut peer = if peer_initiator {
                        builder.build_initiator()
                    } else {
                        builder.build_responder()
                    }
                    .unwrap();
                    let mut message = vec![0; profile(name).unwrap().handshake_message_bytes];
                    if peer_initiator {
                        let len = peer.write_message(&[], &mut message).unwrap();
                        assert_eq!(len, message.len());
                        assert_eq!(message[31] & 0x80 != 0, ephemeral_alias);
                        local.read(&message).unwrap();
                        assert_eq!(peer.read_message(&local.write().unwrap(), &mut []), Ok(0));
                    } else {
                        assert_eq!(peer.read_message(&local.write().unwrap(), &mut []), Ok(0));
                        let len = peer.write_message(&[], &mut message).unwrap();
                        assert_eq!(len, message.len());
                        assert_eq!(message[31] & 0x80 != 0, ephemeral_alias);
                        local.read(&message).unwrap();
                    }
                    assert!(peer.is_handshake_finished());
                    let finished = local.finish().unwrap();
                    assert_eq!(peer.get_handshake_hash(), finished.handshake_hash);
                    let (i2r, r2i) = peer.dangerously_get_raw_split();
                    let i2r = Zeroizing::new(i2r);
                    let _r2i = Zeroizing::new(r2i);
                    let peer_root =
                        initial_root(name, &finished.handshake_hash, &context, &i2r).unwrap();
                    assert_eq!(peer_root.as_ref(), finished.root.as_ref());
                    // Equal numerical DH results do not collapse different
                    // original static/e encodings into one transcript.
                    assert!(final_hashes.insert(finished.handshake_hash));
                }
            }
        }
        assert_eq!(final_hashes.len(), 8);
    }

    #[test]
    fn every_kk_dh_token_stops_before_mix_key_on_zero_result() {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../../testdata/transport_v4/profile_dh.json"))
                .unwrap();
        let vector = corpus["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == "dh_p_zero_result")
            .unwrap();
        let zero_x = decode_hex(vector["public_hex"].as_str().unwrap()).unwrap();
        let one = decode_hex(vector["private_hex"].as_str().unwrap()).unwrap();
        let mut two = one.clone();
        two[31] = 2;
        assert!(dh::derive(registry::DH_PROFILE_P256, &one, &zero_x).is_err());
        assert!(dh::derive(registry::DH_PROFILE_P256, &two, &zero_x).is_ok());
        let normal_peer = dh::public(registry::DH_PROFILE_P256, &[0x22; 32]).unwrap();
        for token in ["es", "ss", "ee", "se"] {
            // The invalid result is deliberately placed at this token. Every
            // earlier DH with the valid zero-x point uses scalar 2 and succeeds.
            let static_key = if ["ss", "se"].contains(&token) {
                &one
            } else {
                &two
            };
            let ephemeral_key = if ["es", "ee"].contains(&token) {
                &one
            } else {
                &two
            };
            let public = dh::public(registry::DH_PROFILE_P256, static_key).unwrap();
            let mut attempt = FixedHandshake::new(FixedInput {
                profile: registry::DH_PROFILE_P256,
                initiator: true,
                local_private: static_key,
                local_public: &public,
                remote_public: if ["es", "ss"].contains(&token) {
                    &zero_x
                } else {
                    &normal_peer
                },
                ephemeral_private: ephemeral_key,
                psk: &[0x55; 32],
                prologue: b"public zero-result token fixture",
                context_digest: [0x66; 32],
            })
            .unwrap();
            if ["es", "ss"].contains(&token) {
                let mut state = attempt.state.take().unwrap();
                assert_eq!(
                    state.write_message(&[], &mut vec![0; attempt.spec.handshake_message_bytes]),
                    Err(Error::Dh),
                    "{token}"
                );
            } else {
                attempt.write().unwrap();
                let mut message = zero_x.clone();
                message.resize(attempt.spec.handshake_message_bytes, 0);
                let mut state = attempt.state.take().unwrap();
                assert_eq!(
                    state.read_message(&message, &mut []),
                    Err(Error::Dh),
                    "{token}"
                );
            }
            assert!(attempt.finish().is_err());
        }
    }

    #[test]
    fn internal_public_backing_preserves_the_declared_field() {
        let mut adapter = Resolver.resolve_dh(&DHChoice::Curve25519).unwrap();
        adapter.set(&[0x11; 32]);
        let peer = dh::public(registry::DH_PROFILE_X25519, &[0x22; 32]).unwrap();
        let mut backing = vec![0; registry::DH_P256_PUBLIC_BYTES];
        backing[..peer.len()].copy_from_slice(&peer);
        let mut result = [0x77; 65];
        adapter.dh(&backing, &mut result).unwrap();
        assert_eq!(
            &result[..32],
            dh::derive(registry::DH_PROFILE_X25519, &[0x11; 32], &peer).unwrap()
        );
        assert!(result[32..].iter().all(|b| *b == 0x77));
        // Corrupted private backing and short buffers fail without publishing
        // a result. This is distinct from accepting malformed wire lengths.
        backing[32] = 1;
        let mut untouched = [0x77; 65];
        assert_eq!(adapter.dh(&backing, &mut untouched), Err(Error::Dh));
        assert_eq!(untouched, [0x77; 65]);
        assert_eq!(adapter.dh(&peer[..31], &mut untouched), Err(Error::Dh));
        assert_eq!(adapter.dh(&peer, &mut untouched[..31]), Err(Error::Dh));
        adapter.set(&[0; 31]);
        assert_eq!(adapter.dh(&peer, &mut untouched), Err(Error::Dh));
        assert_eq!(adapter.generate(&mut FixedOnlyRandom), Err(Error::Rng));
        assert_eq!(
            FixedOnlyRandom.try_fill_bytes(&mut [0; 32]),
            Err(Error::Rng)
        );
    }

    #[test]
    fn generated_initial_root_domains() {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../../testdata/transport_v4/domains.json")).unwrap();
        assert_eq!(corpus["schema_sha256"], registry::SCHEMA_SHA256);
        let mut count = 0;
        for v in corpus["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["domain"] == "initial_root" && v.get("result").is_some())
        {
            let args = &v["inputs"];
            let bytes = |name: &str| -> [u8; 32] {
                decode_hex(args[name]["$bytes"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap()
            };
            let name = args["profile"].as_str().unwrap();
            let info = initial_root_info(name, &bytes("handshake_hash"), &bytes("context_digest"))
                .unwrap();
            assert_eq!(
                info,
                decode_hex(v["result"]["input_hex"].as_str().unwrap()).unwrap()
            );
            let root = initial_root(
                name,
                &bytes("handshake_hash"),
                &bytes("context_digest"),
                &bytes("split_i2r"),
            )
            .unwrap();
            assert_eq!(
                root.as_slice(),
                decode_hex(v["result"]["output_hex"].as_str().unwrap()).unwrap()
            );
            count += 1;
        }
        assert_eq!(count, 2);
    }
}
