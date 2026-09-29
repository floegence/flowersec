//! Purpose-limited software keys and the production Snow DH adapter.
use super::{CryptoError, Profile, Result};
use crate::codec_v4;
use p256::elliptic_curve::sec1::ToSec1Point;
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use snow::{
    params::{CipherChoice, DHChoice, HashChoice},
    resolvers::{CryptoResolver, RingResolver},
    types::{Cipher, Dh, Hash, Random},
};
use std::{fmt, sync::Arc};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(super) struct SoftwareDh {
    profile: Profile,
    private: Zeroizing<[u8; 32]>,
    public: [u8; 65],
}
impl SoftwareDh {
    pub(super) fn ephemeral(profile: Profile) -> Result<Self> {
        Self::generate(profile, &mut Entropy)
    }
    #[cfg(test)]
    pub(super) fn fixture(profile: Profile, private: [u8; 32]) -> Result<Self> {
        Self::from_material(profile, Zeroizing::new(private))
    }
    fn from_material(profile: Profile, private: Zeroizing<[u8; 32]>) -> Result<Self> {
        let mut public = [0; 65];
        match profile {
            Profile::X25519 => public[..32].copy_from_slice(
                x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*private))
                    .as_bytes(),
            ),
            Profile::P256 => public.copy_from_slice(
                p256::SecretKey::from_slice(private.as_ref())
                    .map_err(|_| CryptoError::Key)?
                    .public_key()
                    .to_sec1_point(false)
                    .as_bytes(),
            ),
        }
        Ok(Self {
            profile,
            private,
            public,
        })
    }
    fn generate(profile: Profile, random: &mut dyn Random) -> Result<Self> {
        // Bounded rejection sampling for the exact P-256 scalar domain. No
        // modulo reduction, fixed ephemeral, key pool, or entropy fallback.
        for _ in 0..128 {
            let mut private = Zeroizing::new([0; 32]);
            random
                .try_fill_bytes(private.as_mut())
                .map_err(|_| CryptoError::Key)?;
            if let Ok(key) = Self::from_material(profile, private) {
                return Ok(key);
            }
        }
        Err(CryptoError::Key)
    }
    pub(super) fn public(&self) -> &[u8] {
        &self.public[..self.profile.public_len()]
    }
    pub(super) fn shared(&self, public: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        check_public(self.profile, public)?;
        let mut secret = Zeroizing::new([0; 32]);
        match self.profile {
            Profile::X25519 => {
                let key = x25519_dalek::StaticSecret::from(*self.private);
                let peer = x25519_dalek::PublicKey::from(
                    <[u8; 32]>::try_from(public).map_err(|_| CryptoError::Key)?,
                );
                secret.copy_from_slice(key.diffie_hellman(&peer).as_bytes());
            }
            Profile::P256 => {
                let key = p256::SecretKey::from_slice(self.private.as_ref())
                    .map_err(|_| CryptoError::Key)?;
                let peer =
                    p256::PublicKey::from_sec1_bytes(public).map_err(|_| CryptoError::Key)?;
                secret.copy_from_slice(
                    p256::ecdh::diffie_hellman(key.to_nonzero_scalar(), peer.as_affine())
                        .raw_secret_bytes(),
                );
            }
        }
        if bool::from(secret.ct_eq(&[0; 32])) {
            return Err(CryptoError::Key);
        }
        Ok(secret)
    }
}
pub(super) fn check_public(profile: Profile, public: &[u8]) -> Result<()> {
    if public.len() != profile.public_len() {
        return Err(CryptoError::Key);
    }
    if profile == Profile::P256 {
        let peer = p256::PublicKey::from_sec1_bytes(public).map_err(|_| CryptoError::Key)?;
        if public[0] != 4 || peer.to_sec1_point(false).as_bytes() != public {
            return Err(CryptoError::Key);
        }
    }
    // RFC 7748 aliases/twist inputs are accepted unchanged. Every actual DH,
    // including ss/es/ee/se, applies its own all-zero shared-result gate.
    Ok(())
}

pub(crate) struct LocalKeys {
    dh: Arc<SoftwareDh>,
    signer: Ed25519KeyPair,
}
impl fmt::Debug for LocalKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalKeys { <redacted> }")
    }
}
impl LocalKeys {
    pub(crate) fn generate(profile: Profile) -> Result<Arc<Self>> {
        let dh = Arc::new(SoftwareDh::generate(profile, &mut Entropy)?);
        let mut seed = Zeroizing::new([0; 32]);
        SystemRandom::new()
            .fill(seed.as_mut())
            .map_err(|_| CryptoError::Key)?;
        let signer =
            Ed25519KeyPair::from_seed_unchecked(seed.as_ref()).map_err(|_| CryptoError::Key)?;
        Ok(Arc::new(Self { dh, signer }))
    }
    pub(super) fn dh_public(&self) -> &[u8] {
        self.dh.public()
    }
    pub(super) fn ed_public(&self) -> [u8; 32] {
        self.signer
            .public_key()
            .as_ref()
            .try_into()
            .expect("Ed25519 public length")
    }
    pub(super) fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        let signature: [u8; 64] = self
            .signer
            .sign(message)
            .as_ref()
            .try_into()
            .map_err(|_| CryptoError::Key)?;
        if !codec_v4::strict_verify(&signature, message, &self.ed_public()) {
            return Err(CryptoError::Authentication);
        }
        Ok(signature)
    }
    pub(super) fn resolver(
        self: &Arc<Self>,
        profile: Profile,
    ) -> Result<Box<dyn CryptoResolver + Send>> {
        if self.dh.profile != profile {
            return Err(CryptoError::Key);
        }
        Ok(Box::new(Resolver {
            profile,
            local: self.dh.clone(),
        }))
    }
}
struct Entropy;
impl Random for Entropy {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), snow::Error> {
        SystemRandom::new().fill(dest).map_err(|_| snow::Error::Rng)
    }
}
struct AdapterDh {
    profile: Profile,
    local: Arc<SoftwareDh>,
    key: Option<AdapterKey>,
}
enum AdapterKey {
    Static,
    Ephemeral(SoftwareDh),
}
impl AdapterDh {
    fn key(&self) -> Option<&SoftwareDh> {
        match self.key.as_ref()? {
            AdapterKey::Static => Some(&self.local),
            AdapterKey::Ephemeral(key) => Some(key),
        }
    }
}
impl Dh for AdapterDh {
    fn name(&self) -> &'static str {
        match self.profile {
            Profile::X25519 => "25519",
            Profile::P256 => "P256",
        }
    }
    fn pub_len(&self) -> usize {
        self.profile.public_len()
    }
    fn priv_len(&self) -> usize {
        32
    }
    fn dh_len(&self) -> usize {
        32
    }
    fn set(&mut self, selector: &[u8]) {
        // Builder receives only this fixed capability selector. No static key
        // bytes cross the software key boundary or enter Snow's keypair getter.
        self.key = (selector == [0; 32]).then_some(AdapterKey::Static);
    }
    fn generate(&mut self, rng: &mut dyn Random) -> std::result::Result<(), snow::Error> {
        if self.key.is_some() {
            return Err(snow::Error::Dh);
        }
        self.key = Some(AdapterKey::Ephemeral(
            SoftwareDh::generate(self.profile, rng).map_err(|_| snow::Error::Rng)?,
        ));
        Ok(())
    }
    fn pubkey(&self) -> &[u8] {
        self.key().map_or(&[], SoftwareDh::public)
    }
    fn privkey(&self) -> &[u8] {
        &[]
    }
    fn dh(&self, peer: &[u8], out: &mut [u8]) -> std::result::Result<(), snow::Error> {
        let length = self.profile.public_len();
        let public = peer.get(..length).ok_or(snow::Error::Dh)?;
        if peer[length..].iter().any(|byte| *byte != 0) {
            return Err(snow::Error::Dh);
        }
        let secret = self
            .key()
            .ok_or(snow::Error::Dh)?
            .shared(public)
            .map_err(|_| snow::Error::Dh)?;
        out.get_mut(..32)
            .ok_or(snow::Error::Dh)?
            .copy_from_slice(secret.as_ref());
        Ok(())
    }
}
struct Resolver {
    profile: Profile,
    local: Arc<SoftwareDh>,
}
impl CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(Entropy))
    }
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        if !matches!(
            (self.profile, choice),
            (Profile::X25519, DHChoice::Curve25519) | (Profile::P256, DHChoice::P256)
        ) {
            return None;
        }
        Some(Box::new(AdapterDh {
            profile: self.profile,
            local: self.local.clone(),
            key: None,
        }))
    }
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        matches!(choice, HashChoice::SHA256)
            .then(|| RingResolver.resolve_hash(choice))
            .flatten()
    }
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        if !matches!(
            (self.profile, choice),
            (Profile::X25519, CipherChoice::ChaChaPoly) | (Profile::P256, CipherChoice::AESGCM)
        ) {
            return None;
        }
        RingResolver.resolve_cipher(choice)
    }
}
