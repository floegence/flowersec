//! One isolated, single-use KKpsk0 attempt per unshared Wasm instance.
//!
//! Only the TypeScript crypto boundary can access this ABI. Neither a provider
//! nor a public SDK object receives the instance, memory, seed or raw root.
//! Snow owns token processing, nonce/AD semantics, authentication and Split.
//! There is no transport mode, algorithm negotiation, retry, or raw Split ABI.

use curve25519_dalek::montgomery::MontgomeryPoint;
use hkdf::Hkdf;
use p256::{PublicKey, SecretKey, ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint};
use sha2::Sha256;
use snow::{
    Builder, Error, HandshakeState,
    params::{CipherChoice, DHChoice, HashChoice},
    resolvers::{CryptoResolver, DefaultResolver},
    types::{Cipher, Dh, Hash, Random},
};
use std::sync::Mutex;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

mod registry;

// Snow is always supplied a bounded original ephemeral seed through the ABI.
// Keep transitive getrandom fail-closed so this Wasm image has no hidden host
// entropy import or browser callback.
fn no_host_rng(_: &mut [u8]) -> Result<(), getrandom::Error> { Err(getrandom::Error::UNSUPPORTED) }
getrandom::register_custom_getrandom!(no_host_rng);

// The fixed ABI layout is generated together with its TypeScript descriptor.
const INPUT: usize = registry::INPUT_BYTES;
struct Attempt {
    io: [u8; INPUT],
    state: Option<HandshakeState>,
    profile: u8,
    context: [u8; 32],
    started: bool,
    written: bool,
    read: bool,
    terminal: bool,
}
impl Attempt {
    const fn new() -> Self {
        Self { io: [0; INPUT], state: None, profile: 0, context: [0; 32], started: false,
            written: false, read: false, terminal: false }
    }
    fn close(&mut self) {
        self.terminal = true;
        self.state = None;
        self.io.zeroize();
        self.context.zeroize();
    }
    fn start(&mut self) -> Result<(), Error> {
        if self.started || self.terminal { return Err(Error::Input); }
        self.started = true;
        let profile = self.io[0];
        let role = self.io[1];
        if profile > 1 || role > 1 || self.io[2..4] != [0; 2] { return Err(Error::Input); }
        let public_len = public_length(profile);
        let scalar = Zeroizing::new(<[u8; 32]>::try_from(&self.io[4..36]).map_err(|_| Error::Input)?);
        let local = &self.io[36..101];
        let remote = &self.io[101..166];
        if local[public_len..].iter().chain(remote[public_len..].iter()).any(|v| *v != 0) {
            return Err(Error::Input);
        }
        let generated = public(profile, &scalar)?;
        if generated[..public_len] != local[..public_len] { return Err(Error::Dh); }
        validate_public(profile, &remote[..public_len])?;
        let psk = Zeroizing::new(<[u8; 32]>::try_from(&self.io[166..198]).map_err(|_| Error::Input)?);
        // Entropy is supplied once by the original admitted JS crypto owner.
        // Use Snow's ordinary generate path, never its test-only fixed key API.
        let ephemeral = Zeroizing::new(<[u8; 32]>::try_from(&self.io[198..230]).map_err(|_| Error::Input)?);
        public(profile, &ephemeral)?;
        let size = u32::from_be_bytes(self.io[230..234].try_into().map_err(|_| Error::Input)?) as usize;
        if size == 0 || size > INPUT - registry::PROLOGUE_OFFSET { return Err(Error::Input); }
        self.context.copy_from_slice(&self.io[234..266]);
        let params = registry::NOISE_NAMES[usize::from(profile)].parse().map_err(|_| Error::Input)?;
        let builder = Builder::with_resolver(params, Box::new(Resolver { seed: *ephemeral }))
            .local_private_key(scalar.as_ref())?
            .remote_public_key(&remote[..public_len])?
            .psk(0, &psk)?
            .prologue(&self.io[registry::PROLOGUE_OFFSET..registry::PROLOGUE_OFFSET + size])?;
        let state = if role == 0 { builder.build_initiator() } else { builder.build_responder() }?;
        self.io.zeroize();
        self.profile = profile;
        self.state = Some(state);
        Ok(())
    }
    fn write(&mut self) -> Result<usize, Error> {
        let mut state = self.state.take().ok_or(Error::Input)?;
        if self.terminal || self.written || !state.is_my_turn() || state.is_handshake_finished() { return Err(Error::Input); }
        self.io.zeroize();
        let expected = public_length(self.profile) + 16;
        let size = state.write_message(&[], &mut self.io[..expected])?;
        if size != expected { return Err(Error::Input); }
        self.written = true;
        self.state = Some(state);
        Ok(size)
    }
    fn read(&mut self, size: usize) -> Result<usize, Error> {
        let mut state = self.state.take().ok_or(Error::Input)?;
        if self.terminal || self.read || state.is_my_turn() || state.is_handshake_finished()
            || size != public_length(self.profile) + 16 { return Err(Error::Input); }
        if state.read_message(&self.io[..size], &mut [])? != 0 { return Err(Error::Input); }
        self.io.zeroize();
        self.read = true;
        self.state = Some(state);
        Ok(0)
    }
    fn finish(&mut self) -> Result<usize, Error> {
        let mut state = self.state.take().ok_or(Error::Input)?;
        if self.terminal || !self.written || !self.read || !state.is_handshake_finished() { return Err(Error::Input); }
        self.terminal = true;
        let hash: [u8; 32] = state.get_handshake_hash().try_into().map_err(|_| Error::Input)?;
        // Snow also performs its normal automatic Split at message completion.
        // This public raw-Split operation repeats that KDF; both are accounted
        // by the containing fixed handshake work charge. Neither output is used
        // for a transport seal/open/rekey, including the responder's send key.
        let (first, second) = state.dangerously_get_raw_split();
        let first = Zeroizing::new(first);
        let _second = Zeroizing::new(second);
        let mut info = Vec::with_capacity(256);
        info.extend_from_slice(registry::ROOT_LABEL);
        for value in [registry::PROFILE_NAMES[usize::from(self.profile)].as_bytes(), &hash, &self.context] {
            info.extend_from_slice(&(value.len() as u32).to_be_bytes());
            info.extend_from_slice(value);
        }
        let mut root = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::from_prk(first.as_ref()).map_err(|_| Error::Input)?
            .expand(&info, root.as_mut()).map_err(|_| Error::Input)?;
        self.io.zeroize();
        self.io[..32].copy_from_slice(root.as_ref());
        self.io[32..64].copy_from_slice(&hash);
        self.context.zeroize();
        Ok(64)
    }
}
static ATTEMPT: Mutex<Attempt> = Mutex::new(Attempt::new());

fn public_length(profile: u8) -> usize { if profile == 0 { 32 } else { 65 } }
fn validate_public(profile: u8, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() != public_length(profile) { return Err(Error::Dh); }
    if profile == 1 {
        if bytes[0] != 4 { return Err(Error::Dh); }
        let key = PublicKey::from_sec1_bytes(bytes).map_err(|_| Error::Dh)?;
        if key.to_encoded_point(false).as_bytes() != bytes { return Err(Error::Dh); }
    }
    Ok(())
}
fn public(profile: u8, scalar: &[u8; 32]) -> Result<[u8; 65], Error> {
    let mut bytes = [0; 65];
    if profile == 0 {
        bytes[..32].copy_from_slice(&MontgomeryPoint::mul_base_clamped(*scalar).to_bytes());
    } else {
        let key = SecretKey::from_slice(scalar).map_err(|_| Error::Dh)?;
        bytes.copy_from_slice(key.public_key().to_encoded_point(false).as_bytes());
    }
    Ok(bytes)
}
struct ProfileDh {
    profile: u8,
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 65],
    valid: bool,
}
impl Dh for ProfileDh {
    fn name(&self) -> &'static str { if self.profile == 0 { "25519" } else { "P256" } }
    fn pub_len(&self) -> usize { public_length(self.profile) }
    fn priv_len(&self) -> usize { 32 }
    fn dh_len(&self) -> usize { 32 }
    fn set(&mut self, private: &[u8]) {
        self.valid = false;
        self.secret.zeroize();
        self.public.zeroize();
        if let Ok(bytes) = <[u8; 32]>::try_from(private) {
            let bytes = Zeroizing::new(bytes);
            if let Ok(key) = public(self.profile, &bytes) {
                self.secret.copy_from_slice(bytes.as_ref());
                self.public = key;
                self.valid = true;
            }
        }
    }
    fn generate(&mut self, rng: &mut dyn Random) -> Result<(), Error> {
        let mut seed = Zeroizing::new([0; 32]);
        rng.try_fill_bytes(seed.as_mut())?;
        self.set(seed.as_ref());
        if self.valid { Ok(()) } else { Err(Error::Dh) }
    }
    fn pubkey(&self) -> &[u8] { &self.public[..if self.valid { self.pub_len() } else { 0 }] }
    fn privkey(&self) -> &[u8] { &self.secret[..if self.valid { 32 } else { 0 }] }
    fn dh(&self, peer: &[u8], output: &mut [u8]) -> Result<(), Error> {
        let n = self.pub_len();
        if !self.valid || peer.len() < n || peer[n..].iter().any(|v| *v != 0) || output.len() < 32 { return Err(Error::Dh); }
        let peer = &peer[..n];
        validate_public(self.profile, peer)?;
        let mut shared = Zeroizing::new([0; 32]);
        if self.profile == 0 {
            // RFC 7748 decoding occurs only in this computation view. Snow
            // continues hashing the original static/e bytes, including aliases.
            let point = MontgomeryPoint(peer.try_into().map_err(|_| Error::Dh)?);
            shared.copy_from_slice(&point.mul_clamped(*self.secret).to_bytes());
        } else {
            let secret = SecretKey::from_slice(self.secret.as_ref()).map_err(|_| Error::Dh)?;
            let peer = PublicKey::from_sec1_bytes(peer).map_err(|_| Error::Dh)?;
            shared.copy_from_slice(diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine()).raw_secret_bytes());
        }
        if bool::from(shared.ct_eq(&[0; 32])) { return Err(Error::Dh); }
        output[..32].copy_from_slice(shared.as_ref());
        Ok(())
    }
}
struct SeedRandom { seed: Zeroizing<[u8; 32]>, used: bool }
impl Random for SeedRandom {
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Error> {
        if self.used || output.len() != 32 { return Err(Error::Rng); }
        self.used = true;
        output.copy_from_slice(self.seed.as_ref());
        self.seed.zeroize();
        Ok(())
    }
}
struct Resolver { seed: [u8; 32] }
impl Drop for Resolver { fn drop(&mut self) { self.seed.zeroize(); } }
impl CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(SeedRandom { seed: Zeroizing::new(self.seed), used: false }))
    }
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        let profile = match choice { DHChoice::Curve25519 => 0, DHChoice::P256 => 1, _ => return None };
        Some(Box::new(ProfileDh { profile, secret: Zeroizing::new([0; 32]), public: [0; 65], valid: false }))
    }
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        if *choice == HashChoice::SHA256 { DefaultResolver.resolve_hash(choice) } else { None }
    }
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        match choice { CipherChoice::AESGCM | CipherChoice::ChaChaPoly => DefaultResolver.resolve_cipher(choice), _ => None }
    }
}

// No pointer/length from the peer reaches an unsafe Rust slice. The only shared
// arena has a compile-time bound. An error permanently consumes this instance.
#[unsafe(no_mangle)]
pub extern "C" fn fs_noise_abi() -> u32 { registry::ABI }
#[unsafe(no_mangle)]
pub extern "C" fn fs_noise_io() -> *mut u8 {
    ATTEMPT.try_lock().map_or(std::ptr::null_mut(), |mut a| a.io.as_mut_ptr())
}
fn run(operation: impl FnOnce(&mut Attempt) -> Result<usize, Error>) -> i32 {
    let Ok(mut a) = ATTEMPT.try_lock() else { return -1 };
    match operation(&mut a) { Ok(n) => n as i32, Err(_) => { a.close(); -1 } }
}
#[unsafe(no_mangle)]
pub extern "C" fn fs_noise_start() -> i32 { run(|a| { a.start()?; Ok(0) }) }
#[unsafe(no_mangle)]
pub extern "C" fn fs_noise_write() -> i32 { run(Attempt::write) }
#[unsafe(no_mangle)]
pub extern "C" fn fs_noise_read(size: u32) -> i32 { run(|a| a.read(size as usize)) }
#[unsafe(no_mangle)]
pub extern "C" fn fs_noise_finish() -> i32 { run(Attempt::finish) }
#[unsafe(no_mangle)]
pub extern "C" fn fs_noise_close() { if let Ok(mut a) = ATTEMPT.try_lock() { a.close(); } }
