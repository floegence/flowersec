//! Fixed-material primitive reference; no production key handle or Noise state.
use p256::{
    PublicKey, SecretKey,
    ecdh::diffie_hellman,
    elliptic_curve::{sec1::ToSec1Point, subtle::ConstantTimeEq},
};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::registry::{
    DH_FAILURE, DH_P256_PUBLIC_BYTES, DH_PRIVATE_BYTES, DH_PROFILE_P256, DH_PROFILE_X25519,
    DH_SECRET_BYTES, DH_X25519_PUBLIC_BYTES,
};

pub(crate) fn public(profile: &str, private: &[u8]) -> Result<Vec<u8>, &'static str> {
    let bytes: [u8; DH_PRIVATE_BYTES] = private.try_into().map_err(|_| DH_FAILURE)?;
    let material = Zeroizing::new(bytes);
    match profile {
        DH_PROFILE_X25519 => Ok(XPublicKey::from(&StaticSecret::from(*material))
            .as_bytes()
            .to_vec()),
        DH_PROFILE_P256 => {
            let key = SecretKey::from_slice(material.as_ref()).map_err(|_| DH_FAILURE)?;
            Ok(key.public_key().to_sec1_point(false).as_bytes().to_vec())
        }
        _ => Err(DH_FAILURE),
    }
}

pub(crate) fn derive(
    profile: &str,
    private: &[u8],
    public: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let bytes: [u8; DH_PRIVATE_BYTES] = private.try_into().map_err(|_| DH_FAILURE)?;
    let material = Zeroizing::new(bytes);
    let shared = match profile {
        DH_PROFILE_X25519 => {
            let peer: [u8; DH_X25519_PUBLIC_BYTES] = public.try_into().map_err(|_| DH_FAILURE)?;
            // Montgomery decoding is confined to Dalek's DH computation.
            StaticSecret::from(*material)
                .diffie_hellman(&XPublicKey::from(peer))
                .as_bytes()
                .to_vec()
        }
        DH_PROFILE_P256 => {
            if public.len() != DH_P256_PUBLIC_BYTES || public[0] != 4 {
                return Err(DH_FAILURE);
            }
            let key = SecretKey::from_slice(material.as_ref()).map_err(|_| DH_FAILURE)?;
            let peer = PublicKey::from_sec1_bytes(public).map_err(|_| DH_FAILURE)?;
            if peer.to_sec1_point(false).as_bytes() != public {
                return Err(DH_FAILURE);
            }
            diffie_hellman(key.to_nonzero_scalar(), peer.as_affine())
                .raw_secret_bytes()
                .to_vec()
        }
        _ => return Err(DH_FAILURE),
    };
    let result = Zeroizing::new(shared);
    if result.len() != DH_SECRET_BYTES || bool::from(result.as_slice().ct_eq(&[0; DH_SECRET_BYTES]))
    {
        return Err(DH_FAILURE);
    }
    Ok(result.to_vec())
}
