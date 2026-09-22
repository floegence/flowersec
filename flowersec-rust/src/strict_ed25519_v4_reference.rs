//! Reference-only strict acceptance over stable bytes, not a runtime key handle.
use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar, traits::IsIdentity};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

use super::registry::{
    STRICT_ED25519_POINT_BYTES, STRICT_ED25519_PUBLIC_KEY_BYTES, STRICT_ED25519_SIGNATURE_BYTES,
    STRICT_ED25519_SIGNING_FAILURE,
};

pub(crate) fn verify(signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
    if public_key.len() != STRICT_ED25519_PUBLIC_KEY_BYTES
        || signature.len() != STRICT_ED25519_SIGNATURE_BYTES
    {
        return false;
    }
    for encoded in [public_key, &signature[..STRICT_ED25519_POINT_BYTES]] {
        let Ok(bytes) = <[u8; 32]>::try_from(encoded) else {
            return false;
        };
        let Some(point) = CompressedEdwardsY(bytes).decompress() else {
            return false;
        };
        if point.compress().to_bytes() != bytes || point.is_identity() || !point.is_torsion_free() {
            return false;
        }
    }
    let Ok(scalar) = <[u8; 32]>::try_from(&signature[STRICT_ED25519_POINT_BYTES..]) else {
        return false;
    };
    if !bool::from(Scalar::from_canonical_bytes(scalar).is_some()) {
        return false;
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, signature)
        .is_ok()
}

pub(crate) fn sign(message: &[u8], seed: &[u8]) -> Result<Vec<u8>, &'static str> {
    let key =
        Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| STRICT_ED25519_SIGNING_FAILURE)?;
    sign_once(message, || {
        Ok((
            key.public_key().as_ref().to_vec(),
            key.sign(message).as_ref().to_vec(),
        ))
    })
}

// FnOnce makes retry structurally impossible. This callback is internal test
// injection, not a public provider ownership or cancellation abstraction.
pub(crate) fn sign_once(
    message: &[u8],
    signer: impl FnOnce() -> Result<(Vec<u8>, Vec<u8>), &'static str>,
) -> Result<Vec<u8>, &'static str> {
    let (public_key, signature) = signer().map_err(|_| STRICT_ED25519_SIGNING_FAILURE)?;
    if !verify(&signature, message, &public_key) {
        return Err(STRICT_ED25519_SIGNING_FAILURE);
    }
    Ok(signature)
}
