use p256::{PublicKey as P256PublicKey, SecretKey as P256SecretKey, ecdh::diffie_hellman};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Suite {
    X25519HkdfSha256Aes256Gcm,
    P256HkdfSha256Aes256Gcm,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CryptoError {
    #[error("invalid key material")]
    InvalidKey,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Secret32([u8; 32]);

impl Secret32 {
    fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

pub(crate) enum EphemeralPrivateKey {
    X25519(X25519Secret),
    P256(P256SecretKey),
}

impl std::fmt::Debug for EphemeralPrivateKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EphemeralPrivateKey([REDACTED])")
    }
}

pub(crate) fn generate_ephemeral_keypair(
    suite: Suite,
) -> Result<(EphemeralPrivateKey, Vec<u8>), CryptoError> {
    match suite {
        Suite::X25519HkdfSha256Aes256Gcm => {
            let private = X25519Secret::random_from_rng(OsRng);
            let public = X25519PublicKey::from(&private);
            Ok((
                EphemeralPrivateKey::X25519(private),
                public.as_bytes().to_vec(),
            ))
        }
        Suite::P256HkdfSha256Aes256Gcm => {
            let private = P256SecretKey::random(&mut OsRng);
            let public = private.public_key();
            Ok((
                EphemeralPrivateKey::P256(private),
                public.to_sec1_bytes().to_vec(),
            ))
        }
    }
}

#[cfg(test)]
pub(crate) fn derive_shared_secret(
    suite: Suite,
    private_key: &[u8],
    peer_public_key: &[u8],
) -> Result<Secret32, CryptoError> {
    match suite {
        Suite::X25519HkdfSha256Aes256Gcm => {
            let private: [u8; 32] = private_key
                .try_into()
                .map_err(|_| CryptoError::InvalidKey)?;
            let public: [u8; 32] = peer_public_key
                .try_into()
                .map_err(|_| CryptoError::InvalidKey)?;
            let shared = X25519Secret::from(private).diffie_hellman(&X25519PublicKey::from(public));
            if !shared.was_contributory() {
                return Err(CryptoError::InvalidKey);
            }
            Ok(Secret32::new(*shared.as_bytes()))
        }
        Suite::P256HkdfSha256Aes256Gcm => {
            let private =
                P256SecretKey::from_slice(private_key).map_err(|_| CryptoError::InvalidKey)?;
            let public = P256PublicKey::from_sec1_bytes(peer_public_key)
                .map_err(|_| CryptoError::InvalidKey)?;
            let shared = diffie_hellman(private.to_nonzero_scalar(), public.as_affine());
            let mut bytes = [0; 32];
            bytes.copy_from_slice(shared.raw_secret_bytes());
            Ok(Secret32::new(bytes))
        }
    }
}

impl EphemeralPrivateKey {
    pub(crate) fn derive_shared_secret(
        &self,
        peer_public_key: &[u8],
    ) -> Result<Secret32, CryptoError> {
        match self {
            Self::X25519(private) => {
                let public: [u8; 32] = peer_public_key
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKey)?;
                let shared = private.diffie_hellman(&X25519PublicKey::from(public));
                if !shared.was_contributory() {
                    return Err(CryptoError::InvalidKey);
                }
                Ok(Secret32::new(*shared.as_bytes()))
            }
            Self::P256(private) => {
                let public = P256PublicKey::from_sec1_bytes(peer_public_key)
                    .map_err(|_| CryptoError::InvalidKey)?;
                let shared = diffie_hellman(private.to_nonzero_scalar(), public.as_affine());
                let mut bytes = [0; 32];
                bytes.copy_from_slice(shared.raw_secret_bytes());
                Ok(Secret32::new(bytes))
            }
        }
    }
}
