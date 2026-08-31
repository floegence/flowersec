//! Native TLS 1.3 policy construction for Flowersec v3 carriers.

#![allow(dead_code)]

use std::{fmt, sync::Arc};

use flowersec_native_transport::{
    PathProfile as NativePathProfile, RawQuicClientConfig as NativeRawQuicClientConfig,
    RawQuicLimits as NativeRawQuicLimits,
};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore,
    SignatureScheme,
    client::{
        Resumption,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{WebPkiSupportedAlgorithms, ring, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
    version::TLS13,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use x509_parser::{
    oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY},
    prelude::{FromDer, X509Certificate, X509Version},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum NativeTlsConfigErrorV3 {
    #[error("native TLS trust roots are unavailable")]
    RootsUnavailable,
    #[error("native TLS policy is invalid")]
    InvalidPolicy,
    #[error("native TLS 1.3 configuration failed")]
    Configuration,
}

#[derive(Clone, Debug)]
pub(crate) enum NativeTlsPolicyV3 {
    Ca {
        certificates: Vec<CertificateDer<'static>>,
    },
    Pin {
        active_leaf_hashes: Vec<[u8; 32]>,
    },
}

impl NativeTlsPolicyV3 {
    pub(crate) fn ca_with_platform_roots() -> Result<Self, NativeTlsConfigErrorV3> {
        let loaded = rustls_native_certs::load_native_certs();
        Self::ca_with_configured_roots(loaded.certs)
    }

    pub(crate) fn ca_with_configured_roots(
        certificates: impl IntoIterator<Item = CertificateDer<'static>>,
    ) -> Result<Self, NativeTlsConfigErrorV3> {
        let certificates = certificates.into_iter().collect::<Vec<_>>();
        let mut roots = RootCertStore::empty();
        for certificate in &certificates {
            roots
                .add(certificate.clone())
                .map_err(|_| NativeTlsConfigErrorV3::RootsUnavailable)?;
        }
        if roots.is_empty() {
            return Err(NativeTlsConfigErrorV3::RootsUnavailable);
        }
        Ok(Self::Ca { certificates })
    }

    pub(crate) fn pin(
        active_leaf_hashes: impl IntoIterator<Item = [u8; 32]>,
    ) -> Result<Self, NativeTlsConfigErrorV3> {
        let active_leaf_hashes = active_leaf_hashes.into_iter().collect::<Vec<_>>();
        if active_leaf_hashes.is_empty()
            || active_leaf_hashes.len() > 4
            || active_leaf_hashes
                .iter()
                .enumerate()
                .any(|(index, pin)| active_leaf_hashes[..index].contains(pin))
        {
            return Err(NativeTlsConfigErrorV3::InvalidPolicy);
        }
        Ok(Self::Pin { active_leaf_hashes })
    }

    pub(crate) fn client_config(
        &self,
        alpn: &[u8],
    ) -> Result<Arc<ClientConfig>, NativeTlsConfigErrorV3> {
        if alpn.is_empty() || alpn.len() > u8::MAX as usize {
            return Err(NativeTlsConfigErrorV3::InvalidPolicy);
        }
        let provider = Arc::new(ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&TLS13])
            .map_err(|_| NativeTlsConfigErrorV3::Configuration)?;
        let mut config = match self {
            Self::Ca { certificates } => builder
                .with_root_certificates(root_store(certificates)?)
                .with_no_client_auth(),
            Self::Pin { active_leaf_hashes } => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedServerVerifierV3 {
                    active_leaf_hashes: active_leaf_hashes.clone(),
                    supported: provider.signature_verification_algorithms,
                }))
                .with_no_client_auth(),
        };
        config.alpn_protocols = vec![alpn.to_vec()];
        config.enable_early_data = false;
        config.resumption = Resumption::disabled();
        Ok(Arc::new(config))
    }

    pub(crate) fn raw_quic_config(
        &self,
        profile: NativePathProfile,
        inbound_capacity: u32,
        handshake_timeout: std::time::Duration,
    ) -> Result<NativeRawQuicClientConfig, NativeTlsConfigErrorV3> {
        let limits = NativeRawQuicLimits::for_session(inbound_capacity, handshake_timeout)
            .map_err(|_| NativeTlsConfigErrorV3::Configuration)?;
        match self {
            Self::Ca { certificates } => NativeRawQuicClientConfig::new_ca(
                profile,
                certificates
                    .iter()
                    .map(|certificate| certificate.as_ref().to_vec())
                    .collect(),
                limits,
            ),
            Self::Pin { active_leaf_hashes } => {
                NativeRawQuicClientConfig::new_pin(profile, active_leaf_hashes.clone(), limits)
            }
        }
        .map_err(|_| NativeTlsConfigErrorV3::Configuration)
    }
}

fn root_store(
    certificates: &[CertificateDer<'static>],
) -> Result<RootCertStore, NativeTlsConfigErrorV3> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate.clone())
            .map_err(|_| NativeTlsConfigErrorV3::RootsUnavailable)?;
    }
    if roots.is_empty() {
        return Err(NativeTlsConfigErrorV3::RootsUnavailable);
    }
    Ok(roots)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum PinCertificateFailureV3 {
    #[error("pinned certificate profile is invalid")]
    InvalidProfile,
    #[error("pinned certificate hash does not match")]
    PinMismatch,
}

#[derive(Debug)]
struct PinnedServerVerifierV3 {
    active_leaf_hashes: Vec<[u8; 32]>,
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServerVerifierV3 {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        verify_pin_profile(end_entity.as_ref(), &self.active_leaf_hashes, now.as_secs())
            .map_err(pin_certificate_error)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, certificate, signature, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, certificate, signature, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

fn verify_pin_profile(
    certificate_der: &[u8],
    active_leaf_hashes: &[[u8; 32]],
    now_unix_s: u64,
) -> Result<(), PinCertificateFailureV3> {
    let (remainder, certificate) = X509Certificate::from_der(certificate_der)
        .map_err(|_| PinCertificateFailureV3::InvalidProfile)?;
    let validity = certificate.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    let now = i64::try_from(now_unix_s).map_err(|_| PinCertificateFailureV3::InvalidProfile)?;
    let spki = certificate.public_key();
    let p256 = spki.algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY
        && spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.as_oid().ok())
            .is_some_and(|curve| curve == OID_EC_P256);
    if !remainder.is_empty()
        || certificate.version() != X509Version::V3
        || now < not_before
        || now >= not_after
        || not_after
            .checked_sub(not_before)
            .is_none_or(|duration| duration > 1_209_600)
        || !p256
    {
        return Err(PinCertificateFailureV3::InvalidProfile);
    }
    let digest: [u8; 32] = Sha256::digest(certificate_der).into();
    let mut matched = 0u8;
    for pin in active_leaf_hashes {
        matched |= digest.ct_eq(pin).unwrap_u8();
    }
    if matched == 0 {
        return Err(PinCertificateFailureV3::PinMismatch);
    }
    Ok(())
}

fn pin_certificate_error(error: PinCertificateFailureV3) -> RustlsError {
    RustlsError::InvalidCertificate(CertificateError::Other(rustls::OtherError(Arc::new(error))))
}

impl fmt::Display for PinnedServerVerifierV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PinnedServerVerifierV3")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cert_test_builder::{
        BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };
    use rustls::{
        ServerConfig,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use time::{Duration, OffsetDateTime};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    struct TestIdentityV3 {
        leaf: CertificateDer<'static>,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    }

    #[test]
    fn rejects_empty_or_duplicate_pin_sets() {
        assert_eq!(
            NativeTlsPolicyV3::pin([]).unwrap_err(),
            NativeTlsConfigErrorV3::InvalidPolicy
        );
        assert_eq!(
            NativeTlsPolicyV3::pin([[1; 32], [1; 32]]).unwrap_err(),
            NativeTlsConfigErrorV3::InvalidPolicy
        );
        assert!(NativeTlsPolicyV3::pin([[2; 32], [1; 32]]).is_ok());
    }

    #[test]
    fn configs_are_tls13_only_without_early_data_or_resumption() {
        let policy = NativeTlsPolicyV3::pin([[1; 32]]).unwrap();
        let config = policy.client_config(b"flowersec-direct/3").unwrap();
        assert!(!config.enable_early_data);
        assert_eq!(config.alpn_protocols, [b"flowersec-direct/3"]);
        assert!(format!("{:?}", config.resumption).contains("NoClientSessionStorage"));
    }

    #[tokio::test]
    async fn self_signed_pin_succeeds_and_mismatch_fails_before_application_bytes() {
        let identity = self_signed_identity();
        let correct_pin: [u8; 32] = Sha256::digest(identity.leaf.as_ref()).into();
        let client = NativeTlsPolicyV3::pin([[0xA5; 32], correct_pin])
            .unwrap()
            .client_config(b"flowersec-direct/3")
            .unwrap();
        assert!(run_loopback_tls(identity, client).await);

        let identity = self_signed_identity();
        let client = NativeTlsPolicyV3::pin([[0xA5; 32]])
            .unwrap()
            .client_config(b"flowersec-direct/3")
            .unwrap();
        assert!(!run_loopback_tls(identity, client).await);
    }

    #[tokio::test]
    async fn configured_private_ca_uses_standard_chain_and_name_verification() {
        let (root, identity) = private_ca_identity();
        let client = NativeTlsPolicyV3::ca_with_configured_roots([root])
            .unwrap()
            .client_config(b"flowersec-direct/3")
            .unwrap();
        assert!(run_loopback_tls(identity, client).await);
    }

    #[test]
    fn pin_profile_rejects_expired_and_overlong_certificates() {
        let now = OffsetDateTime::now_utc();
        let expired =
            self_signed_identity_with_validity(now - Duration::days(2), now - Duration::days(1));
        let expired_pin: [u8; 32] = Sha256::digest(expired.leaf.as_ref()).into();
        assert_eq!(
            verify_pin_profile(
                expired.leaf.as_ref(),
                &[expired_pin],
                u64::try_from(now.unix_timestamp()).unwrap(),
            ),
            Err(PinCertificateFailureV3::InvalidProfile)
        );

        let overlong =
            self_signed_identity_with_validity(now - Duration::days(1), now + Duration::days(14));
        let overlong_pin: [u8; 32] = Sha256::digest(overlong.leaf.as_ref()).into();
        assert_eq!(
            verify_pin_profile(
                overlong.leaf.as_ref(),
                &[overlong_pin],
                u64::try_from(now.unix_timestamp()).unwrap(),
            ),
            Err(PinCertificateFailureV3::InvalidProfile)
        );
    }

    fn validity() -> (OffsetDateTime, OffsetDateTime) {
        let now = OffsetDateTime::now_utc();
        (now - Duration::minutes(1), now + Duration::hours(1))
    }

    fn self_signed_identity() -> TestIdentityV3 {
        let (not_before, not_after) = validity();
        self_signed_identity_with_validity(not_before, not_after)
    }

    fn self_signed_identity_with_validity(
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> TestIdentityV3 {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.not_before = not_before;
        params.not_after = not_after;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let certificate = params.self_signed(&key).unwrap();
        let leaf = certificate.der().clone();
        TestIdentityV3 {
            chain: vec![leaf.clone()],
            leaf,
            key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        }
    }

    fn private_ca_identity() -> (CertificateDer<'static>, TestIdentityV3) {
        let (not_before, not_after) = validity();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.not_before = not_before;
        ca_params.not_after = not_after;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        leaf_params.not_before = not_before;
        leaf_params.not_after = not_after;
        leaf_params
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        leaf_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let leaf_certificate: Certificate = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let root = ca.der().clone();
        let leaf = leaf_certificate.der().clone();
        (
            root.clone(),
            TestIdentityV3 {
                chain: vec![leaf.clone(), root],
                leaf,
                key: PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
            },
        )
    }

    async fn run_loopback_tls(identity: TestIdentityV3, client: Arc<ClientConfig>) -> bool {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let provider = Arc::new(ring::default_provider());
        let mut server = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(identity.chain, identity.key)
            .unwrap();
        server.alpn_protocols = vec![b"flowersec-direct/3".to_vec()];
        server.max_early_data_size = 0;
        server.send_tls13_tickets = 0;
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let Ok(mut tls) = acceptor.accept(stream).await else {
                return false;
            };
            let mut byte = [0; 1];
            tls.read_exact(&mut byte).await.is_ok() && byte == [0x5A]
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let server_name = ServerName::try_from("localhost").unwrap().to_owned();
        let client_result = TlsConnector::from(client)
            .connect(server_name, stream)
            .await;
        let client_ok = match client_result {
            Ok(mut tls) => tls.write_all(&[0x5A]).await.is_ok(),
            Err(_) => false,
        };
        let server_ok = server_task.await.unwrap();
        client_ok && server_ok
    }
}
