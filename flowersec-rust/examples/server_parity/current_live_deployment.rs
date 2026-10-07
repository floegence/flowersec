//! Original engineering control configuration is read from an independently
//! installed file. A peer publication can match it, never select or replace it.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlTLS {
    #[serde(rename = "certificatePEM")]
    certificate_pem: String,
    #[serde(rename = "privateKeyPEM")]
    private_key_pem: String,
    #[serde(rename = "trustPEM")]
    trust_pem: String,
}
impl Drop for ControlTLS {
    fn drop(&mut self) {
        self.private_key_pem.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlInstallation {
    endpoint: String,
    authority: String,
    tls: ControlTLS,
    #[serde(rename = "workMS")]
    work_ms: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientInstallation {
    tenant: String,
    audience: String,
    control: ControlInstallation,
    #[serde(default)]
    relay_control: Option<ControlInstallation>,
}

fn installation() -> ClientInstallation {
    let path = env::var("FLOWERSEC_PARITY_LIVE_DEPLOYMENT")
        .expect("live client requires its independent control deployment");
    assert!(
        !path.is_empty() && path.len() <= 4096,
        "invalid independent live deployment path"
    );
    let mut file = std::fs::File::open(path).expect("open independent live control installation");
    let mut bytes = Zeroizing::new(Vec::with_capacity(4_194_305));
    Read::by_ref(&mut file)
        .take(4_194_305)
        .read_to_end(&mut bytes)
        .expect("read bounded original live deployment");
    assert!(
        !bytes.is_empty() && bytes.len() <= 4_194_304,
        "independent live deployment exceeds its input bound"
    );
    serde_json::from_slice(&bytes).expect("decode exact independent live client installation")
}
fn configuration(installed: &ControlInstallation) -> flowersec::ControlHTTPSConfiguration {
    configuration_path(installed, "/flowersec/control/live")
}
fn configuration_path(
    installed: &ControlInstallation,
    protocol_path: &str,
) -> flowersec::ControlHTTPSConfiguration {
    assert!(
        !installed.authority.is_empty() && installed.authority.len() <= 128,
        "invalid installed live authority"
    );
    installed_https(
        &installed.endpoint,
        &installed.tls,
        &installed.work_ms,
        if protocol_path.is_empty() {
            "/"
        } else {
            protocol_path
        },
        protocol_path,
        30_000,
    )
}
fn installed_https(
    endpoint_url: &str,
    tls: &ControlTLS,
    work_ms_text: &str,
    endpoint_path: &str,
    base_path: &str,
    maximum_work_ms: u64,
) -> flowersec::ControlHTTPSConfiguration {
    assert!(
        endpoint_url.len() <= 2048,
        "installed live control endpoint exceeds its bound"
    );
    let endpoint = Url::parse(endpoint_url).expect("parse installed live control endpoint");
    assert_eq!(endpoint.scheme(), "https");
    assert!(
        endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none()
            && endpoint.fragment().is_none(),
        "installed live control endpoint must have one fixed HTTPS origin"
    );
    assert_eq!(
        endpoint.path(),
        endpoint_path,
        "installed control path differs from its original protocol"
    );
    let host = endpoint
        .host_str()
        .expect("installed live control hostname")
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let remote_address = host.parse().unwrap_or_else(|_| {
        assert_eq!(
            host, "localhost",
            "engineering control hostname needs a fixed local address"
        );
        "127.0.0.1".parse().unwrap()
    });
    let work_ms = work_ms_text
        .parse::<u64>()
        .expect("installed canonical live work interval");
    assert_eq!(
        work_ms.to_string(),
        work_ms_text,
        "live work interval is not canonical"
    );
    assert!(
        (1..=maximum_work_ms).contains(&work_ms),
        "installed control work exceeds the SDK's bounded attempt"
    );
    assert!(
        tls.certificate_pem.len() <= 262144
            && tls.private_key_pem.len() <= 65536
            && tls.trust_pem.len() <= 1048576,
        "installed control TLS material exceeds its input bound"
    );
    let roots_der = CertificateDer::pem_slice_iter(tls.trust_pem.as_bytes())
        .map(|certificate| {
            certificate
                .expect("installed control trust certificate")
                .to_vec()
        })
        .collect::<Vec<_>>();
    let client_chain_der = CertificateDer::pem_slice_iter(tls.certificate_pem.as_bytes())
        .map(|certificate| {
            certificate
                .expect("installed original control client certificate")
                .to_vec()
        })
        .collect::<Vec<_>>();
    let client_key =
        rustls::pki_types::PrivateKeyDer::from_pem_slice(tls.private_key_pem.as_bytes())
            .expect("installed original control private key");
    assert!(
        matches!(&client_key, rustls::pki_types::PrivateKeyDer::Pkcs8(_)),
        "control identity requires PKCS8"
    );
    flowersec::ControlHTTPSConfiguration {
        host,
        port: endpoint.port_or_known_default().unwrap(),
        remote_address,
        base_path: base_path.into(),
        roots_der,
        client_chain_der,
        client_key_pkcs8: Zeroizing::new(client_key.secret_der().to_vec()),
        timeout: Duration::from_millis(work_ms),
        provider_runtime_bytes: 1 << 20,
    }
}
fn relay_configuration(
    installed: &ControlInstallation,
    original: &ControlInstallation,
) -> flowersec::ControlHTTPSConfiguration {
    assert!(
        installed.tls.certificate_pem == original.tls.certificate_pem
            && installed.tls.private_key_pem == original.tls.private_key_pem,
        "independent relay control must retain the original endpoint mTLS identity"
    );
    configuration_path(installed, "")
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PoolServerAllowBinding {
    endpoint: String,
    recipient: String,
    incarnation: String,
}
impl PoolServerAllowBinding {
    pub(super) fn new(endpoint: String, binding: flowersec::PoolServerAllowBinding) -> Self {
        Self {
            endpoint,
            recipient: STANDARD.encode(binding.recipient),
            incarnation: STANDARD.encode(binding.incarnation),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolAllowInstallation {
    endpoint: String,
    tls: ControlTLS,
    #[serde(default, rename = "clientCertificateDER")]
    client_certificate_der: Option<String>,
    #[serde(rename = "workMS")]
    work_ms: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolClientInstallation {
    wire_revision: u8,
    tenant: String,
    audience: String,
    server_allow: PoolAllowInstallation,
}

pub(super) fn pool_server_allow(
    material: &CurrentMaterial,
    binding: &PoolServerAllowBinding,
    server_grant: Vec<u8>,
) -> flowersec::TunnelServerAllowConfiguration {
    assert_eq!(material.source, "preauthorized_pool");
    assert_eq!(material.role, 0);
    let path = env::var("FLOWERSEC_PARITY_POOL_DEPLOYMENT")
        .expect("pool client requires its independently installed Allow sender");
    assert!(
        !path.is_empty() && path.len() <= 4096,
        "invalid original pool deployment path"
    );
    let mut file = std::fs::File::open(path).expect("open independent pool control installation");
    let mut bytes = Zeroizing::new(Vec::with_capacity(4_194_305));
    Read::by_ref(&mut file)
        .take(4_194_305)
        .read_to_end(&mut bytes)
        .expect("read bounded independent pool deployment");
    assert!(
        !bytes.is_empty() && bytes.len() <= 4_194_304,
        "pool deployment exceeds its input bound"
    );
    let installed: PoolClientInstallation =
        serde_json::from_slice(&bytes).expect("decode exact independent pool client installation");
    assert_eq!(installed.wire_revision, 4);
    assert!(
        installed.server_allow.client_certificate_der.is_none(),
        "A installation cannot carry B receiver identity policy"
    );
    let artifact = Zeroizing::new(current_bytes(&material.artifact, 65536, None));
    let (tenant, _, audience) = current_artifact_binding(&artifact);
    assert_eq!(
        tenant, installed.tenant,
        "pool tenant differs from its installed control binding"
    );
    assert_eq!(
        audience, installed.audience,
        "pool audience differs from its installed control binding"
    );
    assert_eq!(
        binding.endpoint, installed.server_allow.endpoint,
        "B registration cannot select or replace A's installed destination"
    );
    let control = installed_https(
        &installed.server_allow.endpoint,
        &installed.server_allow.tls,
        &installed.server_allow.work_ms,
        "/tunnel/server-allow",
        "",
        2000,
    );
    assert!(
        control.remote_address.is_loopback(),
        "engineering pool Allow requires its installed loopback address"
    );
    let recipient: [u8; 16] = current_bytes(&binding.recipient, 16, Some(16))
        .try_into()
        .unwrap();
    let incarnation: [u8; 16] = current_bytes(&binding.incarnation, 16, Some(16))
        .try_into()
        .unwrap();
    assert!(
        recipient != [0; 16] && incarnation != [0; 16],
        "original B registration is empty"
    );
    assert!(
        !server_grant.is_empty() && server_grant.len() <= 9302,
        "original server Grant exceeds its bound"
    );
    flowersec::TunnelServerAllowConfiguration {
        control,
        recipient,
        incarnation,
        grant: server_grant,
    }
}

/// A pool receiver reads only its own installed control identity. Peer ready
/// messages cannot supply keys, roots, the coordinator pin or the destination.
pub(super) fn pool_server_allow_receiver(
    material: &CurrentMaterial,
) -> (
    String,
    flowersec::WssServerIdentity,
    flowersec::PoolServerAllowOptions,
) {
    assert_eq!(material.source, "preauthorized_pool");
    assert_eq!(material.role, 1);
    let local_output =
        env::var("FLOWERSEC_PARITY_POOL_CLIENT_DEPLOYMENT_OUTPUT").unwrap_or_default();
    let installed_path = env::var("FLOWERSEC_PARITY_POOL_DEPLOYMENT").unwrap_or_default();
    assert!(
        local_output.is_empty() || installed_path.is_empty(),
        "pool B must select one original provisioning owner"
    );
    if !local_output.is_empty() {
        return provision_local_pool_server_allow(material, &local_output);
    }
    let path = installed_path;
    assert!(
        !path.is_empty(),
        "pool B requires its independently installed Allow receiver"
    );
    assert!(
        !path.is_empty() && path.len() <= 4096,
        "invalid original pool receiver deployment path"
    );
    let mut file = std::fs::File::open(path).expect("open independent pool receiver installation");
    let mut bytes = Zeroizing::new(Vec::with_capacity(4_194_305));
    Read::by_ref(&mut file)
        .take(4_194_305)
        .read_to_end(&mut bytes)
        .expect("read bounded pool receiver installation");
    assert!(
        !bytes.is_empty() && bytes.len() <= 4_194_304,
        "pool receiver installation exceeds its input bound"
    );
    let installed: PoolClientInstallation =
        serde_json::from_slice(&bytes).expect("decode exact pool receiver installation");
    assert_eq!(installed.wire_revision, 4);
    let artifact = Zeroizing::new(current_bytes(&material.artifact, 65536, None));
    let (tenant, _, audience) = current_artifact_binding(&artifact);
    assert_eq!(tenant, installed.tenant);
    assert_eq!(audience, installed.audience);
    installed_pool_receiver(&installed.server_allow)
}
fn installed_pool_receiver(
    allow: &PoolAllowInstallation,
) -> (
    String,
    flowersec::WssServerIdentity,
    flowersec::PoolServerAllowOptions,
) {
    let control = installed_https(
        &allow.endpoint,
        &allow.tls,
        &allow.work_ms,
        "/tunnel/server-allow",
        "",
        2000,
    );
    assert!(
        control.remote_address.is_loopback(),
        "engineering pool Allow requires an installed loopback address"
    );
    let coordinator = current_bytes(
        allow
            .client_certificate_der
            .as_deref()
            .expect("exact installed original A certificate"),
        65536,
        None,
    );
    assert!(
        !coordinator.is_empty(),
        "pool Allow coordinator certificate is empty"
    );
    let authority = if control.host.contains(':') {
        format!("[{}]:{}", control.host, control.port)
    } else {
        format!("{}:{}", control.host, control.port)
    };
    let identity = flowersec::WssServerIdentity {
        certificate_chain_der: control.client_chain_der,
        private_key_der: control.client_key_pkcs8.to_vec(),
    };
    let options = flowersec::PoolServerAllowOptions {
        listen_address: SocketAddr::new(control.remote_address, control.port),
        authority,
        client_roots_der: control.roots_der,
        coordinator_leaf_digest: Sha256::digest(&coordinator).into(),
        timeout: control.timeout,
        provider_runtime_bytes: control.provider_runtime_bytes,
    };
    (allow.endpoint.clone(), identity, options)
}

// The explicit local fixture owner provisions independent A/B TLS keys and
// writes A's sender installation before public B readiness. Peer material can
// supply no key, trust root, control destination or consumer-spend assertion.
fn provision_local_pool_server_allow(
    material: &CurrentMaterial,
    output: &str,
) -> (
    String,
    flowersec::WssServerIdentity,
    flowersec::PoolServerAllowOptions,
) {
    use cert_test_builder::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let output = std::path::Path::new(output);
    assert!(
        output.is_absolute() && output.as_os_str().len() <= 4096,
        "local pool sender requires its owned absolute output path"
    );
    let parent = std::fs::canonicalize(output.parent().expect("owned pool installation directory"))
        .expect("existing original pool installation directory");
    let temporary = std::fs::canonicalize(env::temp_dir()).expect("platform temporary root");
    let repository = std::fs::canonicalize(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap(),
    )
    .expect("current original repository root");
    assert!(
        !parent.starts_with(&repository)
            && !parent.starts_with(&temporary)
            && !parent.starts_with("/tmp")
            && !parent.starts_with("/private/tmp"),
        "pool installation must remain in its external task artifact directory"
    );
    let key = KeyPair::generate().expect("generate independent original control CA key");
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    let now = time::OffsetDateTime::now_utc();
    ca.not_before = now - time::Duration::seconds(30);
    ca.not_after = now + time::Duration::minutes(10);
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let certificate = ca
        .self_signed(&key)
        .expect("issue independent local control CA");
    let issuer = Issuer::new(ca, key);
    let leaf = |name: &str, purpose| {
        let key = KeyPair::generate().expect("generate independent original control leaf key");
        let mut params = CertificateParams::new(vec![name.into()]).unwrap();
        params.not_before = now - time::Duration::seconds(30);
        params.not_after = now + time::Duration::minutes(10);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![purpose];
        let cert = params
            .signed_by(&key, &issuer)
            .expect("issue independent original control leaf");
        (cert, key)
    };
    let (server, server_key) = leaf("127.0.0.1", ExtendedKeyUsagePurpose::ServerAuth);
    let (client, client_key) = leaf(
        "pool-client.flowersec.example",
        ExtendedKeyUsagePurpose::ClientAuth,
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve local pool control address");
    let address = listener.local_addr().unwrap();
    let endpoint = format!("https://{address}/tunnel/server-allow");
    let artifact = Zeroizing::new(current_bytes(&material.artifact, 65536, None));
    let (tenant, _, audience) = current_artifact_binding(&artifact);
    let mut client_key_pem = Zeroizing::new(client_key.serialize_pem());
    let installed = serde_json::json!({ "wire_revision": 4, "tenant": tenant, "audience": audience,
        "server_allow": { "endpoint": endpoint, "workMS": "2000", "tls": {
            "certificatePEM": client.pem(), "privateKeyPEM": &*client_key_pem, "trustPEM": certificate.pem() } } });
    client_key_pem.zeroize();
    let mut installed = installed;
    let bytes = Zeroizing::new(
        serde_json::to_vec(&installed).expect("encode bounded original sender installation"),
    );
    if let Some(Value::String(secret)) = installed.pointer_mut("/server_allow/tls/privateKeyPEM") {
        secret.zeroize();
    }
    assert!(
        !bytes.is_empty() && bytes.len() <= 4_194_304,
        "original pool sender installation exceeds its file bound"
    );
    let mut file_options = std::fs::OpenOptions::new();
    file_options.write(true).create_new(true);
    #[cfg(unix)]
    file_options.mode(0o600);
    let mut file = file_options
        .open(output)
        .expect("create private original A pool sender installation");
    file.write_all(&bytes)
        .expect("write complete original A pool sender installation");
    file.sync_all()
        .expect("sync original A pool sender installation");
    drop(file);
    std::fs::File::open(&parent)
        .unwrap()
        .sync_all()
        .expect("sync original pool sender directory");
    let identity = flowersec::WssServerIdentity {
        certificate_chain_der: vec![server.der().to_vec()],
        private_key_der: server_key.serialize_der(),
    };
    let options = flowersec::PoolServerAllowOptions {
        listen_address: address,
        authority: address.to_string(),
        client_roots_der: vec![certificate.der().to_vec()],
        coordinator_leaf_digest: Sha256::digest(client.der()).into(),
        timeout: Duration::from_millis(2000),
        provider_runtime_bytes: 1 << 20,
    };
    drop(listener);
    (endpoint, identity, options)
}

// Engineering live authorities install a finite 30,000,000 ms root lifetime.
// This bound belongs to local trust policy and is never chosen by a peer reply.
pub(super) async fn bootstrap_namespaces(
    environment: &flowersec::TransportEnvironment,
    material: &CurrentMaterial,
    trust_pem: &str,
) -> Vec<Arc<flowersec::Namespace>> {
    assert!(matches!(
        material.source.as_str(),
        "live_authority" | "preauthorized_pool"
    ));
    assert!(
        !material.namespaces.is_empty() && material.namespaces.len() <= 8,
        "live engineering requires bounded original namespace pins"
    );
    let mut namespaces = Vec::with_capacity(material.namespaces.len());
    for record in &material.namespaces {
        assert_eq!(
            record.tenant, material.namespaces[0].tenant,
            "live engineering namespace pins span tenants"
        );
        let namespace = environment
            .namespace(
                flowersec::NamespaceTrustRoot {
                    tenant: record.tenant.clone(),
                    authority: record.authority.clone(),
                    key_id: current_bytes(&record.root_key_id, 16, Some(16))
                        .try_into()
                        .unwrap(),
                    public_key: current_bytes(&record.root_public_key, 32, Some(32))
                        .try_into()
                        .unwrap(),
                    max_lifetime_ms: 30000000,
                },
                65536,
                131072,
            )
            .expect("capture independently installed original live namespace root");
        namespace
            .bootstrap_from(|original| async move {
                let request = serde_json::to_vec(
                    &serde_json::json!({"tenant":record.tenant,"authority":record.authority,
                    "nonce":STANDARD.encode(original.nonce())}),
                )
                .unwrap();
                let wire =
                    current_https_post(&record.bootstrap_url, trust_pem, &request, 65536).await;
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Reply {
                    response: String,
                    state: String,
                }
                let reply: Reply = serde_json::from_slice(&wire)
                    .expect("decode original live namespace bootstrap");
                let response = current_bytes(&reply.response, 65536, None);
                let state = current_bytes(&reply.state, 4096, None);
                Ok::<_, flowersec::EnvironmentError>((response, state))
            })
            .await
            .expect("verify original live namespace bootstrap");
        namespaces.push(namespace);
    }
    namespaces
}
pub(super) fn source_configuration(
    environment: &flowersec::TransportEnvironment,
    material: &CurrentMaterial,
    namespaces: Vec<Arc<flowersec::Namespace>>,
    trust_pem: &str,
    carrier: &str,
) -> flowersec::LiveAuthoritySourceConfiguration {
    let installed = installation();
    installed_source_configuration(
        environment,
        material,
        namespaces,
        trust_pem,
        carrier,
        &installed,
    )
}
fn installed_source_configuration(
    environment: &flowersec::TransportEnvironment,
    material: &CurrentMaterial,
    namespaces: Vec<Arc<flowersec::Namespace>>,
    trust_pem: &str,
    carrier: &str,
    installed: &ClientInstallation,
) -> flowersec::LiveAuthoritySourceConfiguration {
    assert_eq!(material.source, "live_authority");
    assert_eq!(material.role, 0);
    let artifact = current_bytes(&material.artifact, 65536, None);
    let (tenant, issuer, audience) = current_artifact_binding(&artifact);
    assert_eq!(
        tenant, installed.tenant,
        "live parent tenant differs from its installed control binding"
    );
    assert_eq!(
        audience, installed.audience,
        "live parent audience differs from its installed control binding"
    );
    assert_eq!(
        material.live_control_base_url.as_deref(),
        Some(installed.control.endpoint.as_str()),
        "peer publication differs from independently installed live control endpoint"
    );
    let control = configuration(&installed.control);
    flowersec::LiveAuthoritySourceConfiguration {
        namespaces,
        identity: current_identity(environment, material),
        client_certificate: current_bytes(&material.client_certificate, 8192, None),
        server_certificate: current_bytes(&material.server_certificate, 8192, None),
        artifact_issuer_key_id: issuer,
        activation_signing_key_id: material.activation_signing_key_id.clone(),
        issuance: control.clone(),
        activation: control,
        provider: current_provider_options(material, trust_pem, 0, carrier, &parity_origin()),
        carrier: match carrier {
            "raw-quic" => flowersec::LiveAuthorityCarrier::RawQuic,
            "websocket" => flowersec::LiveAuthorityCarrier::WebSocket,
            "webtransport" => flowersec::LiveAuthorityCarrier::WebTransport,
            _ => panic!("invalid installed live carrier"),
        },
        application_profile: flowersec::ApplicationProfile::Services,
    }
}

pub(super) fn tunnel_configuration(
    material: &CurrentMaterial,
    configuration: &flowersec::LiveAuthoritySourceConfiguration,
) -> flowersec::LiveTunnelSourceConfiguration {
    let slot = material
        .tunnels
        .iter()
        .find(|slot| slot.role == 0 && slot.candidate_index == 0)
        .expect("original live client tunnel policy");
    assert!(
        slot.grant.is_none(),
        "live client cannot import a signed Grant before TxB"
    );
    let policy = slot
        .live_grant
        .as_ref()
        .expect("original installed live Grant policy");
    assert!(
        !policy.authority.is_empty()
            && policy.authority.len() <= 128
            && !policy.audience.is_empty()
            && policy.audience.len() <= 128
            && !policy.service.is_empty()
            && policy.service.len() <= 128
            && !policy.revocation_policy_id.is_empty()
            && policy.revocation_policy_id.len() <= 128,
        "invalid fixed live relay preparation policy"
    );
    current_bytes(&policy.issuer_key_id, 16, Some(16));
    for number in [&policy.revocation_policy_revision, &policy.max_not_after_ms] {
        let value = number
            .parse::<u64>()
            .expect("live Grant policy canonical integer");
        assert!(
            value != 0 && value.to_string() == *number,
            "live Grant policy integer is not canonical"
        );
    }
    assert_eq!(
        material
            .namespaces
            .get(slot.grant_namespace as usize)
            .expect("installed Grant namespace")
            .authority,
        policy.authority,
        "live Grant policy differs from its installed issuer namespace"
    );
    assert_eq!(
        policy.service,
        current_artifact_binding(&current_bytes(&material.artifact, 65536, None)).2,
        "live relay service differs from the original application binding"
    );
    flowersec::LiveTunnelSourceConfiguration {
        control: flowersec::LiveTunnelAuthorityControlConfiguration {
            activation: configuration.activation.clone(),
            relay_preparation: configuration.activation.clone(),
            activation_signing_key_id: configuration.activation_signing_key_id.clone(),
        },
        relay_certificate: current_bytes(&slot.relay_certificate, 8192, None),
        relay_service: policy.service.clone(),
        relay_audience: policy.audience.clone(),
    }
}

// Registered engineering control consumes the original TxA Artifact directly.
// Its fixed JSON endpoint and authority come from the same installation read.
pub(super) fn registered_tunnel_configuration(
    environment: &flowersec::TransportEnvironment,
    material: &CurrentMaterial,
    namespaces: Vec<Arc<flowersec::Namespace>>,
    trust_pem: &str,
    carrier: &str,
) -> flowersec::RegisteredLiveTunnelSourceConfiguration {
    let installed = installation();
    assert!(
        security_identifier(&installed.control.authority),
        "invalid independently installed registered live authority"
    );
    let source = installed_source_configuration(
        environment,
        material,
        namespaces,
        trust_pem,
        carrier,
        &installed,
    );
    let mut tunnel = tunnel_configuration(material, &source);
    if let Some(relay_control) = &installed.relay_control {
        tunnel.control.relay_preparation = relay_configuration(relay_control, &installed.control);
    }
    flowersec::RegisteredLiveTunnelSourceConfiguration {
        source,
        tunnel,
        artifact: current_bytes(&material.artifact, 65536, None),
        authority: installed.control.authority.clone(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerInstallation {
    wire_revision: u8,
    registration_json: String,
    #[serde(rename = "identitySeed")]
    identity_seed: String,
    #[serde(rename = "noiseSeed")]
    noise_seed: String,
    #[serde(rename = "relayCertificate")]
    relay_certificate: String,
    #[serde(rename = "relayAudience")]
    relay_audience: String,
    #[serde(rename = "relayService")]
    relay_service: String,
    #[serde(rename = "relaySubject")]
    relay_subject: String,
    control: ControlInstallation,
    #[serde(default)]
    relay_control: Option<ControlInstallation>,
    #[serde(default)]
    server_allow: Option<PoolAllowInstallation>,
    #[serde(rename = "trustPEM")]
    trust_pem: String,
    origin: String,
    #[serde(rename = "certificatePEM")]
    certificate_pem: String,
    #[serde(rename = "privateKeyPEM")]
    private_key_pem: String,
}
impl Drop for ServerInstallation {
    fn drop(&mut self) {
        self.registration_json.zeroize();
        self.identity_seed.zeroize();
        self.noise_seed.zeroize();
        self.private_key_pem.zeroize();
    }
}

// Parsing the installed registry must reject unknown fields without retaining
// extra copies of private installation data after the bounded decode.
struct InstalledRegistryJSON(Value);
impl Drop for InstalledRegistryJSON {
    fn drop(&mut self) {
        fn clear(value: &mut Value) {
            match value {
                Value::String(text) => text.zeroize(),
                Value::Array(values) => values.iter_mut().for_each(clear),
                Value::Object(fields) => fields.values_mut().for_each(clear),
                _ => {}
            }
        }
        clear(&mut self.0);
    }
}
fn exact_fields(value: &Value, names: &[&str]) {
    let fields = value
        .as_object()
        .expect("installed registry record must be an object");
    assert!(
        fields.keys().all(|name| names.contains(&name.as_str())),
        "installed registry contains unknown fields"
    );
}
fn security_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index != 0 && matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-'))
        })
}

pub(super) struct ServerDeployment {
    pub(super) material: CurrentMaterial,
    installation: ServerInstallation,
}
impl ServerDeployment {
    pub(super) fn trust_pem(&self) -> &str {
        &self.installation.trust_pem
    }
    pub(super) fn relay_service(&self) -> String {
        self.installation.relay_service.clone()
    }
    pub(super) fn relay_audience(&self) -> String {
        self.installation.relay_audience.clone()
    }
    pub(super) fn relay_certificate(&self) -> Vec<u8> {
        current_bytes(&self.installation.relay_certificate, 8192, None)
    }
    pub(super) fn connection(&self) -> flowersec::PoolCredentialBytes {
        flowersec::PoolCredentialBytes {
            artifact: current_bytes(&self.material.artifact, 65536, None),
            client_certificate: current_bytes(&self.material.client_certificate, 8192, None),
            server_certificate: current_bytes(&self.material.server_certificate, 8192, None),
            activation: if self.material.source == "preauthorized_pool" {
                current_bytes(&self.material.activation, 4096, None)
            } else {
                Vec::new()
            },
        }
    }
    pub(super) fn pool_control(&self) -> flowersec::RegisteredPoolServerConfiguration {
        assert_eq!(self.material.source, "preauthorized_pool");
        assert!(
            self.installation.relay_control.is_none(),
            "pool installation cannot replace its original issuer"
        );
        flowersec::RegisteredPoolServerConfiguration {
            control: configuration_path(&self.installation.control, "/flowersec/control/tunnel"),
            authority: self.installation.control.authority.clone(),
            connection: self.connection(),
            relay_certificate: self.relay_certificate(),
            relay_service: self.relay_service(),
            relay_audience: self.relay_audience(),
        }
    }
    pub(super) fn pool_receiver(
        &self,
    ) -> (
        String,
        flowersec::WssServerIdentity,
        flowersec::PoolServerAllowOptions,
    ) {
        assert_eq!(self.material.source, "preauthorized_pool");
        installed_pool_receiver(
            self.installation
                .server_allow
                .as_ref()
                .expect("independent registered pool Allow receiver"),
        )
    }
    pub(super) fn match_pool_publication(
        &self,
        published: &CurrentMaterial,
        trust_pem: &str,
        origin: &str,
        server_identity_pem: (&str, &str),
        reverse: bool,
        grants: [[u8; 32]; 2],
    ) {
        assert_eq!(self.material.source, "preauthorized_pool");
        // Compare signed and installed inputs through the common matcher; only
        // the previously unissued slots are supplied by the original control.
        let mut installed = self.material.clone();
        assert!(installed.tunnels.is_empty());
        assert_eq!(published.tunnels.len(), 2);
        for role in 0..2 {
            let slot = published
                .tunnels
                .iter()
                .find(|s| s.role == role && s.candidate_index == 0)
                .expect("registered original pool public hop");
            assert!(slot.live_grant.is_none());
            let wire = current_bytes(
                slot.grant.as_deref().expect("original registered Grant"),
                9302,
                None,
            );
            let digest: [u8; 32] = Sha256::digest(&wire).into();
            assert_eq!(
                digest, grants[role as usize],
                "publication replaced an originally verified Grant"
            );
            assert_eq!(
                current_bytes(&slot.relay_certificate, 8192, None),
                self.relay_certificate()
            );
        }
        installed.tunnels = published.tunnels.clone();
        self.match_material_publication(
            &installed,
            published,
            trust_pem,
            origin,
            server_identity_pem,
            reverse,
        );
    }
    pub(super) fn control(&self) -> flowersec::RegisteredLiveServerControlConfiguration {
        flowersec::RegisteredLiveServerControlConfiguration {
            control: configuration(&self.installation.control),
            authority: self.installation.control.authority.clone(),
            activation_signing_key_id: self.material.activation_signing_key_id.clone(),
            relay_preparation: self
                .installation
                .relay_control
                .as_ref()
                .map(|relay| relay_configuration(relay, &self.installation.control)),
        }
    }
    pub(super) fn provider(&self, carrier: &str) -> flowersec::WssConnectOptions {
        let provider = current_provider_options(
            &self.material,
            self.trust_pem(),
            1,
            carrier,
            &self.installation.origin,
        );
        if carrier == "raw-quic" {
            assert!(
                provider.origin.is_none(),
                "raw QUIC installation must not introduce an HTTP origin"
            );
        } else {
            assert_eq!(
                provider.origin.as_deref(),
                Some(self.installation.origin.as_str()),
                "installed server origin differs from its signed route"
            );
        }
        provider
    }
    pub(super) fn reverse_provider(
        &self,
        carrier: &str,
    ) -> flowersec::ReverseTunnelProviderOptions {
        let options = self.provider(carrier);
        let (_, _, port, _, _) =
            current_route_endpoint(&current_bytes(&self.material.route, 16384, None), 1);
        assert!(
            !self.installation.certificate_pem.is_empty()
                && !self.installation.private_key_pem.is_empty(),
            "reverse live server requires its independently installed TLS identity"
        );
        let certificates =
            CertificateDer::pem_slice_iter(self.installation.certificate_pem.as_bytes())
                .map(|certificate| {
                    certificate
                        .expect("installed original server TLS certificate")
                        .to_vec()
                })
                .collect::<Vec<_>>();
        assert!(
            !certificates.is_empty(),
            "installed server TLS chain is empty"
        );
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(
            self.installation.private_key_pem.as_bytes(),
        )
        .expect("installed original server TLS private key");
        flowersec::ReverseTunnelProviderOptions {
            listen_address: SocketAddr::new(options.remote_address, port),
            identity: flowersec::WssServerIdentity {
                certificate_chain_der: certificates,
                private_key_der: key.secret_der().to_vec(),
            },
            origin: options.origin,
            timeout: options.timeout,
            publication_timeout: options.publication_timeout,
            queue_messages: options.queue_messages,
            prepare_bytes: options.prepare_bytes,
            native_runtime_bytes: options.native_runtime_bytes,
        }
    }
    pub(super) fn match_publication(
        &self,
        published: &CurrentMaterial,
        trust_pem: &str,
        origin: &str,
        server_identity_pem: (&str, &str),
        reverse: bool,
    ) {
        self.match_material_publication(
            &self.material,
            published,
            trust_pem,
            origin,
            server_identity_pem,
            reverse,
        );
    }
    fn match_material_publication(
        &self,
        installed: &CurrentMaterial,
        published: &CurrentMaterial,
        trust_pem: &str,
        origin: &str,
        server_identity_pem: (&str, &str),
        reverse: bool,
    ) {
        assert_eq!(
            trust_pem,
            self.trust_pem(),
            "relay trust differs from independently installed B trust"
        );
        assert_eq!(
            origin, self.installation.origin,
            "relay origin differs from independently installed B origin"
        );
        assert_eq!(published.wire_revision, installed.wire_revision);
        assert_eq!(published.role, installed.role);
        assert_eq!(published.profile, installed.profile);
        assert_eq!(published.source, installed.source);
        assert_eq!(published.generation.source, installed.generation.source);
        assert_eq!(
            published.generation.generation,
            installed.generation.generation
        );
        assert!(
            published.artifact == installed.artifact
                && published.activation == installed.activation
                && published.identity_seed == installed.identity_seed
                && published.dh_seed == installed.dh_seed,
            "relay publication differs from independently installed B parent or identity"
        );
        assert_eq!(published.client_certificate, installed.client_certificate);
        assert_eq!(published.server_certificate, installed.server_certificate);
        assert_eq!(published.route, installed.route);
        assert_eq!(published.route_digest, installed.route_digest);
        assert_eq!(
            published.activation_signing_key_id,
            installed.activation_signing_key_id
        );
        assert_eq!(
            published.live_control_base_url,
            installed.live_control_base_url
        );
        assert_eq!(published.namespaces, installed.namespaces);
        assert_eq!(published.tunnels.len(), installed.tunnels.len());
        for (published, installed) in published.tunnels.iter().zip(&installed.tunnels) {
            assert_eq!(published.candidate_index, installed.candidate_index);
            assert_eq!(published.role, installed.role);
            assert_eq!(published.grant, installed.grant);
            assert_eq!(published.relay_certificate, installed.relay_certificate);
            assert_eq!(published.grant_namespace, installed.grant_namespace);
            assert_eq!(published.relay_namespace, installed.relay_namespace);
            if self.material.source == "preauthorized_pool" {
                assert!(published.live_grant.is_none() && installed.live_grant.is_none());
                continue;
            }
            let published = published
                .live_grant
                .as_ref()
                .expect("published original pending live hop");
            let installed = installed
                .live_grant
                .as_ref()
                .expect("installed original pending live hop");
            assert_eq!(published.authority, installed.authority);
            assert_eq!(published.issuer_key_id, installed.issuer_key_id);
            assert_eq!(published.audience, installed.audience);
            assert_eq!(published.service, installed.service);
            assert_eq!(
                published.revocation_policy_id,
                installed.revocation_policy_id
            );
            assert_eq!(
                published.revocation_policy_revision,
                installed.revocation_policy_revision
            );
            assert_eq!(published.max_not_after_ms, installed.max_not_after_ms);
        }
        if reverse {
            assert_eq!(
                server_identity_pem.0, self.installation.certificate_pem,
                "relay publication differs from independently installed B TLS certificate"
            );
            assert!(
                server_identity_pem.1 == self.installation.private_key_pem,
                "relay publication differs from independently installed B TLS private key"
            );
        }
    }
}

pub(super) fn server_installation() -> Option<ServerDeployment> {
    let path = env::var_os("FLOWERSEC_PARITY_SERVER_CONTROL_DEPLOYMENT")?;
    if path.is_empty() {
        return None;
    }
    assert!(
        path.len() <= 4096,
        "invalid independent server deployment path"
    );
    let mut file =
        std::fs::File::open(path).expect("open independent original live server deployment");
    let mut bytes = Zeroizing::new(Vec::with_capacity(4194305));
    Read::by_ref(&mut file)
        .take(4194305)
        .read_to_end(&mut bytes)
        .expect("read bounded independent live server deployment");
    assert!(
        !bytes.is_empty() && bytes.len() <= 4194304,
        "independent server deployment exceeds its input bound"
    );
    let installation: ServerInstallation =
        serde_json::from_slice(&bytes).expect("decode exact independent live server deployment");
    assert_eq!(installation.wire_revision, 4);
    for seed in [&installation.identity_seed, &installation.noise_seed] {
        let seed = Zeroizing::new(current_bytes(seed, 32, Some(32)));
        assert!(
            seed.iter().any(|byte| *byte != 0),
            "installed server identity seed must be nonzero"
        );
    }
    for identifier in [
        &installation.relay_audience,
        &installation.relay_service,
        &installation.relay_subject,
        &installation.control.authority,
    ] {
        assert!(
            security_identifier(identifier),
            "invalid independently installed server relay or control identifier"
        );
    }
    assert!(
        !installation.trust_pem.is_empty()
            && installation.trust_pem.len() <= 1048576
            && !installation.origin.is_empty()
            && installation.origin.len() <= 2048
            && installation.certificate_pem.len() <= 262144
            && installation.private_key_pem.len() <= 65536,
        "independent server native installation exceeds its bounds"
    );
    assert!(
        !installation.registration_json.is_empty()
            && installation.registration_json.len() <= 1048576,
        "independent server registry exceeds its envelope bound"
    );
    let mut registry = InstalledRegistryJSON(
        serde_json::from_str(&installation.registration_json)
            .expect("decode exact installed server registry"),
    );
    exact_fields(
        &registry.0,
        &[
            "wire_revision",
            "profile",
            "source",
            "generation",
            "role",
            "artifact",
            "activation",
            "client_certificate",
            "server_certificate",
            "route",
            "route_digest",
            "activation_signing_key_id",
            "identity_seed",
            "dh_seed",
            "namespaces",
            "tunnels",
            "live_control_base_url",
            "relay_deployment",
        ],
    );
    exact_fields(&registry.0["generation"], &["source", "generation"]);
    for namespace in registry.0["namespaces"]
        .as_array()
        .expect("installed registry namespace array")
    {
        exact_fields(
            namespace,
            &[
                "tenant",
                "authority",
                "generation",
                "root_key_id",
                "root_public_key",
                "bootstrap_url",
                "state_url",
            ],
        );
    }
    for tunnel in registry.0["tunnels"]
        .as_array()
        .expect("installed registry tunnel array")
    {
        exact_fields(
            tunnel,
            &[
                "candidate_index",
                "role",
                "grant",
                "live_grant",
                "relay_certificate",
                "grant_namespace",
                "relay_namespace",
            ],
        );
        if !tunnel["live_grant"].is_null() {
            exact_fields(
                &tunnel["live_grant"],
                &[
                    "authority",
                    "issuer_key_id",
                    "audience",
                    "service",
                    "revocation_policy_id",
                    "revocation_policy_revision",
                    "max_not_after_ms",
                ],
            );
        }
    }
    registry.0["role"] = Value::from(1);
    for field in ["identity_seed", "dh_seed"] {
        if let Some(Value::String(seed)) = registry.0.get_mut(field) {
            seed.zeroize();
        }
    }
    registry.0["identity_seed"] = Value::String(installation.identity_seed.clone());
    registry.0["dh_seed"] = Value::String(installation.noise_seed.clone());
    let wire = Zeroizing::new(
        serde_json::to_string(&registry.0).expect("capture original installed server registry"),
    );
    let material = parse_current_material(&wire, 1);
    if material.source == "preauthorized_pool" {
        assert!(
            material.tunnels.is_empty(),
            "registered pool B requires its original unissued registry"
        );
        assert!(material.live_control_base_url.is_none() && installation.relay_control.is_none());
        assert!(
            installation.server_allow.is_some(),
            "registered pool B requires its independently installed Allow receiver"
        );
        configuration_path(&installation.control, "/flowersec/control/tunnel");
    } else {
        assert!(installation.server_allow.is_none());
        assert_eq!(material.source, "live_authority");
        assert_eq!(material.tunnels.len(), 2);
        assert_eq!(
            material.live_control_base_url.as_deref(),
            Some(installation.control.endpoint.as_str()),
            "installed B registry differs from its independently installed control endpoint"
        );
        let relay_certificate = current_bytes(&installation.relay_certificate, 8192, None);
        for role in 0..2 {
            let tunnel = material
                .tunnels
                .iter()
                .find(|tunnel| tunnel.role == role && tunnel.candidate_index == 0)
                .expect("independent server registry original pending hop");
            assert!(
                tunnel.grant.is_none(),
                "installed live server cannot import a pre-TxB Grant"
            );
            assert_eq!(
                current_bytes(&tunnel.relay_certificate, 8192, None),
                relay_certificate
            );
            let policy = tunnel
                .live_grant
                .as_ref()
                .expect("installed server pending live Grant policy");
            assert_eq!(policy.audience, installation.relay_audience);
            assert_eq!(policy.service, installation.relay_service);
            assert_eq!(
                policy.authority,
                material.namespaces[tunnel.grant_namespace as usize].authority
            );
            current_bytes(&policy.issuer_key_id, 16, Some(16));
            assert!(
                security_identifier(&policy.authority)
                    && security_identifier(&policy.revocation_policy_id),
                "invalid installed live hop policy"
            );
            for integer in [&policy.revocation_policy_revision, &policy.max_not_after_ms] {
                let value = integer
                    .parse::<u64>()
                    .expect("installed live hop canonical integer");
                assert!(
                    value > 0 && value.to_string() == *integer,
                    "installed live hop integer is not canonical"
                );
            }
        }
    }
    let relay_certificate = current_bytes(&installation.relay_certificate, 8192, None);
    let mut cursor = 0;
    let CurrentCborValue::Map(certificate) = current_cbor_value(&relay_certificate, &mut cursor, 0)
        .expect("installed relay certificate CBOR")
    else {
        panic!("installed relay certificate must be a map")
    };
    assert_eq!(
        cursor,
        relay_certificate.len(),
        "installed relay certificate has trailing bytes"
    );
    let CurrentCborValue::Text(subject) =
        current_cbor_map_field(&certificate, 1).expect("installed relay certificate subject")
    else {
        panic!("installed relay subject must be text")
    };
    assert_eq!(
        subject, &installation.relay_subject,
        "independent relay subject differs from its installed certificate"
    );
    assert_eq!(
        current_artifact_binding(&current_bytes(&material.artifact, 65536, None)).2,
        installation.relay_service,
        "installed relay service differs from the original server application binding"
    );
    Some(ServerDeployment {
        material,
        installation,
    })
}

pub(super) struct PoolRelayInstallation {
    pub(super) material: CurrentMaterial,
    pub(super) origin: String,
    relay_seed: Zeroizing<Vec<u8>>,
    server_identity: Zeroizing<Vec<u8>>,
    server_noise: Zeroizing<Vec<u8>>,
    relay_certificate: Vec<u8>,
    trust_pem: String,
    control_endpoint: String,
    native_tls: [ControlTLS; 3],
}
impl PoolRelayInstallation {
    pub(super) fn prepared(&self, value: &Value, carriers: [&str; 2]) {
        exact_fields(
            value,
            &[
                "type",
                "runtime",
                "wire_revision",
                "path",
                "source",
                "profile",
                "carrier",
                "server_carrier",
                "control_endpoint",
            ],
        );
        assert_eq!(value["type"], "relay-prepared");
        assert_eq!(value["runtime"], "rust");
        assert_eq!(value["wire_revision"], 4);
        assert_eq!(value["path"], "tunnel");
        assert_eq!(value["source"], "preauthorized_pool");
        assert_eq!(value["profile"], self.material.profile);
        assert_eq!(value["carrier"], carriers[0]);
        assert_eq!(value["server_carrier"], carriers[1]);
        assert_eq!(value["control_endpoint"], self.control_endpoint);
    }
    pub(super) fn match_original(
        &self,
        material: &[CurrentMaterial; 2],
        issued: &CurrentIssuerResponse,
    ) {
        assert_eq!(issued.trust_pem, self.trust_pem);
        assert_eq!(issued.origin, self.origin);
        assert_eq!(
            issued.client_tls_certificate_pem,
            self.native_tls[1].certificate_pem
        );
        assert_eq!(
            issued.server_tls_certificate_pem,
            self.native_tls[2].certificate_pem
        );
        assert!(
            issued.client_tls_private_key_pem == self.native_tls[1].private_key_pem,
            "issuer replaced independently installed A TLS identity"
        );
        assert!(
            issued.server_tls_private_key_pem == self.native_tls[2].private_key_pem,
            "issuer replaced independently installed B TLS identity"
        );
        for (side, endpoint) in issued.relay_endpoints.iter().enumerate() {
            let listener = super::current_tunnel::route_listener(&self.material, side as u8);
            let identity = &self.native_tls[if listener == side as u8 { side + 1 } else { 0 }];
            let certificate = CertificateDer::pem_slice_iter(identity.certificate_pem.as_bytes())
                .next()
                .expect("installed original listener certificate")
                .expect("decode installed original listener certificate");
            assert_eq!(
                current_bytes(&endpoint.server_certificate_der, 16384, None),
                certificate.as_ref()
            );
            let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(
                identity.private_key_pem.as_bytes(),
            )
            .expect("decode installed original listener key");
            assert!(
                Zeroizing::new(current_bytes(
                    endpoint
                        .server_private_key_pkcs8
                        .as_deref()
                        .expect("original listener key"),
                    16384,
                    None
                ))
                .as_slice()
                    == key.secret_der(),
                "issuer replaced independently installed listener TLS key"
            );
        }
        let seed = Zeroizing::new(current_bytes(
            issued
                .relay_identity_seed
                .as_deref()
                .expect("original relay signer"),
            32,
            Some(32),
        ));
        assert!(
            *seed == *self.relay_seed,
            "issuer replaced independently installed relay identity"
        );
        let own = &self.material;
        for m in material {
            assert!(
                m.artifact == own.artifact && m.activation == own.activation,
                "issuer replaced installed pool parent"
            );
            assert_eq!(m.client_certificate, own.client_certificate);
            assert_eq!(m.server_certificate, own.server_certificate);
            assert_eq!(m.route, own.route);
            assert_eq!(m.route_digest, own.route_digest);
            assert_eq!(m.namespaces, own.namespaces);
            assert_eq!(m.generation.source, own.generation.source);
            assert_eq!(m.generation.generation, own.generation.generation);
            assert_eq!(m.activation_signing_key_id, own.activation_signing_key_id);
            assert!(m.live_control_base_url.is_none());
            for slot in &m.tunnels {
                assert_eq!(
                    current_bytes(&slot.relay_certificate, 8192, None),
                    self.relay_certificate
                );
            }
        }
        assert!(
            material[0].identity_seed == own.identity_seed && material[0].dh_seed == own.dh_seed
        );
        assert!(
            Zeroizing::new(current_bytes(&material[1].identity_seed, 32, Some(32))).as_slice()
                == self.server_identity.as_slice()
        );
        assert!(
            Zeroizing::new(current_bytes(&material[1].dh_seed, 32, Some(32))).as_slice()
                == self.server_noise.as_slice()
        );
    }
}
pub(super) fn pool_relay_installation(path: &str) -> PoolRelayInstallation {
    assert!(!path.is_empty() && path.len() <= 4096 && std::path::Path::new(path).is_absolute());
    let mut file = std::fs::File::open(path).expect("open independently installed pool relay");
    let mut wire = Zeroizing::new(Vec::with_capacity(4194305));
    Read::by_ref(&mut file)
        .take(4194305)
        .read_to_end(&mut wire)
        .expect("read bounded pool relay installation");
    assert!(!wire.is_empty() && wire.len() <= 4194304);
    let installed = InstalledRegistryJSON(
        serde_json::from_slice(&wire).expect("decode original pool relay installation"),
    );
    let v = &installed.0;
    exact_fields(
        v,
        &[
            "wire_revision",
            "material_publication_path",
            "registration_json",
            "server_identity_seed",
            "server_dh_seed",
            "relay_identity_seed",
            "relay_certificate",
            "authority",
            "relay_audience",
            "relay_subject",
            "service",
            "control_trust_pem",
            "origin",
            "live_control",
            "remote_relay",
            "server_control",
            "signing",
            "limits",
            "native_tls",
        ],
    );
    assert_eq!(v["wire_revision"], 4);
    assert!(v["live_control"].is_null() && v["remote_relay"].is_null());
    assert_eq!(v["authority"], "winner-1");
    assert_eq!(v["relay_audience"], "flowersec.parity.relay");
    let text = |name| {
        v[name]
            .as_str()
            .expect("installed original pool relay text")
    };
    let material = parse_current_material(text("registration_json"), 0);
    assert_eq!(material.source, "preauthorized_pool");
    assert!(material.tunnels.is_empty() && material.live_control_base_url.is_none());
    assert_eq!(
        current_artifact_binding(&current_bytes(&material.artifact, 65536, None)).2,
        text("service")
    );
    let control = &v["server_control"];
    let host = control["host"]
        .as_str()
        .expect("original control host")
        .parse::<std::net::IpAddr>()
        .unwrap();
    assert!(host.is_loopback());
    let port = u16::try_from(control["port"].as_u64().unwrap()).unwrap();
    assert_ne!(port, 0);
    let control_endpoint = format!(
        "https://{}/flowersec/control/tunnel",
        SocketAddr::new(host, port)
    );
    let origin = text("origin").to_owned();
    assert!(!origin.is_empty() && origin.len() <= 2048);
    let trust_pem = v["native_tls"]["trustPEM"].as_str().unwrap().to_owned();
    assert!(!trust_pem.is_empty() && trust_pem.len() <= 1048576);
    let native_tls = ["relay", "client", "server"].map(|name| {
        serde_json::from_value(v["native_tls"][name].clone())
            .expect("original installed native TLS identity")
    });
    PoolRelayInstallation {
        material,
        origin,
        trust_pem,
        control_endpoint,
        native_tls,
        relay_seed: Zeroizing::new(current_bytes(text("relay_identity_seed"), 32, Some(32))),
        server_identity: Zeroizing::new(current_bytes(text("server_identity_seed"), 32, Some(32))),
        server_noise: Zeroizing::new(current_bytes(text("server_dh_seed"), 32, Some(32))),
        relay_certificate: current_bytes(text("relay_certificate"), 8192, None),
    }
}
