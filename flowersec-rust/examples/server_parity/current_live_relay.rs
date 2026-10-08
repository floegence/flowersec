//! Original live relay assembly consumes only the authority's public projection.
use super::*;

const MAXIMUM_PAIRS: usize = 1;
const NATIVE_RUNTIME_BYTES: u64 = 64 << 20;
const PREPARE_BYTES: usize = 65536;
const CONTROL_CONNECTIONS: usize = 3;
const CONTROL_RUNTIME_BYTES: u64 = 1 << 20;
const POOL_LIMITS: flowersec::SQLitePoolLimits = flowersec::SQLitePoolLimits {
    max_pages: 128,
    max_records: 16,
    max_record_bytes: 65536,
    provider_runtime_bytes: 262144,
    disk_overhead_bytes: 65536,
};

fn dual_native_listener_provider_bytes() -> u64 {
    // Each SharedRelayListener keeps two incoming positions per pair, including
    // its next accept, while one original policy prepays its eventual provider.
    // These physical and authenticated owners coexist until HELLO assignment.
    let connection = NATIVE_RUNTIME_BYTES + PREPARE_BYTES as u64 + 524288;
    let incoming_and_prepaid = (2 * MAXIMUM_PAIRS + MAXIMUM_PAIRS) as u64;
    let native = 2 * (262144 + NATIVE_RUNTIME_BYTES + incoming_and_prepaid * connection);
    // The parent and relay stores retain their two page/row buffers. The
    // control listener and all configured mTLS connections coexist with them.
    let store = u64::from(POOL_LIMITS.max_pages) * 4096 * 2
        + u64::from(POOL_LIMITS.max_record_bytes) * 2
        + 32768
        + POOL_LIMITS.provider_runtime_bytes;
    native + 2 * store + 262144 + CONTROL_CONNECTIONS as u64 * CONTROL_RUNTIME_BYTES
}

fn cbor_map(wire: &[u8]) -> Vec<(CurrentCborValue, CurrentCborValue)> {
    let mut cursor = 0;
    let CurrentCborValue::Map(fields) =
        current_cbor_value(wire, &mut cursor, 0).expect("original public relay CBOR")
    else {
        panic!("original public relay value must be a map")
    };
    assert_eq!(
        cursor,
        wire.len(),
        "original public relay map has trailing bytes"
    );
    fields
}
fn cbor_uint(fields: &[(CurrentCborValue, CurrentCborValue)], id: u64) -> u64 {
    let CurrentCborValue::Uint(value) =
        current_cbor_map_field(fields, id).expect("original public relay integer")
    else {
        panic!("original public relay field must be an integer")
    };
    *value
}
fn public_route(candidate: &[u8]) -> Vec<u8> {
    let mut candidate = cbor_map(candidate);
    assert_eq!(
        cbor_uint(&candidate, 2),
        1,
        "original public candidate must be a tunnel"
    );
    let mut route = vec![(CurrentCborValue::Uint(0), CurrentCborValue::Uint(1))];
    for (from, to) in [(0, 1), (4, 3), (5, 4)] {
        let index = candidate
            .iter()
            .position(|(key, _)| matches!(key, CurrentCborValue::Uint(value) if *value == from))
            .expect("original public candidate route field");
        let (_, value) = candidate.remove(index);
        route.push((CurrentCborValue::Uint(to), value));
    }
    let mut wire = Vec::with_capacity(16384);
    current_encode_cbor(&CurrentCborValue::Map(route), &mut wire);
    assert!(
        wire.len() <= 16384,
        "original public route exceeds its bound"
    );
    wire
}
fn listener_role(route: &[u8], role: u8) -> u8 {
    let route = cbor_map(route);
    let CurrentCborValue::Map(leg) = current_cbor_map_field(&route, if role == 0 { 3 } else { 4 })
        .expect("original public route leg")
    else {
        panic!("original public route leg must be a map")
    };
    u8::try_from(cbor_uint(leg, 4)).expect("original public listener role width")
}
fn certificate_chain(pem: &str) -> Vec<Vec<u8>> {
    assert!(
        !pem.is_empty() && pem.len() <= 1048576,
        "original installed TLS certificates exceed their input bound"
    );
    let chain = CertificateDer::pem_slice_iter(pem.as_bytes())
        .map(|certificate| {
            certificate
                .expect("original installed relay TLS certificate")
                .to_vec()
        })
        .collect::<Vec<_>>();
    assert!(
        !chain.is_empty()
            && chain.len() <= 16
            && chain
                .iter()
                .all(|certificate| !certificate.is_empty() && certificate.len() <= 65536),
        "original installed relay TLS chain exceeds the SDK bound"
    );
    chain
}
fn tls_identity(certificate: &str, private_key: &str) -> flowersec::WssServerIdentity {
    assert!(
        certificate.len() <= 262144 && !private_key.is_empty() && private_key.len() <= 65536,
        "original installed relay TLS identity exceeds its input bound"
    );
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(private_key.as_bytes())
        .expect("original installed relay TLS private key");
    assert!(
        matches!(&key, rustls::pki_types::PrivateKeyDer::Pkcs8(_))
            && key.secret_der().len() <= 8192,
        "original installed relay TLS identity requires a bounded PKCS8 key"
    );
    flowersec::WssServerIdentity {
        certificate_chain_der: certificate_chain(certificate),
        private_key_der: key.secret_der().to_vec(),
    }
}
async fn original_namespaces(
    environment: &flowersec::TransportEnvironment,
    records: &[CurrentNamespaceRecord],
    tenant: &str,
    trust_pem: &str,
) -> Vec<Arc<flowersec::Namespace>> {
    assert!(
        !records.is_empty() && records.len() <= 8,
        "original public relay requires bounded independent namespace pins"
    );
    let mut namespaces = Vec::with_capacity(records.len());
    for record in records {
        assert_eq!(
            record.tenant, tenant,
            "public relay namespace differs from its installed tenant"
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
            .expect("capture original independently installed relay namespace");
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
                    .expect("decode original public relay namespace bootstrap");
                let response = current_bytes(&reply.response, 65536, None);
                let state = current_bytes(&reply.state, 4096, None);
                Ok::<_, flowersec::EnvironmentError>((response, state))
            })
            .await
            .expect("verify original public relay namespace bootstrap");
        namespaces.push(namespace);
    }
    namespaces
}
fn original_ledgers(
    environment: &flowersec::TransportEnvironment,
    binding: flowersec::SQLiteRelayBinding,
    parent_identity: flowersec::SQLitePoolIdentity,
    relay_identity: flowersec::SQLitePoolIdentity,
) -> (CurrentPoolStore, RelayStore) {
    let parent_directory = current_store_directory("live-parent");
    let relay_directory = current_store_directory("live-relay");
    let limits = POOL_LIMITS;
    let backing = environment
        .sqlite_pool_backing(parent_directory.join("parent.sqlite"), limits)
        .expect("reserve original public relay parent disk backing");
    let parent = backing
        .open(flowersec::SQLitePoolOptions {
            identity: parent_identity,
            continuity: Arc::new(CurrentContinuity),
            bindings: vec![flowersec::SQLitePoolBinding {
                tenant: binding.tenant.clone(),
                issuer: binding.parent_issuer,
            }],
            create: true,
        })
        .expect("capture independently installed original public relay parent ledger");
    let parent = CurrentPoolStore {
        store: parent,
        backing,
        directory: parent_directory,
    };
    let backing = environment
        .sqlite_pool_backing(relay_directory.join("relay.sqlite"), limits)
        .expect("reserve original public relay disk backing");
    let ledger = backing
        .open_relay(flowersec::SQLiteRelayOptions {
            identity: relay_identity,
            continuity: Arc::new(CurrentContinuity),
            parent_authority: parent.store.clone(),
            bindings: vec![binding],
            create: true,
        })
        .expect("capture independently installed original public relay ledger");
    (
        parent,
        RelayStore {
            ledger,
            backing,
            directory: relay_directory,
        },
    )
}
#[expect(
    clippy::too_many_arguments,
    reason = "The relay fixture binds both original route and independently installed TLS identity explicitly."
)]
fn original_leg(
    route: &[u8],
    role: u8,
    expected_carrier: &str,
    endpoint_listener: bool,
    roots: &str,
    origin: &str,
    certificate: &str,
    private_key: &str,
) -> flowersec::WssRelayLegOptions {
    let (carrier, host, port, path, route_origin) = current_route_endpoint(route, role);
    assert_eq!(
        carrier,
        match expected_carrier {
            "raw-quic" => 0,
            "websocket" => 1,
            "webtransport" => 2,
            _ => panic!("invalid original relay carrier"),
        },
        "public route differs from requested relay carrier"
    );
    assert_eq!(
        listener_role(route, role),
        if endpoint_listener { role } else { 2 },
        "public route differs from requested relay topology"
    );
    assert!(
        matches!(
            (carrier, path.as_str()),
            (0, "") | (1, "/flowersec/v4/tunnel") | (2, "/flowersec/webtransport/v4/tunnel")
        ),
        "invalid original relay carrier path"
    );
    let remote_address = host.parse().unwrap_or_else(|_| {
        assert_eq!(
            host, "localhost",
            "original engineering relay requires a fixed local route"
        );
        "127.0.0.1".parse().unwrap()
    });
    if route_origin.is_some() {
        assert_eq!(
            route_origin.as_deref(),
            Some(origin),
            "public route differs from installed relay origin"
        );
    }
    let options = flowersec::WssConnectOptions {
        binding_mode: flowersec::BindingMode::AuthenticatedContext,
        remote_address,
        // Network Origin comes from the independent installation; the native
        // provider validates it against the original signed OriginPolicy.
        origin: (carrier == 1 || carrier == 2 && !endpoint_listener).then(|| origin.to_owned()),
        ca_certificates_der: certificate_chain(roots),
        timeout: Duration::from_secs(30),
        publication_timeout: Duration::from_secs(5),
        queue_messages: 16,
        prepare_bytes: PREPARE_BYTES,
        // Includes the original relay's mapping and provider queue windows.
        native_runtime_bytes: if carrier == 1 {
            1 << 20
        } else {
            NATIVE_RUNTIME_BYTES
        },
    };
    if endpoint_listener {
        return flowersec::WssRelayLegOptions::Dialer(options);
    }
    flowersec::WssRelayLegOptions::Listener(flowersec::ReverseTunnelProviderOptions {
        listen_address: SocketAddr::new(remote_address, port),
        identity: tls_identity(certificate, private_key),
        origin: options.origin,
        timeout: options.timeout,
        publication_timeout: options.publication_timeout,
        queue_messages: options.queue_messages,
        prepare_bytes: options.prepare_bytes,
        native_runtime_bytes: options.native_runtime_bytes,
    })
}

struct OriginalLiveRelay {
    host: Arc<flowersec::WssRelayHost>,
    receiver: flowersec::RelayOriginalDeliveryHandle,
    parent: CurrentPoolStore,
    ledger: RelayStore,
}
impl OriginalLiveRelay {
    async fn close(self) -> flowersec::RelayLiveForwardingProgress {
        self.receiver.close();
        self.host.close();
        let progress = self
            .receiver
            .wait_live_completion(Duration::from_secs(5), &CancellationToken::new())
            .await
            .expect("original staged live relay forwarding exit deadline");
        assert!(
            self.receiver
                .wait_cleanup()
                .await
                .expect("original staged live relay control cleanup")
                .complete,
            "original staged live relay retained a control worker"
        );
        assert!(
            self.host
                .wait_cleanup()
                .await
                .expect("original staged live relay native cleanup")
                .complete,
            "original staged live relay retained a physical provider or forwarding tail"
        );
        let Self {
            host,
            receiver,
            parent,
            ledger,
        } = self;
        drop(receiver);
        drop(host);
        drop(ledger);
        drop(parent);
        progress
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "The host fixture supplies independently installed namespace, ledger, TLS and control authority owners."
)]
async fn original_host(
    environment: &flowersec::TransportEnvironment,
    keys: flowersec::IdentityKeys,
    binding: flowersec::SQLiteRelayBinding,
    namespaces: Vec<Arc<flowersec::Namespace>>,
    parent_identity: flowersec::SQLitePoolIdentity,
    relay_identity: flowersec::SQLitePoolIdentity,
    host_options: flowersec::WssRelayHostOptions,
    control_identity: flowersec::WssServerIdentity,
    mut control_options: flowersec::RelayOriginalDeliveryOptions,
    deployment: flowersec::RelayLiveControlDeployment,
) -> OriginalLiveRelay {
    let (parent, ledger) = original_ledgers(
        environment,
        binding.clone(),
        parent_identity,
        relay_identity,
    );
    let host = Arc::new(
        environment
            .wss_relay_host(keys, ledger.ledger.clone(), host_options)
            .expect("capture original public live RelayHost and physical providers"),
    );
    control_options.issuers = vec![flowersec::RelayOriginalIssuer {
        leaf_digest: deployment.issuer_leaf_digest,
        binding,
        namespaces,
    }];
    let receiver = host
        .serve_original_live_control(control_identity, control_options, vec![deployment])
        .await
        .expect("bind original independently installed staged live relay control receiver");
    OriginalLiveRelay {
        host,
        receiver,
        parent,
        ledger,
    }
}
fn acknowledgement(
    message_type: &str,
    carrier: &str,
    server_carrier: &str,
    control_endpoint: &str,
    route_digest: &str,
    profile: &str,
    records: &[CurrentNamespaceRecord],
) {
    print_current_protocol_message(&serde_json::json!({
        "type":message_type,"runtime":"rust","path":"tunnel","wire_revision":4,"source":"live_authority",
        "carrier":carrier,"server_carrier":server_carrier,"control_endpoint":control_endpoint,
        "route_digest":route_digest,"profile":profile,"verification_records":records,
    }));
}
async fn commands(
    environment: flowersec::TransportEnvironment,
    original: OriginalLiveRelay,
    carriers: [&str; 2],
    control_endpoint: &str,
    route_digest: &str,
    profile: &str,
    records: &[CurrentNamespaceRecord],
) {
    // These acknowledgements describe only the original public installation.
    // The driver obtains endpoint material separately from the live authority.
    acknowledgement(
        "relay-prepared",
        carriers[0],
        carriers[1],
        control_endpoint,
        route_digest,
        profile,
        records,
    );
    let mut reader = io::stdin().lock();
    let configure: Value = serde_json::from_str(&read_line(&mut reader))
        .expect("original public relay configuration acknowledgement");
    assert_eq!(configure["type"].as_str(), Some("configure"));
    assert_eq!(configure["wire_revision"].as_u64(), Some(4));
    assert_eq!(configure["route_digest"].as_str(), Some(route_digest));
    assert!(
        configure["authorizations"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "live relay configure cannot install detached Grants"
    );
    assert_eq!(
        serde_json::from_value::<Vec<CurrentNamespaceRecord>>(
            configure["verification_records"].clone()
        )
        .unwrap(),
        records,
        "relay acknowledgement differs from independently installed namespace records"
    );
    // Forwarding starts only when the staged receiver has actually verified and
    // acknowledged both original Grants; configure grants no forwarding right.
    let close: Value =
        serde_json::from_str(&read_line(&mut reader)).expect("original public relay close command");
    assert_eq!(close["type"].as_str(), Some("close"));
    let progress = original.close().await;
    assert!(
        progress.installed == 1
            && progress.published == 1
            && progress.paired == 1
            && progress.ready_forwarded == 1,
        "original public live relay did not verify, pair and forward both READY records"
    );
    if carriers == ["raw-quic", "raw-quic"] {
        assert_eq!(
            progress.datagram_forwarded, 1,
            "original public live relay did not forward datagrams in both directions"
        );
    }
    assert!(
        environment.close().await.unwrap().complete,
        "original public live relay Environment retained ownership"
    );
    let mut cases = vec![
        "admission",
        "pairing",
        "opaque-forwarding",
        "close",
        "cancel",
        "cleanup",
    ];
    if carriers == ["raw-quic", "raw-quic"] {
        cases.push("datagram-forwarding");
    }
    print_current_protocol_message(
        &serde_json::json!({"type":"relay-result","runtime":"rust","carrier":carriers[0],
        "server_carrier":carriers[1],"path":"tunnel","wire_revision":4,"profile":profile,"source":"live_authority",
        "cases":cases,"observed_plaintext":false}),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RelayPublicLiveInstallation {
    wire_revision: u8,
    profile: String,
    origin: String,
    generation: u64,
    namespaces: Vec<CurrentNamespaceRecord>,
    bootstrap_trust_pem: String,
    binding: PublicBinding,
    candidate: String,
    session_contract: String,
    artifact_digest: String,
    lease_id: String,
    initiation_not_after_ms: String,
    session_not_after_ms: String,
    client_certificate: String,
    server_certificate: String,
    relay_certificate: String,
    issuer_leaf_digest: String,
    client_leaf_digest: String,
    server_leaf_digest: String,
    limits: PublicLimits,
    relay_identity_seed: String,
    native_tls: PublicNativeTLS,
    relay_control: PublicControl,
}
impl Drop for RelayPublicLiveInstallation {
    fn drop(&mut self) {
        self.relay_identity_seed.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicBinding {
    tenant: String,
    parent_issuer: String,
    grant_authority: String,
    parent_authority: String,
    server_admission_authority: String,
    relay_authority: String,
    service: String,
    relay_audience: String,
    relay_identity_digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicLimits {
    envelope_bytes: u64,
    total_bytes: String,
    datagram_bytes: u64,
    rate_bytes_per_second: String,
    queue_bytes: u64,
    pending_mappings: u64,
    resident_mappings: u64,
    total_mappings: u64,
    queue_items: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicNativeTLS {
    #[serde(rename = "trustPEM")]
    trust_pem: String,
    relay: PublicTLSIdentity,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicTLSIdentity {
    #[serde(rename = "certificatePEM")]
    certificate_pem: String,
    #[serde(rename = "privateKeyPEM")]
    private_key_pem: String,
}
impl Drop for PublicTLSIdentity {
    fn drop(&mut self) {
        self.private_key_pem.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicControl {
    endpoint: String,
    host: String,
    port: u16,
    tls: PublicControlTLS,
    #[serde(rename = "workMS")]
    work_ms: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicControlTLS {
    #[serde(rename = "certificatePEM")]
    certificate_pem: String,
    #[serde(rename = "privateKeyPEM")]
    private_key_pem: String,
    #[serde(rename = "clientTrustPEM")]
    client_trust_pem: String,
}
impl Drop for PublicControlTLS {
    fn drop(&mut self) {
        self.private_key_pem.zeroize();
    }
}
fn canonical_integer(text: &str) -> u64 {
    let value = text
        .parse::<u64>()
        .expect("original public relay canonical integer");
    assert!(
        value > 0 && value.to_string() == text,
        "original public relay integer is not canonical"
    );
    value
}
fn security_identifier(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index != 0 && matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-'))
        })
}
pub(super) fn installation() -> Option<RelayPublicLiveInstallation> {
    let path = env::var_os("FLOWERSEC_PARITY_RELAY_LIVE_DEPLOYMENT")?;
    if path.is_empty() {
        return None;
    }
    assert!(
        !path.is_empty() && path.len() <= 4096 && std::path::Path::new(&path).is_absolute(),
        "original public relay installation requires a bounded absolute path"
    );
    let mut file = std::fs::File::open(path)
        .expect("open independently installed original public live relay projection");
    let mut bytes = Zeroizing::new(Vec::with_capacity(4194305));
    Read::by_ref(&mut file)
        .take(4194305)
        .read_to_end(&mut bytes)
        .expect("read bounded original public live relay installation");
    assert!(
        !bytes.is_empty() && bytes.len() <= 4194304,
        "original public live relay installation exceeds its file bound"
    );
    Some(
        serde_json::from_slice(&bytes)
            .expect("decode exact authority-exported public live relay installation"),
    )
}
pub(super) async fn run(
    installed: RelayPublicLiveInstallation,
    carrier: &str,
    server_carrier: &str,
    endpoint_listeners: [bool; 2],
) {
    assert_eq!(installed.wire_revision, 4);
    assert_eq!(installed.profile, CURRENT_PROFILE);
    for id in [
        &installed.binding.tenant,
        &installed.binding.grant_authority,
        &installed.binding.parent_authority,
        &installed.binding.server_admission_authority,
        &installed.binding.relay_authority,
        &installed.binding.service,
        &installed.binding.relay_audience,
    ] {
        assert!(
            security_identifier(id),
            "invalid independent public relay binding scope"
        );
    }
    assert!(
        !installed.origin.is_empty() && installed.origin.len() <= 2048,
        "invalid independently installed public relay origin"
    );
    assert!(
        !installed.bootstrap_trust_pem.is_empty() && installed.bootstrap_trust_pem.len() <= 1048576,
        "independent public relay bootstrap trust exceeds its bound"
    );
    assert!(
        installed
            .namespaces
            .iter()
            .any(|record| record.authority == installed.binding.grant_authority),
        "independent public relay Grant authority has no installed namespace pin"
    );
    let provider_bytes = (endpoint_listeners == [false, false]
        && matches!(carrier, "raw-quic" | "webtransport")
        && matches!(server_carrier, "raw-quic" | "webtransport"))
    .then(dual_native_listener_provider_bytes);
    let environment = current_environment_for_role(true, false, provider_bytes);
    let cancel = CancellationToken::new();
    let namespaces = original_namespaces(
        &environment,
        &installed.namespaces,
        &installed.binding.tenant,
        &installed.bootstrap_trust_pem,
    )
    .await;
    let relay_certificate = current_bytes(&installed.relay_certificate, 8192, None);
    let relay_identity_digest: [u8; 32] =
        current_bytes(&installed.binding.relay_identity_digest, 32, Some(32))
            .try_into()
            .unwrap();
    assert_eq!(
        relay_identity_digest,
        current_certificate_digest(&relay_certificate),
        "independent public relay identity differs from its original certificate"
    );
    let candidate = current_bytes(&installed.candidate, 16384, None);
    let route = public_route(&candidate);
    let mut route_hash = Sha256::new();
    route_hash.update(b"flowersec/v4/route\0");
    route_hash.update(u32::try_from(route.len()).unwrap().to_be_bytes());
    route_hash.update(&route);
    let route_digest = STANDARD.encode(route_hash.finalize());
    let artifact_digest: [u8; 32] = current_bytes(&installed.artifact_digest, 32, Some(32))
        .try_into()
        .unwrap();
    let seed = Zeroizing::new(current_bytes(&installed.relay_identity_seed, 32, Some(32)));
    assert!(
        seed.iter().any(|byte| *byte != 0),
        "original relay own identity seed must be nonzero"
    );
    // Relay owns no endpoint Noise state. The SDK key container retains only
    // this relay's local seed; native HOP authentication uses its signing key.
    let keys = environment
        .import_identity_keys(
            &installed.profile,
            seed.as_slice().try_into().unwrap(),
            seed.as_slice().try_into().unwrap(),
        )
        .expect("capture independently installed relay own HOP identity");
    let binding = flowersec::SQLiteRelayBinding {
        tenant: installed.binding.tenant.clone(),
        parent_issuer: current_bytes(&installed.binding.parent_issuer, 16, Some(16))
            .try_into()
            .unwrap(),
        server_admission_authority: installed.binding.server_admission_authority.clone(),
        service: installed.binding.service.clone(),
        relay_audience: installed.binding.relay_audience.clone(),
        relay_identity_digest,
    };
    let store_id: [u8; 32] = Sha256::digest(artifact_digest).into();
    let generation = installed.generation;
    assert!(
        generation > 0,
        "original public relay installation generation must be nonzero"
    );
    let parent_identity = flowersec::SQLitePoolIdentity {
        authority: installed.binding.parent_authority.clone(),
        store_id,
        generation,
    };
    let relay_identity = flowersec::SQLitePoolIdentity {
        authority: installed.binding.relay_authority.clone(),
        store_id,
        generation,
    };
    let host_options = flowersec::WssRelayHostOptions {
        client_leg: original_leg(
            &route,
            0,
            carrier,
            endpoint_listeners[0],
            &installed.native_tls.trust_pem,
            &installed.origin,
            &installed.native_tls.relay.certificate_pem,
            &installed.native_tls.relay.private_key_pem,
        ),
        server_leg: original_leg(
            &route,
            1,
            server_carrier,
            endpoint_listeners[1],
            &installed.native_tls.trust_pem,
            &installed.origin,
            &installed.native_tls.relay.certificate_pem,
            &installed.native_tls.relay.private_key_pem,
        ),
        maximum_pairs: MAXIMUM_PAIRS,
        cancellation: cancel.clone(),
    };
    let work_ms = canonical_integer(&installed.relay_control.work_ms);
    assert!(
        work_ms <= 30000,
        "installed original relay control work exceeds the SDK bound"
    );
    let address = installed
        .relay_control
        .host
        .parse::<std::net::IpAddr>()
        .expect("fixed independent relay control listener address");
    assert!(
        address.is_loopback() && installed.relay_control.port != 0,
        "original engineering relay control needs one fixed loopback listener"
    );
    let listen_address = SocketAddr::new(address, installed.relay_control.port);
    let control_endpoint = &installed.relay_control.endpoint;
    assert!(
        !control_endpoint.is_empty() && control_endpoint.len() <= 2048,
        "independent original relay control endpoint exceeds its input bound"
    );
    let endpoint = Url::parse(control_endpoint)
        .expect("exact independently installed original relay control endpoint");
    assert!(
        endpoint.scheme() == "https"
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none()
            && endpoint.fragment().is_none()
            && endpoint.path() == "/"
            && control_endpoint
                .strip_prefix("https://")
                .and_then(|origin| origin.split_once('/'))
                .is_some_and(|(_, path)| path.is_empty()),
        "original relay control requires the exact installed HTTPS root endpoint"
    );
    assert_eq!(
        endpoint.port_or_known_default(),
        Some(installed.relay_control.port),
        "original relay control endpoint differs from its installed listener port"
    );
    let (endpoint_address, http_authority) = match endpoint
        .host()
        .expect("original relay control endpoint hostname")
    {
        url::Host::Domain(host) => {
            assert_eq!(
                host, "localhost",
                "engineering relay control requires a fixed numeric address or localhost"
            );
            (
                "127.0.0.1".parse().unwrap(),
                format!("{host}:{}", installed.relay_control.port),
            )
        }
        url::Host::Ipv4(host) => (
            std::net::IpAddr::V4(host),
            format!("{host}:{}", installed.relay_control.port),
        ),
        url::Host::Ipv6(host) => (
            std::net::IpAddr::V6(host),
            format!("[{host}]:{}", installed.relay_control.port),
        ),
    };
    assert_eq!(
        endpoint_address, address,
        "original relay control endpoint differs from its independent numeric listener"
    );
    let control_identity = tls_identity(
        &installed.relay_control.tls.certificate_pem,
        &installed.relay_control.tls.private_key_pem,
    );
    let control_options = flowersec::RelayOriginalDeliveryOptions {
        listen_address,
        authority: http_authority,
        client_roots_der: certificate_chain(&installed.relay_control.tls.client_trust_pem),
        issuers: Vec::new(),
        maximum_publications: 1,
        maximum_connections: CONTROL_CONNECTIONS,
        timeout: Duration::from_millis(work_ms),
        provider_runtime_bytes: CONTROL_RUNTIME_BYTES,
        cancellation: cancel.clone(),
    };
    let deployment = flowersec::RelayLiveControlDeployment {
        issuer_leaf_digest: current_bytes(&installed.issuer_leaf_digest, 32, Some(32))
            .try_into()
            .unwrap(),
        client_leaf_digest: current_bytes(&installed.client_leaf_digest, 32, Some(32))
            .try_into()
            .unwrap(),
        server_leaf_digest: current_bytes(&installed.server_leaf_digest, 32, Some(32))
            .try_into()
            .unwrap(),
        artifact_digest,
        lease_id: current_bytes(&installed.lease_id, 16, Some(16))
            .try_into()
            .unwrap(),
        initiation_not_after_ms: canonical_integer(&installed.initiation_not_after_ms),
        session_not_after_ms: canonical_integer(&installed.session_not_after_ms),
        candidate,
        session_contract: current_bytes(&installed.session_contract, 65536, None),
        client_certificate: current_bytes(&installed.client_certificate, 8192, None),
        server_certificate: current_bytes(&installed.server_certificate, 8192, None),
        relay_certificate,
        limits: flowersec::RelayLivePreparationLimits {
            max_envelope_bytes: installed.limits.envelope_bytes,
            max_total_bytes: canonical_integer(&installed.limits.total_bytes),
            max_datagram_bytes: installed.limits.datagram_bytes,
            max_rate_bytes_per_s: canonical_integer(&installed.limits.rate_bytes_per_second),
            max_queue_bytes: installed.limits.queue_bytes,
            max_queue_items: installed.limits.queue_items,
            max_pending_native_mappings: installed.limits.pending_mappings,
            max_resident_native_mappings: installed.limits.resident_mappings,
            max_total_native_mappings: installed.limits.total_mappings,
        },
    };
    let original = original_host(
        &environment,
        keys,
        binding,
        namespaces,
        parent_identity,
        relay_identity,
        host_options,
        control_identity,
        control_options,
        deployment,
    )
    .await;
    for (role, endpoint_listener) in endpoint_listeners.iter().enumerate() {
        if !endpoint_listener {
            let (_, host, port, _, _) = current_route_endpoint(&route, role as u8);
            let host = host.parse().unwrap_or_else(|_| {
                assert_eq!(host, "localhost");
                "127.0.0.1".parse().unwrap()
            });
            assert_eq!(
                original
                    .host
                    .wait_listener_ready(role as u8, Duration::from_secs(10), &cancel)
                    .await
                    .expect("original live relay listener physical readiness"),
                SocketAddr::new(host, port)
            );
        }
    }
    commands(
        environment,
        original,
        [carrier, server_carrier],
        control_endpoint,
        &route_digest,
        &installed.profile,
        &installed.namespaces,
    )
    .await;
}
