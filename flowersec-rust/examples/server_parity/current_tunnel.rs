use super::*;

#[path = "current_live_relay.rs"]
mod current_live_relay;

#[derive(Clone, Deserialize, Serialize)]
struct RelayReady {
    #[serde(rename = "type")]
    message_type: String,
    runtime: String,
    carrier: String,
    server_carrier: String,
    path: String,
    wire_revision: u8,
    endpoint_a_artifact_json: String,
    endpoint_b_artifact_json: String,
    trust_pem: String,
    #[serde(default)]
    client_tls_certificate_pem: String,
    #[serde(default)]
    client_tls_private_key_pem: String,
    #[serde(default)]
    server_tls_certificate_pem: String,
    #[serde(default)]
    server_tls_private_key_pem: String,
    origin: String,
    route_digest: String,
    profile: String,
    source: String,
    authorizations: Vec<CurrentTunnelAuthorization>,
    verification_records: Vec<CurrentNamespaceRecord>,
}
impl std::fmt::Debug for RelayReady {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RelayReady { <opaque> }")
    }
}
impl Drop for RelayReady {
    fn drop(&mut self) {
        self.endpoint_a_artifact_json.zeroize();
        self.endpoint_b_artifact_json.zeroize();
        self.client_tls_private_key_pem.zeroize();
        self.server_tls_private_key_pem.zeroize();
    }
}
#[derive(Debug, Deserialize)]
struct EndpointBInput {
    topology: TunnelTopology,
    relay: RelayReady,
}
#[derive(Clone, Deserialize, Serialize)]
struct EndpointBReady {
    #[serde(rename = "type")]
    message_type: String,
    runtime: String,
    carrier: String,
    path: String,
    wire_revision: u8,
    endpoint_a_artifact_json: String,
    endpoint_b_artifact_json: String,
    relay: RelayReady,
    profile: String,
    source: String,
    authorizations: Vec<CurrentTunnelAuthorization>,
    verification_records: Vec<CurrentNamespaceRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server_allow: Option<current_live_deployment::PoolServerAllowBinding>,
}
impl std::fmt::Debug for EndpointBReady {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EndpointBReady { <opaque> }")
    }
}
impl Drop for EndpointBReady {
    fn drop(&mut self) {
        self.endpoint_a_artifact_json.zeroize();
        self.endpoint_b_artifact_json.zeroize();
    }
}
#[derive(Debug, Deserialize)]
struct EndpointAInput {
    topology: TunnelTopology,
    endpoint_b: EndpointBReady,
}

fn read_line(reader: &mut impl BufRead) -> Zeroizing<String> {
    read_current_protocol_line(reader)
}
pub(super) fn route_listener(material: &CurrentMaterial, role: u8) -> u8 {
    let route = current_bytes(&material.route, 16_384, None);
    let mut cursor = 0;
    let CurrentCborValue::Map(root) = current_cbor_value(&route, &mut cursor, 0).unwrap() else {
        panic!("invalid tunnel Route")
    };
    let CurrentCborValue::Map(leg) =
        current_cbor_map_field(&root, if role == 0 { 3 } else { 4 }).expect("original tunnel leg")
    else {
        panic!("invalid tunnel leg")
    };
    let CurrentCborValue::Uint(listener) =
        current_cbor_map_field(leg, 4).expect("signed listener role")
    else {
        panic!("invalid listener role")
    };
    u8::try_from(*listener).expect("signed listener role range")
}
fn validate_pool_pair(relay: &RelayReady) -> [CurrentMaterial; 2] {
    assert_eq!(relay.message_type, "relay-ready");
    assert_eq!(relay.path, "tunnel");
    assert_eq!(relay.wire_revision, 4);
    assert!(matches!(
        relay.carrier.as_str(),
        "websocket" | "raw-quic" | "webtransport"
    ));
    assert!(matches!(
        relay.server_carrier.as_str(),
        "websocket" | "raw-quic" | "webtransport"
    ));
    assert!(!relay.trust_pem.is_empty() && !relay.origin.is_empty());
    let original = [
        parse_current_material(&relay.endpoint_a_artifact_json, 0),
        parse_current_material(&relay.endpoint_b_artifact_json, 1),
    ];
    assert!(
        original[0].artifact == original[1].artifact,
        "relay must publish one original parent"
    );
    assert_eq!(
        original[0].activation, original[1].activation,
        "relay must publish one original activation"
    );
    assert_eq!(
        original[0].route, original[1].route,
        "relay must publish one original route"
    );
    assert_eq!(
        original[0].client_certificate,
        original[1].client_certificate
    );
    assert_eq!(
        original[0].server_certificate,
        original[1].server_certificate
    );
    assert_eq!(original[0].namespaces, original[1].namespaces);
    assert_eq!(
        original[0].namespaces, relay.verification_records,
        "acknowledged namespaces differ from original publication"
    );
    for material in &original {
        assert_eq!(material.profile, relay.profile);
        assert_eq!(material.source, relay.source);
        assert_eq!(
            current_bytes(&material.route_digest, 32, Some(32)),
            current_bytes(&relay.route_digest, 32, Some(32))
        );
    }
    assert_eq!(
        relay.source, "preauthorized_pool",
        "invalid original tunnel source"
    );
    assert_eq!(
        relay.authorizations.len(),
        2,
        "original paired pool publication must include both public hop records"
    );
    for role in 0..=1 {
        let slot = original[role as usize]
            .tunnels
            .iter()
            .find(|slot| slot.role == role && slot.candidate_index == 0)
            .expect("original candidate hop slot");
        let authorization = relay
            .authorizations
            .iter()
            .find(|record| record.role == role && record.candidate_index == slot.candidate_index)
            .expect("original detached hop authorization");
        assert_eq!(slot.grant.as_deref(), Some(authorization.grant.as_str()));
        assert_eq!(slot.relay_certificate, authorization.relay_certificate);
        assert_eq!(slot.grant_namespace, authorization.grant_namespace);
        assert_eq!(slot.relay_namespace, authorization.relay_namespace);
        assert_eq!(
            authorization.endpoint_certificate,
            if role == 0 {
                original[0].client_certificate.clone()
            } else {
                original[0].server_certificate.clone()
            }
        );
    }
    original
}
fn validate_endpoint(relay: &RelayReady, role: u8) -> CurrentMaterial {
    assert!(role <= 1, "invalid original endpoint role");
    if relay.source == "preauthorized_pool" {
        return validate_pool_pair(relay)
            .into_iter()
            .nth(role as usize)
            .unwrap();
    }
    assert_eq!(
        relay.source, "live_authority",
        "invalid original endpoint source"
    );
    assert_eq!(relay.message_type, "relay-ready");
    assert_eq!(relay.path, "tunnel");
    assert_eq!(relay.wire_revision, 4);
    assert!(matches!(
        relay.carrier.as_str(),
        "websocket" | "raw-quic" | "webtransport"
    ));
    assert!(matches!(
        relay.server_carrier.as_str(),
        "websocket" | "raw-quic" | "webtransport"
    ));
    assert!(!relay.trust_pem.is_empty() && !relay.origin.is_empty());
    assert!(
        relay.authorizations.is_empty(),
        "live publication cannot contain detached authorizations"
    );
    let own = if role == 0 {
        assert!(
            relay.endpoint_b_artifact_json.is_empty()
                && relay.server_tls_private_key_pem.is_empty(),
            "live A cannot receive B private material"
        );
        &relay.endpoint_a_artifact_json
    } else {
        assert!(
            relay.endpoint_a_artifact_json.is_empty()
                && relay.client_tls_private_key_pem.is_empty(),
            "live B cannot receive A private material"
        );
        &relay.endpoint_b_artifact_json
    };
    let material = parse_current_material(own, role);
    assert_eq!(material.profile, relay.profile);
    assert_eq!(material.source, relay.source);
    assert_eq!(
        material.namespaces, relay.verification_records,
        "live endpoint namespace pins differ from original publication"
    );
    assert_eq!(
        current_bytes(&material.route_digest, 32, Some(32)),
        current_bytes(&relay.route_digest, 32, Some(32))
    );
    assert_eq!(
        material.tunnels.len(),
        2,
        "live endpoint requires both original pending leg policies"
    );
    for expected in 0..=1 {
        let slots = material
            .tunnels
            .iter()
            .filter(|slot| slot.role == expected && slot.candidate_index == 0)
            .collect::<Vec<_>>();
        assert_eq!(
            slots.len(),
            1,
            "live endpoint leg association differs from its original candidate"
        );
        assert!(
            slots[0].grant.is_none() && slots[0].live_grant.is_some(),
            "live endpoint contains an issued or missing hop policy"
        );
    }
    material
}

fn tunnel_credential(
    environment: &flowersec::TransportEnvironment,
    material: &CurrentMaterial,
) -> (
    flowersec::IdentityKeys,
    flowersec::TunnelPoolCredentialBytes,
) {
    let (identity, connection) = current_identity_and_credential(environment, material);
    let tunnel = material
        .tunnels
        .iter()
        .find(|slot| slot.role == material.role && slot.candidate_index == 0)
        .expect("original selected tunnel hop");
    let credential = flowersec::TunnelPoolCredentialBytes {
        connection,
        grant: current_bytes(
            tunnel.grant.as_deref().expect("original pool Grant"),
            65536,
            None,
        ),
        relay_certificate: current_bytes(&tunnel.relay_certificate, 8192, None),
    };
    (identity, credential)
}
fn reverse_options(
    material: &CurrentMaterial,
    relay: &RelayReady,
    carrier: &str,
) -> flowersec::ReverseTunnelProviderOptions {
    let options = current_provider_options(
        material,
        &relay.trust_pem,
        material.role,
        carrier,
        &relay.origin,
    );
    let (_, _, port, _, _) =
        current_route_endpoint(&current_bytes(&material.route, 16_384, None), material.role);
    let (certificate, private_key) = if material.role == 0 {
        (
            &relay.client_tls_certificate_pem,
            &relay.client_tls_private_key_pem,
        )
    } else {
        (
            &relay.server_tls_certificate_pem,
            &relay.server_tls_private_key_pem,
        )
    };
    let certificates = CertificateDer::pem_slice_iter(certificate.as_bytes())
        .map(|certificate| {
            certificate
                .expect("original endpoint TLS certificate")
                .to_vec()
        })
        .collect::<Vec<_>>();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(private_key.as_bytes())
        .expect("original endpoint TLS private key");
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
fn admission(
    environment: &flowersec::TransportEnvironment,
    material: &CurrentMaterial,
    credential: &flowersec::PoolCredentialBytes,
) -> (
    CurrentPoolStore,
    CurrentPoolStore,
    Arc<flowersec::SQLiteAdmissionAuthority>,
) {
    let accepted =
        current_pool_store_named(environment, material, &credential.artifact, "accepted");
    let parent = current_pool_store_named(environment, material, &credential.artifact, "parent");
    let (tenant, issuer, audience) = current_artifact_binding(&credential.artifact);
    let server_identity_digest: [u8; 32] =
        current_certificate_digest(&credential.server_certificate);
    let authority = flowersec::SQLiteAdmissionAuthority::new(
        accepted.store.clone(),
        parent.store.clone(),
        vec![flowersec::SQLiteAdmissionBinding {
            tenant,
            issuer,
            server_identity_digest,
            audience,
        }],
    )
    .expect("capture original tunnel admission");
    (accepted, parent, authority)
}
// The engineering issuer fixes these scopes independently of peer HELLO and
// detached Grants. SDK verification checks the signed hop against them.
const RELAY_AUDIENCE: &str = "flowersec.parity.relay";
fn relay_service(material: &CurrentMaterial) -> String {
    current_artifact_binding(&current_bytes(&material.artifact, 65536, None)).2
}
fn limits() -> flowersec::ApplicationLimits {
    flowersec::ApplicationLimits {
        ordinary_callbacks: 8,
        ordinary_callback_bytes: 65536,
        control_callback_bytes: 65536,
    }
}
struct PreparedLiveEndpointB {
    deployment: current_live_deployment::ServerDeployment,
    namespaces: Vec<Arc<flowersec::Namespace>>,
    keys: flowersec::IdentityKeys,
    source: Arc<flowersec::OriginalLiveAcceptedSource>,
    publication: flowersec::RegisteredLiveTunnelServerPublication,
    listener: Option<flowersec::LiveReverseTunnelListener>,
    provider: flowersec::WssConnectOptions,
}
async fn prepare_live_endpoint_b(
    environment: &flowersec::TransportEnvironment,
    deployment: current_live_deployment::ServerDeployment,
    carrier: &str,
    cancel: &CancellationToken,
) -> PreparedLiveEndpointB {
    let material = &deployment.material;
    let namespaces = current_live_deployment::bootstrap_namespaces(
        environment,
        material,
        deployment.trust_pem(),
    )
    .await;
    let keys = current_identity(environment, material);
    let source = environment
        .live_accepted_material_source(namespaces.clone(), keys.clone(), 1)
        .expect("retain independently installed original live B source");
    let publication = source
        .register_tunnel_original(
            deployment.connection(),
            deployment.relay_certificate(),
            deployment.relay_service(),
            deployment.relay_audience(),
        )
        .expect("register original live B before reading relay readiness");
    let provider = deployment.provider(carrier);
    let listener_role = route_listener(material, 1);
    let listener = if listener_role == 1 {
        let (_, host, _, _, _) =
            current_route_endpoint(&current_bytes(&material.route, 16384, None), 1);
        let native_carrier = match carrier {
            "websocket" => flowersec::LiveAuthorityCarrier::WebSocket,
            "raw-quic" => flowersec::LiveAuthorityCarrier::RawQuic,
            "webtransport" => flowersec::LiveAuthorityCarrier::WebTransport,
            _ => panic!("invalid original live B carrier"),
        };
        Some(
            environment
                .prepare_live_reverse_tunnel_listener(
                    deployment.reverse_provider(carrier),
                    native_carrier,
                    host,
                    1,
                )
                .expect("bind independently installed original live B listener"),
        )
    } else {
        assert_eq!(listener_role, 2, "invalid original live B tunnel direction");
        None
    };
    // Registration retains this same physical owner: listener READY precedes
    // the control call, while a dialed carrier can prepare alongside it.
    let preparation = match &listener {
        Some(listener) => flowersec::RegisteredLiveServerPreparation::Listener(listener),
        None => flowersec::RegisteredLiveServerPreparation::Carrier(provider.clone()),
    };
    let publication = publication
        .register_original_control(deployment.control(), preparation, cancel)
        .await
        .expect("complete original registered live B control and carrier preparation");
    PreparedLiveEndpointB {
        deployment,
        namespaces,
        keys,
        source,
        publication,
        listener,
        provider,
    }
}
fn publish_endpoint_b_ready(
    input: &EndpointBInput,
    carrier: &str,
    server_allow: Option<current_live_deployment::PoolServerAllowBinding>,
) {
    let ready = EndpointBReady {
        message_type: "endpoint-b-ready".into(),
        runtime: "rust".into(),
        carrier: carrier.into(),
        path: "tunnel".into(),
        wire_revision: 4,
        endpoint_a_artifact_json: input.relay.endpoint_a_artifact_json.clone(),
        endpoint_b_artifact_json: input.relay.endpoint_b_artifact_json.clone(),
        profile: input.relay.profile.clone(),
        source: input.relay.source.clone(),
        authorizations: input.relay.authorizations.clone(),
        verification_records: input.relay.verification_records.clone(),
        relay: input.relay.clone(),
        server_allow,
    };
    print_current_protocol_message(&ready);
}
async fn endpoint_b_live(
    environment: flowersec::TransportEnvironment,
    prepared: PreparedLiveEndpointB,
    input: EndpointBInput,
    published: &CurrentMaterial,
    carrier: &str,
    cancel: CancellationToken,
    reader: &mut impl BufRead,
) {
    let PreparedLiveEndpointB {
        deployment,
        namespaces,
        keys,
        source,
        publication,
        listener,
        provider,
    } = prepared;
    deployment.match_publication(
        published,
        &input.relay.trust_pem,
        &input.relay.origin,
        (
            &input.relay.server_tls_certificate_pem,
            &input.relay.server_tls_private_key_pem,
        ),
        listener.is_some(),
    );
    let (accepted, parent, admission) =
        admission(&environment, &deployment.material, &deployment.connection());
    let ledger = ExecutionLedger::default();
    let application = current_application::Application::new(ledger.clone());
    let plan = current_application::plan(&environment, application.clone());
    let callbacks = Arc::new(CurrentParityCallbacks {
        plan: plan.clone(),
        application: Some(application.clone()),
    });
    publish_endpoint_b_ready(&input, carrier, None);
    let command: Value =
        serde_json::from_str(&read_line(reader)).expect("original live server connect command");
    assert_eq!(command.get("type").and_then(Value::as_str), Some("connect"));
    // Only B's own original live_receive yields its proof and server Grant.
    // The SDK validates them on the retained Account before acknowledging Allow.
    let material = publication
        .receive_original_publication(&cancel)
        .await
        .expect("consume original registered live B publication");
    let serve = match listener {
        Some(listener) => {
            environment
                .serve_original_live_tunnel_material_on_original_listener(
                    material,
                    namespaces,
                    keys,
                    deployment.relay_service(),
                    deployment.relay_audience(),
                    admission,
                    flowersec::LiveReverseTunnelServeOptions {
                        listener,
                        callbacks,
                        application_limits: limits(),
                        cancellation: cancel.clone(),
                    },
                )
                .await
        }
        None => {
            environment
                .serve_original_live_tunnel_material(
                    material,
                    namespaces,
                    keys,
                    deployment.relay_service(),
                    deployment.relay_audience(),
                    admission,
                    flowersec::TunnelServeOptions {
                        callbacks,
                        application_limits: limits(),
                        cancellation: cancel.clone(),
                        provider,
                    },
                )
                .await
        }
    }
    .expect("Serve the exact original live B owner");
    let session = serve
        .accept()
        .await
        .expect("accept original registered live B Session");
    ledger.record(&["admission"]);
    current_application::server(
        &session,
        &application,
        "tunnel",
        input.relay.carrier != "websocket" && carrier != "websocket",
    )
    .await;
    session.close();
    assert!(
        session.wait_cleanup().await.complete,
        "original live B Session cleanup is incomplete"
    );
    serve.close();
    assert!(
        serve
            .wait_cleanup()
            .await
            .expect("original live B Serve cleanup")
            .complete,
        "original live B Serve cleanup is incomplete"
    );
    source.close();
    drop(session);
    drop(serve);
    drop(application);
    plan.close();
    drop(plan);
    drop(accepted);
    drop(parent);
    drop(source);
    drop(deployment);
    assert!(
        environment.close().await.unwrap().complete,
        "original live B Environment retained ownership"
    );
    ledger.record(&["close", "cleanup"]);
    print_current_result(
        "endpoint-b-result",
        carrier,
        "tunnel",
        &input.relay.profile,
        &input.relay.source,
        &ledger,
    );
}
struct PreparedPoolEndpointB {
    deployment: current_live_deployment::ServerDeployment,
    grants: [[u8; 32]; 2],
    binding: current_live_deployment::PoolServerAllowBinding,
    runtime: PoolEndpointBRuntime,
}
struct PoolEndpointBRuntime {
    serve: flowersec::TunnelServeHandle,
    accepted: CurrentPoolStore,
    parent: CurrentPoolStore,
    ledger: ExecutionLedger,
    application: Arc<current_application::Application>,
    plan: flowersec::HandlerPlan,
}
async fn prepare_pool_endpoint_b(
    environment: &flowersec::TransportEnvironment,
    deployment: current_live_deployment::ServerDeployment,
    carrier: &str,
    cancel: &CancellationToken,
) -> PreparedPoolEndpointB {
    let namespaces = current_live_deployment::bootstrap_namespaces(
        environment,
        &deployment.material,
        deployment.trust_pem(),
    )
    .await;
    let keys = current_identity(environment, &deployment.material);
    let original = environment
        .register_pool_tunnel_server(namespaces, keys, deployment.pool_control(), cancel.clone())
        .await
        .expect("acquire and verify the original registered pool B issuance");
    let grants = original.grant_bytes_digests();
    let (accepted, parent, admission) =
        admission(environment, &deployment.material, &deployment.connection());
    let ledger = ExecutionLedger::default();
    let application = current_application::Application::new(ledger.clone());
    let plan = current_application::plan(environment, application.clone());
    let callbacks = Arc::new(CurrentParityCallbacks {
        plan: plan.clone(),
        application: Some(application.clone()),
    });
    let listener = route_listener(&deployment.material, 1);
    let serve = if listener == 1 {
        original
            .serve_reverse(
                admission,
                flowersec::ReverseTunnelServeOptions {
                    callbacks,
                    application_limits: limits(),
                    cancellation: cancel.clone(),
                    provider: deployment.reverse_provider(carrier),
                },
            )
            .await
    } else {
        assert_eq!(listener, 2);
        original
            .serve(
                admission,
                flowersec::TunnelServeOptions {
                    callbacks,
                    application_limits: limits(),
                    cancellation: cancel.clone(),
                    provider: deployment.provider(carrier),
                },
            )
            .await
    }
    .expect("transfer one original verified pool B owner into Serve");
    if listener == 1 {
        serve
            .wait_reverse_listener_ready(Duration::from_secs(10), cancel)
            .await
            .expect("bind original registered B physical ingress before installation ACK");
    }
    let (endpoint, identity, options) = deployment.pool_receiver();
    let binding = serve
        .serve_pool_allow(identity, options)
        .await
        .expect("install original Allow receiver before acknowledging registered pool material");
    PreparedPoolEndpointB {
        deployment,
        grants,
        binding: current_live_deployment::PoolServerAllowBinding::new(endpoint, binding),
        runtime: PoolEndpointBRuntime {
            serve,
            accepted,
            parent,
            ledger,
            application,
            plan,
        },
    }
}
pub(super) async fn endpoint_b(carrier: &str) {
    let deployment = current_live_deployment::server_installation();
    let concurrent_registration = deployment.as_ref().is_some_and(|deployment| {
        deployment.material.source == "live_authority"
            && route_listener(&deployment.material, 1) == 2
    });
    let environment = current_environment_for_role(false, concurrent_registration, None);
    let cancel = CancellationToken::new();
    // Registration must precede stdin: the authority waits for B's independently
    // installed original recipient before it can start the relay publication.
    let (live, registered_pool) = match deployment {
        Some(deployment) if deployment.material.source == "preauthorized_pool" => (
            None,
            Some(prepare_pool_endpoint_b(&environment, deployment, carrier, &cancel).await),
        ),
        Some(deployment) => (
            Some(prepare_live_endpoint_b(&environment, deployment, carrier, &cancel).await),
            None,
        ),
        None => (None, None),
    };
    let mut reader = io::stdin().lock();
    let input: EndpointBInput =
        serde_json::from_str(&read_line(&mut reader)).expect("decode original tunnel server input");
    let original = validate_endpoint(&input.relay, 1);
    let material = &original;
    assert_eq!(input.topology.endpoint_b, "rust");
    assert_eq!(input.topology.tunnel_runtime, input.relay.runtime);
    assert_eq!(input.topology.ingress_carrier_a, input.relay.carrier);
    assert_eq!(input.topology.ingress_carrier_b, carrier);
    assert_eq!(input.relay.server_carrier, carrier);
    if let Some(prepared) = live {
        assert_eq!(
            material.source, "live_authority",
            "independently installed live B received a different source"
        );
        endpoint_b_live(
            environment,
            prepared,
            input,
            material,
            carrier,
            cancel,
            &mut reader,
        )
        .await;
        return;
    }
    if let Some(prepared) = registered_pool {
        let PreparedPoolEndpointB {
            deployment,
            grants,
            binding,
            runtime,
        } = prepared;
        deployment.match_pool_publication(
            material,
            &input.relay.trust_pem,
            &input.relay.origin,
            (
                &input.relay.server_tls_certificate_pem,
                &input.relay.server_tls_private_key_pem,
            ),
            route_listener(material, 1) == 1,
            grants,
        );
        publish_endpoint_b_ready(&input, carrier, Some(binding));
        drop(deployment);
        finish_pool_endpoint_b(environment, runtime, input, carrier, &mut reader).await;
        return;
    }
    assert_eq!(
        material.source, "preauthorized_pool",
        "live B requires its independent server control deployment before relay startup"
    );
    let namespaces =
        bootstrap_current_namespaces(&environment, material, &input.relay.trust_pem).await;
    let (keys, credential) = tunnel_credential(&environment, material);
    let (accepted, parent, admission) = admission(&environment, material, &credential.connection);
    let ledger = ExecutionLedger::default();
    let application = current_application::Application::new(ledger.clone());
    let plan = current_application::plan(&environment, application.clone());
    let callbacks = Arc::new(CurrentParityCallbacks {
        plan: plan.clone(),
        application: Some(application.clone()),
    });
    let listener = route_listener(material, 1);
    let serve = if listener == 1 {
        environment
            .serve_reverse_tunnel_pool(
                namespaces,
                keys,
                vec![credential],
                relay_service(material),
                RELAY_AUDIENCE.into(),
                admission,
                flowersec::ReverseTunnelServeOptions {
                    callbacks,
                    application_limits: limits(),
                    cancellation: cancel.clone(),
                    provider: reverse_options(material, &input.relay, carrier),
                },
            )
            .await
    } else {
        assert_eq!(
            listener, 2,
            "invalid original logical server tunnel direction"
        );
        environment
            .serve_tunnel_pool(
                namespaces,
                keys,
                vec![credential],
                relay_service(material),
                RELAY_AUDIENCE.into(),
                admission,
                flowersec::TunnelServeOptions {
                    callbacks,
                    application_limits: limits(),
                    cancellation: cancel.clone(),
                    provider: current_provider_options(
                        material,
                        &input.relay.trust_pem,
                        1,
                        carrier,
                        &input.relay.origin,
                    ),
                },
            )
            .await
    }
    .expect("host current original logical server tunnel leg");
    let (endpoint, identity, allow_options) =
        current_live_deployment::pool_server_allow_receiver(material);
    let binding = serve
        .serve_pool_allow(identity, allow_options)
        .await
        .expect("install original authenticated pool B Allow receiver");
    if listener == 1 {
        serve
            .wait_reverse_listener_ready(Duration::from_secs(10), &cancel)
            .await
            .expect("original server physical listener readiness");
    }
    publish_endpoint_b_ready(
        &input,
        carrier,
        Some(current_live_deployment::PoolServerAllowBinding::new(
            endpoint, binding,
        )),
    );
    finish_pool_endpoint_b(
        environment,
        PoolEndpointBRuntime {
            serve,
            accepted,
            parent,
            ledger,
            application,
            plan,
        },
        input,
        carrier,
        &mut reader,
    )
    .await;
}
async fn finish_pool_endpoint_b(
    environment: flowersec::TransportEnvironment,
    runtime: PoolEndpointBRuntime,
    input: EndpointBInput,
    carrier: &str,
    reader: &mut impl BufRead,
) {
    let PoolEndpointBRuntime {
        serve,
        accepted,
        parent,
        ledger,
        application,
        plan,
    } = runtime;
    let command: Value =
        serde_json::from_str(&read_line(reader)).expect("original server connect command");
    assert_eq!(command.get("type").and_then(Value::as_str), Some("connect"));
    let session = serve
        .accept()
        .await
        .expect("accept original current tunnel Session");
    ledger.record(&["admission"]);
    current_application::server(
        &session,
        &application,
        "tunnel",
        input.relay.carrier != "websocket" && carrier != "websocket",
    )
    .await;
    session.close();
    assert!(
        session.wait_cleanup().await.complete,
        "original tunnel Session cleanup is incomplete"
    );
    serve.close();
    assert!(
        serve
            .wait_cleanup()
            .await
            .expect("current tunnel Serve cleanup")
            .complete,
        "original tunnel Serve cleanup is incomplete"
    );
    drop(session);
    drop(serve);
    drop(application);
    plan.close();
    drop(plan);
    drop(accepted);
    drop(parent);
    assert!(
        environment.close().await.unwrap().complete,
        "current server Environment retained original ownership"
    );
    ledger.record(&["close", "cleanup"]);
    print_current_result(
        "endpoint-b-result",
        carrier,
        "tunnel",
        &input.relay.profile,
        &input.relay.source,
        &ledger,
    );
}
pub(super) async fn endpoint_a(carrier: &str) {
    let mut reader = io::stdin().lock();
    let input: EndpointAInput =
        serde_json::from_str(&read_line(&mut reader)).expect("decode original tunnel client input");
    let ready = &input.endpoint_b;
    let original = validate_endpoint(&ready.relay, 0);
    let material = &original;
    assert_eq!(input.topology.endpoint_a, "rust");
    assert_eq!(input.topology.tunnel_runtime, ready.relay.runtime);
    assert_eq!(input.topology.ingress_carrier_a, carrier);
    assert_eq!(input.topology.ingress_carrier_b, ready.relay.server_carrier);
    assert_eq!(ready.message_type, "endpoint-b-ready");
    assert_eq!(ready.path, "tunnel");
    assert_eq!(ready.wire_revision, 4);
    assert!(
        ready.endpoint_a_artifact_json == ready.relay.endpoint_a_artifact_json,
        "original endpoint A material differs"
    );
    assert!(
        ready.endpoint_b_artifact_json == ready.relay.endpoint_b_artifact_json,
        "original endpoint B material differs"
    );
    assert_eq!(ready.authorizations, ready.relay.authorizations);
    assert_eq!(ready.verification_records, ready.relay.verification_records);
    assert_eq!(ready.profile, ready.relay.profile);
    assert_eq!(ready.source, ready.relay.source);
    assert_eq!(ready.carrier, ready.relay.server_carrier);
    assert_eq!(ready.relay.carrier, carrier);
    let environment = current_environment();
    let namespaces = if material.source == "live_authority" {
        current_live_deployment::bootstrap_namespaces(
            &environment,
            material,
            &ready.relay.trust_pem,
        )
        .await
    } else {
        bootstrap_current_namespaces(&environment, material, &ready.relay.trust_pem).await
    };
    let listener = route_listener(material, 0);
    let (source, pool) = if material.source == "live_authority" {
        let configuration = current_live_deployment::registered_tunnel_configuration(
            &environment,
            material,
            namespaces,
            &ready.relay.trust_pem,
            carrier,
        );
        let source = if listener == 0 {
            flowersec::LocalDirectMaterialSource::registered_live_reverse_tunnel_authority(
                &environment,
                configuration,
                reverse_options(material, &ready.relay, carrier),
            )
        } else {
            assert_eq!(listener, 2, "invalid original client live tunnel direction");
            flowersec::LocalDirectMaterialSource::registered_live_tunnel_authority(
                &environment,
                configuration,
            )
        }
        .expect("capture installed original registered live client tunnel source");
        (source, None)
    } else {
        let (identity, credential) = tunnel_credential(&environment, material);
        let pool = current_pool_store(&environment, material, &credential.connection.artifact);
        let binding = ready
            .server_allow
            .as_ref()
            .expect("original B pool Allow registration");
        let mut server_grants = ready
            .authorizations
            .iter()
            .filter(|authorization| authorization.role == 1 && authorization.candidate_index == 0);
        let server_grant = server_grants
            .next()
            .expect("independently issued original server Grant");
        assert!(
            server_grants.next().is_none(),
            "duplicate original server Grant"
        );
        let allow = current_live_deployment::pool_server_allow(
            material,
            binding,
            current_bytes(&server_grant.grant, 9302, None),
        );
        let source = if listener == 0 {
            flowersec::ConnectionMaterialSource::preauthorized_reverse_tunnel_pool_with_server_allow(
                &environment,
                flowersec::PreauthorizedReverseTunnelPoolSourceConfiguration {
                    namespaces,
                    identity,
                    credentials: vec![credential],
                    spend_ledger: pool.store.clone(),
                    application_profile: flowersec::ApplicationProfile::Services,
                    relay_service: relay_service(material),
                    relay_audience: RELAY_AUDIENCE.into(),
                    provider: reverse_options(material, &ready.relay, carrier),
                },
                vec![allow],
            )
        } else {
            assert_eq!(listener, 2, "invalid original client tunnel direction");
            flowersec::ConnectionMaterialSource::preauthorized_tunnel_pool_with_server_allow(
                &environment,
                flowersec::PreauthorizedTunnelPoolSourceConfiguration {
                    namespaces,
                    identity,
                    credentials: vec![credential],
                    spend_ledger: pool.store.clone(),
                    application_profile: flowersec::ApplicationProfile::Services,
                    relay_service: relay_service(material),
                    relay_audience: RELAY_AUDIENCE.into(),
                    provider: current_provider_options(
                        material,
                        &ready.relay.trust_pem,
                        0,
                        carrier,
                        &ready.relay.origin,
                    ),
                },
                vec![allow],
            )
        }
        .expect("capture original client tunnel source");
        (source, Some(pool))
    };
    if env::var("FLOWERSEC_PARITY_HOP_CAPACITY_PROBE").as_deref() == Ok("insufficient") {
        let pool_ref = pool.as_ref().expect("pool source for HOP capacity probe");
        assert_eq!(pool_ref.store.spend_observation(), None);
        assert_eq!(source.acquisition_observation().acquisitions, 0);
        let error = flowersec::connect(
            &environment,
            &source,
            flowersec::ConnectionRequest {
                requirements: flowersec::ConnectionRequirements {
                    application_profile: Some("services".into()),
                    ..flowersec::ConnectionRequirements::default()
                },
                handlers: None,
            },
            CancellationToken::new(),
        )
        .await
        .expect_err("HOP capacity probe must fail before pool spend");
        assert!(matches!(
            error,
            flowersec::ConnectionError::Connect(flowersec::TransportConnectError::Capacity)
        ));
        let facts = error.connection_facts();
        assert_eq!(facts.phase, flowersec::ConnectionPhase::NotStarted);
        assert_eq!(facts.spend_state, flowersec::ConnectionSpendState::Unspent);
        assert_eq!(
            facts.admission_state,
            flowersec::ConnectionAdmissionState::NotStarted
        );
        assert_eq!(
            facts.network_ready,
            flowersec::ConnectionNetworkReady::NotStarted
        );
        assert_eq!(pool_ref.store.spend_observation(), None);
        assert_eq!(source.acquisition_observation().acquisitions, 1);
        source.close();
        drop(source);
        drop(pool);
        assert!(
            environment.close().await.unwrap().complete,
            "HOP capacity probe Environment retained original ownership"
        );
        println!(
            "{}",
            serde_json::json!({
                "type":"endpoint-a-hop-capacity-probe",
                "runtime":"rust",
                "carrier":carrier,
                "path":"tunnel",
                "wire_revision":4,
                "source":material.source,
                "spend":"unspent",
                "credential_send":"not_started"
            })
        );
        return;
    }
    let ledger = ExecutionLedger::default();
    let application = current_application::Application::new(ledger.clone());
    let plan = current_application::plan(&environment, application.clone());
    let cancel = CancellationToken::new();
    let session = {
        let connect = flowersec::connect(
            &environment,
            &source,
            flowersec::ConnectionRequest {
                requirements: flowersec::ConnectionRequirements {
                    application_profile: Some("services".into()),
                    ..flowersec::ConnectionRequirements::default()
                },
                handlers: Some((plan.clone(), limits())),
            },
            cancel.clone(),
        );
        tokio::pin!(connect);
        if listener == 0 {
            tokio::select! {
                result = &mut connect => panic!("original reverse client completed before listener readiness: {:?}", result.err()),
                ready = source.wait_reverse_listener_ready(Duration::from_secs(10), &cancel) => { ready.expect("original client listener readiness"); },
            }
            println!(
                "{}",
                serde_json::json!({"type":"endpoint-a-prepared","runtime":"rust","carrier":carrier,"path":"tunnel","wire_revision":4,"profile":ready.profile,"source":ready.source})
            );
        }
        connect
            .await
            .expect("connect current tunnel through original source")
    };
    plan.close();
    ledger.record(&["admission"]);
    current_application::client(
        &session,
        &application,
        "tunnel",
        carrier != "websocket" && ready.relay.server_carrier != "websocket",
    )
    .await;
    session.wait_termination().await;
    assert!(
        session.wait_cleanup().await.complete,
        "current tunnel client Session retained cleanup"
    );
    source.close();
    drop(session);
    drop(source);
    drop(application);
    drop(plan);
    drop(pool);
    assert!(
        environment.close().await.unwrap().complete,
        "current tunnel client Environment retained original ownership"
    );
    ledger.record(&["close", "cleanup"]);
    print_current_result(
        "endpoint-a-result",
        carrier,
        "tunnel",
        &ready.profile,
        &ready.source,
        &ledger,
    );
}

struct RelayStore {
    ledger: Arc<flowersec::SQLiteRelayLedger>,
    backing: flowersec::SQLitePoolBacking,
    directory: std::path::PathBuf,
}
impl Drop for RelayStore {
    fn drop(&mut self) {
        self.ledger.close();
        if self.ledger.cleanup_complete() {
            std::fs::remove_dir_all(&self.directory)
                .expect("remove closed original relay history files");
            self.backing
                .release_removed()
                .expect("release physically removed original relay backing");
        }
    }
}
fn relay_store(
    environment: &flowersec::TransportEnvironment,
    material: &CurrentMaterial,
    parent: Arc<flowersec::SQLitePoolStore>,
    relay_certificate: &[u8],
) -> RelayStore {
    let (tenant, parent_issuer, service) =
        current_artifact_binding(&current_bytes(&material.artifact, 65536, None));
    let directory = current_store_directory("relay");
    let path = directory.join("relay.sqlite");
    let backing = environment
        .sqlite_pool_backing(
            path,
            flowersec::SQLitePoolLimits {
                max_pages: 128,
                max_records: 16,
                max_record_bytes: 65536,
                provider_runtime_bytes: 262144,
                disk_overhead_bytes: 65536,
            },
        )
        .expect("reserve original relay disk backing");
    let store_id: [u8; 32] =
        Sha256::digest(current_bytes(&material.generation.source, 64, None)).into();
    let ledger = backing
        .open_relay(flowersec::SQLiteRelayOptions {
            identity: flowersec::SQLitePoolIdentity {
                authority: "parity.relay".into(),
                store_id,
                generation: material.generation.generation,
            },
            continuity: Arc::new(CurrentContinuity),
            parent_authority: parent,
            bindings: vec![flowersec::SQLiteRelayBinding {
                tenant,
                parent_issuer,
                server_admission_authority: "local.consumer".into(),
                service,
                relay_audience: RELAY_AUDIENCE.into(),
                relay_identity_digest: current_certificate_digest(relay_certificate),
            }],
            create: true,
        })
        .expect("capture independent original relay ledger mappings");
    RelayStore {
        ledger,
        backing,
        directory,
    }
}
enum Socket {
    Tcp(TcpListener),
    Udp(UdpSocket),
}
impl Socket {
    fn bind(carrier: &str) -> Self {
        match carrier {
            "websocket" => Self::Tcp(TcpListener::bind(("127.0.0.1", 0)).unwrap()),
            "raw-quic" | "webtransport" => Self::Udp(UdpSocket::bind(("127.0.0.1", 0)).unwrap()),
            _ => panic!("unsupported original relay carrier"),
        }
    }
    fn address(&self) -> SocketAddr {
        match self {
            Self::Tcp(listener) => listener.local_addr().unwrap(),
            Self::Udp(socket) => socket.local_addr().unwrap(),
        }
    }
}
fn relay_leg(
    material: &CurrentMaterial,
    relay: &RelayReady,
    endpoint: &CurrentRelayEndpoint,
    role: u8,
    endpoint_listener: bool,
) -> flowersec::WssRelayLegOptions {
    let mut options = current_provider_options(
        material,
        &relay.trust_pem,
        role,
        &endpoint.carrier,
        &relay.origin,
    );
    options.timeout = Duration::from_secs(30);
    // Relay preparation owns all 54 pending/resident mappings, both provider
    // queues and native stream windows; endpoint preparation has fewer scopes.
    if endpoint.carrier != "websocket" {
        options.native_runtime_bytes = 64 << 20;
    }
    if endpoint_listener {
        return flowersec::WssRelayLegOptions::Dialer(options);
    }
    flowersec::WssRelayLegOptions::Listener(flowersec::ReverseTunnelProviderOptions {
        listen_address: endpoint.address.parse().unwrap(),
        identity: flowersec::WssServerIdentity {
            certificate_chain_der: vec![current_bytes(
                &endpoint.server_certificate_der,
                16384,
                None,
            )],
            private_key_der: current_bytes(
                endpoint
                    .server_private_key_pkcs8
                    .as_deref()
                    .expect("original relay listener key"),
                16384,
                None,
            ),
        },
        origin: options.origin,
        timeout: options.timeout,
        publication_timeout: options.publication_timeout,
        queue_messages: options.queue_messages,
        prepare_bytes: options.prepare_bytes,
        native_runtime_bytes: options.native_runtime_bytes,
    })
}
pub(super) async fn relay(
    carrier: &str,
    server_carrier: &str,
    endpoint_listeners: [bool; 2],
    deployment_path: Option<&str>,
) {
    if let Some(installed) = current_live_relay::installation() {
        assert!(
            deployment_path.is_none(),
            "live and pool relay installations are distinct owners"
        );
        current_live_relay::run(installed, carrier, server_carrier, endpoint_listeners).await;
        return;
    }
    use zeroize::Zeroize;
    let installed = deployment_path.map(current_live_deployment::pool_relay_installation);
    let origin = installed
        .as_ref()
        .map_or_else(parity_origin, |value| value.origin.clone());
    let carriers = [carrier, server_carrier];
    let mut prebound = None;
    let mut addresses = Vec::with_capacity(2);
    for side in 0..2 {
        if let Some(installed) = &installed {
            assert_eq!(
                route_listener(&installed.material, side as u8),
                if endpoint_listeners[side] {
                    side as u8
                } else {
                    2
                }
            );
            let (_, host, port, _, _) = current_route_endpoint(
                &current_bytes(&installed.material.route, 16384, None),
                side as u8,
            );
            let address = SocketAddr::new(
                host.parse().unwrap_or_else(|_| {
                    assert_eq!(host, "localhost");
                    "127.0.0.1".parse().unwrap()
                }),
                port,
            );
            assert!(address.ip().is_loopback() && port != 0);
            addresses.push(address);
            if !endpoint_listeners[side] && prebound.is_none() {
                prebound = Some(match carriers[side] {
                    "websocket" => Socket::Tcp(
                        TcpListener::bind(address)
                            .expect("bind installed original Rust relay TCP ingress"),
                    ),
                    "raw-quic" | "webtransport" => Socket::Udp(
                        UdpSocket::bind(address)
                            .expect("bind installed original Rust relay UDP ingress"),
                    ),
                    _ => unreachable!(),
                });
            }
        } else {
            let socket = Socket::bind(carriers[side]);
            addresses.push(socket.address());
            if !endpoint_listeners[side] && prebound.is_none() {
                prebound = Some(socket);
            }
        }
    }
    let mut request = serde_json::json!({"mode":"tunnel","wire_revision":4,"carrier":carrier,"server_carrier":server_carrier,
        "profile":CURRENT_PROFILE,"origin":origin,"topology_id":format!("rust-original-{}",std::process::id()),
        "endpoint_listeners":endpoint_listeners,"relay_owner_handoff":true,"persist":true});
    let (mut issuer, mut issued) = if let Some(installed) = &installed {
        request["deployment_path"] = Value::String(deployment_path.unwrap().to_owned());
        PersistentIssuer::start_with_prepared(
            &request,
            Some(&|value| installed.prepared(value, carriers)),
        )
    } else {
        request["relay_addresses"] = serde_json::to_value(
            addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        PersistentIssuer::start(&request)
    };
    assert_eq!(issued.relay_endpoints.len(), 2);
    assert_eq!(issued.origin, origin);
    for side in 0..2 {
        assert_eq!(issued.relay_endpoints[side].carrier, carriers[side]);
        assert_eq!(
            issued.relay_endpoints[side]
                .address
                .parse::<SocketAddr>()
                .unwrap(),
            addresses[side]
        );
    }
    let mut ready = RelayReady {
        message_type: "relay-ready".into(),
        runtime: "rust".into(),
        carrier: carrier.into(),
        server_carrier: server_carrier.into(),
        path: "tunnel".into(),
        wire_revision: 4,
        endpoint_a_artifact_json: issued
            .endpoint_a_artifact_json
            .clone()
            .expect("original issued endpoint A"),
        endpoint_b_artifact_json: issued
            .endpoint_b_artifact_json
            .clone()
            .expect("original issued endpoint B"),
        trust_pem: issued.trust_pem.clone(),
        client_tls_certificate_pem: issued.client_tls_certificate_pem.clone(),
        client_tls_private_key_pem: issued.client_tls_private_key_pem.clone(),
        server_tls_certificate_pem: issued.server_tls_certificate_pem.clone(),
        server_tls_private_key_pem: issued.server_tls_private_key_pem.clone(),
        origin,
        route_digest: String::new(),
        profile: String::new(),
        source: "preauthorized_pool".into(),
        authorizations: issued.authorizations.clone(),
        verification_records: issued.verification_records.clone(),
    };
    let original_a = parse_current_material(&ready.endpoint_a_artifact_json, 0);
    ready.route_digest = original_a.route_digest.clone();
    ready.profile = original_a.profile.clone();
    drop(original_a);
    let mut original = validate_pool_pair(&ready);
    if let Some(installed) = &installed {
        installed.match_original(&original, &issued);
    }
    let registered = installed.is_some();
    drop(installed);
    assert_eq!(
        route_listener(&original[0], 0),
        if endpoint_listeners[0] { 0 } else { 2 }
    );
    assert_eq!(
        route_listener(&original[1], 1),
        if endpoint_listeners[1] { 1 } else { 2 }
    );
    let environment = current_relay_environment();
    let namespaces =
        bootstrap_current_namespaces(&environment, &original[0], &ready.trust_pem).await;
    let seed: [u8; 32] = current_bytes(
        issued
            .relay_identity_seed
            .as_deref()
            .expect("original relay identity owner"),
        32,
        Some(32),
    )
    .try_into()
    .unwrap();
    let keys = environment
        .import_identity_keys(&original[0].profile, seed, [1; 32])
        .expect("import original relay HOP signer");
    issued.relay_identity_seed.as_mut().unwrap().zeroize();
    let relay_certificate = current_bytes(&original[0].tunnels[0].relay_certificate, 8192, None);
    let parent = current_pool_store_named(
        &environment,
        &original[0],
        &current_bytes(&original[0].artifact, 65536, None),
        "parent",
    );
    let ledger = relay_store(
        &environment,
        &original[0],
        parent.store.clone(),
        &relay_certificate,
    );
    let (_, connection) = current_identity_and_credential(&environment, &original[0]);
    let grants = [0, 1].map(|role| {
        current_bytes(
            original[role]
                .tunnels
                .iter()
                .find(|slot| slot.role == role as u8 && slot.candidate_index == 0)
                .unwrap()
                .grant
                .as_deref()
                .unwrap(),
            65536,
            None,
        )
    });
    let publication = environment
        .relay_pool_publication(
            namespaces,
            flowersec::RelayPoolPublicationInput {
                connection,
                grants,
                relay_certificate,
                candidate_index: 0,
                server_admission_authority: "local.consumer".into(),
                service: relay_service(&original[0]),
                relay_audience: RELAY_AUDIENCE.into(),
            },
        )
        .expect("capture publication inside the original issuer continuation");
    let options = flowersec::WssRelayHostOptions {
        client_leg: relay_leg(
            &original[0],
            &ready,
            &issued.relay_endpoints[0],
            0,
            endpoint_listeners[0],
        ),
        server_leg: relay_leg(
            &original[1],
            &ready,
            &issued.relay_endpoints[1],
            1,
            endpoint_listeners[1],
        ),
        maximum_pairs: 1,
        cancellation: CancellationToken::new(),
    };
    let host = match prebound {
        Some(Socket::Tcp(listener)) => {
            environment.wss_relay_host_on_listener(listener, keys, ledger.ledger.clone(), options)
        }
        Some(Socket::Udp(socket)) => {
            environment.wss_relay_host_on_udp_socket(socket, keys, ledger.ledger.clone(), options)
        }
        None => environment.wss_relay_host(keys, ledger.ledger.clone(), options),
    }
    .expect("capture original physical relay host");
    let (forwarding, winner) = if registered {
        let mut registration = publication
            .register(ledger.ledger.clone(), CancellationToken::new())
            .expect("register exact original pool publication before issuer completion");
        let winner = registration
            .take_pool_winner_continuation()
            .expect("capture one original remote winner continuation");
        (
            host.prepare_registered(registration)
                .expect("retain original registered forwarding"),
            Some(winner),
        )
    } else {
        (
            host.prepare_pool(publication)
                .expect("retain one original paused forwarding publication"),
            None,
        )
    };
    issuer.acknowledge_original_capture();
    let winner_task = winner.map(|winner| issuer.serve_original_winner(winner));
    for role in 0..2 {
        if !endpoint_listeners[role] {
            let listener_cancel = CancellationToken::new();
            let address = tokio::select! {
                ready = host.wait_listener_ready(
                    role as u8,
                    Duration::from_secs(10),
                    &listener_cancel
                ) => ready.expect("original relay physical listener readiness"),
                result = forwarding.wait_completion() => {
                    panic!("original relay publication ended before listener readiness: {result:?}");
                }
            };
            assert_eq!(address, addresses[role]);
        }
    }
    print_current_protocol_message(&ready);
    // Only detached public evidence is retained for the driver's acknowledgement.
    // The forwarding host already owns its verified original publication.
    for material in &mut original {
        material.artifact.zeroize();
        material.identity_seed.zeroize();
        material.dh_seed.zeroize();
    }
    ready.endpoint_a_artifact_json.zeroize();
    ready.endpoint_b_artifact_json.zeroize();
    ready.client_tls_private_key_pem.zeroize();
    ready.server_tls_private_key_pem.zeroize();
    issued.endpoint_a_artifact_json.as_mut().unwrap().zeroize();
    issued.endpoint_b_artifact_json.as_mut().unwrap().zeroize();
    issued.client_tls_private_key_pem.zeroize();
    issued.server_tls_private_key_pem.zeroize();
    for endpoint in &mut issued.relay_endpoints {
        if let Some(key) = &mut endpoint.server_private_key_pkcs8 {
            key.zeroize();
        }
    }
    drop(original);
    drop(issued);
    let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
    let mut command_line = Zeroizing::new(String::new());
    tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut command_line)
        .await
        .expect("read original relay configuration acknowledgement");
    let command: Value =
        serde_json::from_str(&command_line).expect("original relay configuration acknowledgement");
    command_line.zeroize();
    assert_eq!(
        command.get("type").and_then(Value::as_str),
        Some("configure")
    );
    assert_eq!(
        command.get("wire_revision").and_then(Value::as_u64),
        Some(4)
    );
    assert_eq!(
        command.get("route_digest").and_then(Value::as_str),
        Some(ready.route_digest.as_str())
    );
    assert_eq!(
        serde_json::from_value::<Vec<CurrentTunnelAuthorization>>(
            command["authorizations"].clone()
        )
        .unwrap(),
        ready.authorizations
    );
    assert_eq!(
        serde_json::from_value::<Vec<CurrentNamespaceRecord>>(
            command["verification_records"].clone()
        )
        .unwrap(),
        ready.verification_records
    );
    forwarding
        .start()
        .expect("start only the retained original paired publication");
    tokio::select! {
        result = tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut command_line) => {
            result.expect("read original relay close command");
        }
        result = forwarding.wait_completion() => {
            eprintln!("original relay forwarding completed before close command: {result:?}");
            tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut command_line)
                .await
                .expect("read close command after original forwarding completion");
        }
    }
    let command: Value = serde_json::from_str(&command_line).expect("original relay close command");
    command_line.zeroize();
    assert_eq!(command.get("type").and_then(Value::as_str), Some("close"));
    if let Some(mut task) = winner_task {
        let completed = match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
            Ok(completed) => completed,
            Err(_) => {
                // Closing an unfinished topology cannot leave a blocking pipe
                // owner detached from its child process or original custody.
                let _ = issuer.child.kill();
                let completed = task.await;
                let _ = issuer.child.wait();
                completed.expect("original remote winner control timed out");
                panic!("original remote winner control exceeded cleanup deadline");
            }
        };
        let (input, output) = completed.expect("join original remote winner control owner");
        issuer.input = Some(input);
        issuer.output = Some(output);
    }
    forwarding.close();
    host.close();
    let result = tokio::time::timeout(Duration::from_secs(5), forwarding.wait_completion())
        .await
        .expect("actual original forwarding exit deadline");
    assert!(
        matches!(
            result,
            Ok(())
                | Err(flowersec::TransportConnectError::Canceled
                    | flowersec::TransportConnectError::Carrier)
        ),
        "original relay failed: {result:?}"
    );
    let progress = forwarding
        .forwarding_progress()
        .expect("actual original forwarding milestones");
    assert!(
        progress.0 && progress.1,
        "original relay did not authenticate both HOPs and forward both READY records"
    );
    let cleanup = host
        .wait_cleanup()
        .await
        .expect("original relay physical cleanup");
    assert!(
        cleanup.complete,
        "original relay retained a native provider or forwarding tail"
    );
    if carrier == "raw-quic" && server_carrier == "raw-quic" {
        assert!(
            progress.2,
            "original relay did not forward datagrams in both directions"
        );
    }
    drop(forwarding);
    drop(host);
    drop(ledger);
    drop(parent);
    assert!(
        environment.close().await.unwrap().complete,
        "original relay Environment retained ownership"
    );
    issuer.shutdown();
    let mut cases = vec![
        "admission",
        "pairing",
        "opaque-forwarding",
        "close",
        "cancel",
        "cleanup",
    ];
    if carrier == "raw-quic" && server_carrier == "raw-quic" {
        cases.push("datagram-forwarding");
    }
    println!(
        "{}",
        serde_json::json!({"type":"relay-result","runtime":"rust","carrier":carrier,"server_carrier":server_carrier,
        "path":"tunnel","wire_revision":4,"profile":ready.profile,"source":ready.source,"cases":cases,"observed_plaintext":false})
    );
}
