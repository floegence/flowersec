// Both endpoints use production WSS carriers and durable admission.
async fn shared_wss_pair(
    profile: Profile,
) -> (
    crate::TransportEnvironment,
    ServeHandle,
    Session,
    Session,
    ([StoreFixture; 3], (u64, u64)),
) {
    let pin = profile == Profile::X25519;
    let generated = LocalKeys::generate(profile).unwrap();
    let ed = generated.ed_public();
    let mut f = Fixture::with_identity(
        ActivationSource::PreauthorizedPool,
        profile.name(),
        Some([(generated.dh_public(), &ed), (generated.dh_public(), &ed)]),
    );
    let client_keys = f.environment.identity_keys(profile.name()).unwrap();
    let server_keys = f.environment.identity_keys(profile.name()).unwrap();
    f.set_client_keys(&client_keys);
    f.set_server_keys(&server_keys);
    let facts = f.reserve().unwrap();
    let winner_name = facts.pool.as_ref().unwrap().winner_authority.clone();
    let local = StoreFixture::with_authority(&f, Some("accept.example"));
    let parent = StoreFixture::with_authority(&f, Some(&winner_name));
    let pool = StoreFixture::new(&f);
    let a = decode(&f.artifact, "Artifact", 65536, Context::default()).unwrap();
    let authority = SQLiteAdmissionAuthority::new(
        local.store.clone(),
        parent.store.clone(),
        vec![SQLiteAdmissionBinding {
            tenant: a
                .field("Artifact", "tenant_id")
                .unwrap()
                .text()
                .unwrap()
                .into(),
            issuer: a.b("Artifact", "issuer_key_id").unwrap(),
            server_identity_digest: facts.certificate_digests[1],
            audience: a
                .field("Artifact", "audience")
                .unwrap()
                .text()
                .unwrap()
                .into(),
        }],
    )
    .unwrap();
    drop(facts);
    let (identity, ca, digest) = super::super::tests::tls_provisioning();
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    f.set_wss_route(address.port(), pin.then_some(digest));
    let server_bytes = credential_bytes(&f);
    let client_bytes = credential_bytes(&f);
    let source = Arc::new(Source(Mutex::new(Some(server_bytes))));
    let namespace = Arc::new(Namespace::new(f.verifier));
    let environment = f.environment;
    let carrier_baseline = environment.resource_usage();
    let handle = environment
        .serve_wss(
            vec![namespace.clone()],
            server_keys,
            source,
            authority,
            identity,
            WssServeOptions {
                callbacks: Arc::new(TestCallbacks {
                    plan: environment
                        .handler_plan(HandlerPlanOptions {
                            streams: StreamDispatch::Manual,
                            application_bytes: 4096,
                        })
                        .unwrap(),
                }),
                application_limits: ApplicationLimits {
                    ordinary_callbacks: 4,
                    ordinary_callback_bytes: 32768,
                    control_callback_bytes: 32768,
                },
                cancellation: CancellationToken::new(),
                binding_mode: BindingMode::AuthenticatedContext,
                listen_address: address,
                host: "example.com".into(),
                origin: None,
                max_connections: 2,
                max_frame_bytes: 65536,
                handshake_timeout: Duration::from_secs(5),
                publication_timeout: Duration::from_secs(2),
                queue_messages: 2,
                prepare_bytes: 65536,
                native_runtime_bytes: 1 << 20,
            },
        )
        .await
        .unwrap();
    let material = environment
        .pool_connection_material(vec![namespace], client_keys, client_bytes)
        .unwrap();
    let client = environment
        .connect_pool_wss(
            material,
            pool.store.clone(),
            WssConnectOptions {
                binding_mode: BindingMode::AuthenticatedContext,
                remote_address: std::net::Ipv4Addr::LOCALHOST.into(),
                origin: None,
                ca_certificates_der: if pin { vec![] } else { vec![ca] },
                timeout: Duration::from_secs(5),
                publication_timeout: Duration::from_secs(2),
                queue_messages: 2,
                prepare_bytes: 65536,
                native_runtime_bytes: 1 << 20,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let server = tokio::time::timeout(Duration::from_secs(2), handle.accept())
        .await
        .unwrap()
        .unwrap();
    (
        environment,
        handle,
        client,
        server,
        (
            [local, parent, pool],
            (
                carrier_baseline.native_handles,
                carrier_baseline.provider_bytes,
            ),
        ),
    )
}

async fn shared_open_pair(client: &Session, server: &Session) -> (crate::Stream, crate::Stream) {
    // Native publication can block in place, so both endpoints need separate
    // tasks to keep their OPEN/ACK waits independently schedulable.
    let client = client.clone();
    let outgoing = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        client
            .open_stream("shared.isolation", Metadata::empty(), 128)
            .await
    }));
    let incoming = server.next_open().await.unwrap().accept(128).unwrap();
    (outgoing.await.unwrap().unwrap(), incoming)
}

fn shared_envelope(scope: u64, epoch: u32, sequence: u64, length: usize) -> Vec<u8> {
    assert!(length >= 44);
    let mut wire = vec![0; length];
    wire[..4].copy_from_slice(&((length - 8) as u32).to_be_bytes());
    wire[4] = 8;
    wire[8..12].copy_from_slice(&epoch.to_be_bytes());
    wire[12..20].copy_from_slice(&scope.to_be_bytes());
    wire[20..28].copy_from_slice(&sequence.to_be_bytes());
    wire
}

async fn shared_healthy_round_trip(
    client: &Session,
    server: &Session,
    outgoing: &crate::Stream,
    incoming: &crate::Stream,
) {
    outgoing
        .write(Bytes::from_static(b"healthy forward"))
        .await
        .unwrap();
    assert_eq!(
        incoming.read().await.unwrap().unwrap(),
        Bytes::from_static(b"healthy forward")
    );
    incoming
        .write(Bytes::from_static(b"healthy reverse"))
        .await
        .unwrap();
    assert_eq!(
        outgoing.read().await.unwrap().unwrap(),
        Bytes::from_static(b"healthy reverse")
    );
    for session in [client, server] {
        assert_eq!(
            session
                .probe_liveness(Duration::from_secs(2))
                .await
                .unwrap()
                .outcome,
            ProbeOutcome::Responsive
        );
        assert!(session.termination_cause().is_none());
    }
}

async fn shared_wss_cleanup(
    environment: &crate::TransportEnvironment,
    handle: &ServeHandle,
    client: &Session,
    server: &Session,
) {
    client.close();
    server.close();
    handle.close();
    assert!(client.wait_cleanup().await.complete);
    assert!(server.wait_cleanup().await.complete);
    assert!(handle.wait_cleanup().await.unwrap().complete);
    let usage = environment.resource_usage();
    assert_eq!(usage.connections, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_wss_authenticated_data_errors_isolate_original_stream() {
    for profile in [Profile::X25519, Profile::P256] {
        for to_server in [true, false] {
            for fault in ["schema", "target", "offset", "credit"] {
                tokio::time::timeout(Duration::from_secs(15), async {
                    let (environment, handle, client, server, (_stores, carrier_baseline)) =
                        shared_wss_pair(profile).await;
                    let (bad_out, bad_in) = shared_open_pair(&client, &server).await;
                    let (healthy_out, healthy_in) = shared_open_pair(&client, &server).await;
                    let (sender, receiver, bad_send, bad_receive, healthy_send) = if to_server {
                        (&client, &server, &bad_out, &bad_in, &healthy_out)
                    } else {
                        (&server, &client, &bad_in, &bad_out, &healthy_in)
                    };
                    let before = receiver.shared_input_snapshot_for_test(bad_receive);
                    let healthy_before = receiver.shared_input_snapshot_for_test(if to_server {
                        &healthy_in
                    } else {
                        &healthy_out
                    });
                    sender.shared_fault_data_for_test(bad_send, fault, healthy_send);
                    assert!(
                        bad_receive.read().await.is_err(),
                        "authenticated {fault} must reset its outer scope"
                    );
                    let after = receiver.shared_input_snapshot_for_test(bad_receive);
                    assert!(after.first_error, "{fault}: {after:?}");
                    assert!(
                        after.opens > before.opens,
                        "malformed body must first pass real AEAD"
                    );
                    assert_eq!(
                        after.frontier, before.frontier,
                        "{fault} advanced stream frontier"
                    );
                    assert_eq!(after.ack, before.ack, "{fault} advanced ACK");
                    assert_eq!(
                        after.released, before.released,
                        "{fault} released unauthenticated bytes"
                    );
                    // Retired keys may already be removed after both real proofs.
                    if after.record_next.is_some() {
                        assert_eq!(after.record_next, before.record_next);
                    }
                    let healthy_after = receiver.shared_input_snapshot_for_test(if to_server {
                        &healthy_in
                    } else {
                        &healthy_out
                    });
                    assert_eq!(
                        healthy_after.frontier, healthy_before.frontier,
                        "inner target changed the healthy outer scope"
                    );
                    let proof = loop {
                        let snapshot = receiver.shared_input_snapshot_for_test(bad_receive);
                        if let Some(proof) = snapshot.proof {
                            assert!(snapshot.stop_sent);
                            assert!(snapshot.stopped_sent);
                            break proof;
                        }
                        tokio::task::yield_now().await;
                    };
                    assert!(proof.2, "failed DATA must produce DRAINED(aborted)");
                    assert_eq!(Some(proof.1), before.frontier);
                    assert_eq!(proof.0.1, before.frontier.unwrap().1 + 1);
                    assert!(bad_send.wait_cleanup().await.complete);
                    assert!(bad_receive.wait_cleanup().await.complete);
                    shared_healthy_round_trip(&client, &server, &healthy_out, &healthy_in).await;
                    client.rekey().await.unwrap();
                    shared_healthy_round_trip(&client, &server, &healthy_out, &healthy_in).await;
                    shared_wss_cleanup(&environment, &handle, &client, &server).await;
                    let cleaned = environment.resource_usage();
                    assert_eq!(cleaned.native_handles, carrier_baseline.0);
                    assert_eq!(cleaned.provider_bytes, carrier_baseline.1);
                })
                .await
                .unwrap_or_else(|_| panic!("{profile:?} to_server={to_server} {fault} timed out"));
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_wss_closed_data_discard_is_one_lifetime_allowance() {
    for profile in [Profile::X25519, Profile::P256] {
        for to_server in [true, false] {
            for bound in ["records", "bytes", "deadline", "future", "framing"] {
                let mut stage = "setup";
                tokio::time::timeout(Duration::from_secs(15), async {
                    let (environment, handle, client, server, (_stores, carrier_baseline)) =
                        shared_wss_pair(profile).await;
                    stage = "first stream open";
                    let (bad_out, bad_in) = shared_open_pair(&client, &server).await;
                    stage = "healthy stream open";
                    let (healthy_out, healthy_in) = shared_open_pair(&client, &server).await;
                    let (sender, receiver, bad_send, bad_receive, healthy_send) = if to_server {
                        (&client, &server, &bad_out, &bad_in, &healthy_out)
                    } else {
                        (&server, &client, &bad_in, &bad_out, &healthy_in)
                    };
                    sender.shared_fault_data_for_test(bad_send, "offset", healthy_send);
                    stage = "original stream cleanup";
                    assert!(bad_receive.read().await.is_err());
                    assert!(bad_send.wait_cleanup().await.complete);
                    assert!(bad_receive.wait_cleanup().await.complete);
                    let first_discard_at = tokio::time::Instant::now();
                    let first = shared_envelope(bad_send.scope_for_test(), 0, u64::MAX, 44);
                    sender.shared_raw_for_test(&first);
                    stage = "first discarded record";
                    let initial = receiver
                        .wait_shared_input_for_test(bad_receive, |s| s.discard.0 == 1)
                        .await;
                    assert_eq!(initial.discard.1, first.len() as u64);
                    assert!(
                        initial.discard.2.unwrap() >= first_discard_at + Duration::from_secs(10)
                    );
                    assert!(
                        initial.discard.2.unwrap()
                            <= tokio::time::Instant::now() + Duration::from_secs(10)
                    );
                    stage = "rekey";
                    client.rekey().await.unwrap();
                    stage = "post-rekey stream open";
                    let (extra_out, extra_in) = shared_open_pair(&client, &server).await;
                    stage = "authenticated retirement";
                    receiver
                        .wait_shared_input_for_test(bad_receive, |s| s.stable)
                        .await;
                    assert_eq!(
                        receiver.shared_input_snapshot_for_test(bad_receive).discard,
                        initial.discard
                    );
                    shared_healthy_round_trip(&client, &server, &healthy_out, &healthy_in).await;
                    stage = "second stream cleanup";
                    let (extra_send, extra_receive) = if to_server {
                        (&extra_out, &extra_in)
                    } else {
                        (&extra_in, &extra_out)
                    };
                    sender.shared_fault_data_for_test(extra_send, "offset", healthy_send);
                    assert!(extra_receive.read().await.is_err());
                    assert!(extra_send.wait_cleanup().await.complete);
                    assert!(extra_receive.wait_cleanup().await.complete);
                    let second = shared_envelope(extra_send.scope_for_test(), 1, u64::MAX, 44);
                    sender.shared_raw_for_test(&second);
                    stage = "second discarded record";
                    let second_discard = receiver
                        .wait_shared_input_for_test(bad_receive, |s| s.discard.0 == 2)
                        .await;
                    assert_eq!(second_discard.discard.1, 88);
                    assert_eq!(second_discard.discard.2, initial.discard.2);
                    match bound {
                        "records" => {
                            stage = "exact record allowance";
                            for _ in 2..16 {
                                sender.shared_raw_for_test(&first);
                            }
                            receiver
                                .wait_shared_input_for_test(bad_receive, |s| s.discard.0 == 16)
                                .await;
                            sender.shared_raw_for_test(&first);
                        }
                        "bytes" => {
                            stage = "exact byte allowance";
                            let full = shared_envelope(bad_send.scope_for_test(), 0, 0, 65536 - 88);
                            sender.shared_raw_for_test(&full);
                            receiver
                                .wait_shared_input_for_test(bad_receive, |s| s.discard.1 == 65536)
                                .await;
                            sender.shared_raw_for_test(&first);
                        }
                        "deadline" => {
                            receiver.expire_shared_discard_for_test();
                            sender.shared_raw_for_test(&first);
                        }
                        "future" | "framing" => {
                            let mut invalid = first.clone();
                            if bound == "future" {
                                invalid[8..12].copy_from_slice(&2_u32.to_be_bytes());
                            } else {
                                invalid[7] = 1;
                            }
                            sender.shared_raw_for_test(&invalid);
                        }
                        _ => unreachable!(),
                    }
                    stage = "session termination";
                    receiver.wait_shared_termination_for_test().await;
                    stage = "physical cleanup";
                    shared_wss_cleanup(&environment, &handle, &client, &server).await;
                    let cleaned = environment.resource_usage();
                    assert_eq!(cleaned.native_handles, carrier_baseline.0);
                    assert_eq!(cleaned.provider_bytes, carrier_baseline.1);
                })
                .await
                .unwrap_or_else(|_| panic!("{profile:?} to_server={to_server} {bound} timed out at {stage}"));
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_wss_unattributable_data_errors_fail_session() {
    for profile in [Profile::X25519, Profile::P256] {
        for to_server in [true, false] {
            for fault in ["tag", "unknown", "future", "framing"] {
                tokio::time::timeout(Duration::from_secs(15), async {
                    let (environment, handle, client, server, (_stores, carrier_baseline)) =
                        shared_wss_pair(profile).await;
                    let (bad_out, bad_in) = shared_open_pair(&client, &server).await;
                    let (_healthy_out, _healthy_in) = shared_open_pair(&client, &server).await;
                    let (sender, receiver, stream, remote) = if to_server {
                        (&client, &server, &bad_out, &bad_in)
                    } else {
                        (&server, &client, &bad_in, &bad_out)
                    };
                    let before = receiver.shared_input_snapshot_for_test(remote);
                    let mut wire = shared_envelope(
                        if fault == "unknown" {
                            101
                        } else {
                            stream.scope_for_test()
                        },
                        u32::from(fault == "future"),
                        before.record_next.unwrap(),
                        44,
                    );
                    if fault == "framing" {
                        wire[7] = 1;
                    }
                    sender.shared_raw_for_test(&wire);
                    receiver.wait_shared_termination_for_test().await;
                    shared_wss_cleanup(&environment, &handle, &client, &server).await;
                    let cleaned = environment.resource_usage();
                    assert_eq!(cleaned.native_handles, carrier_baseline.0);
                    assert_eq!(cleaned.provider_bytes, carrier_baseline.1);
                })
                .await
                .unwrap_or_else(|_| panic!("{profile:?} to_server={to_server} {fault} timed out"));
            }
        }
    }
}
