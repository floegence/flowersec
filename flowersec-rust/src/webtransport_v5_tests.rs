use super::*;
use crate::{AcceptorOptions, UnreliableSendOutcome, WebTransportListenerPolicy};
use std::time::SystemTime;

const ORIGIN: &str = "https://app.example";

fn direct(url: &str, tls: Value) -> Artifact {
    artifact_with_candidates(vec![
        json!({"carrier":"webtransport","id":"wt","url":url,"tls":tls,"wire_profile":"flowersec-direct/5"}),
    ])
}

async fn exchange(client: &dyn Session, server: &dyn Session, datagrams: bool) {
    let (opened, accepted) = tokio::join!(
        client.open_stream("echo", crate::StreamMetadata::empty()),
        server.accept_stream()
    );
    let opened = opened.unwrap();
    let accepted = accepted.unwrap();
    opened.write(Bytes::from_static(b"request")).await.unwrap();
    opened.close_write().await.unwrap();
    assert_eq!(
        accepted.stream().read().await.unwrap().unwrap(),
        &b"request"[..]
    );
    assert!(accepted.stream().read().await.unwrap().is_none());
    accepted
        .stream()
        .write(Bytes::from_static(b"response"))
        .await
        .unwrap();
    accepted.stream().close_write().await.unwrap();
    assert_eq!(opened.read().await.unwrap().unwrap(), &b"response"[..]);
    assert!(opened.read().await.unwrap().is_none());
    if !datagrams {
        assert!(server.unreliable_messages().is_err());
        return;
    }
    for (sender, receiver) in [(client, server), (server, client)] {
        assert_eq!(
            sender
                .unreliable_messages()
                .unwrap()
                .send(
                    Bytes::from_static(b"message"),
                    SystemTime::now() + Duration::from_secs(5)
                )
                .await
                .unwrap(),
            UnreliableSendOutcome::Accepted
        );
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(3),
                receiver.unreliable_messages().unwrap().receive()
            )
            .await
            .unwrap()
            .unwrap(),
            &b"message"[..]
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webtransport_direct_authority_origin_tls_spend_and_recovery() {
    let (root, identity) = private_ca_identity();
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = socket.local_addr().unwrap();
    let acceptor = Acceptor::bind_webtransport_on_socket(
        socket,
        AcceptorOptions {
            bind_address: address,
            certificate_chain_der: identity.chain,
            private_key_der: identity.key,
            max_inbound_streams: 1,
            accept_timeout: Duration::from_secs(12),
        },
        WebTransportListenerPolicy::new("127.0.0.1", vec![ORIGIN.into()]).unwrap(),
    )
    .unwrap();
    assert_eq!(acceptor.local_address().unwrap(), address);
    let url = format!("https://{address}{}", crate::webtransport_v5::DIRECT);
    let artifact = direct(&url, json!({"mode":"ca"}));
    let server_spends = Arc::new(AtomicUsize::new(0));
    let observed = server_spends.clone();
    let server_artifact = artifact.clone();
    let serving = tokio::spawn(async move {
        acceptor
            .accept(
                &ArtifactLease::new(server_artifact, move || async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }),
                CancellationToken::new(),
            )
            .await
            .unwrap()
    });
    let (other_root, _) = private_ca_identity();
    let bad_pin = json!({"mode":"pin","pins":[{"algorithm":"sha-256","value_b64u":URL_SAFE_NO_PAD.encode([9;32]),"not_after_unix_s":unix_seconds()+600}]});
    for (candidate, origin, trust, code) in [
        (
            artifact.clone(),
            "https://denied.example",
            root.clone(),
            ConnectErrorCode::ConnectionFailed,
        ),
        (
            artifact.clone(),
            ORIGIN,
            other_root,
            ConnectErrorCode::TransportSecurityFailed,
        ),
        (
            direct(&url, bad_pin),
            ORIGIN,
            root.clone(),
            ConnectErrorCode::TransportSecurityFailed,
        ),
    ] {
        let options = ConnectorOptions::new()
            .with_webtransport_origin(origin)
            .unwrap()
            .with_trust_roots_der(vec![trust])
            .unwrap();
        assert_eq!(
            connect_v3(
                ArtifactLease::new(candidate, || async {
                    panic!("failed preparation spent the lease")
                }),
                options
            )
            .await
            .unwrap_err()
            .code(),
            code
        );
        assert_eq!(server_spends.load(Ordering::SeqCst), 0);
    }
    let options = ConnectorOptions::new()
        .with_trust_roots_der(vec![root])
        .unwrap()
        .with_webtransport_origin(ORIGIN)
        .unwrap();
    let client = connect_v3(ArtifactLease::new(artifact, || async { Ok(()) }), options)
        .await
        .unwrap();
    let server = serving.await.unwrap();
    assert_eq!(server_spends.load(Ordering::SeqCst), 1);
    exchange(client.as_ref(), server.as_ref(), true).await;
    client.rekey().await.unwrap();
    client.probe_liveness().await.unwrap();
    let _ = tokio::join!(client.close(), server.close());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webtransport_tunnel_both_roles_pin_forward_stream_and_datagram() {
    tunnel_roundtrip(false, crate::WebTransportProfile::Draft02).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webtransport_native_h3_tunnel_both_roles_forward_stream_and_datagram() {
    tunnel_roundtrip(false, crate::WebTransportProfile::NativeH3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webtransport_prebound_tunnel_to_wss_forwards_only_reliable_streams() {
    tunnel_roundtrip(true, crate::WebTransportProfile::Draft02).await;
}

async fn tunnel_roundtrip(mixed: bool, profile: crate::WebTransportProfile) {
    let (_, identity) = private_ca_identity();
    let pin = URL_SAFE_NO_PAD.encode(Sha256::digest(&identity.chain[0]));
    let authorizer = Arc::new(TestTunnelAuthorizer::default());
    let options = TunnelRuntimeOptions {
        bind_address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        certificate_chain_der: identity.chain,
        private_key_der: identity.key,
        allowed_origins: vec![ORIGIN.into()],
        admission_reasons: Vec::new(),
        max_inbound_streams: 1,
        pair_timeout: Duration::from_secs(5),
        max_pending_legs: 8,
        max_active_pairs: 4,
    };
    let policy = WebTransportListenerPolicy::new("127.0.0.1", vec![ORIGIN.into()])
        .unwrap()
        .with_profile(profile);
    let (runtime, address) = if mixed {
        let mut runtime = TunnelRuntime::bind_websocket(options, authorizer.clone()).unwrap();
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = socket.local_addr().unwrap();
        let url = format!("https://{addr}{}", crate::webtransport_v5::TUNNEL);
        assert_eq!(
            runtime
                .add_webtransport_ingress_on_socket(socket, policy, &url)
                .unwrap(),
            addr
        );
        (runtime, addr)
    } else {
        let runtime =
            TunnelRuntime::bind_webtransport(options, policy, authorizer.clone()).unwrap();
        let addr = runtime.local_address().unwrap();
        (runtime, addr)
    };
    let runtime = Arc::new(runtime);
    let url = format!("https://{address}{}", crate::webtransport_v5::TUNNEL);
    let artifact = |role, local, peer, token| {
        let original = tunnel_artifact(
            runtime.local_address().unwrap().port(),
            role,
            local,
            peer,
            token,
            &pin,
        );
        if mixed && role == 2 {
            return original;
        }
        let mut value: Value = serde_json::from_slice(&original.encode()).unwrap();
        value["path"]["candidates"][0]["carrier"] = json!("webtransport");
        value["path"]["candidates"][0]["url"] = json!(url);
        Artifact::parse(jcs_value(&value).unwrap()).unwrap()
    };
    let client_artifact = artifact(1, "client", "server", "client-token");
    let server_artifact = artifact(2, "server", "client", "server-token");
    authorizer
        .artifacts
        .lock()
        .unwrap()
        .extend([client_artifact.clone(), server_artifact.clone()]);
    let cancel = CancellationToken::new();
    let serving = tokio::spawn({
        let runtime = runtime.clone();
        let cancel = cancel.clone();
        async move { runtime.serve(cancel).await.unwrap() }
    });
    let options = || {
        ConnectorOptions::new()
            .with_webtransport_profile(profile, ORIGIN)
            .unwrap()
            .with_websocket_origin(ORIGIN)
            .unwrap()
    };
    let denied = artifact(1, "client", "server", "unregistered-token");
    assert!(
        connect_v3(ArtifactLease::new(denied, || async { Ok(()) }), options())
            .await
            .is_err()
    );
    let (client, server) = tokio::join!(
        connect_v3(
            ArtifactLease::new(client_artifact, || async { Ok(()) }),
            options()
        ),
        connect_v3(
            ArtifactLease::new(server_artifact, || async { Ok(()) }),
            options()
        )
    );
    let client = client.unwrap();
    let server = server.unwrap();
    exchange(client.as_ref(), server.as_ref(), !mixed).await;
    server.close().await.unwrap();
    client.close().await.unwrap();
    cancel.cancel();
    serving.await.unwrap();
    runtime.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webtransport_native_h3_accepts_public_go_client_stream_and_datagram() {
    use tokio::io::AsyncWriteExt;
    let (root, identity) = private_ca_identity();
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = socket.local_addr().unwrap();
    let acceptor = Acceptor::bind_webtransport_on_socket(
        socket,
        AcceptorOptions {
            bind_address: address,
            certificate_chain_der: identity.chain,
            private_key_der: identity.key,
            max_inbound_streams: 1,
            accept_timeout: Duration::from_secs(10),
        },
        WebTransportListenerPolicy::new("127.0.0.1", vec![ORIGIN.into()])
            .unwrap()
            .with_profile(crate::WebTransportProfile::NativeH3),
    )
    .unwrap();
    let artifact = direct(
        &format!("https://{address}{}", crate::webtransport_v5::DIRECT),
        json!({"mode":"ca"}),
    );
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut child = tokio::process::Command::new("go")
        .current_dir(dir.join("../flowersec-go"))
        .env("GOWORK", "off")
        .args(["run", "-mod=readonly"])
        .arg(dir.join("tests/support/native_h3_client.go"))
        .stdin(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&serde_json::to_vec(&json!({ "artifact": String::from_utf8(artifact.encode().into_vec()).unwrap(), "root": base64::engine::general_purpose::STANDARD.encode(root), "origin": ORIGIN })).unwrap()).await.unwrap();
    let server = tokio::time::timeout(
        Duration::from_secs(45),
        acceptor.accept(
            &ArtifactLease::new(artifact, || async { Ok(()) }),
            CancellationToken::new(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        let incoming = server.accept_stream().await.unwrap();
        assert_eq!(
            incoming.stream().read().await.unwrap().unwrap(),
            &b"hello"[..]
        );
        assert!(incoming.stream().read().await.unwrap().is_none());
        incoming
            .stream()
            .write(Bytes::from_static(b"world"))
            .await
            .unwrap();
        incoming.stream().close_write().await.unwrap();
        let channel = server.unreliable_messages().unwrap();
        assert_eq!(channel.receive().await.unwrap(), &b"request"[..]);
        assert_eq!(
            channel
                .send(
                    Bytes::from_static(b"response"),
                    SystemTime::now() + Duration::from_secs(3)
                )
                .await
                .unwrap(),
            UnreliableSendOutcome::Accepted
        );
        assert!(child.wait().await.unwrap().success());
    })
    .await
    .unwrap();
    let _ = server.close().await;
    drop(acceptor);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webtransport_draft02_dials_independent_go_server_and_exchanges_datagrams() {
    dial_go(crate::WebTransportProfile::Draft02).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webtransport_native_h3_dials_independent_go_server_and_exchanges_datagrams() {
    dial_go(crate::WebTransportProfile::NativeH3).await;
}
async fn dial_go(profile: crate::WebTransportProfile) {
    let origin = "https://127.0.0.1:4443";
    let mut command = tokio::process::Command::new("go");
    command.current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../flowersec-go"));
    let mut child = command
        .env("GOWORK", "off")
        .args([
            "run",
            "./internal/cmd/browser-webtransport-peer",
            "--v3-product-direct",
            "--v3-datagram",
            "--origin",
            origin,
        ])
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    use tokio::io::AsyncBufReadExt;
    let mut lines = tokio::io::BufReader::new(stdout).lines();
    let ready = tokio::time::timeout(Duration::from_secs(60), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .expect("Go peer closed before publishing the route");
    let ready: Value = serde_json::from_str(&ready).unwrap();
    let artifact = Artifact::parse(ready["artifact_json"].as_str().unwrap().as_bytes()).unwrap();
    let client = connect_v3(
        ArtifactLease::new(artifact, || async { Ok(()) }),
        ConnectorOptions::new()
            .with_webtransport_profile(profile, origin)
            .unwrap(),
    )
    .await
    .unwrap();
    let channel = client.unreliable_messages().unwrap();
    assert_eq!(
        channel
            .send(
                Bytes::from_static(b"browser-webtransport-datagram-request"),
                SystemTime::now() + Duration::from_secs(5)
            )
            .await
            .unwrap(),
        UnreliableSendOutcome::Accepted
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), channel.receive())
            .await
            .unwrap()
            .unwrap(),
        &b"browser-webtransport-datagram-response"[..]
    );
    let _ = client.close().await;
    assert!(
        tokio::time::timeout(Duration::from_secs(10), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}
