use std::{
    fs,
    io::{BufRead, BufReader, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime},
};

use crate::raw_quic_v2::{
    RawQuicApplicationError, RawQuicClientConfig, RawQuicLimits, RawQuicListener,
    RawQuicPathProfile, RawQuicServerConfig, RawQuicSession, RawQuicStream, SessionContractV2,
};
use crate::{
    Connector, ConnectorOptions,
    artifact_v2::{Artifact, ArtifactLease},
    protocol_v2::CipherSuiteV2,
    session_v2::{RpcHandlerV2, SessionConfigV2, establish_session_v2},
    transport_v2::{CarrierSessionV2, CarrierUnreliableMessageErrorV2, PathKind, SessionRole},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use bytes::Bytes;
use sha2::Digest as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio_util::sync::CancellationToken;

const TEST_CERT_DER_B64: &str = "MIIBjzCCAUGgAwIBAgIUW8hQEpQsUJN9a6qqF2g6hsNpSm8wBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MjAxOTAxMjFaFw0zNjA3MTcxOTAxMjFaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAAihki/Jec+1EaC6E6PsSxjMYFAazrgkNiUIlbj/+A/0o4GkMIGhMB0GA1UdDgQWBBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAfBgNVHSMEGDAWgBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwBQYDK2VwA0EArZng3XitiH2E1pW/NTxQvEOBXJYpYE8coQmLV4yTjfI43CWHMG6lIrwk/so67oe6Z2R4iHGjUm3Tuy50Fl8hBw==";
const TEST_KEY_DER_B64: &str = "MC4CAQAwBQYDK2VwBCIEICxYUWHqGoh0CBBohsaNg/NThm1n3UeWCzYuq6jS+Qi6";

#[tokio::test]
async fn public_connector_runs_localhost_raw_quic_direct_and_tunnel_end_to_end() {
    for (profile, tunnel_role) in [
        (RawQuicPathProfile::Direct, 1),
        (RawQuicPathProfile::Tunnel, 1),
        (RawQuicPathProfile::Tunnel, 2),
    ] {
        let limits = session_limits(1);
        let listener = RawQuicListener::bind(loopback_ephemeral(), server_config(profile, limits))
            .expect("bind facade E2E listener");
        let address = listener.local_addr().expect("facade listener address");
        let server_task = tokio::spawn(async move {
            let raw = listener.accept().await.expect("accept facade QUIC");
            let admission = raw
                .accept_stream()
                .await
                .expect("accept facade FSB2 stream");
            let fsb2 = read_to_end(&admission).await;
            assert_eq!(&fsb2[..4], b"FSB2");
            admission
                .write_all(&admission_success_fixture())
                .await
                .expect("write facade FSA2");
            admission.close_write().await.expect("finish facade FSA2");
            let path = if profile == RawQuicPathProfile::Direct {
                PathKind::Direct
            } else {
                PathKind::Tunnel
            };
            let listener_role = if path == PathKind::Tunnel && tunnel_role == 2 {
                SessionRole::Client
            } else {
                SessionRole::Server
            };
            let binding = fsb2_binding(&fsb2);
            let (local, peer) = if path == PathKind::Direct {
                (None, None)
            } else if listener_role == SessionRole::Server {
                (Some("endpoint-server"), Some("endpoint-client"))
            } else {
                (Some("endpoint-client"), Some("endpoint-server"))
            };
            let session = establish_session_v2(
                Arc::new(raw),
                raw_session_config(
                    listener_role,
                    path,
                    binding,
                    (path == PathKind::Direct).then_some(binding),
                    local,
                    peer,
                    Duration::from_secs(30),
                ),
            )
            .await
            .expect("establish facade server session");
            let unreliable = session
                .unreliable_messages()
                .expect("raw QUIC negotiated unreliable messages after READY");
            assert_eq!(
                unreliable.receive().await.expect("receive client datagram"),
                Bytes::from_static(b"client-datagram")
            );
            assert_eq!(
                unreliable
                    .send(
                        Bytes::from_static(b"server-datagram"),
                        SystemTime::now() + Duration::from_secs(2),
                    )
                    .await
                    .expect("send server datagram"),
                crate::UnreliableSendOutcome::Accepted
            );
            let incoming = session
                .accept_stream()
                .await
                .expect("accept facade client stream");
            assert_eq!(incoming.kind(), "facade-client");
            assert_eq!(
                incoming.stream().read().await.expect("read client payload"),
                Some(Bytes::from_static(b"request"))
            );
            assert_eq!(
                incoming.stream().read().await.expect("read client FIN"),
                None
            );
            incoming
                .stream()
                .write(Bytes::from_static(b"response"))
                .await
                .expect("write response");
            incoming
                .stream()
                .close_write()
                .await
                .expect("finish response");
            let outbound = session
                .open_stream("facade-server", serde_json::Map::new())
                .await
                .expect("open server stream");
            outbound
                .write(Bytes::from_static(b"server-push"))
                .await
                .expect("write server push");
            outbound.close_write().await.expect("finish server push");
            assert_eq!(
                outbound.read().await.expect("read client reverse FIN"),
                None
            );
            session
        });

        let artifact = Artifact::parse(public_connector_artifact(address, profile, tunnel_role))
            .expect("parse opaque facade artifact");
        let spend_count = Arc::new(AtomicUsize::new(0));
        let observed = spend_count.clone();
        let mut lease = ArtifactLease::new(artifact, move || {
            let observed = observed.clone();
            async move {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        });
        let connector = Connector::new(ConnectorOptions {
            trust_roots_der: vec![test_cert_der()],
            connect_timeout: Duration::from_secs(10),
        })
        .expect("create public connector");
        let session = connector
            .connect(&mut lease, CancellationToken::new())
            .await
            .expect("connect through public facade");
        let unreliable = session
            .unreliable_messages()
            .expect("public facade exposes negotiated unreliable messages");
        assert_eq!(unreliable.max_message_size(), 976);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), unreliable.receive())
                .await
                .is_err(),
            "canceling receive must not close the channel"
        );
        assert_eq!(
            unreliable
                .send(
                    Bytes::from_static(b"client-datagram"),
                    SystemTime::now() + Duration::from_secs(2),
                )
                .await
                .expect("send client datagram"),
            crate::UnreliableSendOutcome::Accepted
        );
        assert_eq!(
            unreliable.receive().await.expect("receive server datagram"),
            Bytes::from_static(b"server-datagram")
        );
        assert_eq!(
            unreliable
                .send(
                    Bytes::from(vec![0_u8; 1_025]),
                    SystemTime::now() + Duration::from_secs(2),
                )
                .await,
            Err(crate::UnreliableMessageError::TooLarge)
        );
        assert_eq!(
            unreliable
                .send(
                    Bytes::from_static(b"expired"),
                    SystemTime::now() - Duration::from_millis(1),
                )
                .await,
            Err(crate::UnreliableMessageError::Expired)
        );
        let stream = session
            .open_stream("facade-client", serde_json::Map::new())
            .await
            .expect("open client stream");
        stream
            .write(Bytes::from_static(b"request"))
            .await
            .expect("write client payload");
        stream.close_write().await.expect("finish client request");
        assert_eq!(
            stream.read().await.expect("read response"),
            Some(Bytes::from_static(b"response"))
        );
        assert_eq!(stream.read().await.expect("read response FIN"), None);
        let incoming = session.accept_stream().await.expect("accept server push");
        assert_eq!(incoming.kind(), "facade-server");
        assert_eq!(
            incoming.stream().read().await.expect("read server push"),
            Some(Bytes::from_static(b"server-push"))
        );
        assert_eq!(
            incoming.stream().read().await.expect("read server FIN"),
            None
        );
        incoming
            .stream()
            .close_write()
            .await
            .expect("finish reverse direction");
        assert_eq!(spend_count.load(Ordering::SeqCst), 1);
        assert!(lease.is_committed());
        let server = server_task.await.expect("join facade server");
        session.close().await.expect("close facade client");
        server.close().await.expect("close facade server");
    }
}

fn public_connector_artifact(
    address: SocketAddr,
    profile: RawQuicPathProfile,
    tunnel_role: u8,
) -> Vec<u8> {
    let contract = session_contract(1);
    let candidate = serde_json::json!({
        "id":"q1", "carrier":"raw_quic", "url":format!("quic://localhost:{}", address.port()),
        "wire_profile":format!("flowersec-{}/2", profile_name(profile)),
    });
    let path = match profile {
        RawQuicPathProfile::Direct => {
            serde_json::json!({"kind":"direct","rendezvous_group_id":"group-1","listener_audience":"listener-1","routing_token":"routing-token","candidates":[candidate]})
        }
        RawQuicPathProfile::Tunnel => {
            let (local, peer) = if tunnel_role == 1 {
                ("endpoint-client", "endpoint-server")
            } else {
                ("endpoint-server", "endpoint-client")
            };
            serde_json::json!({"kind":"tunnel","rendezvous_group_id":"group-1","listener_audience":"listener-1","role":tunnel_role,"local_endpoint_instance_id":local,"expected_peer_endpoint_instance_id":peer,"token":"attach-token","candidates":[candidate]})
        }
    };
    serde_json::to_vec(&serde_json::json!({
        "v":2,"profile":"flowersec/2",
        "session":{"channel_id":"channel-1","init_expire_at_unix_s":2000000000_i64,"idle_timeout_seconds":60,"establish_timeout_seconds":30,"rekey_prepare_timeout_seconds":10,"rekey_completion_timeout_seconds":30,"max_inbound_streams":1,"e2ee_psk_b64u":URL_SAFE_NO_PAD.encode([0x92;32]),"allowed_suites":[1,2],"default_suite":1,"selected_features":0,"contract_hash_b64u":URL_SAFE_NO_PAD.encode(contract.contract_hash)},
        "path":path,"scoped":[],"correlation":{"v":2,"tags":[]}
    })).expect("encode facade artifact")
}

#[test]
fn limits_are_bounded_and_validate_relationships() {
    let defaults = RawQuicLimits::default();
    assert_eq!(defaults.max_inbound_bidirectional_streams, 130);
    assert_eq!(defaults.stream_receive_window, 512 << 10);
    assert_eq!(defaults.connection_receive_window, 1 << 20);
    assert_eq!(defaults.handshake_idle_timeout, Duration::from_secs(10));
    assert_eq!(defaults.max_idle_timeout, Duration::from_secs(60));
    assert_eq!(defaults.keep_alive_interval, Duration::from_secs(20));
    defaults.validate().expect("default raw QUIC limits");

    for invalid in [
        RawQuicLimits {
            max_inbound_bidirectional_streams: 0,
            ..defaults
        },
        RawQuicLimits {
            max_inbound_bidirectional_streams: 131,
            ..defaults
        },
        RawQuicLimits {
            stream_receive_window: 0,
            ..defaults
        },
        RawQuicLimits {
            connection_receive_window: defaults.stream_receive_window - 1,
            ..defaults
        },
        RawQuicLimits {
            stream_receive_window: (6 << 20) + 1,
            connection_receive_window: 16 << 20,
            ..defaults
        },
        RawQuicLimits {
            connection_receive_window: (16 << 20) + 1,
            ..defaults
        },
        RawQuicLimits {
            handshake_idle_timeout: Duration::ZERO,
            ..defaults
        },
        RawQuicLimits {
            keep_alive_interval: defaults.max_idle_timeout,
            ..defaults
        },
    ] {
        assert!(invalid.validate().is_err(), "accepted {invalid:?}");
    }
    assert_eq!(
        defaults
            .with_session_v2_logical_stream_limit(1)
            .expect("logical limit")
            .max_inbound_bidirectional_streams,
        3
    );
    assert_eq!(
        defaults
            .with_session_v2_logical_stream_limit(128)
            .expect("maximum logical limit")
            .max_inbound_bidirectional_streams,
        130
    );

    assert!(
        RawQuicServerConfig::new(
            RawQuicPathProfile::Direct,
            Vec::new(),
            test_key_der(),
            defaults,
        )
        .is_err()
    );
    assert!(
        RawQuicServerConfig::new(
            RawQuicPathProfile::Direct,
            vec![test_cert_der()],
            vec![0xde, 0xad, 0xbe, 0xef],
            defaults,
        )
        .is_err()
    );
}

#[tokio::test]
async fn exact_direct_and_tunnel_alpn_complete_tls13_handshakes() {
    for profile in [RawQuicPathProfile::Direct, RawQuicPathProfile::Tunnel] {
        let (listener, client, server) =
            new_pair(profile, default_limits(), default_limits()).await;
        assert_eq!(client.negotiated_profile(), profile);
        assert_eq!(server.negotiated_profile(), profile);
        assert_eq!(
            listener.local_addr().expect("listener address").ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        native_round_trip(&client, &server).await;
    }
}

#[tokio::test]
async fn raw_quic_admission_preflight_rejects_invalid_fsb2_before_opening_stream() {
    let valid = admission_request_fixture(RawQuicPathProfile::Direct);
    let mut cases = Vec::new();

    let mut reserved = valid.clone();
    reserved[6] = 1;
    cases.push(("reserved-header", reserved));

    let mut truncated = valid.clone();
    truncated.pop();
    cases.push(("truncated-payload", truncated));

    let mut trailing = valid.clone();
    trailing.push(0);
    cases.push(("trailing-byte", trailing));

    let mut noncanonical = valid.clone();
    let payload_length = u32::from_be_bytes(noncanonical[8..12].try_into().expect("length"));
    noncanonical.push(b' ');
    noncanonical[8..12].copy_from_slice(&(payload_length + 1).to_be_bytes());
    cases.push(("noncanonical-json", noncanonical));

    let mut wrong_path = valid.clone();
    wrong_path[5] = 2;
    cases.push(("wrong-path", wrong_path));

    let mut wrong_candidate = valid.clone();
    let chosen = b"\"chosen_candidate_id\":\"q1\"";
    let chosen_offset = wrong_candidate
        .windows(chosen.len())
        .position(|window| window == chosen)
        .expect("chosen candidate field");
    wrong_candidate[chosen_offset + chosen.len() - 2] = b't';
    cases.push(("non-raw-quic-chosen-candidate", wrong_candidate));

    let invalid_authority = mutate_fsb2_payload(&valid, |payload| {
        payload["candidates"][0]["normalized_url"] = serde_json::json!("quic://");
    });
    cases.push(("invalid-candidate-authority", invalid_authority));

    let duplicate_tuple = mutate_fsb2_payload(&valid, |payload| {
        let candidates = payload["candidates"]
            .as_array_mut()
            .expect("candidate array");
        let mut duplicate = candidates[0].clone();
        duplicate["id"] = serde_json::json!("q2");
        candidates.insert(1, duplicate);
    });
    cases.push(("duplicate-candidate-tuple", duplicate_tuple));

    for (name, raw) in cases {
        let (_listener, client, server) = new_pair(
            RawQuicPathProfile::Direct,
            session_limits(1),
            session_limits(1),
        )
        .await;
        let result = client
            .commit_admission_and_establish_v2(
                &raw,
                raw_session_config(
                    SessionRole::Client,
                    PathKind::Direct,
                    [0; 32],
                    Some(fsb2_binding(&raw)),
                    None,
                    None,
                    Duration::from_secs(1),
                ),
                session_contract(1),
            )
            .await;
        assert!(result.is_err(), "accepted malformed FSB2 case {name}");
        assert!(
            !matches!(
                tokio::time::timeout(Duration::from_millis(100), server.accept_stream()).await,
                Ok(Ok(_))
            ),
            "opened an admission stream for malformed FSB2 case {name}"
        );
    }
}

#[tokio::test]
async fn raw_quic_admission_preflight_binds_fsb2_to_session_config_before_opening_stream() {
    let direct = admission_request_fixture(RawQuicPathProfile::Direct);
    let tunnel = admission_request_fixture(RawQuicPathProfile::Tunnel);

    let mut wrong_channel = raw_session_config(
        SessionRole::Client,
        PathKind::Direct,
        [0; 32],
        Some(fsb2_binding(&direct)),
        None,
        None,
        Duration::from_secs(1),
    );
    wrong_channel.channel_id = "other-channel".into();

    let mut wrong_contract = wrong_channel.clone();
    wrong_contract.channel_id = "channel-1".into();
    wrong_contract.session_contract_hash = [0x55; 32];

    let wrong_binding = raw_session_config(
        SessionRole::Client,
        PathKind::Direct,
        [0x77; 32],
        Some(fsb2_binding(&direct)),
        None,
        None,
        Duration::from_secs(1),
    );

    let wrong_direct_role = raw_session_config(
        SessionRole::Server,
        PathKind::Direct,
        [0; 32],
        Some(fsb2_binding(&direct)),
        None,
        None,
        Duration::from_secs(1),
    );

    let wrong_tunnel_role = raw_session_config(
        SessionRole::Server,
        PathKind::Tunnel,
        [0; 32],
        None,
        Some("endpoint-client"),
        Some("endpoint-server"),
        Duration::from_secs(1),
    );

    let wrong_tunnel_endpoint = raw_session_config(
        SessionRole::Client,
        PathKind::Tunnel,
        [0; 32],
        None,
        Some("other-endpoint"),
        Some("endpoint-server"),
        Duration::from_secs(1),
    );

    for (name, profile, raw, config) in [
        (
            "channel-id",
            RawQuicPathProfile::Direct,
            direct.clone(),
            wrong_channel,
        ),
        (
            "session-contract-hash",
            RawQuicPathProfile::Direct,
            direct.clone(),
            wrong_contract,
        ),
        (
            "local-admission-binding",
            RawQuicPathProfile::Direct,
            direct.clone(),
            wrong_binding,
        ),
        (
            "direct-role",
            RawQuicPathProfile::Direct,
            direct,
            wrong_direct_role,
        ),
        (
            "tunnel-role",
            RawQuicPathProfile::Tunnel,
            tunnel.clone(),
            wrong_tunnel_role,
        ),
        (
            "tunnel-endpoint-instance-id",
            RawQuicPathProfile::Tunnel,
            tunnel,
            wrong_tunnel_endpoint,
        ),
    ] {
        let (_listener, client, server) =
            new_pair(profile, session_limits(1), session_limits(1)).await;
        let result = client
            .commit_admission_and_establish_v2(&raw, config, session_contract(1))
            .await;
        assert!(result.is_err(), "accepted FSB2/config mismatch {name}");
        assert!(
            !matches!(
                tokio::time::timeout(Duration::from_millis(100), server.accept_stream()).await,
                Ok(Ok(_))
            ),
            "opened an admission stream for FSB2/config mismatch {name}"
        );
    }
}

#[tokio::test]
async fn active_connection_survives_local_udp_rebinding() {
    let (_listener, client, server) = new_pair(
        RawQuicPathProfile::Direct,
        default_limits(),
        default_limits(),
    )
    .await;
    let previous = client.local_address().expect("client local address");
    let rebound = client
        .migrate_local_address(loopback_ephemeral())
        .expect("rebind active raw QUIC session");
    assert_ne!(rebound, previous);
    native_round_trip(&client, &server).await;
}

#[tokio::test]
async fn handshake_rejects_wrong_alpn_hostname_and_trust() {
    let listener = RawQuicListener::bind(
        loopback_ephemeral(),
        server_config(RawQuicPathProfile::Direct, default_limits()),
    )
    .expect("bind raw QUIC listener");

    let mismatched_alpn = RawQuicSession::dial(
        loopback_ephemeral(),
        listener.local_addr().expect("listener address"),
        "localhost",
        client_config(RawQuicPathProfile::Tunnel, default_limits()),
    );
    let accept = listener.accept();
    let (dial_result, accept_result) = tokio::join!(mismatched_alpn, accept);
    assert!(dial_result.is_err());
    assert!(accept_result.is_err());

    let wrong_hostname = RawQuicSession::dial(
        loopback_ephemeral(),
        listener.local_addr().expect("listener address"),
        "not-localhost.invalid",
        client_config(RawQuicPathProfile::Direct, default_limits()),
    );
    let accept = listener.accept();
    let (dial_result, accept_result) = tokio::join!(wrong_hostname, accept);
    assert!(dial_result.is_err());
    assert!(accept_result.is_err());

    assert!(
        RawQuicClientConfig::new(RawQuicPathProfile::Direct, Vec::new(), default_limits(),)
            .is_err()
    );
    assert!(
        RawQuicClientConfig::new(
            RawQuicPathProfile::Direct,
            vec![vec![0xde, 0xad, 0xbe, 0xef]],
            default_limits(),
        )
        .is_err()
    );
}

#[tokio::test]
async fn handshake_black_hole_is_bounded_by_the_configured_deadline() {
    let black_hole = std::net::UdpSocket::bind(loopback_ephemeral()).expect("bind UDP black hole");
    let limits = RawQuicLimits {
        handshake_idle_timeout: Duration::from_millis(100),
        max_idle_timeout: Duration::from_secs(1),
        keep_alive_interval: Duration::from_millis(250),
        ..default_limits()
    };
    let started = std::time::Instant::now();
    let result = RawQuicSession::dial(
        loopback_ephemeral(),
        black_hole.local_addr().expect("black-hole address"),
        "localhost",
        client_config(RawQuicPathProfile::Direct, limits),
    )
    .await;
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn native_fin_keeps_the_reverse_direction_readable() {
    let (_listener, client, server) = new_pair(
        RawQuicPathProfile::Direct,
        default_limits(),
        default_limits(),
    )
    .await;

    let client_stream = client.open_stream().await.expect("open client stream");
    client_stream
        .write_all(b"request")
        .await
        .expect("write request");
    client_stream.close_write().await.expect("finish request");

    let server_stream = server.accept_stream().await.expect("accept client stream");
    assert_eq!(read_to_end(&server_stream).await, b"request");
    server_stream
        .write_all(b"response")
        .await
        .expect("write response");
    server_stream.close_write().await.expect("finish response");
    assert_eq!(read_to_end(&client_stream).await, b"response");
}

#[tokio::test]
async fn native_reset_aborts_both_directions_without_harming_siblings() {
    let (_listener, client, server) = new_pair(
        RawQuicPathProfile::Direct,
        default_limits(),
        default_limits(),
    )
    .await;

    let reset_client = client.open_stream().await.expect("open reset stream");
    let sibling_client = client.open_stream().await.expect("open sibling stream");
    reset_client
        .write_all(b"reset-me")
        .await
        .expect("write reset stream");
    sibling_client
        .write_all(b"survivor")
        .await
        .expect("write sibling stream");

    let reset_server = server.accept_stream().await.expect("accept reset stream");
    let sibling_server = server.accept_stream().await.expect("accept sibling stream");
    reset_client.reset().await.expect("reset client stream");

    let mut buffer = [0_u8; 32];
    let reset_error = loop {
        match reset_server.read(&mut buffer).await {
            Ok(0) => panic!("reset stream ended with a clean FIN"),
            Ok(_) => {}
            Err(error) => break error,
        }
    };
    assert_eq!(reset_error.kind(), std::io::ErrorKind::ConnectionReset);

    sibling_client
        .close_write()
        .await
        .expect("finish sibling request");
    assert_eq!(read_to_end(&sibling_server).await, b"survivor");
    sibling_server
        .write_all(b"still-alive")
        .await
        .expect("write sibling response");
    sibling_server
        .close_write()
        .await
        .expect("finish sibling response");
    assert_eq!(read_to_end(&sibling_client).await, b"still-alive");
}

#[tokio::test]
async fn reset_interrupts_a_blocked_local_read() {
    let (_listener, client, server) = new_pair(
        RawQuicPathProfile::Direct,
        default_limits(),
        default_limits(),
    )
    .await;
    let stream = Arc::new(client.open_stream().await.expect("open client stream"));
    stream
        .write_all(b"visible")
        .await
        .expect("make stream visible");
    let _peer = server.accept_stream().await.expect("accept client stream");

    let reader = {
        let stream = Arc::clone(&stream);
        tokio::spawn(async move {
            let mut buffer = [0_u8; 1];
            stream.read(&mut buffer).await
        })
    };
    tokio::task::yield_now().await;
    tokio::time::timeout(Duration::from_secs(1), stream.reset())
        .await
        .expect("reset remained blocked behind read")
        .expect("reset stream");
    let error = reader
        .await
        .expect("join blocked reader")
        .expect_err("blocked read survived reset");
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn application_close_diagnostics_are_bounded_before_transport_use() {
    let (_listener, client, server) = new_pair(
        RawQuicPathProfile::Direct,
        default_limits(),
        default_limits(),
    )
    .await;
    assert!(
        client
            .close_with_error(RawQuicApplicationError {
                code: 1_u64 << 62,
                reason: String::new(),
            })
            .is_err()
    );
    assert!(
        client
            .close_with_error(RawQuicApplicationError {
                code: 7,
                reason: "x".repeat(129),
            })
            .is_err()
    );
    native_round_trip(&client, &server).await;
}

#[tokio::test]
async fn peer_stream_limit_blocks_until_capacity_is_released() {
    let server_limits = RawQuicLimits {
        max_inbound_bidirectional_streams: 1,
        ..default_limits()
    };
    let (_listener, client, server) =
        new_pair(RawQuicPathProfile::Direct, default_limits(), server_limits).await;

    let first_client = client.open_stream().await.expect("open first stream");
    first_client
        .write_all(b"occupied")
        .await
        .expect("use first stream");
    let first_server = server.accept_stream().await.expect("accept first stream");

    assert!(
        tokio::time::timeout(Duration::from_millis(100), client.open_stream())
            .await
            .is_err(),
        "second stream bypassed the peer's advertised stream limit"
    );

    first_client
        .reset()
        .await
        .expect("reset first client stream");
    first_server
        .reset()
        .await
        .expect("reset first server stream");
    drop(first_client);
    drop(first_server);

    let second_client = tokio::time::timeout(Duration::from_secs(2), client.open_stream())
        .await
        .expect("stream capacity was not released")
        .expect("open second stream");
    second_client
        .write_all(b"released")
        .await
        .expect("use second stream");
    second_client
        .close_write()
        .await
        .expect("finish second stream");
    let second_server = server.accept_stream().await.expect("accept second stream");
    assert_eq!(read_to_end(&second_server).await, b"released");
}

#[tokio::test]
async fn raw_quic_control_and_rpc_slots_preserve_one_data_stream_capacity() {
    let limits = session_limits(1);
    assert_eq!(limits.max_inbound_bidirectional_streams, 3);
    let (_listener, client_raw, server_raw) =
        new_pair(RawQuicPathProfile::Direct, limits, limits).await;
    let client_carrier: Arc<dyn CarrierSessionV2> = Arc::new(client_raw);
    let server_carrier: Arc<dyn CarrierSessionV2> = Arc::new(server_raw);
    let client_config = SessionConfigV2 {
        role: SessionRole::Client,
        path: PathKind::Direct,
        channel_id: "raw-quic-capacity-one".into(),
        session_contract_hash: [0x61; 32],
        suite: CipherSuiteV2::ChaCha20Poly1305,
        psk: [0x62; 32],
        max_inbound_streams: 1,
        idle_timeout: Duration::from_secs(60),
        local_admission_binding: [1; 32],
        peer_admission_binding: Some([2; 32]),
        local_endpoint_instance_id: None,
        expected_peer_endpoint_instance_id: None,
        rpc_handler: Some(Arc::new(InteropRpc)),
        deadlines: Default::default(),
    };
    let server_config = SessionConfigV2 {
        role: SessionRole::Server,
        local_admission_binding: [2; 32],
        peer_admission_binding: Some([1; 32]),
        ..client_config.clone()
    };
    let (client, server) = tokio::join!(
        establish_session_v2(client_carrier, client_config),
        establish_session_v2(server_carrier, server_config),
    );
    let client = client.expect("client SessionV2");
    let server = server.expect("server SessionV2");
    let rpc = client
        .rpc()
        .call(1, serde_json::json!({"capacity": "reserved"}))
        .await
        .expect("reserved RPC stream");
    assert_eq!(rpc["capacity"], "reserved");

    let (first, first_incoming) = tokio::join!(
        client.open_stream("first", serde_json::Map::new()),
        server.accept_stream(),
    );
    let first = first.expect("first logical stream");
    let _first_incoming = first_incoming.expect("accept first logical stream");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            client.open_stream("blocked", serde_json::Map::new()),
        )
        .await
        .is_err(),
        "second logical stream bypassed the SessionV2 semaphore"
    );

    first.reset().await.expect("reset first logical stream");
    client
        .probe_liveness()
        .await
        .expect("observe peer after reset control record");
    let (third, third_incoming) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            client.open_stream("third", serde_json::Map::new()),
            server.accept_stream(),
        )
    })
    .await
    .expect("capacity was not released after reset");
    assert_eq!(third.expect("third logical stream").internal_test_id(), 5);
    assert_eq!(
        third_incoming
            .expect("accept third logical stream")
            .internal_test_id(),
        5
    );
    client.close().await.expect("close client");
    server.close().await.expect("close server");
}

#[test]
fn public_source_hides_quinn_yamux_and_early_data() {
    let source = include_str!("../src/raw_quic_v2.rs");
    for line in source.lines() {
        let public = line.trim_start().starts_with("pub ");
        assert!(
            !(public && line.contains("quinn")),
            "public quinn surface: {line}"
        );
        assert!(
            !(public && line.contains("yamux")),
            "public Yamux surface: {line}"
        );
    }
    assert!(!source.contains("into_0rtt"));
    assert!(source.contains("max_concurrent_uni_streams(0"));
    assert!(source.contains("datagram_receive_buffer_size(Some("));
    assert!(source.contains("enable_early_data = false"));
    assert!(source.contains("max_early_data_size = 0"));
    assert!(source.contains("with_protocol_versions(&[&rustls::version::TLS13])"));

    let manifest = include_str!("../Cargo.toml");
    let lockfile = include_str!("../Cargo.lock");
    assert!(manifest.contains("quinn = { version = \"=0.11.11\""));
    assert!(
        !manifest
            .lines()
            .any(|line| line.trim_start().starts_with("rcgen"))
    );
    assert!(!lockfile.lines().any(|line| line == "name = \"rcgen\""));
}

#[tokio::test]
async fn raw_quic_negotiates_and_transfers_native_unreliable_messages() {
    let (_listener, client, server) = new_pair(
        RawQuicPathProfile::Direct,
        default_limits(),
        default_limits(),
    )
    .await;
    let client_max = CarrierSessionV2::unreliable_message_max_size(&client)
        .expect("client negotiated QUIC DATAGRAM");
    let server_max = CarrierSessionV2::unreliable_message_max_size(&server)
        .expect("server negotiated QUIC DATAGRAM");
    assert!(client_max >= 1_000);
    assert!(server_max >= 1_000);

    CarrierSessionV2::send_unreliable_message(&client, Bytes::from_static(b"native-datagram"))
        .await
        .expect("send native QUIC DATAGRAM");
    assert_eq!(
        CarrierSessionV2::receive_unreliable_message(&server)
            .await
            .expect("receive native QUIC DATAGRAM"),
        Bytes::from_static(b"native-datagram")
    );
}

#[tokio::test]
async fn raw_quic_unreliable_messages_reject_oversize_without_stream_fallback() {
    let (_listener, client, server) = new_pair(
        RawQuicPathProfile::Direct,
        default_limits(),
        default_limits(),
    )
    .await;
    let maximum = CarrierSessionV2::unreliable_message_max_size(&client).unwrap();
    let result =
        CarrierSessionV2::send_unreliable_message(&client, Bytes::from(vec![0_u8; maximum + 1]))
            .await;
    assert_eq!(result, Err(CarrierUnreliableMessageErrorV2::TooLarge));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), server.accept_stream())
            .await
            .is_err(),
        "oversize DATAGRAM must not open a reliable stream"
    );
}

#[tokio::test]
async fn raw_quic_unreliable_send_reports_exhausted_budget_without_queue_fallback() {
    let profile = RawQuicPathProfile::Direct;
    let limits = default_limits();
    let listener = RawQuicListener::bind(loopback_ephemeral(), server_config(profile, limits))
        .expect("bind budget listener");
    let address = listener.local_addr().expect("budget listener address");
    let constrained = client_config(profile, limits)
        .with_datagram_send_buffer_for_test(1)
        .expect("constrain DATAGRAM send budget");
    let (client, server) = tokio::join!(
        RawQuicSession::dial(loopback_ephemeral(), address, "localhost", constrained),
        listener.accept(),
    );
    let client = client.expect("dial constrained DATAGRAM client");
    let server = server.expect("accept constrained DATAGRAM client");
    assert_eq!(
        CarrierSessionV2::send_unreliable_message(&client, Bytes::from_static(b"budget")).await,
        Err(CarrierUnreliableMessageErrorV2::Dropped)
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), server.accept_stream())
            .await
            .is_err(),
        "exhausted DATAGRAM budget must not open a reliable stream"
    );
}

#[tokio::test]
async fn raw_quic_unreliable_receive_stops_when_connection_closes() {
    let (_listener, client, server) = new_pair(
        RawQuicPathProfile::Direct,
        default_limits(),
        default_limits(),
    )
    .await;
    let receive = CarrierSessionV2::receive_unreliable_message(&server);
    client.close();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), receive)
            .await
            .expect("close must wake DATAGRAM receive"),
        Err(CarrierUnreliableMessageErrorV2::Closed)
    );
}

#[tokio::test]
async fn go_client_to_rust_server_runs_admission_over_native_quic() {
    for profile in [RawQuicPathProfile::Direct, RawQuicPathProfile::Tunnel] {
        let listener = RawQuicListener::bind(
            loopback_ephemeral(),
            server_config(profile, default_limits()),
        )
        .expect("bind Rust raw QUIC server");
        let address = listener.local_addr().expect("listener address").to_string();
        let go = tokio::task::spawn_blocking(move || go_peer("client", Some(&address), profile));

        let session = listener.accept().await.expect("accept Go client");
        let stream = session
            .accept_stream()
            .await
            .expect("accept admission stream");
        let expected_request = admission_request_vector_fixture(profile);
        assert_eq!(read_to_end(&stream).await, expected_request);
        stream
            .write_all(&admission_success_fixture())
            .await
            .expect("write FSA2 success");
        stream
            .close_write()
            .await
            .expect("finish admission response");

        let output = go.await.expect("join Go client");
        assert!(
            output.status.success(),
            "Go client failed for {profile:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("OK"));
    }
}

#[tokio::test]
async fn rust_client_to_go_server_runs_admission_over_native_quic() {
    for profile in [RawQuicPathProfile::Direct, RawQuicPathProfile::Tunnel] {
        let mut child = go_peer_command("server", None, profile)
            .stdout(Stdio::piped())
            .spawn()
            .expect("start Go raw QUIC server");
        let stdout = child.stdout.take().expect("Go server stdout");
        let (mut reader, ready) = tokio::task::spawn_blocking(move || {
            let mut reader = BufReader::new(stdout);
            let mut ready = String::new();
            reader
                .read_line(&mut ready)
                .expect("read Go server READY line");
            (reader, ready)
        })
        .await
        .expect("join READY reader");
        let address = ready
            .trim()
            .strip_prefix("READY ")
            .expect("Go server READY prefix")
            .parse::<SocketAddr>()
            .expect("Go server address");

        let session = RawQuicSession::dial(
            loopback_ephemeral(),
            address,
            "localhost",
            client_config(profile, default_limits()),
        )
        .await
        .expect("dial Go raw QUIC server");
        let stream = session.open_stream().await.expect("open admission stream");
        stream
            .write_all(&admission_request_fixture(profile))
            .await
            .expect("write FSB2 request");
        stream
            .close_write()
            .await
            .expect("finish admission request");
        assert_eq!(read_to_end(&stream).await, admission_success_fixture());
        let barrier = session.open_stream().await.expect("open delivery barrier");
        barrier
            .write_all(b"ACK")
            .await
            .expect("write delivery barrier");
        barrier
            .close_write()
            .await
            .expect("finish delivery barrier");

        let status = tokio::task::spawn_blocking(move || {
            let status = child.wait().expect("wait for Go server");
            let mut remainder = String::new();
            reader
                .read_to_string(&mut remainder)
                .expect("read Go server output");
            (status, remainder)
        })
        .await
        .expect("join Go server wait");
        assert!(status.0.success(), "Go server failed: {}", status.1);
        assert!(status.1.contains("OK"));
    }
}

#[derive(Debug)]
struct InteropRpc;

#[async_trait::async_trait]
impl RpcHandlerV2 for InteropRpc {
    async fn call(
        &self,
        _type_id: u32,
        request: serde_json::Value,
    ) -> std::io::Result<serde_json::Value> {
        Ok(request)
    }

    async fn notify(&self, _type_id: u32, _request: serde_json::Value) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn rust_and_go_run_full_session_v2_over_raw_quic_direct_and_tunnel() {
    for profile in [RawQuicPathProfile::Direct, RawQuicPathProfile::Tunnel] {
        let mut child = go_peer_command("session-server", None, profile)
            .stdout(Stdio::piped())
            .spawn()
            .expect("start Go SessionV2 server");
        let stdout = child.stdout.take().expect("Go server stdout");
        let (mut reader, ready) = tokio::task::spawn_blocking(move || {
            let mut reader = BufReader::new(stdout);
            let mut ready = String::new();
            reader.read_line(&mut ready).expect("read Go READY");
            (reader, ready)
        })
        .await
        .expect("join READY reader");
        let address = ready
            .trim()
            .strip_prefix("READY ")
            .expect("READY prefix")
            .parse::<SocketAddr>()
            .expect("Go address");
        let raw = RawQuicSession::dial(
            loopback_ephemeral(),
            address,
            "localhost",
            client_config(profile, session_limits(4)),
        )
        .await
        .expect("dial Go SessionV2 server");
        let contract = session_contract_with_psk(4, [0x42; 32]);
        let raw_fsb2 = admission_request_fixture_with_contract(profile, contract.contract_hash);
        let (local_endpoint, peer_endpoint) = match profile {
            RawQuicPathProfile::Direct => (None, None),
            RawQuicPathProfile::Tunnel => (
                Some("endpoint-client".to_owned()),
                Some("endpoint-server".to_owned()),
            ),
        };
        let session = raw
            .commit_admission_and_establish_v2(
                &raw_fsb2,
                SessionConfigV2 {
                    role: SessionRole::Client,
                    path: match profile {
                        RawQuicPathProfile::Direct => PathKind::Direct,
                        RawQuicPathProfile::Tunnel => PathKind::Tunnel,
                    },
                    channel_id: "channel-1".into(),
                    session_contract_hash: contract.contract_hash,
                    suite: CipherSuiteV2::ChaCha20Poly1305,
                    psk: [0x42; 32],
                    max_inbound_streams: 4,
                    idle_timeout: Duration::from_secs(60),
                    local_admission_binding: [0; 32],
                    peer_admission_binding: (profile == RawQuicPathProfile::Direct)
                        .then(|| fsb2_binding(&raw_fsb2)),
                    local_endpoint_instance_id: local_endpoint,
                    expected_peer_endpoint_instance_id: peer_endpoint,
                    rpc_handler: Some(Arc::new(InteropRpc)),
                    deadlines: Default::default(),
                },
                contract,
            )
            .await
            .expect("admit and establish Rust SessionV2");

        let stream = session
            .open_stream("rust-open", serde_json::Map::new())
            .await
            .expect("Rust opens logical stream");
        stream
            .write(Bytes::from_static(b"rust-app"))
            .await
            .expect("write Rust app payload");
        stream.close_write().await.expect("Rust app FIN");
        let incoming = session.accept_stream().await.expect("accept Go stream");
        assert_eq!(incoming.kind(), "go-open");
        assert_eq!(
            incoming.stream().read().await.expect("read Go app stream"),
            Some(Bytes::from_static(b"from-go"))
        );
        assert_eq!(
            incoming.stream().read().await.expect("read Go stream FIN"),
            None
        );
        incoming
            .stream()
            .close_write()
            .await
            .expect("close reverse Go stream direction");

        let response = session
            .rpc()
            .call(22, serde_json::json!({"from": "rust"}))
            .await
            .expect("Rust to Go RPC");
        assert_eq!(response["from"], "rust");
        session.rekey().await.expect("Rust/Go SessionV2 rekey");
        let response = session
            .rpc()
            .call(22, serde_json::json!({"epoch": 1}))
            .await
            .expect("Rust to Go RPC after rekey");
        assert_eq!(response["epoch"], 1);
        let done = session
            .open_stream("done", serde_json::Map::new())
            .await
            .expect("open done stream");
        let response = session
            .rpc()
            .call(23, serde_json::json!({"open_acknowledged": true}))
            .await
            .expect("synchronize accepted done stream");
        assert_eq!(response["open_acknowledged"], true);
        let receipt = Bytes::from_static(b"rpc-response-observed");
        let written = done
            .write(receipt.clone())
            .await
            .expect("confirm RPC response receipt");
        assert_eq!(written, receipt.len());
        done.close_write()
            .await
            .expect("finish RPC response receipt");

        let (status, remainder) = tokio::task::spawn_blocking(move || {
            let status = child.wait().expect("wait Go SessionV2 server");
            let mut remainder = String::new();
            reader
                .read_to_string(&mut remainder)
                .expect("read Go output");
            (status, remainder)
        })
        .await
        .expect("join Go server wait");
        assert!(status.success(), "Go SessionV2 failed: {remainder}");
        assert!(remainder.contains("OK"), "Go output: {remainder}");
        session.close().await.expect("close Rust SessionV2");
    }
}

#[tokio::test]
async fn tunnel_session_accepts_distinct_admission_bindings_for_both_legs() {
    let profile = RawQuicPathProfile::Tunnel;
    let limits = session_limits(1);
    let listener = RawQuicListener::bind(loopback_ephemeral(), server_config(profile, limits))
        .expect("bind tunnel listener");
    let address = listener.local_addr().expect("tunnel listener address");
    let server_task = tokio::spawn(async move {
        let raw = listener.accept().await.expect("accept tunnel raw QUIC");
        let admission = raw
            .accept_stream()
            .await
            .expect("accept tunnel admission stream");
        assert_eq!(
            read_to_end(&admission).await,
            admission_request_fixture(profile)
        );
        admission
            .write_all(&admission_success_fixture())
            .await
            .expect("write tunnel FSA2");
        admission.close_write().await.expect("finish tunnel FSA2");
        establish_session_v2(
            Arc::new(raw),
            raw_session_config(
                SessionRole::Server,
                PathKind::Tunnel,
                [0x99; 32],
                None,
                Some("endpoint-server"),
                Some("endpoint-client"),
                Duration::from_secs(30),
            ),
        )
        .await
        .expect("establish server with independent tunnel binding")
    });
    let raw = RawQuicSession::dial(
        loopback_ephemeral(),
        address,
        "localhost",
        client_config(profile, limits),
    )
    .await
    .expect("dial tunnel raw QUIC");
    let client = raw
        .commit_admission_and_establish_v2(
            &admission_request_fixture(profile),
            raw_session_config(
                SessionRole::Client,
                PathKind::Tunnel,
                [0; 32],
                None,
                Some("endpoint-client"),
                Some("endpoint-server"),
                Duration::from_secs(30),
            ),
            session_contract(1),
        )
        .await
        .expect("establish client with independent tunnel binding");
    let server = server_task.await.expect("join tunnel server");
    client.close().await.expect("close tunnel client");
    server.close().await.expect("close tunnel server");
}

#[tokio::test]
async fn admission_and_session_handshake_share_one_establishment_deadline() {
    let profile = RawQuicPathProfile::Direct;
    let limits = session_limits(1);
    let listener = RawQuicListener::bind(loopback_ephemeral(), server_config(profile, limits))
        .expect("bind admission deadline listener");
    let address = listener.local_addr().expect("admission deadline address");
    let stalled_server = tokio::spawn(async move {
        let raw = listener.accept().await.expect("accept deadline raw QUIC");
        let admission = raw
            .accept_stream()
            .await
            .expect("accept deadline admission stream");
        let _request = read_to_end(&admission).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    let raw = RawQuicSession::dial(
        loopback_ephemeral(),
        address,
        "localhost",
        client_config(profile, limits),
    )
    .await
    .expect("dial admission deadline peer");
    let deadline_contract = session_contract_with_establish(1, 1);
    let deadline_raw =
        admission_request_fixture_with_contract(profile, deadline_contract.contract_hash);
    let mut deadline_config = raw_session_config(
        SessionRole::Client,
        PathKind::Direct,
        [0; 32],
        Some(fsb2_binding(&deadline_raw)),
        None,
        None,
        Duration::from_secs(1),
    );
    deadline_config.session_contract_hash = deadline_contract.contract_hash;
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        raw.commit_admission_and_establish_v2(&deadline_raw, deadline_config, deadline_contract),
    )
    .await
    .expect("admission ignored the total establishment deadline")
    .expect_err("stalled FSA2 must time out");
    assert_eq!(result.kind(), std::io::ErrorKind::TimedOut);
    stalled_server.abort();
}

async fn new_pair(
    profile: RawQuicPathProfile,
    client_limits: RawQuicLimits,
    server_limits: RawQuicLimits,
) -> (RawQuicListener, RawQuicSession, RawQuicSession) {
    let listener =
        RawQuicListener::bind(loopback_ephemeral(), server_config(profile, server_limits))
            .expect("bind raw QUIC listener");
    let address = listener.local_addr().expect("listener address");
    let dial = RawQuicSession::dial(
        loopback_ephemeral(),
        address,
        "localhost",
        client_config(profile, client_limits),
    );
    let accept = listener.accept();
    let (client, server) = tokio::join!(dial, accept);
    (
        listener,
        client.expect("dial raw QUIC session"),
        server.expect("accept raw QUIC session"),
    )
}

async fn native_round_trip(client: &RawQuicSession, server: &RawQuicSession) {
    let stream = client.open_stream().await.expect("open native stream");
    stream
        .write_all(b"native-bidi")
        .await
        .expect("write native stream");
    stream.close_write().await.expect("finish native request");
    let peer = server.accept_stream().await.expect("accept native stream");
    assert_eq!(read_to_end(&peer).await, b"native-bidi");
    peer.write_all(b"response")
        .await
        .expect("write native response");
    peer.close_write().await.expect("finish native response");
    assert_eq!(read_to_end(&stream).await, b"response");
}

async fn read_to_end(stream: &RawQuicStream) -> Vec<u8> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream.read(&mut buffer).await.expect("read native stream");
        if read == 0 {
            return output;
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

fn client_config(profile: RawQuicPathProfile, limits: RawQuicLimits) -> RawQuicClientConfig {
    RawQuicClientConfig::new(profile, vec![test_cert_der()], limits)
        .expect("build raw QUIC client config")
}

fn server_config(profile: RawQuicPathProfile, limits: RawQuicLimits) -> RawQuicServerConfig {
    RawQuicServerConfig::new(profile, vec![test_cert_der()], test_key_der(), limits)
        .expect("build raw QUIC server config")
}

fn test_cert_der() -> Vec<u8> {
    STANDARD
        .decode(TEST_CERT_DER_B64)
        .expect("decode static certificate DER")
}

fn test_key_der() -> Vec<u8> {
    STANDARD
        .decode(TEST_KEY_DER_B64)
        .expect("decode static private key DER")
}

fn default_limits() -> RawQuicLimits {
    RawQuicLimits::default()
}

fn session_limits(logical_max: u16) -> RawQuicLimits {
    RawQuicLimits::default()
        .with_session_v2_logical_stream_limit(logical_max)
        .expect("SessionV2 raw QUIC limits")
}

fn raw_session_config(
    role: SessionRole,
    path: PathKind,
    local_admission_binding: [u8; 32],
    peer_admission_binding: Option<[u8; 32]>,
    local_endpoint_instance_id: Option<&str>,
    expected_peer_endpoint_instance_id: Option<&str>,
    establish: Duration,
) -> SessionConfigV2 {
    SessionConfigV2 {
        role,
        path,
        channel_id: "channel-1".into(),
        session_contract_hash: fixture_contract_hash(),
        suite: CipherSuiteV2::ChaCha20Poly1305,
        psk: [0x92; 32],
        max_inbound_streams: 1,
        idle_timeout: Duration::from_secs(60),
        local_admission_binding,
        peer_admission_binding,
        local_endpoint_instance_id: local_endpoint_instance_id.map(str::to_owned),
        expected_peer_endpoint_instance_id: expected_peer_endpoint_instance_id.map(str::to_owned),
        rpc_handler: None,
        deadlines: crate::session_v2::SessionDeadlinesV2 {
            establish,
            rekey_prepare: Duration::from_secs(10),
            rekey_completion: Duration::from_secs(30),
            close_flush: Duration::from_millis(100),
        },
    }
}

fn fsb2_binding(raw: &[u8]) -> [u8; 32] {
    let mut preimage = b"flowersec-v2-admission\0".to_vec();
    preimage.extend_from_slice(raw);
    sha2::Sha256::digest(preimage).into()
}

fn fixture_contract_hash() -> [u8; 32] {
    session_contract(1).contract_hash
}

fn session_contract(max_inbound_streams: u16) -> SessionContractV2 {
    session_contract_with_psk(max_inbound_streams, [0x92; 32])
}

fn session_contract_with_establish(
    max_inbound_streams: u16,
    establish_timeout_seconds: u64,
) -> SessionContractV2 {
    let mut contract = session_contract_with_psk(max_inbound_streams, [0x92; 32]);
    contract.establish_timeout_seconds = establish_timeout_seconds;
    contract.contract_hash = contract.canonical_hash();
    contract
}

fn session_contract_with_psk(max_inbound_streams: u16, psk: [u8; 32]) -> SessionContractV2 {
    let mut contract = SessionContractV2 {
        channel_id: "channel-1".into(),
        idle_timeout_seconds: 60,
        establish_timeout_seconds: 30,
        rekey_prepare_timeout_seconds: 10,
        rekey_completion_timeout_seconds: 30,
        max_inbound_streams,
        psk,
        allowed_suites: vec![1, 2],
        default_suite: 1,
        selected_features: 0,
        contract_hash: [0; 32],
    };
    contract.contract_hash = contract.canonical_hash();
    contract
}

fn loopback_ephemeral() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn admission_request_fixture(profile: RawQuicPathProfile) -> Vec<u8> {
    admission_request_fixture_with_max(profile, 1)
}

fn admission_request_fixture_with_max(
    profile: RawQuicPathProfile,
    max_inbound_streams: u16,
) -> Vec<u8> {
    admission_request_fixture_with_contract(
        profile,
        session_contract(max_inbound_streams).contract_hash,
    )
}

fn admission_request_fixture_with_contract(
    profile: RawQuicPathProfile,
    contract_hash: [u8; 32],
) -> Vec<u8> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../testdata/transport_v2/artifact_vectors.json"
    ))
    .expect("parse artifact vectors");
    let path = profile_name(profile);
    let vector = fixture["positive"]
        .as_array()
        .expect("positive vectors")
        .iter()
        .find(|vector| vector["path_kind"] == path)
        .expect("profile artifact vector");
    let winners = vector["winners"].as_array().expect("positive winners");
    let encoded = winners
        .iter()
        .find(|winner| winner["candidate_id"] == "q1")
        .and_then(|winner| winner["fsb2_hex"].as_str())
        .expect("raw QUIC FSB2 fixture");
    let raw = decode_hex(encoded);
    mutate_fsb2_payload(&raw, |payload| {
        payload["session_contract_hash_b64u"] =
            serde_json::json!(URL_SAFE_NO_PAD.encode(contract_hash));
    })
}

fn admission_request_vector_fixture(profile: RawQuicPathProfile) -> Vec<u8> {
    let hash: [u8; 32] = URL_SAFE_NO_PAD
        .decode("ioBJP5DPhg471caMR-huV5I9RlNKY2Pr9fs2GkP8CmA")
        .expect("vector contract hash")
        .try_into()
        .expect("vector contract hash length");
    admission_request_fixture_with_contract(profile, hash)
}

fn admission_success_fixture() -> Vec<u8> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../testdata/transport_v2/artifact_vectors.json"
    ))
    .expect("parse artifact vectors");
    decode_hex(
        fixture["fsa2"][0]["frame_hex"]
            .as_str()
            .expect("FSA2 success fixture"),
    )
}

fn mutate_fsb2_payload(raw: &[u8], mutate: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut payload: serde_json::Value =
        serde_json::from_slice(&raw[12..]).expect("parse canonical FSB2 payload");
    mutate(&mut payload);
    let payload = serde_json::to_vec(&payload).expect("encode canonical FSB2 payload");
    let mut output = raw[..12].to_vec();
    output[8..12].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    output.extend_from_slice(&payload);
    output
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(digits, 16).expect("valid hex")
        })
        .collect()
}

fn go_peer(mode: &str, address: Option<&str>, profile: RawQuicPathProfile) -> std::process::Output {
    go_peer_command(mode, address, profile)
        .output()
        .expect("run Go raw QUIC peer")
}

fn go_peer_command(mode: &str, address: Option<&str>, profile: RawQuicPathProfile) -> Command {
    let mut command = Command::new("go");
    command
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
        .env("GOWORK", isolated_go_work())
        .arg("run")
        .arg("./flowersec-go/internal/cmd/rust-raw-quic-peer")
        .arg(mode);
    if let Some(address) = address {
        command.arg(address);
    }
    command.arg(profile_name(profile));
    command
}

fn isolated_go_work() -> PathBuf {
    static GO_WORK: OnceLock<PathBuf> = OnceLock::new();
    GO_WORK
        .get_or_init(|| {
            let path = std::env::temp_dir().join(format!(
                "flowersec-rust-interop-{}.work",
                std::process::id()
            ));
            let go_module =
                fs::canonicalize(concat!(env!("CARGO_MANIFEST_DIR"), "/../flowersec-go"))
                    .expect("resolve Flowersec Go module");
            fs::write(&path, format!("go 1.26.5\n\nuse {}\n", go_module.display()))
                .expect("write isolated Go interop workspace");
            path
        })
        .clone()
}

fn profile_name(profile: RawQuicPathProfile) -> &'static str {
    match profile {
        RawQuicPathProfile::Direct => "direct",
        RawQuicPathProfile::Tunnel => "tunnel",
    }
}
