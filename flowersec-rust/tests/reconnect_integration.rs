use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flowersec::{
    ConnectArtifact, CorrelationContext,
    client::ConnectOptions,
    e2ee::{Secret32, ServerHandshakeOptions, Suite},
    endpoint::{DirectAcceptOptions, accept_direct},
    generated::flowersec::direct::v1::{DirectConnectInfo, Suite as DirectSuite},
    observability::DiagnosticEvent,
    reconnect::{
        ArtifactSource, ArtifactSourceError, ConnectionStatus, ReconnectConfig, ReconnectError,
        ReconnectManager, ReconnectSettings,
    },
    streamhello,
    transport::TungsteniteTransport,
    transport_security::TransportSecurityPolicy,
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::mpsc};

#[tokio::test]
async fn reconnect_manager_recovers_after_session_termination() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("local address");
    let psk = [0x61_u8; 32];
    let expires = unix_now() + 60;
    let (accepted_tx, mut accepted_rx) = mpsc::unbounded_channel();
    let server_task = tokio::spawn(async move {
        for connection in 0..2 {
            let (tcp, _) = listener.accept().await.expect("accept TCP");
            let websocket = tokio_tungstenite::accept_async(tcp)
                .await
                .expect("accept WebSocket");
            let mut handshake = ServerHandshakeOptions::new(
                Secret32::new(psk),
                Suite::X25519HkdfSha256Aes256Gcm,
                expires,
            );
            handshake.channel_id = Some("rust-reconnect".to_owned());
            let session = accept_direct(
                Arc::new(TungsteniteTransport::new(websocket)),
                DirectAcceptOptions::new(handshake),
            )
            .await
            .expect("accept direct session");
            let (kind, _rpc_stream) = session.accept_stream().await.expect("accept RPC stream");
            assert_eq!(kind, streamhello::RPC_KIND);
            accepted_tx
                .send(connection)
                .expect("report accepted RPC stream");
            if connection == 0 {
                tokio::time::sleep(Duration::from_millis(25)).await;
                session.close().await.expect("terminate first session");
            } else {
                session.terminated().await;
            }
        }
    });

    let acquisitions = Arc::new(AtomicUsize::new(0));
    let source = ArtifactSource::refreshable({
        let acquisitions = acquisitions.clone();
        move |_| {
            acquisitions.fetch_add(1, Ordering::SeqCst);
            let artifact = artifact(address, psk, expires, Some("trace-reconnect"));
            async move { Ok(artifact) }
        }
    });
    let events = Arc::new(Mutex::new(Vec::<DiagnosticEvent>::new()));
    let config = ReconnectConfig {
        source,
        connect: ConnectOptions {
            transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
            observer: Some(Arc::new({
                let events = events.clone();
                move |event: &DiagnosticEvent| events.lock().unwrap().push(event.clone())
            })),
            trace_id: Some("trace-reconnect".to_owned()),
            ..ConnectOptions::default()
        },
        reconnect: retry_settings(3),
    };
    let manager = ReconnectManager::new();
    let states = manager.subscribe();
    manager
        .connect(config.clone())
        .await
        .expect("initial connect");
    wait_for_reconnected(&manager, &acquisitions).await;
    assert_eq!(manager.state().status, ConnectionStatus::Connected);

    let before = acquisitions.load(Ordering::SeqCst);
    manager
        .connect_if_needed(config)
        .await
        .expect("connected manager is idempotent");
    assert_eq!(acquisitions.load(Ordering::SeqCst), before);
    assert!(states.has_changed().expect("state receiver remains active"));
    for expected in 0..2 {
        let accepted = tokio::time::timeout(Duration::from_secs(3), accepted_rx.recv())
            .await
            .expect("server accepts reconnected RPC stream")
            .expect("server acceptance channel remains open");
        assert_eq!(accepted, expected);
    }

    manager.disconnect().await;
    assert_eq!(manager.state().status, ConnectionStatus::Disconnected);
    server_task.await.expect("server task");

    let events = events.lock().unwrap();
    assert!(events.iter().any(|event| event.code == "reconnect_attempt"));
    assert!(
        events
            .iter()
            .any(|event| event.code == "reconnect_connected")
    );
    assert!(
        events
            .iter()
            .all(|event| event.trace_id.as_deref() == Some("trace-reconnect"))
    );
    assert!(events.iter().all(|event| event.attempt_seq >= 1));
}

#[tokio::test]
async fn reconnect_manager_retries_artifact_acquisition_then_connects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("local address");
    let psk = [0x62_u8; 32];
    let expires = unix_now() + 60;
    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept TCP");
        let websocket = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("accept WebSocket");
        let mut handshake = ServerHandshakeOptions::new(
            Secret32::new(psk),
            Suite::X25519HkdfSha256Aes256Gcm,
            expires,
        );
        handshake.channel_id = Some("rust-reconnect".to_owned());
        let session = accept_direct(
            Arc::new(TungsteniteTransport::new(websocket)),
            DirectAcceptOptions::new(handshake),
        )
        .await
        .expect("accept direct session");
        session.terminated().await;
    });

    let attempts = Arc::new(AtomicUsize::new(0));
    let source = ArtifactSource::refreshable({
        let attempts = attempts.clone();
        move |_| {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            let artifact = artifact(address, psk, expires, None);
            async move {
                if attempt == 0 {
                    Err(ArtifactSourceError::Acquire("temporary outage".to_owned()))
                } else {
                    Ok(artifact)
                }
            }
        }
    });
    let manager = ReconnectManager::default();
    manager
        .connect(ReconnectConfig {
            source,
            connect: plaintext_options(),
            reconnect: retry_settings(2),
        })
        .await
        .expect("second artifact acquisition connects");
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(manager.state().status, ConnectionStatus::Connected);
    manager.disconnect().await;
    server_task.await.expect("server task");
}

#[tokio::test]
async fn reconnect_manager_rejects_non_refreshable_and_invalid_configuration() {
    let manager = ReconnectManager::new();
    let once = artifact(
        "127.0.0.1:9".parse().unwrap(),
        [0x63_u8; 32],
        unix_now() + 60,
        None,
    );
    let error = manager
        .connect(ReconnectConfig {
            source: ArtifactSource::once(once),
            connect: plaintext_options(),
            reconnect: retry_settings(2),
        })
        .await
        .expect_err("automatic reconnect requires refreshable source");
    assert_eq!(error, ReconnectError::RefreshableSourceRequired);
    assert_eq!(manager.state().status, ConnectionStatus::Error);

    let invalid = manager
        .connect(ReconnectConfig {
            source: ArtifactSource::refreshable(|_| async {
                Err(ArtifactSourceError::Acquire("unused".to_owned()))
            }),
            connect: plaintext_options(),
            reconnect: ReconnectSettings {
                factor: 0.5,
                ..retry_settings(2)
            },
        })
        .await
        .expect_err("invalid backoff factor");
    assert_eq!(invalid, ReconnectError::InvalidConfig);
}

#[tokio::test]
async fn reconnect_manager_reports_exhaustion_and_cancellation() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let manager = ReconnectManager::new();
    let exhausted = manager
        .connect(ReconnectConfig {
            source: ArtifactSource::refreshable({
                let attempts = attempts.clone();
                move |_| {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    async { Err(ArtifactSourceError::Acquire("offline".to_owned())) }
                }
            }),
            connect: plaintext_options(),
            reconnect: retry_settings(2),
        })
        .await
        .expect_err("retry budget is exhausted");
    assert!(matches!(
        exhausted,
        ReconnectError::Exhausted { attempts: 2, .. }
    ));
    assert_eq!(attempts.load(Ordering::SeqCst), 2);

    let manager = Arc::new(ReconnectManager::new());
    let config = ReconnectConfig {
        source: ArtifactSource::refreshable(|context| async move {
            context.cancellation.cancelled().await;
            Err(ArtifactSourceError::Canceled)
        }),
        connect: plaintext_options(),
        reconnect: retry_settings(2),
    };
    let connecting = {
        let manager = manager.clone();
        let config = config.clone();
        tokio::spawn(async move { manager.connect(config).await })
    };
    wait_for_status(&manager, ConnectionStatus::Connecting).await;
    let waiting = {
        let manager = manager.clone();
        tokio::spawn(async move { manager.connect_if_needed(config).await })
    };
    manager.disconnect().await;
    assert!(matches!(
        connecting.await.expect("connect task"),
        Err(ReconnectError::Artifact(ArtifactSourceError::Canceled))
            | Err(ReconnectError::Canceled)
    ));
    assert!(matches!(
        waiting.await.expect("waiting task"),
        Err(ReconnectError::Artifact(ArtifactSourceError::Canceled))
            | Err(ReconnectError::Canceled)
    ));
    assert_eq!(manager.state().status, ConnectionStatus::Disconnected);
}

async fn wait_for_reconnected(manager: &ReconnectManager, acquisitions: &AtomicUsize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if acquisitions.load(Ordering::SeqCst) >= 2
                && manager.state().status == ConnectionStatus::Connected
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("manager reconnects");
}

async fn wait_for_status(manager: &ReconnectManager, expected: ConnectionStatus) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if manager.state().status == expected {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("manager reaches expected state");
}

fn artifact(
    address: std::net::SocketAddr,
    psk: [u8; 32],
    expires: i64,
    trace_id: Option<&str>,
) -> ConnectArtifact {
    ConnectArtifact::Direct {
        info: DirectConnectInfo {
            ws_url: format!("ws://{address}/flowersec"),
            channel_id: "rust-reconnect".to_owned(),
            e2ee_psk_b64u: URL_SAFE_NO_PAD.encode(psk),
            channel_init_expire_at_unix_s: expires,
            default_suite: DirectSuite::X25519HkdfSha256Aes256Gcm,
        },
        scoped: Vec::new(),
        correlation: trace_id.map(|trace_id| CorrelationContext {
            v: 1,
            trace_id: Some(trace_id.to_owned()),
            session_id: None,
            tags: Vec::new(),
        }),
    }
}

fn plaintext_options() -> ConnectOptions {
    ConnectOptions {
        transport_security_policy: TransportSecurityPolicy::allow_plaintext_for_loopback(),
        ..ConnectOptions::default()
    }
}

fn retry_settings(max_attempts: usize) -> ReconnectSettings {
    ReconnectSettings {
        enabled: true,
        max_attempts,
        initial_delay: Duration::from_millis(5),
        max_delay: Duration::from_millis(5),
        factor: 1.0,
        jitter_ratio: 0.0,
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs() as i64
}
