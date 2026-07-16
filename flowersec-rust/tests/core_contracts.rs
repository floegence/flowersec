use flowersec::{
    ErrorCode, FlowersecError, Path, Stage,
    framing::{FramingError, read_chunk, read_json_frame, write_chunk, write_json_frame},
    observability::{DiagnosticCodeDomain, DiagnosticEvent, DiagnosticResult, Observer as _},
    transport_security::{
        NetworkPlaintextPolicyOptions, PlaintextRiskAcceptance, TransportRuntime,
        TransportSecurityPolicy,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncWriteExt as _, duplex};
use url::Url;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Message {
    value: String,
}

#[tokio::test]
async fn framing_round_trips_json_and_binary_chunks() {
    let (mut writer, mut reader) = duplex(256);
    let write = tokio::spawn(async move {
        write_json_frame(
            &mut writer,
            &Message {
                value: "flowersec".to_owned(),
            },
        )
        .await
        .expect("write JSON frame");
        write_chunk(&mut writer, b"binary")
            .await
            .expect("write chunk");
    });

    let message: Message = read_json_frame(&mut reader, 0)
        .await
        .expect("read JSON frame with default limit");
    assert_eq!(message.value, "flowersec");
    assert_eq!(
        read_chunk(&mut reader, 16).await.expect("read chunk"),
        b"binary"
    );
    write.await.expect("writer task");
}

#[tokio::test]
async fn framing_rejects_oversized_invalid_and_truncated_frames() {
    let (mut writer, mut reader) = duplex(64);
    writer.write_u32(5).await.expect("write length");
    writer.write_all(b"hello").await.expect("write payload");
    assert!(matches!(
        read_chunk(&mut reader, 4).await,
        Err(FramingError::TooLarge)
    ));

    let (mut writer, mut reader) = duplex(64);
    writer.write_u32(1).await.expect("write length");
    writer.write_all(b"{").await.expect("write invalid JSON");
    assert!(matches!(
        read_json_frame::<_, Message>(&mut reader, 16).await,
        Err(FramingError::InvalidJson(_))
    ));

    let (mut writer, mut reader) = duplex(64);
    writer.write_u32(8).await.expect("write length");
    writer
        .write_all(b"short")
        .await
        .expect("write partial payload");
    drop(writer);
    assert!(matches!(
        read_chunk(&mut reader, 8).await,
        Err(FramingError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof
    ));
}

#[test]
fn stable_error_contract_preserves_path_stage_code_and_source() {
    let code = ErrorCode::new("custom_code");
    assert_eq!(code.as_str(), "custom_code");
    assert_eq!(code.to_string(), "custom_code");
    assert_eq!(format!("{code:?}"), "ErrorCode(\"custom_code\")");
    assert_eq!(
        ErrorCode::from(ErrorCode::TIMEOUT),
        ErrorCode::new("timeout")
    );
    assert_eq!(serde_json::to_string(&Path::Tunnel).unwrap(), "\"tunnel\"");
    assert_eq!(
        serde_json::to_string(&Stage::Handshake).unwrap(),
        "\"handshake\""
    );

    let error = FlowersecError::new(
        Path::Direct,
        Stage::Validate,
        ErrorCode::INVALID_INPUT,
        "invalid request",
    )
    .with_source(io::Error::new(io::ErrorKind::InvalidInput, "details"));
    assert_eq!(error.path, Path::Direct);
    assert_eq!(error.stage, Stage::Validate);
    assert_eq!(error.code.as_str(), ErrorCode::INVALID_INPUT);
    assert_eq!(
        error.to_string(),
        "Direct/Validate/invalid_input: invalid request"
    );
    assert_eq!(
        std::error::Error::source(&error).map(ToString::to_string),
        Some("details".to_owned())
    );
}

#[tokio::test]
async fn transport_security_policies_enforce_tls_and_loopback_rules() {
    let secure = Url::parse("wss://service.example/ws").unwrap();
    let remote_plaintext = Url::parse("ws://service.example/ws").unwrap();
    let localhost = Url::parse("ws://localhost/ws").unwrap();
    let ipv4_loopback = Url::parse("ws://127.0.0.2/ws").unwrap();
    let ipv6_loopback = Url::parse("ws://[::1]/ws").unwrap();

    TransportSecurityPolicy::default()
        .evaluate(&secure, Path::Direct)
        .await
        .expect("TLS is accepted");
    let denied = TransportSecurityPolicy::require_tls()
        .evaluate(&remote_plaintext, Path::Tunnel)
        .await
        .expect_err("plaintext is denied by default");
    assert_eq!(denied.code.as_str(), ErrorCode::TRANSPORT_POLICY_DENIED);
    assert_eq!(denied.stage, Stage::Transport);

    let loopback = TransportSecurityPolicy::allow_plaintext_for_loopback();
    for url in [&secure, &localhost, &ipv4_loopback, &ipv6_loopback] {
        loopback
            .evaluate(url, Path::Direct)
            .await
            .expect("secure or loopback transport is accepted");
    }
    assert!(
        loopback
            .evaluate(&remote_plaintext, Path::Direct)
            .await
            .is_err()
    );
    #[allow(deprecated)]
    let allow_plaintext = TransportSecurityPolicy::allow_plaintext();
    allow_plaintext
        .evaluate(&remote_plaintext, Path::Direct)
        .await
        .expect("explicit plaintext policy is accepted");
    #[allow(deprecated)]
    let debug_plaintext = TransportSecurityPolicy::allow_plaintext();
    assert_eq!(
        format!("{debug_plaintext:?}"),
        "TransportSecurityPolicy(..)"
    );
}

#[tokio::test]
async fn network_plaintext_policy_allows_only_explicit_canonical_ip_hosts() {
    let policy = TransportSecurityPolicy::network_plaintext(NetworkPlaintextPolicyOptions {
        allowed_hosts: vec!["192.168.1.20".to_owned(), "2001:db8::20".to_owned()],
        risk_acceptance: PlaintextRiskAcceptance::AcceptPreE2ECredentialExposure,
    })
    .expect("network plaintext policy");
    for raw in [
        "wss://service.example/ws",
        "ws://192.168.1.20/ws",
        "ws://[2001:db8::20]/ws",
    ] {
        policy
            .evaluate(&Url::parse(raw).unwrap(), Path::Direct)
            .await
            .expect("allowed target");
    }
    for raw in ["ws://192.168.1.21/ws", "ws://127.0.0.1/ws"] {
        assert!(
            policy
                .evaluate(&Url::parse(raw).unwrap(), Path::Direct)
                .await
                .is_err()
        );
    }
}

#[test]
fn network_plaintext_policy_rejects_unsafe_options() {
    for host in [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "example.com",
        "192.168.001.20",
        "[2001:db8::20]",
        "fe80::1",
        "::ffff:c0a8:114",
    ] {
        assert!(
            TransportSecurityPolicy::network_plaintext(NetworkPlaintextPolicyOptions {
                allowed_hosts: vec![host.to_owned()],
                risk_acceptance: PlaintextRiskAcceptance::AcceptPreE2ECredentialExposure,
            })
            .is_err()
        );
    }
}

#[tokio::test]
async fn custom_transport_policy_receives_normalized_input() {
    let observed = Arc::new(Mutex::new(None));
    let policy = TransportSecurityPolicy::new({
        let observed = observed.clone();
        move |input| {
            observed.lock().unwrap().replace(input);
            async { Ok(()) }
        }
    });
    policy
        .evaluate(&Url::parse("WSS://LOCALHOST/socket").unwrap(), Path::Tunnel)
        .await
        .expect("custom policy");
    let input = observed.lock().unwrap().take().expect("observed input");
    assert_eq!(input.path, Path::Tunnel);
    assert_eq!(input.scheme, "wss");
    assert_eq!(input.host, "localhost");
    assert_eq!(input.runtime, TransportRuntime::Rust);
}

#[test]
fn closure_observer_receives_diagnostic_events() {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let observer = {
        let observed = observed.clone();
        move |event: &DiagnosticEvent| observed.lock().unwrap().push(event.clone())
    };
    let event = DiagnosticEvent {
        v: 1,
        namespace: "connect".to_owned(),
        path: Path::Auto,
        stage: Stage::Reconnect,
        code_domain: DiagnosticCodeDomain::Event,
        code: "reconnect_attempt".to_owned(),
        result: DiagnosticResult::Retry,
        elapsed_ms: 1.5,
        attempt_seq: 2,
        trace_id: Some("trace-core-contracts".to_owned()),
        session_id: None,
        resource: None,
        current: None,
        limit: None,
    };
    observer.on_diagnostic(&event);
    assert_eq!(observed.lock().unwrap().as_slice(), &[event]);
}
