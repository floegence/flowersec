use flowersec::{
    ArtifactLease, ArtifactSource, ArtifactSourceError, ConnectionController,
    ConnectionControllerOptions, ConnectorOptions, RetryDisposition, RetryPolicy, RpcPeer,
    RpcPeerExt, SessionError, SessionTermination, StreamMetadata, StreamMetadataError, connect,
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};

#[derive(Serialize)]
struct TypedRequest {
    value: String,
}

#[derive(Deserialize)]
struct TypedResponse {
    accepted: bool,
}

async fn compile_public_api(lease: &mut ArtifactLease, peer: &dyn RpcPeer) {
    let options = ConnectorOptions::new(vec![vec![1]]).expect("explicit trust roots");
    let _ = connect(lease, options).await;
    let response = peer
        .call_typed::<TypedRequest, TypedResponse>(
            7,
            &TypedRequest {
                value: "request".into(),
            },
        )
        .await;
    if let Ok(response) = response {
        let _ = response.accepted;
    }
}

#[test]
fn exposes_explicit_options_and_typed_rpc() {
    let _ = compile_public_api;
}

#[test]
fn connection_controller_requires_a_refreshable_artifact_source() {
    fn compile_controller(source: Arc<dyn ArtifactSource>) -> ConnectionController {
        let connector = ConnectorOptions::new(vec![vec![1]]).expect("explicit trust roots");
        let retry = RetryPolicy::new(Duration::from_millis(1), 2, Duration::from_secs(1))
            .expect("retry policy");
        ConnectionController::new(
            source,
            ConnectionControllerOptions::new(connector).with_retry_policy(retry),
        )
    }
    let _ = compile_controller;
}

#[test]
fn artifact_source_failures_require_structured_dispositions() {
    assert_eq!(
        ArtifactSourceError::terminal().disposition(),
        RetryDisposition::Terminal
    );
    assert_eq!(
        ArtifactSourceError::retryable().disposition(),
        RetryDisposition::Retryable
    );
}

#[test]
fn public_error_codes_expose_direct_stable_strings() {
    let connect_error = ConnectorOptions::new(vec![]).expect_err("empty trust roots are invalid");
    assert_eq!(connect_error.as_str(), "invalid_input");
    assert_eq!(SessionError::Timeout.as_str(), "timeout");
    assert_eq!(SessionError::GoingAway.as_str(), "going_away");
    assert_eq!(SessionError::StreamRejected.as_str(), "stream_rejected");
}

#[test]
fn stream_metadata_is_validated_before_opening_a_stream() {
    let metadata = StreamMetadata::try_from(serde_json::json!({"purpose": "health", "attempt": 1}))
        .expect("valid metadata");
    assert_eq!(metadata.values()["purpose"], "health");
    assert!(matches!(
        StreamMetadata::try_from(serde_json::json!({"fraction": 1.5})),
        Err(StreamMetadataError::InvalidValue)
    ));
    assert!(StreamMetadata::empty().values().is_empty());
}

#[test]
fn artifact_lease_does_not_expose_spend_state() {
    let source = include_str!("../src/artifact_v2.rs");
    assert!(!source.contains("pub fn is_committed"));
}

#[test]
fn session_termination_is_a_stable_value() {
    let termination = SessionTermination {
        error: SessionError::Closed,
    };
    assert_eq!(termination.error, SessionError::Closed);
}

#[test]
fn session_error_names_cover_portable_session_states() {
    assert_eq!(SessionError::GoingAway.as_str(), "going_away");
    assert_eq!(SessionError::StreamRejected.as_str(), "stream_rejected");
    assert_eq!(SessionError::StreamReset.as_str(), "stream_reset");
    assert_eq!(SessionError::RekeyFailed.as_str(), "rekey_failed");
    assert_eq!(SessionError::LivenessFailed.as_str(), "liveness_failed");
}
