use flowersec::{
    ArtifactLease, ConnectorOptions, ErrorRetryAction, RpcPeer, RpcPeerExt, SessionError,
    SessionTermination, StreamMetadata, StreamMetadataError, classify_connect_error,
    classify_session_error, connect,
};
use serde::{Deserialize, Serialize};

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
fn recovery_classification_has_no_derived_boolean_state() {
    let source = include_str!("../src/error_classification.rs");
    assert!(!source.contains("pub retryable:"));
    assert!(!source.contains("pub refresh_artifact:"));
}

#[test]
fn recovery_action_names_match_portable_contract() {
    assert_eq!(ErrorRetryAction::Retry.as_str(), "retry");
    assert_eq!(
        ErrorRetryAction::RefreshArtifact.as_str(),
        "refresh_artifact"
    );
    assert_eq!(ErrorRetryAction::Stop.as_str(), "stop");

    let closed = classify_session_error(SessionError::Closed);
    assert_eq!(closed.action, ErrorRetryAction::RefreshArtifact);
    assert!(closed.session_closed);
}

#[test]
fn public_error_codes_expose_direct_stable_strings() {
    let connect_error = ConnectorOptions::new(vec![]).expect_err("empty trust roots are invalid");
    let connection = classify_connect_error(connect_error);
    assert_eq!(connection.action, ErrorRetryAction::Stop);
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
    assert_eq!(
        classify_session_error(SessionError::GoingAway).action,
        ErrorRetryAction::RefreshArtifact
    );
    assert_eq!(
        classify_session_error(SessionError::StreamRejected).action,
        ErrorRetryAction::Stop
    );
    assert_eq!(
        classify_session_error(SessionError::StreamReset).action,
        ErrorRetryAction::Retry
    );
    assert_eq!(
        classify_session_error(SessionError::RekeyFailed).action,
        ErrorRetryAction::Retry
    );
    assert_eq!(
        classify_session_error(SessionError::LivenessFailed).action,
        ErrorRetryAction::Retry
    );
}
