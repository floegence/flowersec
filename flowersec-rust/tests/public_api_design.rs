use flowersec::{
    ArtifactLease, ConnectErrorCode, ConnectorOptions, ErrorRetryAction, RpcPeer, RpcPeerExt,
    SessionError, classify_connect_error, classify_session_error, connect,
};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

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
    let _ = connect(lease, options, CancellationToken::new()).await;
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
fn recovery_action_names_match_portable_contract() {
    assert_eq!(ErrorRetryAction::Retry.as_str(), "retry");
    assert_eq!(
        ErrorRetryAction::RefreshArtifact.as_str(),
        "refresh_artifact"
    );
    assert_eq!(ErrorRetryAction::Stop.as_str(), "stop");

    let closed = classify_session_error(SessionError::Closed);
    assert!(closed.refresh_artifact);
    assert!(closed.session_closed);
}

#[test]
fn public_error_codes_expose_direct_stable_strings() {
    let connection = classify_connect_error(ConnectErrorCode::Timeout);
    assert_eq!(connection.action, ErrorRetryAction::RefreshArtifact);

    let connect_error = ConnectorOptions::new(vec![]).expect_err("empty trust roots are invalid");
    assert_eq!(connect_error.as_str(), "invalid_input");
    assert_eq!(SessionError::TimedOut.as_str(), "timed_out");
    assert_eq!(SessionError::GoingAway.as_str(), "going_away");
    assert_eq!(SessionError::StreamRejected.as_str(), "stream_rejected");
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
