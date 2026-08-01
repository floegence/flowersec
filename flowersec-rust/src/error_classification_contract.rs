use std::{collections::HashMap, fs, path::PathBuf};

use serde::Deserialize;

use crate::{
    ConnectErrorCode, ErrorRetryClassification, SessionError, classify_connect_error,
    classify_session_error,
};

#[derive(Deserialize)]
struct Contract {
    decisions: HashMap<String, Decision>,
    connect: Vec<Case>,
    session: Vec<Case>,
}

#[derive(Deserialize)]
struct Decision {
    action: String,
    retryable: bool,
    refresh_artifact: bool,
    caller_canceled: bool,
    session_closed: bool,
}

#[derive(Deserialize)]
struct Case {
    decision: String,
    codes: HashMap<String, Vec<String>>,
}

#[test]
fn classifications_match_shared_contract() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("stability")
        .join("public_error_classification.json");
    let contract: Contract = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    for case in contract.connect {
        let expected = &contract.decisions[&case.decision];
        for code in &case.codes["rust"] {
            assert_decision(classify_connect_error(parse_connect(code)), expected);
        }
    }
    for case in contract.session {
        let expected = &contract.decisions[&case.decision];
        for code in &case.codes["rust"] {
            assert_decision(classify_session_error(parse_session(code)), expected);
        }
    }
}

fn assert_decision(actual: ErrorRetryClassification, expected: &Decision) {
    assert_eq!(actual.action.as_str(), expected.action);
    assert_eq!(actual.retryable, expected.retryable);
    assert_eq!(actual.refresh_artifact, expected.refresh_artifact);
    assert_eq!(actual.caller_canceled, expected.caller_canceled);
    assert_eq!(actual.session_closed, expected.session_closed);
}

fn parse_connect(code: &str) -> ConnectErrorCode {
    match code {
        "invalid_input" => ConnectErrorCode::InvalidInput,
        "expired" => ConnectErrorCode::Expired,
        "resolve_failed" => ConnectErrorCode::ResolveFailed,
        "spend_failed" => ConnectErrorCode::SpendFailed,
        "dial_failed" => ConnectErrorCode::DialFailed,
        "timeout" => ConnectErrorCode::Timeout,
        "canceled" => ConnectErrorCode::Canceled,
        "handshake_failed" => ConnectErrorCode::HandshakeFailed,
        _ => panic!("unknown connect code {code}"),
    }
}

fn parse_session(code: &str) -> SessionError {
    match code {
        "canceled" => SessionError::Canceled,
        "closed" => SessionError::Closed,
        "going_away" => SessionError::GoingAway,
        "invalid_input" => SessionError::InvalidInput,
        "rejected" => SessionError::Rejected,
        "stream_rejected" => SessionError::StreamRejected,
        "resource_exhausted" => SessionError::ResourceExhausted,
        "reset" => SessionError::Reset,
        "stream_reset" => SessionError::StreamReset,
        "timed_out" => SessionError::TimedOut,
        "rekey_failed" => SessionError::RekeyFailed,
        "liveness_failed" => SessionError::LivenessFailed,
        "failed" => SessionError::Failed,
        _ => panic!("unknown session code {code}"),
    }
}
