use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flowersec::controlplane::{
    AuthorizationRecord, DirectIssueOptions, EndpointSet, Issuer, RuntimeAuthorizationRequest,
    SessionOptions, TunnelIssueOptions, allow_tunnel_runtime, reject_tunnel_runtime,
    retry_tunnel_runtime,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn controlplane_public_issuance_and_opaque_record_contract() {
    let issuer = Issuer::new();
    let endpoints =
        EndpointSet::new(["wss://example.test/flowersec/v2/direct"]).expect("valid endpoint set");
    let issued = issuer
        .issue_direct(DirectIssueOptions {
            session: SessionOptions::new("controlplane-red"),
            endpoints: endpoints.clone(),
            rendezvous_group_id: "group-red".into(),
            listener_audience: "listener-red".into(),
            upstream_address: "127.0.0.1:23998".into(),
        })
        .expect("issue direct artifact");
    assert!(!issued.artifact_json().is_empty());
    let record = issued.authorization_record();
    let encoded = record.encode().expect("encode opaque record");
    let parsed = AuthorizationRecord::parse(&encoded).expect("parse opaque record");
    assert_eq!(parsed.lookup_key(), record.lookup_key());
    let request = issued
        .runtime_authorization_request("websocket", "127.0.0.1:12345")
        .expect("build runtime authorization request");
    let allowed = request
        .authorize(&record, "lease-red")
        .expect("authorize runtime");
    assert!(String::from_utf8(allowed.json()).unwrap().contains("allow"));
    assert!(flowersec::retry_runtime("temporarily_unavailable").is_ok());
    assert!(flowersec::reject_runtime("not_authorized").is_ok());
    assert_eq!(
        serde_json::from_slice::<Value>(&reject_tunnel_runtime("not_authorized").unwrap().json())
            .unwrap(),
        json!({"decision":"reject","reason":"not_authorized"})
    );
    assert_eq!(
        serde_json::from_slice::<Value>(
            &retry_tunnel_runtime("temporarily_unavailable")
                .unwrap()
                .json()
        )
        .unwrap(),
        json!({"decision":"retry","reason":"temporarily_unavailable"})
    );

    let pair = issuer
        .issue_tunnel_pair(TunnelIssueOptions {
            session: SessionOptions::new("controlplane-tunnel-red"),
            endpoints,
            rendezvous_group_id: "group-red".into(),
            listener_audience: "listener-red".into(),
            first_endpoint_id: "endpoint-a".into(),
            second_endpoint_id: "endpoint-b".into(),
            allow_replacement: true,
        })
        .expect("issue tunnel pair");
    assert_ne!(pair.first().lookup_key(), pair.second().lookup_key());

    let tunnel_request = pair
        .first()
        .runtime_authorization_request("websocket", "127.0.0.1:12346")
        .expect("build tunnel authorization request");
    assert!(
        tunnel_request
            .authorize(&pair.first().authorization_record(), "lease-wrong-boundary")
            .is_err()
    );
    let tunnel_response = tunnel_request
        .authorize_tunnel(&pair.first().authorization_record(), "lease-tunnel")
        .expect("authorize tunnel runtime");
    let tunnel_json = String::from_utf8(tunnel_response.json()).unwrap();
    assert!(!tunnel_json.contains("session"));
    assert!(!tunnel_json.contains("psk"));
    assert!(!tunnel_json.contains("suite"));
    assert!(!tunnel_json.contains("secret"));

    let first: Value = serde_json::from_slice(&pair.first().artifact_json()).unwrap();
    let second: Value = serde_json::from_slice(&pair.second().artifact_json()).unwrap();
    assert_eq!(first["session"], second["session"]);
    assert_ne!(first["path"]["token"], second["path"]["token"]);
}

#[test]
fn runtime_authorization_request_is_strict_and_redacted() {
    assert!(RuntimeAuthorizationRequest::parse(br#"{}"#).is_err());

    let issuer = Issuer::new();
    let issued = issuer
        .issue_direct(DirectIssueOptions {
            session: SessionOptions::new("strict-runtime-request"),
            endpoints: EndpointSet::new(["wss://example.test"]).unwrap(),
            rendezvous_group_id: "strict-group".into(),
            listener_audience: "strict-listener".into(),
            upstream_address: "127.0.0.1:23998".into(),
        })
        .unwrap();
    let valid = issued
        .runtime_authorization_request("websocket", "127.0.0.1:12345")
        .unwrap();
    assert_eq!(
        format!("{valid:?}"),
        "RuntimeAuthorizationRequest { <opaque> }"
    );
    assert_eq!(valid.carrier(), "websocket");
    assert_eq!(valid.remote_address(), "127.0.0.1:12345");

    let artifact: Value = serde_json::from_slice(&issued.artifact_json()).unwrap();
    let fsb2 = direct_fsb2(&artifact);
    let mismatched = serde_json::to_vec(&json!({
        "fsb2_base64url": URL_SAFE_NO_PAD.encode(fsb2),
        "carrier": "raw_quic",
        "remote_address": "127.0.0.1:12345",
    }))
    .unwrap();
    assert!(RuntimeAuthorizationRequest::parse(&mismatched).is_err());
}

fn direct_fsb2(artifact: &Value) -> Vec<u8> {
    let mut candidates = artifact["path"]["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|candidate| {
            json!({
                "carrier": candidate["carrier"],
                "id": candidate["id"],
                "normalized_url": candidate["url"],
                "wire_profile": candidate["wire_profile"],
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    let candidate_json = serde_json::to_vec(&candidates).unwrap();
    let mut preimage = b"flowersec-v2-candidates\0".to_vec();
    preimage.extend_from_slice(&(candidate_json.len() as u32).to_be_bytes());
    preimage.extend_from_slice(&candidate_json);
    let payload = serde_json::to_vec(&json!({
        "candidate_set_hash_b64u": URL_SAFE_NO_PAD.encode(Sha256::digest(preimage)),
        "candidates": candidates,
        "channel_id": artifact["session"]["channel_id"],
        "chosen_candidate_id": artifact["path"]["candidates"][0]["id"],
        "listener_audience": artifact["path"]["listener_audience"],
        "profile": artifact["profile"],
        "rendezvous_group_id": artifact["path"]["rendezvous_group_id"],
        "routing_token": artifact["path"]["routing_token"],
        "session_contract_hash_b64u": artifact["session"]["contract_hash_b64u"],
    }))
    .unwrap();
    let mut raw = b"FSB2".to_vec();
    raw.extend_from_slice(&[2, 1, 0, 0]);
    raw.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    raw.extend_from_slice(&payload);
    raw
}

#[test]
fn runtime_authorization_response_matches_runtime_contract() {
    let issuer = Issuer::new();
    let direct = issuer
        .issue_direct(DirectIssueOptions {
            session: SessionOptions::new("direct-response"),
            endpoints: EndpointSet::new(["wss://example.test"]).unwrap(),
            rendezvous_group_id: "direct-group".into(),
            listener_audience: "direct-listener".into(),
            upstream_address: "127.0.0.1:23998".into(),
        })
        .unwrap();
    let request = direct
        .runtime_authorization_request("websocket", "127.0.0.1:12345")
        .unwrap();
    let response: Value = serde_json::from_slice(
        &request
            .authorize(&direct.authorization_record(), "lease-direct")
            .unwrap()
            .json(),
    )
    .unwrap();
    assert_eq!(response["decision"], "allow");
    assert_eq!(response["direct"]["upstream"]["network"], "tcp");
    assert_eq!(response["direct"]["upstream"]["address"], "127.0.0.1:23998");
    assert_eq!(
        response["direct"]["session"]["channel_id"],
        "direct-response"
    );
    assert!(response["expires_at"].as_str().is_some());
    assert!(response.get("session").is_none() || response["session"].is_null());

    let pair = issuer
        .issue_tunnel_pair(TunnelIssueOptions {
            session: SessionOptions::new("tunnel-response"),
            endpoints: EndpointSet::new(["quic://example.test:443"]).unwrap(),
            rendezvous_group_id: "tunnel-group".into(),
            listener_audience: "tunnel-listener".into(),
            first_endpoint_id: "endpoint-a".into(),
            second_endpoint_id: "endpoint-b".into(),
            allow_replacement: true,
        })
        .unwrap();
    let first = pair.first();
    let request = first
        .runtime_authorization_request("raw_quic", "127.0.0.1:12345")
        .unwrap();
    assert!(
        request
            .authorize(&first.authorization_record(), "lease-tunnel")
            .is_err()
    );
    let response: Value = serde_json::from_slice(
        &request
            .authorize_tunnel(&first.authorization_record(), "lease-tunnel")
            .unwrap()
            .json(),
    )
    .unwrap();
    assert!(response.get("session").is_none());
    assert_eq!(response["expected_peer_endpoint_instance_id"], "endpoint-b");
    assert_eq!(response["allow_replacement"], true);
    assert!(response.get("direct").is_none() || response["direct"].is_null());
}

#[test]
fn external_tunnel_authorization_builds_a_secret_free_allow_response() {
    let pair = Issuer::new()
        .issue_tunnel_pair(TunnelIssueOptions {
            session: SessionOptions::new("external-authorization"),
            endpoints: EndpointSet::new(["wss://example.test/flowersec/v2/tunnel"]).unwrap(),
            rendezvous_group_id: "external-group".into(),
            listener_audience: "external-listener".into(),
            first_endpoint_id: "endpoint-a".into(),
            second_endpoint_id: "endpoint-b".into(),
            allow_replacement: true,
        })
        .unwrap();
    let request = pair
        .first()
        .runtime_authorization_request("websocket", "127.0.0.1:12345")
        .unwrap();
    let response = allow_tunnel_runtime(
        &request,
        "lease-external",
        std::time::SystemTime::now() + std::time::Duration::from_secs(60),
        "endpoint-b",
        true,
    )
    .unwrap();
    let json = response.json();
    let value: Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(value["decision"], "allow");
    assert_eq!(value["credential_id"], request.lookup_key());
    assert_eq!(value["expected_peer_endpoint_instance_id"], "endpoint-b");
    let lowercase = String::from_utf8(json).unwrap().to_ascii_lowercase();
    for forbidden in ["session", "artifact", "psk", "secret"] {
        assert!(!lowercase.contains(forbidden));
    }

    assert!(
        allow_tunnel_runtime(
            &request,
            "lease-external",
            std::time::SystemTime::now() - std::time::Duration::from_secs(1),
            "endpoint-b",
            false,
        )
        .is_err()
    );
}
