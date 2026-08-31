use std::{collections::BTreeSet, sync::Arc};

use flowersec::{NotificationSubscription, RpcPeer, SessionError};
use serde::Deserialize;

#[derive(Deserialize)]
struct NotificationFixture {
    version: u32,
    type_id: u32,
    payloads: Vec<PayloadVector>,
    subscription_scenarios: Vec<String>,
}

#[derive(Deserialize)]
struct PayloadVector {
    id: String,
    json: String,
    decoder: String,
    expected_value: Option<String>,
    outcome: String,
}

#[derive(Deserialize)]
struct StatePayload {
    state: String,
}

fn compile_notification_contract(peer: &dyn RpcPeer) -> Result<(), SessionError> {
    let subscription = peer.subscribe_notification(7, Arc::new(|_payload| {}))?;
    subscription.cancel();
    Ok(())
}

#[test]
fn notification_subscription_public_shape_is_stable() {
    let _ = compile_notification_contract;
    let _ = std::mem::size_of::<NotificationSubscription>();
}

#[test]
fn shared_notification_vectors_match_rust_decoding_and_lifecycle_contract() {
    let fixture: NotificationFixture = serde_json::from_str(include_str!(
        "../../testdata/transport_v3/rpc_notification_vectors.json"
    ))
    .expect("shared notification fixture");
    assert_eq!(fixture.version, 1);
    assert_eq!(fixture.type_id, 8_101);

    for vector in fixture.payloads {
        let payload: serde_json::Value = serde_json::from_str(&vector.json).expect(&vector.id);
        let decoded = match vector.decoder.as_str() {
            "state_object" => {
                serde_json::from_value::<StatePayload>(payload).map(|value| value.state)
            }
            "string_array" => {
                serde_json::from_value::<Vec<String>>(payload).map(|value| value.join("|"))
            }
            "string" => serde_json::from_value::<String>(payload),
            decoder => panic!("unknown shared decoder {decoder}"),
        };
        match vector.outcome.as_str() {
            "success" => {
                let decoded = decoded.expect(&vector.id);
                if let Some(expected) = vector.expected_value {
                    assert_eq!(decoded, expected, "{}", vector.id);
                }
            }
            "decode_failure" => assert!(decoded.is_err(), "{}", vector.id),
            outcome => panic!("unknown shared outcome {outcome}"),
        }
    }

    let declared = fixture
        .subscription_scenarios
        .into_iter()
        .collect::<BTreeSet<_>>();
    let required = [
        "cancel_is_idempotent",
        "duplicate_subscriptions_receive_independently",
        "handler_failure_is_isolated",
        "session_close_terminates_subscriptions",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    assert_eq!(declared, required);
}
