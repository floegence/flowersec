//! Native generated result contracts, without runtime or terminal authority.
#[allow(dead_code)]
#[rustfmt::skip]
#[path = "../src/api_results_v4_generated.rs"]
mod api;

use api::{V4TopUpErrorCode as Code, V4TopUpErrorScope as Scope, V4TopUpWriteAction as Action};
use serde_json::Value;

fn code(value: &str) -> Code {
    match value {
        "source_exhausted" => Code::SourceExhausted,
        "source_unavailable" => Code::SourceUnavailable,
        "source_contract_invalid" => Code::SourceContractInvalid,
        "source_state_unknown" => Code::SourceStateUnknown,
        "operation_conflict" => Code::OperationConflict,
        "stale_generation" => Code::StaleGeneration,
        "future_generation" => Code::FutureGeneration,
        "stale_operation" => Code::StaleOperation,
        "future_operation" => Code::FutureOperation,
        "sequence_gap" => Code::SequenceGap,
        "configuration_capacity" => Code::ConfigurationCapacity,
        "capacity_exhausted" => Code::CapacityExhausted,
        "relink_required" => Code::RelinkRequired,
        "spent_unknown" => Code::SpentUnknown,
        "top_up_request_expired" => Code::TopUpRequestExpired,
        "source_reset_required" => Code::SourceResetRequired,
        "permission_denied" => Code::PermissionDenied,
        _ => panic!("unmapped native TopUp error code"),
    }
}

#[test]
fn top_up_errors_preserve_schema_scope_and_authorized_write_actions() {
    let schema: Value =
        serde_json::from_str(include_str!("../../stability/transport_v4_schema.json")).unwrap();
    let metadata = schema["top_up_error_metadata"].as_object().unwrap();
    assert_eq!(metadata.len(), 17);
    for (name, entry) in metadata {
        let scope = match entry["scope"].as_str().unwrap() {
            "source" => Scope::Source,
            "operation" => Scope::Operation,
            "request" => Scope::Request,
            _ => panic!("unknown scope"),
        };
        for (label, action) in [("none", Action::None), ("terminal", Action::Terminal)] {
            let expected = entry["write_actions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value.as_str() == Some(label));
            let result = api::top_up_error_projection(code(name), action.clone());
            assert_eq!(result.is_some(), expected, "{name}/{label}");
            if let Some(result) = result {
                assert!(result.code == code(name), "{name}/{label}");
                assert!(result.scope == scope, "{name}/{label}");
                assert!(result.write_action == action, "{name}/{label}");
            }
        }
    }
}

#[test]
fn uncertain_state_and_permission_errors_cannot_become_terminal_facts() {
    for code in [
        Code::SourceStateUnknown,
        Code::OperationConflict,
        Code::PermissionDenied,
    ] {
        assert!(api::top_up_error_projection(code, Action::Terminal).is_none());
    }
}
