//! Generated application contracts, independently validated without live authority.
#[path = "support/v4_application.rs"]
mod application;
#[allow(dead_code)]
#[path = "support/v4_cbor.rs"]
mod cbor;
#[allow(dead_code)]
#[path = "support/v4_domains.rs"]
mod domains;
#[allow(dead_code)]
#[path = "support/v4_idna.rs"]
mod idna;
#[allow(dead_code)]
#[path = "support/v4_oracles.rs"]
mod oracles;
#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;
#[allow(dead_code)]
#[path = "support/v4_relations.rs"]
mod relations;
#[allow(dead_code)]
#[path = "support/v4_rules.rs"]
mod rules;
#[allow(dead_code)]
#[path = "support/v4_shape.rs"]
mod shape;
#[allow(dead_code)]
#[path = "support/v4_text.rs"]
mod text;
#[allow(dead_code)]
#[path = "support/v4_unicode.rs"]
mod unicode;
#[allow(dead_code)]
#[path = "support/v4_variants.rs"]
mod variants;

use application::{BusinessResult, SDKResult, application_registry};
use cbor::Value;
use domains::{Argument, Arguments};
use oracles::encoded;
use serde_json::Value as Json;
use shape::Context;
use std::{collections::BTreeSet, sync::OnceLock};
use text::Text;

fn r() -> &'static Text {
    static REFERENCE: OnceLock<Text> = OnceLock::new();
    REFERENCE.get_or_init(|| Text::new(registry::CBOR_REGISTRY_JSON))
}
fn corpus() -> &'static Json {
    static CORPUS: OnceLock<Json> = OnceLock::new();
    CORPUS.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../testdata/transport_v4/application_headers.json"
        ))
        .unwrap()
    })
}
fn maps() -> &'static Json {
    static MAPS: OnceLock<Json> = OnceLock::new();
    MAPS.get_or_init(|| {
        serde_json::from_str(include_str!("../../testdata/transport_v4/corpus.json")).unwrap()
    })
}
fn hex(text: &str) -> Vec<u8> {
    domains::hex(text).unwrap()
}
fn seed(id: &str) -> Vec<u8> {
    hex(maps()["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == id)
        .unwrap()["hex"]
        .as_str()
        .unwrap())
}
fn maximum(kind: &str) -> Vec<u8> {
    hex(corpus()["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["accept"] == true && v["kind"] == kind)
        .unwrap()["hex"]
        .as_str()
        .unwrap())
}
fn read<'a>(name: &str, raw: &'a [u8]) -> Value<'a> {
    r().wire_map(raw, name, &Context::default(), 8192).unwrap()
}
fn field<'v, 'a>(name: &str, value: &'v Value<'a>, key: &str) -> &'v Value<'a> {
    r().app_value(name, value, key).unwrap()
}
fn replace(name: &str, raw: &[u8], key: &str, value: Value<'_>) -> Vec<u8> {
    let id = r().shape.named_field(name, key).unwrap().0;
    let Value::Map(mut pairs) = read(name, raw) else {
        panic!("map fixture")
    };
    pairs.retain(|(key, _)| key != &Value::Unsigned(id));
    pairs.push((Value::Unsigned(id), value));
    pairs.sort_by_key(|(key, _)| {
        if let Value::Unsigned(n) = key {
            *n
        } else {
            panic!("key fixture")
        }
    });
    encoded(&Value::Map(pairs))
}
fn hset(raw: &[u8], key: &str, value: Value<'_>) -> Vec<u8> {
    replace("ApplicationHeader", raw, key, value)
}
fn hash(name: &str, key: &str, raw: &[u8]) -> Vec<u8> {
    r().app_hash(name, [(key.into(), Argument::Bytes(raw.to_vec()))].into())
        .unwrap()
}
fn pair(request: &str, response: &str, length: u64, limit: u64) -> (Vec<u8>, Vec<u8>) {
    let mut req = maximum(request);
    if r()
        .shape
        .named_value(
            "ApplicationHeader",
            &read("ApplicationHeader", &req),
            "response_limit_bytes",
        )
        .unwrap()
        .is_some()
    {
        req = hset(&req, "response_limit_bytes", Value::Unsigned(limit));
    }
    (
        req,
        hset(
            &maximum(response),
            "payload_length",
            Value::Unsigned(length),
        ),
    )
}
fn execution(kind: &str, payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let suffix = match kind {
        "execution_unary_request" | "resume_request" => "unary_execution",
        "execution_stream_request" => "stream_execution",
        "execution_notify" => "notify_execution",
        _ => panic!("kind fixture"),
    };
    let contract = seed(&format!("service_{suffix}"));
    let definition = read("ServiceContract", &contract);
    let mut header = maximum(kind);
    header = hset(
        &header,
        "type_id",
        field("ServiceContract", &definition, "type_id").clone(),
    );
    header = hset(
        &header,
        "response_limit_bytes",
        field("ServiceContract", &definition, "max_response_bytes").clone(),
    );
    header = hset(
        &header,
        "payload_length",
        Value::Unsigned(payload.len() as u64),
    );
    header = hset(
        &header,
        "service_contract_digest",
        Value::Bytes(&hash("service_contract_digest", "contract", &contract)),
    );
    header = hset(
        &header,
        "request_digest",
        Value::Bytes(
            &r().application_execution_digest(&header, &contract, payload)
                .unwrap(),
        ),
    );
    (header, contract)
}

// v4.rust_application.corpus
#[test]
fn complete_header_corpus() {
    assert_eq!(maps()["schema_sha256"], registry::SCHEMA_SHA256);
    assert_eq!(corpus()["schema_revision"], maps()["schema_revision"]);
    let vectors = corpus()["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 589);
    let (mut kinds, mut negative) = (BTreeSet::new(), 0);
    for v in vectors {
        let raw = hex(v["hex"].as_str().unwrap());
        if v["accept"] == true {
            let header = r().application_header(&raw).unwrap();
            kinds.insert(header.kind);
            assert_eq!(header.kind, v["kind"]);
            assert_eq!(encoded(&header.value), raw);
            assert_eq!(
                raw.len() as u64,
                application_registry().kinds[header.kind].max_encoded_bytes
            );
        } else {
            negative += 1;
            let error = r().application_header(&raw).unwrap_err();
            let expected = v["expected_error"].as_str().unwrap();
            if expected.starts_with("application_") {
                assert_eq!(error, expected);
            }
        }
    }
    assert_eq!(negative, 558);
    assert_eq!(
        kinds,
        application_registry()
            .kinds
            .keys()
            .map(String::as_str)
            .collect()
    );
    assert_eq!(
        r().application_header(&hset(
            &maximum("execution_notify"),
            "response_limit_bytes",
            Value::Unsigned(1)
        ))
        .unwrap_err(),
        "application_constant"
    );
}

// v4.rust_application.response_binding
#[test]
fn original_response_bindings() {
    for (kind, variant) in &application_registry().kinds {
        let Some(request_kind) = &variant.request else {
            continue;
        };
        let (request, response) = pair(request_kind, kind, 0, 0);
        r().application_response(&request, &response).unwrap();
        for key in [
            "operation_id",
            "type_id",
            "request_digest",
            "service_contract_digest",
            "control_serial",
        ] {
            let decoded = read("ApplicationHeader", &response);
            let Some(value) = r()
                .shape
                .named_value("ApplicationHeader", &decoded, key)
                .unwrap()
            else {
                continue;
            };
            let changed = match value {
                Value::Unsigned(n) => Value::Unsigned(n - 1),
                _ => Value::Bytes(&[7; 32]),
            };
            assert_eq!(
                r().application_response(&request, &hset(&response, key, changed))
                    .unwrap_err(),
                "application_response_binding"
            );
        }
        for key in ["deadline_at_ms", "admission_mode", "response_limit_bytes"] {
            for n in [0, 1] {
                assert_eq!(
                    r().application_response(&request, &hset(&response, key, Value::Unsigned(n)))
                        .unwrap_err(),
                    "application_fields"
                );
            }
        }
        for (other, v) in &application_registry().kinds {
            if v.request.is_none() && other != request_kind {
                assert_eq!(
                    r().application_response(&maximum(other), &response)
                        .unwrap_err(),
                    "application_response_kind"
                );
            }
        }
    }
}

// v4.rust_application.execution_digest
#[test]
fn complete_execution_and_limits() {
    let payload = [1, 2, 3];
    for kind in &application_registry().policy.execution_requests {
        let (header, contract) = execution(kind, &payload);
        r().verify_application_execution(&header, &contract, &payload)
            .unwrap();
        for (key, value) in [
            ("deadline_at_ms", Value::Unsigned(17)),
            ("admission_mode", Value::Unsigned(0)),
            ("operation_id", Value::Bytes(&[0; 32])),
        ] {
            assert_eq!(
                r().verify_application_execution(&hset(&header, key, value), &contract, &payload),
                Err("application_request_digest")
            );
        }
        assert_eq!(
            r().verify_application_execution(&header, &contract, &[1, 2, 4]),
            Err("application_request_digest")
        );
        assert_eq!(
            r().verify_application_execution(&header, &contract, &[]),
            Err("application_payload_length")
        );
        assert_eq!(
            r().application_execution_digest(
                &hset(&header, "type_id", Value::Unsigned(900)),
                &contract,
                &payload
            ),
            Err("application_contract_binding")
        );
        let changed = replace(
            "ServiceContract",
            &contract,
            "request_schema_revision",
            Value::Text("changed"),
        );
        assert_eq!(
            r().verify_application_execution(&header, &changed, &payload),
            Err("application_contract_binding")
        );
        let rebound = hset(
            &header,
            "service_contract_digest",
            Value::Bytes(&hash("service_contract_digest", "contract", &changed)),
        );
        assert_eq!(
            r().verify_application_execution(&rebound, &changed, &payload),
            Err("application_request_digest")
        );
    }
    let (header, contract) = execution("execution_unary_request", &payload);
    assert_eq!(
        r().application_execution_digest(
            &hset(
                &header,
                "message_kind",
                Value::Unsigned(application_registry().kinds["execution_stream_request"].code)
            ),
            &contract,
            &payload
        ),
        Err("application_contract_variant")
    );
    for kind in application_registry().kinds.keys() {
        if !application_registry()
            .policy
            .execution_requests
            .contains(kind)
        {
            assert_eq!(
                r().application_execution_digest(&maximum(kind), &contract, &payload),
                Err("application_execution_request")
            );
        }
    }
    let small = replace(
        "ServiceContract",
        &contract,
        "request_max_bytes",
        Value::Unsigned(2),
    );
    assert_eq!(
        r().application_execution_digest(
            &hset(
                &header,
                "service_contract_digest",
                Value::Bytes(&hash("service_contract_digest", "contract", &small))
            ),
            &small,
            &payload
        ),
        Err("application_request_limit")
    );
    let limited = replace(
        "ServiceContract",
        &replace(
            "ServiceContract",
            &contract,
            "max_response_bytes",
            Value::Unsigned(2),
        ),
        "min_response_limit_bytes",
        Value::Unsigned(1),
    );
    let rebound = hset(
        &header,
        "service_contract_digest",
        Value::Bytes(&hash("service_contract_digest", "contract", &limited)),
    );
    for n in [0, 3] {
        assert_eq!(
            r().application_execution_digest(
                &hset(&rebound, "response_limit_bytes", Value::Unsigned(n)),
                &limited,
                &payload
            ),
            Err("application_response_limit")
        );
    }
    for length in [0, 1048576] {
        let payload = vec![0; length];
        let (header, contract) = execution("execution_unary_request", &payload);
        r().verify_application_execution(&header, &contract, &payload)
            .unwrap();
    }
}

// v4.rust_application.sdk_stop
#[test]
fn sdk_stop_is_bounded_code_only() {
    for (kind, variant) in &application_registry().kinds {
        if !variant.sdk_error {
            continue;
        }
        for (label, code) in &application_registry().sdk_error_codes {
            let body = encoded(
                &r().shape
                    .named_map(
                        &application_registry().sdk_errors.payload_schema,
                        [("code", Some(Value::Unsigned(*code)))],
                    )
                    .unwrap(),
            );
            let (request, response) = pair(
                variant.request.as_deref().unwrap(),
                kind,
                body.len() as u64,
                0,
            );
            let stream = matches!(
                kind.as_str(),
                "execution_stream_sdk_error" | "transient_stream_sdk_error"
            );
            if stream
                && matches!(
                    label.as_str(),
                    "request_message_aborted" | "response_output_stopped"
                )
            {
                assert_eq!(
                    r().application_sdk_error(&request, &response, &body),
                    Err("streaming_sdk_error_code")
                );
                continue;
            }
            if !stream && label == "source_overflow" {
                assert_eq!(
                    r().application_sdk_error(&request, &response, &body),
                    Err("application_sdk_error_code")
                );
                continue;
            }
            assert_eq!(
                r().application_sdk_error(&request, &response, &body)
                    .unwrap(),
                SDKResult { code: label }
            );
            for n in [0, 1, 255, 256] {
                r().application_response(
                    &request,
                    &hset(&response, "payload_length", Value::Unsigned(n)),
                )
                .unwrap();
            }
            assert_eq!(
                r().application_response(
                    &request,
                    &hset(&response, "payload_length", Value::Unsigned(257))
                )
                .unwrap_err(),
                "application_sdk_error_limit"
            );
            assert_eq!(
                r().application_sdk_error(&request, &response, &[0; 257]),
                Err("application_input_size")
            );
            assert_eq!(
                r().application_sdk_error(&request, &response, &body[..body.len() - 1]),
                Err("application_payload_length")
            );
            for invalid in [
                "a10000",
                "a10019ffff",
                "a0",
                "a200010100",
                "a200010001",
                "a1180001",
                "a1000100",
                "a100",
            ] {
                let raw = hex(invalid);
                assert!(
                    r().application_sdk_error(
                        &request,
                        &hset(
                            &response,
                            "payload_length",
                            Value::Unsigned(raw.len() as u64)
                        ),
                        &raw
                    )
                    .is_err()
                );
            }
            if r()
                .shape
                .named_value(
                    "ApplicationHeader",
                    &read("ApplicationHeader", &request),
                    "response_limit_bytes",
                )
                .unwrap()
                .is_some()
            {
                for (other, v) in &application_registry().kinds {
                    if v.request == variant.request && !v.sdk_error {
                        let (req, res) = pair(variant.request.as_deref().unwrap(), other, 1, 0);
                        assert_eq!(
                            r().application_response(&req, &res).unwrap_err(),
                            "application_response_limit"
                        );
                    }
                }
            }
        }
    }
    let (request, response) = pair("transient_unary_request", "transient_unary_response", 0, 0);
    assert_eq!(
        r().application_sdk_error(&request, &response, &[]),
        Err("application_sdk_error_kind")
    );
}

// v4.rust_application.business_errors
#[test]
fn exact_business_schema_catalog_and_limits() {
    let schema = hex("a10001");
    let digest = hash("business_error_schema_digest", "error_schema", &schema);
    let definition = encoded(
        &r().shape
            .named_map(
                "ErrorDefinition",
                [
                    ("code", Some(Value::Unsigned(12345))),
                    ("schema_revision", Some(Value::Text("error-1"))),
                    ("max_payload_bytes", Some(Value::Unsigned(2))),
                    ("schema_digest", Some(Value::Bytes(&digest))),
                ],
            )
            .unwrap(),
    );
    r().match_application_error_schema(&definition, &schema)
        .unwrap();
    assert_eq!(
        r().match_application_error_schema(&definition, &hex("a0")),
        Err("application_error_schema_mismatch")
    );
    assert_eq!(
        r().match_application_error_schema(&definition, &[0; 8193]),
        Err("application_input_size")
    );
    for semantics in ["execution", "transient"] {
        for shape in ["unary", "stream"] {
            let contract = replace(
                "ServiceContract",
                &seed(&format!("service_{shape}_{semantics}")),
                "application_error_catalog",
                Value::Array(vec![read("ErrorDefinition", &definition)]),
            );
            r().match_application_error_catalog(&contract, std::slice::from_ref(&definition))
                .unwrap();
            assert_eq!(
                r().match_application_error_catalog(&contract, &[]),
                Err("application_error_catalog_mismatch")
            );
            assert_eq!(
                r().match_application_error_catalog(&contract, &vec![definition.clone(); 65]),
                Err("application_error_catalog_size")
            );
            for (key, value) in [
                ("code", Value::Unsigned(12346)),
                ("schema_revision", Value::Text("error-2")),
                ("max_payload_bytes", Value::Unsigned(3)),
                ("schema_digest", Value::Bytes(&[0; 32])),
            ] {
                assert_eq!(
                    r().match_application_error_catalog(
                        &contract,
                        &[replace("ErrorDefinition", &definition, key, value)]
                    ),
                    Err("application_error_catalog_mismatch")
                );
            }
            let (mut request, mut response) = pair(
                &format!("{semantics}_{shape}_request"),
                &format!("{semantics}_{shape}_application_error"),
                2,
                4,
            );
            for side in [&mut request, &mut response] {
                *side = hset(
                    side,
                    "service_contract_digest",
                    Value::Bytes(&hash("service_contract_digest", "contract", &contract)),
                );
                *side = hset(
                    side,
                    "type_id",
                    field(
                        "ServiceContract",
                        &read("ServiceContract", &contract),
                        "type_id",
                    )
                    .clone(),
                );
            }
            let classify = |request: &[u8], length: usize, code: u64| {
                r().application_business_error(
                    request,
                    &hset(
                        &hset(&response, "payload_length", Value::Unsigned(length as u64)),
                        "application_error_code",
                        Value::Unsigned(code),
                    ),
                    &contract,
                    &vec![0; length],
                )
            };
            for (length, code, classification) in [
                (2, 12345, "known_application_error"),
                (3, 12345, "application_result_decode_failed"),
                (3, 0xffffffff, "unknown_application_error"),
            ] {
                assert_eq!(
                    classify(&request, length, code).unwrap(),
                    BusinessResult {
                        classification,
                        code
                    }
                );
            }
            let valid = hset(&response, "application_error_code", Value::Unsigned(12345));
            assert_eq!(
                r().application_business_error(&request, &valid, &contract, &[0]),
                Err("application_payload_length")
            );
            assert_eq!(
                r().application_business_error(&request, &valid, &contract, &[0; 3]),
                Err("application_input_size")
            );
            assert_eq!(
                classify(&request, 5, 12345),
                Err("application_response_limit")
            );
            let zero = hset(&request, "response_limit_bytes", Value::Unsigned(0));
            classify(&zero, 0, 12345).unwrap();
            assert_eq!(classify(&zero, 1, 12345), Err("application_response_limit"));
        }
    }
}

// v4.rust_application.ownership
#[test]
fn input_caps_and_owned_results() {
    let payload = [1, 2, 3];
    let (header, contract) = execution("execution_unary_request", &payload);
    let mut result = r()
        .application_execution_digest(&header, &contract, &payload)
        .unwrap();
    let before = header.clone();
    result.fill(0);
    assert_eq!(header, before);
    assert_eq!(
        r().application_header(&[0; 513]).unwrap_err(),
        "application_input_size"
    );
    assert_eq!(
        r().application_execution_digest(&header, &[0; 8193], &payload),
        Err("application_input_size")
    );
    assert_eq!(
        r().application_execution_digest(&header, &contract, &vec![0; 1048577]),
        Err("application_input_size")
    );
    let args: Arguments = [("contract".into(), Argument::Bytes(contract.clone()))].into();
    let output = r().app_hash("service_contract_digest", args).unwrap();
    let mut changed = contract.clone();
    changed.fill(0);
    assert_eq!(
        output,
        hash("service_contract_digest", "contract", &contract)
    );
}

// v4.rust_application.properties
#[test]
fn header_mutations_are_deterministic() {
    let positives: Vec<_> = corpus()["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["accept"] == true)
        .collect();
    let mut state = 0x235ba919u32;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state
    };
    for _ in 0..4096 {
        let mut raw = hex(positives[next() as usize % positives.len()]["hex"]
            .as_str()
            .unwrap());
        let index = next() as usize % raw.len();
        raw[index] ^= 1 << (next() % 8);
        let before = raw.clone();
        let attempt = || {
            r().application_header(&raw).map(|header| {
                assert_eq!(encoded(&header.value), raw);
                header.kind
            })
        };
        assert_eq!(attempt(), attempt());
        assert_eq!(raw, before);
    }
}
