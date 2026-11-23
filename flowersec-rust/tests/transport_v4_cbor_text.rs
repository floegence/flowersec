//! Independent issuer conversion and exact signed host/Origin validation.
#[path = "support/v4_cbor.rs"]
mod cbor;
#[allow(dead_code)]
#[path = "support/v4_idna.rs"]
mod idna;
#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;
#[path = "support/v4_relations.rs"]
mod relations;
#[path = "support/v4_rules.rs"]
mod rules;
#[path = "support/v4_shape.rs"]
mod shape;
#[path = "support/v4_text.rs"]
mod text;
#[allow(dead_code)]
#[path = "support/v4_unicode.rs"]
mod unicode;
#[allow(dead_code)]
#[path = "support/v4_variants.rs"]
mod variants;

use cbor::Value;
use proptest::prelude::*;
use serde_json::Value as Json;
use shape::Context;
use std::{net::Ipv6Addr, sync::OnceLock};
use text::Text;

fn reference() -> &'static Text {
    static REFERENCE: OnceLock<Text> = OnceLock::new();
    REFERENCE.get_or_init(|| Text::new(registry::CBOR_REGISTRY_JSON))
}

fn corpus() -> &'static Vec<Json> {
    static CORPUS: OnceLock<Vec<Json>> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let json: Json =
            serde_json::from_str(include_str!("../../testdata/transport_v4/corpus.json")).unwrap();
        assert_eq!(json["schema_sha256"], registry::SCHEMA_SHA256);
        json["vectors"].as_array().unwrap().clone()
    })
}

fn context(vector: &Json) -> Context {
    let mut context = Context::default();
    if let Some(limits) = vector["limits"].as_object() {
        for (key, value) in limits {
            if let Some(n) = value.as_u64() {
                context.limits.insert(key.clone(), n);
            }
            if let Some(text) = value.as_str() {
                context.selectors.insert(key.clone(), text.into());
            }
        }
    }
    context
}

fn bytes(vector: &Json) -> Vec<u8> {
    let hex = vector["hex"].as_str().unwrap().as_bytes();
    assert!(hex.len().is_multiple_of(2));
    hex.as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn encode(value: &Value<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    value.encode(&mut out);
    out
}

// v4.rust_text.corpus
#[test]
fn shared_issuer_and_wire_text_corpus() {
    let r = reference();
    let corpus: Json =
        serde_json::from_str(include_str!("../../testdata/transport_v4/text.json")).unwrap();
    assert_eq!(corpus["schema_sha256"], registry::SCHEMA_SHA256);
    let vectors = corpus["vectors"].as_array().unwrap();
    for vector in vectors {
        let input = vector["input"].as_str().unwrap();
        let actual = match vector["operation"].as_str().unwrap() {
            "issuer_dns" => r.idna.issuer_dns(input),
            "wire_dns" => r.idna.wire_dns(input).map(|()| input.into()),
            "issuer_host" => r.issuer_host(input),
            "wire_host" => r.wire_host(input).map(|()| input.into()),
            "wire_origin" => r.wire_origin(input).map(|()| input.into()),
            _ => panic!("unknown text operation"),
        };
        if vector.get("expected_error").is_some() {
            assert!(actual.is_err(), "{} accepted", vector["id"]);
        } else {
            let output = actual.unwrap_or_else(|e| panic!("{}: {e}", vector["id"]));
            assert_eq!(output, vector["output"], "{}", vector["id"]);
            let hex: String = output
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(hex, vector["utf8_hex"]);
        }
    }
    assert_eq!(vectors.len(), 100);
}

// v4.rust_text.wire_maps
#[test]
fn shared_wire_map_corpus_except_external_composition() {
    let mut counts = [0, 0, 0];
    for vector in corpus() {
        let error = vector["expected_error"].as_str().unwrap_or("");
        if matches!(error, "pool_set_membership" | "open_digest_mismatch") {
            counts[2] += 1;
            continue;
        }
        let input = bytes(vector);
        let ctx = context(vector);
        let before = ctx.selectors.clone();
        let result = reference().wire_map(
            &input,
            vector["schema"].as_str().unwrap_or(""),
            &ctx,
            input.len() as u64 + 1,
        );
        assert_eq!(ctx.selectors, before);
        if error.is_empty() {
            counts[0] += 1;
            assert_eq!(
                encode(&result.unwrap_or_else(|e| panic!("{}: {e}", vector["id"]))),
                input
            );
        } else {
            counts[1] += 1;
            assert!(result.is_err(), "{} accepted ({error})", vector["id"]);
        }
        assert_eq!(input, bytes(vector));
    }
    assert_eq!(counts, [337, 826, 2]);
    println!(
        "{} positives, {} negatives, {} external-composition cases",
        counts[0], counts[1], counts[2]
    );
}

// v4.rust_text.address_boundaries
#[test]
fn canonical_addresses_and_registered_origin_ports() {
    let r = reference();
    for (input, canonical) in [
        ("2001:0DB8:0:0:1:0:0:1", "2001:db8::1:0:0:1"),
        ("0:0:0:0:0:0:0:0", "::"),
        ("::FFFF:192.0.2.1", "::ffff:c000:201"),
        ("0:0:0:0:0:0:0:1", "::1"),
    ] {
        assert_eq!(r.issuer_host(input).unwrap(), canonical);
        assert_eq!(
            input.parse::<Ipv6Addr>().unwrap(),
            canonical.parse::<Ipv6Addr>().unwrap()
        );
        r.wire_host(canonical).unwrap();
        assert!(r.wire_host(input).is_err());
    }
    for host in [
        "127.1",
        "127.00.0.1",
        "2130706433",
        "0x7f000001",
        "example.0x",
        "example.123",
        "::ffff:127.0.0.1%lo",
        "example.com.",
        "example.com/path",
        "example.com\u{a0}",
    ] {
        assert!(r.issuer_host(host).is_err(), "{host}");
    }
    r.wire_host("example.0xg").unwrap();
    for origin in [
        "https://example.com",
        "https://[::ffff:c000:201]",
        "http://127.0.0.1:3000",
    ] {
        r.wire_origin(origin).unwrap();
    }
    for origin in [
        "https://example.com:443",
        "http://127.0.0.1:80",
        "https://example.com:0443",
        "https://example.com:65536",
        "https://user@example.com",
        "https://example.com/",
        "https://example.com?x",
        "https://example.com#x",
        "https://EXAMPLE.COM",
        "https://[::ffff:192.0.2.1]",
        "https://example.com\n",
        "unregistered://example.com",
    ] {
        assert!(r.wire_origin(origin).is_err(), "{origin}");
    }
}

// v4.rust_text.properties
proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn ipv6_conversion_preserves_family_bits_and_wire_identity(segments in any::<[u16;8]>()) {
        let address = Ipv6Addr::from(segments);
        let canonical = reference().issuer_host(&address.to_string()).unwrap();
        prop_assert_eq!(canonical.parse::<Ipv6Addr>().unwrap(), address);
        prop_assert!(reference().wire_host(&canonical).is_ok());
        let origin = format!("https://[{canonical}]");
        prop_assert!(reference().wire_origin(&origin).is_ok());
    }
    #[test]
    fn issuer_host_result_is_an_exact_wire_host(input in prop::collection::vec(any::<char>(), 0..128)) {
        let input: String = input.iter().collect();
        if let Ok(host) = reference().issuer_host(&input) {
            prop_assert!(reference().wire_host(&host).is_ok());
            let origin = if host.contains(':') { format!("https://[{host}]") } else { format!("https://{host}") };
            prop_assert!(reference().wire_origin(&origin).is_ok());
        }
    }
    #[test]
    fn mutated_maps_reject_or_preserve_input(index in any::<usize>(), at in any::<usize>(), byte in any::<u8>()) {
        let vector = &corpus()[index % corpus().len()];
        let mut input = bytes(vector);
        if !input.is_empty() { let at = at % input.len(); input[at] ^= byte; }
        let ctx = context(vector);
        let before = ctx.selectors.clone();
        let result = reference().wire_map(&input, vector["schema"].as_str().unwrap_or(""), &ctx, input.len() as u64 + 1);
        prop_assert_eq!(ctx.selectors, before);
        if let Ok(value) = result { prop_assert_eq!(encode(&value), input); }
    }
}
