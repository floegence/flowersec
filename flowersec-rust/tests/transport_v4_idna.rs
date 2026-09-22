//! Pinned Unicode 15.1 IDNA conformance and explicit issuer/wire boundaries.
#[path = "support/v4_idna.rs"]
mod idna;
#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;
#[allow(dead_code)]
#[path = "support/v4_unicode.rs"]
mod unicode;

use idna::{Idna, hash, puny_decode, puny_encode};
use proptest::prelude::*;
use regex_lite::Regex;
use serde_json::Value as Json;
use std::sync::OnceLock;

fn reference() -> &'static Idna {
    static IDNA: OnceLock<Idna> = OnceLock::new();
    IDNA.get_or_init(|| Idna::new(registry::CBOR_REGISTRY_JSON))
}

fn unescape(input: &str) -> Result<String, &'static str> {
    static ESCAPES: OnceLock<Regex> = OnceLock::new();
    let re =
        ESCAPES.get_or_init(|| Regex::new(r"\\u([0-9A-Fa-f]{4})|\\x\{([0-9A-Fa-f]+)\}").unwrap());
    let mut points = Vec::new();
    let mut offset = 0;
    for captures in re.captures_iter(input) {
        let full = captures.get(0).unwrap();
        points.extend(input[offset..full.start()].chars().map(u32::from));
        let value = captures.get(1).or_else(|| captures.get(2)).unwrap();
        points.push(u32::from_str_radix(value.as_str(), 16).map_err(|_| "invalid_scalar")?);
        offset = full.end();
    }
    points.extend(input[offset..].chars().map(u32::from));
    let mut text = String::new();
    let mut index = 0;
    while index < points.len() {
        let mut cp = points[index];
        if (0xd800..=0xdbff).contains(&cp)
            && let Some(&low) = points.get(index + 1)
            && (0xdc00..=0xdfff).contains(&low)
        {
            cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
            index += 1;
        }
        text.push(char::from_u32(cp).ok_or("invalid_scalar")?);
        index += 1;
    }
    Ok(text)
}

// v4.rust_idna.conformance
#[test]
fn official_nontransitional_to_ascii_conformance() {
    let r = reference();
    let raw = include_str!("../../testdata/unicode15_1/IdnaTestV2.txt");
    assert_eq!(hash(raw.as_bytes()), r.conformance_sha256);
    let mut count = 0;
    for (line_number, line) in raw.lines().enumerate() {
        let line = line
            .split('#')
            .next()
            .unwrap()
            .trim_matches([' ', '\t', '\r']);
        if line.is_empty() {
            continue;
        }
        let cols: Vec<_> = line
            .split(';')
            .map(|s| s.trim_matches([' ', '\t', '\r']))
            .collect();
        assert!(cols.len() >= 5);
        let expected = if !cols[3].is_empty() {
            cols[3]
        } else if !cols[1].is_empty() {
            cols[1]
        } else {
            cols[0]
        };
        let status = if !cols[4].is_empty() {
            cols[4]
        } else if !cols[2].is_empty() {
            cols[2]
        } else {
            "[]"
        };
        // Rust strings cannot contain isolated surrogates. Reject them at the
        // fixture's explicit scalar boundary without replacement characters.
        let actual = unescape(cols[0]).and_then(|input| r.process(&input).map(|v| v.0));
        if status == "[]" {
            assert_eq!(actual, unescape(expected), "line {}", line_number + 1);
        } else {
            assert!(
                actual.is_err(),
                "line {} unexpectedly accepted: {:?}",
                line_number + 1,
                actual
            );
        }
        count += 1;
    }
    assert_eq!(count, 6265);
    println!("all {count} official Unicode 15.1 nontransitional ToASCII cases passed");
}

// v4.rust_idna.context
#[test]
fn idna2008_context_and_wire_identity_boundaries() {
    let r = reference();
    // These multilingual fixtures exercise script/joiner/Bidi rules only.
    for input in [
        "\u{375}\u{3b1}.example",
        "\u{5d0}\u{5f3}.example",
        "\u{5d0}\u{5f4}.example",
        "\u{30ab}\u{30fb}\u{30ca}.example",
        "\u{30fb}\u{4e00}.example",
        "\u{627}\u{660}\u{661}.example",
        "\u{627}\u{6f0}\u{6f1}.example",
        "\u{915}\u{94d}\u{200d}\u{937}.example",
        "\u{915}\u{94d}\u{200c}\u{937}.example",
        "a1.\u{645}\u{62b}\u{627}\u{644}",
    ] {
        let ascii = r
            .issuer_dns(input)
            .unwrap_or_else(|e| panic!("{input}: {e}"));
        r.wire_dns(&ascii).unwrap();
    }
    for input in [
        "\u{375}a.example",
        "\u{5f3}\u{5d0}.example",
        "\u{5f4}\u{5d0}.example",
        "a\u{30fb}b.example",
        "\u{627}\u{660}\u{6f0}.example",
        "\u{915}\u{200d}\u{937}.example",
        "\u{628}\u{200c}\u{301}a.example",
        "a\u{200c}\u{628}.example",
        "1.\u{645}\u{62b}\u{627}\u{644}",
        "\u{1f600}.example",
        "xn--e28h.example",
        "xn--abc-.example",
        "xn--a!",
        "a_b.example",
        "\u{1cc00}.example",
    ] {
        assert!(
            r.issuer_dns(input).is_err(),
            "invalid contextual label accepted: {input}"
        );
    }
    // UTS46 alone permits this symbol. Flowersec additionally requires IDNA2008.
    assert_eq!(
        r.process("\u{1f600}.example").unwrap().0,
        "xn--e28h.example"
    );
    for text in [
        "EXAMPLE.COM",
        "\u{fc}.example",
        "example.com.",
        "xn--BCHER-kva.example",
    ] {
        assert!(
            r.wire_dns(text).is_err(),
            "noncanonical wire accepted: {text}"
        );
    }
    assert_eq!(r.issuer_dns("EXAMPLE.COM").unwrap(), "example.com");
    assert!(unescape(r"\uD800").is_err());
    assert!(unescape(r"\x{110000}").is_err());
    assert_eq!(unescape(r"\uD83D\uDE00").unwrap(), "\u{1f600}");
}

// v4.rust_idna.shared_dns
#[test]
fn shared_dns_corpus_preserves_explicit_issuer_wire_boundary() {
    let corpus: Json =
        serde_json::from_str(include_str!("../../testdata/transport_v4/text.json")).unwrap();
    let mut counts = [0, 0];
    for vector in corpus["vectors"].as_array().unwrap() {
        let operation = vector["operation"].as_str().unwrap();
        if !matches!(operation, "issuer_dns" | "wire_dns") {
            continue;
        }
        let input = vector["input"].as_str().unwrap();
        let actual = if operation == "issuer_dns" {
            reference().issuer_dns(input)
        } else {
            reference().wire_dns(input).map(|()| input.to_owned())
        };
        if vector.get("expected_error").is_some() {
            counts[1] += 1;
            assert!(actual.is_err(), "{} accepted", vector["id"]);
        } else {
            counts[0] += 1;
            let actual = actual.unwrap_or_else(|e| panic!("{}: {e}", vector["id"]));
            assert_eq!(actual, vector["output"], "{}", vector["id"]);
            assert_eq!(
                actual
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
                vector["utf8_hex"]
            );
        }
    }
    assert!(counts.iter().all(|&n| n > 0));
    println!(
        "{} positive and {} negative shared DNS cases",
        counts[0], counts[1]
    );
}

// v4.rust_idna.properties
proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn bootstring_round_trips_scalars(points in prop::collection::vec(any::<char>(), 0..64)) {
        let encoded = puny_encode(&points).unwrap();
        prop_assert_eq!(puny_decode(&encoded).unwrap(), points);
    }
    #[test]
    fn issuer_output_is_accepted_unchanged_by_wire(points in prop::collection::vec(any::<char>(), 0..128)) {
        let input: String = points.iter().collect();
        if let Ok(ascii) = reference().issuer_dns(&input) {
            prop_assert!(reference().wire_dns(&ascii).is_ok());
            prop_assert_eq!(reference().issuer_dns(&ascii).unwrap(), ascii);
        }
    }
}
