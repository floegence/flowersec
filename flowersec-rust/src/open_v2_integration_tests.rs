use crate::protocol_v2::{OpenPayloadV2, decode_open_payload_v2, encode_open_payload_v2};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Fixture {
    unicode_version: String,
    positive: Vec<Vector>,
    negative: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    id: String,
    kind: Option<String>,
    kind_utf8_hex: Option<String>,
    metadata_json: Option<String>,
    metadata_hex: Option<String>,
}

#[test]
fn open_unicode_and_canonical_metadata_vectors() {
    let fixture = fixture();
    assert_eq!(fixture.unicode_version, "15.1.0");
    for vector in fixture.positive {
        let kind = vector.kind.expect("positive kind");
        let metadata = vector
            .metadata_json
            .expect("positive metadata")
            .into_bytes();
        let encoded = encode_open_payload_v2(&OpenPayloadV2::new(
            1,
            [0; 32],
            kind.clone(),
            metadata.clone(),
        ))
        .unwrap_or_else(|error| panic!("{}: {error}", vector.id));
        let decoded = decode_open_payload_v2(&encoded)
            .unwrap_or_else(|error| panic!("{}: {error}", vector.id));
        assert_eq!(decoded.kind(), kind, "{}", vector.id);
        assert_eq!(decoded.metadata(), metadata, "{}", vector.id);
    }
    for vector in fixture.negative {
        let metadata = vector
            .metadata_hex
            .map(|value| decode_hex(&value))
            .unwrap_or_else(|| vector.metadata_json.unwrap_or_default().into_bytes());
        if let Some(kind_hex) = vector.kind_utf8_hex {
            let kind = decode_hex(&kind_hex);
            let mut raw = vec![0_u8; 46 + kind.len() + metadata.len()];
            raw[..8].copy_from_slice(&1_u64.to_be_bytes());
            raw[40..42].copy_from_slice(&(kind.len() as u16).to_be_bytes());
            raw[42..46].copy_from_slice(&(metadata.len() as u32).to_be_bytes());
            raw[46..46 + kind.len()].copy_from_slice(&kind);
            raw[46 + kind.len()..].copy_from_slice(&metadata);
            assert!(decode_open_payload_v2(&raw).is_err(), "{}", vector.id);
            continue;
        }
        let payload = OpenPayloadV2::new(1, [0; 32], vector.kind.unwrap_or_default(), metadata);
        assert!(encode_open_payload_v2(&payload).is_err(), "{}", vector.id);
    }
}

#[test]
fn open_enforces_existing_metadata_limits_at_the_boundary() {
    let array = |count: usize| {
        format!(
            "[{}]",
            std::iter::repeat_n("0", count)
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let keys = |count: usize| {
        format!(
            "{{{}}}",
            (0..count)
                .map(|index| format!("\"k{index:02}\":0"))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let metadata_4096 = format!(
        "{{\"a\":\"{}\",\"b\":\"{}\",\"c\":\"{}\",\"d\":\"{}\",\"e\":\"{}\",\"f\":\"{}\",\"g\":\"{}\",\"h\":\"{}\"}}",
        "a".repeat(512),
        "b".repeat(512),
        "c".repeat(512),
        "d".repeat(512),
        "e".repeat(512),
        "f".repeat(512),
        "g".repeat(512),
        "h".repeat(455),
    );
    assert_eq!(metadata_4096.len(), 4_096);

    let valid = [
        ("k".repeat(128), "{}".to_owned()),
        (
            "rpc".to_owned(),
            format!("{{\"{}\":\"{}\"}}", "k".repeat(64), "s".repeat(512)),
        ),
        ("rpc".to_owned(), format!("{{\"a\":{}}}", array(32))),
        ("rpc".to_owned(), "{\"a\":{\"b\":{\"c\":0}}}".to_owned()),
        (
            "rpc".to_owned(),
            format!("{{\"a\":{},\"b\":{}}}", array(32), array(30)),
        ),
        ("rpc".to_owned(), keys(64)),
        ("rpc".to_owned(), metadata_4096),
    ];
    for (kind, metadata) in valid {
        encode_open_payload_v2(&OpenPayloadV2::new(1, [0; 32], kind, metadata.into_bytes()))
            .expect("exact OPEN boundary must pass");
    }

    let invalid = [
        ("k".repeat(129), "{}".to_owned()),
        ("rpc".to_owned(), format!("{{\"{}\":0}}", "k".repeat(65))),
        (
            "rpc".to_owned(),
            format!("{{\"a\":\"{}\"}}", "s".repeat(513)),
        ),
        ("rpc".to_owned(), format!("{{\"a\":{}}}", array(33))),
        (
            "rpc".to_owned(),
            "{\"a\":{\"b\":{\"c\":{\"d\":0}}}}".to_owned(),
        ),
        (
            "rpc".to_owned(),
            format!("{{\"a\":{},\"b\":{}}}", array(32), array(32)),
        ),
        ("rpc".to_owned(), keys(65)),
        (
            "rpc".to_owned(),
            format!("{{\"a\":\"{}\"}}", "s".repeat(4_090)),
        ),
    ];
    for (kind, metadata) in invalid {
        assert!(
            encode_open_payload_v2(&OpenPayloadV2::new(1, [0; 32], kind, metadata.into_bytes(),))
                .is_err()
        );
    }

    let encoded = encode_open_payload_v2(&OpenPayloadV2::new(
        1,
        [0; 32],
        "rpc".to_owned(),
        Vec::new(),
    ))
    .expect("empty metadata canonicalizes");
    assert_eq!(decode_open_payload_v2(&encoded).unwrap().metadata(), b"{}");
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "../../testdata/transport_v2/open_unicode_vectors.json"
    ))
    .expect("decode OPEN vectors")
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("valid hex")
        })
        .collect()
}
