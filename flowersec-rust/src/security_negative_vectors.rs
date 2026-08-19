use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    version: u32,
    profile: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    id: String,
    kind: String,
    value: String,
}

#[test]
fn shared_security_negative_vectors_reject_malformed_inputs() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../testdata/transport_v2/security_negative_vectors.json"
    ))
    .expect("decode security vectors");
    assert_eq!(fixture.version, 1);
    assert_eq!(fixture.profile, "flowersec/2");
    for vector in fixture.vectors {
        let raw = if vector.kind == "artifact_json" {
            vector.value.into_bytes()
        } else {
            hex_decode(&vector.value)
        };
        let accepted = match vector.kind.as_str() {
            "artifact_json" => crate::artifact_v2::Artifact::parse(raw).is_ok(),
            "fsa2_hex" => crate::admission_v2::security_accepts(&vector.kind, &raw),
            "fsr2_hex" | "open_hex" => crate::protocol_v2::security_accepts(&vector.kind, &raw),
            other => panic!("unknown security vector kind {other}"),
        };
        assert!(!accepted, "{} accepted malformed input", vector.id);
    }
}

fn hex_decode(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex(pair[0]) << 4) | hex(pair[1]))
        .collect()
}

fn hex(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex"),
    }
}
