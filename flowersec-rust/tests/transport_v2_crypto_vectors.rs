use flowersec::protocol_v2::{
    CipherSuiteV2, DirectionV2, InnerRecordTypeV2, ProtocolV2Error, RecordHeaderV2, SetupPrefaceV2,
    StreamOpenerRoleV2, compute_setup_mac_v2, derive_epoch_zero_v2, derive_stream_material_v2,
    encode_inner_record_v2, open_record_v2, record_aad_v2, seal_record_v2,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VectorFile {
    version: u8,
    profile: String,
    source: String,
    vectors: Vec<CryptoVector>,
}

#[derive(Debug, Deserialize)]
struct CryptoVector {
    id: String,
    direction: u8,
    epoch: u32,
    logical_stream_id: u64,
    sequence: u64,
    session_prk_hex: String,
    h3_hex: String,
    epoch_secret_hex: String,
    control_root_hex: String,
    stream_root_hex: String,
    setup_root_hex: String,
    rekey_root_hex: String,
    stream_secret_hex: String,
    record_key_hex: String,
    nonce_prefix_hex: String,
    fss2_hex: String,
    fsr2_header_hex: String,
    inner_hex: String,
    aad_hex: String,
    chacha20_poly1305_ciphertext_hex: String,
    aes_256_gcm_ciphertext_hex: String,
}

#[test]
fn rust_consumes_transport_v2_crypto_vectors() {
    let fixture: VectorFile = serde_json::from_str(include_str!(
        "../../testdata/transport_v2/crypto_vectors.json"
    ))
    .expect("parse transport v2 crypto vectors");
    assert_eq!(fixture.version, 1);
    assert_eq!(fixture.profile, "flowersec/2");
    assert!(!fixture.source.is_empty());
    assert!(!fixture.vectors.is_empty());

    for vector in fixture.vectors {
        let direction = DirectionV2::try_from(vector.direction).expect("fixture direction");
        let session_prk = array::<32>(&vector.session_prk_hex);
        let h3 = array::<32>(&vector.h3_hex);

        let roots = derive_epoch_zero_v2(&session_prk, direction).expect("derive epoch zero");
        assert_eq!(format!("{roots:?}"), "EpochRootsV2([REDACTED])");
        assert_hex(
            &vector.id,
            "epoch secret",
            roots.epoch_secret(),
            &vector.epoch_secret_hex,
        );
        assert_hex(
            &vector.id,
            "control root",
            roots.control_root(),
            &vector.control_root_hex,
        );
        assert_hex(
            &vector.id,
            "stream root",
            roots.stream_root(),
            &vector.stream_root_hex,
        );
        assert_hex(
            &vector.id,
            "setup root",
            roots.setup_root(),
            &vector.setup_root_hex,
        );
        assert_hex(
            &vector.id,
            "rekey root",
            roots.rekey_root(),
            &vector.rekey_root_hex,
        );

        let material = derive_stream_material_v2(
            roots.stream_root(),
            &h3,
            vector.logical_stream_id,
            direction,
            vector.epoch,
        )
        .expect("derive stream material");
        assert_eq!(format!("{material:?}"), "RecordMaterialV2([REDACTED])");
        assert_hex(
            &vector.id,
            "stream secret",
            material.secret(),
            &vector.stream_secret_hex,
        );
        assert_hex(
            &vector.id,
            "record key",
            material.record_key(),
            &vector.record_key_hex,
        );
        assert_hex(
            &vector.id,
            "nonce prefix",
            material.nonce_prefix(),
            &vector.nonce_prefix_hex,
        );

        let mut preface = SetupPrefaceV2::new(
            StreamOpenerRoleV2::Client,
            vector.logical_stream_id,
            vector.epoch,
        );
        preface.set_setup_mac(
            compute_setup_mac_v2(roots.setup_root(), &h3, &preface).expect("compute setup MAC"),
        );
        assert_hex(
            &vector.id,
            "FSS2",
            &preface.encode().expect("encode FSS2"),
            &vector.fss2_hex,
        );

        let inner = encode_inner_record_v2(InnerRecordTypeV2::Data, b"abc")
            .expect("encode DATA inner record");
        assert_hex(&vector.id, "inner record", &inner, &vector.inner_hex);
        let header = RecordHeaderV2::new(
            vector.epoch,
            vector.sequence,
            u32::try_from(inner.len() + 16).expect("fixture ciphertext length"),
        );
        assert_hex(
            &vector.id,
            "FSR2 header",
            &header.encode().expect("encode FSR2 header"),
            &vector.fsr2_header_hex,
        );
        assert_hex(
            &vector.id,
            "record AAD",
            &record_aad_v2(&h3, vector.logical_stream_id, direction, &header).expect("build AAD"),
            &vector.aad_hex,
        );

        for (suite, expected) in [
            (
                CipherSuiteV2::ChaCha20Poly1305,
                &vector.chacha20_poly1305_ciphertext_hex,
            ),
            (CipherSuiteV2::Aes256Gcm, &vector.aes_256_gcm_ciphertext_hex),
        ] {
            let ciphertext = seal_record_v2(
                suite,
                material.record_key(),
                material.nonce_prefix(),
                &h3,
                vector.logical_stream_id,
                direction,
                &header,
                &inner,
            )
            .expect("seal fixture record");
            assert_hex(&vector.id, "ciphertext", &ciphertext, expected);
            assert_eq!(
                open_record_v2(
                    suite,
                    material.record_key(),
                    material.nonce_prefix(),
                    &h3,
                    vector.logical_stream_id,
                    direction,
                    &header,
                    &ciphertext,
                )
                .expect("open fixture record"),
                inner
            );
        }

        let ciphertext = decode_hex(&vector.chacha20_poly1305_ciphertext_hex);
        for (stream_id, checked_direction, checked_header) in [
            (vector.logical_stream_id + 2, direction, header),
            (
                vector.logical_stream_id,
                DirectionV2::ServerToClient,
                header,
            ),
            (
                vector.logical_stream_id,
                direction,
                RecordHeaderV2::new(
                    vector.epoch,
                    vector.sequence + 1,
                    header.ciphertext_length(),
                ),
            ),
        ] {
            assert_eq!(
                open_record_v2(
                    CipherSuiteV2::ChaCha20Poly1305,
                    material.record_key(),
                    material.nonce_prefix(),
                    &h3,
                    stream_id,
                    checked_direction,
                    &checked_header,
                    &ciphertext,
                )
                .expect_err("modified authenticated context must fail"),
                ProtocolV2Error::Authentication,
                "{} returned the wrong authentication error",
                vector.id,
            );
        }

        let mut tampered = ciphertext;
        tampered[0] ^= 1;
        assert_eq!(
            open_record_v2(
                CipherSuiteV2::ChaCha20Poly1305,
                material.record_key(),
                material.nonce_prefix(),
                &h3,
                vector.logical_stream_id,
                direction,
                &header,
                &tampered,
            )
            .expect_err("tampered ciphertext must fail"),
            ProtocolV2Error::Authentication,
        );
    }
}

fn assert_hex(vector: &str, field: &str, got: &[u8], expected: &str) {
    assert_eq!(got, decode_hex(expected), "{vector}: {field}");
}

fn array<const N: usize>(value: &str) -> [u8; N] {
    decode_hex(value)
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N}-byte hex value"))
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex input has an odd length");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex is ASCII");
            u8::from_str_radix(text, 16).expect("valid hex byte")
        })
        .collect()
}
