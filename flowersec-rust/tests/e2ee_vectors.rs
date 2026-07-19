use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flowersec::e2ee::{
    Direction, E2eeError, RecordFlag, Suite, TranscriptInputs, decrypt_record, derive_rekey_key,
    derive_session_keys, derive_shared_secret, encrypt_record, transcript_hash,
};
use serde::Deserialize;
use std::{fs, path::PathBuf};

#[derive(Debug, Deserialize)]
struct Vectors {
    transcript_hash: Vec<TranscriptVector>,
    record_frame: Vec<RecordVector>,
    handshake_x25519_negative: Vec<X25519NegativeVector>,
    handshake_p256: Vec<P256Vector>,
}

#[derive(Debug, Deserialize)]
struct X25519NegativeVector {
    case_id: String,
    inputs: X25519NegativeInput,
    expected: X25519NegativeExpected,
}

#[derive(Debug, Deserialize)]
struct X25519NegativeInput {
    private_key_b64u: String,
    peer_public_key_b64u: String,
}

#[derive(Debug, Deserialize)]
struct X25519NegativeExpected {
    reject: bool,
}

#[derive(Debug, Deserialize)]
struct TranscriptVector {
    inputs: TranscriptInput,
    expected: TranscriptExpected,
}

#[derive(Debug, Deserialize)]
struct TranscriptInput {
    version: u8,
    suite: u16,
    role: u8,
    client_features: u32,
    server_features: u32,
    channel_id: String,
    nonce_c_b64u: String,
    nonce_s_b64u: String,
    client_eph_pub_b64u: String,
    server_eph_pub_b64u: String,
}

#[derive(Debug, Deserialize)]
struct TranscriptExpected {
    transcript_hash_b64u: String,
}

#[derive(Debug, Deserialize)]
struct RecordVector {
    inputs: RecordInput,
    expected: RecordExpected,
}

#[derive(Debug, Deserialize)]
struct RecordInput {
    key_b64u: String,
    nonce_prefix_b64u: String,
    flags: u8,
    seq: u64,
    plaintext_utf8: String,
    max_record_bytes: usize,
}

#[derive(Debug, Deserialize)]
struct RecordExpected {
    frame_b64u: String,
}

#[derive(Debug, Deserialize)]
struct P256Vector {
    inputs: P256Input,
    expected: P256Expected,
}

#[derive(Debug, Deserialize)]
struct P256Input {
    version: u8,
    suite: u16,
    role: u8,
    client_features: u32,
    server_features: u32,
    channel_id: String,
    nonce_c_b64u: String,
    nonce_s_b64u: String,
    client_eph_priv_b64u: String,
    server_eph_pub_b64u: String,
    client_eph_pub_b64u: String,
    psk_b64u: String,
}

#[derive(Debug, Deserialize)]
struct P256Expected {
    shared_secret_b64u: String,
    transcript_hash_b64u: String,
    c2s_key_b64u: String,
    s2c_key_b64u: String,
    c2s_nonce_prefix_b64u: String,
    s2c_nonce_prefix_b64u: String,
    rekey_base_b64u: String,
}

#[test]
fn shared_e2ee_vectors() {
    let vectors: Vectors =
        serde_json::from_slice(&fs::read(vector_path()).expect("read E2EE vectors"))
            .expect("parse E2EE vectors");

    for vector in vectors.transcript_hash {
        let input = vector.inputs;
        let nonce_c = array::<32>(&input.nonce_c_b64u);
        let nonce_s = array::<32>(&input.nonce_s_b64u);
        let client_public = decode(&input.client_eph_pub_b64u);
        let server_public = decode(&input.server_eph_pub_b64u);
        let hash = transcript_hash(&TranscriptInputs {
            version: input.version,
            suite: input.suite,
            role: input.role,
            client_features: input.client_features,
            server_features: input.server_features,
            channel_id: &input.channel_id,
            nonce_c,
            nonce_s,
            client_ephemeral_public_key: &client_public,
            server_ephemeral_public_key: &server_public,
        })
        .expect("transcript hash");
        assert_eq!(encode(&hash), vector.expected.transcript_hash_b64u);
    }

    for vector in vectors.record_frame {
        let input = vector.inputs;
        let key = array::<32>(&input.key_b64u);
        let nonce = array::<4>(&input.nonce_prefix_b64u);
        let flag = RecordFlag::try_from(input.flags).expect("record flag");
        let frame = encrypt_record(
            &key,
            nonce,
            flag,
            input.seq,
            input.plaintext_utf8.as_bytes(),
            input.max_record_bytes,
        )
        .expect("encrypt vector");
        assert_eq!(encode(&frame), vector.expected.frame_b64u);
        let decrypted = decrypt_record(&key, nonce, &frame, input.seq, input.max_record_bytes)
            .expect("decrypt vector");
        assert_eq!(decrypted.plaintext, input.plaintext_utf8.as_bytes());
    }

    for vector in vectors.handshake_x25519_negative {
        assert!(vector.expected.reject, "case {}", vector.case_id);
        let result = derive_shared_secret(
            Suite::X25519HkdfSha256Aes256Gcm,
            &decode(&vector.inputs.private_key_b64u),
            &decode(&vector.inputs.peer_public_key_b64u),
        );
        assert!(
            matches!(result, Err(E2eeError::InvalidKey)),
            "case {} accepted a low-order X25519 public key",
            vector.case_id
        );
    }

    for vector in vectors.handshake_p256 {
        let input = vector.inputs;
        let shared = derive_shared_secret(
            Suite::P256HkdfSha256Aes256Gcm,
            &decode(&input.client_eph_priv_b64u),
            &decode(&input.server_eph_pub_b64u),
        )
        .expect("derive P-256 secret");
        assert_eq!(encode(shared.expose()), vector.expected.shared_secret_b64u);
        let client_public = decode(&input.client_eph_pub_b64u);
        let server_public = decode(&input.server_eph_pub_b64u);
        let transcript = transcript_hash(&TranscriptInputs {
            version: input.version,
            suite: input.suite,
            role: input.role,
            client_features: input.client_features,
            server_features: input.server_features,
            channel_id: &input.channel_id,
            nonce_c: array(&input.nonce_c_b64u),
            nonce_s: array(&input.nonce_s_b64u),
            client_ephemeral_public_key: &client_public,
            server_ephemeral_public_key: &server_public,
        })
        .expect("P-256 transcript");
        assert_eq!(encode(&transcript), vector.expected.transcript_hash_b64u);
        let keys = derive_session_keys(&decode(&input.psk_b64u), shared.expose(), transcript)
            .expect("derive session keys");
        assert_eq!(encode(keys.c2s_key.expose()), vector.expected.c2s_key_b64u);
        assert_eq!(encode(keys.s2c_key.expose()), vector.expected.s2c_key_b64u);
        assert_eq!(
            encode(&keys.c2s_nonce_prefix),
            vector.expected.c2s_nonce_prefix_b64u
        );
        assert_eq!(
            encode(&keys.s2c_nonce_prefix),
            vector.expected.s2c_nonce_prefix_b64u
        );
        assert_eq!(
            encode(keys.rekey_base.expose()),
            vector.expected.rekey_base_b64u
        );

        let first = derive_rekey_key(
            keys.rekey_base.expose(),
            transcript,
            7,
            Direction::ClientToServer,
        )
        .expect("derive rekey");
        let second = derive_rekey_key(
            keys.rekey_base.expose(),
            transcript,
            7,
            Direction::ClientToServer,
        )
        .expect("derive rekey again");
        assert_eq!(first.expose(), second.expose());
    }
}

fn vector_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("idl")
        .join("flowersec")
        .join("testdata")
        .join("v1")
        .join("e2ee_vectors.json")
}

fn decode(value: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value).expect("base64url")
}

fn array<const N: usize>(value: &str) -> [u8; N] {
    decode(value).try_into().expect("fixed-size vector")
}

fn encode(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}
