use ed25519_dalek::SigningKey;
use flowersec::{
    ConnectArtifact,
    controlplane::client::{ConnectArtifactRequestConfig, EntryConnectArtifactRequestConfig},
    controlplane::http::{ArtifactIssueInput, ArtifactRequestMetadata},
    controlplane::token::{self, Payload},
    generated::flowersec::{
        controlplane::v1::{ChannelInitGrant, Role as ControlRole, Suite as ControlSuite},
        direct::v1::{DirectConnectInfo, Suite as DirectSuite},
        tunnel::v1::{Attach, Role as TunnelRole},
    },
};

const TOKEN_SENTINEL: &str = "token-sentinel-must-not-appear";
const PSK_SENTINEL: &str = "psk-sentinel-must-not-appear";
const TICKET_SENTINEL: &str = "ticket-sentinel-must-not-appear";

fn tunnel_grant() -> ChannelInitGrant {
    ChannelInitGrant {
        tunnel_url: "wss://tunnel.example.test/v1".to_owned(),
        channel_id: "visible-tunnel-channel".to_owned(),
        channel_init_expire_at_unix_s: 1_900_000_000,
        idle_timeout_seconds: 60,
        role: ControlRole::Client,
        token: TOKEN_SENTINEL.to_owned(),
        e2ee_psk_b64u: PSK_SENTINEL.to_owned(),
        allowed_suites: vec![ControlSuite::X25519HkdfSha256Aes256Gcm],
        default_suite: ControlSuite::X25519HkdfSha256Aes256Gcm,
    }
}

fn direct_info() -> DirectConnectInfo {
    DirectConnectInfo {
        ws_url: "wss://direct.example.test/v1".to_owned(),
        channel_id: "visible-direct-channel".to_owned(),
        e2ee_psk_b64u: PSK_SENTINEL.to_owned(),
        channel_init_expire_at_unix_s: 1_900_000_000,
        default_suite: DirectSuite::X25519HkdfSha256Aes256Gcm,
    }
}

#[test]
fn generated_wire_debug_redacts_tokens_and_psks() {
    let grant = tunnel_grant();
    let grant_debug = format!("{grant:?}");
    assert_redacted(&grant_debug, &[TOKEN_SENTINEL, PSK_SENTINEL]);
    assert!(grant_debug.contains("visible-tunnel-channel"));
    let grant_json = serde_json::to_value(&grant).expect("serialize grant");
    assert_eq!(grant_json["token"], TOKEN_SENTINEL);
    assert_eq!(grant_json["e2ee_psk_b64u"], PSK_SENTINEL);

    let direct = direct_info();
    let direct_debug = format!("{direct:?}");
    assert_redacted(&direct_debug, &[PSK_SENTINEL]);
    assert!(direct_debug.contains("visible-direct-channel"));
    let direct_json = serde_json::to_value(&direct).expect("serialize direct info");
    assert_eq!(direct_json["e2ee_psk_b64u"], PSK_SENTINEL);

    let attach = Attach {
        v: 1,
        channel_id: "visible-attach-channel".to_owned(),
        role: TunnelRole::Client,
        token: TOKEN_SENTINEL.to_owned(),
        endpoint_instance_id: "visible-instance".to_owned(),
        caps: None,
    };
    let attach_debug = format!("{attach:?}");
    assert_redacted(&attach_debug, &[TOKEN_SENTINEL]);
    assert!(attach_debug.contains("visible-attach-channel"));
    let attach_json = serde_json::to_value(&attach).expect("serialize attach");
    assert_eq!(attach_json["token"], TOKEN_SENTINEL);
}

#[test]
fn artifact_and_entry_request_debug_redact_embedded_secrets() {
    let artifact = ConnectArtifact::Tunnel {
        grant: tunnel_grant(),
        scoped: Vec::new(),
        correlation: None,
    };
    let artifact_debug = format!("{artifact:?}");
    assert_redacted(&artifact_debug, &[TOKEN_SENTINEL, PSK_SENTINEL]);
    assert!(artifact_debug.contains("visible-tunnel-channel"));
    let artifact_json = String::from_utf8(artifact.to_json().expect("serialize tunnel artifact"))
        .expect("artifact JSON is UTF-8");
    assert!(artifact_json.contains(TOKEN_SENTINEL));
    assert!(artifact_json.contains(PSK_SENTINEL));

    let direct_artifact = ConnectArtifact::Direct {
        info: direct_info(),
        scoped: Vec::new(),
        correlation: None,
    };
    let direct_artifact_debug = format!("{direct_artifact:?}");
    assert_redacted(&direct_artifact_debug, &[PSK_SENTINEL]);
    assert!(direct_artifact_debug.contains("visible-direct-channel"));
    let direct_artifact_json = String::from_utf8(
        direct_artifact
            .to_json()
            .expect("serialize direct artifact"),
    )
    .expect("artifact JSON is UTF-8");
    assert!(direct_artifact_json.contains(PSK_SENTINEL));

    let request = EntryConnectArtifactRequestConfig {
        request: ConnectArtifactRequestConfig::new("visible-endpoint"),
        entry_ticket: TICKET_SENTINEL.to_owned(),
    };
    let request_debug = format!("{request:?}");
    assert_redacted(&request_debug, &[TICKET_SENTINEL]);
    assert!(request_debug.contains("visible-endpoint"));

    let issue = ArtifactIssueInput {
        endpoint_id: "visible-issue-endpoint".to_owned(),
        payload: None,
        trace_id: "visible-trace".to_owned(),
        entry_ticket: TICKET_SENTINEL.to_owned(),
        is_entry: true,
        metadata: ArtifactRequestMetadata::default(),
    };
    let issue_debug = format!("{issue:?}");
    assert_redacted(&issue_debug, &[TICKET_SENTINEL]);
    assert!(issue_debug.contains("visible-issue-endpoint"));
}

#[test]
fn parsed_token_debug_redacts_signed_material() {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let token = token::sign(
        &signing_key,
        Payload {
            kid: "visible-key".to_owned(),
            aud: "visible-audience".to_owned(),
            iss: "visible-issuer".to_owned(),
            channel_id: "visible-parsed-channel".to_owned(),
            role: 1,
            token_id: "visible-token-id".to_owned(),
            init_exp: 1_900_000_000,
            idle_timeout_seconds: 60,
            iat: 1_899_999_900,
            exp: 1_899_999_960,
        },
    )
    .expect("sign token");
    let parsed = token::parse(&token).expect("parse token");
    let signed_bytes_debug = format!("{:?}", parsed.signed);
    let signature_bytes_debug = format!("{:?}", parsed.signature);

    let parsed_debug = format!("{parsed:?}");

    assert_eq!(parsed_debug.matches("[REDACTED]").count(), 2);
    assert!(parsed_debug.contains("visible-parsed-channel"));
    assert!(!parsed_debug.contains(&signed_bytes_debug));
    assert!(!parsed_debug.contains(&signature_bytes_debug));
    assert!(!parsed_debug.contains(&token));
}

fn assert_redacted(debug: &str, sentinels: &[&str]) {
    assert_eq!(
        debug.matches("[REDACTED]").count(),
        sentinels.len(),
        "unexpected redaction marker count: {debug}"
    );
    for sentinel in sentinels {
        assert!(
            !debug.contains(sentinel),
            "Debug output leaked {sentinel}: {debug}"
        );
    }
}
