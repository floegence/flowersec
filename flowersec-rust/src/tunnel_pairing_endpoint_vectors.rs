use crate::{Artifact, ArtifactLease, ConnectErrorCode, ConnectorOptions, connect};
use serde_json::Value;

#[tokio::test]
async fn tunnel_endpoint_binds_admission_to_its_local_ingress() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../testdata/transport_v5/tunnel_pairing_vectors.json"
    ))
    .unwrap();
    for (role, home, other) in [("client", "A", "B"), ("server", "B", "A")] {
        let leg = &fixture["legs"][role];
        let artifact = Artifact::parse(leg["artifact_json"].as_str().unwrap()).unwrap();
        let candidates = artifact.canonical_candidates();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].normalized_url,
            fixture["listeners"][home]["url"]
        );
        assert_eq!(candidates[0].id, leg["candidate_id"]);
        let admission = artifact.encode_fsb3(&candidates[0].id).unwrap();
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        assert_eq!(hex(&admission.raw), leg["fsb5_hex"]);
        assert_eq!(hex(&admission.binding), leg["admission_binding_hex"]);
        let lease = ArtifactLease::new(artifact, || async { panic!("unexpected spend") });
        let wrong = ConnectorOptions::new()
            .with_tunnel_ingress(fixture["listeners"][other]["url"].as_str().unwrap())
            .unwrap();
        let err = connect(lease.clone(), wrong).await.err().unwrap();
        assert_eq!(err.code(), ConnectErrorCode::TunnelIngressNotAuthorized);
        assert!(lease.claim().is_ok());
    }
}
