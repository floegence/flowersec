use super::*;
use crate::{
    api_v4::TransportEnvironment,
    codec_v4::tests::{array, b, encode_map, sign, t, u},
    environment_v4::{TransportEnvironmentOptions, tests::TestClock},
    namespace_v4::verifier::NamespaceTrustRoot,
};
use ring::signature::{Ed25519KeyPair, KeyPair};

const PROFILE: &str = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
fn signer(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}
fn map<'a>(raw: &'a [u8], name: &str) -> Value<'a> {
    codec::decode_context(
        raw,
        name,
        Limits {
            bytes: 1 << 20,
            nodes: 1 << 20,
        },
        Some(codec::StateLimits {
            bytes: 8192,
            issuers: 16,
            certificates: 16,
            leases: 16,
            segments: 16,
        }),
        Context::with_activation_source(ActivationSource::LiveAuthority),
    )
    .unwrap()
}
fn digest(name: &str, raw: &[u8], schema: &str) -> [u8; 32] {
    codec::digest(name, map(raw, schema)).unwrap()
}
fn replace(raw: &[u8], schema: &str, changes: &[(u64, Vec<u8>)], seed: Option<u8>) -> Vec<u8> {
    let value = map(raw, schema);
    let mut iter = value.children().unwrap();
    let mut fields = Vec::new();
    while let Some(id) = iter.next() {
        let id = id.unwrap().uint().unwrap();
        let child = iter.next().unwrap().unwrap();
        fields.push((
            id,
            changes
                .iter()
                .find(|v| v.0 == id)
                .map_or_else(|| child.raw().to_vec(), |v| v.1.clone()),
        ));
    }
    if seed.is_some() {
        fields.pop();
    }
    for (id, value) in changes {
        if !fields.iter().any(|(existing, _)| existing == id) {
            fields.push((*id, value.clone()));
        }
    }
    fields.sort_by_key(|(id, _)| *id);
    if let Some(seed) = seed {
        sign(schema, &fields, &signer(seed))
    } else {
        encode_map(&fields)
    }
}
fn authorization(profile: &str, id: u8, issuer: u8, seed: u8, role: Option<u64>) -> Vec<u8> {
    let mut fields = vec![
        (0, b(&[id; 16])),
        (1, t("tenant")),
        (2, t("authority")),
        (3, b(&[0; 32])),
        (4, u(1)),
        (5, u(if role.is_some() { 0 } else { 1 })),
        (6, b(&[issuer; 16])),
        (7, b(signer(seed).public_key().as_ref())),
        (8, t("service")),
        (9, u(1)),
        (10, u(10_000)),
        (11, u(0)),
        (12, u(500)),
        (13, u(100_000)),
    ];
    if let Some(role) = role {
        fields.push((14, t(if role == 0 { "client" } else { "server" })));
    }
    fields.push((15, t(profile)));
    if let Some(role) = role {
        fields.push((16, u(role)));
    }
    fields.push((
        24,
        if role.is_some() {
            array(&[u(500), vec![0xf6]])
        } else {
            array(&[vec![0xf6], u(500)])
        },
    ));
    encode_map(&fields)
}

pub(crate) struct Fixture {
    pub(crate) environment: TransportEnvironment,
    pub(crate) verifier: NamespaceVerifier,
    pub(crate) artifact: Vec<u8>,
    pub(crate) client: Vec<u8>,
    pub(crate) server: Vec<u8>,
    pub(crate) activation: Vec<u8>,
    source: ActivationSource,
    trust: Vec<u8>,
    head: Vec<u8>,
    state: Vec<u8>,
}
impl Fixture {
    fn new(source: ActivationSource) -> Self {
        Self::with_identity(source, PROFILE, None)
    }
    pub(crate) fn with_identity(
        source: ActivationSource,
        profile: &str,
        identities: Option<[(&[u8], &[u8; 32]); 2]>,
    ) -> Self {
        Self::with_identity_and_execution(source, profile, identities, false)
    }
    pub(crate) fn with_identity_and_execution(
        source: ActivationSource,
        profile: &str,
        identities: Option<[(&[u8], &[u8; 32]); 2]>,
        execution: bool,
    ) -> Self {
        let environment = TransportEnvironment::with_options(TransportEnvironmentOptions {
            application_executor: crate::ApplicationExecutorConfig {
                execution,
                ..crate::ApplicationExecutorConfig::default()
            },
            clock: Some(TestClock::new(1000, 1010)),
            tenant_limits: crate::environment_v4::ResourceLimits {
                sdk_bytes: 64 << 20,
                ..TransportEnvironmentOptions::default().tenant_limits
            },
            root_limits: crate::environment_v4::ResourceLimits {
                sdk_bytes: 128 << 20,
                ..TransportEnvironmentOptions::default().root_limits
            },
            session_limits: crate::environment_v4::ResourceLimits {
                // Execution fixtures install the complete fixed RPC lane set
                // alongside the authenticated engine and recovery owners.
                sdk_bytes: if execution { 16 << 20 } else { 8 << 20 },
                ..TransportEnvironmentOptions::default().session_limits
            },
            ..TransportEnvironmentOptions::default()
        })
        .unwrap();
        Self::with_identity_and_environment(source, profile, identities, environment)
    }
    pub(crate) fn with_identity_and_environment(
        source: ActivationSource,
        profile: &str,
        identities: Option<[(&[u8], &[u8; 32]); 2]>,
        environment: TransportEnvironment,
    ) -> Self {
        let mut verifier = environment
            .namespace_verifier(
                NamespaceTrustRoot {
                    tenant: "tenant".into(),
                    authority: "authority".into(),
                    key_id: [1; 16],
                    public_key: signer(7).public_key().as_ref().try_into().unwrap(),
                    max_lifetime_ms: 120_000,
                },
                8192,
                1 << 16,
            )
            .unwrap();
        let capacity = encode_map(&[
            (0, t("tenant")),
            (1, t("authority")),
            (2, t("capacity-1")),
            (3, u(8192)),
            (4, u(16)),
            (5, u(16)),
            (6, u(16)),
            (7, u(16)),
            (8, u(795)),
            (9, u(1 << 20)),
            (10, u(1024)),
            (11, u(0)),
            (12, u(100)),
            (13, u(100_000)),
            (14, u(100_000)),
        ]);
        let cap = digest("namespace_capacity_digest", &capacity, "NamespaceCapacity");
        let publication = encode_map(&[
            (0, t("publication")),
            (1, u(1)),
            (2, u(60_000)),
            (3, u(90_000)),
        ]);
        let head_delegation = encode_map(&[
            (0, t(crate::codec_v4::tests::schema_revision())),
            (1, t("tenant")),
            (2, t("authority")),
            (3, b(&cap)),
            (4, u(1)),
            (5, b(&[2; 16])),
            (6, b(&[3; 16])),
            (7, b(signer(9).public_key().as_ref())),
            (8, u(0)),
            (9, t("publication")),
            (10, u(1)),
            (11, u(1)),
            (12, u(1)),
            (13, u(90_000)),
        ]);
        let activation_delegation = encode_map(&[
            (0, t(crate::codec_v4::tests::schema_revision())),
            (1, t("tenant")),
            (2, t("authority")),
            (3, b(&cap)),
            (4, u(1)),
            (5, t("activate-1")),
            (6, b(signer(13).public_key().as_ref())),
            (7, u(1)),
            (8, b(&[5; 16])),
            (9, t("spend")),
            (10, u(1)),
            (11, u(10_000)),
            (12, u(0)),
            (13, u(500)),
            (14, u(20_000)),
            (15, u(50_000)),
            (16, array(&[vec![0xf6], u(500)])),
            (17, b(&[6; 16])),
        ]);
        let permissions = [
            authorization(profile, 10, 4, 11, Some(0)),
            authorization(profile, 11, 4, 11, Some(1)),
            authorization(profile, 12, 5, 12, None),
        ]
        .map(|v| replace(&v, "CredentialIssuerAuthorization", &[(3, b(&cap))], None));
        let policy = encode_map(&[
            (0, t("credentials")),
            (1, u(1)),
            (2, u(50_000)),
            (3, u(90_000)),
        ]);
        let authority = encode_map(&[
            (0, t("tenant")),
            (1, b(&[5; 16])),
            (2, t("spend")),
            (3, t("winner")),
        ]);
        let trust = sign(
            "TrustConfig",
            &[
                (0, t(crate::codec_v4::tests::schema_revision())),
                (1, t("tenant")),
                (2, t("authority")),
                (3, u(1)),
                (4, u(1)),
                (5, u(1)),
                (6, u(100_000)),
                (7, capacity),
                (8, publication),
                (9, array(&[policy])),
                (10, array(&permissions)),
                (11, array(std::slice::from_ref(&head_delegation))),
                (12, array(&[activation_delegation])),
                (13, array(&[authority])),
                (14, array(&[])),
                (15, array(&[])),
                (16, b(&[1; 16])),
            ],
            &signer(7),
        );
        let state = encode_map(&[
            (0, t(crate::codec_v4::tests::schema_revision())),
            (1, t("tenant")),
            (2, t("authority")),
            (3, b(&cap)),
            (4, u(1)),
            (5, array(&[u(0), u(0)])),
            (6, t("publication")),
            (7, u(1)),
            (8, array(&[])),
            (9, array(&[])),
            (10, array(&[])),
            (
                11,
                array(&[encode_map(&[
                    (0, u(0)),
                    (1, u(500)),
                    (2, u(100_000)),
                    (3, u(100_000)),
                ])]),
            ),
        ]);
        let head = sign(
            "FreshnessHead",
            &[
                (0, t(crate::codec_v4::tests::schema_revision())),
                (1, t("tenant")),
                (2, t("authority")),
                (3, b(&cap)),
                (4, u(1)),
                (5, array(&[u(0), u(0)])),
                (6, t("publication")),
                (7, u(1)),
                (8, u(1)),
                (9, u(900)),
                (10, u(60_000)),
                (
                    11,
                    b(&digest(
                        "revocation_state_digest",
                        &state,
                        "RevocationState",
                    )),
                ),
                (12, u(state.len() as u64)),
                (13, b(&[3; 16])),
                (
                    14,
                    b(&digest(
                        "head_signer_delegation_digest",
                        &head_delegation,
                        "HeadSignerDelegation",
                    )),
                ),
            ],
            &signer(9),
        );
        let response = sign(
            "TrustBootstrapResponse",
            &[
                (0, t(crate::codec_v4::tests::schema_revision())),
                (1, t("tenant")),
                (2, t("authority")),
                (3, b(&verifier.bootstrap_nonce())),
                (4, u(900)),
                (5, u(10_000)),
                (6, b(&trust)),
                (7, b(&head)),
                (8, b(&[1; 16])),
            ],
            &signer(7),
        );
        verifier.bootstrap(&response, &state).unwrap();
        let certificate = |role: u64| {
            let noise = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
                [16 + role as u8; 32],
            ));
            sign(
                "IdentityCertificate",
                &[
                    (0, t("tenant")),
                    (1, t(if role == 0 { "client" } else { "server" })),
                    (2, t(profile)),
                    (
                        3,
                        encode_map(&[
                            (0, u(u64::from(profile != PROFILE))),
                            (
                                1,
                                b(identities
                                    .map_or(noise.as_bytes(), |keys| keys[role as usize].0)),
                            ),
                        ]),
                    ),
                    (
                        4,
                        b(identities
                            .map_or(signer(14 + role as u8).public_key().as_ref(), |keys| {
                                keys[role as usize].1
                            })),
                    ),
                    (5, u(role)),
                    (6, t("service")),
                    (7, b(&[4; 16])),
                    (8, u(800)),
                    (9, u(50_000)),
                    (10, t("authority")),
                    (11, u(1)),
                    (12, u(8)),
                    (13, t("credentials")),
                    (14, u(1)),
                    (15, b(&cap)),
                ],
                &signer(11),
            )
        };
        let client = certificate(0);
        let server = certificate(1);
        let leg = encode_map(&[
            (0, u(0)),
            (1, b(&[21; 16])),
            (2, u(1)),
            (3, u(0)),
            (4, u(1)),
            (5, u(1)),
            (6, t("example.com")),
            (7, u(443)),
            (8, t("/flowersec/v4/direct")),
            (9, t("http/1.1")),
            (10, t("flowersec.direct.v4")),
            (11, encode_map(&[(0, u(0)), (1, vec![0xf5])])),
        ]);
        let candidate = encode_map(&[
            (0, b(&[20; 16])),
            (1, u(0)),
            (2, u(0)),
            (3, leg),
            (
                6,
                array(&[encode_map(&[
                    (0, t("tenant")),
                    (1, t("authority")),
                    (2, u(1)),
                    (3, b(&cap)),
                    (4, u(3)),
                ])]),
            ),
        ]);
        let contract = encode_map(&[
            (0, u(1 << 20)),
            (1, u(8)),
            (2, u(65_536)),
            (3, u(0)),
            (4, encode_map(&[(0, u(1)), (1, u(1000)), (2, u(1000))])),
            (5, u(0)),
        ]);
        let artifact = sign(
            "Artifact",
            &[
                (0, t("4")),
                (1, t("flowersec/4")),
                (2, t("4")),
                (3, t(profile)),
                (4, t("tenant")),
                (5, b(&[5; 16])),
                (6, b(&[22; 16])),
                (7, b(&[23; 32])),
                (8, b(&[24; 32])),
                (
                    9,
                    b(&digest(
                        "certificate_digest",
                        &client,
                        "IdentityCertificate",
                    )),
                ),
                (
                    10,
                    b(&digest(
                        "certificate_digest",
                        &server,
                        "IdentityCertificate",
                    )),
                ),
                (11, t("service")),
                (12, array(&[candidate])),
                (13, contract),
                (14, u(0)),
                (15, u(0)),
                (16, encode_map(&[(0, vec![0xf4])])),
                (17, encode_map(&[(0, u(0))])),
                (18, u(800)),
                (19, u(20_000)),
                (20, u(40_000)),
                (21, t("authority")),
                (22, u(1)),
                (23, u(8)),
                (24, t("credentials")),
                (25, u(1)),
                (26, b(&cap)),
            ],
            &signer(12),
        );
        let mut fixture = Self {
            environment,
            verifier,
            artifact,
            client,
            server,
            activation: Vec::new(),
            source,
            trust,
            head,
            state,
        };
        fixture.refresh_activation();
        fixture
    }
    pub(crate) fn set_client_keys(&mut self, keys: &crate::crypto_v4::IdentityKeys) {
        self.client = replace(
            &self.client,
            "IdentityCertificate",
            &[
                (
                    3,
                    encode_map(&[
                        (0, u(u64::from(keys.profile() != PROFILE))),
                        (1, b(keys.noise_static_public_key())),
                    ]),
                ),
                (4, b(&keys.ed25519_public_key())),
            ],
            Some(11),
        );
        self.artifact = replace(
            &self.artifact,
            "Artifact",
            &[(
                9,
                b(&digest(
                    "certificate_digest",
                    &self.client,
                    "IdentityCertificate",
                )),
            )],
            Some(12),
        );
        self.refresh_activation();
    }
    pub(crate) fn set_server_keys(&mut self, keys: &crate::crypto_v4::IdentityKeys) {
        self.server = replace(
            &self.server,
            "IdentityCertificate",
            &[
                (
                    3,
                    encode_map(&[
                        (0, u(u64::from(keys.profile() != PROFILE))),
                        (1, b(keys.noise_static_public_key())),
                    ]),
                ),
                (4, b(&keys.ed25519_public_key())),
            ],
            Some(11),
        );
        self.artifact = replace(
            &self.artifact,
            "Artifact",
            &[(
                10,
                b(&digest(
                    "certificate_digest",
                    &self.server,
                    "IdentityCertificate",
                )),
            )],
            Some(12),
        );
        self.refresh_activation();
    }
    /// Recovery fixtures carry issuer-signed policy and renegotiate their
    /// original transcript; tests never switch an admitted engine's flags.
    pub(crate) fn enable_execution_recovery(&mut self) {
        let artifact = map(&self.artifact, "Artifact");
        let contract = artifact.field("Artifact", "session_contract").unwrap();
        // Execution Sessions reserve eleven original internal channels before
        // admitting business streams; recovery tests also keep raw targets open.
        let contract = replace(
            contract.raw(),
            "SessionContract",
            &[(1, u(32)), (2, u(262_144)), (5, u(2)), (6, u(16))],
            None,
        );
        let recovery = encode_map(&[
            (0, vec![0xf5]),
            (1, u(0)),
            (2, u(0)),
            (3, u(10_000)),
            (4, u(4980)),
        ]);
        self.artifact = replace(
            &self.artifact,
            "Artifact",
            &[(13, contract), (14, u(2)), (15, u(2)), (16, recovery)],
            Some(12),
        );
        self.refresh_activation();
    }
    pub(crate) fn set_max_credit(&mut self, maximum: u64) {
        let artifact = map(&self.artifact, "Artifact");
        let contract = artifact.field("Artifact", "session_contract").unwrap();
        let contract = replace(contract.raw(), "SessionContract", &[(2, u(maximum))], None);
        self.artifact = replace(&self.artifact, "Artifact", &[(13, contract)], Some(12));
        self.refresh_activation();
    }
    pub(crate) fn set_wss_route(&mut self, port: u16, pin: Option<[u8; 32]>) {
        let artifact = map(&self.artifact, "Artifact");
        let candidate = artifact
            .field("Artifact", "candidates")
            .unwrap()
            .at(0)
            .unwrap();
        let original = candidate.field("Candidate", "direct_leg").unwrap();
        let tls = pin.map_or_else(
            || encode_map(&[(0, u(0)), (1, vec![0xf5])]),
            |digest| {
                encode_map(&[
                    (0, u(1)),
                    (1, vec![0xf5]),
                    (2, u(0)),
                    (
                        3,
                        array(&[encode_map(&[
                            (0, b(&digest)),
                            (1, u(0)),
                            (2, u(80_000)),
                            (3, t("x509v3-p256-14d")),
                        ])]),
                    ),
                ])
            },
        );
        let mut children = original.children().unwrap();
        let mut fields = Vec::new();
        while let Some(id) = children.next() {
            let id = id.unwrap().uint().unwrap();
            let value = children.next().unwrap().unwrap();
            fields.push((
                id,
                match id {
                    7 => u(u64::from(port)),
                    11 => tls.clone(),
                    _ => value.raw().to_vec(),
                },
            ));
        }
        let candidate = replace(
            candidate.raw(),
            "Candidate",
            &[(3, encode_map(&fields))],
            None,
        );
        let contract = artifact.field("Artifact", "session_contract").unwrap();
        let contract = replace(contract.raw(), "SessionContract", &[(0, u(65536))], None);
        self.artifact = replace(
            &self.artifact,
            "Artifact",
            &[(12, array(&[candidate])), (13, contract)],
            Some(12),
        );
        self.refresh_activation();
    }
    fn refresh_activation(&mut self) {
        let artifact = map(&self.artifact, "Artifact");
        let artifact_digest = codec::digest("artifact_digest", artifact).unwrap();
        let candidate = artifact
            .field("Artifact", "candidates")
            .unwrap()
            .at(0)
            .unwrap();
        let mut scratch = Vec::with_capacity(ARTIFACT_BYTES);
        let route = route_digest(candidate, &mut scratch).unwrap();
        let (selection, route_selection) = match self.source {
            ActivationSource::LiveAuthority => (b(&[20; 16]), route),
            ActivationSource::PreauthorizedPool => {
                let set = encode_map(&[
                    (0, b(&artifact_digest)),
                    (
                        1,
                        array(&[encode_map(&[(0, u(0)), (1, b(&[20; 16])), (2, b(&route))])]),
                    ),
                ]);
                let once = map(&self.trust, "TrustConfig")
                    .field("TrustConfig", "once_authorities")
                    .unwrap()
                    .at(0)
                    .unwrap()
                    .raw()
                    .to_vec();
                let budget = encode_map(&[
                    (0, encode_map(&[(0, u(8)), (1, u(262_144)), (2, u(256))])),
                    (1, u(32)),
                    (2, u(8 << 20)),
                    (3, u(8192)),
                    (4, u(2)),
                ]);
                (
                    encode_map(&[
                        (0, b(&artifact_digest)),
                        (1, array(&[u(0)])),
                        (
                            2,
                            b(&digest("candidate_set_digest", &set, "PoolSelectionSet")),
                        ),
                        (3, budget),
                        (4, once),
                    ]),
                    digest("route_set_digest", &set, "PoolSelectionSet"),
                )
            }
        };
        self.activation = sign(
            "ActivationAuthorization",
            &[
                (0, u(1)),
                (1, t("spend")),
                (2, t("activate-1")),
                (3, t("tenant")),
                (4, b(&[5; 16])),
                (5, b(&[22; 16])),
                (6, b(&artifact_digest)),
                (7, selection),
                (8, b(&route_selection)),
                (9, b(&[25; 16])),
                (
                    10,
                    b(&bytes::<32>(artifact, "Artifact", "client_identity_digest").unwrap()),
                ),
                (
                    11,
                    b(&bytes::<32>(artifact, "Artifact", "server_identity_digest").unwrap()),
                ),
                (12, t("service")),
                (13, u(950)),
                (14, u(10_000)),
                (15, u(30_000)),
            ],
            &signer(13),
        );
    }
    pub(crate) fn reserve(&self) -> Result<CredentialAdmission, EnvironmentError> {
        self.environment.reserve_direct_credentials(
            &[&self.verifier],
            DirectCredentialInput {
                artifact: &self.artifact,
                client_certificate: &self.client,
                server_certificate: &self.server,
                activation: &self.activation,
                source: self.source,
                candidate_index: 0,
            },
        )
    }
    fn reject(&self) {
        let before = self.environment.resource_usage();
        assert!(self.reserve().is_err());
        assert_eq!(self.environment.resource_usage(), before);
    }
}

#[test]
fn real_live_and_pool_credentials_reserve_the_original_environment() {
    for source in [
        ActivationSource::LiveAuthority,
        ActivationSource::PreauthorizedPool,
    ] {
        let fixture = Fixture::new(source);
        let before = fixture.environment.resource_usage();
        let admission = fixture.reserve().unwrap();
        assert_eq!(
            admission.artifact_digest,
            digest("artifact_digest", &fixture.artifact, "Artifact")
        );
        assert_eq!(
            admission.certificate_digests,
            [
                digest("certificate_digest", &fixture.client, "IdentityCertificate"),
                digest("certificate_digest", &fixture.server, "IdentityCertificate")
            ]
        );
        assert_eq!(admission.candidate_id, [20; 16]);
        assert_eq!(admission.attempt_id, [25; 16]);
        assert_eq!(admission.initiation_not_after_ms, 10_000);
        assert_ne!(admission.route_digest, [0; 32]);
        assert_ne!(admission.activation_digest, [0; 32]);
        assert!(matches!(
            (admission.source, source),
            (
                ActivationSource::LiveAuthority,
                ActivationSource::LiveAuthority
            ) | (
                ActivationSource::PreauthorizedPool,
                ActivationSource::PreauthorizedPool
            )
        ));
        admission.account.check().unwrap();
        assert_eq!(
            fixture.environment.resource_usage().sessions,
            before.sessions + 1
        );
        drop(admission);
        assert_eq!(fixture.environment.resource_usage(), before);
    }
}

#[test]
fn valid_signatures_do_not_replace_original_permission_or_parent_bounds() {
    let mut fixture = Fixture::new(ActivationSource::LiveAuthority);
    let original_artifact = fixture.artifact.clone();
    for changes in [
        vec![(23, u(9))],
        vec![(20, u(120_000))],
        vec![(25, u(2))],
        vec![(11, t("other-service"))],
    ] {
        fixture.artifact = replace(&original_artifact, "Artifact", &changes, Some(12));
        fixture.refresh_activation();
        fixture.reject();
    }
    fixture.artifact = original_artifact;
    let original_client = fixture.client.clone();
    for changes in [
        vec![(1, t("other-client"))],
        vec![(12, u(9))],
        vec![(9, u(120_000))],
        vec![(4, b(&[0; 32]))],
    ] {
        fixture.client = replace(&original_client, "IdentityCertificate", &changes, Some(11));
        fixture.artifact = replace(
            &fixture.artifact,
            "Artifact",
            &[(
                9,
                b(&digest(
                    "certificate_digest",
                    &fixture.client,
                    "IdentityCertificate",
                )),
            )],
            Some(12),
        );
        fixture.refresh_activation();
        fixture.reject();
    }
}

#[test]
fn activation_and_signature_failures_never_allocate_an_account() {
    let mut fixture = Fixture::new(ActivationSource::LiveAuthority);
    let original = fixture.activation.clone();
    for changes in [
        vec![(1, t("wrong-authority"))],
        vec![(7, b(&[99; 16]))],
        vec![(8, b(&[99; 32]))],
        vec![(13, u(700))],
        vec![(14, u(21_000))],
        vec![(15, u(41_000))],
    ] {
        fixture.activation = replace(&original, "ActivationAuthorization", &changes, Some(13));
        fixture.reject();
    }
    fixture.activation = original;
    for target in 0..4 {
        let bytes = match target {
            0 => &mut fixture.artifact,
            1 => &mut fixture.client,
            2 => &mut fixture.server,
            _ => &mut fixture.activation,
        };
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fixture.reject();
        let bytes = match target {
            0 => &mut fixture.artifact,
            1 => &mut fixture.client,
            2 => &mut fixture.server,
            _ => &mut fixture.activation,
        };
        bytes[last] ^= 1;
    }
}

#[test]
fn independent_trust_retirement_closes_the_original_artifact_issuer_gate() {
    let mut fixture = Fixture::new(ActivationSource::LiveAuthority);
    let admission = fixture.reserve().unwrap();
    fixture.trust = replace(
        &fixture.trust,
        "TrustConfig",
        &[(4, u(2)), (5, u(900)), (14, array(&[b(&[5; 16])]))],
        Some(7),
    );
    fixture
        .verifier
        .refresh(Some(&fixture.trust), &fixture.head, &fixture.state)
        .unwrap();
    assert_eq!(admission.account.check(), Err(EnvironmentError::Closed));
    fixture.reject();
}

#[test]
fn namespace_closure_and_material_source_are_exact() {
    let mut fixture = Fixture::new(ActivationSource::LiveAuthority);
    fixture.source = ActivationSource::PreauthorizedPool;
    fixture.reject();
    fixture.source = ActivationSource::LiveAuthority;
    let candidate = map(&fixture.artifact, "Artifact")
        .field("Artifact", "candidates")
        .unwrap()
        .at(0)
        .unwrap()
        .raw()
        .to_vec();
    let original_ref = map(&candidate, "Candidate")
        .field("Candidate", "revocation_namespace_refs")
        .unwrap()
        .at(0)
        .unwrap()
        .raw()
        .to_vec();
    let altered_ref = replace(&original_ref, "RevocationNamespaceRef", &[(4, u(1))], None);
    let candidate = replace(&candidate, "Candidate", &[(6, array(&[altered_ref]))], None);
    fixture.artifact = replace(
        &fixture.artifact,
        "Artifact",
        &[(12, array(&[candidate]))],
        Some(12),
    );
    fixture.refresh_activation();
    fixture.reject();
}

#[test]
fn live_configuration_resolves_original_certificates_and_signer_before_issuance() {
    let fixture = Fixture::new(ActivationSource::LiveAuthority);
    let before = fixture.environment.resource_usage();
    let digests = verify_live_source_configuration(
        fixture.environment.root(),
        &[&fixture.verifier],
        [&fixture.client, &fixture.server],
        [5; 16],
        "activate-1",
    )
    .unwrap();
    assert_eq!(
        digests[0],
        digest("certificate_digest", &fixture.client, "IdentityCertificate")
    );
    assert_eq!(
        digests[1],
        digest("certificate_digest", &fixture.server, "IdentityCertificate")
    );
    assert_eq!(fixture.environment.resource_usage(), before);
    assert!(
        verify_live_source_configuration(
            fixture.environment.root(),
            &[&fixture.verifier],
            [&fixture.client, &fixture.server],
            [5; 16],
            "unconfigured-signer"
        )
        .is_err()
    );
    assert_eq!(fixture.environment.resource_usage(), before);
}
#[test]
fn prepared_live_direct_installs_proof_on_original_account_and_only_tightens_horizon() {
    let fixture = Fixture::new(ActivationSource::LiveAuthority);
    let pending = reserve_live_direct_preparation(
        fixture.environment.root(),
        &[&fixture.verifier],
        DirectCredentialInput {
            artifact: &fixture.artifact,
            client_certificate: &fixture.client,
            server_certificate: &fixture.server,
            activation: &[],
            source: ActivationSource::LiveAuthority,
            candidate_index: 0,
        },
        [25; 16],
        "activate-1",
    )
    .unwrap();
    let original = pending.account.clone();
    let original_usage = fixture.environment.resource_usage();
    let admission = pending
        .complete(
            fixture.environment.root(),
            &[&fixture.verifier],
            &fixture.artifact,
            &fixture.activation,
        )
        .unwrap();
    assert!(admission.account.same_owner(&original));
    assert_eq!(admission.source, ActivationSource::LiveAuthority);
    assert!(admission.pool.is_none());
    assert!(admission.pool_activation.is_none());
    assert_eq!(admission.attempt_id, [25; 16]);
    assert_eq!(
        admission.activation_digest,
        digest(
            "activation_digest",
            &fixture.activation,
            "ActivationAuthorization"
        )
    );
    assert_eq!(
        fixture.environment.resource_usage().sessions,
        original_usage.sessions
    );
    admission.account.check().unwrap();
}
#[test]
fn live_proof_refuses_other_attempt_route_and_unconfigured_signer_without_new_account() {
    let fixture = Fixture::new(ActivationSource::LiveAuthority);
    for change in [
        (9, b(&[26; 16])),
        (8, b(&[27; 32])),
        (2, t("another-signer")),
    ] {
        let before = fixture.environment.resource_usage();
        let pending = reserve_live_direct_preparation(
            fixture.environment.root(),
            &[&fixture.verifier],
            DirectCredentialInput {
                artifact: &fixture.artifact,
                client_certificate: &fixture.client,
                server_certificate: &fixture.server,
                activation: &[],
                source: ActivationSource::LiveAuthority,
                candidate_index: 0,
            },
            [25; 16],
            "activate-1",
        )
        .unwrap();
        let proof = replace(
            &fixture.activation,
            "ActivationAuthorization",
            &[change],
            Some(13),
        );
        assert_eq!(
            pending
                .complete(
                    fixture.environment.root(),
                    &[&fixture.verifier],
                    &fixture.artifact,
                    &proof
                )
                .unwrap_err(),
            EnvironmentError::AuthorizationDenied
        );
        assert_eq!(fixture.environment.resource_usage(), before);
    }
}
