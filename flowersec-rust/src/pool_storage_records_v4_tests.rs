use super::*;
use crate::codec_v4::tests::{array as encoded_array, b, encode_map, hex, t, u};
use crate::namespace_v4::verifier::credential::tests::Fixture;

fn seed(id: &str) -> Vec<u8> {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../testdata/transport_v4/corpus.json")).unwrap();
    hex(corpus["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == id)
        .unwrap()["hex"]
        .as_str()
        .unwrap())
}

fn replace(raw: &[u8], schema: &str, changes: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let schemas: serde_json::Value =
        serde_json::from_str(include_str!("../../stability/transport_v4_schema.json")).unwrap();
    let fields = schemas["frame_maps"][schema]["fields"].as_object().unwrap();
    let value = codec::decode_storage_map(
        raw,
        Limits {
            bytes: 65536,
            nodes: 16384,
        },
    )
    .unwrap();
    let mut children = value.children().unwrap();
    let mut output = Vec::new();
    while let Some(key) = children.next() {
        let id = key.unwrap().uint().unwrap();
        let value = children.next().unwrap().unwrap();
        let name = fields[&id.to_string()]["name"].as_str().unwrap();
        output.push((
            id,
            changes
                .iter()
                .find(|(field, _)| *field == name)
                .map_or_else(|| value.raw().to_vec(), |(_, wire)| wire.clone()),
        ));
    }
    encode_map(&output)
}

// These remain storage-only fixtures. The retained bytes are canonical and
// internally consistent; they do not claim independent signature provenance.
pub(crate) fn relay_publication(
    f: &Fixture,
    binding: &relay::SQLiteRelayBinding,
) -> (Vec<u8>, Vec<u8>) {
    let admission = f.reserve().unwrap();
    let pool = admission.pool.as_ref().unwrap();
    let artifact = decode(&f.artifact, "Artifact", None).unwrap();
    let original = proof(&f.activation, ActivationSource::PreauthorizedPool).unwrap();
    let candidate_bytes = replace(
        &seed("candidate_tunnel_fields"),
        "Candidate",
        &[("candidate_id", b(&admission.candidate_id))],
    );
    let candidate = decode(&candidate_bytes, "Candidate", None).unwrap();
    let route_wire = encode_map(&[
        (0, u(1)),
        (1, b(&admission.candidate_id)),
        (
            3,
            candidate
                .field("Candidate", "client_leg")
                .unwrap()
                .raw()
                .to_vec(),
        ),
        (
            4,
            candidate
                .field("Candidate", "server_leg")
                .unwrap()
                .raw()
                .to_vec(),
        ),
    ]);
    let route = decode(&route_wire, "Route", None).unwrap();
    let route_digest = codec::digest("route_digest", route).unwrap();
    let set_wire = encode_map(&[
        (0, b(&admission.artifact_digest)),
        (
            1,
            encoded_array(&[encode_map(&[
                (0, u(0)),
                (1, b(&admission.candidate_id)),
                (2, b(&route_digest)),
            ])]),
        ),
    ]);
    let set = decode(&set_wire, "PoolSelectionSet", None).unwrap();
    let selection = replace(
        original
            .field("ActivationAuthorization", "candidate_selection")
            .unwrap()
            .raw(),
        "PoolSelectionRef",
        &[
            (
                "candidate_set_digest",
                b(&codec::digest("candidate_set_digest", set).unwrap()),
            ),
            ("candidate_indices", encoded_array(&[u(0)])),
        ],
    );
    let activation = replace(
        &f.activation,
        "ActivationAuthorization",
        &[
            ("candidate_selection", selection),
            (
                "route_selection",
                b(&codec::digest("route_set_digest", set).unwrap()),
            ),
        ],
    );
    let p = proof(&activation, ActivationSource::PreauthorizedPool).unwrap();
    let activation_digest = codec::digest("activation_digest", p).unwrap();
    let relay_certificate = replace(
        &f.server,
        "IdentityCertificate",
        &[("role", u(2)), ("audience", t(&binding.relay_audience))],
    );
    let relay_digest = codec::digest(
        "certificate_digest",
        decode(&relay_certificate, "IdentityCertificate", None).unwrap(),
    )
    .unwrap();
    let seed_grant = seed("grant_fields");
    let grant = decode(&seed_grant, "Grant", None).unwrap();
    let mut parent_fields = Vec::new();
    for name in [
        "tenant_id",
        "revocation_authority_id",
        "namespace_capacity_digest",
        "revocation_policy_id",
        "revocation_policy_revision",
        "lease_id",
        "revocation_epoch",
        "issued_at_ms",
        "initiation_not_after_ms",
        "session_not_after_ms",
    ] {
        parent_fields.push((
            name,
            artifact.field("Artifact", name).unwrap().raw().to_vec(),
        ));
    }
    parent_fields.push((
        "authority_generation",
        artifact
            .field("Artifact", "revocation_authority_generation")
            .unwrap()
            .raw()
            .to_vec(),
    ));
    parent_fields.push(("artifact_issuer_key_id", b(&pool.issuer)));
    parent_fields.push(("artifact_digest", b(&admission.artifact_digest)));
    let parent = replace(
        grant.field("Grant", "parent_ref").unwrap().raw(),
        "GrantParentRef",
        &parent_fields,
    );
    let contract = artifact.field("Artifact", "session_contract").unwrap();
    let legs = encoded_array(&[
        encode_map(&[
            (
                0,
                b(&route
                    .field("Route", "client_leg")
                    .unwrap()
                    .b::<16>("Leg", "leg_id")
                    .unwrap()),
            ),
            (1, u(0)),
        ]),
        encode_map(&[
            (
                0,
                b(&route
                    .field("Route", "server_leg")
                    .unwrap()
                    .b::<16>("Leg", "leg_id")
                    .unwrap()),
            ),
            (1, u(1)),
        ]),
    ]);
    let mut grants = [Vec::new(), Vec::new()];
    let limits = replace(
        grant.field("Grant", "limits").unwrap().raw(),
        "GrantLimits",
        &[(
            "max_envelope_bytes",
            u(contract.u("SessionContract", "max_frame").unwrap() + 8),
        )],
    );
    for (side, wire) in grants.iter_mut().enumerate() {
        let namespace = replace(
            grant.field("Grant", "namespace").unwrap().raw(),
            "GrantNamespace",
            &[
                ("tenant_id", t(&pool.tenant)),
                ("role_mask", u(4 | (1 << side))),
            ],
        );
        *wire = replace(
            &seed_grant,
            "Grant",
            &[
                ("tenant_id", t(&pool.tenant)),
                ("parent_ref", parent.clone()),
                ("route_descriptor", route_wire.clone()),
                ("route_digest", b(&route_digest)),
                ("attempt_id", b(&admission.attempt_id)),
                (
                    "identity_digests",
                    encoded_array(&[
                        b(&admission.certificate_digests[0]),
                        b(&admission.certificate_digests[1]),
                    ]),
                ),
                ("legs", legs.clone()),
                ("limits", limits.clone()),
                ("service", t(&binding.service)),
                ("audience", t(&binding.relay_audience)),
                ("namespace", namespace),
                ("issued_at_ms", u(pool.issued_at)),
                ("not_after_ms", u(pool.session_end)),
                (
                    "session_contract_digest",
                    b(&codec::digest("session_contract_digest", contract).unwrap()),
                ),
                ("relay_identity_digest", b(&relay_digest)),
            ],
        );
    }
    let publication = encoded_array(&[
        t("flowersec/rust-relay-pool-publication/2"),
        b(&activation),
        b(&grants[0]),
        b(&grants[1]),
        b(&f.client),
        b(&f.server),
        b(&relay_certificate),
        b(&candidate_bytes),
        b(&set_wire),
        b(contract.raw()),
        b(&[0]),
    ]);
    let winner = parent::ParentWinnerSelection {
        source: ActivationSource::PreauthorizedPool,
        tenant: &pool.tenant,
        authority: &pool.winner_authority,
        server_authority: &binding.server_admission_authority,
        audience: p
            .field("ActivationAuthorization", "audience")
            .unwrap()
            .text()
            .unwrap(),
        artifact: admission.artifact_digest,
        activation: activation_digest,
        proof: &activation,
        candidate: admission.candidate_id,
        route: route_digest,
        attempt: admission.attempt_id,
        identities: admission.certificate_digests,
        parent_initiation_end: pool.parent_initiation_end,
        parent_session_end: artifact.u("Artifact", "session_not_after_ms").unwrap(),
    }
    .encode(8192)
    .unwrap();
    (publication, winner)
}

pub(crate) fn relay_evidence(publication: &[u8], role: u8, carrier: u8) -> Vec<u8> {
    let f = array::<11>(publication, 65536).unwrap();
    let grant = decode(f[2 + usize::from(role)].bytes().unwrap(), "Grant", None).unwrap();
    let route = grant.field("Grant", "route_descriptor").unwrap();
    let leg = route
        .field(
            "Route",
            if role == 0 {
                "client_leg"
            } else {
                "server_leg"
            },
        )
        .unwrap();
    let dialer = leg.u("Leg", "dialer_role").unwrap();
    let listener = leg.u("Leg", "listener_role").unwrap();
    let context = encode_map(&[
        (0, b(&[if dialer == 2 { carrier } else { 99 }; 16])),
        (1, b(&[if listener == 2 { carrier } else { 99 }; 16])),
        (2, b(&leg.b::<16>("Leg", "leg_id").unwrap())),
        (3, u(dialer)),
        (4, u(listener)),
        (5, b(&[9; 32])),
        (6, b(&[8; 32])),
    ]);
    let digest = codec::digest("grant_digest", grant).unwrap();
    encoded_array(&[
        b(&digest),
        b(&codec::digest("route_digest", route).unwrap()),
        b(&context),
        b(&[7; 64]),
    ])
}

pub(crate) fn alter_map(wire: &[u8], field: u64, replacement: Vec<u8>) -> Vec<u8> {
    let map = codec::decode_storage_map(
        wire,
        Limits {
            bytes: 65536,
            nodes: 4096,
        },
    )
    .unwrap();
    let mut children = map.children().unwrap();
    let mut fields = Vec::new();
    while let Some(key) = children.next() {
        let key = key.unwrap().uint().unwrap();
        let value = children.next().unwrap().unwrap();
        fields.push((
            key,
            if key == field {
                replacement.clone()
            } else {
                value.raw().to_vec()
            },
        ));
    }
    encode_map(&fields)
}

pub(crate) fn alter_array(wire: &[u8], field: usize, replacement: Vec<u8>) -> Vec<u8> {
    let value = codec::decode_control_array(
        wire,
        Limits {
            bytes: 65536,
            nodes: 4096,
        },
    )
    .unwrap();
    encoded_array(
        &value
            .children()
            .unwrap()
            .enumerate()
            .map(|(index, value)| {
                if index == field {
                    replacement.clone()
                } else {
                    value.unwrap().raw().to_vec()
                }
            })
            .collect::<Vec<_>>(),
    )
}
