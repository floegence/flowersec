//! Composition tests share the independent receiver and corpus helpers.
use super::*;
use oracles::PoolProjection;

fn seed_bytes(id: &str) -> Vec<u8> {
    bytes(seed(id)["hex"].as_str().unwrap())
}

// v4.rust_composition.metadata_corpus
#[test]
fn metadata_corpus_and_independent_composition() {
    let r = reference();
    let definition = seed_bytes("typed_definition_fields");
    let (mut positive, mut negative, mut bound) = (0, 0, 0);
    for vector in corpus().iter().filter(|v| {
        matches!(
            v["schema"].as_str(),
            Some("StreamMetadata" | "TypedMessageMetadata")
        )
    }) {
        let input = bytes(vector["hex"].as_str().unwrap());
        let parsed = r.stream_metadata(&input, input.len() as u64 + 1);
        if vector.get("expected_error").is_some() {
            negative += 1;
            if let Ok(Some((name, _))) = parsed {
                assert_ne!(name, "TypedMessageMetadata", "{}", vector["id"]);
                assert_eq!(vector["schema"], "TypedMessageMetadata");
                assert!(r.verify_typed_metadata(&input, &definition, 8192).is_err());
            } else {
                assert!(parsed.is_err(), "{}", vector["id"]);
            }
        } else {
            positive += 1;
            let (name, value) = parsed
                .unwrap_or_else(|e| panic!("{}: {e}", vector["id"]))
                .unwrap();
            assert_eq!(name, vector["schema"]);
            assert_eq!(encoded(&value), input);
            if let Some(derivation) = vector.get("typed_derivation") {
                bound += 1;
                let definition = bytes(derivation["definition_hex"].as_str().unwrap());
                let application = bytes(derivation["application_hex"].as_str().unwrap());
                assert_eq!(
                    r.compose_typed_metadata(&definition, &application, 8192)
                        .unwrap(),
                    input
                );
                assert_eq!(
                    r.verify_typed_metadata(&input, &definition, 8192).unwrap(),
                    application
                );
            }
        }
    }
    assert!(positive > 0 && negative > 0);
    assert_eq!(bound, 2);
}

// v4.rust_composition.metadata_boundaries
#[test]
fn metadata_caps_required_shell_and_owned_bytes() {
    let r = reference();
    let definition = seed_bytes("typed_definition_fields");
    assert_eq!(r.stream_metadata(&[], 4096), Ok(None));
    assert_eq!(r.stream_metadata(&[], 0), Err("limit_unresolved"));
    for mut application in [
        vec![],
        seed_bytes("metadata_empty_values"),
        seed_bytes("metadata_4006"),
    ] {
        let original = application.clone();
        let mut wrapped = r
            .compose_typed_metadata(&definition, &application, 8192)
            .unwrap();
        if application.is_empty() {
            assert_eq!(wrapped.len(), 88);
        }
        if application.len() == 4006 {
            assert_eq!(wrapped.len(), 4096);
        }
        // The shared per-object cap also has to admit the local definition.
        let exact_cap = wrapped.len().max(definition.len()) as u64;
        assert_eq!(
            r.compose_typed_metadata(&definition, &application, exact_cap)
                .unwrap(),
            wrapped
        );
        assert!(
            r.compose_typed_metadata(&definition, &application, exact_cap - 1)
                .is_err()
        );
        let mut returned = r
            .verify_typed_metadata(&wrapped, &definition, 8192)
            .unwrap();
        assert_eq!(returned, original);
        returned.fill(0);
        assert_eq!(application, original);
        application.fill(0);
        let returned = r
            .verify_typed_metadata(&wrapped, &definition, 8192)
            .unwrap();
        wrapped.fill(0);
        assert_eq!(returned, original);
    }
    for id in ["metadata_4007", "metadata_4096"] {
        let application = seed_bytes(id);
        assert!(r.stream_metadata(&application, 4096).is_ok());
        assert!(
            r.compose_typed_metadata(&definition, &application, 8192)
                .is_err()
        );
    }
    assert!(
        r.compose_typed_metadata(&definition, &seed_bytes("typed_metadata_empty"), 8192)
            .is_err()
    );
    for input in [vec![], seed_bytes("metadata_empty_values")] {
        assert_eq!(
            r.verify_typed_metadata(&input, &definition, 8192),
            Err("typed_metadata_required")
        );
    }
    assert_eq!(
        r.verify_typed_metadata(
            &seed_bytes("typed_metadata_bound_empty"),
            &seed_bytes("typed_definition_maximum"),
            8192
        ),
        Err("typed_definition_mismatch")
    );
}

// v4.rust_composition.definition_binding
#[test]
fn every_definition_direction_field_is_bound() {
    let r = reference();
    let definition = seed_bytes("typed_definition_fields");
    let wrapped = r.compose_typed_metadata(&definition, &[], 8192).unwrap();
    for path in [
        "kind",
        "revision",
        "opener_to_acceptor.codec_schema_digest",
        "opener_to_acceptor.codec_revision",
        "opener_to_acceptor.max_message_bytes",
        "acceptor_to_opener.codec_schema_digest",
        "acceptor_to_opener.codec_revision",
        "acceptor_to_opener.max_message_bytes",
        "swap_directions",
    ] {
        let mut value = r
            .wire_map(
                &definition,
                "MessageStreamDefinition",
                &Context::default(),
                8192,
            )
            .unwrap();
        let mut data = Vec::new();
        let mut text = String::new();
        if path == "swap_directions" {
            let left =
                field_mut("MessageStreamDefinition", &mut value, "opener_to_acceptor").clone();
            let right =
                field_mut("MessageStreamDefinition", &mut value, "acceptor_to_opener").clone();
            *field_mut("MessageStreamDefinition", &mut value, "opener_to_acceptor") = right;
            *field_mut("MessageStreamDefinition", &mut value, "acceptor_to_opener") = left;
        } else {
            let slot = if let Some((direction, field)) = path.split_once('.') {
                field_mut(
                    "MessageStreamDirection",
                    field_mut("MessageStreamDefinition", &mut value, direction),
                    field,
                )
            } else {
                field_mut("MessageStreamDefinition", &mut value, path)
            };
            match slot {
                Value::Unsigned(n) => *n -= 1,
                Value::Bytes(raw) => {
                    data.extend_from_slice(raw);
                    data[0] ^= 1;
                    *slot = Value::Bytes(&data);
                }
                Value::Text(raw) => {
                    text.push_str(raw);
                    text.push('x');
                    *slot = Value::Text(&text);
                }
                _ => panic!(),
            }
        }
        let changed = encoded(&value);
        assert!(
            r.wire_map(
                &changed,
                "MessageStreamDefinition",
                &Context::default(),
                8192
            )
            .is_ok()
        );
        assert_eq!(
            r.verify_typed_metadata(&wrapped, &changed, 8192),
            Err("typed_definition_mismatch"),
            "{path}"
        );
    }
}

// v4.rust_composition.metadata_scope
#[test]
fn invalid_inner_metadata_remains_separate_from_outer_open() {
    let r = reference();
    let vector = seed("open_fields");
    let input = seed_bytes("open_fields");
    for id in [
        "metadata_bad_namespace_0",
        "metadata_value_wrong_type",
        "typed_metadata_nested_wrapper",
        "typed_metadata_missing_application",
    ] {
        let mut value = receive(&input, vector).unwrap();
        let metadata = seed_bytes(id);
        *field_mut("OPEN_STREAM", &mut value, "metadata") = Value::Bytes(&metadata);
        let digest = r.shape.open_digest(&value).unwrap();
        *field_mut("OPEN_STREAM", &mut value, "open_digest") = Value::Bytes(&digest);
        assert!(receive(&encoded(&value), vector).is_ok());
        assert!(r.stream_metadata(&metadata, 4096).is_err());
    }
}

struct Material {
    artifact: Vec<u8>,
    fsb: Vec<u8>,
    reference: Vec<u8>,
    selection: PoolProjection,
    context: Context,
}

fn material(indices: &[u64], high_times: bool) -> Material {
    let r = reference();
    let original_artifact = seed_bytes("artifact_transport_fields");
    let mut artifact = r
        .wire_map(&original_artifact, "Artifact", &Context::default(), 1 << 16)
        .unwrap();
    if high_times {
        for (field, value) in [
            ("issued_at_ms", u64::MAX - 2),
            ("initiation_not_after_ms", u64::MAX - 1),
            ("session_not_after_ms", u64::MAX),
        ] {
            *field_mut("Artifact", &mut artifact, field) = Value::Unsigned(value);
        }
    }
    let artifact_bytes = encoded(&artifact);
    let selection = r.derive_pool(&artifact_bytes, indices, 1 << 16).unwrap();
    let proof_bytes = seed_bytes("activation_pool_fields");
    let mut proof = r
        .wire_map(
            &proof_bytes,
            "ActivationAuthorization",
            &context(seed("activation_pool_fields")),
            1 << 16,
        )
        .unwrap();
    if high_times {
        for (field, value) in [
            ("issued_at_ms", u64::MAX - 2),
            ("activation_not_after_ms", u64::MAX - 1),
            ("session_not_after_ms", u64::MAX),
        ] {
            *field_mut("ActivationAuthorization", &mut proof, field) = Value::Unsigned(value);
        }
    }
    let reference = field_mut("ActivationAuthorization", &mut proof, "candidate_selection");
    *field_mut("PoolSelectionRef", reference, "artifact_digest") =
        Value::Bytes(&selection.artifact_digest);
    *field_mut("PoolSelectionRef", reference, "candidate_set_digest") =
        Value::Bytes(&selection.candidate_set_digest);
    *field_mut("PoolSelectionRef", reference, "candidate_indices") =
        Value::Array(indices.iter().map(|&n| Value::Unsigned(n)).collect());
    let reference_bytes = encoded(reference);
    *field_mut("ActivationAuthorization", &mut proof, "artifact_digest") =
        Value::Bytes(&selection.artifact_digest);
    *field_mut("ActivationAuthorization", &mut proof, "route_selection") =
        Value::Bytes(&selection.route_set_digest);
    for field in [
        "client_identity_digest",
        "server_identity_digest",
        "audience",
    ] {
        *field_mut("ActivationAuthorization", &mut proof, field) = r
            .shape
            .required_value("Artifact", &artifact, field)
            .unwrap()
            .clone();
    }
    let proof_bytes = encoded(&proof);
    let original_fsb = seed_bytes("fsb_fields");
    let mut fsb = r
        .wire_map(&original_fsb, "FSB4", &context(seed("fsb_fields")), 1 << 16)
        .unwrap();
    *field_mut("FSB4", &mut fsb, "artifact_digest") = Value::Bytes(&selection.artifact_digest);
    *field_mut("FSB4", &mut fsb, "session_nonce") = r
        .shape
        .required_value("Artifact", &artifact, "session_nonce")
        .unwrap()
        .clone();
    *field_mut("FSB4", &mut fsb, "candidate_id") = Value::Bytes(&selection.members[0].candidate_id);
    *field_mut("FSB4", &mut fsb, "route_digest") = Value::Bytes(&selection.members[0].route_digest);
    *field_mut("FSB4", &mut fsb, "activation_authorization") = Value::Bytes(&proof_bytes);
    let fsb = encoded(&fsb);
    let mut context = Context::default();
    context.selectors.insert(
        "activation_source_profile".into(),
        "preauthorized_pool".into(),
    );
    Material {
        artifact: artifact_bytes,
        fsb,
        reference: reference_bytes,
        selection,
        context,
    }
}

// v4.rust_composition.pool_reference
#[test]
fn pool_reference_binds_original_artifact_indices_and_domains() {
    let r = reference();
    let m = material(&[0, 1], false);
    assert_eq!(
        r.verify_pool_reference(&m.artifact, &m.reference, 1 << 16)
            .unwrap(),
        m.selection
    );
    let mut artifact = r
        .wire_map(&m.artifact, "Artifact", &Context::default(), 1 << 16)
        .unwrap();
    let signature = [99; 64];
    *field_mut("Artifact", &mut artifact, "signature") = Value::Bytes(&signature);
    assert_eq!(
        r.verify_pool_reference(&encoded(&artifact), &m.reference, 1 << 16),
        Err("pool_artifact_digest")
    );
    let mut value = r
        .wire_map(
            &m.reference,
            "PoolSelectionRef",
            &Context::default(),
            1 << 16,
        )
        .unwrap();
    *field_mut("PoolSelectionRef", &mut value, "candidate_indices") =
        Value::Array(vec![Value::Unsigned(0)]);
    assert_eq!(
        r.verify_pool_reference(&m.artifact, &encoded(&value), 1 << 16),
        Err("pool_candidate_set_digest")
    );
    let single = r.derive_pool(&m.artifact, &[0], 1 << 16).unwrap();
    *field_mut("PoolSelectionRef", &mut value, "candidate_set_digest") =
        Value::Bytes(&single.route_set_digest);
    assert_eq!(
        r.verify_pool_reference(&m.artifact, &encoded(&value), 1 << 16),
        Err("pool_candidate_set_digest")
    );
}

// v4.rust_composition.pool_winner
#[test]
fn pool_proof_matches_source_identity_deadlines_and_paired_winner() {
    let r = reference();
    let m = material(&[0, 1], false);
    let before = m.context.selectors.clone();
    assert_eq!(
        r.pool_authorization_projection(&m.artifact, &m.fsb, &m.context, 1 << 16)
            .unwrap(),
        m.selection
    );
    assert_eq!(m.context.selectors, before);
    let mut wrong = m.context.clone();
    wrong
        .selectors
        .insert("activation_source_profile".into(), "live_authority".into());
    for context in [Context::default(), wrong] {
        assert_eq!(
            r.pool_authorization_projection(&m.artifact, &m.fsb, &context, 1 << 16),
            Err("pool_source_profile")
        );
    }
    let mut wrong = m.context.clone();
    wrong
        .selectors
        .insert("crypto_profile_id".into(), "wrong".into());
    assert_eq!(
        r.pool_authorization_projection(&m.artifact, &m.fsb, &wrong, 1 << 16),
        Err("pool_crypto_profile")
    );
    let mut parse_context = m.context.clone();
    parse_context.selectors.extend(
        context(seed("fsb_fields"))
            .selectors
            .into_iter()
            .filter(|(k, _)| k == "crypto_profile_id"),
    );
    // Both valid selected members pass; an ID from one and route from another fails.
    for (id, route, accepted) in [(0, 0, true), (1, 1, true), (0, 1, false)] {
        let mut fsb = r.wire_map(&m.fsb, "FSB4", &parse_context, 1 << 16).unwrap();
        *field_mut("FSB4", &mut fsb, "candidate_id") =
            Value::Bytes(&m.selection.members[id].candidate_id);
        *field_mut("FSB4", &mut fsb, "route_digest") =
            Value::Bytes(&m.selection.members[route].route_digest);
        let result =
            r.pool_authorization_projection(&m.artifact, &encoded(&fsb), &m.context, 1 << 16);
        if accepted {
            assert!(result.is_ok());
        } else {
            assert_eq!(result, Err("pool_winner_membership"));
        }
    }
    for (name, field, error) in [
        (
            "ActivationAuthorization",
            "route_selection",
            "pool_route_set_digest",
        ),
        (
            "PoolSelectionRef",
            "candidate_set_digest",
            "pool_candidate_set_digest",
        ),
        ("FSB4", "candidate_id", "pool_winner_membership"),
        ("FSB4", "session_nonce", "pool_artifact_binding"),
        (
            "ActivationAuthorization",
            "client_identity_digest",
            "pool_artifact_binding",
        ),
        (
            "ActivationAuthorization",
            "server_identity_digest",
            "pool_artifact_binding",
        ),
        (
            "ActivationAuthorization",
            "activation_not_after_ms",
            "pool_parent_deadline",
        ),
        (
            "ActivationAuthorization",
            "session_not_after_ms",
            "pool_parent_deadline",
        ),
        ("PoolSelectionRef", "artifact_digest", "field_equality"),
        (
            "ActivationAuthorization",
            "artifact_digest",
            "field_equality",
        ),
    ] {
        let mut fsb = r.wire_map(&m.fsb, "FSB4", &parse_context, 1 << 16).unwrap();
        let Value::Bytes(proof_bytes) = r
            .shape
            .required_value("FSB4", &fsb, "activation_authorization")
            .unwrap()
        else {
            panic!()
        };
        let mut proof = r
            .wire_map(
                proof_bytes,
                "ActivationAuthorization",
                &parse_context,
                1 << 16,
            )
            .unwrap();
        let root = match name {
            "FSB4" => &mut fsb,
            "PoolSelectionRef" => {
                field_mut("ActivationAuthorization", &mut proof, "candidate_selection")
            }
            _ => &mut proof,
        };
        let slot = field_mut(name, root, field);
        let mut data = Vec::new();
        match slot {
            Value::Bytes(raw) => {
                data.extend_from_slice(raw);
                data[0] ^= 0x80;
                *slot = Value::Bytes(&data);
            }
            Value::Unsigned(n) => {
                *n = if field == "activation_not_after_ms" {
                    500001
                } else {
                    1000001
                }
            }
            _ => panic!(),
        }
        let proof_bytes = encoded(&proof);
        *field_mut("FSB4", &mut fsb, "activation_authorization") = Value::Bytes(&proof_bytes);
        assert_eq!(
            r.pool_authorization_projection(&m.artifact, &encoded(&fsb), &m.context, 1 << 16),
            Err(error),
            "{name}.{field}"
        );
    }
}

// v4.rust_composition.pool_boundaries
#[test]
fn pool_caps_truncation_once_authority_and_full_uint64_times() {
    let r = reference();
    let m = material(&[0, 1], true);
    assert!(
        r.pool_authorization_projection(&m.artifact, &m.fsb, &m.context, 1 << 16)
            .is_ok()
    );
    for cap in [0, m.artifact.len() as u64 - 1] {
        assert!(
            r.pool_authorization_projection(&m.artifact, &m.fsb, &m.context, cap)
                .is_err()
        );
    }
    for (artifact, fsb) in [
        (&m.artifact[..m.artifact.len() - 1], &m.fsb[..]),
        (&m.artifact[..], &m.fsb[..m.fsb.len() - 1]),
    ] {
        assert!(
            r.pool_authorization_projection(artifact, fsb, &m.context, 1 << 16)
                .is_err()
        );
    }
    let mut ctx = m.context.clone();
    let artifact = r
        .wire_map(&m.artifact, "Artifact", &Context::default(), 1 << 16)
        .unwrap();
    let Value::Text(profile) = r
        .shape
        .required_value("Artifact", &artifact, "crypto_profile_id")
        .unwrap()
    else {
        panic!()
    };
    ctx.selectors
        .insert("crypto_profile_id".into(), (*profile).into());
    for authority in [false, true] {
        let mut fsb = r.wire_map(&m.fsb, "FSB4", &ctx, 1 << 16).unwrap();
        let Value::Bytes(proof_bytes) = r
            .shape
            .required_value("FSB4", &fsb, "activation_authorization")
            .unwrap()
        else {
            panic!()
        };
        let mut proof = r
            .wire_map(proof_bytes, "ActivationAuthorization", &ctx, 1 << 16)
            .unwrap();
        if authority {
            let selected = field_mut("ActivationAuthorization", &mut proof, "candidate_selection");
            let once = field_mut("PoolSelectionRef", selected, "once_authority_ref");
            *field_mut("OnceAuthorityRef", once, "spend_authority_id") =
                Value::Text("wrong-authority");
        } else {
            *field_mut(
                "ActivationAuthorization",
                &mut proof,
                "activation_not_after_ms",
            ) = Value::Unsigned(u64::MAX);
        }
        let proof_bytes = encoded(&proof);
        *field_mut("FSB4", &mut fsb, "activation_authorization") = Value::Bytes(&proof_bytes);
        assert_eq!(
            r.pool_authorization_projection(&m.artifact, &encoded(&fsb), &m.context, 1 << 16),
            Err(if authority {
                "field_equality"
            } else {
                "pool_parent_deadline"
            })
        );
    }
    let single = material(&[0], false);
    let both = material(&[0, 1], false);
    let mut fsb = r.wire_map(&single.fsb, "FSB4", &ctx, 1 << 16).unwrap();
    *field_mut("FSB4", &mut fsb, "candidate_id") =
        Value::Bytes(&both.selection.members[1].candidate_id);
    *field_mut("FSB4", &mut fsb, "route_digest") =
        Value::Bytes(&both.selection.members[1].route_digest);
    assert_eq!(
        r.pool_authorization_projection(&single.artifact, &encoded(&fsb), &single.context, 1 << 16),
        Err("pool_winner_membership")
    );
}

// v4.rust_composition.properties
proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]
    #[test]
    fn metadata_mutations_round_trip_or_reject(index in 0usize..6, at in any::<usize>(), byte in any::<u8>()) {
        let r = reference();
        let definition = seed_bytes("typed_definition_fields");
        let mut input = seed_bytes(["metadata_empty_values", "metadata_key_order", "metadata_4006", "typed_metadata_bound_empty", "typed_metadata_bound_maximum", "typed_metadata_nested_wrapper"][index]);
        let at = at % input.len(); input[at] ^= byte;
        if let Ok(Some((name, value))) = r.stream_metadata(&input, 4096) {
            prop_assert_eq!(&encoded(&value), &input);
            if name == "TypedMessageMetadata" {
                if let Ok(application) = r.verify_typed_metadata(&input, &definition, 8192) {
                    prop_assert_eq!(r.compose_typed_metadata(&definition, &application, 8192).unwrap(), input);
                }
            } else if let Ok(wrapped) = r.compose_typed_metadata(&definition, &input, 8192) {
                prop_assert_eq!(r.verify_typed_metadata(&wrapped, &definition, 8192).unwrap(), input);
            }
        }
    }
    #[test]
    fn pool_mutations_require_exact_winner_and_explicit_source(at in any::<usize>(), byte in any::<u8>(), change_artifact in any::<bool>()) {
        static MATERIAL: OnceLock<Material> = OnceLock::new();
        let m = MATERIAL.get_or_init(|| material(&[0,1], false));
        let mut artifact = m.artifact.clone(); let mut fsb = m.fsb.clone();
        let target = if change_artifact { &mut artifact } else { &mut fsb };
        let at = at % target.len(); target[at] ^= byte;
        if let Ok(result) = reference().pool_authorization_projection(&artifact, &fsb, &m.context, 1 << 16) {
            prop_assert_eq!(result, reference().derive_pool(&artifact, &[0,1], 1 << 16).unwrap());
            prop_assert_eq!(reference().pool_authorization_projection(&artifact, &fsb, &Context::default(), 1 << 16), Err("pool_source_profile"));
        }
        prop_assert_eq!(&m.context.selectors["activation_source_profile"], "preauthorized_pool");
    }
}
