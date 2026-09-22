//! Stateless composition only: no codec execution, trust or activation rights.
use super::cbor::{Error, Value};
use super::oracles::{PoolProjection, encoded, single_map_hash};
use super::shape::{Context, Shape, integer};
use super::text::Text;

fn text_lookup<'v, 'a>(value: &'v Value<'a>, name: &str) -> Option<&'v Value<'a>> {
    let Value::Map(pairs) = value else {
        return None;
    };
    pairs.iter().find_map(|(key, value)| {
        if key == &Value::Text(name) {
            Some(value)
        } else {
            None
        }
    })
}

impl Shape {
    fn field_constant(&self, name: &str, field: &str) -> Result<Value<'_>, Error> {
        let (_, descriptor) = self.named_field(name, field)?;
        match descriptor["type"].as_str() {
            Some("text") => Ok(Value::Text(
                descriptor["const"].as_str().ok_or("registry_unresolved")?,
            )),
            Some("uint16") => Ok(Value::Unsigned(integer(&descriptor["const"])?)),
            _ => Err("registry_unresolved"),
        }
    }

    pub fn required_value<'v, 'a>(
        &self,
        name: &str,
        value: &'v Value<'a>,
        field: &str,
    ) -> Result<&'v Value<'a>, Error> {
        self.named_value(name, value, field)?.ok_or("missing_field")
    }
}

impl Text {
    pub fn stream_metadata<'a>(
        &self,
        input: &'a [u8],
        cap: u64,
    ) -> Result<Option<(&'static str, Value<'a>)>, Error> {
        if cap == 0 {
            return Err("limit_unresolved");
        }
        if input.is_empty() {
            return Ok(None);
        }
        // Read syntax under the shared shell cap before selecting exact shape.
        // Ordinary field limits cannot preempt the reserved typed shell.
        let (value, _) =
            self.shape
                .syntax
                .decode(input, "StreamMetadata", &Default::default(), cap);
        let value = value?;
        let namespace = self
            .shape
            .named_value("StreamMetadata", &value, "namespace")?;
        let typed = self
            .shape
            .field_constant("TypedMessageMetadata", "namespace")?;
        let name = if namespace == Some(&typed) {
            "TypedMessageMetadata"
        } else {
            "StreamMetadata"
        };
        Ok(Some((
            name,
            self.wire_map(input, name, &Context::default(), cap)?,
        )))
    }

    pub fn definition_digest(&self, definition: &[u8], cap: u64) -> Result<Vec<u8>, Error> {
        self.wire_map(
            definition,
            "MessageStreamDefinition",
            &Context::default(),
            cap,
        )?;
        single_map_hash(
            "typed_message_definition_digest",
            "MessageStreamDefinition",
            "full",
            definition,
        )
    }

    pub fn compose_typed_metadata(
        &self,
        definition: &[u8],
        application: &[u8],
        cap: u64,
    ) -> Result<Vec<u8>, Error> {
        let digest = self.definition_digest(definition, cap)?;
        if !application.is_empty() {
            self.wire_map(application, "StreamMetadata", &Context::default(), cap)?;
        }
        let mut values = vec![
            (Value::Text("definition"), Value::Bytes(&digest)),
            (Value::Text("application"), Value::Bytes(application)),
        ];
        // Canonical ordering is only for issuer construction of this new map.
        values.sort_by_key(|(key, _)| {
            let bytes = encoded(key);
            (bytes.len(), bytes)
        });
        let value = self.shape.named_map(
            "TypedMessageMetadata",
            [
                (
                    "namespace",
                    Some(
                        self.shape
                            .field_constant("TypedMessageMetadata", "namespace")?,
                    ),
                ),
                (
                    "version",
                    Some(
                        self.shape
                            .field_constant("TypedMessageMetadata", "version")?,
                    ),
                ),
                ("values", Some(Value::Map(values))),
            ],
        )?;
        let result = encoded(&value);
        self.wire_map(&result, "TypedMessageMetadata", &Context::default(), cap)?;
        Ok(result)
    }

    pub fn verify_typed_metadata(
        &self,
        input: &[u8],
        definition: &[u8],
        cap: u64,
    ) -> Result<Vec<u8>, Error> {
        let digest = self.definition_digest(definition, cap)?;
        let Some(("TypedMessageMetadata", value)) = self.stream_metadata(input, cap)? else {
            return Err("typed_metadata_required");
        };
        let values = self
            .shape
            .required_value("TypedMessageMetadata", &value, "values")?;
        let (Some(Value::Bytes(actual)), Some(Value::Bytes(application))) = (
            text_lookup(values, "definition"),
            text_lookup(values, "application"),
        ) else {
            return Err("field_type");
        };
        if *actual != digest {
            return Err("typed_definition_mismatch");
        }
        Ok(application.to_vec())
    }

    pub fn verify_pool_reference(
        &self,
        artifact: &[u8],
        reference: &[u8],
        cap: u64,
    ) -> Result<PoolProjection, Error> {
        let value = self.wire_map(reference, "PoolSelectionRef", &Context::default(), cap)?;
        let Value::Array(items) =
            self.shape
                .required_value("PoolSelectionRef", &value, "candidate_indices")?
        else {
            return Err("field_type");
        };
        let indices = items
            .iter()
            .map(|item| match item {
                Value::Unsigned(n) => Ok(*n),
                _ => Err("integer_type"),
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let result = self.derive_pool(artifact, &indices, cap)?;
        for (field, expected, code) in [
            (
                "artifact_digest",
                &result.artifact_digest,
                "pool_artifact_digest",
            ),
            (
                "candidate_set_digest",
                &result.candidate_set_digest,
                "pool_candidate_set_digest",
            ),
        ] {
            if self
                .shape
                .required_value("PoolSelectionRef", &value, field)?
                != &Value::Bytes(expected)
            {
                return Err(code);
            }
        }
        Ok(result)
    }

    pub fn pool_authorization_projection(
        &self,
        artifact_bytes: &[u8],
        fsb_bytes: &[u8],
        context: &Context,
        cap: u64,
    ) -> Result<PoolProjection, Error> {
        // Source is immutable caller context, never inferred from proof shape.
        if context
            .selectors
            .get("activation_source_profile")
            .map(String::as_str)
            != Some("preauthorized_pool")
        {
            return Err("pool_source_profile");
        }
        let artifact = self.wire_map(artifact_bytes, "Artifact", &Context::default(), cap)?;
        let Value::Text(profile) =
            self.shape
                .required_value("Artifact", &artifact, "crypto_profile_id")?
        else {
            return Err("field_type");
        };
        if context
            .selectors
            .get("crypto_profile_id")
            .is_some_and(|value| value != profile)
        {
            return Err("pool_crypto_profile");
        }
        let mut context = context.clone();
        context
            .selectors
            .insert("crypto_profile_id".into(), (*profile).into());
        let fsb = self.wire_map(fsb_bytes, "FSB4", &context, cap)?;
        let Value::Bytes(proof_bytes) =
            self.shape
                .required_value("FSB4", &fsb, "activation_authorization")?
        else {
            return Err("field_type");
        };
        let proof = self.wire_map(proof_bytes, "ActivationAuthorization", &context, cap)?;
        let reference =
            self.shape
                .required_value("ActivationAuthorization", &proof, "candidate_selection")?;
        let result = self.verify_pool_reference(artifact_bytes, &encoded(reference), cap)?;
        for (name, target, fields) in [
            (
                "FSB4",
                &fsb,
                &["tenant_id", "issuer_key_id", "lease_id", "session_nonce"][..],
            ),
            (
                "ActivationAuthorization",
                &proof,
                &[
                    "client_identity_digest",
                    "server_identity_digest",
                    "audience",
                ][..],
            ),
        ] {
            for field in fields {
                if self.shape.required_value("Artifact", &artifact, field)?
                    != self.shape.required_value(name, target, field)?
                {
                    return Err("pool_artifact_binding");
                }
            }
        }
        for (name, value, field, expected, code) in [
            (
                "FSB4",
                &fsb,
                "artifact_digest",
                &result.artifact_digest,
                "pool_artifact_digest",
            ),
            (
                "ActivationAuthorization",
                &proof,
                "route_selection",
                &result.route_set_digest,
                "pool_route_set_digest",
            ),
        ] {
            if self.shape.required_value(name, value, field)? != &Value::Bytes(expected) {
                return Err(code);
            }
        }
        for (child, parent) in [
            ("activation_not_after_ms", "initiation_not_after_ms"),
            ("session_not_after_ms", "session_not_after_ms"),
        ] {
            let (Value::Unsigned(child), Value::Unsigned(parent)) = (
                self.shape
                    .required_value("ActivationAuthorization", &proof, child)?,
                self.shape.required_value("Artifact", &artifact, parent)?,
            ) else {
                return Err("field_type");
            };
            if child > parent {
                return Err("pool_parent_deadline");
            }
        }
        let id = self.shape.required_value("FSB4", &fsb, "candidate_id")?;
        let route = self.shape.required_value("FSB4", &fsb, "route_digest")?;
        if !result.members.iter().any(|member| {
            id == &Value::Bytes(&member.candidate_id)
                && route == &Value::Bytes(&member.route_digest)
        }) {
            return Err("pool_winner_membership");
        }
        Ok(result)
    }
}
