import Foundation

// Stateless composition only: no codec execution, trust or activation rights.
extension V4ShapeReference {
  func requiredValue(_ name: String, _ value: V4CBORValue, _ field: String) throws -> V4CBORValue {
    guard let result = try namedValue(name, value, field) else { throw V4CBORFailure("missing_field") }
    return result
  }

  func fieldConstant(_ name: String, _ field: String) throws -> V4CBORValue {
    let descriptor = try namedField(name, field).1
    switch descriptor["type"].text {
    case "text":
      guard let value = descriptor["const"].text else { throw V4CBORFailure("registry_unresolved") }
      return .text(value)
    case "uint16": return try .uint(v4RuleInteger(descriptor["const"]))
    default: throw V4CBORFailure("registry_unresolved")
    }
  }
}

extension V4TextReference {
  func streamMetadata(_ input: Data, cap: UInt64) throws -> (schema: String, value: V4CBORValue)? {
    guard cap > 0 else { throw V4CBORFailure("limit_unresolved") }
    if input.isEmpty { return nil }
    // Syntax uses the common shell before exact shape selection. Ordinary value
    // limits must not preempt the reserved typed shell's whole-object allowance.
    let value = try shape.syntax.decode(input, schema: "StreamMetadata", cap: cap).0.get()
    let namespace = try shape.namedValue("StreamMetadata", value, "namespace")
    let typed = try shape.fieldConstant("TypedMessageMetadata", "namespace")
    let name = namespace?.encoded() == typed.encoded() ? "TypedMessageMetadata" : "StreamMetadata"
    return try (name, wireMap(input, schema: name, cap: cap))
  }

  func definitionDigest(_ definition: Data, cap: UInt64) throws -> Data {
    _ = try wireMap(definition, schema: "MessageStreamDefinition", cap: cap)
    return try v4SingleMapHash("typed_message_definition_digest", schema: "MessageStreamDefinition", projection: "full", input: definition)
  }

  func composeTypedMetadata(_ definition: Data, application: Data, cap: UInt64) throws -> Data {
    let digest = try definitionDigest(definition, cap: cap)
    if !application.isEmpty { _ = try wireMap(application, schema: "StreamMetadata", cap: cap) }
    var values: [V4CBORValue.Pair] = [
      .init(key: .text("definition"), value: .bytes(digest)),
      .init(key: .text("application"), value: .bytes(application)),
    ]
    // Canonical ordering is only applied when constructing a new issuer map.
    values.sort { left, right in
      let a = left.key.encoded(), b = right.key.encoded()
      return a.count != b.count ? a.count < b.count : a.lexicographicallyPrecedes(b)
    }
    let value = try shape.namedMap("TypedMessageMetadata", [
      ("namespace", shape.fieldConstant("TypedMessageMetadata", "namespace")),
      ("version", shape.fieldConstant("TypedMessageMetadata", "version")),
      ("values", .map(values)),
    ])
    let result = value.encoded()
    _ = try wireMap(result, schema: "TypedMessageMetadata", cap: cap)
    return result
  }

  func verifyTypedMetadata(_ input: Data, definition: Data, cap: UInt64) throws -> Data {
    let digest = try definitionDigest(definition, cap: cap)
    guard let parsed = try streamMetadata(input, cap: cap), parsed.schema == "TypedMessageMetadata" else { throw V4CBORFailure("typed_metadata_required") }
    guard case .map(let pairs) = try shape.requiredValue(parsed.schema, parsed.value, "values") else { throw V4CBORFailure("field_type") }
    func lookup(_ key: String) -> V4CBORValue? {
      pairs.first { if case .text(let text) = $0.key { return Data(text.utf8) == Data(key.utf8) }; return false }?.value
    }
    guard case .bytes(let actual) = lookup("definition"), case .bytes(let application) = lookup("application") else { throw V4CBORFailure("field_type") }
    guard actual == digest else { throw V4CBORFailure("typed_definition_mismatch") }
    return application.withUnsafeBytes { Data($0) }
  }

  func verifyPoolReference(_ artifact: Data, reference: Data, cap: UInt64) throws -> V4PoolProjection {
    let value = try wireMap(reference, schema: "PoolSelectionRef", cap: cap)
    guard case .array(let items) = try shape.requiredValue("PoolSelectionRef", value, "candidate_indices") else { throw V4CBORFailure("field_type") }
    let indices = try items.map { value -> UInt64 in
      guard case .uint(let n) = value else { throw V4CBORFailure("integer_type") }; return n
    }
    let result = try derivePool(artifact, indices: indices, cap: cap)
    for (field, expected, code) in [
      ("artifact_digest", result.artifactDigest, "pool_artifact_digest"),
      ("candidate_set_digest", result.candidateSetDigest, "pool_candidate_set_digest"),
    ] {
      guard case .bytes(let actual) = try shape.requiredValue("PoolSelectionRef", value, field), actual == expected else { throw V4CBORFailure(code) }
    }
    return result
  }

  func poolAuthorizationProjection(_ artifactBytes: Data, fsb fsbBytes: Data, context: V4CBORContext, cap: UInt64) throws -> V4PoolProjection {
    // The immutable material source comes from caller context, not proof shape.
    guard context.selectors["activation_source_profile"] == "preauthorized_pool" else { throw V4CBORFailure("pool_source_profile") }
    let artifact = try wireMap(artifactBytes, schema: "Artifact", cap: cap)
    guard case .text(let profile) = try shape.requiredValue("Artifact", artifact, "crypto_profile_id") else { throw V4CBORFailure("field_type") }
    if let supplied = context.selectors["crypto_profile_id"], Data(supplied.utf8) != Data(profile.utf8) { throw V4CBORFailure("pool_crypto_profile") }
    var scoped = context
    scoped.selectors["crypto_profile_id"] = profile
    let fsb = try wireMap(fsbBytes, schema: "FSB4", context: scoped, cap: cap)
    guard case .bytes(let proofBytes) = try shape.requiredValue("FSB4", fsb, "activation_authorization") else { throw V4CBORFailure("field_type") }
    let proof = try wireMap(proofBytes, schema: "ActivationAuthorization", context: scoped, cap: cap)
    let reference = try shape.requiredValue("ActivationAuthorization", proof, "candidate_selection")
    let result = try verifyPoolReference(artifactBytes, reference: reference.encoded(), cap: cap)
    for (name, value, fields) in [
      ("FSB4", fsb, ["tenant_id", "issuer_key_id", "lease_id", "session_nonce"]),
      ("ActivationAuthorization", proof, ["client_identity_digest", "server_identity_digest", "audience"]),
    ] {
      for field in fields {
        guard try shape.requiredValue("Artifact", artifact, field).encoded() == shape.requiredValue(name, value, field).encoded() else { throw V4CBORFailure("pool_artifact_binding") }
      }
    }
    for (name, value, field, expected, code) in [
      ("FSB4", fsb, "artifact_digest", result.artifactDigest, "pool_artifact_digest"),
      ("ActivationAuthorization", proof, "artifact_digest", result.artifactDigest, "pool_artifact_digest"),
      ("ActivationAuthorization", proof, "route_selection", result.routeSetDigest, "pool_route_set_digest"),
    ] {
      guard case .bytes(let actual) = try shape.requiredValue(name, value, field), actual == expected else { throw V4CBORFailure(code) }
    }
    for (child, parent) in [("activation_not_after_ms", "initiation_not_after_ms"), ("session_not_after_ms", "session_not_after_ms")] {
      guard case .uint(let deadline) = try shape.requiredValue("ActivationAuthorization", proof, child),
            case .uint(let bound) = try shape.requiredValue("Artifact", artifact, parent) else { throw V4CBORFailure("field_type") }
      guard deadline <= bound else { throw V4CBORFailure("pool_parent_deadline") }
    }
    guard case .bytes(let id) = try shape.requiredValue("FSB4", fsb, "candidate_id"),
          case .bytes(let route) = try shape.requiredValue("FSB4", fsb, "route_digest") else { throw V4CBORFailure("field_type") }
    guard result.members.contains(where: { $0.candidateID == id && $0.routeDigest == route }) else { throw V4CBORFailure("pool_winner_membership") }
    return result
  }
}
