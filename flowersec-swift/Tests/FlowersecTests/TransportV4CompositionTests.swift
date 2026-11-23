import Foundation
import XCTest
@testable import Flowersec

final class TransportV4CompositionTests: XCTestCase {
  private static let reference = try! V4TextReference()
  private static let corpus: [V4JSON] = {
    let raw = try! Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/corpus.json"))
    let corpus = try! JSONDecoder().decode(V4JSON.self, from: raw)
    precondition(corpus["schema_sha256"].text == TransportV4Registry.schemaSHA256)
    return corpus["vectors"].array!
  }()
  private func seed(_ id: String) -> V4JSON { Self.corpus.first { $0["id"].text == id }! }
  private func bytes(_ id: String) throws -> Data { try v4RuleHex(seed(id)["hex"].text!) }
  private func context(_ id: String) -> V4CBORContext {
    var result = V4CBORContext()
    for (key, value) in seed(id)["limits"].object ?? [:] {
      if case .uint(let n) = value { result.limits[key] = n }
      if case .text(let text) = value { result.selectors[key] = text }
    }
    return result
  }
  private func read(_ input: Data, _ name: String, context: V4CBORContext = .init()) throws -> V4CBORValue {
    try Self.reference.wireMap(input, schema: name, context: context, cap: 1 << 16)
  }
  private func field(_ name: String, _ value: V4CBORValue, _ field: String) throws -> V4CBORValue {
    try Self.reference.shape.requiredValue(name, value, field)
  }
  private func set(_ name: String, _ value: inout V4CBORValue, _ field: String, _ replacement: V4CBORValue) throws {
    let id = try Self.reference.shape.namedField(name, field).0
    guard case .map(var pairs) = value, let index = pairs.firstIndex(where: { if case .uint(let key) = $0.key { return key == id }; return false }) else { throw V4CBORFailure("missing_field") }
    pairs[index].value = replacement; value = .map(pairs)
  }
  private func rejects(_ expected: String? = nil, file: StaticString = #filePath, line: UInt = #line, _ operation: () throws -> Void) {
    XCTAssertThrowsError(try operation(), file: file, line: line) { error in
      if let expected { XCTAssertEqual((error as? V4CBORFailure)?.code, expected, file: file, line: line) }
    }
  }

  // v4.swift_composition.metadata_corpus
  func testMetadataCorpusAndIndependentComposition() throws {
    let r = Self.reference, definition = try bytes("typed_definition_fields")
    var positive = 0, negative = 0, bound = 0
    for vector in Self.corpus where ["StreamMetadata", "TypedMessageMetadata"].contains(vector["schema"].text ?? "") {
      let raw = try v4RuleHex(vector["hex"].text!), id = vector["id"].text!
      if vector["expected_error"].text != nil {
        negative += 1
        if let parsed = try? r.streamMetadata(raw, cap: UInt64(raw.count) + 1) {
          XCTAssertNotEqual(parsed.schema, "TypedMessageMetadata", id)
          XCTAssertEqual(vector["schema"].text, "TypedMessageMetadata", id)
          rejects { _ = try r.verifyTypedMetadata(raw, definition: definition, cap: 8192) }
        } else { rejects { _ = try r.streamMetadata(raw, cap: UInt64(raw.count) + 1) } }
      } else {
        positive += 1
        let parsed = try XCTUnwrap(r.streamMetadata(raw, cap: UInt64(raw.count) + 1))
        XCTAssertEqual(parsed.schema, vector["schema"].text, id); XCTAssertEqual(parsed.value.encoded(), raw, id)
        if let derivation = vector.object?["typed_derivation"] {
          bound += 1
          let definition = try v4RuleHex(derivation["definition_hex"].text!), application = try v4RuleHex(derivation["application_hex"].text!)
          XCTAssertEqual(try r.composeTypedMetadata(definition, application: application, cap: 8192), raw, id)
          XCTAssertEqual(try r.verifyTypedMetadata(raw, definition: definition, cap: 8192), application, id)
        }
      }
    }
    XCTAssertGreaterThan(positive, 0); XCTAssertGreaterThan(negative, 0); XCTAssertEqual(bound, 2)
  }

  // v4.swift_composition.metadata_boundaries
  func testMetadataCapsRequiredShellAndOwnedBytes() throws {
    let r = Self.reference, definition = try bytes("typed_definition_fields")
    XCTAssertNil(try r.streamMetadata(Data(), cap: 4096))
    rejects("limit_unresolved") { _ = try r.streamMetadata(Data(), cap: 0) }
    for var application in [Data(), try bytes("metadata_empty_values"), try bytes("metadata_4006")] {
      let original = application
      var wrapped = try r.composeTypedMetadata(definition, application: application, cap: 8192)
      if application.isEmpty { XCTAssertEqual(wrapped.count, 88) }
      if application.count == 4006 { XCTAssertEqual(wrapped.count, 4096) }
      let cap = UInt64(max(wrapped.count, definition.count))
      XCTAssertEqual(try r.composeTypedMetadata(definition, application: application, cap: cap), wrapped)
      rejects { _ = try r.composeTypedMetadata(definition, application: application, cap: cap - 1) }
      var returned = try r.verifyTypedMetadata(wrapped, definition: definition, cap: 8192)
      XCTAssertEqual(returned, original); returned.resetBytes(in: 0..<returned.count); XCTAssertEqual(application, original)
      application.resetBytes(in: 0..<application.count)
      returned = try r.verifyTypedMetadata(wrapped, definition: definition, cap: 8192)
      wrapped.resetBytes(in: 0..<wrapped.count); XCTAssertEqual(returned, original)
    }
    for id in ["metadata_4007", "metadata_4096"] {
      let application = try bytes(id)
      XCTAssertNotNil(try r.streamMetadata(application, cap: 4096))
      rejects { _ = try r.composeTypedMetadata(definition, application: application, cap: 8192) }
    }
    rejects { _ = try r.composeTypedMetadata(definition, application: bytes("typed_metadata_empty"), cap: 8192) }
    for input in [Data(), try bytes("metadata_empty_values")] {
      rejects("typed_metadata_required") { _ = try r.verifyTypedMetadata(input, definition: definition, cap: 8192) }
    }
    rejects("typed_definition_mismatch") { _ = try r.verifyTypedMetadata(bytes("typed_metadata_bound_empty"), definition: bytes("typed_definition_maximum"), cap: 8192) }
  }

  // v4.swift_composition.definition_binding
  func testEveryDefinitionDirectionFieldIsBound() throws {
    let r = Self.reference, definition = try bytes("typed_definition_fields")
    let wrapped = try r.composeTypedMetadata(definition, application: Data(), cap: 8192)
    func changed(_ value: V4CBORValue) throws -> V4CBORValue {
      switch value {
      case .uint(let n): return .uint(n - 1)
      case .bytes(var raw): raw[0] ^= 1; return .bytes(raw)
      case .text(let text): return .text(text + "x")
      default: throw V4CBORFailure("test_field")
      }
    }
    for path in ["kind", "revision", "opener_to_acceptor.codec_schema_digest", "opener_to_acceptor.codec_revision", "opener_to_acceptor.max_message_bytes", "acceptor_to_opener.codec_schema_digest", "acceptor_to_opener.codec_revision", "acceptor_to_opener.max_message_bytes", "swap_directions"] {
      var value = try read(definition, "MessageStreamDefinition")
      if path == "swap_directions" {
        let left = try field("MessageStreamDefinition", value, "opener_to_acceptor"), right = try field("MessageStreamDefinition", value, "acceptor_to_opener")
        try set("MessageStreamDefinition", &value, "opener_to_acceptor", right)
        try set("MessageStreamDefinition", &value, "acceptor_to_opener", left)
      } else {
        let parts = path.split(separator: ".").map(String.init)
        if parts.count == 2 {
          var direction = try field("MessageStreamDefinition", value, parts[0])
          let replacement = try changed(field("MessageStreamDirection", direction, parts[1]))
          try set("MessageStreamDirection", &direction, parts[1], replacement)
          try set("MessageStreamDefinition", &value, parts[0], direction)
        } else {
          let replacement = try changed(field("MessageStreamDefinition", value, path))
          try set("MessageStreamDefinition", &value, path, replacement)
        }
      }
      let raw = value.encoded()
      _ = try read(raw, "MessageStreamDefinition")
      rejects("typed_definition_mismatch") { _ = try r.verifyTypedMetadata(wrapped, definition: raw, cap: 8192) }
    }
  }

  // v4.swift_composition.metadata_scope
  func testInvalidInnerMetadataRemainsSeparateFromOuterOPEN() throws {
    let r = Self.reference
    for id in ["metadata_bad_namespace_0", "metadata_value_wrong_type", "typed_metadata_nested_wrapper", "typed_metadata_missing_application"] {
      var value = try read(bytes("open_fields"), "OPEN_STREAM")
      let metadata = try bytes(id)
      try set("OPEN_STREAM", &value, "metadata", .bytes(metadata))
      let digest = try r.shape.openDigest(value)
      try set("OPEN_STREAM", &value, "open_digest", .bytes(digest))
      let received = try read(value.encoded(), "OPEN_STREAM")
      XCTAssertEqual(try field("OPEN_STREAM", received, "open_digest").encoded(), try V4CBORValue.bytes(r.shape.openDigest(received)).encoded())
      rejects { _ = try r.streamMetadata(metadata, cap: 4096) }
    }
  }

  private struct Material {
    let artifact: Data, fsb: Data, reference: Data
    let selection: V4PoolProjection
    let context: V4CBORContext
  }
  private func material(_ indices: [UInt64], highTimes: Bool = false) throws -> Material {
    let r = Self.reference
    var artifact = try read(bytes("artifact_transport_fields"), "Artifact")
    if highTimes {
      for (key, value) in [("issued_at_ms", UInt64.max - 2), ("initiation_not_after_ms", UInt64.max - 1), ("session_not_after_ms", UInt64.max)] { try set("Artifact", &artifact, key, .uint(value)) }
    }
    let raw = artifact.encoded(), selection = try r.derivePool(raw, indices: indices, cap: 1 << 16)
    var proof = try read(bytes("activation_pool_fields"), "ActivationAuthorization", context: context("activation_pool_fields"))
    if highTimes {
      for (key, value) in [("issued_at_ms", UInt64.max - 2), ("activation_not_after_ms", UInt64.max - 1), ("session_not_after_ms", UInt64.max)] { try set("ActivationAuthorization", &proof, key, .uint(value)) }
    }
    var reference = try field("ActivationAuthorization", proof, "candidate_selection")
    try set("PoolSelectionRef", &reference, "artifact_digest", .bytes(selection.artifactDigest))
    try set("PoolSelectionRef", &reference, "candidate_set_digest", .bytes(selection.candidateSetDigest))
    try set("PoolSelectionRef", &reference, "candidate_indices", .array(indices.map { .uint($0) }))
    try set("ActivationAuthorization", &proof, "candidate_selection", reference)
    try set("ActivationAuthorization", &proof, "artifact_digest", .bytes(selection.artifactDigest))
    try set("ActivationAuthorization", &proof, "route_selection", .bytes(selection.routeSetDigest))
    for key in ["client_identity_digest", "server_identity_digest", "audience"] { try set("ActivationAuthorization", &proof, key, field("Artifact", artifact, key)) }
    var fsb = try read(bytes("fsb_fields"), "FSB4", context: context("fsb_fields"))
    try set("FSB4", &fsb, "artifact_digest", .bytes(selection.artifactDigest))
    try set("FSB4", &fsb, "session_nonce", field("Artifact", artifact, "session_nonce"))
    try set("FSB4", &fsb, "candidate_id", .bytes(selection.members[0].candidateID))
    try set("FSB4", &fsb, "route_digest", .bytes(selection.members[0].routeDigest))
    try set("FSB4", &fsb, "activation_authorization", .bytes(proof.encoded()))
    var context = V4CBORContext(); context.selectors["activation_source_profile"] = "preauthorized_pool"
    return .init(artifact: raw, fsb: fsb.encoded(), reference: reference.encoded(), selection: selection, context: context)
  }
  private func parseContext(_ m: Material) -> V4CBORContext {
    var result = m.context
    result.selectors["crypto_profile_id"] = context("fsb_fields").selectors["crypto_profile_id"]
    return result
  }
  private func authorize(_ m: Material, fsb: Data? = nil) throws -> V4PoolProjection {
    try Self.reference.poolAuthorizationProjection(m.artifact, fsb: fsb ?? m.fsb, context: m.context, cap: 1 << 16)
  }

  // v4.swift_composition.pool_reference
  func testPoolReferenceBindsOriginalArtifactIndicesAndDomains() throws {
    let r = Self.reference, m = try material([0, 1])
    XCTAssertEqual(try r.verifyPoolReference(m.artifact, reference: m.reference, cap: 1 << 16), m.selection)
    var artifact = try read(m.artifact, "Artifact")
    try set("Artifact", &artifact, "signature", .bytes(Data(repeating: 99, count: 64)))
    rejects("pool_artifact_digest") { _ = try r.verifyPoolReference(artifact.encoded(), reference: m.reference, cap: 1 << 16) }
    var reference = try read(m.reference, "PoolSelectionRef")
    try set("PoolSelectionRef", &reference, "candidate_indices", .array([.uint(0)]))
    rejects("pool_candidate_set_digest") { _ = try r.verifyPoolReference(m.artifact, reference: reference.encoded(), cap: 1 << 16) }
    let single = try r.derivePool(m.artifact, indices: [0], cap: 1 << 16)
    try set("PoolSelectionRef", &reference, "candidate_set_digest", .bytes(single.routeSetDigest))
    rejects("pool_candidate_set_digest") { _ = try r.verifyPoolReference(m.artifact, reference: reference.encoded(), cap: 1 << 16) }
  }

  // v4.swift_composition.pool_winner
  func testPoolProofSourceIdentityDeadlinesAndPairedWinner() throws {
    let r = Self.reference, m = try material([0, 1]), before = m.context
    XCTAssertEqual(try authorize(m), m.selection); XCTAssertEqual(m.context, before)
    var wrong = m.context; wrong.selectors["activation_source_profile"] = "live_authority"
    for context in [V4CBORContext(), wrong] {
      rejects("pool_source_profile") { _ = try r.poolAuthorizationProjection(m.artifact, fsb: m.fsb, context: context, cap: 1 << 16) }
    }
    wrong = m.context; wrong.selectors["crypto_profile_id"] = "wrong"
    rejects("pool_crypto_profile") { _ = try r.poolAuthorizationProjection(m.artifact, fsb: m.fsb, context: wrong, cap: 1 << 16) }
    let context = parseContext(m)
    for (id, route, accepted) in [(0, 0, true), (1, 1, true), (0, 1, false)] {
      var fsb = try read(m.fsb, "FSB4", context: context)
      try set("FSB4", &fsb, "candidate_id", .bytes(m.selection.members[id].candidateID))
      try set("FSB4", &fsb, "route_digest", .bytes(m.selection.members[route].routeDigest))
      if accepted { XCTAssertEqual(try authorize(m, fsb: fsb.encoded()), m.selection) }
      else { rejects("pool_winner_membership") { _ = try authorize(m, fsb: fsb.encoded()) } }
    }
    for (name, key, error) in [
      ("ActivationAuthorization", "route_selection", "pool_route_set_digest"),
      ("PoolSelectionRef", "candidate_set_digest", "pool_candidate_set_digest"),
      ("FSB4", "candidate_id", "pool_winner_membership"), ("FSB4", "session_nonce", "pool_artifact_binding"),
      ("ActivationAuthorization", "client_identity_digest", "pool_artifact_binding"),
      ("ActivationAuthorization", "server_identity_digest", "pool_artifact_binding"),
      ("ActivationAuthorization", "activation_not_after_ms", "pool_parent_deadline"),
      ("ActivationAuthorization", "session_not_after_ms", "pool_parent_deadline"),
      ("PoolSelectionRef", "artifact_digest", "field_equality"),
      ("ActivationAuthorization", "artifact_digest", "field_equality"),
    ] {
      var fsb = try read(m.fsb, "FSB4", context: context)
      guard case .bytes(let proofBytes) = try field("FSB4", fsb, "activation_authorization") else { return XCTFail("proof bytes") }
      var proof = try read(proofBytes, "ActivationAuthorization", context: context)
      var target = name == "FSB4" ? fsb : name == "PoolSelectionRef" ? try field("ActivationAuthorization", proof, "candidate_selection") : proof
      let replacement: V4CBORValue
      switch try field(name, target, key) {
      case .bytes(var raw): raw[0] ^= 0x80; replacement = .bytes(raw)
      case .uint: replacement = .uint(key == "activation_not_after_ms" ? 500001 : 1000001)
      default: return XCTFail("mutation")
      }
      try set(name, &target, key, replacement)
      if name == "FSB4" { fsb = target }
      else if name == "PoolSelectionRef" { try set("ActivationAuthorization", &proof, "candidate_selection", target) }
      else { proof = target }
      try set("FSB4", &fsb, "activation_authorization", .bytes(proof.encoded()))
      rejects(error) { _ = try authorize(m, fsb: fsb.encoded()) }
    }
  }

  // v4.swift_composition.pool_boundaries
  func testPoolCapsTruncationOnceAuthorityAndFullUInt64Times() throws {
    let r = Self.reference, m = try material([0, 1], highTimes: true), context = parseContext(m)
    XCTAssertEqual(try authorize(m), m.selection)
    for cap in [0, UInt64(m.artifact.count) - 1] {
      rejects { _ = try r.poolAuthorizationProjection(m.artifact, fsb: m.fsb, context: m.context, cap: cap) }
    }
    for (artifact, fsb) in [(Data(m.artifact.dropLast()), m.fsb), (m.artifact, Data(m.fsb.dropLast()))] {
      rejects { _ = try r.poolAuthorizationProjection(artifact, fsb: fsb, context: m.context, cap: 1 << 16) }
    }
    for authority in [false, true] {
      var fsb = try read(m.fsb, "FSB4", context: context)
      guard case .bytes(let proofBytes) = try field("FSB4", fsb, "activation_authorization") else { return XCTFail("proof bytes") }
      var proof = try read(proofBytes, "ActivationAuthorization", context: context)
      if authority {
        var reference = try field("ActivationAuthorization", proof, "candidate_selection")
        var once = try field("PoolSelectionRef", reference, "once_authority_ref")
        try set("OnceAuthorityRef", &once, "spend_authority_id", .text("wrong-authority"))
        try set("PoolSelectionRef", &reference, "once_authority_ref", once)
        try set("ActivationAuthorization", &proof, "candidate_selection", reference)
      } else { try set("ActivationAuthorization", &proof, "activation_not_after_ms", .uint(UInt64.max)) }
      try set("FSB4", &fsb, "activation_authorization", .bytes(proof.encoded()))
      rejects(authority ? "field_equality" : "pool_parent_deadline") { _ = try authorize(m, fsb: fsb.encoded()) }
    }
    let single = try material([0]), both = try material([0, 1])
    var fsb = try read(single.fsb, "FSB4", context: context)
    try set("FSB4", &fsb, "candidate_id", .bytes(both.selection.members[1].candidateID))
    try set("FSB4", &fsb, "route_digest", .bytes(both.selection.members[1].routeDigest))
    rejects("pool_winner_membership") { _ = try authorize(single, fsb: fsb.encoded()) }
  }

  // v4.swift_composition.properties
  func testMetadataAndPoolMutationProperties() throws {
    let r = Self.reference, definition = try bytes("typed_definition_fields"), m = try material([0, 1])
    var state: UInt64 = 0x41c0a041c0a041c0
    func next() -> UInt64 { state = state &* 6364136223846793005 &+ 1442695040888963407; return state ^ (state >> 31) }
    for _ in 0..<4096 {
      var input = try bytes(["metadata_empty_values", "metadata_key_order", "metadata_4006", "typed_metadata_bound_empty", "typed_metadata_bound_maximum", "typed_metadata_nested_wrapper"][Int(next() % 6)])
      let at = Int(next() % UInt64(input.count)); input[at] ^= UInt8(truncatingIfNeeded: next())
      if let parsed = try? r.streamMetadata(input, cap: 4096) {
        XCTAssertEqual(parsed.value.encoded(), input)
        if parsed.schema == "TypedMessageMetadata" {
          if let application = try? r.verifyTypedMetadata(input, definition: definition, cap: 8192) { XCTAssertEqual(try r.composeTypedMetadata(definition, application: application, cap: 8192), input) }
        } else if let wrapped = try? r.composeTypedMetadata(definition, application: input, cap: 8192) { XCTAssertEqual(try r.verifyTypedMetadata(wrapped, definition: definition, cap: 8192), input) }
      }
      var artifact = m.artifact, fsb = m.fsb
      if next() % 2 == 0 { let at = Int(next() % UInt64(artifact.count)); artifact[at] ^= UInt8(truncatingIfNeeded: next()) }
      else { let at = Int(next() % UInt64(fsb.count)); fsb[at] ^= UInt8(truncatingIfNeeded: next()) }
      if let result = try? r.poolAuthorizationProjection(artifact, fsb: fsb, context: m.context, cap: 1 << 16) {
        XCTAssertEqual(result, try r.derivePool(artifact, indices: [0, 1], cap: 1 << 16))
        rejects("pool_source_profile") { _ = try r.poolAuthorizationProjection(artifact, fsb: fsb, context: .init(), cap: 1 << 16) }
      }
      XCTAssertEqual(m.context.selectors["activation_source_profile"], "preauthorized_pool")
    }
  }
}
