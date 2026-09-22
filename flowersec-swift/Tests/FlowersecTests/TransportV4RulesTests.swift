import Foundation
import XCTest
@testable import Flowersec

final class TransportV4RulesTests: XCTestCase {
  private static let reference = try! V4ShapeReference()
  private static let corpus: [V4JSON] = {
    let data = try! Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/corpus.json"))
    let corpus = try! JSONDecoder().decode(V4JSON.self, from: data)
    precondition(corpus["schema_sha256"].text == TransportV4Registry.schemaSHA256)
    return corpus["vectors"].array!
  }()

  private func bytes(_ vector: V4JSON) throws -> Data { try v4RuleHex(vector["hex"].text!) }
  private func seed(_ id: String) -> V4JSON { Self.corpus.first { $0["id"].text == id }! }
  private func context(_ vector: V4JSON) -> V4CBORContext {
    var context = V4CBORContext()
    for (key, value) in vector["limits"].object ?? [:] {
      if case .uint(let n) = value { context.limits[key] = n }
      if case .text(let text) = value { context.selectors[key] = text }
    }
    return context
  }

  private func replace(_ name: String, _ value: V4CBORValue, _ field: String, _ replacement: V4CBORValue) -> V4CBORValue {
    let id = UInt64(Self.reference.registry["frame_maps"][name]["fields"].object!.first { $0.value["name"].text == field }!.key)!
    guard case .map(var pairs) = value else { preconditionFailure("map required") }
    let index = pairs.firstIndex { if case .uint(let key) = $0.key { return key == id }; return false }!
    pairs[index].value = replacement
    return .map(pairs)
  }

  private func rejects(_ expected: String, file: StaticString = #filePath, line: UInt = #line, _ operation: () throws -> Void) {
    XCTAssertThrowsError(try operation(), file: file, line: line) { error in
      XCTAssertEqual((error as? V4CBORFailure)?.code, expected, file: file, line: line)
    }
  }

  private func corpusCheck(relations: Bool) throws {
    let excluded: Set<String> = ["host_noncanonical", "host_loopback", "origin_endpoint", "origin_default_port", "origin_syntax", "pool_set_membership", "open_digest_mismatch"]
    var positive = 0, negative = 0, separate = 0
    for vector in Self.corpus {
      let error = vector["expected_error"].text, id = vector["id"].text!
      if let error {
        if relations {
          if excluded.contains(error) { separate += 1; continue }
        } else if !error.hasPrefix("variant_") && !["field_range", "field_prefix"].contains(error) && !["admission_rejected_unknown_code", "context_auth_exporter_bytes"].contains(id) { continue }
      }
      let raw = try bytes(vector), ctx = context(vector), before = ctx, name = vector["schema"].text ?? ""
      do {
        let value = try relations ? Self.reference.relations(raw, schema: name, context: ctx, cap: UInt64(raw.count) + 1) : Self.reference.variants(raw, schema: name, context: ctx, cap: UInt64(raw.count) + 1)
        XCTAssertNil(error, "accepted \(id)"); XCTAssertEqual(value.encoded(), raw, id)
      } catch let failure { XCTAssertNotNil(error, "\(id): \(failure)") }
      XCTAssertEqual(ctx, before, id)
      if error == nil { positive += 1 } else { negative += 1 }
    }
    XCTAssertEqual(positive, 337); XCTAssertEqual(negative, relations ? 816 : 133)
    XCTAssertEqual(separate, relations ? 12 : 0)
    print("Swift \(relations ? "relations" : "variants"): \(positive) positive / \(negative) negative / \(separate) separate cases")
  }

  // v4.swift_rules.variants
  func testSharedClosedVariantCorpus() throws { try corpusCheck(relations: false) }

  // v4.swift_rules.relations
  func testSharedStatelessRelationCorpus() throws { try corpusCheck(relations: true) }

  // v4.swift_rules.scoped_paths
  func testScopedPathsAndExternalContext() throws {
    let r = Self.reference
    for id in ["route_direct_fields", "route_tunnel_mixed_fields", "activation_live_fields", "activation_pool_fields"] {
      let vector = seed(id), raw = try bytes(vector), name = vector["schema"].text!
      var ctx = context(vector)
      if name == "Route" { ctx.selectors["path_kind"] = "invalid-caller-selector" }
      let before = ctx
      XCTAssertEqual(try r.relations(raw, schema: name, context: ctx, cap: UInt64(raw.count) + 1).encoded(), raw)
      XCTAssertEqual(ctx, before)
      if name == "ActivationAuthorization" {
        rejects("context_unresolved") { _ = try r.variants(raw, schema: name, cap: 65536) }
        ctx.selectors["activation_source_profile"] = "unknown"
        rejects("context_unresolved") { _ = try r.variants(raw, schema: name, context: ctx, cap: 65536) }
      }
    }
    let fsb = seed("fsb_fields"), ctx = context(fsb)
    let value = try r.relations(bytes(fsb), schema: "FSB4", context: ctx, cap: 65536)
    XCTAssertEqual(try r.rulePath("FSB4", value, "client_certificate.role", context: ctx)?.encoded(), V4CBORValue.uint(0).encoded())
    rejects("unknown_rule_field") { _ = try r.rulePath("FSB4", value, "not_registered", context: ctx) }
    let grant = seed("grant_fields"), grantContext = context(grant)
    let grantValue = try r.relations(bytes(grant), schema: "Grant", context: grantContext, cap: 65536)
    XCTAssertEqual(try r.rulePath("Grant", grantValue, "legs.1.logical_role", context: grantContext)?.encoded(), V4CBORValue.uint(1).encoded())
    XCTAssertNil(try r.rulePath("Grant", grantValue, "legs.18446744073709551615.logical_role", context: grantContext))
    rejects("unknown_rule_field") { _ = try r.rulePath("Grant", grantValue, "legs.invalid.logical_role", context: grantContext) }
  }

  // v4.swift_rules.shape_preserving
  func testShapeValidInputsStillRequireVariantAndRangeChecks() throws {
    let r = Self.reference, vector = seed("grant_certificate_maximum_fields"), ctx = context(vector)
    let certificate = try r.variants(bytes(vector), schema: "IdentityCertificate", context: ctx, cap: 65536)
    let key = try r.rulePath("IdentityCertificate", certificate, "noise_static_public_key", context: ctx)!
    guard case .bytes(var publicKey) = try r.rulePath("IdentityCertificate", certificate, "noise_static_public_key.public_key_bytes", context: ctx) else { return XCTFail("missing key") }
    publicKey[0] ^= 1
    let modifiedKey = replace("NoiseStaticPublicKey", key, "public_key_bytes", .bytes(publicKey))
    let modified = replace("IdentityCertificate", certificate, "noise_static_public_key", modifiedKey).encoded()
    _ = try r.decode(modified, schema: "IdentityCertificate", context: ctx, cap: 65536)
    rejects("field_prefix") { _ = try r.variants(modified, schema: "IdentityCertificate", context: ctx, cap: 65536) }

    let open = Self.corpus.first { $0["schema"].text == "OPEN_STREAM" && $0["expected_error"].text == nil }!, openContext = context(open)
    let original = try r.variants(bytes(open), schema: "OPEN_STREAM", context: openContext, cap: 65536)
    for scope in [0, UInt64(1) << 63, UInt64.max] {
      let raw = replace("OPEN_STREAM", original, "scope", .uint(scope)).encoded()
      _ = try r.decode(raw, schema: "OPEN_STREAM", context: openContext, cap: 65536)
      rejects("field_range") { _ = try r.variants(raw, schema: "OPEN_STREAM", context: openContext, cap: 65536) }
    }
    _ = try r.variants(replace("OPEN_STREAM", original, "scope", .uint((UInt64(1) << 63) - 1)).encoded(), schema: "OPEN_STREAM", context: openContext, cap: 65536)

    let fsb = seed("fsb_fields"), fsbContext = context(fsb)
    let fsbValue = try r.variants(bytes(fsb), schema: "FSB4", context: fsbContext, cap: 65536)
    guard case .bytes(let certificateBytes) = try r.rulePath("FSB4", fsbValue, "client_certificate", context: fsbContext) else { return XCTFail("certificate") }
    let cert = try r.decode(certificateBytes, schema: "IdentityCertificate", context: fsbContext, cap: 65536)
    let changed = replace("IdentityCertificate", cert, "role", .uint(1)).encoded()
    let raw = replace("FSB4", fsbValue, "client_certificate", .bytes(changed)).encoded()
    _ = try r.decode(raw, schema: "FSB4", context: fsbContext, cap: 65536)
    rejects("field_range") { _ = try r.variants(raw, schema: "FSB4", context: fsbContext, cap: 65536) }

    let grant = seed("grant_fields"), grantContext = context(grant)
    let grantValue = try r.variants(bytes(grant), schema: "Grant", context: grantContext, cap: 65536)
    guard case .array(var legs) = try r.rulePath("Grant", grantValue, "legs", context: grantContext) else { return XCTFail("legs") }
    legs[1] = replace("GrantLegRef", legs[1], "logical_role", .uint(0))
    let badLegs = replace("Grant", grantValue, "legs", .array(legs)).encoded()
    _ = try r.decode(badLegs, schema: "Grant", context: grantContext, cap: 65536)
    rejects("field_range") { _ = try r.variants(badLegs, schema: "Grant", context: grantContext, cap: 65536) }
  }

  // v4.swift_rules.full_width
  func testFullWidthTerminalAndDurationRelations() throws {
    let r = Self.reference
    let drained = Self.corpus.first { $0["schema"].text == "STREAM_ACK_DRAINED" && $0["expected_error"].text == nil }!, ctx = context(drained)
    var value = try r.relations(bytes(drained), schema: "STREAM_ACK_DRAINED", context: ctx, cap: 65536)
    let tuple = try r.rulePath("STREAM_ACK_DRAINED", value, "terminal_tuple", context: ctx)!
    value = replace("STREAM_ACK_DRAINED", value, "terminal_tuple", replace("terminal_tuple", tuple, "next_sequence", .uint(UInt64.max - 1)))
    value = replace("STREAM_ACK_DRAINED", value, "observed_tuple", replace("terminal_tuple", tuple, "next_sequence", .uint(UInt64.max)))
    for (outcome, error) in [(UInt64(1), "field_order"), (UInt64(0), "field_equality")] {
      let raw = replace("STREAM_ACK_DRAINED", value, "outcome", .uint(outcome)).encoded()
      _ = try r.decode(raw, schema: "STREAM_ACK_DRAINED", context: ctx, cap: 65536)
      rejects(error) { _ = try r.variants(raw, schema: "STREAM_ACK_DRAINED", context: ctx, cap: 65536) }
    }
    let vector = seed("tls_pin_full_window"), tlsContext = context(vector)
    let pin = try r.relations(bytes(vector), schema: "TLSPin", context: tlsContext, cap: 65536)
    let limit = r.registry["relation_rules"]["TLSPin"].array!.first { $0["op"].text == "max_difference" }!["max"].uint!
    for (before, after, error) in [(UInt64.max - limit, UInt64.max, Optional<String>.none), (UInt64.max - limit - 1, UInt64.max, "field_duration"), (UInt64.max, UInt64(1), "field_order")] {
      let raw = replace("TLSPin", replace("TLSPin", pin, "not_before_ms", .uint(before)), "not_after_ms", .uint(after)).encoded()
      _ = try r.variants(raw, schema: "TLSPin", context: tlsContext, cap: 65536)
      if let error { rejects(error) { _ = try r.relations(raw, schema: "TLSPin", context: tlsContext, cap: 65536) } }
      else { XCTAssertEqual(try r.relations(raw, schema: "TLSPin", context: tlsContext, cap: 65536).encoded(), raw) }
    }
  }

  // v4.swift_rules.signed_bytes
  func testEmbeddedDigestIncludesOriginalCertificateSignature() throws {
    let r = Self.reference, vector = seed("hop_endpoint_hello_fields"), ctx = context(vector)
    let hello = try r.relations(bytes(vector), schema: "HOP_AUTH_HELLO", context: ctx, cap: 65536)
    guard case .bytes(let raw) = try r.rulePath("HOP_AUTH_HELLO", hello, "identity_certificate", context: ctx) else { return XCTFail("certificate") }
    let certificate = try r.decode(raw, schema: "IdentityCertificate", context: ctx, cap: 65536)
    guard case .bytes(var signature) = try r.rulePath("IdentityCertificate", certificate, "signature", context: ctx) else { return XCTFail("signature") }
    signature[0] ^= 1
    let changed = replace("IdentityCertificate", certificate, "signature", .bytes(signature)).encoded()
    let wire = replace("HOP_AUTH_HELLO", hello, "identity_certificate", .bytes(changed)).encoded()
    _ = try r.variants(wire, schema: "HOP_AUTH_HELLO", context: ctx, cap: 65536)
    rejects("map_digest_mismatch") { _ = try r.relations(wire, schema: "HOP_AUTH_HELLO", context: ctx, cap: 65536) }
  }

  // v4.swift_rules.properties
  func testMutatedVariantsAndRelationsPreserveBytesAndContext() throws {
    var state: UInt64 = 0x41a1141a1141a114
    func next() -> UInt64 { state = state &* 6364136223846793005 &+ 1442695040888963407; return state ^ (state >> 31) }
    for _ in 0..<4096 {
      let vector = Self.corpus[Int(next() % UInt64(Self.corpus.count))]
      var raw = try bytes(vector)
      if !raw.isEmpty { let at = Int(next() % UInt64(raw.count)); raw[at] ^= UInt8(truncatingIfNeeded: next()) }
      let ctx = context(vector), before = ctx, name = vector["schema"].text ?? ""
      for relation in [false, true] {
        let result = try? relation ? Self.reference.relations(raw, schema: name, context: ctx, cap: UInt64(raw.count) + 1) : Self.reference.variants(raw, schema: name, context: ctx, cap: UInt64(raw.count) + 1)
        if let result { XCTAssertEqual(result.encoded(), raw) }
        XCTAssertEqual(ctx, before)
      }
    }
  }
}
