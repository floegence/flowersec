import Foundation
import XCTest
@testable import Flowersec

final class TransportV4ShapeTests: XCTestCase {
  private static let reference = try! V4ShapeReference()
  private static let corpus: [V4JSON] = {
    let data = try! Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/corpus.json"))
    let corpus = try! JSONDecoder().decode(V4JSON.self, from: data)
    precondition(corpus["schema_sha256"].text == TransportV4Registry.schemaSHA256)
    return corpus["vectors"].array!
  }()

  private func bytes(_ vector: V4JSON) -> Data {
    let bytes = Array(vector["hex"].text!.utf8)
    precondition(bytes.count.isMultiple(of: 2))
    return Data(stride(from: 0, to: bytes.count, by: 2).map {
      UInt8(String(decoding: bytes[$0...$0 + 1], as: UTF8.self), radix: 16)!
    })
  }

  private func context(_ vector: V4JSON) -> V4CBORContext {
    var context = V4CBORContext()
    for (key, value) in vector["limits"].object ?? [:] {
      if case .uint(let n) = value { context.limits[key] = n }
      if case .text(let s) = value { context.selectors[key] = s }
    }
    return context
  }

  private func seed(_ id: String) -> V4JSON { Self.corpus.first { $0["id"].text == id }! }

  private func fieldID(_ schema: String, _ name: String) -> UInt64 {
    UInt64(Self.reference.registry["frame_maps"][schema]["fields"].object!.first { $0.value["name"].text == name }!.key)!
  }

  private func replace(_ value: V4CBORValue, _ id: UInt64, _ replacement: V4CBORValue) -> V4CBORValue {
    guard case .map(var pairs) = value else { preconditionFailure("map required") }
    let index = pairs.firstIndex { if case .uint(let key) = $0.key { return key == id }; return false }!
    pairs[index].value = replacement
    return .map(pairs)
  }

  private func rejects(_ expected: String? = nil, file: StaticString = #filePath, line: UInt = #line, _ operation: () throws -> Void) {
    XCTAssertThrowsError(try operation(), file: file, line: line) { error in
      if let expected { XCTAssertEqual((error as? V4CBORFailure)?.code, expected, file: file, line: line) }
    }
  }

  // v4.swift_shape.corpus
  func testSharedFieldShapeCorpus() throws {
    let errors: Set<String> = ["unknown_field", "missing_field", "integer_type", "integer_range", "constant_mismatch", "field_type", "field_length", "field_nonzero", "text_pattern", "reserved_namespace", "enum_value", "unknown_bits", "map_type", "map_length", "array_length", "map_size"]
    var positive = 0, negative = 0
    for vector in Self.corpus {
      // These names overlap field errors but require the separate variant layer.
      if ["admission_rejected_unknown_code", "context_auth_exporter_bytes"].contains(vector["id"].text!) { continue }
      if let expected = vector["expected_error"].text, !errors.contains(expected) { continue }
      let input = bytes(vector), ctx = context(vector), original = ctx, id = vector["id"].text!
      do {
        let decoded = try Self.reference.decode(input, schema: vector["schema"].text ?? "", context: ctx, cap: UInt64(input.count) + 1)
        XCTAssertNil(vector["expected_error"].text, "accepted \(id)")
        XCTAssertEqual(decoded.encoded(), input, id)
      } catch {
        XCTAssertNotNil(vector["expected_error"].text, "\(id): \(error)")
      }
      XCTAssertEqual(ctx, original, id)
      if vector["expected_error"].text == nil { positive += 1 } else { negative += 1 }
    }
    XCTAssertEqual(positive, 337); XCTAssertEqual(negative, 324)
    print("Swift field shape: \(positive) positive / \(negative) negative cases")
  }

  // v4.swift_shape.required_unknown
  func testEveryCorpusRootRejectsMissingAndUnknownFields() throws {
    var seen = Set<String>()
    let r = Self.reference
    for vector in Self.corpus {
      guard let name = vector["schema"].text, vector["expected_error"].text == nil, seen.insert(name).inserted else { continue }
      let input = bytes(vector), ctx = context(vector)
      guard case .map(let pairs) = try r.decode(input, schema: name, context: ctx, cap: UInt64(input.count) + 1) else { return XCTFail(name) }
      let descriptor = try r.descriptor(name)
      for id in descriptor["required"].array! {
        let changed = V4CBORValue.map(pairs.filter { if case .uint(let key) = $0.key { return key != id.uint! }; return true })
        rejects { try r.checkMap(name, changed, context: ctx) }
      }
      XCTAssertNil(descriptor["fields"].object?["65535"])
      let changed = V4CBORValue.map(pairs + [.init(key: .uint(65535), value: .uint(0))])
      rejects("unknown_field") { try r.checkMap(name, changed, context: ctx) }
    }
    XCTAssertEqual(seen.count, 93)
  }

  // v4.swift_shape.context_boundaries
  func testExplicitContextAndFullWidthBoundaries() throws {
    let r = Self.reference, rekey = seed("rekey_init_fields"), input = bytes(rekey)
    rejects("context_unresolved") { _ = try r.decode(input, schema: "REKEY_INIT", cap: 65536) }
    var ctx = context(rekey)
    ctx.selectors["crypto_profile_id"] = "unknown"
    rejects("context_unresolved") { _ = try r.decode(input, schema: "REKEY_INIT", context: ctx, cap: 65536) }
    let (p256, profile) = r.registry["field_registries"]["crypto_profiles"].object!.first { $0.value["dh_algorithm"].uint == 1 }!
    ctx.selectors["crypto_profile_id"] = p256
    rejects("field_length") { _ = try r.decode(input, schema: "REKEY_INIT", context: ctx, cap: 65536) }
    let value = try r.decode(input, schema: "REKEY_INIT", context: context(rekey), cap: 65536)
    let keyID = fieldID("REKEY_INIT", "client_ephemeral")
    var publicKey = Data(repeating: 0, count: Int(profile["dh_public_bytes"].uint!))
    publicKey[0] = 3
    rejects("field_prefix") { try r.checkMap("REKEY_INIT", replace(value, keyID, .bytes(publicKey)), context: ctx) }
    // Correct prefix/length establishes shape only, not curve validity.
    publicKey[0] = 4
    try r.checkMap("REKEY_INIT", replace(value, keyID, .bytes(publicKey)), context: ctx)
    let pool = seed("activation_pool_fields")
    rejects("context_unresolved") { _ = try r.decode(bytes(pool), schema: "ActivationAuthorization", cap: 65536) }
    var wrong = context(pool)
    wrong.selectors["activation_source_profile"] = "live_authority"
    rejects { _ = try r.decode(bytes(pool), schema: "ActivationAuthorization", context: wrong, cap: 65536) }
    let owner = try r.decode(bytes(seed("topup_owner_proof_fields")), schema: "OwnerFenceProof", cap: 65536)
    for text in ["Tenant", "tenant\n", "tenant\0", "ténant"] {
      rejects("text_pattern") { try r.checkMap("OwnerFenceProof", replace(owner, fieldID("OwnerFenceProof", "tenant_id"), .text(text)), context: .init()) }
    }
    let maximum = replace(owner, fieldID("OwnerFenceProof", "expires_at_ms"), .uint(UInt64.max)).encoded()
    XCTAssertEqual(try r.decode(maximum, schema: "OwnerFenceProof", cap: 65536).encoded(), maximum)
    // A valid containing discriminator overrides stale caller context locally.
    for vector in Self.corpus where vector["expected_error"].text == nil {
      guard let name = vector["schema"].text,
            let selectors = r.registry["frame_maps"][name]["context_fields"].object, !selectors.isEmpty else { continue }
      var caller = context(vector)
      for key in selectors.keys { caller.selectors[key] = "invalid_external_selector" }
      let before = caller, raw = bytes(vector)
      XCTAssertEqual(try r.decode(raw, schema: name, context: caller, cap: UInt64(raw.count) + 1).encoded(), raw, name)
      XCTAssertEqual(caller, before, name)
    }
  }

  // v4.swift_shape.properties
  func testMutatedInputsRejectOrPreserveOriginalBytesAndContext() throws {
    var state: UInt64 = 0x41f1e1d41f1e1d41
    func next() -> UInt64 { state = state &* 6364136223846793005 &+ 1442695040888963407; return state ^ (state >> 31) }
    for _ in 0..<4096 {
      let vector = Self.corpus[Int(next() % UInt64(Self.corpus.count))]
      var input = bytes(vector)
      if !input.isEmpty { let at = Int(next() % UInt64(input.count)); input[at] ^= UInt8(truncatingIfNeeded: next()) }
      let ctx = context(vector), before = ctx
      if let result = try? Self.reference.decode(input, schema: vector["schema"].text ?? "", context: ctx, cap: UInt64(input.count) + 1) {
        XCTAssertEqual(result.encoded(), input)
      }
      XCTAssertEqual(ctx, before)
    }
  }
}
