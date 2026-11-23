import Foundation
import XCTest
@testable import Flowersec

final class TransportV4OracleTests: XCTestCase {
  private static let reference = try! V4TextReference()
  private static let corpus: [V4JSON] = {
    let raw = try! Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/corpus.json"))
    let corpus = try! JSONDecoder().decode(V4JSON.self, from: raw)
    precondition(corpus["schema_sha256"].text == TransportV4Registry.schemaSHA256)
    return corpus["vectors"].array!
  }()
  private func seed(_ id: String) -> V4JSON { Self.corpus.first { $0["id"].text == id }! }
  private func bytes(_ vector: V4JSON) throws -> Data { try v4RuleHex(vector["hex"].text!) }
  private func poolSeed(_ id: String) throws -> (Data, [UInt64]) {
    let derivation = seed(id)["pool_derivation"]
    return try (v4RuleHex(derivation["artifact_hex"].text!), derivation["indices"].array!.map { $0.uint! })
  }
  private func context(_ vector: V4JSON) -> V4CBORContext {
    var context = V4CBORContext()
    for (key, value) in vector["limits"].object ?? [:] {
      if case .uint(let n) = value { context.limits[key] = n }
      if case .text(let text) = value { context.selectors[key] = text }
    }
    return context
  }
  private func replace(_ name: String, _ value: V4CBORValue, _ field: String, _ replacement: V4CBORValue) throws -> V4CBORValue {
    let id = try Self.reference.shape.namedField(name, field).0
    guard case .map(var pairs) = value else { throw V4CBORFailure("map_type") }
    let index = pairs.firstIndex { if case .uint(let key) = $0.key { return key == id }; return false }!
    pairs[index].value = replacement; return .map(pairs)
  }
  private func rejects(_ expected: String? = nil, file: StaticString = #filePath, line: UInt = #line, _ operation: () throws -> Void) {
    XCTAssertThrowsError(try operation(), file: file, line: line) { error in
      if let expected { XCTAssertEqual((error as? V4CBORFailure)?.code, expected, file: file, line: line) }
    }
  }
  private func receive(_ raw: Data, _ vector: V4JSON) throws -> V4CBORValue {
    let r = Self.reference, name = vector["schema"].text ?? ""
    let value = try r.wireMap(raw, schema: name, context: context(vector), cap: UInt64(raw.count) + 1)
    if let pool = vector.object?["pool_derivation"] {
      XCTAssertEqual(name, "PoolSelectionSet")
      let artifact = try v4RuleHex(pool["artifact_hex"].text!), indices = pool["indices"].array!.map { $0.uint! }
      _ = try r.verifyPoolSet(artifact, indices: indices, received: raw, cap: UInt64(max(artifact.count, raw.count)) + 1)
    }
    if name == "OPEN_STREAM" {
      let digest = try r.shape.openDigest(value)
      guard case .bytes(let actual) = try r.shape.namedValue(name, value, "open_digest"), actual == digest else { throw V4CBORFailure("open_digest_mismatch") }
    }
    return value
  }

  // v4.swift_oracles.corpus
  func testCompleteCorpusWithExternalComposition() throws {
    var positive = 0, negative = 0, pools = 0, opens = 0
    for vector in Self.corpus {
      let raw = try bytes(vector), id = vector["id"].text!
      if let error = vector["expected_error"].text {
        negative += 1
        rejects(["pool_set_membership", "open_digest_mismatch"].contains(error) ? error : nil) { _ = try receive(raw, vector) }
      } else {
        positive += 1
        XCTAssertEqual(try receive(raw, vector).encoded(), raw, id)
      }
      if vector.object?["pool_derivation"] != nil { pools += 1 }
      if vector["schema"].text == "OPEN_STREAM" { opens += 1 }
    }
    XCTAssertEqual(positive, 337); XCTAssertEqual(negative, 828)
    XCTAssertGreaterThan(pools, 0); XCTAssertGreaterThan(opens, 0)
  }

  // v4.swift_oracles.open_digest
  func testOPENExactGeneratedProjection() throws {
    let r = Self.reference, vector = seed("open_fields"), raw = try bytes(vector)
    let value = try receive(raw, vector), digest = try r.shape.openDigest(value)
    for descriptor in r.shape.registry["frame_maps"]["OPEN_STREAM"]["fields"].object!.values {
      let field = descriptor["name"].text!, original = try r.shape.namedValue("OPEN_STREAM", value, field)!
      let replacement: V4CBORValue
      switch original {
      case .uint(let n): replacement = .uint(n ^ 1)
      case .bytes(let raw): replacement = .bytes(raw + Data([120]))
      case .text: replacement = .text("changed")
      default: return XCTFail("uncovered OPEN field")
      }
      // Isolate the digest projection; mutations may fail earlier receive gates.
      let changed = try replace("OPEN_STREAM", value, field, replacement)
      XCTAssertEqual(try r.shape.openDigest(changed) == digest, field == "open_digest", field)
    }
    for (domain, schema, projection) in [("open_digest", "OPEN_STREAM", "full"), ("route_digest", "Artifact", "full"), ("artifact_signature", "Artifact", "full")] {
      rejects("domain_projection") { _ = try v4SingleMapHash(domain, schema: schema, projection: projection, input: raw) }
    }
  }

  // v4.swift_oracles.pool_domains
  func testPoolDomainsMatchSixSharedOutputs() throws {
    let raw = try Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/domains.json"))
    let domains = try JSONDecoder().decode(V4JSON.self, from: raw)
    XCTAssertEqual(domains["schema_sha256"].text, TransportV4Registry.schemaSHA256)
    var comparisons = 0
    for id in ["pool_set_one", "pool_set_two", "pool_set_sixteen"] {
      let (artifact, indices) = try poolSeed(id)
      let result = try Self.reference.derivePool(artifact, indices: indices, cap: UInt64(artifact.count))
      XCTAssertNotEqual(result.candidateSetDigest, result.routeSetDigest)
      XCTAssertEqual(result.encoded, try bytes(seed(id)))
      for (name, digest) in [("candidate_set_digest", result.candidateSetDigest), ("route_set_digest", result.routeSetDigest)] {
        let matches = try domains["vectors"].array!.filter { vector in
          guard vector["domain"].text == name else { return false }
          return try v4RuleHex(vector["inputs"]["selection"]["$bytes"].text!) == result.encoded
        }
        XCTAssertEqual(matches.count, 1)
        XCTAssertEqual(digest, try v4RuleHex(matches[0]["result"]["output_hex"].text!)); comparisons += 1
      }
    }
    XCTAssertEqual(comparisons, 6)
  }

  // v4.swift_oracles.pool_boundaries
  func testOriginalIndicesMembershipAndDetachedResults() throws {
    let r = Self.reference
    var (artifact, indices) = try poolSeed("pool_set_two")
    let cap = UInt64(artifact.count), result = try r.derivePool(artifact, indices: indices, cap: cap)
    for invalid: [UInt64] in [[], [0, 0], [1, 0], [2], [16], [UInt64.max], Array(repeating: 0, count: 17)] {
      let original = invalid
      rejects { _ = try r.derivePool(artifact, indices: invalid, cap: cap) }
      XCTAssertEqual(invalid, original)
    }
    rejects("map_size") { _ = try r.derivePool(artifact, indices: indices, cap: cap - 1) }
    rejects("map_size") { _ = try r.verifyPoolSet(artifact, indices: indices, received: result.encoded, cap: UInt64(result.encoded.count) - 1) }
    for index in indices {
      _ = try r.derivePool(artifact, indices: [index], cap: cap)
      rejects("pool_set_membership") { _ = try r.verifyPoolSet(artifact, indices: [index], received: result.encoded, cap: cap) }
    }
    for field in ["artifact_digest", "candidate_id", "route_digest"] {
      var selection = try r.wireMap(result.encoded, schema: "PoolSelectionSet", cap: cap)
      if field == "artifact_digest" {
        var changed = result.artifactDigest; changed[0] ^= 0x80
        selection = try replace("PoolSelectionSet", selection, field, .bytes(changed))
      } else {
        guard case .array(var entries) = try r.shape.namedValue("PoolSelectionSet", selection, "entries"),
              case .bytes(var data) = try r.shape.namedValue("PoolRouteRef", entries[0], field) else { return XCTFail("entries") }
        data[0] ^= 0x80; entries[0] = try replace("PoolRouteRef", entries[0], field, .bytes(data))
        selection = try replace("PoolSelectionSet", selection, "entries", .array(entries))
      }
      let changed = selection.encoded()
      _ = try r.wireMap(changed, schema: "PoolSelectionSet", cap: cap)
      rejects("pool_set_membership") { _ = try r.verifyPoolSet(artifact, indices: indices, received: changed, cap: cap) }
    }
    for field in ["signature", "priority", "port"] {
      var value = try r.wireMap(artifact, schema: "Artifact", cap: cap)
      if field == "signature" {
        guard case .bytes(var signature) = try r.shape.namedValue("Artifact", value, field) else { return XCTFail("signature") }
        signature[0] ^= 1; value = try replace("Artifact", value, field, .bytes(signature))
      } else {
        guard case .array(var candidates) = try r.shape.namedValue("Artifact", value, "candidates") else { return XCTFail("candidates") }
        if field == "priority" {
          guard case .uint(let n) = try r.shape.namedValue("Candidate", candidates.last!, field) else { return XCTFail("priority") }
          candidates[candidates.count - 1] = try replace("Candidate", candidates.last!, field, .uint(n + 1))
        } else {
          let leg = try r.shape.namedValue("Candidate", candidates[0], "direct_leg")!
          guard case .uint(let port) = try r.shape.namedValue("Leg", leg, field) else { return XCTFail("port") }
          candidates[0] = try replace("Candidate", candidates[0], "direct_leg", replace("Leg", leg, field, .uint(port + 1)))
        }
        value = try replace("Artifact", value, "candidates", .array(candidates))
      }
      let changed = value.encoded(), derived = try r.derivePool(changed, indices: indices, cap: UInt64(changed.count))
      XCTAssertNotEqual(derived.artifactDigest, result.artifactDigest)
      XCTAssertEqual(derived.members[0].routeDigest != result.members[0].routeDigest, field == "port")
      rejects("pool_set_membership") { _ = try r.verifyPoolSet(changed, indices: indices, received: result.encoded, cap: UInt64(changed.count)) }
    }
    let snapshot = result
    artifact.resetBytes(in: 0..<artifact.count)
    XCTAssertEqual(result, snapshot)
  }

  // v4.swift_oracles.properties
  func testMutatedArtifactsIndicesAndReceivedMaps() throws {
    let r = Self.reference
    var state: UInt64 = 0x410ca410ca410ca4
    func next() -> UInt64 { state = state &* 6364136223846793005 &+ 1442695040888963407; return state ^ (state >> 31) }
    for _ in 0..<4096 {
      var (artifact, indices) = try poolSeed(["pool_set_one", "pool_set_two", "pool_set_sixteen"][Int(next() % 3)])
      if next() % 2 == 0 { let at = Int(next() % UInt64(artifact.count)); artifact[at] ^= UInt8(truncatingIfNeeded: next()) }
      if next() % 2 == 0 { indices = (0..<Int(next() % 18)).map { _ in next() % 256 } }
      if let result = try? r.derivePool(artifact, indices: indices, cap: 1 << 16) {
        XCTAssertEqual(try r.verifyPoolSet(artifact, indices: indices, received: result.encoded, cap: 1 << 16), result)
        XCTAssertEqual(result.members.map(\.index), indices)
        let snapshot = result; artifact.resetBytes(in: 0..<artifact.count); XCTAssertEqual(result, snapshot)
      }
      let vector = Self.corpus[Int(next() % UInt64(Self.corpus.count))]
      var raw = try bytes(vector)
      if !raw.isEmpty { let at = Int(next() % UInt64(raw.count)); raw[at] ^= UInt8(truncatingIfNeeded: next()) }
      if let value = try? receive(raw, vector) { XCTAssertEqual(value.encoded(), raw) }
    }
  }
}
