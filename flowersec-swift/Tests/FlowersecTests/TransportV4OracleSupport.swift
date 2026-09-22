import Crypto
import Foundation
@testable import Flowersec

// Stateless external composition only; no trust, admission or winner authority.
private enum V4MapDomains {
  static let registry = try! JSONDecoder().decode(V4JSON.self, from: Data(TransportV4Registry.domainRegistryJSON.utf8))
}

func v4SingleMapHash(_ name: String, schema: String, projection: String, input: Data) throws -> Data {
  guard let domain = V4MapDomains.registry.array?.first(where: { $0["name"].text == name }) else { throw V4CBORFailure("registry_unresolved") }
  guard let parts = domain["input_schema"]["parts"].array, domain["operation"].text == "sha256",
        domain["output_length"].uint == 32, parts.count == 1, parts[0]["encoding"].text == "lp-map",
        parts[0]["schema_ref"].text == schema, parts[0]["projection"].text == projection else { throw V4CBORFailure("domain_projection") }
  guard let label = domain["label_bytes"].text else { throw V4CBORFailure("registry_unresolved") }
  guard let length = UInt32(exactly: input.count) else { throw V4CBORFailure("map_size") }
  var big = length.bigEndian
  return try Data(SHA256.hash(data: v4RuleHex(label) + withUnsafeBytes(of: &big) { Data($0) } + input))
}

extension V4ShapeReference {
  func namedField(_ name: String, _ field: String) throws -> (UInt64, V4JSON) {
    guard let (key, descriptor) = try descriptor(name)["fields"].object?.first(where: { $0.value["name"].text == field }),
          let id = UInt64(key) else { throw V4CBORFailure("unknown_field") }
    return (id, descriptor)
  }

  func namedValue(_ name: String, _ value: V4CBORValue, _ field: String) throws -> V4CBORValue? {
    try value.field(namedField(name, field).0)
  }

  // Issuer construction orders generated IDs, never received candidate indices.
  func namedMap(_ name: String, _ fields: [(String, V4CBORValue?)]) throws -> V4CBORValue {
    var entries: [(UInt64, V4CBORValue)] = []
    for (field, value) in fields {
      let id = try namedField(name, field).0
      if let value { entries.append((id, value)) }
    }
    entries.sort { $0.0 < $1.0 }
    for index in entries.indices.dropFirst() {
      guard entries[index - 1].0 != entries[index].0 else { throw V4CBORFailure("duplicate_field") }
    }
    return .map(entries.map { .init(key: .uint($0.0), value: $0.1) })
  }

  // The caller validates complete OPEN before invoking its digest projection.
  func openDigest(_ value: V4CBORValue) throws -> Data {
    let id = try namedField("OPEN_STREAM", "open_digest").0
    guard case .map(let pairs) = value else { throw V4CBORFailure("map_type") }
    guard value.field(id) != nil else { throw V4CBORFailure("missing_field") }
    let unsigned = V4CBORValue.map(pairs.filter { if case .uint(let key) = $0.key { return key != id }; return true })
    return try v4SingleMapHash("open_digest", schema: "OPEN_STREAM", projection: "without_open_digest", input: unsigned.encoded())
  }
}

struct V4PoolMember: Equatable, Sendable {
  let index: UInt64
  let candidateID: Data
  let routeDigest: Data
}

struct V4PoolProjection: Equatable, Sendable {
  let encoded: Data
  let artifactDigest: Data
  let candidateSetDigest: Data
  let routeSetDigest: Data
  let members: [V4PoolMember]
}

extension V4TextReference {
  func projectCandidate(_ candidate: V4CBORValue) throws -> V4CBORValue {
    let projection = shape.registry["map_projections"]["candidate_route"]
    guard let source = projection["source"].text, let target = projection["target"].text,
          let fields = projection["fields"].array else { throw V4CBORFailure("projection_unresolved") }
    let input = candidate.encoded()
    _ = try wireMap(input, schema: source, cap: UInt64(input.count))
    let values = try fields.map { field -> (String, V4CBORValue?) in
      guard let field = field.text else { throw V4CBORFailure("projection_unresolved") }
      return (field, try shape.namedValue(source, candidate, field))
    }
    let result = try shape.namedMap(target, values), raw = result.encoded()
    _ = try wireMap(raw, schema: target, cap: UInt64(raw.count))
    return result
  }

  func derivePool(_ input: Data, indices: [UInt64], cap: UInt64) throws -> V4PoolProjection {
    let artifact = try wireMap(input, schema: "Artifact", cap: cap)
    let field = try shape.namedField("PoolSelectionRef", "candidate_indices").1
    // Bound the complete original index list before per-member state allocation.
    guard UInt64(indices.count) >= (try v4RuleInteger(field["min_items"])),
          UInt64(indices.count) <= (try v4RuleInteger(field["max_items"])) else { throw V4CBORFailure("array_length") }
    guard case .array(let candidates) = try shape.namedValue("Artifact", artifact, "candidates") else { throw V4CBORFailure("field_type") }
    var members: [V4PoolMember] = []; members.reserveCapacity(indices.count)
    for (position, index) in indices.enumerated() {
      try shape.checkField(field["items"], .uint(index), context: .init())
      guard position == 0 || indices[position - 1] < index else { throw V4CBORFailure("array_order") }
      guard index < UInt64(candidates.count) else { throw V4CBORFailure("pool_index_membership") }
      let candidate = candidates[Int(index)], route = try projectCandidate(candidate)
      let digest = try v4SingleMapHash("route_digest", schema: "Route", projection: "full", input: route.encoded())
      guard case .bytes(let id) = try shape.namedValue("Candidate", candidate, "candidate_id") else { throw V4CBORFailure("field_type") }
      // Explicitly copy public bytes; returned projections retain no Artifact backing.
      members.append(.init(index: index, candidateID: id.withUnsafeBytes { Data($0) }, routeDigest: digest))
    }
    let artifactDigest = try v4SingleMapHash("artifact_digest", schema: "Artifact", projection: "full", input: input)
    let entries = try members.map { member in
      try shape.namedMap("PoolRouteRef", [("candidate_index", .uint(member.index)), ("candidate_id", .bytes(member.candidateID)), ("route_digest", .bytes(member.routeDigest))])
    }
    let selection = try shape.namedMap("PoolSelectionSet", [("artifact_digest", .bytes(artifactDigest)), ("entries", .array(entries))])
    let encoded = selection.encoded()
    _ = try wireMap(encoded, schema: "PoolSelectionSet", cap: UInt64(encoded.count))
    return try V4PoolProjection(encoded: encoded, artifactDigest: artifactDigest,
                               candidateSetDigest: v4SingleMapHash("candidate_set_digest", schema: "PoolSelectionSet", projection: "full", input: encoded),
                               routeSetDigest: v4SingleMapHash("route_set_digest", schema: "PoolSelectionSet", projection: "full", input: encoded), members: members)
  }

  func verifyPoolSet(_ artifact: Data, indices: [UInt64], received: Data, cap: UInt64) throws -> V4PoolProjection {
    _ = try wireMap(received, schema: "PoolSelectionSet", cap: cap)
    let result = try derivePool(artifact, indices: indices, cap: cap)
    guard result.encoded == received else { throw V4CBORFailure("pool_set_membership") }
    return result
  }
}
