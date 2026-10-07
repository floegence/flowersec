#if os(macOS) || os(iOS)
import Foundation

/// An immutable pending intent. Generation and owner proof belong to a physical
/// transmission and are excluded from its registered request digest.
struct V4PoolRefillIntent: Sendable, Equatable {
  let operation: Data
  let tenant: String
  let source: Data
  let desired: UInt64
  let maximumItemBytes: UInt64
  let pool: Data
  let deadlineMS: UInt64
  let identity: Data
  var sequence: UInt64 { operation.suffix(8).reduce(0) { ($0 << 8) | UInt64($1) } }
  private func uint(_ value: UInt64) -> Data { V4NamespaceValue.head(0, value) }
  func fields() throws -> [(UInt64, Data)] {
    guard operation.count == 16, sequence > 0, source.count == 16, source.contains(where: { $0 != 0 }),
      V4NamespaceRegistry.securityID(tenant.utf8), (1...4).contains(desired), (1...65_536).contains(maximumItemBytes),
      pool.count == 32, identity.count == 32, deadlineMS > 0 else { throw V4PoolFailure.configuration }
    return [(0, V4Crypto.bytes(operation)), (1, V4Crypto.text(tenant)), (2, V4Crypto.bytes(source)),
      (3, uint(desired)), (4, uint(maximumItemBytes)), (5, V4Crypto.bytes(pool)),
      (8, uint(deadlineMS)), (9, V4Crypto.bytes(identity))]
  }
  func encoded() throws -> Data { try V4PoolRefillWire.map(fields()) }
  func digest() throws -> Data { try V4Crypto.hash(encoded()) }
  static func decode(_ bytes: Data) throws -> Self {
    var reader = V4PoolWireCursor(bytes, maximum: 4096)
    try reader.map(8)
    try reader.key(0); let operation = try reader.bytes(maximum: 16)
    try reader.key(1); let tenant = try reader.text(maximum: 128)
    try reader.key(2); let source = try reader.bytes(maximum: 16)
    try reader.key(3); let desired = try reader.uint()
    try reader.key(4); let maximum = try reader.uint()
    try reader.key(5); let pool = try reader.bytes(maximum: 32)
    try reader.key(8); let deadline = try reader.uint()
    try reader.key(9); let identity = try reader.bytes(maximum: 32)
    try reader.end()
    let value = Self(operation: operation, tenant: tenant, source: source, desired: desired,
      maximumItemBytes: maximum, pool: pool, deadlineMS: deadline, identity: identity)
    guard try value.encoded() == bytes else { throw V4PoolFailure.storage }
    return value
  }
}

struct V4PoolRefillResponse: Sendable {
  struct Entry: Sendable {
    let sequence: UInt64
    let expiry: UInt64
    let material: Data
  }
  let wire: Data
  let digest: Data
  let generation: UInt64
  let highest: UInt64
  let gap: Bool
  let retired: UInt64?
  let entries: [Entry]
}

struct V4PoolRefillTerminal: Sendable, Equatable {
  let wire: Data
  let code: String
  let retired: Bool
  let permanent: Bool
  let highest: UInt64
  let retiredArtifact: UInt64
  let bindingGeneration: UInt64
  let responseFacts: Data
  let receipt: Data
}

struct V4PoolControlReply: Sendable {
  let code: String
  let response: Data
  // Terminal/fence receipts remain original authenticated wire. No local
  // projection can convert an unknown batch into a committed or retired one.
  let terminal: Data
  let fence: Data
}

enum V4PoolRefillWire {
  private static func uint(_ value: UInt64) -> Data { V4NamespaceValue.head(0, value) }
  static func map(_ fields: [(UInt64, Data)]) -> Data {
    var output = V4NamespaceValue.head(5, UInt64(fields.count))
    for (key, value) in fields.sorted(by: { $0.0 < $1.0 }) { output.append(uint(key)); output.append(value) }
    return output
  }
  static func request(_ intent: V4PoolRefillIntent, generation: UInt64, proof: Data) throws -> Data {
    guard generation > 0, (1...512).contains(proof.count) else { throw V4PoolFailure.configuration }
    return try map(intent.fields() + [(6, uint(generation)), (7, V4Crypto.bytes(proof))])
  }
  static func ack(_ intent: V4PoolRefillIntent, response: V4PoolRefillResponse,
    generation: UInt64, proof: Data) throws -> Data {
    guard generation > 0, (1...512).contains(proof.count) else { throw V4PoolFailure.configuration }
    var fields: [(UInt64, Data)] = [(0, V4Crypto.bytes(intent.operation)), (1, V4Crypto.bytes(intent.pool)),
      (2, V4Crypto.bytes(response.digest)), (3, uint(response.highest)), (4, Data([response.gap ? 0xf5 : 0xf4])),
      (6, Data([0xf5])), (7, V4Crypto.bytes(try intent.digest())), (8, uint(generation)), (9, V4Crypto.bytes(proof))]
    if let retired = response.retired { fields.append((5, uint(retired))) }
    return map(fields)
  }
  static func reply(_ bytes: Data, applicationError: Bool) throws -> V4PoolControlReply {
    var reader = V4PoolWireCursor(bytes, maximum: 524_288)
    try reader.array(4)
    let code = try reader.text(maximum: 64)
    let response = try reader.bytes(maximum: 524_288)
    let terminal = try reader.finiteArray(maximumItems: 32, maximumBytes: 8192)
    let fence = try reader.finiteArray(maximumItems: 3, maximumBytes: 512)
    try reader.end()
    let absent = Data([0x80])
    let success = code == "success" || code == "replay"
    let errors: Set<String> = ["source_exhausted", "source_unavailable", "source_contract_invalid", "source_state_unknown",
      "operation_conflict", "stale_generation", "future_generation", "stale_operation", "future_operation", "sequence_gap",
      "configuration_capacity", "capacity_exhausted", "relink_required", "spent_unknown", "top_up_request_expired", "source_reset_required", "permission_denied"]
    guard success || (errors.contains(code) && response.isEmpty && (terminal == absent || fence == absent))
    else { throw TransportControlError.responseInvalid }
    guard success != applicationError, !success || (terminal == absent && fence == absent)
    else { throw TransportControlError.responseInvalid }
    let terminalCodes: Set<String> = ["configuration_capacity", "capacity_exhausted", "relink_required",
      "spent_unknown", "top_up_request_expired", "source_reset_required"]
    guard terminal == absent || terminalCodes.contains(code), fence == absent || code == "source_reset_required"
    else { throw TransportControlError.responseInvalid }
    return V4PoolControlReply(code: code, response: response, terminal: terminal, fence: fence)
  }
  static func response(_ bytes: Data, intent: V4PoolRefillIntent, originalGeneration: UInt64,
    previousHighest: UInt64, registry: V4NamespaceRegistry) throws -> V4PoolRefillResponse {
    _ = try intent.fields()
    guard originalGeneration > 0 else { throw TransportControlError.responseInvalid }
    let value = try V4NamespaceDocument(bytes, schema: "TopUpResponse", bytes: 524_288,
      nodes: 128, registry: registry).root
    guard try value.b("operation_id") == intent.operation, try value.t("tenant_id") == intent.tenant,
      try value.b("source_incarnation") == intent.source, try value.u("binding_generation") == originalGeneration,
      try value.field("server_committed").equals(true),
      try value.b("response_digest") == V4Crypto.hash(value.excluding(9))
    else { throw TransportControlError.responseInvalid }
    let gap = try value.field("gap_authorized").equals(true)
    let retired = try value.optional("retired_artifact_through")?.uint()
    guard gap == (retired != nil), previousHighest < .max else { throw TransportControlError.responseInvalid }
    let first: UInt64
    if let retired { guard retired >= previousHighest, retired < .max else { throw TransportControlError.responseInvalid }; first = retired + 1 }
    else { first = previousHighest + 1 }
    var entries: [V4PoolRefillResponse.Entry] = []
    for entry in try value.field("entries").children {
      let material = try entry.b("material")
      let number = first.addingReportingOverflow(UInt64(entries.count))
      guard !number.overflow, try entry.u("artifact_sequence") == number.partialValue,
        try entry.u("binding_generation") == originalGeneration, try entry.b("client_identity_digest") == intent.identity,
        try entry.b("material_digest") == V4Crypto.hash(material),
        !material.isEmpty, UInt64(V4Crypto.bytes(material).count) <= intent.maximumItemBytes
      else { throw TransportControlError.responseInvalid }
      entries.append(.init(sequence: number.partialValue, expiry: try entry.u("expiry_ms"), material: material))
    }
    guard entries.count == Int(intent.desired), let last = entries.last,
      try value.u("server_highest_artifact_sequence") == last.sequence else { throw TransportControlError.responseInvalid }
    return V4PoolRefillResponse(wire: bytes, digest: try value.b("response_digest"), generation: originalGeneration,
      highest: last.sequence, gap: gap, retired: retired, entries: entries)
  }
  static func terminal(_ reply: V4PoolControlReply, original: V4PoolRefillJournal.Recovery,
    currentGeneration: UInt64, registry: V4NamespaceRegistry) throws -> V4PoolRefillTerminal? {
    let codes: Set<String> = ["configuration_capacity", "capacity_exhausted", "relink_required", "spent_unknown", "top_up_request_expired", "source_reset_required"]
    let receipt = V4NamespaceValue.head(4, 4) + V4Crypto.text(reply.code) + V4Crypto.bytes(reply.response)
      + reply.terminal + reply.fence
    if reply.terminal == Data([0x80]) {
      if reply.fence == Data([0x80]) { return nil }
      guard reply.code == "source_reset_required", reply.response.isEmpty else { throw TransportControlError.responseInvalid }
      var fence = V4PoolWireCursor(reply.fence, maximum: 512)
      try fence.array(3)
      guard try fence.text(maximum: 128) == original.intent.tenant,
        try fence.bytes(maximum: 16) == original.intent.source else { throw TransportControlError.responseInvalid }
      let generation = try fence.uint(); try fence.end()
      guard generation > 0, generation <= currentGeneration else { throw TransportControlError.responseInvalid }
      return V4PoolRefillTerminal(wire: reply.fence, code: reply.code, retired: false, permanent: true,
        highest: original.previousHighest, retiredArtifact: 0, bindingGeneration: generation,
        responseFacts: Data([0x80]), receipt: receipt)
    }
    guard codes.contains(reply.code), reply.response.isEmpty, reply.fence == Data([0x80]) else { throw TransportControlError.responseInvalid }
    let intent = original.intent
    var reader = V4PoolWireCursor(reply.terminal, maximum: 8192)
    try reader.array(9); try reader.array(10)
    guard try reader.text(maximum: 128) == intent.tenant, try reader.bytes(maximum: 16) == intent.source,
      try reader.bytes(maximum: 16) == intent.operation, try reader.bytes(maximum: 32) == intent.pool,
      try reader.bytes(maximum: 32) == intent.identity, try reader.bytes(maximum: 32) == intent.digest(),
      try reader.uint() == original.generation, try reader.uint() == intent.deadlineMS,
      try reader.uint() == intent.desired, try reader.uint() == intent.maximumItemBytes
    else { throw TransportControlError.responseInvalid }
    let state = try reader.text(maximum: 16)
    let binding = try reader.uint(); let next = try reader.uint(); let retiredSequence = try reader.uint()
    let highest = try reader.uint(); let retiredArtifact = try reader.uint(); let permanent = try reader.boolean()
    let facts = try reader.finiteArray(maximumItems: 6, maximumBytes: 4096)
    try reader.end()
    guard ["terminal", "retired"].contains(state), binding >= original.generation, binding <= currentGeneration,
      intent.sequence < .max, next == intent.sequence + 1, retiredArtifact <= highest,
      highest >= original.previousHighest,
      (state == "retired" ? retiredSequence == intent.sequence : (retiredSequence < .max && retiredSequence + 1 == intent.sequence && !permanent))
    else { throw TransportControlError.responseInvalid }
    if facts != Data([0x80]) {
      guard reply.code == "source_reset_required" else { throw TransportControlError.responseInvalid }
      // A pending operation may have committed remotely before its response was
      // lost. Validate detached facts without installing or acquiring material.
      var comparison = V4PoolWireCursor(facts, maximum: 4096)
      try comparison.array(6)
      let responseGeneration = try comparison.uint(); let responseHighest = try comparison.uint()
      let responseRetired = try comparison.uint(); let responseGap = try comparison.boolean()
      let responseDigest = try comparison.bytes(maximum: 32)
      guard responseGeneration == original.generation, responseHighest == highest,
        responseDigest.count == 32, responseDigest.contains(where: { $0 != 0 }),
        responseGap || responseRetired == 0, !responseGap || responseRetired < .max
      else { throw TransportControlError.responseInvalid }
      try comparison.array(intent.desired)
      var previous: UInt64 = 0
      for index in 0..<Int(intent.desired) {
        try comparison.array(5)
        let sequence = try comparison.uint()
        guard sequence > 0, index == 0 || (previous < .max && sequence == previous + 1),
          index != 0 || !responseGap || sequence == responseRetired + 1,
          try comparison.uint() == original.generation else { throw TransportControlError.responseInvalid }
        _ = try comparison.uint()
        guard try comparison.bytes(maximum: 32).count == 32,
          try comparison.bytes(maximum: 32) == intent.identity else { throw TransportControlError.responseInvalid }
        previous = sequence
      }
      try comparison.end()
      guard previous == responseHighest else { throw TransportControlError.responseInvalid }
      if !original.response.isEmpty {
        let installed = try response(original.response, intent: intent, originalGeneration: original.generation,
          previousHighest: original.previousHighest, registry: registry)
        guard responseFacts(installed, identity: intent.identity) == facts else { throw TransportControlError.responseInvalid }
      }
    } else { guard original.response.isEmpty else { throw TransportControlError.responseInvalid } }
    return V4PoolRefillTerminal(wire: reply.terminal, code: reply.code, retired: state == "retired",
      permanent: permanent, highest: highest, retiredArtifact: retiredArtifact, bindingGeneration: binding,
      responseFacts: facts, receipt: receipt)
  }
  private static func responseFacts(_ response: V4PoolRefillResponse, identity: Data) -> Data {
    var wire = V4NamespaceValue.head(4, 6) + uint(response.generation) + uint(response.highest)
      + uint(response.retired ?? 0) + Data([response.gap ? 0xf5 : 0xf4]) + V4Crypto.bytes(response.digest)
      + V4NamespaceValue.head(4, UInt64(response.entries.count))
    for entry in response.entries {
      wire.append(V4NamespaceValue.head(4, 5) + uint(entry.sequence) + uint(response.generation)
        + uint(entry.expiry) + V4Crypto.bytes(V4Crypto.hash(entry.material)) + V4Crypto.bytes(identity))
    }
    return wire
  }
  static func directCredential(_ bytes: Data) throws -> TransportPoolCredential {
    try V4PoolMaterialBundle.decode(bytes).credential()
  }
}

/// A small canonical cursor for the fixed application envelopes. It cannot
/// allocate a peer-selected object graph or accept indefinite CBOR values.
struct V4PoolWireCursor {
  private let input: Data
  private let maximum: Int
  private var offset = 0
  init(_ input: Data, maximum: Int) { self.input = input; self.maximum = maximum }
  private mutating func head() throws -> (UInt8, UInt64) {
    guard input.count <= maximum, offset < input.count else { throw TransportControlError.responseInvalid }
    let initial = input[input.startIndex + offset]; offset += 1
    let tag = initial & 31
    if tag < 24 { return (initial >> 5, UInt64(tag)) }
    let count: Int
    switch tag { case 24: count = 1; case 25: count = 2; case 26: count = 4; case 27: count = 8; default: throw TransportControlError.responseInvalid }
    guard count <= input.count - offset else { throw TransportControlError.responseInvalid }
    var value: UInt64 = 0
    for _ in 0..<count { value = (value << 8) | UInt64(input[input.startIndex + offset]); offset += 1 }
    let minimum: UInt64 = count == 1 ? 24 : count == 2 ? 256 : count == 4 ? 65_536 : 4_294_967_296
    guard value >= minimum else { throw TransportControlError.responseInvalid }
    return (initial >> 5, value)
  }
  mutating func boolean() throws -> Bool { let (major, value) = try head(); guard major == 7, value == 20 || value == 21 else { throw TransportControlError.responseInvalid }; return value == 21 }
  mutating func uint() throws -> UInt64 { let (major, value) = try head(); guard major == 0 else { throw TransportControlError.responseInvalid }; return value }
  mutating func key(_ expected: UInt64) throws { guard try uint() == expected else { throw TransportControlError.responseInvalid } }
  mutating func arrayCount(maximum: UInt64) throws -> UInt64 {
    let (major, count) = try head()
    guard major == 4, count <= maximum else { throw TransportControlError.responseInvalid }; return count
  }
  mutating func array(_ count: UInt64) throws { let (major, value) = try head(); guard major == 4, value == count else { throw TransportControlError.responseInvalid } }
  mutating func map(_ count: UInt64) throws { let (major, value) = try head(); guard major == 5, value == count else { throw TransportControlError.responseInvalid } }
  mutating func bytes(maximum: Int) throws -> Data { try string(major: 2, maximum: maximum) }
  mutating func text(maximum: Int) throws -> String {
    let bytes = try string(major: 3, maximum: maximum)
    guard let value = String(data: bytes, encoding: .utf8) else { throw TransportControlError.responseInvalid }
    return value
  }
  private mutating func string(major: UInt8, maximum: Int) throws -> Data {
    let (actual, count) = try head()
    guard actual == major, count <= UInt64(maximum), count <= UInt64(input.count - offset) else { throw TransportControlError.responseInvalid }
    let start = offset; offset += Int(count)
    return input.subdata(in: start..<offset)
  }
  mutating func finiteArray(maximumItems: UInt64, maximumBytes: Int) throws -> Data {
    let start = offset
    let (major, count) = try head()
    guard major == 4, count <= maximumItems else { throw TransportControlError.responseInvalid }
    for _ in 0..<count { try skip(depth: 0) }
    guard offset - start <= maximumBytes else { throw TransportControlError.responseInvalid }
    return input.subdata(in: start..<offset)
  }
  private mutating func skip(depth: Int) throws {
    guard depth < 4 else { throw TransportControlError.responseInvalid }
    let (major, count) = try head()
    switch major {
    case 0: break
    case 2, 3:
      guard count <= 8192, count <= UInt64(input.count - offset) else { throw TransportControlError.responseInvalid }; offset += Int(count)
    case 4:
      guard count <= 32 else { throw TransportControlError.responseInvalid }; for _ in 0..<count { try skip(depth: depth + 1) }
    case 7: guard count == 20 || count == 21 else { throw TransportControlError.responseInvalid }
    default: throw TransportControlError.responseInvalid
    }
  }
  mutating func end() throws { guard offset == input.count else { throw TransportControlError.responseInvalid } }
}
#endif
