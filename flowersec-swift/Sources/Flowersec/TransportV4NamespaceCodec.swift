import Clibsodium
import Crypto
import Foundation

// This decoder accepts the independently pinned namespace and credential closure. The
// immutable generated registry describes types; peer input never creates a
// JSON object graph, chooses a trust key, or changes a resource limit.
enum V4NamespaceFailure: Error, Equatable, Sendable {
  case configuration, encoding, schema, signature, untrusted, capacity
  case notBootstrapped, pendingState, rollback, equivocation, closed
  case timeNotProven, futureTimestamp, bootstrapDeadline
}

final class V4NamespaceRegistry: @unchecked Sendable {
  static let backingBytes =
    UInt64(
      TransportV4Registry.cborRegistryJSON.utf8.count
        + TransportV4Registry.domainRegistryJSON.utf8.count) * 64
  private let maps: [String: [String: Any]]
  private let rules: [String: [[String: Any]]]
  private let domains: [[String: Any]]
  let fieldRegistries: [String: Any]
  private static let schemas: Set<String> = [
    "TrustBootstrapResponse", "TrustConfig", "NamespaceCapacity", "PublicationPolicy",
    "CredentialRevocationPolicy", "CredentialIssuerAuthorization", "HeadSignerDelegation",
    "ConnectionActivationDelegation", "OnceAuthorityRef", "FreshnessHead", "RevocationState",
    "RevokedIssuerEntry", "IssuerAuthorizationImpact", "RevokedCertificateEntry",
    "RevokedLeaseEntry", "CohortPolicySegment",
    "IdentityCertificate", "NoiseStaticPublicKey", "Artifact", "SessionContract", "ResumePolicy",
    "Candidate", "Route", "Leg", "TLSPolicy", "TLSPin", "OriginPolicy", "ActivationAuthorization",
    "Grant", "GrantParentRef", "GrantNamespace", "GrantLimits", "GrantLegRef",
    "HopChallengeContext", "HOP_AUTH_HELLO", "HOP_AUTH_ENDPOINT_PROOF", "HOP_AUTH_RELAY_PROOF",
    "TopUpRequest", "OwnerFenceProof", "TopUpEntry", "TopUpResponse", "TopUpAck",
    "PoolSelectionRef", "PoolSelectionSet", "RekeyEnvelope", "SpendPolicy", "PoolAttemptBudget",
    "PoolRouteRef", "RevocationNamespaceRef", "CandidateAttemptBudget",
    "ClientHello", "ServerHello", "TransportContext", "FSB4", "FSA4",
    "READY", "ReadyProofInput", "ReadyMACInput",
    "OPEN_STREAM", "OPEN_ACCEPT", "STREAM_DATA", "STREAM_ACK_CREDIT", "STREAM_ACK_STOP",
    "STREAM_ACK_STOPPED", "STREAM_ACK_DRAINED", "STREAM_ACK_RETIRE_BATCH",
    "STREAM_ACK_RETIRE_ACK", "terminal_tuple", "StreamMetadata",
    "REKEY_REQUEST", "REKEY_INIT", "REKEY_REPLY", "REKEY_COMMIT", "REKEY_ACK", "RekeyBarrierEntry",
    "PING", "PONG", "CLOSE", "GOAWAY", "ERROR",
    "ContractTarget", "ContractTargets", "ContractSnapshot", "ContractSnapshots",
    "ServiceContract", "ErrorDefinition", "StreamContentPolicy", "AdmissionOffer",
    "MessageStreamDefinition", "MessageStreamDirection", "TypedMessageMetadata",
    "ResumeProgress", "ResumeCheckpoint", "ResumeTokenClaims", "ResumeSignedToken", "ResumeMACToken", "ResumeRequest", "ResumeResult",
    "OperationReference", "ExecutionManagementTarget", "ExecutionManagementObservation", "QueryOperationResponse", "RequestCancelResponse", "ApplicationSDKError",
    "ProxyHTTPRequest", "ProxyHTTPResponse", "ProxyField", "ProxyError", "ProxyBodyEnd",
    "ProxyWebSocketOpen", "ProxyWebSocketResponse",
  ]

  init() throws {
    let registry =
      try JSONSerialization.jsonObject(
        with: Data(TransportV4Registry.cborRegistryJSON.utf8)) as! [String: Any]
    let frameMaps = registry["frame_maps"] as! [String: [String: Any]]
    // Materialize the immutable field dictionaries in the prepaid registry
    // once. Keeping their Swift type inside Any avoids rebuilding Foundation
    // bridges during every live authorization check under the environment gate.
    maps = frameMaps.mapValues { descriptor in
      var native = descriptor
      native["fields"] = descriptor["fields"] as! [String: [String: Any]]
      return native
    }
    let variants = registry["variant_rules"] as! [String: [[String: Any]]]
    let relations = registry["relation_rules"] as! [String: [[String: Any]]]
    let text = registry["text_rules"] as! [String: [[String: Any]]]
    rules = variants.merging(relations) { $0 + $1 }.merging(text) { $0 + $1 }
    let fields = registry["field_registries"] as! [String: Any]
    fieldRegistries = fields
    domains =
      try JSONSerialization.jsonObject(
        with: Data(TransportV4Registry.domainRegistryJSON.utf8)) as! [[String: Any]]
  }

  static func number(_ value: Any?) -> UInt64? {
    if let value = value as? String { return UInt64(value) }
    if let value = value as? NSNumber { return UInt64(value.stringValue) }
    return nil
  }

  func map(_ schema: String) throws -> [String: Any] {
    guard Self.schemas.contains(schema), let value = maps[schema] else {
      throw V4NamespaceFailure.schema
    }
    return value
  }

  func field(_ schema: String, _ name: String) throws -> (Int, [String: Any]) {
    let fields = try map(schema)["fields"] as! [String: [String: Any]]
    guard let entry = fields.first(where: { $0.value["name"] as? String == name }),
      let key = Int(entry.key)
    else { throw V4NamespaceFailure.schema }
    return (key, entry.value)
  }

  func signatureField(_ schema: String) throws -> Int {
    guard let field = Self.number(try map(schema)["signature_field"]) else {
      throw V4NamespaceFailure.schema
    }
    return Int(field)
  }

  static func securityID(_ bytes: some Collection<UInt8>) -> Bool {
    guard let first = bytes.first, bytes.count <= 128,
      (97...122).contains(first) || (48...57).contains(first)
    else { return false }
    return bytes.allSatisfy {
      (97...122).contains($0) || (48...57).contains($0)
        || [46, 95, 58, 47, 64, 45].contains($0)
    }
  }

  func validateText(_ value: V4NamespaceValue, field: [String: Any]) throws {
    let bytes = value.payload
    guard String(bytes: bytes, encoding: .utf8) != nil else { throw V4NamespaceFailure.encoding }
    let text = String(decoding: bytes, as: UTF8.self)
    guard text.utf8.elementsEqual(text.precomposedStringWithCanonicalMapping.utf8),
      text.unicodeScalars.allSatisfy({ Unicode151Generated.assigned($0) })
    else { throw V4NamespaceFailure.schema }
    if let pattern = field["pattern_ref"] as? String {
      guard ["security_id", "metadata_namespace"].contains(pattern), Self.securityID(bytes) else {
        throw V4NamespaceFailure.schema
      }
    }
    if field["pattern_ref"] as? String == "metadata_namespace" {
      let parts = bytes.split(separator: 47, omittingEmptySubsequences: false)
      guard parts.count == 2,
        parts.allSatisfy({ part in
          guard (1...32).contains(part.count), let first = part.first,
            (97...122).contains(first) || (48...57).contains(first)
          else { return false }
          return part.allSatisfy {
            (97...122).contains($0) || (48...57).contains($0) || [46, 95, 45].contains($0)
          }
        })
      else { throw V4NamespaceFailure.schema }
    }
    if let prefix = field["forbidden_prefix"] as? String,
      String(decoding: bytes, as: UTF8.self).hasPrefix(prefix)
    {
      throw V4NamespaceFailure.schema
    }
    if let reference = field["text_enum_ref"] as? String {
      guard let values = fieldRegistries[reference] as? [String: Any],
        values[String(decoding: bytes, as: UTF8.self)] != nil
      else { throw V4NamespaceFailure.schema }
    } else if let reference = field["const_ref"] as? String {
      guard fieldRegistries[reference] as? String == String(decoding: bytes, as: UTF8.self) else {
        throw V4NamespaceFailure.schema
      }
    } else if let format = field["text_format"] as? String {
      try V4CredentialText.validate(
        String(decoding: bytes, as: UTF8.self), format: format, registry: self)
    } else if let constant = field["const"] as? String {
      guard String(decoding: bytes, as: UTF8.self) == constant else {
        throw V4NamespaceFailure.schema
      }
    }
  }

  func profileAlgorithm(_ name: String) throws -> UInt64 {
    guard let profile = (fieldRegistries["crypto_profiles"] as? [String: [String: Any]])?[name],
      let algorithm = Self.number(profile["dh_algorithm"])
    else { throw V4NamespaceFailure.schema }
    return algorithm
  }

  func compoundDomain(_ name: String, operation: String) throws -> (Data, [[String: Any]]) {
    guard let domain = domains.first(where: { $0["name"] as? String == name }),
      domain["operation"] as? String == operation,
      let input = domain["input_schema"] as? [String: Any],
      let parts = input["parts"] as? [[String: Any]],
      let hex = domain["label_bytes"] as? String, hex.count.isMultiple(of: 2) else {
      throw V4NamespaceFailure.schema
    }
    var label = Data()
    var offset = hex.startIndex
    while offset < hex.endIndex {
      let end = hex.index(offset, offsetBy: 2)
      guard let byte = UInt8(hex[offset..<end], radix: 16) else { throw V4NamespaceFailure.schema }
      label.append(byte); offset = end
    }
    return (label, parts)
  }

  func domain(_ name: String, schema: String, operation: String) throws -> (Data, String) {
    guard let domain = domains.first(where: { $0["name"] as? String == name }),
      domain["operation"] as? String == operation,
      let input = domain["input_schema"] as? [String: Any],
      let parts = input["parts"] as? [[String: Any]], parts.count == 1,
      parts[0]["encoding"] as? String == "lp-map",
      parts[0]["schema_ref"] as? String == schema,
      let projection = parts[0]["projection"] as? String,
      let hex = domain["label_bytes"] as? String, hex.count.isMultiple(of: 2)
    else { throw V4NamespaceFailure.schema }
    var bytes = Data()
    bytes.reserveCapacity(hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
      let end = hex.index(index, offsetBy: 2)
      guard let byte = UInt8(hex[index..<end], radix: 16) else { throw V4NamespaceFailure.schema }
      bytes.append(byte)
      index = end
    }
    return (bytes, projection)
  }

  private func clause(_ rule: [String: Any], _ value: V4NamespaceValue) throws {
    for name in rule["required"] as? [String] ?? [] { _ = try value.path(name) }
    for name in rule["absent"] as? [String] ?? [] {
      guard try value.optionalPath(name) == nil else { throw V4NamespaceFailure.schema }
    }
    for (name, constant) in rule["constants"] as? [String: Any] ?? [:] {
      guard try value.path(name).equals(constant) else { throw V4NamespaceFailure.schema }
    }
    for (name, choices) in rule["enum_values"] as? [String: [Any]] ?? [:] {
      let member = try value.path(name)
      guard try choices.contains(where: { try member.equals($0) }) else {
        throw V4NamespaceFailure.schema
      }
    }
    for pair in rule["equal"] as? [[String]] ?? [] {
      guard try value.path(pair[0]).raw.elementsEqual(value.path(pair[1]).raw) else {
        throw V4NamespaceFailure.schema
      }
    }
    for pair in rule["less_or_equal"] as? [[String]] ?? [] {
      guard try value.path(pair[0]).uint() <= value.path(pair[1]).uint() else {
        throw V4NamespaceFailure.schema
      }
    }
    for name in rule["nonzero"] as? [String] ?? [] {
      let member = try value.path(name)
      guard member.major == 2 ? member.payload.contains(where: { $0 != 0 }) : try member.uint() != 0
      else { throw V4NamespaceFailure.schema }
    }
    for name in rule["zero_bytes"] as? [String] ?? [] {
      guard try value.path(name).bytes().allSatisfy({ $0 == 0 }) else {
        throw V4NamespaceFailure.schema
      }
    }
    for (name, registry) in rule["registered"] as? [String: String] ?? [:] {
      let number = try value.path(name).uint()
      guard let values = fieldRegistries[registry] as? [String: Any],
        values.values.contains(where: { Self.number($0) == number })
      else { throw V4NamespaceFailure.schema }
    }
    for (name, length) in rule["byte_lengths"] as? [String: Any] ?? [:] {
      guard let count = Self.number(length),
        try UInt64(value.path(name).bytes().count) == count
      else {
        throw V4NamespaceFailure.schema
      }
    }
    for (name, prefix) in rule["byte_prefixes"] as? [String: String] ?? [:] {
      guard prefix == "04", try value.path(name).bytes().first == 4 else {
        throw V4NamespaceFailure.schema
      }
    }
  }

  func ruleCount(_ schema: String) -> Int { (rules[schema] ?? []).count }

  func validateRules(_ value: V4NamespaceValue, range: Range<Int>? = nil) throws {
    let selected = rules[value.schema] ?? []
    for rule in selected[range ?? (selected.startIndex..<selected.endIndex)] {
      if let condition = rule["when"] as? [String: Any] {
        if let name = condition["field"] as? String {
          guard let member = try value.optionalPath(name), try member.equals(condition["value"])
          else { continue }
        } else if let name = condition["context"] as? String {
          guard let actual = value.context[name] else { throw V4NamespaceFailure.schema }
          if actual != condition["value"] as? String { continue }
        } else {
          throw V4NamespaceFailure.schema
        }
      }
      guard let operation = rule["op"] as? String else { throw V4NamespaceFailure.schema }
      switch operation {
      case "map_digest":
        let source = try value.path(rule["source"] as! String)
        let map = source.embeddedValue ?? source
        guard try value.path(rule["field"] as! String).bytes() == map.digest(rule["domain"] as! String)
        else { throw V4NamespaceFailure.schema }
      case "equal_if_present":
        if let left = try value.optionalPath(rule["left"] as! String),
          let right = try value.optionalPath(rule["right"] as! String) {
          guard left.raw.elementsEqual(right.raw) else { throw V4NamespaceFailure.schema }
        }
      case "less_than", "less_or_equal", "equal", "not_equal", "bit_subset", "max_difference":
        let left = try value.path(rule["left"] as! String)
        let right = try value.path(rule["right"] as! String)
        let valid: Bool
        switch operation {
        case "equal": valid = left.raw.elementsEqual(right.raw)
        case "not_equal": valid = !left.raw.elementsEqual(right.raw)
        case "less_than": valid = try left.uint() < right.uint()
        case "less_or_equal": valid = try left.uint() <= right.uint()
        case "bit_subset": valid = try left.uint() & ~right.uint() == 0
        default:
          valid =
            try left.uint() <= right.uint()
            && right.uint() - left.uint() <= Self.number(rule["max"])!
        }
        guard valid else { throw V4NamespaceFailure.schema }
      case "is_null":
        guard try value.path(rule["field"] as! String).isNull else {
          throw V4NamespaceFailure.schema
        }
      case "at_least_one":
        guard
          try (rule["fields"] as! [String]).contains(where: { try value.optionalPath($0) != nil })
        else {
          throw V4NamespaceFailure.schema
        }
      case "variant":
        guard let member = try value.optionalPath(rule["discriminator"] as! String),
          try member.equals(rule["value"])
        else { continue }
        try clause(rule, value)
      case "context_variant":
        guard let selected = value.context[rule["context"] as! String],
          let selectedRule = (rule["cases"] as! [String: [String: Any]])[selected]
        else { throw V4NamespaceFailure.schema }
        try clause(selectedRule, value)
      case "range":
        let number = try value.path(rule["field"] as! String).uint()
        guard number >= Self.number(rule["min"])!, number <= Self.number(rule["max"])! else {
          throw V4NamespaceFailure.schema
        }
      case "profile_algorithm":
        guard
          try profileAlgorithm(value.path(rule["profile"] as! String).text())
            == value.path(rule["algorithm"] as! String).uint()
        else { throw V4NamespaceFailure.schema }
      case "feature_bit":
        let features = fieldRegistries["feature_registry"] as! [String: [String: Any]]
        let bit = Self.number(features[rule["feature"] as! String]!["bit"])!
        guard
          try (value.path(rule["field"] as! String).uint() & (1 << bit) != 0)
            == (rule["present"] as! Bool)
        else { throw V4NamespaceFailure.schema }
      case "exclusive_item":
        let array = try value.field(rule["field"] as! String)
        for member in array.children {
          if let item = try member.optionalPath(rule["item_field"] as! String),
            try item.equals(rule["value"]), array.count != 1
          {
            throw V4NamespaceFailure.schema
          }
        }
      case "ordinal_indices":
        let array = try value.field(rule["field"] as! String)
        let field = Int(Self.number(rule["item_field_id"])!)
        for (index, item) in array.children.enumerated() {
          guard try item.fieldID(field).uint() == UInt64(index) else {
            throw V4NamespaceFailure.schema
          }
        }
      case "allowed_pairs", "allowed_tuples":
        let fields = operation == "allowed_pairs"
          ? [rule["left"] as! String, rule["right"] as! String] : rule["fields"] as! [String]
        guard
          try (rule[operation == "allowed_pairs" ? "pairs" : "rows"] as! [[Any]]).contains(where: { row in
            try fields.enumerated().allSatisfy { try value.path($0.element).equals(row[$0.offset]) }
          })
        else { throw V4NamespaceFailure.schema }
      case "registry_tuple":
        guard var selected = fieldRegistries[rule["registry"] as! String] else {
          throw V4NamespaceFailure.schema
        }
        for selector in rule["selectors"] as! [[String: String]] {
          let key: String
          if let field = selector["field"] {
            let descriptor = try self.field(value.schema, field).1
            let enums = descriptor["enum"] as! [String: Any]
            let number = try value.u(field)
            guard let match = enums.first(where: { Self.number($0.value) == number }) else {
              throw V4NamespaceFailure.schema
            }
            key = match.key
          } else {
            guard let current = value.context[selector["context"]!] else {
              throw V4NamespaceFailure.schema
            }
            key = current
          }
          guard let next = (selected as? [String: Any])?[key] else {
            throw V4NamespaceFailure.schema
          }
          selected = next
        }
        for name in rule["fields"] as! [String] {
          guard try value.t(name) == (selected as? [String: Any])?[name] as? String else {
            throw V4NamespaceFailure.schema
          }
        }
      case "text_format":
        try V4CredentialText.validate(
          value.t(rule["field"] as! String), format: rule["format"] as! String, registry: self)
      case "origin_endpoint":
        let parts = try V4CredentialText.origin(value.t(rule["origin"] as! String), registry: self)
        guard parts.scheme == rule["scheme"] as? String,
          try parts.host == value.t(rule["host"] as! String),
          try parts.port == value.u(rule["port"] as! String)
        else { throw V4NamespaceFailure.schema }
      case "error_scope":
        let code = try value.u(rule["code_field"] as! String)
        guard let codes = fieldRegistries["error_codes"] as? [String: Any],
          let name = codes.first(where: { Self.number($0.value) == code })?.key,
          let policy = (fieldRegistries["error_code_metadata"] as? [String: [String: Any]])?[name]
        else { throw V4NamespaceFailure.schema }
        let target = try value.u(rule["target_scope_field"] as! String)
        let stream = try value.optional(rule["stream_id_field"] as! String)
        switch policy["scope"] as? String {
        case "session":
          guard target == 0, stream == nil else { throw V4NamespaceFailure.schema }
        case "stream":
          guard target > 0, try stream?.uint() == target else { throw V4NamespaceFailure.schema }
        default: throw V4NamespaceFailure.schema
        }
        if try value.optional(rule["retry_after_field"] as! String) != nil,
          policy["retryable"] as? Bool != true
        {
          throw V4NamespaceFailure.schema
        }
      case "unique_by", "increasing_tuple", "increasing_cbor", "increasing", "increasing_bytes",
        "increasing_scopes":
        guard let array = try value.optional(rule["field"] as! String) else { continue }
        let fields = rule["item_fields"] as? [String] ?? []
        var previous: V4NamespaceValue?
        for item in array.children {
          if operation == "increasing_scopes" {
            let scope = try item.uint()
            guard scope > 0, scope <= 9_223_372_036_854_775_807 else {
              throw V4NamespaceFailure.schema
            }
          }
          if operation == "unique_by" {
            for old in array.children {
              if old.index == item.index { break }
              if try fields.allSatisfy({ try old.path($0).raw.elementsEqual(item.path($0).raw) }) {
                throw V4NamespaceFailure.schema
              }
            }
          } else if let previous {
            let less: Bool
            if operation == "increasing_cbor" {
              less = previous.raw.lexicographicallyPrecedes(item.raw)
            } else if operation == "increasing" || operation == "increasing_scopes" {
              if let field = Self.number(rule["item_field_id"]) {
                less = try previous.fieldID(Int(field)).uint() < item.fieldID(Int(field)).uint()
              } else {
                less = try previous.uint() < item.uint()
              }
            } else if operation == "increasing_bytes" {
              less = try previous.fieldID(Int(Self.number(rule["item_field_id"])!)).payload
                .lexicographicallyPrecedes(
                  item.fieldID(Int(Self.number(rule["item_field_id"])!)).payload)
            } else {
              var ordered = false
              for field in fields {
                let left = try previous.path(field)
                let right = try item.path(field)
                if left.raw.elementsEqual(right.raw) { continue }
                ordered = left.raw.lexicographicallyPrecedes(right.raw)
                break
              }
              less = ordered
            }
            guard less else { throw V4NamespaceFailure.schema }
          }
          previous = item
        }
      default: throw V4NamespaceFailure.schema
      }
    }
  }

}

final class V4NamespaceDocument {
  struct Node {
    let offset: Int
    let payload: Int
    var end: Int
    var next: Int
    let major: UInt8
    let number: UInt64
    var schema: String
    var context: [String: String] = [:]
    var embedded: Int?
  }
  private(set) var bytes: [UInt8]
  private(set) var nodes: [Node] = []
  private let nodeLimit: Int
  let registry: V4NamespaceRegistry
  private let limits: [String: UInt64]
  private var incremental: IncrementalState?

  init(
    _ input: Data, schema: String, bytes maximum: Int, nodes: Int,
    registry: V4NamespaceRegistry,
    limits: [String: UInt64] = [:], context: [String: String] = [:],
    cooperative: Bool = false
  ) throws {
    guard maximum > 0, input.count <= maximum, nodes > 0 else {
      throw V4NamespaceFailure.capacity
    }
    self.registry = registry
    self.nodeLimit = nodes
    self.limits = limits
    let descriptor = try registry.map(schema)
    if let cap = V4NamespaceRegistry.number(descriptor["max_encoded_bytes"]), input.count > cap {
      throw V4NamespaceFailure.capacity
    }
    if let reference = descriptor["max_encoded_bytes_ref"] as? String {
      guard let cap = limits[reference], cap > 0, input.count <= cap else {
        throw V4NamespaceFailure.capacity
      }
    }
    self.bytes = []
    self.bytes.reserveCapacity(input.count)
    self.nodes.reserveCapacity(nodes)
    if cooperative {
      guard ["ContractSnapshots", "ContractTargets", "ServiceContract", "AdmissionOffer"].contains(schema) else {
        throw V4NamespaceFailure.configuration
      }
      incremental = IncrementalState(input: input, schema: schema, context: context)
      return
    }
    self.bytes.append(contentsOf: input)
    var offset = 0
    _ = try scan(&offset, depth: 0, field: ["type": "map", "schema_ref": schema], context: context)
    guard offset == input.count else { throw V4NamespaceFailure.encoding }
  }

  // The query lane retains this original document. It never performs a second
  // eager parse after cooperative scanning completes.
  private final class IncrementalMap {
    let index: Int
    let descriptor: [String: Any]
    let fields: [String: [String: Any]]
    let depth: Int
    var context: [String: String]
    var remaining: UInt64
    var previous: UInt64?
    var found: Set<Int> = []
    var child: (Int, [String: Any])?
    init(index: Int, descriptor: [String: Any], depth: Int, context: [String: String], count: UInt64) {
      self.index = index; self.descriptor = descriptor; self.depth = depth; self.context = context
      fields = descriptor["fields"] as! [String: [String: Any]]; remaining = count
    }
  }
  private enum IncrementalAction {
    case value([String: Any], Int, [String: String])
    case map(IncrementalMap)
    case array(Int, UInt64, [String: Any], Int, [String: String])
    case bytes(Int, Int, Bool, Bool)
    case rules(Int, Int)
  }
  private final class IncrementalState {
    var input: Data?
    var copied = 0
    var offset = 0
    var actions: [IncrementalAction]
    init(input: Data, schema: String, context: [String: String]) {
      self.input = input
      actions = [.value(["type": "map", "schema_ref": schema], 0, context)]
      actions.reserveCapacity(32)
    }
  }
  var parsingComplete: Bool { incremental == nil }
  var queryParsingOffset: Int { incremental?.offset ?? bytes.count }

  // At most 4096 input bytes are copied or scanned in one turn. Container and
  // relation work also has a fixed transition bound; a relation gets its own
  // turn so SDK control work remains independent of an application callback.
  @discardableResult func advanceQueryParsing() throws -> Bool {
    guard let state = incremental else { return true }
    if let input = state.input {
      let end = min(input.count, state.copied + 4096)
      bytes.append(contentsOf: input[state.copied..<end]); state.copied = end
      if end == input.count { state.input = nil }
      return false
    }
    var budget = 4096
    var transitions = 0
    while let action = state.actions.popLast() {
      transitions += 1
      if transitions > 64 || budget < 18 {
        state.actions.append(action); return false
      }
      switch action {
      case .value(let field, let depth, let context):
        guard depth <= 8, nodes.count < nodeLimit else { throw V4NamespaceFailure.capacity }
        let start = state.offset
        var end = start
        let (major, number) = try header(&end)
        let type = field["type"] as? String ?? ""
        if type == "map" {
          guard major == 5, number <= 128, let schema = field["schema_ref"] as? String else { throw V4NamespaceFailure.schema }
          let descriptor = try registry.map(schema)
          let index = nodes.count
          nodes.append(Node(offset: start, payload: end, end: end, next: index + 1, major: major, number: number, schema: schema))
          state.offset = end; budget -= end - start
          state.actions.append(.map(IncrementalMap(index: index, descriptor: descriptor, depth: depth, context: context, count: number)))
        } else if type == "array" || type == "array<uint64>" {
          guard major == 4, number >= (V4NamespaceRegistry.number(field["min_items"]) ?? 0),
            number <= (V4NamespaceRegistry.number(field["max_items"]) ?? 1035),
            number <= UInt64(nodeLimit - nodes.count), number <= UInt64(bytes.count - end),
            let item = type == "array<uint64>" ? ["type": "uint64"] : field["items"] as? [String: Any]
          else { throw V4NamespaceFailure.capacity }
          let index = nodes.count
          nodes.append(Node(offset: start, payload: end, end: end, next: index + 1, major: major, number: number, schema: ""))
          state.offset = end; budget -= end - start
          state.actions.append(.array(index, number, item, depth, context))
        } else if type == "bytes" {
          guard major == 2, number <= UInt64(bytes.count - end) else { throw V4NamespaceFailure.encoding }
          if let size = V4NamespaceRegistry.number(field["length"]), number != size { throw V4NamespaceFailure.schema }
          if let maximum = V4NamespaceRegistry.number(field["max_bytes"]), number > maximum { throw V4NamespaceFailure.capacity }
          if let minimum = V4NamespaceRegistry.number(field["min_bytes"]), number < minimum { throw V4NamespaceFailure.schema }
          if let reference = field["max_ref"] as? String {
            guard let cap = limits[reference], number <= cap else { throw V4NamespaceFailure.capacity }
          }
          let index = nodes.count
          nodes.append(Node(offset: start, payload: end, end: end, next: index + 1, major: major, number: number, schema: "", context: context))
          state.offset = end; budget -= end - start
          state.actions.append(.bytes(index, Int(number), field["nonzero"] as? Bool == true, false))
        } else {
          // The fixed query schemas contain only bounded text and scalar leaves.
          // Other registry forms remain on their original non-query decoder.
          guard type == "text" || type == "bool" || type.hasPrefix("uint") else { throw V4NamespaceFailure.schema }
          let cost = end - start + (type == "text" ? Int(clamping: number) : 0)
          guard cost <= 4096 else { throw V4NamespaceFailure.capacity }
          if cost > budget { state.actions.append(action); return false }
          _ = try scan(&state.offset, depth: depth, field: field, context: context)
          budget -= state.offset - start
        }
      case .map(let frame):
        if let (childIndex, child) = frame.child {
          if let mappings = frame.descriptor["context_fields"] as? [String: String], let name = child["name"] as? String {
            for (key, source) in mappings where source == name {
              guard let enums = child["enum"] as? [String: Any],
                let selected = enums.first(where: { V4NamespaceRegistry.number($0.value) == nodes[childIndex].number })
              else { throw V4NamespaceFailure.schema }
              frame.context[key] = selected.key
            }
          }
          frame.child = nil
        }
        if frame.remaining == 0 {
          let required = frame.descriptor["required"] as! [Int]
          guard required.allSatisfy(frame.found.contains) else { throw V4NamespaceFailure.schema }
          let size = state.offset - nodes[frame.index].offset
          if let cap = V4NamespaceRegistry.number(frame.descriptor["max_encoded_bytes"]), size > cap { throw V4NamespaceFailure.capacity }
          if let reference = frame.descriptor["max_encoded_bytes_ref"] as? String {
            guard let cap = limits[reference], size <= cap else { throw V4NamespaceFailure.capacity }
          }
          nodes[frame.index].end = state.offset; nodes[frame.index].next = nodes.count; nodes[frame.index].context = frame.context
          state.actions.append(.rules(frame.index, 0))
        } else {
          let start = state.offset
          let (major, key) = try header(&state.offset)
          guard major == 0, key <= 65535, frame.previous == nil || frame.previous! < key,
            let child = frame.fields[String(key)], nodes.count < nodeLimit else { throw V4NamespaceFailure.schema }
          frame.previous = key; frame.found.insert(Int(key)); frame.remaining -= 1
          nodes.append(Node(offset: state.offset, payload: state.offset, end: state.offset, next: nodes.count + 1, major: 0, number: key, schema: ""))
          frame.child = (nodes.count, child); budget -= state.offset - start
          state.actions.append(.map(frame)); state.actions.append(.value(child, frame.depth + 1, frame.context))
        }
      case .array(let index, let remaining, let item, let depth, let context):
        if remaining == 0 {
          nodes[index].end = state.offset; nodes[index].next = nodes.count; nodes[index].context = context
        } else {
          state.actions.append(.array(index, remaining - 1, item, depth, context))
          state.actions.append(.value(item, depth + 1, context))
        }
      case .bytes(let index, let remaining, let requireNonzero, let nonzero):
        let size = min(remaining, budget)
        let next = state.offset + size
        let foundNonzero = nonzero || (requireNonzero && bytes[state.offset..<next].contains(where: { $0 != 0 }))
        state.offset = next; budget -= size
        if size < remaining {
          state.actions.append(.bytes(index, remaining - size, requireNonzero, foundNonzero)); return false
        }
        guard !requireNonzero || foundNonzero else { throw V4NamespaceFailure.schema }
        nodes[index].end = next; nodes[index].next = nodes.count
      case .rules(let index, let rule):
        let value = V4NamespaceValue(document: self, index: index)
        if rule < registry.ruleCount(value.schema) {
          try registry.validateRules(value, range: rule..<rule + 1)
          state.actions.append(.rules(index, rule + 1)); return false
        }
      }
    }
    guard state.offset == bytes.count else { throw V4NamespaceFailure.encoding }
    incremental = nil
    return true
  }

  deinit { bytes.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) } }

  var root: V4NamespaceValue { V4NamespaceValue(document: self, index: 0) }

  private func header(_ offset: inout Int) throws -> (UInt8, UInt64) {
    guard offset < bytes.count else { throw V4NamespaceFailure.encoding }
    let byte = bytes[offset]
    offset += 1
    let major = byte >> 5
    let extra = byte & 31
    if extra < 24 { return (major, UInt64(extra)) }
    guard extra <= 27 else { throw V4NamespaceFailure.encoding }
    let width = 1 << Int(extra - 24)
    guard width <= bytes.count - offset else { throw V4NamespaceFailure.encoding }
    var value: UInt64 = 0
    for byte in bytes[offset..<offset + width] { value = value << 8 | UInt64(byte) }
    offset += width
    guard value >= [24, 256, 65536, 4_294_967_296][Int(extra - 24)] else {
      throw V4NamespaceFailure.encoding
    }
    return (major, value)
  }

  @discardableResult private func scan(
    _ offset: inout Int, depth: Int, field descriptor: [String: Any],
    context inherited: [String: String]
  ) throws
    -> Int
  {
    var field = descriptor
    var context = inherited
    if field["type"] as? String == "context_variant" {
      guard let name = field["context"] as? String, let selected = context[name],
        let resolved = (field["cases"] as? [String: [String: Any]])?[selected]
      else { throw V4NamespaceFailure.schema }
      field = resolved
    }
    guard depth <= 8, nodes.count < nodeLimit else { throw V4NamespaceFailure.capacity }
    let start = offset
    let (major, number) = try header(&offset)
    let index = nodes.count
    nodes.append(
      Node(
        offset: start, payload: offset, end: offset, next: index + 1,
        major: major, number: number, schema: ""))
    if major == 7, number == 22, field["nullable"] as? Bool == true {
      return index
    }
    let type = field["type"] as? String ?? ""
    switch type {
    case "uint8", "uint16", "uint32", "uint64":
      guard major == 0 else { throw V4NamespaceFailure.schema }
      let bits = Int(type.dropFirst(4))!
      let cap = bits == 64 ? UInt64.max : (1 << bits) - 1
      guard number <= cap else { throw V4NamespaceFailure.schema }
      if let minimum = V4NamespaceRegistry.number(field["min"]), number < minimum {
        throw V4NamespaceFailure.schema
      }
      if let maximum = V4NamespaceRegistry.number(field["max"]), number > maximum {
        throw V4NamespaceFailure.schema
      }
      if let constant = V4NamespaceRegistry.number(field["const"]), number != constant {
        throw V4NamespaceFailure.schema
      }
      if let values = field["enum"] as? [String: Any],
        !values.values.contains(where: { V4NamespaceRegistry.number($0) == number })
      {
        throw V4NamespaceFailure.schema
      }
      if let reference = field["enum_ref"] as? String {
        guard let values = registry.fieldRegistries[reference] as? [String: Any],
          values.values.contains(where: { V4NamespaceRegistry.number($0) == number })
        else {
          throw V4NamespaceFailure.schema
        }
      }
      if let mask = V4NamespaceRegistry.number(field["bitmask"]), number & ~mask != 0 {
        throw V4NamespaceFailure.schema
      }
    case "bool":
      guard major == 7, number == 20 || number == 21 else { throw V4NamespaceFailure.schema }
    case "bytes", "text":
      guard major == (type == "bytes" ? 2 : 3), number <= UInt64(bytes.count - offset) else {
        throw V4NamespaceFailure.encoding
      }
      if let size = V4NamespaceRegistry.number(field["length"]), number != size {
        throw V4NamespaceFailure.schema
      }
      if let cap = V4NamespaceRegistry.number(field["max_bytes"]), number > cap {
        throw V4NamespaceFailure.capacity
      }
      if let minimum = V4NamespaceRegistry.number(field["min_bytes"]), number < minimum {
        throw V4NamespaceFailure.schema
      }
      if let reference = field["max_ref"] as? String {
        guard let maximum = limits[reference], number <= maximum else {
          throw V4NamespaceFailure.capacity
        }
      }
      offset += Int(number)
      nodes[index].end = offset
      if field["nonzero"] as? Bool == true,
        !bytes[nodes[index].payload..<offset].contains(where: { $0 != 0 })
      {
        throw V4NamespaceFailure.schema
      }
      if let embedded = field["encoded_schema_ref"] as? String,
        ["IdentityCertificate", "ActivationAuthorization", "Grant", "StreamMetadata", "ResumeSignedToken", "ResumeMACToken"].contains(embedded),
        !(number == 0 && field["allow_empty"] as? Bool == true)
      {
        var inner = nodes[index].payload
        nodes[index].embedded = try scan(
          &inner, depth: depth + 1, field: ["type": "map", "schema_ref": embedded], context: context
        )
        guard inner == offset else { throw V4NamespaceFailure.encoding }
      }
      if major == 3 {
        try registry.validateText(V4NamespaceValue(document: self, index: index), field: field)
      }
    // Embedded documents are decoded separately under their own reservation
    // slice after the enclosing signed response is authenticated.
    case "array", "array<uint64>":
      guard major == 4 else { throw V4NamespaceFailure.schema }
      let maximum: UInt64
      if let reference = field["max_items_ref"] as? String {
        guard let value = limits[reference] else { throw V4NamespaceFailure.capacity }
        maximum = value
      } else {
        maximum = V4NamespaceRegistry.number(field["max_items"]) ?? 1035
      }
      guard number >= (V4NamespaceRegistry.number(field["min_items"]) ?? 0), number <= maximum,
        number <= UInt64(nodeLimit - nodes.count), number <= UInt64(bytes.count - offset)
      else { throw V4NamespaceFailure.capacity }
      let item = type == "array<uint64>" ? ["type": "uint64"] : field["items"] as? [String: Any]
      guard let item else { throw V4NamespaceFailure.schema }
      for _ in 0..<number { try scan(&offset, depth: depth + 1, field: item, context: context) }
    case "text_map":
      guard major == 5, number >= (V4NamespaceRegistry.number(field["min_items"]) ?? 0),
        number <= (V4NamespaceRegistry.number(field["max_items"]) ?? 0),
        let keyField = field["keys"] as? [String: Any]
      else { throw V4NamespaceFailure.schema }
      let entryFields = field["entries"] as? [String: [String: Any]]
      let commonValue = field["values"] as? [String: Any]
      guard entryFields != nil || commonValue != nil else { throw V4NamespaceFailure.schema }
      var previous: Int?
      var foundEntries: Set<String> = []
      for _ in 0..<number {
        let key = try scan(&offset, depth: depth + 1, field: keyField, context: context)
        if let previous {
          let a = bytes[nodes[previous].offset..<nodes[previous].end]
          let b = bytes[nodes[key].offset..<nodes[key].end]
          guard a.count < b.count || (a.count == b.count && a.lexicographicallyPrecedes(b)) else {
            throw V4NamespaceFailure.encoding
          }
        }
        previous = key
        let valueField: [String: Any]
        if let entryFields {
          let name = try V4NamespaceValue(document: self, index: key).text()
          guard let entry = entryFields[name], foundEntries.insert(name).inserted else {
            throw V4NamespaceFailure.schema
          }
          valueField = entry
        } else {
          valueField = commonValue!
        }
        try scan(&offset, depth: depth + 1, field: valueField, context: context)
      }
      if let entryFields, foundEntries.count != entryFields.count { throw V4NamespaceFailure.schema }
    case "map":
      guard major == 5, number <= 128, let schema = field["schema_ref"] as? String else {
        throw V4NamespaceFailure.schema
      }
      let descriptor = try registry.map(schema)
      let fields = descriptor["fields"] as! [String: [String: Any]]
      let required = descriptor["required"] as! [Int]
      var found: Set<Int> = []
      var previous: UInt64?
      nodes[index].schema = schema
      for _ in 0..<number {
        let (kind, key) = try header(&offset)
        guard kind == 0, key <= 65535, previous == nil || previous! < key,
          let child = fields[String(key)]
        else { throw V4NamespaceFailure.schema }
        previous = key
        found.insert(Int(key))
        // The key is implicit in the generated schema; record it in a bounded
        // key node so field lookup preserves the original map byte range.
        guard nodes.count < nodeLimit else { throw V4NamespaceFailure.capacity }
        nodes.append(
          Node(
            offset: offset, payload: offset, end: offset, next: nodes.count + 1,
            major: 0, number: key, schema: ""))
        let childIndex = try scan(&offset, depth: depth + 1, field: child, context: context)
        if let mappings = descriptor["context_fields"] as? [String: String],
          let name = child["name"] as? String
        {
          for (key, source) in mappings where source == name {
            guard let enums = child["enum"] as? [String: Any],
              let selected = enums.first(where: {
                V4NamespaceRegistry.number($0.value) == nodes[childIndex].number
              })
            else { throw V4NamespaceFailure.schema }
            context[key] = selected.key
          }
        }
      }
      guard required.allSatisfy(found.contains) else { throw V4NamespaceFailure.schema }
      if let cap = V4NamespaceRegistry.number(descriptor["max_encoded_bytes"]), offset - start > cap
      {
        throw V4NamespaceFailure.capacity
      }
      if let reference = descriptor["max_encoded_bytes_ref"] as? String {
        guard let cap = limits[reference], offset - start <= cap else {
          throw V4NamespaceFailure.capacity
        }
      }
    default: throw V4NamespaceFailure.schema
    }
    nodes[index].end = offset
    nodes[index].context = context
    nodes[index].next = nodes.count
    if major == 5 {
      let value = V4NamespaceValue(document: self, index: index)
      try registry.validateRules(value)
      if value.schema == "OPEN_STREAM", try value.b("open_digest") != value.digest("open_digest") {
        throw V4NamespaceFailure.schema
      }
    }
    return index
  }
}

struct V4NamespaceValue {
  let document: V4NamespaceDocument
  let index: Int
  private var node: V4NamespaceDocument.Node { document.nodes[index] }
  var schema: String { node.schema }
  var embeddedValue: Self? { node.embedded.map { Self(document: document, index: $0) } }
  var context: [String: String] { node.context }
  var major: UInt8 { node.major }
  var count: Int { Int(node.number) }
  var raw: ArraySlice<UInt8> { document.bytes[node.offset..<node.end] }
  var payload: ArraySlice<UInt8> { document.bytes[node.payload..<node.end] }
  var isNull: Bool { node.major == 7 && node.number == 22 }
  func uint() throws -> UInt64 {
    guard major == 0 else { throw V4NamespaceFailure.schema }
    return node.number
  }
  func bytes() throws -> Data {
    guard major == 2 else { throw V4NamespaceFailure.schema }
    return Data(payload)
  }
  func text() throws -> String {
    guard major == 3 else { throw V4NamespaceFailure.schema }
    return String(decoding: payload, as: UTF8.self)
  }
  func equals(_ value: Any?) throws -> Bool {
    if major == 3 { return try text() == value as? String }
    if major == 7, node.number == 20 || node.number == 21 {
      return (node.number == 21) == value as? Bool
    }
    guard let number = V4NamespaceRegistry.number(value) else { throw V4NamespaceFailure.schema }
    return try uint() == number
  }
  func optional(_ name: String) throws -> Self? {
    guard major == 5 else { throw V4NamespaceFailure.schema }
    let key = try document.registry.field(schema, name).0
    return optionalID(key)
  }
  func optionalID(_ key: Int) -> Self? {
    var next = index + 1
    while next < node.next {
      let child = next + 1
      if document.nodes[next].number == key { return Self(document: document, index: child) }
      next = document.nodes[child].next
    }
    return nil
  }
  func fieldID(_ key: Int) throws -> Self {
    guard let value = optionalID(key) else { throw V4NamespaceFailure.schema }
    return value
  }
  func field(_ name: String) throws -> Self {
    guard let value = try optional(name) else { throw V4NamespaceFailure.schema }
    return value
  }
  func optionalPath(_ path: String) throws -> Self? {
    var value = self
    for part in path.split(separator: ".") {
      if let embedded = value.node.embedded { value = Self(document: document, index: embedded) }
      if value.major == 4, let number = Int(part) {
        guard let item = value.children.enumerated().first(where: { $0.offset == number }) else {
          return nil
        }
        value = item.element
      } else {
        guard let item = try value.optional(String(part)) else { return nil }
        value = item
      }
    }
    return value
  }
  func path(_ name: String) throws -> Self {
    guard let value = try optionalPath(name) else { throw V4NamespaceFailure.schema }
    return value
  }
  func u(_ name: String) throws -> UInt64 { try field(name).uint() }
  func b(_ name: String) throws -> Data { try field(name).bytes() }
  func t(_ name: String) throws -> String { try field(name).text() }
  var children: Children { Children(value: self) }
  struct Children: Sequence {
    let value: V4NamespaceValue
    func makeIterator() -> Iterator { Iterator(value: value, cursor: value.index + 1) }
    struct Iterator: IteratorProtocol {
      let value: V4NamespaceValue
      var cursor: Int
      mutating func next() -> V4NamespaceValue? {
        guard cursor < value.node.next else { return nil }
        let child = cursor
        cursor = value.document.nodes[child].next
        return V4NamespaceValue(document: value.document, index: child)
      }
    }
  }

  func excluding(_ field: Int) throws -> Data {
    guard major == 5, optionalID(field) != nil else { throw V4NamespaceFailure.schema }
    var body = Self.head(5, UInt64(count - 1))
    var next = index + 1
    while next < node.next {
      let key = document.nodes[next].number
      let child = V4NamespaceValue(document: document, index: next + 1)
      if key != field {
        body.append(Self.head(0, key))
        body.append(contentsOf: child.raw)
      }
      next = document.nodes[next + 1].next
    }
    return body
  }
  private func preimage(_ domain: String, operation: String) throws -> Data {
    let (label, projection) = try document.registry.domain(
      domain, schema: schema, operation: operation)
    var input = Data()
    input.reserveCapacity(raw.count + label.count + 16)
    input.append(label)
    if projection == "full" {
      var length = UInt32(raw.count).bigEndian
      withUnsafeBytes(of: &length) { input.append(contentsOf: $0) }
      input.append(contentsOf: raw)
    } else if projection == "without_signature" || projection == "without_open_digest" {
      let signatureKey =
        try projection == "without_open_digest"
        ? document.registry.field(schema, "open_digest").0
        : document.registry.signatureField(schema)
      var body = Self.head(5, UInt64(count - 1))
      defer { body.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) } }
      var next = index + 1
      while next < node.next {
        let key = document.nodes[next].number
        let child = V4NamespaceValue(document: document, index: next + 1)
        if key != signatureKey {
          body.append(Self.head(0, key))
          body.append(contentsOf: child.raw)
        }
        next = document.nodes[next + 1].next
      }
      var length = UInt32(body.count).bigEndian
      withUnsafeBytes(of: &length) { input.append(contentsOf: $0) }
      input.append(body)
    } else {
      throw V4NamespaceFailure.schema
    }
    return input
  }
  func digest(_ domain: String) throws -> Data {
    var input = try preimage(domain, operation: "sha256")
    defer { input.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) } }
    return Data(SHA256.hash(data: input))
  }
  func verify(_ domain: String, publicKey: Data) throws {
    var input = try preimage(domain, operation: "ed25519")
    defer { input.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) } }
    guard
      StrictEd25519V4Reference.verify(
        signature: try fieldID(document.registry.signatureField(schema)).bytes(),
        message: input, publicKey: publicKey)
    else { throw V4NamespaceFailure.signature }
  }
  static func head(_ major: UInt8, _ number: UInt64) -> Data {
    if number < 24 { return Data([major << 5 | UInt8(number)]) }
    let width = number <= 255 ? 1 : number <= 65535 ? 2 : number <= 0xffff_ffff ? 4 : 8
    let extra: UInt8 = width == 1 ? 24 : width == 2 ? 25 : width == 4 ? 26 : 27
    var value = number.bigEndian
    return Data([major << 5 | extra]) + withUnsafeBytes(of: &value) { Data($0.suffix(width)) }
  }
}
