import Crypto
import Foundation

enum CarrierKind: String, Codable, Equatable, Sendable {
  case webSocket = "websocket"
  case rawQUIC = "raw_quic"
  case webTransport = "webtransport"
}

enum PathKind: String, Codable, Equatable, Sendable {
  case direct
  case tunnel
}

enum NetworkModeV2: String, Codable, Equatable, Sendable {
  case dial
  case listen
}

enum SessionRoleV2: String, Codable, Equatable, Sendable {
  case client
  case server
}

struct RuntimeCapabilityTupleV2: Codable, Equatable, Sendable {
  let carrier: CarrierKind
  let networkMode: NetworkModeV2
  let path: PathKind
  let sessionRole: SessionRoleV2
}

struct UnsupportedRuntimeCarrierV2: Codable, Equatable, Sendable {
  let carrier: CarrierKind
  let reason: String
}

struct RuntimeCapabilityDescriptorV2: Codable, Equatable, Sendable {
  let schemaVersion: UInt8
  let language: String
  let runtime: String
  let tuples: [RuntimeCapabilityTupleV2]
  let unsupported: [UnsupportedRuntimeCarrierV2]

  func canonicalJSON() throws -> Data {
    try validate()
    let object: [String: Any] = [
      "language": language,
      "runtime": runtime,
      "schemaVersion": Int(schemaVersion),
      "tuples": tuples.map { tuple in
        [
          "carrier": tuple.carrier.rawValue,
          "networkMode": tuple.networkMode.rawValue,
          "path": tuple.path.rawValue,
          "sessionRole": tuple.sessionRole.rawValue,
        ]
      },
      "unsupported": unsupported.map { value in
        ["carrier": value.carrier.rawValue, "reason": value.reason]
      },
    ]
    return try JSONSerialization.data(
      withJSONObject: object,
      options: [.sortedKeys, .withoutEscapingSlashes]
    )
  }

  static func decodeCanonicalJSON(_ raw: Data) throws -> RuntimeCapabilityDescriptorV2 {
    guard let object = try JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
      throw RuntimeCapabilityCodecErrorV2.invalid
    }
    try requireExactKeys(object, ["language", "runtime", "schemaVersion", "tuples", "unsupported"])
    guard
      let language = object["language"] as? String,
      let runtime = object["runtime"] as? String,
      let schemaVersion = object["schemaVersion"] as? Int,
      schemaVersion == 2,
      let tupleObjects = object["tuples"] as? [[String: Any]],
      let unsupportedObjects = object["unsupported"] as? [[String: Any]]
    else { throw RuntimeCapabilityCodecErrorV2.invalid }
    let tuples = try tupleObjects.map { value in
      try requireExactKeys(value, ["carrier", "networkMode", "path", "sessionRole"])
      guard
        let carrierRaw = value["carrier"] as? String,
        let carrier = CarrierKind(rawValue: carrierRaw),
        let networkRaw = value["networkMode"] as? String,
        let networkMode = NetworkModeV2(rawValue: networkRaw),
        let pathRaw = value["path"] as? String,
        let path = PathKind(rawValue: pathRaw),
        let roleRaw = value["sessionRole"] as? String,
        let sessionRole = SessionRoleV2(rawValue: roleRaw)
      else { throw RuntimeCapabilityCodecErrorV2.invalid }
      return RuntimeCapabilityTupleV2(
        carrier: carrier,
        networkMode: networkMode,
        path: path,
        sessionRole: sessionRole
      )
    }
    let unsupported = try unsupportedObjects.map { value in
      try requireExactKeys(value, ["carrier", "reason"])
      guard
        let carrierRaw = value["carrier"] as? String,
        let carrier = CarrierKind(rawValue: carrierRaw),
        let reason = value["reason"] as? String
      else { throw RuntimeCapabilityCodecErrorV2.invalid }
      return UnsupportedRuntimeCarrierV2(carrier: carrier, reason: reason)
    }
    let descriptor = RuntimeCapabilityDescriptorV2(
      schemaVersion: 2,
      language: language,
      runtime: runtime,
      tuples: tuples,
      unsupported: unsupported
    )
    guard try descriptor.canonicalJSON() == raw else {
      throw RuntimeCapabilityCodecErrorV2.nonCanonical
    }
    return descriptor
  }

  func digest() throws -> Data {
    let canonical = try canonicalJSON()
    var preimage = Data("flowersec-v2-runtime-capability\0".utf8)
    preimage.appendUInt32BE(UInt32(canonical.count))
    preimage.append(canonical)
    return Data(SHA256.hash(data: preimage))
  }

  func digestHex() throws -> String {
    try digest().map { String(format: "%02x", $0) }.joined()
  }

  func validate() throws {
    guard
      schemaVersion == 2,
      Self.validRegistryToken(language),
      Self.validRegistryToken(runtime),
      !tuples.isEmpty || !unsupported.isEmpty
    else { throw RuntimeCapabilityCodecErrorV2.invalid }
    var supported = Set<CarrierKind>()
    for (index, tuple) in tuples.enumerated() {
      guard Self.valid(tuple) else { throw RuntimeCapabilityCodecErrorV2.invalid }
      if index > 0, !Self.tupleLess(tuples[index - 1], tuple) {
        throw RuntimeCapabilityCodecErrorV2.invalid
      }
      supported.insert(tuple.carrier)
    }
    var unavailable = Set<CarrierKind>()
    for (index, value) in unsupported.enumerated() {
      guard Self.validRegistryToken(value.reason), !supported.contains(value.carrier) else {
        throw RuntimeCapabilityCodecErrorV2.invalid
      }
      if index > 0, unsupported[index - 1].carrier.rawValue >= value.carrier.rawValue {
        throw RuntimeCapabilityCodecErrorV2.invalid
      }
      unavailable.insert(value.carrier)
    }
    for carrier in [CarrierKind.rawQUIC, .webSocket, .webTransport] {
      guard supported.contains(carrier) != unavailable.contains(carrier) else {
        throw RuntimeCapabilityCodecErrorV2.invalid
      }
    }
  }

  private static func valid(_ tuple: RuntimeCapabilityTupleV2) -> Bool {
    switch (tuple.networkMode, tuple.sessionRole, tuple.path) {
    case (.dial, .client, .direct), (.listen, .server, .direct),
      (.dial, .client, .tunnel), (.dial, .server, .tunnel):
      true
    default:
      false
    }
  }

  private static func tupleLess(
    _ left: RuntimeCapabilityTupleV2,
    _ right: RuntimeCapabilityTupleV2
  ) -> Bool {
    let lhs = [
      left.carrier.rawValue, left.networkMode.rawValue, left.sessionRole.rawValue,
      left.path.rawValue,
    ]
    let rhs = [
      right.carrier.rawValue, right.networkMode.rawValue, right.sessionRole.rawValue,
      right.path.rawValue,
    ]
    return lhs.lexicographicallyPrecedes(rhs)
  }

  private static func validRegistryToken(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 128 else { return false }
    return value.utf8.enumerated().allSatisfy { index, byte in
      (byte >= 97 && byte <= 122) || (index > 0 && byte >= 48 && byte <= 57)
        || (index > 0 && byte == 95)
    }
  }

  private static func requireExactKeys(_ value: [String: Any], _ expected: Set<String>) throws {
    guard Set(value.keys) == expected else { throw RuntimeCapabilityCodecErrorV2.invalid }
  }
}

enum RuntimeCapabilityCodecErrorV2: Error, Equatable, Sendable {
  case invalid
  case nonCanonical
}

enum RuntimeCapabilitiesV2 {
  /// Capabilities backed by production adapters and physical macOS system tests.
  static let macOS = RuntimeCapabilityDescriptorV2(
    schemaVersion: 2,
    language: "swift",
    runtime: "macos",
    tuples: [
      RuntimeCapabilityTupleV2(
        carrier: .webSocket, networkMode: .dial, path: .direct, sessionRole: .client),
      RuntimeCapabilityTupleV2(
        carrier: .webSocket, networkMode: .dial, path: .tunnel, sessionRole: .client),
      RuntimeCapabilityTupleV2(
        carrier: .webSocket, networkMode: .dial, path: .tunnel, sessionRole: .server),
    ],
    unsupported: [
      UnsupportedRuntimeCarrierV2(
        carrier: .rawQUIC,
        reason: "network_framework_quic_contract_incomplete_on_supported_targets"
      ),
      UnsupportedRuntimeCarrierV2(
        carrier: .webTransport,
        reason: "network_framework_quic_contract_incomplete_on_supported_targets"
      ),
    ]
  )

  /// Conservative cross-Apple descriptor. macOS-only evidence is not projected onto iOS.
  static let apple = RuntimeCapabilityDescriptorV2(
    schemaVersion: 2,
    language: "swift",
    runtime: "apple",
    tuples: [],
    unsupported: [
      UnsupportedRuntimeCarrierV2(
        carrier: .rawQUIC,
        reason: "network_framework_quic_contract_incomplete_on_supported_targets"
      ),
      UnsupportedRuntimeCarrierV2(
        carrier: .webSocket,
        reason: "transport_v2_websocket_adapter_not_committed"
      ),
      UnsupportedRuntimeCarrierV2(
        carrier: .webTransport,
        reason: "network_framework_quic_contract_incomplete_on_supported_targets"
      ),
    ]
  )
}

public indirect enum JSONValueV2: Equatable, Sendable {
  case null
  case bool(Bool)
  case integer(Int64)
  case string(String)
  case array([JSONValueV2])
  case object([String: JSONValueV2])
}

public enum StreamMetadataErrorV2: Error, Equatable, Sendable {
  case emptyKey
  case keyTooLong
  case keyNotNormalized
  case stringTooLong
  case unsafeInteger
  case arrayTooLong
  case objectTooLarge
  case depthExceeded
  case nodeLimitExceeded
  case encodedTooLarge
}

/// Stable, carrier-neutral failures returned by session and byte-stream operations.
///
/// Wire close codes, carrier errors, cryptographic state, and peer credentials are
/// intentionally collapsed into this closed set before crossing the public boundary.
public enum SessionErrorV2: String, Error, Equatable, Sendable {
  case canceled
  case timeout
  case closed
  case goingAway = "going_away"
  case resourceExhausted = "resource_exhausted"
  case streamRejected = "stream_rejected"
  case streamReset = "stream_reset"
  case rekeyFailed = "rekey_failed"
  case livenessFailed = "liveness_failed"
  case operationFailed = "operation_failed"
}

/// An application-level error returned by a remote RPC handler.
///
/// This value carries only the remote application's semantic code and message;
/// transport and carrier failures are returned as ``SessionErrorV2``.
public struct RPCErrorV2: Error, Equatable, Sendable {
  public let code: UInt32
  public let message: String

  public init(code: UInt32, message: String) {
    self.code = code
    self.message = message
  }
}

public struct StreamMetadataV2: Equatable, Sendable {
  public static let maxEncodedBytes = 4_096
  public static let maxDepth = 4
  public static let maxNodes = 64
  public static let maxObjectKeys = 64
  public static let maxArrayItems = 32
  public static let maxKeyBytes = 64
  public static let maxStringBytes = 512
  public static let maximumSafeInteger: Int64 = 9_007_199_254_740_991

  public static let empty = StreamMetadataV2(values: [:], encodedByteCount: 2)

  public let values: [String: JSONValueV2]
  public let encodedByteCount: Int

  public init(_ values: [String: JSONValueV2]) throws {
    var nodeCount = 1
    try Self.validateObject(values, depth: 0, nodeCount: &nodeCount)
    let encoded = try JSONSerialization.data(
      withJSONObject: try Self.foundationObject(values),
      options: [.sortedKeys, .withoutEscapingSlashes]
    )
    guard encoded.count <= Self.maxEncodedBytes else {
      throw StreamMetadataErrorV2.encodedTooLarge
    }
    self.init(values: values, encodedByteCount: encoded.count)
  }

  private init(values: [String: JSONValueV2], encodedByteCount: Int) {
    self.values = values
    self.encodedByteCount = encodedByteCount
  }

  private static func validateObject(
    _ object: [String: JSONValueV2],
    depth: Int,
    nodeCount: inout Int
  ) throws {
    guard depth <= maxDepth else { throw StreamMetadataErrorV2.depthExceeded }
    guard object.count <= maxObjectKeys else { throw StreamMetadataErrorV2.objectTooLarge }
    for (key, value) in object {
      guard !key.isEmpty else { throw StreamMetadataErrorV2.emptyKey }
      guard key.utf8.count <= maxKeyBytes else { throw StreamMetadataErrorV2.keyTooLong }
      guard key == key.precomposedStringWithCanonicalMapping else {
        throw StreamMetadataErrorV2.keyNotNormalized
      }
      try validate(value, depth: depth + 1, nodeCount: &nodeCount)
    }
  }

  private static func validate(
    _ value: JSONValueV2,
    depth: Int,
    nodeCount: inout Int
  ) throws {
    guard depth <= maxDepth else { throw StreamMetadataErrorV2.depthExceeded }
    nodeCount += 1
    guard nodeCount <= maxNodes else { throw StreamMetadataErrorV2.nodeLimitExceeded }
    switch value {
    case .null, .bool:
      return
    case .integer(let integer):
      guard absSafe(integer) <= maximumSafeInteger else {
        throw StreamMetadataErrorV2.unsafeInteger
      }
    case .string(let string):
      guard string.utf8.count <= maxStringBytes else {
        throw StreamMetadataErrorV2.stringTooLong
      }
    case .array(let array):
      guard array.count <= maxArrayItems else { throw StreamMetadataErrorV2.arrayTooLong }
      for item in array {
        try validate(item, depth: depth + 1, nodeCount: &nodeCount)
      }
    case .object(let object):
      try validateObject(object, depth: depth, nodeCount: &nodeCount)
    }
  }

  private static func absSafe(_ value: Int64) -> Int64 {
    value == .min ? .max : Swift.abs(value)
  }

  private static func foundationObject(_ object: [String: JSONValueV2]) throws -> [String: Any] {
    try object.mapValues(foundationValue)
  }

  private static func foundationValue(_ value: JSONValueV2) throws -> Any {
    switch value {
    case .null:
      return NSNull()
    case .bool(let value):
      return value
    case .integer(let value):
      return value
    case .string(let value):
      return value
    case .array(let values):
      return try values.map(foundationValue)
    case .object(let values):
      return try foundationObject(values)
    }
  }
}

public protocol ByteStreamV2: Sendable {
  var kind: String { get }

  func read(maxBytes: Int) async throws -> Data?
  func write(_ data: Data) async throws -> Int
  func closeWrite() async throws
  func reset() async
  func close() async
  func terminalError() async -> SessionErrorV2?
}

public struct IncomingStreamV2: Sendable {
  public let kind: String
  public let metadata: StreamMetadataV2
  public let stream: any ByteStreamV2

  public init(
    kind: String,
    metadata: StreamMetadataV2,
    stream: any ByteStreamV2
  ) {
    self.kind = kind
    self.metadata = metadata
    self.stream = stream
  }
}

public protocol RPCPeerV2: Sendable {
  func call<Request: Encodable & Sendable, Response: Decodable & Sendable>(
    _ typeID: UInt32,
    _ request: Request,
    as responseType: Response.Type,
    timeout: Duration
  ) async throws -> Response

  func notify<Payload: Encodable & Sendable>(_ typeID: UInt32, _ payload: Payload) async throws
}

public protocol SessionV2: Sendable {
  var rpc: any RPCPeerV2 { get }

  func openStream(kind: String, metadata: StreamMetadataV2) async throws -> any ByteStreamV2
  func acceptStream() async throws -> IncomingStreamV2
  func rekey() async throws
  func probeLiveness() async throws -> Duration
  func waitClosed() async -> SessionErrorV2
  func close() async
}

extension SessionV2 {
  public func openStream(kind: String) async throws -> any ByteStreamV2 {
    try await openStream(kind: kind, metadata: .empty)
  }
}
