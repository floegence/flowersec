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
  let reliableStreams: Bool
  let datagrams: Bool
  let migration: Bool
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
          "reliableStreams": tuple.reliableStreams,
          "datagrams": tuple.datagrams,
          "migration": tuple.migration,
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
      try requireExactKeys(
        value,
        [
          "carrier", "networkMode", "path", "sessionRole", "reliableStreams", "datagrams",
          "migration",
        ]
      )
      guard
        let carrierRaw = value["carrier"] as? String,
        let carrier = CarrierKind(rawValue: carrierRaw),
        let networkRaw = value["networkMode"] as? String,
        let networkMode = NetworkModeV2(rawValue: networkRaw),
        let pathRaw = value["path"] as? String,
        let path = PathKind(rawValue: pathRaw),
        let roleRaw = value["sessionRole"] as? String,
        let sessionRole = SessionRoleV2(rawValue: roleRaw),
        let reliableStreams = value["reliableStreams"] as? Bool,
        let datagrams = value["datagrams"] as? Bool,
        let migration = value["migration"] as? Bool
      else { throw RuntimeCapabilityCodecErrorV2.invalid }
      return RuntimeCapabilityTupleV2(
        carrier: carrier,
        networkMode: networkMode,
        path: path,
        sessionRole: sessionRole,
        reliableStreams: reliableStreams,
        datagrams: datagrams,
        migration: migration
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
    guard tuple.reliableStreams else { return false }
    guard tuple.carrier != .webSocket || (!tuple.datagrams && !tuple.migration) else {
      return false
    }
    return switch (tuple.networkMode, tuple.sessionRole, tuple.path) {
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
  static let macOS = appleWebSocket(runtime: "macos")
  static let iOS = appleWebSocket(runtime: "ios")
  static let linux = RuntimeCapabilityDescriptorV2(
    schemaVersion: 2,
    language: "swift",
    runtime: "linux",
    tuples: [],
    unsupported: [
      UnsupportedRuntimeCarrierV2(
        carrier: .rawQUIC,
        reason: "swift_apple_client_profile_excludes_raw_quic"
      ),
      UnsupportedRuntimeCarrierV2(
        carrier: .webSocket,
        reason: "websocket_adapter_not_supported_on_linux"
      ),
      UnsupportedRuntimeCarrierV2(
        carrier: .webTransport,
        reason: "swift_apple_client_profile_excludes_webtransport"
      ),
    ]
  )

  private static func appleWebSocket(runtime: String) -> RuntimeCapabilityDescriptorV2 {
    RuntimeCapabilityDescriptorV2(
      schemaVersion: 2,
      language: "swift",
      runtime: runtime,
      tuples: [
        RuntimeCapabilityTupleV2(
          carrier: .webSocket, networkMode: .dial, path: .direct, sessionRole: .client,
          reliableStreams: true, datagrams: false, migration: false),
        RuntimeCapabilityTupleV2(
          carrier: .webSocket, networkMode: .dial, path: .tunnel, sessionRole: .client,
          reliableStreams: true, datagrams: false, migration: false),
        RuntimeCapabilityTupleV2(
          carrier: .webSocket, networkMode: .dial, path: .tunnel, sessionRole: .server,
          reliableStreams: true, datagrams: false, migration: false),
      ],
      unsupported: [
        UnsupportedRuntimeCarrierV2(
          carrier: .rawQUIC,
          reason: "swift_apple_client_profile_excludes_raw_quic"
        ),
        UnsupportedRuntimeCarrierV2(
          carrier: .webTransport,
          reason: "swift_apple_client_profile_excludes_webtransport"
        ),
      ]
    )
  }
}

public indirect enum JSONValue: Equatable, Sendable {
  case null
  case bool(Bool)
  case integer(Int64)
  case string(String)
  case array([JSONValue])
  case object([String: JSONValue])
}

public enum StreamMetadataError: Error, Equatable, Sendable {
  case invalidValue
}

/// Stable, carrier-neutral failures returned by session and byte-stream operations.
///
/// Wire close codes, carrier errors, cryptographic state, and peer credentials are
/// intentionally collapsed into this closed set before crossing the public boundary.
public enum SessionError: String, Error, Equatable, Sendable {
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

/// Stable, redacted reason for authoritative session termination.
public struct SessionTermination: Equatable, Sendable {
  public let error: SessionError

  public init(error: SessionError) {
    self.error = error
  }
}

/// An application-level error returned by a remote RPC handler.
///
/// This value carries only the remote application's semantic code and message;
/// transport and carrier failures are returned as ``SessionError``.
public struct RPCError: Error, Equatable, Sendable, CustomStringConvertible,
  CustomDebugStringConvertible, CustomReflectable
{
  public let code: UInt32
  public let message: String

  public init(code: UInt32, message: String) {
    self.code = code
    self.message = message
  }

  public var description: String { "Flowersec.RPCError(code: \(code))" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, children: ["code": code]) }
}

/// A stable failure produced while decoding a peer-originated RPC notification.
public enum RPCNotificationError: Error, Equatable, Sendable {
  case invalidPayload
}

/// A cancelable peer-notification registration.
///
/// Cancellation is idempotent and returns only after the registration has been removed.
public protocol RPCNotificationSubscription: Sendable {
  func cancel() async
}

public struct StreamMetadata: Equatable, Sendable {
  private static let maxEncodedBytes = 4_096
  private static let maxDepth = 4
  private static let maxNodes = 64
  private static let maxObjectKeys = 64
  private static let maxArrayItems = 32
  private static let maxKeyBytes = 64
  private static let maxStringBytes = 512
  private static let maximumSafeInteger: Int64 = 9_007_199_254_740_991

  public static let empty = StreamMetadata(values: [:], encodedByteCount: 2)

  public let values: [String: JSONValue]
  private let encodedByteCount: Int

  public init(_ values: [String: JSONValue]) throws {
    var nodeCount = 1
    try Self.validateObject(values, depth: 0, nodeCount: &nodeCount)
    let encoded = try JSONSerialization.data(
      withJSONObject: try Self.foundationObject(values),
      options: [.sortedKeys, .withoutEscapingSlashes]
    )
    guard encoded.count <= Self.maxEncodedBytes else {
      throw StreamMetadataError.invalidValue
    }
    self.init(values: values, encodedByteCount: encoded.count)
  }

  private init(values: [String: JSONValue], encodedByteCount: Int) {
    self.values = values
    self.encodedByteCount = encodedByteCount
  }

  private static func validateObject(
    _ object: [String: JSONValue],
    depth: Int,
    nodeCount: inout Int
  ) throws {
    guard depth <= maxDepth else { throw StreamMetadataError.invalidValue }
    guard object.count <= maxObjectKeys else { throw StreamMetadataError.invalidValue }
    for (key, value) in object {
      guard OpenUnicodeV2.valid(key, maxBytes: maxKeyBytes, allowEmpty: false) else {
        throw StreamMetadataError.invalidValue
      }
      try validate(value, depth: depth + 1, nodeCount: &nodeCount)
    }
  }

  private static func validate(
    _ value: JSONValue,
    depth: Int,
    nodeCount: inout Int
  ) throws {
    guard depth <= maxDepth else { throw StreamMetadataError.invalidValue }
    nodeCount += 1
    guard nodeCount <= maxNodes else { throw StreamMetadataError.invalidValue }
    switch value {
    case .null, .bool:
      return
    case .integer(let integer):
      guard absSafe(integer) <= maximumSafeInteger else {
        throw StreamMetadataError.invalidValue
      }
    case .string(let string):
      guard OpenUnicodeV2.valid(string, maxBytes: maxStringBytes, allowEmpty: true) else {
        throw StreamMetadataError.invalidValue
      }
    case .array(let array):
      guard array.count <= maxArrayItems else { throw StreamMetadataError.invalidValue }
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

  private static func foundationObject(_ object: [String: JSONValue]) throws -> [String: Any] {
    try object.mapValues(foundationValue)
  }

  private static func foundationValue(_ value: JSONValue) throws -> Any {
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

public protocol ByteStream: Sendable {
  var kind: String { get }

  func read(maxBytes: Int) async throws -> Data?
  func write(_ data: Data) async throws -> Int
  func closeWrite() async throws
  func reset() async throws
  func close() async throws
  func terminalError() async -> SessionError?
}

public struct IncomingStream: Sendable {
  public let kind: String
  public let metadata: StreamMetadata
  public let stream: any ByteStream

  public init(
    kind: String,
    metadata: StreamMetadata,
    stream: any ByteStream
  ) {
    self.kind = kind
    self.metadata = metadata
    self.stream = stream
  }
}

public protocol RPCPeer: Sendable {
  func call<Request: Encodable & Sendable, Response: Decodable & Sendable>(
    _ typeID: UInt32,
    _ request: Request,
    as responseType: Response.Type,
    timeout: Duration
  ) async throws -> Response

  func notify<Payload: Encodable & Sendable>(_ typeID: UInt32, _ payload: Payload) async throws

  func subscribeNotification<Payload: Decodable & Sendable>(
    _ typeID: UInt32,
    as payloadType: Payload.Type,
    handler: @escaping @Sendable (Result<Payload, RPCNotificationError>) async throws -> Void
  ) async throws -> any RPCNotificationSubscription
}

public protocol Session: Sendable {
  var rpc: any RPCPeer { get }

  func openStream(kind: String, metadata: StreamMetadata) async throws -> any ByteStream
  func acceptStream() async throws -> IncomingStream
  func rekey() async throws
  func probeLiveness() async throws -> Duration
  func waitTermination() async -> SessionTermination
  func close() async throws
}

extension Session {
  public func openStream(kind: String) async throws -> any ByteStream {
    try await openStream(kind: kind, metadata: .empty)
  }
}
