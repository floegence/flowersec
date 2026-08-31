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

/// A bounded application-level error returned by a remote RPC handler.
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

public enum RPCNotificationError: Error, Equatable, Sendable {
  case invalidPayload
}

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
    guard depth <= maxDepth, object.count <= maxObjectKeys else {
      throw StreamMetadataError.invalidValue
    }
    for (key, value) in object {
      guard OpenUnicodeV3.valid(key, maxBytes: maxKeyBytes, allowEmpty: false) else {
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
      guard OpenUnicodeV3.valid(string, maxBytes: maxStringBytes, allowEmpty: true) else {
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
