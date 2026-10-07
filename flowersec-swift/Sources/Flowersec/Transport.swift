import Foundation

private extension UInt8 {
  var isASCIIAlpha: Bool { (65...90).contains(self) || (97...122).contains(self) }
  var isASCIILower: Bool { (97...122).contains(self) }
  var isASCIIDigit: Bool { (48...57).contains(self) }
}

public indirect enum JSONValue: Equatable, Sendable {
  case null
  case bool(Bool)
  case integer(Int64)
  case number(Double)
  case string(String)
  case array([JSONValue])
  case object([String: JSONValue])
}

public enum StreamMetadataError: Error, Equatable, Sendable {
  case invalidValue
}

public enum RawStreamMetadataType: String, Sendable {
  case string, number, boolean
}

public struct RawStreamMetadataField: Sendable, Equatable {
  public let name: String
  public let type: RawStreamMetadataType
  public let required: Bool

  public init(name: String, type: RawStreamMetadataType, required: Bool = false) {
    self.name = name
    self.type = type
    self.required = required
  }
}

/// A frozen data-only descriptor for a raw Stream metadata projection.
/// Applying it never changes the authenticated metadata bytes or installs a decoder.
public struct RawStreamMetadataContract: Sendable, Equatable {
  public let contractID: String
  public let namespace: String
  public let version: UInt16
  public let codec: String
  public let fields: [RawStreamMetadataField]
  public let maxEncodedBytes: Int
  public let maxDecodedBytes: Int

  public init(contractID: String, namespace: String, version: UInt16, codec: String = "application/json",
              fields: [RawStreamMetadataField], maxEncodedBytes: Int = 4096, maxDecodedBytes: Int = 4096) throws {
    guard Self.validIdentifier(contractID, maximum: 128), Self.validNamespace(namespace), codec == "application/json",
          fields.count <= 64, (1...4096).contains(maxEncodedBytes), (1...4096).contains(maxDecodedBytes),
          Set(fields.map(\.name)).count == fields.count,
          fields.allSatisfy({ Self.validIdentifier($0.name, maximum: 64) }) else {
      throw StreamMetadataError.invalidValue
    }
    self.contractID = contractID
    self.namespace = namespace
    self.version = version
    self.codec = codec
    self.fields = fields
    self.maxEncodedBytes = maxEncodedBytes
    self.maxDecodedBytes = maxDecodedBytes
  }

  private static func validIdentifier(_ value: String, maximum: Int) -> Bool {
    let bytes = Array(value.utf8)
    guard !bytes.isEmpty, bytes.count <= maximum,
          value.precomposedStringWithCanonicalMapping == value,
          bytes[0].isASCIIAlpha else { return false }
    return bytes.dropFirst().allSatisfy { $0.isASCIIAlpha || $0.isASCIIDigit || $0 == 95 || $0 == 46 || $0 == 45 }
  }

  private static func validNamespace(_ value: String) -> Bool {
    guard value.utf8.count <= 64, !value.hasPrefix("flowersec/"),
          value.precomposedStringWithCanonicalMapping == value,
          let slash = value.firstIndex(of: "/"), slash != value.startIndex,
          slash < value.index(before: value.endIndex) else { return false }
    func validPart(_ part: Substring) -> Bool {
      let bytes = Array(part.utf8)
      guard !bytes.isEmpty, bytes.count <= 32, bytes[0].isASCIILower || bytes[0].isASCIIDigit else { return false }
      return bytes.dropFirst().allSatisfy { $0.isASCIILower || $0.isASCIIDigit || $0 == 95 || $0 == 46 || $0 == 45 }
    }
    return validPart(value[..<slash]) && validPart(value[value.index(after: slash)...])
  }
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
  case livenessPathUnresponsive = "liveness_path_unresponsive"
  case idleTimeout = "idle_timeout"
  case timeUnavailable = "time_unavailable"
  case operationFailed = "operation_failed"
}

/// Stable, redacted reason for authoritative session termination.
public struct SessionTermination: Equatable, Sendable {
  public let error: SessionError

  public init(error: SessionError) {
    self.error = error
  }
}

public struct StreamMetadata: Equatable, Sendable {
  public static let empty = StreamMetadata()

  /// Optional application JSON projection. Other namespaces remain opaque.
  public var values: [String: JSONValue] { (try? jsonValues()) ?? [:] }
  let v4Encoded: Data?
  private let v4Projection: V4StreamMetadataProjection?
  private let v4DescriptorProjection: [String: JSONValue]?

  public var namespace: String? { v4Projection?.namespace }
  public var version: UInt16? { v4Projection?.version }
  public var byteValues: [String: Data]? { v4Projection?.values }

  private init() {
    v4Encoded = nil
    v4Projection = nil
    v4DescriptorProjection = nil
  }

  public init(namespace: String, version: UInt16, values: [String: Data]) throws {
    try self.init(
      encoded: V4StreamMetadataCodec.encode(
        namespace: namespace, version: version, values: values))
  }

  /// Validates exact deterministic CBOR. Zero bytes is the empty sentinel.
  public init(encoded: Data) throws {
    try self.init(encoded: encoded, descriptorProjection: nil)
  }

  private init(encoded: Data, descriptorProjection: [String: JSONValue]?) throws {
    if encoded.isEmpty {
      self = .empty
      return
    }
    self.v4Projection = try V4StreamMetadataCodec.decode(encoded)
    self.v4Encoded = encoded
    self.v4DescriptorProjection = descriptorProjection
  }

  public func encoded() throws -> Data { v4Encoded ?? Data() }

  public func descriptorValues() throws -> [String: JSONValue] {
    guard let values = v4DescriptorProjection else { throw StreamMetadataError.invalidValue }
    return values
  }

  public func applyingRawMetadataContract(_ contract: RawStreamMetadataContract) throws -> StreamMetadata {
    let encoded = try encoded()
    guard encoded.count <= contract.maxEncodedBytes,
          namespace == contract.namespace, version == contract.version else {
      throw StreamMetadataError.invalidValue
    }
    let bytes = byteValues ?? [:]
    let fields = Dictionary(uniqueKeysWithValues: contract.fields.map { ($0.name, $0) })
    guard bytes.keys.allSatisfy({ fields[$0] != nil }), contract.fields.allSatisfy({ !$0.required || bytes[$0.name] != nil }) else {
      throw StreamMetadataError.invalidValue
    }
    var projected: [String: JSONValue] = [:]
    var decoded = 0
    for (key, raw) in bytes {
      let field = fields[key]!
      let value: JSONValue
      do { value = try JSONDecoder().decode(JSONValue.self, from: raw) } catch { throw StreamMetadataError.invalidValue }
      switch (field.type, value) {
      case (.string, .string(let text)):
        decoded += key.utf8.count + text.utf8.count
      case (.number, .integer(_)):
        decoded += key.utf8.count + 8
      case (.number, .number(let number)) where number.isFinite:
        decoded += key.utf8.count + 8
      case (.boolean, .bool(_)):
        decoded += key.utf8.count + 1
      default:
        throw StreamMetadataError.invalidValue
      }
      guard decoded <= contract.maxDecodedBytes else { throw StreamMetadataError.invalidValue }
      projected[key] = value
    }
    return try StreamMetadata(encoded: encoded, descriptorProjection: projected)
  }

  /// JSON is an application codec inside the same ordinary v4 byte-map shell.
  public init(_ values: [String: JSONValue]) throws {
    if values.isEmpty {
      self = .empty
      return
    }
    guard values.count <= 64 else { throw StreamMetadataError.invalidValue }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    var encoded: [String: Data] = [:]
    var total = 0
    for (key, value) in values {
      // Bound traversal and temporary encoding before allocating the shell.
      var remaining = 1024
      try value.validateMetadataJSON(depth: 0, remaining: &remaining)
      let data = try encoder.encode(value)
      total += data.count + key.utf8.count
      guard data.count <= 1024, total <= 4096 else { throw StreamMetadataError.invalidValue }
      encoded[key] = data
    }
    try self.init(namespace: "application/json", version: 1, values: encoded)
  }

  public func jsonValues() throws -> [String: JSONValue] {
    guard let projection = v4Projection else { return [:] }
    guard projection.namespace == "application/json", projection.version == 1 else {
      throw StreamMetadataError.invalidValue
    }
    do {
      return try projection.values.mapValues { try JSONDecoder().decode(JSONValue.self, from: $0) }
    } catch { throw StreamMetadataError.invalidValue }
  }
}

extension JSONValue: Codable {
  public init(from decoder: any Decoder) throws {
    let value = try decoder.singleValueContainer()
    if value.decodeNil() {
      self = .null
    } else if let boolean = try? value.decode(Bool.self) {
      self = .bool(boolean)
    } else if let integer = try? value.decode(Int64.self) {
      self = .integer(integer)
    } else if let number = try? value.decode(Double.self), number.isFinite {
      self = .number(number)
    } else if let string = try? value.decode(String.self) {
      self = .string(string)
    } else if let array = try? value.decode([JSONValue].self) {
      self = .array(array)
    } else {
      self = .object(try value.decode([String: JSONValue].self))
    }
  }

  public func encode(to encoder: any Encoder) throws {
    var output = encoder.singleValueContainer()
    switch self {
    case .null: try output.encodeNil()
    case .bool(let value): try output.encode(value)
    case .integer(let value): try output.encode(value)
    case .number(let value):
      guard value.isFinite else { throw StreamMetadataError.invalidValue }
      try output.encode(value)
    case .string(let value): try output.encode(value)
    case .array(let value): try output.encode(value)
    case .object(let value): try output.encode(value)
    }
  }

  fileprivate func validateMetadataJSON(depth: Int, remaining: inout Int) throws {
    guard depth <= 64, remaining > 0 else { throw StreamMetadataError.invalidValue }
    remaining -= 1
    switch self {
    case .null, .bool, .integer: break
    case .number(let value):
      guard value.isFinite else { throw StreamMetadataError.invalidValue }
    case .string(let value): remaining -= value.utf8.count
    case .array(let values):
      guard values.count <= remaining else { throw StreamMetadataError.invalidValue }
      for value in values {
        try value.validateMetadataJSON(depth: depth + 1, remaining: &remaining)
      }
    case .object(let values):
      guard values.count <= remaining else { throw StreamMetadataError.invalidValue }
      for (key, value) in values {
        remaining -= key.utf8.count
        try value.validateMetadataJSON(depth: depth + 1, remaining: &remaining)
      }
    }
    guard remaining >= 0 else { throw StreamMetadataError.invalidValue }
  }
}

public protocol ByteStream: Sendable {
  var kind: String { get }

  func read(maxBytes: Int) async throws -> Data?
  func write(_ data: Data) async throws -> Int
  func closeWrite() async throws
  /// Waits for authenticated send drain. Providers without an independent
  /// drain signal must throw instead of claiming graceful completion.
  func finish() async throws
  func reset() async throws
  func close() async throws
  func terminalError() async -> SessionError?
}

extension ByteStream {
  public func finish() async throws { throw SessionError.operationFailed }
}

public struct IncomingStream: Sendable {
  public let kind: String
  public let metadata: StreamMetadata
  public let stream: any ByteStream
  public let applicationContext: ApplicationInvocationContext?
  let preparedMessageHandler: V4PreparedMessageHandler?

  public init(
    kind: String,
    metadata: StreamMetadata,
    stream: any ByteStream,
    applicationContext: ApplicationInvocationContext? = nil
  ) {
    self.kind = kind
    self.metadata = metadata
    self.stream = stream
    self.applicationContext = applicationContext
    preparedMessageHandler = nil
  }

  init(
    kind: String, metadata: StreamMetadata, stream: any ByteStream,
    applicationContext: ApplicationInvocationContext? = nil,
    preparedMessageHandler: V4PreparedMessageHandler?
  ) {
    self.kind = kind; self.metadata = metadata; self.stream = stream
    self.applicationContext = applicationContext
    self.preparedMessageHandler = preparedMessageHandler
  }

  func closeHandlerStream() async {
    if let preparedMessageHandler { await preparedMessageHandler.close() }
    else { try? await stream.reset() }
  }
}

public protocol Session: Sendable {
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
