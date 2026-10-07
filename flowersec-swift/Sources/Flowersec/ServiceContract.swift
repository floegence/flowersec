import Foundation
import Crypto

public enum ServiceShape: String, Sendable { case unary, serverStreaming = "server_streaming", notify }
public enum ServiceSemantics: String, Sendable { case transient, execution, observation }
public enum ServiceFailure: String, Error, Sendable {
  case configurationCapacity = "configuration_capacity"
  case resourceExhausted = "resource_exhausted"
  case closed, protocolFailure = "protocol_failure"
  case contractMismatch = "service_contract_mismatch"
  case contractPolicyRejected = "contract_policy_rejected"
  case admissionWindowClosed = "admission_window_closed"
  case deadlineExceeded = "deadline_exceeded"
  case permissionDenied = "permission_denied"
  case operationConflict = "operation_conflict"
  case historyUnknown = "history_unknown"
  case resultExpired = "result_expired"
  case serviceUnavailable = "service_unavailable"
  case serviceFailed = "service_failed"
}

public struct MessageDefinition: Sendable, Equatable {
  public let schemaDigest: Data
  public let revision: String
  public let maxMessageBytes: Int
  public init(schemaDigest: Data, revision: String, maxMessageBytes: Int) throws {
    guard schemaDigest.count == 32, schemaDigest.contains(where: { $0 != 0 }),
      V4NamespaceRegistry.securityID(revision.utf8), (1...1_048_576).contains(maxMessageBytes)
    else { throw ServiceFailure.configurationCapacity }
    self.schemaDigest = schemaDigest
    self.revision = revision
    self.maxMessageBytes = maxMessageBytes
  }
}

public enum MessageCodecFailure: String, Error, Sendable {
  case encodeFailed = "encode_failed"
  case decodeFailed = "decode_failed"
}

/// Application codecs borrow only an owned invocation payload. A codec has no
/// Session, credential, execution admission or recovery authority.
public protocol MessageCodec<Value>: Sendable {
  associatedtype Value: Sendable
  var definition: MessageDefinition { get }
  func encode(_ value: Value, into destination: inout Data) throws -> Int
  func decode(_ source: Data) throws -> Value
  func encode(_ value: Value, context: ApplicationInvocationContext, into destination: inout Data) throws -> Int
  func decode(_ source: Data, context: ApplicationInvocationContext) throws -> Value
}

extension MessageCodec {
  public func encode(_ value: Value, context: ApplicationInvocationContext, into destination: inout Data) throws -> Int {
    try encode(value, into: &destination)
  }
  public func decode(_ source: Data, context: ApplicationInvocationContext) throws -> Value {
    try decode(source)
  }
}
/// An asynchronous codec always enters a separately admitted application
/// invocation. Awaiting application work retains its original permit; the
/// synchronous entry is never used as a substitute for this async contract.
public protocol AsyncMessageCodec<Value>: MessageCodec {
  /// Optional callback for server request decoding. Its isolation must identify
  /// the decoder's actual executor; method references and forwarding closures
  /// can hide an actor hop. Other codec roles use decodeAsync as usual.
  var applicationDecodeCallback: (@isolated(any) @Sendable (Data, ApplicationInvocationContext) async throws -> Value)? { get }
  func encodeAsync(_ value: Value, context: ApplicationInvocationContext) async throws -> Data
  func decodeAsync(_ source: Data, context: ApplicationInvocationContext) async throws -> Value
}

extension AsyncMessageCodec {
  public var applicationDecodeCallback: (@isolated(any) @Sendable (Data, ApplicationInvocationContext) async throws -> Value)? { nil }
  public func encode(_ value: Value, into destination: inout Data) throws -> Int {
    throw MessageCodecFailure.encodeFailed
  }
  public func decode(_ source: Data) throws -> Value {
    throw MessageCodecFailure.decodeFailed
  }
}

// Only concrete SDK adapters defer the user-work run clock past parsing.
// Application codecs cannot claim this marker through the public API.
protocol V4SDKServiceMessageCodec: Sendable {}

/// A concrete byte payload codec. Empty payloads are valid messages.
public struct BytesMessageCodec: MessageCodec, V4SDKServiceMessageCodec {
  public let definition: MessageDefinition
  public init(definition: MessageDefinition) { self.definition = definition }
  public func encode(_ value: Data, into destination: inout Data) throws -> Int {
    guard value.count <= definition.maxMessageBytes else { throw MessageCodecFailure.encodeFailed }
    destination = Data(value)
    return destination.count
  }
  public func decode(_ source: Data) throws -> Data {
    guard source.count <= definition.maxMessageBytes else { throw MessageCodecFailure.decodeFailed }
    return Data(source)
  }
}

/// A primitive UTF-8 codec with strict decoding. Invalid UTF-8 is a bounded
/// codec failure at the known message boundary, never an implicit replacement.
public struct UTF8MessageCodec: MessageCodec, V4SDKServiceMessageCodec {
  public let definition: MessageDefinition
  public init(definition: MessageDefinition) { self.definition = definition }
  public func encode(_ value: String, into destination: inout Data) throws -> Int {
    destination.removeAll(keepingCapacity: true)
    for byte in value.utf8 {
      guard destination.count < definition.maxMessageBytes else { throw MessageCodecFailure.encodeFailed }
      destination.append(byte)
    }
    return destination.count
  }
  public func decode(_ source: Data) throws -> String {
    guard source.count <= definition.maxMessageBytes, let value = String(data: source, encoding: .utf8) else {
      throw MessageCodecFailure.decodeFailed
    }
    return value
  }
}

public struct ApplicationErrorDefinition: Sendable, Equatable {
  public let code: UInt32
  public let message: MessageDefinition
  public let maxPayloadBytes: Int
  public init(code: UInt32, message: MessageDefinition, maxPayloadBytes: Int) throws {
    guard code > 0, (0...message.maxMessageBytes).contains(maxPayloadBytes) else {
      throw ServiceFailure.configurationCapacity
    }
    self.code = code; self.message = message; self.maxPayloadBytes = maxPayloadBytes
  }
}
public struct StreamContentDefinition: Sendable, Equatable {
  public let schemaRevision: String
  public let canonical: Data
  public let readTypeID: UInt32
  public init(schemaRevision: String, canonical: Data, readTypeID: UInt32) throws {
    guard V4NamespaceRegistry.securityID(schemaRevision.utf8), (1...2048).contains(canonical.count), readTypeID > 0 else {
      throw ServiceFailure.configurationCapacity
    }
    self.schemaRevision = schemaRevision; self.canonical = canonical; self.readTypeID = readTypeID
  }
}
public struct StreamingLimits: Sendable, Equatable {
  public let maxItemCount: UInt32
  public let maxPayloadBytes: UInt64
  public let maxDurationMS: UInt64
  public init(maxItemCount: UInt32, maxPayloadBytes: UInt64, maxDurationMS: UInt64) throws {
    guard maxItemCount > 0, maxPayloadBytes > 0, maxDurationMS > 0 else { throw ServiceFailure.configurationCapacity }
    self.maxItemCount = maxItemCount; self.maxPayloadBytes = maxPayloadBytes; self.maxDurationMS = maxDurationMS
  }
}
public struct MethodDefinitionOptions: Sendable {
  public let typeID: UInt32
  public let shape: ServiceShape
  public let semantics: ServiceSemantics
  public let request: MessageDefinition
  public let response: MessageDefinition?
  public let responseRevision: String
  public let requestMaxBytes: Int
  public let minResponseLimitBytes: Int
  public let maxResponseBytes: Int
  public let requireDurable: Bool
  public let checkpointFormat: String?
  public let restartFlushDeadlineMS: UInt64?
  public let streaming: StreamingLimits?
  public let content: StreamContentDefinition?
  public let errors: [ApplicationErrorDefinition]
  public init(
    typeID: UInt32, shape: ServiceShape, semantics: ServiceSemantics,
    request: MessageDefinition, response: MessageDefinition? = nil,
    responseRevision: String, requestMaxBytes: Int,
    minResponseLimitBytes: Int = 0, maxResponseBytes: Int = 0,
    requireDurable: Bool = false, checkpointFormat: String? = nil,
    restartFlushDeadlineMS: UInt64? = nil, streaming: StreamingLimits? = nil,
    content: StreamContentDefinition? = nil, errors: [ApplicationErrorDefinition] = []
  ) {
    self.typeID = typeID; self.shape = shape; self.semantics = semantics
    self.request = request; self.response = response; self.responseRevision = responseRevision
    self.requestMaxBytes = requestMaxBytes; self.minResponseLimitBytes = minResponseLimitBytes
    self.maxResponseBytes = maxResponseBytes; self.requireDurable = requireDurable
    self.checkpointFormat = checkpointFormat; self.restartFlushDeadlineMS = restartFlushDeadlineMS
    self.streaming = streaming; self.content = content; self.errors = errors.sorted { $0.code < $1.code }
  }
}

/// Immutable local type information. Installing a concrete remote contract and
/// acquiring execution permission are separate original-owner gates.
public final class MethodDefinition: Sendable {
  public let options: MethodDefinitionOptions
  public var typeID: UInt32 { options.typeID }
  public var shape: ServiceShape { options.shape }
  public var semantics: ServiceSemantics { options.semantics }
  public init(_ options: MethodDefinitionOptions) throws {
    let o = options
    guard o.typeID > 0, (0...o.request.maxMessageBytes).contains(o.requestMaxBytes),
      (0...1_048_576).contains(o.maxResponseBytes), (0...o.maxResponseBytes).contains(o.minResponseLimitBytes),
      V4NamespaceRegistry.securityID(o.responseRevision.utf8), o.errors.count <= 64,
      !(o.requireDurable && o.semantics != .execution),
      !(o.shape == .notify && o.semantics == .transient),
      !(o.shape != .notify && o.semantics == .observation),
      (o.shape == .serverStreaming) == (o.streaming != nil)
    else { throw ServiceFailure.configurationCapacity }
    if o.shape == .notify {
      guard o.response == nil, o.minResponseLimitBytes == 0, o.maxResponseBytes == 0, o.errors.isEmpty else {
        throw ServiceFailure.configurationCapacity
      }
    } else {
      guard let response = o.response, response.revision == o.responseRevision, o.maxResponseBytes <= response.maxMessageBytes else {
        throw ServiceFailure.configurationCapacity
      }
    }
    if let deadline = o.restartFlushDeadlineMS {
      guard (1...120_000).contains(deadline), o.shape == .unary, o.semantics == .execution else { throw ServiceFailure.configurationCapacity }
    }
    if let format = o.checkpointFormat {
      guard o.semantics == .execution, V4NamespaceRegistry.securityID(format.utf8) else { throw ServiceFailure.configurationCapacity }
    }
    if let content = o.content {
      guard o.shape == .serverStreaming, o.semantics == .execution,
        content.readTypeID != o.typeID, (1...2048).contains(content.canonical.count)
      else { throw ServiceFailure.configurationCapacity }
    }
    for (index, error) in o.errors.enumerated() {
      guard !o.errors[..<index].contains(where: { $0.code == error.code }) else { throw ServiceFailure.configurationCapacity }
    }
    self.options = options
  }
}
public struct ServiceMethod: Sendable {
  public let name: String
  public let exportName: String
  public let method: MethodDefinition
  public init(name: String, exportName: String? = nil, method: MethodDefinition) {
    self.name = name; self.exportName = exportName ?? name; self.method = method
  }
}
public struct ServiceDefinition: Sendable {
  public let namespace: String
  public let methods: [ServiceMethod]
  public init(namespace: String, methods: [ServiceMethod]) throws {
    guard V4NamespaceRegistry.securityID(namespace.utf8), (1...256).contains(methods.count) else {
      throw ServiceFailure.configurationCapacity
    }
    let reserved: Set<String> = ["close", "info", "contract", "refresh", "updateContract", "prepareOperation", "prepareAndSave", "call", "stream", "notify", "cleanupStatus", "waitCleanup"]
    func member(_ text: String) -> Bool {
      let bytes = Array(text.utf8)
      guard (1...128).contains(bytes.count), !reserved.contains(text),
        let first = bytes.first, (65...90).contains(first) || (97...122).contains(first) || first == 95 else { return false }
      return bytes.allSatisfy { (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 95 }
    }
    for (index, entry) in methods.enumerated() {
      guard member(entry.name), member(entry.exportName),
        !methods[..<index].contains(where: { $0.name == entry.name || $0.exportName == entry.exportName || $0.method.typeID == entry.method.typeID })
      else { throw ServiceFailure.configurationCapacity }
    }
    for entry in methods {
      if let content = entry.method.options.content {
        guard let reader = methods.first(where: { $0.method.typeID == content.readTypeID }), reader.method.shape == .unary else {
          throw ServiceFailure.configurationCapacity
        }
      }
    }
    self.namespace = namespace; self.methods = methods
  }
  func contains(_ method: MethodDefinition) -> Bool { methods.contains { $0.method === method } }
}

/// An exact immutable canonical advertisement. It contains no dispatch or
/// publication capability. The TransportEnvironment owns its finite parsing workspace.
public final class ServiceContract: @unchecked Sendable {
  private let reservation: V4CryptoReservation
  private let registry: V4NamespaceRegistry
  private let parser: V4ServiceContractParser
  private var gate: NSRecursiveLock { reservation.environment.gate }
  private let fields: [Range<Int>?]
  private let responseSchemaRevision: String
  private let streamCheckpointFormat: String?
  private let canonical: Data
  private let contractDigest: Data
  public let namespace: String
  public let typeID: UInt32
  public let shape: ServiceShape
  public let semantics: ServiceSemantics
  private let uints: [UInt64?]
  convenience init(environment: V4EnvironmentFoundation, canonical: Data) throws {
    let storage = try environment.serviceContractStorage(bytes: canonical.count)
    let parser = try environment.serviceContractParser()
    let captured = try parser.withDocument(canonical, schema: "ServiceContract", bytes: 8192, nodes: 1024) { value in
      (try V4CompactServiceContract(document: value.document), try value.digest("service_contract_digest"))
    }
    try self.init(canonical: canonical, captured: captured.0, digest: captured.1, reservation: storage, parser: parser)
  }
  convenience init(canonical: Data, document: V4NamespaceDocument, digest: Data, reservation: V4CryptoReservation) throws {
    guard canonical.elementsEqual(document.bytes) else { throw ServiceFailure.protocolFailure }
    let captured = try V4CompactServiceContract(document: document)
    try self.init(canonical: canonical, captured: captured, digest: digest, reservation: reservation,
      parser: reservation.environment.serviceContractParser())
  }
  private init(canonical: Data, captured: V4CompactServiceContract, digest: Data,
    reservation: V4CryptoReservation, parser: V4ServiceContractParser) throws {
    guard digest.count == 32 else { throw ServiceFailure.protocolFailure }
    self.reservation = reservation; self.parser = parser; registry = parser.registry
    self.canonical = Data(canonical); contractDigest = digest
    fields = captured.fields; responseSchemaRevision = captured.responseSchemaRevision
    streamCheckpointFormat = captured.streamCheckpointFormat
    namespace = captured.namespace; typeID = captured.typeID; shape = captured.shape
    semantics = captured.semantics; uints = captured.uints
  }
  func encodedChunk(offset: Int, maximum: Int) throws -> Data {
    try reservation.check()
    guard offset >= 0, offset <= canonical.count, (1...4096).contains(maximum) else { throw ServiceFailure.configurationCapacity }
    return Data(canonical[offset..<min(canonical.count, offset + maximum)])
  }
  func environment() -> V4EnvironmentFoundation { reservation.environment }
  func responseRevision() throws -> String { try reservation.check(); return responseSchemaRevision }
  func checkpointFormat() throws -> String? { try reservation.check(); return streamCheckpointFormat }
  public var digest: Data { contractDigest }
  public var encodedBytes: Int { canonical.count }
  public func copyEncoded(into destination: inout Data) throws -> Int {
    guard destination.count >= canonical.count else { throw ServiceFailure.configurationCapacity }
    destination.replaceSubrange(0..<canonical.count, with: canonical)
    return canonical.count
  }
  func checkEnvironment(_ environment: V4EnvironmentFoundation) throws {
    guard reservation.environment === environment else { throw ServiceFailure.configurationCapacity }
    try reservation.check()
  }
  func uint(_ id: Int) throws -> UInt64 {
    guard uints.indices.contains(id), let value = uints[id] else { throw ServiceFailure.contractMismatch }
    return value
  }
  func optionalUInt(_ id: Int) -> UInt64? { uints.indices.contains(id) ? uints[id] : nil }
  func executionRequestDigest(header: V4ApplicationHeader, payload: Data) throws -> Data {
    try reservation.check()
    guard ["execution_unary_request", "execution_stream_request", "execution_notify", "resume_request"].contains(header.kind),
      try header.bytes(6) == digest, payload.count == (try header.payloadBytes) else { throw ServiceFailure.contractMismatch }
    let (label, parts) = try registry.compoundDomain("execution_request_digest", operation: "sha256")
    var hash = SHA256()
    hash.update(data: label)
    for part in parts {
      guard let name = part["name"] as? String, let encoding = part["encoding"] as? String else { throw ServiceFailure.protocolFailure }
      switch (name, encoding) {
      case ("contract", "lp-map"):
        hash.update(data: V4Crypto.integer(UInt64(canonical.count), width: 4)); hash.update(data: canonical)
      case ("operation_id", "lp-bytes"):
        hash.update(data: V4Crypto.integer(32, width: 4)); hash.update(data: try header.bytes(1))
      case ("payload", "lp-bytes"):
        hash.update(data: V4Crypto.integer(UInt64(payload.count), width: 4)); hash.update(data: payload)
      default:
        let id: Int
        switch name {
        case "message_kind": id = 0
        case "type_id": id = 2
        case "deadline_at_ms": id = 5
        case "admission_mode": id = 7
        case "response_limit_bytes": id = 8
        default: throw ServiceFailure.protocolFailure
        }
        let width: Int
        switch encoding { case "u8": width = 1; case "u32": width = 4; case "u64": width = 8; default: throw ServiceFailure.protocolFailure }
        hash.update(data: V4Crypto.integer(try header.uint(id), width: width))
      }
    }
    return Data(hash.finalize())
  }
  func decodeServiceFailure(_ payload: Data) throws -> ServiceFailure {
    try reservation.check()
    let code = try parser.withDocument(payload, schema: "ApplicationSDKError", bytes: 256, nodes: 8) { try $0.u("code") }
    switch code {
    case 3: return .contractMismatch
    case 4: return .contractPolicyRejected
    case 5: return .resourceExhausted
    case 6: return .serviceUnavailable
    case 7: return .permissionDenied
    case 8: return .deadlineExceeded
    case 9: return .serviceFailed
    case 10: return .serviceUnavailable
    case 11: return .operationConflict
    case 12: return .resultExpired
    default: throw ServiceFailure.protocolFailure
    }
  }
  func withDocument<T>(_ body: (V4NamespaceValue) throws -> T) throws -> T {
    try gate.withLock {
      try reservation.check()
      return try parser.withDocument(canonical, schema: "ServiceContract", bytes: 8192, nodes: 1024, body)
    }
  }
  func fieldEncoding(_ id: Int) throws -> Data? {
    try reservation.check()
    guard fields.indices.contains(id), let range = fields[id] else { return nil }
    return canonical.subdata(in: range)
  }
  fileprivate func captureOffer(_ canonical: Data, maximumWindowMS: UInt64) throws -> (Data, UInt64, UInt64) {
    try gate.withLock {
      try reservation.check()
      guard maximumWindowMS > 0, semantics == .execution else { throw ServiceFailure.configurationCapacity }
      let (digest, before, after) = try parser.withDocument(canonical, schema: "AdmissionOffer", bytes: 256, nodes: 16) { value in
        (try value.b("service_contract_digest"), try value.u("not_before_ms"), try value.u("not_after_ms"))
      }
      guard digest == contractDigest, before < after, after - before <= maximumWindowMS else { throw ServiceFailure.contractMismatch }
      return (digest, before, after)
    }
  }
  public func checkPolicy(_ policy: ContractAcceptance, current: ServiceContract? = nil, explicitUpdate: Bool = false) throws {
    try gate.withLock {
      try reservation.check()
      try policy.check(candidate: self, current: current, explicitUpdate: explicitUpdate)
    }
  }
  public func checkMethod(_ method: MethodDefinition, in definition: ServiceDefinition) throws {
    try gate.withLock {
      try reservation.check()
      try parser.withDocument(canonical, schema: "ServiceContract", bytes: 8192, nodes: 1024) { value in
      let o = method.options
      guard definition.contains(method), namespace == definition.namespace, typeID == method.typeID,
        shape == method.shape, semantics == method.semantics,
        try value.t("request_schema_revision") == o.request.revision,
        try value.t("response_schema_revision") == o.responseRevision,
        try uint(23) <= UInt64(o.requestMaxBytes), try uint(9) >= UInt64(o.minResponseLimitBytes),
        try uint(10) <= UInt64(o.maxResponseBytes),
        (!o.requireDurable || optionalUInt(13) == 1),
        try value.field("restart_flush").equals(o.restartFlushDeadlineMS != nil),
        optionalUInt(22) == o.restartFlushDeadlineMS,
        try value.optional("checkpoint_format")?.text() == o.checkpointFormat
      else { throw ServiceFailure.contractMismatch }
      if let stream = o.streaming {
        guard try uint(24) <= UInt64(stream.maxItemCount), try uint(25) <= stream.maxPayloadBytes, try uint(26) <= stream.maxDurationMS else { throw ServiceFailure.contractMismatch }
      }
      let catalog = try value.field("application_error_catalog")
      guard catalog.count == o.errors.count else { throw ServiceFailure.contractMismatch }
      for (index, entry) in catalog.children.enumerated() {
        let error = o.errors[index]
        guard try entry.u("code") == UInt64(error.code), try entry.t("schema_revision") == error.message.revision,
          try entry.u("max_payload_bytes") <= UInt64(error.maxPayloadBytes), try entry.b("schema_digest") == error.message.schemaDigest
        else { throw ServiceFailure.contractMismatch }
      }
      let content = try value.optional("stream_content_policy")
      let retained = try content.map { try $0.u("mode") == 1 } ?? false
      guard retained == (o.content != nil) else { throw ServiceFailure.contractMismatch }
      if let expected = o.content, let content {
        guard try content.t("definition_schema_revision") == expected.schemaRevision,
          try content.b("definition_bytes") == expected.canonical else { throw ServiceFailure.contractMismatch }
      }
      }
    }
  }
}

public struct AdmissionOffer: Sendable {
  private let contractDigest: Data
  public let notBeforeMS: UInt64
  public let notAfterMS: UInt64
  public init(canonical: Data, contract: ServiceContract, maximumWindowMS: UInt64) throws {
    let (digest, before, after) = try contract.captureOffer(canonical, maximumWindowMS: maximumWindowMS)
    contractDigest = digest; notBeforeMS = before; notAfterMS = after
  }
  func check(contract: ServiceContract, cutoff: UInt64, environment: V4EnvironmentFoundation) throws {
    try contract.checkEnvironment(environment)
    guard contractDigest == contract.digest, let now = environment.clock.sample().interval,
      now.lowerMS >= notBeforeMS, now.upperMS < cutoff, cutoff <= notAfterMS else { throw ServiceFailure.admissionWindowClosed }
  }
}

/// One charged, serialized parsing workspace serves compact immutable contracts.
/// A contract retains canonical bytes and field ranges, never a parser node graph.
final class V4ServiceContractParser: @unchecked Sendable {
  let registry: V4NamespaceRegistry
  private let storage: V4CryptoReservation
  init(storage: V4CryptoReservation) throws { self.storage = storage; registry = try V4NamespaceRegistry() }
  func withDocument<T>(_ canonical: Data, schema: String, bytes: Int, nodes: Int,
    _ body: (V4NamespaceValue) throws -> T) throws -> T {
    try storage.environment.gate.withLock {
      try storage.check()
      let original = try V4NamespaceDocument(canonical, schema: schema, bytes: bytes, nodes: nodes, registry: registry)
      return try body(original.root)
    }
  }
}

/// Finite scalars and canonical ranges extracted while the original parser is
/// owned. This value has no document/registry graph or callback capability.
private struct V4CompactServiceContract {
  let fields: [Range<Int>?]
  let responseSchemaRevision: String
  let streamCheckpointFormat: String?
  let namespace: String
  let typeID: UInt32
  let shape: ServiceShape
  let semantics: ServiceSemantics
  let uints: [UInt64?]
  init(document: V4NamespaceDocument) throws {
    guard document.parsingComplete, document.root.schema == "ServiceContract" else { throw ServiceFailure.protocolFailure }
    let value = document.root
    fields = (0..<29).map { id in
      guard let field = value.optionalID(id) else { return nil }
      return field.raw.startIndex..<field.raw.endIndex
    }
    responseSchemaRevision = try value.t("response_schema_revision")
    streamCheckpointFormat = try value.optional("checkpoint_format")?.text()
    namespace = try value.t("service_namespace"); typeID = UInt32(try value.u("type_id"))
    let code = try value.u("call_shape")
    shape = code == 0 ? .unary : code == 1 ? .serverStreaming : .notify
    let semanticsID = code == 0 ? 3 : code == 1 ? 4 : 5
    semantics = try value.fieldID(semanticsID).uint() == 1 ? .execution : code == 2 ? .observation : .transient
    uints = (0..<29).map { id in
      guard let field = value.optionalID(id), field.major == 0 else { return nil }
      return try? field.uint()
    }
  }
}
