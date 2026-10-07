import Foundation
import Crypto

public struct ApplicationCheckpoint: Sendable, Equatable {
  public let format: String
  public let position: Data
  public init(format: String, position: Data) throws {
    guard V4NamespaceRegistry.securityID(format.utf8), position.count <= 4096 else { throw ServiceFailure.configurationCapacity }
    self.format = format; self.position = position.withUnsafeBytes { Data($0) }
  }
  func encoded() -> Data { V4Crypto.map([(0, V4Crypto.text(format)), (1, V4Crypto.bytes(position))]) }
  init(_ value: V4NamespaceValue) throws { try self.init(format: value.t("format"), position: value.b("position")) }
}
public enum CheckpointTokenProtection: UInt64, Sendable { case ed25519 = 0, hmacSHA256 = 1 }
public struct CheckpointVerificationKey: Sendable {
  public let protection: CheckpointTokenProtection
  public let keyID: Data
  let key: Data
  public init(protection: CheckpointTokenProtection, keyID: Data, key: Data) throws {
    guard keyID.count == 16, key.count == 32 else { throw ServiceFailure.configurationCapacity }
    self.protection = protection; self.keyID = Data(keyID); self.key = Data(key)
  }
}
/// Protected bytes are copied into TransportEnvironment-owned bounded storage. Parsed
/// claims alone grant neither Start nor recovery transaction authority.
public final class ApplicationCheckpointToken: @unchecked Sendable, CustomStringConvertible {
  let encoded: Data
  let protection: CheckpointTokenProtection
  let tenant: String
  let caller: String
  let audience: String
  let namespace: String
  let operation: Data
  let request: Data
  public let checkpoint: ApplicationCheckpoint
  public let generation: UInt64
  public let issuedAtMS: UInt64
  public let expiresAtMS: UInt64
  private let storage: V4CryptoReservation
  init(environment: V4EnvironmentFoundation, encoded: Data, protection: CheckpointTokenProtection,
    verificationKey: CheckpointVerificationKey?) throws {
    guard encoded.count <= (protection == .ed25519 ? 4980 : 4948) else { throw ServiceFailure.configurationCapacity }
    storage = try environment.resumeStorage()
    let registry = try V4NamespaceRegistry()
    let schema = protection == .ed25519 ? "ResumeSignedToken" : "ResumeMACToken"
    let document = try V4NamespaceDocument(encoded, schema: schema, bytes: 4980, nodes: 128, registry: registry)
    let token = document.root; let claims = try token.field("claims")
    tenant = try claims.t("tenant_id"); caller = try claims.t("caller_identity"); audience = try claims.t("audience")
    namespace = try claims.t("service_namespace"); operation = try claims.b("operation_id"); request = try claims.b("request_digest")
    checkpoint = try ApplicationCheckpoint(claims.field("checkpoint")); generation = try claims.u("generation")
    issuedAtMS = try claims.u("issued_at_ms"); expiresAtMS = try claims.u("expires_at_ms")
    guard issuedAtMS < expiresAtMS else { throw ServiceFailure.protocolFailure }
    if let verificationKey {
      guard verificationKey.protection == protection, try token.b("key_id") == verificationKey.keyID else { throw ServiceFailure.permissionDenied }
      if protection == .ed25519 { try token.verify("resume_token_signature", publicKey: verificationKey.key) }
      else {
        let unsigned = V4Crypto.map([(0, Data(claims.raw)), (1, V4Crypto.bytes(verificationKey.keyID))])
        let (label, projection) = try registry.domain("resume_token_mac", schema: schema, operation: "hmac-sha256")
        guard projection == "without_mac" else { throw ServiceFailure.configurationCapacity }
        guard HMAC<SHA256>.isValidAuthenticationCode(try token.b("mac"), authenticating:
          label + V4Crypto.integer(UInt64(unsigned.count), width: 4) + unsigned,
          using: SymmetricKey(data: verificationKey.key)) else { throw ServiceFailure.permissionDenied }
      }
    }
    self.protection = protection; self.encoded = encoded.withUnsafeBytes { Data($0) }
  }
  public var description: String { "ApplicationCheckpointToken(redacted)" }
  func check(in environment: V4EnvironmentFoundation) throws {
    try storage.check(); guard storage.environment === environment else { throw ServiceFailure.permissionDenied }
  }
}

/// An exclusive original accepted native Stream target. It cannot be created
/// from persisted IDs or copied wire facts, and cannot move to another Session.
public final class ServiceResumeTarget: @unchecked Sendable, CustomStringConvertible {
  private var session: (any V4ServiceSession)?
  let kind: String
  let contextDigest: Data
  let streamID: UInt64
  let maximumTokenBytes: Int
  let maximumIssuedDurationMS: UInt64
  private let gate = NSLock()
  private var checkSource: (@Sendable () throws -> Void)?
  private var returnSource: (@Sendable () throws -> any ByteStream)?
  private var disposeSource: (@Sendable () -> Void)?
  private var selected = false
  init(session: any V4ServiceSession, kind: String, contextDigest: Data, streamID: UInt64,
    maximumTokenBytes: Int, maximumIssuedDurationMS: UInt64,
    check: @escaping @Sendable () throws -> Void,
    take: @escaping @Sendable () throws -> any ByteStream, dispose: @escaping @Sendable () -> Void) {
    self.session = session; self.kind = kind; self.contextDigest = contextDigest; self.streamID = streamID
    self.maximumTokenBytes = maximumTokenBytes; self.maximumIssuedDurationMS = maximumIssuedDurationMS
    checkSource = check; returnSource = take; disposeSource = dispose
  }
  func select(for session: any V4ServiceSession) throws {
    try gate.withLock {
      guard !selected, let checkSource, let originalSession = self.session, session === originalSession else { throw ServiceFailure.permissionDenied }
      try checkSource(); selected = true
    }
  }
  func check() throws { try gate.withLock { guard let checkSource else { throw ServiceFailure.closed }; try checkSource() } }
  func takeAtBoundary() throws -> any ByteStream {
    try gate.withLock {
      guard selected, let returnSource, let checkSource else { throw ServiceFailure.closed }
      try checkSource(); let stream = try returnSource()
      self.checkSource = nil; self.returnSource = nil; disposeSource = nil; session = nil; return stream
    }
  }
  public func close() {
    let original = gate.withLock { () -> (@Sendable () -> Void)? in
      let original = disposeSource; disposeSource = nil; checkSource = nil; returnSource = nil; session = nil; return original
    }
    original?()
  }
  public var description: String { "ServiceResumeTarget(redacted)" }
  deinit { close() }
}
public struct ServiceResumeResult: Sendable {
  public enum Status: String, Sendable { case accepted, rejected, unknown }
  public let status: Status
  public let checkpoint: ApplicationCheckpoint?
  public let generation: UInt64?
  public let stream: (any ByteStream)?
}
public final class ServiceResumeOperation: @unchecked Sendable {
  private let gate = NSLock()
  private let original: ServiceOperation<Data>
  private var target: ServiceResumeTarget?
  private let originalGeneration: UInt64
  private var storage: V4CryptoReservation?
  private var loading = false
  private var consumed = false
  private var closed = false
  init(original: ServiceOperation<Data>, target: ServiceResumeTarget, token: ApplicationCheckpointToken,
    storage: V4CryptoReservation) { self.original = original; self.target = target; originalGeneration = token.generation; self.storage = storage }
  public var reference: OperationReference { original.reference! }
  public var submission: OperationSubmission { original.submission }
  var preparationExpired: Bool { original.preparationExpired }
  public func start() async throws { try target?.check(); try await original.start() }
  public func takeResult() async throws -> ServiceResumeResult {
    try gate.withLock { guard !closed, !loading, !consumed else { throw ServiceFailure.closed }; loading = true }
    defer { gate.withLock { loading = false } }
    let encoded = try await original.takeEncodedResult()
    return try gate.withLock {
      guard !closed, let target, let storage else { throw ServiceFailure.closed }; try storage.check(); try target.check()
      let value = try V4NamespaceDocument(encoded.payload, schema: "ResumeResult", bytes: 4248, nodes: 128,
        registry: V4NamespaceRegistry()).root
      let statusCode = try value.u("status")
      let statuses: [ServiceResumeResult.Status] = [.accepted, .rejected, .unknown]
      guard statusCode < UInt64(statuses.count) else { throw ServiceFailure.protocolFailure }
      var checkpoint: ApplicationCheckpoint?
      var generation: UInt64?
      if let progress = try value.optional("progress") {
        checkpoint = try ApplicationCheckpoint(progress.field("confirmed_checkpoint")); generation = try progress.u("new_generation")
      }
      let status = statuses[Int(statusCode)]
      guard status != .accepted || checkpoint != nil && generation != nil && generation! > originalGeneration else { throw ServiceFailure.protocolFailure }
      let stream = status == .accepted ? try target.takeAtBoundary() : nil
      if status != .accepted { target.close() }
      consumed = true; self.target = nil; self.storage = nil
      return ServiceResumeResult(status: status, checkpoint: checkpoint, generation: generation, stream: stream)
    }
  }
  public func close() { gate.withLock { guard !closed else { return }; closed = true; original.close(); target?.close(); target = nil; storage = nil } }
  deinit { close() }
}

extension Session {
  public func captureResumeTarget(_ stream: any ByteStream, kind: String) throws -> ServiceResumeTarget {
    guard let session = self as? any V4ServiceSession else { throw ServiceFailure.serviceUnavailable }
    return try session.captureServiceResumeTarget(stream, kind: kind)
  }
}
extension ServiceClient {
  public func prepareResume(_ method: MethodDefinition, token: ApplicationCheckpointToken, target: ServiceResumeTarget,
    options: ServiceCallOptions) throws -> ServiceResumeOperation {
    try checkPreparation(); try token.check(in: environment)
    let snapshot = try contract(method)
    guard method.shape == .unary, method.semantics == .execution, let response = method.options.response,
      token.tenant == self.target.tenant, token.audience == self.target.audience, token.namespace == definition.namespace,
      let caller = self.target.executionCallerIdentity, token.caller == caller,
      token.encoded.count <= target.maximumTokenBytes,
      let interval = environment.clock.sample().interval, interval.lowerMS >= token.issuedAtMS, interval.upperMS < token.expiresAtMS,
      method.options.checkpointFormat == token.checkpoint.format else { throw ServiceFailure.permissionDenied }
    try target.select(for: session)
    do {
      let payload = V4Crypto.map([(0, V4Crypto.bytes(token.operation)), (1, V4Crypto.bytes(token.request)),
        (2, V4NamespaceValue.head(0, token.protection.rawValue)), (3, V4Crypto.bytes(token.encoded)),
        (4, V4NamespaceValue.head(0, token.generation)), (5, token.checkpoint.encoded()),
        (6, V4Crypto.bytes(target.contextDigest)), (7, V4NamespaceValue.head(0, target.streamID))])
      let storage = try environment.serviceOperationStorage(requestBytes: payload.count, responseBytes: 4248)
      let identity = UUID()
      let operation = try ServiceOperation(client: self, token: identity, method: method, snapshot: snapshot, payload: payload,
        codec: BytesMessageCodec(definition: response), options: options, storage: storage, resume: true,
        checkPrepared: { try target.check() })
      let result = ServiceResumeOperation(original: operation, target: target, token: token, storage: try environment.resumeStorage())
      do {
        try gate.withLock {
          try checkPreparation(); guard operations.count < 1024 else { throw ServiceFailure.resourceExhausted }
          operations[identity] = { [weak result] in result?.close() }
        }
        return result
      } catch { result.close(); throw error }
    } catch { target.close(); throw error }
  }
}
