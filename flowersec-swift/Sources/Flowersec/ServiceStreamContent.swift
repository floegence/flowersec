import Foundation

/// A selector supplied to the content definition's existing authorized read
/// method. It carries no execution, replay, or recovery authority.
public struct StreamContentTarget: Sendable, Equatable {
  public let tenant: String
  public let audience: String
  public let serviceNamespace: String
  public let callerSubject: String
  public let callerAuthority: Data
  public let operationID: Data
  public let requestDigest: Data
  public let serviceContractDigest: Data
  public init(tenant: String, audience: String, serviceNamespace: String, callerSubject: String,
    callerAuthority: Data, operationID: Data, requestDigest: Data, serviceContractDigest: Data) throws {
    guard [tenant, audience, serviceNamespace, callerSubject].allSatisfy({ V4NamespaceRegistry.securityID($0.utf8) }),
      [callerAuthority, operationID, requestDigest, serviceContractDigest].allSatisfy({ $0.count == 32 && $0.contains(where: { $0 != 0 }) }) else {
      throw ServiceFailure.configurationCapacity
    }
    self.tenant = tenant; self.audience = audience; self.serviceNamespace = serviceNamespace; self.callerSubject = callerSubject
    self.callerAuthority = Data(callerAuthority); self.operationID = Data(operationID)
    self.requestDigest = Data(requestDigest); self.serviceContractDigest = Data(serviceContractDigest)
  }
  #if os(macOS) || os(iOS)
  var selector: V4ServerExecutionSelector {
    V4ServerExecutionSelector(tenant: tenant, audience: audience, namespace: serviceNamespace, caller: callerSubject,
      authority: callerAuthority, operation: operationID, request: requestDigest, contract: serviceContractDigest)
  }
  #endif
}

extension OperationReference {
  public func streamContentTarget() throws -> StreamContentTarget {
    guard shape == .serverStreaming else { throw ServiceFailure.contractMismatch }
    return try StreamContentTarget(tenant: tenant, audience: audience, serviceNamespace: serviceNamespace,
      callerSubject: callerSubject, callerAuthority: callerAuthority, operationID: operationID,
      requestDigest: requestDigest, serviceContractDigest: serviceContractDigest)
  }
}

/// Actual store facts, independent of item delivery, execution completion, and
/// transport acknowledgement. A missing position is distinct from expiry.
public struct StreamContentObservation: Sendable, Equatable {
  public let found: Bool
  public let available: Bool
  public let expired: Bool
  public let committedAtMS: UInt64
  public let expiresAtMS: UInt64
  public let bytes: Int
  public let digest: Data
  static let missing = StreamContentObservation(found: false, available: false, expired: false,
    committedAtMS: 0, expiresAtMS: 0, bytes: 0, digest: Data(repeating: 0, count: 32))
}

public struct RetainedStreamContent: Sendable {
  public let observation: StreamContentObservation
  public let payload: Data?
}

struct V4ServiceStreamContentPolicy: Sendable, Equatable {
  let definition: StreamContentDefinition
  let origin: UInt64
  let retentionMS: UInt64
  let maximumItems: Int
  let maximumBytes: Int
  let durable: Bool
}

extension ServiceContract {
  func streamContentPolicy(_ definition: StreamContentDefinition?) throws -> V4ServiceStreamContentPolicy? {
    guard let definition else { return nil }
    return try withDocument { document in
    let policy = try document.field("stream_content_policy")
    guard shape == .serverStreaming, semantics == .execution, try policy.u("mode") == 1,
      try policy.t("definition_schema_revision") == definition.schemaRevision,
      try policy.b("definition_bytes") == definition.canonical else { throw ServiceFailure.contractMismatch }
    let items = try policy.u("max_retained_items"), bytes = try policy.u("max_retained_bytes")
    guard items > 0, items <= 131_072, bytes > 0, bytes <= 1 << 30 else { throw ServiceFailure.configurationCapacity }
    return try V4ServiceStreamContentPolicy(definition: definition, origin: policy.u("retention_origin"),
      retentionMS: policy.u("retention_ms"), maximumItems: Int(items), maximumBytes: Int(bytes), durable: uint(13) == 1)
    }
  }
}

// Content reads use the definition's existing typed unary method. The request
// codec owns its position/reference representation and available/missing/expiry
// response semantics; a saved selector cannot install another read route.
extension ServiceClient {
  public func prepareContentRead<Request: Sendable, Response: Sendable>(_ method: MethodDefinition,
    reference: OperationReference, request: Request, requestCodec: any MessageCodec<Request>,
    responseCodec: any MessageCodec<Response>, options: ServiceCallOptions) async throws -> ServiceOperation<Response> {
    try gate.withLock {
      try checkReference(reference)
      guard !closed, reference.shape == .serverStreaming, method.shape == .unary,
        let stream = definition.methods.first(where: { $0.method.shape == .serverStreaming &&
          snapshots[$0.method.typeID]?.contract.digest == reference.serviceContractDigest }),
        stream.method.options.content?.readTypeID == method.typeID, definition.contains(method) else { throw ServiceFailure.contractMismatch }
    }
    return try await prepareOperation(method, request: request, requestCodec: requestCodec, responseCodec: responseCodec, options: options)
  }
}
