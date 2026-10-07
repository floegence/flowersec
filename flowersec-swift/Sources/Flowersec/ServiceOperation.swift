import Foundation
import Crypto

/// A compact query selector. It retains no Session, request bytes, callback,
/// credentials or execution replay capability, including after local import.
public struct OperationReference: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
  public let targetDomain: String
  public let tenant: String
  public let audience: String
  public let serviceNamespace: String
  public let callerSubject: String
  public let callerAuthority: Data
  public let operationID: Data
  public let requestDigest: Data
  public let serviceContractDigest: Data
  public let shape: ServiceShape
  public let durable: Bool
  public let deadlineAtMS: UInt64
  public let cooperativeCancellation: Bool
  let resultLimit: Int
  public var description: String { "Flowersec.OperationReference(<redacted>)" }
  public var debugDescription: String { description }
  public var admissionNotAfterMS: UInt64 { operationID.prefix(8).reduce(0) { $0 << 8 | UInt64($1) } }
  init(target: ServiceBindingTarget, authority: Data, namespace: String, operation: Data, request: Data,
    contract: Data, shape: ServiceShape, durable: Bool, deadline: UInt64, cancellation: Bool, limit: Int) throws {
    guard authority.count == 32, authority.contains(where: { $0 != 0 }), operation.count == 32,
      request.count == 32, request.contains(where: { $0 != 0 }), contract.count == 32,
      contract.contains(where: { $0 != 0 }), V4NamespaceRegistry.securityID(namespace.utf8), (0...1_048_576).contains(limit) else {
      throw ServiceFailure.configurationCapacity
    }
    let cutoff = operation.prefix(8).reduce(0) { $0 << 8 | UInt64($1) }
    guard cutoff > 0, cutoff <= deadline else { throw ServiceFailure.configurationCapacity }
    targetDomain = target.authority; tenant = target.tenant; audience = target.audience
    serviceNamespace = namespace; callerSubject = target.localSubject; callerAuthority = Data(authority)
    operationID = Data(operation); requestDigest = Data(request); serviceContractDigest = Data(contract)
    self.shape = shape; self.durable = durable; deadlineAtMS = deadline; cooperativeCancellation = cancellation; resultLimit = limit
  }
  func targetEncoded() -> Data {
    V4Crypto.map([(0, V4Crypto.text(tenant)), (1, V4Crypto.text(audience)), (2, V4Crypto.text(serviceNamespace)),
      (3, V4Crypto.text(callerSubject)), (4, V4Crypto.bytes(callerAuthority)), (5, V4Crypto.bytes(operationID)),
      (6, V4Crypto.bytes(requestDigest)), (7, V4Crypto.bytes(serviceContractDigest))])
  }
  func encoded() -> Data {
    let shapeCode: UInt64 = shape == .unary ? 0 : shape == .serverStreaming ? 1 : 2
    return V4Crypto.map([(0, V4NamespaceValue.head(0, 1)), (1, V4Crypto.text(targetDomain)), (2, targetEncoded()),
      (3, V4NamespaceValue.head(0, shapeCode)), (4, V4NamespaceValue.head(0, durable ? 1 : 0)),
      (5, V4NamespaceValue.head(0, deadlineAtMS)), (6, V4NamespaceValue.head(0, cooperativeCancellation ? 1 : 0))])
  }
}

public final class OperationReferenceCodec: @unchecked Sendable {
  private let gate = NSLock()
  private let storage: V4CryptoReservation
  private let registry: V4NamespaceRegistry
  private var closed = false
  init(environment: V4EnvironmentFoundation) throws {
    storage = try environment.operationReferenceStorage()
    registry = try V4NamespaceRegistry()
  }
  public func export(_ reference: OperationReference, into destination: inout Data) throws -> Int {
    try gate.withLock {
      guard !closed else { throw ServiceFailure.closed }; try storage.check()
      let encoded = reference.encoded()
      guard destination.count >= encoded.count else { throw ServiceFailure.resourceExhausted }
      destination.replaceSubrange(0..<encoded.count, with: encoded)
      return encoded.count
    }
  }
  public func importReference(_ encoded: Data, target: ServiceBindingTarget) throws -> OperationReference {
    try gate.withLock {
      guard !closed else { throw ServiceFailure.closed }; try storage.check()
      let value = try V4NamespaceDocument(encoded, schema: "OperationReference", bytes: 2048, nodes: 64, registry: registry).root
      let scope = try value.field("target")
      guard try value.t("target_domain") == target.authority, try scope.t("tenant_id") == target.tenant,
        try scope.t("audience") == target.audience, try scope.t("caller_subject") == target.localSubject else {
        throw ServiceFailure.permissionDenied
      }
      let code = try value.u("call_shape")
      return try OperationReference(target: target, authority: scope.b("caller_authority"), namespace: scope.t("service_namespace"),
        operation: scope.b("operation_id"), request: scope.b("request_digest"), contract: scope.b("service_contract_digest"),
        shape: code == 0 ? .unary : code == 1 ? .serverStreaming : .notify, durable: value.u("execution_mode") == 1,
        deadline: value.u("deadline_at_ms"), cancellation: value.u("cancel_mode") == 1, limit: 1_048_576)
    }
  }
  public func close() { gate.withLock { closed = true; storage.seal() } }
}

public enum OperationSubmission: String, Sendable { case notSubmitted = "not_submitted", submitted }

/// Preparation fixes the bytes and digest exactly once. Start is the sole
/// publication path and never rebuilds a failed or imported operation.
public final class ServiceOperation<Response: Sendable>: @unchecked Sendable {
  private let gate: NSRecursiveLock
  private var client: ServiceClient?
  private let token: UUID
  private let method: MethodDefinition
  private let snapshot: ServiceContractSnapshot
  private let options: ServiceCallOptions
  private var payload: Data?
  private let header: V4ApplicationHeader
  private let checkPrepared: @Sendable () throws -> Void
  private var storage: V4CryptoReservation?
  private let codecIdentity: MessageCodecIdentity
  private var completion: V4MessageCompletion<Response>?
  private var completionFactory: (@Sendable (ServiceClient, V4ServiceUnaryClaim?) throws -> V4MessageCompletion<Response>)?
  private var unaryClaims: [V4ServiceUnaryClaim] = []
  private var originalClients: [ServiceClient] = []
  private var controllerRoute: V4ControllerServiceDeclaration?
  private var reselections = 0
  private var routeRevision: UInt64 = 0
  private var response: V4RPCOperation?
  private var channel: V4RPCChannel?
  private var serial: UInt64?
  private var timer: Task<Void, Never>?
  private var starting = false
  private var loading = false
  private var responseBound = false
  private var closed = false
  private var terminal: (any Error)?
  #if os(macOS) || os(iOS)
  private var diagnostic: V4DiagnosticContext?
  #endif
  public let reference: OperationReference?
  init(client: ServiceClient, token: UUID, method: MethodDefinition, snapshot: ServiceContractSnapshot,
    payload: Data, codec: any MessageCodec<Response>, options: ServiceCallOptions, storage: V4CryptoReservation, resume: Bool = false,
    checkPrepared: @escaping @Sendable () throws -> Void = {}, prepaid: V4ServiceUnaryClaim? = nil,
    channel: V4RPCChannel? = nil) throws {
    self.client = client; self.token = token; self.method = method; self.snapshot = snapshot
    #if os(macOS) || os(iOS)
    diagnostic = client.environment.diagnosticContext(.application)
    #endif
    self.checkPrepared = checkPrepared
    self.payload = payload; self.codecIdentity = MessageCodecIdentity(codec.definition); self.options = options; self.storage = storage
    gate = client.environment.gate; self.channel = prepaid?.channel ?? channel ?? client.channel
    guard self.channel!.sessionEngine === client.channel.sessionEngine,
      channel == nil || self.channel === channel else { throw ServiceFailure.serviceUnavailable }
    let prepared = try V4PreparedServiceRequest(client: client, method: method, snapshot: snapshot, payload: payload, options: options, resume: resume)
    reference = prepared.reference; header = prepared.header
    let responseLimit = Int(try header.uint(8))
    let factory: @Sendable (ServiceClient, V4ServiceUnaryClaim?) throws -> V4MessageCompletion<Response> = { selected, owner in
      try V4MessageCompletion(group: selected.group, bytes: responseLimit, codec: codec,
        definition: codec.definition, context: options.context, sourceCheck: { [weak selected] in
          guard let selected else { throw ServiceFailure.closed }; try selected.check()
        }, onInput: { _ in }, onInputExit: { _ in }, onRelease: {}, prepaid: owner,
        bindingTail: try selected.bindingTail())
    }
    completionFactory = factory; completion = try factory(client, prepaid)
    originalClients = [client]; if let prepaid { unaryClaims = [prepaid] }
    let tail: V4ServiceInputTail
    if let prepaid { tail = V4ServiceInputTail(owner: prepaid) }
    else { tail = V4ServiceInputTail(try storage.executionTail(), binding: try client.bindingTail()) }
    let maximumPrepared = ContinuousClock.now.advanced(by: .seconds(60))
    let trustedPreparedEnd = prepared.preparationEnd
    timer = Task { [weak self] in
      defer { withExtendedLifetime(tail) {} }
      while !Task.isCancelled {
        guard let self else { return }
        let stop = gate.withLock { () -> Bool in
          if closed || response?.headerSubmitted == true { timer = nil; return true }
          let interval = client.environment.clock.sample().interval
          if ContinuousClock.now >= maximumPrepared || interval == nil || interval!.upperMS >= trustedPreparedEnd {
            terminal = interval == nil ? ServiceFailure.serviceUnavailable : ServiceFailure.deadlineExceeded
            close(); timer = nil; return true
          }
          return false
        }
        if stop { return }
        do { try await ContinuousClock().sleep(for: .milliseconds(20)) } catch { return }
      }
    }
  }
  var preparationExpired: Bool { gate.withLock { closed || terminal != nil } }
  public var submission: OperationSubmission { gate.withLock { response?.headerSubmitted == true ? .submitted : .notSubmitted } }
  func attachControllerRoute(_ declaration: V4ControllerServiceDeclaration) throws {
    try gate.withLock {
      guard !closed, !starting, response == nil, declaration.environment === storage?.environment else { throw ServiceFailure.closed }
      controllerRoute = declaration
    }
  }
  /// Reuses the original bytes/header and only a target published for this
  /// declaration. The old preparation and forwarding routes remain retained.
  private func selectControllerRoute() throws -> V4RPCReselection? {
    guard let declaration = controllerRoute, let client = self.client else { return nil }
    if declaration.binding === client { try client.checkPreparation(); return nil }
    guard options.admissionMode == .queued else { throw ServiceFailure.serviceUnavailable }
    guard reselections < 2, response?.headerSubmitted != true, let payload = self.payload,
      let factory = completionFactory else { throw ServiceFailure.serviceUnavailable }
    try options.context?.checkCancellation()
    guard let interval = client.environment.clock.sample().interval, interval.upperMS < options.deadlineAtMS else {
      throw ServiceFailure.deadlineExceeded
    }
    if let reference, let offer = snapshot.offer {
      try offer.check(contract: snapshot.contract, cutoff: reference.admissionNotAfterMS, environment: client.environment)
    }
    let selected = try declaration.selected(method, captured: snapshot, payloadBytes: payload.count,
      responseBytes: Int(try header.uint(8)), cutoff: reference?.admissionNotAfterMS)
    let preparedCompletion = try factory(selected.0, selected.1)
    completion?.close(); completion = preparedCompletion
    self.client = selected.0; channel = selected.1.channel
    self.storage = selected.1.target.storage
    originalClients.append(selected.0); unaryClaims.append(selected.1)
    reselections += 1; routeRevision += 1
    return V4RPCReselection(channel: selected.1.channel, owner: selected.1, install: { [self] selected, serial, operation in
      try gate.withLock {
        guard !closed else { throw ServiceFailure.closed }
        channel = selected; self.serial = serial; response = operation
      }
    })
  }
  public func start() async throws {
    #if os(macOS) || os(iOS)
    diagnostic?.emit(.started)
    #endif
    do { try await startOriginal() }
    catch {
      #if os(macOS) || os(iOS)
      if let failure = gate.withLock({ terminal }) { diagnostic?.failed(failure) }
      #endif
      throw error
    }
  }
  private func startOriginal() async throws {
    try Task.checkCancellation()
    let captured = try gate.withLock { () -> (ServiceClient, V4RPCChannel, UInt64) in
      guard !closed, !starting, response == nil else { throw terminal ?? ServiceFailure.closed }
      _ = try selectControllerRoute()
      guard let client = self.client, let channel = self.channel else { throw ServiceFailure.closed }
      try client.checkAdmission(); try checkPrepared(); try options.context?.checkCancellation(); starting = true
      return (client, channel, routeRevision)
    }
    do {
      guard let payload = gate.withLock({ self.payload }) else { throw ServiceFailure.closed }
      let owner = gate.withLock { unaryClaims.last }
      let deferredGuard = gate.withLock { controllerRoute != nil && options.admissionMode == .queued }
      let (number, pending) = try await captured.1.enqueue(header: header, payload: payload,
        responseCapacity: Int(try header.uint(8)), expectsResponse: true, unaryClaim: owner,
        bindingTail: try captured.0.bindingTail(),
        deferHeaderGuard: deferredGuard, guardHeader: { [self] in
          try gate.withLock {
            guard !closed, let client = self.client else { throw terminal ?? ServiceFailure.closed }
            if let selection = try selectControllerRoute() { throw selection }
            try client.checkAdmission(); try checkPrepared(); try options.context?.checkCancellation()
            guard let interval = client.environment.clock.sample().interval, interval.upperMS < options.deadlineAtMS else {
              throw ServiceFailure.deadlineExceeded
            }
            if let reference, let offer = snapshot.offer {
              try offer.check(contract: snapshot.contract, cutoff: reference.admissionNotAfterMS, environment: client.environment)
            }
          }
        })
      #if os(macOS) || os(iOS)
      let diagnostic = self.diagnostic
      pending.observeFailure { diagnostic?.failed($0) }
      #endif
      let stopped = gate.withLock { () -> Bool in
        starting = false
        if routeRevision == captured.2 { serial = number; response = pending }
        return closed
      }
      if stopped { try await captured.1.abandon(number); throw ServiceFailure.closed }
    } catch {
      gate.withLock { starting = false; if response == nil { terminal = error } }
      throw error
    }
  }
  private func loadResponse() async throws {
    let pending = try gate.withLock { () -> V4RPCOperation? in
      guard !closed else { throw terminal ?? ServiceFailure.closed }
      if let terminal { throw terminal }
      if responseBound { return nil }
      guard !loading, let response else { throw ServiceFailure.resourceExhausted }
      loading = true; return response
    }
    guard let pending else { return }
    defer { gate.withLock { loading = false } }
    let result = try await pending.take()
    do { try gate.withLock {
      guard !closed, let completion, let storage, let client = self.client else { throw ServiceFailure.closed }
      try client.check()
      if result.header.kind.hasSuffix("_sdk_error") {
        let failure = try snapshot.contract.decodeServiceFailure(result.payload)
        terminal = failure; completion.close(); self.completion = nil
        throw failure
      }
      if result.header.kind.hasSuffix("_application_error") {
        let code = UInt32(try result.header.uint(10))
        guard let definition = method.options.errors.first(where: { $0.code == code }),
          result.payload.count <= definition.maxPayloadBytes else { throw ServiceFailure.protocolFailure }
        let failure = ServiceApplicationError(code: code, payload: result.payload, definition: MessageCodecIdentity(definition.message))
        terminal = failure; completion.close(); self.completion = nil
        throw failure
      }
      try completion.bind(encoded: result.payload, storage: storage)
      responseBound = true
    } } catch {
      // The authenticated result was consumed by this original operation.
      // A failed wait above has no such terminal authority.
      gate.withLock { terminal = error }
      #if os(macOS) || os(iOS)
      diagnostic?.failed(error)
      #endif
      throw error
    }
  }
  public func takeResult(context: ApplicationInvocationContext? = nil) async throws -> MessageReceived<Response> {
    do {
      try await loadResponse()
      let completion = try gate.withLock { () -> V4MessageCompletion<Response> in
        guard !closed, let completion = self.completion else { throw terminal ?? ServiceFailure.closed }
        return completion
      }
      let result = try await completion.take(context: context)
      #if os(macOS) || os(iOS)
      diagnostic?.emit(.succeeded)
      #endif
      return result
    } catch {
      #if os(macOS) || os(iOS)
      if error is MessageReceiveError, gate.withLock({ completion?.deliveryCommitted == true }) {
        diagnostic?.failed(error)
      }
      #endif
      throw error
    }
  }
  public func takeEncodedResult(context: ApplicationInvocationContext? = nil) async throws -> EncodedMessageReceived {
    try await loadResponse()
    let result = try gate.withLock {
      guard !closed, let completion else { throw terminal ?? ServiceFailure.closed }
      return EncodedMessageReceived(payload: try completion.takeEncoded(context: context), codec: codecIdentity)
    }
    #if os(macOS) || os(iOS)
    diagnostic?.emit(.succeeded)
    #endif
    return result
  }
  public func close() {
    #if os(macOS) || os(iOS)
    if let failure = gate.withLock({ terminal }) { diagnostic?.failed(failure) }
    diagnostic?.emit(.closed)
    #endif
    let original = gate.withLock { () -> (V4RPCChannel, UInt64)? in
      guard !closed else { return nil }
      closed = true; timer?.cancel(); timer = nil
      completion?.close(); completion = nil
      for original in originalClients { original.release(token) }; client = nil
      storage = nil; payload = nil; completionFactory = nil; controllerRoute = nil
      unaryClaims.removeAll(); originalClients.removeAll()
      guard let channel, let serial else { self.channel = nil; return nil }
      self.channel = nil; response?.abandon()
      return (channel, serial)
    }
    if let (channel, serial) = original { Task { try? await channel.abandon(serial) } }
  }
  deinit { close() }
}
