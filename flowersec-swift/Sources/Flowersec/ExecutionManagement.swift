import Foundation

public struct ExecutionObservation: Sendable {
  public enum State: String, Sendable { case accepted, executing, completed, failed, unknown }
  public enum Reason: String, Sendable {
    case none, cancelled
    case dispatchUnavailable = "dispatch_unavailable", workOutcomeUnknown = "work_outcome_unknown"
    case deadlineExceeded = "deadline_exceeded", notRegistered = "not_registered", historyUnknown = "history_unknown"
  }
  public let found: Bool
  public let reason: Reason
  public let state: State?
  public let cancelRequested: Bool?
  public let dispatched: Bool?
  public let workActive: Bool?
  public let historyNotBeforeGCMS: UInt64?
  public let resultNotAfterMS: UInt64?
  public let resultAvailable: Bool?
  public let resultDeleted: Bool?
  public let resultBytes: UInt32?
  public let applicationErrorCode: UInt32?
  public let resultDigest: Data?
}
public struct ExecutionManagementResult: Sendable {
  public enum Status: String, Sendable {
    case ok, unavailable, unauthorized, unsupported
    case operationConflict = "operation_conflict", deadlineExceeded = "deadline_exceeded"
    case resultExpired = "result_expired", notFound = "not_found", historyUnknown = "history_unknown"
  }
  public enum CancelResult: String, Sendable {
    case requested, terminal, notRegistered = "not_registered", historyUnknown = "history_unknown"
  }
  public let status: Status
  public let observation: ExecutionObservation?
  public let cancelResult: CancelResult?
}

/// The session can tighten or seal control admission synchronously, including
/// while its channel actor is suspended in a provider operation.
private final class V4ExecutionManagementBounds: @unchecked Sendable {
  private let environment: V4EnvironmentFoundation
  private var drainDeadline: ContinuousClock.Instant?
  private var sealed = false
  private var publications = 0
  init(environment: V4EnvironmentFoundation) { self.environment = environment }
  func beginDrain(deadline: ContinuousClock.Instant) {
    environment.gate.withLock { drainDeadline = drainDeadline.map { min($0, deadline) } ?? deadline }
  }
  func seal() { environment.gate.withLock { sealed = true } }
  var physicalPending: Int { environment.gate.withLock { publications } }
  func beginPublication() { environment.gate.withLock { publications += 1 } }
  func endPublication() { environment.gate.withLock { publications -= 1 } }
  func check(deadlineAtMS: UInt64? = nil, opening: Bool = false) throws {
    try environment.gate.withLock {
      guard !sealed else { throw ServiceFailure.closed }
      if let drainDeadline {
        guard ContinuousClock.now < drainDeadline else { throw ServiceFailure.deadlineExceeded }
        guard !opening else { throw ServiceFailure.serviceUnavailable }
      }
      if let deadlineAtMS {
        guard let interval = environment.clock.sample().interval, interval.upperMS < deadlineAtMS else {
          throw ServiceFailure.deadlineExceeded
        }
      }
    }
  }
  func limit(_ deadlineAtMS: UInt64) throws -> UInt64 {
    try environment.gate.withLock {
      try check(deadlineAtMS: deadlineAtMS)
      guard let drainDeadline else { return deadlineAtMS }
      guard let interval = environment.clock.sample().interval else { throw ServiceFailure.serviceUnavailable }
      let remaining = max(.zero, ContinuousClock.now.duration(to: drainDeadline)).components
      let milliseconds = UInt64(remaining.seconds) * 1000 + UInt64(remaining.attoseconds) / 1_000_000_000_000_000
      let (end, overflow) = interval.lowerMS.addingReportingOverflow(milliseconds)
      guard !overflow else { throw ServiceFailure.deadlineExceeded }
      return min(deadlineAtMS, end)
    }
  }
}

typealias V4ExecutionManagementHandler = @Sendable
  (V4ApplicationHeader, Data, (any V4ApplicationDiagnosticLifetime)?) async throws -> Data

protocol V4ExecutionManagementOwner: AnyObject, Sendable {
  func startClient() async
  func installHandler(_ handler: @escaping V4ExecutionManagementHandler,
    checkSource: @escaping @Sendable () throws -> Void) async
  func call(reference: OperationReference, cancel: Bool, deadlineAtMS: UInt64,
    before: @escaping @Sendable () throws -> Void) async throws -> ExecutionManagementResult
  func beginDrain(deadline: ContinuousClock.Instant)
  func seal()
  func physicalPendingCount() async -> Int
  func acceptPeer(_ source: any V4RPCTransport) async
  func close(_ failure: ServiceFailure) async
}

/// M framing has one bounded cursor and exactly two response positions. These
/// SDK operations never enter an application executor or invoke a user codec.
actor V4ExecutionManagementChannel: V4ExecutionManagementOwner {
  private struct Call {
    let id: UInt64
    let request: V4ApplicationHeader
    var publishedRequest: V4ApplicationHeader? = nil
    let result: V4RPCOperation
    let payload: Data
    let before: @Sendable () throws -> Void
    let storage: V4CryptoReservation
    let queryOwner: V4ApplicationQueryOwner
  }
  private enum Outbound {
    case call(Call)
    case reply(Data, UInt64, V4CryptoReservation, V4ApplicationQueryOwner,
      (any V4ApplicationDiagnosticLifetime)?)
  }
  private let environment: V4EnvironmentFoundation
  private nonisolated let bounds: V4ExecutionManagementBounds
  private let registry: V4ApplicationWireRegistry
  private let namespace: V4NamespaceRegistry
  private var storage: V4CryptoReservation?
  private let factory: @Sendable () async throws -> any V4RPCTransport
  private let initiates: Bool
  private let sourceEvents: V4SessionEvents
  private var source: (any V4RPCTransport)?
  private var closingSource: (any V4RPCTransport)?
  private var closingSourceWait: Task<Void, Never>?
  private var pending: [UInt64: Call] = [:]
  private var timedOut: Set<UInt64> = []
  private var queue: [Outbound] = []
  private var inboundHandler: V4ExecutionManagementHandler?
  private var checkSource: @Sendable () throws -> Void = {}
  private var inputDiagnostic: (any V4ApplicationDiagnosticLifetime)?
  private var publishingDiagnostic: (any V4ApplicationDiagnosticLifetime)?
  private var reader: Task<Void, Never>?
  private var writer: Task<Void, Never>?
  private var timer: Task<Void, Never>?
  private var restartRequested = false
  private var initializationDeadline: ContinuousClock.Instant?
  private var waitingCalls = 0
  var physicalPending: Int {
    collectClosed()
    return (reader == nil ? 0 : 1) + (writer == nil ? 0 : 1) + (timer == nil ? 0 : 1) + (closingSource == nil ? 0 : 1) + waitingCalls + bounds.physicalPending
  }
  private var serial: UInt64 = 0
  private var callID: UInt64 = 0
  private var peerSerial: UInt64 = 0
  private var closed = false
  private var prefix = Data()
  private var headerBytes = Data()
  private var body = Data()
  private var headerLength: Int?
  private var header: V4ApplicationHeader?
  private var assembly: ContinuousClock.Instant?
  init(environment: V4EnvironmentFoundation, storage: V4CryptoReservation,
    initiates: Bool = true,
    factory: @escaping @Sendable () async throws -> any V4RPCTransport) throws {
    self.environment = environment; self.storage = storage; self.initiates = initiates; self.factory = factory
    bounds = V4ExecutionManagementBounds(environment: environment)
    sourceEvents = V4SessionEvents(maximum: 16)
    registry = try V4ApplicationWireRegistry(); namespace = try V4NamespaceRegistry()
    pending.reserveCapacity(2); queue.reserveCapacity(2)
    prefix.reserveCapacity(2); headerBytes.reserveCapacity(512); body.reserveCapacity(512)
  }
  nonisolated func beginDrain(deadline: ContinuousClock.Instant) { bounds.beginDrain(deadline: deadline) }
  nonisolated func seal() { bounds.seal() }
  func startClient() async { guard initiates else { return }; start() }
  func installHandler(_ handler: @escaping V4ExecutionManagementHandler,
    checkSource: @escaping @Sendable () throws -> Void = {}) async {
    inboundHandler = handler
    self.checkSource = checkSource
  }
  func physicalPendingCount() async -> Int { physicalPending }
  func acceptPeer(_ source: any V4RPCTransport) async {
    guard !closed, self.source == nil, closingSource == nil, reader == nil, writer == nil, timer == nil, storage != nil else {
      await Self.closeSourceAndWait(source).value; return
    }
    self.source = source
    sourceEvents.signal()
    startWriter(); startTimer()
    reader = Task { [self, source] in
      defer { reader = nil; collectClosed() }
      do { try await receiveAny(source); await retireSource(source, failure: .closed) }
      catch { await retireSource(source, failure: error as? ServiceFailure ?? .protocolFailure) }
    }
  }
  func call(reference: OperationReference, cancel: Bool, deadlineAtMS: UInt64,
    before: @escaping @Sendable () throws -> Void) async throws -> ExecutionManagementResult {
    guard !closed, let storage else { throw ServiceFailure.closed }
    guard closingSource == nil else { throw ServiceFailure.serviceUnavailable }
    try storage.check(); try before()
    // Reserve one of the two prepaid M control positions before waiting for a
    // peer source. Otherwise early server calls could wait without consuming
    // the bounded caller capacity and all arrive together after READY.
    let group = try environment.applicationGroup()
    let queryOwner: V4ApplicationQueryOwner
    do {
      queryOwner = try group.executor.reserveManagementOwner(group: group)
    } catch {
      throw (error as? ServiceFailure) ?? .resourceExhausted
    }
    if !initiates {
      waitingCalls += 1
      do {
        while !closed, source == nil {
          let version = sourceEvents.revision
          guard let interval = environment.clock.sample().interval,
            interval.upperMS < deadlineAtMS,
            deadlineAtMS - interval.lowerMS <= 30_000 else { throw ServiceFailure.deadlineExceeded }
          let remaining = max(1, min(30_000, deadlineAtMS - interval.lowerMS))
          try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { try await self.sourceEvents.wait(after: version) }
            group.addTask {
              try await ContinuousClock().sleep(for: .milliseconds(Int(remaining)))
              throw ServiceFailure.deadlineExceeded
            }
            defer { group.cancelAll() }
            try await group.next()
          }
        }
        guard !closed else { throw ServiceFailure.closed }
      } catch {
        waitingCalls -= 1
        throw error
      }
      waitingCalls -= 1
    }
    try bounds.check(deadlineAtMS: deadlineAtMS)
    guard pending.count + waitingCalls < 2, queue.count < 2, callID < UInt64.max,
      let interval = environment.clock.sample().interval, interval.upperMS < deadlineAtMS,
      deadlineAtMS - interval.lowerMS <= 30_000 else { throw ServiceFailure.resourceExhausted }
    let deadlineAtMS = try bounds.limit(deadlineAtMS)
    try bounds.check(deadlineAtMS: deadlineAtMS)
    let document = try JSONSerialization.jsonObject(with: Data(TransportV4Registry.applicationHeaderRegistryJSON.utf8)) as! [String: Any]
    let management = document["management"] as! [String: Any]
    let methods = management["methods"] as! [String: [String: Any]]
    let method = methods[cancel ? "cancel" : "query"]!
    guard let digestHex = method["contract_digest_hex"] as? String, let typeID = V4NamespaceRegistry.number(method["type"]) else {
      throw ServiceFailure.configurationCapacity
    }
    let digest = try V4ExecutionManagementChannel.hex(digestHex)
    let payload = reference.targetEncoded()
    let callStorage = try storage.borrowManagementPosition()
    callID += 1
    let request = try V4ApplicationHeader(kind: cancel ? "request_cancel_request" : "query_operation_request",
      fields: [2: .uint(typeID), 3: .uint(UInt64(payload.count)), 5: .uint(deadlineAtMS), 6: .bytes(digest), 9: .uint(1)], registry: registry)
    let response = V4RPCOperation(request: request, responseCapacity: 512, expectsResponse: true, query: true, storage: callStorage)
    let call = Call(id: callID, request: request, result: response, payload: payload, before: before, storage: callStorage, queryOwner: queryOwner)
    pending[call.id] = call; queue.append(.call(call))
    startTimer()
    if initiates { start() } else { startWriter() }
    do {
      let result = try await response.take()
      try bounds.check(deadlineAtMS: deadlineAtMS); try before()
      return try decode(result.payload, cancel: cancel)
    } catch {
      response.abandon()
      if let index = queue.firstIndex(where: {
        if case .call(let queued) = $0 { return queued.id == call.id }
        return false
      }) {
        queue.remove(at: index); pending.removeValue(forKey: call.id)
        response.complete(.failure(.closed)); response.finishPublication()
      } else if pending[call.id] != nil {
        // The original writer may still accept a chunk. Keep its association
        // until the complete response or the original source's physical exit.
        timedOut.insert(call.id)
      }
      throw error
    }
  }
  static func unavailableResponse(cancel: Bool) -> Data {
    let fields: [(UInt64, Data)] = [(0, V4NamespaceValue.head(0, 1))]
    if cancel { return V4Crypto.map(fields) }
    return V4Crypto.map(fields)
  }
  static func hex(_ value: String) throws -> Data {
    guard value.count == 64 else { throw ServiceFailure.configurationCapacity }
    var result = Data(); result.reserveCapacity(32)
    var index = value.startIndex
    while index < value.endIndex {
      let end = value.index(index, offsetBy: 2)
      guard let byte = UInt8(value[index..<end], radix: 16) else { throw ServiceFailure.configurationCapacity }
      result.append(byte); index = end
    }
    return result
  }
  private func start() {
    guard initiates, !closed, reader == nil, source == nil, closingSource == nil, let storage else { startWriter(); return }
    guard (try? bounds.check(opening: true)) != nil else { return }
    if initializationDeadline == nil {
      initializationDeadline = ContinuousClock.now.advanced(by: .seconds(30))
    }
    let tail: V4ResourceReference
    do { tail = try storage.executionTail() } catch { return }
    reader = Task { [self] in
      defer {
        tail.release(); reader = nil; collectClosed()
        maybeRestart()
      }
      var opened: (any V4RPCTransport)?
      do {
        try bounds.check(opening: true)
        let stream = try await openSourceWithinInitializationDeadline()
        opened = stream
        guard !closed, !Task.isCancelled else {
          // A factory may finish after close or task cancellation. Retain the
          // late stream through the same physical cleanup waiter as every
          // accepted source; defer clears to that shared retirement owner.
          beginSourceRetirement(stream)
          await closingSourceWait?.value
          closingSourceWait = nil
          closingSource = nil
          collectClosed()
          return
        }
        source = stream
        initializationDeadline = nil
        try bounds.check()
        startWriter(); startTimer()
        try await receiveAny(stream)
        await retireSource(stream, failure: .closed)
      } catch {
        if let opened { await retireSource(opened, failure: error as? ServiceFailure ?? .protocolFailure) }
        else if !closed {
          timer?.cancel()
          if let deadline = initializationDeadline, ContinuousClock.now < deadline {
            restartRequested = true
          } else {
            await close(.deadlineExceeded)
          }
        }
      }
    }
    startTimer()
  }
  private func openSourceWithinInitializationDeadline() async throws -> any V4RPCTransport {
    guard let deadline = initializationDeadline else { return try await factory() }
    guard ContinuousClock.now < deadline else { throw ServiceFailure.deadlineExceeded }
    return try await withThrowingTaskGroup(of: (any V4RPCTransport).self) { group in
      group.addTask {
        let stream = try await self.factory()
        guard !Task.isCancelled else {
          await Self.closeSourceAndWait(stream).value
          throw ServiceFailure.deadlineExceeded
        }
        return stream
      }
      group.addTask {
        try await ContinuousClock().sleep(until: deadline)
        throw ServiceFailure.deadlineExceeded
      }
      defer { group.cancelAll() }
      guard let result = try await group.next() else { throw ServiceFailure.deadlineExceeded }
      return result
    }
  }
  private func startTimer() {
    guard !closed, timer == nil, let storage else { return }
    let tail: V4ResourceReference
    do { tail = try storage.executionTail() } catch { return }
    timer = Task { [self] in
      defer { tail.release(); timer = nil; collectClosed(); maybeRestart() }
      while !closed, !Task.isCancelled {
        do { try bounds.check(); if source != nil { try checkSource() } }
        catch { await close(error as? ServiceFailure ?? .closed); break }
        if let assembly, ContinuousClock.now >= assembly.advanced(by: .seconds(30)) { await close(.deadlineExceeded); break }
        let now = environment.clock.sample().interval
        var expired: [Call] = []
        for (id, call) in pending where !timedOut.contains(id) {
          let deadline = (try? call.request.uint(5)) ?? 0
          guard now == nil || now!.upperMS >= deadline else { continue }
          expired.append(call)
        }
        for call in expired {
          if let index = queue.firstIndex(where: {
            if case .call(let queued) = $0 { return queued.id == call.id }
            return false
          }) {
            queue.remove(at: index); pending.removeValue(forKey: call.id)
            call.result.finishPublication()
          } else {
            timedOut.insert(call.id)
          }
          call.result.complete(.failure(.deadlineExceeded)); call.result.abandon(.deadlineExceeded)
        }
        do { try await ContinuousClock().sleep(for: .milliseconds(20)) } catch { break }
      }
    }
  }
  private func maybeRestart() {
    guard restartRequested, !closed, reader == nil, writer == nil, timer == nil, source == nil, closingSource == nil else { return }
    restartRequested = false
    start()
  }
  private nonisolated static func closeSourceAndWait(_ source: any V4RPCTransport) -> Task<Void, Never> {
    // Cleanup is an original source responsibility, even when the task that
    // noticed retirement was canceled by the session's close path.
    Task.detached {
      try? await source.close()
      #if os(macOS) || os(iOS)
      if let native = source as? V4NativeByteStream {
        while !native.rpcCleanupComplete {
          try? await ContinuousClock().sleep(for: .milliseconds(10))
        }
      }
      #endif
    }
  }
  private func beginSourceRetirement(_ source: any V4RPCTransport) {
    if closingSource == nil { closingSource = source }
    guard closingSourceWait == nil, let retained = closingSource else { return }
    closingSourceWait = Self.closeSourceAndWait(retained)
  }
  private func retireSource(_ source: any V4RPCTransport, failure: ServiceFailure) async {
    guard !closed else { return }
    // A rebuilt source gets one 30-second initialization episode beginning at
    // physical retirement. Cleanup, writer and timer shutdown consume this same
    // episode; a source is never reopened while the old one is still retained.
    initializationDeadline = ContinuousClock.now.advanced(by: .seconds(30))
    self.source = nil
    writer?.cancel(); timer?.cancel()
    for (id, call) in pending {
      call.result.complete(.failure(failure)); timedOut.insert(id)
    }
    failInbound(failure)
    beginSourceRetirement(source)
    await closingSourceWait?.value
    // A concurrent close owns final retirement and keeps the original owners
    // until this same waiter has completed.
    guard !closed else { return }
    pending.removeAll(); timedOut.removeAll()
    queue.removeAll()
    publishingDiagnostic = nil
    resetCursor()
    serial = 0; peerSerial = 0
    closingSourceWait = nil
    closingSource = nil
    sourceEvents.signal()
    let episodeAvailable = initializationDeadline.map { ContinuousClock.now < $0 } ?? false
    restartRequested = initiates && !closed && episodeAvailable
    collectClosed()
    if initiates && !closed && !episodeAvailable {
      await close(.deadlineExceeded)
    }
  }
  private func resetCursor() {
    prefix.removeAll(keepingCapacity: true); headerBytes.removeAll(keepingCapacity: true); body.removeAll(keepingCapacity: true)
    headerLength = nil; header = nil; assembly = nil; inputDiagnostic = nil
  }

  private func startWriter() {
    guard !closed, writer == nil, source != nil, !queue.isEmpty, let storage else { return }
    let tail: V4ResourceReference
    do { tail = try storage.executionTail() } catch { return }
    let originalSourceCheck = checkSource
    writer = Task { [self] in
      defer { tail.release(); writer = nil; collectClosed(); startWriter(); maybeRestart() }
      do {
        while !closed, let stream = source, !queue.isEmpty {
          let item = queue.removeFirst()
          switch item {
          case .call(let call):
            var allocatedSerial: UInt64?
            do {
              try bounds.check(deadlineAtMS: call.request.uint(5)); try call.storage.check(); try call.before()
              try call.result.beforeHeader()
              guard serial < UInt64.max else { throw ServiceFailure.resourceExhausted }
              var fields = call.request.fields
              fields[9] = .uint(serial + 1)
              let request = try V4ApplicationHeader(kind: call.request.kind, fields: fields, registry: registry)
              let encodedHeader = request.encoded()
              let envelope = V4Crypto.integer(UInt64(encodedHeader.count), width: 2) + encodedHeader + call.payload
              serial += 1; allocatedSerial = serial
              var published = call; published.publishedRequest = request
              pending[call.id] = published
              var offset = 0
              while offset < envelope.count {
                let publicationTail = V4ServiceInputTail(try storage.executionTail())
                try call.result.retainPublication()
                bounds.beginPublication()
                let count = try await stream.writeRPCPublicationChunk(Data(envelope.dropFirst(offset)), beforeAccept: {
                  // Every native accept rechecks the original request bounds.
                  // A timed-out waiter keeps its association, but cannot extend
                  // the authority or deadline of the wire publication.
                  try self.bounds.check(deadlineAtMS: request.uint(5)); try call.storage.check(); try call.before()
                  if !call.result.headerSubmitted { try call.result.beforeHeader() }
                }, accepted: { call.result.acceptHeaderBytes($0) }, completed: { [bounds, owner = call.queryOwner, publicationTail] _, _ in
                  defer { withExtendedLifetime(owner) {}; withExtendedLifetime(publicationTail) {} }
                  call.result.finishPublication(); bounds.endPublication()
                })
                guard count > 0, count <= envelope.count - offset else { throw ServiceFailure.protocolFailure }
                offset += count
              }
              call.result.finishPublication()
            } catch {
              call.result.finishPublication()
              if call.result.headerSubmitted { throw error }
              // The writer is the sole serial allocator. A refusal before any
              // accepted bytes can return this serial without making a gap.
              if let allocatedSerial, serial == allocatedSerial { serial -= 1 }
              pending.removeValue(forKey: call.id); timedOut.remove(call.id)
              call.result.complete(.failure(error as? ServiceFailure ?? .closed))
            }
          case .reply(let envelope, let deadlineAtMS, let replyStorage, let owner, let diagnostic):
            publishingDiagnostic = diagnostic
            do {
              var offset = 0
              while offset < envelope.count {
                let publicationTail = V4ServiceInputTail(try storage.executionTail())
                bounds.beginPublication()
                let count = try await stream.writeRPCPublicationChunk(Data(envelope.dropFirst(offset)), beforeAccept: {
                  try self.bounds.check(deadlineAtMS: deadlineAtMS); try replyStorage.check(); try originalSourceCheck()
                }, accepted: { _ in }, completed: { [bounds, owner, publicationTail, diagnostic] _, success in
                  defer {
                    withExtendedLifetime(owner) {}
                    withExtendedLifetime(publicationTail) {}
                    withExtendedLifetime(diagnostic) {}
                  }
                  if !success { diagnostic?.failed(ServiceFailure.serviceUnavailable) }
                  bounds.endPublication()
                })
                guard count > 0, count <= envelope.count - offset else { throw ServiceFailure.protocolFailure }
                offset += count
              }
              withExtendedLifetime(replyStorage) {}
              withExtendedLifetime(diagnostic) {}
              publishingDiagnostic = nil
            } catch {
              diagnostic?.failed(error)
              throw error
            }
          }
        }
      } catch { await close(error as? ServiceFailure ?? .protocolFailure) }
    }
  }
  private func managementBinding(cancel: Bool) throws -> (request: String, response: String, type: UInt32, digest: Data) {
    let document = try JSONSerialization.jsonObject(with: Data(TransportV4Registry.applicationHeaderRegistryJSON.utf8)) as! [String: Any]
    let methods = (document["management"] as! [String: Any])["methods"] as! [String: [String: Any]]
    let method = methods[cancel ? "cancel" : "query"]!
    guard let type = V4NamespaceRegistry.number(method["type"]),
      let digestHex = method["contract_digest_hex"] as? String else {
      throw ServiceFailure.configurationCapacity
    }
    return (method["request_kind"] as? String ?? (cancel ? "request_cancel_request" : "query_operation_request"),
      method["response_kind"] as? String ?? (cancel ? "request_cancel_response" : "query_operation_response"),
      UInt32(type), try Self.hex(digestHex))
  }
  private func validateManagementHeader(_ header: V4ApplicationHeader, cancel: Bool, response: Bool) throws {
    let binding = try managementBinding(cancel: cancel)
    guard header.kind == (response ? binding.response : binding.request),
      try header.typeID == binding.type, try header.bytes(6) == binding.digest else {
      throw ServiceFailure.protocolFailure
    }
  }
  private func validateRequest(_ request: V4ApplicationHeader) throws {
    let cancel = request.kind == "request_cancel_request"
    guard cancel || request.kind == "query_operation_request" else { throw ServiceFailure.protocolFailure }
    try validateManagementHeader(request, cancel: cancel, response: false)
    guard peerSerial < UInt64.max, try request.uint(9) == peerSerial + 1,
      try request.payloadBytes <= 1024 else { throw ServiceFailure.protocolFailure }
    let deadline = try request.uint(5)
    guard let interval = environment.clock.sample().interval, interval.upperMS < deadline,
      deadline - interval.lowerMS <= 30_000 else { throw ServiceFailure.deadlineExceeded }
    try bounds.check(deadlineAtMS: deadline)
  }
  private func receiveRequest(_ request: V4ApplicationHeader, payload: Data) async throws {
    guard !closed, let storage else { throw ServiceFailure.closed }
    try bounds.check(deadlineAtMS: request.uint(5)); try storage.check()
    // Decode the complete target before handler selection. This keeps the
    // unavailable response path subject to the same authenticated payload
    // boundary as the server store path.
    _ = try V4NamespaceDocument(payload, schema: "ExecutionManagementTarget", bytes: 1024, nodes: 32, registry: namespace).root
    guard let handler = inboundHandler else { throw ServiceFailure.serviceUnavailable }
    let group = try environment.applicationGroup()
    // Both original control admission and fixed output backing precede any
    // store lookup/cancel, so saturation cannot cause a store side effect.
    let owner = try group.executor.reserveManagementOwner(group: group)
    let replyStorage = try storage.borrowManagementPosition()
    let diagnostic = inputDiagnostic
    let responseBody = try await handler(request, payload, diagnostic)
    do {
      guard !closed else { throw ServiceFailure.closed }
      try bounds.check(deadlineAtMS: request.uint(5)); try replyStorage.check()
      guard responseBody.count <= 512 else { throw ServiceFailure.resourceExhausted }
      let response = try responseHeader(request, payload: responseBody)
      let encodedHeader = response.encoded()
      let envelope = V4Crypto.integer(UInt64(encodedHeader.count), width: 2) + encodedHeader + responseBody
      queue.append(.reply(envelope, try request.uint(5), replyStorage, owner, diagnostic))
      startWriter()
    } catch {
      diagnostic?.failed(error)
      throw error
    }
  }
  private func responseHeader(_ request: V4ApplicationHeader, payload: Data) throws -> V4ApplicationHeader {
    let expected = request.kind == "query_operation_request" ? "query_operation_response" : "request_cancel_response"
    guard let variant = registry.variants.first(where: { $0.key == expected }) else { throw ServiceFailure.protocolFailure }
    var fields: [Int: V4ApplicationHeader.Scalar] = [:]
    for id in variant.value.fields where id != 0 {
      if id == 3 { fields[id] = .uint(UInt64(payload.count)) }
      else if let constant = variant.value.constants[id] { fields[id] = .uint(constant) }
      else if let value = request.fields[id] { fields[id] = value }
      else { throw ServiceFailure.protocolFailure }
    }
    return try V4ApplicationHeader(kind: expected, fields: fields, registry: registry)
  }
  private func receiveAny(_ stream: any V4RPCTransport) async throws {
    while !closed {
      let remaining: Int
      if let header { remaining = (try header.payloadBytes) - body.count }
      else if let headerLength { remaining = headerLength - headerBytes.count }
      else { remaining = 2 - prefix.count }
      if remaining == 0 {
        guard let header else { throw ServiceFailure.protocolFailure }
        if header.kind == "query_operation_request" || header.kind == "request_cancel_request" {
          try await receiveRequest(header, payload: body)
        } else {
          let responseSerial = try header.uint(9)
          guard responseSerial > 0, responseSerial <= serial,
            try header.payloadBytes <= 512 else { throw ServiceFailure.protocolFailure }
          let cancel = header.kind == "request_cancel_response"
          // The response binding is checked before live/late classification.
          // This keeps duplicate responses from bypassing the fixed method,
          // type and contract digest carried by their original request.
          try validateManagementHeader(header, cancel: cancel, response: true)
          // Decode every response body before classification. A late or legal
          // duplicate still has to carry the exact bounded management result;
          // it cannot be used to bypass the CBOR/schema checks.
          _ = try decode(body, cancel: cancel)
          if let call = pending.values.first(where: { (try? $0.publishedRequest?.uint(9)) == responseSerial }) {
            guard let publishedRequest = call.publishedRequest, call.result.headerSubmitted else {
              throw ServiceFailure.protocolFailure
            }
            try header.checkResponse(to: publishedRequest, registry: registry)
            let wasTimedOut = timedOut.remove(call.id) != nil
            pending.removeValue(forKey: call.id)
            if !wasTimedOut {
              do {
                try bounds.check(deadlineAtMS: call.request.uint(5)); try call.before()
                call.result.complete(.success(V4RPCResponse(header: header, payload: body)))
              } catch { call.result.complete(.failure(error as? ServiceFailure ?? .closed)) }
            }
          }
          // No live association means this is a late/duplicate response. The
          // published high-water mark and the fixed result validation above
          // make it safe to consume without retaining per-serial tombstones.
        }
        resetCursor()
        continue
      }
      try bounds.check(); try storage?.check(); try checkSource()
      guard let bytes = try await stream.read(maxBytes: remaining) else {
        guard prefix.isEmpty, headerBytes.isEmpty, body.isEmpty else { throw ServiceFailure.protocolFailure }; return
      }
      guard !closed else { return }
      try bounds.check(); try storage?.check(); try checkSource()
      guard !bytes.isEmpty, bytes.count <= remaining else { throw ServiceFailure.protocolFailure }
      if prefix.isEmpty, headerLength == nil {
        #if os(macOS) || os(iOS)
        inputDiagnostic = environment.diagnosticContext(.application).map { V4ServiceServerDiagnostic($0) }
        #endif
      }
      if header != nil { body += bytes }
      else if let headerLength {
        headerBytes += bytes
        if headerBytes.count == headerLength {
          let value = try V4ApplicationHeader(encoded: headerBytes, registry: registry)
          switch value.kind {
          case "query_operation_request", "request_cancel_request":
            try validateRequest(value)
            peerSerial += 1
          case "query_operation_response", "request_cancel_response":
            let responseSerial = try value.uint(9)
            guard responseSerial > 0, responseSerial <= serial,
              try value.payloadBytes <= 512 else { throw ServiceFailure.protocolFailure }
          default: throw ServiceFailure.protocolFailure
          }
          header = value
        }
      } else {
        if prefix.isEmpty { assembly = ContinuousClock.now }
        prefix += bytes
        if prefix.count == 2 {
          let count = prefix.reduce(0) { $0 << 8 | Int($1) }
          guard (1...512).contains(count) else { throw ServiceFailure.protocolFailure }
          headerLength = count
        }
      }
    }
  }
  private func decode(_ payload: Data, cancel: Bool) throws -> ExecutionManagementResult {
    let schema = cancel ? "RequestCancelResponse" : "QueryOperationResponse"
    let value = try V4NamespaceDocument(payload, schema: schema, bytes: 512, nodes: 64, registry: namespace).root
    let statuses: [ExecutionManagementResult.Status] = [.ok, .unavailable, .unauthorized, .operationConflict, .unsupported, .deadlineExceeded, .resultExpired, .notFound, .historyUnknown]
    let statusCode = try Int(value.u("status"))
    guard statuses.indices.contains(statusCode) else { throw ServiceFailure.protocolFailure }
    var observation: ExecutionObservation?
    var cancellation: ExecutionManagementResult.CancelResult?
    if let encoded = try value.optional("observation") {
      let found = try encoded.field("found").equals(true)
      guard encoded.count == (found ? 13 : 2) else { throw ServiceFailure.protocolFailure }
      let reasons: [ExecutionObservation.Reason] = [.none, .cancelled, .dispatchUnavailable, .workOutcomeUnknown, .deadlineExceeded, .notRegistered, .historyUnknown]
      let reasonCode = try Int(encoded.u("reason"))
      guard reasons.indices.contains(reasonCode) else { throw ServiceFailure.protocolFailure }
      var state: ExecutionObservation.State?
      if found {
        let states: [ExecutionObservation.State] = [.accepted, .executing, .completed, .failed, .unknown]
        let code = try Int(encoded.u("state"))
        guard (1...5).contains(code) else { throw ServiceFailure.protocolFailure }; state = states[code - 1]
      }
      func flag(_ name: String) throws -> Bool? { try encoded.optional(name).map { try $0.equals(true) } }
      func number(_ name: String) throws -> UInt64? { try encoded.optional(name).map { try $0.uint() } }
      observation = try ExecutionObservation(found: found, reason: reasons[reasonCode], state: state,
        cancelRequested: flag("cancel_requested"), dispatched: flag("dispatched"), workActive: flag("work_active"),
        historyNotBeforeGCMS: number("history_not_before_gc_ms"), resultNotAfterMS: number("result_not_after_ms"),
        resultAvailable: flag("result_available"), resultDeleted: flag("result_deleted"),
        resultBytes: number("result_bytes").map { UInt32($0) }, applicationErrorCode: number("application_error_code").map { UInt32($0) },
        resultDigest: encoded.optional("result_digest").map { try $0.bytes() })
    }
    if let code = try value.optional("cancel_result")?.uint() {
      let results: [ExecutionManagementResult.CancelResult] = [.requested, .terminal, .notRegistered, .historyUnknown]
      guard code < UInt64(results.count) else { throw ServiceFailure.protocolFailure }; cancellation = results[Int(code)]
    }
    let status = statuses[statusCode]
    let observed = [.ok, .resultExpired, .notFound, .historyUnknown].contains(status)
    guard observed == (observation != nil), (observed && cancel) == (cancellation != nil),
      value.count == (observed ? cancel ? 3 : 2 : 1) else { throw ServiceFailure.protocolFailure }
    if status == .notFound, observation?.found != false || observation?.reason != .notRegistered { throw ServiceFailure.protocolFailure }
    if status == .historyUnknown, observation?.found != false || observation?.reason != .historyUnknown { throw ServiceFailure.protocolFailure }
    return ExecutionManagementResult(status: status, observation: observation, cancelResult: cancellation)
  }
  func close(_ failure: ServiceFailure = .closed) async {
    bounds.seal()
    if closed {
      await closingSourceWait?.value
      collectClosed()
      return
    }
    closed = true
    reader?.cancel(); writer?.cancel(); timer?.cancel()
    let original = source; source = nil
    if let original { beginSourceRetirement(original) }
    // Logical completion does not refund original control positions before
    // the source, native cleanup and publication callbacks physically exit.
    for (id, call) in pending {
      call.result.complete(.failure(failure)); timedOut.insert(id)
    }
    failInbound(failure)
    storage?.seal()
    sourceEvents.signal()
    await closingSourceWait?.value
    pending.removeAll(); timedOut.removeAll()
    queue.removeAll()
    publishingDiagnostic = nil
    resetCursor()
    closingSourceWait = nil
    closingSource = nil
    collectClosed()
  }
  private func failInbound(_ failure: ServiceFailure) {
    inputDiagnostic?.failed(failure)
    publishingDiagnostic?.failed(failure)
    for item in queue {
      if case .reply(_, _, _, _, let diagnostic) = item { diagnostic?.failed(failure) }
    }
  }
  private func collectClosed() {
    guard closed else { return }
    guard closingSourceWait == nil else { return }
    closingSource = nil
    if reader == nil, writer == nil, timer == nil, pending.isEmpty, queue.isEmpty,
      waitingCalls == 0, bounds.physicalPending == 0 {
      storage = nil
      inboundHandler = nil
      checkSource = {}
    }
  }
}
