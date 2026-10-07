import Foundation

/// Proof of the actual notification source accepted for the candidate Session.
/// Closing the publisher invalidates every alias under the original root gate.
final class V4NotificationDependency: @unchecked Sendable {
  private let gate: NSRecursiveLock
  private let checkSource: @Sendable () throws -> Void
  private var active = true
  init(environment: V4EnvironmentFoundation, source: any V4RPCTransport) throws {
    gate = environment.gate
    #if os(macOS) || os(iOS)
    guard let native = source as? V4NativeByteStream else { throw ServiceFailure.serviceUnavailable }
    checkSource = { try native.checkServiceDependency() }
    #else
    throw ServiceFailure.serviceUnavailable
    #endif
  }
  func check() throws {
    try gate.withLock { guard active else { throw ServiceFailure.closed }; try checkSource() }
  }
  func close() { gate.withLock { active = false } }
}

public struct NotificationSendResult: Sendable {
  public let submission: OperationSubmission
  public let reference: OperationReference?
}

/// The native notification direction has one original publisher. A caller's
/// cancellation cannot abandon a partially published, unframed body.
actor V4NotificationPublisher {
  private struct Entry {
    let operation: V4RPCOperation
    let payload: Data
    let before: @Sendable () throws -> Void
    let storage: V4CryptoReservation
  }
  private var storage: V4CryptoReservation?
  private let environment: V4EnvironmentFoundation
  private let factory: @Sendable () async throws -> any V4RPCTransport
  private var source: (any V4RPCTransport)?
  private var retiredSource: (any V4RPCTransport)?
  private var sourceClosers = 0
  private var opening: (UUID, Task<any V4RPCTransport, any Error>)?
  private var dependency: V4NotificationDependency?
  private var queue: [Entry] = []
  private var worker: Task<Void, Never>?
  private var current: Entry?
  private var publications: [V4RPCOperation] = []
  private var closed = false
  init(environment: V4EnvironmentFoundation, storage: V4CryptoReservation,
    factory: @escaping @Sendable () async throws -> any V4RPCTransport) {
    self.environment = environment; self.storage = storage; self.factory = factory
    queue.reserveCapacity(16); publications.reserveCapacity(16)
  }
  private func originalSource() async throws -> any V4RPCTransport {
    guard !closed, let storage else { throw ServiceFailure.closed }
    try storage.check()
    if let source { return source }
    let task: Task<any V4RPCTransport, any Error>
    let token: UUID
    if let opening { token = opening.0; task = opening.1 }
    else {
      let tail = try storage.executionTail()
      let factory = self.factory; token = UUID()
      task = Task {
        defer { tail.release() }
        return try await factory()
      }
      opening = (token, task)
    }
    do {
      let original = try await task.value
      guard !closed else {
        retiredSource = original; sourceClosers += 1
        try? await original.close()
        sourceClosers -= 1
        if opening?.0 == token { opening = nil }
        collect()
        throw ServiceFailure.closed
      }
      if source == nil { source = original }
      if opening?.0 == token { opening = nil }
      return source!
    } catch { if opening?.0 == token { opening = nil }; throw error }
  }
  func prepareDependency() async throws -> V4NotificationDependency {
    let original = try await originalSource()
    guard await original.terminalError() == nil else { throw ServiceFailure.serviceUnavailable }
    guard !closed else { throw ServiceFailure.closed }
    if let dependency { try dependency.check(); return dependency }
    let proof = try V4NotificationDependency(environment: environment, source: original)
    try proof.check(); dependency = proof; return proof
  }
  var drainPending: Int { collect(); return publications.count }
  var physicalPending: Int {
    collect()
    return (worker == nil ? 0 : 1) + (opening == nil ? 0 : 1) + publications.count + (retiredSource == nil ? 0 : 1)
  }
  func publish(request: V4ApplicationHeader, payload: Data, tryNow: Bool,
    bindingTail: V4ServiceBindingTail? = nil, before: @escaping @Sendable () throws -> Void) async throws -> V4RPCOperation {
    guard !closed, let storage else { throw ServiceFailure.closed }
    try storage.check(); try before()
    collect()
    guard publications.count < 16,
      !tryNow || current == nil && queue.isEmpty else { throw ServiceFailure.resourceExhausted }
    // The original publisher reservation owns the finite publication queue,
    // encoder/body overlap and response publication tails. Dispatch borrows
    // that owner; it never allocates an unbounded operation resource.
    let operation = V4RPCOperation(request: request, responseCapacity: 0, expectsResponse: false, query: false, storage: storage, bindingTail: bindingTail)
    publications.append(operation)
    queue.append(Entry(operation: operation, payload: Data(payload), before: before, storage: storage))
    start()
    return operation
  }
  private func start() {
    guard !closed, worker == nil, !queue.isEmpty, let storage else { return }
    let tail: V4ResourceReference
    do { tail = try storage.executionTail() } catch { return }
    worker = Task { [self] in
      defer { tail.release(); worker = nil; collect() }
      do {
        let stream = try await originalSource()
        while !closed, !queue.isEmpty {
          let entry = queue.removeFirst(); current = entry
          defer { entry.operation.finishPublication(); current = nil; collect() }
          let encoded = entry.operation.request.encoded()
          let prefix = V4Crypto.integer(UInt64(encoded.count), width: 2) + encoded
          var offset = 0
          do {
            while offset < prefix.count {
              let publicationTail = V4ServiceInputTail(try storage.executionTail())
              try entry.operation.retainPublication()
              let count = try await stream.writeRPCPublicationChunk(Data(prefix.dropFirst(offset)), beforeAccept: {
                try entry.storage.check()
                if !entry.operation.headerSubmitted { try entry.operation.beforeHeader(); try entry.before() }
              }, accepted: { entry.operation.acceptHeaderBytes($0) }, completed: { [operation = entry.operation, publicationTail] _, _ in
                defer { withExtendedLifetime(publicationTail) {} }
                operation.finishPublication()
              })
              guard count > 0, count <= prefix.count - offset else { throw ServiceFailure.protocolFailure }
              offset += count
            }
            offset = 0
            while offset < entry.payload.count {
              let publicationTail = V4ServiceInputTail(try storage.executionTail())
              try entry.operation.retainPublication()
              let count = try await stream.writeRPCPublicationChunk(Data(entry.payload[offset..<min(entry.payload.count, offset + 16_384)]),
                beforeAccept: { try entry.storage.check() }, accepted: { _ in }, completed: { [operation = entry.operation, publicationTail] _, _ in
                  defer { withExtendedLifetime(publicationTail) {} }
                  operation.finishPublication()
                })
              guard count > 0, count <= entry.payload.count - offset else { throw ServiceFailure.protocolFailure }
              offset += count
            }
            entry.operation.complete(.success(V4RPCResponse(header: entry.operation.request, payload: Data())))
          } catch {
            entry.operation.complete(.failure(error as? ServiceFailure ?? .serviceUnavailable))
            if entry.operation.headerSubmitted { throw error }
          }
        }
      } catch { await close(error as? ServiceFailure ?? .protocolFailure) }
    }
  }
  func close(_ failure: ServiceFailure = .closed) async {
    guard !closed else { return }; closed = true
    worker?.cancel(); opening?.1.cancel(); dependency?.close(); dependency = nil
    current?.operation.complete(.failure(failure))
    for entry in queue { entry.operation.complete(.failure(failure)); entry.operation.finishPublication() }; queue.removeAll()
    let original = source; source = nil; retiredSource = original
    if original != nil { sourceClosers += 1 }
    storage?.seal()
    try? await original?.close()
    if original != nil { sourceClosers -= 1 }; collect()
  }
  private func collect() {
    publications.removeAll { !$0.publicationPending }
    guard closed else { return }
    if sourceClosers == 0 {
      #if os(macOS) || os(iOS)
      if let original = retiredSource as? V4NativeByteStream, !original.rpcCleanupComplete { return }
      #endif
      retiredSource = nil
    }
    if worker == nil, opening == nil, publications.isEmpty, retiredSource == nil { storage = nil }
  }
}

public final class ServiceNotificationOperation: @unchecked Sendable {
  private let gate: NSRecursiveLock
  private var client: ServiceClient?
  private let method: MethodDefinition
  private let token: UUID
  private let snapshot: ServiceContractSnapshot
  private let payload: Data
  private let options: ServiceCallOptions
  private let request: V4PreparedServiceRequest
  private var storage: V4CryptoReservation?
  private var response: V4RPCOperation?
  private var started = false
  private var closed = false
  private var timer: Task<Void, Never>?
  #if os(macOS) || os(iOS)
  private let diagnostic: V4DiagnosticContext?
  #endif
  public var reference: OperationReference? { request.reference }
  init(client: ServiceClient, token: UUID, method: MethodDefinition, snapshot: ServiceContractSnapshot, payload: Data,
    options: ServiceCallOptions, storage: V4CryptoReservation) throws {
    self.client = client; self.token = token; self.method = method; self.snapshot = snapshot; self.payload = payload; self.options = options
    self.storage = storage; gate = client.environment.gate
    #if os(macOS) || os(iOS)
    diagnostic = client.environment.diagnosticContext(.application)
    #endif
    request = try V4PreparedServiceRequest(client: client, method: method, snapshot: snapshot, payload: payload, options: options)
    let tail = try storage.executionTail()
    let limit = ContinuousClock.now.advanced(by: .seconds(60))
    timer = Task { [weak self] in
      defer { tail.release() }
      while !Task.isCancelled {
        guard let self else { return }
        let stop = gate.withLock { () -> Bool in
          if closed || response?.headerSubmitted == true { timer = nil; return true }
          guard let interval = client.environment.clock.sample().interval,
            interval.upperMS < request.preparationEnd, ContinuousClock.now < limit else { close(); return true }
          return false
        }
        if stop { return }
        do { try await ContinuousClock().sleep(for: .milliseconds(20)) } catch { return }
      }
    }
  }
  var preparationExpired: Bool { gate.withLock { closed } }
  public var submission: OperationSubmission { gate.withLock { response?.headerSubmitted == true ? .submitted : .notSubmitted } }
  public func start() async throws {
    #if os(macOS) || os(iOS)
    diagnostic?.emit(.started)
    #endif
    do { try await startOriginal() }
    catch {
      #if os(macOS) || os(iOS)
      diagnostic?.failed(error)
      #endif
      throw error
    }
  }
  private func startOriginal() async throws {
    let (client, publisher) = try gate.withLock { () -> (ServiceClient, V4NotificationPublisher) in
      guard !closed, !started, let client = self.client, let publisher = client.session.serviceNotifications else { throw ServiceFailure.closed }
      try client.check(); started = true
      return (client, publisher)
    }
    let owned = try await publisher.publish(request: request.header, payload: payload,
      tryNow: options.context != nil || options.admissionMode == .tryNow,
      bindingTail: try client.bindingTail(), before: { [self] in
        try gate.withLock {
          guard !closed else { throw ServiceFailure.closed }; try client.checkAdmission(); try options.context?.checkCancellation()
          guard let interval = client.environment.clock.sample().interval, interval.upperMS < options.deadlineAtMS else { throw ServiceFailure.deadlineExceeded }
          if let reference, let offer = snapshot.offer {
            try offer.check(contract: snapshot.contract, cutoff: reference.admissionNotAfterMS, environment: client.environment)
          }
        }
      })
    gate.withLock { response = owned; if closed { owned.abandon() } }
  }
  public func waitPublished() async throws -> NotificationSendResult {
    do {
      guard let original = gate.withLock({ response }) else { throw ServiceFailure.closed }
      _ = try await original.take()
      #if os(macOS) || os(iOS)
      diagnostic?.emit(.succeeded)
      #endif
      return NotificationSendResult(submission: .submitted, reference: reference)
    } catch {
      #if os(macOS) || os(iOS)
      diagnostic?.failed(error)
      #endif
      throw error
    }
  }
  public func close() {
    #if os(macOS) || os(iOS)
    diagnostic?.emit(.closed)
    #endif
    gate.withLock {
      guard !closed else { return }; closed = true
      timer?.cancel(); timer = nil; response?.abandon(); storage = nil; client?.release(token); client = nil
    }
  }
  deinit { close() }
}
