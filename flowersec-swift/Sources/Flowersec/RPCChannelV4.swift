import Foundation

protocol V4ServiceInboundDispatcher: AnyObject, Sendable {
  func checkHeader(_ header: V4ApplicationHeader) throws
  func reserveRequest(_ header: V4ApplicationHeader) throws -> V4ServiceServerPosition?
  func reserveNotification(_ header: V4ApplicationHeader, storage: V4CryptoReservation) throws -> V4ServiceServerPosition
  func receive(header: V4ApplicationHeader, payload: Data, serial: UInt64, position: V4ServiceServerPosition?, rejection: ServiceFailure?, channel: V4RPCChannel) async
  func receiveNotification(header: V4ApplicationHeader, payload: Data, position: V4ServiceServerPosition) async
  func close()
}


/// An original inbound admission follows input, callback work, and actual
/// publication. RPC/stream admissions use K; notification admissions use their
/// separate bounded receiver service. Borrowing never creates another slot.
final class V4ServiceServerPosition: @unchecked Sendable {
  let owner: UUID
  private let tail: V4ServiceInputTail
  private let release: @Sendable () -> Void
  init(owner: UUID, tail: V4ServiceInputTail, release: @escaping @Sendable () -> Void) {
    self.owner = owner; self.tail = tail; self.release = release
  }
  deinit { release(); withExtendedLifetime(tail) {} }
}


protocol V4RPCTransport: ByteStream {
  func writeRPCChunk(_ bytes: Data, beforeAccept: @escaping @Sendable () throws -> Void,
    accepted: @escaping @Sendable (Int) -> Void) async throws -> Int
  func writeRPCPublicationChunk(_ bytes: Data, beforeAccept: @escaping @Sendable () throws -> Void,
    accepted: @escaping @Sendable (Int) -> Void, completed: @escaping @Sendable (Int, Bool) -> Void) async throws -> Int
}

extension V4RPCTransport {
  // Acceptance alone cannot prove that the original provider handed off bytes.
  // Providers without completion support retain honest unknown observations.
  func writeRPCPublicationChunk(_ bytes: Data, beforeAccept: @escaping @Sendable () throws -> Void,
    accepted: @escaping @Sendable (Int) -> Void, completed: @escaping @Sendable (Int, Bool) -> Void) async throws -> Int {
    do {
      let count = try await writeRPCChunk(bytes, beforeAccept: beforeAccept, accepted: accepted)
      completed(count, false); return count
    } catch { completed(0, false); throw error }
  }
}

struct V4RPCResponsePublicationFailure: Error {
  let underlying: any Error
  let committed: Bool
  let cause: ResponsePublicationCause?
}

struct V4RPCReselection: Error, Sendable {
  let channel: V4RPCChannel
  let owner: V4ServiceUnaryClaim
  let install: @Sendable (V4RPCChannel, UInt64, V4RPCOperation) throws -> Void
}

struct V4RPCResponse: Sendable {
  let header: V4ApplicationHeader
  let payload: Data
}

/// This owner survives an interrupted waiter. A final authenticated response,
/// valid ABORT, or actual channel input exit settles the network responsibility.
/// Shared outbound K belongs to the original Session engine. Each carrier
/// borrows this same finite set; opening another carrier never multiplies K.
final class V4RPCSessionEngine: @unchecked Sendable {
  let gate: NSRecursiveLock
  let maximum: Int
  private var sequence: UInt64 = 0
  private var positions: Set<UInt64> = []
  private var inboundPositions: Set<UInt64> = []
  private var inboundQueries: Set<UInt64> = []
  private var dispatcher: (any V4ServiceInboundDispatcher)?
  let registry: V4ApplicationWireRegistry
  private var futureStorage: [V4CryptoReservation] = []
  private var futureOwners: [UUID?] = Array(repeating: nil, count: 8)
  private var closed = false
  init(environment: V4EnvironmentFoundation, maximum: Int, prepaidCarriers: [V4CryptoReservation]? = nil) throws {
    gate = environment.gate; self.maximum = maximum; registry = try V4ApplicationWireRegistry()
    // The original Session protects eight carrier owners before READY. Only
    // bootstrap is materialized; every other owner remains a future position.
    if let prepaidCarriers {
      guard prepaidCarriers.count == 8, prepaidCarriers.allSatisfy({ $0.environment === environment }) else {
        throw ServiceFailure.configurationCapacity
      }
      for storage in prepaidCarriers { try storage.check() }
      futureStorage = prepaidCarriers
    } else {
      for _ in 0..<8 { futureStorage.append(try environment.rpcServicesDynamicStorage(execution: false)) }
    }
  }
  func checkout(opener: Int, channelClass: V4RPCChannelClass?, bootstrapAlive: Bool) throws -> V4RPCFuturePosition {
    try gate.withLock {
      guard !closed else { throw ServiceFailure.closed }
      guard opener == 0 || opener == 1 else { throw ServiceFailure.configurationCapacity }
      let start = opener * 4, lower = channelClass == .bulk ? start + 2 : start
      let range = channelClass == nil ? start..<(start + 4) : lower..<(lower + 2)
      guard let index = range.first(where: { futureOwners[$0] == nil && !($0 == 0 && bootstrapAlive) }) else {
        throw ServiceFailure.resourceExhausted
      }
      try futureStorage[index].check(); let token = UUID(); futureOwners[index] = token
      return V4RPCFuturePosition(engine: self, index: index, token: token, storage: futureStorage[index])
    }
  }
  fileprivate func returnFuture(_ position: V4RPCFuturePosition) {
    gate.withLock { if futureOwners[position.index] == position.token { futureOwners[position.index] = nil } }
  }
  func acquire() throws -> V4RPCSessionPosition {
    try gate.withLock {
      guard !closed else { throw ServiceFailure.closed }
      guard positions.count < maximum, sequence < UInt64.max else { throw ServiceFailure.resourceExhausted }
      sequence += 1; positions.insert(sequence)
      return V4RPCSessionPosition(engine: self, number: sequence)
    }
  }
  func installDispatcher(_ value: any V4ServiceInboundDispatcher) {
    gate.withLock { if !closed { dispatcher = value } }
  }
  var inboundDispatcher: any V4ServiceInboundDispatcher {
    gate.withLock { dispatcher ?? V4UnavailableServiceDispatcher(registry: registry) }
  }
  func acquireInbound(query: Bool) throws -> V4RPCSessionPosition {
    try gate.withLock {
      guard !closed else { throw ServiceFailure.closed }
      guard sequence < UInt64.max, query ? inboundQueries.count < 2 : inboundPositions.count < maximum else {
        throw ServiceFailure.resourceExhausted
      }
      sequence += 1
      if query { inboundQueries.insert(sequence) } else { inboundPositions.insert(sequence) }
      return V4RPCSessionPosition(engine: self, number: sequence, inbound: true, query: query)
    }
  }
  fileprivate func release(_ number: UInt64, inbound: Bool, query: Bool) {
    gate.withLock {
      if inbound { if query { inboundQueries.remove(number) } else { inboundPositions.remove(number) } }
      else { positions.remove(number) }
    }
  }
  func close() {
    gate.withLock {
      guard !closed else { return }; closed = true; dispatcher = nil
      // Active positions and their task tails keep the same original storage.
      // Unused future positions need no surviving closed Session handle.
      for storage in futureStorage { storage.seal() }
      futureStorage.removeAll()
    }
  }
}
final class V4RPCFuturePosition: @unchecked Sendable {
  let engine: V4RPCSessionEngine
  let index: Int
  let token: UUID
  let storage: V4CryptoReservation
  private var returned = false
  init(engine: V4RPCSessionEngine, index: Int, token: UUID, storage: V4CryptoReservation) {
    self.engine = engine; self.index = index; self.token = token; self.storage = storage
  }
  func returnAfterPhysicalExit() { engine.gate.withLock { if !returned { returned = true; engine.returnFuture(self) } } }
  deinit { returnAfterPhysicalExit() }
}
final class V4RPCSessionPosition: @unchecked Sendable {
  let engine: V4RPCSessionEngine
  let number: UInt64
  let inbound: Bool
  let query: Bool
  init(engine: V4RPCSessionEngine, number: UInt64, inbound: Bool = false, query: Bool = false) {
    self.engine = engine; self.number = number; self.inbound = inbound; self.query = query
  }
  deinit { engine.release(number, inbound: inbound, query: query) }
}

private final class V4UnavailableServiceDispatcher: V4ServiceInboundDispatcher, @unchecked Sendable {
  let registry: V4ApplicationWireRegistry
  init(registry: V4ApplicationWireRegistry) { self.registry = registry }
  func checkHeader(_ header: V4ApplicationHeader) throws { throw ServiceFailure.serviceUnavailable }
  func reserveRequest(_ header: V4ApplicationHeader) throws -> V4ServiceServerPosition? { nil }
  func reserveNotification(_ header: V4ApplicationHeader, storage: V4CryptoReservation) throws -> V4ServiceServerPosition {
    throw ServiceFailure.serviceUnavailable
  }
  func receive(header: V4ApplicationHeader, payload: Data, serial: UInt64, position: V4ServiceServerPosition?,
    rejection: ServiceFailure?, channel: V4RPCChannel) async {
    let bytes = v4ServiceSDKPayload(rejection ?? .serviceUnavailable)
    guard let variant = registry.variants.first(where: { $0.value.request == header.kind && $0.value.sdkError }) else { return }
    var fields: [Int: V4ApplicationHeader.Scalar] = [:]
    for id in variant.value.fields where id != 0 {
      if id == 3 { fields[id] = .uint(UInt64(bytes.count)) }
      else if let constant = variant.value.constants[id] { fields[id] = .uint(constant) }
      else if let value = header.fields[id] { fields[id] = value }
      else { return }
    }
    guard let reply = try? V4ApplicationHeader(kind: variant.key, fields: fields, registry: registry) else { return }
    try? await channel.respond(to: serial, header: reply, payload: bytes, before: {})
  }
  func receiveNotification(header: V4ApplicationHeader, payload: Data, position: V4ServiceServerPosition) async {}
  func close() {}
}

final class V4RPCOperation: @unchecked Sendable {
  private let gate: NSRecursiveLock
  let request: V4ApplicationHeader
  let responseCapacity: Int
  let expectsResponse: Bool
  let query: Bool
  private var storage: V4CryptoReservation?
  private var result: Result<V4RPCResponse, ServiceFailure>?
  private var terminalFailure: ServiceFailure?
  private var failureObserver: (@Sendable (ServiceFailure) -> Void)?
  private var waiting: CheckedContinuation<V4RPCResponse, any Error>?
  private var waiterToken: UUID?
  private var abandoned = false
  private var abandonmentFailure = ServiceFailure.closed
  private var submitted = false
  private var finished = false
  private var consumed = false
  private var publicationFinished = false
  private var publicationsRemaining = 1
  private var queryOwner: V4ApplicationQueryOwner?
  private var queryPosition: V4ContractFetchPosition?
  private var unaryClaims: [V4ServiceUnaryClaim] = []
  private var bindingTails: [V4ServiceBindingTail] = []
  private var sessionPosition: V4RPCSessionPosition?
  private var physicalWaiter: CheckedContinuation<Void, any Error>?
  init(request: V4ApplicationHeader, responseCapacity: Int, expectsResponse: Bool, query: Bool,
    storage: V4CryptoReservation, queryOwner: V4ApplicationQueryOwner? = nil,
    queryPosition: V4ContractFetchPosition? = nil, unaryClaim: V4ServiceUnaryClaim? = nil,
    bindingTail: V4ServiceBindingTail? = nil, sessionPosition: V4RPCSessionPosition? = nil) {
    self.sessionPosition = sessionPosition
    gate = storage.environment.gate
    self.queryOwner = queryOwner; self.queryPosition = queryPosition
    self.request = request; self.responseCapacity = responseCapacity; self.expectsResponse = expectsResponse
    self.query = query; self.storage = storage
    if let unaryClaim { unaryClaims.append(unaryClaim) }
    if let bindingTail { bindingTails.append(bindingTail) }
  }
  func uses(_ claim: V4ServiceUnaryClaim) -> Bool { gate.withLock { unaryClaims.last === claim } }
  func retainRoute(_ claim: V4ServiceUnaryClaim) throws {
    try gate.withLock {
      guard !submitted, !finished, unaryClaims.count < 3 else { throw ServiceFailure.closed }
      unaryClaims.append(claim); storage = claim.target.rpcStorage
      publicationsRemaining += 1; publicationFinished = false
    }
  }
  var usesDedicatedPosition: Bool { gate.withLock { !unaryClaims.isEmpty } }
  var physicalUnaryTails: ([V4ServiceUnaryClaim], [V4ServiceBindingTail]) {
    gate.withLock { (unaryClaims, bindingTails) }
  }
  var physicalSessionPosition: V4RPCSessionPosition? { gate.withLock { sessionPosition } }
  var physicalQueryPosition: V4ContractFetchPosition? { gate.withLock { queryPosition } }
  var lateOnly: Bool { gate.withLock { abandoned } }
  var headerSubmitted: Bool { gate.withLock { submitted } }
  // Observes the original RPC outcome, never a canceled or rejected take waiter.
  func observeFailure(_ observer: @escaping @Sendable (ServiceFailure) -> Void) {
    gate.withLock {
      if finished && terminalFailure == nil { return }
      failureObserver = observer
      if let terminalFailure { observer(terminalFailure); failureObserver = nil }
    }
  }
  private func failed(_ failure: ServiceFailure) {
    guard terminalFailure == nil else { return }
    terminalFailure = failure
    let observer = failureObserver; failureObserver = nil; observer?(failure)
  }
  func beforeHeader() throws {
    try gate.withLock {
      guard (!abandoned || submitted), !finished else { throw ServiceFailure.closed }
      try storage?.check()
    }
  }
  func acceptHeaderBytes(_ count: Int) { if count > 0 { gate.withLock { submitted = true } } }
  func abandon(_ failure: ServiceFailure = .closed) {
    let waiter = gate.withLock { () -> CheckedContinuation<V4RPCResponse, any Error>? in
      guard !abandoned else { return nil }
      abandoned = true; abandonmentFailure = failure
      failed(failure)
      if finished { result = nil; storage = nil }
      defer { waiting = nil; waiterToken = nil }
      return waiting
    }
    waiter?.resume(throwing: failure)
  }
  func complete(_ result: Result<V4RPCResponse, ServiceFailure>) {
    let delivery = gate.withLock { () -> (CheckedContinuation<V4RPCResponse, any Error>, Result<V4RPCResponse, ServiceFailure>)? in
      guard !finished else { return nil }
      finished = true
      if case .failure(let failure) = result { failed(failure) }
      else { failureObserver = nil }
      if publicationFinished { finishPhysicalExit() }
      if abandoned { storage = nil; return nil }
      self.result = result
      guard let waiting else { return nil }
      self.waiting = nil; waiterToken = nil; self.result = nil; consumed = true; storage = nil
      return (waiting, result)
    }
    if let (waiter, outcome) = delivery { waiter.resume(with: outcome.mapError { $0 as any Error }) }
  }
  // Query admission survives an interrupted caller and an early peer response
  // until both original publication and original input responsibility exit.
  var publicationPending: Bool { gate.withLock { !publicationFinished } }
  func retainPublication() throws {
    try gate.withLock {
      guard !publicationFinished, publicationsRemaining < Int.max else { throw ServiceFailure.closed }
      publicationsRemaining += 1
    }
  }
  func finishPublication() {
    gate.withLock {
      guard publicationsRemaining > 0 else { return }
      publicationsRemaining -= 1; publicationFinished = publicationsRemaining == 0
      if finished && publicationFinished { finishPhysicalExit() }
    }
  }
  private func finishPhysicalExit() {
    queryOwner = nil; queryPosition = nil; unaryClaims.removeAll(); bindingTails.removeAll(); sessionPosition = nil
    let waiting = physicalWaiter; physicalWaiter = nil; waiting?.resume()
  }
  func waitPhysicalExit() async throws {
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
        let outcome: Result<Void, any Error>? = gate.withLock {
          if Task.isCancelled { return .failure(CancellationError()) }
          if finished && publicationFinished { return .success(()) }
          guard physicalWaiter == nil else { return .failure(ServiceFailure.resourceExhausted) }
          physicalWaiter = continuation; return nil
        }
        if let outcome { continuation.resume(with: outcome) }
      }
    } onCancel: {
      let waiting = self.gate.withLock { () -> CheckedContinuation<Void, any Error>? in
        defer { self.physicalWaiter = nil }; return self.physicalWaiter
      }
      waiting?.resume(throwing: CancellationError())
    }
  }
  func take() async throws -> V4RPCResponse {
    let token = UUID()
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        let immediate: Result<V4RPCResponse, any Error>? = gate.withLock {
          if Task.isCancelled { return .failure(CancellationError()) }
          if abandoned { return .failure(abandonmentFailure) }
          if consumed { return .failure(ServiceFailure.closed) }
          if waiting != nil { return .failure(ServiceFailure.resourceExhausted) }
          if let result {
            self.result = nil; consumed = true; storage = nil
            return result.mapError { $0 as any Error }
          }
          waiting = continuation; waiterToken = token
          return nil
        }
        if let immediate { continuation.resume(with: immediate) }
      }
    } onCancel: {
      let waiter = self.gate.withLock { () -> CheckedContinuation<V4RPCResponse, any Error>? in
        guard self.waiterToken == token else { return nil }
        defer { self.waiting = nil; self.waiterToken = nil }
        return self.waiting
      }
      waiter?.resume(throwing: CancellationError())
    }
  }
}

/// One reader cursor and one publisher serve the original ordered application
/// channel. The actor owns finite arrays; suspending a caller creates no worker.
private final class V4RPCHeaderCommit: @unchecked Sendable {
  private let gate = NSLock()
  private var entered = false
  var submitted: Bool { gate.withLock { entered } }
  func accept(_ count: Int) { if count > 0 { gate.withLock { entered = true } } }
}

actor V4RPCChannel {
  private struct Publication {
    let serial: UInt64
    let replyTo: UInt64
    let header: V4ApplicationHeader?
    let payload: Data
    let operation: V4RPCOperation?
    let guardHeader: @Sendable () throws -> Void
    let complete: CheckedContinuation<Void, any Error>?
    let storage: V4CryptoReservation
    let position: V4ServiceServerPosition?
    var observation: ResponsePublication? = nil
    var diagnosticLifetime: (any V4ApplicationDiagnosticLifetime)? = nil
    var fetchPosition: V4ContractFetchPosition? = nil
    var inboundAdmission: V4RPCSessionPosition? = nil
    let commit = V4RPCHeaderCommit()
  }
  private struct Incoming {
    let serial: UInt64
    let replyTo: UInt64
    let header: V4ApplicationHeader
    let operation: V4RPCOperation?
    let storage: V4CryptoReservation?
    let position: V4ServiceServerPosition?
    var rejection: ServiceFailure?
    let created = ContinuousClock.now
    var offset: Int = 0
    var body = Data()
    var fetchPosition: V4ContractFetchPosition? = nil
    var inboundAdmission: V4RPCSessionPosition? = nil
  }
  let environment: V4EnvironmentFoundation
  nonisolated let registry: V4ApplicationWireRegistry
  private let maximumGeneral: Int
  nonisolated let sessionEngine: V4RPCSessionEngine
  private var dedicatedEnginePositions: [UInt64: V4RPCSessionPosition] = [:]
  private var futurePosition: V4RPCFuturePosition?
  private var storage: V4CryptoReservation?
  private var stream: (any V4RPCTransport)?
  private var retiredTransport: (any V4RPCTransport)?
  private var ownsInboundDispatcher = true
  private var closedSessionPositions: [V4RPCSessionPosition] = []
  private var reader: Task<Void, Never>?
  private var closedQueryTails: [V4ContractFetchPosition] = []
  private var closedUnaryTails: [V4ServiceUnaryClaim] = []
  private var closedBindingTails: [V4ServiceBindingTail] = []
  private var writer: Task<Void, Never>?
  private var progressTimer: Task<Void, Never>?
  private var publications: [Publication] = []
  private var activePublication: Publication?
  private var pending: [UInt64: V4RPCOperation] = [:]
  private var incoming: [UInt64: Incoming] = [:]
  private var dedicated: Set<UInt64> = []
  private var dedicatedSequence: UInt64 = 0
  private var serial: UInt64 = 0
  private var peerSerial: UInt64 = 0
  private var closed = false
  private var starting = false
  private var failure: ServiceFailure?
  private var readPrefix = Data()
  private var readBody = Data()
  private var readLength: Int?
  private var assemblyStart: ContinuousClock.Instant?
  private var stoppedRequests: Set<UInt64> = []
  private var inboundDispatcher: (any V4ServiceInboundDispatcher)?
  private var inboundRequests: Set<UInt64> = []
  private var inboundQueries: Set<UInt64> = []
  private var inboundPositions: [UInt64: V4ServiceServerPosition] = [:]
  private var stoppedPeerRequests: Set<UInt64> = []
  private var inboundAdmissions: [UInt64: V4RPCSessionPosition] = [:]
  private struct ReadyWaiter {
    let continuation: CheckedContinuation<Void, any Error>
    let deadline: UInt64?
  }
  private var readyWaiters: [UUID: ReadyWaiter] = [:]
  init(environment: V4EnvironmentFoundation, maximumGeneral: Int, storage: V4CryptoReservation,
    sessionEngine: V4RPCSessionEngine? = nil, futurePosition: V4RPCFuturePosition? = nil,
    prepaidCarriers: [V4CryptoReservation]? = nil) throws {
    guard (1...1024).contains(maximumGeneral) else { throw ServiceFailure.configurationCapacity }
    self.environment = environment; self.maximumGeneral = maximumGeneral; self.storage = storage
    self.sessionEngine = try sessionEngine ?? V4RPCSessionEngine(environment: environment, maximum: maximumGeneral, prepaidCarriers: prepaidCarriers)
    self.futurePosition = futurePosition; registry = self.sessionEngine.registry
    publications.reserveCapacity(maximumGeneral + 2)
    pending.reserveCapacity(maximumGeneral + 2); incoming.reserveCapacity(maximumGeneral + 2)
    readPrefix.reserveCapacity(4); readBody.reserveCapacity(16_380)
  }
  var isAvailable: Bool { !closed && stream != nil && reader != nil }
  var acceptsOpeningWaiter: Bool { !closed }
  #if DEBUG
  var cryptoTestReadyWaiterCount: Int { readyWaiters.count }
  #endif
  func waitReady(deadlineAtMS: UInt64? = nil) async throws {
    let token = UUID()
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
        if Task.isCancelled { continuation.resume(throwing: CancellationError()); return }
        if closed { continuation.resume(throwing: failure ?? .closed); return }
        if let deadlineAtMS {
          guard let now = environment.clock.sample().interval, now.upperMS < deadlineAtMS else {
            continuation.resume(throwing: ServiceFailure.deadlineExceeded); return
          }
        }
        if isAvailable { continuation.resume(); return }
        guard readyWaiters.count < 4 else { continuation.resume(throwing: ServiceFailure.resourceExhausted); return }
        readyWaiters[token] = ReadyWaiter(continuation: continuation, deadline: deadlineAtMS)
      }
    } onCancel: { Task { await self.cancelReady(token) } }
  }
  private func cancelReady(_ token: UUID) {
    readyWaiters.removeValue(forKey: token)?.continuation.resume(throwing: CancellationError())
  }
  var finishedPhysically: Bool {
    guard closed && reader == nil && writer == nil && progressTimer == nil else { return false }
    #if os(macOS) || os(iOS)
    if let native = retiredTransport as? V4NativeByteStream {
      guard native.rpcCleanupComplete else { return false }
      futurePosition?.returnAfterPhysicalExit(); futurePosition = nil; retiredTransport = nil; return true
    }
    #endif
    retiredTransport = nil; futurePosition?.returnAfterPhysicalExit(); futurePosition = nil; return true
  }
  var dynamicDispatcher: any V4ServiceInboundDispatcher { sessionEngine.inboundDispatcher }
  func checkContractChannel() throws {
    guard !closed, stream != nil, reader != nil else { throw ServiceFailure.serviceUnavailable }
    try storage?.check()
  }
  func bindInbound(_ dispatcher: any V4ServiceInboundDispatcher, ownsDispatcher: Bool = true) throws {
    guard !starting, !closed, inboundDispatcher == nil else { throw ServiceFailure.closed }
    try storage?.check(); inboundDispatcher = dispatcher; ownsInboundDispatcher = ownsDispatcher
    sessionEngine.installDispatcher(dispatcher)
  }
  func respond(to requestSerial: UInt64, header: V4ApplicationHeader, payload: Data,
    publication: ResponsePublication? = nil, diagnosticLifetime: (any V4ApplicationDiagnosticLifetime)? = nil,
    before: @escaping @Sendable () throws -> Void) async throws {
    do {
      guard !closed, inboundRequests.contains(requestSerial), payload.count == (try header.payloadBytes), serial < .max,
        publications.count < maximumGeneral + 4 else { throw ServiceFailure.resourceExhausted }
      let responseStorage: V4CryptoReservation
      if registry.variants[header.kind]?.sdkError == true {
        guard payload.count <= 256, let original = storage else { throw ServiceFailure.closed }
        // Each original inbound slot already prepaid its bounded rejection.
        try original.check(); responseStorage = original
      } else { responseStorage = try environment.serviceOperationStorage(requestBytes: payload.count, responseBytes: 0) }
      serial += 1; let responseSerial = serial
      if let publication {
        let bytes = 23 + (try header.encoded()).count + payload.count + 17 * ((payload.count + 16_366) / 16_367)
        try publication.begin(bytes: bytes) { [weak self] in
          Task { await self?.publicationDeadline(responseSerial) }
        }
      }
      try await withCheckedThrowingContinuation { continuation in
        publications.append(Publication(serial: responseSerial, replyTo: requestSerial, header: header, payload: payload, operation: nil,
          guardHeader: before, complete: continuation, storage: responseStorage, position: inboundPositions[requestSerial], observation: publication, diagnosticLifetime: diagnosticLifetime, inboundAdmission: inboundAdmissions[requestSerial]))
        startWriter()
      }
    } catch {
      publication?.abandon(.publishFailed); throw error
    }
  }
  private func publicationDeadline(_ responseSerial: UInt64) async {
    if let index = publications.firstIndex(where: { $0.serial == responseSerial && $0.observation != nil }) {
      let queued = publications.remove(at: index)
      queued.observation?.finishProduction(); queued.complete?.resume(throwing: ServiceFailure.deadlineExceeded)
      return
    }
    guard activePublication?.serial == responseSerial else { return }
    // Native credit waits must wake too. Closing this original RPC owner gives
    // it a finite exit without claiming that a shared-channel Finish flushed it.
    await close(reason: .deadlineExceeded)
  }

  func finishInbound(_ requestSerial: UInt64) { inboundRequests.remove(requestSerial); inboundQueries.remove(requestSerial); inboundPositions.removeValue(forKey: requestSerial); inboundAdmissions.removeValue(forKey: requestSerial); stoppedPeerRequests.remove(requestSerial) }

  func start(_ factory: @escaping @Sendable () async throws -> any V4RPCTransport) throws {
    guard !closed, !starting else { throw ServiceFailure.closed }
    guard let storage else { throw ServiceFailure.closed }
    try storage.check()
    let tail = try storage.executionTail()
    do { try startProgressTimer(storage) }
    catch { tail.release(); throw error }
    starting = true
    reader = Task { [self] in
      defer { tail.release() }
      do {
        let source = try await factory()
        do { try install(source) } catch { retiredTransport = source; try? await source.close(); throw error }
        try await receive(source)
        await close(reason: .closed)
      } catch { await close(reason: error as? ServiceFailure ?? .protocolFailure) }
      reader = nil; closedQueryTails.removeAll(); closedUnaryTails.removeAll(); closedBindingTails.removeAll(); closedSessionPositions.removeAll()
      _ = finishedPhysically
    }
  }
  private func install(_ source: any V4RPCTransport) throws {
    guard !closed else { throw ServiceFailure.closed }
    guard let storage else { throw ServiceFailure.closed }
    try storage.check(); stream = source; startWriter()
    let waiting = readyWaiters; readyWaiters.removeAll()
    for waiter in waiting.values { waiter.continuation.resume() }
  }
  private func startProgressTimer(_ storage: V4CryptoReservation) throws {
    let openingDeadline = ContinuousClock.now.advanced(by: .seconds(30))
    let timerTail = try storage.executionTail()
    progressTimer = Task { [self] in
      defer { timerTail.release() }
      while !closed, !Task.isCancelled {
        if stream == nil && ContinuousClock.now >= openingDeadline {
          await close(reason: .deadlineExceeded); break
        }
        let sample = environment.clock.sample().interval
        let expired = readyWaiters.filter { _, waiter in
          guard let deadline = waiter.deadline else { return false }
          return sample == nil || sample!.upperMS >= deadline
        }
        for (token, waiter) in expired {
          readyWaiters.removeValue(forKey: token)
          waiter.continuation.resume(throwing: sample == nil ? ServiceFailure.serviceUnavailable : ServiceFailure.deadlineExceeded)
        }
        if let assemblyStart, ContinuousClock.now >= assemblyStart.advanced(by: .seconds(30)) {
          await close(reason: .deadlineExceeded); break
        }
        let now = environment.clock.sample().interval
        if let operation = activePublication?.operation, operation.query,
          now == nil || (try? operation.request.uint(5)).map({ $0 <= now!.upperMS }) == true {
          await close(reason: now == nil ? .serviceUnavailable : .deadlineExceeded); break
        }
        for (number, operation) in Array(pending) where !operation.lateOnly {
          if now == nil || (try? operation.request.uint(5)).map({ $0 <= now!.upperMS }) == true {
            try? abandon(number, reason: now == nil ? .serviceUnavailable : .deadlineExceeded)
          }
        }
        var inputExpired = false
        for number in Array(incoming.keys) {
          guard var input = incoming[number] else { continue }
          if ContinuousClock.now >= input.created.advanced(by: .seconds(30)) { inputExpired = true; break }
          if input.replyTo == 0,
            now == nil || (try? input.header.uint(5)).map({ $0 <= now!.upperMS }) == true {
            input.rejection = now == nil ? .serviceUnavailable : .deadlineExceeded
            input.body = Data(); incoming[number] = input
          } else if input.operation?.lateOnly == true, registry.variants[input.header.kind]?.sdkError != true {
            input.body = Data(); incoming[number] = input
          }
        }
        if inputExpired { await close(reason: .deadlineExceeded); break }
        do { try await ContinuousClock().sleep(for: .milliseconds(20)) } catch { break }
      }
      progressTimer = nil
      _ = finishedPhysically
    }
  }
  var drainPending: Int { pending.count + incoming.count + inboundRequests.count + dedicated.count + publications.count + (activePublication == nil ? 0 : 1) }
  var physicalPending: Int {
    if closed && finishedPhysically { return 0 }
    return (reader == nil ? 0 : 1) + (writer == nil ? 0 : 1) + (progressTimer == nil ? 0 : 1)
      + (closed && retiredTransport != nil ? 1 : 0)
  }
  func reserveDedicatedRequest(using original: V4RPCSessionPosition? = nil) throws -> UInt64 {
    guard !closed, let storage else { throw ServiceFailure.closed }
    try storage.check()
    let general = pending.values.reduce(0) { $0 + ($1.query || $1.usesDedicatedPosition ? 0 : 1) }
    guard general + dedicated.count < maximumGeneral, dedicatedSequence < UInt64.max else { throw ServiceFailure.resourceExhausted }
    if let original, original.engine !== sessionEngine { throw ServiceFailure.serviceUnavailable }
    let original = try original ?? sessionEngine.acquire()
    dedicatedSequence += 1; dedicated.insert(dedicatedSequence); dedicatedEnginePositions[dedicatedSequence] = original
    return dedicatedSequence
  }
  func dedicatedRequestOwner(_ position: UInt64) throws -> V4RPCSessionPosition {
    guard let owner = dedicatedEnginePositions[position] else { throw ServiceFailure.serviceUnavailable }
    return owner
  }
  func releaseDedicatedRequest(_ position: UInt64) { dedicated.remove(position); dedicatedEnginePositions.removeValue(forKey: position) }
  func enqueue(header: V4ApplicationHeader, payload: Data, responseCapacity: Int,
    expectsResponse: Bool, query: Bool = false, queryOwner: V4ApplicationQueryOwner? = nil,
    queryPosition: V4ContractFetchPosition? = nil, unaryClaim: V4ServiceUnaryClaim? = nil,
    bindingTail: V4ServiceBindingTail? = nil, deferHeaderGuard: Bool = false, guardHeader: @escaping @Sendable () throws -> Void) throws -> (UInt64, V4RPCOperation) {
    guard !closed else { throw failure ?? ServiceFailure.closed }
    guard let storage else { throw ServiceFailure.closed }
    try storage.check()
    guard payload.count == (try header.payloadBytes), responseCapacity >= 0, responseCapacity <= 1_048_576,
      publications.count < maximumGeneral + 2 else { throw ServiceFailure.resourceExhausted }
    let used = pending.values.reduce(0) { $0 + ($1.query == query && !$1.usesDedicatedPosition ? 1 : 0) }
    if let unaryClaim {
      guard !query, unaryClaim.channel === self, let position = unaryClaim.rpcPosition, dedicated.contains(position),
        !pending.values.contains(where: { $0.uses(unaryClaim) }) else { throw ServiceFailure.resourceExhausted }
    } else {
      guard used + (query ? 0 : dedicated.count) < (query ? 2 : maximumGeneral) else { throw ServiceFailure.resourceExhausted }
    }
    guard serial < UInt64.max else { throw ServiceFailure.resourceExhausted }
    let sessionPosition: V4RPCSessionPosition?
    if query || unaryClaim != nil { sessionPosition = nil } else { sessionPosition = try sessionEngine.acquire() }
    let requestStorage = try unaryClaim?.target.rpcStorage ?? queryPosition?.rpcStorage ??
      environment.serviceOperationStorage(requestBytes: payload.count, responseBytes: responseCapacity)
    if !deferHeaderGuard { try guardHeader() }
    serial += 1
    let operation = V4RPCOperation(request: header, responseCapacity: responseCapacity,
      expectsResponse: expectsResponse, query: query, storage: requestStorage, queryOwner: queryOwner, queryPosition: queryPosition, unaryClaim: unaryClaim, bindingTail: bindingTail, sessionPosition: sessionPosition)
    // Even one-way publication holds its original position through real exit.
    pending[serial] = operation
    publications.append(Publication(serial: serial, replyTo: 0, header: header, payload: Data(payload),
      operation: operation, guardHeader: guardHeader, complete: nil, storage: requestStorage, position: nil,
      fetchPosition: queryPosition))
    startWriter()
    return (serial, operation)
  }
  func abandon(_ request: UInt64, reason: ServiceFailure = .closed) throws {
    guard let operation = pending[request] else { return }
    operation.abandon(reason)
    if !operation.headerSubmitted,
      let index = publications.firstIndex(where: { $0.serial == request && $0.header != nil }) {
      publications.remove(at: index); pending.removeValue(forKey: request)
      operation.complete(.failure(reason)); operation.finishPublication(); return
    }
    guard operation.expectsResponse, !closed, !stoppedRequests.contains(request),
      publications.count < maximumGeneral + 2 else { return }
    stoppedRequests.insert(request)
    let controlStorage = try environment.serviceOperationStorage(requestBytes: 0, responseBytes: 0)
    publications.append(Publication(serial: request, replyTo: 0, header: nil, payload: Data(),
      operation: nil, guardHeader: {}, complete: nil, storage: controlStorage, position: nil))
    startWriter()
  }
  private func startWriter() {
    guard !closed, stream != nil, writer == nil, !publications.isEmpty else { return }
    let tail: V4ResourceReference
    do { guard let storage else { return }; tail = try storage.executionTail() } catch { return }
    writer = Task { [self] in
      defer { tail.release() }
      do {
        while !closed, !publications.isEmpty {
          let publication = publications.removeFirst()
          try await publish(publication)
        }
      } catch { await close(reason: error as? ServiceFailure ?? .protocolFailure) }
      writer = nil
      startWriter()
      _ = finishedPhysically
    }
  }
  private func publish(_ publication: Publication) async throws {
    activePublication = publication
    defer {
      activePublication = nil; publication.observation?.finishProduction()
      publication.operation?.finishPublication(); withExtendedLifetime(publication.position) {}
    }
    do {
      guard let stream, !closed else { throw ServiceFailure.closed }
      let before: @Sendable () throws -> Void = {
        try publication.storage.check(); try publication.observation?.checkPublicationProgress()
        try publication.operation?.beforeHeader()
        if !publication.commit.submitted { try publication.guardHeader() }
      }
      if let header = publication.header {
        if stoppedPeerRequests.contains(publication.replyTo) {
          publication.observation?.fail(.responseAborted); throw ServiceFailure.closed
        }
        let begin = try V4RPCFragment(kind: .begin, serial: publication.serial, replyTo: publication.replyTo, payload: header.encoded()).encoded()
        try await write(begin, source: stream, before: before,
          accepted: { publication.commit.accept($0); publication.operation?.acceptHeaderBytes($0) }, observation: publication.observation, diagnosticLifetime: publication.diagnosticLifetime)
        var offset = 0
        while offset < publication.payload.count {
          if publication.operation?.lateOnly == true || stoppedPeerRequests.contains(publication.replyTo) {
            publication.observation?.fail(.responseAborted)
            let abort = try V4RPCFragment(kind: .abort, serial: publication.serial, offset: UInt32(offset)).encoded()
            try await write(abort, source: stream, before: { try publication.storage.check() }, accepted: { _ in }, diagnosticLifetime: publication.diagnosticLifetime)
            publication.complete?.resume(throwing: ServiceFailure.closed); return
          }
          let count = min(16_367, publication.payload.count - offset)
          let fragment = try V4RPCFragment(kind: .data, serial: publication.serial, offset: UInt32(offset),
            payload: Data(publication.payload[offset..<offset + count])).encoded()
          try await write(fragment, source: stream, before: {
            try publication.storage.check(); try publication.observation?.checkPublicationProgress()
          }, accepted: { _ in }, observation: publication.observation, diagnosticLifetime: publication.diagnosticLifetime)
          offset += count
        }
        if publication.operation?.expectsResponse == false {
          pending.removeValue(forKey: publication.serial)
          publication.operation?.complete(.success(V4RPCResponse(header: header, payload: Data())))
        }
      } else {
        let fragment = try V4RPCFragment(kind: .stopOutput, serial: publication.serial).encoded()
        try await write(fragment, source: stream, before: { try publication.storage.check() }, accepted: { _ in }, diagnosticLifetime: publication.diagnosticLifetime)
      }
      publication.complete?.resume()
    } catch {
      publication.diagnosticLifetime?.failed(error)
      publication.observation?.fail(.publishFailed)
      publication.complete?.resume(throwing: V4RPCResponsePublicationFailure(underlying: error, committed: publication.commit.submitted,
        cause: publication.observation?.state().cause))
      if !publication.commit.submitted {
        pending.removeValue(forKey: publication.serial)
        if let selection = error as? V4RPCReselection, let operation = publication.operation {
          do {
            try await selection.channel.acceptReselected(operation: operation, header: operation.request,
              payload: publication.payload, guardHeader: publication.guardHeader, selection: selection)
          } catch { operation.complete(.failure(error as? ServiceFailure ?? .serviceUnavailable)) }
          return
        }
        publication.operation?.complete(.failure(error as? ServiceFailure ?? .closed)); return
      }
      throw error
    }
  }
  private func acceptReselected(operation: V4RPCOperation, header: V4ApplicationHeader, payload: Data,
    guardHeader: @escaping @Sendable () throws -> Void, selection: V4RPCReselection) throws {
    guard !closed, selection.channel === self, !operation.headerSubmitted,
      selection.owner.channel === self, let position = selection.owner.rpcPosition, dedicated.contains(position),
      publications.count < maximumGeneral + 2, serial < UInt64.max else { throw ServiceFailure.resourceExhausted }
    try selection.owner.target.rpcStorage.check()
    try operation.retainRoute(selection.owner)
    serial += 1
    do { try selection.install(self, serial, operation) }
    catch { operation.finishPublication(); throw error }
    pending[serial] = operation
    publications.append(Publication(serial: serial, replyTo: 0, header: header, payload: payload,
      operation: operation, guardHeader: guardHeader, complete: nil,
      storage: selection.owner.target.rpcStorage, position: nil))
    startWriter()
  }

  private func write(_ bytes: Data, source: any V4RPCTransport,
    before: @escaping @Sendable () throws -> Void, accepted: @escaping @Sendable (Int) -> Void,
    observation: ResponsePublication? = nil, diagnosticLifetime: (any V4ApplicationDiagnosticLifetime)? = nil) async throws {
    var offset = 0
    while offset < bytes.count {
      let ticket = try observation?.ticket()
      let count: Int
      do {
        let chunk = Data(bytes.dropFirst(offset))
        if let ticket {
          count = try await source.writeRPCPublicationChunk(chunk, beforeAccept: before, accepted: accepted) {
            [diagnosticLifetime] bytes, success in
            withExtendedLifetime(diagnosticLifetime) {}
            ticket.completed(bytes: bytes, success: success)
          }
        } else if let diagnosticLifetime {
          // The callback owns this original diagnostic through physical provider
          // completion. It supplies no business success/flush authority.
          count = try await source.writeRPCPublicationChunk(chunk, beforeAccept: before, accepted: accepted) {
            [diagnosticLifetime] _, success in
            if !success { diagnosticLifetime.failed(ServiceFailure.serviceUnavailable) }
            withExtendedLifetime(diagnosticLifetime) {}
          }
        } else { count = try await source.writeRPCChunk(chunk, beforeAccept: before, accepted: accepted) }
      } catch {
        // The transport completes pre-submit failures itself. A provider that
        // already owns the record remains responsible for its real callback.
        if let ticket { _ = await ticket.wait() }
        throw error
      }
      let success = if let ticket { await ticket.wait() } else { true }
      guard success else { throw ServiceFailure.serviceUnavailable }
      guard count > 0, count <= bytes.count - offset else { throw ServiceFailure.protocolFailure }
      try observation?.checkPublicationProgress(); offset += count
    }
  }
  private func receive(_ source: any V4RPCTransport) async throws {
    while !closed {
      // Reads request precisely the remaining cursor region. A complete native
      // read is retained before the next suspension or cancellation boundary.
      let remaining = readLength.map { $0 - readBody.count } ?? (4 - readPrefix.count)
      guard remaining > 0 else { throw ServiceFailure.protocolFailure }
      let bytes: Data?
      if let assemblyStart {
        guard ContinuousClock.now < assemblyStart.advanced(by: .seconds(30)) else { throw ServiceFailure.deadlineExceeded }
      }
      bytes = try await source.read(maxBytes: remaining)
      guard !closed else { return }
      guard let bytes else {
        guard readPrefix.isEmpty, readBody.isEmpty, incoming.isEmpty else { throw ServiceFailure.protocolFailure }
        return
      }
      guard !bytes.isEmpty, bytes.count <= remaining else { throw ServiceFailure.protocolFailure }
      if readLength == nil {
        if readPrefix.isEmpty { assemblyStart = ContinuousClock.now }
        readPrefix += bytes
        if readPrefix.count == 4 {
          let length = readPrefix.reduce(0) { $0 << 8 | Int($1) }
          guard (9...16_380).contains(length) else { throw ServiceFailure.protocolFailure }
          readLength = length
        }
      } else {
        readBody += bytes
        if readBody.count == readLength {
          let fragment = try V4RPCFragment(encoded: readPrefix + readBody)
          try accept(fragment)
          readPrefix.removeAll(keepingCapacity: true); readBody.removeAll(keepingCapacity: true)
          readLength = nil; assemblyStart = nil
        }
      }
    }
  }
  private func accept(_ fragment: V4RPCFragment) throws {
    switch fragment.kind {
    case .begin:
      guard fragment.serial > peerSerial, incoming.count < maximumGeneral + 2 else { throw ServiceFailure.protocolFailure }
      let header = try V4ApplicationHeader(encoded: fragment.payload, registry: registry)
      let operation: V4RPCOperation?
      let inputStorage: V4CryptoReservation?
      let position: V4ServiceServerPosition?
      let rejection: ServiceFailure?
      let inboundAdmission: V4RPCSessionPosition?
      if fragment.replyTo == 0 {
        inboundAdmission = try sessionEngine.acquireInbound(query: header.kind == "query_contracts_request")
        let dispatcher = inboundDispatcher ?? sessionEngine.inboundDispatcher
        guard inboundRequests.count < maximumGeneral + 2 else { throw ServiceFailure.protocolFailure }
        guard ["transient_unary_request", "execution_unary_request", "query_contracts_request", "read_result_request", "resume_request"].contains(header.kind) else { throw ServiceFailure.protocolFailure }
        position = try dispatcher.reserveRequest(header)
        if header.kind == "query_contracts_request" {
          guard inboundQueries.count < 2 else { throw ServiceFailure.resourceExhausted }; inboundQueries.insert(fragment.serial)
        } else {
          guard inboundRequests.count - inboundQueries.count < maximumGeneral else { throw ServiceFailure.resourceExhausted }
        }
        do {
          try dispatcher.checkHeader(header)
          inputStorage = try environment.serviceOperationStorage(requestBytes: header.payloadBytes, responseBytes: 0)
          rejection = nil
        } catch {
          inputStorage = nil
          if let failure = error as? ServiceFailure { rejection = failure }
          else if (error as? V4ResourceFailure) == .capacity { rejection = .resourceExhausted }
          else { rejection = .serviceUnavailable }
        }
        operation = nil; inboundRequests.insert(fragment.serial)
        if let position { inboundPositions[fragment.serial] = position }
        inboundAdmissions[fragment.serial] = inboundAdmission
      } else {
        inboundAdmission = nil
        guard !incoming.values.contains(where: { $0.replyTo == fragment.replyTo }),
          let pendingOperation = pending[fragment.replyTo], pendingOperation.headerSubmitted else { throw ServiceFailure.protocolFailure }
        try header.checkResponse(to: pendingOperation.request, registry: registry)
        guard try header.payloadBytes <= pendingOperation.responseCapacity || registry.variants[header.kind]?.sdkError == true else { throw ServiceFailure.protocolFailure }
        operation = pendingOperation; inputStorage = nil; position = nil; rejection = nil
      }
      peerSerial = fragment.serial
      var input = Incoming(serial: fragment.serial, replyTo: fragment.replyTo, header: header, operation: operation, storage: inputStorage, position: position, rejection: rejection,
        fetchPosition: operation?.physicalQueryPosition, inboundAdmission: inboundAdmission)
      let length = try header.payloadBytes
      if rejection == nil, operation?.lateOnly != true || registry.variants[header.kind]?.sdkError == true { input.body.reserveCapacity(length) }
      if length == 0 { try finish(input) } else { incoming[fragment.serial] = input }
    case .data:
      guard var input = incoming[fragment.serial], Int(fragment.offset) == input.offset,
        fragment.payload.count <= (try input.header.payloadBytes) - input.offset else { throw ServiceFailure.protocolFailure }
      if input.rejection == nil, input.operation?.lateOnly != true || registry.variants[input.header.kind]?.sdkError == true { input.body += fragment.payload }
      input.offset += fragment.payload.count
      if input.offset == (try input.header.payloadBytes) {
        incoming.removeValue(forKey: fragment.serial); try finish(input)
      } else { incoming[fragment.serial] = input }
    case .abort:
      guard let input = incoming[fragment.serial], Int(fragment.offset) == input.offset else { throw ServiceFailure.protocolFailure }
      incoming.removeValue(forKey: fragment.serial); pending.removeValue(forKey: input.replyTo); stoppedRequests.remove(input.replyTo)
      input.operation?.complete(.failure(.serviceUnavailable)); if input.replyTo == 0 { finishInbound(input.serial) }
    case .stopOutput:
      guard inboundRequests.contains(fragment.serial) else { throw ServiceFailure.protocolFailure }
      // Output cancellation does not cancel or reclassify original execution.
      stoppedPeerRequests.insert(fragment.serial)
      for original in publications where original.replyTo == fragment.serial { original.observation?.fail(.responseAborted) }
      if activePublication?.replyTo == fragment.serial { activePublication?.observation?.fail(.responseAborted) }
    }
  }
  private func finish(_ input: Incoming) throws {
    if input.replyTo == 0 {
      let dispatcher = inboundDispatcher ?? sessionEngine.inboundDispatcher
      guard let inputOwner = input.storage ?? storage else { throw ServiceFailure.closed }
      let tail = try inputOwner.executionTail()
      Task { [self, dispatcher, input, tail] in
        defer { tail.release(); withExtendedLifetime(input.position) {} }
        await dispatcher.receive(header: input.header, payload: input.body, serial: input.serial, position: input.position, rejection: input.rejection, channel: self)
        finishInbound(input.serial)
      }
      return
    }
    if registry.variants[input.header.kind]?.sdkError == true {
      _ = try V4NamespaceDocument(input.body, schema: "ApplicationSDKError", bytes: 256, nodes: 8, registry: V4NamespaceRegistry())
    }
    pending.removeValue(forKey: input.replyTo); stoppedRequests.remove(input.replyTo)
    input.operation?.complete(.success(V4RPCResponse(header: input.header, payload: input.body)))
  }
  func closeUnstarted(_ source: any V4RPCTransport) async {
    // OPEN_ACCEPT may already be on the wire when starting the local parser
    // fails. Keep that exact Stream until its physical retirement is proven.
    retiredTransport = source
    if closed { try? await source.close() }
    else { await close(reason: .serviceUnavailable) }
  }
  func close(reason: ServiceFailure = .closed) async {
    guard !closed else { return }
    closed = true; failure = reason
    let openingWaiters = readyWaiters; readyWaiters.removeAll()
    for waiter in openingWaiters.values { waiter.continuation.resume(throwing: reason) }
    let source = stream ?? retiredTransport; stream = nil; retiredTransport = source
    reader?.cancel(); writer?.cancel(); progressTimer?.cancel()
    if ownsInboundDispatcher { inboundDispatcher?.close() }; inboundDispatcher = nil; inboundRequests.removeAll(); inboundQueries.removeAll(); inboundPositions.removeAll(); stoppedPeerRequests.removeAll()
    if reader != nil {
      let original = Array(pending.values) + incoming.values.compactMap { $0.operation }
      closedQueryTails = original.compactMap { $0.physicalQueryPosition }
      closedSessionPositions = original.compactMap { $0.physicalSessionPosition } + Array(dedicatedEnginePositions.values) + Array(inboundAdmissions.values)
      for operation in original {
        let tails = operation.physicalUnaryTails
        closedUnaryTails.append(contentsOf: tails.0); closedBindingTails.append(contentsOf: tails.1)
      }
    }
    inboundAdmissions.removeAll()
    let old = pending; pending.removeAll(); incoming.removeAll(); dedicated.removeAll(); dedicatedEnginePositions.removeAll(); stoppedRequests.removeAll()
    let queued = publications; publications.removeAll()
    for operation in old.values { operation.complete(.failure(reason)) }
    activePublication?.observation?.fail(.ownerUnavailable)
    for publication in queued {
      publication.observation?.abandon(.ownerUnavailable)
      publication.operation?.finishPublication(); publication.complete?.resume(throwing: reason)
    }
    readPrefix.removeAll(); readBody.removeAll(); readLength = nil
    if futurePosition == nil { storage?.seal() }; storage = nil
    try? await source?.close()
    _ = finishedPhysically
  }
}
