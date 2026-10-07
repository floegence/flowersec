import Foundation

/// The immutable codec directions for one application message stream. The
/// opener role selects which direction is inbound for a particular endpoint.
public struct MessageStreamDefinition: Sendable, Equatable {
  public let kind: String
  public let revision: String
  public let openerToAcceptor: MessageDefinition
  public let acceptorToOpener: MessageDefinition
  public let digest: Data
  private let canonical: Data

  public init(
    kind: String, revision: String,
    openerToAcceptor: MessageDefinition, acceptorToOpener: MessageDefinition
  ) throws {
    guard V4ApplicationStreamKind.valid(kind),
      V4NamespaceRegistry.securityID(revision.utf8)
    else { throw ServiceFailure.configurationCapacity }
    func direction(_ codec: MessageDefinition) -> Data {
      V4Crypto.map([
        (0, V4Crypto.bytes(codec.schemaDigest)),
        (1, V4Crypto.text(codec.revision)),
        (2, V4NamespaceValue.head(0, UInt64(codec.maxMessageBytes))),
      ])
    }
    let encoded = V4Crypto.map([
      (0, V4Crypto.text(kind)),
      (1, V4Crypto.text(revision)),
      (2, direction(openerToAcceptor)),
      (3, direction(acceptorToOpener)),
    ])
    let document = try V4NamespaceDocument(
      encoded, schema: "MessageStreamDefinition", bytes: 8192, nodes: 64,
      registry: V4NamespaceRegistry())
    self.kind = kind
    self.revision = revision
    self.openerToAcceptor = openerToAcceptor
    self.acceptorToOpener = acceptorToOpener
    canonical = encoded
    digest = try document.root.digest("typed_message_definition_digest")
  }

  public func copyCanonical(into destination: inout Data) throws -> Int {
    guard destination.count >= canonical.count else { throw ServiceFailure.resourceExhausted }
    destination.replaceSubrange(0..<canonical.count, with: canonical)
    return canonical.count
  }

  public var maximumMessageBytes: Int {
    max(openerToAcceptor.maxMessageBytes, acceptorToOpener.maxMessageBytes)
  }
}

public struct MessageStreamOptions: Sendable, Equatable {
  public let assemblyTimeout: Duration
  public let sendTimeout: Duration
  public let cleanupTimeout: Duration

  public init(
    assemblyTimeout: Duration = .seconds(30),
    sendTimeout: Duration = .seconds(30), cleanupTimeout: Duration = .seconds(5)
  ) throws {
    guard assemblyTimeout > .zero, assemblyTimeout <= .seconds(90),
      sendTimeout > .zero, sendTimeout <= .seconds(90),
      cleanupTimeout > .zero, cleanupTimeout <= .seconds(30)
    else { throw ServiceFailure.configurationCapacity }
    self.assemblyTimeout = assemblyTimeout
    self.sendTimeout = sendTimeout
    self.cleanupTimeout = cleanupTimeout
  }

  static let standard = try! MessageStreamOptions()
}

// Only an authenticated native Session can supply the stream and its original
// resource owner. A public adapter cannot turn an arbitrary ByteStream into an
// authenticated, prepaid application stream.
protocol V4MessageStreamWriter: ByteStream {
  func writeMessageChunk(
    _ bytes: Data, beforeAccept: @escaping @Sendable () throws -> Void,
    accepted: @escaping @Sendable (Int) -> Void
  ) async throws -> Int
}

struct V4PreparedMessageStream: Sendable {
  let stream: any ByteStream
  let storage: V4CryptoReservation
  let prepaidPayload: V4CryptoReservation?
  let prepaidCompletion: V4CompletionReservation?
  let check: @Sendable () throws -> Void
  init(stream: any ByteStream, storage: V4CryptoReservation,
    prepaidPayload: V4CryptoReservation? = nil, prepaidCompletion: V4CompletionReservation? = nil,
    check: @escaping @Sendable () throws -> Void) {
    self.stream = stream; self.storage = storage; self.prepaidPayload = prepaidPayload
    self.prepaidCompletion = prepaidCompletion; self.check = check
  }
}

final class V4PreparedMessageHandler: @unchecked Sendable {
  private typealias Handler = @Sendable (ApplicationInvocationContext) async throws -> Void
  private let gate: NSRecursiveLock
  private var operation: Handler?
  private var closing: (@Sendable () async -> Void)?
  private var check: (@Sendable () throws -> Void)?
  private var started = false
  private var closed = false

  init(
    gate: NSRecursiveLock, check: @escaping @Sendable () throws -> Void,
    invoke: @escaping @Sendable (ApplicationInvocationContext) async throws -> Void,
    close: @escaping @Sendable () async -> Void
  ) {
    self.gate = gate; self.check = check; operation = invoke; closing = close
  }

  func invoke(_ context: ApplicationInvocationContext) async throws {
    let original = try gate.withLock { () throws -> Handler in
      guard !started, !closed, let operation else { throw SessionError.closed }
      try context.checkCancellation()
      try check?()
      started = true
      self.operation = nil
      check = nil
      return operation
    }
    defer { gate.withLock { closing = nil } }
    do { try await original(context) }
    catch { await close(); throw error }
  }

  func close() async {
    let original = gate.withLock { () -> (@Sendable () async -> Void)? in
      guard !closed else { return nil }
      closed = true
      operation = nil
      check = nil
      defer { closing = nil }
      return closing
    }
    await original?()
  }
}

struct V4MessageStreamRegistration: Sendable {
  let definition: MessageStreamDefinition
  let authorize: @Sendable (StreamMetadata, ApplicationInvocationContext) async throws -> Void
  let options: MessageStreamOptions
  let lifetime: V4MessageRegistrationLifetime
  let maximumConcurrentStreams: Int
  let prepare: (@Sendable (V4PreparedMessageStream, StreamMetadata) throws -> V4PreparedMessageHandler)?

  init(
    definition: MessageStreamDefinition,
    authorize: @escaping @Sendable (StreamMetadata, ApplicationInvocationContext) async throws -> Void,
    options: MessageStreamOptions, lifetime: V4MessageRegistrationLifetime,
    maximumConcurrentStreams: Int = 128,
    prepare: (@Sendable (V4PreparedMessageStream, StreamMetadata) throws -> V4PreparedMessageHandler)? = nil
  ) {
    self.definition = definition; self.authorize = authorize; self.options = options
    self.lifetime = lifetime; self.maximumConcurrentStreams = maximumConcurrentStreams
    self.prepare = prepare
  }
}

protocol V4MessageStreamAcceptedOwner: ByteStream {
  func claimMessageStream(definition: MessageStreamDefinition) throws -> V4PreparedMessageStream
}
struct V4TypedStreamClaimInfo: Sendable {
  let opener: Bool
  let application: StreamMetadata
}
struct V4LowLevelMessageCandidate: Sendable {
  let prepared: V4PreparedMessageStream
  let claim: @Sendable () throws -> Void
}
protocol V4LowLevelTypedOwner: V4MessageStreamAcceptedOwner {
  func lowLevelTypedInfo(definition: MessageStreamDefinition) throws -> V4TypedStreamClaimInfo
  func prepareLowLevelTypedMessageStream(definition: MessageStreamDefinition) throws -> V4LowLevelMessageCandidate
}

protocol V4ApplicationSession: Session {
  func invokeStreamHandler(_ incoming: IncomingStream, handler: @escaping StreamHandler) async throws
}

struct V4StreamHandlerRegistry: Sendable {
  let rawKinds: Set<String>
  let metadataContracts: [String: RawStreamMetadataContract]
  let lifetime: V4MessageRegistrationLifetime
  let maximumConcurrentStreams: Int
}

struct V4OutgoingMessageCandidate: Sendable {
  let prepared: V4PreparedMessageStream
  let publish: @Sendable () async throws -> Void
}

protocol V4MessageStreamSession: Session {
  func installMessageStreamRegistrations(_ registrations: [String: V4MessageStreamRegistration]) throws
  func installStreamHandlerRegistry(
    _ registry: V4StreamHandlerRegistry, messages: [String: V4MessageStreamRegistration]
  ) throws
  func prepareOpenMessageStream(
    definition: MessageStreamDefinition, application: StreamMetadata
  ) throws -> V4OutgoingMessageCandidate
}


public extension ByteStream {
  /// Converts an already accepted, authenticated typed stream without creating
  /// a second OPEN or exposing a raw alias. Arbitrary ByteStream values cannot
  /// manufacture this capability.
  func asTypedMessages<InboundCodec: MessageCodec, OutboundCodec: MessageCodec>(
    definition: MessageStreamDefinition,
    inboundCodec: InboundCodec,
    outboundCodec: OutboundCodec,
    options: MessageStreamOptions? = nil
  ) throws -> TypedMessageStream<InboundCodec.Value, OutboundCodec.Value> {
    guard let owner = self as? any V4LowLevelTypedOwner else {
      throw TransportAvailabilityError.runtimeUnavailable
    }
    let info = try owner.lowLevelTypedInfo(definition: definition)
    let inbound = info.opener ? definition.acceptorToOpener : definition.openerToAcceptor
    let outbound = info.opener ? definition.openerToAcceptor : definition.acceptorToOpener
    guard inboundCodec.definition == inbound, outboundCodec.definition == outbound else {
      throw ServiceFailure.contractMismatch
    }
    let candidate = try owner.prepareLowLevelTypedMessageStream(definition: definition)
    let messages: TypedMessageStream<InboundCodec.Value, OutboundCodec.Value>
    do {
      messages = try TypedMessageStream(
        prepared: candidate.prepared, definition: definition, opener: info.opener,
        applicationMetadata: info.application, inboundCodec: inboundCodec, outboundCodec: outboundCodec,
        inboundDefinition: inboundCodec.definition, outboundDefinition: outboundCodec.definition,
        options: options ?? .standard)
    } catch { awaitClose(candidate.prepared.stream); throw error }
    do {
      try candidate.claim()
      return messages
    } catch {
      Task { try? await messages.close() }
      throw error
    }
  }
}

private func awaitClose(_ stream: any ByteStream) {
  Task { try? await stream.close() }
}
extension Session {
  public func openMessageStream<InboundCodec: MessageCodec, OutboundCodec: MessageCodec>(
    definition: MessageStreamDefinition,
    applicationMetadata: StreamMetadata = .empty,
    inboundCodec: InboundCodec,
    outboundCodec: OutboundCodec,
    options: MessageStreamOptions? = nil
  ) async throws -> TypedMessageStream<InboundCodec.Value, OutboundCodec.Value> {
    let inbound = inboundCodec.definition, outbound = outboundCodec.definition
    guard inbound == definition.acceptorToOpener, outbound == definition.openerToAcceptor else {
      throw ServiceFailure.contractMismatch
    }
    guard let native = self as? any V4MessageStreamSession else {
      throw TransportAvailabilityError.runtimeUnavailable
    }
    let candidate = try native.prepareOpenMessageStream(
      definition: definition, application: applicationMetadata)
    let messages: TypedMessageStream<InboundCodec.Value, OutboundCodec.Value>
    do {
      messages = try TypedMessageStream(
        prepared: candidate.prepared, definition: definition, opener: true,
        applicationMetadata: applicationMetadata, inboundCodec: inboundCodec, outboundCodec: outboundCodec,
        inboundDefinition: inbound, outboundDefinition: outbound, options: options ?? .standard)
    } catch {
      try? await candidate.prepared.stream.close()
      throw error
    }
    do {
      try Task.checkCancellation()
      try await candidate.publish()
      return messages
    } catch {
      try? await messages.close()
      throw error
    }
  }
}

final class TypedMessageStreamCore: @unchecked Sendable {
  private var stream: (any ByteStream)?
  let lock: NSRecursiveLock
  private var offset: UInt64 = 0
  private var workers = 0
  private var applicationWorkers = 0
  private struct ApplicationSlot { weak var invocation: V4ApplicationInvocation? }
  private var applicationSlots = Array(repeating: ApplicationSlot(), count: 10)
  private var closeStarted = false
  private var closeFinished = false
  private var storage: V4CryptoReservation?
  private var environment: V4EnvironmentFoundation?
  private var authorizationCheck: (@Sendable () throws -> Void)?
  private final class CleanupWaiter: @unchecked Sendable {
    var canceled = false
    var continuation: CheckedContinuation<CleanupStatus, Error>?
    var timer: Task<Void, Never>?
  }
  private var waiter: CleanupWaiter?
  private let options: MessageStreamOptions
  private weak var currentCursor: ReaderCursor?
  private var assemblyGeneration: UInt64 = 0
  private var assemblyTask: Task<Void, Never>?
  private var assemblyTimers = 0
  private var assemblyFailed = false
  private var closeObserver: (@Sendable () -> Void)?
  private var protocolExitObserver: (@Sendable () -> Void)?
  private var payloadWaitCancel: (@Sendable () -> Void)?
  private let prepaidPayload: V4CryptoReservation?
  private var prepaidCompletion: V4CompletionReservation?

  init(prepared: V4PreparedMessageStream, options: MessageStreamOptions) {
    self.options = options
    prepaidPayload = prepared.prepaidPayload
    prepaidCompletion = prepared.prepaidCompletion
    lock = prepared.storage.environment.gate
    stream = prepared.stream
    storage = prepared.storage
    environment = prepared.storage.environment
    authorizationCheck = prepared.check
  }

  func check() throws {
    try lock.withLock {
      if assemblyFailed { throw SessionError.timeout }
      guard let storage, !closeStarted else { throw SessionError.closed }
      try storage.check()
      guard let authorizationCheck else { throw SessionError.closed }
      try authorizationCheck()
    }
  }

  func reservePayload(bytes: Int, encoding: Bool) throws -> V4CryptoReservation {
    try lock.withLock {
      try check()
      guard let environment else { throw SessionError.closed }
      return try prepaidPayload ?? environment.messageStreamPayloadStorage(bytes: bytes, encoding: encoding)
    }
  }

  func reserveControlledInput(bytes: Int) throws -> V4CryptoReservation {
    try lock.withLock {
      try check()
      guard let environment else { throw SessionError.closed }
      return try environment.messageStreamControlledInputStorage(bytes: bytes)
    }
  }

  func reserveSegments(bytes: Int, blocks: Int) throws -> V4CryptoReservation {
    try lock.withLock {
      try check()
      guard let environment else { throw SessionError.closed }
      return try environment.messageStreamSegmentStorage(bytes: bytes, blocks: blocks)
    }
  }

  func acquireResources<Value: Sendable>(
    tryNow: Bool = false, attempt: @escaping @Sendable () throws -> Value
  ) async throws -> Value {
    if tryNow { return try lock.withLock { try check(); return try attempt() } }
    let work = try lock.withLock { () -> Task<Value, Error> in
      try check()
      guard payloadWaitCancel == nil, let environment else { throw SessionError.resourceExhausted }
      workers += 1
      let task = Task.detached { [self, environment] in
        defer { endWorker() }
        return try await environment.root.waitForResources(account: environment.account, attempt: attempt)
      }
      payloadWaitCancel = { task.cancel() }
      return task
    }
    do {
      let reservation = try await withTaskCancellationHandler {
        try await work.value
      } onCancel: { work.cancel() }
      lock.withLock { payloadWaitCancel = nil }
      try Task.checkCancellation()
      return reservation
    } catch {
      lock.withLock { payloadWaitCancel = nil }
      throw error
    }
  }

  func completionDependent(_ context: ApplicationInvocationContext?) throws -> Bool {
    try lock.withLock {
      try check()
      guard let environment else { throw SessionError.closed }
      return try environment.applicationGroup().executor.hasCompletionAncestor(context)
    }
  }

  func onClose(_ observer: @escaping @Sendable () -> Void) {
    lock.withLock { closeObserver = observer }
  }

  func onProtocolExit(_ observer: @escaping @Sendable () -> Void) {
    lock.withLock {
      if closeFinished && workers == 0 { observer() }
      else { protocolExitObserver = observer }
    }
  }

  func startEncoder(
    context: ApplicationInvocationContext? = nil,
    operation: @escaping @Sendable (ApplicationInvocationContext) async -> Void,
    onExit: @escaping @Sendable () -> Void
  ) throws -> V4ApplicationWork {
    try lock.withLock {
      try check()
      guard let environment else { throw SessionError.closed }
      return try V4ApplicationWork(group: environment.applicationGroup(), context: context,
        operation: operation, onExit: onExit)
    }
  }

  func synchronousEncoderStage(
    context: ApplicationInvocationContext?
  ) throws -> V4SynchronousApplicationStage? {
    try lock.withLock {
      try check()
      guard let environment else { throw SessionError.closed }
      let group = try environment.applicationGroup()
      return try group.executor.synchronousStage(group: group, context: context)
    }
  }

  func applicationEntered(_ invocation: V4ApplicationInvocation) {
    lock.withLock {
      // Eight send entries and this direction's one decoder share the original
      // fixed adapter footprint. No arbitrary callback registration is exposed.
      guard let index = applicationSlots.firstIndex(where: { $0.invocation == nil }) else {
        preconditionFailure("message application owner exceeded its admitted entry bound")
      }
      applicationSlots[index].invocation = invocation
    }
  }

  func applicationExited(_ invocation: V4ApplicationInvocation) {
    lock.withLock {
      if let index = applicationSlots.firstIndex(where: { $0.invocation === invocation }) {
        applicationSlots[index].invocation = nil
      }
    }
  }

  func checkCleanupDependency(_ context: ApplicationInvocationContext?) throws {
    try lock.withLock {
      guard let context, !cleanupStatus().complete else { return }
      guard context.invocation.gate === lock else { throw ApplicationInvocationFailure.dependencyUnavailable }
      try context.checkCancellation()
      let parents = [context.invocation] + context.invocation.ancestors
      if applicationSlots.contains(where: { slot in
        guard let target = slot.invocation, target.active else { return false }
        return parents.contains { $0 === target }
      }) { throw ApplicationInvocationFailure.knownApplicationDependency }
    }
  }

  func beginApplicationWorker() throws {
    try lock.withLock { try check(); applicationWorkers += 1 }
  }

  func retainWorker() { lock.withLock { workers += 1 } }

  var startOffset: UInt64 { lock.withLock { offset } }

  func beginOperation() throws {
    try lock.withLock {
      try check()
      workers += 1
    }
  }

  func endWorker() {
    let ready = lock.withLock { () -> CheckedContinuation<CleanupStatus, Error>? in
      workers -= 1
      return releaseIfFinished()
    }
    ready?.resume(returning: CleanupStatus(complete: true))
  }

  private func releaseIfFinished() -> CheckedContinuation<CleanupStatus, Error>? {
    if closeFinished && workers + applicationWorkers == 1, let timer = waiter?.timer {
      timer.cancel()
      return nil
    }
    guard closeFinished else { return nil }
    // Application input has its own charged execution tail. Closing I/O can
    // release the Session and verification graph while that local computation
    // remains genuinely live and appears in cleanup status.
    if workers == 0 {
      let observer = protocolExitObserver
      protocolExitObserver = nil
      observer?()
      storage = nil
      stream = nil
      environment = nil
      authorizationCheck = nil
    }
    guard workers == 0, applicationWorkers == 0 else { return nil }
    let ready = waiter?.continuation
    waiter?.continuation = nil
    waiter = nil
    return ready
  }

  func makeCompletion<Value: Sendable>(
    bytes: Int, codec: any MessageCodec<Value>, definition: MessageDefinition, context: ApplicationInvocationContext?
  ) throws -> V4MessageCompletion<Value> {
    let group = try lock.withLock { () -> V4ApplicationGroup in
      try check()
      guard let environment else { throw SessionError.closed }
      let group = try environment.applicationGroup()
      applicationWorkers += 1
      return group
    }
    do {
      let reservation = prepaidCompletion
      self.prepaidCompletion = nil
      return try V4MessageCompletion(
        group: group, bytes: bytes, codec: codec, definition: definition, context: context,
        sourceCheck: { [weak self] in
          guard let self else { throw SessionError.closed }
          try self.check()
        }, onInput: { [weak self] invocation in self?.applicationEntered(invocation) },
        onInputExit: { [weak self] invocation in self?.applicationExited(invocation) },
        onRelease: { [self] in endApplicationWorker() }, prepaidCompletion: reservation)
    } catch { endApplicationWorker(); throw error }
  }

  func endApplicationWorker() {
    let ready = lock.withLock { () -> CheckedContinuation<CleanupStatus, Error>? in
      applicationWorkers -= 1
      return releaseIfFinished()
    }
    ready?.resume(returning: CleanupStatus(complete: true))
  }

  func attachCursor(_ cursor: ReaderCursor) {
    lock.withLock { currentCursor = cursor }
  }

  // The timer begins at the original first-byte transfer, even if its Receive
  // waiter was canceled. The current cursor and the timer retain one message.
  func noteInput(count: Int, prefix: Bool, complete: Bool) throws {
    try lock.withLock {
      try check()
      if prefix && count > 0 && assemblyTask == nil {
        guard assemblyTimers < 2, assemblyGeneration < .max else {
          throw SessionError.resourceExhausted
        }
        assemblyGeneration += 1
        let generation = assemblyGeneration
        let deadline = ContinuousClock.now.advanced(by: options.assemblyTimeout)
        assemblyTimers += 1
        workers += 1
        assemblyTask = Task.detached { [self] in
          defer {
            lock.withLock { assemblyTimers -= 1 }
            endWorker()
          }
          do {
            try await ContinuousClock().sleep(until: deadline)
            let cursor = lock.withLock { () -> ReaderCursor? in
              guard assemblyGeneration == generation, assemblyTask != nil, !closeStarted else { return nil }
              assemblyFailed = true
              return currentCursor
            }
            if lock.withLock({ assemblyFailed }) {
              cursor?.close()
              try? await closeStream()
            }
          } catch { }
        }
      }
      if complete { endAssembly() }
    }
  }

  func endAssembly() {
    lock.withLock {
      assemblyTask?.cancel()
      assemblyTask = nil
      currentCursor = nil
    }
  }

  func advance(by count: Int) throws {
    try lock.withLock {
      guard count >= 0 else { throw SessionError.resourceExhausted }
      let (next, overflow) = offset.addingReportingOverflow(UInt64(count))
      guard !overflow else { throw SessionError.resourceExhausted }
      offset = next
    }
  }

  func startClose() -> Bool {
    lock.withLock {
      guard !closeStarted else { return false }
      closeStarted = true
      let observer = closeObserver
      closeObserver = nil
      observer?()
      payloadWaitCancel?()
      assemblyTask?.cancel()
      assemblyTask = nil
      let cursor = currentCursor
      currentCursor = nil
      cursor?.close()
      return true
    }
  }

  func finishClose() {
    let ready = lock.withLock { () -> CheckedContinuation<CleanupStatus, Error>? in
      closeFinished = true
      return releaseIfFinished()
    }
    ready?.resume(returning: CleanupStatus(complete: true))
  }

  func cleanupStatus() -> CleanupStatus {
    lock.withLock {
      let complete = closeFinished && workers == 0 && applicationWorkers == 0
      return CleanupStatus(
        complete: complete, cleanupIncomplete: !complete,
        pendingCallbacks: UInt64(workers + applicationWorkers))
    }
  }

  func waitCleanup() async throws -> CleanupStatus {
    let token = CleanupWaiter()
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        let immediate = lock.withLock { () -> Result<CleanupStatus, Error>? in
          if closeFinished && workers == 0 && applicationWorkers == 0 { return .success(CleanupStatus(complete: true)) }
          if token.canceled { return .failure(SessionError.canceled) }
          guard waiter == nil else { return .failure(SessionError.resourceExhausted) }
          token.continuation = continuation
          waiter = token
          workers += 1
          let deadline = ContinuousClock.now.advanced(by: options.cleanupTimeout)
          token.timer = Task.detached { [self, token] in
            do { try await ContinuousClock().sleep(until: deadline) } catch { }
            let ready = lock.withLock { () -> CheckedContinuation<CleanupStatus, Error>? in
              guard waiter === token else { return nil }
              let continuation = token.continuation
              token.continuation = nil
              token.timer = nil
              waiter = nil
              workers -= 1
              _ = releaseIfFinished()
              return continuation
            }
            ready?.resume(returning: cleanupStatus())
          }
          return nil
        }
        if let immediate { continuation.resume(with: immediate) }
      }
    } onCancel: {
      let pending = self.lock.withLock { () -> CheckedContinuation<CleanupStatus, Error>? in
        token.canceled = true
        guard self.waiter === token else { return nil }
        let pending = token.continuation
        token.continuation = nil
        token.timer?.cancel()
        if token.timer == nil { self.waiter = nil }
        return pending
      }
      pending?.resume(throwing: SessionError.canceled)
    }
  }

  private func borrowStream() throws -> any ByteStream {
    try lock.withLock {
      guard let stream, !closeStarted else { throw SessionError.closed }
      return stream
    }
  }

  func read(maxBytes: Int) async throws -> Data? {
    let stream = try borrowStream()
    return try await stream.read(maxBytes: maxBytes)
  }

  func writeMessageChunk(
    _ bytes: Data, beforeAccept: @escaping @Sendable () throws -> Void,
    accepted: @escaping @Sendable (Int) -> Void
  ) async throws -> Int {
    let stream = try borrowStream()
    guard let writer = stream as? any V4MessageStreamWriter else {
      throw TransportAvailabilityError.runtimeUnavailable
    }
    return try await writer.writeMessageChunk(bytes, beforeAccept: beforeAccept, accepted: accepted)
  }

  func closeWrite() async throws {
    let stream = try borrowStream()
    try await stream.closeWrite()
  }

  func finish() async throws {
    let stream = try borrowStream()
    try await stream.finish()
  }

  func closeStream() async throws {
    let original = lock.withLock { () -> (any ByteStream)? in
      guard startClose() else { return nil }
      return stream
    }
    guard let original else { return }
    defer { finishClose() }
    try await original.close()
  }
}

/// A single owned source lets ReaderCursor keep partial frame bytes when a
/// receive wait is canceled. Raw ByteStream APIs remain available to callers
/// that choose not to use this adapter.
private final class TypedMessageCursorSource: ReaderCursorSource, @unchecked Sendable {
  let cursorGate: NSRecursiveLock
  let startOffset: UInt64
  let initialStatus = ReadStreamStatus.open
  let initialError: ReadStreamError? = nil
  private let core: TypedMessageStreamCore
  private var status = ReadStreamStatus.open
  private var readError: ReadStreamError?
  private var underlyingError: SessionError?
  private var stopped = false
  private var activeRead = false
  private var releaseRequested = false
  private var released = false
  private var payloadStorage: V4CryptoReservation?
  private let prefix: Bool
  private let target: Int
  private var received = 0
  private var prefixBytes = Data()

  init(
    core: TypedMessageStreamCore, target: Int, prefix: Bool,
    payloadStorage: V4CryptoReservation? = nil
  ) throws {
    try core.beginOperation()
    self.core = core
    cursorGate = core.lock
    startOffset = core.startOffset
    self.payloadStorage = payloadStorage
    self.prefix = prefix
    self.target = target
  }

  deinit { release() }

  func currentState() -> (ReadStreamStatus, ReadStreamError?) {
    cursorGate.withLock { (status, readError) }
  }

  func read(maxBytes: Int, transfer: @escaping @Sendable (CursorReadChunk) -> Void) async {
    let admitted = cursorGate.withLock { () -> Bool in
      guard !releaseRequested, !stopped, !activeRead else { return false }
      activeRead = true
      return true
    }
    guard admitted else {
      transfer(CursorReadChunk(data: Data(), status: .aborted, error: nil))
      return
    }
    defer {
      cursorGate.withLock {
        activeRead = false
        releaseIfFinished()
      }
    }
    do {
      try core.check()
      let bytes = try await core.read(maxBytes: maxBytes)
      let result = try cursorGate.withLock { () -> CursorReadChunk in
        guard !stopped else { return CursorReadChunk(data: Data(), status: .aborted, error: nil) }
        guard let bytes else {
          status = .eof
          return CursorReadChunk(data: Data(), status: .eof, error: nil)
        }
        guard bytes.count <= maxBytes else {
          status = .error
          readError = ReadStreamError(
            code: .streamDataInvalid, scope: .stream, retryDisposition: .preserveFacts)
          underlyingError = .streamReset
          return CursorReadChunk(data: Data(), status: .error, error: readError)
        }
        try core.check()
        received += bytes.count
        if prefix { prefixBytes.append(bytes) }
        let emptyMessage = prefix && received == 4
          && prefixBytes.allSatisfy({ $0 == 0 })
        try core.noteInput(
          count: bytes.count, prefix: prefix,
          complete: emptyMessage || (!prefix && received == target))
        try core.advance(by: bytes.count)
        return CursorReadChunk(data: bytes, status: status, error: readError)
      }
      cursorGate.withLock { transfer(result) }
    } catch {
      let sessionError = error as? SessionError ?? .streamReset
      let result = cursorGate.withLock { () -> CursorReadChunk in
        status = .error
        underlyingError = sessionError
        readError = ReadStreamError(
          code: .streamDataInvalid, scope: .stream, retryDisposition: .preserveFacts)
        return CursorReadChunk(data: Data(), status: .error, error: readError)
      }
      cursorGate.withLock { transfer(result) }
    }
  }

  func stopRead() { cursorGate.withLock { stopped = true } }
  func release() {
    cursorGate.withLock {
      releaseRequested = true
      releaseIfFinished()
    }
  }
  private func releaseIfFinished() {
    guard releaseRequested, !activeRead, !released else { return }
    released = true
    payloadStorage = nil
    core.endWorker()
  }

  var sessionError: SessionError? { cursorGate.withLock { underlyingError } }
}

private struct V4MessageReadResources<Value: Sendable>: Sendable {
  let body: V4CryptoReservation
  let completion: V4MessageCompletion<Value>?
}

/// Bounded, length-prefixed typed messages over one application ByteStream.
/// It owns one ReaderCursor at a time and never turns messages into RPC calls
/// or execution/recovery records.
public actor TypedMessageStream<Inbound: Sendable, Outbound: Sendable> {
  private enum ReceivePhase: Sendable {
    case length(ReaderCursor, TypedMessageCursorSource)
    case awaitingPayload(Int)
    case payload(Int, ReaderCursor, TypedMessageCursorSource, V4CryptoReservation)
    case candidate(Data, V4CryptoReservation)
    case decoding(V4MessageCompletion<Inbound>)
  }

  public let definition: MessageStreamDefinition
  public let applicationMetadata: StreamMetadata
  private let core: TypedMessageStreamCore
  private let inboundCodec: any MessageCodec<Inbound>
  private let sendOwner: MessageStreamSendOwner<Outbound>
  private let inboundDefinition: MessageDefinition
  private let outboundDefinition: MessageDefinition
  private var phase: ReceivePhase?
  private var pendingCompletion: V4MessageCompletion<Inbound>?
  private var receiving = false
  private var closed = false
  private var closeTask: Task<Void, Error>?

  init<InboundCodec: MessageCodec, OutboundCodec: MessageCodec>(
    prepared: V4PreparedMessageStream,
    definition: MessageStreamDefinition,
    opener: Bool,
    applicationMetadata: StreamMetadata = .empty,
    inboundCodec: InboundCodec,
    outboundCodec: OutboundCodec,
    inboundDefinition: MessageDefinition,
    outboundDefinition: MessageDefinition,
    options: MessageStreamOptions = .standard
  ) throws where InboundCodec.Value == Inbound, OutboundCodec.Value == Outbound {
    let expectedInbound = opener ? definition.acceptorToOpener : definition.openerToAcceptor
    let expectedOutbound = opener ? definition.openerToAcceptor : definition.acceptorToOpener
    guard inboundDefinition == expectedInbound, outboundDefinition == expectedOutbound,
      prepared.stream.kind == definition.kind
    else { throw ServiceFailure.contractMismatch }
    self.definition = definition
    self.applicationMetadata = applicationMetadata
    let owner = TypedMessageStreamCore(prepared: prepared, options: options)
    core = owner
    self.inboundCodec = inboundCodec
    let publisher = MessageStreamSendOwner<Outbound>(
      core: owner, codec: outboundCodec, definition: outboundDefinition, timeout: options.sendTimeout)
    sendOwner = publisher
    owner.onClose { [weak publisher] in publisher?.close() }
    self.inboundDefinition = inboundDefinition
    self.outboundDefinition = outboundDefinition
  }

  deinit {
    sendOwner.close()
    if case .length(let cursor, _) = phase { cursor.close() }
    if case .payload(_, let cursor, _, _) = phase { cursor.close() }
    if case .decoding(let owner) = phase { owner.close() }
    pendingCompletion?.close()
    pendingCompletion = nil
    let owner = core
    Task { try? await owner.closeStream() }
  }

  @discardableResult
  public nonisolated func send(
    _ value: Outbound, admission: MessageSendAdmission = .queued,
    context: ApplicationInvocationContext? = nil
  ) async throws -> MessageSendResult {
    try await sendOwner.send(value, admission: admission, context: context)
  }

  /// Receives one typed message. `nil` means clean EOF between messages.
  public func receive(context: ApplicationInvocationContext? = nil) async throws -> MessageReceived<Inbound>? {
    guard !closed else { throw SessionError.closed }
    if case .decoding(let owner) = phase, try owner.knownDependency(context) {
      throw ApplicationInvocationFailure.knownApplicationDependency
    }
    guard !receiving else { throw ReadMethodFailure(reason: .readInProgress, cursor: nil) }
    receiving = true
    defer {
      receiving = false
      // A canceled framing wait does not hold a dormant Completion claim or
      // typed delta. The encoded cursor/body remains the same current message.
      pendingCompletion?.close()
      pendingCompletion = nil
    }
    let owner: V4MessageCompletion<Inbound>
    if case .decoding(let current) = phase { owner = current }
    else {
      try core.beginOperation()
      do {
        guard let (encoded, storage) = try await receiveCandidate(typed: true, context: context) else {
          core.endWorker()
          return nil
        }
        guard let prepared = pendingCompletion else { throw V4ResourceFailure.owner }
        try prepared.bind(encoded: encoded, storage: storage)
        owner = prepared
        pendingCompletion = nil
        phase = .decoding(owner)
      } catch { core.endWorker(); throw error }
      core.endWorker()
    }
    defer { if owner.deliveryCommitted { phase = nil } }
    do { return try await owner.take(context: context) }
    catch let error as MessageReceiveError {
      // Failure of a concrete SDK codec is a required structure check. Its
      // bytes were never application input, so the adapter must terminate the
      // original Stream rather than continue at another prefix.
      if !error.applicationInputDelivered { await abortStream() }
      throw error
    }
  }

  /// Receives one owned encoded payload for applications that perform decoding
  /// outside this adapter. The payload never aliases the Session. Its bounded
  /// codec identity does not retain the definition or the live adapter.
  public func receiveEncoded(context: ApplicationInvocationContext? = nil) async throws -> EncodedMessageReceived? {
    guard !closed else { throw SessionError.closed }
    if case .decoding(let owner) = phase, try owner.knownDependency(context) {
      throw ApplicationInvocationFailure.knownApplicationDependency
    }
    guard !receiving else { throw ReadMethodFailure(reason: .readInProgress, cursor: nil) }
    receiving = true
    defer { receiving = false }
    try context?.checkCancellation()
    if case .decoding(let owner) = phase {
      let bytes = try owner.takeEncoded(context: context)
      phase = nil
      return EncodedMessageReceived(payload: bytes, codec: MessageCodecIdentity(inboundDefinition))
    }
    try core.beginOperation()
    defer { core.endWorker() }
    guard let (encoded, storage) = try await receiveCandidate(typed: false, context: context) else { return nil }
    defer { withExtendedLifetime(storage) {} }
    phase = nil
    return EncodedMessageReceived(payload: encoded, codec: MessageCodecIdentity(inboundDefinition))
  }

  private func readCursor(_ cursor: ReaderCursor) async throws -> ReadResult {
    do {
      let result = try await cursor.readExactly()
      try core.check()
      return result
    } catch {
      try core.check()
      throw error
    }
  }

  private func receiveCandidate(typed: Bool, context: ApplicationInvocationContext?) async throws -> (Data, V4CryptoReservation)? {
    let dependent = try core.completionDependent(context)
    let core = self.core, codec = inboundCodec
    while true {
      try Task.checkCancellation()
      try context?.checkCancellation()
      switch phase {
      case nil:
        let source = try TypedMessageCursorSource(core: core, target: 4, prefix: true)
        let cursor: ReaderCursor
        do {
          cursor = try ReaderCursor(source: source, options: ReaderCursorOptions(exact: 4), capacity: 4)
        } catch {
          source.release()
          throw error
        }
        core.attachCursor(cursor)
        phase = .length(cursor, source)
      case .length(let cursor, let source):
        let result = try await readCursor(cursor)
        guard !closed else { throw SessionError.closed }
        if result.waitStatus == .waitCanceled { throw SessionError.canceled }
        if result.data.isEmpty && result.streamStatus == .eof {
          phase = nil
          return nil
        }
        guard result.data.count == 4, result.cause == nil, result.streamStatus == .open else {
          let error = source.sessionError ?? .streamReset
          await abortStream()
          throw error
        }
        let length = result.data.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard UInt64(length) <= UInt64(inboundDefinition.maxMessageBytes) else {
          await abortStream()
          throw ServiceFailure.protocolFailure
        }
        // Retain the consumed prefix independently of the delivered prefix
        // cursor. A later budget attempt must continue this exact message.
        phase = .awaitingPayload(Int(length))
      case .awaitingPayload(let length):
        let bodyStorage: V4CryptoReservation
        do {
          let resources = try await core.acquireResources(tryNow: dependent) {
            let body = try core.reservePayload(bytes: length, encoding: false)
            let completion: V4MessageCompletion<Inbound>? = typed
              ? try core.makeCompletion(bytes: length, codec: codec, definition: self.inboundDefinition, context: context) : nil
            return V4MessageReadResources(body: body, completion: completion)
          }
          bodyStorage = resources.body
          pendingCompletion = resources.completion
        } catch {
          try core.check()
          if error as? SessionError == .canceled || error is CancellationError {
            throw SessionError.canceled
          }
          if dependent || error is ApplicationInvocationFailure {
            // Preserve the same consumed prefix. No partial claim or vector is
            // held while a Completion ancestor waits for another opportunity.
            throw error
          }
          await abortStream()
          throw error
        }
        let payloadSource = try TypedMessageCursorSource(core: core, target: length, prefix: false, payloadStorage: bodyStorage)
        let payloadCursor: ReaderCursor
        do {
          payloadCursor = try ReaderCursor(
            source: payloadSource, options: ReaderCursorOptions(exact: UInt64(length)),
            capacity: UInt64(inboundDefinition.maxMessageBytes))
        } catch {
          payloadSource.release()
          await abortStream()
          throw error
        }
        core.attachCursor(payloadCursor)
        phase = .payload(length, payloadCursor, payloadSource, bodyStorage)
      case .payload(let length, let cursor, let source, let storage):
        if typed && pendingCompletion == nil {
          pendingCompletion = try await core.acquireResources(tryNow: dependent) {
            try core.makeCompletion(bytes: length, codec: codec, definition: self.inboundDefinition, context: context)
          }
        }
        let result = try await readCursor(cursor)
        guard !closed else { throw SessionError.closed }
        if result.waitStatus == .waitCanceled { throw SessionError.canceled }
        guard result.data.count == length, result.cause == nil, result.streamStatus == .open else {
          let error = source.sessionError ?? .streamReset
          await abortStream()
          throw error
        }
        phase = .candidate(result.data, storage)
      case .candidate(let bytes, let storage):
        if typed && pendingCompletion == nil {
          pendingCompletion = try await core.acquireResources(tryNow: dependent) {
            try core.makeCompletion(bytes: bytes.count, codec: codec, definition: self.inboundDefinition, context: context)
          }
        }
        try core.check()
        return (bytes, storage)
      case .decoding:
        throw ReadMethodFailure(reason: .readInProgress, cursor: nil)
      }
    }
  }

  public nonisolated func closeWrite() async throws {
    try await sendOwner.closeWrite()
  }

  public func finish() async throws {
    guard !closed else { throw SessionError.closed }
    try await sendOwner.closeWrite()
    try core.beginOperation()
    defer { core.endWorker() }
    try await core.finish()
  }

  public func close() async throws {
    closed = true
    sendOwner.close()
    if case .length(let cursor, _) = phase { cursor.close() }
    if case .payload(_, let cursor, _, _) = phase { cursor.close() }
    if case .decoding(let owner) = phase { owner.close() }
    pendingCompletion?.close()
    pendingCompletion = nil
    phase = nil
    try await closeUnderlying()
  }

  public func cleanupStatus() -> CleanupStatus { core.cleanupStatus() }
  public func waitCleanup(context: ApplicationInvocationContext? = nil) async throws -> CleanupStatus {
    if case .decoding(let owner) = phase, try owner.knownDependency(context) {
      throw ApplicationInvocationFailure.knownApplicationDependency
    }
    try core.checkCleanupDependency(context)
    return try await core.waitCleanup()
  }

  private func abortStream() async {
    closed = true
    sendOwner.close()
    if case .length(let cursor, _) = phase { cursor.close() }
    if case .payload(_, let cursor, _, _) = phase { cursor.close() }
    if case .decoding(let owner) = phase { owner.close() }
    pendingCompletion?.close()
    pendingCompletion = nil
    phase = nil
    do { try await closeUnderlying() } catch { }
  }

  private func closeUnderlying() async throws {
    if let closeTask { return try await closeTask.value }
    let task = Task { try await core.closeStream() }
    closeTask = task
    try await task.value
  }
}
