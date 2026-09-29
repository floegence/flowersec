import Foundation

public struct ConnectionRequirements: Sendable, Equatable {
  public var independentReliableReadProgress: Bool
  public var boundStreamInputIsolation: Bool
  public var datagram: Bool
  public var localConsumerTLS13Verification: Bool
  public var applicationProfile: String?

  public init(
    independentReliableReadProgress: Bool = false,
    boundStreamInputIsolation: Bool = false,
    datagram: Bool = false,
    localConsumerTLS13Verification: Bool = false,
    applicationProfile: String? = nil
  ) {
    self.independentReliableReadProgress = independentReliableReadProgress
    self.boundStreamInputIsolation = boundStreamInputIsolation
    self.datagram = datagram
    self.localConsumerTLS13Verification = localConsumerTLS13Verification
    self.applicationProfile = applicationProfile
  }
}

public struct CleanupStatus: Sendable, Equatable {
  public let complete: Bool
  public let cleanupIncomplete: Bool
  public let pendingCallbacks: UInt64

  public init(complete: Bool = false, cleanupIncomplete: Bool = false, pendingCallbacks: UInt64 = 0)
  {
    self.complete = complete
    self.cleanupIncomplete = cleanupIncomplete
    self.pendingCallbacks = pendingCallbacks
  }
}

public enum TransportV4AvailabilityError: Error, Sendable {
  case runtimeUnavailable
}

// Only the authenticated v4 assembly may supply these owners. In particular,
// an arbitrary Session is not an ArtifactLease/ApplicationIdentity pair.
protocol ConnectionMaterialOwner: Sendable {
  func close()
  func waitCleanup() async throws -> CleanupStatus
  func cleanupStatus() -> CleanupStatus
}

public final class ConnectionMaterial: Sendable {
  let owner: any ConnectionMaterialOwner
  init(owner: any ConnectionMaterialOwner) { self.owner = owner }
  public func close() { owner.close() }
  public func waitCleanup() async throws -> CleanupStatus { try await owner.waitCleanup() }
  public func cleanupStatus() -> CleanupStatus { owner.cleanupStatus() }
}

public protocol ConnectionMaterialSource: Sendable {
  func acquire(_ requirements: ConnectionRequirements) async throws -> ConnectionMaterial
}

protocol TransportEnvironmentOwner: Sendable {
  // The owner must fence Acquire, material consumption and Session publication
  // against Close, retaining late preparation work until actual cleanup.
  func connect(source: any ConnectionMaterialSource, requirements: ConnectionRequirements)
    async throws -> any Session
  func connectMaterial(_ material: ConnectionMaterial, requirements: ConnectionRequirements)
    async throws -> any Session
  func close() async throws
  func cleanupStatus() -> CleanupStatus
}

public actor TransportEnvironment {
  private let owner: (any TransportEnvironmentOwner)?
  private var closed = false
  private var closing: Task<Void, Error>?

  // A configured native client is required before Acquire or material spend.
  public init() { owner = nil }
  init(owner: any TransportEnvironmentOwner) { self.owner = owner }
  #if os(macOS) || os(iOS)
    public init(configuration: TransportV4ClientConfiguration) async throws {
      owner = try await V4ClientEnvironment.create(configuration)
    }
    public func generateApplicationIdentity(profile: TransportV4CryptoProfile) throws
      -> TransportV4ApplicationIdentity
    {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try TransportV4ApplicationIdentity(
        client.foundation.generateIdentity(profile: V4CryptoProfile(rawValue: profile.rawValue)!))
    }
    public func importApplicationIdentity(
      profile: TransportV4CryptoProfile, signingSeed: Data,
      noiseStaticPrivateKey: Data
    ) throws -> TransportV4ApplicationIdentity {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try TransportV4ApplicationIdentity(
        client.foundation.importIdentity(
          profile: V4CryptoProfile(rawValue: profile.rawValue)!, signingSeed: signingSeed,
          staticKey: noiseStaticPrivateKey))
    }
    public func preparePoolMaterial(
      _ credential: TransportV4PoolCredential,
      identity: TransportV4ApplicationIdentity
    ) throws -> ConnectionMaterial {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try client.material(credential, identity: identity)
    }
    public func invalidateTimeContinuity() {
      (owner as? V4ClientEnvironment)?.invalidateTimeContinuity()
    }
    public func refreshTrustedTime() throws {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      try client.refreshTrustedTime()
    }
    public func refreshNamespace(authority: String, head: Data, state: Data) throws {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      try client.refreshNamespace(authority: authority, head: head, state: state)
    }
  #endif

  public func connect(
    source: any ConnectionMaterialSource,
    requirements: ConnectionRequirements = ConnectionRequirements()
  ) async throws -> any Session {
    guard !closed else { throw SessionError.closed }
    guard let owner else { throw TransportV4AvailabilityError.runtimeUnavailable }
    let session = try await owner.connect(source: source, requirements: requirements)
    return try await publish(session)
  }

  public func connectMaterial(
    _ material: ConnectionMaterial,
    requirements: ConnectionRequirements = ConnectionRequirements()
  ) async throws -> any Session {
    guard !closed else { throw SessionError.closed }
    guard let owner else { throw TransportV4AvailabilityError.runtimeUnavailable }
    let session = try await owner.connectMaterial(material, requirements: requirements)
    return try await publish(session)
  }

  private func publish(_ session: any Session) async throws -> any Session {
    if closed || Task.isCancelled {
      try await session.close()
      throw closed ? SessionError.closed : SessionError.canceled
    }
    return session
  }

  public func close() async throws {
    if let closing { return try await closing.value }
    closed = true
    guard let owner else { return }
    let task = Task { try await owner.close() }
    closing = task
    try await task.value
  }

  public func cleanupStatus() -> CleanupStatus {
    owner?.cleanupStatus() ?? CleanupStatus(complete: closed)
  }
}

public struct ReadProgress: Sendable, Equatable {
  public let offset: UInt64
  public let filled: UInt64
  public let target: UInt64?
}

public enum ReadWaitStatus: String, Sendable {
  case ready, blocked
  case waitCanceled = "wait_canceled"
}
public enum ReadStreamStatus: String, Sendable { case open, eof, aborted, error }
public enum ReadCause: String, Sendable {
  case delimiterNotFound = "delimiter_not_found"
  case unexpectedEOF = "unexpected_eof"
}

public struct ReadStreamError: Error, Sendable, Equatable {
  public enum Code: String, Sendable {
    case protocolViolation = "protocol_violation"
    case framingError = "framing_error"
    case authenticationFailed = "authentication_failed"
    case sequenceError = "sequence_error"
    case replayDetected = "replay_detected"
    case cryptoFailure = "crypto_failure"
    case rekeyFailed = "rekey_failed"
    case resourceExhausted = "resource_exhausted"
    case streamSequenceError = "stream_sequence_error"
    case streamDataInvalid = "stream_data_invalid"
  }
  public enum Scope: String, Sendable { case session, stream }
  public enum RetryDisposition: String, Sendable { case preserveFacts = "preserve_facts" }
  public let code: Code
  public let scope: Scope
  public let retryDisposition: RetryDisposition
}

public struct ReadResult: Sendable, Equatable {
  public let data: Data
  public let progress: ReadProgress
  public let waitStatus: ReadWaitStatus
  public let streamStatus: ReadStreamStatus
  public let cause: ReadCause?
  public let error: ReadStreamError?
}

public struct ReaderCursorOptions: Sendable, Equatable {
  public var exact: UInt64?
  public var delimiter: Data?
  public var maxBytes: UInt64

  public init(exact: UInt64? = nil, delimiter: Data? = nil, maxBytes: UInt64 = 0) {
    self.exact = exact
    self.delimiter = delimiter
    self.maxBytes = maxBytes
  }
}

public struct ReaderCursorSnapshot: Sendable, Equatable {
  public let offset: UInt64
  public let transferredBytes: UInt64
  public let target: UInt64
  public let streamStatus: ReadStreamStatus
  public let targetCause: ReadCause?
  public let streamError: ReadStreamError?
  public let complete: Bool
  public let frozen: Bool
  public let delivered: Bool
  public let closed: Bool
}

public struct ReadMethodFailure: Error, Sendable, Equatable {
  public enum Reason: String, Sendable {
    case invalidArgument = "invalid_argument"
    case targetMismatch = "target_mismatch"
    case readInProgress = "read_in_progress"
    case prefixFrozen = "prefix_frozen"
    case alreadyDelivered = "already_delivered"
    case timePending = "time_pending"
    case timeUnavailable = "time_unavailable"
    case authorizationDenied = "authorization_denied"
    case ownerUnavailable = "owner_unavailable"
    case closed
  }
  public let reason: Reason
  public let cursor: ReaderCursorSnapshot?
}

struct CursorReadChunk: Sendable {
  let data: Data
  let status: ReadStreamStatus
  let error: ReadStreamError?
}

// This is an already reserved, exclusively claimed v4 read direction. It is
// deliberately not ByteStream: raw reads, another cursor and adapters must
// share the native owner's claim gate. A read transfers at most maxBytes; a
// stopped read reports every byte it actually consumed before returning.
protocol ReaderCursorSource: Sendable {
  var cursorGate: NSRecursiveLock { get }
  var admission: V4CursorAdmission? { get }
  // A larger piece is allowed only when the source preserves the original
  // delimiter boundary and matching state under the same gate.
  var delimiterPieceBytes: Int { get }
  var startOffset: UInt64 { get }
  var initialStatus: ReadStreamStatus { get }
  var initialError: ReadStreamError? { get }
  func currentState() -> (ReadStreamStatus, ReadStreamError?)
  // Transfer runs synchronously under cursorGate before the source releases
  // its queue bytes. It never calls application code or waits.
  func read(maxBytes: Int, transfer: @escaping @Sendable (CursorReadChunk) -> Void) async
  func stopRead()
  func release()
}

extension ReaderCursorSource {
  var admission: V4CursorAdmission? { nil }
  var delimiterPieceBytes: Int { 1 }
  func currentState() -> (ReadStreamStatus, ReadStreamError?) { (initialStatus, initialError) }
}

public final class ReaderCursor: @unchecked Sendable {
  private enum Method { case exact, until, line, prefix }
  private final class Waiter: @unchecked Sendable {
    let method: Method
    var canceled = false
    var continuation: CheckedContinuation<ReadResult, Error>?
    init(_ method: Method) { self.method = method }
  }

  private let lock: NSRecursiveLock
  let admission: V4CursorAdmission?
  private let options: ReaderCursorOptions
  private let target: UInt64
  private let start: UInt64
  private var source: (any ReaderCursorSource)?
  private var buffer: Data
  private var transferred: UInt64 = 0
  private var status = ReadStreamStatus.open
  private var cause: ReadCause?
  private var streamError: ReadStreamError?
  private var complete = false
  private var frozen = false
  private var delivered = false
  private var closed = false
  private var closeReason = ReadMethodFailure.Reason.closed
  private var advancing = false
  private var waiter: Waiter?

  // The caller supplies a capacity already charged to the original v4 owner.
  // No public initializer can turn a previous-engine ByteStream into v4 I/O.
  init(source: any ReaderCursorSource, options: ReaderCursorOptions, capacity: UInt64) throws {
    let target = try Self.checkedTarget(
      options: options, capacity: capacity, start: source.startOffset)
    guard (source.initialStatus == .error) == (source.initialError != nil) else {
      throw ReadMethodFailure(reason: .invalidArgument, cursor: nil)
    }
    self.lock = source.cursorGate
    self.admission = source.admission
    self.source = source
    self.options = options
    self.target = target
    self.start = source.startOffset
    self.buffer = Data(capacity: Int(target))
    self.status = source.initialStatus
    self.streamError = source.initialError
    self.complete = options.exact == 0 || source.initialStatus != .open
    if source.initialStatus == .eof && target > 0 { self.cause = .unexpectedEOF }
    try admission?.attach(self)
    if complete { admission?.inputCompleted() }
  }

  static func checkedTarget(options: ReaderCursorOptions, capacity: UInt64, start: UInt64) throws
    -> UInt64
  {
    let target: UInt64
    if let exact = options.exact, options.delimiter == nil, options.maxBytes == 0 {
      target = exact
    } else if options.exact == nil, let delimiter = options.delimiter,
      (1...32).contains(delimiter.count), options.maxBytes >= UInt64(delimiter.count)
    {
      target = options.maxBytes
    } else {
      throw ReadMethodFailure(reason: .invalidArgument, cursor: nil)
    }
    guard target <= capacity, target <= UInt64(Int.max),
      !start.addingReportingOverflow(target).overflow
    else { throw ReadMethodFailure(reason: .invalidArgument, cursor: nil) }
    return target
  }

  deinit { close() }

  public func progress() -> ReaderCursorSnapshot {
    lock.withLock {
      refreshTerminalLocked()
      return snapshotLocked()
    }
  }

  public func readExactly() async throws -> ReadResult { try await read(.exact) }
  public func readUntil() async throws -> ReadResult { try await read(.until) }
  public func readLine() async throws -> ReadResult { try await read(.line) }
  public func takePrefix() async throws -> ReadResult { try await read(.prefix) }

  private func read(_ method: Method) async throws -> ReadResult {
    let token = Waiter(method)
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        register(token, continuation)
      }
    } onCancel: {
      self.cancel(token)
    }
  }

  private func register(_ token: Waiter, _ continuation: CheckedContinuation<ReadResult, Error>) {
    lock.lock()
    token.continuation = continuation
    refreshTerminalLocked()
    let mismatch =
      (token.method == .exact && options.exact == nil)
      || ((token.method == .until || token.method == .line) && options.delimiter == nil)
      || (token.method == .line && options.delimiter != Data([0x0a]))
    let reason: ReadMethodFailure.Reason?
    if mismatch {
      reason = .targetMismatch
    } else if delivered {
      reason = .alreadyDelivered
    } else if closed {
      reason = closeReason
    } else if token.method != .prefix && frozen {
      reason = .prefixFrozen
    } else if let denied = admission?.failure() {
      reason = denied
    } else if waiter != nil && (token.method != .prefix || waiter?.method == .prefix) {
      reason = .readInProgress
    } else {
      reason = nil
    }
    if let reason {
      let error = failureLocked(reason)
      lock.unlock()
      continuation.resume(throwing: error)
      return
    }
    // A committed stream terminal wins over waiter cancellation. Cancellation
    // otherwise transfers no payload and never erases the retained prefix.
    if token.canceled && status == .open {
      let result = resultLocked(data: Data(), wait: .waitCanceled)
      lock.unlock()
      continuation.resume(returning: result)
      return
    }
    var superseded: CheckedContinuation<ReadResult, Error>?
    var supersededError: ReadMethodFailure?
    var stop: (any ReaderCursorSource)?
    if token.method == .prefix {
      frozen = true
      superseded = waiter?.continuation
      supersededError = failureLocked(.prefixFrozen)
      waiter = nil
      if advancing { stop = source }
    }
    waiter = token
    if !advancing && (complete || frozen) {
      let result = deliverLocked()
      let released = detachLocked()
      // Successful continuation handoff and cancellation/revocation use the
      // original gate. A private candidate is not published after unlocking.
      released?.release()
      continuation.resume(returning: result)
      admission?.payloadReleased()
      lock.unlock()
      if let superseded, let supersededError { superseded.resume(throwing: supersededError) }
      return
    }
    let launch = !advancing
    if launch {
      advancing = true
      admission?.advancementStarted()
    }
    lock.unlock()
    if let superseded, let supersededError { superseded.resume(throwing: supersededError) }
    stop?.stopRead()
    if launch {
      Task { await self.advance() }
    }
  }

  private func cancel(_ token: Waiter) {
    lock.lock()
    token.canceled = true
    refreshTerminalLocked()
    guard waiter === token, status == .open else {
      lock.unlock()
      return
    }
    waiter = nil
    let result = resultLocked(data: Data(), wait: .waitCanceled)
    lock.unlock()
    token.continuation?.resume(returning: result)
  }

  // Keep at most one source read alive independently of its cancellable waiter.
  // The native owner scans finite pieces and retains any delimiter suffix in
  // its original queue; isolated sources default to single-byte transfers.
  private func advance() async {
    defer { admission?.advancementFinished() }
    while let (source, maximum) = nextRead() {
      await source.read(maxBytes: maximum) { chunk in
        self.receive(chunk, maximum: maximum)
      }
    }
  }

  private func nextRead() -> ((any ReaderCursorSource), Int)? {
    lock.lock()
    if !closed, let denied = admission?.failure() {
      advancing = false
      let token = waiter
      waiter = nil
      let failure = failureLocked(denied)
      lock.unlock()
      token?.continuation?.resume(throwing: failure)
      if denied == .authorizationDenied || denied == .ownerUnavailable { close(reason: denied) }
      return nil
    }
    if closed || complete || frozen || waiter == nil {
      advancing = false
      let token = waiter
      var result: ReadResult?
      if !closed, token != nil, complete || frozen { result = deliverLocked() }
      let released = (closed || complete || frozen) ? detachLocked() : nil
      released?.release()
      if let result {
        token?.continuation?.resume(returning: result)
        admission?.payloadReleased()
      }
      lock.unlock()
      return nil
    }
    guard let source else {
      lock.unlock()
      return nil
    }
    let remaining = Int(target - transferred)
    let piece = options.delimiter == nil ? 4096 : max(1, min(4096, source.delimiterPieceBytes))
    let maximum = min(piece, remaining)
    lock.unlock()
    return (source, maximum)
  }

  private func receive(_ chunk: CursorReadChunk, maximum: Int) {
    lock.withLock {
      // The internal owner contract rules out oversized results and empty open
      // completions. Treat a violation as a stream fault, never successful EOF.
      guard chunk.data.count <= maximum,
        (chunk.status == .error) == (chunk.error != nil),
        !chunk.data.isEmpty || chunk.status != .open || frozen || closed
      else {
        status = .error
        streamError = ReadStreamError(
          code: .streamDataInvalid, scope: .stream, retryDisposition: .preserveFacts)
        complete = true
        return
      }
      transferred += UInt64(chunk.data.count)
      if !closed { buffer.append(chunk.data) }
      status = chunk.status
      streamError = chunk.error
      if closed { return }
      let matched = options.delimiter.map { buffer.suffix($0.count).elementsEqual($0) } ?? false
      if matched || (options.exact != nil && transferred == target) {
        complete = true
      } else if transferred == target {
        cause = .delimiterNotFound
        complete = true
      } else if status == .eof {
        cause = .unexpectedEOF
        complete = true
      } else if status != .open {
        complete = true
      }
      if complete { admission?.inputCompleted() }
    }
  }

  public func close() {
    close(reason: .closed)
  }

  func authorizationChanged(_ reason: ReadMethodFailure.Reason) {
    if reason == .authorizationDenied || reason == .ownerUnavailable {
      close(reason: reason)
      return
    }
    lock.lock()
    let token = waiter
    waiter = nil
    let failure = failureLocked(reason)
    lock.unlock()
    token?.continuation?.resume(throwing: failure)
  }

  private func close(reason: ReadMethodFailure.Reason) {
    lock.lock()
    guard !closed else {
      lock.unlock()
      return
    }
    closed = true
    closeReason = reason
    buffer.removeAll(keepingCapacity: false)
    let token = waiter
    waiter = nil
    let failure = failureLocked(reason)
    let stop = advancing ? source : nil
    let released = advancing ? nil : detachLocked()
    lock.unlock()
    token?.continuation?.resume(throwing: failure)
    stop?.stopRead()
    released?.release()
    admission?.payloadReleased()
  }

  private func refreshTerminalLocked() {
    guard !closed, !delivered, status == .open, let source else { return }
    let (current, error) = source.currentState()
    guard current != .open else { return }
    status = current
    streamError = error
    if !complete && current == .eof { cause = .unexpectedEOF }
    complete = true
    admission?.inputCompleted()
  }

  private func snapshotLocked() -> ReaderCursorSnapshot {
    ReaderCursorSnapshot(
      offset: start + transferred, transferredBytes: transferred, target: target,
      streamStatus: status, targetCause: cause, streamError: streamError,
      complete: complete, frozen: frozen, delivered: delivered, closed: closed)
  }

  private func failureLocked(_ reason: ReadMethodFailure.Reason) -> ReadMethodFailure {
    ReadMethodFailure(reason: reason, cursor: snapshotLocked())
  }

  private func resultLocked(data: Data, wait: ReadWaitStatus) -> ReadResult {
    ReadResult(
      data: data,
      progress: ReadProgress(
        offset: start + transferred,
        filled: UInt64(data.count), target: target), waitStatus: wait, streamStatus: status,
      cause: cause, error: streamError)
  }

  private func deliverLocked() -> ReadResult {
    delivered = true
    waiter = nil
    let result = resultLocked(data: buffer, wait: .ready)
    buffer = Data()
    return result
  }

  private func detachLocked() -> (any ReaderCursorSource)? {
    let released = source
    source = nil
    return released
  }
}

public enum WritePhase: String, Sendable { case prepared, running, terminal }
public enum WriteTerminalReason: String, Sendable {
  case none, complete, canceled
  case deadlineExceeded = "deadline_exceeded"
  case queueFull = "queue_full"
  case streamTerminated = "stream_terminated"
  case failed
}

public struct WriteProgress: Sendable, Equatable {
  public let requestedBytes: UInt64
  public let acceptedBytes: UInt64
  public let phase: WritePhase
  public let terminalReason: WriteTerminalReason
  public let cleanup: CleanupStatus
}

// The same native request owns ordinary Write and prepared WriteOperation.
// Its acceptance gate records progress, cancellation and cleanup atomically;
// a task around ByteStream.write cannot reconstruct partial acceptance.
protocol PreparedWriteOwner: Sendable {
  func start() throws
  func cancel()
  func progress() -> WriteProgress
  func wait() async throws -> WriteProgress
}

public final class WriteOperation: Sendable {
  private let owner: any PreparedWriteOwner
  init(owner: any PreparedWriteOwner) { self.owner = owner }
  public func start() throws { try owner.start() }
  public func cancel() { owner.cancel() }
  public func progress() -> WriteProgress { owner.progress() }
  public func wait() async throws -> WriteProgress { try await owner.wait() }
  public func cleanupStatus() -> CleanupStatus { owner.progress().cleanup }
}

protocol NotificationSubscriptionOwner: Sendable {
  func close()
  func waitClosed() async throws -> CleanupStatus
  func cleanupStatus() -> CleanupStatus
}

public final class NotificationSubscription: Sendable {
  private let owner: any NotificationSubscriptionOwner
  init(owner: any NotificationSubscriptionOwner) { self.owner = owner }
  public func close() { owner.close() }
  public func waitClosed() async throws -> CleanupStatus { try await owner.waitClosed() }
  public func cleanupStatus() -> CleanupStatus { owner.cleanupStatus() }
}

public struct OperationReference: Sendable, Equatable {
  public let bytes: Data
  init(bytes: Data) { self.bytes = bytes }
}
public enum OperationStatus: String, Sendable {
  case pending, accepted, executing, completed, failed, unknown
}
public struct ResultPayload: Sendable {
  public let status: OperationStatus
  public let payload: Data?
}

protocol OperationOwner: Sendable {
  func start() throws
  func status() -> OperationStatus
  func requestCancel() throws
  func waitStatus() async throws -> OperationStatus
  func cleanupStatus() -> CleanupStatus
}

public final class OperationHandle: Sendable {
  private let owner: any OperationOwner
  init(owner: any OperationOwner) { self.owner = owner }
  public func start() throws { try owner.start() }
  public func status() -> OperationStatus { owner.status() }
  public func requestCancel() throws { try owner.requestCancel() }
  public func waitStatus() async throws -> OperationStatus { try await owner.waitStatus() }
  public func cleanupStatus() -> CleanupStatus { owner.cleanupStatus() }
}
