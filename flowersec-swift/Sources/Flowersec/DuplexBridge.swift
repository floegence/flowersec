import Foundation

// Minted only by the native bridge constructor; copying a public Stream never
// creates a token capable of accessing either claimed direction.
final class V4DuplexBridgeToken: @unchecked Sendable {}

public enum DuplexBridgeFailure: String, Error, Sendable {
  case invalidEndpoint = "invalid_endpoint"
  case configurationCapacity = "configuration_capacity"
  case resourceExhausted = "resource_exhausted"
  case streamOwned = "stream_owned"
  case ownerUnavailable = "owner_unavailable"
  case readFailed = "read_failed"
  case writeFailed = "write_failed"
  case finishFailed = "finish_failed"
  case aborted
  case deadlineExceeded = "deadline_exceeded"
  case waitCanceled = "wait_canceled"
  case waitInProgress = "wait_in_progress"
}

public struct DuplexBridgeOptions: Sendable, Equatable {
  public let chunkBytes: Int
  public let deadline: Duration
  public let cleanupTimeout: Duration

  public init(chunkBytes: Int = 16_384, deadline: Duration = .seconds(30),
    cleanupTimeout: Duration = .seconds(5)) throws {
    guard (1...1_048_576).contains(chunkBytes), deadline > .zero,
      deadline <= .seconds(86_400), cleanupTimeout > .zero,
      cleanupTimeout <= .seconds(30) else { throw DuplexBridgeFailure.configurationCapacity }
    self.chunkBytes = chunkBytes; self.deadline = deadline; self.cleanupTimeout = cleanupTimeout
  }
  static let standard = try! DuplexBridgeOptions()
}

public enum DuplexBridgeEndpointKind: String, Sendable { case flowersecStream = "flowersec_stream", nativeTCP = "native_tcp" }

public enum DuplexBridgeOutcome: String, Sendable { case notStarted = "not_started", running, normal, failed, aborted }
public enum DuplexBridgeSourceStatus: String, Sendable { case reading, eof, failed, aborted }

/// Detached metadata; snapshots never duplicate the charged transfer tail.
public struct DuplexBridgeDirectionProgress: Sendable, Equatable {
  public let sourceReadBytes: UInt64
  public let destinationAcceptedBytes: UInt64
  public let pendingTailBytes: UInt64
  public let sourceStatus: DuplexBridgeSourceStatus
  public let closeWriteCompleted: Bool
  public let sendDrained: Bool
  public let destinationKind: DuplexBridgeEndpointKind
  public let nativeSendFinished: Bool
  public let ioExited: Bool
}

public struct DuplexBridgeProgress: Sendable, Equatable {
  public let aToB: DuplexBridgeDirectionProgress
  public let bToA: DuplexBridgeDirectionProgress
  public let outcome: DuplexBridgeOutcome
  public let failure: DuplexBridgeFailure?
  public let cleanupStatus: CleanupStatus
}

/// One immutable, charged tail. Copying a result shares this original owner.
/// Explicitly copying bytes into caller storage transfers that copy's budget
/// responsibility to the application; it never rewinds the source Stream.
public final class DuplexBridgeTail: @unchecked Sendable {
  private let bytes: Data
  private let storage: V4CryptoReservation
  init(_ bytes: Data, storage: V4CryptoReservation) { self.bytes = bytes; self.storage = storage }
  public var count: Int { bytes.count }
  public func withUnsafeBytes<Value>(_ body: (UnsafeRawBufferPointer) throws -> Value) rethrows -> Value {
    try bytes.withUnsafeBytes(body)
  }
  public func copyBytes(to destination: inout Data) throws -> Int {
    guard destination.count >= bytes.count else { throw DuplexBridgeFailure.resourceExhausted }
    destination.replaceSubrange(0..<bytes.count, with: bytes)
    return bytes.count
  }
}

public struct DuplexTransferProgress: Sendable {
  public let sourceReadBytes: UInt64
  public let destinationAcceptedBytes: UInt64
  public let unacceptedTail: DuplexBridgeTail
}

public struct DuplexBridgeDirectionResult: Sendable {
  public let progress: DuplexTransferProgress
  public let sourceStatus: DuplexBridgeSourceStatus
  /// Authenticated Flowersec send drain, never business completion.
  public let sendDrained: Bool
  public let destinationKind: DuplexBridgeEndpointKind
  public let nativeSendFinished: Bool
  public let failure: DuplexBridgeFailure?
  public let sessionError: SessionError?
  public let nativeError: DuplexTCPError?
}

/// Every Wait returns the same immutable result and the same two tail owners.
/// An incomplete cleanup observation remains historical; CleanupStatus on the
/// bridge observes physical retirement of its original endpoints on demand.
public final class DuplexBridgeResult: Sendable {
  public let aToB: DuplexBridgeDirectionResult
  public let bToA: DuplexBridgeDirectionResult
  public let outcome: DuplexBridgeOutcome
  public let cleanupStatus: CleanupStatus
  public let failure: DuplexBridgeFailure?
  public let sessionError: SessionError?
  public let nativeError: DuplexTCPError?
  init(aToB: DuplexBridgeDirectionResult, bToA: DuplexBridgeDirectionResult,
    outcome: DuplexBridgeOutcome, cleanup: CleanupStatus, failure: DuplexBridgeFailure?, sessionError: SessionError?, nativeError: DuplexTCPError?) {
    self.aToB = aToB; self.bToA = bToA; self.outcome = outcome
    cleanupStatus = cleanup; self.failure = failure; self.sessionError = sessionError; self.nativeError = nativeError
  }
}

public struct DuplexBridgeWaitError: Error, Sendable {
  public let failure: DuplexBridgeFailure
  public let progress: DuplexBridgeProgress
}

/// Owns two unused raw Streams, or a raw Stream and an SDK-owned TCP socket,
/// from the same Environment. Construction acquires both canonical claims and
/// reserves both finite Copy footprints before I/O. External aliases are refused.
public final class DuplexBridge: @unchecked Sendable {
  #if os(macOS) || os(iOS)
  private let owner: V4DuplexBridgeOwner
  #endif

  public init(_ a: any ByteStream, _ b: any ByteStream, options: DuplexBridgeOptions? = nil) throws {
    #if os(macOS) || os(iOS)
    owner = try V4DuplexBridgeOwner(a, b, options: options ?? .standard)
    #else
    throw DuplexBridgeFailure.ownerUnavailable
    #endif
  }
  #if os(macOS) || os(iOS)
  public init(_ stream: any ByteStream, _ tcp: DuplexTCPConnection, options: DuplexBridgeOptions? = nil) throws {
    owner = try V4DuplexBridgeOwner(stream, tcp, nativeFirst: false, options: options ?? .standard)
  }
  public init(_ tcp: DuplexTCPConnection, _ stream: any ByteStream, options: DuplexBridgeOptions? = nil) throws {
    owner = try V4DuplexBridgeOwner(stream, tcp, nativeFirst: true, options: options ?? .standard)
  }
  /// Two native endpoints cannot mint a Flowersec bridge or its resource owner.
  public init(_ a: DuplexTCPConnection, _ b: DuplexTCPConnection, options: DuplexBridgeOptions? = nil) throws {
    throw DuplexBridgeFailure.invalidEndpoint
  }
  #endif
  /// Starts once. Repeated calls join the same operation without another pump.
  public func start() throws {
    #if os(macOS) || os(iOS)
    try owner.start()
    #else
    throw DuplexBridgeFailure.ownerUnavailable
    #endif
  }
  /// Canceling this passive wait never cancels the owned bridge operation.
  public func wait() async throws -> DuplexBridgeResult {
    #if os(macOS) || os(iOS)
    return try await owner.wait()
    #else
    throw DuplexBridgeFailure.ownerUnavailable
    #endif
  }
  public func abort() {
    #if os(macOS) || os(iOS)
    owner.abort()
    #endif
  }
  public func progress() -> DuplexBridgeProgress {
    #if os(macOS) || os(iOS)
    return owner.progress()
    #else
    fatalError("DuplexBridge requires native Stream owners")
    #endif
  }
  public func cleanupStatus() -> CleanupStatus {
    #if os(macOS) || os(iOS)
    return owner.cleanupStatus()
    #else
    return CleanupStatus(complete: true)
    #endif
  }
  deinit { abort() }
}

#if os(macOS) || os(iOS)
protocol V4DuplexBridgeEndpoint: AnyObject, Sendable {
  var bridgeEnvironment: V4EnvironmentFoundation { get }
  var bridgeKind: DuplexBridgeEndpointKind { get }
  func bridgeRead(token: V4DuplexBridgeToken, maxBytes: Int,
    beforeRead: @escaping @Sendable () throws -> Void,
    delivered: @escaping @Sendable (Data) -> Void) async throws -> Data?
  func bridgeWrite(token: V4DuplexBridgeToken, _ data: Data,
    beforeAccept: @escaping @Sendable () throws -> Void,
    accepted: @escaping @Sendable (Int) -> Void) async throws -> Int
  func bridgeCloseWrite(token: V4DuplexBridgeToken,
    beforeFinish: @escaping @Sendable () throws -> Void) async throws
  func bridgeFinish(token: V4DuplexBridgeToken,
    beforeFinish: @escaping @Sendable () throws -> Void) async throws
  func bridgeReset(token: V4DuplexBridgeToken)
  func bridgeCleanupComplete(token: V4DuplexBridgeToken) -> Bool
}

final class V4DuplexBridgeDirection {
  var sourceRead: UInt64 = 0
  var accepted: UInt64 = 0
  var tail = Data()
  var publishedTailBytes: UInt64?
  var sourceStatus: DuplexBridgeSourceStatus = .reading
  var closeWriteCompleted = false
  var sendDrained = false
  var nativeSendFinished = false
  var destinationKind: DuplexBridgeEndpointKind = .flowersecStream
  var sendFinished: Bool { sendDrained || nativeSendFinished }
  var nativeError: DuplexTCPError?
  var exited = false
  var failure: DuplexBridgeFailure?
  var sessionError: SessionError?
  func snapshot() -> DuplexBridgeDirectionProgress {
    DuplexBridgeDirectionProgress(sourceReadBytes: sourceRead, destinationAcceptedBytes: accepted,
      pendingTailBytes: publishedTailBytes ?? UInt64(tail.count), sourceStatus: sourceStatus,
      closeWriteCompleted: closeWriteCompleted, sendDrained: sendDrained,
      destinationKind: destinationKind, nativeSendFinished: nativeSendFinished, ioExited: exited)
  }
}

private final class V4DuplexBridgeOwner: @unchecked Sendable {
  private let token: V4DuplexBridgeToken
  private let options: DuplexBridgeOptions
  private let environment: V4EnvironmentFoundation
  private var a: (any V4DuplexBridgeEndpoint)?
  private var b: (any V4DuplexBridgeEndpoint)?
  private var runtimeStorage: V4CryptoReservation?
  private var resultStorage: V4CryptoReservation?
  private var executionTail: V4ResourceReference?
  private var coordinator: Task<Void, Never>?
  private var aPump: Task<Void, Never>?
  private var bPump: Task<Void, Never>?
  private let directions = [V4DuplexBridgeDirection(), V4DuplexBridgeDirection()]
  private var started = false
  private var sealed = false
  private var waiter = false
  private var finished = false
  private var cleanupIncomplete = false
  private var pumpsJoined = false
  private var firstFailure: DuplexBridgeFailure?
  private var firstSessionError: SessionError?
  private var firstNativeError: DuplexTCPError?
  private var deadline: ContinuousClock.Instant?
  private var cleanupDeadline: ContinuousClock.Instant?
  private var result: DuplexBridgeResult?
  private var gate: NSRecursiveLock { environment.gate }

  init(_ a: any ByteStream, _ b: any ByteStream, options: DuplexBridgeOptions) throws {
    self.options = options
    deadline = ContinuousClock.now.advanced(by: options.deadline)
    let token = V4DuplexBridgeToken()
    self.token = token
    do {
      let prepared = try V4NativeByteStream.prepareBridge(a, b, token: token, chunkBytes: options.chunkBytes)
      self.a = prepared.0; self.b = prepared.1; environment = prepared.0.bridgeEnvironment
      runtimeStorage = prepared.2; resultStorage = prepared.3; executionTail = prepared.4
    } catch let error as DuplexBridgeFailure { throw error }
    catch { throw DuplexBridgeFailure.resourceExhausted }
    coordinator = Task.detached { [self] in await run() }
  }

  init(_ stream: any ByteStream, _ tcp: DuplexTCPConnection, nativeFirst: Bool,
    options: DuplexBridgeOptions) throws {
    self.options = options
    deadline = ContinuousClock.now.advanced(by: options.deadline)
    let token = V4DuplexBridgeToken()
    self.token = token
    do {
      let prepared = try V4NativeByteStream.prepareNativeBridge(stream, tcp.owner,
        token: token, chunkBytes: options.chunkBytes)
      if nativeFirst { self.a = tcp.owner; self.b = prepared.0 }
      else { self.a = prepared.0; self.b = tcp.owner }
      environment = prepared.0.bridgeEnvironment
      runtimeStorage = prepared.1; resultStorage = prepared.2; executionTail = prepared.3
      directions[0].destinationKind = nativeFirst ? .flowersecStream : .nativeTCP
      directions[1].destinationKind = nativeFirst ? .nativeTCP : .flowersecStream
    } catch let error as DuplexBridgeFailure { throw error }
    catch { throw DuplexBridgeFailure.resourceExhausted }
    coordinator = Task.detached { [self] in await run() }
  }

  func start() throws {
    try gate.withLock {
      guard !started else { return }
      guard firstFailure == nil, !sealed else { throw firstFailure ?? .aborted }
      try runtimeStorage?.check()
      if let deadline, ContinuousClock.now >= deadline {
        fail(.deadlineExceeded, underlying: nil, direction: nil)
        throw DuplexBridgeFailure.deadlineExceeded
      }
      started = true
    }
  }
  func abort() {
    gate.withLock {
      guard !finished, firstFailure == nil else { return }
      fail(.aborted, underlying: nil, direction: nil)
      started = true
    }
  }
  private func checkAdmission(_ direction: Int, reading: Bool) throws {
    try runtimeStorage?.check()
    guard !sealed else { throw firstFailure ?? .aborted }
    if let deadline, ContinuousClock.now >= deadline {
      fail(.deadlineExceeded, underlying: nil, direction: nil)
      throw DuplexBridgeFailure.deadlineExceeded
    }
    if reading {
      guard directions[direction].tail.isEmpty,
        directions[direction].sourceRead <= UInt64.max - UInt64(options.chunkBytes)
      else { throw DuplexBridgeFailure.resourceExhausted }
    }
  }
  private func received(_ bytes: Data, direction: Int) {
    // Called inside the original consume gate immediately after ring.consume.
    gate.withLock {
      let value = directions[direction]
      value.sourceRead += UInt64(bytes.count)
      value.tail = bytes
    }
  }
  private func accepted(_ count: Int, direction: Int) {
    // Called synchronously by the original publication owner at acceptance.
    gate.withLock {
      let value = directions[direction]
      value.accepted += UInt64(count)
      value.tail = count == value.tail.count ? Data() : value.tail.subdata(in: count..<value.tail.count)
    }
  }

  private func run() async {
    // The prepaid coordinator owns the prepared period as well as active I/O.
    // Start never resets the original absolute deadline or creates another task.
    while true {
      let ready = gate.withLock { () -> Bool in
        if !sealed {
          do { try runtimeStorage?.check() }
          catch { fail(.ownerUnavailable, underlying: nil, direction: nil) }
          if let deadline, ContinuousClock.now >= deadline {
            fail(.deadlineExceeded, underlying: nil, direction: nil)
          }
        }
        return started || sealed
      }
      if ready { break }
      try? await ContinuousClock().sleep(for: .milliseconds(10))
    }
    gate.withLock {
      if sealed { directions.forEach { $0.exited = true } }
      else {
        aPump = Task.detached { [self] in await pump(0) }
        bPump = Task.detached { [self] in await pump(1) }
      }
    }
    // Monitoring runs while both independent pumps are active. Each pump
    // reports an actual failure immediately, rather than after a sibling join.
    await monitorCleanup()
    let pumps = gate.withLock { (aPump, bPump) }
    await pumps.0?.value; await pumps.1?.value
    gate.withLock {
      pumpsJoined = true
      aPump = nil; bPump = nil
      if !cleanupIncomplete { finishPhysicalCleanup() } else { coordinator = nil }
    }
  }

  private func pump(_ direction: Int) async {
    let endpoints = gate.withLock { direction == 0 ? (a, b) : (b, a) }
    guard let source = endpoints.0, let destination = endpoints.1 else { return }
    var stage: DuplexBridgeFailure = .readFailed
    defer { gate.withLock { directions[direction].exited = true } }
    do {
      while true {
        stage = .readFailed
        let chunk = try await source.bridgeRead(token: token, maxBytes: options.chunkBytes,
          beforeRead: { [self] in try checkAdmission(direction, reading: true) },
          delivered: { [self] bytes in received(bytes, direction: direction) })
        if chunk == nil {
          gate.withLock { directions[direction].sourceStatus = .eof }
          break
        }
        stage = .writeFailed
        while true {
          let input = try gate.withLock { () throws -> Data in
            try checkAdmission(direction, reading: false)
            return directions[direction].tail
          }
          if input.isEmpty { break }
          let count = try await destination.bridgeWrite(token: token, input,
            beforeAccept: { [self] in try checkAdmission(direction, reading: false) },
            accepted: { [self] count in accepted(count, direction: direction) })
          guard count > 0, count <= input.count else { throw DuplexBridgeFailure.writeFailed }
        }
      }
      stage = .finishFailed
      try gate.withLock { try checkAdmission(direction, reading: false) }
      try await destination.bridgeCloseWrite(token: token,
        beforeFinish: { [self] in try checkAdmission(direction, reading: false) })
      gate.withLock { directions[direction].closeWriteCompleted = true }
      // One EOF half-closes only its destination. Both pumps continue until
      // their own EOF before either authenticated Finish is awaited.
      while try gate.withLock({ () throws -> Bool in
        try checkAdmission(direction, reading: false)
        return !directions.allSatisfy { $0.closeWriteCompleted }
      }) {
        try await ContinuousClock().sleep(for: .milliseconds(10))
      }
      try await destination.bridgeFinish(token: token,
        beforeFinish: { [self] in try checkAdmission(direction, reading: false) })
      gate.withLock {
        if destination.bridgeKind == .flowersecStream { directions[direction].sendDrained = true }
        else { directions[direction].nativeSendFinished = true }
      }
    } catch {
      gate.withLock {
        let cause = (error as? DuplexBridgeFailure) ?? stage
        if directions[direction].failure == nil {
          directions[direction].failure = sealed ? .aborted : cause
          directions[direction].sessionError = error as? SessionError
          directions[direction].nativeError = error as? DuplexTCPError
          if directions[direction].sourceStatus != .eof {
            directions[direction].sourceStatus = sealed ? .aborted : .failed
          }
        }
        fail(cause, underlying: error as? SessionError, direction: direction, native: error as? DuplexTCPError)
      }
    }
  }

  private func fail(_ cause: DuplexBridgeFailure, underlying: SessionError?, direction: Int?, native: DuplexTCPError? = nil) {
    guard !sealed else { return }
    firstFailure = cause; firstSessionError = underlying; firstNativeError = native; sealed = true
    cleanupDeadline = ContinuousClock.now.advanced(by: options.cleanupTimeout)
    // This gate is also the read-consume/write-accept gate. Once sealed there
    // can be no new input consumption or acceptance in either direction.
    for (index, value) in directions.enumerated() {
      if value.sourceStatus == .reading { value.sourceStatus = index == direction ? .failed : .aborted }
    }
    a?.bridgeReset(token: token); b?.bridgeReset(token: token)
    aPump?.cancel(); bPump?.cancel()
  }

  private func monitorCleanup() async {
    while true {
      let done = gate.withLock { () -> Bool in
        let now = ContinuousClock.now
        if !sealed, let deadline, now >= deadline,
          !directions.allSatisfy({ $0.sendFinished }) {
          fail(.deadlineExceeded, underlying: nil, direction: nil)
        }
        let exited = directions.allSatisfy { $0.exited }
        if exited, cleanupDeadline == nil { cleanupDeadline = now.advanced(by: options.cleanupTimeout) }
        let retired = exited && a?.bridgeCleanupComplete(token: token) == true && b?.bridgeCleanupComplete(token: token) == true
        if retired { return true }
        if let cleanupDeadline, now >= cleanupDeadline {
          cleanupIncomplete = true
          publish(cleanup: CleanupStatus(cleanupIncomplete: true,
            pendingCallbacks: UInt64(directions.filter { !$0.exited }.count)))
          finished = true
          return true
        }
        return false
      }
      if done { return }
      // The monitor is an owned, prepaid task. A public wait never cancels it.
      try? await ContinuousClock().sleep(for: .milliseconds(10))
    }
  }

  private func finishPhysicalCleanup() {
    // Both pump tasks have been joined, and the Session owners have confirmed
    // stream retirement. Clearing these aliases is the physical release point.
    aPump = nil; bPump = nil; coordinator = nil
    a = nil; b = nil
    executionTail?.release(); executionTail = nil; runtimeStorage = nil
    finished = true; sealed = true
    publish(cleanup: CleanupStatus(complete: true))
    directions.forEach { $0.tail = Data() }
    resultStorage = nil
  }

  private func publish(cleanup: CleanupStatus) {
    guard result == nil, let storage = resultStorage else { return }
    func direction(_ value: V4DuplexBridgeDirection) -> DuplexBridgeDirectionResult {
      value.publishedTailBytes = UInt64(value.tail.count)
      return DuplexBridgeDirectionResult(progress: DuplexTransferProgress(sourceReadBytes: value.sourceRead,
        destinationAcceptedBytes: value.accepted,
        unacceptedTail: DuplexBridgeTail(value.tail, storage: storage)),
        sourceStatus: value.sourceStatus, sendDrained: value.sendDrained,
        destinationKind: value.destinationKind, nativeSendFinished: value.nativeSendFinished,
        failure: value.failure, sessionError: value.sessionError, nativeError: value.nativeError)
    }
    result = DuplexBridgeResult(aToB: direction(directions[0]), bToA: direction(directions[1]),
      outcome: outcome(), cleanup: cleanup, failure: firstFailure, sessionError: firstSessionError, nativeError: firstNativeError)
  }
  private func outcome() -> DuplexBridgeOutcome {
    if let firstFailure { return firstFailure == .aborted || firstFailure == .deadlineExceeded ? .aborted : .failed }
    return directions.allSatisfy { $0.sendFinished } ? .normal : started ? .running : .notStarted
  }
  func cleanupStatus() -> CleanupStatus {
    gate.withLock {
      if cleanupIncomplete, pumpsJoined,
        a?.bridgeCleanupComplete(token: token) == true, b?.bridgeCleanupComplete(token: token) == true {
        cleanupIncomplete = false
        finishPhysicalCleanup()
      }
      if finished { return cleanupIncomplete ? CleanupStatus(cleanupIncomplete: true,
        pendingCallbacks: UInt64(directions.filter { !$0.exited }.count)) : CleanupStatus(complete: true) }
      return CleanupStatus(cleanupIncomplete: cleanupDeadline.map { ContinuousClock.now >= $0 } ?? false,
        pendingCallbacks: UInt64(started ? directions.filter { !$0.exited }.count : 0))
    }
  }
  func progress() -> DuplexBridgeProgress {
    gate.withLock { DuplexBridgeProgress(aToB: directions[0].snapshot(), bToA: directions[1].snapshot(),
      outcome: outcome(), failure: firstFailure, cleanupStatus: cleanupStatus()) }
  }
  func wait() async throws -> DuplexBridgeResult {
    if let value = gate.withLock({ result }) { return value }
    let waitingStorage = try gate.withLock { () throws -> V4CryptoReservation? in
      guard !waiter else { throw DuplexBridgeWaitError(failure: .waitInProgress, progress: progress()) }
      waiter = true
      return runtimeStorage
    }
    defer { withExtendedLifetime(waitingStorage) {}; gate.withLock { waiter = false } }
    do {
      while true {
        try Task.checkCancellation()
        if let value = gate.withLock({ result }) { return value }
        try await ContinuousClock().sleep(for: .milliseconds(10))
      }
    } catch is CancellationError {
      throw DuplexBridgeWaitError(failure: .waitCanceled, progress: progress())
    }
  }
  deinit {
    a?.bridgeReset(token: token); b?.bridgeReset(token: token)
    executionTail?.release()
  }
}
#endif
