import Foundation

public enum TransportDiagnosticState: String, Codable, Sendable { case started, succeeded, failed, closed, other }
public enum TransportDiagnosticPhase: String, Codable, Sendable { case connection, application, rekey, cleanup, other }
public enum TransportDiagnosticCode: String, Codable, Sendable {
  case none, canceled, closed, expired, unsupported
  case invalidMaterial = "invalid_material", securityFailed = "security_failed", connectionFailed = "connection_failed"
  case resourceExhausted = "resource_exhausted", operationFailed = "operation_failed", other
}
public enum TransportDiagnosticRetry: String, Codable, Sendable { case none, terminal, retryable }
public enum TransportDiagnosticAttemptBucket: String, Codable, Sendable { case one = "1", twoToThree = "2-3", fourToSeven = "4-7", eightOrMore = "8+" }
public enum TransportDiagnosticDurationBucket: String, Codable, Sendable {
  case under10ms = "<10ms", under100ms = "10-99ms", under1s = "100-999ms", under10s = "1-9s", atLeast10s = ">=10s"
}

func v4TransportDiagnosticCode(_ error: any Error) -> TransportDiagnosticCode {
  error is CancellationError ? .canceled :
    (error as? ServiceFailure) == .closed ? .closed :
    (error as? ServiceFailure) == .deadlineExceeded ? .expired :
    (error as? ServiceFailure) == .resourceExhausted ? .resourceExhausted : .operationFailed
}

/// The complete public event whitelist. Correlation bytes are random and expire
/// with the sink's UTC bucket; they are never aggregate counter labels.
public struct TransportDiagnosticEvent: Encodable, Equatable, Sendable {
  public let state: TransportDiagnosticState
  public let attemptBucket: TransportDiagnosticAttemptBucket
  public let phase: TransportDiagnosticPhase
  public let code: TransportDiagnosticCode
  public let retryDisposition: TransportDiagnosticRetry
  public let durationBucket: TransportDiagnosticDurationBucket
  public let correlationID: Data
  enum CodingKeys: String, CodingKey {
    case state, phase, code
    case attemptBucket = "attempt_bucket", retryDisposition = "retry_disposition"
    case durationBucket = "duration_bucket", correlationID = "correlation_id"
  }
}

public enum TransportDiagnosticCounter: String, CaseIterable, Sendable {
  case connectionAttempts = "connection_attempts", connectionFailures = "connection_failures"
  case identityRefusals = "identity_refusals", tlsRefusals = "tls_refusals"
  case spendUnknown = "spend_unknown", storeFailures = "store_failures"
  case reservationConflicts = "reservation_conflicts", resourceRefusals = "resource_refusals"
  case slowConsumers = "slow_consumers", rekeyStarted = "rekey_started", rekeySucceeded = "rekey_succeeded"
  case rekeyRequestTimeout = "rekey_request_timeout", rekeyInitTimeout = "rekey_init_timeout"
  case rekeyReplyTimeout = "rekey_reply_timeout", rekeyCommitTimeout = "rekey_commit_timeout"
  case rekeyAckTimeout = "rekey_ack_timeout", datagramDropped = "datagram_dropped", oldDatagramDropped = "old_datagram_dropped"
  case diagnosticDropped = "diagnostic_dropped", cleanupTimeouts = "cleanup_timeouts"
}

final class V4DiagnosticCounters: @unchecked Sendable {
  private let gate = NSLock()
  private var values = Array(repeating: UInt64(0), count: TransportDiagnosticCounter.allCases.count)
  func increment(_ counter: TransportDiagnosticCounter, by amount: UInt64 = 1) {
    gate.withLock {
      guard let index = TransportDiagnosticCounter.allCases.firstIndex(of: counter) else { return }
      let (next, overflow) = values[index].addingReportingOverflow(amount)
      values[index] = overflow ? .max : next
    }
  }
  func snapshot() -> [TransportDiagnosticCounter: UInt64] {
    gate.withLock { Dictionary(uniqueKeysWithValues: zip(TransportDiagnosticCounter.allCases, values)) }
  }
}

/// Detailed events are disabled unless this configuration is installed. The
/// callback owns any external copies and their independently declared retention.
public struct TransportDiagnosticSinkConfiguration: Sendable {
  public var samplingPartsPerMillion: UInt32
  public let receive: @Sendable (TransportDiagnosticEvent) async -> Void
  public init(samplingPartsPerMillion: UInt32 = 10_000,
    receive: @escaping @Sendable (TransportDiagnosticEvent) async -> Void) {
    self.samplingPartsPerMillion = samplingPartsPerMillion; self.receive = receive
  }
}

#if os(macOS) || os(iOS)
final class V4DiagnosticContext: @unchecked Sendable {
  private weak var sink: V4DiagnosticSink?
  private let gate = NSLock()
  private var began = false, ended = false, closed = false
  let started = ContinuousClock.now
  let phase: TransportDiagnosticPhase
  let attempt: TransportDiagnosticAttemptBucket
  var live: Bool { gate.withLock { !closed } }
  init(sink: V4DiagnosticSink, phase: TransportDiagnosticPhase, attempt: UInt64) {
    self.sink = sink; self.phase = phase
    self.attempt = attempt <= 1 ? .one : attempt <= 3 ? .twoToThree : attempt <= 7 ? .fourToSeven : .eightOrMore
  }
  func emit(_ state: TransportDiagnosticState, code: TransportDiagnosticCode = .none,
    retry: TransportDiagnosticRetry = .none) {
    let accepted = gate.withLock { () -> Bool in
      if closed { return false }
      switch state {
      case .started: guard !began else { return false }; began = true
      case .succeeded, .failed: guard !ended else { return false }; ended = true
      case .closed: closed = true
      case .other: break
      }
      return true
    }
    if accepted { sink?.emit(self, state: state, code: code, retry: retry) }
  }
  func failed(_ error: any Error) {
    emit(.failed, code: v4TransportDiagnosticCode(error), retry: .terminal)
  }
}

// One executor diagnostic subpool: a prepaid 4096-slot ring, one callback job,
// and one TTL worker. Callback execution never holds a protocol/resource lock.
final class V4DiagnosticSink: V4NativeConnectionLifecycle, @unchecked Sendable {
  private struct Correlation { weak var owner: V4DiagnosticContext?; var bytes: Data }
  private let gate = NSLock()
  private let events = V4SessionEvents(maximum: 2)
  private let counters: V4DiagnosticCounters
  private let executor: V4DiagnosticExecutor
  private let storage: V4CryptoReservation
  private let workerTail: V4ResourceReference
  private let rotationTail: V4ResourceReference
  private let cleanupTimeout: Duration
  private let sampling: UInt32
  private let random: @Sendable (Int) throws -> Data
  private let utcNow: @Sendable () -> Date
  private var callback: (@Sendable (TransportDiagnosticEvent) async -> Void)?
  private var queue: [TransportDiagnosticEvent?]
  private var correlations: [Correlation?]
  private var head = 0, count = 0
  private var bucketEvents = 0
  private var bucket: Int64 = 0
  private var active = false, closed = false, started = false, workerExited = false, rotationExited = false
  private var storageReleased = false
  private var timeoutRecorded = false
  private var closeDeadline: ContinuousClock.Instant?
  private var worker: Task<Void, Never>?
  private var rotation: Task<Void, Never>?
  init(environment: V4EnvironmentFoundation, configuration: TransportDiagnosticSinkConfiguration,
    random: @escaping @Sendable (Int) throws -> Data = { try V4Crypto.random($0) },
    utcNow: @escaping @Sendable () -> Date = { Date() }) throws {
    guard configuration.samplingPartsPerMillion <= 10_000 else { throw V4ResourceFailure.configuration }
    counters = environment.root.diagnosticCounters; sampling = configuration.samplingPartsPerMillion
    executor = environment.root.diagnosticExecutor()
    cleanupTimeout = environment.cleanupTimeout; callback = configuration.receive
    self.random = random; self.utcNow = utcNow
    let reservation = try environment.diagnosticSinkStorage()
    let delivery = try reservation.executionTail()
    let ttl: V4ResourceReference
    do { ttl = try reservation.executionTail() }
    catch { delivery.release(); reservation.release(); throw error }
    storage = reservation; workerTail = delivery; rotationTail = ttl
    queue = [TransportDiagnosticEvent?](repeating: nil, count: 4096)
    correlations = [Correlation?](repeating: nil, count: 1024)
    bucket = Int64(floor(utcNow().timeIntervalSince1970 / 900))
  }
  func start() {
    gate.withLock {
      guard !started, !closed else { return }
      started = true
      worker = executor.launch { [self] in await deliver(); finishWorker(rotation: false) }
      rotation = executor.launch { [self] in
        while !Task.isCancelled {
          let nextBoundary = (Double(utcBucket()) + 1) * 900
          let delay = max(0.001, min(1, nextBoundary - utcNow().timeIntervalSince1970))
          do { try await ContinuousClock().sleep(for: .seconds(delay)) } catch { break }
          gate.withLock { if !closed { rotateLocked() } }
        }
        finishWorker(rotation: true)
      }
    }
  }
  func context(phase: TransportDiagnosticPhase, attempt: UInt64 = 1) -> V4DiagnosticContext {
    V4DiagnosticContext(sink: self, phase: phase, attempt: attempt)
  }
  private func utcBucket() -> Int64 { Int64(floor(utcNow().timeIntervalSince1970 / 900)) }
  private func rotateLocked() {
    let now = utcBucket()
    guard bucket != now else { return }
    bucket = now
    counters.increment(.diagnosticDropped, by: UInt64(count))
    for index in queue.indices { queue[index] = nil }
    head = 0; count = 0; bucketEvents = 0
    for index in correlations.indices {
      guard let owner = correlations[index]?.owner, owner.live, let id = try? random(16), id.count == 16 else {
        correlations[index] = nil; continue
      }
      correlations[index] = Correlation(owner: owner, bytes: id)
    }
  }
  private func sampled() -> Bool {
    guard sampling > 0, let bytes = try? random(8), bytes.count == 8 else { return false }
    // Round the uniform 64-bit threshold down, so sampling never exceeds
    // the configured rate and requires only one bounded CSPRNG draw.
    let value = V4Crypto.number(bytes)
    return value < (UInt64.max / 1_000_000) * UInt64(sampling)
  }
  func emit(_ context: V4DiagnosticContext, state: TransportDiagnosticState,
    code: TransportDiagnosticCode, retry: TransportDiagnosticRetry) {
    guard sampled() else { return }
    gate.withLock {
      guard !closed else { return }
      rotateLocked()
      guard bucketEvents < 4096, count + (active ? 1 : 0) < 4096 else { counters.increment(.diagnosticDropped); return }
      var selected = correlations.firstIndex { $0?.owner === context }
      if selected == nil {
        guard let index = correlations.firstIndex(where: { $0 == nil }), let id = try? random(16), id.count == 16 else {
          counters.increment(.diagnosticDropped); return
        }
        correlations[index] = Correlation(owner: context, bytes: id); selected = index
      }
      guard let selected, let id = correlations[selected]?.bytes else { return }
      let elapsed = context.started.duration(to: ContinuousClock.now)
      let duration: TransportDiagnosticDurationBucket = elapsed < .milliseconds(10) ? .under10ms :
        elapsed < .milliseconds(100) ? .under100ms : elapsed < .seconds(1) ? .under1s :
        elapsed < .seconds(10) ? .under10s : .atLeast10s
      let event = TransportDiagnosticEvent(state: state, attemptBucket: context.attempt, phase: context.phase,
        code: code, retryDisposition: retry, durationBucket: duration, correlationID: id)
      guard let encoded = try? JSONEncoder().encode(event), encoded.count <= 512 else {
        counters.increment(.diagnosticDropped); return
      }
      queue[(head + count) % queue.count] = event; count += 1; bucketEvents += 1
    }
    events.signal()
  }
  private func deliver() async {
    while true {
      let revision = events.revision
      let next = gate.withLock { () -> (TransportDiagnosticEvent, @Sendable (TransportDiagnosticEvent) async -> Void)? in
        guard !closed, let callback else { return nil }
        rotateLocked()
        guard count > 0, let event = queue[head] else { return nil }
        // Move the same prepaid slot from queue custody to callback custody.
        queue[head] = nil; head = (head + 1) % queue.count; count -= 1; active = true
        return (event, callback)
      }
      if let (event, callback) = next {
        await callback(event)
        gate.withLock { active = false }
      } else {
        if gate.withLock({ closed }) { return }
        try? await events.wait(after: revision)
      }
    }
  }
  func close() {
    let unstarted = gate.withLock { () -> Bool? in
      guard !closed else { return nil }
      closed = true; closeDeadline = ContinuousClock.now.advanced(by: cleanupTimeout); callback = nil
      counters.increment(.diagnosticDropped, by: UInt64(count))
      queue = []; correlations = []
      count = 0; head = 0
      worker?.cancel(); rotation?.cancel()
      return !started
    }
    if let unstarted {
      storage.seal()
      if unstarted { finishWorker(rotation: false); finishWorker(rotation: true) }
    }
    events.signal()
  }
  private func finishWorker(rotation: Bool) {
    if rotation { rotationTail.release() } else { workerTail.release() }
    let complete = gate.withLock { () -> Bool in
      if rotation { rotationExited = true; self.rotation = nil }
      else { workerExited = true; worker = nil }
      return workerExited && rotationExited
    }
    if complete { storage.release(); gate.withLock { storageReleased = true } }
  }
  func cleanupStatus() -> CleanupStatus {
    gate.withLock {
      let pending = UInt64((workerExited ? 0 : 1) + (rotationExited ? 0 : 1))
      let overdue = closed && !storageReleased && (closeDeadline.map { ContinuousClock.now >= $0 } ?? false)
      if overdue && !timeoutRecorded { counters.increment(.cleanupTimeouts); timeoutRecorded = true }
      return CleanupStatus(complete: closed && pending == 0 && storageReleased, cleanupIncomplete: overdue, pendingCallbacks: pending)
    }
  }
  func waitCleanup() async -> CleanupStatus {
    close()
    while true {
      let status = cleanupStatus()
      if status.complete || status.cleanupIncomplete { return status }
      if Task.isCancelled {
        return CleanupStatus(complete: false, cleanupIncomplete: true, pendingCallbacks: status.pendingCallbacks)
      }
      try? await ContinuousClock().sleep(for: .milliseconds(5))
    }
  }
  deinit { close() }
}

public final class TransportDiagnosticSink: Sendable {
  private let original: V4DiagnosticSink
  init(_ original: V4DiagnosticSink) { self.original = original }
  /// Cancels future delivery and requests cancellation of the active callback.
  /// A callback that ignores cancellation retains its original charged slot.
  public func close() async -> CleanupStatus { await original.waitCleanup() }
  public func cleanupStatus() -> CleanupStatus { original.cleanupStatus() }
}

// A root shares this executor independently of ordinary application work,
// Completion and fixed-query workers. Each lane prepays its own two tasks.
final class V4DiagnosticExecutor: @unchecked Sendable {
  private weak var root: V4ResourceRoot?
  init(root: V4ResourceRoot) { self.root = root }
  func makeSink(environment: V4EnvironmentFoundation,
    configuration: TransportDiagnosticSinkConfiguration,
    random: @escaping @Sendable (Int) throws -> Data = { try V4Crypto.random($0) }) throws -> V4DiagnosticSink {
    guard environment.root === root else { throw V4ResourceFailure.owner }
    return try V4DiagnosticSink(environment: environment, configuration: configuration, random: random)
  }
  fileprivate func launch(_ operation: @escaping @Sendable () async -> Void) -> Task<Void, Never> {
    Task.detached(operation: operation)
  }
}
#endif
