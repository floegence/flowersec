import Foundation

public enum ResponsePublicationState: String, Sendable { case notApplicable = "not_applicable", pending, flushed, unknown }
public enum ResponsePublicationCause: String, Sendable {
  case responseSuperseded = "response_superseded", responseAborted = "response_aborted"
  case ownerUnavailable = "owner_unavailable", deadline, publishFailed = "publish_failed"
}
public struct ResponsePublicationStatus: Sendable, Equatable {
  public let state: ResponsePublicationState
  public let cause: ResponsePublicationCause?
}

/// Explicit application maintenance capacity, borrowed from the TransportEnvironment's
/// existing resource hierarchy before restart methods are registered.
public final class ServiceMaintenanceOwner: @unchecked Sendable {
  let environment: V4EnvironmentFoundation
  private let storage: V4CryptoReservation
  public let maximumPublications: Int
  private let gate = NSLock()
  private var active: [UUID: ResponsePublication] = [:]
  private var closed = false
  init(environment: V4EnvironmentFoundation, maximumPublications: Int) throws {
    guard (1...1024).contains(maximumPublications) else { throw ServiceFailure.configurationCapacity }
    self.environment = environment; self.maximumPublications = maximumPublications
    storage = try environment.serviceMaintenanceStorage(maximum: maximumPublications)
    active.reserveCapacity(maximumPublications)
  }
  func check() throws { try gate.withLock { guard !closed else { throw ServiceFailure.closed }; try storage.check() } }
  func reserve(deadlineMS: UInt64) throws -> ResponsePublication {
    try gate.withLock {
      guard !closed, active.count < maximumPublications else { throw ServiceFailure.resourceExhausted }
      try storage.check(); let id = UUID(); let tail = V4ServiceInputTail(try storage.executionTail())
      let publication = ResponsePublication(deadlineMS: deadlineMS, tail: tail, release: { [weak self] in
        guard let self else { return }; gate.withLock { active.removeValue(forKey: id) }
      })
      active[id] = publication; return publication
    }
  }
  public func close() {
    let originals = gate.withLock { () -> [ResponsePublication] in
      guard !closed else { return [] }; closed = true; storage.seal(); return Array(active.values)
    }
    for original in originals { original.fail(.ownerUnavailable) }
  }
  deinit { storage.seal() }
}

/// One original response observation. It does not flush a shared channel or
/// imply peer application receipt. Canceling wait() cancels only that wait.
public final class ResponsePublication: @unchecked Sendable {
  private let gate = NSLock()
  private var status: ResponsePublicationStatus
  private let deadlineMS: UInt64
  private var started: ContinuousClock.Instant?
  private var timer: Task<Void, Never>?
  private var exitAction: (@Sendable () -> Void)?
  private var tail: V4ServiceInputTail?
  private var release: (@Sendable () -> Void)?
  private var expected = 0
  private var handedOff = 0
  private var pendingCallbacks = 0
  private var productionExited = false
  private var waiters: [UUID: CheckedContinuation<ResponsePublicationStatus, any Error>] = [:]
  static let notApplicable = ResponsePublication()
  private init() {
    status = ResponsePublicationStatus(state: .notApplicable, cause: nil); deadlineMS = 0; productionExited = true
  }
  init(deadlineMS: UInt64, tail: V4ServiceInputTail, release: @escaping @Sendable () -> Void) {
    status = ResponsePublicationStatus(state: .pending, cause: nil); self.deadlineMS = deadlineMS; self.tail = tail; self.release = release
    waiters.reserveCapacity(8)
  }
  public func state() -> ResponsePublicationStatus { gate.withLock { status } }
  public func wait() async throws -> ResponsePublicationStatus {
    let id = UUID()
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        let immediate: Result<ResponsePublicationStatus, any Error>? = gate.withLock {
          if Task.isCancelled { return .failure(CancellationError()) }
          if status.state != .pending { return .success(status) }
          guard waiters.count < 8 else { return .failure(ServiceFailure.resourceExhausted) }
          waiters[id] = continuation; return nil
        }
        if let immediate { continuation.resume(with: immediate) }
      }
    } onCancel: {
      let waiting = self.gate.withLock { self.waiters.removeValue(forKey: id) }
      waiting?.resume(throwing: CancellationError())
    }
  }
  func begin(bytes: Int, deadlineAction: @escaping @Sendable () -> Void) throws {
    try gate.withLock {
      guard status.state == .pending, started == nil, bytes > 0 else { throw ServiceFailure.closed }
      expected = bytes; let start = ContinuousClock.now; started = start; exitAction = deadlineAction
      timer = Task { [self] in
        do { try await ContinuousClock().sleep(until: start.advanced(by: .milliseconds(Int64(clamping: deadlineMS)))) }
        catch { return }
        fail(.deadline)
      }
    }
  }
  func checkPending() throws { try gate.withLock { guard status.state == .pending else { throw ServiceFailure.closed } } }
  func checkPublicationProgress() throws {
    try gate.withLock { guard status.state == .pending || status.cause == .responseAborted else { throw ServiceFailure.closed } }
  }
  func ticket() throws -> V4ResponseHandoffTicket {
    try gate.withLock {
      guard (status.state == .pending || status.cause == .responseAborted), started != nil, pendingCallbacks == 0 else { throw ServiceFailure.closed }
      pendingCallbacks += 1; return V4ResponseHandoffTicket(self)
    }
  }
  fileprivate func handoff(bytes: Int, success: Bool) {
    let deliveries = gate.withLock { () -> [CheckedContinuation<ResponsePublicationStatus, any Error>] in
      pendingCallbacks -= 1
      if status.state == .pending {
        if !success || bytes <= 0 || bytes > expected - handedOff { status = ResponsePublicationStatus(state: .unknown, cause: .publishFailed) }
        else { handedOff += bytes }
      }
      return settle()
    }
    deliver(deliveries); collect()
  }
  func finishProduction() {
    let deliveries = gate.withLock { productionExited = true; return settle() }
    deliver(deliveries); collect()
  }
  func abandon(_ cause: ResponsePublicationCause) { fail(cause); finishProduction() }
  @discardableResult func fail(_ cause: ResponsePublicationCause) -> Bool {
    let result = gate.withLock { () -> (Bool, [CheckedContinuation<ResponsePublicationStatus, any Error>], (@Sendable () -> Void)?) in
      let changed = status.state == .pending
      if changed { status = ResponsePublicationStatus(state: .unknown, cause: cause) }
      let wake = changed && (cause == .deadline || cause == .ownerUnavailable) ? exitAction : nil
      return (changed, settle(), wake)
    }
    deliver(result.1); result.2?(); collect(); return result.0
  }
  private func settle() -> [CheckedContinuation<ResponsePublicationStatus, any Error>] {
    if status.state == .pending, productionExited, pendingCallbacks == 0, handedOff == expected, expected > 0 {
      status = ResponsePublicationStatus(state: .flushed, cause: nil)
    }
    guard status.state != .pending else { return [] }
    timer?.cancel(); timer = nil
    let waiting = Array(waiters.values); waiters.removeAll(keepingCapacity: true); return waiting
  }
  private func deliver(_ waiters: [CheckedContinuation<ResponsePublicationStatus, any Error>]) {
    let result = state(); for waiter in waiters { waiter.resume(returning: result) }
  }
  private func collect() {
    let original = gate.withLock { () -> (@Sendable () -> Void)? in
      guard productionExited, pendingCallbacks == 0, status.state != .pending else { return nil }
      tail = nil; exitAction = nil; let original = release; release = nil; return original
    }
    original?()
  }
}

final class V4ResponseHandoffTicket: @unchecked Sendable {
  private let gate = NSLock()
  private var original: ResponsePublication?
  private var outcome: Bool?
  private var waiting: CheckedContinuation<Bool, Never>?
  init(_ original: ResponsePublication) { self.original = original }
  func completed(bytes: Int, success: Bool) {
    let result = gate.withLock { () -> (ResponsePublication?, CheckedContinuation<Bool, Never>?) in
      guard let owner = original else { return (nil, nil) }
      original = nil; outcome = success; let waiter = waiting; waiting = nil; return (owner, waiter)
    }
    result.0?.handoff(bytes: bytes, success: success); result.1?.resume(returning: success)
  }
  // The original publisher waits for each original callback. This bounds its
  // descriptors to one and retains ownership even when its task is cancelled.
  func wait() async -> Bool {
    await withCheckedContinuation { continuation in
      let immediate = gate.withLock { () -> Bool? in
        if let outcome { return outcome }; waiting = continuation; return nil
      }
      if let immediate { continuation.resume(returning: immediate) }
    }
  }
}

final class V4RPCRecordHandoff: V4RecordPublication, @unchecked Sendable {
  private let gate = NSLock()
  private var finished = false
  private var providerOwns = false
  private let bytes: Int
  private let completion: @Sendable (Int, Bool) -> Void
  init(bytes: Int, completion: @escaping @Sendable (Int, Bool) -> Void) { self.bytes = bytes; self.completion = completion }
  func ticket(epoch: UInt32) {}
  func transferred() { gate.withLock { providerOwns = true } }
  func failedBeforeTransfer() {
    let owned = gate.withLock { providerOwns }
    if !owned { completed(false) }
  }
  func completed(_ success: Bool) {
    let first = gate.withLock { guard !finished else { return false }; finished = true; return true }
    if first { completion(bytes, success) }
  }
}
