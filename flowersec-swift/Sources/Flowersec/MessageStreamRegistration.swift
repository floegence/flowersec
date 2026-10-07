import Foundation

// The existing kind registry owns this gate. It never calls the Session while
// closing, so a Session acceptance gate can safely acquire it for the original
// pending OPEN's one commit. Accepted captures survive registration close.
final class V4MessageRegistrationLifetime: @unchecked Sendable {
  private let gate = NSRecursiveLock()
  private var closed = false
  private var pendingAndAccepted: [String: Int] = [:]
  func check() throws {
    try gate.withLock { guard !closed else { throw HandlerRegistrationError.frozen } }
  }
  func capture(kind: String = "", maximum: Int = 128) throws -> V4MessageRegistrationCapture {
    try gate.withLock {
      try check()
      guard maximum > 0, pendingAndAccepted[kind, default: 0] < maximum else {
        throw SessionError.resourceExhausted
      }
      pendingAndAccepted[kind, default: 0] += 1
      return V4MessageRegistrationCapture(lifetime: self, kind: kind)
    }
  }
  fileprivate func release(kind: String) {
    gate.withLock {
      let count = pendingAndAccepted[kind, default: 0]
      if count <= 1 { pendingAndAccepted.removeValue(forKey: kind) }
      else { pendingAndAccepted[kind] = count - 1 }
    }
  }
  func commit<Value>(_ capture: V4MessageRegistrationCapture, operation: () throws -> Value?) throws -> Value? {
    try gate.withLock {
      try check()
      guard capture.lifetime === self, !capture.accepted else { throw ServiceFailure.contractMismatch }
      let value = try operation()
      if value != nil { capture.accepted = true }
      return value
    }
  }
  func close() { gate.withLock { closed = true } }
}

final class V4MessageRegistrationCapture: @unchecked Sendable {
  let lifetime: V4MessageRegistrationLifetime
  fileprivate var accepted = false
  private let kind: String
  init(lifetime: V4MessageRegistrationLifetime, kind: String) {
    self.lifetime = lifetime; self.kind = kind
  }
  deinit { lifetime.release(kind: kind) }
  func commit<Value>(_ operation: () throws -> Value?) throws -> Value? {
    try lifetime.commit(self, operation: operation)
  }
}

// A bounded waiter detaches from an ordinary authorization callback at the
// original pending OPEN deadline. The real callback remains the group's work
// owner until it actually exits; neither its result nor a canceled timer can
// revive the pending acceptance gate.
final class V4MessageOpenAuthorization: @unchecked Sendable {
  private let gate: NSRecursiveLock
  private let group: V4ApplicationGroup
  private let deadline: ContinuousClock.Instant
  private var continuation: CheckedContinuation<Bool, Error>?
  private var callback: Task<Void, Never>?
  private var timer: Task<Void, Never>?
  private var started = false
  private var stopped = false
  private var canceled = false
  private var reference: V4ResourceReference?
  private var workers = 0
  init(group: V4ApplicationGroup, deadline: ContinuousClock.Instant, reference: V4ResourceReference) {
    self.group = group; gate = group.executor.gate; self.deadline = deadline
    self.reference = reference
  }

  func authorize(
    metadata: StreamMetadata,
    registration: V4MessageStreamRegistration
  ) async throws -> Bool {
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        let admitted = gate.withLock { () -> Bool in
          guard !started, !stopped else { continuation.resume(throwing: SessionError.closed); return false }
          if canceled || Task.isCancelled { continuation.resume(throwing: SessionError.canceled); return false }
          guard ContinuousClock.now < deadline else { continuation.resume(returning: false); return false }
          started = true
          workers = 2
          self.continuation = continuation
          return true
        }
        guard admitted else { return }
        let callback = Task.detached { [self, registration, metadata] in
          defer { workerExited() }
          let authorized: Bool
          do {
            authorized = try await group.invoke { [weak self, registration, metadata, deadline] context in
              try context.checkCancellation()
              guard self?.canEnter() == true, ContinuousClock.now < deadline else {
                throw SessionError.timeout
              }
              try registration.lifetime.check()
              do { try await registration.authorize(metadata, context); return true }
              catch { return false }
            }
          } catch { authorized = false }
          finish(authorized)
          gate.withLock { self.callback = nil }
        }
        let timer = Task.detached { [self] in
          defer { workerExited() }
          do { try await ContinuousClock().sleep(until: deadline); finish(false) }
          catch { }
          gate.withLock { self.timer = nil }
        }
        gate.withLock {
          if stopped { callback.cancel(); timer.cancel() }
          else { self.callback = callback; self.timer = timer }
        }
      }
    } onCancel: {
      self.gate.withLock {
        self.canceled = true
        guard !self.stopped else { return }
        self.stopped = true
        let waiting = self.continuation
        self.continuation = nil
        self.callback?.cancel()
        self.timer?.cancel()
        waiting?.resume(throwing: SessionError.canceled)
      }
    }
  }

  private func canEnter() -> Bool {
    gate.withLock { !stopped && ContinuousClock.now < deadline }
  }

  private func workerExited() {
    gate.withLock {
      workers -= 1
      if workers == 0 { reference?.release(); reference = nil }
    }
  }

  deinit { reference?.release() }

  private func finish(_ result: Bool) {
    gate.withLock {
      guard !stopped else { return }
      stopped = true
      let waiting = continuation
      continuation = nil
      callback?.cancel()
      timer?.cancel()
      waiting?.resume(returning: result && ContinuousClock.now < deadline)
    }
  }
}
