#if os(macOS) || os(iOS)
import Foundation

// One original physical join and one observer are prepaid at construction.
// Timing out or canceling an observer never cancels the physical join.
final class V4CleanupJoin: @unchecked Sendable {
  private final class Waiter: @unchecked Sendable {
    var continuation: CheckedContinuation<Void, Error>?
    var timer: Task<Void, Never>?
    var canceled = false
  }
  private let gate: NSRecursiveLock
  private let timeout: Duration
  private let diagnosticCounters: V4DiagnosticCounters
  private var timeoutRecorded = false
  private var storage: V4CryptoReservation?
  private var physicalTail: V4ResourceReference?
  private var observerTail: V4ResourceReference?
  private var deadline: ContinuousClock.Instant?
  private var physicalStarted = false
  private var physicalFinished = false
  private var waiter: Waiter?
  private var physicalTask: Task<Void, Never>?

  init(environment: V4EnvironmentFoundation) throws {
    gate = environment.gate
    timeout = environment.cleanupTimeout
    diagnosticCounters = environment.root.diagnosticCounters
    let original = try environment.cleanupJoinStorage()
    let physical = try original.executionTail()
    let observer: V4ResourceReference
    do { observer = try original.executionTail() }
    catch { physical.release(); original.release(); throw error }
    storage = original; physicalTail = physical; observerTail = observer
  }

  func beginClose() {
    gate.withLock {
      if deadline == nil {
        deadline = ContinuousClock.now.advanced(by: timeout)
        storage?.seal()
      }
    }
  }

  func status(_ original: CleanupStatus) -> CleanupStatus {
    gate.withLock {
      if original.complete && !physicalStarted {
        physicalFinished = true
        storage?.seal()
        physicalTail?.release(); physicalTail = nil
        observerTail?.release(); observerTail = nil
        storage = nil
      }
      let observing: UInt64 = waiter == nil ? 0 : 1
      let joining: UInt64 = physicalStarted && !physicalFinished ? 1 : 0
      let pending = original.pendingCallbacks + observing + joining
      let complete = original.complete && pending == 0
      let timedOut = !complete && (deadline.map { ContinuousClock.now >= $0 } ?? false)
      if timedOut && !timeoutRecorded { timeoutRecorded = true; diagnosticCounters.increment(.cleanupTimeouts) }
      return CleanupStatus(complete: complete,
        cleanupIncomplete: timedOut,
        pendingCallbacks: pending)
    }
  }

  /// Starts the one prepaid physical join independently of the bounded public
  /// observer. All internal cleanup owners await this same task, so they cannot
  /// consume additional slots in the owner's physical completion events.
  private func startPhysicalJoin(operation: @escaping @Sendable () async -> Void) -> Task<Void, Never>? {
    gate.withLock {
      if physicalFinished { return nil }
      if !physicalStarted {
        physicalStarted = true
        physicalTask = Task { [self] in
          await operation()
          let completed = gate.withLock { () -> CheckedContinuation<Void, Error>? in
            physicalTail?.release(); physicalTail = nil
            var completed: CheckedContinuation<Void, Error>?
            if let current = waiter {
              waiter = nil
              current.timer?.cancel(); current.timer = nil
              completed = current.continuation
              current.continuation = nil
            }
            observerTail?.release(); observerTail = nil
            storage = nil
            physicalFinished = true
            physicalTask = nil
            return completed
          }
          completed?.resume()
        }
      }
      return physicalTask
    }
  }

  /// An independent physical observer neither claims nor cancels the single
  /// public waitCleanup continuation. The task itself owns all physical tails.
  func waitPhysicalCompletion(operation: @escaping @Sendable () async -> Void) async {
    let task = startPhysicalJoin(operation: operation)
    await task?.value
  }

  func wait(operation: @escaping @Sendable () async -> Void) async throws {
    let token = Waiter()
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        gate.withLock {
          if token.canceled { continuation.resume(throwing: CancellationError()); return }
          guard let deadline else { continuation.resume(throwing: V4ResourceFailure.closed); return }
          if physicalFinished { continuation.resume(); return }
          guard waiter == nil else { continuation.resume(throwing: V4ResourceFailure.capacity); return }
          _ = startPhysicalJoin(operation: operation)
          if ContinuousClock.now >= deadline { continuation.resume(); return }
          waiter = token
          token.continuation = continuation
          token.timer = Task { [self, token] in
            do { try await ContinuousClock().sleep(until: deadline) } catch {}
            gate.withLock {
              guard waiter === token else { return }
              waiter = nil; token.timer = nil
              if physicalFinished {
                observerTail?.release(); observerTail = nil; storage = nil
              }
              let completed = token.continuation
              token.continuation = nil
              completed?.resume()
            }
          }
        }
      }
    } onCancel: {
      gate.withLock {
        token.canceled = true
        let continuation = token.continuation
        token.continuation = nil
        token.timer?.cancel()
        continuation?.resume(throwing: CancellationError())
      }
    }
  }

  deinit {
    storage?.seal()
    physicalTail?.release()
    observerTail?.release()
  }
}
#endif
