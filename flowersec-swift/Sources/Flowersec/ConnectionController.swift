import Foundation

/// Supplies one independently acquired, single-use artifact lease per connection attempt.
///
/// An ``ArtifactLease`` value is intentionally not accepted by ``ConnectionController``.
/// Long-lived connections require a refreshable source because every new session must use a
/// newly acquired artifact and perform a new admission.
public protocol ArtifactSource: Sendable {
  func acquireArtifact() async throws -> ArtifactLease
}

/// The only artifact-source failures that opt into automatic retry.
///
/// Any other error thrown by ``ArtifactSource/acquireArtifact()`` is terminal.
public struct ArtifactSourceFailure: Error, Equatable, Sendable {
  public let disposition: RetryDisposition

  public init(disposition: RetryDisposition) {
    self.disposition = disposition
  }
}

public enum ConnectionState: String, Equatable, Sendable {
  case idle
  case connecting
  case connected
  case waiting
  case failed
  case closed
}

/// A redacted failure from the one operation owned by a connection attempt.
public enum ConnectionAttemptFailure: Error, Equatable, Sendable {
  case artifactSource(ArtifactSourceFailure)
  case unknownArtifactSource
  case connection(ConnectError)
  case session(SessionError)

  public var retryDisposition: RetryDisposition {
    switch self {
    case .artifactSource(let failure):
      return failure.disposition
    case .unknownArtifactSource:
      return .terminal
    case .connection(let error):
      return error.retryDisposition
    case .session(let error):
      return error.retryDisposition
    }
  }
}

public struct ConnectionSnapshot: Sendable {
  public let state: ConnectionState
  public let attempt: UInt64
  public let currentSession: (any Session)?
  public let failure: ConnectionAttemptFailure?
}

public enum ConnectionControllerConfigurationError: Error, Equatable, Sendable {
  case invalidMaximumAttempts
}

/// Owns the complete reconnect lifecycle above the one-shot Flowersec connector.
///
/// Each successful attempt publishes a new, independent ``Session``. Operations and
/// streams from an earlier session are never migrated or replayed into its replacement.
public actor ConnectionController {
  public private(set) var state: ConnectionState = .idle
  public private(set) var attempt: UInt64 = 0
  public private(set) var currentSession: (any Session)?
  public private(set) var failure: ConnectionAttemptFailure?

  private let source: any ArtifactSource
  private let options: ConnectorOptions
  private let maximumAttempts: UInt64?
  private let connectOneShot: @Sendable (ArtifactLease, ConnectorOptions) async throws -> any Session
  private var scheduler: Task<Void, Never>?
  private var inFlightAttempt: Task<any Session, Error>?
  private var retryGate: ConnectionRetryGate?
  private var retryTimer: Task<Void, Never>?
  private var retryNotBefore: RetryNotBefore?
  private var observers: [UUID: AsyncStream<ConnectionSnapshot>.Continuation] = [:]
  private var closeTask: Task<Void, Never>?

  public init(
    source: any ArtifactSource,
    options: ConnectorOptions = ConnectorOptions(),
    maximumAttempts: UInt64? = nil
  ) throws {
    try Self.validate(maximumAttempts: maximumAttempts)
    self.source = source
    self.options = options
    self.maximumAttempts = maximumAttempts
    self.connectOneShot = { lease, options in
      try await connect(lease: lease, options: options)
    }
  }

  init(
    source: any ArtifactSource,
    options: ConnectorOptions = ConnectorOptions(),
    maximumAttempts: UInt64? = nil,
    connectOneShot: @escaping @Sendable (ArtifactLease, ConnectorOptions) async throws -> any Session
  ) throws {
    try Self.validate(maximumAttempts: maximumAttempts)
    self.source = source
    self.options = options
    self.maximumAttempts = maximumAttempts
    self.connectOneShot = connectOneShot
  }

  private static func validate(maximumAttempts: UInt64?) throws {
    if maximumAttempts == 0 {
      throw ConnectionControllerConfigurationError.invalidMaximumAttempts
    }
  }

  /// Starts the single scheduler. Calls outside the idle state have no effect.
  public func start() {
    guard state == .idle, scheduler == nil else { return }
    scheduler = Task { [weak self] in
      await self?.run()
    }
  }

  /// Returns current state immediately and then every controller-owned transition.
  public func updates() -> AsyncStream<ConnectionSnapshot> {
    let observerID = UUID()
    let pair = AsyncStream.makeStream(of: ConnectionSnapshot.self)
    observers[observerID] = pair.continuation
    pair.continuation.yield(snapshot())
    pair.continuation.onTermination = { [weak self] _ in
      Task { await self?.removeObserver(observerID) }
    }
    return pair.stream
  }

  public func snapshot() -> ConnectionSnapshot {
    ConnectionSnapshot(
      state: state,
      attempt: attempt,
      currentSession: currentSession,
      failure: failure
    )
  }

  /// Wakes only the scheduler's current wait. It never starts a second scheduler or attempt.
  /// An explicit ``RetryDisposition/retryAfter(_:)`` deadline remains authoritative.
  public func retryNow() async -> Bool {
    guard state == .waiting, let retryGate else { return false }
    let now = ContinuousClock.now
    if let notBefore = retryNotBefore, notBefore.instant > now { return false }
    retryTimer?.cancel()
    await retryGate.wake()
    return true
  }

  /// Permanently closes this controller and its current one-shot session.
  public func close() async {
    if let closeTask {
      await closeTask.value
      return
    }
    let activeScheduler = scheduler
    let activeAttempt = inFlightAttempt
    let activeGate = retryGate
    let activeSession = currentSession

    state = .closed
    currentSession = nil
    failure = nil
    scheduler = nil
    inFlightAttempt = nil
    retryGate = nil
    retryNotBefore = nil
    retryTimer?.cancel()
    retryTimer = nil
    activeAttempt?.cancel()
    activeScheduler?.cancel()
    publish()
    finishObservers()

    let cleanup = Task {
      if let activeGate { await activeGate.wake() }
      try? await activeSession?.close()
      await activeScheduler?.value
    }
    closeTask = cleanup
    await cleanup.value
  }

  private func run() async {
    var consecutiveFailures: UInt64 = 0
    var attemptsSinceConnected: UInt64 = 0
    while state != .closed {
      state = .connecting
      failure = nil
      attempt = incrementingWithoutOverflow(attempt)
      attemptsSinceConnected = incrementingWithoutOverflow(attemptsSinceConnected)
      publish()

      let source = self.source
      let options = self.options
      let connectOneShot = self.connectOneShot
      let task = Task<any Session, Error> {
        let lease: ArtifactLease
        do {
          lease = try await source.acquireArtifact()
        } catch let failure as ArtifactSourceFailure {
          throw ConnectionAttemptFailure.artifactSource(failure)
        } catch is CancellationError {
          throw CancellationError()
        } catch {
          throw ConnectionAttemptFailure.unknownArtifactSource
        }
        do {
          try await lease.claimForConnectionController()
        } catch {
          throw ConnectionAttemptFailure.unknownArtifactSource
        }
        try Task.checkCancellation()
        do {
          return try await connectOneShot(lease, options)
        } catch let error as ConnectError {
          throw ConnectionAttemptFailure.connection(error)
        } catch is CancellationError {
          throw CancellationError()
        } catch {
          throw ConnectionAttemptFailure.connection(.connectionFailed)
        }
      }
      inFlightAttempt = task

      do {
        let session = try await task.value
        inFlightAttempt = nil
        guard state != .closed, !Task.isCancelled else {
          try? await session.close()
          return
        }
        consecutiveFailures = 0
        attemptsSinceConnected = 0
        currentSession = session
        state = .connected
        publish()

        let termination = await session.waitTermination()
        guard state != .closed, !Task.isCancelled else { return }
        currentSession = nil
        let sessionFailure = ConnectionAttemptFailure.session(termination.error)
        guard
          await scheduleRetry(
            after: sessionFailure,
            failures: &consecutiveFailures,
            attemptsSinceConnected: attemptsSinceConnected
          )
        else {
          return
        }
        attempt = 0
      } catch is CancellationError {
        inFlightAttempt = nil
        if state != .closed {
          fail(.connection(.canceled))
        }
        return
      } catch let attemptFailure as ConnectionAttemptFailure {
        inFlightAttempt = nil
        guard state != .closed, !Task.isCancelled else { return }
        guard
          await scheduleRetry(
            after: attemptFailure,
            failures: &consecutiveFailures,
            attemptsSinceConnected: attemptsSinceConnected
          )
        else {
          return
        }
      } catch {
        inFlightAttempt = nil
        guard state != .closed, !Task.isCancelled else { return }
        fail(.connection(.connectionFailed))
        return
      }
    }
  }

  private func scheduleRetry(
    after attemptFailure: ConnectionAttemptFailure,
    failures: inout UInt64,
    attemptsSinceConnected: UInt64
  ) async -> Bool {
    let disposition = attemptFailure.retryDisposition
    guard disposition != .terminal else {
      fail(attemptFailure)
      return false
    }
    if let maximumAttempts,
      attemptsSinceConnected >= maximumAttempts
    {
      fail(attemptFailure)
      return false
    }

    failures = incrementingWithoutOverflow(failures)
    let monotonicNow = ContinuousClock.now
    let wallNow = Date()
    let delay = backoff(failure: failures)
    let backoffDeadline = monotonicNow.advanced(by: delay)
    let mandatoryDeadline: RetryNotBefore?
    switch disposition {
    case .terminal:
      return false
    case .retryable:
      mandatoryDeadline = nil
    case .retryAfter(let deadline):
      guard deadline.timeIntervalSinceReferenceDate.isFinite else {
        fail(attemptFailure)
        return false
      }
      mandatoryDeadline = RetryNotBefore(
        instant: monotonicNow.advanced(
          by: .seconds(max(0, deadline.timeIntervalSince(wallNow)))
        )
      )
    }
    let scheduled = maxInstant(backoffDeadline, mandatoryDeadline?.instant)
    return await waitForRetry(
      until: scheduled,
      notBefore: mandatoryDeadline
    )
  }

  private func waitForRetry(
    until deadline: ContinuousClock.Instant,
    notBefore: RetryNotBefore?
  ) async -> Bool {
    let gate = ConnectionRetryGate()
    retryGate = gate
    retryNotBefore = notBefore
    state = .waiting
    retryTimer = makeRetryTimer(deadline: deadline, gate: gate)
    publish()

    await gate.wait()
    retryTimer?.cancel()
    retryTimer = nil
    retryGate = nil
    retryNotBefore = nil
    return state != .closed && !Task.isCancelled
  }

  private func makeRetryTimer(
    deadline: ContinuousClock.Instant,
    gate: ConnectionRetryGate
  ) -> Task<Void, Never> {
    Task {
      do {
        try await Task.sleep(until: deadline, clock: .continuous)
      } catch {
        return
      }
      await gate.wake()
    }
  }

  private func backoff(failure: UInt64) -> Duration {
    let maximumDelay = FlowersecSDKDefaults.ConnectionController.maximumDelay
    let multiplier = FlowersecSDKDefaults.ConnectionController.multiplier
    var delay = FlowersecSDKDefaults.ConnectionController.initialDelay
    var remainingMultiplications = failure > 0 ? failure - 1 : 0
    while remainingMultiplications > 0, delay < maximumDelay {
      let factor = Double(multiplier)
      if delay >= maximumDelay / factor {
        return maximumDelay
      }
      delay = delay * factor
      remainingMultiplications -= 1
    }
    return delay
  }

  private func fail(_ connectionFailure: ConnectionAttemptFailure) {
    guard state != .closed else { return }
    currentSession = nil
    failure = connectionFailure
    state = .failed
    scheduler = nil
    publish()
  }

  private func publish() {
    let value = snapshot()
    for continuation in observers.values {
      continuation.yield(value)
    }
  }

  private func finishObservers() {
    for continuation in observers.values {
      continuation.finish()
    }
    observers.removeAll()
  }

  private func removeObserver(_ id: UUID) {
    observers.removeValue(forKey: id)
  }

  private func maxInstant(
    _ instant: ContinuousClock.Instant,
    _ other: ContinuousClock.Instant?
  ) -> ContinuousClock.Instant {
    guard let other else { return instant }
    return instant < other ? other : instant
  }

  private func incrementingWithoutOverflow(_ value: UInt64) -> UInt64 {
    value == .max ? .max : value + 1
  }
}

private struct RetryNotBefore {
  let instant: ContinuousClock.Instant
}

private actor ConnectionRetryGate {
  private var finished = false
  private var waiter: CheckedContinuation<Void, Never>?

  func wait() async {
    guard !finished else { return }
    await withCheckedContinuation { continuation in
      if finished {
        continuation.resume()
      } else {
        waiter = continuation
      }
    }
  }

  func wake() {
    guard !finished else { return }
    finished = true
    waiter?.resume()
    waiter = nil
  }
}
