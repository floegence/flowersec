import Dispatch
import Foundation

/// A stable Source failure. Source configuration and exhaustion are terminal;
/// no failure asserts that prior remote effects were rolled back.
public struct ConnectionSourceFailure: Error, Equatable, Sendable {
  public let code: ConnectionMaterialSourceError
  public let disposition: RetryDisposition
  public init(code: ConnectionMaterialSourceError, disposition: RetryDisposition = .terminal) {
    self.code = code; self.disposition = disposition
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

public enum ConnectionAttemptFailure: Error, Equatable, Sendable {
  case source(ConnectionSourceFailure)
  case connection(ConnectError)
  case session(SessionError, ConnectionAttemptFacts? = nil)

  var connectionFacts: ConnectionAttemptFacts? {
    switch self {
    case .source: .notStarted
    case .connection(let error): error.connection
    case .session(_, let facts): facts
    }
  }
  var cleanupStatus: CleanupStatus? {
    if case .connection(let error) = self { return error.cleanup }
    return nil
  }
  public var retryDisposition: RetryDisposition {
    switch self {
    case .source(let failure): failure.disposition
    case .connection(let error): error.retryDisposition
    case .session(let error, let facts): facts?.permitsAutomaticRetry == false ? .terminal : error.retryDisposition
    }
  }
}

public struct ConnectionSnapshot: Sendable {
  public let state: ConnectionState
  public let attempt: UInt64
  public let currentSession: (any Session)?
  public let generation: UInt64
  public let failure: ConnectionAttemptFailure?
  public let retryDisposition: RetryDisposition?
  let connectionFacts: ConnectionAttemptFacts
  let cleanupStatus: CleanupStatus
  init(state: ConnectionState, attempt: UInt64, currentSession: (any Session)?, failure: ConnectionAttemptFailure?,
    retryDisposition: RetryDisposition?, generation: UInt64 = 0, connectionFacts: ConnectionAttemptFacts = .notStarted,
    cleanupStatus: CleanupStatus = CleanupStatus(complete: true)) {
    self.state = state; self.attempt = attempt; self.currentSession = currentSession
    self.failure = failure; self.retryDisposition = retryDisposition; self.generation = generation
    self.connectionFacts = connectionFacts; self.cleanupStatus = cleanupStatus
  }
}

public enum ConnectionFailurePhase: String, Equatable, Sendable {
  case source
  case connect
  case session
}

public struct ConnectionDiagnosticFailure: Equatable, Sendable {
  public let phase: ConnectionFailurePhase
  public let code: String
}

public struct ConnectionDiagnostic: Equatable, Sendable {
  public let state: ConnectionState
  public let attempt: UInt64
  public let failure: ConnectionDiagnosticFailure?
  public let retryDisposition: RetryDisposition?
  public let connection: ConnectionAttemptFacts
  public let cleanup: CleanupStatus
}

extension ConnectionSnapshot {
  /// Removes the live Session and retains only stable, redacted state.
  public var diagnostic: ConnectionDiagnostic {
    ConnectionDiagnostic(
      state: state,
      attempt: attempt,
      failure: failure.map { value in
        switch value {
        case .source(let error):
          ConnectionDiagnosticFailure(phase: .source, code: error.code.rawValue)
        case .connection(let error):
          ConnectionDiagnosticFailure(phase: .connect, code: error.code.rawValue)
        case .session(let error, _):
          ConnectionDiagnosticFailure(phase: .session, code: error.rawValue)
        }
      },
      retryDisposition: retryDisposition,
      connection: connectionFacts,
      cleanup: cleanupStatus
    )
  }
}

public enum ConnectionControllerErrorCode: String, Equatable, Sendable {
  case notReady = "not_ready"
  case notAccepting = "not_accepting"
  case failed
  case closed
  case canceled
}

public struct ConnectionControllerError: Error, Equatable, Sendable {
  public let code: ConnectionControllerErrorCode
  public let diagnostic: ConnectionDiagnostic
}

// The Controller owns one current dispatch generation. A service acquisition
// borrows its original gate and fixed Session identity, never a new connection
// right. Retiring a generation fences only future preparation/installation;
// already prepared operations retain their fixed Session and result owners.
// The binding's existing storage pays this one local alias. Retiring a
// generation drops the facade's reference without closing prepared handles.
final class V4ControllerServiceBindingSlot: @unchecked Sendable {
  private let gate: NSRecursiveLock
  private var binding: ServiceClient?
  init(_ binding: ServiceClient) { gate = binding.environment.gate; self.binding = binding }
  var client: ServiceClient? { gate.withLock { binding } }
  func release() { gate.withLock { binding = nil } }
}

final class V4ControllerServiceGeneration: @unchecked Sendable {
  let generation: UInt64
  let environment: V4EnvironmentFoundation
  private weak var session: (any V4ServiceSession)?
  private var current = true
  private struct BindingReference { weak var slot: V4ControllerServiceBindingSlot? }
  private var bindings: [BindingReference] = []
  init(session: any V4ServiceSession, generation: UInt64) {
    self.session = session; environment = session.serviceEnvironment; self.generation = generation
  }
  func matches(_ session: any V4ServiceSession, generation: UInt64) -> Bool {
    environment.gate.withLock { current && self.generation == generation && self.session === session }
  }
  func check(_ session: any V4ServiceSession) throws {
    try environment.gate.withLock {
      guard current, self.session === session else { throw ServiceFailure.serviceUnavailable }
      try session.checkServiceAdmission()
    }
  }
  func attach(_ client: ServiceClient) throws -> V4ControllerServiceBindingSlot {
    try environment.gate.withLock {
      try check(client.session)
      bindings.removeAll { $0.slot == nil }
      guard bindings.count < 256 else { throw ServiceFailure.resourceExhausted }
      let slot = V4ControllerServiceBindingSlot(client)
      bindings.append(BindingReference(slot: slot)); return slot
    }
  }
  func retire() {
    environment.gate.withLock {
      current = false; session = nil
      for reference in bindings { reference.slot?.release() }
      bindings.removeAll()
    }
  }
}

struct V4ControllerServiceSelection: Sendable {
  let session: any V4ServiceSession
  let generation: V4ControllerServiceGeneration
}

public enum ConnectionControllerConfigurationError: Error, Equatable, Sendable {
  case invalidMaximumAttempts
}

/// Owns current TransportEnvironment connection attempts, retry and fixed Sessions.

/// Candidate initializer view. It intentionally exposes only the Session
/// protocol surface; transport-native admission and mutable Controller state
/// remain unavailable to initializer code.
public protocol ServiceInitializerSession: Session {}

public actor ConnectionController {
  private static let maxSafeInteger: UInt64 = 9_007_199_254_740_991
  public private(set) var state: ConnectionState = .idle
  public private(set) var attempt: UInt64 = 0
  public private(set) var currentSession: (any Session)?
  public private(set) var generation: UInt64 = 0
  public private(set) var failure: ConnectionAttemptFailure?
  public private(set) var retryDisposition: RetryDisposition?
  private var latestConnectionFacts: ConnectionAttemptFacts = .notStarted
  private var latestCleanupStatus = CleanupStatus(complete: true)

  private struct NotificationSlot { weak var root: (any V4ControllerNotificationRoot)? }
  private var notificationRoots: [NotificationSlot] = []
  private var currentNotificationPlan: V4ControllerNotificationPlan?
  private var currentConfiguration: CurrentConnectionConfiguration?
  private var inFlightCurrent: Task<any Session, Error>?
  private var replacementActive = false
  private var inFlightReplacement: Task<ConnectionReplacementResult, Error>?
  private var currentMonitor: Task<SessionTermination, Never>?
  private var retainedSession: SessionRetirement?
  private var serviceGeneration: V4ControllerServiceGeneration?
  private struct ServiceDeclarationSlot { weak var value: V4ControllerServiceDeclaration? }
  private var serviceDeclarations: [ServiceDeclarationSlot] = []
  private var dependencyRevision: UInt64 = 0
  private let maximumAttempts: UInt64?
  private let clock: ConnectionControllerClock = .live
  private var scheduler: Task<Void, Never>?
  private var retryGate: ConnectionRetryGate?
  private var retryTimer: Task<Void, Never>?
  private var retryNotBefore: RetryNotBefore?
  private var observers: [UUID: AsyncStream<ConnectionSnapshot>.Continuation] = [:]
  private var closeTask: Task<Void, Never>?
  private var closeDeadline: ContinuousClock.Instant?
  private var closeCompleted = false
  private var active: Bool { state != .closed && !Task.isCancelled }

  public init(environment: TransportEnvironment, source: ConnectionMaterialSource,
    requirements: ConnectionRequirements = ConnectionRequirements(), maximumAttempts: UInt64? = nil,
    initializeSession: (@isolated(any) @Sendable (any Session) async throws -> Void)? = nil,
    initializeServiceSession: (@isolated(any) @Sendable (any ServiceInitializerSession) async throws -> Void)? = nil) throws {
    self.maximumAttempts = try Self.validate(maximumAttempts: maximumAttempts)
    currentConfiguration = CurrentConnectionConfiguration(environment: environment, source: source, requirements: requirements,
      initializeSession: initializeSession, initializeServiceSession: initializeServiceSession)
  }

  private static func validate(maximumAttempts: UInt64?) throws -> UInt64? {
    guard let maximumAttempts else { return nil }
    guard maximumAttempts <= maxSafeInteger else {
      throw ConnectionControllerConfigurationError.invalidMaximumAttempts
    }
    return maximumAttempts == 0 ? nil : maximumAttempts
  }

  public func subscribeNotifications<Value: Sendable>(_ method: MethodDefinition, in definition: ServiceDefinition,
    target: ServiceBindingTarget, snapshot: ServiceContractSnapshot, codec: any MessageCodec<Value>,
    observation: ControllerNotificationObservation = .currentOnly, options: NotificationSubscriptionOptions, context: ApplicationInvocationContext? = nil,
    handler: @escaping @Sendable (ApplicationInvocationContext, ControllerNotificationEvent<Value>) async throws -> Void
  ) async throws -> ControllerNotificationSubscription<Value> {
    guard state != .closed, let configuration = currentConfiguration else { throw ServiceFailure.closed }
    notificationRoots.removeAll { $0.root?.isClosed ?? true }
    guard notificationRoots.count < 32 else { throw ServiceFailure.resourceExhausted }
    let foundation = try await configuration.environment.notificationFoundation()
    try Task.checkCancellation()
    guard state != .closed else { throw ServiceFailure.closed }
    // Foundation acquisition suspends the actor; concurrent subscriptions must
    // still pass the same finite registration gate before owning a root.
    notificationRoots.removeAll { $0.root?.isClosed ?? true }
    guard notificationRoots.count < 32 else { throw ServiceFailure.resourceExhausted }
    let subscription = try ControllerNotificationSubscription(environment: foundation, definition: definition, method: method,
      target: target, snapshot: snapshot, codec: codec, observation: observation, options: options, context: context, handler: handler)
    notificationRoots.append(NotificationSlot(root: subscription))
    // A stable published Session can receive this root even while a replacement
    // is preparing. Roots registered before the next publication are included
    // by that plan's late pass; roots registered afterwards attach here.
    if state == .connected, let session = currentSession as? any V4ServiceSession,
      let plan = currentNotificationPlan {
      await attachLateNotificationRoots(to: session, plan: plan, roots: [subscription])
    }
    if state == .closed || Task.isCancelled {
      subscription.close()
      notificationRoots.removeAll { $0.root?.token == subscription.token }
      if state == .closed { throw ServiceFailure.closed }
      throw CancellationError()
    }
    // Losing the observed incarnation leaves an owned, accurately unattached
    // subscription. Only the caller's cancellation or Controller Close closes it.
    return subscription
  }

  public func start() {
    guard state == .idle, scheduler == nil, !replacementActive else { return }
    scheduler = Task { [weak self] in await self?.run() }
  }

  /// Captures one established Session without starting the controller. The
  /// returned Session and work bound to it keep their original attachment when
  /// the controller later publishes another Session.
  public func waitForSession() async throws -> any Session {
    let stream = updates()
    for await value in stream {
      if Task.isCancelled {
        throw ConnectionControllerError(code: .canceled, diagnostic: value.diagnostic)
      }
      switch value.state {
      case .connected:
        if let session = value.currentSession { return session }
      case .failed:
        throw ConnectionControllerError(code: .failed, diagnostic: value.diagnostic)
      case .closed:
        throw ConnectionControllerError(code: .closed, diagnostic: value.diagnostic)
      case .idle, .connecting, .waiting:
        break
      }
    }
    let value = snapshot().diagnostic
    throw ConnectionControllerError(
      code: Task.isCancelled ? .canceled : .closed,
      diagnostic: value
    )
  }

  /// Captures the fixed, currently published and accepting native Session at
  /// this actor gate. It never starts a connection or waits for another lease.
  public func captureSession() throws -> any Session {
    guard state != .closed else { throw ConnectionControllerError(code: .closed, diagnostic: snapshot().diagnostic) }
    guard state == .connected, currentConfiguration != nil,
      let session = currentSession as? any V4ServiceSession else {
      throw ConnectionControllerError(code: .notReady, diagnostic: snapshot().diagnostic)
    }
    try session.checkServiceSession()
    guard !session.serviceObservationDraining else {
      throw ConnectionControllerError(code: .notAccepting, diagnostic: snapshot().diagnostic)
    }
    return session
  }

  // Service selection is immediate and never starts or waits for a source.
  // The final contract installation rechecks this same original generation.
  func captureServiceSelection() throws -> V4ControllerServiceSelection {
    let session = try captureSession()
    guard let native = session as? any V4ServiceSession else { throw ServiceFailure.serviceUnavailable }
    synchronizeServiceGeneration()
    guard let serviceGeneration else { throw ServiceFailure.serviceUnavailable }
    try serviceGeneration.check(native)
    return V4ControllerServiceSelection(session: native, generation: serviceGeneration)
  }

  func registerServiceDeclaration(_ declaration: V4ControllerServiceDeclaration,
    generation: V4ControllerServiceGeneration) throws {
    guard state == .connected, serviceGeneration === generation, dependencyRevision < UInt64.max else {
      throw V4ControllerBindingFailure.superseded
    }
    serviceDeclarations.removeAll { $0.value == nil || $0.value?.active == false }
    guard serviceDeclarations.count < 64 else { throw ServiceFailure.resourceExhausted }
    serviceDeclarations.append(ServiceDeclarationSlot(value: declaration)); dependencyRevision += 1
  }
  private func servicePlan() throws -> V4ControllerServicePlan {
    serviceDeclarations.removeAll { $0.value == nil || $0.value?.active == false }
    return try V4ControllerServicePlan(serviceDeclarations.compactMap { $0.value }.filter { $0.needsCandidate })
  }

  private func synchronizeServiceGeneration() {
    guard state == .connected, let session = currentSession as? any V4ServiceSession else {
      serviceGeneration?.retire(); serviceGeneration = nil; return
    }
    if serviceGeneration?.matches(session, generation: generation) == true { return }
    serviceGeneration?.retire()
    serviceGeneration = V4ControllerServiceGeneration(session: session, generation: generation)
  }

  /// Explicitly acquires one new candidate, including before the first current
  /// Session or after an initializer failed. The application must first resolve
  /// any earlier initialization effects through its own authority. This never
  /// retries an old attempt or restores dispatch to an old Session pointer.
  public func replaceSession(retirement: ConnectionReplacementRetirement = .drain(timeout: .seconds(30)),
    capacity: ConnectionReplacementCapacity? = nil) async throws -> ConnectionReplacementResult {
    try Task.checkCancellation()
    guard state == .connected || state == .idle || state == .failed,
      let configuration = currentConfiguration else {
      throw ConnectionControllerError(code: state == .closed ? .closed : .notReady, diagnostic: snapshot().diagnostic)
    }
    let previous = currentSession
    let resumesScheduler = state != .connected
    if retainedSession?.progress().cleanup.complete == true { retainedSession = nil }
    guard !replacementActive, retainedSession == nil, inFlightCurrent == nil else { throw ServiceFailure.resourceExhausted }
    let duration: Duration
    switch retirement { case .drain(let timeout): duration = timeout; case .retain(let interval): duration = interval }
    guard duration > .zero, duration <= .seconds(30), generation < Self.maxSafeInteger else { throw ServiceFailure.configurationCapacity }
    let expected = generation
    replacementActive = true
    let reservation: (any V4ControllerHandoffReservation)?
    var initializationStorage: V4CryptoReservation?
    let dependencies: V4ControllerServicePlan
    let dependencyGeneration = dependencyRevision
    do {
      dependencies = try servicePlan()
      // A first candidate reserves its ordinary full connection vector in the
      // same establishment path. No old Session means no retirement position.
      if previous != nil || capacity != nil {
        reservation = try await configuration.environment.controllerHandoffReservation(previous: previous, capacity: capacity,
          notificationTokens: notificationRoots.compactMap { $0.root?.token })
      } else {
        reservation = nil
        if configuration.initializeSession != nil || configuration.initializeServiceSession != nil {
          initializationStorage = try await configuration.environment.controllerInitializationReservation()
        }
      }
      guard state != .closed, generation == expected, !Task.isCancelled else { reservation?.release(); throw SessionError.canceled }
      if resumesScheduler { await scheduler?.value; scheduler = nil }
      guard state != .closed, !Task.isCancelled else { reservation?.release(); throw SessionError.canceled }
    } catch { initializationStorage?.seal(); replacementActive = false; throw error }
    let prepaidInitialization = initializationStorage
    let original = Task { [self] in
      defer { prepaidInitialization?.seal(); replacementActive = false; inFlightReplacement = nil }
      return try await performReplacement(configuration, previous: previous, expectedGeneration: expected,
        duration: duration, retirement: retirement, reservation: reservation,
        dependencies: dependencies, dependencyGeneration: dependencyGeneration,
        resumesScheduler: resumesScheduler, prepaidInitialization: prepaidInitialization)
    }
    inFlightReplacement = original
    // Waiting is separate from the original replacement owner. Cancellation
    // before the publication gate withdraws only that attempt's switch right.
    return try await withTaskCancellationHandler {
      let result = try await original.value
      try Task.checkCancellation()
      return result
    } onCancel: { original.cancel() }
  }

  private func performReplacement(_ configuration: CurrentConnectionConfiguration, previous: (any Session)?,
    expectedGeneration: UInt64, duration: Duration, retirement: ConnectionReplacementRetirement,
    reservation: (any V4ControllerHandoffReservation)?, dependencies: V4ControllerServicePlan,
    dependencyGeneration: UInt64, resumesScheduler: Bool, prepaidInitialization: V4CryptoReservation?) async throws -> ConnectionReplacementResult {
    notificationRoots.removeAll { $0.root?.isClosed ?? true }
    let plan = V4ControllerNotificationPlan(notificationRoots.compactMap { $0.root }, handoff: reservation)
    var candidate: (any Session)?
    var transferred = false
    var initializerEntered = false
    defer { if !transferred { reservation?.release() } }
    do {
      try reservation?.check(); try Task.checkCancellation()
      let fixed = try await configuration.environment.connectForController(source: configuration.source,
        requirements: configuration.requirements, notifications: plan, handoff: reservation)
      candidate = fixed
      try await dependencies.prepare(fixed)
      if configuration.initializeSession != nil || configuration.initializeServiceSession != nil {
        // Existing children keep their Session, but no new Controller work can
        // dispatch while initialization may change the application's authority.
        state = .connecting; serviceGeneration?.retire(); serviceGeneration = nil; publish()
      }
      if let initialize = configuration.initializeSession {
        initializerEntered = true
        do { try await configuration.environment.initializeControllerCandidate(fixed, handoff: reservation, prepaidInitialization: prepaidInitialization, callback: initialize) }
      } else if let initialize = configuration.initializeServiceSession {
        initializerEntered = true
        do {
          try await configuration.environment.initializeControllerCandidate(fixed, handoff: reservation, prepaidInitialization: prepaidInitialization, callback: { session in
            guard let restricted = session as? any ServiceInitializerSession else { throw ServiceFailure.serviceUnavailable }
            try await initialize(restricted)
          }) }
        catch {
          if let facts = (fixed as? V4ConnectionFactsOwner)?.connectionFactsOwner { facts.publicationFailed() }
          throw CurrentSessionInitializationFailure((fixed as? V4ConnectionFactsOwner)?.connectionFactsOwner.snapshot())
        }
      }
      try Task.checkCancellation(); try reservation?.check()
      guard state != .closed, generation == expectedGeneration,
        dependencyRevision == dependencyGeneration else { throw SessionError.canceled }
      try dependencies.check()
      guard let next = fixed as? any V4ServiceSession else { throw SessionError.operationFailed }
      try next.checkServiceSession()
      let old: SessionRetirement?
      if let previous {
        #if os(macOS) || os(iOS)
        guard let native = previous as? V4NativeSession, let reservation else { throw SessionError.operationFailed }
        let deadline: ContinuousClock.Instant
        if case .retain = retirement { deadline = try native.retirementDeadline(maximum: duration) }
        else { deadline = ContinuousClock.now.advanced(by: duration) }
        old = SessionRetirement(session: previous, plan: currentNotificationPlan, deadline: deadline,
          policy: retirement, reservation: reservation)
        #else
        throw SessionError.operationFailed
        #endif
      } else { old = nil }
      // No suspension separates installing the original retirement owner and
      // publishing the new current/notification generation at this actor gate.
      let nextServiceGeneration = V4ControllerServiceGeneration(session: next, generation: generation + 1)
      try next.serviceEnvironment.gate.withLock {
        try dependencies.publish(generation: nextServiceGeneration) {
          reservation?.finishCandidate()
          serviceGeneration?.retire()
          retainedSession = old; generation += 1; serviceGeneration = nextServiceGeneration
          currentSession = fixed; currentNotificationPlan = plan
          state = .connected; failure = nil; retryDisposition = nil; attempt = 0
          if let facts = (fixed as? V4ConnectionFactsOwner)?.connectionFactsOwner {
            facts.published(); latestConnectionFacts = facts.snapshot()
          }
          publishNotificationPlan(plan)
        }
      }
      old?.start(); transferred = true
      if old == nil { reservation?.release() }
      let publishedGeneration = generation
      currentMonitor?.cancel(); publish()
      if resumesScheduler { scheduler = Task { [weak self] in await self?.resumePublished(configuration) } }
      // Publication already won. Late observation failures cannot roll it back
      // or release the retirement reservation now owned by the old Session.
      await attachLateNotificationRoots(to: next, plan: plan)
      return ConnectionReplacementResult(currentSwitched: true, generation: publishedGeneration, currentSession: fixed,
        previousSession: previous, retirement: old)
    } catch {
      plan.retire()
      if let candidate, let facts = (candidate as? V4ConnectionFactsOwner)?.connectionFactsOwner { facts.publicationFailed() }
      let candidateFacts = (candidate as? V4ConnectionFactsOwner)?.connectionFactsOwner.snapshot()
      if let candidate {
        try? await candidate.close()
        await waitPhysicalRetirement(candidate)
      }
      if (initializerEntered || error is CurrentSessionInitializationFailure), state != .closed {
        state = .failed; failure = .session(.operationFailed, candidateFacts); retryDisposition = .terminal
        if let facts = (candidate as? V4ConnectionFactsOwner)?.connectionFactsOwner { latestConnectionFacts = facts.snapshot() }
        currentMonitor?.cancel(); publish()
      }
      throw error
    }
  }

  public func updates() -> AsyncStream<ConnectionSnapshot> {
    let id = UUID()
    let pair = AsyncStream.makeStream(
      of: ConnectionSnapshot.self, bufferingPolicy: .bufferingNewest(1))
    guard observers.count < 128 else { pair.continuation.finish(); return pair.stream }
    observers[id] = pair.continuation
    pair.continuation.yield(snapshot())
    pair.continuation.onTermination = { [weak self] _ in
      Task { await self?.removeObserver(id) }
    }
    return pair.stream
  }

  public func snapshot() -> ConnectionSnapshot {
    ConnectionSnapshot(
      state: state, attempt: attempt, currentSession: currentSession, failure: failure,
      retryDisposition: retryDisposition, generation: generation,
      connectionFacts: failure?.connectionFacts ?? (currentSession as? V4ConnectionFactsOwner)?.connectionFactsOwner.snapshot() ?? latestConnectionFacts,
      cleanupStatus: failure?.cleanupStatus ?? latestCleanupStatus)
  }

  public func retryNow() async -> Bool {
    guard state == .waiting, let retryGate else { return false }
    if let notBefore = retryNotBefore,
      wallNowMilliseconds(clock.wallNow()) < notBefore.wallDeadlineMilliseconds
    {
      return false
    }
    retryTimer?.cancel()
    return await retryGate.wake(.manual)
  }

  public func close() async {
    if closeTask != nil {
      await waitForCloseBounded()
      return
    }
    let activeScheduler = scheduler
    let activeCurrent = inFlightCurrent
    let activeReplacement = inFlightReplacement
    let activeRetained = retainedSession
    let activeMonitor = currentMonitor
    let activeGate = retryGate
    let activeSession = currentSession
    state = .closed
    for declaration in serviceDeclarations { declaration.value?.close() }
    serviceDeclarations.removeAll()
    serviceGeneration?.retire(); serviceGeneration = nil
    currentSession = nil
    failure = nil
    scheduler = nil
    inFlightCurrent = nil
    inFlightReplacement = nil; retainedSession = nil; currentMonitor = nil
    currentConfiguration = nil
    currentNotificationPlan?.retire(); currentNotificationPlan = nil
    for slot in notificationRoots { slot.root?.close() }; notificationRoots.removeAll()
    retryGate = nil
    retryNotBefore = nil
    retryDisposition = nil
    retryTimer?.cancel()
    retryTimer = nil
    activeCurrent?.cancel(); activeReplacement?.cancel(); activeMonitor?.cancel()
    activeScheduler?.cancel()
    publish()
    finishObservers()
    closeDeadline = ContinuousClock.now.advanced(by: .seconds(5))
    let cleanup = Task {
      if let activeGate { await activeGate.wake(.cancellation) }
      if let activeCurrent, let late = try? await activeCurrent.value {
        try? await late.close()
        await self.waitPhysicalRetirement(late)
      }
      if let activeReplacement, let late = try? await activeReplacement.value {
        try? await late.currentSession.close()
        await late.retirement?.close()
        _ = try? await late.retirement?.wait()
        await self.waitPhysicalRetirement(late.currentSession)
      }
      await activeRetained?.close()
      _ = try? await activeRetained?.wait()
      try? await activeSession?.close()
      if let activeSession { await self.waitPhysicalRetirement(activeSession) }
      await activeScheduler?.value
      self.closeCompleted = true
    }
    closeTask = cleanup
    await waitForCloseBounded()
  }

  public func cleanupStatus() -> CleanupStatus {
    CleanupStatus(complete: state == .closed && closeCompleted,
      cleanupIncomplete: state == .closed && !closeCompleted)
  }

  private func waitForCloseBounded() async {
    guard let until = closeDeadline else { return }
    while !closeCompleted, ContinuousClock.now < until, !Task.isCancelled {
      do { try await ContinuousClock().sleep(for: .milliseconds(10)) } catch { return }
    }
  }

  private func waitPhysicalRetirement(_ session: any Session) async {
    #if os(macOS) || os(iOS)
    if let native = session as? V4NativeSession {
      let waiter = Task.detached { await native.waitPhysicalCleanup() }
      await waiter.value
    }
    #endif
  }

  private func notificationIncarnationIsCurrent(_ session: any V4ServiceSession,
    plan: V4ControllerNotificationPlan) -> Bool {
    guard state == .connected, let current = currentSession as? any V4ServiceSession else { return false }
    return current === session && currentNotificationPlan === plan
  }

  // Called in the same Environment gate as the current switch. Every live
  // root, including one registered after the attempt snapshot, observes the
  // new current identity immediately. A missing source remains unattached;
  // current_only cannot keep delivering from the superseded source.
  private func publishNotificationPlan(_ plan: V4ControllerNotificationPlan) {
    notificationRoots.removeAll { $0.root?.isClosed ?? true }
    for root in notificationRoots.compactMap({ $0.root }) { _ = plan.includeLate(root) }
    plan.publish()
  }

  private func attachLateNotificationRoots(to session: any V4ServiceSession,
    plan: V4ControllerNotificationPlan, roots selectedRoots: [any V4ControllerNotificationRoot]? = nil) async {
    guard notificationIncarnationIsCurrent(session, plan: plan), !plan.isRetired else { return }
    notificationRoots.removeAll { $0.root?.isClosed ?? true }
    // One bounded pass. An unattached/closed root must not cause an immediate
    // retry loop or make observation capacity block Controller publication.
    let roots = selectedRoots ?? notificationRoots.compactMap { $0.root }
    guard let receiver = session.serviceNotificationReceiver,
      let identity = try? session.serviceIdentity else {
      for root in roots where !root.isClosed { root.noteLateAttachment() }
      return
    }
    for root in roots {
      guard notificationIncarnationIsCurrent(session, plan: plan), !plan.isRetired else { return }
      guard !root.isClosed, !root.attached(id: plan.id), plan.includeLate(root) else { continue }
      root.noteLateAttachment()
      await root.attach(id: plan.id, environment: session.serviceEnvironment, identity: identity,
        check: { [weak session, weak plan] in
          guard let session, let plan, !plan.isRetired else { throw ServiceFailure.closed }
          try session.checkServiceSession()
        }, candidate: false, receiver: receiver,
        draining: { [weak session] in session?.serviceObservationDraining ?? false }, handoff: nil,
        slotAvailable: { [weak self, weak session, weak plan, weak root] in
          guard let self, let session, let plan, let root else { return }
          await self.attachLateNotificationRoots(to: session, plan: plan, roots: [root])
        })
      guard notificationIncarnationIsCurrent(session, plan: plan), !plan.isRetired else {
        // Preserve other roots that legitimately belong to a retained old plan.
        // This particular late result cannot gain new publication rights.
        root.retire(id: plan.id)
        return
      }
      // Current identity was published at the switch even when unattached.
      // Only an installed source gains delivery rights in this late pass.
      guard root.attached(id: plan.id) else { continue }
      root.publish(id: plan.id)
    }
  }

  private func runCurrent(_ configuration: CurrentConnectionConfiguration) async {
    var failures: UInt64 = 0
    var attempts: UInt64 = 0
    while active {
      state = .connecting; failure = nil; retryDisposition = nil
      attempt = increment(attempt); attempts = increment(attempts); publish()
      notificationRoots.removeAll { $0.root?.isClosed ?? true }
      let notificationPlan = V4ControllerNotificationPlan(notificationRoots.compactMap { $0.root })
      let dependencies: V4ControllerServicePlan
      do { dependencies = try servicePlan() }
      catch { notificationPlan.retire(); fail(.session(.resourceExhausted)); return }
      let dependencyGeneration = dependencyRevision
      let diagnosticAttempt = attempts
      let original = Task {
        let candidate = try await configuration.environment.connectForController(source: configuration.source,
          requirements: configuration.requirements, notifications: notificationPlan, diagnosticAttempt: diagnosticAttempt)
        do {
          try await dependencies.prepare(candidate)
          if let initialize = configuration.initializeSession {
            try Task.checkCancellation()
            try await configuration.environment.initializeControllerCandidate(candidate, callback: initialize)
          } else if let initialize = configuration.initializeServiceSession {
            try Task.checkCancellation()
            try await configuration.environment.initializeControllerCandidate(candidate, callback: { session in
              guard let restricted = session as? any ServiceInitializerSession else { throw ServiceFailure.serviceUnavailable }
              try await initialize(restricted)
            })
          }
          try Task.checkCancellation()
          return candidate
        } catch {
          if let facts = (candidate as? V4ConnectionFactsOwner)?.connectionFactsOwner { facts.publicationFailed() }
          let facts = (candidate as? V4ConnectionFactsOwner)?.connectionFactsOwner.snapshot()
          try? await candidate.close()
          await self.waitPhysicalRetirement(candidate)
          // A failed or canceled initializer can have committed remote work.
          // Closing the transport cannot prove rollback or authorize replay.
          throw CurrentSessionInitializationFailure(facts)
        }
      }
      inFlightCurrent = original
      do {
        let session = try await original.value
        inFlightCurrent = nil
        guard active else {
          (session as? V4ConnectionFactsOwner)?.connectionFactsOwner.publicationFailed()
          notificationPlan.retire(); try? await session.close(); return
        }
        do {
          guard generation < Self.maxSafeInteger else { throw ServiceFailure.resourceExhausted }
          guard dependencyRevision == dependencyGeneration, let native = session as? any V4ServiceSession else {
            throw SessionError.operationFailed
          }
          let nextServiceGeneration = V4ControllerServiceGeneration(session: native, generation: generation + 1)
          try native.serviceEnvironment.gate.withLock {
            try dependencies.publish(generation: nextServiceGeneration) {
              generation += 1; serviceGeneration = nextServiceGeneration
              currentSession = session; currentNotificationPlan = notificationPlan
              state = .connected; failures = 0; attempts = 0; retryDisposition = nil
              if let facts = (session as? V4ConnectionFactsOwner)?.connectionFactsOwner {
                facts.published(); latestConnectionFacts = facts.snapshot()
              }
              publishNotificationPlan(notificationPlan)
            }
          }
        } catch {
          notificationPlan.retire()
          if let facts = (session as? V4ConnectionFactsOwner)?.connectionFactsOwner { facts.publicationFailed() }
          let facts = (session as? V4ConnectionFactsOwner)?.connectionFactsOwner.snapshot()
          try? await session.close(); await waitPhysicalRetirement(session)
          throw CurrentSessionInitializationFailure(facts)
        }
        publish()
        if let native = session as? any V4ServiceSession {
          await attachLateNotificationRoots(to: native, plan: notificationPlan)
        }
        guard let ended = await watchPublishedCurrent() else { return }
        // A previous retirement position remains occupied until the physical
        // tails leave. Reconnect never evicts it or acquires behind its back.
        if let retained = retainedSession {
          _ = try? await retained.wait()
          guard active else { return }
          if retained.progress().cleanup.complete { retainedSession = nil }
        }
        guard await scheduleRetry(after: .session(ended.error), failures: &failures, attempts: attempts) else { return }
      } catch {
        notificationPlan.retire()
        inFlightCurrent = nil
        guard active else { return }
        let projected = Self.currentFailure(error)
        guard await scheduleRetry(after: projected, failures: &failures, attempts: attempts) else { return }
      }
    }
  }
  private func watchPublishedCurrent() async -> SessionTermination? {
    while active, (state == .connected || replacementActive), let watched = currentSession {
      let watchedGeneration = generation
      let monitor = Task { await watched.waitTermination() }
      currentMonitor = monitor
      let termination = await monitor.value
      currentMonitor = nil
      guard active, state != .failed else { return nil }
      if generation != watchedGeneration { continue }
      if let replacement = inFlightReplacement { _ = try? await replacement.value }
      guard active, state != .failed else { return nil }
      if generation != watchedGeneration { continue }
      try? await watched.close()
      await waitPhysicalRetirement(watched)
      guard active, state != .failed else { return nil }
      currentNotificationPlan?.retire(); currentNotificationPlan = nil
      serviceGeneration?.retire(); serviceGeneration = nil
      currentSession = nil; attempt = 0
      return termination
    }
    return nil
  }

  private func resumePublished(_ configuration: CurrentConnectionConfiguration) async {
    guard let ended = await watchPublishedCurrent() else { return }
    if let retained = retainedSession {
      _ = try? await retained.wait()
      guard active else { return }
      if retained.progress().cleanup.complete { retainedSession = nil }
    }
    var failures: UInt64 = 0
    if await scheduleRetry(after: .session(ended.error), failures: &failures, attempts: 0) {
      await runCurrent(configuration)
    }
  }

  private static func currentFailure(_ error: any Error) -> ConnectionAttemptFailure {
    if let error = error as? CurrentSessionInitializationFailure { return .session(.operationFailed, error.facts) }
    if let error = error as? SessionError { return .session(error) }
    if let error = error as? ConnectError { return .connection(error) }
    if error is CancellationError { return .session(.canceled) }
    if let error = error as? ConnectionMaterialSourceError {
      switch error {
      case .closed: return .source(ConnectionSourceFailure(code: .closed))
      case .exhausted, .generationConflict: return .source(ConnectionSourceFailure(code: error))
      }
    }
    #if os(macOS) || os(iOS)
    if let error = error as? TransportControlError {
      switch error {
      case .canceled: return .session(.canceled)
      case .closed: return .source(ConnectionSourceFailure(code: .closed))
      case .invalidConfiguration: return .connection(.invalidMaterial)
      case .responseInvalid: return .connection(.securityFailed)
      case .unavailable, .busy: return .connection(.connectionFailed)
      }
    }
    if let error = error as? TransportConnectError {
      switch error {
      case .invalidMaterial: return .connection(.invalidMaterial)
      case .unsupported: return .connection(.unsupported)
      case .securityFailed, .futureTimestamp: return .connection(.securityFailed)
      case .expired: return .connection(.expired)
      case .canceled: return .session(.canceled)
      case .closed: return .session(.closed)
      case .connectionFailed, .admissionRejected, .timePending, .timeNotProven,
        .bootstrapDeadline, .timeUnavailable: return .connection(.connectionFailed)
      }
    }
    #endif
    return .connection(.connectionFailed)
  }

  private func run() async {
    guard let configuration = currentConfiguration else { return }
    await runCurrent(configuration)
  }

  private func scheduleRetry(
    after attemptFailure: ConnectionAttemptFailure,
    failures: inout UInt64,
    attempts: UInt64,
    alreadyCounted: Bool = false,
    dispositionOverride: RetryDisposition? = nil
  ) async -> Bool {
    guard active else { return false }
    let disposition = dispositionOverride ?? attemptFailure.retryDisposition
    guard validRetryDisposition(disposition) else {
      fail(.connection(.invalidMaterial))
      return false
    }
    guard disposition != .terminal else {
      fail(attemptFailure)
      return false
    }
    if let maximumAttempts, attempts >= maximumAttempts {
      fail(terminalFailure(attemptFailure))
      return false
    }
    failure = attemptFailure
    latestConnectionFacts = attemptFailure.connectionFacts ?? .unobserved
    latestCleanupStatus = attemptFailure.cleanupStatus ?? latestCleanupStatus
    if !alreadyCounted { failures = increment(failures) }
    let monotonicNow = min(clock.monotonicMilliseconds(), Self.maxSafeInteger)
    let backoffDeadline = saturatingAdd(
      monotonicNow, milliseconds(backoff(failure: failures)))
    let mandatory: RetryNotBefore?
    switch disposition {
    case .terminal: return false
    case .retryable: mandatory = nil
    case .retryAfter(let deadline):
      guard validRetryAfter(deadline) else {
        fail(.connection(.invalidMaterial))
        return false
      }
      mandatory = RetryNotBefore(wallDeadlineMilliseconds: deadline)
    }
    return await waitForRetry(backoffDeadline: backoffDeadline, notBefore: mandatory)
  }

  private func waitForRetry(
    backoffDeadline: UInt64, notBefore: RetryNotBefore?
  ) async -> Bool {
    guard active else { return false }
    retryNotBefore = notBefore
    retryDisposition = notBefore.map { .retryAfter($0.wallDeadlineMilliseconds) } ?? .retryable
    state = .waiting
    let clock = self.clock
    publish()
    var manualBackoffBypass = false
    while active {
      let gate = ConnectionRetryGate()
      retryGate = gate
      let skipsBackoff = manualBackoffBypass
      retryTimer = Task {
        while !Task.isCancelled {
          let monotonicNow = min(clock.monotonicMilliseconds(), Self.maxSafeInteger)
          let monotonicRemaining =
            skipsBackoff || backoffDeadline <= monotonicNow
            ? 0 : backoffDeadline - monotonicNow
          let wallRemaining: UInt64 =
            notBefore.map {
              let now = wallNowMilliseconds(clock.wallNow())
              return $0.wallDeadlineMilliseconds > now ? $0.wallDeadlineMilliseconds - now : 0
            } ?? 0
          if monotonicRemaining == 0, wallRemaining == 0 {
            await gate.wake(.timer)
            return
          }
          let nextDeadline =
            monotonicRemaining == 0
            ? wallRemaining
            : wallRemaining == 0 ? monotonicRemaining : min(monotonicRemaining, wallRemaining)
          let remaining = min(nextDeadline, 1_000)
          do { try await clock.sleep(.milliseconds(Int64(remaining))) } catch { return }
        }
      }

      let wake = await gate.wait()
      retryTimer?.cancel()
      retryTimer = nil
      guard active else { break }
      if wake == .manual { manualBackoffBypass = true }

      let monotonicReady =
        manualBackoffBypass
        || min(clock.monotonicMilliseconds(), Self.maxSafeInteger) >= backoffDeadline
      let wallReady =
        notBefore.map {
          wallNowMilliseconds(clock.wallNow()) >= $0.wallDeadlineMilliseconds
        } ?? true
      if monotonicReady, wallReady {
        retryGate = nil
        retryNotBefore = nil
        return true
      }
    }
    retryGate = nil
    retryNotBefore = nil
    return false
  }

  private func backoff(failure: UInt64) -> Duration {
    var delay = FlowersecSDKDefaults.ConnectionController.initialDelay
    let maximum = FlowersecSDKDefaults.ConnectionController.maximumDelay
    var remaining = failure > 0 ? failure - 1 : 0
    while remaining > 0, delay < maximum {
      if delay >= maximum / Double(FlowersecSDKDefaults.ConnectionController.multiplier) {
        return maximum
      }
      delay = delay * Double(FlowersecSDKDefaults.ConnectionController.multiplier)
      remaining -= 1
    }
    return delay
  }

  private func fail(_ value: ConnectionAttemptFailure) {
    guard state != .closed else { return }
    serviceGeneration?.retire(); serviceGeneration = nil
    currentSession = nil
    failure = value
    retryDisposition = .terminal
    state = .failed
    scheduler = nil
    publish()
  }

  nonisolated private func validRetryAfter(_ deadline: UInt64) -> Bool {
    deadline <= 253_402_300_799_999
  }

  nonisolated private func validRetryDisposition(_ disposition: RetryDisposition) -> Bool {
    guard case .retryAfter(let deadline) = disposition else { return true }
    return validRetryAfter(deadline)
  }

  nonisolated private func terminalFailure(
    _ value: ConnectionAttemptFailure
  ) -> ConnectionAttemptFailure {
    switch value {
    case .source(let failure):
      return .source(ConnectionSourceFailure(code: failure.code))
    case .connection(let error):
      return .connection(error.terminalized())
    case .session:
      // Session termination starts a fresh cycle with an empty attempt budget;
      // a session failure cannot reach this exhaustion branch.
      return value
    }
  }

  private func publish() {
    synchronizeServiceGeneration()
    let value = snapshot()
    for observer in observers.values { observer.yield(value) }
  }

  private func finishObservers() {
    for observer in observers.values { observer.finish() }
    observers.removeAll()
  }

  private func removeObserver(_ id: UUID) { observers.removeValue(forKey: id) }

  private func increment(_ value: UInt64) -> UInt64 {
    value >= Self.maxSafeInteger ? Self.maxSafeInteger : value + 1
  }
  private func saturatingAdd(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
    let (sum, overflow) = lhs.addingReportingOverflow(rhs)
    return overflow || sum > Self.maxSafeInteger ? Self.maxSafeInteger : sum
  }

  private func milliseconds(_ duration: Duration) -> UInt64 {
    let components = duration.components
    guard components.seconds >= 0, components.attoseconds >= 0 else { return 0 }
    return saturatingAdd(
      UInt64(components.seconds) * 1_000,
      UInt64(components.attoseconds) / 1_000_000_000_000_000)
  }

  private nonisolated func wallNowMilliseconds(_ date: Date) -> UInt64 {
    let milliseconds = date.timeIntervalSince1970 * 1_000
    guard milliseconds.isFinite, milliseconds > 0 else { return 0 }
    return min(UInt64(milliseconds.rounded(.down)), Self.maxSafeInteger)
  }
}

struct ConnectionControllerClock: Sendable {
  let wallNow: @Sendable () -> Date
  let monotonicMilliseconds: @Sendable () -> UInt64
  let sleep: @Sendable (Duration) async throws -> Void

  static let live = ConnectionControllerClock(
    wallNow: { Date() },
    monotonicMilliseconds: {
      DispatchTime.now().uptimeNanoseconds / 1_000_000
    },
    sleep: { duration in try await Task.sleep(for: duration) }
  )
}

private struct RetryNotBefore: Sendable { let wallDeadlineMilliseconds: UInt64 }

private enum ConnectionRetryWake: Sendable { case timer, manual, cancellation }

private actor ConnectionRetryGate {
  private var result: ConnectionRetryWake?
  private var waiter: CheckedContinuation<ConnectionRetryWake, Never>?

  func wait() async -> ConnectionRetryWake {
    if let result { return result }
    return await withCheckedContinuation { continuation in
      if let result { continuation.resume(returning: result) } else { waiter = continuation }
    }
  }

  @discardableResult
  func wake(_ result: ConnectionRetryWake) -> Bool {
    guard self.result == nil else { return false }
    self.result = result
    waiter?.resume(returning: result)
    waiter = nil
    return true
  }
}

private struct CurrentConnectionConfiguration: Sendable {
  let environment: TransportEnvironment
  let source: ConnectionMaterialSource
  let requirements: ConnectionRequirements
  let initializeSession: (@isolated(any) @Sendable (any Session) async throws -> Void)?
  let initializeServiceSession: (@isolated(any) @Sendable (any ServiceInitializerSession) async throws -> Void)?
}
private struct CurrentSessionInitializationFailure: Error, Sendable {
  let facts: ConnectionAttemptFacts?
  init(_ facts: ConnectionAttemptFacts? = nil) { self.facts = facts }
}
