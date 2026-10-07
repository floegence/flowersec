import Foundation

public enum SessionDrainOutcome: String, Sendable {
  case draining, drained, deadlineAborted = "deadline_aborted", terminated
}

public struct SessionDrainProgress: Sendable {
  public let outcome: SessionDrainOutcome
  public let cleanup: CleanupStatus
}

protocol V4SessionDrainOwner: AnyObject, Sendable {
  func progress() -> SessionDrainProgress
  func wait() async throws -> SessionDrainProgress
}

/// Repeated Drain calls observe the same original operation and deadline.
/// Canceling a wait does not reopen admission or cancel already admitted work.
public final class SessionDrainOperation: Sendable {
  private let owner: any V4SessionDrainOwner
  init(_ owner: any V4SessionDrainOwner) { self.owner = owner }
  public func progress() -> SessionDrainProgress { owner.progress() }
  public func wait() async throws -> SessionDrainProgress { try await owner.wait() }
}

extension Session {
  public func drain(timeout: Duration = .seconds(30)) throws -> SessionDrainOperation {
    #if os(macOS) || os(iOS)
    guard let original = self as? V4NativeSession else { throw SessionError.operationFailed }
    return try original.beginDrain(timeout: timeout)
    #else
    throw SessionError.operationFailed
    #endif
  }
}

protocol V4ControllerHandoffReservation: AnyObject, Sendable {
  func check() throws
  func takeNotification(token: UUID, in environment: V4EnvironmentFoundation) throws -> V4CryptoReservation
  func takeInitialization(in environment: V4EnvironmentFoundation) throws -> V4CryptoReservation
  func finishCandidate()
  func takeSessionResources(in environment: V4EnvironmentFoundation, plan: V4DirectPoolPlan) throws -> V4PrepaidSessionResources
  func takeNativeConnection(in environment: V4EnvironmentFoundation, maximumFrame: Int) throws -> V4CryptoReservation
  func release()
}

#if os(macOS) || os(iOS)
final class V4NativeHandoffReservation: V4ControllerHandoffReservation, @unchecked Sendable {
  private let gate = NSLock()
  private var storage: V4CryptoReservation?
  private var tail: V4ResourceReference?
  private var nativeStorage: V4CryptoReservation?
  private var sessionResources: V4PrepaidSessionResources?
  private let maximumFrame: Int
  private var initializationStorage: V4CryptoReservation?
  private var notificationStorage: [UUID: V4CryptoReservation]
  init(_ storage: V4CryptoReservation, nativeStorage: V4CryptoReservation,
    sessionResources: V4PrepaidSessionResources, maximumFrame: Int, initializationStorage: V4CryptoReservation, notificationStorage: [UUID: V4CryptoReservation]) throws {
    self.storage = storage; self.nativeStorage = nativeStorage; self.sessionResources = sessionResources
    self.maximumFrame = maximumFrame; self.initializationStorage = initializationStorage
    self.notificationStorage = notificationStorage; tail = try storage.executionTail()
  }
  func takeNotification(token: UUID, in environment: V4EnvironmentFoundation) throws -> V4CryptoReservation {
    try gate.withLock {
      guard let storage, let reference = notificationStorage.removeValue(forKey: token), reference.environment === environment else {
        throw ServiceFailure.configurationCapacity
      }
      try storage.check(); try reference.check()
      return reference
    }
  }
  func takeInitialization(in environment: V4EnvironmentFoundation) throws -> V4CryptoReservation {
    try gate.withLock {
      guard let storage, let initializationStorage, initializationStorage.environment === environment else { throw SessionError.closed }
      try storage.check(); try initializationStorage.check()
      self.initializationStorage = nil
      return initializationStorage
    }
  }
  func finishCandidate() { gate.withLock {
    initializationStorage?.seal(); initializationStorage = nil
    for reference in notificationStorage.values { reference.seal() }; notificationStorage.removeAll()
  } }
  func takeSessionResources(in environment: V4EnvironmentFoundation, plan: V4DirectPoolPlan) throws -> V4PrepaidSessionResources {
    try gate.withLock {
      guard let storage, let sessionResources else { throw SessionError.closed }
      try storage.check(); try sessionResources.check(in: environment, plan: plan)
      self.sessionResources = nil
      return sessionResources
    }
  }
  func check() throws { try gate.withLock { guard let storage else { throw SessionError.closed }; try storage.check() } }
  func takeNativeConnection(in environment: V4EnvironmentFoundation, maximumFrame: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard let storage, let nativeStorage, storage.environment === environment,
        nativeStorage.environment === environment, (304...self.maximumFrame).contains(maximumFrame) else { throw SessionError.resourceExhausted }
      try storage.check(); try nativeStorage.check()
      self.nativeStorage = nil
      return nativeStorage
    }
  }
  func release() { gate.withLock { for reference in notificationStorage.values { reference.seal() }; notificationStorage.removeAll(); initializationStorage?.seal(); initializationStorage = nil; sessionResources?.release(); sessionResources = nil; nativeStorage?.seal(); nativeStorage = nil; storage?.seal(); storage = nil; tail?.release(); tail = nil } }
  deinit { release() }
}

final class V4NativeSessionDrain: V4SessionDrainOwner, @unchecked Sendable {
  private let gate = NSLock()
  private weak var session: V4NativeSession?
  private let deadline: ContinuousClock.Instant
  private var storage: V4CryptoReservation?
  private var task: Task<Void, Never>?
  private var outcome: SessionDrainOutcome = .draining
  private var finished = false
  init(session: V4NativeSession, deadline: ContinuousClock.Instant, storage: V4CryptoReservation) {
    self.session = session; self.deadline = deadline; self.storage = storage
  }
  func start() throws {
    try gate.withLock {
      guard task == nil, !finished, let session, let storage else { throw SessionError.closed }
      let tail = try storage.executionTail()
      task = Task { [self] in
      defer { tail.release(); gate.withLock { finished = true; task = nil; self.storage?.seal(); self.storage = nil } }
      var result: SessionDrainOutcome = .terminated
      do {
        while true {
          try storage.check()
          if ContinuousClock.now >= deadline { result = .deadlineAborted; break }
          if try await session.drainBusinessComplete() { result = .drained; break }
          try await ContinuousClock().sleep(for: .milliseconds(10))
        }
      } catch { result = .terminated }
      gate.withLock { outcome = result }
      await session.finishDrain()
      // Actual callback and publisher exits retain their original owners even
      // after the close deadline. They cannot refund the retirement position.
      while await session.retirementPendingCallbacks() > 0 {
        try? await ContinuousClock().sleep(for: .milliseconds(10))
      }
      }
    }
  }
  func progress() -> SessionDrainProgress {
    gate.withLock { SessionDrainProgress(outcome: outcome, cleanup: CleanupStatus(complete: finished, cleanupIncomplete: outcome != .draining && !finished)) }
  }
  func wait() async throws -> SessionDrainProgress {
    while true {
      try Task.checkCancellation()
      let status = progress()
      if status.outcome != .draining { return status }
      try await ContinuousClock().sleep(for: .milliseconds(10))
    }
  }
}
#endif

public enum ConnectionReplacementRetirement: Sendable {
  case drain(timeout: Duration)
  case retain(for: Duration)
}
public enum SessionRetirementState: String, Sendable { case retained, draining, closing, closed }
public struct SessionRetirementProgress: Sendable {
  public let state: SessionRetirementState
  public let deadline: ContinuousClock.Instant
  public let cleanup: CleanupStatus
}

/// The old Session keeps its own routing and authorization. Its retirement
/// deadline never changes when another handle observes or waits on it.
public final class SessionRetirement: @unchecked Sendable {
  private let gate = NSLock()
  private let session: any Session
  private let plan: V4ControllerNotificationPlan?
  private let reservation: any V4ControllerHandoffReservation
  private let deadline: ContinuousClock.Instant
  private let policy: ConnectionReplacementRetirement
  private var state: SessionRetirementState
  private var finished = false
  private var task: Task<Void, Never>?
  init(session: any Session, plan: V4ControllerNotificationPlan?, deadline: ContinuousClock.Instant,
    policy: ConnectionReplacementRetirement, reservation: any V4ControllerHandoffReservation) {
    self.session = session; self.plan = plan; self.deadline = deadline; self.policy = policy; self.reservation = reservation
    if case .retain = policy { state = .retained } else { state = .draining }
  }
  func start() {
    gate.withLock {
      guard task == nil, !finished else { return }
      task = Task { [self] in
      defer { reservation.release(); gate.withLock { finished = true; task = nil } }
      switch policy {
      case .retain:
        do { try await ContinuousClock().sleep(until: deadline) } catch {}
      case .drain:
        let remaining = ContinuousClock.now.duration(to: deadline)
        if remaining > .zero, let drain = try? session.drain(timeout: remaining) {
          _ = try? await drain.wait()
        }
      }
      gate.withLock { state = .closing }
      try? await session.close()
      plan?.retire()
      #if os(macOS) || os(iOS)
      if let native = session as? V4NativeSession {
        // Cancellation wakes retention, while this separately prepaid original
        // cleanup task observes actual exits without a canceled sleep spin.
        let cleanup = Task {
          while await native.retirementPendingCallbacks() > 0 {
            try? await ContinuousClock().sleep(for: .milliseconds(10))
          }
        }
        await cleanup.value
      }
      #endif
      gate.withLock { state = .closed }
      }
    }
  }
  public func progress() -> SessionRetirementProgress {
    gate.withLock { SessionRetirementProgress(state: state, deadline: deadline,
      cleanup: CleanupStatus(complete: finished, cleanupIncomplete: state == .closing && !finished)) }
  }
  public func wait() async throws -> SessionRetirementProgress {
    while true {
      try Task.checkCancellation()
      let status = progress(); if status.cleanup.complete { return status }
      try await ContinuousClock().sleep(for: .milliseconds(10))
    }
  }
  func close() async {
    let original = gate.withLock { task }
    original?.cancel()
    try? await session.close()
    // The original task keeps the actual callback owners and reservation.
    // Closing a handle is bounded; it never refunds an unfinished tail.
    let until = ContinuousClock.now.advanced(by: .seconds(5))
    while !progress().cleanup.complete, ContinuousClock.now < until, !Task.isCancelled {
      do { try await ContinuousClock().sleep(for: .milliseconds(10)) } catch { break }
    }
  }
}

public struct ConnectionReplacementResult: Sendable {
  public let currentSwitched: Bool
  public let generation: UInt64
  public let currentSession: any Session
  public let previousSession: (any Session)?
  public let retirement: SessionRetirement?
}

/// Finite replacement ceilings are reserved before Acquire. Omitting this
/// value uses the current Session's signed limits. A candidate may narrow the
/// limits, but growing them requires an explicit prepaid capacity.
public struct ConnectionReplacementCapacity: Sendable {
  public let maximumFrameBytes: Int
  public let maximumStreams: Int
  public let maximumCreditBytes: UInt64
  public let maximumGeneralOutstanding: Int
  public let applicationProfile: String
  public init(maximumFrameBytes: Int, maximumStreams: Int, maximumCreditBytes: UInt64,
    maximumGeneralOutstanding: Int, applicationProfile: String) {
    self.maximumFrameBytes = maximumFrameBytes; self.maximumStreams = maximumStreams
    self.maximumCreditBytes = maximumCreditBytes; self.maximumGeneralOutstanding = maximumGeneralOutstanding
    self.applicationProfile = applicationProfile
  }
  var profile: UInt64? { ["transport", "services", "execution"].firstIndex(of: applicationProfile).map(UInt64.init) }
  var slots: Int { min(2 * maximumStreams + 128, 4096) + 128 }
  func check() throws {
    guard (304...1_048_576).contains(maximumFrameBytes), (1...1024).contains(maximumStreams),
      maximumCreditBytes >= UInt64(maximumStreams), maximumCreditBytes <= 8 << 20,
      let profile, profile == 0 || (1...1024).contains(maximumGeneralOutstanding) else { throw ServiceFailure.configurationCapacity }
  }
}

enum V4PrepaidSessionResource: Hashable { case native, reliable, handshake, services, publisher, receiver, management, server, serverManagement, rpcCarrier(Int) }
final class V4PrepaidSessionResources: @unchecked Sendable {
  private let gate = NSLock()
  private let environment: V4EnvironmentFoundation
  private let capacity: ConnectionReplacementCapacity
  private var storage: [V4PrepaidSessionResource: V4CryptoReservation] = [:]
  init(environment: V4EnvironmentFoundation, capacity: ConnectionReplacementCapacity) throws {
    try capacity.check()
    self.environment = environment; self.capacity = capacity
    storage[.native] = try environment.nativeSessionStorage(slots: capacity.slots)
    storage[.reliable] = try environment.reliableSessionStorage(maxCredit: capacity.maximumCreditBytes, slots: capacity.slots)
    storage[.handshake] = try environment.reserveHandshake()
    if capacity.profile! > 0 {
      storage[.services] = try environment.rpcServicesStorage(maximumGeneral: capacity.maximumGeneralOutstanding, execution: capacity.profile == 2)
      for index in 0..<8 { storage[.rpcCarrier(index)] = try environment.rpcServicesDynamicStorage(execution: false) }
      storage[.publisher] = try environment.notificationPublisherStorage()
      storage[.receiver] = try environment.notificationReceiverStorage()
      if capacity.profile == 2 { storage[.management] = try environment.executionManagementStorage() }
      if let registry = environment.serviceRegistry {
        storage[.server] = try environment.serviceServerSessionStorage(maximumGeneral: capacity.maximumGeneralOutstanding)
        if registry.needsManagementStorage { storage[.serverManagement] = try environment.executionManagementStorage() }
      }
    }
  }
  func check(in original: V4EnvironmentFoundation, plan: V4DirectPoolPlan) throws {
    try gate.withLock {
      guard original === environment, plan.environment === environment,
        plan.route.maximumFrame <= capacity.maximumFrameBytes, plan.maxStreams <= capacity.maximumStreams,
        plan.maxCredit <= capacity.maximumCreditBytes, plan.applicationProfile <= capacity.profile!,
        plan.applicationProfile == 0 || plan.maximumGeneralOutstanding <= capacity.maximumGeneralOutstanding
      else { throw ServiceFailure.configurationCapacity }
      for reference in storage.values { try reference.check() }
    }
  }
  func take(_ resource: V4PrepaidSessionResource) throws -> V4CryptoReservation {
    try gate.withLock {
      guard let reference = storage.removeValue(forKey: resource) else { throw ServiceFailure.configurationCapacity }
      try reference.check()
      return reference
    }
  }
  func release() { gate.withLock { for reference in storage.values { reference.seal() }; storage.removeAll() } }
  deinit { release() }
}
