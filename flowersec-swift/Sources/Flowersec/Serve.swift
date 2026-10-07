#if os(macOS) || os(iOS)
import Foundation

/// The configured native carrier is fixed for this aggregate. Signed material
/// still determines the actual endpoint, TLS policy and dialer/listener role.
public enum ServeCarrier: Sendable { case webSocket }
public struct ServeRequestContext: Sendable {
  public let carrier: ServeCarrier
  public let requirements: ConnectionRequirements
}

/// Created only after the original FSB and peer identity have been verified.
/// These immutable authorization references contain no signing or key handles.
public struct AuthenticatedRequestContext: Sendable {
  public let tenant: String
  public let audience: String
  public let clientSubject: String
  public let serverSubject: String
  public let clientIdentityDigest: Data
  public let serverIdentityDigest: Data
  public let artifactDigest: Data
  public let leaseID: Data
  public let attemptID: Data
  public let applicationProfile: String
  init(_ plan: V4DirectPoolPlan) throws {
    tenant = try plan.artifact.t("tenant_id"); audience = try plan.artifact.t("audience")
    clientSubject = try plan.client.t("subject_id"); serverSubject = try plan.server.t("subject_id")
    clientIdentityDigest = plan.credential.certificateDigests[0]
    serverIdentityDigest = plan.credential.certificateDigests[1]
    artifactDigest = plan.credential.artifactDigest; leaseID = try plan.artifact.b("lease_id")
    attemptID = plan.credential.attemptID
    applicationProfile = ["transport", "services", "execution"][Int(plan.applicationProfile)]
  }
}

/// The authority's original reservation owner. close burns unused authority;
/// waitCleanup joins its actual release. Neither operation may create a new
/// authorization or retry a previously submitted application operation. If
/// authorization throws before returning a lease, the callback remains the
/// owner and must settle its reservation before it exits.
public protocol ServeApplicationLease: Sendable {
  func close()
  func waitCleanup() async throws -> CleanupStatus
  func waitPhysicalCleanup() async throws -> CleanupStatus
}

public extension ServeApplicationLease {
  func waitPhysicalCleanup() async throws -> CleanupStatus { try await waitCleanup() }
}

public struct HandlerPlan: Sendable {
  public let streams: StreamHandlers?
  public let services: ServiceRegistry?
  public init(streams: StreamHandlers? = nil, services: ServiceRegistry? = nil) {
    self.streams = streams; self.services = services
  }
}
public struct AuthorizeApplicationResult: Sendable {
  public let lease: any ServeApplicationLease
  public init(lease: any ServeApplicationLease) { self.lease = lease }
}
public enum ServeSessionDisposition: Sendable { case accepted, close }
public enum ServeErrorCode: String, Sendable {
  case configurationCapacity = "configuration_capacity", requestRejected = "request_rejected"
  case applicationRejected = "application_rejected", sourceUnavailable = "source_unavailable"
  case connectionFailed = "connection_failed", onSessionFailed = "on_session_failed"
  case releaseFailed = "release_failed", canceled, closed, deadlineExceeded = "deadline_exceeded"
}
public struct ServeError: Error, Sendable {
  public let code: ServeErrorCode
  public let connection: ConnectionAttemptFacts
  public let cleanup: CleanupStatus
  init(_ code: ServeErrorCode, connection: ConnectionAttemptFacts = .notStarted,
    cleanup: CleanupStatus = CleanupStatus(complete: true)) {
    self.code = code; self.connection = connection; self.cleanup = cleanup
  }
}
public struct ServeReleaseContext: Sendable {
  public let request: AuthenticatedRequestContext?
  public let published: Bool
  public let failure: ServeError?
  public let cleanup: CleanupStatus
}

/// All callbacks and borrowed dependencies are fixed before admission starts.
/// A listener is the SDK's closed server material source, including a live
/// server source's materialSource; it cannot substitute unverified wire input.
public struct ServeOptions: Sendable {
  public let listener: ConnectionMaterialSource
  public let carrier: ServeCarrier
  public let requirements: ConnectionRequirements
  public let maximumConcurrentSessions: Int
  public let maintenanceOwner: ServiceMaintenanceOwner?
  public let authorizeRequest: @isolated(any) @Sendable (ApplicationInvocationContext, ServeRequestContext) async throws -> Void
  public let resolveHandlers: @isolated(any) @Sendable (ApplicationInvocationContext, AuthenticatedRequestContext) async throws -> HandlerPlan
  public let authorizeApplication: @isolated(any) @Sendable (ApplicationInvocationContext, AuthenticatedRequestContext, HandlerPlan) async throws -> AuthorizeApplicationResult
  public let onSession: @isolated(any) @Sendable (ApplicationInvocationContext, any Session) async throws -> ServeSessionDisposition
  public let release: @isolated(any) @Sendable (ApplicationInvocationContext, ServeReleaseContext) async throws -> CleanupStatus
  public init(listener: ConnectionMaterialSource, carrier: ServeCarrier = .webSocket,
    requirements: ConnectionRequirements = ConnectionRequirements(), maximumConcurrentSessions: Int = 8,
    maintenanceOwner: ServiceMaintenanceOwner? = nil,
    authorizeRequest: @escaping @isolated(any) @Sendable (ApplicationInvocationContext, ServeRequestContext) async throws -> Void,
    resolveHandlers: @escaping @isolated(any) @Sendable (ApplicationInvocationContext, AuthenticatedRequestContext) async throws -> HandlerPlan,
    authorizeApplication: @escaping @isolated(any) @Sendable (ApplicationInvocationContext, AuthenticatedRequestContext, HandlerPlan) async throws -> AuthorizeApplicationResult,
    onSession: @escaping @isolated(any) @Sendable (ApplicationInvocationContext, any Session) async throws -> ServeSessionDisposition,
    release: @escaping @isolated(any) @Sendable (ApplicationInvocationContext, ServeReleaseContext) async throws -> CleanupStatus) {
    self.listener = listener; self.carrier = carrier; self.requirements = requirements
    self.maximumConcurrentSessions = maximumConcurrentSessions; self.maintenanceOwner = maintenanceOwner
    self.authorizeRequest = authorizeRequest; self.resolveHandlers = resolveHandlers
    self.authorizeApplication = authorizeApplication; self.onSession = onSession; self.release = release
  }
}

public struct ServeProgress: Sendable {
  public let accepting: Bool
  public let pendingSessions: Int
  public let outcome: SessionDrainOutcome
  public let failure: ServeError?
  public let cleanup: CleanupStatus
}

/// Owns only this aggregate's admissions, Sessions and callback tails. The
/// Environment, material source and handler registries are borrowed.
public final class ServeHandle: Sendable, CustomStringConvertible {
  private let owner: V4ServeOwner
  init(_ owner: V4ServeOwner) { self.owner = owner }
  public func progress() -> ServeProgress { owner.progress() }
  public func drain(timeout: Duration = .seconds(30)) throws { try owner.drain(timeout: timeout) }
  public func waitDrain() async throws -> ServeProgress { try await owner.waitDrain() }
  public func close() { owner.close() }
  public func cleanupStatus() -> CleanupStatus { owner.progress().cleanup }
  public func waitCleanup(timeout: Duration = .seconds(5)) async throws -> CleanupStatus {
    try await owner.waitCleanup(timeout: timeout)
  }
  public var description: String { "Flowersec.ServeHandle(<redacted>)" }
  deinit { owner.close() }
}

// Enter on the callback's actual executor before disclosing its authenticated
// input or claiming publication. An actor hop cannot bypass a winning Drain.
private func v4ServeCallback<Argument: Sendable, Value: Sendable>(isolation: isolated (any Actor)?,
  callback: @isolated(any) @Sendable (ApplicationInvocationContext, Argument) async throws -> Value,
  context: ApplicationInvocationContext, argument: Argument,
  check: @Sendable () throws -> Void) async throws -> Value {
  try context.checkCancellation(); try check()
  return try await callback(context, argument)
}
private func v4ServeCallback<First: Sendable, Second: Sendable, Value: Sendable>(isolation: isolated (any Actor)?,
  callback: @isolated(any) @Sendable (ApplicationInvocationContext, First, Second) async throws -> Value,
  context: ApplicationInvocationContext, first: First, second: Second,
  check: @Sendable () throws -> Void) async throws -> Value {
  try context.checkCancellation(); try check()
  return try await callback(context, first, second)
}

// Cancellation does not detach an application callback or lose a late lease.
// Its original ordinary executor position and continuation remain until exit.
private final class V4ServeInvocation<Value: Sendable>: @unchecked Sendable {
  private let group: V4ApplicationGroup
  private var canceled = false
  private var result: Result<Value, any Error>?
  private var work: V4ApplicationWork?
  init(group: V4ApplicationGroup) { self.group = group }
  func run(_ operation: @escaping @Sendable (ApplicationInvocationContext) async throws -> Value) async throws -> Value {
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        do {
          let original = try group.executor.gate.withLock { () throws -> V4ApplicationWork in
            guard !canceled, !Task.isCancelled else { throw ServeError(.canceled) }
            let original = try V4ApplicationWork(group: group, context: nil, operation: { [self] context in
              let value: Result<Value, any Error>
              do { value = .success(try await operation(context)) } catch { value = .failure(error) }
              group.executor.gate.withLock { result = value }
            }, onExit: { [self] in
              let value = result ?? .failure(ServeError(.canceled))
              result = nil; work = nil; continuation.resume(with: value)
            })
            work = original; return original
          }
          original.start()
        } catch { continuation.resume(throwing: error) }
      }
    } onCancel: {
      self.group.executor.gate.withLock { self.canceled = true; self.work?.cancel() }
    }
  }
}

final class V4ServeAdmission: @unchecked Sendable {
  let id = UUID()
  private let owner: V4ServeOwner
  private(set) var request: AuthenticatedRequestContext?
  private(set) var handlers: HandlerPlan?
  private var lease: (any ServeApplicationLease)?
  private var facts: V4ConnectionFacts?
  private var leaseClosed = false
  private var releaseResult: Bool?
  private(set) var releaseCleanupIncomplete = false
  private var durableAdmissionClaimed = false
  private var materialCleanup: ConnectionMaterial?
  var cleanupOnly = false
  var admissionTimer: Task<Void, Never>?
  var session: (any Session)?
  var worker: Task<Void, Never>?
  var cleanupWorker: Task<Void, Never>?
  var admissionWorker: Task<Void, Never>?
  var dispatch: Task<Void, Never>?
  var published = false
  var failure: ServeError?
  init(_ owner: V4ServeOwner) { self.owner = owner }
  func startDeadline() throws { try owner.startAdmissionDeadline(self) }
  func withAdmission<Value>(_ body: () throws -> Value) throws -> Value {
    try owner.environment.gate.withLock {
      try owner.checkAdmission()
      if let failure { throw failure }
      guard !cleanupOnly else { throw ServeError(.closed) }
    }
    let value = try body()
    try owner.environment.gate.withLock {
      try owner.checkAdmission()
      if let failure { throw failure }
      guard !cleanupOnly else { throw ServeError(.closed) }
    }
    return value
  }
  func withAdmissionCritical<Value>(_ body: () throws -> Value) throws -> Value {
    try owner.environment.gate.withLock {
      try owner.checkAdmission()
      if let failure { throw failure }
      guard !cleanupOnly else { throw ServeError(.closed) }
      return try body()
    }
  }
  func withDurableAdmission<Value>(_ body: () throws -> Value) throws -> Value {
    try withAdmissionCritical {
      guard !durableAdmissionClaimed else { throw ServeError(.closed) }
      // The admission worker already retains the original execution tail for
      // this entry. Keep the aggregate guard short while storage uses it.
      durableAdmissionClaimed = true
    }
    let value = try body()
    try withAdmission {}
    return value
  }
  func transferMaterialCleanup(_ material: ConnectionMaterial) {
    // Material ownership must be recorded even after Drain/Close fences new
    // admission work. This is cleanup accounting, not admission authorization.
    owner.environment.gate.withLock {
      if materialCleanup == nil { materialCleanup = material }
    }
  }
  func authorize(_ plan: V4DirectPoolPlan) async throws -> V4PreparedStreamHandlers? {
    guard plan.role == .server, request == nil else { throw ServeError(.configurationCapacity) }
    let metadata = try AuthenticatedRequestContext(plan)
    request = metadata; facts = plan.credential.connectionFacts
    do {
      let handlers = try await owner.invoke { [self, owner] context in
        let callback = owner.options.resolveHandlers
        return try await v4ServeCallback(isolation: callback.isolation, callback: callback,
          context: context, argument: metadata, check: { try self.withAdmission {} })
      }
      self.handlers = handlers
      try withAdmissionCritical {
        if let registry = handlers.services {
          guard registry.environment === owner.environment, plan.applicationProfile > 0 else { throw ServeError(.configurationCapacity) }
          try registry.freezeSessionPlan()
          if let maintenance = owner.options.maintenanceOwner {
            guard registry.configuration.maintenanceOwner === maintenance else { throw ServeError(.configurationCapacity) }
          }
        }
      }
      let prepared = try handlers.streams?.prepare(in: owner.environment)
      let authorization = try await owner.invoke { [self, owner] context in
        let callback = owner.options.authorizeApplication
        return try await v4ServeCallback(isolation: callback.isolation, callback: callback,
          context: context, first: metadata, second: handlers, check: { try self.withAdmission {} })
      }
      lease = authorization.lease
      try Task.checkCancellation(); try withAdmission {}
      return prepared
    } catch {
      let code = (error as? ServeError)?.code ?? (Task.isCancelled ? .canceled : .applicationRejected)
      failure = ServeError(code, connection: plan.credential.connectionFacts.snapshot())
      throw error
    }
  }
  func cancelDeadline() async {
    let timer = owner.environment.gate.withLock { () -> Task<Void, Never>? in
      defer { admissionTimer = nil }; return admissionTimer
    }
    timer?.cancel(); await timer?.value
  }

  func releaseAfterCleanup() async -> Bool {
    // This runs on an independent original cleanup task even when the request
    // waiter was canceled. The authority lease is released exactly once.
    var cleanup = CleanupStatus(complete: true)
    if let material = materialCleanup {
      material.close()
      cleanup = await material.waitPhysicalCleanup()
      guard cleanup.complete else {
        failure = ServeError(.releaseFailed, connection: facts?.snapshot() ?? .notStarted, cleanup: cleanup)
        return false
      }
      materialCleanup = nil
    }
    if let lease {
      if !leaseClosed { leaseClosed = true; lease.close() }
      do { cleanup = try await lease.waitPhysicalCleanup() }
      catch { cleanup = CleanupStatus(cleanupIncomplete: true); failure = ServeError(.releaseFailed, connection: facts?.snapshot() ?? .notStarted, cleanup: cleanup) }
      guard cleanup.complete else { return false }
      self.lease = nil
    }
    if releaseResult != nil { return true }
    let status = ServeReleaseContext(request: request, published: published, failure: failure, cleanup: cleanup)
    do {
      let released = try await owner.invoke { [owner] context in
        let callback = owner.options.release
        return try await v4ServeCallback(isolation: callback.isolation, callback: callback,
          context: context, argument: status, check: {})
      }
      // The release callback result is an application outcome. Physical
      // material/lease cleanup is already complete here, so a false result
      // must not keep scheduling cleanup workers forever.
      releaseResult = released.complete
      if !released.complete {
        releaseCleanupIncomplete = true
        failure = ServeError(.releaseFailed, connection: facts?.snapshot() ?? .notStarted, cleanup: released)
      }
      return true
    } catch {
      releaseResult = false
      releaseCleanupIncomplete = true
      failure = ServeError(.releaseFailed, connection: facts?.snapshot() ?? .notStarted, cleanup: CleanupStatus(cleanupIncomplete: true))
      return true
    }
  }
}

final class V4ServeOwner: V4NativeConnectionLifecycle, @unchecked Sendable {
  let environment: V4EnvironmentFoundation
  let options: ServeOptions
  private let client: V4ClientEnvironment
  private let storage: V4CryptoReservation
  private let group: V4ApplicationGroup
  private let events = V4SessionEvents(maximum: 128)
  private var entries: [UUID: V4ServeAdmission] = [:]
  private var accepting = true
  private var acceptTask: Task<Void, Never>?
  private var acceptFinished = false
  private var closeTask: Task<Void, Never>?
  private var drainTimer: Task<Void, Never>?
  private var drainTimerFinished = true
  private var drainDeadline: ContinuousClock.Instant?
  private var outcome: SessionDrainOutcome = .draining
  private var failure: ServeError?
  private var cleanupIncomplete = false
  private var releaseIncomplete = false
  private var finished = false
  init(client: V4ClientEnvironment, options: ServeOptions) throws {
    environment = client.foundation; self.client = client; self.options = options
    try V4DirectEstablishment.requirements(options.requirements)
    if let maintenance = options.maintenanceOwner {
      guard maintenance.environment === environment else { throw ServeError(.configurationCapacity) }
      try maintenance.check()
    }
    storage = try environment.serveStorage(maximumSessions: options.maximumConcurrentSessions)
    group = try environment.applicationGroup()
    entries.reserveCapacity(options.maximumConcurrentSessions)
    try environment.registerNativeConnection(self)
  }
  func start() throws {
    try environment.gate.withLock {
      try checkAdmission()
      let tail = try storage.executionTail()
      acceptTask = Task { [self] in
        defer {
          tail.release()
          environment.gate.withLock { acceptFinished = true; acceptTask = nil; collect() }
          events.signal()
        }
        await acceptLoop()
      }
    }
  }
  func startAdmissionDeadline(_ entry: V4ServeAdmission) throws {
    try environment.gate.withLock {
      try checkAdmission()
      guard entries[entry.id] === entry, entry.admissionTimer == nil else { throw ServeError(.closed) }
      entry.admissionTimer = Task { [weak self, weak entry] in
        do { try await ContinuousClock().sleep(for: .milliseconds(Int64(FlowersecSDKDefaults.Transport.handshakeTimeoutMilliseconds))) }
        catch { return }
        guard let self, let entry else { return }
        environment.gate.withLock {
          if entries[entry.id] === entry, entry.session == nil {
            entry.failure = ServeError(.deadlineExceeded); entry.admissionWorker?.cancel()
          }
        }
      }
    }
  }
  func invoke<Value: Sendable>(_ operation: @escaping @Sendable (ApplicationInvocationContext) async throws -> Value) async throws -> Value {
    try await V4ServeInvocation<Value>(group: group).run(operation)
  }
  func checkAdmission() throws {
    guard accepting else { throw ServeError(.closed, cleanup: progress().cleanup) }
    try storage.check(); try options.maintenanceOwner?.check(); try Task.checkCancellation()
  }
  private func acceptLoop() async {
    while true {
      let version = events.revision
      do {
        let entry = try environment.gate.withLock { () throws -> V4ServeAdmission? in
          try checkAdmission()
          guard entries.count < options.maximumConcurrentSessions else { return nil }
          let entry = V4ServeAdmission(self)
          let tail = try storage.executionTail()
          entries[entry.id] = entry
          entry.admissionWorker = Task { [self, entry] in
            defer { tail.release() }
            await admit(entry)
          }
          return entry
        }
        guard let entry else { try await events.wait(after: version); continue }
        let attempt = environment.gate.withLock { entry.admissionWorker }
        await withTaskCancellationHandler {
          await attempt?.value
        } onCancel: { attempt?.cancel() }
        environment.gate.withLock { entry.admissionWorker = nil }
        // A rejected request or consumed failed handshake belongs to one
        // attempt. A bounded cadence prevents an empty/rejecting source from
        // spinning without making healthy siblings enter Drain.
        if entry.failure != nil { try await ContinuousClock().sleep(for: .milliseconds(250)) }
      } catch {
        if !Task.isCancelled { try? drain(timeout: .seconds(30)) }
        return
      }
    }
  }
  private func admit(_ entry: V4ServeAdmission) async {
    do {
      // This policy precedes taking a source's original carrier/admission
      // right. A live source may independently own an earlier preparation.
      do {
        try await invoke { [options] context in
          let callback = options.authorizeRequest
          try await v4ServeCallback(isolation: callback.isolation, callback: callback, context: context,
            argument: ServeRequestContext(carrier: options.carrier, requirements: options.requirements),
            check: { try self.environment.gate.withLock { try self.checkAdmission() } })
        }
      } catch {
        entry.failure = ServeError(Task.isCancelled ? .canceled : .requestRejected)
        throw error
      }
      try entry.withAdmission {}
      let session = try await client.connect(source: options.listener, requirements: options.requirements,
        notificationPlan: nil, serve: entry)
      await entry.cancelDeadline()
      do {
        try entry.withAdmissionCritical {
          let tail = try storage.executionTail()
          entry.session = session
          entry.worker = Task { [self, entry] in await serveSession(entry, session: session, tail: tail) }
        }
      } catch {
        try? await session.close()
        if let native = session as? V4NativeSession { await native.waitPhysicalCleanup() }
        throw error
      }
    } catch {
      let sourceClosed = entry.failure == nil && (error as? ConnectionMaterialSourceError) == .closed
      let projected: ServeError
      if let error = error as? ServeError { projected = error }
      else if let error = error as? ConnectError { projected = ServeError(.connectionFailed, connection: error.connection, cleanup: error.cleanup) }
      else { projected = ServeError(Task.isCancelled ? .canceled : .sourceUnavailable) }
      if let original = entry.failure {
        entry.failure = ServeError(original.code, connection: projected.connection, cleanup: projected.cleanup)
      } else { entry.failure = projected }
      let cleanup = Task { [self, entry] in await finish(entry) }
      await cleanup.value
      let groupFenced = environment.gate.withLock { () -> Bool in
        failure = entry.failure
        if !accepting { return false }
        if sourceClosed { return true }
        do { try storage.check(); try options.maintenanceOwner?.check(); return false }
        catch { return true }
      }
      if groupFenced { try? drain(timeout: .seconds(30)) }
    }
  }
  private func serveSession(_ entry: V4ServeAdmission, session: any Session, tail: V4ResourceReference) async {
    await withTaskCancellationHandler {
      do {
        let disposition = try await invoke { [options, entry] context in
          let callback = options.onSession
          return try await v4ServeCallback(isolation: callback.isolation, callback: callback,
            context: context, argument: session, check: {
              try entry.withAdmissionCritical {
                try (session as? any V4ServiceSession)?.checkServiceSession()
                try (session as? V4NativeSession)?.publishApplication()
                entry.published = true
                (session as? V4ConnectionFactsOwner)?.connectionFactsOwner.published()
                if let streams = entry.handlers?.streams {
                  entry.dispatch = Task { try? await streams.serve(session: session) }
                }
              }
            })
        }
        if case .close = disposition { try? await session.close() }
        _ = await session.waitTermination()
      } catch {
        if !environment.gate.withLock({ entry.published }) {
          (session as? V4ConnectionFactsOwner)?.connectionFactsOwner.publicationFailed()
        }
        entry.failure = ServeError(Task.isCancelled ? .canceled : .onSessionFailed,
          connection: (session as? V4ConnectionFactsOwner)?.connectionFactsOwner.snapshot() ?? .unobserved,
          cleanup: CleanupStatus(cleanupIncomplete: true))
      }
      // Cancellation must not abandon handlers or authority cleanup.
      let cleanup = Task { [self, entry] in
        try? await session.close()
        let dispatch = environment.gate.withLock { entry.dispatch }
        dispatch?.cancel(); await dispatch?.value
        environment.gate.withLock { entry.dispatch = nil }
        if let native = session as? V4NativeSession { await native.waitPhysicalCleanup() }
        await finish(entry, tail: tail)
      }
      await cleanup.value
    } onCancel: { self.environment.gate.withLock { entry.dispatch?.cancel() } }
  }
  private func finish(_ entry: V4ServeAdmission, tail: V4ResourceReference? = nil) async {
    await entry.cancelDeadline()
    let complete = await entry.releaseAfterCleanup()
    tail?.release()
    environment.gate.withLock {
      if let error = entry.failure { failure = error }
      entry.session = nil; entry.cleanupOnly = true; entry.worker = nil
      releaseIncomplete = releaseIncomplete || entry.releaseCleanupIncomplete
      if complete { entries.removeValue(forKey: entry.id) }
      cleanupIncomplete = releaseIncomplete || entries.values.contains { $0.cleanupOnly }
      collect()
    }
    if !complete { startCleanupWaiter(entry) }
    events.signal()
  }
  private func startCleanupWaiter(_ entry: V4ServeAdmission) {
    environment.gate.withLock {
      guard entries[entry.id] === entry, entry.cleanupOnly, entry.worker == nil,
        entry.cleanupWorker == nil else { return }
      entry.cleanupWorker = Task { [self, entry] in
        defer {
          environment.gate.withLock { entry.cleanupWorker = nil }
          events.signal()
        }
        while true {
          do { try await ContinuousClock().sleep(for: environment.cleanupTimeout) }
          catch { return }
          await finish(entry)
          if environment.gate.withLock({ entries[entry.id] == nil }) { return }
        }
      }
    }
  }
  private func resumeIncompleteCleanup() {
    environment.gate.withLock {
      for entry in entries.values where entry.cleanupOnly && entry.worker == nil {
        if entry.cleanupWorker == nil { startCleanupWaiter(entry) }
      }
    }
  }
  private func collect() {
    guard !accepting, acceptFinished, entries.isEmpty, closeTask == nil, !finished else { return }
    drainTimer?.cancel()
    guard drainTimerFinished else { return }
    finished = true; drainTimer = nil
    if outcome == .draining { outcome = .drained }
    // The ordinary executor group belongs to the shared Environment.
    storage.seal(); environment.retireNativeConnection(self)
  }
  func drain(timeout: Duration) throws {
    let sessions = try environment.gate.withLock { () throws -> [any Session] in
      guard timeout > .zero, timeout <= .seconds(30) else { throw ServeError(.configurationCapacity) }
      if drainDeadline != nil || finished { return [] }
      drainDeadline = ContinuousClock.now.advanced(by: timeout); accepting = false
      acceptTask?.cancel()
      let deadline = drainDeadline!
      drainTimerFinished = false
      drainTimer = Task { [self] in
        defer { environment.gate.withLock { drainTimerFinished = true; collect() }; events.signal() }
        do { try await ContinuousClock().sleep(until: deadline) } catch { return }
        environment.gate.withLock { outcome = .deadlineAborted }
        close()
      }
      collect(); return entries.values.compactMap { $0.session }
    }
    for session in sessions { _ = try? session.drain(timeout: timeout) }
    events.signal()
  }
  func close() {
    environment.gate.withLock {
      guard !finished, closeTask == nil else { return }
      accepting = false; acceptTask?.cancel(); drainTimer?.cancel(); drainTimer = nil
      if outcome == .draining { outcome = .terminated }
      let sessions = entries.values.compactMap { $0.session }
      for entry in entries.values { entry.admissionWorker?.cancel(); entry.worker?.cancel() }
      closeTask = Task { [self] in
        for session in sessions { try? await session.close() }
        environment.gate.withLock { closeTask = nil; collect() }; events.signal()
      }
    }
    events.signal()
  }
  func progress() -> ServeProgress {
    environment.gate.withLock {
      ServeProgress(accepting: accepting, pendingSessions: entries.count, outcome: outcome, failure: failure,
        cleanup: CleanupStatus(complete: finished && !cleanupIncomplete,
          cleanupIncomplete: cleanupIncomplete || releaseIncomplete || (!accepting && !finished),
          pendingCallbacks: UInt64(entries.count + (acceptFinished ? 0 : 1))))
    }
  }
  func waitDrain() async throws -> ServeProgress {
    while true {
      let version = events.revision
      let value = progress()
      if !value.accepting, value.outcome != .draining { return value }
      do { try await events.wait(after: version) }
      catch { throw ServeError(.canceled, cleanup: progress().cleanup) }
    }
  }
  func waitCleanup(timeout: Duration) async throws -> CleanupStatus {
    guard timeout > .zero, timeout <= .seconds(30) else { throw ServeError(.configurationCapacity) }
    resumeIncompleteCleanup()
    return try await withThrowingTaskGroup(of: CleanupStatus.self) { tasks in
      tasks.addTask { [self] in
        while true {
          let version = events.revision
          // Completion and its cleanup outcome must come from the same
          // snapshot; a concurrent final release can retire the last entry.
          let (value, isFinished) = environment.gate.withLock { (progress(), finished) }
          if value.cleanup.complete { return value.cleanup }
          if isFinished { throw ServeError(.releaseFailed, cleanup: value.cleanup) }
          try await events.wait(after: version)
        }
      }
      tasks.addTask { [self] in
        try await ContinuousClock().sleep(for: timeout)
        throw ServeError(.deadlineExceeded, cleanup: progress().cleanup)
      }
      defer { tasks.cancelAll() }
      do { return try await tasks.next()! }
      catch let error as ServeError { throw error }
      catch { throw ServeError(.canceled, cleanup: progress().cleanup) }
    }
  }
}
#endif
