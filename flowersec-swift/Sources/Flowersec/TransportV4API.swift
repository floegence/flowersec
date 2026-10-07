import Foundation

public enum ConnectionEndpointRole: UInt8, Sendable { case client = 0, server = 1 }

public struct ConnectionRequirements: Sendable, Equatable {
  public var independentReliableReadProgress: Bool
  public var boundStreamInputIsolation: Bool
  public var datagram: Bool
  public var localConsumerTLS13Verification: Bool
  public var applicationProfile: String?
  var nativeListenerAcceptance = false

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

extension CleanupStatus {
  // Observations may cover the same original physical tail. Preserve their
  // refusal without counting one callback twice at nested error boundaries.
  func preserving(_ other: CleanupStatus) -> CleanupStatus {
    CleanupStatus(complete: complete && other.complete,
      cleanupIncomplete: cleanupIncomplete || other.cleanupIncomplete,
      pendingCallbacks: max(pendingCallbacks, other.pendingCallbacks))
  }
}

public enum TransportAvailabilityError: Error, Sendable {
  case runtimeUnavailable
}

// Only authenticated current assembly may supply these original material owners.
protocol ConnectionMaterialOwner: Sendable {
  func close()
  func waitCleanup() async throws -> CleanupStatus
  func waitPhysicalCleanup() async -> CleanupStatus
  func cleanupStatus() -> CleanupStatus
}

extension ConnectionMaterialOwner {
  func waitPhysicalCleanup() async -> CleanupStatus { (try? await waitCleanup()) ?? cleanupStatus() }
}

public final class ConnectionMaterial: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
  let owner: any ConnectionMaterialOwner
  init(owner: any ConnectionMaterialOwner) { self.owner = owner }
  public func close() { owner.close() }
  public func waitCleanup() async throws -> CleanupStatus { try await owner.waitCleanup() }
  func waitPhysicalCleanup() async -> CleanupStatus { await owner.waitPhysicalCleanup() }
  public func cleanupStatus() -> CleanupStatus { owner.cleanupStatus() }
  public var description: String { "Flowersec.ConnectionMaterial(<redacted>)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, children: EmptyCollection<(label: String?, value: Any)>()) }
  deinit { owner.close() }
}

public enum ConnectionMaterialSourceError: String, Error, Sendable {
  case closed
  case exhausted
  case generationConflict = "generation_conflict"
}

protocol ConnectionMaterialSourceOwner: Sendable {
  func acquire(_ requirements: ConnectionRequirements) async throws -> ConnectionMaterial
  func close()
  func cleanupStatus() -> CleanupStatus
  func waitCleanup() async throws -> CleanupStatus
}

extension ConnectionMaterialSourceOwner {
  func close() {}
  func cleanupStatus() -> CleanupStatus { CleanupStatus(complete: true) }
  func waitCleanup() async throws -> CleanupStatus { cleanupStatus() }
}

/// A closed SDK source. The TransportEnvironment fixes its activation profile, trusted
/// provider and authority configuration; Acquire captures one complete local
/// identity generation before preparing its matching independently usable lease.
public final class ConnectionMaterialSource: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
  let owner: any ConnectionMaterialSourceOwner
  init(owner: any ConnectionMaterialSourceOwner) { self.owner = owner }
  public func acquire(_ requirements: ConnectionRequirements = ConnectionRequirements()) async throws -> ConnectionMaterial {
    try await owner.acquire(requirements)
  }
  public func close() { owner.close() }
  public func cleanupStatus() -> CleanupStatus { owner.cleanupStatus() }
  public func waitCleanup() async throws -> CleanupStatus { try await owner.waitCleanup() }
  public var description: String { "Flowersec.ConnectionMaterialSource(<redacted>)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, children: EmptyCollection<(label: String?, value: Any)>()) }
  deinit { owner.close() }
}

#if os(macOS) || os(iOS)
extension ConnectionMaterialSource {
  public func replaceLiveConfiguration(_ configuration: TransportLiveAuthoritySourceConfiguration,
    identity: TransportApplicationIdentity) throws {
    guard let live = owner as? V4LiveMaterialSource else { throw ConnectionMaterialSourceError.generationConflict }
    try live.replace(configuration: configuration, identity: identity)
  }
  /// Publishes a complete replacement snapshot. The SDK advances its local
  /// generation; callers do not maintain transport generation counters.
  public func replacePoolGeneration(_ credentials: [TransportPoolCredential],
    identity: TransportApplicationIdentity) throws {
    guard let pool = owner as? V4PoolMaterialSource else { throw ConnectionMaterialSourceError.generationConflict }
    try pool.replace(credentials, identity: identity)
  }
}
#endif

protocol TransportEnvironmentOwner: Sendable {
  // The owner must fence Acquire, material consumption and Session publication
  // against Close, retaining late preparation work until actual cleanup.
  func connect(source: ConnectionMaterialSource, requirements: ConnectionRequirements)
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
    public init(configuration: TransportClientConfiguration) async throws {
      do { owner = try await V4ClientEnvironment.create(configuration) }
      catch { throw TransportConnectError.namespaceFailure(error) }
    }
    public func makeNativeProxyUpstream(_ configuration: NativeProxyUpstreamConfiguration) throws -> NativeProxyUpstream {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try NativeProxyUpstream(environment: client.foundation, configuration: configuration)
    }
    public func makeParentWinnerAuthority(_ configuration: ParentWinnerStoreConfiguration) throws -> ParentWinnerAuthority {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try ParentWinnerAuthority(environment: client.foundation, configuration: configuration)
    }
    /// Installs a common CAS on this TransportEnvironment's server pool history. Call
    /// after creating the authority and before any server-role pool consumption.
    /// Environments without pool history, a mismatched authority ID, or a second
    /// installation fail closed.
    public func installParentWinnerAuthority(_ configuration: ParentWinnerAuthorityConfiguration) throws {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      try client.installParentWinnerAuthority(configuration)
    }
    public func makeRelayHost(_ configuration: RelayHostConfiguration,
      identity: TransportApplicationIdentity) throws -> RelayHost {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try client.relayHost(configuration, identity: identity)
    }
    public func makeServiceMaintenanceOwner(maximumPublications: Int = 16) throws -> ServiceMaintenanceOwner {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try ServiceMaintenanceOwner(environment: client.foundation, maximumPublications: maximumPublications)
    }
    public func makeServiceRegistry(_ configuration: ServiceRegistryConfiguration) throws -> ServiceRegistry {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      let registry = try ServiceRegistry(environment: client.foundation, configuration: configuration)
      try client.foundation.installServiceRegistry(registry); return registry
    }
    public func openServiceExecutionStore(_ configuration: SQLiteServiceExecutionConfiguration) throws -> SQLiteServiceExecutionStore {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try SQLiteServiceExecutionStore(environment: client.foundation, configuration: configuration)
    }
    public func openOperationReferenceStore(_ configuration: SQLiteOperationReferenceConfiguration) throws -> SQLiteOperationReferenceStore {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try SQLiteOperationReferenceStore(environment: client.foundation, configuration: configuration)
    }
    public func captureCheckpointToken(_ encoded: Data, protection: CheckpointTokenProtection,
      verificationKey: CheckpointVerificationKey? = nil) throws -> ApplicationCheckpointToken {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try ApplicationCheckpointToken(environment: client.foundation, encoded: encoded,
        protection: protection, verificationKey: verificationKey)
    }
    public func makeOperationReferenceCodec() throws -> OperationReferenceCodec {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try OperationReferenceCodec(environment: client.foundation)
    }
    public func captureServiceContract(_ canonical: Data) throws -> ServiceContract {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try ServiceContract(environment: client.foundation, canonical: canonical)
    }
    public func generateApplicationIdentity(profile: TransportCryptoProfile) throws
      -> TransportApplicationIdentity
    {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try TransportApplicationIdentity(
        client.foundation.generateIdentity(profile: V4CryptoProfile(rawValue: profile.rawValue)!))
    }
    public func importApplicationIdentity(
      profile: TransportCryptoProfile, signingSeed: Data,
      noiseStaticPrivateKey: Data
    ) throws -> TransportApplicationIdentity {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try TransportApplicationIdentity(
        client.foundation.importIdentity(
          profile: V4CryptoProfile(rawValue: profile.rawValue)!, signingSeed: signingSeed,
          staticKey: noiseStaticPrivateKey))
    }
    public func preparePoolMaterial(
      _ credential: TransportPoolCredential,
      identity: TransportApplicationIdentity, role: ConnectionEndpointRole = .client
    ) throws -> ConnectionMaterial {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try client.material(credential.withRole(role), identity: identity)
    }
    /// Creates a finite, local preauthorized source. Acquire never issues or
    /// tops up authorization and never changes the source's activation profile.
    public func makePreauthorizedPoolSource(_ credentials: [TransportPoolCredential],
      identity: TransportApplicationIdentity, role: ConnectionEndpointRole = .client) throws -> ConnectionMaterialSource {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try client.poolSource(credentials.map { $0.withRole(role) }, identity: identity)
    }
    public func makeConnectionMaterialSource(_ configuration: TransportMaterialSourceConfiguration,
      identity: TransportApplicationIdentity) throws -> ConnectionMaterialSource {
      switch configuration {
      case .preauthorizedPool(let credentials): return try makePreauthorizedPoolSource(credentials, identity: identity)
      case .liveAuthority(let control): return try makeLiveAuthoritySource(control, identity: identity)
      case .registeredLiveAuthority(let control): return try makeRegisteredLiveAuthoritySource(control, identity: identity)
      case .managedPreauthorizedPool(let pool): return try makeManagedPreauthorizedPoolSource(pool, identity: identity)
      }
    }
    public func makeManagedPreauthorizedPoolSource(_ configuration: TransportManagedPoolSourceConfiguration,
      identity: TransportApplicationIdentity) throws -> ConnectionMaterialSource {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try client.managedPoolSource(configuration, identity: identity)
    }
    public func makeLiveAuthoritySource(_ configuration: TransportLiveAuthoritySourceConfiguration,
      identity: TransportApplicationIdentity) throws -> ConnectionMaterialSource {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try client.liveSource(configuration, identity: identity)
    }
    /// Consumes one original independently installed live Artifact through its
    /// authenticated registered authority and the original relay continuation.
    public func makeRegisteredLiveAuthoritySource(_ configuration: TransportRegisteredLiveAuthoritySourceConfiguration,
      identity: TransportApplicationIdentity) throws -> ConnectionMaterialSource {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try client.registeredLiveSource(configuration, identity: identity)
    }
    /// Installs finite original tunnel server preparations behind authenticated
    /// Allow delivery. Use materialSource with Accept or Serve and deliver the
    /// matching binding to the independently configured client.
    public func makePreauthorizedPoolServerSource(_ credentials: [TransportPoolCredential],
      identity: TransportApplicationIdentity, control: TransportServerAllowHTTPSConfiguration) async throws -> TransportPoolServerSource {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try await client.poolServerSource(credentials.map { $0.withRole(.server) }, identity: identity, control: control)
    }
    /// Starts an independent original server-allow listener. Registrations are
    /// fixed before advertising their binding to the authorization authority.
    public func makeLiveServerSource(_ configuration: TransportLiveServerSourceConfiguration,
      identity: TransportApplicationIdentity) async throws -> TransportLiveServerSource {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return try await client.liveServerSource(configuration, identity: identity)
    }
    public func invalidateTimeContinuity() {
      (owner as? V4ClientEnvironment)?.invalidateTimeContinuity()
    }
    public func refreshTrustedTime() throws {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      try client.refreshTrustedTime()
    }
    public func refreshNamespace(authority: String, head: Data, state: Data) throws {
      try refreshNamespace(authority: authority, trust: nil, head: head, state: state)
    }
    /// Applies an independently root-signed TrustConfig revision through the
    /// original live namespace owner and verifies the complete Head/State pair.
    /// Mature trust rejection takes effect even if the replacement pair fails.
    public func refreshNamespace(authority: String, trust: Data?, head: Data, state: Data) throws {
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      do { try client.refreshNamespace(authority: authority, trust: trust, head: head, state: state) }
      catch { throw TransportConnectError.namespaceFailure(error) }
    }
  #endif

  func notificationFoundation() throws -> V4EnvironmentFoundation {
    #if os(macOS) || os(iOS)
      guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
      return client.foundation
    #else
      throw TransportAvailabilityError.runtimeUnavailable
    #endif
  }
  func controllerHandoffReservation(previous: (any Session)?, capacity: ConnectionReplacementCapacity?, notificationTokens: [UUID]) throws -> any V4ControllerHandoffReservation {
    #if os(macOS) || os(iOS)
    guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
    let ceiling: ConnectionReplacementCapacity
    if let capacity { ceiling = capacity }
    else if let original = previous as? V4NativeSession { ceiling = try original.replacementCapacity() }
    else { throw ServiceFailure.configurationCapacity }
    try ceiling.check()
    guard notificationTokens.count <= 128, Set(notificationTokens).count == notificationTokens.count else { throw ServiceFailure.configurationCapacity }
    var notifications: [UUID: V4CryptoReservation] = [:]
    for token in notificationTokens { notifications[token] = try client.foundation.controllerNotificationSourceStorage() }
    return try V4NativeHandoffReservation(client.foundation.controllerHandoffStorage(),
      nativeStorage: client.foundation.nativeConnectionStorage(maximumFrame: ceiling.maximumFrameBytes, listener: true),
      sessionResources: V4PrepaidSessionResources(environment: client.foundation, capacity: ceiling), maximumFrame: ceiling.maximumFrameBytes,
      initializationStorage: client.foundation.controllerInitializationStorage(), notificationStorage: notifications)
    #else
    throw SessionError.operationFailed
    #endif
  }

  func controllerInitializationReservation() throws -> V4CryptoReservation {
    #if os(macOS) || os(iOS)
    guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
    return try client.foundation.controllerInitializationStorage()
    #else
    throw TransportAvailabilityError.runtimeUnavailable
    #endif
  }

  func initializeControllerCandidate(_ candidate: any Session, handoff: (any V4ControllerHandoffReservation)? = nil,
    prepaidInitialization: V4CryptoReservation? = nil,
    callback: @isolated(any) @Sendable (any Session) async throws -> Void) async throws {
    #if os(macOS) || os(iOS)
      guard !closed, let client = owner as? V4ClientEnvironment,
        let native = candidate as? V4NativeSession,
        native.serviceEnvironment === client.foundation else { throw SessionError.closed }
      let storage = try prepaidInitialization ?? handoff?.takeInitialization(in: client.foundation) ?? client.foundation.controllerInitializationStorage()
      guard storage.environment === client.foundation else { throw SessionError.closed }
      let tail = try storage.executionTail()
      defer { tail.release() }
      try storage.check(); try native.checkServiceSession(); try Task.checkCancellation()
      try await callback(candidate)
      try storage.check(); try native.checkServiceSession(); try Task.checkCancellation()
    #else
      throw TransportAvailabilityError.runtimeUnavailable
    #endif
  }
  func connectForController(source: ConnectionMaterialSource, requirements: ConnectionRequirements,
    notifications: V4ControllerNotificationPlan, handoff: (any V4ControllerHandoffReservation)? = nil,
    diagnosticAttempt: UInt64 = 1) async throws -> any Session {
    #if os(macOS) || os(iOS)
      do {
        guard !closed, let client = owner as? V4ClientEnvironment else { throw SessionError.closed }
        let session = try await client.connect(source: source, requirements: requirements, notificationPlan: notifications,
          handoff: handoff, diagnosticAttempt: diagnosticAttempt)
        return try await publish(session, applicationPublication: false)
      } catch {
        throw await projected(error)
      }
    #else
      throw TransportAvailabilityError.runtimeUnavailable
    #endif
  }

  public func connect(
    source: ConnectionMaterialSource,
    requirements: ConnectionRequirements = ConnectionRequirements()
  ) async throws -> any Session {
    do {
      guard !closed else { throw SessionError.closed }
      guard let owner else { throw TransportAvailabilityError.runtimeUnavailable }
      let session = try await owner.connect(source: source, requirements: requirements)
      return try await publish(session)
    } catch {
      throw await projected(error)
    }
  }

  #if os(macOS) || os(iOS)
  /// Starts one bounded admission aggregate over the original server source.
  /// The returned owner drains and closes its Sessions without closing this
  /// borrowed Environment, source, maintenance owner or handler registry.
  public func serve(_ options: ServeOptions) throws -> ServeHandle {
    guard !closed, let client = owner as? V4ClientEnvironment else { throw ServeError(.closed) }
    do {
      let aggregate = try V4ServeOwner(client: client, options: options)
      try aggregate.start()
      return ServeHandle(aggregate)
    } catch let error as ServeError { throw error }
    catch { throw ServeError(.configurationCapacity) }
  }
  #endif

  /// Accept one native connection on the listener fixed by the original signed
  /// route. A dialer-only finite record is refused before acquisition.
  public func accept(source: ConnectionMaterialSource,
    requirements: ConnectionRequirements = ConnectionRequirements()) async throws -> any Session {
    var requirements = requirements
    requirements.nativeListenerAcceptance = true
    return try await connect(source: source, requirements: requirements)
  }

  public func connectMaterial(
    _ material: ConnectionMaterial,
    requirements: ConnectionRequirements = ConnectionRequirements()
  ) async throws -> any Session {
    do {
      guard !closed else { throw SessionError.closed }
      guard let owner else { throw TransportAvailabilityError.runtimeUnavailable }
      let session = try await owner.connectMaterial(material, requirements: requirements)
      return try await publish(session)
    } catch {
      throw await projected(error)
    }
  }

  private func projected(_ error: any Error) async -> any Error {
    #if os(macOS) || os(iOS)
    if let failure = error as? V4ConnectFailureProjection { return await failure.delivered() }
    #endif
    if let failure = error as? ConnectError { return failure }
    if error is TransportAvailabilityError { return error }
    // Public connection entry points expose terminal connection facts. A
    // closed Environment is rejected before source acquisition, so preserve
    // the notStarted/unspent/cleanup-complete projection rather than leaking
    // the lower-level SessionError into the connection API.
    if let session = error as? SessionError, session == .closed {
      return ConnectError.capture(session, connection: .notStarted,
        cleanup: CleanupStatus(complete: true))
    }
    return ConnectError.capture(error, connection: .notStarted,
      cleanup: CleanupStatus(complete: true))
  }

  private func publish(_ session: any Session, applicationPublication: Bool = true) async throws -> any Session {
    if closed || Task.isCancelled {
      #if os(macOS) || os(iOS)
      let error: any Error = closed ? TransportConnectError.closed : TransportConnectError.canceled
      if let native = session as? V4NativeSession {
        native.connectionFactsOwner.publicationFailed()
        try? await native.close()
        let pending = UInt64(await native.retirementPendingCallbacks())
        let observed = CleanupStatus(complete: pending == 0, pendingCallbacks: pending)
        let failure = ConnectError.capture(error,
          connection: native.connectionFactsOwner.snapshot(), cleanup: observed)
        throw V4ConnectFailureProjection(failure: failure, observeCleanup: {
          let remaining = UInt64(await native.retirementPendingCallbacks())
          return observed.preserving(CleanupStatus(
            complete: remaining == 0, pendingCallbacks: remaining))
        })
      }
      #else
      let error: any Error = closed ? SessionError.closed : SessionError.canceled
      #endif
      if let facts = (session as? V4ConnectionFactsOwner)?.connectionFactsOwner {
        facts.publicationFailed()
      }
      try await session.close()
      throw error
    }
    if applicationPublication, let facts = (session as? V4ConnectionFactsOwner)?.connectionFactsOwner { facts.published() }
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

  /// Fixed aggregate counters are collected even when detailed events are off.
  /// This snapshot has no correlation identifiers or caller-selected labels.
  public func diagnosticCounters() -> [TransportDiagnosticCounter: UInt64] {
    #if os(macOS) || os(iOS)
    if let client = owner as? V4ClientEnvironment { return client.foundation.root.diagnosticCounters.snapshot() }
    #endif
    return Dictionary(uniqueKeysWithValues: TransportDiagnosticCounter.allCases.map { ($0, 0) })
  }
  #if os(macOS) || os(iOS)
  public func diagnosticSink() -> TransportDiagnosticSink? {
    guard let client = owner as? V4ClientEnvironment else { return nil }
    return client.foundation.gate.withLock { client.foundation.diagnosticSink.map(TransportDiagnosticSink.init) }
  }
  #endif
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
