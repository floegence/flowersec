import Foundation

struct V4EnvironmentConfiguration: Sendable {
  enum VerificationContinuity: Sendable { case onlineBootstrap, durableRestore }
  let identity: V4ResourceIdentity
  let limit: V4ResourceVector
  let maximumReadBudgets: Int
  let maximumWork: Int
  let runtimeOverheadBytes: UInt64
  let cleanupTimeout: Duration
  let verificationContinuity: VerificationContinuity
  var maximumNamespaces: Int = 8
  var automaticLiveness: TransportAutomaticLivenessPolicy? = nil
  var applicationResources: ApplicationResourceProfile = .client
}

struct V4EnvironmentAuthorizationBounds: Sendable {
  let notBeforeMS: UInt64
  let issuedAtMS: UInt64
  let notAfterMS: UInt64
  let freshnessNotAfterMS: UInt64
}

protocol V4NativeConnectionLifecycle: AnyObject, Sendable { func close() }
private final class V4NativeConnectionSlot {
  weak var value: (any V4NativeConnectionLifecycle)?
}

// Only this file's TransportEnvironment factory can mint a namespace admission.
final class V4NamespaceAdmission {
  let environment: V4EnvironmentFoundation
  let pinnedRoot: V4NamespaceTrustRoot
  let configuration: V4NamespaceConfiguration
  let reservation: V4ResourceReference
  fileprivate init(
    environment: V4EnvironmentFoundation, pinnedRoot: V4NamespaceTrustRoot,
    configuration: V4NamespaceConfiguration, reservation: V4ResourceReference
  ) {
    self.environment = environment
    self.pinnedRoot = pinnedRoot
    self.configuration = configuration
    self.reservation = reservation
  }
}

final class V4CredentialWorkAdmission {
  let environment: V4EnvironmentFoundation
  let reservation: V4ResourceReference
  init(environment: V4EnvironmentFoundation, reservation: V4ResourceReference) {
    self.environment = environment
    self.reservation = reservation
  }
}

// Only TransportEnvironment factories create these original resource owners. ARC retains
// the actual charge through every key, operation and output-buffer alias.
final class V4CryptoReservation: @unchecked Sendable {
  let environment: V4EnvironmentFoundation
  private let reference: V4ResourceReference
  private var reservedTail: V4ResourceReference?
  private var released = false
  fileprivate init(environment: V4EnvironmentFoundation, reference: V4ResourceReference) {
    self.environment = environment
    self.reference = reference
  }
  func check() throws { try reference.check() }
  func seal() { reference.seal() }
  func release() {
    environment.gate.withLock {
      guard !released else { return }
      released = true
      reservedTail?.release(); reservedTail = nil
      reference.release()
    }
  }
  // An M position borrows its channel's prepaid fixed backing. The original
  // management owner bounds occupancy; releasing this alias refunds no charge.
  func borrowManagementPosition() throws -> V4CryptoReservation {
    try environment.gate.withLock {
      V4CryptoReservation(environment: environment, reference: try reference.borrow())
    }
  }
  func controlCustody() throws -> V4ResourceCustody { try environment.originalResourceCustody(reference) }
  func prepareExecutionTail() throws {
    try environment.gate.withLock {
      guard reservedTail == nil else { throw V4ResourceFailure.owner }
      reservedTail = try reference.borrow()
    }
  }
  func executionTail() throws -> V4ResourceReference {
    try environment.gate.withLock {
      if let tail = reservedTail {
        try tail.markExecutionTail()
        reservedTail = nil
        return tail
      }
      return try reference.borrow(executionTail: true)
    }
  }
  deinit { release() }
}

// A non-authorizing physical lease contains no material or continuation owner.
// Returning a body view can retain this lease without creating an ownership
// cycle through a material that consumes that same response.
final class V4ResourceCustody: @unchecked Sendable {
  let environment: V4EnvironmentFoundation
  fileprivate let reference: V4ResourceReference
  fileprivate init(environment: V4EnvironmentFoundation, reference: V4ResourceReference) {
    self.environment = environment; self.reference = reference
  }
  func check(in environment: V4EnvironmentFoundation) throws {
    guard self.environment === environment else { throw V4ResourceFailure.owner }
    try reference.check()
  }
  deinit { reference.release() }
}

// A compact, separately reserved delivery lease. Its construction is internal
// to trusted assembly; it does not validate a credential, install namespace
// state, satisfy online bootstrap or confer any connection/activation right.
final class V4EnvironmentAuthorization: @unchecked Sendable {
  let foundation: V4EnvironmentFoundation
  private let reference: V4ResourceReference
  private let bounds: V4EnvironmentAuthorizationBounds
  private let deadline: V4SecurityDeadline
  private var closed = false

  fileprivate init(
    foundation: V4EnvironmentFoundation, reference: V4ResourceReference,
    bounds: V4EnvironmentAuthorizationBounds
  ) throws {
    self.foundation = foundation
    self.reference = reference
    self.bounds = bounds
    deadline = try V4SecurityDeadline(
      clock: foundation.clock,
      capMS: min(bounds.notAfterMS, bounds.freshnessNotAfterMS))
    try check()
  }

  deinit { reference.release() }

  func check() throws {
    try foundation.gate.withLock {
      guard !closed else { throw V4TimeFailure.expired }
      try reference.check()
      let sample = try deadline.sample()
      guard let interval = sample.interval else { throw V4TimeFailure.unavailable }
      guard bounds.issuedAtMS <= interval.upperMS else { throw V4TimeFailure.configuration }
      guard interval.lowerMS >= max(bounds.notBeforeMS, bounds.issuedAtMS) else {
        throw V4TimeFailure.pending
      }
    }
  }

  func nativeDeadline() throws -> ContinuousClock.Instant {
    try foundation.gate.withLock {
      try check()
      let ticks = try deadline.remainingTicks()
      guard ticks <= UInt64(Int64.max) else { throw V4TimeFailure.unavailable }
      return ContinuousClock.now.advanced(by: .milliseconds(Int64(ticks)))
    }
  }

  func revoke() {
    foundation.gate.withLock {
      if closed { return }
      closed = true
      deadline.cancel()
      foundation.authorizationChanged(self)
    }
  }

}

// Internal owners share one resource and trusted-time boundary. Only the native
// client assembly can establish and promote a public Session.
final class V4EnvironmentFoundation: TransportEnvironmentOwner, @unchecked Sendable {
  private struct ReadSlot { weak var value: V4ReadBudget? }
  private struct WorkSlot { weak var value: V4EnvironmentWork? }
  private struct NamespaceSlot {
    var tenant: String?
    var authority: String?
    weak var value: V4NamespaceVerifier?
  }
  let root: V4ResourceRoot
  private let tenantAccount: V4ResourceAccount
  let account: V4ResourceAccount
  let clock: V4TrustedClock
  var automaticLiveness: TransportAutomaticLivenessPolicy? { configuration.automaticLiveness }
  var cleanupTimeout: Duration { configuration.cleanupTimeout }
  var applicationResources: ApplicationResourceProfile { configuration.applicationResources }
  var gate: NSRecursiveLock { root.gate }
  private let configuration: V4EnvironmentConfiguration
  private var backing: V4ResourceReference?
  private var reads: [ReadSlot]
  private var work: [WorkSlot]
  private var applications: V4ApplicationGroup?
  private var contractCoordinator: V4ServiceContractCoordinator?
  private var contractParser: V4ServiceContractParser?
  private var serviceMethodAccount: V4ResourceAccount?
  private var nativeConnections = (0..<16).map { _ in V4NativeConnectionSlot() }
  private var namespaces: [NamespaceSlot]
  private var sequence: UInt64 = 0
  private var closed = false
  #if os(macOS) || os(iOS)
  #if DEBUG
  var nativeSessionTestPrepared: (@Sendable (V4NativeSession) -> Void)?
  #endif
  private(set) var diagnosticSink: V4DiagnosticSink?
  func installDiagnosticSink(_ configuration: TransportDiagnosticSinkConfiguration?,
    random: @escaping @Sendable (Int) throws -> Data = { try V4Crypto.random($0) }) throws {
    guard let configuration else { return }
    let sink = try gate.withLock { () throws -> V4DiagnosticSink in
      guard !closed, diagnosticSink == nil else { throw V4ResourceFailure.closed }
      let sink = try root.diagnosticExecutor().makeSink(environment: self, configuration: configuration, random: random)
      diagnosticSink = sink
      return sink
    }
    sink.start()
  }
  func diagnosticContext(_ phase: TransportDiagnosticPhase, attempt: UInt64 = 1) -> V4DiagnosticContext? {
    gate.withLock { diagnosticSink?.context(phase: phase, attempt: attempt) }
  }
  func diagnosticSinkStorage() throws -> V4CryptoReservation {
    try gate.withLock {
      // The 2 MiB event slab covers all 4096 queued/in-flight records at their
      // 512-byte encoding cap; the separate slab covers 1024 rotating IDs.
      try cryptoOwner(kind: 66, charge: V4ResourceVector(sdkBytes: (2 << 20) + 131_072,
        items: 4, work: 1, tasks: 2, timers: 1))
    }
  }
  private var localServiceRegistry: ServiceRegistry?
  var serviceRegistry: ServiceRegistry? { gate.withLock { localServiceRegistry } }
  func installServiceRegistry(_ registry: ServiceRegistry) throws {
    try gate.withLock {
      guard !closed, localServiceRegistry == nil, registry.environment === self else { throw ServiceFailure.configurationCapacity }
      localServiceRegistry = registry
    }
  }
  #endif

  init(
    root: V4ResourceRoot, tenant: V4ResourceAccount,
    configuration: V4EnvironmentConfiguration, timeProfile: V4TimeProfile,
    monotonicSource: any V4MonotonicSource
  ) throws {
    guard tenant.authority === root, configuration.identity.valid,
      configuration.maximumReadBudgets > 0,
      configuration.maximumWork > 0, configuration.runtimeOverheadBytes > 0,
      configuration.maximumNamespaces > 0, configuration.maximumNamespaces <= 64,
      configuration.cleanupTimeout > .zero,
      configuration.verificationContinuity == .onlineBootstrap
    else { throw V4ResourceFailure.configuration }
    self.root = root
    tenantAccount = tenant
    self.configuration = configuration
    account = try tenant.child(
      kind: .environment, identity: configuration.identity, limit: configuration.limit)
    do {
      clock = try V4TrustedClock(profile: timeProfile, source: monotonicSource, gate: root.gate)
      try configuration.automaticLiveness?.validate(timeProfile)
      let (readBytes, readOverflow) = UInt64(configuration.maximumReadBudgets)
        .multipliedReportingOverflow(by: UInt64(MemoryLayout<ReadSlot>.stride))
      let (workBytes, workOverflow) = UInt64(configuration.maximumWork)
        .multipliedReportingOverflow(by: UInt64(MemoryLayout<WorkSlot>.stride))
      let namespaceBytes =
        UInt64(configuration.maximumNamespaces)
        * UInt64(MemoryLayout<NamespaceSlot>.stride + 256)
      let (ownerBytes, ownerOverflow) = readBytes.addingReportingOverflow(workBytes)
      let (slotBytes, slotOverflow) = ownerBytes.addingReportingOverflow(namespaceBytes)
      let (bytes, overheadOverflow) = slotBytes.addingReportingOverflow(
        configuration.runtimeOverheadBytes)
      guard !readOverflow, !workOverflow, !ownerOverflow, !slotOverflow, !overheadOverflow else {
        throw V4ResourceFailure.configuration
      }
      backing = try account.reserve(
        owner: V4ResourceOwnerKey(
          environment: configuration.identity,
          instance: V4ResourceIdentity(high: 0, low: 1),
          backing: V4ResourceIdentity(high: 0, low: 1),
          kind: 1, direction: 2), value: V4ResourceVector(sdkBytes: bytes, items: 1))
      sequence = 1
      reads = Array(repeating: ReadSlot(), count: configuration.maximumReadBudgets)
      work = Array(repeating: WorkSlot(), count: configuration.maximumWork)
      namespaces = Array(repeating: NamespaceSlot(), count: configuration.maximumNamespaces)
    } catch {
      account.close()
      throw error
    }
  }

  deinit { beginClose() }

  private func owner(kind: UInt16) throws -> V4ResourceOwnerKey {
    guard sequence < .max else { throw V4ResourceFailure.capacity }
    sequence += 1
    let identity = V4ResourceIdentity(high: configuration.identity.high, low: sequence)
    return V4ResourceOwnerKey(
      environment: configuration.identity, instance: identity,
      backing: identity, kind: kind, direction: 2)
  }

  func authorization(
    bounds: V4EnvironmentAuthorizationBounds,
    runtimeBytes: UInt64
  ) throws -> V4EnvironmentAuthorization {
    try gate.withLock {
      guard !closed else { throw V4ResourceFailure.closed }
      guard bounds.notBeforeMS < bounds.notAfterMS, bounds.issuedAtMS < bounds.notAfterMS,
        bounds.freshnessNotAfterMS > 0, runtimeBytes > 0
      else { throw V4ResourceFailure.configuration }
      let reference = try account.reserve(
        owner: owner(kind: 2),
        value: V4ResourceVector(sdkBytes: runtimeBytes, items: 1))
      do {
        return try V4EnvironmentAuthorization(
          foundation: self, reference: reference, bounds: bounds)
      } catch {
        reference.release()
        throw error
      }
    }
  }

  func readBudget(_ configuration: V4ReadBudgetConfiguration) throws -> V4ReadBudget {
    try gate.withLock {
      guard !closed else { throw V4ResourceFailure.closed }
      guard let slot = reads.firstIndex(where: { $0.value == nil }) else {
        throw V4ResourceFailure.capacity
      }
      guard configuration.directions > 0, configuration.cursors > 0,
        configuration.authorizations > 0
      else {
        throw V4ResourceFailure.configuration
      }
      let directions = UInt64(configuration.directions)
      let cursors = UInt64(configuration.cursors)
      let authorizations = UInt64(configuration.authorizations)
      let (tasks, taskOverflow) = cursors.multipliedReportingOverflow(by: 2)
      let (readItems, itemOverflow) = directions.addingReportingOverflow(cursors)
      let (items, totalOverflow) = readItems.addingReportingOverflow(authorizations)
      guard !taskOverflow, !itemOverflow, !totalOverflow else {
        throw V4ResourceFailure.configuration
      }
      let reference = try account.reserve(
        owner: owner(kind: 3),
        value: V4ResourceVector(
          sdkBytes: configuration.sdkBytes, items: items,
          work: readItems, tasks: tasks, timers: cursors))
      do {
        let value = try V4ReadBudget(configuration, foundation: self, reservation: reference)
        reads[slot] = ReadSlot(value: value)
        return value
      } catch {
        reference.release()
        throw error
      }
    }
  }

  func namespace(
    pinnedRoot: V4NamespaceTrustRoot, configuration: V4NamespaceConfiguration
  ) throws -> V4NamespaceVerifier {
    try gate.withLock {
      guard !closed else { throw V4ResourceFailure.closed }
      guard
        !namespaces.contains(where: {
          $0.tenant == pinnedRoot.tenant && $0.authority == pinnedRoot.authority
        })
      else { throw V4ResourceFailure.owner }
      guard let slot = namespaces.firstIndex(where: { $0.tenant == nil }) else {
        throw V4ResourceFailure.capacity
      }
      let reference = try account.reserve(
        owner: owner(kind: 5), value: V4NamespaceVerifier.charge(configuration))
      do {
        let value = try V4NamespaceVerifier(
          V4NamespaceAdmission(
            environment: self, pinnedRoot: pinnedRoot, configuration: configuration,
            reservation: reference))
        namespaces[slot] = NamespaceSlot(
          tenant: pinnedRoot.tenant, authority: pinnedRoot.authority, value: value)
        return value
      } catch {
        reference.release()
        throw error
      }
    }
  }

  func verifyDirectCredentials(
    configuration: V4CredentialConfiguration, input: V4CredentialInput
  ) throws -> V4CredentialAdmission {
    try gate.withLock {
      guard !closed else { throw V4ResourceFailure.closed }
      let reference = try account.reserve(owner: owner(kind: 6), value: V4CredentialVerifier.charge)
      do {
        return try V4CredentialVerifier.verify(
          V4CredentialWorkAdmission(environment: self, reservation: reference),
          configuration: configuration, input: input)
      } catch {
        reference.release()
        throw error
      }
    }
  }

  private func cryptoOwner(kind: UInt16, charge: V4ResourceVector) throws -> V4CryptoReservation {
    guard !closed else { throw V4ResourceFailure.closed }
    return try V4CryptoReservation(
      environment: self, reference: account.reserve(owner: owner(kind: kind), value: charge))
  }

  func nativeConnectionStorage(maximumFrame: Int, listener: Bool = false) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (304...1_048_576).contains(maximumFrame) else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(
        kind: 11,
        charge: V4ResourceVector(
          sdkBytes: UInt64(maximumFrame) * 10 + 4_199_424, items: listener ? 5 : 4, work: listener ? 2 : 1, tasks: 3,
          timers: 1, connections: listener ? 2 : 1, handles: listener ? 3 : 2))
    }
  }
  func registerNativeConnection(_ connection: any V4NativeConnectionLifecycle) throws {
    try gate.withLock {
      guard !closed, let slot = nativeConnections.first(where: { $0.value == nil }) else {
        throw V4ResourceFailure.capacity
      }
      slot.value = connection
    }
  }

  func retireNativeConnection(_ connection: any V4NativeConnectionLifecycle) {
    gate.withLock {
      if let slot = nativeConnections.first(where: { $0.value === connection }) { slot.value = nil }
    }
  }

  func poolDiskStorage(diskBytes: UInt64) throws -> V4PersistentDiskCharge {
    try gate.withLock {
      guard !closed, ((3 << 20)...(3 << 30)).contains(diskBytes) else {
        throw V4ResourceFailure.configuration
      }
      let id = try V4Crypto.random(16)
      return try root.persistentDisk(
        tenant: tenantAccount,
        identity: V4ResourceIdentity(
          high: V4Crypto.number(id.prefix(8)),
          low: V4Crypto.number(id.suffix(8))), bytes: diskBytes)
    }
  }
  func poolStoreStorage() throws -> V4CryptoReservation {
    try gate.withLock {
      // Admit the single cleanup observer, its deadline Task and sleep timer
      // before opening storage. The original cleanup tail retains this whole
      // charge until physical close and the observer timer have both exited.
      try cryptoOwner(
        kind: 12,
        charge: V4ResourceVector(sdkBytes: V4NamespaceRegistry.backingBytes + (2 << 20) + 65_536, items: 6, work: 1,
          tasks: 1, timers: 1, handles: 3))
    }
  }

  func cleanupJoinStorage() throws -> V4CryptoReservation {
    try gate.withLock {
      try cryptoOwner(kind: 65, charge: V4ResourceVector(sdkBytes: 16_384,
        items: 7, work: 1, tasks: 2, timers: 1))
    }
  }

  func reliableSessionStorage(maxCredit: UInt64, slots: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard maxCredit <= 8 << 20, (1...4225).contains(slots) else {
        throw V4ResourceFailure.capacity
      }
      return try cryptoOwner(
        kind: 10,
        charge: V4ResourceVector(
          sdkBytes: maxCredit * 2 + UInt64(slots) * 8192 + 2_097_152 + 16_384
            + V4ReliableSession.sharedIngressStorageBytes,
          items: 11, work: 8, tasks: 8))
    }
  }

  func generateIdentity(profile: V4CryptoProfile) throws -> V4LocalIdentity {
    try gate.withLock {
      try V4LocalIdentity(
        owner: cryptoOwner(kind: 7, charge: V4ResourceVector(sdkBytes: 8192, items: 1)),
        profile: profile)
    }
  }
  func importIdentity(profile: V4CryptoProfile, signingSeed: Data, staticKey: Data) throws
    -> V4LocalIdentity
  {
    try gate.withLock {
      try V4LocalIdentity(
        owner: cryptoOwner(kind: 7, charge: V4ResourceVector(sdkBytes: 8192, items: 1)),
        profile: profile, signingSeed: signingSeed, staticKey: staticKey)
    }
  }
  func rpcServicesDynamicStorage(execution: Bool) throws -> V4CryptoReservation {
    try gate.withLock {
      _ = try applicationGroup()
      // Eight finite local/peer carrier positions are created by the original
      // Session engine before READY. Each position owns its own wire/parser,
      // OPEN wait and physical-retirement tail; no later OPEN may mint one.
      return try cryptoOwner(kind: 31, charge: V4ResourceVector(
        sdkBytes: 2 * 8192 + 65_536 + 8 * 4096 + (execution ? 16_384 : 0),
        items: 16 + 8, work: 1, tasks: 2, timers: 1, handles: execution ? 4 : 3))
    }
  }

  func rpcServicesStorage(maximumGeneral: Int, execution: Bool) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (1...1024).contains(maximumGeneral) else { throw V4ResourceFailure.configuration }
      _ = try applicationGroup()
      let positions = UInt64(maximumGeneral + 2)
      let bytes: UInt64 = V4NamespaceRegistry.backingBytes + positions * 8192
        + 524_288 + 10 * 32_768 + (execution ? 32_768 : 0)
      return try cryptoOwner(kind: 30, charge: V4ResourceVector(
        sdkBytes: bytes, items: positions * 4 + 32,
        work: 2, tasks: 3, timers: 1, handles: execution ? 11 : 10))
    }
  }

  func resumeStorage() throws -> V4CryptoReservation {
    try gate.withLock { try cryptoOwner(kind: 40, charge: V4ResourceVector(sdkBytes: V4NamespaceRegistry.backingBytes + 65_536, items: 32)) }
  }
  func notificationReceiverStorage() throws -> V4CryptoReservation {
    try gate.withLock {
      try cryptoOwner(kind: 38, charge: V4ResourceVector(sdkBytes: 131_072, items: 130, tasks: 2, timers: 1, handles: 1))
    }
  }
  func notificationSubscriptionStorage(applicationBytes: UInt64) throws -> V4CryptoReservation {
    try gate.withLock {
      guard applicationBytes < 1 << 63 else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(kind: 39, charge: V4ResourceVector(sdkBytes: applicationBytes + 8192,
        items: 20, work: 1, tasks: 1, timers: 1))
    }
  }
  func notificationPublisherStorage() throws -> V4CryptoReservation {
    try gate.withLock {
      try cryptoOwner(kind: 37, charge: V4ResourceVector(sdkBytes: 65_536, items: 20, tasks: 2, handles: 1))
    }
  }

  func executionManagementStorage() throws -> V4CryptoReservation {
    try gate.withLock {
      let group = try applicationGroup()
      try group.executor.protectManagement()
      return try cryptoOwner(kind: 34, charge: V4ResourceVector(
        sdkBytes: V4NamespaceRegistry.backingBytes + 131_072, items: 20, work: 2, tasks: 3, timers: 1, handles: 1))
    }
  }

  func operationReferenceStoreStorage() throws -> V4CryptoReservation {
    try gate.withLock {
      try cryptoOwner(kind: 36, charge: V4ResourceVector(sdkBytes: 2 << 20, items: 4, work: 1, tasks: 1, handles: 3))
    }
  }

  func operationReferenceStorage() throws -> V4CryptoReservation {
    try gate.withLock {
      try cryptoOwner(kind: 32, charge: V4ResourceVector(
        sdkBytes: V4NamespaceRegistry.backingBytes + 32_768, items: 2))
    }
  }

  func serviceContracts() throws -> V4ServiceContractCoordinator {
    try gate.withLock {
      guard !closed else { throw ServiceFailure.closed }
      if let contractCoordinator { return contractCoordinator }
      let methods = applicationResources == .constrained ? 16 : 256
      let storage = try serviceMethodOwner(kind: 33, charge: V4ResourceVector(
        sdkBytes: UInt64(methods * 1024 + 65_536), items: UInt64(methods + 128),
        work: UInt64(applicationResources == .constrained ? 2 : 4),
        tasks: UInt64(applicationResources == .constrained ? 3 : 5), timers: 1))
      let coordinator = V4ServiceContractCoordinator(environment: self, storage: storage)
      contractCoordinator = coordinator
      return coordinator
    }
  }

  func serviceBindingStorage(methods: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (1...256).contains(methods) else { throw V4ResourceFailure.configuration }
      return try serviceMethodOwner(kind: 33, charge: V4ResourceVector(
        sdkBytes: UInt64(methods) * 8192 + 32_768, items: UInt64(methods) + 2, handles: 1))
    }
  }

  func serviceOperationStorage(requestBytes: Int, responseBytes: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (0...1_048_576).contains(requestBytes), (0...1_048_576).contains(responseBytes) else {
        throw V4ResourceFailure.configuration
      }
      return try cryptoOwner(kind: 31, charge: V4ResourceVector(
        sdkBytes: UInt64(requestBytes + responseBytes) * 2 + 32_768, items: 4, tasks: 2, timers: 1))
    }
  }

  func serviceServerOperationStorage(requestBytes: Int, responseBytes: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (0...1_048_576).contains(requestBytes), (0...1_048_576).contains(responseBytes) else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(kind: 31, charge: V4ResourceVector(
        sdkBytes: UInt64(requestBytes + responseBytes) * 2 + 32_768, items: 5, tasks: 3, timers: 1))
    }
  }

  func serviceServerSessionStorage(maximumGeneral: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (1...1024).contains(maximumGeneral) else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(kind: 37, charge: V4ResourceVector(
        sdkBytes: V4NamespaceRegistry.backingBytes + UInt64(maximumGeneral + 2) * 16_384 + 65_536,
        items: UInt64(maximumGeneral * 2 + 22), tasks: 1, handles: 1))
    }
  }

  func duplexBridgeStorage(chunkBytes: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (1...1_048_576).contains(chunkBytes) else { throw V4ResourceFailure.configuration }
      let bytes = UInt64(chunkBytes) * 8 + 16_384
      return try cryptoOwner(kind: 52, charge: V4ResourceVector(
        sdkBytes: bytes, items: 16, work: 2, tasks: 6, timers: 2, handles: 2))
    }
  }

  func duplexNativeTCPStorage(chunkBytes: Int, kernelBufferBytes: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (1...65_536).contains(chunkBytes), (16_384...262_144).contains(kernelBufferBytes)
      else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(kind: 54, charge: V4ResourceVector(
        sdkBytes: UInt64(chunkBytes) * 2 + 16_384,
        providerBytes: UInt64(kernelBufferBytes) * 8 + 65_536,
        items: 8, work: 1, tasks: 1, timers: 1, connections: 1, handles: 1))
    }
  }

  func duplexBridgeResultStorage(chunkBytes: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (1...1_048_576).contains(chunkBytes) else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(kind: 53, charge: V4ResourceVector(
        sdkBytes: UInt64(chunkBytes) * 2 + 2048, items: 3, handles: 1))
    }
  }

  func serviceMaintenanceStorage(maximum: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (1...1024).contains(maximum) else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(kind: 36, charge: V4ResourceVector(sdkBytes: UInt64(maximum) * 8192,
        items: UInt64(maximum) * 10 + 1, tasks: UInt64(maximum) * 2, timers: UInt64(maximum), handles: 1))
    }
  }
  func serveStorage(maximumSessions: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (1...64).contains(maximumSessions) else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(kind: 55, charge: V4ResourceVector(
        sdkBytes: UInt64(maximumSessions) * 16_384 + 8192, items: UInt64(maximumSessions) * 4 + 4,
        work: UInt64(maximumSessions) + 1, tasks: UInt64(maximumSessions) * 3 + 3, timers: 1, handles: 1))
    }
  }
  func controllerHandoffStorage() throws -> V4CryptoReservation {
    try gate.withLock { try cryptoOwner(kind: 49, charge: V4ResourceVector(sdkBytes: 32_768, items: 8, work: 1, tasks: 4, timers: 2, handles: 1)) }
  }
  func sessionDrainStorage() throws -> V4CryptoReservation {
    try gate.withLock { try cryptoOwner(kind: 50, charge: V4ResourceVector(sdkBytes: 8192, items: 2, work: 1, tasks: 1, timers: 1)) }
  }
  func controllerInitializationStorage() throws -> V4CryptoReservation {
    try gate.withLock { try cryptoOwner(kind: 46, charge: V4ResourceVector(sdkBytes: 8192, items: 2, work: 1, tasks: 1)) }
  }
  func liveGrantPreparationStorage() throws -> V4CryptoReservation {
    try gate.withLock { try cryptoOwner(kind: 48, charge: V4ResourceVector(sdkBytes: V4NamespaceRegistry.backingBytes + 1_048_576, items: 8, work: 1)) }
  }
  func liveMaterialSourceStorage() throws -> V4CryptoReservation {
    try gate.withLock { try cryptoOwner(kind: 45, charge: V4ResourceVector(sdkBytes: 4 << 20, items: 16, handles: 1)) }
  }
  func controlHTTPSStorage(bytes: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (1...393_216).contains(bytes) else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(kind: 43, charge: V4ResourceVector(sdkBytes: UInt64(bytes) * 2 + 69_632,
        providerBytes: 1 << 20, items: 20, handles: 1))
    }
  }
  func originalResourceCustody(_ reference: V4ResourceReference) throws -> V4ResourceCustody {
    try gate.withLock {
      guard !closed, reference.belongs(to: account) else { throw V4ResourceFailure.owner }
      return try V4ResourceCustody(environment: self, reference: reference.borrow(executionTail: true))
    }
  }
  func controlHTTPCallStorage(maximumBytes: Int, requestBytes: Int = 1024,
    custody: V4ResourceCustody? = nil) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (1...524_288).contains(maximumBytes), (1...524_288).contains(requestBytes) else { throw V4ResourceFailure.configuration }
      let charge = V4ResourceVector(sdkBytes: UInt64(maximumBytes) * 4 + UInt64(requestBytes) * 2 + 65_536,
        providerBytes: 2 << 20, items: 8, work: 1, tasks: 2, timers: 1, connections: 1, handshakes: 1, handles: 1)
      if let custody {
        try custody.check(in: self)
        return try V4CryptoReservation(environment: self,
          reference: custody.reference.reserveRelated(owner: owner(kind: 44), value: charge))
      }
      return try cryptoOwner(kind: 44, charge: charge)
    }
  }
  func managedPoolStorage(maximumRows: Int, maximumBytes: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (4...64).contains(maximumRows), (4_194_304...67_108_864).contains(maximumBytes) else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(kind: 47, charge: V4ResourceVector(
        sdkBytes: V4NamespaceRegistry.backingBytes + 8_388_608, diskBytes: UInt64(maximumBytes) * 3,
        items: UInt64(maximumRows + 32), work: 2, tasks: 2, timers: 2, handles: 2))
    }
  }
  func materialSourceStorage(bytes: Int, items: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (1...64).contains(items), (0...(16 << 20)).contains(bytes) else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(kind: 42, charge: V4ResourceVector(
        sdkBytes: UInt64(bytes) * 2 + UInt64(items) * 1024 + 4096,
        items: UInt64(items + 2), handles: 1))
    }
  }
  func serviceExecutionStoreStorage(rows: Int, active: Int, databaseBytes: Int, contentItems: Int = 0) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (1...8192).contains(rows), (1...1024).contains(active), active <= rows,
        (0...131_072).contains(contentItems), databaseBytes > 0, databaseBytes <= 2 << 30 else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(kind: 36, charge: V4ResourceVector(
        sdkBytes: V4NamespaceRegistry.backingBytes + 4_194_304 + UInt64(active) * 16_384 + UInt64(contentItems) * 4608,
        diskBytes: UInt64(databaseBytes) * 3, items: UInt64(rows * 3 + active * 2 + contentItems + 4), work: 1, tasks: 1, handles: 1))
    }
  }
  func serviceApplicationRegistryStorage() throws -> V4CryptoReservation {
    try gate.withLock {
      try cryptoOwner(kind: 37, charge: V4ResourceVector(sdkBytes: 65_536, items: 2))
    }
  }
  func serviceRegistryStorage(methods: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (1...256).contains(methods) else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(kind: 37, charge: V4ResourceVector(
        sdkBytes: V4NamespaceRegistry.backingBytes + UInt64(methods) * 16_384 + 65_536,
        items: UInt64(methods * 3 + 4), handles: 1))
    }
  }

  func controllerNotificationStorage(applicationBytes: UInt64) throws -> V4CryptoReservation {
    try gate.withLock {
      guard applicationBytes > 0, applicationBytes < 1 << 63 else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(kind: 34, charge: V4ResourceVector(
        sdkBytes: applicationBytes + 65_536, items: 24, work: 1, tasks: 3, timers: 1, handles: 1))
    }
  }
  func controllerNotificationSourceStorage() throws -> V4CryptoReservation {
    try gate.withLock { try cryptoOwner(kind: 34, charge: V4ResourceVector(sdkBytes: 8192, items: 3, tasks: 1)) }
  }

  func serviceQueryStorage(responseBytes: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (9216...73728).contains(responseBytes) else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(kind: 31, charge: V4ResourceVector(
        sdkBytes: V4NamespaceRegistry.backingBytes + UInt64(responseBytes) * 4 + 524_288,
        items: 4, tasks: 2, timers: 1))
    }
  }

  func serverAllowHTTPSStorage(bytes: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (1...98_304).contains(bytes) else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(kind: 53, charge: V4ResourceVector(sdkBytes: UInt64(bytes) * 2 + 65_536,
        providerBytes: 1 << 20, items: 4, work: 1, tasks: 1, connections: 1, handles: 2))
    }
  }
  func relayPublicationQueueStorage(capacity: Int) throws -> V4CryptoReservation {
    guard (1...64).contains(capacity) else { throw V4ResourceFailure.configuration }
    return try gate.withLock { try cryptoOwner(kind: 52, charge: V4ResourceVector(sdkBytes: UInt64(4096 + capacity * 512), items: UInt64(capacity + 1), work: 1, tasks: 1)) }
  }
  func relayHostStorage(maximumFrame: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (10_346...1_048_576).contains(maximumFrame) else { throw V4ResourceFailure.capacity }
      return try cryptoOwner(kind: 44, charge: V4ResourceVector(sdkBytes: V4NamespaceRegistry.backingBytes
        + UInt64(maximumFrame + 8) * 8 + 1_048_576, items: 64, work: 8, tasks: 8, timers: 3, handles: 8))
    }
  }

  func proxyOperationStorage(limits: ProxyClientLimits, server: Bool = false) throws -> V4CryptoReservation {
    try gate.withLock {
      try cryptoOwner(kind: 35, charge: V4ResourceVector(
        sdkBytes: V4NamespaceRegistry.backingBytes + UInt64(limits.maximumBodyBytes) * 2
          + UInt64(limits.maximumMetadataBytes) * 4 + UInt64(limits.maximumWebSocketFrameBytes) * 2 + 65_536,
        // A server retains its supervisor, terminal observer, wire operation
        // and (for WebSockets) both pumps until their real exits. The close
        // deadline reuses a completed pump's task slot and stays in this owner.
        items: 16, work: server ? 3 : 1, tasks: server ? 5 : 2, timers: server ? 1 : 0, handles: 2))
    }
  }

  func nativeProxyUpstreamStorage() throws -> V4CryptoReservation {
    try gate.withLock {
      try cryptoOwner(kind: 51, charge: V4ResourceVector(sdkBytes: 1 << 20, items: 256, handles: 1))
    }
  }

  func nativeProxyConnectionStorage(limits: ProxyClientLimits) throws -> V4CryptoReservation {
    try gate.withLock {
      try cryptoOwner(kind: 50, charge: V4ResourceVector(
        sdkBytes: V4NamespaceRegistry.backingBytes + UInt64(limits.maximumBodyBytes) * 4
          + UInt64(limits.maximumMetadataBytes) * 8 + UInt64(limits.maximumWebSocketFrameBytes) * 8 + 262_144,
        providerBytes: 2 << 20, items: 32, work: 2, tasks: 4, timers: 2,
        connections: 1, handshakes: 1, handles: 4))
    }
  }

  private func serviceMethodOwner(kind: UInt16, charge: V4ResourceVector) throws -> V4CryptoReservation {
    guard !closed else { throw V4ResourceFailure.closed }
    let pool: V4ResourceAccount
    if let serviceMethodAccount { pool = serviceMethodAccount }
    else {
      let constrained = applicationResources == .constrained
      pool = try account.child(kind: .pool, identity: owner(kind: 33).instance, limit: V4ResourceVector(
        sdkBytes: constrained ? 1 << 20 : 6 << 20, items: constrained ? 512 : 2048,
        work: constrained ? 2 : 4, tasks: constrained ? 3 : 5, timers: 1, handles: 64))
      serviceMethodAccount = pool
    }
    return try V4CryptoReservation(environment: self, reference: pool.reserve(owner: owner(kind: kind), value: charge))
  }
  func serviceContractParser() throws -> V4ServiceContractParser {
    try gate.withLock {
      guard !closed else { throw V4ResourceFailure.closed }
      if let contractParser { return contractParser }
      let storage = try cryptoOwner(kind: 17, charge: V4ResourceVector(
        sdkBytes: V4NamespaceRegistry.backingBytes + 524_288, items: 2, work: 1))
      let parser = try V4ServiceContractParser(storage: storage); contractParser = parser; return parser
    }
  }
  func serviceContractStorage(bytes: Int = 8192) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (1...8192).contains(bytes) else { throw V4ResourceFailure.configuration }
      // One immutable canonical backing, field ranges and scalars. Parser and
      // wire-copy overlaps remain charged to their original workspace owners.
      return try serviceMethodOwner(kind: 17, charge: V4ResourceVector(sdkBytes: UInt64(bytes) + 2048, items: 1))
    }
  }

  func messageStreamRegistrationStorage(count: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (1...256).contains(count) else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(
        kind: 20, charge: V4ResourceVector(
          sdkBytes: UInt64(count) * 16_384 + V4NamespaceRegistry.backingBytes,
          items: UInt64(count) * 3, handles: 1))
    }
  }

  func applicationGroup() throws -> V4ApplicationGroup {
    try gate.withLock {
      guard !closed else { throw V4ResourceFailure.closed }
      if let applications { try applications.check(); return applications }
      let executor: V4ApplicationExecutor
      if let existing = root.applicationExecutor {
        guard existing.profile == configuration.applicationResources else { throw V4ResourceFailure.configuration }
        executor = existing
      }
      else {
        executor = try V4ApplicationExecutor(root: root, profile: configuration.applicationResources)
        root.applicationExecutor = executor
      }
      let key = try owner(kind: 23)
      let reference = try account.reserve(owner: key, value: V4ResourceVector(sdkBytes: 4096, items: 1))
      do {
        let group = try executor.attach(account: account, owner: key, reference: reference)
        try executor.protectCompletions()
        applications = group
        return group
      } catch { reference.release(); throw error }
    }
  }

  func messageOpenAuthorizationStorage() throws -> V4ResourceReference {
    try gate.withLock {
      guard !closed else { throw V4ResourceFailure.closed }
      return try account.reserve(owner: owner(kind: 29), value: V4ResourceVector(
        sdkBytes: 8192, items: 1, tasks: 2, timers: 1))
    }
  }

  func messageStreamStorage() throws -> V4CryptoReservation {
    try gate.withLock {
      let storage = try cryptoOwner(
        kind: 18,
        charge: V4ResourceVector(
          sdkBytes: V4NamespaceRegistry.backingBytes + 65_536,
          items: 12, work: 1, tasks: 8, timers: 3, handles: 3))
      _ = try applicationGroup()
      return storage
    }
  }

  func messageStreamPayloadStorage(bytes: Int, encoding: Bool) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (0...1_048_576).contains(bytes) else { throw V4ResourceFailure.configuration }
      // Keep overlapping Data, cursor, prefix and provider-copy responsibility
      // charged until the actual operation and its original read have exited.
      let storage = try cryptoOwner(
        kind: 19,
        charge: V4ResourceVector(
          sdkBytes: UInt64(bytes) * (encoding ? 6 : 4) + 4096,
          items: 3, work: 0, tasks: encoding ? 2 : 1, timers: encoding ? 1 : 0))
      try storage.prepareExecutionTail()
      return storage
    }
  }

  func messageStreamControlledInputStorage(bytes: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (0...1_048_576).contains(bytes) else { throw V4ResourceFailure.configuration }
      // The input snapshot, copy overlap, 65 descriptors, bounded publisher
      // chunk copies, task captures and prefix all precede controlled encoding.
      let storage = try cryptoOwner(kind: 21, charge: V4ResourceVector(
        sdkBytes: UInt64(bytes) * 4 + 65_536,
        items: 3, tasks: 2, timers: 1))
      try storage.prepareExecutionTail()
      return storage
    }
  }

  func messageStreamSegmentStorage(bytes: Int, blocks: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard bytes > 0, bytes <= 2_097_152, (1...65).contains(blocks) else {
        throw V4ResourceFailure.configuration
      }
      return try cryptoOwner(kind: 22, charge: V4ResourceVector(
        // Foundation may replace an external Data backing on mutation. Keep
        // that bounded copy overlap charged with the original allocation.
        sdkBytes: UInt64(bytes) * 2 + UInt64(blocks) * 512, items: UInt64(blocks)))
    }
  }

  func nativeSessionStorage(slots: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (1...4225).contains(slots) else { throw V4ResourceFailure.capacity }
      return try cryptoOwner(
        kind: 14,
        charge: V4ResourceVector(
          sdkBytes: UInt64(slots) * 8192 + 4_194_304,
          items: 1, work: 1, tasks: 2, timers: 1))
    }
  }
  func reserveHandshake() throws -> V4CryptoReservation {
    try gate.withLock { try cryptoOwner(kind: 8, charge: V4Handshake.charge) }
  }
  func clientProviderStorage(bytes: UInt64) throws -> V4CryptoReservation {
    try gate.withLock {
      try cryptoOwner(
        kind: 15, charge: V4ResourceVector(sdkBytes: bytes, items: 1, work: 1, tasks: 1))
    }
  }
  func clientConnectStorage() throws -> V4CryptoReservation {
    try gate.withLock {
      try cryptoOwner(
        kind: 16, charge: V4ResourceVector(sdkBytes: 1 << 20, items: 1, work: 1, tasks: 1))
    }
  }

  func handshake(
    admission: V4CredentialAdmission, role: V4CryptoRole, identity: V4LocalIdentity,
    input: V4HandshakeInput, reservation: V4CryptoReservation? = nil,
    streamStorage: V4CryptoReservation? = nil
  ) throws -> V4Handshake {
    let (storage, tail) = try gate.withLock { () throws -> (V4CryptoReservation, V4ResourceReference) in
      try admission.claimHandshake(in: self)
      try identity.check(in: self)
      let storage = try reservation ?? cryptoOwner(kind: 8, charge: V4Handshake.charge)
      return (storage, try storage.executionTail())
    }
    defer { tail.release() }
    return try V4Handshake(owner: storage,
      admission: admission, role: role, identity: identity, input: input,
      streamStorage: streamStorage)
  }

  func cryptoBuffer(
    capacity: Int, credential: V4CredentialAdmission? = nil, delivery: (() throws -> Void)? = nil,
    copies: UInt64 = 2
  ) throws -> V4CryptoBuffer {
    try gate.withLock {
      guard (0...1_048_584).contains(capacity), (2...4).contains(copies) else { throw V4ResourceFailure.capacity }
      return try V4CryptoBuffer(
        owner: cryptoOwner(
          kind: 9,
          charge: V4ResourceVector(
            sdkBytes: UInt64(capacity) * copies + 512, items: 1)), capacity: capacity,
        credential: credential, delivery: delivery)
    }
  }

  // The complete declared callback/input footprint is acquired before the
  // task exists. Cancellation seals work but cannot refund a running callback.
  // Arbitrary descendants and allocations require the caller's independently
  // qualified external execution profile; return must join owned descendants.
  func startWork(
    charge: V4ResourceVector,
    operation: @escaping @Sendable () async -> Void,
    onExit: @escaping @Sendable () -> Void = {}
  ) throws -> V4EnvironmentWork {
    try gate.withLock {
      guard !closed else { throw V4ResourceFailure.closed }
      guard charge.tasks >= 1, charge.work >= 1, charge.sdkBytes > 0,
        let slot = work.firstIndex(where: { $0.value == nil || $0.value?.isFinished == true })
      else { throw V4ResourceFailure.capacity }
      let reference = try account.reserve(owner: owner(kind: 4), value: charge)
      do {
        let tail = try reference.borrow(executionTail: true)
        let value = V4EnvironmentWork(
          foundation: self, reservation: reference, tail: tail, operation: operation, onExit: onExit)
        work[slot] = WorkSlot(value: value)
        value.start()
        return value
      } catch {
        reference.release()
        throw error
      }
    }
  }

  fileprivate func authorizationChanged(_ authorization: V4EnvironmentAuthorization) {
    for index in reads.indices { reads[index].value?.foundationAuthorizationChanged(authorization) }
  }

  func connect(source: ConnectionMaterialSource, requirements: ConnectionRequirements)
    async throws -> any Session
  {
    try gate.withLock {
      guard !closed else { throw SessionError.closed }
      throw TransportAvailabilityError.runtimeUnavailable
    }
  }

  func connectMaterial(_ material: ConnectionMaterial, requirements: ConnectionRequirements)
    async throws -> any Session
  {
    try gate.withLock {
      guard !closed else { throw SessionError.closed }
      throw TransportAvailabilityError.runtimeUnavailable
    }
  }

  func beginClose() {
    gate.withLock {
      guard !closed else { return }
      closed = true
      account.close(cleanupTimeout: configuration.cleanupTimeout)
      contractCoordinator?.close(); contractCoordinator = nil; contractParser = nil; serviceMethodAccount = nil
      clock.close()
      for index in reads.indices { reads[index].value?.close() }
      for index in work.indices { work[index].value?.cancel() }
      #if os(macOS) || os(iOS)
      diagnosticSink?.close(); diagnosticSink = nil
      localServiceRegistry?.close(); localServiceRegistry = nil
      #endif
      applications?.close()
      applications = nil
      for index in namespaces.indices { namespaces[index].value?.close() }
      for connection in nativeConnections { connection.value?.close() }
      reads = []
      work = []
      namespaces = []
      backing?.release()
      backing = nil
    }
  }

  func close() async throws {
    beginClose()
    _ = try await account.waitCleanup()
  }
  func cleanupStatus() -> CleanupStatus { account.cleanupStatus() }
  func waitCleanup() async throws -> CleanupStatus { try await account.waitCleanup() }
}

final class V4EnvironmentWork: @unchecked Sendable {
  private let gate: NSRecursiveLock
  private var reservation: V4ResourceReference?
  private var tail: V4ResourceReference?
  private var operation: (@Sendable () async -> Void)?
  private var onExit: (@Sendable () -> Void)?
  private var task: Task<Void, Never>?
  private var canceled = false
  private var finished = false

  fileprivate init(
    foundation: V4EnvironmentFoundation, reservation: V4ResourceReference,
    tail: V4ResourceReference, operation: @escaping @Sendable () async -> Void,
    onExit: @escaping @Sendable () -> Void
  ) {
    self.gate = foundation.gate
    self.reservation = reservation
    self.tail = tail
    self.operation = operation
    self.onExit = onExit
  }

  fileprivate func start() {
    gate.withLock {
      task = Task { [self] in
        await invoke()
        gate.withLock {
          finished = true
          task = nil
          tail?.release()
          reservation?.release()
          tail = nil
          reservation = nil
          let exited = onExit
          onExit = nil
          exited?()
        }
      }
    }
  }

  private func invoke() async {
    let callback = gate.withLock {
      let value = canceled ? nil : operation
      operation = nil
      return value
    }
    await callback?()
  }

  var isFinished: Bool { gate.withLock { finished } }
  func cancel() {
    gate.withLock {
      canceled = true
      reservation?.seal()
      task?.cancel()
    }
  }
}
