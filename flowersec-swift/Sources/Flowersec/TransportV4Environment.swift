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
  var automaticLiveness: TransportV4AutomaticLivenessPolicy? = nil
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

// Only this file's Environment factory can mint a namespace admission.
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
  fileprivate init(environment: V4EnvironmentFoundation, reservation: V4ResourceReference) {
    self.environment = environment
    self.reservation = reservation
  }
}

// Only Environment factories create these original resource owners. ARC retains
// the actual charge through every key, operation and output-buffer alias.
final class V4CryptoReservation: @unchecked Sendable {
  let environment: V4EnvironmentFoundation
  private let reference: V4ResourceReference
  fileprivate init(environment: V4EnvironmentFoundation, reference: V4ResourceReference) {
    self.environment = environment
    self.reference = reference
  }
  func check() throws { try reference.check() }
  func seal() { reference.seal() }
  func executionTail() throws -> V4ResourceReference { try reference.borrow(executionTail: true) }
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
  var automaticLiveness: TransportV4AutomaticLivenessPolicy? { configuration.automaticLiveness }
  var gate: NSRecursiveLock { root.gate }
  private let configuration: V4EnvironmentConfiguration
  private var backing: V4ResourceReference?
  private var reads: [ReadSlot]
  private var work: [WorkSlot]
  private var nativeConnections = (0..<16).map { _ in V4NativeConnectionSlot() }
  private var namespaces: [NamespaceSlot]
  private var sequence: UInt64 = 0
  private var closed = false

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

  func nativeConnectionStorage(maximumFrame: Int) throws -> V4CryptoReservation {
    try gate.withLock {
      guard (304...1_048_576).contains(maximumFrame) else { throw V4ResourceFailure.configuration }
      return try cryptoOwner(
        kind: 11,
        charge: V4ResourceVector(
          sdkBytes: UInt64(maximumFrame) * 8 + 4_194_304, items: 1, work: 1, tasks: 2,
          timers: 1, connections: 1, handles: 2))
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
      try cryptoOwner(
        kind: 12,
        charge: V4ResourceVector(sdkBytes: 2 << 20, items: 1, work: 1, handles: 3))
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
          sdkBytes: maxCredit * 2 + UInt64(slots) * 8192 + 2_097_152 + 16_384,
          items: 9, work: 8, tasks: 8))
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
    try gate.withLock {
      try admission.claimHandshake(in: self)
      try identity.check(in: self)
      return try V4Handshake(
        owner: reservation ?? cryptoOwner(kind: 8, charge: V4Handshake.charge),
        admission: admission, role: role, identity: identity, input: input,
        streamStorage: streamStorage)
    }
  }

  func cryptoBuffer(
    capacity: Int, credential: V4CredentialAdmission? = nil, delivery: (() throws -> Void)? = nil
  ) throws -> V4CryptoBuffer {
    try gate.withLock {
      guard (0...1_048_584).contains(capacity) else { throw V4ResourceFailure.capacity }
      return try V4CryptoBuffer(
        owner: cryptoOwner(
          kind: 9,
          charge: V4ResourceVector(
            sdkBytes: UInt64(capacity) * 2 + 512, items: 1)), capacity: capacity,
        credential: credential, delivery: delivery)
    }
  }

  // The complete declared callback/input footprint is acquired before the
  // task exists. Cancellation seals work but cannot refund a running callback.
  // Arbitrary descendants and allocations require the caller's independently
  // qualified external execution profile; return must join owned descendants.
  func startWork(
    charge: V4ResourceVector,
    operation: @escaping @Sendable () async -> Void
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
          foundation: self, reservation: reference, tail: tail, operation: operation)
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

  func connect(source: any ConnectionMaterialSource, requirements: ConnectionRequirements)
    async throws -> any Session
  {
    try gate.withLock {
      guard !closed else { throw SessionError.closed }
      throw TransportV4AvailabilityError.runtimeUnavailable
    }
  }

  func connectMaterial(_ material: ConnectionMaterial, requirements: ConnectionRequirements)
    async throws -> any Session
  {
    try gate.withLock {
      guard !closed else { throw SessionError.closed }
      throw TransportV4AvailabilityError.runtimeUnavailable
    }
  }

  func beginClose() {
    gate.withLock {
      guard !closed else { return }
      closed = true
      account.close(cleanupTimeout: configuration.cleanupTimeout)
      clock.close()
      for index in reads.indices { reads[index].value?.close() }
      for index in work.indices { work[index].value?.cancel() }
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
  private var task: Task<Void, Never>?
  private var canceled = false
  private var finished = false

  fileprivate init(
    foundation: V4EnvironmentFoundation, reservation: V4ResourceReference,
    tail: V4ResourceReference, operation: @escaping @Sendable () async -> Void
  ) {
    self.gate = foundation.gate
    self.reservation = reservation
    self.tail = tail
    self.operation = operation
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
