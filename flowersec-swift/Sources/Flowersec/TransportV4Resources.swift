import Foundation

// Resource owners intentionally share this recursive submission gate. A claimed
// synchronous crypto job must leave every enclosing acquisition, including a
// native Session or typed-stream caller's acquisition, before doing crypto.
// Only an owner with an immutable input and a retained physical job may use it.
final class V4CommitGate: NSRecursiveLock, @unchecked Sendable {
  private var depth = 0
  override func lock() { super.lock(); depth += 1 }
  override func unlock() { depth -= 1; super.unlock() }
  func outside<T>(_ operation: () throws -> T) rethrows -> T {
    let acquisitions = depth
    precondition(acquisitions > 0)
    for _ in 0..<acquisitions { unlock() }
    defer { for _ in 0..<acquisitions { lock() } }
    return try operation()
  }
}

// All types in this file are internal composition capabilities. Neither peer
// labels nor caller-provided strings can create accounts or resource owners.
enum V4ResourceFailure: Error, Equatable, Sendable {
  case configuration, capacity, closed, owner
}

struct V4ResourceVector: Equatable, Sendable {
  var sdkBytes: UInt64 = 0
  var providerBytes: UInt64 = 0
  var diskBytes: UInt64 = 0
  var items: UInt64 = 0
  var work: UInt64 = 0
  var tasks: UInt64 = 0
  var timers: UInt64 = 0
  var connections: UInt64 = 0
  var handshakes: UInt64 = 0
  var sessions: UInt64 = 0
  var handles: UInt64 = 0

  private subscript(_ index: Int) -> UInt64 {
    get {
      switch index {
      case 0: return sdkBytes
      case 1: return providerBytes
      case 2: return diskBytes
      case 3: return items
      case 4: return work
      case 5: return tasks
      case 6: return timers
      case 7: return connections
      case 8: return handshakes
      case 9: return sessions
      default: return handles
      }
    }
    set {
      switch index {
      case 0: sdkBytes = newValue
      case 1: providerBytes = newValue
      case 2: diskBytes = newValue
      case 3: items = newValue
      case 4: work = newValue
      case 5: tasks = newValue
      case 6: timers = newValue
      case 7: connections = newValue
      case 8: handshakes = newValue
      case 9: sessions = newValue
      default: handles = newValue
      }
    }
  }

  func adding(_ other: Self) throws -> Self {
    var result = self
    for index in 0..<11 {
      let (sum, overflow) = self[index].addingReportingOverflow(other[index])
      guard !overflow else { throw V4ResourceFailure.configuration }
      result[index] = sum
    }
    return result
  }

  func contains(_ other: Self) -> Bool {
    for index in 0..<11 where self[index] < other[index] { return false }
    return true
  }

  fileprivate func subtracting(_ other: Self) -> Self {
    precondition(contains(other))
    var result = self
    for index in 0..<11 { result[index] -= other[index] }
    return result
  }
}

struct V4ResourceIdentity: Equatable, Sendable {
  let high: UInt64
  let low: UInt64
  var valid: Bool { high != 0 || low != 0 }
}

struct V4ResourceOwnerKey: Equatable, Sendable {
  let environment: V4ResourceIdentity
  let instance: V4ResourceIdentity
  let backing: V4ResourceIdentity
  let kind: UInt16
  let direction: UInt8
  fileprivate var valid: Bool {
    environment.valid && instance.valid && backing.valid && kind != 0 && direction <= 2
  }
}

struct V4ResourceRootConfiguration: Sendable {
  let limit: V4ResourceVector
  let accounts: Int
  let reservations: Int
  let references: Int
  let cleanupWaiters: Int
  // Admitted allocator/lock/continuation/timer overhead beyond the fixed slabs.
  // It is supplied by the trusted runtime profile, not an RSS guarantee.
  let runtimeOverheadBytes: UInt64
}

struct V4ResourceSnapshot: Equatable, Sendable {
  let used: V4ResourceVector
  let reservations: Int
  let references: Int
  let executionTails: Int
  let closed: Bool
  var resourceWaiters: Int = 0
}

struct V4ResourceAccount: Sendable {
  enum Kind: Sendable { case tenant, environment, session, direction, pool, result, history }
  fileprivate let root: V4ResourceRoot
  fileprivate let index: Int
  fileprivate let generation: UInt64
  var authority: V4ResourceRoot { root }

  func child(kind: Kind, identity: V4ResourceIdentity, limit: V4ResourceVector) throws -> Self {
    try root.account(
      kind: kind, identity: identity, limit: limit, parent: self, reuseExisting: false)
  }
  func reserve(owner: V4ResourceOwnerKey, value: V4ResourceVector) throws -> V4ResourceReference {
    try root.reserve(account: self, owner: owner, value: value)
  }
  func close(cleanupTimeout: Duration = .seconds(5)) {
    root.close(account: self, timeout: cleanupTimeout)
  }
  func snapshot() throws -> V4ResourceSnapshot { try root.snapshot(account: self) }
  func cleanupStatus() -> CleanupStatus { root.cleanupStatus(account: self) }
  func waitCleanup() async throws -> CleanupStatus { try await root.waitCleanup(account: self) }
  func check() throws { try root.gate.withLock { _ = try root.checkedAccount(self) } }
}

// Copying a handle never creates a new reference. Borrow explicitly reserves
// a distinct fixed slot. Generation checks make stale release/take harmless.
struct V4ResourceReference: Sendable {
  fileprivate let root: V4ResourceRoot
  fileprivate let index: Int
  fileprivate let generation: UInt64

  func check() throws { try root.check(self) }
  func checkRetained() throws { try root.checkRetained(self) }
  func markExecutionTail() throws { try root.markExecutionTail(self) }
  func borrow(executionTail: Bool = false) throws -> Self {
    try root.borrow(self, tail: executionTail)
  }
  func reserveRelated(owner: V4ResourceOwnerKey, value: V4ResourceVector) throws -> Self {
    try root.reserveRelated(self, owner: owner, value: value)
  }
  func transfer(to account: V4ResourceAccount, owner: V4ResourceOwnerKey) throws -> Self {
    try root.transfer(self, account: account, owner: owner)
  }
  func seal() { root.seal(self) }
  func release() { root.release(self) }
  func belongs(to account: V4ResourceAccount) -> Bool { root.belongs(self, account: account) }
}

private final class V4BudgetResult<Value: Sendable>: @unchecked Sendable {
  // All writes/read transfers use the original root gate or the continuation
  // that follows it. No application callback can observe this private holder.
  var value: Value?
}

// Shared execution services have one physical backing at the root. Each
// participant attaches that backing to its original account ancestry; closing
// one TransportEnvironment cannot release or strand another participant's service.
final class V4ResourceService: @unchecked Sendable {
  private let reference: V4ResourceReference
  fileprivate init(_ reference: V4ResourceReference) { self.reference = reference }
  func check() throws { try reference.check() }
  func attach(account: V4ResourceAccount, owner: V4ResourceOwnerKey) throws -> V4ResourceReference {
    try reference.root.attachService(reference, account: account, owner: owner)
  }
  deinit { reference.release() }
}

final class V4ResourceRoot: @unchecked Sendable {
  let diagnosticCounters = V4DiagnosticCounters()
  private static let maximumDepth = 8
  let gate = V4CommitGate()
  private struct AccountSlot {
    var generation: UInt64 = 0
    var kind = V4ResourceAccount.Kind.tenant
    var identity = V4ResourceIdentity(high: 0, low: 0)
    var parent = -1
    var depth = 0
    var limit = V4ResourceVector()
    var used = V4ResourceVector()
    var children = 0
    var charges = 0
    var active = false
    var closed = false
    var cleanupDeadline: ContinuousClock.Instant?
    var cleanupTimeoutRecorded = false
  }
  private struct ChargeSlot {
    var generation: UInt64 = 0
    var value = V4ResourceVector()
    var references = 0
    var active = false
    var sealed = false
    var service = false
  }
  private struct ReferenceSlot {
    var generation: UInt64 = 0
    var charge = 0
    var account = 0
    var owner: V4ResourceOwnerKey?
    var active = false
    var tail = false
  }
  private final class CleanupWaiter: @unchecked Sendable {
    let account: V4ResourceAccount
    var canceled = false
    var continuation: CheckedContinuation<CleanupStatus, Error>?
    var timer: Task<Void, Never>?
    init(_ account: V4ResourceAccount) { self.account = account }
  }

  private final class BudgetWaiter: @unchecked Sendable {
    let account: V4ResourceAccount
    let order: UInt64
    let attempt: @Sendable () throws -> Void
    var canceled = false
    var continuation: CheckedContinuation<Void, Error>?
    init(account: V4ResourceAccount, order: UInt64, attempt: @escaping @Sendable () throws -> Void) {
      self.account = account; self.order = order; self.attempt = attempt
    }
  }
  private enum RootWaiter {
    case cleanup(CleanupWaiter)
    case budget(BudgetWaiter)
  }
  private var budgetOrder: UInt64 = 0
  private var settlingWaiters = false
  weak var applicationExecutor: V4ApplicationExecutor?
  #if os(macOS) || os(iOS)
  private var diagnosticExecutorOwner: V4DiagnosticExecutor?
  func diagnosticExecutor() -> V4DiagnosticExecutor {
    gate.withLock {
      if let diagnosticExecutorOwner { return diagnosticExecutorOwner }
      let executor = V4DiagnosticExecutor(root: self)
      diagnosticExecutorOwner = executor
      return executor
    }
  }
  #endif

  private let limit: V4ResourceVector
  private var used: V4ResourceVector
  private var accounts: [AccountSlot]
  private var charges: [ChargeSlot]
  private var references: [ReferenceSlot]
  // Exact account reference counts per physical backing. This bounded slab
  // preserves overlapping old/new account charges through explicit transfer.
  private var scopeCounts: [UInt32]
  private var waiters: [RootWaiter?]
  private var closed = false

  init(_ configuration: V4ResourceRootConfiguration) throws {
    guard configuration.accounts > 0, configuration.reservations > 0,
      configuration.references >= configuration.reservations, configuration.cleanupWaiters > 0,
      configuration.runtimeOverheadBytes > 0
    else { throw V4ResourceFailure.configuration }
    let (scopeCount, overflow) = configuration.accounts.multipliedReportingOverflow(
      by: configuration.reservations)
    guard !overflow else { throw V4ResourceFailure.configuration }
    var bytes = configuration.runtimeOverheadBytes
    for (count, stride) in [
      (configuration.accounts, MemoryLayout<AccountSlot>.stride),
      (configuration.reservations, MemoryLayout<ChargeSlot>.stride),
      (configuration.references, MemoryLayout<ReferenceSlot>.stride),
      (scopeCount, MemoryLayout<UInt32>.stride),
      // Include the fixed continuation/token/closure storage, not just the
      // pointer in the shared slab. Arbitrary application captures are absent.
      (configuration.cleanupWaiters, MemoryLayout<RootWaiter?>.stride + 1024),
    ] {
      let (size, multiplicationOverflow) = UInt64(count).multipliedReportingOverflow(
        by: UInt64(stride))
      let (total, additionOverflow) = bytes.addingReportingOverflow(size)
      guard !multiplicationOverflow, !additionOverflow else {
        throw V4ResourceFailure.configuration
      }
      bytes = total
    }
    let backing = V4ResourceVector(
      sdkBytes: bytes, tasks: UInt64(configuration.cleanupWaiters),
      timers: UInt64(configuration.cleanupWaiters))
    guard configuration.limit.contains(backing) else { throw V4ResourceFailure.capacity }
    limit = configuration.limit
    used = backing
    accounts = Array(repeating: AccountSlot(), count: configuration.accounts)
    charges = Array(repeating: ChargeSlot(), count: configuration.reservations)
    references = Array(repeating: ReferenceSlot(), count: configuration.references)
    scopeCounts = Array(repeating: 0, count: scopeCount)
    waiters = Array(repeating: nil, count: configuration.cleanupWaiters)
  }

  func account(
    kind: V4ResourceAccount.Kind, identity: V4ResourceIdentity,
    limit: V4ResourceVector, parent: V4ResourceAccount? = nil,
    reuseExisting: Bool = true
  ) throws -> V4ResourceAccount {
    try gate.withLock {
      guard !closed else { throw V4ResourceFailure.closed }
      guard identity.valid, limit != V4ResourceVector() else {
        throw V4ResourceFailure.configuration
      }
      let parentIndex: Int
      if let parent { parentIndex = try checkedAccount(parent) } else { parentIndex = -1 }
      let depth = parentIndex < 0 ? 1 : accounts[parentIndex].depth + 1
      guard depth <= Self.maximumDepth else { throw V4ResourceFailure.configuration }
      for index in accounts.indices where accounts[index].active {
        let current = accounts[index]
        if current.parent == parentIndex && current.kind == kind && current.identity == identity {
          guard reuseExisting else { throw V4ResourceFailure.owner }
          guard current.limit == limit else { throw V4ResourceFailure.configuration }
          guard !current.closed else { throw V4ResourceFailure.closed }
          return V4ResourceAccount(root: self, index: index, generation: current.generation)
        }
      }
      guard let index = accounts.firstIndex(where: { !$0.active && $0.generation < .max }) else {
        throw V4ResourceFailure.capacity
      }
      accounts[index] = AccountSlot(
        generation: accounts[index].generation + 1,
        kind: kind, identity: identity, parent: parentIndex, depth: depth, limit: limit,
        active: true)
      if parentIndex >= 0 { accounts[parentIndex].children += 1 }
      return V4ResourceAccount(root: self, index: index, generation: accounts[index].generation)
    }
  }

  fileprivate func checkedAccount(_ account: V4ResourceAccount, allowClosed: Bool = false) throws
    -> Int
  {
    guard account.root === self, accounts.indices.contains(account.index),
      accounts[account.index].active, accounts[account.index].generation == account.generation
    else { throw V4ResourceFailure.owner }
    if !allowClosed {
      guard !closed else { throw V4ResourceFailure.closed }
      var index = account.index
      while index >= 0 {
        guard !accounts[index].closed else { throw V4ResourceFailure.closed }
        index = accounts[index].parent
      }
    }
    return account.index
  }

  private func validateOwner(_ owner: V4ResourceOwnerKey, account: Int) throws {
    guard owner.valid else { throw V4ResourceFailure.owner }
    var index = account
    var environmentFound = false
    while index >= 0 {
      if accounts[index].kind == .environment || accounts[index].kind == .history {
        guard accounts[index].identity == owner.environment else { throw V4ResourceFailure.owner }
        environmentFound = true
      }
      index = accounts[index].parent
    }
    guard environmentFound else { throw V4ResourceFailure.owner }
  }

  private func freeReference() throws -> Int {
    guard let index = references.firstIndex(where: { !$0.active && $0.generation < .max }) else {
      throw V4ResourceFailure.capacity
    }
    return index
  }

  private func checkScope(account: Int, value: V4ResourceVector, charge: Int? = nil) throws {
    var current = account
    while current >= 0 {
      if charge == nil || scopeCounts[charge! * accounts.count + current] == 0 {
        guard accounts[current].limit.contains(try accounts[current].used.adding(value)) else {
          throw V4ResourceFailure.capacity
        }
      }
      if let charge, scopeCounts[charge * accounts.count + current] == .max {
        throw V4ResourceFailure.capacity
      }
      current = accounts[current].parent
    }
  }

  private func attachScope(account: Int, charge: Int) {
    var current = account
    while current >= 0 {
      let index = charge * accounts.count + current
      if scopeCounts[index] == 0 {
        accounts[current].used = try! accounts[current].used.adding(charges[charge].value)
        accounts[current].charges += 1
      }
      scopeCounts[index] += 1
      current = accounts[current].parent
    }
  }

  func reserve(
    account: V4ResourceAccount, owner: V4ResourceOwnerKey,
    value: V4ResourceVector
  ) throws -> V4ResourceReference {
    do { return try gate.withLock {
      let accountIndex = try checkedAccount(account)
      try validateOwner(owner, account: accountIndex)
      guard value != V4ResourceVector() else { throw V4ResourceFailure.configuration }
      guard !references.contains(where: { $0.active && $0.owner == owner }) else {
        throw V4ResourceFailure.owner
      }
      guard limit.contains(try used.adding(value)) else { throw V4ResourceFailure.capacity }
      try checkScope(account: accountIndex, value: value)
      guard let charge = charges.firstIndex(where: { !$0.active && $0.generation < .max }) else {
        throw V4ResourceFailure.capacity
      }
      let reference = try freeReference()
      charges[charge] = ChargeSlot(
        generation: charges[charge].generation + 1,
        value: value, references: 1, active: true)
      references[reference] = ReferenceSlot(
        generation: references[reference].generation + 1,
        charge: charge, account: accountIndex, owner: owner, active: true)
      attachScope(account: accountIndex, charge: charge)
      used = try used.adding(value)
      return V4ResourceReference(
        root: self, index: reference, generation: references[reference].generation)
    } } catch {
      if let failure = error as? V4ResourceFailure {
        if failure == .capacity { diagnosticCounters.increment(.resourceRefusals) }
        if failure == .owner { diagnosticCounters.increment(.reservationConflicts) }
      }
      throw error
    }
  }

  fileprivate func reserveRelated(_ reference: V4ResourceReference,
    owner: V4ResourceOwnerKey, value: V4ResourceVector) throws -> V4ResourceReference {
    try gate.withLock {
      let original = references[try checkedReference(reference)]
      guard original.account >= 0, original.owner?.environment == owner.environment
      else { throw V4ResourceFailure.owner }
      let account = V4ResourceAccount(root: self, index: original.account,
        generation: accounts[original.account].generation)
      return try reserve(account: account, owner: owner, value: value)
    }
  }

  func reserveService(_ value: V4ResourceVector) throws -> V4ResourceService {
    try gate.withLock {
      guard !closed else { throw V4ResourceFailure.closed }
      guard value != V4ResourceVector() else { throw V4ResourceFailure.configuration }
      guard limit.contains(try used.adding(value)),
        let charge = charges.firstIndex(where: { !$0.active && $0.generation < .max }) else {
        throw V4ResourceFailure.capacity
      }
      let index = try freeReference()
      charges[charge] = ChargeSlot(
        generation: charges[charge].generation + 1, value: value,
        references: 1, active: true, service: true)
      references[index] = ReferenceSlot(
        generation: references[index].generation + 1, charge: charge,
        account: -1, active: true)
      used = try used.adding(value)
      return V4ResourceService(V4ResourceReference(
        root: self, index: index, generation: references[index].generation))
    }
  }

  fileprivate func attachService(
    _ source: V4ResourceReference, account: V4ResourceAccount, owner: V4ResourceOwnerKey
  ) throws -> V4ResourceReference {
    try gate.withLock {
      let original = references[try checkedReference(source)]
      guard original.account == -1, charges[original.charge].service else { throw V4ResourceFailure.owner }
      let target = try checkedAccount(account)
      try validateOwner(owner, account: target)
      guard !references.contains(where: { $0.active && $0.owner == owner }) else { throw V4ResourceFailure.owner }
      try checkScope(account: target, value: charges[original.charge].value, charge: original.charge)
      let index = try freeReference()
      references[index] = ReferenceSlot(
        generation: references[index].generation + 1, charge: original.charge,
        account: target, owner: owner, active: true)
      charges[original.charge].references += 1
      attachScope(account: target, charge: original.charge)
      return V4ResourceReference(root: self, index: index, generation: references[index].generation)
    }
  }

  private func checkedReference(_ reference: V4ResourceReference, allowClosed: Bool = false) throws
    -> Int
  {
    guard reference.root === self, references.indices.contains(reference.index),
      references[reference.index].active,
      references[reference.index].generation == reference.generation
    else { throw V4ResourceFailure.owner }
    let slot = references[reference.index]
    if !allowClosed {
      guard !closed, !charges[slot.charge].sealed else { throw V4ResourceFailure.closed }
      if slot.account < 0 {
        guard slot.account == -1, slot.owner == nil, charges[slot.charge].service else {
          throw V4ResourceFailure.owner
        }
      } else {
        _ = try checkedAccount(V4ResourceAccount(
          root: self, index: slot.account, generation: accounts[slot.account].generation))
      }
    }
    return reference.index
  }

  fileprivate func check(_ reference: V4ResourceReference) throws {
    try gate.withLock { _ = try checkedReference(reference) }
  }

  fileprivate func checkRetained(_ reference: V4ResourceReference) throws {
    // Retention proves existing physical custody only; it creates no authority
    // to admit work or disclose a private protocol input after account close.
    try gate.withLock { _ = try checkedReference(reference, allowClosed: true) }
  }

  fileprivate func markExecutionTail(_ reference: V4ResourceReference) throws {
    try gate.withLock {
      let index = try checkedReference(reference)
      references[index].tail = true
    }
  }

  fileprivate func borrow(_ reference: V4ResourceReference, tail: Bool) throws
    -> V4ResourceReference
  {
    try gate.withLock {
      let original = references[try checkedReference(reference)]
      let index = try freeReference()
      try checkScope(
        account: original.account, value: charges[original.charge].value, charge: original.charge)
      references[index] = ReferenceSlot(
        generation: references[index].generation + 1,
        charge: original.charge, account: original.account, owner: original.owner, active: true,
        tail: tail)
      charges[original.charge].references += 1
      attachScope(account: original.account, charge: original.charge)
      return V4ResourceReference(root: self, index: index, generation: references[index].generation)
    }
  }

  fileprivate func transfer(
    _ reference: V4ResourceReference, account: V4ResourceAccount,
    owner: V4ResourceOwnerKey
  ) throws -> V4ResourceReference {
    try gate.withLock {
      let originalIndex = try checkedReference(reference)
      let original = references[originalIndex]
      let target = try checkedAccount(account)
      try validateOwner(owner, account: target)
      guard owner.environment == original.owner?.environment,
        owner.backing == original.owner?.backing,
        !references.contains(where: { $0.active && $0.owner == owner })
      else { throw V4ResourceFailure.owner }
      let index = try freeReference()
      try checkScope(
        account: target, value: charges[original.charge].value, charge: original.charge)
      references[index] = ReferenceSlot(
        generation: references[index].generation + 1,
        charge: original.charge, account: target, owner: owner, active: true, tail: original.tail)
      charges[original.charge].references += 1
      attachScope(account: target, charge: original.charge)
      releaseLocked(originalIndex)
      return V4ResourceReference(root: self, index: index, generation: references[index].generation)
    }
  }

  fileprivate func belongs(_ reference: V4ResourceReference, account: V4ResourceAccount) -> Bool {
    gate.withLock {
      guard let index = try? checkedReference(reference), (try? checkedAccount(account)) != nil
      else { return false }
      return isDescendant(references[index].account, of: account.index)
    }
  }

  fileprivate func seal(_ reference: V4ResourceReference) {
    gate.withLock {
      guard let index = try? checkedReference(reference, allowClosed: true) else { return }
      charges[references[index].charge].sealed = true
    }
  }

  fileprivate func release(_ reference: V4ResourceReference) {
    gate.withLock {
      guard let index = try? checkedReference(reference, allowClosed: true) else { return }
      releaseLocked(index)
      settleWaitersLocked()
    }
  }

  private func releaseLocked(_ index: Int) {
    let reference = references[index]
    references[index].active = false
    references[index].owner = nil
    let charge = reference.charge
    var current = reference.account
    while current >= 0 {
      let scope = charge * accounts.count + current
      scopeCounts[scope] -= 1
      if scopeCounts[scope] == 0 {
        accounts[current].used = accounts[current].used.subtracting(charges[charge].value)
        accounts[current].charges -= 1
      }
      current = accounts[current].parent
    }
    charges[charge].references -= 1
    if charges[charge].references == 0 {
      used = used.subtracting(charges[charge].value)
      charges[charge].active = false
    }
    retireClosedAccountsLocked()
  }

  private func isDescendant(_ child: Int, of ancestor: Int) -> Bool {
    var current = child
    while current >= 0 {
      if current == ancestor { return true }
      current = accounts[current].parent
    }
    return false
  }

  fileprivate func close(account: V4ResourceAccount, timeout: Duration) {
    gate.withLock {
      guard (try? checkedAccount(account, allowClosed: true)) != nil else { return }
      let deadline = ContinuousClock.now.advanced(by: max(.zero, timeout))
      for index in accounts.indices
      where accounts[index].active && isDescendant(index, of: account.index) {
        accounts[index].closed = true
        accounts[index].cleanupDeadline = min(accounts[index].cleanupDeadline ?? deadline, deadline)
      }
      retireClosedAccountsLocked()
      settleWaitersLocked()
    }
  }

  func close() {
    gate.withLock {
      closed = true
      let deadline = ContinuousClock.now.advanced(by: .seconds(5))
      for index in accounts.indices where accounts[index].active {
        accounts[index].closed = true
        accounts[index].cleanupDeadline = min(accounts[index].cleanupDeadline ?? deadline, deadline)
      }
      retireClosedAccountsLocked()
      settleWaitersLocked()
    }
  }

  private func retireClosedAccountsLocked() {
    for depth in stride(from: Self.maximumDepth, through: 1, by: -1) {
      for index in accounts.indices {
        if accounts[index].active && accounts[index].closed && accounts[index].depth == depth
          && accounts[index].charges == 0 && accounts[index].children == 0
        {
          accounts[index].active = false
          let parent = accounts[index].parent
          if parent >= 0 { accounts[parent].children -= 1 }
        }
      }
    }
  }

  func snapshot() -> V4ResourceSnapshot {
    gate.withLock {
      V4ResourceSnapshot(
        used: used, reservations: charges.reduce(0) { $0 + ($1.active ? 1 : 0) },
        references: references.reduce(0) { $0 + ($1.active ? 1 : 0) },
        executionTails: references.reduce(0) { $0 + ($1.active && $1.tail ? 1 : 0) }, closed: closed,
        resourceWaiters: waiters.reduce(0) { count, waiter in
          if case .budget = waiter { return count + 1 }
          return count
        }
      )
    }
  }

  fileprivate func snapshot(account: V4ResourceAccount) throws -> V4ResourceSnapshot {
    try gate.withLock {
      let index = try checkedAccount(account, allowClosed: true)
      var refs = 0
      var tails = 0
      for reference in references
      where reference.active && isDescendant(reference.account, of: index) {
        refs += 1
        if reference.tail { tails += 1 }
      }
      return V4ResourceSnapshot(
        used: accounts[index].used, reservations: accounts[index].charges,
        references: refs, executionTails: tails, closed: accounts[index].closed,
        resourceWaiters: waiters.reduce(0) { count, slot in
          if case .budget(let waiter) = slot, isDescendant(waiter.account.index, of: index) { return count + 1 }
          return count
        })
    }
  }

  fileprivate func cleanupStatus(account: V4ResourceAccount) -> CleanupStatus {
    gate.withLock { cleanupLocked(account) }
  }

  private func cleanupLocked(_ account: V4ResourceAccount) -> CleanupStatus {
    guard account.root === self, accounts.indices.contains(account.index) else {
      return CleanupStatus()
    }
    let slot = accounts[account.index]
    // A retired/reused generation can only follow the old owner's real exit.
    if slot.generation != account.generation || !slot.active {
      return CleanupStatus(complete: true)
    }
    var tails: UInt64 = 0
    for reference in references
    where reference.active && reference.tail && isDescendant(reference.account, of: account.index) {
      tails += 1
    }
    let timedOut = slot.cleanupDeadline.map { ContinuousClock.now >= $0 } ?? false
    if slot.closed && timedOut && !slot.cleanupTimeoutRecorded {
      accounts[account.index].cleanupTimeoutRecorded = true
      diagnosticCounters.increment(.cleanupTimeouts)
    }
    return CleanupStatus(
      complete: false, cleanupIncomplete: slot.closed && timedOut, pendingCallbacks: tails)
  }

  fileprivate func waitCleanup(account: V4ResourceAccount) async throws -> CleanupStatus {
    let token = CleanupWaiter(account)
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        gate.withLock {
          token.continuation = continuation
          let status = cleanupLocked(account)
          if status.complete || status.cleanupIncomplete {
            token.continuation = nil
            continuation.resume(returning: status)
            return
          }
          if token.canceled {
            token.continuation = nil
            continuation.resume(throwing: CancellationError())
            return
          }
          guard account.root === self, let deadline = accounts[account.index].cleanupDeadline else {
            token.continuation = nil
            continuation.resume(throwing: V4ResourceFailure.closed)
            return
          }
          guard let index = waiters.firstIndex(where: { $0 == nil }) else {
            token.continuation = nil
            continuation.resume(throwing: V4ResourceFailure.capacity)
            return
          }
          waiters[index] = .cleanup(token)
          token.timer = Task { [self, token] in
            do { try await ContinuousClock().sleep(until: deadline) } catch {}
            gate.withLock {
              if case .cleanup(let active) = waiters[index], active === token {
                let status = cleanupLocked(account)
                if let continuation = token.continuation {
                  token.continuation = nil
                  continuation.resume(returning: status)
                }
                waiters[index] = nil
              }
              token.timer = nil
            }
          }
        }
      }
    } onCancel: {
      self.gate.withLock {
        token.canceled = true
        let continuation = token.continuation
        token.continuation = nil
        token.timer?.cancel()
        continuation?.resume(throwing: CancellationError())
      }
    }
  }

  func waitForResources<Value: Sendable>(
    account: V4ResourceAccount,
    attempt: @escaping @Sendable () throws -> Value
  ) async throws -> Value {
    let result = V4BudgetResult<Value>()
    let token = try gate.withLock { () -> BudgetWaiter in
      _ = try checkedAccount(account)
      guard budgetOrder < .max else { throw V4ResourceFailure.capacity }
      budgetOrder += 1
      return BudgetWaiter(account: account, order: budgetOrder, attempt: { result.value = try attempt() })
    }
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        gate.withLock {
          if token.canceled || Task.isCancelled {
            continuation.resume(throwing: SessionError.canceled)
            return
          }
          do {
            _ = try checkedAccount(account)
            try token.attempt()
            continuation.resume()
            return
          } catch V4ResourceFailure.capacity { }
          catch { continuation.resume(throwing: error); return }
          guard let index = waiters.firstIndex(where: { $0 == nil }) else {
            continuation.resume(throwing: V4ResourceFailure.capacity)
            return
          }
          token.continuation = continuation
          waiters[index] = .budget(token)
        }
      }
    } onCancel: {
      self.gate.withLock {
        token.canceled = true
        for index in self.waiters.indices {
          if case .budget(let active) = self.waiters[index], active === token {
            self.waiters[index] = nil
          }
        }
        let continuation = token.continuation
        token.continuation = nil
        continuation?.resume(throwing: SessionError.canceled)
      }
    }
    return try gate.withLock {
      guard let value = result.value else { throw V4ResourceFailure.owner }
      result.value = nil
      return value
    }
  }

  func resourcesChanged() { gate.withLock { settleWaitersLocked() } }

  // Account release/close wakes the same bounded waiter slab. Resource attempts
  // are atomic and never reserve a subset while waiting for the rest.
  private func settleWaitersLocked() {
    // An unsuccessful factory can release a tentative owner under this same
    // recursive gate. It must not retry or resume its own waiter recursively.
    guard !settlingWaiters else { return }
    settlingWaiters = true
    defer { settlingWaiters = false }
    for index in waiters.indices {
      guard case .cleanup(let waiter) = waiters[index], let continuation = waiter.continuation else { continue }
      let status = cleanupLocked(waiter.account)
      if status.complete || status.cleanupIncomplete {
        waiter.continuation = nil
        continuation.resume(returning: status)
        waiter.timer?.cancel()
      }
    }
    var previous: UInt64 = 0
    for _ in waiters.indices {
      var selected: Int?
      var order = UInt64.max
      for index in waiters.indices {
        if case .budget(let waiter) = waiters[index], waiter.order > previous, waiter.order <= order {
          selected = index
          order = waiter.order
        }
      }
      guard let index = selected, case .budget(let waiter) = waiters[index],
        let continuation = waiter.continuation else { break }
      previous = order
      let result: Result<Void, Error>
      do {
        _ = try checkedAccount(waiter.account)
        try waiter.attempt()
        result = .success(())
      } catch V4ResourceFailure.capacity { continue }
      catch { result = .failure(error) }
      waiter.continuation = nil
      waiters[index] = nil
      continuation.resume(with: result)
    }
  }

}

// Durable disk belongs to the tenant/root, independently of a connection
// TransportEnvironment's cleanup. ARC never refunds existing persistent files.
final class V4PersistentDiskCharge: Sendable {
  private let account: V4ResourceAccount
  private let reference: V4ResourceReference
  fileprivate init(account: V4ResourceAccount, reference: V4ResourceReference) {
    self.account = account
    self.reference = reference
  }
  func check() throws { try reference.check() }
  func executionTail() throws -> V4ResourceReference { try reference.borrow(executionTail: true) }
  func retire() {
    account.close()
    reference.release()
  }
}
extension V4ResourceRoot {
  func persistentDisk(tenant: V4ResourceAccount, identity: V4ResourceIdentity, bytes: UInt64) throws
    -> V4PersistentDiskCharge
  {
    try gate.withLock {
      let index = try checkedAccount(tenant)
      guard accounts[index].kind == .tenant, bytes > 0 else { throw V4ResourceFailure.owner }
      // Explicit file-removal verification remains available after the
      // connection Environment closes and retains this original history charge.
      let charge = V4ResourceVector(sdkBytes: 8192, diskBytes: bytes, items: 1, work: 1)
      let account = try tenant.child(kind: .history, identity: identity, limit: charge)
      do {
        let reference = try account.reserve(
          owner: V4ResourceOwnerKey(
            environment: identity, instance: identity, backing: identity,
            kind: 13, direction: 2), value: charge)
        return V4PersistentDiskCharge(account: account, reference: reference)
      } catch {
        account.close()
        throw error
      }
    }
  }
}
