import Foundation

public enum ApplicationInvocationFailure: String, Error, Sendable {
  case dependencyUnavailable = "dependency_unavailable"
  case completionDependencyUnavailable = "completion_dependency_unavailable"
  case knownApplicationDependency = "known_application_dependency"
  case closed, canceled
}

// Original application diagnostics may be retained by actual publication
// callbacks without retaining application authority or creating another worker.
protocol V4ApplicationDiagnosticLifetime: AnyObject, Sendable {
  func failed(_ error: any Error)
  func failed(code: TransportDiagnosticCode)
}

/// A borrowed, unforgeable view of one real application invocation. Keeping
/// this view after the callback exits grants no right to create more SDK work.
public final class ApplicationInvocationContext: @unchecked Sendable {
  let invocation: V4ApplicationInvocation
  init(_ invocation: V4ApplicationInvocation) { self.invocation = invocation }
  #if os(macOS) || os(iOS)
  var diagnosticLifetime: (any V4ApplicationDiagnosticLifetime)? {
    get { invocation.gate.withLock { invocation.diagnosticLifetime } }
    set { invocation.gate.withLock { invocation.diagnosticLifetime = newValue } }
  }
  #endif
  public var isCancelled: Bool {
    invocation.gate.withLock {
      !invocation.active || invocation.canceled || invocation.ancestors.contains { $0.active && $0.canceled }
    }
  }
  public func checkCancellation() throws {
    try invocation.gate.withLock {
      guard invocation.active else { throw ApplicationInvocationFailure.closed }
      guard !invocation.canceled,
        !invocation.ancestors.contains(where: { $0.active && $0.canceled }) else {
        throw ApplicationInvocationFailure.canceled
      }
    }
  }
}

/// Local finite application capacity; independent of the authenticated wire
/// application profile and never learned from a peer advertisement.
public struct ApplicationResourceProfile: Sendable, Equatable {
  public let name: String
  public let ordinaryRunning: Int
  public let ordinaryReady: Int
  public let residentRunning: Int
  public let residentReady: Int
  public let ordinaryBackingBytes: UInt64
  public let queryOwnerLimit: Int
  public static let client = ApplicationResourceProfile(name: "client", ordinaryRunning: 26, ordinaryReady: 52,
    residentRunning: 18, residentReady: 36, ordinaryBackingBytes: 7 * 1024 * 1024, queryOwnerLimit: 12)
  public static let server = ApplicationResourceProfile(name: "server", ordinaryRunning: 26, ordinaryReady: 52,
    residentRunning: 18, residentReady: 36, ordinaryBackingBytes: 7 * 1024 * 1024, queryOwnerLimit: 12)
  public static let constrained = ApplicationResourceProfile(name: "constrained", ordinaryRunning: 8, ordinaryReady: 16,
    residentRunning: 6, residentReady: 12, ordinaryBackingBytes: 3 * 1024 * 1024, queryOwnerLimit: 6)
  private init(name: String, ordinaryRunning: Int, ordinaryReady: Int, residentRunning: Int,
    residentReady: Int, ordinaryBackingBytes: UInt64, queryOwnerLimit: Int) {
    self.name = name; self.ordinaryRunning = ordinaryRunning; self.ordinaryReady = ordinaryReady
    self.residentRunning = residentRunning; self.residentReady = residentReady
    self.ordinaryBackingBytes = ordinaryBackingBytes; self.queryOwnerLimit = queryOwnerLimit
  }
  public static func custom(ordinaryRunning: Int, ordinaryReady: Int, residentRunning: Int,
    residentReady: Int, ordinaryBackingBytes: UInt64, queryOwners: Int) throws -> Self {
    guard (1...1024).contains(ordinaryRunning), (1...4096).contains(ordinaryReady),
      (0...ordinaryRunning).contains(residentRunning), (0...ordinaryReady).contains(residentReady),
      (1...128).contains(queryOwners), ordinaryBackingBytes >= UInt64(ordinaryRunning + ordinaryReady) * 8192 else {
      throw ServiceFailure.configurationCapacity
    }
    return Self(name: "", ordinaryRunning: ordinaryRunning, ordinaryReady: ordinaryReady,
      residentRunning: residentRunning, residentReady: residentReady,
      ordinaryBackingBytes: ordinaryBackingBytes, queryOwnerLimit: queryOwners)
  }
  var ordinaryLimit: Int { ordinaryRunning }
  var residentLimit: Int { residentRunning }
  var ordinaryBytes: UInt64 { ordinaryBackingBytes }
  var queryOwners: Int { queryOwnerLimit }
}

enum V4ApplicationLane: Equatable { case ordinary, resident, completion }

// Direct ordinary synchronous stages retain their existing permit, inherit
// every live ancestor and close their child context at the real function exit.
final class V4SynchronousApplicationStage: @unchecked Sendable {
  let parent: V4ApplicationInvocation
  let context: ApplicationInvocationContext
  private var active = true
  init(parent: V4ApplicationInvocation, child: V4ApplicationInvocation) {
    self.parent = parent; context = ApplicationInvocationContext(child)
  }
  func finish() {
    parent.gate.withLock {
      guard active else { return }
      active = false
      context.invocation.active = false
      #if os(macOS) || os(iOS)
      context.invocation.diagnosticLifetime = nil
      #endif
      context.invocation.permit = nil
      context.invocation.ancestors = []
      parent.synchronousDepth -= 1
      if !parent.active, parent.synchronousDepth == 0 {
        #if os(macOS) || os(iOS)
        parent.diagnosticLifetime = nil
        #endif
        let permit = parent.permit
        parent.permit = nil
        parent.ancestors = []
        permit?.release()
      }
    }
  }
  deinit { finish() }
}

final class V4ApplicationInvocation: @unchecked Sendable {
  let gate: NSRecursiveLock
  var permit: V4ApplicationPermit?
  var ancestors: [V4ApplicationInvocation]
  var active = true
  var canceled = false
  var synchronousDepth = 0
  #if os(macOS) || os(iOS)
  var diagnosticLifetime: (any V4ApplicationDiagnosticLifetime)?
  #endif
  init(permit: V4ApplicationPermit, ancestors: [V4ApplicationInvocation]) {
    gate = permit.group.executor.gate; self.permit = permit; self.ancestors = ancestors
    #if os(macOS) || os(iOS)
    diagnosticLifetime = ancestors.last?.diagnosticLifetime
    #endif
  }
  func close() {
    let original = gate.withLock { () -> V4ApplicationPermit? in
      guard active else { return nil }
      active = false
      guard synchronousDepth == 0 else { return nil }
      #if os(macOS) || os(iOS)
      diagnosticLifetime = nil
      #endif
      let original = permit
      permit = nil
      ancestors = []
      return original
    }
    original?.release()
  }
}

final class V4ApplicationPermit: @unchecked Sendable {
  let group: V4ApplicationGroup
  let lane: V4ApplicationLane
  let ancestors: [V4ApplicationInvocation]
  var released = false
  var started = false
  let preparedPosition: V4OrdinaryReservation?
  init(group: V4ApplicationGroup, lane: V4ApplicationLane, ancestors: [V4ApplicationInvocation],
    preparedPosition: V4OrdinaryReservation? = nil) {
    self.group = group; self.lane = lane; self.ancestors = ancestors; self.preparedPosition = preparedPosition
  }
  func release() { group.executor.returnPermit(self) }
}

final class V4CompletionClaim: @unchecked Sendable {
  let group: V4ApplicationGroup
  let parent: V4ApplicationInvocation
  var active = true
  init(group: V4ApplicationGroup, parent: V4ApplicationInvocation) { self.group = group; self.parent = parent }
  func release() { group.executor.returnClaim(self) }
  deinit { release() }
}

struct V4CompletionRegistration: Sendable {
  let index: Int
  let generation: UInt64
}

protocol V4CompletionWork: AnyObject, Sendable {
  var group: V4ApplicationGroup { get }
  var order: UInt64 { get set }
  var eligible: Bool { get }
  var jobPending: Bool { get }
  var ready: Bool { get }
  var claim: V4CompletionClaim? { get }
  func selectReady()
  func selectClaimed()
  func startJob()
  func grant(_ permit: V4ApplicationPermit)
  func cancelBeforeInput()
}

// One executor is shared by all participating Environments at the same budget
// root. Group descriptors and payloads keep their own account ancestry.
struct V4ApplicationWorkload: Sendable, Equatable {
  let ordinaryRunning: Int
  let ordinaryReserved: Int
  let residentRunning: Int
  let completionRunning: Int
  let completionClaims: Int
  let completionReady: Int
  let completionOwners: Int
}

final class V4ApplicationExecutor: @unchecked Sendable {
  private struct GroupSlot { weak var value: V4ApplicationGroup? }
  private struct CompletionSlot {
    weak var value: (any V4CompletionWork)?
    var generation: UInt64 = 0
    var active = false
    var reserved = false
  }
  let root: V4ResourceRoot
  var gate: NSRecursiveLock { root.gate }
  let ordinaryService: V4ResourceService
  let fixedQueries: V4FixedQueryExecutor
  private(set) var completionService: V4ResourceService?
  private(set) var managementService: V4ResourceService?
  private struct OrdinarySlot { weak var value: V4ApplicationWork?; var reservation: UUID? }
  let profile: ApplicationResourceProfile
  private var ordinaryJobs: [OrdinarySlot]
  private var groups = Array(repeating: GroupSlot(), count: 4096)
  private var completions = Array(repeating: CompletionSlot(), count: 4096)
  private var queryOwners = 0
  private var managementOwners = 0
  private var ordinary = 0
  private var resident = 0
  private var ordinaryReserved = 0
  private var residentReserved = 0
  private var runningCompletions = 0
  private var claims = 0
  private var readyCompletions = 0
  private var order: UInt64 = 0
  private weak var lastGroup: V4ApplicationGroup?

  init(root: V4ResourceRoot, profile: ApplicationResourceProfile = .client) throws {
    self.root = root; self.profile = profile
    fixedQueries = try V4FixedQueryExecutor(root: root, maximum: profile.queryOwners)
    ordinaryJobs = Array(repeating: OrdinarySlot(), count: profile.ordinaryRunning + profile.ordinaryReady)
    // Real ordinary service is unavailable to maintenance, fixed queries and
    // Completion. Its fixed slab includes the bounded participant indices.
    ordinaryService = try root.reserveService(V4ResourceVector(
      sdkBytes: profile.ordinaryBytes, items: UInt64(profile.ordinaryRunning + profile.ordinaryReady + 1),
      work: UInt64(profile.ordinaryLimit), tasks: UInt64(profile.ordinaryLimit)))
  }

  var workload: V4ApplicationWorkload {
    gate.withLock {
      V4ApplicationWorkload(ordinaryRunning: ordinary, ordinaryReserved: ordinaryReserved,
        residentRunning: resident, completionRunning: runningCompletions,
        completionClaims: claims, completionReady: readyCompletions,
        completionOwners: completions.reduce(0) { $0 + ($1.active ? 1 : 0) })
    }
  }

  func attach(
    account: V4ResourceAccount, owner: V4ResourceOwnerKey,
    reference: V4ResourceReference
  ) throws -> V4ApplicationGroup {
    try gate.withLock {
      try ordinaryService.check()
      guard let index = groups.firstIndex(where: { $0.value == nil }) else { throw V4ResourceFailure.capacity }
      let group = try V4ApplicationGroup(executor: self, account: account, owner: owner, reference: reference)
      groups[index].value = group
      return group
    }
  }

  func protectCompletions() throws {
    try gate.withLock {
      guard completionService == nil else { return }
      let service = try root.reserveService(V4ResourceVector(
        sdkBytes: 256 * 1024, items: 6, work: 2, tasks: 6))
      var attached: [V4ApplicationGroup] = []
      do {
        for slot in groups {
          guard let group = slot.value, !group.closed else { continue }
          try group.attachCompletion(service)
          attached.append(group)
        }
        completionService = service
      } catch {
        for group in attached { group.detachCompletion() }
        throw error
      }
    }
  }

  func protectManagement() throws {
    try gate.withLock {
      guard managementService == nil else { return }
      let service = try root.reserveService(V4ResourceVector(sdkBytes: 256 * 1024, items: 3, work: 2, tasks: 2))
      var attached: [V4ApplicationGroup] = []
      do {
        for slot in groups {
          guard let group = slot.value, !group.closed else { continue }
          try group.attachManagement(service); attached.append(group)
        }
        managementService = service
      } catch { for group in attached { group.detachManagement() }; throw error }
    }
  }

  private func ancestry(_ context: ApplicationInvocationContext?) throws -> [V4ApplicationInvocation] {
    guard let state = context?.invocation else { return [] }
    guard state.active, !state.canceled, let permit = state.permit, !permit.released,
      permit.group.executor === self else { throw ApplicationInvocationFailure.dependencyUnavailable }
    let parents = [state] + state.ancestors.filter { $0.active && $0.permit?.released == false }
    guard parents.count <= 8, !parents.contains(where: { $0.canceled }) else {
      throw ApplicationInvocationFailure.dependencyUnavailable
    }
    return parents
  }

  func hasCompletionAncestor(_ context: ApplicationInvocationContext?) throws -> Bool {
    try gate.withLock { try ancestry(context).contains { $0.permit?.lane == .completion } }
  }

  func depends(_ context: ApplicationInvocationContext?, on other: V4ApplicationInvocation?) throws -> Bool {
    try gate.withLock {
      let parents = try ancestry(context)
      guard let other, other.active else { return false }
      guard other.permit?.group.executor === self else {
        throw ApplicationInvocationFailure.dependencyUnavailable
      }
      guard let current = context?.invocation else { return false }
      return current === other || parents.dropFirst().contains { $0 === other }
    }
  }

  func tryOrdinary(
    group: V4ApplicationGroup, context: ApplicationInvocationContext?, resident requestedResident: Bool = false,
    preparedPosition: V4OrdinaryReservation? = nil
  ) throws -> V4ApplicationPermit {
    try gate.withLock {
      try group.check()
      let parents = try ancestry(context)
      let isResident = requestedResident || parents.contains { $0.permit?.lane == .resident }
      if let preparedPosition {
        guard preparedPosition.group === group, !isResident,
          ordinaryJobs.indices.contains(preparedPosition.index),
          ordinaryJobs[preparedPosition.index].reservation == preparedPosition.token,
          ordinaryJobs[preparedPosition.index].value == nil else { throw ApplicationInvocationFailure.dependencyUnavailable }
        try preparedPosition.check(); group.users += 1
        return V4ApplicationPermit(group: group, lane: .ordinary, ancestors: parents, preparedPosition: preparedPosition)
      }
      guard ordinaryReserved < profile.ordinaryReady, !isResident || residentReserved < profile.residentReady else {
        if context == nil { throw V4ResourceFailure.capacity }
        throw ApplicationInvocationFailure.dependencyUnavailable
      }
      ordinaryReserved += 1
      if isResident { residentReserved += 1 }
      group.users += 1
      return V4ApplicationPermit(group: group, lane: isResident ? .resident : .ordinary, ancestors: parents)
    }
  }

  func synchronousStage(
    group: V4ApplicationGroup, context: ApplicationInvocationContext?
  ) throws -> V4SynchronousApplicationStage? {
    try gate.withLock {
      guard let context else { return nil }
      let parents = try ancestry(context)
      guard let permit = context.invocation.permit, permit.lane != .completion else { return nil }
      try group.check()
      guard context.invocation.synchronousDepth == 0, parents.count < 8 else {
        throw ApplicationInvocationFailure.dependencyUnavailable
      }
      let child = V4ApplicationInvocation(permit: permit, ancestors: parents)
      context.invocation.synchronousDepth += 1
      return V4SynchronousApplicationStage(parent: context.invocation, child: child)
    }
  }

  func reserveQueryOwner(group: V4ApplicationGroup) throws -> V4ApplicationQueryOwner {
    try gate.withLock {
      try group.check()
      guard queryOwners < profile.queryOwners else { throw V4ResourceFailure.capacity }
      queryOwners += 1; group.users += 1
      return V4ApplicationQueryOwner(group: group)
    }
  }
  func reserveManagementOwner(group: V4ApplicationGroup) throws -> V4ApplicationQueryOwner {
    try gate.withLock {
      try group.check()
      guard let managementService else { throw V4ResourceFailure.capacity }
      try managementService.check()
      // The root's prepaid M service has two original control positions. Q
      // occupancy cannot consume them, including abandoned network tails.
      guard managementOwners < 2 else { throw V4ResourceFailure.capacity }
      managementOwners += 1; group.users += 1
      return V4ApplicationQueryOwner(group: group, management: true)
    }
  }
  func returnQueryOwner(_ owner: V4ApplicationQueryOwner) {
    gate.withLock {
      guard owner.active else { return }; owner.active = false
      if owner.management { managementOwners -= 1 } else { queryOwners -= 1 }
      owner.group.users -= 1; owner.group.cleanup(); root.resourcesChanged()
    }
  }
  func scheduleOrdinary() {
    let selected = gate.withLock { () -> [V4ApplicationWork] in
      var selected: [V4ApplicationWork] = []
      for slot in ordinaryJobs {
        guard ordinary < profile.ordinaryRunning else { break }
        guard let work = slot.value, work.eligible else { continue }
        if work.select() { selected.append(work) }
      }
      return selected
    }
    for work in selected { work.launch() }
  }

  func reserveOrdinaryPosition(group: V4ApplicationGroup) throws -> V4OrdinaryReservation {
    try gate.withLock {
      try group.check()
      guard ordinaryReserved < profile.ordinaryReady,
        let index = ordinaryJobs.firstIndex(where: { $0.value == nil && $0.reservation == nil }) else {
        throw V4ResourceFailure.capacity
      }
      let reference = try group.account.reserve(owner: group.nextOwner(kind: 28),
        value: V4ResourceVector(sdkBytes: 8192, items: 1))
      let token = UUID(); ordinaryJobs[index].reservation = token
      ordinaryReserved += 1; group.users += 1
      return V4OrdinaryReservation(group: group, index: index, token: token, reference: reference)
    }
  }
  fileprivate func returnOrdinaryPosition(_ reservation: V4OrdinaryReservation) {
    gate.withLock {
      guard ordinaryJobs.indices.contains(reservation.index),
        ordinaryJobs[reservation.index].reservation == reservation.token else { return }
      ordinaryJobs[reservation.index].reservation = nil
      ordinaryReserved -= 1; reservation.group.users -= 1; reservation.group.cleanup()
    }
  }
  func registerOrdinary(_ work: V4ApplicationWork, reservation: V4OrdinaryReservation? = nil) throws {
    try gate.withLock {
      if let reservation {
        guard reservation.group === work.group, ordinaryJobs.indices.contains(reservation.index),
          ordinaryJobs[reservation.index].reservation == reservation.token,
          ordinaryJobs[reservation.index].value == nil else { throw V4ResourceFailure.capacity }
        ordinaryJobs[reservation.index].value = work; return
      }
      guard let index = ordinaryJobs.firstIndex(where: { $0.value == nil && $0.reservation == nil }) else {
        throw V4ResourceFailure.capacity
      }
      ordinaryJobs[index].value = work
    }
  }

  func unregisterOrdinary(_ work: V4ApplicationWork) {
    gate.withLock {
      if let index = ordinaryJobs.firstIndex(where: { $0.value === work }) { ordinaryJobs[index].value = nil }
    }
  }

  func beginOrdinary(_ permit: V4ApplicationPermit) throws {
    try gate.withLock {
      guard !permit.released, !permit.started, permit.group.executor === self,
        permit.lane != .completion else { throw ApplicationInvocationFailure.closed }
      try permit.group.check()
      guard ordinary < profile.ordinaryRunning, permit.lane != .resident || resident < profile.residentRunning else { throw V4ResourceFailure.capacity }
      permit.started = true
      if permit.preparedPosition == nil { ordinaryReserved -= 1 }
      ordinary += 1
      if permit.lane == .resident { residentReserved -= 1; resident += 1 }
    }
  }

  func claim(group: V4ApplicationGroup, context: ApplicationInvocationContext) throws -> V4CompletionClaim? {
    try gate.withLock {
      let parents = try ancestry(context)
      guard parents.contains(where: { $0.permit?.lane == .completion }) else { return nil }
      try group.check()
      guard runningCompletions + claims < 2 else { throw ApplicationInvocationFailure.completionDependencyUnavailable }
      claims += 1
      group.users += 1
      return V4CompletionClaim(group: group, parent: context.invocation)
    }
  }

  func reserveCompletionPosition(group: V4ApplicationGroup) throws -> V4CompletionReservation {
    try gate.withLock {
      try group.check()
      guard completionService != nil,
        let index = completions.firstIndex(where: { !$0.active && $0.generation < .max }) else { throw V4ResourceFailure.capacity }
      completions[index].generation += 1; completions[index].active = true; completions[index].reserved = true
      group.users += 1
      return V4CompletionReservation(group: group,
        registration: V4CompletionRegistration(index: index, generation: completions[index].generation))
    }
  }
  fileprivate func returnCompletionPosition(_ reservation: V4CompletionReservation) {
    gate.withLock {
      let registration = reservation.registration
      guard completions.indices.contains(registration.index), completions[registration.index].active,
        completions[registration.index].generation == registration.generation,
        completions[registration.index].reserved, completions[registration.index].value == nil else { return }
      completions[registration.index].active = false; completions[registration.index].reserved = false
      reservation.group.users -= 1; reservation.group.cleanup(); root.resourcesChanged()
    }
  }
  func register(_ work: any V4CompletionWork, reservation: V4CompletionReservation? = nil) throws -> V4CompletionRegistration {
    try gate.withLock {
      try work.group.check()
      if let reservation {
        let registration = reservation.registration
        guard reservation.group === work.group, completions.indices.contains(registration.index),
          completions[registration.index].active, completions[registration.index].reserved,
          completions[registration.index].generation == registration.generation,
          completions[registration.index].value == nil, order < .max else { throw V4ResourceFailure.capacity }
        order += 1; work.order = order; completions[registration.index].value = work
        return registration
      }
      guard completionService != nil, order < .max,
        let index = completions.firstIndex(where: { !$0.active && $0.generation < .max }) else { throw V4ResourceFailure.capacity }
      order += 1
      work.order = order
      completions[index].generation += 1
      completions[index].active = true
      completions[index].value = work
      work.group.users += 1
      return V4CompletionRegistration(index: index, generation: completions[index].generation)
    }
  }

  func unregister(_ registration: V4CompletionRegistration, group: V4ApplicationGroup) {
    gate.withLock {
      guard completions.indices.contains(registration.index),
        completions[registration.index].active,
        completions[registration.index].generation == registration.generation else { return }
      completions[registration.index].value = nil
      if completions[registration.index].reserved { root.resourcesChanged(); return }
      completions[registration.index].active = false
      group.users -= 1
      group.cleanup()
      root.resourcesChanged()
    }
  }

  private func usableClaim(_ work: any V4CompletionWork) -> V4CompletionClaim? {
    guard let claim = work.claim, claim.active else { return nil }
    guard claim.parent.active, claim.parent.permit?.released == false else {
      returnClaimLocked(claim)
      return nil
    }
    return claim
  }

  // Complete inputs with actual receivers are indexed here. Dormant results
  // create neither a task nor a ready job. Jobs waiting for a real permit are
  // limited by the same four protected ready positions.
  func schedule() {
    let selected = gate.withLock { () -> [any V4CompletionWork] in
      var selected: [any V4CompletionWork] = []
      // A promised dependent child cannot sit behind four unclaimed ready
      // jobs that its own claim prevents from running. Convert that promise
      // directly to its protected permit without taking another ready slot.
      for slot in completions {
        guard let work = slot.value, work.eligible, !work.jobPending,
          let claim = usableClaim(work) else { continue }
        returnClaimLocked(claim)
        runningCompletions += 1
        work.group.users += 1
        work.selectClaimed()
        work.grant(V4ApplicationPermit(group: work.group, lane: .completion,
          ancestors: [claim.parent] + claim.parent.ancestors))
        lastGroup = work.group
        selected.append(work)
      }
      for slot in completions {
        guard let work = slot.value, work.ready, work.eligible else { continue }
        let claim = usableClaim(work)
        guard claim != nil || runningCompletions + claims < 2 else { continue }
        if let claim { returnClaimLocked(claim) }
        runningCompletions += 1
        readyCompletions -= 1
        work.group.users += 1
        work.grant(V4ApplicationPermit(group: work.group, lane: .completion,
          ancestors: claim.map { [$0.parent] + $0.parent.ancestors } ?? []))
      }
      while readyCompletions < 4 {
        var candidate: (any V4CompletionWork)?
        var fallback: (any V4CompletionWork)?
        for slot in completions {
          guard let work = slot.value, work.eligible, !work.jobPending else { continue }
          if fallback == nil || work.order < fallback!.order { fallback = work }
          if work.group !== lastGroup, candidate == nil || work.order < candidate!.order { candidate = work }
        }
        guard let work = candidate ?? fallback else { break }
        work.selectReady()
        readyCompletions += 1
        lastGroup = work.group
        selected.append(work)
      }
      return selected
    }
    // Runtime task creation is outside the protocol/resource gate. The task
    // still has to win its original complete-input guard before application entry.
    for work in selected { work.startJob() }
    scheduleOrdinary()
  }

  func enter(_ work: any V4CompletionWork) -> V4ApplicationPermit? {
    gate.withLock {
      guard work.ready, work.eligible else { return nil }
      let claim = usableClaim(work)
      guard claim != nil || runningCompletions + claims < 2 else { return nil }
      if let claim { returnClaimLocked(claim) }
      runningCompletions += 1
      readyCompletions -= 1
      work.group.users += 1
      return V4ApplicationPermit(group: work.group, lane: .completion,
        ancestors: claim.map { [$0.parent] + $0.parent.ancestors } ?? [])
    }
  }

  func leaveReady(_ work: any V4CompletionWork) {
    gate.withLock { if work.ready { readyCompletions -= 1 } }
  }

  private func returnClaimLocked(_ claim: V4CompletionClaim) {
    guard claim.active else { return }
    claim.active = false
    claims -= 1
    claim.group.users -= 1
    claim.group.cleanup()
  }
  func returnClaim(_ claim: V4CompletionClaim) { gate.withLock { returnClaimLocked(claim) } }
  func returnPermit(_ permit: V4ApplicationPermit) {
    gate.withLock {
      guard !permit.released else { return }
      permit.released = true
      if permit.lane == .completion { runningCompletions -= 1 }
      else if permit.started {
        ordinary -= 1
        if permit.lane == .resident { resident -= 1 }
      } else if permit.preparedPosition == nil {
        ordinaryReserved -= 1
        if permit.lane == .resident { residentReserved -= 1 }
      }
      permit.group.users -= 1
      permit.group.cleanup()
    }
  }

  func close(_ group: V4ApplicationGroup) {
    gate.withLock {
      for slot in ordinaryJobs {
        if let work = slot.value, work.group === group { work.cancel() }
      }
      for slot in completions {
        if let work = slot.value, work.group === group { work.cancelBeforeInput() }
      }
      if lastGroup === group { lastGroup = nil }
      group.cleanup()
    }
  }
}

final class V4CompletionReservation: @unchecked Sendable {
  let group: V4ApplicationGroup
  let registration: V4CompletionRegistration
  init(group: V4ApplicationGroup, registration: V4CompletionRegistration) {
    self.group = group; self.registration = registration
  }
  deinit { group.executor.returnCompletionPosition(self) }
}

final class V4ApplicationQueryOwner: @unchecked Sendable {
  let group: V4ApplicationGroup
  var active = true
  let management: Bool
  init(group: V4ApplicationGroup, management: Bool = false) { self.group = group; self.management = management }
  func release() { group.executor.returnQueryOwner(self) }
  deinit { release() }
}

final class V4ApplicationGroup: @unchecked Sendable {
  let executor: V4ApplicationExecutor
  let account: V4ResourceAccount
  private let baseOwner: V4ResourceOwnerKey
  private var nonce: UInt64 = 0
  private var reference: V4ResourceReference?
  private var ordinary: V4ResourceReference?
  private var completion: V4ResourceReference?
  private var management: V4ResourceReference?
  private var queries: V4ResourceReference?
  var closed = false
  var users = 0

  init(executor: V4ApplicationExecutor, account: V4ResourceAccount, owner: V4ResourceOwnerKey,
       reference: V4ResourceReference) throws {
    self.executor = executor; self.account = account; baseOwner = owner; self.reference = reference
    do {
      queries = try executor.fixedQueries.attach(account: account, owner: nextOwner(kind: 41))
      ordinary = try executor.ordinaryService.attach(account: account, owner: nextOwner(kind: 25))
      if let service = executor.completionService { try attachCompletion(service) }
      if let service = executor.managementService { try attachManagement(service) }
    } catch {
      ordinary?.release(); ordinary = nil
      completion?.release(); completion = nil
      management?.release(); management = nil
      queries?.release(); queries = nil
      throw error
    }
  }
  deinit {
    ordinary?.release(); completion?.release(); management?.release(); queries?.release(); reference?.release()
  }
  func nextOwner(kind: UInt16) throws -> V4ResourceOwnerKey {
    guard nonce < .max else { throw V4ResourceFailure.capacity }
    nonce += 1
    return V4ResourceOwnerKey(environment: baseOwner.environment,
      instance: baseOwner.instance,
      backing: V4ResourceIdentity(high: baseOwner.instance.low, low: nonce), kind: kind, direction: 2)
  }
  func check() throws {
    guard !closed, let reference else { throw ApplicationInvocationFailure.closed }
    try reference.check()
    try executor.ordinaryService.check()
  }
  func attachCompletion(_ service: V4ResourceService) throws {
    completion = try service.attach(account: account, owner: nextOwner(kind: 26))
  }
  func detachCompletion() { completion?.release(); completion = nil }
  func attachManagement(_ service: V4ResourceService) throws {
    management = try service.attach(account: account, owner: nextOwner(kind: 35))
  }
  func detachManagement() { management?.release(); management = nil }

  var workload: V4ApplicationWorkload { executor.workload }

  func reserveCompletion(bytes: Int) throws -> V4ResourceReference {
    try executor.gate.withLock {
      try check()
      guard (0...1_048_576).contains(bytes) else { throw V4ResourceFailure.configuration }
      return try account.reserve(owner: nextOwner(kind: 27), value: V4ResourceVector(
        sdkBytes: UInt64(bytes) * 2 + 8192, items: 2))
    }
  }
  func close() {
    executor.gate.withLock { closed = true }
    executor.close(self)
  }
  func cleanup() {
    guard closed, users == 0 else { return }
    ordinary?.release(); ordinary = nil
    completion?.release(); completion = nil
    management?.release(); management = nil
    queries?.release(); queries = nil
    reference?.release(); reference = nil
  }
}

// A prepared ordinary position owns its actual target capacity before a send
// entry is admitted. Task creation happens only after the entry gate exits.
final class V4ApplicationWork: @unchecked Sendable {
  let group: V4ApplicationGroup
  private var permit: V4ApplicationPermit?
  private var reference: V4ResourceReference?
  private let preparedPosition: V4OrdinaryReservation?
  private var operation: (@Sendable (ApplicationInvocationContext) async -> Void)?
  private var onExit: (@Sendable () -> Void)?
  private var task: Task<Void, Never>?
  private var invocation: V4ApplicationInvocation?
  private var canceled = false
  private var started = false
  private var finished = false
  private var gate: NSRecursiveLock { group.executor.gate }

  init(group: V4ApplicationGroup, context: ApplicationInvocationContext?, resident: Bool = false,
       preparedPosition: V4OrdinaryReservation? = nil, operation: @escaping @Sendable (ApplicationInvocationContext) async -> Void,
       onExit: @escaping @Sendable () -> Void) throws {
    self.group = group; self.operation = operation; self.onExit = onExit; self.preparedPosition = preparedPosition
    try gate.withLock {
      let permit = try group.executor.tryOrdinary(group: group, context: context, resident: resident, preparedPosition: preparedPosition)
      do {
        if preparedPosition == nil {
          reference = try group.account.reserve(owner: group.nextOwner(kind: 28),
            value: V4ResourceVector(sdkBytes: 8192, items: 1))
        }
        self.permit = permit
      } catch { permit.release(); throw error }
    }
    do { try group.executor.registerOrdinary(self, reservation: preparedPosition) }
    catch { permit?.release(); reference?.release(); permit = nil; reference = nil; throw error }
  }

  var isFinished: Bool { gate.withLock { finished } }
  func hasDependency(_ context: ApplicationInvocationContext?) throws -> Bool {
    try gate.withLock {
      guard let invocation, let context else { return false }
      // The waiter is a dependency of this work when this work is the waiter
      // itself or was admitted beneath the waiter's invocation.
      return try group.executor.depends(ApplicationInvocationContext(invocation), on: context.invocation)
    }
  }
  var eligible: Bool { started && !finished && !canceled && permit?.started == false }
  func select() -> Bool {
    guard eligible, let permit else { return false }
    do { try group.executor.beginOrdinary(permit); return true }
    catch { return false }
  }
  func start() {
    gate.withLock { if !finished { started = true } }
    group.executor.scheduleOrdinary()
  }
  func launch() {
    let task = Task.detached { [self] in
      let work = gate.withLock { () -> ((@Sendable (ApplicationInvocationContext) async -> Void), ApplicationInvocationContext)? in
        guard !canceled, let permit, let operation else { return nil }
        do {
          try group.check()
          let state = V4ApplicationInvocation(permit: permit, ancestors: permit.ancestors)
          invocation = state
          self.operation = nil
          return (operation, ApplicationInvocationContext(state))
        } catch { return nil }
      }
      if let (operation, context) = work {
        await operation(context)
        context.invocation.close()
      }
      gate.withLock {
        invocation = nil
        operation = nil
        permit?.release(); permit = nil
        reference?.release(); reference = nil
        finished = true
        self.task = nil
        group.executor.unregisterOrdinary(self)
        let exited = onExit
        onExit = nil
        exited?()
      }
      group.executor.schedule()
    }
    gate.withLock { if !finished { self.task = task } }
  }

  func cancel() {
    gate.withLock {
      canceled = true
      invocation?.canceled = true
      task?.cancel()
      if permit?.started == false {
        permit?.release(); permit = nil; reference?.release(); reference = nil
        operation = nil; finished = true; group.executor.unregisterOrdinary(self)
        let exited = onExit; onExit = nil; exited?()
      }
    }
    group.executor.scheduleOrdinary()
  }
  deinit { permit?.release(); reference?.release() }
}

private final class V4ApplicationCall<Value: Sendable>: @unchecked Sendable {
  let gate: NSRecursiveLock
  var canceled = false
  var result: Result<Value, Error>?
  var continuation: CheckedContinuation<Value, Error>?
  var work: V4ApplicationWork?
  init(gate: NSRecursiveLock) { self.gate = gate }
}

extension V4ApplicationGroup {
  func invoke<Value: Sendable>(
    context: ApplicationInvocationContext? = nil, preparedPosition: V4OrdinaryReservation? = nil,
    operation: @escaping @Sendable (ApplicationInvocationContext) async throws -> Value
  ) async throws -> Value {
    let call = V4ApplicationCall<Value>(gate: executor.gate)
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        let work: V4ApplicationWork?
        do {
          work = try executor.gate.withLock {
            if call.canceled || Task.isCancelled {
              continuation.resume(throwing: ApplicationInvocationFailure.canceled)
              return nil
            }
            call.continuation = continuation
            let work = try V4ApplicationWork(group: self, context: context, preparedPosition: preparedPosition, operation: { invocation in
              // Keep arbitrary application errors local to this invocation.
              // Typed message decode uses its own fixed error projection.
              let result: Result<Value, Error>
              do { result = .success(try await operation(invocation)) }
              catch { result = .failure(error) }
              call.gate.withLock { call.result = result }
            }, onExit: {
              let waiting = call.continuation
              call.continuation = nil
              call.work = nil
              let result = call.result ?? .failure(ApplicationInvocationFailure.closed)
              call.result = nil
              waiting?.resume(with: result)
            })
            call.work = work
            return work
          }
        } catch {
          executor.gate.withLock { call.continuation = nil }
          continuation.resume(throwing: error)
          return
        }
        work?.start()
      }
    } onCancel: {
      call.gate.withLock {
        call.canceled = true
        let pending = call.continuation
        call.continuation = nil
        call.work?.cancel()
        pending?.resume(throwing: ApplicationInvocationFailure.canceled)
      }
    }
  }
}

/// A finite ordinary Ready and job descriptor reservation. It is never marked
/// running until a real callback starts; it stays protected while that callback
/// runs and returns to the same original descriptor only after physical exit.
final class V4OrdinaryReservation: @unchecked Sendable {
  let group: V4ApplicationGroup
  let index: Int
  let token: UUID
  private let reference: V4ResourceReference
  fileprivate init(group: V4ApplicationGroup, index: Int, token: UUID, reference: V4ResourceReference) {
    self.group = group; self.index = index; self.token = token; self.reference = reference
  }
  func check() throws { try reference.check(); try group.check() }
  deinit { group.executor.returnOrdinaryPosition(self); reference.release() }
}
