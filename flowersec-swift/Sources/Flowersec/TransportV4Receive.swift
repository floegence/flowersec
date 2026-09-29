import Foundation

// Native receive components accept only already authenticated Stream data.
// They do not parse records, validate credentials or establish a Session.
// Runtime overhead is a trusted profile input, separate from payload storage;
// these counters do not qualify Foundation, TLS or process RSS on their own.
struct V4ReadBudgetConfiguration: Sendable {
  let sdkBytes: UInt64
  let directions: Int
  let cursors: Int
  let authorizations: Int
  let rootRuntimeBytes: UInt64
  let directionRuntimeBytes: UInt64
  let cursorRuntimeBytes: UInt64
  let authorizationRuntimeBytes: UInt64
}

struct V4ReadBudgetSnapshot: Sendable, Equatable {
  let sdkBytes: UInt64
  let directions: Int
  let cursors: Int
  let authorizations: Int
}

enum V4ReceiveFailure: Error, Equatable {
  case configuration, capacity, closed, credit, sequence, terminal
}

final class V4ReadBudget: @unchecked Sendable {
  fileprivate struct DirectionSlot {
    weak var value: V4ReceiveDirection?
    var bytes: UInt64 = 0
  }
  fileprivate struct CursorSlot {
    weak var value: V4CursorAdmission?
    var bytes: UInt64 = 0
  }
  fileprivate struct AuthorizationSlot {
    weak var value: V4ReadAuthorization?
    var occupied = false
  }

  let gate: NSRecursiveLock
  private var foundation: V4EnvironmentFoundation?
  private var foundationReservation: V4ResourceReference?
  fileprivate let config: V4ReadBudgetConfiguration
  fileprivate var directions: [DirectionSlot]
  fileprivate var cursors: [CursorSlot]
  fileprivate var authorizations: [AuthorizationSlot]
  fileprivate var used: UInt64
  fileprivate var closed = false
  private var closing = false

  init(
    _ config: V4ReadBudgetConfiguration, foundation: V4EnvironmentFoundation? = nil,
    reservation: V4ResourceReference? = nil
  ) throws {
    guard (foundation == nil) == (reservation == nil) else { throw V4ResourceFailure.owner }
    if let foundation, let reservation {
      guard reservation.belongs(to: foundation.account) else { throw V4ResourceFailure.owner }
    }
    self.gate = foundation?.gate ?? NSRecursiveLock()
    self.foundation = foundation
    self.foundationReservation = reservation
    guard config.directions > 0, config.cursors > 0, config.authorizations > 0,
      config.rootRuntimeBytes > 0, config.directionRuntimeBytes > 0,
      config.cursorRuntimeBytes > 0, config.authorizationRuntimeBytes > 0
    else { throw V4ReceiveFailure.configuration }
    var metadata = config.rootRuntimeBytes
    for (count, stride) in [
      (config.directions, MemoryLayout<DirectionSlot>.stride),
      (config.cursors, MemoryLayout<CursorSlot>.stride),
      (config.authorizations, MemoryLayout<AuthorizationSlot>.stride),
    ] {
      let (bytes, overflow) = UInt64(count).multipliedReportingOverflow(by: UInt64(stride))
      let (sum, sumOverflow) = metadata.addingReportingOverflow(bytes)
      guard !overflow, !sumOverflow else { throw V4ReceiveFailure.configuration }
      metadata = sum
    }
    guard metadata <= config.sdkBytes else { throw V4ReceiveFailure.capacity }
    self.config = config
    self.used = metadata
    directions = Array(repeating: DirectionSlot(), count: config.directions)
    cursors = Array(repeating: CursorSlot(), count: config.cursors)
    authorizations = Array(repeating: AuthorizationSlot(), count: config.authorizations)
  }

  deinit { foundationReservation?.release() }

  fileprivate func releaseFoundationIfCleanLocked() {
    guard closed, !closing, foundationReservation != nil,
      directions.allSatisfy({ $0.bytes == 0 }), cursors.allSatisfy({ $0.bytes == 0 }),
      authorizations.allSatisfy({ !$0.occupied })
    else { return }
    directions = []
    cursors = []
    authorizations = []
    used = 0
    foundationReservation?.release()
    foundationReservation = nil
    foundation = nil
  }

  func authorization(verified: V4EnvironmentAuthorization) throws -> V4ReadAuthorization {
    try gate.withLock {
      guard let foundation, verified.foundation === foundation else {
        throw V4ResourceFailure.owner
      }
      return try makeAuthorization(deadline: verified.nativeDeadline(), verified: verified)
    }
  }

  func foundationAuthorizationChanged(_ authorization: V4EnvironmentAuthorization) {
    gate.withLock {
      for index in authorizations.indices {
        if let value = authorizations[index].value, value.foundationAuthorization === authorization
        {
          value.revoke()
        }
      }
    }
  }

  func snapshot() -> V4ReadBudgetSnapshot {
    gate.withLock {
      V4ReadBudgetSnapshot(
        sdkBytes: used,
        directions: directions.reduce(0) { $0 + ($1.bytes == 0 ? 0 : 1) },
        cursors: cursors.reduce(0) { $0 + ($1.bytes == 0 ? 0 : 1) },
        authorizations: authorizations.reduce(0) { $0 + ($1.occupied ? 1 : 0) })
    }
  }

  // Called only by trusted assembly after validating the original complete
  // authorization and converting its nonrenewable bound to a monotonic cap.
  // The object is a compact local disclosure fence, not a credential verifier.
  func authorization(validatedHardDeadline: ContinuousClock.Instant) throws -> V4ReadAuthorization {
    try gate.withLock {
      guard foundation == nil else { throw V4ResourceFailure.owner }
      return try makeAuthorization(deadline: validatedHardDeadline, verified: nil)
    }
  }

  private func makeAuthorization(
    deadline: ContinuousClock.Instant,
    verified: V4EnvironmentAuthorization?
  ) throws -> V4ReadAuthorization {
    try gate.withLock {
      guard !closed else { throw V4ReceiveFailure.closed }
      guard deadline > ContinuousClock.now else {
        throw V4ReceiveFailure.configuration
      }
      guard let slot = authorizations.firstIndex(where: { !$0.occupied }) else {
        throw V4ReceiveFailure.capacity
      }
      try charge(config.authorizationRuntimeBytes)
      let value = V4ReadAuthorization(budget: self, slot: slot, deadline: deadline)
      value.foundationAuthorization = verified
      authorizations[slot] = AuthorizationSlot(value: value, occupied: true)
      return value
    }
  }

  func direction(
    capacity: Int, initialReceiveLimit: UInt64,
    authorization: V4ReadAuthorization
  ) throws -> V4ReceiveDirection {
    try gate.withLock {
      guard !closed else { throw V4ReceiveFailure.closed }
      guard authorization.budget === self, capacity > 0,
        initialReceiveLimit <= UInt64(capacity)
      else { throw V4ReceiveFailure.configuration }
      if let reason = authorization.failureLocked() {
        throw ReadMethodFailure(reason: reason, cursor: nil)
      }
      guard let slot = directions.firstIndex(where: { $0.bytes == 0 }) else {
        throw V4ReceiveFailure.capacity
      }
      let charge = try sum(
        UInt64(capacity), UInt64(min(capacity, 4096)), config.directionRuntimeBytes)
      try self.charge(charge)
      let value = V4ReceiveDirection(
        budget: self, slot: slot, capacity: capacity,
        limit: initialReceiveLimit, authorization: authorization)
      directions[slot] = DirectionSlot(value: value, bytes: charge)
      return value
    }
  }

  fileprivate func admitCursor(
    target: UInt64, authorization: V4ReadAuthorization,
    deadline: ContinuousClock.Instant
  ) throws -> V4CursorAdmission {
    guard !closed else { throw V4ReceiveFailure.closed }
    guard let slot = cursors.firstIndex(where: { $0.bytes == 0 }) else {
      throw V4ReceiveFailure.capacity
    }
    let charge = try sum(target, min(target, 4096), config.cursorRuntimeBytes)
    try self.charge(charge)
    let value = V4CursorAdmission(
      budget: self, slot: slot, authorization: authorization,
      deadline: min(deadline, authorization.hardDeadline))
    cursors[slot] = CursorSlot(value: value, bytes: charge)
    return value
  }

  fileprivate func charge(_ bytes: UInt64) throws {
    try foundationReservation?.check()
    guard bytes <= config.sdkBytes - used else { throw V4ReceiveFailure.capacity }
    used += bytes
  }

  fileprivate func sum(_ values: UInt64...) throws -> UInt64 {
    var result: UInt64 = 0
    for value in values {
      let (next, overflow) = result.addingReportingOverflow(value)
      guard !overflow else { throw V4ReceiveFailure.capacity }
      result = next
    }
    return result
  }

  func close() {
    gate.withLock {
      guard !closed else { return }
      closed = true
      closing = true
      for index in cursors.indices { cursors[index].value?.authorizationChanged(.ownerUnavailable) }
      for index in directions.indices { directions[index].value?.close() }
      closing = false
      releaseFoundationIfCleanLocked()
    }
  }
}

final class V4ReadAuthorization: @unchecked Sendable {
  enum TimeState { case usable, pending, unavailable }
  fileprivate let budget: V4ReadBudget
  private let slot: Int
  let hardDeadline: ContinuousClock.Instant
  private var state = TimeState.usable
  private var revoked = false
  fileprivate var foundationAuthorization: V4EnvironmentAuthorization?

  fileprivate init(budget: V4ReadBudget, slot: Int, deadline: ContinuousClock.Instant) {
    self.budget = budget
    self.slot = slot
    hardDeadline = deadline
  }

  deinit {
    budget.gate.withLock {
      budget.authorizations[slot] = V4ReadBudget.AuthorizationSlot()
      budget.used -= budget.config.authorizationRuntimeBytes
      budget.releaseFoundationIfCleanLocked()
    }
  }

  // Refresh may restore time availability, but cannot extend the original
  // hard deadline or reopen a revoked authorization.
  func setTimeState(_ state: TimeState) {
    budget.gate.withLock {
      guard !revoked else { return }
      self.state = state
      notifyLocked()
    }
  }

  func revoke() {
    budget.gate.withLock {
      guard !revoked else { return }
      revoked = true
      notifyLocked()
    }
  }

  fileprivate func failureLocked() -> ReadMethodFailure.Reason? {
    if budget.closed { return .ownerUnavailable }
    if revoked || ContinuousClock.now >= hardDeadline { return .authorizationDenied }
    if let foundationAuthorization {
      do { try foundationAuthorization.check() } catch V4TimeFailure.pending {
        return .timePending
      } catch V4TimeFailure.unavailable { return .timeUnavailable } catch V4ResourceFailure.closed {
        return .ownerUnavailable
      } catch { return .authorizationDenied }
    }
    switch state {
    case .usable: return nil
    case .pending: return .timePending
    case .unavailable: return .timeUnavailable
    }
  }

  private func notifyLocked() {
    if let failure = failureLocked() {
      for index in budget.cursors.indices {
        if let value = budget.cursors[index].value, value.authorization === self {
          value.authorizationChanged(failure)
        }
      }
    }
    for index in budget.directions.indices {
      if let value = budget.directions[index].value, value.authorization === self {
        value.authorizationChangedLocked()
      }
    }
  }
}

// A detached candidate retains only this compact authorization, its byte
// reservation and timer. The budget has weak slots and retains no I/O graph.
final class V4CursorAdmission: @unchecked Sendable {
  private final class CleanupWaiter: @unchecked Sendable {
    var canceled = false
    var continuation: CheckedContinuation<Void, Error>?
  }
  fileprivate let budget: V4ReadBudget
  fileprivate let authorization: V4ReadAuthorization
  private let slot: Int
  private let deadline: ContinuousClock.Instant
  private weak var cursor: ReaderCursor?
  private var timer: Task<Void, Never>?
  private var timerPending = false
  private var sourcePending = true
  private var payloadPending = true
  private var inputComplete = false
  private var workers = 0
  private var released = false
  private var cleanupWaiter: CleanupWaiter?

  fileprivate init(
    budget: V4ReadBudget, slot: Int, authorization: V4ReadAuthorization,
    deadline: ContinuousClock.Instant
  ) {
    self.budget = budget
    self.slot = slot
    self.authorization = authorization
    self.deadline = deadline
  }

  func attach(_ cursor: ReaderCursor) throws {
    try budget.gate.withLock {
      if let reason = failure() { throw ReadMethodFailure(reason: reason, cursor: nil) }
      self.cursor = cursor
      timerPending = true
      timer = Task { [self] in
        do {
          try await ContinuousClock().sleep(until: deadline)
          // A completed private candidate no longer has an assembly deadline.
          // Keep the original authorization timer and its charge until handoff.
          let safetyDeadline = budget.gate.withLock {
            inputComplete ? authorization.hardDeadline : deadline
          }
          if safetyDeadline > ContinuousClock.now {
            try await ContinuousClock().sleep(until: safetyDeadline)
          }
          authorizationChanged(.authorizationDenied)
        } catch is CancellationError {
          // Cancellation ends this timer only; the original resource gate
          // still waits for the read worker and private payload to exit.
        } catch {
          authorizationChanged(.timeUnavailable)
        }
        budget.gate.withLock {
          timerPending = false
          timer = nil
          releaseIfFinishedLocked()
        }
      }
    }
  }

  func failure() -> ReadMethodFailure.Reason? {
    budget.gate.withLock {
      if !inputComplete && ContinuousClock.now >= deadline { return .authorizationDenied }
      return authorization.failureLocked()
    }
  }

  func authorizationChanged(_ reason: ReadMethodFailure.Reason) {
    budget.gate.withLock { cursor?.authorizationChanged(reason) }
  }

  func inputCompleted() { budget.gate.withLock { inputComplete = true } }

  func advancementStarted() { budget.gate.withLock { workers += 1 } }
  func advancementFinished() {
    budget.gate.withLock {
      workers -= 1
      releaseIfFinishedLocked()
    }
  }
  func sourceReleased() {
    budget.gate.withLock {
      sourcePending = false
      releaseIfFinishedLocked()
    }
  }
  func payloadReleased() {
    budget.gate.withLock {
      payloadPending = false
      timer?.cancel()
      releaseIfFinishedLocked()
    }
  }
  func waitCleanup() async throws {
    let token = CleanupWaiter()
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        budget.gate.withLock {
          token.continuation = continuation
          if released {
            continuation.resume()
            return
          }
          if token.canceled {
            continuation.resume(throwing: CancellationError())
            return
          }
          guard cleanupWaiter == nil else {
            continuation.resume(throwing: V4ReceiveFailure.capacity)
            return
          }
          cleanupWaiter = token
        }
      }
    } onCancel: {
      self.budget.gate.withLock {
        token.canceled = true
        if self.cleanupWaiter === token {
          self.cleanupWaiter = nil
          token.continuation?.resume(throwing: CancellationError())
        }
      }
    }
  }

  private func releaseIfFinishedLocked() {
    guard !released, !sourcePending, !payloadPending, !timerPending, workers == 0 else { return }
    released = true
    budget.used -= budget.cursors[slot].bytes
    budget.cursors[slot] = V4ReadBudget.CursorSlot()
    budget.releaseFoundationIfCleanLocked()
    cursor = nil
    let waiter = cleanupWaiter
    cleanupWaiter = nil
    waiter?.continuation?.resume()
  }
}

struct V4ReceiveSnapshot: Sendable, Equatable {
  let acknowledgedOffset: UInt64
  let releasedOffset: UInt64
  let receiveLimit: UInt64
  let queuedBytes: Int
  let cursorClaimed: Bool
  let readPending: Bool
  let closed: Bool
}

final class V4ReceiveDirection: @unchecked Sendable {
  fileprivate let budget: V4ReadBudget
  fileprivate let authorization: V4ReadAuthorization
  private let slot: Int
  private var ring: [UInt8]
  private var head = 0
  private var count = 0
  private var acknowledged: UInt64 = 0
  private var released: UInt64 = 0
  private var limit: UInt64
  private var terminal = ReadStreamStatus.open
  private var terminalError: ReadStreamError?
  private var closed = false
  private var cleaned = false
  private var claimed = false
  private weak var source: V4NativeCursorSource?

  fileprivate init(
    budget: V4ReadBudget, slot: Int, capacity: Int, limit: UInt64,
    authorization: V4ReadAuthorization
  ) {
    self.budget = budget
    self.slot = slot
    self.authorization = authorization
    ring = Array(repeating: 0, count: capacity)
    self.limit = limit
  }

  deinit {
    budget.gate.withLock {
      if !cleaned {
        budget.used -= budget.directions[slot].bytes
        budget.directions[slot] = V4ReadBudget.DirectionSlot()
        budget.releaseFoundationIfCleanLocked()
      }
    }
  }

  func snapshot() -> V4ReceiveSnapshot {
    budget.gate.withLock {
      V4ReceiveSnapshot(
        acknowledgedOffset: acknowledged, releasedOffset: released,
        receiveLimit: limit, queuedBytes: count, cursorClaimed: claimed,
        readPending: source?.hasPendingRead ?? false, closed: closed)
    }
  }

  func cursor(
    options: ReaderCursorOptions, capacity: UInt64,
    deadline: ContinuousClock.Instant
  ) throws -> ReaderCursor {
    try budget.gate.withLock {
      guard !closed else { throw V4ReceiveFailure.closed }
      guard !claimed else { throw ReadMethodFailure(reason: .readInProgress, cursor: nil) }
      if let failure = authorization.failureLocked() {
        throw ReadMethodFailure(reason: failure, cursor: nil)
      }
      let target = try ReaderCursor.checkedTarget(
        options: options, capacity: capacity, start: released)
      guard deadline > ContinuousClock.now else {
        throw ReadMethodFailure(reason: .authorizationDenied, cursor: nil)
      }
      let admission = try budget.admitCursor(
        target: target, authorization: authorization, deadline: deadline)
      let source = V4NativeCursorSource(
        direction: self, start: released,
        status: visibleStatusLocked(), error: terminalError, admission: admission,
        delimiter: options.delimiter)
      claimed = true
      self.source = source
      do {
        return try ReaderCursor(source: source, options: options, capacity: capacity)
      } catch {
        source.release()
        admission.payloadReleased()
        throw error
      }
    }
  }

  // Synchronous raw consumption and cursor admission share this one gate.
  // A blocked result leaves the original queue untouched and owns no waiter.
  func tryRead(maxBytes: Int) throws -> ReadResult {
    try budget.gate.withLock {
      guard maxBytes > 0 else { throw ReadMethodFailure(reason: .invalidArgument, cursor: nil) }
      guard !closed else { throw ReadMethodFailure(reason: .ownerUnavailable, cursor: nil) }
      guard !claimed else { throw ReadMethodFailure(reason: .readInProgress, cursor: nil) }
      if let failure = authorization.failureLocked() {
        throw ReadMethodFailure(reason: failure, cursor: nil)
      }
      guard count > 0 || terminal != .open else {
        return ReadResult(
          data: Data(), progress: ReadProgress(offset: released, filled: 0, target: nil),
          waitStatus: .blocked, streamStatus: .open, cause: nil, error: nil)
      }
      var chunk: CursorReadChunk?
      var matcher: V4DelimiterMatcher?
      transferLocked(maxBytes: min(maxBytes, 4096), matcher: &matcher) { chunk = $0 }
      let value = chunk!
      return ReadResult(
        data: value.data,
        progress: ReadProgress(offset: released, filled: UInt64(value.data.count), target: nil),
        waitStatus: .ready, streamStatus: value.status, cause: nil, error: value.error)
    }
  }

  // The record/Stream owner must authenticate and attribute this input before
  // invoking this internal entry. All checks precede mutation or publication.
  func receiveAuthenticated(offset: UInt64, data: Data, eof: Bool = false) throws {
    try budget.gate.withLock {
      guard !closed else { throw V4ReceiveFailure.closed }
      if let failure = authorization.failureLocked(),
        failure == .authorizationDenied || failure == .ownerUnavailable
      {
        throw ReadMethodFailure(reason: failure, cursor: nil)
      }
      guard terminal == .open, !data.isEmpty || eof else { throw V4ReceiveFailure.terminal }
      guard offset == acknowledged else { throw V4ReceiveFailure.sequence }
      let (end, overflow) = offset.addingReportingOverflow(UInt64(data.count))
      guard !overflow, end <= limit, data.count <= ring.count - count else {
        throw V4ReceiveFailure.credit
      }
      for byte in data {
        ring[(head + count) % ring.count] = byte
        count += 1
      }
      acknowledged = end
      if eof { terminal = .eof }
      source?.satisfyLocked()
    }
  }

  // Expanding the absolute limit reserves only existing fixed ring capacity.
  // No read or cursor automatically emits credit or enlarges this reservation.
  func grant(_ newLimit: UInt64) throws {
    try budget.gate.withLock {
      guard !closed, terminal == .open else { throw V4ReceiveFailure.closed }
      if newLimit > limit, let failure = authorization.failureLocked() {
        throw ReadMethodFailure(reason: failure, cursor: nil)
      }
      guard newLimit >= limit, newLimit >= released,
        newLimit - released <= UInt64(ring.count)
      else { throw V4ReceiveFailure.credit }
      limit = newLimit
    }
  }

  func abort(error: ReadStreamError? = nil) {
    budget.gate.withLock {
      guard !closed, terminal == .open || (terminal == .eof && count > 0) else { return }
      count = 0
      terminal = error == nil ? .aborted : .error
      terminalError = error
      source?.satisfyLocked()
    }
  }

  func close() {
    budget.gate.withLock {
      guard !closed else { return }
      closed = true
      count = 0
      source?.admission?.authorizationChanged(.ownerUnavailable)
      cleanupLocked()
    }
  }

  fileprivate func visibleStatusLocked() -> ReadStreamStatus { count == 0 ? terminal : .open }

  fileprivate func transferLocked(
    maxBytes: Int, matcher: inout V4DelimiterMatcher?,
    transfer: (CursorReadChunk) -> Void
  ) {
    var amount = min(maxBytes, count)
    if matcher != nil {
      for index in 0..<amount {
        if matcher?.consume(ring[(head + index) % ring.count]) == true {
          amount = index + 1
          break
        }
      }
    }
    var data = Data(count: amount)
    data.withUnsafeMutableBytes { (output: UnsafeMutableRawBufferPointer) in
      for index in 0..<amount { output[index] = ring[(head + index) % ring.count] }
    }
    head = (head + amount) % ring.count
    count -= amount
    released += UInt64(amount)
    // The native queue frontier and the cursor's filled/offset become visible
    // together. The callback only copies into the original private backing.
    transfer(CursorReadChunk(data: data, status: visibleStatusLocked(), error: terminalError))
  }

  fileprivate func releaseCursorLocked(_ original: V4NativeCursorSource) {
    guard source === original else { return }
    source = nil
    claimed = false
    cleanupLocked()
  }

  fileprivate func authorizationChangedLocked() { source?.satisfyLocked() }

  private func cleanupLocked() {
    guard closed, !claimed, !cleaned else { return }
    cleaned = true
    ring = []
    budget.used -= budget.directions[slot].bytes
    budget.directions[slot] = V4ReadBudget.DirectionSlot()
    budget.releaseFoundationIfCleanLocked()
  }

  fileprivate var currentErrorLocked: ReadStreamError? { terminalError }

  fileprivate var readyLocked: Bool { count > 0 || terminal != .open }
}

private struct V4DelimiterMatcher {
  private let delimiter: [UInt8]
  private let prefix: [Int]
  private var matched = 0

  init(_ bytes: Data) {
    delimiter = Array(bytes)
    var prefix = Array(repeating: 0, count: bytes.count)
    var matched = 0
    for index in 1..<bytes.count {
      while matched > 0 && delimiter[index] != delimiter[matched] { matched = prefix[matched - 1] }
      if delimiter[index] == delimiter[matched] { matched += 1 }
      prefix[index] = matched
    }
    self.prefix = prefix
  }

  mutating func consume(_ byte: UInt8) -> Bool {
    while matched > 0 && byte != delimiter[matched] { matched = prefix[matched - 1] }
    if byte == delimiter[matched] { matched += 1 }
    return matched == delimiter.count
  }
}

private final class V4NativeCursorSource: ReaderCursorSource, @unchecked Sendable {
  private struct Pending {
    let maximum: Int
    let transfer: @Sendable (CursorReadChunk) -> Void
    let continuation: CheckedContinuation<Void, Never>
  }
  let cursorGate: NSRecursiveLock
  let admission: V4CursorAdmission?
  let startOffset: UInt64
  let initialStatus: ReadStreamStatus
  let initialError: ReadStreamError?
  let delimiterPieceBytes = 4096
  private var direction: V4ReceiveDirection?
  private var pending: Pending?
  private var stopped = false
  private var matcher: V4DelimiterMatcher?
  fileprivate var hasPendingRead: Bool { pending != nil }

  init(
    direction: V4ReceiveDirection, start: UInt64, status: ReadStreamStatus,
    error: ReadStreamError?, admission: V4CursorAdmission, delimiter: Data?
  ) {
    self.direction = direction
    cursorGate = direction.budget.gate
    self.admission = admission
    startOffset = start
    initialStatus = status
    initialError = status == .error ? error : nil
    matcher = delimiter.map(V4DelimiterMatcher.init)
  }

  func currentState() -> (ReadStreamStatus, ReadStreamError?) {
    cursorGate.withLock {
      guard let direction else { return (initialStatus, initialError) }
      return (direction.visibleStatusLocked(), direction.currentErrorLocked)
    }
  }

  func read(maxBytes: Int, transfer: @escaping @Sendable (CursorReadChunk) -> Void) async {
    await withCheckedContinuation { continuation in
      cursorGate.withLock {
        precondition(pending == nil)
        pending = Pending(maximum: maxBytes, transfer: transfer, continuation: continuation)
        satisfyLocked()
      }
    }
  }

  fileprivate func satisfyLocked() {
    guard let read = pending else { return }
    if stopped || direction == nil {
      pending = nil
      read.transfer(CursorReadChunk(data: Data(), status: .open, error: nil))
      read.continuation.resume()
      return
    }
    guard let direction else { return }
    if let failure = admission?.failure() {
      if failure == .authorizationDenied || failure == .ownerUnavailable {
        admission?.authorizationChanged(failure)
      }
      return
    }
    guard direction.readyLocked else { return }
    pending = nil
    direction.transferLocked(maxBytes: read.maximum, matcher: &matcher, transfer: read.transfer)
    read.continuation.resume()
  }

  func stopRead() {
    cursorGate.withLock {
      stopped = true
      satisfyLocked()
    }
  }

  func release() {
    cursorGate.withLock {
      guard let direction else { return }
      precondition(pending == nil)
      direction.releaseCursorLocked(self)
      self.direction = nil
      admission?.sourceReleased()
    }
  }
}
