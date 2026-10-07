import Foundation
import XCTest

@testable import Flowersec

@MainActor
final class TransportEnvironmentTests: XCTestCase {
  private let identity = V4ResourceIdentity(high: 1, low: 1)
  private let profile = V4TimeProfile(
    rateNumerator: 0, rateDenominator: 1,
    quantizationMS: 0, maximumWidthMS: 100, maximumAnchorAgeMS: 1000)

  private func limit(bytes: UInt64 = 1 << 20) -> V4ResourceVector {
    V4ResourceVector(
      sdkBytes: bytes, providerBytes: bytes, diskBytes: bytes,
      items: 128, work: 128, tasks: 128, timers: 128, connections: 32,
      handshakes: 32, sessions: 32, handles: 128)
  }

  private func root(references: Int = 32) throws -> V4ResourceRoot {
    try V4ResourceRoot(
      V4ResourceRootConfiguration(
        limit: limit(), accounts: 16,
        reservations: 16, references: references, cleanupWaiters: 4, runtimeOverheadBytes: 1024))
  }

  private func owner(
    _ number: UInt64, backing: UInt64? = nil,
    environment: V4ResourceIdentity? = nil
  ) -> V4ResourceOwnerKey {
    V4ResourceOwnerKey(
      environment: environment ?? identity,
      instance: V4ResourceIdentity(high: 2, low: number),
      backing: V4ResourceIdentity(high: 3, low: backing ?? number), kind: 2, direction: 0)
  }

  private func accounts(_ root: V4ResourceRoot, bytes: UInt64 = 1024) throws
    -> (V4ResourceAccount, V4ResourceAccount, V4ResourceAccount)
  {
    let tenant = try root.account(
      kind: .tenant, identity: V4ResourceIdentity(high: 9, low: 9), limit: limit(bytes: bytes))
    let environment = try tenant.child(
      kind: .environment, identity: identity, limit: limit(bytes: bytes))
    let session = try environment.child(
      kind: .session, identity: V4ResourceIdentity(high: 5, low: 5), limit: limit(bytes: bytes))
    return (tenant, environment, session)
  }

  private func foundation(
    root: V4ResourceRoot, source: FoundationTickSource,
    id: V4ResourceIdentity? = nil, cleanup: Duration = .milliseconds(40)
  ) throws -> V4EnvironmentFoundation {
    let tenant = try root.account(
      kind: .tenant, identity: V4ResourceIdentity(high: 9, low: 9), limit: limit())
    return try V4EnvironmentFoundation(
      root: root, tenant: tenant,
      configuration: V4EnvironmentConfiguration(
        identity: id ?? identity, limit: limit(),
        maximumReadBudgets: 2, maximumWork: 2, runtimeOverheadBytes: 512,
        cleanupTimeout: cleanup, verificationContinuity: .onlineBootstrap),
      timeProfile: profile, monotonicSource: source)
  }

  private func install(_ clock: V4TrustedClock, lower: UInt64 = 1000, upper: UInt64 = 1010) throws {
    try clock.installTrusted(
      at: clock.mark(), interval: V4TimeInterval(lowerMS: lower, upperMS: upper))
  }

  private func eventually(
    _ predicate: () -> Bool, file: StaticString = #filePath, line: UInt = #line
  ) async {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !predicate() && ContinuousClock.now < deadline { await Task.yield() }
    XCTAssertTrue(predicate(), file: file, line: line)
  }

  func testHierarchicalAdmissionIsAtomicAndSharesTenantAcrossEnvironments() throws {
    let root = try root()
    let (tenant, first, session) = try accounts(root, bytes: 100)
    let secondID = V4ResourceIdentity(high: 1, low: 2)
    let second = try tenant.child(kind: .environment, identity: secondID, limit: limit(bytes: 100))
    let original = root.snapshot()
    let charge = try session.reserve(
      owner: owner(1), value: V4ResourceVector(sdkBytes: 60, work: 1))
    let charged = root.snapshot()
    XCTAssertEqual(try tenant.snapshot().used.sdkBytes, 60)
    XCTAssertEqual(try first.snapshot().used.sdkBytes, 60)
    XCTAssertThrowsError(
      try second.reserve(
        owner: owner(2, environment: secondID),
        value: V4ResourceVector(sdkBytes: 50))
    ) { error in
      XCTAssertEqual(error as? V4ResourceFailure, .capacity)
    }
    XCTAssertEqual(root.snapshot(), charged)
    XCTAssertEqual(try second.snapshot().used.sdkBytes, 0)
    charge.release()
    XCTAssertEqual(root.snapshot(), original)
  }

  func testBorrowAndTransferKeepOldScopeChargedUntilActualTailExit() throws {
    let root = try root()
    let (_, environment, session) = try accounts(root)
    let result = try environment.child(
      kind: .result, identity: V4ResourceIdentity(high: 6, low: 6), limit: limit(bytes: 1024))
    let original = try session.reserve(
      owner: owner(1), value: V4ResourceVector(sdkBytes: 64, tasks: 1))
    let tail = try original.borrow(executionTail: true)
    let transferred = try original.transfer(to: result, owner: owner(2, backing: 1))
    XCTAssertThrowsError(try original.check())
    original.release()
    XCTAssertEqual(try session.snapshot().used.sdkBytes, 64)
    XCTAssertEqual(try result.snapshot().used.sdkBytes, 64)
    XCTAssertEqual(try environment.snapshot().used.sdkBytes, 64)
    XCTAssertEqual(root.snapshot().reservations, 1)
    session.close()
    XCTAssertFalse(session.cleanupStatus().complete)
    XCTAssertEqual(session.cleanupStatus().pendingCallbacks, 1)
    tail.release()
    XCTAssertTrue(session.cleanupStatus().complete)
    XCTAssertEqual(try result.snapshot().used.sdkBytes, 64)
    transferred.release()
    XCTAssertEqual(try environment.snapshot().used.sdkBytes, 0)
    XCTAssertEqual(root.snapshot().references, 0)
  }

  func testFailedTransferAndReferenceExhaustionNeverPartiallyCharge() throws {
    let root = try root(references: 16)
    let (_, environment, session) = try accounts(root)
    let small = try environment.child(
      kind: .result, identity: V4ResourceIdentity(high: 7, low: 7), limit: limit(bytes: 1))
    let original = try session.reserve(owner: owner(1), value: V4ResourceVector(sdkBytes: 32))
    let before = root.snapshot()
    XCTAssertThrowsError(try original.transfer(to: small, owner: owner(2, backing: 1)))
    XCTAssertEqual(root.snapshot(), before)
    try original.check()
    var borrows: [Flowersec.V4ResourceReference] = []
    for _ in 0..<15 { borrows.append(try original.borrow()) }
    let full = root.snapshot()
    XCTAssertThrowsError(try original.borrow())
    XCTAssertEqual(root.snapshot(), full)
    for borrow in borrows { borrow.release() }
    original.release()
    XCTAssertEqual(root.snapshot().references, 0)
  }

  func testForeignRootAndStaleReleaseCannotMutateNewOwner() throws {
    let first = try root()
    let second = try root()
    let (_, _, session) = try accounts(first)
    let (_, _, foreign) = try accounts(second)
    let original = try session.reserve(owner: owner(1), value: V4ResourceVector(sdkBytes: 8))
    let before = second.snapshot()
    XCTAssertThrowsError(try original.transfer(to: foreign, owner: owner(2, backing: 1)))
    XCTAssertEqual(second.snapshot(), before)
    original.release()
    let next = try session.reserve(owner: owner(2), value: V4ResourceVector(sdkBytes: 9))
    original.release()
    XCTAssertEqual(try session.snapshot().used.sdkBytes, 9)
    try next.check()
    next.release()
  }

  func testCloseReportsIncompleteWithoutRefundingNoncooperativeTask() async throws {
    let root = try root()
    let source = FoundationTickSource()
    let environment = try foundation(root: root, source: source)
    let blocker = FoundationWorkBlocker()
    let work = try environment.startWork(charge: V4ResourceVector(sdkBytes: 256, work: 1, tasks: 1))
    {
      await blocker.run()
    }
    await blocker.waitStarted()
    environment.beginClose()
    let before = root.snapshot()
    XCTAssertEqual(before.executionTails, 1)
    let status = try await environment.waitCleanup()
    XCTAssertTrue(status.cleanupIncomplete)
    XCTAssertFalse(status.complete)
    XCTAssertEqual(status.pendingCallbacks, 1)
    XCTAssertEqual(root.snapshot().used, before.used)
    XCTAssertThrowsError(
      try environment.startWork(charge: V4ResourceVector(sdkBytes: 1, work: 1, tasks: 1)) {})
    await blocker.finish()
    await eventually { work.isFinished }
    XCTAssertTrue(environment.cleanupStatus().complete)
    XCTAssertEqual(root.snapshot().references, 0)
  }

  func testCancelingCleanupWaitDoesNotCancelOrReleaseOriginalTask() async throws {
    let root = try root()
    let environment = try foundation(
      root: root, source: FoundationTickSource(), cleanup: .seconds(2))
    let blocker = FoundationWorkBlocker()
    let work = try environment.startWork(charge: V4ResourceVector(sdkBytes: 256, work: 1, tasks: 1))
    {
      await blocker.run()
    }
    await blocker.waitStarted()
    environment.beginClose()
    let waiter = Task { try await environment.waitCleanup() }
    waiter.cancel()
    do {
      _ = try await waiter.value
      XCTFail("Wait cancellation must detach this observer")
    } catch is CancellationError {}
    XCTAssertEqual(root.snapshot().executionTails, 1)
    XCTAssertFalse(work.isFinished)
    await blocker.finish()
    await eventually { work.isFinished }
    XCTAssertTrue(environment.cleanupStatus().complete)
  }

  func testClosingOneEnvironmentPreservesBorrowedRootAndSibling() async throws {
    let root = try root()
    let first = try foundation(root: root, source: FoundationTickSource())
    let second = try foundation(
      root: root, source: FoundationTickSource(), id: V4ResourceIdentity(high: 1, low: 2))
    try await first.close()
    XCTAssertFalse(root.snapshot().closed)
    let work = try second.startWork(charge: V4ResourceVector(sdkBytes: 64, work: 1, tasks: 1)) {}
    await eventually { work.isFinished }
    try await second.close()
    XCTAssertTrue(first.cleanupStatus().complete)
    XCTAssertTrue(second.cleanupStatus().complete)
  }

  func testDuplicateEnvironmentIdentityDoesNotCloseExistingOwner() throws {
    let root = try root()
    let environment = try foundation(root: root, source: FoundationTickSource())
    defer { environment.beginClose() }
    XCTAssertThrowsError(try foundation(root: root, source: FoundationTickSource()))
    try environment.account.check()
  }

  func testTrustedIntervalPreservesOriginalAnchorAgeAndRejectsContradiction() throws {
    let source = FoundationTickSource()
    let clock = try V4TrustedClock(profile: profile, source: source, gate: NSRecursiveLock())
    let original = try clock.mark()
    try clock.installTrusted(at: original, interval: V4TimeInterval(lowerMS: 1000, upperMS: 1010))
    source.advance(500)
    XCTAssertEqual(clock.sample().interval, V4TimeInterval(lowerMS: 1500, upperMS: 1510))
    try clock.installTrusted(at: original, interval: V4TimeInterval(lowerMS: 1000, upperMS: 1010))
    source.advance(501)
    XCTAssertEqual(clock.sample().failure, .unavailable)
    XCTAssertThrowsError(
      try clock.installTrusted(at: original, interval: V4TimeInterval(lowerMS: 1000, upperMS: 1010))
    )
    try install(clock, lower: 3000, upper: 3010)
    XCTAssertThrowsError(try install(clock, lower: 4000, upper: 4010)) { error in
      XCTAssertEqual(error as? V4TimeFailure, .contradiction)
    }
    XCTAssertNil(clock.sample().interval)
  }

  func testClockRefinementCannotExtendOriginalMonotonicDeadline() throws {
    let source = FoundationTickSource()
    let clock = try V4TrustedClock(profile: profile, source: source, gate: NSRecursiveLock())
    try install(clock, lower: 900, upper: 1000)
    let deadline = try V4SecurityDeadline(clock: clock, capMS: 1100)
    XCTAssertEqual(try deadline.remainingTicks(), 100)
    source.advance(40)
    try install(clock, lower: 950, upper: 960)
    XCTAssertEqual(try deadline.remainingTicks(), 60)
    source.advance(60)
    XCTAssertThrowsError(try deadline.check()) { error in
      XCTAssertEqual(error as? V4TimeFailure, .expired)
    }
    try install(clock, lower: 1010, upper: 1020)
    XCTAssertThrowsError(try deadline.check())
  }

  func testTighteningPreservesOriginalDeadlineAfterClockRefinement() throws {
    for cap: UInt64 in [1100, 1090, 1200] {
      let source = FoundationTickSource()
      let clock = try V4TrustedClock(profile: profile, source: source, gate: NSRecursiveLock())
      try install(clock, lower: 900, upper: 1000)
      let deadline = try V4SecurityDeadline(clock: clock, capMS: 1100)
      source.advance(40)
      try install(clock, lower: 950, upper: 960)
      try deadline.tighten(to: cap)
      XCTAssertEqual(deadline.capMS, min(cap, 1100))
      XCTAssertEqual(try deadline.remainingTicks(), 60)
      source.advance(60)
      // The refined upper bound is still below each cap. The original
      // monotonic end must nevertheless reject further authorization.
      XCTAssertThrowsError(try deadline.tighten(to: cap)) { error in
        XCTAssertEqual(error as? V4TimeFailure, .expired)
      }
      XCTAssertThrowsError(try deadline.check())
    }
  }

  func testTighteningCanShortenButCannotReviveDeadline() throws {
    let source = FoundationTickSource()
    let clock = try V4TrustedClock(profile: profile, source: source, gate: NSRecursiveLock())
    try install(clock, lower: 900, upper: 1000)
    let deadline = try V4SecurityDeadline(clock: clock, capMS: 1100)
    try deadline.tighten(to: 1050)
    XCTAssertEqual(try deadline.remainingTicks(), 50)
    source.advance(50)
    XCTAssertThrowsError(try deadline.tighten(to: 1200)) { error in
      XCTAssertEqual(error as? V4TimeFailure, .expired)
    }
    XCTAssertEqual(deadline.capMS, 1050)
  }

  func testContinuityFailureCannotBeHiddenByReturningOldIncarnation() throws {
    let source = FoundationTickSource()
    let clock = try V4TrustedClock(profile: profile, source: source, gate: NSRecursiveLock())
    try install(clock)
    let deadline = try V4SecurityDeadline(clock: clock, capMS: 2000)
    let window = try V4LocalWorkWindow(clock: clock, durationMS: 500)
    source.fail()
    XCTAssertThrowsError(try deadline.check()) { error in
      XCTAssertEqual(error as? V4TimeFailure, .continuity)
    }
    XCTAssertThrowsError(try window.check())
    source.restore()
    try install(clock)
    XCTAssertThrowsError(try deadline.check())
    XCTAssertThrowsError(try window.check())
    let replacement = try V4SecurityDeadline(clock: clock, capMS: 2000)
    try replacement.check()
  }

  func testTimeArithmeticRoundsOutwardAndRejectsOverflow() throws {
    let bounded = V4TimeProfile(
      rateNumerator: 1, rateDenominator: 10,
      quantizationMS: 1, maximumWidthMS: 100, maximumAnchorAgeMS: 1000)
    try bounded.validate()
    XCTAssertEqual(try bounded.elapsed(10), V4TimeInterval(lowerMS: 8, upperMS: 13))
    let deadline = try bounded.deadlineDelta(upper: 100, deadline: 200)
    XCTAssertLessThanOrEqual(try bounded.elapsed(deadline).upperMS, 100)
    let wait = try bounded.proveDelta(lower: 100, bound: 200)
    XCTAssertGreaterThanOrEqual(try bounded.elapsed(wait).lowerMS, 100)
    XCTAssertThrowsError(try bounded.elapsed(.max))
    XCTAssertThrowsError(
      try bounded.advance(V4TimeInterval(lowerMS: .max - 1, upperMS: .max), delta: 10))
    XCTAssertThrowsError(try bounded.deadlineDelta(upper: 200, deadline: 200))
  }

  func testAuthorizationRequiresLowerBoundAndStrictUpperBound() throws {
    let root = try root()
    let source = FoundationTickSource()
    let environment = try foundation(root: root, source: source)
    defer { environment.beginClose() }
    try install(environment.clock)
    let initial = root.snapshot()
    XCTAssertThrowsError(
      try environment.authorization(
        bounds: V4EnvironmentAuthorizationBounds(
          notBeforeMS: 1005, issuedAtMS: 1000, notAfterMS: 2000, freshnessNotAfterMS: 1900),
        runtimeBytes: 128)
    ) { error in
      XCTAssertEqual(error as? V4TimeFailure, .pending)
    }
    XCTAssertEqual(root.snapshot(), initial)
    let authorization = try environment.authorization(
      bounds: V4EnvironmentAuthorizationBounds(
        notBeforeMS: 1000, issuedAtMS: 1000, notAfterMS: 2000, freshnessNotAfterMS: 1900),
      runtimeBytes: 128)
    try authorization.check()
    source.advance(890)
    XCTAssertThrowsError(try authorization.check()) { error in
      XCTAssertEqual(error as? V4TimeFailure, .expired)
    }
  }

  func testEnvironmentReadBudgetUsesSharedReservationAndRevocationGate() async throws {
    let root = try root()
    let environment = try foundation(root: root, source: FoundationTickSource())
    try install(environment.clock)
    var authorization: V4EnvironmentAuthorization? = try environment.authorization(
      bounds: V4EnvironmentAuthorizationBounds(
        notBeforeMS: 1000, issuedAtMS: 1000, notAfterMS: 5000, freshnessNotAfterMS: 5000),
      runtimeBytes: 128)
    let config = V4ReadBudgetConfiguration(
      sdkBytes: 8192, directions: 2, cursors: 2, authorizations: 2,
      rootRuntimeBytes: 256, directionRuntimeBytes: 256, cursorRuntimeBytes: 512,
      authorizationRuntimeBytes: 128)
    let before = root.snapshot().used.sdkBytes
    let budget = try environment.readBudget(config)
    XCTAssertEqual(root.snapshot().used.sdkBytes, before + config.sdkBytes)
    XCTAssertThrowsError(
      try budget.authorization(validatedHardDeadline: .now.advanced(by: .seconds(5))))
    var readAuthorization: V4ReadAuthorization? = try budget.authorization(verified: authorization!)
    var direction: V4ReceiveDirection? = try budget.direction(
      capacity: 8, initialReceiveLimit: 8,
      authorization: readAuthorization!)
    var cursor: ReaderCursor? = try direction!.cursor(
      options: ReaderCursorOptions(exact: 4), capacity: 4,
      deadline: .now.advanced(by: .seconds(1)))
    let reading = Task { [original = cursor!] in try await original.readExactly() }
    await eventually { direction!.snapshot().readPending }
    authorization!.revoke()
    do {
      _ = try await reading.value
      XCTFail("The original TransportEnvironment gate must fence cursor delivery")
    } catch let failure as ReadMethodFailure {
      XCTAssertEqual(failure.reason, .authorizationDenied)
    }
    try await cursor?.admission?.waitCleanup()
    environment.beginClose()
    XCTAssertFalse(environment.cleanupStatus().complete)
    cursor = nil
    direction = nil
    readAuthorization = nil
    authorization = nil
    await eventually { environment.cleanupStatus().complete }
    XCTAssertEqual(root.snapshot().references, 0)
  }
}

private final class FoundationTickSource: V4MonotonicSource, @unchecked Sendable {
  private let lock = NSLock()
  private var tick: UInt64 = 0
  private var failed = false
  func read() throws -> V4MonotonicTick {
    try lock.withLock {
      if failed { throw V4TimeFailure.unavailable }
      return V4MonotonicTick(milliseconds: tick, incarnation: 1)
    }
  }
  func advance(_ amount: UInt64) { lock.withLock { tick += amount } }
  func fail() { lock.withLock { failed = true } }
  func restore() { lock.withLock { failed = false } }
}

private actor FoundationWorkBlocker {
  private var running = false
  private var startWaiter: CheckedContinuation<Void, Never>?
  private var finishWaiter: CheckedContinuation<Void, Never>?
  func run() async {
    running = true
    startWaiter?.resume()
    startWaiter = nil
    await withCheckedContinuation { finishWaiter = $0 }
  }
  func waitStarted() async {
    if running { return }
    await withCheckedContinuation { startWaiter = $0 }
  }
  func finish() {
    finishWaiter?.resume()
    finishWaiter = nil
  }
}
