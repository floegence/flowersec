#if os(macOS) || os(iOS)
import Foundation
import XCTest

@testable import Flowersec

@MainActor
final class TransportCleanupJoinTests: XCTestCase {
  private let pending = CleanupStatus(complete: false, cleanupIncomplete: false, pendingCallbacks: 1)
  private let completed = CleanupStatus(complete: true, cleanupIncomplete: false, pendingCallbacks: 0)

  private func eventually(_ condition: () -> Bool) async {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !condition() && ContinuousClock.now < deadline { await Task.yield() }
    XCTAssertTrue(condition())
  }

  func testUnusedJoinSealsAndReleasesItsOriginalReservation() throws {
    let fixture = try NamespaceFixture(createOwner: false)
    let before = fixture.root.snapshot().used
    let join = try V4CleanupJoin(environment: fixture.environment)
    XCTAssertGreaterThan(fixture.root.snapshot().used.sdkBytes, before.sdkBytes)
    XCTAssertTrue(join.status(completed).complete)
    XCTAssertEqual(fixture.root.snapshot().used, before)
  }

  func testLedgerPhysicalCloseRetainsItsChargeAfterSourceCleanupTransfer() async throws {
    let fixture = try NamespaceFixture(createOwner: false)
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let directory = root.appendingPathComponent(".flowersec/swift-ledger-cleanup-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let before = try fixture.environment.account.snapshot().used
    let ledger = try V4LiveServerAdmissionLedger(environment: fixture.environment,
      configuration: LiveServerAdmissionStoreConfiguration(directory: directory,
        backingIdentity: Data(repeating: 11, count: 16), create: true, maximumRows: 4,
        maximumBytes: 1 << 20, checkContinuity: { _ in }),
      tenant: "tenant", audience: "service", serverIdentity: Data(repeating: 12, count: 32))
    defer { ledger.close() }
    let charged = try fixture.environment.account.snapshot().used
    XCTAssertGreaterThan(charged.sdkBytes, before.sdkBytes)
    XCTAssertEqual(charged.handles, before.handles + 3)
    try fixture.environment.gate.withLock {
      ledger.transferSourceCleanup()
      ledger.retireWhenIdle()
      XCTAssertFalse(ledger.cleanupStatus().complete)
      XCTAssertEqual(ledger.cleanupStatus().pendingCallbacks, 1)
      XCTAssertEqual(ledger.sourceCleanupPending(), 0)
      XCTAssertEqual(try fixture.environment.account.snapshot().used, charged,
        "Moving cleanup out of Source must not release the ledger's physical charge")
    }
    await ledger.waitPhysicalCleanup()
    XCTAssertTrue(ledger.cleanupStatus().complete)
    XCTAssertEqual(ledger.sourceCleanupPending(), 0)
    XCTAssertEqual(try fixture.environment.account.snapshot().used, before)
    XCTAssertEqual(fixture.root.snapshot().used.diskBytes, 3 << 20)
  }

  func testPrepublicationRetryBorrowerWaitsForItsOwnHTTPCleanup() {
    // The live server registration attaches one borrower per pre-publication
    // HTTP request, even when both requests share the original preparation.
    let first = V4ServerAllowRequestCleanup()
    let retry = V4ServerAllowRequestCleanup()
    let pending = V4PendingBorrowers(initial: 2)
    first.observeCompletion { pending.decrement() }
    retry.observeCompletion { pending.decrement() }
    first.complete()
    XCTAssertEqual(pending.value, 1, "a disconnected first request must not retire a retry borrower")
    retry.complete()
    XCTAssertEqual(pending.value, 0)
  }

  func testIndependentObserversShareOriginalPhysicalJoinBeforePublicCloseWait() async throws {
    let fixture = try NamespaceFixture(createOwner: false, cleanupTimeout: .seconds(1))
    let before = fixture.root.snapshot().used
    let join = try V4CleanupJoin(environment: fixture.environment)
    let charged = fixture.root.snapshot().used
    let operation = V4CleanupTestOperation()
    let sourceObserver = Task { await join.waitPhysicalCompletion { await operation.run() } }
    let startDeadline = ContinuousClock.now.advanced(by: .seconds(2))
    while await operation.state.invocations == 0 && ContinuousClock.now < startDeadline { await Task.yield() }
    join.beginClose()
    let materialObserver = Task {
      await join.waitPhysicalCompletion { XCTFail("Material started another physical cleanup task") }
    }
    let publicObserver = Task {
      try await join.wait { XCTFail("Public cleanup restarted the original physical join") }
    }
    await eventually { join.status(self.pending).pendingCallbacks == 3 }
    XCTAssertEqual(fixture.root.snapshot().used, charged)
    await operation.release()
    await sourceObserver.value
    await materialObserver.value
    try await publicObserver.value
    XCTAssertTrue(join.status(completed).complete)
    XCTAssertEqual(fixture.root.snapshot().used, before)
    let state = await operation.state
    XCTAssertEqual(state.invocations, 1)
    XCTAssertFalse(state.canceled)
  }

  func testDeadlineDoesNotCancelPhysicalOwnerOrRenewOnAnotherWait() async throws {
    let fixture = try NamespaceFixture(createOwner: false)
    let before = fixture.root.snapshot().used
    let join = try V4CleanupJoin(environment: fixture.environment)
    let charged = fixture.root.snapshot().used
    let operation = V4CleanupTestOperation()
    join.beginClose()
    try await join.wait { await operation.run() }
    XCTAssertTrue(join.status(pending).cleanupIncomplete)
    XCTAssertEqual(fixture.root.snapshot().used, charged)
    try await join.wait { XCTFail("A second waiter restarted original physical cleanup") }
    XCTAssertEqual(fixture.root.snapshot().used, charged)
    await operation.release()
    await eventually { join.status(self.completed).complete }
    XCTAssertEqual(fixture.root.snapshot().used, before)
    let state = await operation.state
    XCTAssertEqual(state.invocations, 1)
    XCTAssertFalse(state.canceled)
  }

  func testCanceledObserverWithdrawsWithoutCancelingPhysicalCleanup() async throws {
    let fixture = try NamespaceFixture(createOwner: false, cleanupTimeout: .seconds(1))
    let before = fixture.root.snapshot().used
    let join = try V4CleanupJoin(environment: fixture.environment)
    let charged = fixture.root.snapshot().used
    let operation = V4CleanupTestOperation()
    join.beginClose()
    let observer = Task { try await join.wait { await operation.run() } }
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while await operation.state.invocations == 0 && ContinuousClock.now < deadline { await Task.yield() }
    observer.cancel()
    do { try await observer.value; XCTFail("Canceled observer returned success") }
    catch { XCTAssertTrue(error is CancellationError) }
    await eventually { join.status(self.pending).pendingCallbacks == 2 }
    XCTAssertEqual(fixture.root.snapshot().used, charged)
    let next = Task { try await join.wait { XCTFail("New observer replaced physical cleanup") } }
    await operation.release()
    try await next.value
    await eventually { join.status(self.completed).complete }
    XCTAssertEqual(fixture.root.snapshot().used, before)
    let state = await operation.state
    XCTAssertEqual(state.invocations, 1)
    XCTAssertFalse(state.canceled)
  }
}

private actor V4CleanupTestOperation {
  private var continuation: CheckedContinuation<Void, Never>?
  private var released = false
  private(set) var state = (invocations: 0, canceled: false)
  func run() async {
    state.invocations += 1
    if !released { await withCheckedContinuation { continuation = $0 } }
    state.canceled = Task.isCancelled
  }
  func release() {
    released = true
    continuation?.resume(); continuation = nil
  }
}
#endif

private final class V4PendingBorrowers: @unchecked Sendable {
  private let lock = NSLock()
  private var count: Int
  init(initial: Int) { count = initial }
  func decrement() { lock.withLock { count -= 1 } }
  var value: Int { lock.withLock { count } }
}
