import Foundation
import XCTest

@testable import Flowersec

@MainActor
final class TransportReceiveTests: XCTestCase {
  private func budget(directions: Int = 4, cursors: Int = 4, bytes: UInt64 = 128 * 1024) throws
    -> V4ReadBudget
  {
    try V4ReadBudget(
      V4ReadBudgetConfiguration(
        sdkBytes: bytes, directions: directions,
        cursors: cursors, authorizations: 4, rootRuntimeBytes: 256,
        directionRuntimeBytes: 256, cursorRuntimeBytes: 1024, authorizationRuntimeBytes: 128))
  }

  private func fixture(capacity: Int = 8, cursors: Int = 4) throws
    -> (V4ReadBudget, V4ReadAuthorization, V4ReceiveDirection)
  {
    let root = try budget(cursors: cursors)
    let authorization = try root.authorization(
      validatedHardDeadline: .now.advanced(by: .seconds(5)))
    let direction = try root.direction(
      capacity: capacity, initialReceiveLimit: UInt64(capacity),
      authorization: authorization)
    return (root, authorization, direction)
  }

  private func eventually(
    _ predicate: () -> Bool, file: StaticString = #filePath, line: UInt = #line
  ) async {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !predicate() && ContinuousClock.now < deadline { await Task.yield() }
    XCTAssertTrue(predicate(), file: file, line: line)
  }

  func testAuthenticatedQueueValidatesCreditAndSequenceBeforeMutation() throws {
    let (root, _, direction) = try fixture(capacity: 4)
    defer { root.close() }
    try direction.receiveAuthenticated(offset: 0, data: Data("abcd".utf8))
    let original = direction.snapshot()
    XCTAssertThrowsError(try direction.receiveAuthenticated(offset: 4, data: Data([1])))
    XCTAssertThrowsError(try direction.receiveAuthenticated(offset: 0, data: Data([1])))
    XCTAssertThrowsError(try direction.grant(5))
    XCTAssertEqual(direction.snapshot(), original)

    let prefix = try direction.tryRead(maxBytes: 2)
    XCTAssertEqual(prefix.data, Data("ab".utf8))
    XCTAssertEqual(prefix.progress.offset, 2)
    try direction.grant(6)
    try direction.receiveAuthenticated(offset: 4, data: Data("ef".utf8), eof: true)
    let suffix = try direction.tryRead(maxBytes: 8)
    XCTAssertEqual(suffix.data, Data("cdef".utf8))
    XCTAssertEqual(suffix.progress, ReadProgress(offset: 6, filled: 4, target: nil))
    XCTAssertEqual(suffix.streamStatus, .eof)
    XCTAssertEqual(direction.snapshot().releasedOffset, 6)
  }

  func testNativeCursorTransfersAtomicallyAcrossAWindow() async throws {
    let (root, _, direction) = try fixture(capacity: 4)
    defer { root.close() }
    let cursor = try direction.cursor(
      options: ReaderCursorOptions(exact: 8), capacity: 8,
      deadline: .now.advanced(by: .seconds(2)))
    let admission = try XCTUnwrap(cursor.admission)
    let reading = Task { try await cursor.readExactly() }
    await eventually { direction.snapshot().readPending }
    try direction.receiveAuthenticated(offset: 0, data: Data("abcd".utf8))
    // No continuation or worker has to run to commit the transferred prefix.
    XCTAssertEqual(cursor.progress().transferredBytes, 4)
    XCTAssertEqual(direction.snapshot().releasedOffset, 4)
    XCTAssertEqual(direction.snapshot().receiveLimit, 4)
    XCTAssertThrowsError(try direction.tryRead(maxBytes: 1)) { error in
      XCTAssertEqual((error as? ReadMethodFailure)?.reason, .readInProgress)
    }
    try direction.grant(8)
    await eventually { direction.snapshot().readPending }
    try direction.receiveAuthenticated(offset: 4, data: Data("efgh".utf8), eof: true)
    let result = try await reading.value
    XCTAssertEqual(result.data, Data("abcdefgh".utf8))
    XCTAssertEqual(result.progress, ReadProgress(offset: 8, filled: 8, target: 8))
    XCTAssertEqual(result.streamStatus, .eof)
    try await admission.waitCleanup()
    XCTAssertFalse(direction.snapshot().cursorClaimed)
    XCTAssertEqual(root.snapshot().cursors, 0)
  }

  func testNativeDelimiterMatcherPreservesFirstBoundaryAndRingSuffix() async throws {
    let (root, _, direction) = try fixture(capacity: 16)
    defer { root.close() }
    try direction.receiveAuthenticated(offset: 0, data: Data("skip".utf8))
    _ = try direction.tryRead(maxBytes: 4)
    try direction.grant(20)
    let cursor = try direction.cursor(
      options: ReaderCursorOptions(delimiter: Data("abab".utf8), maxBytes: 12), capacity: 12,
      deadline: .now.advanced(by: .seconds(2)))
    let read = Task { try await cursor.readUntil() }
    await eventually { direction.snapshot().readPending }
    try direction.receiveAuthenticated(offset: 4, data: Data("aaab".utf8))
    await eventually { direction.snapshot().readPending }
    try direction.receiveAuthenticated(offset: 8, data: Data("abTAIL".utf8))
    let result = try await read.value
    XCTAssertEqual(result.data, Data("aaabab".utf8))
    XCTAssertEqual(result.progress, ReadProgress(offset: 10, filled: 6, target: 12))
    XCTAssertNil(result.cause)
    let suffix = try direction.tryRead(maxBytes: 16)
    XCTAssertEqual(suffix.data, Data("TAIL".utf8))
    XCTAssertEqual(suffix.progress.offset, 14)
    try await cursor.admission?.waitCleanup()
  }

  func testCanceledWaitRetainsDirectionAndRealPrefix() async throws {
    let (root, _, direction) = try fixture()
    defer { root.close() }
    let cursor = try direction.cursor(
      options: ReaderCursorOptions(exact: 4), capacity: 4,
      deadline: .now.advanced(by: .seconds(2)))
    let read = Task { try await cursor.readExactly() }
    await eventually { direction.snapshot().readPending }
    read.cancel()
    let canceled = try await read.value
    XCTAssertEqual(canceled.waitStatus, .waitCanceled)
    XCTAssertEqual(canceled.progress.filled, 0)
    XCTAssertThrowsError(
      try direction.cursor(
        options: ReaderCursorOptions(exact: 1), capacity: 1,
        deadline: .now.advanced(by: .seconds(2))))
    try direction.receiveAuthenticated(offset: 0, data: Data("ab".utf8))
    XCTAssertEqual(cursor.progress().transferredBytes, 2)
    XCTAssertEqual(direction.snapshot().releasedOffset, 2)
    let resumed = Task { try await cursor.readExactly() }
    await eventually { direction.snapshot().readPending }
    try direction.receiveAuthenticated(offset: 2, data: Data("cd".utf8))
    let result = try await resumed.value
    XCTAssertEqual(result.data, Data("abcd".utf8))
    try await cursor.admission?.waitCleanup()
  }

  func testPrivateCompletedCandidateRetainsAuthorizationAndBudget() async throws {
    let (root, authorization, direction) = try fixture()
    defer { root.close() }
    let cursor = try direction.cursor(
      options: ReaderCursorOptions(exact: 4), capacity: 4,
      deadline: .now.advanced(by: .seconds(2)))
    let read = Task { try await cursor.readExactly() }
    await eventually { direction.snapshot().readPending }
    read.cancel()
    _ = try await read.value
    try direction.receiveAuthenticated(offset: 0, data: Data("data".utf8))
    await eventually { !direction.snapshot().cursorClaimed }
    XCTAssertTrue(cursor.progress().complete)
    XCTAssertFalse(cursor.progress().delivered)
    XCTAssertEqual(root.snapshot().cursors, 1)
    direction.close()
    XCTAssertEqual(root.snapshot().directions, 0)
    XCTAssertEqual(root.snapshot().cursors, 1)
    authorization.revoke()
    do {
      _ = try await cursor.readExactly()
      XCTFail("Revocation must fence the final payload handoff")
    } catch let failure as ReadMethodFailure {
      XCTAssertEqual(failure.reason, .authorizationDenied)
      XCTAssertEqual(failure.cursor?.transferredBytes, 4)
      XCTAssertEqual(failure.cursor?.streamStatus, .open)
    }
    try await cursor.admission?.waitCleanup()
    XCTAssertEqual(root.snapshot().cursors, 0)
  }

  func testCompleteCandidateOutlivesAssemblyDeadline() async throws {
    let (root, _, direction) = try fixture()
    defer { root.close() }
    let deadline = ContinuousClock.now.advanced(by: .milliseconds(100))
    let cursor = try direction.cursor(
      options: ReaderCursorOptions(exact: 4), capacity: 4, deadline: deadline)
    let reading = Task { try await cursor.readExactly() }
    await eventually { direction.snapshot().readPending }
    reading.cancel()
    _ = try await reading.value
    try direction.receiveAuthenticated(offset: 0, data: Data("data".utf8))
    await eventually { cursor.progress().complete && !direction.snapshot().cursorClaimed }
    try await ContinuousClock().sleep(until: deadline.advanced(by: .milliseconds(20)))
    let result = try await cursor.readExactly()
    XCTAssertEqual(result.data, Data("data".utf8))
    try await cursor.admission?.waitCleanup()
  }

  func testIdleExactZeroObservesCommittedTerminalBeforeCanceledWait() async throws {
    for eof in [true, false] {
      let (root, _, direction) = try fixture()
      defer { root.close() }
      let cursor = try direction.cursor(
        options: ReaderCursorOptions(exact: 0), capacity: 0,
        deadline: .now.advanced(by: .seconds(2)))
      if eof {
        try direction.receiveAuthenticated(offset: 0, data: Data(), eof: true)
      } else {
        direction.abort()
      }
      let reading = Task { try await cursor.readExactly() }
      reading.cancel()
      let result = try await reading.value
      XCTAssertEqual(result.streamStatus, eof ? .eof : .aborted)
      XCTAssertEqual(result.waitStatus, .ready)
      try await cursor.admission?.waitCleanup()
    }
  }

  func testTimePauseDoesNotConsumeOrDiscardAndCanResume() async throws {
    let (root, authorization, direction) = try fixture()
    defer { root.close() }
    let cursor = try direction.cursor(
      options: ReaderCursorOptions(exact: 4), capacity: 4,
      deadline: .now.advanced(by: .seconds(2)))
    let read = Task { try await cursor.readExactly() }
    await eventually { direction.snapshot().readPending }
    authorization.setTimeState(.pending)
    do {
      _ = try await read.value
      XCTFail("The original waiter must observe the time gate")
    } catch let failure as ReadMethodFailure {
      XCTAssertEqual(failure.reason, .timePending)
    }
    try direction.receiveAuthenticated(offset: 0, data: Data("data".utf8))
    XCTAssertEqual(direction.snapshot().queuedBytes, 4)
    XCTAssertEqual(direction.snapshot().releasedOffset, 0)
    XCTAssertEqual(cursor.progress().transferredBytes, 0)
    authorization.setTimeState(.usable)
    XCTAssertEqual(cursor.progress().transferredBytes, 4)
    let result = try await cursor.readExactly()
    XCTAssertEqual(result.data, Data("data".utf8))
    try await cursor.admission?.waitCleanup()
  }

  func testCursorDeadlineInterruptsIdleReadWithoutResettingDirection() async throws {
    let (root, _, direction) = try fixture()
    defer { root.close() }
    let cursor = try direction.cursor(
      options: ReaderCursorOptions(exact: 1), capacity: 1,
      deadline: .now.advanced(by: .milliseconds(40)))
    do {
      _ = try await cursor.readExactly()
      XCTFail("The original finite deadline must wake an idle read")
    } catch let failure as ReadMethodFailure {
      XCTAssertEqual(failure.reason, .authorizationDenied)
      XCTAssertEqual(failure.cursor?.streamStatus, .open)
      XCTAssertEqual(failure.cursor?.transferredBytes, 0)
    }
    try await cursor.admission?.waitCleanup()
    XCTAssertEqual(root.snapshot().cursors, 0)
    XCTAssertFalse(direction.snapshot().closed)
    try direction.receiveAuthenticated(offset: 0, data: Data([42]))
    XCTAssertEqual(try direction.tryRead(maxBytes: 1).data, Data([42]))
  }

  func testBudgetCloseWakesPendingCursorAndRetainsChargesUntilActualExit() async throws {
    let (root, _, direction) = try fixture()
    let cursor = try direction.cursor(
      options: ReaderCursorOptions(exact: 4), capacity: 4,
      deadline: .now.advanced(by: .seconds(2)))
    let read = Task { try await cursor.readExactly() }
    await eventually { direction.snapshot().readPending }
    root.close()
    do {
      _ = try await read.value
      XCTFail("Closing the budget authority must end its original waiters")
    } catch let failure as ReadMethodFailure {
      XCTAssertEqual(failure.reason, .ownerUnavailable)
    }
    try await cursor.admission?.waitCleanup()
    XCTAssertEqual(root.snapshot().cursors, 0)
    XCTAssertEqual(root.snapshot().directions, 0)
    XCTAssertThrowsError(try direction.tryRead(maxBytes: 1))
  }

  func testSharedCapacityAndEnvironmentIdentityAreEnforcedBeforeClaims() async throws {
    let (root, authorization, direction) = try fixture(cursors: 1)
    defer { root.close() }
    let other = try budget()
    defer { other.close() }
    let before = other.snapshot()
    XCTAssertThrowsError(
      try other.direction(
        capacity: 8, initialReceiveLimit: 8,
        authorization: authorization))
    XCTAssertEqual(other.snapshot(), before)
    let secondDirection = try root.direction(
      capacity: 8, initialReceiveLimit: 8,
      authorization: authorization)
    let cursor = try direction.cursor(
      options: ReaderCursorOptions(exact: 0), capacity: 0,
      deadline: .now.advanced(by: .seconds(2)))
    XCTAssertThrowsError(
      try secondDirection.cursor(
        options: ReaderCursorOptions(exact: 0), capacity: 0,
        deadline: .now.advanced(by: .seconds(2))))
    XCTAssertFalse(secondDirection.snapshot().cursorClaimed)
    let result = try await cursor.readExactly()
    XCTAssertEqual(result.data, Data())
    try await cursor.admission?.waitCleanup()
    let second = try secondDirection.cursor(
      options: ReaderCursorOptions(exact: 0), capacity: 0,
      deadline: .now.advanced(by: .seconds(2)))
    second.close()
    try await second.admission?.waitCleanup()
    XCTAssertEqual(root.snapshot().cursors, 0)
  }

  func testAuthorizationFencesNewCreditAndTerminalFactsRemainStable() throws {
    let (root, authorization, direction) = try fixture()
    defer { root.close() }
    try direction.receiveAuthenticated(offset: 0, data: Data([1, 2]))
    _ = try direction.tryRead(maxBytes: 2)
    authorization.setTimeState(.pending)
    XCTAssertThrowsError(try direction.grant(10)) { error in
      XCTAssertEqual((error as? ReadMethodFailure)?.reason, .timePending)
    }
    XCTAssertEqual(direction.snapshot().receiveLimit, 8)
    authorization.setTimeState(.usable)
    try direction.grant(10)
    try direction.receiveAuthenticated(offset: 2, data: Data(), eof: true)
    direction.abort()
    XCTAssertEqual(try direction.tryRead(maxBytes: 1).streamStatus, .eof)
    authorization.revoke()
    XCTAssertThrowsError(try direction.receiveAuthenticated(offset: 2, data: Data([3]))) { error in
      XCTAssertEqual((error as? ReadMethodFailure)?.reason, .authorizationDenied)
    }
  }

  func testAbortKeepsTransferredPrefixAndDoesNotFabricateEOF() async throws {
    let (root, _, direction) = try fixture()
    defer { root.close() }
    let cursor = try direction.cursor(
      options: ReaderCursorOptions(exact: 6), capacity: 6,
      deadline: .now.advanced(by: .seconds(2)))
    let read = Task { try await cursor.readExactly() }
    await eventually { direction.snapshot().readPending }
    try direction.receiveAuthenticated(offset: 0, data: Data("ab".utf8))
    await eventually { direction.snapshot().readPending }
    direction.abort()
    let result = try await read.value
    XCTAssertEqual(result.data, Data("ab".utf8))
    XCTAssertEqual(result.streamStatus, .aborted)
    XCTAssertEqual(result.progress.filled, 2)
    XCTAssertNil(result.cause)
    XCTAssertNil(result.error)
    try await cursor.admission?.waitCleanup()
  }
}
