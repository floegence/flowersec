import Foundation
import XCTest
@testable import Flowersec

@MainActor
final class TransportV4CursorTests: XCTestCase {
  func testExactAndDelimiterLeaveSuffixAtOriginalSource() async throws {
    let source = CursorSourceProbe(data: Data("hello\nbody".utf8), start: 41)
    let line = try ReaderCursor(source: source,
      options: ReaderCursorOptions(delimiter: Data([10]), maxBytes: 12), capacity: 12)
    let result = try await line.readLine()
    XCTAssertEqual(result.data, Data("hello\n".utf8))
    XCTAssertEqual(result.progress, ReadProgress(offset: 47, filled: 6, target: 12))
    XCTAssertEqual(result.waitStatus, .ready)
    XCTAssertEqual(result.streamStatus, .open)
    XCTAssertNil(result.cause)
    XCTAssertEqual(source.remaining, Data("body".utf8))
    XCTAssertEqual(source.releases, 1)

    let body = try ReaderCursor(source: source, options: ReaderCursorOptions(exact: 4), capacity: 4)
    let bodyResult = try await body.readExactly()
    XCTAssertEqual(bodyResult.data, Data("body".utf8))
    XCTAssertEqual(bodyResult.progress.offset, 51)
    XCTAssertEqual(body.progress().transferredBytes, 4)
    do {
      _ = try await body.takePrefix()
      XCTFail("The payload must be delivered once")
    } catch let error as ReadMethodFailure {
      XCTAssertEqual(error.reason, .alreadyDelivered)
      XCTAssertEqual(error.cursor?.transferredBytes, 4)
    }
  }

  func testTargetLimitAndEOFAreDistinctPartialResults() async throws {
    let boundedSource = CursorSourceProbe(data: Data("abcdef".utf8))
    let bounded = try ReaderCursor(source: boundedSource,
      options: ReaderCursorOptions(delimiter: Data([10]), maxBytes: 3), capacity: 3)
    let limited = try await bounded.readUntil()
    XCTAssertEqual(limited.data, Data("abc".utf8))
    XCTAssertEqual(limited.cause, .delimiterNotFound)
    XCTAssertEqual(limited.streamStatus, .open)
    XCTAssertEqual(limited.progress.filled, 3)
    XCTAssertEqual(boundedSource.remaining, Data("def".utf8))

    let shortSource = CursorSourceProbe(data: Data("ab".utf8), start: 90)
    let short = try ReaderCursor(source: shortSource, options: ReaderCursorOptions(exact: 4), capacity: 4)
    let eof = try await short.readExactly()
    XCTAssertEqual(eof.data, Data("ab".utf8))
    XCTAssertEqual(eof.cause, .unexpectedEOF)
    XCTAssertEqual(eof.streamStatus, .eof)
    XCTAssertEqual(eof.progress, ReadProgress(offset: 92, filled: 2, target: 4))
    XCTAssertEqual(short.progress().offset, 92)
  }

  func testCanceledWaitKeepsPartialPrefixAndSingleReadOwner() async throws {
    let source = CursorSourceProbe(suspended: true)
    let cursor = try ReaderCursor(source: source, options: ReaderCursorOptions(exact: 4), capacity: 4)
    let first = Task { try await cursor.readExactly() }
    await source.waitForReads(1)
    source.complete(Data("ab".utf8))
    await source.waitForReads(2)
    first.cancel()
    let canceled = try await first.value
    XCTAssertEqual(canceled.waitStatus, .waitCanceled)
    XCTAssertEqual(canceled.data, Data())
    XCTAssertEqual(canceled.progress, ReadProgress(offset: 2, filled: 0, target: 4))
    XCTAssertEqual(cursor.progress().transferredBytes, 2)
    XCTAssertEqual(source.releases, 0)

    let resumed = Task { try await cursor.readExactly() }
    source.complete(Data("cd".utf8))
    let result = try await resumed.value
    XCTAssertEqual(result.data, Data("abcd".utf8))
    XCTAssertEqual(result.progress, ReadProgress(offset: 4, filled: 4, target: 4))
    XCTAssertEqual(source.readCount, 2)
    XCTAssertEqual(source.releases, 1)
  }

  func testConcurrentReadIsRejectedAndTakePrefixSettlesLateBytes() async throws {
    let source = CursorSourceProbe(suspended: true)
    let cursor = try ReaderCursor(source: source, options: ReaderCursorOptions(exact: 8), capacity: 8)
    let original = Task { try await cursor.readExactly() }
    await source.waitForReads(1)
    do {
      _ = try await cursor.readExactly()
      XCTFail("Concurrent advancement must be rejected")
    } catch let error as ReadMethodFailure {
      XCTAssertEqual(error.reason, .readInProgress)
    }
    let prefix = Task { try await cursor.takePrefix() }
    await source.waitForStops(1)
    do {
      _ = try await original.value
      XCTFail("TakePrefix must permanently freeze the original read")
    } catch let error as ReadMethodFailure {
      XCTAssertEqual(error.reason, .prefixFrozen)
    }
    XCTAssertEqual(source.releases, 0)
    source.complete(Data("late".utf8))
    let result = try await prefix.value
    XCTAssertEqual(result.data, Data("late".utf8))
    XCTAssertEqual(result.progress, ReadProgress(offset: 4, filled: 4, target: 8))
    XCTAssertNil(result.cause)
    XCTAssertEqual(result.streamStatus, .open)
    XCTAssertEqual(source.readCount, 1)
    XCTAssertEqual(source.releases, 1)
  }

  func testCanceledTakePrefixKeepsFrozenCandidate() async throws {
    let source = CursorSourceProbe(suspended: true)
    let cursor = try ReaderCursor(source: source, options: ReaderCursorOptions(exact: 8), capacity: 8)
    let read = Task { try await cursor.readExactly() }
    await source.waitForReads(1)
    let prefix = Task { try await cursor.takePrefix() }
    await source.waitForStops(1)
    _ = try? await read.value
    prefix.cancel()
    let canceled = try await prefix.value
    XCTAssertEqual(canceled.waitStatus, .waitCanceled)
    source.complete(Data("tail".utf8))
    await source.waitForReleases(1)
    let result = try await cursor.takePrefix()
    XCTAssertEqual(result.data, Data("tail".utf8))
    XCTAssertEqual(result.progress.filled, 4)
    XCTAssertEqual(source.readCount, 1)
  }

  func testCloseDoesNotReleaseAnOutstandingRead() async throws {
    let source = CursorSourceProbe(suspended: true)
    let cursor = try ReaderCursor(source: source, options: ReaderCursorOptions(exact: 4), capacity: 4)
    let read = Task { try await cursor.readExactly() }
    await source.waitForReads(1)
    cursor.close()
    do {
      _ = try await read.value
      XCTFail("Closed cursor must not deliver payload")
    } catch let error as ReadMethodFailure {
      XCTAssertEqual(error.reason, .closed)
    }
    XCTAssertEqual(source.releases, 0)
    source.complete(Data("ab".utf8))
    await source.waitForReleases(1)
    XCTAssertEqual(cursor.progress().transferredBytes, 2)
    XCTAssertEqual(cursor.progress().offset, 2)
    XCTAssertTrue(cursor.progress().closed)
  }

  func testZeroExactPreservesAnAlreadyObservedEOF() async throws {
    let source = CursorSourceProbe(initialStatus: .eof)
    let cursor = try ReaderCursor(source: source, options: ReaderCursorOptions(exact: 0), capacity: 0)
    let result = try await cursor.readExactly()
    XCTAssertEqual(result.streamStatus, .eof)
    XCTAssertEqual(result.progress.filled, 0)
    XCTAssertNil(result.cause)
    XCTAssertEqual(source.readCount, 0)
  }

  func testValidationAndMethodMismatchDoNotConsume() async throws {
    let source = CursorSourceProbe(data: Data("bytes".utf8))
    for options in [
      ReaderCursorOptions(), ReaderCursorOptions(exact: 2, delimiter: Data([10]), maxBytes: 4),
      ReaderCursorOptions(delimiter: Data()), ReaderCursorOptions(delimiter: Data([10])),
      ReaderCursorOptions(delimiter: Data([13, 10]), maxBytes: 1), ReaderCursorOptions(exact: .max),
    ] {
      XCTAssertThrowsError(try ReaderCursor(source: source, options: options, capacity: 8))
    }
    let cursor = try ReaderCursor(source: source,
      options: ReaderCursorOptions(delimiter: Data([13, 10]), maxBytes: 8), capacity: 8)
    for read in [{ try await cursor.readExactly() }, { try await cursor.readLine() }] {
      do {
        _ = try await read()
        XCTFail("Mismatched methods must fail before consumption")
      } catch let error as ReadMethodFailure {
        XCTAssertEqual(error.reason, .targetMismatch)
      }
    }
    XCTAssertEqual(source.readCount, 0)
    let empty = try await cursor.takePrefix()
    XCTAssertEqual(empty.data, Data())
    XCTAssertEqual(empty.streamStatus, .open)
    XCTAssertEqual(empty.progress.target, 8)
    XCTAssertNil(empty.cause)
  }

  func testUnassembledEnvironmentRefusesBeforeAcquireAndClosesIdempotently() async throws {
    let environment = TransportEnvironment()
    let source = UnavailableMaterialSource()
    do {
      _ = try await environment.connect(source: source)
      XCTFail("A v4 environment cannot publish an unverified previous-engine session")
    } catch TransportV4AvailabilityError.runtimeUnavailable {}
    let calls = await source.calls
    XCTAssertEqual(calls, 0)
    try await environment.close()
    try await environment.close()
    let cleanup = await environment.cleanupStatus()
    XCTAssertTrue(cleanup.complete)
    do {
      _ = try await environment.connect(source: source)
      XCTFail("Closing must fence subsequent preparation")
    } catch SessionError.closed {}
  }
}

private actor ProbeEvents {
  private var count = 0
  private var waiters: [(Int, CheckedContinuation<Void, Never>)] = []
  func signal() {
    count += 1
    let ready = waiters.filter { $0.0 <= count }
    waiters.removeAll { $0.0 <= count }
    for (_, continuation) in ready { continuation.resume() }
  }
  func wait(_ target: Int) async {
    if count >= target { return }
    await withCheckedContinuation { waiters.append((target, $0)) }
  }
}

private final class CursorSourceProbe: ReaderCursorSource, @unchecked Sendable {
  let cursorGate = NSRecursiveLock()
  private var lock: NSRecursiveLock { cursorGate }
  private let readEvents = ProbeEvents()
  private let stopEvents = ProbeEvents()
  private let releaseEvents = ProbeEvents()
  private let origin: UInt64
  private let suspended: Bool
  let initialStatus: ReadStreamStatus
  let initialError: ReadStreamError? = nil
  private var data: Data
  private var consumed: UInt64 = 0
  private var reads = 0
  private var released = 0
  private var pending: (CheckedContinuation<Void, Never>, @Sendable (CursorReadChunk) -> Void)?

  init(data: Data = Data(), start: UInt64 = 0, suspended: Bool = false,
    initialStatus: ReadStreamStatus = .open)
  {
    self.data = data
    self.origin = start
    self.suspended = suspended
    self.initialStatus = initialStatus
  }

  var startOffset: UInt64 { lock.withLock { origin + consumed } }
  var remaining: Data { lock.withLock { data } }
  var readCount: Int { lock.withLock { reads } }
  var releases: Int { lock.withLock { released } }

  func read(maxBytes: Int, transfer: @escaping @Sendable (CursorReadChunk) -> Void) async {
    await withCheckedContinuation { continuation in
      lock.withLock {
        reads += 1
        if suspended {
          precondition(pending == nil)
          pending = (continuation, transfer)
          return
        }
        let bytes = Data(data.prefix(maxBytes))
        data.removeFirst(bytes.count)
        consumed += UInt64(bytes.count)
        transfer(CursorReadChunk(data: bytes, status: bytes.isEmpty ? .eof : .open, error: nil))
        continuation.resume()
      }
      Task { await readEvents.signal() }
    }
  }

  func complete(_ bytes: Data, status: ReadStreamStatus = .open) {
    lock.withLock {
      consumed += UInt64(bytes.count)
      let result = pending
      pending = nil
      precondition(result != nil)
      result?.1(CursorReadChunk(data: bytes, status: status, error: nil))
      result?.0.resume()
    }
  }

  func stopRead() { Task { await stopEvents.signal() } }
  func release() {
    lock.withLock { released += 1 }
    Task { await releaseEvents.signal() }
  }
  func waitForReads(_ count: Int) async { await readEvents.wait(count) }
  func waitForStops(_ count: Int) async { await stopEvents.wait(count) }
  func waitForReleases(_ count: Int) async { await releaseEvents.wait(count) }
}

private actor UnavailableMaterialSource: ConnectionMaterialSource {
  private(set) var calls = 0
  func acquire(_ requirements: ConnectionRequirements) async throws -> ConnectionMaterial {
    calls += 1
    throw SessionError.operationFailed
  }
}
