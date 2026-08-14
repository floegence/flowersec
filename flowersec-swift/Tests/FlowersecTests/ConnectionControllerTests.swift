import Foundation
import XCTest

@testable import Flowersec

final class ConnectionControllerTests: XCTestCase {
  func testSharedControllerDefaultsBackoffAndInvariantsMatchTheImplementation() throws {
    let vectors = try loadConnectionControllerVectors()
    XCTAssertEqual(vectors.version, 2)
    XCTAssertEqual(vectors.states, ["idle", "connecting", "connected", "waiting", "failed", "closed"])
    XCTAssertEqual(vectors.retryDispositions, ["terminal", "retryable", "retry_after"])
    XCTAssertEqual(
      FlowersecSDKDefaults.ConnectionController.initialDelay,
      .milliseconds(vectors.defaults.initialDelayMilliseconds))
    XCTAssertEqual(
      FlowersecSDKDefaults.ConnectionController.maximumDelay,
      .milliseconds(vectors.defaults.maximumDelayMilliseconds))
    XCTAssertEqual(FlowersecSDKDefaults.ConnectionController.multiplier, vectors.defaults.factor)
    XCTAssertEqual(vectors.defaults.jitterRatio, 0)
    XCTAssertNil(vectors.defaults.attemptLimit)
    for vector in vectors.backoffVectors {
      let exponent = max(0, Int(vector.consecutiveFailure) - 1)
      let delay = min(
        vectors.defaults.maximumDelayMilliseconds,
        vectors.defaults.initialDelayMilliseconds * Int(pow(Double(vectors.defaults.factor), Double(exponent)))
      )
      XCTAssertEqual(delay, vector.delayMilliseconds)
    }
    XCTAssertEqual(vectors.invariants.oneShotArtifactController, "forbidden")
    XCTAssertTrue(vectors.invariants.freshArtifactPerAttempt)
    XCTAssertTrue(vectors.invariants.singleScheduler)
    XCTAssertTrue(vectors.invariants.singleInFlightAttempt)
    XCTAssertTrue(vectors.invariants.startIdempotent)
    XCTAssertTrue(vectors.invariants.closeIdempotent)
    XCTAssertFalse(vectors.invariants.retryNowOutsideWaiting)
    XCTAssertFalse(vectors.invariants.retryAfterBypass)
    XCTAssertFalse(vectors.invariants.subordinateCloseFailurePropagates)
    XCTAssertEqual(vectors.invariants.publicRetryConfiguration, ["maximum_attempts"])
    XCTAssertFalse(vectors.invariants.oldStreamMigration)
    XCTAssertFalse(vectors.invariants.rpcReplay)
    XCTAssertFalse(vectors.invariants.writeReplay)
    XCTAssertFalse(vectors.invariants.crossSessionExactlyOnce)
    XCTAssertTrue(vectors.scenarios.allSatisfy { !$0.events.isEmpty })
  }

  func testRepeatedStartCreatesOneAttemptAndCloseWaitsForItsCancellation() async throws {
    let scenario = try connectionControllerScenario(named: "close_cancels_single_attempt")
    XCTAssertEqual(scenario.maxInFlightAttempts, 1)
    XCTAssertEqual(scenario.states, ["idle", "connecting", "closed"])
    let source = BlockingArtifactSource()
    let controller = try ConnectionController(source: source)

    await controller.start()
    await controller.start()
    await source.waitUntilAcquiring()
    await controller.start()

    let acquisitionCount = await source.acquisitionCount
    XCTAssertEqual(acquisitionCount, 1)

    await controller.close()

    let cancellationObserved = await source.cancellationObserved
    XCTAssertTrue(cancellationObserved)
    let snapshot = await controller.snapshot()
    XCTAssertEqual(snapshot.state, .closed)
  }

  func testRetryNowCannotBypassAbsoluteRetryAfterDeadline() async throws {
    let scenario = try connectionControllerScenario(named: "retry_after_is_authoritative")
    XCTAssertEqual(scenario.retryAtUnixMilliseconds, 1_004_000)
    XCTAssertEqual(scenario.states, ["idle", "connecting", "waiting", "connecting", "connected"])
    let deadline = Date().addingTimeInterval(2)
    let source = RetryAfterArtifactSource(deadline: deadline)
    let controller = try ConnectionController(
      source: source
    )

    await controller.start()
    let waiting = await waitForState(.waiting, controller: controller)
    XCTAssertTrue(waiting)

    let retryAfterWake = await controller.retryNow()
    XCTAssertFalse(retryAfterWake)
    try await Task.sleep(for: .milliseconds(50))

    let acquisitionCount = await source.acquisitionCount
    XCTAssertEqual(acquisitionCount, 1)
    let snapshot = await controller.snapshot()
    XCTAssertEqual(snapshot.state, .waiting)

    await controller.close()
  }

  func testRetryNowWakesTheExistingSchedulerWithoutStartingParallelAttempts() async throws {
    let scenario = try connectionControllerScenario(named: "retry_now_wakes_existing_wait")
    XCTAssertEqual(scenario.schedulerCount, 1)
    XCTAssertEqual(scenario.maxInFlightAttempts, 1)
    let source = RetryThenBlockingArtifactSource()
    let controller = try ConnectionController(
      source: source
    )

    await controller.start()
    let reachedWaiting = await waitForState(.waiting, controller: controller)
    XCTAssertTrue(reachedWaiting)
    let retryWake = await controller.retryNow()
    XCTAssertTrue(retryWake)
    await source.waitForAcquisitionCount(2)

    let acquisitionCount = await source.acquisitionCount
    let maximumConcurrentAcquisitions = await source.maximumConcurrentAcquisitions
    let snapshot = await controller.snapshot()
    XCTAssertEqual(acquisitionCount, 2)
    XCTAssertEqual(maximumConcurrentAcquisitions, 1)
    XCTAssertEqual(snapshot.state, .connecting)
    await controller.close()
  }

  func testTerminalArtifactFailureStopsAfterOneAttempt() async throws {
    let scenario = try connectionControllerScenario(named: "terminal_failure")
    XCTAssertEqual(scenario.artifactAcquisitions, 1)
    let source = AlwaysFailingArtifactSource(disposition: .terminal)
    let controller = try ConnectionController(source: source)

    await controller.start()
    let reachedFailed = await waitForState(.failed, controller: controller)
    XCTAssertTrue(reachedFailed)

    let acquisitionCount = await source.acquisitionCount
    XCTAssertEqual(acquisitionCount, scenario.artifactAcquisitions)
    let snapshot = await controller.snapshot()
    XCTAssertEqual(snapshot.attempt, 1)
    XCTAssertEqual(
      snapshot.failure,
      .artifactSource(ArtifactSourceFailure(disposition: .terminal))
    )
    await controller.close()
  }

  func testRetryableArtifactFailureStopsAtTheExplicitAttemptLimit() async throws {
    let scenario = try connectionControllerScenario(named: "explicit_attempt_exhaustion")
    XCTAssertEqual(scenario.artifactAcquisitions, 2)
    XCTAssertEqual(scenario.policy?.maximumAttempts, 2)
    let source = AlwaysFailingArtifactSource(disposition: .retryable)
    let controller = try ConnectionController(
      source: source,
      maximumAttempts: UInt64(try XCTUnwrap(scenario.artifactAcquisitions))
    )

    await controller.start()
    let reachedFailed = await waitForState(.failed, controller: controller)
    XCTAssertTrue(reachedFailed)

    let acquisitionCount = await source.acquisitionCount
    XCTAssertEqual(acquisitionCount, scenario.artifactAcquisitions)
    let snapshot = await controller.snapshot()
    XCTAssertEqual(snapshot.attempt, UInt64(try XCTUnwrap(scenario.artifactAcquisitions)))
    XCTAssertEqual(
      snapshot.failure,
      .artifactSource(ArtifactSourceFailure(disposition: .retryable))
    )
    await controller.close()
  }

  func testSharedControllerVectorInventoryHasOneOwningTestPerScenario() throws {
    XCTAssertEqual(
      Set(try loadConnectionControllerVectors().scenarios.map(\.name)),
      Set([
        "connect_and_replace_after_termination",
        "retry_now_wakes_existing_wait",
        "repeated_start_is_idempotent",
        "start_after_close_stays_closed",
        "retry_now_outside_waiting_returns_false",
        "retry_after_is_authoritative",
        "terminal_failure",
        "explicit_attempt_exhaustion",
        "close_cancels_single_attempt",
        "repeated_close_is_idempotent",
        "close_waits_for_owned_cleanup",
        "subordinate_close_failure_is_ignored",
      ])
    )
  }

  func testStartAfterCloseAndRetryNowOutsideWaitingFollowSharedVectors() async throws {
    let closedScenario = try connectionControllerScenario(named: "start_after_close_stays_closed")
    let retryScenario = try connectionControllerScenario(named: "retry_now_outside_waiting_returns_false")
    XCTAssertEqual(closedScenario.artifactAcquisitions, 0)
    XCTAssertEqual(retryScenario.retryNowResults, [false, false, false])

    let source = BlockingArtifactSource()
    let controller = try ConnectionController(source: source)
    let idleRetry = await controller.retryNow()
    XCTAssertFalse(idleRetry)
    await controller.close()
    await controller.start()
    let closedRetry = await controller.retryNow()
    let closedSnapshot = await controller.snapshot()
    let acquisitionCount = await source.acquisitionCount
    XCTAssertFalse(closedRetry)
    XCTAssertEqual(closedSnapshot.state, .closed)
    XCTAssertEqual(acquisitionCount, 0)
  }

  func testRepeatedCloseWaitsForCleanupAndIgnoresSubordinateFailure() async throws {
    let repeated = try connectionControllerScenario(named: "repeated_close_is_idempotent")
    let waits = try connectionControllerScenario(named: "close_waits_for_owned_cleanup")
    let ignored = try connectionControllerScenario(named: "subordinate_close_failure_is_ignored")
    XCTAssertEqual(repeated.cleanupCalls, 1)
    XCTAssertEqual(waits.cleanupCalls, 1)
    XCTAssertEqual(ignored.cleanupCalls, 1)

    let session = ControlledCloseSession(throwsOnClose: true)
    let source = SingleLeaseArtifactSource(
      lease: ArtifactLease(artifact: try loadArtifact()) {})
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { _, _ in session }
    )
    await controller.start()
    let connected = await waitForState(.connected, controller: controller)
    XCTAssertTrue(connected)

    let completion = CloseCompletionProbe()
    let firstClose = Task {
      await controller.close()
      await completion.markCompleted()
    }
    await session.waitUntilCloseStarted()
    let secondClose = Task { await controller.close() }
    await Task.yield()
    let completedBeforeRelease = await completion.completed
    let callsBeforeRelease = await session.closeCallCount
    XCTAssertFalse(completedBeforeRelease)
    XCTAssertEqual(callsBeforeRelease, 1)

    await session.releaseClose()
    await firstClose.value
    await secondClose.value
    let callsAfterRelease = await session.closeCallCount
    let finalSnapshot = await controller.snapshot()
    XCTAssertEqual(callsAfterRelease, 1)
    XCTAssertEqual(finalSnapshot.state, .closed)
  }

  func testArtifactLeaseCannotBeClaimedByTwoControllerAttempts() async throws {
    let artifact = try loadArtifact()
    let lease = ArtifactLease(artifact: artifact) {}

    try await lease.claimForConnectionController()
    do {
      try await lease.claimForConnectionController()
      XCTFail("Expected the reused controller lease claim to fail")
    } catch {}
  }

  private func waitForState(
    _ expected: ConnectionState,
    controller: ConnectionController,
    timeout: Duration = .seconds(1)
  ) async -> Bool {
    let deadline = ContinuousClock.now + timeout
    while ContinuousClock.now < deadline {
      if await controller.snapshot().state == expected { return true }
      await Task.yield()
    }
    return await controller.snapshot().state == expected
  }

  private func loadArtifact() throws -> Artifact {
    let url = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("testdata/transport_v2/artifact_vectors.json")
    let root = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
    let positive = root["positive"] as! [[String: Any]]
    let raw = positive[0]["artifact_json"] as! String
    return try parseArtifact(Data(raw.utf8))
  }
}

private actor BlockingArtifactSource: ArtifactSource {
  private(set) var acquisitionCount = 0
  private(set) var cancellationObserved = false
  private var acquiring = false
  private var acquiringWaiters: [CheckedContinuation<Void, Never>] = []

  func acquireArtifact() async throws -> ArtifactLease {
    acquisitionCount += 1
    acquiring = true
    let waiters = acquiringWaiters
    acquiringWaiters.removeAll()
    for waiter in waiters { waiter.resume() }

    do {
      try await Task.sleep(for: .seconds(60))
    } catch is CancellationError {
      cancellationObserved = true
      throw CancellationError()
    }
    throw BlockingArtifactSourceError.unexpectedWake
  }

  func waitUntilAcquiring() async {
    if acquiring { return }
    await withCheckedContinuation { acquiringWaiters.append($0) }
  }
}

private enum BlockingArtifactSourceError: Error {
  case unexpectedWake
}

private actor RetryAfterArtifactSource: ArtifactSource {
  private let deadline: Date
  private(set) var acquisitionCount = 0

  init(deadline: Date) {
    self.deadline = deadline
  }

  func acquireArtifact() throws -> ArtifactLease {
    acquisitionCount += 1
    throw ArtifactSourceFailure(disposition: .retryAfter(deadline))
  }
}

private actor AlwaysFailingArtifactSource: ArtifactSource {
  private let disposition: RetryDisposition
  private(set) var acquisitionCount = 0

  init(disposition: RetryDisposition) {
    self.disposition = disposition
  }

  func acquireArtifact() throws -> ArtifactLease {
    acquisitionCount += 1
    throw ArtifactSourceFailure(disposition: disposition)
  }
}

private actor RetryThenBlockingArtifactSource: ArtifactSource {
  private(set) var acquisitionCount = 0
  private(set) var maximumConcurrentAcquisitions = 0
  private var activeAcquisitions = 0
  private var acquisitionWaiters: [CheckedContinuation<Void, Never>] = []

  func acquireArtifact() async throws -> ArtifactLease {
    acquisitionCount += 1
    activeAcquisitions += 1
    maximumConcurrentAcquisitions = max(maximumConcurrentAcquisitions, activeAcquisitions)
    let waiters = acquisitionWaiters
    acquisitionWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
    defer { activeAcquisitions -= 1 }

    if acquisitionCount == 1 {
      throw ArtifactSourceFailure(disposition: .retryable)
    }
    try await Task.sleep(for: .seconds(60))
    throw BlockingArtifactSourceError.unexpectedWake
  }

  func waitForAcquisitionCount(_ expected: Int) async {
    while acquisitionCount < expected {
      await withCheckedContinuation { acquisitionWaiters.append($0) }
    }
  }
}

private actor SingleLeaseArtifactSource: ArtifactSource {
  private let lease: ArtifactLease
  private var consumed = false

  init(lease: ArtifactLease) { self.lease = lease }

  func acquireArtifact() throws -> ArtifactLease {
    guard !consumed else { throw ArtifactSourceFailure(disposition: .terminal) }
    consumed = true
    return lease
  }
}

private actor ControlledCloseSession: Session {
  nonisolated let rpc: any RPCPeer = ControlledRPCPeer()
  private let throwsOnClose: Bool
  private var closeStarted = false
  private var closeReleased = false
  private var closeWaiters: [CheckedContinuation<Void, Never>] = []
  private var terminationWaiters: [CheckedContinuation<SessionTermination, Never>] = []
  private(set) var closeCallCount = 0

  init(throwsOnClose: Bool) { self.throwsOnClose = throwsOnClose }

  func openStream(kind: String, metadata: StreamMetadata) async throws -> any ByteStream {
    _ = kind
    _ = metadata
    throw SessionError.closed
  }

  func acceptStream() async throws -> IncomingStream { throw SessionError.closed }
  func rekey() async throws { throw SessionError.closed }
  func probeLiveness() async throws -> Duration { throw SessionError.closed }

  func waitTermination() async -> SessionTermination {
    if closeStarted { return SessionTermination(error: .closed) }
    return await withCheckedContinuation { terminationWaiters.append($0) }
  }

  func close() async throws {
    closeCallCount += 1
    closeStarted = true
    let terminationWaiters = self.terminationWaiters
    self.terminationWaiters.removeAll()
    for waiter in terminationWaiters { waiter.resume(returning: SessionTermination(error: .closed)) }
    if !closeReleased {
      await withCheckedContinuation { closeWaiters.append($0) }
    }
    if throwsOnClose { throw SessionError.operationFailed }
  }

  func waitUntilCloseStarted() async {
    while !closeStarted { await Task.yield() }
  }

  func releaseClose() {
    closeReleased = true
    let waiters = closeWaiters
    closeWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
  }
}

private struct ControlledRPCPeer: RPCPeer, Sendable {
  func call<Request: Encodable & Sendable, Response: Decodable & Sendable>(
    _ typeID: UInt32,
    _ request: Request,
    as responseType: Response.Type,
    timeout: Duration
  ) async throws -> Response {
    _ = typeID
    _ = request
    _ = responseType
    _ = timeout
    throw SessionError.closed
  }

  func notify<Payload: Encodable & Sendable>(_ typeID: UInt32, _ payload: Payload) async throws {
    _ = typeID
    _ = payload
    throw SessionError.closed
  }

  func subscribeNotification<Payload: Decodable & Sendable>(
    _ typeID: UInt32,
    as payloadType: Payload.Type,
    handler: @escaping @Sendable (Result<Payload, RPCNotificationError>) async throws -> Void
  ) async throws -> any RPCNotificationSubscription {
    _ = typeID
    _ = payloadType
    _ = handler
    throw SessionError.closed
  }
}

private actor CloseCompletionProbe {
  private(set) var completed = false
  func markCompleted() { completed = true }
}
