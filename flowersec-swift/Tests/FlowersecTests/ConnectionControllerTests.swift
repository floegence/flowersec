import Foundation
import XCTest

@testable import Flowersec

final class ConnectionControllerTests: XCTestCase {
  func testSharedControllerDefaultsBackoffAndInvariantsMatchTheImplementation() throws {
    let vectors = try loadConnectionControllerVectors()
    XCTAssertEqual(vectors.version, 1)
    XCTAssertEqual(vectors.states, ["idle", "connecting", "connected", "waiting", "failed", "closed"])
    XCTAssertEqual(vectors.retryDispositions, ["terminal", "retryable", "retry_after"])
    let policy = ConnectionRetryPolicy()
    XCTAssertEqual(policy.initialDelay, .milliseconds(vectors.defaults.initialDelayMilliseconds))
    XCTAssertEqual(policy.maximumDelay, .milliseconds(vectors.defaults.maximumDelayMilliseconds))
    XCTAssertEqual(policy.multiplier, vectors.defaults.factor)
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
    XCTAssertFalse(vectors.invariants.retryNowOutsideWaiting)
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
      source: source,
      retryPolicy: ConnectionRetryPolicy(
        initialDelay: .milliseconds(10),
        maximumDelay: .milliseconds(10)
      )
    )

    await controller.start()
    let waiting = await waitForState(.waiting, controller: controller)
    XCTAssertTrue(waiting)

    await controller.retryNow()
    try await Task.sleep(for: .milliseconds(50))

    let acquisitionCount = await source.acquisitionCount
    XCTAssertEqual(acquisitionCount, 1)
    let snapshot = await controller.snapshot()
    XCTAssertEqual(snapshot.state, .waiting)
    XCTAssertNotNil(snapshot.nextRetryAt)
    if let nextRetryAt = snapshot.nextRetryAt {
      XCTAssertGreaterThanOrEqual(nextRetryAt, deadline)
    }

    await controller.close()
  }

  func testRetryNowWakesTheExistingSchedulerWithoutStartingParallelAttempts() async throws {
    let scenario = try connectionControllerScenario(named: "retry_now_wakes_existing_wait")
    XCTAssertEqual(scenario.schedulerCount, 1)
    XCTAssertEqual(scenario.maxInFlightAttempts, 1)
    let source = RetryThenBlockingArtifactSource()
    let controller = try ConnectionController(
      source: source,
      retryPolicy: ConnectionRetryPolicy(
        initialDelay: .seconds(30),
        maximumDelay: .seconds(30)
      )
    )

    await controller.start()
    let reachedWaiting = await waitForState(.waiting, controller: controller)
    XCTAssertTrue(reachedWaiting)
    await controller.retryNow()
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
      .terminal(.artifactSource(ArtifactSourceFailure(disposition: .terminal)))
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
      retryPolicy: ConnectionRetryPolicy(
        initialDelay: .milliseconds(1),
        maximumDelay: .milliseconds(1),
        maximumAttempts: UInt64(try XCTUnwrap(scenario.artifactAcquisitions))
      )
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
      .maximumAttemptsReached(
        last: .artifactSource(ArtifactSourceFailure(disposition: .retryable)))
    )
    await controller.close()
  }

  func testSharedControllerVectorInventoryHasOneOwningTestPerScenario() throws {
    XCTAssertEqual(
      Set(try loadConnectionControllerVectors().scenarios.map(\.name)),
      Set([
        "connect_and_replace_after_termination",
        "retry_now_wakes_existing_wait",
        "retry_after_is_authoritative",
        "terminal_failure",
        "explicit_attempt_exhaustion",
        "close_cancels_single_attempt",
      ])
    )
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
