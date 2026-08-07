import Foundation
import XCTest

@testable import Flowersec

final class ConnectionControllerTests: XCTestCase {
  func testRepeatedStartCreatesOneAttemptAndCloseWaitsForItsCancellation() async throws {
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
