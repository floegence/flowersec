#if os(macOS) || os(iOS)
import Foundation
import XCTest

@testable import Flowersec

@MainActor
final class TransportDiagnosticsTests: XCTestCase {
  func testDisabledEventsKeepUnsampledFiniteCounters() async throws {
    let fixture = try NamespaceFixture(nativeResources: true)
    XCTAssertNil(fixture.environment.diagnosticContext(.connection))
    let received = DiagnosticTestRecorder()
    try fixture.environment.installDiagnosticSink(TransportDiagnosticSinkConfiguration(samplingPartsPerMillion: 0) {
      received.append($0)
    })
    let context = try XCTUnwrap(fixture.environment.diagnosticContext(.application))
    context.emit(.started); context.emit(.succeeded)
    let owner = V4ResourceOwnerKey(environment: V4ResourceIdentity(high: 2, low: 2),
      instance: V4ResourceIdentity(high: 99, low: 1), backing: V4ResourceIdentity(high: 99, low: 2), kind: 99, direction: 0)
    XCTAssertThrowsError(try fixture.environment.account.reserve(owner: owner, value: V4ResourceVector(sdkBytes: 8 << 30)))
    let original = try fixture.environment.account.reserve(owner: owner, value: V4ResourceVector(sdkBytes: 1))
    defer { original.release() }
    XCTAssertThrowsError(try fixture.environment.account.reserve(owner: owner, value: V4ResourceVector(sdkBytes: 1)))
    let snapshot = fixture.root.diagnosticCounters.snapshot()
    XCTAssertEqual(snapshot.count, TransportDiagnosticCounter.allCases.count)
    XCTAssertEqual(snapshot[.resourceRefusals], 1)
    XCTAssertEqual(snapshot[.reservationConflicts], 1)
    let sink = try XCTUnwrap(fixture.environment.diagnosticSink)
    _ = await sink.waitCleanup()
    XCTAssertTrue(received.snapshot.isEmpty)
  }

  func testWhitelistIdentifierCapAndBucketPurging() async throws {
    let fixture = try NamespaceFixture(nativeResources: true)
    let entropy = DiagnosticTestEntropy(), received = DiagnosticTestRecorder()
    let sink = try V4DiagnosticSink(environment: fixture.environment,
      configuration: TransportDiagnosticSinkConfiguration { received.append($0) },
      random: { entropy.bytes($0) }, utcNow: { entropy.now })
    defer { sink.close() }
    var contexts: [V4DiagnosticContext] = []
    for _ in 0..<1024 {
      let context = sink.context(phase: .application)
      contexts.append(context); context.emit(.other)
    }
    let excess = sink.context(phase: .connection)
    excess.emit(.other)
    XCTAssertEqual(fixture.root.diagnosticCounters.snapshot()[.diagnosticDropped], 1)
    entropy.advanceBucket()
    // All old SDK events are purged. The surviving operation keeps its
    // lifetime but receives freshly generated correlation bytes.
    contexts[0].emit(.other)
    sink.start()
    try await waitUntil { received.snapshot.count == 1 }
    let event = try XCTUnwrap(received.snapshot.first)
    XCTAssertEqual(event.correlationID.count, 16)
    XCTAssertGreaterThan(V4Crypto.number(event.correlationID.suffix(8)), 1024)
    XCTAssertEqual(fixture.root.diagnosticCounters.snapshot()[.diagnosticDropped], 1025)
    let encoded = try JSONEncoder().encode(event)
    XCTAssertLessThanOrEqual(encoded.count, 512)
    let object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    XCTAssertEqual(Set(object.keys), Set(["state", "attempt_bucket", "phase", "code", "retry_disposition", "duration_bucket", "correlation_id"]))
    _ = await sink.waitCleanup()
    withExtendedLifetime(contexts) {}
  }

  func testEventCapDoesNotResetWhenCallbacksDrain() async throws {
    let fixture = try NamespaceFixture(nativeResources: true)
    let entropy = DiagnosticTestEntropy(), received = DiagnosticTestRecorder()
    let sink = try V4DiagnosticSink(environment: fixture.environment,
      configuration: TransportDiagnosticSinkConfiguration { received.append($0) },
      random: { entropy.bytes($0) }, utcNow: { entropy.now })
    defer { sink.close() }
    let connection = sink.context(phase: .connection), application = sink.context(phase: .application)
    connection.emit(.other); application.emit(.other)
    for _ in 2..<4096 { connection.emit(.other) }
    sink.start()
    try await waitUntil { received.snapshot.count == 4096 }
    connection.emit(.other)
    XCTAssertEqual(fixture.root.diagnosticCounters.snapshot()[.diagnosticDropped], 1)
    let delivered = received.snapshot
    XCTAssertNotEqual(delivered[0].correlationID, delivered[1].correlationID)
    XCTAssertEqual(delivered[0].correlationID, delivered[2].correlationID)
    _ = await sink.waitCleanup()
  }

  func testCloseRetainsNoncooperativeCallbackAndOriginalDeadline() async throws {
    let fixture = try NamespaceFixture(nativeResources: true)
    let entropy = DiagnosticTestEntropy(), received = DiagnosticTestRecorder(), hold = DiagnosticTestHold()
    let baseline = try fixture.environment.account.snapshot()
    let sink = try V4DiagnosticSink(environment: fixture.environment,
      configuration: TransportDiagnosticSinkConfiguration { event in received.append(event); await hold.wait() },
      random: { entropy.bytes($0) }, utcNow: { entropy.now })
    defer { hold.release(); sink.close() }
    let context = sink.context(phase: .application)
    context.emit(.other); context.emit(.other)
    sink.start()
    try await waitUntil { hold.waiting }
    let status = await sink.waitCleanup()
    XCTAssertFalse(status.complete)
    XCTAssertTrue(status.cleanupIncomplete)
    XCTAssertGreaterThan(status.pendingCallbacks, 0)
    let charged = try fixture.environment.account.snapshot()
    XCTAssertGreaterThan(charged.executionTails, baseline.executionTails)
    XCTAssertGreaterThan(charged.used.sdkBytes, baseline.used.sdkBytes)
    let repeated = await sink.waitCleanup()
    XCTAssertTrue(repeated.cleanupIncomplete)
    context.emit(.other)
    hold.release()
    try await waitUntil { sink.cleanupStatus().complete }
    XCTAssertEqual(received.snapshot.count, 1)
    XCTAssertEqual(try fixture.environment.account.snapshot(), baseline)
  }

  func testCloseBeforeStartReleasesBothOriginalTails() async throws {
    let fixture = try NamespaceFixture(nativeResources: true)
    let baseline = try fixture.environment.account.snapshot()
    let sink = try V4DiagnosticSink(environment: fixture.environment,
      configuration: TransportDiagnosticSinkConfiguration { _ in XCTFail("closed sink delivered an event") })
    sink.close(); sink.start()
    XCTAssertTrue(sink.cleanupStatus().complete)
    XCTAssertEqual(try fixture.environment.account.snapshot(), baseline)
    XCTAssertThrowsError(try V4DiagnosticSink(environment: fixture.environment,
      configuration: TransportDiagnosticSinkConfiguration(samplingPartsPerMillion: 10_001) { _ in }))
  }

  func testSamplingUsesIndependentDrawsAtConfiguredThreshold() async throws {
    let fixture = try NamespaceFixture(nativeResources: true)
    let received = DiagnosticTestRecorder()
    let threshold = (UInt64.max / 1_000_000) * 5_000
    let draws = DiagnosticTestSamplingDraws([threshold - 1, threshold])
    let sink = try V4DiagnosticSink(environment: fixture.environment,
      configuration: TransportDiagnosticSinkConfiguration(samplingPartsPerMillion: 5_000) { received.append($0) },
      random: { draws.bytes($0) })
    defer { sink.close() }
    let context = sink.context(phase: .connection, attempt: 3)
    context.emit(.started); context.emit(.succeeded)
    sink.start()
    try await waitUntil { received.snapshot.count == 1 }
    _ = await sink.waitCleanup()
    XCTAssertEqual(draws.sampleCount, 2)
    XCTAssertEqual(received.snapshot.count, 1)
    XCTAssertEqual(received.snapshot.first?.attemptBucket, .twoToThree)
  }

  private func waitUntil(_ condition: () -> Bool) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while !condition() {
      if ContinuousClock.now >= deadline { throw TransportControlError.unavailable }
      try await ContinuousClock().sleep(for: .milliseconds(1))
    }
  }
}

private final class DiagnosticTestEntropy: @unchecked Sendable {
  private let gate = NSLock()
  private var identifier: UInt64 = 0
  private var seconds: TimeInterval = 900_000
  var now: Date { gate.withLock { Date(timeIntervalSince1970: seconds) } }
  func advanceBucket() { gate.withLock { seconds += 900 } }
  func bytes(_ count: Int) -> Data {
    gate.withLock {
      if count == 8 { return Data(repeating: 0, count: 8) }
      identifier += 1
      return Data(repeating: 0, count: 8) + V4Crypto.integer(identifier, width: 8)
    }
  }
}

private final class DiagnosticTestRecorder: @unchecked Sendable {
  private let gate = NSLock()
  private var values: [TransportDiagnosticEvent] = []
  var snapshot: [TransportDiagnosticEvent] { gate.withLock { values } }
  func append(_ event: TransportDiagnosticEvent) { gate.withLock { values.append(event) } }
}

private final class DiagnosticTestSamplingDraws: @unchecked Sendable {
  private let gate = NSLock()
  private let draws: [UInt64]
  private var index = 0
  init(_ draws: [UInt64]) { self.draws = draws }
  var sampleCount: Int { gate.withLock { index } }
  func bytes(_ count: Int) -> Data {
    gate.withLock {
      guard count == 8 else { return Data(repeating: 1, count: 16) }
      defer { index += 1 }
      return V4Crypto.integer(index < draws.count ? draws[index] : .max, width: 8)
    }
  }
}

private final class DiagnosticTestHold: @unchecked Sendable {
  private let gate = NSLock()
  private var continuation: CheckedContinuation<Void, Never>?
  private var released = false
  var waiting: Bool { gate.withLock { continuation != nil } }
  func wait() async {
    await withCheckedContinuation { continuation in
      let done = gate.withLock { () -> Bool in
        if released { return true }; self.continuation = continuation; return false
      }
      if done { continuation.resume() }
    }
  }
  func release() {
    let original = gate.withLock { () -> CheckedContinuation<Void, Never>? in
      released = true; defer { continuation = nil }; return continuation
    }
    original?.resume()
  }
}
#endif
