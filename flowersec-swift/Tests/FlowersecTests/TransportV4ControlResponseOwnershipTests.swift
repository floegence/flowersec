#if os(macOS) || os(iOS)
import Foundation
import XCTest

@testable import Flowersec

@MainActor
final class TransportControlResponseOwnershipTests: XCTestCase {
  func testShortAndLargeResponsesRetainOriginalChargeUntilRelease() async throws {
    for count in [1, 32_768] {
      let fixture = try NamespaceFixture(nativeResources: true)
      let environment = fixture.environment
      defer { environment.beginClose() }
      let bytes = Data(repeating: 0xf5, count: count)
      let authority = try V4ControlTestAuthority(identity: V4ControlTestAuthority.Identity()) { path, _ in
        guard path == "/ownership" else { throw TransportControlError.responseInvalid }
        return bytes
      }
      defer { authority.stop() }
      let provider = try V4ControlHTTPS(environment: environment, configuration: authority.configuration())
      defer { provider.close() }
      let baseline = try environment.account.snapshot()
      var response: V4ControlHTTPResponse? = try await provider.post(path: "/ownership", body: Data([0x80]),
        maximumResponseBytes: count, check: { try environment.account.check() })
      XCTAssertEqual(response?.bytes, bytes)
      provider.close()
      // The one-byte case exercises Foundation's inline representation. A
      // completed socket alone must not refund the original response owner.
      try withExtendedLifetime(response) {
        XCTAssertFalse(provider.cleanupStatus().complete)
        XCTAssertGreaterThanOrEqual(provider.cleanupStatus().pendingCallbacks, 1)
        let held = try environment.account.snapshot()
        XCTAssertGreaterThan(held.executionTails, baseline.executionTails)
        XCTAssertGreaterThan(held.used.sdkBytes, baseline.used.sdkBytes)
      }
      response = nil
      try await requirePhysicalCleanup(provider)
      XCTAssertEqual(try environment.account.snapshot(), baseline)
    }
  }

  func testRequestCleanupDoesNotIncludeAnotherResponseOrOpenProvider() async throws {
    let fixture = try NamespaceFixture(nativeResources: true)
    let environment = fixture.environment
    defer { environment.beginClose() }
    let authority = try V4ControlTestAuthority(identity: V4ControlTestAuthority.Identity()) { _, _ in
      Data([0xf5])
    }
    defer { authority.stop() }
    let provider = try V4ControlHTTPS(environment: environment, configuration: authority.configuration())
    defer { provider.close() }
    let first = V4ControlHTTPCallCleanup(), second = V4ControlHTTPCallCleanup()
    XCTAssertTrue(first.cleanupStatus().complete)
    var response: V4ControlHTTPResponse? = try await provider.post(path: "/ownership", body: Data([0x80]),
      maximumResponseBytes: 1, cleanup: first, check: { try environment.account.check() })
    let other = try await provider.post(path: "/ownership", body: Data([0x80]),
      maximumResponseBytes: 1, cleanup: second, check: { try environment.account.check() })
    XCTAssertEqual(response?.bytes, Data([0xf5]))
    withExtendedLifetime(response) {
      XCTAssertFalse(first.cleanupStatus().complete)
      XCTAssertGreaterThanOrEqual(first.cleanupStatus().pendingCallbacks, 1)
    }
    response = nil
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while !first.cleanupStatus().complete {
      guard ContinuousClock.now < deadline else { throw TransportControlError.unavailable }
      try await ContinuousClock().sleep(for: .milliseconds(5))
    }
    withExtendedLifetime(other) {
      XCTAssertEqual(first.cleanupStatus(), CleanupStatus(complete: true))
      XCTAssertFalse(second.cleanupStatus().complete)
      XCTAssertGreaterThanOrEqual(second.cleanupStatus().pendingCallbacks, 1)
      XCTAssertFalse(provider.cleanupStatus().complete)
    }
  }

  private func requirePhysicalCleanup(_ provider: V4ControlHTTPS) async throws {
    try await withThrowingTaskGroup(of: Void.self) { group in
      group.addTask { _ = try await provider.waitCleanup() }
      group.addTask {
        try await ContinuousClock().sleep(for: .seconds(5))
        throw TransportControlError.unavailable
      }
      defer { group.cancelAll() }
      _ = try await group.next()
    }
  }
}
#endif
