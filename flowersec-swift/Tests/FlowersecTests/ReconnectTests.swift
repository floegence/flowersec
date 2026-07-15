import Foundation
import XCTest

@testable import Flowersec

final class ReconnectTests: XCTestCase {
  func testOnceSourceConsumesArtifactExactlyOnce() async throws {
    let source = ArtifactSource.once(artifact())
    _ = try await source.acquire()
    do {
      _ = try await source.acquire()
      XCTFail("Expected the one-time source to be consumed")
    } catch let error as ArtifactSourceError {
      XCTAssertEqual(error, .onceConsumed)
    }
  }

  func testAutomaticReconnectRequiresRefreshableSource() async throws {
    let manager = ReconnectManager()
    do {
      try await manager.connect(
        ReconnectConfig(
          source: .once(artifact()),
          settings: ReconnectSettings(enabled: true)
        )
      )
      XCTFail("Expected a refreshable source requirement")
    } catch let error as ReconnectError {
      XCTAssertEqual(error, .refreshableSourceRequired)
    }
    let state = await manager.state()
    XCTAssertEqual(state.status, .error)
  }

  func testRefreshableSourceRetriesAndStopsOnTerminalConnectError() async throws {
    let calls = ReconnectTestCounter()
    let diagnostics = ReconnectDiagnosticRecorder()
    let expectedArtifact = artifact()
    let source = ArtifactSource.refreshable { _ in
      let call = await calls.incrementSource()
      if call < 3 { throw ArtifactSourceError.acquisitionFailed("temporary") }
      return expectedArtifact
    }
    let config = ReconnectConfig(
      source: source,
      options: ConnectOptions(onDiagnosticEvent: { event in
        diagnostics.record(event)
      }),
      settings: ReconnectSettings(
        enabled: true,
        maxAttempts: 5,
        initialDelay: .zero,
        maxDelay: .zero,
        factor: 1,
        jitterRatio: 0
      ),
      connector: { _, _ in
        await calls.incrementConnector()
        throw FlowersecError(
          path: .direct,
          stage: .validate,
          code: .invalidPSK,
          message: "Invalid E2EE key."
        )
      }
    )
    let manager = ReconnectManager()
    do {
      try await manager.connect(config)
      XCTFail("Expected the terminal connection error")
    } catch let error as ReconnectError {
      guard case .connection(let flowersec) = error else {
        return XCTFail("Unexpected reconnect error: \(error)")
      }
      XCTAssertEqual(flowersec.code, .invalidPSK)
    }
    let sourceCount = await calls.sourceCount()
    let connectorCount = await calls.connectorCount()
    XCTAssertEqual(sourceCount, 3)
    XCTAssertEqual(connectorCount, 1)
    let events = diagnostics.events()
    XCTAssertEqual(
      events.map { "\($0.code):\($0.attemptSeq)" },
      [
        "reconnect_attempt:1",
        "reconnect_scheduled:1",
        "reconnect_retry_attempt:2",
        "reconnect_scheduled:2",
        "reconnect_retry_attempt:3",
        "reconnect_exhausted:3",
      ]
    )
  }

  func testExplicitZeroDelayAndJitterArePreserved() throws {
    let settings = try ReconnectSettings(
      enabled: true,
      maxAttempts: 3,
      initialDelay: .zero,
      maxDelay: .zero,
      factor: 1,
      jitterRatio: 0
    ).normalized()
    XCTAssertEqual(settings.initialDelay, Duration.zero)
    XCTAssertEqual(settings.maxDelay, Duration.zero)
    XCTAssertEqual(settings.jitterRatio, 0)
    XCTAssertEqual(settings.delay(forFailedAttemptIndex: 2), Duration.zero)
  }

  private nonisolated func artifact() -> ConnectArtifact {
    .direct(
      DirectConnectInfo(
        wsURL: URL(string: "wss://direct.example.test/v1/connect")!,
        channelID: "channel-reconnect",
        psk: Data(repeating: 4, count: 32),
        channelInitExpiresAtUnixS: Int64(Date().timeIntervalSince1970) + 600,
        defaultSuite: .x25519HKDFSHA256AES256GCM
      ),
      metadata: .empty
    )
  }
}

private actor ReconnectTestCounter {
  private var sources = 0
  private var connectors = 0

  func incrementSource() -> Int {
    sources += 1
    return sources
  }

  func incrementConnector() {
    connectors += 1
  }

  func sourceCount() -> Int { sources }
  func connectorCount() -> Int { connectors }
}

private final class ReconnectDiagnosticRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var values: [DiagnosticEvent] = []

  func record(_ event: DiagnosticEvent) {
    lock.lock()
    values.append(event)
    lock.unlock()
  }

  func events() -> [DiagnosticEvent] {
    lock.lock()
    defer { lock.unlock() }
    return values
  }
}
