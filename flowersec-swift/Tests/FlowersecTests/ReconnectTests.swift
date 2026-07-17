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

  func testConnectedTerminationWaitsForFirstBackoffBeforeReconnect() async throws {
    let calls = ReconnectTestCounter()
    let sessions = ReconnectSessionFactory()
    let diagnostics = ReconnectDiagnosticRecorder()
    let expectedArtifact = artifact()
    let source = ArtifactSource.refreshable { _ in
      _ = await calls.incrementSource()
      return expectedArtifact
    }
    let manager = ReconnectManager()
    let config = ReconnectConfig(
      source: source,
      options: ConnectOptions(onDiagnosticEvent: diagnostics.record),
      settings: ReconnectSettings(
        enabled: true,
        maxAttempts: 3,
        initialDelay: .milliseconds(200),
        maxDelay: .milliseconds(200),
        factor: 1,
        jitterRatio: 0
      ),
      connector: { _, _ in try await sessions.connect() }
    )

    try await manager.connect(config)
    await sessions.waitForAttemptCount(1)
    let terminatedAt = ContinuousClock.now
    await sessions.failFirstConnection()
    try await Task.sleep(for: .milliseconds(50))
    let sourceCountBeforeRetry = await calls.sourceCount()
    let attemptCountBeforeRetry = await sessions.attemptCount()
    XCTAssertEqual(sourceCountBeforeRetry, 1)
    XCTAssertEqual(attemptCountBeforeRetry, 1)

    await sessions.waitForAttemptCount(2)
    XCTAssertGreaterThanOrEqual(terminatedAt.duration(to: .now), .milliseconds(150))
    let sourceCountAfterRetry = await calls.sourceCount()
    XCTAssertEqual(sourceCountAfterRetry, 2)
    XCTAssertTrue(
      diagnostics.events().contains {
        $0.code == "reconnect_scheduled" && $0.attemptSeq == 1
      }
    )
    XCTAssertTrue(
      diagnostics.events().contains {
        $0.code == "reconnect_retry_attempt" && $0.attemptSeq == 2
      }
    )
    await manager.disconnect()
  }

  func testDisconnectCancelsPostTerminationBackoff() async throws {
    let calls = ReconnectTestCounter()
    let sessions = ReconnectSessionFactory()
    let diagnostics = ReconnectDiagnosticRecorder()
    let manager = ReconnectManager()
    let expectedArtifact = artifact()
    let config = ReconnectConfig(
      source: .refreshable { _ in
        _ = await calls.incrementSource()
        return expectedArtifact
      },
      options: ConnectOptions(onDiagnosticEvent: diagnostics.record),
      settings: ReconnectSettings(
        enabled: true,
        maxAttempts: 3,
        initialDelay: .seconds(2),
        maxDelay: .seconds(2),
        factor: 1,
        jitterRatio: 0
      ),
      connector: { _, _ in try await sessions.connect() }
    )

    try await manager.connect(config)
    await sessions.failFirstConnection()
    for _ in 0..<100
    where !diagnostics.events().contains(where: {
      $0.code == "reconnect_scheduled"
    }) {
      try await Task.sleep(for: .milliseconds(5))
    }
    XCTAssertTrue(diagnostics.events().contains { $0.code == "reconnect_scheduled" })

    await manager.disconnect()
    let state = await manager.state()
    let sourceCount = await calls.sourceCount()
    let attemptCount = await sessions.attemptCount()
    XCTAssertEqual(state.status, .disconnected)
    XCTAssertEqual(sourceCount, 1)
    XCTAssertEqual(attemptCount, 1)
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

private actor ReconnectSessionFactory {
  private var attempts = 0
  private var firstChannel: ReconnectTestYamuxChannel?
  private var attemptWaiters: [(Int, CheckedContinuation<Void, Never>)] = []

  func connect() async throws -> FlowersecClient {
    attempts += 1
    resumeAttemptWaiters()
    guard attempts == 1 else {
      throw FlowersecError(
        path: .direct,
        stage: .validate,
        code: .invalidPSK,
        message: "Stop the reconnect test after the delayed attempt."
      )
    }

    let channel = ReconnectTestYamuxChannel()
    firstChannel = channel
    let secure = FlowersecSecureChannel(
      transport: ReconnectTestBinaryTransport(),
      keys: reconnectTestKeyState()
    )
    let yamux = FlowersecYamuxClient(channel: channel)
    await yamux.start()
    return FlowersecClient(
      rpc: RPCClient(stream: InMemoryRPCStream()),
      secure: secure,
      yamux: yamux,
      path: .direct
    )
  }

  func failFirstConnection() async {
    while firstChannel == nil { await Task.yield() }
    await firstChannel?.fail()
  }

  func attemptCount() -> Int { attempts }

  func waitForAttemptCount(_ count: Int) async {
    if attempts >= count { return }
    await withCheckedContinuation { attemptWaiters.append((count, $0)) }
  }

  private func resumeAttemptWaiters() {
    var remaining: [(Int, CheckedContinuation<Void, Never>)] = []
    for waiter in attemptWaiters {
      if attempts >= waiter.0 { waiter.1.resume() } else { remaining.append(waiter) }
    }
    attemptWaiters = remaining
  }
}

private actor ReconnectTestYamuxChannel: FlowersecYamuxChannel {
  private var readContinuation: CheckedContinuation<Data, Error>?
  private var failure: Error?

  func write(_ data: Data) async throws {}

  func readExact(_ length: Int) async throws -> Data {
    if let failure { throw failure }
    return try await withCheckedThrowingContinuation { readContinuation = $0 }
  }

  func close() async {
    readContinuation?.resume(returning: Data())
    readContinuation = nil
  }

  func fail() {
    let error = FlowersecError.closed(path: .direct)
    failure = error
    readContinuation?.resume(throwing: error)
    readContinuation = nil
  }
}

private actor ReconnectTestBinaryTransport: FlowersecBinaryTransport {
  func writeBinary(_ data: Data) async throws {}
  func readBinary() async throws -> Data { Data() }
  func close() async {}
}

private func reconnectTestKeyState() -> FlowersecRecordKeyState {
  FlowersecRecordKeyState(
    sendKey: Data(repeating: 1, count: 32),
    recvKey: Data(repeating: 2, count: 32),
    sendNoncePrefix: Data(repeating: 3, count: 4),
    recvNoncePrefix: Data(repeating: 4, count: 4),
    rekeyBase: Data(repeating: 5, count: 32),
    transcript: Data(repeating: 6, count: 32),
    sendDirection: 1,
    recvDirection: 2,
    sendSeq: 1,
    recvSeq: 1
  )
}
