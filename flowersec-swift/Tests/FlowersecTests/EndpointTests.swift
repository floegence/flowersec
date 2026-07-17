import Foundation
import XCTest

@testable import Flowersec

final class EndpointTests: XCTestCase {
  private struct Ping: Codable, Sendable { var value: String }
  private struct Pong: Codable, Sendable, Equatable {
    var value: String
    var ok: Bool
  }

  func testHandshakeTimeoutPreservesDirectAndTunnelPaths() async throws {
    for path in [FlowersecPath.direct, .tunnel] {
      let transport = EndpointBlockingTransport()
      do {
        _ = try await Endpoint.withHandshakeTimeout(
          transport: transport,
          path: path,
          timeout: .milliseconds(20)
        ) { _ in
          try await transport.readBinary()
        }
        XCTFail("Expected endpoint handshake timeout for \(path)")
      } catch let error as FlowersecError {
        XCTAssertEqual(error.path, path)
        XCTAssertEqual(error.stage, .handshake)
        XCTAssertEqual(error.code, .timeout)
      }
      try await waitForCondition { await transport.isClosed }
    }
  }

  func testHandshakeDeadlineWinsReadyCompletionBoundary() async throws {
    for _ in 0..<100 {
      let transport = EndpointScriptedTransport(frames: [])
      do {
        _ = try await Endpoint.withHandshakeTimeout(
          transport: transport,
          path: .direct,
          timeout: .zero
        ) { _ in
          42
        }
        XCTFail("Expected the elapsed deadline to win")
      } catch let error as FlowersecError {
        XCTAssertEqual(error.path, .direct)
        XCTAssertEqual(error.stage, .handshake)
        XCTAssertEqual(error.code, .timeout)
      }
    }
  }

  func testHandshakeCompletionBeforeDeadlineSurvivesDelayedConsumption() async throws {
    let transport = EndpointScriptedTransport(frames: [])
    let finishedAt = ContinuousClock.now
    let deadline = finishedAt + .milliseconds(20)
    try await Task.sleep(for: .milliseconds(30))

    let value: Int = try Endpoint.resolveHandshakeRaceEvent(
      .completed(42, finishedAt: finishedAt),
      transport: transport,
      path: .direct,
      deadline: deadline
    )
    XCTAssertEqual(value, 42)
  }

  func testHandshakeCancellationWinsCompletionBoundary() async throws {
    let transport = EndpointScriptedTransport(frames: [])
    let operationStarted = Flag()
    let releaseOperation = AsyncGate()
    let task = Task {
      try await Endpoint.withHandshakeTimeout(
        transport: transport,
        path: .direct,
        timeout: .seconds(1)
      ) { _ in
        await operationStarted.set()
        await releaseOperation.wait()
        return 42
      }
    }

    try await waitForFlag(operationStarted)
    task.cancel()
    await releaseOperation.release()
    do {
      _ = try await task.value
      XCTFail("Expected cancellation to win")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .handshake)
      XCTAssertEqual(error.code, .canceled)
    }
  }

  func testHandshakeCancellationDuringTaskRegistrationDoesNotStartOperation() async throws {
    let transport = EndpointScriptedTransport(frames: [])
    let operationStarted = Flag()
    let task = Task {
      try await Endpoint.withHandshakeTimeout(
        transport: transport,
        path: .direct,
        timeout: .seconds(1),
        beforeTaskRegistration: {
          withUnsafeCurrentTask { $0?.cancel() }
        }
      ) { _ in
        await operationStarted.set()
        return 42
      }
    }

    do {
      _ = try await task.value
      XCTFail("Expected registration-boundary cancellation")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .handshake)
      XCTAssertEqual(error.code, .canceled)
    }
    let didStart = await operationStarted.value
    XCTAssertFalse(didStart)
    try await waitForCondition { await transport.isClosed }
  }

  func testPreCanceledResolvedDirectDoesNotCallResolver() async throws {
    let transport = EndpointScriptedTransport(frames: [try directInitFrame()])
    let resolverCalled = Flag()
    let task = Task {
      withUnsafeCurrentTask { $0?.cancel() }
      return try await Endpoint.acceptDirectResolved(
        transport: transport,
        resolver: { _ in
          await resolverCalled.set()
          throw TestEndpointFailure.unreachable
        }
      )
    }

    do {
      _ = try await task.value
      XCTFail("Expected pre-canceled resolved direct endpoint")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .handshake)
      XCTAssertEqual(error.code, .canceled)
    }
    let wasResolverCalled = await resolverCalled.value
    XCTAssertFalse(wasResolverCalled)
    try await waitForCondition { await transport.isClosed }
  }

  func testPreCanceledDirectDoesNotCommitCredential() async throws {
    let transport = EndpointScriptedTransport(frames: [])
    let commitCalled = Flag()
    let credential = DirectEndpointCredential(
      channelID: "pre-canceled-direct",
      suite: .x25519HKDFSHA256AES256GCM,
      psk: Data(repeating: 7, count: 32),
      initExpiresAtUnixS: Int64(Date().timeIntervalSince1970) + 60,
      commitAuthenticated: { await commitCalled.set() }
    )
    let task = Task {
      withUnsafeCurrentTask { $0?.cancel() }
      return try await Endpoint.acceptDirect(transport: transport, credential: credential)
    }

    do {
      _ = try await task.value
      XCTFail("Expected pre-canceled direct endpoint")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .handshake)
      XCTAssertEqual(error.code, .canceled)
    }
    let wasCommitCalled = await commitCalled.value
    XCTAssertFalse(wasCommitCalled)
    try await waitForCondition { await transport.isClosed }
  }

  func testHandshakeTimeoutDoesNotWaitForBlockingTransportClose() async throws {
    let closeStarted = Flag()
    let closeFinished = Flag()
    let releaseClose = AsyncGate()
    let transport = EndpointBlockingCloseTransport(
      closeStarted: closeStarted,
      closeFinished: closeFinished,
      releaseClose: releaseClose
    )
    let started = ContinuousClock.now

    do {
      _ = try await Endpoint.withHandshakeTimeout(
        transport: transport,
        path: .direct,
        timeout: .milliseconds(20)
      ) { _ in
        try await transport.readBinary()
      }
      XCTFail("Expected handshake timeout")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .handshake)
      XCTAssertEqual(error.code, .timeout)
    }
    XCTAssertLessThan(ContinuousClock.now - started, .seconds(1))
    try await waitForFlag(closeStarted)
    let closeCallCount = await transport.closeCallCount
    XCTAssertEqual(closeCallCount, 1)

    await releaseClose.release()
    try await waitForFlag(closeFinished)
  }

  func testResolvedDirectHardTimeoutDoesNotWaitForPermanentResolver() async throws {
    let transport = EndpointScriptedTransport(frames: [try directInitFrame()])
    let started = ContinuousClock.now
    do {
      _ = try await Endpoint.acceptDirectResolved(
        transport: transport,
        resolver: { _ in
          await suspendForever()
          throw TestEndpointFailure.unreachable
        },
        options: EndpointOptions(handshakeTimeout: .milliseconds(20))
      )
      XCTFail("Expected permanent resolver to time out")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .handshake)
      XCTAssertEqual(error.code, .timeout)
    }
    XCTAssertLessThan(ContinuousClock.now - started, .seconds(1))
    try await waitForCondition { await transport.isClosed }
  }

  func testResolvedDirectLateResolverCannotStartHandshakeAfterTimeout() async throws {
    let pair = BinaryTransportPair()
    let server = TrackingBinaryTransport(inner: pair.server)
    let psk = try Data.secureRandom(count: 32)
    let expiresAt = Int64(Date().timeIntervalSince1970) + 60
    let gate = AsyncGate()
    let resolverStarted = Flag()
    let resolverFinished = Flag()
    let info = DirectConnectInfo(
      wsURL: URL(string: "wss://127.0.0.1/direct")!,
      channelID: "swift-endpoint-late-resolver",
      psk: psk,
      channelInitExpiresAtUnixS: expiresAt,
      defaultSuite: .x25519HKDFSHA256AES256GCM
    )
    let clientTask = Task {
      try await Flowersec.establishConnection(
        info,
        transport: pair.client,
        options: ConnectOptions(liveness: .disabled),
        path: .direct,
        idleTimeout: nil
      )
    }
    let endpointTask = Task {
      try await Endpoint.acceptDirectResolved(
        transport: server,
        resolver: { initInfo in
          await resolverStarted.set()
          await gate.wait()
          await resolverFinished.set()
          return DirectEndpointCredential(
            channelID: initInfo.channelID,
            suite: initInfo.suite,
            psk: psk,
            initExpiresAtUnixS: expiresAt
          )
        },
        options: EndpointOptions(handshakeTimeout: .milliseconds(50))
      )
    }

    try await waitForFlag(resolverStarted)
    do {
      _ = try await endpointTask.value
      XCTFail("Expected resolver timeout")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .handshake)
      XCTAssertEqual(error.code, .timeout)
    }
    let writesAtTimeout = await server.writeCallCount
    XCTAssertEqual(writesAtTimeout, 0)

    await gate.release()
    try await waitForFlag(resolverFinished)
    try await Task.sleep(for: .milliseconds(20))
    let writesAfterLateResolver = await server.writeCallCount
    XCTAssertEqual(writesAfterLateResolver, writesAtTimeout)

    clientTask.cancel()
    _ = try? await clientTask.value
  }

  func testResolvedDirectFailureClosesTransportAndPreservesResolveCode() async throws {
    let transport = EndpointScriptedTransport(frames: [try directInitFrame()])
    do {
      _ = try await Endpoint.acceptDirectResolved(
        transport: transport,
        resolver: { _ in throw TestEndpointFailure.resolver }
      )
      XCTFail("Expected resolver failure")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .validate)
      XCTAssertEqual(error.code, .resolveFailed)
    }
    try await waitForCondition { await transport.isClosed }
  }

  func testResolvedDirectValidatesChannelIDBeforeResolver() async throws {
    let cases: [(String, FlowersecCode)] = [
      ("   ", .missingChannelID),
      (" channel-test ", .invalidInput),
      (String(repeating: "x", count: 257), .invalidInput),
    ]
    for (channelID, expectedCode) in cases {
      let transport = EndpointScriptedTransport(
        frames: [try directInitFrame(channelID: channelID)]
      )
      do {
        _ = try await Endpoint.acceptDirectResolved(
          transport: transport,
          resolver: { _ in throw TestEndpointFailure.unreachable }
        )
        XCTFail("Expected invalid channel ID")
      } catch let error as FlowersecError {
        XCTAssertEqual(error.path, .direct)
        XCTAssertEqual(error.stage, .validate)
        XCTAssertEqual(error.code, expectedCode)
      }
      try await waitForCondition { await transport.isClosed }
    }
  }

  func testResolvedDirectInvalidProtocolFieldsUseSharedHandshakeTupleBeforeResolver() async throws {
    let cases: [(role: UInt8, version: UInt8, suite: Int)] = [
      (1, FlowersecWire.protocolVersion + 1, Suite.x25519HKDFSHA256AES256GCM.rawValue),
      (2, FlowersecWire.protocolVersion, Suite.x25519HKDFSHA256AES256GCM.rawValue),
      (1, FlowersecWire.protocolVersion, 99),
    ]
    for fields in cases {
      let resolverCalled = Flag()
      let transport = EndpointScriptedTransport(
        frames: [
          try directInitFrame(
            role: fields.role,
            version: fields.version,
            suite: fields.suite
          )
        ]
      )
      do {
        _ = try await Endpoint.acceptDirectResolved(
          transport: transport,
          resolver: { _ in
            await resolverCalled.set()
            throw TestEndpointFailure.unreachable
          }
        )
        XCTFail("Expected invalid direct handshake init")
      } catch let error as FlowersecError {
        XCTAssertEqual(error.path, .direct)
        XCTAssertEqual(error.stage, .handshake)
        XCTAssertEqual(error.code, .handshakeFailed)
      }
      let wasResolverCalled = await resolverCalled.value
      XCTAssertFalse(wasResolverCalled)
    }
  }

  func testResolvedDirectCancellationIsNotWrappedAsResolveFailure() async throws {
    let transport = EndpointScriptedTransport(frames: [try directInitFrame()])
    do {
      _ = try await Endpoint.acceptDirectResolved(
        transport: transport,
        resolver: { _ in throw CancellationError() }
      )
      XCTFail("Expected resolver cancellation")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .handshake)
      XCTAssertEqual(error.code, .canceled)
    }
    try await waitForCondition { await transport.isClosed }
  }

  func testResolvedDirectCommitUsesTheSameHardDeadline() async throws {
    let pair = BinaryTransportPair()
    let server = TrackingBinaryTransport(inner: pair.server)
    let psk = try Data.secureRandom(count: 32)
    let expiresAt = Int64(Date().timeIntervalSince1970) + 60
    let info = DirectConnectInfo(
      wsURL: URL(string: "wss://127.0.0.1/direct")!,
      channelID: "swift-endpoint-commit-timeout",
      psk: psk,
      channelInitExpiresAtUnixS: expiresAt,
      defaultSuite: .x25519HKDFSHA256AES256GCM
    )
    let clientTask = Task {
      try await Flowersec.establishConnection(
        info,
        transport: pair.client,
        options: ConnectOptions(liveness: .disabled),
        path: .direct,
        idleTimeout: nil
      )
    }

    do {
      _ = try await Endpoint.acceptDirectResolved(
        transport: server,
        resolver: { initInfo in
          DirectEndpointCredential(
            channelID: initInfo.channelID,
            suite: initInfo.suite,
            psk: psk,
            initExpiresAtUnixS: expiresAt,
            commitAuthenticated: { await suspendForever() }
          )
        },
        options: EndpointOptions(handshakeTimeout: .milliseconds(50))
      )
      XCTFail("Expected commit timeout")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .handshake)
      XCTAssertEqual(error.code, .timeout)
    }
    try await waitForCondition { await server.isClosed }
    clientTask.cancel()
    _ = try? await clientTask.value
  }

  func testResolvedDirectLateCommitCannotStartYamuxAfterTimeout() async throws {
    let pair = BinaryTransportPair()
    let server = TrackingBinaryTransport(inner: pair.server)
    let psk = try Data.secureRandom(count: 32)
    let expiresAt = Int64(Date().timeIntervalSince1970) + 60
    let gate = AsyncGate()
    let commitStarted = Flag()
    let commitFinished = Flag()
    let info = DirectConnectInfo(
      wsURL: URL(string: "wss://127.0.0.1/direct")!,
      channelID: "swift-endpoint-late-commit",
      psk: psk,
      channelInitExpiresAtUnixS: expiresAt,
      defaultSuite: .x25519HKDFSHA256AES256GCM
    )
    let clientTask = Task {
      try await Flowersec.establishConnection(
        info,
        transport: pair.client,
        options: ConnectOptions(liveness: .disabled),
        path: .direct,
        idleTimeout: nil
      )
    }
    let endpointTask = Task {
      try await Endpoint.acceptDirectResolved(
        transport: server,
        resolver: { initInfo in
          DirectEndpointCredential(
            channelID: initInfo.channelID,
            suite: initInfo.suite,
            psk: psk,
            initExpiresAtUnixS: expiresAt,
            commitAuthenticated: {
              await commitStarted.set()
              await gate.wait()
              await commitFinished.set()
            }
          )
        },
        options: EndpointOptions(handshakeTimeout: .milliseconds(100))
      )
    }

    try await waitForFlag(commitStarted)
    do {
      _ = try await endpointTask.value
      XCTFail("Expected commit timeout")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .handshake)
      XCTAssertEqual(error.code, .timeout)
    }
    let readsAtTimeout = await server.readCallCount

    await gate.release()
    try await waitForFlag(commitFinished)
    try await Task.sleep(for: .milliseconds(20))
    let readsAfterLateCommit = await server.readCallCount
    XCTAssertEqual(readsAfterLateCommit, readsAtTimeout)

    clientTask.cancel()
    _ = try? await clientTask.value
  }

  func testTunnelGrantValidationRunsBeforeTransportActivity() async throws {
    var normalized = validTunnelGrant()
    normalized.channelID = "  channel-test  "
    normalized.token = "  token  "
    let values = try Endpoint.validateTunnelGrant(normalized)
    XCTAssertEqual(values.channelID, "channel-test")
    XCTAssertEqual(values.token, "token")

    let cases: [(ChannelInitGrant, FlowersecCode)] = [
      (
        {
          var grant = validTunnelGrant()
          grant.role = 1
          return grant
        }(), .roleMismatch
      ),
      (
        {
          var grant = validTunnelGrant()
          grant.channelID = "  "
          return grant
        }(), .missingChannelID
      ),
      (
        {
          var grant = validTunnelGrant()
          grant.channelID = String(repeating: "x", count: 257)
          return grant
        }(), .invalidInput
      ),
      (
        {
          var grant = validTunnelGrant()
          grant.token = "  "
          return grant
        }(), .missingToken
      ),
      (
        {
          var grant = validTunnelGrant()
          grant.channelInitExpiresAtUnixS = 0
          return grant
        }(), .missingInitExp
      ),
      (
        {
          var grant = validTunnelGrant()
          grant.allowedSuites = []
          return grant
        }(), .invalidSuite
      ),
      (
        {
          var grant = validTunnelGrant()
          grant.defaultSuite = .p256HKDFSHA256AES256GCM
          return grant
        }(), .invalidSuite
      ),
      (
        {
          var grant = validTunnelGrant()
          grant.psk = Data(repeating: 0, count: 31)
          return grant
        }(), .invalidPSK
      ),
    ]
    for (grant, expectedCode) in cases {
      do {
        _ = try await Endpoint.connectTunnel(
          grant: grant,
          options: EndpointOptions(connectTimeout: .milliseconds(10))
        )
        XCTFail("Expected invalid tunnel grant \(expectedCode)")
      } catch let error as FlowersecError {
        XCTAssertEqual(error.path, .tunnel)
        XCTAssertEqual(error.stage, .validate)
        XCTAssertEqual(error.code, expectedCode)
      }
    }
  }

  func testPreCanceledTunnelAttachDoesNotReachSubmissionBoundary() async throws {
    let transport = EndpointCancelableAttachTransport()
    let task = Task {
      withUnsafeCurrentTask { $0?.cancel() }
      try await Endpoint.writeTunnelAttach(transport: transport, text: "one-time-token")
    }

    do {
      try await task.value
      XCTFail("Expected pre-canceled tunnel attach")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .tunnel)
      XCTAssertEqual(error.stage, .connect)
      XCTAssertEqual(error.code, .canceled)
    }
    let writeCallCount = await transport.writeCallCount
    let submittedTexts = await transport.submittedTexts
    XCTAssertEqual(writeCallCount, 0)
    XCTAssertEqual(submittedTexts, [])
    try await waitForCondition { await transport.isClosed }
  }

  func testPreCanceledConnectTunnelStopsBeforeTransportPolicy() async throws {
    let policyCalled = Flag()
    let task = Task {
      withUnsafeCurrentTask { $0?.cancel() }
      return try await Endpoint.connectTunnel(
        grant: validTunnelGrant(),
        options: EndpointOptions(
          transportSecurityPolicy: .custom { _ in
            await policyCalled.set()
            return true
          }
        )
      )
    }

    do {
      _ = try await task.value
      XCTFail("Expected pre-canceled tunnel connection")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .tunnel)
      XCTAssertEqual(error.stage, .connect)
      XCTAssertEqual(error.code, .canceled)
    }
    let wasPolicyCalled = await policyCalled.value
    XCTAssertFalse(wasPolicyCalled)
  }

  func testCanceledTunnelPolicyUsesEndpointCanceledTuple() async throws {
    let policyStarted = Flag()
    let releasePolicy = AsyncGate()
    let task = Task {
      try await Endpoint.connectTunnel(
        grant: validTunnelGrant(),
        options: EndpointOptions(
          transportSecurityPolicy: .custom { _ in
            await policyStarted.set()
            await releasePolicy.wait()
            try Task.checkCancellation()
            return true
          }
        )
      )
    }
    try await waitForFlag(policyStarted)

    task.cancel()
    await releasePolicy.release()

    do {
      _ = try await task.value
      XCTFail("Expected canceled endpoint transport policy")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .tunnel)
      XCTAssertEqual(error.stage, .connect)
      XCTAssertEqual(error.code, .canceled)
    }
  }

  func testCanceledEndpointResumeActorHopDoesNotStartSocket() async throws {
    let resumeStarted = Flag()
    let releaseResume = AsyncGate()
    let socketStarted = SynchronousFlag()
    let transport = FlowersecWebSocketBinaryTransport(
      url: URL(string: "wss://example.invalid/tunnel")!,
      origin: nil,
      connectTimeout: .seconds(1),
      path: .tunnel,
      beforeResume: {
        await resumeStarted.set()
        await releaseResume.wait()
      },
      resumeOverride: { socketStarted.set() }
    )
    let task = Task { try await Endpoint.resumeTunnelTransport(transport) }
    try await waitForFlag(resumeStarted)

    task.cancel()
    await releaseResume.release()

    do {
      try await task.value
      XCTFail("Expected canceled endpoint resume")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .tunnel)
      XCTAssertEqual(error.stage, .connect)
      XCTAssertEqual(error.code, .canceled)
    }
    XCTAssertFalse(socketStarted.value)
  }

  func testCanceledPendingTunnelAttachClosesBeforeSubmissionBoundary() async throws {
    let transport = EndpointCancelableAttachTransport()
    let task = Task {
      try await Endpoint.writeTunnelAttach(transport: transport, text: "one-time-token")
    }
    await transport.waitUntilWriteStarted()

    task.cancel()

    do {
      try await task.value
      XCTFail("Expected canceled tunnel attach")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .tunnel)
      XCTAssertEqual(error.stage, .connect)
      XCTAssertEqual(error.code, .canceled)
    }
    let submittedTexts = await transport.submittedTexts
    XCTAssertEqual(submittedTexts, [])
    try await waitForCondition { await transport.isClosed }
  }

  func testResolvedDirectEndpointServesRPC() async throws {
    let pair = BinaryTransportPair()
    let psk = try Data.secureRandom(count: 32)
    let expiresAt = Int64(Date().timeIntervalSince1970) + 60
    let committed = Flag()
    let info = DirectConnectInfo(
      wsURL: URL(string: "wss://127.0.0.1/direct")!,
      channelID: "swift-endpoint-test",
      psk: psk,
      channelInitExpiresAtUnixS: expiresAt,
      defaultSuite: .x25519HKDFSHA256AES256GCM
    )
    let options = ConnectOptions(liveness: .disabled)

    async let endpoint = Endpoint.acceptDirectResolved(
      transport: pair.server,
      resolver: { initInfo in
        XCTAssertEqual(initInfo.channelID, info.channelID)
        XCTAssertEqual(initInfo.suite, info.defaultSuite)
        return DirectEndpointCredential(
          channelID: initInfo.channelID,
          suite: initInfo.suite,
          psk: psk,
          initExpiresAtUnixS: expiresAt,
          commitAuthenticated: { await committed.set() }
        )
      }
    )
    async let client = Flowersec.establishConnection(
      info,
      transport: pair.client,
      options: options,
      path: .direct,
      idleTimeout: nil
    )

    let session = try await endpoint
    let wasCommitted = await committed.value
    XCTAssertTrue(wasCommitted)
    let router = RPCRouter()
    await router.register(77) { (ping: Ping) in
      Pong(value: ping.value, ok: true)
    }
    let serveTask = Task { try await session.serveRPC(router: router) }
    let connected = try await client
    let response: Pong = try await connected.rpc.call(77, Ping(value: "hello"))
    XCTAssertEqual(response, Pong(value: "hello", ok: true))

    await connected.close()
    await session.close()
    serveTask.cancel()
    _ = try? await serveTask.value
  }

  func testGeneratedTypedRPCClientAndServerRoundTrip() async throws {
    let pair = BinaryTransportPair()
    let psk = try Data.secureRandom(count: 32)
    let expiresAt = Int64(Date().timeIntervalSince1970) + 60
    let info = DirectConnectInfo(
      wsURL: URL(string: "wss://127.0.0.1/direct")!,
      channelID: "swift-generated-rpc-test",
      psk: psk,
      channelInitExpiresAtUnixS: expiresAt,
      defaultSuite: .x25519HKDFSHA256AES256GCM
    )

    async let endpoint = Endpoint.acceptDirectResolved(
      transport: pair.server,
      resolver: { initInfo in
        DirectEndpointCredential(
          channelID: initInfo.channelID,
          suite: initInfo.suite,
          psk: psk,
          initExpiresAtUnixS: expiresAt
        )
      }
    )
    async let client = Flowersec.establishConnection(
      info,
      transport: pair.client,
      options: ConnectOptions(liveness: .disabled),
      path: .direct,
      idleTimeout: nil
    )

    let session = try await endpoint
    let handler = GeneratedDemoHandler()
    let router = RPCRouter()
    await registerWireDemoDemo(router: router, handler: handler)
    let serveTask = Task { try await session.serveRPC(router: router) }
    let connected = try await client
    let demo = WireDemoDemoClient(rpc: connected.rpc)

    let response = try await demo.ping(WireDemoPingRequest())
    XCTAssertTrue(response.ok)

    try await demo.notifyHello(WireDemoHelloNotify(hello: "typed hello"))
    let notification = await handler.nextHello()
    XCTAssertEqual(notification, "typed hello")

    await connected.close()
    await session.close()
    serveTask.cancel()
    _ = try? await serveTask.value
  }

}

private enum TestEndpointFailure: Error {
  case resolver
  case unreachable
}

private func suspendForever() async {
  await withUnsafeContinuation { (_: UnsafeContinuation<Void, Never>) in }
}

private func directInitFrame(
  channelID: String = "swift-resolver-test",
  role: UInt8 = 1,
  version: UInt8 = FlowersecWire.protocolVersion,
  suite: Int = Suite.x25519HKDFSHA256AES256GCM.rawValue
) throws -> Data {
  let message = E2EEInitMessage(
    channelID: channelID,
    role: role,
    version: version,
    suite: suite,
    clientEphPubB64u: "unused",
    nonceCB64u: "unused",
    clientFeatures: 0
  )
  return FlowersecHandshakeFrame.encode(
    type: FlowersecWire.handshakeTypeInit,
    payload: try JSONEncoder().encode(message)
  )
}

private func validTunnelGrant() -> ChannelInitGrant {
  ChannelInitGrant(
    tunnelURL: URL(string: "wss://127.0.0.1:1/tunnel")!,
    channelID: "channel-test",
    channelInitExpiresAtUnixS: 1,
    idleTimeoutSeconds: 60,
    role: 2,
    token: "token",
    psk: Data(repeating: 0, count: 32),
    allowedSuites: [.x25519HKDFSHA256AES256GCM],
    defaultSuite: .x25519HKDFSHA256AES256GCM
  )
}

private actor EndpointScriptedTransport: FlowersecBinaryTransport {
  private var frames: [Data]
  private var closed = false
  private var readers: [CheckedContinuation<Data, Error>] = []

  init(frames: [Data]) {
    self.frames = frames
  }

  func writeBinary(_ data: Data) throws {}

  func readBinary() async throws -> Data {
    if !frames.isEmpty { return frames.removeFirst() }
    guard !closed else { throw FlowersecError.closed() }
    return try await withCheckedThrowingContinuation { continuation in
      readers.append(continuation)
    }
  }

  func close() {
    guard !closed else { return }
    closed = true
    for reader in readers { reader.resume(throwing: FlowersecError.closed()) }
    readers.removeAll()
  }

  var isClosed: Bool { closed }
}

private actor TrackingBinaryTransport: FlowersecBinaryTransport {
  private let inner: any FlowersecBinaryTransport
  private var closed = false
  private var reads = 0
  private var writes = 0

  init(inner: any FlowersecBinaryTransport) {
    self.inner = inner
  }

  func writeBinary(_ data: Data) async throws {
    writes += 1
    try await inner.writeBinary(data)
  }

  func readBinary() async throws -> Data {
    reads += 1
    return try await inner.readBinary()
  }

  func close() async {
    guard !closed else { return }
    closed = true
    await inner.close()
  }

  var isClosed: Bool { closed }
  var readCallCount: Int { reads }
  var writeCallCount: Int { writes }
}

private actor EndpointBlockingTransport: FlowersecBinaryTransport {
  private var closed = false
  private var readers: [CheckedContinuation<Data, Error>] = []

  func writeBinary(_ data: Data) throws {}

  func readBinary() async throws -> Data {
    guard !closed else { throw FlowersecError.closed() }
    return try await withCheckedThrowingContinuation { continuation in
      readers.append(continuation)
    }
  }

  func close() {
    guard !closed else { return }
    closed = true
    for reader in readers { reader.resume(throwing: FlowersecError.closed()) }
    readers.removeAll()
  }

  var isClosed: Bool { closed }
}

private actor EndpointBlockingCloseTransport: FlowersecBinaryTransport {
  private let closeStarted: Flag
  private let closeFinished: Flag
  private let releaseClose: AsyncGate
  private var readers: [CheckedContinuation<Data, Error>] = []
  private var closeCalls = 0

  init(closeStarted: Flag, closeFinished: Flag, releaseClose: AsyncGate) {
    self.closeStarted = closeStarted
    self.closeFinished = closeFinished
    self.releaseClose = releaseClose
  }

  func writeBinary(_ data: Data) throws {}

  func readBinary() async throws -> Data {
    try await withCheckedThrowingContinuation { continuation in
      readers.append(continuation)
    }
  }

  func close() async {
    closeCalls += 1
    await closeStarted.set()
    await releaseClose.wait()
    let pendingReaders = readers
    readers.removeAll()
    for reader in pendingReaders {
      reader.resume(throwing: FlowersecError.closed())
    }
    await closeFinished.set()
  }

  var closeCallCount: Int { closeCalls }
}

private actor EndpointCancelableAttachTransport: FlowersecTunnelAttachTransport {
  private var closed = false
  private var writes = 0
  private var sent: [String] = []
  private var pendingWrite: CheckedContinuation<Void, Never>?
  private var writeStartWaiters: [CheckedContinuation<Void, Never>] = []

  func writeBinary(_ data: Data) async throws {}

  func readBinary() async throws -> Data {
    throw FlowersecError.closed(path: .tunnel)
  }

  func writeText(_ text: String) async throws {
    writes += 1
    let waiters = writeStartWaiters
    writeStartWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
    await withCheckedContinuation { continuation in
      pendingWrite = continuation
    }
    guard !closed else { throw FlowersecError.closed(path: .tunnel) }
    sent.append(text)
  }

  func close() async {
    guard !closed else { return }
    closed = true
    let write = pendingWrite
    pendingWrite = nil
    write?.resume()
    let waiters = writeStartWaiters
    writeStartWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
  }

  func waitUntilWriteStarted() async {
    guard writes == 0 else { return }
    await withCheckedContinuation { continuation in
      writeStartWaiters.append(continuation)
    }
  }

  var isClosed: Bool { closed }
  var writeCallCount: Int { writes }
  var submittedTexts: [String] { sent }
}

private actor GeneratedDemoHandler: WireDemoDemoHandler {
  private var notifications: [String] = []
  private var waiters: [CheckedContinuation<String, Never>] = []

  func ping(_ request: WireDemoPingRequest) async throws -> WireDemoPingResponse {
    WireDemoPingResponse(ok: true)
  }

  func hello(_ payload: WireDemoHelloNotify) async {
    if waiters.isEmpty {
      notifications.append(payload.hello)
    } else {
      waiters.removeFirst().resume(returning: payload.hello)
    }
  }

  func nextHello() async -> String {
    if !notifications.isEmpty {
      return notifications.removeFirst()
    }
    return await withCheckedContinuation { continuation in
      waiters.append(continuation)
    }
  }
}

private actor Flag {
  private var stored = false
  var value: Bool { stored }
  func set() { stored = true }
}

private final class SynchronousFlag: @unchecked Sendable {
  private let lock = NSLock()
  private var stored = false

  var value: Bool {
    lock.lock()
    defer { lock.unlock() }
    return stored
  }

  func set() {
    lock.lock()
    stored = true
    lock.unlock()
  }
}

private actor AsyncGate {
  private var released = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  func wait() async {
    if released { return }
    await withCheckedContinuation { continuation in
      waiters.append(continuation)
    }
  }

  func release() {
    guard !released else { return }
    released = true
    let current = waiters
    waiters.removeAll()
    for waiter in current { waiter.resume() }
  }
}

private func waitForFlag(_ flag: Flag) async throws {
  try await waitForCondition { await flag.value }
}

private func waitForCondition(_ condition: @escaping @Sendable () async -> Bool) async throws {
  let deadline = ContinuousClock.now + .seconds(1)
  while !(await condition()) {
    if ContinuousClock.now >= deadline {
      throw TestEndpointFailure.unreachable
    }
    try await Task.sleep(for: .milliseconds(5))
  }
}

private struct BinaryTransportPair {
  let client: TestBinaryTransport
  let server: TestBinaryTransport

  init() {
    let clientInbound = PacketPipe()
    let serverInbound = PacketPipe()
    client = TestBinaryTransport(inbound: clientInbound, outbound: serverInbound)
    server = TestBinaryTransport(inbound: serverInbound, outbound: clientInbound)
  }
}

private struct TestBinaryTransport: FlowersecBinaryTransport {
  let inbound: PacketPipe
  let outbound: PacketPipe

  func writeBinary(_ data: Data) async throws {
    try await outbound.send(data)
  }

  func readBinary() async throws -> Data {
    try await inbound.receive()
  }

  func close() async {
    await inbound.close()
    await outbound.close()
  }
}

private actor PacketPipe {
  private var packets: [Data] = []
  private var waiters: [CheckedContinuation<Data, Error>] = []
  private var closed = false

  func send(_ data: Data) throws {
    guard !closed else { throw FlowersecError.closed() }
    if waiters.isEmpty {
      packets.append(data)
    } else {
      waiters.removeFirst().resume(returning: data)
    }
  }

  func receive() async throws -> Data {
    if !packets.isEmpty { return packets.removeFirst() }
    guard !closed else { throw FlowersecError.closed() }
    return try await withCheckedThrowingContinuation { continuation in
      waiters.append(continuation)
    }
  }

  func close() {
    guard !closed else { return }
    closed = true
    for waiter in waiters { waiter.resume(throwing: FlowersecError.closed()) }
    waiters.removeAll()
    packets.removeAll()
  }
}
