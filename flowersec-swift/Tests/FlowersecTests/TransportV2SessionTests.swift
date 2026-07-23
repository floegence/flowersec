import Foundation
import XCTest

@testable import Flowersec

final class TransportV2SessionTests: XCTestCase {
  func testNOnePhysicalCapacityEstablishesAndCarriesOneApplicationStream() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair(
      inboundBidirectionalStreamCapacity: 3
    )
    let configs = try makeConfigs(maxInboundStreams: 1)
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    let opening = try await clientSession.openStream(kind: "n-one")
    let incoming = try await serverSession.acceptStream()
    _ = try await opening.write(Data([1]))
    let received = try await incoming.stream.read(maxBytes: 1)
    XCTAssertEqual(received, Data([1]))
    await clientSession.close()
    await serverSession.close()
  }

  func testPhysicalCapacityMismatchFailsBeforeControlStreamOpen() async throws {
    let (clientCarrier, _) = MemoryCarrierSession.pair(inboundBidirectionalStreamCapacity: 4)
    let configs = try makeConfigs(maxInboundStreams: 1)
    do {
      _ = try await TransportV2Session.establish(carrier: clientCarrier, config: configs.client)
      XCTFail("mismatched physical capacity unexpectedly established")
    } catch let error as TransportV2SessionError {
      XCTAssertEqual(error, .invalidConfiguration)
    }
    let openedStreamCount = await clientCarrier.openedStreamCount
    XCTAssertEqual(openedStreamCount, 0)
  }

  func testOpenRejectRequiresExpectedHashAndNonzeroReason() throws {
    let expectedHash = Data(repeating: 7, count: 32)
    var payload = expectedHash
    payload.appendUInt16BE(2)
    XCTAssertEqual(
      try validateOpenRejectV2(payload: payload, expectedOpenHash: expectedHash),
      2
    )

    var zeroReason = expectedHash
    zeroReason.appendUInt16BE(0)
    XCTAssertThrowsError(
      try validateOpenRejectV2(payload: zeroReason, expectedOpenHash: expectedHash)
    )

    var wrongHash = payload
    wrongHash[0] ^= 1
    XCTAssertThrowsError(
      try validateOpenRejectV2(payload: wrongHash, expectedOpenHash: expectedHash)
    )
  }

  func testResourceExhaustionUsesRegisteredOpenRejectReason() {
    XCTAssertEqual(openRejectResourceExhaustedReasonV2, 2)
  }

  func testEstablishesAndCarriesBidirectionalStreamsWithFIN() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()

    async let server = TransportV2Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    let outbound = try await clientSession.openStream(
      kind: "测试/echo",
      metadata: try StreamMetadataV2(["name": .string("cafe\u{301}")])
    )
    let inbound = try await serverSession.acceptStream()
    XCTAssertEqual(inbound.kind, "测试/echo")
    XCTAssertEqual(inbound.metadata.values["name"], .string("café"))

    let written = try await outbound.write(Data("hello".utf8))
    XCTAssertEqual(written, 5)
    let received = try await inbound.stream.read(maxBytes: 32)
    XCTAssertEqual(received, Data("hello".utf8))
    try await outbound.closeWrite()
    let afterFIN = try await inbound.stream.read(maxBytes: 32)
    XCTAssertNil(afterFIN)

    let reverse = try await serverSession.openStream(kind: "reverse")
    let reverseInbound = try await clientSession.acceptStream()
    let reverseWritten = try await reverse.write(Data("world".utf8))
    XCTAssertEqual(reverseWritten, 5)
    let reverseReceived = try await reverseInbound.stream.read(maxBytes: 32)
    XCTAssertEqual(reverseReceived, Data("world".utf8))

    await clientSession.close()
    await serverSession.close()
  }

  func testLivenessAndResetAreDeliveredOverControlStream() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    let clientStream = try await clientSession.openStream(kind: "long-lived")
    let serverStream = try await serverSession.acceptStream().stream
    let elapsed = try await clientSession.probeLiveness()
    XCTAssertGreaterThanOrEqual(elapsed, Duration.zero)
    await clientStream.reset()
    try await Task.sleep(for: .milliseconds(10))
    let terminalError = await serverStream.terminalError()
    XCTAssertNotNil(terminalError)

    await clientSession.close()
    await serverSession.close()
  }

  func testLazyRPCUsesReservedEncryptedStreamsInBothDirections() async throws {
    let clientRouter = RPCRouter()
    let serverRouter = RPCRouter()
    await clientRouter.register(11) { (request: SessionEcho) in request }
    await serverRouter.register(22) { (request: SessionEcho) in request }

    var configs = try makeConfigs()
    configs.client.deadlines.rekeyPrepare = .seconds(1)
    configs.client.deadlines.rekeyCompletion = .seconds(1)
    configs.server.deadlines.rekeyPrepare = .seconds(1)
    configs.server.deadlines.rekeyCompletion = .seconds(1)
    configs.client.rpcRouter = clientRouter
    configs.server.rpcRouter = serverRouter
    let clientConfig = configs.client
    let serverConfig = configs.server
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    let serverResponse: SessionEcho
    do {
      serverResponse = try await clientSession.rpc.call(
        22,
        SessionEcho(value: "from-client"),
        as: SessionEcho.self,
        timeout: .seconds(2)
      )
    } catch {
      XCTFail("initial client-to-server RPC failed: \(error)")
      throw error
    }
    XCTAssertEqual(serverResponse, SessionEcho(value: "from-client"))
    let clientResponse: SessionEcho
    do {
      clientResponse = try await serverSession.rpc.call(
        11,
        SessionEcho(value: "from-server"),
        as: SessionEcho.self,
        timeout: .seconds(2)
      )
    } catch {
      XCTFail("initial server-to-client RPC failed: \(error)")
      throw error
    }
    XCTAssertEqual(clientResponse, SessionEcho(value: "from-server"))

    do {
      try await clientSession.rekey()
    } catch {
      XCTFail("client rekey failed while both reserved RPC streams were active: \(error)")
      throw error
    }
    do {
      try await serverSession.rekey()
    } catch {
      XCTFail("server rekey failed while both reserved RPC streams were active: \(error)")
      throw error
    }
    let postRekey: SessionEcho
    do {
      postRekey = try await clientSession.rpc.call(
        22,
        SessionEcho(value: "post-rekey"),
        as: SessionEcho.self,
        timeout: .seconds(2)
      )
    } catch {
      XCTFail("post-rekey client-to-server RPC failed: \(error)")
      throw error
    }
    XCTAssertEqual(postRekey, SessionEcho(value: "post-rekey"))

    await clientSession.close()
    await serverSession.close()
  }

  func testActiveBidirectionalStreamSurvivesConsecutiveRekeys() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    let clientStream = try await clientSession.openStream(kind: "rekey")
    let serverStream = try await serverSession.acceptStream().stream
    try await clientSession.rekey()
    try await clientSession.rekey()
    let clientWritten = try await clientStream.write(Data("epoch-two".utf8))
    XCTAssertEqual(clientWritten, 9)
    let serverReceived = try await serverStream.read(maxBytes: 32)
    XCTAssertEqual(serverReceived, Data("epoch-two".utf8))

    try await serverSession.rekey()
    let serverWritten = try await serverStream.write(Data("reverse".utf8))
    XCTAssertEqual(serverWritten, 7)
    let clientReceived = try await clientStream.read(maxBytes: 32)
    XCTAssertEqual(clientReceived, Data("reverse".utf8))

    await clientSession.close()
    await serverSession.close()
  }

  func testPeerInitiatedRekeyUsesReceiverCompletionDeadline() async throws {
    let blocker = SwitchableWriteBlocker()
    let (clientCarrier, serverBase) = MemoryCarrierSession.pair()
    let serverCarrier = StallableWriteCarrierSession(
      base: serverBase,
      blocker: blocker,
      blockAcceptedStreamNumber: 2
    )
    var configs = try makeConfigs()
    configs.client.deadlines.rekeyCompletion = .seconds(1)
    configs.server.deadlines.rekeyCompletion = .milliseconds(25)
    let clientConfig = configs.client
    let serverConfig = configs.server
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)
    let clientStream = try await clientSession.openStream(kind: "peer-rekey-deadline")
    let serverStream = try await serverSession.acceptStream().stream

    await blocker.enable(afterSuccessfulWrites: 0)
    let rekeying = Task { try await clientSession.rekey() }
    await blocker.waitUntilBlocked()
    let terminal = await serverSession.waitClosed()
    XCTAssertEqual(terminal, .protocolViolation)
    await blocker.release()
    rekeying.cancel()
    _ = try? await rekeying.value
    await clientStream.reset()
    await serverStream.reset()
  }

  func testWaitClosedIsRepeatableAndReportsNormalClose() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)
    let waiting = Task { await clientSession.waitClosed() }

    await clientSession.close()
    let first = await waiting.value
    let repeated = await clientSession.waitClosed()
    XCTAssertEqual(first, .closed)
    XCTAssertEqual(repeated, .closed)
    await serverSession.close()
  }

  func testApplicationDataAndFINWaitForStreamRekeyACK() async throws {
    let blocker = SwitchableWriteBlocker()
    let (clientCarrier, serverBase) = MemoryCarrierSession.pair()
    let serverCarrier = StallableWriteCarrierSession(
      base: serverBase,
      blocker: blocker,
      blockAcceptedStreamNumber: 2
    )
    var configs = try makeConfigs()
    configs.client.deadlines.rekeyPrepare = .seconds(1)
    configs.client.deadlines.rekeyCompletion = .seconds(1)
    let clientConfig = configs.client
    let serverConfig = configs.server
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)
    let clientStream = try await clientSession.openStream(kind: "rekey-write-barrier")
    let serverStream = try await serverSession.acceptStream().stream

    await blocker.enable(afterSuccessfulWrites: 0)
    let firstRekey = Task { try await clientSession.rekey() }
    await blocker.waitUntilBlocked()
    let dataProbe = CompletionProbe()
    let writing = Task {
      _ = try await clientStream.write(Data("after-data-rekey".utf8))
      await dataProbe.finish()
    }
    try await Task.sleep(for: .milliseconds(20))
    let dataCompletedWhileRekeyBlocked = await dataProbe.completed
    XCTAssertFalse(dataCompletedWhileRekeyBlocked)
    await blocker.release()
    try await firstRekey.value
    try await writing.value
    let received = try await serverStream.read(maxBytes: 64)
    XCTAssertEqual(received, Data("after-data-rekey".utf8))

    await blocker.enable(afterSuccessfulWrites: 0)
    let secondRekey = Task { try await clientSession.rekey() }
    await blocker.waitUntilBlocked()
    let finProbe = CompletionProbe()
    let finishing = Task {
      try await clientStream.closeWrite()
      await finProbe.finish()
    }
    try await Task.sleep(for: .milliseconds(20))
    let finCompletedWhileRekeyBlocked = await finProbe.completed
    XCTAssertFalse(finCompletedWhileRekeyBlocked)
    await blocker.release()
    try await secondRekey.value
    try await finishing.value
    let afterFIN = try await serverStream.read(maxBytes: 1)
    XCTAssertNil(afterFIN)

    await clientSession.close()
    await serverSession.close()
  }

  func testEstablishAppliesInternalDeadline() async throws {
    var config = try makeConfigs().client
    config.deadlines.establish = .milliseconds(20)
    let started = ContinuousClock.now
    do {
      _ = try await TransportV2Session.establish(
        carrier: StallingCarrierSession(),
        config: config
      )
      XCTFail("establish unexpectedly succeeded")
    } catch let error as TransportV2SessionError {
      XCTAssertEqual(error, .handshakeFailed)
    }
    XCTAssertLessThan(started.duration(to: ContinuousClock.now), .seconds(1))
  }

  func testSignedIdleTimeoutSendsGoAwayThenClosesInactiveSession() async throws {
    var configs = try makeConfigs(clientIdleTimeoutSeconds: 1)
    configs.client.deadlines.idleOverride = .milliseconds(30)
    configs.client.deadlines.closeFlush = .milliseconds(30)
    let clientConfig = configs.client
    let serverConfig = configs.server
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair(kind: .rawQUIC)
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    let acceptProbe = SessionOperationProbe()
    let accepting = Task {
      do {
        _ = try await serverSession.acceptStream()
        await acceptProbe.record(.succeeded)
      } catch let error as TransportV2SessionError {
        await acceptProbe.record(.sessionError(error))
      } catch is CancellationError {
        await acceptProbe.record(.cancelled)
      } catch {
        await acceptProbe.record(.failed)
      }
    }
    let queued = await waitUntil {
      await serverSession.incomingWaiterCountForTesting() == 1
    }
    XCTAssertTrue(queued)
    let closed = await waitUntil(timeout: .milliseconds(500)) {
      await acceptProbe.outcome != .pending
    }
    XCTAssertTrue(closed)
    let acceptOutcome = await acceptProbe.outcome
    XCTAssertEqual(acceptOutcome, .sessionError(.closed))
    let goAway = await serverSession.goAwayStateForTesting()
    XCTAssertEqual(goAway.receivedLastAccepted, 0)
    do {
      _ = try await clientSession.openStream(kind: "after-idle")
      XCTFail("idle-closed session accepted a new stream")
    } catch let error as TransportV2SessionError {
      XCTAssertEqual(error, .closed)
    }
    _ = await accepting.result
    await clientSession.close()
    await serverSession.close()
  }

  func testSignedZeroIdleTimeoutDisablesWatchdog() async throws {
    var configs = try makeConfigs()
    configs.client.deadlines.idleOverride = .milliseconds(20)
    configs.server.deadlines.idleOverride = .milliseconds(20)
    let clientConfig = configs.client
    let serverConfig = configs.server
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    try await Task.sleep(for: .milliseconds(70))
    _ = try await clientSession.probeLiveness()
    await clientSession.close()
    await serverSession.close()
  }

  func testSuccessfulStreamActivityResetsSignedIdleWatchdog() async throws {
    var configs = try makeConfigs(clientIdleTimeoutSeconds: 1, serverIdleTimeoutSeconds: 1)
    configs.client.deadlines.idleOverride = .milliseconds(80)
    configs.server.deadlines.idleOverride = .milliseconds(80)
    let clientConfig = configs.client
    let serverConfig = configs.server
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair(kind: .webTransport)
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)
    let clientStream = try await clientSession.openStream(kind: "idle-activity")
    let serverStream = try await serverSession.acceptStream().stream

    for byte in UInt8(1)...UInt8(4) {
      try await Task.sleep(for: .milliseconds(40))
      _ = try await clientStream.write(Data([byte]))
      let received = try await serverStream.read(maxBytes: 1)
      XCTAssertEqual(received, Data([byte]))
    }
    _ = try await clientSession.probeLiveness()
    await clientSession.close()
    await serverSession.close()
  }

  func testCloseIsBoundedAndRejectsOperationsWhileSessionCloseWriteIsStalled() async throws {
    let blocker = SwitchableWriteBlocker()
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair(kind: .rawQUIC)
    let clientCarrier = StallableWriteCarrierSession(
      base: clientBase,
      blocker: blocker,
      blockOpenStreamNumber: 1
    )
    var configs = try makeConfigs()
    configs.client.deadlines.closeFlush = .milliseconds(40)
    let clientConfig = configs.client
    let serverConfig = configs.server
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    let acceptProbe = SessionOperationProbe()
    let accepting = Task {
      do {
        _ = try await clientSession.acceptStream()
        await acceptProbe.record(.succeeded)
      } catch let error as TransportV2SessionError {
        await acceptProbe.record(.sessionError(error))
      } catch is CancellationError {
        await acceptProbe.record(.cancelled)
      } catch {
        await acceptProbe.record(.failed)
      }
    }
    let queued = await waitUntil {
      await clientSession.incomingWaiterCountForTesting() == 1
    }
    XCTAssertTrue(queued)

    await blocker.enable(afterSuccessfulWrites: 1)
    let closeProbe = CompletionProbe()
    let closing = Task {
      await clientSession.close()
      await closeProbe.finish()
    }
    await blocker.waitUntilBlocked()

    let acceptReleased = await waitUntil(timeout: .milliseconds(20)) {
      await acceptProbe.outcome != .pending
    }
    XCTAssertTrue(acceptReleased)
    let acceptOutcome = await acceptProbe.outcome
    XCTAssertEqual(acceptOutcome, .sessionError(.closed))
    do {
      _ = try await clientSession.openStream(kind: "during-close")
      XCTFail("closing session accepted a new stream")
    } catch let error as TransportV2SessionError {
      XCTAssertEqual(error, .closed)
    }
    let bounded = await waitUntil(timeout: .milliseconds(300)) { await closeProbe.completed }
    XCTAssertTrue(bounded)
    let peerGoAway = await serverSession.goAwayStateForTesting()
    XCTAssertEqual(peerGoAway.receivedLastAccepted, 0)

    await blocker.release()
    _ = await accepting.result
    _ = await closing.result
    await serverSession.close()
  }

  func testCloseDeadlineAlsoBoundsHangingCarrierClose() async throws {
    let closeGate = HangingCloseGate()
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair(kind: .rawQUIC)
    let clientCarrier = HangingCloseCarrierSession(base: clientBase, gate: closeGate)
    var configs = try makeConfigs()
    configs.client.deadlines.closeFlush = .milliseconds(30)
    let clientConfig = configs.client
    let serverConfig = configs.server
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    let closeProbe = CompletionProbe()
    let closing = Task {
      await clientSession.close()
      await closeProbe.finish()
    }
    await closeGate.waitUntilEntered()
    let bounded = await waitUntil(timeout: .milliseconds(300)) { await closeProbe.completed }
    XCTAssertTrue(bounded)
    let closeWorkStillActive = await closeGate.active
    XCTAssertFalse(closeWorkStillActive)

    await closeGate.release()
    _ = await closing.result
    await serverSession.close()
  }

  func testProbeLivenessCancellationRemovesWaiterAndPreservesSession() async throws {
    let blocker = SwitchableWriteBlocker()
    let (clientCarrier, serverBase) = MemoryCarrierSession.pair()
    let serverCarrier = StallableWriteCarrierSession(
      base: serverBase,
      blocker: blocker,
      blockAcceptedStreamNumber: 1
    )
    let configs = try makeConfigs()
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    await blocker.enable(afterSuccessfulWrites: 0)
    let probing = Task { try await clientSession.probeLiveness() }
    await blocker.waitUntilBlocked()
    probing.cancel()
    do {
      _ = try await probing.value
      XCTFail("cancelled liveness probe unexpectedly succeeded")
    } catch is CancellationError {
    }
    let waiterCountAfterCancellation = await clientSession.lifecycleWaiterCountsForTesting().pings
    XCTAssertEqual(waiterCountAfterCancellation, 0)

    await blocker.release()
    _ = try await clientSession.probeLiveness()
    await clientSession.close()
    await serverSession.close()
  }

  func testProbeLivenessFailsWhenPONGMissesDeadline() async throws {
    let blocker = SwitchableWriteBlocker()
    let (clientCarrier, serverBase) = MemoryCarrierSession.pair()
    let serverCarrier = StallableWriteCarrierSession(
      base: serverBase,
      blocker: blocker,
      blockAcceptedStreamNumber: 1
    )
    var configs = try makeConfigs()
    configs.client.deadlines.liveness = .milliseconds(25)
    let clientConfig = configs.client
    let serverConfig = configs.server
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    await blocker.enable(afterSuccessfulWrites: 0)
    let started = ContinuousClock.now
    do {
      _ = try await clientSession.probeLiveness()
      XCTFail("liveness probe unexpectedly succeeded without PONG")
    } catch let error as TransportV2SessionError {
      XCTAssertEqual(error, .livenessFailed)
    }
    XCTAssertLessThan(started.duration(to: ContinuousClock.now), .milliseconds(300))
    let waiterCountAfterTimeout = await clientSession.lifecycleWaiterCountsForTesting().pings
    XCTAssertEqual(waiterCountAfterTimeout, 0)

    await blocker.release()
    _ = try await clientSession.probeLiveness()
    await clientSession.close()
    await serverSession.close()
  }

  func testCancellingQueuedRekeyRemovesOnlyThatCaller() async throws {
    let gate = FirstReadGate()
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair()
    let clientCarrier = FirstReadBlockingCarrierSession(
      base: clientBase,
      gate: gate,
      blockAcceptedStreamNumber: 1
    )
    var configs = try makeConfigs()
    configs.client.deadlines.rekeyPrepare = .seconds(1)
    let clientConfig = configs.client
    let serverConfig = configs.server
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    let opening = Task { try await serverSession.openStream(kind: "queued-rekey-cancel") }
    await gate.waitUntilBlocked()
    let firstRekey = Task { try await clientSession.rekey() }
    let freezeQueued = await waitUntil {
      await clientSession.lifecycleWaiterCountsForTesting().inboundResponders == 1
    }
    XCTAssertTrue(freezeQueued)
    let cancelledRekey = Task { try await clientSession.rekey() }
    let rekeyQueued = await waitUntil {
      await clientSession.lifecycleWaiterCountsForTesting().rekeyGate == 1
    }
    XCTAssertTrue(rekeyQueued)
    cancelledRekey.cancel()
    do {
      try await cancelledRekey.value
      XCTFail("cancelled queued rekey unexpectedly succeeded")
    } catch is CancellationError {
    }
    let rekeyWaiterCount = await clientSession.lifecycleWaiterCountsForTesting().rekeyGate
    XCTAssertEqual(rekeyWaiterCount, 0)

    await gate.release()
    let incoming = try await clientSession.acceptStream()
    let outgoing = try await opening.value
    try await firstRekey.value
    let sendEpoch = await clientSession.sendEpochForTesting()
    XCTAssertEqual(sendEpoch, 1)
    _ = try await outgoing.write(Data([1]))
    let received = try await incoming.stream.read(maxBytes: 1)
    XCTAssertEqual(received, Data([1]))
    await clientSession.close()
    await serverSession.close()
  }

  func testCancellingRekeyWaitingForActiveOpenReleasesRekeyGate() async throws {
    let gate = BlockingWriteGate()
    let (clientCarrier, serverBase) = MemoryCarrierSession.pair()
    let serverCarrier = BlockingCarrierSession(
      base: serverBase,
      gate: gate,
      blockAcceptedStreamNumber: 2
    )
    var configs = try makeConfigs()
    configs.client.deadlines.rekeyPrepare = .seconds(1)
    let clientConfig = configs.client
    let serverConfig = configs.server
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    let opening = Task { try await clientSession.openStream(kind: "active-open-cancel") }
    await gate.waitUntilBlocked()
    let rekeying = Task { try await clientSession.rekey() }
    let waiting = await waitUntil {
      await clientSession.lifecycleWaiterCountsForTesting().activeOpen == 1
    }
    XCTAssertTrue(waiting)
    rekeying.cancel()
    do {
      try await rekeying.value
      XCTFail("cancelled active-open rekey unexpectedly succeeded")
    } catch is CancellationError {
    }
    let waiterCounts = await clientSession.lifecycleWaiterCountsForTesting()
    XCTAssertEqual(waiterCounts.activeOpen, 0)
    XCTAssertFalse(waiterCounts.rekeyInProgress)

    await gate.release()
    let outgoing = try await opening.value
    let incoming = try await serverSession.acceptStream()
    try await clientSession.rekey()
    _ = try await outgoing.write(Data([2]))
    let received = try await incoming.stream.read(maxBytes: 1)
    XCTAssertEqual(received, Data([2]))
    await clientSession.close()
    await serverSession.close()
  }

  func testCancellingResponderFreezeUnfreezesInboundOpen() async throws {
    let gate = FirstReadGate()
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair()
    let clientCarrier = FirstReadBlockingCarrierSession(
      base: clientBase,
      gate: gate,
      blockAcceptedStreamNumber: 1
    )
    var configs = try makeConfigs()
    configs.client.deadlines.rekeyPrepare = .seconds(1)
    let clientConfig = configs.client
    let serverConfig = configs.server
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    let opening = Task { try await serverSession.openStream(kind: "freeze-cancel") }
    await gate.waitUntilBlocked()
    let rekeying = Task { try await clientSession.rekey() }
    let waiting = await waitUntil {
      await clientSession.lifecycleWaiterCountsForTesting().inboundResponders == 1
    }
    XCTAssertTrue(waiting)
    rekeying.cancel()
    do {
      try await rekeying.value
      XCTFail("cancelled responder freeze unexpectedly succeeded")
    } catch is CancellationError {
    }
    let waiterCounts = await clientSession.lifecycleWaiterCountsForTesting()
    XCTAssertEqual(waiterCounts.inboundResponders, 0)
    XCTAssertFalse(waiterCounts.localRespondersFrozen)

    await gate.release()
    let incoming = try await clientSession.acceptStream()
    let outgoing = try await opening.value
    _ = try await outgoing.write(Data([3]))
    let received = try await incoming.stream.read(maxBytes: 1)
    XCTAssertEqual(received, Data([3]))
    await clientSession.close()
    await serverSession.close()
  }

  func testRekeyPrepareTimeoutUnfreezesAndLeavesSessionRecoverable() async throws {
    let gate = FirstReadGate()
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair()
    let clientCarrier = FirstReadBlockingCarrierSession(
      base: clientBase,
      gate: gate,
      blockAcceptedStreamNumber: 1
    )
    var configs = try makeConfigs()
    configs.client.deadlines.rekeyPrepare = .milliseconds(25)
    let clientConfig = configs.client
    let serverConfig = configs.server
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    let opening = Task { try await serverSession.openStream(kind: "prepare-timeout") }
    await gate.waitUntilBlocked()
    let prepareProbe = SessionOperationProbe()
    let timedRekey = Task {
      do {
        try await clientSession.rekey()
        await prepareProbe.record(.succeeded)
      } catch let error as TransportV2SessionError {
        await prepareProbe.record(.sessionError(error))
      } catch is CancellationError {
        await prepareProbe.record(.cancelled)
      } catch {
        await prepareProbe.record(.failed)
      }
    }
    let prepareFinished = await waitUntil(timeout: .milliseconds(300)) {
      await prepareProbe.outcome != .pending
    }
    guard prepareFinished else {
      timedRekey.cancel()
      await gate.release()
      _ = await timedRekey.result
      opening.cancel()
      _ = await opening.result
      XCTFail("rekey prepare deadline did not release the caller")
      await clientSession.close()
      await serverSession.close()
      return
    }
    let prepareOutcome = await prepareProbe.outcome
    XCTAssertEqual(prepareOutcome, .sessionError(.rekeyFailed))
    _ = await timedRekey.result
    let waiterCounts = await clientSession.lifecycleWaiterCountsForTesting()
    XCTAssertEqual(waiterCounts.inboundResponders, 0)
    XCTAssertFalse(waiterCounts.localRespondersFrozen)
    XCTAssertFalse(waiterCounts.rekeyInProgress)

    await gate.release()
    let incoming = try await clientSession.acceptStream()
    let outgoing = try await opening.value
    _ = try await outgoing.write(Data([4]))
    let received = try await incoming.stream.read(maxBytes: 1)
    XCTAssertEqual(received, Data([4]))
    let laterRekeyProbe = SessionOperationProbe()
    let laterRekey = Task {
      do {
        try await clientSession.rekey()
        await laterRekeyProbe.record(.succeeded)
      } catch let error as TransportV2SessionError {
        await laterRekeyProbe.record(.sessionError(error))
      } catch is CancellationError {
        await laterRekeyProbe.record(.cancelled)
      } catch {
        await laterRekeyProbe.record(.failed)
      }
    }
    let laterRekeyFinished = await waitUntil {
      await laterRekeyProbe.outcome != .pending
    }
    XCTAssertTrue(laterRekeyFinished)
    let laterRekeyOutcome = await laterRekeyProbe.outcome
    XCTAssertEqual(laterRekeyOutcome, .succeeded)
    if !laterRekeyFinished { laterRekey.cancel() }
    _ = await laterRekey.result
    await clientSession.close()
    await serverSession.close()
  }

  func testAcceptStreamCancellationAtomicallyRemovesOnlyCancelledWaiters() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    let probes = (0..<256).map { _ in SessionOperationProbe() }
    let waiters = probes.map { probe in
      Task {
        do {
          _ = try await serverSession.acceptStream()
          await probe.record(.succeeded)
        } catch is CancellationError {
          await probe.record(.cancelled)
        } catch let error as TransportV2SessionError {
          await probe.record(.sessionError(error))
        } catch {
          await probe.record(.failed)
        }
      }
    }
    let allQueued = await waitUntil {
      await serverSession.incomingWaiterCountForTesting() == waiters.count
    }
    XCTAssertTrue(allQueued)
    for waiter in waiters { waiter.cancel() }
    let allRemoved = await waitUntil(timeout: .seconds(1)) {
      await serverSession.incomingWaiterCountForTesting() == 0
    }
    XCTAssertTrue(allRemoved)
    for waiter in waiters { _ = await waiter.result }
    for probe in probes {
      let outcome = await probe.outcome
      XCTAssertEqual(outcome, .cancelled)
    }

    let stream = try await clientSession.openStream(kind: "after-cancelled-accepts")
    let incoming = try await serverSession.acceptStream()
    XCTAssertEqual(stream.kind, incoming.kind)
    await clientSession.close()
    await serverSession.close()
  }

  func testSessionEngineIsCarrierNeutral() async throws {
    for kind in [CarrierKind.webSocket, .rawQUIC, .webTransport] {
      let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair(kind: kind)
      let configs = try makeConfigs()
      async let server = TransportV2Session.establish(
        carrier: serverCarrier, config: configs.server)
      async let client = TransportV2Session.establish(
        carrier: clientCarrier, config: configs.client)
      let (clientSession, serverSession) = try await (client, server)
      await clientSession.close()
      await serverSession.close()
    }
  }

  func testSimultaneousRekeyAdvancesBothActiveDirections() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)
    let clientStream = try await clientSession.openStream(kind: "simultaneous-rekey")
    let serverStream = try await serverSession.acceptStream().stream

    async let clientRekey: Void = clientSession.rekey()
    async let serverRekey: Void = serverSession.rekey()
    _ = try await (clientRekey, serverRekey)

    _ = try await clientStream.write(Data("client".utf8))
    _ = try await serverStream.write(Data("server".utf8))
    let fromClient = try await serverStream.read(maxBytes: 16)
    let fromServer = try await clientStream.read(maxBytes: 16)
    XCTAssertEqual(fromClient, Data("client".utf8))
    XCTAssertEqual(fromServer, Data("server".utf8))
    await clientSession.close()
    await serverSession.close()
  }

  func testFailedCarrierOpenCommitsResetBeforeRekeyWatermark() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let failOnce = FailSecondOpenCarrierSession(base: clientCarrier)
    let configs = try makeConfigs()
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV2Session.establish(carrier: failOnce, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    do {
      _ = try await clientSession.openStream(kind: "fails-before-fss2")
      XCTFail("open unexpectedly succeeded")
    } catch is CarrierOpenFailure {
    }
    try await clientSession.rekey()
    let stream = try await clientSession.openStream(kind: "after-reset")
    let incoming = try await serverSession.acceptStream()
    XCTAssertEqual(stream.kind, incoming.kind)
    await clientSession.close()
    await serverSession.close()
  }

  func testStreamLedgerTracksAbandonedLateSetupAndTerminalStates() throws {
    var ledger = TransportV2StreamLedger(openerRole: .client)
    try ledger.peerReset(3)
    XCTAssertEqual(ledger.state(of: 3), .abandonedNoFSS2)
    XCTAssertEqual(ledger.frontier, 0)

    try ledger.validFSS2(1)
    XCTAssertEqual(ledger.state(of: 1), .openSeen)
    try ledger.validOpen(1)
    XCTAssertEqual(ledger.frontier, 3)

    XCTAssertEqual(try ledger.validFSS2ForAbandoned(3), .reset)
    XCTAssertEqual(ledger.state(of: 3), .usedOrTerminal)
    XCTAssertThrowsError(try ledger.validFSS2ForAbandoned(3))
    XCTAssertThrowsError(try ledger.validFSS2(1))
  }

  func testStreamKeyUpdateACKUsesLogicalIDTransitionEpochOrder() throws {
    let vectors: SessionWireVectors = try readSessionWireVectors()
    let vector = try XCTUnwrap(vectors.streamKeyUpdateACK.first)
    let payload = StreamKeyUpdateACKPayloadV2(
      logicalStreamID: try XCTUnwrap(UInt64(vector.logicalIDHex, radix: 16)),
      transition: try XCTUnwrap(UInt64(vector.transitionIDHex, radix: 16)),
      epoch: try XCTUnwrap(UInt32(vector.nextEpochHex, radix: 16))
    )
    XCTAssertEqual(payload.encoded(), try decodeHex(vector.payloadHex))
    XCTAssertEqual(try StreamKeyUpdateACKPayloadV2(encoded: payload.encoded()), payload)
  }

  func testIdenticalRekeyACKIsIdempotentButDifferentACKIsRejected() throws {
    let expected = StreamKeyUpdateACKPayloadV2(
      logicalStreamID: 1,
      transition: 7,
      epoch: 3
    )
    XCTAssertEqual(
      try classifyRekeyACKV2(received: expected, pending: expected, lastAccepted: nil),
      .accepted
    )
    XCTAssertEqual(
      try classifyRekeyACKV2(received: expected, pending: nil, lastAccepted: expected),
      .duplicate
    )
    XCTAssertThrowsError(
      try classifyRekeyACKV2(
        received: StreamKeyUpdateACKPayloadV2(
          logicalStreamID: 1,
          transition: 8,
          epoch: 4
        ),
        pending: nil,
        lastAccepted: expected
      )
    )
  }

  func testGoAwayUsesResolvedBoundaryAndRejectsNewOpen() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    _ = try await clientSession.openStream(kind: "before-goaway")
    _ = try await serverSession.acceptStream()
    try await serverSession.sendGoAway(reason: 2)
    try await Task.sleep(for: .milliseconds(20))

    do {
      _ = try await clientSession.openStream(kind: "after-goaway")
      XCTFail("open unexpectedly passed GOAWAY")
    } catch let error as TransportV2SessionError {
      XCTAssertEqual(error, .goingAway)
    }
    let serverState = await serverSession.goAwayStateForTesting()
    let clientState = await clientSession.goAwayStateForTesting()
    XCTAssertEqual(serverState.sentLastAccepted, 1)
    XCTAssertEqual(clientState.receivedLastAccepted, 1)
    await clientSession.close()
    await serverSession.close()
  }

  func testGoAwayRejectsWrongParityFutureAndChangedBoundaries() throws {
    var state = ReceivedGoAwayStateV2()
    XCTAssertThrowsError(
      try state.accept(lastAccepted: 2, reason: 2, localRole: .client, localHighWatermark: 3)
    )
    XCTAssertThrowsError(
      try state.accept(lastAccepted: 5, reason: 2, localRole: .client, localHighWatermark: 3)
    )
    try state.accept(lastAccepted: 3, reason: 2, localRole: .client, localHighWatermark: 3)
    try state.accept(lastAccepted: 3, reason: 2, localRole: .client, localHighWatermark: 3)
    XCTAssertThrowsError(
      try state.accept(lastAccepted: 1, reason: 2, localRole: .client, localHighWatermark: 3)
    )
  }

  func testGoAwayBoundaryCancelsAlreadyAllocatedOpen() async throws {
    let gate = BlockingWriteGate()
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair()
    let clientCarrier = BlockingCarrierSession(
      base: clientBase,
      gate: gate,
      blockOpenStreamNumber: 2
    )
    let configs = try makeConfigs()
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    let opening = Task { try await clientSession.openStream(kind: "past-goaway") }
    await gate.waitUntilBlocked()
    try await serverSession.sendGoAway(reason: 2)
    try await Task.sleep(for: .milliseconds(20))
    await gate.release()

    do {
      _ = try await opening.value
      XCTFail("allocated open unexpectedly passed GOAWAY")
    } catch let error as TransportV2SessionError {
      XCTAssertEqual(error, .goingAway)
    }
    await clientSession.close()
    await serverSession.close()
  }

  func testOpenCancellationDuringFSS2WriteCommitsResetBeforeRekey() async throws {
    let gate = BlockingWriteGate()
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair()
    let clientCarrier = BlockingCarrierSession(
      base: clientBase,
      gate: gate,
      blockOpenStreamNumber: 2
    )
    let configs = try makeConfigs()
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    let opening = Task { try await clientSession.openStream(kind: "cancel-fss2") }
    await gate.waitUntilBlocked()
    opening.cancel()
    do {
      _ = try await opening.value
      XCTFail("cancelled open unexpectedly succeeded")
    } catch is CancellationError {
    }

    try await clientSession.rekey()
    let stream = try await clientSession.openStream(kind: "after-cancel")
    let incoming = try await serverSession.acceptStream()
    XCTAssertEqual(stream.kind, incoming.kind)
    await clientSession.close()
    await serverSession.close()
  }

  func testLateFSS2AfterCommittedResetIsStreamScoped() async throws {
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair()
    let clientCarrier = LateFSS2CarrierSession(base: clientBase)
    let configs = try makeConfigs()
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    let opening = Task { try await clientSession.openStream(kind: "late-fss2") }
    await clientCarrier.waitUntilFSS2Captured()
    opening.cancel()
    do {
      _ = try await opening.value
      XCTFail("cancelled open unexpectedly succeeded")
    } catch is CancellationError {
    }

    _ = try await clientSession.probeLiveness()
    try await clientCarrier.deliverLateFSS2()
    try await Task.sleep(for: .milliseconds(20))
    _ = try await clientSession.probeLiveness()
    try await clientSession.rekey()

    let stream = try await clientSession.openStream(kind: "after-late-fss2")
    let incoming = try await serverSession.acceptStream()
    XCTAssertEqual(stream.kind, incoming.kind)
    await clientSession.close()
    await serverSession.close()
  }

  func testOpenCancellationWhileWaitingForACKCommitsResetBeforeRekey() async throws {
    let gate = BlockingWriteGate()
    let (clientCarrier, serverBase) = MemoryCarrierSession.pair()
    let serverCarrier = BlockingCarrierSession(
      base: serverBase,
      gate: gate,
      blockAcceptedStreamNumber: 2
    )
    let configs = try makeConfigs()
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    let opening = Task { try await clientSession.openStream(kind: "cancel-ack") }
    await gate.waitUntilBlocked()
    opening.cancel()
    do {
      _ = try await opening.value
      XCTFail("cancelled open unexpectedly succeeded")
    } catch is CancellationError {
    }

    try await clientSession.rekey()
    await gate.release()
    let stream = try await clientSession.openStream(kind: "after-cancel")
    let incoming = try await serverSession.acceptStream()
    XCTAssertEqual(stream.kind, incoming.kind)
    await clientSession.close()
    await serverSession.close()
  }

  func testConsecutiveRekeysRetireObsoleteEpochRoots() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    for _ in 0..<5 { try await clientSession.rekey() }
    let clientCounts = await clientSession.epochRootCountsForTesting()
    let serverCounts = await serverSession.epochRootCountsForTesting()
    XCTAssertEqual(clientCounts.send, 1)
    XCTAssertLessThanOrEqual(serverCounts.receive, 2)

    await clientSession.close()
    await serverSession.close()
    let closedCounts = await clientSession.epochRootCountsForTesting()
    XCTAssertEqual(closedCounts.send, 0)
    XCTAssertEqual(closedCounts.receive, 0)
  }

  func testLocalRekeyWaitsForInFlightInboundOpenResponder() async throws {
    let gate = FirstReadGate()
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair()
    let clientCarrier = FirstReadBlockingCarrierSession(
      base: clientBase,
      gate: gate,
      blockAcceptedStreamNumber: 1
    )
    var configs = try makeConfigs()
    configs.client.deadlines.rekeyPrepare = .seconds(1)
    configs.client.deadlines.rekeyCompletion = .seconds(1)
    configs.server.deadlines.rekeyPrepare = .seconds(1)
    configs.server.deadlines.rekeyCompletion = .seconds(1)
    let clientConfig = configs.client
    let serverConfig = configs.server
    async let server = TransportV2Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV2Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    let opening = Task { try await serverSession.openStream(kind: "concurrent-inbound-open") }
    await gate.waitUntilBlocked()
    let rekeyProbe = CompletionProbe()
    let rekeying = Task {
      try await clientSession.rekey()
      await rekeyProbe.finish()
    }
    try await Task.sleep(for: .milliseconds(20))
    let rekeyCompletedWhileResponderBlocked = await rekeyProbe.completed
    XCTAssertFalse(rekeyCompletedWhileResponderBlocked)

    await gate.release()
    let incoming = try await clientSession.acceptStream()
    let outgoing = try await opening.value
    try await rekeying.value
    _ = try await outgoing.write(Data("after-responder-barrier".utf8))
    let received = try await incoming.stream.read(maxBytes: 64)
    XCTAssertEqual(
      received,
      Data("after-responder-barrier".utf8)
    )
    await clientSession.close()
    await serverSession.close()
  }

  private func makeConfigs(
    maxInboundStreams: UInt16 = 8,
    clientIdleTimeoutSeconds: UInt32 = 0,
    serverIdleTimeoutSeconds: UInt32 = 0
  ) throws -> (
    client: TransportV2SessionConfig, server: TransportV2SessionConfig
  ) {
    let psk = Data((0..<32).map(UInt8.init))
    let contract = Data((32..<64).map(UInt8.init))
    let clientBinding = Data((64..<96).map(UInt8.init))
    let serverBinding = Data((96..<128).map(UInt8.init))
    return (
      TransportV2SessionConfig(
        role: .client,
        path: .direct,
        channelID: "swift-session-test",
        sessionContractHash: contract,
        suite: .chacha20Poly1305,
        psk: psk,
        maxInboundStreams: maxInboundStreams,
        idleTimeoutSeconds: clientIdleTimeoutSeconds,
        localAdmissionBinding: clientBinding,
        peerAdmissionBinding: serverBinding
      ),
      TransportV2SessionConfig(
        role: .server,
        path: .direct,
        channelID: "swift-session-test",
        sessionContractHash: contract,
        suite: .chacha20Poly1305,
        psk: psk,
        maxInboundStreams: maxInboundStreams,
        idleTimeoutSeconds: serverIdleTimeoutSeconds,
        localAdmissionBinding: serverBinding,
        peerAdmissionBinding: clientBinding
      )
    )
  }

  private func readSessionWireVectors() throws -> SessionWireVectors {
    let workingDirectory = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    let relativePath = "testdata/transport_v2/session_wire_vectors.json"
    let candidates = [
      workingDirectory.appendingPathComponent(relativePath),
      workingDirectory.deletingLastPathComponent().appendingPathComponent(relativePath),
    ]
    let url = try XCTUnwrap(candidates.first { FileManager.default.fileExists(atPath: $0.path) })
    return try JSONDecoder().decode(
      SessionWireVectors.self,
      from: Data(contentsOf: url)
    )
  }

  private func decodeHex(_ value: String) throws -> Data {
    guard value.count.isMultiple(of: 2) else {
      throw TransportV2ProtocolStateError.invalidTransition
    }
    var output = Data()
    var index = value.startIndex
    while index < value.endIndex {
      let end = value.index(index, offsetBy: 2)
      guard let byte = UInt8(value[index..<end], radix: 16) else {
        throw TransportV2ProtocolStateError.invalidTransition
      }
      output.append(byte)
      index = end
    }
    return output
  }

  private func waitUntil(
    timeout: Duration = .seconds(1),
    _ condition: @escaping @Sendable () async -> Bool
  ) async -> Bool {
    let deadline = ContinuousClock.now + timeout
    while ContinuousClock.now < deadline {
      if await condition() { return true }
      try? await Task.sleep(for: .milliseconds(1))
    }
    return await condition()
  }
}

private struct SessionWireVectors: Decodable {
  let streamKeyUpdateACK: [StreamKeyUpdateACKVector]

  enum CodingKeys: String, CodingKey {
    case streamKeyUpdateACK = "stream_key_update_ack"
  }
}

private struct StreamKeyUpdateACKVector: Decodable {
  let logicalIDHex: String
  let transitionIDHex: String
  let nextEpochHex: String
  let payloadHex: String

  enum CodingKeys: String, CodingKey {
    case logicalIDHex = "logical_id_hex"
    case transitionIDHex = "transition_id_hex"
    case nextEpochHex = "next_epoch_hex"
    case payloadHex = "payload_hex"
  }
}

private struct SessionEcho: Codable, Equatable, Sendable {
  let value: String
}

private actor SessionOperationProbe {
  enum Outcome: Equatable, Sendable {
    case pending
    case succeeded
    case cancelled
    case sessionError(TransportV2SessionError)
    case failed
  }

  private(set) var outcome: Outcome = .pending

  func record(_ outcome: Outcome) {
    guard self.outcome == .pending else { return }
    self.outcome = outcome
  }
}

private actor CompletionProbe {
  private(set) var completed = false

  func finish() { completed = true }
}

private actor MemoryCarrierSession: TransportV2CarrierSession {
  nonisolated let chosenCarrier: CarrierKind
  nonisolated let inboundBidirectionalStreamCapacity: UInt16
  private let incoming = MemoryCarrierStreamQueue()
  private var peer: MemoryCarrierSession?
  private(set) var openedStreamCount = 0
  private var nextID: UInt64

  init(
    nextID: UInt64,
    chosenCarrier: CarrierKind,
    inboundBidirectionalStreamCapacity: UInt16
  ) {
    self.nextID = nextID
    self.chosenCarrier = chosenCarrier
    self.inboundBidirectionalStreamCapacity = inboundBidirectionalStreamCapacity
  }

  static func pair(
    kind: CarrierKind = .webSocket,
    inboundBidirectionalStreamCapacity: UInt16 = 10
  ) -> (MemoryCarrierSession, MemoryCarrierSession) {
    let client = MemoryCarrierSession(
      nextID: 1,
      chosenCarrier: kind,
      inboundBidirectionalStreamCapacity: inboundBidirectionalStreamCapacity
    )
    let server = MemoryCarrierSession(
      nextID: 2,
      chosenCarrier: kind,
      inboundBidirectionalStreamCapacity: inboundBidirectionalStreamCapacity
    )
    Task {
      await client.setPeer(server)
      await server.setPeer(client)
    }
    return (client, server)
  }

  func openStream() async throws -> any TransportV2CarrierStream {
    while peer == nil { await Task.yield() }
    let id = nextID
    nextID += 2
    openedStreamCount += 1
    let pair = MemoryCarrierStream.pair(id: id)
    await peer?.enqueue(pair.1)
    return pair.0
  }

  func acceptStream() async throws -> any TransportV2CarrierStream {
    try await incoming.next()
  }

  func close(code: UInt16, reason: String) async {
    await incoming.finish()
  }

  nonisolated func abort(code: UInt16, reason: String) {
    Task { await incoming.finish() }
  }

  private func setPeer(_ peer: MemoryCarrierSession) {
    self.peer = peer
  }

  private func enqueue(_ stream: any TransportV2CarrierStream) async {
    await incoming.push(stream)
  }
}

private actor HangingCloseCarrierSession: TransportV2CarrierSession {
  nonisolated let chosenCarrier: CarrierKind
  nonisolated let inboundBidirectionalStreamCapacity: UInt16
  private let base: MemoryCarrierSession
  private let gate: HangingCloseGate

  init(base: MemoryCarrierSession, gate: HangingCloseGate) {
    self.base = base
    self.gate = gate
    chosenCarrier = base.chosenCarrier
    inboundBidirectionalStreamCapacity = base.inboundBidirectionalStreamCapacity
  }

  func openStream() async throws -> any TransportV2CarrierStream {
    try await base.openStream()
  }

  func acceptStream() async throws -> any TransportV2CarrierStream {
    try await base.acceptStream()
  }

  func close(code: UInt16, reason: String) async {
    await gate.enter()
    await base.close(code: code, reason: reason)
  }

  nonisolated func abort(code: UInt16, reason: String) {
    Task { await gate.release() }
    base.abort(code: code, reason: reason)
  }
}

private actor HangingCloseGate {
  private var entered = false
  private var released = false
  private var enterWaiters: [CheckedContinuation<Void, Never>] = []
  private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

  var active: Bool { entered && !released }

  func enter() async {
    entered = true
    let waiters = enterWaiters
    enterWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
    if released { return }
    await withCheckedContinuation { releaseWaiters.append($0) }
  }

  func waitUntilEntered() async {
    if entered { return }
    await withCheckedContinuation { enterWaiters.append($0) }
  }

  func release() {
    released = true
    let waiters = releaseWaiters
    releaseWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
  }
}

private actor StallingCarrierSession: TransportV2CarrierSession {
  nonisolated let chosenCarrier: CarrierKind = .webSocket
  nonisolated let inboundBidirectionalStreamCapacity: UInt16 = 10

  func openStream() async throws -> any TransportV2CarrierStream { StallingCarrierStream() }

  func acceptStream() async throws -> any TransportV2CarrierStream {
    throw CancellationError()
  }

  func close(code: UInt16, reason: String) async {}

  nonisolated func abort(code: UInt16, reason: String) {}
}

private actor FirstReadBlockingCarrierSession: TransportV2CarrierSession {
  nonisolated let chosenCarrier: CarrierKind
  nonisolated let inboundBidirectionalStreamCapacity: UInt16
  private let base: MemoryCarrierSession
  private let gate: FirstReadGate
  private let blockAcceptedStreamNumber: Int
  private var acceptCount = 0

  init(
    base: MemoryCarrierSession,
    gate: FirstReadGate,
    blockAcceptedStreamNumber: Int
  ) {
    self.base = base
    self.gate = gate
    self.blockAcceptedStreamNumber = blockAcceptedStreamNumber
    chosenCarrier = base.chosenCarrier
    inboundBidirectionalStreamCapacity = base.inboundBidirectionalStreamCapacity
  }

  func openStream() async throws -> any TransportV2CarrierStream {
    try await base.openStream()
  }

  func acceptStream() async throws -> any TransportV2CarrierStream {
    acceptCount += 1
    let stream = try await base.acceptStream()
    guard acceptCount == blockAcceptedStreamNumber else { return stream }
    return FirstReadBlockingCarrierStream(base: stream, gate: gate)
  }

  func close(code: UInt16, reason: String) async {
    await base.close(code: code, reason: reason)
  }

  nonisolated func abort(code: UInt16, reason: String) {
    Task { await gate.release() }
    base.abort(code: code, reason: reason)
  }
}

private actor FirstReadBlockingCarrierStream: TransportV2CarrierStream {
  nonisolated let carrierStreamID: UInt64
  private let base: any TransportV2CarrierStream
  private let gate: FirstReadGate
  private var blocked = false

  init(base: any TransportV2CarrierStream, gate: FirstReadGate) {
    self.base = base
    self.gate = gate
    carrierStreamID = base.carrierStreamID
  }

  func read(maxBytes: Int) async throws -> Data? {
    if !blocked {
      blocked = true
      await gate.block()
    }
    return try await base.read(maxBytes: maxBytes)
  }

  func write(_ data: Data) async throws -> Int { try await base.write(data) }
  func closeWrite() async throws { try await base.closeWrite() }

  func reset(code: UInt16) async {
    await gate.release()
    await base.reset(code: code)
  }

  func close() async { await base.close() }

  nonisolated func abort(code: UInt16) {
    Task { await gate.release() }
    base.abort(code: code)
  }
}

private actor FirstReadGate {
  private var entered = false
  private var released = false
  private var blockWaiters: [CheckedContinuation<Void, Never>] = []
  private var enteredWaiters: [CheckedContinuation<Void, Never>] = []

  func block() async {
    entered = true
    let waiters = enteredWaiters
    enteredWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
    if released { return }
    await withCheckedContinuation { blockWaiters.append($0) }
  }

  func waitUntilBlocked() async {
    if entered { return }
    await withCheckedContinuation { enteredWaiters.append($0) }
  }

  func release() {
    guard !released else { return }
    released = true
    let waiters = blockWaiters
    blockWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
  }
}

private actor StallableWriteCarrierSession: TransportV2CarrierSession {
  nonisolated let chosenCarrier: CarrierKind
  nonisolated let inboundBidirectionalStreamCapacity: UInt16
  private let base: MemoryCarrierSession
  private let blocker: SwitchableWriteBlocker
  private let blockOpenStreamNumber: Int?
  private let blockAcceptedStreamNumber: Int?
  private var openCount = 0
  private var acceptCount = 0

  init(
    base: MemoryCarrierSession,
    blocker: SwitchableWriteBlocker,
    blockOpenStreamNumber: Int? = nil,
    blockAcceptedStreamNumber: Int? = nil
  ) {
    self.base = base
    self.blocker = blocker
    self.blockOpenStreamNumber = blockOpenStreamNumber
    self.blockAcceptedStreamNumber = blockAcceptedStreamNumber
    chosenCarrier = base.chosenCarrier
    inboundBidirectionalStreamCapacity = base.inboundBidirectionalStreamCapacity
  }

  func openStream() async throws -> any TransportV2CarrierStream {
    openCount += 1
    let stream = try await base.openStream()
    guard openCount == blockOpenStreamNumber else { return stream }
    return StallableWriteCarrierStream(base: stream, blocker: blocker)
  }

  func acceptStream() async throws -> any TransportV2CarrierStream {
    acceptCount += 1
    let stream = try await base.acceptStream()
    guard acceptCount == blockAcceptedStreamNumber else { return stream }
    return StallableWriteCarrierStream(base: stream, blocker: blocker)
  }

  func close(code: UInt16, reason: String) async {
    await base.close(code: code, reason: reason)
  }

  nonisolated func abort(code: UInt16, reason: String) {
    Task { await blocker.release() }
    base.abort(code: code, reason: reason)
  }
}

private actor StallableWriteCarrierStream: TransportV2CarrierStream {
  nonisolated let carrierStreamID: UInt64
  private let base: any TransportV2CarrierStream
  private let blocker: SwitchableWriteBlocker

  init(base: any TransportV2CarrierStream, blocker: SwitchableWriteBlocker) {
    self.base = base
    self.blocker = blocker
    carrierStreamID = base.carrierStreamID
  }

  func read(maxBytes: Int) async throws -> Data? { try await base.read(maxBytes: maxBytes) }

  func write(_ data: Data) async throws -> Int {
    await blocker.beforeWrite()
    return try await base.write(data)
  }

  func closeWrite() async throws { try await base.closeWrite() }
  func reset(code: UInt16) async { await base.reset(code: code) }
  func close() async { await base.close() }

  nonisolated func abort(code: UInt16) {
    Task { await blocker.release() }
    base.abort(code: code)
  }
}

private actor SwitchableWriteBlocker {
  private var remainingSuccessfulWrites: Int?
  private var blocked = false
  private var released = false
  private var blockWaiters: [CheckedContinuation<Void, Never>] = []
  private var enteredWaiters: [CheckedContinuation<Void, Never>] = []

  func enable(afterSuccessfulWrites: Int) {
    released = false
    blocked = false
    remainingSuccessfulWrites = afterSuccessfulWrites
  }

  func beforeWrite() async {
    guard !released, let remainingSuccessfulWrites else { return }
    if remainingSuccessfulWrites > 0 {
      self.remainingSuccessfulWrites = remainingSuccessfulWrites - 1
      return
    }
    blocked = true
    let waiters = enteredWaiters
    enteredWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
    await withCheckedContinuation { blockWaiters.append($0) }
  }

  func waitUntilBlocked() async {
    if blocked { return }
    await withCheckedContinuation { enteredWaiters.append($0) }
  }

  func release() {
    released = true
    blocked = false
    remainingSuccessfulWrites = nil
    let waiters = blockWaiters
    blockWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
  }
}

private struct CarrierOpenFailure: Error {}

private actor FailSecondOpenCarrierSession: TransportV2CarrierSession {
  nonisolated let chosenCarrier: CarrierKind
  nonisolated let inboundBidirectionalStreamCapacity: UInt16
  private let base: MemoryCarrierSession
  private var openCount = 0

  init(base: MemoryCarrierSession) {
    self.base = base
    chosenCarrier = base.chosenCarrier
    inboundBidirectionalStreamCapacity = base.inboundBidirectionalStreamCapacity
  }

  func openStream() async throws -> any TransportV2CarrierStream {
    openCount += 1
    if openCount == 2 { throw CarrierOpenFailure() }
    return try await base.openStream()
  }

  func acceptStream() async throws -> any TransportV2CarrierStream {
    try await base.acceptStream()
  }

  func close(code: UInt16, reason: String) async {
    await base.close(code: code, reason: reason)
  }

  nonisolated func abort(code: UInt16, reason: String) {
    base.abort(code: code, reason: reason)
  }
}

private actor BlockingCarrierSession: TransportV2CarrierSession {
  nonisolated let chosenCarrier: CarrierKind
  nonisolated let inboundBidirectionalStreamCapacity: UInt16
  private let base: MemoryCarrierSession
  private let gate: BlockingWriteGate
  private let blockOpenStreamNumber: Int?
  private let blockAcceptedStreamNumber: Int?
  private var openCount = 0
  private var acceptCount = 0

  init(
    base: MemoryCarrierSession,
    gate: BlockingWriteGate,
    blockOpenStreamNumber: Int? = nil,
    blockAcceptedStreamNumber: Int? = nil
  ) {
    self.base = base
    self.gate = gate
    self.blockOpenStreamNumber = blockOpenStreamNumber
    self.blockAcceptedStreamNumber = blockAcceptedStreamNumber
    chosenCarrier = base.chosenCarrier
    inboundBidirectionalStreamCapacity = base.inboundBidirectionalStreamCapacity
  }

  func openStream() async throws -> any TransportV2CarrierStream {
    openCount += 1
    let stream = try await base.openStream()
    if openCount == blockOpenStreamNumber {
      return BlockingWriteCarrierStream(base: stream, gate: gate)
    }
    return stream
  }

  func acceptStream() async throws -> any TransportV2CarrierStream {
    acceptCount += 1
    let stream = try await base.acceptStream()
    if acceptCount == blockAcceptedStreamNumber {
      return BlockingWriteCarrierStream(base: stream, gate: gate)
    }
    return stream
  }

  func close(code: UInt16, reason: String) async {
    await base.close(code: code, reason: reason)
  }

  nonisolated func abort(code: UInt16, reason: String) {
    Task { await gate.cancel() }
    base.abort(code: code, reason: reason)
  }
}

private struct LateFSS2WriteError: Error {}

private actor LateFSS2CarrierSession: TransportV2CarrierSession {
  nonisolated let chosenCarrier: CarrierKind
  nonisolated let inboundBidirectionalStreamCapacity: UInt16
  private let base: MemoryCarrierSession
  private var openCount = 0
  private var lateStream: LateFSS2CarrierStream?

  init(base: MemoryCarrierSession) {
    self.base = base
    chosenCarrier = base.chosenCarrier
    inboundBidirectionalStreamCapacity = base.inboundBidirectionalStreamCapacity
  }

  func openStream() async throws -> any TransportV2CarrierStream {
    openCount += 1
    let stream = try await base.openStream()
    guard openCount == 2 else { return stream }
    let late = LateFSS2CarrierStream(base: stream)
    lateStream = late
    return late
  }

  func acceptStream() async throws -> any TransportV2CarrierStream {
    try await base.acceptStream()
  }

  func close(code: UInt16, reason: String) async {
    await base.close(code: code, reason: reason)
  }

  nonisolated func abort(code: UInt16, reason: String) {
    base.abort(code: code, reason: reason)
  }

  func waitUntilFSS2Captured() async {
    while lateStream == nil { await Task.yield() }
    await lateStream?.waitUntilCaptured()
  }

  func deliverLateFSS2() async throws {
    guard let lateStream else { throw LateFSS2WriteError() }
    try await lateStream.deliverCaptured()
  }
}

private actor LateFSS2CarrierStream: TransportV2CarrierStream {
  nonisolated let carrierStreamID: UInt64
  private let base: any TransportV2CarrierStream
  private var captured: Data?
  private var writeWaiter: CheckedContinuation<Int, Error>?
  private var capturedWaiters: [CheckedContinuation<Void, Never>] = []
  private var delivered = false

  init(base: any TransportV2CarrierStream) {
    self.base = base
    carrierStreamID = base.carrierStreamID
  }

  func read(maxBytes: Int) async throws -> Data? { try await base.read(maxBytes: maxBytes) }

  func write(_ data: Data) async throws -> Int {
    guard captured == nil else { return try await base.write(data) }
    captured = data
    let waiters = capturedWaiters
    capturedWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
    return try await withCheckedThrowingContinuation { writeWaiter = $0 }
  }

  func closeWrite() async throws { try await base.closeWrite() }

  func reset(code: UInt16) async {
    if let writeWaiter {
      self.writeWaiter = nil
      writeWaiter.resume(throwing: LateFSS2WriteError())
    } else if delivered {
      await base.reset(code: code)
    }
  }

  func close() async { await base.close() }

  nonisolated func abort(code: UInt16) {
    Task { await self.reset(code: code) }
    base.abort(code: code)
  }

  func waitUntilCaptured() async {
    if captured != nil { return }
    await withCheckedContinuation { capturedWaiters.append($0) }
  }

  func deliverCaptured() async throws {
    guard let captured, !delivered else { throw LateFSS2WriteError() }
    delivered = true
    _ = try await base.write(captured)
  }
}

private actor BlockingWriteCarrierStream: TransportV2CarrierStream {
  nonisolated let carrierStreamID: UInt64
  private let base: any TransportV2CarrierStream
  private let gate: BlockingWriteGate
  private var blocked = false

  init(base: any TransportV2CarrierStream, gate: BlockingWriteGate) {
    self.base = base
    self.gate = gate
    carrierStreamID = base.carrierStreamID
  }

  func read(maxBytes: Int) async throws -> Data? { try await base.read(maxBytes: maxBytes) }

  func write(_ data: Data) async throws -> Int {
    if !blocked {
      blocked = true
      try await gate.block()
    }
    return try await base.write(data)
  }

  func closeWrite() async throws { try await base.closeWrite() }

  func reset(code: UInt16) async {
    await gate.cancel()
    await base.reset(code: code)
  }

  func close() async { await base.close() }

  nonisolated func abort(code: UInt16) {
    Task { await gate.cancel() }
    base.abort(code: code)
  }
}

private actor BlockingWriteGate {
  private var entered = false
  private var result: Result<Void, Error>?
  private var blockWaiters: [CheckedContinuation<Void, Error>] = []
  private var enteredWaiters: [CheckedContinuation<Void, Never>] = []

  func block() async throws {
    entered = true
    let waiters = enteredWaiters
    enteredWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
    if let result { return try result.get() }
    return try await withCheckedThrowingContinuation { blockWaiters.append($0) }
  }

  func waitUntilBlocked() async {
    if entered { return }
    await withCheckedContinuation { enteredWaiters.append($0) }
  }

  func release() { finish(.success(())) }
  func cancel() { finish(.failure(CancellationError())) }

  private func finish(_ result: Result<Void, Error>) {
    guard self.result == nil else { return }
    self.result = result
    let waiters = blockWaiters
    blockWaiters.removeAll()
    for waiter in waiters { waiter.resume(with: result) }
  }
}

private actor StallingCarrierStream: TransportV2CarrierStream {
  nonisolated let carrierStreamID: UInt64 = 1

  func read(maxBytes: Int) async throws -> Data? {
    try await Task.sleep(for: .seconds(60))
    return nil
  }

  func write(_ data: Data) async throws -> Int { data.count }
  func closeWrite() async throws {}
  func reset(code: UInt16) async {}
  nonisolated func abort(code: UInt16) {}
  func close() async {}
}

private actor MemoryCarrierStream: TransportV2CarrierStream {
  nonisolated let carrierStreamID: UInt64
  private let incoming = MemoryByteQueue()
  private var peer: MemoryCarrierStream?
  private var buffered = Data()
  private var ended = false

  init(id: UInt64) {
    carrierStreamID = id
  }

  static func pair(id: UInt64) -> (MemoryCarrierStream, MemoryCarrierStream) {
    let left = MemoryCarrierStream(id: id)
    let right = MemoryCarrierStream(id: id)
    Task {
      await left.setPeer(right)
      await right.setPeer(left)
    }
    return (left, right)
  }

  func read(maxBytes: Int) async throws -> Data? {
    while buffered.isEmpty && !ended {
      guard let value = try await incoming.next() else {
        ended = true
        break
      }
      buffered.append(value)
    }
    guard !buffered.isEmpty else { return nil }
    let count = min(maxBytes, buffered.count)
    let result = Data(buffered.prefix(count))
    buffered.removeFirst(count)
    return result
  }

  func write(_ data: Data) async throws -> Int {
    while peer == nil { await Task.yield() }
    await peer?.enqueue(data)
    return data.count
  }

  func closeWrite() async throws {
    while peer == nil { await Task.yield() }
    await peer?.finishWrite()
  }

  func reset(code: UInt16) async {
    await incoming.fail(FlowersecStreamResetError(path: .direct))
    await peer?.finishReset()
  }

  func close() async {
    await incoming.finish()
  }

  nonisolated func abort(code: UInt16) {
    Task {
      await incoming.fail(FlowersecStreamResetError(path: .direct))
      await peer?.finishReset()
    }
  }

  private func setPeer(_ peer: MemoryCarrierStream) { self.peer = peer }
  private func enqueue(_ data: Data) async { await incoming.push(data) }
  private func finishWrite() async { await incoming.finish() }
  private func finishReset() async {
    await incoming.fail(FlowersecStreamResetError(path: .direct))
  }
}

private actor MemoryCarrierStreamQueue {
  private var values: [any TransportV2CarrierStream] = []
  private var waiters: [CheckedContinuation<any TransportV2CarrierStream, Error>] = []
  private var closed = false

  func push(_ value: any TransportV2CarrierStream) {
    if !waiters.isEmpty {
      waiters.removeFirst().resume(returning: value)
    } else if !closed {
      values.append(value)
    }
  }

  func next() async throws -> any TransportV2CarrierStream {
    if !values.isEmpty { return values.removeFirst() }
    if closed { throw CancellationError() }
    return try await withCheckedThrowingContinuation { waiters.append($0) }
  }

  func finish() {
    closed = true
    let pending = waiters
    waiters.removeAll()
    for waiter in pending { waiter.resume(throwing: CancellationError()) }
  }
}

private actor MemoryByteQueue {
  private var values: [Data] = []
  private var waiters: [CheckedContinuation<Data?, Error>] = []
  private var terminal: Result<Data?, Error>?

  func push(_ value: Data) {
    if !waiters.isEmpty {
      waiters.removeFirst().resume(returning: value)
    } else if terminal == nil {
      values.append(value)
    }
  }

  func next() async throws -> Data? {
    if !values.isEmpty { return values.removeFirst() }
    if let terminal { return try terminal.get() }
    return try await withCheckedThrowingContinuation { waiters.append($0) }
  }

  func finish() { terminate(.success(nil)) }
  func fail(_ error: any Error) { terminate(.failure(error)) }

  private func terminate(_ result: Result<Data?, Error>) {
    guard terminal == nil else { return }
    terminal = result
    let pending = waiters
    waiters.removeAll()
    for waiter in pending { waiter.resume(with: result) }
  }
}
