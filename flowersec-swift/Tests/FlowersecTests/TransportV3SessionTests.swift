import Foundation
import XCTest

@testable import Flowersec

extension TransportV3CarrierSession {
  var capabilities: CarrierCapabilitiesV3 {
    CarrierCapabilitiesV3(reliableStreams: true, datagrams: false, migration: false)
  }

  func sendDatagram(_ data: Data) async throws {
    throw TransportV3CarrierError.datagramsUnavailable
  }

  func receiveDatagram(maxBytes: Int) async throws -> Data {
    throw TransportV3CarrierError.datagramsUnavailable
  }
}

extension TransportV3CarrierStream {
  func stopSending(code: UInt16) async throws {
    throw TransportV3CarrierError.stopSendingUnsupported
  }
}

final class TransportV3SessionTests: XCTestCase {
  func testPublicWrappersKeepSessionStreamRPCAndSubscriptionOpaque() async throws {
    let secret = "opaque-wrapper-secret-marker"
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)
    let publicSession: any Session = OpaqueSessionV3(clientSession)
    let opening = Task { try await publicSession.openStream(kind: secret) }
    _ = try await serverSession.acceptStream()
    let stream = try await opening.value
    let reverseOpening = Task { try await serverSession.openStream(kind: "reverse-opaque") }
    let incoming = try await publicSession.acceptStream()
    _ = try await reverseOpening.value
    let subscription = try await publicSession.rpc.subscribeNotification(
      8_101,
      as: String.self
    ) { _ in
      _ = secret
    }

    for (value, expected) in [
      (publicSession as Any, "Flowersec.Session"),
      (stream as Any, "Flowersec.ByteStream"),
      (publicSession.rpc as Any, "Flowersec.RPCPeer"),
      (subscription as Any, "Flowersec.RPCNotificationSubscription"),
      (incoming.stream as Any, "Flowersec.ByteStream"),
    ] {
      XCTAssertTrue(Mirror(reflecting: value).children.isEmpty)
      XCTAssertEqual(String(describing: value), expected)
      XCTAssertEqual(String(reflecting: value), expected)
      XCTAssertFalse(String(describing: value).contains(secret))
      XCTAssertFalse(String(reflecting: value).contains(secret))
    }

    await subscription.cancel()
    await subscription.cancel()
    try await clientSession.close()
    try await serverSession.close()
  }

  func testPublicByteStreamRejectsNonpositiveReadBeforeReadingPayload() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)
    let publicSession: any Session = OpaqueSessionV3(clientSession)
    let opening = Task { try await publicSession.openStream(kind: "read-boundary") }
    let incoming = try await serverSession.acceptStream()
    let stream = try await opening.value

    for invalid in [0, -1] {
      do {
        _ = try await stream.read(maxBytes: invalid)
        XCTFail("read(maxBytes: \(invalid)) unexpectedly succeeded")
      } catch let error as SessionError {
        XCTAssertEqual(error, .operationFailed)
      }
    }
    _ = try await incoming.stream.write(Data([0x42]))
    let payload = try await stream.read(maxBytes: 1)
    XCTAssertEqual(payload, Data([0x42]))
    try await clientSession.close()
    try await serverSession.close()
  }

  func testSharedStreamKindVectorsMatchPortableSessionValidation() async throws {
    let url = packageRoot().appendingPathComponent(
      "testdata/transport_v3/session_handler_vectors.json")
    let vectors = try JSONDecoder().decode(
      SessionHandlerVectors.self,
      from: Data(contentsOf: url)
    )

    for vector in vectors.streamKinds {
      let kind = String(repeating: vector.unit, count: vector.repetitions) + vector.suffix
      let encode = {
        try OpenPayloadV3(
          logicalStreamID: 1,
          fss3Hash: Data(repeating: 0, count: 32),
          kind: kind,
          metadata: Data("{}".utf8)
        ).encoded()
      }
      if vector.id == "reserved-rpc-kind" || vector.id == "reserved-previous-rpc-kind" {
        XCTAssertNoThrow(try encode(), vector.id)
        continue
      }
      if vector.valid {
        XCTAssertNoThrow(try encode(), vector.id)
      } else {
        XCTAssertThrowsError(try encode(), vector.id)
      }
    }

    XCTAssertEqual(vectors.inheritedCodecFrom, "transport_v2")
    XCTAssertEqual(vectors.transportContractVersion, 3)

    let streamHandlers = try StreamHandlers()
    try streamHandlers.handleStream(kind: vectors.duplicateKind) { _ in }
    XCTAssertThrowsError(
      try streamHandlers.handleStream(kind: vectors.duplicateKind) { _ in }
    ) { error in
      XCTAssertEqual(error as? HandlerRegistrationError, .alreadyRegistered)
    }

    for vector in vectors.rpcTypeIDs {
      let data = try JSONSerialization.data(
        withJSONObject: [
          "type_id": NSNumber(value: vector.value),
          "request_id": 1,
          "response_to": 0,
          "payload": [:],
        ],
        options: [.sortedKeys]
      )
      if vector.valid {
        XCTAssertNoThrow(try RPCEnvelope(data: data), vector.id)
      } else {
        XCTAssertThrowsError(try RPCEnvelope(data: data), vector.id)
      }
    }

    let router = RPCRouter()
    let firstRegistration = await router.register(
      vectors.duplicateTypeID
    ) { (payload: Data) async throws -> Data in payload }
    let duplicateRegistration = await router.register(
      vectors.duplicateTypeID
    ) { (payload: Data) async throws -> Data in payload }
    let zeroRegistration = await router.register(
      0
    ) { (payload: Data) async throws -> Data in payload }
    XCTAssertTrue(firstRegistration)
    XCTAssertFalse(duplicateRegistration)
    XCTAssertFalse(zeroRegistration)

    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)
    do {
      _ = try await clientSession.openStream(kind: "flowersec.rpc.v3")
      XCTFail("reserved RPC stream kind was accepted as an application stream")
    } catch {
      XCTAssertTrue(error is TransportV3SessionError)
    }
    try await clientSession.close()
    try await serverSession.close()
  }

  func testNOnePhysicalCapacityEstablishesAndCarriesOneApplicationStream() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair(
      inboundBidirectionalStreamCapacity: 3
    )
    let configs = try makeConfigs(maxInboundStreams: 1)
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    let opening = try await clientSession.openStream(kind: "n-one")
    let incoming = try await serverSession.acceptStream()
    _ = try await opening.write(Data([1]))
    let received = try await incoming.stream.read(maxBytes: 1)
    XCTAssertEqual(received, Data([1]))
    try await clientSession.close()
    try await serverSession.close()
  }

  func testPhysicalCapacityMismatchFailsBeforeControlStreamOpen() async throws {
    let (clientCarrier, _) = MemoryCarrierSession.pair(inboundBidirectionalStreamCapacity: 4)
    let configs = try makeConfigs(maxInboundStreams: 1)
    do {
      _ = try await TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
      XCTFail("mismatched physical capacity unexpectedly established")
    } catch let error as TransportV3SessionError {
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
      try validateOpenRejectV3(payload: payload, expectedOpenHash: expectedHash),
      2
    )

    var zeroReason = expectedHash
    zeroReason.appendUInt16BE(0)
    XCTAssertThrowsError(
      try validateOpenRejectV3(payload: zeroReason, expectedOpenHash: expectedHash)
    )

    var wrongHash = payload
    wrongHash[0] ^= 1
    XCTAssertThrowsError(
      try validateOpenRejectV3(payload: wrongHash, expectedOpenHash: expectedHash)
    )
  }

  func testReservedRPCMetadataIsRejectedWithoutConsumingTheRPCSlot() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    do {
      _ = try await clientSession.openReservedRPCForTesting(
        metadata: try StreamMetadata(["invalid": .bool(true)]))
      XCTFail("reserved RPC metadata unexpectedly passed admission")
    } catch let error as TransportV3SessionError {
      XCTAssertEqual(error, .openRejected(openRejectInvalidMetadataReasonV3))
    }

    let validRPC = try await clientSession.openReservedRPCForTesting(metadata: .empty)
    try await validRPC.close()
    try await clientSession.close()
    try await serverSession.close()
  }

  func testResourceExhaustionUsesRegisteredOpenRejectReason() {
    XCTAssertEqual(openRejectResourceExhaustedReasonV3, 2)
  }

  func testEstablishesAndCarriesBidirectionalStreamsWithFIN() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()

    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    let outbound = try await clientSession.openStream(
      kind: "测试/echo",
      metadata: try StreamMetadata(["name": .string("café")])
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

    try await clientSession.close()
    try await serverSession.close()
  }

  func testLivenessAndResetAreDeliveredOverControlStream() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    let clientStream = try await clientSession.openStream(kind: "long-lived")
    let serverStream = try await serverSession.acceptStream().stream
    let elapsed = try await clientSession.probeLiveness()
    XCTAssertGreaterThanOrEqual(elapsed, Duration.zero)
    try await clientStream.reset()
    try await Task.sleep(for: .milliseconds(10))
    let terminalError = await serverStream.terminalError()
    XCTAssertNotNil(terminalError)

    try await clientSession.close()
    try await serverSession.close()
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
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
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

    try await clientSession.close()
    try await serverSession.close()
  }

  func testConcurrentFirstRPCCallsShareOneReservedStream() async throws {
    let serverRouter = RPCRouter()
    await serverRouter.register(22) { (request: SessionEcho) in request }
    var configs = try makeConfigs()
    configs.server.rpcRouter = serverRouter
    let clientConfig = configs.client
    let serverConfig = configs.server
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)
    let baseline = await clientCarrier.openedStreamCount

    try await withThrowingTaskGroup(of: SessionEcho.self) { group in
      for index in 0..<32 {
        group.addTask {
          try await clientSession.rpc.call(
            22,
            SessionEcho(value: "call-\(index)"),
            as: SessionEcho.self,
            timeout: .seconds(2)
          )
        }
      }
      var values: Set<String> = []
      for try await response in group { values.insert(response.value) }
      XCTAssertEqual(values.count, 32)
    }
    let openedStreamCount = await clientCarrier.openedStreamCount
    XCTAssertEqual(openedStreamCount, baseline + 1)

    try await clientSession.close()
    try await serverSession.close()
  }

  func testFailedRPCInitializationCanRetryDeterministically() async throws {
    let serverRouter = RPCRouter()
    await serverRouter.register(22) { (request: SessionEcho) in request }
    var configs = try makeConfigs()
    configs.server.rpcRouter = serverRouter
    let clientConfig = configs.client
    let serverConfig = configs.server
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let failOnce = FailSecondOpenCarrierSession(base: clientCarrier)
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: failOnce, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    do {
      let _: SessionEcho = try await clientSession.rpc.call(
        22, SessionEcho(value: "first"), as: SessionEcho.self, timeout: .seconds(1))
      XCTFail("first RPC initialization unexpectedly succeeded")
    } catch is CarrierOpenFailure {
    }
    let response: SessionEcho = try await clientSession.rpc.call(
      22, SessionEcho(value: "retry"), as: SessionEcho.self, timeout: .seconds(2))
    XCTAssertEqual(response, SessionEcho(value: "retry"))

    try await clientSession.close()
    try await serverSession.close()
  }

  func testPublicRPCProjectionMapsMalformedResponseToOperationFailed() async throws {
    let secret = "malformed-rpc-secret-marker"
    let serverRouter = RPCRouter()
    await serverRouter.register(23) { (_: SessionEcho) in secret }

    var configs = try makeConfigs()
    configs.server.rpcRouter = serverRouter
    let clientConfig = configs.client
    let serverConfig = configs.server
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)
    let publicSession: any Session = OpaqueSessionV3(clientSession)

    do {
      let _: SessionEcho = try await publicSession.rpc.call(
        23,
        SessionEcho(value: "request"),
        as: SessionEcho.self,
        timeout: .seconds(2)
      )
      XCTFail("malformed response unexpectedly crossed the public RPC facade")
    } catch let error as SessionError {
      XCTAssertEqual(error, .operationFailed)
      XCTAssertFalse(String(describing: error).contains(secret))
      XCTAssertTrue(Mirror(reflecting: error).children.isEmpty)
    }

    try await clientSession.close()
    try await serverSession.close()
  }

  func testPublicNotificationSubscriptionIsTypedDeterministicAndIsolated() async throws {
    let vectors = try JSONDecoder().decode(
      RPCNotificationVectors.self,
      from: Data(
        contentsOf: packageRoot().appendingPathComponent(
          "testdata/transport_v3/rpc_notification_vectors.json"))
    )
    XCTAssertEqual(
      Set(vectors.subscriptionScenarios),
      Set([
        "duplicate_subscriptions_receive_independently",
        "cancel_is_idempotent",
        "handler_failure_is_isolated",
        "session_close_terminates_subscriptions",
      ])
    )
    let payloads = Dictionary(uniqueKeysWithValues: vectors.payloads.map { ($0.id, $0) })
    let objectPayload = try JSONDecoder().decode(
      PublicNotificationOutboundObject.self,
      from: Data(try XCTUnwrap(payloads["object_unicode_unknown"]).json.utf8)
    )
    let arrayPayload = try JSONDecoder().decode(
      [String].self,
      from: Data(try XCTUnwrap(payloads["array"]).json.utf8)
    )
    let scalarPayload = try JSONDecoder().decode(
      String.self,
      from: Data(try XCTUnwrap(payloads["scalar"]).json.utf8)
    )
    let invalidPayload = try JSONDecoder().decode(
      PublicNotificationInvalidObject.self,
      from: Data(try XCTUnwrap(payloads["decode_failure"]).json.utf8)
    )
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)
    let publicSession: any Session = OpaqueSessionV3(clientSession)
    let recorder = PublicNotificationRecorder()

    let object = try await publicSession.rpc.subscribeNotification(
      vectors.typeID,
      as: PublicNotificationObject.self
    ) { result in
      let value = try result.get()
      await recorder.append("object:\(value.state)")
      throw PublicNotificationHandlerFailure()
    }
    let duplicate = try await publicSession.rpc.subscribeNotification(
      vectors.typeID,
      as: PublicNotificationObject.self
    ) { result in
      let value = try result.get()
      await recorder.append("duplicate:\(value.state)")
    }
    let array = try await publicSession.rpc.subscribeNotification(
      vectors.typeID + 1,
      as: [String].self
    ) { result in
      await recorder.append("array:\(try result.get().joined(separator: ","))")
    }
    let scalar = try await publicSession.rpc.subscribeNotification(
      vectors.typeID + 2,
      as: String.self
    ) { result in
      await recorder.append("scalar:\(try result.get())")
    }
    let invalid = try await publicSession.rpc.subscribeNotification(
      vectors.typeID + 3,
      as: PublicNotificationObject.self
    ) { result in
      switch result {
      case .success:
        await recorder.append("invalid:unexpected-success")
      case .failure(let error):
        await recorder.append("invalid:\(error)")
      }
    }

    try await serverSession.rpc.notify(
      vectors.typeID,
      objectPayload
    )
    try await serverSession.rpc.notify(vectors.typeID + 1, arrayPayload)
    try await serverSession.rpc.notify(vectors.typeID + 2, scalarPayload)
    try await serverSession.rpc.notify(vectors.typeID + 3, invalidPayload)

    let delivered = await waitUntil { await recorder.count() == 5 }
    XCTAssertTrue(delivered)
    let observed = await recorder.values()
    XCTAssertTrue(observed.contains("object:notification accepted 通知"))
    XCTAssertTrue(observed.contains("duplicate:notification accepted 通知"))
    XCTAssertTrue(observed.contains("array:notification,通知"))
    XCTAssertTrue(observed.contains("scalar:notification"))
    XCTAssertTrue(observed.contains("invalid:invalidPayload"))

    await object.cancel()
    await object.cancel()
    await duplicate.cancel()
    try await serverSession.rpc.notify(
      vectors.typeID,
      PublicNotificationOutboundObject(state: "after-cancel", unknown: [:])
    )
    try await Task.sleep(for: .milliseconds(20))
    let countAfterCancel = await recorder.count()
    XCTAssertEqual(countAfterCancel, 5)

    try await publicSession.close()
    await array.cancel()
    await scalar.cancel()
    await invalid.cancel()
    try await serverSession.close()
  }

  func testActiveBidirectionalStreamSurvivesConsecutiveRekeys() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
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

    try await clientSession.close()
    try await serverSession.close()
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
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
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
    try await clientStream.reset()
    try await serverStream.reset()
  }

  func testWaitClosedIsRepeatableAndReportsNormalClose() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)
    let waiting = Task { await clientSession.waitClosed() }

    try await clientSession.close()
    let first = await waiting.value
    let repeated = await clientSession.waitClosed()
    XCTAssertEqual(first, .closed)
    XCTAssertEqual(repeated, .closed)
    try await serverSession.close()
  }

  func testCloseUsesReciprocalAuthenticatedTerminalSequenceBeforeCarrierClose() async throws {
    let clientEvents = CloseCarrierEventsV3()
    let serverEvents = CloseCarrierEventsV3()
    let (clientBase, serverBase) = MemoryCarrierSession.pair()
    let clientCarrier = ObservedCloseCarrierSessionV3(
      base: clientBase, events: clientEvents, observedOpen: 1)
    let serverCarrier = ObservedCloseCarrierSessionV3(
      base: serverBase, events: serverEvents, observedAccept: 1)
    var configs = try makeConfigs()
    configs.client.deadlines.closeFlush = .seconds(1)
    configs.server.deadlines.closeFlush = .seconds(1)
    let clientConfig = configs.client
    let serverConfig = configs.server
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)
    await clientEvents.enable()
    await serverEvents.enable()

    try await clientSession.close()
    let serverClosed = await serverSession.waitClosed()
    let clientOutbound = await clientEvents.outboundEvents()
    let serverOutbound = await serverEvents.outboundEvents()
    XCTAssertEqual(serverClosed, .closed)
    XCTAssertEqual(
      clientOutbound, [.write, .write, .closeWrite, .carrierClose])
    XCTAssertEqual(serverOutbound, [.write, .closeWrite, .carrierClose])
  }

  func testTerminalSequenceSuppressesPONGQueuedBehindCloseWrite() async throws {
    let clientEvents = CloseCarrierEventsV3()
    let serverEvents = CloseCarrierEventsV3()
    let (clientBase, serverBase) = MemoryCarrierSession.pair()
    let clientCarrier = ObservedCloseCarrierSessionV3(
      base: clientBase, events: clientEvents, observedOpen: 1)
    let serverCarrier = ObservedCloseCarrierSessionV3(
      base: serverBase, events: serverEvents, observedAccept: 1)
    var configs = try makeConfigs()
    configs.client.deadlines.closeFlush = .seconds(2)
    configs.server.deadlines.closeFlush = .seconds(2)
    let clientConfig = configs.client
    let serverConfig = configs.server
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)
    await clientEvents.enable(blockNextWrite: true)
    await serverEvents.enable()

    let closing = Task { try await clientSession.close() }
    let closeWriteStarted = await clientEvents.waitForWrites(1)
    XCTAssertTrue(closeWriteStarted)
    let probing = Task { try await serverSession.probeLiveness() }
    let pingWritten = await serverEvents.waitForWrites(1)
    let pingRead = await clientEvents.waitForReads(2)
    XCTAssertTrue(pingWritten)
    XCTAssertTrue(pingRead)
    for _ in 0..<10 { await Task.yield() }
    await clientEvents.releaseWrite()

    try await closing.value
    _ = try? await probing.value
    let serverClosed = await serverSession.waitClosed()
    let clientOutbound = await clientEvents.outboundEvents()
    XCTAssertEqual(serverClosed, .closed)
    XCTAssertEqual(
      clientOutbound, [.write, .write, .closeWrite, .carrierClose])
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
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
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

    try await clientSession.close()
    try await serverSession.close()
  }

  func testEstablishAppliesInternalDeadline() async throws {
    var config = try makeConfigs().client
    config.deadlines.establish = .milliseconds(20)
    let started = ContinuousClock.now
    do {
      _ = try await TransportV3Session.establish(
        carrier: StallingCarrierSession(),
        config: config
      )
      XCTFail("establish unexpectedly succeeded")
    } catch let error as TransportV3SessionError {
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
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    let acceptProbe = SessionOperationProbe()
    let accepting = Task {
      do {
        _ = try await serverSession.acceptStream()
        await acceptProbe.record(.succeeded)
      } catch let error as TransportV3SessionError {
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
    } catch let error as TransportV3SessionError {
      XCTAssertEqual(error, .closed)
    }
    _ = await accepting.result
    try await clientSession.close()
    try await serverSession.close()
  }

  func testSignedZeroIdleTimeoutDisablesWatchdog() async throws {
    var configs = try makeConfigs()
    configs.client.deadlines.idleOverride = .milliseconds(20)
    configs.server.deadlines.idleOverride = .milliseconds(20)
    let clientConfig = configs.client
    let serverConfig = configs.server
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    try await Task.sleep(for: .milliseconds(70))
    _ = try await clientSession.probeLiveness()
    try await clientSession.close()
    try await serverSession.close()
  }

  func testSuccessfulStreamActivityResetsSignedIdleWatchdog() async throws {
    var configs = try makeConfigs(clientIdleTimeoutSeconds: 1, serverIdleTimeoutSeconds: 1)
    configs.client.deadlines.idleOverride = .milliseconds(80)
    configs.server.deadlines.idleOverride = .milliseconds(80)
    let clientConfig = configs.client
    let serverConfig = configs.server
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair(kind: .webTransport)
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
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
    try await clientSession.close()
    try await serverSession.close()
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
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    let acceptProbe = SessionOperationProbe()
    let accepting = Task {
      do {
        _ = try await clientSession.acceptStream()
        await acceptProbe.record(.succeeded)
      } catch let error as TransportV3SessionError {
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
      try await clientSession.close()
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
    } catch let error as TransportV3SessionError {
      XCTAssertEqual(error, .closed)
    }
    let bounded = await waitUntil(timeout: .milliseconds(300)) { await closeProbe.completed }
    XCTAssertTrue(bounded)
    let peerGoAway = await serverSession.goAwayStateForTesting()
    XCTAssertEqual(peerGoAway.receivedLastAccepted, 0)

    await blocker.release()
    _ = await accepting.result
    _ = await closing.result
    try await serverSession.close()
  }

  func testCloseDeadlineAlsoBoundsHangingCarrierClose() async throws {
    let closeGate = HangingCloseGate()
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair(kind: .rawQUIC)
    let clientCarrier = HangingCloseCarrierSession(base: clientBase, gate: closeGate)
    var configs = try makeConfigs()
    configs.client.deadlines.closeFlush = .milliseconds(30)
    let clientConfig = configs.client
    let serverConfig = configs.server
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    let closeProbe = CompletionProbe()
    let closing = Task {
      try await clientSession.close()
      await closeProbe.finish()
    }
    await closeGate.waitUntilEntered()
    let bounded = await waitUntil(timeout: .milliseconds(300)) { await closeProbe.completed }
    XCTAssertTrue(bounded)
    let closeWorkStillActive = await closeGate.active
    XCTAssertFalse(closeWorkStillActive)

    await closeGate.release()
    _ = await closing.result
    try await serverSession.close()
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
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
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
    try await clientSession.close()
    try await serverSession.close()
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
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    await blocker.enable(afterSuccessfulWrites: 0)
    let started = ContinuousClock.now
    do {
      _ = try await clientSession.probeLiveness()
      XCTFail("liveness probe unexpectedly succeeded without PONG")
    } catch let error as TransportV3SessionError {
      XCTAssertEqual(error, .livenessFailed)
    }
    XCTAssertLessThan(started.duration(to: ContinuousClock.now), .milliseconds(300))
    let waiterCountAfterTimeout = await clientSession.lifecycleWaiterCountsForTesting().pings
    XCTAssertEqual(waiterCountAfterTimeout, 0)

    await blocker.release()
    _ = try await clientSession.probeLiveness()
    try await clientSession.close()
    try await serverSession.close()
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
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
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
    try await clientSession.close()
    try await serverSession.close()
  }

  func testCallerCancellationAfterRekeyCommitLeavesOwnedCompletionRunning() async throws {
    let blocker = SwitchableWriteBlocker()
    let (clientCarrier, serverBase) = MemoryCarrierSession.pair()
    let serverCarrier = StallableWriteCarrierSession(
      base: serverBase,
      blocker: blocker,
      blockAcceptedStreamNumber: 1
    )
    var configs = try makeConfigs()
    configs.client.deadlines.rekeyCompletion = .seconds(1)
    let clientConfig = configs.client
    let serverConfig = configs.server
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)
    let publicSession: any Session = OpaqueSessionV3(clientSession)

    await blocker.enable(afterSuccessfulWrites: 0)
    let rekeying = Task { try await publicSession.rekey() }
    await blocker.waitUntilBlocked()
    rekeying.cancel()
    do {
      try await rekeying.value
      XCTFail("cancelled committed rekey unexpectedly completed for its caller")
    } catch let error as SessionError {
      XCTAssertEqual(error, .canceled)
    }
    var lifecycle = await clientSession.lifecycleWaiterCountsForTesting()
    XCTAssertTrue(lifecycle.rekeyInProgress)

    await blocker.release()
    let completed = await waitUntil {
      let state = await clientSession.lifecycleWaiterCountsForTesting()
      return await clientSession.sendEpochForTesting() == 1 && !state.rekeyInProgress
    }
    XCTAssertTrue(completed)
    lifecycle = await clientSession.lifecycleWaiterCountsForTesting()
    XCTAssertFalse(lifecycle.rekeyInProgress)
    try await clientSession.rekey()
    let secondEpoch = await clientSession.sendEpochForTesting()
    XCTAssertEqual(secondEpoch, 2)

    try await clientSession.close()
    try await serverSession.close()
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
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
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
    try await clientSession.close()
    try await serverSession.close()
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
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
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
    try await clientSession.close()
    try await serverSession.close()
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
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)

    let opening = Task { try await serverSession.openStream(kind: "prepare-timeout") }
    await gate.waitUntilBlocked()
    let prepareProbe = SessionOperationProbe()
    let timedRekey = Task {
      do {
        try await clientSession.rekey()
        await prepareProbe.record(.succeeded)
      } catch let error as TransportV3SessionError {
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
      try await clientSession.close()
      try await serverSession.close()
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
      } catch let error as TransportV3SessionError {
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
    try await clientSession.close()
    try await serverSession.close()
  }

  func testAcceptStreamCancellationAtomicallyRemovesOnlyCancelledWaiters() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    let probes = (0..<256).map { _ in SessionOperationProbe() }
    let waiters = probes.map { probe in
      Task {
        do {
          _ = try await serverSession.acceptStream()
          await probe.record(.succeeded)
        } catch is CancellationError {
          await probe.record(.cancelled)
        } catch let error as TransportV3SessionError {
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
    try await clientSession.close()
    try await serverSession.close()
  }

  func testSessionEngineIsCarrierNeutral() async throws {
    for kind in [CarrierKind.webSocket, .rawQUIC, .webTransport] {
      let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair(kind: kind)
      let configs = try makeConfigs()
      async let server = TransportV3Session.establish(
        carrier: serverCarrier, config: configs.server)
      async let client = TransportV3Session.establish(
        carrier: clientCarrier, config: configs.client)
      let (clientSession, serverSession) = try await (client, server)
      try await clientSession.close()
      try await serverSession.close()
    }
  }

  func testSimultaneousRekeyAdvancesBothActiveDirections() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
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
    try await clientSession.close()
    try await serverSession.close()
  }

  func testFailedCarrierOpenCommitsResetBeforeRekeyWatermark() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let failOnce = FailSecondOpenCarrierSession(base: clientCarrier)
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: failOnce, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    do {
      _ = try await clientSession.openStream(kind: "fails-before-fss3")
      XCTFail("open unexpectedly succeeded")
    } catch is CarrierOpenFailure {
    }
    try await clientSession.rekey()
    let stream = try await clientSession.openStream(kind: "after-reset")
    let incoming = try await serverSession.acceptStream()
    XCTAssertEqual(stream.kind, incoming.kind)
    try await clientSession.close()
    try await serverSession.close()
  }

  func testStreamLedgerTracksAbandonedLateSetupAndTerminalStates() throws {
    var ledger = TransportV3StreamLedger(openerRole: .client)
    try ledger.peerReset(3)
    XCTAssertEqual(ledger.state(of: 3), .abandonedNoFSS3)
    XCTAssertEqual(ledger.frontier, 0)

    try ledger.validFSS3(1)
    XCTAssertEqual(ledger.state(of: 1), .openSeen)
    try ledger.validOpen(1)
    XCTAssertEqual(ledger.frontier, 3)

    XCTAssertEqual(try ledger.validFSS3ForAbandoned(3), .reset)
    XCTAssertEqual(ledger.state(of: 3), .usedOrTerminal)
    XCTAssertThrowsError(try ledger.validFSS3ForAbandoned(3))
    XCTAssertThrowsError(try ledger.validFSS3(1))
  }

  func testStreamKeyUpdateACKUsesLogicalIDTransitionEpochOrder() throws {
    let vectors: SessionWireVectors = try readSessionWireVectors()
    let vector = try XCTUnwrap(vectors.streamKeyUpdateACK.first)
    let payload = StreamKeyUpdateACKPayloadV3(
      logicalStreamID: try XCTUnwrap(UInt64(vector.logicalIDHex, radix: 16)),
      transition: try XCTUnwrap(UInt64(vector.transitionIDHex, radix: 16)),
      epoch: try XCTUnwrap(UInt32(vector.nextEpochHex, radix: 16))
    )
    XCTAssertEqual(payload.encoded(), try decodeHex(vector.payloadHex))
    XCTAssertEqual(try StreamKeyUpdateACKPayloadV3(encoded: payload.encoded()), payload)

    let boundary = vectors.transitionBoundary
    let maximum = try XCTUnwrap(UInt64(boundary.maximumTransitionIDHex, radix: 16))
    let nextAfterMaximum = try XCTUnwrap(UInt64(boundary.nextAfterMaximumHex, radix: 16))
    XCTAssertEqual(maximum, UInt64.max)
    XCTAssertEqual(nextAfterMaximum, 0)
    XCTAssertEqual(nextSessionTransitionV3(maximum), nextAfterMaximum)
    XCTAssertNil(nextSessionTransitionV3(nextAfterMaximum))
    XCTAssertNil(expectedSessionTransitionV3(after: maximum))
    XCTAssertTrue(boundary.maximumIsUsableOnce)
    XCTAssertEqual(boundary.exhaustionError, "resource_exhausted")
    XCTAssertEqual(boundary.exhaustionGoAwayReason, 5)
    XCTAssertEqual(boundary.receiveAfterMaximum, "protocol_failure")
    XCTAssertEqual(boundary.goAwayDeliveryFailure, "session_failure")

    let epoch = vectors.epochBoundary
    XCTAssertEqual(try XCTUnwrap(UInt32(epoch.maximumEpochHex, radix: 16)), UInt32.max)
    XCTAssertTrue(epoch.maximumIsUsable)
    XCTAssertEqual(epoch.rekeyAfterMaximum, "resource_exhausted")
    XCTAssertEqual(epoch.exhaustionGoAwayReason, 5)
    XCTAssertEqual(epoch.receiveAfterMaximum, "protocol_failure")
    XCTAssertEqual(epoch.goAwayDeliveryFailure, "session_failure")

    let lifecycle = vectors.rekeyLifecycle
    XCTAssertEqual(lifecycle.exhaustionGoAwayWriteFailure.operationError, "resource_exhausted")
    XCTAssertEqual(lifecycle.exhaustionGoAwayWriteFailure.terminationError, "operation_failed")
    XCTAssertEqual(lifecycle.exhaustionGoAwayWriteFailure.sessionState, "closed")
    XCTAssertEqual(lifecycle.exhaustionGoAwayDeadlineExpiry.operationError, "rekey_failed")
    XCTAssertEqual(lifecycle.exhaustionGoAwayDeadlineExpiry.terminationError, "timeout")
    XCTAssertEqual(lifecycle.exhaustionGoAwayDeadlineExpiry.sessionState, "closed")
    XCTAssertEqual(lifecycle.postCommitCallerCancellation.callerError, "canceled")
    XCTAssertEqual(lifecycle.postCommitCallerCancellation.completionOwner, "session")
    XCTAssertEqual(
      lifecycle.postCommitCallerCancellation.completionDeadline,
      "rekey_completion_timeout"
    )
    XCTAssertEqual(lifecycle.postCommitCallerCancellation.sessionStateAfterSuccess, "open")
  }

  func testTransitionMaximumUsesProductionRekeyOnceThenExhausts() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)
    try await clientSession.setRekeyBoundaryStateForTesting(nextTransition: UInt64.max)
    try await serverSession.setRekeyBoundaryStateForTesting(receivedTransition: UInt64.max - 1)

    try await clientSession.rekey()
    let nextTransition = await clientSession.nextTransitionForTesting()
    XCTAssertEqual(nextTransition, 0)
    do {
      try await clientSession.rekey()
      XCTFail("post-maximum transition rekey unexpectedly succeeded")
    } catch let error as TransportV3SessionError {
      XCTAssertEqual(error, .resourceExhausted)
    }
    let receivedGoAway = await waitUntil {
      await serverSession.goAwayStateForTesting().receivedReason == 5
    }
    XCTAssertTrue(receivedGoAway)

    try await clientSession.close()
    try await serverSession.close()
  }

  func testEpochMaximumProjectsResourceExhaustedAndGoAway() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)
    try await clientSession.setRekeyBoundaryStateForTesting(sendEpoch: UInt32.max)
    try await serverSession.setRekeyBoundaryStateForTesting(receiveEpoch: UInt32.max)

    do {
      try await clientSession.rekey()
      XCTFail("post-maximum epoch rekey unexpectedly succeeded")
    } catch let error as TransportV3SessionError {
      XCTAssertEqual(error, .resourceExhausted)
    }
    let receivedGoAway = await waitUntil {
      await serverSession.goAwayStateForTesting().receivedReason == 5
    }
    XCTAssertTrue(receivedGoAway)

    try await clientSession.close()
    try await serverSession.close()
  }

  func testPostMaximumRekeyRejectsBeforeResponderDrain() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)
    try await clientSession.setRekeyBoundaryStateForTesting(receivedTransition: UInt64.max)
    await clientSession.setActiveInboundRespondersForTesting(1)
    let payload = try decodeHex("0000000000000001000000010000000000000000")

    do {
      try await clientSession.receiveSessionKeyUpdateForTesting(payload)
      XCTFail("post-maximum transition update unexpectedly succeeded")
    } catch let error as TransportV3SessionError {
      XCTAssertEqual(error, .protocolViolation)
    }
    var waiterCounts = await clientSession.lifecycleWaiterCountsForTesting()
    XCTAssertFalse(waiterCounts.peerRespondersFrozen)

    try await clientSession.setRekeyBoundaryStateForTesting(
      receivedTransition: 0,
      receiveEpoch: UInt32.max
    )
    do {
      try await clientSession.receiveSessionKeyUpdateForTesting(payload)
      XCTFail("post-maximum epoch update unexpectedly succeeded")
    } catch let error as TransportV3SessionError {
      XCTAssertEqual(error, .protocolViolation)
    }
    waiterCounts = await clientSession.lifecycleWaiterCountsForTesting()
    XCTAssertFalse(waiterCounts.peerRespondersFrozen)
    await clientSession.setActiveInboundRespondersForTesting(0)

    try await clientSession.close()
    try await serverSession.close()
  }

  func testExhaustionGoAwayWriteFailureTerminatesSession() async throws {
    let blocker = SwitchableWriteBlocker()
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair()
    let clientCarrier = StallableWriteCarrierSession(
      base: clientBase,
      blocker: blocker,
      blockOpenStreamNumber: 1
    )
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)
    try await clientSession.setRekeyBoundaryStateForTesting(nextTransition: 0)
    await blocker.failNextWrite()
    let publicSession: any Session = OpaqueSessionV3(clientSession)

    do {
      try await publicSession.rekey()
      XCTFail("exhaustion rekey unexpectedly succeeded")
    } catch let error as SessionError {
      XCTAssertEqual(error, .resourceExhausted)
    }
    let terminal = await publicSession.waitTermination()
    XCTAssertEqual(terminal.error, .operationFailed)

    try? await clientSession.close()
    try? await serverSession.close()
  }

  func testExhaustionGoAwayUsesThePreparationDeadline() async throws {
    let blocker = SwitchableWriteBlocker()
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair()
    let clientCarrier = StallableWriteCarrierSession(
      base: clientBase,
      blocker: blocker,
      blockOpenStreamNumber: 1
    )
    var configs = try makeConfigs()
    configs.client.deadlines.rekeyPrepare = .milliseconds(25)
    let serverConfig = configs.server
    let clientConfig = configs.client
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)
    try await clientSession.setRekeyBoundaryStateForTesting(nextTransition: 0)
    await blocker.enable(afterSuccessfulWrites: 0)
    let publicSession: any Session = OpaqueSessionV3(clientSession)
    let rekey = Task { try await publicSession.rekey() }
    await blocker.waitUntilBlocked()

    do {
      try await rekey.value
      XCTFail("blocked exhaustion GOAWAY unexpectedly succeeded")
    } catch let error as SessionError {
      XCTAssertEqual(error, .rekeyFailed)
    }
    await assertThrowsAsync {
      _ = try await clientSession.openStream(kind: "after-exhaustion-timeout")
    }
    await blocker.release()
    let terminal = await publicSession.waitTermination()
    XCTAssertEqual(terminal.error, .timeout)

    try? await clientSession.close()
    try? await serverSession.close()
  }

  func testIdenticalRekeyACKIsIdempotentButDifferentACKIsRejected() throws {
    let expected = StreamKeyUpdateACKPayloadV3(
      logicalStreamID: 1,
      transition: 7,
      epoch: 3
    )
    XCTAssertEqual(
      try classifyRekeyACKV3(received: expected, pending: expected, lastAccepted: nil),
      .accepted
    )
    XCTAssertEqual(
      try classifyRekeyACKV3(received: expected, pending: nil, lastAccepted: expected),
      .duplicate
    )
    XCTAssertThrowsError(
      try classifyRekeyACKV3(
        received: StreamKeyUpdateACKPayloadV3(
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
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    _ = try await clientSession.openStream(kind: "before-goaway")
    _ = try await serverSession.acceptStream()
    try await serverSession.sendGoAway(reason: 2)
    try await Task.sleep(for: .milliseconds(20))

    do {
      _ = try await clientSession.openStream(kind: "after-goaway")
      XCTFail("open unexpectedly passed GOAWAY")
    } catch let error as TransportV3SessionError {
      XCTAssertEqual(error, .goingAway)
    }
    let serverState = await serverSession.goAwayStateForTesting()
    let clientState = await clientSession.goAwayStateForTesting()
    XCTAssertEqual(serverState.sentLastAccepted, 1)
    XCTAssertEqual(serverState.sentReason, 2)
    XCTAssertEqual(clientState.receivedLastAccepted, 1)
    XCTAssertEqual(clientState.receivedReason, 2)

    try await serverSession.close()
    let clientTerminal = await clientSession.waitClosed()
    let terminalClientState = await clientSession.goAwayStateForTesting()
    XCTAssertEqual(clientTerminal, .closed)
    XCTAssertEqual(terminalClientState.receivedLastAccepted, 1)
    XCTAssertEqual(terminalClientState.receivedReason, 2)
    try await clientSession.close()
    try await serverSession.close()
  }

  func testCloseAfterGoAwayWritesOnlySessionCloseOnControlWire() async throws {
    let clientEvents = CloseCarrierEventsV3()
    let serverEvents = CloseCarrierEventsV3()
    let (clientBase, serverBase) = MemoryCarrierSession.pair()
    let clientCarrier = ObservedCloseCarrierSessionV3(
      base: clientBase, events: clientEvents, observedOpen: 1)
    let serverCarrier = ObservedCloseCarrierSessionV3(
      base: serverBase, events: serverEvents, observedAccept: 1)
    var configs = try makeConfigs()
    configs.client.deadlines.closeFlush = .seconds(1)
    configs.server.deadlines.closeFlush = .seconds(1)
    let clientConfig = configs.client
    let serverConfig = configs.server
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)
    await clientEvents.enable()
    await serverEvents.enable()

    try await serverSession.sendGoAway(reason: 2)
    let goAwayWritten = await serverEvents.waitForWrites(1)
    XCTAssertTrue(goAwayWritten)
    try await serverSession.close()

    let serverTerminal = await serverSession.waitClosed()
    let serverOutbound = await serverEvents.outboundEvents()
    let clientTerminal = await clientSession.waitClosed()
    XCTAssertEqual(serverTerminal, .closed)
    XCTAssertEqual(serverOutbound, [.write, .write, .closeWrite, .carrierClose])
    XCTAssertEqual(clientTerminal, .closed)
    try await clientSession.close()
  }

  func testGoAwayRejectsWrongParityFutureAndChangedBoundaries() throws {
    var state = ReceivedGoAwayStateV3()
    XCTAssertThrowsError(
      try state.accept(lastAccepted: 2, reason: 2, localRole: .client, localHighWatermark: 3)
    )
    XCTAssertThrowsError(
      try state.accept(lastAccepted: 5, reason: 2, localRole: .client, localHighWatermark: 3)
    )
    try state.accept(lastAccepted: 3, reason: 2, localRole: .client, localHighWatermark: 3)
    try state.accept(lastAccepted: 3, reason: 2, localRole: .client, localHighWatermark: 3)
    XCTAssertThrowsError(
      try state.accept(lastAccepted: 3, reason: 3, localRole: .client, localHighWatermark: 3)
    )
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
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    let opening = Task { try await clientSession.openStream(kind: "past-goaway") }
    await gate.waitUntilBlocked()
    try await serverSession.sendGoAway(reason: 2)
    try await Task.sleep(for: .milliseconds(20))
    await gate.release()

    do {
      _ = try await opening.value
      XCTFail("allocated open unexpectedly passed GOAWAY")
    } catch let error as TransportV3SessionError {
      XCTAssertEqual(error, .goingAway)
    }
    try await clientSession.close()
    try await serverSession.close()
  }

  func testOpenCancellationDuringFSS3WriteCommitsResetBeforeRekey() async throws {
    let gate = BlockingWriteGate()
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair()
    let clientCarrier = BlockingCarrierSession(
      base: clientBase,
      gate: gate,
      blockOpenStreamNumber: 2
    )
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    let opening = Task { try await clientSession.openStream(kind: "cancel-fss3") }
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
    try await clientSession.close()
    try await serverSession.close()
  }

  func testLateFSS3AfterCommittedResetIsStreamScoped() async throws {
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair()
    let clientCarrier = LateFSS3CarrierSession(base: clientBase)
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    let opening = Task { try await clientSession.openStream(kind: "late-fss3") }
    await clientCarrier.waitUntilFSS3Captured()
    opening.cancel()
    do {
      _ = try await opening.value
      XCTFail("cancelled open unexpectedly succeeded")
    } catch is CancellationError {
    }

    _ = try await clientSession.probeLiveness()
    try await clientCarrier.deliverLateFSS3()
    try await Task.sleep(for: .milliseconds(20))
    _ = try await clientSession.probeLiveness()
    try await clientSession.rekey()

    let stream = try await clientSession.openStream(kind: "after-late-fss3")
    let incoming = try await serverSession.acceptStream()
    XCTAssertEqual(stream.kind, incoming.kind)
    try await clientSession.close()
    try await serverSession.close()
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
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
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
    try await clientSession.close()
    try await serverSession.close()
  }

  func testConsecutiveRekeysRetireObsoleteEpochRoots() async throws {
    let (clientCarrier, serverCarrier) = MemoryCarrierSession.pair()
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)

    for _ in 0..<5 { try await clientSession.rekey() }
    let clientCounts = await clientSession.epochRootCountsForTesting()
    let serverCounts = await serverSession.epochRootCountsForTesting()
    XCTAssertEqual(clientCounts.send, 1)
    XCTAssertLessThanOrEqual(serverCounts.receive, 2)

    try await clientSession.close()
    try await serverSession.close()
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
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
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
    try await clientSession.close()
    try await serverSession.close()
  }

  func testDataWriteFailureTerminatesEstablishedStreamExactlyOnce() async throws {
    let faults = EstablishedStreamFaults()
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair(
      inboundBidirectionalStreamCapacity: 3
    )
    let clientCarrier = FaultingEstablishedStreamCarrierSession(
      base: clientBase,
      faults: faults,
      wrapOpenedStreamNumber: 2
    )
    let configs = try makeConfigs(maxInboundStreams: 1)
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)
    let stream = try await clientSession.openStream(kind: "failed-data")
    _ = try await serverSession.acceptStream()

    await faults.failNextWrite()
    await faults.blockReset()
    let failingWrite = Task { try await stream.write(Data([1])) }
    let resetEntered = await waitUntil { await faults.resetEntered }
    XCTAssertTrue(resetEntered)
    let terminal = await stream.terminalError()
    XCTAssertNotNil(terminal)
    await assertThrowsAsync { _ = try await stream.write(Data([2])) }
    await assertThrowsAsync { try await stream.closeWrite() }
    await faults.releaseReset()
    do {
      _ = try await failingWrite.value
      XCTFail("injected DATA write unexpectedly succeeded")
    } catch is InjectedEstablishedStreamFailure {
    } catch {
      XCTFail("injected DATA write error was replaced: \(error)")
    }
    let resetCount = await faults.resetCount
    XCTAssertEqual(resetCount, 1)

    let replacement = try await clientSession.openStream(kind: "replacement")
    _ = try await serverSession.acceptStream()
    do {
      _ = try await clientSession.openStream(kind: "over-capacity")
      XCTFail("failed stream released its permit more than once")
    } catch let error as TransportV3SessionError {
      XCTAssertEqual(error, .resourceExhausted)
    }
    try await replacement.reset()
    try await clientSession.close()
    try await serverSession.close()
  }

  func testStreamProtocolReadFailureAuthenticatesResetAndReleasesCapacity() async throws {
    try await exerciseEstablishedStreamReadFailure(
      .corruptHeader, expected: .protocolViolation, closeWithFIN: false)
  }

  func testStreamAuthenticationReadFailureAuthenticatesResetAndReleasesCapacity() async throws {
    try await exerciseEstablishedStreamReadFailure(
      .corruptCiphertext, expected: .streamReset, closeWithFIN: false)
  }

  func testStreamTruncationAuthenticatesResetAndPreservesClosedError() async throws {
    try await exerciseEstablishedStreamReadFailure(
      .truncate, expected: .closed, closeWithFIN: false)
  }

  func testEncryptedFINRequiresImmediateNativeEOFAndRejectsTrailingByte() async throws {
    try await exerciseEstablishedStreamReadFailure(
      .trailingAfterEOF, expected: .protocolViolation, closeWithFIN: true)
  }

  func testEncryptedFINDoesNotReleaseCapacityBeforeNativeEOF() async throws {
    let faults = EstablishedStreamFaults()
    let (clientCarrier, serverBase) = MemoryCarrierSession.pair(
      inboundBidirectionalStreamCapacity: 3)
    let serverCarrier = FaultingEstablishedStreamCarrierSession(
      base: serverBase, faults: faults, wrapAcceptedStreamNumber: 2)
    let configs = try makeConfigs(maxInboundStreams: 1)
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)
    let opening = Task { try await clientSession.openStream(kind: "blocked-native-eof") }
    let incoming = try await serverSession.acceptStream()
    let stream = try await opening.value

    try await incoming.stream.closeWrite()
    let clientEOF = try await stream.read(maxBytes: 1)
    XCTAssertNil(clientEOF)
    await faults.setReadFault(.blockEOF)
    try await stream.closeWrite()
    let readingFIN = Task { try await incoming.stream.read(maxBytes: 1) }
    let eofReadStarted = await waitUntil { await faults.eofReadStarted }
    XCTAssertTrue(eofReadStarted)

    do {
      _ = try await clientSession.openStream(kind: "before-native-eof")
      XCTFail("stream capacity was released before native EOF")
    } catch let error as TransportV3SessionError {
      XCTAssertEqual(error, .openRejected(openRejectResourceExhaustedReasonV3))
    }

    await faults.releaseEOF()
    let serverEOF = try await readingFIN.value
    XCTAssertNil(serverEOF)
    let replacementOpening = Task {
      try await clientSession.openStream(kind: "after-native-eof")
    }
    let replacementIncoming = try await serverSession.acceptStream()
    let replacement = try await replacementOpening.value
    try await replacement.reset()
    try? await replacementIncoming.stream.reset()
    try await clientSession.close()
    try await serverSession.close()
  }

  func testFINRecordWriteFailureTerminatesEstablishedStream() async throws {
    let faults = EstablishedStreamFaults()
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair()
    let clientCarrier = FaultingEstablishedStreamCarrierSession(
      base: clientBase,
      faults: faults,
      wrapOpenedStreamNumber: 2
    )
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)
    let stream = try await clientSession.openStream(kind: "failed-fin-record")
    _ = try await serverSession.acceptStream()

    await faults.failNextWrite()
    await assertThrowsAsync { try await stream.closeWrite() }
    let terminal = await stream.terminalError()
    XCTAssertNotNil(terminal)
    await assertThrowsAsync { try await stream.closeWrite() }
    let resetCount = await faults.resetCount
    XCTAssertEqual(resetCount, 1)
    try await clientSession.close()
    try await serverSession.close()
  }

  func testCarrierCloseWriteFailureDoesNotCommitLocalFIN() async throws {
    let faults = EstablishedStreamFaults()
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair()
    let clientCarrier = FaultingEstablishedStreamCarrierSession(
      base: clientBase,
      faults: faults,
      wrapOpenedStreamNumber: 2
    )
    let configs = try makeConfigs()
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)
    let stream = try await clientSession.openStream(kind: "failed-native-fin")
    _ = try await serverSession.acceptStream()

    await faults.failNextCloseWrite()
    await assertThrowsAsync { try await stream.closeWrite() }
    let terminal = await stream.terminalError()
    XCTAssertNotNil(terminal)
    await assertThrowsAsync { try await stream.closeWrite() }
    let resetCount = await faults.resetCount
    XCTAssertEqual(resetCount, 1)
    try await clientSession.close()
    try await serverSession.close()
  }

  func testStreamRekeyACKWriteFailureTerminatesStreamAndSession() async throws {
    let faults = EstablishedStreamFaults()
    let (clientCarrier, serverBase) = MemoryCarrierSession.pair()
    let serverCarrier = FaultingEstablishedStreamCarrierSession(
      base: serverBase,
      faults: faults,
      wrapAcceptedStreamNumber: 2
    )
    var configs = try makeConfigs()
    configs.client.deadlines.rekeyCompletion = .milliseconds(100)
    configs.server.deadlines.rekeyCompletion = .milliseconds(100)
    let clientConfig = configs.client
    let serverConfig = configs.server
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)
    _ = try await clientSession.openStream(kind: "failed-rekey-ack")
    let stream = try await serverSession.acceptStream().stream

    await faults.failNextWrite()
    await assertThrowsAsync { try await clientSession.rekey() }
    let terminal = await stream.terminalError()
    XCTAssertNotNil(terminal)
    let resetCount = await faults.resetCount
    XCTAssertEqual(resetCount, 1)
    let closedProbe = CompletionProbe()
    let waiting = Task {
      _ = await serverSession.waitClosed()
      await closedProbe.finish()
    }
    let sessionClosed = await waitUntil(timeout: .milliseconds(300)) {
      await closedProbe.completed
    }
    XCTAssertTrue(sessionClosed)
    waiting.cancel()
    try? await clientSession.close()
    try? await serverSession.close()
  }

  func testStreamRekeyUpdateWriteFailureTerminatesStreamAndSession() async throws {
    let faults = EstablishedStreamFaults()
    let (clientBase, serverCarrier) = MemoryCarrierSession.pair()
    let clientCarrier = FaultingEstablishedStreamCarrierSession(
      base: clientBase,
      faults: faults,
      wrapOpenedStreamNumber: 2
    )
    var configs = try makeConfigs()
    configs.client.deadlines.rekeyCompletion = .milliseconds(100)
    configs.server.deadlines.rekeyCompletion = .milliseconds(100)
    let clientConfig = configs.client
    let serverConfig = configs.server
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: serverConfig)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: clientConfig)
    let (clientSession, serverSession) = try await (client, server)
    let stream = try await clientSession.openStream(kind: "failed-rekey-update")
    _ = try await serverSession.acceptStream()

    await faults.failNextWrite()
    await assertThrowsAsync { try await clientSession.rekey() }
    let terminal = await stream.terminalError()
    XCTAssertNotNil(terminal)
    let resetCount = await faults.resetCount
    XCTAssertEqual(resetCount, 1)
    let closedProbe = CompletionProbe()
    let waiting = Task {
      _ = await clientSession.waitClosed()
      await closedProbe.finish()
    }
    let sessionClosed = await waitUntil(timeout: .milliseconds(300)) {
      await closedProbe.completed
    }
    XCTAssertTrue(sessionClosed)
    waiting.cancel()
    try? await clientSession.close()
    try? await serverSession.close()
  }

  private func exerciseEstablishedStreamReadFailure(
    _ readFault: EstablishedStreamReadFault,
    expected: TransportV3SessionError,
    closeWithFIN: Bool
  ) async throws {
    let faults = EstablishedStreamFaults()
    let (clientCarrier, serverBase) = MemoryCarrierSession.pair(
      inboundBidirectionalStreamCapacity: 3)
    let serverCarrier = FaultingEstablishedStreamCarrierSession(
      base: serverBase, faults: faults, wrapAcceptedStreamNumber: 2)
    let configs = try makeConfigs(maxInboundStreams: 1)
    async let server = TransportV3Session.establish(carrier: serverCarrier, config: configs.server)
    async let client = TransportV3Session.establish(carrier: clientCarrier, config: configs.client)
    let (clientSession, serverSession) = try await (client, server)
    let opening = Task { try await clientSession.openStream(kind: "failed-read") }
    let incoming = try await serverSession.acceptStream()
    let stream = try await opening.value

    await faults.setReadFault(readFault)
    if closeWithFIN {
      try await stream.closeWrite()
    } else {
      _ = try await stream.write(Data("fault-payload".utf8))
    }
    do {
      _ = try await incoming.stream.read(maxBytes: 64)
      XCTFail("injected stream read failure unexpectedly succeeded")
    } catch let error as TransportV3SessionError {
      XCTAssertEqual(error, expected)
    } catch {
      XCTFail("typed stream read failure was replaced: \(error)")
    }

    let resetCompleted = await waitUntil { await faults.resetCount == 1 }
    XCTAssertTrue(resetCompleted)
    do {
      _ = try await stream.read(maxBytes: 1)
      XCTFail("peer did not observe stream reset")
    } catch let error as TransportV3SessionError {
      XCTAssertEqual(error, .streamReset)
    } catch {
      XCTFail("peer reset was not projected as a typed stream error: \(error)")
    }

    let replacementOpening = Task {
      try await clientSession.openStream(kind: "replacement-after-read-failure")
    }
    let replacementIncoming = try await serverSession.acceptStream()
    let replacement = try await replacementOpening.value
    try await replacement.reset()
    try? await replacementIncoming.stream.reset()
    try await clientSession.close()
    try await serverSession.close()
  }

  private func makeConfigs(
    maxInboundStreams: UInt16 = 8,
    clientIdleTimeoutSeconds: UInt32 = 0,
    serverIdleTimeoutSeconds: UInt32 = 0
  ) throws -> (
    client: TransportV3SessionConfig, server: TransportV3SessionConfig
  ) {
    let psk = Data((0..<32).map(UInt8.init))
    let contract = Data((32..<64).map(UInt8.init))
    let clientBinding = Data((64..<96).map(UInt8.init))
    let serverBinding = Data((96..<128).map(UInt8.init))
    return (
      TransportV3SessionConfig(
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
      TransportV3SessionConfig(
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
    let url = packageRoot().appendingPathComponent(
      "testdata/transport_v3/session_wire_vectors.json")
    return try JSONDecoder().decode(
      SessionWireVectors.self,
      from: Data(contentsOf: url)
    )
  }

  private func decodeHex(_ value: String) throws -> Data {
    guard value.count.isMultiple(of: 2) else {
      throw TransportV3ProtocolStateError.invalidTransition
    }
    var output = Data()
    var index = value.startIndex
    while index < value.endIndex {
      let end = value.index(index, offsetBy: 2)
      guard let byte = UInt8(value[index..<end], radix: 16) else {
        throw TransportV3ProtocolStateError.invalidTransition
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

  private func assertThrowsAsync(
    _ operation: () async throws -> Void,
    file: StaticString = #filePath,
    line: UInt = #line
  ) async {
    do {
      try await operation()
      XCTFail("operation unexpectedly succeeded", file: file, line: line)
    } catch {}
  }
}

private struct SessionWireVectors: Decodable {
  let streamKeyUpdateACK: [StreamKeyUpdateACKVector]
  let transitionBoundary: TransitionBoundaryVector
  let epochBoundary: EpochBoundaryVector
  let rekeyLifecycle: RekeyLifecycleVector

  enum CodingKeys: String, CodingKey {
    case streamKeyUpdateACK = "stream_key_update_ack"
    case transitionBoundary = "transition_boundary"
    case epochBoundary = "epoch_boundary"
    case rekeyLifecycle = "rekey_lifecycle"
  }
}

private struct RekeyFailureLifecycleVector: Decodable {
  let operationError: String
  let terminationError: String
  let sessionState: String

  enum CodingKeys: String, CodingKey {
    case operationError = "operation_error"
    case terminationError = "termination_error"
    case sessionState = "session_state"
  }
}

private struct RekeyCallerCancellationVector: Decodable {
  let callerError: String
  let completionOwner: String
  let completionDeadline: String
  let sessionStateAfterSuccess: String

  enum CodingKeys: String, CodingKey {
    case callerError = "caller_error"
    case completionOwner = "completion_owner"
    case completionDeadline = "completion_deadline"
    case sessionStateAfterSuccess = "session_state_after_success"
  }
}

private struct RekeyLifecycleVector: Decodable {
  let exhaustionGoAwayWriteFailure: RekeyFailureLifecycleVector
  let exhaustionGoAwayDeadlineExpiry: RekeyFailureLifecycleVector
  let postCommitCallerCancellation: RekeyCallerCancellationVector

  enum CodingKeys: String, CodingKey {
    case exhaustionGoAwayWriteFailure = "exhaustion_goaway_write_failure"
    case exhaustionGoAwayDeadlineExpiry = "exhaustion_goaway_deadline_expiry"
    case postCommitCallerCancellation = "post_commit_caller_cancellation"
  }
}

private struct TransitionBoundaryVector: Decodable {
  let maximumTransitionIDHex: String
  let nextAfterMaximumHex: String
  let maximumIsUsableOnce: Bool
  let exhaustionError: String
  let exhaustionGoAwayReason: UInt16
  let receiveAfterMaximum: String
  let goAwayDeliveryFailure: String

  enum CodingKeys: String, CodingKey {
    case maximumTransitionIDHex = "maximum_transition_id_hex"
    case nextAfterMaximumHex = "next_after_maximum_hex"
    case maximumIsUsableOnce = "maximum_is_usable_once"
    case exhaustionError = "exhaustion_error"
    case exhaustionGoAwayReason = "exhaustion_goaway_reason"
    case receiveAfterMaximum = "receive_after_maximum"
    case goAwayDeliveryFailure = "goaway_delivery_failure"
  }
}

private struct EpochBoundaryVector: Decodable {
  let maximumEpochHex: String
  let maximumIsUsable: Bool
  let rekeyAfterMaximum: String
  let exhaustionGoAwayReason: UInt16
  let receiveAfterMaximum: String
  let goAwayDeliveryFailure: String

  enum CodingKeys: String, CodingKey {
    case maximumEpochHex = "maximum_epoch_hex"
    case maximumIsUsable = "maximum_is_usable"
    case rekeyAfterMaximum = "rekey_after_maximum"
    case exhaustionGoAwayReason = "exhaustion_goaway_reason"
    case receiveAfterMaximum = "receive_after_maximum"
    case goAwayDeliveryFailure = "goaway_delivery_failure"
  }
}

private struct SessionHandlerVectors: Decodable {
  let streamKinds: [SessionHandlerStreamKindVector]
  let duplicateKind: String
  let rpcTypeIDs: [SessionHandlerRPCTypeIDVector]
  let duplicateTypeID: UInt32
  let inheritedCodecFrom: String
  let transportContractVersion: UInt8

  enum CodingKeys: String, CodingKey {
    case streamKinds = "stream_kinds"
    case duplicateKind = "duplicate_kind"
    case rpcTypeIDs = "rpc_type_ids"
    case duplicateTypeID = "duplicate_type_id"
    case inheritedCodecFrom = "inherited_codec_from"
    case transportContractVersion = "transport_contract_version"
  }
}

private struct SessionHandlerRPCTypeIDVector: Decodable {
  let id: String
  let value: UInt64
  let valid: Bool
}

private struct SessionHandlerStreamKindVector: Decodable {
  let id: String
  let unit: String
  let repetitions: Int
  let suffix: String
  let valid: Bool

  enum CodingKeys: String, CodingKey {
    case id
    case unit
    case repetitions = "repeat"
    case suffix
    case valid
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

private struct PublicNotificationObject: Decodable, Sendable {
  let state: String
}

private struct PublicNotificationOutboundObject: Codable, Sendable {
  let state: String
  let unknown: [String: Bool]
}

private struct PublicNotificationInvalidObject: Codable, Sendable {
  let state: Int
}

private struct RPCNotificationVectors: Decodable {
  let typeID: UInt32
  let payloads: [RPCNotificationPayloadVector]
  let subscriptionScenarios: [String]

  enum CodingKeys: String, CodingKey {
    case typeID = "type_id"
    case payloads
    case subscriptionScenarios = "subscription_scenarios"
  }
}

private struct RPCNotificationPayloadVector: Decodable {
  let id: String
  let json: String
}

private struct PublicNotificationHandlerFailure: Error {}

private actor PublicNotificationRecorder {
  private var recorded: [String] = []

  func append(_ value: String) { recorded.append(value) }
  func count() -> Int { recorded.count }
  func values() -> [String] { recorded }
}

private actor SessionOperationProbe {
  enum Outcome: Equatable, Sendable {
    case pending
    case succeeded
    case cancelled
    case sessionError(TransportV3SessionError)
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

private struct InjectedEstablishedStreamFailure: Error {}

private enum EstablishedStreamReadFault: Equatable, Sendable {
  case blockEOF
  case corruptHeader
  case corruptCiphertext
  case truncate
  case trailingAfterEOF
}

private actor EstablishedStreamFaults {
  private var failWrite = false
  private var failCloseWrite = false
  private(set) var resetCount = 0
  private(set) var resetEntered = false
  private var resetBlocked = false
  private let resetGate = EstablishedStreamResetGate()
  private let eofGate = EstablishedStreamEOFGate()
  private var readFault: EstablishedStreamReadFault?
  private var readsBeforeFault = 0
  private(set) var eofReadStarted = false

  func failNextWrite() { failWrite = true }
  func failNextCloseWrite() { failCloseWrite = true }
  func consumeWriteFailure() -> Bool {
    defer { failWrite = false }
    return failWrite
  }
  func consumeCloseWriteFailure() -> Bool {
    defer { failCloseWrite = false }
    return failCloseWrite
  }
  func recordReset() { resetCount += 1 }
  func setReadFault(_ fault: EstablishedStreamReadFault) {
    readFault = fault
    readsBeforeFault = fault == .corruptCiphertext ? 1 : 0
  }
  func filterRead(_ data: Data?) async -> Data? {
    guard let readFault else { return data }
    if readFault == .blockEOF {
      guard data == nil else { return data }
      self.readFault = nil
      eofReadStarted = true
      await eofGate.wait()
      return nil
    }
    if readFault == .trailingAfterEOF {
      guard data == nil else { return data }
      self.readFault = nil
      return Data([0xA5])
    }
    guard readsBeforeFault == 0 else {
      readsBeforeFault -= 1
      return data
    }
    self.readFault = nil
    switch readFault {
    case .blockEOF:
      return data
    case .corruptHeader:
      guard var data, data.count > 8 else { return data }
      data[data.startIndex + 8] ^= 1
      return data
    case .corruptCiphertext:
      guard var data, !data.isEmpty else { return data }
      data[data.index(before: data.endIndex)] ^= 1
      return data
    case .truncate:
      return nil
    case .trailingAfterEOF:
      return data
    }
  }
  func releaseEOF() async { await eofGate.release() }
  func blockReset() { resetBlocked = true }
  func enterReset() async {
    resetEntered = true
    if resetBlocked { await resetGate.wait() }
  }
  func releaseReset() async { await resetGate.release() }
}

private actor EstablishedStreamResetGate {
  private var released = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  func wait() async {
    if released { return }
    await withCheckedContinuation { waiters.append($0) }
  }

  func release() {
    guard !released else { return }
    released = true
    let pending = waiters
    waiters.removeAll()
    for waiter in pending { waiter.resume() }
  }
}

private actor EstablishedStreamEOFGate {
  private var released = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  func wait() async {
    if released { return }
    await withCheckedContinuation { waiters.append($0) }
  }

  func release() {
    guard !released else { return }
    released = true
    let pending = waiters
    waiters.removeAll()
    for waiter in pending { waiter.resume() }
  }
}

private actor FaultingEstablishedStreamCarrierSession: TransportV3CarrierSession {
  nonisolated let chosenCarrier: CarrierKind
  nonisolated let inboundBidirectionalStreamCapacity: UInt16
  private let base: MemoryCarrierSession
  private let faults: EstablishedStreamFaults
  private let wrapOpenedStreamNumber: Int?
  private let wrapAcceptedStreamNumber: Int?
  private var openCount = 0
  private var acceptCount = 0

  init(
    base: MemoryCarrierSession,
    faults: EstablishedStreamFaults,
    wrapOpenedStreamNumber: Int? = nil,
    wrapAcceptedStreamNumber: Int? = nil
  ) {
    self.base = base
    self.faults = faults
    self.wrapOpenedStreamNumber = wrapOpenedStreamNumber
    self.wrapAcceptedStreamNumber = wrapAcceptedStreamNumber
    chosenCarrier = base.chosenCarrier
    inboundBidirectionalStreamCapacity = base.inboundBidirectionalStreamCapacity
  }

  func openStream() async throws -> any TransportV3CarrierStream {
    openCount += 1
    let stream = try await base.openStream()
    return openCount == wrapOpenedStreamNumber
      ? FaultingEstablishedStreamCarrierStream(base: stream, faults: faults) : stream
  }

  func acceptStream() async throws -> any TransportV3CarrierStream {
    acceptCount += 1
    let stream = try await base.acceptStream()
    return acceptCount == wrapAcceptedStreamNumber
      ? FaultingEstablishedStreamCarrierStream(base: stream, faults: faults) : stream
  }

  func close(code: UInt16, reason: String) async {
    await base.close(code: code, reason: reason)
  }

  nonisolated func abort(code: UInt16, reason: String) {
    base.abort(code: code, reason: reason)
  }
}

private actor FaultingEstablishedStreamCarrierStream: TransportV3CarrierStream {
  nonisolated let carrierStreamID: UInt64
  private let base: any TransportV3CarrierStream
  private let faults: EstablishedStreamFaults

  init(base: any TransportV3CarrierStream, faults: EstablishedStreamFaults) {
    self.base = base
    self.faults = faults
    carrierStreamID = base.carrierStreamID
  }

  func read(maxBytes: Int) async throws -> Data? {
    await faults.filterRead(try await base.read(maxBytes: maxBytes))
  }
  func write(_ data: Data) async throws -> Int {
    if await faults.consumeWriteFailure() { throw InjectedEstablishedStreamFailure() }
    return try await base.write(data)
  }
  func closeWrite() async throws {
    if await faults.consumeCloseWriteFailure() { throw InjectedEstablishedStreamFailure() }
    try await base.closeWrite()
  }
  func reset(code: UInt16) async {
    await faults.enterReset()
    await base.reset(code: code)
    await faults.recordReset()
  }
  func close() async { await base.close() }
  nonisolated func abort(code: UInt16) { base.abort(code: code) }
}

private enum CloseCarrierEventV3: Equatable, Sendable {
  case read
  case write
  case closeWrite
  case carrierClose
  case abort
}

private actor CloseCarrierEventsV3 {
  private var enabled = false
  private var events: [CloseCarrierEventV3] = []
  private var blockWrite = false
  private var writeReleased = false
  private var writeWaiters: [CheckedContinuation<Void, Never>] = []

  func enable(blockNextWrite: Bool = false) {
    enabled = true
    events.removeAll()
    blockWrite = blockNextWrite
    writeReleased = !blockNextWrite
  }

  func recordRead() {
    if enabled { events.append(.read) }
  }

  func beforeWrite() async {
    guard enabled else { return }
    events.append(.write)
    guard blockWrite, !writeReleased else { return }
    blockWrite = false
    await withCheckedContinuation { writeWaiters.append($0) }
  }

  func record(_ event: CloseCarrierEventV3) {
    if enabled { events.append(event) }
  }

  func releaseWrite() {
    writeReleased = true
    let waiters = writeWaiters
    writeWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
  }

  func waitForWrites(_ count: Int) async -> Bool {
    await waitUntil { events.filter { $0 == .write }.count >= count }
  }

  func waitForReads(_ count: Int) async -> Bool {
    await waitUntil { events.filter { $0 == .read }.count >= count }
  }

  func outboundEvents() -> [CloseCarrierEventV3] {
    events.filter { $0 != .read }
  }

  private func waitUntil(_ predicate: () -> Bool) async -> Bool {
    let deadline = ContinuousClock.now + .seconds(1)
    while ContinuousClock.now < deadline {
      if predicate() { return true }
      await Task.yield()
    }
    return predicate()
  }
}

private actor ObservedCloseCarrierSessionV3: TransportV3CarrierSession {
  nonisolated let chosenCarrier: CarrierKind
  nonisolated let inboundBidirectionalStreamCapacity: UInt16
  private let base: MemoryCarrierSession
  private let events: CloseCarrierEventsV3
  private let observedOpen: Int?
  private let observedAccept: Int?
  private var openCount = 0
  private var acceptCount = 0

  init(
    base: MemoryCarrierSession,
    events: CloseCarrierEventsV3,
    observedOpen: Int? = nil,
    observedAccept: Int? = nil
  ) {
    self.base = base
    self.events = events
    self.observedOpen = observedOpen
    self.observedAccept = observedAccept
    chosenCarrier = base.chosenCarrier
    inboundBidirectionalStreamCapacity = base.inboundBidirectionalStreamCapacity
  }

  func openStream() async throws -> any TransportV3CarrierStream {
    openCount += 1
    let stream = try await base.openStream()
    return openCount == observedOpen
      ? ObservedCloseCarrierStreamV3(base: stream, events: events) : stream
  }

  func acceptStream() async throws -> any TransportV3CarrierStream {
    acceptCount += 1
    let stream = try await base.acceptStream()
    return acceptCount == observedAccept
      ? ObservedCloseCarrierStreamV3(base: stream, events: events) : stream
  }

  func close(code: UInt16, reason: String) async {
    await events.record(.carrierClose)
    await base.close(code: code, reason: reason)
  }

  nonisolated func abort(code: UInt16, reason: String) {
    Task { await events.record(.abort) }
    base.abort(code: code, reason: reason)
  }
}

private actor ObservedCloseCarrierStreamV3: TransportV3CarrierStream {
  nonisolated let carrierStreamID: UInt64
  private let base: any TransportV3CarrierStream
  private let events: CloseCarrierEventsV3

  init(base: any TransportV3CarrierStream, events: CloseCarrierEventsV3) {
    self.base = base
    self.events = events
    carrierStreamID = base.carrierStreamID
  }

  func read(maxBytes: Int) async throws -> Data? {
    let result = try await base.read(maxBytes: maxBytes)
    if result != nil { await events.recordRead() }
    return result
  }

  func write(_ data: Data) async throws -> Int {
    await events.beforeWrite()
    return try await base.write(data)
  }

  func closeWrite() async throws {
    await events.record(.closeWrite)
    try await base.closeWrite()
  }

  func reset(code: UInt16) async { await base.reset(code: code) }
  func close() async { await base.close() }
  nonisolated func abort(code: UInt16) { base.abort(code: code) }
}

private actor MemoryCarrierSession: TransportV3CarrierSession {
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

  func openStream() async throws -> any TransportV3CarrierStream {
    while peer == nil { await Task.yield() }
    let id = nextID
    nextID += 2
    openedStreamCount += 1
    let pair = MemoryCarrierStream.pair(id: id)
    await peer?.enqueue(pair.1)
    return pair.0
  }

  func acceptStream() async throws -> any TransportV3CarrierStream {
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

  private func enqueue(_ stream: any TransportV3CarrierStream) async {
    await incoming.push(stream)
  }
}

private actor HangingCloseCarrierSession: TransportV3CarrierSession {
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

  func openStream() async throws -> any TransportV3CarrierStream {
    try await base.openStream()
  }

  func acceptStream() async throws -> any TransportV3CarrierStream {
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

private actor StallingCarrierSession: TransportV3CarrierSession {
  nonisolated let chosenCarrier: CarrierKind = .webSocket
  nonisolated let inboundBidirectionalStreamCapacity: UInt16 = 10

  func openStream() async throws -> any TransportV3CarrierStream { StallingCarrierStream() }

  func acceptStream() async throws -> any TransportV3CarrierStream {
    throw CancellationError()
  }

  func close(code: UInt16, reason: String) async {}

  nonisolated func abort(code: UInt16, reason: String) {}
}

private actor FirstReadBlockingCarrierSession: TransportV3CarrierSession {
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

  func openStream() async throws -> any TransportV3CarrierStream {
    try await base.openStream()
  }

  func acceptStream() async throws -> any TransportV3CarrierStream {
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

private actor FirstReadBlockingCarrierStream: TransportV3CarrierStream {
  nonisolated let carrierStreamID: UInt64
  private let base: any TransportV3CarrierStream
  private let gate: FirstReadGate
  private var blocked = false

  init(base: any TransportV3CarrierStream, gate: FirstReadGate) {
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

private actor StallableWriteCarrierSession: TransportV3CarrierSession {
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

  func openStream() async throws -> any TransportV3CarrierStream {
    openCount += 1
    let stream = try await base.openStream()
    guard openCount == blockOpenStreamNumber else { return stream }
    return StallableWriteCarrierStream(base: stream, blocker: blocker)
  }

  func acceptStream() async throws -> any TransportV3CarrierStream {
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

private actor StallableWriteCarrierStream: TransportV3CarrierStream {
  nonisolated let carrierStreamID: UInt64
  private let base: any TransportV3CarrierStream
  private let blocker: SwitchableWriteBlocker

  init(base: any TransportV3CarrierStream, blocker: SwitchableWriteBlocker) {
    self.base = base
    self.blocker = blocker
    carrierStreamID = base.carrierStreamID
  }

  func read(maxBytes: Int) async throws -> Data? { try await base.read(maxBytes: maxBytes) }

  func write(_ data: Data) async throws -> Int {
    try await blocker.beforeWrite()
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
  private var failNext = false
  private var blockWaiters: [CheckedContinuation<Void, Never>] = []
  private var enteredWaiters: [CheckedContinuation<Void, Never>] = []

  func enable(afterSuccessfulWrites: Int) {
    released = false
    blocked = false
    remainingSuccessfulWrites = afterSuccessfulWrites
  }

  func failNextWrite() { failNext = true }

  func beforeWrite() async throws {
    if failNext {
      failNext = false
      throw InjectedEstablishedStreamFailure()
    }
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

private actor FailSecondOpenCarrierSession: TransportV3CarrierSession {
  nonisolated let chosenCarrier: CarrierKind
  nonisolated let inboundBidirectionalStreamCapacity: UInt16
  private let base: MemoryCarrierSession
  private var openCount = 0

  init(base: MemoryCarrierSession) {
    self.base = base
    chosenCarrier = base.chosenCarrier
    inboundBidirectionalStreamCapacity = base.inboundBidirectionalStreamCapacity
  }

  func openStream() async throws -> any TransportV3CarrierStream {
    openCount += 1
    if openCount == 2 { throw CarrierOpenFailure() }
    return try await base.openStream()
  }

  func acceptStream() async throws -> any TransportV3CarrierStream {
    try await base.acceptStream()
  }

  func close(code: UInt16, reason: String) async {
    await base.close(code: code, reason: reason)
  }

  nonisolated func abort(code: UInt16, reason: String) {
    base.abort(code: code, reason: reason)
  }
}

private actor BlockingCarrierSession: TransportV3CarrierSession {
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

  func openStream() async throws -> any TransportV3CarrierStream {
    openCount += 1
    let stream = try await base.openStream()
    if openCount == blockOpenStreamNumber {
      return BlockingWriteCarrierStream(base: stream, gate: gate)
    }
    return stream
  }

  func acceptStream() async throws -> any TransportV3CarrierStream {
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

private struct LateFSS3WriteError: Error {}

private actor LateFSS3CarrierSession: TransportV3CarrierSession {
  nonisolated let chosenCarrier: CarrierKind
  nonisolated let inboundBidirectionalStreamCapacity: UInt16
  private let base: MemoryCarrierSession
  private var openCount = 0
  private var lateStream: LateFSS3CarrierStream?

  init(base: MemoryCarrierSession) {
    self.base = base
    chosenCarrier = base.chosenCarrier
    inboundBidirectionalStreamCapacity = base.inboundBidirectionalStreamCapacity
  }

  func openStream() async throws -> any TransportV3CarrierStream {
    openCount += 1
    let stream = try await base.openStream()
    guard openCount == 2 else { return stream }
    let late = LateFSS3CarrierStream(base: stream)
    lateStream = late
    return late
  }

  func acceptStream() async throws -> any TransportV3CarrierStream {
    try await base.acceptStream()
  }

  func close(code: UInt16, reason: String) async {
    await base.close(code: code, reason: reason)
  }

  nonisolated func abort(code: UInt16, reason: String) {
    base.abort(code: code, reason: reason)
  }

  func waitUntilFSS3Captured() async {
    while lateStream == nil { await Task.yield() }
    await lateStream?.waitUntilCaptured()
  }

  func deliverLateFSS3() async throws {
    guard let lateStream else { throw LateFSS3WriteError() }
    try await lateStream.deliverCaptured()
  }
}

private actor LateFSS3CarrierStream: TransportV3CarrierStream {
  nonisolated let carrierStreamID: UInt64
  private let base: any TransportV3CarrierStream
  private var captured: Data?
  private var writeWaiter: CheckedContinuation<Int, Error>?
  private var capturedWaiters: [CheckedContinuation<Void, Never>] = []
  private var delivered = false

  init(base: any TransportV3CarrierStream) {
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
      writeWaiter.resume(throwing: LateFSS3WriteError())
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
    guard let captured, !delivered else { throw LateFSS3WriteError() }
    delivered = true
    _ = try await base.write(captured)
  }
}

private actor BlockingWriteCarrierStream: TransportV3CarrierStream {
  nonisolated let carrierStreamID: UInt64
  private let base: any TransportV3CarrierStream
  private let gate: BlockingWriteGate
  private var blocked = false

  init(base: any TransportV3CarrierStream, gate: BlockingWriteGate) {
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

private actor StallingCarrierStream: TransportV3CarrierStream {
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

private actor MemoryCarrierStream: TransportV3CarrierStream {
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
  private var values: [any TransportV3CarrierStream] = []
  private var waiters: [CheckedContinuation<any TransportV3CarrierStream, Error>] = []
  private var closed = false

  func push(_ value: any TransportV3CarrierStream) {
    if !waiters.isEmpty {
      waiters.removeFirst().resume(returning: value)
    } else if !closed {
      values.append(value)
    }
  }

  func next() async throws -> any TransportV3CarrierStream {
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
