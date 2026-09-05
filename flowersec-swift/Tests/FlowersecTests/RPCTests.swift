import Foundation
import XCTest

@testable import Flowersec

final class FlowersecRPCTests: XCTestCase {
  func testEnvelopeConsumesSharedMalformedVectors() throws {
    let root = try XCTUnwrap(
      JSONSerialization.jsonObject(
        with: Data(
          contentsOf: packageRoot().appendingPathComponent(
            "testdata/transport_v3/rpc_malformed_envelopes.json")))
        as? [String: Any]
    )
    XCTAssertEqual((root["version"] as? NSNumber)?.intValue, 1)
    XCTAssertEqual((root["transport_contract_version"] as? NSNumber)?.intValue, 3)
    let vectors = try XCTUnwrap(root["vectors"] as? [[String: Any]])
    XCTAssertFalse(vectors.isEmpty)
    for vector in vectors {
      let id = try XCTUnwrap(vector["id"] as? String)
      let valid = try XCTUnwrap(vector["valid"] as? Bool)
      let envelope = try XCTUnwrap(vector["envelope"])
      let data = try JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys])
      if valid {
        XCTAssertNoThrow(try RPCEnvelope(data: data), id)
      } else {
        XCTAssertThrowsError(try RPCEnvelope(data: data), id)
      }
    }
  }

  func testEnvelopeRoundTripsNullErrorPayload() throws {
    let envelope = RPCEnvelope(
      typeID: 7,
      requestID: 0,
      responseTo: 161,
      payload: Data("null".utf8),
      error: RPCErrorPayload(code: 429, message: "server overloaded")
    )
    let decoded = try RPCEnvelope(data: envelope.encoded())
    XCTAssertEqual(decoded, envelope)
  }

  func testEnvelopeEnforcesPortableInboundRPCErrorInvariant() throws {
    func envelope(error: [String: Any]) throws -> Data {
      try JSONSerialization.data(
        withJSONObject: [
          "type_id": 1,
          "request_id": 0,
          "response_to": 1,
          "payload": [:],
          "error": error,
        ],
        options: [.sortedKeys]
      )
    }

    let fixture = try JSONDecoder().decode(
      SharedRPCErrorVectors.self,
      from: Data(
        contentsOf: packageRoot().appendingPathComponent(
          "testdata/transport_v3/rpc_error_vectors.json"))
    )
    XCTAssertEqual(fixture.maximumMessageBytes, 1_024)

    for vector in fixture.cases {
      let id = vector.id
      let message = String(repeating: vector.message.unit, count: vector.message.repeatCount)
        + vector.message.suffix
      var error: [String: Any] = ["code": NSNumber(value: vector.code)]
      if vector.message.presence == "present" {
        error["message"] = message
      }
      if vector.extraField {
        error["internal"] = "secret"
      }
      if vector.valid {
        let decoded = try RPCEnvelope(data: envelope(error: error))
        XCTAssertEqual(decoded.error?.code, vector.code, id)
        if vector.message.presence == "present" {
          XCTAssertEqual(decoded.error?.message, message, id)
        } else {
          XCTAssertNil(decoded.error?.message, id)
        }
      } else {
        XCTAssertThrowsError(try RPCEnvelope(data: envelope(error: error)), id)
      }
    }

    for vector in fixture.rawCases {
      let id = vector.id
      var raw = Data(
        "{\"type_id\":1,\"request_id\":0,\"response_to\":1,\"payload\":null,\"error\":{\"code\":\(vector.code),\"message\":\""
          .utf8
      )
      raw.append(try decodeHex(vector.messageHex))
      raw.append(Data("\"}}".utf8))
      if vector.valid {
        XCTAssertNoThrow(try RPCEnvelope(data: raw), id)
      } else {
        XCTAssertThrowsError(try RPCEnvelope(data: raw), id)
      }
    }
  }

  func testClientEnforcesRPCErrorInvariantAtReceiveBoundary() async throws {
    let validASCII = String(repeating: "a", count: 1_024)
    let validMultibyte = String(repeating: "é", count: 512)

    func responseData(requestID: UInt64, error: [String: Any]) throws -> Data {
      try JSONSerialization.data(
        withJSONObject: [
          "type_id": 1,
          "request_id": 0,
          "response_to": NSNumber(value: requestID),
          "payload": NSNull(),
          "error": error,
        ],
        options: [.sortedKeys]
      )
    }

    for (name, error) in [
      ("missing message", ["code": 7]),
      ("ASCII 1024 bytes", ["code": 7, "message": validASCII]),
      ("multibyte UTF-8 1024 bytes", ["code": 7, "message": validMultibyte]),
    ] as [(String, [String: Any])] {
      let stream = InMemoryRPCStream()
      let client = RPCClient(stream: stream)
      await client.start()
      let call = Task {
        let _: RPCReply = try await client.call(1, RPCRequest(value: name), timeout: .seconds(1))
      }
      let request = try await stream.nextWrittenEnvelope()
      try await stream.pushRawFrame(responseData(requestID: request.requestID, error: error))
      do {
        try await call.value
        XCTFail("Expected application error for \(name)")
      } catch let applicationError as FlowersecRPCError {
        XCTAssertEqual(applicationError.code, 7, name)
        XCTAssertEqual(applicationError.message, error["message"] as? String, name)
      }
      await client.close()
    }

    let invalidCases =
      [
        ("zero code", ["code": 0]),
        ("ASCII 1025 bytes", ["code": 7, "message": validASCII + "a"]),
        ("multibyte UTF-8 1025 bytes", ["code": 7, "message": validMultibyte + "a"]),
        ("extra error field", ["code": 7, "internal": "secret"]),
      ] as [(String, [String: Any])]
    for (name, error) in invalidCases {
      let stream = InMemoryRPCStream()
      let client = RPCClient(stream: stream)
      await client.start()
      let call = Task {
        let _: RPCReply = try await client.call(1, RPCRequest(value: name), timeout: .seconds(1))
      }
      let request = try await stream.nextWrittenEnvelope()
      try await stream.pushRawFrame(responseData(requestID: request.requestID, error: error))
      do {
        try await call.value
        XCTFail("Expected protocol failure for \(name)")
      } catch let failure as FlowersecError {
        XCTAssertEqual(failure.stage, .rpc, name)
        XCTAssertEqual(failure.code, .rpcFailed, name)
      } catch {
        XCTFail("Unexpected error for \(name): \(error)")
      }
      await client.close()
    }

    let stream = InMemoryRPCStream()
    let client = RPCClient(stream: stream)
    await client.start()
    let malformedCall = Task {
      let _: RPCReply = try await client.call(
        1, RPCRequest(value: "malformed UTF-8"), timeout: .seconds(1)
      )
    }
    let request = try await stream.nextWrittenEnvelope()
    var malformed = Data(
      "{\"type_id\":1,\"request_id\":0,\"response_to\":\(request.requestID),\"payload\":null,\"error\":{\"code\":7,\"message\":\""
        .utf8
    )
    malformed.append(0xff)
    malformed.append(Data("\"}}".utf8))
    try await stream.pushRawFrame(malformed)
    do {
      try await malformedCall.value
      XCTFail("Expected malformed UTF-8 protocol failure")
    } catch let failure as FlowersecError {
      XCTAssertEqual(failure.stage, .rpc)
      XCTAssertEqual(failure.code, .rpcFailed)
    } catch {
      XCTFail("Unexpected malformed UTF-8 error: \(error)")
    }
    await client.close()
  }

  func testPublicRPCErrorFormattingAndReflectionHideApplicationMessage() {
    let secret = "rpc-error-secret-marker"
    let error = RPCError(code: 73, message: secret)
    XCTAssertEqual(String(describing: error), "Flowersec.RPCError(code: 73)")
    XCTAssertEqual(String(reflecting: error), "Flowersec.RPCError(code: 73)")
    XCTAssertFalse(String(describing: error).contains(secret))
    XCTAssertFalse(String(reflecting: error).contains(secret))
    let children = Array(Mirror(reflecting: error).children)
    XCTAssertEqual(children.count, 1)
    XCTAssertEqual(children.first?.label, "code")
    XCTAssertEqual(children.first?.value as? UInt32, 73)
  }

  func testServerSendsTypedNotification() async throws {
    let stream = InMemoryByteStream()
    let server = try RPCServer(stream: stream, router: RPCRouter())
    try await server.notify(7010, RPCNotification(value: "world"))
    let data = try await stream.nextWrittenJSONFrame()
    let envelope = try RPCEnvelope(data: data)
    XCTAssertEqual(envelope.typeID, 7010)
    XCTAssertEqual(envelope.requestID, 0)
    XCTAssertEqual(envelope.responseTo, 0)
    XCTAssertEqual(
      try JSONDecoder().decode(RPCNotification.self, from: envelope.payload),
      RPCNotification(value: "world")
    )
    await server.close()
    do {
      try await server.notify(7010, RPCNotification(value: "closed"))
      XCTFail("Expected a closed server error")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.code, .notConnected)
    }
  }

  func testServerRejectsResponseEnvelopeOnRequestStream() async throws {
    let stream = InMemoryByteStream()
    let server = try RPCServer(stream: stream, router: RPCRouter())
    let serve = Task { try await server.serve() }
    try await stream.pushJSONFrame(
      RPCEnvelope(
        typeID: 1,
        requestID: 0,
        responseTo: 7,
        payload: Data("null".utf8),
        error: nil
      ).encoded()
    )

    do {
      try await serve.value
      XCTFail("server accepted an RPC response on its request stream")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.stage, .rpc)
      XCTAssertEqual(error.code, .rpcFailed)
    }
    await server.close()
  }

  func testServerSanitizesInvalidHandlerErrorsBeforeWritingResponse() async throws {
    let validASCII = String(repeating: "a", count: 1_024)
    let validMultibyte = String(repeating: "é", count: 512)
    let cases: [(String, FlowersecRPCError, UInt32, String)] = [
      ("ASCII 1024 bytes", FlowersecRPCError(code: 7, message: validASCII), 7, validASCII),
      (
        "multibyte UTF-8 1024 bytes", FlowersecRPCError(code: 7, message: validMultibyte), 7,
        validMultibyte
      ),
      ("zero code", FlowersecRPCError(code: 0, message: "invalid"), 500, "internal error"),
      (
        "ASCII 1025 bytes", FlowersecRPCError(code: 7, message: validASCII + "a"), 500,
        "internal error"
      ),
      (
        "multibyte UTF-8 1025 bytes", FlowersecRPCError(code: 7, message: validMultibyte + "a"),
        500, "internal error"
      ),
    ]

    for (name, handlerError, expectedCode, expectedMessage) in cases {
      let stream = InMemoryByteStream()
      let router = RPCRouter()
      await router.register(1) { (_: Data) async throws -> Data in
        throw handlerError
      }
      let server = try RPCServer(stream: stream, router: router)
      let serve = Task { try await server.serve() }
      try await stream.pushJSONFrame(
        RPCEnvelope(
          typeID: 1,
          requestID: 1,
          responseTo: 0,
          payload: Data("null".utf8),
          error: nil
        ).encoded()
      )
      let responseData = try await stream.nextWrittenJSONFrame()
      let response = try XCTUnwrap(
        JSONSerialization.jsonObject(with: responseData) as? [String: Any],
        name
      )
      let wireError = try XCTUnwrap(response["error"] as? [String: Any], name)
      XCTAssertEqual((wireError["code"] as? NSNumber)?.uint32Value, expectedCode, name)
      XCTAssertEqual(wireError["message"] as? String, expectedMessage, name)
      XCTAssertEqual(Set(wireError.keys), ["code", "message"], name)
      serve.cancel()
      await server.close()
      _ = try? await serve.value
    }
  }

  func testServerIsolatesNotificationHandlerFailure() async throws {
    let stream = InMemoryByteStream()
    let router = RPCRouter()
    await router.register(7011) { (_: RPCNotification) async throws -> RPCNotification in
      throw IntentionalRPCServerError()
    }
    await router.register(7012) { (request: RPCNotification) async throws -> RPCNotification in
      RPCNotification(value: "after-\(request.value)")
    }
    let server = try RPCServer(stream: stream, router: router)
    let serve = Task { try await server.serve() }
    try await stream.pushJSONFrame(
      RPCEnvelope(
        typeID: 7011,
        requestID: 0,
        responseTo: 0,
        payload: JSONEncoder.flowersecRPCTest.encode(RPCNotification(value: "fail")),
        error: nil
      ).encoded()
    )
    try await stream.pushJSONFrame(
      RPCEnvelope(
        typeID: 7012,
        requestID: 1,
        responseTo: 0,
        payload: JSONEncoder.flowersecRPCTest.encode(RPCNotification(value: "failure")),
        error: nil
      ).encoded()
    )

    let response = try RPCEnvelope(data: await stream.nextWrittenJSONFrame())
    XCTAssertEqual(response.responseTo, 1)
    XCTAssertEqual(
      try JSONDecoder().decode(RPCNotification.self, from: response.payload),
      RPCNotification(value: "after-failure")
    )

    serve.cancel()
    await server.close()
    _ = try? await serve.value
  }

  func testCallWritesEnvelopeAndDecodesResponse() async throws {
    let stream = InMemoryRPCStream()
    let client = RPCClient(stream: stream)
    await client.start()

    async let response: RPCReply = client.call(
      7001,
      RPCRequest(value: "hello"),
      timeout: .seconds(1)
    )
    let request = try await stream.nextWrittenEnvelope()
    XCTAssertEqual(request.typeID, 7001)
    XCTAssertEqual(request.requestID, 1)
    XCTAssertEqual(request.responseTo, 0)
    XCTAssertEqual(
      try JSONDecoder().decode(RPCRequest.self, from: request.payload),
      RPCRequest(value: "hello")
    )

    try await stream.pushEnvelope(
      RPCEnvelope(
        typeID: 7001,
        requestID: 0,
        responseTo: request.requestID,
        payload: JSONEncoder.flowersecRPCTest.encode(RPCReply(ok: true)),
        error: nil
      )
    )

    let decodedResponse = try await response
    XCTAssertEqual(decodedResponse, RPCReply(ok: true))
    await client.close()
  }

  func testCallMapsPeerErrorResponse() async throws {
    let stream = InMemoryRPCStream()
    let client = RPCClient(stream: stream)
    await client.start()

    async let response: RPCReply = client.call(
      7002,
      RPCRequest(value: "fail"),
      timeout: .seconds(1)
    )
    let request = try await stream.nextWrittenEnvelope()
    try await stream.pushEnvelope(
      RPCEnvelope(
        typeID: 7002,
        requestID: 0,
        responseTo: request.requestID,
        payload: Data("{}".utf8),
        error: RPCErrorPayload(code: 403, message: "Denied")
      )
    )

    do {
      _ = try await response
      XCTFail("Expected RPC error")
    } catch let error as FlowersecRPCError {
      XCTAssertEqual(error, FlowersecRPCError(code: 403, message: "Denied"))
    }
    await client.close()
  }

  func testNotifyDispatchesRegisteredHandler() async throws {
    let stream = InMemoryRPCStream()
    let client = RPCClient(stream: stream)
    await client.start()

    let expectation = expectation(description: "notify")
    let subscription = try await client.subscribeNotification(7003) { data in
      let decoded = try? JSONDecoder().decode(RPCReply.self, from: data)
      XCTAssertEqual(decoded, RPCReply(ok: true))
      expectation.fulfill()
    }

    try await stream.pushEnvelope(
      RPCEnvelope(
        typeID: 7003,
        requestID: 0,
        responseTo: 0,
        payload: JSONEncoder.flowersecRPCTest.encode(RPCReply(ok: true)),
        error: nil
      )
    )

    await fulfillment(of: [expectation], timeout: 1)
    await subscription.cancel()
    await subscription.cancel()
    await client.close()
  }

  func testLateResponseAfterCancellationDoesNotCloseClient() async throws {
    let stream = InMemoryRPCStream()
    let client = RPCClient(stream: stream)
    await client.start()

    let cancelled = Task {
      let _: RPCReply = try await client.call(
        7004,
        RPCRequest(value: "pending"),
        timeout: .seconds(2)
      )
    }
    let cancelledRequest = try await stream.nextWrittenEnvelope()
    cancelled.cancel()
    do {
      try await cancelled.value
      XCTFail("Expected cancellation")
    } catch is CancellationError {
      XCTAssertTrue(true)
    }

    try await stream.pushEnvelope(
      RPCEnvelope(
        typeID: 7004,
        requestID: 0,
        responseTo: cancelledRequest.requestID,
        payload: JSONEncoder.flowersecRPCTest.encode(RPCReply(ok: true)),
        error: nil
      )
    )

    async let response: RPCReply = client.call(
      7004,
      RPCRequest(value: "next"),
      timeout: .seconds(2)
    )
    let nextRequest = try await stream.nextWrittenEnvelope()

    try await stream.pushEnvelope(
      RPCEnvelope(
        typeID: 7004,
        requestID: 0,
        responseTo: nextRequest.requestID,
        payload: JSONEncoder.flowersecRPCTest.encode(RPCReply(ok: true)),
        error: nil
      )
    )

    let decodedResponse = try await response
    XCTAssertEqual(decodedResponse, RPCReply(ok: true))
    await client.close()
  }

  func testCallTimesOutWhenPeerDoesNotRespond() async throws {
    let stream = InMemoryRPCStream()
    let client = RPCClient(stream: stream)
    await client.start()

    do {
      let _: RPCReply = try await client.call(
        7005,
        RPCRequest(value: "slow"),
        timeout: .milliseconds(30)
      )
      XCTFail("Expected timeout")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .rpc)
      XCTAssertEqual(error.code, .timeout)
    }
    await client.close()
  }

  func testTunnelCallTimeoutUsesTunnelRPCPath() async throws {
    let stream = InMemoryRPCStream()
    let client = RPCClient(stream: stream, path: .tunnel)
    await client.start()

    do {
      let _: RPCReply = try await client.call(
        7007,
        RPCRequest(value: "slow"),
        timeout: .milliseconds(30)
      )
      XCTFail("Expected timeout")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .tunnel)
      XCTAssertEqual(error.stage, .rpc)
      XCTAssertEqual(error.code, .timeout)
    }
    await client.close()
  }

  func testMalformedTunnelResponseUsesTunnelRPCPath() async throws {
    let stream = InMemoryRPCStream()
    let client = RPCClient(stream: stream, path: .tunnel)
    await client.start()

    let call = Task {
      let _: RPCReply = try await client.call(
        7008,
        RPCRequest(value: "malformed"),
        timeout: .seconds(1)
      )
    }
    _ = try await stream.nextWrittenEnvelope()
    try await stream.pushRawFrame(Data("{".utf8))

    do {
      try await call.value
      XCTFail("Expected malformed RPC response")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .tunnel)
      XCTAssertEqual(error.stage, .rpc)
      XCTAssertEqual(error.code, .rpcFailed)
    }
    await client.close()
  }

  func testInvalidTunnelResponsePayloadUsesTunnelRPCPath() async throws {
    let stream = InMemoryRPCStream()
    let client = RPCClient(stream: stream, path: .tunnel)
    await client.start()

    let call = Task {
      let _: RPCReply = try await client.call(
        7009,
        RPCRequest(value: "invalid-payload"),
        timeout: .seconds(1)
      )
    }
    let request = try await stream.nextWrittenEnvelope()
    try await stream.pushEnvelope(
      RPCEnvelope(
        typeID: 7009,
        requestID: 0,
        responseTo: request.requestID,
        payload: Data("{\"unexpected\":true}".utf8),
        error: nil
      )
    )

    do {
      try await call.value
      XCTFail("Expected invalid RPC response payload")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .tunnel)
      XCTAssertEqual(error.stage, .rpc)
      XCTAssertEqual(error.code, .rpcFailed)
    }
    await client.close()
  }

  func testCancelledCallDoesNotRemainPending() async throws {
    let stream = InMemoryRPCStream()
    let client = RPCClient(stream: stream)
    await client.start()

    let task = Task {
      let _: RPCReply = try await client.call(
        7006,
        RPCRequest(value: "cancel"),
        timeout: .seconds(2)
      )
    }
    _ = try await stream.nextWrittenEnvelope()
    task.cancel()

    do {
      try await task.value
      XCTFail("Expected cancellation")
    } catch is CancellationError {
      XCTAssertTrue(true)
    }

    try await stream.pushEnvelope(
      RPCEnvelope(
        typeID: 7006,
        requestID: 0,
        responseTo: 1,
        payload: JSONEncoder.flowersecRPCTest.encode(RPCReply(ok: true)),
        error: nil
      )
    )
    await client.close()
  }

  func testNotificationsAreFIFOAndSnapshotHandlersWithoutBlockingResponses() async throws {
    let stream = InMemoryRPCStream()
    let client = RPCClient(stream: stream)
    let recorder = RPCNotificationRecorder()
    let gate = RPCNotificationGate()
    await client.start()

    let subscription = try await client.subscribeNotification(7100) { data in
      let notification = try? JSONDecoder().decode(RPCNotification.self, from: data)
      guard let value = notification?.value else { return }
      await recorder.append(value)
      if value == "first" { await gate.wait() }
    }

    try await stream.pushEnvelope(notificationEnvelope(typeID: 7100, value: "first"))
    try await waitForRPCCondition { await gate.isStarted() }
    try await stream.pushEnvelope(notificationEnvelope(typeID: 7100, value: "second"))

    async let response: RPCReply = client.call(
      7101,
      RPCRequest(value: "while-notification-blocked"),
      timeout: .seconds(1)
    )
    let request = try await stream.nextWrittenEnvelope()
    try await stream.pushEnvelope(
      RPCEnvelope(
        typeID: request.typeID,
        requestID: 0,
        responseTo: request.requestID,
        payload: JSONEncoder.flowersecRPCTest.encode(RPCReply(ok: true)),
        error: nil
      )
    )
    let decodedResponse = try await response
    XCTAssertEqual(decodedResponse, RPCReply(ok: true))

    await subscription.cancel()
    await gate.release()
    try await waitForRPCCondition { await recorder.count() >= 2 }
    let recordedValues = await recorder.values()
    XCTAssertEqual(recordedValues, ["first", "second"])
    await client.close()
  }

  func testNotificationQueueOverflowTerminatesPendingCalls() async throws {
    let stream = InMemoryRPCStream()
    let client = RPCClient(stream: stream, path: .tunnel)
    let gate = RPCNotificationGate()
    await client.start()
    let subscription = try await client.subscribeNotification(7200) { _ in await gate.wait() }

    try await stream.pushEnvelope(notificationEnvelope(typeID: 7200, value: "active"))
    try await waitForRPCCondition { await gate.isStarted() }

    let pending = Task {
      let _: RPCReply = try await client.call(
        7201,
        RPCRequest(value: "pending"),
        timeout: .seconds(5)
      )
    }
    _ = try await stream.nextWrittenEnvelope()
    for index in 0...FlowersecSDKDefaults.RPC.maxQueuedNotifications {
      try await stream.pushEnvelope(
        notificationEnvelope(typeID: 7200, value: "queued-\(index)")
      )
    }

    do {
      try await pending.value
      XCTFail("Expected notification queue exhaustion")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .tunnel)
      XCTAssertEqual(error.stage, .rpc)
      XCTAssertEqual(error.code, .resourceExhausted)
    }
    await gate.release()
    await subscription.cancel()
    await client.close()
  }

  func testCloseCancelsActiveNotificationAndDropsQueuedWork() async throws {
    let stream = InMemoryRPCStream()
    let client = RPCClient(stream: stream)
    let recorder = RPCNotificationRecorder()
    await client.start()
    let subscription = try await client.subscribeNotification(7300) { data in
      let notification = try? JSONDecoder().decode(RPCNotification.self, from: data)
      guard let value = notification?.value else { return }
      await recorder.append(value)
      do {
        try await Task.sleep(for: .seconds(5))
      } catch is CancellationError {
        await recorder.recordCancellation()
      } catch {}
    }

    try await stream.pushEnvelope(notificationEnvelope(typeID: 7300, value: "active"))
    try await waitForRPCCondition { await recorder.count() >= 1 }
    try await stream.pushEnvelope(notificationEnvelope(typeID: 7300, value: "queued"))
    await client.close()
    try await waitForRPCCondition { await recorder.wasCanceled() }
    let recordedValues = await recorder.values()
    XCTAssertEqual(recordedValues, ["active"])
    await subscription.cancel()
  }

  func testEnvelopeRejectsNonPortableJSONIDs() throws {
    let fixtureData = try Data(
      contentsOf: packageRoot().appendingPathComponent("testdata/runtime_contract_vectors.json")
    )
    let fixture = try XCTUnwrap(
      JSONSerialization.jsonObject(with: fixtureData) as? [String: Any]
    )
    let maximum = try XCTUnwrap(fixture["max_portable_json_integer"] as? NSNumber).uint64Value
    XCTAssertEqual(maximum, RPCEnvelope.maximumPortableID)
    XCTAssertEqual(maximum, RPCClient.maximumPortableRequestID)

    let values = try XCTUnwrap(fixture["rpc_json_integers"] as? [[String: Any]])
    for item in values {
      let identifier = try XCTUnwrap(item["id"] as? String)
      let value = try XCTUnwrap(item["value"])
      let valid = try XCTUnwrap(item["valid"] as? Bool)
      let data = try JSONSerialization.data(
        withJSONObject: [
          "payload": [:],
          "request_id": value,
          "response_to": 0,
          "type_id": 1,
        ],
        options: [.sortedKeys]
      )
      if valid {
        XCTAssertNoThrow(try RPCEnvelope(data: data), identifier)
      } else {
        XCTAssertThrowsError(try RPCEnvelope(data: data), identifier)
      }
    }

    XCTAssertThrowsError(
      try RPCEnvelope(
        typeID: 1,
        requestID: maximum + 1,
        responseTo: 0,
        payload: Data("{}".utf8),
        error: nil
      ).encoded()
    )
  }

  func testClientRequestIDStopsAtPortableMaximum() async throws {
    let fixtureData = try Data(
      contentsOf: packageRoot().appendingPathComponent("testdata/runtime_contract_vectors.json")
    )
    let fixture = try XCTUnwrap(
      JSONSerialization.jsonObject(with: fixtureData) as? [String: Any]
    )
    let generation = try XCTUnwrap(fixture["request_id_generation"] as? [String: Any])
    let first = try XCTUnwrap(generation["first"] as? NSNumber).uint64Value
    let last = try XCTUnwrap(generation["last"] as? NSNumber).uint64Value
    XCTAssertEqual(first, 1)
    XCTAssertEqual(last, RPCClient.maximumPortableRequestID)
    XCTAssertEqual(generation["after_last"] as? String, "fail_before_write")

    let firstStream = InMemoryRPCStream()
    let firstClient = RPCClient(stream: firstStream)
    await firstClient.start()
    async let firstResponse: RPCReply = firstClient.call(
      7400,
      RPCRequest(value: "first"),
      timeout: .seconds(1)
    )
    let firstRequest = try await firstStream.nextWrittenEnvelope()
    XCTAssertEqual(firstRequest.requestID, first)
    try await firstStream.pushEnvelope(
      RPCEnvelope(
        typeID: 7400,
        requestID: 0,
        responseTo: firstRequest.requestID,
        payload: JSONEncoder.flowersecRPCTest.encode(RPCReply(ok: true)),
        error: nil
      )
    )
    _ = try await firstResponse
    await firstClient.close()

    let stream = InMemoryRPCStream()
    let client = RPCClient(
      stream: stream,
      nextRequestID: last
    )
    await client.start()

    async let response: RPCReply = client.call(
      7400,
      RPCRequest(value: "last"),
      timeout: .seconds(1)
    )
    let request = try await stream.nextWrittenEnvelope()
    XCTAssertEqual(request.requestID, last)
    try await stream.pushEnvelope(
      RPCEnvelope(
        typeID: 7400,
        requestID: 0,
        responseTo: request.requestID,
        payload: JSONEncoder.flowersecRPCTest.encode(RPCReply(ok: true)),
        error: nil
      )
    )
    let decodedResponse = try await response
    XCTAssertEqual(decodedResponse, RPCReply(ok: true))

    do {
      let _: RPCReply = try await client.call(
        7400,
        RPCRequest(value: "overflow"),
        timeout: .seconds(1)
      )
      XCTFail("Expected request ID exhaustion")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.stage, .rpc)
      XCTAssertEqual(error.code, .rpcFailed)
    }
    await client.close()
  }

}

private struct SharedRPCErrorVectors: Decodable {
  var maximumMessageBytes: Int
  var cases: [SharedRPCErrorVector]
  var rawCases: [SharedRawRPCErrorVector]

  enum CodingKeys: String, CodingKey {
    case maximumMessageBytes = "maximum_message_bytes"
    case cases
    case rawCases = "raw_cases"
  }
}

private struct SharedRPCErrorVector: Decodable {
  var id: String
  var code: UInt32
  var message: SharedRPCErrorVectorMessage
  var extraField: Bool
  var valid: Bool

  enum CodingKeys: String, CodingKey {
    case id, code, message, valid
    case extraField = "extra_field"
  }
}

private struct SharedRPCErrorVectorMessage: Decodable {
  var presence: String
  var unit: String
  var repeatCount: Int
  var suffix: String

  enum CodingKeys: String, CodingKey {
    case presence, unit, suffix
    case repeatCount = "repeat"
  }
}

private struct SharedRawRPCErrorVector: Decodable {
  var id: String
  var code: UInt32
  var messageHex: String
  var valid: Bool

  enum CodingKeys: String, CodingKey {
    case id, code, valid
    case messageHex = "message_hex"
  }
}

private enum RPCFixtureError: Error {
  case invalidHex
}

private func decodeHex(_ value: String) throws -> Data {
  guard value.count.isMultiple(of: 2) else { throw RPCFixtureError.invalidHex }
  var output = Data()
  var index = value.startIndex
  while index < value.endIndex {
    let end = value.index(index, offsetBy: 2)
    guard let byte = UInt8(value[index..<end], radix: 16) else {
      throw RPCFixtureError.invalidHex
    }
    output.append(byte)
    index = end
  }
  return output
}

private func notificationEnvelope(typeID: UInt32, value: String) throws -> RPCEnvelope {
  RPCEnvelope(
    typeID: typeID,
    requestID: 0,
    responseTo: 0,
    payload: try JSONEncoder.flowersecRPCTest.encode(RPCNotification(value: value)),
    error: nil
  )
}

private func waitForRPCCondition(
  _ condition: @escaping @Sendable () async -> Bool
) async throws {
  for _ in 0..<200 {
    if await condition() { return }
    try await Task.sleep(for: .milliseconds(5))
  }
  throw RPCWaitTimeout()
}

private struct RPCRequest: Codable, Equatable {
  var value: String
}

private struct RPCReply: Codable, Equatable {
  var ok: Bool
}

private struct RPCNotification: Codable, Equatable {
  var value: String
}

private struct IntentionalRPCServerError: Error {}
private struct RPCWaitTimeout: Error {}

private actor RPCNotificationGate {
  private var started = false
  private var released = false
  private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

  func wait() async {
    started = true
    if released { return }
    await withCheckedContinuation { releaseWaiters.append($0) }
  }

  func isStarted() -> Bool { started }

  func release() {
    released = true
    let waiters = releaseWaiters
    releaseWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
  }
}

private actor RPCNotificationRecorder {
  private var recorded: [String] = []
  private var canceled = false

  func append(_ value: String) {
    recorded.append(value)
  }

  func values() -> [String] { recorded }
  func count() -> Int { recorded.count }
  func wasCanceled() -> Bool { canceled }

  func recordCancellation() {
    canceled = true
  }
}
