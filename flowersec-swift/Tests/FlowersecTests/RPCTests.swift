import Foundation
import XCTest

@testable import Flowersec

final class FlowersecRPCTests: XCTestCase {
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
    let subscription = client.onNotify(7003) { data in
      let decoded = try? JSONDecoder().decode(RPCReply.self, from: data)
      XCTAssertEqual(decoded, RPCReply(ok: true))
      expectation.fulfill()
    }
    await Task.yield()

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
    subscription.cancel()
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
      XCTAssertEqual(error, .timeout)
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

}

private struct RPCRequest: Codable, Equatable {
  var value: String
}

private struct RPCReply: Codable, Equatable {
  var ok: Bool
}
