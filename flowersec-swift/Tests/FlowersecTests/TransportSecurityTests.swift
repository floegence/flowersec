import Foundation
import XCTest

@testable import Flowersec

final class TransportSecurityTests: XCTestCase {
  func testTransportSecurityPresets() async throws {
    let allowed: [(TransportSecurityPolicy, String)] = [
      (.requireTLS, "wss://example.com/ws"),
      (.allowPlaintextForLoopback, "ws://localhost/ws"),
      (.allowPlaintextForLoopback, "ws://127.42.0.9/ws"),
      (.allowPlaintextForLoopback, "ws://[::1]/ws"),
      (.allowPlaintext, "ws://example.com/ws"),
    ]
    for (policy, rawURL) in allowed {
      let url = try XCTUnwrap(URL(string: rawURL))
      try await FlowersecTransportSecurity.enforce(
        url: url,
        path: .direct,
        options: ConnectOptions(transportSecurityPolicy: policy)
      )
    }

    let denied: [(TransportSecurityPolicy, String)] = [
      (.requireTLS, "ws://127.0.0.1/ws"),
      (.allowPlaintextForLoopback, "ws://localhost.example/ws"),
      (.allowPlaintextForLoopback, "ws://127.1/ws"),
      (.allowPlaintextForLoopback, "ws://127.0.00.1/ws"),
      (.allowPlaintextForLoopback, "ws://2130706433/ws"),
      (.allowPlaintextForLoopback, "ws://loopback.example/ws"),
    ]
    for (policy, rawURL) in denied {
      let url = try XCTUnwrap(URL(string: rawURL))
      do {
        try await FlowersecTransportSecurity.enforce(
          url: url,
          path: .tunnel,
          options: ConnectOptions(transportSecurityPolicy: policy)
        )
        XCTFail("Expected policy denial for \(rawURL)")
      } catch let error as FlowersecError {
        XCTAssertEqual(error.path, .tunnel)
        XCTAssertEqual(error.stage, .validate)
        XCTAssertEqual(error.code, .transportPolicyDenied)
      }
    }
  }

  func testCustomPolicyReceivesSanitizedInput() async throws {
    let called = expectation(description: "custom transport policy")
    let policy = TransportSecurityPolicy.custom { input in
      XCTAssertEqual(input.path, .tunnel)
      XCTAssertEqual(input.scheme, "wss")
      XCTAssertEqual(input.host, "example.com")
      XCTAssertEqual(input.runtime, .swift)
      called.fulfill()
      return true
    }
    let url = try XCTUnwrap(URL(string: "wss://example.com/private?token=secret"))
    try await FlowersecTransportSecurity.enforce(
      url: url,
      path: .tunnel,
      options: ConnectOptions(transportSecurityPolicy: policy)
    )
    await fulfillment(of: [called], timeout: 1)
  }

  func testMissingPolicyEmitsPlaintextDiagnostic() async throws {
    let emitted = expectation(description: "plaintext diagnostic")
    let url = try XCTUnwrap(URL(string: "ws://example.com/ws"))
    var options = ConnectOptions()
    options.onTransportSecurityDiagnostic = { event in
      XCTAssertEqual(event.code, "plaintext_transport")
      XCTAssertEqual(event.path, .direct)
      XCTAssertEqual(event.scheme, "ws")
      XCTAssertEqual(event.host, "example.com")
      emitted.fulfill()
    }
    try await FlowersecTransportSecurity.enforce(url: url, path: .direct, options: options)
    await fulfillment(of: [emitted], timeout: 1)
  }
}
