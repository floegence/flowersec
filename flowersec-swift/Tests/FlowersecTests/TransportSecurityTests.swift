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

  func testNetworkPlaintextPolicyAllowsOnlyExplicitCanonicalIPHosts() async throws {
    let policy = try TransportSecurityPolicy.networkPlaintext(options: .init(
      allowedHosts: ["192.168.1.20", "2001:db8::20"],
      riskAcceptance: .acceptPreE2ECredentialExposure
    ))
    let allowed = [
      "wss://service.example/ws",
      "ws://192.168.1.20/ws",
      "ws://[2001:db8::20]/ws",
    ]
    for raw in allowed {
      var options = ConnectOptions()
      options.transportSecurityPolicy = policy
      try await FlowersecTransportSecurity.enforce(url: try XCTUnwrap(URL(string: raw)), path: .direct, options: options)
    }
    for raw in ["ws://192.168.1.21/ws", "ws://127.0.0.1/ws"] {
      var options = ConnectOptions()
      options.transportSecurityPolicy = policy
      do {
        try await FlowersecTransportSecurity.enforce(url: try XCTUnwrap(URL(string: raw)), path: .direct, options: options)
        XCTFail("Expected network plaintext policy denial for \(raw)")
      } catch let error as FlowersecError {
        XCTAssertEqual(error.code, .transportPolicyDenied)
      }
    }
  }

  func testNetworkPlaintextPolicyRejectsUnsafeOptions() throws {
    let unsafeHosts = [
      "localhost",
      "127.0.0.1",
      "0.0.0.0",
      "example.com",
      "192.168.001.20",
      "[2001:db8::20]",
      "fe80::1",
      "::ffff:c0a8:114",
    ]
    XCTAssertThrowsError(try TransportSecurityPolicy.networkPlaintext(options: .init(
      allowedHosts: [],
      riskAcceptance: .acceptPreE2ECredentialExposure
    )))
    for host in unsafeHosts {
      XCTAssertThrowsError(try TransportSecurityPolicy.networkPlaintext(options: .init(
        allowedHosts: [host],
        riskAcceptance: .acceptPreE2ECredentialExposure
      )))
    }
  }

  func testDefaultPolicyRejectsPlaintextWithoutDiagnostic() async throws {
    let emitted = expectation(description: "plaintext diagnostic")
    emitted.isInverted = true
    let url = try XCTUnwrap(URL(string: "ws://example.com/ws"))
    var options = ConnectOptions()
    options.onTransportSecurityDiagnostic = { _ in emitted.fulfill() }
    do {
      try await FlowersecTransportSecurity.enforce(url: url, path: .direct, options: options)
      XCTFail("Expected the default policy to deny plaintext")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.code, .transportPolicyDenied)
    }
    await fulfillment(of: [emitted], timeout: 0.05)
  }

  func testExplicitPlaintextPolicyEmitsDiagnostic() async throws {
    for (policy, rawURL) in [
      (TransportSecurityPolicy.allowPlaintext, "ws://example.com/ws"),
      (.allowPlaintextForLoopback, "ws://localhost/ws"),
    ] {
      let emitted = expectation(description: "plaintext diagnostic")
      let genericEmitted = expectation(description: "generic plaintext diagnostic")
      let url = try XCTUnwrap(URL(string: rawURL))
      let options = ConnectOptions(
        transportSecurityPolicy: policy,
        onTransportSecurityDiagnostic: { event in
          XCTAssertEqual(event.code, "plaintext_transport")
          XCTAssertEqual(event.path, .direct)
          XCTAssertEqual(event.scheme, "ws")
          emitted.fulfill()
        },
        onDiagnosticEvent: { event in
          XCTAssertEqual(event.v, 1)
          XCTAssertEqual(event.namespace, "connect")
          XCTAssertEqual(event.path, .direct)
          XCTAssertEqual(event.stage, .transport)
          XCTAssertEqual(event.codeDomain, .event)
          XCTAssertEqual(event.code, "plaintext_transport")
          XCTAssertEqual(event.result, .skip)
          XCTAssertEqual(event.resource, "websocket_transport")
          genericEmitted.fulfill()
        }
      )
      try await FlowersecTransportSecurity.enforce(url: url, path: .direct, options: options)
      await fulfillment(of: [emitted, genericEmitted], timeout: 1)
    }
  }

  func testConnectOptionHardeningDefaults() {
    let options = ConnectOptions()
    if case .requireTLS = options.transportSecurityPolicy {} else {
      XCTFail("Expected TLS by default")
    }
    XCTAssertEqual(options.handshakeTimeout, .seconds(10))
    XCTAssertEqual(options.outboundRecordChunkBytes, 64 * 1024)
    XCTAssertEqual(options.maxOutboundBufferedBytes, 4 * 1024 * 1024)
    XCTAssertEqual(options.yamuxLimits, YamuxLimits())
    XCTAssertEqual(options.liveness, .pathDefault)
    XCTAssertTrue(options.scopeResolvers.isEmpty)
    XCTAssertFalse(options.relaxedOptionalScopeValidation)
  }

  func testConnectRejectsNonPositiveHandshakeAndOutboundBufferLimits() async throws {
    let info = DirectConnectInfo(
      wsURL: URL(string: "wss://example.invalid/ws")!,
      channelID: "channel-option-test",
      psk: Data(repeating: 0x2a, count: 32),
      channelInitExpiresAtUnixS: Int64(Date().timeIntervalSince1970) + 60,
      defaultSuite: .x25519HKDFSHA256AES256GCM
    )
    let invalidOptions = [
      ConnectOptions(handshakeTimeout: .zero),
      ConnectOptions(maxOutboundBufferedBytes: 0),
    ]
    for options in invalidOptions {
      do {
        _ = try await Flowersec.connectDirect(info, options: options)
        XCTFail("Expected invalid connect options to fail before opening the transport")
      } catch let error as FlowersecError {
        XCTAssertEqual(error.path, .direct)
        XCTAssertEqual(error.stage, .validate)
        XCTAssertEqual(error.code, .invalidOption)
      }
    }
  }
}
