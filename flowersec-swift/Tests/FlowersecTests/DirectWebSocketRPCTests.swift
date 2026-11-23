#if os(macOS)
import Foundation
import XCTest

import Flowersec

final class DirectWebSocketRPCTests: XCTestCase {
  func testManyMethodsWithOneInFlightInEachDirection() async throws {
    let methods = (0..<64).map { UInt32(10_000 + $0) }
    var handlers = RPCHandlers()
    for method in methods {
      try handlers.register(method, context: String.self) { (role: String, sequence: Int) in
        "\(role):\(method):\(sequence)"
      }
    }
    let fixtures = Bundle.module.resourceURL!.appendingPathComponent("Fixtures")
    let origin = "https://app.example"
    let grants = AsyncStream.makeStream(of: DirectAdmissionGrant.self)
    let accepted = AsyncStream.makeStream(of: (any Session).self)
    let listener = try await DirectWebSocketListener.listen(
      bindAddress: "127.0.0.1", port: 0, allowedOrigins: [origin],
      certificateChainPEM: Data(contentsOf: fixtures.appendingPathComponent("self_signed_cert.pem")),
      privateKeyPEM: Data(contentsOf: fixtures.appendingPathComponent("self_signed_key.pem")),
      maxConcurrentRPCRequests: 1,
      authorize: { _ in var iterator = grants.stream.makeAsyncIterator(); return await iterator.next() },
      onSession: { session, _ in
        accepted.continuation.yield(session); accepted.continuation.finish()
        _ = await session.waitTermination()
      })
    do {
      let wire = try TransportV3Tests.validArtifact(endpoint: "wss://127.0.0.1:\(listener.port)/flowersec/v5/direct")
      weak var admittedArtifact: Artifact?
      do {
        let artifact = try parseArtifact(wire)
        admittedArtifact = artifact
        grants.continuation.yield(DirectAdmissionGrant(artifact: artifact, handlers: handlers.bound(to: "server")) {})
      }
      grants.continuation.finish()
      let client = try await connect(lease: ArtifactLease(artifact: parseArtifact(wire)) {}, options: ConnectorOptions(
        origin: origin, connectTimeout: .seconds(5),
        trustRootsPEM: [try Data(contentsOf: fixtures.appendingPathComponent("self_signed_ca.pem"))],
        rpcHandlers: handlers.bound(to: "client"), maxConcurrentRPCRequests: 1))
      var iterator = accepted.stream.makeAsyncIterator()
      let incoming = await iterator.next()
      let server = try XCTUnwrap(incoming)
      XCTAssertNil(admittedArtifact, "the application callback should not keep the spent invitation alive")
      for sequence in 0..<(3 * methods.count) {
        let forward = methods[sequence % methods.count]
        let reverse = methods[methods.count - 1 - sequence % methods.count]
        async let forwardReply = client.rpc.call(forward, sequence, as: String.self, timeout: .seconds(5))
        async let reverseReply = server.rpc.call(reverse, sequence, as: String.self, timeout: .seconds(5))
        let replies = try await (forwardReply, reverseReply)
        XCTAssertEqual(replies.0, "server:\(forward):\(sequence)")
        XCTAssertEqual(replies.1, "client:\(reverse):\(sequence)")
      }
      try await client.close()
    } catch {
      grants.continuation.finish(); accepted.continuation.finish(); await listener.close(); throw error
    }
    await listener.close()
    await listener.waitClosed()
  }
}
#endif
