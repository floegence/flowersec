import Foundation
import Testing

@testable import Flowersec

private struct PublicRequest: Codable, Sendable {
  let value: String
}

private struct PublicResponse: Codable, Sendable {
  let accepted: Bool
}

private struct PublicNotification: Codable, Sendable {
  let state: String
}

@Test
func unversionedOneShotPublicAPICompiles() async throws {
  let parse: (Data) throws -> Artifact = parseArtifact
  let connectAttempt: @Sendable (ArtifactLease, ConnectorOptions) async throws -> any Session = {
    lease, options in
    try await connect(lease: lease, options: options)
  }
  let rpcCall: @Sendable (any RPCPeer) async throws -> PublicResponse = { peer in
    try await peer.call(
      7, PublicRequest(value: "request"), as: PublicResponse.self, timeout: .seconds(1))
  }
  let notificationSubscription: @Sendable (any RPCPeer) async throws ->
    any RPCNotificationSubscription = { peer in
      try await peer.subscribeNotification(9_002, as: PublicNotification.self) { result in
        _ = try result.get()
      }
    }

  _ = parse
  _ = connectAttempt
  _ = rpcCall
  _ = notificationSubscription
}

@Test
func retryDispositionsMatchPortableContract() {
  #expect(ConnectError.invalidOptions.retryDisposition == .terminal)
  #expect(ConnectError.expiredArtifact.retryDisposition == .retryable)
  #expect(SessionError.canceled.retryDisposition == .terminal)
  #expect(SessionError.closed.retryDisposition == .retryable)

  let deadline = Date(timeIntervalSince1970: 1_234)
  #expect(RetryDisposition.retryAfter(deadline) == .retryAfter(deadline))
}
