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
  let streamHandlers = try StreamHandlers()
  try streamHandlers.handleStream(kind: "application.stream") { _ in }

  _ = parse
  _ = connectAttempt
  _ = rpcCall
  _ = notificationSubscription
  _ = streamHandlers
}

@Test
func retryDispositionsMatchPortableContract() {
  #expect(ConnectErrorV2.invalidOptions.retryDispositionV2 == .terminal)
  #expect(ConnectError.expiredArtifact.retryDisposition == .retryable)
  #expect(ConnectError.canceled.code == .connectionFailed)
  #expect(ConnectError.canceled.retryDisposition == .terminal)
  #expect(SessionError.canceled.retryDispositionV2 == .terminal)
  #expect(SessionError.closed.retryDispositionV2 == .retryable)

  let deadline = Date(timeIntervalSince1970: 1_234)
  #expect(RetryDispositionV2.retryAfter(deadline) == .retryAfter(deadline))
  #expect(RetryDispositionV3.retryAfter(1_234_000) == .retryAfter(1_234_000))
}

@available(*, deprecated)
@Test
func versionedCompatibilityAliasesStillCompile() async throws {
  let parse: (Data) throws -> ArtifactV3 = parseArtifactV3
  let connectAttempt: @Sendable (ArtifactLeaseV3, ConnectorOptions) async throws -> any Session = {
    lease, options in
    try await connectV3(lease: lease, options: options)
  }
  let retry: RetryDisposition = .terminal

  _ = parse
  _ = connectAttempt
  _ = retry
}
