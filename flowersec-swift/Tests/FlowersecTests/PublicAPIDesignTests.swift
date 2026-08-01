import Foundation
import Testing

@testable import Flowersec

private struct PublicRequest: Codable, Sendable {
  let value: String
}

private struct PublicResponse: Codable, Sendable {
  let accepted: Bool
}

@Test
func unversionedOneShotPublicAPICompiles() async throws {
  let parse: (Data) throws -> Artifact = parseArtifact
  let connectAttempt: @Sendable (ArtifactLease, ConnectorOptions) async throws -> any Session = {
    lease, options in
    try await connect(lease: lease, options: options)
  }
  let rpcCall: @Sendable (any RPCPeer) async throws -> PublicResponse = { peer in
    try await peer.call(7, PublicRequest(value: "request"), as: PublicResponse.self, timeout: .seconds(1))
  }

  _ = parse
  _ = connectAttempt
  _ = rpcCall
}

@Test
func recoveryActionNamesMatchPortableContract() {
  #expect(RetryAction.retry.rawValue == "retry")
  #expect(RetryAction.refreshArtifact.rawValue == "refresh_artifact")
  #expect(RetryAction.stop.rawValue == "stop")
  #expect(classifySessionError(.closed).refreshArtifact)
  #expect(classifySessionError(.closed).sessionClosed)
}
