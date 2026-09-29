import Flowersec
import Foundation
import Testing

struct TransportV4PublicAPITests {
  @Test func metadataUsesPublicValidatedBinaryAPI() throws {
    let metadata = try StreamMetadata(
      namespace: "acme/chat", version: 1,
      values: ["content-type": Data("application/octet-stream".utf8)])
    let decoded = try StreamMetadata(encodedV4: metadata.encodedV4())
    #expect(decoded.v4Namespace == "acme/chat")
    #expect(decoded.v4Version == 1)
    #expect(decoded.v4Values?["content-type"] == Data("application/octet-stream".utf8))
  }

  @Test func unconfiguredPublicEnvironmentDoesNotAcquire() async throws {
    let environment = TransportEnvironment()
    do {
      _ = try await environment.connect(source: UnavailableSource())
      Issue.record("unconfigured Environment acquired material")
    } catch TransportV4AvailabilityError.runtimeUnavailable {}
    try await environment.close()
    #expect(await environment.cleanupStatus().complete)
  }
}

private struct UnavailableSource: ConnectionMaterialSource {
  func acquire(_ requirements: ConnectionRequirements) async throws -> ConnectionMaterial {
    Issue.record("unconfigured Environment invoked the source")
    throw SessionError.operationFailed
  }
}

#if os(macOS) || os(iOS)
  // Type-check the owned public factory without importing implementation symbols
  // or exercising deployment adapters with fabricated trust or history.
  private func configuredPublicSurface(
    configuration: TransportV4ClientConfiguration, credential: TransportV4PoolCredential,
    signingSeed: Data, staticKey: Data, head: Data, state: Data
  ) async throws -> any Session {
    let environment = try await TransportEnvironment(configuration: configuration)
    try await environment.refreshTrustedTime()
    try await environment.refreshNamespace(
      authority: configuration.namespaces[0].authority,
      head: head, state: state)
    let identity = try await environment.importApplicationIdentity(
      profile: .x25519,
      signingSeed: signingSeed, noiseStaticPrivateKey: staticKey)
    let material = try await environment.preparePoolMaterial(credential, identity: identity)
    return try await environment.connectMaterial(
      material,
      requirements: ConnectionRequirements(
        localConsumerTLS13Verification: true,
        applicationProfile: "transport"))
  }
#endif
