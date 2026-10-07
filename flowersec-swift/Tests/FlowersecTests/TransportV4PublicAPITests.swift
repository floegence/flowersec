import Flowersec
import Foundation
import Testing

struct TransportPublicAPITests {
  @Test func metadataUsesPublicValidatedBinaryAPI() throws {
    let metadata = try StreamMetadata(
      namespace: "acme/chat", version: 1,
      values: ["content-type": Data("application/octet-stream".utf8)])
    let decoded = try StreamMetadata(encoded: metadata.encoded())
    #expect(decoded.namespace == "acme/chat")
    #expect(decoded.version == 1)
    #expect(decoded.byteValues?["content-type"] == Data("application/octet-stream".utf8))
  }

  @Test func unconfiguredPublicEnvironmentClosesIdempotently() async throws {
    let environment = TransportEnvironment()
    try await environment.close(); try await environment.close()
    #expect(await environment.cleanupStatus().complete)
  }
}


#if os(macOS) || os(iOS)
  // Type-check the owned public factory without importing implementation symbols
  // or exercising deployment adapters with fabricated trust or history.
  private func configuredPublicSurface(
    configuration: TransportClientConfiguration, credential: TransportPoolCredential,
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
    let source = try await environment.makePreauthorizedPoolSource([credential], identity: identity)
    return try await environment.connect(
      source: source,
      requirements: ConnectionRequirements(
        localConsumerTLS13Verification: true,
        applicationProfile: "transport"))
  }
#endif

#if os(macOS) || os(iOS)
  private func configuredLiveSourceSurface(environment: TransportEnvironment,
    configuration: TransportLiveAuthoritySourceConfiguration,
    identity: TransportApplicationIdentity) async throws -> any Session {
    let source = try await environment.makeConnectionMaterialSource(.liveAuthority(configuration), identity: identity)
    return try await environment.connect(source: source,
      requirements: ConnectionRequirements(localConsumerTLS13Verification: true, applicationProfile: configuration.applicationProfile))
  }
  private func explicitMaterialSurface(environment: TransportEnvironment, material: ConnectionMaterial) async throws -> any Session {
    try await environment.connectMaterial(material)
  }
  private func originalLiveServerSurface(environment: TransportEnvironment,
    configuration: TransportLiveServerSourceConfiguration, original: TransportLiveServerMaterial,
    identity: TransportApplicationIdentity) async throws -> any Session {
    let source = try await environment.makeLiveServerSource(configuration, identity: identity)
    let binding: TransportLiveServerBinding = try source.registerOriginal(original)
    _ = binding.incarnation
    return try await environment.connect(source: source.materialSource)
  }
  private func registeredRelaySurface(environment: TransportEnvironment, identity: TransportApplicationIdentity,
    original: TransportLiveRelayRegistration, claims: RelayClaimStoreConfiguration,
    winners: ParentWinnerStoreConfiguration) async throws -> (ParentWinnerAuthority, RelayHost, RelayPublication) {
    let authority = try await environment.makeParentWinnerAuthority(winners)
    let host = try await environment.makeRelayHost(RelayHostConfiguration(registeredLive: original, claims: claims), identity: identity)
    let publication = try host.registerLiveOriginal(original)
    return (authority, host, publication)
  }
  private func continuousRelaySurface(environment: TransportEnvironment, configuration: RelayHostConfiguration,
    identity: TransportApplicationIdentity, original: TransportLiveRelayPublication) async throws -> (RelayHost, RelayPublication) {
    let host = try await environment.makeRelayHost(configuration, identity: identity)
    let publication = try host.publishLiveOriginal(original)
    return (host, publication)
  }
#endif
