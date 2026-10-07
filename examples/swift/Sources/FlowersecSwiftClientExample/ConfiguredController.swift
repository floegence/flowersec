import Flowersec
import Foundation

// The caller supplies the existing trusted namespace/time assembly, explicit
// control TLS identity and application private keys. This recipe neither signs
// credentials nor infers an authority from network response fields.
func makeLiveController(environmentConfiguration: TransportClientConfiguration,
  sourceConfiguration: TransportLiveAuthoritySourceConfiguration,
  profile: TransportCryptoProfile, signingSeed: Data, staticPrivateKey: Data,
  initializeSession: (@isolated(any) @Sendable (any Session) async throws -> Void)? = nil
) async throws -> (TransportEnvironment, ConnectionMaterialSource, ConnectionController) {
  let environment = try await TransportEnvironment(configuration: environmentConfiguration)
  do {
    let identity = try await environment.importApplicationIdentity(profile: profile,
      signingSeed: signingSeed, noiseStaticPrivateKey: staticPrivateKey)
    let source = try await environment.makeConnectionMaterialSource(.liveAuthority(sourceConfiguration), identity: identity)
    let controller = try ConnectionController(environment: environment, source: source,
      requirements: ConnectionRequirements(localConsumerTLS13Verification: true,
        applicationProfile: sourceConfiguration.applicationProfile), initializeSession: initializeSession)
    await controller.start()
    // Each later transport attempt uses this same configured source and issues
    // a fresh lease. The controller does not replay the application's stream.
    return (environment, source, controller)
  } catch { try? await environment.close(); throw error }
}

// Capture once before starting a long-lived terminal/editor transfer. A later
// controller reconnection cannot redirect any read, FIN or cleanup below.
// This function owns only its stream; the caller owns the shared controller.
func consumeCapturedStream(controller: ConnectionController, kind: String,
  request: Data, receive: @Sendable (Data) async throws -> Void) async throws {
  let session = try await controller.waitForSession()
  let stream = try await session.openStream(kind: kind)
  do {
    var offset = 0
    while offset < request.count {
      try Task.checkCancellation()
      let count = try await stream.write(Data(request.dropFirst(offset)))
      guard count > 0 else { throw EngineeringMaterialError.bootstrapFailed }
      offset += count
    }
    try await stream.finish()
    while let chunk = try await stream.read(maxBytes: 16_384) {
      try Task.checkCancellation()
      try await receive(chunk)
    }
    try await stream.close()
  } catch { try? await stream.close(); throw error }
}
