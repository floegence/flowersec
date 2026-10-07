import Flowersec
import Foundation

// The caller provides original independently issued Artifact and certificate
// material, a trusted attempt/recipient, explicit control TLS identity and
// independent durable backing. Register before publishing this binding to the
// authority. The server-allow ACK is emitted by the native SDK listener only
// after that original server carrier is prepared.
func makeLiveServer(environment: TransportEnvironment, identity: TransportApplicationIdentity,
  sourceConfiguration: TransportLiveServerSourceConfiguration,
  originalMaterial: TransportLiveServerMaterial
) async throws -> (TransportLiveServerSource, TransportLiveServerBinding) {
  let source = try await environment.makeLiveServerSource(sourceConfiguration, identity: identity)
  do { return (source, try source.registerOriginal(originalMaterial)) }
  catch { source.close(); _ = try? await source.waitCleanup(); throw error }
}

// The original verified route fixes whether this server dials or listens.
// Acquisition transfers the prepared physical carrier and prepaid resources;
// closing the Source later does not cancel that material or its Session.
func connectLiveServer(environment: TransportEnvironment, source: TransportLiveServerSource) async throws -> any Session {
  try await environment.connect(source: source.materialSource)
}

// Use the explicit acceptance requirement only for a signed listener route.
func acceptLiveServer(environment: TransportEnvironment, source: TransportLiveServerSource) async throws -> any Session {
  try await environment.accept(source: source.materialSource)
}

// Each publication is an independently configured original TxB input. This
// host keeps one durable ledger across all queued runs. Admission rejects a
// duplicate before it enters the queue, including after a canceled run.
func publishLiveRelay(host: RelayHost, original: TransportLiveRelayPublication) throws -> RelayPublication {
  try host.publishLiveOriginal(original)
}

// Install this independent deployment before the client's native Prepare.
// Start host.run() and await initialPublication.waitListening() before Connect.
// The caller owns cancellation and waitCleanup(). Source control
// configuration points relayPreparation at the pinned preparation endpoint.
func makeRegisteredLiveRelay(environment: TransportEnvironment, identity: TransportApplicationIdentity,
  registration: TransportLiveRelayRegistration, claims: RelayClaimStoreConfiguration
) async throws -> RelayHost {
  try await environment.makeRelayHost(RelayHostConfiguration(registeredLive: registration, claims: claims), identity: identity)
}

// Start the daemon and join original local listener/control readiness before
// constructing or connecting the live client Source. If startup fails, stop
// the daemon and join its callbacks before returning the error.
func startRegisteredLiveRelay(_ host: RelayHost) async throws -> Task<Void, any Error> {
  let run = Task { try await host.run() }
  do {
    try await host.initialPublication.waitListening()
    return run
  } catch {
    await host.stop()
    _ = try? await run.value
    throw error
  }
}

// Install this configuration on the TransportEnvironment's pool history, then share it
// with relay and live-server domains for the same parent. Retain the authority
// for the whole admission-service lifetime.
func makeCommonParentWinner(environment: TransportEnvironment, configuration: ParentWinnerStoreConfiguration
) async throws -> ParentWinnerAuthority {
  let authority = try await environment.makeParentWinnerAuthority(configuration)
  do {
    try await environment.installParentWinnerAuthority(authority.configuration)
    return authority
  } catch {
    authority.close()
    throw error
  }
}
