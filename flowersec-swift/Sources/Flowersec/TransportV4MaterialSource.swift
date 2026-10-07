import Foundation

#if os(macOS) || os(iOS)
/// A source generation owns encoded, already issued pool records and one
/// immutable local key handle. It never obtains authority or replenishes itself.
private final class V4PoolSourceGeneration: @unchecked Sendable {
  let identity: TransportApplicationIdentity
  let generation: UInt64
  let role: V4CryptoRole
  let storage: V4CryptoReservation
  private var credentials: [TransportPoolCredential?]
  private let profiles: [UInt64]
  private var next = 0
  init(client: V4ClientEnvironment, credentials: [TransportPoolCredential],
    identity: TransportApplicationIdentity, generation: UInt64) throws {
    guard generation > 0, (1...64).contains(credentials.count) else { throw TransportConnectError.invalidMaterial }
    guard let first = credentials.first, credentials.allSatisfy({ $0.input.localRole == first.input.localRole }) else { throw TransportConnectError.invalidMaterial }
    role = first.input.localRole
    try identity.owner.check(in: client.foundation)
    var bytes = 0
    for credential in credentials {
      let value = credential.input
      guard (1...65_536).contains(value.artifact.count), (1...8192).contains(value.clientCertificate.count),
        (1...8192).contains(value.serverCertificate.count), (1...65_536).contains(value.activation.count),
        (0..<16).contains(value.candidateIndex), value.source == .preauthorizedPool else { throw TransportConnectError.invalidMaterial }
      var allowBytes = 0
      if let allow = value.poolServerAllow {
        let c = allow.control
        guard (1...9302).contains(allow.grant.count), allow.recipient.count == 16, allow.incarnation.count == 16,
          (1...16).contains(c.trustRootsPEM.count),
          c.trustRootsPEM.reduce(0, { $0 + $1.count }) <= 262_144,
          (1...65_536).contains(c.clientCertificatePEM.count), (1...16_384).contains(c.clientPrivateKeyPEM.count)
        else { throw TransportConnectError.invalidMaterial }
        allowBytes = allow.grant.count + allow.recipient.count + allow.incarnation.count
          + c.trustRootsPEM.reduce(0, { $0 + $1.count }) + c.clientCertificatePEM.count + c.clientPrivateKeyPEM.count
      }
      let count = value.artifact.count + value.clientCertificate.count + value.serverCertificate.count + value.activation.count
        + value.grant.count + value.relayCertificate.count
        + value.poolTunnels.reduce(0) { $0 + $1.grant.count + $1.relayCertificate.count }
        + allowBytes
      guard count <= (16 << 20) - bytes else { throw TransportConnectError.invalidMaterial }
      bytes += count
    }
    // Admit the retained aliases and profile metadata before their allocation.
    // Each subsequent verification also owns its original bounded work charge.
    let storage = try client.foundation.materialSourceStorage(bytes: bytes, items: credentials.count)
    var profiles: [UInt64] = []
    profiles.reserveCapacity(credentials.count)
    for credential in credentials {
      // Static source publication checks the complete signed certificate and
      // key/profile pair; Acquire and consumption recheck current authority.
      profiles.append(try client.validatePoolCredential(credential, identity: identity))
    }
    self.storage = storage
    self.identity = identity; self.generation = generation; self.credentials = credentials.map { Optional($0) }; self.profiles = profiles
  }
  func checkRequirements(_ requirements: ConnectionRequirements, client: V4ClientEnvironment) throws {
    try storage.check()
    guard next < credentials.count, let credential = credentials[next] else { throw ConnectionMaterialSourceError.exhausted }
    if let requested = requirements.applicationProfile {
      let expected: UInt64 = requested == "transport" ? 0 : requested == "services" ? 1 : 2
      guard profiles[next] == expected else { throw TransportConnectError.unsupported }
    }
    _ = try client.validatePoolCredential(credential, identity: identity, requirements: requirements)
  }
  func take(_ requirements: ConnectionRequirements, client: V4ClientEnvironment) throws -> TransportPoolCredential {
    try checkRequirements(requirements, client: client)
    guard let credential = credentials[next] else { throw ConnectionMaterialSourceError.exhausted }
    credentials[next] = nil; next += 1; return credential
  }
}

/// The SDK owns the closed preauthorized-pool variant and its provider binding.
/// No callback can substitute another identity or activation-source profile.
final class V4PoolMaterialSource: V4ConfiguredMaterialSourceOwner, V4NativeConnectionLifecycle, @unchecked Sendable {
  private let client: V4ClientEnvironment
  let incarnation: Data
  private var current: V4PoolSourceGeneration?
  private var closed = false
  private var acquired: UInt64 = 0
  init(client: V4ClientEnvironment, credentials: [TransportPoolCredential],
    identity: TransportApplicationIdentity, generation: UInt64) throws {
    self.client = client; incarnation = try V4Crypto.random(16)
    current = try V4PoolSourceGeneration(client: client, credentials: credentials, identity: identity, generation: generation)
  }
  var acquisitionCount: UInt64 { client.foundation.gate.withLock { acquired } }
  func check(in environment: V4EnvironmentFoundation) throws {
    try client.foundation.gate.withLock {
      guard environment === client.foundation else { throw TransportConnectError.invalidMaterial }
      guard !closed, let snapshot = current else { throw ConnectionMaterialSourceError.closed }
      try snapshot.storage.check(); try snapshot.identity.owner.check(in: environment)
    }
  }
  func checkRequirements(_ requirements: ConnectionRequirements, in environment: V4EnvironmentFoundation) throws {
    try client.foundation.gate.withLock {
      try V4DirectEstablishment.requirements(requirements)
      try check(in: environment)
      guard let snapshot = current else { throw ConnectionMaterialSourceError.closed }
      try snapshot.checkRequirements(requirements, client: client)
    }
  }
  func acquire(_ requirements: ConnectionRequirements) async throws -> ConnectionMaterial {
    try V4DirectEstablishment.requirements(requirements)
    return try client.foundation.gate.withLock {
      guard !closed, let snapshot = current else { throw ConnectionMaterialSourceError.closed }
      // Capture the complete identity/profile/generation before reading its
      // issued record. Provider, roots and authorities are fixed by client.
      try snapshot.identity.owner.check(in: client.foundation)
      let credential = try snapshot.take(requirements, client: client)
      if acquired < .max { acquired += 1 }
      let material = try client.material(credential, identity: snapshot.identity)
      guard let original = material.owner as? V4DirectPoolMaterial else { throw TransportConnectError.invalidMaterial }
      try original.captureSource(incarnation: incarnation, generation: snapshot.generation)
      return material
    }
  }
  func replace(_ credentials: [TransportPoolCredential], identity: TransportApplicationIdentity) throws {
    try client.foundation.gate.withLock {
      guard !closed, let old = current else { throw ConnectionMaterialSourceError.closed }
      guard old.generation < .max else { throw ConnectionMaterialSourceError.generationConflict }
      let candidate = try V4PoolSourceGeneration(client: client, credentials: credentials.map { TransportPoolCredential(input: $0.input.withRole(old.role)) }, identity: identity, generation: old.generation + 1)
      current = candidate
    }
  }
  func close() { client.foundation.gate.withLock { closed = true; current = nil } }
  func cleanupStatus() -> CleanupStatus { client.foundation.gate.withLock { CleanupStatus(complete: closed) } }
  func waitCleanup() async throws -> CleanupStatus { cleanupStatus() }
  deinit { close() }
}
#endif
