#if os(macOS) || os(iOS)
import Crypto
import Darwin
import Foundation
import SQLite3

/// Independent, durable host continuity is required whenever an existing
/// claim store is reopened. Existing rows can refuse replay but cannot restart
/// an authenticated hop or restore a forwarding capability.
public struct RelayClaimStoreConfiguration: Sendable {
  public let parentWinner: ParentWinnerAuthorityConfiguration?
  public let directory: URL
  public let backingIdentity: Data
  public let create: Bool
  public let maximumRows: Int
  public let maximumBytes: Int
  public let checkContinuity: @Sendable (Data) throws -> Void
  public init(directory: URL, backingIdentity: Data, create: Bool, maximumRows: Int = 4096,
    maximumBytes: Int = 16 << 20, parentWinner: ParentWinnerAuthorityConfiguration? = nil, checkContinuity: @escaping @Sendable (Data) throws -> Void) {
    self.parentWinner = parentWinner; self.directory = directory; self.backingIdentity = backingIdentity; self.create = create
    self.maximumRows = maximumRows; self.maximumBytes = maximumBytes; self.checkContinuity = checkContinuity
  }
}

/// A continuous relay with a bounded queue of independently issued publications.
/// Original Artifact, identity certificates and role Grants are publication
/// inputs; signing identity, future scopes and host continuity remain local.
public enum RelayInitialPublication: Sendable {
  case preauthorized(client: TransportPoolCredential, server: TransportPoolCredential)
  case live(TransportLiveRelayPublication)
  case registeredLive(TransportLiveRelayRegistration)
}
public struct RelayHostConfiguration: Sendable {
  public let initialPublication: RelayInitialPublication
  public let claims: RelayClaimStoreConfiguration
  public let maximumPendingPublications: Int
  public init(client: TransportPoolCredential, server: TransportPoolCredential, claims: RelayClaimStoreConfiguration, maximumPendingPublications: Int = 8) {
    initialPublication = .preauthorized(client: client, server: server); self.claims = claims
    self.maximumPendingPublications = maximumPendingPublications
  }
  public init(live: TransportLiveRelayPublication, claims: RelayClaimStoreConfiguration, maximumPendingPublications: Int = 8) {
    initialPublication = .live(live); self.claims = claims; self.maximumPendingPublications = maximumPendingPublications
  }
  public init(registeredLive: TransportLiveRelayRegistration, claims: RelayClaimStoreConfiguration, maximumPendingPublications: Int = 8) {
    initialPublication = .registeredLive(registeredLive); self.claims = claims
    self.maximumPendingPublications = maximumPendingPublications
  }
}

/// Independent deployment installed before native client Prepare. Future scopes
/// and the signed parent fix the only permitted TxA request. The pinned control
/// peer installs original TxB material on these same physical owners.
public struct TransportLiveRelayRegistration: Sendable, CustomStringConvertible, CustomReflectable {
  public let artifact: Data
  public let clientCertificate: Data
  public let serverCertificate: Data
  public let client: TransportLiveTunnelConfiguration
  public let server: TransportLiveTunnelConfiguration
  public let activationSigningKeyID: String
  public let preparationControl: TransportServerAllowHTTPSConfiguration?
  public let control: TransportServerAllowHTTPSConfiguration
  public init(artifact: Data, clientCertificate: Data, serverCertificate: Data,
    client: TransportLiveTunnelConfiguration, server: TransportLiveTunnelConfiguration,
    activationSigningKeyID: String, control: TransportServerAllowHTTPSConfiguration,
    preparationControl: TransportServerAllowHTTPSConfiguration? = nil) {
    self.artifact = artifact; self.clientCertificate = clientCertificate; self.serverCertificate = serverCertificate
    self.client = client; self.server = server; self.activationSigningKeyID = activationSigningKeyID; self.control = control; self.preparationControl = preparationControl
  }
  public var description: String { "Flowersec.LiveRelayRegistration(<redacted>)" }
  public var customMirror: Mirror { Mirror(self, children: EmptyCollection<(label: String?, value: Any)>()) }
}

/// Original live publication inputs retain two independently trusted future
/// Grant scopes. The original public activation proof fixes the common parent
/// selection; forwarding carries opaque bounded endpoint envelopes.
public struct TransportLiveRelayPublication: Sendable, CustomStringConvertible, CustomReflectable {
  public let activationAuthorization: Data
  public let activationSigningKeyID: String
  public let artifact: Data
  public let clientCertificate: Data
  public let serverCertificate: Data
  public let attempt: Data
  public let client: TransportLiveTunnelConfiguration
  public let server: TransportLiveTunnelConfiguration
  public let clientGrant: Data
  public let serverGrant: Data
  public init(artifact: Data, clientCertificate: Data, serverCertificate: Data, attempt: Data,
    client: TransportLiveTunnelConfiguration, server: TransportLiveTunnelConfiguration,
    clientGrant: Data, serverGrant: Data, activationAuthorization: Data = Data(), activationSigningKeyID: String = "") {
    self.activationAuthorization = activationAuthorization; self.activationSigningKeyID = activationSigningKeyID
    self.artifact = artifact; self.clientCertificate = clientCertificate; self.serverCertificate = serverCertificate
    self.attempt = attempt; self.client = client; self.server = server; self.clientGrant = clientGrant; self.serverGrant = serverGrant
  }
  public var description: String { "Flowersec.LiveRelayPublication(<redacted>)" }
  public var customMirror: Mirror { Mirror(self, children: EmptyCollection<(label: String?, value: Any)>()) }
}

// Closed original TxA projection. Native preparation and this exact request
// have separate owners; neither a later receipt nor a different attempt can
// attach itself to an already registered deployment.
private enum V4RelayPreparationRequest {
  static func match(_ bytes: Data, admission: V4CredentialAdmission, index: Int) throws -> (attempt: Data, end: UInt64) {
    try admission.checkPreparation(in: admission.environment)
    let (artifact, _, _) = try admission.relayOriginals(in: admission.environment)
    var cursor = V4PoolWireCursor(bytes, maximum: 1024); try cursor.array(13)
    guard try cursor.text(maximum: 32) == "live-authorization-1",
      try cursor.text(maximum: 128) == artifact.t("tenant_id"),
      try cursor.text(maximum: 128) == artifact.t("audience"),
      try cursor.text(maximum: 128) == admission.cryptoProfile,
      try cursor.bytes(maximum: 16) == artifact.b("issuer_key_id"),
      try cursor.bytes(maximum: 16) == artifact.b("lease_id") else { throw V4CryptoFailure.authentication }
    let attempt = try cursor.bytes(maximum: 16)
    guard attempt.count == 16, attempt.contains(where: { $0 != 0 }),
      try cursor.bytes(maximum: 32) == admission.artifactDigest,
      try cursor.bytes(maximum: 32) == admission.certificateDigests[0],
      try cursor.bytes(maximum: 32) == admission.certificateDigests[1] else { throw V4CryptoFailure.authentication }
    try cursor.array(3)
    guard try cursor.uint() == UInt64(index), try cursor.bytes(maximum: 16) == admission.candidateID,
      try cursor.bytes(maximum: 32) == admission.routeDigest else { throw V4CryptoFailure.authentication }
    let end = try cursor.uint()
    guard end > 0, end <= admission.initiationNotAfterMS, try cursor.uint() == 1 else { throw V4CryptoFailure.authentication }
    try cursor.end(); return (attempt, end)
  }
}

// A local original publication owner fixes the attempt before either Grant is
// completed. It cannot be restored from a claim row or made by a wire decoder.
final class V4OriginalRelayPublication: @unchecked Sendable {
  let attempt: Data
  private let admissions: [V4CredentialAdmission]
  fileprivate init(attempt: Data, admissions: [V4CredentialAdmission]) throws {
    guard attempt.count == 16, attempt.contains(where: { $0 != 0 }), admissions.count == 2,
      admissions[0].localRole == .client, admissions[1].localRole == .server,
      admissions.allSatisfy({ $0.source == .liveAuthority }) else { throw V4CryptoFailure.authentication }
    self.attempt = Data(attempt); self.admissions = admissions
  }
  func check(admission: V4CredentialAdmission) throws {
    guard admissions.contains(where: { $0 === admission }) else { throw V4CryptoFailure.authentication }
    try admission.checkPreparation(in: admission.environment)
  }
}
final class V4RelayLiveGrantDelivery: @unchecked Sendable {
  let grant: Data
  private let original: V4OriginalRelayPublication
  private let admission: V4CredentialAdmission
  fileprivate init(grant: Data, original: V4OriginalRelayPublication, admission: V4CredentialAdmission) {
    self.grant = grant; self.original = original; self.admission = admission
  }
  func check(admission: V4CredentialAdmission) throws {
    guard self.admission === admission else { throw V4CryptoFailure.authentication }
    try original.check(admission: admission)
    guard admission.attemptID == original.attempt else { throw V4CryptoFailure.authentication }
  }
}

/// An original publication owns exactly one paired run. Completion joins both
/// physical carriers, including when publication preparation or HOP fails.
public final class RelayPublication: @unchecked Sendable {
  private let pair: V4RelayPair
  private let gate = NSLock()
  private var outcome: Result<Void, any Error>?
  private var started = false
  private var closeAction: (@Sendable () -> Void)?
  private var waiters: [CheckedContinuation<Void, any Error>] = []
  fileprivate init(pair: V4RelayPair) { self.pair = pair }
  fileprivate func onClose(_ action: @escaping @Sendable () -> Void) { gate.withLock { closeAction = action } }
  public func close() {
    let (pending, action) = gate.withLock { (!started, closeAction) }
    pair.close()
    if pending { finish(.failure(TransportConnectError.canceled)) }
    action?()
  }
  public func cleanupStatus() -> CleanupStatus { pair.cleanupStatus() }
  public func waitCleanup() async throws -> CleanupStatus { try await pair.waitCleanup() }
  /// Waits for all original local carrier/control listeners to bind. This
  /// reports deployment readiness, never HOP activation or Session readiness.
  public func waitListening() async throws {
    try await withTaskCancellationHandler { try await pair.waitListening() } onCancel: { self.close() }
  }
  public func waitCompletion() async throws {
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        gate.withLock {
          if let outcome { continuation.resume(with: outcome) }
          else if waiters.isEmpty { waiters.append(continuation) }
          else { continuation.resume(throwing: TransportControlError.busy) }
        }
      }
    } onCancel: { self.close() }
  }
  fileprivate func execute() async {
    let admitted = gate.withLock { () -> Bool in
      guard outcome == nil, !started else { return false }; started = true; return true
    }
    guard admitted else { return }
    let result: Result<Void, any Error>
    do { try await pair.run(); result = .success(()) }
    catch { result = .failure(error) }
    await pair.stop()
    finish(result)
  }
  fileprivate func cancelPending() { pair.close(); finish(.failure(TransportConnectError.canceled)) }
  private func finish(_ result: Result<Void, any Error>) {
    gate.withLock {
      guard outcome == nil else { return }
      outcome = result
      for waiter in waiters { waiter.resume(with: result) }; waiters.removeAll()
    }
  }
}

/// Holds one durable claim ledger throughout the daemon lifetime. Each new
/// publication has its own original credentials, preparation, claim and join.
public final class RelayHost: V4NativeConnectionLifecycle, @unchecked Sendable {
  private let environment: V4EnvironmentFoundation
  private let credentials: V4CredentialConfiguration
  private let endpoints: [TransportEndpoint]
  private let roots: [Data]
  private let listenerTLS: NativeListenerTLSConfiguration?
  private let claimConfiguration: RelayClaimStoreConfiguration
  private let maximumPendingPublications: Int
  private let identity: V4LocalIdentity
  private let ledger: V4RelayClaimLedger
  private let storage: V4CryptoReservation
  public let initialPublication: RelayPublication
  private var pending: [RelayPublication]
  private var active: RelayPublication?
  private var wake: CheckedContinuation<Void, Never>?
  private var task: Task<Void, any Error>?
  private var closed = false
  private var used = false
  init(environment: V4EnvironmentFoundation, credentials: V4CredentialConfiguration, endpoints: [TransportEndpoint],
    roots: [Data], listenerTLS: NativeListenerTLSConfiguration?, configuration: RelayHostConfiguration,
    identity: V4LocalIdentity) throws {
    guard (1...64).contains(configuration.maximumPendingPublications) else { throw V4ResourceFailure.configuration }
    self.environment = environment; self.credentials = credentials; self.endpoints = endpoints; self.roots = roots
    self.listenerTLS = listenerTLS; self.claimConfiguration = configuration.claims
    self.maximumPendingPublications = configuration.maximumPendingPublications; self.identity = identity
    storage = try environment.relayPublicationQueueStorage(capacity: configuration.maximumPendingPublications)
    let pair = try V4RelayPair(environment: environment, credentials: credentials, endpoints: endpoints, roots: roots,
      listenerTLS: listenerTLS, configuration: configuration, identity: identity)
    ledger = pair.ledger
    try pair.publishOriginal()
    initialPublication = RelayPublication(pair: pair); pending = [initialPublication]
    let initial = initialPublication
    initial.onClose { [weak self, weak initial] in if let initial { self?.cancelPublication(initial) } }
    try environment.registerNativeConnection(self)
  }
  /// Admission is bounded and synchronous. Success follows the original
  /// durable publication COMMIT; duplicate claims fail even after cleanup.
  public func publishOriginal(client: TransportPoolCredential, server: TransportPoolCredential) throws -> RelayPublication {
    try environment.gate.withLock {
      guard !closed else { throw TransportConnectError.closed }
      guard pending.count < maximumPendingPublications else { throw V4ResourceFailure.capacity }
      try storage.check(); try ledger.check()
      let next = RelayHostConfiguration(client: client, server: server, claims: claimConfiguration,
        maximumPendingPublications: maximumPendingPublications)
      let pair = try V4RelayPair(environment: environment, credentials: credentials, endpoints: endpoints, roots: roots,
        listenerTLS: listenerTLS, configuration: next, identity: identity, ledger: ledger)
      do { try pair.publishOriginal() } catch { pair.close(); throw error }
      let publication = RelayPublication(pair: pair)
      publication.onClose { [weak self, weak publication] in if let publication { self?.cancelPublication(publication) } }
      pending.append(publication); wake?.resume(); wake = nil
      return publication
    }
  }
  public func publishLiveOriginal(_ original: TransportLiveRelayPublication) throws -> RelayPublication {
    try environment.gate.withLock {
      guard !closed else { throw TransportConnectError.closed }
      guard pending.count < maximumPendingPublications else { throw V4ResourceFailure.capacity }
      try storage.check(); try ledger.check()
      let next = RelayHostConfiguration(live: original, claims: claimConfiguration, maximumPendingPublications: maximumPendingPublications)
      let pair = try V4RelayPair(environment: environment, credentials: credentials, endpoints: endpoints, roots: roots,
        listenerTLS: listenerTLS, configuration: next, identity: identity, ledger: ledger)
      do { try pair.publishOriginal() } catch { pair.close(); throw error }
      let publication = RelayPublication(pair: pair)
      publication.onClose { [weak self, weak publication] in if let publication { self?.cancelPublication(publication) } }
      pending.append(publication); wake?.resume(); wake = nil; return publication
    }
  }
  public func registerLiveOriginal(_ original: TransportLiveRelayRegistration) throws -> RelayPublication {
    try environment.gate.withLock {
      guard !closed else { throw TransportConnectError.closed }
      guard pending.count < maximumPendingPublications else { throw V4ResourceFailure.capacity }
      try storage.check(); try ledger.check()
      let next = RelayHostConfiguration(registeredLive: original, claims: claimConfiguration, maximumPendingPublications: maximumPendingPublications)
      let pair = try V4RelayPair(environment: environment, credentials: credentials, endpoints: endpoints, roots: roots,
        listenerTLS: listenerTLS, configuration: next, identity: identity, ledger: ledger)
      do { try pair.publishOriginal() } catch { pair.close(); throw error }
      let publication = RelayPublication(pair: pair)
      publication.onClose { [weak self, weak publication] in if let publication { self?.cancelPublication(publication) } }
      pending.append(publication); wake?.resume(); wake = nil; return publication
    }
  }
  private func cancelPublication(_ publication: RelayPublication) {
    environment.gate.withLock {
      pending.removeAll { $0 === publication }
      wake?.resume(); wake = nil
    }
  }
  /// Runs until canceled or stopped. A failed pair completes its own ticket;
  /// the daemon proceeds to the next independent original publication.
  public func run() async throws {
    let operation = try environment.gate.withLock { () throws -> Task<Void, any Error> in
      guard !closed, !used else { throw TransportConnectError.closed }
      used = true
      let tail = try storage.executionTail()
      let value = Task { [self] in
        defer {
          close()
          environment.gate.withLock { active = nil; task = nil; ledger.close(); storage.seal() }
          tail.release()
        }
        while true {
          try Task.checkCancellation()
          let publication = environment.gate.withLock { () -> RelayPublication? in
            guard !closed, !pending.isEmpty else { return nil }
            let next = pending.removeFirst(); active = next; return next
          }
          if let publication {
            await publication.execute()
            environment.gate.withLock { active = nil }
          } else {
            if environment.gate.withLock({ closed }) { break }
            await withCheckedContinuation { continuation in
              environment.gate.withLock {
                if closed || !pending.isEmpty { continuation.resume() } else { wake = continuation }
              }
            }
          }
        }
      }
      task = value; return value
    }
    try await withTaskCancellationHandler { try await operation.value } onCancel: { self.close() }
  }
  public func close() {
    environment.gate.withLock {
      guard !closed else { return }; closed = true
      task?.cancel(); active?.close()
      for publication in pending { publication.cancelPending() }; pending.removeAll()
      wake?.resume(); wake = nil
      if task == nil { ledger.close(); storage.seal() }
    }
  }
  public func stop() async { close(); let operation = environment.gate.withLock { task }; _ = try? await operation?.value }
  public func cleanupStatus() -> CleanupStatus {
    environment.gate.withLock { CleanupStatus(complete: closed && task == nil && active == nil && pending.isEmpty,
      cleanupIncomplete: closed && task != nil, pendingCallbacks: task == nil ? 0 : 1) }
  }
  public func waitCleanup() async throws -> CleanupStatus { await stop(); return cleanupStatus() }
  deinit { close() }
}

fileprivate final class V4RelayPair: @unchecked Sendable {
  private let environment: V4EnvironmentFoundation
  private let identity: V4LocalIdentity
  private let admissions: [V4CredentialAdmission]
  private let routes: [V4WebSocketRoute]
  private var grants: [V4NamespaceValue]
  private let endpoints: [TransportEndpoint]
  private let roots: [Data]
  private let listenerTLS: NativeListenerTLSConfiguration?
  fileprivate let ledger: V4RelayClaimLedger
  private let storage: V4CryptoReservation
  private var meter: V4RelayMeter?
  private let registration: TransportLiveRelayRegistration?
  private let credentials: V4CredentialConfiguration
  private var control: V4ServerAllowHTTPS?
  private var preparationControl: V4ServerAllowHTTPS?
  private var originalPublication: V4OriginalRelayPublication?
  private var originalRequest: Data?
  private var originalPreparationEnd: UInt64 = 0
  private var serverGrantPublication: Data?
  private var serverGrantPublicationDigest: Data?
  private var serverActivation: Data?
  private var serverGrantOwner: V4RelayLiveGrantDelivery?
  private var clientGrantPublication: Data?
  private var clientGrantPublicationDigest: Data?
  private var clientGrantOwner: V4RelayLiveGrantDelivery?
  private var localListenersReady = [false, false]
  private var controlsReady = false
  private var listening = false
  private var listeningWaiter: CheckedContinuation<Void, any Error>?
  private var carrierReady = [false, false]
  private var carrierWaiters: [CheckedContinuation<Void, any Error>?] = [nil, nil]
  private var grantsInstalled = false
  private var activationStarted = false
  private var nativeStorage: [V4CryptoReservation?] = []
  private var sockets: [V4PreparedWebSocket?] = [nil, nil]
  private var task: Task<Void, any Error>?
  private var running = false
  private var used = false
  private var closed = false
  private var preparationTasks: [Task<V4PreparedWebSocket, any Error>] = []
  init(environment: V4EnvironmentFoundation, credentials: V4CredentialConfiguration, endpoints: [TransportEndpoint],
    roots: [Data], listenerTLS: NativeListenerTLSConfiguration?, configuration: RelayHostConfiguration,
    identity: V4LocalIdentity, ledger: V4RelayClaimLedger? = nil) throws {
    self.environment = environment; self.identity = identity; self.roots = roots; self.listenerTLS = listenerTLS; self.credentials = credentials
    try identity.check(in: environment)
    let clientInput: V4CredentialInput; let serverInput: V4CredentialInput
    let live: TransportLiveRelayPublication?
    let registration: TransportLiveRelayRegistration?
    switch configuration.initialPublication {
    case .live(let original):
      live = original; registration = nil
      guard original.client.candidateIndex == original.server.candidateIndex,
        original.client.scope.roleMask == 5, original.server.scope.roleMask == 6,
        original.client.relayCertificate == original.server.relayCertificate,
        original.client.grantLimits == original.server.grantLimits else { throw V4CryptoFailure.authentication }
      clientInput = V4CredentialInput(artifact: original.artifact, clientCertificate: original.clientCertificate, serverCertificate: original.serverCertificate,
        activation: Data(), source: .liveAuthority, candidateIndex: original.client.candidateIndex, liveTunnel: original.client, localRole: .client)
      serverInput = V4CredentialInput(artifact: original.artifact, clientCertificate: original.clientCertificate, serverCertificate: original.serverCertificate,
        activation: Data(), source: .liveAuthority, candidateIndex: original.server.candidateIndex, liveTunnel: original.server, localRole: .server)
    case .registeredLive(let original):
      live = nil; registration = original
      guard V4NamespaceRegistry.securityID(original.activationSigningKeyID.utf8),
        original.client.candidateIndex == original.server.candidateIndex,
        original.client.scope.roleMask == 5, original.server.scope.roleMask == 6,
        original.client.relayCertificate == original.server.relayCertificate,
        original.client.grantLimits == original.server.grantLimits else { throw V4CryptoFailure.authentication }
      clientInput = V4CredentialInput(artifact: original.artifact, clientCertificate: original.clientCertificate, serverCertificate: original.serverCertificate,
        activation: Data(), source: .liveAuthority, candidateIndex: original.client.candidateIndex, liveTunnel: original.client, localRole: .client)
      serverInput = V4CredentialInput(artifact: original.artifact, clientCertificate: original.clientCertificate, serverCertificate: original.serverCertificate,
        activation: Data(), source: .liveAuthority, candidateIndex: original.server.candidateIndex, liveTunnel: original.server, localRole: .server)
    case .preauthorized(let client, let server):
      live = nil; registration = nil
      clientInput = client.input.withRole(.client); serverInput = server.input.withRole(.server)
      guard clientInput.source == .preauthorizedPool, serverInput.source == .preauthorizedPool,
        clientInput.artifact == serverInput.artifact, clientInput.activation == serverInput.activation,
        clientInput.clientCertificate == serverInput.clientCertificate, clientInput.serverCertificate == serverInput.serverCertificate,
        clientInput.candidateIndex == serverInput.candidateIndex else { throw V4CryptoFailure.authentication }
    }
    self.registration = registration
    let first = try environment.verifyDirectCredentials(configuration: credentials, input: clientInput)
    var second: V4CredentialAdmission?
    do {
      let last = try environment.verifyDirectCredentials(configuration: credentials, input: serverInput); second = last
      if let live {
        let publication = try V4OriginalRelayPublication(attempt: live.attempt, admissions: [first, last])
        try first.bindOriginalRelayAttempt(publication); try last.bindOriginalRelayAttempt(publication)
        guard !live.activationAuthorization.isEmpty, V4NamespaceRegistry.securityID(live.activationSigningKeyID.utf8) else { throw V4PoolFailure.configuration }
        _ = try first.completeLiveAuthorization(live.activationAuthorization, signingKeyID: live.activationSigningKeyID, configuration: credentials)
        _ = try last.completeLiveAuthorization(live.activationAuthorization, signingKeyID: live.activationSigningKeyID, configuration: credentials)
        try first.completeOriginalRelayGrant(V4RelayLiveGrantDelivery(grant: live.clientGrant, original: publication, admission: first))
        try last.completeOriginalRelayGrant(V4RelayLiveGrantDelivery(grant: live.serverGrant, original: publication, admission: last))
      }
      guard first.pathKind == 1, last.pathKind == 1, first.routeDigest == last.routeDigest,
        first.attemptID == last.attemptID else { throw V4CryptoFailure.authentication }
      let relay = try first.originalRelayCertificate(); let secondRelay = try last.originalRelayCertificate()
      guard relay.raw.elementsEqual(secondRelay.raw), try relay.u("role") == 2,
        try relay.b("ed25519_public_key") == identity.identityPublicKey,
        try relay.field("noise_static_public_key").b("public_key_bytes") == identity.dhPublicKey,
        identity.profile.rawValue == first.cryptoProfile else { throw V4CryptoFailure.authentication }
      let initialGrants: [V4NamespaceValue]
      if registration == nil {
        initialGrants = try [first.tunnelGrant().0, last.tunnelGrant().0]
        try Self.matchGrants(initialGrants)
      } else { initialGrants = [] }
      let routes = try [first.relayWebSocketRoute(in: environment), last.relayWebSocketRoute(in: environment)]
      var selected: [TransportEndpoint] = []
      for route in routes {
        let matches = endpoints.filter { $0.hostname == route.host && $0.port == route.port }
        guard matches.count == 1, route.requiresTLS, route.isRelay,
          route.isDialer || listenerTLS != nil else { throw TransportConnectError.unsupported }
        selected.append(matches[0])
      }
      self.admissions = [first, last]; self.grants = initialGrants; self.grantsInstalled = registration == nil
      self.routes = routes; self.endpoints = selected
      localListenersReady = routes.map(\.isDialer); controlsReady = registration == nil
      storage = try environment.relayHostStorage(maximumFrame: routes[0].maximumFrame)
      meter = initialGrants.isEmpty ? nil : try V4RelayMeter(grants: initialGrants, clock: environment.clock)
      for route in routes { nativeStorage.append(try environment.nativeConnectionStorage(maximumFrame: route.maximumFrame, listener: !route.isDialer)) }
      self.ledger = try ledger ?? V4RelayClaimLedger(environment: environment, configuration: configuration.claims,
        tenant: clientInput.liveTunnel?.scope.tenant ?? first.relayOriginals(in: environment).0.t("tenant_id"), relay: relay.digest("certificate_digest"))
      try self.ledger.checkBinding(tenant: clientInput.liveTunnel?.scope.tenant ?? first.relayOriginals(in: environment).0.t("tenant_id"), relay: relay.digest("certificate_digest"))
    } catch { first.close(); second?.close(); throw error }
  }
  func publishOriginal() throws {
    try environment.gate.withLock {
      guard !closed, !used else { throw TransportConnectError.closed }
      if registration != nil {
        try ledger.publishPendingOriginal(admissions: admissions) { try self.check(preparing: true) }
      } else { try ledger.publishOriginal(admissions: admissions, grants: grants) { try self.check(preparing: true) } }
    }
  }
  /// A run is single use, including failures after durable claim. Cancellation
  /// closes both original sockets and joins their actual native completions.
  public func run() async throws {
    let operation = try environment.gate.withLock { () throws -> Task<Void, any Error> in
      guard !closed, !used else { throw TransportConnectError.closed }
      try storage.check(); try identity.check(in: environment)
      used = true; running = true
      let operation = Task { [self] in try await execute() }
      task = operation; return operation
    }
    defer { environment.gate.withLock { control?.close(); preparationControl?.close(); listeningWaiter?.resume(throwing: TransportConnectError.closed); listeningWaiter = nil; task = nil; running = false; closed = true; storage.seal(); for admission in admissions { admission.close() } } }
    try await withTaskCancellationHandler { try await operation.value } onCancel: { self.close() }
  }
  public func close() {
    environment.gate.withLock {
      closed = true; task?.cancel(); control?.close(); preparationControl?.close()
      listeningWaiter?.resume(throwing: TransportConnectError.canceled); listeningWaiter = nil
      for waiter in carrierWaiters { waiter?.resume(throwing: TransportConnectError.canceled) }; carrierWaiters = [nil, nil]
      for preparation in preparationTasks { preparation.cancel() }
      for charge in nativeStorage { charge?.seal() }; nativeStorage.removeAll()
      for socket in sockets { socket?.close() }
      if !running { storage.seal(); for admission in admissions { admission.close() } }
    }
  }
  public func stop() async {
    close()
    let pending = environment.gate.withLock { task }
    _ = try? await pending?.value
    for socket in environment.gate.withLock({ sockets }) { await socket?.waitClosed() }
    environment.gate.withLock { sockets = [nil, nil] }
    if let control = environment.gate.withLock({ control }) { _ = try? await control.waitCleanup(); environment.gate.withLock { self.control = nil } }
    if let control = environment.gate.withLock({ preparationControl }) { _ = try? await control.waitCleanup(); environment.gate.withLock { self.preparationControl = nil } }
  }
  public func cleanupStatus() -> CleanupStatus {
    environment.gate.withLock { CleanupStatus(complete: closed && !running && preparationTasks.isEmpty && (control?.cleanupStatus().complete ?? true) && (preparationControl?.cleanupStatus().complete ?? true),
      cleanupIncomplete: closed && running, pendingCallbacks: running ? 1 : 0) }
  }
  public func waitCleanup() async throws -> CleanupStatus {
    let pending = environment.gate.withLock { task }
    _ = try? await pending?.value
    return cleanupStatus()
  }
  func waitListening() async throws {
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
        environment.gate.withLock {
          if closed { continuation.resume(throwing: TransportConnectError.closed) }
          else if listening { continuation.resume() }
          else if listeningWaiter != nil { continuation.resume(throwing: TransportControlError.busy) }
          else { listeningWaiter = continuation }
        }
      }
    } onCancel: { self.close() }
  }
  private func listenerBound(side: Int? = nil) throws {
    try environment.gate.withLock {
      try check(preparing: true)
      if let side { localListenersReady[side] = true } else { controlsReady = true }
      if !listening, controlsReady, localListenersReady.allSatisfy({ $0 }) {
        listening = true; listeningWaiter?.resume(); listeningWaiter = nil
      }
    }
  }
  private func check(preparing: Bool) throws {
    try environment.gate.withLock {
      guard !closed else { throw TransportConnectError.closed }
      try storage.check(); try identity.check(in: environment); try ledger.check()
      for admission in admissions {
        if preparing { try admission.checkPreparation(in: environment) }
        else { try admission.checkSessionAuthorization(in: environment) }
      }
    }
    try Task.checkCancellation()
  }
  private func execute() async throws {
    let tail = try storage.executionTail()
    defer { tail.release() }
    do {
      try check(preparing: true)
      if let registration {
        let listener = try V4ServerAllowHTTPS(environment: environment, configuration: registration.control,
          requestPaths: registration.preparationControl == nil
            ? ["/tunnel/relay-ready", "/tunnel/relay-prepare", "/tunnel/relay-server-grant", "/tunnel/relay-activate-client"]
            : ["/tunnel/relay-server-grant", "/tunnel/relay-activate-client"],
          maximumRequestBytes: 24_576, minimumRequestIntervalMS: 0,
          receiveAtPath: { [self] path, bytes in try receiveControl(path: path, bytes: bytes) },
          receive: { _ in throw V4CryptoFailure.phase })
        try environment.gate.withLock { try check(preparing: true); control = listener }
        try await listener.start()
        if let preparation = registration.preparationControl {
          guard preparation.port != registration.control.port || preparation.numericAddress != registration.control.numericAddress else { throw V4PoolFailure.configuration }
          let pendingControl = try V4ServerAllowHTTPS(environment: environment, configuration: preparation,
            requestPaths: ["/tunnel/relay-ready", "/tunnel/relay-prepare"], maximumRequestBytes: 1024, minimumRequestIntervalMS: 0,
            receiveAtPath: { [self] path, bytes in try receiveControl(path: path, bytes: bytes) },
            receive: { _ in throw V4CryptoFailure.phase })
          try environment.gate.withLock { try check(preparing: true); preparationControl = pendingControl }
          try await pendingControl.start()
        }
      }
      try listenerBound()
      let preparations = routes.enumerated().map { side, route in
        Task { [self] in
          let endpoint = endpoints[side]
          if registration != nil && route.isDialer {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
              environment.gate.withLock {
                if closed { continuation.resume(throwing: TransportConnectError.closed) }
                else if carrierReady[side] { continuation.resume() }
                else { carrierWaiters[side] = continuation }
              }
            }
          }
          let native = try environment.gate.withLock { () throws -> V4CryptoReservation in
            try check(preparing: true)
            guard side < nativeStorage.count, let charge = nativeStorage[side] else { throw V4ResourceFailure.owner }
            nativeStorage[side] = nil; return charge
          }
          let prepared: V4PreparedWebSocket
          if route.isDialer {
            prepared = try await V4PreparedWebSocket.prepare(route: route, numericAddress: endpoint.numericAddress, trustRootsPEM: roots, prepaidNative: native)
          } else {
            prepared = try await V4PreparedWebSocket.listen(route: route, numericAddress: endpoint.numericAddress, tls: listenerTLS, prepaidNative: native,
              onListening: { [self] in try listenerBound(side: side) })
          }
          try environment.gate.withLock {
            sockets[side] = prepared
            guard !closed else { prepared.close(); throw TransportConnectError.closed }
          }
          return prepared
        }
      }
      environment.gate.withLock { preparationTasks = preparations; if closed { for task in preparations { task.cancel() } } }
      let physical = try await withThrowingTaskGroup(of: (Int, V4PreparedWebSocket).self) { group in
        for (side, preparation) in preparations.enumerated() { group.addTask { (side, try await preparation.value) } }
        var sockets: [V4PreparedWebSocket?] = [nil, nil]
        do { for try await (side, socket) in group { sockets[side] = socket } }
        catch { close(); group.cancelAll(); throw error }
        guard let first = sockets[0], let second = sockets[1] else { throw V4CryptoFailure.phase }
        return [first, second]
      }
      environment.gate.withLock { preparationTasks.removeAll() }
      if registration != nil {
        // A server Grant may be installed before the original authority
        // publication reaches the B-host. Keep the prepared relay bounded by
        // the original admission deadline even if no second control request
        // ever arrives.
        while !environment.gate.withLock({ grantsInstalled }) {
          try check(preparing: true)
          try await ContinuousClock().sleep(for: .milliseconds(10))
        }
      }
      try check(preparing: true)
      guard grantsInstalled, let meter else { throw V4CryptoFailure.phase }
      let possessions = try await withThrowingTaskGroup(of: V4RelayPossession.self) { group in
        for side in 0..<2 { group.addTask { try await self.authenticate(side: side, socket: physical[side]) } }
        var results: [V4RelayPossession] = []
        do { for try await result in group { results.append(result) } }
        catch { group.cancelAll(); for socket in physical { socket.close() }; throw error }
        return results.sorted { $0.side < $1.side }
      }
      try check(preparing: true)
      // The capability is returned solely by this original two-row COMMIT.
      // No existing row or recovery query yields a route activation.
      guard let profile = V4CryptoProfile(rawValue: admissions[0].cryptoProfile) else { throw V4CryptoFailure.configuration }
      try meter.claimInitial(profile: profile, maximumFrame: routes[0].maximumFrame)
      let activation = try ledger.commit(possessions, routes: routes) { try self.check(preparing: true) }
      for side in 0..<2 {
        let proof = try identity.signHandshake(possessions[side].prefix + Data([2]), in: environment)
        let response = V4Crypto.map([(0, V4NamespaceValue.head(0, 2)), (1, V4Crypto.bytes(proof))])
        try await sendHop(response, side: side, socket: physical[side])
      }
      for socket in physical { try socket.promoteRelay(activation) }
      try await withThrowingTaskGroup(of: Void.self) { group in
        for side in 0..<2 { group.addTask { try await self.forward(side: side, source: physical[side], destination: physical[1 - side]) } }
        group.addTask {
          while true {
            try self.check(preparing: false)
            try await ContinuousClock().sleep(for: .milliseconds(10))
          }
        }
        do { _ = try await group.next(); group.cancelAll(); for socket in physical { socket.close() }; while try await group.next() != nil {} }
        catch { group.cancelAll(); for socket in physical { socket.close() }; throw error }
      }
      for socket in physical { socket.close(); await socket.waitClosed() }
    } catch {
      close()
      let preparations = environment.gate.withLock { preparationTasks }
      for preparation in preparations { preparation.cancel() }
      for socket in environment.gate.withLock({ sockets }) { socket?.close() }
      for preparation in preparations { _ = try? await preparation.value }
      environment.gate.withLock { preparationTasks.removeAll() }
      for socket in environment.gate.withLock({ sockets }) { await socket?.waitClosed() }
      for admission in admissions { admission.close() }
      throw error
    }
  }
  private func activeMeter() throws -> V4RelayMeter {
    try environment.gate.withLock { try check(preparing: false); guard grantsInstalled, let meter else { throw V4CryptoFailure.phase }; return meter }
  }
  private static func matchGrants(_ grants: [V4NamespaceValue]) throws {
    guard grants.count == 2,
      try grants[0].field("tenant_id").text() == grants[1].field("tenant_id").text(),
      try grants[0].b("pairing_id") == grants[1].b("pairing_id"),
      try grants[0].field("parent_ref").raw.elementsEqual(grants[1].field("parent_ref").raw),
      try grants[0].field("route_descriptor").raw.elementsEqual(grants[1].field("route_descriptor").raw),
      try grants[0].b("route_digest") == grants[1].b("route_digest"),
      try grants[0].b("attempt_id") == grants[1].b("attempt_id"),
      try grants[0].field("identity_digests").raw.elementsEqual(grants[1].field("identity_digests").raw),
      try grants[0].field("legs").raw.elementsEqual(grants[1].field("legs").raw),
      try grants[0].field("service").text() == grants[1].field("service").text(),
      try grants[0].field("audience").text() == grants[1].field("audience").text(),
      try grants[0].field("limits").raw.elementsEqual(grants[1].field("limits").raw),
      try grants[0].b("session_contract_digest") == grants[1].b("session_contract_digest"),
      try grants[0].b("relay_identity_digest") == grants[1].b("relay_identity_digest")
    else { throw V4CryptoFailure.authentication }
  }
  private func receiveControl(path: String, bytes: Data) throws -> V4ServerAllowAcknowledgement {
    do {
      return try environment.gate.withLock {
        try checkControl()
        guard let registration else { throw V4CryptoFailure.phase }
        if path == "/tunnel/relay-ready" {
          var cursor = V4PoolWireCursor(bytes, maximum: 1024); try cursor.array(5)
          guard try cursor.text(maximum: 32) == "tunnel-relay-ready-1",
            try cursor.bytes(maximum: 32) == admissions[0].artifactDigest,
            try cursor.bytes(maximum: 16) == admissions[0].candidateID,
            try cursor.bytes(maximum: 32) == admissions[0].routeDigest else { throw V4CryptoFailure.authentication }
          let side = try cursor.uint(); try cursor.end()
          guard side < 2, routes[Int(side)].isDialer else { throw V4CryptoFailure.authentication }
          let position = Int(side)
          return V4ServerAllowAcknowledgement(check: { [self] in try checkControlAndClose() }, written: { [self] in
            do {
              try environment.gate.withLock {
                try checkControl()
                if !carrierReady[position] {
                  carrierReady[position] = true; carrierWaiters[position]?.resume(); carrierWaiters[position] = nil
                }
              }
            } catch { close(); throw error }
          })
        }
        if path == "/tunnel/relay-prepare" {
          if let originalRequest {
            guard originalRequest == bytes else { throw V4PoolFailure.conflict }
            return V4ServerAllowAcknowledgement(check: { [self] in try checkControlAndClose() }, written: {})
          }
          guard !activationStarted else { throw V4CryptoFailure.phase }
          let projection = try V4RelayPreparationRequest.match(bytes, admission: admissions[0], index: registration.client.candidateIndex)
          let original = try V4OriginalRelayPublication(attempt: projection.attempt, admissions: admissions)
          try admissions[0].bindOriginalRelayAttempt(original); try admissions[1].bindOriginalRelayAttempt(original)
          // Acknowledging TxA preparation never opens HOP or forwarding.
          originalPublication = original; originalRequest = Data(bytes); originalPreparationEnd = projection.end
          return V4ServerAllowAcknowledgement(check: { [self] in try checkControlAndClose() }, written: {})
        }
        guard let original = originalPublication, let request = originalRequest else { throw V4CryptoFailure.phase }
        if path == "/tunnel/relay-server-grant" {
          if let installed = serverGrantPublication {
            guard installed == bytes,
              serverGrantPublicationDigest == Data(SHA256.hash(data: installed)) else { throw V4PoolFailure.conflict }
            return V4ServerAllowAcknowledgement(check: { [self] in try checkControlAndClose() }, written: {})
          }
          guard !activationStarted, !grantsInstalled else { throw V4CryptoFailure.phase }
          activationStarted = true
          var cursor = V4PoolWireCursor(bytes, maximum: 24_576); try cursor.array(4)
          guard try cursor.text(maximum: 40) == "tunnel-relay-server-grant-1",
            try cursor.bytes(maximum: 1024) == request else { throw V4CryptoFailure.authentication }
          let activation = try cursor.bytes(maximum: 4096)
          let serverGrant = try cursor.bytes(maximum: 9302); try cursor.end()
          let serverAdmission = admissions[1]
          _ = try serverAdmission.completeLiveAuthorization(activation, signingKeyID: registration.activationSigningKeyID, configuration: credentials)
          guard serverAdmission.initiationNotAfterMS <= originalPreparationEnd else { throw V4CryptoFailure.authentication }
          let owner = V4RelayLiveGrantDelivery(grant: serverGrant, original: original, admission: serverAdmission)
          try serverAdmission.completeOriginalRelayGrant(owner)
          _ = try serverAdmission.tunnelGrant()
          try checkControl()
          serverActivation = Data(activation)
          serverGrantOwner = owner
          serverGrantPublication = Data(bytes)
          serverGrantPublicationDigest = Data(SHA256.hash(data: bytes))
          // This ACK confirms only server Grant installation; the client leg gates HOP.
          return V4ServerAllowAcknowledgement(check: { [self] in try checkControlAndClose() }, written: {})
        }
        if path == "/tunnel/relay-activate-client" {
          guard let installedServerPublication = serverGrantPublication,
            let installedServerDigest = serverGrantPublicationDigest,
            let installedServerActivation = serverActivation, serverGrantOwner != nil,
            installedServerDigest == Data(SHA256.hash(data: installedServerPublication)) else {
            throw V4CryptoFailure.phase
          }
          if let installed = clientGrantPublication {
            guard installed == bytes,
              clientGrantPublicationDigest == Data(SHA256.hash(data: installed)) else { throw V4PoolFailure.conflict }
            return activationAcknowledgement()
          }
          guard !grantsInstalled else { throw V4CryptoFailure.phase }
          var cursor = V4PoolWireCursor(bytes, maximum: 24_576); try cursor.array(4)
          guard try cursor.text(maximum: 40) == "tunnel-relay-activate-client-1",
            try cursor.bytes(maximum: 1024) == request else { throw V4CryptoFailure.authentication }
          let activation = try cursor.bytes(maximum: 4096)
          guard activation == installedServerActivation else { throw V4CryptoFailure.authentication }
          let clientGrant = try cursor.bytes(maximum: 9302); try cursor.end()
          let clientAdmission = admissions[0]
          _ = try clientAdmission.completeLiveAuthorization(activation, signingKeyID: registration.activationSigningKeyID, configuration: credentials)
          guard clientAdmission.initiationNotAfterMS <= originalPreparationEnd else { throw V4CryptoFailure.authentication }
          let owner = V4RelayLiveGrantDelivery(grant: clientGrant, original: original, admission: clientAdmission)
          try clientAdmission.completeOriginalRelayGrant(owner)
          let installed = try admissions.map { try $0.tunnelGrant().0 }
          try Self.matchGrants(installed)
          let installedMeter = try V4RelayMeter(grants: installed, clock: environment.clock)
          try checkControl()
          grants = installed; meter = installedMeter
          clientGrantOwner = owner
          clientGrantPublication = Data(bytes)
          clientGrantPublicationDigest = Data(SHA256.hash(data: bytes))
          return activationAcknowledgement()
        }
        throw V4CryptoFailure.phase
      }
    } catch {
      // Invalid, conflicting, expired, or canceled control legs retire this original publication.
      close()
      throw error
    }
  }
  private func checkControl() throws { try check(preparing: true) }
  private func checkControlAndClose() throws {
    do { try checkControl() }
    catch { close(); throw error }
  }
  private func activationAcknowledgement() -> V4ServerAllowAcknowledgement {
    V4ServerAllowAcknowledgement(check: { [self] in try checkControlAndClose() }, written: { [self] in
      do {
        try environment.gate.withLock {
          try checkControl()
          // An exact retry can repeat the ACK, never the original installation
          // or the release of the HOP continuation.
          if !grantsInstalled { grantsInstalled = true }
        }
      } catch { close(); throw error }
    })
  }
  private func sendHop(_ bytes: Data, side: Int, socket: V4PreparedWebSocket) async throws {
    try check(preparing: true)
    let wire = V4Crypto.integer(UInt64(bytes.count), width: 4) + Data([16, 0, 0, 0]) + bytes
    try await activeMeter().accept(side: side, count: wire.count)
    let buffer = try environment.cryptoBuffer(capacity: wire.count, credential: admissions[side])
    try buffer.store(wire); try socket.publish(buffer); try await socket.flush()
  }
  private func receiveHop(side: Int, socket: V4PreparedWebSocket) async throws -> Data {
    try check(preparing: true)
    let buffer = try await socket.receive(); defer { buffer.close() }
    let count = try buffer.withBytes { $0.count }
    try await activeMeter().accept(side: side, count: count)
    return try buffer.withBytes { wire in
      guard wire.count > 8, wire.count <= 10_354, V4Crypto.number(wire.prefix(4)) == wire.count - 8,
        wire[4] == 16, wire[5..<8] == Data([0, 0, 0]) else { throw V4CryptoFailure.authentication }
      return Data(wire.dropFirst(8))
    }
  }
  private func authenticate(side: Int, socket: V4PreparedWebSocket) async throws -> V4RelayPossession {
    let admission = admissions[side]; let route = routes[side]; let grant = grants[side]
    let (_, client, server) = try admission.relayOriginals(in: environment)
    let endpoint = side == 0 ? client : server
    let (_, relay) = try admission.tunnelGrant()
    let (incarnation, challenge) = try socket.relayChallenge()
    let local = V4Crypto.map([(0, V4NamespaceValue.head(0, 0)), (1, V4Crypto.bytes(incarnation)),
      (2, V4Crypto.bytes(challenge)), (4, V4Crypto.bytes(Data(relay.raw)))])
    let registry = try V4NamespaceRegistry()
    func decode(_ data: Data, schema: String, context: [String: String] = [:]) throws -> V4NamespaceValue {
      try V4NamespaceDocument(data, schema: schema, bytes: 10_346, nodes: 4096, registry: registry, context: context).root
    }
    _ = try decode(local, schema: "HOP_AUTH_HELLO", context: ["hop_sender_role": "relay"])
    let peerWire: Data
    if route.isDialer { try await sendHop(local, side: side, socket: socket); peerWire = try await receiveHop(side: side, socket: socket) }
    else { peerWire = try await receiveHop(side: side, socket: socket); try await sendHop(local, side: side, socket: socket) }
    let peer = try decode(peerWire, schema: "HOP_AUTH_HELLO", context: ["hop_sender_role": "endpoint"])
    guard try peer.u("phase") == 0, try peer.b("grant") == Data(grant.raw),
      try peer.b("identity_certificate") == Data(endpoint.raw) else { throw V4CryptoFailure.authentication }
    let candidate = try admission.originalCandidate()
    let leg = try candidate.field(side == 0 ? "client_leg" : "server_leg")
    let hop = V4Crypto.map([
      (0, V4Crypto.bytes(route.isDialer ? incarnation : try peer.b("local_incarnation"))),
      (1, V4Crypto.bytes(route.isDialer ? try peer.b("local_incarnation") : incarnation)),
      (2, V4Crypto.bytes(try leg.b("leg_id"))), (3, V4NamespaceValue.head(0, route.dialerRole)),
      (4, V4NamespaceValue.head(0, route.listenerRole)),
      (5, V4Crypto.bytes(route.isDialer ? challenge : try peer.b("local_challenge"))),
      (6, V4Crypto.bytes(route.isDialer ? try peer.b("local_challenge") : challenge)),
    ])
    _ = try decode(hop, schema: "HopChallengeContext")
    let (domain, _) = try registry.compoundDomain("grant_possession", operation: "ed25519")
    let prefix = domain + V4Crypto.lp(try grant.digest("grant_digest")) + V4Crypto.lp(admission.routeDigest)
      + V4Crypto.lp(try leg.b("leg_id")) + V4Crypto.lp(try grant.b("pairing_id")) + V4Crypto.lp(hop)
    let endpointProof = try decode(await receiveHop(side: side, socket: socket), schema: "HOP_AUTH_ENDPOINT_PROOF")
    guard try endpointProof.u("phase") == 1,
      StrictEd25519V4Reference.verify(signature: try endpointProof.b("proof"), message: prefix + Data([UInt8(side)]),
        publicKey: try endpoint.b("ed25519_public_key")) else { throw V4CryptoFailure.authentication }
    try check(preparing: true)
    return V4RelayPossession(side: side, prefix: prefix, admission: admission, grant: grant,
      challenge: V4Crypto.hash(hop), proof: V4Crypto.hash(try endpointProof.b("proof")), incarnation: incarnation)
  }
  private func forward(side: Int, source: V4PreparedWebSocket, destination: V4PreparedWebSocket) async throws {
    while true {
      try check(preparing: false)
      let buffer = try await source.receive()
      do {
        try check(preparing: false)
        let count = try buffer.withBytes { wire -> Int in
          guard wire.count > 8, V4Crypto.number(wire.prefix(4)) == wire.count - 8,
            wire[5..<8] == Data([0, 0, 0]), (1...15).contains(wire[4]) else { throw V4CryptoFailure.authentication }
          return wire.count
        }
        // Both independently signed hop limits cover traffic on both legs.
        try await activeMeter().accept(side: side, count: count)
        try await activeMeter().accept(side: 1 - side, count: count)
        try check(preparing: false)
        try destination.publish(buffer); try await destination.flush()
        buffer.close()
      } catch { buffer.close(); throw error }
    }
  }
  deinit { close() }
}

final class V4RelayPossession: @unchecked Sendable {
  let side: Int; let prefix: Data; let admission: V4CredentialAdmission; let grant: V4NamespaceValue
  let challenge: Data; let proof: Data; let incarnation: Data
  fileprivate init(side: Int, prefix: Data, admission: V4CredentialAdmission, grant: V4NamespaceValue,
    challenge: Data, proof: Data, incarnation: Data) {
    self.side = side; self.prefix = prefix; self.admission = admission; self.grant = grant
    self.challenge = challenge; self.proof = proof; self.incarnation = incarnation
  }
  var key: Data {
    get throws {
      let parent = try grant.field("parent_ref")
      return V4Crypto.map([(0, V4Crypto.text(try grant.t("tenant_id"))), (1, V4Crypto.bytes(try parent.b("artifact_issuer_key_id"))),
        (2, V4Crypto.bytes(try parent.b("lease_id"))), (3, V4Crypto.bytes(admission.candidateID)),
        (4, V4Crypto.bytes(admission.attemptID)), (5, V4NamespaceValue.head(0, UInt64(side)))])
    }
  }
  var projection: Data {
    get throws {
      V4Crypto.map([(0, V4Crypto.bytes(try grant.digest("grant_digest"))), (1, V4Crypto.bytes(admission.routeDigest)),
        (2, V4Crypto.bytes(try grant.b("pairing_id"))), (3, V4Crypto.bytes(challenge)), (4, V4Crypto.bytes(proof)),
        (5, V4Crypto.bytes(incarnation)), (6, V4Crypto.bytes(admission.artifactDigest)), (7, V4Crypto.bytes(admission.activationDigest)), (8, V4Crypto.text(admission.source.rawValue))])
    }
  }
}

// Only the stack of the original successful claim COMMIT creates this object.
// Its routes are the actual two prepared carriers, never reconstructed fields.
final class V4RelayActivation: @unchecked Sendable {
  private let routes: [V4WebSocketRoute]
  private var claimed: [Bool] = [false, false]
  fileprivate init(routes: [V4WebSocketRoute]) { self.routes = routes }
  func claim(_ route: V4WebSocketRoute) throws {
    try route.environment.gate.withLock {
      guard let index = routes.firstIndex(where: { $0 === route }), !claimed[index] else { throw V4CryptoFailure.phase }
      try route.check(); claimed[index] = true
    }
  }
}

private final class V4RelayMeter: @unchecked Sendable {
  private struct Limit { let envelope: UInt64; let total: UInt64; let rate: UInt64 }
  private let lock = NSLock()
  private let limits: [Limit]
  private let clock: V4TrustedClock
  private let origin: V4ClockMark
  private var totals: [UInt64] = [0, 0]
  private var tokens: [UInt128]
  private var creditedMS: [UInt64] = [0, 0]
  init(grants: [V4NamespaceValue], clock: V4TrustedClock) throws {
    self.clock = clock; origin = try clock.mark()
    limits = try grants.map { grant in
      let limits = try grant.field("limits")
      let envelope = try limits.u("max_envelope_bytes")
      let total = try limits.u("max_total_bytes"); let rate = try limits.u("max_rate_bytes_per_s")
      guard total > 0, rate > 0, (8...1_048_584).contains(envelope),
        try envelope <= limits.u("max_queue_bytes"), try limits.u("max_queue_items") >= 1 else {
        throw V4ResourceFailure.capacity
      }
      return Limit(envelope: envelope, total: total, rate: rate)
    }
    tokens = limits.map { UInt128($0.envelope) * 2000 }
  }
  // This uses the existing two hop counters after possession. Claiming never
  // resets their quota, and exhausted original traffic cannot mint activation.
  func claimInitial(profile: V4CryptoProfile, maximumFrame: Int) throws {
    let registry = try V4NamespaceRegistry()
    func maximum(_ schema: String) throws -> UInt64 {
      let map = try registry.map(schema)
      guard let bytes = V4NamespaceRegistry.number(map["max_encoded_bytes"])
        ?? V4NamespaceRegistry.number(map["encoded_bytes"]), bytes > 0 else { throw V4NamespaceFailure.schema }
      return bytes
    }
    let frame = UInt64(maximumFrame)
    // Canonical two-field proof map: phase byte plus a 64-byte signature.
    var need: UInt64 = 70 + 8
    for schema in ["ClientHello", "ServerHello", "FSB4", "FSA4"] { need += try min(frame, maximum(schema)) + 8 }
    need += UInt64(profile.publicBytes + 16 + 8) * 2 + (frame + 8) * 4
    try lock.withLock {
      for side in 0..<2 {
        guard totals[side] <= limits[side].total, need <= limits[side].total - totals[side] else {
          throw V4ResourceFailure.capacity
        }
      }
    }
  }
  // A rate wait stays in its original already-paid I/O call. Lower elapsed
  // time under the TransportEnvironment clock supplies credit; wall time grants none.
  func accept(side: Int, count: Int) async throws {
    guard (0..<2).contains(side), count > 0 else { throw V4ResourceFailure.configuration }
    let value = UInt64(count)
    while true {
      try Task.checkCancellation()
      let now = try clock.mark()
      guard now.sameEra(as: origin), now.milliseconds >= origin.milliseconds else { throw V4TimeFailure.continuity }
      let elapsed = try clock.profile.elapsed(now.milliseconds - origin.milliseconds).lowerMS
      let wait = try lock.withLock { () throws -> UInt64 in
        let limit = limits[side]
        guard value <= limit.envelope, totals[side] <= limit.total,
          value <= limit.total - totals[side] else { throw V4ResourceFailure.capacity }
        if elapsed > creditedMS[side] {
          let refill = UInt128(elapsed - creditedMS[side]) * UInt128(limit.rate)
          tokens[side] = min(UInt128(limit.envelope) * 2000, tokens[side] + refill)
          creditedMS[side] = elapsed
        }
        let charge = UInt128(value) * 1000
        if tokens[side] >= charge {
          tokens[side] -= charge; totals[side] += value
          return 0
        }
        let missing = charge - tokens[side]
        let delay = (missing + UInt128(limit.rate) - 1) / UInt128(limit.rate)
        return UInt64(min(UInt128(50), max(UInt128(1), delay)))
      }
      if wait == 0 { return }
      try await ContinuousClock().sleep(for: .milliseconds(Int64(wait)))
    }
  }
}

final class V4RelayClaimLedger: @unchecked Sendable {
  private static let format = V4SQLiteStorageFormat(group: .relay)
  private static let manifestSQL = format.manifest()
  private static let publicationsSQL = "CREATE TABLE publications (claim_key BLOB PRIMARY KEY, projection BLOB NOT NULL) WITHOUT ROWID, STRICT"
  private static let claimsSQL = "CREATE TABLE claims (claim_key BLOB PRIMARY KEY, projection BLOB NOT NULL) WITHOUT ROWID, STRICT"
  private static let originalsSQL = "CREATE TABLE claim_originals (parent BLOB PRIMARY KEY, projection BLOB NOT NULL) WITHOUT ROWID, STRICT"
  private let environment: V4EnvironmentFoundation
  private let configuration: RelayClaimStoreConfiguration
  private let path: String
  private let binding: Data
  private let tenant: String
  private let relay: Data
  private let registry: V4NamespaceRegistry
  private let storage: V4CryptoReservation
  private let disk: V4PersistentDiskCharge
  private var db: OpaquePointer?
  private var file: Int32 = -1
  private var lockFile: Int32 = -1
  private var fileIdentity = stat()
  private var lockIdentity = stat()
  private var directoryIdentity = stat()
  private var closed = false
  init(environment: V4EnvironmentFoundation, configuration: RelayClaimStoreConfiguration, tenant: String, relay: Data) throws {
    let c = configuration
    guard c.directory.isFileURL, c.directory.standardizedFileURL.path == c.directory.resolvingSymlinksInPath().path,
      c.directory.path.utf8.count <= 2048, c.backingIdentity.count == 16, c.backingIdentity.contains(where: { $0 != 0 }),
      (4...65_536).contains(c.maximumRows), ((1 << 20)...(1 << 30)).contains(c.maximumBytes), c.maximumBytes % 4096 == 0,
      lstat(c.directory.path, &directoryIdentity) == 0, Self.safe(directoryIdentity, directory: true) else { throw V4PoolFailure.configuration }
    self.environment = environment; self.configuration = c; self.tenant = tenant; self.relay = relay
    path = c.directory.appendingPathComponent("relay-claims.sqlite3").path
    binding = V4Crypto.map([(0, V4Crypto.bytes(c.backingIdentity)), (1, V4Crypto.text(tenant)), (2, V4Crypto.bytes(relay)),
      (3, V4NamespaceValue.head(0, UInt64(c.maximumRows))), (4, V4NamespaceValue.head(0, UInt64(c.maximumBytes)))])
    registry = try V4NamespaceRegistry()
    storage = try environment.poolStoreStorage()
    disk = try environment.poolDiskStorage(diskBytes: UInt64(c.maximumBytes) * 3)
    try c.checkContinuity(c.backingIdentity)
    do {
      lockFile = Darwin.open(path + ".lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC | (c.create ? O_CREAT | O_EXCL : 0), 0o600)
      guard lockFile >= 0, fstat(lockFile, &lockIdentity) == 0, Self.safe(lockIdentity),
        flock(lockFile, LOCK_EX | LOCK_NB) == 0 else { throw V4PoolFailure.storage }
      file = Darwin.open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC | (c.create ? O_CREAT | O_EXCL : 0), 0o600)
      guard file >= 0, fstat(file, &fileIdentity) == 0, Self.safe(fileIdentity),
        fileIdentity.st_size >= 0, fileIdentity.st_size <= c.maximumBytes,
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK
      else { throw V4PoolFailure.storage }
      if !c.create { try V4SQLiteAdmission.prepare(db!) }
      sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 65_536); sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 4096)
      sqlite3_limit(db, SQLITE_LIMIT_ATTACHED, 0)
      try execute("PRAGMA trusted_schema=OFF")
      if !c.create {
        try inspectCurrentFormat()
          try V4SQLiteAdmission.allowWrites(db!)
          try V4SQLiteAdmission.restoreCloseCheckpoint(db!)
      }
      try execute("PRAGMA journal_mode=DELETE"); try execute("PRAGMA synchronous=FULL")
      try execute("PRAGMA fullfsync=ON"); try execute("PRAGMA trusted_schema=OFF"); try execute("PRAGMA mmap_size=0")
      try execute("PRAGMA temp_store=MEMORY"); try execute("PRAGMA cache_size=-256")
      if c.create { try execute("PRAGMA page_size=4096") }
      guard try scalar("PRAGMA page_size") == 4096,
        try scalar("PRAGMA max_page_count=\(c.maximumBytes / 4096)") == c.maximumBytes / 4096 else { throw V4PoolFailure.storage }
      if c.create {
        try execute("BEGIN IMMEDIATE")
        try execute(Self.manifestSQL); try execute(Self.publicationsSQL)
        try execute(Self.claimsSQL); try execute(Self.originalsSQL)
        try execute("PRAGMA user_version=\(Self.format.requiredRevision)")
        try write("INSERT INTO manifest VALUES(1,'\(Self.format.group.rawValue)',\(Self.format.requiredRevision),?1)", blobs: [binding]); try execute("COMMIT")
        guard fsync(file) == 0 else { throw V4PoolFailure.storage }
        let directory = Darwin.open(c.directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw V4PoolFailure.storage }
        defer { Darwin.close(directory) }; guard fsync(directory) == 0 else { throw V4PoolFailure.storage }
      }
      try check()
    } catch {
      if error is StorageFormatError || (error as? V4PoolFailure) == .storage { environment.root.diagnosticCounters.increment(.storeFailures) }
      close(); throw error
    }
  }
  private func inspectCurrentFormat() throws {
    guard let db else { throw V4PoolFailure.closed }
    try execute("BEGIN")
    do {
      let observed = try Self.format.inspect(db, identity: binding)
      do { try check(writable: false); try validateCurrentRows() }
      catch { throw Self.format.refusal(.schemaOrStateInvalid, observed: observed) }
      guard try scalar("PRAGMA page_size") == 4096 else { throw Self.format.refusal(.backendConfiguration, observed: observed) }
      try execute("ROLLBACK")
    } catch { try? execute("ROLLBACK"); throw error }
  }
  static func safe(_ info: stat, directory: Bool = false) -> Bool {
    info.st_uid == geteuid() && info.st_mode & 0o077 == 0
      && info.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG) && (directory || info.st_nlink == 1)
  }
  func check(writable: Bool = true) throws {
    guard !closed, let db else { throw V4PoolFailure.closed }
    try storage.check(); try disk.check(); try configuration.checkContinuity(configuration.backingIdentity)
    var current = stat(); var directory = stat(); var lock = stat()
    guard lstat(configuration.directory.path, &directory) == 0, Self.safe(directory, directory: true),
      directory.st_dev == directoryIdentity.st_dev, directory.st_ino == directoryIdentity.st_ino,
      lstat(path, &current) == 0, Self.safe(current), current.st_dev == fileIdentity.st_dev, current.st_ino == fileIdentity.st_ino,
      lstat(path + ".lock", &lock) == 0, Self.safe(lock), lock.st_dev == lockIdentity.st_dev, lock.st_ino == lockIdentity.st_ino
    else { throw V4PoolFailure.storage }
    var moved: Int32 = 0
    guard current.st_size >= 0, current.st_size <= configuration.maximumBytes,
      sqlite3_file_control(db, "main", SQLITE_FCNTL_HAS_MOVED, &moved) == SQLITE_OK, moved == 0 else { throw V4PoolFailure.storage }
    for suffix in ["-journal", "-wal", "-shm"] {
      var sidecar = stat()
      if lstat(path + suffix, &sidecar) == 0 {
        guard Self.safe(sidecar), sidecar.st_size >= 0, sidecar.st_size <= configuration.maximumBytes else { throw V4PoolFailure.storage }
      } else if errno != ENOENT { throw V4PoolFailure.storage }
    }
    _ = try Self.format.inspect(db, identity: binding)
    guard (!writable || sqlite3_db_readonly(db, "main") == 0),
      try scalar("SELECT (SELECT count(*) FROM claims) + (SELECT count(*) FROM publications) + (SELECT count(*) FROM claim_originals)") <= configuration.maximumRows else { throw V4PoolFailure.storage }
  }
  private struct StoredKey {
    let parent: Data
    let candidate: Data
    let attempt: Data
    let side: UInt64
    let fields: [(UInt64, Data)]
    var opposite: Data { V4Crypto.map(fields + [(5, V4NamespaceValue.head(0, 1 - side))]) }
  }
  private func storedKey(_ bytes: Data, publication: Bool) throws -> StoredKey {
    var cursor = V4PoolWireCursor(bytes, maximum: 512)
    try cursor.map(6); try cursor.key(0); let storedTenant = try cursor.text(maximum: 128)
    try cursor.key(1); let issuer = try cursor.bytes(maximum: 16)
    try cursor.key(2); let lease = try cursor.bytes(maximum: 16)
    try cursor.key(3); let candidate = try cursor.bytes(maximum: 16)
    try cursor.key(4); let attempt = try cursor.bytes(maximum: 16)
    try cursor.key(5); let side = try cursor.uint(); try cursor.end()
    guard storedTenant == tenant, issuer.count == 16, lease.count == 16, candidate.count == 16,
      attempt.count == (publication ? 0 : 16), side <= 1 else { throw V4PoolFailure.storage }
    let parent: [(UInt64, Data)] = [(0, V4Crypto.text(storedTenant)), (1, V4Crypto.bytes(issuer)), (2, V4Crypto.bytes(lease))]
    return StoredKey(parent: V4Crypto.map(parent), candidate: candidate, attempt: attempt, side: side,
      fields: parent + [(3, V4Crypto.bytes(candidate)), (4, V4Crypto.bytes(attempt))])
  }
  private func storedPossession(_ bytes: Data) throws -> (fields: [Data], source: UInt64) {
    var cursor = V4PoolWireCursor(bytes, maximum: 1024); try cursor.map(9)
    var fields: [Data] = []
    for (key, size) in [32, 32, 16, 32, 32, 16, 32, 32].enumerated() {
      try cursor.key(UInt64(key)); let value = try cursor.bytes(maximum: size)
      guard value.count == size else { throw V4PoolFailure.storage }; fields.append(value)
    }
    try cursor.key(8); let source = try cursor.text(maximum: 32); try cursor.end()
    guard source == V4ActivationSource.liveAuthority.rawValue || source == V4ActivationSource.preauthorizedPool.rawValue else { throw V4PoolFailure.storage }
    return (fields, source == V4ActivationSource.liveAuthority.rawValue ? 0 : 1)
  }
  private func storedOriginal(_ bytes: Data, parent: Data) throws -> (selection: V4StoredParentWinnerProjection, sides: [Data]) {
    var cursor = V4PoolWireCursor(bytes, maximum: 20_480); try cursor.map(3)
    try cursor.key(0); let projection = try cursor.bytes(maximum: 16_384)
    try cursor.key(1); let first = try cursor.bytes(maximum: 1024)
    try cursor.key(2); let last = try cursor.bytes(maximum: 1024); try cursor.end()
    let selection = try V4StoredParentWinnerProjection.capture(parent: parent, projection: projection,
      authority: configuration.parentWinner?.authority, registry: registry)
    guard selection.tenant == tenant else { throw V4PoolFailure.storage }
    let left = try storedPossession(first), right = try storedPossession(last)
    for side in [left, right] {
      guard side.source == selection.source, side.fields[1] == selection.route,
        side.fields[6] == selection.artifact, side.fields[7] == selection.activation else { throw V4PoolFailure.storage }
    }
    guard left.fields[2] == right.fields[2] else { throw V4PoolFailure.storage }
    return (selection, [first, last])
  }
  private func validatePublication(_ bytes: Data) throws {
    var cursor = V4PoolWireCursor(bytes, maximum: 1024); try cursor.map(5); try cursor.key(0)
    // Both variants are part of this physical revision: pending live
    // registration, or the original paired Grant publication.
    if bytes.count > 2, bytes[bytes.startIndex + 2] >> 5 == 3 {
      guard try cursor.text(maximum: 64) == "flowersec/swift/pending-live-relay/1" else { throw V4PoolFailure.storage }
      for key in 1...4 { try cursor.key(UInt64(key)); guard try cursor.bytes(maximum: 32).count == 32 else { throw V4PoolFailure.storage } }
    } else {
      guard try cursor.bytes(maximum: 32).count == 32 else { throw V4PoolFailure.storage }
      for key in 1...4 {
        try cursor.key(UInt64(key)); let size = key == 4 ? 16 : 32
        guard try cursor.bytes(maximum: size).count == size else { throw V4PoolFailure.storage }
      }
    }
    try cursor.end()
  }
  private func blob(_ row: OpaquePointer, _ column: Int32, maximum: Int) throws -> Data {
    let count = Int(sqlite3_column_bytes(row, column))
    guard sqlite3_column_type(row, column) == SQLITE_BLOB, count > 0, count <= maximum,
      let bytes = sqlite3_column_blob(row, column) else { throw V4PoolFailure.storage }
    return Data(bytes: bytes, count: count)
  }
  private func lookup(_ table: String, column: String, key: Data, maximum: Int) throws -> Data? {
    let row = try statement("SELECT projection FROM \(table) WHERE \(column)=?1"); defer { sqlite3_finalize(row) }
    guard key.withUnsafeBytes({ sqlite3_bind_blob(row, 1, $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }) == SQLITE_OK else { throw V4PoolFailure.storage }
    let step = sqlite3_step(row); if step == SQLITE_DONE { return nil }
    guard step == SQLITE_ROW else { throw V4PoolFailure.storage }
    let result = try blob(row, 0, maximum: maximum)
    guard sqlite3_step(row) == SQLITE_DONE else { throw V4PoolFailure.storage }; return result
  }
  private func validateCurrentRows() throws {
    guard try scalar("SELECT count(*) FROM sqlite_schema") == 4 else { throw V4PoolFailure.storage }
    for (table, expected) in [("manifest", Self.manifestSQL), ("publications", Self.publicationsSQL), ("claims", Self.claimsSQL), ("claim_originals", Self.originalsSQL)] {
      let row = try statement("SELECT sql=?1 FROM sqlite_schema WHERE type='table' AND name='\(table)'"); defer { sqlite3_finalize(row) }
      guard sqlite3_bind_text(row, 1, expected, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self)) == SQLITE_OK,
        sqlite3_step(row) == SQLITE_ROW, sqlite3_column_int(row, 0) == 1, sqlite3_step(row) == SQLITE_DONE else { throw V4PoolFailure.storage }
    }
    for table in ["publications", "claim_originals", "claims"] {
      let column = table == "claim_originals" ? "parent" : "claim_key"
      let rows = try statement("SELECT \(column),projection FROM \(table) ORDER BY \(column) LIMIT \(configuration.maximumRows + 1)")
      defer { sqlite3_finalize(rows) }
      var count = 0
      while true {
        let step = sqlite3_step(rows); if step == SQLITE_DONE { break }
        guard step == SQLITE_ROW, count < configuration.maximumRows else { throw V4PoolFailure.storage }; count += 1
        let key = try blob(rows, 0, maximum: 512), value = try blob(rows, 1, maximum: table == "claim_originals" ? 20_480 : 1024)
        if table == "claim_originals" { _ = try storedOriginal(value, parent: key); continue }
        let parsed = try storedKey(key, publication: table == "publications")
        if table == "publications" {
          try validatePublication(value)
          guard try lookup(table, column: column, key: parsed.opposite, maximum: 1024) != nil else { throw V4PoolFailure.storage }
        } else {
          _ = try storedPossession(value)
          guard let original = try lookup("claim_originals", column: "parent", key: parsed.parent, maximum: 20_480) else { throw V4PoolFailure.storage }
          let stored = try storedOriginal(original, parent: parsed.parent)
          guard parsed.candidate == stored.selection.candidate, parsed.attempt == stored.selection.attempt,
            value == stored.sides[Int(parsed.side)],
            try lookup("claims", column: "claim_key", key: parsed.opposite, maximum: 1024) == stored.sides[Int(1 - parsed.side)] else { throw V4PoolFailure.storage }
        }
      }
    }
  }
  func checkBinding(tenant: String, relay: Data) throws {
    guard tenant == self.tenant, relay == self.relay else { throw V4CryptoFailure.authentication }
    try check()
  }
  // The refusal is written before a publication enters the bounded queue. A
  // canceled or failed preparation keeps this row, so no caller can retry the
  // same claim as a new original run. Reading a row creates no capability.
  func publishPendingOriginal(admissions: [V4CredentialAdmission], validate: () throws -> Void) throws {
    try environment.gate.withLock {
      guard admissions.count == 2 else { throw V4CryptoFailure.authentication }
      try check(); try validate(); try execute("BEGIN IMMEDIATE")
      do {
        guard try scalar("SELECT 2 * count(*) FROM publications") <= configuration.maximumRows - 4 else { throw V4PoolFailure.capacity }
        for (side, admission) in admissions.enumerated() {
          let (artifact, _, _) = try admission.relayOriginals(in: environment)
          // The parent key excludes the future attempt. A failed or uncertain
          // registration permanently refuses recreation of this deployment.
          let key = V4Crypto.map([(0, V4Crypto.text(try artifact.t("tenant_id"))),
            (1, V4Crypto.bytes(try artifact.b("issuer_key_id"))), (2, V4Crypto.bytes(try artifact.b("lease_id"))),
            (3, V4Crypto.bytes(admission.candidateID)), (4, V4Crypto.bytes(Data())), (5, V4NamespaceValue.head(0, UInt64(side)))])
          let projection = V4Crypto.map([(0, V4Crypto.text("flowersec/swift/pending-live-relay/1")),
            (1, V4Crypto.bytes(admission.artifactDigest)), (2, V4Crypto.bytes(admission.routeDigest)),
            (3, V4Crypto.bytes(admission.certificateDigests[0])), (4, V4Crypto.bytes(admission.certificateDigests[1]))])
          try write("INSERT INTO publications VALUES(?1,?2)", blobs: [key, projection])
        }
        try check(); try validate(); try execute("COMMIT"); try check(); try validate()
      } catch { try? execute("ROLLBACK"); throw error }
    }
  }
  func publishOriginal(admissions: [V4CredentialAdmission], grants: [V4NamespaceValue], validate: () throws -> Void) throws {
    try environment.gate.withLock {
      guard admissions.count == 2, grants.count == 2 else { throw V4CryptoFailure.authentication }
      try check(); try validate(); try execute("BEGIN IMMEDIATE")
      do {
        guard try scalar("SELECT 2 * count(*) FROM publications") <= configuration.maximumRows - 4 else {
          throw V4PoolFailure.capacity
        }
        for side in 0..<2 {
          let grant = grants[side]; let admission = admissions[side]; let parent = try grant.field("parent_ref")
          let key = V4Crypto.map([(0, V4Crypto.text(try grant.t("tenant_id"))), (1, V4Crypto.bytes(try parent.b("artifact_issuer_key_id"))),
            (2, V4Crypto.bytes(try parent.b("lease_id"))), (3, V4Crypto.bytes(admission.candidateID)),
            (4, V4Crypto.bytes(Data())), (5, V4NamespaceValue.head(0, UInt64(side)))])
          let projection = V4Crypto.map([(0, V4Crypto.bytes(try grant.digest("grant_digest"))),
            (1, V4Crypto.bytes(admission.artifactDigest)), (2, V4Crypto.bytes(admission.activationDigest)),
            (3, V4Crypto.bytes(admission.routeDigest)), (4, V4Crypto.bytes(try grant.b("pairing_id")))])
          try write("INSERT INTO publications VALUES(?1,?2)", blobs: [key, projection])
        }
        try check(); try validate(); try execute("COMMIT"); try check(); try validate()
      } catch { try? execute("ROLLBACK"); throw error }
    }
  }
  func commit(_ possessions: [V4RelayPossession], routes: [V4WebSocketRoute], validate: @escaping () throws -> Void) throws -> V4RelayActivation {
    try environment.gate.withLock {
      guard possessions.count == 2, possessions[0].side == 0, possessions[1].side == 1,
        routes.count == 2, routes[0].credential === possessions[0].admission, routes[1].credential === possessions[1].admission else {
        throw V4CryptoFailure.authentication
      }
      try check(); try validate()
      let first = possessions[0]; let last = possessions[1]
      guard let authority = configuration.parentWinner?.authority else { throw V4PoolFailure.configuration }
      let selection = try first.admission.parentWinnerSelection(authority: authority)
      guard try selection == last.admission.parentWinnerSelection(authority: authority) else { throw V4PoolFailure.conflict }
      // The refusal binds both original possession owners across all
      // candidates before common CAS. It is never a relay activation and
      // cannot be resumed from an exact selection readback after uncertainty.
      try execute("BEGIN IMMEDIATE")
      do {
        guard try scalar("SELECT (SELECT count(*) FROM claims) + (SELECT count(*) FROM publications) + (SELECT count(*) FROM claim_originals)") <= configuration.maximumRows - 3 else { throw V4PoolFailure.capacity }
        let original = V4Crypto.map([(0, V4Crypto.bytes(selection.projection)),
          (1, V4Crypto.bytes(try first.projection)), (2, V4Crypto.bytes(try last.projection))])
        try write("INSERT INTO claim_originals VALUES(?1,?2)", blobs: [selection.parent, original])
        try check(); try validate(); try execute("COMMIT"); try check(); try validate()
      } catch { try? execute("ROLLBACK"); throw error }
      let winner = try V4OriginalParentWinner.select(configuration: configuration.parentWinner,
        possession: first,
        willDispatch: {
          first.admission.connectionFacts.spendDispatched()
          last.admission.connectionFacts.spendDispatched()
        },
        didCommit: {
          first.admission.connectionFacts.spent()
          last.admission.connectionFacts.spent()
        }) { try self.check(); try validate() }
      try winner.consume(owner: first, admission: first.admission)
      // The common CAS is irreversible before this original paired TxA-P.
      // Failure or uncertainty ends this run; no candidate race resumes.
      try execute("BEGIN IMMEDIATE")
      do {
        try check(); try validate()
        guard try scalar("SELECT (SELECT count(*) FROM claims) + (SELECT count(*) FROM publications) + (SELECT count(*) FROM claim_originals)") <= configuration.maximumRows - 2 else { throw V4PoolFailure.capacity }
        for possession in possessions { try write("INSERT INTO claims VALUES(?1,?2)", blobs: [possession.key, possession.projection]) }
        try check(); try validate(); try execute("COMMIT")
        try check(); try validate()
        return V4RelayActivation(routes: routes)
      } catch { try? execute("ROLLBACK"); throw error }
    }
  }
  private func statement(_ sql: String) throws -> OpaquePointer {
    guard let db else { throw V4PoolFailure.closed }
    var value: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &value, nil) == SQLITE_OK, let value else { throw V4PoolFailure.storage }
    return value
  }
  private func execute(_ sql: String) throws {
    guard let db, sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw V4PoolFailure.storage }
  }
  private func scalar(_ sql: String) throws -> Int {
    let value = try statement(sql); defer { sqlite3_finalize(value) }
    guard sqlite3_step(value) == SQLITE_ROW else { throw V4PoolFailure.storage }
    return Int(sqlite3_column_int64(value, 0))
  }
  private func write(_ sql: String, blobs: [Data]) throws {
    let value = try statement(sql); defer { sqlite3_finalize(value) }
    for (offset, blob) in blobs.enumerated() {
      let result = blob.withUnsafeBytes { sqlite3_bind_blob(value, Int32(offset + 1), $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
      guard result == SQLITE_OK else { throw V4PoolFailure.storage }
    }
    guard sqlite3_step(value) == SQLITE_DONE else { throw V4PoolFailure.conflict }
  }
  func close() {
    guard !closed else { return }; closed = true
    if let db { sqlite3_close_v2(db); self.db = nil }
    if file >= 0 { Darwin.close(file); file = -1 }
    if lockFile >= 0 { Darwin.close(lockFile); lockFile = -1 }
    storage.seal()
  }
  deinit { close() }
}
#endif
