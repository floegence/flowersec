#if os(macOS) || os(iOS)
import Crypto
import Foundation

/// Material is independently configured before client authorization starts.
/// Attempt and recipient are supplied by the trusted host; the SDK creates the
/// registration incarnation and never imports it from a request or a receipt.
public struct TransportLiveServerMaterial: Sendable, CustomStringConvertible, CustomReflectable {
  public let artifact: Data
  public let clientCertificate: Data
  public let serverCertificate: Data
  public let attempt: Data
  public let recipient: Data
  public let candidateIndex: Int
  public let activationSigningKeyID: String
  public let tunnel: TransportLiveTunnelConfiguration?
  public init(artifact: Data, clientCertificate: Data, serverCertificate: Data,
    attempt: Data, recipient: Data, candidateIndex: Int = 0, activationSigningKeyID: String,
    tunnel: TransportLiveTunnelConfiguration? = nil) {
    self.artifact = artifact; self.clientCertificate = clientCertificate; self.serverCertificate = serverCertificate
    self.attempt = attempt; self.recipient = recipient; self.candidateIndex = candidateIndex
    self.activationSigningKeyID = activationSigningKeyID; self.tunnel = tunnel
  }
  public var description: String { "Flowersec.LiveServerMaterial(<redacted>)" }
  public var customMirror: Mirror { Mirror(self, children: EmptyCollection<(label: String?, value: Any)>()) }
}

public struct TransportLiveServerBinding: Sendable {
  public let recipient: Data
  public let incarnation: Data
  public let attempt: Data
  public let artifactDigest: Data
  public let candidateIndex: Int
  public let candidateID: Data
  public let routeDigest: Data
}

/// The independent server admission domain has its own immutable backing
/// manifest and filename. Historical records can refuse a registration or
/// admission; they cannot reconstruct its original preparation or consume it.
public struct LiveServerAdmissionStoreConfiguration: Sendable {
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

public struct TransportLiveServerSourceConfiguration: Sendable {
  public let relayPreparation: TransportControlHTTPSConfiguration?
  public let control: TransportServerAllowHTTPSConfiguration
  public let admissions: LiveServerAdmissionStoreConfiguration
  public let maximumRegistrations: Int
  public init(control: TransportServerAllowHTTPSConfiguration, admissions: LiveServerAdmissionStoreConfiguration, maximumRegistrations: Int = 8, relayPreparation: TransportControlHTTPSConfiguration? = nil) {
    self.relayPreparation = relayPreparation; self.control = control; self.admissions = admissions; self.maximumRegistrations = maximumRegistrations
  }
}

/// Retains the original registration service and a closed SDK Source owner.
/// Closing this source fences registration and Acquire. An acquired material
/// has already taken its own original carrier and admission lifetime.
public final class TransportLiveServerSource: @unchecked Sendable {
  public let materialSource: ConnectionMaterialSource
  private let original: V4LiveServerMaterialSource
  init(_ owner: V4LiveServerMaterialSource) { original = owner; materialSource = ConnectionMaterialSource(owner: owner) }
  public func registerOriginal(_ material: TransportLiveServerMaterial) throws -> TransportLiveServerBinding {
    try original.registerOriginal(material)
  }
  public func close() { materialSource.close() }
  public func cleanupStatus() -> CleanupStatus { materialSource.cleanupStatus() }
  public func waitCleanup() async throws -> CleanupStatus { try await materialSource.waitCleanup() }
  deinit { close() }
}

// This capability is made only by the authenticated delivery callback for an
// independently fixed original registration. Decoding bytes cannot make it.
final class V4LiveServerGrantDelivery: @unchecked Sendable {
  let grant: Data
  private let registration: V4LiveServerRegistration
  fileprivate init(grant: Data, registration: V4LiveServerRegistration) { self.grant = grant; self.registration = registration }
  func check(admission: V4CredentialAdmission) throws {
    guard registration.plan.credential === admission else { throw V4CryptoFailure.authentication }
    try registration.checkPublication()
  }
}

struct V4ServerAllowRequest: Sendable {
  let tenant: String; let audience: String
  let artifact: Data; let grantDigest: Data; let relay: Data; let attempt: Data; let pairing: Data
  let serverLeg: Data; let recipient: Data; let incarnation: Data
  let candidateIndex: Int; let candidate: Data; let route: Data; let notAfterMS: UInt64; let grant: Data
  static func decode(_ bytes: Data) throws -> Self {
    var cursor = V4PoolWireCursor(bytes, maximum: 10_326)
    try cursor.array(14)
    guard try cursor.text(maximum: 32) == "tunnel-server-allow-1" else { throw TransportControlError.responseInvalid }
    let tenant = try cursor.text(maximum: 128); let audience = try cursor.text(maximum: 128)
    let artifact = try cursor.bytes(maximum: 32); let grantDigest = try cursor.bytes(maximum: 32); let relay = try cursor.bytes(maximum: 32)
    let attempt = try cursor.bytes(maximum: 16); let pairing = try cursor.bytes(maximum: 16); let serverLeg = try cursor.bytes(maximum: 16)
    let recipient = try cursor.bytes(maximum: 16); let incarnation = try cursor.bytes(maximum: 16)
    try cursor.array(3)
    let candidateIndex = try cursor.uint(); let candidate = try cursor.bytes(maximum: 16); let route = try cursor.bytes(maximum: 32)
    let notAfterMS = try cursor.uint(); let grant = try cursor.bytes(maximum: 9302); try cursor.end()
    guard !tenant.isEmpty, !audience.isEmpty, candidateIndex < 16, notAfterMS > 0, !grant.isEmpty,
      [artifact, grantDigest, relay, route].allSatisfy({ $0.count == 32 && $0.contains(where: { $0 != 0 }) }),
      [attempt, pairing, serverLeg, recipient, incarnation, candidate].allSatisfy({ $0.count == 16 && $0.contains(where: { $0 != 0 }) })
    else { throw TransportControlError.responseInvalid }
    return Self(tenant: tenant, audience: audience, artifact: artifact, grantDigest: grantDigest, relay: relay,
      attempt: attempt, pairing: pairing, serverLeg: serverLeg, recipient: recipient, incarnation: incarnation,
      candidateIndex: Int(candidateIndex), candidate: candidate, route: route, notAfterMS: notAfterMS, grant: grant)
  }
}

final class V4LiveServerRegistration: V4NativeConnectionLifecycle, @unchecked Sendable {
  let plan: V4DirectPoolPlan
  let attempt: Data
  let activationSigningKeyID: String
  let binding: TransportLiveServerBinding
  private let environment: V4EnvironmentFoundation
  private let credentials: V4CredentialConfiguration
  private let identity: V4LocalIdentity
  private let endpoint: TransportEndpoint
  private let roots: [Data]
  private let tls: NativeListenerTLSConfiguration?
  private let relayPreparation: V4ControlHTTPS?
  private let storage: V4CryptoReservation
  private let cleanupJoin: V4CleanupJoin
  // Only CleanupJoin's one prepaid physical task waits on this event channel.
  private let cleanupEvents = V4SessionEvents(maximum: 2)
  private var ledger: V4LiveServerAdmissionLedger?
  private var prepaid: V4PrepaidSessionResources?
  private var native: V4CryptoReservation?
  private var publicationDeadline: V4SecurityDeadline?
  private var ledgerDetached = false
  private var preparation: Task<Void, any Error>?
  private var prepared: V4PreparedWebSocket?
  private var connectingCarrier: V4PreparedWebSocket?
  private var carrier: AnyObject?
  private var publicationBytes: Data?
  private var published = false
  private(set) var transferred = false
  private var consumed = false
  private var consuming = false
  private var closed = false
  private var completionJoined = false
  private var originalAcknowledgementPending: UInt64 = 0
  private weak var source: V4LiveServerMaterialSource?
  init(environment: V4EnvironmentFoundation, credentials: V4CredentialConfiguration, plan: V4DirectPoolPlan,
    identity: V4LocalIdentity, endpoint: TransportEndpoint, roots: [Data], tls: NativeListenerTLSConfiguration?,
    ledger: V4LiveServerAdmissionLedger, configuration: TransportLiveServerMaterial, relayPreparation: TransportControlHTTPSConfiguration? = nil, source: V4LiveServerMaterialSource) throws {
    guard plan.role == .server, plan.credential.source == .liveAuthority,
      configuration.attempt.count == 16, configuration.attempt.contains(where: { $0 != 0 }),
      configuration.recipient.count == 16, configuration.recipient.contains(where: { $0 != 0 }),
      plan.route.isDialer || !plan.route.requiresTLS || tls != nil,
      configuration.tunnel == nil || configuration.tunnel?.scope.roleMask == 6 else { throw TransportConnectError.invalidMaterial }
    self.environment = environment; self.credentials = credentials; self.plan = plan; self.identity = identity
    self.endpoint = endpoint; self.roots = roots; self.tls = tls; self.ledger = ledger; self.source = source
    self.relayPreparation = try relayPreparation.map { try V4ControlHTTPS(environment: environment, configuration: $0) }
    attempt = Data(configuration.attempt); activationSigningKeyID = configuration.activationSigningKeyID
    storage = try environment.liveMaterialSourceStorage()
    cleanupJoin = try V4CleanupJoin(environment: environment)
    let incarnation = try V4Crypto.random(16)
    guard incarnation.contains(where: { $0 != 0 }) else { throw V4CryptoFailure.key }
    binding = TransportLiveServerBinding(recipient: Data(configuration.recipient), incarnation: incarnation, attempt: attempt,
      artifactDigest: plan.credential.artifactDigest, candidateIndex: configuration.candidateIndex,
      candidateID: plan.credential.candidateID, routeDigest: plan.credential.routeDigest)
    prepaid = try V4PrepaidSessionResources(environment: environment, capacity: ConnectionReplacementCapacity(
      maximumFrameBytes: plan.route.maximumFrame, maximumStreams: plan.maxStreams, maximumCreditBytes: plan.maxCredit,
      maximumGeneralOutstanding: plan.maximumGeneralOutstanding, applicationProfile: ["transport", "services", "execution"][Int(plan.applicationProfile)]))
    native = try environment.nativeConnectionStorage(maximumFrame: plan.route.maximumFrame, listener: !plan.route.isDialer)
    try plan.credential.bindLiveServerAttempt(self)
    try plan.credential.prepareLiveActivation(signingKeyID: activationSigningKeyID)
    do {
      try ledger.registerOriginal(self)
      try environment.registerNativeConnection(self)
    } catch { ledger.releaseOriginal(self); throw error }
  }
  func checkPublication() throws {
    try environment.gate.withLock {
      guard !closed, !transferred, !consumed else { throw TransportConnectError.closed }
      try storage.check(); try identity.check(in: environment); try plan.credential.checkPreparation(in: environment); try publicationDeadline?.check(); try prepared?.check()
      guard let ledger else { throw TransportConnectError.closed }; try ledger.check()
    }
  }
  func checkCarrierAdmission() throws {
    try environment.gate.withLock {
      guard !closed, published, transferred, !consumed, carrier != nil else { throw V4CryptoFailure.phase }
      try storage.check(); try identity.check(in: environment); try plan.credential.checkPreparation(in: environment); try publicationDeadline?.check()
      guard let ledger else { throw TransportConnectError.closed }; try ledger.check()
    }
  }
  fileprivate func receive(_ bytes: Data, cleanup: V4ServerAllowRequestCleanup) async throws -> V4ServerAllowAcknowledgement {
    if environment.gate.withLock({ published && publicationBytes == bytes }) {
      try checkDuplicate(bytes)
      return V4ServerAllowAcknowledgement(check: { try self.checkDuplicate(bytes) }, written: {})
    }
    let operation = try environment.gate.withLock { () throws -> Task<Void, any Error> in
      try checkPublication()
      if let publicationBytes {
        guard publicationBytes == bytes, let preparation else { throw V4CryptoFailure.authentication }
        // The first authenticated request may have disconnected after its
        // preparation started but before the ACK write published the material.
        // A retry reuses that same preparation task, while its own HTTP call
        // still owns an independent channel/timer/task/write retirement tail.
        // Join that borrower before returning the shared preparation so source
        // and transferred material cleanup cannot complete on the retry's
        // logical result alone.
        let acknowledgementTail = try storage.executionTail()
        originalAcknowledgementPending += 1
        cleanup.observeCompletion { [self, acknowledgementTail] in
          environment.gate.withLock {
            acknowledgementTail.release()
            originalAcknowledgementPending -= 1
          }
          cleanupEvents.signal()
        }
        return preparation
      }
      let request = try V4ServerAllowRequest.decode(bytes)
      guard plan.credential.pathKind == 1,
        request.tenant == credentials.tenant, request.audience == credentials.audience,
        request.artifact == binding.artifactDigest, request.attempt == attempt,
        request.recipient == binding.recipient, request.incarnation == binding.incarnation,
        request.candidateIndex == binding.candidateIndex, request.candidate == binding.candidateID, request.route == binding.routeDigest,
        request.notAfterMS <= plan.credential.initiationNotAfterMS else { throw V4CryptoFailure.authentication }
      let deadline = try V4SecurityDeadline(clock: environment.clock, capMS: request.notAfterMS)
      try deadline.check()
      // Envelope preflight precedes the one-use Grant completion, so an
      // unrelated request cannot poison an independently fixed preparation.
      let grant = try V4NamespaceDocument(request.grant, schema: "Grant", bytes: 9302, nodes: 4096,
        registry: V4NamespaceRegistry()).root
      let relay = try plan.credential.originalRelayCertificate()
      let candidate = try plan.credential.originalCandidate()
      guard try grant.digest("grant_digest") == request.grantDigest, try relay.digest("certificate_digest") == request.relay,
        try grant.b("attempt_id") == attempt, try grant.b("pairing_id") == request.pairing,
        try candidate.field("server_leg").b("leg_id") == request.serverLeg,
        try grant.u("not_after_ms") >= request.notAfterMS else { throw V4CryptoFailure.authentication }
      let delivery = V4LiveServerGrantDelivery(grant: request.grant, registration: self)
      try plan.credential.completeLiveServerGrant(delivery)
      do {
        // The first authenticated original delivery and any pre-publication
        // retry borrow registration lifetime. Publication can complete before
        // each HTTP request's native write, channel, timer and task tails have
        // actually exited. Replays after publication use the existing result
        // and do not add another material tail.
        let acknowledgementTail = try storage.executionTail()
        publicationDeadline = deadline
        publicationBytes = Data(bytes)
        originalAcknowledgementPending += 1
        cleanup.observeCompletion { [self, acknowledgementTail] in
          environment.gate.withLock {
            acknowledgementTail.release()
            originalAcknowledgementPending -= 1
          }
          cleanupEvents.signal()
        }
        return try startPreparation()
      } catch { close(); source?.preparationFailed(self, error: error); throw error }
    }
    // HTTP disconnect/cancellation cannot create or cancel a second original
    // preparation. The independent TransportEnvironment registration owns this task.
    try await operation.value
    try checkPublication()
    return V4ServerAllowAcknowledgement(check: { try self.checkPublication() }, written: { try self.publishPrepared() })
  }
  private func checkDuplicate(_ bytes: Data) throws {
    try environment.gate.withLock {
      guard published, publicationBytes == bytes else { throw V4CryptoFailure.authentication }
      try plan.credential.checkSessionAuthorization(in: environment); try publicationDeadline?.check()
    }
  }
  fileprivate func startDirect() throws {
    guard plan.credential.pathKind == 0 else { throw V4CryptoFailure.phase }
    _ = try startPreparation()
  }
  private func startPreparation() throws -> Task<Void, any Error> {
    guard preparation == nil else { throw V4CryptoFailure.phase }
    let tail = try storage.executionTail()
    let operation = Task { [self] in
      defer { tail.release(); environment.gate.withLock { completionJoined = true }; cleanupEvents.signal() }
      do {
        try checkPublication()
        let native = try environment.gate.withLock { () throws -> V4CryptoReservation in
          guard let charge = self.native else { throw V4ResourceFailure.owner }; self.native = nil; return charge
        }
        let socket: V4PreparedWebSocket
        if plan.route.isDialer { socket = try await V4PreparedWebSocket.prepare(route: plan.route, numericAddress: endpoint.numericAddress, trustRootsPEM: roots, prepaidNative: native) }
        else { socket = try await V4PreparedWebSocket.listen(route: plan.route, numericAddress: endpoint.numericAddress, tls: tls, prepaidNative: native, onListening: { [self] in
          if let relayPreparation { try await V4RelayCarrierReady.send(admission: plan.credential, provider: relayPreparation, custody: try storage.controlCustody()) { try self.checkPublication() } }
        }) }
        try environment.gate.withLock {
          prepared = socket; carrier = socket.tunnelCarrierIdentity
          try socket.observeClosed { [weak self] in self?.nativeCarrierClosed() }
          guard !closed, !Task.isCancelled else { socket.close(); throw TransportConnectError.canceled }
          try checkPublication()
        }
        if plan.credential.pathKind == 0 { try publishPrepared() }
      } catch {
        let socket = environment.gate.withLock { prepared }; socket?.close(); await socket?.waitClosed()
        let handedOff = environment.gate.withLock { transferred }
        environment.gate.withLock {
          closed = true; cleanupJoin.beginClose(); relayPreparation?.close()
          if !handedOff {
            prepaid?.release(); prepaid = nil; plan.credential.close(); publicationDeadline?.cancel()
            if !ledgerDetached { ledger?.releaseOriginal(self); ledgerDetached = true }; ledger = nil
          }
          storage.seal()
        }
        // A successful material handoff owns the carrier and credential
        // outside this registration. Cancellation of this now-unneeded
        // preparation tail is cleanup, not a new source failure.
        if !handedOff { source?.preparationFailed(self, error: error) }
        throw error
      }
    }
    preparation = operation; return operation
  }
  private func nativeCarrierClosed() {
    environment.gate.withLock {
      guard !closed, !transferred, !consumed else { return }
      close(); source?.preparationFailed(self, error: TransportConnectError.connectionFailed)
    }
  }
  private func publishPrepared() throws {
    try environment.gate.withLock {
      guard !closed, !transferred, prepared != nil else { throw TransportConnectError.closed }
      if published { return }
      try checkPublication(); published = true; source?.publishReady(self)
    }
  }
  func take(_ requirements: ConnectionRequirements) throws -> ConnectionMaterial {
    try environment.gate.withLock {
      try checkPublication(); try V4DirectEstablishment.requirements(requirements, route: plan.route)
      guard published, prepared != nil else { throw V4CryptoFailure.phase }
      if let profile = requirements.applicationProfile {
        guard profile == ["transport", "services", "execution"][Int(plan.applicationProfile)] else { throw TransportConnectError.unsupported }
      }
      transferred = true
      return ConnectionMaterial(owner: V4DirectPoolMaterial(plan: plan, identity: identity, liveServer: self))
    }
  }
  func takePreparedCarrier() throws -> V4PreparedWebSocket {
    try environment.gate.withLock {
      try checkCarrierAdmission()
      guard let socket = prepared else { throw V4CryptoFailure.phase }
      prepared = nil; connectingCarrier = socket
      return socket
    }
  }
  func takeSessionResources() throws -> V4PrepaidSessionResources {
    try environment.gate.withLock {
      try checkCarrierAdmission()
      guard let resources = prepaid else { throw V4CryptoFailure.phase }; prepaid = nil
      try resources.check(in: environment, plan: plan); return resources
    }
  }
  func authenticateFSB(_ bytes: Data, context: Data) throws {
    try environment.gate.withLock {
      try checkCarrierAdmission()
      let request = try V4NamespaceDocument(bytes, schema: "FSB4", bytes: plan.route.maximumFrame, nodes: 4096,
        registry: V4NamespaceRegistry(), context: ["activation_source_profile": "live_authority"]).root
      try request.verify("fsb_signature", publicKey: plan.client.b("ed25519_public_key"))
      try plan.installOriginalServerActivation(request.b("activation_authorization"), registration: self, configuration: credentials)
      try V4DirectEstablishment.verifyRequest(plan, context: context, fsb: bytes)
    }
  }
  func consume(_ claim: V4PreparedPoolClaim, fsb: Data, context: Data) throws -> V4ConsumedWebSocket {
    let (tail, ledger) = try environment.gate.withLock { () throws -> (V4ResourceReference, V4LiveServerAdmissionLedger) in
      try checkCarrierAdmission(); try claim.check()
      guard claim.environment === environment, claim.facts == nil, claim.tunnelCarrierIdentity === carrier,
        let value = self.ledger else { throw V4CryptoFailure.authentication }
      guard !consuming else { throw V4CryptoFailure.phase }
      let tail = try storage.executionTail()
      consuming = true
      return (tail, value)
    }
    defer {
      environment.gate.withLock {
        consuming = false
        if closed { closeResources() }
      }
      tail.release()
      cleanupEvents.signal()
    }
    do {
      try V4DirectEstablishment.verifyRequest(plan, context: context, fsb: fsb)
      let admission = try ledger.admitOriginal(self, claim: claim, fsb: fsb, context: context)
      // Only this original successful durable COMMIT continues consumption.
      return try environment.gate.withLock {
        let socket = try V4ConsumedWebSocket.liveServer(admission)
        try Task.checkCancellation()
        consumed = true
        return socket
      }
    }
  }
  func transferCleanupToSource() {
    source?.retainTransferredCleanup(self)
  }
  func finish(success: Bool) {
    environment.gate.withLock {
      closed = true; relayPreparation?.close(); carrier = nil
      cleanupJoin.beginClose()
      if success {
        // The Session owns the transferred carrier, while the original
        // preparation and relay-control tails still belong to this
        // registration. Let those tails finish naturally; the source's
        // transferred observer joins their physical cleanup before reclaiming
        // the bounded registration slot.
        prepared = nil; connectingCarrier = nil
      } else {
        preparation?.cancel(); prepared?.close(); connectingCarrier?.close()
      }
      if !ledgerDetached { ledger?.releaseOriginal(self); ledgerDetached = true }; ledger = nil
      if !success { publicationDeadline?.cancel() }; native?.seal(); native = nil
      prepaid?.release(); prepaid = nil; storage.seal()
      if !success { plan.credential.close() }
    }
    cleanupEvents.signal()
  }
  func closeFromSource() { environment.gate.withLock { if !transferred { close() } } }
  func close() {
    environment.gate.withLock {
      guard !closed else { return }; closed = true; relayPreparation?.close()
      cleanupJoin.beginClose()
      preparation?.cancel(); prepared?.close(); connectingCarrier?.close(); prepaid?.release(); prepaid = nil; native?.seal(); native = nil; publicationDeadline?.cancel()
      guard !consuming else { return }
      closeResources()
    }
    cleanupEvents.signal()
  }
  private func closeResources() {
    if !consumed { plan.credential.close() }
    if !ledgerDetached { ledger?.releaseOriginal(self); ledgerDetached = true }; ledger = nil
    storage.seal()
  }
  func cleanupStatus() -> CleanupStatus {
    cleanupJoin.status(physicalCleanupStatus())
  }
  private func physicalCleanupStatus() -> CleanupStatus {
    environment.gate.withLock {
      let socketPending = (prepared ?? connectingCarrier)?.cleanupStatus().pendingCallbacks ?? 0
      let taskPending: UInt64 = completionJoined || preparation == nil ? 0 : 1
      let controlPending = relayPreparation?.cleanupStatus().pendingCallbacks ?? 0
      let pending = taskPending + socketPending + controlPending + (consuming ? 1 : 0)
        + originalAcknowledgementPending
      return CleanupStatus(complete: closed && pending == 0,
        cleanupIncomplete: closed && pending != 0, pendingCallbacks: pending)
    }
  }
  func waitCleanup() async throws -> CleanupStatus {
    try await cleanupJoin.wait { [self] in await waitPhysicalComponents() }
    let result = cleanupStatus()
    return result
  }
  private func waitPhysicalComponents() async {
    let operation = environment.gate.withLock { preparation }
    if let operation {
      // The preparation task releases its charged tail in defer before it
      // publishes completion. Reassert the joined fact after awaiting the
      // task so a successful handoff cannot leave the registration's observer
      // pending on a missed callback race.
      _ = try? await operation.value
      environment.gate.withLock { completionJoined = true }
      cleanupEvents.signal()
    }
    // Acquire transfers material before the connection has promoted its
    // carrier to Session. Wait for finish/close before capturing a socket so
    // an early cleanup observer cannot retain and join the Session's carrier.
    while true {
      let revision = cleanupEvents.revision
      if environment.gate.withLock({ closed && !consuming }) { break }
      try? await cleanupEvents.wait(after: revision)
    }
    let socket = environment.gate.withLock { prepared ?? connectingCarrier }; await socket?.waitPhysicalCleanup()
    if let relayPreparation { await relayPreparation.waitPhysicalCleanup() }
    while true {
      let revision = cleanupEvents.revision
      if physicalCleanupStatus().complete {
        return
      }
      try? await cleanupEvents.wait(after: revision)
    }
  }
  func waitPhysicalCleanup() async {
    await cleanupJoin.waitPhysicalCompletion { [self] in await waitPhysicalComponents() }
  }
  func waitTransferredCleanup() async {
    await waitPhysicalCleanup()
  }
  deinit { close() }
}

private final class V4WeakServerRegistration {
  weak var value: V4LiveServerRegistration?
  init(_ value: V4LiveServerRegistration) { self.value = value }
}

final class V4LiveServerMaterialSource: V4ConfiguredMaterialSourceOwner, V4NativeConnectionLifecycle, @unchecked Sendable {
  private let environment: V4EnvironmentFoundation
  private let credentials: V4CredentialConfiguration
  private let endpoints: [TransportEndpoint]
  private let roots: [Data]
  private let tls: NativeListenerTLSConfiguration?
  private let identity: V4LocalIdentity
  private let configuration: TransportLiveServerSourceConfiguration
  private let storage: V4CryptoReservation
  private let ledger: V4LiveServerAdmissionLedger
  private let cleanupJoin: V4CleanupJoin
  private let cleanupEvents = V4SessionEvents(maximum: 2)
  private var control: V4ServerAllowHTTPS?
  private var registrations: [Data: V4LiveServerRegistration] = [:]
  private var retiring: [Data: V4LiveServerRegistration] = [:]
  // A successful material handoff transfers cleanup observation here. The
  // weak routing index remains separate so it cannot own lifecycle by itself.
  private var transferredCleanup: [Data: V4LiveServerRegistration] = [:]
  private var transferredObservers: [Data: Task<Void, Never>] = [:]
  private var transferred: [Data: V4WeakServerRegistration] = [:]
  private var ready: [V4LiveServerRegistration] = []
  private var waiter: CheckedContinuation<ConnectionMaterial, any Error>?
  private var requested: ConnectionRequirements?
  private var acquireGeneration: UInt64 = 0
  private var waitingGeneration: UInt64?
  private var failures: [any Error] = []
  private var closed = false
  private var registeringOriginal = false
  init(environment: V4EnvironmentFoundation, credentials: V4CredentialConfiguration, endpoints: [TransportEndpoint],
    roots: [Data], tls: NativeListenerTLSConfiguration?, identity: V4LocalIdentity, configuration: TransportLiveServerSourceConfiguration) throws {
    guard (1...64).contains(configuration.maximumRegistrations) else { throw V4ResourceFailure.configuration }
    self.environment = environment; self.credentials = credentials; self.endpoints = endpoints; self.roots = roots
    self.tls = tls; self.identity = identity; self.configuration = configuration
    storage = try environment.relayPublicationQueueStorage(capacity: configuration.maximumRegistrations)
    cleanupJoin = try V4CleanupJoin(environment: environment)
    let tail = try storage.executionTail()
    defer { tail.release() }
    ledger = try V4LiveServerAdmissionLedger(environment: environment, configuration: configuration.admissions,
      tenant: credentials.tenant, audience: credentials.audience, serverIdentity: identity.identityPublicKey)
    do {
      try environment.gate.withLock {
        try storage.check(); try identity.check(in: environment); try ledger.check(); try Task.checkCancellation()
        try environment.registerNativeConnection(self)
      }
    } catch { ledger.close(); storage.seal(); throw error }
  }
  func start() async throws {
    let service = try V4ServerAllowHTTPS(environment: environment, configuration: configuration.control,
      receiveWithCleanup: { [weak self] body, cleanup in
        guard let self else { throw TransportControlError.closed }
        let request = try V4ServerAllowRequest.decode(body)
        let registration = try environment.gate.withLock { () throws -> V4LiveServerRegistration in
          try check(in: environment)
          guard let registration = registrations[request.incarnation] ?? transferred[request.incarnation]?.value else { throw V4CryptoFailure.authentication }
          return registration
        }
        return try await registration.receive(body, cleanup: cleanup)
      }, receive: { _ in throw V4CryptoFailure.phase })
    try environment.gate.withLock { guard !closed else { throw TransportControlError.closed }; control = service }
    do { try await service.start() } catch { close(); throw error }
  }
  func registerOriginal(_ configuration: TransportLiveServerMaterial) throws -> TransportLiveServerBinding {
    let tail = try environment.gate.withLock { () throws -> V4ResourceReference in
      try check(in: environment); try Task.checkCancellation()
      collectRetired()
      guard !registeringOriginal,
        registrations.count + retiring.count + transferredCleanup.count < self.configuration.maximumRegistrations
      else { throw V4ResourceFailure.capacity }
      let tail = try storage.executionTail()
      registeringOriginal = true
      return tail
    }
    defer { environment.gate.withLock { registeringOriginal = false }; tail.release(); cleanupEvents.signal() }
    let input = V4CredentialInput(artifact: configuration.artifact, clientCertificate: configuration.clientCertificate,
        serverCertificate: configuration.serverCertificate, activation: Data(), source: .liveAuthority,
        candidateIndex: configuration.candidateIndex, liveTunnel: configuration.tunnel, localRole: .server)
    let admission = try environment.verifyDirectCredentials(configuration: credentials, input: input)
    do {
      let plan = try admission.directPoolPlan(in: environment, identity: identity)
      let matches = endpoints.filter { $0.hostname == plan.route.host && $0.port == plan.route.port }
      guard matches.count == 1 else { throw TransportConnectError.unsupported }
      let registration = try V4LiveServerRegistration(environment: environment, credentials: credentials, plan: plan,
        identity: identity, endpoint: matches[0], roots: roots, tls: tls, ledger: ledger, configuration: configuration, relayPreparation: self.configuration.relayPreparation, source: self)
      let installed = environment.gate.withLock { () -> Bool in
        guard !closed,
          registrations.count + retiring.count + transferredCleanup.count < self.configuration.maximumRegistrations
        else { return false }
        registrations[registration.binding.incarnation] = registration
        return true
      }
      guard installed else { registration.close(); throw ConnectionMaterialSourceError.closed }
      do { if plan.credential.pathKind == 0 { try registration.startDirect() } }
      catch {
        registration.close()
        _ = environment.gate.withLock { registrations.removeValue(forKey: registration.binding.incarnation) }
        throw error
      }
      do {
        return try environment.gate.withLock {
          try check(in: environment); try Task.checkCancellation()
          guard registrations[registration.binding.incarnation] === registration else { throw ConnectionMaterialSourceError.closed }
          return registration.binding
        }
      } catch { registration.close(); throw error }
    } catch { admission.close(); throw error }
  }
  func check(in original: V4EnvironmentFoundation) throws {
    try environment.gate.withLock {
      guard original === environment, !closed else { throw ConnectionMaterialSourceError.closed }
      try storage.check(); try identity.check(in: environment); try ledger.check()
    }
  }
  func acquire(_ requirements: ConnectionRequirements) async throws -> ConnectionMaterial {
    try V4DirectEstablishment.requirements(requirements)
    let generation = try environment.gate.withLock { () throws -> UInt64 in
      try check(in: environment); try Task.checkCancellation()
      guard waitingGeneration == nil else { throw TransportControlError.busy }
      let next = acquireGeneration.addingReportingOverflow(1)
      guard !next.overflow else { throw V4ResourceFailure.capacity }
      acquireGeneration = next.partialValue; waitingGeneration = acquireGeneration; requested = requirements
      return acquireGeneration
    }
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        environment.gate.withLock {
          do {
            try check(in: environment)
            guard waitingGeneration == generation else { throw TransportConnectError.canceled }
            try Task.checkCancellation()
            if !failures.isEmpty { throw failures.removeFirst() }
            if !ready.isEmpty {
              waitingGeneration = nil; requested = nil
              continuation.resume(returning: try takeReady(requirements)); return
            }
            waiter = continuation
          } catch {
            if waitingGeneration == generation { waitingGeneration = nil; waiter = nil; requested = nil }
            continuation.resume(throwing: error)
          }
        }
      }
    } onCancel: {
      self.environment.gate.withLock {
        // A late cancellation belongs only to its original Acquire. A newer
        // invocation may already own the source's single waiting position.
        guard self.waitingGeneration == generation else { return }
        self.waitingGeneration = nil; self.requested = nil
        let original = self.waiter; self.waiter = nil
        original?.resume(throwing: TransportConnectError.canceled)
      }
    }
  }
  private func collectRetired() {
    retiring = retiring.filter { !$0.value.cleanupStatus().complete }
    let completedTransferred = transferredCleanup.compactMap { incarnation, registration in
      registration.cleanupStatus().complete ? incarnation : nil
    }
    for incarnation in completedTransferred {
      transferredCleanup.removeValue(forKey: incarnation)
      transferred.removeValue(forKey: incarnation)
      transferredObservers.removeValue(forKey: incarnation)
    }
    transferred = transferred.filter {
      transferredCleanup[$0.key] != nil && $0.value.value != nil
    }
  }
  fileprivate func retainTransferredCleanup(_ registration: V4LiveServerRegistration) {
    environment.gate.withLock {
      // takeReady reserves the bounded strong observer slot before returning
      // material. The handoff only confirms that reservation; it never grows
      // the source's transferred owner set after the fact.
      guard transferredCleanup[registration.binding.incarnation] === registration else { return }
      transferred[registration.binding.incarnation] = V4WeakServerRegistration(registration)
      startTransferredObserver(registration)
    }
    cleanupEvents.signal()
  }
  private func startTransferredObserver(_ registration: V4LiveServerRegistration) {
    let incarnation = registration.binding.incarnation
    guard transferredObservers[incarnation] == nil else { return }
    transferredObservers[incarnation] = Task { [weak self, registration] in
      // The material's public waitCleanup may be observing the same original
      // registration. Use the independent physical join here, then let the
      // registration finish its CleanupJoin bookkeeping before freeing the
      // source's bounded strong observer slot.
      await registration.waitTransferredCleanup()
      self?.transferredCleanupCompleted(registration)
    }
  }
  fileprivate func transferredCleanupCompleted(_ registration: V4LiveServerRegistration) {
    guard registration.cleanupStatus().complete else { return }
    environment.gate.withLock {
      guard transferredCleanup[registration.binding.incarnation] === registration else { return }
      transferredCleanup.removeValue(forKey: registration.binding.incarnation)
      transferred.removeValue(forKey: registration.binding.incarnation)
      transferredObservers.removeValue(forKey: registration.binding.incarnation)
    }
    cleanupEvents.signal()
  }
  private func takeReady(_ requirements: ConnectionRequirements) throws -> ConnectionMaterial {
    collectRetired()
    guard transferredCleanup.count < configuration.maximumRegistrations else { throw V4ResourceFailure.capacity }
    guard let first = ready.first else { throw V4CryptoFailure.phase }
    let material = try first.take(requirements)
    ledger.transferSourceCleanup()
    ready.removeFirst(); registrations.removeValue(forKey: first.binding.incarnation)
    transferredCleanup[first.binding.incarnation] = first
    transferred[first.binding.incarnation] = V4WeakServerRegistration(first)
    startTransferredObserver(first)
    return material
  }
  fileprivate func publishReady(_ registration: V4LiveServerRegistration) {
    environment.gate.withLock {
      guard !closed, registrations[registration.binding.incarnation] === registration else { registration.closeFromSource(); return }
      ready.append(registration)
      if let waiter, let requested {
        self.waiter = nil; self.requested = nil; waitingGeneration = nil
        do { waiter.resume(returning: try takeReady(requested)) } catch { waiter.resume(throwing: error) }
      }
    }
  }
  fileprivate func preparationFailed(_ registration: V4LiveServerRegistration, error: any Error) {
    environment.gate.withLock {
      guard registrations[registration.binding.incarnation] === registration else { return }
      registrations.removeValue(forKey: registration.binding.incarnation)
      ready.removeAll { $0 === registration }
      // The failed original still owns its preparation/provider tail. Keep it
      // in the same bounded source until its actual cleanup completes.
      retiring[registration.binding.incarnation] = registration
      if let waiter { self.waiter = nil; requested = nil; waitingGeneration = nil; waiter.resume(throwing: error) }
      else if failures.count < configuration.maximumRegistrations { failures.append(error) }
    }
  }
  func close() {
    environment.gate.withLock {
      guard !closed else { return }; closed = true
      cleanupJoin.beginClose()
      control?.close()
      let original = waiter; waiter = nil; requested = nil; waitingGeneration = nil
      original?.resume(throwing: ConnectionMaterialSourceError.closed)
      for (key, registration) in registrations { retiring[key] = registration }
      registrations.removeAll(); ready.removeAll(); failures.removeAll()
      for registration in retiring.values { registration.closeFromSource() }
      ledger.retireWhenIdle(); storage.seal()
    }
  }
  func cleanupStatus() -> CleanupStatus {
    environment.gate.withLock {
      collectRetired()
      let count = UInt64(
        registrations.values.filter { !$0.cleanupStatus().complete }.count
          + retiring.values.filter { !$0.cleanupStatus().complete }.count
      )
        + (control?.cleanupStatus().pendingCallbacks ?? 0) + (registeringOriginal ? 1 : 0)
        + ledger.sourceCleanupPending()
      return cleanupJoin.status(CleanupStatus(complete: closed && count == 0,
        cleanupIncomplete: closed && count != 0, pendingCallbacks: count))
    }
  }
  func waitCleanup() async throws -> CleanupStatus {
    try await cleanupJoin.wait { [self] in
      while true {
        let revision = cleanupEvents.revision
        if environment.gate.withLock({ !registeringOriginal }) { break }
        try? await cleanupEvents.wait(after: revision)
      }
      if let control { await control.waitPhysicalCleanup() }
      for registration in environment.gate.withLock({ Array(registrations.values) + Array(retiring.values) }) {
        await registration.waitPhysicalCleanup()
      }
      await ledger.waitSourceCleanup()
    }
    return cleanupStatus()
  }
  deinit { close() }
}
#endif
