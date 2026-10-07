#if os(macOS) || os(iOS)
import Foundation

/// A finite server source retains independently installed pool credentials and
/// exposes their original delivery bindings only after native preparation starts.
public final class TransportPoolServerSource: @unchecked Sendable {
  public let materialSource: ConnectionMaterialSource
  public let bindings: [TransportLiveServerBinding]
  init(_ original: V4PoolServerMaterialSource) {
    materialSource = ConnectionMaterialSource(owner: original)
    bindings = original.bindings
  }
  public func close() { materialSource.close() }
  public func cleanupStatus() -> CleanupStatus { materialSource.cleanupStatus() }
  public func waitCleanup() async throws -> CleanupStatus { try await materialSource.waitCleanup() }
  deinit { close() }
}

// A request can release this original preparation exactly once. It cannot
// replace the installed Grant, reconstruct an admission, or assert client spend.
final class V4PoolServerRegistration: V4NativeConnectionLifecycle, @unchecked Sendable {
  let plan: V4DirectPoolPlan
  let binding: TransportLiveServerBinding
  private let environment: V4EnvironmentFoundation
  private let identity: V4LocalIdentity
  private let endpoint: TransportEndpoint
  private let roots: [Data]
  private let tls: NativeListenerTLSConfiguration?
  private let storage: V4CryptoReservation
  private let cleanupJoin: V4CleanupJoin
  private let cleanupEvents = V4SessionEvents(maximum: 2)
  private let listeningEvents = V4SessionEvents(maximum: 1)
  private weak var source: V4PoolServerMaterialSource?
  private var prepaid: V4PrepaidSessionResources?
  private var native: V4CryptoReservation?
  private var preparation: Task<Void, any Error>?
  private var prepared: V4PreparedWebSocket?
  private var connectingCarrier: V4PreparedWebSocket?
  private var carrierIdentity: ObjectIdentifier?
  private var deadline: V4SecurityDeadline?
  private var failure: (any Error)?
  private var listening = false
  private var joined = false
  private var receiving = false
  private var published = false
  private(set) var transferred = false
  private var closed = false
  private var acknowledgements: UInt64 = 0
  var available: Bool { environment.gate.withLock { !closed && !transferred } }

  init(environment: V4EnvironmentFoundation, plan: V4DirectPoolPlan, identity: V4LocalIdentity,
    candidateIndex: Int, endpoint: TransportEndpoint, roots: [Data], tls: NativeListenerTLSConfiguration?,
    storage: V4CryptoReservation, source: V4PoolServerMaterialSource) throws {
    guard plan.role == .server, plan.credential.source == .preauthorizedPool,
      plan.credential.pathKind == 1, plan.route.isDialer || !plan.route.requiresTLS || tls != nil
    else { throw TransportConnectError.invalidMaterial }
    self.environment = environment; self.plan = plan; self.identity = identity
    self.endpoint = endpoint; self.roots = roots; self.tls = tls; self.storage = storage; self.source = source
    cleanupJoin = try V4CleanupJoin(environment: environment)
    let recipient = try V4Crypto.random(16); let incarnation = try V4Crypto.random(16)
    guard [recipient, incarnation].allSatisfy({ $0.contains(where: { $0 != 0 }) }) else { throw V4CryptoFailure.key }
    binding = TransportLiveServerBinding(recipient: recipient, incarnation: incarnation,
      attempt: plan.credential.attemptID, artifactDigest: plan.credential.artifactDigest,
      candidateIndex: candidateIndex, candidateID: plan.credential.candidateID, routeDigest: plan.credential.routeDigest)
    prepaid = try V4PrepaidSessionResources(environment: environment, capacity: ConnectionReplacementCapacity(
      maximumFrameBytes: plan.route.maximumFrame, maximumStreams: plan.maxStreams, maximumCreditBytes: plan.maxCredit,
      maximumGeneralOutstanding: plan.maximumGeneralOutstanding,
      applicationProfile: ["transport", "services", "execution"][Int(plan.applicationProfile)]))
    native = try environment.nativeConnectionStorage(maximumFrame: plan.route.maximumFrame, listener: !plan.route.isDialer)
    try environment.registerNativeConnection(self)
  }
  private func checkOriginal() throws {
    guard !closed else { throw TransportConnectError.closed }
    try storage.check(); try identity.check(in: environment)
    try plan.credential.checkPreparation(in: environment); try deadline?.check()
    if let failure { throw failure }
  }
  private func checkPublication() throws {
    try checkOriginal()
    guard !published, !transferred else { throw V4CryptoFailure.phase }
    guard let source else { throw TransportConnectError.closed }; try source.check(in: environment)
    try prepared?.check()
  }
  func checkCarrierAdmission() throws {
    try environment.gate.withLock {
      try checkOriginal()
      guard published, transferred, carrierIdentity != nil else { throw V4CryptoFailure.phase }
    }
  }
  func start() throws {
    try environment.gate.withLock {
      try checkPublication()
      guard preparation == nil else { throw V4CryptoFailure.phase }
      let tail = try storage.executionTail()
      preparation = Task { [self] in
        defer {
          tail.release(); environment.gate.withLock { joined = true }
          cleanupEvents.signal(); listeningEvents.signal()
        }
        do {
          let charge = try environment.gate.withLock { () throws -> V4CryptoReservation in
            try checkPublication()
            guard let native else { throw V4ResourceFailure.owner }; self.native = nil; return native
          }
          let socket: V4PreparedWebSocket
          if plan.route.isDialer {
            socket = try await V4PreparedWebSocket.prepare(route: plan.route,
              numericAddress: endpoint.numericAddress, trustRootsPEM: roots, prepaidNative: charge)
          } else {
            socket = try await V4PreparedWebSocket.listen(route: plan.route,
              numericAddress: endpoint.numericAddress, tls: tls, prepaidNative: charge, onListening: { [self] in
                try environment.gate.withLock { try checkPublication(); listening = true }
                listeningEvents.signal()
              })
          }
          do {
            try environment.gate.withLock {
              try checkPublication(); try Task.checkCancellation(); try socket.check()
              prepared = socket; carrierIdentity = ObjectIdentifier(socket.tunnelCarrierIdentity)
              try socket.observeClosed { [weak self] in self?.nativeCarrierClosed() }
            }
          } catch { socket.close(); await socket.waitPhysicalCleanup(); throw error }
        } catch {
          environment.gate.withLock { failure = error }
          close(); source?.preparationFailed(self, error: error)
          throw error
        }
      }
    }
  }
  private func nativeCarrierClosed() {
    environment.gate.withLock {
      guard !closed, !transferred else { return }
      failure = TransportConnectError.connectionFailed
      close(); source?.preparationFailed(self, error: TransportConnectError.connectionFailed)
    }
  }
  func waitListening() async throws {
    guard !plan.route.isDialer else { return }
    while true {
      let revision = listeningEvents.revision
      let ready = try environment.gate.withLock { () throws -> Bool in
        if let failure { throw failure }
        try checkPublication(); return listening
      }
      if ready { return }
      try await listeningEvents.wait(after: revision)
    }
  }
  func receive(_ bytes: Data, cleanup: V4ServerAllowRequestCleanup) async throws -> V4ServerAllowAcknowledgement {
    let operation = try environment.gate.withLock { () throws -> Task<Void, any Error> in
      try checkPublication(); try Task.checkCancellation()
      guard !receiving, let preparation else { throw V4CryptoFailure.phase }
      let request = try V4ServerAllowRequest.decode(bytes)
      let grant = try plan.credential.tunnelGrant().0
      let relay = try plan.credential.originalRelayCertificate()
      let candidate = try plan.credential.originalCandidate()
      guard request.tenant == (try plan.artifact.t("tenant_id")),
        request.audience == (try plan.artifact.t("audience")), request.artifact == binding.artifactDigest,
        request.attempt == binding.attempt, request.recipient == binding.recipient, request.incarnation == binding.incarnation,
        request.candidateIndex == binding.candidateIndex, request.candidate == binding.candidateID, request.route == binding.routeDigest,
        request.grant.elementsEqual(grant.raw), request.grantDigest == (try grant.digest("grant_digest")),
        request.relay == (try relay.digest("certificate_digest")), request.pairing == (try grant.b("pairing_id")),
        request.serverLeg == (try candidate.field("server_leg").b("leg_id")),
        request.notAfterMS <= min(plan.credential.initiationNotAfterMS,
          try plan.artifact.u("session_not_after_ms"), try grant.u("not_after_ms"))
      else { throw V4CryptoFailure.authentication }
      let deadline = try V4SecurityDeadline(clock: environment.clock, capMS: request.notAfterMS)
      try deadline.check()
      let tail = try storage.executionTail()
      do { try plan.credential.constrainPoolServerAllow(registration: self, notAfterMS: request.notAfterMS) }
      catch { tail.release(); throw error }
      self.deadline = deadline; receiving = true; acknowledgements += 1
      cleanup.observeCompletion { [self, tail] in
        environment.gate.withLock {
          tail.release(); acknowledgements -= 1
          if !published, !closed {
            failure = TransportConnectError.connectionFailed
            close(); source?.preparationFailed(self, error: TransportConnectError.connectionFailed)
          }
        }
        cleanupEvents.signal()
      }
      return preparation
    }
    try await operation.value
    try Task.checkCancellation()
    try environment.gate.withLock { try checkPublication(); guard prepared != nil else { throw V4CryptoFailure.phase } }
    return V4ServerAllowAcknowledgement(check: { [self] in
      try environment.gate.withLock { try checkPublication(); guard prepared != nil else { throw V4CryptoFailure.phase } }
    }, written: { [self] in
      try environment.gate.withLock {
        try checkPublication(); guard receiving, prepared != nil else { throw V4CryptoFailure.phase }
        published = true; source?.publishReady(self)
      }
    })
  }
  func take(_ requirements: ConnectionRequirements) throws -> ConnectionMaterial {
    try environment.gate.withLock {
      try checkOriginal(); try V4DirectEstablishment.requirements(requirements, route: plan.route)
      guard published, !transferred, prepared != nil else { throw V4CryptoFailure.phase }
      if let profile = requirements.applicationProfile {
        guard profile == ["transport", "services", "execution"][Int(plan.applicationProfile)] else { throw TransportConnectError.unsupported }
      }
      transferred = true
      return ConnectionMaterial(owner: V4DirectPoolMaterial(plan: plan, identity: identity, poolServer: self))
    }
  }
  func takePreparedCarrier() throws -> V4PreparedWebSocket {
    try environment.gate.withLock {
      try checkCarrierAdmission()
      guard let prepared else { throw V4CryptoFailure.phase }
      self.prepared = nil; connectingCarrier = prepared; return prepared
    }
  }
  func takeSessionResources() throws -> V4PrepaidSessionResources {
    try environment.gate.withLock {
      try checkCarrierAdmission()
      guard let prepaid else { throw V4CryptoFailure.phase }
      try prepaid.check(in: environment, plan: plan); self.prepaid = nil; return prepaid
    }
  }
  func checkCarrier(_ original: V4PreparedWebSocket) throws {
    try environment.gate.withLock {
      try checkCarrierAdmission()
      guard carrierIdentity == ObjectIdentifier(original.tunnelCarrierIdentity), connectingCarrier === original
      else { throw V4CryptoFailure.authentication }
      try original.check()
    }
  }
  func finish(success: Bool) {
    environment.gate.withLock {
      guard !closed else { return }; closed = true; cleanupJoin.beginClose()
      if success { prepared = nil; connectingCarrier = nil; carrierIdentity = nil }
      else { preparation?.cancel(); prepared?.close(); connectingCarrier?.close(); plan.credential.close() }
      deadline?.cancel(); native?.seal(); native = nil; prepaid?.release(); prepaid = nil; storage.seal()
    }
    cleanupEvents.signal(); listeningEvents.signal()
  }
  func closeFromSource() { environment.gate.withLock { if !transferred { close() } } }
  func close() { finish(success: false) }
  private func physicalCleanupStatus() -> CleanupStatus {
    environment.gate.withLock {
      let task: UInt64 = preparation == nil || joined ? 0 : 1
      let pending = task + acknowledgements + ((prepared ?? connectingCarrier)?.cleanupStatus().pendingCallbacks ?? 0)
      return CleanupStatus(complete: closed && pending == 0, cleanupIncomplete: closed && pending != 0, pendingCallbacks: pending)
    }
  }
  func cleanupStatus() -> CleanupStatus { cleanupJoin.status(physicalCleanupStatus()) }
  private func waitPhysicalComponents() async {
    if let operation = environment.gate.withLock({ preparation }) { _ = try? await operation.value }
    while true {
      let revision = cleanupEvents.revision
      if environment.gate.withLock({ closed }) { break }
      try? await cleanupEvents.wait(after: revision)
    }
    // Capture only after material finish detaches a successfully admitted Session.
    let socket = environment.gate.withLock { prepared ?? connectingCarrier }
    await socket?.waitPhysicalCleanup()
    while true {
      let revision = cleanupEvents.revision
      if physicalCleanupStatus().complete { return }
      try? await cleanupEvents.wait(after: revision)
    }
  }
  func waitTransferredCleanup() async {
    await cleanupJoin.waitPhysicalCompletion { [self] in await waitPhysicalComponents() }
  }
  func waitCleanup() async throws -> CleanupStatus {
    try await cleanupJoin.wait { [self] in await waitPhysicalComponents() }; return cleanupStatus()
  }
  deinit { close() }
}

final class V4PoolServerMaterialSource: V4ConfiguredMaterialSourceOwner, V4NativeConnectionLifecycle, @unchecked Sendable {
  private let environment: V4EnvironmentFoundation
  private let identity: V4LocalIdentity
  private let storage: V4CryptoReservation
  private let cleanupJoin: V4CleanupJoin
  private let readyEvents = V4SessionEvents(maximum: 1)
  private let cleanupEvents = V4SessionEvents(maximum: 1)
  private var registrations: [V4PoolServerRegistration] = []
  private var ready: [V4PoolServerRegistration] = []
  private var failures: [any Error] = []
  private var control: V4ServerAllowHTTPS?
  private var closed = false
  private var acquiring = false
  var bindings: [TransportLiveServerBinding] { environment.gate.withLock { registrations.map(\.binding) } }
  init(environment: V4EnvironmentFoundation, identity: V4LocalIdentity) throws {
    self.environment = environment; self.identity = identity
    storage = try environment.liveMaterialSourceStorage(); cleanupJoin = try V4CleanupJoin(environment: environment)
    try environment.registerNativeConnection(self)
  }
  func append(plan: V4DirectPoolPlan, candidateIndex: Int, endpoint: TransportEndpoint,
    roots: [Data], tls: NativeListenerTLSConfiguration?, storage: V4CryptoReservation) throws {
    try environment.gate.withLock {
      try check(in: environment)
      guard registrations.count < 8 else { throw V4ResourceFailure.capacity }
      // Independently prepared listeners must not compete for the same socket.
      guard plan.route.isDialer || !registrations.contains(where: {
        !$0.plan.route.isDialer && $0.plan.route.port == plan.route.port
      }) else { throw TransportConnectError.invalidMaterial }
      registrations.append(try V4PoolServerRegistration(environment: environment, plan: plan, identity: identity,
        candidateIndex: candidateIndex, endpoint: endpoint, roots: roots, tls: tls, storage: storage, source: self))
    }
  }
  func start(_ configuration: TransportServerAllowHTTPSConfiguration) async throws {
    guard (1...2000).contains(configuration.timeoutMilliseconds) else { throw TransportControlError.invalidConfiguration }
    let service = try V4ServerAllowHTTPS(environment: environment, configuration: configuration,
      receiveWithCleanup: { [weak self] body, cleanup in
        guard let self else { throw TransportControlError.closed }
        let request = try V4ServerAllowRequest.decode(body)
        let registration = try environment.gate.withLock { () throws -> V4PoolServerRegistration in
          try check(in: environment)
          guard let original = registrations.first(where: { $0.binding.incarnation == request.incarnation })
          else { throw V4CryptoFailure.authentication }
          return original
        }
        return try await registration.receive(body, cleanup: cleanup)
      }, receive: { _ in throw V4CryptoFailure.phase })
    try environment.gate.withLock {
      try check(in: environment); control = service
      for registration in registrations { try registration.start() }
    }
    do {
      for registration in environment.gate.withLock({ registrations }) { try await registration.waitListening() }
      try await service.start()
      try environment.gate.withLock { try check(in: environment); try Task.checkCancellation() }
    } catch { close(); throw error }
  }
  func check(in original: V4EnvironmentFoundation) throws {
    try environment.gate.withLock {
      guard original === environment, !closed else { throw ConnectionMaterialSourceError.closed }
      try storage.check(); try identity.check(in: environment)
    }
  }
  func checkRequirements(_ requirements: ConnectionRequirements, in original: V4EnvironmentFoundation) throws {
    try V4DirectEstablishment.requirements(requirements)
    try environment.gate.withLock {
      try check(in: original)
      guard !failures.isEmpty || registrations.contains(where: { $0.available }) else { throw ConnectionMaterialSourceError.exhausted }
      for registration in registrations where registration.available {
        try V4DirectEstablishment.requirements(requirements, route: registration.plan.route)
        if let profile = requirements.applicationProfile {
          guard profile == ["transport", "services", "execution"][Int(registration.plan.applicationProfile)]
          else { throw TransportConnectError.unsupported }
        }
      }
    }
  }
  func acquire(_ requirements: ConnectionRequirements) async throws -> ConnectionMaterial {
    let tail = try environment.gate.withLock { () throws -> V4ResourceReference in
      try checkRequirements(requirements, in: environment); try Task.checkCancellation()
      guard !acquiring else { throw TransportControlError.busy }
      let tail = try storage.executionTail(); acquiring = true; return tail
    }
    defer {
      environment.gate.withLock { acquiring = false; tail.release() }
      cleanupEvents.signal()
    }
    while true {
      let revision = readyEvents.revision
      if let material = try environment.gate.withLock({ () throws -> ConnectionMaterial? in
        try check(in: environment); try Task.checkCancellation()
        if !failures.isEmpty { throw failures.removeFirst() }
        if let original = ready.first {
          let material = try original.take(requirements); ready.removeFirst(); return material
        }
        guard registrations.contains(where: { $0.available }) else { throw ConnectionMaterialSourceError.exhausted }
        return nil
      }) { return material }
      try await readyEvents.wait(after: revision)
    }
  }
  func publishReady(_ registration: V4PoolServerRegistration) {
    environment.gate.withLock {
      guard !closed, registrations.contains(where: { $0 === registration }), !ready.contains(where: { $0 === registration }) else { return }
      ready.append(registration)
    }
    readyEvents.signal()
  }
  func preparationFailed(_ registration: V4PoolServerRegistration, error: any Error) {
    environment.gate.withLock {
      guard !closed, !registration.transferred, failures.count < registrations.count else { return }
      ready.removeAll { $0 === registration }
      failures.append(error)
    }
    readyEvents.signal()
  }
  func close() {
    environment.gate.withLock {
      guard !closed else { return }; closed = true; cleanupJoin.beginClose(); control?.close()
      ready.removeAll(); failures.removeAll()
      for registration in registrations { registration.closeFromSource() }
      storage.seal()
    }
    readyEvents.signal()
  }
  func cleanupStatus() -> CleanupStatus {
    environment.gate.withLock {
      let pending = registrations.reduce(UInt64(0)) { $0 + $1.cleanupStatus().pendingCallbacks }
        + (control?.cleanupStatus().pendingCallbacks ?? 0) + (acquiring ? 1 : 0)
      let complete = closed && !acquiring && registrations.allSatisfy({ $0.cleanupStatus().complete }) && (control?.cleanupStatus().complete ?? true)
      return cleanupJoin.status(CleanupStatus(complete: complete, cleanupIncomplete: closed && !complete, pendingCallbacks: pending))
    }
  }
  func waitCleanup() async throws -> CleanupStatus {
    try await cleanupJoin.wait { [self] in
      while true {
        let revision = cleanupEvents.revision
        if environment.gate.withLock({ !acquiring }) { break }
        try? await cleanupEvents.wait(after: revision)
      }
      if let control = environment.gate.withLock({ control }) { await control.waitPhysicalCleanup() }
      for registration in environment.gate.withLock({ registrations }) { await registration.waitTransferredCleanup() }
    }
    return cleanupStatus()
  }
  deinit { close() }
}
#endif
