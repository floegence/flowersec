#if os(macOS) || os(iOS)
  import Foundation

  public enum TransportConnectError: Error, Sendable, Equatable {
    case invalidMaterial, unsupported, securityFailed, connectionFailed, expired, canceled, closed
    case admissionRejected(code: UInt16)
    case timePending, timeNotProven, futureTimestamp, bootstrapDeadline, timeUnavailable
  }

  extension TransportConnectError {
    static func namespaceFailure(_ error: any Error) -> any Error {
      switch error {
      case V4NamespaceFailure.timeNotProven: return Self.timeNotProven
      case V4NamespaceFailure.futureTimestamp: return Self.futureTimestamp
      case V4NamespaceFailure.bootstrapDeadline: return Self.bootstrapDeadline
      case V4TimeFailure.pending: return Self.timePending
      case V4TimeFailure.expired: return Self.expired
      case V4TimeFailure.unavailable, V4TimeFailure.continuity, V4TimeFailure.contradiction:
        return Self.timeUnavailable
      case V4TimeFailure.canceled, is CancellationError: return Self.canceled
      case V4NamespaceFailure.closed, V4ResourceFailure.closed: return Self.closed
      case V4NamespaceFailure.untrusted, V4NamespaceFailure.signature,
        V4NamespaceFailure.schema, V4NamespaceFailure.encoding,
        V4NamespaceFailure.rollback, V4NamespaceFailure.equivocation:
        return Self.securityFailed
      default: return error
      }
    }
  }

  final class V4NativeServiceTransportSlot: @unchecked Sendable {
    private let gate = NSLock()
    private weak var session: V4NativeSession?
    func bind(_ session: V4NativeSession) { gate.withLock { self.session = session } }
    var observationDraining: Bool { gate.withLock { session?.serviceObservationDraining ?? false } }
    func check() throws {
      guard let original = gate.withLock({ session }) else { throw ServiceFailure.closed }
      try original.checkServiceSession()
    }
    func checkpointIssuancePolicy() throws -> (Int, UInt64) {
      guard let original = gate.withLock({ session }) else { throw ServiceFailure.closed }
      return try original.checkpointIssuancePolicy()
    }
    func open(kind: String) async throws -> any V4RPCTransport {
      guard let original = gate.withLock({ session }) else { throw ServiceFailure.closed }
      return try await original.openServiceTransport(kind: kind)
    }
  }

  // Only this file's original dual-READY path can promote the consumed native
  // socket to Session lifetime. Neither a raw record owner nor copied fields
  // can satisfy this constructor.
  final class V4NativeSessionAdmission: @unchecked Sendable {
    let socket: V4ConsumedWebSocket
    let core: V4ReliableSession
    let plan: V4DirectPoolPlan
    let storage: V4CryptoReservation
    let services: V4RPCChannel?
    let management: (any V4ExecutionManagementOwner)?
    let notifications: V4NotificationPublisher?
    let notificationReceiver: V4NotificationReceiver?
    let serviceTransport: V4NativeServiceTransportSlot?
    let server: V4ServiceServerSession?
    let streamHandlers: V4PreparedStreamHandlers?
    let requiresApplicationPublication: Bool
    fileprivate init(
      socket: V4ConsumedWebSocket, core: V4ReliableSession,
      plan: V4DirectPoolPlan, storage: V4CryptoReservation, services: V4RPCChannel? = nil,
      management: (any V4ExecutionManagementOwner)? = nil, notifications: V4NotificationPublisher? = nil, notificationReceiver: V4NotificationReceiver? = nil, serviceTransport: V4NativeServiceTransportSlot? = nil, server: V4ServiceServerSession? = nil,
      streamHandlers: V4PreparedStreamHandlers? = nil, requiresApplicationPublication: Bool = false
    ) {
      self.socket = socket
      self.core = core
      self.plan = plan
      self.storage = storage
      self.services = services
      self.management = management
      self.notifications = notifications; self.notificationReceiver = notificationReceiver; self.serviceTransport = serviceTransport; self.server = server; self.streamHandlers = streamHandlers
      self.requiresApplicationPublication = requiresApplicationPublication
    }
  }

  final class V4DirectPoolMaterial: ConnectionMaterialOwner, V4ConnectionFactsOwner, @unchecked Sendable {
    enum ControlCall: Int { case relayReady, registeredPrepare, relayPrepare, authorize, relayActivate, poolServerAllow }
    let plan: V4DirectPoolPlan
    let identity: V4LocalIdentity
    var connectionFactsOwner: V4ConnectionFacts { plan.credential.connectionFacts }
    let liveControl: (any V4LiveAuthorizationControl)?
    let poolServerAllow: V4PoolServerAllow?
    var liveServer: V4LiveServerRegistration?
    let poolServer: V4PoolServerRegistration?
    private var used = false
    private(set) var sourceIncarnation: Data?
    private(set) var sourceGeneration: UInt64?
    private var closed = false
    private var running = false
    private var cancel: (@Sendable () -> Void)?
    private let cleanupEvents = V4SessionEvents(maximum: 2)
    private var controlCalls = [V4ControlHTTPCallCleanup?](repeating: nil, count: 6)
    private var controlJoin: V4CleanupJoin?
    init(plan: V4DirectPoolPlan, identity: V4LocalIdentity, liveControl: (any V4LiveAuthorizationControl)? = nil, liveServer: V4LiveServerRegistration? = nil, poolServerAllow: V4PoolServerAllow? = nil, poolServer: V4PoolServerRegistration? = nil) {
      self.plan = plan
      self.identity = identity
      self.liveControl = liveControl
      self.poolServerAllow = poolServerAllow
      self.liveServer = liveServer
      self.poolServer = poolServer
    }
    func controlCall(_ phase: ControlCall) throws -> V4ControlHTTPCallCleanup {
      try plan.environment.gate.withLock {
        try check()
        guard controlCalls[phase.rawValue] == nil else { throw TransportControlError.busy }
        if controlJoin == nil { controlJoin = try V4CleanupJoin(environment: plan.environment) }
        let original = V4ControlHTTPCallCleanup()
        controlCalls[phase.rawValue] = original
        return original
      }
    }
    func captureSource(incarnation: Data, generation: UInt64) throws {
      try plan.environment.gate.withLock {
        guard !used, !closed, sourceIncarnation == nil, incarnation.count == 16, generation > 0 else { throw TransportConnectError.invalidMaterial }
        sourceIncarnation = Data(incarnation); sourceGeneration = generation
      }
    }
    func claim(in environment: V4EnvironmentFoundation) throws {
      try environment.gate.withLock {
        guard environment === plan.environment, !used, !closed else {
          throw TransportConnectError.invalidMaterial
        }
        try plan.credential.checkPreparation(in: environment)
        try identity.check(in: environment)
        used = true
        running = true
      }
    }
    func check() throws {
      try plan.environment.gate.withLock {
        guard !closed, running else { throw TransportConnectError.closed }
        try plan.credential.checkPreparation(in: plan.environment)
        try identity.check(in: plan.environment)
        try poolServer?.checkCarrierAdmission()
      }
    }
    func cancellation(_ action: @escaping @Sendable () -> Void) throws {
      try plan.environment.gate.withLock {
        try check()
        cancel = action
      }
    }
    func finish(success: Bool) {
      plan.environment.gate.withLock {
        running = false
        cancel = nil
        closed = true
        controlJoin?.beginClose()
        // Keep the registration strongly attached to this material after a
        // successful handoff. Its transferred carrier is dropped by
        // registration.finish(success:), while preparation, relay, control and
        // ledger cleanup remain observed until their physical tails join.
        if success, let registration = liveServer {
          registration.finish(success: true)
          registration.transferCleanupToSource()
        } else {
          liveServer?.finish(success: success)
        }
        poolServer?.finish(success: success)
        liveControl?.materialFinished(success: success)
        if !success { plan.credential.close() }
      }
      cleanupEvents.signal()
    }
    func close() {
      let changed = plan.environment.gate.withLock { () -> Bool in
        if closed { return false }
        closed = true
        controlJoin?.beginClose()
        cancel?()
        liveControl?.materialFinished(success: false)
        if running || !used { liveServer?.close(); poolServer?.close(); plan.credential.close() }
        return true
      }
      if changed { cleanupEvents.signal() }
    }
    func cleanupStatus() -> CleanupStatus {
      let status = physicalCleanupStatus()
      return plan.environment.gate.withLock { controlJoin?.status(status) ?? status }
    }
    private func physicalCleanupStatus() -> CleanupStatus {
      plan.environment.gate.withLock {
        // finish(success:) detaches the Session's carrier from registration.
        // Its remaining preparation/control tails still belong to material
        // observation, including Serve's original release-after-cleanup path.
        let registration = liveServer?.cleanupStatus()
        let poolRegistration = poolServer?.cleanupStatus()
        let control = controlCalls.compactMap { $0?.cleanupStatus() }
        let pending = (running ? UInt64(1) : 0) + (registration?.pendingCallbacks ?? 0)
          + (poolRegistration?.pendingCallbacks ?? 0) + control.reduce(0) { $0 + $1.pendingCallbacks }
        let complete = closed && !running && (registration?.complete ?? true)
          && (poolRegistration?.complete ?? true) && control.allSatisfy(\.complete)
        return CleanupStatus(complete: complete,
          cleanupIncomplete: !complete && ((registration?.cleanupIncomplete ?? false) || (poolRegistration?.cleanupIncomplete ?? false)),
          pendingCallbacks: pending)
      }
    }
    func waitPhysicalCleanup() async -> CleanupStatus {
      let join = plan.environment.gate.withLock { controlJoin }
      if let join {
        await join.waitPhysicalCompletion { [self] in await waitPhysicalComponents() }
      } else { await waitPhysicalComponents() }
      return cleanupStatus()
    }
    private func waitPhysicalComponents() async {
      let registration = plan.environment.gate.withLock { liveServer }
      if let registration { await registration.waitTransferredCleanup() }
      if let poolServer { await poolServer.waitTransferredCleanup() }
      while true {
        let revision = cleanupEvents.revision
        if plan.environment.gate.withLock({ closed && !running }) { break }
        try? await cleanupEvents.wait(after: revision)
      }
      let controls = plan.environment.gate.withLock { controlCalls.compactMap { $0 } }
      for control in controls { await control.waitPhysicalCleanup() }
    }
    func waitCleanup() async throws -> CleanupStatus {
      while true {
        let revision = cleanupEvents.revision
        if let join = plan.environment.gate.withLock({ closed ? controlJoin : nil }) {
          try await join.wait { [self] in await waitPhysicalComponents() }
          return cleanupStatus()
        }
        if plan.environment.gate.withLock({ closed && !running }) { break }
        try await cleanupEvents.wait(after: revision)
      }
      if let join = plan.environment.gate.withLock({ controlJoin }) {
        try await join.wait { [self] in await waitPhysicalComponents() }
        return cleanupStatus()
      }
      let registration = plan.environment.gate.withLock { liveServer }
      if let registration {
        let status = try await registration.waitCleanup()
        if !status.complete { return status }
      }
      if let poolServer {
        let status = try await poolServer.waitCleanup()
        if !status.complete { return status }
      }
      // Native cancellation is synchronous, while real socket/task completion
      // remains owned by the original connect operation.
      while true {
        let revision = cleanupEvents.revision
        let status = cleanupStatus()
        if status.complete { return status }
        try await cleanupEvents.wait(after: revision)
      }
    }
  }

  enum V4DirectEstablishment {
    static func requirements(_ value: ConnectionRequirements) throws {
      guard !value.independentReliableReadProgress, !value.boundStreamInputIsolation,
        !value.datagram, value.applicationProfile == nil || ["transport", "services", "execution"].contains(value.applicationProfile!)
      else { throw TransportConnectError.unsupported }
    }
    static func requirements(_ value: ConnectionRequirements, route: V4WebSocketRoute) throws {
      try requirements(value)
      guard (!value.localConsumerTLS13Verification || (route.requiresTLS && route.isDialer)),
        (!value.nativeListenerAcceptance || !route.isDialer) else {
        throw TransportConnectError.unsupported
      }
    }
    static func connect(
      material: V4DirectPoolMaterial, address: String, roots: [Data], listenerTLS: NativeListenerTLSConfiguration? = nil,
      store: V4SQLitePoolStore?, requirements: ConnectionRequirements,
      notificationPlan: V4ControllerNotificationPlan? = nil, handoff: (any V4ControllerHandoffReservation)? = nil,
      serve: V4ServeAdmission? = nil, claimed: Bool = false
    ) async throws -> V4NativeSession {
      let plan = material.plan
      let environment = plan.environment
      if !claimed {
        do {
          // Claim ownership before installing the failure-finishing defer. A
          // concurrent caller that loses this claim must only observe the
          // original material; it cannot finish its facts or close its carrier.
          try material.claim(in: environment)
        } catch {
          throw v4FailureProjection(error,
            connection: material.connectionFactsOwner.snapshot(),
            cleanup: { material.cleanupStatus() })
        }
      }
      var prepared: V4PreparedWebSocket?
      var consumed: V4ConsumedWebSocket?
      var handshake: V4Handshake?
      var session: V4NativeSession?
      var successful = false
      defer { material.finish(success: successful) }
      try self.requirements(requirements, route: plan.route)
      if let required = requirements.applicationProfile {
        guard required == ["transport", "services", "execution"][Int(plan.applicationProfile)] else {
          throw TransportConnectError.unsupported
        }
      }
      do {
        // All persistent runtime/key/stream owners are admitted before spend.
        let prepaid = try material.liveServer?.takeSessionResources() ?? material.poolServer?.takeSessionResources()
          ?? handoff?.takeSessionResources(in: environment, plan: plan)
        let native = try prepaid?.take(.native) ?? environment.nativeSessionStorage(slots: plan.slots)
        let streamStorage = try prepaid?.take(.reliable) ?? environment.reliableSessionStorage(
          maxCredit: plan.maxCredit,
          slots: plan.slots)
        let handshakeStorage = try prepaid?.take(.handshake) ?? environment.reserveHandshake()
        let services: V4RPCChannel?
        if plan.applicationProfile == 0 { services = nil }
        else {
          let servicesStorage = try prepaid?.take(.services) ?? environment.rpcServicesStorage(
            maximumGeneral: plan.maximumGeneralOutstanding, execution: plan.applicationProfile == 2)
          let carriers: [V4CryptoReservation]?
          if let prepaid { carriers = try (0..<8).map { try prepaid.take(.rpcCarrier($0)) } }
          else { carriers = nil }
          services = try V4RPCChannel(environment: environment,
            maximumGeneral: plan.maximumGeneralOutstanding, storage: servicesStorage, prepaidCarriers: carriers)
        }
        let serviceTransport = plan.applicationProfile == 0 ? nil : V4NativeServiceTransportSlot()
        let notifications: V4NotificationPublisher?
        if let serviceTransport {
          notifications = try V4NotificationPublisher(environment: environment,
            storage: prepaid?.take(.publisher) ?? environment.notificationPublisherStorage(), factory: { try await serviceTransport.open(kind: "flowersec.notify.v4") })
        } else { notifications = nil }
        let notificationReceiver = plan.applicationProfile == 0 ? nil : try V4NotificationReceiver(
          environment: environment, storage: prepaid?.take(.receiver) ?? environment.notificationReceiverStorage())
        if let notificationPlan, let notificationReceiver, let serviceTransport {
          let identity = try plan.serviceIdentity()
          await notificationPlan.install(environment: environment, identity: identity, receiver: notificationReceiver,
            check: { try serviceTransport.check() }, draining: { serviceTransport.observationDraining })
          try material.check()
          if Task.isCancelled { throw TransportConnectError.canceled }
        }
        var server: V4ServiceServerSession?
        var streamHandlers: V4PreparedStreamHandlers?
        if serve == nil, let registry = environment.serviceRegistry, let services, let serviceTransport {
          let identity = try plan.serviceIdentity()
          server = try registry.admission(identity: identity, execution: plan.applicationProfile == 2,
            maximumGeneral: plan.maximumGeneralOutstanding, checkpointPolicy: { try serviceTransport.checkpointIssuancePolicy() }, prepaid: prepaid, check: { try serviceTransport.check() })
          if let server { try await services.bindInbound(server, ownsDispatcher: false); await notificationReceiver?.bindServer(server) }
        } else { server = nil }
        let management: (any V4ExecutionManagementOwner)?
        if plan.applicationProfile == 2, let serviceTransport {
          management = try V4ExecutionManagementChannel(environment: environment,
            storage: prepaid?.take(.management) ?? environment.executionManagementStorage(),
            initiates: plan.role == .client, factory: {
              guard plan.role == .client else { throw ServiceFailure.serviceUnavailable }
              return try await serviceTransport.open(kind: "flowersec.execution-management.v4")
            })
        } else { management = nil }
        if let registration = material.liveServer {
          prepared = try registration.takePreparedCarrier()
        } else if let registration = material.poolServer {
          prepared = try registration.takePreparedCarrier()
        } else if plan.route.isDialer {
          prepared = try await V4PreparedWebSocket.prepare(route: plan.route,
            numericAddress: address, trustRootsPEM: roots, handoff: handoff)
        } else {
          prepared = try await V4PreparedWebSocket.listen(route: plan.route,
            numericAddress: address, tls: listenerTLS, handoff: handoff, onListening: {
              if let control = material.liveControl { try await control.carrierListening(material) }
            })
        }
        let original = prepared!
        try material.cancellation { original.close() }
        try material.check()
        if Task.isCancelled { throw TransportConnectError.canceled }
        let socket: V4ConsumedWebSocket
        let clientHello: Data; let serverHello: Data; let context: Data; let fsb: Data; let fsa: Data
        var hop: V4TunnelHop?
        if plan.role == .server {
          // Authenticate the complete original FSB before committing the server
          // admission once right. An HTTP upgrade alone cannot spend it.
          guard material.liveControl == nil else { throw TransportConnectError.invalidMaterial }
          if plan.credential.source == .preauthorizedPool {
            guard store != nil, material.liveServer == nil else { throw TransportConnectError.invalidMaterial }
            if plan.credential.pathKind == 1 {
              guard let registration = material.poolServer else { throw TransportConnectError.invalidMaterial }
              try registration.checkCarrier(original)
            } else {
              guard material.poolServer == nil else { throw TransportConnectError.invalidMaterial }
            }
          } else {
            guard material.liveServer != nil, material.poolServer == nil else { throw TransportConnectError.invalidMaterial }
          }
          if plan.credential.pathKind == 1 {
            hop = try await V4TunnelHop.authenticate(socket: original, plan: plan, identity: material.identity, storage: handshakeStorage)
          }
          let initial = V4InitialWebSocket(prepared: original, plan: plan)
          clientHello = try await initial.receive(type: 1, maximum: 16_384)
          serverHello = try self.serverHello(plan, clientHello: clientHello)
          try initial.send(type: 1, body: serverHello); try await original.flush()
          context = try self.context(plan, clientHello: clientHello, serverHello: serverHello)
          fsb = try await initial.receive(type: 2, maximum: plan.route.maximumFrame)
          if let registration = material.liveServer { try registration.authenticateFSB(fsb, context: context) }
          else { try verifyRequest(plan, context: context, fsb: fsb) }
          if let serve {
            streamHandlers = try await serve.authorize(plan)
            if let registry = serve.handlers?.services {
              guard let services, let serviceTransport else { throw ServeError(.configurationCapacity) }
              server = try registry.admission(identity: plan.serviceIdentity(), execution: plan.applicationProfile == 2,
                maximumGeneral: plan.maximumGeneralOutstanding,
                checkpointPolicy: { try serviceTransport.checkpointIssuancePolicy() },
                check: { try serviceTransport.check() })
              if let server { try await services.bindInbound(server, ownsDispatcher: false); await notificationReceiver?.bindServer(server) }
            }
          }
          // Claim the original admission under the aggregate gate, then let
          // storage run independently while its physical execution is retained.
          let consume = {
            if let registration = material.liveServer {
              return try original.consumeLiveServer(registration: registration, fsb: fsb, context: context)
            }
            guard let store else { throw TransportConnectError.invalidMaterial }
            try material.poolServer?.checkCarrier(original)
            let socket = try original.consumePool(using: store)
            do { try material.poolServer?.checkCarrier(original); return socket }
            catch { socket.close(); throw error }
          }
          if let serve { socket = try serve.withDurableAdmission(consume) }
          else { socket = try consume() }
          consumed = socket
          if let serve { try serve.withAdmission {} }
          fsa = try serverAdmission(plan, context: context, fsb: fsb, identity: material.identity)
        } else {
          let serverAllow: V4PreparedPoolServerAllow?
          if plan.credential.source == .preauthorizedPool {
            guard let store, material.liveControl == nil else { throw TransportConnectError.invalidMaterial }
            if plan.credential.pathKind == 1 {
              guard let configured = material.poolServerAllow else { throw TransportConnectError.invalidMaterial }
              serverAllow = try configured.prepare(material: material, carrier: original)
            } else {
              guard material.poolServerAllow == nil else { throw TransportConnectError.invalidMaterial }
              serverAllow = nil
            }
            socket = try original.consumePool(using: store)
          } else {
            guard let live = material.liveControl else { throw TransportConnectError.invalidMaterial }
            serverAllow = nil
            try await live.authorize(material); try material.check(); socket = try original.consumeLive()
          }
          consumed = socket
          if let serverAllow { try await serverAllow.publish(afterConsuming: socket) }
          if plan.credential.pathKind == 1 {
            hop = try await V4TunnelHop.authenticate(socket: socket, plan: plan, identity: material.identity, storage: handshakeStorage)
          }
          let initial = V4InitialWebSocket(socket: socket, plan: plan)
          clientHello = try hello(plan)
          try initial.send(type: 1, body: clientHello); try await socket.flush()
          serverHello = try await initial.receive(type: 1, maximum: 16_384)
          context = try self.context(plan, clientHello: clientHello, serverHello: serverHello)
          fsb = try admission(plan, context: context, identity: material.identity)
          plan.credential.connectionFacts.admissionDispatched()
          try initial.send(type: 2, body: fsb); try await socket.flush()
          fsa = try await initial.receive(type: 3, maximum: 16_384)
          try response(plan, context: context, fsb: fsb, fsa: fsa)
          plan.credential.connectionFacts.admitted()
        }
        let exchange = V4InitialWebSocket(socket: socket, plan: plan, serve: serve)
        if plan.role == .server {
          if let serve { try serve.withAdmission {} }
          try exchange.send(type: 3, body: fsa)
          try await socket.flush()
          plan.credential.connectionFacts.admitted()
        }
        try material.check()
        let crypto = try environment.handshake(
          admission: plan.credential, role: plan.role,
          identity: material.identity,
          input: V4HandshakeInput(
            artifact: Data(plan.artifact.raw), clientHello: clientHello,
            serverHello: serverHello, transportContext: context, fsb: fsb, fsa: fsa, tunnelHop: hop),
          reservation: handshakeStorage, streamStorage: streamStorage)
        handshake = crypto
        if plan.role == .client {
          try crypto.submitNoise(to: exchange); try await socket.flush()
          try crypto.receiveNoise(await exchange.receive(type: 4, maximum: 81))
          try crypto.submitReady(to: exchange); try await socket.flush()
          try crypto.receiveReady(await exchange.receive(type: 5, maximum: 103))
          plan.credential.connectionFacts.networkReady()
        } else {
          let noise = try await exchange.receive(type: 4, maximum: 81)
          if let serve { try serve.withAdmission {} }
          try crypto.receiveNoise(noise); try crypto.submitNoise(to: exchange)
          try await socket.flush()
          let ready = try await exchange.receive(type: 5, maximum: 103)
          if let serve { try serve.withAdmission {} }
          try crypto.receiveReady(ready)
          if let serve { try serve.withAdmission {} }
          try crypto.submitReady(to: exchange)
          try await socket.flush()
          plan.credential.connectionFacts.networkReady()
        }
        try material.check()
        if Task.isCancelled { throw TransportConnectError.canceled }
        try serve?.withAdmission {}
        let core = try crypto.establish().makeSession()
        if let management {
          let managementServer = server
          await management.installHandler({ request, payload, diagnostic in
            if let managementServer { return try await managementServer.handleManagementRequest(request, payload: payload, diagnostic: diagnostic) }
            let cancel = request.kind == "request_cancel_request"
            guard cancel || request.kind == "query_operation_request" else { throw ServiceFailure.protocolFailure }
            return V4ExecutionManagementChannel.unavailableResponse(cancel: cancel)
          }, checkSource: {
            if let managementServer { try managementServer.checkManagementSource() }
          })
        }
        let admission = V4NativeSessionAdmission(
          socket: socket, core: core, plan: plan, storage: native, services: services,
          management: management, notifications: notifications, notificationReceiver: notificationReceiver, serviceTransport: serviceTransport, server: server, streamHandlers: streamHandlers, requiresApplicationPublication: serve != nil)
        try socket.promote(admission)
        let result = try V4NativeSession(admission)
        session = result
        try material.check()
        if Task.isCancelled { throw TransportConnectError.canceled }
        successful = true
        return result
      } catch {
        notificationPlan?.retire()
        handshake?.close()
        if let session { try? await session.close() }
        consumed?.close()
        prepared?.close()
        if let consumed { await consumed.waitClosed() } else if let prepared { await prepared.waitClosed() }
        material.connectionFactsOwner.finishFailure()
        let failedSession = session
        let failedPrepared = prepared
        let inheritedCleanup = (error as? ConnectError)?.cleanup ?? CleanupStatus(complete: true)
        // The enclosing defer finishes the original material before operation
        // delivery. Retain these exact owners rather than a premature snapshot.
        let failure = ConnectError.capture(error,
          connection: material.connectionFactsOwner.snapshot(), cleanup: material.cleanupStatus())
        throw V4ConnectFailureProjection(failure: failure, observeCleanup: {
          var cleanup = material.cleanupStatus()
          // A consumed socket has already joined through waitClosed() above;
          // its state intentionally exposes no aggregate cleanup snapshot.
          // Prepared listeners still retain their own physical tail.
          if let carrier = failedPrepared?.cleanupStatus() {
            cleanup = cleanup.preserving(carrier)
          }
          if let failedSession {
            // close() above joined the original reader, scheduler and socket.
            // Service callbacks still retain their own physical positions.
            let pending = UInt64(await failedSession.retirementPendingCallbacks())
            cleanup = cleanup.preserving(CleanupStatus(complete: pending == 0,
              pendingCallbacks: pending))
          }
          return cleanup.preserving(inheritedCleanup)
        })
      }
    }
    private static func decode(
      _ bytes: Data, schema: String, source: V4ActivationSource = .preauthorizedPool
    )
      throws -> V4NamespaceValue
    {
      try V4NamespaceDocument(
        bytes, schema: schema, bytes: 65536, nodes: 4096,
        registry: V4NamespaceRegistry(), context: ["activation_source_profile": source.rawValue]
      ).root
    }
    static func hello(_ plan: V4DirectPoolPlan) throws -> Data {
      let value = V4Crypto.map([
        (0, V4Crypto.text("flowersec/4")), (1, V4Crypto.text("4")),
        (2, V4Crypto.text(plan.credential.cryptoProfile)),
        (3, V4Crypto.bytes(plan.credential.artifactDigest)),
        (4, V4Crypto.bytes(plan.credential.candidateID)),
        (5, V4Crypto.bytes(plan.credential.routeDigest)),
        (6, V4Crypto.bytes(plan.credential.attemptID)),
        (7, V4Crypto.bytes(try plan.artifact.b("session_nonce"))),
        (8, V4NamespaceValue.head(0, plan.resumeEnabled ? 2 : 0)), (9, V4NamespaceValue.head(0, 2)),
        (10, V4Crypto.bytes(Data())),
      ])
      _ = try decode(value, schema: "ClientHello")
      return value
    }
    static func context(_ plan: V4DirectPoolPlan, clientHello: Data, serverHello: Data) throws
      -> Data
    {
      let client = try decode(clientHello, schema: "ClientHello")
      let server = try decode(serverHello, schema: "ServerHello")
      for name in [
        "protocol_id", "profile_revision", "crypto_profile_id", "artifact_digest",
        "candidate_id", "route_digest", "attempt_id", "client_nonce",
      ] {
        guard try client.field(name).raw.elementsEqual(server.field(name).raw) else {
          throw V4CryptoFailure.authentication
        }
      }
      guard try server.u("binding_mode") == 1, try server.u("selected_features") == 0 else {
        throw V4CryptoFailure.authentication
      }
      let transcript = V4Crypto.hash(
        V4Crypto.domain("hello-transcript", [clientHello, serverHello]))
      let value = V4Crypto.map([
        (0, V4Crypto.text("4")), (1, V4Crypto.text(plan.credential.cryptoProfile)),
        (2, V4NamespaceValue.head(0, plan.route.accessClass)), (3, V4NamespaceValue.head(0, plan.credential.pathKind)),
        (4, V4Crypto.bytes(plan.credential.artifactDigest)),
        (5, V4Crypto.bytes(plan.credential.routeDigest)),
        (6, V4Crypto.bytes(plan.credential.attemptID)),
        (7, V4Crypto.bytes(try plan.artifact.b("session_nonce"))),
        (8, V4Crypto.bytes(transcript)), (9, V4NamespaceValue.head(0, 0)),
        (10, V4NamespaceValue.head(0, 1)), (11, V4NamespaceValue.head(0, 0)),
        (12, V4Crypto.bytes(Data())),
      ])
      _ = try decode(value, schema: "TransportContext")
      return value
    }
    static func serverHello(_ plan: V4DirectPoolPlan, clientHello: Data) throws -> Data {
      let client = try decode(clientHello, schema: "ClientHello")
      let expected = try decode(hello(plan), schema: "ClientHello")
      for field in 0...7 {
        guard try client.fieldID(field).raw.elementsEqual(expected.fieldID(field).raw) else { throw V4CryptoFailure.authentication }
      }
      guard try client.u("supported_binding_modes") & 2 != 0 else { throw V4CryptoFailure.authentication }
      var fields = try (0...7).map { (UInt64($0), Data(try client.fieldID($0).raw)) }
      fields += [(8, V4Crypto.bytes(try V4Crypto.random(32))), (9, V4NamespaceValue.head(0, 0)),
        (10, V4NamespaceValue.head(0, 0)), (11, V4NamespaceValue.head(0, 1)), (12, V4Crypto.bytes(Data()))]
      let value = V4Crypto.map(fields); _ = try decode(value, schema: "ServerHello"); return value
    }
    static func verifyRequest(_ plan: V4DirectPoolPlan, context: Data, fsb: Data) throws {
      let request = try decode(fsb, schema: "FSB4", source: plan.credential.source)
      try request.verify("fsb_signature", publicKey: plan.client.b("ed25519_public_key"))
      let c = try decode(context, schema: "TransportContext")
      let bindings: [(String, Data)] = [
        ("artifact_digest", plan.credential.artifactDigest), ("candidate_id", plan.credential.candidateID),
        ("route_digest", plan.credential.routeDigest), ("attempt_id", plan.credential.attemptID),
        ("session_nonce", try plan.artifact.b("session_nonce")),
        ("issuer_key_id", try plan.artifact.b("issuer_key_id")), ("lease_id", try plan.artifact.b("lease_id")),
        ("hello_transcript_digest", try c.b("hello_transcript_digest")),
        ("transport_context_digest", try c.digest("transport_context_digest")),
        ("activation_authorization", try Data(plan.activationProof().raw)), ("client_certificate", Data(plan.client.raw)),
      ]
      for (field, bytes) in bindings { guard try request.b(field) == bytes else { throw V4CryptoFailure.authentication } }
      guard try request.t("tenant_id") == plan.artifact.t("tenant_id"), try request.u("selected_features") == 0,
        try request.u("binding_mode") == 1 else { throw V4CryptoFailure.authentication }
      try plan.credential.checkPreparation(in: plan.environment)
    }
    static func serverAdmission(_ plan: V4DirectPoolPlan, context: Data, fsb: Data, identity: V4LocalIdentity) throws -> Data {
      try verifyRequest(plan, context: context, fsb: fsb)
      let request = try decode(fsb, schema: "FSB4", source: plan.credential.source)
      let c = try decode(context, schema: "TransportContext")
      var fields: [(UInt64, Data)] = [
        (0, V4NamespaceValue.head(0, 0)), (1, V4NamespaceValue.head(0, 0)), (2, V4NamespaceValue.head(0, 1)),
        (3, V4Crypto.bytes(try V4Crypto.random(32))), (4, V4Crypto.bytes(try request.digest("admission_binding"))),
        (5, V4Crypto.bytes(plan.credential.routeDigest)), (6, V4Crypto.bytes(try c.b("hello_transcript_digest"))),
        (7, V4NamespaceValue.head(0, 0)), (8, V4NamespaceValue.head(0, 1)),
        (9, V4Crypto.bytes(try c.digest("transport_context_digest"))),
        (10, V4Crypto.bytes(plan.credential.certificateDigests[0])), (11, V4Crypto.bytes(plan.credential.certificateDigests[1])),
        (12, V4Crypto.bytes(Data(plan.server.raw))),
      ]
      fields.append((13, V4Crypto.bytes(try identity.signHandshake(V4Crypto.domain("fsa4/signature", [V4Crypto.map(fields)]), in: plan.environment))))
      let value = V4Crypto.map(fields); _ = try decode(value, schema: "FSA4"); return value
    }
    private static func admission(
      _ plan: V4DirectPoolPlan, context: Data,
      identity: V4LocalIdentity
    ) throws -> Data {
      let c = try decode(context, schema: "TransportContext")
      var fields: [(UInt64, Data)] = [
        (0, V4Crypto.bytes(plan.credential.artifactDigest)),
        (1, V4Crypto.text(try plan.artifact.t("tenant_id"))),
        (2, V4Crypto.bytes(try plan.artifact.b("issuer_key_id"))),
        (3, V4Crypto.bytes(try plan.artifact.b("lease_id"))),
        (4, V4Crypto.bytes(try plan.artifact.b("session_nonce"))),
        (5, V4Crypto.bytes(plan.credential.candidateID)),
        (6, V4Crypto.bytes(plan.credential.routeDigest)),
        (7, V4Crypto.bytes(plan.credential.attemptID)),
        (8, V4Crypto.bytes(try V4Crypto.random(32))),
        (9, V4Crypto.bytes(try c.b("hello_transcript_digest"))),
        (10, V4NamespaceValue.head(0, 0)), (11, V4NamespaceValue.head(0, 1)),
        (12, V4Crypto.bytes(try c.digest("transport_context_digest"))),
        (13, V4Crypto.bytes(Data(try plan.activationProof().raw))), (14, V4Crypto.bytes(Data(plan.client.raw))),
      ]
      let signature = try identity.signHandshake(
        V4Crypto.domain("fsb4/signature", [V4Crypto.map(fields)]),
        in: plan.environment)
      fields.append((15, V4Crypto.bytes(signature)))
      let bytes = V4Crypto.map(fields)
      _ = try decode(bytes, schema: "FSB4", source: plan.credential.source)
      return bytes
    }
    static func response(_ plan: V4DirectPoolPlan, context: Data, fsb: Data, fsa: Data) throws {
      let c = try decode(context, schema: "TransportContext")
      let request = try decode(fsb, schema: "FSB4", source: plan.credential.source)
      let result = try decode(fsa, schema: "FSA4")
      guard try result.b("server_certificate") == Data(plan.server.raw) else {
        throw V4CryptoFailure.authentication
      }
      try result.verify("fsa_signature", publicKey: plan.server.b("ed25519_public_key"))
      guard try result.b("route_digest") == plan.credential.routeDigest,
        try result.b("hello_transcript_digest") == c.b("hello_transcript_digest"),
        try result.u("selected_features") == 0, try result.u("binding_mode") == 1
      else { throw V4CryptoFailure.authentication }
      try plan.credential.checkPreparation(in: plan.environment)
      // Rejection schema deliberately zeroes admission/session facts. The
      // original signed server identity, hello, route and mode authenticate
      // its refusal without treating zero fields as an admission grant.
      if try result.u("status") == 1 {
        plan.credential.connectionFacts.admissionRejected()
        throw TransportConnectError.admissionRejected(code: try UInt16(result.u("code")))
      }
      let bindings: [(String, Data)] = [
        ("admission_binding", try request.digest("admission_binding")),
        ("route_digest", plan.credential.routeDigest),
        ("hello_transcript_digest", try c.b("hello_transcript_digest")),
        ("transport_context_digest", try c.digest("transport_context_digest")),
        ("client_identity_digest", plan.credential.certificateDigests[0]),
        ("server_identity_digest", plan.credential.certificateDigests[1]),
      ]
      for (name, bytes) in bindings {
        guard try result.b(name) == bytes else { throw V4CryptoFailure.authentication }
      }
      guard try result.u("selected_features") == 0, try result.u("binding_mode") == 1 else {
        throw V4CryptoFailure.authentication
      }
      try plan.credential.checkPreparation(in: plan.environment)
      guard try result.u("code") == 0 else { throw V4CryptoFailure.authentication }
    }
  }
  private final class V4InitialWebSocket: V4HandshakeWriter {
    private let consumed: V4ConsumedWebSocket?
    private let prepared: V4PreparedWebSocket?
    private let serve: V4ServeAdmission?
    let plan: V4DirectPoolPlan
    init(prepared: V4PreparedWebSocket, plan: V4DirectPoolPlan) {
      self.prepared = prepared; consumed = nil; self.plan = plan; serve = nil
    }
    init(socket: V4ConsumedWebSocket, plan: V4DirectPoolPlan, serve: V4ServeAdmission? = nil) {
      consumed = socket; prepared = nil
      self.plan = plan; self.serve = serve
    }
    func send(type: UInt8, body: Data) throws {
      guard !body.isEmpty, body.count <= plan.route.maximumFrame else {
        throw V4CryptoFailure.capacity
      }
      let bytes = V4Crypto.integer(UInt64(body.count), width: 4) + Data([type, 0, 0, 0]) + body
      let buffer = try plan.environment.cryptoBuffer(
        capacity: bytes.count, credential: plan.credential)
      try buffer.store(bytes)
      if let consumed { try consumed.publish(buffer, admissionCheck: { try self.serve?.withAdmission {} }) }
      else if let prepared { try prepared.publish(buffer) } else { throw V4CryptoFailure.phase }
    }
    func checkHop(_ hop: V4TunnelHop) throws {
      guard let consumed else { throw V4CryptoFailure.phase }; try hop.checkCarrier(consumed.tunnelCarrierIdentity)
    }
    func submit(_ flight: V4HandshakeFlight, buffer: V4CryptoBuffer) throws {
      try send(type: flight == .noise ? 4 : 5, body: buffer.withBytes { $0 })
    }
    func receive(type: UInt8, maximum: Int) async throws -> Data {
      let buffer: V4CryptoBuffer
      if let consumed { buffer = try await consumed.receive() }
      else if let prepared { buffer = try await prepared.receive() }
      else { throw V4CryptoFailure.phase }
      defer { buffer.close() }
      return try buffer.withBytes { bytes in
        guard bytes.count > 8, bytes.count <= maximum + 8,
          V4Crypto.number(bytes.prefix(4)) == bytes.count - 8,
          bytes[4] == type, bytes[5..<8] == Data([0, 0, 0])
        else { throw V4CryptoFailure.authentication }
        return Data(bytes.dropFirst(8))
      }
    }
  }
#endif
