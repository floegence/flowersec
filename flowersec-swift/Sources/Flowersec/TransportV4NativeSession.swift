#if os(macOS) || os(iOS)
  import Foundation

  // One finite event channel wakes original waiters. Cancellation removes only
  // its waiter and never detaches the socket pump or manufactures EOF.
  final class V4SessionEvents: @unchecked Sendable {
    private final class Waiter: @unchecked Sendable {
      var canceled = false
      var continuation: CheckedContinuation<Void, any Error>?
    }
    private let gate = NSLock()
    private let maximum: Int
    private var generation: UInt64 = 0
    private var waiters: [Waiter] = []
    init(maximum: Int) { self.maximum = maximum }
    var revision: UInt64 { gate.withLock { generation } }
    func signal() {
      let pending = gate.withLock {
        generation &+= 1
        let pending = waiters.compactMap { item -> CheckedContinuation<Void, any Error>? in
          defer { item.continuation = nil }
          return item.continuation
        }
        waiters.removeAll(keepingCapacity: true)
        return pending
      }
      for item in pending { item.resume() }
    }
    func wait(after version: UInt64) async throws {
      let token = Waiter()
      try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation {
          (continuation: CheckedContinuation<Void, any Error>) in
          let immediate: Result<Void, any Error>? = gate.withLock {
            if token.canceled { return .failure(SessionError.canceled) }
            if version != generation { return .success(()) }
            if waiters.count >= maximum { return .failure(SessionError.resourceExhausted) }
            token.continuation = continuation
            waiters.append(token)
            return nil
          }
          if let immediate { continuation.resume(with: immediate) }
        }
      } onCancel: {
        let pending = self.gate.withLock {
          token.canceled = true
          self.waiters.removeAll { $0 === token }
          defer { token.continuation = nil }
          return token.continuation
        }
        pending?.resume(throwing: SessionError.canceled)
      }
    }
  }

  final class V4NativeSession: V4MessageStreamSession, V4ApplicationSession, V4ServiceSession, V4ConnectionFactsOwner, ServiceInitializerSession, @unchecked Sendable {
    private struct PendingRawOpen {
      let handle: V4StreamHandle
      let kind: String
      let metadata: StreamMetadata
      let capture: V4MessageRegistrationCapture?
      let deadline: ContinuousClock.Instant
    }
    private struct PendingMessageOpen {
      let handle: V4StreamHandle
      let kind: String
      let metadata: StreamMetadata
      let registration: V4MessageStreamRegistration
      let storage: V4CryptoReservation
      let capture: V4MessageRegistrationCapture
      let deadline: ContinuousClock.Instant
    }
    private final class Lifetime: V4NativeConnectionLifecycle, @unchecked Sendable {
      weak var session: V4NativeSession?
      func close() { session?.terminate(.closed) }
    }
    private let admission: V4NativeSessionAdmission
    var connectionFactsOwner: V4ConnectionFacts { admission.plan.credential.connectionFacts }
    private let events: V4SessionEvents
    private let lifetime = Lifetime()
    private var reader: Task<Void, Never>?
    private var scheduler: Task<Void, Never>?
    private var rpcInitializer: Task<Void, Never>?
    private var applicationPublished: Bool
    private var termination: SessionError?
    private var drainOwner: V4NativeSessionDrain?
    private var activeAccept = false
    private var activeOpen = false
    private var activeRekey = false
    private var wrappers = 0
    private var messageRegistrations: [String: V4MessageStreamRegistration] = [:]
    private var streamHandlerRegistry: V4StreamHandlerRegistry?
    private var messageRegistrationStorage: V4CryptoReservation?
    private var messageRegistrationsInstalled = false
    private let idle: V4SessionIdleWatchdog
    var serviceEnvironment: V4EnvironmentFoundation { admission.plan.environment }
    var serviceChannel: V4RPCChannel? { admission.services }
    private var dynamicRPCChannels: [V4RPCChannelClass: [V4RPCChannel]] = [:]
    private var peerRPCChannels: [V4RPCChannel] = []
    private var openingRPCChannels: [V4RPCChannelClass: V4RPCChannel] = [:]
    func openServiceChannel(_ channelClass: V4RPCChannelClass) async throws -> V4RPCChannel { try await openServiceChannel(channelClass, deadlineAtMS: nil) }
    func openServiceChannel(_ channelClass: V4RPCChannelClass, deadlineAtMS: UInt64? = nil) async throws -> V4RPCChannel {
      guard let bootstrap = admission.services else { throw ServiceFailure.serviceUnavailable }
      if channelClass == .interactive, await bootstrap.acceptsOpeningWaiter {
        do { try await bootstrap.waitReady(deadlineAtMS: deadlineAtMS); return bootstrap }
        catch {
          if error is CancellationError || error as? ServiceFailure == .deadlineExceeded || error as? ServiceFailure == .resourceExhausted { throw error }
          if await bootstrap.acceptsOpeningWaiter { throw error }
        }
      }
      try checkServiceOpeningDeadline(deadlineAtMS)
      let original = gate.withLock { dynamicRPCChannels[channelClass, default: []] }
      for channel in original {
        if await channel.isAvailable { try await channel.waitReady(deadlineAtMS: deadlineAtMS); return channel }
      }
      var retired: [V4RPCChannel] = []
      for channel in original { if await channel.finishedPhysically { retired.append(channel) } }
      let bootstrapFinished = await bootstrap.finishedPhysically
      let selected = try gate.withLock { () -> (V4RPCChannel, Bool) in
        try check()
        try checkServiceOpeningDeadline(deadlineAtMS)
        dynamicRPCChannels[channelClass]?.removeAll { item in retired.contains { $0 === item } }
        if let opening = openingRPCChannels[channelClass] { return (opening, false) }
        let future = try bootstrap.sessionEngine.checkout(opener: Int(admission.plan.role.rawValue),
          channelClass: channelClass, bootstrapAlive: !bootstrapFinished)
        let channel = try V4RPCChannel(environment: admission.plan.environment,
          maximumGeneral: admission.plan.maximumGeneralOutstanding, storage: future.storage,
          sessionEngine: bootstrap.sessionEngine, futurePosition: future)
        dynamicRPCChannels[channelClass, default: []].append(channel)
        openingRPCChannels[channelClass] = channel
        return (channel, true)
      }
      let channel = selected.0
      if selected.1 {
        guard let serviceTransport = admission.serviceTransport else {
          await channel.close(); gate.withLock { openingRPCChannels.removeValue(forKey: channelClass) }
          throw ServiceFailure.serviceUnavailable
        }
        do {
          try checkServiceOpeningDeadline(deadlineAtMS)
          try await channel.start { try await serviceTransport.open(kind: "flowersec.rpc.v4") }
        }
        catch {
          await channel.close(); gate.withLock {
            if openingRPCChannels[channelClass] === channel { openingRPCChannels.removeValue(forKey: channelClass) }
          }
          throw error
        }
      }
      do {
        try await channel.waitReady(deadlineAtMS: deadlineAtMS)
        gate.withLock { if openingRPCChannels[channelClass] === channel { openingRPCChannels.removeValue(forKey: channelClass) } }
        return channel
      } catch {
        // An individual canceled or expired waiter cannot retire another
        // caller's original OPEN. A failed channel can release this alias.
        if !(await channel.acceptsOpeningWaiter) {
          gate.withLock { if openingRPCChannels[channelClass] === channel { openingRPCChannels.removeValue(forKey: channelClass) } }
        }
        throw error
      }
    }
    // Only a client may originate M. Server sessions retain the admitted
    // owner for receive-side cleanup while their protocol loop accepts the
    // peer's M stream through V4ServiceServerSession.
    var serviceManagement: (any V4ExecutionManagementOwner)? { admission.management }
    var serviceNotifications: V4NotificationPublisher? { admission.notifications }
    var serviceNotificationReceiver: V4NotificationReceiver? { admission.notificationReceiver }
    var serviceIdentity: ServiceCallerIdentity {
      get throws {
        let plan = admission.plan
        return try plan.serviceIdentity()
      }
    }
    func checkpointIssuancePolicy() throws -> (Int, UInt64) {
      try gate.withLock {
        try check(); try core.checkResumeIssuance()
        guard admission.plan.resumeEnabled else { throw ServiceFailure.serviceUnavailable }
        return (admission.plan.maximumResumeTokenBytes, admission.plan.maximumResumeTokenDurationMS)
      }
    }
    func checkServiceSession() throws { try gate.withLock { try check() } }
    var serviceObservationDraining: Bool { core.observationDraining }
    private var gate: NSRecursiveLock { admission.plan.environment.gate }
    fileprivate var core: V4ReliableSession { admission.core }
    #if DEBUG
    var cryptoTestTerminated: Bool { gate.withLock { termination != nil } }
    var cryptoTestRekeyFrozen: Bool { core.cryptoTestRekeyFrozen }
    func cryptoTestObserve(_ observer: (@Sendable (UInt64, UInt8, Bool) -> Void)?) {
      core.cryptoTestObserve(observer)
    }
    func cryptoTestObservePreparation(_ observer: (@Sendable (UInt64, V4CryptoPreparationTestStage) -> Void)?) {
      core.cryptoTestObservePreparation(observer)
    }
    func cryptoTestSharedInput(_ id: UInt64) -> V4SharedInputTestSnapshot {
      core.cryptoTestSharedInput(id)
    }
    #endif
    private var socket: V4ConsumedWebSocket { admission.socket }
    init(_ admission: V4NativeSessionAdmission) throws {
      self.admission = admission
      applicationPublished = !admission.requiresApplicationPublication
      events = V4SessionEvents(maximum: admission.plan.slots * 4 + 8)
      idle = try V4SessionIdleWatchdog(
        clock: admission.plan.environment.clock, durationMS: admission.plan.idleMS)
      try admission.storage.check()
      if let handlers = admission.streamHandlers {
        try handlers.registry.lifetime.check(); try handlers.storage?.check()
        streamHandlerRegistry = handlers.registry; messageRegistrations = handlers.messages
        messageRegistrationStorage = handlers.storage; messageRegistrationsInstalled = true
      }
      lifetime.session = self
      admission.serviceTransport?.bind(self)
      try admission.plan.environment.registerNativeConnection(lifetime)
      let inputTail = try admission.storage.executionTail()
      let maintenanceTail: V4ResourceReference
      do { maintenanceTail = try admission.storage.executionTail() } catch {
        inputTail.release()
        throw error
      }
      socket.wakeup { [weak self] in self?.events.signal() }
      socket.recordCompletion { [weak self] in try self?.recordActivity() }
      core.observeAuthenticatedInput { [weak self] in try self?.recordActivity() }
      #if DEBUG
      admission.plan.environment.nativeSessionTestPrepared?(self)
      #endif
      reader = Task { [weak self, socket] in
        defer { inputTail.release() }
        do {
          while !Task.isCancelled {
            while let session = self {
              let version = session.events.revision
              if try session.gate.withLock({
                try session.check()
                return try session.core.canReceive()
              }) {
                break
              }
              try await session.events.wait(after: version)
            }
            let input = try await socket.receive()
            guard let self else {
              input.close()
              socket.close()
              return
            }
            defer { input.close() }
            try self.gate.withLock {
              try self.check()
              let disposition = try input.withBytes { try self.core.receive($0) }
              switch disposition {
              case .committed, .isolatedStream, .discardedData:
                // These outcomes belong to this original complete input. An
                // isolated Stream or bounded rejection keeps the same reader;
                // thrown framing/AEAD/Session errors still end it below.
                break
              }
              if try socket.writable(maintenance: true) { _ = try self.core.poll(to: socket) }
              self.events.signal()
            }
          }
        } catch { self?.terminate(Self.failure(error)) }
        await socket.waitClosed()
      }
      scheduler = Task { [weak self] in
        defer { maintenanceTail.release() }
        do {
          while !Task.isCancelled {
            try await ContinuousClock().sleep(for: .milliseconds(10))
            guard let self else { return }
            try self.gate.withLock {
              try self.check()
              if try self.socket.writable(maintenance: true) {
                _ = try self.core.poll(to: self.socket)
              } else {
                self.core.noteLivenessProviderBlocked()
              }
              self.events.signal()
            }
            if self.gate.withLock({ self.applicationPublished }) {
              try await self.acceptOrdinaryRPCChannel()
              try await self.acceptServiceNotification()
              try await self.acceptRegisteredServiceStream()
              self.admission.server?.pollStreams()
            }
          }
        } catch { self?.terminate(Self.failure(error)) }
      }
      if let services = admission.services {
        let serviceTail = try admission.storage.executionTail()
        rpcInitializer = Task { [weak self] in
          defer { serviceTail.release() }
          guard let self else { return }
          do {
            try await waitApplicationPublication()
            try await services.start { [self] in try await bootstrapTransport() }
          } catch { await services.close(reason: .serviceUnavailable) }
          gate.withLock { rpcInitializer = nil }
        }
      }
      if admission.plan.role == .client, let management = admission.management {
        Task { await management.startClient() }
      }
    }
    // Serve calls this on the original Environment gate at the first business
    // publication. READY permits protocol maintenance but does not grant an
    // unpublished server Session permission to run application dispatch.
    func publishApplication() throws {
      try gate.withLock {
        try check()
        guard !core.observationDraining else { throw SessionError.goingAway }
        applicationPublished = true
        events.signal()
      }
    }
    private func waitApplicationPublication() async throws {
      while true {
        try Task.checkCancellation()
        let version = events.revision
        if try gate.withLock({ try check(); return applicationPublished }) { return }
        try await events.wait(after: version)
      }
    }
    fileprivate static func failure(_ error: any Error) -> SessionError {
      if let error = error as? SessionError { return error }
      if error is CancellationError { return .canceled }
      if let carrier = error as? V4WebSocketFailure, case .connectionLost = carrier { return .closed }
      if error as? V4CryptoFailure == .capacity || error is V4ResourceFailure {
        return .resourceExhausted
      }
      if let time = error as? V4TimeFailure {
        return time == .expired ? .timeout : time == .canceled ? .canceled : .timeUnavailable
      }
      return .operationFailed
    }
    private func recordActivity() throws {
      try gate.withLock {
        if let termination { throw termination }
        do { try idle.activity() } catch {
          terminate(Self.failure(error))
          throw error
        }
      }
    }
    private func check() throws {
      if let termination { throw termination }
      do { try idle.check() } catch {
        terminate(Self.failure(error))
        throw error
      }
      try admission.storage.check()
      try admission.plan.credential.checkSessionAuthorization(in: admission.plan.environment)
      // The original TLS authorization also fences already-buffered delivery.
      try socket.check()
      _ = try core.epoch()
    }
    // Reuse the original bounded waiter and pending-OPEN deadline while a
    // maintenance record owns its output/crypto position. No acceptance can
    // steal that position or fabricate a new publication after the deadline.
    private func withMaintenance<T>(before deadline: ContinuousClock.Instant,
      _ operation: () throws -> T) async throws -> T {
      while true {
        let revision = events.revision
        let result: T? = try gate.withLock {
          try check()
          if Task.isCancelled { throw SessionError.canceled }
          guard ContinuousClock.now < deadline else { throw SessionError.timeout }
          guard try socket.writable(maintenance: true), try core.canMaintain() else { return nil }
          return try operation()
        }
        if let result { return result }
        try await events.wait(after: revision)
      }
    }
    private func terminate(_ error: SessionError) {
      gate.withLock {
        guard termination == nil else { return }
        termination = error
        connectionFactsOwner.diagnosticClosed()
        idle.close()
        socket.recordCompletion(nil)
        core.observeAuthenticatedInput(nil)
        if error == .timeUnavailable { core.noteLivenessTimeUnavailable() }
        core.close()
        socket.close()
        reader?.cancel()
        scheduler?.cancel()
        rpcInitializer?.cancel()
        if let services = admission.services { Task { await services.close() } }
        for channel in dynamicRPCChannels.values.flatMap({ $0 }) + peerRPCChannels { Task { await channel.close() } }
        admission.services?.sessionEngine.close()
        if let management = admission.management { management.seal(); Task { await management.close(.closed) } }
        if let notifications = admission.notifications { Task { await notifications.close() } }
        admission.server?.close()
        if let receiver = admission.notificationReceiver { Task { await receiver.close() } }
        admission.storage.seal()
        events.signal()
      }
    }
    func captureServiceResumeTarget(_ stream: any ByteStream, kind: String) throws -> ServiceResumeTarget {
      guard let original = stream as? V4NativeByteStream, admission.plan.resumeEnabled else { throw ServiceFailure.serviceUnavailable }
      return try original.captureResume(in: self, kind: kind)
    }
    fileprivate func resumeFacts(_ handle: V4StreamHandle, capture: Bool = true) throws -> (Data, UInt64, Int, UInt64) {
      try gate.withLock {
        try check(); let (context, streamID) = try core.resumeStreamFacts(handle, capture: capture)
        return (context, streamID, admission.plan.maximumResumeTokenBytes, admission.plan.maximumResumeTokenDurationMS)
      }
    }
    private func acceptServiceNotification() async throws {
      let receiver = admission.notificationReceiver
      let notificationAvailable: Bool
      if let receiver { notificationAvailable = await receiver.acceptsChannel } else { notificationAvailable = false }
      let stream = try gate.withLock { () -> V4NativeByteStream? in
        try check()
        guard try socket.writable(maintenance: true), try core.canMaintain(), let handle = try core.pendingOpen(service: true,
          kinds: ["flowersec.notify.v4", "flowersec.execution-management.v4"]) else { return nil }
        let metadata = try core.pendingMetadata(handle); defer { metadata.metadata.close() }
        let managementBlocked = metadata.kind == "flowersec.execution-management.v4" && core.observationDraining
        guard !managementBlocked,
          (metadata.kind == "flowersec.notify.v4" && notificationAvailable || metadata.kind == "flowersec.execution-management.v4" && admission.management != nil),
          wrappers < admission.plan.slots else {
          try core.decideOpen(handle, decision: .reject(.resource), to: socket); return nil
        }
        wrappers += 1
        let stream = V4NativeByteStream(session: self, handle: handle, kind: metadata.kind)
        try core.decideOpen(handle, decision: .accept(receiveWindow: 16_384), to: socket)
        events.signal(); return stream
      }
      if let stream {
        if stream.kind == "flowersec.execution-management.v4", let management = admission.management {
          await management.acceptPeer(stream)
        } else if let receiver { await receiver.accept(stream) }
      }
    }
    private func acceptOrdinaryRPCChannel() async throws {
      guard let bootstrap = admission.services else { return }
      let original = gate.withLock { peerRPCChannels }
      var retired: [V4RPCChannel] = []
      for channel in original { if await channel.finishedPhysically { retired.append(channel) } }
      gate.withLock { peerRPCChannels.removeAll { item in retired.contains { $0 === item } } }
      let dispatcher = await bootstrap.dynamicDispatcher
      let bootstrapFinished = await bootstrap.finishedPhysically
      let accepted: (V4RPCChannel, V4NativeByteStream)? = try gate.withLock {
        try check()
        guard try socket.writable(maintenance: true), try core.canMaintain(), let handle = try core.pendingOpen(service: true, kinds: ["flowersec.rpc.v4"]) else { return nil }
        guard peerRPCChannels.count < 4, wrappers < admission.plan.slots else {
          try core.decideOpen(handle, decision: .reject(.resource), to: socket); return nil
        }
        let future: V4RPCFuturePosition
        do {
          future = try bootstrap.sessionEngine.checkout(opener: 1 - Int(admission.plan.role.rawValue),
            channelClass: nil, bootstrapAlive: !bootstrapFinished)
        } catch ServiceFailure.resourceExhausted {
          try core.decideOpen(handle, decision: .reject(.resource), to: socket); return nil
        }
        let channel = try V4RPCChannel(environment: admission.plan.environment,
          maximumGeneral: admission.plan.maximumGeneralOutstanding, storage: future.storage,
          sessionEngine: bootstrap.sessionEngine, futurePosition: future)
        wrappers += 1
        let stream = V4NativeByteStream(session: self, handle: handle, kind: "flowersec.rpc.v4")
        try core.decideOpen(handle, decision: .accept(receiveWindow: 16_384), to: socket)
        peerRPCChannels.append(channel); events.signal(); return (channel, stream)
      }
      if let (channel, stream) = accepted {
        do {
          try await channel.bindInbound(dispatcher, ownsDispatcher: false)
          try await channel.start { stream }
        } catch {
          await channel.closeUnstarted(stream)
        }
      }
    }

    private func acceptRegisteredServiceStream() async throws {
      guard let server = admission.server, !server.streamKinds.isEmpty else { return }
      var candidate: V4NativeByteStream?
      do {
        try gate.withLock {
          try check()
          guard try socket.writable(maintenance: true), try core.canMaintain(), let handle = try core.pendingOpen(kinds: server.streamKinds) else { return }
          let metadata = try core.pendingMetadata(handle); defer { metadata.metadata.close() }
          guard wrappers < admission.plan.slots else { try core.decideOpen(handle, decision: .reject(.resource), to: socket); return }
          wrappers += 1
          let stream = V4NativeByteStream(session: self, handle: handle, kind: metadata.kind); candidate = stream
          try core.decideOpen(handle, decision: .accept(receiveWindow: admission.plan.window), to: socket)
          let facts: (Data, UInt64, Int, UInt64)?
          if admission.plan.resumeEnabled { facts = try? resumeFacts(handle) } else { facts = nil }
          try server.adoptStream(id: handle.number, kind: metadata.kind, source: stream, facts: facts,
            readable: { [weak self] in
              guard let self else { throw ServiceFailure.closed }
              return try self.gate.withLock { try self.check(); return try self.core.applicationInputAvailable(handle) }
            })
          events.signal()
        }
      } catch { if let candidate { try? await candidate.close() }; throw error }
    }

    func openServiceTransport(kind: String) async throws -> any V4RPCTransport {
      guard admission.services != nil,
        ["flowersec.notify.v4", "flowersec.execution-management.v4", "flowersec.rpc.v4"].contains(kind),
        (kind != "flowersec.execution-management.v4" || admission.plan.applicationProfile == 2) else {
        throw ServiceFailure.serviceUnavailable
      }
      while true {
        let version = events.revision
        let ready = try gate.withLock { try check(); return !activeOpen }
        if ready {
          return try await openEncodedStream(kind: kind, encodedMetadata: Data(), service: true)
        }
        try await events.wait(after: version)
      }
    }

    private func bootstrapTransport() async throws -> any V4RPCTransport {
      while true {
        try Task.checkCancellation()
        let version = events.revision
        let result: V4NativeByteStream? = try gate.withLock {
          try check()
          guard let handle = try core.bootstrapStream() else { throw ServiceFailure.serviceUnavailable }
          if !core.bootstrapMaterialized, try socket.writable(), try core.canOpen() {
            // Native Swift establishment is client-side. This is the original
            // preaccepted scope 1, never a public OPEN replacement.
            _ = try core.materializeBootstrap(to: socket)
          }
          guard core.bootstrapMaterialized else { return nil }
          return try stream(handle, kind: "flowersec.rpc.v4")
        }
        if let result { return result }
        try await events.wait(after: version)
      }
    }

    private func stream(
      _ handle: V4StreamHandle, kind: String,
      messageDefinition: MessageStreamDefinition? = nil,
      messageStorage: V4CryptoReservation? = nil,
      messageApplication: StreamMetadata = .empty,
      messageCapture: V4MessageRegistrationCapture? = nil
    ) throws -> V4NativeByteStream {
      guard wrappers < admission.plan.slots else { throw SessionError.resourceExhausted }
      wrappers += 1
      return V4NativeByteStream(
        session: self, handle: handle, kind: kind,
        messageDefinition: messageDefinition, messageStorage: messageStorage,
        messageApplication: messageApplication, messageCapture: messageCapture)
    }
    fileprivate func releaseWrapper() { gate.withLock { wrappers -= 1 } }
    private func prepareMessageAcceptance(_ candidate: PendingMessageOpen) throws -> V4NativeByteStream {
      // Reserve the existing native wrapper position before allocating its
      // unpublished facade. Construction itself never holds the accept gate.
      try gate.withLock {
        try check()
        try candidate.storage.check()
        guard try core.phase(candidate.handle) == .pending,
          wrappers < admission.plan.slots else { throw SessionError.resourceExhausted }
        wrappers += 1
      }
      return V4NativeByteStream(
        session: self, handle: candidate.handle, kind: candidate.kind,
        messageDefinition: candidate.registration.definition,
        messageStorage: candidate.storage, messageApplication: candidate.metadata,
        messageCapture: candidate.capture)
    }

    func installMessageStreamRegistrations(_ registrations: [String: V4MessageStreamRegistration]) throws {
      try gate.withLock {
        try check()
        guard !messageRegistrationsInstalled, !activeAccept else { throw HandlerRegistrationError.frozen }
        if !registrations.isEmpty {
          let storage = try admission.plan.environment.messageStreamRegistrationStorage(count: registrations.count)
          guard registrations.allSatisfy({ $0.key == $0.value.definition.kind }) else {
            throw HandlerRegistrationError.invalidHandler
          }
          messageRegistrationStorage = storage
          messageRegistrations = registrations
        }
        messageRegistrationsInstalled = true
      }
    }

    func installStreamHandlerRegistry(
      _ registry: V4StreamHandlerRegistry, messages: [String: V4MessageStreamRegistration]
    ) throws {
      try gate.withLock {
        try check()
        try registry.lifetime.check()
        let count = registry.rawKinds.count + messages.count
        // A Serve plan installs this same frozen registry before READY. The
        // later dispatch loop borrows it without reallocating or widening it.
        if messageRegistrationsInstalled, streamHandlerRegistry?.lifetime === registry.lifetime { return }
        guard !messageRegistrationsInstalled, !activeAccept else { throw HandlerRegistrationError.frozen }
        guard count <= 256, (1...128).contains(registry.maximumConcurrentStreams),
          registry.rawKinds.isDisjoint(with: messages.keys),
          Set(registry.metadataContracts.keys).isSubset(of: registry.rawKinds),
          messages.allSatisfy({ $0.key == $0.value.definition.kind && $0.value.lifetime === registry.lifetime })
        else { throw HandlerRegistrationError.invalidHandler }
        if count > 0 {
          messageRegistrationStorage = try admission.plan.environment.messageStreamRegistrationStorage(count: count)
        }
        messageRegistrations = messages
        streamHandlerRegistry = registry
        messageRegistrationsInstalled = true
      }
    }

    private func prepareRawAcceptance(_ candidate: PendingRawOpen) throws -> V4NativeByteStream {
      try gate.withLock {
        try check()
        guard try core.phase(candidate.handle) == .pending,
          wrappers < admission.plan.slots else { throw SessionError.resourceExhausted }
        wrappers += 1
      }
      return V4NativeByteStream(session: self, handle: candidate.handle, kind: candidate.kind,
        messageCapture: candidate.capture)
    }

    private func commitRawAcceptance(
      _ candidate: PendingRawOpen, value: V4NativeByteStream
    ) throws -> IncomingStream? {
      guard ContinuousClock.now < candidate.deadline else { throw SessionError.timeout }
      try core.decideOpen(candidate.handle, decision: .accept(receiveWindow: admission.plan.window),
        to: socket, claim: { try candidate.capture?.accept() })
      events.signal()
      guard try core.phase(candidate.handle) == .accepted else { return nil }
      return IncomingStream(kind: candidate.kind, metadata: candidate.metadata, stream: value)
    }

    fileprivate func withMessageStreamClaimInfo<Value>(
      _ operation: () throws -> Value
    ) throws -> Value {
      try gate.withLock { try operation() }
    }

    fileprivate func withMessageStreamClaim(
      _ operation: () throws -> V4PreparedMessageStream
    ) throws -> V4PreparedMessageStream {
      try gate.withLock { try operation() }
    }

    fileprivate func lowLevelTypedInfo(
      handle: V4StreamHandle, definition: MessageStreamDefinition
    ) throws -> Bool {
      try gate.withLock { try check(); return try core.typedClaimRole(handle, kind: definition.kind) }
    }
    fileprivate func lowLevelTypedStorage() throws -> V4CryptoReservation {
      try gate.withLock { try check(); return try admission.plan.environment.messageStreamStorage() }
    }

    fileprivate func messagePreparation(
      stream: any ByteStream, storage: V4CryptoReservation
    ) throws -> V4PreparedMessageStream {
      try gate.withLock {
        try check()
        try storage.check()
        guard storage.environment === admission.plan.environment else { throw V4ResourceFailure.owner }
        return V4PreparedMessageStream(stream: stream, storage: storage, check: { [weak self] in
          guard let self else { throw SessionError.closed }
          try self.gate.withLock { try self.check() }
        })
      }
    }

    func prepareOpenMessageStream(
      definition: MessageStreamDefinition, application: StreamMetadata
    ) throws -> V4OutgoingMessageCandidate {
      let storage = try gate.withLock { () -> V4CryptoReservation in
        try check()
        return try admission.plan.environment.messageStreamStorage()
      }
      let metadata = try V4StreamMetadataCodec.typed(definition: definition.digest, application: application)
      let encodedMetadata = try metadata.encoded()
      let deferred = V4DeferredMessageStream(kind: definition.kind)
      let prepared = try messagePreparation(stream: deferred, storage: storage)
      return V4OutgoingMessageCandidate(prepared: prepared, publish: { [self] in
        try deferred.beginPublication()
        try Task.checkCancellation()
        let value = try await openEncodedStream(kind: definition.kind, encodedMetadata: encodedMetadata)
        do {
          let owned = try value.claimOpenedMessageStream(definition: definition, storage: storage)
          guard let writer = owned.stream as? any V4MessageStreamWriter else {
            throw TransportAvailabilityError.runtimeUnavailable
          }
          do { try gate.withLock { try check(); try deferred.bind(writer) } }
          catch { try? await writer.close(); throw error }
        } catch { try? await value.close(); throw error }
      })
    }

    func openStream(kind: String, metadata: StreamMetadata) async throws -> any ByteStream {
      guard metadata.namespace != "flowersec/typed-message" else { throw StreamMetadataError.invalidValue }
      return try await openEncodedStream(kind: kind, encodedMetadata: metadata.encoded())
    }

    private func openEncodedStream(kind: String, encodedMetadata: Data, service: Bool = false) async throws -> V4NativeByteStream {
      try gate.withLock {
        try check()
        guard !activeOpen else { throw SessionError.resourceExhausted }
        activeOpen = true
      }
      defer { gate.withLock { activeOpen = false }; events.signal() }
      var handle: V4StreamHandle?
      do {
        while true {
          let version = events.revision
          let result: V4NativeByteStream? = try gate.withLock {
            try check()
            if Task.isCancelled { throw SessionError.canceled }
            if handle == nil, try socket.writable(), try core.canOpen() {
              handle = try core.open(
                kind: kind, metadata: encodedMetadata,
                receiveWindow: service ? 16_384 : admission.plan.window, to: socket, service: service)
            }
            guard let handle else { return nil }
            switch try core.phase(handle) {
            case .accepted: return try stream(handle, kind: kind)
            case .recent, .stable: throw SessionError.streamRejected
            default: return nil
            }
          }
          if let result { return result }
          try await events.wait(after: version)
        }
      } catch {
        if let handle {
          try? core.reset(handle)
          // Reset only publishes the terminal decision. Keep the original
          // handle owner until the native stream has retired all queued work,
          // including when this task was canceled by the caller.
          await Task.detached { [self, core, handle] in
            while !self.gate.withLock({ core.internalCleanupComplete(handle) }) {
              try? await ContinuousClock().sleep(for: .milliseconds(10))
            }
          }.value
        }
        events.signal()
        throw Self.failure(error)
      }
    }
    func acceptStream() async throws -> IncomingStream {
      try gate.withLock {
        try check()
        guard !activeAccept else { throw SessionError.resourceExhausted }
        activeAccept = true
      }
      defer { gate.withLock { activeAccept = false } }
      var pending: V4StreamHandle?
      var typed: PendingMessageOpen?
      var raw: PendingRawOpen?
      do {
        while true {
          let version = events.revision
          let result: IncomingStream? = try gate.withLock {
            try check()
            if Task.isCancelled { throw SessionError.canceled }
            guard try socket.writable(maintenance: true), try core.canMaintain() else { return nil }
            if pending == nil { pending = try core.pendingOpen(excluding: admission.server?.streamKinds ?? []) }
            guard let handle = pending else { return nil }
            let metadata = try core.pendingMetadata(handle)
            defer { metadata.metadata.close() }
            let decoded: StreamMetadata
            do {
              decoded = try metadata.metadata.withBytes { try StreamMetadata(encoded: $0) }
            } catch {
              try core.decideOpen(handle, decision: .reject(.metadata), to: socket)
              pending = nil
              events.signal()
              return nil
            }
            if decoded.namespace == "flowersec/typed-message" {
              do {
                guard let registration = messageRegistrations[metadata.kind] else {
                  throw StreamMetadataError.invalidValue
                }
                try messageRegistrationStorage?.check()
                let storage = try admission.plan.environment.messageStreamStorage()
                let application = try V4StreamMetadataCodec.typedApplication(
                  decoded, definition: registration.definition.digest)
                typed = PendingMessageOpen(
                  handle: handle, kind: metadata.kind, metadata: application,
                  registration: registration, storage: storage,
                  capture: try registration.lifetime.capture(kind: metadata.kind,
                    maximum: registration.maximumConcurrentStreams),
                  deadline: try core.pendingOpenDeadline(handle))
              } catch {
                try core.decideOpen(handle, decision: .reject(.metadata), to: socket)
                pending = nil
                events.signal()
              }
              return nil
            }
            // A typed registration never silently falls back to a raw stream.
            guard messageRegistrations[metadata.kind] == nil else {
              try core.decideOpen(handle, decision: .reject(.metadata), to: socket)
              pending = nil
              events.signal()
              return nil
            }
            do {
              var projected = decoded
              let capture: V4MessageRegistrationCapture?
              if let registry = streamHandlerRegistry {
                try messageRegistrationStorage?.check()
                guard registry.rawKinds.contains(metadata.kind) else { throw SessionError.streamRejected }
                capture = try registry.lifetime.capture(kind: metadata.kind,
                  maximum: registry.maximumConcurrentStreams)
                if let contract = registry.metadataContracts[metadata.kind] {
                  projected = try decoded.applyingRawMetadataContract(contract)
                }
              } else { capture = nil }
              raw = PendingRawOpen(handle: handle, kind: metadata.kind, metadata: projected,
                capture: capture, deadline: try core.pendingOpenDeadline(handle))
            } catch {
              try core.decideOpen(handle, decision: .reject(.application), to: socket)
              pending = nil
              events.signal()
            }
            return nil
          }
          if let result { return result }
          if let candidate = raw {
            raw = nil
            do {
              let value = try prepareRawAcceptance(candidate)
              let accepted = try await withMaintenance(before: candidate.deadline) { () -> IncomingStream? in
                try check()
                if Task.isCancelled { throw SessionError.canceled }
                guard try core.phase(candidate.handle) == .pending else { return nil }
                return try commitRawAcceptance(candidate, value: value)
              }
              pending = nil
              if let accepted { return accepted }
            } catch {
              try gate.withLock {
                let phase = try core.phase(candidate.handle)
                pending = nil
                if phase == .accepted { try? core.reset(candidate.handle); throw error }
                if phase == .pending {
                  try core.decideOpen(candidate.handle, decision: .reject(.application), to: socket)
                }
                events.signal()
              }
            }
            continue
          }
          if let candidate = typed {
            typed = nil
            // The original pending OPEN and its complete adapter reservation
            // remain live while the application's authorization callback runs.
            let authorized: Bool
            var preparedValue: V4NativeByteStream?
            var preparedView: V4NativeMessageStream?
            var preparedHandler: V4PreparedMessageHandler?
            do {
              let value = try prepareMessageAcceptance(candidate)
              preparedValue = value
              if let prepare = candidate.registration.prepare {
                let (prepared, view) = try value.preparePendingMessageStream(
                  definition: candidate.registration.definition)
                preparedView = view
                preparedHandler = try prepare(prepared, candidate.metadata)
              }
              let group = try admission.plan.environment.applicationGroup()
              let reference = try admission.plan.environment.messageOpenAuthorizationStorage()
              let waiting = V4MessageOpenAuthorization(group: group, deadline: candidate.deadline,
                reference: reference)
              authorized = try await waiting.authorize(metadata: candidate.metadata,
                registration: candidate.registration)
            } catch { authorized = false }
            let accepted: IncomingStream? = try await withMaintenance(before: candidate.deadline) {
              try check()
              if Task.isCancelled { throw SessionError.canceled }
              try candidate.storage.check()
              guard try core.phase(candidate.handle) == .pending else {
                pending = nil
                return nil
              }
              guard authorized, let value = preparedValue else {
                try core.decideOpen(candidate.handle, decision: .reject(.application), to: socket)
                pending = nil
                events.signal()
                return nil
              }
              do {
                  guard ContinuousClock.now < candidate.deadline else { throw SessionError.timeout }
                  try core.decideOpen(
                    candidate.handle, decision: .accept(receiveWindow: admission.plan.window), to: socket,
                    claim: { try candidate.capture.accept() })
                  pending = nil
                  events.signal()
                  guard try core.phase(candidate.handle) == .accepted else { return nil }
                  preparedView?.activate()
                  return IncomingStream(kind: candidate.kind, metadata: candidate.metadata, stream: value,
                    preparedMessageHandler: preparedHandler)
              } catch {
                let phase = try core.phase(candidate.handle)
                pending = nil
                if phase == .accepted {
                  // Acceptance already won. A later failure ends that same
                  // Stream; it can never be recast as a rejected OPEN.
                  try? core.reset(candidate.handle)
                  events.signal()
                  throw error
                }
                if phase == .pending {
                  try core.decideOpen(candidate.handle, decision: .reject(.application), to: socket)
                }
                events.signal()
                return nil
              }
            }
            if let accepted { return accepted }
            continue
          }
          try await events.wait(after: version)
        }
      } catch {
        if let pending {
          try? gate.withLock { try core.decideOpen(pending, decision: .reject(.application), to: socket) }
        }
        throw Self.failure(error)
      }
    }
    func invokeStreamHandler(_ incoming: IncomingStream, handler: @escaping StreamHandler) async throws {
      let group = try admission.plan.environment.applicationGroup()
      if let prepared = incoming.preparedMessageHandler {
        // The typed application job owns only the prepared adapter. A
        // noncooperative handler cannot pin a redundant raw wrapper or the
        // Session through an SDK dispatch closure after the adapter closes.
        try await group.invoke { context in try await prepared.invoke(context) }
        return
      }
      try await group.invoke { [weak self] context in
        guard try self?.canEnterApplication() == true else { throw SessionError.closed }
        try context.checkCancellation()
        try await handler(IncomingStream(kind: incoming.kind, metadata: incoming.metadata,
          stream: incoming.stream, applicationContext: context))
      }
    }

    private func canEnterApplication() throws -> Bool {
      try gate.withLock { try check(); return true }
    }

    fileprivate func read(_ handle: V4StreamHandle, maximum: Int, beforeRead: (@Sendable () throws -> Void)? = nil, delivered: (@Sendable (Data) -> Void)? = nil) async throws -> Data? {
      guard (1...1_048_576).contains(maximum) else { throw SessionError.resourceExhausted }
      while true {
        let version = events.revision
        let result: Data?? = try gate.withLock {
          try check()
          if Task.isCancelled { throw SessionError.canceled }
          try beforeRead?()
          switch try core.read(handle, maximum: maximum, delivered: delivered) {
          case .data(let buffer):
            defer { buffer.close() }
            let data = try buffer.withBytes { $0 }
            try core.replenish(handle, window: admission.plan.window)
            events.signal()
            return .some(data)
          case .eof: return .some(nil)
          case .aborted: throw SessionError.streamReset
          case .pending: return nil
          }
        }
        if let result { return result }
        try await events.wait(after: version)
      }
    }
    fileprivate func write(
      _ handle: V4StreamHandle, data: Data, fin: Bool = false,
      beforeAccept: (@Sendable () throws -> Void)? = nil,
      accepted: (@Sendable (Int) -> Void)? = nil,
      completed: (@Sendable (Int, Bool) -> Void)? = nil
    ) async throws -> Int {
      var original: V4RPCRecordHandoff?
      do {
        while true {
          let version = events.revision
          let count: Int? = try gate.withLock {
            try check()
            if Task.isCancelled { throw SessionError.canceled }
            guard try socket.writable(), try core.canOpen() else { return nil }
            let capacity = try core.writeCapacity(handle)
            if !data.isEmpty && capacity == 0 { return nil }
            try beforeAccept?()
            let selected = Data(data.prefix(capacity))
            original = completed.map { V4RPCRecordHandoff(bytes: selected.count, completion: $0) }
            let count = try core.write(handle, data: selected, fin: fin, to: socket, accepted: accepted, publication: original)
            events.signal(); return count
          }
          if let count { return count }
          try await events.wait(after: version)
        }
      } catch {
        if let original { original.failedBeforeTransfer() } else { completed?(0, false) }
        throw error
      }
    }
    fileprivate func closeWrite(_ handle: V4StreamHandle,
      beforeFinish: (@Sendable () throws -> Void)? = nil) async throws {
      try gate.withLock {
        try beforeFinish?()
        if try core.finSubmitted(handle) { return }
        try check()
        try core.requestCloseWrite(handle)
        events.signal()
      }
      while true {
        let version = events.revision
        if try gate.withLock({
          try beforeFinish?()
          if try core.finSubmitted(handle) { return true }
          try check()
          if Task.isCancelled { throw SessionError.canceled }
          if try core.streamError(handle) != nil { throw SessionError.streamReset }
          return false
        }) {
          return
        }
        try await events.wait(after: version)
      }
    }
    fileprivate func finish(_ handle: V4StreamHandle,
      beforeFinish: (@Sendable () throws -> Void)? = nil) async throws {
      while true {
        let version = events.revision
        if try gate.withLock({
          try beforeFinish?()
          if try core.sendFinished(handle) { return true }
          try check()
          return false
        }) {
          return
        }
        try await events.wait(after: version)
      }
    }
    fileprivate func disposeStream(_ handle: V4StreamHandle, bridge: V4DuplexBridgeToken? = nil) {
      gate.withLock {
        // Unpublished candidates belong to the original pending rejection
        // owner. Disposal may reset only a Stream whose acceptance won.
        guard (try? core.phase(handle)) == .accepted, core.canDispose(handle, bridge: bridge) else { return }
        try? core.reset(handle)
        events.signal()
      }
    }

    fileprivate func reset(_ handle: V4StreamHandle) throws {
      try gate.withLock {
        try check()
        try core.reset(handle)
        events.signal()
      }
    }
    fileprivate func streamError(_ handle: V4StreamHandle) -> SessionError? {
      gate.withLock {
        if let termination { return termination }
        do {
          try check()
          return try core.streamError(handle)
        } catch { return Self.failure(error) }
      }
    }
    fileprivate func waitStreamTermination(_ handle: V4StreamHandle) async throws -> SessionError {
      while true {
        try Task.checkCancellation()
        let version = events.revision
        if let error = streamError(handle) { return error }
        try await events.wait(after: version)
      }
    }
    func rekey() async throws {
      let epoch = try gate.withLock {
        try check()
        guard !activeRekey else { throw SessionError.resourceExhausted }
        let epoch = try core.epoch()
        try core.beginRekeyIntent()
        activeRekey = true
        return epoch
      }
      defer { gate.withLock { activeRekey = false } }
      var requested = false
      while true {
        let version = events.revision
        let done = try gate.withLock {
          try check()
          if Task.isCancelled { throw SessionError.canceled }
          // The scheduler may finish the original intent before this caller
          // wakes. Observe completion before requesting another round.
          if try core.epoch() > epoch { return true }
          if !requested, try socket.writable(maintenance: true), try core.canMaintain() {
            requested = try core.requestRekey(to: socket)
          }
          return try core.epoch() > epoch
        }
        if done { return }
        try await events.wait(after: version)
      }
    }
    func probeLiveness() async throws -> Duration {
      let probe: V4LivenessProbe
      do {
        probe = try gate.withLock {
          try check()
          if Task.isCancelled { throw SessionError.canceled }
          return try core.beginProbe()
        }
      } catch let error as TransportLivenessError { throw error } catch {
        throw TransportLivenessError(
          reason: Task.isCancelled
            ? .canceled
            : error is V4TimeFailure || error as? SessionError == .timeUnavailable
              ? .timeUnavailable : .closed,
          progress: TransportLivenessProgress(
            submitted: false, complete: false, elapsedMilliseconds: nil))
      }
      defer { gate.withLock { core.releaseProbe(probe) } }
      do {
        return try await withTaskCancellationHandler {
          var submitted = false
          while true {
            let version = events.revision
            let result: TransportLivenessProgress? = try gate.withLock {
              if let result = try core.probeResult(probe) { return result }
              try check()
              if !submitted, try socket.writable(maintenance: true) {
                submitted = try core.submitProbe(probe, to: socket)
              }
              return try core.probeResult(probe)
            }
            if let result, let elapsed = result.elapsedMilliseconds {
              return .milliseconds(elapsed)
            }
            try await events.wait(after: version)
          }
        } onCancel: {
          probe.requestCancellation()
        }
      } catch {
        return try gate.withLock {
          core.endProbe(
            probe,
            reason: Task.isCancelled
              ? .canceled
              : error is V4TimeFailure || error as? SessionError == .timeUnavailable
                ? .timeUnavailable : .closed)
          // A result that won the Session gate remains authoritative, including
          // a PONG completed just before Task cancellation or Session close.
          guard let result = try core.probeResult(probe), let elapsed = result.elapsedMilliseconds
          else {
            throw TransportLivenessError(
              reason: .timeUnavailable,
              progress: TransportLivenessProgress(
                submitted: false, complete: false, elapsedMilliseconds: nil))
          }
          return .milliseconds(elapsed)
        }
      }
    }
    func replacementCapacity() throws -> ConnectionReplacementCapacity {
      try gate.withLock {
        try check()
        let plan = admission.plan
        return ConnectionReplacementCapacity(maximumFrameBytes: plan.route.maximumFrame, maximumStreams: plan.maxStreams,
          maximumCreditBytes: plan.maxCredit, maximumGeneralOutstanding: plan.maximumGeneralOutstanding,
          applicationProfile: ["transport", "services", "execution"][Int(plan.applicationProfile)])
      }
    }
    func retirementDeadline(maximum: Duration) throws -> ContinuousClock.Instant {
      try gate.withLock {
        try check()
        guard maximum > .zero, maximum <= .seconds(30), !core.observationDraining else { throw SessionError.goingAway }
        return try admission.plan.credential.retirementDeadline(in: admission.plan.environment, maximum: maximum)
      }
    }
    func beginDrain(timeout: Duration) throws -> SessionDrainOperation {
      try gate.withLock {
        if let drainOwner { return SessionDrainOperation(drainOwner) }
        try check()
        guard timeout > .zero, timeout <= .seconds(30) else { throw SessionError.operationFailed }
        let deadline = try admission.plan.credential.retirementDeadline(in: admission.plan.environment, maximum: timeout)
        let owner = V4NativeSessionDrain(session: self, deadline: deadline, storage: try admission.plan.environment.sessionDrainStorage())
        try core.beginDrain(); admission.server?.beginDrain(deadline: deadline)
        admission.management?.beginDrain(deadline: deadline)
        drainOwner = owner
        do { try owner.start() } catch { terminate(Self.failure(error)); throw error }
        events.signal()
        return SessionDrainOperation(owner)
      }
    }
    func drainBusinessComplete() async throws -> Bool {
      let coreDone = try gate.withLock { try check(); return try core.drainBusinessComplete() }
      guard coreDone else { return false }
      if let services = admission.services, await services.drainPending > 0 { return false }
      let channels = gate.withLock { dynamicRPCChannels.values.flatMap { $0 } + peerRPCChannels }
      for channel in channels { if await channel.drainPending > 0 { return false } }
      if let notifications = admission.notifications, await notifications.drainPending > 0 { return false }
      guard admission.server?.drainPending == nil || admission.server?.drainPending == 0 else { return false }
      if let receiver = admission.notificationReceiver, await receiver.businessPending > 0 { return false }
      return true
    }
    func finishDrain() async {
      // The termination decision and accepted management/notification close
      // begin under the original session gate. The caller has already drained
      // every asynchronous business owner before entering this boundary.
      gate.withLock { terminate(.closed) }
      await join()
    }
    func retirementPendingCallbacks() async -> Int {
      var pending = gate.withLock { rpcInitializer == nil ? 0 : 1 }
      pending += admission.server?.physicalPending ?? 0
      if let services = admission.services { pending += await services.physicalPending }
      let channels = gate.withLock { dynamicRPCChannels.values.flatMap { $0 } + peerRPCChannels }
      for channel in channels { pending += await channel.physicalPending }
      if let notifications = admission.notifications { pending += await notifications.physicalPending }
      if let management = admission.management { pending += await management.physicalPendingCount() }
      if let receiver = admission.notificationReceiver { pending += await receiver.physicalPending }
      return pending
    }
    func waitPhysicalCleanup() async {
      await join()
      while await retirementPendingCallbacks() > 0 {
        try? await ContinuousClock().sleep(for: .milliseconds(10))
      }
    }
    func waitTermination() async -> SessionTermination {
      while true {
        let version = events.revision
        if let error = gate.withLock({ termination }) {
          await join()
          return SessionTermination(error: error)
        }
        do { try await events.wait(after: version) } catch {
          return SessionTermination(error: .canceled)
        }
      }
    }
    func close() async throws {
      terminate(.closed)
      await join()
    }
    private func join() async {
      let tasks = gate.withLock { (reader, scheduler) }
      await tasks.0?.value
      await tasks.1?.value
      await socket.waitClosed()
    }
    deinit { terminate(.closed) }
  }

  final class V4NativeByteStream: V4DuplexBridgeEndpoint, V4LowLevelTypedOwner, V4RPCTransport, V4ProxySessionStream, @unchecked Sendable {
    let kind: String
    private let session: V4NativeSession
    private let handle: V4StreamHandle
    private var gate: NSRecursiveLock { session.serviceEnvironment.gate }
    var rpcCleanupComplete: Bool { gate.withLock { !reading && !writing && session.core.internalCleanupComplete(handle) } }
    private var reading = false
    private var writing = false
    private var finished = false
    private var aborted = false
    private var messageClaimed = false
    private var resumeClaimed = false
    private var rawUsed = false
    private var bridgeClaimed = false
    private var bridgeReading = false
    private var bridgeWriting = false
    private let messageDefinition: MessageStreamDefinition?
    private let messageApplication: StreamMetadata
    private let messageCapture: V4MessageRegistrationCapture?
    private var messageStorage: V4CryptoReservation?
    init(
      session: V4NativeSession, handle: V4StreamHandle, kind: String,
      messageDefinition: MessageStreamDefinition? = nil,
      messageStorage: V4CryptoReservation? = nil,
      messageApplication: StreamMetadata = .empty,
      messageCapture: V4MessageRegistrationCapture? = nil
    ) {
      self.session = session
      self.handle = handle
      self.kind = kind
      self.messageDefinition = messageDefinition
      self.messageStorage = messageStorage
      self.messageApplication = messageApplication
      self.messageCapture = messageCapture
    }
    fileprivate func preparePendingMessageStream(
      definition: MessageStreamDefinition
    ) throws -> (V4PreparedMessageStream, V4NativeMessageStream) {
      let view = V4NativeMessageStream(original: self)
      let prepared = try session.withMessageStreamClaim {
        try gate.withLock {
          guard messageDefinition == definition, let storage = messageStorage,
            !bridgeClaimed, !rawUsed, !messageClaimed, !reading, !writing, !aborted, !finished else {
            throw ServiceFailure.contractMismatch
          }
          let prepared = try session.messagePreparation(stream: view, storage: storage)
          messageStorage = nil
          try session.core.checkApplicationOwner(handle)
          messageClaimed = true
          return prepared
        }
      }
      return (prepared, view)
    }

    func claimMessageStream(definition: MessageStreamDefinition) throws -> V4PreparedMessageStream {
      let view = V4NativeMessageStream(original: self)
      // The facade candidate exists before the original claim gate. Only its
      // exact native I/O token is published when the claim wins.
      return try session.withMessageStreamClaim {
        try gate.withLock {
          guard messageDefinition == definition, let storage = messageStorage,
            !bridgeClaimed, !rawUsed, !messageClaimed, !reading, !writing, !aborted, !finished else {
            throw ServiceFailure.contractMismatch
          }
          let result = try session.messagePreparation(stream: view, storage: storage)
          messageStorage = nil
          try session.core.checkApplicationOwner(handle)
          messageClaimed = true
          view.activate()
          return result
        }
      }
    }

    func lowLevelTypedInfo(definition: MessageStreamDefinition) throws -> V4TypedStreamClaimInfo {
      try session.withMessageStreamClaimInfo {
        try gate.withLock {
          guard !bridgeClaimed, !rawUsed, !messageClaimed, !reading, !writing, !aborted, !finished else {
            throw ServiceFailure.contractMismatch
          }
          guard messageDefinition == definition else { throw ServiceFailure.contractMismatch }
          let opener = try session.lowLevelTypedInfo(handle: handle, definition: definition)
          return V4TypedStreamClaimInfo(opener: opener, application: messageApplication)
        }
      }
    }

    func prepareLowLevelTypedMessageStream(
      definition: MessageStreamDefinition
    ) throws -> V4LowLevelMessageCandidate {
      let view = V4NativeMessageStream(original: self)
      let prepared = try session.withMessageStreamClaim {
        try gate.withLock {
          guard !bridgeClaimed, !rawUsed, !messageClaimed, !reading, !writing, !aborted, !finished,
            messageDefinition == definition else { throw ServiceFailure.contractMismatch }
          _ = try session.lowLevelTypedInfo(handle: handle, definition: definition)
          let storage = try messageStorage ?? session.lowLevelTypedStorage()
          return try session.messagePreparation(stream: view, storage: storage)
        }
      }
      // Full typed facade construction follows outside this gate. Its inactive
      // view cannot touch the accepted raw owner while construction is pending.
      return V4LowLevelMessageCandidate(prepared: prepared, claim: { [self] in
        _ = try session.withMessageStreamClaim {
          try gate.withLock {
            guard !bridgeClaimed, !rawUsed, !messageClaimed, !reading, !writing, !aborted, !finished,
              messageDefinition == definition else { throw ServiceFailure.contractMismatch }
            _ = try session.lowLevelTypedInfo(handle: handle, definition: definition)
            try prepared.storage.check()
            guard messageStorage == nil || messageStorage === prepared.storage else {
              throw ServiceFailure.contractMismatch
            }
            messageStorage = nil
            try session.core.checkApplicationOwner(handle)
            messageClaimed = true
            view.activate()
            return prepared
          }
        }
      })
    }

    func claimOpenedMessageStream(
      definition: MessageStreamDefinition, storage: V4CryptoReservation
    ) throws -> V4PreparedMessageStream {
      let view = V4NativeMessageStream(original: self)
      return try session.withMessageStreamClaim {
        try gate.withLock {
          guard kind == definition.kind, messageDefinition == nil, messageStorage == nil,
            !bridgeClaimed, !rawUsed, !messageClaimed, !reading, !writing, !aborted, !finished else {
            throw ServiceFailure.contractMismatch
          }
          let result = try session.messagePreparation(stream: view, storage: storage)
          try session.core.checkApplicationOwner(handle)
          messageClaimed = true
          view.activate()
          return result
        }
      }
    }

    func captureResume(in expected: V4NativeSession, kind: String) throws -> ServiceResumeTarget {
      guard session === expected, self.kind == kind else { throw ServiceFailure.permissionDenied }
      return try session.withMessageStreamClaimInfo {
        try gate.withLock {
          guard !bridgeClaimed, !rawUsed, !messageClaimed, !reading, !writing, !aborted, !finished, messageDefinition == nil else { throw ServiceFailure.closed }
          let (context, streamID, tokenBytes, durationMS) = try session.resumeFacts(handle)
          try session.core.checkApplicationOwner(handle)
          messageClaimed = true; resumeClaimed = true
          return ServiceResumeTarget(session: session, kind: kind, contextDigest: context, streamID: streamID,
            maximumTokenBytes: tokenBytes, maximumIssuedDurationMS: durationMS,
            check: { [self] in
              try gate.withLock {
                guard resumeClaimed, !reading, !writing, !aborted, !finished else { throw ServiceFailure.closed }
                _ = try session.resumeFacts(handle, capture: false)
              }
            }, take: { [self] in
              try gate.withLock {
                guard resumeClaimed, !aborted, !finished else { throw ServiceFailure.closed }
                resumeClaimed = false; messageClaimed = false; return self
              }
            }, dispose: { [self] in
              gate.withLock { resumeClaimed = false; aborted = true }
              session.disposeStream(handle)
            })
        }
      }
    }
    func checkServiceDependency() throws {
      try gate.withLock {
        guard !aborted, !finished, !reading, !writing, !messageClaimed, !bridgeClaimed else { throw ServiceFailure.closed }
        try session.core.checkApplicationOwner(handle)
      }
    }
    private func checkIO(message: Bool) throws {
      guard messageStorage == nil, messageClaimed == message, !bridgeClaimed else { throw SessionError.closed }
      try session.core.checkApplicationOwner(handle)
      if !message { rawUsed = true }
    }

    static func prepareBridge(
      _ a: any ByteStream, _ b: any ByteStream, token: V4DuplexBridgeToken,
      chunkBytes: Int
    ) throws -> (V4NativeByteStream, V4NativeByteStream, V4CryptoReservation, V4CryptoReservation, V4ResourceReference) {
      guard let a = a as? V4NativeByteStream, let b = b as? V4NativeByteStream else {
        throw DuplexBridgeFailure.ownerUnavailable
      }
      let environment = a.session.serviceEnvironment
      guard environment === b.session.serviceEnvironment else { throw DuplexBridgeFailure.ownerUnavailable }
      return try environment.gate.withLock {
        guard !a.session.core.sameEndpoint(a.handle, b.handle) else { throw DuplexBridgeFailure.invalidEndpoint }
        try a.checkBridgeCandidate(); try b.checkBridgeCandidate()
        let storage = try environment.duplexBridgeStorage(chunkBytes: chunkBytes)
        let resultStorage = try environment.duplexBridgeResultStorage(chunkBytes: chunkBytes)
        let tail = try storage.executionTail()
        do {
          try a.session.core.claimBridge(a.handle, token: token)
          do { try b.session.core.claimBridge(b.handle, token: token) }
          catch { a.session.core.rollbackBridge(a.handle, token: token); throw error }
          a.bridgeClaimed = true; b.bridgeClaimed = true
          return (a, b, storage, resultStorage, tail)
        } catch { tail.release(); throw error }
      }
    }
    static func prepareNativeBridge(_ stream: any ByteStream, _ native: V4DuplexTCPOwner,
      token: V4DuplexBridgeToken, chunkBytes: Int
    ) throws -> (V4NativeByteStream, V4CryptoReservation, V4CryptoReservation, V4ResourceReference) {
      guard let stream = stream as? V4NativeByteStream else { throw DuplexBridgeFailure.ownerUnavailable }
      let environment = stream.session.serviceEnvironment
      guard environment === native.bridgeEnvironment else { throw DuplexBridgeFailure.ownerUnavailable }
      return try environment.gate.withLock {
        try stream.checkBridgeCandidate()
        try native.checkBridgeCandidate(chunkBytes: chunkBytes)
        let storage = try environment.duplexBridgeStorage(chunkBytes: chunkBytes)
        let resultStorage = try environment.duplexBridgeResultStorage(chunkBytes: chunkBytes)
        let tail = try storage.executionTail()
        do {
          try stream.session.core.claimBridge(stream.handle, token: token)
          do { try native.claimBridge(token: token, chunkBytes: chunkBytes) }
          catch { stream.session.core.rollbackBridge(stream.handle, token: token); throw error }
          stream.bridgeClaimed = true
          return (stream, storage, resultStorage, tail)
        } catch { tail.release(); throw error }
      }
    }
    private func checkBridgeCandidate() throws {
      try session.checkServiceSession()
      guard messageStorage == nil, messageDefinition == nil, !bridgeClaimed,
        !rawUsed, !messageClaimed, !resumeClaimed, !reading, !writing, !aborted, !finished
      else { throw DuplexBridgeFailure.streamOwned }
      try session.core.checkBridgeCandidate(handle)
    }
    var bridgeEnvironment: V4EnvironmentFoundation { session.serviceEnvironment }
    var bridgeKind: DuplexBridgeEndpointKind { .flowersecStream }
    func bridgeRead(token: V4DuplexBridgeToken, maxBytes: Int,
      beforeRead: @escaping @Sendable () throws -> Void,
      delivered: @escaping @Sendable (Data) -> Void
    ) async throws -> Data? {
      try gate.withLock {
        try session.core.checkApplicationOwner(handle, bridge: token)
        guard bridgeClaimed, !bridgeReading, !aborted else { throw SessionError.closed }
        bridgeReading = true
      }
      defer { gate.withLock { bridgeReading = false } }
      do {
        return try await session.read(handle, maximum: maxBytes,
          beforeRead: { [self] in
            try session.core.checkApplicationOwner(handle, bridge: token)
            try beforeRead()
          }, delivered: delivered)
      } catch let error as DuplexBridgeFailure { throw error }
      catch { throw V4NativeSession.failure(error) }
    }
    func bridgeWrite(token: V4DuplexBridgeToken, _ data: Data,
      beforeAccept: @escaping @Sendable () throws -> Void,
      accepted: @escaping @Sendable (Int) -> Void
    ) async throws -> Int {
      try gate.withLock {
        try session.core.checkApplicationOwner(handle, bridge: token)
        guard bridgeClaimed, !bridgeWriting, !finished, !aborted else { throw SessionError.closed }
        bridgeWriting = true
      }
      defer { gate.withLock { bridgeWriting = false } }
      do {
        return try await session.write(handle, data: data,
          beforeAccept: { [self] in
            try session.core.checkApplicationOwner(handle, bridge: token)
            try beforeAccept()
          }, accepted: accepted)
      } catch let error as DuplexBridgeFailure { throw error }
      catch { throw V4NativeSession.failure(error) }
    }
    func bridgeCloseWrite(token: V4DuplexBridgeToken,
      beforeFinish: @escaping @Sendable () throws -> Void) async throws {
      try gate.withLock {
        try session.core.checkApplicationOwner(handle, bridge: token)
        try beforeFinish()
        guard bridgeClaimed, !aborted else { throw SessionError.closed }
        finished = true
      }
      do {
        try await session.closeWrite(handle, beforeFinish: { [self] in
          try session.core.checkApplicationOwner(handle, bridge: token)
          try beforeFinish()
        })
      } catch let error as DuplexBridgeFailure { throw error }
      catch { throw V4NativeSession.failure(error) }
    }
    func bridgeFinish(token: V4DuplexBridgeToken,
      beforeFinish: @escaping @Sendable () throws -> Void) async throws {
      do {
        try await session.finish(handle, beforeFinish: { [self] in
          try session.core.checkApplicationOwner(handle, bridge: token)
          try beforeFinish()
        })
      } catch let error as DuplexBridgeFailure { throw error }
      catch { throw V4NativeSession.failure(error) }
    }
    func bridgeReset(token: V4DuplexBridgeToken) {
      gate.withLock {
        guard bridgeClaimed else { return }
        guard (try? session.core.checkApplicationOwner(handle, bridge: token)) != nil else { return }
        session.disposeStream(handle, bridge: token)
        aborted = true
      }
    }
    func bridgeCleanupComplete(token: V4DuplexBridgeToken) -> Bool {
      gate.withLock {
        !bridgeReading && !bridgeWriting && session.core.bridgeCleanupComplete(handle, token: token)
      }
    }

    func checkProxySession(_ expected: any V4ServiceSession) throws {
      guard let expected = expected as? V4NativeSession, session === expected else { throw ProxyClientFailure.protocolFailure }
      try session.checkServiceSession()
    }
    func read(maxBytes: Int) async throws -> Data? { try await read(maxBytes: maxBytes, message: false) }
    func read(maxBytes: Int, message: Bool) async throws -> Data? {
      try gate.withLock {
        try checkIO(message: message)
        guard !reading else { throw SessionError.resourceExhausted }
        guard !aborted else { throw SessionError.streamReset }
        reading = true
      }
      defer { gate.withLock { reading = false } }
      do { return try await session.read(handle, maximum: maxBytes) } catch {
        throw V4NativeSession.failure(error)
      }
    }

    func write(_ data: Data) async throws -> Int {
      try await write(data, message: false)
    }
    func writeRPCChunk(_ bytes: Data, beforeAccept: @escaping @Sendable () throws -> Void,
      accepted: @escaping @Sendable (Int) -> Void) async throws -> Int {
      try await write(bytes, message: false, beforeAccept: beforeAccept, accepted: accepted)
    }

    func writeRPCPublicationChunk(_ bytes: Data, beforeAccept: @escaping @Sendable () throws -> Void,
      accepted: @escaping @Sendable (Int) -> Void, completed: @escaping @Sendable (Int, Bool) -> Void) async throws -> Int {
      try await write(bytes, message: false, beforeAccept: beforeAccept, accepted: accepted, completed: completed)
    }

    func write(
      _ data: Data, message: Bool,
      beforeAccept: (@Sendable () throws -> Void)? = nil,
      accepted: (@Sendable (Int) -> Void)? = nil,
      completed: (@Sendable (Int, Bool) -> Void)? = nil
    ) async throws -> Int {
      do {
        try gate.withLock {
          try checkIO(message: message)
          guard !writing else { throw SessionError.resourceExhausted }
          guard !finished, !aborted else { throw SessionError.streamReset }
          writing = true
        }
      } catch { completed?(0, false); throw V4NativeSession.failure(error) }
      defer { gate.withLock { writing = false } }
      do {
        return try await session.write(handle, data: data, beforeAccept: beforeAccept, accepted: accepted, completed: completed)
      } catch { throw V4NativeSession.failure(error) }
    }

    func closeWrite() async throws { try await closeWrite(message: false) }
    func closeWrite(message: Bool) async throws {
      try gate.withLock { try checkIO(message: message); finished = true }
      do { try await session.closeWrite(handle) } catch { throw V4NativeSession.failure(error) }
    }
    func finish() async throws { try await finish(message: false) }
    func finish(message: Bool) async throws {
      do {
        try await closeWrite(message: message)
        try await session.finish(handle)
      } catch { throw V4NativeSession.failure(error) }
    }
    func reset() async throws { try await reset(message: false) }
    func reset(message: Bool) async throws {
      let needed = try gate.withLock { () -> Bool in
        // An unclaimed accepted wrapper can always be disposed by its original
        // handler owner, including when facade construction failed.
        guard messageClaimed == message, !bridgeClaimed else { throw SessionError.closed }
        try session.core.checkApplicationOwner(handle)
        if !message { rawUsed = true }
        return !aborted
      }
      guard needed else { return }
      do { try session.reset(handle) } catch { throw V4NativeSession.failure(error) }
      gate.withLock { aborted = true; messageStorage = nil }
    }
    func close() async throws { try await reset() }

    func disposeClaimedStream() {
      // A candidate that never won the claim has no right to reset its source.
      guard gate.withLock({ messageClaimed }) else { return }
      session.disposeStream(handle)
    }
    func terminalError() async -> SessionError? {
      if gate.withLock({ aborted }) { return .streamReset }
      return session.streamError(handle)
    }
    func waitProxyTermination() async throws -> SessionError {
      if gate.withLock({ aborted }) { return .streamReset }
      return try await session.waitStreamTermination(handle)
    }
    deinit {
      session.disposeStream(handle)
      session.releaseWrapper()
    }
  }

  // The opener can prepare its typed facade before allocating an ID or
  // emitting OPEN. This single native token gains I/O only after that OPEN's
  // acceptance; close cannot be undone by a late publication continuation.
  private final class V4DeferredMessageStream: V4MessageStreamWriter, @unchecked Sendable {
    let kind: String
    private let gate = NSLock()
    private var source: (any V4MessageStreamWriter)?
    private var publishing = false
    private var closed = false
    init(kind: String) { self.kind = kind }
    func beginPublication() throws {
      try gate.withLock {
        guard !closed, !publishing else { throw SessionError.closed }
        publishing = true
      }
    }
    func bind(_ stream: any V4MessageStreamWriter) throws {
      try gate.withLock {
        guard publishing, !closed, source == nil, stream.kind == kind else { throw SessionError.closed }
        source = stream
      }
    }
    private func activeSource() throws -> any V4MessageStreamWriter {
      try gate.withLock {
        guard !closed, let source else { throw SessionError.closed }
        return source
      }
    }
    func read(maxBytes: Int) async throws -> Data? { try await activeSource().read(maxBytes: maxBytes) }
    func write(_ data: Data) async throws -> Int { try await activeSource().write(data) }
    func writeMessageChunk(
      _ data: Data, beforeAccept: @escaping @Sendable () throws -> Void,
      accepted: @escaping @Sendable (Int) -> Void
    ) async throws -> Int {
      try await activeSource().writeMessageChunk(data, beforeAccept: beforeAccept, accepted: accepted)
    }
    func closeWrite() async throws { try await activeSource().closeWrite() }
    func finish() async throws { try await activeSource().finish() }
    func reset() async throws { try await close() }
    func close() async throws {
      let original = gate.withLock { () -> (any V4MessageStreamWriter)? in
        guard !closed else { return nil }
        closed = true
        defer { source = nil }
        return source
      }
      try await original?.close()
    }
    func terminalError() async -> SessionError? {
      guard let original = try? activeSource() else { return .closed }
      return await original.terminalError()
    }
  }

  // Transfer of typed ownership does not leave a usable raw alias. Only this
  // private native view can exercise the claimed directions and reset owner.
  fileprivate final class V4NativeMessageStream: V4MessageStreamWriter, @unchecked Sendable {
    let original: V4NativeByteStream
    private let gate = NSLock()
    private var claimed = false
    var kind: String { original.kind }
    init(original: V4NativeByteStream) { self.original = original }
    func activate() { gate.withLock { claimed = true } }
    private func checkActivated() throws {
      try gate.withLock { guard claimed else { throw SessionError.closed } }
    }
    func read(maxBytes: Int) async throws -> Data? {
      try checkActivated()
      return try await original.read(maxBytes: maxBytes, message: true)
    }
    func write(_ data: Data) async throws -> Int {
      try checkActivated()
      return try await original.write(data, message: true)
    }
    func writeMessageChunk(
      _ data: Data, beforeAccept: @escaping @Sendable () throws -> Void,
      accepted: @escaping @Sendable (Int) -> Void
    ) async throws -> Int {
      try checkActivated()
      return try await original.write(data, message: true, beforeAccept: beforeAccept, accepted: accepted)
    }
    func closeWrite() async throws {
      try checkActivated()
      try await original.closeWrite(message: true)
    }
    func finish() async throws {
      try checkActivated()
      try await original.finish(message: true)
    }
    func reset() async throws {
      guard gate.withLock({ claimed }) else { return }
      try await original.reset(message: true)
    }
    func close() async throws { try await reset() }
    func terminalError() async -> SessionError? { await original.terminalError() }
    deinit {
      if gate.withLock({ claimed }) { original.disposeClaimedStream() }
    }
  }

#endif
