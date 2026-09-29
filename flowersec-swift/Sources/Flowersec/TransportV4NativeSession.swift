#if os(macOS) || os(iOS)
  import Foundation

  // One finite event channel wakes original waiters. Cancellation removes only
  // its waiter and never detaches the socket pump or manufactures EOF.
  private final class V4SessionEvents: @unchecked Sendable {
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

  final class V4NativeSession: Session, @unchecked Sendable {
    private final class Lifetime: V4NativeConnectionLifecycle, @unchecked Sendable {
      weak var session: V4NativeSession?
      func close() { session?.terminate(.closed) }
    }
    private let admission: V4NativeSessionAdmission
    private let events: V4SessionEvents
    private let lifetime = Lifetime()
    private var reader: Task<Void, Never>?
    private var scheduler: Task<Void, Never>?
    private var termination: SessionError?
    private var activeAccept = false
    private var activeOpen = false
    private var activeRekey = false
    private var wrappers = 0
    private let idle: V4SessionIdleWatchdog
    private let unavailableRPC = V4TransportOnlyRPC()
    var rpc: any RPCPeer { unavailableRPC }
    private var gate: NSRecursiveLock { admission.plan.environment.gate }
    private var core: V4ReliableSession { admission.core }
    private var socket: V4ConsumedWebSocket { admission.socket }
    init(_ admission: V4NativeSessionAdmission) throws {
      self.admission = admission
      events = V4SessionEvents(maximum: admission.plan.slots * 4 + 8)
      idle = try V4SessionIdleWatchdog(
        clock: admission.plan.environment.clock, durationMS: admission.plan.idleMS)
      try admission.storage.check()
      lifetime.session = self
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
              try input.withBytes { try self.core.receive($0) }
              if try socket.writable() { _ = try self.core.poll(to: socket) }
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
              if try self.socket.writable() {
                _ = try self.core.poll(to: self.socket)
              } else {
                self.core.noteLivenessProviderBlocked()
              }
              self.events.signal()
            }
          }
        } catch { self?.terminate(Self.failure(error)) }
      }
    }
    fileprivate static func failure(_ error: any Error) -> SessionError {
      if let error = error as? SessionError { return error }
      if error is CancellationError { return .canceled }
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
    private func terminate(_ error: SessionError) {
      gate.withLock {
        guard termination == nil else { return }
        termination = error
        idle.close()
        socket.recordCompletion(nil)
        core.observeAuthenticatedInput(nil)
        if error == .timeUnavailable { core.noteLivenessTimeUnavailable() }
        core.close()
        socket.close()
        reader?.cancel()
        scheduler?.cancel()
        admission.storage.seal()
        events.signal()
      }
    }
    private func stream(_ handle: V4StreamHandle, kind: String) throws -> V4NativeByteStream {
      guard wrappers < admission.plan.slots else { throw SessionError.resourceExhausted }
      wrappers += 1
      return V4NativeByteStream(session: self, handle: handle, kind: kind)
    }
    fileprivate func releaseWrapper() { gate.withLock { wrappers -= 1 } }
    func openStream(kind: String, metadata: StreamMetadata) async throws -> any ByteStream {
      let encodedMetadata = try metadata.encodedV4()
      try gate.withLock {
        try check()
        guard !activeOpen else { throw SessionError.resourceExhausted }
        activeOpen = true
      }
      defer { gate.withLock { activeOpen = false } }
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
                receiveWindow: admission.plan.window, to: socket)
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
        if let handle { try? core.reset(handle) }
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
      do {
        while true {
          let version = events.revision
          let result: IncomingStream? = try gate.withLock {
            try check()
            if Task.isCancelled { throw SessionError.canceled }
            guard try socket.writable() else { return nil }
            if pending == nil { pending = try core.pendingOpen() }
            guard let handle = pending else { return nil }
            let metadata = try core.pendingMetadata(handle)
            defer { metadata.metadata.close() }
            let decoded: StreamMetadata
            do {
              decoded = try metadata.metadata.withBytes { try StreamMetadata(encodedV4: $0) }
            } catch {
              try core.decideOpen(handle, decision: .reject(.metadata), to: socket)
              pending = nil
              return nil
            }
            let value = try stream(handle, kind: metadata.kind)
            try core.decideOpen(
              handle, decision: .accept(receiveWindow: admission.plan.window), to: socket)
            pending = nil
            return IncomingStream(kind: metadata.kind, metadata: decoded, stream: value)
          }
          if let result { return result }
          try await events.wait(after: version)
        }
      } catch {
        if let pending {
          try? core.decideOpen(pending, decision: .reject(.application), to: socket)
        }
        throw Self.failure(error)
      }
    }
    fileprivate func read(_ handle: V4StreamHandle, maximum: Int) async throws -> Data? {
      guard (1...1_048_576).contains(maximum) else { throw SessionError.resourceExhausted }
      while true {
        let version = events.revision
        let result: Data?? = try gate.withLock {
          try check()
          if Task.isCancelled { throw SessionError.canceled }
          switch try core.read(handle, maximum: maximum) {
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
    fileprivate func write(_ handle: V4StreamHandle, data: Data, fin: Bool = false) async throws
      -> Int
    {
      while true {
        let version = events.revision
        let count: Int? = try gate.withLock {
          try check()
          if Task.isCancelled { throw SessionError.canceled }
          guard try socket.writable(), try core.canOpen() else { return nil }
          let capacity = try core.writeCapacity(handle)
          if !data.isEmpty && capacity == 0 { return nil }
          let count = try core.write(
            handle, data: Data(data.prefix(capacity)), fin: fin, to: socket)
          events.signal()
          return count
        }
        if let count { return count }
        try await events.wait(after: version)
      }
    }
    fileprivate func closeWrite(_ handle: V4StreamHandle) async throws {
      try gate.withLock {
        if try core.finSubmitted(handle) { return }
        try check()
        try core.requestCloseWrite(handle)
        events.signal()
      }
      while true {
        let version = events.revision
        if try gate.withLock({
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
    fileprivate func finish(_ handle: V4StreamHandle) async throws {
      while true {
        let version = events.revision
        if try gate.withLock({
          if try core.sendFinished(handle) { return true }
          try check()
          return false
        }) {
          return
        }
        try await events.wait(after: version)
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
          if !requested, try socket.writable() {
            _ = try core.requestRekey(to: socket)
            requested = true
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
      } catch let error as TransportV4LivenessError { throw error } catch {
        throw TransportV4LivenessError(
          reason: Task.isCancelled
            ? .canceled
            : error is V4TimeFailure || error as? SessionError == .timeUnavailable
              ? .timeUnavailable : .closed,
          progress: TransportV4LivenessProgress(
            submitted: false, complete: false, elapsedMilliseconds: nil))
      }
      defer { gate.withLock { core.releaseProbe(probe) } }
      do {
        return try await withTaskCancellationHandler {
          var submitted = false
          while true {
            let version = events.revision
            let result: TransportV4LivenessProgress? = try gate.withLock {
              if let result = try core.probeResult(probe) { return result }
              try check()
              if !submitted, try socket.writable() {
                try core.submitProbe(probe, to: socket)
                submitted = true
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
            throw TransportV4LivenessError(
              reason: .timeUnavailable,
              progress: TransportV4LivenessProgress(
                submitted: false, complete: false, elapsedMilliseconds: nil))
          }
          return .milliseconds(elapsed)
        }
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

  private final class V4NativeByteStream: ByteStream, @unchecked Sendable {
    let kind: String
    private let session: V4NativeSession
    private let handle: V4StreamHandle
    private let gate = NSLock()
    private var reading = false
    private var writing = false
    private var finished = false
    private var aborted = false
    init(session: V4NativeSession, handle: V4StreamHandle, kind: String) {
      self.session = session
      self.handle = handle
      self.kind = kind
    }
    func read(maxBytes: Int) async throws -> Data? {
      try gate.withLock {
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
      try gate.withLock {
        guard !writing else { throw SessionError.resourceExhausted }
        guard !finished, !aborted else { throw SessionError.streamReset }
        writing = true
      }
      defer { gate.withLock { writing = false } }
      do { return try await session.write(handle, data: data) } catch {
        throw V4NativeSession.failure(error)
      }
    }
    func closeWrite() async throws {
      gate.withLock { finished = true }
      do { try await session.closeWrite(handle) } catch { throw V4NativeSession.failure(error) }
    }
    func finish() async throws {
      do {
        try await closeWrite()
        try await session.finish(handle)
      } catch { throw V4NativeSession.failure(error) }
    }
    func reset() async throws {
      if gate.withLock({ aborted }) { return }
      do { try session.reset(handle) } catch { throw V4NativeSession.failure(error) }
      gate.withLock { aborted = true }
    }
    func close() async throws { try await reset() }
    func terminalError() async -> SessionError? {
      gate.withLock { aborted ? .streamReset : session.streamError(handle) }
    }
    deinit {
      try? session.reset(handle)
      session.releaseWrapper()
    }
  }

  private struct V4TransportOnlyRPC: RPCPeer {
    func call<Request: Encodable & Sendable, Response: Decodable & Sendable>(
      _ typeID: UInt32,
      _ request: Request, as responseType: Response.Type, timeout: Duration
    ) async throws -> Response { throw SessionError.operationFailed }
    func notify<Payload: Encodable & Sendable>(_ typeID: UInt32, _ payload: Payload) async throws {
      throw SessionError.operationFailed
    }
    func subscribeNotification<Payload: Decodable & Sendable>(
      _ typeID: UInt32, as payloadType: Payload.Type,
      handler: @escaping @Sendable (Result<Payload, RPCNotificationError>) async throws -> Void
    )
      async throws -> any RPCNotificationSubscription
    { throw SessionError.operationFailed }
  }
#endif
