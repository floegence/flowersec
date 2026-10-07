import Foundation

public enum MessageSendAdmission: String, Sendable { case queued, tryNow = "try_now" }
public enum MessageSubmission: String, Sendable { case notSubmitted = "not_submitted", submitted }
public struct MessageSendResult: Sendable, Equatable {
  public let submission: MessageSubmission
  public let streamBytesAcceptedAtReturn: UInt64
  public let publicationPending: Bool
  public let cleanup: CleanupStatus
}
public enum MessageStreamFailure: String, Error, Sendable {
  case closed, canceled
  case deadlineExceeded = "deadline_exceeded"
  case resourceExhausted = "resource_exhausted"
  case wouldBlock = "would_block"
  case encodeFailed = "encode_failed"
  case writeFailed = "write_failed"
  case dependencyUnavailable = "dependency_unavailable"
}
public struct MessageStreamError: Error, Sendable {
  public let code: MessageStreamFailure
  public let progress: MessageSendResult
}

// Entry, timer and encoder lifetime share the original TransportEnvironment gate. A
// canceled waiter cannot refund an encoder or provider that has not returned.
final class MessageStreamSendOwner<Value: Sendable>: @unchecked Sendable {
  private enum Phase: Equatable { case preparing, ready, publishing, terminal }
  private final class Entry: @unchecked Sendable {
    let maximum: Int
    let deadline: ContinuousClock.Instant
    var storage: V4CryptoReservation?
    var work: V4ApplicationWork?
    var tail: V4ResourceReference?
    var timer: Task<Void, Never>?
    var publisher: Task<Void, Never>?
    var payload: Data?
    var segments: [V4MessageSegment]?
    var payloadLength = 0
    var retainedBytes: Int
    var phase = Phase.preparing
    var failure: MessageStreamFailure?
    var accepted: UInt64 = 0
    var encoderPending = true
    var timerPending = true
    var publisherPending = false
    var published = false
    var continuation: CheckedContinuation<MessageSendResult, Error>?
    init(maximum: Int, deadline: ContinuousClock.Instant, storage: V4CryptoReservation, retainedBytes: Int) {
      self.maximum = maximum; self.deadline = deadline; self.storage = storage
      self.retainedBytes = retainedBytes
    }
  }
  private final class Waiter: @unchecked Sendable {
    var canceled = false
    var entry: Entry?
  }
  private final class CloseWaiter: @unchecked Sendable {
    var canceled = false
    var continuation: CheckedContinuation<Void, Error>?
  }

  private static var byteCap: Int { 2 * 1024 * 1024 + 32 }
  private let core: TypedMessageStreamCore
  private let codec: any MessageCodec<Value>
  private let definition: MessageDefinition
  private let timeout: Duration
  private var entries: [Entry] = []
  private var order: [Entry] = []
  private var retainedBytes = 0
  private var publishing: Entry?
  private var sealed = false
  private var closed = false
  private var closeStarted = false
  private var closeTask: Task<Void, Never>?
  private var closeTimer: Task<Void, Never>?
  private var closeResult: Result<Void, MessageStreamFailure>?
  private var closeWaiter: CloseWaiter?
  private var resetStarted = false

  init(core: TypedMessageStreamCore, codec: any MessageCodec<Value>, definition: MessageDefinition, timeout: Duration) {
    self.core = core; self.codec = codec; self.definition = definition; self.timeout = timeout
  }

  func send(_ value: Value, admission: MessageSendAdmission, context: ApplicationInvocationContext? = nil) async throws -> MessageSendResult {
    let waiter = Waiter()
    let deadline = ContinuousClock.now.advanced(by: timeout)
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        var encoder: V4ApplicationWork?
        var direct: (V4SynchronousApplicationStage, @Sendable (ApplicationInvocationContext) -> Void, Entry)?
        var directOperation: (@Sendable (ApplicationInvocationContext) -> Void)?
        core.lock.withLock {
          if waiter.canceled || Task.isCancelled {
            continuation.resume(throwing: rejection(.canceled))
            return
          }
          if closed || sealed {
            continuation.resume(throwing: rejection(.closed))
            return
          }
          let effectiveAdmission: MessageSendAdmission = context == nil ? admission : .tryNow
          if effectiveAdmission == .tryNow && (publishing != nil || !order.isEmpty) {
            continuation.resume(throwing: rejection(.wouldBlock))
            return
          }
          let maximum = definition.maxMessageBytes
          let controlled: V4ControlledMessageInput?
          if V4MessageSegments.available, codec is BytesMessageCodec, let bytes = value as? Data {
            controlled = .bytes(bytes)
          } else if V4MessageSegments.available, codec is UTF8MessageCodec, let text = value as? String {
            controlled = .utf8(text)
          } else { controlled = nil }
          let initialBytes = controlled == nil ? maximum + 4 : 4
          guard entries.count < 8, initialBytes <= Self.byteCap - retainedBytes else {
            continuation.resume(throwing: rejection(effectiveAdmission == .tryNow ? .wouldBlock : .resourceExhausted))
            return
          }
          let entry: Entry
          do {
            try core.beginApplicationWorker()
            do {
              let storage: V4CryptoReservation
              let input: V4ControlledMessageInput?
              if let controlled {
                let size = try controlled.boundedSize(maximum: maximum)
                storage = try core.reserveControlledInput(bytes: size)
                input = controlled.ownedCopy()
              } else {
                storage = try core.reservePayload(bytes: maximum, encoding: true)
                input = nil
              }
              entry = Entry(maximum: maximum, deadline: deadline, storage: storage, retainedBytes: initialBytes)
              let operation: @Sendable (ApplicationInvocationContext) async -> Void
              if let input {
                let controlledOperation: @Sendable (ApplicationInvocationContext) -> Void = { [self, entry, input] invocation in
                  guard beginEncoding(entry) else { return }
                  core.applicationEntered(invocation.invocation)
                  defer { core.applicationExited(invocation.invocation) }
                  let writer = V4MessageSegments(
                    maximum: entry.maximum, gate: core.lock,
                    reserve: { [self, entry] bytes, blocks in
                      try reserveGrowth(entry, bytes: bytes, blocks: blocks)
                    }, check: { [self, entry] in try checkEncoding(entry) })
                  do {
                    try input.encode(into: writer)
                    let candidate = try writer.finalize()
                    encoded(entry, segments: candidate.segments, length: candidate.length)
                  } catch { failEncoding(entry, error: error) }
                }
                directOperation = controlledOperation
                operation = { invocation in controlledOperation(invocation) }
              } else if let asynchronous = codec as? any AsyncMessageCodec<Value> {
                operation = { [self, entry, asynchronous] invocation in
                  guard beginEncoding(entry) else { return }
                  core.applicationEntered(invocation.invocation)
                  defer { core.applicationExited(invocation.invocation) }
                  do {
                    let payload = try await asynchronous.encodeAsync(value, context: invocation)
                    guard payload.count <= entry.maximum else {
                      failEncoding(entry)
                      return
                    }
                    encoded(entry, payload: ownedEncodedPayload(payload))
                  } catch { failEncoding(entry) }
                }
              } else {
                let synchronous: @Sendable (ApplicationInvocationContext) -> Void = { [self, entry] invocation in
                  guard beginEncoding(entry) else { return }
                  core.applicationEntered(invocation.invocation)
                  defer { core.applicationExited(invocation.invocation) }
                  var payload = Data()
                  payload.reserveCapacity(entry.maximum)
                  do {
                    let count = try codec.encode(value, context: invocation, into: &payload)
                    guard count == payload.count, count <= entry.maximum else {
                      failEncoding(entry)
                      return
                    }
                    encoded(entry, payload: ownedEncodedPayload(payload))
                  } catch { failEncoding(entry) }
                }
                directOperation = synchronous
                operation = { invocation in synchronous(invocation) }
              }
              // A direct live ordinary caller executes this synchronous stage
              // outside every protocol/resource lock, without a new task.
              if let directOperation,
                let stage = try core.synchronousEncoderStage(context: context) {
                direct = (stage, directOperation, entry)
              } else {
                entry.work = try core.startEncoder(context: context,
                  operation: { invocation in await operation(invocation) },
                  onExit: { [self, entry] in encoderExited(entry) })
              }
            } catch {
              core.endApplicationWorker()
              throw error
            }
          } catch {
            let code: MessageStreamFailure
            if error as? SessionError == .closed || error as? ApplicationInvocationFailure == .closed { code = .closed }
            else if error is ApplicationInvocationFailure { code = .dependencyUnavailable }
            else if error is MessageCodecFailure { code = .encodeFailed }
            else { code = effectiveAdmission == .tryNow ? .wouldBlock : .resourceExhausted }
            continuation.resume(throwing: rejection(code))
            return
          }
          encoder = entry.work
          entry.continuation = continuation
          waiter.entry = entry
          entries.append(entry)
          order.append(entry)
          retainedBytes += entry.retainedBytes
          entry.timer = Task.detached { [self, entry] in
            do {
              try await ContinuousClock().sleep(until: entry.deadline)
              deadlineExpired(entry)
            } catch { }
            core.lock.withLock {
              entry.timerPending = false
              entry.timer = nil
              releaseIfFinished(entry)
            }
          }
        }
        if let (stage, operation, entry) = direct {
          operation(stage.context)
          stage.finish()
          encoderExited(entry)
        } else { encoder?.start() }
      }
    } onCancel: {
      self.core.lock.withLock {
        waiter.canceled = true
        if let entry = waiter.entry { self.cancelWait(entry) }
      }
    }
  }

  private func rejection(_ code: MessageStreamFailure) -> MessageStreamError {
    MessageStreamError(code: code, progress: MessageSendResult(
      submission: .notSubmitted, streamBytesAcceptedAtReturn: 0,
      publicationPending: false, cleanup: CleanupStatus(complete: true)))
  }

  private func progress(_ entry: Entry) -> MessageSendResult {
    let callbacks = (entry.encoderPending ? 1 : 0) + (entry.timerPending ? 1 : 0) + (entry.publisherPending ? 1 : 0)
    return MessageSendResult(
      submission: entry.accepted == 0 ? .notSubmitted : .submitted,
      streamBytesAcceptedAtReturn: entry.accepted,
      publicationPending: entry.phase != .terminal,
      cleanup: CleanupStatus(complete: callbacks == 0, cleanupIncomplete: callbacks != 0,
                             pendingCallbacks: UInt64(callbacks)))
  }

  private func resume(_ entry: Entry, code: MessageStreamFailure?) {
    guard let continuation = entry.continuation else { return }
    entry.continuation = nil
    let result = progress(entry)
    if let code { continuation.resume(throwing: MessageStreamError(code: code, progress: result)) }
    else { continuation.resume(returning: result) }
  }

  private func beginEncoding(_ entry: Entry) -> Bool {
    core.lock.withLock {
      guard entry.phase == .preparing else { return false }
      guard !closed else { finish(entry, code: .closed); return false }
      guard ContinuousClock.now < entry.deadline else {
        finish(entry, code: .deadlineExceeded)
        return false
      }
      do {
        try core.check()
        try entry.storage?.check()
        if let storage = entry.storage {
          entry.tail = try storage.executionTail()
          entry.storage = nil
        }
        return true
      }
      catch { finish(entry, code: .closed); return false }
    }
  }

  private func ownedEncodedPayload(_ payload: Data) -> Data {
    payload.withUnsafeBytes { source in
      guard let address = source.baseAddress, !source.isEmpty else { return Data() }
      return Data(bytes: address, count: source.count)
    }
  }

  private func encoded(_ entry: Entry, payload: Data) {
    core.lock.withLock {
      guard entry.phase == .preparing, !closed else { return }
      guard ContinuousClock.now < entry.deadline else { finish(entry, code: .deadlineExceeded); return }
      do { try core.check(); try entry.storage?.check() }
      catch { finish(entry, code: .closed); return }
      entry.payload = payload
      entry.payloadLength = payload.count
      entry.phase = .ready
    }
  }

  private func checkEncoding(_ entry: Entry) throws {
    guard entry.phase == .preparing, !closed else { throw MessageStreamFailure.closed }
    guard ContinuousClock.now < entry.deadline else { throw MessageStreamFailure.deadlineExceeded }
    try core.check()
    try entry.storage?.check()
  }

  private func reserveGrowth(_ entry: Entry, bytes: Int, blocks: Int) throws -> V4CryptoReservation {
    try core.lock.withLock {
      try checkEncoding(entry)
      // Retain both the native allocation and any Foundation replacement until
      // their actual owners exit. This is the same encoded-send byte cap.
      let responsibility = bytes * 2
      guard responsibility <= Self.byteCap - retainedBytes else { throw MessageStreamFailure.resourceExhausted }
      let storage = try core.reserveSegments(bytes: bytes, blocks: blocks)
      entry.retainedBytes += responsibility
      retainedBytes += responsibility
      return storage
    }
  }

  private func encoded(_ entry: Entry, segments: [V4MessageSegment], length: Int) {
    core.lock.withLock {
      do { try checkEncoding(entry) }
      catch { failEncoding(entry, error: error); return }
      entry.segments = segments
      entry.payloadLength = length
      entry.phase = .ready
    }
  }

  private func failEncoding(_ entry: Entry, error: Error? = nil) {
    core.lock.withLock {
      if entry.phase == .preparing {
        let code: MessageStreamFailure
        if let failure = error as? MessageStreamFailure { code = failure }
        else if error as? V4ResourceFailure == .capacity { code = .resourceExhausted }
        else if error as? SessionError == .timeout { code = .deadlineExceeded }
        else if error as? V4ResourceFailure == .closed || error as? SessionError == .closed { code = .closed }
        else { code = .encodeFailed }
        finish(entry, code: code)
      }
    }
  }

  private func encoderExited(_ entry: Entry) {
    core.lock.withLock {
      entry.encoderPending = false
      entry.work = nil
      // TransportEnvironment close may prevent the original callback from entering.
      if entry.phase == .preparing { finish(entry, code: .closed) }
      releaseIfFinished(entry)
      advance()
    }
  }

  private func cancelWait(_ entry: Entry) {
    if entry.phase == .terminal { resume(entry, code: entry.failure); return }
    // Once a prefix byte is accepted, only this waiter is canceled. Its
    // original publisher continues to a complete frame or the fixed deadline.
    if entry.accepted == 0 && entry.phase != .terminal {
      finish(entry, code: .canceled)
      if entry.publisherPending { entry.publisher?.cancel() }
    } else {
      resume(entry, code: entry.failure ?? .canceled)
    }
  }

  private func deadlineExpired(_ entry: Entry) {
    core.lock.withLock {
      guard entry.phase != .terminal else { return }
      let submitted = entry.accepted != 0
      finish(entry, code: .deadlineExceeded)
      entry.publisher?.cancel()
      if submitted { startReset() }
    }
  }

  private func finish(_ entry: Entry, code: MessageStreamFailure?) {
    guard entry.phase != .terminal else { return }
    entry.phase = .terminal
    entry.failure = code
    if code != nil { entry.work?.cancel() }
    order.removeAll { $0 === entry }
    entry.timer?.cancel()
    if !entry.publisherPending { entry.payload = nil; entry.segments = nil }
    // Retain encoder and provider custody; only the logical FIFO position is
    // removed. Their actual exit remains part of the finite entry capacity.
    resume(entry, code: code)
    releaseIfFinished(entry)
    advance()
  }

  private func releaseIfFinished(_ entry: Entry) {
    guard entry.phase == .terminal, !entry.encoderPending, !entry.timerPending, !entry.publisherPending,
      entries.contains(where: { $0 === entry }) else { return }
    entry.payload = nil
    entry.segments = nil
    entry.storage = nil
    entry.tail?.release(); entry.tail = nil
    retainedBytes -= entry.retainedBytes
    entries.removeAll { $0 === entry }
    core.endApplicationWorker()
  }

  private func advance() {
    guard !closed, publishing == nil else { return }
    guard let first = order.first else { startFINIfReady(); return }
    guard first.phase == .ready, !first.encoderPending else { return }
    do { try core.beginOperation() }
    catch { finish(first, code: .closed); return }
    first.phase = .publishing
    first.publisherPending = true
    publishing = first
    first.publisher = Task.detached { [self, first] in
      do {
        let candidate = core.lock.withLock { (first.payload, first.segments, first.payloadLength) }
        guard candidate.0 != nil || candidate.1 != nil else { throw SessionError.streamReset }
        let size = UInt32(candidate.2)
        let prefix = Data([
          UInt8(truncatingIfNeeded: size >> 24), UInt8(truncatingIfNeeded: size >> 16),
          UInt8(truncatingIfNeeded: size >> 8), UInt8(truncatingIfNeeded: size),
        ])
        try await publish(prefix, entry: first)
        if let payload = candidate.0 { try await publish(payload, entry: first) }
        if let segments = candidate.1 {
          for segment in segments {
            var offset = 0
            while offset < segment.used {
              let chunk = segment.copyChunk(offset: offset, maximum: 16_384)
              try await publish(chunk, entry: first)
              offset += chunk.count
            }
          }
        }
        core.lock.withLock {
          first.published = true
          finish(first, code: nil)
        }
      } catch {
        core.lock.withLock {
          let partial = first.accepted != 0
          if first.phase != .terminal {
            let failure: MessageStreamFailure
            if closed { failure = .closed }
            else if ContinuousClock.now >= first.deadline { failure = .deadlineExceeded }
            else { failure = .writeFailed }
            finish(first, code: failure)
          }
          if partial { startReset() }
        }
      }
      core.lock.withLock {
        first.publisherPending = false
        first.publisher = nil
        first.payload = nil
        first.segments = nil
        if publishing === first { publishing = nil }
        releaseIfFinished(first)
        advance()
        core.endWorker()
      }
    }
  }

  private func publish(_ bytes: Data, entry: Entry) async throws {
    var offset = 0
    while offset < bytes.count {
      let chunk = bytes.subdata(in: offset..<min(bytes.count, offset + 16_384))
      let count = try await core.writeMessageChunk(chunk, beforeAccept: { [self, entry] in
        try core.lock.withLock {
          guard !closed, entry.phase == .publishing, ContinuousClock.now < entry.deadline else {
            throw SessionError.canceled
          }
          try core.check()
        }
      }, accepted: { [self, entry] count in
        core.lock.withLock { entry.accepted += UInt64(count) }
      })
      guard count > 0, count <= chunk.count else { throw SessionError.streamReset }
      offset += count
    }
  }

  func closeWrite() async throws {
    let token = CloseWaiter()
    let deadline = ContinuousClock.now.advanced(by: timeout)
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        core.lock.withLock {
          if token.canceled || Task.isCancelled { continuation.resume(throwing: SessionError.canceled); return }
          if let result = closeResult { continuation.resume(with: result.mapError { $0 as Error }); return }
          guard !closed, closeWaiter == nil else {
            continuation.resume(throwing: closed ? SessionError.closed : SessionError.resourceExhausted)
            return
          }
          if !sealed {
            do { try core.beginOperation() }
            catch { continuation.resume(throwing: SessionError.closed); return }
            sealed = true
            closeTimer = Task.detached { [self] in
              defer { core.endWorker() }
              do {
                try await ContinuousClock().sleep(until: deadline)
                core.lock.withLock {
                  guard closeResult == nil, !closed else { return }
                  closeResult = .failure(.deadlineExceeded)
                  let pending = closeWaiter
                  closeWaiter = nil
                  pending?.continuation?.resume(throwing: MessageStreamFailure.deadlineExceeded)
                  pending?.continuation = nil
                  startReset()
                }
              } catch { }
              core.lock.withLock { closeTimer = nil }
            }
          }
          token.continuation = continuation
          closeWaiter = token
          startFINIfReady()
        }
      }
    } onCancel: {
      self.core.lock.withLock {
        token.canceled = true
        if self.closeWaiter === token {
          self.closeWaiter = nil
          token.continuation?.resume(throwing: SessionError.canceled)
          token.continuation = nil
        }
      }
    }
  }

  private func startFINIfReady() {
    guard sealed, !closed, !closeStarted, order.isEmpty, publishing == nil else { return }
    closeStarted = true
    core.retainWorker()
    closeTask = Task.detached { [self] in
      let result: Result<Void, MessageStreamFailure>
      do { try await core.closeWrite(); result = .success(()) }
      catch { result = .failure(.writeFailed) }
      core.lock.withLock {
        if closeResult == nil { closeResult = result }
        closeTimer?.cancel()
        closeTask = nil
        let waiter = closeWaiter
        closeWaiter = nil
        waiter?.continuation?.resume(with: (closeResult ?? result).mapError { $0 as Error })
        waiter?.continuation = nil
        core.endWorker()
      }
    }
  }

  func close() {
    core.lock.withLock {
      guard !closed else { return }
      closed = true
      sealed = true
      closeTask?.cancel()
      closeTimer?.cancel()
      let pending = entries
      for entry in pending {
        entry.publisher?.cancel()
        finish(entry, code: .closed)
      }
      let waiter = closeWaiter
      closeWaiter = nil
      waiter?.continuation?.resume(throwing: SessionError.closed)
      waiter?.continuation = nil
    }
  }

  private func startReset() {
    guard !resetStarted else { return }
    resetStarted = true
    close()
    core.retainWorker()
    Task.detached { [core] in
      try? await core.closeStream()
      core.endWorker()
    }
  }
}
