import Foundation

/// A bounded projection of a codec's identity, independent of its callbacks
/// and of the Stream's authorization or resource graph.
public struct MessageCodecIdentity: Sendable, Equatable {
  public let schemaDigest: Data
  public let revision: String
  init(_ definition: MessageDefinition) {
    schemaDigest = definition.schemaDigest
    revision = definition.revision
  }
}

public struct MessageReceived<Value: Sendable>: Sendable {
  public let value: Value
  public let codec: MessageCodecIdentity
  public let applicationInputDelivered: Bool
}

public struct EncodedMessageReceived: Sendable {
  public let payload: Data
  public let codec: MessageCodecIdentity
  public var applicationInputDelivered: Bool { false }
}

public struct MessageReceiveError: Error, Sendable {
  public let code: MessageCodecFailure
  public let codec: MessageCodecIdentity
  public let applicationInputDelivered: Bool
}

public struct MessageResultModeConflict: Error, Sendable, Equatable {
  public enum Cause: String, Sendable { case decoderStarted = "decoder_started" }
  public let cause: Cause
  public let applicationInputDelivered: Bool
  init() { cause = .decoderStarted; applicationInputDelivered = true }
}

// One current message owns one decoder completion. Canceling a receiver does
// not consume an outcome or rerun application code; it only removes its waiter.
final class V4MessageCompletion<Value: Sendable>: V4CompletionWork, @unchecked Sendable {
  private final class Waiter: @unchecked Sendable {
    var canceled = false
    var committed = false
    let context: ApplicationInvocationContext?
    var continuation: CheckedContinuation<MessageReceived<Value>, Error>?
    init(context: ApplicationInvocationContext?) { self.context = context }
  }
  let group: V4ApplicationGroup
  var order: UInt64 = 0
  private var encoded: Data?
  private var storage: V4CryptoReservation?
  private var bodyTail: V4ResourceReference?
  private var descriptor: V4ResourceReference?
  private var ownsDescriptor = true
  private var prepaidOwner: V4ServiceUnaryClaim?
  private var bindingTail: V4ServiceBindingTail?
  private var codec: (any MessageCodec<Value>)?
  private let codecIdentity: MessageCodecIdentity
  private let controlled: Bool
  private var sourceCheck: (@Sendable () throws -> Void)?
  private var onRelease: (@Sendable () -> Void)?
  private var prepaidCompletion: V4CompletionReservation?
  private var onInput: (@Sendable (V4ApplicationInvocation) -> Void)?
  private var onInputExit: (@Sendable (V4ApplicationInvocation) -> Void)?
  private var waiter: Waiter?
  private var job: Task<Void, Never>?
  private var permitWaiter: CheckedContinuation<V4ApplicationPermit?, Never>?
  private var granted: V4ApplicationPermit?
  private var invocation: V4ApplicationInvocation?
  private var outcome: Result<Value, MessageCodecFailure>?
  private var closed = false
  private var consumed = false
  private var inputDelivered = false
  private var started = false
  private var released = false
  private var selected = false
  private var pending = false
  private var serviceClaim: V4CompletionClaim?
  private var registration: V4CompletionRegistration?
  private var dispatchGeneration: UInt64 = 0
  private var gate: NSRecursiveLock { group.executor.gate }

  init(
    group: V4ApplicationGroup, bytes: Int,
    codec: any MessageCodec<Value>, definition: MessageDefinition, context: ApplicationInvocationContext?, sourceCheck: @escaping @Sendable () throws -> Void,
    onInput: @escaping @Sendable (V4ApplicationInvocation) -> Void,
    onInputExit: @escaping @Sendable (V4ApplicationInvocation) -> Void,
    onRelease: @escaping @Sendable () -> Void, prepaid: V4ServiceUnaryClaim? = nil,
    bindingTail: V4ServiceBindingTail? = nil, prepaidCompletion: V4CompletionReservation? = nil
  ) throws {
    self.group = group; self.codec = codec
    codecIdentity = MessageCodecIdentity(definition)
    controlled = codec is BytesMessageCodec || codec is UTF8MessageCodec
    self.sourceCheck = sourceCheck
    self.onInput = onInput; self.onInputExit = onInputExit
    ownsDescriptor = prepaid == nil; prepaidOwner = prepaid; self.bindingTail = bindingTail
    self.prepaidCompletion = prepaidCompletion
    descriptor = try prepaid?.target.descriptor ?? group.reserveCompletion(bytes: bytes)
    do {
      if let context { serviceClaim = try group.executor.claim(group: group, context: context) }
      registration = try group.executor.register(self, reservation: prepaid?.target.completion ?? prepaidCompletion)
      self.onRelease = onRelease
    } catch {
      serviceClaim?.release(); serviceClaim = nil
      if ownsDescriptor { descriptor?.release() }; descriptor = nil
      self.prepaidCompletion = nil
      throw error
    }
  }

  var eligible: Bool {
    !closed && !consumed && !started && encoded != nil && waiter != nil && (pending || dispatchGeneration < .max)
  }
  var jobPending: Bool { pending }
  var ready: Bool { selected }
  var claim: V4CompletionClaim? { serviceClaim }
  var applicationInputDelivered: Bool { gate.withLock { inputDelivered } }
  var deliveryCommitted: Bool { gate.withLock { consumed } }

  func bind(encoded: Data, storage: V4CryptoReservation) throws {
    try gate.withLock {
      guard !closed, !consumed, self.encoded == nil, !started else { throw SessionError.closed }
      try sourceCheck?()
      self.encoded = encoded
      self.storage = storage
    }
  }

  func knownDependency(_ context: ApplicationInvocationContext?) throws -> Bool {
    try group.executor.depends(context, on: gate.withLock { invocation })
  }

  func take(context: ApplicationInvocationContext?) async throws -> MessageReceived<Value> {
    let token = Waiter(context: context)
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        gate.withLock {
          if token.canceled || Task.isCancelled {
            if !started { serviceClaim?.release(); serviceClaim = nil }
            continuation.resume(throwing: SessionError.canceled)
            return
          }
          guard !closed, !consumed else { continuation.resume(throwing: SessionError.closed); return }
          guard started || pending || dispatchGeneration < .max else {
            continuation.resume(throwing: V4ResourceFailure.capacity); return
          }
          guard waiter == nil else {
            continuation.resume(throwing: ReadMethodFailure(reason: .readInProgress, cursor: nil)); return
          }
          do {
            if try group.executor.depends(context, on: invocation) {
              throw ApplicationInvocationFailure.knownApplicationDependency
            }
            if !inputDelivered { try sourceCheck?() }
            if !started, serviceClaim?.active != true, let context {
              serviceClaim = try group.executor.claim(group: group, context: context)
            }
          } catch {
            if !started { serviceClaim?.release(); serviceClaim = nil }
            continuation.resume(throwing: error)
            return
          }
          token.continuation = continuation
          waiter = token
          deliverIfReady()
        }
        group.executor.schedule()
      }
    } onCancel: {
      self.gate.withLock {
        guard !token.committed else { return }
        token.canceled = true
        guard self.waiter === token else { return }
        self.waiter = nil
        let continuation = token.continuation
        token.continuation = nil
        if !self.started {
          self.serviceClaim?.release()
          self.serviceClaim = nil
          self.stopReady()
        }
        continuation?.resume(throwing: SessionError.canceled)
      }
    }
  }

  func takeEncoded(context: ApplicationInvocationContext?) throws -> Data {
    try gate.withLock {
      guard !closed, !consumed else { throw SessionError.closed }
      if try group.executor.depends(context, on: invocation) {
        throw ApplicationInvocationFailure.knownApplicationDependency
      }
      try context?.checkCancellation()
      guard !inputDelivered else { throw MessageResultModeConflict() }
      try sourceCheck?()
      guard let encoded else { throw SessionError.closed }
      // A private SDK decoder may still borrow the original bytes. The full
      // encoded/typed overlap is already reserved; return a separate backing.
      let bytes = encoded.withUnsafeBytes { source -> Data in
        guard let address = source.baseAddress, !source.isEmpty else { return Data() }
        return Data(bytes: address, count: source.count)
      }
      consumed = true
      outcome = nil
      serviceClaim?.release(); serviceClaim = nil
      stopReady()
      releaseIfFinished()
      return bytes
    }
  }

  func selectReady() { dispatchGeneration += 1; selected = true; pending = true }
  func selectClaimed() { dispatchGeneration += 1; selected = false; pending = true }
  func startJob() {
    let generation = gate.withLock { dispatchGeneration }
    let task = Task.detached { [self] in
      let permit = await acquirePermit()
      if let permit { await execute(permit) }
      gate.withLock {
        pending = false
        job = nil
        deliverIfReady()
        releaseIfFinished()
      }
      group.executor.schedule()
    }
    gate.withLock { if pending && dispatchGeneration == generation { job = task } }
  }

  private func acquirePermit() async -> V4ApplicationPermit? {
    await withCheckedContinuation { continuation in
      gate.withLock {
        if let granted {
          self.granted = nil
          continuation.resume(returning: granted)
          return
        }
        guard selected, eligible else {
          stopReady()
          continuation.resume(returning: nil)
          return
        }
        if let permit = group.executor.enter(self) {
          selected = false
          continuation.resume(returning: permit)
        } else { permitWaiter = continuation }
      }
    }
  }

  func grant(_ permit: V4ApplicationPermit) {
    selected = false
    if serviceClaim?.active == false { serviceClaim = nil }
    if let continuation = permitWaiter {
      permitWaiter = nil
      continuation.resume(returning: permit)
    } else { granted = permit }
  }

  private func stopReady() {
    if selected {
      group.executor.leaveReady(self)
      selected = false
    }
    if let granted { self.granted = nil; granted.release() }
    let waiting = permitWaiter
    permitWaiter = nil
    waiting?.resume(returning: nil)
  }

  private func execute(_ permit: V4ApplicationPermit) async {
    let input: (Data, ApplicationInvocationContext)? = gate.withLock {
      guard eligible, let encoded else { permit.release(); return nil }
      do {
        if let context = waiter?.context { try context.checkCancellation() }
        try sourceCheck?()
        let state = V4ApplicationInvocation(permit: permit, ancestors: permit.ancestors)
        if !controlled {
          if prepaidOwner == nil { bodyTail = try storage?.executionTail() }
          storage = nil
          sourceCheck = nil
          inputDelivered = true
        }
        invocation = state
        onInput?(state)
        started = true
        return (encoded, ApplicationInvocationContext(state))
      } catch {
        permit.release()
        let original = waiter
        waiter = nil
        let waiting = original?.continuation
        original?.continuation = nil
        waiting?.resume(throwing: error)
        return nil
      }
    }
    guard let (input, context) = input, let codec = gate.withLock({ self.codec }) else { return }
    let result: Result<Value, MessageCodecFailure>
    do {
      if let asynchronous = codec as? any AsyncMessageCodec<Value> {
        result = .success(try await asynchronous.decodeAsync(input, context: context))
      } else { result = .success(try codec.decode(input, context: context)) }
    } catch { result = .failure(.decodeFailed) }
    // The actual application function has returned before the permit is
    // released. Only bounded SDK bookkeeping and handoff remain afterwards.
    gate.withLock { onInputExit?(context.invocation) }
    context.invocation.close()
    gate.withLock {
      invocation = nil
      if !closed, !consumed { outcome = result }
    }
  }

  private func deliverIfReady() {
    guard !pending, !closed, !consumed, let outcome, let token = waiter,
      !token.canceled, let continuation = token.continuation else { return }
    if !inputDelivered {
      do { try sourceCheck?() }
      catch {
        waiter = nil
        token.continuation = nil
        continuation.resume(throwing: error)
        return
      }
    }
    // CheckedContinuation.resume is this runtime's irreversible owned handoff.
    // A later cancellation or Close cannot give this value to another waiter.
    consumed = true
    token.committed = true
    token.continuation = nil
    waiter = nil
    self.outcome = nil
    continuation.resume(with: outcome.map {
      MessageReceived(value: $0, codec: codecIdentity, applicationInputDelivered: inputDelivered)
    }.mapError {
      MessageReceiveError(code: $0, codec: codecIdentity, applicationInputDelivered: inputDelivered) as Error
    })
    releaseIfFinished()
  }

  func cancelBeforeInput() {
    guard !started else { return }
    let token = waiter
    waiter = nil
    token?.continuation?.resume(throwing: SessionError.closed)
    token?.continuation = nil
    serviceClaim?.release(); serviceClaim = nil
    stopReady()
  }

  func close() {
    gate.withLock {
      guard !closed else { return }
      closed = true
      outcome = nil
      invocation?.canceled = true
      let token = waiter
      waiter = nil
      token?.continuation?.resume(throwing: SessionError.closed)
      token?.continuation = nil
      serviceClaim?.release(); serviceClaim = nil
      stopReady()
      job?.cancel()
      releaseIfFinished()
    }
  }

  private func releaseIfFinished() {
    guard !released, !pending, consumed || closed else { return }
    released = true
    encoded = nil
    codec = nil
    storage = nil
    bodyTail?.release(); bodyTail = nil
    if ownsDescriptor { descriptor?.release() }; descriptor = nil
    sourceCheck = nil
    onInput = nil; onInputExit = nil
    if let registration {
      group.executor.unregister(registration, group: group)
      self.registration = nil
    }
    self.prepaidCompletion = nil
    let onRelease = self.onRelease
    self.onRelease = nil
    onRelease?(); prepaidOwner = nil; bindingTail = nil
  }

  deinit {
    // Owner Close is the normal path; retain fallbacks for construction/drop
    // before a waiter was installed. Running jobs retain this same owner.
    if !released {
      if let registration { group.executor.unregister(registration, group: group) }
      bodyTail?.release(); if ownsDescriptor { descriptor?.release() }
      onRelease?()
    }
  }
}
