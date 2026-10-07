import Foundation

public struct RetainedOperationResult: Sendable {
  public let payload: Data
  public let reference: OperationReference
  public var applicationInputDelivered: Bool { false }
}

/// The fixed read method is current local service configuration. A saved
/// reference supplies only a selector, never a contract or a dispatch route.
public struct OperationResultReadBinding: Sendable {
  public let contract: ServiceContract
  public init(contract: ServiceContract) throws {
    guard contract.shape == .unary, contract.semantics == .transient,
      try contract.uint(23) >= 1024, try contract.uint(10) <= 1_048_576 else { throw ServiceFailure.contractMismatch }
    self.contract = contract
  }
}

public final class OperationResultRead: @unchecked Sendable {
  private let gate = NSLock()
  private var client: ServiceClient?
  private let binding: OperationResultReadBinding
  public let reference: OperationReference
  private let pending: V4RPCOperation
  private let channel: V4RPCChannel
  private let serial: UInt64
  private var loading = false
  private var result: Data?
  private var terminal: ServiceFailure?
  private var consumed = false
  private var closed = false
  init(client: ServiceClient, binding: OperationResultReadBinding, reference: OperationReference,
    pending: V4RPCOperation, serial: UInt64) {
    self.client = client; self.binding = binding; self.reference = reference; self.pending = pending
    channel = client.channel; self.serial = serial
  }
  public var submission: OperationSubmission { pending.headerSubmitted ? .submitted : .notSubmitted }
  public func takeEncodedResult() async throws -> RetainedOperationResult {
    let fetch = try gate.withLock { () -> Bool in
      guard !closed, !consumed, !loading else { throw ServiceFailure.closed }
      if let terminal { throw terminal }
      guard result == nil else { return false }
      loading = true; return true
    }
    if fetch {
      do {
        let received = try await pending.take()
        try gate.withLock {
          loading = false
          if received.header.kind == "read_result_sdk_error" { terminal = try binding.contract.decodeServiceFailure(received.payload) }
          else { result = received.payload }
        }
      } catch { gate.withLock { loading = false }; throw error }
    }
    return try gate.withLock {
      guard !closed, !consumed, let client = self.client else { throw ServiceFailure.closed }
      if let terminal { throw terminal }
      try client.checkReference(reference)
      guard let result else { throw ServiceFailure.closed }
      consumed = true; self.result = nil
      return RetainedOperationResult(payload: result, reference: reference)
    }
  }
  /// The fixed SDK representation is the owned original encoding. Application
  /// decoders belong to the caller's separately admitted application worker.
  public func takeResult() async throws -> RetainedOperationResult { try await takeEncodedResult() }
  public func close() {
    let owned = gate.withLock { () -> Bool in
      guard !closed else { return false }; closed = true; client = nil; result = nil; pending.abandon(); return true
    }
    if owned { Task { [channel, serial] in try? await channel.abandon(serial) } }
  }
  deinit { close() }
}

extension ServiceClient {
  public func readOperationResult(_ reference: OperationReference, binding: OperationResultReadBinding,
    deadlineAtMS: UInt64) async throws -> OperationResultRead {
    try checkReference(reference)
    guard reference.shape == .unary, session.serviceManagement != nil else { throw ServiceFailure.configurationCapacity }
    let contract = binding.contract
    try contract.checkEnvironment(environment)
    guard let now = environment.clock.sample().interval, now.upperMS < deadlineAtMS,
      deadlineAtMS - now.upperMS <= (try contract.uint(11)),
      reference.resultLimit <= (try contract.uint(10)) else { throw ServiceFailure.contractMismatch }
    let payload = reference.targetEncoded()
    let header = try V4ApplicationHeader(kind: "read_result_request", fields: [2: .uint(UInt64(contract.typeID)),
      3: .uint(UInt64(payload.count)), 5: .uint(deadlineAtMS), 6: .bytes(contract.digest)], registry: channel.registry)
    let (serial, pending) = try await channel.enqueue(header: header, payload: payload, responseCapacity: reference.resultLimit,
      expectsResponse: true, query: true, guardHeader: { [self] in
        try checkReference(reference)
        guard let interval = environment.clock.sample().interval, interval.upperMS < deadlineAtMS else { throw ServiceFailure.deadlineExceeded }
      })
    return OperationResultRead(client: self, binding: binding, reference: reference, pending: pending, serial: serial)
  }
}
