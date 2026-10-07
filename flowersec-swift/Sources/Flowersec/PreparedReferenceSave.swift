import Foundation

public struct PreparedAndSavedNotification: Sendable {
  public let status: OperationPreparationStatus
  public let operation: ServiceNotificationOperation?
  public let reference: OperationReference
  public let save: ReferenceSaveOutcome
  public let saveAttempted: Bool
}
public struct PreparedAndSavedStream<Item: Sendable>: Sendable {
  public let status: OperationPreparationStatus
  public let operation: ServiceStreamingOperation<Item>?
  public let reference: OperationReference
  public let save: ReferenceSaveOutcome
  public let saveAttempted: Bool
}
public struct PreparedAndSavedResume: Sendable {
  public let status: OperationPreparationStatus
  public let operation: ServiceResumeOperation?
  public let reference: OperationReference
  public let save: ReferenceSaveOutcome
  public let saveAttempted: Bool
}
private final class V4PreparedSaveReceipt: @unchecked Sendable {
  private let gate = NSLock()
  private var entered = false
  private var result: ReferenceSaveOutcome?
  func enter() { gate.withLock { entered = true } }
  func record(_ value: ReferenceSaveOutcome) { gate.withLock { result = value } }
  var observation: (ReferenceSaveOutcome, Bool) { gate.withLock { (result ?? (entered ? .saveUnknown : .notSaved), entered) } }
}
extension ServiceClient {
  private func savePreparedReference(_ reference: OperationReference, store: any OperationReferenceStore,
    options: ServiceCallOptions) async -> (ReferenceSaveOutcome, Bool, Bool) {
    let receipt = V4PreparedSaveReceipt()
    do {
      let storage = try environment.operationReferenceStorage()
      let tail = V4ServiceInputTail(try storage.executionTail())
      _ = try await group.invoke(context: options.context) { context in
        defer { withExtendedLifetime(tail) {} }
        try context.checkCancellation(); receipt.enter()
        let outcome: ReferenceSaveOutcome
        do { outcome = try await store.save(reference, context: context) } catch { outcome = .saveUnknown }
        receipt.record(outcome); return outcome
      }
    } catch { }
    let (outcome, attempted) = receipt.observation
    return (outcome, attempted, Task.isCancelled || options.context?.isCancelled == true)
  }
  public func prepareNotifyAndSave<Request: Sendable>(_ method: MethodDefinition, request: Request,
    codec: any MessageCodec<Request>, store: any OperationReferenceStore, options: ServiceCallOptions) async throws -> PreparedAndSavedNotification {
    guard method.semantics == .execution, store.targetDomain == target.authority else { throw ServiceFailure.configurationCapacity }
    let operation = try await prepareNotify(method, request: request, codec: codec, options: options)
    guard let reference = operation.reference else { operation.close(); throw ServiceFailure.configurationCapacity }
    let (save, attempted, canceled) = await savePreparedReference(reference, store: store, options: options)
    let status: OperationPreparationStatus = canceled ? .canceled : operation.preparationExpired ? .expired : save == .saved ? .prepared : .saveFailed
    if status != .prepared { operation.close() }
    return PreparedAndSavedNotification(status: status, operation: status == .prepared ? operation : nil,
      reference: reference, save: save, saveAttempted: attempted)
  }
  public func prepareStreamAndSave<Request: Sendable, Item: Sendable>(_ method: MethodDefinition, request: Request,
    requestCodec: any MessageCodec<Request>, itemCodec: any MessageCodec<Item>, store: any OperationReferenceStore,
    options: ServiceCallOptions) async throws -> PreparedAndSavedStream<Item> {
    guard method.semantics == .execution, store.targetDomain == target.authority else { throw ServiceFailure.configurationCapacity }
    let operation = try await prepareStream(method, request: request, requestCodec: requestCodec, itemCodec: itemCodec, options: options)
    guard let reference = operation.reference else { operation.close(); throw ServiceFailure.configurationCapacity }
    let (save, attempted, canceled) = await savePreparedReference(reference, store: store, options: options)
    let status: OperationPreparationStatus = canceled ? .canceled : operation.preparationExpired ? .expired : save == .saved ? .prepared : .saveFailed
    if status != .prepared { operation.close() }
    return PreparedAndSavedStream(status: status, operation: status == .prepared ? operation : nil,
      reference: reference, save: save, saveAttempted: attempted)
  }
  public func prepareResumeAndSave(_ method: MethodDefinition, token: ApplicationCheckpointToken,
    target: ServiceResumeTarget, store: any OperationReferenceStore, options: ServiceCallOptions) async throws -> PreparedAndSavedResume {
    guard store.targetDomain == self.target.authority else { throw ServiceFailure.configurationCapacity }
    let operation = try prepareResume(method, token: token, target: target, options: options)
    let reference = operation.reference
    let (save, attempted, canceled) = await savePreparedReference(reference, store: store, options: options)
    let status: OperationPreparationStatus = canceled ? .canceled : operation.preparationExpired ? .expired : save == .saved ? .prepared : .saveFailed
    if status != .prepared { operation.close() }
    return PreparedAndSavedResume(status: status, operation: status == .prepared ? operation : nil,
      reference: reference, save: save, saveAttempted: attempted)
  }
}
