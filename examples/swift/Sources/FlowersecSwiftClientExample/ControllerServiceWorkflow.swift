import Flowersec
import Foundation

// The existing Controller, trusted application definition/target and contract
// source are borrowed. The caller chooses the deadline and replacement policy.
// No failed business call is repeated during the current-generation switch.
func runControllerServiceReplacement(controller: ConnectionController,
  definition: ServiceDefinition, target: ServiceBindingTarget,
  contractSource: any ServiceContractSource, deadlineAtMS: UInt64,
  retirement: ConnectionReplacementRetirement = .drain(timeout: .seconds(30)),
  consume: @Sendable (ControllerServiceClient) async throws -> Void) async throws {
  _ = try await controller.waitForSession()
  let service = try await controller.bindService(definition, target: target,
    contractSource: contractSource, deadlineAtMS: deadlineAtMS, acceptance: .exact, offerRefresh: .explicit)
  do {
    try await consume(service)
    let replacement = try await controller.replaceSession(retirement: retirement)
    guard replacement.currentSwitched else { throw ServiceFailure.serviceUnavailable }
    // Subsequent preparations select the published generation and preserve
    // each installed exact contract. Old prepared work stays on its Session.
    try await consume(service)
    if let retirement = replacement.retirement {
      let cleanup = try await retirement.wait()
      guard cleanup.cleanup.complete else { throw ServiceFailure.serviceUnavailable }
    }
    await service.close()
  } catch { await service.close(); throw error }
}
