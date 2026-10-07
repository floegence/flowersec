import Testing

@testable import Flowersec

@Test
func connectionFactsFollowDurableCutpointsAndBlockUnsafeRetry() {
  let owner = V4ConnectionFacts(source: .preauthorizedPool)

  #expect(owner.snapshot().permitsAutomaticRetry)
  owner.spendDispatched()
  #expect(owner.snapshot().spendState == .unknown)
  #expect(!owner.snapshot().permitsAutomaticRetry)

  owner.spent()
  owner.admissionDispatched()
  #expect(owner.snapshot().admissionState == .inFlight)
  owner.admitted()
  owner.networkReady()

  let ready = owner.snapshot()
  #expect(ready.spendState == .spent)
  #expect(ready.admissionState == .admitted)
  #expect(ready.networkReady == .ready)
  #expect(ready.phase == .ready)
}

@Test
func failedApplicationPublicationPreservesNetworkReadyFacts() {
  let owner = V4ConnectionFacts(source: .liveAuthority)
  owner.spendDispatched()
  owner.spent()
  owner.admitted()
  owner.networkReady()
  owner.publicationFailed()

  let facts = owner.snapshot()
  #expect(facts.networkReady == .ready)
  #expect(facts.applicationPublish == .failed)
  #expect(facts.phase == .ready)
  #expect(!facts.permitsAutomaticRetry)
}

@Test
func localReportCarriesDetachedFactsAndCleanup() {
  let owner = V4ConnectionFacts(source: .preauthorizedPool)
  owner.spendDispatched()
  let facts = owner.snapshot()
  let cleanup = CleanupStatus(complete: false, pendingCallbacks: 1)
  let report = LocalReport(code: "connection_failed", connection: facts, cleanup: cleanup)

  #expect(report.connection == facts)
  #expect(report.cleanup == cleanup)
  #expect(report.reservation == .notReserved)
  #expect(report.actions == [.endConnection])
}

@Test
func nestedConnectFailurePreservesOriginalIncompleteCleanup() {
  let owner = V4ConnectionFacts(source: .preauthorizedPool)
  owner.spendDispatched()
  owner.spent()
  let original = CleanupStatus(complete: false, cleanupIncomplete: true, pendingCallbacks: 2)
  let failure = ConnectError.capture(ConnectError.connectionFailed,
    connection: owner.snapshot(), cleanup: original)
  let delivered = ConnectError.capture(failure,
    connection: owner.snapshot(), cleanup: CleanupStatus(complete: true))

  #expect(delivered.cleanup == original)
  #expect(delivered.localReport.cleanup == original)
  #expect(delivered.retryDisposition == .terminal)
  let repeated = ConnectError.capture(delivered,
    connection: owner.snapshot(), cleanup: original)
  #expect(repeated.cleanup.pendingCallbacks == 2)
}

#if os(macOS) || os(iOS)
@Test
func liveControlCancellationProjectsTerminalDispositionBeforeSpend() {
  for error in [TransportControlError.canceled, .closed] {
    let failure = ConnectError.capture(error, connection: .notStarted,
      cleanup: CleanupStatus(complete: true))
    #expect(failure.code == .connectionFailed)
    #expect(failure.retryDisposition == .terminal)
    #expect(failure.connection == .notStarted)
    #expect(failure.cleanup.complete)
  }
}

@Test
func connectFailureDeliveryRefreshesOriginalOwnerAfterCallTailExit() async {
  let owner = V4ConnectionFacts(source: .preauthorizedPool)
  owner.spendDispatched()
  owner.spent()
  let beforeExit = ConnectError.capture(ConnectError.connectionFailed,
    connection: owner.snapshot(), cleanup: CleanupStatus(complete: false, pendingCallbacks: 1))
  let projection = V4ConnectFailureProjection(failure: beforeExit,
    observeCleanup: { CleanupStatus(complete: true) })
  let delivered = await projection.delivered()

  #expect(delivered.cleanup.complete)
  #expect(!delivered.cleanup.cleanupIncomplete)
  #expect(delivered.cleanup.pendingCallbacks == 0)
  #expect(delivered.localReport.cleanup == delivered.cleanup)
  #expect(delivered.connection == beforeExit.connection)
  #expect(delivered.retryDisposition == .terminal)
}
#endif
