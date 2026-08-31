import Testing

@testable import Flowersec

struct RetryDispositionContractTests {
  @Test func currentFailuresExposeOneConsistentRetryContract() {
    #expect(ConnectError.artifactInvalid.retryDisposition == .terminal)
    #expect(ConnectError.expiredArtifact.retryDisposition == .retryable)
    #expect(ConnectError.transportSecurityUnsupported.retryDisposition == .terminal)
    #expect(ConnectError.transportSecurityFailed.retryDisposition == .terminal)
    #expect(ConnectError.connectionFailed.retryDisposition == .retryable)

    #expect(SessionError.canceled.retryDisposition == .terminal)
    #expect(SessionError.operationFailed.retryDisposition == .terminal)
    #expect(SessionError.closed.retryDisposition == .retryable)
    #expect(SessionError.timeout.retryDisposition == .retryable)
  }

  @Test func retryAfterPreservesTheAbsoluteNotBeforeDeadline() {
    let deadline: UInt64 = 2_000_000_000_000
    let failure = ArtifactSourceFailure(disposition: .retryAfter(deadline))
    #expect(failure.disposition == .retryAfter(deadline))
  }
}
