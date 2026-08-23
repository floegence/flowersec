import Foundation
import XCTest

@testable import Flowersec

final class ConnectionControllerTests: XCTestCase {
  func testTopLevelControllerVectorsBindProductionResultsRetryAndLeaseState() async throws {
    let root = try controllerVectorsV3()
    let rows = try XCTUnwrap(root["internal_transport_results"] as? [[Any]])
    let expectedActions = [
      "invalid_artifact/": "terminal",
      "expired_artifact/": "acquire_primary",
      "tls_unsupported/": "skip_candidate",
      "tls_policy_expired/": "policy_refresh",
      "tls_failed/ca_untrusted": "candidate_terminal",
      "tls_failed/pin_mismatch": "policy_refresh",
      "tls_failed/unknown": "policy_refresh_for_pin",
      "connection_failed/browser_pin_opaque": "policy_sensitive_replacement",
    ]
    let projections: [String: ConnectError] = [
      "invalid_artifact": .artifactInvalid,
      "expired_artifact": .expiredArtifact,
      "tls_unsupported": .transportSecurityUnsupported,
      "tls_policy_expired": .transportSecurityFailed,
      "tls_failed": .transportSecurityFailed,
      "connection_failed": .connectionFailed,
    ]
    var seen = Set<String>()
    for row in rows {
      XCTAssertEqual(row.count, 3)
      let code = try XCTUnwrap(row[0] as? String)
      let detail = row[1] as? String
      let action = try XCTUnwrap(row[2] as? String)
      let key = "\(code)/\(detail ?? "")"
      XCTAssertEqual(action, expectedActions[key], key)
      XCTAssertTrue(seen.insert(key).inserted, "duplicate internal result \(key)")
      let projected = try XCTUnwrap(projections[code])
      switch code {
      case "expired_artifact", "connection_failed":
        XCTAssertEqual(projected.retryDispositionV3, .retryable, key)
      default:
        XCTAssertEqual(projected.retryDispositionV3, .terminal, key)
      }
    }
    XCTAssertEqual(seen, Set(expectedActions.keys))

    let retryAfter = try XCTUnwrap(root["retry_after"] as? [String: Any])
    let valid = try XCTUnwrap(retryAfter["valid"] as? [NSNumber])
    let invalid = try XCTUnwrap(retryAfter["invalid"] as? [Any])
    XCTAssertEqual(retryAfter["aggregate"] as? String, "maximum_absolute_unix_ms")
    for value in valid {
      XCTAssertTrue(validRetryAfterVectorValue(value), "valid retry_after \(value)")
      XCTAssertEqual(
        RetryDispositionV3.retryAfter(value.uint64Value),
        .retryAfter(value.uint64Value))
    }
    XCTAssertEqual(valid.map(\.uint64Value).max(), 253_402_300_799_999)
    for value in invalid {
      XCTAssertFalse(validRetryAfterVectorValue(value), "invalid retry_after \(value)")
    }

    let leaseMachine = try XCTUnwrap(root["lease_state_machine"] as? [String: Any])
    XCTAssertEqual(
      leaseMachine["states"] as? [String],
      ["idle", "claimed", "spending", "consumed", "retired"])
    XCTAssertEqual(
      leaseMachine["transitions"] as? [[String]],
      [
        ["idle", "claimed", "claim"],
        ["claimed", "spending", "commitSpend"],
        ["spending", "consumed", "durable_result"],
        ["claimed", "retired", "retire"],
      ])
    XCTAssertEqual(leaseMachine["terminal_states"] as? [String], ["consumed", "retired"])

    let spends = AsyncCounterV3()
    let spendingLease = ArtifactLeaseV3(
      artifact: try artifactV3(), commitSpend: { _ = await spends.increment() })
    let spendingCopy = spendingLease
    let spendClaim = try await spendingLease.claim()
    try await spendClaim.commitSpend()
    let consumed = await spendClaim.isConsumed
    let spendCount = await spends.value
    XCTAssertTrue(consumed)
    XCTAssertEqual(spendCount, 1)
    await assertThrowsArtifactLeaseUnavailable { try await spendingCopy.claim() }

    let retires = AsyncCounterV3()
    let retiringLease = ArtifactLeaseV3(
      artifact: try artifactV3(), commitSpend: {}, retire: { _ = await retires.increment() })
    let retiringCopy = retiringLease
    try await retiringLease.claim().retire()
    let retireCount = await retires.value
    XCTAssertEqual(retireCount, 1)
    await assertThrowsArtifactLeaseUnavailable { try await retiringCopy.claim() }
  }

  func testControllerClaimOwnsTheSharedOneShotLease() async throws {
    let spent = AsyncCounterV3()
    let lease = ArtifactLeaseV3(
      artifact: try artifactV3(),
      commitSpend: { _ = await spent.increment() })
    let oneShotCopy = lease
    let controllerClaim = try await lease.claimForConnectionController()

    do {
      _ = try await oneShotCopy.claim()
      XCTFail("one-shot copy claimed a controller-owned lease")
    } catch {
      XCTAssertEqual(error as? ArtifactLeaseErrorV3, .unavailable)
    }
    let connectorLease = controllerClaim.connectorLease()
    let connectorCopy = connectorLease
    let connectorClaim = try await connectorLease.claim()
    do {
      _ = try await connectorCopy.claim()
      XCTFail("a second connector claim succeeded")
    } catch {
      XCTAssertEqual(error as? ArtifactLeaseErrorV3, .unavailable)
    }
    try await connectorClaim.commitSpend()
    let spendCount = await spent.value
    XCTAssertEqual(spendCount, 1)
  }

  func testControllerAndOneShotClaimsHaveExactlyOneConcurrentWinner() async throws {
    let lease = ArtifactLeaseV3(artifact: try artifactV3(), commitSpend: {})
    let controllerTask = Task { try await lease.claimForConnectionController() }
    let oneShotTask = Task { try await lease.claim() }
    let controller = await controllerTask.result
    let oneShot = await oneShotTask.result

    let winners = [controller, oneShot].filter {
      if case .success = $0 { return true }
      return false
    }
    XCTAssertEqual(winners.count, 1)
    if case .success(let claimed) = controller { try await claimed.retire() }
    if case .success(let claimed) = oneShot { try await claimed.retire() }
  }

  func testCloseCancelsBlockedRetirementWithoutPublishingRetryState() async throws {
    let retireGate = CancellationAwareRetireGateV3()
    let lease = ArtifactLeaseV3(
      artifact: try artifactV3(),
      commitSpend: {},
      retire: { try await retireGate.wait() }
    )
    let controller = try ConnectionController(
      source: SequenceArtifactSourceV3([lease]),
      connectOneShot: { _, _ in throw ConnectError.connectionFailed }
    )
    await controller.start()
    let retireStarted = await retireGate.waitUntilEntered()
    XCTAssertTrue(retireStarted)

    let closeCompleted = AsyncFlagV3()
    let closing = Task {
      await controller.close()
      await closeCompleted.set()
    }
    let bounded = await waitUntilV3(timeout: .milliseconds(500)) {
      await closeCompleted.value
    }
    XCTAssertTrue(bounded)
    await closing.value

    let snapshot = await controller.snapshot()
    let retirementCancelled = await retireGate.cancelled
    XCTAssertEqual(snapshot.state, .closed)
    XCTAssertNil(snapshot.retryDisposition)
    XCTAssertTrue(retirementCancelled)
  }

  func testSpendCancellationDoesNotWaitForUncooperativeCallback() async throws {
    let gate = UncooperativeSpendGateV3()
    let lease = ArtifactLeaseV3(
      artifact: try artifactV3(),
      commitSpend: { await gate.wait() })
    let claimed = try await lease.claim()
    let finished = AsyncFlagV3()
    let cancellationObserved = AsyncFlagV3()
    let spending = Task {
      do {
        try await claimed.commitSpend()
      } catch is CancellationError {
        await cancellationObserved.set()
      } catch {
        XCTFail("unexpected spend error: \(error)")
      }
      await finished.set()
    }

    let spendStarted = await waitUntilV3 { await gate.started }
    XCTAssertTrue(spendStarted)
    let spendingState = await claimed.isSpending
    XCTAssertTrue(spendingState)
    spending.cancel()
    let returnedBeforeRelease = await waitUntilV3(timeout: .milliseconds(500)) {
      await finished.value
    }
    let canceledBeforeRelease = await cancellationObserved.value
    let consumedBeforeRelease = await claimed.isConsumed
    await gate.release()
    _ = await spending.result

    XCTAssertTrue(returnedBeforeRelease)
    XCTAssertTrue(canceledBeforeRelease)
    XCTAssertTrue(consumedBeforeRelease)
    do {
      _ = try await lease.claim()
      XCTFail("a canceled spend must leave the lease unavailable")
    } catch {
      XCTAssertEqual(error as? ArtifactLeaseErrorV3, .unavailable)
    }
  }

  func testCloseDoesNotWaitForUncooperativeSpendCallback() async throws {
    let gate = UncooperativeSpendGateV3()
    let cancellationObserved = AsyncFlagV3()
    let tracked = ArtifactLeaseV3(
      artifact: try artifactV3(),
      commitSpend: { await gate.wait() })
    let source = SequenceArtifactSourceV3([tracked])
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { lease, _ in
        let claimed = try await lease.claim()
        do {
          try await claimed.commitSpend()
        } catch is CancellationError {
          await cancellationObserved.set()
          throw CancellationError()
        }
        return ControllerSessionV3()
      })
    await controller.start()
    let spendStarted = await waitUntilV3 { await gate.started }
    XCTAssertTrue(spendStarted)

    let closeFinished = AsyncFlagV3()
    let closing = Task {
      await controller.close()
      await closeFinished.set()
    }
    let returnedBeforeRelease = await waitUntilV3(timeout: .milliseconds(500)) {
      await closeFinished.value
    }
    let canceledBeforeRelease = await cancellationObserved.value
    let snapshotBeforeRelease = await controller.snapshot()
    await gate.release()
    await closing.value

    XCTAssertTrue(returnedBeforeRelease)
    XCTAssertTrue(canceledBeforeRelease)
    XCTAssertEqual(snapshotBeforeRelease.state, .closed)
    do {
      _ = try await tracked.claim()
      XCTFail("the spend attempt must consume the controller lease")
    } catch {
      XCTAssertEqual(error as? ArtifactLeaseErrorV3, .unavailable)
    }
  }

  func testV3ControllerVectorsAndBackoffAreOwnedByTheDefaultController() throws {
    let root = try controllerVectorsV3()
    XCTAssertEqual(root["version"] as? Int, 3)
    XCTAssertEqual(
      root["public_errors"] as? [String],
      ConnectErrorCode.allCases.map(\.rawValue))
    let defaults = try XCTUnwrap(root["defaults"] as? [String: Any])
    XCTAssertEqual(defaults["initial_backoff_ms"] as? Int, 250)
    XCTAssertEqual(defaults["maximum_backoff_ms"] as? Int, 30_000)
    XCTAssertEqual(defaults["maximum_policy_sensitive_replacement_leases_per_cycle"] as? Int, 1)
    let vectors = try XCTUnwrap(root["backoff_vectors"] as? [[String: Any]])
    XCTAssertEqual(
      vectors.map { $0["delay_ms"] as! Int },
      [250, 500, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000, 30_000, 30_000, 30_000]
    )
    let scenarios = try XCTUnwrap(root["scenarios"] as? [[String: Any]])
    XCTAssertFalse(scenarios.isEmpty)
    var ids = Set<String>()
    for scenario in scenarios {
      let id = try XCTUnwrap(scenario["id"] as? String)
      XCTAssertTrue(ids.insert(id).inserted, "duplicate controller scenario \(id)")
      let driver = try XCTUnwrap(scenario["driver"] as? String)
      switch driver {
      case "policy-replacement", "candidate-capability-filter", "replacement-expiry",
        "replacement-acquisition", "post-spend-retry", "lease-cancel-race",
        "attempt-exhaustion", "retry-after-clock",
        "candidate-failure-aggregation", "failure-ordinal", "expiry-boundary", "cycle-reset",
        "cycle-reset-terminal",
        "retry-clock-boundary", "candidate-security-aggregation", "multi-trigger-replacement",
        "retire-cleanup", "quota-preservation", "attempt-saturation", "capability-barrier",
        "admission-spend-boundary", "duplicate-lease-identity":
        break
      default: XCTFail("unknown controller vector driver \(driver)")
      }
      XCTAssertFalse(try XCTUnwrap(scenario["steps"] as? [String]).isEmpty)
      _ = try XCTUnwrap(scenario["input"] as? [String: Any])
      let expected = try XCTUnwrap(scenario["expected"] as? [String: Any])
      let required: Set<String> = [
        "final_state", "public_error", "disposition", "acquisitions", "connect_attempts",
        "transports_created", "replacement_acquisitions", "replacement_quota_used",
        "spend_callbacks", "retire_callbacks", "lease_terminal_states", "retry_delays_ms",
      ]
      XCTAssertTrue(required.isSubset(of: Set(expected.keys)), "\(id) missing expected fields")
      let acquisitions = try XCTUnwrap(expected["acquisitions"] as? Int)
      let connectAttempts = try XCTUnwrap(expected["connect_attempts"] as? Int)
      let transports = try XCTUnwrap(expected["transports_created"] as? Int)
      let replacements = try XCTUnwrap(expected["replacement_acquisitions"] as? Int)
      let quota = try XCTUnwrap(expected["replacement_quota_used"] as? Int)
      let spends = try XCTUnwrap(expected["spend_callbacks"] as? Int)
      let retires = try XCTUnwrap(expected["retire_callbacks"] as? Int)
      let terminal = try XCTUnwrap(expected["lease_terminal_states"] as? [String])
      XCTAssertLessThanOrEqual(transports, connectAttempts)
      XCTAssertLessThanOrEqual(replacements, acquisitions)
      XCTAssertLessThanOrEqual(quota, replacements)
      XCTAssertEqual(terminal.count, spends + retires)
      XCTAssertTrue(terminal.allSatisfy { $0 == "consumed" || $0 == "retired" })
      for delay in try XCTUnwrap(expected["retry_delays_ms"] as? [Int]) {
        XCTAssertTrue(vectors.contains { $0["delay_ms"] as? Int == delay } || delay == 1)
      }
      for key in Set(expected.keys).subtracting(required) {
        switch key {
        case "no_mode_downgrade", "blocked_policy_remains_blocked", "order_independent",
          "counter_saturated", "capability_rechecked", "cleanup_error_ignored", "timer_saturated",
          "source_cancellation_propagated", "close_waits_for_acquire_settlement":
          XCTAssertEqual(expected[key] as? Bool, true, "\(id) has invalid \(key)")
        case "tls_error_claimed", "retry_now_allowed_before_deadline":
          _ = try XCTUnwrap(expected[key] as? Bool)
        case "wall_end_ms", "monotonic_end_ms", "attempt", "credential_bytes_written",
          "failure_ordinal", "maximum_wall_reread_ms":
          _ = try XCTUnwrap(expected[key] as? Int)
        default: XCTFail("\(id) has unknown expected field \(key)")
        }
      }
    }
  }

  func testPinMismatchUsesOneChangedPinReplacementAndEstablishes() async throws {
    let expected = try controllerExpectedV3("pin-mismatch-changed-pin-success")
    let retired = AsyncCounterV3()
    let spent = AsyncCounterV3()
    let primary = try lease(artifact: artifactV3(), spent: spent, retired: retired)
    let replacement = try lease(artifact: changedPinArtifactV3(), spent: spent, retired: retired)
    let source = SequenceArtifactSourceV3([primary, replacement])
    let attempts = AsyncCounterV3()
    let session = ControllerSessionV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { lease, _ in
        if await attempts.increment() == 1 { throw nativePinFailureV3() }
        let claimed = try await lease.claim()
        try await claimed.commitSpend()
        return session
      }
    )
    await controller.start()
    let connected = await waitForState(.connected, controller: controller)
    let acquisitions = await source.acquisitions
    let retirements = await retired.value
    let spends = await spent.value
    let connectAttempts = await attempts.value
    XCTAssertTrue(connected)
    XCTAssertEqual(expected["final_state"] as? String, "connected")
    XCTAssertEqual(acquisitions, expected["acquisitions"] as? Int)
    XCTAssertEqual(connectAttempts, expected["connect_attempts"] as? Int)
    XCTAssertEqual(connectAttempts, expected["transports_created"] as? Int)
    XCTAssertEqual(expected["replacement_acquisitions"] as? Int, 1)
    XCTAssertEqual(expected["replacement_quota_used"] as? Int, 1)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int)
    XCTAssertEqual(spends, expected["spend_callbacks"] as? Int)
    XCTAssertEqual(expected["lease_terminal_states"] as? [String], ["retired", "consumed"])
    XCTAssertEqual(expected["retry_delays_ms"] as? [Int], [])
    XCTAssertTrue(expected["public_error"] is NSNull)
    XCTAssertTrue(expected["disposition"] is NSNull)
    await controller.close()
  }

  func testReplacementPreSpendFailurePreservesPrimarySecurityTrigger() async throws {
    let retired = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), retired: retired),
      try lease(artifact: changedPinArtifactV3(), retired: retired),
    ])
    let calls = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { _, _ in
        if await calls.increment() == 1 {
          throw ControllerConnectFailureV3.connection(
            .transportSecurityFailed, .retryable,
            policyTriggerIDs: ["w-pin"], opaquePolicyTriggerIDs: [], failedIDs: ["w-pin"])
        }
        throw ConnectError.connectionFailed
      }
    )

    await controller.start()
    let failed = await waitForState(.failed, controller: controller)
    let snapshot = await controller.snapshot()
    let retirements = await retired.value
    XCTAssertTrue(failed)
    XCTAssertEqual(snapshot.failure, .connection(.transportSecurityFailed))
    XCTAssertEqual(snapshot.retryDisposition, .terminal)
    XCTAssertEqual(retirements, 2)
    await controller.close()
  }

  func testDigestOnlyPinRotationIsEligible() async throws {
    let retired = AsyncCounterV3()
    let spent = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), spent: spent, retired: retired),
      try lease(artifact: changedPinExpiryArtifactV3(), spent: spent, retired: retired),
    ])
    let calls = AsyncCounterV3()
    let session = ControllerSessionV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { lease, _ in
        if await calls.increment() == 1 { throw nativePinFailureV3() }
        let claimed = try await lease.claim()
        try await claimed.commitSpend()
        return session
      }
    )

    await controller.start()
    let connected = await waitForState(.connected, controller: controller)
    XCTAssertTrue(connected)
    let acquisitions = await source.acquisitions
    let retirements = await retired.value
    let spends = await spent.value
    XCTAssertEqual(acquisitions, 2)
    XCTAssertEqual(retirements, 1)
    XCTAssertEqual(spends, 1)
    await controller.close()
  }

  func testRetryableReplacementSourceFailureContinuesFindingReplacement() async throws {
    let retired = AsyncCounterV3()
    let spent = AsyncCounterV3()
    let source = ResultArtifactSourceV3([
      .success(try lease(artifact: artifactV3(), spent: spent, retired: retired)),
      .failure(ArtifactSourceFailure(disposition: .retryable)),
      .success(try lease(artifact: changedPinArtifactV3(), spent: spent, retired: retired)),
    ])
    let calls = AsyncCounterV3()
    let session = ControllerSessionV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { lease, _ in
        if await calls.increment() == 1 { throw nativePinFailureV3() }
        let claimed = try await lease.claim()
        try await claimed.commitSpend()
        return session
      }
    )

    await controller.start()
    let waiting = await waitForState(.waiting, controller: controller)
    let woke = await controller.retryNow()
    let connected = await waitForState(.connected, controller: controller)
    XCTAssertTrue(waiting)
    XCTAssertTrue(woke)
    XCTAssertTrue(connected)
    let acquisitions = await source.acquisitions
    let retirements = await retired.value
    let spends = await spent.value
    XCTAssertEqual(acquisitions, 3)
    XCTAssertEqual(retirements, 1)
    XCTAssertEqual(spends, 1)
    await controller.close()
  }

  func testReplacementSourceFailuresPreserveArtifactSourcePhase() async throws {
    for (name, sourceFailure, maximumAttempts) in [
      ("terminal", ArtifactSourceFailure(disposition: .terminal), nil),
      ("attempt exhaustion", ArtifactSourceFailure(disposition: .retryable), UInt64(2)),
    ] {
      let retired = AsyncCounterV3()
      let source = ResultArtifactSourceV3([
        .success(try lease(artifact: artifactV3(), retired: retired)),
        .failure(sourceFailure),
      ])
      let controller = try ConnectionController(
        source: source,
        maximumAttempts: maximumAttempts,
        connectOneShot: { _, _ in throw nativePinFailureV3() }
      )

      await controller.start()
      let failed = await waitForState(.failed, controller: controller)
      let snapshot = await controller.snapshot()
      let acquisitions = await source.acquisitions
      let retirements = await retired.value
      XCTAssertTrue(failed, name)
      XCTAssertEqual(
        snapshot.failure,
        .artifactSource(ArtifactSourceFailure(disposition: .terminal)),
        name)
      XCTAssertEqual(snapshot.retryDisposition, .terminal, name)
      XCTAssertEqual(acquisitions, 2, name)
      XCTAssertEqual(retirements, 1, name)
      await controller.close()
    }
  }

  func testReplacementInvalidRetryAfterWinsAtAttemptExhaustion() async throws {
    let retired = AsyncCounterV3()
    let source = ResultArtifactSourceV3([
      .success(try lease(artifact: artifactV3(), retired: retired)),
      .failure(
        ArtifactSourceFailure(disposition: .retryAfter(253_402_300_800_000))),
    ])
    let controller = try ConnectionController(
      source: source,
      maximumAttempts: 2,
      connectOneShot: { _, _ in throw nativePinFailureV3() }
    )

    await controller.start()
    let failed = await waitForState(.failed, controller: controller)
    let snapshot = await controller.snapshot()
    let acquisitions = await source.acquisitions
    let retirements = await retired.value
    XCTAssertTrue(failed)
    XCTAssertEqual(snapshot.failure, .connection(.artifactInvalid))
    XCTAssertEqual(snapshot.retryDisposition, .terminal)
    XCTAssertEqual(acquisitions, 2)
    XCTAssertEqual(retirements, 1)
    await controller.close()
  }

  func testReplacementLeaseClaimLoserIsArtifactInvalid() async throws {
    let retired = AsyncCounterV3()
    let repeated = try lease(artifact: artifactV3(), retired: retired)
    let source = SequenceArtifactSourceV3([repeated, repeated])
    let attempts = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { _, _ in
        _ = await attempts.increment()
        throw nativePinFailureV3()
      }
    )

    await controller.start()
    let failed = await waitForState(.failed, controller: controller)
    let snapshot = await controller.snapshot()
    let acquisitions = await source.acquisitions
    let connectAttempts = await attempts.value
    let retirements = await retired.value
    XCTAssertTrue(failed)
    XCTAssertEqual(snapshot.failure, .connection(.artifactInvalid))
    XCTAssertEqual(snapshot.retryDisposition, .terminal)
    XCTAssertEqual(acquisitions, 2)
    XCTAssertEqual(connectAttempts, 1)
    XCTAssertEqual(retirements, 1)
    await controller.close()
  }

  func testPrimaryInvalidRetryAfterFailsBeforePolicyRefresh() async throws {
    let retired = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), retired: retired)
    ])
    let attempts = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { _, _ in
        _ = await attempts.increment()
        throw ControllerConnectFailureV3.connection(
          .transportSecurityFailed,
          .retryAfter(253_402_300_800_000),
          policyTriggerIDs: ["w-pin"],
          opaquePolicyTriggerIDs: [],
          failedIDs: ["w-pin"])
      }
    )

    await controller.start()
    let failed = await waitForState(.failed, controller: controller)
    let snapshot = await controller.snapshot()
    let acquisitions = await source.acquisitions
    let connectAttempts = await attempts.value
    let retirements = await retired.value
    XCTAssertTrue(failed)
    XCTAssertEqual(snapshot.failure, .connection(.artifactInvalid))
    XCTAssertEqual(snapshot.retryDisposition, .terminal)
    XCTAssertEqual(acquisitions, 1)
    XCTAssertEqual(connectAttempts, 1)
    XCTAssertEqual(retirements, 1)
    await controller.close()
  }

  func testReplacementInvalidRetryAfterFailsClosedBeforeRetry() async throws {
    let retired = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), retired: retired),
      try lease(artifact: changedPinArtifactV3(), retired: retired),
    ])
    let attempts = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { _, _ in
        if await attempts.increment() == 1 {
          throw nativePinFailureV3()
        }
        throw ControllerConnectFailureV3.connection(
          .transportSecurityFailed,
          .retryAfter(253_402_300_800_000),
          policyTriggerIDs: [],
          opaquePolicyTriggerIDs: [],
          failedIDs: ["w-pin"])
      }
    )

    await controller.start()
    let failed = await waitForState(.failed, controller: controller)
    let snapshot = await controller.snapshot()
    let acquisitions = await source.acquisitions
    let connectAttempts = await attempts.value
    let retirements = await retired.value
    XCTAssertTrue(failed)
    XCTAssertEqual(snapshot.failure, .connection(.artifactInvalid))
    XCTAssertEqual(snapshot.retryDisposition, .terminal)
    XCTAssertEqual(acquisitions, 2)
    XCTAssertEqual(connectAttempts, 2)
    XCTAssertEqual(retirements, 2)
    await controller.close()
  }

  func testBrowserOpaquePinFailureRefreshesOnceAndKeepsConnectionError() async throws {
    let expected = try controllerExpectedV3("browser-opaque-exhausted")
    let retired = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), retired: retired),
      try lease(artifact: artifactV3(), retired: retired),
    ])
    let calls = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { _, _ in
        _ = await calls.increment()
        throw ControllerConnectFailureV3.connection(
          .connectionFailed, .retryable, policyTriggerIDs: [],
          opaquePolicyTriggerIDs: ["w-pin"], failedIDs: ["w-pin"])
      }
    )

    await controller.start()
    let failed = await waitForState(.failed, controller: controller)
    let snapshot = await controller.snapshot()
    let acquisitions = await source.acquisitions
    let attempts = await calls.value
    let retirements = await retired.value
    XCTAssertTrue(failed)
    XCTAssertEqual(snapshot.failure, .connection(.connectionFailed))
    XCTAssertEqual(snapshot.retryDisposition, .terminal)
    XCTAssertEqual(acquisitions, expected["acquisitions"] as? Int)
    XCTAssertEqual(attempts, expected["connect_attempts"] as? Int)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int)
    XCTAssertEqual(expected["tls_error_claimed"] as? Bool, false)
    await controller.close()
  }

  func testMixedSecurityAndOpaqueTriggersRefresh() async throws {
    let expected = try controllerExpectedV3("mixed-security-opaque-policy-refresh")
    let retired = AsyncCounterV3()
    let spent = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: mixedCAPinArtifactV3(), spent: spent, retired: retired),
      try lease(artifact: changedPinArtifactV3(), spent: spent, retired: retired),
    ])
    let calls = AsyncCounterV3()
    let session = ControllerSessionV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { lease, _ in
        if await calls.increment() == 1 {
          throw ControllerConnectFailureV3.connection(
            .transportSecurityFailed, .retryable,
            policyTriggerIDs: [], opaquePolicyTriggerIDs: ["w-pin"],
            failedIDs: ["w-ca", "w-pin"])
        }
        let claimed = try await lease.claim()
        try await claimed.commitSpend()
        return session
      })

    await controller.start()
    let connected = await waitForState(.connected, controller: controller)
    let snapshot = await controller.snapshot()
    let acquisitions = await source.acquisitions
    let attempts = await calls.value
    let retirements = await retired.value
    let spends = await spent.value
    XCTAssertTrue(connected)
    XCTAssertEqual(snapshot.state, .connected)
    XCTAssertEqual(acquisitions, expected["acquisitions"] as? Int)
    XCTAssertEqual(attempts, expected["connect_attempts"] as? Int)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int)
    XCTAssertEqual(spends, expected["spend_callbacks"] as? Int)
    await controller.close()
  }

  func testSamePinAndPinToCAReplacementsAreTerminalWithoutThirdLease() async throws {
    for (scenarioID, replacementArtifact) in [
      ("pin-mismatch-same-policy-terminal", try artifactV3()),
      ("pin-to-ca-filtered", try caOnlyArtifactV3()),
    ] {
      let expected = try controllerExpectedV3(scenarioID)
      let retired = AsyncCounterV3()
      let spent = AsyncCounterV3()
      let source = SequenceArtifactSourceV3([
        try lease(artifact: artifactV3(), spent: spent, retired: retired),
        try lease(artifact: replacementArtifact, spent: spent, retired: retired),
      ])
      let calls = AsyncCounterV3()
      let controller = try ConnectionController(
        source: source,
        connectOneShot: { _, _ in
          _ = await calls.increment()
          throw nativePinFailureV3()
        }
      )
      await controller.start()
      let failed = await waitForState(.failed, controller: controller)
      let snapshot = await controller.snapshot()
      let acquisitions = await source.acquisitions
      let retirements = await retired.value
      let spends = await spent.value
      let connectAttempts = await calls.value
      XCTAssertTrue(failed)
      XCTAssertEqual(snapshot.failure, .connection(.transportSecurityFailed))
      XCTAssertEqual(expected["final_state"] as? String, "failed")
      XCTAssertEqual(expected["public_error"] as? String, "transport_security_failed")
      XCTAssertEqual(expected["disposition"] as? String, "terminal")
      XCTAssertEqual(acquisitions, expected["acquisitions"] as? Int)
      XCTAssertEqual(connectAttempts, expected["connect_attempts"] as? Int)
      XCTAssertEqual(connectAttempts, expected["transports_created"] as? Int)
      XCTAssertEqual(expected["replacement_acquisitions"] as? Int, 1)
      XCTAssertEqual(expected["replacement_quota_used"] as? Int, 1)
      XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int)
      XCTAssertEqual(spends, expected["spend_callbacks"] as? Int)
      XCTAssertEqual(expected["lease_terminal_states"] as? [String], ["retired", "retired"])
      XCTAssertEqual(expected["retry_delays_ms"] as? [Int], [])
      if scenarioID == "pin-to-ca-filtered" {
        XCTAssertEqual(expected["no_mode_downgrade"] as? Bool, true)
      }
      await controller.close()
    }
  }

  func testMixedCAPinCAFailureDoesNotTriggerPinReplacement() async throws {
    let retired = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: mixedCAPinArtifactV3(), retired: retired),
      try lease(artifact: changedPinArtifactV3(), retired: retired),
    ])
    let calls = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { _, _ in
        _ = await calls.increment()
        throw ControllerConnectFailureV3.connection(
          .transportSecurityFailed, .terminal,
          policyTriggerIDs: [], opaquePolicyTriggerIDs: [], failedIDs: ["w-ca"])
      }
    )

    await controller.start()
    let failed = await waitForState(.failed, controller: controller)
    let snapshot = await controller.snapshot()
    let acquisitions = await source.acquisitions
    let attempts = await calls.value
    let retirements = await retired.value
    XCTAssertTrue(failed)
    XCTAssertEqual(snapshot.failure, .connection(.transportSecurityFailed))
    XCTAssertEqual(snapshot.retryDisposition, .terminal)
    XCTAssertEqual(acquisitions, 1)
    XCTAssertEqual(attempts, 1)
    XCTAssertEqual(retirements, 1)
    await controller.close()
  }

  func testPublicTransportSecurityFailureWithoutProvenanceDoesNotRefreshPolicy() async throws {
    let retired = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), retired: retired),
      try lease(artifact: changedPinArtifactV3(), retired: retired),
    ])
    let calls = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { _, _ in
        _ = await calls.increment()
        throw ConnectError.transportSecurityFailed
      }
    )

    await controller.start()
    let failed = await waitForState(.failed, controller: controller)
    let snapshot = await controller.snapshot()
    let acquisitions = await source.acquisitions
    let connectAttempts = await calls.value
    let retirements = await retired.value
    XCTAssertTrue(failed)
    XCTAssertEqual(snapshot.failure, .connection(.transportSecurityFailed))
    XCTAssertEqual(snapshot.retryDisposition, .terminal)
    XCTAssertEqual(acquisitions, 1)
    XCTAssertEqual(connectAttempts, 1)
    XCTAssertEqual(retirements, 1)
    await controller.close()
  }

  func testOnlyActuallyFailedPinEndpointEntersReplacementProvenance() async throws {
    let retired = AsyncCounterV3()
    let spent = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: twoPinArtifactV3(), spent: spent, retired: retired),
      try lease(artifact: changedOneOfTwoPinsArtifactV3(), spent: spent, retired: retired),
    ])
    let attempts = AsyncCounterV3()
    let replacementCandidates = CandidateIDRecorderV3()
    let session = ControllerSessionV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { lease, _ in
        if await attempts.increment() == 1 {
          throw ControllerConnectFailureV3.connection(
            .transportSecurityFailed, .terminal,
            policyTriggerIDs: ["w-pin"], opaquePolicyTriggerIDs: [], failedIDs: ["w-pin"])
        }
        await replacementCandidates.record(Set(lease.artifact.canonicalCandidates.map(\.id)))
        let claimed = try await lease.claim()
        try await claimed.commitSpend()
        return session
      }
    )

    await controller.start()
    let connected = await waitForState(.connected, controller: controller)
    let candidates = await replacementCandidates.value
    let acquisitions = await source.acquisitions
    let retirements = await retired.value
    let spends = await spent.value
    XCTAssertTrue(connected)
    XCTAssertEqual(candidates, ["t-pin", "w-pin"])
    XCTAssertEqual(acquisitions, 2)
    XCTAssertEqual(retirements, 1)
    XCTAssertEqual(spends, 1)
    await controller.close()
  }

  func testAllUnsupportedIsTerminalWithoutCreatingTransport() async throws {
    let expected = try controllerExpectedV3("all-unsupported")
    let retired = AsyncCounterV3()
    let spent = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), spent: spent, retired: retired)
    ])
    let connectAttempts = AsyncCounterV3()
    let transports = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      maximumAttempts: 1,
      connectOneShot: { _, _ in
        _ = await connectAttempts.increment()
        throw ConnectError.transportSecurityUnsupported
      }
    )

    await controller.start()
    let failed = await waitForState(.failed, controller: controller)
    let snapshot = await controller.snapshot()
    let acquisitions = await source.acquisitions
    let attempts = await connectAttempts.value
    let created = await transports.value
    let spends = await spent.value
    let retirements = await retired.value
    XCTAssertTrue(failed)
    XCTAssertEqual(snapshot.failure, .connection(.transportSecurityUnsupported))
    XCTAssertEqual(expected["final_state"] as? String, "failed")
    XCTAssertEqual(expected["public_error"] as? String, "transport_security_unsupported")
    XCTAssertEqual(expected["disposition"] as? String, "terminal")
    XCTAssertEqual(acquisitions, expected["acquisitions"] as? Int)
    XCTAssertEqual(attempts, expected["connect_attempts"] as? Int)
    XCTAssertEqual(created, expected["transports_created"] as? Int)
    XCTAssertEqual(expected["replacement_acquisitions"] as? Int, 0)
    XCTAssertEqual(expected["replacement_quota_used"] as? Int, 0)
    XCTAssertEqual(spends, expected["spend_callbacks"] as? Int)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int)
    XCTAssertEqual(expected["lease_terminal_states"] as? [String], ["retired"])
    XCTAssertEqual(expected["retry_delays_ms"] as? [Int], [])
    await controller.close()
  }

  func testExpiredReplacementReturnsToPrimaryBackoffWithoutRestoringQuota() async throws {
    try await runExpiredReplacementVector("replacement-expired-returns-primary", beforeRace: false)
  }

  func testExpiredReplacementBeforeRaceReturnsToPrimary() async throws {
    try await runExpiredReplacementVector(
      "replacement-expired-before-race-returns-primary", beforeRace: true)
  }

  private func runExpiredReplacementVector(_ id: String, beforeRace: Bool) async throws {
    let expected = try controllerExpectedV3(id)
    let retired = AsyncCounterV3()
    let spent = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), spent: spent, retired: retired),
      try lease(
        artifact: beforeRace ? expiredArtifactV3() : changedPinArtifactV3(), spent: spent,
        retired: retired),
      try lease(artifact: mixedCAPinArtifactV3(), spent: spent, retired: retired),
    ])
    let calls = AsyncCounterV3()
    let primaryCandidates = CandidateIDRecorderV3()
    let session = ControllerSessionV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { lease, _ in
        switch await calls.increment() {
        case 1: throw nativePinFailureV3()
        case 2 where !beforeRace: throw ConnectError.expiredArtifact
        default:
          await primaryCandidates.record(Set(lease.artifact.canonicalCandidates.map(\.id)))
          let claimed = try await lease.claim()
          try await claimed.commitSpend()
          return session
        }
      }
    )
    await controller.start()
    let waiting = await waitForState(.waiting, controller: controller)
    let initialAcquisitions = await source.acquisitions
    let initialRetirements = await retired.value
    let woke = await controller.retryNow()
    let connected = await waitForState(.connected, controller: controller)
    let finalAcquisitions = await source.acquisitions
    let finalRetirements = await retired.value
    let finalSpends = await spent.value
    let connectAttempts = await calls.value
    let allowedPrimaryCandidates = await primaryCandidates.value
    XCTAssertTrue(waiting)
    XCTAssertEqual(initialAcquisitions, 2)
    XCTAssertEqual(initialRetirements, 2)
    XCTAssertTrue(woke)
    XCTAssertTrue(connected)
    XCTAssertEqual(expected["final_state"] as? String, "connected")
    XCTAssertEqual(finalAcquisitions, expected["acquisitions"] as? Int)
    XCTAssertEqual(connectAttempts, expected["connect_attempts"] as? Int)
    XCTAssertEqual(connectAttempts, expected["transports_created"] as? Int)
    XCTAssertEqual(expected["replacement_acquisitions"] as? Int, 1)
    XCTAssertEqual(expected["replacement_quota_used"] as? Int, 1)
    XCTAssertEqual(allowedPrimaryCandidates, ["w-ca"])
    XCTAssertEqual(finalSpends, expected["spend_callbacks"] as? Int)
    XCTAssertEqual(finalRetirements, expected["retire_callbacks"] as? Int)
    XCTAssertEqual(
      expected["lease_terminal_states"] as? [String], ["retired", "retired", "consumed"])
    XCTAssertEqual(expected["retry_delays_ms"] as? [Int], [500])
    XCTAssertEqual(expected["blocked_policy_remains_blocked"] as? Bool, true)
    XCTAssertTrue(expected["public_error"] is NSNull)
    XCTAssertTrue(expected["disposition"] is NSNull)
    await controller.close()
  }

  func testRetryableReplacementAcquisitionContinuesSearch() async throws {
    let expected = try controllerExpectedV3("replacement-acquisition-retryable-continues-search")
    let retired = AsyncCounterV3()
    let spent = AsyncCounterV3()
    let source = ResultArtifactSourceV3([
      .success(try lease(artifact: artifactV3(), spent: spent, retired: retired)),
      .failure(ArtifactSourceFailure(disposition: .retryable)),
      .success(try lease(artifact: changedPinArtifactV3(), spent: spent, retired: retired)),
    ])
    let calls = AsyncCounterV3()
    let session = ControllerSessionV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { lease, _ in
        if await calls.increment() == 1 { throw nativePinFailureV3() }
        let claimed = try await lease.claim()
        try await claimed.commitSpend()
        return session
      }
    )
    await controller.start()
    let waiting = await waitForState(.waiting, controller: controller)
    let woke = await controller.retryNow()
    let connected = await waitForState(.connected, controller: controller)
    let acquisitions = await source.acquisitions
    let connectAttempts = await calls.value
    let retirements = await retired.value
    let spends = await spent.value
    XCTAssertTrue(waiting)
    XCTAssertTrue(woke)
    XCTAssertTrue(connected)
    XCTAssertEqual(acquisitions, expected["acquisitions"] as? Int)
    XCTAssertEqual(connectAttempts, expected["connect_attempts"] as? Int)
    XCTAssertEqual(connectAttempts, expected["transports_created"] as? Int)
    XCTAssertEqual(expected["replacement_acquisitions"] as? Int, 1)
    XCTAssertEqual(expected["replacement_quota_used"] as? Int, 1)
    XCTAssertEqual(spends, expected["spend_callbacks"] as? Int)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int)
    XCTAssertEqual(expected["lease_terminal_states"] as? [String], ["retired", "consumed"])
    XCTAssertEqual(expected["retry_delays_ms"] as? [Int], [500])
    await controller.close()
  }

  func testPostSpendRetryPreservesReplacementQuota() async throws {
    let expected = try controllerExpectedV3("post-spend-retry-preserves-quota")
    let retired = AsyncCounterV3()
    let spent = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), retired: retired),
      try lease(artifact: changedPinArtifactV3(), spent: spent, retired: retired),
      try lease(artifact: changedPinArtifactV3(), retired: retired),
    ])
    let calls = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { lease, _ in
        let call = await calls.increment()
        if call == 2 {
          let claimed = try await lease.claim()
          try await claimed.commitSpend()
          throw ConnectError.connectionFailed
        }
        if call == 3 {
          throw ControllerConnectFailureV3.connection(
            .connectionFailed,
            .terminal,
            policyTriggerIDs: [],
            opaquePolicyTriggerIDs: ["w-pin"],
            failedIDs: ["w-pin"])
        }
        throw nativePinFailureV3()
      }
    )
    await controller.start()
    let waiting = await waitForState(.waiting, controller: controller)
    let initialSpends = await spent.value
    let woke = await controller.retryNow()
    let failed = await waitForState(.failed, controller: controller)
    let acquisitions = await source.acquisitions
    let finalSpends = await spent.value
    let finalRetirements = await retired.value
    let connectAttempts = await calls.value
    XCTAssertTrue(waiting)
    XCTAssertEqual(initialSpends, 1)
    XCTAssertTrue(woke)
    XCTAssertTrue(failed)
    XCTAssertEqual(expected["final_state"] as? String, "failed")
    XCTAssertEqual(expected["public_error"] as? String, "transport_security_failed")
    XCTAssertEqual(expected["disposition"] as? String, "terminal")
    XCTAssertEqual(acquisitions, expected["acquisitions"] as? Int)
    XCTAssertEqual(connectAttempts, expected["connect_attempts"] as? Int)
    XCTAssertEqual(connectAttempts, expected["transports_created"] as? Int)
    XCTAssertEqual(expected["replacement_acquisitions"] as? Int, 1)
    XCTAssertEqual(expected["replacement_quota_used"] as? Int, 1)
    XCTAssertEqual(finalSpends, expected["spend_callbacks"] as? Int)
    XCTAssertEqual(finalRetirements, expected["retire_callbacks"] as? Int)
    XCTAssertEqual(
      expected["lease_terminal_states"] as? [String], ["retired", "consumed", "retired"])
    XCTAssertEqual(expected["retry_delays_ms"] as? [Int], [500])
    await controller.close()
  }

  func testAttemptExhaustionUsesFirstBackoffAndCreatesNoTransport() async throws {
    let expected = try controllerExpectedV3("attempt-exhaustion")
    let source = RetryableFailureArtifactSourceV3()
    let connectAttempts = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      maximumAttempts: 2,
      connectOneShot: { _, _ in
        _ = await connectAttempts.increment()
        throw ConnectError.connectionFailed
      }
    )

    await controller.start()
    let waiting = await waitForState(.waiting, controller: controller)
    let woke = await controller.retryNow()
    let failed = await waitForState(.failed, controller: controller)
    let snapshot = await controller.snapshot()
    let acquisitions = await source.acquisitions
    let attempts = await connectAttempts.value
    XCTAssertTrue(waiting)
    XCTAssertTrue(woke)
    XCTAssertTrue(failed)
    XCTAssertEqual(
      snapshot.failure, .artifactSource(ArtifactSourceFailure(disposition: .terminal)))
    XCTAssertEqual(snapshot.failure?.retryDisposition, .terminal)
    XCTAssertEqual(snapshot.retryDisposition, .terminal)
    XCTAssertEqual(expected["final_state"] as? String, "failed")
    XCTAssertEqual(expected["public_error"] as? String, "connection_failed")
    XCTAssertEqual(expected["disposition"] as? String, "terminal")
    XCTAssertEqual(acquisitions, expected["acquisitions"] as? Int)
    XCTAssertEqual(attempts, expected["connect_attempts"] as? Int)
    XCTAssertEqual(expected["transports_created"] as? Int, 0)
    XCTAssertEqual(expected["replacement_acquisitions"] as? Int, 0)
    XCTAssertEqual(expected["replacement_quota_used"] as? Int, 0)
    XCTAssertEqual(expected["spend_callbacks"] as? Int, 0)
    XCTAssertEqual(expected["retire_callbacks"] as? Int, 0)
    XCTAssertEqual(expected["lease_terminal_states"] as? [String], [])
    XCTAssertEqual(expected["retry_delays_ms"] as? [Int], [250])
    await controller.close()
  }

  func testAttemptExhaustionTerminalizesConnectionFailureDisposition() async throws {
    let retired = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), retired: retired),
      try lease(artifact: artifactV3(), retired: retired),
    ])
    let clock = VectorManualClockV3(wallMilliseconds: 0, monotonicMilliseconds: 0)
    let attempts = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      maximumAttempts: 2,
      clock: clock.controllerClock,
      connectOneShot: { _, _ in
        _ = await attempts.increment()
        throw ConnectError.connectionFailed
      })

    await controller.start()
    let waiting = await waitForState(.waiting, controller: controller)
    XCTAssertTrue(waiting)
    let sleeping = await clock.waitForSleepCount(1)
    XCTAssertTrue(sleeping)
    clock.advance(wallMilliseconds: 0, monotonicMilliseconds: 250)
    let failed = await waitForState(.failed, controller: controller)
    XCTAssertTrue(failed)
    let snapshot = await controller.snapshot()
    guard case .connection(let failure) = snapshot.failure else {
      XCTFail("expected connection failure")
      await controller.close()
      return
    }
    XCTAssertEqual(failure.code, .connectionFailed)
    let failureDisposition = snapshot.failure?.retryDisposition
    XCTAssertEqual(failureDisposition, RetryDispositionV3.terminal)
    XCTAssertEqual(snapshot.retryDisposition, .terminal)
    let attemptCount = await attempts.value
    XCTAssertEqual(attemptCount, 2)
    await controller.close()
  }

  func testInvalidRetryAfterDeadlinesAreArtifactInvalidAndTerminal() async throws {
    let invalidDeadlines: [UInt64] = [253_402_300_800_000]
    for deadline in invalidDeadlines {
      let source = ResultArtifactSourceV3([
        .failure(ArtifactSourceFailure(disposition: .retryAfter(deadline)))
      ])
      let controller = try ConnectionController(source: source, maximumAttempts: 1)

      await controller.start()
      let failed = await waitForState(.failed, controller: controller)
      let snapshot = await controller.snapshot()
      let acquisitions = await source.acquisitions
      XCTAssertTrue(failed, "deadline \(deadline) did not fail")
      XCTAssertEqual(snapshot.failure, .connection(.artifactInvalid))
      XCTAssertEqual(snapshot.retryDisposition, .terminal)
      XCTAssertEqual(acquisitions, 1)
      await controller.close()
    }
  }

  func testRetryNowRechecksAbsoluteDeadlineAfterWallClockRollback() async throws {
    let deadline: UInt64 = 1_000
    let clock = VectorManualClockV3(wallMilliseconds: 0, monotonicMilliseconds: 0)
    let source = ResultArtifactSourceV3([
      .failure(ArtifactSourceFailure(disposition: .retryAfter(deadline))),
      .success(try lease(artifact: artifactV3(), retired: AsyncCounterV3())),
    ])
    let session = ControllerSessionV3()
    let connectAttempts = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      clock: clock.controllerClock,
      connectOneShot: { lease, _ in
        _ = await connectAttempts.increment()
        let claimed = try await lease.claim()
        try await claimed.commitSpend()
        return session
      })

    await controller.start()
    let reachedWaiting = await waitForState(.waiting, controller: controller)
    let initialTimerArmed = await clock.waitForSleepCount(1)
    XCTAssertTrue(reachedWaiting)
    XCTAssertTrue(initialTimerArmed)
    clock.overrideNextWallRead(milliseconds: Int64(deadline))

    let manualWake = await controller.retryNow()
    let timerRearmed = await clock.waitForSleepCount(2)
    XCTAssertTrue(manualWake)
    XCTAssertTrue(timerRearmed)
    let acquisitionsDuringRollback = await source.acquisitions
    let attemptsDuringRollback = await connectAttempts.value
    let rollbackSnapshot = await controller.snapshot()
    XCTAssertEqual(acquisitionsDuringRollback, 1)
    XCTAssertEqual(attemptsDuringRollback, 0)
    XCTAssertEqual(rollbackSnapshot.state, .waiting)

    clock.advance(wallMilliseconds: Int64(deadline), monotonicMilliseconds: 0)
    let connected = await waitForState(.connected, controller: controller)
    XCTAssertTrue(connected)
    let finalAcquisitions = await source.acquisitions
    let finalAttempts = await connectAttempts.value
    XCTAssertEqual(finalAcquisitions, 2)
    XCTAssertEqual(finalAttempts, 1)
    await controller.close()
  }

  func testEveryV3ControllerScenarioExecutesProductionPaths() async throws {
    let root = try controllerVectorsV3()
    let scenarios = try XCTUnwrap(root["scenarios"] as? [[String: Any]])
    let ids = scenarios.compactMap { $0["id"] as? String }
    XCTAssertEqual(ids.count, 41)
    XCTAssertEqual(Set(ids).count, 41)

    for id in ids {
      switch id {
      case "pin-mismatch-changed-pin-success":
        try await testPinMismatchUsesOneChangedPinReplacementAndEstablishes()
      case "pin-mismatch-same-policy-terminal", "pin-to-ca-filtered":
        try await testSamePinAndPinToCAReplacementsAreTerminalWithoutThirdLease()
      case "browser-opaque-exhausted":
        try await testBrowserOpaquePinFailureRefreshesOnceAndKeepsConnectionError()
      case "mixed-security-opaque-policy-refresh":
        try await testMixedSecurityAndOpaqueTriggersRefresh()
      case "all-unsupported":
        try await testAllUnsupportedIsTerminalWithoutCreatingTransport()
      case "replacement-expired-returns-primary":
        try await testExpiredReplacementReturnsToPrimaryBackoffWithoutRestoringQuota()
      case "replacement-expired-before-race-returns-primary":
        try await testExpiredReplacementBeforeRaceReturnsToPrimary()
      case "replacement-acquisition-retryable-continues-search":
        try await testRetryableReplacementAcquisitionContinuesSearch()
      case "post-spend-retry-preserves-quota":
        try await testPostSpendRetryPreservesReplacementQuota()
      case "lease-cancellation-first", "lease-delivery-first":
        try await runCancellationVectorV3(id)
      case "attempt-exhaustion":
        try await testAttemptExhaustionUsesFirstBackoffAndCreatesNoTransport()
      case "retry-after-and-monotonic-backoff":
        try await runRetryAfterVectorV3(id)
      case "race-order-independent-security-priority", "single-ca-untrusted-terminal",
        "ca-untrusted-dominates-ordinary-failure":
        try await runSecurityAggregationVectorV3(id)
      case "failure-ordinal-counts-attempt-once":
        try await runFailureOrdinalVectorV3(id)
      case "artifact-expiry-before-race", "artifact-expiry-at-race-end",
        "artifact-expiry-immediately-before-spend", "artifact-expiry-after-spend":
        try await runExpiryBoundaryVectorV3(id)
      case "established-session-termination-resets-cycle":
        try await runCycleResetVectorV3(id)
      case "established-session-terminal-termination-resets-cycle":
        try await runTerminalCycleResetVectorV3(id)
      case "retry-after-wall-clock-forward-jump", "retry-after-wall-clock-backward-jump",
        "retry-after-wall-reread-bounded", "monotonic-timer-safe-integer-saturation":
        try await runClockBoundaryVectorV3(id)
      case "multiple-pin-trigger-endpoints-filtered":
        try await runMultiTriggerVectorV3(id)
      case "retire-cleanup-failure-does-not-retry-lease":
        try await runRetireCleanupVectorV3(id)
      case "ordinary-retry-refresh-preserves-replacement-quota":
        try await runQuotaPreservationVectorV3(id)
      case "attempt-counter-safe-integer-saturation":
        try await runAttemptSaturationVectorV3(id)
      case "capability-snapshot-invalidation-barrier":
        try await runCapabilityBarrierVectorV3(id)
      case "primary-fsa3-reject-consumes-spent", "primary-fsa3-retryable-consumes-spent",
        "replacement-fsa3-reject-consumes-spent",
        "replacement-fsa3-retryable-consumes-spent", "primary-fsh3-failure-consumes-spent",
        "replacement-fsh3-failure-consumes-spent":
        try await runAdmissionBoundaryVectorV3(id)
      case "artifact-source-repeats-consumed-lease", "artifact-source-repeats-retired-lease":
        try await runDuplicateLeaseVectorV3(id)
      default:
        XCTFail("controller scenario has no production runner: \(id)")
      }
    }
  }

  func testEveryV3BrowserCapabilityScenarioExecutesBarrierContract() async throws {
    let root = try controllerVectorsV3()
    let scenarios = try XCTUnwrap(root["browser_capability_scenarios"] as? [[String: Any]])
    XCTAssertEqual(scenarios.count, 1)
    let scenario = try XCTUnwrap(scenarios.first)
    XCTAssertEqual(scenario["id"] as? String, "concurrent-capability-invalidation-replacement-barrier")
    XCTAssertEqual(scenario["driver"] as? String, "capability-linearization-barrier")
    XCTAssertFalse(try XCTUnwrap(scenario["steps"] as? [String]).isEmpty)
    let input = try XCTUnwrap(scenario["input"] as? [String: Any])
    XCTAssertEqual(input["concurrent_controllers"] as? Int, 2)
    XCTAssertEqual(input["initial_capability"] as? String, "enabled")
    XCTAssertEqual(input["invalidated_capability"] as? String, "ca_only")
    XCTAssertEqual(input["primary_trigger"] as? String, "browser_pin_opaque")
    XCTAssertEqual(input["invalidation_trigger"] as? String, "synchronous_not_supported")
    let expected = try XCTUnwrap(scenario["expected"] as? [String: Any])
    let retired = AsyncCounterV3()
    let barrier = CapabilityLinearizationBarrierV3()
    let refreshSource = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), retired: retired),
      try lease(artifact: changedPinWithCAArtifactV3(), retired: retired),
    ])
    let staleSource = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), retired: retired)
    ])
    let refreshRuntime = CoordinatedCapabilityRuntimeV3(barrier: barrier, stale: false)
    let staleRuntime = CoordinatedCapabilityRuntimeV3(barrier: barrier, stale: true)
    let refreshCalls = AsyncCounterV3()
    let refreshController = try ConnectionController(
      source: refreshSource,
      connectOneShot: { lease, options in
        if await refreshCalls.increment() == 1 {
          _ = await barrier.arrive()
          await barrier.waitForRelease()
          throw ControllerConnectFailureV3.connection(
            .connectionFailed, .retryable, policyTriggerIDs: [],
            opaquePolicyTriggerIDs: ["w-pin"], failedIDs: ["w-pin"])
        }
        await barrier.recordReplacementSnapshot()
        return try await SessionConnectorV3(
          lease: lease, options: options, runtime: refreshRuntime,
          currentUnixSeconds: { 1_900_000_000 }
        ).connectForController()
      })
    let staleController = try ConnectionController(
      source: staleSource,
      connectOneShot: { lease, options in
        try await SessionConnectorV3(
          lease: lease, options: options, runtime: staleRuntime,
          currentUnixSeconds: { 1_900_000_000 }
        ).connectForController()
      })

    await refreshController.start()
    await staleController.start()
    await barrier.waitForInitialAcquisitions()
    await barrier.invalidateAndRelease()
    let staleFailed = await waitForState(.failed, controller: staleController)
    let refreshFailed = await waitForState(.failed, controller: refreshController)
    XCTAssertTrue(staleFailed, "stale controller")
    XCTAssertTrue(refreshFailed, "refresh controller")

    let refreshSnapshot = await refreshController.snapshot()
    let staleSnapshot = await staleController.snapshot()
    let acquisitions = await refreshSource.acquisitions + staleSource.acquisitions
    let retirements = await retired.value
    let concurrentPeak = await barrier.concurrentAcquisitionPeak
    let snapshots = await barrier.capabilitySnapshots
    let replacementAcquisitions = await barrier.replacementAcquisitions
    XCTAssertEqual(refreshSnapshot.state.rawValue, expected["final_state"] as? String)
    XCTAssertEqual(refreshSnapshot.failure, .connection(.connectionFailed))
    XCTAssertEqual(staleSnapshot.failure, .connection(.transportSecurityUnsupported))
    XCTAssertEqual(acquisitions, expected["acquisitions"] as? Int)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int)
    XCTAssertEqual(concurrentPeak, expected["concurrent_acquisition_peak"] as? Int)
    XCTAssertEqual(snapshots, expected["capability_snapshots"] as? [String])
    XCTAssertEqual(replacementAcquisitions, expected["replacement_acquisitions"] as? Int)
    await refreshController.close()
    await staleController.close()
  }

  private func runCancellationVectorV3(_ id: String) async throws {
    let expected = try controllerExpectedV3(id)
    let retired = AsyncCounterV3()
    let retireGate = BlockingRetireGateV3()
    let tracked = ArtifactLeaseV3(
      artifact: try artifactV3(),
      commitSpend: {},
      retire: {
        await retireGate.wait()
        _ = await retired.increment()
      })
    if id == "lease-cancellation-first" {
      let source = BlockingArtifactSourceV3(tracked)
      let connects = AsyncCounterV3()
      let controller = try ConnectionController(
        source: source,
        connectOneShot: { _, _ in
          _ = await connects.increment()
          throw ConnectError.connectionFailed
        })
      await controller.start()
      assertTrueV3(await waitUntilV3 { await source.acquisitions == 1 }, id)
      let closeTask = Task { await controller.close() }
      assertTrueV3(await waitUntilV3 { await controller.state == .closed }, id)
      await source.release()
      assertTrueV3(await waitUntilV3 { await retireGate.entered }, id)
      let closeFinished = AsyncFlagV3()
      let joinedClose = Task {
        await closeTask.value
        await closeFinished.set()
      }
      let finishedBeforeRetireRelease = await closeFinished.value
      XCTAssertFalse(finishedBeforeRetireRelease)
      await retireGate.release()
      await joinedClose.value
      let snapshot = await controller.snapshot()
      let attempts = await connects.value
      let retirements = await retired.value
      XCTAssertEqual(snapshot.state.rawValue, expected["final_state"] as? String, id)
      XCTAssertEqual(attempts, expected["connect_attempts"] as? Int, id)
      XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int, id)
      XCTAssertEqual(expected["source_cancellation_propagated"] as? Bool, true, id)
      XCTAssertEqual(expected["close_waits_for_acquire_settlement"] as? Bool, true, id)
      return
    }

    let source = SequenceArtifactSourceV3([tracked])
    let started = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { _, _ in
        _ = await started.increment()
        do { try await Task.sleep(for: .seconds(60)) } catch { throw ConnectError.canceled }
        throw ConnectError.connectionFailed
      })
    await controller.start()
    assertTrueV3(await waitUntilV3 { await started.value == 1 }, id)
    let closing = Task { await controller.close() }
    assertTrueV3(await waitUntilV3 { await retireGate.entered }, id)
    let closeFinished = AsyncFlagV3()
    let joinedClose = Task {
      await closing.value
      await closeFinished.set()
    }
    let finishedBeforeRetireRelease = await closeFinished.value
    XCTAssertFalse(finishedBeforeRetireRelease)
    await retireGate.release()
    await joinedClose.value
    let snapshot = await controller.snapshot()
    let attempts = await started.value
    let retirements = await retired.value
    XCTAssertEqual(snapshot.state.rawValue, expected["final_state"] as? String, id)
    XCTAssertEqual(attempts, expected["connect_attempts"] as? Int, id)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int, id)
    XCTAssertEqual(expected["source_cancellation_propagated"] as? Bool, true, id)
    XCTAssertEqual(expected["close_waits_for_acquire_settlement"] as? Bool, true, id)
  }

  func testControllerDrainsLateSourceErrorAfterCancellation() async throws {
    let source = BlockingErrorArtifactSourceV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { _, _ in throw ConnectError.connectionFailed }
    )
    await controller.start()
    let acquired = await waitUntilV3 { await source.acquisitions == 1 }
    XCTAssertTrue(acquired)

    let closeFinished = AsyncFlagV3()
    let closing = Task {
      await controller.close()
      await closeFinished.set()
    }
    let closed = await waitUntilV3 { await controller.state == .closed }
    XCTAssertTrue(closed)
    try? await Task.sleep(for: .milliseconds(20))
    let finishedBeforeSourceRelease = await closeFinished.value
    XCTAssertFalse(finishedBeforeSourceRelease)
    await source.release()
    await closing.value
    let snapshot = await controller.snapshot()
    XCTAssertEqual(snapshot.state, .closed)
  }

  private func runRetryAfterVectorV3(_ id: String) async throws {
    let expected = try controllerExpectedV3(id)
    let input = try controllerInputV3(id)
    let clock = VectorManualClockV3(
      wallMilliseconds: Int64(try XCTUnwrap(input["wall_start_ms"] as? Int)),
      monotonicMilliseconds: UInt64(try XCTUnwrap(input["monotonic_start_ms"] as? Int))
    )
    let spent = AsyncCounterV3()
    let retryAtMilliseconds = UInt64(try XCTUnwrap(input["retry_after_unix_ms"] as? Int))
    let source = ResultArtifactSourceV3([
      .failure(ArtifactSourceFailure(disposition: .retryAfter(retryAtMilliseconds))),
      .success(try lease(artifact: artifactV3(), spent: spent, retired: AsyncCounterV3())),
    ])
    let session = ControllerSessionV3()
    let controller = try ConnectionController(
      source: source,
      clock: clock.controllerClock,
      connectOneShot: { lease, _ in
        let claimed = try await lease.claim()
        try await claimed.commitSpend()
        return session
      })
    await controller.start()
    assertTrueV3(await waitForState(.waiting, controller: controller), id)
    assertTrueV3(await clock.waitForSleepCount(1), id)
    XCTAssertEqual(clock.requestedSleeps().first, 250, id)
    assertFalseV3(await controller.retryNow(), id)
    let wallAdvances = try XCTUnwrap(input["wall_advances_ms"] as? [Int])
    let monotonicAdvances = try XCTUnwrap(input["monotonic_advances_ms"] as? [Int])
    clock.advance(
      wallMilliseconds: Int64(wallAdvances[0]), monotonicMilliseconds: UInt64(monotonicAdvances[0]))
    assertTrueV3(await clock.waitForSleepCount(2), id)
    XCTAssertEqual(clock.requestedSleeps().dropFirst().first, 1_000, id)
    clock.advance(
      wallMilliseconds: Int64(wallAdvances[1]), monotonicMilliseconds: UInt64(monotonicAdvances[1]))
    assertTrueV3(await waitForState(.connected, controller: controller), id)
    let acquisitions = await source.acquisitions
    let spends = await spent.value
    XCTAssertEqual(acquisitions, expected["acquisitions"] as? Int, id)
    XCTAssertEqual(spends, expected["spend_callbacks"] as? Int, id)
    XCTAssertEqual(clock.requestedSleeps().map(Int.init), expected["retry_delays_ms"] as? [Int], id)
    XCTAssertEqual(clock.wallMillisecondsValue, Int64(try XCTUnwrap(expected["wall_end_ms"] as? Int)), id)
    XCTAssertEqual(
      clock.monotonicMillisecondsValue,
      UInt64(try XCTUnwrap(expected["monotonic_end_ms"] as? Int)),
      id)
    await controller.close()
  }

  func testRetryNowReportsWakeWhenTheCallingTaskIsCancelled() async throws {
    let source = RetryableFailureArtifactSourceV3()
    let controller = try ConnectionController(source: source)
    await controller.start()
    let waiting = await waitForState(.waiting, controller: controller)
    XCTAssertTrue(waiting)

    let caller = Task { await controller.retryNow() }
    caller.cancel()
    let woke = await caller.value
    XCTAssertTrue(woke)
    await controller.close()
  }

  private func runSecurityAggregationVectorV3(_ id: String) async throws {
    let expected = try controllerExpectedV3(id)
    let input = try controllerInputV3(id)
    if id == "race-order-independent-security-priority" {
      let permutations = try XCTUnwrap(input["permutations"] as? [[String]])
      try await runSecurityCompletionPermutationsV3(
        permutations, expected: expected, scenarioID: id)
      return
    }
    let retired = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: caOnlyArtifactV3(), retired: retired)
    ])
    let attempts = AsyncCounterV3()
    let expectedAttempts = try XCTUnwrap(expected["connect_attempts"] as? Int)
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { _, _ in
        for _ in 0..<expectedAttempts { _ = await attempts.increment() }
        throw ControllerConnectFailureV3.connection(
          .transportSecurityFailed, .terminal, policyTriggerIDs: [],
          opaquePolicyTriggerIDs: [], failedIDs: ["w-ca"])
      })
    await controller.start()
    assertTrueV3(await waitForState(.failed, controller: controller), id)
    let snapshot = await controller.snapshot()
    let actualAttempts = await attempts.value
    let retirements = await retired.value
    XCTAssertEqual(snapshot.failure, .connection(.transportSecurityFailed), id)
    XCTAssertEqual(actualAttempts, expectedAttempts, id)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int, id)
    await controller.close()
  }

  private func runSecurityCompletionPermutationsV3(
    _ permutations: [[String]], expected: [String: Any], scenarioID: String
  ) async throws {
    let outcomeSet = Set(["tls_unsupported", "tls_failed", "connection_failed"])
    XCTAssertEqual(permutations.count, 6, scenarioID)
    var uniquePermutations = Set<String>()
    for permutation in permutations {
      XCTAssertEqual(permutation.count, outcomeSet.count, scenarioID)
      XCTAssertEqual(Set(permutation), outcomeSet, scenarioID)
      XCTAssertTrue(
        uniquePermutations.insert(permutation.joined(separator: ",")).inserted,
        "duplicate completion permutation \(permutation) in \(scenarioID)")
    }
    XCTAssertEqual(uniquePermutations.count, 6, scenarioID)

    let expectedAttempts = try XCTUnwrap(expected["connect_attempts"] as? Int)
    let expectedTransports = try XCTUnwrap(expected["transports_created"] as? Int)
    let expectedAcquisitions = try XCTUnwrap(expected["acquisitions"] as? Int)
    let expectedRetirements = try XCTUnwrap(expected["retire_callbacks"] as? Int)
    let expectedSpends = try XCTUnwrap(expected["spend_callbacks"] as? Int)
    let expectedPublicError = try XCTUnwrap(expected["public_error"] as? String)
    let expectedDisposition = try XCTUnwrap(expected["disposition"] as? String)
    XCTAssertEqual(expected["order_independent"] as? Bool, true, scenarioID)

    for permutation in permutations {
      let label = "\(scenarioID): \(permutation.joined(separator: " -> "))"
      let spent = AsyncCounterV3()
      let retired = AsyncCounterV3()
      let runtime = PermutationFailureRuntimeV3()
      let source = SequenceArtifactSourceV3([
        try lease(artifact: threeFailureCandidateArtifactV3(), spent: spent, retired: retired)
      ])
      let controller = try ConnectionController(
        source: source,
        connectOneShot: { lease, options in
          try await SessionConnectorV3(
            lease: lease, options: options, runtime: runtime,
            currentUnixSeconds: { 1_900_000_000 }
          ).connectForController()
        })

      await controller.start()
      await runtime.waitForAllCandidates(expectedCount: expectedAttempts)
      for outcome in permutation { await runtime.complete(outcome) }
      assertTrueV3(await waitForState(.failed, controller: controller), label)

      let snapshot = await controller.snapshot()
      let runtimeSnapshot = await runtime.snapshot()
      let acquisitions = await source.acquisitions
      let spendCount = await spent.value
      let retireCount = await retired.value
      XCTAssertEqual(snapshot.state.rawValue, expected["final_state"] as? String, label)
      XCTAssertEqual(snapshot.attempt, UInt64(expectedAcquisitions), label)
      guard case .connection(let failure) = snapshot.failure else {
        XCTFail("expected public connection failure for \(label)")
        await controller.close()
        continue
      }
      XCTAssertEqual(failure.code.rawValue, expectedPublicError, label)
      XCTAssertEqual(failure.retryDisposition, .terminal, label)
      XCTAssertEqual(snapshot.retryDisposition, .terminal, label)
      XCTAssertEqual(expectedDisposition, "terminal", label)
      XCTAssertEqual(acquisitions, expectedAcquisitions, label)
      XCTAssertEqual(runtimeSnapshot.arrivals, expectedAttempts, label)
      XCTAssertEqual(runtimeSnapshot.arrivals, expectedTransports, label)
      XCTAssertEqual(runtimeSnapshot.completions, permutation, label)
      XCTAssertEqual(spendCount, expectedSpends, label)
      XCTAssertEqual(retireCount, expectedRetirements, label)
      XCTAssertEqual(expected["lease_terminal_states"] as? [String], ["retired"], label)
      await controller.close()
    }
  }

  private func runFailureOrdinalVectorV3(_ id: String) async throws {
    let expected = try controllerExpectedV3(id)
    let clock = VectorManualClockV3(wallMilliseconds: 0, monotonicMilliseconds: 0)
    let retired = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), retired: retired)
    ])
    let attempts = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      clock: clock.controllerClock,
      connectOneShot: { _, _ in
        _ = await attempts.increment()
        _ = await attempts.increment()
        throw ConnectError.connectionFailed
      })
    await controller.start()
    assertTrueV3(await waitForState(.waiting, controller: controller), id)
    assertTrueV3(await clock.waitForSleepCount(1), id)
    let snapshot = await controller.snapshot()
    let actualAttempts = await attempts.value
    let retirements = await retired.value
    XCTAssertEqual(snapshot.state.rawValue, expected["final_state"] as? String, id)
    XCTAssertEqual(actualAttempts, expected["connect_attempts"] as? Int, id)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int, id)
    XCTAssertEqual(clock.requestedSleeps().first, 250, id)
    await controller.close()
  }

  private func runExpiryBoundaryVectorV3(_ id: String) async throws {
    let expected = try controllerExpectedV3(id)
    let clock = VectorManualClockV3(wallMilliseconds: 0, monotonicMilliseconds: 0)
    let spent = AsyncCounterV3()
    let retired = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), spent: spent, retired: retired)
    ])
    let attempts = AsyncCounterV3()
    let preRace = id == "artifact-expiry-before-race"
    let postSpend = id == "artifact-expiry-after-spend"
    let controller = try ConnectionController(
      source: source,
      clock: clock.controllerClock,
      connectOneShot: { lease, _ in
        if !preRace { _ = await attempts.increment() }
        if postSpend {
          let claimed = try await lease.claim()
          try await claimed.commitSpend()
        }
        throw ConnectError.expiredArtifact
      })
    await controller.start()
    assertTrueV3(await waitForState(.waiting, controller: controller), id)
    assertTrueV3(await clock.waitForSleepCount(1), id)
    let actualAttempts = await attempts.value
    let spends = await spent.value
    let retirements = await retired.value
    XCTAssertEqual(actualAttempts, expected["connect_attempts"] as? Int, id)
    XCTAssertEqual(spends, expected["spend_callbacks"] as? Int, id)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int, id)
    XCTAssertEqual(expected["credential_bytes_written"] as? Int, 0, id)
    await controller.close()
  }

  private func runCycleResetVectorV3(_ id: String) async throws {
    let expected = try controllerExpectedV3(id)
    let clock = VectorManualClockV3(wallMilliseconds: 0, monotonicMilliseconds: 0)
    let spent = AsyncCounterV3()
    let retired = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), spent: spent, retired: retired),
      try lease(artifact: artifactV3(), spent: spent, retired: retired),
      try lease(artifact: artifactV3(), spent: spent, retired: retired),
    ])
    let first = ControllerSessionV3()
    let second = ControllerSessionV3()
    let calls = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      clock: clock.controllerClock,
      connectOneShot: { lease, _ in
        let call = await calls.increment()
        if call == 1 { throw ConnectError.connectionFailed }
        let claimed = try await lease.claim()
        try await claimed.commitSpend()
        return call == 2 ? first : second
      })
    await controller.start()
    assertTrueV3(await waitForState(.waiting, controller: controller), id)
    assertTrueV3(await clock.waitForSleepCount(1), id)
    clock.advance(wallMilliseconds: 0, monotonicMilliseconds: 250)
    assertTrueV3(await waitForState(.connected, controller: controller), id)
    try await first.close()
    assertTrueV3(await waitForState(.waiting, controller: controller), id)
    let waitingSnapshot = await controller.snapshot()
    XCTAssertEqual(waitingSnapshot.attempt, 0, id)
    assertTrueV3(await clock.waitForSleepCount(2), id)
    clock.advance(wallMilliseconds: 0, monotonicMilliseconds: 250)
    assertTrueV3(await waitForState(.connected, controller: controller), id)
    let acquisitions = await source.acquisitions
    let attempts = await calls.value
    let spends = await spent.value
    let retirements = await retired.value
    XCTAssertEqual(acquisitions, expected["acquisitions"] as? Int, id)
    XCTAssertEqual(attempts, expected["connect_attempts"] as? Int, id)
    XCTAssertEqual(spends, expected["spend_callbacks"] as? Int, id)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int, id)
    XCTAssertEqual(clock.requestedSleeps(), [250, 250], id)
    await controller.close()
  }

  private func runTerminalCycleResetVectorV3(_ id: String) async throws {
    let expected = try controllerExpectedV3(id)
    let spent = AsyncCounterV3()
    let retired = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), spent: spent, retired: retired),
    ])
    let session = ControllerSessionV3(terminationError: .operationFailed)
    let calls = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { lease, _ in
        _ = await calls.increment()
        let claimed = try await lease.claim()
        try await claimed.commitSpend()
        return session
      })
    await controller.start()
    assertTrueV3(await waitForState(.connected, controller: controller), id)
    try await session.close()
    assertTrueV3(await waitForState(.failed, controller: controller), id)
    let snapshot = await controller.snapshot()
    let acquisitions = await source.acquisitions
    let attempts = await calls.value
    let spends = await spent.value
    let retirements = await retired.value
    XCTAssertEqual(snapshot.attempt, (expected["attempt"] as? NSNumber)?.uint64Value, id)
    XCTAssertEqual(snapshot.failure, .session(.operationFailed), id)
    XCTAssertEqual(snapshot.retryDisposition, .terminal, id)
    XCTAssertEqual(acquisitions, expected["acquisitions"] as? Int, id)
    XCTAssertEqual(attempts, expected["connect_attempts"] as? Int, id)
    XCTAssertEqual(spends, expected["spend_callbacks"] as? Int, id)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int, id)
    XCTAssertEqual(expected["failure_ordinal"] as? Int, 1, id)
    await controller.close()
  }

  private func runClockBoundaryVectorV3(_ id: String) async throws {
    let expected = try controllerExpectedV3(id)
    let input = try controllerInputV3(id)
    let expectedSleeps = try XCTUnwrap(expected["retry_delays_ms"] as? [Int]).map(UInt64.init)
    let failureOrdinal = try XCTUnwrap(input["failure_ordinal"] as? Int)
    XCTAssertGreaterThan(failureOrdinal, 0, id)
    let wallStart = Int64(try XCTUnwrap(input["wall_start_ms"] as? Int))
    let monotonicStart = UInt64(try XCTUnwrap(input["monotonic_start_ms"] as? NSNumber).uint64Value)
    let clock = VectorManualClockV3(
      wallMilliseconds: wallStart, monotonicMilliseconds: monotonicStart)

    if id == "monotonic-timer-safe-integer-saturation" {
      let session = ControllerSessionV3()
      let source = ResultArtifactSourceV3([
        .failure(ArtifactSourceFailure(disposition: .retryable)),
        .success(try lease(artifact: artifactV3(), retired: AsyncCounterV3())),
      ])
      let controller = try ConnectionController(
        source: source,
        clock: clock.controllerClock,
        connectOneShot: { lease, _ in
          let claimed = try await lease.claim()
          try await claimed.commitSpend()
          return session
        })
      await controller.start()
      let waiting = await waitForState(.waiting, controller: controller)
      XCTAssertTrue(waiting, id)
      assertTrueV3(await clock.waitForSleepCount(1), id)
      XCTAssertEqual(clock.requestedSleeps(), expectedSleeps, id)
      clock.advance(wallMilliseconds: 0, monotonicMilliseconds: 1)
      let connected = await waitForState(.connected, controller: controller)
      XCTAssertTrue(connected, id)
      XCTAssertEqual(expected["timer_saturated"] as? Bool, true, id)
      await controller.close()
      return
    }

    let retryAtMilliseconds = Int64(try XCTUnwrap(input["retry_after_unix_ms"] as? Int))
    let deadline = UInt64(retryAtMilliseconds)
    var sourceResults = Array(
      repeating: Result<ArtifactLeaseV3, ArtifactSourceFailure>.failure(
        ArtifactSourceFailure(disposition: .retryable)),
      count: failureOrdinal - 1)
    sourceResults.append(.failure(ArtifactSourceFailure(disposition: .retryAfter(deadline))))
    sourceResults.append(.success(try lease(artifact: artifactV3(), retired: AsyncCounterV3())))
    let source = ResultArtifactSourceV3(sourceResults)
    let session = ControllerSessionV3()
    let controller = try ConnectionController(
      source: source,
      clock: clock.controllerClock,
      connectOneShot: { lease, _ in
        let claimed = try await lease.claim()
        try await claimed.commitSpend()
        return session
      })
    await controller.start()
    for acquisition in 1..<failureOrdinal {
      assertTrueV3(
        await waitUntilV3 { await source.acquisitions >= acquisition },
        "\(id) acquisition \(acquisition)")
      assertTrueV3(await clock.waitForSleepCount(acquisition), "\(id) sleep \(acquisition)")
      assertTrueV3(await controller.retryNow(), "\(id) retryNow \(acquisition)")
    }
    assertTrueV3(
      await waitUntilV3 { await source.acquisitions >= failureOrdinal }, "\(id) target acquisition")
    let sleepOffset = failureOrdinal - 1
    let waiting = await waitForState(.waiting, controller: controller)
    XCTAssertTrue(waiting, id)
    assertTrueV3(await clock.waitForSleepCount(sleepOffset + 1), id)

    switch id {
    case "retry-after-wall-clock-forward-jump":
      clock.advance(wallMilliseconds: 5_000, monotonicMilliseconds: 250)
      let connected = await waitForState(.connected, controller: controller)
      XCTAssertTrue(connected, id)
    case "retry-after-wall-clock-backward-jump":
      clock.advance(wallMilliseconds: -2_000, monotonicMilliseconds: 1_000)
      assertTrueV3(await clock.waitForSleepCount(sleepOffset + 2), id)
      clock.advance(wallMilliseconds: 3_000, monotonicMilliseconds: 1_000)
      let connected = await waitForState(.connected, controller: controller)
      XCTAssertTrue(connected, id)
    case "retry-after-wall-reread-bounded":
      XCTAssertEqual(expected["maximum_wall_reread_ms"] as? Int, 1_000, id)
      clock.advance(wallMilliseconds: 1_000, monotonicMilliseconds: 1_000)
      assertTrueV3(await clock.waitForSleepCount(sleepOffset + 2), id)
      let snapshot = await controller.snapshot()
      XCTAssertEqual(snapshot.state, .waiting, id)
    default:
      XCTFail("unexpected clock boundary vector \(id)")
    }
    XCTAssertEqual(
      Array(clock.requestedSleeps().dropFirst(sleepOffset).prefix(expectedSleeps.count)),
      expectedSleeps,
      id)
    await controller.close()
  }

  private func runMultiTriggerVectorV3(_ id: String) async throws {
    let expected = try controllerExpectedV3(id)
    let retired = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: twoPinArtifactV3(), retired: retired),
      try lease(artifact: changedOneOfTwoPinsArtifactV3(), retired: retired),
    ])
    let calls = AsyncCounterV3()
    let replacementCandidates = CandidateIDRecorderV3()
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { lease, _ in
        let call = await calls.increment()
        if call == 2 {
          await replacementCandidates.record(Set(lease.artifact.canonicalCandidates.map(\.id)))
        }
        throw ControllerConnectFailureV3.connection(
          .transportSecurityFailed, .terminal,
          policyTriggerIDs: call == 1 ? ["t-pin", "w-pin"] : ["w-pin"],
          opaquePolicyTriggerIDs: [],
          failedIDs: Set(lease.artifact.canonicalCandidates.map(\.id)))
      })
    await controller.start()
    let failed = await waitForState(.failed, controller: controller)
    XCTAssertTrue(failed, id)
    let acquisitions = await source.acquisitions
    let attempts = await calls.value
    let retirements = await retired.value
    let candidates = await replacementCandidates.value
    XCTAssertEqual(acquisitions, expected["acquisitions"] as? Int, id)
    XCTAssertEqual(attempts, expected["connect_attempts"] as? Int, id)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int, id)
    XCTAssertEqual(candidates, ["w-pin"], id)
    XCTAssertEqual(expected["no_mode_downgrade"] as? Bool, true, id)
    await controller.close()
  }

  private func runRetireCleanupVectorV3(_ id: String) async throws {
    let expected = try controllerExpectedV3(id)
    let clock = VectorManualClockV3(wallMilliseconds: 0, monotonicMilliseconds: 0)
    let retired = AsyncCounterV3()
    let spent = AsyncCounterV3()
    let first = ArtifactLeaseV3(
      artifact: try artifactV3(),
      commitSpend: {},
      retire: {
        _ = await retired.increment()
        throw VectorControllerErrorV3.retireFailed
      })
    let second = try lease(artifact: artifactV3(), spent: spent, retired: retired)
    let source = SequenceArtifactSourceV3([first, second])
    let calls = AsyncCounterV3()
    let session = ControllerSessionV3()
    let controller = try ConnectionController(
      source: source,
      clock: clock.controllerClock,
      connectOneShot: { lease, _ in
        if await calls.increment() == 1 { throw ConnectError.connectionFailed }
        let claimed = try await lease.claim()
        try await claimed.commitSpend()
        return session
      })
    await controller.start()
    let waiting = await waitForState(.waiting, controller: controller)
    XCTAssertTrue(waiting, id)
    assertTrueV3(await clock.waitForSleepCount(1), id)
    clock.advance(wallMilliseconds: 0, monotonicMilliseconds: 250)
    let connected = await waitForState(.connected, controller: controller)
    XCTAssertTrue(connected, id)
    let acquisitions = await source.acquisitions
    let attempts = await calls.value
    let spends = await spent.value
    let retirements = await retired.value
    XCTAssertEqual(acquisitions, expected["acquisitions"] as? Int, id)
    XCTAssertEqual(attempts, expected["connect_attempts"] as? Int, id)
    XCTAssertEqual(spends, expected["spend_callbacks"] as? Int, id)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int, id)
    XCTAssertEqual(expected["cleanup_error_ignored"] as? Bool, true, id)
    await controller.close()
  }

  private func runQuotaPreservationVectorV3(_ id: String) async throws {
    let expected = try controllerExpectedV3(id)
    let clock = VectorManualClockV3(wallMilliseconds: 0, monotonicMilliseconds: 0)
    let retired = AsyncCounterV3()
    let spent = AsyncCounterV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), retired: retired),
      try lease(artifact: artifactV3(), retired: retired),
      try lease(artifact: changedPinArtifactV3(), spent: spent, retired: retired),
    ])
    let calls = AsyncCounterV3()
    let session = ControllerSessionV3()
    let controller = try ConnectionController(
      source: source,
      clock: clock.controllerClock,
      connectOneShot: { lease, _ in
        switch await calls.increment() {
        case 1: throw ConnectError.connectionFailed
        case 2: throw nativePinFailureV3()
        default:
          let claimed = try await lease.claim()
          try await claimed.commitSpend()
          return session
        }
      })
    await controller.start()
    let waiting = await waitForState(.waiting, controller: controller)
    XCTAssertTrue(waiting, id)
    assertTrueV3(await clock.waitForSleepCount(1), id)
    clock.advance(wallMilliseconds: 0, monotonicMilliseconds: 250)
    let connected = await waitForState(.connected, controller: controller)
    XCTAssertTrue(connected, id)
    let acquisitions = await source.acquisitions
    let attempts = await calls.value
    let spends = await spent.value
    let retirements = await retired.value
    XCTAssertEqual(acquisitions, expected["acquisitions"] as? Int, id)
    XCTAssertEqual(attempts, expected["connect_attempts"] as? Int, id)
    XCTAssertEqual(spends, expected["spend_callbacks"] as? Int, id)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int, id)
    await controller.close()
  }

  private func runAttemptSaturationVectorV3(_ id: String) async throws {
    let expected = try controllerExpectedV3(id)
    let maxSafe = UInt64(9_007_199_254_740_991)
    let source = NeverArtifactSourceV3()
    let controller = try ConnectionController(
      source: source,
      maximumAttempts: maxSafe,
      initialAttempt: maxSafe,
      connectOneShot: { _, _ in throw ConnectError.connectionFailed })
    await controller.start()
    let connecting = await waitForState(.connecting, controller: controller)
    XCTAssertTrue(connecting, id)
    let snapshot = await controller.snapshot()
    XCTAssertEqual(snapshot.attempt, maxSafe, id)
    XCTAssertEqual(
      snapshot.attempt, UInt64(try XCTUnwrap(expected["attempt"] as? NSNumber).uint64Value), id)
    XCTAssertEqual(expected["counter_saturated"] as? Bool, true, id)
    await controller.close()
  }

  private func runCapabilityBarrierVectorV3(_ id: String) async throws {
    let expected = try controllerExpectedV3(id)
    let retired = AsyncCounterV3()
    let runtime = CapabilityInvalidatingRuntimeV3()
    let source = SequenceArtifactSourceV3([
      try lease(artifact: artifactV3(), retired: retired)
    ])
    let controller = try ConnectionController(
      source: source,
      connectOneShot: { lease, options in
        try await SessionConnectorV3(
          lease: lease, options: options, runtime: runtime,
          currentUnixSeconds: { 1_900_000_000 }
        ).connectForController()
      })
    await controller.start()
    await runtime.waitForPrepareArrival()
    await runtime.invalidateAndRelease()
    let failed = await waitForState(.failed, controller: controller)
    XCTAssertTrue(failed, id)
    let snapshot = await controller.snapshot()
    let preparations = await runtime.prepareCount
    let transports = await runtime.transportCount
    let retirements = await retired.value
    XCTAssertEqual(snapshot.failure, .connection(.transportSecurityUnsupported), id)
    XCTAssertEqual(preparations, expected["connect_attempts"] as? Int, id)
    XCTAssertEqual(transports, expected["transports_created"] as? Int, id)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int, id)
    XCTAssertEqual(expected["capability_rechecked"] as? Bool, true, id)
    await controller.close()
  }

  private func runAdmissionBoundaryVectorV3(_ id: String) async throws {
    let expected = try controllerExpectedV3(id)
    let clock = VectorManualClockV3(wallMilliseconds: 0, monotonicMilliseconds: 0)
    let replacement = id.hasPrefix("replacement-")
    let retryable = id.contains("retryable") || id.contains("fsh3")
    let retired = AsyncCounterV3()
    let spent = AsyncCounterV3()
    var leases = [try lease(artifact: artifactV3(), spent: spent, retired: retired)]
    if replacement {
      leases.append(
        try lease(artifact: changedPinArtifactV3(), spent: spent, retired: retired))
    }
    let source = SequenceArtifactSourceV3(leases)
    let calls = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      clock: clock.controllerClock,
      connectOneShot: { lease, _ in
        let call = await calls.increment()
        if replacement && call == 1 { throw nativePinFailureV3() }
        let claimed = try await lease.claim()
        try await claimed.commitSpend()
        if id.contains("fsa3") {
          throw ControllerConnectFailureV3.connection(
            .connectionFailed, retryable ? .retryable : .terminal,
            policyTriggerIDs: [], opaquePolicyTriggerIDs: [], failedIDs: [])
        }
        throw ConnectError.connectionFailed
      })
    await controller.start()
    let wantedState: ConnectionState = retryable ? .waiting : .failed
    let reached = await waitForState(wantedState, controller: controller)
    XCTAssertTrue(reached, id)
    if retryable { assertTrueV3(await clock.waitForSleepCount(1), id) }
    let acquisitions = await source.acquisitions
    let attempts = await calls.value
    let spends = await spent.value
    let retirements = await retired.value
    let snapshot = await controller.snapshot()
    XCTAssertEqual(snapshot.state.rawValue, expected["final_state"] as? String, id)
    XCTAssertEqual(acquisitions, expected["acquisitions"] as? Int, id)
    XCTAssertEqual(attempts, expected["connect_attempts"] as? Int, id)
    XCTAssertEqual(spends, expected["spend_callbacks"] as? Int, id)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int, id)
    if retryable {
      XCTAssertEqual(clock.requestedSleeps().first, replacement ? 500 : 250, id)
    }
    await controller.close()
  }

  private func runDuplicateLeaseVectorV3(_ id: String) async throws {
    let expected = try controllerExpectedV3(id)
    let clock = VectorManualClockV3(wallMilliseconds: 0, monotonicMilliseconds: 0)
    let consumed = id.hasSuffix("consumed-lease")
    let spent = AsyncCounterV3()
    let retired = AsyncCounterV3()
    let repeated = try lease(artifact: artifactV3(), spent: spent, retired: retired)
    let source = SequenceArtifactSourceV3([repeated, repeated])
    let calls = AsyncCounterV3()
    let controller = try ConnectionController(
      source: source,
      clock: clock.controllerClock,
      connectOneShot: { lease, _ in
        _ = await calls.increment()
        if consumed {
          let claimed = try await lease.claim()
          try await claimed.commitSpend()
        }
        throw ConnectError.connectionFailed
      })
    await controller.start()
    let waiting = await waitForState(.waiting, controller: controller)
    XCTAssertTrue(waiting, id)
    assertTrueV3(await clock.waitForSleepCount(1), id)
    clock.advance(wallMilliseconds: 0, monotonicMilliseconds: 250)
    let failed = await waitForState(.failed, controller: controller)
    XCTAssertTrue(failed, id)
    let snapshot = await controller.snapshot()
    let acquisitions = await source.acquisitions
    let attempts = await calls.value
    let spends = await spent.value
    let retirements = await retired.value
    XCTAssertEqual(snapshot.failure, .connection(.artifactInvalid), id)
    XCTAssertEqual(acquisitions, expected["acquisitions"] as? Int, id)
    XCTAssertEqual(attempts, expected["connect_attempts"] as? Int, id)
    XCTAssertEqual(spends, expected["spend_callbacks"] as? Int, id)
    XCTAssertEqual(retirements, expected["retire_callbacks"] as? Int, id)
    await controller.close()
  }

  private func waitForState(
    _ expected: ConnectionState,
    controller: ConnectionController,
    timeout: Duration = .seconds(2)
  ) async -> Bool {
    let deadline = ContinuousClock.now + timeout
    while ContinuousClock.now < deadline {
      if await controller.snapshot().state == expected { return true }
      await Task.yield()
    }
    return await controller.snapshot().state == expected
  }
}

private func nativePinFailureV3(
  disposition: RetryDispositionV3 = .terminal,
  failedIDs: Set<String> = ["w-pin"]
) -> ControllerConnectFailureV3 {
  .connection(
    .transportSecurityFailed,
    disposition,
    policyTriggerIDs: failedIDs,
    opaquePolicyTriggerIDs: [],
    failedIDs: failedIDs)
}

private func controllerVectorsV3() throws -> [String: Any] {
  let url = packageRootV3().appendingPathComponent("testdata/transport_v3/controller_vectors.json")
  return try XCTUnwrap(
    JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
}

private func validRetryAfterVectorValue(_ value: Any) -> Bool {
  guard let number = value as? NSNumber else { return false }
  let scalar = number.doubleValue
  return scalar.isFinite && scalar.rounded(.towardZero) == scalar && scalar >= 0
    && scalar <= 253_402_300_799_999
}

private func assertThrowsArtifactLeaseUnavailable(
  _ operation: () async throws -> ClaimedArtifactLeaseV3,
  file: StaticString = #filePath,
  line: UInt = #line
) async {
  do {
    _ = try await operation()
    XCTFail("expected ArtifactLeaseErrorV3.unavailable", file: file, line: line)
  } catch {
    XCTAssertEqual(error as? ArtifactLeaseErrorV3, .unavailable, file: file, line: line)
  }
}

private func controllerExpectedV3(_ id: String) throws -> [String: Any] {
  let root = try controllerVectorsV3()
  let scenarios = try XCTUnwrap(root["scenarios"] as? [[String: Any]])
  let scenario = try XCTUnwrap(scenarios.first { $0["id"] as? String == id })
  return try XCTUnwrap(scenario["expected"] as? [String: Any])
}

private func controllerInputV3(_ id: String) throws -> [String: Any] {
  let root = try controllerVectorsV3()
  let scenarios = try XCTUnwrap(root["scenarios"] as? [[String: Any]])
  let scenario = try XCTUnwrap(scenarios.first { $0["id"] as? String == id })
  return try XCTUnwrap(scenario["input"] as? [String: Any])
}

private func artifactV3() throws -> ArtifactV3 {
  try mutateArtifactV3 { root in
    var path = root["path"] as! [String: Any]
    let candidates = path["candidates"] as! [[String: Any]]
    path["candidates"] = candidates.filter { $0["id"] as? String == "w-pin" }
    root["path"] = path
  }
}

private func baseArtifactV3() throws -> ArtifactV3 {
  let url = packageRootV3().appendingPathComponent("testdata/transport_v3/artifact_vectors.json")
  let root = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
  let positive = root["positive"] as! [[String: Any]]
  return try parseArtifactV3(Data((positive[0]["artifact_json"] as! String).utf8))
}

private func changedPinArtifactV3() throws -> ArtifactV3 {
  try mutateArtifactV3 { root in
    var path = root["path"] as! [String: Any]
    var candidates = path["candidates"] as! [[String: Any]]
    let index = candidates.firstIndex { $0["id"] as? String == "w-pin" }!
    candidates[index]["tls"] = [
      "mode": "pin",
      "pins": [
        [
          "algorithm": "sha-256",
          "not_after_unix_s": 2_000_000_500,
          "value_b64u": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo",
        ]
      ],
    ]
    path["candidates"] = [candidates[index]]
    root["path"] = path
  }
}

private func changedPinWithCAArtifactV3() throws -> ArtifactV3 {
  try mutateArtifactV3 { root in
    var path = root["path"] as! [String: Any]
    var candidates = path["candidates"] as! [[String: Any]]
    let pinIndex = candidates.firstIndex { $0["id"] as? String == "w-pin" }!
    candidates[pinIndex]["tls"] = [
      "mode": "pin",
      "pins": [[
        "algorithm": "sha-256",
        "not_after_unix_s": 2_000_000_500,
        "value_b64u": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo",
      ]],
    ]
    path["candidates"] = candidates.filter { ["w-pin", "w-ca"].contains($0["id"] as? String) }
    root["path"] = path
  }
}

private func changedPinExpiryArtifactV3() throws -> ArtifactV3 {
  try mutateArtifactV3 { root in
    var path = root["path"] as! [String: Any]
    var candidates = path["candidates"] as! [[String: Any]]
    let index = candidates.firstIndex { $0["id"] as? String == "w-pin" }!
    var tls = candidates[index]["tls"] as! [String: Any]
    var pins = tls["pins"] as! [[String: Any]]
    pins[0]["not_after_unix_s"] = (pins[0]["not_after_unix_s"] as! Int) + 1
    tls["pins"] = pins
    candidates[index]["tls"] = tls
    path["candidates"] = [candidates[index]]
    root["path"] = path
  }
}

private func caOnlyArtifactV3() throws -> ArtifactV3 {
  let original = try baseArtifactV3()
  var root = try JSONSerialization.jsonObject(with: original.canonicalJSON) as! [String: Any]
  var path = root["path"] as! [String: Any]
  let candidates = path["candidates"] as! [[String: Any]]
  path["candidates"] = candidates.filter { $0["id"] as? String == "w-ca" }
  root["path"] = path
  return try parseArtifactV3(FlowersecJCSV3.encode(root))
}

private func threeFailureCandidateArtifactV3() throws -> ArtifactV3 {
  try mutateArtifactV3 { root in
    var path = root["path"] as! [String: Any]
    let candidates = path["candidates"] as! [[String: Any]]
    path["candidates"] = candidates.filter {
      ["w-ca", "q-pin", "t-pin"].contains($0["id"] as? String)
    }
    root["path"] = path
  }
}

private func mixedCAPinArtifactV3() throws -> ArtifactV3 {
  try mutateArtifactV3 { root in
    var path = root["path"] as! [String: Any]
    let candidates = path["candidates"] as! [[String: Any]]
    path["candidates"] = candidates.filter {
      ["w-ca", "w-pin"].contains($0["id"] as? String)
    }
    root["path"] = path
  }
}

private func twoPinArtifactV3() throws -> ArtifactV3 {
  try mutateArtifactV3 { root in
    var path = root["path"] as! [String: Any]
    let candidates = path["candidates"] as! [[String: Any]]
    path["candidates"] = candidates.filter {
      ["t-pin", "w-pin"].contains($0["id"] as? String)
    }
    root["path"] = path
  }
}

private func changedOneOfTwoPinsArtifactV3() throws -> ArtifactV3 {
  try mutateArtifactV3 { root in
    var path = root["path"] as! [String: Any]
    var candidates = path["candidates"] as! [[String: Any]]
    let index = candidates.firstIndex { $0["id"] as? String == "w-pin" }!
    candidates[index]["tls"] = [
      "mode": "pin",
      "pins": [
        [
          "algorithm": "sha-256",
          "not_after_unix_s": 2_000_000_500,
          "value_b64u": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo",
        ]
      ],
    ]
    path["candidates"] = candidates.filter {
      ["t-pin", "w-pin"].contains($0["id"] as? String)
    }
    root["path"] = path
  }
}

private func expiredArtifactV3() throws -> ArtifactV3 {
  try mutateArtifactV3 { root in
    var session = root["session"] as! [String: Any]
    session["init_expire_at_unix_s"] = 1
    root["session"] = session
  }
}

private func mutateArtifactV3(
  _ mutate: (inout [String: Any]) -> Void
) throws -> ArtifactV3 {
  let original = try baseArtifactV3()
  var root = try JSONSerialization.jsonObject(with: original.canonicalJSON) as! [String: Any]
  mutate(&root)
  return try parseArtifactV3(FlowersecJCSV3.encode(root))
}

private func lease(
  artifact: ArtifactV3,
  spent: AsyncCounterV3 = AsyncCounterV3(),
  retired: AsyncCounterV3
) throws -> ArtifactLeaseV3 {
  ArtifactLeaseV3(
    artifact: artifact,
    commitSpend: { _ = await spent.increment() },
    retire: { _ = await retired.increment() }
  )
}

private func packageRootV3() -> URL {
  URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    .deletingLastPathComponent()
}

private actor SequenceArtifactSourceV3: ArtifactSource {
  private var leases: [ArtifactLeaseV3]
  private(set) var acquisitions = 0

  init(_ leases: [ArtifactLeaseV3]) { self.leases = leases }

  func acquireArtifact() throws -> ArtifactLeaseV3 {
    acquisitions += 1
    guard !leases.isEmpty else { throw ArtifactSourceFailure(disposition: .terminal) }
    return leases.removeFirst()
  }
}

private actor ResultArtifactSourceV3: ArtifactSource {
  private var results: [Result<ArtifactLeaseV3, ArtifactSourceFailure>]
  private(set) var acquisitions = 0

  init(_ results: [Result<ArtifactLeaseV3, ArtifactSourceFailure>]) { self.results = results }

  func acquireArtifact() throws -> ArtifactLeaseV3 {
    acquisitions += 1
    guard !results.isEmpty else { throw ArtifactSourceFailure(disposition: .terminal) }
    return try results.removeFirst().get()
  }
}

private actor RetryableFailureArtifactSourceV3: ArtifactSource {
  private(set) var acquisitions = 0

  func acquireArtifact() throws -> ArtifactLeaseV3 {
    acquisitions += 1
    throw ArtifactSourceFailure(disposition: .retryable)
  }
}

private actor BlockingArtifactSourceV3: ArtifactSource {
  private let lease: ArtifactLeaseV3
  private var released = false
  private var waiters: [CheckedContinuation<Void, Never>] = []
  private(set) var acquisitions = 0

  init(_ lease: ArtifactLeaseV3) { self.lease = lease }

  func acquireArtifact() async throws -> ArtifactLeaseV3 {
    acquisitions += 1
    if !released {
      await withCheckedContinuation { waiters.append($0) }
    }
    return lease
  }

  func release() {
    released = true
    let current = waiters
    waiters.removeAll()
    for waiter in current { waiter.resume() }
  }
}

private actor BlockingErrorArtifactSourceV3: ArtifactSource {
  private var released = false
  private var waiters: [CheckedContinuation<Void, Never>] = []
  private(set) var acquisitions = 0

  func acquireArtifact() async throws -> ArtifactLeaseV3 {
    acquisitions += 1
    if !released {
      await withCheckedContinuation { waiters.append($0) }
    }
    throw LateArtifactSourceErrorV3.unexpected
  }

  func release() {
    released = true
    let current = waiters
    waiters.removeAll()
    for waiter in current { waiter.resume() }
  }
}

private enum LateArtifactSourceErrorV3: Error {
  case unexpected
}

private actor NeverArtifactSourceV3: ArtifactSource {
  func acquireArtifact() async throws -> ArtifactLeaseV3 {
    try await Task.sleep(for: .seconds(60))
    throw ArtifactSourceFailure(disposition: .terminal)
  }
}

private actor CapabilityInvalidatingRuntimeV3: RuntimeCarrierAdapterV3 {
  nonisolated let capabilities = RuntimeCapabilitiesV3.macOS
  private(set) var prepareCount = 0
  private(set) var transportCount = 0
  private var prepareArrived = false
  private var invalidated = false
  private var arrivalWaiters: [CheckedContinuation<Void, Never>] = []
  private var releaseWaiter: CheckedContinuation<Void, Never>?

  nonisolated func validate(options: ConnectorOptions) throws {}

  func prepare(
    candidate: CanonicalCandidateV3,
    path: PathKind,
    role: SessionRoleV3,
    options: ConnectorOptions,
    activePinHashes: [Data]?
  ) async throws -> any PreparedCarrierConnectionV3 {
    prepareCount += 1
    prepareArrived = true
    let waiters = arrivalWaiters
    arrivalWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
    await withCheckedContinuation { continuation in
      if invalidated {
        continuation.resume()
      } else {
        precondition(releaseWaiter == nil)
        releaseWaiter = continuation
      }
    }
    guard invalidated else {
      transportCount += 1
      throw ConnectorBoundaryErrorV3.runtimeFailed
    }
    throw ConnectorBoundaryErrorV3.runtimeUnsupported
  }

  func waitForPrepareArrival() async {
    if prepareArrived { return }
    await withCheckedContinuation { arrivalWaiters.append($0) }
  }

  func invalidateAndRelease() {
    invalidated = true
    let waiter = releaseWaiter
    releaseWaiter = nil
    waiter?.resume()
  }
}

private actor CapabilityLinearizationBarrierV3 {
  private var initialArrivals = 0
  private var activeInitialAcquisitions = 0
  private var released = false
  private var arrivalWaiters: [CheckedContinuation<Void, Never>] = []
  private var releaseWaiters: [CheckedContinuation<Void, Never>] = []
  private(set) var concurrentAcquisitionPeak = 0
  private(set) var capabilitySnapshots: [String] = []
  private(set) var replacementAcquisitions = 0

  func arrive() -> Int {
    let index = initialArrivals + 1
    initialArrivals = index
    if index <= 2 {
      activeInitialAcquisitions += 1
      concurrentAcquisitionPeak = max(concurrentAcquisitionPeak, activeInitialAcquisitions)
      capabilitySnapshots.append("enabled")
      if index == 2 {
        let waiters = arrivalWaiters
        arrivalWaiters.removeAll()
        for waiter in waiters { waiter.resume() }
      }
    }
    return index
  }

  func recordReplacementSnapshot() {
    capabilitySnapshots.append("ca_only")
    replacementAcquisitions += 1
  }

  func waitForInitialAcquisitions() async {
    if initialArrivals >= 2 { return }
    await withCheckedContinuation { arrivalWaiters.append($0) }
  }

  func waitForRelease() async {
    if released { return }
    await withCheckedContinuation { releaseWaiters.append($0) }
  }

  func leaveInitialAcquisition() {
    activeInitialAcquisitions = max(0, activeInitialAcquisitions - 1)
  }

  func invalidateAndRelease() {
    released = true
    let waiters = releaseWaiters
    releaseWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
  }

}

private actor CoordinatedCapabilityRuntimeV3: RuntimeCarrierAdapterV3 {
  nonisolated let capabilities = RuntimeCapabilitiesV3.macOS
  private let barrier: CapabilityLinearizationBarrierV3
  private let stale: Bool

  init(barrier: CapabilityLinearizationBarrierV3, stale: Bool) {
    self.barrier = barrier
    self.stale = stale
  }

  nonisolated func validate(options: ConnectorOptions) throws {}

  func prepare(
    candidate: CanonicalCandidateV3,
    path: PathKind,
    role: SessionRoleV3,
    options: ConnectorOptions,
    activePinHashes: [Data]?
  ) async throws -> any PreparedCarrierConnectionV3 {
    let arrival = await barrier.arrive()
    if arrival <= 2 {
      await barrier.waitForRelease()
      await barrier.leaveInitialAcquisition()
    }
    if stale { throw ConnectorBoundaryErrorV3.runtimeUnsupported }
    if candidate.id == "w-pin" { throw ConnectorBoundaryErrorV3.browserPinOpaque }
    if candidate.id == "w-ca" { throw ConnectorBoundaryErrorV3.admissionRejected }
    throw ConnectorBoundaryErrorV3.runtimeFailed
  }
}

private actor PermutationFailureRuntimeV3: RuntimeCarrierAdapterV3 {
  struct Snapshot: Sendable {
    let arrivals: Int
    let completions: [String]
  }

  nonisolated let capabilities = RuntimeCapabilityDescriptorV3(
    language: "swift", runtime: "macos", schemaVersion: 3,
    tuples: [
      RuntimeCapabilityTupleV3(
        carrier: .rawQUIC, datagrams: false, migration: false, networkMode: .dial,
        path: .direct, reliableStreams: true, securityModes: ["pin"], sessionRole: .client),
      RuntimeCapabilityTupleV3(
        carrier: .webSocket, datagrams: false, migration: false, networkMode: .dial,
        path: .direct, reliableStreams: true, securityModes: ["ca"], sessionRole: .client),
      RuntimeCapabilityTupleV3(
        carrier: .webTransport, datagrams: false, migration: false, networkMode: .dial,
        path: .direct, reliableStreams: true, securityModes: ["pin"], sessionRole: .client),
    ],
    unsupported: [])

  private var gates: [String: CheckedContinuation<Void, Never>] = [:]
  private var arrivedCandidates = Set<String>()
  private var completionOrder: [String] = []
  private var arrivalWaiters: [CheckedContinuation<Void, Never>] = []
  private var completionWaiters: [String: [CheckedContinuation<Void, Never>]] = [:]

  nonisolated func validate(options: ConnectorOptions) throws {}

  func prepare(
    candidate: CanonicalCandidateV3,
    path: PathKind,
    role: SessionRoleV3,
    options: ConnectorOptions,
    activePinHashes: [Data]?
  ) async throws -> any PreparedCarrierConnectionV3 {
    let outcome: String
    switch candidate.id {
    case "w-ca": outcome = "tls_failed"
    case "q-pin": outcome = "tls_unsupported"
    case "t-pin": outcome = "connection_failed"
    default: preconditionFailure("unexpected permutation candidate \(candidate.id)")
    }
    arrivedCandidates.insert(candidate.id)
    let waiters = arrivalWaiters
    arrivalWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
    await withCheckedContinuation { continuation in
      precondition(gates[outcome] == nil, "duplicate permutation outcome \(outcome)")
      gates[outcome] = continuation
    }
    completionOrder.append(outcome)
    let completedWaiters = completionWaiters.removeValue(forKey: outcome) ?? []
    for waiter in completedWaiters { waiter.resume() }
    switch outcome {
    case "tls_unsupported": throw ConnectorBoundaryErrorV3.runtimeUnsupported
    case "tls_failed": throw ConnectorBoundaryErrorV3.securityFailed
    case "connection_failed": throw ConnectorBoundaryErrorV3.runtimeFailed
    default: preconditionFailure("unexpected permutation outcome \(outcome)")
    }
  }

  func waitForAllCandidates(expectedCount: Int) async {
    while arrivedCandidates.count < expectedCount {
      await withCheckedContinuation { arrivalWaiters.append($0) }
    }
  }

  func complete(_ outcome: String) async {
    guard let gate = gates.removeValue(forKey: outcome) else {
      preconditionFailure("completion released before candidate arrived: \(outcome)")
    }
    gate.resume()
    if completionOrder.contains(outcome) { return }
    await withCheckedContinuation { completionWaiters[outcome, default: []].append($0) }
  }

  func snapshot() -> Snapshot {
    Snapshot(arrivals: arrivedCandidates.count, completions: completionOrder)
  }
}

private enum VectorControllerErrorV3: Error { case retireFailed }

private final class VectorManualClockV3: @unchecked Sendable {
  private static let maxSafeInteger: UInt64 = 9_007_199_254_740_991
  private let lock = NSLock()
  private var wallMilliseconds: Int64
  private var monotonicMilliseconds: UInt64
  private var wallReadOverrides: [Int64] = []
  private var sleeps: [UInt64] = []
  private var waiters: [UUID: CheckedContinuation<Void, Error>] = [:]
  private var canceled = Set<UUID>()

  init(wallMilliseconds: Int64, monotonicMilliseconds: UInt64) {
    self.wallMilliseconds = wallMilliseconds
    self.monotonicMilliseconds = monotonicMilliseconds
  }

  var controllerClock: ConnectionControllerClockV3 {
    ConnectionControllerClockV3(
      wallNow: { [self] in
        lock.withLock {
          let current =
            wallReadOverrides.isEmpty ? wallMilliseconds : wallReadOverrides.removeFirst()
          return Date(timeIntervalSince1970: Double(current) / 1_000)
        }
      },
      monotonicMilliseconds: { [self] in lock.withLock { monotonicMilliseconds } },
      sleep: { [self] duration in try await suspend(for: duration) }
    )
  }

  func advance(wallMilliseconds wallDelta: Int64, monotonicMilliseconds monotonicDelta: UInt64) {
    let continuations: [CheckedContinuation<Void, Error>] = lock.withLock {
      wallMilliseconds =
        wallMilliseconds.addingReportingOverflow(wallDelta).overflow
        ? (wallDelta >= 0 ? Int64.max : Int64.min)
        : wallMilliseconds + wallDelta
      let (sum, overflow) = monotonicMilliseconds.addingReportingOverflow(monotonicDelta)
      monotonicMilliseconds =
        overflow || sum > Self.maxSafeInteger
        ? Self.maxSafeInteger : sum
      let current = Array(waiters.values)
      waiters.removeAll()
      return current
    }
    for continuation in continuations { continuation.resume() }
  }

  func overrideNextWallRead(milliseconds: Int64) {
    lock.withLock { wallReadOverrides.append(milliseconds) }
  }

  func requestedSleeps() -> [UInt64] { lock.withLock { sleeps } }

  var wallMillisecondsValue: Int64 { lock.withLock { wallMilliseconds } }

  var monotonicMillisecondsValue: UInt64 { lock.withLock { monotonicMilliseconds } }

  func waitForSleepCount(_ count: Int, timeout: Duration = .seconds(1)) async -> Bool {
    let deadline = ContinuousClock.now + timeout
    while ContinuousClock.now < deadline {
      if lock.withLock({ sleeps.count >= count }) { return true }
      await Task.yield()
    }
    return lock.withLock { sleeps.count >= count }
  }

  private func suspend(for duration: Duration) async throws {
    let id = UUID()
    let milliseconds = durationMillisecondsV3(duration)
    try Task.checkCancellation()
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        let resumeCanceled: Bool = lock.withLock {
          sleeps.append(milliseconds)
          if canceled.remove(id) != nil { return true }
          waiters[id] = continuation
          return false
        }
        if resumeCanceled { continuation.resume(throwing: CancellationError()) }
      }
    } onCancel: {
      let continuation: CheckedContinuation<Void, Error>? = self.lock.withLock {
        self.canceled.insert(id)
        return self.waiters.removeValue(forKey: id)
      }
      continuation?.resume(throwing: CancellationError())
    }
  }
}

private func durationMillisecondsV3(_ duration: Duration) -> UInt64 {
  let components = duration.components
  guard components.seconds >= 0, components.attoseconds >= 0 else { return 0 }
  return UInt64(components.seconds) * 1_000
    + UInt64(components.attoseconds) / 1_000_000_000_000_000
}

private func waitUntilV3(
  timeout: Duration = .seconds(1),
  _ predicate: @escaping @Sendable () async -> Bool
) async -> Bool {
  let deadline = ContinuousClock.now + timeout
  while ContinuousClock.now < deadline {
    if await predicate() { return true }
    await Task.yield()
  }
  return await predicate()
}

private func assertTrueV3(
  _ value: Bool,
  _ message: @autoclosure () -> String = "",
  file: StaticString = #filePath,
  line: UInt = #line
) {
  XCTAssertTrue(value, message(), file: file, line: line)
}

private func assertFalseV3(
  _ value: Bool,
  _ message: @autoclosure () -> String = "",
  file: StaticString = #filePath,
  line: UInt = #line
) {
  XCTAssertFalse(value, message(), file: file, line: line)
}

private actor AsyncCounterV3 {
  private(set) var value = 0

  @discardableResult
  func increment() -> Int {
    value += 1
    return value
  }
}

private actor AsyncFlagV3 {
  private(set) var value = false

  func set() { value = true }
}

private actor CancellationAwareRetireGateV3 {
  private(set) var entered = false
  private(set) var cancelled = false

  func wait() async throws {
    entered = true
    do {
      try await Task.sleep(for: .seconds(60))
    } catch is CancellationError {
      cancelled = true
      throw CancellationError()
    }
  }

  func waitUntilEntered() async -> Bool {
    let deadline = ContinuousClock.now + .seconds(1)
    while ContinuousClock.now < deadline {
      if entered { return true }
      await Task.yield()
    }
    return entered
  }
}

private actor BlockingRetireGateV3 {
  private(set) var entered = false
  private var released = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  func wait() async {
    entered = true
    guard !released else { return }
    await withCheckedContinuation { waiters.append($0) }
  }

  func release() {
    released = true
    let current = waiters
    waiters.removeAll()
    for waiter in current { waiter.resume() }
  }
}

private actor UncooperativeSpendGateV3 {
  private(set) var started = false
  private var released = false
  private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

  func wait() async {
    started = true
    guard !released else { return }
    await withCheckedContinuation { releaseWaiters.append($0) }
  }

  func release() {
    released = true
    let currentReleaseWaiters = releaseWaiters
    releaseWaiters.removeAll()
    for waiter in currentReleaseWaiters { waiter.resume() }
  }
}

private actor CandidateIDRecorderV3 {
  private(set) var value = Set<String>()

  func record(_ ids: Set<String>) { value = ids }
}

private actor ControllerSessionV3: Session {
  nonisolated let rpc: any RPCPeer = ControllerRPCPeerV3()
  private let terminationError: SessionError
  private var closed = false
  private var terminationWaiters: [CheckedContinuation<SessionTermination, Never>] = []

  init(terminationError: SessionError = .closed) {
    self.terminationError = terminationError
  }

  func openStream(kind: String, metadata: StreamMetadata) async throws -> any ByteStream {
    throw SessionError.closed
  }
  func acceptStream() async throws -> IncomingStream { throw SessionError.closed }
  func rekey() async throws { throw SessionError.closed }
  func probeLiveness() async throws -> Duration { throw SessionError.closed }
  func waitTermination() async -> SessionTermination {
    if closed { return SessionTermination(error: terminationError) }
    return await withCheckedContinuation { terminationWaiters.append($0) }
  }
  func close() async throws {
    closed = true
    let waiters = terminationWaiters
    terminationWaiters.removeAll()
    for waiter in waiters { waiter.resume(returning: SessionTermination(error: terminationError)) }
  }
}

private struct ControllerRPCPeerV3: RPCPeer, Sendable {
  func call<Request: Encodable & Sendable, Response: Decodable & Sendable>(
    _ typeID: UInt32,
    _ request: Request,
    as responseType: Response.Type,
    timeout: Duration
  ) async throws -> Response { throw SessionError.closed }

  func notify<Payload: Encodable & Sendable>(
    _ typeID: UInt32, _ payload: Payload
  ) async throws { throw SessionError.closed }

  func subscribeNotification<Payload: Decodable & Sendable>(
    _ typeID: UInt32,
    as payloadType: Payload.Type,
    handler: @escaping @Sendable (Result<Payload, RPCNotificationError>) async throws -> Void
  ) async throws -> any RPCNotificationSubscription { throw SessionError.closed }
}
