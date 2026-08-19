import Crypto
import Foundation
import NIOCore
import NIOFoundationCompat
import NIOHTTP1
import NIOPosix
import NIOSSL
@preconcurrency import NIOWebSocket
import XCTest

@testable import Flowersec

final class ConnectorV2Tests: XCTestCase {
  #if os(macOS)
    func testProductionV3AdapterAcceptsConfiguredPrivateCA() async throws {
      let tls = try ConnectorTestTLS.load()
      let accepted = ConnectorAcceptedTransport()
      let server = try await ConnectorWSSServer.start(
        tls: tls, selectedProtocol: "flowersec.direct.v3", accepted: accepted)
      defer { Task { await server.close() } }
      let artifact = try v3WebSocketArtifact(port: server.port, tls: ["mode": "ca"])
      let connection = try await AppleWebSocketRuntimeAdapterV3().prepare(
        candidate: try XCTUnwrap(artifact.canonicalCandidates.first),
        path: .direct,
        role: .client,
        options: ConnectorOptions(
          origin: "https://client.example",
          connectTimeout: .seconds(2),
          trustRootsPEM: [tls.caPEM]
        ),
        activePinHashes: nil
      )

      XCTAssertEqual(connection.carrier, .webSocket)
      await connection.close()
    }

    func testProductionV3AdapterAcceptsSelfSignedPinAndOverlap() async throws {
      let oldTLS = try ConnectorTestTLS.makeShortLivedSelfSigned()
      let newTLS = try ConnectorTestTLS.makeShortLivedSelfSigned()
      let oldHash = Data(SHA256.hash(data: Data(try oldTLS.certificate.toDERBytes())))
      let newHash = Data(SHA256.hash(data: Data(try newTLS.certificate.toDERBytes())))
      XCTAssertNotEqual(oldHash, newHash)
      let activeUntil = Int(Date().timeIntervalSince1970) + 3_600
      let pins = [oldHash, newHash]
        .map { $0.base64URLEncodedStringV3() }
        .sorted()
        .map {
          [
            "algorithm": "sha-256",
            "not_after_unix_s": activeUntil,
            "value_b64u": $0,
          ] as [String: Any]
        }
      for material in [oldTLS, newTLS] {
        let accepted = ConnectorAcceptedTransport()
        let server = try await ConnectorWSSServer.start(
          tls: material, selectedProtocol: "flowersec.direct.v3", accepted: accepted)
        let artifact = try v3WebSocketArtifact(
          port: server.port,
          tls: ["mode": "pin", "pins": pins]
        )
        let connection = try await AppleWebSocketRuntimeAdapterV3().prepare(
          candidate: try XCTUnwrap(artifact.canonicalCandidates.first),
          path: .direct,
          role: .client,
          options: ConnectorOptions(
            origin: "https://client.example", connectTimeout: .seconds(2)),
          activePinHashes: [oldHash, newHash]
        )

        XCTAssertEqual(connection.carrier, .webSocket)
        await connection.close()
        await server.close()
      }
    }

    func testV3UnsupportedCandidateCreatesNoTransportOrLeaseSpend() async throws {
      let artifact = try v3WebSocketArtifact(port: 9, tls: ["mode": "ca"])
      let runtime = UnsupportedCountingRuntimeV3()
      let spend = ConnectorSpendCounter()
      let connector = try SessionConnectorV3(
        lease: ArtifactLeaseV3(artifact: artifact) { await spend.commit() },
        options: ConnectorOptions(
          origin: "https://client.example", connectTimeout: .milliseconds(250)),
        runtime: runtime
      )

      do {
        _ = try await connector.connect()
        XCTFail("unsupported candidate unexpectedly created a transport")
      } catch {
        XCTAssertEqual(error as? ConnectError, .transportSecurityUnsupported)
      }
      let prepareCount = await runtime.prepareCount()
      let spendCount = await spend.value()
      XCTAssertEqual(prepareCount, 0)
      XCTAssertEqual(spendCount, 0)
    }

    func testProductionV3PinMismatchFailsBeforeLeaseSpend() async throws {
      let tls = try ConnectorTestTLS.makeShortLivedSelfSigned()
      let accepted = ConnectorAcceptedTransport()
      let server = try await ConnectorWSSServer.start(
        tls: tls, selectedProtocol: "flowersec.direct.v3", accepted: accepted)
      defer { Task { await server.close() } }
      let artifact = try v3WebSocketArtifact(
        port: server.port,
        tls: pinPolicyV3(hash: Data(repeating: 0xA5, count: 32), expiresIn: 3_600)
      )
      let spend = ConnectorSpendCounter()
      let lease = ArtifactLeaseV3(artifact: artifact) { await spend.commit() }

      do {
        _ = try await connectV3(
          lease: lease,
          options: ConnectorOptions(
            origin: "https://client.example", connectTimeout: .seconds(2)))
        XCTFail("mismatched pin unexpectedly established a carrier")
      } catch {
        XCTAssertEqual(error as? ConnectError, .transportSecurityFailed)
      }
      let spendCount = await spend.value()
      XCTAssertEqual(spendCount, 0)
    }

    func testProductionV3PinNetworkFailureRemainsOrdinaryConnectionFailure() async throws {
      let artifact = try v3WebSocketArtifact(
        port: 9,
        tls: pinPolicyV3(hash: Data(repeating: 0xA5, count: 32), expiresIn: 3_600)
      )
      do {
        _ = try await connectV3(
          lease: ArtifactLeaseV3(artifact: artifact) {},
          options: ConnectorOptions(
            origin: "https://client.example", connectTimeout: .milliseconds(250)))
        XCTFail("closed endpoint unexpectedly established a carrier")
      } catch {
        XCTAssertEqual(error as? ConnectError, .connectionFailed)
      }
    }

    func testProductionV3ExpiredPinsFailBeforeCreatingTransportOrSpending() async throws {
      let artifact = try v3WebSocketArtifact(
        port: 9,
        tls: pinPolicyV3(hash: Data(repeating: 0xA5, count: 32), expiresIn: -1)
      )
      let spend = ConnectorSpendCounter()
      let lease = ArtifactLeaseV3(artifact: artifact) { await spend.commit() }

      do {
        _ = try await connectV3(
          lease: lease,
          options: ConnectorOptions(
            origin: "https://client.example", connectTimeout: .milliseconds(250)))
        XCTFail("expired pin policy unexpectedly created a carrier")
      } catch {
        XCTAssertEqual(error as? ConnectError, .transportSecurityFailed)
      }
      let spendCount = await spend.value()
      XCTAssertEqual(spendCount, 0)
    }

    func testV3FSA3RejectAndRetryablePreserveSpendAndControllerDisposition() async throws {
      for status in [AdmissionStatusV3.reject, AdmissionStatusV3.retryable] {
        let artifact = try v3WebSocketArtifact(port: 9, tls: ["mode": "ca"])
        let spend = ConnectorSpendCounter()
        let retire = ConnectorSpendCounter()
        let runtime = FSAResponseRuntimeV3(status: status)
        let connector = try SessionConnectorV3(
          lease: ArtifactLeaseV3(
            artifact: artifact,
            commitSpend: { await spend.commit() },
            retire: { await retire.commit() }
          ),
          options: ConnectorOptions(
            origin: "https://client.example", connectTimeout: .milliseconds(250)),
          runtime: runtime
        )

        do {
          _ = try await connector.connectForController()
          XCTFail("FSA3 failure unexpectedly established a session")
        } catch let error as ControllerConnectFailureV3 {
          let expectedDisposition: RetryDispositionV3 = status == .reject ? .terminal : .retryable
          XCTAssertEqual(
            error,
          .connection(
            .connectionFailed, expectedDisposition, policyTriggerIDs: [],
            opaquePolicyTriggerIDs: [], failedIDs: []))
        }
        let spendCount = await spend.value()
        let retireCount = await retire.value()
        let prepareCount = await runtime.prepareCount()
        XCTAssertEqual(spendCount, 1)
        XCTAssertEqual(retireCount, 0)
        XCTAssertEqual(prepareCount, 1)
      }
    }
  #endif

  func testV3ControllerFailureProvenanceIncludesOnlyAttemptedFailures() async throws {
    let artifact = try baseArtifactV3ForConnector()
    let runtime = CandidateFailureRuntimeV3()
    let spend = ConnectorSpendCounter()
    let connector = try SessionConnectorV3(
      lease: ArtifactLeaseV3(
        artifact: artifact,
        commitSpend: { await spend.commit() }),
      options: ConnectorOptions(
        origin: "https://client.example", connectTimeout: .seconds(1)),
      runtime: runtime
    )

    do {
      _ = try await connector.connectForController()
      XCTFail("failed candidates unexpectedly established a session")
    } catch let error as ControllerConnectFailureV3 {
      XCTAssertEqual(
        error,
        .connection(
          .transportSecurityFailed, .terminal,
          policyTriggerIDs: ["w-pin"], opaquePolicyTriggerIDs: [],
          failedIDs: ["w-ca", "w-pin"]))
    }
    let preparedIDs = await runtime.preparedIDs()
    let spendCount = await spend.value()
    XCTAssertEqual(preparedIDs, ["w-ca", "w-pin"])
    XCTAssertEqual(spendCount, 0)
  }

  func testV3BrowserOpaqueMarkerStaysOrdinaryButTriggersPinRefresh() async throws {
    let connector = try SessionConnectorV3(
      lease: ArtifactLeaseV3(artifact: try baseArtifactV3ForConnector()) {},
      options: ConnectorOptions(connectTimeout: .seconds(1)),
      runtime: OpaqueCandidateFailureRuntimeV3()
    )

    do {
      _ = try await connector.connectForController()
      XCTFail("opaque browser pin failures unexpectedly established a session")
    } catch let error as ControllerConnectFailureV3 {
      XCTAssertEqual(
        error,
        .connection(
          .connectionFailed, .retryable, policyTriggerIDs: [],
          opaquePolicyTriggerIDs: ["w-pin"], failedIDs: ["w-ca", "w-pin"]))
    }
  }

  func testV3CandidatePreparationRacesAndClosesLateLoser() async throws {
    let recorder = CandidateRaceRecorderV3()
    let runtime = CandidateRaceRuntimeV3(recorder: recorder, slowCandidateID: "w-ca")
    let spent = ConnectorSpendCounter()
    let connector = try SessionConnectorV3(
      lease: ArtifactLeaseV3(
        artifact: try expiringArtifactV3ForConnector(at: 101),
        commitSpend: { await spent.commit() }),
      options: ConnectorOptions(connectTimeout: .seconds(1)),
      runtime: runtime,
      currentUnixSeconds: { 100 }
    )

    do {
      _ = try await connector.connect()
      XCTFail("recording connection unexpectedly established a session")
    } catch {
      XCTAssertEqual(error as? ConnectError, .connectionFailed)
    }
    let settled = await waitUntilConnectorV3(timeout: .milliseconds(500)) {
      await recorder.snapshot().closed.count == 2
    }
    XCTAssertTrue(settled)
    let snapshot = await recorder.snapshot()
    let spendCount = await spent.value()
    XCTAssertEqual(snapshot.writes, ["w-pin"])
    XCTAssertEqual(snapshot.closed, ["w-ca", "w-pin"])
    XCTAssertEqual(spendCount, 1)
  }

  func testV3HangingPreparationLoserDoesNotDelayWinnerOrRetainLateConnection() async throws {
    let recorder = CandidateRaceRecorderV3()
    let gate = CandidatePrepareGateV3()
    let spent = ConnectorSpendCounter()
    let connector = try SessionConnectorV3(
      lease: ArtifactLeaseV3(
        artifact: try baseArtifactV3ForConnector(),
        commitSpend: { await spent.commit() }),
      options: ConnectorOptions(connectTimeout: .seconds(1)),
      runtime: GatedCandidateRuntimeV3(
        recorder: recorder, gate: gate, immediateCandidateID: "w-pin")
    )

    let started = ContinuousClock.now
    do {
      _ = try await connector.connect()
      XCTFail("recording winner unexpectedly established a session")
    } catch {
      XCTAssertEqual(error as? ConnectError, .connectionFailed)
    }
    XCTAssertLessThan(started.duration(to: .now), .milliseconds(250))
    let spendCount = await spent.value()
    let winnerSnapshot = await recorder.snapshot()
    XCTAssertEqual(spendCount, 1)
    XCTAssertEqual(winnerSnapshot.writes, ["w-pin"])
    XCTAssertEqual(winnerSnapshot.closed, ["w-pin"])

    await gate.release()
    let loserClosed = await waitUntilConnectorV3(timeout: .milliseconds(500)) {
      await recorder.snapshot().closed == ["w-ca", "w-pin"]
    }
    XCTAssertTrue(loserClosed)
  }

  func testV3TimeoutBeforeLatePreparationsSpendsNothingAndClosesReturnedConnections()
    async throws
  {
    let recorder = CandidateRaceRecorderV3()
    let gate = CandidatePrepareGateV3()
    let spent = ConnectorSpendCounter()
    let connector = try SessionConnectorV3(
      lease: ArtifactLeaseV3(
        artifact: try baseArtifactV3ForConnector(),
        commitSpend: { await spent.commit() }),
      options: ConnectorOptions(connectTimeout: .milliseconds(20)),
      runtime: GatedCandidateRuntimeV3(recorder: recorder, gate: gate)
    )

    let started = ContinuousClock.now
    do {
      _ = try await connector.connect()
      XCTFail("late preparations unexpectedly established a session")
    } catch {
      XCTAssertEqual(error as? ConnectError, .timeout)
    }
    XCTAssertLessThan(started.duration(to: .now), .milliseconds(120))
    let spendCountAfterTimeout = await spent.value()
    XCTAssertEqual(spendCountAfterTimeout, 0)
    let timedOutSnapshot = await recorder.snapshot()
    XCTAssertTrue(timedOutSnapshot.writes.isEmpty)
    XCTAssertTrue(timedOutSnapshot.closed.isEmpty)

    await gate.release()
    let lateConnectionsClosed = await waitUntilConnectorV3(timeout: .milliseconds(500)) {
      await recorder.snapshot().closed == ["w-ca", "w-pin"]
    }
    XCTAssertTrue(lateConnectionsClosed)
    let finalSpendCount = await spent.value()
    XCTAssertEqual(finalSpendCount, 0)
  }

  func testV3CancellationBeforeLatePreparationsSpendsNothingAndClosesReturnedConnections()
    async throws
  {
    let recorder = CandidateRaceRecorderV3()
    let gate = CandidatePrepareGateV3()
    let spent = ConnectorSpendCounter()
    let connector = try SessionConnectorV3(
      lease: ArtifactLeaseV3(
        artifact: try baseArtifactV3ForConnector(),
        commitSpend: { await spent.commit() }),
      options: ConnectorOptions(connectTimeout: .seconds(1)),
      runtime: GatedCandidateRuntimeV3(recorder: recorder, gate: gate)
    )
    let connecting = Task { try await connector.connect() }
    let bothPreparing = await waitUntilConnectorV3(timeout: .milliseconds(500)) {
      await gate.arrivalCount == 2
    }
    XCTAssertTrue(bothPreparing)

    connecting.cancel()
    do {
      _ = try await connecting.value
      XCTFail("cancelled preparations unexpectedly established a session")
    } catch {
      XCTAssertEqual(error as? ConnectError, .canceled)
    }
    let spendCountAfterCancellation = await spent.value()
    XCTAssertEqual(spendCountAfterCancellation, 0)

    await gate.release()
    let lateConnectionsClosed = await waitUntilConnectorV3(timeout: .milliseconds(500)) {
      await recorder.snapshot().closed == ["w-ca", "w-pin"]
    }
    XCTAssertTrue(lateConnectionsClosed)
    let canceledSnapshot = await recorder.snapshot()
    XCTAssertTrue(canceledSnapshot.writes.isEmpty)
    let finalSpendCount = await spent.value()
    XCTAssertEqual(finalSpendCount, 0)
  }

  func testV3NoWinnerRaceEndExpiryOverridesCandidateFailures() async throws {
    let recorder = CandidateRaceRecorderV3()
    let clock = SteppingUnixClockV3(values: [100, 101])
    let connector = try SessionConnectorV3(
      lease: ArtifactLeaseV3(artifact: try expiringArtifactV3ForConnector(at: 101)) {},
      options: ConnectorOptions(connectTimeout: .seconds(1)),
      runtime: CandidateRaceRuntimeV3(recorder: recorder, failAll: true),
      currentUnixSeconds: { clock.read() }
    )

    do {
      _ = try await connector.connect()
      XCTFail("expired all-failed race unexpectedly established a session")
    } catch {
      XCTAssertEqual(error as? ConnectError, .expiredArtifact)
    }
    let snapshot = await recorder.snapshot()
    XCTAssertTrue(snapshot.writes.isEmpty)
  }

  func testV3ExpiryAfterSpendWritesNoFSB3Bytes() async throws {
    let recorder = CandidateRaceRecorderV3()
    let clock = MutableUnixClockV3(value: 100)
    let spent = ConnectorSpendCounter()
    let connector = try SessionConnectorV3(
      lease: ArtifactLeaseV3(
        artifact: try expiringArtifactV3ForConnector(at: 101),
        commitSpend: {
          await spent.commit()
          clock.set(101)
        }),
      options: ConnectorOptions(connectTimeout: .seconds(1)),
      runtime: CandidateRaceRuntimeV3(recorder: recorder),
      currentUnixSeconds: { clock.read() }
    )

    do {
      _ = try await connector.connect()
      XCTFail("post-spend expired artifact unexpectedly wrote FSB3")
    } catch {
      XCTAssertEqual(error as? ConnectError, .expiredArtifact)
    }
    let snapshot = await recorder.snapshot()
    let spendCount = await spent.value()
    XCTAssertEqual(spendCount, 1)
    XCTAssertTrue(snapshot.writes.isEmpty)
    XCTAssertEqual(snapshot.closed, ["w-ca", "w-pin"])
  }

  func testV3ConnectDeadlineClosesHangingAdmissionRead() async throws {
    let recorder = HangingAdmissionRecorderV3()
    let spent = ConnectorSpendCounter()
    let connector = try SessionConnectorV3(
      lease: ArtifactLeaseV3(
        artifact: try baseArtifactV3ForConnector(),
        commitSpend: { await spent.commit() }
      ),
      options: ConnectorOptions(connectTimeout: .milliseconds(20)),
      runtime: HangingAdmissionRuntimeV3(recorder: recorder)
    )

    let started = ContinuousClock.now
    do {
      _ = try await connector.connect()
      XCTFail("hanging admission unexpectedly established a session")
    } catch {
      XCTAssertEqual(error as? ConnectError, .timeout)
    }
    XCTAssertLessThan(started.duration(to: .now), .milliseconds(120))
    let settled = await waitUntilConnectorV3(timeout: .milliseconds(500)) {
      let snapshot = await recorder.snapshot()
      return snapshot.reads == 1 && snapshot.closed == 2
    }
    XCTAssertTrue(settled)
    let spendCount = await spent.value()
    XCTAssertEqual(spendCount, 1)
  }

  func testServerParityClientProfile() async throws {
    #if os(macOS)
      guard ProcessInfo.processInfo.environment["FLOWERSEC_PARITY_READY_BASE64"] != nil else { throw XCTSkip("server parity input is supplied by the parity runner") }
      guard let encoded = ProcessInfo.processInfo.environment["FLOWERSEC_PARITY_READY_BASE64"],
        let data = Data(base64Encoded: encoded),
        let ready = try JSONSerialization.jsonObject(with: data) as? [String: Any],
        let artifactJSON = ready["artifact_json"] as? String,
        let trustPEM = ready["trust_pem"] as? String,
        let origin = ready["origin"] as? String,
        let protocolVersion = ProcessInfo.processInfo.environment["FLOWERSEC_PARITY_PROTOCOL"],
        protocolVersion == "v2" || protocolVersion == "v3",
        let path = ProcessInfo.processInfo.environment["FLOWERSEC_PARITY_PATH"],
        path == "direct" || path == "tunnel"
      else { throw XCTSkip("server parity input is supplied by the parity runner") }
      let options = ConnectorOptions(
        origin: origin, connectTimeout: .seconds(5), trustRootsPEM: [Data(trustPEM.utf8)])
      let session: any Session
      if protocolVersion == "v2" {
        session = try await connectV2(
          lease: ArtifactLeaseV2(artifact: try parseArtifactV2(Data(artifactJSON.utf8))) {},
          options: options)
      } else {
        session = try await connectV3(
          lease: ArtifactLeaseV3(artifact: try parseArtifactV3(Data(artifactJSON.utf8))) {},
          options: options)
      }
      let echo: [String: String] = try await session.rpc.call(7001, ["value": "ping"], as: [String: String].self, timeout: .seconds(5))
      XCTAssertEqual(echo["value"], "ping")
      try await session.rpc.notify(7002, ["value": "notify"])
      let stream = try await session.openStream(kind: "parity.echo", metadata: try StreamMetadata(["cell": .string(path)]))
      _ = try await stream.write(Data("hello".utf8))
      try await stream.closeWrite()
      let echoed = try await stream.read(maxBytes: 32)
      XCTAssertEqual(echoed, Data("world".utf8))
      let reset = try await session.openStream(kind: "parity.reset")
      _ = try await reset.write(Data("reset".utf8))
      try await reset.closeWrite()
      do { _ = try await reset.read(maxBytes: 32); XCTFail("reset stream succeeded") } catch { }
      try await session.rekey()
      _ = try await session.probeLiveness()
      try await session.close()
    #else
      throw ConnectError.runtimeUnsupported
    #endif
  }

  func testConnectionControllerV2ReplacesTerminatedGoWSSSessionWithoutReplay() async throws {
    let scenario = try connectionControllerScenario(named: "connect_and_replace_after_termination")
    XCTAssertEqual(scenario.sessions, ["session-1", "session-2"])
    XCTAssertEqual(scenario.replay, [])
    let firstPeer = try GoWSSPeer.start(path: "direct")
    defer { firstPeer.stop() }
    let secondPeer = try GoWSSPeer.start(path: "direct")
    defer { secondPeer.stop() }
    let firstArtifact = try goWSSArtifact(endpoint: firstPeer.endpoint, vectorIndex: 0)
    let secondArtifact = try goWSSArtifact(endpoint: secondPeer.endpoint, vectorIndex: 0)
    let source = ControllerGoWSSArtifactSourceV2(artifacts: [firstArtifact, secondArtifact])
    let controller = try ConnectionControllerV2(
      source: source,
      options: ConnectorOptions(
        origin: "https://client.example",
        connectTimeout: .seconds(5),
        trustRootsPEM: [
          Data(firstPeer.endpoint.caPEM.utf8), Data(secondPeer.endpoint.caPEM.utf8),
        ]
      )
    )

    await controller.start()
    let firstSession = try await waitForControllerSession(
      controller,
      source: source,
      afterAcquisitions: 1
    )
    try await exerciseGoSession(firstSession)
    let staleStream = try await firstSession.openStream(kind: "must-not-migrate")
    let firstResult = firstPeer.finish()
    XCTAssertEqual(firstResult.status, 0, firstResult.stderr)
    _ = await firstSession.waitTermination()

    await XCTAssertThrowsErrorAsync(
      try await staleStream.write(Data("must-not-replay".utf8)))
    let secondSession = try await waitForControllerSession(
      controller,
      source: source,
      afterAcquisitions: 2
    )

    await XCTAssertThrowsErrorAsync(try await firstSession.openStream(kind: "must-not-migrate"))
    await XCTAssertThrowsErrorAsync(try await firstSession.rpc.notify(90, "must-not-replay"))
    try await exerciseGoSession(secondSession)
    await controller.close()
    let secondResult = secondPeer.finish()
    XCTAssertEqual(secondResult.status, 0, secondResult.stderr)
    let sourceCounts = await source.counts()
    XCTAssertEqual(sourceCounts.acquisitions, 2)
    XCTAssertEqual(sourceCounts.spends, 2)
  }

  func testRealLocalWSSDirectEndToEnd() async throws {
    try await exerciseRealWSS(vectorIndex: 0)
  }

  func testLoopbackPlaintextDirectRuntimeContract() async throws {
    let accepted = ConnectorAcceptedTransport()
    let raw = try loadArtifactJSON(index: 0)
    let original = try parseArtifactV2(Data(raw.utf8)).value
    let candidateURL = try XCTUnwrap(
      original.path.candidates.first(where: { $0.carrier == "websocket" })?.url)
    let server = try await ConnectorWSSServer.startPlaintext(
      selectedProtocol: "flowersec.direct.v2", accepted: accepted)
    let rewritten = try singleWebSocketArtifactJSON(
      raw: raw,
      candidateURL: candidateURL,
      replacementURL: "ws://127.0.0.1:\(server.port)/flowersec/v2/direct"
    )
    let artifact = try parseArtifactV2(Data(rewritten.utf8))
    let spend = ConnectorSpendCounter()
    let lease = ArtifactLeaseV2(artifact: artifact) { await spend.commit() }
    async let serverSession = Self.establishServerSession(artifact: artifact, accepted: accepted)
    async let clientSession = connectV2(
      lease: lease,
      options: ConnectorOptions(origin: "http://127.0.0.1:\(server.port)", connectTimeout: .seconds(5))
    )
    let (client, serverPeer) = try await (clientSession, serverSession)

    _ = try await client.probeLiveness()
    let outbound = try await client.openStream(kind: "loopback-direct")
    let inbound = try await serverPeer.acceptStream()
    _ = try await outbound.write(Data("client".utf8))
    let received = try await inbound.stream.read(maxBytes: 32)
    XCTAssertEqual(received, Data("client".utf8))
    try await outbound.closeWrite()
    let eof = try await inbound.stream.read(maxBytes: 1)
    XCTAssertNil(eof)
    try await client.close()
    try await serverPeer.close()
    let spendCount = await spend.value()
    let selectedProtocol = await accepted.protocolValue()
    XCTAssertEqual(spendCount, 1)
    XCTAssertEqual(selectedProtocol, "flowersec.direct.v2")
    await server.close()

    let tunnelRaw = try loadArtifactJSON(index: 1)
    let tunnel = try parseArtifactV2(Data(tunnelRaw.utf8)).value
    let tunnelCandidateURL = try XCTUnwrap(
      tunnel.path.candidates.first(where: { $0.carrier == "websocket" })?.url)
    let plaintextTunnel = try singleWebSocketArtifactJSON(
      raw: tunnelRaw,
      candidateURL: tunnelCandidateURL,
      replacementURL: "ws://127.0.0.1:\(server.port)/flowersec/v2/tunnel")
    XCTAssertThrowsError(try parseArtifactV2(Data(plaintextTunnel.utf8)))
    let nonLoopback = rewritten.replacingOccurrences(of: "127.0.0.1", with: "192.0.2.10")
    XCTAssertThrowsError(try parseArtifactV2(Data(nonLoopback.utf8)))
  }

  func testRealGoWSSDirectEndToEnd() async throws {
    try await exerciseGoWSS(path: "direct", vectorIndex: 0)
  }

  func testRealGoWSSPublicNotificationSubscription() async throws {
    let peer = try GoWSSPeer.start(path: "direct", serverNotify: true)
    defer { peer.stop() }
    let artifact = try goWSSArtifact(endpoint: peer.endpoint, vectorIndex: 0)
    let session = try await connectV2(
      lease: ArtifactLeaseV2(artifact: artifact) {},
      options: ConnectorOptions(
        origin: "https://client.example",
        connectTimeout: .seconds(5),
        trustRootsPEM: [Data(peer.endpoint.caPEM.utf8)]
      )
    )
    let delivered = expectation(description: "typed Go RPC notification")
    let subscription = try await session.rpc.subscribeNotification(
      9_002,
      as: GoWSSNotification.self
    ) { result in
      XCTAssertEqual(try result.get(), GoWSSNotification(state: "accepted"))
      delivered.fulfill()
    }

    try await session.rpc.notify(9_001, GoWSSNotification(state: "ready"))
    await fulfillment(of: [delivered], timeout: 5)
    try await exerciseGoSession(session)
    await subscription.cancel()
    await subscription.cancel()
    try await session.close()

    let result = peer.finish()
    XCTAssertEqual(result.status, 0, result.stderr)
  }

  func testRealGoWSSTunnelEndToEnd() async throws {
    try await exerciseGoWSS(path: "tunnel", vectorIndex: 1)
  }

  func testRealLocalWSSTunnelBridgesTwoAdmittedLegsEndToEnd() async throws {
    let tls = try ConnectorTestTLS.load()
    let accepted = ConnectorAcceptedTransport()
    let source = try loadArtifactJSON(index: 1)
    let original = try parseArtifactV2(Data(source.utf8)).value
    let server = try await ConnectorWSSServer.start(
      tls: tls, selectedProtocol: "flowersec.tunnel.v2", accepted: accepted)
    let candidateURL = original.path.candidates.first(where: { $0.carrier == "websocket" })!.url
    let localURL = "wss://localhost:\(server.port)/flowersec/v2/tunnel"
    let clientRaw = source.replacingOccurrences(of: candidateURL, with: localURL)
    let serverRaw =
      clientRaw
      .replacingOccurrences(of: "\"role\":1", with: "\"role\":2")
      .replacingOccurrences(of: "endpoint-client", with: "endpoint-swap")
      .replacingOccurrences(of: "endpoint-server", with: "endpoint-client")
      .replacingOccurrences(of: "endpoint-swap", with: "endpoint-server")
    let clientArtifact = try parseArtifactV2(Data(clientRaw.utf8))
    let serverArtifact = try parseArtifactV2(Data(serverRaw.utf8))
    let clientSpend = ConnectorSpendCounter()
    let serverSpend = ConnectorSpendCounter()
    let options = ConnectorOptions(
      connectTimeout: .seconds(5), trustRootsPEM: [tls.caPEM])
    let clientLease = ArtifactLeaseV2(artifact: clientArtifact) { await clientSpend.commit() }
    let serverLease = ArtifactLeaseV2(artifact: serverArtifact) { await serverSpend.commit() }
    async let bridgeResult: Void = Self.bridgeTunnelLegs(accepted: accepted)
    async let clientResult = connectV2(lease: clientLease, options: options)
    async let serverResult = connectV2(lease: serverLease, options: options)
    let (client, serverPeer) = try await (clientResult, serverResult)

    let outbound = try await client.openStream(kind: "tunnel-e2e")
    let inbound = try await serverPeer.acceptStream()
    _ = try await outbound.write(Data("through-tunnel".utf8))
    let received = try await inbound.stream.read(maxBytes: 64)
    XCTAssertEqual(received, Data("through-tunnel".utf8))
    try await outbound.closeWrite()
    let eof = try await inbound.stream.read(maxBytes: 1)
    XCTAssertNil(eof)
    let reverse = try await serverPeer.openStream(kind: "tunnel-reverse")
    let reverseInbound = try await client.acceptStream()
    _ = try await reverse.write(Data("back".utf8))
    let reverseReceived = try await reverseInbound.stream.read(maxBytes: 32)
    XCTAssertEqual(reverseReceived, Data("back".utf8))
    try await client.close()
    try await serverPeer.close()
    _ = try? await bridgeResult
    let clientSpendCount = await clientSpend.value()
    let serverSpendCount = await serverSpend.value()
    XCTAssertEqual(clientSpendCount, 1)
    XCTAssertEqual(serverSpendCount, 1)
    await server.close()
  }

  private static func bridgeTunnelLegs(accepted: ConnectorAcceptedTransport) async throws {
    let first = try await accepted.accept()
    let second = try await accepted.accept()
    let firstFSB2 = try await first.readBinary()
    let secondFSB2 = try await second.readBinary()
    let firstRole = try tunnelRole(firstFSB2)
    let secondRole = try tunnelRole(secondFSB2)
    guard Set([firstRole, secondRole]) == Set([1, 2]) else { throw ConnectorQueueError.invalid }
    let success = Data([70, 83, 65, 50, 2, 0, 0, 0])
    try await first.writeBinary(success)
    try await second.writeBinary(success)
    try await withThrowingTaskGroup(of: Void.self) { group in
      group.addTask { try await relay(from: first, to: second) }
      group.addTask { try await relay(from: second, to: first) }
      defer { group.cancelAll() }
      _ = try await group.next()
    }
  }

  private static func tunnelRole(_ fsb2: Data) throws -> Int {
    guard fsb2.count >= 12,
      let payload = try JSONSerialization.jsonObject(with: fsb2.dropFirst(12)) as? [String: Any],
      let role = payload["role"] as? Int
    else { throw ConnectorQueueError.invalid }
    return role
  }

  private static func relay(
    from source: ConnectorNIOBinaryTransport,
    to destination: ConnectorNIOBinaryTransport
  ) async throws {
    while !Task.isCancelled { try await destination.writeBinary(try await source.readBinary()) }
  }

  private func exerciseRealWSS(vectorIndex: Int) async throws {
    let tls = try ConnectorTestTLS.load()
    let accepted = ConnectorAcceptedTransport()
    let raw = try loadArtifactJSON(index: vectorIndex)
    let original = try parseArtifactV2(Data(raw.utf8)).value
    let expectedProtocol =
      original.path.kind == "direct" ? "flowersec.direct.v2" : "flowersec.tunnel.v2"
    let server = try await ConnectorWSSServer.start(
      tls: tls, selectedProtocol: expectedProtocol, accepted: accepted)
    let rewritten = raw.replacingOccurrences(
      of: original.path.candidates.first(where: { $0.carrier == "websocket" })!.url,
      with: "wss://localhost:\(server.port)/flowersec/v2/\(original.path.kind)"
    )
    let artifact = try parseArtifactV2(Data(rewritten.utf8))
    let spend = ConnectorSpendCounter()
    let lease = ArtifactLeaseV2(artifact: artifact) { await spend.commit() }
    let options = ConnectorOptions(
      connectTimeout: .seconds(5), trustRootsPEM: [tls.caPEM])
    do {
      async let serverSession = Self.establishServerSession(
        artifact: artifact, accepted: accepted)
      async let clientSession = connectV2(lease: lease, options: options)
      let (client, serverPeer) = try await (clientSession, serverSession)

      let outbound = try await client.openStream(kind: "wss-e2e")
      let inbound = try await serverPeer.acceptStream()
      _ = try await outbound.write(Data("client".utf8))
      let received = try await inbound.stream.read(maxBytes: 32)
      XCTAssertEqual(received, Data("client".utf8))
      try await outbound.closeWrite()
      let eof = try await inbound.stream.read(maxBytes: 1)
      XCTAssertNil(eof)
      let reverse = try await serverPeer.openStream(kind: "reverse")
      let reverseInbound = try await client.acceptStream()
      _ = try await reverse.write(Data("server".utf8))
      let reverseReceived = try await reverseInbound.stream.read(maxBytes: 32)
      XCTAssertEqual(reverseReceived, Data("server".utf8))
      try await client.close()
      try await serverPeer.close()
      let spendCount = await spend.value()
      let selectedProtocol = await accepted.protocolValue()
      XCTAssertEqual(spendCount, 1)
      XCTAssertEqual(selectedProtocol, expectedProtocol)
    } catch {
      await server.close()
      throw error
    }
    await server.close()
  }

  private static func establishServerSession(
    artifact: ArtifactV2, accepted: ConnectorAcceptedTransport
  ) async throws -> TransportV2Session {
    let transport = try await accepted.accept()
    let fsb2 = try await transport.readBinary()
    try await transport.writeBinary(Data([70, 83, 65, 50, 2, 0, 0, 0]))
    let wire = artifact.value
    var preimage = Data("flowersec-v2-admission\0".utf8)
    preimage.append(fsb2)
    let binding = Data(SHA256.hash(data: preimage))
    let path: PathKind = wire.path.kind == "direct" ? .direct : .tunnel
    let carrier = WebSocketCarrierSessionV2(
      transport: transport, path: path, client: false,
      inboundCapacity: wire.session.maxInboundStreams + 2)
    let config = TransportV2SessionConfig(
      role: .server, path: path, channelID: wire.session.channelID,
      sessionContractHash: try decodeTest32(wire.session.contractHashBase64URL),
      suite: TransportCipherSuiteV2(rawValue: wire.session.defaultSuite)!,
      psk: try decodeTest32(wire.session.e2eePSKBase64URL),
      maxInboundStreams: wire.session.maxInboundStreams,
      idleTimeoutSeconds: wire.session.idleTimeoutSeconds,
      localAdmissionBinding: path == .direct ? binding : Data(repeating: 0, count: 32),
      peerAdmissionBinding: binding,
      localEndpointInstanceID: wire.path.expectedPeerEndpointInstanceID ?? "",
      expectedPeerEndpointInstanceID: wire.path.localEndpointInstanceID ?? ""
    )
    return try await TransportV2Session.establish(carrier: carrier, config: config)
  }

  func testWebSocketCarrierProvidesBidirectionalStreamsAndFIN() async throws {
    let pair = ConnectorBinaryPair()
    let client = WebSocketCarrierSessionV2(
      transport: pair.client, path: .direct, client: true, inboundCapacity: 3)
    let server = WebSocketCarrierSessionV2(
      transport: pair.server, path: .direct, client: false, inboundCapacity: 3)

    await XCTAssertThrowsErrorAsync(try await client.sendDatagram(Data())) {
      XCTAssertEqual($0 as? TransportV2CarrierError, .datagramsUnavailable)
    }
    await XCTAssertThrowsErrorAsync(try await client.receiveDatagram(maxBytes: 1)) {
      XCTAssertEqual($0 as? TransportV2CarrierError, .datagramsUnavailable)
    }

    let outbound = try await client.openStream()
    let inbound = try await server.acceptStream()
    let written = try await outbound.write(Data("hello".utf8))
    let first = try await inbound.read(maxBytes: 2)
    let second = try await inbound.read(maxBytes: 8)
    XCTAssertEqual(written, 5)
    XCTAssertEqual(first, Data("he".utf8))
    XCTAssertEqual(second, Data("llo".utf8))
    await XCTAssertThrowsErrorAsync(try await outbound.stopSending(code: 6)) {
      XCTAssertEqual($0 as? TransportV2CarrierError, .stopSendingUnsupported)
    }
    try await outbound.closeWrite()
    let eof = try await inbound.read(maxBytes: 1)
    XCTAssertNil(eof)

    let reverse = try await server.openStream()
    let reverseInbound = try await client.acceptStream()
    let reverseWritten = try await reverse.write(Data("ok".utf8))
    let reverseRead = try await reverseInbound.read(maxBytes: 8)
    XCTAssertEqual(reverseWritten, 2)
    XCTAssertEqual(reverseRead, Data("ok".utf8))
    await client.close(code: 0, reason: "done")
    await server.close(code: 0, reason: "done")
  }

  func testWebSocketCarrierAbortSynchronouslyRejectsLateStreams() async throws {
    let pair = ConnectorBinaryPair()
    let client = WebSocketCarrierSessionV2(
      transport: pair.client, path: .direct, client: true, inboundCapacity: 1)
    let server = WebSocketCarrierSessionV2(
      transport: pair.server, path: .direct, client: false, inboundCapacity: 1)

    client.abort(code: 6, reason: "test abort")
    await XCTAssertThrowsErrorAsync(try await client.openStream()) {
      XCTAssertEqual($0 as? TransportV2CarrierError, .closed)
    }
    await server.close(code: 0, reason: "done")
  }

  func testConnectRejectsInvalidPublicOptions() async throws {
    let artifact = try loadArtifact()
    let lease = ArtifactLeaseV2(artifact: artifact) {}
    do {
      _ = try await connectV2(
        lease: lease,
        options: ConnectorOptions(origin: "http://example.com"))
      XCTFail("invalid public options unexpectedly established a session")
    } catch {
      XCTAssertEqual(error as? ConnectError, .invalidOptions)
    }
  }

  func testConnectorCommitsSpendBeforeFSB2AndClosesAfterAdmissionReject() async throws {
    let artifact = try loadArtifact()
    let events = ConnectorEventRecorder()
    let lease = ArtifactLeaseV2(artifact: artifact) { await events.append("spend") }
    let connector = try SessionConnectorV2(
      lease: lease,
      options: ConnectorOptions(),
      runtime: ConnectorAdmissionRuntime(events: events)
    )

    do {
      _ = try await connector.connect()
      XCTFail("admission rejection unexpectedly established a session")
    } catch {
      XCTAssertEqual(error as? ConnectError, .connectionFailed)
    }
    let recordedEvents = await events.values()
    XCTAssertEqual(recordedEvents, ["dial", "spend", "write", "read", "close"])
  }

  func testConnectTimeoutReturnsBeforeDurableSpendCompletesAndStillCleansUp() async throws {
    let artifact = try loadArtifact()
    let events = ConnectorEventRecorder()
    let lease = ArtifactLeaseV2(artifact: artifact) {
      await events.append("spend-start")
      try await Task.sleep(for: .milliseconds(250))
      await events.append("spend-finished")
    }
    let connector = try SessionConnectorV2(
      lease: lease,
      options: ConnectorOptions(connectTimeout: .milliseconds(20)),
      runtime: ConnectorAdmissionRuntime(events: events)
    )

    let started = ContinuousClock.now
    do {
      _ = try await connector.connect()
      XCTFail("slow durable spend unexpectedly established a session")
    } catch {
      XCTAssertEqual(error as? ConnectError, .timeout)
    }
    let elapsed = started.duration(to: .now)
    XCTAssertLessThan(elapsed, .milliseconds(120))
    let eventsAtTimeout = await events.values()
    XCTAssertEqual(eventsAtTimeout, ["dial", "spend-start"])

    try await Task.sleep(for: .milliseconds(300))
    let settledEvents = await events.values()
    XCTAssertEqual(settledEvents, ["dial", "spend-start", "spend-finished", "close"])
  }

  func testRealWSSFailureCancelsServerAcceptWithinDeadline() async throws {
    let tls = try ConnectorTestTLS.load()
    let accepted = ConnectorAcceptedTransport()
    let raw = try loadArtifactJSON(index: 0)
    let original = try parseArtifactV2(Data(raw.utf8)).value
    let server = try await ConnectorWSSServer.start(
      tls: tls, selectedProtocol: "flowersec.direct.v2", accepted: accepted)
    let rewritten = raw.replacingOccurrences(
      of: original.path.candidates.first(where: { $0.carrier == "websocket" })!.url,
      with: "wss://localhost:\(server.port)/flowersec/v2/direct"
    )
    let artifact = try parseArtifactV2(Data(rewritten.utf8))
    let started = ContinuousClock.now

    do {
      async let serverSession = Self.establishServerSession(
        artifact: artifact, accepted: accepted)
      async let clientSession = connectV2(
        lease: ArtifactLeaseV2(artifact: artifact) {},
        options: ConnectorOptions(connectTimeout: .milliseconds(250))
      )
      _ = try await (clientSession, serverSession)
      XCTFail("untrusted WSS connection unexpectedly succeeded")
    } catch {
      XCTAssertEqual(error as? ConnectError, .connectionFailed)
    }
    XCTAssertLessThan(started.duration(to: .now), .seconds(1))
    await server.close()
  }

  private func loadArtifact() throws -> ArtifactV2 {
    try parseArtifactV2(Data(loadArtifactJSON(index: 0).utf8))
  }

  #if os(macOS)
    private func v3WebSocketArtifact(
      port: Int,
      tls: [String: Any]
    ) throws -> ArtifactV3 {
      let url = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("testdata/transport_v3/artifact_vectors.json")
      let vectors = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
      let positive = vectors["positive"] as! [[String: Any]]
      var root = try JSONSerialization.jsonObject(
        with: Data((positive[0]["artifact_json"] as! String).utf8)) as! [String: Any]
      var path = root["path"] as! [String: Any]
      path["candidates"] = [[
        "carrier": "websocket",
        "id": "w-local",
        "tls": tls,
        "url": "wss://localhost:\(port)/flowersec/v3/direct",
        "wire_profile": "flowersec-direct/3",
      ]]
      root["path"] = path
      var session = root["session"] as! [String: Any]
      session["init_expire_at_unix_s"] = Int(Date().timeIntervalSince1970) + 3_600
      root["session"] = session
      return try parseArtifactV3(FlowersecJCSV3.encode(root))
    }

    private func pinPolicyV3(hash: Data, expiresIn seconds: Int) -> [String: Any] {
      [
        "mode": "pin",
        "pins": [[
          "algorithm": "sha-256",
          "not_after_unix_s": Int(Date().timeIntervalSince1970) + seconds,
          "value_b64u": hash.base64URLEncodedStringV3(),
        ]],
      ]
    }
  #endif

  private func loadArtifactJSON(index: Int) throws -> String {
    let url = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("testdata/transport_v2/artifact_vectors.json")
    let root = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
    let positive = root["positive"] as! [[String: Any]]
    return positive[index]["artifact_json"] as! String
  }

  private func singleWebSocketArtifactJSON(
    raw: String,
    candidateURL: String,
    replacementURL: String
  ) throws -> String {
    var wire = try XCTUnwrap(
      JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any])
    var path = try XCTUnwrap(wire["path"] as? [String: Any])
    var candidates = try XCTUnwrap(path["candidates"] as? [[String: Any]])
    var candidate = try XCTUnwrap(candidates.first(where: { $0["url"] as? String == candidateURL }))
    candidate["url"] = replacementURL
    candidates = [candidate]
    path["candidates"] = candidates
    wire["path"] = path
    return String(
      data: try JSONSerialization.data(
        withJSONObject: wire, options: [.sortedKeys, .withoutEscapingSlashes]),
      encoding: .utf8
    )!
  }

  private func exerciseGoWSS(path: String, vectorIndex: Int) async throws {
    let process = Process()
    let output = Pipe()
    let errors = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = ["go", "run", "./internal/cmd/ts-session-peer", "--path", path]
    process.currentDirectoryURL = packageRoot().appendingPathComponent("flowersec-go")
    process.standardOutput = output
    process.standardError = errors
    try process.run()
    defer {
      if process.isRunning {
        process.terminate()
        process.waitUntilExit()
      }
    }

    let endpoint = try JSONDecoder().decode(
      GoWSSEndpoint.self,
      from: readFirstLine(output.fileHandleForReading)
    )
    let source = try loadArtifactJSON(index: vectorIndex)
    var wire = try XCTUnwrap(
      JSONSerialization.jsonObject(with: Data(source.utf8)) as? [String: Any])
    var pathObject = try XCTUnwrap(wire["path"] as? [String: Any])
    let candidates = try XCTUnwrap(pathObject["candidates"] as? [[String: Any]])
    var webSocket = try XCTUnwrap(candidates.first(where: { $0["id"] as? String == "w1" }))
    webSocket["url"] = endpoint.url
    pathObject["candidates"] = [webSocket]
    wire["path"] = pathObject
    let artifact = try parseArtifactV2(
      JSONSerialization.data(
        withJSONObject: wire, options: [.sortedKeys, .withoutEscapingSlashes])
    )
    let candidateSet = try AdmissionCodecV2.canonicalizeCandidates(artifact)
    XCTAssertEqual(candidateSet.candidates.map(\.normalizedURL), [endpoint.url])
    let clientStarted = ContinuousClock.now
    var clientOperation = "connect"
    do {
      let session = try await connectV2(
        lease: ArtifactLeaseV2(artifact: artifact) {},
        options: ConnectorOptions(
          origin: "https://client.example",
          connectTimeout: .seconds(5),
          trustRootsPEM: [Data(endpoint.caPEM.utf8)]
        )
      )

      clientOperation = "liveness"
      _ = try await session.probeLiveness()
      clientOperation = "open stream"
      let stream = try await session.openStream(kind: "interop.echo")
      clientOperation = "write initial payload"
      _ = try await stream.write(Data("hello-go".utf8))
      clientOperation = "read peer payloads"
      let greeting = try await readMessage(stream)
      let serverRekey = try await readMessage(stream)
      XCTAssertEqual(greeting, Data("hello-ts".utf8))
      XCTAssertEqual(serverRekey, Data("go-rekey-ok".utf8))
      clientOperation = "rekey"
      try await session.rekey()
      clientOperation = "write post-rekey payload"
      _ = try await stream.write(Data("ts-rekey-ok".utf8))
      clientOperation = "finish stream"
      try await stream.closeWrite()
      clientOperation = "read stream finish"
      let done = try await readMessage(stream)
      let eof = try await stream.read(maxBytes: 1)
      XCTAssertEqual(done, Data("done".utf8))
      XCTAssertNil(eof)
      try await session.close()
    } catch {
      process.waitUntilExit()
      let peerError = errors.fileHandleForReading.readDataToEndOfFile()
      throw GoWSSInteropError(
        client: error,
        clientDuration: clientStarted.duration(to: .now),
        clientOperation: clientOperation,
        peer: String(decoding: peerError, as: UTF8.self),
        peerExit: process.terminationStatus
      )
    }

    process.waitUntilExit()
    let peerError = errors.fileHandleForReading.readDataToEndOfFile()
    XCTAssertEqual(process.terminationStatus, 0, String(decoding: peerError, as: UTF8.self))
  }

  private func goWSSArtifact(endpoint: GoWSSEndpoint, vectorIndex: Int) throws -> ArtifactV2 {
    let source = try loadArtifactJSON(index: vectorIndex)
    var wire = try XCTUnwrap(
      JSONSerialization.jsonObject(with: Data(source.utf8)) as? [String: Any])
    var pathObject = try XCTUnwrap(wire["path"] as? [String: Any])
    let candidates = try XCTUnwrap(pathObject["candidates"] as? [[String: Any]])
    var webSocket = try XCTUnwrap(candidates.first(where: { $0["id"] as? String == "w1" }))
    webSocket["url"] = endpoint.url
    pathObject["candidates"] = [webSocket]
    wire["path"] = pathObject
    return try parseArtifactV2(
      JSONSerialization.data(
        withJSONObject: wire, options: [.sortedKeys, .withoutEscapingSlashes])
    )
  }

  private func exerciseGoSession(_ session: any Session) async throws {
    _ = try await session.probeLiveness()
    let stream = try await session.openStream(kind: "interop.echo")
    _ = try await stream.write(Data("hello-go".utf8))
    let greeting = try await readMessage(stream)
    let serverRekey = try await readMessage(stream)
    XCTAssertEqual(greeting, Data("hello-ts".utf8))
    XCTAssertEqual(serverRekey, Data("go-rekey-ok".utf8))
    try await session.rekey()
    _ = try await stream.write(Data("ts-rekey-ok".utf8))
    try await stream.closeWrite()
    let done = try await readMessage(stream)
    let eof = try await stream.read(maxBytes: 1)
    XCTAssertEqual(done, Data("done".utf8))
    XCTAssertNil(eof)
  }

  private func waitForControllerSession(
    _ controller: ConnectionControllerV2,
    source: ControllerGoWSSArtifactSourceV2,
    afterAcquisitions minimumAcquisitions: Int
  ) async throws -> any Session {
    let deadline = ContinuousClock.now + .seconds(5)
    while ContinuousClock.now < deadline {
      let snapshot = await controller.snapshot()
      if snapshot.state == .failed { throw ControllerGoWSSTestError.failed }
      let counts = await source.counts()
      if counts.acquisitions >= minimumAcquisitions,
        snapshot.state == .connected,
        let session = snapshot.currentSession
      {
        return session
      }
      try await Task.sleep(for: .milliseconds(1))
    }
    let snapshot = await controller.snapshot()
    let counts = await source.counts()
    throw ControllerGoWSSTestError.timeout(
      state: snapshot.state,
      attempt: snapshot.attempt,
      hasCurrentSession: snapshot.currentSession != nil,
      acquisitions: counts.acquisitions
    )
  }

  private func readMessage(_ stream: any ByteStream) async throws -> Data {
    let value = try await stream.read(maxBytes: 64)
    return try XCTUnwrap(value)
  }

  private func readFirstLine(_ handle: FileHandle) throws -> Data {
    var buffered = Data()
    while true {
      let chunk = try handle.read(upToCount: 1) ?? Data()
      guard !chunk.isEmpty else { throw ConnectorQueueError.closed }
      buffered.append(chunk)
      if chunk[0] == 0x0a { return buffered.dropLast() }
    }
  }
}

private func baseArtifactV3ForConnector() throws -> ArtifactV3 {
  let url = packageRoot().appendingPathComponent("testdata/transport_v3/artifact_vectors.json")
  let root = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
  let positive = root["positive"] as! [[String: Any]]
  return try parseArtifactV3(Data((positive[0]["artifact_json"] as! String).utf8))
}

private func expiringArtifactV3ForConnector(at expiry: Int) throws -> ArtifactV3 {
  let artifact = try baseArtifactV3ForConnector()
  var root = try JSONSerialization.jsonObject(with: artifact.canonicalJSON) as! [String: Any]
  var session = root["session"] as! [String: Any]
  session["init_expire_at_unix_s"] = expiry
  root["session"] = session
  return try parseArtifactV3(FlowersecJCSV3.encode(root))
}

private struct ConnectorBinaryPair {
  let client: ConnectorMemoryBinaryTransport
  let server: ConnectorMemoryBinaryTransport

  init() {
    let clientQueue = ConnectorBinaryQueue()
    let serverQueue = ConnectorBinaryQueue()
    client = ConnectorMemoryBinaryTransport(inbound: clientQueue, outbound: serverQueue)
    server = ConnectorMemoryBinaryTransport(inbound: serverQueue, outbound: clientQueue)
  }
}

private actor ConnectorMemoryBinaryTransport: FlowersecBinaryTransport {
  private let inbound: ConnectorBinaryQueue
  private let outbound: ConnectorBinaryQueue

  init(inbound: ConnectorBinaryQueue, outbound: ConnectorBinaryQueue) {
    self.inbound = inbound
    self.outbound = outbound
  }

  func writeBinary(_ data: Data) async throws { await outbound.push(data) }
  func readBinary() async throws -> Data { try await inbound.next() }
  func close() async { await inbound.finish() }
}

private actor ConnectorBinaryQueue {
  private var values: [Data] = []
  private var waiters: [CheckedContinuation<Data, Error>] = []
  private var closed = false

  func push(_ value: Data) {
    guard !closed else { return }
    if let waiter = waiters.first {
      waiters.removeFirst()
      waiter.resume(returning: value)
    } else {
      values.append(value)
    }
  }

  func next() async throws -> Data {
    if !values.isEmpty { return values.removeFirst() }
    if closed { throw ConnectorQueueError.closed }
    return try await withCheckedThrowingContinuation { waiters.append($0) }
  }

  func finish() {
    closed = true
    let pending = waiters
    waiters.removeAll()
    for waiter in pending { waiter.resume(throwing: ConnectorQueueError.closed) }
  }
}

private enum ConnectorQueueError: Error { case closed, invalid }

private func XCTAssertThrowsErrorAsync<T>(
  _ expression: @autoclosure () async throws -> T,
  _ errorHandler: (any Error) -> Void = { _ in },
  file: StaticString = #filePath,
  line: UInt = #line
) async {
  do {
    _ = try await expression()
    XCTFail("Expected expression to throw", file: file, line: line)
  } catch {
    errorHandler(error)
  }
}

private func decodeTest32(_ value: String) throws -> Data {
  var text = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
  text += String(repeating: "=", count: (4 - text.count % 4) % 4)
  return try XCTUnwrap(Data(base64Encoded: text))
}

private actor ConnectorSpendCounter {
  private var count = 0
  func commit() { count += 1 }
  func value() -> Int { count }
}

private struct GoWSSEndpoint: Decodable {
  let url: String
  let caPEM: String

  enum CodingKeys: String, CodingKey {
    case url
    case caPEM = "ca_pem"
  }
}

private struct GoWSSNotification: Codable, Equatable, Sendable {
  let state: String
}

private final class GoWSSPeer: @unchecked Sendable {
  let endpoint: GoWSSEndpoint
  private let process: Process
  private let errors: Pipe
  private var result: (status: Int32, stderr: String)?

  private init(process: Process, errors: Pipe, endpoint: GoWSSEndpoint) {
    self.process = process
    self.errors = errors
    self.endpoint = endpoint
  }

  static func start(path: String, serverNotify: Bool = false) throws -> GoWSSPeer {
    let process = Process()
    let output = Pipe()
    let errors = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = ["go", "run", "./internal/cmd/ts-session-peer", "--path", path]
    if serverNotify { process.arguments?.append("--server-notify") }
    process.currentDirectoryURL = packageRoot().appendingPathComponent("flowersec-go")
    process.standardOutput = output
    process.standardError = errors
    try process.run()
    do {
      let endpoint = try JSONDecoder().decode(
        GoWSSEndpoint.self,
        from: readEndpointLine(output.fileHandleForReading)
      )
      return GoWSSPeer(process: process, errors: errors, endpoint: endpoint)
    } catch {
      if process.isRunning {
        process.terminate()
        process.waitUntilExit()
      }
      throw error
    }
  }

  func finish() -> (status: Int32, stderr: String) {
    if let result { return result }
    if !waitForExit(process, timeout: 5) {
      process.terminate()
      _ = waitForExit(process, timeout: 2)
    }
    let value = (
      status: process.isRunning ? -1 : process.terminationStatus,
      stderr: String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    )
    result = value
    return value
  }

  func stop() {
    if process.isRunning {
      process.terminate()
      _ = waitForExit(process, timeout: 2)
    }
  }

  private static func waitForExit(_ process: Process, timeout: TimeInterval) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while process.isRunning && Date() < deadline {
      Thread.sleep(forTimeInterval: 0.01)
    }
    return !process.isRunning
  }

  private func waitForExit(_ process: Process, timeout: TimeInterval) -> Bool {
    Self.waitForExit(process, timeout: timeout)
  }

  private static func readEndpointLine(_ handle: FileHandle) throws -> Data {
    var buffered = Data()
    while true {
      let chunk = try handle.read(upToCount: 1) ?? Data()
      guard !chunk.isEmpty else { throw ControllerGoWSSTestError.peerClosed }
      if chunk[0] == 0x0a { return buffered }
      buffered.append(chunk)
    }
  }
}

private actor ControllerGoWSSArtifactSourceV2: ArtifactSourceV2 {
  private var artifacts: [ArtifactV2]
  private var acquisitions = 0
  private var spends = 0

  init(artifacts: [ArtifactV2]) {
    self.artifacts = artifacts
  }

  func acquireArtifact() throws -> ArtifactLeaseV2 {
    guard !artifacts.isEmpty else {
      throw ArtifactSourceFailureV2(disposition: .terminal)
    }
    acquisitions += 1
    let artifact = artifacts.removeFirst()
    return ArtifactLeaseV2(artifact: artifact) { await self.recordSpend() }
  }

  func counts() -> (acquisitions: Int, spends: Int) {
    (acquisitions, spends)
  }

  private func recordSpend() {
    spends += 1
  }
}

private enum ControllerGoWSSTestError: Error {
  case failed
  case peerClosed
  case timeout(
    state: ConnectionStateV2,
    attempt: UInt64,
    hasCurrentSession: Bool,
    acquisitions: Int
  )
}

private struct GoWSSInteropError: LocalizedError {
  let client: any Error
  let clientDuration: Duration
  let clientOperation: String
  let peer: String
  let peerExit: Int32

  var errorDescription: String? {
    "Swift client \(clientOperation) failed after \(clientDuration): \(client); Go peer exit \(peerExit): \(peer.trimmingCharacters(in: .whitespacesAndNewlines))"
  }
}

private struct ConnectorTestTLS {
  let caPEM: Data
  let certificate: NIOSSLCertificate
  let privateKey: NIOSSLPrivateKey

  static func load() throws -> Self {
    let resources = try XCTUnwrap(Bundle.module.resourceURL?.appendingPathComponent("Fixtures"))
    let ca = try Data(contentsOf: resources.appendingPathComponent("self_signed_ca.pem"))
    let cert = try Data(contentsOf: resources.appendingPathComponent("self_signed_cert.pem"))
    let key = try Data(contentsOf: resources.appendingPathComponent("self_signed_key.pem"))
    return try Self(
      caPEM: ca,
      certificate: XCTUnwrap(NIOSSLCertificate.fromPEMBytes(Array(cert)).first),
      privateKey: NIOSSLPrivateKey(bytes: Array(key), format: .pem)
    )
  }

  #if os(macOS)
    static func makeShortLivedSelfSigned() throws -> Self {
      let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("flowersec-swift-v3-tls-\(UUID().uuidString)", isDirectory: true)
      try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
      defer { try? FileManager.default.removeItem(at: directory) }
      let certificateURL = directory.appendingPathComponent("leaf.pem")
      let privateKeyURL = directory.appendingPathComponent("leaf-key.pem")
      let process = Process()
      let errors = Pipe()
      process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
      process.arguments = [
        "openssl", "req", "-x509", "-newkey", "ec",
        "-pkeyopt", "ec_paramgen_curve:P-256", "-sha256", "-nodes", "-days", "7",
        "-subj", "/CN=localhost",
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "keyUsage=critical,digitalSignature",
        "-addext", "extendedKeyUsage=serverAuth",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-keyout", privateKeyURL.path,
        "-out", certificateURL.path,
      ]
      process.standardOutput = FileHandle.nullDevice
      process.standardError = errors
      try process.run()
      process.waitUntilExit()
      let diagnostic = String(
        data: errors.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
      guard process.terminationStatus == 0 else {
        throw ConnectorGeneratedTLSError.failed(diagnostic)
      }
      let certificatePEM = try Data(contentsOf: certificateURL)
      let privateKeyPEM = try Data(contentsOf: privateKeyURL)
      return try Self(
        caPEM: certificatePEM,
        certificate: XCTUnwrap(NIOSSLCertificate.fromPEMBytes(Array(certificatePEM)).first),
        privateKey: NIOSSLPrivateKey(bytes: Array(privateKeyPEM), format: .pem)
      )
    }
  #endif
}

private enum ConnectorGeneratedTLSError: Error {
  case failed(String)
}

private actor UnsupportedCountingRuntimeV3: RuntimeCarrierAdapterV3 {
  nonisolated let capabilities = RuntimeCapabilitiesV3.linux
  private var preparations = 0

  nonisolated func validate(options: ConnectorOptions) throws {}

  func prepare(
    candidate: CanonicalCandidateV3,
    path: PathKind,
    role: SessionRoleV3,
    options: ConnectorOptions,
    activePinHashes: [Data]?
  ) async throws -> any PreparedCarrierConnectionV3 {
    preparations += 1
    throw ConnectorBoundaryErrorV3.runtimeUnsupported
  }

  func prepareCount() -> Int { preparations }
}

private actor CandidateFailureRuntimeV3: RuntimeCarrierAdapterV3 {
  nonisolated let capabilities = RuntimeCapabilitiesV3.macOS
  private var candidateIDs = Set<String>()

  nonisolated func validate(options: ConnectorOptions) throws {}

  func prepare(
    candidate: CanonicalCandidateV3,
    path: PathKind,
    role: SessionRoleV3,
    options: ConnectorOptions,
    activePinHashes: [Data]?
  ) async throws -> any PreparedCarrierConnectionV3 {
    candidateIDs.insert(candidate.id)
    if candidate.id == "w-pin" { throw ConnectorBoundaryErrorV3.securityFailed }
    throw ConnectorBoundaryErrorV3.runtimeFailed
  }

  func preparedIDs() -> Set<String> { candidateIDs }
}

private actor OpaqueCandidateFailureRuntimeV3: RuntimeCarrierAdapterV3 {
  nonisolated let capabilities = RuntimeCapabilitiesV3.macOS

  nonisolated func validate(options: ConnectorOptions) throws {}

  func prepare(
    candidate: CanonicalCandidateV3,
    path: PathKind,
    role: SessionRoleV3,
    options: ConnectorOptions,
    activePinHashes: [Data]?
  ) async throws -> any PreparedCarrierConnectionV3 {
    if candidate.id == "w-pin" { throw ConnectorBoundaryErrorV3.browserPinOpaque }
    throw ConnectorBoundaryErrorV3.runtimeFailed
  }
}

private final class MutableUnixClockV3: @unchecked Sendable {
  private let lock = NSLock()
  private var value: UInt64

  init(value: UInt64) { self.value = value }

  func read() -> UInt64 { lock.withLock { value } }

  func set(_ value: UInt64) { lock.withLock { self.value = value } }
}

private final class SteppingUnixClockV3: @unchecked Sendable {
  private let lock = NSLock()
  private var values: [UInt64]
  private var last: UInt64

  init(values: [UInt64]) {
    precondition(!values.isEmpty)
    self.values = values
    self.last = values[0]
  }

  func read() -> UInt64 {
    lock.withLock {
      if !values.isEmpty { last = values.removeFirst() }
      return last
    }
  }
}

private actor CandidateRaceRecorderV3 {
  struct Snapshot: Sendable {
    let writes: [String]
    let closed: [String]
  }

  private var writes: [String] = []
  private var closed = Set<String>()

  func recordWrite(_ id: String) { writes.append(id) }
  func recordClose(_ id: String) { closed.insert(id) }

  func snapshot() -> Snapshot {
    Snapshot(writes: writes, closed: closed.sorted())
  }
}

private actor CandidateRaceRuntimeV3: RuntimeCarrierAdapterV3 {
  nonisolated let capabilities = RuntimeCapabilitiesV3.macOS
  private let recorder: CandidateRaceRecorderV3
  private let slowCandidateID: String?
  private let failAll: Bool

  init(
    recorder: CandidateRaceRecorderV3,
    slowCandidateID: String? = nil,
    failAll: Bool = false
  ) {
    self.recorder = recorder
    self.slowCandidateID = slowCandidateID
    self.failAll = failAll
  }

  nonisolated func validate(options: ConnectorOptions) throws {}

  func prepare(
    candidate: CanonicalCandidateV3,
    path: PathKind,
    role: SessionRoleV3,
    options: ConnectorOptions,
    activePinHashes: [Data]?
  ) async throws -> any PreparedCarrierConnectionV3 {
    if failAll { throw ConnectorBoundaryErrorV3.runtimeFailed }
    if candidate.id == slowCandidateID {
      try? await Task.sleep(for: .milliseconds(25))
    }
    return CandidateRacePreparedConnectionV3(candidateID: candidate.id, recorder: recorder)
  }
}

private actor CandidatePrepareGateV3 {
  private var arrivals = Set<String>()
  private var waiters: [CheckedContinuation<Void, Never>] = []
  private var released = false

  var arrivalCount: Int { arrivals.count }

  func wait(candidateID: String) async {
    arrivals.insert(candidateID)
    guard !released else { return }
    await withCheckedContinuation { continuation in
      waiters.append(continuation)
    }
  }

  func release() {
    guard !released else { return }
    released = true
    let pending = waiters
    waiters.removeAll()
    for waiter in pending { waiter.resume() }
  }
}

private struct GatedCandidateRuntimeV3: RuntimeCarrierAdapterV3 {
  let capabilities = RuntimeCapabilitiesV3.macOS
  let recorder: CandidateRaceRecorderV3
  let gate: CandidatePrepareGateV3
  let immediateCandidateID: String?

  init(
    recorder: CandidateRaceRecorderV3,
    gate: CandidatePrepareGateV3,
    immediateCandidateID: String? = nil
  ) {
    self.recorder = recorder
    self.gate = gate
    self.immediateCandidateID = immediateCandidateID
  }

  func validate(options: ConnectorOptions) throws {}

  func prepare(
    candidate: CanonicalCandidateV3,
    path: PathKind,
    role: SessionRoleV3,
    options: ConnectorOptions,
    activePinHashes: [Data]?
  ) async throws -> any PreparedCarrierConnectionV3 {
    if candidate.id != immediateCandidateID {
      await gate.wait(candidateID: candidate.id)
    }
    return CandidateRacePreparedConnectionV3(candidateID: candidate.id, recorder: recorder)
  }
}

private actor HangingAdmissionRecorderV3 {
  struct Snapshot: Sendable {
    let reads: Int
    let closed: Int
  }

  private var reads = 0
  private var closed = 0

  func recordRead() { reads += 1 }
  func recordClose() { closed += 1 }
  func snapshot() -> Snapshot { Snapshot(reads: reads, closed: closed) }
}

private actor HangingAdmissionRuntimeV3: RuntimeCarrierAdapterV3 {
  nonisolated let capabilities = RuntimeCapabilitiesV3.macOS
  private let recorder: HangingAdmissionRecorderV3

  init(recorder: HangingAdmissionRecorderV3) { self.recorder = recorder }

  nonisolated func validate(options: ConnectorOptions) throws {}

  func prepare(
    candidate: CanonicalCandidateV3,
    path: PathKind,
    role: SessionRoleV3,
    options: ConnectorOptions,
    activePinHashes: [Data]?
  ) async throws -> any PreparedCarrierConnectionV3 {
    HangingAdmissionConnectionV3(recorder: recorder)
  }
}

private actor HangingAdmissionConnectionV3: PreparedCarrierConnectionV3 {
  nonisolated let carrier = CarrierKind.webSocket
  private let recorder: HangingAdmissionRecorderV3
  private var readWaiter: CheckedContinuation<Data, Error>?
  private var closed = false

  init(recorder: HangingAdmissionRecorderV3) { self.recorder = recorder }

  func writeAdmission(_ frame: Data) async throws {
    guard !closed else { throw ConnectorBoundaryErrorV3.runtimeFailed }
  }

  func readAdmission() async throws -> Data {
    await recorder.recordRead()
    return try await withCheckedThrowingContinuation { continuation in
      if closed {
        continuation.resume(throwing: ConnectorBoundaryErrorV3.runtimeFailed)
      } else {
        readWaiter = continuation
      }
    }
  }

  func makeCarrier(inboundCapacity: UInt16) async throws -> any TransportV3CarrierSession {
    throw ConnectorBoundaryErrorV3.sessionFailed
  }

  func close() async {
    guard !closed else { return }
    closed = true
    let waiter = readWaiter
    readWaiter = nil
    waiter?.resume(throwing: ConnectorBoundaryErrorV3.runtimeFailed)
    await recorder.recordClose()
  }
}

private func waitUntilConnectorV3(
  timeout: Duration,
  _ predicate: @escaping @Sendable () async -> Bool
) async -> Bool {
  let deadline = ContinuousClock.now.advanced(by: timeout)
  while ContinuousClock.now < deadline {
    if await predicate() { return true }
    try? await Task.sleep(for: .milliseconds(2))
  }
  return await predicate()
}

private struct CandidateRacePreparedConnectionV3: PreparedCarrierConnectionV3 {
  let carrier = CarrierKind.webSocket
  let candidateID: String
  let recorder: CandidateRaceRecorderV3

  func writeAdmission(_ frame: Data) async throws {
    await recorder.recordWrite(candidateID)
    throw ConnectorBoundaryErrorV3.runtimeFailed
  }

  func readAdmission() async throws -> Data { throw ConnectorBoundaryErrorV3.runtimeFailed }

  func makeCarrier(inboundCapacity: UInt16) async throws -> any TransportV3CarrierSession {
    throw ConnectorBoundaryErrorV3.runtimeFailed
  }

  func close() async { await recorder.recordClose(candidateID) }
}

private actor FSAResponseRuntimeV3: RuntimeCarrierAdapterV3 {
  nonisolated let capabilities = RuntimeCapabilitiesV3.macOS
  private let status: AdmissionStatusV3
  private var preparations = 0

  init(status: AdmissionStatusV3) { self.status = status }

  nonisolated func validate(options: ConnectorOptions) throws {}

  func prepare(
    candidate: CanonicalCandidateV3,
    path: PathKind,
    role: SessionRoleV3,
    options: ConnectorOptions,
    activePinHashes: [Data]?
  ) async throws -> any PreparedCarrierConnectionV3 {
    preparations += 1
    return FSAResponsePreparedConnectionV3(status: status)
  }

  func prepareCount() -> Int { preparations }
}

private struct FSAResponsePreparedConnectionV3: PreparedCarrierConnectionV3 {
  let carrier = CarrierKind.webSocket
  let status: AdmissionStatusV3

  func writeAdmission(_ frame: Data) async throws {}

  func readAdmission() async throws -> Data {
    let reason = status == .reject ? Data("reject".utf8) : Data("retryable".utf8)
    var frame = Data([0x46, 0x53, 0x41, 0x33, 3, status.rawValue])
    frame.append(UInt8((reason.count >> 8) & 0xff))
    frame.append(UInt8(reason.count & 0xff))
    frame.append(reason)
    return frame
  }

  func makeCarrier(inboundCapacity: UInt16) async throws -> any TransportV3CarrierSession {
    throw ConnectorBoundaryErrorV3.sessionFailed
  }

  func close() async {}
}

private actor ConnectorAcceptedTransport {
  private struct Waiter {
    let id: UInt64
    let continuation: CheckedContinuation<ConnectorNIOBinaryTransport, Error>
  }

  private var values: [ConnectorNIOBinaryTransport] = []
  private var waiters: [Waiter] = []
  private var nextWaiterID: UInt64 = 1
  private var closed = false
  private var selectedProtocol: String?

  func deliver(_ transport: ConnectorNIOBinaryTransport, protocolValue: String?) {
    guard !closed else {
      Task { await transport.close() }
      return
    }
    selectedProtocol = protocolValue
    if let waiter = waiters.first {
      waiters.removeFirst()
      waiter.continuation.resume(returning: transport)
    } else {
      values.append(transport)
    }
  }

  func accept() async throws -> ConnectorNIOBinaryTransport {
    if !values.isEmpty { return values.removeFirst() }
    if closed { throw ConnectorQueueError.closed }
    let waiterID = nextWaiterID
    nextWaiterID &+= 1
    if nextWaiterID == 0 { nextWaiterID = 1 }
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        if Task.isCancelled {
          continuation.resume(throwing: CancellationError())
        } else if closed {
          continuation.resume(throwing: ConnectorQueueError.closed)
        } else {
          waiters.append(Waiter(id: waiterID, continuation: continuation))
        }
      }
    } onCancel: {
      Task { await self.cancel(waiterID) }
    }
  }

  func protocolValue() -> String? { selectedProtocol }

  func finish() {
    guard !closed else { return }
    closed = true
    let pending = waiters
    let queued = values
    waiters.removeAll()
    values.removeAll()
    for waiter in pending { waiter.continuation.resume(throwing: ConnectorQueueError.closed) }
    for transport in queued { Task { await transport.close() } }
  }

  private func cancel(_ waiterID: UInt64) {
    guard let index = waiters.firstIndex(where: { $0.id == waiterID }) else { return }
    waiters.remove(at: index).continuation.resume(throwing: CancellationError())
  }
}

private final class ConnectorWSSServer: @unchecked Sendable {
  let port: Int
  private let group: MultiThreadedEventLoopGroup
  private let channel: any Channel
  private let accepted: ConnectorAcceptedTransport

  private init(
    port: Int,
    group: MultiThreadedEventLoopGroup,
    channel: any Channel,
    accepted: ConnectorAcceptedTransport
  ) {
    self.port = port
    self.group = group
    self.channel = channel
    self.accepted = accepted
  }

  static func start(
    tls material: ConnectorTestTLS,
    selectedProtocol: String,
    accepted: ConnectorAcceptedTransport
  ) async throws -> ConnectorWSSServer {
    try await startServer(tls: material, selectedProtocol: selectedProtocol, accepted: accepted)
  }

  static func startPlaintext(
    selectedProtocol: String,
    accepted: ConnectorAcceptedTransport
  ) async throws -> ConnectorWSSServer {
    try await startServer(tls: nil, selectedProtocol: selectedProtocol, accepted: accepted)
  }

  private static func startServer(
    tls material: ConnectorTestTLS?,
    selectedProtocol: String,
    accepted: ConnectorAcceptedTransport
  ) async throws -> ConnectorWSSServer {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let context: NIOSSLContext?
    if let material {
      var tls = TLSConfiguration.makeServerConfiguration(
        certificateChain: [.certificate(material.certificate)],
        privateKey: .privateKey(material.privateKey))
      tls.minimumTLSVersion = .tlsv13
      tls.maximumTLSVersion = .tlsv13
      tls.applicationProtocols = ["http/1.1"]
      context = try NIOSSLContext(configuration: tls)
    } else {
      context = nil
    }
    let channel = try await ServerBootstrap(group: group)
      .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
      .childChannelInitializer { channel in
        let upgrader = NIOWebSocketServerUpgrader(
          maxFrameSize: FlowersecSDKDefaults.Yamux.maxFrameBytes + 12,
          shouldUpgrade: { channel, request in
            guard request.headers["sec-websocket-protocol"].contains(selectedProtocol) else {
              return channel.eventLoop.makeSucceededFuture(nil)
            }
            var headers = HTTPHeaders()
            headers.add(name: "sec-websocket-protocol", value: selectedProtocol)
            return channel.eventLoop.makeSucceededFuture(headers)
          },
          upgradePipelineHandler: { channel, request in
            let transport = ConnectorNIOBinaryTransport(channel: channel)
            let handler = ConnectorNIOWebSocketHandler(transport: transport)
            do {
              try channel.pipeline.syncOperations.addHandlers(
                NIOWebSocketFrameAggregator(
                  minNonFinalFragmentSize: 1,
                  maxAccumulatedFrameCount: 1024,
                  maxAccumulatedFrameSize: FlowersecSDKDefaults.Yamux.maxFrameBytes + 12),
                handler
              )
              Task {
                await accepted.deliver(
                  transport, protocolValue: request.headers.first(name: "sec-websocket-protocol"))
              }
              return channel.eventLoop.makeSucceededFuture(())
            } catch {
              return channel.eventLoop.makeFailedFuture(error)
            }
          })
        let upgrade: NIOHTTPServerUpgradeSendableConfiguration = (
          upgraders: [upgrader], completionHandler: { _ in }
        )
        do {
          if let context {
            try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context))
          }
          return channel.pipeline.configureHTTPServerPipeline(withServerUpgrade: upgrade)
        } catch { return channel.eventLoop.makeFailedFuture(error) }
      }.bind(host: "127.0.0.1", port: 0).get()
    return ConnectorWSSServer(
      port: try XCTUnwrap(channel.localAddress?.port), group: group, channel: channel,
      accepted: accepted)
  }

  func close() async {
    await accepted.finish()
    try? await channel.close().get()
    try? await group.shutdownGracefully()
  }
}

private final class ConnectorNIOBinaryTransport: FlowersecBinaryTransport, @unchecked Sendable {
  private let channel: any Channel
  private let lock = NSLock()
  private var frames: [Data] = []
  private var waiters: [CheckedContinuation<Data, Error>] = []
  private var closed = false

  init(channel: any Channel) { self.channel = channel }

  func writeBinary(_ data: Data) async throws {
    var buffer = channel.allocator.buffer(capacity: data.count)
    buffer.writeBytes(data)
    try await channel.writeAndFlush(WebSocketFrame(fin: true, opcode: .binary, data: buffer)).get()
  }

  func readBinary() async throws -> Data {
    try await withCheckedThrowingContinuation { continuation in
      lock.withLock {
        if closed {
          continuation.resume(throwing: ConnectorQueueError.closed)
        } else if !frames.isEmpty {
          continuation.resume(returning: frames.removeFirst())
        } else {
          waiters.append(continuation)
        }
      }
    }
  }

  func close() async {
    finish()
    try? await channel.close().get()
  }

  func receive(_ data: Data) {
    let waiter = lock.withLock { () -> CheckedContinuation<Data, Error>? in
      if let waiter = waiters.first {
        waiters.removeFirst()
        return waiter
      }
      frames.append(data)
      return nil
    }
    waiter?.resume(returning: data)
  }

  func finish() {
    let pending = lock.withLock { () -> [CheckedContinuation<Data, Error>] in
      guard !closed else { return [] }
      closed = true
      let pending = waiters
      waiters.removeAll()
      frames.removeAll()
      return pending
    }
    for waiter in pending { waiter.resume(throwing: ConnectorQueueError.closed) }
  }
}

private final class ConnectorNIOWebSocketHandler: ChannelInboundHandler, @unchecked Sendable {
  typealias InboundIn = WebSocketFrame
  private let transport: ConnectorNIOBinaryTransport
  init(transport: ConnectorNIOBinaryTransport) { self.transport = transport }
  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let frame = unwrapInboundIn(data)
    guard frame.opcode == .binary else {
      context.close(promise: nil)
      return
    }
    var payload = frame.unmaskedData
    transport.receive(payload.readData(length: payload.readableBytes) ?? Data())
  }
  func channelInactive(context: ChannelHandlerContext) {
    transport.finish()
    context.fireChannelInactive()
  }
  func errorCaught(context: ChannelHandlerContext, error: any Error) {
    transport.finish()
    context.close(promise: nil)
  }
}

private actor ConnectorEventRecorder {
  private var events: [String] = []
  func append(_ event: String) { events.append(event) }
  func values() -> [String] { events }
}

private struct ConnectorAdmissionRuntime: RuntimeCarrierAdapterV2 {
  let capabilities = RuntimeCapabilitiesV2.macOS
  let events: ConnectorEventRecorder

  func validate(options: ConnectorOptions) throws {}

  func prepare(
    candidate: CanonicalCandidateV2,
    path: PathKind,
    role: SessionRoleV2,
    options: ConnectorOptions
  ) async throws -> any PreparedCarrierConnectionV2 {
    await events.append("dial")
    return ConnectorAdmissionConnection(events: events)
  }
}

private actor ConnectorAdmissionConnection: PreparedCarrierConnectionV2 {
  nonisolated let carrier = CarrierKind.webSocket
  private let events: ConnectorEventRecorder

  init(events: ConnectorEventRecorder) { self.events = events }

  func writeAdmission(_ data: Data) async throws {
    XCTAssertEqual(data.prefix(4), Data("FSB2".utf8))
    await events.append("write")
  }

  func readAdmission() async throws -> Data {
    await events.append("read")
    var response = Data("FSA2".utf8)
    response.append(contentsOf: [2, 1, 0, 8])
    response.append(Data("capacity".utf8))
    return response
  }

  func makeCarrier(inboundCapacity: UInt16) async throws -> any TransportV2CarrierSession {
    throw ConnectorQueueError.invalid
  }

  func close() async { await events.append("close") }
}
