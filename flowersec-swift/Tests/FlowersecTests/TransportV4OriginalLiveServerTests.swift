#if os(macOS) || os(iOS)
import Darwin
import Foundation
import NIOSSL
import XCTest

@testable import Flowersec

@MainActor
final class TransportOriginalLiveServerTests: XCTestCase {
  func testServePublishesAuthenticatedPlanAndReleasesOriginalLeaseAfterDrain() async throws {
    let fixture = try V4OriginalServerFixture(loseAdmissionResult: false)
    defer { fixture.close(); try? FileManager.default.removeItem(at: fixture.directory) }
    let deadline = Task { try await Task.sleep(for: .seconds(30)); fixture.timeout() }
    defer { deadline.cancel() }
    let state = V4OriginalServeCallbacks(admissionPath: fixture.admissionPath)
    let streams = try StreamHandlers()
    try streams.handleStream(kind: "echo") { incoming in
      var bytes = Data()
      while let part = try await incoming.stream.read(maxBytes: 4096) { bytes.append(part) }
      var offset = 0
      while offset < bytes.count {
        let count = try await incoming.stream.write(Data(bytes.dropFirst(offset)))
        guard count > 0 else { throw SessionError.operationFailed }; offset += count
      }
    }
    let handle = try await fixture.environment.serve(state.options(source: fixture.source.materialSource, streams: streams))
    do {
      try await fixture.start()
      let original = try await fixture.authorize(fixture.initial)
      let host = try fixture.startRelay(original.publication)
      let run = Task { try await host.run() }; fixture.installRun(run)
      try await fixture.waitRelayListeners(original); try await fixture.allow(original)
      try await original.peer.establish(roots: [fixture.tls.rootPEM])
      let bytes = Data("aggregate Serve authenticated echo".utf8)
      let echoed = try await original.peer.echo(bytes)
      XCTAssertEqual(echoed, bytes)
      XCTAssertTrue(original.peer.readySubmitted)
      try await state.waitForPublication()
      XCTAssertEqual(state.authorizations, 1); XCTAssertEqual(state.publications, 1)
      try handle.drain(timeout: .seconds(1))
      _ = try await handle.waitDrain()
      let cleanup = try await handle.waitCleanup()
      XCTAssertTrue(cleanup.complete); XCTAssertEqual(state.releases, 1); XCTAssertEqual(state.lease.closes, 1)
      XCTAssertEqual(try v4CommittedRowCount(path: fixture.admissionPath, table: "admissions"), 1)
      XCTAssertFalse(fixture.source.cleanupStatus().complete, "Serve closes only its borrowed source's acquired material")
      original.peer.close(); await original.peer.waitClosed()
      try await fixture.finish()
    } catch {
      handle.close(); _ = try? await handle.waitCleanup(); fixture.close(); try? await fixture.finish(); throw error
    }
  }

  func testServeDrainDuringApplicationAuthorizationCannotCommitAdmissionOrPublishReady() async throws {
    let fixture = try V4OriginalServerFixture(loseAdmissionResult: false)
    defer { fixture.close(); try? FileManager.default.removeItem(at: fixture.directory) }
    let deadline = Task { try await Task.sleep(for: .seconds(30)); fixture.timeout() }
    defer { deadline.cancel() }
    let state = V4OriginalServeCallbacks(admissionPath: fixture.admissionPath, holdAuthorization: true)
    let handle = try await fixture.environment.serve(state.options(source: fixture.source.materialSource))
    do {
      try await fixture.start()
      let original = try await fixture.authorize(fixture.initial)
      let host = try fixture.startRelay(original.publication)
      let run = Task { try await host.run() }; fixture.installRun(run)
      try await fixture.waitRelayListeners(original); try await fixture.allow(original)
      let peer = Task { try await original.peer.establish(roots: [fixture.tls.rootPEM]) }
      fixture.retainPeerTask(peer)
      try await state.waitForAuthorization()
      XCTAssertEqual(try v4CommittedRowCount(path: fixture.admissionPath, table: "admissions"), 0)
      try handle.drain(timeout: .seconds(1))
      XCTAssertFalse(handle.cleanupStatus().complete)
      state.releaseAuthorization()
      do { try await peer.value; XCTFail("Drain allowed a late authorization to publish READY") } catch {}
      let cleanup = try await handle.waitCleanup()
      XCTAssertTrue(cleanup.complete); XCTAssertEqual(state.lease.closes, 1)
      XCTAssertEqual(state.publications, 0); XCTAssertEqual(state.releases, 1)
      XCTAssertFalse(original.peer.fsaReceived)
      XCTAssertEqual(try v4CommittedRowCount(path: fixture.admissionPath, table: "admissions"), 0)
      try await fixture.finish()
    } catch {
      state.releaseAuthorization(); handle.close(); _ = try? await handle.waitCleanup()
      fixture.close(); try? await fixture.finish(); throw error
    }
  }

  func testServeDrainWinsBeforeQueuedOnSessionAndPreventsRawDispatch() async throws {
    let fixture = try V4OriginalServerFixture(loseAdmissionResult: false)
    defer { fixture.close(); try? FileManager.default.removeItem(at: fixture.directory) }
    let deadline = Task { try await Task.sleep(for: .seconds(30)); fixture.timeout() }
    defer { deadline.cancel() }
    let state = V4OriginalServeCallbacks(admissionPath: fixture.admissionPath)
    let blocker = V4ServePublicationBlocker()
    let actor = V4ServePublicationActor()
    let callback = await actor.callback()
    let occupied = Task { await actor.occupy(blocker) }
    defer { blocker.release() }
    try await blocker.waitStarted()
    let streams = try StreamHandlers()
    try streams.handleStream(kind: "echo") { _ in blocker.recordDispatch() }
    let handle = try await fixture.environment.serve(state.options(source: fixture.source.materialSource,
      streams: streams, onSession: callback))
    var phase = "start"
    do {
      try await fixture.start()
      let original = try await fixture.authorize(fixture.initial)
      let host = try fixture.startRelay(original.publication)
      let run = Task { try await host.run() }; fixture.installRun(run)
      try await fixture.waitRelayListeners(original); try await fixture.allow(original)
      phase = "establish"
      try await original.peer.establish(roots: [fixture.tls.rootPEM])
      phase = "drain"
      let incoming = Task { _ = try await original.peer.echo(Data("unpublished".utf8)) }
      fixture.retainPeerTask(incoming)
      try await ContinuousClock().sleep(for: .milliseconds(100))
      XCTAssertEqual(blocker.dispatches, 0)
      try handle.drain(timeout: .seconds(1))
      blocker.release(); await occupied.value
      do { try await incoming.value; XCTFail("Unpublished raw dispatch was admitted") } catch {}
      phase = "serve cleanup"
      let cleanup = try await handle.waitCleanup()
      XCTAssertTrue(cleanup.complete)
      let callbacks = await actor.invocations
      XCTAssertEqual(callbacks, 0); XCTAssertEqual(blocker.dispatches, 0)
      XCTAssertEqual(state.publishedReleases, 0); XCTAssertEqual(state.lease.closes, 1)
      phase = "fixture cleanup"
      try await fixture.finish()
    } catch {
      XCTFail("Queued publication failed during \(phase), canceled=\(Task.isCancelled): \(error)")
      blocker.release(); await occupied.value
      handle.close(); _ = try? await handle.waitCleanup(); fixture.close(); try? await fixture.finish(); throw error
    }
  }

  func testServeRequestRejectionPreservesHealthySiblingSession() async throws {
    let fixture = try V4OriginalServerFixture(loseAdmissionResult: false)
    defer { fixture.close(); try? FileManager.default.removeItem(at: fixture.directory) }
    let deadline = Task { try await Task.sleep(for: .seconds(30)); fixture.timeout() }
    defer { deadline.cancel() }
    let state = V4OriginalServeCallbacks(admissionPath: fixture.admissionPath, rejectSecondRequest: true)
    let streams = try StreamHandlers()
    try streams.handleStream(kind: "echo") { incoming in
      while let bytes = try await incoming.stream.read(maxBytes: 4096) {
        let count = try await incoming.stream.write(bytes)
        XCTAssertEqual(count, bytes.count)
      }
    }
    let handle = try await fixture.environment.serve(state.options(source: fixture.source.materialSource,
      streams: streams, maximumConcurrentSessions: 2))
    var phase = "start"
    do {
      try await fixture.start();
      phase = "authorization"
      let original = try await fixture.authorize(fixture.initial);
      let host = try fixture.startRelay(original.publication);
      let run = Task { try await host.run() }; fixture.installRun(run)
      phase = "listeners"
      try await fixture.waitRelayListeners(original);
      phase = "allow"
      try await fixture.allow(original);
      phase = "establish"
      try await original.peer.establish(roots: [fixture.tls.rootPEM]);
      phase = "publication"
      try await state.waitForPublication();
      phase = "rejection"
      try await state.waitForRejectedRequest();
      XCTAssertTrue(handle.progress().accepting)
      let bytes = Data("healthy sibling after rejection".utf8)
      phase = "echo"
      let echoed = try await original.peer.echo(bytes);
      XCTAssertEqual(echoed, bytes)
      XCTAssertEqual(state.publications, 1)
      handle.close();
      phase = "serve cleanup"
      _ = try await handle.waitCleanup();
      phase = "fixture cleanup"
      try await fixture.finish();
    } catch {
      XCTFail("Healthy sibling workflow failed during \(phase): \(error)")
      handle.close(); _ = try? await handle.waitCleanup(); fixture.close(); try? await fixture.finish(); throw error
    }
  }

  func testProductionLiveClientSourcePreparesBeforeTxBWithRegisteredRelay() async throws {
    for relayDialsClient in [false, true] {
      let fixture = try V4OriginalServerFixture(loseAdmissionResult: false, relayDialsClient: relayDialsClient)
      defer { fixture.close(); try? FileManager.default.removeItem(at: fixture.directory) }
      let deadline = Task { try await Task.sleep(for: .seconds(30)); fixture.timeout() }
      defer { deadline.cancel() }
      var phase = "start"
      do {
        try await fixture.start()
        phase = "live source"
        try await fixture.exerciseProductionLiveSource()
        phase = "fixture cleanup"
        try await fixture.finish()
        XCTAssertFalse(fixture.timedOut)
      } catch {
        XCTFail("Live source direction \(relayDialsClient) failed during \(phase), canceled=\(Task.isCancelled): \(error)")
        fixture.close(); try? await fixture.finish(); throw error
      }
    }
  }

  func testRegisteredLiveSourceAuthenticatesEchoAndJoinsRefusalAndCancellation() async throws {
    for scenario in V4RegisteredSourceScenario.allCases {
      let fixture = try V4OriginalServerFixture(loseAdmissionResult: false)
      defer { fixture.close(); try? FileManager.default.removeItem(at: fixture.directory) }
      let deadline = Task { try await Task.sleep(for: .seconds(30)); fixture.timeout() }
      defer { deadline.cancel() }
      do {
        try await fixture.start()
        try await fixture.exerciseProductionLiveSource(registered: scenario)
        try await fixture.finish()
        XCTAssertFalse(fixture.timedOut)
      } catch {
        XCTFail("Registered source \(scenario) failed: \(error)")
        fixture.close(); try? await fixture.finish(); throw error
      }
    }
  }

  func testPoolServerSourcePreservesCanceledAcquireAndAuthenticatedAllowHandoff() async throws {
    for closeBeforeAllow in [false, true] {
      let fixture = try V4OriginalServerFixture(loseAdmissionResult: false)
      defer { fixture.close(); try? FileManager.default.removeItem(at: fixture.directory) }
      let deadline = Task { try await Task.sleep(for: .seconds(30)); fixture.timeout() }
      defer { deadline.cancel() }
      do {
        try await fixture.exercisePoolServerSource(closeBeforeAllow: closeBeforeAllow)
        try await fixture.finish()
        XCTAssertFalse(fixture.timedOut)
      } catch {
        XCTFail("Pool server closeBeforeAllow=\(closeBeforeAllow) failed: \(error)")
        fixture.close(); try? await fixture.finish(); throw error
      }
    }
  }

  func testNativeHTTPProxyCancellationClosesSlowUpstreamAndPreservesFINAndSibling() async throws {
    let fixture = try V4OriginalServerFixture(loseAdmissionResult: false)
    defer { fixture.close(); try? FileManager.default.removeItem(at: fixture.directory) }
    let deadline = Task { try await Task.sleep(for: .seconds(30)); fixture.timeout() }
    defer { deadline.cancel() }
    var phase = "start"
    do {
      try await fixture.start()
      phase = "public proxy workflow and sibling"
      try await fixture.exerciseProductionLiveSource { client, server in
        try await fixture.exerciseNativeHTTPProxy(client: client, server: server)
      }
      phase = "fixture cleanup"
      try await fixture.finish()
      XCTAssertFalse(fixture.timedOut)
    } catch {
      XCTFail("Native HTTP proxy failed during \(phase): \(error)")
      fixture.close(); try? await fixture.finish(); throw error
    }
  }

  func testNativeWebSocketProxyCloseDrainAndCancellationKeepOriginalOwnerAndSibling() async throws {
    let fixture = try V4OriginalServerFixture(loseAdmissionResult: false)
    defer { fixture.close(); try? FileManager.default.removeItem(at: fixture.directory) }
    let deadline = Task { try await Task.sleep(for: .seconds(30)); fixture.timeout() }
    defer { deadline.cancel() }
    do {
      try await fixture.start()
      try await fixture.exerciseProductionLiveSource { client, server in
        try await fixture.exerciseNativeWebSocketProxy(client: client, server: server)
      }
      try await fixture.finish()
      XCTAssertFalse(fixture.timedOut)
    } catch {
      XCTFail("Public native WebSocket proxy workflow failed: \(error)")
      fixture.close(); try? await fixture.finish(); throw error
    }
  }

  func testOriginalServerAllowACKRetryAndContinuousRelayForwarding() async throws {
    let fixture = try V4OriginalServerFixture(loseAdmissionResult: false)
    defer { fixture.close(); try? FileManager.default.removeItem(at: fixture.directory) }
    let deadline = Task { try await Task.sleep(for: .seconds(30)); fixture.timeout() }
    defer { deadline.cancel() }
    do {
      try await fixture.start()
      let first = try await fixture.authorize(fixture.initial)
      let host = try fixture.startRelay(first.publication)
      let run = Task { try await host.run() }
      fixture.installRun(run)
      let firstTicket = host.initialPublication
      try await fixture.forward(first, ticket: firstTicket, payload: Data("first original encrypted stream".utf8))
      XCTAssertEqual(try v4CommittedRowCount(path: fixture.admissionPath, table: "originals"), 1)
      XCTAssertEqual(try v4CommittedRowCount(path: fixture.admissionPath, table: "admissions"), 1)
      XCTAssertEqual(try v4CommittedRowCount(path: fixture.relayPath, table: "claims"), 2)
      XCTAssertFalse(host.cleanupStatus().complete)

      // The same daemon and ledger accept a separately authorized lease. No
      // receipt, historical row, or first ticket recreates its preparation.
      let secondCredentials = try V4TunnelCredentialFixture(profile: .x25519, hostname: "localhost",
        port: fixture.nextClientPort, serverPort: fixture.nextServerPort, lease: 31, nativeResources: true)
      fixture.retainFoundation(secondCredentials.credentials.base.environment)
      fixture.initial.credentials.base.source.advance(100)
      let second = try await fixture.authorize(secondCredentials)
      let secondTicket = try host.publishLiveOriginal(second.publication)
      try await fixture.forward(second, ticket: secondTicket, payload: Data("second independent encrypted stream".utf8))
      XCTAssertEqual(try v4CommittedRowCount(path: fixture.admissionPath, table: "originals"), 2)
      XCTAssertEqual(try v4CommittedRowCount(path: fixture.admissionPath, table: "admissions"), 2)
      XCTAssertEqual(try v4CommittedRowCount(path: fixture.relayPath, table: "publications"), 4)
      XCTAssertEqual(try v4CommittedRowCount(path: fixture.relayPath, table: "claims"), 4)
      XCTAssertThrowsError(try host.publishLiveOriginal(first.publication)) { error in
        XCTAssertEqual(error as? V4PoolFailure, .conflict)
      }
      try await fixture.finish()
      XCTAssertFalse(fixture.timedOut)
    } catch {
      fixture.close()
      try? await fixture.finish()
      throw error
    }
  }

  func testNativeRelayUsesEachSignedDirectionIndependently() async throws {
    let fixture = try V4OriginalServerFixture(loseAdmissionResult: false, relayDialsClient: true)
    defer { fixture.close(); try? FileManager.default.removeItem(at: fixture.directory) }
    let deadline = Task { try await Task.sleep(for: .seconds(30)); fixture.timeout() }
    defer { deadline.cancel() }
    do {
      try await fixture.start()
      let original = try await fixture.authorize(fixture.initial)
      XCTAssertFalse(original.peer.plan.route.isDialer)
      let peer = Task {
        try await original.peer.establish(roots: [fixture.tls.rootPEM], listenerTLS:
          NativeListenerTLSConfiguration(certificateChainPEM: fixture.tls.serverPEM,
            privateKeyPEM: fixture.tls.serverKeyPEM))
      }
      fixture.retainPeerTask(peer)
      // The relay dials this real client listener while accepting the server
      // dialer on the other signed leg. Endpoint role stays client/server.
      try await V4OriginalTestPort.waitOccupied(fixture.clientPort)
      let host = try fixture.startRelay(original.publication)
      let run = Task { try await host.run() }
      fixture.installRun(run)
      try await fixture.forward(original, ticket: host.initialPublication,
        payload: Data("mixed native relay direction".utf8), preparedPeer: peer)
      XCTAssertEqual(try v4CommittedRowCount(path: fixture.admissionPath, table: "admissions"), 1)
      XCTAssertEqual(try v4CommittedRowCount(path: fixture.relayPath, table: "claims"), 2)
      try await fixture.finish()
      XCTAssertFalse(fixture.timedOut)
    } catch {
      fixture.close(); try? await fixture.finish(); throw error
    }
  }

  func testTransferredOriginalMaterialRetainsCarrierAfterSourceClose() async throws {
    let fixture = try V4OriginalServerFixture(loseAdmissionResult: false)
    defer { fixture.close(); try? FileManager.default.removeItem(at: fixture.directory) }
    let deadline = Task { try await Task.sleep(for: .seconds(30)); fixture.timeout() }
    defer { deadline.cancel() }
    do {
      try await fixture.start()
      let original = try await fixture.authorize(fixture.initial)
      let host = try fixture.startRelay(original.publication)
      let run = Task { try await host.run() }
      fixture.installRun(run)
      try await fixture.forward(original, ticket: host.initialPublication,
        payload: Data("transferred carrier remains independently owned".utf8), closeSourceAfterAcquire: true)
      do { _ = try await fixture.source.materialSource.acquire(); XCTFail("closed Source released another original") }
      catch { XCTAssertEqual(error as? ConnectionMaterialSourceError, .closed) }
      XCTAssertEqual(try v4CommittedRowCount(path: fixture.admissionPath, table: "admissions"), 1)
      try await fixture.finish()
      XCTAssertFalse(fixture.timedOut)
    } catch {
      fixture.close(); try? await fixture.finish(); throw error
    }
  }

  func testCompletedSourceCleanupStaysCompleteDuringTransferredMaterialAndEnvironmentClose() async throws {
    for closeEnvironment in [false, true] {
      let fixture = try V4OriginalServerFixture(loseAdmissionResult: false)
      defer { fixture.close(); try? FileManager.default.removeItem(at: fixture.directory) }
      let deadline = Task { try await Task.sleep(for: .seconds(30)); fixture.timeout() }
      defer { deadline.cancel() }
      do {
        try await fixture.start()
        let original = try await fixture.authorize(fixture.initial)
        let host = try fixture.startRelay(original.publication)
        let run = Task { try await host.run() }; fixture.installRun(run)
        try await fixture.waitRelayListeners(original); try await fixture.allow(original)
        let material = try await fixture.source.materialSource.acquire()
        fixture.retain(material)
        fixture.source.close()
        let completed = try await fixture.source.waitCleanup()
        XCTAssertTrue(completed.complete)
        XCTAssertEqual(completed.pendingCallbacks, 0)
        // The gate prevents the dispatched SQLite cleanup from releasing its
        // original tail until both the close and this observation have run.
        fixture.foundation.gate.withLock {
          if closeEnvironment { fixture.foundation.beginClose() }
          material.close()
          let materialCleanup = material.cleanupStatus()
          XCTAssertFalse(materialCleanup.complete, "Material completed before its native close callbacks exited")
          XCTAssertGreaterThan(materialCleanup.pendingCallbacks, 0)
          let cleanup = fixture.source.cleanupStatus()
          XCTAssertTrue(cleanup.complete, "Transferred ledger cleanup rejoined a completed Source")
          XCTAssertFalse(cleanup.cleanupIncomplete)
          XCTAssertEqual(cleanup.pendingCallbacks, 0)
        }
        let repeated = try await fixture.source.waitCleanup()
        XCTAssertTrue(repeated.complete)
        XCTAssertEqual(repeated.pendingCallbacks, 0)
        let materialCleanup = try await material.waitCleanup()
        XCTAssertTrue(materialCleanup.complete || materialCleanup.cleanupIncomplete)
        let cleanupDeadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !material.cleanupStatus().complete && ContinuousClock.now < cleanupDeadline { await Task.yield() }
        XCTAssertTrue(material.cleanupStatus().complete)
        XCTAssertEqual(material.cleanupStatus().pendingCallbacks, 0)
        try await fixture.finish()
        XCTAssertTrue(fixture.source.cleanupStatus().complete)
        XCTAssertFalse(fixture.timedOut)
      } catch {
        fixture.close(); try? await fixture.finish(); throw error
      }
    }
  }

  func testOriginalAdmissionCommitResultLossNeverProducesFSAOrReady() async throws {
    let fixture = try V4OriginalServerFixture(loseAdmissionResult: true)
    defer { fixture.close(); try? FileManager.default.removeItem(at: fixture.directory) }
    let deadline = Task { try await Task.sleep(for: .seconds(30)); fixture.timeout() }
    defer { deadline.cancel() }
    do {
      try await fixture.start()
      let original = try await fixture.authorize(fixture.initial)
      let host = try fixture.startRelay(original.publication)
      let run = Task { try await host.run() }
      fixture.installRun(run)
      try await fixture.waitRelayListeners()
      try await fixture.allow(original)
      let material = try await fixture.source.materialSource.acquire()
      fixture.retain(material)
      let server = Task { try await fixture.environment.connectMaterial(material) }
      fixture.installServer(server)
      do {
        try await original.peer.establish(roots: [fixture.tls.rootPEM])
        XCTFail("an unknown original admission result reached dual READY")
      } catch {}
      do { _ = try await server.value; XCTFail("lost admission COMMIT result published a Session") }
      catch {
        let failure = try XCTUnwrap(error as? ConnectError)
        XCTAssertEqual(failure.code, .connectionFailed)
        XCTAssertEqual(failure.retryDisposition, .terminal)
        XCTAssertEqual(failure.connection.networkReady, .notStarted)
      }
      XCTAssertTrue(original.peer.fsbSubmitted, "the real peer must reach authenticated FSB")
      XCTAssertFalse(original.peer.fsaReceived)
      XCTAssertFalse(original.peer.readySubmitted)
      XCTAssertTrue(fixture.lossObserved)
      XCTAssertEqual(try v4CommittedRowCount(path: fixture.admissionPath, table: "originals"), 1)
      XCTAssertEqual(try v4CommittedRowCount(path: fixture.admissionPath, table: "admissions"), 1)
      do { _ = try await fixture.environment.connectMaterial(material); XCTFail("original consumed material retried") } catch {}
      original.peer.close()
      await original.peer.waitClosed()
      fixture.source.close()
      let sourceCleanup = try await fixture.source.waitCleanup()
      XCTAssertTrue(sourceCleanup.complete)
      XCTAssertThrowsError(try fixture.reopenSource().registerOriginal(original.serverMaterial)) { error in
        XCTAssertEqual(error as? V4PoolFailure, .conflict)
      }
      XCTAssertEqual(try v4CommittedRowCount(path: fixture.admissionPath, table: "admissions"), 1,
        "reopening retains a refusal and cannot restore the lost admission capability")
      try await fixture.finish()
      XCTAssertFalse(fixture.timedOut)
    } catch {
      fixture.close()
      try? await fixture.finish()
      throw error
    }
  }
}

/// Real endpoint peer for the original live server Source. Only its control
/// authority uses fixture signing keys. HOP, FSB verification, SQLite admission,
/// Noise, both READY flights and encrypted records use the production owners.
/// The production Source fixture pre-registers native relay factories and uses
/// the original TxA and TxB mTLS callbacks. Separate peer fixtures exercise
/// server admission failures with final original signed publications.
private enum V4RegisteredSourceScenario: CaseIterable, Sendable { case success, refused, canceled }

private final class V4OriginalServerFixture: @unchecked Sendable {
  struct Original: Sendable {
    let peer: V4OriginalClientPeer
    let binding: TransportLiveServerBinding
    let serverMaterial: TransportLiveServerMaterial
    let publication: TransportLiveRelayPublication
    let allowBody: Data
  }
  let initial: V4TunnelCredentialFixture
  let foundation: V4EnvironmentFoundation
  let tls: V4ControlTestAuthority.Identity
  let directory: URL
  let admissionPath: String
  let relayPath: String
  let winner: ParentWinnerAuthority
  let clientPort: Int
  let serverPort: Int
  let nextClientPort: Int
  let nextServerPort: Int
  private let control: TransportServerAllowHTTPSConfiguration
  private let serverIdentity: V4LocalIdentity
  private let relayIdentity: V4LocalIdentity
  private let clientIdentity: V4LocalIdentity
  private let hostEnvironment: V4ClientEnvironment
  let environment: TransportEnvironment
  let source: TransportLiveServerSource
  private let sourceOwner: V4LiveServerMaterialSource
  private let caller: V4ControlHTTPS
  private let gate = NSLock()
  private let loss: V4AdmissionResultLoss
  private var host: RelayHost?
  private var run: Task<Void, any Error>?
  private var server: Task<any Session, any Error>?
  private var peers: [V4OriginalClientPeer] = []
  private var materials: [ConnectionMaterial] = []
  private var sources: [TransportLiveServerSource] = []
  private var extraFoundations: [V4EnvironmentFoundation] = []
  private var peerTasks: [Task<Void, any Error>] = []
  private var didTimeout = false
  var timedOut: Bool { gate.withLock { didTimeout } }
  var lossObserved: Bool { loss.observed }

  init(loseAdmissionResult: Bool, relayDialsClient: Bool = false) throws {
    // Reserve all ports together before handing them to original listeners.
    // Each publication uses fresh signed ports to avoid inheriting TIME_WAIT.
    // No readiness connection consumes a one-child route.
    let client = try V4OriginalTestPort(); defer { client.close() }
    let server = try V4OriginalTestPort(); defer { server.close() }
    let nextClient = try V4OriginalTestPort(); defer { nextClient.close() }
    let nextServer = try V4OriginalTestPort(); defer { nextServer.close() }
    let controlReservation = try V4OriginalTestPort(); defer { controlReservation.close() }
    clientPort = client.port; serverPort = server.port
    nextClientPort = nextClient.port; nextServerPort = nextServer.port
    initial = try V4TunnelCredentialFixture(profile: .x25519, hostname: "localhost", port: client.port,
      serverPort: server.port, nativeResources: true, relayDialsClient: relayDialsClient)
    foundation = initial.credentials.base.environment
    tls = try V4ControlTestAuthority.Identity()
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    directory = root.appendingPathComponent(".flowersec/swift-original-server-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    admissionPath = directory.appendingPathComponent("live-server-admissions.sqlite3").path
    relayPath = directory.appendingPathComponent("relay-claims.sqlite3").path
    winner = try ParentWinnerAuthority(environment: foundation, configuration: ParentWinnerStoreConfiguration(directory: directory,
      backingIdentity: Data(repeating: 104, count: 16), authority: "winner", create: true,
      maximumRows: 16, maximumBytes: 1 << 20, checkContinuity: { _ in }))
    loss = V4AdmissionResultLoss(path: admissionPath, enabled: loseAdmissionResult)
    clientIdentity = try foundation.importIdentity(profile: .x25519,
      signingSeed: Data(repeating: 21, count: 32), staticKey: Data(repeating: 31, count: 32))
    serverIdentity = try foundation.importIdentity(profile: .x25519,
      signingSeed: Data(repeating: 22, count: 32), staticKey: Data(repeating: 32, count: 32))
    relayIdentity = try foundation.importIdentity(profile: .x25519,
      signingSeed: Data(repeating: 23, count: 32), staticKey: Data(repeating: 33, count: 32))
    let endpoints = [client.port, server.port, nextClient.port, nextServer.port].map {
      TransportEndpoint(hostname: "localhost", port: $0, numericAddress: "127.0.0.1")
    }
    let listenerTLS = NativeListenerTLSConfiguration(certificateChainPEM: tls.serverPEM,
      privateKeyPEM: tls.serverKeyPEM)
    hostEnvironment = V4ClientEnvironment(foundation: foundation, namespaces: [initial.credentials.base.owner!],
      credentials: initial.credentials.configuration(), endpoints: endpoints, roots: [tls.rootPEM], backing: nil,
      store: nil, provider: try foundation.clientProviderStorage(bytes: 1 << 20), listenerTLS: listenerTLS)
    environment = TransportEnvironment(owner: hostEnvironment)
    let authorityClient = try XCTUnwrap(try NIOSSLCertificate.fromPEMBytes(Array(tls.clientPEM)).first)
    control = TransportServerAllowHTTPSConfiguration(numericAddress: "127.0.0.1", port: controlReservation.port,
      serverTLS: listenerTLS, authorityClientCertificateDER: Data(try authorityClient.toDERBytes()))
    let observer = loss
    let admissions = LiveServerAdmissionStoreConfiguration(directory: directory,
      backingIdentity: Data(repeating: 101, count: 16), create: true, maximumRows: 16, maximumBytes: 1 << 20, parentWinner: winner.configuration,
      checkContinuity: { _ in try observer.check() })
    sourceOwner = try V4LiveServerMaterialSource(environment: foundation, credentials: initial.credentials.configuration(),
      endpoints: endpoints, roots: [tls.rootPEM], tls: nil, identity: serverIdentity,
      configuration: TransportLiveServerSourceConfiguration(control: control, admissions: admissions))
    source = TransportLiveServerSource(sourceOwner)
    caller = try V4ControlHTTPS(environment: foundation, configuration: TransportControlHTTPSConfiguration(
      endpoint: TransportEndpoint(hostname: "localhost", port: controlReservation.port, numericAddress: "127.0.0.1"),
      trustRootsPEM: [tls.rootPEM], clientCertificatePEM: tls.clientPEM, clientPrivateKeyPEM: tls.clientKeyPEM,
      maximumConcurrentRequests: 1, timeoutMilliseconds: 5000))
  }

  func start() async throws { try await sourceOwner.start() }
  func installRun(_ task: Task<Void, any Error>) { gate.withLock { run = task } }
  func installServer(_ task: Task<any Session, any Error>) { gate.withLock { server = task } }
  func retain(_ material: ConnectionMaterial) { gate.withLock { materials.append(material) } }
  func retainFoundation(_ original: V4EnvironmentFoundation) { gate.withLock { extraFoundations.append(original) } }
  func retainPeerTask(_ task: Task<Void, any Error>) { gate.withLock { peerTasks.append(task) } }
  func timeout() { gate.withLock { didTimeout = true }; close() }

  func authorize(_ credentials: V4TunnelCredentialFixture) async throws -> Original {
    let tunnel = TransportLiveTunnelConfiguration(scope: credentials.scope(),
      relayCertificate: credentials.relay, grantLimits: credentials.limits())
    let admission = try foundation.verifyDirectCredentials(configuration: initial.credentials.configuration(),
      input: V4CredentialInput(artifact: credentials.original.artifact,
        clientCertificate: credentials.original.clientCertificate, serverCertificate: credentials.original.serverCertificate,
        activation: Data(), source: .liveAuthority, candidateIndex: 0, liveTunnel: tunnel))
    let plan = try admission.directPoolPlan(in: foundation, identity: clientIdentity)
    let peer = V4OriginalClientPeer(plan: plan, identity: clientIdentity)
    gate.withLock { peers.append(peer) }
    let request = try admission.beginLiveAuthorization(signingKeyID: "activate")
    let serverTunnel = TransportLiveTunnelConfiguration(scope: credentials.scope(roleMask: 6),
      relayCertificate: credentials.relay, grantLimits: credentials.limits())
    let material = TransportLiveServerMaterial(artifact: credentials.original.artifact,
      clientCertificate: credentials.original.clientCertificate, serverCertificate: credentials.original.serverCertificate,
      attempt: admission.attemptID, recipient: Data(repeating: 102, count: 16), activationSigningKeyID: "activate",
      tunnel: serverTunnel)
    let binding = try source.registerOriginal(material)
    // Register independently before the authenticated original authorization
    // request. The HTTP body cannot select another server registration.
    let authority = try V4ControlTestAuthority(identity: tls) { path, body in
      guard path == "/live/authorize" else { throw TransportControlError.responseInvalid }
      return try credentials.liveAuthorityResponse(body)
    }
    defer { authority.stop() }
    let activation = try V4ControlHTTPS(environment: foundation, configuration: authority.configuration())
    defer { activation.close() }
    let response = try await activation.post(path: "/live/authorize", body: request, maximumResponseBytes: 73_728,
      check: { try admission.checkPreparation(in: self.foundation) })
    defer { withExtendedLifetime(response) {} }
    try plan.installLiveAuthorization(response.bytes, signingKeyID: "activate", configuration: initial.credentials.configuration())
    XCTAssertEqual(authority.requests, ["/live/authorize"])
    let clientGrant = try V4LiveTunnelMaterial.decode(response.bytes).grant
    let serverGrant = try credentials.grant(attempt: admission.attemptID,
      overrides: [13: credentials.namespace(role: 6)])
    let publication = TransportLiveRelayPublication(artifact: credentials.original.artifact,
      clientCertificate: credentials.original.clientCertificate, serverCertificate: credentials.original.serverCertificate,
      attempt: admission.attemptID, client: tunnel, server: serverTunnel, clientGrant: clientGrant, serverGrant: serverGrant,
      activationAuthorization: try V4LiveTunnelMaterial.decode(response.bytes).activation, activationSigningKeyID: "activate")
    let grant = try V4NamespaceDocument(serverGrant, schema: "Grant", bytes: 9302, nodes: 4096,
      registry: credentials.registry).root
    let candidate = try admission.originalCandidate()
    let fields = [V4Crypto.text("tunnel-server-allow-1"), V4Crypto.text("tenant"), V4Crypto.text("service"),
      V4Crypto.bytes(binding.artifactDigest), V4Crypto.bytes(try grant.digest("grant_digest")),
      V4Crypto.bytes(NamespaceFixture.digest("certificate-digest", credentials.relay)),
      V4Crypto.bytes(binding.attempt), V4Crypto.bytes(try grant.b("pairing_id")),
      V4Crypto.bytes(try candidate.field("server_leg").b("leg_id")), V4Crypto.bytes(binding.recipient),
      V4Crypto.bytes(binding.incarnation), V4NamespaceValue.head(4, 3)
        + V4NamespaceValue.head(0, UInt64(binding.candidateIndex)) + V4Crypto.bytes(binding.candidateID)
        + V4Crypto.bytes(binding.routeDigest), V4NamespaceValue.head(0, 1500), V4Crypto.bytes(serverGrant)]
    return Original(peer: peer, binding: binding, serverMaterial: material, publication: publication,
      allowBody: V4NamespaceValue.head(4, 14) + fields.reduce(Data(), +))
  }

  func startRelay(_ original: TransportLiveRelayPublication) throws -> RelayHost {
    let claims = RelayClaimStoreConfiguration(directory: directory, backingIdentity: Data(repeating: 103, count: 16),
      create: true, maximumRows: 16, maximumBytes: 1 << 20, parentWinner: winner.configuration, checkContinuity: { _ in })
    let daemon = try hostEnvironment.relayHost(RelayHostConfiguration(live: original, claims: claims),
      identity: TransportApplicationIdentity(relayIdentity))
    gate.withLock { host = daemon }; return daemon
  }

  func waitRelayListeners(_ original: Original? = nil) async throws {
    let client = original?.peer.plan.route.port ?? clientPort
    let server: Int
    if let original {
      server = try Int(original.peer.plan.credential.originalCandidate().field("server_leg").u("port"))
    } else { server = serverPort }
    if original?.peer.plan.route.isDialer ?? true { try await V4OriginalTestPort.waitOccupied(client) }
    try await V4OriginalTestPort.waitOccupied(server)
  }
  func allow(_ original: Original) async throws {
    let ack = try await caller.post(path: "/tunnel/server-allow", body: original.allowBody, maximumResponseBytes: 1,
      check: { try original.peer.plan.credential.checkPreparation(in: self.foundation) })
    XCTAssertEqual(ack.bytes, Data([0xf5]))
    initial.credentials.base.source.advance(100)
    let duplicate = try await caller.post(path: "/tunnel/server-allow", body: original.allowBody, maximumResponseBytes: 1,
      check: { try original.peer.plan.credential.checkPreparation(in: self.foundation) })
    XCTAssertEqual(duplicate.bytes, ack.bytes, "an exact original request retries only its acknowledgement")
    XCTAssertEqual(try v4CommittedRowCount(path: admissionPath, table: "admissions"),
      try v4CommittedRowCount(path: admissionPath, table: "originals") - 1,
      "ACK writes and retries cannot spend server admission before authenticated FSB")
  }

  func forward(_ original: Original, ticket: RelayPublication, payload: Data,
    preparedPeer: Task<Void, any Error>? = nil, closeSourceAfterAcquire: Bool = false) async throws {
    try await waitRelayListeners(original)
    try await allow(original)
    let material = try await source.materialSource.acquire()
    retain(material)
    if closeSourceAfterAcquire {
      source.close()
      let cleanup = try await source.waitCleanup()
      XCTAssertTrue(cleanup.complete)
    }
    let connection = Task { try await self.environment.connectMaterial(material) }
    installServer(connection)
    if let preparedPeer { try await preparedPeer.value }
    else { try await original.peer.establish(roots: [tls.rootPEM]) }
    let session = try await connection.value
    let materialCleanup = try await material.waitCleanup()
    XCTAssertTrue(materialCleanup.complete, "A handed-off Session must not remain in material cleanup")
    material.close()
    XCTAssertTrue(original.peer.fsbSubmitted)
    XCTAssertTrue(original.peer.fsaReceived)
    XCTAssertTrue(original.peer.readySubmitted)
    let echo = Task { () async throws -> Data in
      let incoming = try await session.acceptStream()
      guard incoming.kind == "echo" else { throw V4CryptoFailure.authentication }
      var received = Data()
      while let data = try await incoming.stream.read(maxBytes: 4096) { received.append(data) }
      var offset = 0
      while offset < received.count {
        let accepted = try await incoming.stream.write(Data(received.dropFirst(offset)))
        guard accepted > 0 else { throw V4CryptoFailure.phase }; offset += accepted
      }
      try await incoming.stream.closeWrite()
      return received
    }
    do {
      let received = try await original.peer.echo(payload)
      XCTAssertEqual(received, payload)
      let serverReceived = try await echo.value
      XCTAssertEqual(serverReceived, payload)
      do { _ = try await environment.connectMaterial(material); XCTFail("one original material connected twice") } catch {}
      original.peer.close()
      await original.peer.waitClosed()
      try await session.close()
      // Closing real carriers terminates forwarding with its actual result.
      // A publication ticket is not itself proof of a successful Session.
      _ = try? await ticket.waitCompletion()
      let cleanup = try await ticket.waitCleanup()
      XCTAssertTrue(cleanup.complete)
    } catch {
      echo.cancel(); original.peer.close(); try? await session.close()
      _ = try? await echo.value
      throw error
    }
  }

  func exerciseProductionLiveSource(
    registered: V4RegisteredSourceScenario? = nil,
    whileSiblingOpen: (@Sendable (any Session, any Session) async throws -> Void)? = nil
  ) async throws {
    let reservation = try V4OriginalTestPort()
    let relayPort = reservation.port; reservation.close()
    let pinned = try XCTUnwrap(try NIOSSLCertificate.fromPEMBytes(Array(tls.clientPEM)).first)
    let relayControl = TransportServerAllowHTTPSConfiguration(numericAddress: "127.0.0.1", port: relayPort,
      serverTLS: NativeListenerTLSConfiguration(certificateChainPEM: tls.serverPEM, privateKeyPEM: tls.serverKeyPEM),
      authorityClientCertificateDER: Data(try pinned.toDERBytes()))
    let relayEndpoint = TransportControlHTTPSConfiguration(
      endpoint: TransportEndpoint(hostname: "localhost", port: relayPort, numericAddress: "127.0.0.1"),
      trustRootsPEM: [tls.rootPEM], clientCertificatePEM: tls.clientPEM, clientPrivateKeyPEM: tls.clientKeyPEM,
      maximumConcurrentRequests: 1, timeoutMilliseconds: 5000)
    let clientTunnel = TransportLiveTunnelConfiguration(scope: initial.scope(), relayCertificate: initial.relay, grantLimits: initial.limits())
    let serverTunnel = TransportLiveTunnelConfiguration(scope: initial.scope(roleMask: 6), relayCertificate: initial.relay, grantLimits: initial.limits())
    let relayRegistration = TransportLiveRelayRegistration(artifact: initial.original.artifact,
      clientCertificate: initial.original.clientCertificate, serverCertificate: initial.original.serverCertificate,
      client: clientTunnel, server: serverTunnel, activationSigningKeyID: "activate", control: relayControl)
    let claims = RelayClaimStoreConfiguration(directory: directory, backingIdentity: Data(repeating: 103, count: 16),
      create: true, maximumRows: 16, maximumBytes: 1 << 20, parentWinner: winner.configuration, checkContinuity: { _ in })
    let daemon = try hostEnvironment.relayHost(RelayHostConfiguration(registeredLive: relayRegistration, claims: claims),
      identity: TransportApplicationIdentity(relayIdentity))
    gate.withLock { host = daemon }
    let relayRun = Task { try await daemon.run() }; installRun(relayRun)
    try await daemon.initialPublication.waitListening()
    // Listener readiness does not consume the only child or issue a Grant.
    let candidate = try XCTUnwrap(V4NamespaceDocument(initial.original.artifact, schema: "Artifact", bytes: 65_536, nodes: 16_384,
      registry: initial.registry).root.field("candidates").children.first(where: { _ in true }))
    let serverLegID = try candidate.field("server_leg").b("leg_id")
    if try candidate.field("client_leg").u("listener_role") == 2 { try await V4OriginalTestPort.waitOccupied(clientPort) }
    let delivery = try V4ControlHTTPS(environment: foundation, configuration: relayEndpoint)
    let authority = try V4ControlTestAuthority(identity: tls, maximumRequestBytes: 24_576,
      contentTypes: { _ in registered == nil ? ("application/cbor", "application/cbor") : ("application/json", "application/json") }, respondAsync: { [self] path, body in
      if path == "/issue/artifact" { return initial.original.artifact }
      var request = body
      var reply: [String: Any] = [:]
      if registered != nil {
        guard path == "/flowersec/control/live",
          let envelope = try JSONSerialization.jsonObject(with: body) as? [String: String],
          let payload = envelope["payload"], let signature = envelope["proof"].flatMap({ Data(base64Encoded: $0) }),
          try NamespaceFixture.key(21).publicKey.isValidSignature(signature,
            for: Data("flowersec/original-tunnel-control/1\0".utf8) + Data(payload.utf8)),
          let value = try JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any],
          let incarnation = value["incarnation"] as? String,
          let kind = value["kind"] as? String else { throw TransportControlError.responseInvalid }
        reply = ["incarnation": incarnation, "authority": "registered-test"]
        if kind == "live_client_prepared" {
          if registered == .canceled {
            while true { try await ContinuousClock().sleep(for: .milliseconds(10)) }
          }
          reply["prepared"] = true
          if registered == .refused { reply["registered"] = true }
          return try JSONSerialization.data(withJSONObject: reply, options: [.sortedKeys])
        }
        guard kind == "live_authorize", let authentication = value["authentication"] as? String,
          let authenticated = Data(base64Encoded: authentication), authenticated.count > 32,
          let encodedSignature = value["signature"] as? String,
          let authorizationSignature = Data(base64Encoded: encodedSignature),
          try NamespaceFixture.key(21).publicKey.isValidSignature(authorizationSignature, for: authenticated)
        else { throw TransportControlError.responseInvalid }
        request = Data(authenticated.dropFirst(32))
      } else {
        guard path == "/live/authorize" else { throw TransportControlError.responseInvalid }
      }
      // The original native client has already completed Prepare. The relay
      // has fixed this exact TxA request and still has no installed Grants.
      XCTAssertEqual(try v4CommittedRowCount(path: relayPath, table: "claims"), 0)
      let response = try initial.liveAuthorityResponse(request)
      var cursor = V4PoolWireCursor(request, maximum: 1024); try cursor.array(13)
      _ = try cursor.text(maximum: 32)
      for _ in 0..<3 { _ = try cursor.text(maximum: 128) }
      _ = try cursor.bytes(maximum: 16); _ = try cursor.bytes(maximum: 16)
      let attempt = try cursor.bytes(maximum: 16)
      let serverMaterial = TransportLiveServerMaterial(artifact: initial.original.artifact,
        clientCertificate: initial.original.clientCertificate, serverCertificate: initial.original.serverCertificate,
        attempt: attempt, recipient: Data(repeating: 102, count: 16), activationSigningKeyID: "activate", tunnel: serverTunnel)
      let binding = try source.registerOriginal(serverMaterial)
      let material = try V4LiveTunnelMaterial.decode(response)
      let serverGrant = try initial.grant(attempt: attempt, overrides: [13: initial.namespace(role: 6)])
      let grant = try V4NamespaceDocument(serverGrant, schema: "Grant", bytes: 9302, nodes: 4096, registry: initial.registry).root
      let fields = [V4Crypto.text("tunnel-server-allow-1"), V4Crypto.text("tenant"), V4Crypto.text("service"),
        V4Crypto.bytes(binding.artifactDigest), V4Crypto.bytes(try grant.digest("grant_digest")),
        V4Crypto.bytes(NamespaceFixture.digest("certificate-digest", initial.relay)), V4Crypto.bytes(attempt),
        V4Crypto.bytes(try grant.b("pairing_id")), V4Crypto.bytes(serverLegID),
        V4Crypto.bytes(binding.recipient), V4Crypto.bytes(binding.incarnation), V4NamespaceValue.head(4, 3)
          + V4NamespaceValue.head(0, UInt64(binding.candidateIndex)) + V4Crypto.bytes(binding.candidateID) + V4Crypto.bytes(binding.routeDigest),
        V4NamespaceValue.head(0, 1500), V4Crypto.bytes(serverGrant)]
      let allow = try await caller.post(path: "/tunnel/server-allow", body: V4NamespaceValue.head(4, 14) + fields.reduce(Data(), +),
        maximumResponseBytes: 1, check: { _ = try self.foundation.clock.mark() })
      XCTAssertEqual(allow.bytes, Data([0xf5]))
      let installServerGrant = V4NamespaceValue.head(4, 4) + V4Crypto.text("tunnel-relay-server-grant-1")
        + V4Crypto.bytes(request) + V4Crypto.bytes(material.activation) + V4Crypto.bytes(serverGrant)
      let ack = try await delivery.post(path: "/tunnel/relay-server-grant", body: installServerGrant, maximumResponseBytes: 1,
        check: { _ = try self.foundation.clock.mark() })
      XCTAssertEqual(ack.bytes, Data([0xf5]))
      if registered != nil {
        reply["grant"] = response.base64EncodedString()
        return try JSONSerialization.data(withJSONObject: reply, options: [.sortedKeys])
      }
      return response
    }, respond: { _, _ in throw V4CryptoFailure.phase })
    let clientCredentials = try V4TunnelCredentialFixture(profile: .x25519, hostname: "localhost",
      port: clientPort, serverPort: serverPort, nativeResources: true,
      relayDialsClient: try candidate.field("client_leg").u("dialer_role") == 2)
    let clientFoundation = clientCredentials.credentials.base.environment
    retainFoundation(clientFoundation)
    let localIdentity = try clientFoundation.importIdentity(profile: .x25519,
      signingSeed: Data(repeating: 21, count: 32), staticKey: Data(repeating: 31, count: 32))
    defer { localIdentity.close() }
    let clientHost = V4ClientEnvironment(foundation: clientFoundation, namespaces: [clientCredentials.credentials.base.owner!],
      credentials: clientCredentials.credentials.configuration(), endpoints: [TransportEndpoint(hostname: "localhost", port: clientPort, numericAddress: "127.0.0.1")],
      roots: [tls.rootPEM], backing: nil, store: nil, provider: try clientFoundation.clientProviderStorage(bytes: 1 << 20),
      listenerTLS: NativeListenerTLSConfiguration(certificateChainPEM: tls.serverPEM, privateKeyPEM: tls.serverKeyPEM))
    let clientEnvironment = TransportEnvironment(owner: clientHost)
    let live: ConnectionMaterialSource
    if registered != nil {
      live = try await clientEnvironment.makeRegisteredLiveAuthoritySource(.init(control: authority.configuration(),
        authority: "registered-test", artifact: initial.original.artifact,
        clientCertificate: initial.original.clientCertificate, serverCertificate: initial.original.serverCertificate,
        activationSigningKeyID: "activate", tunnel: clientTunnel, relayPreparation: relayEndpoint),
        identity: TransportApplicationIdentity(localIdentity))
    } else {
      live = try clientHost.liveSource(TransportLiveAuthoritySourceConfiguration(issuance: authority.configuration(),
        activation: authority.configuration(), clientCertificate: initial.original.clientCertificate,
        serverCertificate: initial.original.serverCertificate, activationSigningKeyID: "activate", tunnel: clientTunnel,
        relayPreparation: relayEndpoint), identity: TransportApplicationIdentity(localIdentity))
    }
    if registered == .refused || registered == .canceled {
      let connecting = Task { try await clientEnvironment.connect(source: live) }
      if registered == .canceled {
        let start = ContinuousClock.now
        while authority.requests.isEmpty {
          guard start.duration(to: .now) < .seconds(5) else { throw SessionError.timeout }
          try await ContinuousClock().sleep(for: .milliseconds(5))
        }
        connecting.cancel()
      }
      do { let unexpected = try await connecting.value; try? await unexpected.close(); XCTFail("Invalid registered authority must not publish a Session") }
      catch let error as ConnectError {
        XCTAssertEqual(error.connection.spendState, .unspent)
        XCTAssertEqual(error.connection.networkReady, .notStarted)
        XCTAssertEqual(error.connection.applicationPublish, .notStarted)
        XCTAssertTrue(error.cleanup.complete); XCTAssertEqual(error.cleanup.pendingCallbacks, 0)
      }
      do { let retry = try await live.acquire(); retry.close(); XCTFail("Original parent must be withdrawn after failed preparation") }
      catch { XCTAssertEqual(error as? ConnectionMaterialSourceError, .closed) }
      live.close()
      let cleanup = try await live.waitCleanup()
      XCTAssertTrue(cleanup.complete); XCTAssertEqual(cleanup.pendingCallbacks, 0)
      XCTAssertEqual(authority.requests, ["/flowersec/control/live"])
      XCTAssertEqual(try v4CommittedRowCount(path: relayPath, table: "claims"), 0)
      XCTAssertEqual(try v4CommittedRowCount(path: admissionPath, table: "admissions"), 0)
      delivery.close(); daemon.close(); await authority.stopAsync()
      return
    }
    let accepting = Task { try await self.environment.connect(source: self.source.materialSource) }; installServer(accepting)
    var connected: (any Session)?
    var accepted: (any Session)?
    do {
      let client = try await clientEnvironment.connect(source: live); connected = client
      let server = try await accepting.value; accepted = server
      XCTAssertEqual(authority.requests, registered == nil
        ? ["/issue/artifact", "/live/authorize"] : ["/flowersec/control/live", "/flowersec/control/live"])
      if registered != nil {
        do { let replay = try await live.acquire(); replay.close(); XCTFail("Registered parent must be single use") }
        catch { XCTAssertEqual(error as? ConnectionMaterialSourceError, .closed) }
        live.close()
        let cleanup = try await live.waitCleanup()
        XCTAssertTrue(cleanup.complete); XCTAssertEqual(cleanup.pendingCallbacks, 0)
      }
      XCTAssertEqual(try v4CommittedRowCount(path: relayPath, table: "claims"), 2)
      XCTAssertEqual(try v4CommittedRowCount(path: admissionPath, table: "admissions"), 1)
      XCTAssertEqual(try v4CommittedRowCount(path: directory.appendingPathComponent("parent-winner.sqlite3").path, table: "winners"), 1,
        "relay possession and authenticated server FSB must match the same public selection")
      let payload = Data("production live Source encrypted echo".utf8)
      let echo = Task {
        let incoming = try await server.acceptStream()
        var bytes = Data()
        while let chunk = try await incoming.stream.read(maxBytes: 4096) { bytes.append(chunk) }
        var offset = 0
        while offset < bytes.count {
          let count = try await incoming.stream.write(Data(bytes.dropFirst(offset)))
          guard count > 0 else { throw V4CryptoFailure.phase }; offset += count
        }
        // Keep the reply owner until the client's authenticated drain. Dropping
        // it after CloseWrite alone can reset an otherwise successful reply.
        try await incoming.stream.finish()
        return bytes
      }
      retainPeerTask(Task { _ = try await echo.value })
      let stream = try await client.openStream(kind: "echo")
      var offset = 0
      while offset < payload.count {
        let count = try await stream.write(Data(payload.dropFirst(offset)))
        guard count > 0 else { throw V4CryptoFailure.phase }; offset += count
      }
      // Keep this unrelated Stream active while another public workflow runs.
      try await whileSiblingOpen?(client, server)
      try await stream.closeWrite()
      var received = Data()
      while let chunk = try await stream.read(maxBytes: 4096) { received.append(chunk) }
      let echoed = try await echo.value
      XCTAssertEqual(received, payload); XCTAssertEqual(echoed, payload)
      try await client.close(); try await server.close()
      live.close(); delivery.close(); await authority.stopAsync()
      _ = try? await daemon.initialPublication.waitCompletion()
    } catch {
      live.close(); delivery.close(); accepting.cancel()
      if let connected { try? await connected.close() }; if let accepted { try? await accepted.close() }
      daemon.close(); await authority.stopAsync(); throw error
    }
  }

  func exercisePoolServerSource(closeBeforeAllow: Bool) async throws {
    var poolCredentials: [V4TunnelCredentialFixture] = []
    defer { withExtendedLifetime(poolCredentials) {} }
    let serverGrant = try initial.grant(overrides: [13: initial.namespace(role: 6)])
    let clientCredential = TransportPoolCredential(input: try initial.input())
    let serverCredential = TransportPoolCredential(input: try initial.input(grant: serverGrant)).withRole(.server)
    let claims = RelayClaimStoreConfiguration(directory: directory, backingIdentity: Data(repeating: 105, count: 16),
      create: true, maximumRows: 16, maximumBytes: 1 << 20, parentWinner: winner.configuration, checkContinuity: { _ in })
    let daemon = try hostEnvironment.relayHost(.init(client: clientCredential, server: serverCredential, claims: claims),
      identity: TransportApplicationIdentity(relayIdentity))
    gate.withLock { host = daemon }
    let relayRun = Task { try await daemon.run() }; installRun(relayRun)
    try await daemon.initialPublication.waitListening()

    func poolEnvironment(_ name: String, signingSeed: UInt8) throws -> (TransportEnvironment, TransportApplicationIdentity) {
      let credentials = try V4TunnelCredentialFixture(profile: .x25519, hostname: "localhost", port: clientPort,
        serverPort: serverPort, nativeResources: true)
      poolCredentials.append(credentials)
      let owner = credentials.credentials.base.environment
      retainFoundation(owner)
      let local = try owner.importIdentity(profile: .x25519,
        signingSeed: Data(repeating: signingSeed, count: 32), staticKey: Data(repeating: signingSeed + 10, count: 32))
      let history = directory.appendingPathComponent(name)
      try FileManager.default.createDirectory(at: history, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
      let backing = try V4PoolStoreBacking(environment: owner, directory: history,
        identity: .init(storeID: Data(repeating: signingSeed, count: 16), generation: 1, tenant: "tenant",
          issuer: Data(repeating: 5, count: 16), spendAuthority: "spend", winnerAuthority: "winner"),
        maximumBytes: 1 << 20, maximumRows: 16, parentWinner: winner.configuration, continuity: { _ in })
      let store = try backing.open(create: true)
      let host = V4ClientEnvironment(foundation: owner, namespaces: [credentials.credentials.base.owner!],
        credentials: credentials.credentials.configuration(), endpoints: [clientPort, serverPort].map {
          .init(hostname: "localhost", port: $0, numericAddress: "127.0.0.1")
        }, roots: [tls.rootPEM], backing: backing, store: store, provider: try owner.clientProviderStorage(bytes: 1 << 20),
        listenerTLS: .init(certificateChainPEM: tls.serverPEM, privateKeyPEM: tls.serverKeyPEM))
      return (TransportEnvironment(owner: host), TransportApplicationIdentity(local))
    }
    let (serverEnvironment, serverIdentity) = try poolEnvironment("pool-server", signingSeed: 22)
    let poolControl = TransportServerAllowHTTPSConfiguration(numericAddress: control.numericAddress, port: control.port,
      serverTLS: control.serverTLS, authorityClientCertificateDER: control.authorityClientCertificateDER, timeoutMilliseconds: 2000)
    let pool = try await serverEnvironment.makePreauthorizedPoolServerSource([serverCredential], identity: serverIdentity, control: poolControl)
    var clientEnvironment: TransportEnvironment?
    var clientSource: ConnectionMaterialSource?
    var clientSession: (any Session)?
    var serverSession: (any Session)?
    do {
      let binding = try XCTUnwrap(pool.bindings.first)
      XCTAssertEqual(pool.bindings.count, 1)
      do { let wrong = try await pool.materialSource.acquire(.init(applicationProfile: "services")); wrong.close(); XCTFail("Profile mismatch consumed prepared server") }
      catch { XCTAssertEqual(error as? TransportConnectError, .unsupported) }
      let waiting = Task { try await pool.materialSource.acquire() }
      try await ContinuousClock().sleep(for: .milliseconds(20))
      do { let duplicate = try await pool.materialSource.acquire(); duplicate.close(); XCTFail("Only one server Acquire waiter may enter") }
      catch { XCTAssertEqual(error as? TransportControlError, .busy) }
      waiting.cancel()
      do { let canceled = try await waiting.value; canceled.close(); XCTFail("Canceled waiter consumed server preparation") }
      catch { XCTAssertEqual(error as? SessionError, .canceled) }
      if closeBeforeAllow {
        pool.close()
        let cleanup = try await pool.waitCleanup()
        XCTAssertTrue(cleanup.complete); XCTAssertEqual(cleanup.pendingCallbacks, 0)
        do { let closed = try await pool.materialSource.acquire(); closed.close(); XCTFail("Closed source accepted a waiter") }
        catch { XCTAssertEqual(error as? ConnectionMaterialSourceError, .closed) }
        try await serverEnvironment.close(); return
      }
      let grant = try V4NamespaceDocument(serverGrant, schema: "Grant", bytes: 9302, nodes: 4096, registry: initial.registry).root
      let candidate = try V4NamespaceDocument(initial.original.artifact, schema: "Artifact", bytes: 65_536,
        nodes: 16_384, registry: initial.registry).root.field("candidates").children.map { $0 }[0]
      let forged = [V4Crypto.text("tunnel-server-allow-1"), V4Crypto.text("tenant"), V4Crypto.text("service"),
        V4Crypto.bytes(binding.artifactDigest), V4Crypto.bytes(try grant.digest("grant_digest")),
        V4Crypto.bytes(NamespaceFixture.digest("certificate-digest", initial.relay)), V4Crypto.bytes(binding.attempt),
        V4Crypto.bytes(try grant.b("pairing_id")), V4Crypto.bytes(try candidate.field("server_leg").b("leg_id")),
        V4Crypto.bytes(Data(repeating: 99, count: 16)), V4Crypto.bytes(binding.incarnation), V4NamespaceValue.head(4, 3)
          + V4NamespaceValue.head(0, UInt64(binding.candidateIndex)) + V4Crypto.bytes(binding.candidateID) + V4Crypto.bytes(binding.routeDigest),
        V4NamespaceValue.head(0, 1500), V4Crypto.bytes(serverGrant)]
      do {
        _ = try await caller.post(path: "/tunnel/server-allow", body: V4NamespaceValue.head(4, 14) + forged.reduce(Data(), +),
          maximumResponseBytes: 1, check: { _ = try self.foundation.clock.mark() })
        XCTFail("Foreign Allow recipient must not release preparation")
      } catch {}
      // The independently supplied monotonic test clock must pass the real
      // control listener's minimum interval before the next original request.
      poolCredentials[0].credentials.base.source.advance(100)
      let (native, identity) = try poolEnvironment("pool-client", signingSeed: 21); clientEnvironment = native
      let endpoint = TransportControlHTTPSConfiguration(endpoint: .init(hostname: "localhost", port: control.port, numericAddress: "127.0.0.1"),
        trustRootsPEM: [tls.rootPEM], clientCertificatePEM: tls.clientPEM, clientPrivateKeyPEM: tls.clientKeyPEM,
        maximumConcurrentRequests: 1, timeoutMilliseconds: 2000)
      let allowed = TransportPoolCredential(artifact: initial.original.artifact,
        clientCertificate: initial.original.clientCertificate, serverCertificate: initial.original.serverCertificate,
        activationAuthorization: initial.original.activation, grant: try initial.grant(), relayCertificate: initial.relay,
        serverAllow: .init(control: endpoint, recipient: binding.recipient, incarnation: binding.incarnation, serverGrant: serverGrant))
      let outgoing = try await native.makePreauthorizedPoolSource([allowed], identity: identity); clientSource = outgoing
      let accepting = Task { try await serverEnvironment.connect(source: pool.materialSource) }; installServer(accepting)
      let client = try await native.connect(source: outgoing); clientSession = client
      let server = try await accepting.value; serverSession = server
      do { let replay = try await pool.materialSource.acquire(); replay.close(); XCTFail("Finite server preparation was acquired twice") }
      catch { XCTAssertEqual(error as? ConnectionMaterialSourceError, .exhausted) }
      // Retiring the finite source must leave the handed-off native Session live.
      pool.close()
      let cleanup = try await pool.waitCleanup()
      XCTAssertTrue(cleanup.complete); XCTAssertEqual(cleanup.pendingCallbacks, 0)
      let receiving = Task { try await server.acceptStream() }
      retainPeerTask(Task { _ = try await receiving.value })
      let stream = try await client.openStream(kind: "pool.server.echo")
      let incoming = try await receiving.value
      let payload = Data("authenticated Allow preserves handed-off Session".utf8)
      let written = try await stream.write(payload)
      let received = try await incoming.stream.read(maxBytes: 128)
      XCTAssertEqual(written, payload.count); XCTAssertEqual(received, payload)
      let reply = try await incoming.stream.write(payload)
      let echoed = try await stream.read(maxBytes: 128)
      XCTAssertEqual(reply, payload.count); XCTAssertEqual(echoed, payload)
      try await stream.closeWrite(); try await incoming.stream.closeWrite()
      let clientEOF = try await stream.read(maxBytes: 1); let serverEOF = try await incoming.stream.read(maxBytes: 1)
      XCTAssertNil(clientEOF); XCTAssertNil(serverEOF)
      try await client.close(); clientSession = nil; try await server.close(); serverSession = nil
      outgoing.close(); _ = try await outgoing.waitCleanup()
      try await native.close(); try await serverEnvironment.close()
      XCTAssertEqual(try v4CommittedRowCount(path: relayPath, table: "claims"), 2)
    } catch {
      pool.close(); clientSource?.close()
      if let clientSession { try? await clientSession.close() }; if let serverSession { try? await serverSession.close() }
      _ = try? await pool.waitCleanup(); try? await clientEnvironment?.close(); try? await serverEnvironment.close()
      throw error
    }
  }

  func exerciseNativeHTTPProxy(client: any Session, server: any Session) async throws {
    let limits = try ProxyClientLimits(maximumMetadataBytes: 4096, maximumChunkBytes: 1024,
      maximumBodyBytes: 4096, maximumWebSocketFrameBytes: 1024)
    let proxyClient = try ProxyClient(session: client, limits: limits)
    for cancelBeforeResponse in [true, false] {
      let backend = try await DuplexTCPTestServer.start()
      let upstream: NativeProxyUpstream
      let proxyServer: ProxyServer
      do {
        upstream = try await environment.makeNativeProxyUpstream(NativeProxyUpstreamConfiguration(
          origin: XCTUnwrap(URL(string: "http://127.0.0.1:\(backend.port)")), numericAddress: "127.0.0.1",
          limits: limits, timeoutMilliseconds: 20_000))
        proxyServer = try ProxyServer(session: server, upstream: upstream, limits: limits, maximumConcurrentStreams: 1)
      } catch { await backend.close(); throw error }
      let serving = Task {
        let incoming = try await server.acceptStream()
        XCTAssertEqual(incoming.kind, "flowersec-proxy/http1")
        try await proxyServer.serve(incoming)
      }
      retainPeerTask(serving)
      let opening = Task { try await proxyClient.open(HTTPProxyRequest(method: "POST", path: "/slow", body: Data("request".utf8))) }
      var phase = "request arrival"
      do {
        let request = Data("POST /slow HTTP/1.1\r\nHost: 127.0.0.1:\(backend.port)\r\nConnection: close\r\nContent-Length: 7\r\n\r\nrequest".utf8)
        // The real native socket has received the entire request, but this
        // backend has not sent any response. The public client closes its write side.
        try await backend.waitInput(request)
        XCTAssertFalse(backend.inputEOF)
        let active = await proxyServer.cleanupStatus()
        XCTAssertEqual(active.pendingCallbacks, 1)
        if cancelBeforeResponse {
          phase = "cancel open"
          opening.cancel()
          do {
            let exchange = try await opening.value
            try? await exchange.close()
            XCTFail("Canceled open returned an HTTP exchange")
          } catch {
            XCTAssertTrue(error is CancellationError || (error as? SessionError) == .canceled)
          }
          // This five-second peer deadline is shorter than the upstream timeout.
          // No response, Session close, or explicit server close can cause EOF.
          phase = "canceled upstream EOF"
          try await backend.waitInput(request, eof: true)
          phase = "canceled serve cleanup"
          let cleanupDeadline = ContinuousClock.now.advanced(by: .seconds(5))
          while await proxyServer.cleanupStatus().pendingCallbacks != 0 {
            guard ContinuousClock.now < cleanupDeadline else { throw SessionError.timeout }
            try await Task.sleep(for: .milliseconds(5))
          }
          do { try await serving.value; XCTFail("Reset Stream completed proxy serve successfully") }
          catch { XCTAssertEqual(error as? SessionError, .streamReset) }
        } else {
          phase = "normal response"
          // Normal request FIN must leave the response direction available.
          try await backend.send(Data("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nresponse".utf8))
          let exchange = try await opening.value
          XCTAssertEqual(exchange.status, 200)
          var body = Data()
          body: while true {
            switch try await exchange.readBodyPart() {
            case .bytes(let bytes): body.append(bytes)
            case .end(let trailers): XCTAssertTrue(trailers.isEmpty); break body
            }
          }
          XCTAssertEqual(body, Data("response".utf8))
          phase = "normal exchange cleanup"
          try await exchange.close()
          phase = "normal serve cleanup"
          try await serving.value
          phase = "normal upstream EOF"
          try await backend.waitInput(request, eof: true)
        }
        let completed = await proxyServer.cleanupStatus()
        XCTAssertEqual(completed.pendingCallbacks, 0)
        phase = "proxy server close"
        try await proxyServer.close()
        let closed = await proxyServer.cleanupStatus()
        XCTAssertTrue(closed.complete)
        await backend.close()
      } catch {
        XCTFail("Native HTTP proxy cancel=\(cancelBeforeResponse) failed during \(phase): \(error)")
        let received = backend.input
        opening.cancel(); serving.cancel()
        try? await proxyServer.close()
        await backend.close()
        let openResult = await opening.result; let serveResult = await serving.result
        XCTFail("Native HTTP proxy input=\(String(decoding: received, as: UTF8.self)), open=\(openResult), serve=\(serveResult)")
        throw error
      }
    }
  }

  func exerciseNativeWebSocketProxy(client: any Session, server: any Session) async throws {
    let limits = try ProxyClientLimits(maximumMetadataBytes: 4096, maximumChunkBytes: 1024,
      maximumBodyBytes: 4096, maximumWebSocketFrameBytes: 16_384)
    let proxyClient = try ProxyClient(session: client, limits: limits)
    let close = Data([0x03, 0xe8])
    for scenario in ["downstream-close", "upstream-close-slow-reader", "cancel-held-receive", "peer-reset-held-receive"] {
      let backend = try await ProxyWebSocketTestServer.start()
      let hold = ProxyWebSocketReceiveHold()
      let native: NativeProxyUpstream
      let proxyServer: ProxyServer
      do {
        native = try await environment.makeNativeProxyUpstream(NativeProxyUpstreamConfiguration(
          origin: XCTUnwrap(URL(string: "http://127.0.0.1:\(backend.port)")), numericAddress: "127.0.0.1",
          limits: limits, timeoutMilliseconds: 20_000))
        let upstream: any ProxyUpstream = scenario.hasSuffix("held-receive")
          ? ProxyHeldNativeUpstream(original: native, hold: hold) : native
        proxyServer = try ProxyServer(session: server, upstream: upstream, limits: limits, maximumConcurrentStreams: 1)
      } catch { await backend.close(); throw error }
      let serving = Task {
        let incoming = try await server.acceptStream()
        XCTAssertEqual(incoming.kind, "flowersec-proxy/ws")
        try await proxyServer.serve(incoming)
      }
      retainPeerTask(serving)
      let opening = Task { try await proxyClient.openWebSocket(path: "/socket") }
      var connection: ProxyWebSocket?
      var phase = "upgrade"
      do {
        let socket = try await opening.value; connection = socket
        phase = "bidirectional data"
        let request = Data("original public WebSocket request".utf8)
        try await socket.send(.binary(request))
        try await backend.waitInput([.init(operation: .binary, payload: request)])
        if scenario.hasSuffix("held-receive") {
          phase = "entered native receive"
          try await backend.send(.binary, Data("held original callback".utf8))
          try await hold.waitEntered()
          phase = "cancel or peer reset"
          if scenario == "cancel-held-receive" { serving.cancel() }
          else { try await socket.close() }
          try await backend.waitClosed()
          let waiting = await proxyServer.cleanupStatus()
          XCTAssertEqual(waiting.pendingCallbacks, 1, "Original callback must keep its operation slot after socket close")
          hold.release()
          do { try await serving.value; XCTFail("Canceled or reset WebSocket serve succeeded") }
          catch {
            XCTAssertTrue(error is CancellationError || (error as? SessionError) == .canceled || (error as? SessionError) == .streamReset)
          }
        } else {
          let first = Data(repeating: 0x41, count: 8192), second = Data(repeating: 0x42, count: 8192)
          phase = "queued native data"
          try await backend.send(.binary, first)
          try await backend.send(.binary, second)
          if scenario == "downstream-close" {
            try await socket.send(.close(close))
            try await backend.waitInput([.init(operation: .binary, payload: request), .init(operation: .close, payload: close)])
          }
          try await backend.send(.close, close)
          // Let the real upstream finish writing while the public downstream
          // deliberately leaves both data frames and Close unread.
          try await Task.sleep(for: .milliseconds(100))
          if scenario == "upstream-close-slow-reader" {
            let waiting = await proxyServer.cleanupStatus()
            XCTAssertEqual(waiting.pendingCallbacks, 1, "The opposite Close still belongs to the original relay")
          }
          phase = "slow downstream data and Close"
          for expected in [first, second] {
            guard case .binary(let bytes) = try await socket.receive() else { throw ProxyClientFailure.protocolFailure }
            XCTAssertEqual(bytes, expected)
          }
          guard case .close(let bytes) = try await socket.receive() else { throw ProxyClientFailure.protocolFailure }
          XCTAssertEqual(bytes, close)
          if scenario == "upstream-close-slow-reader" {
            try await socket.send(.close(close))
            try await backend.waitInput([.init(operation: .binary, payload: request), .init(operation: .close, payload: close)])
          }
          phase = "authenticated send drain"
          try await serving.value
          try await backend.waitClosed()
        }
        let finished = await proxyServer.cleanupStatus()
        XCTAssertEqual(finished.pendingCallbacks, 0)
        try? await socket.close()
        try await proxyServer.close()
        let closed = await proxyServer.cleanupStatus()
        XCTAssertTrue(closed.complete)
        await backend.close()
      } catch {
        XCTFail("Native WebSocket proxy \(scenario) failed during \(phase): \(error)")
        hold.release(); opening.cancel(); serving.cancel()
        try? await connection?.close(); try? await proxyServer.close(); await backend.close()
        _ = await opening.result; _ = await serving.result
        throw error
      }
    }
  }

  func reopenSource() throws -> TransportLiveServerSource {
    let admissions = LiveServerAdmissionStoreConfiguration(directory: directory,
      backingIdentity: Data(repeating: 101, count: 16), create: false, maximumRows: 16, maximumBytes: 1 << 20, parentWinner: winner.configuration,
      checkContinuity: { _ in })
    let reopened = TransportLiveServerSource(try V4LiveServerMaterialSource(environment: foundation,
      credentials: initial.credentials.configuration(), endpoints: [
        TransportEndpoint(hostname: "localhost", port: serverPort, numericAddress: "127.0.0.1")],
      roots: [tls.rootPEM], tls: nil, identity: serverIdentity,
      configuration: TransportLiveServerSourceConfiguration(control: control, admissions: admissions)))
    gate.withLock { sources.append(reopened) }; return reopened
  }

  func close() {
    source.close(); caller.close()
    let snapshot = gate.withLock { (host, peers, materials, sources, server, peerTasks) }
    snapshot.0?.close()
    for peer in snapshot.1 { peer.close() }
    for material in snapshot.2 { material.close() }
    for source in snapshot.3 { source.close() }
    snapshot.4?.cancel()
    for task in snapshot.5 { task.cancel() }
  }
  func finish() async throws {
    close()
    let snapshot = gate.withLock { (host, run, peers, sources, server) }
    if let host = snapshot.0 { await host.stop(); _ = try await host.waitCleanup() }
    _ = try? await snapshot.1?.value
    _ = try? await snapshot.4?.value
    for peer in snapshot.2 { await peer.waitClosed() }
    for task in gate.withLock({ peerTasks }) { _ = try? await task.value }
    _ = try await source.waitCleanup()
    for source in snapshot.3 { _ = try await source.waitCleanup() }
    winner.close(); clientIdentity.close(); serverIdentity.close(); relayIdentity.close()
    try await environment.close()
    for original in gate.withLock({ extraFoundations }) { try await original.close() }
  }
}

/// Reads the committed database through an independent connection. It never
/// writes a row or fabricates an admission result. The first observed committed
/// admission loses the caller's result after the original COMMIT has happened.
private final class V4AdmissionResultLoss: @unchecked Sendable {
  let path: String
  let enabled: Bool
  private let gate = NSLock()
  private var didObserve = false
  var observed: Bool { gate.withLock { didObserve } }
  init(path: String, enabled: Bool) { self.path = path; self.enabled = enabled }
  func check() throws {
    if enabled, try v4CommittedRowCount(path: path, table: "admissions") > 0 {
      gate.withLock { didObserve = true }; throw V4PoolFailure.storage
    }
  }
}

private final class V4OriginalClientPeer: V4HandshakeWriter, @unchecked Sendable {
  let plan: V4DirectPoolPlan
  let identity: V4LocalIdentity
  private let gate = NSLock()
  private var prepared: V4PreparedWebSocket?
  private var socket: V4ConsumedWebSocket?
  private var handshake: V4Handshake?
  private var core: V4ReliableSession?
  private var resources: [V4CryptoReservation] = []
  private var closed = false
  private var sentFSB = false
  private var receivedFSA = false
  private var sentReady = false
  var fsbSubmitted: Bool { gate.withLock { sentFSB } }
  var fsaReceived: Bool { gate.withLock { receivedFSA } }
  var readySubmitted: Bool { gate.withLock { sentReady } }
  init(plan: V4DirectPoolPlan, identity: V4LocalIdentity) { self.plan = plan; self.identity = identity }

  func establish(roots: [Data], listenerTLS: NativeListenerTLSConfiguration? = nil) async throws {
    let foundation = plan.environment
    let handshakeStorage = try foundation.reserveHandshake()
    gate.withLock { resources.append(handshakeStorage) }
    let streamStorage = try foundation.reliableSessionStorage(maxCredit: plan.maxCredit, slots: plan.slots)
    gate.withLock { resources.append(streamStorage) }
    let native: V4PreparedWebSocket
    if plan.route.isDialer {
      native = try await V4PreparedWebSocket.prepare(route: plan.route, numericAddress: "127.0.0.1", trustRootsPEM: roots)
    } else {
      native = try await V4PreparedWebSocket.listen(route: plan.route, numericAddress: "127.0.0.1", tls: listenerTLS)
    }
    try gate.withLock { prepared = native; if closed { native.close(); throw V4CryptoFailure.closed } }
    let consumed = try native.consumeLive()
    try gate.withLock { socket = consumed; if closed { consumed.close(); throw V4CryptoFailure.closed } }
    let hop = try await V4TunnelHop.authenticate(socket: consumed, plan: plan, identity: identity, storage: handshakeStorage)
    let clientHello = try V4DirectEstablishment.hello(plan)
    try send(type: 1, body: clientHello); try await consumed.flush()
    let serverHello = try await receive(type: 1, maximum: 16_384)
    let context = try V4DirectEstablishment.context(plan, clientHello: clientHello, serverHello: serverHello)
    let fsb = try request(context: context)
    try send(type: 2, body: fsb); gate.withLock { sentFSB = true }; try await consumed.flush()
    let fsa = try await receive(type: 3, maximum: 16_384)
    gate.withLock { receivedFSA = true }
    try V4DirectEstablishment.response(plan, context: context, fsb: fsb, fsa: fsa)
    let crypto = try foundation.handshake(admission: plan.credential, role: .client, identity: identity,
      input: V4HandshakeInput(artifact: Data(plan.artifact.raw), clientHello: clientHello, serverHello: serverHello,
        transportContext: context, fsb: fsb, fsa: fsa, tunnelHop: hop),
      reservation: handshakeStorage, streamStorage: streamStorage)
    try gate.withLock { handshake = crypto; if closed { crypto.close(); throw V4CryptoFailure.closed } }
    try crypto.submitNoise(to: self); try await consumed.flush()
    try crypto.receiveNoise(await receive(type: 4, maximum: 81))
    try crypto.submitReady(to: self); try await consumed.flush()
    try crypto.receiveReady(await receive(type: 5, maximum: 103))
    let session = try crypto.establish().makeSession()
    try gate.withLock { core = session; if closed { session.close(); throw V4CryptoFailure.closed } }
  }

  private func request(context: Data) throws -> Data {
    let c = try V4NamespaceDocument(context, schema: "TransportContext", bytes: 65_536, nodes: 4096,
      registry: V4NamespaceRegistry()).root
    var fields: [(UInt64, Data)] = [
      (0, V4Crypto.bytes(plan.credential.artifactDigest)), (1, V4Crypto.text(try plan.artifact.t("tenant_id"))),
      (2, V4Crypto.bytes(try plan.artifact.b("issuer_key_id"))), (3, V4Crypto.bytes(try plan.artifact.b("lease_id"))),
      (4, V4Crypto.bytes(try plan.artifact.b("session_nonce"))), (5, V4Crypto.bytes(plan.credential.candidateID)),
      (6, V4Crypto.bytes(plan.credential.routeDigest)), (7, V4Crypto.bytes(plan.credential.attemptID)),
      (8, V4Crypto.bytes(try V4Crypto.random(32))), (9, V4Crypto.bytes(try c.b("hello_transcript_digest"))),
      (10, V4NamespaceValue.head(0, 0)), (11, V4NamespaceValue.head(0, 1)),
      (12, V4Crypto.bytes(try c.digest("transport_context_digest"))),
      (13, V4Crypto.bytes(Data(try plan.activationProof().raw))), (14, V4Crypto.bytes(Data(plan.client.raw))),
    ]
    fields.append((15, V4Crypto.bytes(try identity.signHandshake(
      V4Crypto.domain("fsb4/signature", [V4Crypto.map(fields)]), in: plan.environment))))
    let value = V4Crypto.map(fields)
    _ = try V4NamespaceDocument(value, schema: "FSB4", bytes: plan.route.maximumFrame, nodes: 4096,
      registry: V4NamespaceRegistry(), context: ["activation_source_profile": "live_authority"])
    return value
  }

  func send(type: UInt8, body: Data) throws {
    let native = try gate.withLock { () throws -> V4ConsumedWebSocket in
      guard !closed, let socket else { throw V4CryptoFailure.closed }; return socket
    }
    guard !body.isEmpty, body.count <= plan.route.maximumFrame else { throw V4CryptoFailure.capacity }
    let wire = V4Crypto.integer(UInt64(body.count), width: 4) + Data([type, 0, 0, 0]) + body
    let buffer = try plan.environment.cryptoBuffer(capacity: wire.count, credential: plan.credential)
    try buffer.store(wire); try native.publish(buffer)
  }
  func checkHop(_ hop: V4TunnelHop) throws {
    try gate.withLock { guard !closed, let socket else { throw V4CryptoFailure.closed }; try socket.checkHop(hop) }
  }
  func submit(_ flight: V4HandshakeFlight, buffer: V4CryptoBuffer) throws {
    try send(type: flight == .noise ? 4 : 5, body: buffer.withBytes { $0 })
    if flight == .ready { gate.withLock { sentReady = true } }
  }
  private func receive(type: UInt8, maximum: Int) async throws -> Data {
    let native = try gate.withLock { () throws -> V4ConsumedWebSocket in
      guard !closed, let socket else { throw V4CryptoFailure.closed }; return socket
    }
    let buffer = try await native.receive(); defer { buffer.close() }
    return try buffer.withBytes { wire in
      guard wire.count > 8, wire.count <= maximum + 8, V4Crypto.number(wire.prefix(4)) == wire.count - 8,
        wire[4] == type, wire[5..<8] == Data([0, 0, 0]) else { throw V4CryptoFailure.authentication }
      return Data(wire.dropFirst(8))
    }
  }

  func echo(_ data: Data) async throws -> Data {
    let (session, native) = try gate.withLock { () throws -> (V4ReliableSession, V4ConsumedWebSocket) in
      guard !closed, let core, let socket else { throw V4CryptoFailure.closed }; return (core, socket)
    }
    let stream = try session.open(kind: "echo", receiveWindow: plan.window, to: native)
    try await native.flush()
    for _ in 0..<128 {
      if try session.phase(stream) == .accepted { break }
      try await receiveRecord(session, socket: native)
    }
    guard try session.phase(stream) == .accepted else { throw V4CryptoFailure.phase }
    let written = try session.write(stream, data: data, fin: true, to: native)
    guard written == data.count else { throw V4CryptoFailure.capacity }
    _ = try session.poll(to: native); try await native.flush()
    var result = Data()
    for _ in 0..<128 {
      switch try session.read(stream, maximum: 4096) {
      case .data(let buffer):
        defer { buffer.close() }; result.append(try buffer.withBytes { $0 })
        _ = try session.poll(to: native); try await native.flush()
      case .pending: try await receiveRecord(session, socket: native)
      case .eof: return result
      case .aborted: throw V4CryptoFailure.authentication
      }
    }
    throw V4CryptoFailure.capacity
  }
  private func receiveRecord(_ session: V4ReliableSession, socket: V4ConsumedWebSocket) async throws {
    let buffer = try await socket.receive(); defer { buffer.close() }
    try buffer.withBytes { try session.receive($0) }
    _ = try session.poll(to: socket); try await socket.flush()
  }
  func close() {
    let owners = gate.withLock { closed = true; return (socket, prepared, handshake, core, resources) }
    owners.0?.close(); owners.1?.close(); owners.3?.close(); owners.2?.close()
    for resource in owners.4 { resource.seal() }
    plan.credential.close()
  }
  func waitClosed() async {
    let owners = gate.withLock { (socket, prepared) }
    if let socket = owners.0 { await socket.waitClosed() }
    else if let prepared = owners.1 { await prepared.waitClosed() }
    gate.withLock { socket = nil; prepared = nil; handshake = nil; core = nil; resources.removeAll() }
  }
}

/// A bound, unconnected ordinary-user loopback socket reserves an ephemeral
/// port. Readiness checks attempt another bind, so they cannot consume the
/// production listener's sole authorized HTTP/WebSocket child.
private final class V4OriginalTestPort {
  private var fd: Int32
  let port: Int
  init() throws {
    let value = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard value >= 0 else { throw TransportControlError.unavailable }
    var address = Self.address(port: 0)
    let result = withUnsafePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        Darwin.bind(value, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
      }
    }
    guard result == 0 else { Darwin.close(value); throw TransportControlError.unavailable }
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    let named = withUnsafeMutablePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(value, $0, &length) }
    }
    guard named == 0 else { Darwin.close(value); throw TransportControlError.unavailable }
    fd = value; port = Int(UInt16(bigEndian: address.sin_port))
  }
  private static func address(port: Int) -> sockaddr_in {
    var value = sockaddr_in()
    value.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); value.sin_family = sa_family_t(AF_INET)
    value.sin_port = UInt16(port).bigEndian; value.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    return value
  }
  static func waitOccupied(_ port: Int) async throws {
    for _ in 0..<500 {
      try Task.checkCancellation()
      let value = Darwin.socket(AF_INET, SOCK_STREAM, 0)
      guard value >= 0 else { throw TransportControlError.unavailable }
      var address = address(port: port)
      let result = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
          Darwin.bind(value, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
      }
      let error = errno; Darwin.close(value)
      if result < 0 {
        guard error == EADDRINUSE else { throw TransportControlError.unavailable }; return
      }
      try await Task.sleep(for: .milliseconds(10))
    }
    throw TransportControlError.unavailable
  }
  func close() { if fd >= 0 { Darwin.close(fd); fd = -1 } }
  deinit { close() }
}
#endif

#if os(macOS) || os(iOS)
private final class V4OriginalServeLease: ServeApplicationLease, @unchecked Sendable {
  private let gate = NSLock()
  private var closeCount = 0
  var closes: Int { gate.withLock { closeCount } }
  func close() { gate.withLock { closeCount += 1 } }
  func waitCleanup() async throws -> CleanupStatus { CleanupStatus(complete: closes == 1) }
}
private final class V4OriginalServeCallbacks: @unchecked Sendable {
  let lease = V4OriginalServeLease()
  private let gate = NSLock()
  private let admissionPath: String
  private let hold: Bool
  private let rejectSecondRequest: Bool
  private var requestCount = 0
  private var rejectedRequests = 0
  private var publishedReleaseCount = 0
  private var authorizationCount = 0
  private var publicationCount = 0
  private var releaseCount = 0
  private var releasedAuthorization = false
  private var waiter: CheckedContinuation<Void, Never>?
  init(admissionPath: String, holdAuthorization: Bool = false, rejectSecondRequest: Bool = false) {
    self.admissionPath = admissionPath; hold = holdAuthorization; self.rejectSecondRequest = rejectSecondRequest
  }
  var authorizations: Int { gate.withLock { authorizationCount } }
  var publications: Int { gate.withLock { publicationCount } }
  var releases: Int { gate.withLock { releaseCount } }
  var publishedReleases: Int { gate.withLock { publishedReleaseCount } }
  func options(source: ConnectionMaterialSource, streams: StreamHandlers? = nil, maximumConcurrentSessions: Int = 1,
    onSession: (@isolated(any) @Sendable (ApplicationInvocationContext, any Session) async throws -> ServeSessionDisposition)? = nil) -> ServeOptions {
    ServeOptions(listener: source, maximumConcurrentSessions: maximumConcurrentSessions, authorizeRequest: { [self] context, _ in
      try context.checkCancellation()
      let reject = gate.withLock { () -> Bool in
        requestCount += 1
        if rejectSecondRequest, requestCount == 2 { rejectedRequests += 1; return true }
        return false
      }
      if reject { throw ServeError(.requestRejected) }
    }, resolveHandlers: { [self] context, request in
      try context.checkCancellation()
      XCTAssertEqual(request.tenant, "tenant")
      XCTAssertEqual(try v4CommittedRowCount(path: admissionPath, table: "admissions"), 0)
      return HandlerPlan(streams: streams)
    }, authorizeApplication: { [self] _, request, _ in
      XCTAssertEqual(request.artifactDigest.count, 32); XCTAssertEqual(request.attemptID.count, 16)
      gate.withLock { authorizationCount += 1 }
      if hold {
        await withCheckedContinuation { continuation in
          let alreadyReleased = gate.withLock { () -> Bool in
            if releasedAuthorization { return true }; waiter = continuation; return false
          }
          if alreadyReleased { continuation.resume() }
        }
      }
      return AuthorizeApplicationResult(lease: lease)
    }, onSession: onSession ?? { [self] context, _ in
      try context.checkCancellation()
      XCTAssertEqual(try v4CommittedRowCount(path: admissionPath, table: "admissions"), 1)
      gate.withLock { publicationCount += 1 }; return .accepted
    }, release: { [self] _, status in
      XCTAssertTrue(status.cleanup.complete)
      if status.request != nil { XCTAssertEqual(lease.closes, 1) }
      gate.withLock { releaseCount += 1; if status.published { publishedReleaseCount += 1 } }
      return status.cleanup
    })
  }
  func releaseAuthorization() {
    let original = gate.withLock { () -> CheckedContinuation<Void, Never>? in
      releasedAuthorization = true; defer { waiter = nil }; return waiter
    }
    original?.resume()
  }
  func waitForAuthorization() async throws { try await wait { self.authorizations > 0 } }
  func waitForPublication() async throws { try await wait { self.publications > 0 } }
  func waitForRejectedRequest() async throws { try await wait { self.gate.withLock { self.rejectedRequests > 0 } } }
  private func wait(_ condition: @Sendable () -> Bool) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while !condition() {
      guard ContinuousClock.now < deadline else { throw SessionError.timeout }
      try await ContinuousClock().sleep(for: .milliseconds(5))
    }
  }
}
private final class V4ServePublicationBlocker: @unchecked Sendable {
  private let condition = NSCondition()
  private var occupied = false
  private var released = false
  private var dispatchCount = 0
  var dispatches: Int { condition.lock(); defer { condition.unlock() }; return dispatchCount }
  func recordDispatch() { condition.lock(); dispatchCount += 1; condition.unlock() }
  func occupy() {
    condition.lock(); defer { condition.unlock() }
    occupied = true
    let end = Date().addingTimeInterval(10)
    while !released { if !condition.wait(until: end) { break } }
  }
  func release() { condition.lock(); released = true; condition.broadcast(); condition.unlock() }
  private var started: Bool { condition.lock(); defer { condition.unlock() }; return occupied }
  func waitStarted() async throws {
    let end = ContinuousClock.now.advanced(by: .seconds(5))
    while !started {
      guard ContinuousClock.now < end else { throw SessionError.timeout }
      try await ContinuousClock().sleep(for: .milliseconds(5))
    }
  }
}
private actor V4ServePublicationActor {
  private(set) var invocations = 0
  func occupy(_ blocker: V4ServePublicationBlocker) { blocker.occupy() }
  func callback() -> @isolated(any) @Sendable (ApplicationInvocationContext, any Session) async throws -> ServeSessionDisposition {
    v4ServeIsolatedTestCallback { [self] _, _ in invocations += 1; return .accepted }
  }
}
private func v4ServeIsolatedTestCallback(
  @_inheritActorContext _ callback: @escaping @isolated(any) @Sendable (ApplicationInvocationContext, any Session) async throws -> ServeSessionDisposition
) -> @isolated(any) @Sendable (ApplicationInvocationContext, any Session) async throws -> ServeSessionDisposition {
  callback
}
#endif
