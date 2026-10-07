#if os(macOS) || os(iOS)
import Crypto
import Foundation
import NIOCore
import NIOWebSocket
import NIOSSL
import SQLite3
import XCTest

@testable import Flowersec

@MainActor
final class TransportTunnelCredentialTests: XCTestCase {
  func testServerAllowAcknowledgementRechecksBeforeSinglePublicationCommit() throws {
    let expected = Data("original-registration".utf8)
    let state = V4ServerAllowAckState(expected: expected)
    let acknowledgement = V4ServerAllowAcknowledgement(check: { try state.check() }, written: { state.publish() })

    try acknowledgement.completeWrite()
    XCTAssertEqual(state.snapshot.checks, 1)
    XCTAssertEqual(state.snapshot.delivered, expected)
    XCTAssertThrowsError(try acknowledgement.completeWrite())
    XCTAssertEqual(state.snapshot.checks, 1, "a completed ACK cannot re-run publication")
  }

  func testOriginalMTLSTunnelTxBCompletesGrantAndRejectsRelayForgeryWithoutControlReplay() async throws {
    for profile in V4CryptoProfile.allCases {
      let peer = V4TunnelHopTestPeer(validRelayProof: false)
      let listener = try V4WebSocketTestServer(subprotocol: "flowersec.tunnel.v4", handler: { channel in
        peer.attach(channel); return peer
      })
      defer { listener.stop() }
      let fixture = try V4TunnelCredentialFixture(profile: profile, hostname: "localhost", port: listener.port, nativeResources: true)
      let foundation = fixture.credentials.base.environment
      let identity = try foundation.importIdentity(profile: profile,
        signingSeed: Data(repeating: 21, count: 32), staticKey: Data(repeating: 31, count: 32))
      defer { identity.close() }
      let ca = try Data(contentsOf: Bundle.module.url(forResource: "self_signed_ca", withExtension: "pem", subdirectory: "Fixtures")!)
      let host = V4ClientEnvironment(foundation: foundation, namespaces: [fixture.credentials.base.owner!],
        credentials: fixture.credentials.configuration(),
        endpoints: [TransportEndpoint(hostname: "localhost", port: listener.port, numericAddress: "127.0.0.1")],
        roots: [ca], backing: nil, store: nil, provider: try foundation.clientProviderStorage(bytes: 1 << 20))
      let environment = TransportEnvironment(owner: host)
      let tlsIdentity = try V4ControlTestAuthority.Identity()
      let issuance = try V4ControlTestAuthority(identity: tlsIdentity) { path, body in
        guard path == "/issue/artifact" else { throw TransportControlError.responseInvalid }
        var reader = V4PoolWireCursor(body, maximum: 1024)
        try reader.array(1)
        guard try reader.bytes(maximum: 32).count == 32 else { throw TransportControlError.responseInvalid }
        try reader.end()
        return fixture.original.artifact
      }
      defer { issuance.stop() }
      let activation = try V4ControlTestAuthority(identity: tlsIdentity) { path, body in
        guard path == "/live/authorize" else { throw TransportControlError.responseInvalid }
        let response = try fixture.liveAuthorityResponse(body)
        let material = try V4LiveTunnelMaterial.decode(response)
        peer.configure(grant: material.grant, relay: fixture.relay)
        return response
      }
      defer { activation.stop() }
      let relayControl = V4TunnelLiveRelayTestControl(fixture: fixture, peer: peer)
      let preparation = try V4ControlTestAuthority(identity: tlsIdentity, maximumRequestBytes: 24_576) { path, body in
        try relayControl.respond(path: path, body: body)
      }
      defer { preparation.stop() }
      let configuration = TransportLiveAuthoritySourceConfiguration(issuance: issuance.configuration(),
        activation: activation.configuration(), clientCertificate: fixture.original.clientCertificate,
        serverCertificate: fixture.original.serverCertificate, activationSigningKeyID: "activate",
        tunnel: TransportLiveTunnelConfiguration(scope: fixture.scope(), relayCertificate: fixture.relay, grantLimits: fixture.limits()),
        relayPreparation: preparation.configuration())
      let source = try await environment.makeLiveAuthoritySource(configuration, identity: TransportApplicationIdentity(identity))
      let material = try await source.acquire()
      source.close()
      let original = try XCTUnwrap(material.owner as? V4DirectPoolMaterial)
      XCTAssertThrowsError(try original.plan.credential.tunnelGrant())
      do { _ = try await environment.connectMaterial(material); XCTFail("Relay forgery reached native READY") }
      catch {
        let failure = try XCTUnwrap(error as? ConnectError)
        XCTAssertEqual(failure.code, .securityFailed)
        XCTAssertEqual(failure.retryDisposition, .terminal)
        XCTAssertEqual(failure.connection.spendState, .spent)
        XCTAssertEqual(failure.connection.networkReady, .notStarted)
      }
      XCTAssertTrue(peer.endpointPossessionVerified)
      XCTAssertEqual(peer.frameTypes, [16, 16]); XCTAssertNil(peer.failure)
      XCTAssertEqual(issuance.requests, ["/issue/artifact"])
      XCTAssertEqual(activation.requests, ["/live/authorize"])
      XCTAssertEqual(preparation.requests, ["/tunnel/relay-prepare", "/tunnel/relay-activate-client"])
      XCTAssertTrue(material.cleanupStatus().complete)
      let failedAttempt = original.plan.credential.attemptID
      do { _ = try await environment.connectMaterial(material); XCTFail("failed original material dispatched another TxB") } catch {}
      XCTAssertEqual(original.plan.credential.attemptID, failedAttempt)
      XCTAssertEqual(issuance.requests, ["/issue/artifact"])
      XCTAssertEqual(activation.requests, ["/live/authorize"])
      XCTAssertEqual(preparation.requests, ["/tunnel/relay-prepare", "/tunnel/relay-activate-client"])
      do { _ = try await source.acquire(); XCTFail("Closed captured Source reissued tunnel material") } catch {}
      try await environment.close()
    }
  }

  func testLiveServerOriginalRegistrationRefusesReplayAfterCommitAndUnknownResult() async throws {
    for loseOriginalResult in [false, true] {
      let fixture = try V4TunnelCredentialFixture(profile: .x25519, hostname: "localhost", port: 443)
      let credentials = try CredentialFixture(profile: CredentialFixture.x25519Profile, allowTunnel: true, nativeResources: true)
      credentials.tunnelLegs = (fixture.clientLeg, fixture.serverLeg)
      let localOriginal = try credentials.input(source: .preauthorizedPool, namespaceRole: 7)
      XCTAssertEqual(localOriginal.artifact, fixture.original.artifact)
      let foundation = credentials.base.environment
      let serverIdentity = try foundation.importIdentity(profile: .x25519,
        signingSeed: Data(repeating: 22, count: 32), staticKey: Data(repeating: 32, count: 32))
      defer { serverIdentity.close() }
      let tls = try V4ControlTestAuthority.Identity()
      let clientCertificate = try XCTUnwrap(try NIOSSLCertificate.fromPEMBytes(Array(tls.clientPEM)).first)
      let control = TransportServerAllowHTTPSConfiguration(numericAddress: "127.0.0.1", port: 443,
        serverTLS: NativeListenerTLSConfiguration(certificateChainPEM: tls.serverPEM, privateKeyPEM: tls.serverKeyPEM),
        authorityClientCertificateDER: Data(try clientCertificate.toDERBytes()))
      let endpoints = [TransportEndpoint(hostname: "localhost", port: 443, numericAddress: "127.0.0.1")]
      let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
      let directory = root.appendingPathComponent(".flowersec/swift-live-server-original-\(UUID().uuidString)")
      try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
      defer { try? FileManager.default.removeItem(at: directory) }
      let path = directory.appendingPathComponent("live-server-admissions.sqlite3").path
      let continuity: @Sendable (Data) throws -> Void = { _ in
        // Observe only the separately committed SQLite state. Losing the local
        // continuity check after COMMIT must not turn a durable refusal into
        // an original result, or permit a new registration for that lease.
        if loseOriginalResult, try v4CommittedRowCount(path: path, table: "originals") > 0 {
          throw V4PoolFailure.storage
        }
      }
      let admissions = LiveServerAdmissionStoreConfiguration(directory: directory,
        backingIdentity: Data(repeating: 90, count: 16), create: true, maximumRows: 16,
        maximumBytes: 1 << 20, checkContinuity: continuity)
      let owner = try V4LiveServerMaterialSource(environment: foundation, credentials: credentials.configuration(),
        endpoints: endpoints, roots: [], tls: nil, identity: serverIdentity,
        configuration: TransportLiveServerSourceConfiguration(control: control, admissions: admissions))
      let source = TransportLiveServerSource(owner)
      let serverScope = TransportGrantScope(tenant: "tenant", authority: "authority", capacityDigest: credentials.base.capacityDigest,
        generation: 1, policyID: "credentials", policyRevision: 1, issuer: Data(repeating: 15, count: 16),
        audience: "relay-service", service: "relay-service", roleMask: 6, cohort: 9, issuedMS: 900,
        expiresMS: 1600, parentAuthority: "authority", parentCapacity: credentials.base.capacityDigest,
        parentGeneration: 1, parentIssuer: Data(repeating: 5, count: 16), parentCohort: 9)
      let material = TransportLiveServerMaterial(artifact: fixture.original.artifact,
        clientCertificate: fixture.original.clientCertificate, serverCertificate: fixture.original.serverCertificate,
        attempt: Data(repeating: 91, count: 16), recipient: Data(repeating: 92, count: 16),
        activationSigningKeyID: "activate", tunnel: TransportLiveTunnelConfiguration(scope: serverScope,
          relayCertificate: fixture.relay, grantLimits: fixture.limits()))
      if loseOriginalResult {
        XCTAssertThrowsError(try source.registerOriginal(material)) { error in
          XCTAssertEqual(error as? V4PoolFailure, .storage)
        }
      } else {
        let binding = try source.registerOriginal(material)
        XCTAssertEqual(binding.attempt, material.attempt)
        XCTAssertEqual(binding.incarnation.count, 16)
        XCTAssertEqual(binding.artifactDigest, NamespaceFixture.digest("artifact-digest", material.artifact))
        XCTAssertThrowsError(try source.registerOriginal(material)) { error in
          XCTAssertEqual(error as? V4PoolFailure, .conflict)
        }
      }
      source.close()
      let closed = try await source.waitCleanup()
      XCTAssertTrue(closed.complete)
      XCTAssertEqual(try v4CommittedRowCount(path: path, table: "originals"), 1)
      XCTAssertEqual(try v4CommittedRowCount(path: path, table: "admissions"), 0,
        "durable registration alone cannot grant a carrier admission or restore activation")

      let reopened = LiveServerAdmissionStoreConfiguration(directory: directory,
        backingIdentity: admissions.backingIdentity, create: false, maximumRows: 16, maximumBytes: 1 << 20,
        checkContinuity: { _ in })
      let reopenedOwner = try V4LiveServerMaterialSource(environment: foundation, credentials: credentials.configuration(),
        endpoints: endpoints, roots: [], tls: nil, identity: serverIdentity,
        configuration: TransportLiveServerSourceConfiguration(control: control, admissions: reopened))
      let restored = TransportLiveServerSource(reopenedOwner)
      XCTAssertThrowsError(try restored.registerOriginal(material)) { error in
        XCTAssertEqual(error as? V4PoolFailure, .conflict)
      }
      restored.close()
      let restoredCleanup = try await restored.waitCleanup()
      XCTAssertTrue(restoredCleanup.complete)
      XCTAssertEqual(try v4CommittedRowCount(path: path, table: "originals"), 1)
      XCTAssertEqual(try v4CommittedRowCount(path: path, table: "admissions"), 0)
    }
  }

  func testRelayHostCommitsIndependentPublicationsAndContinuesAfterOriginalPreparationFailure() async throws {
    // Retain a real listener at the signed endpoint so each original relay
    // preparation fails without needing a fabricated relay possession proof.
    let occupied = try V4WebSocketTestServer(subprotocol: "flowersec.tunnel.v4")
    defer { occupied.stop() }
    let fixture = try V4TunnelCredentialFixture(profile: .x25519, hostname: "localhost", port: occupied.port)
    let credentials = try CredentialFixture(profile: CredentialFixture.x25519Profile, allowTunnel: true, nativeResources: true)
    credentials.tunnelLegs = (fixture.clientLeg, fixture.serverLeg)
    let localOriginal = try credentials.input(source: .preauthorizedPool, namespaceRole: 7)
    XCTAssertEqual(localOriginal.artifact, fixture.original.artifact)
    let foundation = credentials.base.environment
    let relayIdentity = try foundation.importIdentity(profile: .x25519,
      signingSeed: Data(repeating: 23, count: 32), staticKey: Data(repeating: 33, count: 32))
    defer { relayIdentity.close() }

    let tlsIdentity = try V4ControlTestAuthority.Identity()
    let ca = try Data(contentsOf: Bundle.module.url(forResource: "self_signed_ca", withExtension: "pem", subdirectory: "Fixtures")!)
    let endpoints = [TransportEndpoint(hostname: "localhost", port: occupied.port, numericAddress: "127.0.0.1")]
    let listenerTLS = NativeListenerTLSConfiguration(certificateChainPEM: tlsIdentity.serverPEM,
      privateKeyPEM: tlsIdentity.serverKeyPEM)
    let hostEnvironment = V4ClientEnvironment(foundation: foundation, namespaces: [credentials.base.owner!],
      credentials: credentials.configuration(), endpoints: endpoints, roots: [ca], backing: nil, store: nil,
      provider: try foundation.clientProviderStorage(bytes: 1 << 20), listenerTLS: listenerTLS)

    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let directory = root.appendingPathComponent(".flowersec/swift-relay-host-publications-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let claimStore = RelayClaimStoreConfiguration(directory: directory, backingIdentity: Data(repeating: 92, count: 16),
      create: true, maximumRows: 32, maximumBytes: 1 << 20, checkContinuity: { _ in })

    func livePublication(_ attempt: UInt8, lease: UInt8? = nil) throws -> TransportLiveRelayPublication {
      let fixture = try V4TunnelCredentialFixture(profile: .x25519, hostname: "localhost", port: occupied.port,
        lease: lease ?? attempt)
      let attemptID = Data(repeating: attempt, count: 16)
      func scope(roleMask: UInt64) -> TransportGrantScope {
        TransportGrantScope(tenant: "tenant", authority: "authority", capacityDigest: fixture.credentials.base.capacityDigest,
          generation: 1, policyID: "credentials", policyRevision: 1, issuer: Data(repeating: 15, count: 16),
          audience: "relay-service", service: "relay-service", roleMask: roleMask, cohort: 9, issuedMS: 900,
          expiresMS: 1600, parentAuthority: "authority", parentCapacity: fixture.credentials.base.capacityDigest,
          parentGeneration: 1, parentIssuer: Data(repeating: 5, count: 16), parentCohort: 9)
      }
      let client = TransportLiveTunnelConfiguration(scope: scope(roleMask: 5), relayCertificate: fixture.relay,
        grantLimits: fixture.limits())
      let server = TransportLiveTunnelConfiguration(scope: scope(roleMask: 6), relayCertificate: fixture.relay,
        grantLimits: fixture.limits())
      let original = try fixture.credentials.input(source: .liveAuthority,
        artifact: [6: .bytes(Data(repeating: lease ?? attempt, count: 16))],
        activation: [5: .bytes(Data(repeating: lease ?? attempt, count: 16)), 9: .bytes(attemptID)], namespaceRole: 7)
      let clientGrant = try fixture.grant(attempt: attemptID)
      let serverGrant = try fixture.grant(attempt: attemptID,
        overrides: [13: fixture.namespace(role: 6)])
      return TransportLiveRelayPublication(artifact: fixture.original.artifact,
        clientCertificate: fixture.original.clientCertificate, serverCertificate: fixture.original.serverCertificate,
        attempt: attemptID, client: client, server: server, clientGrant: clientGrant, serverGrant: serverGrant,
        activationAuthorization: original.activation, activationSigningKeyID: "activate")
    }

    let original = try livePublication(93)
    let next = try livePublication(94)
    let configuration = RelayHostConfiguration(live: original, claims: claimStore, maximumPendingPublications: 3)
    let host = try hostEnvironment.relayHost(configuration, identity: TransportApplicationIdentity(relayIdentity))
    let first = host.initialPublication
    let second = try host.publishLiveOriginal(next)
    let path = directory.appendingPathComponent("relay-claims.sqlite3").path
    XCTAssertEqual(try v4CommittedRowCount(path: path, table: "publications"), 4)
    XCTAssertEqual(try v4CommittedRowCount(path: path, table: "claims"), 0,
      "queue publication does not create a forwarding claim before both original HOP proofs")

    XCTAssertThrowsError(try host.publishLiveOriginal(original),
      "a prior durable publication claim cannot be replayed as new queue work")
    XCTAssertThrowsError(try host.publishLiveOriginal(livePublication(100, lease: 93)),
      "changing the attempt cannot recreate the same parent and candidate")
    first.close()
    do { try await first.waitCompletion(); XCTFail("closed first publication resolved successfully") } catch {}
    XCTAssertThrowsError(try host.publishLiveOriginal(original),
      "closing the first ticket must preserve its durable refusal")
    let third = try host.publishLiveOriginal(livePublication(95))
    let fourth = try host.publishLiveOriginal(livePublication(96))
    XCTAssertThrowsError(try host.publishLiveOriginal(livePublication(97))) { error in
      XCTAssertEqual(error as? V4ResourceFailure, .capacity)
    }
    XCTAssertEqual(try v4CommittedRowCount(path: path, table: "publications"), 8,
      "a queue-capacity refusal must occur before any new durable claim")
    host.close()
    let cleanup = try await host.waitCleanup()
    XCTAssertTrue(cleanup.complete)
    for publication in [first, second, third, fourth] {
      do { try await publication.waitCompletion(); XCTFail("closing queued original publication must resolve its ticket") }
      catch {}
    }
    let reopened = RelayClaimStoreConfiguration(directory: directory, backingIdentity: claimStore.backingIdentity,
      create: false, maximumRows: 32, maximumBytes: 1 << 20, checkContinuity: { _ in })
    XCTAssertThrowsError(try hostEnvironment.relayHost(
      RelayHostConfiguration(live: original, claims: reopened, maximumPendingPublications: 3),
      identity: TransportApplicationIdentity(relayIdentity)))
    XCTAssertEqual(try v4CommittedRowCount(path: path, table: "publications"), 8,
      "historical rows remain refusal-only after reopening the real SQLite ledger")

    let daemon = try hostEnvironment.relayHost(
      RelayHostConfiguration(live: livePublication(98), claims: reopened, maximumPendingPublications: 3),
      identity: TransportApplicationIdentity(relayIdentity))
    defer { daemon.close() }
    let run = Task { try await daemon.run() }
    let originalFailure = daemon.initialPublication
    do { try await originalFailure.waitCompletion(); XCTFail("occupied original listener reached forwarding") } catch {}
    let firstFailureCleanup = try await originalFailure.waitCleanup()
    XCTAssertTrue(firstFailureCleanup.complete)
    XCTAssertFalse(daemon.cleanupStatus().complete, "one failed publication must leave the daemon available")

    let nextFailure = try daemon.publishLiveOriginal(livePublication(99))
    do { try await nextFailure.waitCompletion(); XCTFail("second occupied listener reached forwarding") } catch {}
    let secondFailureCleanup = try await nextFailure.waitCleanup()
    XCTAssertTrue(secondFailureCleanup.complete)
    XCTAssertThrowsError(try daemon.publishLiveOriginal(livePublication(98))) { error in
      XCTAssertEqual(error as? V4PoolFailure, .conflict)
    }
    await daemon.stop()
    _ = try? await run.value
    XCTAssertTrue(daemon.cleanupStatus().complete)
    // Inspect committed rows only after the original exclusive SQLite owner
    // has physically closed; an independent reader cannot borrow its fence.
    XCTAssertEqual(try v4CommittedRowCount(path: path, table: "publications"), 12)
    XCTAssertEqual(try v4CommittedRowCount(path: path, table: "claims"), 0,
      "failed physical preparations must never synthesize HOP claim results")
    try await hostEnvironment.close()
  }

  func testHopHelloValidatesEmbeddedGrantRoleAndIdentity() throws {
    let fixture = try V4TunnelCredentialFixture(profile: .x25519)
    func hello(grant: Data?, identity: Data) -> Data {
      var fields: [(UInt64, Data)] = [(0, V4NamespaceValue.head(0, 0)),
        (1, V4Crypto.bytes(Data(repeating: 1, count: 16))),
        (2, V4Crypto.bytes(Data(repeating: 2, count: 32))), (4, V4Crypto.bytes(identity))]
      if let grant { fields.append((3, V4Crypto.bytes(grant))) }
      return V4Crypto.map(fields.sorted { $0.0 < $1.0 })
    }
    func decode(_ bytes: Data, sender: String) throws {
      _ = try V4NamespaceDocument(bytes, schema: "HOP_AUTH_HELLO", bytes: 10_346,
        nodes: 4096, registry: fixture.registry, context: ["hop_sender_role": sender])
    }
    try decode(hello(grant: fixture.grant(), identity: fixture.original.clientCertificate), sender: "endpoint")
    try decode(hello(grant: nil, identity: fixture.relay), sender: "relay")
    XCTAssertThrowsError(try decode(hello(grant: fixture.grant(), identity: fixture.relay), sender: "relay"))
    XCTAssertThrowsError(try decode(hello(grant: nil, identity: fixture.original.clientCertificate), sender: "endpoint"))
    let serverRole = try fixture.grant(overrides: [13: fixture.namespace(role: 6)])
    XCTAssertThrowsError(try decode(hello(grant: serverRole, identity: fixture.original.clientCertificate), sender: "endpoint"))
    let otherIdentity = try fixture.credentials.certificate(0, override: [1: .text("other-client")])
    XCTAssertThrowsError(try decode(hello(grant: fixture.grant(), identity: otherIdentity), sender: "endpoint"))
  }

  func testOriginalNativeCarrierAuthenticatesHopAndRejectsForgedRelayPossessionBeforeHello() async throws {
    for profile in V4CryptoProfile.allCases {
      for validRelayProof in [true, false] {
        let peer = V4TunnelHopTestPeer(validRelayProof: validRelayProof)
        let listener = try V4WebSocketTestServer(subprotocol: "flowersec.tunnel.v4", handler: { channel in
          peer.attach(channel); return peer
        })
        defer { listener.stop() }
        let fixture = try V4TunnelCredentialFixture(profile: profile, hostname: "localhost", port: listener.port)
        let environment = fixture.credentials.base.environment
        let identity = try environment.importIdentity(profile: profile,
          signingSeed: Data(repeating: 21, count: 32), staticKey: Data(repeating: 31, count: 32))
        defer { identity.close() }
        let admission = try fixture.credentials.verify(fixture.input())
        defer { admission.close() }
        let plan = try admission.directPoolPlan(in: environment, identity: identity)
        peer.configure(grant: try fixture.grant(), relay: fixture.relay)
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
          .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let directory = root.appendingPathComponent(".flowersec/swift-native-tunnel-hop-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
          attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let backing = try V4PoolStoreBacking(environment: environment, directory: directory,
          identity: V4PoolStoreIdentity(storeID: Data(repeating: 7, count: 16), generation: 1,
            tenant: "tenant", issuer: Data(repeating: 5, count: 16), spendAuthority: "spend", winnerAuthority: "winner"),
          maximumBytes: 1 << 20, maximumRows: 16, continuity: { _ in })
        let store = try backing.open(create: true)
        defer { store.close() }
        let ca = try Data(contentsOf: Bundle.module.url(forResource: "self_signed_ca", withExtension: "pem", subdirectory: "Fixtures")!)
        let prepared = try await V4PreparedWebSocket.prepare(route: plan.route, numericAddress: "127.0.0.1", trustRootsPEM: [ca])
        defer { prepared.close() }
        let socket = try prepared.consumePool(using: store)
        defer { socket.close() }
        let storage = try environment.reserveHandshake()
        defer { storage.seal() }
        do {
          let hop = try await V4TunnelHop.authenticate(socket: socket, plan: plan, identity: identity, storage: storage)
          XCTAssertTrue(validRelayProof)
          try hop.check(admission: admission, role: .client, in: environment)
          try hop.checkCarrier(socket.tunnelCarrierIdentity)
          XCTAssertThrowsError(try hop.checkCarrier(prepared))
          try hop.claimHandshake(admission: admission, role: .client, in: environment)
          XCTAssertThrowsError(try hop.claimHandshake(admission: admission, role: .client, in: environment))
        } catch {
          XCTAssertFalse(validRelayProof)
          XCTAssertEqual(error as? V4CryptoFailure, .authentication)
        }
        XCTAssertTrue(peer.endpointPossessionVerified)
        XCTAssertEqual(peer.frameTypes, [16, 16])
        XCTAssertNil(peer.failure)
        // The fixture tests native HOP_AUTH only. It never claims a RelayClaim,
        // paired forwarding gate, ServerAllow owner or end-to-end READY result.
        socket.close(); await socket.waitClosed()
        store.close(); try? FileManager.default.removeItem(at: directory)
        try? backing.retireRemovedFiles()
      }
    }
  }

  func testOriginalSignedPoolGrantClosesBothLegsAndRelayDependencies() throws {
    for profile in V4CryptoProfile.allCases {
      let fixture = try V4TunnelCredentialFixture(profile: profile)
      let admission = try fixture.credentials.verify(fixture.input())
      defer { admission.close() }
      let (grant, relay) = try admission.tunnelGrant()
      XCTAssertEqual(Data(grant.raw), try fixture.grant())
      XCTAssertEqual(Data(relay.raw), fixture.relay)
      XCTAssertEqual(admission.pathKind, 1)
      XCTAssertEqual(admission.sessionNotAfterMS, 1600)
      let route = try admission.webSocketRoute(in: fixture.credentials.base.environment)
      XCTAssertEqual(route.path, "/flowersec/v4/tunnel")
      XCTAssertEqual(route.subprotocol, "flowersec.tunnel.v4")
      XCTAssertEqual(route.host, "relay.example")
    }
  }

  func testLocalGrantRejectsChangedAttemptRoleIssuerRouteAndRelayBeforePrepare() throws {
    let fixture = try V4TunnelCredentialFixture(profile: .x25519)
    let changed: [[UInt64: Data]] = [
      [6: V4Crypto.bytes(Data(repeating: 99, count: 16))],
      [5: V4Crypto.bytes(Data(repeating: 99, count: 32))],
      [18: V4Crypto.bytes(Data(repeating: 99, count: 32))],
      [12: V4Crypto.bytes(Data(repeating: 99, count: 16))],
      [13: fixture.namespace(role: 6)],
      [16: fixture.limits(maximumEnvelope: 1_048_576)],
    ]
    for fields in changed {
      XCTAssertThrowsError(try fixture.credentials.verify(fixture.input(grant: fixture.grant(overrides: fields))))
    }
    XCTAssertThrowsError(try fixture.credentials.verify(fixture.input(grant: fixture.grant(signer: 14))))
    let wrongRelay = try fixture.credentials.certificate(2, override: [4: .bytes(Data(repeating: 98, count: 32))])
    XCTAssertThrowsError(try fixture.credentials.verify(fixture.input(relay: wrongRelay)))
    let wrongRoles = try fixture.credentials.input(source: .preauthorizedPool, indices: [0, 1], namespaceRole: 3)
    let wrongClosure = V4CredentialInput(artifact: wrongRoles.artifact, clientCertificate: wrongRoles.clientCertificate,
      serverCertificate: wrongRoles.serverCertificate, activation: wrongRoles.activation,
      source: .preauthorizedPool, candidateIndex: 0, grant: try fixture.grant(), relayCertificate: fixture.relay)
    XCTAssertThrowsError(try fixture.credentials.verify(wrongClosure))
  }

  func testLiveGrantCompletesOnlyOriginalIndependentPreparationAfterOriginalTxB() throws {
    let fixture = try V4TunnelCredentialFixture(profile: .x25519)
    let identity = try fixture.credentials.base.environment.importIdentity(profile: .x25519,
      signingSeed: Data(repeating: 21, count: 32), staticKey: Data(repeating: 31, count: 32))
    defer { identity.close() }
    let original = try fixture.credentials.input(source: .liveAuthority, namespaceRole: 7)
    let future = TransportLiveTunnelConfiguration(scope: fixture.scope(), relayCertificate: fixture.relay,
      grantLimits: fixture.limits())
    let input = V4CredentialInput(artifact: original.artifact, clientCertificate: original.clientCertificate,
      serverCertificate: original.serverCertificate, activation: Data(), source: .liveAuthority,
      candidateIndex: 0, liveTunnel: future)
    let admission = try fixture.credentials.verify(input)
    defer { admission.close() }
    let plan = try admission.directPoolPlan(in: fixture.credentials.base.environment, identity: identity)
    XCTAssertThrowsError(try admission.tunnelGrant())
    XCTAssertThrowsError(try admission.claimHandshake(in: fixture.credentials.base.environment))
    _ = try admission.beginLiveAuthorization(signingKeyID: "activate")
    let attempt = admission.attemptID
    let authorized = try fixture.credentials.input(source: .liveAuthority, activation: [9: .bytes(attempt)], namespaceRole: 7)
    let grant = try fixture.grant(attempt: attempt)
    let response = Data([0x83]) + V4Crypto.text("live-tunnel-material-1")
      + V4Crypto.bytes(authorized.activation) + V4Crypto.bytes(grant)
    try plan.installLiveAuthorization(response, signingKeyID: "activate", configuration: fixture.credentials.configuration())
    XCTAssertEqual(Data(try admission.tunnelGrant().0.raw), grant)
    XCTAssertEqual(Data(try plan.activationProof().raw), authorized.activation)
    let originalActivationDigest = admission.activationDigest
    XCTAssertThrowsError(try plan.installLiveAuthorization(response, signingKeyID: "activate", configuration: fixture.credentials.configuration()))
    XCTAssertEqual(admission.activationDigest, originalActivationDigest)
    XCTAssertEqual(admission.attemptID, attempt)
    XCTAssertEqual(Data(try admission.tunnelGrant().0.raw), grant)
    XCTAssertEqual(Data(try plan.activationProof().raw), authorized.activation,
      "retrying the exact original TxB cannot replace the captured activation or Grant")
    XCTAssertThrowsError(try admission.completeLiveTunnelGrant(grant))
    XCTAssertThrowsError(try admission.beginLiveAuthorization(signingKeyID: "activate"))
  }

  func testCompleteBundleRetainsSortedCandidateRolePairsAndRejectsDroppedOrRepeatedSelectors() throws {
    let fixture = try V4TunnelCredentialFixture(profile: .x25519)
    let input = try fixture.input()
    let base = V4Crypto.bytes(input.artifact) + V4Crypto.bytes(input.activation)
      + V4Crypto.bytes(input.clientCertificate) + V4Crypto.bytes(input.serverCertificate)
    func entry(_ index: UInt64, _ role: UInt64, _ grant: Data) -> Data {
      Data([0x84]) + V4NamespaceValue.head(0, index) + V4NamespaceValue.head(0, role)
        + V4Crypto.bytes(grant) + V4Crypto.bytes(fixture.relay)
    }
    let first = try fixture.grant()
    let second = try fixture.grant(candidateIndex: 1)
    let entries = Data([0x83]) + entry(0, 0, first) + entry(0, 1, first) + entry(1, 0, second)
    let bundle = try V4PoolMaterialBundle.decode(Data([0x85]) + base + entries)
    XCTAssertEqual(bundle.tunnels.count, 3)
    XCTAssertEqual(bundle.tunnels.map(\.candidateIndex), [0, 0, 1])
    XCTAssertEqual(bundle.tunnels.map(\.role), [0, 1, 0])
    let selected = try bundle.credential(candidateIndex: 1)
    XCTAssertEqual(selected.input.grant, second); XCTAssertEqual(selected.input.poolTunnels.count, 3)
    let admission = try fixture.credentials.verify(selected.input)
    admission.close()
    XCTAssertThrowsError(try V4PoolMaterialBundle.decode(Data([0x85]) + base + Data([0x82])
      + entry(0, 0, first) + entry(0, 0, first)))
    XCTAssertThrowsError(try V4PoolMaterialBundle.decode(Data([0x85]) + base + Data([0x82])
      + entry(1, 0, second) + entry(0, 0, first)))
    let compact = try V4PoolMaterialBundle.decode(Data([0x86]) + base + V4Crypto.bytes(first) + V4Crypto.bytes(fixture.relay))
    XCTAssertEqual(compact.grant, first); XCTAssertEqual(compact.relayCertificate, fixture.relay)
  }
}

func v4CommittedRowCount(path: String, table: String) throws -> Int {
  guard ["originals", "admissions", "publications", "claims", "winners", "claim_originals", "refusals"].contains(table) else { throw V4PoolFailure.configuration }
  guard FileManager.default.fileExists(atPath: path) else { return 0 }
  var connection: OpaquePointer?
  guard sqlite3_open_v2(path, &connection, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK,
    let connection else {
    if let connection { sqlite3_close_v2(connection) }
    throw V4PoolFailure.storage
  }
  defer { sqlite3_close_v2(connection) }
  var statement: OpaquePointer?
  guard sqlite3_prepare_v2(connection, "SELECT count(*) FROM \(table)", -1, &statement, nil) == SQLITE_OK,
    let statement else { throw V4PoolFailure.storage }
  defer { sqlite3_finalize(statement) }
  guard sqlite3_step(statement) == SQLITE_ROW else { throw V4PoolFailure.storage }
  return Int(sqlite3_column_int64(statement, 0))
}

private final class V4ServerAllowAckState: @unchecked Sendable {
  private let gate = NSLock()
  private let expected: Data
  private var delivered = Data()
  private var checks = 0
  init(expected: Data) { self.expected = expected }
  var snapshot: (checks: Int, delivered: Data) { gate.withLock { (checks, delivered) } }
  func check() throws {
    try gate.withLock {
      checks += 1
      guard delivered.isEmpty else { throw V4CryptoFailure.authentication }
    }
  }
  func publish() { gate.withLock { delivered = expected } }
}

final class V4TunnelCredentialFixture: @unchecked Sendable {
  let credentials: CredentialFixture
  let registry: V4NamespaceRegistry
  let original: V4CredentialInput
  let relay: Data
  let clientLeg: V4CBORValue
  let serverLeg: V4CBORValue
  init(profile: V4CryptoProfile, hostname: String = "relay.example", port: Int = 443,
    serverPort: Int? = nil, lease: UInt8 = 30, nativeResources: Bool = false,
    relayDialsClient: Bool = false, mixedDirectCandidate: Bool = false) throws {
    credentials = try CredentialFixture(profile: profile.rawValue, allowTunnel: true, nativeResources: nativeResources)
    registry = try V4NamespaceRegistry()
    func leg(role: UInt64) -> V4CBORValue {
      NamespaceFixture.map([
        0: .uint(0), 1: .bytes(Data(repeating: UInt8(50 + role), count: 16)), 2: .uint(role),
        3: .uint(role == 0 && relayDialsClient ? 2 : role),
        4: .uint(role == 0 && relayDialsClient ? 0 : 2), 5: .uint(1), 6: .text(hostname),
        7: .uint(UInt64(role == 1 ? (serverPort ?? port) : port)),
        8: .text("/flowersec/v4/tunnel"), 9: .text("http/1.1"), 10: .text("flowersec.tunnel.v4"),
        11: NamespaceFixture.map([0: .uint(0), 1: .bool(true)]),
      ])
    }
    clientLeg = leg(role: 0); serverLeg = leg(role: 1)
    credentials.tunnelLegs = (clientLeg, serverLeg)
    if mixedDirectCandidate { credentials.directCandidateIndices = [0] }
    original = try credentials.input(source: .preauthorizedPool, indices: [0, 1],
      artifact: [6: .bytes(Data(repeating: lease, count: 16))],
      activation: [5: .bytes(Data(repeating: lease, count: 16))], namespaceRole: 7)
    relay = try credentials.certificate(2)
  }
  func namespace(role: UInt64 = 5) -> Data {
    NamespaceFixture.map([
      0: .text("tenant"), 1: .text("authority"), 2: .uint(1),
      3: .bytes(credentials.base.capacityDigest), 4: .uint(role), 5: .uint(9),
      6: .text("credentials"), 7: .uint(1),
    ]).encoded()
  }
  func limits(maximumEnvelope: UInt64 = 1_048_584) -> Data {
    NamespaceFixture.map([
      0: .uint(maximumEnvelope), 1: .uint(8_388_672), 2: .uint(0), 3: .uint(8_388_672),
      4: .uint(2_097_168), 5: .uint(0), 6: .uint(0), 7: .uint(0), 8: .uint(2),
    ]).encoded()
  }
  func scope(roleMask: UInt64 = 5) -> TransportGrantScope {
    .init(tenant: "tenant", authority: "authority", capacityDigest: credentials.base.capacityDigest,
      generation: 1, policyID: "credentials", policyRevision: 1, issuer: Data(repeating: 15, count: 16),
      audience: "relay-service", service: "relay-service", roleMask: roleMask, cohort: 9, issuedMS: 900,
      expiresMS: 1600, parentAuthority: "authority", parentCapacity: credentials.base.capacityDigest,
      parentGeneration: 1, parentIssuer: Data(repeating: 5, count: 16), parentCohort: 9)
  }
  func input(grant: Data? = nil, relay: Data? = nil) throws -> V4CredentialInput {
    V4CredentialInput(artifact: original.artifact, clientCertificate: original.clientCertificate,
      serverCertificate: original.serverCertificate, activation: original.activation, source: .preauthorizedPool,
      candidateIndex: 0, grant: try grant ?? self.grant(), relayCertificate: relay ?? self.relay)
  }
  func liveAuthorityResponse(_ request: Data) throws -> Data {
    var reader = V4PoolWireCursor(request, maximum: 1024)
    try reader.array(13)
    guard try reader.text(maximum: 32) == "live-authorization-1", try reader.text(maximum: 128) == "tenant",
      try reader.text(maximum: 128) == "service", try reader.text(maximum: 128) == credentials.profile,
      try reader.bytes(maximum: 16) == Data(repeating: 5, count: 16),
      try reader.bytes(maximum: 16) == V4NamespaceDocument(original.artifact, schema: "Artifact", bytes: 65_536,
        nodes: 4096, registry: registry).root.b("lease_id") else { throw TransportControlError.responseInvalid }
    let attempt = try reader.bytes(maximum: 16)
    guard attempt.count == 16, attempt.contains(where: { $0 != 0 }),
      try reader.bytes(maximum: 32) == NamespaceFixture.digest("artifact-digest", original.artifact),
      try reader.bytes(maximum: 32) == NamespaceFixture.digest("certificate-digest", original.clientCertificate),
      try reader.bytes(maximum: 32) == NamespaceFixture.digest("certificate-digest", original.serverCertificate)
    else { throw TransportControlError.responseInvalid }
    try reader.array(3)
    guard try reader.uint() == 0, try reader.bytes(maximum: 16) == Data(repeating: 40, count: 16),
      try reader.bytes(maximum: 32) == credentials.routeDigest(0), try reader.uint() == 1500,
      try reader.uint() == 1 else { throw TransportControlError.responseInvalid }
    try reader.end()
    let parent = try V4NamespaceDocument(original.artifact, schema: "Artifact", bytes: 65_536, nodes: 4096, registry: registry).root
    let activated = try credentials.input(source: .liveAuthority, artifact: [6: .bytes(parent.b("lease_id"))],
      activation: [5: .bytes(parent.b("lease_id")), 9: .bytes(attempt)], namespaceRole: 7)
    return Data([0x83]) + V4Crypto.text("live-tunnel-material-1")
      + V4Crypto.bytes(activated.activation) + V4Crypto.bytes(try grant(attempt: attempt))
  }
  func grant(attempt: Data? = nil, candidateIndex: Int = 0, overrides: [UInt64: Data] = [:], signer: UInt8 = 15) throws -> Data {
    let parent = try V4NamespaceDocument(original.artifact, schema: "Artifact", bytes: 65_536, nodes: 4096, registry: registry).root
    let candidate = try parent.field("candidates").children.map { $0 }[candidateIndex]
    let route = try V4CredentialVerifier.routeDocument(candidate, registry: registry)
    let relayCertificate = try V4NamespaceDocument(relay, schema: "IdentityCertificate", bytes: 8192, nodes: 4096, registry: registry).root
    let projection: [(UInt64, String)] = [
      (0, "tenant_id"), (1, "revocation_authority_id"), (2, "revocation_authority_generation"),
      (3, "namespace_capacity_digest"), (4, "revocation_policy_id"), (5, "revocation_policy_revision"),
      (6, "issuer_key_id"), (7, "lease_id"), (8, "revocation_epoch"), (9, "issued_at_ms"),
      (10, "initiation_not_after_ms"), (11, "session_not_after_ms"),
    ]
    var parentRef = try projection.map { ($0.0, Data(try parent.field($0.1).raw)) }
    parentRef.append((12, V4Crypto.bytes(try parent.digest("artifact_digest"))))
    let identities = Data([0x82]) + V4Crypto.bytes(try parent.b("client_identity_digest"))
      + V4Crypto.bytes(try parent.b("server_identity_digest"))
    let legs = Data([0x82]) + NamespaceFixture.map([0: .bytes(Data(repeating: 50, count: 16)), 1: .uint(0)]).encoded()
      + NamespaceFixture.map([0: .bytes(Data(repeating: 51, count: 16)), 1: .uint(1)]).encoded()
    var fields: [UInt64: Data] = [
      0: V4Crypto.text("tenant"), 1: V4Crypto.bytes(Data(repeating: UInt8(65 + candidateIndex), count: 16)),
      2: V4Crypto.bytes(Data(repeating: UInt8(66 + candidateIndex), count: 32)), 3: V4Crypto.map(parentRef),
      4: Data(route.raw), 5: V4Crypto.bytes(try route.digest("route_digest")),
      6: V4Crypto.bytes(attempt ?? Data(repeating: 33, count: 16)), 7: V4Crypto.bytes(Data(repeating: 67, count: 16)),
      8: identities, 9: legs, 10: V4Crypto.text("relay-service"), 11: V4Crypto.text("relay-service"),
      12: V4Crypto.bytes(Data(repeating: 15, count: 16)), 13: namespace(), 14: V4NamespaceValue.head(0, 900),
      15: V4NamespaceValue.head(0, 1600), 16: limits(),
      17: V4Crypto.bytes(try parent.field("session_contract").digest("session_contract_digest")),
      18: V4Crypto.bytes(try relayCertificate.digest("certificate_digest")),
    ]
    fields.merge(overrides) { _, new in new }
    let unsigned = V4Crypto.map(fields.sorted(by: { $0.key < $1.key }).map { ($0.key, $0.value) })
    let signature = try NamespaceFixture.sign(V4Crypto.domain("grant/signature", [unsigned]), seed: signer)
    fields[19] = V4Crypto.bytes(signature)
    return V4Crypto.map(fields.sorted(by: { $0.key < $1.key }).map { ($0.key, $0.value) })
  }
}
private final class V4TunnelLiveRelayTestControl: @unchecked Sendable {
  private let gate = NSLock()
  private let fixture: V4TunnelCredentialFixture
  private let peer: V4TunnelHopTestPeer
  private var originalRequest: Data?
  private var activated = false
  init(fixture: V4TunnelCredentialFixture, peer: V4TunnelHopTestPeer) {
    self.fixture = fixture; self.peer = peer
  }
  func respond(path: String, body: Data) throws -> Data {
    try gate.withLock {
      guard peer.carrierAttached else { throw V4CryptoFailure.phase }
      if path == "/tunnel/relay-prepare" {
        guard originalRequest == nil, !activated, peer.frameTypes.isEmpty else { throw V4CryptoFailure.phase }
        _ = try fixture.liveAuthorityResponse(body)
        originalRequest = body
      } else if path == "/tunnel/relay-activate-client" {
        guard let originalRequest, !activated else { throw V4CryptoFailure.phase }
        var reader = V4PoolWireCursor(body, maximum: 73_728)
        try reader.array(4)
        guard try reader.text(maximum: 32) == "tunnel-relay-activate-client-1",
          try reader.bytes(maximum: 1024) == originalRequest else { throw V4CryptoFailure.authentication }
        let original = try V4LiveTunnelMaterial.decode(fixture.liveAuthorityResponse(originalRequest))
        guard try reader.bytes(maximum: 4096) == original.activation,
          try reader.bytes(maximum: 9302) == original.grant else { throw V4CryptoFailure.authentication }
        try reader.end(); activated = true
      } else { throw TransportControlError.responseInvalid }
      return Data([0xf5])
    }
  }
}

private final class V4TunnelHopTestPeer: ChannelInboundHandler, @unchecked Sendable {
  typealias InboundIn = WebSocketFrame
  typealias OutboundOut = WebSocketFrame
  private let gate = NSRecursiveLock()
  private let validRelayProof: Bool
  private var channel: (any Channel)?
  private var grant = Data()
  private var relay = Data()
  private var possessionPrefix = Data()
  private var endpointKey = Data()
  private var types: [UInt8] = []
  private var verified = false
  private var error: String?
  var carrierAttached: Bool { gate.withLock { channel != nil } }
  var endpointPossessionVerified: Bool { gate.withLock { verified } }
  var frameTypes: [UInt8] { gate.withLock { types } }
  var failure: String? { gate.withLock { error } }
  init(validRelayProof: Bool) { self.validRelayProof = validRelayProof }
  func configure(grant: Data, relay: Data) { gate.withLock { self.grant = grant; self.relay = relay } }
  func attach(_ channel: any Channel) { gate.withLock { self.channel = channel } }
  private func send(_ body: Data) throws {
    guard let channel else { throw SessionError.closed }
    let wire = V4Crypto.integer(UInt64(body.count), width: 4) + Data([16, 0, 0, 0]) + body
    var buffer = channel.allocator.buffer(capacity: wire.count); buffer.writeBytes(wire)
    channel.writeAndFlush(wrapOutboundOut(WebSocketFrame(fin: true, opcode: .binary, data: buffer)), promise: nil)
  }
  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    do { try gate.withLock {
      let frame = unwrapInboundIn(data)
      let wire = Data(frame.unmaskedData.readableBytesView)
      guard frame.opcode == .binary, frame.fin, wire.count > 8,
        V4Crypto.number(wire.prefix(4)) == wire.count - 8, wire[4] == 16,
        wire[5..<8] == Data([0, 0, 0]), types.count < 2 else { throw V4CryptoFailure.authentication }
      types.append(wire[4])
      let registry = try V4NamespaceRegistry()
      if types.count == 1 {
        let hello = try V4NamespaceDocument(Data(wire.dropFirst(8)), schema: "HOP_AUTH_HELLO",
          bytes: 10_346, nodes: 4096, registry: registry, context: ["hop_sender_role": "endpoint"]).root
        guard try hello.b("grant") == grant else { throw V4CryptoFailure.authentication }
        let local = try V4NamespaceDocument(hello.b("identity_certificate"), schema: "IdentityCertificate",
          bytes: 8192, nodes: 4096, registry: registry).root
        guard try local.u("role") == 0 else { throw V4CryptoFailure.authentication }
        endpointKey = try local.b("ed25519_public_key")
        let signed = try V4NamespaceDocument(grant, schema: "Grant", bytes: 9302, nodes: 4096, registry: registry).root
        let leg = try signed.field("route_descriptor").field("client_leg")
        let listenerIncarnation = Data(repeating: 70, count: 16)
        let listenerChallenge = Data(repeating: 71, count: 32)
        let hopContext = V4Crypto.map([
          (0, V4Crypto.bytes(try hello.b("local_incarnation"))), (1, V4Crypto.bytes(listenerIncarnation)),
          (2, V4Crypto.bytes(try leg.b("leg_id"))), (3, V4NamespaceValue.head(0, 0)),
          (4, V4NamespaceValue.head(0, 2)), (5, V4Crypto.bytes(try hello.b("local_challenge"))),
          (6, V4Crypto.bytes(listenerChallenge)),
        ])
        let (domain, _) = try registry.compoundDomain("grant_possession", operation: "ed25519")
        possessionPrefix = domain + V4Crypto.lp(try signed.digest("grant_digest"))
          + V4Crypto.lp(try signed.b("route_digest")) + V4Crypto.lp(try leg.b("leg_id"))
          + V4Crypto.lp(try signed.b("pairing_id")) + V4Crypto.lp(hopContext)
        try send(V4Crypto.map([(0, V4NamespaceValue.head(0, 0)), (1, V4Crypto.bytes(listenerIncarnation)),
          (2, V4Crypto.bytes(listenerChallenge)), (4, V4Crypto.bytes(relay))]))
      } else {
        let proof = try V4NamespaceDocument(Data(wire.dropFirst(8)), schema: "HOP_AUTH_ENDPOINT_PROOF",
          bytes: 70, nodes: 8, registry: registry).root
        guard StrictEd25519V4Reference.verify(signature: try proof.b("proof"),
          message: possessionPrefix + Data([0]), publicKey: endpointKey) else { throw V4CryptoFailure.authentication }
        verified = true
        let response = validRelayProof
          ? try NamespaceFixture.sign(possessionPrefix + Data([2]), seed: 23) : Data(repeating: 0, count: 64)
        try send(V4Crypto.map([(0, V4NamespaceValue.head(0, 2)), (1, V4Crypto.bytes(response))]))
      }
    } } catch {
      gate.withLock { self.error = String(describing: error) }
      context.close(promise: nil)
    }
  }
}

#endif
