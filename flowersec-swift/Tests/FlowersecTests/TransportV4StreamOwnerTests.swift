import Foundation
import XCTest

@testable import Flowersec

@MainActor
final class TransportStreamOwnerTests: XCTestCase {
  func bytes(_ result: V4StreamRead) throws -> Data {
    guard case .data(let buffer) = result else {
      XCTFail("expected data")
      return Data()
    }
    defer { buffer.close() }
    return try buffer.withBytes { $0 }
  }
  func testPendingPongKeepsFirstNonceAndDiscardsFurtherAuthenticatedPingsForBothProfiles() throws {
    for profile in V4CryptoProfile.allCases {
      let fixture = try CryptoOwnerFixture(profile)
      let (raw, b) = try fixture.establish()
      let server = try b.makeSession()
      defer { raw.close(); server.close() }
      let c = CryptoTestPublisher(), s = CryptoTestPublisher()
      let first = Data(repeating: 1, count: 16)
      let repeated = Data(repeating: 2, count: 16)
      func ping(_ nonce: Data) throws {
        try raw.publish(scope: raw.maintenance, frameType: 14,
          plaintext: V4Crypto.map([(0, V4Crypto.bytes(nonce))]), to: c)
        XCTAssertEqual(try server.receive(c.last()), .committed)
      }
      func pong(_ nonce: Data) throws {
        XCTAssertTrue(try server.poll(to: s))
        let record = try raw.receive(scope: raw.maintenance, wire: s.last())
        defer { record.close() }
        XCTAssertEqual(record.frameType, 15)
        XCTAssertEqual(try record.withBytes { $0 }, V4Crypto.map([(0, V4Crypto.bytes(nonce))]))
      }

      try ping(first)
      XCTAssertFalse(try server.canReceive(), "The only pending PONG position is occupied")
      // Each repeated nonce has a new authenticated record sequence. Overflow
      // consumes input without replacing the original reply or closing Session.
      try ping(repeated)
      try ping(repeated)
      XCTAssertEqual(b.cryptoTestFrontier(0, sending: false), 3)
      try pong(first)
      XCTAssertTrue(try server.canReceive())
      XCTAssertFalse(try server.poll(to: s), "Overflow PINGs must not create additional PONG work")

      try ping(repeated)
      try pong(repeated)
      XCTAssertFalse(try server.poll(to: s))
    }
  }

  func testPendingPongDoesNotMaskInvalidPingScopeForBothProfiles() throws {
    for profile in V4CryptoProfile.allCases {
      let fixture = try CryptoOwnerFixture(profile)
      let (raw, b) = try fixture.establish()
      let server = try b.makeSession()
      defer { raw.close(); server.close() }
      let c = CryptoTestPublisher()
      let body = V4Crypto.map([(0, V4Crypto.bytes(Data(repeating: 3, count: 16)))])
      try raw.publish(scope: raw.maintenance, frameType: 14, plaintext: body, to: c)
      XCTAssertEqual(try server.receive(c.last()), .committed)
      XCTAssertFalse(try server.canReceive())
      try raw.publish(scope: raw.maintenance, frameType: 14, plaintext: body, to: c)
      var wire = try c.last()
      wire.replaceSubrange(12..<20, with: V4Crypto.integer(3, width: 8))
      XCTAssertThrowsError(try server.receive(wire)) {
        XCTAssertEqual($0 as? V4CryptoFailure, .authentication,
          "A wrong scope must fail authentication even while the PONG position is occupied")
      }
      XCTAssertThrowsError(try server.epoch(), "Invalid maintenance scope must close the Session")
    }
  }

  func testStreamAcceptanceSurvivesAuthorizationFailureAfterProviderHandoff() throws {
    let fixture = try CryptoOwnerFixture(.x25519)
    let (a, b) = try fixture.establish()
    let client = try a.makeSession(), server = try b.makeSession()
    let c = CryptoTestPublisher(), s = CryptoTestPublisher()
    let local = try client.open(kind: "example.echo", receiveWindow: 8, to: c)
    try server.receive(c.last())
    let remote = try XCTUnwrap(server.pendingOpen())
    try server.decideOpen(remote, decision: .accept(receiveWindow: 8), to: s)
    try client.receive(s.last())
    let accepted = V4StreamAcceptedTestSnapshot()
    c.onWrite = { fixture.credentials.base.environment.beginClose() }
    XCTAssertThrowsError(try client.write(
      local, data: Data([1, 2, 3]), to: c, accepted: { accepted.record($0) }))
    // This is a local provider handoff, even though the post-handoff security
    // check ended the Session before write could return its ordinary count.
    XCTAssertEqual(accepted.count, 3)
  }

  func testActualReadyToOpenCreditDataFinAndRetirementForBothProfiles() throws {
    for profile in V4CryptoProfile.allCases {
      let fixture = try CryptoOwnerFixture(profile)
      let (a, b) = try fixture.establish()
      let client = try a.makeSession()
      let server = try b.makeSession()
      let c = CryptoTestPublisher()
      let s = CryptoTestPublisher()
      let local = try client.open(kind: "example.echo", receiveWindow: 8, to: c)
      XCTAssertEqual(local.number, 1)
      XCTAssertThrowsError(try client.write(local, data: Data([1]), to: c))
      try server.receive(c.last())
      let remote = try XCTUnwrap(server.pendingOpen())
      let metadata = try server.pendingMetadata(remote)
      XCTAssertEqual(metadata.kind, "example.echo")
      XCTAssertEqual(try metadata.metadata.withBytes { $0 }, Data())
      metadata.metadata.close()
      try server.decideOpen(remote, decision: .accept(receiveWindow: 4), to: s)
      let accepted = try s.last()
      try server.write(remote, data: Data([6, 7]), to: s)
      try client.receive(s.last(), on: local)
      if case .pending = try client.read(local, maximum: 8) {} else { XCTFail("outcome required") }
      try client.receive(accepted)
      XCTAssertEqual(try bytes(client.read(local, maximum: 8)), Data([6, 7]))
      try client.write(local, data: Data([1, 2, 3, 4]), to: c)
      try server.receive(c.last(), on: remote)
      XCTAssertEqual(try bytes(server.read(remote, maximum: 2)), Data([1, 2]))
      try server.grant(remote, receiveLimit: 6)
      XCTAssertThrowsError(try client.write(local, data: Data([5]), to: c))
      XCTAssertTrue(try server.poll(to: s))
      try client.receive(s.last())
      try client.write(local, data: Data([5, 6]), fin: true, to: c)
      try server.receive(c.last(), on: remote)
      XCTAssertEqual(try bytes(server.read(remote, maximum: 8)), Data([3, 4, 5, 6]))
      if case .pending = try server.read(remote, maximum: 8) {
      } else {
        XCTFail("drain publication required")
      }
      XCTAssertTrue(try server.poll(to: s))
      try client.receive(s.last())
      if case .eof = try server.read(remote, maximum: 8) {} else { XCTFail("FIN must end in EOF") }
      try server.write(remote, data: Data(), fin: true, to: s)
      try client.receive(s.last(), on: local)
      XCTAssertTrue(try client.poll(to: c))
      try server.receive(c.last())
      XCTAssertEqual(try client.phase(local), .recent)
      XCTAssertEqual(try server.phase(remote), .recent)
      try client.reset(local)
      XCTAssertThrowsError(try server.reset(local), "Another Session cannot close the original Stream")
      fixture.credentials.base.source.advance(51)
      XCTAssertTrue(try client.poll(to: c))
      try server.receive(c.last())
      XCTAssertTrue(try server.poll(to: s))
      try client.receive(s.last())
      XCTAssertEqual(try client.phase(local), .stable)
      try client.reset(local)
      try client.reset(local)
      XCTAssertTrue(try client.sendFinished(local))
      if case .eof = try client.read(local, maximum: 8) {
      } else {
        XCTFail("retired FIN must retain EOF")
      }
      XCTAssertThrowsError(try client.write(local, data: Data([9]), to: c))
    }
  }

  func testRejectedStreamsUseCumulativeOrdinalsAndReleaseBoundedSlots() throws {
    let fixture = try CryptoOwnerFixture(.x25519)
    let (a, b) = try fixture.establish()
    let client = try a.makeSession()
    let server = try b.makeSession()
    let c = CryptoTestPublisher()
    let s = CryptoTestPublisher()
    var local = try client.open(kind: "example.echo", receiveWindow: 32, to: c)
    try server.receive(c.last())
    for iteration in 0..<40 {
      let remote = try XCTUnwrap(server.pendingOpen())
      try server.decideOpen(remote, decision: .reject(.application), to: s)
      try client.receive(s.last())
      if case .aborted = try client.read(local, maximum: 1) {
      } else {
        XCTFail("reject cannot be EOF")
      }
      let old = local
      local = try client.open(kind: "example.echo", receiveWindow: 32, to: c)
      let nextOpen = try c.last()
      XCTAssertEqual(local.number, UInt64(iteration * 2 + 3))
      XCTAssertTrue(try client.poll(to: c))
      try server.receive(c.last())
      XCTAssertTrue(try server.poll(to: s))
      try client.receive(s.last())
      XCTAssertEqual(try client.phase(old), .stable)
      try server.receive(nextOpen)
    }
  }

  func testCanceledPingIgnoresAuthenticatedLateResponseAndAllowsNextProbe() throws {
    let fixture = try CryptoOwnerFixture(.p256)
    let (a, b) = try fixture.establish()
    let client = try a.makeSession()
    let server = try b.makeSession()
    let c = CryptoTestPublisher()
    let s = CryptoTestPublisher()
    let probe = try client.beginProbe()
    try client.submitProbe(probe, to: c)
    try server.receive(c.last())
    XCTAssertFalse(try server.canReceive())
    XCTAssertTrue(try server.poll(to: s))
    XCTAssertTrue(try server.canReceive())
    let late = try s.last()
    client.releaseProbe(probe)
    let nextProbe = try client.beginProbe()
    defer { client.releaseProbe(nextProbe) }
    try client.submitProbe(nextProbe, to: c)
    try client.receive(late)
    XCTAssertNil(try client.probeResult(nextProbe))
    try server.receive(c.last())
    XCTAssertTrue(try server.poll(to: s))
    try client.receive(s.last())
    XCTAssertNotNil(try client.probeResult(nextProbe))
  }

  func testAuthenticatedStreamErrorDoesNotCloseUnrelatedStreamsAndGoAwayCannotRetract() throws {
    let fixture = try CryptoOwnerFixture(.x25519)
    let (raw, b) = try fixture.establish()
    let server = try b.makeSession()
    let c = CryptoTestPublisher()
    let s = CryptoTestPublisher()
    _ = try rawOpen(raw, publisher: c)
    try server.receive(c.last())
    let remote = try XCTUnwrap(server.pendingOpen())
    try server.decideOpen(remote, decision: .accept(receiveWindow: 8), to: s)
    try raw.publish(
      scope: raw.maintenance, frameType: 11,
      plaintext: V4Crypto.map([
        (0, V4NamespaceValue.head(0, 10)), (1, V4NamespaceValue.head(0, 1)),
        (2, V4NamespaceValue.head(0, 1)),
      ]), to: c)
    try server.receive(c.last())
    XCTAssertEqual(try server.streamError(remote), .streamReset)
    XCTAssertEqual(try server.epoch(), 0)
    let goaway = V4Crypto.map([(0, V4NamespaceValue.head(0, 2)), (1, V4NamespaceValue.head(0, 0))])
    try raw.publish(scope: raw.maintenance, frameType: 13, plaintext: goaway, to: c)
    try server.receive(c.last())
    try raw.publish(scope: raw.maintenance, frameType: 13, plaintext: goaway, to: c)
    try server.receive(c.last())
    try raw.publish(
      scope: raw.maintenance, frameType: 13,
      plaintext: V4Crypto.map([(0, V4NamespaceValue.head(0, 0)), (1, V4NamespaceValue.head(0, 0))]),
      to: c)
    XCTAssertThrowsError(try server.receive(c.last()))
  }

  func testSessionHandoffRevokesRawRecordAliasesAndCannotBeClaimedTwice() throws {
    let fixture = try CryptoOwnerFixture(.p256)
    let (raw, _) = try fixture.establish()
    let session = try raw.makeSession()
    XCTAssertThrowsError(try raw.makeSession())
    XCTAssertThrowsError(try raw.admitReliableScope(1))
    XCTAssertThrowsError(
      try raw.publish(
        scope: raw.maintenance, frameType: 9,
        plaintext: Data(), to: CryptoTestPublisher()))
    let out = CryptoTestPublisher()
    _ = try session.open(kind: "example.echo", receiveWindow: 8, to: out)
  }

  func testStopProofsPreserveAbortAndDoNotDestroyUnreadFin() throws {
    let fixture = try CryptoOwnerFixture(.x25519)
    let (a, b) = try fixture.establish()
    let client = try a.makeSession()
    let server = try b.makeSession()
    let c = CryptoTestPublisher()
    let s = CryptoTestPublisher()
    let local = try client.open(kind: "example.echo", receiveWindow: 8, to: c)
    try server.receive(c.last())
    let remote = try XCTUnwrap(server.pendingOpen())
    try server.decideOpen(remote, decision: .accept(receiveWindow: 8), to: s)
    try client.receive(s.last())
    try client.write(local, data: Data([1, 2]), fin: true, to: c)
    try server.receive(c.last(), on: remote)
    // A completed send direction is not reset again when the reverse direction
    // is abandoned. Its unread, authenticated FIN bytes retain their owner.
    XCTAssertTrue(try server.poll(to: s))
    try client.receive(s.last())
    XCTAssertTrue(try client.sendFinished(local))
    try client.reset(local)
    for _ in 0..<12 {
      if try client.poll(to: c) { try server.receive(c.last()) }
      if try server.poll(to: s) { try client.receive(s.last()) }
    }
    XCTAssertEqual(try bytes(server.read(remote, maximum: 8)), Data([1, 2]))
    if case .eof = try server.read(remote, maximum: 8) {} else { XCTFail("unread FIN was lost") }
    if case .aborted = try client.read(local, maximum: 8) {} else { XCTFail("reset became EOF") }
  }

  func testCloseWriteSealsBeforePublicationAndOriginalSchedulerFinishesIt() throws {
    let fixture = try CryptoOwnerFixture(.x25519)
    let (a, b) = try fixture.establish()
    let client = try a.makeSession()
    let server = try b.makeSession()
    let c = CryptoTestPublisher()
    let s = CryptoTestPublisher()
    let local = try client.open(kind: "example.half", receiveWindow: 8, to: c)
    try server.receive(c.last())
    let remote = try XCTUnwrap(server.pendingOpen())
    try server.decideOpen(remote, decision: .accept(receiveWindow: 8), to: s)
    try client.receive(s.last())
    try client.write(local, data: Data([1, 2]), to: c)
    try server.receive(c.last(), on: remote)
    try client.requestCloseWrite(local)
    try client.requestCloseWrite(local)
    XCTAssertThrowsError(try client.writeCapacity(local))
    XCTAssertFalse(try client.finSubmitted(local))
    XCTAssertTrue(try client.poll(to: c))
    XCTAssertTrue(try client.finSubmitted(local))
    try server.receive(c.last(), on: remote)
    XCTAssertTrue(try server.poll(to: s))
    try client.receive(s.last())
    XCTAssertTrue(try client.sendFinished(local))
    XCTAssertEqual(try bytes(server.read(remote, maximum: 8)), Data([1, 2]))
  }

  func testFailedPublisherClosesSessionAndBufferedDelivery() throws {
    let fixture = try CryptoOwnerFixture(.x25519)
    let (a, b) = try fixture.establish()
    let client = try a.makeSession()
    let server = try b.makeSession()
    let c = CryptoTestPublisher()
    let s = CryptoTestPublisher()
    let local = try client.open(kind: "example.echo", receiveWindow: 8, to: c)
    try server.receive(c.last())
    let remote = try XCTUnwrap(server.pendingOpen())
    try server.decideOpen(remote, decision: .accept(receiveWindow: 8), to: s)
    try client.receive(s.last())
    try client.write(local, data: Data([1]), to: c)
    try server.receive(c.last(), on: remote)
    let data = try server.read(remote, maximum: 1)
    try server.grant(remote, receiveLimit: 9)
    s.failure = true
    XCTAssertThrowsError(try server.poll(to: s))
    guard case .data(let buffer) = data else { return XCTFail("missing data") }
    XCTAssertThrowsError(try buffer.withBytes { $0 })
    XCTAssertThrowsError(try server.phase(remote))
  }

  func rawOpen(_ raw: V4ReliableChannel, publisher: CryptoTestPublisher) throws -> V4RecordScope {
    let scope = try raw.admitReliableScope(1)
    var fields: [(UInt64, Data)] = [
      (0, V4NamespaceValue.head(0, 1)),
      (1, V4NamespaceValue.head(0, 0)), (2, V4NamespaceValue.head(0, 1)),
      (3, V4NamespaceValue.head(0, 0)), (4, V4NamespaceValue.head(0, 0)),
      (5, V4Crypto.text("example.echo")), (6, V4Crypto.bytes(Data())),
      (7, V4NamespaceValue.head(0, 8)),
    ]
    fields.append(
      (8, V4Crypto.bytes(V4Crypto.hash(V4Crypto.domain("open", [V4Crypto.map(fields)])))))
    try raw.publish(scope: scope, frameType: 7, plaintext: V4Crypto.map(fields), to: publisher)
    return scope
  }
  func testAuthenticatedMalformedDataIsolatesWhileUnboundBadTagCloses() throws {
    for mode in 0..<3 {
      let fixture = try CryptoOwnerFixture(.x25519)
      let (raw, b) = try fixture.establish()
      let server = try b.makeSession()
      let c = CryptoTestPublisher()
      let s = CryptoTestPublisher()
      let scope = try rawOpen(raw, publisher: c)
      try server.receive(c.last())
      let remote = try XCTUnwrap(server.pendingOpen())
      try server.decideOpen(remote, decision: .accept(receiveWindow: 8), to: s)
      try raw.publish(scope: scope, frameType: 8, plaintext: Data([0xa0]), to: c)
      var wire = try c.last()
      if mode != 0 { wire[wire.count - 1] ^= 1 }
      let originalFrontier = b.cryptoTestFrontier(scope.number, sending: false)
      if mode == 1 { XCTAssertThrowsError(try server.receive(wire)) }
      else { XCTAssertEqual(try server.receive(wire, on: mode == 2 ? remote : nil), .isolatedStream) }
      XCTAssertEqual(b.cryptoTestFrontier(scope.number, sending: false), originalFrontier,
        "failed AEAD/schema/state validation must not advance the reliable authentication frontier")
      if mode == 1 {
        XCTAssertThrowsError(try server.phase(remote))
      } else {
        XCTAssertEqual(try server.phase(remote), .accepted)
        if case .aborted = try server.read(remote, maximum: 1) {
        } else {
          XCTFail("isolation must abort")
        }
        XCTAssertTrue(try server.poll(to: s))
        // Quarantine can drop input only through the original bound handle.
        try server.receive(wire, on: remote)
      }
    }
  }

  func testSharedDiscardProofAndCountersSurviveRetirementAndRekeyForBothProfiles() throws {
    for profile in V4CryptoProfile.allCases {
      let fixture = try CryptoOwnerFixture(profile)
      let (a, b) = try fixture.establish()
      let client = try a.makeSession(), server = try b.makeSession()
      defer { client.close(); server.close() }
      let c = CryptoTestPublisher(), s = CryptoTestPublisher()
      func settle() throws {
        for _ in 0..<32 {
          var progress = false
          if try client.poll(to: c) { try server.receive(c.last()); progress = true }
          if try server.poll(to: s) { try client.receive(s.last()); progress = true }
          if !progress { return }
        }
        XCTFail("bounded maintenance failed to settle")
      }
      let local = try client.open(kind: "example.retire", receiveWindow: 8, to: c)
      try server.receive(c.last())
      let remote = try XCTUnwrap(server.pendingOpen())
      try server.decideOpen(remote, decision: .accept(receiveWindow: 8), to: s)
      try client.receive(s.last())
      try client.write(local, data: Data(), fin: true, to: c)
      let late = try c.last()
      try server.receive(late)
      let terminal = server.cryptoTestSharedInput(local.number)
      XCTAssertFalse(terminal.receiveEnabled)
      // FIN itself proves terminal input before DRAINED is published.
      XCTAssertEqual(try server.receive(late), .discardedData)
      XCTAssertEqual(server.cryptoTestSharedInput(local.number).scopeUsage, terminal.scopeUsage)
      try server.write(remote, data: Data(), fin: true, to: s)
      try client.receive(s.last())
      try settle()
      fixture.credentials.base.source.advance(51)
      try settle()
      XCTAssertEqual(try server.phase(remote), .stable)
      XCTAssertNil(server.cryptoTestSharedInput(local.number).current)
      XCTAssertEqual(try server.receive(late), .discardedData)
      XCTAssertTrue(try client.requestRekey(to: c))
      try server.receive(c.last())
      try settle()
      XCTAssertEqual(try server.epoch(), 1)
      XCTAssertEqual(try server.receive(late), .discardedData)
      XCTAssertEqual(server.cryptoTestSharedInput(local.number).records, 3)
      XCTAssertEqual(server.cryptoTestSharedInput(local.number).bytes, UInt64(late.count * 3))
      for _ in 3..<16 { XCTAssertEqual(try server.receive(late), .discardedData) }
      XCTAssertThrowsError(try server.receive(late))
      XCTAssertThrowsError(try server.epoch())
    }
  }

  func testRetainedSharedTerminalRejectsEpochBeforeAuthenticatedOpen() throws {
    let fixture = try CryptoOwnerFixture(.x25519)
    let (a, b) = try fixture.establish()
    let client = try a.makeSession(), server = try b.makeSession()
    defer { client.close(); server.close() }
    let c = CryptoTestPublisher(), s = CryptoTestPublisher()
    XCTAssertTrue(try client.requestRekey(to: c))
    try server.receive(c.last())
    for _ in 0..<8 {
      if try server.poll(to: s) { try client.receive(s.last()) }
      if try client.poll(to: c) { try server.receive(c.last()) }
    }
    XCTAssertEqual(try server.epoch(), 1)
    let local = try client.open(kind: "example.epoch", receiveWindow: 8, to: c)
    try server.receive(c.last())
    let remote = try XCTUnwrap(server.pendingOpen())
    try server.decideOpen(remote, decision: .accept(receiveWindow: 8), to: s)
    try client.receive(s.last())
    try client.write(local, data: Data(), fin: true, to: c)
    var wire = try c.last()
    try server.receive(wire)
    wire.replaceSubrange(8..<12, with: V4Crypto.integer(0, width: 4))
    XCTAssertThrowsError(try server.receive(wire))
    XCTAssertThrowsError(try server.epoch())
  }

  func testReservedKindsCapacityAndRevocationRemainOwnerChecked() throws {
    let fixture = try CryptoOwnerFixture(.x25519)
    let (a, _) = try fixture.establish()
    let client = try a.makeSession()
    let c = CryptoTestPublisher()
    XCTAssertThrowsError(try client.open(kind: "flowersec.rpc.v4", receiveWindow: 1, to: c))
    XCTAssertThrowsError(try client.open(kind: "example.echo", receiveWindow: 16385, to: c))
    let stream = try client.open(kind: "example.echo", receiveWindow: 16384, to: c)
    XCTAssertThrowsError(try client.open(kind: "example.echo", receiveWindow: 1, to: c))
    fixture.credentials.base.source.advance(700)
    XCTAssertThrowsError(try client.phase(stream))
  }

  func testReadyBootstrapIsImplicitAndMaterializedOnlyOnce() throws {
    let contract = NamespaceFixture.map([
      0: .uint(1_048_576), 1: .uint(16), 2: .uint(16384), 3: .uint(0),
      4: NamespaceFixture.map([0: .uint(1), 1: .uint(1000), 2: .uint(1000)]),
      5: .uint(1), 6: .uint(4),
    ])
    let fixture = try CryptoOwnerFixture(.p256, artifact: [13: contract])
    let (a, b) = try fixture.establish()
    let client = try a.makeSession()
    let server = try b.makeSession()
    let c = CryptoTestPublisher()
    let s = CryptoTestPublisher()
    let local = try XCTUnwrap(client.bootstrapStream())
    let remote = try XCTUnwrap(server.bootstrapStream())
    XCTAssertThrowsError(try client.write(local, data: Data([1]), to: c))
    XCTAssertThrowsError(try server.write(remote, data: Data([1]), to: s))
    c.onWrite = { XCTAssertFalse(try client.canOpen(), "Bootstrap publication still owns OPEN preparation") }
    _ = try client.materializeBootstrap(to: c)
    c.onWrite = nil
    XCTAssertTrue(try client.canOpen())
    try server.receive(c.last(), on: remote)
    XCTAssertNil(try server.pendingOpen())
    try server.write(remote, data: Data([1]), to: s)
    try client.receive(s.last(), on: local)
    XCTAssertEqual(try bytes(client.read(local, maximum: 1)), Data([1]))
    XCTAssertThrowsError(try client.materializeBootstrap(to: c))
    let ordinary = try client.open(kind: "example.echo", receiveWindow: 0, to: c)
    XCTAssertEqual(ordinary.number, 3)
  }

  func testProductionStreamDecoderMatchesSharedCorpus() throws {
    let schemas: Set<String> = [
      "OPEN_STREAM", "OPEN_ACCEPT", "STREAM_DATA", "STREAM_ACK_CREDIT",
      "STREAM_ACK_STOP", "STREAM_ACK_STOPPED", "STREAM_ACK_DRAINED", "STREAM_ACK_RETIRE_BATCH",
      "STREAM_ACK_RETIRE_ACK", "terminal_tuple", "StreamMetadata",
      "PING", "PONG", "ERROR", "CLOSE", "GOAWAY",
    ]
    let registry = try V4NamespaceRegistry()
    var count = 0
    for vector in try cryptoCorpus("corpus")["vectors"].array! {
      guard let schema = vector["schema"].text, schemas.contains(schema),
        let hex = vector["hex"].text
      else { continue }
      let limits = vector["limits"].object ?? [:]
      do {
        _ = try V4NamespaceDocument(
          cryptoHex(hex), schema: schema, bytes: 1_048_576,
          nodes: 32768, registry: registry, limits: limits.compactMapValues(\.uint),
          context: limits.compactMapValues(\.text))
        XCTAssertNil(vector["expected_error"].text, vector["id"].text!)
      } catch { XCTAssertNotNil(vector["expected_error"].text, "\(vector["id"].text!): \(error)") }
      count += 1
    }
    XCTAssertGreaterThan(count, 20)
  }
}

private final class V4StreamAcceptedTestSnapshot: @unchecked Sendable {
  private let lock = NSLock()
  private var value = 0
  func record(_ count: Int) { lock.withLock { value += count } }
  var count: Int { lock.withLock { value } }
}
