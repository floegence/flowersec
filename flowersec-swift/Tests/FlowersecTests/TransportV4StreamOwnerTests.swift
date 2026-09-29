import Foundation
import XCTest

@testable import Flowersec

@MainActor
final class TransportV4StreamOwnerTests: XCTestCase {
  func bytes(_ result: V4StreamRead) throws -> Data {
    guard case .data(let buffer) = result else {
      XCTFail("expected data")
      return Data()
    }
    defer { buffer.close() }
    return try buffer.withBytes { $0 }
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
      fixture.credentials.base.source.advance(51)
      XCTAssertTrue(try client.poll(to: c))
      try server.receive(c.last())
      XCTAssertTrue(try server.poll(to: s))
      try client.receive(s.last())
      XCTAssertEqual(try client.phase(local), .stable)
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
      XCTAssertThrowsError(try server.receive(wire, on: mode == 2 ? remote : nil))
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
    _ = try client.materializeBootstrap(to: c)
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
