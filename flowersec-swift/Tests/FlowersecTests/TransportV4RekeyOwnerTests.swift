import Crypto
import Foundation
import XCTest

@testable import Flowersec

@MainActor
final class TransportV4RekeyOwnerTests: XCTestCase {
  func testRetirementPublishesAfterFrozenBarrierWithoutWaitingForRekeyCompletion() throws {
    for profile in V4CryptoProfile.allCases {
      let fixture = try CryptoOwnerFixture(profile)
      let (a, b) = try fixture.establish()
      let client = try a.makeSession()
      let server = try b.makeSession()
      defer { client.close(); server.close() }
      let c = CryptoTestPublisher()
      let s = CryptoTestPublisher()
      let local = try client.open(kind: "example.retirement", receiveWindow: 8, to: c)
      try server.receive(c.last())
      let remote = try XCTUnwrap(server.pendingOpen())
      try server.decideOpen(remote, decision: .accept(receiveWindow: 8), to: s)
      try client.receive(s.last())
      try client.write(local, data: Data(), fin: true, to: c)
      try server.receive(c.last(), on: remote)
      try server.write(remote, data: Data(), fin: true, to: s)
      try client.receive(s.last(), on: local)

      // Freeze while both directions still own their terminal proof. The
      // original INIT and REPLY must precede retirement of that same scope.
      XCTAssertTrue(try client.requestRekey(to: c))
      try server.receive(c.last())
      XCTAssertTrue(try server.poll(to: s))  // DRAINED precedes REPLY.
      try client.receive(s.last())
      XCTAssertTrue(try client.poll(to: c))
      try server.receive(c.last())
      XCTAssertEqual(try client.phase(local), .recent)
      XCTAssertEqual(try server.phase(remote), .recent)
      fixture.credentials.base.source.advance(51)

      // The client is waiting for REPLY but its INIT has been published.
      // Retirement must proceed without advancing the rekey transaction.
      guard try client.poll(to: c) else { return XCTFail("retirement blocked by pending REPLY") }
      try server.receive(c.last())
      XCTAssertTrue(try server.poll(to: s))
      let reply = try s.last()
      XCTAssertEqual(reply[4], 6)  // REKEY publication releases the server fence.
      guard try server.poll(to: s) else { return XCTFail("retirement ACK blocked by pending COMMIT") }
      let retirementACK = try s.last()
      try client.receive(reply)
      try client.receive(retirementACK)
      XCTAssertEqual(try client.phase(local), .stable)
      XCTAssertEqual(try server.phase(remote), .stable)
      XCTAssertEqual(try client.epoch(), 0)
      XCTAssertEqual(try server.epoch(), 0)

      // The original barrier still verifies after logical retirement. Its
      // final markers release the held proof and permit ordinary new streams.
      XCTAssertTrue(try client.poll(to: c))
      try server.receive(c.last())
      XCTAssertTrue(try server.poll(to: s))
      try client.receive(s.last())
      XCTAssertEqual(try client.epoch(), 1)
      XCTAssertEqual(try server.epoch(), 1)
      let next = try client.open(kind: "example.after-retirement", receiveWindow: 8, to: c)
      try server.receive(c.last())
      let accepted = try XCTUnwrap(server.pendingOpen())
      try server.decideOpen(accepted, decision: .accept(receiveWindow: 8), to: s)
      try client.receive(s.last())
      try client.write(next, data: Data([1, 2]), to: c)
      try server.receive(c.last(), on: accepted)
      guard case .data(let value) = try server.read(accepted, maximum: 8) else {
        return XCTFail("new stream lost after retirement and rekey")
      }
      defer { value.close() }
      XCTAssertEqual(try value.withBytes { $0 }, Data([1, 2]))
    }
  }

  func testActualFourPhasesForBothProfilesAndBothRequestRoles() throws {
    for profile in V4CryptoProfile.allCases {
      for serverRequest in [false, true] {
        let fixture = try CryptoOwnerFixture(profile)
        let (a, b) = try fixture.establish()
        let client = try a.makeSession()
        let server = try b.makeSession()
        let c = CryptoTestPublisher()
        let s = CryptoTestPublisher()
        if serverRequest {
          XCTAssertTrue(try server.requestRekey(to: s))
          try client.receive(s.last())
          XCTAssertFalse(try server.requestRekey(to: s))
        }
        XCTAssertTrue(try client.requestRekey(to: c))
        XCTAssertEqual(V4Crypto.number(try c.last()[8..<12]), 0)
        try server.receive(c.last())
        XCTAssertTrue(try server.poll(to: s))
        try client.receive(s.last())
        XCTAssertTrue(try client.poll(to: c))
        XCTAssertEqual(V4Crypto.number(try c.last()[8..<12]), 1)
        XCTAssertEqual(V4Crypto.number(try c.last()[20..<28]), 0)
        try server.receive(c.last())
        XCTAssertEqual(try server.epoch(), 0)
        XCTAssertTrue(try server.poll(to: s))
        XCTAssertEqual(try server.epoch(), 1)
        try client.receive(s.last())
        XCTAssertEqual(try client.epoch(), 1)
        XCTAssertGreaterThan(a.usage().session.seals, a.usage().epoch.seals)
        let stream = try client.open(kind: "example.after-rekey", receiveWindow: 8, to: c)
        try server.receive(c.last())
        let remote = try XCTUnwrap(server.pendingOpen())
        try server.decideOpen(remote, decision: .accept(receiveWindow: 8), to: s)
        try client.receive(s.last())
        try client.write(stream, data: Data([1, 2]), fin: true, to: c)
        try server.receive(c.last(), on: remote)
        guard case .data(let buffer) = try server.read(remote, maximum: 8) else {
          return XCTFail("data missing")
        }
        XCTAssertEqual(try buffer.withBytes { $0 }, Data([1, 2]))
      }
    }
  }

  func testDelayedOpenAndDataMustDrainBeforeReplyAndCandidateDeliveryWaitsForAck() throws {
    let fixture = try CryptoOwnerFixture(.p256)
    let (a, b) = try fixture.establish()
    let client = try a.makeSession()
    let server = try b.makeSession()
    let c = CryptoTestPublisher()
    let s = CryptoTestPublisher()
    let local = try client.open(kind: "example.echo", receiveWindow: 8, to: c)
    let opening = try c.last()
    XCTAssertTrue(try client.requestRekey(to: c))
    try server.receive(c.last())
    XCTAssertFalse(try server.poll(to: s))
    try server.receive(opening)
    let remote = try XCTUnwrap(server.pendingOpen())
    try server.decideOpen(remote, decision: .accept(receiveWindow: 8), to: s)
    try client.receive(s.last())
    XCTAssertThrowsError(try client.write(local, data: Data([1]), to: c))
    XCTAssertTrue(try server.poll(to: s))
    try client.receive(s.last())
    XCTAssertTrue(try client.poll(to: c))
    try server.receive(c.last())
    XCTAssertTrue(try server.poll(to: s))
    let ack = try s.last()
    try server.write(remote, data: Data([7, 8]), to: s)
    try client.receive(s.last(), on: local)
    if case .pending = try client.read(local, maximum: 8) {
    } else {
      XCTFail("candidate epoch delivered before ACK")
    }
    try client.receive(ack)
    guard case .data(let buffer) = try client.read(local, maximum: 8) else {
      return XCTFail("data missing")
    }
    XCTAssertEqual(try buffer.withBytes { $0 }, Data([7, 8]))
    try client.write(local, data: Data([1]), to: c)
    try server.receive(c.last(), on: remote)
  }

  func testCandidateOpenWaitsForActualAckBeforeExposureAndAcceptance() throws {
    for profile in V4CryptoProfile.allCases {
      let fixture = try CryptoOwnerFixture(profile)
      let (a, b) = try fixture.establish()
      let client = try a.makeSession()
      let server = try b.makeSession()
      let c = CryptoTestPublisher()
      let s = CryptoTestPublisher()
      XCTAssertTrue(try client.requestRekey(to: c))
      try server.receive(c.last())
      XCTAssertTrue(try server.poll(to: s))
      try client.receive(s.last())
      XCTAssertTrue(try client.poll(to: c))
      try server.receive(c.last())
      XCTAssertTrue(try server.poll(to: s))
      let ack = try s.last()
      let local = try server.open(kind: "example.early", receiveWindow: 8, to: s)
      try client.receive(s.last())
      XCTAssertNil(try client.pendingOpen())
      XCTAssertFalse(try client.poll(to: c))
      try client.receive(ack)
      let remote = try XCTUnwrap(client.pendingOpen())
      let metadata = try client.pendingMetadata(remote)
      XCTAssertEqual(metadata.kind, "example.early")
      metadata.metadata.close()
      try client.decideOpen(remote, decision: .accept(receiveWindow: 8), to: c)
      try server.receive(c.last())
      try server.write(local, data: Data([9]), to: s)
      try client.receive(s.last(), on: remote)
      guard case .data(let buffer) = try client.read(remote, maximum: 8) else {
        return XCTFail("candidate OPEN did not become usable after ACK")
      }
      XCTAssertEqual(try buffer.withBytes { $0 }, Data([9]))
    }
  }

  func testOldApplicationFrontierBlocksReplyUntilActualAuthenticatedRecordArrives() throws {
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
    try client.write(local, data: Data([1, 2]), to: c)
    let delayed = try c.last()
    XCTAssertTrue(try client.requestRekey(to: c))
    try server.receive(c.last())
    XCTAssertFalse(try server.poll(to: s))
    try server.receive(delayed, on: remote)
    XCTAssertTrue(try server.poll(to: s))
    try client.receive(s.last())
    XCTAssertTrue(try client.poll(to: c))
    try server.receive(c.last())
    XCTAssertTrue(try server.poll(to: s))
    try client.receive(s.last())
    try client.write(local, data: Data([3]), to: c)
    try server.receive(c.last(), on: remote)
    guard case .data(let buffer) = try server.read(remote, maximum: 8) else {
      return XCTFail("data missing")
    }
    XCTAssertEqual(try buffer.withBytes { $0 }, Data([1, 2, 3]))
  }

  func testMissingOldMaintenanceSuffixCannotBeHiddenByValidCommit() throws {
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
    XCTAssertTrue(try client.requestRekey(to: c))
    try server.receive(c.last())
    XCTAssertTrue(try server.poll(to: s))
    try client.receive(s.last())
    try client.reset(local)
    XCTAssertTrue(try client.poll(to: c))  // Drop old STOP_OUTPUT.
    XCTAssertTrue(try client.poll(to: c))  // Drop old STOPPED.
    // Authenticated new COMMIT retains the full old frontier.
    XCTAssertTrue(try client.poll(to: c))
    XCTAssertEqual(V4Crypto.number(try c.last()[8..<12]), 1)
    XCTAssertThrowsError(try server.receive(c.last()))
    XCTAssertThrowsError(try server.epoch())
  }

  func testFailedOrReentrantRekeyPublicationAndExpiredAuthorizationAreTerminal() throws {
    let fixture = try CryptoOwnerFixture(.x25519)
    let (a, _) = try fixture.establish()
    let client = try a.makeSession()
    let c = CryptoTestPublisher()
    c.onWrite = { XCTAssertThrowsError(try client.requestRekey(to: c)) }
    c.failure = true
    XCTAssertThrowsError(try client.requestRekey(to: c))
    XCTAssertThrowsError(try client.epoch())
    let other = try CryptoOwnerFixture(.x25519)
    let (raw, _) = try other.establish()
    let session = try raw.makeSession()
    XCTAssertTrue(try session.requestRekey(to: CryptoTestPublisher()))
    other.credentials.base.source.advance(700)
    XCTAssertThrowsError(try session.poll(to: CryptoTestPublisher()))
    XCTAssertThrowsError(try session.epoch())
  }

  func testSignedServiceCapacityMatchesSharedIntegerBoundaries() throws {
    var tested = 0
    for vector in try cryptoCorpus("rekey_credit")["vectors"].array!
    where vector["operation"].text == "service" {
      let input = vector["input"]
      func n(_ key: String) -> UInt64 { UInt64(input[key].text!)! }
      do {
        let clock = try V4TrustedClock(
          profile: V4TimeProfile(
            rateNumerator: n("rate_numerator"),
            rateDenominator: n("rate_denominator"), quantizationMS: n("quantization_ms"),
            maximumWidthMS: 100, maximumAnchorAgeMS: 1_000_000),
          source: NamespaceTickSource(), gate: NSRecursiveLock())
        guard n("session_not_after_ms") > n("issued_at_ms") else {
          throw V4CryptoFailure.configuration
        }
        let credit = try V4RekeyCredit(
          burst: n("burst_rounds"), period: n("refill_period_ms"),
          startBudget: n("request_start_budget_ms"),
          serviceMS: n("session_not_after_ms") - n("issued_at_ms"), clock: clock)
        XCTAssertNil(vector["expected_error"].text, vector["id"].text!)
        XCTAssertEqual(
          credit.maximumRounds, UInt64(vector["expected"]["max_rounds"].text!), vector["id"].text!)
      } catch { XCTAssertNotNil(vector["expected_error"].text, "\(vector["id"].text!): \(error)") }
      tested += 1
    }
    XCTAssertEqual(tested, 22)
  }
  func testCreditRefillBeginsAtAckAndKeepsPartialBalance() throws {
    let source = NamespaceTickSource()
    let clock = try V4TrustedClock(
      profile: V4TimeProfile(
        rateNumerator: 0, rateDenominator: 1,
        quantizationMS: 0, maximumWidthMS: 1, maximumAnchorAgeMS: 100000), source: source,
      gate: NSRecursiveLock())
    var credit = try V4RekeyCredit(
      burst: 2, period: 1000, startBudget: 100, serviceMS: 10000, clock: clock)
    let post = try credit.charge(server: false)
    XCTAssertEqual(post, 1000)
    source.advance(5000)
    try credit.complete(post)
    XCTAssertEqual(try credit.available(server: false), 1000)
    source.advance(100)
    XCTAssertEqual(try credit.available(server: false), 1200)
    let second = try credit.charge(server: false)
    XCTAssertEqual(second, 200)
    source.advance(900)
    try credit.complete(second)
    XCTAssertEqual(try credit.available(server: false), 200)
  }

  func testProductionRekeyMathAndOriginalProjectionMatchSharedRounds() throws {
    let registry = try V4NamespaceRegistry()
    let vectors = try cryptoCorpus("rekey")
    var phases: [String: (V4JSON, V4JSON)] = [:]
    for round in vectors["rounds"].array! {
      let ctx = round["context"]
      let profile = try XCTUnwrap(V4CryptoProfile(rawValue: ctx["profile"].text!))
      let hash = cryptoHex(ctx["handshake_hash_hex"].text!)
      let context = cryptoHex(ctx["context_digest_hex"].text!)
      let epoch = UInt32(ctx["epoch"].uint!)
      let id = cryptoHex(ctx["rekey_id_hex"].text!)
      let secret = V4Crypto.expand(
        SymmetricKey(data: cryptoHex(round["old_root_hex"].text!)),
        info: V4RekeyMaterial.domain(
          "rekey-secret", profile: profile, hash: hash, context: context, epoch: epoch))
      XCTAssertEqual(secret.withUnsafeBytes { Data($0) }, cryptoHex(round["secret_hex"].text!))
      let dh = try V4SoftwareDH(
        profile: profile, material: cryptoHex(round["input"]["client_private_hex"].text!))
      var shared = try dh.shared(cryptoHex(round["server_public_hex"].text!))
      defer {
        V4Crypto.wipe(&shared)
        dh.close()
      }
      XCTAssertEqual(shared, cryptoHex(round["dh_hex"].text!))
      var extracted = V4Crypto.mac(secret, shared)
      defer { V4Crypto.wipe(&extracted) }
      XCTAssertEqual(extracted, cryptoHex(round["prk_hex"].text!))
      let rootInfo =
        V4RekeyMaterial.domain(
          "rekey-root", profile: profile, hash: hash, context: context, epoch: epoch)
        + V4Crypto.integer(UInt64(epoch + 1), width: 4) + V4Crypto.lp(id)
        + V4Crypto.lp(cryptoHex(round["transcript_hex"].text!))
      XCTAssertEqual(rootInfo, cryptoHex(round["root_info_hex"].text!))
      let nextRoot = V4Crypto.expand(SymmetricKey(data: extracted), info: rootInfo)
      XCTAssertEqual(nextRoot.withUnsafeBytes { Data($0) }, cryptoHex(round["new_root_hex"].text!))
      let values = round["phases"].array!
      let first = cryptoHex(values[0]["message_hex"].text!)
      let reply = cryptoHex(values[1]["message_hex"].text!)
      XCTAssertEqual(
        V4RekeyMaterial.transcript(
          "rekey-init-digest", hash: hash, profile: profile,
          epoch: epoch, initial: first), cryptoHex(round["init_digest_hex"].text!))
      XCTAssertEqual(
        V4RekeyMaterial.transcript(
          "rekey-transcript", hash: hash, profile: profile,
          epoch: epoch, initial: first, reply: reply), cryptoHex(round["transcript_hex"].text!))
      for phase in values {
        phases[phase["id"].text!] = (round, phase)
        let number = UInt8(phase["phase"].uint!)
        let value = try V4NamespaceDocument(
          cryptoHex(phase["message_hex"].text!), schema: phase["schema"].text!,
          bytes: 65536, nodes: 8192, registry: registry
        ).root
        let unsigned = try value.excluding(number == 2 ? 6 : 5)
        XCTAssertEqual(unsigned, cryptoHex(phase["unsigned_hex"].text!))
        XCTAssertEqual(
          try V4RekeyMaterial.confirmation(
            base: SymmetricKey(data: cryptoHex(phase["base_hex"].text!)),
            profile: profile, hash: hash, context: context, epoch: epoch, id: id, phase: number,
            unsigned: unsigned),
          try value.b("confirmation_mac"))
      }
    }
    for negative in vectors["negatives"].array! {
      let (round, phase) = phases[negative["source"].text!]!
      var context = round["context"].object!
      for (key, value) in negative["context_patch"].object ?? [:] { context[key] = value }
      do {
        let profile = try XCTUnwrap(V4CryptoProfile(rawValue: context["profile"]!.text!))
        let number = UInt8(phase["phase"].uint!)
        let value = try V4NamespaceDocument(
          cryptoHex(negative["message_hex"].text!), schema: phase["schema"].text!,
          bytes: 65536, nodes: 8192, registry: registry
        ).root
        let epoch = UInt32(context["epoch"]!.uint!)
        let id = cryptoHex(context["rekey_id_hex"]!.text!)
        guard try value.b("rekey_id") == id,
          try value.u("next_epoch") == context["next_epoch"]!.uint!,
          context["next_epoch"]!.uint! == UInt64(epoch) + 1
        else { continue }
        var matchesExpectations = true
        for (field, expected) in negative["expected"].object ?? [:] {
          if field == "old_maintenance_next_sequence" {
            let actual = try value.u(field)
            matchesExpectations = matchesExpectations && actual == UInt64(expected.text!)!
          } else {
            let actual = try value.b(field)
            matchesExpectations = matchesExpectations && actual == cryptoHex(expected.text!)
          }
        }
        if !matchesExpectations { continue }
        let expected = try V4RekeyMaterial.confirmation(
          base: SymmetricKey(data: cryptoHex(negative["base_hex"].text!)),
          profile: profile, hash: cryptoHex(context["handshake_hash_hex"]!.text!),
          context: cryptoHex(context["context_digest_hex"]!.text!), epoch: epoch, id: id,
          phase: number, unsigned: value.excluding(number == 2 ? 6 : 5))
        XCTAssertNotEqual(expected, try value.b("confirmation_mac"), negative["id"].text!)
      } catch {}
    }
  }
}
