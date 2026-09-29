import Crypto
import Foundation
import XCTest

@testable import Flowersec

@MainActor
final class TransportV4CryptoOwnerTests: XCTestCase {
  func testActualCredentialNoiseDualReadyAndReliableRecordsForBothProfiles() throws {
    for profile in V4CryptoProfile.allCases {
      let fixture = try CryptoOwnerFixture(profile)
      let (client, server) = try fixture.establish()
      let clientScope = try client.admitReliableScope(3)
      let serverScope = try server.admitReliableScope(3)
      let wire = CryptoTestPublisher()
      for sequence in 0..<3 {
        let body = Data("message-\(sequence)".utf8)
        try client.publish(scope: clientScope, frameType: 8, plaintext: body, to: wire)
        let received = try server.receive(scope: serverScope, wire: wire.last())
        XCTAssertEqual(received.sequence, UInt64(sequence))
        XCTAssertEqual(try received.withBytes { $0 }, body)
      }
      try server.publish(
        scope: server.maintenance, frameType: 14, plaintext: Data([1, 2]), to: wire)
      XCTAssertEqual(
        try client.receive(scope: client.maintenance, wire: wire.last()).withBytes { $0 },
        Data([1, 2]))
      XCTAssertEqual(client.usage().session.seals, 3)
      XCTAssertEqual(server.usage().session.opens, 3)
      XCTAssertEqual(client.usage().derivations, 4)
      fixture.credentials.base.source.advance(490)
      try client.publish(scope: clientScope, frameType: 8, plaintext: Data(), to: wire)
      try server.receive(scope: serverScope, wire: wire.last()).close()
      fixture.credentials.base.source.advance(200)
      XCTAssertThrowsError(
        try client.publish(scope: clientScope, frameType: 8, plaintext: Data(), to: wire))
    }
  }

  func testReadyAndRecordInputsAcceptBoundedDataSlices() throws {
    let fixture = try CryptoOwnerFixture(.x25519)
    let (client, server, c, s) = try fixture.noise()
    try client.submitReady(to: c)
    try server.submitReady(to: s)
    func slice(_ bytes: Data) -> Data {
      (Data(count: 200) + bytes).dropFirst(200)
    }
    XCTAssertEqual(try slice(c.last()).startIndex, 200)
    try client.receiveReady(slice(s.last()))
    try server.receiveReady(slice(c.last()))
    let a = try client.establish()
    let b = try server.establish()
    let publisher = CryptoTestPublisher()
    try a.publish(scope: a.maintenance, frameType: 14, plaintext: Data([1]), to: publisher)
    let result = try b.receive(scope: b.maintenance, wire: slice(publisher.last()))
    XCTAssertEqual(try result.withBytes { $0 }, Data([1]))
  }

  func testDualReadyIsRequiredAndReflectionOrReplayClosesAttempt() throws {
    for mode in 0..<4 {
      let fixture = try CryptoOwnerFixture(.x25519)
      let (client, server, clientWire, serverWire) = try fixture.noise()
      if mode == 0 {
        XCTAssertThrowsError(try client.establish())
        XCTAssertThrowsError(try client.submitReady(to: clientWire))
        continue
      }
      try client.submitReady(to: clientWire)
      try server.submitReady(to: serverWire)
      if mode == 1 {
        XCTAssertThrowsError(try client.receiveReady(clientWire.last()))
      } else if mode == 2 {
        var damaged = try serverWire.last()
        damaged[damaged.count - 1] ^= 1
        XCTAssertThrowsError(try client.receiveReady(damaged))
      } else {
        try client.receiveReady(serverWire.last())
        XCTAssertThrowsError(try client.receiveReady(serverWire.last()))
      }
      XCTAssertThrowsError(try client.establish())
    }
  }

  func testOriginalTranscriptIdentityEnvironmentAndOneUseAdmissionAreRequired() throws {
    let fixture = try CryptoOwnerFixture(.x25519)
    let input = try fixture.transcript()
    let environment = fixture.credentials.base.environment
    let admission = try fixture.credentials.verify(fixture.input)
    _ = try environment.handshake(
      admission: admission, role: .client, identity: fixture.client, input: input)
    XCTAssertThrowsError(
      try environment.handshake(
        admission: admission, role: .client, identity: fixture.client, input: input))
    let other = try CryptoOwnerFixture(.x25519)
    XCTAssertThrowsError(
      try environment.handshake(
        admission: fixture.credentials.verify(fixture.input),
        role: .client, identity: other.client, input: input))
    for part in ["fsb", "fsa", "hello", "context"] {
      let corrupted = try fixture.transcript(damage: part)
      XCTAssertThrowsError(
        try environment.handshake(
          admission: fixture.credentials.verify(fixture.input),
          role: .client, identity: fixture.client, input: corrupted), part)
    }
    XCTAssertNotEqual(fixture.client.dhPublicKey, fixture.server.dhPublicKey)
    XCTAssertNotEqual(fixture.client.identityPublicKey, fixture.server.identityPublicKey)
  }

  func testRevocationAndIncompleteStateFenceEveryHandshakeOperation() throws {
    for revoke in [false, true] {
      let fixture = try CryptoOwnerFixture(.x25519)
      let (client, _, wire, _) = try fixture.noise()
      let state =
        revoke
        ? fixture.credentials.state(certificates: [
          NamespaceFixture.map([
            0: .bytes(
              NamespaceFixture.digest("certificate-digest", fixture.input.clientCertificate)),
            1: .uint(9), 2: .uint(1800),
          ])
        ]) : fixture.credentials.state()
      let head = try fixture.credentials.base.head(state: state, sequence: 2)
      if revoke {
        try fixture.credentials.base.owner!.refresh(head: head, state: state)
      } else {
        XCTAssertThrowsError(
          try fixture.credentials.base.owner!.refresh(head: head, state: Data([0xa0])))
      }
      XCTAssertThrowsError(try client.submitReady(to: wire))
      XCTAssertThrowsError(try client.establish())
    }
  }

  func testFailedOrReentrantPublisherCannotMintReadyOrReuseRecordSequence() throws {
    let fixture = try CryptoOwnerFixture(.x25519)
    let (client, _, wire, _) = try fixture.noise()
    wire.failure = true
    XCTAssertThrowsError(try client.submitReady(to: wire))
    wire.failure = false
    XCTAssertThrowsError(try client.submitReady(to: wire))
    XCTAssertThrowsError(try client.establish())
    let established = try CryptoOwnerFixture(.p256)
    let (sender, _) = try established.establish()
    let recordWire = CryptoTestPublisher()
    recordWire.failure = true
    XCTAssertThrowsError(
      try sender.publish(
        scope: sender.maintenance, frameType: 14, plaintext: Data(), to: recordWire))
    XCTAssertEqual(sender.usage().session.seals, 1)
    XCTAssertThrowsError(
      try sender.publish(
        scope: sender.maintenance, frameType: 14, plaintext: Data(), to: CryptoTestPublisher()))
    let reentrant = try CryptoOwnerFixture(.x25519)
    let (active, _) = try reentrant.establish()
    let publisher = CryptoTestPublisher()
    publisher.onWrite = {
      XCTAssertThrowsError(
        try active.publish(
          scope: active.maintenance, frameType: 14, plaintext: Data(), to: publisher))
    }
    try active.publish(scope: active.maintenance, frameType: 14, plaintext: Data(), to: publisher)
    XCTAssertEqual(active.usage().session.seals, 1)
  }

  func testRecordAuthenticationPrechargeReplayScopesAndPlaintextLifetime() throws {
    for kind in 0..<4 {
      let fixture = try CryptoOwnerFixture(.x25519)
      let (client, server) = try fixture.establish()
      let out = CryptoTestPublisher()
      try client.publish(scope: client.maintenance, frameType: 14, plaintext: Data([7]), to: out)
      var wire = try out.last()
      if kind == 0 {
        wire[wire.count - 1] ^= 1
        XCTAssertThrowsError(try server.receive(scope: server.maintenance, wire: wire))
        XCTAssertEqual(server.usage().session.opens, 1)
      } else if kind == 1 {
        let authenticated = try server.receive(scope: server.maintenance, wire: wire)
        XCTAssertEqual(try authenticated.withBytes { $0 }, Data([7]))
        XCTAssertThrowsError(try server.receive(scope: server.maintenance, wire: wire))
        XCTAssertThrowsError(try authenticated.withBytes { $0 })
        XCTAssertEqual(server.usage().session.opens, 1)
      } else if kind == 2 {
        XCTAssertThrowsError(try server.receive(scope: client.maintenance, wire: wire))
        XCTAssertEqual(server.usage().derivations, 2)
      } else {
        wire[19] = 3
        XCTAssertThrowsError(try server.receive(scope: server.maintenance, wire: wire))
        XCTAssertEqual(server.usage().derivations, 2)
      }
    }
    let fixture = try CryptoOwnerFixture(.p256)
    let (client, _) = try fixture.establish()
    let scope = try client.admitReliableScope(3)
    try client.retire(scope)
    XCTAssertThrowsError(try client.admitReliableScope(3))
    XCTAssertEqual(client.usage().derivations, 4)
  }

  func testPendingPlaintextRechecksOriginalRevocationAndEnvironmentClose() throws {
    let fixture = try CryptoOwnerFixture(.x25519)
    let (client, server) = try fixture.establish()
    let out = CryptoTestPublisher()
    try client.publish(scope: client.maintenance, frameType: 14, plaintext: Data([7]), to: out)
    let result = try server.receive(scope: server.maintenance, wire: out.last())
    let state = fixture.credentials.state(certificates: [
      NamespaceFixture.map([
        0: .bytes(NamespaceFixture.digest("certificate-digest", fixture.input.serverCertificate)),
        1: .uint(9), 2: .uint(1700),
      ])
    ])
    try fixture.credentials.base.owner!.refresh(
      head: fixture.credentials.base.head(state: state, sequence: 2), state: state)
    XCTAssertThrowsError(try result.withBytes { $0 })
    XCTAssertThrowsError(
      try server.publish(scope: server.maintenance, frameType: 14, plaintext: Data(), to: out))
    let before = fixture.credentials.base.root.snapshot().used.sdkBytes
    fixture.credentials.base.environment.beginClose()
    XCTAssertGreaterThan(fixture.credentials.base.root.snapshot().used.sdkBytes, before / 2)
    XCTAssertThrowsError(try out.last())
  }

  func testNoiseFlightsUseFreshEphemeralsAndPreparationDeadline() throws {
    let fixture = try CryptoOwnerFixture(.x25519)
    let input = try fixture.transcript()
    let environment = fixture.credentials.base.environment
    let first = try environment.handshake(
      admission: fixture.credentials.verify(fixture.input), role: .client, identity: fixture.client,
      input: input)
    let second = try environment.handshake(
      admission: fixture.credentials.verify(fixture.input), role: .client, identity: fixture.client,
      input: input)
    let a = CryptoTestPublisher()
    let b = CryptoTestPublisher()
    try first.submitNoise(to: a)
    try second.submitNoise(to: b)
    XCTAssertNotEqual(try a.last().prefix(32), try b.last().prefix(32))
    fixture.credentials.base.source.advance(490)
    XCTAssertThrowsError(try first.receiveNoise(b.last()))
    XCTAssertThrowsError(try second.submitReady(to: b))
  }

  func testCryptoDecoderMatchesHandshakeShapeCorpus() throws {
    let schemas: Set<String> = [
      "ClientHello", "ServerHello", "TransportContext", "FSB4", "FSA4", "READY", "ReadyProofInput",
      "ReadyMACInput",
    ]
    let corpus = try cryptoCorpus("corpus")
    let registry = try V4NamespaceRegistry()
    var count = 0
    for vector in corpus["vectors"].array! {
      guard let schema = vector["schema"].text, schemas.contains(schema),
        let hex = vector["hex"].text
      else { continue }
      let limits = vector["limits"].object ?? [:]
      do {
        _ = try V4NamespaceDocument(
          cryptoHex(hex), schema: schema, bytes: 65_536, nodes: 32768,
          registry: registry, limits: limits.compactMapValues(\.uint),
          context: limits.compactMapValues(\.text))
        XCTAssertNil(vector["expected_error"].text, vector["id"].text!)
      } catch { XCTAssertNotNil(vector["expected_error"].text, "\(vector["id"].text!): \(error)") }
      count += 1
    }
    XCTAssertGreaterThan(count, 20)
  }
}

final class CryptoTestPublisher: V4HandshakeWriter, V4RecordPublisher {
  var buffers: [V4CryptoBuffer] = []
  var failure = false
  var onWrite: (() throws -> Void)?
  func submit(_ flight: V4HandshakeFlight, buffer: V4CryptoBuffer) throws { try publish(buffer) }
  func publish(_ buffer: V4CryptoBuffer) throws {
    buffers = [buffer]
    try onWrite?()
    if failure { throw V4CryptoFailure.closed }
  }
  func last() throws -> Data { try buffers.last!.withBytes { $0 } }
}

final class CryptoOwnerFixture {
  let credentials: CredentialFixture
  let client: V4LocalIdentity
  let server: V4LocalIdentity
  let input: V4CredentialInput
  init(_ profile: V4CryptoProfile, artifact: [UInt64: V4CBORValue] = [:]) throws {
    credentials = try CredentialFixture(profile: profile.rawValue)
    let environment = credentials.base.environment
    client = try environment.generateIdentity(profile: profile)
    server = try environment.generateIdentity(profile: profile)
    func certificate(_ identity: V4LocalIdentity) -> [UInt64: V4CBORValue] {
      [
        3: NamespaceFixture.map([
          0: .uint(profile == .x25519 ? 0 : 1), 1: .bytes(identity.dhPublicKey),
        ]),
        4: .bytes(identity.identityPublicKey),
      ]
    }
    input = try credentials.input(
      client: certificate(client), server: certificate(server), artifact: artifact)
  }
  func transcript(damage: String? = nil) throws -> V4HandshakeInput {
    let a = NamespaceFixture.digest("artifact-digest", input.artifact)
    let c = NamespaceFixture.digest("certificate-digest", input.clientCertificate)
    let s = NamespaceFixture.digest("certificate-digest", input.serverCertificate)
    let route = credentials.routeDigest(0)
    let common: [UInt64: V4CBORValue] = [
      0: .text("flowersec/4"), 1: .text("4"), 2: .text(client.profile.rawValue),
      3: .bytes(a), 4: .bytes(Data(repeating: 40, count: 16)), 5: .bytes(route),
      6: .bytes(Data(repeating: 33, count: 16)), 7: .bytes(Data(repeating: 31, count: 32)),
    ]
    var ch = NamespaceFixture.map(
      common.merging([
        8: .uint(0), 9: .uint(3), 10: .bytes(Data()),
      ]) { _, n in n }
    ).encoded()
    let sh = NamespaceFixture.map(
      common.merging([
        8: .bytes(Data(repeating: 80, count: 32)), 9: .uint(0), 10: .uint(0),
        11: .uint(1), 12: .bytes(Data()),
      ]) { _, n in n }
    ).encoded()
    let hello = Data(
      SHA256.hash(
        data: Data("flowersec/v4/hello-transcript\0".utf8)
          + V4Crypto.lp(ch) + V4Crypto.lp(sh)))
    var context = NamespaceFixture.map([
      0: .text("4"), 1: .text(client.profile.rawValue), 2: .uint(0), 3: .uint(0),
      4: .bytes(a), 5: .bytes(route), 6: .bytes(Data(repeating: 33, count: 16)),
      7: .bytes(Data(repeating: 31, count: 32)), 8: .bytes(hello), 9: .uint(0),
      10: .uint(1), 11: .uint(0), 12: .bytes(Data()),
    ]).encoded()
    let contextDigest = NamespaceFixture.digest("transport-context", context)
    func sign(_ fields: [UInt64: V4CBORValue], id: UInt64, label: String, key: V4LocalIdentity)
      throws -> Data
    {
      var fields = fields
      fields[id] = .bytes(
        try key.signHandshake(
          NamespaceFixture.input(label, NamespaceFixture.map(fields).encoded()),
          in: credentials.base.environment))
      return NamespaceFixture.map(fields).encoded()
    }
    var fsb = try sign(
      [
        0: .bytes(a), 1: .text("tenant"), 2: .bytes(Data(repeating: 5, count: 16)),
        3: .bytes(Data(repeating: 30, count: 16)), 4: .bytes(Data(repeating: 31, count: 32)),
        5: .bytes(Data(repeating: 40, count: 16)), 6: .bytes(route),
        7: .bytes(Data(repeating: 33, count: 16)), 8: .bytes(Data(repeating: 81, count: 32)),
        9: .bytes(hello), 10: .uint(0), 11: .uint(1), 12: .bytes(contextDigest),
        13: .bytes(input.activation), 14: .bytes(input.clientCertificate),
      ], id: 15, label: "fsb4/signature", key: client)
    var fsa = try sign(
      [
        0: .uint(0), 1: .uint(0), 2: .uint(1), 3: .bytes(Data(repeating: 82, count: 32)),
        4: .bytes(NamespaceFixture.digest("admission-binding", fsb)), 5: .bytes(route),
        6: .bytes(hello), 7: .uint(0), 8: .uint(1), 9: .bytes(contextDigest),
        10: .bytes(c), 11: .bytes(s), 12: .bytes(input.serverCertificate),
      ], id: 13, label: "fsa4/signature", key: server)
    if damage == "fsb" { fsb[fsb.count - 1] ^= 1 }
    if damage == "fsa" { fsa[fsa.count - 1] ^= 1 }
    if damage == "hello" { ch[ch.count - 1] ^= 1 }
    if damage == "context" { context[context.count - 1] ^= 1 }
    return V4HandshakeInput(
      artifact: input.artifact, clientHello: ch, serverHello: sh,
      transportContext: context, fsb: fsb, fsa: fsa)
  }
  func noise() throws -> (V4Handshake, V4Handshake, CryptoTestPublisher, CryptoTestPublisher) {
    let environment = credentials.base.environment
    let transcript = try transcript()
    let clientState = try environment.handshake(
      admission: credentials.verify(input), role: .client,
      identity: client, input: transcript)
    let serverState = try environment.handshake(
      admission: credentials.verify(input), role: .server,
      identity: server, input: transcript)
    let c = CryptoTestPublisher()
    let s = CryptoTestPublisher()
    try clientState.submitNoise(to: c)
    try serverState.receiveNoise(c.last())
    try serverState.submitNoise(to: s)
    try clientState.receiveNoise(s.last())
    return (clientState, serverState, c, s)
  }
  func establish() throws -> (V4ReliableChannel, V4ReliableChannel) {
    let (client, server, c, s) = try noise()
    try client.submitReady(to: c)
    try server.submitReady(to: s)
    try client.receiveReady(s.last())
    try server.receiveReady(c.last())
    return try (client.establish(), server.establish())
  }
}

func cryptoCorpus(_ name: String) throws -> V4JSON {
  try JSONDecoder().decode(
    V4JSON.self,
    from: Data(
      contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/\(name).json")))
}
func cryptoHex(_ text: String) -> Data {
  let bytes = Array(text.utf8)
  return Data(
    stride(from: 0, to: bytes.count, by: 2).map {
      UInt8(String(decoding: bytes[$0...$0 + 1], as: UTF8.self), radix: 16)!
    })
}
