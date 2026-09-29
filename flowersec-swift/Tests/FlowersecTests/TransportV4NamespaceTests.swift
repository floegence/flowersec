import Crypto
import Foundation
import XCTest

@testable import Flowersec

@MainActor
final class TransportV4NamespaceTests: XCTestCase {
  func testNonceBoundBootstrapAuthenticatesPinnedRootAndCompleteState() throws {
    let fixture = try NamespaceFixture()
    let initial = fixture.root.snapshot()
    XCTAssertThrowsError(try fixture.owner!.checkCurrent())
    let state = fixture.state()
    let response = try fixture.response(state: state)
    try fixture.owner!.bootstrap(response: response, state: state)
    try fixture.owner!.checkCurrent()
    XCTAssertEqual(fixture.owner!.currentSequence, 1)
    XCTAssertThrowsError(try fixture.owner!.bootstrapNonce())
    XCTAssertThrowsError(
      try fixture.owner!.bootstrap(response: response, state: state))
    XCTAssertEqual(fixture.root.snapshot(), initial)
  }

  func testIndependentRootAndOriginalNonceCannotBeSubstituted() throws {
    let fixture = try NamespaceFixture()
    let state = fixture.state()
    XCTAssertThrowsError(
      try fixture.owner!.bootstrap(
        response: fixture.response(state: state, nonce: Data(repeating: 9, count: 32)), state: state
      ))
    XCTAssertThrowsError(
      try fixture.owner!.bootstrap(
        response: fixture.response(state: state, responseSeed: 13), state: state))
    XCTAssertThrowsError(
      try fixture.owner!.bootstrap(
        response: fixture.response(state: state, trustSeed: 13), state: state))
    XCTAssertThrowsError(
      try fixture.owner!.bootstrap(
        response: fixture.response(state: state, headSeed: 13), state: state))
    XCTAssertNil(fixture.owner!.currentSequence)
    try fixture.owner!.bootstrap(response: fixture.response(state: state), state: state)
    try fixture.owner!.checkCurrent()
  }

  func testAuthenticatedNewHeadFencesOldStateBeforeFailedFetch() throws {
    let fixture = try NamespaceFixture()
    let state = fixture.state()
    try fixture.owner!.bootstrap(response: fixture.response(state: state), state: state)
    let next = try fixture.head(state: state, sequence: 2)
    XCTAssertThrowsError(try fixture.owner!.refresh(head: next, state: Data([0xa0])))
    XCTAssertThrowsError(try fixture.owner!.checkCurrent()) { error in
      XCTAssertEqual(error as? V4NamespaceFailure, .pendingState)
    }
    XCTAssertThrowsError(try fixture.owner!.refresh(head: fixture.head(state: state), state: state))
    { error in
      XCTAssertEqual(error as? V4NamespaceFailure, .rollback)
    }
    try fixture.owner!.refresh(head: next, state: state)
    XCTAssertEqual(fixture.owner!.currentSequence, 2)
  }

  func testAuthenticatedSameSequenceConflictPermanentlyClosesOwner() throws {
    let fixture = try NamespaceFixture()
    let state = fixture.state()
    try fixture.owner!.bootstrap(response: fixture.response(state: state), state: state)
    XCTAssertThrowsError(
      try fixture.owner!.refresh(
        head: fixture.head(state: state, until: 3900), state: state)
    ) { error in
      XCTAssertEqual(error as? V4NamespaceFailure, .equivocation)
    }
    XCTAssertThrowsError(try fixture.owner!.checkCurrent())
    XCTAssertThrowsError(try fixture.owner!.bootstrapNonce())
    fixture.owner = nil
    XCTAssertThrowsError(
      try fixture.environment.namespace(
        pinnedRoot: fixture.pin, configuration: fixture.configuration)
    ) { error in
      XCTAssertEqual(error as? V4ResourceFailure, .owner)
    }
  }

  func testFullStateBindingAndOriginalRevocationsAreRetained() throws {
    let fixture = try NamespaceFixture()
    let certificate = NamespaceFixture.map([
      0: .bytes(Data(repeating: 4, count: 32)), 1: .uint(0), 2: .uint(1000),
    ])
    let state = fixture.state(certificates: [certificate])
    try fixture.owner!.bootstrap(response: fixture.response(state: state), state: state)
    let absent = fixture.state()
    XCTAssertThrowsError(
      try fixture.owner!.refresh(
        head: fixture.head(state: absent, sequence: 2), state: absent)
    ) { error in
      XCTAssertEqual(error as? V4NamespaceFailure, .rollback)
    }
    XCTAssertNil(fixture.owner!.currentSequence)
    try fixture.owner!.refresh(head: fixture.head(state: state, sequence: 3), state: state)
    XCTAssertEqual(fixture.owner!.currentSequence, 3)
  }

  func testIssuerRevocationRequiresExactCompleteOriginalPermissionEvidence() throws {
    let fixture = try NamespaceFixture()
    let authorization = fixture.authorization()
    let original = NamespaceFixture.map([
      0: .bytes(
        NamespaceFixture.digest("credential-issuer-authorization", authorization.encoded())),
      1: .array([.uint(20), .null]), 2: .uint(1), 3: .uint(1500),
    ])
    let issuer = NamespaceFixture.map([
      0: .bytes(Data(repeating: 4, count: 16)), 1: .array([original]),
    ])
    let state = fixture.state(issuers: [issuer])
    let response = try fixture.response(state: state, authorizations: [authorization])
    try fixture.owner!.bootstrap(response: response, state: state)
    try fixture.owner!.checkCurrent()

    let invalidFixture = try NamespaceFixture()
    let unrelated = NamespaceFixture.map([
      0: .bytes(Data(repeating: 8, count: 32)), 1: .array([.uint(20), .null]),
      2: .uint(1), 3: .uint(1500),
    ])
    let forgedIssuer = NamespaceFixture.map([
      0: .bytes(Data(repeating: 4, count: 16)), 1: .array([unrelated]),
    ])
    let forgedState = invalidFixture.state(issuers: [forgedIssuer])
    XCTAssertThrowsError(
      try invalidFixture.owner!.bootstrap(
        response: invalidFixture.response(state: forgedState, authorizations: [authorization]),
        state: forgedState))
    XCTAssertNil(invalidFixture.owner!.currentSequence)
  }

  func testLeaseRevocationImpactMayGrowWithoutChangingItsOriginalIdentity() throws {
    let fixture = try NamespaceFixture()
    func lease(_ end: UInt64, artifact: UInt8 = 6) -> V4CBORValue {
      NamespaceFixture.map([
        0: .bytes(Data(repeating: 4, count: 16)), 1: .bytes(Data(repeating: 5, count: 16)),
        2: .bytes(Data(repeating: artifact, count: 32)), 3: .uint(0), 4: .uint(end),
      ])
    }
    let original = fixture.state(leases: [lease(1000)])
    try fixture.owner!.bootstrap(response: fixture.response(state: original), state: original)
    let extended = fixture.state(leases: [lease(1100)])
    try fixture.owner!.refresh(head: fixture.head(state: extended, sequence: 2), state: extended)
    XCTAssertThrowsError(
      try fixture.owner!.refresh(
        head: fixture.head(state: original, sequence: 3), state: original))
    let rebound = fixture.state(leases: [lease(1100, artifact: 7)])
    XCTAssertThrowsError(
      try fixture.owner!.refresh(
        head: fixture.head(state: rebound, sequence: 4), state: rebound))
    try fixture.owner!.refresh(head: fixture.head(state: extended, sequence: 5), state: extended)
    XCTAssertEqual(fixture.owner!.currentSequence, 5)
  }

  func testFloorRetirementRequiresTrustedLowerBoundAndCannotRollBack() throws {
    let fixture = try NamespaceFixture()
    let state = fixture.state()
    try fixture.owner!.bootstrap(response: fixture.response(state: state), state: state)
    let premature = fixture.state(floors: [1, 0])
    XCTAssertThrowsError(
      try fixture.owner!.refresh(
        head: fixture.head(state: premature, sequence: 2, floors: [1, 0]), state: premature)
    ) { error in
      XCTAssertEqual(error as? V4TimeFailure, .pending)
    }
    XCTAssertNil(fixture.owner!.currentSequence)
    XCTAssertThrowsError(
      try fixture.owner!.refresh(
        head: fixture.head(state: state, sequence: 3), state: state)
    ) { error in
      XCTAssertEqual(error as? V4NamespaceFailure, .rollback)
    }
    fixture.source.advance(101)
    try fixture.owner!.refresh(
      head: fixture.head(state: premature, sequence: 3, floors: [1, 0]), state: premature)
    try fixture.owner!.checkCurrent()
  }

  func testNonOverlappingPerClassSegmentsAndCheckedCohortArithmetic() throws {
    let first = NamespaceFixture.map([0: .uint(0), 1: .uint(5), 2: .uint(100)])
    let overlaps = NamespaceFixture.map([0: .uint(3), 1: .uint(8), 2: .uint(100)])
    let fixture = try NamespaceFixture()
    let invalid = fixture.state(segments: [first, overlaps])
    XCTAssertThrowsError(
      try fixture.owner!.bootstrap(response: fixture.response(state: invalid), state: invalid))
    let otherClass = NamespaceFixture.map([0: .uint(3), 1: .uint(8), 3: .uint(100)])
    let valid = fixture.state(segments: [first, otherClass])
    try fixture.owner!.bootstrap(response: fixture.response(state: valid), state: valid)
    let overflow = NamespaceFixture.map([0: .uint(UInt64.max), 1: .uint(UInt64.max), 2: .uint(100)])
    let next = fixture.state(segments: [first, otherClass, overflow])
    XCTAssertThrowsError(
      try fixture.owner!.refresh(head: fixture.head(state: next, sequence: 2), state: next))
  }

  func testSameHeadCannotRenewDeadlineAndBootstrapWindowDoesNotRestart() throws {
    let fixture = try NamespaceFixture()
    let state = fixture.state()
    try fixture.owner!.bootstrap(response: fixture.response(state: state), state: state)
    fixture.source.advance(2990)
    XCTAssertThrowsError(try fixture.owner!.checkCurrent())
    XCTAssertThrowsError(try fixture.owner!.refresh(head: fixture.head(state: state), state: state))
    let waiting = try NamespaceFixture()
    let reply = try waiting.response(state: waiting.state())
    waiting.source.advance(10_000)
    XCTAssertThrowsError(try waiting.owner!.bootstrap(response: reply, state: waiting.state()))
    XCTAssertThrowsError(try waiting.owner!.bootstrapNonce())
  }

  func testClosingEnvironmentFencesNamespaceAndRetainsRealAliasCharge() throws {
    let fixture = try NamespaceFixture()
    let state = fixture.state()
    try fixture.owner!.bootstrap(response: fixture.response(state: state), state: state)
    fixture.environment.beginClose()
    XCTAssertThrowsError(try fixture.owner!.checkCurrent())
    XCTAssertFalse(fixture.environment.cleanupStatus().complete)
    XCTAssertGreaterThan(fixture.root.snapshot().references, 0)
    fixture.owner = nil
    XCTAssertTrue(fixture.environment.cleanupStatus().complete)
    XCTAssertEqual(fixture.root.snapshot().references, 0)
  }

  func testNamespaceCapacityFailureDoesNotClaimOrPartiallyCharge() throws {
    let fixture = try NamespaceFixture(createOwner: false)
    let before = fixture.root.snapshot()
    XCTAssertThrowsError(
      try fixture.environment.namespace(
        pinnedRoot: fixture.pin,
        configuration: V4NamespaceConfiguration(stateBytes: 8192, stateNodes: 0, bootstrapMS: 1000))
    )
    XCTAssertEqual(fixture.root.snapshot(), before)
    fixture.owner = try fixture.environment.namespace(
      pinnedRoot: fixture.pin, configuration: fixture.configuration)
    XCTAssertThrowsError(
      try fixture.environment.namespace(
        pinnedRoot: fixture.pin, configuration: fixture.configuration))
  }

  func testProductionNamespaceDecoderRejectsNoncanonicalAndUnboundedInput() throws {
    let fixture = try NamespaceFixture()
    let state = fixture.state()
    let limits: [String: UInt64] = [
      "max_state_encoded_bytes": 8192, "max_revoked_issuers": 16,
      "max_revoked_certificates": 16, "max_revoked_leases": 16, "max_cohort_policy_segments": 16,
      "max_revoked_issuer_authorizations": 128,
    ]
    let registry = try V4NamespaceRegistry()
    func decode(_ input: Data, nodes: Int = 4096) throws {
      _ = try V4NamespaceDocument(
        input, schema: "RevocationState", bytes: 8192, nodes: nodes, registry: registry,
        limits: limits)
    }
    try decode(state)
    XCTAssertThrowsError(try decode(state, nodes: 4))
    XCTAssertThrowsError(try decode(state + Data([0])))
    XCTAssertThrowsError(try decode(Data([0xb8, 12]) + state.dropFirst()))
    XCTAssertThrowsError(try decode(Data([0xbf, 0xff])))
    XCTAssertThrowsError(try decode(Data(repeating: 0, count: 8193)))
    var duplicate = state
    duplicate[4] = 0
    XCTAssertThrowsError(try decode(duplicate))
  }

  func testProductionDecoderMatchesSharedNamespaceShapeAndRuleCorpus() throws {
    let schemas: Set<String> = [
      "TrustBootstrapResponse", "TrustConfig", "NamespaceCapacity",
      "PublicationPolicy", "CredentialRevocationPolicy", "CredentialIssuerAuthorization",
      "HeadSignerDelegation", "ConnectionActivationDelegation", "OnceAuthorityRef", "FreshnessHead",
      "RevocationState", "RevokedIssuerEntry", "IssuerAuthorizationImpact",
      "RevokedCertificateEntry",
      "RevokedLeaseEntry", "CohortPolicySegment",
    ]
    let corpus = try JSONDecoder().decode(
      V4JSON.self,
      from: Data(
        contentsOf:
          packageRoot().appendingPathComponent("testdata/transport_v4/corpus.json")))
    let registry = try V4NamespaceRegistry()
    var checked = 0
    for vector in corpus["vectors"].array! {
      guard let schema = vector["schema"].text, schemas.contains(schema),
        let hex = vector["hex"].text
      else { continue }
      var bytes = Data()
      var index = hex.startIndex
      while index < hex.endIndex {
        let end = hex.index(index, offsetBy: 2)
        bytes.append(UInt8(hex[index..<end], radix: 16)!)
        index = end
      }
      let limits = (vector["limits"].object ?? [:]).compactMapValues(\.uint)
      do {
        _ = try V4NamespaceDocument(
          bytes, schema: schema, bytes: 1 << 20, nodes: 32768, registry: registry, limits: limits)
        XCTAssertNil(vector["expected_error"].text, vector["id"].text!)
      } catch {
        XCTAssertNotNil(vector["expected_error"].text, "\(vector["id"].text!): \(error)")
      }
      checked += 1
    }
    XCTAssertGreaterThan(checked, 30)
  }
}

final class NamespaceTickSource: V4MonotonicSource, @unchecked Sendable {
  private let gate = NSLock()
  private var value: UInt64 = 0
  func read() throws -> V4MonotonicTick {
    gate.withLock { V4MonotonicTick(milliseconds: value, incarnation: 1) }
  }
  func advance(_ ticks: UInt64) { gate.withLock { value += ticks } }
}

final class NamespaceFixture {
  let source = NamespaceTickSource()
  let root: V4ResourceRoot
  let environment: V4EnvironmentFoundation
  let pin: V4NamespaceTrustRoot
  let configuration = V4NamespaceConfiguration(
    stateBytes: 8192, stateNodes: 4096, bootstrapMS: 10_000)
  var owner: V4NamespaceVerifier?
  let capacity: V4CBORValue
  let capacityDigest: Data
  let delegation: V4CBORValue

  init(createOwner: Bool = true) throws {
    let limit = V4ResourceVector(
      sdkBytes: 1 << 30, diskBytes: 1 << 30, items: 128, work: 128, tasks: 128,
      timers: 128, connections: 16, handshakes: 16, sessions: 16, handles: 128)
    root = try V4ResourceRoot(
      V4ResourceRootConfiguration(
        limit: limit, accounts: 16,
        reservations: 32, references: 64, cleanupWaiters: 4, runtimeOverheadBytes: 1024))
    let tenant = try root.account(
      kind: .tenant, identity: V4ResourceIdentity(high: 1, low: 1), limit: limit)
    environment = try V4EnvironmentFoundation(
      root: root, tenant: tenant,
      configuration: V4EnvironmentConfiguration(
        identity: V4ResourceIdentity(high: 2, low: 2),
        limit: limit, maximumReadBudgets: 2, maximumWork: 2, runtimeOverheadBytes: 1024,
        cleanupTimeout: .milliseconds(10), verificationContinuity: .onlineBootstrap),
      timeProfile: V4TimeProfile(
        rateNumerator: 0, rateDenominator: 1, quantizationMS: 0,
        maximumWidthMS: 100, maximumAnchorAgeMS: 100_000), monotonicSource: source)
    try environment.clock.installTrusted(
      at: environment.clock.mark(),
      interval:
        V4TimeInterval(lowerMS: 1000, upperMS: 1010))
    pin = V4NamespaceTrustRoot(
      tenant: "tenant", authority: "authority",
      keyID: Data(repeating: 1, count: 16), publicKey: try Self.key(7).publicKey.rawRepresentation,
      maximumTrustLifetimeMS: 10_000)
    capacity = Self.map([
      0: .text("tenant"), 1: .text("authority"), 2: .text("capacity.1"),
      3: .uint(8192), 4: .uint(16), 5: .uint(16), 6: .uint(16), 7: .uint(16), 8: .uint(795),
      9: .uint(262144), 10: .uint(128), 11: .uint(0), 12: .uint(100), 13: .uint(1000),
      14: .uint(1000),
    ])
    capacityDigest = Self.digest("namespace-capacity", capacity.encoded())
    delegation = Self.map([
      0: .text("4"), 1: .text("tenant"), 2: .text("authority"),
      3: .bytes(capacityDigest), 4: .uint(1), 5: .bytes(Data(repeating: 2, count: 16)),
      6: .bytes(Data(repeating: 3, count: 16)),
      7: .bytes(try Self.key(9).publicKey.rawRepresentation),
      8: .uint(0), 9: .text("publication"), 10: .uint(1), 11: .uint(1), 12: .uint(1),
      13: .uint(5000),
    ])
    if createOwner {
      owner = try environment.namespace(pinnedRoot: pin, configuration: configuration)
    }
  }
  deinit {
    owner?.close()
    environment.beginClose()
  }

  static func map(_ fields: [UInt64: V4CBORValue]) -> V4CBORValue {
    .map(fields.sorted { $0.key < $1.key }.map { .init(key: .uint($0.key), value: $0.value) })
  }
  static func key(_ seed: UInt8) throws -> Curve25519.Signing.PrivateKey {
    try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: seed, count: 32))
  }
  static func input(_ label: String, _ bytes: Data) -> Data {
    var length = UInt32(bytes.count).bigEndian
    return Data("flowersec/v4/\(label)\0".utf8) + withUnsafeBytes(of: &length) { Data($0) } + bytes
  }
  static func digest(_ label: String, _ bytes: Data) -> Data {
    Data(SHA256.hash(data: input(label, bytes)))
  }
  static func signed(_ fields: [UInt64: V4CBORValue], signature: UInt64, label: String, seed: UInt8)
    throws -> Data
  {
    var fields = fields
    fields[signature] = .bytes(try key(seed).signature(for: input(label, map(fields).encoded())))
    return map(fields).encoded()
  }
  func authorization() -> V4CBORValue {
    Self.map([
      0: .bytes(Data(repeating: 5, count: 16)), 1: .text("tenant"), 2: .text("authority"),
      3: .bytes(capacityDigest), 4: .uint(1), 5: .uint(0), 6: .bytes(Data(repeating: 4, count: 16)),
      7: .bytes(try! Self.key(11).publicKey.rawRepresentation), 8: .text("service"), 9: .uint(1),
      10: .uint(1500), 11: .uint(0), 12: .uint(20), 13: .uint(2500), 14: .text("client"),
      15: .text("fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1"), 16: .uint(0),
      24: .array([.uint(20), .null]),
    ])
  }
  func state(
    issuers: [V4CBORValue] = [], certificates: [V4CBORValue] = [],
    leases: [V4CBORValue] = [], segments: [V4CBORValue] = [], floors: [UInt64] = [0, 0]
  ) -> Data {
    Self.map([
      0: .text("4"), 1: .text("tenant"), 2: .text("authority"), 3: .bytes(capacityDigest),
      4: .uint(1), 5: .array(floors.map(V4CBORValue.uint)), 6: .text("publication"), 7: .uint(1),
      8: .array(issuers), 9: .array(certificates), 10: .array(leases),
      11: .array(segments.sorted { $0.encoded().lexicographicallyPrecedes($1.encoded()) }),
    ]).encoded()
  }
  func head(
    state: Data, sequence: UInt64 = 1, until: UInt64 = 4000,
    floors: [UInt64] = [0, 0], seed: UInt8 = 9
  ) throws -> Data {
    try Self.signed(
      [
        0: .text("4"), 1: .text("tenant"), 2: .text("authority"), 3: .bytes(capacityDigest),
        4: .uint(1), 5: .array(floors.map(V4CBORValue.uint)), 6: .text("publication"), 7: .uint(1),
        8: .uint(sequence), 9: .uint(900), 10: .uint(until),
        11: .bytes(Self.digest("revocation-state", state)),
        12: .uint(UInt64(state.count)), 13: .bytes(Data(repeating: 3, count: 16)),
        14: .bytes(Self.digest("head-signer-delegation", delegation.encoded())),
      ], signature: 15,
      label: "freshness-head-signature", seed: seed)
  }
  func response(
    state: Data, nonce: Data? = nil, responseSeed: UInt8 = 7, trustSeed: UInt8 = 7,
    headSeed: UInt8 = 9, authorizations: [V4CBORValue] = [],
    policies: [V4CBORValue] = [], activationDelegations: [V4CBORValue] = [],
    onceAuthorities: [V4CBORValue] = []
  ) throws -> Data {
    let trust = try Self.signed(
      [
        0: .text("4"), 1: .text("tenant"), 2: .text("authority"),
        3: .uint(1), 4: .uint(1), 5: .uint(1), 6: .uint(5000), 7: capacity,
        8: Self.map([0: .text("publication"), 1: .uint(1), 2: .uint(4000), 3: .uint(5000)]),
        9: .array(policies), 10: .array(authorizations), 11: .array([delegation]),
        12: .array(activationDelegations),
        13: .array(onceAuthorities), 14: .array([]), 15: .array([]), 16: .bytes(pin.keyID),
      ], signature: 17,
      label: "trust-config/signature", seed: trustSeed)
    return try Self.signed(
      [
        0: .text("4"), 1: .text("tenant"), 2: .text("authority"),
        3: .bytes(nonce ?? owner!.bootstrapNonce()), 4: .uint(900), 5: .uint(2000),
        6: .bytes(trust), 7: .bytes(head(state: state, seed: headSeed)), 8: .bytes(pin.keyID),
      ],
      signature: 9, label: "trust-bootstrap/signature", seed: responseSeed)
  }
}
