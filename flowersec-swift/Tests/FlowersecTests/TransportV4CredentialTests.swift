import Crypto
import Foundation
import XCTest

@testable import Flowersec

@MainActor
final class TransportV4CredentialTests: XCTestCase {
  func testLiveAndPoolUseActualSignaturesAndOriginalOwner() throws {
    for source in [V4ActivationSource.liveAuthority, .preauthorizedPool] {
      let fixture = try CredentialFixture()
      let before = fixture.base.root.snapshot()
      var admission: V4CredentialAdmission? = try fixture.verify(fixture.input(source: source))
      XCTAssertEqual(admission!.source, source)
      XCTAssertEqual(admission!.candidateID, Data(repeating: 40, count: 16))
      XCTAssertEqual(admission!.sessionNotAfterMS, 1700)
      XCTAssertEqual(admission!.initiationNotAfterMS, 1500)
      XCTAssertEqual(admission!.routeDigest, fixture.routeDigest(0))
      XCTAssertGreaterThan(fixture.base.root.snapshot().used.sdkBytes, before.used.sdkBytes)
      try admission!.checkPreparation(in: fixture.base.environment)
      let foreign = try NamespaceFixture()
      XCTAssertThrowsError(try admission!.checkPreparation(in: foreign.environment))
      try admission!.checkPreparation(in: fixture.base.environment)
      admission!.close()
      XCTAssertThrowsError(try admission!.checkPreparation(in: fixture.base.environment))
      XCTAssertGreaterThan(fixture.base.root.snapshot().used.sdkBytes, before.used.sdkBytes)
      admission = nil
      XCTAssertEqual(fixture.base.root.snapshot(), before)
    }
  }

  func testFailuresRefundWorkAndDoNotPoisonNamespace() throws {
    let fixture = try CredentialFixture()
    let before = fixture.base.root.snapshot()
    for field in ["artifact", "client", "server", "activation"] {
      let input = try fixture.input(badSignature: field)
      XCTAssertThrowsError(try fixture.verify(input), field)
      XCTAssertEqual(fixture.base.root.snapshot(), before, field)
    }
    for configuration in [
      fixture.configuration(tenant: "foreign"), fixture.configuration(audience: "other"),
      fixture.configuration(client: "other"), fixture.configuration(server: "other"),
      fixture.configuration(profiles: [CredentialFixture.p256Profile]),
    ] {
      XCTAssertThrowsError(
        try fixture.base.environment.verifyDirectCredentials(
          configuration: configuration, input: fixture.input()))
      XCTAssertEqual(fixture.base.root.snapshot(), before)
    }
    try fixture.verify(fixture.input()).checkPreparation(in: fixture.base.environment)
  }

  func testSourceCandidateAndPoolBindingsCannotBeSubstituted() throws {
    let fixture = try CredentialFixture()
    let live = try fixture.input()
    let pool = try fixture.input(source: .preauthorizedPool)
    for input in [
      fixture.rebind(live, source: .preauthorizedPool),
      fixture.rebind(pool, source: .liveAuthority),
      fixture.rebind(live, index: 1), fixture.rebind(pool, index: 2),
      try fixture.input(source: .preauthorizedPool, indices: [1]),
      try fixture.input(source: .preauthorizedPool, indices: [0, 2]),
      try fixture.input(source: .preauthorizedPool, poolDigest: Data(repeating: 3, count: 32)),
      try fixture.input(source: .preauthorizedPool, swapPoolDomains: true),
      try fixture.input(source: .preauthorizedPool, once: "other"),
      try fixture.input(activation: [8: .bytes(Data(repeating: 3, count: 32))]),
      try fixture.input(activation: [1: .text("other")]),
      try fixture.input(activation: [6: .bytes(Data(repeating: 3, count: 32))]),
    ] { XCTAssertThrowsError(try fixture.verify(input)) }
    try fixture.verify(fixture.rebind(pool, index: 1)).checkPreparation(
      in: fixture.base.environment)
  }

  func testIssuerRoleCohortLifetimeAndDigestBounds() throws {
    let fixture = try CredentialFixture()
    let cases: [V4CredentialInput] = [
      try fixture.input(client: [5: .uint(1)]),
      try fixture.input(client: [1: .text("other")]),
      try fixture.input(client: [12: .uint(8)]),
      try fixture.input(client: [11: .uint(2)]),
      try fixture.input(client: [9: .uint(2001)]),
      try fixture.input(client: [8: .uint(1100), 12: .uint(11)]),
      try fixture.input(client: [13: .text("unregistered")]),
      try fixture.input(artifact: [9: .bytes(Data(repeating: 2, count: 32))]),
      try fixture.input(artifact: [23: .uint(10)]),
      try fixture.input(artifact: [20: .uint(2001)]),
      try fixture.input(activation: [13: .uint(899)]),
      try fixture.input(activation: [14: .uint(1501)]),
      try fixture.input(activation: [15: .uint(1801)]),
      try fixture.input(activation: [2: .text("other")]),
    ]
    for (index, input) in cases.enumerated() {
      XCTAssertThrowsError(try fixture.verify(input), "case \(index)")
    }
    let weakIssuer = try CredentialFixture(issuerEnd: 1600)
    XCTAssertThrowsError(try weakIssuer.verify(weakIssuer.input()))
    let wrongRoleIssuer = try CredentialFixture(clientPermissionSubject: "other")
    XCTAssertThrowsError(try wrongRoleIssuer.verify(wrongRoleIssuer.input()))
    let shortDelegation = try CredentialFixture(activationEnd: 1499)
    XCTAssertThrowsError(try shortDelegation.verify(shortDelegation.input()))
  }

  func testIdentityAndNoiseKeysAreValidatedBeforeCapabilityMinting() throws {
    let fixture = try CredentialFixture()
    for key in [Data(repeating: 0, count: 32), Data([1]) + Data(repeating: 0, count: 31)] {
      XCTAssertThrowsError(try fixture.verify(fixture.input(client: [4: .bytes(key)])))
      XCTAssertThrowsError(
        try fixture.verify(
          fixture.input(client: [3: NamespaceFixture.map([0: .uint(0), 1: .bytes(key)])])))
    }
    let p256 = try CredentialFixture(profile: CredentialFixture.p256Profile)
    try p256.verify(p256.input()).checkPreparation(in: p256.base.environment)
    XCTAssertThrowsError(
      try p256.verify(
        p256.input(client: [
          3: NamespaceFixture.map([
            0: .uint(1), 1: .bytes(Data([4]) + Data(repeating: 0, count: 64)),
          ])
        ])))
  }

  func testCompleteNamespaceClosureRequiresOriginalEnvironmentAndRoleMask() throws {
    let fixture = try CredentialFixture()
    let foreign = try CredentialFixture()
    XCTAssertThrowsError(
      try fixture.base.environment.verifyDirectCredentials(
        configuration: foreign.configuration(), input: fixture.input()))
    for role in [UInt64(1), 2, 7] {
      XCTAssertThrowsError(try fixture.verify(fixture.input(namespaceRole: role)))
    }
    XCTAssertThrowsError(try fixture.verify(fixture.input(namespaceGeneration: 2)))
  }

  func testNewHeadWithoutFullStatePausesExistingCapability() throws {
    let fixture = try CredentialFixture()
    let admission = try fixture.verify(fixture.input())
    let state = fixture.state()
    let head = try fixture.base.head(state: state, sequence: 2)
    XCTAssertThrowsError(try fixture.base.owner!.refresh(head: head, state: Data([0xa0])))
    XCTAssertThrowsError(try admission.checkPreparation(in: fixture.base.environment)) { error in
      XCTAssertEqual(error as? V4NamespaceFailure, .pendingState)
    }
    fixture.base.source.advance(100)
    try fixture.base.owner!.refresh(head: head, state: state)
    try admission.checkPreparation(in: fixture.base.environment)
    fixture.base.source.advance(390)
    XCTAssertThrowsError(try admission.checkPreparation(in: fixture.base.environment))
    try admission.checkSessionAuthorization(in: fixture.base.environment)
  }

  func testOriginalPreparationDeadlineAndCertificateSessionIntersection() throws {
    let fixture = try CredentialFixture()
    let admission = try fixture.verify(fixture.input())
    fixture.base.source.advance(490)
    XCTAssertThrowsError(try admission.checkPreparation(in: fixture.base.environment)) { error in
      XCTAssertEqual(error as? V4TimeFailure, .expired)
    }
    try admission.checkSessionAuthorization(in: fixture.base.environment)
    fixture.base.source.advance(200)
    XCTAssertThrowsError(try admission.checkSessionAuthorization(in: fixture.base.environment))
  }

  func testCurrentCertificateLeaseAndActivationSignerRevocationsFenceCapability() throws {
    for kind in 0..<3 {
      let fixture = try CredentialFixture()
      let input = try fixture.input()
      let admission = try fixture.verify(input)
      let state: Data
      switch kind {
      case 0:
        state = fixture.state(certificates: [
          NamespaceFixture.map([
            0: .bytes(admission.certificateDigests[0]), 1: .uint(9), 2: .uint(1800),
          ])
        ])
      case 1:
        state = fixture.state(leases: [
          NamespaceFixture.map([
            0: .bytes(Data(repeating: 5, count: 16)),
            1: .bytes(Data(repeating: 30, count: 16)),
            2: .bytes(admission.artifactDigest), 3: .uint(9), 4: .uint(1800),
          ])
        ])
      default:
        let impact = NamespaceFixture.map([
          0: .bytes(
            NamespaceFixture.digest(
              "connection-activation-delegation", fixture.activationDelegation.encoded())),
          1: .array([.null, .uint(20)]), 2: .uint(1), 3: .uint(1500),
        ])
        state = fixture.state(issuers: [
          NamespaceFixture.map([
            0: .bytes(Data(repeating: 6, count: 16)), 1: .array([impact]),
          ])
        ])
      }
      try fixture.base.owner!.refresh(
        head: fixture.base.head(state: state, sequence: 2), state: state)
      XCTAssertThrowsError(try admission.checkPreparation(in: fixture.base.environment))
      XCTAssertThrowsError(try fixture.verify(input), "revocation kind \(kind)")
    }
  }

  func testCloseFencesAdmissionAndRetainsOriginalChargeUntilLastAlias() throws {
    for closeEnvironment in [false, true] {
      let fixture = try CredentialFixture()
      var admission: V4CredentialAdmission? = try fixture.verify(fixture.input())
      if closeEnvironment {
        fixture.base.environment.beginClose()
      } else {
        fixture.base.owner!.close()
      }
      XCTAssertThrowsError(try admission!.checkSessionAuthorization(in: fixture.base.environment))
      let retained = fixture.base.root.snapshot()
      XCTAssertGreaterThanOrEqual(retained.used.sdkBytes, V4CredentialVerifier.charge.sdkBytes)
      admission = nil
      XCTAssertEqual(
        retained.used.sdkBytes - fixture.base.root.snapshot().used.sdkBytes,
        V4CredentialVerifier.charge.sdkBytes)
    }
  }

  func testProductionCredentialDecoderMatchesSharedCorpus() throws {
    let schemas: Set<String> = [
      "IdentityCertificate", "NoiseStaticPublicKey", "Artifact", "SessionContract", "ResumePolicy",
      "Candidate", "Route", "Leg", "TLSPolicy", "TLSPin", "OriginPolicy", "ActivationAuthorization",
      "PoolSelectionRef", "PoolSelectionSet", "RekeyEnvelope", "SpendPolicy", "PoolAttemptBudget",
      "PoolRouteRef", "RevocationNamespaceRef", "CandidateAttemptBudget",
    ]
    let corpus = try JSONDecoder().decode(
      V4JSON.self,
      from: Data(
        contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/corpus.json")))
    let registry = try V4NamespaceRegistry()
    var positive = 0
    var negative = 0
    for vector in corpus["vectors"].array! {
      guard let schema = vector["schema"].text, schemas.contains(schema),
        let hex = vector["hex"].text
      else { continue }
      // Membership needs the original Artifact; the signed pool tests above
      // exercise that cross-object production check. This loop checks decoding.
      if vector["expected_error"].text == "pool_set_membership" { continue }
      let bytes = Array(hex.utf8)
      let data = Data(
        stride(from: 0, to: bytes.count, by: 2).map {
          UInt8(String(decoding: bytes[$0...$0 + 1], as: UTF8.self), radix: 16)!
        })
      let limits = vector["limits"].object ?? [:]
      do {
        let decoded = try V4NamespaceDocument(
          data, schema: schema, bytes: 1 << 20, nodes: 32768, registry: registry,
          limits: limits.compactMapValues(\.uint), context: limits.compactMapValues(\.text))
        XCTAssertNil(vector["expected_error"].text, vector["id"].text!)
        XCTAssertEqual(Data(decoded.root.raw), data)
      } catch {
        XCTAssertNotNil(vector["expected_error"].text, "\(vector["id"].text!): \(error)")
      }
      if vector["expected_error"].text == nil { positive += 1 } else { negative += 1 }
    }
    XCTAssertGreaterThan(positive, 40)
    XCTAssertGreaterThan(negative, 150)
    print("Swift production credential codec: \(positive) positive / \(negative) negative")
  }
}

final class CredentialFixture {
  static let x25519Profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1"
  static let p256Profile = "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"
  let base: NamespaceFixture
  let profile: String
  let activationDelegation: V4CBORValue
  private let once: V4CBORValue
  var candidateLeg: V4CBORValue?
  private(set) var bootstrapResponse = Data()
  private(set) var bootstrapState = Data()

  init(
    profile: String = x25519Profile, issuerEnd: UInt64 = 2500,
    clientPermissionSubject: String = "client", activationEnd: UInt64 = 1500
  ) throws {
    base = try NamespaceFixture()
    self.profile = profile
    once = NamespaceFixture.map([
      0: .text("tenant"), 1: .bytes(Data(repeating: 5, count: 16)),
      2: .text("spend"), 3: .text("winner"),
    ])
    activationDelegation = NamespaceFixture.map([
      0: .text("4"), 1: .text("tenant"), 2: .text("authority"),
      3: .bytes(base.capacityDigest), 4: .uint(1), 5: .text("activate"),
      6: .bytes(try NamespaceFixture.key(13).publicKey.rawRepresentation), 7: .uint(1),
      8: .bytes(Data(repeating: 5, count: 16)), 9: .text("spend"), 10: .uint(1),
      11: .uint(1500), 12: .uint(0), 13: .uint(20), 14: .uint(activationEnd), 15: .uint(2000),
      16: .array([.null, .uint(20)]), 17: .bytes(Data(repeating: 6, count: 16)),
    ])
    var permissions: [V4CBORValue] = []
    for role in 0..<3 {
      var fields: [UInt64: V4CBORValue] = [
        0: .bytes(Data(repeating: UInt8(70 + role), count: 16)),
        1: .text("tenant"), 2: .text("authority"), 3: .bytes(base.capacityDigest), 4: .uint(1),
        5: .uint(role == 2 ? 1 : 0), 6: .bytes(Data(repeating: role == 2 ? 5 : 4, count: 16)),
        7: .bytes(try NamespaceFixture.key(role == 2 ? 12 : 11).publicKey.rawRepresentation),
        8: .text("service"), 9: .uint(1), 10: .uint(1500), 11: .uint(0), 12: .uint(20),
        13: .uint(issuerEnd), 15: .text(profile),
        24: .array(role == 2 ? [.null, .uint(20)] : [.uint(20), .null]),
      ]
      if role < 2 {
        fields[14] = .text(role == 0 ? clientPermissionSubject : "server")
        fields[16] = .uint(UInt64(role))
      }
      permissions.append(NamespaceFixture.map(fields))
    }
    let state = state()
    bootstrapState = state
    bootstrapResponse = try base.response(
      state: state, authorizations: permissions,
      policies: [
        NamespaceFixture.map([
          0: .text("credentials"), 1: .uint(1), 2: .uint(1000), 3: .uint(5000),
        ])
      ], activationDelegations: [activationDelegation], onceAuthorities: [once])
    try base.owner!.bootstrap(response: bootstrapResponse, state: state)
  }

  func state(
    issuers: [V4CBORValue] = [], certificates: [V4CBORValue] = [], leases: [V4CBORValue] = []
  ) -> Data {
    base.state(
      issuers: issuers, certificates: certificates, leases: leases,
      segments: [NamespaceFixture.map([0: .uint(0), 1: .uint(20), 2: .uint(1000), 3: .uint(1000)])])
  }

  func configuration(
    tenant: String = "tenant", audience: String = "service", client: String = "client",
    server: String = "server", profiles: [String]? = nil
  ) -> V4CredentialConfiguration {
    V4CredentialConfiguration(
      namespaces: [base.owner!], tenant: tenant, audience: audience,
      clientSubject: client, serverSubject: server, cryptoProfiles: profiles ?? [profile])
  }
  func verify(_ input: V4CredentialInput) throws -> V4CredentialAdmission {
    try base.environment.verifyDirectCredentials(configuration: configuration(), input: input)
  }
  func rebind(_ input: V4CredentialInput, source: V4ActivationSource? = nil, index: Int? = nil)
    -> V4CredentialInput
  {
    V4CredentialInput(
      artifact: input.artifact, clientCertificate: input.clientCertificate,
      serverCertificate: input.serverCertificate, activation: input.activation,
      source: source ?? input.source, candidateIndex: index ?? input.candidateIndex)
  }
  private func leg(_ index: Int) -> V4CBORValue {
    if let candidateLeg { return candidateLeg }
    return NamespaceFixture.map([
      0: .uint(0), 1: .bytes(Data(repeating: UInt8(50 + index), count: 16)), 2: .uint(1),
      3: .uint(0), 4: .uint(1), 5: .uint(0), 6: .text("server.example"), 7: .uint(443),
      8: .text(""), 9: .text("flowersec-direct/4"), 10: .text(""),
      11: NamespaceFixture.map([0: .uint(0), 1: .bool(true)]),
    ])
  }
  func routeDigest(_ index: Int) -> Data {
    NamespaceFixture.digest(
      "route",
      NamespaceFixture.map([
        0: .uint(0), 1: .bytes(Data(repeating: UInt8(40 + index), count: 16)), 2: leg(index),
      ]).encoded())
  }
  private func certificate(_ role: Int, override: [UInt64: V4CBORValue], bad: Bool) throws -> Data {
    let noise: V4CBORValue
    if profile == Self.x25519Profile {
      noise = NamespaceFixture.map([
        0: .uint(0),
        1: .bytes(
          try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: UInt8(31 + role), count: 32)
          ).publicKey.rawRepresentation),
      ])
    } else {
      noise = NamespaceFixture.map([
        0: .uint(1),
        1: .bytes(
          try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: UInt8(31 + role), count: 32)
          ).publicKey.x963Representation),
      ])
    }
    let fields: [UInt64: V4CBORValue] = [
      0: .text("tenant"), 1: .text(role == 0 ? "client" : "server"), 2: .text(profile), 3: noise,
      4: .bytes(try NamespaceFixture.key(UInt8(21 + role)).publicKey.rawRepresentation),
      5: .uint(UInt64(role)), 6: .text("service"), 7: .bytes(Data(repeating: 4, count: 16)),
      8: .uint(900), 9: .uint(role == 0 ? 1800 : 1700), 10: .text("authority"),
      11: .uint(1), 12: .uint(9), 13: .text("credentials"), 14: .uint(1),
      15: .bytes(base.capacityDigest),
    ]
    return try NamespaceFixture.signed(
      fields.merging(override) { _, new in new }, signature: 16,
      label: "certificate/signature", seed: bad ? 14 : 11)
  }

  func input(
    source: V4ActivationSource = .liveAuthority, indices: [UInt64] = [0, 1],
    client: [UInt64: V4CBORValue] = [:], server: [UInt64: V4CBORValue] = [:],
    artifact: [UInt64: V4CBORValue] = [:], activation: [UInt64: V4CBORValue] = [:],
    badSignature: String? = nil, poolDigest: Data? = nil, swapPoolDomains: Bool = false,
    once spend: String = "spend", namespaceRole: UInt64 = 3, namespaceGeneration: UInt64 = 1
  ) throws -> V4CredentialInput {
    let clientBytes = try certificate(0, override: client, bad: badSignature == "client")
    let serverBytes = try certificate(1, override: server, bad: badSignature == "server")
    let clientDigest = NamespaceFixture.digest("certificate-digest", clientBytes)
    let serverDigest = NamespaceFixture.digest("certificate-digest", serverBytes)
    let namespace = NamespaceFixture.map([
      0: .text("tenant"), 1: .text("authority"), 2: .uint(namespaceGeneration),
      3: .bytes(base.capacityDigest), 4: .uint(namespaceRole),
    ])
    let candidates: [V4CBORValue] = (0..<2).map { index in
      NamespaceFixture.map([
        0: .bytes(Data(repeating: UInt8(40 + index), count: 16)), 1: .uint(UInt64(index)),
        2: .uint(0), 3: leg(index), 6: .array([namespace]),
      ])
    }
    let fields: [UInt64: V4CBORValue] = [
      0: .text("4"), 1: .text("flowersec/4"), 2: .text("4"), 3: .text(profile),
      4: .text("tenant"), 5: .bytes(Data(repeating: 5, count: 16)),
      6: .bytes(Data(repeating: 30, count: 16)), 7: .bytes(Data(repeating: 31, count: 32)),
      8: .bytes(Data(repeating: 32, count: 32)), 9: .bytes(clientDigest), 10: .bytes(serverDigest),
      11: .text("service"), 12: .array(candidates),
      13: NamespaceFixture.map([
        0: .uint(1_048_576), 1: .uint(16), 2: .uint(16384), 3: .uint(0),
        4: NamespaceFixture.map([0: .uint(1), 1: .uint(1000), 2: .uint(1000)]), 5: .uint(0),
      ]), 14: .uint(0), 15: .uint(0), 16: NamespaceFixture.map([0: .bool(false)]),
      17: NamespaceFixture.map([0: .uint(0)]), 18: .uint(900), 19: .uint(1500), 20: .uint(1800),
      21: .text("authority"), 22: .uint(1), 23: .uint(9), 24: .text("credentials"), 25: .uint(1),
      26: .bytes(base.capacityDigest),
    ]
    let artifactBytes = try NamespaceFixture.signed(
      fields.merging(artifact) { _, new in new }, signature: 27,
      label: "artifact/signature", seed: badSignature == "artifact" ? 14 : 12)
    let artifactDigest = NamespaceFixture.digest("artifact-digest", artifactBytes)
    var selection: V4CBORValue = .bytes(Data(repeating: 40, count: 16))
    var route = routeDigest(0)
    if source == .preauthorizedPool {
      let set = NamespaceFixture.map([
        0: .bytes(artifactDigest),
        1: .array(
          indices.map { index in
            NamespaceFixture.map([
              0: .uint(index), 1: .bytes(Data(repeating: UInt8(40 + index), count: 16)),
              2: .bytes(routeDigest(Int(index))),
            ])
          }),
      ]).encoded()
      let candidateSet = NamespaceFixture.digest("candidate-set", set)
      let routeSet = NamespaceFixture.digest("route-set", set)
      selection = NamespaceFixture.map([
        0: .bytes(artifactDigest), 1: .array(indices.map(V4CBORValue.uint)),
        2: .bytes(poolDigest ?? (swapPoolDomains ? routeSet : candidateSet)),
        3: NamespaceFixture.map([
          0: NamespaceFixture.map([0: .uint(1), 1: .uint(4096), 2: .uint(8)]),
          1: .uint(2), 2: .uint(8192), 3: .uint(16), 4: .uint(1),
        ]),
        4: NamespaceFixture.map([
          0: .text("tenant"), 1: .bytes(Data(repeating: 5, count: 16)),
          2: .text(spend), 3: .text("winner"),
        ]),
      ])
      route = swapPoolDomains ? candidateSet : routeSet
    }
    let activationFields: [UInt64: V4CBORValue] = [
      0: .uint(1), 1: .text("spend"), 2: .text("activate"), 3: .text("tenant"),
      4: .bytes(Data(repeating: 5, count: 16)), 5: .bytes(Data(repeating: 30, count: 16)),
      6: .bytes(artifactDigest), 7: selection, 8: .bytes(route),
      9: .bytes(Data(repeating: 33, count: 16)), 10: .bytes(clientDigest), 11: .bytes(serverDigest),
      12: .text("service"), 13: .uint(900), 14: .uint(1500), 15: .uint(1800),
    ]
    let activationBytes = try NamespaceFixture.signed(
      activationFields.merging(activation) { _, new in new }, signature: 16,
      label: "activation_authorization/signature", seed: badSignature == "activation" ? 14 : 13)
    return V4CredentialInput(
      artifact: artifactBytes, clientCertificate: clientBytes, serverCertificate: serverBytes,
      activation: activationBytes, source: source, candidateIndex: 0)
  }
}
