import Crypto
import Foundation

enum TransportSecurityFailureV3: Error, Equatable, Sendable {
  case tlsUnsupported
  case tlsPolicyExpired
  case caUntrusted
  case pinMismatch
  case unknownTLS
}

enum TransportSecurityPolicyV3: Equatable, Sendable {
  enum RootsSource: Equatable, Sendable { case platform, configured }
  case ca(serverName: String, rootsSource: RootsSource)
  case pin(serverName: String, activeLeafDERSHA256: [Data])
}

enum RuntimeCarrierV3: String, Codable, Equatable, Sendable {
  case rawQUIC = "raw_quic"
  case webSocket = "websocket"
  case webTransport = "webtransport"
}
enum RuntimeNetworkModeV3: String, Codable, Equatable, Sendable { case dial, listen }
enum RuntimePathV3: String, Codable, Equatable, Sendable { case direct, tunnel }
enum RuntimeSessionRoleV3: String, Codable, Equatable, Sendable { case client, server }
typealias SessionRoleV3 = RuntimeSessionRoleV3

struct RuntimeCapabilityTupleV3: Codable, Equatable, Sendable {
  let carrier: RuntimeCarrierV3
  let datagrams: Bool
  let migration: Bool
  let networkMode: RuntimeNetworkModeV3
  let path: RuntimePathV3
  let reliableStreams: Bool
  let securityModes: [String]
  let sessionRole: RuntimeSessionRoleV3

  func object() -> [String: Any] {
    [
      "carrier": carrier.rawValue, "datagrams": datagrams, "migration": migration,
      "networkMode": networkMode.rawValue, "path": path.rawValue,
      "reliableStreams": reliableStreams, "securityModes": securityModes,
      "sessionRole": sessionRole.rawValue,
    ]
  }
}

struct UnsupportedRuntimeCarrierV3: Codable, Equatable, Sendable {
  let carrier: RuntimeCarrierV3
  let reason: String
  func object() -> [String: Any] { ["carrier": carrier.rawValue, "reason": reason] }
}

struct RuntimeCapabilityDescriptorV3: Codable, Equatable, Sendable {
  let language: String
  let runtime: String
  let schemaVersion: UInt8
  let tuples: [RuntimeCapabilityTupleV3]
  let unsupported: [UnsupportedRuntimeCarrierV3]

  func canonicalJSON() throws -> Data {
    try validateWireDescriptor()
    return try FlowersecJCSV3.encode([
      "language": language, "runtime": runtime, "schemaVersion": schemaVersion,
      "tuples": tuples.map { $0.object() }, "unsupported": unsupported.map { $0.object() },
    ])
  }

  func digest() throws -> Data {
    FlowersecJCSV3.hashLP(
      domain: TransportV3Contract.runtimeCapabilityLabel, canonical: try canonicalJSON())
  }

  static func decode(_ data: Data) throws -> RuntimeCapabilityDescriptorV3 {
    do {
      try JSONPreflightV3.validate(data)
      let raw = try JSONSerialization.jsonObject(with: data)
      guard let object = raw as? [String: Any], try FlowersecJCSV3.encode(raw) == data else {
        throw ArtifactError.invalidArtifact
      }
      try exact(object, ["language", "runtime", "schemaVersion", "tuples", "unsupported"])
      guard let tuples = object["tuples"] as? [[String: Any]],
        let unsupported = object["unsupported"] as? [[String: Any]]
      else { throw ArtifactError.invalidArtifact }
      for tuple in tuples {
        try exact(
          tuple,
          [
            "carrier", "datagrams", "migration", "networkMode", "path", "reliableStreams",
            "securityModes", "sessionRole",
          ])
      }
      for item in unsupported { try exact(item, ["carrier", "reason"]) }
      let descriptor = try JSONDecoder().decode(RuntimeCapabilityDescriptorV3.self, from: data)
      try descriptor.validateWireDescriptor()
      return descriptor
    } catch let error as ArtifactError {
      throw error
    } catch {
      throw ArtifactError.invalidArtifact
    }
  }

  func validateLocalRuntimeProfile(_ expectedRuntime: String) throws {
    try validateWireDescriptor()
    guard language == "swift", runtime == expectedRuntime,
      self == RuntimeCapabilitiesV3.uncheckedProfile(for: expectedRuntime)
    else { throw ArtifactError.invalidArtifact }
  }

  private func validateWireDescriptor() throws {
    guard schemaVersion == 3, capabilityTokenV3(language), capabilityTokenV3(runtime),
      !tuples.isEmpty || !unsupported.isEmpty
    else { throw ArtifactError.invalidArtifact }

    var previousTuple: RuntimeCapabilityTupleV3?
    for tuple in tuples {
      try validateCapabilityTupleV3(tuple)
      if let previousTuple, compareCapabilityTupleIdentityV3(previousTuple, tuple) >= 0 {
        throw ArtifactError.invalidArtifact
      }
      previousTuple = tuple
    }
    var previousUnsupported: RuntimeCarrierV3?
    for item in unsupported {
      guard registeredUnsupportedReasonV3(item.reason),
        !tuples.contains(where: { $0.carrier == item.carrier })
      else { throw ArtifactError.invalidArtifact }
      if let previousUnsupported,
        previousUnsupported.rawValue >= item.carrier.rawValue
      {
        throw ArtifactError.invalidArtifact
      }
      previousUnsupported = item.carrier
    }
    for carrier in [RuntimeCarrierV3.rawQUIC, .webSocket, .webTransport] {
      let supported = tuples.contains(where: { $0.carrier == carrier })
      let unavailable = unsupported.contains(where: { $0.carrier == carrier })
      guard supported != unavailable else { throw ArtifactError.invalidArtifact }
    }
    try validateRegisteredRuntimeV3(self)
  }

  private static func exact(_ object: [String: Any], _ expected: [String]) throws {
    guard object.keys.sorted() == expected.sorted() else { throw ArtifactError.invalidArtifact }
  }
}

enum RuntimeCapabilitiesV3 {
  static let iOS = fixedProfile(for: "ios")
  static let macOS = fixedProfile(for: "macos")
  static let linux = fixedProfile(for: "linux")

  fileprivate static func uncheckedProfile(for runtime: String) -> RuntimeCapabilityDescriptorV3 {
    if runtime == "ios" || runtime == "macos" { return apple(runtime: runtime) }
    return RuntimeCapabilityDescriptorV3(
      language: "swift", runtime: "linux", schemaVersion: 3, tuples: [],
      unsupported: [
        UnsupportedRuntimeCarrierV3(
          carrier: .rawQUIC, reason: "swift_apple_client_profile_excludes_raw_quic"),
        UnsupportedRuntimeCarrierV3(
          carrier: .webSocket, reason: "websocket_adapter_not_supported_on_linux"),
        UnsupportedRuntimeCarrierV3(
          carrier: .webTransport, reason: "swift_apple_client_profile_excludes_webtransport"),
      ])
  }

  static func forRuntime(_ runtime: String) -> RuntimeCapabilityDescriptorV3 {
    switch runtime {
    case "ios": iOS
    case "macos": macOS
    default: linux
    }
  }

  private static func fixedProfile(for runtime: String) -> RuntimeCapabilityDescriptorV3 {
    let descriptor = uncheckedProfile(for: runtime)
    precondition((try? descriptor.validateLocalRuntimeProfile(runtime)) != nil)
    return descriptor
  }

  private static func apple(runtime: String) -> RuntimeCapabilityDescriptorV3 {
    RuntimeCapabilityDescriptorV3(
      language: "swift", runtime: runtime, schemaVersion: 3,
      tuples: [
        RuntimeCapabilityTupleV3(
          carrier: .webSocket, datagrams: false, migration: false, networkMode: .dial,
          path: .direct, reliableStreams: true, securityModes: ["ca", "pin"], sessionRole: .client),
        RuntimeCapabilityTupleV3(
          carrier: .webSocket, datagrams: false, migration: false, networkMode: .dial,
          path: .tunnel, reliableStreams: true, securityModes: ["ca", "pin"], sessionRole: .client),
        RuntimeCapabilityTupleV3(
          carrier: .webSocket, datagrams: false, migration: false, networkMode: .dial,
          path: .tunnel, reliableStreams: true, securityModes: ["ca", "pin"], sessionRole: .server),
      ],
      unsupported: [
        UnsupportedRuntimeCarrierV3(
          carrier: .rawQUIC, reason: "swift_apple_client_profile_excludes_raw_quic"),
        UnsupportedRuntimeCarrierV3(
          carrier: .webTransport, reason: "swift_apple_client_profile_excludes_webtransport"),
      ])
  }
}

private func capabilityTokenV3(_ value: String) -> Bool {
  let bytes = Array(value.utf8)
  guard !bytes.isEmpty, bytes.count <= 128, (97...122).contains(bytes[0]) else { return false }
  return bytes.dropFirst().allSatisfy {
    (97...122).contains($0) || (48...57).contains($0) || $0 == 95
  }
}

private func compareCapabilityTupleIdentityV3(
  _ lhs: RuntimeCapabilityTupleV3, _ rhs: RuntimeCapabilityTupleV3
) -> Int {
  let left = [
    lhs.carrier.rawValue, lhs.networkMode.rawValue, lhs.sessionRole.rawValue, lhs.path.rawValue,
  ]
  let right = [
    rhs.carrier.rawValue, rhs.networkMode.rawValue, rhs.sessionRole.rawValue, rhs.path.rawValue,
  ]
  for (lhs, rhs) in zip(left, right) {
    if lhs != rhs { return lhs < rhs ? -1 : 1 }
  }
  return 0
}

private func validateCapabilityTupleV3(_ tuple: RuntimeCapabilityTupleV3) throws {
  let validDeployment: Bool
  switch tuple.path {
  case .direct:
    validDeployment =
      (tuple.networkMode == .dial && tuple.sessionRole == .client)
      || (tuple.networkMode == .listen && tuple.sessionRole == .server)
  case .tunnel:
    validDeployment = tuple.networkMode == .dial
  }
  let validModes =
    tuple.networkMode == .listen
    ? tuple.securityModes.isEmpty
    : tuple.securityModes == ["ca"] || tuple.securityModes == ["pin"]
      || tuple.securityModes == ["ca", "pin"]
  guard tuple.reliableStreams, validDeployment, validModes,
    tuple.carrier != .webSocket || (!tuple.datagrams && !tuple.migration)
  else { throw ArtifactError.invalidArtifact }
}

private func registeredCapabilityTuplesV3(
  carrier: RuntimeCarrierV3, datagrams: Bool, dialMigration: Bool,
  includeListener: Bool, securityModes: [String]
) -> [RuntimeCapabilityTupleV3] {
  var tuples = [
    RuntimeCapabilityTupleV3(
      carrier: carrier, datagrams: datagrams, migration: dialMigration,
      networkMode: .dial, path: .direct, reliableStreams: true,
      securityModes: securityModes, sessionRole: .client),
    RuntimeCapabilityTupleV3(
      carrier: carrier, datagrams: datagrams, migration: dialMigration,
      networkMode: .dial, path: .tunnel, reliableStreams: true,
      securityModes: securityModes, sessionRole: .client),
    RuntimeCapabilityTupleV3(
      carrier: carrier, datagrams: datagrams, migration: dialMigration,
      networkMode: .dial, path: .tunnel, reliableStreams: true,
      securityModes: securityModes, sessionRole: .server),
  ]
  if includeListener {
    tuples.append(
      RuntimeCapabilityTupleV3(
        carrier: carrier, datagrams: datagrams, migration: false,
        networkMode: .listen, path: .direct, reliableStreams: true,
        securityModes: [], sessionRole: .server))
  }
  return tuples
}

private func validateRegisteredCarrierV3(
  _ descriptor: RuntimeCapabilityDescriptorV3, carrier: RuntimeCarrierV3,
  tupleSets: [[RuntimeCapabilityTupleV3]], unsupportedReasons: [String]
) throws {
  let actual = descriptor.tuples.filter { $0.carrier == carrier }
  if let item = descriptor.unsupported.first(where: { $0.carrier == carrier }) {
    guard actual.isEmpty, unsupportedReasons.contains(item.reason)
    else { throw ArtifactError.invalidArtifact }
  } else {
    guard tupleSets.contains(actual) else { throw ArtifactError.invalidArtifact }
  }
}

private func validateRegisteredRuntimeV3(_ descriptor: RuntimeCapabilityDescriptorV3) throws {
  let ca = ["ca"]
  let caPin = ["ca", "pin"]
  let w4 = {
    registeredCapabilityTuplesV3(
      carrier: .webSocket, datagrams: false, dialMigration: false,
      includeListener: true, securityModes: $0)
  }
  let w3 = {
    registeredCapabilityTuplesV3(
      carrier: .webSocket, datagrams: false, dialMigration: false,
      includeListener: false, securityModes: $0)
  }
  let q4m = registeredCapabilityTuplesV3(
    carrier: .rawQUIC, datagrams: true, dialMigration: true,
    includeListener: true, securityModes: caPin)
  let q4n = registeredCapabilityTuplesV3(
    carrier: .rawQUIC, datagrams: true, dialMigration: false,
    includeListener: true, securityModes: caPin)
  let h4 = registeredCapabilityTuplesV3(
    carrier: .webTransport, datagrams: true, dialMigration: false,
    includeListener: true, securityModes: caPin)
  let h3ca = registeredCapabilityTuplesV3(
    carrier: .webTransport, datagrams: true, dialMigration: false,
    includeListener: false, securityModes: ca)
  let h3pin = registeredCapabilityTuplesV3(
    carrier: .webTransport, datagrams: true, dialMigration: false,
    includeListener: false, securityModes: caPin)
  let identity = "\(descriptor.language)/\(descriptor.runtime)"
  switch identity {
  case "go/native":
    try validateRegisteredCarrierV3(
      descriptor, carrier: .rawQUIC, tupleSets: [q4m], unsupportedReasons: [])
    try validateRegisteredCarrierV3(
      descriptor, carrier: .webSocket, tupleSets: [w4(caPin)], unsupportedReasons: [])
    try validateRegisteredCarrierV3(
      descriptor, carrier: .webTransport, tupleSets: [h4], unsupportedReasons: [])
  case "typescript/browser":
    try validateRegisteredCarrierV3(
      descriptor, carrier: .rawQUIC, tupleSets: [], unsupportedReasons: ["browser_no_raw_udp"])
    try validateRegisteredCarrierV3(
      descriptor, carrier: .webSocket, tupleSets: [w3(ca)],
      unsupportedReasons: ["browser_websocket_api_unavailable"])
    try validateRegisteredCarrierV3(
      descriptor, carrier: .webTransport, tupleSets: [h3ca, h3pin],
      unsupportedReasons: ["browser_webtransport_api_unavailable"])
  case "typescript/node":
    try validateRegisteredCarrierV3(
      descriptor, carrier: .rawQUIC, tupleSets: [q4n],
      unsupportedReasons: ["node_native_transport_unavailable"])
    try validateRegisteredCarrierV3(
      descriptor, carrier: .webSocket, tupleSets: [w4(caPin)], unsupportedReasons: [])
    try validateRegisteredCarrierV3(
      descriptor, carrier: .webTransport, tupleSets: [],
      unsupportedReasons: ["node_webtransport_driver_unavailable"])
  case "rust/native":
    try validateRegisteredCarrierV3(
      descriptor, carrier: .rawQUIC, tupleSets: [q4m], unsupportedReasons: [])
    try validateRegisteredCarrierV3(
      descriptor, carrier: .webSocket, tupleSets: [w4(caPin)], unsupportedReasons: [])
    try validateRegisteredCarrierV3(
      descriptor, carrier: .webTransport, tupleSets: [], unsupportedReasons: ["driver_unavailable"])
  case "swift/ios", "swift/macos":
    try validateRegisteredCarrierV3(
      descriptor, carrier: .rawQUIC, tupleSets: [],
      unsupportedReasons: ["swift_apple_client_profile_excludes_raw_quic"])
    try validateRegisteredCarrierV3(
      descriptor, carrier: .webSocket, tupleSets: [w3(caPin)], unsupportedReasons: [])
    try validateRegisteredCarrierV3(
      descriptor, carrier: .webTransport, tupleSets: [],
      unsupportedReasons: ["swift_apple_client_profile_excludes_webtransport"])
  case "swift/linux":
    try validateRegisteredCarrierV3(
      descriptor, carrier: .rawQUIC, tupleSets: [],
      unsupportedReasons: ["swift_apple_client_profile_excludes_raw_quic"])
    try validateRegisteredCarrierV3(
      descriptor, carrier: .webSocket, tupleSets: [],
      unsupportedReasons: ["websocket_adapter_not_supported_on_linux"])
    try validateRegisteredCarrierV3(
      descriptor, carrier: .webTransport, tupleSets: [],
      unsupportedReasons: ["swift_apple_client_profile_excludes_webtransport"])
  default:
    throw ArtifactError.invalidArtifact
  }
}

private func registeredUnsupportedReasonV3(_ value: String) -> Bool {
  [
    "adapter_not_composed",
    "browser_no_raw_udp",
    "browser_websocket_api_unavailable",
    "browser_webtransport_api_unavailable",
    "driver_unavailable",
    "node_native_transport_unavailable",
    "node_webtransport_driver_unavailable",
    "swift_apple_client_profile_excludes_raw_quic",
    "swift_apple_client_profile_excludes_webtransport",
    "websocket_adapter_not_supported_on_linux",
  ].contains(value)
}

enum LeafPublicKeyV3: Equatable, Sendable { case ecdsaP256, other }

struct PresentedLeafCertificateV3: Sendable {
  let der: Data
  let x509Version: Int
  let notBeforeUnixSeconds: Int64
  let notAfterUnixSeconds: Int64
  let publicKey: LeafPublicKeyV3
  let tlsProofComplete: Bool
}

enum PinVerifierV3 {
  static func verifyStatic(
    leaf: PresentedLeafCertificateV3, activePins: [Data], nowUnixSeconds: Int64
  ) throws {
    guard !leaf.der.isEmpty, leaf.x509Version == 3,
      nowUnixSeconds >= leaf.notBeforeUnixSeconds,
      nowUnixSeconds < leaf.notAfterUnixSeconds,
      leaf.notAfterUnixSeconds > leaf.notBeforeUnixSeconds,
      leaf.publicKey == .ecdsaP256
    else { throw TransportSecurityFailureV3.unknownTLS }
    let lifetime = leaf.notAfterUnixSeconds.subtractingReportingOverflow(
      leaf.notBeforeUnixSeconds)
    guard !lifetime.overflow, lifetime.partialValue <= 1_209_600 else {
      throw TransportSecurityFailureV3.unknownTLS
    }
    let digest = Data(SHA256.hash(data: leaf.der))
    var matched: UInt8 = 0
    for pin in activePins {
      if constantTimeEqual(pin, digest) { matched |= 1 }
    }
    guard matched != 0 else {
      throw TransportSecurityFailureV3.pinMismatch
    }
  }

  static func verify(
    leaf: PresentedLeafCertificateV3, activePins: [Data], nowUnixSeconds: Int64
  ) throws {
    try verifyStatic(leaf: leaf, activePins: activePins, nowUnixSeconds: nowUnixSeconds)
    guard leaf.tlsProofComplete else { throw TransportSecurityFailureV3.unknownTLS }
  }

  private static func constantTimeEqual(_ left: Data, _ right: Data) -> Bool {
    guard left.count == right.count else { return false }
    var difference: UInt8 = 0
    for (lhs, rhs) in zip(left, right) { difference |= lhs ^ rhs }
    return difference == 0
  }
}

enum TransportV3Contract {
  static let frameMagics = ["FSB3", "FSA3", "FSC3", "FSH3", "FSS3", "FSR3", "FSD3"]
  static let sessionProfile = "flowersec/3"
  static let directProfile = "flowersec-direct/3"
  static let tunnelProfile = "flowersec-tunnel/3"
  static let directWebSocketPath = "/flowersec/v3/direct"
  static let tunnelWebSocketPath = "/flowersec/v3/tunnel"
  static let directWebTransportPath = "/flowersec/webtransport/v3/direct"
  static let tunnelWebTransportPath = "/flowersec/webtransport/v3/tunnel"
  static let directWebSocketSubprotocol = "flowersec.direct.v3"
  static let tunnelWebSocketSubprotocol = "flowersec.tunnel.v3"

  static func wireProfile(for kind: String) -> String {
    switch kind {
    case "direct": return directProfile
    case "tunnel": return tunnelProfile
    default: return ""
    }
  }

  static func webSocketPath(for kind: String) -> String {
    switch kind {
    case "direct": return directWebSocketPath
    case "tunnel": return tunnelWebSocketPath
    default: return ""
    }
  }

  static func webTransportPath(for kind: String) -> String {
    switch kind {
    case "direct": return directWebTransportPath
    case "tunnel": return tunnelWebTransportPath
    default: return ""
    }
  }

  static let sessionContractLabel = "flowersec-v3-session-contract\0"
  static let candidatesLabel = "flowersec-v3-candidates\0"
  static let admissionLabel = "flowersec-v3-admission\0"
  static let runtimeCapabilityLabel = "flowersec-v3-runtime-capability\0"
  static let handshakeDomain = "flowersec-v3-handshake\0"
  static let serverFinishedLabel = "flowersec v3 server finished"
  static let clientFinishedLabel = "flowersec v3 client finished"
  static let epochZeroLabel = "flowersec v3 epoch zero"
  static let controlRootLabel = "flowersec v3 control root"
  static let streamRootLabel = "flowersec v3 stream root"
  static let setupRootLabel = "flowersec v3 setup root"
  static let rekeyRootLabel = "flowersec v3 rekey root"
  static let nextEpochLabel = "flowersec v3 next epoch"
  static let streamLabel = "flowersec v3 stream"
  static let controlLabel = "flowersec v3 control"
  static let recordKeyLabel = "flowersec v3 record key"
  static let nonceLabel = "flowersec v3 nonce"
  static let unreliableRootLabel = "flowersec v3 unreliable root"
  static let unreliableLabel = "flowersec v3 unreliable"
  static let unreliableKeyLabel = "flowersec v3 unreliable key"
  static let unreliableNonceLabel = "flowersec v3 unreliable nonce"
  static let unreliableDomain = "flowersec-v3-unreliable"
  static let setupDomain = "flowersec-v3-setup"
  static let recordDomain = "flowersec-v3-record"
  static let openDomain = "flowersec-v3-open\0"
  static let acceptorAdmissionsLabel = "flowersec-v3-acceptor-admissions\0"

}
