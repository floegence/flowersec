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
    try validate()
    return try FlowersecJCSV3.encode([
      "language": language, "runtime": runtime, "schemaVersion": schemaVersion,
      "tuples": tuples.map { $0.object() }, "unsupported": unsupported.map { $0.object() },
    ])
  }

  func digest() throws -> Data {
    FlowersecJCSV3.hashLP(
      domain: "flowersec-v3-runtime-capability\0", canonical: try canonicalJSON())
  }

  static func decode(_ data: Data) throws -> RuntimeCapabilityDescriptorV3 {
    do {
      try JSONPreflightV3.validate(data)
      let raw = try JSONSerialization.jsonObject(with: data)
      guard let object = raw as? [String: Any], try FlowersecJCSV3.encode(raw) == data else {
        throw ArtifactErrorV3.invalidArtifact
      }
      try exact(object, ["language", "runtime", "schemaVersion", "tuples", "unsupported"])
      guard let tuples = object["tuples"] as? [[String: Any]],
        let unsupported = object["unsupported"] as? [[String: Any]]
      else { throw ArtifactErrorV3.invalidArtifact }
      for tuple in tuples {
        try exact(tuple, [
          "carrier", "datagrams", "migration", "networkMode", "path", "reliableStreams",
          "securityModes", "sessionRole",
        ])
      }
      for item in unsupported { try exact(item, ["carrier", "reason"]) }
      let descriptor = try JSONDecoder().decode(RuntimeCapabilityDescriptorV3.self, from: data)
      try descriptor.validate()
      return descriptor
    } catch let error as ArtifactErrorV3 {
      throw error
    } catch {
      throw ArtifactErrorV3.invalidArtifact
    }
  }

  private func validate() throws {
    guard schemaVersion == 3, language == "swift", ["ios", "macos", "linux"].contains(runtime)
    else { throw ArtifactErrorV3.invalidArtifact }
    let expected = RuntimeCapabilitiesV3.forRuntime(runtime)
    guard self == expected else { throw ArtifactErrorV3.invalidArtifact }
  }

  private static func exact(_ object: [String: Any], _ expected: [String]) throws {
    guard object.keys.sorted() == expected.sorted() else { throw ArtifactErrorV3.invalidArtifact }
  }
}

enum RuntimeCapabilitiesV3 {
  static let iOS = apple(runtime: "ios")
  static let macOS = apple(runtime: "macos")
  static let linux = RuntimeCapabilityDescriptorV3(
    language: "swift", runtime: "linux", schemaVersion: 3, tuples: [],
    unsupported: [
      UnsupportedRuntimeCarrierV3(
        carrier: .rawQUIC, reason: "swift_apple_client_profile_excludes_raw_quic"),
      UnsupportedRuntimeCarrierV3(
        carrier: .webSocket, reason: "websocket_adapter_not_supported_on_linux"),
      UnsupportedRuntimeCarrierV3(
        carrier: .webTransport, reason: "swift_apple_client_profile_excludes_webtransport"),
    ])

  static func forRuntime(_ runtime: String) -> RuntimeCapabilityDescriptorV3 {
    switch runtime {
    case "ios": iOS
    case "macos": macOS
    default: linux
    }
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
    guard activePins.contains(where: { constantTimeEqual($0, digest) }) else {
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
  static let directProfile = "flowersec-direct/3"
  static let tunnelProfile = "flowersec-tunnel/3"
  static let directWebSocketPath = "/flowersec/v3/direct"
  static let tunnelWebSocketPath = "/flowersec/v3/tunnel"
  static let directWebSocketSubprotocol = "flowersec.direct.v3"
  static let tunnelWebSocketSubprotocol = "flowersec.tunnel.v3"
}
