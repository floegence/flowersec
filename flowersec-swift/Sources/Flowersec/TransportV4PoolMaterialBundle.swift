import Foundation

/// Complete reference pool material. The envelope supplies no credential or
/// trust authority; every selected signed map is verified in the TransportEnvironment.
struct V4PoolMaterialBundle: Sendable, CustomStringConvertible {
  struct Tunnel: Sendable {
    let candidateIndex: Int
    let role: UInt64
    let grant: Data
    let relayCertificate: Data
  }
  let artifact: Data
  let activation: Data
  let clientCertificate: Data
  let serverCertificate: Data
  let grant: Data
  let relayCertificate: Data
  let tunnels: [Tunnel]
  var description: String { "Flowersec.PoolMaterialBundle(<redacted>)" }
  #if os(macOS) || os(iOS)
  static func decode(_ wire: Data) throws -> Self {
    var cursor = V4PoolWireCursor(wire, maximum: 65_536)
    let count = try cursor.arrayCount(maximum: 6)
    guard (4...6).contains(count) else { throw TransportControlError.responseInvalid }
    func required(_ bytes: Data) throws -> Data {
      guard !bytes.isEmpty else { throw TransportControlError.responseInvalid }; return bytes
    }
    let artifact = try required(cursor.bytes(maximum: 65_535))
    let activation = try required(cursor.bytes(maximum: 4096))
    let client = try required(cursor.bytes(maximum: 8192))
    let server = try required(cursor.bytes(maximum: 8192))
    var grant = Data(); var relay = Data(); var tunnels: [Tunnel] = []
    if count == 6 {
      grant = try required(cursor.bytes(maximum: 9302))
      relay = try required(cursor.bytes(maximum: 8192))
    } else if count == 5 {
      let entries = try cursor.arrayCount(maximum: 32)
      guard entries > 0 else { throw TransportControlError.responseInvalid }
      var previous: (UInt64, UInt64)?
      for _ in 0..<entries {
        try cursor.array(4)
        let index = try cursor.uint(); let role = try cursor.uint()
        guard index < 16, role <= 1,
          previous == nil || index > previous!.0 || (index == previous!.0 && role > previous!.1)
        else { throw TransportControlError.responseInvalid }
        tunnels.append(.init(candidateIndex: Int(index), role: role,
          grant: try required(cursor.bytes(maximum: 9302)), relayCertificate: try required(cursor.bytes(maximum: 8192))))
        previous = (index, role)
      }
    }
    try cursor.end()
    return Self(artifact: artifact, activation: activation, clientCertificate: client,
      serverCertificate: server, grant: grant, relayCertificate: relay, tunnels: tunnels)
  }
  func credential(candidateIndex: Int = 0) throws -> TransportPoolCredential {
    let selected = tunnels.filter { $0.candidateIndex == candidateIndex && $0.role == 0 }
    guard selected.count <= 1 else { throw TransportControlError.responseInvalid }
    return material(candidateIndex: candidateIndex, grant: selected.first?.grant ?? grant,
      relay: selected.first?.relayCertificate ?? relayCertificate)
  }
  private func material(candidateIndex: Int, grant: Data, relay: Data) -> TransportPoolCredential {
    TransportPoolCredential(input: V4CredentialInput(artifact: artifact,
      clientCertificate: clientCertificate, serverCertificate: serverCertificate,
      activation: activation, source: .preauthorizedPool, candidateIndex: candidateIndex,
      grant: grant, relayCertificate: relay, poolTunnels: tunnels))
  }
  // Qualify every local tunnel pair before the batch becomes available. A
  // remote role remains bounded original bytes, not a local trust dependency.
  // Candidate choice is made only among the original activation's pool set.
  func validatedCredential(client: V4ClientEnvironment, identity: TransportApplicationIdentity,
    registry: V4NamespaceRegistry) throws -> TransportPoolCredential {
    let parent = try V4NamespaceDocument(artifact, schema: "Artifact", bytes: 65_536,
      nodes: 16_384, registry: registry).root
    let candidates = try parent.field("candidates").children.map { $0 }
    let authorization = try V4NamespaceDocument(activation, schema: "ActivationAuthorization",
      bytes: 4096, nodes: 4096, registry: registry,
      context: ["activation_source_profile": V4ActivationSource.preauthorizedPool.rawValue]).root
    let allowed = try authorization.field("candidate_selection").field("candidate_indices")
      .children.map { try Int($0.uint()) }
    var local: [Int: Tunnel] = [:]
    for entry in tunnels {
      guard candidates.indices.contains(entry.candidateIndex),
        try candidates[entry.candidateIndex].u("path_kind") == 1
      else { throw TransportControlError.responseInvalid }
      if entry.role == 0 { local[entry.candidateIndex] = entry }
    }
    if !grant.isEmpty {
      let signed = try V4NamespaceDocument(grant, schema: "Grant", bytes: 9302, nodes: 4096, registry: registry).root
      let candidateID = try signed.field("route_descriptor").b("candidate_id")
      guard let selected = try candidates.enumerated().first(where: { try $0.element.b("candidate_id") == candidateID }),
        try selected.element.u("path_kind") == 1, local.isEmpty
      else { throw TransportControlError.responseInvalid }
      local[selected.offset] = Tunnel(candidateIndex: selected.offset, role: 0, grant: grant,
        relayCertificate: relayCertificate)
    }
    if !tunnels.isEmpty && local.isEmpty { throw TransportControlError.responseInvalid }
    for (index, tunnel) in local.sorted(by: { $0.key < $1.key }) {
      guard allowed.contains(index) else { throw TransportControlError.responseInvalid }
      _ = try client.validatePoolCredential(material(candidateIndex: index, grant: tunnel.grant,
        relay: tunnel.relayCertificate), identity: identity, requireEndpoint: false)
    }
    for index in allowed {
      guard candidates.indices.contains(index) else { throw TransportControlError.responseInvalid }
      let kind = try candidates[index].u("path_kind")
      guard kind <= 1 else { throw TransportControlError.responseInvalid }
      let leg = try candidates[index].field(kind == 0 ? "direct_leg" : "client_leg")
      guard try leg.u("carrier") == 1, try leg.u("access_class") == 0,
        try leg.u("dialer_role") == 0, try leg.u("listener_role") == (kind == 0 ? 1 : 2)
      else { continue }
      let selected: TransportPoolCredential
      if kind == 0 { selected = material(candidateIndex: index, grant: Data(), relay: Data()) }
      else if kind == 1, let tunnel = local[index] {
        selected = material(candidateIndex: index, grant: tunnel.grant, relay: tunnel.relayCertificate)
      } else { continue }
      do {
        _ = try client.validatePoolCredential(selected, identity: identity)
        return selected
      } catch TransportConnectError.unsupported { continue }
    }
    throw TransportConnectError.unsupported
  }
  #endif
}
