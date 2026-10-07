#if os(macOS)
import Foundation
@testable import Flowersec

private struct PeerParityInstalledKey: CodingKey {
  let stringValue: String
  var intValue: Int? { nil }
  init?(stringValue: String) { self.stringValue = stringValue }
  init?(intValue: Int) { return nil }
}
private func peerParityInstalledFields(_ decoder: any Decoder, allowed: Set<String>) throws {
  let fields = try decoder.container(keyedBy: PeerParityInstalledKey.self)
  guard fields.allKeys.allSatisfy({ allowed.contains($0.stringValue) }) else { throw PeerParityFailure.invalidMaterial }
}

// This input is installed by the original fixture owner before authority and
// endpoint startup. The ready message can be compared to it, never replace it.
final class PeerParityRegisteredLiveInstallation: Decodable {
  final class TLS: Decodable {
    let certificatePEM: Data; var privateKeyPEM: Data; let trustPEM: Data
    enum CodingKeys: String, CodingKey { case certificatePEM, privateKeyPEM, trustPEM }
    init(from decoder: any Decoder) throws {
      try peerParityInstalledFields(decoder, allowed: ["certificatePEM", "privateKeyPEM", "trustPEM"])
      let fields = try decoder.container(keyedBy: CodingKeys.self)
      certificatePEM = Data(try fields.decode(String.self, forKey: .certificatePEM).utf8)
      privateKeyPEM = Data(try fields.decode(String.self, forKey: .privateKeyPEM).utf8)
      trustPEM = Data(try fields.decode(String.self, forKey: .trustPEM).utf8)
      guard (1...65_536).contains(certificatePEM.count), (1...16_384).contains(privateKeyPEM.count),
        (1...262_144).contains(trustPEM.count) else { throw PeerParityFailure.invalidMaterial }
    }
    deinit { V4Crypto.wipe(&privateKeyPEM) }
  }
  struct Control: Decodable {
    let endpoint: String; let authority: String; let tls: TLS; let workMS: String
    enum CodingKeys: String, CodingKey { case endpoint, authority, tls, workMS }
    init(from decoder: any Decoder) throws {
      try peerParityInstalledFields(decoder, allowed: ["endpoint", "authority", "tls", "workMS"])
      let fields = try decoder.container(keyedBy: CodingKeys.self)
      endpoint = try fields.decode(String.self, forKey: .endpoint); authority = try fields.decode(String.self, forKey: .authority)
      tls = try fields.decode(TLS.self, forKey: .tls); workMS = try fields.decode(String.self, forKey: .workMS)
    }
    func configuration(path: String) throws -> TransportControlHTTPSConfiguration {
      guard endpoint.utf8.count <= 2048, let url = URL(string: endpoint), url.scheme == "https", url.host == "localhost",
        let port = url.port, (1024...65535).contains(port), url.path == path,
        url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
        url.absoluteString == "https://localhost:\(port)\(path)",
        V4NamespaceRegistry.securityID(authority.utf8), let work = UInt64(workMS), String(work) == workMS, (1...30_000).contains(work)
      else { throw PeerParityFailure.invalidMaterial }
      return TransportControlHTTPSConfiguration(endpoint: TransportEndpoint(hostname: "localhost", port: port, numericAddress: "127.0.0.1"),
        trustRootsPEM: [tls.trustPEM], clientCertificatePEM: tls.certificatePEM, clientPrivateKeyPEM: tls.privateKeyPEM,
        maximumConcurrentRequests: 1, timeoutMilliseconds: work)
    }
  }
  let tenant: String; let audience: String; let control: Control; let relay_control: Control
  enum CodingKeys: String, CodingKey { case tenant, audience, control, relay_control }
  init(from decoder: any Decoder) throws {
    try peerParityInstalledFields(decoder, allowed: ["tenant", "audience", "control", "relay_control"])
    let fields = try decoder.container(keyedBy: CodingKeys.self)
    tenant = try fields.decode(String.self, forKey: .tenant); audience = try fields.decode(String.self, forKey: .audience)
    control = try fields.decode(Control.self, forKey: .control); relay_control = try fields.decode(Control.self, forKey: .relay_control)
    guard V4NamespaceRegistry.securityID(tenant.utf8), V4NamespaceRegistry.securityID(audience.utf8),
      control.tls.certificatePEM == relay_control.tls.certificatePEM, control.tls.privateKeyPEM == relay_control.tls.privateKeyPEM
    else { throw PeerParityFailure.invalidMaterial }
    _ = try control.configuration(path: "/flowersec/control/live"); _ = try relay_control.configuration(path: "/")
  }
  static func read(variables: [String: String]) throws -> PeerParityRegisteredLiveInstallation {
    guard let path = variables["FLOWERSEC_PARITY_LIVE_DEPLOYMENT"], !path.isEmpty, path.utf8.count <= 4096,
      (path as NSString).isAbsolutePath else { throw PeerParityFailure.invalidMaterial }
    let file = try FileHandle(forReadingFrom: URL(fileURLWithPath: path)); defer { try? file.close() }
    var body = Data(); defer { V4Crypto.wipe(&body) }
    while let bytes = try file.read(upToCount: 32_768), !bytes.isEmpty {
      guard body.count + bytes.count <= 4 << 20 else { throw PeerParityFailure.responseTooLarge }
      body.append(bytes)
    }
    guard !body.isEmpty else { throw PeerParityFailure.invalidMaterial }
    return try JSONDecoder().decode(Self.self, from: body)
  }
  func check(material: PeerParityMaterial, ready: PeerParityReady) throws {
    let parent = try material.artifactValue()
    guard ready.path == "tunnel", ready.source == "live_authority", material.source == "live_authority",
      try parent.t("tenant_id") == tenant, try parent.t("audience") == audience,
      material.live_control_base_url == control.endpoint, material.activation.isEmpty,
      material.namespaces.count == 1, material.namespaces[0].tenant == tenant,
      material.namespaces[0].authority == (try parent.t("revocation_authority_id")),
      let key = material.activation_signing_key_id, V4NamespaceRegistry.securityID(key.utf8)
    else { throw PeerParityFailure.invalidMaterial }
  }
  func configuration(material: PeerParityMaterial, ready: PeerParityReady) throws -> TransportRegisteredLiveAuthoritySourceConfiguration {
    try check(material: material, ready: ready)
    guard let entries = material.tunnels, entries.count == 2,
      let local = entries.first(where: { $0.candidate_index == 0 && $0.role == 0 }),
      let peer = entries.first(where: { $0.candidate_index == 0 && $0.role == 1 }),
      (local.grant?.isEmpty ?? true), (peer.grant?.isEmpty ?? true),
      local.relay_certificate == peer.relay_certificate, let pending = local.live_grant,
      local.grant_namespace == 0, local.relay_namespace == 0, peer.grant_namespace == 0, peer.relay_namespace == 0,
      let signingKeyID = material.activation_signing_key_id
    else { throw PeerParityFailure.invalidMaterial }
    let parent = try material.artifactValue()
    guard pending.authority == material.namespaces[0].authority, pending.service == audience,
      pending.issuer_key_id.count == 16, let expiry = UInt64(pending.max_not_after_ms), expiry > 0,
      String(expiry) == pending.max_not_after_ms, let revision = UInt64(pending.revocation_policy_revision), revision > 0,
      String(revision) == pending.revocation_policy_revision
    else { throw PeerParityFailure.invalidMaterial }
    let candidate = try parent.field("candidates").children.first(where: { _ in true })
    guard let candidate, try candidate.u("path_kind") == 1,
      let reference = try candidate.field("revocation_namespace_refs").children.first(where: {
        try $0.t("tenant_id") == tenant && $0.t("revocation_authority_id") == pending.authority && ($0.u("role_mask") & 5) == 5
      }) else { throw PeerParityFailure.invalidMaterial }
    let scope = try TransportGrantScope(tenant: tenant, authority: pending.authority,
      capacityDigest: reference.b("namespace_capacity_digest"), generation: reference.u("generation"),
      policyID: pending.revocation_policy_id, policyRevision: revision, issuer: pending.issuer_key_id,
      audience: pending.audience, service: pending.service, roleMask: 5, cohort: parent.u("revocation_epoch"),
      issuedMS: parent.u("issued_at_ms"), expiresMS: expiry, parentAuthority: parent.t("revocation_authority_id"),
      parentCapacity: parent.b("namespace_capacity_digest"), parentGeneration: parent.u("revocation_authority_generation"),
      parentIssuer: parent.b("issuer_key_id"), parentCohort: parent.u("revocation_epoch"))
    let contract = try parent.field("session_contract")
    let maximumGeneral = try contract.u("rpc_max_general_outstanding")
    guard try contract.u("application_profile") == 1, (1...1024).contains(maximumGeneral) else { throw PeerParityFailure.invalidMaterial }
    let (envelope, overflow) = try contract.u("max_frame").addingReportingOverflow(8)
    guard !overflow, envelope <= 65_536 else { throw PeerParityFailure.invalidMaterial }
    // This WSS engineering profile fixes the original relay's public resource
    // policy locally. No TxB reply chooses limits or expands these capacities.
    let limits = V4PoolRefillWire.map([
      (0, V4NamespaceValue.head(0, envelope)), (1, V4NamespaceValue.head(0, 1 << 30)),
      (2, V4NamespaceValue.head(0, 0)), (3, V4NamespaceValue.head(0, 64 << 20)),
      (4, V4NamespaceValue.head(0, 4 << 20)), (5, V4NamespaceValue.head(0, 0)),
      (6, V4NamespaceValue.head(0, 0)), (7, V4NamespaceValue.head(0, 0)), (8, V4NamespaceValue.head(0, 256))])
    return try TransportRegisteredLiveAuthoritySourceConfiguration(control: control.configuration(path: "/flowersec/control/live"),
      authority: control.authority, artifact: material.artifact, clientCertificate: material.client_certificate,
      serverCertificate: material.server_certificate, activationSigningKeyID: signingKeyID,
      tunnel: TransportLiveTunnelConfiguration(scope: scope, relayCertificate: local.relay_certificate, grantLimits: limits),
      relayPreparation: relay_control.configuration(path: "/"), applicationProfile: "services",
      maximumGeneralOutstanding: Int(maximumGeneral))
  }
}

// Pool readiness contains only the public original B registration. The
// destination, roots and A private key come from the independently installed
// file and are fixed before the SDK acquires or consumes this credential.
struct PeerParityPoolInstallation: Decodable {
  struct Control: Decodable {
    let endpoint: String
    let tls: PeerParityRegisteredLiveInstallation.TLS
    let workMS: String
    enum CodingKeys: String, CodingKey { case endpoint, tls, workMS }
    init(from decoder: any Decoder) throws {
      try peerParityInstalledFields(decoder, allowed: ["endpoint", "tls", "workMS"])
      let fields = try decoder.container(keyedBy: CodingKeys.self)
      endpoint = try fields.decode(String.self, forKey: .endpoint)
      tls = try fields.decode(PeerParityRegisteredLiveInstallation.TLS.self, forKey: .tls)
      workMS = try fields.decode(String.self, forKey: .workMS)
    }
  }
  let wire_revision: Int
  let tenant: String
  let audience: String
  let server_allow: Control
  enum CodingKeys: String, CodingKey { case wire_revision, tenant, audience, server_allow }
  init(from decoder: any Decoder) throws {
    try peerParityInstalledFields(decoder, allowed: ["wire_revision", "tenant", "audience", "server_allow"])
    let fields = try decoder.container(keyedBy: CodingKeys.self)
    wire_revision = try fields.decode(Int.self, forKey: .wire_revision)
    tenant = try fields.decode(String.self, forKey: .tenant)
    audience = try fields.decode(String.self, forKey: .audience)
    server_allow = try fields.decode(Control.self, forKey: .server_allow)
    guard wire_revision == 4, V4NamespaceRegistry.securityID(tenant.utf8),
      V4NamespaceRegistry.securityID(audience.utf8) else { throw PeerParityFailure.invalidMaterial }
  }
  static func read(variables: [String: String]) throws -> Self {
    guard let path = variables["FLOWERSEC_PARITY_POOL_DEPLOYMENT"], !path.isEmpty, path.utf8.count <= 4096,
      (path as NSString).isAbsolutePath else { throw PeerParityFailure.invalidMaterial }
    let file = try FileHandle(forReadingFrom: URL(fileURLWithPath: path)); defer { try? file.close() }
    var body = Data(); defer { V4Crypto.wipe(&body) }
    while let bytes = try file.read(upToCount: 32_768), !bytes.isEmpty {
      guard body.count + bytes.count <= 4 << 20 else { throw PeerParityFailure.responseTooLarge }
      body.append(bytes)
    }
    guard !body.isEmpty else { throw PeerParityFailure.invalidMaterial }
    return try JSONDecoder().decode(Self.self, from: body)
  }
  func configuration(material: PeerParityMaterial, ready: PeerParityReady) throws -> TransportPoolServerAllowConfiguration {
    let parent = try material.artifactValue(), control = server_allow
    guard ready.path == "tunnel", ready.source == "preauthorized_pool", material.source == ready.source,
      material.role == 0, try parent.t("tenant_id") == tenant, try parent.t("audience") == audience,
      let binding = ready.server_allow, control.endpoint == binding.endpoint,
      control.endpoint.utf8.count <= 2048, let url = URL(string: control.endpoint), url.scheme == "https",
      let host = url.host, ["localhost", "127.0.0.1", "[::1]", "::1"].contains(host),
      let port = url.port, (1...65535).contains(port), url.path == "/tunnel/server-allow",
      url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
      let work = UInt64(control.workMS), String(work) == control.workMS, (1...2000).contains(work),
      let tunnels = material.tunnels, tunnels.count == 2,
      let local = tunnels.first(where: { $0.candidate_index == 0 && $0.role == 0 }),
      let server = tunnels.first(where: { $0.candidate_index == 0 && $0.role == 1 }),
      server.relay_certificate == local.relay_certificate, let grant = server.grant, (1...9302).contains(grant.count)
    else { throw PeerParityFailure.invalidMaterial }
    let hostname = host == "[::1]" ? "::1" : host
    let authority = hostname == "::1" ? "[::1]:\(port)" : "\(hostname):\(port)"
    guard control.endpoint == "https://\(authority)/tunnel/server-allow" else { throw PeerParityFailure.invalidMaterial }
    let https = TransportControlHTTPSConfiguration(
      endpoint: TransportEndpoint(hostname: hostname, port: port, numericAddress: hostname == "localhost" ? "127.0.0.1" : hostname),
      trustRootsPEM: [control.tls.trustPEM], clientCertificatePEM: control.tls.certificatePEM,
      clientPrivateKeyPEM: control.tls.privateKeyPEM, maximumConcurrentRequests: 1, timeoutMilliseconds: work)
    return TransportPoolServerAllowConfiguration(control: https, recipient: binding.recipient,
      incarnation: binding.incarnation, serverGrant: grant)
  }
}

#endif
