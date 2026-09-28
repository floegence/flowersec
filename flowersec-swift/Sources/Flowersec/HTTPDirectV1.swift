import CoreFoundation
import Foundation

#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#endif

/// An explicit public HTTP direct envelope. Ordinary TLS connectors reject it.
public final class HTTPDirectArtifactV1: @unchecked Sendable, CustomStringConvertible,
  CustomDebugStringConvertible, CustomReflectable
{
  let endpoint: String
  let inner: Artifact

  fileprivate init(endpoint: String, inner: Artifact) {
    self.endpoint = endpoint
    self.inner = inner
  }

  public var description: String { "Flowersec.HTTPDirectArtifactV1(<redacted>)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }
}

/// Shares one atomic, single-use lease across all copies of this handle.
public struct HTTPDirectArtifactLeaseV1: Sendable, CustomStringConvertible,
  CustomDebugStringConvertible, CustomReflectable
{
  let endpoint: String
  let inner: ArtifactLease

  public init(
    artifact: HTTPDirectArtifactV1,
    commitSpend: @escaping @Sendable () async throws -> Void,
    retire: @escaping @Sendable () async throws -> Void = {}
  ) {
    endpoint = artifact.endpoint
    inner = ArtifactLease(artifact: artifact.inner, commitSpend: commitSpend, retire: retire)
  }

  public var description: String { "Flowersec.HTTPDirectArtifactLeaseV1(<redacted>)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }
}

/// Validates the canonical HTTP envelope and its unchanged v3 admission binding.
public func parseHTTPDirectArtifactV1(_ data: Data) throws -> HTTPDirectArtifactV1 {
  guard !data.isEmpty, data.count <= 100_000 else { throw ArtifactError.artifactTooLarge }
  do {
    try JSONPreflightV3.validate(data)
    guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(root.keys) == Set(["v", "profile", "endpoint", "artifact_b64u"]),
      try FlowersecJCSV3.encode(root) == data,
      root["v"] as? Int == 1, CFGetTypeID(root["v"] as CFTypeRef) != CFBooleanGetTypeID(),
      root["profile"] as? String == "flowersec-http-direct/1",
      let endpoint = root["endpoint"] as? String,
      let encoded = root["artifact_b64u"] as? String,
      let bytes = Data(base64URLEncoded: encoded),
      !bytes.isEmpty, bytes.count <= 65_536, bytes.base64URLEncodedString() == encoded
    else { throw ArtifactError.invalidArtifact }
    let binding = try HTTPDirectEndpointV1(endpoint)
    let artifact = try parseArtifact(bytes)
    guard artifact.value.path.kind == "direct", artifact.canonicalCandidates.count == 1,
      let candidate = artifact.canonicalCandidates.first,
      candidate.id == "http-direct", candidate.carrier == "websocket",
      candidate.tls.mode == "ca", candidate.wireProfile == "flowersec-direct/3",
      candidate.normalizedURL == binding.tlsBinding,
      artifact.value.path.candidates.first?.url == binding.tlsBinding
    else { throw ArtifactError.invalidArtifact }
    return HTTPDirectArtifactV1(endpoint: endpoint, inner: artifact)
  } catch { throw ArtifactError.invalidArtifact }
}

/// Connects only to the envelope's exact public HTTP origin, without TLS fallback.
public func connectHTTPDirectV1(
  lease: HTTPDirectArtifactLeaseV1,
  options: ConnectorOptions
) async throws -> any Session {
  #if os(macOS) || os(iOS)
    return try await SessionConnectorV3(
      lease: lease.inner, options: options,
      runtime: AppleWebSocketRuntimeAdapterV3(httpDirectEndpoint: lease.endpoint)
    ).connect()
  #else
    let claimed: ClaimedArtifactLeaseV3
    do { claimed = try await lease.inner.claim() } catch { throw ConnectError.artifactInvalid }
    try? await claimed.retire()
    throw ConnectError.transportSecurityUnsupported
  #endif
}

struct HTTPDirectEndpointV1 {
  let url: URL
  let origin: String
  let tlsBinding: String

  init(_ raw: String) throws {
    guard let url = URL(string: raw), let host = url.host,
      raw.hasPrefix("ws://"), !raw.contains("%"),
      url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
      url.path == TransportV3Contract.directWebSocketPath,
      Self.allowedHost(host)
    else { throw ArtifactError.invalidArtifact }
    let port = url.port ?? 80
    let authority = (host.contains(":") ? "[\(host)]" : host) + ":\(port)"
    let binding = try ArtifactCodecV3.normalizeURL(
      "wss://\(authority)\(url.path)", carrier: "websocket", kind: "direct")
    guard let canonicalHost = URL(string: binding)?.host else {
      throw ArtifactError.invalidArtifact
    }
    let canonicalAuthority =
      (canonicalHost.contains(":") ? "[\(canonicalHost)]" : canonicalHost)
      + (port == 80 ? "" : ":\(port)")
    guard raw == "ws://\(canonicalAuthority)\(TransportV3Contract.directWebSocketPath)" else {
      throw ArtifactError.invalidArtifact
    }
    self.url = url
    self.origin = "http://\(canonicalAuthority)"
    self.tlsBinding = binding
  }

  private static func allowedHost(_ host: String) -> Bool {
    if host == "localhost" { return true }
    if host.contains(":") {
      var address = in6_addr()
      guard inet_pton(AF_INET6, host, &address) == 1 else {
        return false
      }
      let bytes = withUnsafeBytes(of: address) { Array($0) }
      return !bytes.allSatisfy { $0 == 0 } && bytes[0] != 0xff
        && !(bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80)
        && !(bytes.prefix(10).allSatisfy { $0 == 0 } && bytes[10] == 0xff && bytes[11] == 0xff)
    }
    var address = in_addr()
    guard inet_pton(AF_INET, host, &address) == 1 else { return false }
    let bytes = withUnsafeBytes(of: address) { Array($0) }
    return !bytes.allSatisfy { $0 == 0 } && !bytes.allSatisfy { $0 == 255 }
      && !(224...239).contains(bytes[0]) && !(bytes[0] == 169 && bytes[1] == 254)
  }
}
