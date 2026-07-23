import Crypto
import Foundation

#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#endif

enum AdmissionCodecErrorV2: Error, Equatable, Sendable {
  case invalidCandidate
  case fsb2PayloadTooLarge
  case invalidFSA2
  case unknownAdmissionReason
}

enum AdmissionStatusV2: UInt8, Equatable, Sendable {
  case success = 0
  case reject = 1
  case retryable = 2
}

struct AdmissionResponseV2: Equatable, Sendable {
  let status: AdmissionStatusV2
  let reason: String
}

struct CanonicalCandidateV2: Codable, Equatable, Sendable {
  let carrier: String
  let id: String
  let normalizedURL: String
  let wireProfile: String

  enum CodingKeys: String, CodingKey {
    case carrier, id
    case normalizedURL = "normalized_url"
    case wireProfile = "wire_profile"
  }
}

struct CandidateSetV2: Equatable, Sendable {
  let candidates: [CanonicalCandidateV2]
  let canonicalJSON: Data
  let hash: Data
}

enum AdmissionCodecV2 {
  static let maxCanonicalFSB2Payload = 32_768
  static let maxAdmissionReasonBytes = 64

  static func canonicalizeCandidates(_ artifact: ArtifactV2) throws -> CandidateSetV2 {
    let path = artifact.value.path
    var seenTuples = Set<String>()
    let candidates = try path.candidates.map { candidate -> CanonicalCandidateV2 in
      let normalized = try normalize(candidate.url, carrier: candidate.carrier, kind: path.kind)
      let tuple = candidate.carrier + "\0" + normalized + "\0" + candidate.wireProfile
      guard seenTuples.insert(tuple).inserted else { throw AdmissionCodecErrorV2.invalidCandidate }
      return CanonicalCandidateV2(
        carrier: candidate.carrier,
        id: candidate.id,
        normalizedURL: normalized,
        wireProfile: candidate.wireProfile
      )
    }.sorted { $0.id < $1.id }
    let canonical = try encodeCanonical(candidates)
    guard canonical.count <= 12 * 1_024 else { throw AdmissionCodecErrorV2.invalidCandidate }
    var preimage = Data("flowersec-v2-candidates\0".utf8)
    preimage.append(contentsOf: withUnsafeBytes(of: UInt32(canonical.count).bigEndian, Array.init))
    preimage.append(canonical)
    return CandidateSetV2(
      candidates: candidates,
      canonicalJSON: canonical,
      hash: Data(SHA256.hash(data: preimage))
    )
  }

  static func encodeFSB2(artifact: ArtifactV2, chosenCandidateID: String) throws -> Data {
    let value = artifact.value
    let candidateSet = try canonicalizeCandidates(artifact)
    guard candidateSet.candidates.contains(where: { $0.id == chosenCandidateID }) else {
      throw AdmissionCodecErrorV2.invalidCandidate
    }
    let candidates = try JSONSerialization.jsonObject(with: candidateSet.canonicalJSON)
    var payload: [String: Any] = [
      "candidate_set_hash_b64u": encodeBase64URL(candidateSet.hash),
      "candidates": candidates,
      "channel_id": value.session.channelID,
      "chosen_candidate_id": chosenCandidateID,
      "listener_audience": value.path.listenerAudience,
      "profile": value.profile,
      "rendezvous_group_id": value.path.rendezvousGroupID,
      "session_contract_hash_b64u": value.session.contractHashBase64URL,
    ]
    let pathCode: UInt8
    switch value.path.kind {
    case "direct":
      pathCode = 1
      payload["routing_token"] = value.path.routingToken
    case "tunnel":
      pathCode = 2
      payload["attach_token"] = value.path.token
      payload["endpoint_instance_id"] = value.path.localEndpointInstanceID
      payload["role"] = value.path.role
    default:
      throw AdmissionCodecErrorV2.invalidCandidate
    }
    let canonical = try JSONSerialization.data(
      withJSONObject: payload, options: [.sortedKeys, .withoutEscapingSlashes]
    )
    guard canonical.count <= maxCanonicalFSB2Payload else {
      throw AdmissionCodecErrorV2.fsb2PayloadTooLarge
    }
    var frame = Data("FSB2".utf8)
    frame.append(2)
    frame.append(pathCode)
    frame.append(contentsOf: [0, 0])
    frame.append(contentsOf: withUnsafeBytes(of: UInt32(canonical.count).bigEndian, Array.init))
    frame.append(canonical)
    return frame
  }

  static func decodeFSA2(_ frame: Data, reasons: Set<String>) throws -> AdmissionResponseV2 {
    guard frame.count >= 8, frame.prefix(4) == Data("FSA2".utf8), frame[4] == 2,
      let status = AdmissionStatusV2(rawValue: frame[5])
    else { throw AdmissionCodecErrorV2.invalidFSA2 }
    let reasonLength = Int(UInt16(frame[6]) << 8 | UInt16(frame[7]))
    guard reasonLength <= maxAdmissionReasonBytes, frame.count == 8 + reasonLength,
      let reason = String(data: frame.dropFirst(8), encoding: .utf8)
    else { throw AdmissionCodecErrorV2.invalidFSA2 }
    switch status {
    case .success:
      guard reason.isEmpty else { throw AdmissionCodecErrorV2.invalidFSA2 }
    case .reject, .retryable:
      guard validReason(reason) else { throw AdmissionCodecErrorV2.invalidFSA2 }
      guard reasons.contains(reason) else { throw AdmissionCodecErrorV2.unknownAdmissionReason }
    }
    return AdmissionResponseV2(status: status, reason: reason)
  }

  private static func encodeCanonical<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try encoder.encode(value)
  }

  private static func normalize(_ raw: String, carrier: String, kind: String) throws -> String {
    guard !raw.contains(where: { "\\?#%".contains($0) }),
      let components = URLComponents(string: raw), components.user == nil,
      components.password == nil, let rawHost = components.host, !rawHost.isEmpty
    else { throw AdmissionCodecErrorV2.invalidCandidate }
    let scheme = components.scheme?.lowercased()
    let host: String
    if rawHost.contains(":") {
      let address = rawHost.hasPrefix("[") && rawHost.hasSuffix("]")
        ? String(rawHost.dropFirst().dropLast()) : rawHost
      guard let canonical = canonicalIPv6(address) else { throw AdmissionCodecErrorV2.invalidCandidate }
      host = "[\(canonical)]"
    } else {
      do { host = try IDNAHostV2.lookupASCII(rawHost) }
      catch { throw AdmissionCodecErrorV2.invalidCandidate }
    }
    let port = components.port == 443 ? nil : components.port
    guard port == nil || (1...65_535).contains(port!) else {
      throw AdmissionCodecErrorV2.invalidCandidate
    }
    let authority = host + (port.map { ":\($0)" } ?? "")
    switch carrier {
    case "websocket":
      guard scheme == "wss", components.path == "/flowersec/v2/\(kind)" else {
        throw AdmissionCodecErrorV2.invalidCandidate
      }
      return "wss://\(authority)\(components.path)"
    case "raw_quic":
      guard scheme == "quic", components.path.isEmpty || components.path == "/" else {
        throw AdmissionCodecErrorV2.invalidCandidate
      }
      return "quic://\(authority)"
    case "webtransport":
      guard scheme == "https", components.path == "/flowersec/webtransport/v2/\(kind)" else {
        throw AdmissionCodecErrorV2.invalidCandidate
      }
      return "https://\(authority)\(components.path)"
    default:
      throw AdmissionCodecErrorV2.invalidCandidate
    }
  }

  private static func canonicalIPv6(_ host: String) -> String? {
    var address = in6_addr()
    guard inet_pton(AF_INET6, host, &address) == 1 else { return nil }
    var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else { return nil }
    let end = buffer.firstIndex(of: 0) ?? buffer.endIndex
    return String(decoding: buffer[..<end].map(UInt8.init(bitPattern:)), as: UTF8.self)
  }

  private static func encodeBase64URL(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
  }

  private static func validReason(_ reason: String) -> Bool {
    let bytes = Array(reason.utf8)
    guard (1...maxAdmissionReasonBytes).contains(bytes.count),
      (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(bytes[0])
    else { return false }
    return bytes.dropFirst().allSatisfy {
      (UInt8(ascii: "a")...UInt8(ascii: "z")).contains($0)
        || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) || $0 == UInt8(ascii: "_")
    }
  }
}
