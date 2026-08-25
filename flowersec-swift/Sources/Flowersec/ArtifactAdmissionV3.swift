import CoreFoundation
import Crypto
import Foundation

enum AdmissionCodecErrorV3: Error, Equatable, Sendable {
  case invalid
  case payloadTooLarge
  case nonCanonical
}

enum AdmissionStatusV3: UInt8, Equatable, Sendable {
  case success = 0
  case reject = 1
  case retryable = 2
}

struct AdmissionResponseV3: Equatable, Sendable {
  let status: AdmissionStatusV3
  let reason: String
}

struct EncodedFSB3: Equatable, Sendable {
  let candidateID: String
  let frame: Data
  let admissionBinding: Data
}

struct DecodedFSB3: Equatable, Sendable {
  let pathKind: String
  let chosenCandidateID: String
  let frame: Data
  let admissionBinding: Data
}

enum AdmissionCodecV3 {
  static func encodeFSB3(artifact: Artifact, chosenCandidateID: String) throws -> EncodedFSB3 {
    guard artifact.canonicalCandidates.contains(where: { $0.id == chosenCandidateID }) else {
      throw AdmissionCodecErrorV3.invalid
    }
    let value = artifact.value
    let candidates = try JSONSerialization.jsonObject(with: artifact.candidateSetJSON)
    var payload: [String: Any] = [
      "candidate_set_hash_b64u": artifact.candidateSetHash.base64URLEncodedStringV3(),
      "candidates": candidates,
      "channel_id": value.session.channelID,
      "chosen_candidate_id": chosenCandidateID,
      "listener_audience": value.path.listenerAudience,
      "profile": TransportV3Contract.sessionProfile,
      "rendezvous_group_id": value.path.rendezvousGroupID,
      "session_contract_hash_b64u": value.session.contractHashBase64URL,
    ]
    let pathCode: UInt8
    if value.path.kind == "direct" {
      pathCode = 1
      payload["routing_token"] = value.path.routingToken
    } else if value.path.kind == "tunnel" {
      pathCode = 2
      payload["attach_token"] = value.path.token
      payload["endpoint_instance_id"] = value.path.localEndpointInstanceID
      payload["role"] = value.path.role
    } else {
      throw AdmissionCodecErrorV3.invalid
    }
    let canonical = try FlowersecJCSV3.encode(payload)
    guard (1...32_768).contains(canonical.count) else {
      throw AdmissionCodecErrorV3.payloadTooLarge
    }
    var frame = Data("FSB3".utf8)
    frame.append(contentsOf: [3, pathCode, 0, 0])
    frame.appendUInt32BE(UInt32(canonical.count))
    frame.append(canonical)
    var bindingInput = Data(TransportV3Contract.admissionLabel.utf8)
    bindingInput.append(frame)
    return EncodedFSB3(
      candidateID: chosenCandidateID, frame: frame,
      admissionBinding: Data(SHA256.hash(data: bindingInput)))
  }

  static func acceptorAdmissionsHash(_ admissions: [EncodedFSB3]) throws -> Data {
    guard (1...4).contains(admissions.count) else { throw AdmissionCodecErrorV3.invalid }
    let sorted = admissions.sorted {
      $0.candidateID.utf8.lexicographicallyPrecedes($1.candidateID.utf8)
    }
    guard zip(sorted, sorted.dropFirst()).allSatisfy({ $0.candidateID < $1.candidateID }) else {
      throw AdmissionCodecErrorV3.invalid
    }
    var preimage = Data(TransportV3Contract.acceptorAdmissionsLabel.utf8)
    for admission in sorted {
      preimage.appendUInt32BE(UInt32(admission.frame.count))
      preimage.append(admission.frame)
    }
    return Data(SHA256.hash(data: preimage))
  }

  static func decodeFSB3(_ frame: Data) throws -> DecodedFSB3 {
    guard frame.count >= 12, frame.prefix(4) == Data("FSB3".utf8), frame[4] == 3,
      frame[6] == 0, frame[7] == 0
    else { throw AdmissionCodecErrorV3.invalid }
    let pathKind: String
    switch frame[5] {
    case 1: pathKind = "direct"
    case 2: pathKind = "tunnel"
    default: throw AdmissionCodecErrorV3.invalid
    }
    let payloadLength = Int(frame.readUInt32BE(at: 8))
    guard (1...32_768).contains(payloadLength), frame.count == 12 + payloadLength else {
      if payloadLength > 32_768 { throw AdmissionCodecErrorV3.payloadTooLarge }
      throw AdmissionCodecErrorV3.invalid
    }
    let payload = Data(frame.dropFirst(12))
    let raw: Any
    do {
      try JSONPreflightV3.validate(payload)
      raw = try JSONSerialization.jsonObject(with: payload)
      guard try FlowersecJCSV3.encode(raw) == payload else {
        throw AdmissionCodecErrorV3.nonCanonical
      }
    } catch let error as AdmissionCodecErrorV3 {
      throw error
    } catch {
      throw AdmissionCodecErrorV3.invalid
    }
    guard let object = raw as? [String: Any] else { throw AdmissionCodecErrorV3.invalid }
    let common = [
      "candidate_set_hash_b64u", "candidates", "channel_id", "chosen_candidate_id",
      "listener_audience", "profile", "rendezvous_group_id", "session_contract_hash_b64u",
    ]
    try exactKeys(
      object,
      pathKind == "direct"
        ? common + ["routing_token"]
        : common + ["attach_token", "endpoint_instance_id", "role"])
    guard object["profile"] as? String == TransportV3Contract.sessionProfile,
      let channelID = object["channel_id"] as? String, registryID(channelID, maximum: 128),
      let groupID = object["rendezvous_group_id"] as? String, registryID(groupID, maximum: 128),
      let listener = object["listener_audience"] as? String, registryID(listener, maximum: 128),
      let chosen = object["chosen_candidate_id"] as? String, candidateID(chosen),
      let sessionHash = object["session_contract_hash_b64u"] as? String,
      FlowersecJCSV3.canonical32(sessionHash) != nil,
      let candidateHash = object["candidate_set_hash_b64u"] as? String,
      FlowersecJCSV3.canonical32(candidateHash) != nil,
      let candidateObjects = object["candidates"] as? [[String: Any]],
      (1...4).contains(candidateObjects.count)
    else { throw AdmissionCodecErrorV3.invalid }
    var candidates: [CanonicalCandidateV3] = []
    var endpoints = Set<String>()
    var previousID: String?
    for candidateObject in candidateObjects {
      try exactKeys(candidateObject, ["carrier", "id", "normalized_url", "tls", "wire_profile"])
      guard let carrier = candidateObject["carrier"] as? String,
        ["raw_quic", "websocket", "webtransport"].contains(carrier),
        let id = candidateObject["id"] as? String, candidateID(id),
        previousID.map({ $0 < id }) ?? true,
        let normalizedURL = candidateObject["normalized_url"] as? String,
        let wireProfile = candidateObject["wire_profile"] as? String,
        wireProfile == "flowersec-\(pathKind)/3",
        let tlsObject = candidateObject["tls"] as? [String: Any]
      else { throw AdmissionCodecErrorV3.invalid }
      let tls = try decodeTLSPolicy(tlsObject)
      let candidate = CanonicalCandidateV3(
        carrier: carrier, id: id, normalizedURL: normalizedURL, tls: tls, wireProfile: wireProfile)
      guard
        try ArtifactCodecV3.normalizeURL(normalizedURL, carrier: carrier, kind: pathKind)
          == normalizedURL,
        endpoints.insert("\(carrier)\0\(pathKind)\0\(normalizedURL)").inserted,
        try FlowersecJCSV3.encode(candidate.object()).count <= 2_304
      else { throw AdmissionCodecErrorV3.invalid }
      candidates.append(candidate)
      previousID = id
    }
    guard candidates.contains(where: { $0.id == chosen }) else {
      throw AdmissionCodecErrorV3.invalid
    }
    let candidateSet = try FlowersecJCSV3.encode(candidates.map { $0.object() })
    guard candidateSet.count <= 12_288,
      FlowersecJCSV3.hashLP(
        domain: TransportV3Contract.candidatesLabel, canonical: candidateSet)
        == FlowersecJCSV3.canonical32(candidateHash)
    else { throw AdmissionCodecErrorV3.invalid }
    if pathKind == "direct" {
      guard let token = object["routing_token"] as? String, ascii(token, maximum: 8_192) else {
        throw AdmissionCodecErrorV3.invalid
      }
    } else {
      guard let token = object["attach_token"] as? String, ascii(token, maximum: 8_192),
        let endpoint = object["endpoint_instance_id"] as? String,
        registryID(endpoint, maximum: 128),
        let role = unsignedInteger(object["role"]), role == 1 || role == 2
      else { throw AdmissionCodecErrorV3.invalid }
    }
    var bindingInput = Data(TransportV3Contract.admissionLabel.utf8)
    bindingInput.append(frame)
    return DecodedFSB3(
      pathKind: pathKind, chosenCandidateID: chosen, frame: frame,
      admissionBinding: Data(SHA256.hash(data: bindingInput)))
  }

  static func decodeFSA3(_ frame: Data) throws -> AdmissionResponseV3 {
    guard frame.count >= 8, frame.prefix(4) == Data("FSA3".utf8), frame[4] == 3,
      let status = AdmissionStatusV3(rawValue: frame[5])
    else { throw AdmissionCodecErrorV3.invalid }
    let reasonLength = Int(frame.readUInt16BE(at: 6))
    guard reasonLength <= 64, frame.count == 8 + reasonLength,
      let reason = String(data: frame.dropFirst(8), encoding: .utf8)
    else { throw AdmissionCodecErrorV3.invalid }
    if status == .success {
      guard reason.isEmpty else { throw AdmissionCodecErrorV3.invalid }
    } else {
      let bytes = Array(reason.utf8)
      guard !bytes.isEmpty, bytes.count <= 64, (97...122).contains(bytes[0]),
        bytes.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 95 }),
        !(reason == "expired_artifact" && status != .retryable),
        !forbiddenTransportSecurityReason(reason)
      else { throw AdmissionCodecErrorV3.invalid }
    }
    return AdmissionResponseV3(status: status, reason: reason)
  }

  private static func forbiddenTransportSecurityReason(_ reason: String) -> Bool {
    [
      "browser_pin_opaque", "ca_untrusted", "pin_mismatch", "pin_tls_unknown",
      "tls_failed", "tls_pin_mismatch", "tls_policy_expired", "tls_untrusted", "tls_unsupported",
      "transport_security_failed", "transport_security_unsupported",
    ].contains(reason)
  }

  private static func decodeTLSPolicy(_ object: [String: Any]) throws -> TLSPolicyWireV3 {
    guard let mode = object["mode"] as? String else { throw AdmissionCodecErrorV3.invalid }
    if mode == "ca" {
      try exactKeys(object, ["mode"])
      return TLSPolicyWireV3(mode: mode, pins: nil)
    }
    guard mode == "pin", let values = object["pins"] as? [[String: Any]],
      (1...4).contains(values.count)
    else { throw AdmissionCodecErrorV3.invalid }
    try exactKeys(object, ["mode", "pins"])
    var pins: [CertificatePinWireV3] = []
    var previous: (String, String)?
    for value in values {
      try exactKeys(value, ["algorithm", "not_after_unix_s", "value_b64u"])
      guard value["algorithm"] as? String == "sha-256",
        let hash = value["value_b64u"] as? String, FlowersecJCSV3.canonical32(hash) != nil,
        let notAfter = unsignedInteger(value["not_after_unix_s"]), notAfter > 0,
        previous.map({ $0 < ("sha-256", hash) }) ?? true
      else { throw AdmissionCodecErrorV3.invalid }
      pins.append(
        CertificatePinWireV3(
          algorithm: "sha-256", valueBase64URL: hash, notAfterUnixSeconds: notAfter))
      previous = ("sha-256", hash)
    }
    return TLSPolicyWireV3(mode: mode, pins: pins)
  }

  private static func exactKeys(_ object: [String: Any], _ expected: [String]) throws {
    guard object.keys.sorted() == expected.sorted() else { throw AdmissionCodecErrorV3.invalid }
  }

  private static func registryID(_ value: String, maximum: Int) -> Bool {
    let bytes = Array(value.utf8)
    return (1...maximum).contains(bytes.count)
      && bytes.allSatisfy {
        (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
          || $0 == 46 || $0 == 95 || $0 == 126 || $0 == 45
      }
  }

  private static func candidateID(_ value: String) -> Bool {
    let bytes = Array(value.utf8)
    return (1...64).contains(bytes.count)
      && ((97...122).contains(bytes[0]) || (48...57).contains(bytes[0]))
      && bytes.allSatisfy {
        (97...122).contains($0) || (48...57).contains($0) || $0 == 46 || $0 == 95 || $0 == 45
      }
  }

  private static func ascii(_ value: String, maximum: Int) -> Bool {
    let bytes = Array(value.utf8)
    return (1...maximum).contains(bytes.count) && bytes.allSatisfy { $0 <= 0x7f }
  }

  private static func unsignedInteger(_ value: Any?) -> UInt64? {
    guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else {
      return nil
    }
    let double = number.doubleValue
    guard double.isFinite, double >= 0, double.rounded(.towardZero) == double,
      double <= 9_007_199_254_740_991
    else { return nil }
    return UInt64(double)
  }
}
