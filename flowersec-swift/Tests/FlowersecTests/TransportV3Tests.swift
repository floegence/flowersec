import Crypto
import Foundation
import Testing

@testable import Flowersec

@Suite("Transport v3 contract")
struct TransportV3Tests {
  @Test func jcsSortsObjectKeysByUTF16CodeUnits() throws {
    let value: [String: Any] = ["😀": 5, "a": 4]
    #expect(try String(decoding: FlowersecJCSV3.encode(value), as: UTF8.self) == "{\"a\":4,\"😀\":5}")
  }

  @Test func strictArtifactCanonicalizationFSBAndDomainBinding() throws {
    let artifact = try parseArtifact(Self.validArtifact())
    #expect(
      artifact.canonicalCandidates[0].normalizedURL == "wss://example.com/flowersec/v3/direct")
    let encoded = try AdmissionCodecV3.encodeFSB3(artifact: artifact, chosenCandidateID: "a")
    #expect(encoded.frame.prefix(5) == Data("FSB3".utf8) + Data([3]))
    var expected = Data("flowersec-v3-admission\0".utf8)
    expected.append(encoded.frame)
    #expect(encoded.admissionBinding == Data(SHA256.hash(data: expected)))
    #expect(throws: ArtifactError.self) {
      try parseArtifact(Data([0x20]) + Self.validArtifact())
    }
  }

  @Test func artifactJSONPreflightRejectsScopedAllocationBoundaries() {
    let tooDeep =
      "{\"value\":" + String(repeating: "[", count: 15) + "null"
      + String(repeating: "]", count: 15) + "}"
    let sixtyFourNulls = Array(repeating: "null", count: 64).joined(separator: ",")
    let tooManyNodes =
      "{\"a\":[\(sixtyFourNulls)],\"b\":[\(sixtyFourNulls)],"
      + "\"c\":[\(sixtyFourNulls)],\"d\":[\(sixtyFourNulls)]}"
    let tooManyMembers =
      "{" + (0..<65).map { "\"k\($0)\":null" }.joined(separator: ",")
      + "}"
    let tooManyElements =
      "{\"value\":["
      + Array(repeating: "null", count: 65).joined(separator: ",") + "]}"
    let oversizedKey = "{\"\(String(repeating: "k", count: 129))\":null}"
    let oversizedString = "{\"value\":\"\(String(repeating: "x", count: 1_025))\"}"

    for payload in [
      tooDeep, tooManyNodes, tooManyMembers, tooManyElements, oversizedKey, oversizedString,
    ] {
      let document = Data("{\"scoped\":[{\"payload\":\(payload)}]}".utf8)
      #expect(throws: JSONPreflightV3.ValidationError.self) {
        try JSONPreflightV3.validateArtifact(document)
      }
    }
  }

  @Test func artifactFSB3AndCapabilityRejectNestedDuplicateKeysInPreflight() throws {
    let artifactText = try #require(String(data: Self.validArtifact(), encoding: .utf8))
    let duplicateArtifact = artifactText.replacingOccurrences(
      of: "\"mode\":\"ca\"",
      with: "\"mode\":\"ca\",\"m\\u006fde\":\"pin\"")
    #expect(throws: JSONPreflightV3.ValidationError.self) {
      try JSONPreflightV3.validateArtifact(Data(duplicateArtifact.utf8))
    }
    #expect(throws: ArtifactError.self) {
      try parseArtifact(Data(duplicateArtifact.utf8))
    }

    let artifact = try parseArtifact(Self.validArtifact())
    let admission = try AdmissionCodecV3.encodeFSB3(artifact: artifact, chosenCandidateID: "a")
    let payloadText = try #require(String(data: admission.frame.dropFirst(12), encoding: .utf8))
    let duplicatePayload = Data(
      payloadText.replacingOccurrences(
        of: "\"mode\":\"ca\"",
        with: "\"mode\":\"ca\",\"m\\u006fde\":\"pin\""
      ).utf8)
    var duplicateFrame = Data(admission.frame.prefix(8))
    duplicateFrame.appendUInt32BE(UInt32(duplicatePayload.count))
    duplicateFrame.append(duplicatePayload)
    #expect(throws: AdmissionCodecErrorV3.self) {
      try AdmissionCodecV3.decodeFSB3(duplicateFrame)
    }

    let capability = try RuntimeCapabilitiesV3.macOS.canonicalJSON()
    let capabilityText = try #require(String(data: capability, encoding: .utf8))
    let duplicateCapability = capabilityText.replacingOccurrences(
      of: "\"carrier\":\"websocket\"",
      with: "\"carrier\":\"websocket\",\"carri\\u0065r\":\"websocket\"")
    #expect(throws: ArtifactError.self) {
      try RuntimeCapabilityDescriptorV3.decode(Data(duplicateCapability.utf8))
    }
  }

  @Test func publicDecoderRejectsPrivateLoopbackProfileAndAcceptsOnlyItsNestedArtifact() throws {
    let url = packageRoot().appendingPathComponent(
      "testdata/private_loopback_v1/profile_vectors.json")
    let root = try #require(
      JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    #expect(root["profile"] as? String == "flowersec-private-loopback/1")
    #expect(root["nested_profile"] as? String == "flowersec/3")
    let positive = try #require(root["positive"] as? [[String: Any]])
    for vector in positive {
      let artifactJSON = try #require(vector["artifact_json"] as? String)
      #expect(throws: ArtifactError.self) {
        try parseArtifact(Data(artifactJSON.utf8))
      }
      let envelope = try #require(
        JSONSerialization.jsonObject(with: Data(artifactJSON.utf8)) as? [String: Any])
      let encoded = try #require(envelope["artifact_b64u"] as? String)
      let inner = try #require(Data(base64URLEncoded: encoded))
      _ = try parseArtifact(inner)
    }
  }

  @Test func activePinsUseExclusiveExpiryAndDeclaredPolicyDigest() throws {
    let first = Data(repeating: 1, count: 32).base64URLEncodedStringV3()
    let second = Data(repeating: 2, count: 32).base64URLEncodedStringV3()
    let candidate = CanonicalCandidateV3(
      carrier: "websocket", id: "a", normalizedURL: "wss://example.com/flowersec/v3/direct",
      tls: TLSPolicyWireV3(
        mode: "pin",
        pins: [
          CertificatePinWireV3(
            algorithm: "sha-256", valueBase64URL: first, notAfterUnixSeconds: 10),
          CertificatePinWireV3(
            algorithm: "sha-256", valueBase64URL: second, notAfterUnixSeconds: 20),
        ]), wireProfile: "flowersec-direct/3")
    #expect(try candidate.activePinHashes(at: 10) == [Data(repeating: 2, count: 32)])
    #expect(throws: TransportSecurityFailureV3.tlsPolicyExpired) {
      try candidate.activePinHashes(at: 20)
    }
    #expect(try candidate.tlsPolicyDigest().count == 32)
  }

  @Test func copiedLeaseHasOneOwnerAndTerminalSpend() async throws {
    let artifact = try parseArtifact(Self.validArtifact())
    let counter = CounterV3()
    let lease = ArtifactLease(artifact: artifact, commitSpend: { await counter.increment() })
    let claimed = try await lease.claim()
    await #expect(throws: ArtifactLeaseError.unavailable) { try await lease.claim() }
    try await claimed.commitSpend()
    #expect(await counter.value == 1)
    await #expect(throws: ArtifactLeaseError.unavailable) { try await lease.claim() }
  }

  #if !os(macOS) && !os(iOS)
    @Test func unsupportedPublicConnectorRetiresItsClaimedLease() async throws {
      let spend = CounterV3()
      let retired = CounterV3()
      let lease = ArtifactLease(
        artifact: try parseArtifact(Self.validArtifact()),
        commitSpend: { await spend.increment() },
        retire: { await retired.increment() })

      await #expect(throws: ConnectError.transportSecurityUnsupported) {
        _ = try await connect(lease: lease, options: ConnectorOptions(origin: "https://app.example"))
      }
      #expect(await spend.value == 0)
      #expect(await retired.value == 1)
      await #expect(throws: ArtifactLeaseError.unavailable) {
        try await lease.claim()
      }
      await #expect(throws: ConnectError.artifactInvalid) {
        _ = try await connect(lease: lease, options: ConnectorOptions(origin: "https://app.example"))
      }
      #expect(await retired.value == 1)
    }
  #endif

  @Test func canceledSpendWithUnknownCallbackResultIsConsumed() async throws {
    let artifact = try parseArtifact(Self.validArtifact())
    let started = AsyncStream<Void>.makeStream()
    let release = AsyncStream<Void>.makeStream()
    let lease = ArtifactLease(
      artifact: artifact,
      commitSpend: {
        started.continuation.yield(())
        for await _ in release.stream { break }
      })
    let claimed = try await lease.claim()
    let task = Task { try await claimed.commitSpend() }
    var iterator = started.stream.makeAsyncIterator()
    _ = await iterator.next()
    task.cancel()
    var consumed = false
    for _ in 0..<100 {
      if await claimed.isConsumed {
        consumed = true
        break
      }
      await Task.yield()
    }
    #expect(consumed)
    release.continuation.finish()
    _ = await task.result
  }

  @Test func failedSpendIsConsumed() async throws {
    let artifact = try parseArtifact(Self.validArtifact())
    let lease = ArtifactLease(
      artifact: artifact,
      commitSpend: {
        throw SpendFailureV3.durabilityUnavailable
      })
    let claimed = try await lease.claim()
    await #expect(throws: SpendFailureV3.durabilityUnavailable) {
      try await claimed.commitSpend()
    }
    await #expect(throws: ArtifactLeaseError.unavailable) {
      try await lease.claim()
    }
  }

  @Test func capabilityAndPinVerifierAreStrict() throws {
    let capability = RuntimeCapabilitiesV3.macOS
    let canonical = try #require(String(data: capability.canonicalJSON(), encoding: .utf8))
    #expect(canonical.contains("\"schemaVersion\":3"))
    #expect(canonical.contains("\"securityModes\":[\"ca\",\"pin\"]"))
    let der = Data("leaf".utf8)
    let hash = Data(SHA256.hash(data: der))
    let leaf = PresentedLeafCertificateV3(
      der: der, x509Version: 3, notBeforeUnixSeconds: 10, notAfterUnixSeconds: 20,
      publicKey: .ecdsaP256, tlsProofComplete: true)
    try PinVerifierV3.verify(
      leaf: leaf, activePins: [Data(repeating: 0, count: 32), hash], nowUnixSeconds: 10)
    #expect(throws: TransportSecurityFailureV3.pinMismatch) {
      try PinVerifierV3.verify(
        leaf: leaf, activePins: [Data(repeating: 0, count: 32)], nowUnixSeconds: 10)
    }
    let legacyLeaf = PresentedLeafCertificateV3(
      der: der, x509Version: 1, notBeforeUnixSeconds: 10, notAfterUnixSeconds: 20,
      publicKey: .ecdsaP256, tlsProofComplete: true)
    #expect(throws: TransportSecurityFailureV3.unknownTLS) {
      try PinVerifierV3.verify(leaf: legacyLeaf, activePins: [hash], nowUnixSeconds: 10)
    }
  }

  @Test func urlNormalizationRejectsPlaintextAndLegacyNumericHosts() throws {
    #expect(
      try ArtifactCodecV3.normalizeURL(
        "wss://127.0.0.1:0443/flowersec/v3/direct", carrier: "websocket", kind: "direct")
        == "wss://127.0.0.1/flowersec/v3/direct")
    for value in [
      "ws://127.0.0.1/flowersec/v3/direct", "wss://127.1/flowersec/v3/direct",
      "wss://example.1/flowersec/v3/direct", "wss://example.0x/flowersec/v3/direct",
    ] {
      #expect(throws: ArtifactError.self) {
        try ArtifactCodecV3.normalizeURL(value, carrier: "websocket", kind: "direct")
      }
    }
  }

  @Test func fsa3RejectsTransportSecurityReasons() {
    for reason in [
      "tls_failed", "tls_pin_mismatch", "tls_policy_expired", "tls_unsupported",
      "transport_security_failed", "transport_security_unsupported",
    ] {
      var frame = Data("FSA3".utf8)
      frame.append(contentsOf: [3, 1])
      frame.appendUInt16BE(UInt16(reason.utf8.count))
      frame.append(contentsOf: reason.utf8)
      #expect(throws: AdmissionCodecErrorV3.invalid) {
        try AdmissionCodecV3.decodeFSA3(frame)
      }
    }
  }

  @Test func sharedArtifactVectorsFreezeCanonicalizationAndAdmissionBytes() throws {
    let vectors = try Self.loadVectorObject("artifact_vectors.json")
    let positive = try #require(vectors["positive"] as? [[String: Any]])
    for vector in positive {
      let id = try #require(vector["id"] as? String)
      let artifactJSON = try #require(vector["artifact_json"] as? String)
      let artifact = try parseArtifact(Data(artifactJSON.utf8))
      #expect(artifact.canonicalJSON == Data(artifactJSON.utf8), Comment(rawValue: id))
      let artifactObject = try #require(
        JSONSerialization.jsonObject(with: Data(artifactJSON.utf8)) as? [String: Any])
      let session = try #require(artifactObject["session"] as? [String: Any])
      let sessionProjection: [String: Any] = [
        "allowed_suites": try #require(session["allowed_suites"]),
        "channel_id": try #require(session["channel_id"]),
        "default_suite": try #require(session["default_suite"]),
        "establish_timeout_seconds": try #require(session["establish_timeout_seconds"]),
        "idle_timeout_seconds": try #require(session["idle_timeout_seconds"]),
        "max_inbound_streams": try #require(session["max_inbound_streams"]),
        "profile": "flowersec/3",
        "rekey_completion_timeout_seconds": try #require(
          session["rekey_completion_timeout_seconds"]),
        "rekey_prepare_timeout_seconds": try #require(session["rekey_prepare_timeout_seconds"]),
        "selected_features": try #require(session["selected_features"]),
      ]
      let sessionCanonical = try FlowersecJCSV3.encode(sessionProjection)
      let expectedSessionCanonical = try #require(vector["session_canonical_json"] as? String)
      #expect(
        sessionCanonical == Data(expectedSessionCanonical.utf8),
        Comment(rawValue: "\(id) session canonical JSON"))
      let expectedSessionHash = try #require(vector["session_contract_hash_b64u"] as? String)
      #expect(
        FlowersecJCSV3.hashLP(
          domain: "flowersec-v3-session-contract\0", canonical: sessionCanonical
        ).base64URLEncodedStringV3() == expectedSessionHash,
        Comment(rawValue: "\(id) session contract hash"))
      let candidateJSON = try #require(vector["candidates_canonical_json"] as? String)
      #expect(artifact.candidateSetJSON == Data(candidateJSON.utf8), Comment(rawValue: id))
      let candidateHash = try #require(vector["candidate_set_hash_b64u"] as? String)
      #expect(artifact.candidateSetHash.base64URLEncodedStringV3() == candidateHash)

      let digests = try #require(vector["tls_policy_digests"] as? [[String: Any]])
      for digest in digests {
        let candidateID = try #require(digest["candidate_id"] as? String)
        let expected = try Data(hexV3: #require(digest["digest_hex"] as? String))
        let candidate = try #require(
          artifact.canonicalCandidates.first(where: { $0.id == candidateID }))
        #expect(
          try candidate.tlsPolicyDigest() == expected, Comment(rawValue: "\(id) \(candidateID)"))
      }

      let winnerVectors = try #require(vector["winners"] as? [[String: Any]])
      var admissions: [EncodedFSB3] = []
      for winner in winnerVectors {
        let candidateID = try #require(winner["candidate_id"] as? String)
        let admission = try AdmissionCodecV3.encodeFSB3(
          artifact: artifact, chosenCandidateID: candidateID)
        let expectedFrame = try Data(hexV3: #require(winner["fsb3_hex"] as? String))
        let expectedBinding = try Data(
          hexV3: #require(winner["admission_binding_hex"] as? String))
        #expect(
          admission.frame == expectedFrame,
          Comment(rawValue: "\(id) \(candidateID) FSB3"))
        #expect(
          admission.admissionBinding == expectedBinding,
          Comment(rawValue: "\(id) \(candidateID) binding"))
        let decoded = try AdmissionCodecV3.decodeFSB3(expectedFrame)
        #expect(decoded.chosenCandidateID == candidateID, Comment(rawValue: id))
        #expect(decoded.frame == expectedFrame, Comment(rawValue: id))
        #expect(decoded.admissionBinding == expectedBinding, Comment(rawValue: id))
        admissions.append(admission)
      }
      let expectedAdmissionsHash = try Data(
        hexV3: #require(vector["acceptor_admissions_hash_hex"] as? String))
      #expect(
        try AdmissionCodecV3.acceptorAdmissionsHash(admissions) == expectedAdmissionsHash,
        Comment(rawValue: "\(id) acceptor hash"))
    }

    let negative = try #require(vectors["negative"] as? [[String: Any]])
    let negativeIDs = Set(negative.compactMap { $0["id"] as? String })
    #expect(negativeIDs.contains("scope-payload-positive-safe-integer-overflow"))
    #expect(negativeIDs.contains("scope-payload-negative-safe-integer-overflow"))
    for vector in negative {
      let id = try #require(vector["id"] as? String)
      let value = try #require(vector["value"] as? String)
      #expect(throws: ArtifactError.self, Comment(rawValue: id)) {
        try parseArtifact(Data(value.utf8))
      }
    }

    for field in ["scalar_boundaries", "scoped_payload_boundaries"] {
      let boundaries = try #require(vectors[field] as? [[String: Any]])
      for vector in boundaries {
        let id = try #require(vector["id"] as? String)
        let accepted = try #require(vector["accepted"] as? Bool)
        let value = Data(try #require(vector["artifact_json"] as? String).utf8)
        if accepted {
          let artifact = try parseArtifact(value)
          #expect(artifact.canonicalJSON == value, Comment(rawValue: id))
        } else {
          #expect(throws: ArtifactError.self, Comment(rawValue: id)) {
            try parseArtifact(value)
          }
        }
      }
    }

    let artifactByteNegative = try #require(vectors["artifact_byte_negative"] as? [[String: Any]])
    for vector in artifactByteNegative {
      let id = try #require(vector["id"] as? String)
      let value = try Data(hexV3: #require(vector["value_hex"] as? String))
      let expected = try Self.artifactError(code: #require(vector["error_code"] as? String))
      #expect(throws: expected, Comment(rawValue: id)) { try parseArtifact(value) }
    }
    let fsb3Negative = try #require(vectors["fsb3_negative"] as? [[String: Any]])
    for vector in fsb3Negative {
      let id = try #require(vector["id"] as? String)
      let value = try Data(hexV3: #require(vector["value_hex"] as? String))
      let expected = try Self.admissionError(code: #require(vector["error_code"] as? String))
      #expect(throws: expected, Comment(rawValue: id)) {
        try AdmissionCodecV3.decodeFSB3(value)
      }
    }
    let fsa3Negative = try #require(vectors["fsa3_negative"] as? [[String: Any]])
    for vector in fsa3Negative {
      let id = try #require(vector["id"] as? String)
      let value = try Data(hexV3: #require(vector["value_hex"] as? String))
      let expected = try Self.admissionError(code: #require(vector["error_code"] as? String))
      #expect(throws: expected, Comment(rawValue: id)) {
        try AdmissionCodecV3.decodeFSA3(value)
      }
    }

    let fsaVectors = try #require(vectors["fsa3"] as? [[String: Any]])
    for vector in fsaVectors {
      let id = try #require(vector["id"] as? String)
      let status = try #require(vector["status"] as? Int)
      let reason = try #require(vector["reason"] as? String)
      let decoded = try AdmissionCodecV3.decodeFSA3(
        Data(hexV3: #require(vector["frame_hex"] as? String)))
      #expect(decoded.status.rawValue == UInt8(status), Comment(rawValue: id))
      #expect(decoded.reason == reason, Comment(rawValue: id))
    }
    #expect(throws: AdmissionCodecErrorV3.self) {
      try AdmissionCodecV3.decodeFSA3(Data(hexV3: "4653413303010010657870697265645f6172746966616374"))
    }

    let activePinSnapshots = try #require(vectors["active_pin_snapshots"] as? [[String: Any]])
    for vector in activePinSnapshots {
      let id = try #require(vector["id"] as? String)
      let attemptNowValue = try #require(vector["attempt_now"] as? Int)
      let attemptNow = try #require(UInt64(exactly: attemptNowValue))
      let declared = try #require(vector["declared"] as? [String: Any])
      let pins = try #require(declared["pins"] as? [[String: Any]])
      let policy = TLSPolicyWireV3(
        mode: try #require(declared["mode"] as? String),
        pins: try pins.map { pin in
          let notAfter = try #require(pin["not_after_unix_s"] as? Int)
          return CertificatePinWireV3(
            algorithm: try #require(pin["algorithm"] as? String),
            valueBase64URL: try #require(pin["value_b64u"] as? String),
            notAfterUnixSeconds: try #require(UInt64(exactly: notAfter)))
        })
      let candidate = CanonicalCandidateV3(
        carrier: "websocket", id: "snapshot",
        normalizedURL: "wss://example.com/flowersec/v3/direct", tls: policy,
        wireProfile: "flowersec-direct/3")
      let expectedActivePins = try #require(vector["active_value_b64u"] as? [String])
      let result = try #require(vector["result"] as? String)
      if result == "tls_policy_expired" {
        #expect(expectedActivePins.isEmpty, Comment(rawValue: id))
        #expect(throws: TransportSecurityFailureV3.tlsPolicyExpired, Comment(rawValue: id)) {
          _ = try candidate.activePinHashes(at: attemptNow)
        }
      } else {
        #expect(result == "attempt", Comment(rawValue: id))
        let activePinResult = try candidate.activePinHashes(at: attemptNow)
        let activePins = try #require(activePinResult)
        #expect(
          activePins.map { $0.base64URLEncodedStringV3() } == expectedActivePins,
          Comment(rawValue: id))
      }
    }
  }

  private static func artifactError(code: String) throws -> ArtifactError {
    guard code == "invalid_artifact" else { throw ArtifactError.invalidArtifact }
    return .invalidArtifact
  }

  private static func admissionError(code: String) throws -> AdmissionCodecErrorV3 {
    switch code {
    case "invalid_fsb3", "invalid_fsa3": return .invalid
    case "fsb3_payload_too_large": return .payloadTooLarge
    case "noncanonical_fsb3": return .nonCanonical
    default: throw ArtifactError.invalidArtifact
    }
  }

  @Test func consumesGoProductionIssuerAdmissionVector() throws {
    let root = try Self.loadVectorObject("go_issuer_admission_vectors.json")
    let artifactJSON = try #require(root["artifact_json"] as? String)
    let artifact = try parseArtifact(Data(artifactJSON.utf8))
    let candidateID = try #require(root["chosen_candidate_id"] as? String)
    let admission = try AdmissionCodecV3.encodeFSB3(
      artifact: artifact, chosenCandidateID: candidateID)
    let expectedFrame = try Data(hexV3: #require(root["fsb3_hex"] as? String))
    let expectedBinding = try Data(hexV3: #require(root["admission_binding_hex"] as? String))
    let expectedAdmissions = try Data(
      hexV3: #require(root["acceptor_admissions_hash_hex"] as? String))
    #expect(admission.frame == expectedFrame)
    #expect(admission.admissionBinding == expectedBinding)
    #expect(
      try AdmissionCodecV3.acceptorAdmissionsHash([admission]) == expectedAdmissions)
  }

  @Test func versionIsolationVectorsRejectV2MutationsAtProductionBoundaries() async throws {
    let root = try Self.loadVectorObject("version_isolation_vectors.json")
    let frames = try #require(root["frames"] as? [[String: Any]])
    #expect(root["version"] as? Int == 3)

    for frame in frames {
      let id = try #require(frame["id"] as? String)
      let valid = try Data(hexV3: #require(frame["v3_hex"] as? String))
      let magic = try Data(hexV3: #require(frame["v2_magic_hex"] as? String))
      let version = try Data(hexV3: #require(frame["v2_version_hex"] as? String))
      switch id {
      case "fsb3":
        #expect(throws: AdmissionCodecErrorV3.self) { try AdmissionCodecV3.decodeFSB3(magic) }
        #expect(throws: AdmissionCodecErrorV3.self) { try AdmissionCodecV3.decodeFSB3(version) }
        _ = try AdmissionCodecV3.decodeFSB3(valid)
      case "fsa3":
        #expect(throws: AdmissionCodecErrorV3.self) { try AdmissionCodecV3.decodeFSA3(magic) }
        #expect(throws: AdmissionCodecErrorV3.self) { try AdmissionCodecV3.decodeFSA3(version) }
        _ = try AdmissionCodecV3.decodeFSA3(valid)
      case "fsc3":
        try TransportV3Handshake.requireControlPreface(valid)
        #expect(throws: TransportV3SessionError.self) {
          try TransportV3Handshake.requireControlPreface(magic)
        }
        #expect(throws: TransportV3SessionError.self) {
          try TransportV3Handshake.requireControlPreface(version)
        }
      case "fss3":
        #expect(throws: TransportV3CryptoError.self) { try SetupPrefaceV3(encoded: magic) }
        #expect(throws: TransportV3CryptoError.self) { try SetupPrefaceV3(encoded: version) }
        _ = try SetupPrefaceV3(encoded: valid)
      case "fsr3":
        #expect(throws: TransportV3CryptoError.self) { try RecordHeaderV3(encoded: magic) }
        #expect(throws: TransportV3CryptoError.self) { try RecordHeaderV3(encoded: version) }
        _ = try RecordHeaderV3(encoded: valid)
      case "fsd3":
        #expect(throws: TransportV3CryptoError.self) { try UnreliableHeaderV3(encoded: magic) }
        #expect(throws: TransportV3CryptoError.self) { try UnreliableHeaderV3(encoded: version) }
        _ = try UnreliableHeaderV3(encoded: valid)
      case "fsh3":
        #expect(
          try await TransportV3Handshake.readFrame(
            from: VersionIsolationCarrierStreamV3(valid), expectedType: valid[5]) == valid)
        await #expect(throws: TransportV3SessionError.self) {
          try await TransportV3Handshake.readFrame(
            from: VersionIsolationCarrierStreamV3(magic), expectedType: valid[5])
        }
        await #expect(throws: TransportV3SessionError.self) {
          try await TransportV3Handshake.readFrame(
            from: VersionIsolationCarrierStreamV3(version), expectedType: valid[5])
        }
      default:
        Issue.record("unexpected isolation frame \(id)")
      }
    }

    let artifactText = try #require(String(data: Self.validArtifact(), encoding: .utf8))
    let artifactVectors = try Self.loadVectorObject("artifact_vectors.json")
    let positiveArtifacts = try #require(artifactVectors["positive"] as? [[String: Any]])
    let tunnelArtifacts: [String] = positiveArtifacts.compactMap {
      $0["artifact_json"] as? String
    }
    let tunnelArtifactText = try #require(
      tunnelArtifacts.first {
        ($0.data(using: String.Encoding.utf8).flatMap { try? parseArtifact($0) })?.value.path.kind
          == "tunnel"
      })
    let profileMutations = try #require(root["profile_mutations"] as? [[String: Any]])
    for mutation in profileMutations {
      let id = try #require(mutation["id"] as? String)
      let v3 = try #require(mutation["v3"] as? String)
      let v2 = try #require(mutation["v2"] as? String)
      if id == "tunnel" {
        #expect(v3 == TransportV3Contract.tunnelProfile)
        #expect(v2 == "flowersec-tunnel/2")
      } else if id == "direct" {
        #expect(v3 == TransportV3Contract.directProfile)
      } else {
        #expect(v3 == TransportV3Contract.sessionProfile)
      }
      let marker =
        id == "session"
        ? "\"profile\":\"\(TransportV3Contract.sessionProfile)\""
        : "\"wire_profile\":\"\(TransportV3Contract.wireProfile(for: id))\""
      let sourceText = id == "tunnel" ? tunnelArtifactText : artifactText
      let mutated = sourceText.replacingOccurrences(
        of: marker, with: marker.replacingOccurrences(of: "/3", with: "/2"))
      #expect(throws: ArtifactError.self, Comment(rawValue: "profile_mutations/\(id)")) {
        try parseArtifact(Data(mutated.utf8))
      }
      #expect(v2.hasSuffix("/2"))
    }

    let pathMutations = try #require(root["path_mutations"] as? [[String: Any]])
    for mutation in pathMutations {
      let id = try #require(mutation["id"] as? String)
      let v3 = try #require(mutation["v3"] as? String)
      let v2 = try #require(mutation["v2"] as? String)
      let carrier = id.hasPrefix("webtransport") ? "webtransport" : "websocket"
      let kind = id.hasSuffix("-tunnel") ? "tunnel" : "direct"
      let expectedPath =
        carrier == "webtransport"
        ? TransportV3Contract.webTransportPath(for: kind)
        : TransportV3Contract.webSocketPath(for: kind)
      #expect(v3 == expectedPath, Comment(rawValue: "path_mutations/\(id)/v3"))
      #expect(
        try ArtifactCodecV3.normalizeURL(
          "\(carrier == "webtransport" ? "https" : "wss")://example.com\(v3)",
          carrier: carrier, kind: kind)
          == "\(carrier == "webtransport" ? "https" : "wss")://example.com\(expectedPath)")
      #expect(throws: ArtifactError.self, Comment(rawValue: "path_mutations/\(id)")) {
        try ArtifactCodecV3.normalizeURL(
          "\(carrier == "webtransport" ? "https" : "wss")://example.com\(v2)", carrier: carrier,
          kind: kind)
      }
    }

    let subprotocolMutations = try #require(
      root["subprotocol_mutations"] as? [[String: Any]])
    for mutation in subprotocolMutations {
      let id = try #require(mutation["id"] as? String)
      let v3 = try #require(mutation["v3"] as? String)
      let v2 = try #require(mutation["v2"] as? String)
      let expected: String
      switch id {
      case "websocket-direct": expected = TransportV3Contract.directWebSocketSubprotocol
      case "websocket-tunnel": expected = TransportV3Contract.tunnelWebSocketSubprotocol
      default:
        Issue.record("unexpected subprotocol mutation \(id)")
        continue
      }
      #expect(mutation["error_code"] as? String == "version_isolation")
      #expect(v3 == expected, Comment(rawValue: "subprotocol_mutations/\(id)/v3"))
      #expect(v2 != expected, Comment(rawValue: "subprotocol_mutations/\(id)/v2"))
    }

    let alpnMutations = try #require(root["alpn_mutations"] as? [[String: Any]])
    for mutation in alpnMutations {
      let id = try #require(mutation["id"] as? String)
      let v3 = try #require(mutation["v3"] as? String)
      let v2 = try #require(mutation["v2"] as? String)
      let expected =
        id == "direct"
        ? TransportV3Contract.directProfile
        : TransportV3Contract.tunnelProfile
      #expect(v3 == expected, Comment(rawValue: "alpn_mutations/\(id)/v3"))
      #expect(v2 != expected, Comment(rawValue: "alpn_mutations/\(id)/v2"))
    }
    let cryptoMutations = try #require(root["crypto_label_mutations"] as? [[String: Any]])
    for mutation in cryptoMutations {
      let id = try #require(mutation["id"] as? String)
      let v3 = try #require(mutation["v3"] as? String)
      let v2 = try #require(mutation["v2"] as? String)
      let expected: String
      switch id {
      case "session-contract": expected = TransportV3Contract.sessionContractLabel
      case "candidates": expected = TransportV3Contract.candidatesLabel
      case "admission": expected = TransportV3Contract.admissionLabel
      case "runtime-capability": expected = TransportV3Contract.runtimeCapabilityLabel
      case "handshake": expected = TransportV3Contract.handshakeDomain
      case "server-finished": expected = TransportV3Contract.serverFinishedLabel
      case "client-finished": expected = TransportV3Contract.clientFinishedLabel
      case "epoch-zero": expected = TransportV3Contract.epochZeroLabel
      case "control-root": expected = TransportV3Contract.controlRootLabel
      case "stream-root": expected = TransportV3Contract.streamRootLabel
      case "setup-root": expected = TransportV3Contract.setupRootLabel
      case "rekey-root": expected = TransportV3Contract.rekeyRootLabel
      case "next-epoch": expected = TransportV3Contract.nextEpochLabel
      case "stream": expected = TransportV3Contract.streamLabel
      case "control": expected = TransportV3Contract.controlLabel
      case "record-key": expected = TransportV3Contract.recordKeyLabel
      case "nonce": expected = TransportV3Contract.nonceLabel
      case "unreliable-root": expected = TransportV3Contract.unreliableRootLabel
      case "unreliable": expected = TransportV3Contract.unreliableLabel
      case "unreliable-key": expected = TransportV3Contract.unreliableKeyLabel
      case "unreliable-nonce": expected = TransportV3Contract.unreliableNonceLabel
      case "unreliable-aad": expected = TransportV3Contract.unreliableDomain
      case "setup-mac": expected = TransportV3Contract.setupDomain + "\0"
      case "record-aad": expected = TransportV3Contract.recordDomain + "\0"
      case "open": expected = TransportV3Contract.openDomain
      case "acceptor-admissions": expected = TransportV3Contract.acceptorAdmissionsLabel
      default:
        Issue.record("unexpected crypto isolation label \(id)")
        continue
      }
      #expect(v3 == expected, Comment(rawValue: "crypto_label_mutations/\(id)/v3"))
      #expect(v2 != expected, Comment(rawValue: "crypto_label_mutations/\(id)/v2"))
    }
  }

  @Test func sharedDatagramVectorsFreezeFSD3WireCryptoAndErrors() throws {
    let fixture = try Self.loadVectorObject("datagram_vectors.json")
    #expect(fixture["schema_version"] as? Int == 3)
    let vectors = try #require(fixture["vectors"] as? [[String: Any]])
    #expect(!vectors.isEmpty)

    for vector in vectors {
      let name = try #require(vector["name"] as? String)
      func decode(_ field: String) throws -> Data {
        let encoded = try #require(vector[field] as? String, Comment(rawValue: "\(name) \(field)"))
        let value = try #require(
          Data(base64URLEncoded: encoded), Comment(rawValue: "\(name) \(field)"))
        #expect(value.base64URLEncodedString() == encoded, Comment(rawValue: "\(name) \(field)"))
        return value
      }

      let suiteRaw = try #require(vector["suite"] as? Int)
      let suite = try #require(TransportCipherSuiteV3(rawValue: UInt16(suiteRaw)))
      let directionRaw = try #require(vector["direction"] as? Int)
      let direction = try #require(TransportDirectionV3(rawValue: UInt8(directionRaw)))
      let epochValue = try #require(vector["epoch"] as? Int)
      let sequenceValue = try #require(vector["sequence"] as? Int)
      let expiresAtValue = try #require(vector["expires_at_unix_ms"] as? Int)
      let epoch = try #require(UInt32(exactly: epochValue))
      let sequence = try #require(UInt64(exactly: sequenceValue))
      let expiresAt = try #require(UInt64(exactly: expiresAtValue))
      let sessionPRK = try decode("session_prk_b64u")
      let h3 = try decode("h3_b64u")
      let plaintext = try decode("plaintext_b64u")
      let expectedEpochSecret = try decode("epoch_secret_b64u")
      let expectedRoot = try decode("unreliable_root_b64u")
      let expectedSecret = try decode("material_secret_b64u")
      let expectedRecordKey = try decode("record_key_b64u")
      let expectedNoncePrefix = try decode("nonce_prefix_b64u")
      let expectedNonce = try decode("nonce_b64u")
      let headerHex = try #require(vector["header_hex"] as? String)
      let expectedHeader = try Data(hexV3: headerHex)
      let expectedAAD = try decode("aad_b64u")
      let expectedCiphertext = try decode("ciphertext_b64u")
      let expectedWire = try decode("wire_b64u")

      let epochZero = try TransportV3Crypto.deriveEpochZero(
        sessionPRK: sessionPRK, direction: direction)
      let epochSecret = try TransportV3Crypto.deriveNextEpoch(
        rekeyRoot: epochZero.rekeyRoot,
        h3: h3,
        direction: direction,
        nextEpoch: epoch
      )
      #expect(epochSecret == expectedEpochSecret, Comment(rawValue: name))
      let material = try TransportV3Crypto.deriveUnreliableMaterial(
        epochSecret: epochSecret, h3: h3, direction: direction, epoch: epoch)
      #expect(material.root == expectedRoot, Comment(rawValue: name))
      #expect(material.secret == expectedSecret, Comment(rawValue: name))
      #expect(material.recordKey == expectedRecordKey, Comment(rawValue: name))
      #expect(material.noncePrefix == expectedNoncePrefix, Comment(rawValue: name))
      #expect(
        try TransportV3Crypto.unreliableNonce(
          noncePrefix: material.noncePrefix, sequence: sequence) == expectedNonce,
        Comment(rawValue: name))

      let header = UnreliableHeaderV3(
        epoch: epoch,
        sequence: sequence,
        expiresAtUnixMilliseconds: expiresAt,
        ciphertextLength: UInt32(plaintext.count + TransportV3Crypto.aeadTagBytes)
      )
      let encodedHeader = try header.encoded()
      #expect(encodedHeader == expectedHeader, Comment(rawValue: name))
      #expect(try UnreliableHeaderV3(encoded: encodedHeader) == header, Comment(rawValue: name))
      #expect(
        try TransportV3Crypto.unreliableAAD(h3: h3, direction: direction, header: header)
          == expectedAAD,
        Comment(rawValue: name))

      let ciphertext = try TransportV3Crypto.sealUnreliable(
        suite: suite,
        material: material,
        h3: h3,
        direction: direction,
        header: header,
        plaintext: plaintext
      )
      #expect(ciphertext == expectedCiphertext, Comment(rawValue: name))
      #expect(
        try TransportV3Crypto.openUnreliable(
          suite: suite,
          material: material,
          h3: h3,
          direction: direction,
          header: header,
          ciphertext: ciphertext
        ) == plaintext,
        Comment(rawValue: name))
      #expect(encodedHeader + ciphertext == expectedWire, Comment(rawValue: name))

      var malformedHeader = encodedHeader
      malformedHeader[5] = 1
      #expect(throws: TransportV3CryptoError.invalidUnreliableMessage) {
        try UnreliableHeaderV3(encoded: malformedHeader)
      }
      let zeroExpiryHeader = UnreliableHeaderV3(
        epoch: epoch,
        sequence: sequence,
        expiresAtUnixMilliseconds: 0,
        ciphertextLength: UInt32(plaintext.count + TransportV3Crypto.aeadTagBytes)
      )
      #expect(throws: TransportV3CryptoError.invalidUnreliableMessage) {
        try zeroExpiryHeader.encoded()
      }
      let emptyPlaintextHeader = UnreliableHeaderV3(
        epoch: epoch,
        sequence: sequence,
        expiresAtUnixMilliseconds: expiresAt,
        ciphertextLength: UInt32(TransportV3Crypto.aeadTagBytes)
      )
      #expect(throws: TransportV3CryptoError.invalidUnreliableMessage) {
        try emptyPlaintextHeader.encoded()
      }
      var tampered = ciphertext
      tampered[tampered.startIndex] ^= 1
      #expect(throws: TransportV3CryptoError.authenticationFailed) {
        try TransportV3Crypto.openUnreliable(
          suite: suite,
          material: material,
          h3: h3,
          direction: direction,
          header: header,
          ciphertext: tampered
        )
      }
      #expect(throws: TransportV3CryptoError.unreliableMessageTooLarge) {
        try TransportV3Crypto.sealUnreliable(
          suite: suite,
          material: material,
          h3: h3,
          direction: direction,
          header: header,
          plaintext: Data()
        )
      }
    }
  }

  @Test func sharedSwiftCapabilityVectorsMatchExactBytesAndDigests() throws {
    let root = try Self.loadVectorObject("capability_vectors.json")
    let vectors = try #require(root["vectors"] as? [[String: Any]])
    let expectedNames: Set<String> = [
      "go-native",
      "typescript-browser-ca-only",
      "typescript-browser-chromium-151.0.7922.34",
      "typescript-node",
      "rust-native",
      "swift-ios",
      "swift-macos",
      "swift-linux",
    ]
    #expect(vectors.count == expectedNames.count)
    var names = Set<String>()
    for vector in vectors {
      let name = try #require(vector["name"] as? String)
      #expect(names.insert(name).inserted, Comment(rawValue: "duplicate \(name)"))
      let canonical = try #require(vector["canonical_json"] as? String)
      let descriptor = try RuntimeCapabilityDescriptorV3.decode(Data(canonical.utf8))
      let reproduced = try descriptor.canonicalJSON()
      #expect(reproduced == Data(canonical.utf8), Comment(rawValue: name))
      let expectedDigest = try Data(hexV3: #require(vector["digest_hex"] as? String))
      #expect(
        FlowersecJCSV3.hashLP(
          domain: "flowersec-v3-runtime-capability\0", canonical: reproduced)
          == expectedDigest,
        Comment(rawValue: "\(name) production capability domain"))
      #expect(try descriptor.digest() == expectedDigest, Comment(rawValue: name))
    }
    #expect(names == expectedNames)
    for (name, capability) in [
      ("swift-ios", RuntimeCapabilitiesV3.iOS),
      ("swift-macos", RuntimeCapabilitiesV3.macOS),
      ("swift-linux", RuntimeCapabilitiesV3.linux),
    ] {
      let vector = try #require(vectors.first(where: { $0["name"] as? String == name }))
      let canonical = try #require(vector["canonical_json"] as? String)
      let digest = try #require(vector["digest_hex"] as? String)
      #expect(try capability.canonicalJSON() == Data(canonical.utf8), Comment(rawValue: name))
      #expect(try capability.digest() == Data(hexV3: digest), Comment(rawValue: name))
      try capability.validateLocalRuntimeProfile(String(name.dropFirst("swift-".count)))
    }
    let go = try #require(vectors.first(where: { $0["name"] as? String == "go-native" }))
    let decodedGo = try RuntimeCapabilityDescriptorV3.decode(
      Data(try #require(go["canonical_json"] as? String).utf8))
    #expect(throws: ArtifactError.self) {
      try decodedGo.validateLocalRuntimeProfile("macos")
    }
    let invalid = try #require(root["invalid"] as? [[String: Any]])
    #expect(invalid.count >= 20)
    for vector in invalid {
      let id = try #require(vector["id"] as? String)
      let value = Data(try #require(vector["value"] as? String).utf8)
      #expect(throws: ArtifactError.self, Comment(rawValue: id)) {
        try RuntimeCapabilityDescriptorV3.decode(value)
      }
    }
  }

  private static func loadVectorObject(_ name: String) throws -> [String: Any] {
    let url = packageRoot().appendingPathComponent("testdata/transport_v3/\(name)")
    let root = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
    return try #require(root as? [String: Any])
  }

  private static func validArtifact() throws -> Data {
    let projection: [String: Any] = [
      "allowed_suites": [1], "channel_id": "channel", "default_suite": 1,
      "establish_timeout_seconds": 30, "idle_timeout_seconds": 0,
      "max_inbound_streams": 1, "profile": "flowersec/3",
      "rekey_completion_timeout_seconds": 30, "rekey_prepare_timeout_seconds": 10,
      "selected_features": 0,
    ]
    let contract = try FlowersecJCSV3.hashLP(
      domain: "flowersec-v3-session-contract\0", value: projection
    ).base64URLEncodedStringV3()
    return try FlowersecJCSV3.encode([
      "correlation": ["tags": [], "v": 3],
      "path": [
        "candidates": [
          [
            "carrier": "websocket", "id": "a", "tls": ["mode": "ca"],
            "url": "wss://example.com:0443/flowersec/v3/direct",
            "wire_profile": "flowersec-direct/3",
          ]
        ],
        "kind": "direct", "listener_audience": "listener",
        "rendezvous_group_id": "group", "routing_token": "token",
      ],
      "profile": "flowersec/3", "scoped": [],
      "session": [
        "allowed_suites": [1], "channel_id": "channel", "contract_hash_b64u": contract,
        "default_suite": 1,
        "e2ee_psk_b64u": Data(repeating: 7, count: 32).base64URLEncodedStringV3(),
        "establish_timeout_seconds": 30, "idle_timeout_seconds": 0,
        "init_expire_at_unix_s": 9_999_999_999, "max_inbound_streams": 1,
        "rekey_completion_timeout_seconds": 30, "rekey_prepare_timeout_seconds": 10,
        "selected_features": 0,
      ],
      "v": 3,
    ])
  }
}

private actor VersionIsolationCarrierStreamV3: TransportV3CarrierStream {
  nonisolated let carrierStreamID: UInt64 = 1
  private let data: Data
  private var offset = 0

  init(_ data: Data) {
    self.data = data
  }

  func read(maxBytes: Int) async throws -> Data? {
    guard offset < data.count else { return nil }
    let end = min(data.count, offset + maxBytes)
    defer { offset = end }
    return Data(data[offset..<end])
  }

  func write(_ data: Data) async throws -> Int { data.count }
  func closeWrite() async throws {}
  func stopSending(code: UInt16) async throws {}
  func reset(code: UInt16) async {}
  nonisolated func abort(code: UInt16) {}
  func close() async {}
}

private enum SpendFailureV3: Error, Equatable {
  case durabilityUnavailable
}

extension Data {
  fileprivate init(hexV3 value: String) throws {
    guard value.count.isMultiple(of: 2) else { throw ArtifactError.invalidArtifact }
    var bytes: [UInt8] = []
    bytes.reserveCapacity(value.count / 2)
    var index = value.startIndex
    while index < value.endIndex {
      let next = value.index(index, offsetBy: 2)
      guard let byte = UInt8(value[index..<next], radix: 16) else {
        throw ArtifactError.invalidArtifact
      }
      bytes.append(byte)
      index = next
    }
    self.init(bytes)
  }
}

private actor CounterV3 {
  private(set) var value = 0
  func increment() { value += 1 }
}
