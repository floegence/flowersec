import Crypto
import Foundation
import XCTest

@testable import Flowersec

final class TransportV4CryptoVectorTests: XCTestCase {
  func testProductionNoiseMatchesBothSharedTranscriptsAndAllNegativeFlights() throws {
    let corpus = try cryptoCorpus("noise")
    let input = corpus["inputs"]
    let transcripts = corpus["transcripts"].array!
    func pair(_ profile: V4CryptoProfile) throws -> (
      V4NoiseState, V4NoiseState, V4SoftwareDH, V4SoftwareDH
    ) {
      let c = try V4SoftwareDH(
        profile: profile, material: cryptoHex(input["client_static_private_hex"].text!))
      let s = try V4SoftwareDH(
        profile: profile, material: cryptoHex(input["server_static_private_hex"].text!))
      let psk = cryptoHex(input["psk_hex"].text!)
      let prologue = cryptoHex(input["prologue_hex"].text!)
      return try (
        V4NoiseState(
          profile: profile, role: .client, localPublic: c.publicKey, peerPublic: s.publicKey,
          sharedStatic: { try c.shared($0) }, psk: psk, prologue: prologue),
        V4NoiseState(
          profile: profile, role: .server, localPublic: s.publicKey, peerPublic: c.publicKey,
          sharedStatic: { try s.shared($0) }, psk: psk, prologue: prologue),
        V4SoftwareDH(
          profile: profile, material: cryptoHex(input["client_ephemeral_private_hex"].text!)),
        V4SoftwareDH(
          profile: profile, material: cryptoHex(input["server_ephemeral_private_hex"].text!))
      )
    }
    for vector in transcripts {
      let profile = V4CryptoProfile(rawValue: vector["profile"].text!)!
      let (c, s, ce, se) = try pair(profile)
      let m1 = try c.write(ephemeral: ce)
      XCTAssertEqual(m1, cryptoHex(vector["message1_hex"].text!))
      try s.read(m1)
      let m2 = try s.write(ephemeral: se)
      XCTAssertEqual(m2, cryptoHex(vector["message2_hex"].text!))
      try c.read(m2)
      for state in [c, s] {
        let material = try state.finish(context: cryptoHex(input["context_digest_hex"].text!))
        XCTAssertEqual(material.hash, cryptoHex(vector["handshake_hash_hex"].text!))
        XCTAssertEqual(
          material.root.withUnsafeBytes { Data($0) }, cryptoHex(vector["initial_root_hex"].text!))
        XCTAssertThrowsError(
          try state.finish(context: cryptoHex(input["context_digest_hex"].text!)))
      }
    }
    for negative in corpus["negatives"].array! {
      let vector = transcripts.first { $0["id"].text == negative["transcript"].text }!
      let profile = V4CryptoProfile(rawValue: vector["profile"].text!)!
      let (c, s, ce, _) = try pair(profile)
      let changed = cryptoHex(negative["message_hex"].text!)
      if negative["flight"].uint == 1 {
        XCTAssertThrowsError(try s.read(changed), negative["id"].text!)
      } else {
        _ = try c.write(ephemeral: ce)
        XCTAssertThrowsError(try c.read(changed), negative["id"].text!)
      }
    }
    XCTAssertEqual(corpus["negatives"].array!.count, 524)
  }

  func testProductionReadyMatchesSharedMessagesMACsAndAllRejections() throws {
    let corpus = try cryptoCorpus("ready")
    func material(_ context: V4JSON) throws -> (V4ReadyBinding, SymmetricKey, Data, V4CryptoRole) {
      guard let name = context["crypto_profile_id"].text,
        let profile = V4CryptoProfile(rawValue: name),
        let raw = context["role"].uint, raw < 2, let role = V4CryptoRole(rawValue: UInt8(raw))
      else { throw V4CryptoFailure.configuration }
      func bytes(_ name: String) -> Data { cryptoHex(context[name + "_hex"].text!) }
      let certificate = bytes("certificate_digest")
      let identity = bytes("public_key")
      return (
        V4ReadyBinding(
          profile: profile, context: bytes("transport_context_digest"),
          admission: bytes("admission_binding"), certificates: [certificate, certificate],
          identities: [identity, identity], fsb: bytes("fsb_digest"), fsa: bytes("fsa_digest"),
          features: context["selected_features"].uint!), SymmetricKey(data: bytes("epoch_root")),
        bytes("handshake_hash"), role
      )
    }
    let vectors = corpus["vectors"].array!
    for vector in vectors {
      let (binding, root, hash, role) = try material(vector["context"])
      let proof = cryptoHex(vector["identity_proof_hex"].text!)
      XCTAssertEqual(
        binding.message(hash: hash, role: role), cryptoHex(vector["signature_message_hex"].text!))
      XCTAssertEqual(
        binding.message(hash: hash, role: role, proof: proof),
        cryptoHex(vector["mac_message_hex"].text!))
      let key = binding.key(root: root, hash: hash, role: role)
      XCTAssertEqual(key.withUnsafeBytes { Data($0) }, cryptoHex(vector["key_hex"].text!))
      XCTAssertEqual(
        V4Crypto.mac(key, binding.message(hash: hash, role: role, proof: proof)),
        cryptoHex(vector["confirmation_mac_hex"].text!))
      try binding.verify(cryptoHex(vector["ready_hex"].text!), root: root, hash: hash, role: role)
    }
    for negative in corpus["negatives"].array! {
      let source = vectors.first { $0["id"].text == negative["source"].text }!
      let context = V4JSON.object(
        source["context"].object!.merging(negative["context_patch"].object!) { _, new in new })
      XCTAssertThrowsError(
        try {
          let (binding, root, hash, role) = try material(context)
          try binding.verify(
            cryptoHex(negative["ready_hex"].text!), root: root, hash: hash, role: role)
        }(), negative["id"].text!)
    }
    XCTAssertEqual(vectors.count, 8)
    XCTAssertEqual(corpus["negatives"].array!.count, 1896)
  }

  func testProductionRecordDerivationAEADAndAllSharedNegativeInputs() throws {
    let corpus = try cryptoCorpus("records")
    let vectors = corpus["vectors"].array!
    for vector in vectors {
      let profile = V4CryptoProfile(rawValue: vector["profile"].text!)!
      let role = V4CryptoRole(rawValue: UInt8(vector["direction"].uint!))!
      let epoch = UInt32(vector["epoch"].uint!)
      let scope = vector["sequence_scope"].uint!
      let sequence = vector["sequence"].uint!
      func bytes(_ name: String) -> Data { cryptoHex(vector[name + "_hex"].text!) }
      let key = V4RecordMaterial.key(
        root: SymmetricKey(data: bytes("epoch_root")), profile: profile,
        hash: bytes("handshake_hash"), epoch: epoch, direction: role, scope: scope)
      let nonce = V4RecordMaterial.nonce(epoch: epoch, sequence: sequence)
      let aad = V4RecordMaterial.aad(
        profile: profile, envelope: bytes("envelope_header"), header: bytes("record_header"),
        direction: role)
      XCTAssertEqual(key.withUnsafeBytes { Data($0) }, bytes("key"))
      XCTAssertEqual(nonce, bytes("nonce"))
      XCTAssertEqual(aad, bytes("aad"))
      XCTAssertEqual(
        try V4Crypto.seal(profile, key: key, nonce: nonce, aad: aad, plaintext: bytes("plaintext")),
        bytes("ciphertext"))
      XCTAssertEqual(
        try V4Crypto.open(
          profile, key: key, nonce: nonce, aad: aad, ciphertext: bytes("ciphertext")),
        bytes("plaintext"))
    }
    for negative in corpus["negatives"].array! {
      let vector = vectors.first { $0["id"].text == negative["source"].text }!
      let profile = V4CryptoProfile(rawValue: vector["profile"].text!)!
      var bytes = Dictionary(
        uniqueKeysWithValues: ["key", "nonce", "aad", "ciphertext"].map {
          ($0, cryptoHex(vector[$0 + "_hex"].text!))
        })
      bytes[negative["field"].text!] = cryptoHex(negative["value_hex"].text!)
      XCTAssertThrowsError(
        try V4Crypto.open(
          profile, key: SymmetricKey(data: bytes["key"]!),
          nonce: bytes["nonce"]!, aad: bytes["aad"]!, ciphertext: bytes["ciphertext"]!),
        negative["id"].text!)
    }
    XCTAssertEqual(vectors.count, 16)
    XCTAssertEqual(corpus["negatives"].array!.count, 2448)
  }

  func testProductionCryptoUsageArithmeticAndExactHardLimits() throws {
    let corpus = try cryptoCorpus("crypto_usage")
    var checked = 0
    for vector in corpus["vectors"].array! {
      let expectedError = vector["expected_error"].text
      // The production API uses a Bool and UInt64, so invalid JSON operation
      // names/decimal encodings are not representable inputs to this owner.
      if ["crypto_usage_integer", "crypto_usage_operation"].contains(expectedError) { continue }
      let input = vector["input"]
      let operation = input["operation"].text!
      do {
        let usage = try V4CryptoUsage.delta(
          seal: operation == "seal",
          aadBytes: input["aad_bytes"].uint!, inputBytes: input["input_bytes"].uint!)
        XCTAssertNil(expectedError)
        XCTAssertEqual(usage.seals + usage.opens, vector["expected"]["calls"].uint!)
        XCTAssertEqual(usage.blocks, vector["expected"]["authentication_blocks"].uint!)
        XCTAssertEqual(usage.ciphertextBytes, vector["expected"]["ciphertext_bytes"].uint!)
      } catch { XCTAssertNotNil(expectedError, vector["id"].text!) }
      checked += 1
    }
    XCTAssertEqual(checked, 22)
    let registry = try JSONDecoder().decode(
      V4JSON.self, from: Data(TransportV4Registry.cryptoUsageRegistryJSON.utf8))
    for profile in V4CryptoProfile.allCases {
      let limits = V4CryptoUsage.limits(profile)
      for (name, limit) in [
        ("key", limits.key), ("epoch", limits.epoch), ("session", limits.session),
      ] {
        let specified = registry["profiles"][profile.rawValue][name]
        XCTAssertEqual(limit.seals, specified["seal_calls"].uint)
        XCTAssertEqual(limit.opens, specified["open_attempts"].uint)
        XCTAssertEqual(limit.blocks, specified["authentication_blocks"].uint)
        XCTAssertEqual(limit.ciphertextBytes, specified["ciphertext_bytes"].uint)
        XCTAssertTrue(limit.fits(limit))
        for delta in [
          V4CryptoUsage(seals: 1), V4CryptoUsage(opens: 1), V4CryptoUsage(blocks: 1),
          V4CryptoUsage(ciphertextBytes: 1),
        ] {
          XCTAssertFalse(try limit.adding(delta).fits(limit))
        }
      }
    }
    XCTAssertThrowsError(try V4CryptoUsage(seals: .max).adding(V4CryptoUsage(seals: 1)))
  }
}
