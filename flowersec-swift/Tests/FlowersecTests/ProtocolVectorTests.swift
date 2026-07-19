import Foundation
import Crypto
import XCTest

@testable import Flowersec

final class ProtocolVectorTests: XCTestCase {
  func testBase64URLAndBigEndianHelpers() throws {
    let bytes = Data([0xfb, 0xef, 0xff])
    XCTAssertEqual(bytes.base64URLEncodedString(), "--__")
    XCTAssertEqual(Data(base64URLEncoded: "--__"), bytes)

    var data = Data()
    data.appendUInt16BE(0x1234)
    data.appendUInt32BE(0x5678_9abc)
    data.appendUInt64BE(0x0102_0304_0506_0708)
    XCTAssertEqual(data.readUInt16BE(at: 0), 0x1234)
    XCTAssertEqual(data.readUInt32BE(at: 2), 0x5678_9abc)
    XCTAssertEqual(data.readUInt64BE(at: 6), 0x0102_0304_0506_0708)
  }

  func testSecureRandomRejectsNegativeCount() throws {
    XCTAssertEqual(try Data.secureRandom(count: 0), Data())
    XCTAssertEqual(try Data.secureRandom(count: 33).count, 33)
    XCTAssertThrowsError(try Data.secureRandom(count: -1)) { error in
      XCTAssertEqual((error as? FlowersecError)?.code, .invalidInput)
    }
  }

  func testRecordFrameGoldenVector() throws {
    let vector = try e2eeVectors().recordFrames.first { $0.caseID == "record_app_hello" }
    let unwrapped = try XCTUnwrap(vector)
    let key = try XCTUnwrap(Data(base64URLEncoded: unwrapped.inputs.keyB64u))
    let noncePrefix = try XCTUnwrap(Data(base64URLEncoded: unwrapped.inputs.noncePrefixB64u))
    let frame = try FlowersecRecordCodec.encrypt(
      key: key,
      noncePrefix: noncePrefix,
      flags: UInt8(unwrapped.inputs.flags),
      seq: UInt64(unwrapped.inputs.seq),
      plaintext: Data(unwrapped.inputs.plaintextUTF8.utf8)
    )
    XCTAssertEqual(frame.base64URLEncodedString(), unwrapped.expected.frameB64u)

    let record = try FlowersecRecordCodec.decrypt(
      key: key,
      noncePrefix: noncePrefix,
      frame: frame,
      expectedSeq: UInt64(unwrapped.inputs.seq)
    )
    XCTAssertEqual(record.plaintext, Data(unwrapped.inputs.plaintextUTF8.utf8))
  }

  func testTranscriptHashGoldenVector() throws {
    let vector = try e2eeVectors().transcriptHashes.first { $0.caseID == "transcript_basic_x25519" }
    let unwrapped = try XCTUnwrap(vector)
    let input = unwrapped.inputs
    let transcript = try FlowersecHandshake.transcriptHash(
      input: FlowersecHandshakeTranscriptInput(
        suite: try XCTUnwrap(Suite(rawValue: input.suite)),
        channelID: input.channelID,
        nonceC: try XCTUnwrap(Data(base64URLEncoded: input.nonceCB64u)),
        nonceS: try XCTUnwrap(Data(base64URLEncoded: input.nonceSB64u)),
        clientPublicKey: try XCTUnwrap(Data(base64URLEncoded: input.clientEphPubB64u)),
        serverPublicKey: try XCTUnwrap(Data(base64URLEncoded: input.serverEphPubB64u)),
        serverFeatures: UInt32(input.serverFeatures)
      )
    )
    XCTAssertEqual(transcript.base64URLEncodedString(), unwrapped.expected.transcriptHashB64u)
  }

  func testP256HandshakeSessionKeyGoldenVector() throws {
    let vector = try e2eeVectors().handshakeP256.first { $0.caseID == "handshake_p256_basic" }
    let unwrapped = try XCTUnwrap(vector)
    let input = unwrapped.inputs
    let clientPrivateKey = try P256.KeyAgreement.PrivateKey(
      rawRepresentation: try XCTUnwrap(Data(base64URLEncoded: input.clientEphPrivB64u))
    )
    let serverPrivateKey = try P256.KeyAgreement.PrivateKey(
      rawRepresentation: try XCTUnwrap(Data(base64URLEncoded: input.serverEphPrivB64u))
    )
    let clientPublicKey = clientPrivateKey.publicKey.x963Representation
    let serverPublicKey = serverPrivateKey.publicKey.x963Representation
    XCTAssertEqual(clientPublicKey.base64URLEncodedString(), input.clientEphPubB64u)
    XCTAssertEqual(serverPublicKey.base64URLEncodedString(), input.serverEphPubB64u)

    let serverPeerKey = try P256.KeyAgreement.PublicKey(x963Representation: serverPublicKey)
    let sharedSecret = try clientPrivateKey.sharedSecretFromKeyAgreement(with: serverPeerKey)
    let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }
    XCTAssertEqual(sharedSecretData.base64URLEncodedString(), unwrapped.expected.sharedSecretB64u)

    let transcript = try FlowersecHandshake.transcriptHash(
      input: FlowersecHandshakeTranscriptInput(
        suite: try XCTUnwrap(Suite(rawValue: input.suite)),
        channelID: input.channelID,
        nonceC: try XCTUnwrap(Data(base64URLEncoded: input.nonceCB64u)),
        nonceS: try XCTUnwrap(Data(base64URLEncoded: input.nonceSB64u)),
        clientPublicKey: clientPublicKey,
        serverPublicKey: serverPublicKey,
        serverFeatures: UInt32(input.serverFeatures)
      )
    )
    XCTAssertEqual(transcript.base64URLEncodedString(), unwrapped.expected.transcriptHashB64u)

    let keys = FlowersecHandshake.deriveSessionKeys(
      psk: try XCTUnwrap(Data(base64URLEncoded: input.pskB64u)),
      sharedSecret: sharedSecretData,
      transcript: transcript
    )
    XCTAssertEqual(keys.c2sKey.base64URLEncodedString(), unwrapped.expected.c2sKeyB64u)
    XCTAssertEqual(keys.s2cKey.base64URLEncodedString(), unwrapped.expected.s2cKeyB64u)
    XCTAssertEqual(keys.c2sNoncePrefix.base64URLEncodedString(), unwrapped.expected.c2sNoncePrefixB64u)
    XCTAssertEqual(keys.s2cNoncePrefix.base64URLEncodedString(), unwrapped.expected.s2cNoncePrefixB64u)
    XCTAssertEqual(keys.rekeyBase.base64URLEncodedString(), unwrapped.expected.rekeyBaseB64u)
  }

  func testX25519RejectsSharedLowOrderPublicKeyVectors() throws {
    for vector in try e2eeVectors().handshakeX25519Negative {
      XCTAssertTrue(vector.expected.reject, vector.caseID)
      let privateKey = try Curve25519.KeyAgreement.PrivateKey(
        rawRepresentation: try XCTUnwrap(Data(base64URLEncoded: vector.inputs.privateKeyB64u))
      )
      let peerPublicKey = try Curve25519.KeyAgreement.PublicKey(
        rawRepresentation: try XCTUnwrap(
          Data(base64URLEncoded: vector.inputs.peerPublicKeyB64u)
        )
      )
      XCTAssertThrowsError(
        try FlowersecHandshake.x25519SharedSecret(
          privateKey: privateKey,
          peerPublicKey: peerPublicKey
        ),
        vector.caseID
      )
    }
  }

  private func e2eeVectors() throws -> E2EEVectors {
    let url = packageRoot()
      .appendingPathComponent("idl/flowersec/testdata/v1/e2ee_vectors.json")
    let data = try Data(contentsOf: url)
    return try JSONDecoder().decode(E2EEVectors.self, from: data)
  }
}

private struct E2EEVectors: Decodable {
  var transcriptHashes: [TranscriptHashVector]
  var recordFrames: [RecordFrameVector]
  var handshakeX25519Negative: [HandshakeX25519NegativeVector]
  var handshakeP256: [HandshakeP256Vector]

  private enum CodingKeys: String, CodingKey {
    case transcriptHashes = "transcript_hash"
    case recordFrames = "record_frame"
    case handshakeX25519Negative = "handshake_x25519_negative"
    case handshakeP256 = "handshake_p256"
  }
}

private struct HandshakeX25519NegativeVector: Decodable {
  var caseID: String
  var inputs: HandshakeX25519NegativeInputs
  var expected: HandshakeX25519NegativeExpected

  private enum CodingKeys: String, CodingKey {
    case caseID = "case_id"
    case inputs
    case expected
  }
}

private struct HandshakeX25519NegativeInputs: Decodable {
  var privateKeyB64u: String
  var peerPublicKeyB64u: String

  private enum CodingKeys: String, CodingKey {
    case privateKeyB64u = "private_key_b64u"
    case peerPublicKeyB64u = "peer_public_key_b64u"
  }
}

private struct HandshakeX25519NegativeExpected: Decodable {
  var reject: Bool
}

private struct TranscriptHashVector: Decodable {
  var caseID: String
  var inputs: TranscriptHashInputs
  var expected: TranscriptHashExpected

  private enum CodingKeys: String, CodingKey {
    case caseID = "case_id"
    case inputs
    case expected
  }
}

private struct TranscriptHashInputs: Decodable {
  var suite: Int
  var serverFeatures: Int
  var channelID: String
  var nonceCB64u: String
  var nonceSB64u: String
  var clientEphPubB64u: String
  var serverEphPubB64u: String

  private enum CodingKeys: String, CodingKey {
    case suite
    case serverFeatures = "server_features"
    case channelID = "channel_id"
    case nonceCB64u = "nonce_c_b64u"
    case nonceSB64u = "nonce_s_b64u"
    case clientEphPubB64u = "client_eph_pub_b64u"
    case serverEphPubB64u = "server_eph_pub_b64u"
  }
}

private struct TranscriptHashExpected: Decodable {
  var transcriptHashB64u: String

  private enum CodingKeys: String, CodingKey {
    case transcriptHashB64u = "transcript_hash_b64u"
  }
}

private struct RecordFrameVector: Decodable {
  var caseID: String
  var inputs: RecordFrameInputs
  var expected: RecordFrameExpected

  private enum CodingKeys: String, CodingKey {
    case caseID = "case_id"
    case inputs
    case expected
  }
}

private struct RecordFrameInputs: Decodable {
  var keyB64u: String
  var noncePrefixB64u: String
  var flags: Int
  var seq: Int
  var plaintextUTF8: String

  private enum CodingKeys: String, CodingKey {
    case keyB64u = "key_b64u"
    case noncePrefixB64u = "nonce_prefix_b64u"
    case flags
    case seq
    case plaintextUTF8 = "plaintext_utf8"
  }
}

private struct RecordFrameExpected: Decodable {
  var frameB64u: String

  private enum CodingKeys: String, CodingKey {
    case frameB64u = "frame_b64u"
  }
}

private struct HandshakeP256Vector: Decodable {
  var caseID: String
  var inputs: HandshakeP256Inputs
  var expected: HandshakeP256Expected

  private enum CodingKeys: String, CodingKey {
    case caseID = "case_id"
    case inputs
    case expected
  }
}

private struct HandshakeP256Inputs: Decodable {
  var suite: Int
  var serverFeatures: Int
  var channelID: String
  var nonceCB64u: String
  var nonceSB64u: String
  var clientEphPrivB64u: String
  var serverEphPrivB64u: String
  var clientEphPubB64u: String
  var serverEphPubB64u: String
  var pskB64u: String

  private enum CodingKeys: String, CodingKey {
    case suite
    case serverFeatures = "server_features"
    case channelID = "channel_id"
    case nonceCB64u = "nonce_c_b64u"
    case nonceSB64u = "nonce_s_b64u"
    case clientEphPrivB64u = "client_eph_priv_b64u"
    case serverEphPrivB64u = "server_eph_priv_b64u"
    case clientEphPubB64u = "client_eph_pub_b64u"
    case serverEphPubB64u = "server_eph_pub_b64u"
    case pskB64u = "psk_b64u"
  }
}

private struct HandshakeP256Expected: Decodable {
  var sharedSecretB64u: String
  var transcriptHashB64u: String
  var c2sKeyB64u: String
  var s2cKeyB64u: String
  var c2sNoncePrefixB64u: String
  var s2cNoncePrefixB64u: String
  var rekeyBaseB64u: String

  private enum CodingKeys: String, CodingKey {
    case sharedSecretB64u = "shared_secret_b64u"
    case transcriptHashB64u = "transcript_hash_b64u"
    case c2sKeyB64u = "c2s_key_b64u"
    case s2cKeyB64u = "s2c_key_b64u"
    case c2sNoncePrefixB64u = "c2s_nonce_prefix_b64u"
    case s2cNoncePrefixB64u = "s2c_nonce_prefix_b64u"
    case rekeyBaseB64u = "rekey_base_b64u"
  }
}

func packageRoot(filePath: String = #filePath) -> URL {
  URL(fileURLWithPath: filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
}
