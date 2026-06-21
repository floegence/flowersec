import Foundation
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

  private enum CodingKeys: String, CodingKey {
    case transcriptHashes = "transcript_hash"
    case recordFrames = "record_frame"
  }
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

func packageRoot(filePath: String = #filePath) -> URL {
  URL(fileURLWithPath: filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
}
