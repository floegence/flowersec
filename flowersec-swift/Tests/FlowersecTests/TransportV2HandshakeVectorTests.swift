import Foundation
import XCTest

@testable import Flowersec

final class TransportV2HandshakeVectorTests: XCTestCase {
  func testHandshakeCodecAndKDFMatchSharedVectors() throws {
    let fixture = try loadFixture()
    XCTAssertEqual(fixture.version, 1)
    XCTAssertEqual(fixture.profile, "flowersec/2")
    XCTAssertFalse(fixture.vectors.isEmpty)

    for vector in fixture.vectors {
      let suite = try XCTUnwrap(TransportCipherSuiteV2(rawValue: vector.suite))
      try TransportV2Handshake.verifyVectorForTesting(
        TransportV2HandshakeVectorInput(
          id: vector.id,
          suite: suite,
          fsc2: try handshakeHex(vector.fsc2Hex),
          clientInit: try handshakeHex(vector.clientInitHex),
          serverCore: try handshakeHex(vector.serverCoreHex),
          serverFinished: try handshakeHex(vector.serverFinishedHex),
          clientCore: try handshakeHex(vector.clientCoreHex),
          clientFinished: try handshakeHex(vector.clientFinishedHex),
          psk: try handshakeHex(vector.pskHex),
          clientPrivate: try handshakeHex(vector.clientPrivateHex),
          serverPrivate: try handshakeHex(vector.serverPrivateHex),
          clientPublic: try XCTUnwrap(Data(base64URLEncoded: vector.clientPublicBase64URL)),
          serverPublic: try XCTUnwrap(Data(base64URLEncoded: vector.serverPublicBase64URL)),
          sharedSecret: try handshakeHex(vector.sharedSecretHex),
          handshakePRK: try handshakeHex(vector.handshakePRKHex),
          h0: try handshakeHex(vector.h0Hex),
          h1: try handshakeHex(vector.h1Hex),
          serverConfirm: try handshakeHex(vector.serverConfirmHex),
          h2: try handshakeHex(vector.h2Hex),
          clientConfirm: try handshakeHex(vector.clientConfirmHex),
          h3: try handshakeHex(vector.h3Hex),
          sessionPRK: try handshakeHex(vector.sessionPRKHex)
        )
      )
    }
  }

  private func loadFixture() throws -> HandshakeVectorFile {
    let url = packageRoot().appendingPathComponent("testdata/transport_v2/handshake_vectors.json")
    return try JSONDecoder().decode(HandshakeVectorFile.self, from: Data(contentsOf: url))
  }
}

private struct HandshakeVectorFile: Decodable {
  let version: UInt8
  let profile: String
  let vectors: [HandshakeVector]
}

private struct HandshakeVector: Decodable {
  let id: String
  let suite: UInt16
  let pskHex: String
  let clientPrivateHex: String
  let serverPrivateHex: String
  let clientPublicBase64URL: String
  let serverPublicBase64URL: String
  let sharedSecretHex: String
  let fsc2Hex: String
  let clientInitHex: String
  let serverCoreHex: String
  let serverFinishedHex: String
  let clientCoreHex: String
  let clientFinishedHex: String
  let handshakePRKHex: String
  let h0Hex: String
  let h1Hex: String
  let serverConfirmHex: String
  let h2Hex: String
  let clientConfirmHex: String
  let h3Hex: String
  let sessionPRKHex: String

  private enum CodingKeys: String, CodingKey {
    case id
    case suite
    case pskHex = "psk_hex"
    case clientPrivateHex = "client_private_hex"
    case serverPrivateHex = "server_private_hex"
    case clientPublicBase64URL = "client_public_b64u"
    case serverPublicBase64URL = "server_public_b64u"
    case sharedSecretHex = "shared_secret_hex"
    case fsc2Hex = "fsc2_hex"
    case clientInitHex = "client_init_hex"
    case serverCoreHex = "server_core_hex"
    case serverFinishedHex = "server_finished_hex"
    case clientCoreHex = "client_core_hex"
    case clientFinishedHex = "client_finished_hex"
    case handshakePRKHex = "handshake_prk_hex"
    case h0Hex = "h0_hex"
    case h1Hex = "h1_hex"
    case serverConfirmHex = "server_confirm_hex"
    case h2Hex = "h2_hex"
    case clientConfirmHex = "client_confirm_hex"
    case h3Hex = "h3_hex"
    case sessionPRKHex = "session_prk_hex"
  }
}

private enum HandshakeHexError: Error {
  case invalidLength
  case invalidByte
}

private func handshakeHex(_ value: String) throws -> Data {
  guard value.utf8.count.isMultiple(of: 2) else { throw HandshakeHexError.invalidLength }
  var data = Data()
  data.reserveCapacity(value.utf8.count / 2)
  var index = value.startIndex
  while index < value.endIndex {
    let next = value.index(index, offsetBy: 2)
    guard let byte = UInt8(value[index..<next], radix: 16) else {
      throw HandshakeHexError.invalidByte
    }
    data.append(byte)
    index = next
  }
  return data
}
