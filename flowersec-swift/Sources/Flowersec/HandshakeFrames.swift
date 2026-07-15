import Foundation

enum FlowersecHandshakeFrame {
  static func encode(type: UInt8, payload: Data) -> Data {
    var data = Data()
    data.append(FlowersecWire.handshakeMagic)
    data.append(FlowersecWire.protocolVersion)
    data.append(type)
    data.appendUInt32BE(UInt32(payload.count))
    data.append(payload)
    return data
  }

  static func decode(_ frame: Data, expectedType: UInt8) throws -> Data {
    guard frame.count >= 10 else {
      throw FlowersecError.invalidHandshake("Handshake frame is too short.")
    }
    guard frame.prefix(4) == FlowersecWire.handshakeMagic else {
      throw FlowersecError.invalidHandshake("Handshake frame magic is invalid.")
    }
    guard frame[4] == FlowersecWire.protocolVersion else {
      throw FlowersecError.invalidHandshake("Handshake frame version is invalid.")
    }
    guard frame[5] == expectedType else {
      throw FlowersecError.invalidHandshake("Unexpected handshake frame type.")
    }
    let length = Int(frame.readUInt32BE(at: 6))
    guard length <= FlowersecWire.maxHandshakePayloadBytes, frame.count == 10 + length else {
      throw FlowersecError.invalidHandshake("Handshake frame length is invalid.")
    }
    return frame.subdata(in: 10..<frame.count)
  }
}

struct E2EEInitMessage: Codable {
  var channelID: String
  var role: UInt8
  var version: UInt8
  var suite: Int
  var clientEphPubB64u: String
  var nonceCB64u: String
  var clientFeatures: UInt32

  private enum CodingKeys: String, CodingKey {
    case channelID = "channel_id"
    case role
    case version
    case suite
    case clientEphPubB64u = "client_eph_pub_b64u"
    case nonceCB64u = "nonce_c_b64u"
    case clientFeatures = "client_features"
  }
}

struct E2EEResponseMessage: Codable {
  var handshakeID: String
  var serverEphPubB64u: String
  var nonceSB64u: String
  var serverFeatures: UInt32

  private enum CodingKeys: String, CodingKey {
    case handshakeID = "handshake_id"
    case serverEphPubB64u = "server_eph_pub_b64u"
    case nonceSB64u = "nonce_s_b64u"
    case serverFeatures = "server_features"
  }
}

struct E2EEAckMessage: Codable {
  var handshakeID: String
  var timestampUnixS: UInt64
  var authTagB64u: String

  private enum CodingKeys: String, CodingKey {
    case handshakeID = "handshake_id"
    case timestampUnixS = "timestamp_unix_s"
    case authTagB64u = "auth_tag_b64u"
  }
}

struct TunnelAttach: Encodable {
  var v: UInt32
  var channelID: String
  var role: UInt8
  var token: String
  var endpointInstanceID: String
  var caps: [String: String]?

  func encoded() throws -> String {
    let data = try JSONEncoder.flowersecWire.encode(self)
    guard let text = String(data: data, encoding: .utf8) else {
      throw FlowersecError(
        path: .tunnel,
        stage: .attach,
        code: .invalidInput,
        message: "Tunnel attach JSON could not be encoded."
      )
    }
    return text
  }

  private enum CodingKeys: String, CodingKey {
    case v
    case channelID = "channel_id"
    case role
    case token
    case endpointInstanceID = "endpoint_instance_id"
    case caps
  }
}

extension JSONEncoder {
  static var flowersecWire: JSONEncoder {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return encoder
  }
}
