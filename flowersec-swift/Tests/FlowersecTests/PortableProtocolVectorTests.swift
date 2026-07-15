import Foundation
import XCTest

@testable import Flowersec

final class PortableProtocolVectorTests: XCTestCase {
  func testSharedPortableProtocolVectors() async throws {
    let vectors: PortableVectors = try readJSON("testdata/portable_protocol_vectors.json")
    XCTAssertEqual(vectors.version, 1)

    for item in vectors.transportPolicy {
      let policy: TransportSecurityPolicy
      switch item.policy {
      case "require_tls": policy = .requireTLS
      case "allow_plaintext_for_loopback": policy = .allowPlaintextForLoopback
      case "allow_plaintext": policy = .allowPlaintext
      default:
        XCTFail("Unknown transport policy: \(item.policy)")
        continue
      }
      do {
        try await FlowersecTransportSecurity.enforce(
          url: try XCTUnwrap(URL(string: item.url)),
          path: .direct,
          options: ConnectOptions(transportSecurityPolicy: policy)
        )
        XCTAssertTrue(item.allowed, "Expected transport policy denial for \(item.url)")
      } catch let error as FlowersecError {
        XCTAssertFalse(item.allowed, "Unexpected transport policy denial for \(item.url)")
        XCTAssertEqual(error.code, .transportPolicyDenied)
      }
    }

    let header = try decodeHex(vectors.yamuxHeader.bytesHex)
    XCTAssertEqual(header.count, 12)
    XCTAssertEqual(header[0], vectors.yamuxHeader.version)
    XCTAssertEqual(header[1], vectors.yamuxHeader.type)
    XCTAssertEqual(readUInt16(header, 2), vectors.yamuxHeader.flags)
    XCTAssertEqual(readUInt32(header, 4), vectors.yamuxHeader.streamID)
    XCTAssertEqual(readUInt32(header, 8), vectors.yamuxHeader.length)

    let rpc = try RPCEnvelope(data: JSONEncoder().encode(vectors.rpcEnvelope))
    XCTAssertEqual(rpc.typeID, 7)
    XCTAssertEqual(rpc.requestID, 42)
    XCTAssertEqual(
      try JSONDecoder().decode([String: String].self, from: rpc.payload)["message"],
      "flowersec"
    )

    let encodedError = try Controlplane.encodeErrorEnvelope(
      code: vectors.controlplaneErrorEnvelope.error.code,
      message: vectors.controlplaneErrorEnvelope.error.message
    )
    XCTAssertEqual(
      try JSONSerialization.jsonObject(with: encodedError) as? NSDictionary,
      try JSONSerialization.jsonObject(
        with: JSONEncoder().encode(vectors.controlplaneErrorEnvelope)
      ) as? NSDictionary
    )
    XCTAssertEqual(vectors.proxyHTTPRequestMeta.version, ProxyProtocol.version)
    XCTAssertEqual(vectors.proxyHTTPRequestMeta.method, "POST")
    XCTAssertEqual(vectors.proxyHTTPRequestMeta.timeoutMilliseconds, 1500)
    XCTAssertEqual(vectors.proxyWebSocketOpenMeta.version, ProxyProtocol.version)
    XCTAssertEqual(vectors.proxyWebSocketOpenMeta.connectionID, "connection-vector-1")
    XCTAssertEqual(vectors.diagnosticEvent.path, .tunnel)
    XCTAssertEqual(vectors.diagnosticEvent.stage, .yamux)
    XCTAssertEqual(vectors.diagnosticEvent.code, "liveness_timeout")

    let errors: CodeRegistry = try readJSON("stability/connect_error_code_registry.json")
    XCTAssertTrue(errors.codes.contains { $0.code == "resource_exhausted" })
    let diagnostics: CodeRegistry = try readJSON(
      "stability/connect_diagnostics_code_registry.json"
    )
    XCTAssertTrue(diagnostics.codes.contains { $0.code == vectors.diagnosticEvent.code })
  }

  private func readJSON<Value: Decodable>(_ path: String) throws -> Value {
    let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    return try JSONDecoder().decode(
      Value.self,
      from: Data(contentsOf: root.appendingPathComponent(path))
    )
  }

  private func decodeHex(_ value: String) throws -> Data {
    guard value.count.isMultiple(of: 2) else {
      throw FlowersecError.invalidYamux("Hex input must have an even length.")
    }
    var output = Data()
    var index = value.startIndex
    while index < value.endIndex {
      let end = value.index(index, offsetBy: 2)
      guard let byte = UInt8(value[index..<end], radix: 16) else {
        throw FlowersecError.invalidYamux("Hex input is invalid.")
      }
      output.append(byte)
      index = end
    }
    return output
  }

  private func readUInt16(_ data: Data, _ offset: Int) -> UInt16 {
    UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
  }

  private func readUInt32(_ data: Data, _ offset: Int) -> UInt32 {
    UInt32(data[offset]) << 24 | UInt32(data[offset + 1]) << 16
      | UInt32(data[offset + 2]) << 8 | UInt32(data[offset + 3])
  }
}

private struct PortableVectors: Decodable {
  var version: Int
  var transportPolicy: [TransportCase]
  var yamuxHeader: YamuxHeaderVector
  var rpcEnvelope: RPCEnvelopeVector
  var controlplaneErrorEnvelope: ControlplaneErrorEnvelopeVector
  var proxyHTTPRequestMeta: ProxyHTTPRequestMeta
  var proxyWebSocketOpenMeta: ProxyWebSocketOpenMeta
  var diagnosticEvent: DiagnosticEvent

  enum CodingKeys: String, CodingKey {
    case version
    case transportPolicy = "transport_policy"
    case yamuxHeader = "yamux_header"
    case rpcEnvelope = "rpc_envelope"
    case controlplaneErrorEnvelope = "controlplane_error_envelope"
    case proxyHTTPRequestMeta = "proxy_http_request_meta"
    case proxyWebSocketOpenMeta = "proxy_ws_open_meta"
    case diagnosticEvent = "diagnostic_event"
  }
}

private struct TransportCase: Decodable {
  var url: String
  var policy: String
  var allowed: Bool
}

private struct YamuxHeaderVector: Decodable {
  var bytesHex: String
  var version: UInt8
  var type: UInt8
  var flags: UInt16
  var streamID: UInt32
  var length: UInt32

  enum CodingKeys: String, CodingKey {
    case bytesHex = "bytes_hex"
    case version
    case type
    case flags
    case streamID = "stream_id"
    case length
  }
}

private struct RPCEnvelopeVector: Codable {
  var typeID: UInt32
  var requestID: UInt64
  var responseTo: UInt64
  var payload: [String: String]

  enum CodingKeys: String, CodingKey {
    case typeID = "type_id"
    case requestID = "request_id"
    case responseTo = "response_to"
    case payload
  }
}

private struct ControlplaneErrorEnvelopeVector: Codable {
  var error: ErrorBody

  struct ErrorBody: Codable {
    var code: String
    var message: String
  }
}

private struct CodeRegistry: Decodable {
  var codes: [Code]

  struct Code: Decodable {
    var code: String
  }
}
