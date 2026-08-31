import Foundation
import XCTest

@testable import Flowersec

final class ServerParityTests: XCTestCase {
  func testClientProfile() async throws {
    #if os(macOS)
      guard
        let encoded = ProcessInfo.processInfo.environment["FLOWERSEC_PARITY_READY_BASE64"],
        let data = Data(base64Encoded: encoded),
        let ready = try JSONSerialization.jsonObject(with: data) as? [String: Any],
        let artifactJSON = ready["artifact_json"] as? String,
        let trustPEM = ready["trust_pem"] as? String,
        let origin = ready["origin"] as? String,
        let path = ProcessInfo.processInfo.environment["FLOWERSEC_PARITY_PATH"],
        path == "direct" || path == "tunnel"
      else {
        throw XCTSkip("server parity input is supplied by the parity runner")
      }

      let session = try await connect(
        lease: ArtifactLease(artifact: try parseArtifact(Data(artifactJSON.utf8))) {},
        options: ConnectorOptions(
          origin: origin,
          connectTimeout: .seconds(5),
          trustRootsPEM: [Data(trustPEM.utf8)]
        )
      )
      let echo: [String: String] = try await session.rpc.call(
        7001,
        ["value": "ping"],
        as: [String: String].self,
        timeout: .seconds(5)
      )
      XCTAssertEqual(echo["value"], "ping")
      try await session.rpc.notify(7002, ["value": "notify"])

      let stream = try await session.openStream(
        kind: "parity.echo",
        metadata: try StreamMetadata(["cell": .string(path)])
      )
      _ = try await stream.write(Data("hello".utf8))
      try await stream.closeWrite()
      let echoed = try await stream.read(maxBytes: 32)
      XCTAssertEqual(echoed, Data("world".utf8))
      let endOfStream = try await stream.read(maxBytes: 32)
      XCTAssertNil(endOfStream)

      let reset = try await session.openStream(kind: "parity.reset")
      _ = try await reset.write(Data("reset".utf8))
      try await reset.closeWrite()
      do {
        _ = try await reset.read(maxBytes: 32)
        XCTFail("reset stream succeeded")
      } catch {}

      try await session.rekey()
      _ = try await session.probeLiveness()
      let completed: [String: String] = try await session.rpc.call(
        7003,
        ["value": "complete"],
        as: [String: String].self,
        timeout: .seconds(5)
      )
      XCTAssertEqual(completed["value"], "complete")
      try await session.close()
    #else
      throw XCTSkip("the WebSocket runtime is available on Apple platforms")
    #endif
  }
}
