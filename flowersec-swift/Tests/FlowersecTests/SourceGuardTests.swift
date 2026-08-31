import Foundation
import XCTest

final class SourceGuardTests: XCTestCase {
  func testLegacyRuntimeFilesAreDeleted() {
    let sourceRoot = packageRoot().appendingPathComponent("flowersec-swift/Sources/Flowersec")
    for name in [
      "AppleWebSocketRuntimeAdapterV2.swift",
      "Artifact.swift",
      "ArtifactAdmissionV2.swift",
      "ConnectionControllerV2.swift",
      "IDNAHostV2.swift",
      "OpaqueSessionV2.swift",
      "SessionConnectorV2.swift",
      "TransportV2.swift",
      "TransportV2Crypto.swift",
      "TransportV2Handshake.swift",
      "TransportV2Open.swift",
      "TransportV2Session.swift",
    ] {
      XCTAssertFalse(FileManager.default.fileExists(atPath: sourceRoot.appendingPathComponent(name).path))
    }
  }

  func testPublicSurfaceHasNoVersionedOrDeprecatedAliases() throws {
    let sourceRoot = packageRoot().appendingPathComponent("flowersec-swift/Sources/Flowersec")
    let sources = try swiftFiles(under: sourceRoot)
      .map { try String(contentsOf: $0, encoding: .utf8) }
      .joined(separator: "\n")
    XCTAssertFalse(sources.contains("@available(*, deprecated"))
    for line in sources.split(separator: "\n") where line.trimmingCharacters(in: .whitespaces).hasPrefix("public ") {
      XCTAssertFalse(line.contains("V2"), "versioned legacy public declaration: \(line)")
      XCTAssertFalse(line.contains("V3"), "versioned current alias leaked publicly: \(line)")
    }
  }

  func testMaintainedRuntimeContainsNoLegacyTransportImplementation() throws {
    let sourceRoot = packageRoot().appendingPathComponent("flowersec-swift/Sources/Flowersec")
    for file in try swiftFiles(under: sourceRoot) {
      let lines = try String(contentsOf: file, encoding: .utf8).split(separator: "\n")
      for line in lines {
        if line.contains("flowersec.rpc.v2") { continue }
        for token in ["TransportV2", "ArtifactV2", "SessionConnectorV2", "FSB2", "FSA2"] {
          XCTAssertFalse(line.contains(token), "\(file.lastPathComponent) contains \(token)")
        }
      }
    }
  }

  func testSDKDoesNotContainDownstreamProductSemantics() throws {
    let sourceRoot = packageRoot().appendingPathComponent("flowersec-swift/Sources/Flowersec")
    let forbidden = ["Redeven", "RedevenFlowersec", "FlowersecDirectClient", "RuntimeTerminal"]
    for file in try swiftFiles(under: sourceRoot) {
      let text = try String(contentsOf: file, encoding: .utf8)
      for token in forbidden {
        XCTAssertFalse(text.contains(token), "\(file.lastPathComponent) contains \(token)")
      }
    }
  }

  private func swiftFiles(under root: URL) throws -> [URL] {
    guard let enumerator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey]) else {
      throw NSError(domain: "FlowersecSourceGuard", code: 1)
    }
    return try enumerator.compactMap { element in
      guard let url = element as? URL, url.pathExtension == "swift" else { return nil }
      return try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true ? url : nil
    }
  }
}
