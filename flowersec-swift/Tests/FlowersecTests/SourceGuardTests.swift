import Foundation
import XCTest

final class SourceGuardTests: XCTestCase {
  func testSwiftSDKDoesNotContainRedevenProductSemantics() throws {
    let sourceRoot = packageRoot().appendingPathComponent("flowersec-swift/Sources/Flowersec")
    let forbiddenFileNames = [
      "RuntimeTypedRPC.swift",
      "RuntimeJSONValue.swift",
      "RuntimeRPCPayloads.swift",
      "DirectRuntimeClient.swift",
    ]
    for name in forbiddenFileNames {
      XCTAssertFalse(
        FileManager.default.fileExists(atPath: sourceRoot.appendingPathComponent(name).path),
        "Swift SDK must not include downstream product file \(name)"
      )
    }

    let forbidden = [
      "Redeven",
      "redeven",
      "RedevenFlowersec",
      "RedevenRPCClient",
      "FlowersecDirectClient",
      "FlowersecDirectSession",
      "FlowersecDirectError",
      "RuntimeFS",
      "RuntimeGit",
      "RuntimeTerminal",
      "RuntimeFlower",
      "RuntimeTypedRPC",
      "RuntimeJSONValue",
      "RuntimeRPCPayload",
      "FlowerMessage",
      "TerminalSession",
      "MonitorSnapshot",
      "direct runtime",
    ]
    let files = try swiftFiles(under: sourceRoot)
    for file in files {
      let text = try String(contentsOf: file, encoding: .utf8)
      for token in forbidden {
        XCTAssertFalse(
          text.contains(token),
          "\(file.path) must not contain downstream product token \(token)"
        )
      }
    }
  }

  private func swiftFiles(under root: URL) throws -> [URL] {
    let keys: [URLResourceKey] = [.isRegularFileKey]
    let urls = FileManager.default.enumerator(
      at: root,
      includingPropertiesForKeys: keys
    )?
      .compactMap { $0 as? URL } ?? []
    return try urls.filter { url in
      let values = try url.resourceValues(forKeys: Set(keys))
      return values.isRegularFile == true && url.pathExtension == "swift"
    }
  }
}
