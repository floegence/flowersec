import Foundation
import XCTest

final class SourceGuardTests: XCTestCase {
  private let downstreamProductTokens = [
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

    let files = try swiftFiles(under: sourceRoot)
    for file in files {
      let text = try String(contentsOf: file, encoding: .utf8)
      for token in downstreamProductTokens {
        XCTAssertFalse(
          text.contains(token),
          "\(file.path) must not contain downstream product token \(token)"
        )
      }
    }
  }

  func testPublishedDocsAndExamplesDoNotContainDownstreamProductSemantics() throws {
    let root = packageRoot()
    let roots = [
      root.appendingPathComponent("README.md"),
      root.appendingPathComponent("flowersec-swift/README.md"),
      root.appendingPathComponent("docs"),
      root.appendingPathComponent("examples"),
      root.appendingPathComponent(".github"),
    ]
    let files = try roots.flatMap { try textFiles(under: $0) }
    for file in files {
      if file.path.hasSuffix("/docs/MIGRATION_TRANSPORT_V2.md") {
        continue
      }
      let text = try String(contentsOf: file, encoding: .utf8)
      for token in downstreamProductTokens {
        XCTAssertFalse(
          text.contains(token),
          "\(file.path) must not contain downstream product token \(token)"
        )
      }
    }
  }

  func testTransportV2PublicContractDoesNotExposeCarrierImplementations() throws {
    let sourceRoot = packageRoot().appendingPathComponent("flowersec-swift/Sources/Flowersec")
    for name in ["TransportV2.swift", "TransportV2Crypto.swift"] {
      let text = try String(
        contentsOf: sourceRoot.appendingPathComponent(name),
        encoding: .utf8
      )
      for token in ["NWProtocolQUIC", "NWConnection", "FlowersecYamux", "YamuxStream"] {
        XCTAssertFalse(text.contains(token), "\(name) must not expose \(token)")
      }
    }
  }

  private func swiftFiles(under root: URL) throws -> [URL] {
    try textFiles(under: root).filter { $0.pathExtension == "swift" }
  }

  private func textFiles(under root: URL) throws -> [URL] {
    let keys: [URLResourceKey] = [.isDirectoryKey, .isRegularFileKey]
    let rootValues = try root.resourceValues(forKeys: Set(keys))
    if rootValues.isRegularFile == true {
      return [root]
    }
    guard rootValues.isDirectory == true else {
      return []
    }
    guard
      let enumerator = FileManager.default.enumerator(
        at: root,
        includingPropertiesForKeys: keys
      )
    else {
      throw NSError(
        domain: "FlowersecSourceGuard",
        code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Unable to enumerate \(root.path)"]
      )
    }

    var files: [URL] = []
    for case let url as URL in enumerator {
      let values = try url.resourceValues(forKeys: Set(keys))
      if values.isDirectory == true && ignoredDirectoryNames.contains(url.lastPathComponent) {
        enumerator.skipDescendants()
        continue
      }
      if values.isRegularFile == true && isTextFile(url) {
        files.append(url)
      }
    }
    return files
  }

  private func isTextFile(_ url: URL) -> Bool {
    switch url.pathExtension {
    case "go", "json", "md", "mjs", "swift", "ts", "tsx", "txt", "yaml", "yml":
      return true
    default:
      return false
    }
  }

  private var ignoredDirectoryNames: Set<String> {
    [".build", ".git", ".swiftpm", "dist", "node_modules"]
  }
}
