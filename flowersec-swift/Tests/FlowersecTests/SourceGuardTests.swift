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

  func testTransportV2PublicContractKeepsBinaryCarrierAndCryptoInternal() throws {
    let sourceRoot = packageRoot().appendingPathComponent("flowersec-swift/Sources/Flowersec")
    let connector = try String(
      contentsOf: sourceRoot.appendingPathComponent("ConnectorV2.swift"),
      encoding: .utf8)
    let crypto = try String(
      contentsOf: sourceRoot.appendingPathComponent("TransportV2Crypto.swift"),
      encoding: .utf8)
    XCTAssertFalse(connector.contains("public protocol FlowersecBinaryTransport"))
    XCTAssertFalse(crypto.contains("public enum TransportCipherSuiteV2"))
    XCTAssertFalse(crypto.contains("  public "), "v2 wire key material must remain internal")
  }

  func testOnlyOpaqueApplicationContractFilesDeclarePublicAPI() throws {
    let sourceRoot = packageRoot().appendingPathComponent("flowersec-swift/Sources/Flowersec")
    let publicContractFiles: Set<String> = [
      "ArtifactV2.swift",
      "ConnectorV2.swift",
      "TransportV2.swift",
    ]
    for file in try swiftFiles(under: sourceRoot)
    where !publicContractFiles.contains(file.lastPathComponent) {
      let text = try String(contentsOf: file, encoding: .utf8)
      let declarations = text.split(separator: "\n", omittingEmptySubsequences: false)
        .map { $0.trimmingCharacters(in: .whitespaces) }
        .filter { $0.hasPrefix("public ") || $0.hasPrefix("open ") }
      XCTAssertTrue(
        declarations.isEmpty,
        "\(file.lastPathComponent) must remain internal; found \(declarations)"
      )
    }
  }

  func testOpaquePublicContractDoesNotExposeNegotiationOrLogicalIdentifiers() throws {
    let sourceRoot = packageRoot().appendingPathComponent("flowersec-swift/Sources/Flowersec")
    let transport = try String(
      contentsOf: sourceRoot.appendingPathComponent("TransportV2.swift"),
      encoding: .utf8
    )
    let connector = try String(
      contentsOf: sourceRoot.appendingPathComponent("ConnectorV2.swift"),
      encoding: .utf8
    )

    for declaration in [
      "public enum CarrierKind",
      "public enum PathKind",
      "public enum NetworkModeV2",
      "public enum SessionRoleV2",
      "public struct RuntimeCapabilityTupleV2",
      "public struct UnsupportedRuntimeCarrierV2",
      "public struct RuntimeCapabilityDescriptorV2",
      "public enum RuntimeCapabilityCodecErrorV2",
      "public enum RuntimeCapabilitiesV2",
    ] {
      XCTAssertFalse(transport.contains(declaration), "public API must not restore \(declaration)")
    }
    let options = try XCTUnwrap(structBody(named: "ConnectorOptionsV2", in: connector))
    let connectError = try XCTUnwrap(enumBody(named: "ConnectErrorV2", in: connector))
    XCTAssertFalse(
      options.contains("admissionReasons"),
      "ConnectorOptionsV2 must not expose admission reason registries"
    )
    for errorCase in ["case unsupportedCarrier", "case admissionRejected"] {
      XCTAssertFalse(
        connectError.contains(errorCase),
        "ConnectErrorV2 must not expose \(errorCase)"
      )
    }

    let byteStream = try XCTUnwrap(protocolBody(named: "ByteStreamV2", in: transport))
    let session = try XCTUnwrap(protocolBody(named: "SessionV2", in: transport))
    let incoming = try XCTUnwrap(structBody(named: "IncomingStreamV2", in: transport))
    XCTAssertFalse(byteStream.contains("var id:"), "ByteStreamV2 must not expose logical IDs")
    XCTAssertFalse(incoming.contains(" let id:"), "IncomingStreamV2 must not expose logical IDs")
    XCTAssertFalse(session.contains("var path:"), "SessionV2 must not expose path selection")
    XCTAssertFalse(
      session.contains("var endpointInstanceID:"),
      "SessionV2 must not expose endpoint instance IDs"
    )
  }

  func testSwiftPublicSurfaceDoesNotRestoreTransportV1() throws {
    let sourceRoot = packageRoot().appendingPathComponent("flowersec-swift/Sources/Flowersec")
    for name in [
      "Controlplane.swift", "Endpoint.swift", "Handshake.swift", "HandshakeFrames.swift",
      "ProxyClient.swift", "ProxyServer.swift", "Reconnect.swift", "RecordCodec.swift",
      "SecureChannel.swift", "ServerHandshake.swift",
    ] {
      XCTAssertFalse(
        FileManager.default.fileExists(atPath: sourceRoot.appendingPathComponent(name).path))
    }

    for name in [
      "InternalSessionSupport.swift", "ProxyNIOWebSocket.swift", "ProxyTypes.swift", "RPC.swift",
      "RPCServer.swift", "SDKDefaults.swift", "Yamux.swift", "YamuxChannel.swift",
    ] {
      let text = try String(contentsOf: sourceRoot.appendingPathComponent(name), encoding: .utf8)
      XCTAssertFalse(
        text.contains("public "), "\(name) must remain an internal v2 implementation detail")
    }

    let generated = sourceRoot.appendingPathComponent("Generated")
    XCTAssertFalse(
      FileManager.default.fileExists(atPath: generated.path),
      "Transport v1 generated Swift source directory must not be maintained")
  }

  private func swiftFiles(under root: URL) throws -> [URL] {
    try textFiles(under: root).filter { $0.pathExtension == "swift" }
  }

  private func protocolBody(named name: String, in source: String) -> Substring? {
    declarationBody(after: "public protocol \(name)", in: source)
  }

  private func structBody(named name: String, in source: String) -> Substring? {
    declarationBody(after: "public struct \(name)", in: source)
  }

  private func enumBody(named name: String, in source: String) -> Substring? {
    declarationBody(after: "public enum \(name)", in: source)
  }

  private func declarationBody(after marker: String, in source: String) -> Substring? {
    guard let declaration = source.range(of: marker),
      let open = source[declaration.upperBound...].firstIndex(of: "{")
    else { return nil }
    var depth = 0
    for index in source.indices[open...] {
      switch source[index] {
      case "{":
        depth += 1
      case "}":
        depth -= 1
        if depth == 0 { return source[open...index] }
      default:
        break
      }
    }
    return nil
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
