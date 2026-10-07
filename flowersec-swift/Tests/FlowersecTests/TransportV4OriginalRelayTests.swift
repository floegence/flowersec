#if os(macOS)
import Crypto
import Foundation
import Darwin
import XCTest

@testable import Flowersec

@MainActor
final class TransportOriginalRelayTests: XCTestCase {
  func testNativeClientCrossesOriginalPoolRelayBothLegsNoiseAndBothReady() async throws {
    let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let fixture = try await V4OriginalGoRelayFixture.start(repository: repository)
    var environment: TransportEnvironment?
    var source: ConnectionMaterialSource?
    var session: (any Session)?
    do {
      let original: V4OriginalRelayManifest = try await fixture.receive(type: "material")
      XCTAssertEqual(original.material.wire_revision, 4)
      XCTAssertEqual(original.material.role, 0)
      XCTAssertEqual(original.material.source, "preauthorized_pool")
      XCTAssertEqual(original.material.profile, V4CryptoProfile.x25519.rawValue)
      let registry = try V4NamespaceRegistry()
      let artifact = try V4NamespaceDocument(original.material.artifact, schema: "Artifact",
        bytes: 65_536, nodes: 16_384, registry: registry).root
      let activation = try V4NamespaceDocument(original.material.activation, schema: "ActivationAuthorization",
        bytes: 4096, nodes: 4096, registry: registry, context: ["activation_source_profile": "preauthorized_pool"]).root
      let route = try V4NamespaceDocument(original.material.route, schema: "Route", bytes: 16_384, nodes: 4096, registry: registry).root
      let clientLeg = try route.field("client_leg")
      let serverLeg = try route.field("server_leg")
      XCTAssertEqual(try clientLeg.t("host"), "localhost")
      XCTAssertEqual(try clientLeg.u("dialer_role"), 0); XCTAssertEqual(try clientLeg.u("listener_role"), 2)
      XCTAssertEqual(try serverLeg.u("dialer_role"), 2); XCTAssertEqual(try serverLeg.u("listener_role"), 1)
      XCTAssertNotEqual(try clientLeg.b("leg_id"), try serverLeg.b("leg_id"))
      XCTAssertNotEqual(try clientLeg.u("port"), try serverLeg.u("port"))
      XCTAssertNotNil(original.material.tunnels?.first { $0.candidate_index == 0 && $0.role == 0 })
      XCTAssertEqual(original.material.tunnels?.count, 2)
      let once = try activation.field("candidate_selection").field("once_authority_ref")
      let namespaces = original.material.namespaces.map { record in
        TransportTrustNamespace(authority: record.authority, rootKeyID: record.root_key_id,
          rootPublicKey: record.root_public_key, maximumTrustLifetimeMilliseconds: 30_000_000,
          maximumStateBytes: 262_144, maximumStateNodes: 32_768) { nonce in
          try await record.bootstrap(nonce: nonce, roots: [Data(original.trust_pem.utf8)])
        }
      }
      let historyDirectory = fixture.scratch.appendingPathComponent("client-history")
      try FileManager.default.createDirectory(at: historyDirectory, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
      var configuration = TransportClientConfiguration(tenant: original.tenant, audience: original.audience,
        clientSubject: original.client_subject, serverSubject: original.server_subject, namespaces: namespaces,
        endpoints: [TransportEndpoint(hostname: "localhost", port: try Int(clientLeg.u("port")), numericAddress: "127.0.0.1")],
        history: TransportPoolHistory(directory: historyDirectory, storeID: try V4Crypto.random(16), generation: 1,
          artifactIssuerKeyID: try artifact.b("issuer_key_id"), spendAuthority: try once.t("spend_authority_id"),
          winnerAuthority: try once.t("winner_authority_id"), create: true, checkContinuity: {}),
        trustedTime: {
          let now = UInt64(Date().timeIntervalSince1970 * 1000)
          return TransportTrustedTime(lowerMilliseconds: now, upperMilliseconds: now + 2)
        })
      configuration.trustRootsPEM = [Data(original.trust_pem.utf8)]
      configuration.maximumRuntimeItems = 8192; configuration.maximumResourceReservations = 4096
      configuration.maximumResourceReferences = 8192
      configuration.timePolicy.driftNumerator = 0; configuration.timePolicy.quantizationMilliseconds = 0
      let native = try await TransportEnvironment(configuration: configuration)
      environment = native
      let identity = try await native.importApplicationIdentity(profile: .x25519,
        signingSeed: original.material.identity_seed, noiseStaticPrivateKey: original.material.dh_seed)
      let installation = try PeerParityPoolInstallation.read(variables: [
        "FLOWERSEC_PARITY_POOL_DEPLOYMENT": fixture.scratch.appendingPathComponent("pool-client.json").path])
      let allow = try installation.configuration(material: original.material, ready: original.ready)
      let credential = try original.material.credential(path: "tunnel", serverAllow: allow)
      let materialSource = try await native.makePreauthorizedPoolSource([credential], identity: identity)
      source = materialSource
      let originalSource = try XCTUnwrap(materialSource.owner as? V4PoolMaterialSource)
      try fixture.send(type: "start")
      let _: V4OriginalRelayMilestone = try await fixture.receive(type: "relay-started")
      let connected = try await native.connect(source: materialSource,
        requirements: ConnectionRequirements(localConsumerTLS13Verification: true, applicationProfile: "services"))
      session = connected
      let serverReady: V4OriginalRelayMilestone = try await fixture.receive(type: "server-ready")
      XCTAssertEqual(serverReady.authorized, 1); XCTAssertEqual(originalSource.acquisitionCount, 1)
      let stream = try await connected.openStream(kind: "swift.native.tunnel.echo")
      let request = Data("native-two-leg-ready".utf8)
      let written = try await stream.write(request); XCTAssertEqual(written, request.count)
      try await stream.finish()
      var received = Data()
      while let chunk = try await stream.read(maxBytes: 64) {
        guard received.count + chunk.count <= 64 else { throw V4OriginalRelayFixtureFailure.protocolFailure }
        received.append(chunk)
      }
      XCTAssertEqual(received, Data("original-relay-ready".utf8))
      try await stream.close(); try await connected.close(); session = nil
      materialSource.close(); source = nil
      try await native.close(); environment = nil
      try fixture.send(type: "close")
      let complete: V4OriginalRelayMilestone = try await fixture.receive(type: "complete")
      XCTAssertEqual(complete.echoes, 1); XCTAssertEqual(complete.authorized, 1); XCTAssertEqual(complete.released, 1)
      XCTAssertTrue(complete.relay_cleanup == true)
      try await fixture.finish()
    } catch {
      try? await session?.close(); source?.close(); try? await environment?.close()
      await fixture.abort()
      throw error
    }
  }
}

private struct V4OriginalRelayManifest: Decodable {
  typealias Material = PeerParityMaterial
  let ready: PeerParityReady
  let type: String; let material: Material; let trust_pem: String
  let tenant: String; let audience: String; let client_subject: String; let server_subject: String
}
private struct V4OriginalRelayMilestone: Decodable {
  let type: String; let authorized: Int?; let released: Int?; let echoes: Int?; let relay_cleanup: Bool?
}
private enum V4OriginalRelayFixtureFailure: Error { case protocolFailure, deadline, processFailure, outputCapacity }

// The fixture uses an isolated ignored module, the exact repository Go version,
// and the production original relay harness. The built executable runs directly
// so cancellation joins the actual relay process rather than a go-run wrapper.
private final class V4OriginalGoRelayFixture: @unchecked Sendable {
  let scratch: URL
  private let artifacts: URL
  private let process: Process
  private let input: Pipe
  private let stdout: Pipe
  private let stderr: Pipe
  private let gate = NSLock()
  private var lines: [Data] = []
  private var pending = Data()
  private var diagnostics = Data()
  private var outputEnded = false
  private var overflow = false
  private var reader: Task<Void, Never>?
  private var errorReader: Task<Void, Never>?
  private init(scratch: URL, artifacts: URL, executable: URL) throws {
    self.scratch = scratch; self.artifacts = artifacts
    process = Process(); input = Pipe(); stdout = Pipe(); stderr = Pipe()
    process.executableURL = executable; process.arguments = [artifacts.path, scratch.appendingPathComponent("pool-client.json").path]
    process.standardInput = input; process.standardOutput = stdout; process.standardError = stderr
    try process.run()
    try? input.fileHandleForReading.close()
    try? stdout.fileHandleForWriting.close()
    try? stderr.fileHandleForWriting.close()
    reader = Task.detached { [self] in
      defer { gate.withLock { outputEnded = true } }
      // FileHandle.read(upToCount:) waits to fill the requested pipe read on
      // Darwin. Each short protocol line must wake its peer immediately.
      while true {
        let bytes = stdout.fileHandleForReading.availableData
        if bytes.isEmpty { break }
        let keep = gate.withLock { () -> Bool in
          guard pending.count + bytes.count <= 524_288 else { overflow = true; return false }
          pending.append(bytes)
          while let end = pending.firstIndex(of: 10) {
            guard lines.count < 8 else { overflow = true; return false }
            lines.append(Data(pending[..<end])); pending.removeSubrange(...end)
          }
          return true
        }
        if !keep { process.terminate(); break }
      }
    }
    errorReader = Task.detached { [self] in
      while let bytes = try? stderr.fileHandleForReading.read(upToCount: 4096), !bytes.isEmpty {
        gate.withLock { diagnostics.append(bytes.prefix(max(0, 65_536 - diagnostics.count))) }
      }
    }
  }
  static func start(repository: URL) async throws -> V4OriginalGoRelayFixture {
    let id = UUID().uuidString
    let scratch = repository.appendingPathComponent(".flowersec/swift-native-original-relay-\(id)")
    let artifacts = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".flowersec-test-artifacts/swift-native-original-relay-\(id)")
    do {
      for directory in [scratch, artifacts] {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
          attributes: [.posixPermissions: 0o700])
      }
      let tools = try JSONSerialization.jsonObject(with: Data(contentsOf: repository.appendingPathComponent("toolchains.json"))) as? [String: Any]
      guard let version = (tools?["go"] as? [String: Any])?["version"] as? String else { throw V4OriginalRelayFixtureFailure.protocolFailure }
      let module = "github.com/floegence/flowersec/flowersec-go/v6"
      let goPath = repository.appendingPathComponent("flowersec-go").path
      let quotedPath = String(decoding: try JSONSerialization.data(withJSONObject: goPath, options: [.fragmentsAllowed, .withoutEscapingSlashes]), as: UTF8.self)
      let moduleFile = "module \(module)/internal/swiftnativefixture\n\ngo \(version)\n\nrequire \(module) v6.0.0\n\nreplace \(module) => \(quotedPath)\n"
      try Data(moduleFile.utf8).write(to: scratch.appendingPathComponent("go.mod"))
      try FileManager.default.copyItem(at: repository.appendingPathComponent("flowersec-go/go.sum"), to: scratch.appendingPathComponent("go.sum"))
      let source = try XCTUnwrap(Bundle.module.url(forResource: "main", withExtension: "go", subdirectory: "Fixtures/native_tunnel_relay"))
      try FileManager.default.copyItem(at: source, to: scratch.appendingPathComponent("main.go"))
      let executable = scratch.appendingPathComponent("original-relay")
      let build = Process(); let output = Pipe()
      build.executableURL = URL(fileURLWithPath: "/usr/bin/env")
      build.arguments = ["go", "build", "-mod=mod", "-o", executable.path, "."]
      build.currentDirectoryURL = scratch; build.standardOutput = output; build.standardError = output
      var variables = ProcessInfo.processInfo.environment; variables["GOTOOLCHAIN"] = "go\(version)"; variables["GOWORK"] = "off"
      build.environment = variables
      try build.run()
      let read = Task.detached { () -> Data in
        var captured = Data()
        while let bytes = try? output.fileHandleForReading.read(upToCount: 4096), !bytes.isEmpty {
          captured.append(bytes.prefix(max(0, 65_536 - captured.count)))
        }
        return captured
      }
      try? output.fileHandleForWriting.close()
      do {
        let deadline = ContinuousClock.now.advanced(by: .seconds(120))
        while build.isRunning {
          try Task.checkCancellation()
          guard ContinuousClock.now < deadline else { throw V4OriginalRelayFixtureFailure.deadline }
          try await ContinuousClock().sleep(for: .milliseconds(10))
        }
        await join(build, terminate: false)
        let log = await read.value
        guard build.terminationStatus == 0 else {
          try retain(log: log, artifacts: artifacts)
          throw V4OriginalRelayFixtureFailure.processFailure
        }
        try Task.checkCancellation()
      } catch {
        // This original owner joins the process and its output reader before
        // the outer owner removes any build files, including on cancellation.
        await join(build, terminate: true)
        try? retain(log: await read.value, artifacts: artifacts)
        throw error
      }
      return try V4OriginalGoRelayFixture(scratch: scratch, artifacts: artifacts, executable: executable)
    } catch {
      try? FileManager.default.removeItem(at: scratch)
      let contents = (try? FileManager.default.contentsOfDirectory(atPath: artifacts.path)) ?? []
      if contents.isEmpty { try? FileManager.default.removeItem(at: artifacts) }
      throw error
    }
  }
  func send(type: String) throws {
    guard process.isRunning else { throw V4OriginalRelayFixtureFailure.processFailure }
    let bytes = try JSONSerialization.data(withJSONObject: ["type": type]) + Data([10])
    try input.fileHandleForWriting.write(contentsOf: bytes)
  }
  func receive<T: Decodable>(type: String) async throws -> T {
    let deadline = ContinuousClock.now.advanced(by: .seconds(30))
    while true {
      if let bytes = try gate.withLock({ () throws -> Data? in
        if overflow { throw V4OriginalRelayFixtureFailure.outputCapacity }
        if !lines.isEmpty { return lines.removeFirst() }
        if outputEnded { throw V4OriginalRelayFixtureFailure.processFailure }
        return nil
      }) {
        let envelope = try JSONSerialization.jsonObject(with: bytes) as? [String: Any]
        guard envelope?["type"] as? String == type else { throw V4OriginalRelayFixtureFailure.protocolFailure }
        return try JSONDecoder().decode(T.self, from: bytes)
      }
      try Task.checkCancellation()
      guard ContinuousClock.now < deadline else { throw V4OriginalRelayFixtureFailure.deadline }
      try await ContinuousClock().sleep(for: .milliseconds(10))
    }
  }
  func finish() async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(10))
    while process.isRunning {
      guard ContinuousClock.now < deadline else { await abort(); throw V4OriginalRelayFixtureFailure.deadline }
      try await ContinuousClock().sleep(for: .milliseconds(10))
    }
    await Self.join(process, terminate: false)
    await reader?.value; await errorReader?.value
    reader = nil; errorReader = nil
    guard process.terminationStatus == 0 else { await abort(); throw V4OriginalRelayFixtureFailure.processFailure }
    try FileManager.default.removeItem(at: scratch); try FileManager.default.removeItem(at: artifacts)
  }
  func abort() async {
    try? input.fileHandleForWriting.close()
    await Self.join(process, terminate: true)
    await reader?.value; await errorReader?.value
    reader = nil; errorReader = nil
    let log = gate.withLock { diagnostics }
    try? FileManager.default.removeItem(at: scratch)
    // Only a bounded checksummed failure log survives a failed fixture.
    try? FileManager.default.removeItem(at: artifacts)
    try? FileManager.default.createDirectory(at: artifacts, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try? Self.retain(log: log, artifacts: artifacts)
  }
  private static func join(_ process: Process, terminate: Bool) async {
    // Detached cleanup is independent of the canceled test's task. SIGTERM
    // lets the original Go context release relay claims and both native legs.
    await Task.detached {
      if terminate, process.isRunning { process.terminate() }
      let deadline = ContinuousClock.now.advanced(by: .seconds(10))
      while process.isRunning, ContinuousClock.now < deadline {
        try? await ContinuousClock().sleep(for: .milliseconds(10))
      }
      if process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
      process.waitUntilExit()
    }.value
  }
  private static func retain(log: Data, artifacts: URL) throws {
    let name = artifacts.appendingPathComponent("failure.log")
    try log.write(to: name)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: name.path)
    let checksum = SHA256.hash(data: log).map { String(format: "%02x", $0) }.joined()
    try Data((checksum + "  failure.log\n").utf8).write(to: artifacts.appendingPathComponent("failure.log.sha256"))
  }
}
#endif
