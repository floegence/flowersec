#if os(macOS)
import Crypto
import Foundation
import XCTest
@testable import Flowersec

// The external driver selects this test with one original issuer-owned ready
// message. No fixture codec manufactures an activation, route or namespace.
@MainActor
final class ServerParityTests: XCTestCase {
  func testClientProfile() async throws {
    let variables = ProcessInfo.processInfo.environment
    guard let encoded = variables["FLOWERSEC_PARITY_READY_BASE64"] else {
      throw XCTSkip("The shared parity driver supplies the original ready message")
    }
    guard encoded.utf8.count <= 2_800_000, let bytes = Data(base64Encoded: encoded), bytes.count <= 2 << 20 else {
      throw PeerParityFailure.invalidMaterial
    }
    let ready = try JSONDecoder().decode(PeerParityReady.self, from: bytes)
    guard ready.type == "ready", ready.wire_revision == 4, ready.carrier == "websocket",
      ["preauthorized_pool", "live_authority"].contains(ready.source), ["direct", "tunnel"].contains(ready.path),
      ready.path == variables["FLOWERSEC_PARITY_PATH"], ready.artifact_json.utf8.count <= 1 << 20
    else { throw PeerParityFailure.unsupportedMaterial }
    let material = try JSONDecoder().decode(PeerParityMaterial.self, from: Data(ready.artifact_json.utf8))
    try material.check(ready: ready)
    let registered: PeerParityRegisteredLiveInstallation?
    if ready.source == "live_authority" { registered = try PeerParityRegisteredLiveInstallation.read(variables: variables) }
    else { registered = nil }
    if let registered { try registered.check(material: material, ready: ready) }
    let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let directory: URL
    if registered != nil {
      guard let root = variables["FLOWERSEC_TEST_ARTIFACT_DIR"], !root.isEmpty, root.utf8.count <= 4096,
        (root as NSString).isAbsolutePath else { throw PeerParityFailure.invalidMaterial }
      let artifacts = URL(fileURLWithPath: root, isDirectory: true).resolvingSymlinksInPath().standardizedFileURL
      let repositoryPath = repository.resolvingSymlinksInPath().standardizedFileURL.path
      let temporary = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true).resolvingSymlinksInPath().standardizedFileURL.path
      guard artifacts.path != repositoryPath, !artifacts.path.hasPrefix(repositoryPath + "/"),
        ![temporary, "/tmp", "/private/tmp"].contains(where: { artifacts.path == $0 || artifacts.path.hasPrefix($0 + "/") })
      else { throw PeerParityFailure.invalidMaterial }
      directory = artifacts.appendingPathComponent("swift-parity-\(UUID().uuidString)", isDirectory: true)
    } else { directory = repository.appendingPathComponent(".flowersec/swift-parity-\(UUID().uuidString)") }
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    var environment: TransportEnvironment?
    do {
      let native = try await TransportEnvironment(configuration: material.configuration(ready: ready, directory: directory))
      environment = native
      try await exercise(native: native, material: material, ready: ready, registered: registered)
      try await native.close()
      let cleanup = await native.cleanupStatus()
      XCTAssertTrue(cleanup.complete, "Environment cleanup: \(cleanup)")
      if cleanup.complete { try FileManager.default.removeItem(at: directory) }
    } catch {
      try? await environment?.close()
      let cleanup = await environment?.cleanupStatus()
      try retainFailure(error)
      if environment == nil || cleanup?.complete == true { try? FileManager.default.removeItem(at: directory) }
      throw error
    }
  }
  // Return every retained contract and closed handle before observing the
  // Environment's physical cleanup; their memory remains charged while held.
  private func exercise(native: TransportEnvironment, material: PeerParityMaterial,
    ready: PeerParityReady, registered: PeerParityRegisteredLiveInstallation?) async throws {
    var source: ConnectionMaterialSource?
    var session: (any Session)?
    var client: ServiceClient?
    var subscription: ServiceNotificationSubscription<PeerParityValue>?
    var registry: ServiceRegistry?
    var applicationIdentity: TransportApplicationIdentity?
    var phase = "application definitions"
    do {
      phase = "application definitions"
      let application = try PeerParityApplication()
      let observations = PeerParityObservations()
      let query = try ServiceContractQueryBinding(typeID: 7,
        contractDigest: Data([9]) + Data(repeating: 0, count: 31), maximumLifetimeMS: 30_000)
      phase = "service registry"
      let localRegistry = try await native.makeServiceRegistry(ServiceRegistryConfiguration(
        authority: application.definition.namespace, maximumMethods: 4, queryBinding: query))
      registry = localRegistry
      let artifact = try material.artifactValue()
      let server = try material.document(material.server_certificate, schema: "IdentityCertificate")
      phase = "server caller"
      let caller = try ServiceServerCaller(subject: server.t("subject_id"),
        identityDigest: artifact.b("server_identity_digest"), executionAuthority: Data(repeating: 9, count: 32))
      phase = "service contracts"
      let echoContract = try await native.captureServiceContract(PeerParityApplication.contract(typeID: 7001, notify: false))
      let notifyContract = try await native.captureServiceContract(PeerParityApplication.contract(typeID: 7002, notify: true))
      phase = "service registration"
      try localRegistry.registerUnary(application.echo, in: application.definition,
        contract: echoContract, callers: [caller], requestCodec: application.codec, responseCodec: application.codec) { _, _, input in
        guard input.value == "ping" else { throw PeerParityFailure.applicationMismatch }
        try await observations.waitForSubscription()
        await observations.echoReceived()
        return input
      }
      try localRegistry.registerNotify(application.notification, in: application.definition,
        contract: notifyContract, callers: [caller], codec: application.codec) { _, _, input in
        guard input.value == "notify" else { throw PeerParityFailure.applicationMismatch }
      }
      guard let profile = TransportCryptoProfile(rawValue: material.profile) else { throw PeerParityFailure.unsupportedMaterial }
      phase = "application identity"
      let identity = try await native.importApplicationIdentity(profile: profile,
        signingSeed: material.identity_seed, noiseStaticPrivateKey: material.dh_seed)
      applicationIdentity = identity
      phase = "material source"
      let originalSource: ConnectionMaterialSource
      if let registered {
        originalSource = try await native.makeRegisteredLiveAuthoritySource(
          registered.configuration(material: material, ready: ready), identity: identity)
      } else {
        let serverAllow: TransportPoolServerAllowConfiguration?
        if ready.path == "tunnel" {
          serverAllow = try PeerParityPoolInstallation.read(variables: ProcessInfo.processInfo.environment)
            .configuration(material: material, ready: ready)
        } else { serverAllow = nil }
        let credential = try material.credential(path: ready.path, serverAllow: serverAllow)
        originalSource = try await native.makePreauthorizedPoolSource([credential], identity: identity)
      }
      source = originalSource
      let listener = try material.localListener(path: ready.path)
      let requirements = ConnectionRequirements(localConsumerTLS13Verification: !listener, applicationProfile: "services")
      phase = "connection"
      let connected: any Session
      if listener { connected = try await native.accept(source: originalSource, requirements: requirements) }
      else { connected = try await native.connect(source: originalSource, requirements: requirements) }
      session = connected
      if ready.source == "preauthorized_pool" {
        let sourceOwner = try XCTUnwrap(originalSource.owner as? V4PoolMaterialSource)
        XCTAssertEqual(sourceOwner.acquisitionCount, 1)
      }
      phase = "service binding"
      let bound = try await application.bind(session: connected, environment: native, target: material.target())
      client = bound
      phase = "notification subscription"
      let observer = try await bound.subscribe(application.notification, codec: application.codec,
        options: NotificationSubscriptionOptions(pendingLimit: 2, applicationTimeoutMS: 10_000)) { _, input in
        guard input.value == "notify" else { throw PeerParityFailure.applicationMismatch }
        await observations.notificationReceived()
      }
      subscription = observer
      await observations.subscriptionReady()
      phase = "RPC exchange"
      try await call(bound, application.echo, value: "ping", application: application)
      try await bound.notify(application.notification, request: PeerParityValue(value: "notify"), codec: application.codec,
        options: ServiceCallOptions(deadlineAtMS: deadline()))
      try await observations.waitForReciprocalApplication()

      phase = "stream exchange"
      let metadata = try StreamMetadata(["cell": .string(ready.path)])
      let echo = try await connected.openStream(kind: "parity.echo", metadata: metadata)
      try await write(Data("hello".utf8), to: echo)
      try await echo.closeWrite()
      let response = try await read(echo, maximum: 16)
      XCTAssertEqual(response, Data("world".utf8))
      try await echo.finish()
      try await call(bound, application.echo, value: "ping", application: application)
      let reset = try await connected.openStream(kind: "parity.reset")
      try await write(Data("reset".utf8), to: reset)
      try await reset.closeWrite()
      var resetObserved = false
      do { _ = try await read(reset, maximum: 16) }
      catch { resetObserved = (error as? SessionError) == .streamReset }
      try await reset.close()
      XCTAssertTrue(resetObserved, "The original authenticated stream must report its reset")
      let canceledWait = Task { () -> SessionTermination in
        withUnsafeCurrentTask { $0?.cancel() }
        return await connected.waitTermination()
      }
      let canceled = await canceledWait.value
      XCTAssertEqual(canceled.error, .canceled)
      try await call(bound, application.echo, value: "ping", application: application)
      try await call(bound, application.datagramReady, value: "datagram-ready", application: application)
      try await connected.rekey()
      _ = try await connected.probeLiveness()
      try await call(bound, application.completion, value: "complete", application: application)
      try await bound.notify(application.notification, request: PeerParityValue(value: "notify"), codec: application.codec,
        options: ServiceCallOptions(deadlineAtMS: deadline()))
      try await call(bound, application.echo, value: "notifications-observed", application: application)
      phase = "application cleanup"
      let drain = try connected.drain(timeout: .seconds(5))
      let drained = try await drain.wait()
      XCTAssertEqual(drained.outcome, .drained)
      let termination = await connected.waitTermination()
      XCTAssertEqual(termination.error, .closed)
      observer.close()
      let observerCleanup = try await observer.waitClosed()
      XCTAssertTrue(observerCleanup.complete)
      subscription = nil
      bound.close(); client = nil
      try await connected.close(); session = nil
      originalSource.close(); source = nil
      localRegistry.close(); registry = nil
      identity.close(); applicationIdentity = nil
    } catch {
      XCTFail("Current parity failed during \(phase): \(type(of: error)): \(error)")
      subscription?.close()
      _ = try? await subscription?.waitClosed()
      client?.close(); registry?.close()
      try? await session?.close(); source?.close()
      applicationIdentity?.close()
      throw error
    }
  }
  private func deadline() -> UInt64 { UInt64(Date().timeIntervalSince1970 * 1000) + 10_000 }
  private func call(_ client: ServiceClient, _ method: MethodDefinition, value: String, application: PeerParityApplication) async throws {
    let result = try await client.call(method, request: PeerParityValue(value: value), requestCodec: application.codec,
      responseCodec: application.codec, options: ServiceCallOptions(deadlineAtMS: deadline(), responseLimitBytes: 4096))
    guard result.value.value == value else { throw PeerParityFailure.applicationMismatch }
  }
  private func write(_ input: Data, to stream: any ByteStream) async throws {
    var offset = 0
    while offset < input.count {
      let written = try await stream.write(input.subdata(in: offset..<input.count))
      guard written > 0, written <= input.count - offset else { throw PeerParityFailure.applicationMismatch }
      offset += written
    }
  }
  private func read(_ stream: any ByteStream, maximum: Int) async throws -> Data {
    var output = Data()
    while let bytes = try await stream.read(maxBytes: maximum) {
      guard output.count + bytes.count <= maximum else { throw PeerParityFailure.applicationMismatch }
      output.append(bytes)
    }
    return output
  }
  private func retainFailure(_ error: any Error) throws {
    let directory = FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".flowersec-test-artifacts/swift-parity-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    let log = Data("Swift current parity failed: \(String(describing: error))\n".utf8)
    let digest = SHA256.hash(data: log).map { String(format: "%02x", $0) }.joined()
    let logURL = directory.appendingPathComponent("failure.log")
    try log.write(to: logURL)
    guard SHA256.hash(data: try Data(contentsOf: logURL)).map({ String(format: "%02x", $0) }).joined() == digest else {
      throw PeerParityFailure.applicationMismatch
    }
    try Data("\(digest)  failure.log\n".utf8).write(to: directory.appendingPathComponent("SHA256SUMS"))
  }
}

actor PeerParityObservations {
  private var ready = false
  private var echoed = false
  private var notified = false
  func subscriptionReady() { ready = true }
  func echoReceived() { echoed = true }
  func notificationReceived() { notified = true }
  func waitForSubscription() async throws { try await wait { self.ready } }
  func waitForReciprocalApplication() async throws { try await wait { self.echoed && self.notified } }
  private func wait(_ complete: () -> Bool) async throws {
    let start = ContinuousClock.now
    while !complete() {
      try Task.checkCancellation()
      guard start.duration(to: .now) < .seconds(10) else { throw PeerParityFailure.applicationMismatch }
      try await ContinuousClock().sleep(for: .milliseconds(5))
    }
  }
}

struct PeerParityReady: Decodable {
  struct ServerAllow: Decodable {
    let endpoint: String
    let recipient: Data
    let incarnation: Data
    enum CodingKeys: String, CodingKey { case endpoint, recipient, incarnation }
    init(from decoder: any Decoder) throws {
      let fields = try decoder.container(keyedBy: CodingKeys.self)
      endpoint = try fields.decode(String.self, forKey: .endpoint)
      let recipientText = try fields.decode(String.self, forKey: .recipient)
      let incarnationText = try fields.decode(String.self, forKey: .incarnation)
      guard endpoint.utf8.count <= 2048, recipientText.utf8.count == 24, incarnationText.utf8.count == 24,
        let recipient = Data(base64Encoded: recipientText), let incarnation = Data(base64Encoded: incarnationText),
        recipient.base64EncodedString() == recipientText, incarnation.base64EncodedString() == incarnationText,
        [recipient, incarnation].allSatisfy({ $0.count == 16 && $0.contains(where: { $0 != 0 }) })
      else { throw PeerParityFailure.invalidMaterial }
      self.recipient = recipient; self.incarnation = incarnation
    }
  }
  let server_allow: ServerAllow?
  let type: String; let wire_revision: Int; let carrier: String; let path: String
  let artifact_json: String; let trust_pem: String; let profile: String; let source: String
  let origin: String
  let client_tls_certificate_pem: String?
  let client_tls_private_key_pem: String?
  let server_tls_certificate_pem: String?
  let server_tls_private_key_pem: String?
}
struct PeerParityMaterial: Decodable {
  struct Generation: Decodable { let source: Data; let generation: UInt64 }
  struct Namespace: Decodable, Sendable {
    let tenant: String; let authority: String; let generation: UInt64
    let root_key_id: Data; let root_public_key: Data; let bootstrap_url: String; let state_url: String
    var bootstrapURL: String { bootstrap_url }
  }
  struct Tunnel: Decodable {
    struct LiveGrant: Decodable {
      let authority: String; let issuer_key_id: Data; let audience: String; let service: String
      let revocation_policy_id: String; let revocation_policy_revision: String; let max_not_after_ms: String
    }
    let candidate_index: Int; let role: Int; let grant: Data?; let relay_certificate: Data
    let grant_namespace: Int?; let relay_namespace: Int?; let live_grant: LiveGrant?
  }
  let wire_revision: Int; let profile: String; let source: String; let generation: Generation; let role: Int
  let artifact: Data; let activation: Data; let client_certificate: Data; let server_certificate: Data
  let route: Data; let route_digest: Data; let identity_seed: Data; let dh_seed: Data
  let namespaces: [Namespace]; let tunnels: [Tunnel]?
  let activation_signing_key_id: String?; let live_control_base_url: String?
  enum CodingKeys: String, CodingKey {
    case wire_revision, profile, source, generation, role, artifact, activation, client_certificate, server_certificate,
      route, route_digest, identity_seed, dh_seed, namespaces, tunnels, activation_signing_key_id, live_control_base_url
  }
  init(from decoder: any Decoder) throws {
    let values = try decoder.container(keyedBy: CodingKeys.self)
    wire_revision = try values.decode(Int.self, forKey: .wire_revision)
    profile = try values.decode(String.self, forKey: .profile); source = try values.decode(String.self, forKey: .source)
    generation = try values.decode(Generation.self, forKey: .generation); role = try values.decode(Int.self, forKey: .role)
    artifact = try values.decode(Data.self, forKey: .artifact)
    activation = try values.decodeIfPresent(Data.self, forKey: .activation) ?? Data()
    client_certificate = try values.decode(Data.self, forKey: .client_certificate)
    server_certificate = try values.decode(Data.self, forKey: .server_certificate)
    route = try values.decode(Data.self, forKey: .route); route_digest = try values.decode(Data.self, forKey: .route_digest)
    identity_seed = try values.decode(Data.self, forKey: .identity_seed); dh_seed = try values.decode(Data.self, forKey: .dh_seed)
    namespaces = try values.decode([Namespace].self, forKey: .namespaces); tunnels = try values.decodeIfPresent([Tunnel].self, forKey: .tunnels)
    activation_signing_key_id = try values.decodeIfPresent(String.self, forKey: .activation_signing_key_id)
    live_control_base_url = try values.decodeIfPresent(String.self, forKey: .live_control_base_url)
  }
  func check(ready: PeerParityReady) throws {
    guard wire_revision == 4, role == 0, profile == ready.profile, source == ready.source,
      generation.source.count == 16, generation.generation > 0, identity_seed.count == 32,
      dh_seed.count == 32, route_digest.count == 32, (1...16).contains(namespaces.count),
      artifact.count <= 65_536, activation.count <= 4096, client_certificate.count <= 8192,
      server_certificate.count <= 8192, route.count <= 16_384, (tunnels?.count ?? 0) <= 2
    else { throw PeerParityFailure.invalidMaterial }
    if source == "live_authority" {
      guard ready.path == "tunnel", activation.isEmpty, tunnels?.count == 2,
        tunnels?.allSatisfy({ ($0.grant?.isEmpty ?? true) && $0.live_grant != nil }) == true
      else { throw PeerParityFailure.invalidMaterial }
    } else {
      guard !activation.isEmpty else { throw PeerParityFailure.invalidMaterial }
    }
  }
  func document(_ input: Data, schema: String) throws -> V4NamespaceValue {
    try V4NamespaceDocument(input, schema: schema, bytes: 65_536, nodes: 32_768,
      registry: V4NamespaceRegistry(), context: ["activation_source_profile": source]).root
  }
  func artifactValue() throws -> V4NamespaceValue { try document(artifact, schema: "Artifact") }
  func configuration(ready: PeerParityReady, directory: URL) throws -> TransportClientConfiguration {
    let artifact = try artifactValue()
    let route = try document(route, schema: "Route")
    guard try route.digest("route_digest") == route_digest,
      try route.u("path_kind") == (ready.path == "direct" ? 0 : 1)
    else { throw PeerParityFailure.invalidMaterial }
    let leg = try route.field(ready.path == "direct" ? "direct_leg" : "client_leg")
    guard try leg.u("carrier") == 1, try leg.u("access_class") == 0,
      Set([try leg.u("dialer_role"), try leg.u("listener_role")]) == Set([UInt64(0), ready.path == "direct" ? UInt64(1) : UInt64(2)])
    else { throw PeerParityFailure.unsupportedMaterial }
    let localListener = try leg.u("listener_role") == 0
    if ready.path == "tunnel", let selected = ProcessInfo.processInfo.environment["FLOWERSEC_PARITY_CLIENT_LISTENER"] {
      guard selected == (localListener ? "endpoint" : "relay") else { throw PeerParityFailure.unsupportedMaterial }
    }
    if let selected = ProcessInfo.processInfo.environment["FLOWERSEC_PARITY_CLIENT_CARRIERS"] {
      guard selected == "websocket" else { throw PeerParityFailure.unsupportedMaterial }
    }
    let history: TransportPoolHistory?
    if source == "preauthorized_pool" {
      let once = try document(activation, schema: "ActivationAuthorization").field("candidate_selection").field("once_authority_ref")
      history = try TransportPoolHistory(directory: directory, storeID: V4Crypto.random(16), generation: 1,
        artifactIssuerKeyID: artifact.b("issuer_key_id"), spendAuthority: once.t("spend_authority_id"),
        winnerAuthority: once.t("winner_authority_id"), create: true, checkContinuity: {})
    } else { history = nil }
    let client = try document(client_certificate, schema: "IdentityCertificate")
    let server = try document(server_certificate, schema: "IdentityCertificate")
    guard namespaces.allSatisfy({ $0.tenant == (try? artifact.t("tenant_id")) && $0.root_key_id.count == 16 && $0.root_public_key.count == 32 }) else {
      throw PeerParityFailure.invalidMaterial
    }
    let roots = [Data(ready.trust_pem.utf8)]
    let pins = namespaces.map { record in
      TransportTrustNamespace(authority: record.authority, rootKeyID: record.root_key_id,
        rootPublicKey: record.root_public_key, maximumTrustLifetimeMilliseconds: 30_000_000,
        maximumStateBytes: 262_144, maximumStateNodes: 32_768) { nonce in
        try await record.bootstrap(nonce: nonce, roots: roots)
      }
    }
    var config = TransportClientConfiguration(tenant: try artifact.t("tenant_id"), audience: try artifact.t("audience"),
      clientSubject: try client.t("subject_id"), serverSubject: try server.t("subject_id"), namespaces: pins,
      endpoints: [TransportEndpoint(hostname: try leg.t("host"), port: try Int(leg.u("port")), numericAddress: "127.0.0.1")],
      history: history, trustedTime: {
        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        return TransportTrustedTime(lowerMilliseconds: now, upperMilliseconds: now + 2)
      })
    if localListener {
      guard let certificate = ready.client_tls_certificate_pem, let key = ready.client_tls_private_key_pem,
        !certificate.isEmpty, !key.isEmpty, certificate.utf8.count <= 262_144, key.utf8.count <= 16_384 else {
        throw PeerParityFailure.invalidMaterial
      }
      config.listenerTLS = NativeListenerTLSConfiguration(certificateChainPEM: Data(certificate.utf8), privateKeyPEM: Data(key.utf8))
    }
    config.trustRootsPEM = roots; config.webSocketOrigin = ready.origin
    config.maximumRuntimeBytes = 4 << 30
    config.maximumRuntimeItems = 16_384; config.maximumResourceReservations = 8192
    config.maximumResourceReferences = 16_384
    config.timePolicy.driftNumerator = 0; config.timePolicy.quantizationMilliseconds = 0
    return config
  }
  func localListener(path: String) throws -> Bool {
    let signed = try document(route, schema: "Route")
    return try signed.field(path == "direct" ? "direct_leg" : "client_leg").u("listener_role") == 0
  }
  func credential(path: String, serverAllow: TransportPoolServerAllowConfiguration? = nil) throws -> TransportPoolCredential {
    let tunnels = self.tunnels ?? []
    if path == "direct" {
      guard tunnels.isEmpty, serverAllow == nil else { throw PeerParityFailure.invalidMaterial }
      return TransportPoolCredential(artifact: artifact, clientCertificate: client_certificate,
        serverCertificate: server_certificate, activationAuthorization: activation)
    }
    guard source == "preauthorized_pool", tunnels.count == 2, let serverAllow,
      let local = tunnels.first(where: { $0.candidate_index == 0 && $0.role == 0 }), let grant = local.grant, !grant.isEmpty else {
      throw PeerParityFailure.invalidMaterial
    }
    return TransportPoolCredential(artifact: artifact, clientCertificate: client_certificate,
      serverCertificate: server_certificate, activationAuthorization: activation,
      candidateIndex: local.candidate_index, grant: grant, relayCertificate: local.relay_certificate, serverAllow: serverAllow)
  }
  func target() throws -> ServiceBindingTarget {
    let artifact = try artifactValue()
    return try ServiceBindingTarget(authority: "flowersec.parity", tenant: artifact.t("tenant_id"), audience: artifact.t("audience"),
      localSubject: document(client_certificate, schema: "IdentityCertificate").t("subject_id"),
      peers: [.init(subject: document(server_certificate, schema: "IdentityCertificate").t("subject_id"),
        identityDigest: artifact.b("server_identity_digest"))])
  }
}
enum PeerParityFailure: Error {
  case invalidMaterial, unsupportedMaterial, responseTooLarge, bootstrapFailed, applicationMismatch
}
#endif
