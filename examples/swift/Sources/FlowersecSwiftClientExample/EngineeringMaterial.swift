import Flowersec
import Foundation
import Security
#if canImport(Darwin)
import Darwin
#endif

// This local engineering binding is trusted input from the explicitly selected
// fixture host. It is not a production authority discovery mechanism.
struct EngineeringMaterial: Decodable, Sendable {
  struct Generation: Decodable, Sendable {
    let source: Data
    let generation: UInt64
  }
  struct Namespace: Decodable, Sendable {
    let tenant: String
    let authority: String
    let generation: UInt64
    let rootKeyID: Data
    let rootPublicKey: Data
    let bootstrapURL: String
    let stateURL: String
    enum CodingKeys: String, CodingKey {
      case tenant, authority, generation
      case rootKeyID = "root_key_id", rootPublicKey = "root_public_key"
      case bootstrapURL = "bootstrap_url", stateURL = "state_url"
    }
  }
  struct Tunnel: Decodable, Sendable {
    let candidateIndex: Int
    let role: Int
    let grant: Data
    let relayCertificate: Data
    enum CodingKeys: String, CodingKey {
      case role, grant
      case candidateIndex = "candidate_index", relayCertificate = "relay_certificate"
    }
  }
  struct ServerAllow: Decodable, Sendable {
    let endpoint: String
    let recipient: Data
    let incarnation: Data
  }
  let tunnels: [Tunnel]?
  let serverAllow: ServerAllow?
  let wireRevision: Int
  let profile: String
  let source: String
  let generation: Generation
  let role: Int
  let artifact: Data
  let activation: Data
  let clientCertificate: Data
  let serverCertificate: Data
  let route: Data
  let routeDigest: Data
  let activationSigningKeyID: String
  let identitySeed: Data
  let dhSeed: Data
  let namespaces: [Namespace]
  enum CodingKeys: String, CodingKey {
    case profile, source, generation, role, artifact, activation, route, namespaces, tunnels
    case serverAllow = "server_allow"
    case wireRevision = "wire_revision", clientCertificate = "client_certificate"
    case serverCertificate = "server_certificate", routeDigest = "route_digest"
    case activationSigningKeyID = "activation_signing_key_id"
    case identitySeed = "identity_seed", dhSeed = "dh_seed"
  }

  static func load(_ path: String) throws -> EngineeringMaterial {
    let input = try readBoundedFile(path, maximumBytes: 1 << 20)
    let decoder = JSONDecoder()
    let material = try decoder.decode(Self.self, from: input)
    guard material.wireRevision == 4, material.role == 0,
      material.source == "preauthorized_pool",
      material.generation.source.count == 16, material.generation.generation > 0,
      material.identitySeed.count == 32, material.dhSeed.count == 32,
      material.routeDigest.count == 32, !material.activationSigningKeyID.isEmpty,
      (1...16).contains(material.namespaces.count)
    else { throw EngineeringMaterialError.invalidMaterial }
    for record in material.namespaces {
      guard record.rootKeyID.count == 16, record.rootPublicKey.count == 32,
        record.generation > 0 else { throw EngineeringMaterialError.invalidMaterial }
      _ = try engineeringURL(record.bootstrapURL)
      _ = try engineeringURL(record.stateURL)
    }
    return material
  }

  func configuration(history: EngineeringHistory, roots: [Data]) throws
    -> TransportClientConfiguration
  {
    let artifactMap = try FixtureCBOR.decode(artifact)
    let clientMap = try FixtureCBOR.decode(clientCertificate)
    let serverMap = try FixtureCBOR.decode(serverCertificate)
    let activationMap = try FixtureCBOR.decode(activation)
    let routeMap = try FixtureCBOR.decode(route)
    let kind = try routeMap.field(0).uint
    guard kind <= 1 else { throw EngineeringMaterialError.unsupportedMaterial }
    let leg = try routeMap.field(kind == 0 ? 2 : 3)
    guard try leg.field(5).uint == 1,
      try artifactMap.field(3).text == profile, try leg.field(0).uint == 0,
      try leg.field(3).uint == 0, try leg.field(4).uint == (kind == 0 ? 1 : 2)
    else { throw EngineeringMaterialError.unsupportedMaterial }
    let port = try leg.field(7).uint
    guard (1...65_535).contains(port) else { throw EngineeringMaterialError.invalidMaterial }
    let tenant = try artifactMap.field(4).text
    guard namespaces.allSatisfy({ $0.tenant == tenant }) else {
      throw EngineeringMaterialError.invalidMaterial
    }
    let once = try activationMap.field(7).field(4)
    let pins = namespaces.map { record in
      TransportTrustNamespace(
        authority: record.authority, rootKeyID: record.rootKeyID,
        rootPublicKey: record.rootPublicKey,
        maximumTrustLifetimeMilliseconds: 30_000_000,
        maximumStateBytes: 65_536, maximumStateNodes: 8192
      ) { nonce in
        try await record.bootstrap(nonce: nonce, roots: roots)
      }
    }
    let pool = TransportPoolHistory(
      directory: history.directory, storeID: history.storeID, generation: 1,
      artifactIssuerKeyID: try artifactMap.field(5).bytes,
      spendAuthority: try once.field(2).text,
      winnerAuthority: try once.field(3).text, create: true
    ) { try history.checkContinuity() }
    var configuration = TransportClientConfiguration(
      tenant: tenant, audience: try artifactMap.field(11).text,
      clientSubject: try clientMap.field(1).text,
      serverSubject: try serverMap.field(1).text, namespaces: pins,
      endpoints: [TransportEndpoint(hostname: try leg.field(6).text,
        port: Int(port), numericAddress: "127.0.0.1")],
      history: pool
    ) {
      // This test host explicitly uses the local wall clock. Production hosts
      // supply their independently established trusted-time bounds.
      let now = Date().timeIntervalSince1970 * 1000
      guard now.isFinite, now >= 0, now < Double(UInt64.max) else {
        throw EngineeringMaterialError.invalidMaterial
      }
      let milliseconds = UInt64(now)
      return TransportTrustedTime(lowerMilliseconds: milliseconds,
        upperMilliseconds: milliseconds)
    }
    configuration.trustRootsPEM = roots
    configuration.webSocketOrigin = ProcessInfo.processInfo.environment["FSEC_ORIGIN"]
    // Admit the fixture's complete namespace, service and native owner graph
    // within fixed local limits, independently of received material.
    configuration.maximumRuntimeItems = 16_384
    configuration.maximumResourceReservations = 8192
    configuration.maximumResourceReferences = 16_384
    return configuration
  }

  func serviceTarget() throws -> ServiceBindingTarget {
    let artifact = try FixtureCBOR.decode(artifact)
    let client = try FixtureCBOR.decode(clientCertificate)
    let server = try FixtureCBOR.decode(serverCertificate)
    return try ServiceBindingTarget(authority: "flowersec.parity", tenant: artifact.field(4).text,
      audience: artifact.field(11).text, localSubject: client.field(1).text,
      peers: [.init(subject: server.field(1).text, identityDigest: artifact.field(10).bytes)])
  }
}

extension EngineeringMaterial {
  func makeSource(environment: TransportEnvironment) async throws -> ConnectionMaterialSource {
    guard let profile = TransportCryptoProfile(rawValue: profile) else { throw EngineeringMaterialError.unsupportedMaterial }
    let identity = try await environment.importApplicationIdentity(profile: profile,
      signingSeed: identitySeed, noiseStaticPrivateKey: dhSeed)
    // The selected fixture explicitly supplies a preauthorized local pool.
    // The SDK captures its complete immutable identity generation before
    // Acquire; no custom callback assembles or swaps connection material.
    let kind = try FixtureCBOR.decode(route).field(0).uint
    let credential: TransportPoolCredential
    if kind == 0 {
      guard (tunnels ?? []).isEmpty, serverAllow == nil else { throw EngineeringMaterialError.invalidMaterial }
      credential = TransportPoolCredential(artifact: artifact, clientCertificate: clientCertificate,
        serverCertificate: serverCertificate, activationAuthorization: activation)
    } else {
      guard kind == 1, let tunnels, tunnels.count == 2,
        let local = tunnels.first(where: { $0.candidateIndex == 0 && $0.role == 0 }),
        let remote = tunnels.first(where: { $0.candidateIndex == 0 && $0.role == 1 }),
        local.relayCertificate == remote.relayCertificate else { throw EngineeringMaterialError.invalidMaterial }
      let variables = ProcessInfo.processInfo.environment
      let binding: ServerAllow
      if let serverAllow { binding = serverAllow }
      else {
        struct Ready: Decodable { let server_allow: ServerAllow }
        guard let encoded = variables["FLOWERSEC_PARITY_READY_BASE64"], encoded.utf8.count <= 3 << 20,
          let bytes = Data(base64Encoded: encoded), bytes.count <= 2 << 20 else { throw EngineeringMaterialError.invalidMaterial }
        binding = try JSONDecoder().decode(Ready.self, from: bytes).server_allow
      }
      let installed = try EngineeringPoolInstallation.read(variables: variables)
      let parent = try FixtureCBOR.decode(artifact)
      let allow = try installed.configuration(binding: binding, tenant: parent.field(4).text,
        audience: parent.field(11).text, grant: remote.grant)
      credential = TransportPoolCredential(artifact: artifact, clientCertificate: clientCertificate,
        serverCertificate: serverCertificate, activationAuthorization: activation,
        grant: local.grant, relayCertificate: local.relayCertificate, serverAllow: allow)
    }
    return try await environment.makePreauthorizedPoolSource([credential], identity: identity)
  }
}

enum EngineeringMaterialError: Error {
  case invalidMaterial, unsupportedMaterial, alreadyAcquired, responseTooLarge, bootstrapFailed
}

func readBoundedFile(_ path: String, maximumBytes: Int) throws -> Data {
  let file = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
  defer { try? file.close() }
  var data = Data()
  while let chunk = try file.read(upToCount: min(16_384, maximumBytes + 1 - data.count)), !chunk.isEmpty {
    data.append(chunk)
    guard data.count <= maximumBytes else { throw EngineeringMaterialError.responseTooLarge }
  }
  return data
}

private func engineeringURL(_ string: String) throws -> URL {
  guard let url = URL(string: string), ["http", "https"].contains(url.scheme ?? ""), ["localhost", "127.0.0.1"].contains(url.host ?? ""),
    url.user == nil, url.password == nil, url.fragment == nil,
    let port = url.port, (1...65535).contains(port)
  else { throw EngineeringMaterialError.unsupportedMaterial }
  return url
}

private final class EngineeringBootstrapDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
  private let hostname: String
  private let roots: [SecCertificate]
  private let gate = NSLock()
  private var invalidated = false
  private var invalidationWaiter: CheckedContinuation<Void, Never>?
  init(hostname: String, rootsPEM: [Data]) throws {
    self.hostname = hostname
    var certificates: [SecCertificate] = []
    for pem in rootsPEM {
      guard let text = String(data: pem, encoding: .utf8) else { throw EngineeringMaterialError.invalidMaterial }
      for section in text.components(separatedBy: "-----BEGIN CERTIFICATE-----").dropFirst() {
        guard let end = section.range(of: "-----END CERTIFICATE-----") else { throw EngineeringMaterialError.invalidMaterial }
        let base64 = String(section[..<end.lowerBound]).components(separatedBy: .whitespacesAndNewlines).joined()
        guard let der = Data(base64Encoded: base64),
          let certificate = SecCertificateCreateWithData(nil, der as CFData), certificates.count < 16 else {
          throw EngineeringMaterialError.invalidMaterial
        }
        certificates.append(certificate)
      }
    }
    roots = certificates
    super.init()
  }
  func urlSession(_ session: URLSession, task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
    completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
    completionHandler(nil)
  }
  func urlSession(_ session: URLSession, task: URLSessionTask,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    urlSession(session, didReceive: challenge, completionHandler: completionHandler)
  }
  func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
      challenge.protectionSpace.host == hostname, let trust = challenge.protectionSpace.serverTrust,
      SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, hostname as CFString)) == errSecSuccess,
      SecTrustSetAnchorCertificates(trust, roots as CFArray) == errSecSuccess,
      SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
      SecTrustEvaluateWithError(trust, nil) else {
      completionHandler(.cancelAuthenticationChallenge, nil); return
    }
    completionHandler(.useCredential, URLCredential(trust: trust))
  }
  func urlSession(_ session: URLSession, didBecomeInvalidWithError error: (any Error)?) {
    let waiting = gate.withLock { () -> CheckedContinuation<Void, Never>? in
      invalidated = true; defer { invalidationWaiter = nil }; return invalidationWaiter
    }
    waiting?.resume()
  }
  func waitInvalidated() async {
    await withCheckedContinuation { continuation in
      let complete = gate.withLock {
        if invalidated { return true }; invalidationWaiter = continuation; return false
      }
      if complete { continuation.resume() }
    }
  }
}

extension EngineeringMaterial.Namespace {
  fileprivate func bootstrap(nonce: Data, roots: [Data]) async throws -> TransportNamespaceSnapshot {
    struct Request: Encodable { let tenant: String; let authority: String; let nonce: Data }
    struct Response: Decodable { let response: Data; let state: Data }
    let url = try engineeringURL(bootstrapURL)
    guard url.scheme != "https" || !roots.isEmpty else { throw EngineeringMaterialError.invalidMaterial }
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.timeoutInterval = 10
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = try JSONEncoder().encode(Request(tenant: tenant, authority: authority, nonce: nonce))
    let configuration = URLSessionConfiguration.ephemeral
    configuration.httpCookieStorage = nil
    configuration.urlCache = nil
    configuration.tlsMinimumSupportedProtocolVersion = .TLSv13
    configuration.tlsMaximumSupportedProtocolVersion = .TLSv13
    configuration.httpMaximumConnectionsPerHost = 1
    let delegate = try EngineeringBootstrapDelegate(hostname: request.url!.host!, rootsPEM: roots)
    let callbacks = OperationQueue()
    callbacks.maxConcurrentOperationCount = 1
    let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: callbacks)
    do {
      let (bytes, response) = try await session.bytes(for: request)
      guard let response = response as? HTTPURLResponse, response.statusCode == 200 else {
        throw EngineeringMaterialError.bootstrapFailed
      }
      var input = Data()
      for try await byte in bytes {
        guard input.count < 65_536 else { throw EngineeringMaterialError.responseTooLarge }
        input.append(byte)
      }
      let snapshot = try JSONDecoder().decode(Response.self, from: input)
      guard !snapshot.response.isEmpty, snapshot.response.count <= 32_768,
        !snapshot.state.isEmpty, snapshot.state.count <= 4096 else {
        throw EngineeringMaterialError.responseTooLarge
      }
      session.finishTasksAndInvalidate()
      await delegate.waitInvalidated()
      return TransportNamespaceSnapshot(response: snapshot.response, state: snapshot.state)
    } catch {
      session.invalidateAndCancel()
      await delegate.waitInvalidated()
      throw error
    }
  }
}

// A fresh local durable directory, never a store chosen by received material.
// Existing directories are rejected so this one-shot example cannot replace or
// roll back a previous spend history. Keep this directory after process exit.
struct EngineeringHistory: Sendable {
  let directory: URL
  let storeID: Data
  private let device: dev_t
  private let inode: ino_t
  init(receiptPath: String) throws {
    let requested = URL(fileURLWithPath: receiptPath + ".history", isDirectory: true)
    // Resolve the trusted parent before SQLite's no-symlink open. Keep the
    // new leaf unchanged so an existing history or symlink is still rejected.
    guard let parent = realpath(requested.deletingLastPathComponent().path, nil) else {
      throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    defer { free(parent) }
    directory = URL(fileURLWithPath: String(cString: parent), isDirectory: true)
      .appendingPathComponent(requested.lastPathComponent, isDirectory: true)
    guard mkdir(directory.path, 0o700) == 0 else {
      throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    try syncDirectory(at: directory.deletingLastPathComponent())
    var attributes = stat()
    guard lstat(directory.path, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFDIR else {
      throw EngineeringMaterialError.invalidMaterial
    }
    device = attributes.st_dev
    inode = attributes.st_ino
    var identifier = UUID().uuid
    storeID = withUnsafeBytes(of: &identifier) { Data($0) }
  }
  func checkContinuity() throws {
    var attributes = stat()
    guard lstat(directory.path, &attributes) == 0,
      attributes.st_mode & S_IFMT == S_IFDIR,
      attributes.st_dev == device, attributes.st_ino == inode,
      attributes.st_uid == geteuid(), attributes.st_mode & 0o077 == 0
    else { throw EngineeringMaterialError.invalidMaterial }
  }
}

// Only reads the fixed local fixture maps needed to configure the public SDK.
// The SDK separately validates canonical maps, signatures, permissions, current
// trust, identity possession, deadlines and original durable spend.
indirect enum FixtureCBOR {
  case unsigned(UInt64), bytes(Data), text(String), array([FixtureCBOR]), map([UInt64: FixtureCBOR])
  case boolean(Bool), null
  var uint: UInt64 { get throws {
    guard case .unsigned(let value) = self else { throw EngineeringMaterialError.invalidMaterial }; return value
  } }
  var bytes: Data { get throws {
    guard case .bytes(let value) = self else { throw EngineeringMaterialError.invalidMaterial }; return value
  } }
  var text: String { get throws {
    guard case .text(let value) = self else { throw EngineeringMaterialError.invalidMaterial }; return value
  } }
  func field(_ key: UInt64) throws -> FixtureCBOR {
    guard case .map(let values) = self, let value = values[key] else {
      throw EngineeringMaterialError.invalidMaterial
    }
    return value
  }
  static func decode(_ data: Data) throws -> FixtureCBOR {
    guard (1...65_536).contains(data.count) else { throw EngineeringMaterialError.invalidMaterial }
    var parser = Parser(data: Array(data))
    let value = try parser.read(depth: 0)
    guard parser.offset == data.count else { throw EngineeringMaterialError.invalidMaterial }
    return value
  }
  private struct Parser {
    let data: [UInt8]
    var offset = 0
    var nodes = 0
    mutating func byte() throws -> UInt8 {
      guard offset < data.count else { throw EngineeringMaterialError.invalidMaterial }
      defer { offset += 1 }; return data[offset]
    }
    mutating func argument(_ info: UInt8) throws -> UInt64 {
      if info < 24 { return UInt64(info) }
      let count: Int
      switch info { case 24: count = 1; case 25: count = 2; case 26: count = 4; case 27: count = 8
      default: throw EngineeringMaterialError.invalidMaterial }
      var value: UInt64 = 0
      for _ in 0..<count { value = (value << 8) | UInt64(try byte()) }
      let minimum: UInt64 = count == 1 ? 24 : count == 2 ? 256 : count == 4 ? 65_536 : 4_294_967_296
      guard value >= minimum else { throw EngineeringMaterialError.invalidMaterial }
      return value
    }
    mutating func read(depth: Int) throws -> FixtureCBOR {
      nodes += 1
      guard depth <= 8, nodes <= 4096 else { throw EngineeringMaterialError.invalidMaterial }
      let tag = try byte(), major = tag >> 5, info = tag & 31
      if major == 7 {
        switch info { case 20: return .boolean(false); case 21: return .boolean(true); case 22: return .null
        default: throw EngineeringMaterialError.invalidMaterial }
      }
      let count = try argument(info)
      switch major {
      case 0: return .unsigned(count)
      case 2, 3:
        guard count <= UInt64(data.count - offset) else { throw EngineeringMaterialError.invalidMaterial }
        let value = Data(data[offset..<(offset + Int(count))]); offset += Int(count)
        if major == 2 { return .bytes(value) }
        guard let string = String(data: value, encoding: .utf8) else { throw EngineeringMaterialError.invalidMaterial }
        return .text(string)
      case 4:
        guard count <= 1035 else { throw EngineeringMaterialError.invalidMaterial }
        var values: [FixtureCBOR] = []
        for _ in 0..<count { values.append(try read(depth: depth + 1)) }; return .array(values)
      case 5:
        guard count <= 128 else { throw EngineeringMaterialError.invalidMaterial }
        var values: [UInt64: FixtureCBOR] = [:], previous: UInt64?
        for _ in 0..<count {
          let key = try read(depth: depth + 1).uint
          guard key <= 65_535, previous == nil || key > previous! else { throw EngineeringMaterialError.invalidMaterial }
          values[key] = try read(depth: depth + 1); previous = key
        }
        return .map(values)
      default: throw EngineeringMaterialError.invalidMaterial
      }
    }
  }
}

// The sender's keys, trust and complete destination are installed before B
// publishes its public recipient metadata. Neither readiness nor Grant bytes
// can choose another control destination or TLS identity.
private struct EngineeringPoolInstallation: Decodable {
  final class TLS: Decodable {
    let certificatePEM: Data
    private(set) var privateKeyPEM: Data
    let trustPEM: Data
    enum CodingKeys: String, CodingKey { case certificatePEM, privateKeyPEM, trustPEM }
    init(from decoder: any Decoder) throws {
      let fields = try decoder.container(keyedBy: CodingKeys.self)
      certificatePEM = Data(try fields.decode(String.self, forKey: .certificatePEM).utf8)
      privateKeyPEM = Data(try fields.decode(String.self, forKey: .privateKeyPEM).utf8)
      trustPEM = Data(try fields.decode(String.self, forKey: .trustPEM).utf8)
    }
    deinit { privateKeyPEM.resetBytes(in: 0..<privateKeyPEM.count) }
  }
  struct Control: Decodable {
    let endpoint: String
    let tls: TLS
    let workMS: String
    let clientCertificateDER: Data?
  }
  let wire_revision: Int
  let tenant: String
  let audience: String
  let server_allow: Control
  static func read(variables: [String: String]) throws -> Self {
    guard let path = variables["FLOWERSEC_PARITY_POOL_DEPLOYMENT"], !path.isEmpty,
      path.utf8.count <= 4096, (path as NSString).isAbsolutePath else { throw EngineeringMaterialError.invalidMaterial }
    var bytes = try readBoundedFile(path, maximumBytes: 4 << 20)
    defer { bytes.resetBytes(in: 0..<bytes.count) }
    return try JSONDecoder().decode(Self.self, from: bytes)
  }
  func configuration(binding: EngineeringMaterial.ServerAllow, tenant: String, audience: String,
    grant: Data) throws -> TransportPoolServerAllowConfiguration {
    let c = server_allow
    guard wire_revision == 4, self.tenant == tenant, self.audience == audience,
      c.clientCertificateDER == nil, c.endpoint == binding.endpoint, c.endpoint.utf8.count <= 2048,
      let url = URL(string: c.endpoint), url.scheme == "https", url.host == "127.0.0.1",
      let port = url.port, (1...65535).contains(port), url.path == "/tunnel/server-allow",
      url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
      c.endpoint == "https://127.0.0.1:\(port)/tunnel/server-allow",
      let work = UInt64(c.workMS), String(work) == c.workMS, (1...2000).contains(work),
      [binding.recipient, binding.incarnation].allSatisfy({ $0.count == 16 && $0.contains(where: { $0 != 0 }) }),
      (1...9302).contains(grant.count), (1...65_536).contains(c.tls.certificatePEM.count),
      (1...16_384).contains(c.tls.privateKeyPEM.count), (1...262_144).contains(c.tls.trustPEM.count)
    else { throw EngineeringMaterialError.invalidMaterial }
    let control = TransportControlHTTPSConfiguration(
      endpoint: TransportEndpoint(hostname: "127.0.0.1", port: port, numericAddress: "127.0.0.1"),
      trustRootsPEM: [c.tls.trustPEM], clientCertificatePEM: c.tls.certificatePEM,
      clientPrivateKeyPEM: c.tls.privateKeyPEM, maximumConcurrentRequests: 1, timeoutMilliseconds: work)
    return TransportPoolServerAllowConfiguration(control: control, recipient: binding.recipient,
      incarnation: binding.incarnation, serverGrant: grant)
  }
}
