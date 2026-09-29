#if os(macOS) || os(iOS)
  import Foundation

  public enum TransportV4CryptoProfile: String, Sendable {
    case x25519 = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1"
    case p256 = "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"
  }
  public struct TransportV4TrustedTime: Sendable {
    public let lowerMilliseconds: UInt64
    public let upperMilliseconds: UInt64
    public init(lowerMilliseconds: UInt64, upperMilliseconds: UInt64) {
      self.lowerMilliseconds = lowerMilliseconds
      self.upperMilliseconds = upperMilliseconds
    }
  }
  public struct TransportV4TimePolicy: Sendable {
    public var driftNumerator: UInt64 = 100
    public var driftDenominator: UInt64 = 1_000_000
    public var quantizationMilliseconds: UInt64 = 1
    public var maximumWidthMilliseconds: UInt64 = 10_000
    public var maximumAnchorAgeMilliseconds: UInt64 = 60_000
    public init() {}
  }
  public struct TransportV4NamespaceSnapshot: Sendable {
    public let response: Data
    public let state: Data
    public init(response: Data, state: Data) {
      self.response = response
      self.state = state
    }
  }
  public struct TransportV4TrustNamespace: Sendable {
    public let authority: String
    public let rootKeyID: Data
    public let rootPublicKey: Data
    public let maximumTrustLifetimeMilliseconds: UInt64
    public let maximumStateBytes: Int
    public let maximumStateNodes: Int
    // Qualified adapter: one original nonce-bound request, bounded response,
    // no detached cancellation tail. TLS/control authentication is host-owned;
    // the SDK independently verifies the complete signed bootstrap response.
    public let bootstrap: @Sendable (Data) async throws -> TransportV4NamespaceSnapshot
    public init(
      authority: String, rootKeyID: Data, rootPublicKey: Data,
      maximumTrustLifetimeMilliseconds: UInt64, maximumStateBytes: Int = 1 << 20,
      maximumStateNodes: Int = 65536,
      bootstrap: @escaping @Sendable (Data) async throws -> TransportV4NamespaceSnapshot
    ) {
      self.authority = authority
      self.rootKeyID = rootKeyID
      self.rootPublicKey = rootPublicKey
      self.maximumTrustLifetimeMilliseconds = maximumTrustLifetimeMilliseconds
      self.maximumStateBytes = maximumStateBytes
      self.maximumStateNodes = maximumStateNodes
      self.bootstrap = bootstrap
    }
  }
  public struct TransportV4Endpoint: Sendable {
    public let hostname: String
    public let port: Int
    public let numericAddress: String
    public init(hostname: String, port: Int, numericAddress: String) {
      self.hostname = hostname
      self.port = port
      self.numericAddress = numericAddress
    }
  }
  public struct TransportV4PoolHistory: Sendable {
    public let directory: URL
    public let storeID: Data
    public let generation: UInt64
    public let artifactIssuerKeyID: Data
    public let spendAuthority: String
    public let winnerAuthority: String
    public let create: Bool
    public var maximumBytes: Int = 16 << 20
    public var maximumRows: Int = 4096
    // Independently trusted host continuity gate. Opening a copied/rolled-back
    // history or choosing a new store from received material is forbidden.
    public let checkContinuity: @Sendable () throws -> Void
    public init(
      directory: URL, storeID: Data, generation: UInt64, artifactIssuerKeyID: Data,
      spendAuthority: String, winnerAuthority: String, create: Bool,
      checkContinuity: @escaping @Sendable () throws -> Void
    ) {
      self.directory = directory
      self.storeID = storeID
      self.generation = generation
      self.artifactIssuerKeyID = artifactIssuerKeyID
      self.spendAuthority = spendAuthority
      self.winnerAuthority = winnerAuthority
      self.create = create
      self.checkContinuity = checkContinuity
    }
  }
  public struct TransportV4ClientConfiguration: Sendable {
    public let tenant: String
    public let audience: String
    public let clientSubject: String
    public let serverSubject: String
    public let namespaces: [TransportV4TrustNamespace]
    public let endpoints: [TransportV4Endpoint]
    public let history: TransportV4PoolHistory
    public let trustedTime: @Sendable () throws -> TransportV4TrustedTime
    public var timePolicy = TransportV4TimePolicy()
    public var trustRootsPEM: [Data] = []
    public var maximumRuntimeBytes: UInt64 = 2 << 30
    public var providerRuntimeBytes: UInt64 = 16 << 20
    public var automaticLiveness: TransportV4AutomaticLivenessPolicy? = nil
    public init(
      tenant: String, audience: String, clientSubject: String, serverSubject: String,
      namespaces: [TransportV4TrustNamespace], endpoints: [TransportV4Endpoint],
      history: TransportV4PoolHistory,
      trustedTime: @escaping @Sendable () throws -> TransportV4TrustedTime
    ) {
      self.tenant = tenant
      self.audience = audience
      self.clientSubject = clientSubject
      self.serverSubject = serverSubject
      self.namespaces = namespaces
      self.endpoints = endpoints
      self.history = history
      self.trustedTime = trustedTime
    }
  }
  public final class TransportV4ApplicationIdentity: Sendable, CustomStringConvertible {
    let owner: V4LocalIdentity
    init(_ owner: V4LocalIdentity) { self.owner = owner }
    public var profile: TransportV4CryptoProfile {
      TransportV4CryptoProfile(rawValue: owner.profile.rawValue)!
    }
    public var signingPublicKey: Data { owner.identityPublicKey }
    public var noiseStaticPublicKey: Data { owner.dhPublicKey }
    public var description: String { "Flowersec.ApplicationIdentity(<redacted>)" }
    public func close() { owner.close() }
  }
  public struct TransportV4PoolCredential: Sendable, CustomStringConvertible {
    let input: V4CredentialInput
    public init(
      artifact: Data, clientCertificate: Data, serverCertificate: Data,
      activationAuthorization: Data, candidateIndex: Int = 0
    ) {
      input = V4CredentialInput(
        artifact: artifact, clientCertificate: clientCertificate,
        serverCertificate: serverCertificate, activation: activationAuthorization,
        source: .preauthorizedPool, candidateIndex: candidateIndex)
    }
    public var description: String { "Flowersec.PoolCredential(<redacted>)" }
  }

  final class V4ClientEnvironment: TransportEnvironmentOwner, @unchecked Sendable {
    let foundation: V4EnvironmentFoundation
    private var namespaces: [V4NamespaceVerifier]
    private var credentials: V4CredentialConfiguration?
    private let endpoints: [TransportV4Endpoint]
    private let roots: [Data]
    private var backing: V4PoolStoreBacking?
    private var store: V4SQLitePoolStore?
    private var provider: V4CryptoReservation?
    private let source: V4ContinuousTimeSource?
    private let trustedTime: (@Sendable () throws -> TransportV4TrustedTime)?
    private var closed = false
    private var operations: [V4ConnectOperation] = []
    init(
      foundation: V4EnvironmentFoundation, namespaces: [V4NamespaceVerifier],
      credentials: V4CredentialConfiguration, endpoints: [TransportV4Endpoint], roots: [Data],
      backing: V4PoolStoreBacking, store: V4SQLitePoolStore, provider: V4CryptoReservation,
      source: V4ContinuousTimeSource? = nil,
      trustedTime: (@Sendable () throws -> TransportV4TrustedTime)? = nil
    ) {
      self.foundation = foundation
      self.namespaces = namespaces
      self.credentials = credentials
      self.endpoints = endpoints
      self.roots = roots
      self.backing = backing
      self.store = store
      self.provider = provider
      self.source = source
      self.trustedTime = trustedTime
    }
    private static func installTime(
      _ callback: @Sendable () throws -> TransportV4TrustedTime,
      foundation: V4EnvironmentFoundation
    ) throws {
      let start = try foundation.clock.mark()
      let time = try callback()
      let end = try foundation.clock.mark()
      guard end.sameEra(as: start), end.milliseconds >= start.milliseconds else {
        throw V4TimeFailure.continuity
      }
      let elapsed = try foundation.clock.profile.elapsed(end.milliseconds - start.milliseconds)
      let (upper, overflow) = time.upperMilliseconds.addingReportingOverflow(elapsed.upperMS)
      guard !overflow else { throw V4TimeFailure.unavailable }
      try foundation.clock.installTrusted(
        at: end,
        interval: V4TimeInterval(lowerMS: time.lowerMilliseconds, upperMS: upper))
    }
    static func create(_ config: TransportV4ClientConfiguration) async throws -> V4ClientEnvironment
    {
      guard (1...8).contains(config.namespaces.count), (1...16).contains(config.endpoints.count),
        config.maximumRuntimeBytes >= 64 << 20, config.maximumRuntimeBytes <= 8 << 30,
        config.providerRuntimeBytes >= 1 << 20,
        config.providerRuntimeBytes < config.maximumRuntimeBytes,
        config.history.maximumBytes >= 1 << 20
      else { throw TransportV4ConnectError.unsupported }
      let limit = V4ResourceVector(
        sdkBytes: config.maximumRuntimeBytes,
        diskBytes: UInt64(config.history.maximumBytes) * 3, items: 512, work: 128,
        tasks: 128, timers: 128, connections: 16, handshakes: 16, sessions: 16, handles: 128)
      let root = try V4ResourceRoot(
        V4ResourceRootConfiguration(
          limit: limit, accounts: 64,
          reservations: 512, references: 1024, cleanupWaiters: 16, runtimeOverheadBytes: 16384))
      let tenant = try root.account(
        kind: .tenant, identity: V4ResourceIdentity(high: 1, low: 1), limit: limit)
      let source = V4ContinuousTimeSource()
      let p = config.timePolicy
      let foundation = try V4EnvironmentFoundation(
        root: root, tenant: tenant,
        configuration: V4EnvironmentConfiguration(
          identity: V4ResourceIdentity(high: 2, low: 1),
          limit: limit, maximumReadBudgets: 8, maximumWork: 32, runtimeOverheadBytes: 16384,
          cleanupTimeout: .seconds(5), verificationContinuity: .onlineBootstrap,
          automaticLiveness: config.automaticLiveness),
        timeProfile: V4TimeProfile(
          rateNumerator: p.driftNumerator, rateDenominator: p.driftDenominator,
          quantizationMS: p.quantizationMilliseconds, maximumWidthMS: p.maximumWidthMilliseconds,
          maximumAnchorAgeMS: p.maximumAnchorAgeMilliseconds), monotonicSource: source)
      do {
        let provider = try foundation.clientProviderStorage(bytes: config.providerRuntimeBytes)
        try installTime(config.trustedTime, foundation: foundation)
        var namespaces: [V4NamespaceVerifier] = []
        for item in config.namespaces {
          let namespace = try foundation.namespace(
            pinnedRoot: V4NamespaceTrustRoot(
              tenant: config.tenant,
              authority: item.authority, keyID: item.rootKeyID, publicKey: item.rootPublicKey,
              maximumTrustLifetimeMS: item.maximumTrustLifetimeMilliseconds),
            configuration: V4NamespaceConfiguration(
              stateBytes: item.maximumStateBytes,
              stateNodes: item.maximumStateNodes, bootstrapMS: 10000))
          let tail = try provider.executionTail()
          defer { tail.release() }
          let snapshot = try await item.bootstrap(namespace.bootstrapNonce())
          if Task.isCancelled { throw TransportV4ConnectError.canceled }
          try provider.check()
          try namespace.bootstrap(response: snapshot.response, state: snapshot.state)
          namespaces.append(namespace)
        }
        let h = config.history
        let backing = try V4PoolStoreBacking(
          environment: foundation, directory: h.directory,
          identity: V4PoolStoreIdentity(
            storeID: h.storeID, generation: h.generation, tenant: config.tenant,
            issuer: h.artifactIssuerKeyID, spendAuthority: h.spendAuthority,
            winnerAuthority: h.winnerAuthority),
          maximumBytes: h.maximumBytes, maximumRows: h.maximumRows,
          continuity: { _ in try h.checkContinuity() })
        let store = try backing.open(create: h.create)
        return V4ClientEnvironment(
          foundation: foundation, namespaces: namespaces,
          credentials: V4CredentialConfiguration(
            namespaces: namespaces, tenant: config.tenant,
            audience: config.audience, clientSubject: config.clientSubject,
            serverSubject: config.serverSubject,
            cryptoProfiles: V4CryptoProfile.allCases.map(\.rawValue)), endpoints: config.endpoints,
          roots: config.trustRootsPEM, backing: backing, store: store, provider: provider,
          source: source,
          trustedTime: config.trustedTime)
      } catch {
        foundation.beginClose()
        throw error
      }
    }
    func material(_ input: TransportV4PoolCredential, identity: TransportV4ApplicationIdentity)
      throws
      -> ConnectionMaterial
    {
      try foundation.gate.withLock {
        guard !closed, let credentials else { throw TransportV4ConnectError.closed }
        let admission = try foundation.verifyDirectCredentials(
          configuration: credentials, input: input.input)
        do {
          let plan = try admission.directPoolPlan(in: foundation, identity: identity.owner)
          return ConnectionMaterial(
            owner: V4DirectPoolMaterial(plan: plan, identity: identity.owner))
        } catch {
          admission.close()
          throw error
        }
      }
    }
    private func run(_ body: @escaping @Sendable () async throws -> any Session) async throws
      -> any Session
    {
      let operation = try foundation.gate.withLock {
        guard !closed else { throw TransportV4ConnectError.closed }
        operations.removeAll { $0.finished }
        guard operations.count < 8 else { throw SessionError.resourceExhausted }
        let value = try V4ConnectOperation(foundation: foundation, body: body)
        operations.append(value)
        return value
      }
      defer { foundation.gate.withLock { operations.removeAll { $0 === operation } } }
      return try await withTaskCancellationHandler {
        let session = try await operation.value()
        let denied = foundation.gate.withLock { closed || Task.isCancelled }
        if denied {
          try await session.close()
          throw TransportV4ConnectError.canceled
        }
        return session
      } onCancel: {
        operation.close()
      }
    }
    func connect(source: any ConnectionMaterialSource, requirements: ConnectionRequirements)
      async throws -> any Session
    {
      try V4DirectEstablishment.requirements(requirements)
      return try await run { [self] in
        let material = try await source.acquire(requirements)
        if Task.isCancelled {
          material.close()
          _ = try? await material.waitCleanup()
          throw TransportV4ConnectError.canceled
        }
        return try await connectOriginal(material, requirements: requirements)
      }
    }
    func connectMaterial(_ material: ConnectionMaterial, requirements: ConnectionRequirements)
      async throws -> any Session
    {
      try V4DirectEstablishment.requirements(requirements)
      return try await run { [self] in
        try await connectOriginal(material, requirements: requirements)
      }
    }
    private func connectOriginal(
      _ material: ConnectionMaterial, requirements: ConnectionRequirements
    ) async throws -> any Session {
      guard let original = material.owner as? V4DirectPoolMaterial,
        original.plan.environment === foundation
      else {
        throw TransportV4ConnectError.invalidMaterial
      }
      let route = original.plan.route
      let matches = endpoints.filter { $0.hostname == route.host && $0.port == route.port }
      guard matches.count == 1 else { throw TransportV4ConnectError.unsupported }
      let store = try foundation.gate.withLock {
        guard !closed, let store = self.store else { throw TransportV4ConnectError.closed }
        return store
      }
      return try await V4DirectEstablishment.connect(
        material: original, address: matches[0].numericAddress,
        roots: roots, store: store, requirements: requirements)
    }
    func close() async throws {
      foundation.gate.withLock {
        closed = true
        for operation in operations { operation.close() }
        foundation.beginClose()
        operations.removeAll { $0.finished }
        namespaces.removeAll()
        credentials = nil
        store = nil
        backing = nil
        provider = nil
      }
      try await foundation.close()
    }
    func cleanupStatus() -> CleanupStatus { foundation.cleanupStatus() }
    func invalidateTimeContinuity() { source?.invalidateContinuity() }
    func refreshTrustedTime() throws {
      try foundation.gate.withLock {
        guard !closed else { throw TransportV4ConnectError.closed }
        guard let trustedTime, let provider else { throw TransportV4ConnectError.unsupported }
        try provider.check()
        let tail = try provider.executionTail()
        defer { tail.release() }
        try Self.installTime(trustedTime, foundation: foundation)
      }
    }
    func refreshNamespace(authority: String, head: Data, state: Data) throws {
      try foundation.gate.withLock {
        guard !closed else { throw TransportV4ConnectError.closed }
        guard let namespace = namespaces.first(where: { $0.authority == authority }) else {
          throw TransportV4ConnectError.unsupported
        }
        try namespace.refresh(head: head, state: state)
      }
    }
  }

  private final class V4ConnectOperation: V4NativeConnectionLifecycle, @unchecked Sendable {
    private let gate = NSLock()
    private let storage: V4CryptoReservation
    private var task: Task<any Session, any Error>?
    private var complete = false
    var finished: Bool { gate.withLock { complete } }
    init(
      foundation: V4EnvironmentFoundation, body: @escaping @Sendable () async throws -> any Session
    ) throws {
      storage = try foundation.clientConnectStorage()
      let tail = try storage.executionTail()
      do { try foundation.registerNativeConnection(self) } catch {
        tail.release()
        throw error
      }
      gate.withLock {
        task = Task { [self] in
          defer {
            storage.seal()
            tail.release()
            gate.withLock { complete = true }
          }
          try storage.check()
          if Task.isCancelled { throw TransportV4ConnectError.canceled }
          return try await body()
        }
      }
    }
    func value() async throws -> any Session {
      guard let current = gate.withLock({ task }) else { throw TransportV4ConnectError.closed }
      defer { gate.withLock { task = nil } }
      return try await current.value
    }
    func close() {
      let current = gate.withLock { task }
      current?.cancel()
    }
  }
#endif
