#if os(macOS) || os(iOS)
  import Foundation

  public enum TransportCryptoProfile: String, Sendable {
    case x25519 = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1"
    case p256 = "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"
  }
  public struct TransportTrustedTime: Sendable {
    public let lowerMilliseconds: UInt64
    public let upperMilliseconds: UInt64
    public init(lowerMilliseconds: UInt64, upperMilliseconds: UInt64) {
      self.lowerMilliseconds = lowerMilliseconds
      self.upperMilliseconds = upperMilliseconds
    }
  }
  public struct TransportTimePolicy: Sendable {
    public var driftNumerator: UInt64 = 100
    public var driftDenominator: UInt64 = 1_000_000
    public var quantizationMilliseconds: UInt64 = 1
    public var maximumWidthMilliseconds: UInt64 = 10_000
    public var maximumAnchorAgeMilliseconds: UInt64 = 60_000
    public init() {}
  }
  public struct TransportNamespaceSnapshot: Sendable {
    public let response: Data
    public let state: Data
    public init(response: Data, state: Data) {
      self.response = response
      self.state = state
    }
  }
  public struct TransportTrustNamespace: Sendable {
    public let authority: String
    public let rootKeyID: Data
    public let rootPublicKey: Data
    public let maximumTrustLifetimeMilliseconds: UInt64
    public let maximumStateBytes: Int
    public let maximumStateNodes: Int
    // Qualified adapter: one original nonce-bound request, bounded response,
    // no detached cancellation tail. TLS/control authentication is host-owned;
    // the SDK independently verifies the complete signed bootstrap response.
    public let bootstrap: @Sendable (Data) async throws -> TransportNamespaceSnapshot
    public init(
      authority: String, rootKeyID: Data, rootPublicKey: Data,
      maximumTrustLifetimeMilliseconds: UInt64, maximumStateBytes: Int = 1 << 20,
      maximumStateNodes: Int = 65536,
      bootstrap: @escaping @Sendable (Data) async throws -> TransportNamespaceSnapshot
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
  public struct TransportEndpoint: Sendable {
    public let hostname: String
    public let port: Int
    public let numericAddress: String
    public init(hostname: String, port: Int, numericAddress: String) {
      self.hostname = hostname
      self.port = port
      self.numericAddress = numericAddress
    }
  }
  public struct TransportPoolHistory: Sendable {
    public let parentWinner: ParentWinnerAuthorityConfiguration?
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
      spendAuthority: String, winnerAuthority: String, create: Bool, parentWinner: ParentWinnerAuthorityConfiguration? = nil,
      checkContinuity: @escaping @Sendable () throws -> Void
    ) {
      self.parentWinner = parentWinner
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
  public struct NativeListenerTLSConfiguration: Sendable, CustomStringConvertible {
    public let certificateChainPEM: Data
    public let privateKeyPEM: Data
    public init(certificateChainPEM: Data, privateKeyPEM: Data) {
      self.certificateChainPEM = certificateChainPEM; self.privateKeyPEM = privateKeyPEM
    }
    public var description: String { "Flowersec.NativeListenerTLSConfiguration(<redacted>)" }
  }
  public struct TransportClientConfiguration: Sendable {
    public let tenant: String
    public let audience: String
    public let clientSubject: String
    public let serverSubject: String
    public let namespaces: [TransportTrustNamespace]
    public let endpoints: [TransportEndpoint]
    public let history: TransportPoolHistory?
    public let trustedTime: @Sendable () throws -> TransportTrustedTime
    public var timePolicy = TransportTimePolicy()
    public var trustRootsPEM: [Data] = []
    /// Canonical Origin sent by native WebSocket dialers, subject to the signed route policy.
    public var webSocketOrigin: String? = nil
    public var listenerTLS: NativeListenerTLSConfiguration? = nil
    public var maximumRuntimeItems: UInt64 = 512
    public var maximumResourceReservations: Int = 512
    public var maximumResourceReferences: Int = 1024
    public var maximumPersistentApplicationBytes: UInt64 = 128 << 20
    public var maximumRuntimeBytes: UInt64 = 2 << 30
    public var providerRuntimeBytes: UInt64 = 16 << 20
    public var maximumNativeProviderBytes: UInt64 = 64 << 20
    public var automaticLiveness: TransportAutomaticLivenessPolicy? = nil
    public var applicationResources: ApplicationResourceProfile = .client
    public var diagnostics: TransportDiagnosticSinkConfiguration? = nil
    public init(
      tenant: String, audience: String, clientSubject: String, serverSubject: String,
      namespaces: [TransportTrustNamespace], endpoints: [TransportEndpoint],
      history: TransportPoolHistory? = nil,
      trustedTime: @escaping @Sendable () throws -> TransportTrustedTime
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
  public final class TransportApplicationIdentity: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let owner: V4LocalIdentity
    init(_ owner: V4LocalIdentity) { self.owner = owner }
    public var profile: TransportCryptoProfile {
      TransportCryptoProfile(rawValue: owner.profile.rawValue)!
    }
    public var signingPublicKey: Data { owner.identityPublicKey }
    public var noiseStaticPublicKey: Data { owner.dhPublicKey }
    public var description: String { "Flowersec.ApplicationIdentity(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: EmptyCollection<(label: String?, value: Any)>()) }
    public func close() { owner.close() }
  }
  public struct TransportPoolCredential: Sendable, CustomStringConvertible {
    let input: V4CredentialInput
    public init(
      artifact: Data, clientCertificate: Data, serverCertificate: Data,
      activationAuthorization: Data, candidateIndex: Int = 0,
      grant: Data = Data(), relayCertificate: Data = Data(),
      serverAllow: TransportPoolServerAllowConfiguration? = nil
    ) {
      input = V4CredentialInput(
        artifact: artifact, clientCertificate: clientCertificate,
        serverCertificate: serverCertificate, activation: activationAuthorization,
        source: .preauthorizedPool, candidateIndex: candidateIndex, grant: grant, relayCertificate: relayCertificate, poolServerAllow: serverAllow?.input)
    }
    init(input: V4CredentialInput) { self.input = input }
    func withRole(_ role: ConnectionEndpointRole) -> Self {
      Self(input: input.withRole(role == .client ? .client : .server))
    }
    public var description: String { "Flowersec.PoolCredential(<redacted>)" }
  }

  final class V4ClientEnvironment: TransportEnvironmentOwner, @unchecked Sendable {
    let foundation: V4EnvironmentFoundation
    private var namespaces: [V4NamespaceVerifier]
    private var credentials: V4CredentialConfiguration?
    private let endpoints: [TransportEndpoint]
    private let roots: [Data]
    private var listenerTLS: NativeListenerTLSConfiguration?
    private var backing: V4PoolStoreBacking?
    private var store: V4SQLitePoolStore?
    private var provider: V4CryptoReservation?
    private let source: V4ContinuousTimeSource?
    private let trustedTime: (@Sendable () throws -> TransportTrustedTime)?
    private var closed = false
    private var operations: [V4ConnectOperation] = []
    init(
      foundation: V4EnvironmentFoundation, namespaces: [V4NamespaceVerifier],
      credentials: V4CredentialConfiguration, endpoints: [TransportEndpoint], roots: [Data],
      backing: V4PoolStoreBacking?, store: V4SQLitePoolStore?, provider: V4CryptoReservation,
      source: V4ContinuousTimeSource? = nil,
      trustedTime: (@Sendable () throws -> TransportTrustedTime)? = nil, listenerTLS: NativeListenerTLSConfiguration? = nil
    ) {
      self.foundation = foundation
      self.namespaces = namespaces
      self.credentials = credentials
      self.endpoints = endpoints
      self.roots = roots
      self.listenerTLS = listenerTLS
      self.backing = backing
      self.store = store
      self.provider = provider
      self.source = source
      self.trustedTime = trustedTime
    }
    private static func installTime(
      _ callback: @Sendable () throws -> TransportTrustedTime,
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
    static func create(_ config: TransportClientConfiguration) async throws -> V4ClientEnvironment
    {
      guard (1...8).contains(config.namespaces.count), (1...16).contains(config.endpoints.count),
        config.maximumRuntimeBytes >= 64 << 20, config.maximumRuntimeBytes <= 8 << 30,
        config.providerRuntimeBytes >= 1 << 20,
        config.maximumNativeProviderBytes >= 4 << 20, config.maximumNativeProviderBytes <= 8 << 30,
        config.providerRuntimeBytes < config.maximumRuntimeBytes,
        config.history == nil || (config.history?.maximumBytes ?? 0) >= 1 << 20
      else { throw TransportConnectError.unsupported }
      guard config.maximumPersistentApplicationBytes <= 8 << 30, (512...1 << 20).contains(config.maximumRuntimeItems),
        (512...1 << 20).contains(config.maximumResourceReservations), (1024...1 << 21).contains(config.maximumResourceReferences) else { throw TransportConnectError.unsupported }
      if let origin = config.webSocketOrigin {
        guard origin.utf8.count <= 8192 else { throw TransportConnectError.unsupported }
        try V4CredentialText.validate(origin, format: "origin", registry: V4NamespaceRegistry())
      }
      let (persistentBytes, persistentOverflow) = (UInt64(config.history?.maximumBytes ?? 0) * 3).addingReportingOverflow(config.maximumPersistentApplicationBytes)
      guard !persistentOverflow else { throw TransportConnectError.unsupported }
      let limit = V4ResourceVector(
        sdkBytes: config.maximumRuntimeBytes, providerBytes: config.maximumNativeProviderBytes,
        diskBytes: persistentBytes, items: config.maximumRuntimeItems, work: 128,
        tasks: 128, timers: 128, connections: 16, handshakes: 16, sessions: 16, handles: 128)
      let root = try V4ResourceRoot(
        V4ResourceRootConfiguration(
          limit: limit, accounts: 64,
          reservations: config.maximumResourceReservations, references: config.maximumResourceReferences, cleanupWaiters: 16, runtimeOverheadBytes: 16384))
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
          automaticLiveness: config.automaticLiveness, applicationResources: config.applicationResources),
        timeProfile: V4TimeProfile(
          rateNumerator: p.driftNumerator, rateDenominator: p.driftDenominator,
          quantizationMS: p.quantizationMilliseconds, maximumWidthMS: p.maximumWidthMilliseconds,
          maximumAnchorAgeMS: p.maximumAnchorAgeMilliseconds), monotonicSource: source)
      do {
        try foundation.installDiagnosticSink(config.diagnostics)
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
          if Task.isCancelled { throw TransportConnectError.canceled }
          try provider.check()
          try await namespace.bootstrapWhenReady(response: snapshot.response, state: snapshot.state)
          namespaces.append(namespace)
        }
        let backing: V4PoolStoreBacking?
        let store: V4SQLitePoolStore?
        if let h = config.history {
          let history = try V4PoolStoreBacking(environment: foundation, directory: h.directory,
            identity: V4PoolStoreIdentity(storeID: h.storeID, generation: h.generation, tenant: config.tenant,
              issuer: h.artifactIssuerKeyID, spendAuthority: h.spendAuthority, winnerAuthority: h.winnerAuthority),
            maximumBytes: h.maximumBytes, maximumRows: h.maximumRows, parentWinner: h.parentWinner,
            continuity: { _ in try h.checkContinuity() })
          backing = history; store = try history.open(create: h.create)
        } else { backing = nil; store = nil }
        return V4ClientEnvironment(
          foundation: foundation, namespaces: namespaces,
          credentials: V4CredentialConfiguration(
            namespaces: namespaces, tenant: config.tenant,
            audience: config.audience, clientSubject: config.clientSubject,
            serverSubject: config.serverSubject,
            cryptoProfiles: V4CryptoProfile.allCases.map(\.rawValue), webSocketOrigin: config.webSocketOrigin), endpoints: config.endpoints,
          roots: config.trustRootsPEM, backing: backing, store: store, provider: provider,
          source: source,
          trustedTime: config.trustedTime, listenerTLS: config.listenerTLS)
      } catch {
        foundation.beginClose()
        throw error
      }
    }
    func validatePoolCredential(_ input: TransportPoolCredential, identity: TransportApplicationIdentity,
      requireEndpoint: Bool = true, requirements: ConnectionRequirements? = nil) throws -> UInt64 {
      try foundation.gate.withLock {
        guard !closed, let credentials else { throw TransportConnectError.closed }
        try identity.owner.check(in: foundation)
        let admission = try foundation.verifyDirectCredentials(configuration: credentials, input: input.input)
        defer { admission.close() }
        if admission.localRole == .server, admission.pathKind == 1 {
          throw TransportConnectError.invalidMaterial
        }
        if let serverAllow = input.input.poolServerAllow {
          guard serverAllow.control.basePath.isEmpty, (1...2000).contains(serverAllow.control.timeoutMilliseconds),
            [serverAllow.recipient, serverAllow.incarnation].allSatisfy({ $0.count == 16 && $0.contains(where: { $0 != 0 }) })
          else { throw TransportConnectError.invalidMaterial }
          let prepared = try admission.preparePoolServerGrant(serverAllow.grant, configuration: credentials)
          defer { prepared.close() }
          let local = try admission.tunnelGrant().0
          guard let server = prepared.completedGrant, try local.b("pairing_id") == server.b("pairing_id")
          else { throw TransportConnectError.securityFailed }
        }
        if !requireEndpoint {
          return try admission.poolApplicationProfile(in: foundation, identity: identity.owner)
        }
        let plan = try admission.directPoolPlan(in: foundation, identity: identity.owner)
        if let requirements { try V4DirectEstablishment.requirements(requirements, route: plan.route) }
        guard plan.route.isDialer || !plan.route.requiresTLS || listenerTLS != nil else {
          throw TransportConnectError.unsupported
        }
        guard endpoints.filter({ $0.hostname == plan.route.host && $0.port == plan.route.port }).count == 1
        else { throw TransportConnectError.unsupported }
        return plan.applicationProfile
      }
    }
    func poolSource(_ inputs: [TransportPoolCredential], identity: TransportApplicationIdentity) throws -> ConnectionMaterialSource {
      try foundation.gate.withLock {
        guard !closed else { throw TransportConnectError.closed }
        guard store != nil else { throw TransportConnectError.invalidMaterial }
        let source = try V4PoolMaterialSource(client: self, credentials: inputs, identity: identity, generation: 1)
        try foundation.registerNativeConnection(source)
        return ConnectionMaterialSource(owner: source)
      }
    }
    func installParentWinnerAuthority(_ configuration: ParentWinnerAuthorityConfiguration) throws {
      let backing = try foundation.gate.withLock { () throws -> V4PoolStoreBacking in
        guard !closed, let value = self.backing else { throw V4PoolFailure.configuration }
        return value
      }
      try backing.installParentWinner(configuration)
    }
    func relayHost(_ configuration: RelayHostConfiguration, identity: TransportApplicationIdentity) throws -> RelayHost {
      try foundation.gate.withLock {
        guard !closed, let credentials else { throw TransportConnectError.closed }
        return try RelayHost(environment: foundation, credentials: credentials, endpoints: endpoints, roots: roots,
          listenerTLS: listenerTLS, configuration: configuration, identity: identity.owner)
      }
    }
    func liveCredentialConfiguration() throws -> V4CredentialConfiguration {
      try foundation.gate.withLock {
        guard !closed, let credentials else { throw TransportConnectError.closed }
        return credentials
      }
    }
    func managedPoolSource(_ configuration: TransportManagedPoolSourceConfiguration,
      identity: TransportApplicationIdentity) throws -> ConnectionMaterialSource {
      try foundation.gate.withLock {
        guard !closed else { throw TransportConnectError.closed }
        guard store != nil else { throw TransportConnectError.invalidMaterial }
        return ConnectionMaterialSource(owner: try V4ManagedPoolMaterialSource(client: self, configuration: configuration, identity: identity))
      }
    }
    func liveSource(_ configuration: TransportLiveAuthoritySourceConfiguration,
      identity: TransportApplicationIdentity) throws -> ConnectionMaterialSource {
      try foundation.gate.withLock {
        guard !closed else { throw TransportConnectError.closed }
        return ConnectionMaterialSource(owner: try V4LiveMaterialSource(client: self, configuration: configuration, identity: identity))
      }
    }
    func registeredLiveSource(_ configuration: TransportRegisteredLiveAuthoritySourceConfiguration,
      identity: TransportApplicationIdentity) throws -> ConnectionMaterialSource {
      try foundation.gate.withLock {
        guard !closed else { throw TransportConnectError.closed }
        return ConnectionMaterialSource(owner: try V4RegisteredLiveMaterialSource(client: self, configuration: configuration, identity: identity))
      }
    }
    func poolServerSource(_ inputs: [TransportPoolCredential], identity: TransportApplicationIdentity,
      control: TransportServerAllowHTTPSConfiguration) async throws -> TransportPoolServerSource {
      guard (1...8).contains(inputs.count), (1...2000).contains(control.timeoutMilliseconds) else {
        throw TransportConnectError.invalidMaterial
      }
      let original = try foundation.gate.withLock { () throws -> V4PoolServerMaterialSource in
        guard !closed, store != nil, let credentials else { throw TransportConnectError.closed }
        try identity.owner.check(in: foundation)
        let source = try V4PoolServerMaterialSource(environment: foundation, identity: identity.owner)
        do {
          for value in inputs {
            let input = value.input
            guard input.source == .preauthorizedPool, input.localRole == .server, input.poolServerAllow == nil,
              (1...65_536).contains(input.artifact.count), (1...8192).contains(input.clientCertificate.count),
              (1...8192).contains(input.serverCertificate.count), (1...65_536).contains(input.activation.count),
              (1...9302).contains(input.grant.count), (1...8192).contains(input.relayCertificate.count),
              (0..<16).contains(input.candidateIndex), input.poolTunnels.count <= 16
            else { throw TransportConnectError.invalidMaterial }
            var bytes = input.artifact.count + input.clientCertificate.count + input.serverCertificate.count
              + input.activation.count + input.grant.count + input.relayCertificate.count
            for tunnel in input.poolTunnels {
              guard (1...9302).contains(tunnel.grant.count), (1...8192).contains(tunnel.relayCertificate.count)
              else { throw TransportConnectError.invalidMaterial }
              bytes += tunnel.grant.count + tunnel.relayCertificate.count
            }
            let storage = try foundation.materialSourceStorage(bytes: bytes, items: 1)
            let admission = try foundation.verifyDirectCredentials(configuration: credentials, input: input)
            do {
              let plan = try admission.directPoolPlan(in: foundation, identity: identity.owner)
              let endpoints = self.endpoints.filter { $0.hostname == plan.route.host && $0.port == plan.route.port }
              guard endpoints.count == 1, let endpoint = endpoints.first else { throw TransportConnectError.unsupported }
              try source.append(plan: plan, candidateIndex: input.candidateIndex, endpoint: endpoint,
                roots: roots, tls: listenerTLS, storage: storage)
            } catch { admission.close(); throw error }
          }
          return source
        } catch { source.close(); throw error }
      }
      do {
        try await original.start(control)
        try foundation.gate.withLock { guard !closed else { throw TransportConnectError.closed }; try Task.checkCancellation() }
        return TransportPoolServerSource(original)
      } catch { original.close(); _ = try? await original.waitCleanup(); throw error }
    }
    func liveServerSource(_ configuration: TransportLiveServerSourceConfiguration,
      identity: TransportApplicationIdentity) async throws -> TransportLiveServerSource {
      let credentials = try foundation.gate.withLock { () throws -> V4CredentialConfiguration in
        guard !closed, let value = self.credentials else { throw TransportConnectError.closed }
        return value
      }
      let original = try V4LiveServerMaterialSource(environment: foundation, credentials: credentials, endpoints: endpoints,
        roots: roots, tls: listenerTLS, identity: identity.owner, configuration: configuration)
      try await original.start()
      do {
        try foundation.gate.withLock {
          guard !closed else { throw TransportConnectError.closed }
          try Task.checkCancellation()
        }
      }
      catch { original.close(); _ = try? await original.waitCleanup(); throw error }
      return TransportLiveServerSource(original)
    }
    func material(_ input: TransportPoolCredential, identity: TransportApplicationIdentity) throws -> ConnectionMaterial {
      try foundation.gate.withLock {
        guard store != nil else { throw TransportConnectError.invalidMaterial }
        return try directMaterial(input.input, identity: identity)
      }
    }
    func directMaterial(_ input: V4CredentialInput, identity: TransportApplicationIdentity,
      live: (any V4LiveAuthorizationControl)? = nil) throws -> ConnectionMaterial {
      try foundation.gate.withLock {
        guard !closed, let credentials else { throw TransportConnectError.closed }
        if input.source == .preauthorizedPool {
          guard live == nil, store != nil else { throw TransportConnectError.invalidMaterial }
        } else { guard live != nil else { throw TransportConnectError.invalidMaterial } }
        let admission = try foundation.verifyDirectCredentials(configuration: credentials, input: input)
        do {
          let plan = try admission.directPoolPlan(in: foundation, identity: identity.owner)
          if plan.role == .server, admission.source == .preauthorizedPool, admission.pathKind == 1 {
            throw TransportConnectError.invalidMaterial
          }
          guard endpoints.filter({ $0.hostname == plan.route.host && $0.port == plan.route.port }).count == 1 else { throw TransportConnectError.unsupported }
          let serverAllow = try input.poolServerAllow.map {
            try V4PoolServerAllow(environment: foundation, plan: plan, configuration: credentials, input: $0)
          }
          return ConnectionMaterial(owner: V4DirectPoolMaterial(plan: plan, identity: identity.owner, liveControl: live, poolServerAllow: serverAllow))
        } catch { admission.close(); throw error }
      }
    }
    private func run(
      _ body: @escaping @Sendable () async throws -> any Session,
      connection: @escaping @Sendable () -> ConnectionAttemptFacts,
      cleanup: @escaping @Sendable () -> CleanupStatus
    ) async throws -> any Session {
      do {
        let operation = try foundation.gate.withLock {
          guard !closed else { throw TransportConnectError.closed }
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
          guard denied else { return session }
          let error: TransportConnectError = foundation.gate.withLock { closed }
            ? .closed : .canceled
          if let native = session as? V4NativeSession {
            native.connectionFactsOwner.publicationFailed()
            try? await native.close()
            let pending = UInt64(await native.retirementPendingCallbacks())
            let observed = cleanup().preserving(CleanupStatus(
              complete: pending == 0, pendingCallbacks: pending))
            let failure = ConnectError.capture(error,
              connection: native.connectionFactsOwner.snapshot(), cleanup: observed)
            throw V4ConnectFailureProjection(failure: failure, observeCleanup: {
              let remaining = UInt64(await native.retirementPendingCallbacks())
              return observed.preserving(cleanup()).preserving(CleanupStatus(
                complete: remaining == 0, pendingCallbacks: remaining))
            })
          }
          try await session.close()
          throw error
        } onCancel: {
          operation.close()
        }
      } catch let failure as V4ConnectFailureProjection {
        throw failure
      } catch let failure as ConnectError {
        // The operation already observed its original owners after its call
        // tail exited. A source fallback has no authority to reset those facts.
        throw failure
      } catch {
        throw v4FailureProjection(error, connection: connection(), cleanup: cleanup)
      }
    }
    func connect(source: ConnectionMaterialSource, requirements: ConnectionRequirements)
      async throws -> any Session {
      try await connect(source: source, requirements: requirements, notificationPlan: nil)
    }
    func connect(source: ConnectionMaterialSource, requirements: ConnectionRequirements,
      notificationPlan: V4ControllerNotificationPlan?, handoff: (any V4ControllerHandoffReservation)? = nil,
      serve: V4ServeAdmission? = nil, diagnosticAttempt: UInt64 = 1) async throws -> any Session
    {
      try await diagnosedConnection(attempt: diagnosticAttempt) { [self] in
        try await connectSource(source, requirements: requirements, notificationPlan: notificationPlan,
          handoff: handoff, serve: serve)
      }
    }
    private func diagnosedConnection(attempt: UInt64 = 1, _ body: @Sendable () async throws -> any Session) async throws -> any Session {
      let counters = foundation.root.diagnosticCounters
      counters.increment(.connectionAttempts)
      let diagnostic = foundation.diagnosticContext(.connection, attempt: attempt)
      diagnostic?.emit(.started)
      do {
        let session = try await body()
        if let facts = (session as? V4ConnectionFactsOwner)?.connectionFactsOwner {
          facts.observeDiagnostic(diagnostic, counters: counters)
        } else { diagnostic?.emit(.succeeded) }
        return session
      } catch {
        counters.increment(.connectionFailures)
        let failure = (error as? V4ConnectFailureProjection)?.failure ?? (error as? ConnectError)
          ?? ConnectError.capture(error, connection: .notStarted, cleanup: CleanupStatus(complete: true))
        if failure.code == .securityFailed { counters.increment(.identityRefusals) }
        if failure.connection.spendState == .unknown { counters.increment(.spendUnknown) }
        diagnostic?.emit(.failed, code: TransportDiagnosticCode(rawValue: failure.code.rawValue) ?? .other,
          retry: failure.retryDisposition == .retryable ? .retryable : .terminal)
        throw error
      }
    }
    private func connectSource(_ source: ConnectionMaterialSource, requirements: ConnectionRequirements,
      notificationPlan: V4ControllerNotificationPlan?, handoff: (any V4ControllerHandoffReservation)?,
      serve: V4ServeAdmission?) async throws -> any Session
    {
      do {
        try V4DirectEstablishment.requirements(requirements)
        if let original = source.owner as? any V4ConfiguredMaterialSourceOwner {
          try original.checkRequirements(requirements, in: foundation)
        }
      } catch let failure as V4ConnectFailureProjection {
        throw failure
      } catch {
        throw v4FailureProjection(error, connection: .notStarted,
          cleanup: { CleanupStatus(complete: true) })
      }
      let attempt = V4SourceConnectionObservation()
      return try await run({ [self] in
        let material: ConnectionMaterial
        do {
          if let live = source.owner as? V4LiveMaterialSource {
            material = try await live.acquire(requirements, cleanup: attempt.acquisition)
          } else {
            material = try await source.acquire(requirements)
          }
        } catch let failure as V4ConnectFailureProjection {
          throw failure
        } catch let failure as ConnectError {
          throw failure
        } catch {
          // Acquire has returned, but its own native HTTP driver/body may
          // still be retiring. A borrowed source's other work is unrelated.
          throw V4ConnectFailureProjection(failure: ConnectError.capture(error,
            connection: .notStarted, cleanup: attempt.cleanupStatus()),
            observeCleanup: { attempt.cleanupStatus() })
        }
        attempt.capture(material)
        serve?.transferMaterialCleanup(material)
        if Task.isCancelled {
          let facts = (material.owner as? V4ConnectionFactsOwner)?.connectionFactsOwner
          material.close()
          throw V4ConnectFailureProjection(failure: ConnectError.capture(TransportConnectError.canceled,
            connection: facts?.snapshot() ?? .notStarted, cleanup: attempt.cleanupStatus()),
            observeCleanup: { attempt.cleanupStatus() })
        }
        do {
          return try await connectOriginal(material, requirements: requirements,
            notificationPlan: notificationPlan, handoff: handoff, serve: serve)
        } catch let failure as V4ConnectFailureProjection {
          throw V4ConnectFailureProjection(failure: failure.failure, observeCleanup: {
            let cleanup = await failure.observeCleanup()
            return attempt.includingAcquisition(cleanup)
          })
        }
      }, connection: { attempt.connectionFacts() }, cleanup: { attempt.cleanupStatus() })
    }
    func connectMaterial(_ material: ConnectionMaterial, requirements: ConnectionRequirements)
      async throws -> any Session
    {
      try await diagnosedConnection { [self] in
        try await connectOwnedMaterial(material, requirements: requirements)
      }
    }
    private func connectOwnedMaterial(_ material: ConnectionMaterial, requirements: ConnectionRequirements)
      async throws -> any Session
    {
      do { try V4DirectEstablishment.requirements(requirements) }
      catch let failure as V4ConnectFailureProjection { throw failure }
      catch {
        let facts = (material.owner as? V4ConnectionFactsOwner)?.connectionFactsOwner
        throw v4FailureProjection(error, connection: facts?.snapshot() ?? .notStarted,
          cleanup: { material.cleanupStatus() })
      }
      return try await run({ [self] in
        try await connectOriginal(material, requirements: requirements)
      }, connection: {
        (material.owner as? V4ConnectionFactsOwner)?.connectionFactsOwner.snapshot() ?? .notStarted
      }, cleanup: { material.cleanupStatus() })
    }
    private func connectOriginal(
      _ material: ConnectionMaterial, requirements: ConnectionRequirements,
      notificationPlan: V4ControllerNotificationPlan? = nil, handoff: (any V4ControllerHandoffReservation)? = nil,
      serve: V4ServeAdmission? = nil
    ) async throws -> any Session {
      guard let original = material.owner as? V4DirectPoolMaterial,
        original.plan.environment === foundation
      else {
        throw v4FailureProjection(TransportConnectError.invalidMaterial,
          connection: (material.owner as? V4ConnectionFactsOwner)?.connectionFactsOwner.snapshot() ?? .notStarted,
          cleanup: { material.cleanupStatus() })
      }
      do {
        // Claim before every material dependent preflight. A losing concurrent
        // call must not finish facts or close the original carrier.
        do {
          try original.claim(in: foundation)
        } catch {
          throw v4FailureProjection(error,
            connection: original.connectionFactsOwner.snapshot(),
            cleanup: { original.cleanupStatus() })
        }
        serve?.transferMaterialCleanup(material)
        if serve != nil, original.plan.role != .server { throw ServeError(.configurationCapacity) }
        try serve?.startDeadline()
        let route = original.plan.route
        if !route.isDialer && route.requiresTLS && listenerTLS == nil {
          throw TransportConnectError.unsupported
        }
        let matches = endpoints.filter { $0.hostname == route.host && $0.port == route.port }
        guard matches.count == 1 else { throw TransportConnectError.unsupported }
        let store = try foundation.gate.withLock {
          guard !closed else { throw TransportConnectError.closed }
          if original.plan.credential.source == .preauthorizedPool && self.store == nil {
            throw TransportConnectError.invalidMaterial
          }
          return self.store
        }
        return try await V4DirectEstablishment.connect(
          material: original, address: matches[0].numericAddress,
          roots: roots, listenerTLS: listenerTLS, store: store, requirements: requirements,
          notificationPlan: notificationPlan, handoff: handoff, serve: serve, claimed: true)
      } catch let failure as V4ConnectFailureProjection {
        // Establishment owns cleanup after a successful claim. In particular,
        // a second concurrent caller reaches this branch without ownership.
        throw failure
      } catch {
        // Preflight after claim is still this attempt's responsibility.
        original.finish(success: false)
        throw v4FailureProjection(error,
          connection: original.connectionFactsOwner.snapshot(),
          cleanup: { original.cleanupStatus() })
      }
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
        guard !closed else { throw TransportConnectError.closed }
        guard let trustedTime, let provider else { throw TransportConnectError.unsupported }
        try provider.check()
        let tail = try provider.executionTail()
        defer { tail.release() }
        try Self.installTime(trustedTime, foundation: foundation)
      }
    }
    func refreshNamespace(authority: String, trust: Data? = nil, head: Data, state: Data) throws {
      try foundation.gate.withLock {
        guard !closed else { throw TransportConnectError.closed }
        guard let namespace = namespaces.first(where: { $0.authority == authority }) else {
          throw TransportConnectError.unsupported
        }
        try namespace.refresh(trust: trust, head: head, state: state)
      }
    }
  }

  // This operation-local observation never treats the borrowed source's open
  // generation, background refill, or another Acquire as connection cleanup.
  private final class V4SourceConnectionObservation: @unchecked Sendable {
    let acquisition = V4ControlHTTPCallCleanup()
    private let gate = NSLock()
    private var material: ConnectionMaterial?
    func capture(_ material: ConnectionMaterial) { gate.withLock { self.material = material } }
    func connectionFacts() -> ConnectionAttemptFacts {
      let original = gate.withLock { material }
      return (original?.owner as? V4ConnectionFactsOwner)?.connectionFactsOwner.snapshot() ?? .notStarted
    }
    func cleanupStatus() -> CleanupStatus {
      let original = gate.withLock { material }
      return includingAcquisition(original?.cleanupStatus() ?? CleanupStatus(complete: true))
    }
    func includingAcquisition(_ cleanup: CleanupStatus) -> CleanupStatus {
      let acquired = acquisition.cleanupStatus()
      let (pending, overflow) = cleanup.pendingCallbacks.addingReportingOverflow(acquired.pendingCallbacks)
      return CleanupStatus(complete: cleanup.complete && acquired.complete,
        cleanupIncomplete: cleanup.cleanupIncomplete || acquired.cleanupIncomplete,
        pendingCallbacks: overflow ? .max : pending)
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
          if Task.isCancelled { throw TransportConnectError.canceled }
          return try await body()
        }
      }
    }
    func value() async throws -> any Session {
      guard let current = gate.withLock({ task }) else { throw TransportConnectError.closed }
      defer { gate.withLock { task = nil } }
      do { return try await current.value }
      catch let failure as V4ConnectFailureProjection {
        // Task completion has already sealed storage and retired its actual
        // call tail. The delivered failure observes only this attempt's owners.
        throw await failure.delivered()
      }
    }
    func close() {
      let current = gate.withLock { task }
      current?.cancel()
    }
  }
#endif
