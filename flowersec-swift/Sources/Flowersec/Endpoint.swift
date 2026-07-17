import Foundation

public struct EndpointOptions: Sendable {
  public var origin: String?
  public var connectTimeout: Duration
  public var handshakeTimeout: Duration
  public var handshakeClockSkew: Duration
  public var transportSecurityPolicy: TransportSecurityPolicy
  public var onTransportSecurityDiagnostic: (@Sendable (TransportSecurityDiagnostic) -> Void)?
  public var onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)?
  public var serverFeatures: UInt32
  public var outboundRecordChunkBytes: Int
  public var maxOutboundBufferedBytes: Int
  public var yamuxLimits: YamuxLimits
  public var handshakeCache: EndpointHandshakeCache

  public init(
    origin: String? = nil,
    connectTimeout: Duration = FlowersecSDKDefaults.Transport.connectTimeout,
    handshakeTimeout: Duration = FlowersecSDKDefaults.Transport.handshakeTimeout,
    handshakeClockSkew: Duration = FlowersecSDKDefaults.Transport.handshakeClockSkew,
    transportSecurityPolicy: TransportSecurityPolicy = .requireTLS,
    onTransportSecurityDiagnostic: (@Sendable (TransportSecurityDiagnostic) -> Void)? = nil,
    onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)? = nil,
    serverFeatures: UInt32 = 0,
    outboundRecordChunkBytes: Int = FlowersecSDKDefaults.E2EE.outboundRecordChunkBytes,
    maxOutboundBufferedBytes: Int = FlowersecSDKDefaults.E2EE.maxOutboundBufferedBytes,
    yamuxLimits: YamuxLimits = YamuxLimits(),
    handshakeCache: EndpointHandshakeCache = EndpointHandshakeCache()
  ) {
    self.origin = origin
    self.connectTimeout = connectTimeout
    self.handshakeTimeout = handshakeTimeout
    self.handshakeClockSkew = handshakeClockSkew
    self.transportSecurityPolicy = transportSecurityPolicy
    self.onTransportSecurityDiagnostic = onTransportSecurityDiagnostic
    self.onDiagnosticEvent = onDiagnosticEvent
    self.serverFeatures = serverFeatures
    self.outboundRecordChunkBytes = outboundRecordChunkBytes
    self.maxOutboundBufferedBytes = maxOutboundBufferedBytes
    self.yamuxLimits = yamuxLimits
    self.handshakeCache = handshakeCache
  }
}

public struct DirectEndpointCredential: Sendable {
  public var channelID: String
  public var suite: Suite
  public var psk: Data
  public var initExpiresAtUnixS: Int64
  /// Commits an authenticated credential before Yamux starts. The backing transaction must be
  /// idempotent, cancellation-safe, and bounded by its own deadline.
  public var commitAuthenticated: (@Sendable () async throws -> Void)?

  public init(
    channelID: String,
    suite: Suite,
    psk: Data,
    initExpiresAtUnixS: Int64,
    commitAuthenticated: (@Sendable () async throws -> Void)? = nil
  ) {
    self.channelID = channelID
    self.suite = suite
    self.psk = psk
    self.initExpiresAtUnixS = initExpiresAtUnixS
    self.commitAuthenticated = commitAuthenticated
  }
}

/// Structurally validated fields from an unauthenticated peer INIT. The peer is authenticated only
/// after the subsequent PSK handshake succeeds.
public struct DirectHandshakeInit: Equatable, Sendable {
  public var channelID: String
  public var version: UInt8
  public var suite: Suite
  public var clientFeatures: UInt32

  public init(channelID: String, version: UInt8, suite: Suite, clientFeatures: UInt32) {
    self.channelID = channelID
    self.version = version
    self.suite = suite
    self.clientFeatures = clientFeatures
  }
}

/// Resolves credentials without consuming them. The resolver must cooperate with task cancellation.
public typealias DirectCredentialResolver =
  @Sendable (DirectHandshakeInit) async throws -> DirectEndpointCredential

public struct EndpointStream: Sendable {
  public var kind: String
  public var stream: any FlowersecByteStream

  public init(kind: String, stream: any FlowersecByteStream) {
    self.kind = kind
    self.stream = stream
  }
}

public final class EndpointSession: @unchecked Sendable {
  public let path: FlowersecPath
  public let endpointInstanceID: String?
  private let secure: FlowersecSecureChannel
  private let yamux: FlowersecYamuxClient

  init(
    path: FlowersecPath,
    endpointInstanceID: String?,
    secure: FlowersecSecureChannel,
    yamux: FlowersecYamuxClient
  ) {
    self.path = path
    self.endpointInstanceID = endpointInstanceID
    self.secure = secure
    self.yamux = yamux
  }

  public func openStream(kind: String) async throws -> any FlowersecByteStream {
    let value = kind.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !value.isEmpty else {
      throw FlowersecError.missingStreamKind(path: path)
    }
    let stream = try await yamux.openStream()
    do {
      try await FlowersecJSONFrame.write(
        try streamHelloData(kind: value),
        to: stream
      )
      return stream
    } catch {
      await stream.close()
      throw error
    }
  }

  public func acceptStream() async throws -> EndpointStream {
    let accepted = try await acceptTypedStream()
    return EndpointStream(kind: accepted.kind, stream: accepted.stream)
  }

  public func serveRPC(
    router: RPCRouter,
    options: RPCServerOptions = RPCServerOptions()
  ) async throws {
    while true {
      let accepted = try await acceptTypedStream()
      guard accepted.kind == "rpc" else {
        await accepted.stream.close()
        continue
      }
      let server = try RPCServer(
        stream: accepted.stream,
        router: router,
        options: options,
        path: path
      )
      try await server.serve()
      return
    }
  }

  public func probeLiveness(
    timeout: Duration = FlowersecSDKDefaults.Transport.handshakeTimeout
  ) async throws -> Duration {
    try await yamux.probeLiveness(timeout: timeout)
  }

  public func rekey() async throws {
    do {
      try await secure.rekey()
    } catch is CancellationError {
      throw CancellationError()
    } catch {
      throw FlowersecError(
        path: path,
        stage: .secure,
        code: .rekeyFailed,
        message: "Endpoint secure channel rekey failed: \(error.localizedDescription)"
      )
    }
  }

  public func close() async {
    await yamux.close()
  }

  public func terminationError() async -> FlowersecError? {
    guard let error = await yamux.terminated() else { return nil }
    if let error = error as? FlowersecError {
      return error.withPath(path)
    }
    return FlowersecError(
      path: path,
      stage: .yamux,
      code: .notConnected,
      message: "The endpoint session terminated: \(error.localizedDescription)"
    )
  }

  fileprivate func acceptTypedStream() async throws -> (kind: String, stream: FlowersecYamuxStream)
  {
    let stream = try await yamux.acceptStream()
    do {
      let data = try await FlowersecJSONFrame.read(from: stream)
      guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
        let version = object["v"] as? NSNumber,
        version.uint32Value == 1,
        let kind = object["kind"] as? String,
        !kind.isEmpty
      else {
        throw FlowersecError.invalidRPC("StreamHello is invalid.", path: path)
      }
      return (kind, stream)
    } catch {
      await stream.close()
      throw error
    }
  }
}

public enum Endpoint {
  public static func acceptDirect(
    transport: any FlowersecBinaryTransport,
    credential: DirectEndpointCredential,
    secureTransport: Bool = true,
    options: EndpointOptions = EndpointOptions()
  ) async throws -> EndpointSession {
    do {
      try validate(options: options, path: .direct)
      try await enforceAcceptedTransport(secure: secureTransport, options: options)
    } catch {
      startTransportClose(transport)
      throw error
    }
    return try await establish(
      transport: transport,
      credential: credential,
      path: .direct,
      endpointInstanceID: nil,
      idleTimeout: nil,
      options: options
    )
  }

  public static func acceptDirectResolved(
    transport: any FlowersecBinaryTransport,
    resolver: @escaping DirectCredentialResolver,
    secureTransport: Bool = true,
    options: EndpointOptions = EndpointOptions()
  ) async throws -> EndpointSession {
    do {
      try validate(options: options, path: .direct)
      try await enforceAcceptedTransport(secure: secureTransport, options: options)
    } catch {
      startTransportClose(transport)
      throw error
    }
    return try await withHandshakeTimeout(
      transport: transport,
      path: .direct,
      timeout: options.handshakeTimeout
    ) { deadline in
      let frame = try await transport.readBinary()
      let payload = try FlowersecHandshakeFrame.decode(
        frame,
        expectedType: FlowersecWire.handshakeTypeInit
      )
      let message = try JSONDecoder().decode(E2EEInitMessage.self, from: payload)
      guard message.version == FlowersecWire.protocolVersion,
        message.role == 1,
        let suite = Suite(rawValue: message.suite)
      else {
        throw FlowersecError.invalidHandshake("Direct handshake init is invalid.")
      }
      let channelID = message.channelID.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !channelID.isEmpty else {
        throw FlowersecError(
          path: .direct,
          stage: .validate,
          code: .missingChannelID,
          message: "Direct handshake init is missing channel_id."
        )
      }
      guard channelID == message.channelID, channelID.utf8.count <= 256 else {
        throw FlowersecError(
          path: .direct,
          stage: .validate,
          code: .invalidInput,
          message: "Direct handshake channel_id is not canonical."
        )
      }
      try checkHandshakeBoundary(path: .direct, deadline: deadline)
      let initInfo = DirectHandshakeInit(
        channelID: channelID,
        version: message.version,
        suite: suite,
        clientFeatures: message.clientFeatures
      )
      let credential: DirectEndpointCredential
      do {
        credential = try await resolver(initInfo)
      } catch {
        if let interruption = handshakeInterruption(path: .direct, error: error) {
          throw interruption
        }
        throw FlowersecError(
          path: .direct,
          stage: .validate,
          code: .resolveFailed,
          message: "Direct endpoint credential resolution failed: \(error.localizedDescription)"
        )
      }
      try checkHandshakeBoundary(path: .direct, deadline: deadline)
      guard credential.channelID == channelID, credential.suite == suite else {
        throw FlowersecError.invalidHandshake(
          "Resolved direct credentials do not match the init.")
      }
      return try await establishWithoutTimeout(
        transport: PrefetchedBinaryTransport(first: frame, inner: transport),
        credential: credential,
        path: .direct,
        endpointInstanceID: nil,
        idleTimeout: nil,
        options: options,
        deadline: deadline
      )
    }
  }

  public static func connectTunnel(
    grant: ChannelInitGrant,
    options: EndpointOptions = EndpointOptions()
  ) async throws -> EndpointSession {
    let validatedGrant = try validateTunnelGrant(grant)
    try validate(options: options, path: .tunnel)
    do {
      try checkConnectCancellation(path: .tunnel)
      try await FlowersecTransportSecurity.enforce(
        url: grant.tunnelURL,
        path: .tunnel,
        options: connectOptions(options)
      )
      try checkConnectCancellation(path: .tunnel)
    } catch {
      if Task.isCancelled || error is CancellationError {
        throw connectCanceled(path: .tunnel)
      }
      throw error
    }
    let transport = FlowersecWebSocketBinaryTransport(
      url: grant.tunnelURL,
      origin: options.origin,
      connectTimeout: options.connectTimeout,
      path: .tunnel,
      onDiagnosticEvent: options.onDiagnosticEvent
    )
    do {
      try checkConnectCancellation(path: .tunnel)
    } catch {
      startTransportClose(transport)
      throw error
    }
    try await resumeTunnelTransport(transport)
    let endpointInstanceID = try Data.secureRandom(count: 24).base64URLEncodedString()
    try await writeTunnelAttach(
      transport: transport,
      text: TunnelAttach(
        v: 1,
        channelID: validatedGrant.channelID,
        role: 2,
        token: validatedGrant.token,
        endpointInstanceID: endpointInstanceID,
        caps: nil
      ).encoded()
    )
    return try await establish(
      transport: transport,
      credential: DirectEndpointCredential(
        channelID: validatedGrant.channelID,
        suite: grant.defaultSuite,
        psk: grant.psk,
        initExpiresAtUnixS: grant.channelInitExpiresAtUnixS
      ),
      path: .tunnel,
      endpointInstanceID: endpointInstanceID,
      idleTimeout: .seconds(max(0, grant.idleTimeoutSeconds)),
      options: options
    )
  }

  private static func establish(
    transport: any FlowersecBinaryTransport,
    credential: DirectEndpointCredential,
    path: FlowersecPath,
    endpointInstanceID: String?,
    idleTimeout: Duration?,
    options: EndpointOptions
  ) async throws -> EndpointSession {
    try await withHandshakeTimeout(
      transport: transport, path: path, timeout: options.handshakeTimeout
    ) { deadline in
      try await establishWithoutTimeout(
        transport: transport,
        credential: credential,
        path: path,
        endpointInstanceID: endpointInstanceID,
        idleTimeout: idleTimeout,
        options: options,
        deadline: deadline
      )
    }
  }

  private static func establishWithoutTimeout(
    transport: any FlowersecBinaryTransport,
    credential: DirectEndpointCredential,
    path: FlowersecPath,
    endpointInstanceID: String?,
    idleTimeout: Duration?,
    options: EndpointOptions,
    deadline: ContinuousClock.Instant
  ) async throws -> EndpointSession {
    var psk = Data(credential.psk)
    defer { psk.resetBytes(in: 0..<psk.count) }
    let secure = try await FlowersecHandshake.runServerHandshake(
      transport: transport,
      cache: options.handshakeCache,
      options: EndpointServerHandshakeOptions(
        channelID: credential.channelID,
        suite: credential.suite,
        psk: psk,
        initExpiresAtUnixS: credential.initExpiresAtUnixS,
        clockSkew: options.handshakeClockSkew,
        serverFeatures: options.serverFeatures,
        outboundRecordChunkBytes: options.outboundRecordChunkBytes,
        maxOutboundBufferedBytes: options.maxOutboundBufferedBytes,
        path: path,
        onDiagnosticEvent: options.onDiagnosticEvent
      )
    )
    do {
      try checkHandshakeBoundary(path: path, deadline: deadline)
    } catch {
      startSecureClose(secure)
      throw error
    }
    do {
      try await credential.commitAuthenticated?()
    } catch is CancellationError {
      startSecureClose(secure)
      throw CancellationError()
    } catch {
      startSecureClose(secure)
      if let interruption = handshakeInterruption(path: path, error: error) {
        throw interruption
      }
      throw FlowersecError(
        path: path,
        stage: .handshake,
        code: .credentialCommitFailed,
        message: "Endpoint credential commit failed: \(error.localizedDescription)"
      )
    }
    do {
      try checkHandshakeBoundary(path: path, deadline: deadline)
    } catch {
      startSecureClose(secure)
      throw error
    }
    let liveness: (interval: Duration, timeout: Duration)?
    if path == .tunnel, let idleTimeout, idleTimeout > .zero {
      let interval = max(.milliseconds(500), idleTimeout / 2)
      liveness = (interval, min(.seconds(10), interval))
    } else {
      liveness = nil
    }
    let yamux = FlowersecYamuxClient(
      channel: secure,
      limits: options.yamuxLimits,
      automaticLiveness: liveness,
      path: path,
      client: false,
      onDiagnosticEvent: options.onDiagnosticEvent
    )
    await yamux.start()
    do {
      try checkHandshakeBoundary(path: path, deadline: deadline)
    } catch {
      startYamuxClose(yamux)
      throw error
    }
    return EndpointSession(
      path: path,
      endpointInstanceID: endpointInstanceID,
      secure: secure,
      yamux: yamux
    )
  }

  private static func validate(options: EndpointOptions, path: FlowersecPath) throws {
    guard options.connectTimeout > .zero,
      options.handshakeTimeout > .zero,
      options.handshakeClockSkew >= .zero,
      options.outboundRecordChunkBytes > 0,
      options.maxOutboundBufferedBytes > 0
    else {
      throw FlowersecError(
        path: path,
        stage: .validate,
        code: .invalidOption,
        message: "Endpoint options are invalid."
      )
    }
    try options.yamuxLimits.validate()
  }

  static func validateTunnelGrant(_ grant: ChannelInitGrant) throws -> (
    channelID: String,
    token: String
  ) {
    guard grant.role == 2 else {
      throw FlowersecError(
        path: .tunnel,
        stage: .validate,
        code: .roleMismatch,
        message: "Tunnel endpoint grants must use the server role."
      )
    }
    let channelID = grant.channelID.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !channelID.isEmpty else {
      throw FlowersecError(
        path: .tunnel,
        stage: .validate,
        code: .missingChannelID,
        message: "Tunnel endpoint grant is missing channel_id."
      )
    }
    guard channelID.utf8.count <= 256 else {
      throw FlowersecError(
        path: .tunnel,
        stage: .validate,
        code: .invalidInput,
        message: "Tunnel endpoint channel_id is too long."
      )
    }
    let token = grant.token.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !token.isEmpty else {
      throw FlowersecError(
        path: .tunnel,
        stage: .validate,
        code: .missingToken,
        message: "Tunnel endpoint grant is missing its attach token."
      )
    }
    guard grant.channelInitExpiresAtUnixS > 0 else {
      throw FlowersecError(
        path: .tunnel,
        stage: .validate,
        code: .missingInitExp,
        message: "Tunnel endpoint grant is missing its init expiry."
      )
    }
    guard !grant.allowedSuites.isEmpty,
      grant.allowedSuites.contains(grant.defaultSuite)
    else {
      throw FlowersecError(
        path: .tunnel,
        stage: .validate,
        code: .invalidSuite,
        message: "Tunnel endpoint grant has invalid cipher suites."
      )
    }
    guard grant.psk.count == 32 else {
      throw FlowersecError(
        path: .tunnel,
        stage: .validate,
        code: .invalidPSK,
        message: "Tunnel endpoint PSK must be 32 bytes."
      )
    }
    return (channelID, token)
  }

  private static func enforceAcceptedTransport(
    secure: Bool,
    options: EndpointOptions
  ) async throws {
    let url = URL(string: secure ? "wss://127.0.0.1/" : "ws://127.0.0.1/")!
    try await FlowersecTransportSecurity.enforce(
      url: url,
      path: .direct,
      options: connectOptions(options)
    )
  }

  private static func connectOptions(_ options: EndpointOptions) -> ConnectOptions {
    ConnectOptions(
      origin: options.origin,
      connectTimeout: options.connectTimeout,
      handshakeTimeout: options.handshakeTimeout,
      transportSecurityPolicy: options.transportSecurityPolicy,
      onTransportSecurityDiagnostic: options.onTransportSecurityDiagnostic,
      onDiagnosticEvent: options.onDiagnosticEvent,
      outboundRecordChunkBytes: options.outboundRecordChunkBytes,
      maxOutboundBufferedBytes: options.maxOutboundBufferedBytes,
      yamuxLimits: options.yamuxLimits,
      liveness: .disabled,
      scopeResolvers: [:]
    )
  }

  static func withHandshakeTimeout<T: Sendable>(
    transport: any FlowersecBinaryTransport,
    path: FlowersecPath,
    timeout: Duration,
    beforeTaskRegistration: (@Sendable () -> Void)? = nil,
    operation: @escaping @Sendable (ContinuousClock.Instant) async throws -> T
  ) async throws -> T {
    if Task.isCancelled {
      startTransportClose(transport)
      throw handshakeCanceled(path: path)
    }
    let deadline = ContinuousClock.now + timeout
    let race = AsyncStream<EndpointHandshakeRace<T>>.makeStream(
      bufferingPolicy: .bufferingOldest(1)
    )
    let registration = EndpointHandshakeTaskRegistration()
    let event = await withTaskCancellationHandler {
      let operationStart = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingOldest(1))
      let operationTask = Task<Void, Never> {
        var iterator = operationStart.stream.makeAsyncIterator()
        guard await iterator.next() != nil else { return }
        do {
          try Task.checkCancellation()
          let value = try await operation(deadline)
          let finishedAt = ContinuousClock.now
          if Task.isCancelled {
            throw handshakeCanceled(path: path)
          }
          if finishedAt >= deadline {
            throw handshakeTimedOut(path: path)
          }
          race.continuation.yield(.completed(value, finishedAt: finishedAt))
        } catch {
          race.continuation.yield(.failed(error, finishedAt: ContinuousClock.now))
        }
      }
      beforeTaskRegistration?()
      if registration.register(operationTask) {
        operationStart.continuation.yield(())
      }
      operationStart.continuation.finish()

      let timeoutStart = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingOldest(1))
      let timeoutTask = Task<Void, Never> {
        var iterator = timeoutStart.stream.makeAsyncIterator()
        guard await iterator.next() != nil else { return }
        do {
          try Task.checkCancellation()
          let remaining = deadline - ContinuousClock.now
          if remaining > .zero {
            try await Task.sleep(for: remaining)
          }
          race.continuation.yield(.timedOut)
        } catch is CancellationError {
          return
        } catch {
          race.continuation.yield(.failed(error, finishedAt: ContinuousClock.now))
        }
      }
      if registration.register(timeoutTask) {
        timeoutStart.continuation.yield(())
      }
      timeoutStart.continuation.finish()

      var iterator = race.stream.makeAsyncIterator()
      return await iterator.next()
    } onCancel: {
      registration.cancelAll()
      startTransportClose(transport)
      race.continuation.yield(.canceled)
    }
    race.continuation.finish()
    registration.cancelAll()

    return try resolveHandshakeRaceEvent(
      event,
      transport: transport,
      path: path,
      deadline: deadline
    )
  }

  static func resolveHandshakeRaceEvent<T: Sendable>(
    _ event: EndpointHandshakeRace<T>?,
    transport: any FlowersecBinaryTransport,
    path: FlowersecPath,
    deadline: ContinuousClock.Instant
  ) throws -> T {
    guard let event else {
      startTransportClose(transport)
      if let interruption = handshakeBoundaryInterruption(path: path, deadline: deadline) {
        throw interruption
      }
      throw FlowersecError.invalidHandshake(
        "Endpoint handshake ended without a result.",
        path: path
      )
    }
    if Task.isCancelled {
      startTransportClose(transport)
      throw handshakeCanceled(path: path)
    }
    switch event {
    case .completed(let value, let finishedAt):
      guard finishedAt < deadline else {
        startTransportClose(transport)
        throw handshakeTimedOut(path: path)
      }
      return value
    case .failed(let error, let finishedAt):
      startTransportClose(transport)
      if finishedAt >= deadline {
        throw handshakeTimedOut(path: path)
      }
      if let interruption = handshakeInterruption(path: path, error: error) {
        throw interruption
      }
      throw error
    case .timedOut:
      startTransportClose(transport)
      throw handshakeTimedOut(path: path)
    case .canceled:
      startTransportClose(transport)
      throw handshakeCanceled(path: path)
    }
  }

  private static func checkHandshakeBoundary(
    path: FlowersecPath,
    deadline: ContinuousClock.Instant
  ) throws {
    if let interruption = handshakeBoundaryInterruption(path: path, deadline: deadline) {
      throw interruption
    }
  }

  static func writeTunnelAttach(
    transport: any FlowersecTunnelAttachTransport,
    text: String
  ) async throws {
    do {
      try checkConnectCancellation(path: .tunnel)
      try await withTaskCancellationHandler {
        try checkConnectCancellation(path: .tunnel)
        try await transport.writeText(text)
        try checkConnectCancellation(path: .tunnel)
      } onCancel: {
        startTransportClose(transport)
      }
    } catch {
      startTransportClose(transport)
      if Task.isCancelled || error is CancellationError {
        throw connectCanceled(path: .tunnel)
      }
      throw error
    }
  }

  static func resumeTunnelTransport(
    _ transport: FlowersecWebSocketBinaryTransport
  ) async throws {
    do {
      try await transport.resume()
    } catch {
      startTransportClose(transport)
      if Task.isCancelled || error is CancellationError {
        throw connectCanceled(path: .tunnel)
      }
      throw error
    }
  }

  private static func checkConnectCancellation(path: FlowersecPath) throws {
    if Task.isCancelled {
      throw connectCanceled(path: path)
    }
  }

  private static func handshakeBoundaryInterruption(
    path: FlowersecPath,
    deadline: ContinuousClock.Instant
  ) -> FlowersecError? {
    // Caller cancellation wins when it is already observable at the completion boundary.
    if Task.isCancelled {
      return handshakeCanceled(path: path)
    }
    if ContinuousClock.now >= deadline {
      return handshakeTimedOut(path: path)
    }
    return nil
  }

  private static func startTransportClose(_ transport: any FlowersecBinaryTransport) {
    Task { await transport.close() }
  }

  private static func startSecureClose(_ secure: FlowersecSecureChannel) {
    Task { await secure.close() }
  }

  private static func startYamuxClose(_ yamux: FlowersecYamuxClient) {
    Task { await yamux.close() }
  }

  private static func handshakeInterruption(
    path: FlowersecPath,
    error: any Error
  ) -> FlowersecError? {
    if error is CancellationError {
      return handshakeCanceled(path: path)
    }
    guard let flowersecError = error as? FlowersecError else { return nil }
    switch flowersecError.code {
    case .timeout:
      return handshakeTimedOut(path: path)
    case .canceled:
      return handshakeCanceled(path: path)
    default:
      return nil
    }
  }

  private static func handshakeTimedOut(path: FlowersecPath) -> FlowersecError {
    FlowersecError(
      path: path,
      stage: .handshake,
      code: .timeout,
      message: "Endpoint handshake timed out."
    )
  }

  private static func handshakeCanceled(path: FlowersecPath) -> FlowersecError {
    FlowersecError(
      path: path,
      stage: .handshake,
      code: .canceled,
      message: "Endpoint handshake was canceled."
    )
  }

  private static func connectCanceled(path: FlowersecPath) -> FlowersecError {
    FlowersecError(
      path: path,
      stage: .connect,
      code: .canceled,
      message: "Endpoint connection was canceled."
    )
  }
}

enum EndpointHandshakeRace<T: Sendable>: @unchecked Sendable {
  case completed(T, finishedAt: ContinuousClock.Instant)
  case failed(any Error, finishedAt: ContinuousClock.Instant)
  case timedOut
  case canceled
}

private final class EndpointHandshakeTaskRegistration: @unchecked Sendable {
  private let lock = NSLock()
  private var tasks: [Task<Void, Never>] = []
  private var canceled = false

  func register(_ task: Task<Void, Never>) -> Bool {
    lock.lock()
    guard !canceled else {
      lock.unlock()
      task.cancel()
      return false
    }
    tasks.append(task)
    lock.unlock()
    return true
  }

  func cancelAll() {
    lock.lock()
    canceled = true
    let registered = tasks
    tasks.removeAll()
    lock.unlock()
    for task in registered { task.cancel() }
  }
}

protocol FlowersecTunnelAttachTransport: FlowersecBinaryTransport {
  func writeText(_ text: String) async throws
}

extension FlowersecWebSocketBinaryTransport: FlowersecTunnelAttachTransport {}

private actor PrefetchedBinaryTransport: FlowersecBinaryTransport {
  private var first: Data?
  private let inner: any FlowersecBinaryTransport

  init(first: Data, inner: any FlowersecBinaryTransport) {
    self.first = first
    self.inner = inner
  }

  func writeBinary(_ data: Data) async throws {
    try await inner.writeBinary(data)
  }

  func readBinary() async throws -> Data {
    if let first {
      self.first = nil
      return first
    }
    return try await inner.readBinary()
  }

  func close() async {
    await inner.close()
  }
}

private func streamHelloData(kind: String) throws -> Data {
  try JSONSerialization.data(
    withJSONObject: ["kind": kind, "v": NSNumber(value: 1)],
    options: [.sortedKeys]
  )
}
