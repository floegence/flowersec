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

  fileprivate init(
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
      throw FlowersecError(
        path: path,
        stage: .validate,
        code: .invalidInput,
        message: "Stream kind is empty."
      )
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
    try validate(options: options, path: .direct)
    try await enforceAcceptedTransport(secure: secureTransport, options: options)
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
    try validate(options: options, path: .direct)
    try await enforceAcceptedTransport(secure: secureTransport, options: options)
    return try await withHandshakeTimeout(transport: transport, timeout: options.handshakeTimeout) {
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
      let initInfo = DirectHandshakeInit(
        channelID: message.channelID,
        version: message.version,
        suite: suite,
        clientFeatures: message.clientFeatures
      )
      let credential: DirectEndpointCredential
      do {
        credential = try await resolver(initInfo)
      } catch {
        throw FlowersecError(
          path: .direct,
          stage: .validate,
          code: .resolveFailed,
          message: "Direct endpoint credential resolution failed: \(error.localizedDescription)"
        )
      }
      guard credential.channelID == message.channelID, credential.suite == suite else {
        throw FlowersecError.invalidHandshake("Resolved direct credentials do not match the init.")
      }
      return try await establishWithoutTimeout(
        transport: PrefetchedBinaryTransport(first: frame, inner: transport),
        credential: credential,
        path: .direct,
        endpointInstanceID: nil,
        idleTimeout: nil,
        options: options
      )
    }
  }

  public static func connectTunnel(
    grant: ChannelInitGrant,
    options: EndpointOptions = EndpointOptions()
  ) async throws -> EndpointSession {
    guard grant.role == 2 else {
      throw FlowersecError(
        path: .tunnel,
        stage: .validate,
        code: .invalidInput,
        message: "Tunnel endpoint grants must use the server role."
      )
    }
    guard grant.allowedSuites.contains(grant.defaultSuite),
      !grant.token.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    else {
      throw FlowersecError(
        path: .tunnel,
        stage: .validate,
        code: .invalidSuite,
        message: "Tunnel endpoint grant is invalid."
      )
    }
    try validate(options: options, path: .tunnel)
    try await FlowersecTransportSecurity.enforce(
      url: grant.tunnelURL,
      path: .tunnel,
      options: connectOptions(options)
    )
    let transport = FlowersecWebSocketBinaryTransport(
      url: grant.tunnelURL,
      origin: options.origin,
      connectTimeout: options.connectTimeout,
      path: .tunnel,
      onDiagnosticEvent: options.onDiagnosticEvent
    )
    await transport.resume()
    let endpointInstanceID = try Data.secureRandom(count: 24).base64URLEncodedString()
    do {
      try await transport.writeText(
        TunnelAttach(
          v: 1,
          channelID: grant.channelID,
          role: 2,
          token: grant.token,
          endpointInstanceID: endpointInstanceID,
          caps: nil
        ).encoded()
      )
      return try await establish(
        transport: transport,
        credential: DirectEndpointCredential(
          channelID: grant.channelID,
          suite: grant.defaultSuite,
          psk: grant.psk,
          initExpiresAtUnixS: grant.channelInitExpiresAtUnixS
        ),
        path: .tunnel,
        endpointInstanceID: endpointInstanceID,
        idleTimeout: .seconds(max(0, grant.idleTimeoutSeconds)),
        options: options
      )
    } catch {
      await transport.close()
      throw error
    }
  }

  private static func establish(
    transport: any FlowersecBinaryTransport,
    credential: DirectEndpointCredential,
    path: FlowersecPath,
    endpointInstanceID: String?,
    idleTimeout: Duration?,
    options: EndpointOptions
  ) async throws -> EndpointSession {
    try await withHandshakeTimeout(transport: transport, timeout: options.handshakeTimeout) {
      try await establishWithoutTimeout(
        transport: transport,
        credential: credential,
        path: path,
        endpointInstanceID: endpointInstanceID,
        idleTimeout: idleTimeout,
        options: options
      )
    }
  }

  private static func establishWithoutTimeout(
    transport: any FlowersecBinaryTransport,
    credential: DirectEndpointCredential,
    path: FlowersecPath,
    endpointInstanceID: String?,
    idleTimeout: Duration?,
    options: EndpointOptions
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
      try await credential.commitAuthenticated?()
    } catch {
      await secure.close()
      throw FlowersecError(
        path: path,
        stage: .handshake,
        code: .credentialCommitFailed,
        message: "Endpoint credential commit failed: \(error.localizedDescription)"
      )
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

  private static func withHandshakeTimeout<T: Sendable>(
    transport: any FlowersecBinaryTransport,
    timeout: Duration,
    operation: @escaping @Sendable () async throws -> T
  ) async throws -> T {
    try await withThrowingTaskGroup(of: EndpointHandshakeRace<T>.self) { group in
      group.addTask {
        do { return .completed(try await operation()) } catch { return .failed(error) }
      }
      group.addTask {
        do {
          try await Task.sleep(for: timeout)
          return .timedOut
        } catch {
          return .failed(error)
        }
      }
      guard let result = try await group.next() else {
        throw FlowersecError.invalidHandshake("Endpoint handshake ended without a result.")
      }
      group.cancelAll()
      switch result {
      case .completed(let value): return value
      case .failed(let error): throw error
      case .timedOut:
        await transport.close()
        throw FlowersecError(
          path: .direct,
          stage: .handshake,
          code: .timeout,
          message: "Endpoint handshake timed out."
        )
      }
    }
  }
}

private enum EndpointHandshakeRace<T: Sendable>: @unchecked Sendable {
  case completed(T)
  case failed(any Error)
  case timedOut
}

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
