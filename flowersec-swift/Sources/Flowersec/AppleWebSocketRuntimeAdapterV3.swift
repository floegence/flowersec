import Foundation

#if os(macOS) || os(iOS)
  import NIOSSL

  enum SwiftRuntimeErrorV3: Error, Equatable, Sendable {
    case invalidConfiguration
    case connectionFailed
    case protocolNegotiationFailed
  }

  struct AppleWebSocketRuntimeAdapterV3: RuntimeCarrierAdapterV3 {
    #if os(iOS)
      let capabilities = RuntimeCapabilitiesV3.iOS
    #else
      let capabilities = RuntimeCapabilitiesV3.macOS
    #endif

    func validate(options: ConnectorOptions) throws {
      guard validOrigin(options.origin) else {
        throw SwiftRuntimeErrorV3.invalidConfiguration
      }
      for pem in options.trustRootsPEM {
        guard !pem.isEmpty, !(try NIOSSLCertificate.fromPEMBytes(Array(pem))).isEmpty else {
          throw SwiftRuntimeErrorV3.invalidConfiguration
        }
      }
    }

    func prepare(
      candidate: CanonicalCandidateV3,
      path: PathKind,
      role: SessionRoleV3,
      options: ConnectorOptions,
      activePinHashes: [Data]?
    ) async throws -> any PreparedCarrierConnectionV3 {
      guard candidate.carrier == RuntimeCarrierV3.webSocket.rawValue,
        let url = URL(string: candidate.normalizedURL),
        url.absoluteString == candidate.normalizedURL,
        url.scheme == "wss",
        url.path
          == (path == .direct
            ? TransportV3Contract.directWebSocketPath
            : TransportV3Contract.tunnelWebSocketPath),
        url.query == nil, url.fragment == nil, url.user == nil, url.password == nil,
        let host = url.host
      else { throw ConnectorBoundaryErrorV3.runtimeUnsupported }
      let subprotocol =
        path == .direct
        ? TransportV3Contract.directWebSocketSubprotocol
        : TransportV3Contract.tunnelWebSocketSubprotocol
      var headers = [ProxyHeader(name: "Sec-WebSocket-Protocol", value: subprotocol)]
      headers.append(ProxyHeader(name: "Origin", value: options.origin))
      let roots = try options.trustRootsPEM.flatMap {
        try NIOSSLCertificate.fromPEMBytes(Array($0))
      }
      let policy: TransportSecurityPolicyV3
      switch (candidate.tls.mode, activePinHashes) {
      case ("pin", let pins?):
        policy = .pin(serverName: host, activeLeafDERSHA256: pins)
      case ("ca", nil):
        policy = .ca(serverName: host, rootsSource: roots.isEmpty ? .platform : .configured)
      default:
        throw ConnectorBoundaryErrorV3.artifactInvalid
      }
      let handler: ProxyTLSClientHandler
      do {
        handler = try NativeTLSPolicyAdapterV3.makeClientHandlerFactory(
          policy: policy,
          serverHostname: host,
          configuredRoots: roots
        )
      } catch {
        throw ConnectorBoundaryErrorV3.runtimeUnsupported
      }
      let socket: any ProxyUpstreamWebSocket
      do {
        socket = try await ProxyNIOWebSocketConnector.connect(
          url: url,
          headers: headers,
          maxFrameBytes: FlowersecSDKDefaults.Yamux.maxFrameBytes + 12,
          timeout: options.connectTimeout,
          tlsHandler: handler
        )
      } catch let failure as ProxyUpstreamFailure {
        if failure.tlsLocated { throw ConnectorBoundaryErrorV3.securityFailed }
        throw SwiftRuntimeErrorV3.connectionFailed
      } catch {
        throw SwiftRuntimeErrorV3.connectionFailed
      }
      guard socket.selectedProtocol == subprotocol else {
        await socket.close()
        throw SwiftRuntimeErrorV3.protocolNegotiationFailed
      }
      return PreparedWebSocketConnectionV3(
        transport: NIOWebSocketBinaryTransportV3(socket: socket),
        path: path,
        role: role
      )
    }

    private func validOrigin(_ origin: String) -> Bool {
      guard let components = URLComponents(string: origin), components.host != nil,
        components.user == nil, components.password == nil,
        components.path.isEmpty || components.path == "/",
        components.query == nil, components.fragment == nil
      else { return false }
      return components.scheme == "http" || components.scheme == "https"
    }
  }

  private actor PreparedWebSocketConnectionV3: PreparedCarrierConnectionV3 {
    nonisolated let carrier = CarrierKind.webSocket
    private let transport: NIOWebSocketBinaryTransportV3
    private let path: PathKind
    private let role: SessionRoleV3
    private var handedOff = false

    init(transport: NIOWebSocketBinaryTransportV3, path: PathKind, role: SessionRoleV3) {
      self.transport = transport
      self.path = path
      self.role = role
    }

    func writeAdmission(_ frame: Data) async throws {
      guard !handedOff else { throw SwiftRuntimeErrorV3.connectionFailed }
      try await transport.writeBinary(frame)
    }

    func readAdmission() async throws -> Data {
      guard !handedOff else { throw SwiftRuntimeErrorV3.connectionFailed }
      return try await transport.readBinary()
    }

    func makeCarrier(inboundCapacity: UInt16) async throws -> any TransportV3CarrierSession {
      guard !handedOff else { throw SwiftRuntimeErrorV3.connectionFailed }
      handedOff = true
      return WebSocketCarrierSessionV3(
        transport: transport,
        path: path,
        client: role == .client,
        inboundCapacity: inboundCapacity
      )
    }

    func close() async { await transport.close() }
  }

  private actor NIOWebSocketBinaryTransportV3: FlowersecBinaryTransport {
    private let socket: any ProxyUpstreamWebSocket
    private var closed = false

    init(socket: any ProxyUpstreamWebSocket) { self.socket = socket }

    func writeBinary(_ data: Data) async throws {
      guard !closed else { throw TransportV3CarrierError.closed }
      try await socket.send(ProxyWebSocketFrame(operation: .binary, payload: data))
      guard !closed else { throw TransportV3CarrierError.closed }
    }

    func readBinary() async throws -> Data {
      while true {
        guard !closed else { throw TransportV3CarrierError.closed }
        let frame = try await socket.receive()
        guard !closed else { throw TransportV3CarrierError.closed }
        switch frame.operation {
        case .binary:
          return frame.payload
        case .ping:
          try await socket.send(ProxyWebSocketFrame(operation: .pong, payload: frame.payload))
        case .pong:
          continue
        case .close:
          await close()
          throw TransportV3CarrierError.closed
        case .text:
          throw SwiftRuntimeErrorV3.connectionFailed
        }
      }
    }

    func close() async {
      guard !closed else { return }
      closed = true
      await socket.close()
    }
  }

  final class WebSocketCarrierSessionV3: TransportV3CarrierSession, @unchecked Sendable {
    let chosenCarrier = CarrierKind.webSocket
    let capabilities = CarrierCapabilitiesV3(
      reliableStreams: true,
      datagrams: false,
      migration: false
    )
    let inboundBidirectionalStreamCapacity: UInt16
    private let yamux: FlowersecYamuxClient
    private let stateLock = NSLock()
    private var terminated = false

    init(
      transport: any FlowersecBinaryTransport,
      path: PathKind,
      client: Bool,
      inboundCapacity: UInt16
    ) {
      inboundBidirectionalStreamCapacity = inboundCapacity
      let limits = YamuxLimits(
        maxActiveStreams: Int(inboundCapacity) * 2,
        maxInboundStreams: Int(inboundCapacity)
      )
      yamux = FlowersecYamuxClient(
        channel: WebSocketYamuxChannelV3(transport: transport),
        limits: limits,
        path: path == .direct ? .direct : .tunnel,
        client: client
      )
      Task { await yamux.start() }
    }

    func openStream() async throws -> any TransportV3CarrierStream {
      guard !isTerminated else { throw TransportV3CarrierError.closed }
      let stream = try await yamux.openStream()
      guard !isTerminated else {
        try? await stream.reset()
        throw TransportV3CarrierError.closed
      }
      return WebSocketCarrierStreamV3(stream: stream)
    }

    func acceptStream() async throws -> any TransportV3CarrierStream {
      guard !isTerminated else { throw TransportV3CarrierError.closed }
      let stream = try await yamux.acceptStream()
      guard !isTerminated else {
        try? await stream.reset()
        throw TransportV3CarrierError.closed
      }
      return WebSocketCarrierStreamV3(stream: stream)
    }

    func sendDatagram(_ data: Data) async throws {
      throw TransportV3CarrierError.datagramsUnavailable
    }

    func receiveDatagram(maxBytes: Int) async throws -> Data {
      throw TransportV3CarrierError.datagramsUnavailable
    }

    func close(code: UInt16, reason: String) async {
      _ = markTerminated()
      await yamux.close()
    }

    nonisolated func abort(code: UInt16, reason: String) {
      guard markTerminated() else { return }
      Task { await yamux.close() }
    }

    private var isTerminated: Bool { stateLock.withLock { terminated } }

    private nonisolated func markTerminated() -> Bool {
      stateLock.withLock {
        guard !terminated else { return false }
        terminated = true
        return true
      }
    }
  }

  private final class WebSocketCarrierStreamV3: TransportV3CarrierStream, @unchecked Sendable {
    let carrierStreamID: UInt64
    private let stream: FlowersecYamuxStream
    private let stateLock = NSLock()
    private var aborted = false

    init(stream: FlowersecYamuxStream) {
      self.stream = stream
      carrierStreamID = UInt64(stream.id)
    }

    func read(maxBytes: Int) async throws -> Data? {
      guard !isAborted else { throw TransportV3CarrierError.streamReset }
      let data = try await stream.read(maxBytes: maxBytes)
      guard !isAborted else { throw TransportV3CarrierError.streamReset }
      return data
    }

    func write(_ data: Data) async throws -> Int {
      guard !isAborted else { throw TransportV3CarrierError.streamReset }
      try await stream.write(data)
      guard !isAborted else { throw TransportV3CarrierError.streamReset }
      return data.count
    }

    func closeWrite() async throws {
      guard !isAborted else { throw TransportV3CarrierError.streamReset }
      await stream.close()
      guard !isAborted else { throw TransportV3CarrierError.streamReset }
    }

    func stopSending(code: UInt16) async throws {
      guard !isAborted else { throw TransportV3CarrierError.streamReset }
      throw TransportV3CarrierError.stopSendingUnsupported
    }

    func reset(code: UInt16) async {
      _ = markAborted()
      try? await stream.reset()
    }

    nonisolated func abort(code: UInt16) {
      guard markAborted() else { return }
      Task { try? await stream.reset() }
    }

    func close() async { await stream.close() }

    private var isAborted: Bool { stateLock.withLock { aborted } }

    private nonisolated func markAborted() -> Bool {
      stateLock.withLock {
        guard !aborted else { return false }
        aborted = true
        return true
      }
    }
  }

  private actor WebSocketYamuxChannelV3: FlowersecYamuxChannel {
    private let transport: any FlowersecBinaryTransport
    private var buffer = Data()
    private var offset = 0

    init(transport: any FlowersecBinaryTransport) { self.transport = transport }

    func write(_ data: Data) async throws { try await transport.writeBinary(data) }

    func readExact(_ length: Int) async throws -> Data {
      while buffer.count - offset < length {
        buffer.append(try await transport.readBinary())
      }
      let end = offset + length
      let output = Data(buffer[offset..<end])
      offset = end
      if offset == buffer.count {
        buffer.removeAll(keepingCapacity: true)
        offset = 0
      }
      return output
    }

    func close() async { await transport.close() }
  }
#endif
