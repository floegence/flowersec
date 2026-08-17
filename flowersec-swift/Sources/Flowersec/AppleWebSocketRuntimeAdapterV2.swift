import Foundation

#if os(macOS) || os(iOS)
  import NIOSSL

  enum SwiftRuntimeErrorV2: Error, Equatable, Sendable {
    case invalidConfiguration
    case connectionFailed
    case protocolNegotiationFailed
  }

  struct AppleWebSocketRuntimeAdapterV2: RuntimeCarrierAdapterV2 {
    #if os(iOS)
      let capabilities = RuntimeCapabilitiesV2.iOS
    #else
      let capabilities = RuntimeCapabilitiesV2.macOS
    #endif

    func validate(options: ConnectorOptions) throws {
      for pem in options.trustRootsPEM {
        guard !pem.isEmpty, !(try NIOSSLCertificate.fromPEMBytes(Array(pem))).isEmpty else {
          throw SwiftRuntimeErrorV2.invalidConfiguration
        }
      }
    }

    func prepare(
      candidate: CanonicalCandidateV2,
      path: PathKind,
      role: SessionRoleV2,
      options: ConnectorOptions
    ) async throws -> any PreparedCarrierConnectionV2 {
      guard candidate.carrier == CarrierKind.webSocket.rawValue,
        let url = URL(string: candidate.normalizedURL)
      else { throw ConnectorBoundaryErrorV2.runtimeUnsupported }
      let subprotocol = path == .direct ? "flowersec.direct.v2" : "flowersec.tunnel.v2"
      var headers = [ProxyHeader(name: "Sec-WebSocket-Protocol", value: subprotocol)]
      if let origin = options.origin { headers.append(ProxyHeader(name: "Origin", value: origin)) }
      let trustRoots = try options.trustRootsPEM.flatMap {
        try NIOSSLCertificate.fromPEMBytes(Array($0))
      }
      let socket: any ProxyUpstreamWebSocket
      do {
        socket = try await ProxyNIOWebSocketConnector.connect(
          url: url,
          headers: headers,
          maxFrameBytes: FlowersecSDKDefaults.Yamux.maxFrameBytes + 12,
          timeout: options.connectTimeout,
          trustRoots: trustRoots.isEmpty ? nil : trustRoots
        )
      } catch {
        throw SwiftRuntimeErrorV2.connectionFailed
      }
      guard socket.selectedProtocol == subprotocol else {
        await socket.close()
        throw SwiftRuntimeErrorV2.protocolNegotiationFailed
      }
      return PreparedWebSocketConnectionV2(
        transport: NIOWebSocketBinaryTransportV2(socket: socket),
        path: path,
        role: role
      )
    }
  }

  private actor PreparedWebSocketConnectionV2: PreparedCarrierConnectionV2 {
    nonisolated let carrier = CarrierKind.webSocket
    private let transport: NIOWebSocketBinaryTransportV2
    private let path: PathKind
    private let role: SessionRoleV2
    private var handedOff = false

    init(transport: NIOWebSocketBinaryTransportV2, path: PathKind, role: SessionRoleV2) {
      self.transport = transport
      self.path = path
      self.role = role
    }

    func writeAdmission(_ frame: Data) async throws {
      guard !handedOff else { throw SwiftRuntimeErrorV2.connectionFailed }
      try await transport.writeBinary(frame)
    }

    func readAdmission() async throws -> Data {
      guard !handedOff else { throw SwiftRuntimeErrorV2.connectionFailed }
      return try await transport.readBinary()
    }

    func makeCarrier(inboundCapacity: UInt16) async throws -> any TransportV2CarrierSession {
      guard !handedOff else { throw SwiftRuntimeErrorV2.connectionFailed }
      handedOff = true
      return WebSocketCarrierSessionV2(
        transport: transport,
        path: path,
        client: role == .client,
        inboundCapacity: inboundCapacity
      )
    }

    func close() async { await transport.close() }
  }

  private actor NIOWebSocketBinaryTransportV2: FlowersecBinaryTransport {
    private let socket: any ProxyUpstreamWebSocket
    private var closed = false

    init(socket: any ProxyUpstreamWebSocket) { self.socket = socket }

    func writeBinary(_ data: Data) async throws {
      guard !closed else { throw TransportV2CarrierError.closed }
      try await socket.send(ProxyWebSocketFrame(operation: .binary, payload: data))
      guard !closed else { throw TransportV2CarrierError.closed }
    }

    func readBinary() async throws -> Data {
      while true {
        guard !closed else { throw TransportV2CarrierError.closed }
        let frame = try await socket.receive()
        guard !closed else { throw TransportV2CarrierError.closed }
        switch frame.operation {
        case .binary:
          return frame.payload
        case .ping:
          // Control frames are handled by the carrier and never enter Yamux.
          try await socket.send(ProxyWebSocketFrame(operation: .pong, payload: frame.payload))
        case .pong:
          continue
        case .close:
          await close()
          throw TransportV2CarrierError.closed
        case .text:
          throw SwiftRuntimeErrorV2.connectionFailed
        }
      }
    }

    func close() async {
      guard !closed else { return }
      closed = true
      await socket.close()
    }
  }

  final class WebSocketCarrierSessionV2: TransportV2CarrierSession, @unchecked Sendable {
    let chosenCarrier = CarrierKind.webSocket
    let capabilities = CarrierCapabilitiesV2(
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
        channel: WebSocketYamuxChannelV2(transport: transport),
        limits: limits,
        path: path == .direct ? .direct : .tunnel,
        client: client
      )
      Task { await yamux.start() }
    }

    func openStream() async throws -> any TransportV2CarrierStream {
      guard !isTerminated else { throw TransportV2CarrierError.closed }
      let stream = try await yamux.openStream()
      guard !isTerminated else {
        try? await stream.reset()
        throw TransportV2CarrierError.closed
      }
      return WebSocketCarrierStreamV2(stream: stream)
    }

    func acceptStream() async throws -> any TransportV2CarrierStream {
      guard !isTerminated else { throw TransportV2CarrierError.closed }
      let stream = try await yamux.acceptStream()
      guard !isTerminated else {
        try? await stream.reset()
        throw TransportV2CarrierError.closed
      }
      return WebSocketCarrierStreamV2(stream: stream)
    }

    func sendDatagram(_ data: Data) async throws {
      throw TransportV2CarrierError.datagramsUnavailable
    }

    func receiveDatagram(maxBytes: Int) async throws -> Data {
      throw TransportV2CarrierError.datagramsUnavailable
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

  private final class WebSocketCarrierStreamV2: TransportV2CarrierStream, @unchecked Sendable {
    let carrierStreamID: UInt64
    private let stream: FlowersecYamuxStream
    private let stateLock = NSLock()
    private var aborted = false

    init(stream: FlowersecYamuxStream) {
      self.stream = stream
      carrierStreamID = UInt64(stream.id)
    }

    func read(maxBytes: Int) async throws -> Data? {
      guard !isAborted else { throw TransportV2CarrierError.streamReset }
      let data = try await stream.read(maxBytes: maxBytes)
      guard !isAborted else { throw TransportV2CarrierError.streamReset }
      return data
    }

    func write(_ data: Data) async throws -> Int {
      guard !isAborted else { throw TransportV2CarrierError.streamReset }
      try await stream.write(data)
      guard !isAborted else { throw TransportV2CarrierError.streamReset }
      return data.count
    }

    func closeWrite() async throws {
      guard !isAborted else { throw TransportV2CarrierError.streamReset }
      await stream.close()
      guard !isAborted else { throw TransportV2CarrierError.streamReset }
    }

    func stopSending(code: UInt16) async throws {
      guard !isAborted else { throw TransportV2CarrierError.streamReset }
      throw TransportV2CarrierError.stopSendingUnsupported
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

  private actor WebSocketYamuxChannelV2: FlowersecYamuxChannel {
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
