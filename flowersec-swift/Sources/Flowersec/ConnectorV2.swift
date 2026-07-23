import Crypto
import Foundation
import NIOSSL

public struct ConnectorOptionsV2: Sendable {
  public var origin: String?
  public var admissionReasons: Set<String>
  public var connectTimeout: Duration
  public var trustRootsPEM: [Data]

  public init(
    origin: String? = nil,
    admissionReasons: Set<String> = [],
    connectTimeout: Duration = .seconds(30),
    trustRootsPEM: [Data] = []
  ) {
    self.origin = origin
    self.admissionReasons = admissionReasons
    self.connectTimeout = connectTimeout
    self.trustRootsPEM = trustRootsPEM
  }
}

public enum ConnectErrorV2: String, Error, Equatable, Sendable {
  case invalidOptions = "invalid_options"
  case unsupportedCarrier = "unsupported_carrier"
  case expiredArtifact = "expired_artifact"
  case canceled = "canceled"
  case timeout
  case admissionRejected = "admission_rejected"
  case connectionFailed = "connection_failed"
}

/// Establishes a carrier-neutral Transport v2 session from an opaque artifact lease.
public struct ConnectorV2: Sendable {
  private let lease: ArtifactLeaseV2
  private let options: ConnectorOptionsV2
  private let dial: @Sendable (URL, String, ConnectorOptionsV2) async throws -> any FlowersecBinaryTransport

  public init(lease: ArtifactLeaseV2, options: ConnectorOptionsV2 = ConnectorOptionsV2()) throws {
    try Self.validate(options)
    self.lease = lease
    self.options = options
    self.dial = { url, subprotocol, options in
      var headers = [ProxyHeader(name: "Sec-WebSocket-Protocol", value: subprotocol)]
      if let origin = options.origin { headers.append(ProxyHeader(name: "Origin", value: origin)) }
      let socket = try await ProxyNIOWebSocketConnector.connect(
        url: url,
        headers: headers,
        maxFrameBytes: FlowersecSDKDefaults.Yamux.maxFrameBytes + 12,
        timeout: options.connectTimeout,
        trustRoots: try options.trustRootsPEM.flatMap {
          try NIOSSLCertificate.fromPEMBytes(Array($0))
        }.nilIfEmpty
      )
      guard socket.selectedProtocol == subprotocol else {
        await socket.close()
        throw ConnectErrorV2.connectionFailed
      }
      return NIOWebSocketBinaryTransportV2(socket: socket)
    }
  }

  init(
    lease: ArtifactLeaseV2,
    options: ConnectorOptionsV2,
    dial: @escaping @Sendable (URL, String, ConnectorOptionsV2) async throws -> any FlowersecBinaryTransport
  ) throws {
    try Self.validate(options)
    self.lease = lease
    self.options = options
    self.dial = dial
  }

  public func connect() async throws -> any SessionV2 {
    do {
      return try await withThrowingTaskGroup(of: (any SessionV2).self) { group in
        group.addTask { try await connectWithoutDeadline() }
        group.addTask {
          try await Task.sleep(for: options.connectTimeout)
          throw ConnectErrorV2.timeout
        }
        defer { group.cancelAll() }
        guard let session = try await group.next() else { throw ConnectErrorV2.connectionFailed }
        return session
      }
    } catch is CancellationError {
      throw ConnectErrorV2.canceled
    } catch let error as ConnectErrorV2 {
      throw error
    } catch {
      throw ConnectErrorV2.connectionFailed
    }
  }

  private func connectWithoutDeadline() async throws -> any SessionV2 {
    try Task.checkCancellation()
    let artifact = lease.artifact.value
    guard artifact.session.initExpireAtUnixSeconds > Int64(Date().timeIntervalSince1970) else {
      throw ConnectErrorV2.expiredArtifact
    }
    guard let candidate = artifact.path.candidates.first(where: { $0.carrier == "websocket" }),
      let url = URL(string: candidate.url)
    else { throw ConnectErrorV2.unsupportedCarrier }
    let path: PathKind = artifact.path.kind == "direct" ? .direct : .tunnel
    let subprotocol = path == .direct ? "flowersec.direct.v2" : "flowersec.tunnel.v2"
    let transport = try await dial(url, subprotocol, options)
    do {
      try Task.checkCancellation()
      try await lease.commitSpend()
      try Task.checkCancellation()
      let fsb2 = try AdmissionCodecV2.encodeFSB2(
        artifact: lease.artifact, chosenCandidateID: candidate.id)
      try await transport.writeBinary(fsb2)
      let response = try AdmissionCodecV2.decodeFSA2(
        try await transport.readBinary(), reasons: options.admissionReasons)
      guard response.status == .success else { throw ConnectErrorV2.admissionRejected }

      let carrier = WebSocketCarrierSessionV2(
        transport: transport,
        path: path,
        client: artifact.path.role != 2,
        inboundCapacity: artifact.session.maxInboundStreams + 2
      )
      let binding = Self.admissionBinding(fsb2)
      let config = TransportV2SessionConfig(
        role: artifact.path.role == 2 ? .server : .client,
        path: path,
        channelID: artifact.session.channelID,
        sessionContractHash: try Self.decode32(artifact.session.contractHashBase64URL),
        suite: TransportCipherSuiteV2(rawValue: artifact.session.defaultSuite)!,
        psk: try Self.decode32(artifact.session.e2eePSKBase64URL),
        maxInboundStreams: artifact.session.maxInboundStreams,
        idleTimeoutSeconds: artifact.session.idleTimeoutSeconds,
        localAdmissionBinding: binding,
        peerAdmissionBinding: path == .direct ? binding : Data(repeating: 0, count: 32),
        localEndpointInstanceID: artifact.path.localEndpointInstanceID ?? "",
        expectedPeerEndpointInstanceID: artifact.path.expectedPeerEndpointInstanceID ?? ""
      )
      return try await TransportV2Session.establish(carrier: carrier, config: config)
    } catch {
      await transport.close()
      throw error
    }
  }

  private static func validate(_ options: ConnectorOptionsV2) throws {
    guard options.connectTimeout > .zero,
      options.admissionReasons.allSatisfy({
        $0.range(of: "^[a-z][a-z0-9_]{0,63}$", options: .regularExpression) != nil
      })
    else { throw ConnectErrorV2.invalidOptions }
    do {
      for pem in options.trustRootsPEM {
        guard !pem.isEmpty, !(try NIOSSLCertificate.fromPEMBytes(Array(pem))).isEmpty else {
          throw ConnectErrorV2.invalidOptions
        }
      }
    } catch { throw ConnectErrorV2.invalidOptions }
    if let origin = options.origin {
      guard let value = URLComponents(string: origin), value.scheme == "https",
        value.host != nil, value.user == nil, value.password == nil,
        (value.path.isEmpty || value.path == "/"), value.query == nil, value.fragment == nil
      else { throw ConnectErrorV2.invalidOptions }
    }
  }

  private static func admissionBinding(_ fsb2: Data) -> Data {
    var input = Data("flowersec-v2-admission\0".utf8)
    input.append(fsb2)
    return Data(SHA256.hash(data: input))
  }

  private static func decode32(_ value: String) throws -> Data {
    var text = value.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    text += String(repeating: "=", count: (4 - text.count % 4) % 4)
    guard let data = Data(base64Encoded: text), data.count == 32 else {
      throw ConnectErrorV2.connectionFailed
    }
    return data
  }
}

private extension Array {
  var nilIfEmpty: Self? { isEmpty ? nil : self }
}

private actor NIOWebSocketBinaryTransportV2: FlowersecBinaryTransport {
  private let socket: any ProxyUpstreamWebSocket

  init(socket: any ProxyUpstreamWebSocket) { self.socket = socket }

  func writeBinary(_ data: Data) async throws {
    try await socket.send(ProxyWebSocketFrame(operation: .binary, payload: data))
  }

  func readBinary() async throws -> Data {
    let frame = try await socket.receive()
    guard frame.operation == .binary else { throw ConnectErrorV2.connectionFailed }
    return frame.payload
  }

  func close() async { await socket.close() }
}

final class WebSocketCarrierSessionV2: TransportV2CarrierSession, @unchecked Sendable {
  let chosenCarrier = CarrierKind.webSocket
  let inboundBidirectionalStreamCapacity: UInt16
  private let yamux: FlowersecYamuxClient

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
    WebSocketCarrierStreamV2(stream: try await yamux.openStream())
  }

  func acceptStream() async throws -> any TransportV2CarrierStream {
    WebSocketCarrierStreamV2(stream: try await yamux.acceptStream())
  }

  func close(code: UInt16, reason: String) async { await yamux.close() }
  nonisolated func abort(code: UInt16, reason: String) { Task { await yamux.close() } }
}

private final class WebSocketCarrierStreamV2: TransportV2CarrierStream, @unchecked Sendable {
  let carrierStreamID: UInt64
  private let stream: FlowersecYamuxStream

  init(stream: FlowersecYamuxStream) {
    self.stream = stream
    carrierStreamID = UInt64(stream.id)
  }

  func read(maxBytes: Int) async throws -> Data? { try await stream.read(maxBytes: maxBytes) }
  func write(_ data: Data) async throws -> Int { try await stream.write(data); return data.count }
  func closeWrite() async throws { await stream.close() }
  func reset(code: UInt16) async { try? await stream.reset() }
  nonisolated func abort(code: UInt16) { Task { try? await stream.reset() } }
  func close() async { await stream.close() }
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
    if offset == buffer.count { buffer.removeAll(keepingCapacity: true); offset = 0 }
    return output
  }

  func close() async { await transport.close() }
}
