#if os(macOS) || os(iOS)
import Crypto
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import NIOTLS
@testable import Flowersec

/// Test-only original mTLS authority. The fixture CA issues one server and one
/// client identity; application Artifact/TxB signing remains the separate
/// independently trusted CredentialFixture issuer, never the consumer key.
final class V4ControlTestAuthority: @unchecked Sendable {
  struct Identity: Sendable {
    let rootPEM: Data
    let serverPEM: Data
    let serverKeyPEM: Data
    let clientPEM: Data
    let clientKeyPEM: Data
    init() throws {
      let root = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 81, count: 32))
      let server = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 82, count: 32))
      let client = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 83, count: 32))
      rootPEM = try V4TestCertificate.pem(V4TestCertificate.certificate(key: root, issuer: root, subject: "Flowersec Test CA", serial: 1, ca: true))
      serverPEM = try V4TestCertificate.pem(V4TestCertificate.certificate(key: server, issuer: root, subject: "localhost", serial: 2, ca: false))
      clientPEM = try V4TestCertificate.pem(V4TestCertificate.certificate(key: client, issuer: root, subject: "client.test", serial: 3, ca: false))
      serverKeyPEM = Data(server.pemRepresentation.utf8); clientKeyPEM = Data(client.pemRepresentation.utf8)
    }
  }
  let identity: Identity
  private let group: MultiThreadedEventLoopGroup
  private let listener: any Channel
  private let state: State
  var port: Int { listener.localAddress!.port! }
  var requests: [String] { state.gate.withLock { state.requests } }
  private final class State: @unchecked Sendable {
    let gate = NSLock()
    var children: [any Channel] = []
    var requests: [String] = []
    var tasks: [UUID: Task<Void, Never>] = [:]
  }
  init(identity: Identity, maximumRequestBytes: Int = 1024,
    contentTypes: @escaping @Sendable (String) -> (request: String, response: String) = { _ in ("application/cbor", "application/cbor") },
    respondAsync: (@Sendable (String, Data) async throws -> Data)? = nil,
    respond: @escaping @Sendable (String, Data) throws -> Data) throws {
    self.identity = identity
    var tls = TLSConfiguration.makeServerConfiguration(
      certificateChain: try NIOSSLCertificate.fromPEMBytes(Array(identity.serverPEM)).map { .certificate($0) },
      privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(identity.serverKeyPEM), format: .pem)))
    tls.minimumTLSVersion = .tlsv13; tls.maximumTLSVersion = .tlsv13
    tls.applicationProtocols = ["http/1.1"]; tls.certificateVerification = .noHostnameVerification
    tls.trustRoots = .certificates(try NIOSSLCertificate.fromPEMBytes(Array(identity.rootPEM)))
    let context = try NIOSSLContext(configuration: tls)
    let state = State(); self.state = state
    group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    listener = try ServerBootstrap(group: group).childChannelInitializer { channel in
      let admitted = state.gate.withLock { () -> Bool in
        guard state.children.count < 8 else { return false }; state.children.append(channel); return true
      }
      guard admitted else { return channel.eventLoop.makeFailedFuture(TransportControlError.busy) }
      do {
        try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context))
        return channel.pipeline.configureHTTPServerPipeline().flatMapThrowing {
          try channel.pipeline.syncOperations.addHandler(Handler(state: state, maximumRequestBytes: maximumRequestBytes, contentTypes: contentTypes, respond: respond, respondAsync: respondAsync))
        }
      } catch { return channel.eventLoop.makeFailedFuture(error) }
    }.bind(host: "127.0.0.1", port: 0).wait()
  }
  func configuration() -> TransportControlHTTPSConfiguration {
    .init(endpoint: .init(hostname: "localhost", port: port, numericAddress: "127.0.0.1"),
      trustRootsPEM: [identity.rootPEM], clientCertificatePEM: identity.clientPEM,
      clientPrivateKeyPEM: identity.clientKeyPEM, maximumConcurrentRequests: 1, timeoutMilliseconds: 5000)
  }
  func stop() {
    for task in state.gate.withLock({ Array(state.tasks.values) }) { task.cancel() }
    for child in state.gate.withLock({ state.children }) { try? child.close().wait() }
    try? listener.close().wait(); try? group.syncShutdownGracefully()
  }
  func stopAsync() async {
    let snapshot = state.gate.withLock { (state.children, Array(state.tasks.values)) }
    for task in snapshot.1 { task.cancel() }
    for child in snapshot.0 { try? await child.close().get() }
    for task in snapshot.1 { await task.value }
    try? await listener.close().get()
    await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
      group.shutdownGracefully { _ in continuation.resume() }
    }
  }
  private final class Handler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart
    let state: State
    let maximumRequestBytes: Int
    let contentTypes: @Sendable (String) -> (request: String, response: String)
    let respond: @Sendable (String, Data) throws -> Data
    let respondAsync: (@Sendable (String, Data) async throws -> Data)?
    var head: HTTPRequestHead?
    var authenticated = false
    var body = Data()
    init(state: State, maximumRequestBytes: Int, contentTypes: @escaping @Sendable (String) -> (request: String, response: String), respond: @escaping @Sendable (String, Data) throws -> Data, respondAsync: (@Sendable (String, Data) async throws -> Data)?) { self.state = state; self.maximumRequestBytes = maximumRequestBytes; self.contentTypes = contentTypes; self.respond = respond; self.respondAsync = respondAsync }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
      do {
        switch unwrapInboundIn(data) {
        case .head(let value):
          guard authenticated, head == nil, value.method == .POST, value.headers["content-type"] == [contentTypes(value.uri).request],
            value.headers["transfer-encoding"].isEmpty, value.headers["cookie"].isEmpty,
            value.headers["content-length"].count == 1, let length = Int(value.headers["content-length"][0]),
            (1...maximumRequestBytes).contains(length) else { throw TransportControlError.responseInvalid }
          head = value
        case .body(let buffer):
          guard buffer.readableBytes <= maximumRequestBytes - body.count else { throw TransportControlError.responseInvalid }
          body.append(contentsOf: buffer.readableBytesView)
        case .end(let trailers):
          guard trailers == nil, let head, Int(head.headers["content-length"][0]) == body.count else { throw TransportControlError.responseInvalid }
          state.gate.withLock { state.requests.append(head.uri) }
          if let respondAsync {
            let channel = context.channel; let request = body; let id = UUID()
            let responseContentType = contentTypes(head.uri).response
            state.gate.withLock {
              state.tasks[id] = Task { [state] in
                defer { state.gate.withLock { _ = state.tasks.removeValue(forKey: id) } }
                do {
                  let reply = try await respondAsync(head.uri, request)
                  try Task.checkCancellation()
                  guard !reply.isEmpty, reply.count <= 65_536 else { throw TransportControlError.responseInvalid }
                  try await channel.eventLoop.submit {
                    let headers = HTTPHeaders([("Content-Type", responseContentType), ("Content-Length", String(reply.count)), ("Cache-Control", "no-store"), ("Connection", "close")])
                    channel.write(HTTPServerResponsePart.head(.init(version: .http1_1, status: .ok, headers: headers)), promise: nil)
                    var buffer = channel.allocator.buffer(capacity: reply.count); buffer.writeBytes(reply)
                    channel.write(HTTPServerResponsePart.body(.byteBuffer(buffer)), promise: nil)
                    let promise = channel.eventLoop.makePromise(of: Void.self)
                    channel.writeAndFlush(HTTPServerResponsePart.end(nil), promise: promise)
                    return promise.futureResult
                  }.flatMap { $0 }.get()
                } catch { try? await channel.close().get() }
              }
            }
            channel.closeFuture.whenComplete { [state] _ in state.gate.withLock { state.tasks[id]?.cancel() } }
            return
          }
          let reply = try respond(head.uri, body)
          guard !reply.isEmpty, reply.count <= 65_536 else { throw TransportControlError.responseInvalid }
          let headers = HTTPHeaders([("Content-Type", contentTypes(head.uri).response), ("Content-Length", String(reply.count)), ("Cache-Control", "no-store"), ("Connection", "close")])
          context.write(wrapOutboundOut(.head(.init(version: .http1_1, status: .ok, headers: headers))), promise: nil)
          var buffer = context.channel.allocator.buffer(capacity: reply.count); buffer.writeBytes(reply)
          context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
          context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
        }
      } catch { context.close(promise: nil) }
    }
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
      if let event = event as? TLSUserEvent, case .handshakeCompleted(let negotiated) = event {
        guard negotiated == "http/1.1" else { context.close(promise: nil); return }
        authenticated = true
      }
      context.fireUserInboundEventTriggered(event)
    }
    func errorCaught(context: ChannelHandlerContext, error: Error) { context.close(promise: nil) }
  }
}

/// A minimal bounded X.509 assembly for fixture identities. Dates cover the
/// trusted test clock as well as native server verification. No platform tool,
/// external signer, generated file or network certificate request is used.
private enum V4TestCertificate {
  static func der(_ tag: UInt8, _ body: Data) -> Data {
    let length = body.count
    if length < 128 { return Data([tag, UInt8(length)]) + body }
    let bytes = length <= 255 ? Data([UInt8(length)]) : Data([UInt8(length >> 8), UInt8(length & 255)])
    return Data([tag, 0x80 | UInt8(bytes.count)]) + bytes + body
  }
  static func sequence(_ parts: [Data]) -> Data { der(0x30, parts.reduce(Data(), +)) }
  static func oid(_ bytes: [UInt8]) -> Data { der(0x06, Data(bytes)) }
  static func name(_ text: String) -> Data { sequence([der(0x31, sequence([oid([0x55, 0x04, 0x03]), der(0x0c, Data(text.utf8))]))]) }
  static func extensionValue(_ id: [UInt8], _ body: Data, critical: Bool = false) -> Data {
    sequence([oid(id)] + (critical ? [Data([0x01, 0x01, 0xff])] : []) + [der(0x04, body)])
  }
  static func certificate(key: P256.Signing.PrivateKey, issuer: P256.Signing.PrivateKey,
    subject: String, serial: UInt8, ca: Bool) throws -> Data {
    let algorithm = sequence([oid([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])])
    let publicKey = sequence([sequence([oid([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
      oid([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])]), der(0x03, Data([0]) + key.publicKey.x963Representation)])
    var extensions = [extensionValue([0x55, 0x1d, 0x13], ca ? sequence([Data([0x01, 0x01, 0xff])]) : sequence([]), critical: true),
      extensionValue([0x55, 0x1d, 0x0f], der(0x03, ca ? Data([1, 0x06]) : Data([7, 0x80])), critical: true)]
    if !ca {
      extensions.append(extensionValue([0x55, 0x1d, 0x11], sequence([der(0x82, Data(subject.utf8))])))
      extensions.append(extensionValue([0x55, 0x1d, 0x25], sequence([
        oid([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]), oid([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02])])))
    }
    // Epoch zero covers the signed trusted interval and satisfies the native
    // pinned leaf requirement that notBefore be nonnegative.
    let tbs = sequence([der(0xa0, Data([0x02, 0x01, 0x02])), Data([0x02, 0x01, serial]), algorithm,
      name("Flowersec Test CA"), sequence([der(0x17, Data("700101000000Z".utf8)), der(0x18, Data("20500101000000Z".utf8))]),
      name(subject), publicKey, der(0xa3, sequence(extensions))])
    let signature = try issuer.signature(for: tbs).derRepresentation
    return sequence([tbs, algorithm, der(0x03, Data([0]) + signature)])
  }
  static func pem(_ bytes: Data) -> Data {
    Data(("-----BEGIN CERTIFICATE-----\n" + bytes.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]) + "\n-----END CERTIFICATE-----\n").utf8)
  }
}
#endif
