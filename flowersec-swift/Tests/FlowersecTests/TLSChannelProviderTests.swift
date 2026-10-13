#if os(macOS) || os(iOS)
import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import NIOTLS
import XCTest
@testable import Flowersec

final class TLSChannelProviderTests: XCTestCase {
  func testApplicationChannelRetainsTargetCAAndHostnameVerification() async throws {
    let fixtures = packageRoot().appendingPathComponent("flowersec-swift/Tests/FlowersecTests/Fixtures")
    let certificate = try Data(contentsOf: fixtures.appendingPathComponent("self_signed_cert.pem"))
    let roots = try Data(contentsOf: fixtures.appendingPathComponent("self_signed_ca.pem"))
    let key = try NIOSSLPrivateKey(file: fixtures.appendingPathComponent("self_signed_key.pem").path, format: .pem)
    let chain = try NIOSSLCertificate.fromPEMBytes(Array(certificate))
    var tls = TLSConfiguration.makeServerConfiguration(certificateChain: chain.map { .certificate($0) }, privateKey: .privateKey(key))
    tls.minimumTLSVersion = .tlsv13
    let context = try NIOSSLContext(configuration: tls), group = MultiThreadedEventLoopGroup.singleton
    let server = try await ServerBootstrap(group: group).childChannelInitializer { channel in
      channel.pipeline.addHandlers([NIOSSLServerHandler(context: context), TLSChannelEcho()])
    }.bind(host: "127.0.0.1", port: 0).get()
    let port = try XCTUnwrap(server.localAddress?.port)
    do {
      for (host, roots, success) in [("localhost", [roots], true), ("wrong.example", [roots], false), ("localhost", [], false)] {
        let result = group.any().makePromise(of: String.self)
        let provider = try TLSChannelProvider(origin: URL(string: "https://\(host):\(port)")!) { initialize in
          try await ClientBootstrap(group: group).channelInitializer(initialize).connect(host: "127.0.0.1", port: port).get()
        }
        let channel = try await provider.openChannel(trustRootsPEM: roots) { channel in
          channel.pipeline.addHandler(TLSChannelReply(result: result))
        }
        let timeout = result.futureResult.eventLoop.scheduleTask(in: .seconds(2)) { result.fail(TLSChannelError.verificationFailed); channel.close(promise: nil) }
        do {
          let reply = try await result.futureResult.get()
          XCTAssertTrue(success); XCTAssertEqual(reply, "hello")
        } catch { XCTAssertFalse(success, "\(host): \(error)") }
        timeout.cancel(); try? await channel.close().get()
      }
      try await server.close().get()
    } catch { try? await server.close().get(); throw error }
  }

  func testRejectsAmbiguousOriginsBeforeCallingApplication() throws {
    for origin in ["http://localhost", "https://localhost/path", "https://user@localhost", "https://localhost?query", "https://localhost#fragment"] {
      XCTAssertThrowsError(try TLSChannelProvider(origin: URL(string: origin)!) { _ in throw TLSChannelError.invalidOrigin })
    }
  }
}

private final class TLSChannelEcho: ChannelInboundHandler, Sendable {
  typealias InboundIn = ByteBuffer
  func channelRead(context: ChannelHandlerContext, data: NIOAny) { context.writeAndFlush(data, promise: nil) }
  func errorCaught(context: ChannelHandlerContext, error: any Error) { context.close(promise: nil) }
}
private final class TLSChannelReply: ChannelInboundHandler, Sendable {
  typealias InboundIn = ByteBuffer
  let result: EventLoopPromise<String>
  init(result: EventLoopPromise<String>) { self.result = result }
  func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
    if let event = event as? TLSUserEvent, case .handshakeCompleted = event {
      var bytes = context.channel.allocator.buffer(capacity: 5); bytes.writeString("hello")
      context.writeAndFlush(NIOAny(bytes), promise: nil)
    }
    context.fireUserInboundEventTriggered(event)
  }
  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    var bytes = unwrapInboundIn(data); result.succeed(bytes.readString(length: bytes.readableBytes) ?? "")
  }
  func errorCaught(context: ChannelHandlerContext, error: any Error) { result.fail(error); context.close(promise: nil) }
  func channelInactive(context: ChannelHandlerContext) { result.fail(TLSChannelError.verificationFailed); context.fireChannelInactive() }
}
#endif
