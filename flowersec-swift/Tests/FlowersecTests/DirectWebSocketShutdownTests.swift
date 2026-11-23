#if os(macOS)
import Foundation
import NIOCore
import NIOPosix
import NIOTLS
import XCTest

import Flowersec

final class DirectWebSocketShutdownTests: XCTestCase {
  func testListenerRebindsAfterPreviousServerActivelyClosedTCPConnection() async throws {
    let group = MultiThreadedEventLoopGroup.singleton
    let accepted = group.next().makePromise(of: (any Channel).self)
    let previous = try await ServerBootstrap(group: group).childChannelInitializer { channel in
      accepted.succeed(channel)
      return channel.eventLoop.makeSucceededVoidFuture()
    }.bind(host: "127.0.0.1", port: 0).get()
    let address = try XCTUnwrap(previous.localAddress)
    let port = try XCTUnwrap(address.port)
    do {
      let peer = try await ClientBootstrap(group: group).connect(to: address).get()
      let child = try await accepted.futureResult.get()
      try await child.close().get()
      try await peer.closeFuture.get()
      try await previous.close().get()
    } catch {
      try? await previous.close().get()
      throw error
    }
    let fixtures = Bundle.module.resourceURL!.appendingPathComponent("Fixtures")
    let replacement = try await DirectWebSocketListener.listen(
      bindAddress: "127.0.0.1", port: port, allowedOrigins: ["https://app.example"],
      certificateChainPEM: Data(contentsOf: fixtures.appendingPathComponent("self_signed_cert.pem")),
      privateKeyPEM: Data(contentsOf: fixtures.appendingPathComponent("self_signed_key.pem")),
      authorize: { _ in nil }, onSession: { _, _ in })
    XCTAssertEqual(replacement.port, port)
    await replacement.close()
  }

  func testWaitClosedJoinsTLSClientBeforeHTTPUpgrade() async throws {
    let fixtures = Bundle.module.resourceURL!.appendingPathComponent("Fixtures")
    func listen(port: Int) async throws -> DirectWebSocketListener {
      try await DirectWebSocketListener.listen(
        bindAddress: "127.0.0.1", port: port, allowedOrigins: ["https://app.example"],
        certificateChainPEM: Data(contentsOf: fixtures.appendingPathComponent("self_signed_cert.pem")),
        privateKeyPEM: Data(contentsOf: fixtures.appendingPathComponent("self_signed_key.pem")),
        authorize: { _ in XCTFail("unexpected admission before HTTP upgrade"); return nil },
        onSession: { _, _ in XCTFail("unexpected application session") })
    }
    let listener = try await listen(port: 0)
    let peer = ShutdownPeer()
    do {
      do {
        let other = try await listen(port: listener.port)
        await other.close()
        XCTFail("two active listeners bound the same endpoint")
      } catch let error as IOError {
        XCTAssertEqual(error.errnoCode, EADDRINUSE)
      }
      let channel = try await peer.provider(port: listener.port).openChannel(
        trustRootsPEM: [Data(contentsOf: fixtures.appendingPathComponent("self_signed_ca.pem"))],
        initializer: { channel in channel.eventLoop.makeSucceededVoidFuture() })
      await fulfillment(of: [peer.ready], timeout: 5)
      let observed = XCTestExpectation(description: "passive listener shutdown")
      let observer = Task { await listener.waitClosed(); observed.fulfill() }
      let closer = Task { await listener.close() }
      await fulfillment(of: [peer.inputClosed], timeout: 5)
      let result = await XCTWaiter.fulfillment(of: [observed], timeout: 0.25)
      XCTAssertEqual(result, .timedOut, "the listener returned while its accepted TLS socket was still closing")
      try await channel.close().get()
      await closer.value
      await observer.value
      let replacement = try await listen(port: listener.port)
      await replacement.close()
    } catch { await listener.close(); throw error }
  }

  func testCloseCancelsAuthorizationBeforePeerFinishesTLSShutdown() async throws {
    let fixtures = Bundle.module.resourceURL!.appendingPathComponent("Fixtures")
    let origin = "https://app.example"
    let loop = MultiThreadedEventLoopGroup.singleton.next()
    let entered = XCTestExpectation(description: "SDK entered authorization")
    let resumeLookup = loop.makePromise(of: Void.self)
    let wasCancelled = loop.makePromise(of: Bool.self)
    let listener = try await DirectWebSocketListener.listen(
      bindAddress: "127.0.0.1", port: 0, allowedOrigins: [origin],
      certificateChainPEM: Data(contentsOf: fixtures.appendingPathComponent("self_signed_cert.pem")),
      privateKeyPEM: Data(contentsOf: fixtures.appendingPathComponent("self_signed_key.pem")),
      authorize: { _ in
        entered.fulfill()
        try await resumeLookup.futureResult.get()
        wasCancelled.succeed(Task.isCancelled)
        return nil
      }, onSession: { _, _ in XCTFail("unexpected application session") })
    let peer = ShutdownPeer()
    do {
      let provider = try peer.provider(port: listener.port)
      let artifact = try parseArtifact(TransportV3Tests.validArtifact(
        endpoint: "wss://127.0.0.1:\(listener.port)/flowersec/v5/direct"))
      let options = ConnectorOptions(origin: origin, connectTimeout: .seconds(10),
        trustRootsPEM: [try Data(contentsOf: fixtures.appendingPathComponent("self_signed_ca.pem"))])
      let client = Task { try await connect(lease: ArtifactLease(artifact: artifact) {}, options: options,
                                            channelProvider: provider) }
      let enteredResult = await XCTWaiter.fulfillment(of: [entered], timeout: 5)
      guard enteredResult == .completed else {
        resumeLookup.succeed(()); client.cancel(); XCTFail("authorization never started")
        await listener.close(); _ = await client.result; return
      }
      let closer = Task { await listener.close() }
      await fulfillment(of: [peer.inputClosed], timeout: 5)
      resumeLookup.succeed(())
      let canceled = try await wasCancelled.futureResult.get()
      XCTAssertTrue(canceled, "listener shutdown must cancel authorization independently of the peer's TLS shutdown")
      let channel = try await peer.channel.futureResult.get()
      try? await channel.close().get()
      await closer.value
      if case .success(let session) = await client.result { try? await session.close(); XCTFail("unexpected admission") }
      await listener.waitClosed()
    } catch { await listener.close(); throw error }
  }

  func testWaitClosedJoinsAcceptedSessionCleanup() async throws {
    let fixtures = Bundle.module.resourceURL!.appendingPathComponent("Fixtures")
    let origin = "https://app.example"
    let grants = AsyncStream.makeStream(of: DirectAdmissionGrant.self)
    let cleanup = MultiThreadedEventLoopGroup.singleton.next().makePromise(of: Void.self)
    let canceled = XCTestExpectation(description: "listener canceled the accepted application")
    let observed = XCTestExpectation(description: "listener shutdown observed")
    let listener = try await DirectWebSocketListener.listen(
      bindAddress: "127.0.0.1", port: 0, allowedOrigins: [origin],
      certificateChainPEM: Data(contentsOf: fixtures.appendingPathComponent("self_signed_cert.pem")),
      privateKeyPEM: Data(contentsOf: fixtures.appendingPathComponent("self_signed_key.pem")),
      authorize: { _ in var iterator = grants.stream.makeAsyncIterator(); return await iterator.next() },
      onSession: { _, _ in
        try await withTaskCancellationHandler {
          try await cleanup.futureResult.get()
        } onCancel: { canceled.fulfill() }
      })
    let observer = Task { await listener.waitClosed(); observed.fulfill() }
    let client: any Session
    do {
      let artifact = try parseArtifact(TransportV3Tests.validArtifact(
        endpoint: "wss://127.0.0.1:\(listener.port)/flowersec/v5/direct"))
      var handlers = RPCHandlers()
      try handlers.register(7001) { (message: String) in message }
      grants.continuation.yield(DirectAdmissionGrant(artifact: artifact, handlers: handlers) {})
      grants.continuation.finish()
      client = try await connect(lease: ArtifactLease(artifact: artifact) {}, options: ConnectorOptions(
        origin: origin, connectTimeout: .seconds(5),
        trustRootsPEM: [try Data(contentsOf: fixtures.appendingPathComponent("self_signed_ca.pem"))]))
      let reply = try await client.rpc.call(7001, "before shutdown", as: String.self, timeout: .seconds(5))
      XCTAssertEqual(reply, "before shutdown")
      let closer = Task { await listener.close() }
      await fulfillment(of: [canceled], timeout: 5)
      let result = await XCTWaiter.fulfillment(of: [observed], timeout: 0.25)
      XCTAssertEqual(result, .timedOut, "waitClosed returned before the accepted application finished cleanup")
      cleanup.succeed(())
      await closer.value
      await observer.value
      await listener.waitClosed()
    } catch {
      grants.continuation.finish()
      cleanup.succeed(())
      await listener.close()
      await observer.value
      throw error
    }
    _ = await client.waitTermination()
    let activity = try await sessionActivity(client)
    XCTAssertFalse(activity.open)
  }
}

private final class ShutdownPeer: ChannelInboundHandler, Sendable {
  typealias InboundIn = ByteBuffer
  let ready = XCTestExpectation(description: "trusted TLS handshake completed")
  let inputClosed = XCTestExpectation(description: "peer received the listener's TLS shutdown")
  let channel = MultiThreadedEventLoopGroup.singleton.next().makePromise(of: (any Channel).self)

  func provider(port: Int) throws -> TLSChannelProvider {
    try TLSChannelProvider(origin: URL(string: "https://127.0.0.1:\(port)")!) { initialize in
      let peer = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
        .channelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
        .channelInitializer { channel in
          initialize(channel).flatMap { channel.pipeline.addHandler(self) }
        }.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: port)).get()
      self.channel.succeed(peer)
      return peer
    }
  }

  func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
    if let tls = event as? TLSUserEvent, case .handshakeCompleted = tls { ready.fulfill() }
    if let event = event as? ChannelEvent, case .inputClosed = event { inputClosed.fulfill() }
    context.fireUserInboundEventTriggered(event)
  }
}
#endif
