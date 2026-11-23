import Foundation
import NIOCore

/// Supplies an application-owned byte channel for one exact HTTPDirect endpoint.
///
/// The application authenticates the outer transport and binds it to the endpoint
/// before constructing this value. The initializer must run on the channel's
/// event loop before any bytes are delivered. Inbound and outbound values are
/// NIO `ByteBuffer`s. Flowersec owns the WebSocket upgrade and session protocol;
/// closing the supplied channel must close only this connection's byte stream.
/// The connector must honor cancellation and close partially opened channels.
/// This API does not enable plaintext transport for ordinary TLS artifacts.
public struct HTTPDirectChannelProvider: Sendable, CustomStringConvertible {
  public typealias Initializer = @Sendable (any Channel) -> EventLoopFuture<Void>
  public typealias Connect = @Sendable (@escaping Initializer) async throws -> any Channel

  let endpoint: String
  let connect: Connect

  public init(endpoint: URL, connect: @escaping Connect) throws {
    self.endpoint = try HTTPDirectEndpointV1(endpoint.absoluteString).url.absoluteString
    self.connect = connect
  }

  public var description: String { "HTTPDirectChannelProvider(<redacted>)" }
}
