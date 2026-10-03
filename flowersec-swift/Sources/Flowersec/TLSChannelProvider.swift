import Foundation
import NIOCore

/// Supplies application-owned byte streams bound to one canonical HTTPS origin.
///
/// The application authenticates and binds its outer transport before creating
/// this provider. Each connection must initialize its pipeline on the event loop
/// before activation or byte delivery, honor cancellation, and close partial opens.
/// Flowersec installs and verifies end-to-end TLS inside the supplied transport.
/// Closing a channel must release that stream without closing sibling streams.
public struct TLSChannelProvider: Sendable, CustomStringConvertible, CustomReflectable {
  public typealias Initializer = @Sendable (any Channel) -> EventLoopFuture<Void>
  public typealias Connect = @Sendable (@escaping Initializer) async throws -> any Channel

  let origin: String
  let hostname: String
  let connect: Connect

  public init(origin: URL, connect: @escaping Connect) throws {
    guard var parts = URLComponents(url: origin, resolvingAgainstBaseURL: false),
      parts.scheme == "https", let host = parts.host, !host.isEmpty,
      parts.path.isEmpty, parts.user == nil, parts.password == nil,
      parts.query == nil, parts.fragment == nil
    else { throw ArtifactError.invalidArtifact }
    parts.scheme = "wss"
    parts.path = TransportV3Contract.directWebSocketPath
    guard let endpoint = parts.url,
      try ArtifactCodecV3.normalizeURL(
        endpoint.absoluteString, carrier: "websocket", kind: "direct")
        == endpoint.absoluteString
    else { throw ArtifactError.invalidArtifact }
    self.origin = origin.absoluteString
    self.hostname = host
    self.connect = connect
  }

  public var description: String { "TLSChannelProvider(<redacted>)" }
  public var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }

  /// Opens a CA-verified TLS 1.3 channel for same-origin application HTTP requests.
  ///
  /// The initializer installs application handlers after TLS and before activation.
  /// TLS errors arrive through the pipeline; callers must close on completion,
  /// failure, cancellation, or timeout. No plaintext or direct-network fallback is
  /// performed. Empty roots use platform trust; supplied PEM roots replace it.
  public func openChannel(
    trustRootsPEM: [Data] = [], initializer: @escaping Initializer
  ) async throws -> any Channel {
    #if os(macOS) || os(iOS)
      let handler = try NativeTLSPolicyAdapterV3.makeCAClientHandlerFactory(
        serverHostname: hostname, trustRootsPEM: trustRootsPEM)
      return try await openChannel(tlsHandler: handler, initializer: initializer)
    #else
      throw ConnectError.transportSecurityUnsupported
    #endif
  }

  #if os(macOS) || os(iOS)
    func openChannel(
      tlsHandler: ProxyTLSClientHandler,
      initializer: @escaping Initializer
    ) async throws -> any Channel {
      try Task.checkCancellation()
      let channel = try await connect { channel in
        do {
          try channel.pipeline.syncOperations.addHandler(tlsHandler.make())
          return initializer(channel)
        } catch {
          return channel.eventLoop.makeFailedFuture(error)
        }
      }
      do {
        try Task.checkCancellation()
        return channel
      } catch {
        try? await channel.close().get()
        throw error
      }
    }
  #endif

  func matches(_ endpoint: URL) -> Bool {
    guard var parts = URLComponents(url: endpoint, resolvingAgainstBaseURL: false),
      parts.scheme == "wss", parts.user == nil, parts.password == nil,
      parts.query == nil, parts.fragment == nil
    else { return false }
    parts.scheme = "https"
    parts.path = ""
    return parts.url?.absoluteString == origin
  }
}
