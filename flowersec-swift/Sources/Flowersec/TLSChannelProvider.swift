import Foundation
import NIOCore

#if os(macOS) || os(iOS)
  import NIOSSL
#endif

public enum TLSChannelError: Error, Sendable { case invalidOrigin, unsupported, verificationFailed }

/// Application-owned byte channels bound to one canonical HTTPS origin.
/// Connect must run the initializer on the event loop before activation, honor
/// cancellation, and close partial opens. Flowersec installs target TLS inside
/// this transport; closing one channel must not close sibling streams.
public struct TLSChannelProvider: Sendable, CustomStringConvertible, CustomReflectable {
  public typealias Initializer = @Sendable (any Channel) -> EventLoopFuture<Void>
  public typealias Connect = @Sendable (@escaping Initializer) async throws -> any Channel
  let hostname: String
  let port: Int
  let connect: Connect

  public init(origin: URL, connect: @escaping Connect) throws {
    guard let parts = URLComponents(url: origin, resolvingAgainstBaseURL: false),
      parts.scheme == "https", let host = parts.host, !host.isEmpty,
      parts.path.isEmpty, parts.user == nil, parts.password == nil,
      parts.query == nil, parts.fragment == nil,
      (1...65535).contains(parts.port ?? 443)
    else { throw TLSChannelError.invalidOrigin }
    let name = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
    guard V4CredentialText.addressBytes(name) != nil || (try? IDNAHost.lookupASCII(name)) == name else {
      throw TLSChannelError.invalidOrigin
    }
    hostname = name; port = parts.port ?? 443; self.connect = connect
  }

  public var description: String { "TLSChannelProvider(<redacted>)" }
  public var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }

  /// Opens a CA-verified TLS 1.3 channel, using platform or replacement PEM roots.
  /// The initializer runs after TLS handlers are installed and before activation.
  /// Callers own timeout, cancellation and channel close; there is no direct fallback.
  public func openChannel(trustRootsPEM: [Data] = [], initializer: @escaping Initializer) async throws -> any Channel {
    #if os(macOS) || os(iOS)
      guard trustRootsPEM.count <= 16, trustRootsPEM.reduce(0, { $0 + $1.count }) <= 262144 else {
        throw TLSChannelError.verificationFailed
      }
      var tls = TLSConfiguration.makeClientConfiguration()
      tls.minimumTLSVersion = .tlsv13; tls.maximumTLSVersion = .tlsv13
      tls.certificateVerification = V4CredentialText.addressBytes(hostname) == nil ? .fullVerification : .noHostnameVerification
      if !trustRootsPEM.isEmpty {
        let roots = try trustRootsPEM.flatMap { try NIOSSLCertificate.fromPEMBytes(Array($0)) }
        guard !roots.isEmpty, roots.count <= 16 else { throw TLSChannelError.verificationFailed }
        tls.trustRoots = .certificates(roots)
      }
      let context = try NIOSSLContext(configuration: tls), host = hostname
      return try await openInitialized { channel in
        do {
          let handler = try NIOSSLClientHandler._makeSSLClientHandler(context: context,
            serverHostname: V4CredentialText.addressBytes(host) == nil ? host : nil,
            additionalPeerCertificateVerificationCallback: { certificate, channel in
              guard V4NativeWebSocketTLS.matchesIdentity(certificate, host: host) else {
                return channel.eventLoop.makeFailedFuture(TLSChannelError.verificationFailed)
              }
              return channel.eventLoop.makeSucceededVoidFuture()
            })
          try channel.pipeline.syncOperations.addHandler(handler)
          return channel.pipeline.addHandler(TLSChannelErrorHandler()).flatMap { initializer(channel) }
        } catch { return channel.eventLoop.makeFailedFuture(error) }
      }
    #else
      throw TLSChannelError.unsupported
    #endif
  }

  func matches(host: String, port: Int) -> Bool { hostname == host && self.port == port }

  func openInitialized(_ initializer: @escaping Initializer) async throws -> any Channel {
    try Task.checkCancellation()
    let channel = try await connect(initializer)
    do { try Task.checkCancellation(); return channel }
    catch { try? await channel.close().get(); throw error }
  }
}

#if os(macOS) || os(iOS)
private final class TLSChannelErrorHandler: ChannelInboundHandler, Sendable {
  typealias InboundIn = ByteBuffer
  func errorCaught(context: ChannelHandlerContext, error: any Error) {
    if error is NIOSSLError || error is NIOSSLExtraError || error is BoringSSLError {
      context.fireErrorCaught(TLSChannelError.verificationFailed)
    } else { context.fireErrorCaught(error) }
  }
}
#endif
