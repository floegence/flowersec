import Foundation
import NIOCore

/// An application-owned byte channel for one exact signed private loopback endpoint.
/// The initializer runs before activation or byte delivery. The connector honors
/// cancellation and closes partial opens; one close must preserve sibling streams.
/// Flowersec owns the upgrade, signed local policy and session authentication.
public struct HTTPDirectChannelProvider: Sendable, CustomStringConvertible {
  public typealias Initializer = TLSChannelProvider.Initializer
  public typealias Connect = TLSChannelProvider.Connect
  let hostname: String
  let port: Int
  let connect: Connect
  public init(endpoint: URL, connect: @escaping Connect) throws {
    guard let parts = URLComponents(url: endpoint, resolvingAgainstBaseURL: false),
      parts.scheme == "ws", let host = parts.host, let port = parts.port,
      parts.path == "/flowersec/v4/local", parts.user == nil, parts.password == nil,
      parts.query == nil, parts.fragment == nil, (1024...65535).contains(port)
    else { throw TLSChannelError.invalidOrigin }
    let name = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
    guard V4CredentialText.isLoopbackAddress(name) else { throw TLSChannelError.invalidOrigin }
    hostname = name; self.port = port; self.connect = connect
  }
  public var description: String { "HTTPDirectChannelProvider(<redacted>)" }
  func matches(host: String, port: Int) -> Bool { hostname == host && self.port == port }
  func openInitialized(_ initializer: @escaping Initializer) async throws -> any Channel {
    try Task.checkCancellation()
    let channel = try await connect(initializer)
    do { try Task.checkCancellation(); return channel }
    catch { try? await channel.close().get(); throw error }
  }
}
