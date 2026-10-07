import Foundation

// Current runtime defaults. Signed transport limits and authority windows come
// from the original v4 contract and never inherit a generic SDK fallback.
internal enum FlowersecSDKDefaults {
  internal enum Transport {
    internal static let connectTimeoutMilliseconds: Int64 = 10_000
    internal static let handshakeTimeoutMilliseconds: UInt64 = 10_000
  }
  internal enum Proxy {
    internal static let maximumMetadataBytes = 1024 * 1024
    internal static let maximumChunkBytes = 256 * 1024
    internal static let maximumBodyBytes = 64 * 1024 * 1024
    internal static let maximumWebSocketFrameBytes = 1024 * 1024
    internal static let defaultTimeoutMilliseconds: UInt32 = 30_000
    internal static let maximumTimeoutMilliseconds: UInt32 = 300_000
    internal static let maximumConcurrentStreams = 64
  }
  internal enum ConnectionController {
    internal static let initialDelay: Duration = .milliseconds(250)
    internal static let maximumDelay: Duration = .seconds(30)
    internal static let multiplier: UInt64 = 2
  }
}
