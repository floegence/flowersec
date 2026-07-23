import Foundation

internal enum FlowersecSDKDefaults {
  internal enum Transport {
    internal static let connectTimeout: Duration = .seconds(10)
    internal static let handshakeTimeout: Duration = .seconds(10)
    internal static let handshakeClockSkew: Duration = .seconds(30)
  }

  internal enum E2EE {
    internal static let maxHandshakePayloadBytes = 8 * 1024
    internal static let maxRecordBytes = 1024 * 1024
    internal static let outboundRecordChunkBytes = 64 * 1024
    internal static let maxInboundBufferedBytes = 4 * 1024 * 1024
    internal static let maxOutboundBufferedBytes = 4 * 1024 * 1024
  }

  internal enum Yamux {
    internal static let maxActiveStreams = 64
    internal static let maxInboundStreams = 32
    internal static let maxFrameBytes = 256 * 1024
    internal static let preferredOutboundFrameBytes = 64 * 1024
    internal static let maxStreamWriteQueueBytes = 4 * 1024 * 1024
    internal static let maxStreamReceiveBytes = 256 * 1024
    internal static let maxSessionReceiveBytes = 16 * 1024 * 1024
  }

  internal enum RPC {
    internal static let maxJSONFrameBytes = 1024 * 1024
    internal static let maxConcurrentRequests = 32
    internal static let maxQueuedRequests = 128
    internal static let maxQueuedNotifications = 128
  }

  internal enum Controlplane {
    internal static let maxRequestBodyBytes = 32 * 1024
    internal static let maxResponseBodyBytes = 1024 * 1024
  }

  internal enum Proxy {
    internal static let maxJSONFrameBytes = 1024 * 1024
    internal static let maxChunkBytes = 256 * 1024
    internal static let maxBodyBytes = 64 * 1024 * 1024
    internal static let maxWSFrameBytes = 1024 * 1024
    internal static let defaultTimeoutMilliseconds = 30_000
    internal static let maxTimeoutMilliseconds = 300_000
    internal static let maxConcurrentStreams = 64
  }

  internal enum Reconnect {
    internal static let maxAttempts = 5
    internal static let initialDelayMilliseconds = 500
    internal static let maxDelayMilliseconds = 10_000
    internal static let factor = 1.8
    internal static let jitterRatio = 0.2
  }
}
