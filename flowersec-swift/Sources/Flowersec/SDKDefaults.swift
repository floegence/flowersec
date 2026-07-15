import Foundation

public enum FlowersecSDKDefaults {
  public enum Transport {
    public static let connectTimeout: Duration = .seconds(10)
    public static let handshakeTimeout: Duration = .seconds(10)
    public static let handshakeClockSkew: Duration = .seconds(30)
  }

  public enum E2EE {
    public static let maxHandshakePayloadBytes = 8 * 1024
    public static let maxRecordBytes = 1024 * 1024
    public static let outboundRecordChunkBytes = 64 * 1024
    public static let maxOutboundBufferedBytes = 4 * 1024 * 1024
  }

  public enum Yamux {
    public static let maxActiveStreams = 64
    public static let maxInboundStreams = 32
    public static let maxFrameBytes = 256 * 1024
    public static let preferredOutboundFrameBytes = 64 * 1024
    public static let maxStreamReceiveBytes = 256 * 1024
    public static let maxSessionReceiveBytes = 16 * 1024 * 1024
  }

  public enum RPC {
    public static let maxJSONFrameBytes = 1024 * 1024
    public static let maxConcurrentRequests = 32
    public static let maxQueuedRequests = 128
    public static let maxQueuedNotifications = 128
  }

  public enum Controlplane {
    public static let maxRequestBodyBytes = 32 * 1024
    public static let maxResponseBodyBytes = 1024 * 1024
  }

  public enum Proxy {
    public static let maxJSONFrameBytes = 1024 * 1024
    public static let maxChunkBytes = 256 * 1024
    public static let maxBodyBytes = 64 * 1024 * 1024
    public static let maxWSFrameBytes = 1024 * 1024
    public static let defaultTimeoutMilliseconds = 30_000
    public static let maxTimeoutMilliseconds = 300_000
  }

  public enum Reconnect {
    public static let maxAttempts = 5
    public static let initialDelayMilliseconds = 500
    public static let maxDelayMilliseconds = 10_000
    public static let factor = 1.8
    public static let jitterRatio = 0.2
  }
}
