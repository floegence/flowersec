export const SDK_DEFAULTS = Object.freeze({
  transport: Object.freeze({
    connectTimeoutMs: 10_000,
    handshakeTimeoutMs: 10_000,
    handshakeClockSkewMs: 30_000,
  }),
  e2ee: Object.freeze({
    maxHandshakePayloadBytes: 8 * 1024,
    maxRecordBytes: 1024 * 1024,
    outboundRecordChunkBytes: 64 * 1024,
    maxInboundBufferedBytes: 4 * 1024 * 1024,
    maxOutboundBufferedBytes: 4 * 1024 * 1024,
  }),
  yamux: Object.freeze({
    maxActiveStreams: 64,
    maxInboundStreams: 32,
    maxFrameBytes: 256 * 1024,
    preferredOutboundFrameBytes: 64 * 1024,
    maxStreamWriteQueueBytes: 4 * 1024 * 1024,
    maxStreamReceiveBytes: 256 * 1024,
    maxSessionReceiveBytes: 16 * 1024 * 1024,
  }),
  rpc: Object.freeze({
    maxJsonFrameBytes: 1024 * 1024,
    maxConcurrentRequests: 32,
    maxQueuedRequests: 128,
    maxQueuedNotifications: 128,
  }),
  controlplane: Object.freeze({
    maxRequestBodyBytes: 32 * 1024,
    maxResponseBodyBytes: 1024 * 1024,
  }),
  proxy: Object.freeze({
    maxJsonFrameBytes: 1024 * 1024,
    maxChunkBytes: 256 * 1024,
    maxBodyBytes: 64 * 1024 * 1024,
    maxWsFrameBytes: 1024 * 1024,
    defaultTimeoutMs: 30_000,
    maxTimeoutMs: 300_000,
  }),
  reconnect: Object.freeze({
    maxAttempts: 5,
    initialDelayMs: 500,
    maxDelayMs: 10_000,
    factor: 1.8,
    jitterRatio: 0.2,
  }),
});
