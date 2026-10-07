export const SDK_DEFAULTS = Object.freeze({
  transport: Object.freeze({
    connectTimeoutMs: 10_000,
    handshakeTimeoutMs: 10_000,
    handshakeClockSkewMs: 30_000,
  }),
  connectionController: Object.freeze({
    initialDelayMs: 250,
    maxDelayMs: 30_000,
    factor: 2,
    jitterRatio: 0,
    defaultAttemptLimit: null,
  }),
  controlplane: Object.freeze({
    maxRequestBodyBytes: 32 * 1024,
    maxResponseBodyBytes: 1024 * 1024,
  }),
  proxy: Object.freeze({
    maxMetadataBytes: 1024 * 1024,
    maxChunkBytes: 256 * 1024,
    maxBodyBytes: 64 * 1024 * 1024,
    maxWsFrameBytes: 1024 * 1024,
    maxConcurrentStreams: 64,
    defaultTimeoutMs: 30_000,
    maxTimeoutMs: 300_000,
  }),
});
