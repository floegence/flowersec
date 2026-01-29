export const PROXY_PROTOCOL_VERSION = 1 as const;

export const PROXY_KIND_HTTP1 = "flowersec-proxy/http1" as const;
export const PROXY_KIND_WS = "flowersec-proxy/ws" as const;

export const DEFAULT_MAX_CHUNK_BYTES = 256 * 1024;
export const DEFAULT_MAX_BODY_BYTES = 64 * 1024 * 1024;
export const DEFAULT_MAX_WS_FRAME_BYTES = 1024 * 1024;

export const DEFAULT_DEFAULT_TIMEOUT_MS = 30_000;
export const DEFAULT_MAX_TIMEOUT_MS = 5 * 60_000;

