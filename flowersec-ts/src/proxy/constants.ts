import { SDK_DEFAULTS } from "../defaults.js";

export const PROXY_PROTOCOL_VERSION = 1 as const;

export const PROXY_KIND_HTTP1 = "flowersec-proxy/http1" as const;
export const PROXY_KIND_WS = "flowersec-proxy/ws" as const;

export const DEFAULT_MAX_CHUNK_BYTES = SDK_DEFAULTS.proxy.maxChunkBytes;
export const DEFAULT_MAX_BODY_BYTES = SDK_DEFAULTS.proxy.maxBodyBytes;
export const DEFAULT_MAX_WS_FRAME_BYTES = SDK_DEFAULTS.proxy.maxWsFrameBytes;
export const DEFAULT_MAX_CONCURRENT_STREAMS = SDK_DEFAULTS.proxy.maxConcurrentStreams;
