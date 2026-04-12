import type { Header } from "./types.js";

export const PROXY_WINDOW_FETCH_FORWARD_MSG_TYPE = "flowersec-proxy:window_fetch";
export const PROXY_WINDOW_FETCH_MSG_TYPE = "flowersec-proxy:fetch";
export const PROXY_WINDOW_WS_OPEN_MSG_TYPE = "flowersec-proxy:ws_open";
export const PROXY_WINDOW_WS_OPEN_ACK_MSG_TYPE = "flowersec-proxy:ws_open_ack";
export const PROXY_WINDOW_WS_ERROR_MSG_TYPE = "flowersec-proxy:ws_error";
export const PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE = "flowersec-proxy:stream_chunk";
export const PROXY_WINDOW_STREAM_END_MSG_TYPE = "flowersec-proxy:stream_end";
export const PROXY_WINDOW_STREAM_RESET_MSG_TYPE = "flowersec-proxy:stream_reset";
export const PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE = "flowersec-proxy:stream_close";

export type ProxyWindowFetchRequest = Readonly<{
  id: string;
  method: string;
  path: string;
  headers: readonly Header[];
  external_origin?: string;
  body?: ArrayBuffer;
}>;

export type ProxyWindowFetchForwardMsg = Readonly<{
  type: typeof PROXY_WINDOW_FETCH_FORWARD_MSG_TYPE;
  req: ProxyWindowFetchRequest;
}>;

export type ProxyWindowFetchMsg = Readonly<{
  type: typeof PROXY_WINDOW_FETCH_MSG_TYPE;
  req: ProxyWindowFetchRequest;
}>;

export type ProxyWindowWsOpenMsg = Readonly<{
  type: typeof PROXY_WINDOW_WS_OPEN_MSG_TYPE;
  path: string;
  protocols?: readonly string[];
}>;

export type ProxyWindowWsOpenAckMsg = Readonly<{
  type: typeof PROXY_WINDOW_WS_OPEN_ACK_MSG_TYPE;
  protocol: string;
}>;

export type ProxyWindowWsErrorMsg = Readonly<{
  type: typeof PROXY_WINDOW_WS_ERROR_MSG_TYPE;
  message: string;
}>;

export type ProxyWindowStreamChunkMsg = Readonly<{
  type: typeof PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE;
  data: ArrayBuffer;
}>;

export type ProxyWindowStreamEndMsg = Readonly<{
  type: typeof PROXY_WINDOW_STREAM_END_MSG_TYPE;
}>;

export type ProxyWindowStreamResetMsg = Readonly<{
  type: typeof PROXY_WINDOW_STREAM_RESET_MSG_TYPE;
  message: string;
}>;

export type ProxyWindowStreamCloseMsg = Readonly<{
  type: typeof PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE;
}>;
