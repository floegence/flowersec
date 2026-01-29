export type Header = Readonly<{ name: string; value: string }>;

export type ProxyError = Readonly<{ code: string; message: string }>;

export type HttpRequestMetaV1 = Readonly<{
  v: 1;
  request_id: string;
  method: string;
  path: string;
  headers: Header[];
  timeout_ms?: number;
}>;

export type HttpResponseMetaV1 = Readonly<{
  v: 1;
  request_id: string;
  ok: boolean;
  status?: number;
  headers?: Header[];
  error?: ProxyError;
}>;

export type WsOpenMetaV1 = Readonly<{
  v: 1;
  conn_id: string;
  path: string;
  headers: Header[];
}>;

export type WsOpenRespV1 = Readonly<{
  v: 1;
  conn_id: string;
  ok: boolean;
  protocol?: string;
  error?: ProxyError;
}>;

