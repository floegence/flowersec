export type TunnelConnectResult = "ok" | "fail";
export type TunnelConnectReason = "websocket_error" | "websocket_closed";

export type TunnelAttachResult = "ok" | "fail";
export type TunnelAttachReason = "send_failed";

export type TunnelHandshakeResult = "ok" | "fail";
export type TunnelHandshakeReason = "handshake_error";

export type WsCloseKind = "local" | "peer_or_error";

export type WsErrorReason =
  | "error"
  | "recv_buffer_exceeded"
  | "unexpected_text_frame"
  | "unexpected_message_type";

export type RpcCallResult =
  | "ok"
  | "rpc_error"
  | "handler_not_found"
  | "transport_error"
  | "canceled";

export type ClientObserver = {
  onTunnelConnect(result: TunnelConnectResult, reason: TunnelConnectReason | undefined, elapsedSeconds: number): void;
  onTunnelAttach(result: TunnelAttachResult, reason: TunnelAttachReason | undefined): void;
  onTunnelHandshake(result: TunnelHandshakeResult, reason: TunnelHandshakeReason | undefined, elapsedSeconds: number): void;
  onWsClose(kind: WsCloseKind, code?: number): void;
  onWsError(reason: WsErrorReason): void;
  onRpcCall(result: RpcCallResult, elapsedSeconds: number): void;
  onRpcNotify(): void;
};

export type ClientObserverLike = Partial<ClientObserver>;

export const NoopObserver: ClientObserver = {
  onTunnelConnect: () => {},
  onTunnelAttach: () => {},
  onTunnelHandshake: () => {},
  onWsClose: () => {},
  onWsError: () => {},
  onRpcCall: () => {},
  onRpcNotify: () => {}
};

export function normalizeObserver(observer?: ClientObserverLike): ClientObserver {
  if (observer == null) return NoopObserver;
  return {
    onTunnelConnect: observer.onTunnelConnect ?? NoopObserver.onTunnelConnect,
    onTunnelAttach: observer.onTunnelAttach ?? NoopObserver.onTunnelAttach,
    onTunnelHandshake: observer.onTunnelHandshake ?? NoopObserver.onTunnelHandshake,
    onWsClose: observer.onWsClose ?? NoopObserver.onWsClose,
    onWsError: observer.onWsError ?? NoopObserver.onWsError,
    onRpcCall: observer.onRpcCall ?? NoopObserver.onRpcCall,
    onRpcNotify: observer.onRpcNotify ?? NoopObserver.onRpcNotify
  };
}

export function nowSeconds(): number {
  if (typeof performance !== "undefined" && typeof performance.now === "function") {
    return performance.now() / 1000;
  }
  return Date.now() / 1000;
}
