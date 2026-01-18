import type { ClientPath } from "../client.js";

export type ConnectResult = "ok" | "fail";
export type ConnectReason = "websocket_error" | "websocket_closed" | "timeout" | "canceled";

export type AttachResult = "ok" | "fail";
export type AttachReason = "send_failed";

export type HandshakeResult = "ok" | "fail";
export type HandshakeReason = "handshake_error" | "timeout" | "canceled";

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
  onConnect(path: ClientPath, result: ConnectResult, reason: ConnectReason | undefined, elapsedSeconds: number): void;
  onAttach(result: AttachResult, reason: AttachReason | undefined): void;
  onHandshake(path: ClientPath, result: HandshakeResult, reason: HandshakeReason | undefined, elapsedSeconds: number): void;
  onWsClose(kind: WsCloseKind, code?: number): void;
  onWsError(reason: WsErrorReason): void;
  onRpcCall(result: RpcCallResult, elapsedSeconds: number): void;
  onRpcNotify(): void;
};

export type ClientObserverLike = Partial<ClientObserver>;

export const NoopObserver: ClientObserver = {
  onConnect: () => {},
  onAttach: () => {},
  onHandshake: () => {},
  onWsClose: () => {},
  onWsError: () => {},
  onRpcCall: () => {},
  onRpcNotify: () => {}
};

export function normalizeObserver(observer?: ClientObserverLike): ClientObserver {
  if (observer == null) return NoopObserver;
  return {
    onConnect: observer.onConnect ?? NoopObserver.onConnect,
    onAttach: observer.onAttach ?? NoopObserver.onAttach,
    onHandshake: observer.onHandshake ?? NoopObserver.onHandshake,
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
