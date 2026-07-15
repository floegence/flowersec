import type { WebSocketLike } from "../ws-client/binaryTransport.js";
import { createNodeWsFactory } from "../node/wsFactory.js";
import {
  acceptDirect,
  acceptDirectResolved,
  connectTunnel,
  type DirectAcceptOptions,
  type DirectCredentialResolver,
  type DirectHandshakeCredential,
  type Session,
  type Suite,
  type TunnelEndpointOptions,
} from "./index.js";

export function adaptNodeWebSocket(websocket: unknown): WebSocketLike {
  const raw = websocket as any;
  if (raw == null || typeof raw.send !== "function" || typeof raw.close !== "function") {
    throw new TypeError("a Node WebSocket is required");
  }
  if (typeof raw.addEventListener === "function" && typeof raw.removeEventListener === "function") {
    return raw as WebSocketLike;
  }

  const listeners = new Map<string, Map<(event: any) => void, (...args: any[]) => void>>();
  return {
    get binaryType() { return String(raw.binaryType ?? "nodebuffer"); },
    set binaryType(value: string) { raw.binaryType = value; },
    get readyState() { return Number(raw.readyState); },
    get bufferedAmount() { return Number(raw.bufferedAmount ?? 0); },
    send(data) { raw.send(data); },
    close(code, reason) { raw.close(code, reason); },
    addEventListener(type, listener) {
      const wrapped = (...args: any[]) => {
        if (type === "message") listener({ data: args[0] });
        else if (type === "close") listener({ code: args[0], reason: args[1]?.toString?.() ?? "" });
        else listener(args[0]);
      };
      const byListener = listeners.get(type) ?? new Map();
      byListener.set(listener, wrapped);
      listeners.set(type, byListener);
      raw.on(type, wrapped);
    },
    removeEventListener(type, listener) {
      const byListener = listeners.get(type);
      const wrapped = byListener?.get(listener);
      if (wrapped == null) return;
      byListener!.delete(listener);
      raw.off(type, wrapped);
    },
  };
}

export function acceptDirectNode(
  websocket: unknown,
  handshake: Readonly<{ channelId: string; suite: Suite }> & DirectHandshakeCredential,
  options: DirectAcceptOptions = {},
): Promise<Session> {
  return acceptDirect(adaptNodeWebSocket(websocket), handshake, options);
}

export function acceptDirectResolvedNode(
  websocket: unknown,
  resolver: DirectCredentialResolver,
  options: DirectAcceptOptions = {},
): Promise<Session> {
  return acceptDirectResolved(adaptNodeWebSocket(websocket), resolver, options);
}

export function connectTunnelEndpointNode(
  grant: unknown,
  options: Omit<TunnelEndpointOptions, "wsFactory">,
): Promise<Session> {
  return connectTunnel(grant, { ...options, wsFactory: createNodeWsFactory() });
}
