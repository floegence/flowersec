import { createServer as createHTTPSServer, type Server as HTTPSServer } from "node:https";
import { createRequire } from "node:module";
import { constants } from "node:crypto";

import type { CarrierSessionV3 } from "../v3/carrier.js";
import type { PathKind } from "../v3/contract.js";
import { createServerWebSocketCarrierSessionV3 } from "../v3/webSocketCarrier.js";
import { WebSocketBinaryTransport } from "../ws-client/binaryTransport.js";
import { defaultWsMaxPayload } from "./wsDefaults.js";

export type NodeWebSocketListenerOptionsV3 = Readonly<{
  host: string;
  port: number;
  path: PathKind;
  tls: Readonly<{ certificate: string; privateKey: string }>;
  allowedOrigins: readonly string[];
  inboundBidirectionalStreamCapacity: number;
}>;

export type NodeWebSocketListenerV3 = Readonly<{
  address(): Readonly<{ host: string; port: number }>;
  accept(options?: Readonly<{ signal?: AbortSignal }>): Promise<CarrierSessionV3>;
  close(): Promise<void>;
}>;

export async function startNodeWebSocketListenerV3(
  options: NodeWebSocketListenerOptionsV3,
): Promise<NodeWebSocketListenerV3> {
  validateOptions(options);
  const protocol = options.path === "direct" ? "flowersec.direct.v3" : "flowersec.tunnel.v3";
  const endpoint = `/flowersec/v3/${options.path}`;
  const require = createRequire(import.meta.url);
  const wsModule = require("ws") as any;
  const WebSocketServer = wsModule.WebSocketServer;
  const server: HTTPSServer = createHTTPSServer({
    key: options.tls.privateKey,
    cert: options.tls.certificate,
    minVersion: "TLSv1.3",
    maxVersion: "TLSv1.3",
    secureOptions: constants.SSL_OP_NO_TICKET,
  });
  const sessions = new SessionQueueV3();
  const sockets = new Set<any>();
  const wss = new WebSocketServer({
    noServer: true,
    perMessageDeflate: false,
    maxPayload: defaultWsMaxPayload({}),
    handleProtocols(protocols: Set<string>) { return protocols.size === 1 && protocols.has(protocol) ? protocol : false; },
  });
  server.on("upgrade", (request, socket, head) => {
    const origin = request.headers.origin;
    const requested = request.headers["sec-websocket-protocol"];
    if (request.url !== endpoint || typeof origin !== "string" ||
        !options.allowedOrigins.includes(origin) || requested !== protocol) {
      socket.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
      socket.destroy();
      return;
    }
    wss.handleUpgrade(request, socket, head, (webSocket: any) => wss.emit("connection", webSocket));
  });
  wss.on("connection", (socket: any) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    sessions.push(createServerWebSocketCarrierSessionV3(new WebSocketBinaryTransport(socket), {
      path: options.path,
      inboundBidirectionalStreamCapacity: options.inboundBidirectionalStreamCapacity,
    }));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port, options.host, resolve);
  });
  let closed = false;
  return Object.freeze({
    address() {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("Node WebSocket v3 listener is not listening");
      return Object.freeze({ host: address.address, port: address.port });
    },
    async accept(acceptOptions = {}) { return await sessions.shift(acceptOptions.signal); },
    async close() {
      if (closed) return;
      closed = true;
      sessions.close();
      for (const socket of sockets) socket.close();
      wss.close();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => error === undefined ? resolve() : reject(error)));
    },
  });
}

function validateOptions(options: NodeWebSocketListenerOptionsV3): void {
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65_535 ||
      options.allowedOrigins.length === 0 || new Set(options.allowedOrigins).size !== options.allowedOrigins.length ||
      options.allowedOrigins.some((origin) => !validOrigin(origin)) ||
      !Number.isInteger(options.inboundBidirectionalStreamCapacity) ||
      options.inboundBidirectionalStreamCapacity < 3 || options.inboundBidirectionalStreamCapacity > 130 ||
      options.tls.certificate.length === 0 || options.tls.privateKey.length === 0) {
    throw new TypeError("invalid Node WebSocket v3 listener options");
  }
}

function validOrigin(raw: string): boolean {
  try {
    const value = new URL(raw);
    return (value.protocol === "https:" || value.protocol === "http:") && value.origin === raw &&
      value.username === "" && value.password === "";
  } catch {
    return false;
  }
}

class SessionQueueV3 {
  private readonly values: CarrierSessionV3[] = [];
  private readonly waiters = new Set<Readonly<{
    resolve(value: CarrierSessionV3): void;
    reject(error: Error): void;
  }>>();
  private closed = false;

  push(value: CarrierSessionV3): void {
    if (this.closed) { void value.close(); return; }
    const waiter = this.waiters.values().next().value;
    if (waiter === undefined) this.values.push(value);
    else { this.waiters.delete(waiter); waiter.resolve(value); }
  }

  async shift(signal?: AbortSignal): Promise<CarrierSessionV3> {
    if (signal?.aborted === true) throw signal.reason ?? new Error("accept canceled");
    const value = this.values.shift();
    if (value !== undefined) return value;
    if (this.closed) throw new Error("WebSocket v3 listener is closed");
    return await new Promise<CarrierSessionV3>((resolve, reject) => {
      const waiter = {
        resolve: (session: CarrierSessionV3) => { cleanup(); resolve(session); },
        reject: (error: Error) => { cleanup(); reject(error); },
      };
      const abort = () => {
        this.waiters.delete(waiter);
        reject(signal?.reason ?? new Error("accept canceled"));
      };
      const cleanup = () => signal?.removeEventListener("abort", abort);
      this.waiters.add(waiter);
      signal?.addEventListener("abort", abort, { once: true });
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    const error = new Error("WebSocket v3 listener is closed");
    for (const waiter of this.waiters) waiter.reject(error);
    this.waiters.clear();
    for (const value of this.values) void value.close();
    this.values.length = 0;
  }
}
