import { createServer as createHTTPServer, type Server as HTTPServer } from "node:http";
import { createServer as createHTTPSServer, type Server as HTTPSServer } from "node:https";
import { createRequire } from "node:module";
import { isIP } from "node:net";

import { createServerWebSocketCarrierSessionV2 } from "../transport/webSocketAdapter.js";
import { WebSocketBinaryTransport } from "../ws-client/binaryTransport.js";
import type { CarrierSessionV2 } from "../v2/carrier.js";
import type { PathKind } from "../v2/contract.js";
import { defaultWsMaxPayload } from "./wsDefaults.js";

export type NodeWebSocketServerOptions = Readonly<{
  host: string;
  port: number;
  path: PathKind;
  tls?: Readonly<{ certificate: string; privateKey: string }>;
  allowedOrigins: readonly string[];
  inboundBidirectionalStreamCapacity: number;
}>;

export type NodeWebSocketServer = Readonly<{
  address(): Readonly<{ host: string; port: number }>;
  accept(options?: Readonly<{ signal?: AbortSignal }>): Promise<CarrierSessionV2>;
  close(): Promise<void>;
}>;

export async function startNodeWebSocketServer(options: NodeWebSocketServerOptions): Promise<NodeWebSocketServer> {
  validateOptions(options);
  const protocol = options.path === "direct" ? "flowersec.direct.v2" : "flowersec.tunnel.v2";
  const endpoint = "/flowersec/v2/" + options.path;
  const require = createRequire(import.meta.url);
  const wsModule = require("ws") as any;
  const WebSocketServer = wsModule.WebSocketServer;
  const server: HTTPServer | HTTPSServer = options.tls === undefined
    ? createHTTPServer()
    : createHTTPSServer({ key: options.tls.privateKey, cert: options.tls.certificate, minVersion: "TLSv1.3", maxVersion: "TLSv1.3" });
  const sessions = new SessionQueue();
  const sockets = new Set<any>();
  const wss = new WebSocketServer({
    noServer: true,
    perMessageDeflate: false,
    maxPayload: defaultWsMaxPayload({}),
    handleProtocols(protocols: Set<string>) { return protocols.has(protocol) ? protocol : false; },
  });
  server.on("upgrade", (request, socket, head) => {
    const origin = request.headers.origin;
    const requested = request.headers["sec-websocket-protocol"];
    const remote = request.socket.remoteAddress;
    const local = request.socket.localAddress;
    const plaintextAllowed = options.tls === undefined && options.path === "direct" && isLoopback(remote) && isLoopback(local);
    if (request.url !== endpoint || typeof origin !== "string" || !options.allowedOrigins.includes(origin) || requested !== protocol || (options.tls === undefined && !plaintextAllowed)) {
      socket.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
      socket.destroy();
      return;
    }
    wss.handleUpgrade(request, socket, head, (webSocket: any) => wss.emit("connection", webSocket));
  });
  wss.on("connection", (socket: any) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    const transport = new WebSocketBinaryTransport(socket);
    sessions.push(createServerWebSocketCarrierSessionV2(transport, {
      path: options.path,
      inboundBidirectionalStreamCapacity: options.inboundBidirectionalStreamCapacity,
    }));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port, options.host, resolve);
  });
  let closed = false;
  return {
    address() {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("Node WebSocket server is not listening");
      return Object.freeze({ host: address.address, port: address.port });
    },
    async accept(acceptOptions = {}) { return await sessions.shift(acceptOptions.signal); },
    async close() {
      if (closed) return;
      closed = true;
      sessions.close();
      for (const socket of sockets) socket.close();
      wss.close();
      await new Promise<void>((resolve, reject) => server.close((error) => error === undefined ? resolve() : reject(error)));
    },
  };
}

function validateOptions(options: NodeWebSocketServerOptions): void {
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65_535 || options.allowedOrigins.length === 0) {
    throw new TypeError("invalid Node WebSocket listener options");
  }
  if (options.tls === undefined && (options.path !== "direct" || !isLoopback(options.host))) {
    throw new TypeError("plaintext WebSocket is restricted to direct loopback listeners");
  }
}

function isLoopback(address: string | undefined): boolean {
  if (address === undefined) return false;
  if (address === "::1") return true;
  if (isIP(address) === 4) return address.startsWith("127.");
  return address.toLowerCase().startsWith("::ffff:127.");
}

class SessionQueue {
  private readonly values: CarrierSessionV2[] = [];
  private readonly waiters = new Set<Readonly<{ resolve(value: CarrierSessionV2): void; reject(error: Error): void }>>();
  private closed = false;

  push(value: CarrierSessionV2): void {
    if (this.closed) { void value.close(); return; }
    const waiter = this.waiters.values().next().value;
    if (waiter === undefined) this.values.push(value);
    else { this.waiters.delete(waiter); waiter.resolve(value); }
  }

  async shift(signal?: AbortSignal): Promise<CarrierSessionV2> {
    if (signal?.aborted === true) throw new Error("accept canceled");
    const value = this.values.shift();
    if (value !== undefined) return value;
    if (this.closed) throw new Error("WebSocket listener is closed");
    return await new Promise<CarrierSessionV2>((resolve, reject) => {
      const waiter = { resolve: (session: CarrierSessionV2) => { cleanup(); resolve(session); }, reject };
      const abort = () => { this.waiters.delete(waiter); reject(new Error("accept canceled")); };
      const cleanup = () => signal?.removeEventListener("abort", abort);
      this.waiters.add(waiter);
      signal?.addEventListener("abort", abort, { once: true });
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    const error = new Error("WebSocket listener is closed");
    for (const waiter of this.waiters) waiter.reject(error);
    this.waiters.clear();
    for (const value of this.values) void value.close();
    this.values.length = 0;
  }
}
