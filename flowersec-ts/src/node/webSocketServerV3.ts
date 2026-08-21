import { createServer as createHTTPSServer, type Server as HTTPSServer } from "node:https";
import { createRequire } from "node:module";
import { constants } from "node:crypto";
import type { Socket } from "node:net";

import type { CarrierSessionV3 } from "../v3/carrier.js";
import type { PathKind } from "../v3/contract.js";
import { createServerWebSocketCarrierSessionV3 } from "../v3/webSocketCarrier.js";
import { WebSocketBinaryTransport } from "../ws-client/binaryTransport.js";
import { defaultWsMaxPayload } from "./wsDefaults.js";
import {
  FLOWERSEC_V3_PATHS,
  websocketSubprotocolForPathV3,
} from "../v3/transportConstants.js";

export type NodeWebSocketListenerOptionsV3 = Readonly<{
  host: string;
  port: number;
  path: PathKind;
  tls: Readonly<{ certificate: string; privateKey: string }>;
  allowedOrigins: readonly string[];
  inboundBidirectionalStreamCapacity: number;
  maxPendingSessions?: number;
  pendingSessionTimeoutMs?: number;
  cleanupTimeoutMs?: number;
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
  const maxPendingSessions = options.maxPendingSessions ?? 1_024;
  const pendingSessionTimeoutMs = options.pendingSessionTimeoutMs ?? 10_000;
  const cleanupTimeoutMs = options.cleanupTimeoutMs ?? 2_000;
  const protocol = websocketSubprotocolForPathV3(options.path);
  const endpoint = FLOWERSEC_V3_PATHS.websocket[options.path];
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
  const sessions = new SessionQueueV3(maxPendingSessions, pendingSessionTimeoutMs);
  const sockets = new Set<any>();
  const networkSockets = new Set<Socket>();
  const wss = new WebSocketServer({
    noServer: true,
    perMessageDeflate: false,
    maxPayload: defaultWsMaxPayload({}),
    handleProtocols(protocols: Set<string>) { return protocols.size === 1 && protocols.has(protocol) ? protocol : false; },
  });
  server.on("connection", (socket) => {
    networkSockets.add(socket);
    socket.once("close", () => networkSockets.delete(socket));
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
    const session = createServerWebSocketCarrierSessionV3(new WebSocketBinaryTransport(socket), {
      path: options.path,
      inboundBidirectionalStreamCapacity: options.inboundBidirectionalStreamCapacity,
    });
    socket.once("close", () => {
      sockets.delete(socket);
      sessions.remove(session);
    });
    sessions.push(session);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port, options.host, resolve);
  });
  let closePromise: Promise<void> | undefined;
  return Object.freeze({
    address() {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("Node WebSocket v3 listener is not listening");
      return Object.freeze({ host: address.address, port: address.port });
    },
    async accept(acceptOptions = {}) { return await sessions.shift(acceptOptions.signal); },
    async close() {
      closePromise ??= closeListener();
      await closePromise;
    },
  });

  async function closeListener(): Promise<void> {
    sessions.close();
    for (const socket of sockets) socket.close();
    const graceful = Promise.all([
      new Promise<void>((resolve, reject) => {
        wss.close((error?: Error) => error === undefined ? resolve() : reject(error));
      }),
      new Promise<void>((resolve, reject) => {
        server.close((error) => error === undefined ? resolve() : reject(error));
      }),
    ]);
    let timer: ReturnType<typeof setTimeout> | undefined;
    let timedOut: boolean;
    try {
      timedOut = await Promise.race([
        graceful.then(() => false),
        new Promise<true>((resolve) => {
          timer = setTimeout(() => resolve(true), cleanupTimeoutMs);
          timer.unref?.();
        }),
      ]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
    if (!timedOut) return;
    for (const socket of sockets) socket.terminate();
    for (const socket of networkSockets) socket.destroy();
  }
}

function validateOptions(options: NodeWebSocketListenerOptionsV3): void {
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65_535 ||
      options.allowedOrigins.length === 0 || new Set(options.allowedOrigins).size !== options.allowedOrigins.length ||
      options.allowedOrigins.some((origin) => !validOrigin(origin)) ||
      !Number.isInteger(options.inboundBidirectionalStreamCapacity) ||
      options.inboundBidirectionalStreamCapacity < 3 || options.inboundBidirectionalStreamCapacity > 130 ||
      (options.maxPendingSessions !== undefined && (!Number.isSafeInteger(options.maxPendingSessions) || options.maxPendingSessions < 1 || options.maxPendingSessions > 1_024)) ||
      (options.pendingSessionTimeoutMs !== undefined && (!Number.isSafeInteger(options.pendingSessionTimeoutMs) || options.pendingSessionTimeoutMs < 1 || options.pendingSessionTimeoutMs > 600_000)) ||
      (options.cleanupTimeoutMs !== undefined && (!Number.isSafeInteger(options.cleanupTimeoutMs) || options.cleanupTimeoutMs < 1 || options.cleanupTimeoutMs > 600_000)) ||
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
  private readonly values: Array<Readonly<{
    value: CarrierSessionV3;
    timer: ReturnType<typeof setTimeout>;
  }>> = [];
  private readonly waiters = new Set<Readonly<{
    resolve(value: CarrierSessionV3): void;
    reject(error: Error): void;
  }>>();
  private closed = false;

  constructor(
    private readonly maximum: number,
    private readonly timeoutMs: number,
  ) {}

  push(value: CarrierSessionV3): void {
    if (this.closed) { value.abort({ code: 1, reason: "WebSocket v3 listener closed" }); return; }
    const waiter = this.waiters.values().next().value;
    if (waiter !== undefined) {
      this.waiters.delete(waiter);
      waiter.resolve(value);
      return;
    }
    if (this.values.length >= this.maximum) {
      value.abort({ code: 1, reason: "WebSocket v3 pending capacity exceeded" });
      return;
    }
    const entry = {
      value,
      timer: setTimeout(() => {
        if (this.remove(value)) {
          value.abort({ code: 1, reason: "WebSocket v3 pending admission timed out" });
        }
      }, this.timeoutMs),
    };
    this.values.push(entry);
  }

  remove(value: CarrierSessionV3): boolean {
    const index = this.values.findIndex((entry) => entry.value === value);
    if (index < 0) return false;
    const [entry] = this.values.splice(index, 1);
    if (entry !== undefined) clearTimeout(entry.timer);
    return true;
  }

  async shift(signal?: AbortSignal): Promise<CarrierSessionV3> {
    if (signal?.aborted === true) throw signal.reason ?? new Error("accept canceled");
    const entry = this.values.shift();
    if (entry !== undefined) {
      clearTimeout(entry.timer);
      return entry.value;
    }
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
    for (const entry of this.values) {
      clearTimeout(entry.timer);
      entry.value.abort({ code: 1, reason: "WebSocket v3 listener closed" });
    }
    this.values.length = 0;
  }
}
