import { SDK_DEFAULTS } from "../defaults.js";
import { SessionError, type ByteStream, type OperationOptions } from "../public/contract.js";

import {
  createServiceWorkerControllerGuard,
  type ServiceWorkerControllerGuardConflictPolicy,
  type ServiceWorkerControllerGuardMonitorOptions,
  type ServiceWorkerControllerGuardRepairOptions,
} from "./controllerGuard.js";
import { registerServiceWorkerAndEnsureControl } from "./registerServiceWorker.js";
import type { ProxyFetchRequest, ProxyRuntime, ProxyRuntimeLimits } from "./types.js";

const FETCH_MESSAGE = "flowersec-proxy:window_fetch_v2";
const WEBSOCKET_OPEN_MESSAGE = "flowersec-proxy:window_ws_open_v2";
const WEBSOCKET_ACK_MESSAGE = "flowersec-proxy:window_ws_open_ack_v2";
const MAX_BRIDGE_CHUNK_BYTES = 1024 * 1024;
const MAX_BRIDGE_BUFFER_BYTES = 4 * 1024 * 1024;

type BridgeMessage = Readonly<{
  type: "chunk" | "ack" | "end" | "reset" | "close";
  id?: number;
  data?: ArrayBuffer;
}>;

export class MessagePortByteStream implements ByteStream {
  readonly kind = "flowersec.proxy.window.v2";
  terminalError: SessionError | undefined;
  private readonly reads: Uint8Array[] = [];
  private readonly readWaiters: Array<Readonly<{ resolve(value: Uint8Array | null): void; reject(error: Error): void }>> = [];
  private readonly writeWaiters = new Map<number, Readonly<{ resolve(): void; reject(error: Error): void }>>();
  private nextWrite = 1;
  private buffered = 0;
  private readBuffered = 0;
  private ended = false;
  private closed = false;

  constructor(private readonly port: MessagePort) {
    port.onmessage = (event) => this.handle(event.data as BridgeMessage | unknown);
    port.onmessageerror = () => this.fail(new SessionError("operation_failed"));
    port.start();
  }

  async read(options: OperationOptions = {}): Promise<Uint8Array | null> {
    if (options.signal?.aborted === true) throw new SessionError("canceled");
    const queued = this.reads.shift();
    if (queued !== undefined) {
      this.readBuffered -= queued.byteLength;
      return queued;
    }
    if (this.ended) return null;
    if (this.terminalError !== undefined) throw this.terminalError;
    return await new Promise<Uint8Array | null>((resolve, reject) => {
      const waiter = { resolve, reject };
      const onAbort = () => {
        const index = this.readWaiters.indexOf(waiter);
        if (index >= 0) this.readWaiters.splice(index, 1);
        reject(new SessionError("canceled"));
      };
      options.signal?.addEventListener("abort", onAbort, { once: true });
      this.readWaiters.push(waiter);
    });
  }

  async write(data: Uint8Array, options: OperationOptions = {}): Promise<number> {
    if (this.closed || this.terminalError !== undefined) throw this.terminalError ?? new SessionError("closed");
    if (options.signal?.aborted === true) throw new SessionError("canceled");
    if (data.length === 0) return 0;
    if (data.length > MAX_BRIDGE_CHUNK_BYTES || this.buffered + data.length > MAX_BRIDGE_BUFFER_BYTES) {
      throw new SessionError("resource_exhausted");
    }
    const id = this.nextWrite++;
    const copy = data.slice();
    this.buffered += copy.length;
    await new Promise<void>((resolve, reject) => {
      this.writeWaiters.set(id, {
        resolve: () => { this.buffered -= copy.length; resolve(); },
        reject: (error) => { this.buffered -= copy.length; reject(error); },
      });
      try {
        this.port.postMessage({ type: "chunk", id, data: copy.buffer } satisfies BridgeMessage, [copy.buffer]);
      } catch {
        this.writeWaiters.delete(id);
        this.buffered -= copy.length;
        reject(new SessionError("operation_failed"));
      }
    });
    return data.length;
  }

  async closeWrite(): Promise<void> {
    if (this.closed) return;
    this.port.postMessage({ type: "end" } satisfies BridgeMessage);
  }

  async reset(): Promise<void> {
    if (this.closed) return;
    this.port.postMessage({ type: "reset" } satisfies BridgeMessage);
    this.fail(new SessionError("stream_reset"));
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.port.postMessage({ type: "close" } satisfies BridgeMessage);
    this.finish();
  }

  private handle(value: BridgeMessage | unknown): void {
    if (value === null || typeof value !== "object" || !("type" in value)) return;
    const message = value as BridgeMessage;
    if (message.type === "chunk") {
      if (!Number.isSafeInteger(message.id) || !(message.data instanceof ArrayBuffer) || message.data.byteLength > MAX_BRIDGE_CHUNK_BYTES) {
        this.fail(new SessionError("operation_failed"));
        return;
      }
      const chunk = new Uint8Array(message.data);
      const id = message.id!;
      const waiter = this.readWaiters.shift();
      if (waiter === undefined) {
        if (this.readBuffered + chunk.byteLength > MAX_BRIDGE_BUFFER_BYTES) {
          this.fail(new SessionError("resource_exhausted"));
          return;
        }
        this.reads.push(chunk);
        this.readBuffered += chunk.byteLength;
      } else {
        waiter.resolve(chunk);
      }
      this.port.postMessage({ type: "ack", id } satisfies BridgeMessage);
      return;
    }
    if (message.type === "ack" && Number.isSafeInteger(message.id)) {
      const waiter = this.writeWaiters.get(message.id!);
      if (waiter !== undefined) {
        this.writeWaiters.delete(message.id!);
        waiter.resolve();
      }
      return;
    }
    if (message.type === "end") {
      this.ended = true;
      for (const waiter of this.readWaiters.splice(0)) waiter.resolve(null);
      return;
    }
    if (message.type === "reset") this.fail(new SessionError("stream_reset"));
    else if (message.type === "close") this.finish();
  }

  private finish(): void {
    if (this.closed) return;
    this.closed = true;
    this.ended = true;
    this.reads.length = 0;
    this.readBuffered = 0;
    for (const waiter of this.readWaiters.splice(0)) waiter.resolve(null);
    for (const waiter of this.writeWaiters.values()) waiter.reject(new SessionError("closed"));
    this.writeWaiters.clear();
    this.port.close();
  }

  private fail(error: SessionError): void {
    if (this.terminalError !== undefined) return;
    this.terminalError = error;
    this.closed = true;
    this.reads.length = 0;
    this.readBuffered = 0;
    for (const waiter of this.readWaiters.splice(0)) waiter.reject(error);
    for (const waiter of this.writeWaiters.values()) waiter.reject(error);
    this.writeWaiters.clear();
    this.port.close();
  }
}

function bridgeLimits(maxWsFrameBytes?: number, maxWsBufferedAmountBytes?: number): ProxyRuntimeLimits {
  const wsFrame = maxWsFrameBytes ?? SDK_DEFAULTS.proxy.maxWsFrameBytes;
  const buffered = maxWsBufferedAmountBytes ?? MAX_BRIDGE_BUFFER_BYTES;
  if (!Number.isSafeInteger(wsFrame) || wsFrame <= 0 || !Number.isSafeInteger(buffered) || buffered <= 0) {
    throw new TypeError("invalid proxy window bridge limits");
  }
  return Object.freeze({
    maxJsonFrameBytes: SDK_DEFAULTS.proxy.maxJsonFrameBytes,
    maxChunkBytes: SDK_DEFAULTS.proxy.maxChunkBytes,
    maxBodyBytes: SDK_DEFAULTS.proxy.maxBodyBytes,
    maxWsFrameBytes: wsFrame,
    maxWsBufferedAmountBytes: buffered,
    maxConcurrentHttpStreams: 24,
    maxQueuedHttpRequests: 128,
    maxQueuedHttpBodyBytes: 64 * 1024 * 1024,
  });
}

function capability(input: string | undefined): string | undefined {
  if (input === undefined) return undefined;
  if (input === "" || input !== input.trim() || /[\u0000-\u0020\u007f]/u.test(input) || input.length > 256) {
    throw new TypeError("invalid proxy window capability nonce");
  }
  return input;
}

export type RegisterProxyAppWindowOptions = Readonly<{
  controllerOrigin: string;
  controllerWindow?: Window | null;
  targetWindow?: Window;
  maxWsFrameBytes?: number;
  maxWsBufferedAmountBytes?: number;
  capabilityNonce?: string;
}>;

export type ProxyAppWindowHandle = Readonly<{
  runtime: ProxyRuntime;
  dispose(): void;
}>;

export function registerProxyAppWindow(options: RegisterProxyAppWindowOptions): ProxyAppWindowHandle {
  const target = options.targetWindow ?? globalThis.window;
  const controller = options.controllerWindow ?? target.opener ?? (target.parent === target ? null : target.parent);
  if (controller === null) throw new Error("proxy controller window is unavailable");
  const origin = new URL(options.controllerOrigin).origin;
  if (origin !== options.controllerOrigin) throw new TypeError("controllerOrigin must be an origin");
  const nonce = capability(options.capabilityNonce);
  const limits = bridgeLimits(options.maxWsFrameBytes, options.maxWsBufferedAmountBytes);
  let disposed = false;

  const dispatchFetch = (request: ProxyFetchRequest, port: MessagePort) => {
    if (disposed) {
      port.postMessage({ type: "flowersec-proxy:response_error", status: 503, code: "closed", message: "proxy service unavailable" });
      port.close();
      return;
    }
    controller.postMessage({ type: FETCH_MESSAGE, version: 2, request, ...(nonce === undefined ? {} : { capabilityNonce: nonce }) }, origin, [port]);
  };

  const runtime: ProxyRuntime = Object.freeze({
    limits,
    dispatchFetch,
    openWebSocketStream: async (path, openOptions = {}) => {
      if (disposed) throw new SessionError("closed");
      const channel = new MessageChannel();
      const response = new Promise<Readonly<{ stream: ByteStream; protocol: string }>>((resolve, reject) => {
        const timer = setTimeout(() => { channel.port1.close(); reject(new SessionError("timeout")); }, 10_000);
        channel.port1.onmessage = (event) => {
          if (event.data?.type !== WEBSOCKET_ACK_MESSAGE) return;
          clearTimeout(timer);
          if (event.data.ok !== true) {
            channel.port1.close();
            reject(new SessionError("operation_failed"));
            return;
          }
          resolve(Object.freeze({ stream: new MessagePortByteStream(channel.port1), protocol: typeof event.data.protocol === "string" ? event.data.protocol : "" }));
        };
      });
      controller.postMessage({
        type: WEBSOCKET_OPEN_MESSAGE,
        version: 2,
        path,
        protocols: openOptions.protocols ?? [],
        ...(nonce === undefined ? {} : { capabilityNonce: nonce }),
      }, origin, [channel.port2]);
      if (openOptions.signal !== undefined) {
        openOptions.signal.addEventListener("abort", () => channel.port1.close(), { once: true });
      }
      return await response;
    },
    dispose: () => { disposed = true; },
  });

  return Object.freeze({
    runtime,
    dispose: () => { disposed = true; },
  });
}

export type RegisterProxyControllerWindowOptions = Readonly<{
  runtime: ProxyRuntime;
  allowedOrigins: readonly string[];
  targetWindow?: Window;
  expectedSource?: Window | null;
  capabilityNonce?: string;
}>;

export type ProxyControllerWindowHandle = Readonly<{ dispose(): void }>;

async function bridgeStreams(runtimeStream: ByteStream, port: MessagePort): Promise<void> {
  const bridge = new MessagePortByteStream(port);
  const left = (async () => {
    while (true) {
      const chunk = await runtimeStream.read();
      if (chunk === null) { await bridge.closeWrite(); return; }
      await bridge.write(chunk);
    }
  })();
  const right = (async () => {
    while (true) {
      const chunk = await bridge.read();
      if (chunk === null) { await runtimeStream.closeWrite(); return; }
      let offset = 0;
      while (offset < chunk.length) offset += await runtimeStream.write(chunk.subarray(offset));
    }
  })();
  await Promise.all([left, right]);
  await runtimeStream.close();
  await bridge.close();
}

export function registerProxyControllerWindow(options: RegisterProxyControllerWindowOptions): ProxyControllerWindowHandle {
  const target = options.targetWindow ?? globalThis.window;
  const allowed = new Set(options.allowedOrigins.map((origin) => new URL(origin).origin));
  if (allowed.size === 0 || [...allowed].some((origin) => !options.allowedOrigins.includes(origin))) {
    throw new TypeError("allowedOrigins must contain exact origins");
  }
  const nonce = capability(options.capabilityNonce);
  let disposed = false;
  const onMessage = (event: MessageEvent) => {
    if (disposed || !allowed.has(event.origin) || (options.expectedSource !== undefined && event.source !== options.expectedSource)) return;
    if (nonce !== undefined && event.data?.capabilityNonce !== nonce) return;
    const port = event.ports?.[0];
    if (port === undefined) return;
    if (event.data?.type === FETCH_MESSAGE && event.data.version === 2) {
      options.runtime.dispatchFetch(event.data.request as ProxyFetchRequest, port);
      return;
    }
    if (event.data?.type === WEBSOCKET_OPEN_MESSAGE && event.data.version === 2) {
      void (async () => {
        try {
          const opened = await options.runtime.openWebSocketStream(String(event.data.path ?? ""), {
            protocols: Array.isArray(event.data.protocols) ? event.data.protocols.map(String) : [],
          });
          port.postMessage({ type: WEBSOCKET_ACK_MESSAGE, ok: true, protocol: opened.protocol });
          await bridgeStreams(opened.stream, port);
        } catch {
          port.postMessage({ type: WEBSOCKET_ACK_MESSAGE, ok: false });
          port.close();
        }
      })();
    }
  };
  target.addEventListener("message", onMessage);
  return Object.freeze({ dispose: () => { disposed = true; target.removeEventListener("message", onMessage); } });
}

export type ProxyAppServiceWorkerControlOptions = Readonly<{
  scriptUrl: string;
  scope?: string;
  expectedScriptPathSuffix: string;
  repair?: ServiceWorkerControllerGuardRepairOptions;
  monitor?: ServiceWorkerControllerGuardMonitorOptions;
  conflicts?: ServiceWorkerControllerGuardConflictPolicy;
}>;

export type RegisterProxyAppWindowWithServiceWorkerControlOptions = RegisterProxyAppWindowOptions & Readonly<{
  serviceWorker: ProxyAppServiceWorkerControlOptions;
}>;

export async function registerProxyAppWindowWithServiceWorkerControl(
  options: RegisterProxyAppWindowWithServiceWorkerControlOptions,
): Promise<ProxyAppWindowHandle> {
  await registerServiceWorkerAndEnsureControl({
    scriptUrl: options.serviceWorker.scriptUrl,
    ...(options.serviceWorker.scope === undefined ? {} : { scope: options.serviceWorker.scope }),
    ...(options.serviceWorker.repair?.queryKey === undefined ? {} : { repairQueryKey: options.serviceWorker.repair.queryKey }),
    ...(options.serviceWorker.repair?.maxAttempts === undefined ? {} : { maxRepairAttempts: options.serviceWorker.repair.maxAttempts }),
    ...(options.serviceWorker.repair?.controllerTimeoutMs === undefined ? {} : { controllerTimeoutMs: options.serviceWorker.repair.controllerTimeoutMs }),
  });
  const guard = createServiceWorkerControllerGuard({
    ...(options.targetWindow === undefined ? {} : { targetWindow: options.targetWindow, navigationWindow: options.targetWindow }),
    expectedScriptPathSuffix: options.serviceWorker.expectedScriptPathSuffix,
    ...(options.serviceWorker.repair === undefined ? {} : { repair: options.serviceWorker.repair }),
    ...(options.serviceWorker.monitor === undefined ? {} : { monitor: options.serviceWorker.monitor }),
    ...(options.serviceWorker.conflicts === undefined ? {} : { conflicts: options.serviceWorker.conflicts }),
  });
  await guard.ensure();
  const app = registerProxyAppWindow(options);
  return Object.freeze({
    runtime: app.runtime,
    dispose: () => { app.dispose(); guard.dispose(); },
  });
}
