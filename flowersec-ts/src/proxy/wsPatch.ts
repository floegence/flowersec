import { createByteReader } from "../streamio/index.js";
import { readU32be, u16be, u32be } from "../utils/bin.js";

import { DEFAULT_MAX_WS_FRAME_BYTES } from "./constants.js";
import type { ProxyRuntime } from "./runtime.js";

function readU16be(buf: Uint8Array, off: number): number {
  return ((buf[off]! << 8) | buf[off + 1]!) >>> 0;
}

const te = new TextEncoder();
const td = new TextDecoder();

type Listener = (ev: any) => void;

function defaultPortForProtocol(protocol: string): string {
  // Protocol strings include the trailing ':' in URL (e.g. 'http:', 'ws:').
  if (protocol === "http:" || protocol === "ws:") return "80";
  if (protocol === "https:" || protocol === "wss:") return "443";
  return "";
}

class ListenerMap {
  private readonly map = new Map<string, Set<Listener>>();
  on(type: string, cb: Listener): void {
    let s = this.map.get(type);
    if (!s) {
      s = new Set();
      this.map.set(type, s);
    }
    s.add(cb);
  }
  off(type: string, cb: Listener): void {
    this.map.get(type)?.delete(cb);
  }
  emit(type: string, ev: any): void {
    for (const cb of this.map.get(type) ?? []) {
      try {
        cb.call(null, ev);
      } catch {
        // Best-effort event fanout.
      }
    }
  }
}

async function writeWSFrame(
  stream: { write: (b: Uint8Array) => Promise<void> },
  op: number,
  payload: Uint8Array,
  maxPayload: number
): Promise<void> {
  if (maxPayload > 0 && payload.length > maxPayload) throw new Error("ws payload too large");
  const hdr = new Uint8Array(5);
  hdr[0] = op & 0xff;
  hdr.set(u32be(payload.length), 1);
  await stream.write(hdr);
  if (payload.length > 0) await stream.write(payload);
}

async function readWSFrame(
  reader: Readonly<{ readExactly: (n: number) => Promise<Uint8Array> }>,
  maxPayload: number
): Promise<Readonly<{ op: number; payload: Uint8Array }>> {
  const hdr = await reader.readExactly(5);
  const op = hdr[0]!;
  const n = readU32be(hdr, 1);
  if (maxPayload > 0 && n > maxPayload) throw new Error("ws payload too large");
  const payload = n === 0 ? new Uint8Array() : await reader.readExactly(n);
  return { op, payload };
}

export type WebSocketPatchOptions = Readonly<{
  runtime: ProxyRuntime;
  // Default: proxy same host/port (including ws<->http and wss<->https scheme mapping).
  shouldProxy?: (url: URL) => boolean;
  maxWsFrameBytes?: number;
}>;

export function installWebSocketPatch(opts: WebSocketPatchOptions): Readonly<{ uninstall: () => void }> {
  const Original = (globalThis as any).WebSocket as any;
  if (Original == null) {
    return { uninstall: () => {} };
  }

  const shouldProxy =
    opts.shouldProxy ??
    ((u: URL) => {
      const loc = (globalThis as any).location;
      const hostname = typeof loc?.hostname === "string" ? loc.hostname : "";
      if (hostname === "") return false;

      const locProto = typeof loc?.protocol === "string" ? loc.protocol : "";
      const locPortRaw = typeof loc?.port === "string" ? loc.port : "";
      const locPort = locPortRaw !== "" ? locPortRaw : defaultPortForProtocol(locProto);

      const uPort = u.port !== "" ? u.port : defaultPortForProtocol(u.protocol);
      return u.hostname === hostname && uPort === locPort;
    });

  const runtime = opts.runtime;
  const runtimeMaxWsFrameBytes =
    typeof runtime.limits?.maxWsFrameBytes === "number" && Number.isFinite(runtime.limits.maxWsFrameBytes)
      ? runtime.limits.maxWsFrameBytes
      : DEFAULT_MAX_WS_FRAME_BYTES;
  const maxWsFrameBytesRaw = opts.maxWsFrameBytes ?? runtimeMaxWsFrameBytes;
  if (!Number.isFinite(maxWsFrameBytesRaw)) throw new Error("maxWsFrameBytes must be a finite number");
  const maxWsFrameBytesFloor = Math.floor(maxWsFrameBytesRaw);
  if (maxWsFrameBytesFloor < 0) throw new Error("maxWsFrameBytes must be >= 0");
  const maxWsFrameBytes = maxWsFrameBytesFloor === 0 ? runtimeMaxWsFrameBytes : maxWsFrameBytesFloor;

  class PatchedWebSocket {
    static readonly CONNECTING = 0;
    static readonly OPEN = 1;
    static readonly CLOSING = 2;
    static readonly CLOSED = 3;

    url = "";
    readyState = PatchedWebSocket.CONNECTING;
    bufferedAmount = 0;
    extensions = "";
    protocol = "";
    binaryType: "blob" | "arraybuffer" = "blob";

    onopen: ((ev: any) => void) | null = null;
    onmessage: ((ev: any) => void) | null = null;
    onerror: ((ev: any) => void) | null = null;
    onclose: ((ev: any) => void) | null = null;

    private readonly listeners = new ListenerMap();
    private readonly ac = new AbortController();
    private stream: any = null;
    private readLoopPromise: Promise<void> | null = null;
    private writeChain: Promise<void> = Promise.resolve();

    constructor(url: string | URL, protocols?: string | string[]) {
      const u = new URL(String(url), (globalThis as any).location?.href);
      if (!shouldProxy(u)) {
        return new Original(String(url), protocols);
      }
      this.url = u.toString();
      void this.init(u, protocols);
    }

    addEventListener(type: string, listener: Listener): void {
      this.listeners.on(type, listener);
    }

    removeEventListener(type: string, listener: Listener): void {
      this.listeners.off(type, listener);
    }

    send(data: any): void {
      if (this.readyState !== PatchedWebSocket.OPEN || this.stream == null) {
        throw new Error("WebSocket is not open");
      }
      const sendBytes = (op: number, payload: Uint8Array) => {
        this.writeChain = this.writeChain
          .then(() => writeWSFrame(this.stream, op, payload, maxWsFrameBytes))
          .catch((e) => this.fail(e));
      };
      if (typeof data === "string") {
        sendBytes(1, te.encode(data));
        return;
      }
      if (data instanceof ArrayBuffer) {
        sendBytes(2, new Uint8Array(data));
        return;
      }
      if (ArrayBuffer.isView(data)) {
        sendBytes(2, new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
        return;
      }
      if (typeof Blob !== "undefined" && data instanceof Blob) {
        void data
          .arrayBuffer()
          .then((ab) => sendBytes(2, new Uint8Array(ab)))
          .catch((e) => this.fail(e));
        return;
      }
      throw new Error("unsupported WebSocket send payload");
    }

    close(code?: number, reason?: string): void {
      if (this.readyState === PatchedWebSocket.CLOSED) return;
      this.readyState = PatchedWebSocket.CLOSING;
      const payloadParts: Uint8Array[] = [];
      if (code != null) payloadParts.push(u16be(code));
      if (reason != null && reason !== "") payloadParts.push(te.encode(reason));
      const payload = payloadParts.length === 0 ? new Uint8Array() : payloadParts.reduce((a, b) => {
        const out = new Uint8Array(a.length + b.length);
        out.set(a, 0);
        out.set(b, a.length);
        return out;
      });
      this.writeChain = this.writeChain
        .then(() => (this.stream ? writeWSFrame(this.stream, 8, payload, maxWsFrameBytes) : undefined))
        .catch(() => undefined)
        .finally(() => {
          try {
            this.ac.abort("closed");
          } catch {
            // Best-effort abort.
          }
        }) as Promise<void>;
    }

    private emit(type: "open" | "message" | "error" | "close", ev: any): void {
      const prop = (this as any)["on" + type] as ((ev: any) => void) | null;
      if (typeof prop === "function") {
        try {
          prop.call(this, ev);
        } catch {
          // Best-effort.
        }
      }
      this.listeners.emit(type, ev);
    }

    private async init(u: URL, protocols?: string | string[]): Promise<void> {
      try {
        const list =
          typeof protocols === "string"
            ? [protocols]
            : Array.isArray(protocols)
              ? protocols
              : [];

        const { stream, protocol } = await runtime.openWebSocketStream(u.pathname + u.search, {
          protocols: list,
          signal: this.ac.signal
        });
        this.stream = stream;
        this.protocol = protocol;
        this.readyState = PatchedWebSocket.OPEN;
        this.emit("open", { type: "open" });

        this.readLoopPromise = this.readLoop(stream, this.ac.signal);
      } catch (e) {
        this.fail(e);
      }
    }

    private async readLoop(stream: any, signal: AbortSignal): Promise<void> {
      const reader = createByteReader(stream, { signal });
      try {
        while (true) {
          const { op, payload } = await readWSFrame(reader, maxWsFrameBytes);
          if (op === 9) {
            // Ping -> Pong (not exposed to WebSocket JS API).
            await writeWSFrame(stream, 10, payload, maxWsFrameBytes);
            continue;
          }
          if (op === 10) continue;
          if (op === 8) {
            this.readyState = PatchedWebSocket.CLOSED;
            const code = payload.length >= 2 ? readU16be(payload, 0) : 1000;
            const reason = payload.length > 2 ? td.decode(payload.subarray(2)) : "";
            this.emit("close", { type: "close", code, reason, wasClean: true });
            return;
          }
          if (op === 1) {
            this.emit("message", { type: "message", data: td.decode(payload) });
            continue;
          }
          if (op === 2) {
            if (this.binaryType === "arraybuffer") {
              const ab = payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength);
              this.emit("message", { type: "message", data: ab });
              continue;
            }
            if (typeof Blob !== "undefined") {
              this.emit("message", { type: "message", data: new Blob([new Uint8Array(payload)]) });
              continue;
            }
            // Fallback for non-browser contexts.
            const ab = payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength);
            this.emit("message", { type: "message", data: ab });
            continue;
          }
        }
      } catch (e) {
        if (this.readyState !== PatchedWebSocket.CLOSED) this.fail(e);
      }
    }

    private fail(e: any): void {
      this.readyState = PatchedWebSocket.CLOSED;
      const msg = e instanceof Error ? e.message : String(e);
      this.emit("error", { type: "error", message: msg });
      this.emit("close", { type: "close", code: 1006, reason: msg, wasClean: false });
      try {
        this.ac.abort(msg);
      } catch {
        // Best-effort.
      }
    }
  }

  (globalThis as any).WebSocket = PatchedWebSocket as any;
  return { uninstall: () => ((globalThis as any).WebSocket = Original) };
}
