import { readU32be, u16be, u32be } from "../utils/bin.js";
import type { ByteStream } from "../public/contract.js";

import { ProxyByteReader, writeAll } from "./stream.js";
import type { ProxyRuntime, ProxyRuntimeLimits } from "./types.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function defaultPort(protocol: string): string {
  if (protocol === "http:" || protocol === "ws:") return "80";
  if (protocol === "https:" || protocol === "wss:") return "443";
  return "";
}

function readU16(input: Uint8Array): number {
  return ((input[0]! << 8) | input[1]!) >>> 0;
}

async function writeFrame(stream: ByteStream, opcode: number, payload: Uint8Array, maximum: number): Promise<void> {
  if (payload.length > maximum) throw new Error("WebSocket frame exceeds the proxy limit");
  const header = new Uint8Array(5);
  header[0] = opcode;
  header.set(u32be(payload.length), 1);
  await writeAll(stream, header);
  await writeAll(stream, payload);
}

async function readFrame(reader: ProxyByteReader, maximum: number): Promise<Readonly<{ opcode: number; payload: Uint8Array }>> {
  const header = await reader.readExactly(5);
  const length = readU32be(header, 1);
  if (length > maximum) throw new Error("WebSocket frame exceeds the proxy limit");
  return { opcode: header[0]!, payload: await reader.readExactly(length) };
}

type EventListenerLike = EventListenerOrEventListenerObject | ((event: Event) => void);

class EventListeners {
  private readonly values = new Map<string, Set<EventListenerLike>>();
  add(type: string, listener: EventListenerLike): void {
    const entries = this.values.get(type) ?? new Set<EventListenerLike>();
    entries.add(listener);
    this.values.set(type, entries);
  }
  remove(type: string, listener: EventListenerLike): void { this.values.get(type)?.delete(listener); }
  dispatch(type: string, event: Event, target: unknown): void {
    for (const listener of this.values.get(type) ?? []) {
      try {
        if (typeof listener === "function") listener.call(target, event);
        else listener.handleEvent(event);
      } catch {
        // Event listener failures do not corrupt the transport state.
      }
    }
  }
}

export type WebSocketPatchOptions = Readonly<{
  runtime: Pick<ProxyRuntime, "limits" | "openWebSocketStream">;
  shouldProxy?: (url: URL) => boolean;
  maxWsFrameBytes?: number;
  maxWsBufferedAmountBytes?: number;
  closeHandshakeTimeoutMs?: number;
}>;

function limit(name: string, input: number | undefined, fallback: number): number {
  const value = input ?? fallback;
  if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${name} must be a positive safe integer`);
  return value;
}

export function installWebSocketPatch(options: WebSocketPatchOptions): Readonly<{ uninstall(): void }> {
  const Original = (globalThis as unknown as { WebSocket?: typeof WebSocket }).WebSocket;
  if (Original === undefined) return Object.freeze({ uninstall: () => undefined });
  const NativeWebSocket = Original;
  const runtimeLimits = options.runtime.limits as Partial<ProxyRuntimeLimits>;
  const maxFrameBytes = limit("maxWsFrameBytes", options.maxWsFrameBytes, runtimeLimits.maxWsFrameBytes ?? 1024 * 1024);
  const maxBufferedBytes = limit("maxWsBufferedAmountBytes", options.maxWsBufferedAmountBytes, runtimeLimits.maxWsBufferedAmountBytes ?? 4 * 1024 * 1024);
  const closeHandshakeTimeoutMs = limit("closeHandshakeTimeoutMs", options.closeHandshakeTimeoutMs, 5_000);
  const shouldProxy = options.shouldProxy ?? ((url: URL) => {
    const location = globalThis.location;
    if (location?.hostname === undefined || location.hostname === "") return false;
    const localPort = location.port || defaultPort(location.protocol);
    const remotePort = url.port || defaultPort(url.protocol);
    return url.hostname === location.hostname && remotePort === localPort;
  });

  class ProxyWebSocket {
    static readonly CONNECTING = 0;
    static readonly OPEN = 1;
    static readonly CLOSING = 2;
    static readonly CLOSED = 3;
    readonly CONNECTING = 0;
    readonly OPEN = 1;
    readonly CLOSING = 2;
    readonly CLOSED = 3;

    url = "";
    readyState = ProxyWebSocket.CONNECTING;
    bufferedAmount = 0;
    extensions = "";
    protocol = "";
    binaryType: BinaryType = "blob";
    onopen: ((event: Event) => void) | null = null;
    onmessage: ((event: MessageEvent) => void) | null = null;
    onerror: ((event: Event) => void) | null = null;
    onclose: ((event: CloseEvent) => void) | null = null;

    private readonly listeners = new EventListeners();
    private readonly abort = new AbortController();
    private stream: ByteStream | undefined;
    private writes: Promise<void> = Promise.resolve();
    private closeTimer: ReturnType<typeof setTimeout> | undefined;

    constructor(input: string | URL, protocols?: string | string[]) {
      const url = new URL(String(input), globalThis.location?.href);
      if (!shouldProxy(url)) return new NativeWebSocket(input, protocols) as unknown as ProxyWebSocket;
      this.url = url.toString();
      void this.connect(url, protocols);
    }

    addEventListener(type: string, listener: EventListenerLike): void { this.listeners.add(type, listener); }
    removeEventListener(type: string, listener: EventListenerLike): void { this.listeners.remove(type, listener); }
    dispatchEvent(event: Event): boolean { this.listeners.dispatch(event.type, event, this); return !event.defaultPrevented; }

    send(data: string | ArrayBufferLike | Blob | ArrayBufferView): void {
      if (this.readyState !== ProxyWebSocket.OPEN || this.stream === undefined) throw new DOMException("WebSocket is not open", "InvalidStateError");
      let opcode: number;
      let bytes: number;
      let load: () => Promise<Uint8Array>;
      if (typeof data === "string") {
        const encoded = encoder.encode(data);
        opcode = 1; bytes = encoded.length; load = async () => encoded;
      } else if (typeof Blob !== "undefined" && data instanceof Blob) {
        opcode = 2; bytes = data.size; load = async () => new Uint8Array(await data.arrayBuffer());
      } else if (ArrayBuffer.isView(data)) {
        opcode = 2; bytes = data.byteLength;
        load = async () => new Uint8Array(data.buffer, data.byteOffset, data.byteLength).slice();
      } else {
        const buffer = data as ArrayBufferLike;
        opcode = 2; bytes = buffer.byteLength;
        load = async () => new Uint8Array(buffer).slice();
      }
      if (bytes > maxFrameBytes || this.bufferedAmount + bytes > maxBufferedBytes) {
        this.fail();
        return;
      }
      this.bufferedAmount += bytes;
      const stream = this.stream;
      this.writes = this.writes.then(async () => await writeFrame(stream, opcode, await load(), maxFrameBytes))
        .catch(() => this.fail())
        .finally(() => { this.bufferedAmount = Math.max(0, this.bufferedAmount - bytes); });
    }

    close(code?: number, reason = ""): void {
      if (this.readyState === ProxyWebSocket.CLOSED || this.readyState === ProxyWebSocket.CLOSING) return;
      if (code !== undefined && (code < 1000 || code > 4999 || code === 1005 || code === 1006 || code === 1015)) {
        throw new DOMException("Invalid WebSocket close code", "InvalidAccessError");
      }
      const reasonBytes = encoder.encode(reason);
      if (reasonBytes.length > 123) throw new DOMException("WebSocket close reason is too long", "SyntaxError");
      if (this.readyState === ProxyWebSocket.CONNECTING || this.stream === undefined) {
        this.fail();
        return;
      }
      this.readyState = ProxyWebSocket.CLOSING;
      const payload = code === undefined ? new Uint8Array() : new Uint8Array([...u16be(code), ...reasonBytes]);
      const stream = this.stream;
      this.closeTimer = setTimeout(() => this.fail(), closeHandshakeTimeoutMs);
      this.writes = this.writes
        .then(async () => await writeFrame(stream, 8, payload, maxFrameBytes))
        .catch(() => this.fail());
    }

    private async connect(url: URL, protocols?: string | string[]): Promise<void> {
      try {
        const opened = await options.runtime.openWebSocketStream(url.pathname + url.search, {
          protocols: typeof protocols === "string" ? [protocols] : protocols ?? [],
          signal: this.abort.signal,
        });
        this.stream = opened.stream;
        this.protocol = opened.protocol;
        this.readyState = ProxyWebSocket.OPEN;
        this.emit("open", new Event("open"));
        await this.readLoop(opened.stream);
      } catch {
        this.fail();
      }
    }

    private async readLoop(stream: ByteStream): Promise<void> {
      const reader = new ProxyByteReader(stream, { signal: this.abort.signal });
      while (this.readyState !== ProxyWebSocket.CLOSED) {
        const frame = await readFrame(reader, maxFrameBytes);
        if (frame.opcode === 9) {
          this.writes = this.writes.then(async () => await writeFrame(stream, 10, frame.payload, maxFrameBytes)).catch(() => this.fail());
        } else if (frame.opcode === 8) {
          if (frame.payload.length === 1) throw new Error("invalid WebSocket close frame");
          const code = frame.payload.length >= 2 ? readU16(frame.payload) : 1000;
          const reason = frame.payload.length > 2 ? decoder.decode(frame.payload.subarray(2)) : "";
          const peerInitiated = this.readyState === ProxyWebSocket.OPEN;
          this.readyState = ProxyWebSocket.CLOSING;
          if (this.closeTimer !== undefined) clearTimeout(this.closeTimer);
          if (peerInitiated) {
            this.writes = this.writes.then(async () => await writeFrame(stream, 8, frame.payload, maxFrameBytes));
          }
          await this.writes;
          this.completeClose(code, reason);
          return;
        } else if (frame.opcode === 1) {
          this.emit("message", new MessageEvent("message", { data: decoder.decode(frame.payload) }));
        } else if (frame.opcode === 2) {
          const data = this.binaryType === "arraybuffer"
            ? frame.payload.slice().buffer
            : new Blob([frame.payload.slice()]);
          this.emit("message", new MessageEvent("message", { data }));
        }
      }
    }

    private emit(type: "open" | "message" | "error" | "close", event: Event): void {
      const callback = this[`on${type}`] as ((event: Event) => void) | null;
      try { callback?.call(this, event); } catch { /* User event handlers are isolated. */ }
      this.listeners.dispatch(type, event, this);
    }

    private fail(): void {
      if (this.readyState === ProxyWebSocket.CLOSED) return;
      if (this.closeTimer !== undefined) clearTimeout(this.closeTimer);
      this.readyState = ProxyWebSocket.CLOSED;
      this.bufferedAmount = 0;
      this.emit("error", new Event("error"));
      this.emit("close", new CloseEvent("close", { code: 1006, reason: "proxy WebSocket failed", wasClean: false }));
      const stream = this.stream;
      this.stream = undefined;
      this.abort.abort();
      void stream?.reset().catch(() => undefined);
    }

    private completeClose(code: number, reason: string): void {
      if (this.readyState === ProxyWebSocket.CLOSED) return;
      if (this.closeTimer !== undefined) clearTimeout(this.closeTimer);
      this.readyState = ProxyWebSocket.CLOSED;
      this.bufferedAmount = 0;
      this.emit("close", new CloseEvent("close", { code, reason, wasClean: true }));
      const stream = this.stream;
      this.stream = undefined;
      this.abort.abort();
      void stream?.close().catch(() => stream.reset().catch(() => undefined));
    }
  }

  (globalThis as unknown as { WebSocket: unknown }).WebSocket = ProxyWebSocket;
  return Object.freeze({
    uninstall: () => { (globalThis as unknown as { WebSocket: unknown }).WebSocket = NativeWebSocket; },
  });
}
