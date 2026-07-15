import { describe, expect, it, vi } from "vitest";

import type { Client } from "../client.js";
import { u32be } from "../utils/bin.js";

import { PROXY_KIND_HTTP1, PROXY_PROTOCOL_VERSION } from "./constants.js";
import { CookieJar } from "./cookieJar.js";
import { createProxyRuntime, ensureServiceWorkerRuntimeRegistered } from "./runtime.js";

const te = new TextEncoder();
const td = new TextDecoder();

class FakeServiceWorker {
  readonly listeners: Record<string, ((ev: any) => void)[]> = {};
  controller: null | { postMessage: (msg: unknown, transfer?: Transferable[]) => void } = {
    postMessage: (_msg: unknown, transfer?: Transferable[]) => {
      const port = transfer?.[0] as MessagePort | undefined;
      port?.postMessage({ type: "flowersec-proxy:register-runtime-ack", ok: true });
      port?.close();
    },
  };

  addEventListener(type: string, cb: (ev: any) => void): void {
    this.listeners[type] ??= [];
    this.listeners[type]!.push(cb);
  }

  removeEventListener(type: string, cb: (ev: any) => void): void {
    this.listeners[type] = (this.listeners[type] ?? []).filter((x) => x !== cb);
  }

  emit(type: string, ev: any): void {
    for (const cb of this.listeners[type] ?? []) cb(ev);
  }
}

class FakeStream {
  readonly writes: Uint8Array[] = [];
  private readonly reads: Array<Uint8Array | null> = [];
  resetCalls = 0;

  constructor(reads: Uint8Array[]) {
    this.reads = [...reads, null];
  }

  async write(b: Uint8Array): Promise<void> {
    this.writes.push(b);
  }

  async read(): Promise<Uint8Array | null> {
    return this.reads.shift() ?? null;
  }

  async close(): Promise<void> {}

  reset(_err: Error): void {
    this.resetCalls++;
  }
}

class GatedResponseStream {
  readonly writes: Uint8Array[] = [];
  resetCalls = 0;
  private readonly immediateReads: Uint8Array[];
  private readonly gatedReads: Array<Uint8Array | null>;
  private readGateStarted = false;
  private releaseReadGate: (() => void) | undefined;

  constructor(immediateReads: Uint8Array[], gatedReads: Uint8Array[]) {
    this.immediateReads = [...immediateReads];
    this.gatedReads = [...gatedReads, null];
  }

  async write(b: Uint8Array): Promise<void> {
    this.writes.push(b);
  }

  async read(): Promise<Uint8Array | null> {
    if (this.immediateReads.length > 0) return this.immediateReads.shift() ?? null;
    if (!this.readGateStarted) {
      this.readGateStarted = true;
      await new Promise<void>((resolve) => {
        this.releaseReadGate = resolve;
      });
    }
    return this.gatedReads.shift() ?? null;
  }

  async close(): Promise<void> {}

  reset(_err: Error): void {
    this.resetCalls++;
  }

  releaseReads(): void {
    this.releaseReadGate?.();
  }

  hasStartedGatedRead(): boolean {
    return this.readGateStarted;
  }
}

function jsonFrame(v: unknown): Uint8Array {
  const json = te.encode(JSON.stringify(v));
  const hdr = u32be(json.length);
  const out = new Uint8Array(4 + json.length);
  out.set(hdr, 0);
  out.set(json, 4);
  return out;
}

function chunkFrame(payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + payload.length);
  out.set(u32be(payload.length), 0);
  out.set(payload, 4);
  return out;
}

function readU32be(buf: Uint8Array, off: number): number {
  return ((buf[off]! << 24) | (buf[off + 1]! << 16) | (buf[off + 2]! << 8) | buf[off + 3]!) >>> 0;
}

describe("createProxyRuntime (http1)", () => {
  it("waits for an explicit service worker runtime registration ack", async () => {
    const postMessage = vi.fn((_msg: unknown, transfer?: Transferable[]) => {
      const port = transfer?.[0] as MessagePort | undefined;
      port?.postMessage({ type: "flowersec-proxy:register-runtime-ack", ok: true });
      port?.close();
    });

    const sw = new FakeServiceWorker();
    sw.controller = { postMessage };
    const oldNavigatorDesc = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    Object.defineProperty(globalThis, "navigator", { value: { serviceWorker: sw }, configurable: true });
    try {
      await ensureServiceWorkerRuntimeRegistered({ timeoutMs: 100 });
      expect(postMessage).toHaveBeenCalledTimes(1);
      expect(postMessage).toHaveBeenCalledWith(
        { type: "flowersec-proxy:register-runtime" },
        expect.arrayContaining([expect.any(MessagePort)]),
      );
    } finally {
      if (oldNavigatorDesc) Object.defineProperty(globalThis, "navigator", oldNavigatorDesc);
    }
  });

  it("sends the configured runtime registration token", async () => {
    const postMessage = vi.fn((_msg: unknown, transfer?: Transferable[]) => {
      const port = transfer?.[0] as MessagePort | undefined;
      port?.postMessage({ type: "flowersec-proxy:register-runtime-ack", ok: true });
      port?.close();
    });

    const sw = new FakeServiceWorker();
    sw.controller = { postMessage };
    const oldNavigatorDesc = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    Object.defineProperty(globalThis, "navigator", { value: { serviceWorker: sw }, configurable: true });
    try {
      await ensureServiceWorkerRuntimeRegistered({ timeoutMs: 100, runtimeRegistrationToken: "tok_123" });
      expect(postMessage).toHaveBeenCalledWith(
        { type: "flowersec-proxy:register-runtime", token: "tok_123" },
        expect.arrayContaining([expect.any(MessagePort)]),
      );
    } finally {
      if (oldNavigatorDesc) Object.defineProperty(globalThis, "navigator", oldNavigatorDesc);
    }
  });

  it("registers the runtime with the active service worker controller and retries on controllerchange", () => {
    const firstPostMessage = vi.fn((_msg: unknown, transfer?: Transferable[]) => {
      const port = transfer?.[0] as MessagePort | undefined;
      port?.postMessage({ type: "flowersec-proxy:register-runtime-ack", ok: true });
      port?.close();
    });
    const secondPostMessage = vi.fn((_msg: unknown, transfer?: Transferable[]) => {
      const port = transfer?.[0] as MessagePort | undefined;
      port?.postMessage({ type: "flowersec-proxy:register-runtime-ack", ok: true });
      port?.close();
    });
    const client: Client = {
      path: "tunnel",
      rpc: null as any,
      openStream: async () => {
        throw new Error("unexpected openStream");
      },
      ping: async () => {},
      close: () => {}
    };

    const sw = new FakeServiceWorker();
    sw.controller = { postMessage: firstPostMessage };
    const oldNavigatorDesc = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    Object.defineProperty(globalThis, "navigator", { value: { serviceWorker: sw }, configurable: true });
    try {
      createProxyRuntime({ client });
      expect(firstPostMessage).toHaveBeenCalledWith(
        { type: "flowersec-proxy:register-runtime" },
        expect.arrayContaining([expect.any(MessagePort)]),
      );

      sw.controller = { postMessage: secondPostMessage };
      sw.emit("controllerchange", {});
      expect(secondPostMessage).toHaveBeenCalledWith(
        { type: "flowersec-proxy:register-runtime" },
        expect.arrayContaining([expect.any(MessagePort)]),
      );
    } finally {
      if (oldNavigatorDesc) Object.defineProperty(globalThis, "navigator", oldNavigatorDesc);
    }
  });

  it("reuses the runtime registration token when controllerchange retries", () => {
    const firstPostMessage = vi.fn((_msg: unknown, transfer?: Transferable[]) => {
      const port = transfer?.[0] as MessagePort | undefined;
      port?.postMessage({ type: "flowersec-proxy:register-runtime-ack", ok: true });
      port?.close();
    });
    const secondPostMessage = vi.fn((_msg: unknown, transfer?: Transferable[]) => {
      const port = transfer?.[0] as MessagePort | undefined;
      port?.postMessage({ type: "flowersec-proxy:register-runtime-ack", ok: true });
      port?.close();
    });
    const client: Client = {
      path: "tunnel",
      rpc: null as any,
      openStream: async () => {
        throw new Error("unexpected openStream");
      },
      ping: async () => {},
      close: () => {}
    };

    const sw = new FakeServiceWorker();
    sw.controller = { postMessage: firstPostMessage };
    const oldNavigatorDesc = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    Object.defineProperty(globalThis, "navigator", { value: { serviceWorker: sw }, configurable: true });
    try {
      createProxyRuntime({ client, runtimeRegistrationToken: "tok_456" });
      expect(firstPostMessage).toHaveBeenCalledWith(
        { type: "flowersec-proxy:register-runtime", token: "tok_456" },
        expect.arrayContaining([expect.any(MessagePort)]),
      );

      sw.controller = { postMessage: secondPostMessage };
      sw.emit("controllerchange", {});
      expect(secondPostMessage).toHaveBeenCalledWith(
        { type: "flowersec-proxy:register-runtime", token: "tok_456" },
        expect.arrayContaining([expect.any(MessagePort)]),
      );
    } finally {
      if (oldNavigatorDesc) Object.defineProperty(globalThis, "navigator", oldNavigatorDesc);
    }
  });

  it("keeps legacy service worker responses eager when chunk credits are absent", async () => {
    const respMeta = jsonFrame({
      v: PROXY_PROTOCOL_VERSION,
      request_id: "req1",
      ok: true,
      status: 200,
      headers: [
        { name: "content-type", value: "text/plain; charset=utf-8" },
        { name: "set-cookie", value: "b=2; Path=/" }
      ]
    });
    const respBody = chunkFrame(te.encode("hello"));
    const respEnd = u32be(0);

    const stream = new FakeStream([respMeta, respBody, respEnd]);

    let seenKind: string | null = null;
    const client: Client = {
      path: "tunnel",
      rpc: null as any,
      openStream: async (kind: string) => {
        seenKind = kind;
        return stream as any;
      },
      ping: async () => {},
      close: () => {}
    };

    const sw = new FakeServiceWorker();
    const oldNavigatorDesc = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    Object.defineProperty(globalThis, "navigator", { value: { serviceWorker: sw }, configurable: true });
    try {
      const cookieJar = new CookieJar();
      cookieJar.setCookie("a=1; Path=/");
      createProxyRuntime({ client, cookieJar });

      const portMessages: any[] = [];
      let portClosed = false;
      const port = {
        onmessage: null as null | ((ev: any) => void),
        postMessage: (msg: any) => portMessages.push(msg),
        close: () => {
          portClosed = true;
        }
      };

      sw.emit("message", {
        data: {
          type: "flowersec-proxy:fetch",
          req: {
            id: "req1",
            method: "GET",
            path: "/hello",
            external_origin: "https://env-123.example.test",
            headers: [
              { name: "accept", value: "text/plain" },
              { name: "cookie", value: "bad=1" }
            ]
          }
        },
        ports: [port]
      });

      // Wait for response_end.
      for (let i = 0; i < 100 && portMessages.find((m) => m?.type === "flowersec-proxy:response_end") == null; i++) {
        await new Promise((r) => setTimeout(r, 0));
      }
      await new Promise((r) => setTimeout(r, 0));

      expect(seenKind).toBe(PROXY_KIND_HTTP1);
      expect(portClosed).toBe(true);

      const metaMsg = portMessages.find((m) => m?.type === "flowersec-proxy:response_meta");
      expect(metaMsg).toBeTruthy();
      expect(metaMsg.status).toBe(200);
      expect((metaMsg.headers ?? []).find((h: any) => (h.name ?? "").toLowerCase() === "set-cookie")).toBeFalsy();

      const chunkMsg = portMessages.find((m) => m?.type === "flowersec-proxy:response_chunk");
      expect(chunkMsg).toBeTruthy();
      expect(td.decode(new Uint8Array(chunkMsg.data))).toBe("hello");

      expect(portMessages.find((m) => m?.type === "flowersec-proxy:response_end")).toBeTruthy();

      // The Set-Cookie is stored in the runtime CookieJar, not written to browser cookies.
      expect(cookieJar.getCookieHeader("/")).toBe("a=1; b=2");

      // Request meta includes CookieJar cookie (not the original request cookie header).
      expect(stream.writes.length).toBe(2);
      expect(stream.resetCalls).toBe(0);
      const firstWrite = stream.writes[0]!;
      const n = readU32be(firstWrite, 0);
      const reqMeta = JSON.parse(td.decode(firstWrite.subarray(4, 4 + n))) as any;
      expect(reqMeta.v).toBe(PROXY_PROTOCOL_VERSION);
      expect(reqMeta.request_id).toBe("req1");
      expect(reqMeta.method).toBe("GET");
      expect(reqMeta.path).toBe("/hello");
      expect(reqMeta.external_origin).toBe("https://env-123.example.test");
      expect(reqMeta.headers).toContainEqual({ name: "cookie", value: "a=1" });
      expect(reqMeta.headers).not.toContainEqual({ name: "cookie", value: "bad=1" });
    } finally {
      if (oldNavigatorDesc) Object.defineProperty(globalThis, "navigator", oldNavigatorDesc);
    }
  });

  it("advances credit-enabled responses one chunk at a time", async () => {
    const stream = new FakeStream([
      jsonFrame({
        v: PROXY_PROTOCOL_VERSION,
        request_id: "credit-1",
        ok: true,
        status: 200,
        headers: [{ name: "content-type", value: "application/octet-stream" }],
      }),
      chunkFrame(new Uint8Array([1])),
      chunkFrame(new Uint8Array([2])),
      u32be(0),
    ]);
    const client: Client = {
      path: "tunnel",
      rpc: null as any,
      openStream: async () => stream as any,
      ping: async () => {},
      close: () => {},
    };

    const sw = new FakeServiceWorker();
    const oldNavigatorDesc = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    Object.defineProperty(globalThis, "navigator", { value: { serviceWorker: sw }, configurable: true });
    try {
      const runtime = createProxyRuntime({ client });
      const messages: any[] = [];
      let closed = false;
      const port = {
        onmessage: null as null | ((ev: any) => void),
        postMessage: (message: any) => messages.push(message),
        close: () => { closed = true; },
      };

      runtime.dispatchFetch({
        id: "credit-1",
        method: "GET",
        path: "/download",
        headers: [],
        response_flow_control: "chunk_credit_v1",
      }, port as any);

      for (let i = 0; i < 100 && messages.every((m) => m.type !== "flowersec-proxy:response_meta"); i++) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
      expect(messages.filter((m) => m.type === "flowersec-proxy:response_chunk")).toHaveLength(0);
      expect(closed).toBe(false);

      port.onmessage?.({ data: { type: "flowersec-proxy:response_credit" } });
      for (let i = 0; i < 100 && messages.filter((m) => m.type === "flowersec-proxy:response_chunk").length < 1; i++) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
      expect(messages.filter((m) => m.type === "flowersec-proxy:response_chunk")).toHaveLength(1);
      expect(messages.some((m) => m.type === "flowersec-proxy:response_end")).toBe(false);

      port.onmessage?.({ data: { type: "flowersec-proxy:response_credit" } });
      for (let i = 0; i < 100 && messages.every((m) => m.type !== "flowersec-proxy:response_end"); i++) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
      const chunks = messages
        .filter((m) => m.type === "flowersec-proxy:response_chunk")
        .map((m) => Array.from(new Uint8Array(m.data)));
      expect(chunks).toEqual([[1], [2]]);
      expect(closed).toBe(true);
    } finally {
      if (oldNavigatorDesc) Object.defineProperty(globalThis, "navigator", oldNavigatorDesc);
    }
  });

  it("aborts a credit wait without forwarding buffered response data", async () => {
    const stream = new FakeStream([
      jsonFrame({
        v: PROXY_PROTOCOL_VERSION,
        request_id: "credit-abort",
        ok: true,
        status: 200,
        headers: [],
      }),
      chunkFrame(new Uint8Array([1, 2, 3])),
      u32be(0),
    ]);
    const client: Client = {
      path: "tunnel",
      rpc: null as any,
      openStream: async () => stream as any,
      ping: async () => {},
      close: () => {},
    };

    const sw = new FakeServiceWorker();
    const oldNavigatorDesc = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    Object.defineProperty(globalThis, "navigator", { value: { serviceWorker: sw }, configurable: true });
    try {
      const runtime = createProxyRuntime({ client });
      const messages: any[] = [];
      let closed = false;
      const port = {
        onmessage: null as null | ((ev: any) => void),
        postMessage: (message: any) => messages.push(message),
        close: () => { closed = true; },
      };

      runtime.dispatchFetch({
        id: "credit-abort",
        method: "GET",
        path: "/download",
        headers: [],
        response_flow_control: "chunk_credit_v1",
      }, port as any);
      for (let i = 0; i < 100 && messages.every((m) => m.type !== "flowersec-proxy:response_meta"); i++) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }

      port.onmessage?.({ data: { type: "flowersec-proxy:abort" } });
      for (let i = 0; i < 100 && !closed; i++) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
      expect(messages.filter((m) => m.type === "flowersec-proxy:response_chunk")).toHaveLength(0);
      expect(messages.some((m) => m.type === "flowersec-proxy:response_error")).toBe(true);
      expect(stream.resetCalls).toBeGreaterThanOrEqual(1);
      expect(closed).toBe(true);
    } finally {
      if (oldNavigatorDesc) Object.defineProperty(globalThis, "navigator", oldNavigatorDesc);
    }
  });

  it("does not consume a previously granted credit after abort", async () => {
    const stream = new GatedResponseStream(
      [jsonFrame({
        v: PROXY_PROTOCOL_VERSION,
        request_id: "credit-abort-race",
        ok: true,
        status: 200,
        headers: [],
      })],
      [chunkFrame(new Uint8Array([7, 8, 9])), u32be(0)],
    );
    const client: Client = {
      path: "tunnel",
      rpc: null as any,
      openStream: async () => stream as any,
      ping: async () => {},
      close: () => {},
    };

    const sw = new FakeServiceWorker();
    const oldNavigatorDesc = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    Object.defineProperty(globalThis, "navigator", { value: { serviceWorker: sw }, configurable: true });
    try {
      const runtime = createProxyRuntime({ client });
      const messages: any[] = [];
      let closed = false;
      const port = {
        onmessage: null as null | ((ev: any) => void),
        postMessage: (message: any) => messages.push(message),
        close: () => { closed = true; },
      };

      runtime.dispatchFetch({
        id: "credit-abort-race",
        method: "GET",
        path: "/download",
        headers: [],
        response_flow_control: "chunk_credit_v1",
      }, port as any);
      for (let i = 0; i < 100 && !stream.hasStartedGatedRead(); i++) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }

      port.onmessage?.({ data: { type: "flowersec-proxy:response_credit" } });
      port.onmessage?.({ data: { type: "flowersec-proxy:abort" } });
      stream.releaseReads();
      for (let i = 0; i < 100 && !closed; i++) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }

      expect(messages.filter((m) => m.type === "flowersec-proxy:response_chunk")).toHaveLength(0);
      expect(messages.some((m) => m.type === "flowersec-proxy:response_error")).toBe(true);
      expect(stream.resetCalls).toBeGreaterThanOrEqual(1);
      expect(closed).toBe(true);
    } finally {
      if (oldNavigatorDesc) Object.defineProperty(globalThis, "navigator", oldNavigatorDesc);
    }
  });

  it("derives default cookie paths from the response request path in runtime mode", async () => {
    const streams = [
      new FakeStream([
        jsonFrame({
          v: PROXY_PROTOCOL_VERSION,
          request_id: "req1",
          ok: true,
          status: 200,
          headers: [{ name: "set-cookie", value: "sid=1" }]
        }),
        chunkFrame(te.encode("one")),
        u32be(0)
      ]),
      new FakeStream([
        jsonFrame({
          v: PROXY_PROTOCOL_VERSION,
          request_id: "req2",
          ok: true,
          status: 200,
          headers: [{ name: "content-type", value: "text/plain; charset=utf-8" }]
        }),
        chunkFrame(te.encode("two")),
        u32be(0)
      ]),
      new FakeStream([
        jsonFrame({
          v: PROXY_PROTOCOL_VERSION,
          request_id: "req3",
          ok: true,
          status: 200,
          headers: [{ name: "content-type", value: "text/plain; charset=utf-8" }]
        }),
        chunkFrame(te.encode("three")),
        u32be(0)
      ])
    ];

    let openCount = 0;
    const client: Client = {
      path: "tunnel",
      rpc: null as any,
      openStream: async (kind: string) => {
        expect(kind).toBe(PROXY_KIND_HTTP1);
        const stream = streams[openCount];
        openCount++;
        if (!stream) throw new Error("unexpected openStream");
        return stream as any;
      },
      ping: async () => {},
      close: () => {}
    };

    const sw = new FakeServiceWorker();
    const oldNavigatorDesc = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    Object.defineProperty(globalThis, "navigator", { value: { serviceWorker: sw }, configurable: true });
    try {
      const cookieJar = new CookieJar();
      createProxyRuntime({ client, cookieJar });

      const dispatchFetch = async (id: string, path: string): Promise<any[]> => {
        const portMessages: any[] = [];
        const port = {
          onmessage: null as null | ((ev: any) => void),
          postMessage: (msg: any) => portMessages.push(msg),
          close: () => {}
        };

        sw.emit("message", {
          data: {
            type: "flowersec-proxy:fetch",
            req: {
              id,
              method: "GET",
              path,
              headers: [{ name: "accept", value: "text/plain" }]
            }
          },
          ports: [port]
        });

        for (let i = 0; i < 100 && portMessages.find((m) => m?.type === "flowersec-proxy:response_end") == null; i++) {
          await new Promise((r) => setTimeout(r, 0));
        }
        await new Promise((r) => setTimeout(r, 0));
        return portMessages;
      };

      await dispatchFetch("req1", "/admin/panel?tab=security");
      expect(cookieJar.getCookieHeader("/admin/next")).toBe("sid=1");
      expect(cookieJar.getCookieHeader("/administrator")).toBe("");

      await dispatchFetch("req2", "/admin/next");
      await dispatchFetch("req3", "/administrator");

      const req2Write = streams[1]!.writes[0]!;
      const req2Len = readU32be(req2Write, 0);
      const req2Meta = JSON.parse(td.decode(req2Write.subarray(4, 4 + req2Len))) as any;
      expect(req2Meta.headers).toContainEqual({ name: "cookie", value: "sid=1" });

      const req3Write = streams[2]!.writes[0]!;
      const req3Len = readU32be(req3Write, 0);
      const req3Meta = JSON.parse(td.decode(req3Write.subarray(4, 4 + req3Len))) as any;
      expect((req3Meta.headers ?? []).find((h: any) => (h.name ?? "").toLowerCase() === "cookie")).toBeFalsy();
    } finally {
      if (oldNavigatorDesc) Object.defineProperty(globalThis, "navigator", oldNavigatorDesc);
    }
  });

  it("fails on oversized response chunks (maxChunkBytes enforced)", async () => {
    const respMeta = jsonFrame({
      v: PROXY_PROTOCOL_VERSION,
      request_id: "req1",
      ok: true,
      status: 200,
      headers: [{ name: "content-type", value: "text/plain; charset=utf-8" }]
    });
    const respBody = chunkFrame(te.encode("hello")); // 5 bytes
    const respEnd = u32be(0);

    const stream = new FakeStream([respMeta, respBody, respEnd]);
    const client: Client = {
      path: "tunnel",
      rpc: null as any,
      openStream: async (_kind: string) => stream as any,
      ping: async () => {},
      close: () => {}
    };

    const sw = new FakeServiceWorker();
    const oldNavigatorDesc = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    Object.defineProperty(globalThis, "navigator", { value: { serviceWorker: sw }, configurable: true });
    try {
      createProxyRuntime({ client, maxChunkBytes: 4 });

      const portMessages: any[] = [];
      const port = {
        onmessage: null as null | ((ev: any) => void),
        postMessage: (msg: any) => portMessages.push(msg),
        close: () => {}
      };

      sw.emit("message", {
        data: { type: "flowersec-proxy:fetch", req: { id: "req1", method: "GET", path: "/hello", headers: [] } },
        ports: [port]
      });

      for (let i = 0; i < 100 && portMessages.find((m) => m?.type === "flowersec-proxy:response_error") == null; i++) {
        await new Promise((r) => setTimeout(r, 0));
      }

      const errMsg = portMessages.find((m) => m?.type === "flowersec-proxy:response_error");
      expect(errMsg).toBeTruthy();
      expect(errMsg.status).toBe(502);
      expect(String(errMsg.message)).toContain("response chunk too large");
      expect(stream.resetCalls).toBeGreaterThan(0);
    } finally {
      if (oldNavigatorDesc) Object.defineProperty(globalThis, "navigator", oldNavigatorDesc);
    }
  });

  it("rejects paths containing whitespace (aligns with server path validation)", async () => {
    let openCalls = 0;
    const client: Client = {
      path: "tunnel",
      rpc: null as any,
      openStream: async () => {
        openCalls++;
        throw new Error("unexpected openStream");
      },
      ping: async () => {},
      close: () => {}
    };

    const sw = new FakeServiceWorker();
    const oldNavigatorDesc = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    Object.defineProperty(globalThis, "navigator", { value: { serviceWorker: sw }, configurable: true });
    try {
      createProxyRuntime({ client });

      const portMessages: any[] = [];
      const port = {
        onmessage: null as null | ((ev: any) => void),
        postMessage: (msg: any) => portMessages.push(msg),
        close: () => {}
      };

      sw.emit("message", {
        data: { type: "flowersec-proxy:fetch", req: { id: "req1", method: "GET", path: "/a b", headers: [] } },
        ports: [port]
      });

      for (let i = 0; i < 100 && portMessages.find((m) => m?.type === "flowersec-proxy:response_error") == null; i++) {
        await new Promise((r) => setTimeout(r, 0));
      }

      const errMsg = portMessages.find((m) => m?.type === "flowersec-proxy:response_error");
      expect(errMsg).toBeTruthy();
      expect(String(errMsg.message)).toContain("path contains whitespace");
      expect(openCalls).toBe(0);
    } finally {
      if (oldNavigatorDesc) Object.defineProperty(globalThis, "navigator", oldNavigatorDesc);
    }
  });

  it("rejects invalid external origins before opening an upstream stream", async () => {
    let openCalls = 0;
    const client: Client = {
      path: "tunnel",
      rpc: null as any,
      openStream: async () => {
        openCalls++;
        throw new Error("unexpected openStream");
      },
      ping: async () => {},
      close: () => {}
    };

    const sw = new FakeServiceWorker();
    const oldNavigatorDesc = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    Object.defineProperty(globalThis, "navigator", { value: { serviceWorker: sw }, configurable: true });
    try {
      createProxyRuntime({ client });

      const portMessages: any[] = [];
      const port = {
        onmessage: null as null | ((ev: any) => void),
        postMessage: (msg: any) => portMessages.push(msg),
        close: () => {}
      };

      sw.emit("message", {
        data: {
          type: "flowersec-proxy:fetch",
          req: { id: "req1", method: "GET", path: "/hello", headers: [], external_origin: "https://env.example.test/app" }
        },
        ports: [port]
      });

      for (let i = 0; i < 100 && portMessages.find((m) => m?.type === "flowersec-proxy:response_error") == null; i++) {
        await new Promise((r) => setTimeout(r, 0));
      }

      const errMsg = portMessages.find((m) => m?.type === "flowersec-proxy:response_error");
      expect(errMsg).toBeTruthy();
      expect(String(errMsg.message)).toContain("external_origin");
      expect(openCalls).toBe(0);
    } finally {
      if (oldNavigatorDesc) Object.defineProperty(globalThis, "navigator", oldNavigatorDesc);
    }
  });

  it("rejects denied HTTP paths before opening a stream or reading cookies", async () => {
    let openCalls = 0;
    const client: Client = {
      path: "tunnel",
      rpc: null as any,
      openStream: async () => {
        openCalls++;
        throw new Error("unexpected openStream");
      },
      ping: async () => {},
      close: () => {}
    };

    const sw = new FakeServiceWorker();
    const oldNavigatorDesc = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    Object.defineProperty(globalThis, "navigator", { value: { serviceWorker: sw }, configurable: true });
    try {
      const cookieJar = {
        getCookieHeader: vi.fn(() => "sid=1"),
        updateFromSetCookieHeaders: vi.fn(),
      } as unknown as CookieJar;
      createProxyRuntime({
        client,
        cookieJar,
        pathPolicy: {
          allowedPathPrefixes: ["/app/"],
          deniedPathPrefixes: ["/app/admin/"],
        },
      });

      const portMessages: any[] = [];
      const port = {
        onmessage: null as null | ((ev: any) => void),
        postMessage: (msg: any) => portMessages.push(msg),
        close: () => {}
      };

      sw.emit("message", {
        data: { type: "flowersec-proxy:fetch", req: { id: "req1", method: "GET", path: "/app/admin/panel?x=1", headers: [] } },
        ports: [port]
      });

      for (let i = 0; i < 100 && portMessages.find((m) => m?.type === "flowersec-proxy:response_error") == null; i++) {
        await new Promise((r) => setTimeout(r, 0));
      }

      const errMsg = portMessages.find((m) => m?.type === "flowersec-proxy:response_error");
      expect(errMsg).toBeTruthy();
      expect(errMsg.status).toBe(403);
      expect(String(errMsg.message)).toContain("denied");
      expect(openCalls).toBe(0);
      expect(cookieJar.getCookieHeader).not.toHaveBeenCalled();
    } finally {
      if (oldNavigatorDesc) Object.defineProperty(globalThis, "navigator", oldNavigatorDesc);
    }
  });

  it("uses a trusted configured external origin before app-supplied external_origin", async () => {
    const respMeta = jsonFrame({
      v: PROXY_PROTOCOL_VERSION,
      request_id: "req1",
      ok: true,
      status: 200,
      headers: [{ name: "content-type", value: "text/plain" }]
    });
    const stream = new FakeStream([respMeta, u32be(0)]);
    const client: Client = {
      path: "tunnel",
      rpc: null as any,
      openStream: async () => stream as any,
      ping: async () => {},
      close: () => {}
    };

    const sw = new FakeServiceWorker();
    const oldNavigatorDesc = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    Object.defineProperty(globalThis, "navigator", { value: { serviceWorker: sw }, configurable: true });
    try {
      createProxyRuntime({ client, externalOrigin: "https://trusted.example.test" });

      const portMessages: any[] = [];
      const port = {
        onmessage: null as null | ((ev: any) => void),
        postMessage: (msg: any) => portMessages.push(msg),
        close: () => {}
      };

      sw.emit("message", {
        data: {
          type: "flowersec-proxy:fetch",
          req: {
            id: "req1",
            method: "GET",
            path: "/hello",
            headers: [],
            external_origin: "https://untrusted.example.test",
          }
        },
        ports: [port]
      });

      for (let i = 0; i < 100 && portMessages.find((m) => m?.type === "flowersec-proxy:response_end") == null; i++) {
        await new Promise((r) => setTimeout(r, 0));
      }

      const firstWrite = stream.writes[0]!;
      const n = readU32be(firstWrite, 0);
      const reqMeta = JSON.parse(td.decode(firstWrite.subarray(4, 4 + n))) as any;
      expect(reqMeta.external_origin).toBe("https://trusted.example.test");
    } finally {
      if (oldNavigatorDesc) Object.defineProperty(globalThis, "navigator", oldNavigatorDesc);
    }
  });
});
