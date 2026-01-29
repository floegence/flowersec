import { describe, expect, it } from "vitest";

import type { Client } from "../client.js";
import { u32be } from "../utils/bin.js";

import { PROXY_KIND_HTTP1, PROXY_PROTOCOL_VERSION } from "./constants.js";
import { createProxyRuntime } from "./runtime.js";

const te = new TextEncoder();
const td = new TextDecoder();

class FakeServiceWorker {
  readonly listeners: Record<string, ((ev: any) => void)[]> = {};
  controller: null | { postMessage: (msg: unknown) => void } = { postMessage: (_msg: unknown) => {} };

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
  it("writes http_request_meta with CookieJar cookie and streams response body (set-cookie stripped)", async () => {
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
      const rt = createProxyRuntime({ client });
      rt.cookieJar.setCookie("a=1; Path=/");

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
      expect(rt.cookieJar.getCookieHeader("/")).toBe("a=1; b=2");

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
      expect(reqMeta.headers).toContainEqual({ name: "cookie", value: "a=1" });
      expect(reqMeta.headers).not.toContainEqual({ name: "cookie", value: "bad=1" });
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
});
