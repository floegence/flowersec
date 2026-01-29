import { describe, expect, it } from "vitest";

import type { Client } from "../client.js";
import { u32be } from "../utils/bin.js";

import { createProxyRuntime } from "./runtime.js";
import { PROXY_KIND_WS, PROXY_PROTOCOL_VERSION } from "./constants.js";

const te = new TextEncoder();
const td = new TextDecoder();

class FakeStream {
  readonly writes: Uint8Array[] = [];
  private readonly reads: Array<Uint8Array | null> = [];

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

  reset(_err: Error): void {}
}

function jsonFrame(v: unknown): Uint8Array {
  const json = te.encode(JSON.stringify(v));
  const hdr = u32be(json.length);
  const out = new Uint8Array(4 + json.length);
  out.set(hdr, 0);
  out.set(json, 4);
  return out;
}

function readU32be(buf: Uint8Array, off: number): number {
  return ((buf[off]! << 24) | (buf[off + 1]! << 16) | (buf[off + 2]! << 8) | buf[off + 3]!) >>> 0;
}

describe("createProxyRuntime.openWebSocketStream", () => {
  it("writes ws_open_meta with cookie + sec-websocket-protocol and validates ws_open_resp", async () => {
    const wsOpenResp = jsonFrame({ v: PROXY_PROTOCOL_VERSION, conn_id: "x", ok: true, protocol: "demo" });
    const stream = new FakeStream([wsOpenResp]);

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

    const rt = createProxyRuntime({ client });
    rt.cookieJar.setCookie("a=1; Path=/");

    const out = await rt.openWebSocketStream("/ws?x=1", { protocols: ["demo"] });
    expect(out.protocol).toBe("demo");
    expect(seenKind).toBe(PROXY_KIND_WS);

    expect(stream.writes.length).toBe(1);
    const written = stream.writes[0]!;
    const n = readU32be(written, 0);
    const meta = JSON.parse(td.decode(written.subarray(4, 4 + n))) as any;
    expect(meta.v).toBe(PROXY_PROTOCOL_VERSION);
    expect(typeof meta.conn_id).toBe("string");
    expect(meta.path).toBe("/ws?x=1");
    expect(meta.headers).toContainEqual({ name: "sec-websocket-protocol", value: "demo" });
    expect(meta.headers).toContainEqual({ name: "cookie", value: "a=1" });
  });
});

