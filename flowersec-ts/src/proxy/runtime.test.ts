import { describe, expect, it } from "vitest";

import { u32be } from "../utils/bin.js";
import type { ByteStreamV2, SessionV2, StreamOpenOptionsV2 } from "../v2/contract.js";
import { createProxyRuntime } from "./runtime.js";

function concat(chunks: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.length; }
  return output;
}

function jsonFrame(value: unknown): Uint8Array {
  const payload = new TextEncoder().encode(JSON.stringify(value));
  return concat([u32be(payload.length), payload]);
}

class FakeStream implements ByteStreamV2 {
  readonly kind = "fake";
  terminalError = undefined;
  readonly writes: Uint8Array[] = [];
  closed = false;
  resetCalled = false;
  private readonly reads: Array<Uint8Array | Error | null>;

  constructor(reads: Array<Uint8Array | Error | null>, private readonly partialWrite = 3) { this.reads = reads; }
  async read(): Promise<Uint8Array | null> {
    const value = this.reads.shift() ?? null;
    if (value instanceof Error) throw value;
    return value;
  }
  async write(data: Uint8Array): Promise<number> {
    const count = Math.min(this.partialWrite, data.length);
    this.writes.push(data.subarray(0, count).slice());
    return count;
  }
  async closeWrite(): Promise<void> {}
  async reset(): Promise<void> { this.resetCalled = true; }
  async close(): Promise<void> { this.closed = true; }
}

class FakeSession implements SessionV2 {
  readonly rpc = {} as SessionV2["rpc"];
  readonly termination = new Promise<never>(() => undefined);
  readonly opens: Array<Readonly<{ kind: string; options: StreamOpenOptionsV2 | undefined }>> = [];
  constructor(private readonly streams: FakeStream[]) {}
  async openStream(kind: string, options?: StreamOpenOptionsV2): Promise<ByteStreamV2> {
    this.opens.push({ kind, options });
    const stream = this.streams.shift();
    if (stream === undefined) throw new Error("missing fake stream");
    return stream;
  }
  async acceptStream(): Promise<never> { throw new Error("unused"); }
  async rekey(): Promise<void> {}
  async probeLiveness(): Promise<number> { return 0; }
  async waitClosed(): Promise<never> { return await this.termination; }
  async close(): Promise<void> {}
}

async function collectPort(port: MessagePort, terminal: string): Promise<Record<string, unknown>[]> {
  return await new Promise((resolve, reject) => {
    const values: Record<string, unknown>[] = [];
    const timer = setTimeout(() => reject(new Error("message collection timed out")), 1_000);
    port.onmessage = (event) => {
      values.push(event.data as Record<string, unknown>);
      if (event.data?.type === terminal || event.data?.type === "flowersec-proxy:response_error") {
        clearTimeout(timer);
        port.close();
        resolve(values);
      }
    };
    port.start();
  });
}

describe("SessionV2 proxy runtime", () => {
  it("streams an HTTP request with partial writes and returns bounded response messages", async () => {
    const response = concat([
      jsonFrame({ v: 1, request_id: "request-1", ok: true, status: 201, headers: [{ name: "content-type", value: "text/plain" }] }),
      u32be(2), new Uint8Array([111, 107]), u32be(0),
    ]);
    const stream = new FakeStream([response, null]);
    const session = new FakeSession([stream]);
    const runtime = createProxyRuntime({ session, maxChunkBytes: 8, maxBodyBytes: 64 });
    const channel = new MessageChannel();
    const collecting = collectPort(channel.port2, "flowersec-proxy:response_end");
    runtime.dispatchFetch({
      id: "request-1",
      method: "POST",
      path: "/api?q=1",
      headers: [{ name: "content-type", value: "text/plain" }, { name: "authorization", value: "secret" }],
      body: new Uint8Array([1, 2, 3]).buffer,
    }, channel.port1);
    const messages = await collecting;

    expect(session.opens).toEqual([{
      kind: "flowersec-proxy/http1",
      options: expect.objectContaining({ metadata: { protocol: "flowersec.proxy.http", version: 2 } }),
    }]);
    expect(messages.map((message) => message.type)).toEqual([
      "flowersec-proxy:response_meta",
      "flowersec-proxy:response_chunk",
      "flowersec-proxy:response_end",
    ]);
    expect(new TextDecoder().decode(new Uint8Array(messages[1]!.data as ArrayBuffer))).toBe("ok");
    expect(new TextDecoder().decode(concat(stream.writes))).not.toContain("secret");
    expect(stream.closed).toBe(true);
    runtime.dispose();
  });

  it("redacts internal stream failures", async () => {
    const stream = new FakeStream([new Error("private endpoint detail")]);
    const runtime = createProxyRuntime({ session: new FakeSession([stream]) });
    const channel = new MessageChannel();
    const collecting = collectPort(channel.port2, "flowersec-proxy:response_error");
    runtime.dispatchFetch({ id: "failure", method: "GET", path: "/", headers: [] }, channel.port1);
    const [failure] = await collecting;
    expect(failure).toMatchObject({ status: 502, code: "operation_failed", message: "proxy request failed" });
    expect(JSON.stringify(failure)).not.toContain("private endpoint detail");
    expect(stream.resetCalled).toBe(true);
    runtime.dispose();
  });

  it("opens WebSockets through a carrier-neutral ByteStreamV2", async () => {
    const stream = new FakeStream([jsonFrame({ v: 1, ok: true, protocol: "chat" })]);
    const session = new FakeSession([stream]);
    const runtime = createProxyRuntime({ session });
    const opened = await runtime.openWebSocketStream("/socket", { protocols: ["chat"] });
    expect(opened).toEqual({ stream, protocol: "chat" });
    expect(session.opens[0]).toEqual({
      kind: "flowersec-proxy/ws",
      options: { metadata: { protocol: "flowersec.proxy.websocket", version: 2 } },
    });
    runtime.dispose();
  });
});
