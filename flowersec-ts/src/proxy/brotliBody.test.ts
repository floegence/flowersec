import { brotliCompressSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { brotliWorkerSource } from "../generated/brotliWorker.js";
import { decodeBrotliBody, type BrotliDecoder } from "./brotliBody.js";

const createDecoder = new Function(`return (${brotliWorkerSource})();`) as () => BrotliDecoder;
function body(data: Uint8Array, piece = data.length): ReadableStream<Uint8Array<ArrayBuffer>> {
  let offset = 0;
  return new ReadableStream({
    pull(controller) {
      if (offset === data.length) { controller.close(); return; }
      const end = Math.min(data.length, offset + piece);
      controller.enqueue(Uint8Array.from(data.subarray(offset, end)));
      offset = end;
    },
  });
}

describe("bounded Brotli presentation", () => {
  it("consumes fragmented input and publishes bounded output under backpressure", async () => {
    const plain = Buffer.alloc(200_000, 65);
    const reader = decodeBrotliBody(body(brotliCompressSync(plain), 1), plain.length, createDecoder).getReader();
    let total = 0;
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      expect(next.value.length).toBeLessThanOrEqual(65_536);
      expect(next.value.every(byte => byte === 65)).toBe(true);
      total += next.value.length;
    }
    expect(total).toBe(plain.length);
  });

  it.each(["truncated", "trailing"])("rejects %s coded bytes", async failure => {
    const compressed = brotliCompressSync(Buffer.from("complete encoded content"));
    const input = failure === "truncated" ? compressed.subarray(0, compressed.length - 1) : Buffer.concat([compressed, Buffer.from([0])]);
    await expect(new Response(decodeBrotliBody(body(input, 1), 1024, createDecoder)).text()).rejects.toThrow(/brotli/i);
  });

  it("rejects expansion before enqueue and cancels the source", async () => {
    let canceled = false;
    const input = new ReadableStream<Uint8Array<ArrayBuffer>>({
      start(controller) { controller.enqueue(Uint8Array.from(brotliCompressSync(Buffer.alloc(8192, 65)))); },
      cancel() { canceled = true; },
    });
    await expect(new Response(decodeBrotliBody(input, 1024, createDecoder)).text()).rejects.toThrow("decoded body exceeds limit");
    expect(canceled).toBe(true);
  });

  it("cancellation frees the decoder and joins a pending source read", async () => {
    let canceled = false;
    let freed = 0;
    const input = new ReadableStream<Uint8Array<ArrayBuffer>>({ cancel() { canceled = true; } });
    const result = decodeBrotliBody(input, 1024, () => {
      const native = createDecoder();
      return { dec: (...args) => native.dec(...args), free() { freed++; native.free(); } };
    }).getReader();
    const reading = result.read();
    await result.cancel();
    expect(await reading).toEqual({ done: true, value: undefined });
    expect(canceled).toBe(true);
    expect(freed).toBe(1);
  });
});
