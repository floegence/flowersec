import { once } from "node:events";
import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { ByteStream } from "../public/contract.js";
import { createByteStreamDuplex } from "./byteStreamDuplex.js";

function fixture(overrides: Partial<ByteStream> = {}): ByteStream {
  return { kind: "test/http", terminalError: undefined,
    read: vi.fn(async () => null), write: vi.fn(async (data) => data.length),
    closeWrite: vi.fn(async () => {}), close: vi.fn(async () => {}), reset: vi.fn(async () => {}), ...overrides };
}

describe("createByteStreamDuplex", () => {
  it("preserves large binary writes across partial transport writes and half-closes", async () => {
    const payload = Buffer.alloc(1024 * 1024 + 17);
    for (let i = 0; i < payload.length; i++) payload[i] = i % 251;
    const output: Buffer[] = [];
    const stream = fixture({ write: vi.fn(async (data) => {
      expect(data.length).toBeLessThanOrEqual(64 * 1024);
      const count = Math.min(data.length, 7919);
      output.push(Buffer.from(data.subarray(0, count)));
      return count;
    }) });
    const duplex = createByteStreamDuplex(stream);
    duplex.end(payload);
    await once(duplex, "finish");
    const hash = (value: Buffer): string => createHash("sha256").update(value).digest("hex");
    expect(hash(Buffer.concat(output))).toBe(hash(payload));
    expect(stream.closeWrite).toHaveBeenCalledOnce();
    expect(stream.close).not.toHaveBeenCalled();
    duplex.resume();
    await once(duplex, "close");
    expect(stream.close).toHaveBeenCalledOnce();
  });

  it("stops reading at backpressure and resumes without changing bytes", async () => {
    let reads = 0;
    const stream = fixture({ read: vi.fn(async () => ++reads <= 3 ? Buffer.alloc(64 * 1024, reads) : null) });
    const duplex = createByteStreamDuplex(stream);
    duplex.read(0);
    await new Promise((resolve) => setImmediate(resolve));
    expect(reads).toBe(1);
    const chunks: Buffer[] = [];
    duplex.end();
    for await (const chunk of duplex) chunks.push(Buffer.from(chunk as Uint8Array));
    expect(Buffer.concat(chunks)).toEqual(Buffer.concat([1, 2, 3].map((n) => Buffer.alloc(64 * 1024, n))));
  });

  it("cancels pending operations and resets exactly once without exposing peer errors", async () => {
    const controller = new AbortController();
    const stream = fixture({ read: vi.fn((options) => new Promise((_resolve, reject) => {
      options?.signal?.addEventListener("abort", () => reject(new Error("private peer detail")), { once: true });
    })) });
    const duplex = createByteStreamDuplex(stream, controller.signal);
    const error = once(duplex, "error");
    duplex.resume();
    controller.abort();
    expect(String((await error)[0])).toBe("Error: Application stream canceled");
    expect(stream.reset).toHaveBeenCalledOnce();
  });

  it("rejects zero-progress writes", async () => {
    const stream = fixture({ write: vi.fn(async () => 0) });
    const duplex = createByteStreamDuplex(stream);
    const error = once(duplex, "error");
    duplex.end("abc");
    expect(String((await error)[0])).toBe("Error: Application stream write failed");
    expect(stream.reset).toHaveBeenCalledOnce();
  });
});
