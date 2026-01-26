import { describe, expect, test } from "vitest";
import type { RpcEnvelope } from "../gen/flowersec/rpc/v1.gen.js";
import { readU32be } from "../utils/bin.js";
import { writeJsonFrame } from "../framing/jsonframe.js";
import { RpcClient } from "./client.js";

class ByteQueue {
  private readonly chunks: Uint8Array[] = [];
  private readonly waiters: Array<{ n: number; resolve: (b: Uint8Array) => void }> = [];

  async write(b: Uint8Array): Promise<void> {
    this.chunks.push(b);
    this.flush();
  }

  readExactly(n: number): Promise<Uint8Array> {
    const out = this.tryRead(n);
    if (out != null) return Promise.resolve(out);
    return new Promise((resolve) => {
      this.waiters.push({ n, resolve });
    });
  }

  private flush(): void {
    while (this.waiters.length > 0) {
      const next = this.waiters[0];
      const out = this.tryRead(next.n);
      if (out == null) return;
      this.waiters.shift();
      next.resolve(out);
    }
  }

  private tryRead(n: number): Uint8Array | null {
    let available = 0;
    for (const chunk of this.chunks) available += chunk.length;
    if (available < n) return null;
    const out = new Uint8Array(n);
    let offset = 0;
    let remaining = n;
    while (remaining > 0) {
      const chunk = this.chunks[0];
      if (chunk.length <= remaining) {
        out.set(chunk, offset);
        offset += chunk.length;
        remaining -= chunk.length;
        this.chunks.shift();
      } else {
        out.set(chunk.subarray(0, remaining), offset);
        this.chunks[0] = chunk.subarray(remaining);
        remaining = 0;
      }
    }
    return out;
  }
}

function decodeEnvelope(frame: Uint8Array): RpcEnvelope {
  const n = readU32be(frame, 0);
  const payload = frame.subarray(4, 4 + n);
  return JSON.parse(new TextDecoder().decode(payload)) as RpcEnvelope;
}

describe("RpcClient observer", () => {
  test("records call outcomes and notifications", async () => {
    const queue = new ByteQueue();
    const calls: string[] = [];
    let notifyCount = 0;

    const client = new RpcClient(queue.readExactly.bind(queue), async (frame) => {
      const env = decodeEnvelope(frame);
      if (env.request_id === 0) return;
      let error: RpcEnvelope["error"] | undefined;
      if (env.type_id === 2) error = { code: 500, message: "oops" };
      if (env.type_id === 3) error = { code: 404, message: "missing" };
      await writeJsonFrame(queue.write.bind(queue), {
        type_id: env.type_id,
        request_id: 0,
        response_to: env.request_id,
        payload: env.payload,
        error
      });
    }, {
      observer: {
        onRpcCall: (result) => calls.push(result),
        onRpcNotify: () => {
          notifyCount += 1;
        }
      }
    });

    await client.call(1, { ok: true });
    await client.call(2, { ok: false });
    await client.call(3, { ok: false });

    await writeJsonFrame(queue.write.bind(queue), {
      type_id: 9,
      request_id: 0,
      response_to: 0,
      payload: { ping: true }
    });

    await new Promise((resolve) => setTimeout(resolve, 0));
    client.close();

    expect(calls).toEqual(["ok", "rpc_error", "handler_not_found"]);
    expect(notifyCount).toBe(1);
  });
});
