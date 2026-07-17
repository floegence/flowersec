import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import { SecureChannel } from "./e2ee/secureChannel.js";
import { RpcClient } from "./rpc/client.js";
import { assertRpcEnvelope } from "./rpc/validate.js";

type RuntimeVectors = Readonly<{
  max_portable_json_integer: number;
  outbound_buffer_admission: readonly Readonly<{
    id: string;
    limit: number;
    unfinished: readonly number[];
    next: number;
    result: "accepted" | "resource_exhausted";
  }>[];
  rpc_json_integers: readonly Readonly<{ id: string; value: unknown; valid: boolean }>[];
  request_id_generation: Readonly<{
    first: number;
    last: number;
    after_last: "fail_before_write";
  }>;
}>;

const vectors = JSON.parse(
  readFileSync(new URL("../../testdata/runtime_contract_vectors.json", import.meta.url), "utf8"),
) as RuntimeVectors;

describe("shared runtime contract vectors", () => {
  test("enforces the portable RPC JSON integer range", () => {
    for (const item of vectors.rpc_json_integers) {
      const validate = () => assertRpcEnvelope({
        type_id: 1,
        request_id: item.value,
        response_to: 0,
        payload: null,
      });
      if (item.valid) expect(validate, item.id).not.toThrow();
      else expect(validate, item.id).toThrow();
    }
  });

  test("enforces cumulative outbound admission", async () => {
    for (const item of vectors.outbound_buffer_admission) {
      let releaseBlockedWrite = () => {};
      let reportBlockedWrite = () => {};
      const blockedWrite = new Promise<void>((resolve) => { releaseBlockedWrite = resolve; });
      const writeStarted = new Promise<void>((resolve) => { reportBlockedWrite = resolve; });
      const shouldBlock = item.unfinished.length > 0;
      let writeCalls = 0;
      const channel = makeChannel(item.limit, {
        async readBinary(): Promise<Uint8Array> { return await new Promise(() => {}); },
        async writeBinary(): Promise<void> {
          writeCalls += 1;
          if (shouldBlock && writeCalls === 1) {
            reportBlockedWrite();
            await blockedWrite;
          }
        },
        close(): void {},
      });
      const unfinished = item.unfinished.map((bytes) => channel.write(new Uint8Array(bytes)));
      if (shouldBlock) await writeStarted;

      const next = channel.write(new Uint8Array(item.next));
      if (item.result === "resource_exhausted") {
        await expect(next, item.id).rejects.toThrow(/outbound buffer exceeded/);
      }
      releaseBlockedWrite();
      await Promise.all(unfinished);
      if (item.result === "accepted") await expect(next, item.id).resolves.toBeUndefined();
      channel.close();
    }
  });

  test("generates portable request IDs and fails before write after the maximum", async () => {
    const generation = vectors.request_id_generation;
    expect(generation.first).toBe(1);
    expect(generation.last).toBe(vectors.max_portable_json_integer);
    expect(generation.after_last).toBe("fail_before_write");

    expect(await generatedRequestID(BigInt(generation.first))).toBe(generation.first);
    expect(await generatedRequestID(BigInt(generation.last))).toBe(generation.last);

    const writes: Uint8Array[] = [];
    const client = rpcClientCapturing(writes);
    (client as unknown as { nextId: bigint }).nextId = BigInt(generation.last) + 1n;
    await expect(client.call(1, null)).rejects.toThrow(/request id overflow/);
    expect(writes).toHaveLength(0);
    client.close();
  });
});

async function generatedRequestID(start: bigint): Promise<number> {
  const writes: Uint8Array[] = [];
  const client = rpcClientCapturing(writes);
  (client as unknown as { nextId: bigint }).nextId = start;
  const controller = new AbortController();
  controller.abort(new Error("stop after write"));
  await expect(client.call(1, null, controller.signal)).rejects.toThrow(/stop after write/);
  client.close();
  const frame = writes[0];
  if (frame == null) throw new Error("RPC call did not write a frame");
  const envelope = JSON.parse(new TextDecoder().decode(frame.subarray(4))) as { request_id: number };
  return envelope.request_id;
}

function rpcClientCapturing(writes: Uint8Array[]): RpcClient {
  return new RpcClient(
    async () => await new Promise<Uint8Array>(() => {}),
    async (frame) => { writes.push(frame); },
  );
}

function makeChannel(limit: number, transport: ConstructorParameters<typeof SecureChannel>[0]["transport"]): SecureChannel {
  return new SecureChannel({
    transport,
    maxRecordBytes: 1 << 20,
    maxOutboundBufferedBytes: limit,
    sendKey: new Uint8Array(32).fill(1),
    recvKey: new Uint8Array(32).fill(1),
    sendNoncePrefix: new Uint8Array(4).fill(2),
    recvNoncePrefix: new Uint8Array(4).fill(2),
    rekeyBase: new Uint8Array(32).fill(3),
    transcriptHash: new Uint8Array(32).fill(4),
    sendDir: 1,
    recvDir: 2,
  });
}
