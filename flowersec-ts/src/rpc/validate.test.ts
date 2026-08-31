import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import { readJsonFrame } from "../framing/jsonframe.js";
import { assertRpcEnvelope } from "./validate.js";

type VectorMessage = Readonly<{
  presence: "absent" | "present";
  unit: string;
  repeat: number;
  suffix: string;
}>;

type RPCErrorFixture = Readonly<{
  transport_contract_version?: 3;
  maximum_message_bytes: number;
  cases: readonly Readonly<{
    id: string;
    code: number;
    message: VectorMessage;
    extra_field: boolean;
    valid: boolean;
  }>[];
  raw_cases: readonly Readonly<{
    id: string;
    code: number;
    message_hex: string;
    valid: boolean;
  }>[];
}>;

type RPCEnvelopeFixture = Readonly<{
  version: number;
  transport_contract_version?: 3;
  vectors: readonly Readonly<{ id: string; valid: boolean; reason: string; envelope: unknown }>[];
}>;

const rpcErrorFixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/rpc_error_vectors.json", import.meta.url),
  "utf8",
)) as RPCErrorFixture;

const envelopeFixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/rpc_malformed_envelopes.json", import.meta.url),
  "utf8",
)) as RPCEnvelopeFixture;

const envelope = (error: unknown): unknown => ({
  type_id: 1,
  request_id: 0,
  response_to: 1,
  payload: {},
  error,
});

describe("RPC envelope validation", () => {
  test("consumes the shared strict envelope vectors", () => {
    {
      expect(envelopeFixture.version).toBe(1);
      expect(envelopeFixture.transport_contract_version).toBe(3);
      for (const vector of envelopeFixture.vectors) {
        const id = `v3/${vector.id}`;
        if (vector.valid) expect(() => assertRpcEnvelope(vector.envelope), id).not.toThrow();
        else expect(() => assertRpcEnvelope(vector.envelope), `${id}: ${vector.reason}`).toThrow();
      }
    }
  });

  test("enforces the shared portable inbound RPC error invariant", async () => {
    {
      expect(rpcErrorFixture.transport_contract_version).toBe(3);
      expect(rpcErrorFixture.maximum_message_bytes).toBe(1_024);
      for (const vector of rpcErrorFixture.cases) {
        const id = `v3/${vector.id}`;
        const error: Record<string, unknown> = { code: vector.code };
        if (vector.message.presence === "present") {
          error.message = vector.message.unit.repeat(vector.message.repeat) + vector.message.suffix;
        }
        if (vector.extra_field) error.internal = "secret";
        if (vector.valid) {
          expect(() => assertRpcEnvelope(envelope(error)), id).not.toThrow();
        } else {
          expect(() => assertRpcEnvelope(envelope(error)), id).toThrow();
        }
      }

      for (const vector of rpcErrorFixture.raw_cases) {
        const id = `v3/${vector.id}`;
        const message = Uint8Array.from(
          vector.message_hex.match(/.{2}/g) ?? [],
          (value) => Number.parseInt(value, 16),
        );
        const prefix = new TextEncoder().encode(
          `{"type_id":1,"request_id":0,"response_to":1,"payload":null,"error":{"code":${vector.code},"message":"`,
        );
        const suffix = new TextEncoder().encode('"}}');
        const payload = new Uint8Array(prefix.length + message.length + suffix.length);
        payload.set(prefix);
        payload.set(message, prefix.length);
        payload.set(suffix, prefix.length + message.length);
        const frame = new Uint8Array(4 + payload.length);
        new DataView(frame.buffer).setUint32(0, payload.length);
        frame.set(payload, 4);
        let offset = 0;
        const readExactly = async (length: number) => {
          const chunk = frame.slice(offset, offset + length);
          offset += length;
          return chunk;
        };
        const decode = async () => assertRpcEnvelope(await readJsonFrame(readExactly, 1 << 20));
        if (vector.valid) {
          await expect(decode(), id).resolves.toBeDefined();
        } else {
          await expect(decode(), id).rejects.toThrow();
        }
      }
    }
  });
});
