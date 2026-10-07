import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import { assertRpcEnvelope } from "./rpcJSON.js";

type VectorMessage = Readonly<{
  presence: "absent" | "present";
  unit: string;
  repeat: number;
  suffix: string;
}>;

type RPCErrorFixture = Readonly<{
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
  vectors: readonly Readonly<{ id: string; valid: boolean; reason: string; envelope: unknown }>[];
}>;

const rpcErrorFixture = JSON.parse(readFileSync(
  new URL("../../../testdata/rpc/rpc_error_vectors.json", import.meta.url),
  "utf8",
)) as RPCErrorFixture;

const envelopeFixture = JSON.parse(readFileSync(
  new URL("../../../testdata/rpc/rpc_malformed_envelopes.json", import.meta.url),
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
      for (const vector of envelopeFixture.vectors) {
        const id = vector.id;
        if (vector.valid) expect(() => assertRpcEnvelope(vector.envelope), id).not.toThrow();
        else expect(() => assertRpcEnvelope(vector.envelope), `${id}: ${vector.reason}`).toThrow();
      }
    }
  });

  test("enforces the shared portable inbound RPC error invariant", async () => {
    {
      expect(rpcErrorFixture.maximum_message_bytes).toBe(1_024);
      for (const vector of rpcErrorFixture.cases) {
        const id = vector.id;
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
        const id = vector.id;
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
        const decode = async () => assertRpcEnvelope(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload)));
        if (vector.valid) {
          await expect(decode(), id).resolves.toBeDefined();
        } else {
          await expect(decode(), id).rejects.toThrow();
        }
      }
    }
  });
});
