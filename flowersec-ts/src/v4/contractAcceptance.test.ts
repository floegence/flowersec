import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { CBORDecoder, cborDecoderCharge } from "./runtime/cbor.js";
import { ResourceRoot, ResourceVector } from "./runtime/resources.js";
import { captureContractAcceptance, checkContractAcceptance, type ContractRange } from "./runtime/contractAcceptance.js";
import { Reference, encode, uint, type Value } from "./testSupport/cbor.js";

const corpus = JSON.parse(readFileSync(new URL("../../../testdata/transport_v4/corpus.json", import.meta.url), "utf8")) as { vectors: { id: string; hex: string }[] };
function seed(id: string): Uint8Array { return Uint8Array.from(Buffer.from(corpus.vectors.find(v => v.id === id)!.hex, "hex")); }
function changed(raw: Uint8Array, id: bigint, value: Value): Uint8Array {
  const result = new Reference().decode(raw, "ServiceContract", {}, 8192n);
  if (!result.ok) throw new Error("fixture");
  const decoded = result.value;
  if (decoded.kind !== "map") throw new Error("fixture");
  return encode({ kind: "map", value: decoded.value.map(([key, old]) => [key, key.kind === "uint" && key.value === id ? value : old]) });
}
function fixture() {
  const limit = new ResourceVector([128n << 20n, 0n, 0n, 100000n, 1000n, 0n, 0n, 0n, 0n, 0n, 0n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 4, reservations: 8, references: 16,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const tenant = "1".repeat(32), environment = "2".repeat(32), accounts = [root.account("tenant", tenant, limit), root.account("environment", environment, limit)];
  const config = { bytes: 8192, nodes: 4096, textBytes: 128, arrayItems: 64, runtimeBytes: 4096n };
  const codecs = [1, 2].map(id => new CBORDecoder(config, root.reserve({ owner: { tenant, environment, kind: "contract", backing: String(id).repeat(32) }, accounts, charge: cborDecoderCharge(config) })));
  return { codecs, close: () => { codecs.forEach(c => c.close()); expect(root.snapshot().reservations).toBe(0); } };
}
describe("canonical contract acceptance", () => {
  it("permits only explicitly listed numeric changes and preserves shape", () => {
    const f = fixture();
    try {
      const raw = seed("service_unary_execution"), old = f.codecs[0]!.decodeMap(raw, "ServiceContract");
      const policy = captureContractAcceptance({ mode: "bounded", ranges: [{ field: "history_retention_ms", lower: 1n, upper: 0xffffffffffffffffn }] });
      const scratch = new Uint8Array(512);
      for (const [id, value, allowed] of [[14n, uint(123456n), true], [23n, uint(777n), false], [13n, uint(0n), false], [6n, { kind: "text", value: "other" }, false]] as const) {
        const next = f.codecs[1]!.decodeMap(changed(raw, id, value), "ServiceContract");
        const check = () => checkContractAcceptance(next, old, policy, scratch, true);
        if (allowed) expect(check).not.toThrow(); else expect(check).toThrow("contract_policy_rejected");
        next.release();
      }
      const next = f.codecs[1]!.decodeMap(changed(raw, 14n, uint(123456n)), "ServiceContract");
      expect(() => checkContractAcceptance(next, old, { mode: "exact" }, scratch)).toThrow();
      expect(() => checkContractAcceptance(next, old, { mode: "exact" }, scratch, true)).not.toThrow();
      next.release(); old.release();
    } finally { f.close(); }
  });
  it("requires equal fixed response bounds and preserves the response mode", () => {
    const f = fixture();
    try {
      const raw = seed("service_unary_fixed_empty"), old = f.codecs[0]!.decodeMap(raw, "ServiceContract");
      const policy = captureContractAcceptance({ mode: "bounded", ranges: [
        { field: "min_response_limit_bytes", lower: 0n, upper: 1024n },
        { field: "max_response_bytes", lower: 0n, upper: 1024n }
      ] });
      expect(() => f.codecs[1]!.decodeMap(changed(raw, 10n, uint(1n)), "ServiceContract")).toThrow();
      const next = f.codecs[1]!.decodeMap(changed(changed(raw, 8n, uint(1n)), 10n, uint(1n)), "ServiceContract");
      expect(() => checkContractAcceptance(next, old, policy, new Uint8Array(512), true)).toThrow("contract_policy_rejected");
      next.release(); old.release();
    } finally { f.close(); }
  });
  it("rejects unsupported fields, duplicate ranges and variant-inapplicable ranges", () => {
    for (const ranges of [[], [{ field: "unknown", lower: 0n, upper: 1n }], [{ field: "history_retention_ms", lower: 0n, upper: 1n }],
      [{ field: "max_response_bytes", lower: 1n, upper: 1048577n }],
      [{ field: "max_response_bytes", lower: 1n, upper: 5n }, { field: "max_response_bytes", lower: 1n, upper: 5n }]]) {
      expect(() => captureContractAcceptance({ mode: "bounded", ranges: ranges as ContractRange[] })).toThrow();
    }
    const f = fixture();
    try {
      const doc = f.codecs[0]!.decodeMap(seed("service_unary_transient"), "ServiceContract");
      const policy = captureContractAcceptance({ mode: "bounded", ranges: [{ field: "history_retention_ms", lower: 1n, upper: 100n }] });
      expect(() => checkContractAcceptance(doc, undefined, policy, new Uint8Array(512))).toThrow();
      doc.release();
    } finally { f.close(); }
  });
});
