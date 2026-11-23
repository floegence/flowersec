import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { transportV4Registry } from "../generated/transportV4Registry.js";
import { encode, equal, join, uint } from "./testSupport/cbor.js";
import type { Value } from "./testSupport/cbor.js";
import { emptyContext, integer } from "./testSupport/shape.js";
import type { Context } from "./testSupport/shape.js";
import { hex } from "./testSupport/rules.js";
import { Oracles, singleMapHash } from "./testSupport/oracles.js";
import type { PoolProjection } from "./testSupport/oracles.js";
import { V4Failure, root } from "./testSupport/unicode.js";

type Vector = { id: string; hex: string; schema?: string; expected_error?: string; limits?: Record<string, number | string>; pool_derivation?: { artifact_hex: string; indices: number[] } };
const corpus = JSON.parse(readFileSync(new URL("testdata/transport_v4/corpus.json", root), "utf8")) as { schema_sha256: string; vectors: Vector[] };
const reference = new Oracles();
const seed = (id: string): Vector => corpus.vectors.find(vector => vector.id === id)!;
const poolSeed = (id: string): [Uint8Array, bigint[]] => { const pool = seed(id).pool_derivation!; return [hex(pool.artifact_hex), pool.indices.map(integer)]; };
const context = (vector: Vector): Context => ({
  limits: Object.fromEntries(Object.entries(vector.limits ?? {}).filter(([, value]) => typeof value === "number").map(([key, value]) => [key, integer(value)])),
  selectors: Object.fromEntries(Object.entries(vector.limits ?? {}).filter((entry): entry is [string, string] => typeof entry[1] === "string")),
});
function replace(name: string, value: Value, field: string, replacement: Value): Value {
  const [id] = reference.namedField(name, field);
  if (value.kind !== "map") throw new Error("map fixture");
  expect(value.value.some(([key]) => key.kind === "uint" && key.value === id)).toBe(true);
  return { kind: "map", value: value.value.map(([key, item]) => [key, key.kind === "uint" && key.value === id ? replacement : item]) };
}
function byteValue(value: Value): Uint8Array { if (value.kind !== "bytes") throw new Error("bytes fixture"); return value.value; }
function receive(raw: Uint8Array, vector: Vector): Value {
  const name = vector.schema ?? "", value = reference.wireMap(raw, name, context(vector), BigInt(raw.length) + 1n);
  if (vector.pool_derivation) {
    expect(name).toBe("PoolSelectionSet");
    const artifact = hex(vector.pool_derivation.artifact_hex);
    reference.verifyPoolSet(artifact, vector.pool_derivation.indices.map(integer), raw, BigInt(Math.max(artifact.length, raw.length)) + 1n);
  }
  if (name === "OPEN_STREAM" && !equal(byteValue(reference.requiredValue(name, value, "open_digest")), reference.openDigest(value))) throw new V4Failure("open_digest_mismatch");
  return value;
}
function failure(operation: () => unknown, expected?: string): void {
  let error: unknown; try { operation(); } catch (caught) { error = caught; }
  expect(error).toBeInstanceOf(V4Failure); if (expected) expect((error as V4Failure).code).toBe(expected);
}

describe("v4.ts_oracles", () => {
  // v4.ts_oracles.corpus
  it("consumes the complete corpus including external composition", () => {
    expect(corpus.schema_sha256).toBe(transportV4Registry.schemaSHA256);
    let positive = 0, negative = 0, pools = 0, opens = 0;
    for (const vector of corpus.vectors) {
      const raw = hex(vector.hex);
      if (vector.expected_error) {
        negative += 1;
        failure(() => receive(raw, vector), ["pool_set_membership", "open_digest_mismatch"].includes(vector.expected_error) ? vector.expected_error : undefined);
      } else { positive += 1; expect(encode(receive(raw, vector)), vector.id).toEqual(raw); }
      if (vector.pool_derivation) pools += 1; if (vector.schema === "OPEN_STREAM") opens += 1;
    }
    expect(positive).toBe(337); expect(negative).toBe(828); expect(pools).toBeGreaterThan(0); expect(opens).toBeGreaterThan(0);
  });

  // v4.ts_oracles.open_digest
  it("binds every OPEN field through the exact generated projection", () => {
    const vector = seed("open_fields"), raw = hex(vector.hex), value = receive(raw, vector), digest = reference.openDigest(value);
    for (const descriptor of Object.values(reference.descriptor("OPEN_STREAM").fields)) {
      const field = descriptor.name!, original = reference.requiredValue("OPEN_STREAM", value, field);
      let replacement: Value;
      if (original.kind === "uint") replacement = uint(original.value ^ 1n);
      else if (original.kind === "bytes") replacement = { kind: "bytes", value: join([original.value, Uint8Array.of(120)]) };
      else if (original.kind === "text") replacement = { kind: "text", value: "changed" };
      else throw new Error("uncovered OPEN field");
      // Isolate the digest projection; these mutations may fail earlier gates.
      expect(equal(reference.openDigest(replace("OPEN_STREAM", value, field, replacement)), digest), field).toBe(field === "open_digest");
    }
    for (const [domain, schema, projection] of [["open_digest", "OPEN_STREAM", "full"], ["route_digest", "Artifact", "full"], ["artifact_signature", "Artifact", "full"]] as const) failure(() => singleMapHash(domain, schema, projection, raw), "domain_projection");
  });

  // v4.ts_oracles.pool_domains
  it("reproduces six shared pool digest outputs under distinct domains", () => {
    type DomainVector = { domain: string; inputs: { selection?: { $bytes: string } }; result: { output_hex: string } };
    const domains = JSON.parse(readFileSync(new URL("testdata/transport_v4/domains.json", root), "utf8")) as { schema_sha256: string; vectors: DomainVector[] };
    expect(domains.schema_sha256).toBe(transportV4Registry.schemaSHA256);
    let comparisons = 0;
    for (const id of ["pool_set_one", "pool_set_two", "pool_set_sixteen"]) {
      const [artifact, indices] = poolSeed(id), result = reference.derivePool(artifact, indices, BigInt(artifact.length));
      expect(result.candidateSetDigest).not.toEqual(result.routeSetDigest); expect(result.encoded).toEqual(hex(seed(id).hex));
      for (const [name, digest] of [["candidate_set_digest", result.candidateSetDigest], ["route_set_digest", result.routeSetDigest]] as const) {
        const matches = domains.vectors.filter(vector => vector.domain === name && equal(hex(vector.inputs.selection!.$bytes), result.encoded));
        expect(matches.length).toBe(1); expect(digest).toEqual(hex(matches[0]!.result.output_hex)); comparisons += 1;
      }
    }
    expect(comparisons).toBe(6);
  });

  // v4.ts_oracles.pool_boundaries
  it("rejects index/set substitutions and returns detached public projections", () => {
    const [artifact, indices] = poolSeed("pool_set_two"), cap = BigInt(artifact.length), result = reference.derivePool(artifact, indices, cap);
    for (const invalid of [[], [0n, 0n], [1n, 0n], [2n], [16n], [-1n], [0xffffffffffffffffn], new Array<bigint>(17).fill(0n)]) {
      const original = [...invalid]; failure(() => reference.derivePool(artifact, invalid, cap)); expect(invalid).toEqual(original);
    }
    failure(() => reference.derivePool(artifact, indices, cap - 1n), "map_size");
    failure(() => reference.verifyPoolSet(artifact, indices, result.encoded, BigInt(result.encoded.length) - 1n), "map_size");
    for (const index of indices) {
      reference.derivePool(artifact, [index], cap);
      failure(() => reference.verifyPoolSet(artifact, [index], result.encoded, cap), "pool_set_membership");
    }
    for (const field of ["artifact_digest", "candidate_id", "route_digest"]) {
      let selection = reference.wireMap(result.encoded, "PoolSelectionSet", emptyContext(), cap);
      if (field === "artifact_digest") {
        const changed = result.artifactDigest.slice(); changed[0] = changed[0]! ^ 0x80;
        selection = replace("PoolSelectionSet", selection, field, { kind: "bytes", value: changed });
      } else {
        const entries = reference.requiredValue("PoolSelectionSet", selection, "entries"); if (entries.kind !== "array") throw new Error("entries fixture");
        const changed = byteValue(reference.requiredValue("PoolRouteRef", entries.value[0]!, field)).slice(); changed[0] = changed[0]! ^ 0x80;
        entries.value[0] = replace("PoolRouteRef", entries.value[0]!, field, { kind: "bytes", value: changed });
      }
      const changed = encode(selection); reference.wireMap(changed, "PoolSelectionSet", emptyContext(), cap);
      failure(() => reference.verifyPoolSet(artifact, indices, changed, cap), "pool_set_membership");
    }
    for (const field of ["signature", "priority", "port"]) {
      let value = reference.wireMap(artifact, "Artifact", emptyContext(), cap);
      if (field === "signature") {
        const signature = byteValue(reference.requiredValue("Artifact", value, field)).slice(); signature[0] = signature[0]! ^ 1;
        value = replace("Artifact", value, field, { kind: "bytes", value: signature });
      } else {
        const candidates = reference.requiredValue("Artifact", value, "candidates"); if (candidates.kind !== "array") throw new Error("candidates fixture");
        const at = field === "priority" ? candidates.value.length - 1 : 0, candidate = candidates.value[at]!;
        if (field === "priority") {
          const current = reference.requiredValue("Candidate", candidate, field); if (current.kind !== "uint") throw new Error("priority fixture");
          candidates.value[at] = replace("Candidate", candidate, field, uint(current.value + 1n));
        } else {
          const leg = reference.requiredValue("Candidate", candidate, "direct_leg"), port = reference.requiredValue("Leg", leg, field);
          if (port.kind !== "uint") throw new Error("port fixture");
          candidates.value[at] = replace("Candidate", candidate, "direct_leg", replace("Leg", leg, field, uint(port.value + 1n)));
        }
      }
      const changed = encode(value), derived = reference.derivePool(changed, indices, BigInt(changed.length));
      expect(derived.artifactDigest).not.toEqual(result.artifactDigest);
      expect(!equal(derived.members[0]!.routeDigest, result.members[0]!.routeDigest)).toBe(field === "port");
      failure(() => reference.verifyPoolSet(changed, indices, result.encoded, BigInt(changed.length)), "pool_set_membership");
    }
    const originalArtifact = artifact.slice(), snapshot = structuredClone(result);
    artifact.fill(0); expect(result).toEqual(snapshot);
    const fromBuffer = Buffer.from(originalArtifact), detached = reference.derivePool(fromBuffer, indices, cap), saved = structuredClone(detached);
    fromBuffer.fill(0); expect(detached).toEqual(saved);
    detached.members[0]!.candidateID.fill(0); expect(originalArtifact).not.toEqual(artifact); expect(detached.encoded).toEqual(saved.encoded);
  });

  // v4.ts_oracles.properties
  it("checks 4096 mutated pools and 4096 complete received maps", () => {
    let state = 0x410ca410;
    function next(): number { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; }
    for (let iteration = 0; iteration < 4096; iteration++) {
      let [artifact, indices] = poolSeed(["pool_set_one", "pool_set_two", "pool_set_sixteen"][next() % 3]!);
      if (next() % 2 === 0) { const at = next() % artifact.length; artifact[at] = artifact[at]! ^ (next() & 255); }
      if (next() % 2 === 0) indices = Array.from({ length: next() % 18 }, () => BigInt(next() % 256));
      let result: PoolProjection | undefined;
      try { result = reference.derivePool(artifact, indices, 1n << 16n); } catch (error) { expect(error).toBeInstanceOf(V4Failure); }
      if (result) {
        expect(reference.verifyPoolSet(artifact, indices, result.encoded, 1n << 16n)).toEqual(result); expect(result.members.map(member => member.index)).toEqual(indices);
        const snapshot = structuredClone(result); artifact.fill(0); expect(result).toEqual(snapshot);
      }
      const vector = corpus.vectors[next() % corpus.vectors.length]!, raw = hex(vector.hex);
      if (raw.length) { const at = next() % raw.length; raw[at] = raw[at]! ^ (next() & 255); }
      let value: Value | undefined;
      try { value = receive(raw, vector); } catch (error) { expect(error).toBeInstanceOf(V4Failure); }
      if (value) expect(encode(value)).toEqual(raw);
    }
  }, 60000);
});
