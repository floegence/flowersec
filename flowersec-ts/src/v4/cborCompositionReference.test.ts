import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { transportV4Registry } from "../generated/transportV4Registry.js";
import { encode, uint } from "./testSupport/cbor.js";
import type { Value } from "./testSupport/cbor.js";
import { emptyContext, integer } from "./testSupport/shape.js";
import type { Context } from "./testSupport/shape.js";
import { hex } from "./testSupport/rules.js";
import { Composition } from "./testSupport/composition.js";
import type { PoolProjection } from "./testSupport/oracles.js";
import { V4Failure, root } from "./testSupport/unicode.js";

type Vector = { id: string; hex: string; schema?: string; expected_error?: string; limits?: Record<string, number | string>; typed_derivation?: { definition_hex: string; application_hex: string } };
const corpus = JSON.parse(readFileSync(new URL("testdata/transport_v4/corpus.json", root), "utf8")) as { schema_sha256: string; vectors: Vector[] };
const reference = new Composition(), cap = 1n << 16n;
const seed = (id: string): Vector => corpus.vectors.find(vector => vector.id === id)!;
const bytes = (id: string): Uint8Array => hex(seed(id).hex);
const ctx = (id: string): Context => ({
  limits: Object.fromEntries(Object.entries(seed(id).limits ?? {}).filter(([, value]) => typeof value === "number").map(([key, value]) => [key, integer(value)])),
  selectors: Object.fromEntries(Object.entries(seed(id).limits ?? {}).filter((entry): entry is [string, string] => typeof entry[1] === "string")),
});
const read = (input: Uint8Array, name: string, context = emptyContext()): Value => reference.wireMap(input, name, context, cap);
const field = (name: string, value: Value, key: string): Value => reference.requiredValue(name, value, key);
const bstr = (value: Uint8Array): Value => ({ kind: "bytes", value });
function byteValue(value: Value): Uint8Array { if (value.kind !== "bytes") throw new Error("bytes fixture"); return value.value; }
function set(name: string, value: Value, key: string, replacement: Value): void {
  const [id] = reference.namedField(name, key);
  if (value.kind !== "map") throw new Error("map fixture");
  const pair = value.value.find(([key]) => key.kind === "uint" && key.value === id);
  if (!pair) throw new Error("field fixture"); pair[1] = replacement;
}
function failure(operation: () => unknown, expected?: string): void {
  let error: unknown; try { operation(); } catch (caught) { error = caught; }
  expect(error).toBeInstanceOf(V4Failure); if (expected) expect((error as V4Failure).code).toBe(expected);
}
function attempted<T>(operation: () => T): T | undefined {
  try { return operation(); } catch (error) { expect(error).toBeInstanceOf(V4Failure); return undefined; }
}

type Material = { artifact: Uint8Array; fsb: Uint8Array; reference: Uint8Array; selection: PoolProjection; context: Context };
function material(indices: bigint[], highTimes = false): Material {
  const artifact = read(bytes("artifact_transport_fields"), "Artifact");
  if (highTimes) for (const [key, value] of [["issued_at_ms", 0xfffffffffffffffdn], ["initiation_not_after_ms", 0xfffffffffffffffen], ["session_not_after_ms", 0xffffffffffffffffn]] as const) set("Artifact", artifact, key, uint(value));
  const raw = encode(artifact), selection = reference.derivePool(raw, indices, cap);
  const proof = read(bytes("activation_pool_fields"), "ActivationAuthorization", ctx("activation_pool_fields"));
  if (highTimes) for (const [key, value] of [["issued_at_ms", 0xfffffffffffffffdn], ["activation_not_after_ms", 0xfffffffffffffffen], ["session_not_after_ms", 0xffffffffffffffffn]] as const) set("ActivationAuthorization", proof, key, uint(value));
  const selectionRef = field("ActivationAuthorization", proof, "candidate_selection");
  set("PoolSelectionRef", selectionRef, "artifact_digest", bstr(selection.artifactDigest));
  set("PoolSelectionRef", selectionRef, "candidate_set_digest", bstr(selection.candidateSetDigest));
  set("PoolSelectionRef", selectionRef, "candidate_indices", { kind: "array", value: indices.map(uint) });
  set("ActivationAuthorization", proof, "artifact_digest", bstr(selection.artifactDigest));
  set("ActivationAuthorization", proof, "route_selection", bstr(selection.routeSetDigest));
  for (const key of ["client_identity_digest", "server_identity_digest", "audience"]) set("ActivationAuthorization", proof, key, field("Artifact", artifact, key));
  const fsb = read(bytes("fsb_fields"), "FSB4", ctx("fsb_fields"));
  set("FSB4", fsb, "artifact_digest", bstr(selection.artifactDigest));
  set("FSB4", fsb, "session_nonce", field("Artifact", artifact, "session_nonce"));
  set("FSB4", fsb, "candidate_id", bstr(selection.members[0]!.candidateID));
  set("FSB4", fsb, "route_digest", bstr(selection.members[0]!.routeDigest));
  set("FSB4", fsb, "activation_authorization", bstr(encode(proof)));
  return { artifact: raw, fsb: encode(fsb), reference: encode(selectionRef), selection, context: { limits: {}, selectors: { activation_source_profile: "preauthorized_pool" } } };
}
const parseContext = (m: Material): Context => ({ limits: m.context.limits, selectors: { ...m.context.selectors, crypto_profile_id: ctx("fsb_fields").selectors.crypto_profile_id! } });
const authorize = (m: Material, fsb = m.fsb): PoolProjection => reference.poolAuthorizationProjection(m.artifact, fsb, m.context, cap);

describe("v4.ts_composition", () => {
  // v4.ts_composition.metadata_corpus
  it("consumes metadata corpus and independently composes bound fixtures", () => {
    expect(corpus.schema_sha256).toBe(transportV4Registry.schemaSHA256);
    let positive = 0, negative = 0, bound = 0;
    for (const vector of corpus.vectors.filter(vector => ["StreamMetadata", "TypedMessageMetadata"].includes(vector.schema ?? ""))) {
      const raw = hex(vector.hex);
      if (vector.expected_error) {
        negative += 1;
        const parsed = attempted(() => reference.streamMetadata(raw, BigInt(raw.length) + 1n));
        // A mutated reserved namespace can be valid ordinary metadata, but it
        // must never satisfy a registration requiring the typed shell.
        if (parsed) {
          expect(parsed.schema).not.toBe("TypedMessageMetadata"); expect(vector.schema).toBe("TypedMessageMetadata");
          failure(() => reference.verifyTypedMetadata(raw, bytes("typed_definition_fields"), 8192n));
        }
      } else {
        positive += 1;
        const parsed = reference.streamMetadata(raw, BigInt(raw.length) + 1n)!;
        expect(parsed.schema, vector.id).toBe(vector.schema); expect(encode(parsed.value), vector.id).toEqual(raw);
        if (vector.typed_derivation) {
          bound += 1;
          const definition = hex(vector.typed_derivation.definition_hex), application = hex(vector.typed_derivation.application_hex);
          expect(reference.composeTypedMetadata(definition, application, 8192n)).toEqual(raw);
          expect(reference.verifyTypedMetadata(raw, definition, 8192n)).toEqual(application);
        }
      }
    }
    expect(positive).toBeGreaterThan(0); expect(negative).toBeGreaterThan(0); expect(bound).toBe(2);
  });

  // v4.ts_composition.metadata_boundaries
  it("enforces the total shell cap and detaches application bytes including Buffer inputs", () => {
    const definition = bytes("typed_definition_fields");
    expect(reference.streamMetadata(new Uint8Array(), 4096n)).toBeUndefined();
    failure(() => reference.streamMetadata(new Uint8Array(), 0n), "limit_unresolved");
    for (const application of [new Uint8Array(), bytes("metadata_empty_values"), bytes("metadata_4006")]) {
      const original = application.slice(), wrapped = reference.composeTypedMetadata(definition, application, 8192n);
      if (!application.length) expect(wrapped.length).toBe(88);
      if (application.length === 4006) expect(wrapped.length).toBe(4096);
      const exact = BigInt(Math.max(wrapped.length, definition.length));
      expect(reference.composeTypedMetadata(definition, application, exact)).toEqual(wrapped);
      failure(() => reference.composeTypedMetadata(definition, application, exact - 1n));
      const returned = reference.verifyTypedMetadata(wrapped, definition, 8192n);
      returned.fill(0); expect(application).toEqual(original);
      application.fill(0); expect(reference.verifyTypedMetadata(wrapped, definition, 8192n)).toEqual(original);
      const source = Buffer.from(wrapped), detached = reference.verifyTypedMetadata(source, definition, 8192n);
      source.fill(0); wrapped.fill(0); expect(detached).toEqual(original);
    }
    for (const id of ["metadata_4007", "metadata_4096"]) {
      const application = bytes(id); expect(reference.streamMetadata(application, 4096n)).toBeDefined();
      failure(() => reference.composeTypedMetadata(definition, application, 8192n));
    }
    failure(() => reference.composeTypedMetadata(definition, bytes("typed_metadata_empty"), 8192n));
    for (const input of [new Uint8Array(), bytes("metadata_empty_values")]) failure(() => reference.verifyTypedMetadata(input, definition, 8192n), "typed_metadata_required");
    failure(() => reference.verifyTypedMetadata(bytes("typed_metadata_bound_empty"), bytes("typed_definition_maximum"), 8192n), "typed_definition_mismatch");
  });

  // v4.ts_composition.definition_binding
  it("binds every definition field and both opener/acceptor directions", () => {
    const definition = bytes("typed_definition_fields"), wrapped = reference.composeTypedMetadata(definition, new Uint8Array(), 8192n);
    const change = (value: Value): Value => {
      if (value.kind === "uint") return uint(value.value - 1n);
      if (value.kind === "bytes") { const raw = value.value.slice(); raw[0] = raw[0]! ^ 1; return bstr(raw); }
      if (value.kind === "text") return { kind: "text", value: value.value + "x" };
      throw new Error("uncovered definition field");
    };
    for (const path of ["kind", "revision", "opener_to_acceptor.codec_schema_digest", "opener_to_acceptor.codec_revision", "opener_to_acceptor.max_message_bytes", "acceptor_to_opener.codec_schema_digest", "acceptor_to_opener.codec_revision", "acceptor_to_opener.max_message_bytes", "swap_directions"]) {
      const value = read(definition, "MessageStreamDefinition"), parts = path.split(".");
      if (path === "swap_directions") {
        const left = field("MessageStreamDefinition", value, "opener_to_acceptor"), right = field("MessageStreamDefinition", value, "acceptor_to_opener");
        set("MessageStreamDefinition", value, "opener_to_acceptor", right); set("MessageStreamDefinition", value, "acceptor_to_opener", left);
      } else if (parts.length === 2) {
        const direction = field("MessageStreamDefinition", value, parts[0]!);
        set("MessageStreamDirection", direction, parts[1]!, change(field("MessageStreamDirection", direction, parts[1]!)));
      } else set("MessageStreamDefinition", value, path, change(field("MessageStreamDefinition", value, path)));
      const raw = encode(value); read(raw, "MessageStreamDefinition");
      failure(() => reference.verifyTypedMetadata(wrapped, raw, 8192n), "typed_definition_mismatch");
    }
  });

  // v4.ts_composition.metadata_scope
  it("keeps invalid inner metadata separate from valid outer OPEN framing and digest", () => {
    for (const id of ["metadata_bad_namespace_0", "metadata_value_wrong_type", "typed_metadata_nested_wrapper", "typed_metadata_missing_application"]) {
      const value = read(bytes("open_fields"), "OPEN_STREAM"), metadata = bytes(id);
      set("OPEN_STREAM", value, "metadata", bstr(metadata)); set("OPEN_STREAM", value, "open_digest", bstr(reference.openDigest(value)));
      const received = read(encode(value), "OPEN_STREAM");
      expect(byteValue(field("OPEN_STREAM", received, "open_digest"))).toEqual(reference.openDigest(received));
      failure(() => reference.streamMetadata(metadata, 4096n));
    }
  });

  // v4.ts_composition.pool_reference
  it("binds pool references to original signed Artifact bytes, indices and domains", () => {
    const m = material([0n, 1n]); expect(reference.verifyPoolReference(m.artifact, m.reference, cap)).toEqual(m.selection);
    const artifact = read(m.artifact, "Artifact"); set("Artifact", artifact, "signature", bstr(new Uint8Array(64).fill(99)));
    failure(() => reference.verifyPoolReference(encode(artifact), m.reference, cap), "pool_artifact_digest");
    const selection = read(m.reference, "PoolSelectionRef"); set("PoolSelectionRef", selection, "candidate_indices", { kind: "array", value: [uint(0n)] });
    failure(() => reference.verifyPoolReference(m.artifact, encode(selection), cap), "pool_candidate_set_digest");
    set("PoolSelectionRef", selection, "candidate_set_digest", bstr(reference.derivePool(m.artifact, [0n], cap).routeSetDigest));
    failure(() => reference.verifyPoolReference(m.artifact, encode(selection), cap), "pool_candidate_set_digest");
  });

  // v4.ts_composition.pool_winner
  it("requires explicit source, immutable context, matching identities/deadlines and one paired winner", () => {
    const m = material([0n, 1n]), before = structuredClone(m.context);
    expect(authorize(m)).toEqual(m.selection); expect(m.context).toEqual(before);
    for (const context of [emptyContext(), { limits: {}, selectors: { activation_source_profile: "live_authority" } }]) failure(() => reference.poolAuthorizationProjection(m.artifact, m.fsb, context, cap), "pool_source_profile");
    failure(() => reference.poolAuthorizationProjection(m.artifact, m.fsb, { ...m.context, selectors: { ...m.context.selectors, crypto_profile_id: "wrong" } }, cap), "pool_crypto_profile");
    const context = parseContext(m);
    for (const [id, route, accepted] of [[0, 0, true], [1, 1, true], [0, 1, false]] as const) {
      const fsb = read(m.fsb, "FSB4", context);
      set("FSB4", fsb, "candidate_id", bstr(m.selection.members[id]!.candidateID)); set("FSB4", fsb, "route_digest", bstr(m.selection.members[route]!.routeDigest));
      if (accepted) expect(authorize(m, encode(fsb))).toEqual(m.selection);
      else failure(() => authorize(m, encode(fsb)), "pool_winner_membership");
    }
    for (const [name, key, expected] of [
      ["ActivationAuthorization", "route_selection", "pool_route_set_digest"], ["PoolSelectionRef", "candidate_set_digest", "pool_candidate_set_digest"],
      ["FSB4", "candidate_id", "pool_winner_membership"], ["FSB4", "session_nonce", "pool_artifact_binding"],
      ["ActivationAuthorization", "client_identity_digest", "pool_artifact_binding"], ["ActivationAuthorization", "server_identity_digest", "pool_artifact_binding"],
      ["ActivationAuthorization", "audience", "pool_artifact_binding"],
      ["ActivationAuthorization", "activation_not_after_ms", "pool_parent_deadline"], ["ActivationAuthorization", "session_not_after_ms", "pool_parent_deadline"],
      ["PoolSelectionRef", "artifact_digest", "field_equality"], ["ActivationAuthorization", "artifact_digest", "field_equality"],
    ] as const) {
      const fsb = read(m.fsb, "FSB4", context), proof = read(byteValue(field("FSB4", fsb, "activation_authorization")), "ActivationAuthorization", context);
      const target = name === "FSB4" ? fsb : name === "PoolSelectionRef" ? field("ActivationAuthorization", proof, "candidate_selection") : proof;
      const original = field(name, target, key); let replacement: Value;
      if (original.kind === "bytes") { const raw = original.value.slice(); raw[0] = raw[0]! ^ 0x80; replacement = bstr(raw); }
      else if (original.kind === "uint") replacement = uint(key === "activation_not_after_ms" ? 500001n : 1000001n);
      else if (original.kind === "text") replacement = { kind: "text", value: "other-audience" };
      else throw new Error("mutation fixture");
      set(name, target, key, replacement); set("FSB4", fsb, "activation_authorization", bstr(encode(proof)));
      if (key === "audience") {
        // Keep the earlier proof/certificate relation valid so this mutation
        // reaches the separate original-Artifact audience binding.
        const certificate = read(byteValue(field("FSB4", fsb, "client_certificate")), "IdentityCertificate");
        set("IdentityCertificate", certificate, "audience", replacement);
        set("FSB4", fsb, "client_certificate", bstr(encode(certificate)));
      }
      failure(() => authorize(m, encode(fsb)), expected);
    }
    expect(m.context).toEqual(before);
  });

  // v4.ts_composition.pool_boundaries
  it("enforces caps, truncation, once-authority, unselected winners and full UInt64 parent times", () => {
    const m = material([0n, 1n], true), context = parseContext(m); expect(authorize(m)).toEqual(m.selection);
    for (const limit of [0n, BigInt(m.artifact.length) - 1n]) failure(() => reference.poolAuthorizationProjection(m.artifact, m.fsb, m.context, limit));
    for (const [artifact, fsb] of [[m.artifact.subarray(0, -1), m.fsb], [m.artifact, m.fsb.subarray(0, -1)]] as const) failure(() => reference.poolAuthorizationProjection(artifact, fsb, m.context, cap));
    for (const authority of [false, true]) {
      const fsb = read(m.fsb, "FSB4", context), proof = read(byteValue(field("FSB4", fsb, "activation_authorization")), "ActivationAuthorization", context);
      if (authority) {
        const selection = field("ActivationAuthorization", proof, "candidate_selection"), once = field("PoolSelectionRef", selection, "once_authority_ref");
        set("OnceAuthorityRef", once, "spend_authority_id", { kind: "text", value: "wrong-authority" });
      } else set("ActivationAuthorization", proof, "activation_not_after_ms", uint(0xffffffffffffffffn));
      set("FSB4", fsb, "activation_authorization", bstr(encode(proof)));
      failure(() => authorize(m, encode(fsb)), authority ? "field_equality" : "pool_parent_deadline");
    }
    const single = material([0n]), both = material([0n, 1n]), fsb = read(single.fsb, "FSB4", context);
    set("FSB4", fsb, "candidate_id", bstr(both.selection.members[1]!.candidateID)); set("FSB4", fsb, "route_digest", bstr(both.selection.members[1]!.routeDigest));
    failure(() => authorize(single, encode(fsb)), "pool_winner_membership");
  });

  // v4.ts_composition.properties
  it("checks 4096 metadata and 4096 pool-proof mutations", () => {
    const definition = bytes("typed_definition_fields"), m = material([0n, 1n]), before = structuredClone(m.context);
    let state = 0x41c0a041;
    const next = (): number => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; };
    const mutate = (raw: Uint8Array): void => { const at = next() % raw.length; raw[at] = raw[at]! ^ (next() & 255); };
    for (let iteration = 0; iteration < 4096; iteration++) {
      const input = bytes(["metadata_empty_values", "metadata_key_order", "metadata_4006", "typed_metadata_bound_empty", "typed_metadata_bound_maximum", "typed_metadata_nested_wrapper"][next() % 6]!); mutate(input);
      const parsed = attempted(() => reference.streamMetadata(input, 4096n));
      if (parsed) {
        expect(encode(parsed.value)).toEqual(input);
        if (parsed.schema === "TypedMessageMetadata") {
          const application = attempted(() => reference.verifyTypedMetadata(input, definition, 8192n));
          if (application) expect(reference.composeTypedMetadata(definition, application, 8192n)).toEqual(input);
        } else {
          const wrapped = attempted(() => reference.composeTypedMetadata(definition, input, 8192n));
          if (wrapped) expect(reference.verifyTypedMetadata(wrapped, definition, 8192n)).toEqual(input);
        }
      }
      const artifact = m.artifact.slice(), fsb = m.fsb.slice(); mutate(next() % 2 === 0 ? artifact : fsb);
      const result = attempted(() => reference.poolAuthorizationProjection(artifact, fsb, m.context, cap));
      if (result) {
        expect(result).toEqual(reference.derivePool(artifact, [0n, 1n], cap));
        failure(() => reference.poolAuthorizationProjection(artifact, fsb, emptyContext(), cap), "pool_source_profile");
        const snapshot = structuredClone(result); artifact.fill(0); fsb.fill(0); expect(result).toEqual(snapshot);
      }
    }
    expect(m.context).toEqual(before);
  // This test runs two 4096-case properties. Allow their combined budget when
  // the mandatory gate runs all language suites concurrently; this is not a SLO.
  }, 60000);
});
