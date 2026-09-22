// Stateless external composition; no trust, admission or winner authority.
import { createHash } from "node:crypto";
import { transportV4Domains } from "../../generated/transportV4Registry.js";
import { encode, equal, join, own, uint } from "./cbor.js";
import type { Field, Value } from "./cbor.js";
import { emptyContext, integer, lookup, record } from "./shape.js";
import { array, hex } from "./rules.js";
import { TextReference } from "./text.js";
import { V4Failure } from "./unicode.js";

export function singleMapHash(name: string, schema: string, projection: string, input: Uint8Array): Uint8Array {
  const domain = (transportV4Domains as readonly unknown[]).map(record).find(domain => domain.name === name);
  if (!domain) throw new V4Failure("registry_unresolved");
  const parts = array(record(domain.input_schema).parts);
  if (domain.operation !== "sha256" || integer(domain.output_length) !== 32n || parts.length !== 1 || record(parts[0]).encoding !== "lp-map" || record(parts[0]).schema_ref !== schema || record(parts[0]).projection !== projection) throw new V4Failure("domain_projection");
  if (input.length > 0xffffffff) throw new V4Failure("map_size");
  const length = new Uint8Array(4); new DataView(length.buffer).setUint32(0, input.length, false);
  return new Uint8Array(createHash("sha256").update(join([hex(domain.label_bytes), length, input])).digest());
}

export type PoolMember = { index: bigint; candidateID: Uint8Array; routeDigest: Uint8Array };
export type PoolProjection = { encoded: Uint8Array; artifactDigest: Uint8Array; candidateSetDigest: Uint8Array; routeSetDigest: Uint8Array; members: PoolMember[] };

export class Oracles extends TextReference {
  namedField(name: string, field: string): [bigint, Field] {
    const entry = Object.entries(this.descriptor(name).fields).find(([, descriptor]) => descriptor.name === field);
    if (!entry) throw new V4Failure("unknown_field"); return [BigInt(entry[0]), entry[1]];
  }

  namedValue(name: string, value: Value, field: string): Value | undefined {
    return lookup(value, this.namedField(name, field)[0]);
  }

  requiredValue(name: string, value: Value, field: string): Value {
    const actual = this.namedValue(name, value, field);
    if (actual === undefined) throw new V4Failure("missing_field"); return actual;
  }

  // Construction orders registered IDs; received candidate indices are not sorted.
  namedMap(name: string, fields: readonly (readonly [string, Value | undefined])[]): Value {
    const entries: [bigint, Value][] = [];
    for (const [field, value] of fields) {
      const [id] = this.namedField(name, field); if (value !== undefined) entries.push([id, value]);
    }
    entries.sort(([a], [b]) => a === b ? 0 : a < b ? -1 : 1);
    for (let i = 1; i < entries.length; i++) if (entries[i - 1]![0] === entries[i]![0]) throw new V4Failure("duplicate_field");
    return { kind: "map", value: entries.map(([id, value]) => [uint(id), value]) };
  }

  // Callers validate the complete OPEN before invoking its digest projection.
  openDigest(value: Value): Uint8Array {
    const [id] = this.namedField("OPEN_STREAM", "open_digest");
    if (value.kind !== "map") throw new V4Failure("map_type");
    if (lookup(value, id) === undefined) throw new V4Failure("missing_field");
    const unsigned: Value = { kind: "map", value: value.value.filter(([key]) => key.kind !== "uint" || key.value !== id) };
    return singleMapHash("open_digest", "OPEN_STREAM", "without_open_digest", encode(unsigned));
  }

  projectCandidate(candidate: Value): Value {
    const projection = own(this.registry.map_projections, "candidate_route");
    if (!projection) throw new V4Failure("projection_unresolved");
    const input = encode(candidate); this.wireMap(input, projection.source, emptyContext(), BigInt(input.length));
    const result = this.namedMap(projection.target, projection.fields.map(field => [field, this.namedValue(projection.source, candidate, field)]));
    const raw = encode(result); this.wireMap(raw, projection.target, emptyContext(), BigInt(raw.length)); return result;
  }

  derivePool(input: Uint8Array, indices: readonly bigint[], cap: bigint): PoolProjection {
    const artifact = this.wireMap(input, "Artifact", emptyContext(), cap);
    const [, field] = this.namedField("PoolSelectionRef", "candidate_indices");
    // Bound the original complete list before allocating per-member state.
    if (BigInt(indices.length) < integer(field.min_items) || BigInt(indices.length) > integer(field.max_items)) throw new V4Failure("array_length");
    const candidates = this.requiredValue("Artifact", artifact, "candidates");
    if (candidates.kind !== "array" || !field.items) throw new V4Failure("field_type");
    const members: PoolMember[] = [];
    for (let position = 0; position < indices.length; position++) {
      const index = indices[position]!;
      this.checkField(field.items, uint(index), emptyContext());
      if (position > 0 && indices[position - 1]! >= index) throw new V4Failure("array_order");
      if (index >= BigInt(candidates.value.length)) throw new V4Failure("pool_index_membership");
      const candidate = candidates.value[Number(index)]!, route = this.projectCandidate(candidate);
      const routeDigest = singleMapHash("route_digest", "Route", "full", encode(route));
      const id = this.requiredValue("Candidate", candidate, "candidate_id");
      if (id.kind !== "bytes") throw new V4Failure("field_type");
      members.push({ index, candidateID: new Uint8Array(id.value), routeDigest });
    }
    const artifactDigest = singleMapHash("artifact_digest", "Artifact", "full", input);
    const entries = members.map(member => this.namedMap("PoolRouteRef", [["candidate_index", uint(member.index)], ["candidate_id", { kind: "bytes", value: member.candidateID }], ["route_digest", { kind: "bytes", value: member.routeDigest }]]));
    const selection = this.namedMap("PoolSelectionSet", [["artifact_digest", { kind: "bytes", value: artifactDigest }], ["entries", { kind: "array", value: entries }]]);
    const encoded = encode(selection); this.wireMap(encoded, "PoolSelectionSet", emptyContext(), BigInt(encoded.length));
    return { encoded, artifactDigest, candidateSetDigest: singleMapHash("candidate_set_digest", "PoolSelectionSet", "full", encoded), routeSetDigest: singleMapHash("route_set_digest", "PoolSelectionSet", "full", encoded), members };
  }

  verifyPoolSet(artifact: Uint8Array, indices: readonly bigint[], received: Uint8Array, cap: bigint): PoolProjection {
    this.wireMap(received, "PoolSelectionSet", emptyContext(), cap);
    const result = this.derivePool(artifact, indices, cap);
    if (!equal(result.encoded, received)) throw new V4Failure("pool_set_membership"); return result;
  }
}
