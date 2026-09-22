// Stateless composition only; no codec installation, trust or activation rights.
import { compare, encode, equal, uint } from "./cbor.js";
import type { Value } from "./cbor.js";
import { emptyContext, integer } from "./shape.js";
import type { Context } from "./shape.js";
import { Oracles, singleMapHash } from "./oracles.js";
import type { PoolProjection } from "./oracles.js";
import { V4Failure } from "./unicode.js";

export class Composition extends Oracles {
  fieldConstant(name: string, field: string): Value {
    const descriptor = this.namedField(name, field)[1];
    if (descriptor.type === "text" && typeof descriptor.const === "string") return { kind: "text", value: descriptor.const };
    if (descriptor.type === "uint16") return uint(integer(descriptor.const));
    throw new V4Failure("registry_unresolved");
  }

  streamMetadata(input: Uint8Array, cap: bigint): { schema: string; value: Value } | undefined {
    if (cap <= 0n) throw new V4Failure("limit_unresolved");
    if (!input.length) return undefined;
    // Select the exact shell before ordinary per-value limits can preempt the
    // reserved typed shell's whole-object allowance. Do not repair received bytes.
    const decoded = this.syntax.decode(input, "StreamMetadata", {}, cap);
    if (!decoded.ok) throw new V4Failure(decoded.error);
    const namespace = this.namedValue("StreamMetadata", decoded.value, "namespace");
    const typed = this.fieldConstant("TypedMessageMetadata", "namespace");
    const schema = namespace && equal(encode(namespace), encode(typed)) ? "TypedMessageMetadata" : "StreamMetadata";
    return { schema, value: this.wireMap(input, schema, emptyContext(), cap) };
  }

  definitionDigest(definition: Uint8Array, cap: bigint): Uint8Array {
    this.wireMap(definition, "MessageStreamDefinition", emptyContext(), cap);
    return singleMapHash("typed_message_definition_digest", "MessageStreamDefinition", "full", definition);
  }

  composeTypedMetadata(definition: Uint8Array, application: Uint8Array, cap: bigint): Uint8Array {
    const digest = this.definitionDigest(definition, cap);
    if (application.length) this.wireMap(application, "StreamMetadata", emptyContext(), cap);
    const values: [Value, Value][] = [
      [{ kind: "text", value: "definition" }, { kind: "bytes", value: digest }],
      [{ kind: "text", value: "application" }, { kind: "bytes", value: application }],
    ];
    // Canonical sorting is permitted only when constructing a new issuer map.
    values.sort(([a], [b]) => compare(encode(a), encode(b)));
    const value = this.namedMap("TypedMessageMetadata", [
      ["namespace", this.fieldConstant("TypedMessageMetadata", "namespace")],
      ["version", this.fieldConstant("TypedMessageMetadata", "version")],
      ["values", { kind: "map", value: values }],
    ]);
    const output = encode(value); this.wireMap(output, "TypedMessageMetadata", emptyContext(), cap); return output;
  }

  verifyTypedMetadata(input: Uint8Array, definition: Uint8Array, cap: bigint): Uint8Array {
    const digest = this.definitionDigest(definition, cap), parsed = this.streamMetadata(input, cap);
    if (parsed?.schema !== "TypedMessageMetadata") throw new V4Failure("typed_metadata_required");
    const values = this.requiredValue(parsed.schema, parsed.value, "values");
    if (values.kind !== "map") throw new V4Failure("field_type");
    const field = (name: string): Value | undefined => values.value.find(([key]) => key.kind === "text" && key.value === name)?.[1];
    const actual = field("definition"), application = field("application");
    if (actual?.kind !== "bytes" || application?.kind !== "bytes") throw new V4Failure("field_type");
    if (!equal(actual.value, digest)) throw new V4Failure("typed_definition_mismatch");
    return new Uint8Array(application.value);
  }

  verifyPoolReference(artifact: Uint8Array, reference: Uint8Array, cap: bigint): PoolProjection {
    const value = this.wireMap(reference, "PoolSelectionRef", emptyContext(), cap);
    const items = this.requiredValue("PoolSelectionRef", value, "candidate_indices");
    if (items.kind !== "array") throw new V4Failure("field_type");
    const indices = items.value.map(item => { if (item.kind !== "uint") throw new V4Failure("integer_type"); return item.value; });
    const result = this.derivePool(artifact, indices, cap);
    for (const [field, expected, code] of [
      ["artifact_digest", result.artifactDigest, "pool_artifact_digest"],
      ["candidate_set_digest", result.candidateSetDigest, "pool_candidate_set_digest"],
    ] as const) {
      const actual = this.requiredValue("PoolSelectionRef", value, field);
      if (actual.kind !== "bytes" || !equal(actual.value, expected)) throw new V4Failure(code);
    }
    return result;
  }

  poolAuthorizationProjection(artifactBytes: Uint8Array, fsbBytes: Uint8Array, context: Context, cap: bigint): PoolProjection {
    // The immutable source is supplied by the caller, never inferred from proof.
    if (context.selectors.activation_source_profile !== "preauthorized_pool") throw new V4Failure("pool_source_profile");
    const artifact = this.wireMap(artifactBytes, "Artifact", emptyContext(), cap);
    const profile = this.requiredValue("Artifact", artifact, "crypto_profile_id");
    if (profile.kind !== "text") throw new V4Failure("field_type");
    if (context.selectors.crypto_profile_id !== undefined && context.selectors.crypto_profile_id !== profile.value) throw new V4Failure("pool_crypto_profile");
    const scoped: Context = { limits: context.limits, selectors: { ...context.selectors, crypto_profile_id: profile.value } };
    const fsb = this.wireMap(fsbBytes, "FSB4", scoped, cap), proofBytes = this.requiredValue("FSB4", fsb, "activation_authorization");
    if (proofBytes.kind !== "bytes") throw new V4Failure("field_type");
    const proof = this.wireMap(proofBytes.value, "ActivationAuthorization", scoped, cap);
    const reference = this.requiredValue("ActivationAuthorization", proof, "candidate_selection");
    const result = this.verifyPoolReference(artifactBytes, encode(reference), cap);
    for (const [name, value, fields] of [
      ["FSB4", fsb, ["tenant_id", "issuer_key_id", "lease_id", "session_nonce"]],
      ["ActivationAuthorization", proof, ["client_identity_digest", "server_identity_digest", "audience"]],
    ] as const) {
      for (const field of fields) if (!equal(encode(this.requiredValue("Artifact", artifact, field)), encode(this.requiredValue(name, value, field)))) throw new V4Failure("pool_artifact_binding");
    }
    for (const [name, value, field, expected, code] of [
      ["FSB4", fsb, "artifact_digest", result.artifactDigest, "pool_artifact_digest"],
      ["ActivationAuthorization", proof, "artifact_digest", result.artifactDigest, "pool_artifact_digest"],
      ["ActivationAuthorization", proof, "route_selection", result.routeSetDigest, "pool_route_set_digest"],
    ] as const) {
      const actual = this.requiredValue(name, value, field);
      if (actual.kind !== "bytes" || !equal(actual.value, expected)) throw new V4Failure(code);
    }
    for (const [child, parent] of [["activation_not_after_ms", "initiation_not_after_ms"], ["session_not_after_ms", "session_not_after_ms"]] as const) {
      const deadline = this.requiredValue("ActivationAuthorization", proof, child), bound = this.requiredValue("Artifact", artifact, parent);
      if (deadline.kind !== "uint" || bound.kind !== "uint") throw new V4Failure("field_type");
      if (deadline.value > bound.value) throw new V4Failure("pool_parent_deadline");
    }
    const id = this.requiredValue("FSB4", fsb, "candidate_id"), route = this.requiredValue("FSB4", fsb, "route_digest");
    if (id.kind !== "bytes" || route.kind !== "bytes") throw new V4Failure("field_type");
    if (!result.members.some(member => equal(member.candidateID, id.value) && equal(member.routeDigest, route.value))) throw new V4Failure("pool_winner_membership");
    return result;
  }
}
