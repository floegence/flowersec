import { cborDecoderCharge } from "./cbor.js";
import { ResourceVector, type ProtectedResourceReservation } from "./resources.js";
import { type DecodeContext } from "./schema.js";
import { type CredentialWork, type OwnedCredentialMap, equalCredential, requireCredential } from "./credentialSupport.js";

/** Original protected namespace arenas. All old/new parsing and signature
 * overlap is reserved before bootstrap, including canceled provider tails. */
export class NamespaceArenas {
  readonly #pools = new Map<string, { slot: ProtectedResourceReservation; busy: boolean }[]>();
  readonly #configs = new Map<string, { bytes: number; nodes: number }>();
  readonly #backing: ProtectedResourceReservation;
  #closed = false;
  constructor(private readonly work: CredentialWork, stateBytes: number, stateNodes: number, trustSlots: number, trustNodes: number, runtime: bigint) {
    this.#backing = work.protect("namespace_metadata", new ResourceVector([BigInt(270336 + stateBytes + 8192) + runtime, 0n, 0n, 16n, 2n, 2n, 1n, 0n, 0n, 2n, 0n]));
    try {
      for (const [name, bytes, nodes, count] of [["TrustConfig", 262144, trustNodes, trustSlots], ["TrustBootstrapResponse", 270336, trustNodes, 1],
        ["FreshnessHead", 795, 795, 4], ["RevocationState", stateBytes, stateNodes, 2]] as const) {
        this.#configs.set(name, { bytes, nodes }); const pool: { slot: ProtectedResourceReservation; busy: boolean }[] = []; this.#pools.set(name, pool);
        const charge = cborDecoderCharge({ bytes, nodes, textBytes: Math.min(bytes, 4096), arrayItems: nodes, runtimeBytes: runtime });
        for (let i = 0; i < count; i++) pool.push({ slot: work.protect("namespace_arena", charge, 1), busy: false });
      }
      work.prepaySignatures(270336, trustNodes);
    } catch (error) { this.close(); throw error; }
  }
  parse(raw: Uint8Array, schema: string, context: DecodeContext = {}): OwnedCredentialMap {
    requireCredential(!this.#closed, "credential_closed"); const pool = this.#pools.get(schema), config = this.#configs.get(schema);
    const entry = pool?.find(slot => !slot.busy); requireCredential(entry !== undefined && config !== undefined, "configuration_capacity"); entry.busy = true;
    let ref;
    try { ref = entry.slot.checkout(); return this.work.parse(raw, schema, config.bytes, config.nodes, context, ref, () => { entry.busy = false; }); }
    catch (error) { entry.busy = false; throw error; } finally { ref?.release(); }
  }
  close(): void { if (this.#closed) return; this.#closed = true; for (const pool of this.#pools.values()) for (const entry of pool) entry.slot.closeAfterUse(); this.#backing.closeAfterUse(); }
}
const equalField = (a: OwnedCredentialMap, an: number, as: string, b: OwnedCredentialMap, bn: number, bs: string, field: string): boolean =>
  equalCredential(a.encoded(a.field(field, an, as)), b.encoded(b.field(field, bn, bs)));
export function sameMap(a: OwnedCredentialMap, an: number, b: OwnedCredentialMap, bn: number): boolean { return equalCredential(a.encoded(an), b.encoded(bn)); }
export function namespaceFloors(map: OwnedCredentialMap): readonly [bigint, bigint] { const nodes = [...map.items("credential_revocation_floors")]; return [map.doc.uint(nodes[0]!), map.doc.uint(nodes[1]!)]; }
export function containsID(map: OwnedCredentialMap, field: string, bytes: Uint8Array): boolean {
  for (const n of map.items(field)) { const value = new Uint8Array(map.doc.size(n)); map.doc.copyPayload(n, value); if (equalCredential(bytes, value)) return true; } return false;
}
export function revokedIssuer(state: OwnedCredentialMap | undefined, issuer: Uint8Array): boolean {
  return state !== undefined && [...state.items("revoked_issuers")].some(n => equalCredential(state.bytes("issuer_key_id", n, "RevokedIssuerEntry"), issuer));
}
const permissionKinds = [["issuer_authorizations", "CredentialIssuerAuthorization", "credential_issuer_authorization_digest", "issuer_public_key"],
  ["activation_delegations", "ConnectionActivationDelegation", "connection_activation_delegation_digest", "signer_public_key"]] as const;

/** History is a bounded set of original signed configurations. It cannot be
 * replaced by the latest permissions, expiry or a mutable map of key names. */
export function checkTrustTransition(history: readonly OwnedCredentialMap[], next: OwnedCredentialMap, state: OwnedCredentialMap | undefined, work: CredentialWork): void {
  const previous = history.at(-1); if (previous === undefined) return;
  requireCredential(next.uint("revision") > previous.uint("revision") && next.uint("issued_at_ms") >= previous.uint("issued_at_ms") && next.uint("authority_generation") >= previous.uint("authority_generation"));
  for (const field of ["capacity", "publication"]) requireCredential(equalField(previous, 0, "TrustConfig", next, 0, "TrustConfig", field), "credential_untrusted");
  for (const old of history) {
    for (const field of ["retired_issuers", "rejected_head_signers"]) for (const n of old.items(field)) {
      const bytes = new Uint8Array(old.doc.size(n)); old.doc.copyPayload(n, bytes); requireCredential(containsID(next, field, bytes), "credential_untrusted");
    }
    for (const [field, schema, identifiers] of [["issuer_authorizations", "CredentialIssuerAuthorization", ["authorization_id"]],
      ["head_delegations", "HeadSignerDelegation", ["delegation_id"]], ["activation_delegations", "ConnectionActivationDelegation", ["signing_key_id"]],
      ["once_authorities", "OnceAuthorityRef", ["artifact_issuer_key_id"]], ["credential_policies", "CredentialRevocationPolicy", ["revocation_policy_id", "revocation_policy_revision"]]] as const) {
      for (const a of old.items(field)) for (const b of next.items(field)) if (identifiers.every(id => equalField(old, a, schema, next, b, schema, id))) requireCredential(sameMap(old, a, next, b), "credential_untrusted");
    }
    for (const a of old.items("head_delegations")) for (const b of next.items("head_delegations")) if (equalField(old, a, "HeadSignerDelegation", next, b, "HeadSignerDelegation", "signer_key_id"))
      requireCredential(equalField(old, a, "HeadSignerDelegation", next, b, "HeadSignerDelegation", "signer_public_key"), "credential_untrusted");
    for (const [af, as, , ak] of permissionKinds) for (const [bf, bs, , bk] of permissionKinds) for (const a of old.items(af)) for (const b of next.items(bf))
      if (equalField(old, a, as, next, b, bs, "issuer_key_id")) requireCredential(equalCredential(old.bytes(ak, a, as), next.bytes(bk, b, bs)), "credential_untrusted");
    if (next.uint("authority_generation") > old.uint("authority_generation")) {
      for (const [field, schema] of permissionKinds) for (const a of old.items(field)) requireCredential(containsID(next, "retired_issuers", old.bytes("issuer_key_id", a, schema)), "credential_untrusted");
      for (const a of old.items("head_delegations")) requireCredential(containsID(next, "rejected_head_signers", old.bytes("signer_key_id", a, "HeadSignerDelegation")), "credential_untrusted");
    }
  }
  for (const [field, schema, domain] of permissionKinds) for (const n of next.items(field)) {
    const issuer = next.bytes("issuer_key_id", n, schema), proof = work.digest(next, domain, n);
    const known = history.some(old => [...old.items(field)].some(a => equalCredential(old.bytes("issuer_key_id", a, schema), issuer) && equalCredential(work.digest(old, domain, a), proof)));
    if (!known) requireCredential(!containsID(previous, "retired_issuers", issuer) && !revokedIssuer(state, issuer), "credential_revoked");
  }
}
export function checkStateHistory(history: readonly OwnedCredentialMap[], state: OwnedCredentialMap, work: CredentialWork): void {
  for (const old of history) {
    if (old.uint("authority_generation") !== state.uint("authority_generation")) continue;
    for (const [field, schema, domain] of permissionKinds) for (const a of old.items(field)) {
      const issuer = old.bytes("issuer_key_id", a, schema), denied = [...state.items("revoked_issuers")].find(n => equalCredential(state.bytes("issuer_key_id", n, "RevokedIssuerEntry"), issuer));
      if (denied === undefined) continue;
      const digest = work.digest(old, domain, a), impact = [...state.items("authorizations", denied, "RevokedIssuerEntry")].find(n => equalCredential(state.bytes("authorization_digest", n, "IssuerAuthorizationImpact"), digest));
      requireCredential(impact !== undefined, "credential_untrusted");
      for (const name of ["max_affected_cohorts", "signing_not_before_ms", "signing_not_after_ms"]) requireCredential(equalField(old, a, schema, state, impact, "IssuerAuthorizationImpact", name), "credential_untrusted");
    }
  }
}
export function checkStateSuccessor(previous: OwnedCredentialMap, next: OwnedCredentialMap, trust: OwnedCredentialMap): void {
  if (next.uint("authority_generation") > previous.uint("authority_generation")) return;
  requireCredential(next.uint("authority_generation") === previous.uint("authority_generation")); const floors = namespaceFloors(next), oldFloors = namespaceFloors(previous);
  for (let i = 0; i < 2; i++) requireCredential(floors[i]! >= oldFloors[i]!);
  for (const [field, schema, ids, kind] of [["revoked_certificates", "RevokedCertificateEntry", ["certificate_digest"], 0], ["revoked_leases", "RevokedLeaseEntry", ["issuer_key_id", "lease_id"], 1]] as const) {
    const entries = [...next.items(field)];
    for (const n of previous.items(field)) {
      const match = entries.find(m => ids.every(id => equalField(previous, n, schema, next, m, schema, id)));
      if (match === undefined) requireCredential(previous.uint("cohort", n, schema) < floors[kind], "credential_untrusted");
      else requireCredential(sameMap(previous, n, next, match), "credential_untrusted");
    }
  }
  for (const n of previous.items("cohort_policy_segments")) {
    if ([...next.items("cohort_policy_segments")].some(m => sameMap(previous, n, next, m))) continue;
    for (const [kind, field] of ["certificate_impact_ms", "connection_impact_ms"].entries()) if (previous.optional(field, n, "CohortPolicySegment") >= 0)
      requireCredential(previous.uint("last_cohort", n, "CohortPolicySegment") < floors[kind]!, "credential_untrusted");
  }
  for (const n of previous.items("revoked_issuers")) {
    const issuer = previous.bytes("issuer_key_id", n, "RevokedIssuerEntry"), match = [...next.items("revoked_issuers")].find(m => equalCredential(next.bytes("issuer_key_id", m, "RevokedIssuerEntry"), issuer));
    if (match === undefined) requireCredential(containsID(trust, "retired_issuers", issuer), "credential_untrusted");
    for (const a of previous.items("authorizations", n, "RevokedIssuerEntry")) {
      if (match !== undefined && [...next.items("authorizations", match, "RevokedIssuerEntry")].some(b => sameMap(previous, a, next, b))) continue;
      requireCredential(match === undefined, "credential_untrusted");
      for (const [kind, max] of [...previous.items("max_affected_cohorts", a, "IssuerAuthorizationImpact")].entries())
        if (previous.doc.kind(max) !== "null") requireCredential(previous.doc.uint(max) < floors[kind]!, "credential_untrusted");
    }
  }
}
