import { FixedCBORWriter } from "../v4/runtime/openAdmission.js";
import { type OwnedCredentialMap, CredentialWork, credentialWorkCharge, credentialOwner, equalCredential, requireCredential } from "../v4/runtime/credentialSupport.js";
import type { VerifiedCredentialClosure, ServerAdmissionFields } from "../v4/runtime/credentialVerifier.js";
import { isVerifiedRelayCredentials, type VerifiedRelayCredentials, type RelayClaimFields } from "../v4/runtime/relayCredentials.js";
import type { ResourceReference } from "../v4/runtime/resources.js";
import type { CredentialResources } from "../v4/runtime/credentialSupport.js";
import { verifyEd25519 } from "../v4/runtime/ed25519.js";
import { wireDomains } from "../v4/runtime/schemaRegistry.js";
import { admissionLeaseKey, encodeParentWinner } from "./admissionRecord.js";

export interface RelayIssuanceRecord {
  readonly fields: Omit<ServerAdmissionFields, "admissionBinding">;
  readonly lease: Uint8Array; readonly candidate: Uint8Array; readonly parent: Uint8Array; readonly winner: Uint8Array;
  readonly root: Uint8Array; readonly endpointCertificates: readonly Uint8Array[]; readonly relayCertificates: readonly Uint8Array[]; readonly grants: readonly Uint8Array[]; readonly grantDigests: readonly Uint8Array[];
  readonly retainedUntil: bigint;
}
/** Called only by the original issuance owner before publishing the material.
 * The relay never constructs this record from a received claim or a lookup. */
export function captureRelayIssuance(resources: CredentialResources, closure: VerifiedCredentialClosure, legs: readonly [VerifiedRelayCredentials, VerifiedRelayCredentials], reference: ResourceReference, maxBytes: number): RelayIssuanceRecord {
  const fields = closure.parentSelectionFields(reference);
  let preparation: ReturnType<VerifiedCredentialClosure["clientPreparation"]> | undefined, workRef: ResourceReference | undefined, work: CredentialWork | undefined, buffer: Uint8Array | undefined;
  const grants: Uint8Array[] = [], endpointCertificates: Uint8Array[] = [], relayCertificates: Uint8Array[] = [], digests: Uint8Array[] = []; let parent: Uint8Array | undefined, root: Uint8Array | undefined;
  try {
    preparation = closure.clientPreparation(reference);
    requireCredential(preparation.pathKind === 1 && legs.every(isVerifiedRelayCredentials) && legs[0].role === 0 && legs[1].role === 1);
    workRef = resources.root.reserve({ owner: credentialOwner(resources, "relay_issuance_projection"), accounts: resources.accounts, charge: credentialWorkCharge(65536, resources.runtimeBytes) });
    buffer = new Uint8Array(maxBytes); requireCredential(workRef.sameEnvironment(reference)); work = new CredentialWork(resources, 65536, workRef); work.prepayParsers(65536, 16384, 2);
    for (const [role, leg] of legs.entries()) {
      leg.check(reference); endpointCertificates.push(leg.certificate("endpoint", reference)); relayCertificates.push(leg.certificate("relay", reference)); const bytes = leg.grant(reference), grant = work.parse(bytes, "Grant", 65536); grants.push(bytes);
      try {
        const ref = grant.field("parent_ref"), descriptor = grant.encoded(grant.field("route_descriptor"));
        try { requireCredential(equalCredential(descriptor, preparation.route)); } finally { descriptor.fill(0); }
        requireCredential(equalCredential(grant.bytes("artifact_digest", ref, "GrantParentRef"), fields.artifactDigest) && equalCredential(grant.bytes("lease_id", ref, "GrantParentRef"), fields.lease) &&
          equalCredential(grant.bytes("artifact_issuer_key_id", ref, "GrantParentRef"), fields.issuer) && equalCredential(grant.bytes("attempt_id"), fields.attempt));
        const ids = [...grant.items("identity_digests")];
        for (const [index, node] of ids.entries()) { const digest = new Uint8Array(32); grant.doc.copyPayload(node, digest); try { requireCredential(equalCredential(digest, fields.identities[index]!)); } finally { digest.fill(0); } }
        const currentParent = grant.encoded(ref), winner = new Uint8Array(encodeParentWinner(buffer, fields));
        let currentRoot: Uint8Array;
        try { currentRoot = new Uint8Array(encodeRelayRoot(buffer, winner, currentParent, grant)); } finally { winner.fill(0); }
        if (role === 0) { parent = currentParent; root = currentRoot; }
        else { requireCredential(equalCredential(currentParent, parent!) && equalCredential(currentRoot, root!)); currentParent.fill(0); currentRoot.fill(0); }
        digests.push(work.digest(grant, "grant_digest"));
      } finally { grant.close(); }
    }
    const winner = new Uint8Array(encodeParentWinner(buffer, fields)), parentMap = work.parse(parent!, "GrantParentRef", 8192), end = parentMap.uint("session_not_after_ms"); parentMap.close();
    const retainedUntil = end + 604800000n; requireCredential(retainedUntil <= 0xffffffffffffffffn, "configuration_capacity");
    return Object.freeze({ fields, lease: admissionLeaseKey(fields), candidate: new Uint8Array(fields.candidateID), parent: parent!, winner, root: root!, endpointCertificates: Object.freeze(endpointCertificates), relayCertificates: Object.freeze(relayCertificates), grants: Object.freeze(grants), grantDigests: Object.freeze(digests), retainedUntil });
  } catch (error) { parent?.fill(0); root?.fill(0); for (const bytes of [...grants, ...digests, ...endpointCertificates, ...relayCertificates]) bytes.fill(0); clearRelayFields(fields); throw error; }
  finally { buffer?.fill(0); work?.close(); workRef?.release(); if (preparation !== undefined) { for (const value of Object.values(preparation)) if (value instanceof Uint8Array) value.fill(0); for (const value of [...preparation.identities, ...preparation.noiseKeys, ...preparation.identityKeys]) value.fill(0); } }
}
/** Reproduce the immutable root from original encoded parent/winner records.
 * This is a projection only; it cannot create an issuance or claim fact. */
function encodeRelayRoot(buffer: Uint8Array, winner: Uint8Array, parent: Uint8Array, grant: OwnedCredentialMap): Uint8Array {
  const values = [grant.bytes("pairing_id"), grant.bytes("relay_identity_digest"), grant.bytes("session_contract_digest"), grant.bytes("route_digest"),
    new TextEncoder().encode(grant.text("service")), new TextEncoder().encode(grant.text("audience"))];
  try { return new FixedCBORWriter(buffer).array(8).data(winner).data(parent).data(values[0]!).data(values[1]!).data(values[2]!).data(values[3]!).data(values[4]!, true).data(values[5]!, true).result(); }
  finally { for (const value of values) value.fill(0); }
}
export interface PersistedRelayIssuance {
  readonly lease: Uint8Array; readonly candidate: Uint8Array; readonly side: number; readonly grant_digest: Uint8Array; readonly grant: Uint8Array;
  readonly endpoint_certificate: Uint8Array; readonly relay_certificate: Uint8Array; readonly root: Uint8Array; readonly winner: Uint8Array;
  readonly source: number; readonly winner_authority: string; readonly original: Uint8Array; readonly retained_until: Uint8Array;
}
function arrayNodes(map: OwnedCredentialMap, count: number): number[] {
  const doc = map.doc; requireCredential(doc.kind() === "array" && doc.size() === count, "credential_invalid");
  const nodes: number[] = []; for (let node = doc.firstChild(); node >= 0; node = doc.nextSibling(node)) nodes.push(node);
  requireCredential(nodes.length === count, "credential_invalid"); return nodes;
}
function recordBytes(map: OwnedCredentialMap, node: number, expected: Uint8Array): void {
  const doc = map.doc; requireCredential(doc.kind(node) === "bytes" && doc.size(node) === expected.length, "credential_invalid");
  for (let i = 0; i < expected.length; i++) requireCredential(doc.payloadByte(node, i) === expected[i], "credential_invalid");
}
function matchGrantBytes(map: OwnedCredentialMap, node: number, grant: OwnedCredentialMap, field: string, parent = false): void {
  const expected = parent ? grant.bytes(field, grant.field("parent_ref"), "GrantParentRef") : grant.bytes(field);
  try { recordBytes(map, node, expected); } finally { expected.fill(0); }
}
/** Reopen compares the complete canonical projection, not just SQL links.
 * Historic credentials may now be revoked; this checks immutable persisted
 * facts without reauthorizing them against today's namespace or clock. */
export function validatePersistedRelayIssuance(work: CredentialWork, row: PersistedRelayIssuance, buffer: Uint8Array): void {
  const maps: OwnedCredentialMap[] = []; const owned: Uint8Array[] = [];
  try {
    const grant = work.parse(row.grant, "Grant", 65536); maps.push(grant);
    const endpoint = work.parse(row.endpoint_certificate, "IdentityCertificate", 8192); maps.push(endpoint);
    const relay = work.parse(row.relay_certificate, "IdentityCertificate", 8192); maps.push(relay);
    const winner = work.parseRecord(row.winner, buffer.length, 64); maps.push(winner); const n = arrayNodes(winner, 18), doc = winner.doc;
    requireCredential(row.side === 0 || row.side === 1);
    requireCredential(doc.text(n[0]!) === "flowersec/parent-winner/1" && doc.text(n[1]!) === (row.source === 0 ? "live_authority" : "preauthorized_pool") &&
      (row.source === 0 && row.winner_authority === "" || row.source === 1 && row.winner_authority.length > 0) && doc.text(n[2]!) === grant.text("tenant_id") && doc.text(n[3]!) === row.winner_authority && doc.text(n[4]!) === endpoint.text("audience"));
    requireCredential(endpoint.uint("role") === BigInt(row.side) && relay.uint("role") === 2n && endpoint.text("tenant_id") === grant.text("tenant_id") && relay.text("tenant_id") === grant.text("tenant_id") &&
      relay.text("audience") === grant.text("audience") && endpoint.text("crypto_profile_id") === relay.text("crypto_profile_id"));
    const role = grant.uint("role_mask", grant.field("namespace"), "GrantNamespace"); requireCredential(role === (4n | 1n << BigInt(row.side)));
    matchGrantBytes(winner, n[5]!, grant, "artifact_issuer_key_id", true); matchGrantBytes(winner, n[6]!, grant, "lease_id", true); matchGrantBytes(winner, n[7]!, grant, "artifact_digest", true);
    requireCredential(doc.kind(n[8]!) === "bytes" && doc.size(n[8]!) === 32 && doc.kind(n[9]!) === "bytes" && doc.size(n[9]!) === (row.source === 0 ? 0 : 32));
    recordBytes(winner, n[10]!, row.candidate); const candidate = grant.bytes("candidate_id", grant.field("route_descriptor"), "Route"); owned.push(candidate); requireCredential(equalCredential(candidate, row.candidate)); matchGrantBytes(winner, n[11]!, grant, "route_digest"); matchGrantBytes(winner, n[12]!, grant, "attempt_id");
    const ids = [...grant.items("identity_digests")]; requireCredential(ids.length === 2);
    for (let side = 0; side < 2; side++) { const id = new Uint8Array(32); owned.push(id); grant.doc.copyPayload(ids[side]!, id); recordBytes(winner, n[13 + side]!, id); }
    const endpointDigest = work.digest(endpoint, "certificate_digest"), relayDigest = work.digest(relay, "certificate_digest"), grantDigest = work.digest(grant, "grant_digest"); owned.push(endpointDigest, relayDigest, grantDigest);
    recordBytes(winner, n[13 + row.side]!, endpointDigest); const expectedRelay = grant.bytes("relay_identity_digest"); owned.push(expectedRelay);
    requireCredential(equalCredential(relayDigest, expectedRelay) && equalCredential(grantDigest, row.grant_digest));
    const parent = grant.encoded(grant.field("parent_ref")); owned.push(parent); requireCredential(equalCredential(parent, row.original));
    const issuer = grant.bytes("artifact_issuer_key_id", grant.field("parent_ref"), "GrantParentRef"), leaseID = grant.bytes("lease_id", grant.field("parent_ref"), "GrantParentRef"); owned.push(issuer, leaseID);
    const lease = admissionLeaseKey({ tenant: grant.text("tenant_id"), issuer, lease: leaseID } as ServerAdmissionFields); owned.push(lease);
    const routeDigest = work.digest(grant, "route_digest", grant.field("route_descriptor")), expectedRoute = grant.bytes("route_digest"); owned.push(routeDigest, expectedRoute);
    const computedRoot = encodeRelayRoot(buffer, row.winner, parent, grant); owned.push(computedRoot);
    requireCredential(equalCredential(routeDigest, expectedRoute) && equalCredential(lease, row.lease) && equalCredential(computedRoot, row.root));
    const issued = doc.uint(n[15]!), activationEnd = doc.uint(n[16]!), sessionEnd = doc.uint(n[17]!), ref = grant.field("parent_ref");
    requireCredential(issued <= activationEnd && activationEnd <= grant.uint("initiation_not_after_ms", ref, "GrantParentRef") && sessionEnd <= grant.uint("session_not_after_ms", ref, "GrantParentRef") && issued < sessionEnd);
    requireCredential(row.retained_until.length === 8 && new DataView(row.retained_until.buffer, row.retained_until.byteOffset, 8).getBigUint64(0) === grant.uint("session_not_after_ms", ref, "GrantParentRef") + 604800000n);
  } finally { for (const map of maps) map.close(); for (const bytes of owned) bytes.fill(0); buffer.fill(0); }
}
/** A claimed safety slot must contain its actual committed issuance and old
 * fence. Observer or reopen errors cannot erase either side's consumed slot. */
export function validatePersistedRelayClaim(work: CredentialWork, projection: Uint8Array, side: number, fence: bigint, selected: Uint8Array,
  issuance: Readonly<{ grant: Uint8Array; grant_digest: Uint8Array; endpoint_certificate: Uint8Array; relay_certificate: Uint8Array }>, buffer: Uint8Array): void {
  let map: OwnedCredentialMap | undefined, grant: OwnedCredentialMap | undefined, context: OwnedCredentialMap | undefined, certificate: OwnedCredentialMap | undefined; const owned: Uint8Array[] = [];
  try {
    map = work.parseRecord(projection, buffer.length, 64); const n = arrayNodes(map, 14), doc = map.doc;
    recordBytes(map, n[0]!, selected); recordBytes(map, n[1]!, issuance.grant); recordBytes(map, n[9]!, issuance.grant_digest);
    requireCredential(doc.uint(n[6]!) === fence && doc.uint(n[7]!) === BigInt(side) && doc.uint(n[13]!) === 1n && doc.uint(n[5]!) > 0n);
    for (const index of [2, 3, 4, 8, 10, 11]) requireCredential(doc.kind(n[index]!) === "bytes" &&
      (index === 11 ? doc.size(n[index]!) > 0 && doc.size(n[index]!) <= 129 : doc.size(n[index]!) === (index === 10 ? 64 : 16)));
    const challenge = new Uint8Array(doc.size(n[11]!)), proof = new Uint8Array(64); owned.push(challenge, proof); doc.copyPayload(n[11]!, challenge); doc.copyPayload(n[10]!, proof);
    grant = work.parse(issuance.grant, "Grant", 65536); context = work.parse(challenge, "HopChallengeContext", 129, 128);
    certificate = work.parse(issuance.endpoint_certificate, "IdentityCertificate", 8192);
    const route = grant.field("route_descriptor"), leg = grant.field(side === 0 ? "client_leg" : "server_leg", route, "Route"), dialer = context.uint("dialer_role"), listener = context.uint("listener_role");
    requireCredential(dialer === grant.uint("dialer_role", leg, "Leg") && listener === grant.uint("listener_role", leg, "Leg") && (dialer === 2n || listener === 2n));
    const incarnation = context.bytes(dialer === 2n ? "dialer_incarnation" : "listener_incarnation"), legID = grant.bytes("leg_id", leg, "Leg"), contextLeg = context.bytes("leg_id"); owned.push(incarnation, legID, contextLeg);
    recordBytes(map, n[8]!, incarnation); requireCredential(equalCredential(legID, contextLeg));
    requireCredential(doc.uint(n[12]!) > grant.uint("issued_at_ms") && doc.uint(n[12]!) <= grant.uint("not_after_ms"));
    const domain = wireDomains.find(value => value.name === "grant_possession"); requireCredential(domain?.operation === "ed25519");
    const label = Uint8Array.from(domain.label_bytes.match(/../gu)!.map(value => Number.parseInt(value, 16))), fields = [issuance.grant_digest, grant.bytes("route_digest"), contextLeg, grant.bytes("pairing_id"), challenge]; owned.push(label, fields[1]!, fields[3]!);
    const message = new Uint8Array(label.length + fields.reduce((length, bytes) => length + 4 + bytes.length, 0) + 1); owned.push(message); message.set(label); let at = label.length;
    for (const field of fields) { new DataView(message.buffer).setUint32(at, field.length); at += 4; message.set(field, at); at += field.length; } message[at] = side;
    const key = certificate.bytes("ed25519_public_key"); owned.push(key); requireCredential(verifyEd25519(proof, message, key));
  } finally { map?.close(); grant?.close(); context?.close(); certificate?.close(); for (const bytes of owned) bytes.fill(0); buffer.fill(0); }
}
export function clearRelayFields(fields: object): void { for (const value of Object.values(fields)) if (value instanceof Uint8Array) value.fill(0); const identities = (fields as { identities?: readonly Uint8Array[] }).identities; for (const value of identities ?? []) value.fill(0); }
export function clearRelayIssuance(record: RelayIssuanceRecord): void { clearRelayFields(record.fields); for (const bytes of [record.lease, record.candidate, record.parent, record.winner, record.root, ...record.grants, ...record.grantDigests, ...record.endpointCertificates, ...record.relayCertificates]) bytes.fill(0); }
export function relayClaimKey(fields: RelayClaimFields): Uint8Array { return admissionLeaseKey({ tenant: fields.tenant, issuer: fields.issuer, lease: fields.lease } as ServerAdmissionFields); }
export function encodeRelayClaim(buffer: Uint8Array, fields: RelayClaimFields, owner: Readonly<{ relay: Uint8Array; invocation: Uint8Array; carrier: Uint8Array; generation: bigint }>, epoch: bigint, root: Uint8Array, grant: Uint8Array, deadline: bigint): Uint8Array {
  return new FixedCBORWriter(buffer).array(14).data(root).data(grant).data(owner.relay).data(owner.invocation).data(owner.carrier).uint(owner.generation).uint(epoch).uint(fields.endpointRole)
    .data(fields.relayIncarnation).data(fields.grantDigest).data(fields.possession).data(fields.challenge).uint(deadline).uint(1).result();
}
