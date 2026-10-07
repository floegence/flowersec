import type { CredentialWork} from "../v4/runtime/credentialSupport.js";
import { type OwnedCredentialMap, equalCredential, requireCredential } from "../v4/runtime/credentialSupport.js";
import { FixedCBORWriter } from "../v4/runtime/openAdmission.js";
import type { ServerAdmissionFields } from "../v4/runtime/credentialVerifier.js";
import type { V4SQLitePoolIdentity } from "./sqliteV4.js";

import type { ServerAdmissionOwner } from "../v4/runtime/serverAdmissionAuthority.js";
export type { ServerAdmissionOwner } from "../v4/runtime/serverAdmissionAuthority.js";
export function admissionLeaseKey(f: Pick<ServerAdmissionFields, "tenant" | "issuer" | "lease">): Uint8Array {
  const tenant = new TextEncoder().encode(f.tenant), result = new Uint8Array(1 + tenant.length + 32);
  if (tenant.length < 1 || tenant.length > 128) throw new Error("configuration_capacity");
  result[0] = tenant.length; result.set(tenant, 1); result.set(f.issuer, tenant.length + 1); result.set(f.lease, tenant.length + 17); return result;
}
function text(writer: FixedCBORWriter, value: string): FixedCBORWriter { return writer.data(new TextEncoder().encode(value), true); }
/** Shared by candidate services; excludes local carrier and FSB facts, which
 * do not exist when a relay fixes the same immutable parent selection. */
export function encodeParentWinner(buffer: Uint8Array, f: Omit<ServerAdmissionFields, "admissionBinding">): Uint8Array {
  const w = new FixedCBORWriter(buffer).array(18);
  text(w, "flowersec/parent-winner/1"); text(w, f.source); text(w, f.tenant); text(w, f.winnerAuthority); text(w, f.audience);
  for (const bytes of [f.issuer, f.lease, f.artifactDigest, f.proofDigest, f.candidateSet, f.candidateID, f.routeDigest, f.attempt, ...f.identities]) w.data(bytes);
  return w.uint(f.issuedAt).uint(f.activationEnd).uint(f.sessionEnd).result();
}
export function encodeAdmission(buffer: Uint8Array, f: ServerAdmissionFields, identity: V4SQLitePoolIdentity, epoch: bigint,
  owner: ServerAdmissionOwner, deadline: bigint, reservedAt: bigint, retainedUntil: bigint, fsb: Uint8Array, context: Uint8Array,
  reservation: Uint8Array, admittedAt: bigint): Uint8Array {
  const w = new FixedCBORWriter(buffer).map(9);
  w.uint(0).uint(reservation.length === 0 ? 0 : 1);
  w.uint(1).array(4); text(w, identity.authority); w.data(identity.storeID).uint(identity.generation).uint(epoch);
  w.uint(2).array(4).data(owner.acceptor).data(owner.invocation).data(owner.carrier).uint(owner.generation);
  w.uint(3).array(7).uint(deadline).uint(reservedAt).uint(retainedUntil).uint(admittedAt).uint(f.issuedAt).uint(f.activationEnd).uint(f.sessionEnd);
  w.uint(4).array(7); for (const value of [f.source, f.tenant, f.audience, f.profile, f.spendAuthority, f.winnerAuthority, f.signingKey]) text(w, value);
  w.uint(5).array(12); for (const value of [f.issuer, f.lease, f.artifactDigest, f.proofDigest, f.candidateID, f.candidateSet,
    f.routeDigest, f.attempt, f.sessionNonce, ...f.identities, f.admissionBinding]) w.data(value);
  return w.uint(6).data(fsb).uint(7).data(context).uint(8).data(reservation).result();
}

export interface PersistedAdmissionRecord {
  readonly lease: Uint8Array; readonly source: number; readonly state: number; readonly fence: bigint; readonly retainedUntil: bigint; readonly projection: Uint8Array;
}
function recordArray(map: OwnedCredentialMap, node: number, length: number): number[] {
  requireCredential(map.doc.kind(node) === "array" && map.doc.size(node) === length, "credential_invalid");
  const result: number[] = []; for (let child = map.doc.firstChild(node); child >= 0; child = map.doc.nextSibling(child)) result.push(child);
  requireCredential(result.length === length, "credential_invalid"); return result;
}
function recordData(map: OwnedCredentialMap, node: number, maximum: number, exact?: number): Uint8Array {
  requireCredential(map.doc.kind(node) === "bytes" && map.doc.size(node) <= maximum && (exact === undefined || map.doc.size(node) === exact), "credential_invalid");
  const bytes = new Uint8Array(map.doc.size(node)); map.doc.copyPayload(node, bytes); return bytes;
}
/** Recover immutable admission facts from the original signed FSB. This never
 * offers its historical authorization as a new admission capability. */
export function validatePersistedAdmission(work: CredentialWork, record: PersistedAdmissionRecord, identity: V4SQLitePoolIdentity,
  currentEpoch: bigint, buffer: Uint8Array, service: (fields: ServerAdmissionFields) => boolean): Uint8Array {
  const maps: OwnedCredentialMap[] = [], owned: Uint8Array[] = [];
  const data = (map: OwnedCredentialMap, node: number, maximum: number, exact?: number): Uint8Array => { const result = recordData(map, node, maximum, exact); owned.push(result); return result; };
  try {
    const map = work.parseRecord(record.projection, buffer.length, 256); maps.push(map); const doc = map.doc;
    requireCredential(doc.kind() === "map" && doc.size() === 9 && (record.source === 0 || record.source === 1) && (record.state === 0 || record.state === 1));
    const field = (id: number): number => { const node = doc.field(0, id); requireCredential(node >= 0); return node; };
    requireCredential(doc.uint(field(0)) === BigInt(record.state));
    const store = recordArray(map, field(1), 4), owner = recordArray(map, field(2), 4), times = recordArray(map, field(3), 7), texts = recordArray(map, field(4), 7), values = recordArray(map, field(5), 12);
    requireCredential(doc.text(store[0]!) === identity.authority && equalCredential(data(map, store[1]!, 32, 32), identity.storeID) && doc.uint(store[2]!) === identity.generation &&
      doc.uint(store[3]!) === record.fence && record.fence > 0n && record.fence <= currentEpoch && doc.uint(owner[3]!) > 0n);
    for (let index = 0; index < 3; index++) { const bytes = data(map, owner[index]!, 16, 16); requireCredential(bytes.some(byte => byte !== 0)); }
    const source = doc.text(texts[0]!); requireCredential(source === (record.source === 0 ? "live_authority" : "preauthorized_pool"));
    const lengths = [16, 16, 32, 32, 16, record.source === 0 ? 0 : 32, 32, 16, 32, 32, 32, 32];
    const payloads = values.map((node, index) => data(map, node, lengths[index]!, lengths[index]!));
    const fields: ServerAdmissionFields = {
      source, tenant: doc.text(texts[1]!), audience: doc.text(texts[2]!), profile: doc.text(texts[3]!), spendAuthority: doc.text(texts[4]!), winnerAuthority: doc.text(texts[5]!), signingKey: doc.text(texts[6]!),
      issuer: payloads[0]!, lease: payloads[1]!, artifactDigest: payloads[2]!, proofDigest: payloads[3]!, candidateID: payloads[4]!, candidateSet: payloads[5]!, routeDigest: payloads[6]!, attempt: payloads[7]!, sessionNonce: payloads[8]!, identities: [payloads[9]!, payloads[10]!], admissionBinding: payloads[11]!,
      issuedAt: doc.uint(times[4]!), activationEnd: doc.uint(times[5]!), sessionEnd: doc.uint(times[6]!), initiationEnd: doc.uint(times[5]!),
    };
    requireCredential(service(fields) && (record.source === 0 ? fields.winnerAuthority === "" : fields.winnerAuthority.length > 0));
    const lease = admissionLeaseKey(fields); owned.push(lease); requireCredential(equalCredential(lease, record.lease));
    const deadline = doc.uint(times[0]!), reservedAt = doc.uint(times[1]!), retainedUntil = doc.uint(times[2]!), admittedAt = doc.uint(times[3]!);
    requireCredential(fields.issuedAt <= reservedAt && reservedAt < deadline && deadline <= fields.activationEnd && reservedAt < fields.sessionEnd && retainedUntil === record.retainedUntil &&
      reservedAt <= 0xffffffffffffffffn - 604800000n && retainedUntil >= reservedAt + 604800000n);
    const reservation = data(map, field(8), 32); requireCredential(record.state === 0 ? reservation.length === 0 && admittedAt === 0n : reservation.length === 32 && reservation.some(byte => byte !== 0) && admittedAt >= reservedAt && admittedAt < deadline);
    const fsbBytes = data(map, field(6), 65536), contextBytes = data(map, field(7), 2048); requireCredential(fsbBytes.length > 0 && contextBytes.length > 0);
    const fsb = work.parse(fsbBytes, "FSB4", 65536, 16384, { selectors: { activation_source_profile: source } }); maps.push(fsb);
    const context = work.parse(contextBytes, "TransportContext", 2048); maps.push(context);
    const clientBytes = fsb.bytes("client_certificate"); owned.push(clientBytes); const client = work.parse(clientBytes, "IdentityCertificate", 8192); maps.push(client);
    const key = client.bytes("ed25519_public_key"), clientDigest = work.digest(client, "certificate_digest"); owned.push(key, clientDigest);
    work.verify(fsb, key, { selectors: { activation_source_profile: source } });
    requireCredential(equalCredential(clientDigest, fields.identities[0]!) && client.uint("role") === 0n && client.text("tenant_id") === fields.tenant && client.text("crypto_profile_id") === fields.profile);
    client.close(); maps.pop();
    const proof = fsb.bytes("activation_authorization"); owned.push(proof); const activation = work.parse(proof, "ActivationAuthorization", 4096, 16384, { selectors: { activation_source_profile: source } }); maps.push(activation);
    const binding = work.digest(fsb, "admission_binding"), contextDigest = work.digest(context, "transport_context_digest"), proofDigest = work.digest(activation, "activation_digest"); owned.push(binding, contextDigest, proofDigest);
    requireCredential(equalCredential(binding, fields.admissionBinding) && equalCredential(proofDigest, fields.proofDigest) && fsb.text("tenant_id") === fields.tenant && context.text("crypto_profile_id") === fields.profile &&
      activation.text("authority_id") === fields.spendAuthority && activation.text("signing_key_id") === fields.signingKey && activation.uint("issued_at_ms") === fields.issuedAt &&
      activation.uint("activation_not_after_ms") === fields.activationEnd && fields.sessionEnd <= activation.uint("session_not_after_ms"));
    for (const [name, expected] of [["issuer_key_id", fields.issuer], ["lease_id", fields.lease], ["artifact_digest", fields.artifactDigest], ["candidate_id", fields.candidateID], ["attempt_id", fields.attempt], ["session_nonce", fields.sessionNonce], ["route_digest", fields.routeDigest], ["transport_context_digest", contextDigest]] as const) {
      const value = fsb.bytes(name); owned.push(value); requireCredential(equalCredential(value, expected));
    }
    for (const [name, expected] of [["artifact_digest", fields.artifactDigest], ["attempt_id", fields.attempt], ["session_nonce", fields.sessionNonce], ["route_digest", fields.routeDigest]] as const) {
      const value = context.bytes(name); owned.push(value); requireCredential(equalCredential(value, expected));
    }
    requireCredential(activation.text("tenant_id") === fields.tenant && activation.text("audience") === fields.audience);
    for (const [name, expected] of [["artifact_issuer_key_id", fields.issuer], ["lease_id", fields.lease], ["client_identity_digest", fields.identities[0]!], ["server_identity_digest", fields.identities[1]!], ["artifact_digest", fields.artifactDigest], ["attempt_id", fields.attempt]] as const) { const value = activation.bytes(name); owned.push(value); requireCredential(equalCredential(value, expected)); }
    const hello = fsb.bytes("hello_transcript_digest"), contextHello = context.bytes("hello_transcript_digest"); owned.push(hello, contextHello);
    requireCredential(equalCredential(hello, contextHello) && fsb.uint("selected_features") === context.uint("selected_features") && fsb.uint("binding_mode") === context.uint("binding_mode"));
    if (record.source === 0) {
      const candidate = activation.bytes("candidate_selection"), route = activation.bytes("route_selection"); owned.push(candidate, route); requireCredential(equalCredential(candidate, fields.candidateID) && equalCredential(route, fields.routeDigest));
    } else { const candidateSet = activation.bytes("candidate_set_digest", activation.field("candidate_selection"), "PoolSelectionRef"); owned.push(candidateSet); requireCredential(equalCredential(candidateSet, fields.candidateSet)); }
    return new Uint8Array(encodeParentWinner(buffer, fields));
  } finally { for (const map of maps) map.close(); for (const bytes of owned) bytes.fill(0); buffer.fill(0); }
}
/** Standalone ParentWinner rows can outlive a local endpoint reservation. */
export function validatePersistedParentWinner(work: CredentialWork, lease: Uint8Array, projection: Uint8Array, cap: number, authority: string): void {
  const map = work.parseRecord(projection, cap, 64), owned: Uint8Array[] = [];
  try {
    const doc = map.doc, n = recordArray(map, 0, 18);
    requireCredential(doc.text(n[0]!) === "flowersec/parent-winner/1" && doc.text(n[1]!) === "preauthorized_pool" && doc.text(n[3]!) === authority);
    const lengths = [16, 16, 32, 32, 32, 16, 32, 16, 32, 32];
    for (let i = 0; i < lengths.length; i++) owned.push(recordData(map, n[5 + i]!, lengths[i]!, lengths[i]!));
    const key = admissionLeaseKey({ tenant: doc.text(n[2]!), issuer: owned[0]!, lease: owned[1]! } as ServerAdmissionFields); owned.push(key); requireCredential(equalCredential(key, lease));
    requireCredential(doc.text(n[4]!).length > 0 && doc.uint(n[15]!) < doc.uint(n[16]!) && doc.uint(n[15]!) < doc.uint(n[17]!));
  } finally { map.close(); for (const bytes of owned) bytes.fill(0); }
}
