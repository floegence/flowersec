import { FixedCBORWriter } from "../v4/runtime/openAdmission.js";
import type { ServerAdmissionFields } from "../v4/runtime/credentialVerifier.js";
import type { V4SQLitePoolIdentity } from "./sqliteV4.js";

import type { ServerAdmissionOwner } from "../v4/runtime/serverAdmissionAuthority.js";
export type { ServerAdmissionOwner } from "../v4/runtime/serverAdmissionAuthority.js";
export function admissionLeaseKey(f: ServerAdmissionFields): Uint8Array {
  const tenant = new TextEncoder().encode(f.tenant), result = new Uint8Array(1 + tenant.length + 32);
  if (tenant.length < 1 || tenant.length > 128) throw new Error("configuration_capacity");
  result[0] = tenant.length; result.set(tenant, 1); result.set(f.issuer, tenant.length + 1); result.set(f.lease, tenant.length + 17); return result;
}
function text(writer: FixedCBORWriter, value: string): FixedCBORWriter { return writer.data(new TextEncoder().encode(value), true); }
/** Shared by candidate services; excludes local carrier and FSB facts, which
 * do not exist when a relay fixes the same immutable parent selection. */
export function encodeParentWinner(buffer: Uint8Array, f: ServerAdmissionFields): Uint8Array {
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
