import { FixedCBORWriter } from "./openAdmission.js";
import { requireCredential } from "./credentialSupport.js";
import type { PoolSpendFields } from "./credentialVerifier.js";
import type { PoolSpendOwner } from "./poolSpend.js";
export interface PoolRecordIdentity { readonly authority: string; readonly storeID: Uint8Array; readonly generation: bigint }
export function poolLeaseKey(f: PoolSpendFields): Uint8Array {
  const tenant = new TextEncoder().encode(f.tenant), result = new Uint8Array(1 + tenant.length + 32);
  if (tenant.length < 1 || tenant.length > 128) requireCredential(false, "configuration_capacity"); result[0] = tenant.length; result.set(tenant, 1); result.set(f.issuer, tenant.length + 1); result.set(f.lease, tenant.length + 17); return result;
}
export function encodePoolProjection(buffer: Uint8Array, f: PoolSpendFields, identity: PoolRecordIdentity, epoch: bigint, owner: PoolSpendOwner, cap: bigint, now: bigint, retention: bigint): Uint8Array {
  const w = new FixedCBORWriter(buffer).map(40);
  w.uint(0).uint(1).uint(1).data(identity.storeID).uint(2).uint(identity.generation).uint(3).uint(epoch).uint(4).data(new TextEncoder().encode(f.tenant), true).uint(5).data(f.issuer).uint(6).data(f.lease)
    .uint(7).data(f.artifactDigest).uint(8).data(f.proof).uint(9).data(f.proofDigest).uint(10).data(f.candidateID).uint(11).uint(f.candidateIndex).uint(12).data(f.routeDigest)
    .uint(13).data(f.attempt).uint(14).data(owner.connect).uint(15).data(owner.carrier).uint(16).uint(owner.generation).uint(17).data(f.candidateSet).uint(18).data(f.routeSet)
    .uint(19).data(f.descriptor).uint(20).uint(f.issuedAt).uint(21).uint(f.activationEnd).uint(22).uint(f.sessionEnd).uint(23).uint(cap).uint(24).uint(now).uint(25).uint(retention)
    .uint(26).uint(f.initiationEnd).uint(27).data(new TextEncoder().encode(f.authority), true).uint(28).data(new TextEncoder().encode(f.winnerAuthority), true).uint(29).data(new TextEncoder().encode(f.namespace), true).uint(30).uint(f.namespaceGeneration)
    .uint(31).data(f.capacityDigest).uint(32).uint(0).uint(33).data(f.identities[0]!).uint(34).data(f.identities[1]!).uint(35).data(f.sessionNonce).uint(36).data(new TextEncoder().encode(f.profile), true)
    .uint(37).data(new TextEncoder().encode(f.audience), true).uint(38).data(new TextEncoder().encode(f.signingKey), true).uint(39).data(new TextEncoder().encode("preauthorized_pool"), true);
  return w.result();
}
