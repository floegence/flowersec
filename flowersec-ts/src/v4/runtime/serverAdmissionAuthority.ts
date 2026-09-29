import type { VerifiedCredentialClosure } from "./credentialVerifier.js";
import type { ResourceReference, ResourceVector } from "./resources.js";
import type { TrustedDeadline } from "./deadline.js";
export interface ServerAdmissionOwner {
  readonly acceptor: Uint8Array; readonly invocation: Uint8Array; readonly carrier: Uint8Array; readonly generation: bigint;
  readonly signal?: AbortSignal;
}
export interface AdmissionResponse {
  readonly serverEpoch: bigint; readonly reservationKey: Uint8Array; readonly admissionBinding: Uint8Array;
}
/** Internal production adapter boundary. Registration is not exported by the
 * SDK. Application callbacks cannot report an admission transaction outcome. */
export interface ServerAdmissionAuthority {
  charge(): ResourceVector;
  admit(closure: VerifiedCredentialClosure, fsb: Uint8Array, context: Uint8Array, owner: ServerAdmissionOwner, deadline: TrustedDeadline,
    work: ResourceReference, guard: () => void, dispatch: (response: AdmissionResponse) => void): void;
}
const authorities = new WeakSet<object>();
export function registerServerAdmissionAuthority(authority: ServerAdmissionAuthority): void { authorities.add(authority); }
export function isServerAdmissionAuthority(authority: unknown): authority is ServerAdmissionAuthority {
  return typeof authority === "object" && authority !== null && authorities.has(authority);
}
