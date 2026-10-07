/** Detached advertisement for an installed execution method. The hexadecimal
 * digest identifies the exact contract; the UTC window grants no execution,
 * capacity reservation, renewal or Start capability. */
export interface V4AdmissionOffer {
  readonly serviceContractDigest: string;
  readonly notBeforeMS: bigint;
  readonly notAfterMS: bigint;
}
