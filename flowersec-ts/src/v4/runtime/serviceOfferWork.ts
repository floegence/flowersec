import type { ContractQueryTarget } from "./contractQuery.js";
import type { ContractSnapshotBatch } from "./contractSnapshotReader.js";
import type { TrustedDeadline } from "./deadline.js";
import type { ContractRenewalProtection } from "./queryRenewalPosition.js";
import type { ResourceReference, ResourceRequest } from "./resources.js";
import type { ServiceBindingSource } from "./serviceBinding.js";
import type { ServiceOfferMembership } from "./serviceOfferPlan.js";

/** These callbacks are implemented only by the original SDK binding. No
 * application encoder, policy hook or business handler participates. */
export interface ServiceOfferParticipant {
  renewalSource(): ServiceBindingSource;
  renewalUnavailable(members: readonly ServiceOfferMembership[], reason: string): void;
  claimRenewal(members: readonly ServiceOfferMembership[], deadline: TrustedDeadline): ServiceOfferWork | undefined;
}
export interface ServiceOfferWork {
  readonly targets: readonly ContractQueryTarget[];
  readonly windows: readonly bigint[];
  readonly protection: ContractRenewalProtection;
  candidateRequests(): readonly ResourceRequest[];
  captureCandidates(references: readonly ResourceReference[]): readonly ResourceReference[];
  current(): boolean;
  install(batch: ContractSnapshotBatch, offset: number): void;
  /** Called only after the shared physical query has actually exited. */
  finish(reason?: string): readonly (string | undefined)[];
}
