import type { TrustedClock } from "./clock.js";
import type { ContractQueryAcquisition } from "./contractQueryAcquisition.js";
import type { ContractSnapshotBatch } from "./contractSnapshotReader.js";
import { timerChunk } from "./deadline.js";
import type { ResourceReference, ResourceRoot } from "./resources.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { ServiceBindingSource } from "./serviceBinding.js";
import type { ScheduledOffer, ServiceOfferMembership, ServiceOfferPlan } from "./serviceOfferPlan.js";
import type { ServiceOfferParticipant, ServiceOfferWork } from "./serviceOfferWork.js";

function failure(error: unknown): string {
  return error instanceof Error && /^[a-z][a-z0-9_]{0,63}$/u.test(error.message) ? error.message : "source_unavailable";
}
interface Claimed {
  readonly work: ServiceOfferWork;
  readonly members: readonly ServiceOfferMembership[];
}

/** One coalesced Environment wake and at most one active renewal batch. The
 * original J/Q acquisition owns all network/reader work and physical cleanup.
 * This scheduler never acquires a Session or creates a per-service channel. */
export class ServiceOfferScheduler {
  #root: ResourceRoot | undefined;
  #clock: TrustedClock | undefined;
  #plan: ServiceOfferPlan | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #query: ContractQueryAcquisition | undefined;
  #running = false;
  #closed = false;
  #settled: (() => void) | undefined;
  #lastUpperMS = 0n;
  constructor(root: ResourceRoot, clock: TrustedClock, plan: ServiceOfferPlan, settled: () => void) {
    this.#root = root; this.#clock = clock; this.#plan = plan; this.#settled = settled;
    plan.observe(() => this.#wake()); Object.freeze(this);
  }
  #wake(): void {
    if (this.#closed || this.#running) return;
    if (this.#timer !== undefined) clearTimeout(this.#timer);
    // Always defer observer work beyond the original method installation gate.
    this.#timer = setTimeout(() => { this.#timer = undefined; this.#tick(); }, 0);
  }
  #later(milliseconds: bigint): void {
    if (!this.#closed) this.#timer = setTimeout(() => { this.#timer = undefined; this.#tick(); }, timerChunk(milliseconds));
  }
  #tick(): void {
    if (this.#closed || this.#running) return;
    let batch: readonly ScheduledOffer[];
    try {
      this.#lastUpperMS = this.#clock!.sample().requireInterval().upperMS;
      if (this.#closed) return;
      const next = this.#plan!.schedule(this.#lastUpperMS); batch = next.batch;
      if (batch.length === 0) { if (next.waitMS !== undefined) this.#later(next.waitMS); return; }
    } catch {
      // Sampling time is local SDK work. Unavailable time cannot authorize a
      // remote query; a single bounded wake can notice authenticated recovery.
      this.#later(1000n); return;
    }
    this.#running = true;
    void this.#run(batch).finally(() => {
      this.#running = false;
      if (this.#closed) this.#collect(); else this.#wake();
    });
  }
  async #run(batch: readonly ScheduledOffer[]): Promise<void> {
    const plan = this.#plan!, claimed: Claimed[] = [], unclaimed = new Set(batch.map(item => item.membership));
    let source: ServiceBindingSource | undefined, query: ContractQueryAcquisition | undefined;
    let result: ContractSnapshotBatch | undefined, reason: string | undefined;
    const bodies: ResourceReference[] = [];
    try {
      const groups = new Map<ServiceOfferParticipant, ScheduledOffer[]>();
      for (const item of batch) {
        let group = groups.get(item.participant);
        if (group === undefined) { group = []; groups.set(item.participant, group); } group.push(item);
      }
      const duration = plan.envelope().deadlineMS;
      for (const [participant, items] of groups) {
        const members = items.map(item => item.membership);
        try {
          if (this.#closed) throw new RPCProtocolError("service_binding_closed");
          const current = participant.renewalSource(); current.check();
          if (current.group !== batch[0]!.group || items.some(item => item.group !== current.group || item.authority !== batch[0]!.authority)) throw new RPCProtocolError("service_target_mismatch");
          const deadline = current.deadline(duration); plan.start(members, deadline);
          const work = participant.claimRenewal(members, deadline);
          if (work === undefined) throw new RPCProtocolError("refresh_in_progress");
          source ??= current; claimed.push({ work, members });
        } catch (error) {
          const reason = failure(error); participant.renewalUnavailable(members, reason); plan.finish(members, this.#lastUpperMS, reason);
        }
        for (const member of members) unclaimed.delete(member);
      }
      if (claimed.length === 0) return;
      // One original absolute deadline covers the whole legal shared batch.
      // All selected methods retain that cap for any bounded later feedback.
      const deadline = source!.deadline(duration), members = claimed.flatMap(entry => entry.members);
      plan.start(members, deadline);
      const targets = claimed.flatMap(entry => entry.work.targets), windows = claimed.flatMap(entry => entry.work.windows);
      if (this.#closed || claimed.some(entry => !entry.work.current())) throw new RPCProtocolError("source_unavailable");
      query = source!.query(targets, deadline, windows, undefined, () => {
        if (this.#closed) throw new RPCProtocolError("service_binding_closed");
        const requests = claimed.map(entry => entry.work.candidateRequests());
        const references = this.#root!.reserveBatch(requests.flat());
        try {
          let offset = 0;
          for (let index = 0; index < claimed.length; index++) {
            const count = requests[index]!.length;
            bodies.push(...claimed[index]!.work.captureCandidates(references.slice(offset, offset + count))); offset += count;
          }
          return { bodies };
        } finally { for (const reference of references) reference.release(); }
      }, claimed[0]!.work.protection);
      this.#query = query; source = undefined;
      const progress = await query.wait();
      if (progress.state !== "ready") throw new RPCProtocolError(progress.sdkError ?? progress.failure ?? "source_unavailable");
      result = query.take(); let offset = 0;
      for (const entry of claimed) { entry.work.install(result, offset); offset += entry.work.targets.length; }
    } catch (error) { reason = failure(error); }
    finally {
      source = undefined; result?.release(); query?.close();
      for (const reference of bodies) reference.release(); bodies.length = 0;
      // Cancellation of any participant revokes only its installation. The
      // shared batch and its task reservation stay occupied until real reuse.
      if (query !== undefined) await query.waitForReuse();
      this.#query = undefined;
      try { this.#lastUpperMS = this.#clock!.sample().requireInterval().upperMS; } catch { /* Original cap is unchanged. */ }
      for (const entry of claimed) {
        const reasons = entry.work.finish(reason);
        for (let index = 0; index < entry.members.length; index++) plan.finish([entry.members[index]!], this.#lastUpperMS, reasons[index]);
      }
      plan.finish([...unclaimed], this.#lastUpperMS, reason ?? "source_unavailable");
    }
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
    this.#query?.close(); this.#collect();
  }
  #collect(): void {
    if (!this.#closed || this.#running) return;
    this.#root = undefined; this.#clock = undefined; this.#plan = undefined;
    const settled = this.#settled; this.#settled = undefined; settled?.();
  }
  cleanupComplete(): boolean { return this.#closed && !this.#running; }
}
Object.freeze(ServiceOfferScheduler.prototype); Object.freeze(ServiceOfferScheduler);
