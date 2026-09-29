import type { StreamOpenPreparation } from "./streamOpenPreparation.js";
import type { ClockSample, TrustedClock } from "./clock.js";
import { timerChunk, type TrustedDeadline } from "./deadline.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { RPCStreamMessages } from "./rpcStreamMessages.js";
import type { ServiceContractSnapshot } from "./serviceContract.js";

export interface RPCStreamPoolTarget {
  readonly namespace: string;
  readonly authority: string;
  readonly kind: string;
  readonly metadata: Uint8Array;
  readonly contract: ServiceContractSnapshot;
}
export interface RPCStreamPoolMessages {
  readonly messages: RPCStreamMessages;
  readonly open?: StreamOpenPreparation;
  readonly adapter: ResourceReference;
  readonly error: ResourceReference;
}
export interface RPCStreamPoolDemand {
  ready(deadline: TrustedDeadline, signal?: AbortSignal): Promise<void>;
  prepareUpdate(contract: ServiceContractSnapshot): Readonly<{ check(): void; commit(): void }>;
  close(): void;
}
export interface RPCStreamPoolCheckout {
  readonly fixed: RPCStreamPoolMessages;
  current(): boolean;
  take(): RPCStreamPoolMessages;
  release(): void;
}
interface Identity {
  readonly namespace: string; readonly authority: string; readonly kind: string; readonly metadata: Uint8Array; readonly digest: Uint8Array;
}
interface Target extends Identity {
  readonly members: Set<Member>;
  entry: Entry | undefined;
  failure: boolean;
}
interface Member { target: Target; active: boolean; waiting: (() => void) | undefined; }
interface Entry {
  readonly target: Target; readonly fixed: RPCStreamPoolMessages; readonly abort: AbortController;
  readonly changed: () => void;
  deadline: TrustedDeadline | undefined;
  timer: ReturnType<typeof setTimeout> | undefined;
  started: boolean; working: boolean; available: boolean; claimed: boolean; closed: boolean; transferred: boolean;
}
export function rpcPreacceptedStreamsCharge(runtimeBytes: bigint): ResourceVector {
  // Eight demanded targets plus eight real pending/empty/closing entries.
  // A retired target's exact metadata stays charged until its Stream exits.
  return new ResourceVector([131072n + runtimeBytes * 16n, 0n, 0n, 24n, 8n, 9n, 8n, 0n, 0n, 0n, 0n]);
}
function matches(a: Identity, b: Identity): boolean {
  return a.namespace === b.namespace && a.authority === b.authority && a.kind === b.kind &&
    a.digest.every((value, index) => value === b.digest[index]) &&
    a.metadata.length === b.metadata.length && a.metadata.every((value, index) => value === b.metadata[index]);
}
function identity(wanted: RPCStreamPoolTarget): Identity {
  const digest = new Uint8Array(32); wanted.contract.copyDigest(digest);
  return { namespace: wanted.namespace, authority: wanted.authority, kind: wanted.kind, metadata: new Uint8Array(wanted.metadata), digest };
}
/** The Session's original bounded accepted-Stream slab. Only explicit binding
 * demand may open or replenish; checkout never starts work or adds demand. */
export class RPCPreacceptedStreams {
  #reference: ResourceReference | undefined;
  readonly #targets = new Set<Target>();
  readonly #entries = new Set<Entry>();
  #closed = false;
  #scheduled = false;
  #cleaning = false;
  #create: ((target: Omit<RPCStreamPoolTarget, "contract">) => RPCStreamPoolMessages) | undefined;
  #open: ((target: Omit<RPCStreamPoolTarget, "contract">, fixed: RPCStreamPoolMessages, signal: AbortSignal) => Promise<void>) | undefined;
  #deadline: TrustedDeadline | undefined;
  #clock: TrustedClock | undefined;
  #changed: (() => void) | undefined;
  constructor(runtimeBytes: bigint, reference: ResourceReference, clock: TrustedClock, deadline: TrustedDeadline,
    create: (target: Omit<RPCStreamPoolTarget, "contract">) => RPCStreamPoolMessages,
    open: (target: Omit<RPCStreamPoolTarget, "contract">, fixed: RPCStreamPoolMessages, signal: AbortSignal) => Promise<void>, changed: () => void) {
    this.#reference = reference.take(rpcPreacceptedStreamsCharge(runtimeBytes)); this.#clock = clock; this.#deadline = deadline;
    this.#create = create; this.#open = open; this.#changed = changed;
  }
  #check(): void { if (this.#closed) throw new RPCProtocolError("source_unavailable"); this.#reference!.checkRetained(); this.#deadline!.check(); if (this.#closed) throw new RPCProtocolError("source_unavailable"); }
  #capacity(targets: readonly Identity[]): void {
    if (targets.length > 8 || targets.some(target => targets.filter(other => other.namespace === target.namespace).length > 2)) throw new RPCProtocolError("configuration_capacity");
  }
  demand(targets: readonly RPCStreamPoolTarget[]): readonly RPCStreamPoolDemand[] {
    this.#check();
    if (targets.length < 1 || targets.length > 8) throw new RPCProtocolError("configuration_capacity");
    const wanted = targets.map(identity), projected: Identity[] = [...this.#targets];
    for (const target of wanted) if (!projected.some(existing => matches(existing, target))) projected.push(target);
    this.#capacity(projected);
    const members: Member[] = [];
    try {
      for (const target of wanted) {
        let original = [...this.#targets].find(existing => matches(existing, target));
        if (original === undefined) { original = { ...target, members: new Set(), entry: undefined, failure: false }; this.#targets.add(original); }
        if (original.members.size >= 1024) throw new RPCProtocolError("configuration_capacity");
        const member: Member = { target: original, active: true, waiting: undefined };
        original.members.add(member); members.push(member); original.failure = false;
      }
      // Reserve the whole declared set's original reader/credit/error owners
      // before scheduling the first OPEN. A failed Bind never leaves demand.
      for (const member of members) this.#supply(member.target);
      this.#schedule();
      return Object.freeze(members.map(member => Object.freeze({
        ready: (deadline: TrustedDeadline, signal?: AbortSignal) => this.#ready(member, deadline, signal),
        prepareUpdate: (contract: ServiceContractSnapshot) => this.#prepareUpdate(member, contract),
        close: () => this.#remove(member),
      })));
    } catch (error) { for (const member of members) this.#remove(member); throw error; }
  }
  #ready(member: Member, deadline: TrustedDeadline, signal?: AbortSignal): Promise<void> {
    if (member.waiting !== undefined) throw new RPCProtocolError("wait_in_progress");
    return new Promise<void>((resolve, reject) => {
      let done = false, checking = false, timer: ReturnType<typeof setTimeout> | undefined;
      const finish = (error?: unknown): void => {
        if (done) return; done = true; member.waiting = undefined;
        if (timer !== undefined) clearTimeout(timer); signal?.removeEventListener("abort", cancel);
        if (error === undefined) resolve(); else reject(error);
      };
      const cancel = (): void => finish(new RPCProtocolError("canceled"));
      const check = (): void => {
        if (done || checking) return; checking = true;
        try {
          this.#check(); deadline.check();
          if (!member.active || signal?.aborted) throw new RPCProtocolError("canceled");
          if (member.target.failure) throw new RPCProtocolError("not_ready");
          const entry = member.target.entry;
          if (entry !== undefined && this.#available(entry)) finish();
        } catch (error) { finish(error); }
        finally { checking = false; }
      };
      const tick = (): void => {
        timer = undefined; check();
        if (!done) try { timer = setTimeout(tick, timerChunk(deadline.remainingMS())); } catch (error) { finish(error); }
      };
      member.waiting = check; signal?.addEventListener("abort", cancel, { once: true }); tick();
    });
  }
  #prepareUpdate(member: Member, contract: ServiceContractSnapshot): Readonly<{ check(): void; commit(): void }> {
    this.#check(); if (!member.active) throw new RPCProtocolError("source_unavailable");
    const previous = member.target, digest = new Uint8Array(32); contract.copyDigest(digest);
    const wanted: Identity = { ...previous, digest };
    const project = (): Target | undefined => {
      if (this.#closed || !member.active || member.target !== previous) throw new RPCProtocolError("source_unavailable");
      const target = [...this.#targets].find(target => matches(target, wanted));
      const projected: Identity[] = [...this.#targets];
      if (target === undefined) {
        const index = projected.indexOf(previous); if (previous.members.size === 1 && index !== -1) projected.splice(index, 1);
        projected.push(wanted);
      }
      this.#capacity(projected);
      if (target !== previous && target !== undefined && target.members.size >= 1024) throw new RPCProtocolError("configuration_capacity");
      return target;
    };
    let next = project();
    const candidate: Target = { namespace: previous.namespace, authority: previous.authority, kind: previous.kind,
      metadata: new Uint8Array(previous.metadata), digest, members: new Set(), entry: undefined, failure: false };
    return { check: () => { next = project(); }, commit: () => {
      // The caller checks every participant before this non-failing scalar
      // transfer in the original contract installation gate.
      if (next === previous) return;
      if (next === undefined) { next = candidate; this.#targets.add(next); }
      previous.members.delete(member); next.members.add(member); member.target = next;
      if (previous.members.size === 0) this.#targets.delete(previous);
      this.#schedule();
    } };
  }
  #remove(member: Member): void {
    if (!member.active) return; member.active = false; const target = member.target;
    target.members.delete(member); member.waiting?.();
    if (target.members.size === 0) {
      this.#targets.delete(target);
      if (target.entry !== undefined) this.#closeEntry(target.entry); else this.#clearTarget(target);
    }
    this.#collect();
  }
  #wake(target: Target): void { for (const member of target.members) member.waiting?.(); }
  #room(target: Target): boolean {
    return this.#entries.size < 8 && [...this.#entries].filter(entry => entry.target.namespace === target.namespace).length < 2;
  }
  #supply(target: Target): void {
    if (this.#closed || target.members.size === 0 || target.entry !== undefined || !this.#room(target)) return;
    const fixed = this.#create!(target);
    const entry: Entry = { target, fixed, abort: new AbortController(),
      changed: () => { if (entry.available && !entry.fixed.messages.unused()) this.#closeEntry(entry); this.#collect(); },
      deadline: undefined, timer: undefined, started: false, working: false, available: false, claimed: false, closed: false, transferred: false };
    target.entry = entry; target.failure = false; this.#entries.add(entry); fixed.messages.onChange(entry.changed);
  }
  async #fill(entry: Entry): Promise<void> {
    entry.started = entry.working = true;
    try {
      const target = entry.target;
      await this.#open!({ namespace: target.namespace, authority: target.authority, kind: target.kind, metadata: target.metadata }, entry.fixed, entry.abort.signal);
      this.#check();
      if (entry.closed || target.members.size === 0 || !entry.fixed.messages.unused()) throw new RPCProtocolError("not_ready");
      entry.deadline = this.#deadline!.forkAgeAt(this.#clock!.sample(), 30000n); entry.available = true; this.#arm(entry);
    } catch { entry.target.failure = true; this.#closeEntry(entry); }
    finally { entry.fixed.open?.close(); entry.fixed.adapter.release(); entry.working = false; this.#wake(entry.target); this.#collect(); }
  }
  #arm(entry: Entry): void {
    if (entry.timer !== undefined) clearTimeout(entry.timer); entry.timer = undefined;
    if (entry.closed || entry.transferred) return;
    try { entry.deadline!.check(); entry.timer = setTimeout(() => this.#arm(entry), timerChunk(entry.deadline!.remainingMS())); }
    catch { this.#closeEntry(entry); this.#collect(); }
  }
  #available(entry: Entry, sample?: ClockSample): boolean {
    if (this.#closed || entry.closed || entry.claimed || entry.transferred || !entry.available || entry.working || !entry.fixed.messages.unused()) return false;
    try { if (sample === undefined) entry.deadline!.check(); else entry.deadline!.checkAt(sample); return true; } catch { return false; }
  }
  /** Observe an existing exact entry without creating demand or claiming it. */
  checkReady(wanted: RPCStreamPoolTarget): void {
    this.#check(); const projected = identity(wanted);
    try {
      const target = [...this.#targets].find(target => matches(target, projected)), entry = target?.entry;
      if (entry === undefined || target!.failure || !this.#available(entry)) throw new RPCProtocolError("not_ready");
    } finally { projected.metadata.fill(0); projected.digest.fill(0); }
  }
  claim(wanted: RPCStreamPoolTarget): RPCStreamPoolCheckout {
    this.#check(); const sample = this.#clock!.sample(), target = [...this.#targets].find(target =>
      target.namespace === wanted.namespace && target.authority === wanted.authority && target.kind === wanted.kind && wanted.contract.hasDigest(target.digest) &&
      target.metadata.length === wanted.metadata.length && target.metadata.every((value, index) => value === wanted.metadata[index]));
    const entry = target?.entry;
    if (entry === undefined || !this.#available(entry, sample)) throw new RPCProtocolError("not_ready");
    entry.fixed.messages.check(); entry.claimed = true;
    let active = true, taken = false;
    const current = (): boolean => active && !taken && !this.#closed && !entry.closed && entry.claimed && entry.available && !entry.working && entry.fixed.messages.unused();
    return Object.freeze({ fixed: entry.fixed, current, take: () => {
      if (!current()) throw new RPCProtocolError("not_ready");
      taken = entry.transferred = true; entry.available = false; entry.claimed = false;
      if (entry.timer !== undefined) clearTimeout(entry.timer); entry.timer = undefined;
      entry.fixed.messages.clearChange(entry.changed); entry.target.entry = undefined; this.#entries.delete(entry);
      this.#schedule(); return entry.fixed;
    }, release: () => { if (!active) return; active = false; if (!taken) entry.claimed = false; this.#collect(); } });
  }
  #closeEntry(entry: Entry): void {
    if (entry.closed || entry.transferred) return; entry.closed = true; entry.available = false;
    if (entry.timer !== undefined) clearTimeout(entry.timer); entry.timer = undefined;
    entry.abort.abort(); entry.fixed.messages.close(); entry.fixed.error.release();
    if (!entry.started) { entry.fixed.open?.close(); entry.fixed.adapter.release(); }
    this.#wake(entry.target);
  }
  #schedule(): void {
    if (this.#closed || this.#scheduled) return; this.#scheduled = true;
    queueMicrotask(() => {
      this.#scheduled = false;
      for (const entry of this.#entries) if (entry.target.members.size === 0) this.#closeEntry(entry);
      for (const target of this.#targets) if (!target.failure) { try { this.#supply(target); } catch { target.failure = true; this.#wake(target); } }
      for (const entry of this.#entries) if (!this.#closed && !entry.closed && !entry.started) void this.#fill(entry);
      this.#collect();
    });
  }
  #clearTarget(target: Target): void { target.metadata.fill(0); target.digest.fill(0); }
  #collect(): void {
    if (this.#cleaning) return; this.#cleaning = true;
    try {
      for (const entry of this.#entries) if (entry.closed && !entry.working && !entry.claimed && entry.fixed.messages.cleanupComplete()) {
        this.#entries.delete(entry); if (entry.target.entry === entry) entry.target.entry = undefined;
        if (entry.target.members.size === 0) this.#clearTarget(entry.target);
      }
      if (!this.#closed && [...this.#targets].some(target => target.members.size !== 0 && target.entry === undefined && !target.failure && this.#room(target))) this.#schedule();
      if (this.#closed && this.#entries.size === 0 && !this.#scheduled) {
        for (const target of this.#targets) this.#clearTarget(target);
        this.#targets.clear(); this.#open = this.#create = undefined; this.#clock = undefined; this.#deadline = undefined;
        this.#reference?.release(); this.#reference = undefined; const changed = this.#changed; this.#changed = undefined; changed?.();
      }
    } finally { this.#cleaning = false; }
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    for (const entry of this.#entries) this.#closeEntry(entry);
    for (const target of this.#targets) this.#wake(target); this.#collect();
  }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
}
