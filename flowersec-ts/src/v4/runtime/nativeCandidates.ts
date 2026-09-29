import { ResourceVector, type ResourceReference } from "./resources.js";

export function nativeCandidateCount(depth: 1 | 2 | undefined, direction: 0 | 1, directions: number): number {
  if (depth !== undefined && depth !== 1 && depth !== 2 || !Number.isSafeInteger(directions) || directions < 0 || directions > 4096) throw new Error("configuration_capacity");
  return depth === 1 ? 0 : Math.min(directions, direction === 0 ? 16 : 32);
}
export function nativeCandidateCharge(count: number, directions: number, runtimeBytes: bigint): ResourceVector {
  if (!Number.isSafeInteger(count) || count < 0 || count > 32 || !Number.isSafeInteger(directions) || directions < count || directions > 4096 ||
      runtimeBytes <= 0n || runtimeBytes + 1024n > 8192n) throw new Error("configuration_capacity");
  // Each extra position includes H_DATA, its finite segment indices, one real
  // read continuation and cleanup state. Queued requests contain no payload.
  return new ResourceVector([512n + BigInt(directions) * 128n + BigInt(count) * (runtimeBytes + 1024n), 0n, 0n,
    BigInt(count + directions + 1), BigInt(count), BigInt(count + 1), BigInt(count), 0n, 0n, 0n, 0n]);
}
export interface NativeCandidatePermit {
  readonly head: Uint8Array;
  release(): void;
}
interface Request { readonly owner: object; readonly grant: (permit: NativeCandidatePermit) => void }

/** Optional next-candidate positions share one FIFO across the Session. A
 * request never blocks depth-one progress or owns receive/AEAD capacity. */
export class NativeCandidatePool {
  readonly enabled: boolean;
  #reference: ResourceReference | undefined;
  readonly #free: Uint8Array[] = [];
  readonly #requests: Request[] = [];
  readonly #held = new Set<object>();
  #timer: ReturnType<typeof setTimeout> | undefined;
  #closed = false;
  constructor(count: number, private readonly directions: number, runtimeBytes: bigint, reference: ResourceReference) {
    this.enabled = count > 0;
    this.#reference = reference.take(nativeCandidateCharge(count, directions, runtimeBytes));
    try { for (let i = 0; i < count; i++) this.#free.push(new Uint8Array(128)); }
    catch (error) { this.close(); throw error; }
  }
  request(owner: object, grant: (permit: NativeCandidatePermit) => void): () => void {
    if (this.#closed || !this.enabled) return () => undefined;
    this.#reference!.check();
    if (this.#held.has(owner) || this.#requests.some(value => value.owner === owner) || this.#requests.length + this.#held.size >= this.directions) throw new Error("configuration_capacity");
    const request = { owner, grant }; this.#requests.push(request); this.#schedule();
    return () => { const at = this.#requests.indexOf(request); if (at >= 0) this.#requests.splice(at, 1); };
  }
  #schedule(): void {
    if (this.#closed || this.#timer !== undefined || this.#free.length === 0 || this.#requests.length === 0) return;
    this.#timer = setTimeout(() => {
      this.#timer = undefined;
      if (this.#closed) { this.#cleanup(); return; }
      // One grant per host turn. New and just-served directions join the tail.
      const request = this.#requests.shift();
      if (request === undefined) return;
      const head = this.#free.shift()!; this.#held.add(request.owner);
      let released = false;
      const permit: NativeCandidatePermit = { head, release: () => {
        if (released) return; released = true;
        if (!this.#held.delete(request.owner)) throw new Error("invalid_resource_owner");
        head.fill(0); if (!this.#closed) this.#free.push(head);
        this.#schedule(); this.#cleanup();
      } };
      try { request.grant(permit); } catch { permit.release(); }
      this.#schedule();
    }, 0);
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
    this.#requests.length = 0;
    for (const head of this.#free) head.fill(0); this.#free.length = 0;
    this.#cleanup();
  }
  #cleanup(): void {
    if (!this.#closed || this.#held.size !== 0 || this.#timer !== undefined) return;
    this.#reference?.release(); this.#reference = undefined;
  }
  cleanupComplete(): boolean { return this.#reference === undefined; }
}
