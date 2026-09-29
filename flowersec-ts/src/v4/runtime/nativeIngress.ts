import { ResourceVector, type ResourceReference, type ResourceRoot } from "./resources.js";
import { timerChunk, type TrustedDeadline } from "./deadline.js";
import { RecordWorkspace } from "./recordWorkspace.js";
import { EnvelopeDecoder, type EnvelopeFrame } from "./envelope.js";
import { ReceiveWorkspace } from "./receiveWorkspace.js";
import { NativeCandidatePool } from "./nativeCandidates.js";

export function nativeIngressCharge(directions: number, runtimeBytes: bigint): ResourceVector {
  if (!Number.isSafeInteger(directions) || directions < 1 || directions > 4096 || runtimeBytes <= 0n) throw new Error("configuration_capacity");
  return new ResourceVector([runtimeBytes + BigInt(directions) * 128n + 512n, 0n, 0n, BigInt(directions + 1), 2n, 2n, 2n, 0n, 0n, 0n, 0n]);
}
interface Ready { readonly owner: object; readonly resolve: () => void; readonly reject: (error: Error) => void }

/** One actual JS ordinary authentication turn at a time. Only complete frames
 * enter this queue; per-direction assembly/backing belongs to the caller.
 * Every ready direction joins the tail, including a just-served direction.
 * One host task between grants allows native I/O, timers and maintenance to
 * run. This fairness mechanism is not a measured latency qualification. */
export class NativeIngressScheduler {
  readonly workspace: RecordWorkspace;
  readonly receiveWorkspace: ReceiveWorkspace;
  readonly candidates: NativeCandidatePool;
  readonly #decoder: EnvelopeDecoder;
  #reference: ResourceReference | undefined;
  readonly #ready: Ready[] = [];
  #active: object | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #closed = false;
  #capacityWait: (() => void) | undefined;
  #capacityChanged = false;
  #stopAvailability: (() => void) | undefined;
  constructor(private readonly capacity: number, runtimeBytes: bigint, reference: ResourceReference, root: ResourceRoot,
    maxFrame: number, crypto: ResourceReference, envelope: ResourceReference, receive: ResourceReference, receiveDecoder: ResourceReference,
    candidateCount: number, candidateReference: ResourceReference) {
    this.#reference = reference.take(nativeIngressCharge(capacity, runtimeBytes));
    let workspace: RecordWorkspace | undefined, decoder: EnvelopeDecoder | undefined, plaintext: ReceiveWorkspace | undefined;
    let candidates: NativeCandidatePool | undefined;
    try {
      this.candidates = candidates = new NativeCandidatePool(candidateCount, capacity, runtimeBytes, candidateReference);
      this.workspace = workspace = new RecordWorkspace(maxFrame, runtimeBytes, crypto);
      this.#decoder = decoder = new EnvelopeDecoder({ maxFrame, mode: "stream", runtimeBytes }, envelope);
      this.receiveWorkspace = plaintext = new ReceiveWorkspace(maxFrame, runtimeBytes, receive, receiveDecoder);
      this.#stopAvailability = root.observeAvailability(this.#reference, () => this.capacityAvailable());
    } catch (error) { candidates?.close(); workspace?.close(); decoder?.close(); plaintext?.close(); this.#reference.release(); this.#reference = undefined; throw error; }
  }
  acquire(owner: object): Promise<void> {
    if (this.#closed) return Promise.reject(new Error("closed"));
    this.#reference!.check();
    if (this.#active === owner || this.#ready.some(entry => entry.owner === owner) || this.#ready.length >= this.capacity) return Promise.reject(new Error("configuration_capacity"));
    return new Promise((resolve, reject) => { this.#ready.push({ owner, resolve, reject }); this.#schedule(); });
  }
  release(owner: object): void {
    if (this.#active !== owner) throw new Error("invalid_resource_owner");
    this.#active = undefined; this.#schedule(); this.#cleanup();
  }
  frame(owner: object, segments: readonly Uint8Array[]): EnvelopeFrame {
    if (this.#closed || this.#active !== owner) throw new Error("invalid_resource_owner");
    let frame: EnvelopeFrame | undefined;
    try {
      for (const bytes of segments) {
        if (bytes.length === 0) continue;
        if (frame !== undefined) throw new Error("protocol_violation");
        const progress = this.#decoder.push(bytes);
        if (progress.consumed !== bytes.length) throw new Error("protocol_violation");
        frame = progress.frame;
      }
      if (frame === undefined) throw new Error("protocol_violation");
      return frame;
    } catch (error) { frame?.release(); if (!this.#closed) this.#decoder.discardUnpublished(); throw error; }
  }
  /** Register before the attempt, including an asynchronous provider call, so
   * an intervening release cannot be lost between failure and waiting. */
  capacityAttempt(): void { this.#capacityChanged = false; }
  capacityAvailable(): void { this.#capacityChanged = true; this.#capacityWait?.(); }
  waitCapacity(deadline: TrustedDeadline, signal: AbortSignal): Promise<void> {
    if (this.#closed || signal.aborted) return Promise.reject(new Error("closed"));
    if (this.#capacityWait !== undefined) return Promise.reject(new Error("busy"));
    return new Promise((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined, finished = false;
      const finish = (): void => {
        if (finished) return; finished = true; if (timer !== undefined) clearTimeout(timer);
        signal.removeEventListener("abort", finish); this.#capacityWait = undefined;
        try { if (this.#closed || signal.aborted) throw new Error("closed"); deadline.check(); resolve(); }
        catch (error) { reject(error); }
        this.#cleanup();
      };
      this.#capacityWait = finish;
      try {
        deadline.check();
        timer = setTimeout(finish, timerChunk(deadline.remainingMS())); signal.addEventListener("abort", finish, { once: true });
        if (this.#closed || signal.aborted || this.#capacityChanged) finish();
      } catch (error) {
        finished = true; if (timer !== undefined) clearTimeout(timer); this.#capacityWait = undefined; reject(error); this.#cleanup();
      }
    });
  }
  #schedule(): void {
    if (this.#closed || this.#active !== undefined || this.#timer !== undefined || this.#ready.length === 0) return;
    this.#timer = setTimeout(() => {
      this.#timer = undefined;
      if (this.#closed) { this.#cleanup(); return; }
      const entry = this.#ready.shift()!; this.#active = entry.owner; entry.resolve();
    }, 0);
  }
  close(): void {
    this.#closed = true;
    this.candidates.close(); this.workspace.close(); this.receiveWorkspace.close(); this.#decoder.close();
    if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
    for (const entry of this.#ready.splice(0)) entry.reject(new Error("closed"));
    this.#stopAvailability?.(); this.#stopAvailability = undefined;
    this.#capacityWait?.();
    this.#cleanup();
  }
  #cleanup(): void { if (this.#closed && this.#active === undefined && this.#capacityWait === undefined && this.#timer === undefined && this.#ready.length === 0 && this.#decoder.cleanupComplete()) { this.#reference?.release(); this.#reference = undefined; } }
  cleanupComplete(): boolean { return this.#reference === undefined && this.candidates.cleanupComplete() && this.workspace.cleanupComplete() && this.receiveWorkspace.cleanupComplete() && this.#decoder.cleanupComplete(); }
}
