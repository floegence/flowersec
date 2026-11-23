export const MAX_STREAM_LIFETIME_SLOTS_V3 = 1_048_576;
const pageBytes = 1024;
const inlineSlots = 8;

export function maxLogicalStreamIDV3(openerRole: 1 | 2): bigint {
  return BigInt(MAX_STREAM_LIFETIME_SLOTS_V3) * 2n - (openerRole === 1 ? 1n : 0n);
}

export enum StreamLifetimeStateV3 {
  Empty = 0,
  AbandonedNoFSS3 = 1,
  PrefaceSeen = 2,
  ActiveOrResolved = 3,
}

export type LateFSS3ActionV3 = "accepted" | "reset";

export class StreamLifetimeLedgerV3Error extends Error {
  constructor(
    readonly code: "capacity" | "duplicate" | "invalid_state",
    message: string,
  ) {
    super(message);
    this.name = "StreamLifetimeLedgerV3Error";
  }
}
export class StreamLifetimeLedgerV3 {
  private initialStates = 0;
  private pages?: Uint8Array[];
  private resolvedFrontier = 0n;

  constructor(private readonly openerRole: 1 | 2) {}

  get frontier(): bigint {
    return this.resolvedFrontier;
  }

  get backingBytes(): number {
    return this.pages?.reduce((bytes, page) => bytes + page.byteLength, 0) ?? 0;
  }

  state(id: bigint): StreamLifetimeStateV3 {
    const index = this.slotIndex(id, false);
    return index === undefined ? StreamLifetimeStateV3.Empty : this.stateAt(index);
  }

  validFSS3(id: bigint): LateFSS3ActionV3 {
    const index = this.requireSlot(id);
    switch (this.stateAt(index)) {
      case StreamLifetimeStateV3.Empty:
        this.setStateAt(index, StreamLifetimeStateV3.PrefaceSeen);
        return "accepted";
      case StreamLifetimeStateV3.AbandonedNoFSS3:
        this.setStateAt(index, StreamLifetimeStateV3.ActiveOrResolved);
        this.advanceFrontier();
        return "reset";
      case StreamLifetimeStateV3.PrefaceSeen:
      case StreamLifetimeStateV3.ActiveOrResolved:
        throw new StreamLifetimeLedgerV3Error("duplicate", "duplicate logical stream identity");
    }
  }

  validOpen(id: bigint): void {
    const index = this.requireSlot(id);
    if (this.stateAt(index) !== StreamLifetimeStateV3.PrefaceSeen) {
      throw new StreamLifetimeLedgerV3Error("invalid_state", "OPEN without a pending FSS3 identity");
    }
    this.setStateAt(index, StreamLifetimeStateV3.ActiveOrResolved);
    this.advanceFrontier();
  }

  peerReset(id: bigint): void {
    const index = this.requireSlot(id);
    switch (this.stateAt(index)) {
      case StreamLifetimeStateV3.Empty:
        this.setStateAt(index, StreamLifetimeStateV3.AbandonedNoFSS3);
        break;
      case StreamLifetimeStateV3.PrefaceSeen:
        this.setStateAt(index, StreamLifetimeStateV3.ActiveOrResolved);
        break;
      case StreamLifetimeStateV3.AbandonedNoFSS3:
      case StreamLifetimeStateV3.ActiveOrResolved:
        break;
    }
    this.advanceFrontier();
  }

  localResetCommitted(id: bigint): void {
    const index = this.requireSlot(id);
    const state = this.stateAt(index);
    if (state === StreamLifetimeStateV3.ActiveOrResolved) return;
    if (state !== StreamLifetimeStateV3.PrefaceSeen) {
      throw new StreamLifetimeLedgerV3Error("invalid_state", "ordered reset without a pending FSS3 identity");
    }
    this.setStateAt(index, StreamLifetimeStateV3.ActiveOrResolved);
    this.advanceFrontier();
  }

  private requireSlot(id: bigint): number {
    const index = this.slotIndex(id, true);
    if (index === undefined) {
      throw new StreamLifetimeLedgerV3Error("capacity", "logical stream lifetime ledger capacity exceeded");
    }
    return index;
  }

  private slotIndex(id: bigint, validate: boolean): number | undefined {
    const validParity = id > 0n && (this.openerRole === 1 ? (id & 1n) === 1n : (id & 1n) === 0n);
    if (!validParity) {
      if (validate) throw new StreamLifetimeLedgerV3Error("capacity", "logical stream identity is outside the opener role");
      return undefined;
    }
    const ordinal = this.openerRole === 1 ? (id + 1n) / 2n : id / 2n;
    if (ordinal < 1n || ordinal > BigInt(MAX_STREAM_LIFETIME_SLOTS_V3)) return undefined;
    return Number(ordinal - 1n);
  }

  private stateAt(index: number): StreamLifetimeStateV3 {
    if (index < inlineSlots) return (this.initialStates >>> (index * 2)) & 0x03;
    const shift = (index % 4) * 2;
    const byteIndex = Math.floor(index / 4);
    const page = this.pages?.[Math.floor(byteIndex / pageBytes)];
    return (((page?.[byteIndex % pageBytes] ?? 0) >>> shift) & 0x03) as StreamLifetimeStateV3;
  }

  private setStateAt(index: number, state: StreamLifetimeStateV3): void {
    if (index < inlineSlots) {
      const shift = index * 2;
      this.initialStates = (this.initialStates & ~(0x03 << shift)) | (state << shift);
      return;
    }
    const byteIndex = Math.floor(index / 4);
    const shift = (index % 4) * 2;
    const mask = 0x03 << shift;
    const pages = this.pages ??= [];
    const page = pages[Math.floor(byteIndex / pageBytes)] ??= new Uint8Array(pageBytes);
    const offset = byteIndex % pageBytes;
    page[offset] = (page[offset]! & ~mask) | (state << shift);
  }

  private advanceFrontier(): void {
    let next = this.resolvedFrontier === 0n
      ? (this.openerRole === 1 ? 1n : 2n)
      : this.resolvedFrontier + 2n;
    while (true) {
      const index = this.slotIndex(next, false);
      if (index === undefined) return;
      const state = this.stateAt(index);
      if (state !== StreamLifetimeStateV3.AbandonedNoFSS3 && state !== StreamLifetimeStateV3.ActiveOrResolved) {
        return;
      }
      this.resolvedFrontier = next;
      next += 2n;
    }
  }
}
