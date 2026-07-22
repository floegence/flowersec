export const MAX_STREAM_LIFETIME_SLOTS_V2 = 1_048_576;

export function maxLogicalStreamIDV2(openerRole: 1 | 2): bigint {
  return BigInt(MAX_STREAM_LIFETIME_SLOTS_V2) * 2n - (openerRole === 1 ? 1n : 0n);
}

export enum StreamLifetimeStateV2 {
  Empty = 0,
  AbandonedNoFSS2 = 1,
  PrefaceSeen = 2,
  ActiveOrResolved = 3,
}

export type LateFSS2ActionV2 = "accepted" | "reset";

export class StreamLifetimeLedgerV2Error extends Error {
  constructor(
    readonly code: "capacity" | "duplicate" | "invalid_state",
    message: string,
  ) {
    super(message);
    this.name = "StreamLifetimeLedgerV2Error";
  }
}

export class StreamLifetimeLedgerV2 {
  private readonly states = new Uint8Array(MAX_STREAM_LIFETIME_SLOTS_V2 / 4);
  private resolvedFrontier = 0n;

  constructor(private readonly openerRole: 1 | 2) {}

  get frontier(): bigint {
    return this.resolvedFrontier;
  }

  get backingBytes(): number {
    return this.states.byteLength;
  }

  state(id: bigint): StreamLifetimeStateV2 {
    const index = this.slotIndex(id, false);
    return index === undefined ? StreamLifetimeStateV2.Empty : this.stateAt(index);
  }

  validFSS2(id: bigint): LateFSS2ActionV2 {
    const index = this.requireSlot(id);
    switch (this.stateAt(index)) {
      case StreamLifetimeStateV2.Empty:
        this.setStateAt(index, StreamLifetimeStateV2.PrefaceSeen);
        return "accepted";
      case StreamLifetimeStateV2.AbandonedNoFSS2:
        this.setStateAt(index, StreamLifetimeStateV2.ActiveOrResolved);
        this.advanceFrontier();
        return "reset";
      case StreamLifetimeStateV2.PrefaceSeen:
      case StreamLifetimeStateV2.ActiveOrResolved:
        throw new StreamLifetimeLedgerV2Error("duplicate", "duplicate logical stream identity");
    }
  }

  validOpen(id: bigint): void {
    const index = this.requireSlot(id);
    if (this.stateAt(index) !== StreamLifetimeStateV2.PrefaceSeen) {
      throw new StreamLifetimeLedgerV2Error("invalid_state", "OPEN without a pending FSS2 identity");
    }
    this.setStateAt(index, StreamLifetimeStateV2.ActiveOrResolved);
    this.advanceFrontier();
  }

  peerReset(id: bigint): void {
    const index = this.requireSlot(id);
    switch (this.stateAt(index)) {
      case StreamLifetimeStateV2.Empty:
        this.setStateAt(index, StreamLifetimeStateV2.AbandonedNoFSS2);
        break;
      case StreamLifetimeStateV2.PrefaceSeen:
        this.setStateAt(index, StreamLifetimeStateV2.ActiveOrResolved);
        break;
      case StreamLifetimeStateV2.AbandonedNoFSS2:
      case StreamLifetimeStateV2.ActiveOrResolved:
        break;
    }
    this.advanceFrontier();
  }

  localResetCommitted(id: bigint): void {
    const index = this.requireSlot(id);
    const state = this.stateAt(index);
    if (state === StreamLifetimeStateV2.ActiveOrResolved) return;
    if (state !== StreamLifetimeStateV2.PrefaceSeen) {
      throw new StreamLifetimeLedgerV2Error("invalid_state", "ordered reset without a pending FSS2 identity");
    }
    this.setStateAt(index, StreamLifetimeStateV2.ActiveOrResolved);
    this.advanceFrontier();
  }

  private requireSlot(id: bigint): number {
    const index = this.slotIndex(id, true);
    if (index === undefined) {
      throw new StreamLifetimeLedgerV2Error("capacity", "logical stream lifetime ledger capacity exceeded");
    }
    return index;
  }

  private slotIndex(id: bigint, validate: boolean): number | undefined {
    const validParity = id > 0n && (this.openerRole === 1 ? (id & 1n) === 1n : (id & 1n) === 0n);
    if (!validParity) {
      if (validate) throw new StreamLifetimeLedgerV2Error("capacity", "logical stream identity is outside the opener role");
      return undefined;
    }
    const ordinal = this.openerRole === 1 ? (id + 1n) / 2n : id / 2n;
    if (ordinal < 1n || ordinal > BigInt(MAX_STREAM_LIFETIME_SLOTS_V2)) return undefined;
    return Number(ordinal - 1n);
  }

  private stateAt(index: number): StreamLifetimeStateV2 {
    const shift = (index % 4) * 2;
    return ((this.states[Math.floor(index / 4)]! >>> shift) & 0x03) as StreamLifetimeStateV2;
  }

  private setStateAt(index: number, state: StreamLifetimeStateV2): void {
    const byteIndex = Math.floor(index / 4);
    const shift = (index % 4) * 2;
    const mask = 0x03 << shift;
    this.states[byteIndex] = (this.states[byteIndex]! & ~mask) | (state << shift);
  }

  private advanceFrontier(): void {
    let next = this.resolvedFrontier === 0n
      ? (this.openerRole === 1 ? 1n : 2n)
      : this.resolvedFrontier + 2n;
    while (true) {
      const index = this.slotIndex(next, false);
      if (index === undefined) return;
      const state = this.stateAt(index);
      if (state !== StreamLifetimeStateV2.AbandonedNoFSS2 && state !== StreamLifetimeStateV2.ActiveOrResolved) {
        return;
      }
      this.resolvedFrontier = next;
      next += 2n;
    }
  }
}
