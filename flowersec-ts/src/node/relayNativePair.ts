import type { V4AuthenticatedTransport, V4NativeApplicationStream } from "../v4/runtime/session.js";
import { isVerifiedRelayCredentials, isVerifiedRelayClaim, type VerifiedRelayCredentials, type VerifiedRelayClaim, type RelayLimits } from "../v4/runtime/relayCredentials.js";
import { equalCredential, requireCredential } from "../v4/runtime/credentialSupport.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { inspectRecordPrefix } from "../v4/runtime/envelope.js";
import { wire, datagramScope, } from "../v4/runtime/wireRegistry.js";
import type { TrustedClock, ClockMark } from "../v4/runtime/clock.js";
import { TimeError } from "../v4/runtime/timeArithmetic.js";
import { NativeDirectionFailure } from "../v4/runtime/nativeFailure.js";

export interface RelayNativePairLimits {
  readonly maxEnvelopeBytes: number; readonly maxDatagramBytes: number;
  readonly maxPendingNativeMappings: number; readonly maxResidentNativeMappings: number; readonly maxTotalNativeMappings: number;
  readonly maxQueueItems: number; readonly maxQueueBytes: number; readonly runtimeBytes: bigint;
}
export function relayNativePairCharge(config: RelayNativePairLimits): ResourceVector {
  const sharedMappings = config.maxPendingNativeMappings === 0 && config.maxResidentNativeMappings === 0 && config.maxTotalNativeMappings === 0;
  requireCredential(Number.isSafeInteger(config.maxEnvelopeBytes) && config.maxEnvelopeBytes >= 76 && config.maxEnvelopeBytes <= wire.resource_caps.max_payload_length + 8 && Number.isSafeInteger(config.maxDatagramBytes) && config.maxDatagramBytes >= 0 && config.maxDatagramBytes <= 1024 &&
    Number.isSafeInteger(config.maxPendingNativeMappings) && (sharedMappings || config.maxPendingNativeMappings >= 3) && config.maxPendingNativeMappings <= 4096 && Number.isSafeInteger(config.maxResidentNativeMappings) && (sharedMappings || config.maxResidentNativeMappings >= 1) && config.maxResidentNativeMappings <= 4096 &&
    Number.isSafeInteger(config.maxTotalNativeMappings) && config.maxTotalNativeMappings >= config.maxResidentNativeMappings * 2 && config.maxTotalNativeMappings <= 65536 && Number.isSafeInteger(config.maxQueueItems) && config.maxQueueItems >= 2 * config.maxResidentNativeMappings + 2 &&
    Number.isSafeInteger(config.maxQueueBytes) && config.maxQueueBytes >= (2 * config.maxResidentNativeMappings + 2) * config.maxEnvelopeBytes && config.runtimeBytes > 0n, "configuration_capacity");
  const slots = config.maxResidentNativeMappings + config.maxPendingNativeMappings;
  return new ResourceVector([BigInt((2 * slots + 2) * config.maxEnvelopeBytes + 2 * config.maxDatagramBytes) + BigInt(config.maxTotalNativeMappings) * 128n + BigInt(slots) * 512n + config.runtimeBytes,
    0n, 0n, BigInt(slots * 8 + config.maxTotalNativeMappings + 16), BigInt(slots * 2 + 8), 0n, 0n, 0n, 0n, 0n, 0n]);
}
interface RelayMappingBuffers { readonly buffers: readonly [Uint8Array, Uint8Array] }
/** Original finite forwarding backing exists before either durable leg claim.
 * Adoption transfers it once; rejected handshakes clear unused backing. */
export class RelayNativePairPreparation {
  #reference: ResourceReference | undefined; #maintenance: readonly [Uint8Array, Uint8Array] | undefined;
  readonly #positions: RelayMappingBuffers[] = []; readonly #config: RelayNativePairLimits;
  constructor(config: RelayNativePairLimits, reservation: ResourceReference) {
    this.#config = Object.freeze({ ...config }); this.#reference = reservation.take(relayNativePairCharge(config));
    try {
      this.#maintenance = [new Uint8Array(config.maxEnvelopeBytes), new Uint8Array(config.maxEnvelopeBytes)];
      for (let index = 0; index < config.maxResidentNativeMappings + config.maxPendingNativeMappings; index++) this.#positions.push({ buffers: [new Uint8Array(config.maxEnvelopeBytes), new Uint8Array(config.maxEnvelopeBytes)] }); Object.freeze(this);
    } catch (error) { this.close(); throw error; }
  }
  take(config: RelayNativePairLimits): Readonly<{ reference: ResourceReference; maintenance: readonly [Uint8Array, Uint8Array]; positions: RelayMappingBuffers[] }> {
    requireCredential(this.#reference !== undefined && this.#maintenance !== undefined && Object.keys(this.#config).every(key => this.#config[key as keyof RelayNativePairLimits] === config[key as keyof RelayNativePairLimits]));
    this.#reference.check(); const result = { reference: this.#reference, maintenance: this.#maintenance, positions: this.#positions.splice(0) }; this.#reference = undefined; this.#maintenance = undefined; return Object.freeze(result);
  }
  close(): void { for (const position of this.#positions) for (const buffer of position.buffers) buffer.fill(0); this.#positions.length = 0; for (const buffer of this.#maintenance ?? []) buffer.fill(0); this.#maintenance = undefined; this.#reference?.release(); this.#reference = undefined; }
}
export interface RelayPairedHop { readonly transport: V4AuthenticatedTransport; readonly credentials: VerifiedRelayCredentials; readonly claim: VerifiedRelayClaim; readonly meter: RelayHopByteMeter; }

export class RelayHopByteMeter {
  #total = 0n; #pending = 0n; #tokens: bigint; #tick: ClockMark; #remainder = 0n;
  constructor(readonly limits: RelayLimits, private readonly clock: TrustedClock, private readonly check: () => void, private readonly signal: AbortSignal) { this.#tokens = limits.rateBytesPerSecond; this.#tick = this.#mark(); }
  #mark(): ClockMark { const sample = this.clock.sample(); sample.requireInterval(); requireCredential(sample.mark !== undefined); return sample.mark; }
  requireRemaining(bytes: bigint): void { this.check(); requireCredential(bytes >= 0n && this.#total + this.#pending + bytes <= this.limits.totalBytes); }
  async reserve(bytes: number): Promise<(actual: number | undefined) => void> {
    const requested = BigInt(bytes); requireCredential(Number.isSafeInteger(bytes) && bytes > 0 && requested <= this.limits.rateBytesPerSecond);
    for (;;) {
      this.check(); requireCredential(!this.signal.aborted && this.#total + this.#pending + requested <= this.limits.totalBytes);
      const now = this.#mark(); if (!now.sameEra(this.#tick) || now.milliseconds < this.#tick.milliseconds) throw new TimeError("time_continuity"); const elapsed = now.milliseconds - this.#tick.milliseconds, numerator = elapsed * this.limits.rateBytesPerSecond + this.#remainder, refill = numerator / 1000n; this.#remainder = numerator % 1000n; this.#tick = now;
      if (this.#tokens + refill >= this.limits.rateBytesPerSecond) { this.#tokens = this.limits.rateBytesPerSecond; this.#remainder = 0n; } else this.#tokens += refill;
      if (this.#tokens >= requested) { this.#tokens -= requested; this.#pending += requested; break; }
      const wait = ((requested - this.#tokens) * 1000n + this.limits.rateBytesPerSecond - 1n) / this.limits.rateBytesPerSecond;
      await new Promise<void>((resolve, reject) => {
        const abort = (): void => { clearTimeout(timer); this.signal.removeEventListener("abort", abort); reject(new Error("carrier_closed")); };
        const timer = setTimeout(() => { this.signal.removeEventListener("abort", abort); resolve(); }, Number(wait > 60000n ? 60000n : wait));
        this.signal.addEventListener("abort", abort, { once: true }); if (this.signal.aborted) abort();
      });
    }
    let settled = false;
    return actual => { requireCredential(!settled && (actual === undefined || Number.isSafeInteger(actual) && actual >= 0 && actual <= bytes)); settled = true; this.#pending -= requested;
      // Unknown failed I/O burns the complete submitted bound. It is never
      // exposed as a claim of actual delivered bytes or business completion.
      const used = actual === undefined ? requested : BigInt(actual); this.#total += used; this.#tokens += requested - used; if (this.#tokens >= this.limits.rateBytesPerSecond) { this.#tokens = this.limits.rateBytesPerSecond; this.#remainder = 0n; } };
  }
}
interface Mapping {
  readonly generation: bigint; readonly opener: 0 | 1; readonly streams: [V4NativeApplicationStream | undefined, V4NativeApplicationStream | undefined];
  readonly position: RelayMappingBuffers; readonly buffers: readonly [Uint8Array, Uint8Array]; readonly stopped: [boolean, boolean]; readonly controllers: readonly [AbortController, AbortController];
  readonly messages: [number, number];
  readonly messageCharges: [Readonly<{ release(): void }> | undefined, Readonly<{ release(): void }> | undefined];
  scope: bigint; pending: boolean; retirement?: Promise<void>;
}
export async function readRelayEnvelope(transport: V4AuthenticatedTransport, destination: Uint8Array, check: () => void, signal?: AbortSignal, reserve?: (bytes: number) => Promise<(actual: number | undefined) => void>): Promise<number | null> {
  if (transport.mode === "message") {
    check(); const settle = await reserve?.(destination.length); let bytes: Uint8Array | null;
    try { bytes = await transport.read(destination.length, signal === undefined ? undefined : { signal }); settle?.(bytes?.length ?? 0); }
    catch (error) { settle?.(undefined); throw error; }
    check(); if (bytes === null) return null;
    try {
      requireCredential(bytes.length >= 8 && bytes.length <= destination.length && new DataView(bytes.buffer, bytes.byteOffset, 8).getUint32(0) === bytes.length - 8 && bytes[5] === 0 && bytes[6] === 0 && bytes[7] === 0);
      destination.set(bytes); return bytes.length;
    } finally { bytes.fill(0); }
  }
  let count = 0, expected = 8;
  while (count < expected) {
    check(); const maximum = Math.min(16384, expected - count), settle = await reserve?.(maximum); let bytes: Uint8Array | null;
    try { bytes = await transport.read(maximum, signal === undefined ? undefined : { signal }); settle?.(bytes?.length ?? 0); }
    catch (error) { settle?.(undefined); throw error; }
    check(); if (bytes === null) { requireCredential(count === 0); return null; } requireCredential(bytes.length > 0 && bytes.length <= maximum); try { destination.set(bytes, count); count += bytes.length; } finally { bytes.fill(0); }
    if (count === 8) { expected = 8 + new DataView(destination.buffer, destination.byteOffset, 8).getUint32(0); requireCredential(expected <= destination.length && destination[5] === 0 && destination[6] === 0 && destination[7] === 0); }
  }
  return count;
}
/** A finite opaque forwarder across native and shared message hops. Each OPEN remains on its
 * original generation while native creation, both directions and cleanup run.
 * Headers route ciphertext; they never authenticate or accept endpoint work. */
export class RelayNativePair {
  readonly #config: RelayNativePairLimits; readonly #messageOnly: boolean; readonly #reference: ResourceReference; readonly #hops: readonly [RelayPairedHop, RelayPairedHop];
  readonly #free: RelayMappingBuffers[]; readonly #meters: readonly [RelayHopByteMeter, RelayHopByteMeter]; readonly #maintenance: readonly [Uint8Array, Uint8Array];
  readonly #writeBusy: [boolean, boolean] = [false, false];
  #forwardedBytes = 0n; #forwardedDatagrams = 0n;
  readonly #abort = new AbortController(); readonly #mappings = new Set<Mapping>(); readonly #used = new Map<bigint, number>(); readonly #tasks = new Set<Promise<void>>();
  readonly #waiters = new Set<() => void>(); readonly #done: Promise<void>; #resolve!: () => void; #generation = 0n; #pending = 0; #resident = 0; #creations = 0; #started = false; #closed = false; #cleaned = false; #queueReservedBytes = 0; #queueReservedItems = 0;
  constructor(config: RelayNativePairLimits, hops: readonly [RelayPairedHop, RelayPairedHop], reservation: ResourceReference | RelayNativePairPreparation) {
    this.#config = Object.freeze({ ...config }); this.#messageOnly = hops.every(hop => hop.transport.mode === "message"); const prepared = reservation instanceof RelayNativePairPreparation ? reservation : new RelayNativePairPreparation(config, reservation), backing = prepared.take(config);
    this.#reference = backing.reference.take(relayNativePairCharge(config)); this.#hops = Object.freeze(hops.map(hop => Object.freeze({ ...hop }))) as unknown as readonly [RelayPairedHop, RelayPairedHop]; this.#done = new Promise(resolve => { this.#resolve = resolve; });
    this.#maintenance = backing.maintenance; this.#free = backing.positions;
    try {
      for (const hop of hops) requireCredential(isVerifiedRelayCredentials(hop.credentials) && isVerifiedRelayClaim(hop.claim) && hop.claim.belongsTo(hop.credentials, this.#reference));
      const fields = hops.map(hop => hop.claim.fields(this.#reference));
      try { requireCredential(fields[0]!.endpointRole === 0 && fields[1]!.endpointRole === 1 && fields[0]!.tenant === fields[1]!.tenant && fields[0]!.service === fields[1]!.service && fields[0]!.audience === fields[1]!.audience && fields[0]!.profile === fields[1]!.profile && fields[0]!.parentAuthority === fields[1]!.parentAuthority && fields[0]!.parentGeneration === fields[1]!.parentGeneration && fields[0]!.parentCohort === fields[1]!.parentCohort && fields[0]!.endpointAudience === fields[1]!.endpointAudience && fields[0]!.parentPolicy === fields[1]!.parentPolicy && fields[0]!.parentPolicyRevision === fields[1]!.parentPolicyRevision && fields[0]!.parentIssuedAt === fields[1]!.parentIssuedAt && fields[0]!.parentInitiationEnd === fields[1]!.parentInitiationEnd && fields[0]!.parentSessionEnd === fields[1]!.parentSessionEnd && fields[0]!.identities.length === 2 && fields[1]!.identities.length === 2 && !equalCredential(fields[0]!.leg, fields[1]!.leg));
        for (const side of [0, 1]) requireCredential(equalCredential(fields[0]!.identities[side]!, fields[1]!.identities[side]!));
        for (const name of ["issuer", "lease", "artifact", "parentCapacity", "attempt", "candidate", "pairing", "route", "contract", "relayIdentity", "relayIncarnation"] as const) requireCredential(equalCredential(fields[0]![name], fields[1]![name]));
      } finally { for (const field of fields) { for (const value of Object.values(field)) if (value instanceof Uint8Array) value.fill(0); for (const value of field.identities) value.fill(0); } }
      const limits = hops.map(hop => hop.credentials.limits(this.#reference));
      for (const [side, hop] of hops.entries()) {
        const signed = limits[side]!; requireCredential((hop.transport.mode === "message" && hop.transport.nativeStreams === undefined || hop.transport.mode === "stream" && hop.transport.nativeStreams !== undefined && hop.transport.nativeStreams.capacity >= config.maxResidentNativeMappings) && signed.envelopeBytes === BigInt(config.maxEnvelopeBytes) &&
          signed.pendingMappings >= BigInt(config.maxPendingNativeMappings) && signed.residentMappings >= BigInt(config.maxResidentNativeMappings) && signed.totalMappings >= BigInt(config.maxTotalNativeMappings) &&
          signed.queueItems >= BigInt(config.maxQueueItems) && signed.queueBytes >= BigInt(config.maxQueueBytes) && signed.datagramBytes === BigInt(config.maxDatagramBytes) && signed.rateBytesPerSecond >= BigInt(config.maxEnvelopeBytes));
        if (config.maxDatagramBytes > 0) requireCredential(hop.transport.nativeDatagrams !== undefined && hop.transport.nativeDatagrams.maxDatagramBytes() >= config.maxDatagramBytes);
      }
      requireCredential(this.#messageOnly ? config.maxDatagramBytes === 0 : config.maxPendingNativeMappings >= 3 && config.maxResidentNativeMappings >= 1, "configuration_capacity");
      this.#meters = [hops[0].meter, hops[1].meter]; this.#check();
    } catch (error) { for (const buffer of this.#maintenance) buffer.fill(0); for (const position of this.#free) for (const buffer of position.buffers) buffer.fill(0); this.#free.length = 0; this.#reference.release(); throw error; }
  }
  #check(): void { requireCredential(!this.#closed, "credential_closed"); this.#reference.check(); for (const hop of this.#hops) { hop.credentials.check(this.#reference); hop.claim.check(this.#reference); } }
  #launch(work: () => Promise<void>): void {
    const task = Promise.resolve().then(work).catch(() => this.close()).finally(() => { this.#tasks.delete(task); this.#cleanup(); }); this.#tasks.add(task);
  }
  start(): void {
    this.#check(); requireCredential(!this.#started); this.#started = true;
    for (const side of [0, 1] as const) {
      if (!this.#messageOnly) this.#hops[side].transport.nativeStreams?.enable(); this.#launch(() => this.#lane(side));
      if (!this.#messageOnly && this.#hops[side].transport.nativeStreams !== undefined) this.#launch(() => this.#accept(side));
      if (this.#config.maxDatagramBytes > 0) this.#launch(() => this.#datagrams(side));
    }
  }
  async #wait(): Promise<void> {
    this.#check(); await new Promise<void>(resolve => { requireCredential(this.#waiters.size < 4 * (this.#config.maxResidentNativeMappings + this.#config.maxPendingNativeMappings) + 16); this.#waiters.add(resolve); }); this.#check();
  }
  async #send(side: 0 | 1, transport: V4AuthenticatedTransport, bytes: Uint8Array): Promise<void> {
    const shared = transport.mode === "message";
    if (shared) { while (this.#writeBusy[side]) await this.#wait(); this.#check(); this.#writeBusy[side] = true; }
    let settle: ((actual: number | undefined) => void) | undefined;
    try {
      this.#check(); settle = await this.#meters[side].reserve(bytes.length); let admitted = false;
      const receipt = transport.submit(bytes, () => { this.#check(); requireCredential(!admitted); admitted = true; });
      if (receipt !== undefined) await receipt.completion; requireCredential(receipt !== undefined && admitted); settle(bytes.length); settle = undefined; this.#forwardedBytes += BigInt(bytes.length);
    } catch (error) { settle?.(undefined); throw error; }
    finally { if (shared) { this.#writeBusy[side] = false; this.#wake(); } }
  }
  /** Admit the next bounded receive before it can borrow ciphertext. Empty
   * preallocated mapping buffers do not consume signed queue positions. The
   * position keeps its actual bytes through the physical send receipt. */
  async #queue(maximum: number, signal: AbortSignal = this.#abort.signal): Promise<Readonly<{ resize(bytes: number): void; release(): void }>> {
    requireCredential(Number.isSafeInteger(maximum) && maximum > 0 && maximum <= this.#config.maxQueueBytes);
    const aborted = (): void => { this.#wake(); }; signal.addEventListener("abort", aborted, { once: true });
    try {
      for (;;) {
        this.#check(); if (signal.aborted) throw new Error("canceled");
        if (this.#queueReservedItems < this.#config.maxQueueItems && this.#queueReservedBytes + maximum <= this.#config.maxQueueBytes) break;
        await new Promise<void>(resolve => { requireCredential(this.#waiters.size < 2 * (this.#config.maxResidentNativeMappings + this.#config.maxPendingNativeMappings) + 8); this.#waiters.add(resolve); });
      }
      this.#queueReservedItems++; this.#queueReservedBytes += maximum; let retained = maximum, closed = false;
      return Object.freeze({ resize: (bytes: number): void => { requireCredential(!closed && Number.isSafeInteger(bytes) && bytes >= 0 && bytes <= retained); this.#queueReservedBytes -= retained - bytes; retained = bytes; this.#wake(); },
        release: (): void => { if (closed) return; closed = true; this.#queueReservedItems--; this.#queueReservedBytes -= retained; this.#wake(); } });
    } finally { signal.removeEventListener("abort", aborted); }
  }
  async #lane(side: 0 | 1): Promise<void> {
    const source = this.#hops[side].transport, destination = this.#hops[1 - side]!.transport, buffer = this.#maintenance[side];
    for (;;) {
      const queued = await this.#queue(buffer.length);
      try {
        const count = await readRelayEnvelope(source, buffer, () => this.#check(), this.#abort.signal, bytes => this.#meters[side].reserve(bytes)); requireCredential(count !== null); queued.resize(count); const type = buffer[4]!;
        requireCredential(type !== wire.frame_types.HOP_AUTH && type !== wire.frame_types.DATAGRAM && type >= wire.frame_types.NEGOTIATE! && type < wire.frame_types.HOP_AUTH!);
        if (!this.#messageOnly && (type === wire.frame_types.OPEN_STREAM || type === wire.frame_types.STREAM_DATA)) {
          requireCredential(source.mode === "message"); await this.#message(side, buffer, count);
        } else { await this.#send((1 - side) as 0 | 1, destination, buffer.subarray(0, count)); }
      } finally { buffer.fill(0); queued.release(); }
    }
  }
  async #space(): Promise<void> {
    while (!this.#closed && (this.#pending >= this.#config.maxPendingNativeMappings || this.#mappings.size >= this.#config.maxResidentNativeMappings + this.#config.maxPendingNativeMappings)) await new Promise<void>(resolve => { requireCredential(this.#waiters.size < 2 * (this.#config.maxResidentNativeMappings + this.#config.maxPendingNativeMappings) + 8); this.#waiters.add(resolve); }); this.#check();
  }
  #wake(): void { for (const resolve of this.#waiters) resolve(); this.#waiters.clear(); }
  async #accept(side: 0 | 1): Promise<void> {
    for (;;) {
      await this.#space(); this.#check();
      if (this.#pending >= this.#config.maxPendingNativeMappings || this.#mappings.size >= this.#config.maxResidentNativeMappings + this.#config.maxPendingNativeMappings) continue;
      if (this.#creations >= this.#config.maxTotalNativeMappings) return; requireCredential(this.#generation < 0xffffffffffffffffn);
      const position = this.#free.pop(); requireCredential(position !== undefined);
      const mapping: Mapping = { position, generation: ++this.#generation, opener: side, streams: [undefined, undefined], buffers: position.buffers, stopped: [false, false], controllers: [new AbortController(), new AbortController()], scope: 0n, pending: true, messages: [0, 0], messageCharges: [undefined, undefined] };
      this.#pending++; this.#mappings.add(mapping);
      try { mapping.streams[side] = await this.#hops[side].transport.nativeStreams!.accept({ signal: this.#abort.signal }); this.#check(); requireCredential(this.#creations < this.#config.maxTotalNativeMappings); this.#creations++; }
      catch (error) { this.close(); await this.#retire(mapping); throw error; }
      this.#launch(() => this.#mapping(mapping));
    }
  }
  async #message(side: 0 | 1, bytes: Uint8Array, count: number): Promise<void> {
    const fields = this.#hops[side].claim.fields(this.#reference), profile = fields.profile;
    for (const value of Object.values(fields)) if (value instanceof Uint8Array) value.fill(0); for (const value of fields.identities) value.fill(0);
    const record = this.#record(bytes, count, profile);
    let mapping = [...this.#mappings].find(value => value.scope === record.scope), created = false;
    if (mapping === undefined) {
      // The prepaid scope entry retains ended directions after slot reuse.
      // Ingress was already metered before this provider-buffered DATA arrived.
      const retired = this.#used.get(record.scope);
      if (record.frameType === wire.frame_types.STREAM_DATA && retired !== undefined && (retired & (1 << side)) !== 0) return;
      requireCredential(record.frameType === wire.frame_types.OPEN_STREAM && !this.#used.has(record.scope)); await this.#space();
      requireCredential(this.#resident < this.#config.maxResidentNativeMappings && this.#creations < this.#config.maxTotalNativeMappings && this.#generation < 0xffffffffffffffffn);
      const position = this.#free.pop(); requireCredential(position !== undefined);
      mapping = { position, generation: ++this.#generation, opener: side, streams: [undefined, undefined], buffers: position.buffers, stopped: [false, false], controllers: [new AbortController(), new AbortController()], scope: record.scope, pending: true, messages: [0, 0], messageCharges: [undefined, undefined] };
      this.#used.set(record.scope, 0); this.#resident++; this.#pending++; this.#creations++; this.#mappings.add(mapping); created = true;
    } else { requireCredential(record.frameType === wire.frame_types.STREAM_DATA); }
    try {
      if (mapping.stopped[side] || mapping.retirement !== undefined) return;
      while (mapping.messages[side] !== 0 && !mapping.stopped[side] && mapping.retirement === undefined) await this.#wait();
      if (mapping.stopped[side] || mapping.retirement !== undefined) return;
      const queued = await this.#queue(count);
      try {
        this.#check();
        if (mapping.stopped[side] || mapping.retirement !== undefined || !this.#mappings.has(mapping)) { queued.release(); return; }
        mapping.buffers[side].set(bytes.subarray(0, count)); mapping.messages[side] = count; mapping.messageCharges[side] = queued;
      } catch (error) { queued.release(); throw error; }
      this.#wake(); if (created) { this.#launch(() => this.#mapping(mapping!)); created = false; }
    } finally {
      // A newly allocated position has no supervisor until its first message
      // is staged. Every earlier exit must retire that original position.
      if (created) await this.#retire(mapping);
    }
  }
  async #readMapping(mapping: Mapping, side: 0 | 1, signal: AbortSignal): Promise<number | null> {
    const source = mapping.streams[side];
    if (source !== undefined) return readRelayEnvelope(source, mapping.buffers[side], () => this.#check(), signal, bytes => this.#meters[side].reserve(bytes));
    const aborted = (): void => this.#wake(); signal.addEventListener("abort", aborted, { once: true });
    try { while (mapping.messages[side] === 0) { if (signal.aborted || mapping.stopped[side]) return null; await this.#wait(); } return mapping.messages[side]; }
    finally { signal.removeEventListener("abort", aborted); }
  }
  #consumeMessage(mapping: Mapping, side: 0 | 1): void {
    if (mapping.streams[side] !== undefined) return;
    mapping.buffers[side].fill(0); mapping.messages[side] = 0; mapping.messageCharges[side]?.release(); mapping.messageCharges[side] = undefined; this.#wake();
  }
  #record(buffer: Uint8Array, count: number, profile: string): ReturnType<typeof inspectRecordPrefix> {
    requireCredential(count >= 8 && count <= buffer.length && new DataView(buffer.buffer, buffer.byteOffset, 8).getUint32(0) === count - 8 && buffer[5] === 0 && buffer[6] === 0 && buffer[7] === 0); return inspectRecordPrefix(buffer.subarray(0, count), count - 8, profile);
  }
  async #mapping(mapping: Mapping): Promise<void> {
    const side = mapping.opener, peer = (1 - side) as 0 | 1, buffer = mapping.buffers[side], fields = this.#hops[side].claim.fields(this.#reference), profile = fields.profile;
    for (const value of Object.values(fields)) if (value instanceof Uint8Array) value.fill(0); for (const value of fields.identities) value.fill(0);
    try {
      const queued = mapping.streams[side] === undefined ? undefined : await this.#queue(buffer.length);
      try {
        const count = await this.#readMapping(mapping, side, this.#abort.signal); requireCredential(count !== null); queued?.resize(count);
        const record = this.#record(buffer, count, profile); requireCredential(record.frameType === wire.frame_types.OPEN_STREAM);
        if (mapping.scope === 0n) { requireCredential(!this.#used.has(record.scope) && this.#resident < this.#config.maxResidentNativeMappings); this.#used.set(record.scope, 0); mapping.scope = record.scope; this.#resident++; } else { requireCredential(mapping.scope === record.scope); }
        if (this.#hops[peer].transport.nativeStreams !== undefined) { requireCredential(this.#creations < this.#config.maxTotalNativeMappings); this.#creations++; }
        // The original mapping owns the native create task before forwarding
        // OPEN. A late result can only attach here or be closed here.
        if (this.#hops[peer].transport.nativeStreams !== undefined) mapping.streams[peer] = await this.#hops[peer].transport.nativeStreams!.open({ signal: this.#abort.signal }); this.#check(); mapping.pending = false; this.#pending--; this.#wake();
        await this.#send(peer, mapping.streams[peer] ?? this.#hops[peer].transport, buffer.subarray(0, count));
      } finally { buffer.fill(0); this.#consumeMessage(mapping, side); queued?.release(); }
      const directions = [this.#direction(mapping, side, profile), this.#direction(mapping, peer, profile)].map(direction => direction.catch(error => { this.close(); throw error; }));
      const results = await Promise.allSettled(directions);
      for (const result of results) if (result.status === "rejected") throw result.reason;
    } catch (error) { this.close(); throw error; } finally { await this.#retire(mapping); }
  }
  async #direction(mapping: Mapping, side: 0 | 1, profile: string): Promise<void> {
    const source = mapping.streams[side], nativeDestination = mapping.streams[1 - side], destination = nativeDestination ?? this.#hops[1 - side]!.transport, buffer = mapping.buffers[side], local = mapping.controllers[side];
    const stopped = (failure: NativeDirectionFailure): void => {
      if (mapping.stopped[side]) return;
      mapping.stopped[side] = true; local.abort(); this.#wake();
      if (source !== undefined) void source.stopSending(failure.code === "normal_drained" ? "normal_drained" : undefined).catch(() => this.close());
    };
    const detach = nativeDestination?.observeWriteFailure(stopped) ?? (() => undefined), signal = AbortSignal.any([this.#abort.signal, local.signal]);
    try {
      for (;;) {
        let queued: Readonly<{ resize(bytes: number): void; release(): void }> | undefined;
        try {
          if (source !== undefined) queued = await this.#queue(buffer.length, signal);
          const count = await this.#readMapping(mapping, side, signal);
          if (count === null) { queued?.resize(0); if (nativeDestination !== undefined && !mapping.stopped[side]) await nativeDestination.closeWrite(); return; } queued?.resize(count);
          const record = this.#record(buffer, count, profile); requireCredential(record.scope === mapping.scope && record.frameType === wire.frame_types.STREAM_DATA);
          if (mapping.stopped[side]) return;
          await this.#send((1 - side) as 0 | 1, destination, buffer.subarray(0, count));
        } catch (error) {
          if (mapping.stopped[side] && !this.#closed) return;
          // A bound native direction can terminate without ending its reverse
          // direction or any other mapping. Only the endpoints authenticate
          // STOPPED/DRAINED; the relay preserves the physical direction signal.
          if (error instanceof NativeDirectionFailure && !this.#closed) {
            mapping.stopped[side] = true; local.abort(); this.#wake();
            if (source !== undefined) await source.stopSending(error.code === "normal_drained" ? "normal_drained" : undefined);
            if (nativeDestination !== undefined) await nativeDestination.resetWrite();
            return;
          }
          throw error;
        }
        finally { buffer.fill(0); this.#consumeMessage(mapping, side); queued?.release(); }
      }
    } finally { detach(); }
  }
  #retire(mapping: Mapping): Promise<void> {
    if (mapping.retirement !== undefined) return mapping.retirement;
    if (!this.#mappings.has(mapping)) return Promise.resolve();
    // Install the owner before any physical termination wait. Concurrent
    // cleanup paths may join it but cannot return the same position twice.
    mapping.retirement = Promise.resolve().then(() => this.#finishRetirement(mapping)); this.#wake(); return mapping.retirement;
  }
  async #finishRetirement(mapping: Mapping): Promise<void> {
    if (this.#closed) for (const stream of mapping.streams) if (stream !== undefined) void stream.close();
    await Promise.all(mapping.streams.filter((stream): stream is V4NativeApplicationStream => stream !== undefined).map(stream => stream.waitTermination()));
    for (const side of [0, 1] as const) { mapping.messageCharges[side]?.release(); mapping.messageCharges[side] = undefined; mapping.messages[side] = 0; }
    // Both directions and their original native handles have exited. Record
    // this fact before making the slot reusable, within the existing bounded
    // 128-byte per-scope metadata allowance; no retired mapping stays alive.
    if (mapping.scope !== 0n) { requireCredential(this.#used.has(mapping.scope)); this.#used.set(mapping.scope, 0b11); }
    for (const buffer of mapping.buffers) buffer.fill(0); this.#free.push(mapping.position); this.#mappings.delete(mapping); if (mapping.pending) this.#pending--; if (mapping.scope !== 0n) this.#resident--; this.#wake();
  }
  async #datagrams(side: 0 | 1): Promise<void> {
    const source = this.#hops[side].transport.nativeDatagrams!, destination = this.#hops[1 - side]!.transport.nativeDatagrams!, fields = this.#hops[side].claim.fields(this.#reference), profile = fields.profile;
    for (const value of Object.values(fields)) if (value instanceof Uint8Array) value.fill(0); for (const value of fields.identities) value.fill(0);
    for (;;) {
      const queued = await this.#queue(this.#config.maxDatagramBytes); let bytes: Uint8Array | undefined;
      try {
        this.#check(); const received = await this.#meters[side].reserve(this.#config.maxDatagramBytes);
        try { bytes = await source.receive(this.#config.maxDatagramBytes, { signal: this.#abort.signal }); requireCredential(bytes.length <= this.#config.maxDatagramBytes); received(bytes.length); } catch (error) { received(undefined); throw error; } this.#check(); queued.resize(bytes.length);
        const record = this.#record(bytes, bytes.length, profile); requireCredential(record.frameType === wire.frame_types.DATAGRAM && record.scope === datagramScope);
        const peer = (1 - side) as 0 | 1, settle = await this.#meters[peer].reserve(bytes.length); let receipt: Readonly<{ completion: Promise<void> }> | undefined, admitted = false;
        try { if (destination.maxDatagramBytes() < bytes.length) { settle(0); continue; } receipt = destination.submit(bytes, () => { this.#check(); requireCredential(!admitted); admitted = true; }); if (receipt !== undefined) await receipt.completion; requireCredential(receipt === undefined || admitted); settle(receipt === undefined ? 0 : bytes.length); if (receipt !== undefined) this.#forwardedDatagrams++; }
        catch (error) { settle(undefined); throw error; }
      } finally { bytes?.fill(0); queued.release(); }
    }
  }
  close(): void { if (this.#closed) return; this.#closed = true; this.#abort.abort(); this.#wake(); for (const hop of this.#hops) void hop.transport.close(); for (const mapping of this.#mappings) { for (const controller of mapping.controllers) controller.abort(); for (const stream of mapping.streams) if (stream !== undefined) void stream.close(); } this.#cleanup(); }
  #cleanup(): void {
    if (!this.#closed || this.#tasks.size !== 0 || this.#mappings.size !== 0 || this.#queueReservedItems !== 0 || this.#queueReservedBytes !== 0 || this.#cleaned) return;
    this.#cleaned = true; void Promise.all(this.#hops.map(hop => hop.transport.waitTermination())).then(() => { for (const buffer of this.#maintenance) buffer.fill(0); for (const position of this.#free) for (const buffer of position.buffers) buffer.fill(0); this.#free.length = 0; this.#used.clear(); this.#reference.release(); this.#resolve(); }).catch(() => { /* Physical completion remains unknown; retain original backing. */ });
  }
  forwardingObservations(): Readonly<{ bytes: bigint; datagrams: bigint }> { return Object.freeze({ bytes: this.#forwardedBytes, datagrams: this.#forwardedDatagrams }); }
  waitTermination(): Promise<void> { return this.#done; }
}

for (const constructor of [RelayNativePair, RelayNativePairPreparation, RelayHopByteMeter]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }
