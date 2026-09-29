import { transportV4CryptoUsageRegistryJSON } from "../../generated/transportV4Registry.js";
import type { ClockMark} from "./clock.js";
import { TrustedClock } from "./clock.js";
import type { ResourceReference} from "./resources.js";
import { ResourceVector } from "./resources.js";
import { own } from "./schemaRegistry.js";
import { datagramScope, maxStreamScope, ownProfile, wire } from "./wireRegistry.js";

export type RecordCryptoFailure = "configuration_capacity" | "crypto_usage_exhausted" | "crypto_owner" | "crypto_closed" |
  "crypto_busy" | "record_authentication" | "record_sequence" | "record_replay" | "record_epoch" | "record_scope" | "record_released" |
  "datagram_paused" | "datagram_receive_disabled" | "datagram_key_budget" | "security_unavailable" | "crypto_provider_unavailable";
export class RecordCryptoError extends Error {
  readonly code: RecordCryptoFailure;
  constructor(code: RecordCryptoFailure) { super(code); this.name = "RecordCryptoError"; this.code = code; }
}
export function cryptoFailure(code: RecordCryptoFailure): never { throw new RecordCryptoError(code); }
const maximum = (1n << 64n) - 1n;
const capability = Symbol("original crypto accounting");
type Triple = readonly [bigint, bigint, bigint];
interface Limits { readonly seal_calls: string; readonly open_attempts: string; readonly authentication_blocks: string; readonly ciphertext_bytes: string }
interface Profile {
  readonly key: Limits; readonly epoch: Limits; readonly session: Limits;
  readonly root_max_age_ms: string; readonly max_epochs: string; readonly max_record_key_derivations: string;
}
interface Registry { readonly profiles: Readonly<Record<string, Profile>>; readonly authentication_block_bytes: number; readonly length_blocks: number }
function freeze<T>(v: T): T {
  if (v !== null && typeof v === "object") { for (const c of Object.values(v)) freeze(c); Object.freeze(v); }
  return v;
}
const registry = freeze(JSON.parse(transportV4CryptoUsageRegistryJSON) as Registry);
const scopeCount = wire.streams.client_ordinals + wire.streams.server_ordinals + 2;
const bitmapBytes = Math.ceil(scopeCount * 2 / 8);
const zero: Triple = Object.freeze([0n, 0n, 0n]);
export interface CryptoMaintenanceReserve { readonly calls: bigint; readonly blocks: bigint; readonly bytes: bigint }
export interface CryptoUsageConfig {
  readonly clock: TrustedClock;
  readonly profile: string;
  readonly sendDirection: 0 | 1;
  readonly keys: number;
  readonly maintenance: CryptoMaintenanceReserve;
  readonly runtimeBytes: bigint;
}
interface Captured extends Omit<CryptoUsageConfig, "clock"> { readonly limits: Profile; readonly reserve: Triple }
function capture(c: Omit<CryptoUsageConfig, "clock">): Captured {
  const profile = c.profile, sendDirection = c.sendDirection, keys = c.keys, maintenance = c.maintenance, runtimeBytes = c.runtimeBytes;
  const limits = own(registry.profiles, profile), p = ownProfile(profile);
  const calls = maintenance.calls, blocks = maintenance.blocks, bytes = maintenance.bytes;
  if (limits === undefined || p === undefined || sendDirection !== 0 && sendDirection !== 1 || !Number.isSafeInteger(keys) || keys < 4 || keys > 65536 ||
    typeof runtimeBytes !== "bigint" || runtimeBytes <= 0n || [calls, blocks, bytes].some(n => typeof n !== "bigint" || n <= 0n || n > maximum)) cryptoFailure("configuration_capacity");
  for (const limit of [limits.key, limits.epoch, limits.session]) {
    if (calls >= BigInt(limit.seal_calls) || calls >= BigInt(limit.open_attempts) || blocks >= BigInt(limit.authentication_blocks) || bytes >= BigInt(limit.ciphertext_bytes)) cryptoFailure("configuration_capacity");
  }
  return Object.freeze({ profile, sendDirection, keys, maintenance: Object.freeze({ calls, blocks, bytes }), runtimeBytes, limits,
    reserve: Object.freeze([calls, blocks, bytes]) as Triple });
}
export function cryptoUsageCharge(c: Omit<CryptoUsageConfig, "clock">): ResourceVector {
  const v = capture(c);
  // Two live epoch counters, one Session counter and the fixed reusable key
  // counters. RuntimeBytes covers handles, slot metadata and JS integer work.
  return new ResourceVector([BigInt((v.keys * 4 + 18) * 8 + 2 * bitmapBytes) + v.runtimeBytes, 0n, 0n, BigInt(v.keys + 3), 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
export function recordCryptoCost(aadBytes: number, plaintextBytes: number, tagBytes = 16): Triple {
  if (![aadBytes, plaintextBytes, tagBytes].every(n => Number.isSafeInteger(n) && n >= 0) || tagBytes !== 16) cryptoFailure("configuration_capacity");
  const aad = BigInt(aadBytes), body = BigInt(plaintextBytes), block = BigInt(registry.authentication_block_bytes);
  const blocks = (aad + block - 1n) / block + (body + block - 1n) / block + BigInt(registry.length_blocks), bytes = body + BigInt(tagBytes);
  if (blocks > maximum || bytes > maximum) cryptoFailure("configuration_capacity");
  return Object.freeze([1n, blocks, bytes]);
}
interface EpochState { ledger: CryptoUsageLedger | undefined; readonly number: number; used: BigUint64Array; derived: Uint8Array; keys: number; closed: boolean }
interface KeyState { ledger: CryptoUsageLedger | undefined; epoch: CryptoEpochUsage | undefined; readonly slot: number; readonly direction: 0 | 1; readonly scope: bigint }
const epochs = new WeakMap<CryptoEpochUsage, EpochState>();
const keys = new WeakMap<CryptoKeyUsage, KeyState>();
interface KeyPositionState {
  ledger: CryptoUsageLedger | undefined;
  scope: bigint | undefined;
  readonly direction: 0 | 1;
  readonly indices: readonly number[];
  closing: boolean;
  reservation?: KeyReservationState;
}
interface KeyReservationState {
  ledger: CryptoUsageLedger | undefined;
  readonly marker: KeyPositionState;
  current: KeyPositionState | undefined;
  closing: boolean;
}
const keyReservations = new WeakMap<CryptoKeyReservation, KeyReservationState>();
const keyPositions = new WeakMap<CryptoKeyPositions, KeyPositionState>();
/** Original counter positions, distinct from irreversible cryptographic usage.
 * Closing seals new derivation; a live key keeps its counter until actual exit. */
export class CryptoKeyPositions {
  constructor(token: symbol, state: KeyPositionState) {
    if (token !== capability) cryptoFailure("crypto_owner");
    keyPositions.set(this, state); Object.freeze(this);
  }
  close(): void { const state = keyPositions.get(this); state?.ledger?.closeKeyPositions(this); }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.CryptoKeyPositions"; }
}
/** A fixed two-generation counter pair. A new lease is possible only after
 * every real key from the previous lease has exited. Closing keeps live tails. */
export class CryptoKeyReservation {
  constructor(token: symbol, state: KeyReservationState) {
    if (token !== capability) cryptoFailure("crypto_owner"); keyReservations.set(this, state); Object.freeze(this);
  }
  available(): boolean { const state = keyReservations.get(this); return state?.ledger !== undefined && !state.closing && state.current === undefined; }
  checkout(): CryptoKeyPositions {
    const state = keyReservations.get(this); if (state?.ledger === undefined) cryptoFailure("crypto_closed");
    return state.ledger.checkoutKeyReservation(this);
  }
  close(): void { const state = keyReservations.get(this); state?.ledger?.closeKeyReservation(this); }
}
export class CryptoEpochUsage {
  constructor(token: symbol, state: EpochState) { if (token !== capability) cryptoFailure("crypto_owner"); epochs.set(this, state); Object.freeze(this); }
  close(): void { const s = epochs.get(this); s?.ledger?.closeEpoch(this); }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.CryptoEpochUsage"; }
}
export class CryptoKeyUsage {
  constructor(token: symbol, state: KeyState) { if (token !== capability) cryptoFailure("crypto_owner"); keys.set(this, state); Object.freeze(this); }
  precharge(frame: number, aadBytes: number, plaintextBytes: number): Triple {
    const s = keys.get(this); if (s?.ledger === undefined) cryptoFailure("crypto_closed");
    return s.ledger.precharge(this, frame, aadBytes, plaintextBytes);
  }
  close(): void { const s = keys.get(this); s?.ledger?.closeKey(this); }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.CryptoKeyUsage"; }
}

// This is the original Session's permanent cryptographic ledger, distinct
// from refundable memory/work charges. Retiring keys or epochs frees only
// live slots. Every failed/cancelled precharge and derivation stays consumed.
export class CryptoUsageLedger {
  readonly #config: Captured;
  #clock: TrustedClock | undefined;
  #reservation: ResourceReference | undefined;
  #session: BigUint64Array;
  #epochSlots: (CryptoEpochUsage | undefined)[];
  #keySlots: (CryptoKeyUsage | undefined)[];
  #keyPositions: (KeyPositionState | undefined)[];
  #keyUsage: BigUint64Array;
  #epochCount = 0;
  #derivations = 0n;
  #closed = false;
  #invalidTotal = 0;
  #possibleFailures = 0;
  #pause: ClockMark | undefined;
  #receiveDisabled = false;
  constructor(config: CryptoUsageConfig, reservation: ResourceReference) {
    const c = capture(config), clock = config.clock; this.#config = c;
    if (!(clock instanceof TrustedClock)) cryptoFailure("configuration_capacity");
    this.#clock = clock;
    this.#reservation = reservation.take(cryptoUsageCharge(c));
    try { this.#session = new BigUint64Array(6); this.#epochSlots = Array<CryptoEpochUsage | undefined>(2).fill(undefined); this.#keySlots = Array<CryptoKeyUsage | undefined>(c.keys).fill(undefined); this.#keyPositions = Array<KeyPositionState | undefined>(c.keys).fill(undefined); this.#keyUsage = new BigUint64Array(c.keys * 3); }
    catch (error) { this.#reservation.release(); this.#reservation = undefined; throw error; }
    Object.freeze(this);
  }
  get profile(): string { return this.#config.profile; }
  get rootMaxAgeMS(): bigint { return BigInt(this.#config.limits.root_max_age_ms); }
  get sendDirection(): 0 | 1 { return this.#config.sendDirection; }
  belongsToClock(clock: TrustedClock): boolean { return this.#clock === clock; }
  belongsTo(reservation: ResourceReference): boolean { return this.#reservation?.sameEnvironment(reservation) === true; }
  #check(): void { if (this.#closed) cryptoFailure("crypto_closed"); this.#reservation!.check(); }
  newEpoch(number: number): CryptoEpochUsage {
    this.#check();
    if (!Number.isSafeInteger(number) || number !== this.#epochCount || BigInt(number) >= BigInt(this.#config.limits.max_epochs)) cryptoFailure("record_epoch");
    const slot = this.#epochSlots.indexOf(undefined); if (slot < 0) cryptoFailure("crypto_busy");
    const value = new CryptoEpochUsage(capability, { ledger: this, number, used: new BigUint64Array(6), derived: new Uint8Array(bitmapBytes), keys: 0, closed: false });
    this.#epochSlots[slot] = value; this.#epochCount++;
    return value;
  }
  checkConfiguration(config: CryptoUsageConfig): void {
    this.#check(); const captured = capture(config), original = this.#config;
    if (config.clock !== this.#clock || captured.profile !== original.profile || captured.sendDirection !== original.sendDirection ||
        captured.keys !== original.keys || captured.runtimeBytes !== original.runtimeBytes ||
        captured.reserve.some((value, index) => value !== original.reserve[index])) cryptoFailure("configuration_capacity");
  }
  borrowReference(): ResourceReference { this.#check(); return this.#reservation!.borrow(); }
  prepareKeyPositions(direction: 0 | 1, original: ResourceReference): CryptoKeyPositions {
    this.#check();
    if (direction !== 0 && direction !== 1 || !this.belongsTo(original)) cryptoFailure("crypto_owner");
    const indices: number[] = [];
    for (let i = 4; i < this.#keySlots.length && indices.length < 2; i++) {
      if (this.#keySlots[i] === undefined && this.#keyPositions[i] === undefined) indices.push(i);
    }
    if (indices.length !== 2) cryptoFailure("crypto_busy");
    const state: KeyPositionState = { ledger: this, scope: undefined, direction, indices, closing: false };
    const result = new CryptoKeyPositions(capability, state);
    for (const index of indices) this.#keyPositions[index] = state;
    return result;
  }
  reserveReusableKeyPositions(direction: 0 | 1, original: ResourceReference): CryptoKeyReservation {
    const handle = this.prepareKeyPositions(direction, original), marker = keyPositions.get(handle)!;
    const state: KeyReservationState = { ledger: this, marker, current: undefined, closing: false };
    marker.reservation = state; return new CryptoKeyReservation(capability, state);
  }
  checkoutKeyReservation(handle: CryptoKeyReservation): CryptoKeyPositions {
    this.#check(); const reservation = keyReservations.get(handle);
    if (reservation?.ledger !== this || reservation.closing || reservation.current !== undefined) cryptoFailure("crypto_busy");
    const marker = reservation.marker;
    if (marker.indices.some(index => this.#keyPositions[index] !== marker || this.#keySlots[index] !== undefined)) cryptoFailure("crypto_busy");
    const state: KeyPositionState = { ledger: this, scope: undefined, direction: marker.direction, indices: marker.indices, closing: false, reservation };
    const result = new CryptoKeyPositions(capability, state);
    reservation.current = state;
    for (const index of state.indices) this.#keyPositions[index] = state;
    return result;
  }
  closeKeyReservation(handle: CryptoKeyReservation): void {
    const state = keyReservations.get(handle); if (state?.ledger !== this || state.closing) return;
    state.closing = true;
    if (state.current === undefined) this.#closeKeyPositions(state.marker);
    this.#cleanup();
  }
  bindKeyPositions(handle: CryptoKeyPositions, scope: bigint, direction: 0 | 1, original: ResourceReference): CryptoKeyPositions {
    this.#check(); const state = keyPositions.get(handle);
    if (typeof scope !== "bigint" || scope < 1n || scope > maxStreamScope || !this.belongsTo(original) ||
        state?.ledger !== this || state.closing || state.scope !== undefined || state.direction !== direction) cryptoFailure("crypto_owner");
    state.scope = scope; return handle;
  }
  reserveKeyPositions(scope: bigint, direction: 0 | 1, original: ResourceReference): CryptoKeyPositions {
    const handle = this.prepareKeyPositions(direction, original);
    try { return this.bindKeyPositions(handle, scope, direction, original); }
    catch (error) { handle.close(); throw error; }
  }
  closeKeyPositions(handle: CryptoKeyPositions): void {
    const state = keyPositions.get(handle);
    if (state?.ledger !== this) return;
    this.#closeKeyPositions(state); this.#cleanup();
  }
  #closeKeyPositions(state: KeyPositionState): void {
    state.closing = true;
    const reservation = state.reservation;
    if (reservation !== undefined && !reservation.closing) {
      if (state.indices.some(index => this.#keySlots[index] !== undefined)) return;
      for (const index of state.indices) this.#keyPositions[index] = reservation.marker;
      reservation.current = undefined; state.ledger = undefined; return;
    }
    for (const index of state.indices) if (this.#keyPositions[index] === state && this.#keySlots[index] === undefined) this.#keyPositions[index] = undefined;
    if (state.indices.every(index => this.#keyPositions[index] !== state)) {
      state.ledger = undefined;
      if (reservation !== undefined) { reservation.current = undefined; reservation.ledger = undefined; reservation.marker.ledger = undefined; }
    }
  }
  derive(epoch: CryptoEpochUsage, scope: bigint, direction: 0 | 1, positions?: CryptoKeyPositions): CryptoKeyUsage {
    this.#check();
    const e = epochs.get(epoch);
    if (e?.ledger !== this || e.closed || typeof scope !== "bigint" || scope < 0n || scope > maxStreamScope && scope !== datagramScope || direction !== 0 && direction !== 1) cryptoFailure("crypto_owner");
    if (this.#derivations >= BigInt(this.#config.limits.max_record_key_derivations)) cryptoFailure("crypto_usage_exhausted");
    // The two epoch positions each own both scope-zero directions. Ordinary
    // derivation cannot consume the current/candidate maintenance counters.
    let slot = -1;
    if (positions !== undefined) {
      const state = keyPositions.get(positions);
      if (state?.ledger !== this || state.closing || state.scope !== scope || state.direction !== direction) cryptoFailure("crypto_owner");
      slot = state.indices.find(index => this.#keyPositions[index] === state && this.#keySlots[index] === undefined) ?? -1;
    } else if (scope === 0n) slot = this.#epochSlots.indexOf(epoch) * 2 + direction;
    else for (let index = 4; index < this.#keySlots.length; index++) {
      if (this.#keySlots[index] === undefined && this.#keyPositions[index] === undefined) { slot = index; break; }
    }
    if (slot < 0 || this.#keySlots[slot] !== undefined) cryptoFailure("crypto_busy");
    let index = 0;
    if (scope === datagramScope) index = 1;
    else if (scope !== 0n) {
      const client = scope % 2n === 1n, ordinal = (scope + 1n) / 2n;
      if (ordinal > BigInt(client ? wire.streams.client_ordinals : wire.streams.server_ordinals)) cryptoFailure("record_scope");
      index = Number(ordinal) + 1 + (client ? 0 : wire.streams.client_ordinals);
    }
    index += direction * scopeCount;
    const byte = Math.floor(index / 8), bit = 1 << (index % 8);
    if ((e.derived[byte]! & bit) !== 0) cryptoFailure("record_scope");
    const value = new CryptoKeyUsage(capability, { ledger: this, epoch, slot, direction, scope });
    this.#derivations++; e.keys++; e.derived[byte] = e.derived[byte]! | bit; this.#keySlots[slot] = value;
    return value;
  }
  epochNumber(epoch: CryptoEpochUsage): number {
    this.#check(); const e = epochs.get(epoch);
    if (e?.ledger !== this || e.closed) cryptoFailure("crypto_owner");
    return e.number;
  }
  checkKey(key: CryptoKeyUsage): void {
    this.#check(); const k = keys.get(key), e = k?.epoch === undefined ? undefined : epochs.get(k.epoch);
    if (k?.ledger !== this || e?.ledger !== this || e.closed || this.#keySlots[k.slot] !== key) cryptoFailure("crypto_owner");
  }
  datagramReceiveStatus(): Readonly<{ state: "available" | "temporarily_blocked" | "receive_disabled"; retryAfterMS: bigint | null }> {
    this.#check();
    if (this.#receiveDisabled) return Object.freeze({ state: "receive_disabled", retryAfterMS: null });
    if (this.#pause !== undefined) {
      const clock = this.#clock!, now = clock.monotonic();
      this.#check();
      if (!now.sameEra(this.#pause) || now.milliseconds < this.#pause.milliseconds) cryptoFailure("security_unavailable");
      const elapsed = now.milliseconds - this.#pause.milliseconds;
      if (clock.profile.rate.elapsed(elapsed).lowerMS < 1000n) {
        return Object.freeze({ state: "temporarily_blocked", retryAfterMS: clock.profile.rate.proveDelta(0n, 1000n) - elapsed });
      }
      this.#pause = undefined;
    }
    return Object.freeze({ state: "available", retryAfterMS: null });
  }
  checkDatagramReceive(): void {
    const status = this.datagramReceiveStatus();
    if (status.state === "receive_disabled") cryptoFailure("datagram_receive_disabled");
    if (status.state !== "available") cryptoFailure("datagram_paused");
  }
  reserveDatagramAttempt(): void {
    this.checkDatagramReceive();
    if (this.#invalidTotal + this.#possibleFailures >= 32) cryptoFailure("datagram_paused");
    this.#possibleFailures++;
  }
  finishDatagramAttempt(outcome: "authenticated" | "failed" | "not_called" | "indeterminate"): void {
    if (this.#possibleFailures === 0) cryptoFailure("crypto_owner");
    this.#possibleFailures--;
    if (outcome === "indeterminate") this.#receiveDisabled = true;
    if (outcome === "failed") {
      this.#invalidTotal++;
      if (this.#invalidTotal >= 32) this.#receiveDisabled = true;
      else if (!this.#closed && this.#invalidTotal % 8 === 0) {
        try { this.#pause = this.#clock!.monotonic(); }
        catch { this.#receiveDisabled = true; }
      }
    }
    this.#cleanup();
  }
  usageSnapshot(key: CryptoKeyUsage): Readonly<{ key: Triple; epoch: Triple; session: Triple; derivations: bigint; epochs: number }> {
    this.checkKey(key);
    const k = keys.get(key)!, e = epochs.get(k.epoch!)!;
    const triple = (v: BigUint64Array, offset: number): Triple => Object.freeze([v[offset]!, v[offset + 1]!, v[offset + 2]!]);
    return Object.freeze({ key: triple(this.#keyUsage, k.slot * 3), epoch: triple(e.used, k.direction * 3),
      session: triple(this.#session, k.direction * 3), derivations: this.#derivations, epochs: this.#epochCount });
  }
  precharge(key: CryptoKeyUsage, frame: number, aadBytes: number, plaintextBytes: number): Triple {
    const cost = recordCryptoCost(aadBytes, plaintextBytes); this.#check();
    const k = keys.get(key), e = k?.epoch === undefined ? undefined : epochs.get(k.epoch);
    if (k?.ledger !== this || e?.ledger !== this || e.closed || this.#keySlots[k.slot] !== key) cryptoFailure("crypto_owner");
    const reserve = frame === wire.frame_types.REKEY && k.scope === 0n ? zero : this.#config.reserve;
    const open = k.direction !== this.#config.sendDirection, offset = k.direction * 3, keyOffset = k.slot * 3;
    const fits = (used: BigUint64Array, at: number, limits: Limits, spare: Triple): boolean => {
      const limit: Triple = [BigInt(open ? limits.open_attempts : limits.seal_calls), BigInt(limits.authentication_blocks), BigInt(limits.ciphertext_bytes)];
      return cost.every((value, i) => used[at + i]! <= limit[i]! - spare[i]! && value <= limit[i]! - spare[i]! - used[at + i]!);
    };
    if (!fits(e.used, offset, this.#config.limits.epoch, reserve) || !fits(this.#session, offset, this.#config.limits.session, reserve)) cryptoFailure("crypto_usage_exhausted");
    if (!fits(this.#keyUsage, keyOffset, this.#config.limits.key, k.scope === 0n ? reserve : zero)) {
      cryptoFailure(open && k.scope === datagramScope ? "datagram_key_budget" : "crypto_usage_exhausted");
    }
    for (let i = 0; i < 3; i++) {
      this.#keyUsage[keyOffset + i] = this.#keyUsage[keyOffset + i]! + cost[i]!;
      e.used[offset + i] = e.used[offset + i]! + cost[i]!;
      this.#session[offset + i] = this.#session[offset + i]! + cost[i]!;
    }
    return cost;
  }
  closeKey(key: CryptoKeyUsage): void {
    const k = keys.get(key); if (k?.ledger !== this) return;
    const epoch = k.epoch!, e = epochs.get(epoch)!;
    this.#keySlots[k.slot] = undefined; this.#keyUsage.fill(0n, k.slot * 3, k.slot * 3 + 3);
    const position = this.#keyPositions[k.slot];
    if (position?.closing) this.#closeKeyPositions(position);
    k.ledger = undefined; k.epoch = undefined; e.keys--; this.#retireEpoch(epoch);
  }
  closeEpoch(epoch: CryptoEpochUsage): void {
    const e = epochs.get(epoch); if (e?.ledger !== this) return;
    e.closed = true; this.#retireEpoch(epoch);
  }
  #retireEpoch(epoch: CryptoEpochUsage): void {
    const e = epochs.get(epoch)!;
    if (!e.closed || e.keys !== 0) return;
    this.#epochSlots[this.#epochSlots.indexOf(epoch)] = undefined; e.used.fill(0n); e.derived.fill(0);
    e.used = new BigUint64Array(0); e.derived = new Uint8Array(0); e.ledger = undefined;
    this.#cleanup();
  }
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    for (const position of this.#keyPositions) if (position?.reservation !== undefined) position.reservation.closing = true;
    for (const position of this.#keyPositions) if (position !== undefined) this.#closeKeyPositions(position);
    // Key owners remain responsible for real crypto and output tails.
    for (const epoch of this.#epochSlots) if (epoch !== undefined) this.closeEpoch(epoch);
    this.#cleanup();
  }
  #cleanup(): void {
    if (!this.#closed || this.#possibleFailures !== 0 || this.#keySlots.some(k => k !== undefined) || this.#keyPositions.some(p => p !== undefined) || this.#epochSlots.some(e => e !== undefined)) return;
    this.#keyUsage.fill(0n); this.#session.fill(0n); this.#reservation?.release(); this.#reservation = undefined;
    this.#keyUsage = new BigUint64Array(0); this.#session = new BigUint64Array(0); this.#keySlots = []; this.#keyPositions = []; this.#epochSlots = [];
    this.#clock = undefined; this.#pause = undefined;
  }
  cleanupComplete(): boolean { return this.#reservation === undefined; }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.CryptoUsageLedger"; }
}
for (const c of [CryptoUsageLedger, CryptoEpochUsage, CryptoKeyUsage]) { Object.freeze(c.prototype); Object.freeze(c); }
