// Local v4 runtime accounting. This module has no wire authority, automatic
// retries, GC-based refunds or Node dependency. One root must be shared by all
// participating Environments for a deployment-wide bound to mean anything.

const maximum = (1n << 64n) - 1n;
const scopeLimit = 8;
const capability = Symbol("resource capability");
export const resourceDimensions = Object.freeze([
  "sdk_bytes", "provider_bytes", "disk_bytes", "items", "work_slots", "tasks",
  "timers", "connections", "tls_handshakes", "sessions", "native_handles",
] as const);
const dimensions = resourceDimensions.length;

export type ResourceFailure = "configuration_capacity" | "resource_exhausted" | "admission_closed" | "invalid_resource_owner";
export class ResourceError extends Error {
  readonly code: ResourceFailure;
  constructor(code: ResourceFailure) { super(code); this.name = "ResourceError"; this.code = code; }
}
function fail(code: ResourceFailure): never { throw new ResourceError(code); }
function positiveSize(n: number): number {
  if (!Number.isSafeInteger(n) || n < 1 || n > 65536) fail("configuration_capacity");
  return n;
}
function quantity(n: bigint): bigint {
  if (typeof n !== "bigint" || n < 0n || n > maximum) fail("configuration_capacity");
  return n;
}
function add(a: bigint, b: bigint): bigint {
  if (b > maximum - a) fail("configuration_capacity");
  return a + b;
}
function identity(s: string, digits = 32): string {
  if (typeof s !== "string" || s.length !== digits || !/^[0-9a-f]+$/u.test(s) || /^0+$/u.test(s)) fail("invalid_resource_owner");
  return s;
}
const vectors = new WeakMap<ResourceVector, BigUint64Array>();
function data(v: ResourceVector): BigUint64Array {
  const result = vectors.get(v);
  if (result === undefined) fail("invalid_resource_owner");
  return result;
}

// Vector captures quantities before entering any admission gate. Its backing
// is private; getters on caller-owned input cannot execute during accounting.
export class ResourceVector {
  constructor(values: readonly bigint[]) {
    if (values.length !== dimensions) fail("configuration_capacity");
    const v = new BigUint64Array(dimensions);
    for (let i = 0; i < dimensions; i++) v[i] = quantity(values[i]!);
    vectors.set(this, v);
    Object.freeze(this);
  }
  static zero(): ResourceVector { return new ResourceVector(Array<bigint>(dimensions).fill(0n)); }
  values(): readonly bigint[] { return Object.freeze(Array.from(data(this))); }
  contains(other: ResourceVector): boolean { return contains(data(this), data(other)); }
  add(other: ResourceVector): ResourceVector {
    const a = data(this), b = data(other), result: bigint[] = [];
    for (let i = 0; i < dimensions; i++) result.push(add(a[i]!, b[i]!));
    return new ResourceVector(result);
  }
}
function contains(limit: BigUint64Array, value: BigUint64Array): boolean {
  for (let i = 0; i < dimensions; i++) if (value[i]! > limit[i]!) return false;
  return true;
}
function equal(a: BigUint64Array, b: BigUint64Array): boolean {
  for (let i = 0; i < dimensions; i++) if (a[i] !== b[i]) return false;
  return true;
}
function fits(used: BigUint64Array, limit: BigUint64Array, extra: BigUint64Array): boolean {
  for (let i = 0; i < dimensions; i++) if (extra[i]! > limit[i]! - used[i]!) return false;
  return true;
}
function increase(a: BigUint64Array, b: BigUint64Array): void {
  for (let i = 0; i < dimensions; i++) a[i] = a[i]! + b[i]!;
}
function decrease(a: BigUint64Array, b: BigUint64Array): void {
  for (let i = 0; i < dimensions; i++) a[i] = a[i]! - b[i]!;
}

export type ResourceAccountKind = "tenant" | "environment" | "session" | "direction" | "pool";
export interface ResourceOwner {
  readonly tenant: string;
  readonly environment: string;
  readonly kind: string;
  readonly backing: string;
}
export interface ResourceRootConfig {
  readonly profileRevision: string;
  readonly limit: ResourceVector;
  readonly accounts: number;
  readonly reservations: number;
  readonly references: number;
  // Measured host allowances for JS objects, strings, handles and allocator
  // overhead, in addition to the exact typed-array backing below. A declaration
  // is not a proof of JS heap/RSS or of external native queue bounds.
  readonly rootRuntimeBytes: bigint;
  readonly accountRuntimeBytes: bigint;
  readonly reservationRuntimeBytes: bigint;
  readonly referenceRuntimeBytes: bigint;
}
export interface ResourceRequest {
  readonly owner: ResourceOwner;
  readonly charge: ResourceVector;
  readonly accounts: readonly ResourceAccount[];
}
interface AccountSlot {
  protection: AccountProtection | undefined;
  lease: ResourceAccount | undefined;
  generation: bigint;
  kind: ResourceAccountKind;
  id: string;
  active: boolean;
  closed: boolean;
  charges: number;
  limit: BigUint64Array;
  used: BigUint64Array;
  pending: BigUint64Array;
}
interface ChargeSlot {
  protection: Protection | undefined;
  generation: bigint;
  active: boolean;
  sealed: boolean;
  refs: number;
  count: number;
  vector: BigUint64Array;
  accounts: Int32Array;
  accountRefs: Uint32Array;
}
interface ReferenceSlot {
  idle: boolean;
  generation: bigint;
  active: boolean;
  primary: boolean;
  charge: number;
  owner: ResourceOwner | undefined;
  count: number;
  accounts: Int32Array;
  transferID: string;
  transferredTo: ResourceReference | undefined;
}
interface Protection {
  root: ResourceRoot | undefined;
  charge: number;
  generation: bigint;
  indices: number[];
  closing: boolean;
  bytes: { readonly floor: bigint; readonly scopes: readonly number[]; active: boolean } | undefined;
}
const protections = new WeakMap<ProtectedResourceReservation, Protection>();

// A protected position keeps its original bytes and reference slots prepaid
// between uses. Extra aliases and transfers must really return before reuse.
export class ProtectedResourceReservation {
  constructor(token: symbol, state: Protection) {
    if (token !== capability) fail("invalid_resource_owner");
    protections.set(this, state); Object.freeze(this);
  }
  available(): boolean {
    const state = protections.get(this);
    return state?.root !== undefined && state.root.protectedAvailable(this);
  }
  sameEnvironment(reference: ResourceReference): boolean {
    const state = protections.get(this);
    return state?.root !== undefined && state.root === references.get(reference)?.root && state.root.protectedSameEnvironment(this, reference);
  }
  checkout(): ResourceReference {
    const s = protections.get(this);
    if (s?.root === undefined) fail("admission_closed");
    return s.root.checkoutProtected(this);
  }
  /** Admit only the actual backing bytes into an already protected position.
   * Original account scopes remain charged until every real alias exits. */
  checkoutBytes(bytes: bigint, scopes: readonly ResourceAccount[]): ResourceReference {
    const s = protections.get(this);
    if (s?.root === undefined) fail("admission_closed");
    return s.root.checkoutProtectedBytes(this, bytes, scopes);
  }
  /** Checkout an already prepaid vector into additional original scopes. */
  checkoutScoped(scopes: readonly ResourceAccount[]): ResourceReference {
    const s = protections.get(this); if (s?.root === undefined) fail("invalid_resource_owner");
    return s.root.checkoutProtectedBytes(this, 0n, scopes, true);
  }
  close(): void { const s = protections.get(this); s?.root?.closeProtected(this, true); }
  closeAfterUse(): void { const s = protections.get(this); s?.root?.closeProtected(this, false); }
  cleanupComplete(): boolean { return protections.get(this)?.root === undefined; }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.ProtectedResourceReservation"; }
}

interface AccountProtection {
  root: ResourceRoot | undefined;
  reference: ResourceReference | undefined;
  indices: number[];
  remaining: number;
  next: number;
  closing: boolean;
}
const accountProtections = new WeakMap<ProtectedResourceAccounts, AccountProtection>();

export function protectedAccountPoolCharge(count: number, runtimeBytes: bigint): ResourceVector {
  if (!Number.isSafeInteger(count) || count < 1 || count > 4096 || runtimeBytes <= 0n) fail("configuration_capacity");
  // Root-owned slot arrays already pay their full fixed backing. This charge
  // covers the pool index, lease handles and its original cleanup descriptor.
  return new ResourceVector([BigInt(count) * 64n + runtimeBytes + 128n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
/** Original account slots remain reserved between stream generations. A closed
 * lease cannot be checked out again until every real charge/alias has exited. */
export class ProtectedResourceAccounts {
  constructor(token: symbol, state: AccountProtection) {
    if (token !== capability) fail("invalid_resource_owner");
    accountProtections.set(this, state); Object.freeze(this);
  }
  checkout(): ResourceAccount {
    const state = accountProtections.get(this);
    if (state?.root === undefined) fail("admission_closed");
    return state.root.checkoutAccount(this);
  }
  close(): void { const state = accountProtections.get(this); state?.root?.closeAccountPool(this); }
  cleanupComplete(): boolean { return accountProtections.get(this)?.root === undefined; }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.ProtectedResourceAccounts"; }
}

interface Handle { root: ResourceRoot | undefined; index: number; generation: bigint }
const accounts = new WeakMap<ResourceAccount, Handle>();
const references = new WeakMap<ResourceReference, Handle>();

/** A single shared runtime service is charged at its actual budget root.
 * Participant descriptors and every payload still use scoped reservations. */
export class ResourceServiceReference {
  #root: ResourceRoot | undefined;
  constructor(token: symbol, root: ResourceRoot, readonly charge: ResourceVector) {
    if (token !== capability) fail("invalid_resource_owner");
    this.#root = root; Object.freeze(this);
  }
  check(): void { if (this.#root === undefined) fail("admission_closed"); this.#root.checkService(this); }
  attach(reference: ResourceReference): () => void {
    if (this.#root === undefined) fail("admission_closed");
    return this.#root.attachService(this, reference);
  }
  available(): void { this.#root?.serviceAvailable(this); }
  release(): void { const root = this.#root; if (root === undefined) return; this.#root = undefined; root.releaseService(this); }
}

export class ResourceAccount {
  constructor(token: symbol, root: ResourceRoot, index: number, generation: bigint) {
    if (token !== capability) fail("invalid_resource_owner");
    accounts.set(this, { root, index, generation });
    Object.freeze(this);
  }
  close(): void { const h = accounts.get(this); h?.root?.closeAccount(this); }
  usage(): ResourceVector {
    const h = accounts.get(this);
    if (h?.root === undefined) fail("invalid_resource_owner");
    return h.root.accountUsage(this);
  }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.ResourceAccount"; }
}

// Explicit release is the only refund. A forgotten handle keeps its slot and
// full original backing occupied. Take moves one original reference; Borrow
// acquires another real reference to the same charge without duplicating bytes.
export class ResourceReference {
  constructor(token: symbol, root: ResourceRoot, index: number, generation: bigint) {
    if (token !== capability) fail("invalid_resource_owner");
    references.set(this, { root, index, generation });
    Object.freeze(this);
  }
  check(): void { referenceRoot(this).checkReference(this, false); }
  checkRetained(): void { referenceRoot(this).checkReference(this, true); }
  sameEnvironment(other: ResourceReference): boolean {
    const root = referenceRoot(this);
    return root === referenceRoot(other) && root.sameEnvironment(this, other);
  }
  take(minimum: ResourceVector): ResourceReference { return referenceRoot(this).take(this, minimum, false); }
  takeBorrow(): ResourceReference { return referenceRoot(this).take(this, undefined, true); }
  /** Internal reduction after the uniquely owned backing actually shrinks. */
  shrink(charge: ResourceVector, aliases: readonly ResourceReference[] = []): void { referenceRoot(this).shrink(this, charge, aliases); }
  /** Move unique backing responsibility without refunding it between owners. */
  moveBytesTo(destination: ResourceReference, bytes: bigint): void { referenceRoot(this).moveBytes(this, destination, bytes); }
  borrow(): ResourceReference { return referenceRoot(this).borrow(this); }
  transfer(owner: ResourceOwner, eventID: string, scopes: readonly ResourceAccount[]): ResourceReference {
    return referenceRoot(this).transfer(this, owner, eventID, scopes);
  }
  seal(): void { referenceRoot(this).seal(this); }
  release(): void { const h = references.get(this); h?.root?.release(this); }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.ResourceReference"; }
}
function referenceRoot(ref: ResourceReference): ResourceRoot {
  const root = references.get(ref)?.root;
  if (root === undefined) fail("invalid_resource_owner");
  return root;
}
function captureOwner(source: ResourceOwner): ResourceOwner {
  const tenant = source.tenant, environment = source.environment, kind = source.kind, backing = source.backing;
  identity(tenant); identity(environment); identity(backing);
  if (typeof kind !== "string" || kind.length < 1 || kind.length > 64 || !/^[a-z][a-z0-9_]*$/u.test(kind)) fail("invalid_resource_owner");
  return Object.freeze({ tenant, environment, kind, backing });
}
function sameOwner(a: ResourceOwner, b: ResourceOwner): boolean {
  return a.tenant === b.tenant && a.environment === b.environment && a.kind === b.kind && a.backing === b.backing;
}

export interface ResourceSnapshot {
  readonly limit: ResourceVector;
  readonly charged: ResourceVector;
  readonly peak: ResourceVector;
  readonly reservations: number;
  readonly references: number;
  readonly closed: boolean;
  readonly cleanupComplete: boolean;
}

export class ResourceRoot {
  readonly profileRevision: string;
  readonly #limit: BigUint64Array;
  readonly #used: BigUint64Array;
  readonly #peak: BigUint64Array;
  readonly #accounts: AccountSlot[];
  readonly #charges: ChargeSlot[];
  readonly #refs: ReferenceSlot[];
  // Fixed preflight workspace; no callbacks or await can reenter its use.
  readonly #pending = new BigUint64Array(dimensions);
  #chargeCount = 0;
  #referenceCount = 0;
  readonly #services = new Set<ResourceServiceReference>();
  readonly #serviceScopes = new Map<ResourceServiceReference, Map<number, number>>();
  #closed = false;
  readonly #availability = new Set<{ reference: ResourceReference; changed: () => void; dirty: boolean }>();
  #availabilityQueued = false;

  /** Internal bounded waiters use their owner's prepaid metadata and task slot.
   * Notifications run after accounting, never within a resource transaction. */
  observeAvailability(original: ResourceReference, changed: () => void): () => void {
    this.#reference(original);
    if (this.#availability.size >= this.#refs.length) fail("resource_exhausted");
    const entry = { reference: original.borrow(), changed, dirty: false };
    this.#availability.add(entry);
    return () => { if (this.#availability.delete(entry)) entry.reference.release(); };
  }
  #changed(): void {
    for (const entry of this.#availability) entry.dirty = true;
    if (this.#availabilityQueued || this.#availability.size === 0) return;
    this.#availabilityQueued = true;
    queueMicrotask(() => {
      this.#availabilityQueued = false;
      for (const entry of Array.from(this.#availability)) {
        if (entry.dirty && this.#availability.has(entry)) {
          entry.dirty = false;
          try { entry.changed(); } catch { /* The original waiter owns its failure. */ }
        }
      }
    });
  }

  constructor(config: ResourceRootConfig) {
    // Capture all caller properties before constructing or charging the root.
    const profileRevision = identity(config.profileRevision, 64);
    const limit = data(config.limit).slice(), a = positiveSize(config.accounts), c = positiveSize(config.reservations), r = positiveSize(config.references);
    const runtime = [config.rootRuntimeBytes, config.accountRuntimeBytes, config.reservationRuntimeBytes, config.referenceRuntimeBytes];
    for (const n of runtime) if (quantity(n) === 0n) fail("configuration_capacity");
    if (r < c) fail("configuration_capacity");
    let backing = 4n * BigInt(dimensions) * 8n;
    backing = add(backing, BigInt(a) * 3n * BigInt(dimensions) * 8n);
    backing = add(backing, BigInt(c) * BigInt(dimensions * 8 + scopeLimit * 8));
    backing = add(backing, BigInt(r) * BigInt(scopeLimit * 4));
    for (const [count, bytes] of [[1n, runtime[0]!], [BigInt(a), runtime[1]!], [BigInt(c), runtime[2]!], [BigInt(r), runtime[3]!]]) {
      backing = add(backing, quantity(count! * bytes!));
    }
    if (backing > limit[0]!) fail("configuration_capacity");
    this.profileRevision = profileRevision;
    this.#limit = limit;
    this.#used = new BigUint64Array(dimensions); this.#used[0] = backing;
    this.#peak = this.#used.slice();
    this.#accounts = Array.from({ length: a }, (): AccountSlot => ({ protection: undefined, lease: undefined, generation: 0n, kind: "tenant", id: "", active: false, closed: false, charges: 0,
      limit: new BigUint64Array(dimensions), used: new BigUint64Array(dimensions), pending: new BigUint64Array(dimensions) }));
    this.#charges = Array.from({ length: c }, (): ChargeSlot => ({ protection: undefined, generation: 0n, active: false, sealed: false, refs: 0, count: 0,
      vector: new BigUint64Array(dimensions), accounts: new Int32Array(scopeLimit), accountRefs: new Uint32Array(scopeLimit) }));
    this.#refs = Array.from({ length: r }, (): ReferenceSlot => ({ idle: false, generation: 0n, active: false, primary: false, charge: -1, owner: undefined,
      count: 0, accounts: new Int32Array(scopeLimit), transferID: "", transferredTo: undefined }));
    Object.freeze(this);
  }

  account(kind: ResourceAccountKind, id: string, limit: ResourceVector): ResourceAccount {
    identity(id);
    if (!["tenant", "environment", "session", "direction", "pool"].includes(kind)) fail("configuration_capacity");
    const cap = data(limit);
    if (!cap.some(n => n !== 0n)) fail("configuration_capacity");
    if (this.#closed) fail("admission_closed");
    let free = -1;
    for (let i = 0; i < this.#accounts.length; i++) {
      const s = this.#accounts[i]!;
      if (s.active && s.id === id && s.kind === kind) {
        if (s.closed) fail("admission_closed");
        if (!equal(s.limit, cap)) fail("configuration_capacity");
        return new ResourceAccount(capability, this, i, s.generation);
      }
      if (!s.active && s.generation < maximum && free < 0) free = i;
    }
    if (free < 0) fail("resource_exhausted");
    const s = this.#accounts[free]!;
    s.generation++; s.kind = kind; s.id = id; s.active = true; s.closed = false; s.charges = 0;
    s.limit.set(cap); s.used.fill(0n);
    return new ResourceAccount(capability, this, free, s.generation);
  }

  /** Atomically claim actual root account slots before irreversible admission.
   * Anonymous protected accounts cannot be reopened by an unrelated ID lookup. */
  reserveAccountPool(count: number, kind: ResourceAccountKind, limit: ResourceVector, runtimeBytes: bigint,
    original: ResourceReference): ProtectedResourceAccounts {
    const charge = protectedAccountPoolCharge(count, runtimeBytes), cap = data(limit);
    if (this.#closed) fail("admission_closed");
    if (!["tenant", "environment", "session", "direction", "pool"].includes(kind) || !cap.some(n => n !== 0n) ||
        referenceRoot(original) !== this) fail("invalid_resource_owner");
    original.check();
    const indices: number[] = [];
    for (let i = 0; i < this.#accounts.length && indices.length < count; i++) {
      const slot = this.#accounts[i]!;
      if (!slot.active && slot.generation < maximum) indices.push(i);
    }
    if (indices.length !== count) fail("resource_exhausted");
    const reference = original.take(charge);
    const state: AccountProtection = { root: this, reference, indices, remaining: count, next: 0, closing: false };
    const result = new ProtectedResourceAccounts(capability, state);
    for (const index of indices) {
      const slot = this.#accounts[index]!;
      slot.protection = state; slot.kind = kind; slot.id = ""; slot.active = true; slot.closed = true; slot.charges = 0;
      slot.limit.set(cap); slot.used.fill(0n); slot.pending.fill(0n);
    }
    return result;
  }
  checkoutAccount(pool: ProtectedResourceAccounts): ResourceAccount {
    const state = accountProtections.get(pool);
    if (this.#closed || state?.root !== this || state.closing) fail("admission_closed");
    state.reference!.check();
    for (let n = 0; n < state.indices.length; n++) {
      const offset: number = (state.next + n) % state.indices.length;
      const index: number = state.indices[offset]!;
      const slot: AccountSlot = this.#accounts[index]!;
      if (slot.protection !== state || !slot.closed || slot.charges !== 0 || slot.generation === maximum) continue;
      slot.generation++; slot.closed = false; state.next = (offset + 1) % state.indices.length;
      return slot.lease = new ResourceAccount(capability, this, index, slot.generation);
    }
    fail("resource_exhausted");
  }
  closeAccountPool(pool: ProtectedResourceAccounts): void {
    const state = accountProtections.get(pool);
    if (state?.root !== this || state.closing) return;
    state.closing = true;
    for (const index of state.indices) {
      const slot = this.#accounts[index]!;
      if (slot.protection !== state) continue;
      slot.closed = true;
      if (slot.lease !== undefined) accounts.get(slot.lease)!.root = undefined;
      slot.lease = undefined; this.#collectAccount(slot);
    }
    this.#changed();
  }
  #collectAccount(slot: AccountSlot): void {
    if (!slot.closed || slot.charges !== 0) return;
    const protection = slot.protection;
    if (protection !== undefined && !protection.closing) return;
    slot.active = false; slot.id = ""; slot.protection = undefined;
    if (protection !== undefined && --protection.remaining === 0) {
      const reference = protection.reference; protection.reference = undefined; protection.root = undefined;
      reference?.release();
    }
  }

  #account(handle: ResourceAccount): number {
    const h = accounts.get(handle);
    if (h === undefined || h.root !== this) fail("invalid_resource_owner");
    const s = this.#accounts[h.index];
    if (s === undefined || !s.active || s.generation !== h.generation) fail("invalid_resource_owner");
    return h.index;
  }
  #scopes(owner: ResourceOwner, input: readonly ResourceAccount[]): number[] {
    const n = input.length;
    if (!Number.isSafeInteger(n) || n < 2 || n > scopeLimit) fail("invalid_resource_owner");
    // Input access may run application getters. Capture first, then validate
    // against current state; no root state has been changed at this point.
    const handles: ResourceAccount[] = [];
    for (let i = 0; i < n; i++) handles.push(input[i]!);
    const result: number[] = [];
    let tenant = 0, environment = 0;
    for (const handle of handles) {
      const index = this.#account(handle), s = this.#accounts[index]!;
      if (s.closed) fail("admission_closed");
      if (result.includes(index)) fail("invalid_resource_owner");
      if (s.kind === "tenant") { if (s.id !== owner.tenant) fail("invalid_resource_owner"); tenant++; }
      if (s.kind === "environment") { if (s.id !== owner.environment) fail("invalid_resource_owner"); environment++; }
      result.push(index);
    }
    if (tenant !== 1 || environment !== 1) fail("invalid_resource_owner");
    return result;
  }

  reserve(request: ResourceRequest): ResourceReference { return this.reserveBatch([request])[0]!; }
  reserveService(charge: ResourceVector): ResourceServiceReference {
    const vector = data(charge);
    if (this.#closed) fail("admission_closed");
    if (!vector.some(value => value !== 0n)) fail("configuration_capacity");
    if (this.#services.size >= this.#charges.length || !fits(this.#used, this.#limit, vector)) fail("resource_exhausted");
    const reference = new ResourceServiceReference(capability, this, charge);
    this.#services.add(reference); this.#serviceScopes.set(reference, new Map()); increase(this.#used, vector);
    for (let i = 0; i < dimensions; i++) if (this.#used[i]! > this.#peak[i]!) this.#peak[i] = this.#used[i]!;
    return reference;
  }
  checkService(reference: ResourceServiceReference): void {
    if (this.#closed) fail("admission_closed");
    if (!this.#services.has(reference)) fail("invalid_resource_owner");
  }
  serviceAvailable(reference: ResourceServiceReference): void {
    if (!this.#services.has(reference)) fail("invalid_resource_owner");
    this.#changed();
  }
  attachService(service: ResourceServiceReference, reference: ResourceReference): () => void {
    this.checkService(service);
    const [source] = this.#reference(reference), counts = this.#serviceScopes.get(service)!;
    const indices = Array.from(source.accounts.subarray(0, source.count)), vector = data(service.charge);
    for (const index of indices) {
      const account = this.#accounts[index]!;
      if (!counts.has(index) && !fits(account.used, account.limit, vector)) fail("resource_exhausted");
    }
    for (const index of indices) {
      const count = counts.get(index) ?? 0, account = this.#accounts[index]!;
      if (count === 0) { increase(account.used, vector); account.charges++; }
      counts.set(index, count + 1);
    }
    let retained = true;
    return () => {
      if (!retained) return; retained = false;
      for (const index of indices) {
        const count = counts.get(index)!;
        if (count > 1) counts.set(index, count - 1);
        else {
          counts.delete(index); const account = this.#accounts[index]!; decrease(account.used, vector); account.charges--;
          this.#collectAccount(account);
        }
      }
      this.#changed();
    };
  }
  releaseService(reference: ResourceServiceReference): void {
    if (this.#serviceScopes.get(reference)?.size !== 0) fail("invalid_resource_owner");
    if (!this.#services.delete(reference)) fail("invalid_resource_owner");
    this.#serviceScopes.delete(reference);
    decrease(this.#used, data(reference.charge)); this.#changed();
  }
  reserveBatch(input: readonly ResourceRequest[]): ResourceReference[] {
    const count = input.length;
    if (!Number.isSafeInteger(count) || count < 1 || count > this.#refs.length) fail("configuration_capacity");
    const captured: { owner: ResourceOwner; vector: BigUint64Array; handles: ResourceAccount[] }[] = [];
    for (let i = 0; i < count; i++) {
      const request = input[i]!, owner = captureOwner(request.owner), vector = data(request.charge), scope = request.accounts, n = scope.length;
      if (!Number.isSafeInteger(n) || n < 2 || n > scopeLimit) fail("invalid_resource_owner");
      const handles: ResourceAccount[] = [];
      for (let j = 0; j < n; j++) handles.push(scope[j]!);
      captured.push({ owner, vector, handles });
    }
    // Everything below uses only captured primitive values and SDK objects.
    if (this.#closed) fail("admission_closed");
    const requests = captured.map(r => ({ ...r, scopes: this.#scopes(r.owner, r.handles) }));
    this.#pending.fill(0n);
    for (const s of this.#accounts) s.pending.fill(0n);
    for (let i = 0; i < requests.length; i++) {
      const r = requests[i]!;
      if (!r.vector.some(n => n !== 0n)) fail("configuration_capacity");
      for (const ref of this.#refs) if (ref.active && ref.owner !== undefined && sameOwner(ref.owner, r.owner)) fail("invalid_resource_owner");
      for (let j = 0; j < i; j++) if (sameOwner(requests[j]!.owner, r.owner)) fail("invalid_resource_owner");
      for (let d = 0; d < dimensions; d++) {
        this.#pending[d] = add(this.#pending[d]!, r.vector[d]!);
        for (const index of r.scopes) {
          const s = this.#accounts[index]!;
          s.pending[d] = add(s.pending[d]!, r.vector[d]!);
        }
      }
    }
    if (!fits(this.#used, this.#limit, this.#pending)) fail("resource_exhausted");
    for (const s of this.#accounts) if (!fits(s.used, s.limit, s.pending)) fail("resource_exhausted");
    const charges: number[] = [], refs: number[] = [];
    for (let i = 0; i < this.#charges.length && charges.length < count; i++) if (!this.#charges[i]!.active && this.#charges[i]!.generation < maximum) charges.push(i);
    for (let i = 0; i < this.#refs.length && refs.length < count; i++) if (!this.#refs[i]!.active && this.#refs[i]!.generation < maximum) refs.push(i);
    if (charges.length !== count || refs.length !== count) fail("resource_exhausted");
    // Construct result capabilities before committing any charge. Their finite
    // metadata is included in the original root's reference runtime allowance.
    const result = refs.map(index => new ResourceReference(capability, this, index, this.#refs[index]!.generation + 1n));
    for (let i = 0; i < count; i++) {
      const r = requests[i]!, c = this.#charges[charges[i]!]!, ref = this.#refs[refs[i]!]!;
      c.generation++; c.active = true; c.sealed = false; c.refs = 1; c.count = r.scopes.length; c.vector.set(r.vector);
      c.accounts.fill(-1); c.accountRefs.fill(0);
      ref.generation++; ref.active = true; ref.idle = false; ref.primary = true; ref.charge = charges[i]!; ref.owner = r.owner; ref.count = r.scopes.length;
      ref.accounts.fill(-1); ref.transferID = ""; ref.transferredTo = undefined;
      for (let j = 0; j < r.scopes.length; j++) {
        const index = r.scopes[j]!;
        c.accounts[j] = index; c.accountRefs[j] = 1; ref.accounts[j] = index;
        const s = this.#accounts[index]!; increase(s.used, r.vector); s.charges++;
      }
      this.#chargeCount++; this.#referenceCount++;
    }
    increase(this.#used, this.#pending);
    for (let i = 0; i < dimensions; i++) if (this.#used[i]! > this.#peak[i]!) this.#peak[i] = this.#used[i]!;
    return result;
  }

  #reference(ref: ResourceReference, retained = false): [ReferenceSlot, ChargeSlot, Handle] {
    const h = references.get(ref);
    if (h === undefined || h.root !== this) fail("invalid_resource_owner");
    const slot = this.#refs[h.index];
    if (slot === undefined || !slot.active || slot.idle || slot.generation !== h.generation) fail("invalid_resource_owner");
    const charge = this.#charges[slot.charge]!;
    if (!retained) {
      if (this.#closed || charge.sealed) fail("admission_closed");
      for (let i = 0; i < slot.count; i++) if (this.#accounts[slot.accounts[i]!]!.closed) fail("admission_closed");
    }
    return [slot, charge, h];
  }
  checkReference(ref: ResourceReference, retained: boolean): void { this.#reference(ref, retained); }
  shrink(ref: ResourceReference, requested: ResourceVector, inputAliases: readonly ResourceReference[]): void {
    if (inputAliases.length > 4) fail("invalid_resource_owner");
    const aliases = Array.from(inputAliases);
    // Reducing an already-owned backing is cleanup, including after the
    // root/account has sealed new admission. It creates no resource or alias.
    const next = data(requested), [source, charge] = this.#reference(ref, true);
    if (!source.primary || charge.refs !== 1 + aliases.length || charge.protection !== undefined || source.transferID !== "" ||
        !contains(charge.vector, next) || !next.some(n => n !== 0n)) fail("invalid_resource_owner");
    const slots = new Set<ReferenceSlot>();
    for (const alias of aliases) {
      const [slot, backing] = this.#reference(alias, true);
      if (slot.primary || slot.transferID !== "" || backing !== charge || slots.has(slot) || !sameOwner(slot.owner!, source.owner!) || slot.count !== source.count ||
          Array.from(slot.accounts.subarray(0, slot.count)).some(index => !source.accounts.subarray(0, source.count).includes(index))) fail("invalid_resource_owner");
      slots.add(slot);
    }
    const difference = charge.vector.map((value, index) => value - next[index]!);
    decrease(this.#used, difference);
    for (let i = 0; i < charge.count; i++) decrease(this.#accounts[charge.accounts[i]!]!.used, difference);
    charge.vector.set(next); this.#changed();
  }
  sameEnvironment(a: ResourceReference, b: ResourceReference): boolean {
    const [x] = this.#reference(a), [y] = this.#reference(b);
    return x.owner!.tenant === y.owner!.tenant && x.owner!.environment === y.owner!.environment;
  }
  moveBytes(from: ResourceReference, to: ResourceReference, bytes: bigint): void {
    quantity(bytes);
    const [source, original] = this.#reference(from), [target, next] = this.#reference(to);
    if (source === target || !source.primary || !target.primary || original.refs !== 1 ||
        original.protection !== undefined || next.protection !== undefined || source.transferID !== "" || target.transferID !== "" ||
        original.count !== next.count || source.owner!.tenant !== target.owner!.tenant || source.owner!.environment !== target.owner!.environment ||
        Array.from(original.accounts.subarray(0, original.count)).some(index => !next.accounts.subarray(0, next.count).includes(index)) ||
        bytes > original.vector[0]! || bytes > maximum - next.vector[0]!) fail("invalid_resource_owner");
    // Both owners have exactly the same accounting scopes. Root and account
    // totals stay unchanged; no observer can see a refund before the transfer.
    original.vector[0] = original.vector[0]! - bytes;
    next.vector[0] = next.vector[0]! + bytes;
  }
  take(ref: ResourceReference, minimum: ResourceVector | undefined, borrowed: boolean): ResourceReference {
    const needed = minimum === undefined ? undefined : data(minimum);
    const [s, c, h] = this.#reference(ref);
    if (s.primary === borrowed || s.transferID !== "") fail("invalid_resource_owner");
    if (s.generation === maximum || needed !== undefined && !contains(c.vector, needed)) fail("resource_exhausted");
    const result = new ResourceReference(capability, this, h.index, s.generation + 1n);
    s.generation++; h.root = undefined;
    return result;
  }
  #freeReference(): number {
    for (let i = 0; i < this.#refs.length; i++) if (!this.#refs[i]!.active && this.#refs[i]!.generation < maximum) return i;
    return fail("resource_exhausted");
  }
  borrow(ref: ResourceReference): ResourceReference {
    const [source, charge] = this.#reference(ref);
    if (!source.primary || source.transferID !== "") fail("invalid_resource_owner");
    const p = charge.protection;
    if (p !== undefined) {
      for (const index of p.indices.slice(1)) {
        const s = this.#refs[index]!;
        if (s.idle && s.generation < maximum && s.count === source.count &&
          Array.from(s.accounts.subarray(0, s.count)).every(i => source.accounts.subarray(0, source.count).includes(i))) {
          const result = new ResourceReference(capability, this, index, s.generation + 1n);
          s.generation++; s.idle = false; s.primary = false; s.owner = source.owner;
          return result;
        }
      }
    }
    return this.#alias(source, charge, source.owner!, Array.from(source.accounts.subarray(0, source.count)), false);
  }
  #alias(source: ReferenceSlot, charge: ChargeSlot, owner: ResourceOwner, scopes: number[], primary: boolean): ResourceReference {
    // Preflight the union as well as each new account before mutating anything.
    const union = Array.from(charge.accounts.subarray(0, charge.count));
    for (const index of scopes) if (!union.includes(index)) union.push(index);
    if (union.length > scopeLimit) fail("resource_exhausted");
    for (const index of scopes) if (!charge.accounts.subarray(0, charge.count).includes(index)) {
      const a = this.#accounts[index]!;
      if (!fits(a.used, a.limit, charge.vector)) fail("resource_exhausted");
    }
    const index = this.#freeReference(), s = this.#refs[index]!;
    const result = new ResourceReference(capability, this, index, s.generation + 1n);
    s.generation++; s.active = true; s.idle = false; s.primary = primary; s.charge = source.charge; s.owner = owner; s.count = scopes.length;
    s.accounts.fill(-1); s.transferID = ""; s.transferredTo = undefined;
    for (let i = 0; i < scopes.length; i++) {
      const a = scopes[i]!; s.accounts[i] = a;
      let at = charge.accounts.subarray(0, charge.count).indexOf(a);
      if (at < 0) {
        at = charge.count++; charge.accounts[at] = a; charge.accountRefs[at] = 0;
        const account = this.#accounts[a]!; increase(account.used, charge.vector); account.charges++;
      }
      charge.accountRefs[at] = charge.accountRefs[at]! + 1;
    }
    charge.refs++; this.#referenceCount++;
    return result;
  }
  transfer(ref: ResourceReference, inputOwner: ResourceOwner, eventID: string, inputScopes: readonly ResourceAccount[]): ResourceReference {
    const owner = captureOwner(inputOwner); identity(eventID);
    const scopes = this.#scopes(owner, inputScopes);
    const [source, charge] = this.#reference(ref);
    if (owner.tenant !== source.owner!.tenant || owner.environment !== source.owner!.environment) fail("invalid_resource_owner");
    if (source.transferID !== "") {
      const target = source.transferredTo;
      if (source.transferID !== eventID || target === undefined) fail("invalid_resource_owner");
      const [existing] = this.#reference(target);
      if (!sameOwner(existing.owner!, owner) || existing.count !== scopes.length || scopes.some(i => !existing.accounts.subarray(0, existing.count).includes(i))) fail("invalid_resource_owner");
      return target;
    }
    for (const slot of this.#refs) if (slot.active && slot.owner !== undefined && slot !== source && sameOwner(slot.owner, owner)) fail("invalid_resource_owner");
    const result = this.#alias(source, charge, owner, scopes, true);
    source.transferID = eventID; source.transferredTo = result; source.primary = false;
    return result;
  }
  seal(ref: ResourceReference): void { const [, c] = this.#reference(ref, true); c.sealed = true; }
  release(ref: ResourceReference): void {
    const h = references.get(ref);
    if (h === undefined || h.root !== this) return;
    const s = this.#refs[h.index];
    h.root = undefined;
    if (s === undefined || !s.active || s.generation !== h.generation) return;
    const c = this.#charges[s.charge]!;
    if (c.protection?.indices.includes(h.index)) {
      s.idle = true;
      this.#finishProtection(c);
      this.#changed();
      return;
    }
    this.#releaseSlot(s, c);
    this.#finishProtection(c);
  }
  #releaseSlot(s: ReferenceSlot, c: ChargeSlot): void {
    for (let i = 0; i < s.count; i++) {
      const index = s.accounts[i]!, at = c.accounts.subarray(0, c.count).indexOf(index);
      c.accountRefs[at] = c.accountRefs[at]! - 1;
      if (c.accountRefs[at] === 0) {
        const a = this.#accounts[index]!; decrease(a.used, c.vector); a.charges--;
        this.#collectAccount(a);
        c.count--;
        c.accounts[at] = c.accounts[c.count]!; c.accountRefs[at] = c.accountRefs[c.count]!;
        c.accounts[c.count] = -1; c.accountRefs[c.count] = 0;
      }
    }
    s.active = false; s.owner = undefined; s.transferredTo = undefined; s.transferID = ""; s.accounts.fill(-1); s.count = 0;
    this.#referenceCount--; c.refs--;
    if (c.refs === 0) { decrease(this.#used, c.vector); c.vector.fill(0n); c.active = false; this.#chargeCount--; }
    this.#changed();
  }
  protect(ref: ResourceReference, minimum: ResourceVector, inputAliases: readonly ResourceReference[] = []): ProtectedResourceReservation {
    return this.#protect(ref, minimum, inputAliases, false);
  }
  /** Protect the metadata, charge slot and reference positions of a reusable
   * byte backing. This does not preallocate or promise its variable bytes. */
  protectBytes(ref: ResourceReference, minimum: ResourceVector): ProtectedResourceReservation {
    return this.#protect(ref, minimum, [], true);
  }
  /** Keep the complete vector prepaid while later Session scopes attach to
   * the same backing. No root capacity is refunded between checkout and use. */
  protectScoped(ref: ResourceReference, minimum: ResourceVector, aliases: readonly ResourceReference[] = []): ProtectedResourceReservation {
    return this.#protect(ref, minimum, aliases, true);
  }
  #protect(ref: ResourceReference, minimum: ResourceVector, inputAliases: readonly ResourceReference[], variableBytes: boolean): ProtectedResourceReservation {
    const needed = data(minimum), n = inputAliases.length;
    if (!Number.isSafeInteger(n) || n > 4) fail("invalid_resource_owner");
    const aliases: ResourceReference[] = [];
    for (let i = 0; i < n; i++) aliases.push(inputAliases[i]!);
    const [source, charge, original] = this.#reference(ref);
    if (!source.primary || source.transferID !== "" || charge.protection !== undefined || charge.refs !== 1 + n) fail("invalid_resource_owner");
    if (!contains(charge.vector, needed) || source.generation === maximum) fail("resource_exhausted");
    const indices = [original.index], handles = [original];
    for (const alias of aliases) {
      const [s, c, h] = this.#reference(alias);
      if (c !== charge || s.primary || s.transferID !== "" || indices.includes(h.index) || !sameOwner(s.owner!, source.owner!) || s.count !== source.count ||
        Array.from(s.accounts.subarray(0, s.count)).some(i => !source.accounts.subarray(0, source.count).includes(i))) fail("invalid_resource_owner");
      if (s.generation === maximum) fail("resource_exhausted");
      indices.push(h.index); handles.push(h);
    }
    const state: Protection = { root: this, charge: source.charge, generation: charge.generation, indices, closing: false,
      bytes: variableBytes ? { floor: charge.vector[0]!, scopes: Array.from(source.accounts.subarray(0, source.count)), active: false } : undefined };
    const result = new ProtectedResourceReservation(capability, state);
    // All validation and allocation preceded this atomic change of ownership.
    for (const h of handles) { const s = this.#refs[h.index]!; s.generation++; s.idle = true; h.root = undefined; }
    charge.protection = state;
    return result;
  }
  #protection(handle: ProtectedResourceReservation): [Protection, ChargeSlot] {
    const p = protections.get(handle);
    if (p === undefined || p.root !== this) fail("invalid_resource_owner");
    const c = this.#charges[p.charge]!;
    if (!c.active || c.generation !== p.generation || c.protection !== p) fail("invalid_resource_owner");
    return [p, c];
  }
  protectedAvailable(handle: ProtectedResourceReservation): boolean {
    const [p, c] = this.#protection(handle), primary = this.#refs[p.indices[0]!]!;
    return !p.closing && !this.#closed && c.refs === p.indices.length &&
      p.indices.every(index => this.#refs[index]!.idle && this.#refs[index]!.generation < maximum) &&
      Array.from(primary.accounts.subarray(0, primary.count)).every(index => !this.#accounts[index]!.closed);
  }
  protectedSameEnvironment(handle: ProtectedResourceReservation, reference: ResourceReference): boolean {
    const [state] = this.#protection(handle), [other] = this.#reference(reference), original = this.#refs[state.indices[0]!]!;
    return original.owner!.tenant === other.owner!.tenant && original.owner!.environment === other.owner!.environment;
  }
  checkoutProtected(handle: ProtectedResourceReservation): ResourceReference {
    const [p, c] = this.#protection(handle), s = this.#refs[p.indices[0]!]!;
    if (p.bytes !== undefined) fail("invalid_resource_owner");
    this.#checkProtectedCheckout(p, c, s);
    const result = new ResourceReference(capability, this, p.indices[0]!, s.generation + 1n);
    this.#activateProtected(c, s);
    return result;
  }
  #checkProtectedCheckout(p: Protection, c: ChargeSlot, s: ReferenceSlot): void {
    if (p.closing || this.#closed) fail("admission_closed");
    for (let i = 0; i < s.count; i++) if (this.#accounts[s.accounts[i]!]!.closed) fail("admission_closed");
    if (c.refs !== p.indices.length || p.indices.some(i => !this.#refs[i]!.idle || this.#refs[i]!.generation === maximum)) fail("resource_exhausted");
  }
  #activateProtected(c: ChargeSlot, s: ReferenceSlot): void {
    c.sealed = false; s.idle = false; s.primary = true; s.generation++; s.transferID = ""; s.transferredTo = undefined;
  }
  checkoutProtectedBytes(handle: ProtectedResourceReservation, bytes: bigint, inputScopes: readonly ResourceAccount[], prepaid = false): ResourceReference {
    quantity(bytes);
    if (bytes === 0n && !prepaid || prepaid && bytes !== 0n) fail("configuration_capacity");
    // Capture application-facing inputs before checking the original position.
    // A getter may reenter/close it, so revalidate after scope capture.
    const [original] = this.#protection(handle), owner = this.#refs[original.indices[0]!]!.owner!;
    const scopes = this.#scopes(owner, inputScopes);
    const [p, c] = this.#protection(handle), s = this.#refs[p.indices[0]!]!, state = p.bytes;
    if (state === undefined || state.active || state.scopes.some(index => !scopes.includes(index))) fail("invalid_resource_owner");
    this.#checkProtectedCheckout(p, c, s);
    const total = add(state.floor, bytes);
    if (bytes > this.#limit[0]! - this.#used[0]!) fail("resource_exhausted");
    const extra = scopes.filter(index => !state.scopes.includes(index));
    const next = c.vector.slice(); next[0] = total;
    for (const index of state.scopes) {
      const a = this.#accounts[index]!;
      if (bytes > a.limit[0]! - a.used[0]!) fail("resource_exhausted");
    }
    for (const index of extra) {
      const a = this.#accounts[index]!;
      if (!fits(a.used, a.limit, next)) fail("resource_exhausted");
    }
    const result = new ResourceReference(capability, this, p.indices[0]!, s.generation + 1n);
    // The root counts this backing once. Existing scopes pay the byte delta;
    // newly attached Session/direction scopes pay its entire retained vector.
    this.#used[0] = this.#used[0]! + bytes;
    if (this.#used[0]! > this.#peak[0]!) this.#peak[0] = this.#used[0]!;
    for (const index of state.scopes) this.#accounts[index]!.used[0] = this.#accounts[index]!.used[0]! + bytes;
    c.vector.set(next);
    for (const index of extra) {
      const a = this.#accounts[index]!; increase(a.used, next); a.charges++;
      c.accounts[c.count] = index; c.accountRefs[c.count++] = p.indices.length;
      for (const at of p.indices) { const slot = this.#refs[at]!; slot.accounts[slot.count++] = index; }
    }
    state.active = true; this.#activateProtected(c, s);
    return result;
  }
  closeProtected(handle: ProtectedResourceReservation, seal: boolean): void {
    const [p, c] = this.#protection(handle);
    p.closing = true;
    if (seal) c.sealed = true;
    this.#finishProtection(c);
  }
  #finishProtection(c: ChargeSlot): void {
    const p = c.protection;
    if (p === undefined || c.refs !== p.indices.length || p.indices.some(i => !this.#refs[i]!.idle)) return;
    const bytes = p.bytes;
    if (bytes?.active) {
      // Returning the primary is insufficient while a provider/transfer alias
      // survives. Rebind only after all original references really return.
      const delta = c.vector[0]! - bytes.floor;
      this.#used[0] = this.#used[0]! - delta;
      for (let i = c.count - 1; i >= bytes.scopes.length; i--) {
        const a = this.#accounts[c.accounts[i]!]!; decrease(a.used, c.vector); a.charges--;
        c.accounts[i] = -1; c.accountRefs[i] = 0; c.count--;
        this.#collectAccount(a);
      }
      for (const index of bytes.scopes) this.#accounts[index]!.used[0] = this.#accounts[index]!.used[0]! - delta;
      for (const index of p.indices) {
        const slot = this.#refs[index]!; slot.accounts.fill(-1, bytes.scopes.length); slot.count = bytes.scopes.length;
        slot.transferID = ""; slot.transferredTo = undefined;
      }
      c.vector[0] = bytes.floor; bytes.active = false;
    }
    if (!p.closing) return;
    c.protection = undefined; p.root = undefined;
    for (const i of p.indices) this.#releaseSlot(this.#refs[i]!, c);
  }

  closeAccount(handle: ResourceAccount): void {
    const index = this.#account(handle), a = this.#accounts[index]!;
    a.closed = true; if (a.lease === handle) a.lease = undefined;
    this.#collectAccount(a);
    accounts.get(handle)!.root = undefined;
    this.#changed();
  }
  accountUsage(handle: ResourceAccount): ResourceVector { return new ResourceVector(Array.from(this.#accounts[this.#account(handle)]!.used)); }
  close(): void { this.#closed = true; this.#changed(); }
  snapshot(): ResourceSnapshot {
    return Object.freeze({ limit: new ResourceVector(Array.from(this.#limit)), charged: new ResourceVector(Array.from(this.#used)), peak: new ResourceVector(Array.from(this.#peak)),
      reservations: this.#chargeCount + this.#services.size, references: this.#referenceCount + this.#services.size,
      closed: this.#closed, cleanupComplete: this.#closed && this.#chargeCount === 0 && this.#services.size === 0 });
  }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.ResourceRoot"; }
}

// Internal capability methods are immutable. A caller-owned object cannot
// replace a method and reenter a partially committed accounting transaction.
for (const constructor of [ResourceVector, ResourceRoot, ResourceReference, ResourceServiceReference, ResourceAccount, ProtectedResourceReservation, ProtectedResourceAccounts]) {
  Object.freeze(constructor.prototype); Object.freeze(constructor);
}
