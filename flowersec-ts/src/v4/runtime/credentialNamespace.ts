import { hostRandomFill, type RandomFill } from "./random.js";
import type { TrustedClock } from "./clock.js";
import { TrustedDeadline, TrustedWindow, timerChunk } from "./deadline.js";
import { TimeError } from "./timeArithmetic.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { type DecodeContext } from "./schema.js";
import { CredentialWork, type OwnedCredentialMap, checkCredentialTime, credentialTimeAdd, equalCredential, requireCredential, type CredentialResources } from "./credentialSupport.js";
import { NamespaceArenas, namespaceFloors, containsID, checkStateSuccessor, checkStateHistory, checkTrustTransition, sameMap } from "./namespaceContinuity.js";

export interface CredentialNamespaceConfig {
  readonly tenant: string; readonly authority: string; readonly rootKeyID: Uint8Array; readonly rootPublicKey: Uint8Array;
  readonly random?: RandomFill; readonly clock: TrustedClock; readonly maxTrustLifetimeMS: bigint; readonly bootstrapMS: bigint;
  readonly stateBytes: number; readonly stateNodes: number; readonly resources: CredentialResources;
  readonly continuity?: "online_bootstrap"; readonly trustConfigurations?: number; readonly trustNodes?: number;
  readonly subscriptions?: number; readonly maxStateFetchMS?: bigint; readonly maxFetchAttempts?: number;
}
export interface CredentialEvidence {
  readonly namespace: CredentialNamespace; readonly kind: 0 | 1; readonly cohort: bigint; readonly generation: bigint;
  readonly issuer: Uint8Array; readonly digest: Uint8Array; readonly lease?: Uint8Array;
  readonly permissionDigest: Uint8Array; readonly permissionKind: "issuer" | "activation";
  readonly policyID: string; readonly policyRevision: bigint; readonly expires: bigint;
}
export interface NamespaceStateFetch {
  readonly head: Uint8Array; readonly digest: Uint8Array; readonly encodedBytes: number; readonly signal: AbortSignal;
}
/** A trusted bounded transport fills the original destination and resolves only
 * after it has stopped borrowing request/destination bytes, including abort. */
export interface NamespaceBootstrapFetch { readonly nonce: Uint8Array; readonly signal: AbortSignal }
export type NamespaceBootstrapProvider = (request: NamespaceBootstrapFetch, response: Uint8Array, state: Uint8Array) => Promise<Readonly<{ responseBytes: number; stateBytes: number }>>;
export type NamespaceStateProvider = (request: NamespaceStateFetch, destination: Uint8Array) => Promise<number>;
const namespaces = new WeakSet<CredentialNamespace>();
export function isCredentialNamespace(value: unknown): value is CredentialNamespace { return typeof value === "object" && value !== null && namespaces.has(value as CredentialNamespace); }
const namespaceToken = Symbol("namespace original subscription");
interface HeadOwner { map: OwnedCredentialMap; trust: OwnedCredentialMap; signer: number; deadline: TrustedDeadline; references: number; pending: boolean }
interface NamespacePair { head: HeadOwner; state: OwnedCredentialMap }
interface Candidate { head: HeadOwner; deadline: TrustedDeadline; attempts: number; canceled: boolean }
interface Subscriber { reference: ResourceReference; incarnation: bigint; changed: () => void; live: boolean }

/** One online namespace slot. Its signed history and original protected arenas
 * survive failures/replacement until all actual consumers and fetch tails exit.
 * It never imports a root from a peer or claims in-memory durable restoration. */
export class CredentialNamespace {
  readonly tenant: string; readonly authority: string; readonly clock: TrustedClock;
  readonly #config: Required<Pick<CredentialNamespaceConfig, "trustConfigurations" | "trustNodes" | "subscriptions" | "maxStateFetchMS" | "maxFetchAttempts">> & CredentialNamespaceConfig;
  readonly #work: CredentialWork; readonly #arenas: NamespaceArenas;
  readonly #rootKey: Uint8Array; readonly #rootID: Uint8Array;
  readonly #nonce = new Uint8Array(32); #bootstrap: TrustedWindow;
  readonly #history: OwnedCredentialMap[] = []; readonly #subscribers = new Set<Subscriber>();
  #trust: OwnedCredentialMap | undefined; #pair: NamespacePair | undefined; #observed: HeadOwner | undefined; #candidate: Candidate | undefined;
  #capacityDigest: Uint8Array = new Uint8Array(); #stateContext: DecodeContext = {};
  #generation = 0n; #incarnation = 1n; #closed = false; #failed = false; #busy = false; #replacement = false; #cleaned = false;
  #finishedGeneration = 0n; #finishedSequence = 0n;
  #fetch: Promise<boolean> | undefined; #abort: AbortController | undefined; #timer: ReturnType<typeof setTimeout> | undefined;
  #fetchBuffer: Uint8Array; #bootstrapBuffer: Uint8Array; #bootstrapJob = false; #notifying = false; #notifyAgain = false;
  constructor(config: CredentialNamespaceConfig, reservation: ResourceReference) {
    requireCredential(new.target === CredentialNamespace && (config.continuity === undefined || config.continuity === "online_bootstrap"), "credential_untrusted");
    requireCredential(/^[a-z0-9][a-z0-9._:/@-]{0,127}$/u.test(config.tenant) && /^[a-z0-9][a-z0-9._:/@-]{0,127}$/u.test(config.authority), "configuration_capacity");
    requireCredential(config.rootKeyID.length === 16 && config.rootPublicKey.length === 32 && config.maxTrustLifetimeMS > 0n && config.stateBytes > 0 && config.stateBytes <= 1 << 24 && config.stateNodes >= config.stateBytes, "configuration_capacity");
    this.#config = Object.freeze({ ...config, trustConfigurations: config.trustConfigurations ?? 8, trustNodes: config.trustNodes ?? 270336,
      subscriptions: config.subscriptions ?? 1024, maxStateFetchMS: config.maxStateFetchMS ?? 90000n, maxFetchAttempts: config.maxFetchAttempts ?? 3 });
    for (const [value, cap] of [[this.#config.trustConfigurations, 64], [this.#config.trustNodes, 1 << 20], [this.#config.subscriptions, 65536], [this.#config.maxFetchAttempts, 16]])
      requireCredential(Number.isSafeInteger(value) && value! >= 1 && value! <= cap!, "configuration_capacity");
    requireCredential(this.#config.trustNodes >= 270336, "configuration_capacity");
    requireCredential(this.#config.maxStateFetchMS > 0n && this.#config.maxStateFetchMS <= 90000n, "configuration_capacity");
    this.tenant = config.tenant; this.authority = config.authority; this.clock = config.clock;
    this.#rootKey = new Uint8Array(config.rootPublicKey); this.#rootID = new Uint8Array(config.rootKeyID);
    this.#work = new CredentialWork(config.resources, Math.max(270336, config.stateBytes), reservation);
    let arenas: NamespaceArenas | undefined;
    try {
      this.#arenas = arenas = new NamespaceArenas(this.#work, config.stateBytes, config.stateNodes, this.#config.trustConfigurations + 1, this.#config.trustNodes, config.resources.runtimeBytes);
      this.#bootstrap = new TrustedWindow(this.clock, config.bootstrapMS); this.#fetchBuffer = new Uint8Array(config.stateBytes); this.#bootstrapBuffer = new Uint8Array(270336); (this.#config.random ?? hostRandomFill)(this.#nonce);
    } catch (error) { arenas?.close(); this.#work.close(); throw error; }
    namespaces.add(this); Object.freeze(this);
  }
  bootstrapNonce(): Uint8Array {
    requireCredential(!this.#closed && !this.#busy && (this.#trust === undefined || this.#replacement), "credential_closed"); this.#bootstrap.check(); return new Uint8Array(this.#nonce);
  }
  beginReplacement(): Uint8Array {
    requireCredential(!this.#closed && this.#failed && !this.#busy && this.#fetch === undefined && !this.#replacement, "credential_closed");
    this.#bootstrap = new TrustedWindow(this.clock, this.#config.bootstrapMS); (this.#config.random ?? hostRandomFill)(this.#nonce); this.#replacement = true; return this.bootstrapNonce();
  }
  /** A failed safety incarnation never becomes usable again. The retained
   * immutable history is the replacement's lower bound, not a blank cache. */
  failContinuity(): void {
    if (this.#closed) return;
    if (this.#failed) { this.cancelFetch(); return; } this.#failed = true;
    requireCredential(this.#incarnation < 0xffffffffffffffffn, "configuration_capacity"); this.#incarnation++;
    this.cancelFetch(); this.#dropCandidate(); this.#notify();
  }
  bootstrap(response: Uint8Array, state: Uint8Array): void {
    requireCredential(!this.#closed && !this.#busy && (this.#trust === undefined || this.#replacement), "credential_closed");
    this.#bootstrap.check(); this.#busy = true;
    let reply: OwnedCredentialMap | undefined, trust: OwnedCredentialMap | undefined, head: HeadOwner | undefined, content: OwnedCredentialMap | undefined;
    const priorTrust = this.#trust, priorGeneration = this.#generation, priorContext = this.#stateContext, priorCapacity = this.#capacityDigest;
    try {
      reply = this.#arenas.parse(response, "TrustBootstrapResponse"); this.#work.verify(reply, this.#rootKey); this.#namespace(reply);
      requireCredential(equalCredential(reply.bytes("signing_key_id"), this.#rootID) && equalCredential(reply.bytes("request_nonce"), this.#nonce));
      checkCredentialTime(this.clock, reply.uint("issued_at_ms"), reply.uint("not_after_ms"));
      const trustBytes = reply.bytes("trust_config"), headBytes = reply.bytes("freshness_head");
      try {
        trust = this.#readTrust(trustBytes);
        if (priorTrust !== undefined && sameMap(priorTrust, 0, trust, 0)) { trust.close(); trust = undefined; }
        else { checkTrustTransition(this.#history, trust, this.#pair?.state, this.#work); this.#trust = trust; this.#configure(trust); }
        head = this.#verifyHead(headBytes); requireCredential(!head.pending, "credential_expired");
        this.#followsObserved(head); content = this.#state(state, head);
        if (this.#pair !== undefined) checkStateSuccessor(this.#pair.state, content, this.#trust!);
        this.#bootstrap.check();
        if (trust !== undefined) { this.#history.push(trust); trust = undefined; }
        this.#replaceObserved(head); this.#install(head, content); content = undefined;
        this.#failed = false; this.#replacement = false; this.#nonce.fill(0);
      } finally { trustBytes.fill(0); headBytes.fill(0); }
    } catch (error) { this.#trust = priorTrust; this.#generation = priorGeneration; this.#stateContext = priorContext; this.#capacityDigest = priorCapacity; throw error; }
    finally { reply?.close(); trust?.close(); if (head !== undefined) this.#releaseHead(head); content?.close(); this.#busy = false; this.#notify(); }
  }
  fetchBootstrap(provider: NamespaceBootstrapProvider): Promise<boolean> {
    if (this.#fetch !== undefined) return this.#fetch;
    const nonce = this.bootstrapNonce(), incarnation = this.#incarnation, abort = new AbortController(); this.#abort = abort; this.#bootstrapJob = true;
    const tick = (): void => { try { this.#bootstrap.check(); this.#timer = setTimeout(tick, timerChunk(this.#bootstrap.remainingMS())); } catch { abort.abort(); } };
    const operation = Promise.resolve().then(async () => {
      tick(); requireCredential(!abort.signal.aborted, "credential_expired");
      const result = await provider(Object.freeze({ nonce, signal: abort.signal }), this.#bootstrapBuffer, this.#fetchBuffer);
      requireCredential(!abort.signal.aborted && !this.#closed && incarnation === this.#incarnation, "credential_closed");
      requireCredential(Number.isSafeInteger(result.responseBytes) && result.responseBytes > 0 && result.responseBytes <= this.#bootstrapBuffer.length &&
        Number.isSafeInteger(result.stateBytes) && result.stateBytes > 0 && result.stateBytes <= this.#fetchBuffer.length, "configuration_capacity");
      this.#bootstrap.check(); this.bootstrap(this.#bootstrapBuffer.subarray(0, result.responseBytes), this.#fetchBuffer.subarray(0, result.stateBytes)); return true;
    }).finally(() => {
      if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
      nonce.fill(0); this.#bootstrapBuffer.fill(0); this.#fetchBuffer.fill(0); this.#fetch = undefined; this.#abort = undefined; this.#bootstrapJob = false;
      if (abort.signal.aborted) this.#replacement = false; this.#cleanup();
    });
    this.#fetch = operation; void operation.catch(() => undefined); return operation;
  }
  updateTrust(raw: Uint8Array): void {
    requireCredential(!this.#closed && !this.#failed && !this.#busy && this.#trust !== undefined, "credential_closed"); this.#busy = true;
    let next: OwnedCredentialMap | undefined;
    try {
      next = this.#readTrust(raw);
      if (sameMap(next, 0, this.#trust, 0)) { this.#checkTrust(); return; }
      checkTrustTransition(this.#history, next, this.#pair?.state, this.#work);
      this.#history.push(next); this.#trust = next; this.#configure(next); next = undefined;
      if (this.#candidate !== undefined) { try { this.#checkHead(this.#candidate.head); } catch { this.cancelFetch(); this.#dropCandidate(); } }
    } finally { next?.close(); this.#busy = false; this.#notify(); }
  }
  #namespace(map: OwnedCredentialMap, node = 0, schema = map.schema): void {
    requireCredential(map.text("tenant_id", node, schema) === this.tenant && map.text("revocation_authority_id", node, schema) === this.authority, "credential_untrusted");
  }
  #binding(map: OwnedCredentialMap, node = 0, schema = map.schema): void {
    this.#namespace(map, node, schema);
    requireCredential(map.uint("authority_generation", node, schema) === this.#generation && equalCredential(map.bytes("namespace_capacity_digest", node, schema), this.#capacityDigest));
  }
  #readTrust(raw: Uint8Array): OwnedCredentialMap {
    const trust = this.#arenas.parse(raw, "TrustConfig");
    try {
      this.#work.verify(trust, this.#rootKey); this.#namespace(trust); requireCredential(equalCredential(trust.bytes("signing_key_id"), this.#rootID), "credential_untrusted");
      checkCredentialTime(this.clock, trust.uint("issued_at_ms"), trust.uint("not_after_ms"));
      requireCredential(trust.uint("not_after_ms") - trust.uint("issued_at_ms") <= this.#config.maxTrustLifetimeMS, "credential_untrusted");
      const cap = trust.field("capacity"), publication = trust.field("publication"), generation = trust.uint("authority_generation"), digest = this.#work.digest(trust, "namespace_capacity_digest", cap);
      this.#namespace(trust, cap, "NamespaceCapacity");
      requireCredential(trust.uint("max_state_encoded_bytes", cap, "NamespaceCapacity") <= BigInt(this.#config.stateBytes) && trust.uint("max_head_encoded_bytes", cap, "NamespaceCapacity") >= 795n, "configuration_capacity");
      for (const name of ["max_state_encoded_bytes", "max_revoked_issuers", "max_revoked_certificates", "max_revoked_leases", "max_cohort_policy_segments", "max_trust_proof_entries"]) requireCredential(trust.uint(name, cap, "NamespaceCapacity") <= BigInt(Number.MAX_SAFE_INTEGER), "configuration_capacity");
      let entries = 0n, proofBytes = 0n;
      const signed = this.#history.some(old => sameMap(old, 0, trust, 0)) ? this.#history : [...this.#history, trust];
      requireCredential(signed.length <= this.#config.trustConfigurations, "configuration_capacity");
      for (const config of signed) for (const [field, schema] of [["issuer_authorizations", "CredentialIssuerAuthorization"], ["head_delegations", "HeadSignerDelegation"], ["activation_delegations", "ConnectionActivationDelegation"]] as const)
        for (const n of config.items(field)) { entries++; proofBytes += BigInt(config.doc.encodedSize(n)); if (config === trust) { this.#namespace(trust, n, schema); requireCredential(trust.uint("authority_generation", n, schema) === generation && equalCredential(trust.bytes("namespace_capacity_digest", n, schema), digest)); } }
      requireCredential(entries <= trust.uint("max_trust_proof_entries", cap, "NamespaceCapacity") && proofBytes <= trust.uint("max_trust_proof_bytes", cap, "NamespaceCapacity"), "configuration_capacity");
      const issuerKeys = new Map<string, Uint8Array>();
      for (const [field, schema, keyName] of [["issuer_authorizations", "CredentialIssuerAuthorization", "issuer_public_key"], ["activation_delegations", "ConnectionActivationDelegation", "signer_public_key"]] as const)
        for (const n of trust.items(field)) { const id = key(trust.bytes("issuer_key_id", n, schema)), publicKey = trust.bytes(keyName, n, schema); requireCredential(!issuerKeys.has(id) || equalCredential(issuerKeys.get(id)!, publicKey), "credential_untrusted"); issuerKeys.set(id, publicKey); }
      for (const n of trust.items("head_delegations")) {
        requireCredential(trust.text("publication_policy_id", n, "HeadSignerDelegation") === trust.text("publication_policy_id", publication, "PublicationPolicy") && trust.uint("publication_policy_revision", n, "HeadSignerDelegation") === trust.uint("publication_policy_revision", publication, "PublicationPolicy"));
        requireCredential(trust.uint("not_after_ms", n, "HeadSignerDelegation") - trust.uint("issued_at_ms", n, "HeadSignerDelegation") <= trust.uint("max_signer_lifetime_ms", publication, "PublicationPolicy"));
        requireCredential(this.clock.sample().requireInterval().lowerMS >= trust.uint("issued_at_ms", n, "HeadSignerDelegation"), "credential_expired");
      }
      for (const n of trust.items("once_authorities")) requireCredential(trust.text("tenant_id", n, "OnceAuthorityRef") === this.tenant);
      return trust;
    } catch (error) { trust.close(); throw error; }
  }
  #configure(trust: OwnedCredentialMap): void {
    this.#generation = trust.uint("authority_generation"); const cap = trust.field("capacity");
    this.#capacityDigest = this.#work.digest(trust, "namespace_capacity_digest", cap);
    const limits: Record<string, number> = {};
    for (const name of ["max_state_encoded_bytes", "max_revoked_issuers", "max_revoked_certificates", "max_revoked_leases", "max_cohort_policy_segments", "max_trust_proof_entries"]) {
      const value = trust.uint(name, cap, "NamespaceCapacity"); requireCredential(value <= BigInt(Number.MAX_SAFE_INTEGER), "configuration_capacity"); limits[name] = Number(value);
    }
    limits.max_revoked_issuer_authorizations = limits.max_trust_proof_entries!; this.#stateContext = { limits };
  }
  #verifyHead(raw: Uint8Array): HeadOwner {
    const map = this.#arenas.parse(raw, "FreshnessHead"), trust = this.#trust!;
    try {
      this.#binding(map); const signerID = map.bytes("signing_key_id"), delegation = map.bytes("signer_delegation_digest");
      const signer = [...trust.items("head_delegations")].find(n => equalCredential(trust.bytes("signer_key_id", n, "HeadSignerDelegation"), signerID) && equalCredential(this.#work.digest(trust, "head_signer_delegation_digest", n), delegation));
      requireCredential(signer !== undefined && !containsID(trust, "rejected_head_signers", signerID), "credential_untrusted");
      this.#work.verify(map, trust.bytes("signer_public_key", signer, "HeadSignerDelegation"));
      const from = map.uint("this_update_ms"), until = map.uint("next_update_ms"), publication = trust.field("publication");
      requireCredential(from >= trust.uint("not_before_ms", signer, "HeadSignerDelegation") && from >= trust.uint("issued_at_ms", signer, "HeadSignerDelegation") && until <= trust.uint("not_after_ms", signer, "HeadSignerDelegation") && until - from <= trust.uint("max_head_validity_ms", publication, "PublicationPolicy"));
      requireCredential(map.text("publication_policy_id") === trust.text("publication_policy_id", publication, "PublicationPolicy") && map.uint("publication_policy_revision") === trust.uint("publication_policy_revision", publication, "PublicationPolicy"));
      const head: HeadOwner = { map, trust, signer, deadline: new TrustedDeadline(this.clock, min(until, trust.uint("not_after_ms"))), references: 1, pending: false };
      head.pending = !this.#headTime(head); return head;
    } catch (error) { map.close(); throw error; }
  }
  #headTime(head: HeadOwner): boolean {
    const map = head.map, trust = head.trust, cap = trust.field("capacity"), floors = namespaceFloors(map);
    let required = map.uint("this_update_ms");
    for (const [kind, field] of ["max_certificate_impact_ms", "max_connection_impact_ms"].entries()) if (floors[kind]! > 0n)
      required = max(required, credentialTimeAdd(credentialTimeAdd(trust.uint("cohort_time_origin_ms", cap, "NamespaceCapacity"), floors[kind]! * trust.uint("cohort_duration_ms", cap, "NamespaceCapacity")), trust.uint(field, cap, "NamespaceCapacity")));
    head.deadline.check(); const now = this.clock.sample().requireInterval(); requireCredential(now.upperMS >= required, "credential_expired"); return now.lowerMS >= required;
  }
  #checkHead(head: HeadOwner): void {
    this.#checkTrust(); const trust = this.#trust!, map = head.map;
    requireCredential(map.uint("authority_generation") === this.#generation && !containsID(trust, "rejected_head_signers", map.bytes("signing_key_id")), "credential_revoked");
    requireCredential([...trust.items("head_delegations")].some(n => equalCredential(this.#work.digest(trust, "head_signer_delegation_digest", n), map.bytes("signer_delegation_digest"))), "credential_revoked");
    head.deadline.check();
  }
  #followsObserved(head: HeadOwner): void {
    const old = this.#observed?.map; if (old === undefined || old.uint("authority_generation") < head.map.uint("authority_generation")) return;
    requireCredential(old.uint("authority_generation") === head.map.uint("authority_generation") && head.map.uint("head_sequence") >= old.uint("head_sequence"));
    if (head.map.uint("head_sequence") === old.uint("head_sequence")) requireCredential(sameMap(old, 0, head.map, 0));
    requireCredential(head.map.uint("this_update_ms") >= old.uint("this_update_ms")); const before = namespaceFloors(old), after = namespaceFloors(head.map);
    for (let i = 0; i < 2; i++) requireCredential(after[i]! >= before[i]!);
  }
  #retainHead(head: HeadOwner): HeadOwner { head.references++; return head; }
  #releaseHead(head: HeadOwner): void { if (--head.references === 0) head.map.close(); }
  #replaceObserved(head: HeadOwner): void { const old = this.#observed; this.#observed = this.#retainHead(head); if (old !== undefined) this.#releaseHead(old); }
  observe(raw: Uint8Array): void {
    requireCredential(!this.#closed && !this.#failed && !this.#busy && this.#trust !== undefined, "credential_closed"); this.#checkTrust();
    const head = this.#verifyHead(raw);
    try {
      this.#followsObserved(head);
      if (!head.pending) this.#replaceObserved(head);
      if (this.#candidate === undefined && this.#fetch === undefined) {
        const selected = this.#observed !== undefined && this.#canPin(this.#observed) ? this.#observed : head.pending && this.#canPin(head) ? head : undefined;
        if (selected !== undefined) this.#pin(selected);
      }
      this.#notify(); this.#reuseState();
    } finally { this.#releaseHead(head); }
  }
  #newerThanActive(head: HeadOwner): boolean {
    return this.#pair === undefined || head.map.uint("authority_generation") > this.#pair.head.map.uint("authority_generation") || head.map.uint("head_sequence") > this.#pair.head.map.uint("head_sequence");
  }
  #canPin(head: HeadOwner): boolean {
    const generation = head.map.uint("authority_generation"), sequence = head.map.uint("head_sequence");
    return this.#newerThanActive(head) && (generation > this.#finishedGeneration || generation === this.#finishedGeneration && sequence > this.#finishedSequence);
  }
  #pin(head: HeadOwner): void {
    const deadline = TrustedDeadline.ageAt(this.clock, this.clock.sample(), this.#config.maxStateFetchMS, head.deadline.cap);
    this.#candidate = { head: this.#retainHead(head), deadline, attempts: 0, canceled: false };
  }
  #dropCandidate(): void {
    const candidate = this.#candidate; this.#candidate = undefined;
    if (candidate !== undefined) {
      const generation = candidate.head.map.uint("authority_generation"), sequence = candidate.head.map.uint("head_sequence");
      if (generation > this.#finishedGeneration || generation === this.#finishedGeneration && sequence > this.#finishedSequence) { this.#finishedGeneration = generation; this.#finishedSequence = sequence; }
      candidate.canceled = true; this.#releaseHead(candidate.head);
    }
  }
  advance(): void {
    this.#checkTrust(); if (this.#failed || this.#closed) return;
    const candidate = this.#candidate;
    if (candidate !== undefined) {
      try {
        candidate.deadline.check(); this.#checkHead(candidate.head);
        if (candidate.head.pending && this.#headTime(candidate.head)) {
          candidate.head.pending = false;
          if (this.#observed === undefined || candidate.head.map.uint("head_sequence") > this.#observed.map.uint("head_sequence")) { this.#followsObserved(candidate.head); this.#replaceObserved(candidate.head); this.#notify(); }
        }
      } catch (error) { if (error instanceof TimeError && ["time_unavailable", "time_pending", "time_continuity"].includes(error.code)) throw error; this.cancelFetch(); this.#dropCandidate(); throw error; }
    } else if (this.#fetch === undefined && this.#observed !== undefined && this.#canPin(this.#observed)) this.#pin(this.#observed);
    this.#reuseState();
  }
  #state(raw: Uint8Array, head: HeadOwner): OwnedCredentialMap {
    const state = this.#arenas.parse(raw, "RevocationState", this.#stateContext);
    try {
      this.#binding(state); for (const name of ["credential_revocation_floors", "publication_policy_id", "publication_policy_revision"]) requireCredential(equalCredential(head.map.encoded(head.map.field(name)), state.encoded(state.field(name))));
      requireCredential(head.map.uint("state_encoded_bytes") === BigInt(state.doc.encodedSize()) && equalCredential(head.map.bytes("state_digest"), this.#work.digest(state, "revocation_state_digest")));
      this.#segments(state); checkStateHistory(this.#history.includes(this.#trust!) ? this.#history : [...this.#history, this.#trust!], state, this.#work); return state;
    } catch (error) { state.close(); throw error; }
  }
  #segments(state: OwnedCredentialMap): void {
    const trust = this.#trust!, cap = trust.field("capacity");
    for (const [field, maximum] of [["certificate_impact_ms", "max_certificate_impact_ms"], ["connection_impact_ms", "max_connection_impact_ms"]] as const) {
      const segments = [...state.items("cohort_policy_segments")].filter(n => state.optional(field, n, "CohortPolicySegment") >= 0).sort((a, b) => state.uint("first_cohort", a, "CohortPolicySegment") < state.uint("first_cohort", b, "CohortPolicySegment") ? -1 : 1);
      let previous = -1n;
      for (const n of segments) { requireCredential(state.uint("first_cohort", n, "CohortPolicySegment") > previous); previous = state.uint("last_cohort", n, "CohortPolicySegment"); requireCredential(state.uint(field, n, "CohortPolicySegment") <= trust.uint(maximum, cap, "NamespaceCapacity")); }
    }
  }
  #install(head: HeadOwner, state: OwnedCredentialMap): void {
    const old = this.#pair; this.#pair = { head: this.#retainHead(head), state };
    if (old !== undefined) { this.#releaseHead(old.head); old.state.close(); }
  }
  #installCandidate(state: OwnedCredentialMap, candidate: Candidate): void {
    requireCredential(this.#candidate === candidate && !candidate.canceled && !candidate.head.pending && !this.#failed && !this.#closed, "credential_closed");
    candidate.deadline.check(); this.#checkHead(candidate.head);
    if (this.#pair !== undefined) checkStateSuccessor(this.#pair.state, state, this.#trust!);
    requireCredential(this.#newerThanActive(candidate.head)); this.#install(candidate.head, state); this.#dropCandidate(); this.#notify();
  }
  #reuseState(): void {
    const candidate = this.#candidate, pair = this.#pair;
    if (candidate === undefined || pair === undefined || candidate.head.pending || this.#fetch !== undefined || !equalCredential(candidate.head.map.bytes("state_digest"), pair.head.map.bytes("state_digest"))) return;
    const state = pair.state.retain(); try { this.#installCandidate(state, candidate); } catch (error) { state.close(); throw error; }
  }
  refresh(head: Uint8Array, state: Uint8Array): boolean {
    this.observe(head); this.advance(); const candidate = this.#candidate;
    if (candidate === undefined) return this.#observed === undefined || !this.#newerThanActive(this.#observed);
    if (candidate.head.pending || this.#fetch !== undefined || !equalCredential(candidate.head.map.encoded(), head)) return false;
    const content = this.#state(state, candidate.head);
    try { this.#installCandidate(content, candidate); return true; } catch (error) { content.close(); throw error; }
  }
  fetchPending(provider: NamespaceStateProvider): Promise<boolean> {
    if (this.#fetch !== undefined) return this.#fetch;
    this.advance(); const candidate = this.#candidate; if (candidate === undefined) return Promise.resolve(this.#observed === undefined || !this.#newerThanActive(this.#observed)); if (candidate.head.pending) return Promise.resolve(false);
    requireCredential(candidate.attempts < this.#config.maxFetchAttempts, "configuration_capacity"); candidate.attempts++;
    const size = Number(candidate.head.map.uint("state_encoded_bytes")); requireCredential(size > 0 && size <= this.#fetchBuffer.length, "configuration_capacity");
    const incarnation = this.#incarnation, retained = this.#retainHead(candidate.head), abort = new AbortController(); this.#abort = abort;
    const headBytes = retained.map.encoded(), digest = retained.map.bytes("state_digest");
    const tick = (): void => { try { candidate.deadline.check(); this.#checkHead(retained); this.#timer = setTimeout(tick, timerChunk(candidate.deadline.remainingMS())); } catch { abort.abort(); candidate.canceled = true; } };
    const operation = Promise.resolve().then(async () => {
      tick(); requireCredential(!abort.signal.aborted, "credential_expired");
      const n = await provider(Object.freeze({ head: headBytes, digest, encodedBytes: size, signal: abort.signal }), this.#fetchBuffer.subarray(0, size));
      requireCredential(!abort.signal.aborted && !candidate.canceled && incarnation === this.#incarnation && this.#candidate === candidate && n === size, "credential_closed");
      const state = this.#state(this.#fetchBuffer.subarray(0, size), retained);
      try { this.#installCandidate(state, candidate); return true; } catch (error) { state.close(); throw error; }
    }).finally(() => {
      if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
      this.#fetchBuffer.fill(0); headBytes.fill(0); digest.fill(0); this.#releaseHead(retained); this.#fetch = undefined; this.#abort = undefined;
      if (candidate.canceled && this.#candidate === candidate) this.#dropCandidate(); this.#cleanup();
    });
    this.#fetch = operation; void operation.catch(() => undefined); return operation;
  }
  cancelFetch(): void { this.#abort?.abort(); if (this.#bootstrapJob) this.#bootstrap.cancel(); if (this.#candidate !== undefined) this.#candidate.canceled = true; if (this.#fetch === undefined) this.#dropCandidate(); }
  #checkTrust(): void {
    requireCredential(!this.#closed && !this.#failed && this.#trust !== undefined, "credential_closed"); this.#work.check();
    checkCredentialTime(this.clock, this.#trust.uint("issued_at_ms"), this.#trust.uint("not_after_ms"));
  }
  check(reference?: ResourceReference): void {
    this.#checkTrust(); requireCredential(this.#pair !== undefined, "credential_closed");
    if (reference !== undefined) requireCredential(this.#work.sameEnvironment(reference)); this.#checkHead(this.#pair.head);
  }
  subscribe(reference: ResourceReference, changed: () => void): CredentialNamespaceSubscription {
    this.check(reference); requireCredential(this.#subscribers.size < this.#config.subscriptions, "configuration_capacity");
    const charge = new ResourceVector([this.#config.resources.runtimeBytes + 256n, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
    const retained = this.#work.reserve("namespace_subscription", charge), subscriber = { reference: retained, incarnation: this.#incarnation, changed, live: true };
    this.#subscribers.add(subscriber); return new CredentialNamespaceSubscription(namespaceToken, this, subscriber);
  }
  checkSubscription(token: symbol, subscriber: Subscriber): void {
    requireCredential(token === namespaceToken && subscriber.live && this.#subscribers.has(subscriber) && subscriber.incarnation === this.#incarnation, "credential_closed");
    subscriber.reference.check(); this.check(subscriber.reference);
  }
  releaseSubscription(token: symbol, subscriber: Subscriber): void {
    requireCredential(token === namespaceToken); if (!subscriber.live) return; subscriber.live = false;
    this.#subscribers.delete(subscriber); subscriber.reference.release(); this.#cleanup();
  }
  #notify(): void {
    if (this.#notifying) { this.#notifyAgain = true; return; } this.#notifying = true;
    try { do { this.#notifyAgain = false; for (const s of this.#subscribers) if (s.live) { try { s.changed(); } catch { /* Safety owners recheck their original gate before handoff. */ } } } while (this.#notifyAgain); }
    finally { this.#notifying = false; this.#cleanup(); }
  }
  close(): void { if (this.#closed) return; this.#closed = true; this.cancelFetch(); this.#dropCandidate(); this.#notify(); this.#cleanup(); }
  #cleanup(): void {
    if (!this.#closed || this.#cleaned || this.#fetch !== undefined || this.#busy || this.#notifying || this.#subscribers.size > 0) return; this.#cleaned = true;
    this.#nonce.fill(0); this.#rootKey.fill(0); this.#rootID.fill(0); this.#capacityDigest.fill(0); this.#fetchBuffer.fill(0); this.#bootstrapBuffer.fill(0);
    if (this.#pair !== undefined) { this.#releaseHead(this.#pair.head); this.#pair.state.close(); } if (this.#observed !== undefined) this.#releaseHead(this.#observed);
    this.#pair = undefined; this.#observed = undefined; this.#trust = undefined; for (const trust of this.#history) trust.close(); this.#history.length = 0;
    this.#arenas.close(); this.#work.close();
  }
  cleanupComplete(): boolean { this.#cleanup(); return this.#cleaned; }
  async waitCleanup(): Promise<void> { await this.#fetch?.catch(() => undefined); this.#cleanup(); }
  matches(map: OwnedCredentialMap): boolean {
    return map.text("tenant_id") === this.tenant && map.text("revocation_authority_id") === this.authority;
  }
  checkNamespace(map: OwnedCredentialMap): void {
    this.check(); this.#namespace(map);
    requireCredential(map.uint("revocation_authority_generation") === this.#generation && equalCredential(map.bytes("namespace_capacity_digest"), this.#capacityDigest));
  }
  checkReference(map: OwnedCredentialMap, node: number): void {
    this.#namespace(map, node, "RevocationNamespaceRef");
    requireCredential(map.uint("generation", node, "RevocationNamespaceRef") === this.#generation && equalCredential(map.bytes("namespace_capacity_digest", node, "RevocationNamespaceRef"), this.#capacityDigest));
  }
  impactDeadline(cohort: bigint, kind: 0 | 1): bigint {
    this.check(); const trust = this.#trust!, state = this.#pair!.state, cap = trust.field("capacity"), field = kind === 0 ? "certificate_impact_ms" : "connection_impact_ms";
    let impact: bigint | undefined;
    for (const node of state.items("cohort_policy_segments")) if (cohort >= state.uint("first_cohort", node, "CohortPolicySegment") && cohort <= state.uint("last_cohort", node, "CohortPolicySegment") && state.optional(field, node, "CohortPolicySegment") >= 0) {
      requireCredential(impact === undefined); impact = state.uint(field, node, "CohortPolicySegment");
    }
    requireCredential(impact !== undefined, "credential_untrusted");
    const duration = trust.uint("cohort_duration_ms", cap, "NamespaceCapacity"), origin = trust.uint("cohort_time_origin_ms", cap, "NamespaceCapacity");
    return credentialTimeAdd(credentialTimeAdd(origin, (cohort + 1n) * duration), impact);
  }
  verifyCredential(map: OwnedCredentialMap, kind: 0 | 1, work: CredentialWork): CredentialEvidence {
    this.checkNamespace(map); const trust = this.#trust!, cap = trust.field("capacity"), cohort = map.uint("revocation_epoch"), issued = map.uint("issued_at_ms"), end = map.uint(kind === 0 ? "expires_at_ms" : "session_not_after_ms");
    const origin = trust.uint("cohort_time_origin_ms", cap, "NamespaceCapacity"), duration = trust.uint("cohort_duration_ms", cap, "NamespaceCapacity");
    requireCredential(issued >= origin && (issued - origin) / duration === cohort && end <= this.impactDeadline(cohort, kind));
    const issuer = map.bytes("issuer_key_id"); requireCredential(!containsID(trust, "retired_issuers", issuer), "credential_revoked");
    const schema = "CredentialIssuerAuthorization";
    const auth = [...trust.items("issuer_authorizations")].find(node =>
      equalCredential(trust.bytes("issuer_key_id", node, schema), issuer) && trust.uint("credential_kind", node, schema) === BigInt(kind) &&
      trust.text("audience", node, schema) === map.text("audience") && trust.text("crypto_profile_id", node, schema) === map.text("crypto_profile_id") &&
      issued >= trust.uint("signing_not_before_ms", node, schema) && issued < trust.uint("signing_not_after_ms", node, schema) &&
      cohort >= trust.uint("first_cohort", node, schema) && cohort <= trust.uint("last_cohort", node, schema) && end <= trust.uint("max_credential_not_after_ms", node, schema) &&
      (kind === 1 || trust.text("subject_id", node, schema) === map.text("subject_id") && trust.uint("role", node, schema) === map.uint("role")));
    requireCredential(auth !== undefined, "credential_untrusted"); work.verify(map, trust.bytes("issuer_public_key", auth, schema));
    const evidence: CredentialEvidence = Object.freeze({ namespace: this, kind, cohort, issuer, generation: this.#generation, permissionKind: "issuer", permissionDigest: work.digest(trust, "credential_issuer_authorization_digest", auth), digest: work.digest(map, kind === 0 ? "certificate_digest" : "artifact_digest"),
      ...(kind === 1 ? { lease: map.bytes("lease_id") } : {}), policyID: map.text("revocation_policy_id"), policyRevision: map.uint("revocation_policy_revision"), expires: end });
    this.checkEvidence(evidence); return evidence;
  }
  policyRequirements(e: CredentialEvidence): Readonly<{ staleness: bigint; signerLifetime: bigint }> {
    this.check(); requireCredential(e.namespace === this); const trust = this.#trust!;
    const p = [...trust.items("credential_policies")].find(node => trust.text("revocation_policy_id", node, "CredentialRevocationPolicy") === e.policyID && trust.uint("revocation_policy_revision", node, "CredentialRevocationPolicy") === e.policyRevision);
    requireCredential(p !== undefined, "credential_untrusted");
    return { staleness: trust.uint("max_staleness_ms", p, "CredentialRevocationPolicy"), signerLifetime: trust.uint("max_head_signer_lifetime_ms", p, "CredentialRevocationPolicy") };
  }
  activeVersion(): readonly [bigint, bigint] { this.check(); return [this.#pair!.head.map.uint("authority_generation"), this.#pair!.head.map.uint("head_sequence")]; }
  availableUntil(staleness: bigint): bigint {
    this.check(); const head = this.#pair!.head.map;
    return [this.#trust!.uint("not_after_ms"), this.#pair!.head.deadline.cap, head.uint("next_update_ms"), credentialTimeAdd(head.uint("this_update_ms"), staleness)].reduce((a, b) => a < b ? a : b);
  }
  checkPolicy(staleness: bigint, signerLifetime: bigint): void {
    this.check(); const trust = this.#trust!, pair = this.#pair!, publication = trust.field("publication");
    requireCredential(trust.uint("max_signer_lifetime_ms", publication, "PublicationPolicy") <= signerLifetime, "credential_untrusted");
    checkCredentialTime(this.clock, pair.head.map.uint("this_update_ms"), credentialTimeAdd(pair.head.map.uint("this_update_ms"), staleness));
  }
  checkEvidence(e: CredentialEvidence): void {
    const policy = this.policyRequirements(e); this.checkPolicy(policy.staleness, policy.signerLifetime);
    const trust = this.#trust!, state = this.#pair!.state;
    checkCredentialTime(this.clock, 0n, e.expires);
    requireCredential(e.generation === this.#generation, "credential_revoked");
    const field = e.permissionKind === "issuer" ? "issuer_authorizations" : "activation_delegations", domain = e.permissionKind === "issuer" ? "credential_issuer_authorization_digest" : "connection_activation_delegation_digest";
    requireCredential([...trust.items(field)].some(n => equalCredential(this.#work.digest(trust, domain, n), e.permissionDigest)), "credential_revoked");
    const floors = namespaceFloors(state), observed = this.#observed === undefined ? floors : namespaceFloors(this.#observed.map);
    requireCredential(e.cohort >= max(floors[e.kind], observed[e.kind]), "credential_revoked");
    requireCredential(!containsID(trust, "retired_issuers", e.issuer), "credential_revoked");
    for (const n of state.items("revoked_issuers")) requireCredential(!equalCredential(state.bytes("issuer_key_id", n, "RevokedIssuerEntry"), e.issuer), "credential_revoked");
    if (e.kind === 0) for (const n of state.items("revoked_certificates")) requireCredential(!equalCredential(state.bytes("certificate_digest", n, "RevokedCertificateEntry"), e.digest), "credential_revoked");
    if (e.lease !== undefined) for (const n of state.items("revoked_leases")) requireCredential(!(equalCredential(state.bytes("issuer_key_id", n, "RevokedLeaseEntry"), e.issuer) && equalCredential(state.bytes("lease_id", n, "RevokedLeaseEntry"), e.lease)), "credential_revoked");
  }
  onceAuthority(issuer: Uint8Array): Uint8Array {
    this.check(); const trust = this.#trust!, node = [...trust.items("once_authorities")].find(n => equalCredential(trust.bytes("artifact_issuer_key_id", n, "OnceAuthorityRef"), issuer));
    requireCredential(node !== undefined, "credential_untrusted"); return trust.encoded(node);
  }
  verifyActivation(activation: OwnedCredentialMap, parent: CredentialEvidence, work: CredentialWork): CredentialEvidence {
    this.checkEvidence(parent); const trust = this.#trust!, s = "ConnectionActivationDelegation";
    const node = [...trust.items("activation_delegations")].find(n => trust.text("signing_key_id", n, s) === activation.text("signing_key_id"));
    requireCredential(node !== undefined, "credential_untrusted");
    const issuer = trust.bytes("issuer_key_id", node, s), issued = activation.uint("issued_at_ms"), until = activation.uint("activation_not_after_ms"), end = activation.uint("session_not_after_ms");
    requireCredential(!containsID(trust, "retired_issuers", issuer) && equalCredential(trust.bytes("artifact_issuer_key_id", node, s), parent.issuer) &&
      trust.text("authority_id", node, s) === activation.text("authority_id") && trust.uint("purpose", node, s) === 1n &&
      issued >= trust.uint("signing_not_before_ms", node, s) && issued < trust.uint("signing_not_after_ms", node, s) &&
      parent.cohort >= trust.uint("first_parent_cohort", node, s) && parent.cohort <= trust.uint("last_parent_cohort", node, s) &&
      until <= trust.uint("max_activation_not_after_ms", node, s) && end <= trust.uint("max_session_not_after_ms", node, s) && end <= this.impactDeadline(parent.cohort, 1), "credential_untrusted");
    work.verify(activation, trust.bytes("signer_public_key", node, s), { selectors: { activation_source_profile: activation.doc.selector("activation_source_profile")! } });
    const evidence: CredentialEvidence = Object.freeze({ namespace: this, kind: 1, cohort: parent.cohort, issuer, generation: this.#generation, permissionKind: "activation", permissionDigest: work.digest(trust, "connection_activation_delegation_digest", node), digest: work.digest(activation, "activation_digest"),
      policyID: parent.policyID, policyRevision: parent.policyRevision, expires: end }); this.checkEvidence(evidence); return evidence;
  }

}
export class CredentialNamespaceSubscription {
  #namespace: CredentialNamespace | undefined;
  constructor(token: symbol, namespace: CredentialNamespace, private readonly subscriber: Subscriber) {
    requireCredential(token === namespaceToken, "credential_untrusted"); this.#namespace = namespace; Object.freeze(this);
  }
  check(): void { requireCredential(this.#namespace !== undefined, "credential_closed"); this.#namespace.checkSubscription(namespaceToken, this.subscriber); }
  close(): void { this.#namespace?.releaseSubscription(namespaceToken, this.subscriber); this.#namespace = undefined; }
}
const min = (a: bigint, b: bigint): bigint => a < b ? a : b;
const max = (a: bigint, b: bigint): bigint => a > b ? a : b;
function key(bytes: Uint8Array): string { return Array.from(bytes, x => x.toString(16).padStart(2, "0")).join(""); }
for (const ctor of [CredentialNamespace, CredentialNamespaceSubscription]) { Object.freeze(ctor.prototype); Object.freeze(ctor); }
